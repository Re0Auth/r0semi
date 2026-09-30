package federation

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
	"time"
)

// The per-binding 401 cooldown (Z09V-1, docs/issues/P2-medium.md).
//
// The per-HOST breaker in httpclient cannot answer this: it is keyed by host, so
// one account's rejected credential looks exactly like the host being down, and
// counting it there shed every OTHER account's reads of the same source for a
// cooldown (five read by one account, measured). A 401 is the state of one
// binding's upstream credential, so the counter that acts on it has to be keyed by
// the binding, not the host.
//
// This is that counter, and it is deliberately separate from the breaker:
//
//   - it never opens anything for a host, so another binding on the same host is
//     untouched;
//   - it is not reported through circuit transitions. upstream_circuit_transitions_total
//     has a single `state` label and would then mix host health with credential
//     state, so this mechanism emits nothing there. A cooling binding records the
//     read as UpstreamUnavailable on the existing upstream_fetches_total result
//     label — no new label value, so no dashboard or documentation drift — and no
//     metric carries a user identifier.
const (
	// bindingCooldownThreshold is how many consecutive 401s from a source on ONE
	// binding start the cooldown. It mirrors the breaker's FailureThreshold so the
	// shipped shape of "a permanently-401 source is not paid for forever" survives
	// the breaker no longer counting the status.
	bindingCooldownThreshold = 5
	// bindingCooldownWindow is how long a cooling binding is not asked again. It
	// mirrors the breaker's Cooldown.
	bindingCooldownWindow = 30 * time.Second
	// maxCooledBindings bounds the map. A per-binding key has no natural release
	// the way Z09-4's byte-keyed map does: an entry deleted only when its cooldown
	// lapses still exists for every binding that was ever rejected, and a binding
	// that is unbound or erased is never seen again to delete it. The map is
	// therefore capped with least-recently-used eviction (see reject/cooling), so
	// memory is bounded by the number of DISTINCT bindings rejected inside the
	// window — not by the request rate. Evicting an entry that was still cooling
	// costs one upstream call, never an incorrect answer.
	maxCooledBindings = 4096
)

// ErrBindingCooldown reports that this binding's upstream credential has been
// rejected by the source too many times in a row, so the data plane is not asking
// that source again on this binding's behalf for a cooldown.
//
// It is a NEW error rather than httpclient.ErrCircuitOpen, which was the other
// option (Z09V-1, docs/issues/P2-medium.md). Reusing the breaker's sentinel would
// have kept the existing 502/observability.UpstreamCircuitOpen route, but that
// route is the HOST-health vocabulary: an operator reading `circuit_open` would see
// "we stopped calling because the source is down" for a condition that is "one
// caller's credential is dead". The two are what the rest of this package works
// hard to keep apart, so this error gets its own status (503 temporarily
// unavailable + Retry-After, the same fail-closed direction as ErrBufferBudget) and
// is recorded as UpstreamUnavailable, which is honest and adds no label value.
var ErrBindingCooldown = errors.New("federation: this binding's upstream credential is in cooldown")

// BindingCooldownError names the binding a cooldown is blocking. Like
// NotBoundError it reports the game and source, never the subject: this error
// reaches a response body and an access-log line, and a subject is a pseudonymous
// account identifier.
type BindingCooldownError struct {
	Game   string
	Source string
}

func (e *BindingCooldownError) Error() string {
	return fmt.Sprintf("federation: %s/%s is not being asked: the credential was rejected repeatedly", e.Game, e.Source)
}

func (e *BindingCooldownError) Is(target error) bool { return target == ErrBindingCooldown }

// bindingCooldown counts consecutive 401s per binding and holds a cooling window
// once the threshold is reached. It is safe for concurrent use and never blocks.
//
// The map is bounded by limit with least-recently-used eviction: the most
// recently used entry is at the front of lru, and a new key evicts the back when
// the map is full. Every counter has a natural "reset" — any non-401 outcome
// deletes the entry — so eviction is a second bound for keys that stop being seen
// entirely, not the primary one.
type bindingCooldown struct {
	mu        sync.Mutex
	limit     int
	threshold int
	window    time.Duration
	now       func() time.Time
	entries   map[string]*coolingBinding
	// lru orders keys by last use, front = most recent. It is rebuilt with the
	// map, so an entry is on the list exactly while it is in the map.
	lru *list.List
}

// coolingBinding is one binding's consecutive-rejection state. failures resets to
// zero by deletion; until is zero until the threshold is reached.
type coolingBinding struct {
	key      string
	failures int
	until    time.Time
	elem     *list.Element
}

// newBindingCooldown builds a cooldown. A limit <= 0 takes maxCooledBindings, a
// threshold <= 0 takes bindingCooldownThreshold, a window <= 0 takes
// bindingCooldownWindow, and a nil clock takes time.Now.
func newBindingCooldown(limit, threshold int, window time.Duration, now func() time.Time) *bindingCooldown {
	if limit <= 0 {
		limit = maxCooledBindings
	}
	if threshold <= 0 {
		threshold = bindingCooldownThreshold
	}
	if window <= 0 {
		window = bindingCooldownWindow
	}
	if now == nil {
		now = time.Now
	}
	return &bindingCooldown{
		limit:     limit,
		threshold: threshold,
		window:    window,
		now:       now,
		entries:   make(map[string]*coolingBinding),
		lru:       list.New(),
	}
}

// cooling reports whether key is inside its cooldown window. A lapsed entry is
// dropped here, which is the lazy half of the map's bound.
func (c *bindingCooldown) cooling(key string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		return false
	}
	if e.until.IsZero() {
		// Still accumulating rejections, so it is not cooling and must NOT be
		// treated as a lapsed window: a zero `until` means "the threshold has not
		// been reached", not "the window ended at the zero time".
		c.lru.MoveToFront(e.elem)
		return false
	}
	if !c.now().Before(e.until) {
		c.removeLocked(e)
		return false
	}
	c.lru.MoveToFront(e.elem)
	return true
}

// reject records one 401 and reports whether key is now cooling. Reaching the
// threshold starts the window; further rejections while cooling refresh the
// counter and the deadline, so a binding that keeps being tried stays out.
func (c *bindingCooldown) reject(key string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		e = &coolingBinding{key: key}
		e.elem = c.lru.PushFront(e)
		c.entries[key] = e
		if len(c.entries) > c.limit {
			if back := c.lru.Back(); back != nil && back.Value != nil {
				c.removeLocked(back.Value.(*coolingBinding))
			}
		}
	} else {
		c.lru.MoveToFront(e.elem)
	}
	e.failures++
	if e.failures < c.threshold {
		return false
	}
	e.until = c.now().Add(c.window)
	return true
}

// reset clears a binding's counter. It is called on every outcome that is not a
// 401, so the counter is "consecutive 401s": a healthy read, a refresh that
// succeeded, or a transport error all end the run.
func (c *bindingCooldown) reset(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil {
		c.removeLocked(e)
	}
}

// removeLocked drops an entry from both the map and the ordering list. The caller
// holds c.mu.
func (c *bindingCooldown) removeLocked(e *coolingBinding) {
	delete(c.entries, e.key)
	c.lru.Remove(e.elem)
}
