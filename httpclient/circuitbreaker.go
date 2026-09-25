package httpclient

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when a host's breaker is open and the request was
// rejected without being attempted.
var ErrCircuitOpen = errors.New("httpclient: circuit breaker is open")

// BreakerOptions tunes a CircuitBreaker. A zero field takes its default.
type BreakerOptions struct {
	// FailureThreshold is how many consecutive qualifying failures trip the
	// breaker. Defaults to 5.
	FailureThreshold int
	// Cooldown is how long the breaker stays open before it admits a trial
	// request. Defaults to 30s.
	Cooldown time.Duration
	// HalfOpenSuccesses is how many consecutive trial successes close the
	// breaker. Defaults to 2.
	HalfOpenSuccesses int
	// Now, when set, is the clock. Used by tests.
	Now func() time.Time
}

const (
	defaultBreakerFailures  = 5
	defaultBreakerCooldown  = 30 * time.Second
	defaultBreakerHalfOpens = 2
)

// CircuitBreaker wraps next with a per-host circuit breaker.
//
// A host that keeps failing is skipped for a cooldown window instead of charging
// every request a full timeout: the data plane already has a bulkhead and
// per-request deadlines, and a source that is down would otherwise turn each user
// read into a 20-second wait. After the cooldown one trial request is admitted;
// the configured number of consecutive successes closes the breaker, and any
// failure trips it again.
//
// Only failures that say something about the upstream count: a transport error
// the caller did not cause, or a 5xx. A 4xx is the request's problem, and a
// caller-side cancellation (the request context is done) is nobody's fault here.
// State is keyed by URL host and kept for the process's life; the set of hosts is
// the deployment's configured sources, so it is bounded.
//
// It composes as a RoundTripper so it sits in the transport chain alongside
// Bulkhead and the result is still a plain *http.Client — usable both as a Doer
// and as the concrete client the OAuth token exchange needs.
func CircuitBreaker(next http.RoundTripper, opts BreakerOptions) http.RoundTripper {
	if opts.FailureThreshold <= 0 {
		opts.FailureThreshold = defaultBreakerFailures
	}
	if opts.Cooldown <= 0 {
		opts.Cooldown = defaultBreakerCooldown
	}
	if opts.HalfOpenSuccesses <= 0 {
		opts.HalfOpenSuccesses = defaultBreakerHalfOpens
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &breakerTransport{next: next, opts: opts, hosts: map[string]*breakerState{}}
}

type breakerPhase int

const (
	breakerClosed breakerPhase = iota
	breakerOpen
	breakerHalfOpen
)

type breakerState struct {
	phase      breakerPhase
	failures   int
	successes  int
	openedAt   time.Time
	trialInUse bool
}

type breakerTransport struct {
	next  http.RoundTripper
	opts  BreakerOptions
	mu    sync.Mutex
	hosts map[string]*breakerState
}

func (b *breakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if !b.admit(host) {
		return nil, ErrCircuitOpen
	}
	resp, err := b.next.RoundTrip(req)
	b.record(host, req, err, resp)
	return resp, err
}

// admit reports whether a request may proceed, moving an expired open breaker to
// half-open and reserving the single trial slot.
func (b *breakerTransport) admit(host string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.stateFor(host)
	switch st.phase {
	case breakerOpen:
		if b.opts.Now().Sub(st.openedAt) < b.opts.Cooldown {
			return false
		}
		st.phase = breakerHalfOpen
		st.successes = 0
		st.trialInUse = true
		return true
	case breakerHalfOpen:
		if st.trialInUse {
			return false
		}
		st.trialInUse = true
		return true
	default:
		return true
	}
}

func (b *breakerTransport) record(host string, req *http.Request, err error, resp *http.Response) {
	failed := false
	switch {
	case err != nil:
		// A caller-side cancellation or deadline is not the upstream's fault.
		failed = req.Context().Err() == nil
	case resp != nil && resp.StatusCode >= http.StatusInternalServerError:
		failed = true
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.stateFor(host)
	switch st.phase {
	case breakerOpen:
		// Unreachable through admit; kept coherent anyway.
	case breakerHalfOpen:
		st.trialInUse = false
		if failed {
			st.phase = breakerOpen
			st.openedAt = b.opts.Now()
			return
		}
		st.successes++
		if st.successes >= b.opts.HalfOpenSuccesses {
			st.phase = breakerClosed
			st.failures = 0
			st.successes = 0
		}
	default:
		if failed {
			st.failures++
			if st.failures >= b.opts.FailureThreshold {
				st.phase = breakerOpen
				st.openedAt = b.opts.Now()
			}
			return
		}
		st.failures = 0
	}
}

func (b *breakerTransport) stateFor(host string) *breakerState {
	st := b.hosts[host]
	if st == nil {
		st = &breakerState{}
		b.hosts[host] = st
	}
	return st
}
