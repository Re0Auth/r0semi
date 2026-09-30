package federation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/account"
)

// The per-binding 401 cooldown, its state machine and its bound (Z09V-1,
// docs/issues/P2-medium.md). The behavior is "consecutive 401s on ONE binding",
// so the counter must reset on any other outcome and must never leak to another
// binding.

// stepClock is a manually advanced clock, so the cooldown window is exercised
// without sleeping.
type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// allow (below the threshold nothing is shed), fail (the threshold starts the
// window), reset (any non-401 outcome ends the run) and lapse (the window is a
// window).
func TestBindingCooldownAllowsCoolsResetsAndLapses(t *testing.T) {
	clock := &stepClock{t: time.Unix(0, 0)}
	const threshold = 5
	c := newBindingCooldown(8, threshold, 30*time.Second, clock.now)

	for i := 0; i < threshold-1; i++ {
		if c.reject("binding") {
			t.Fatalf("rejection %d of %d started the cooldown early", i+1, threshold)
		}
		if c.cooling("binding") {
			t.Fatalf("rejection %d of %d is cooling, want not yet", i+1, threshold)
		}
	}
	if !c.reject("binding") {
		t.Fatalf("rejection %d did not start the cooldown", threshold)
	}
	if !c.cooling("binding") {
		t.Fatalf("a binding at the threshold is not cooling")
	}
	if c.cooling("other") {
		t.Fatal("one binding's rejection cooled another binding")
	}

	// A non-401 outcome resets the run.
	c.reset("binding")
	if c.cooling("binding") {
		t.Fatal("reset left the binding cooling")
	}
	if c.reject("binding") {
		t.Fatal("the counter was not reset: a single rejection after reset started the cooldown")
	}

	// The window lapses on its own.
	for i := 0; i < threshold; i++ {
		c.reject("binding")
	}
	if !c.cooling("binding") {
		t.Fatal("the binding is not cooling after the threshold")
	}
	clock.advance(30 * time.Second)
	if c.cooling("binding") {
		t.Fatal("the binding is still cooling after the window elapsed")
	}
}

// The map has no natural release for a key that stops being seen, so it is
// bounded with least-recently-used eviction. An evicted key simply starts its run
// over; the worst case is one extra upstream call.
func TestBindingCooldownEvictsTheLeastRecentlyUsedBinding(t *testing.T) {
	c := newBindingCooldown(2, 5, time.Minute, time.Now)
	for i := 0; i < 4; i++ {
		c.reject("a")
	}
	for i := 0; i < 4; i++ {
		c.reject("b")
	}
	if !c.reject("a") {
		t.Fatal("the fifth rejection of a did not start its cooldown")
	}
	// c is new, so the map exceeds its limit and the back of the LRU (b, which was
	// not touched after a) is evicted.
	c.reject("c")
	if len(c.entries) != 2 {
		t.Fatalf("the cooldown map holds %d entries, want 2 (its limit)", len(c.entries))
	}
	if _, ok := c.entries["b"]; ok {
		t.Fatal("the least recently used binding was not evicted")
	}
	if !c.cooling("a") {
		t.Fatal("eviction dropped a cooling binding that had just been used")
	}
	if _, ok := c.entries["c"]; !ok {
		t.Fatal("the newly rejected binding was not recorded")
	}
}

// The isolation test Z09V-1 is about: two bindings, ONE host, one of them with a
// credential the source rejects. The dead one must cool on its own and the live
// one must keep being served — which the per-host breaker could not do.
func TestBindingCooldownIsIsolatedBetweenBindingsOnOneHost(t *testing.T) {
	var calls atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer dead-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.Close)

	reg, err := NewRegistry(Source{
		Game: game, Name: sourceName, DisplayName: "Fake", Issuer: up.URL, TokenClass: "revocable",
		Resources: []Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: profileScope}},
	})
	if err != nil {
		t.Fatal(err)
	}

	clock := &stepClock{t: time.Unix(0, 0)}
	b := backend{store: NewMemoryBindingStore(), vault: newVault(t)}
	b.bind(t, "usr_atk", sourceName, "dead-token", "", time.Time{})
	b.bind(t, "usr_vic", sourceName, "live-token", "", time.Time{})
	svc := mustService(t, Config{
		Registry: reg, Doer: up.Client(), Now: clock.now,
		BindingFailureThreshold: 5, BindingCooldown: 30 * time.Second,
	}, b)

	ctx := context.Background()
	fetch := func(user string) error {
		_, err := svc.Fetch(ctx, FetchRequest{User: account.UserID(user), Game: game, Resource: "profile"})
		return err
	}

	if err := fetch("usr_vic"); err != nil {
		t.Fatalf("baseline victim read = %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := fetch("usr_atk"); err == nil {
			t.Fatalf("attacker read %d: the dead credential was accepted", i+1)
		}
	}

	before := calls.Load()
	if err := fetch("usr_vic"); err != nil {
		t.Errorf("the victim's read was shed by another binding's dead credential: %v", err)
	}
	if got := calls.Load(); got != before+1 {
		t.Errorf("the victim's read produced %d upstream calls, want 1", got-before)
	}

	// The attacker's own binding is now in cooldown: shed without an upstream call.
	before = calls.Load()
	if err := fetch("usr_atk"); !errors.Is(err, ErrBindingCooldown) {
		t.Errorf("attacker read after the threshold = %v, want ErrBindingCooldown", err)
	}
	if got := calls.Load(); got != before {
		t.Errorf("a cooling binding was still dialed %d time(s)", got-before)
	}

	// And it recovers on its own: after the window the source is asked again.
	clock.advance(31 * time.Second)
	if err := fetch("usr_atk"); !isUnauthorized(err) {
		t.Errorf("attacker read after the cooldown = %v, want the source's 401 again (it was asked)", err)
	}
	if got := calls.Load(); got != before+1 {
		t.Errorf("after the cooldown the upstream call count moved by %d, want 1", got-before)
	}
}
