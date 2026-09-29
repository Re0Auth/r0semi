//go:build audit6

// Readiness and probe-exemption probes for zone 06 (round 6).
//
// Two questions:
//  1. What did the P1-4 fix (0e6b701, the readinessCache) actually change, and
//     is the round-5 startup probe's red the vulnerability or the fix? (Answer
//     expected: the fix — the probe measures "32 concurrent checks" which the
//     cache now bounds to one.)
//  2. Did the fix open a window of its own? The cache answers from c.err while
//     a check is running — and before the FIRST check has ever completed, c.err
//     is the zero value (nil). A request that races the first-ever check is
//     told "ready" about a dependency that was never verified.
package z06httpedge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// blockingReady parks every caller inside the dependency check until release,
// and counts how many got in at once.
type blockingReady struct {
	release chan struct{}
	inside  atomic.Int64
	peak    atomic.Int64
	calls   atomic.Int64
}

func newBlockingReady() *blockingReady {
	return &blockingReady{release: make(chan struct{})}
}

func (b *blockingReady) probe(context.Context) error {
	now := b.inside.Add(1)
	b.calls.Add(1)
	for {
		old := b.peak.Load()
		if now <= old || b.peak.CompareAndSwap(old, now) {
			break
		}
	}
	<-b.release
	b.inside.Add(-1)
	return nil
}

// failingReady returns an error until released, then succeeds; it lets a probe
// hold the FIRST check open while other requests arrive.
type failingReady struct {
	release chan struct{}
	calls   atomic.Int64
	err     error
}

func newFailingReady(err error) *failingReady {
	return &failingReady{release: make(chan struct{}), err: err}
}

func (f *failingReady) probe(context.Context) error {
	f.calls.Add(1)
	<-f.release
	return f.err
}

// TestZ06ReadyzBoundsTheCostOfItsOwnExemption is the regression check on the
// P1-4 fix: /readyz is exempt from the limiter and the in-flight cap (by the
// ruling in docs/operations.md), so the cost of what it does has to be bounded
// by construction. The fix bounds it at ONE dependency check at a time, with
// concurrent probes answered from the cached result. This probe drives the
// round-5 scenario (32 concurrent /readyz while max_in_flight=1 is saturated)
// and asserts the fixed behavior: at most one check runs, none of them is
// refused because of load, and the concurrency inside the check is 1.
func TestZ06ReadyzBoundsTheCostOfItsOwnExemption(t *testing.T) {
	peer := "203.0.113.7:5555"

	// Control server: the limiter is in force for ordinary requests, and probes
	// are exempt from it (that half of the ruling is unchanged).
	ctrlCfg := edgeConfig()
	ctrlCfg.Limiter = ratelimit.New(noRefill, 1)
	ctrlCfg.Ready = func(context.Context) error { return nil }
	ctrlSrv, err := httpapi.New(ctrlCfg)
	if err != nil {
		t.Fatal(err)
	}
	get := func(h http.Handler, path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := get(ctrlSrv.Handler(), "/v1/me"); code != http.StatusUnauthorized {
		t.Fatalf("first /v1/me = %d, want 401", code)
	}
	if code := get(ctrlSrv.Handler(), "/v1/me"); code != http.StatusTooManyRequests {
		t.Fatalf("second /v1/me = %d, want 429", code)
	}
	for i := 0; i < 4; i++ {
		if code := get(ctrlSrv.Handler(), "/readyz"); code != http.StatusOK {
			t.Fatalf("/readyz #%d with an empty bucket = %d, want 200", i, code)
		}
	}

	// The measured server: the in-flight cap is 1 and the readiness check
	// parks inside the dependency, which is what made the round-5 probe able
	// to observe unbounded concurrency before the fix.
	ready := newBlockingReady()
	cfg := edgeConfig()
	cfg.Limiter = ratelimit.New(noRefill, 1)
	cfg.MaxInFlight = 1
	cfg.Ready = ready.probe
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	const n = 32
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = get(h, "/readyz")
		}(i)
	}
	// The first /readyz parks inside the readiness check; the rest must be
	// answered from the cache rather than queueing behind it.
	deadline := time.Now().Add(2 * time.Second)
	for ready.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ready.calls.Load() != 1 {
		t.Fatalf("readiness check calls = %d, want exactly 1 while %d probes raced it", ready.calls.Load(), n)
	}
	close(ready.release)
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("/readyz #%d = %d, want 200 (a probe must never fail because of load)", i, code)
		}
	}
	if peak := ready.peak.Load(); peak != 1 {
		t.Fatalf("peak concurrency inside the readiness check = %d, want 1 (the fix's cost cap)", peak)
	}
}

// TestZ06ReadyzColdStartAnswersReadyBeforeTheFirstCheckCompletes is the new
// window: readinessCache.check answers from c.err when a check is running,
// and before the first check has ever completed that value is the zero value
// (nil). A request that races the process's first /readyz is told "ok" about a
// dependency that was never verified — not "one second stale", which the
// ruling documents, but "never checked at all".
func TestZ06ReadyzColdStartAnswersReadyBeforeTheFirstCheckCompletes(t *testing.T) {
	depErr := context.DeadlineExceeded // a dependency that is DOWN on cold start
	ready := newFailingReady(depErr)
	cfg := edgeConfig()
	cfg.Ready = ready.probe
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// The process's first /readyz enters the check and parks there (as a hung
	// database would).
	firstDone := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		firstDone <- rec.Code
	}()
	deadline := time.Now().Add(2 * time.Second)
	for ready.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ready.calls.Load() != 1 {
		t.Fatal("the first /readyz never entered the readiness check; the probe is vacuous")
	}

	// While that first check is still running — the dependency has answered
	// nothing — a second /readyz must not be told "ready". The only honest
	// answers are "not ready" or "I am still checking"; 200 "ok" is a value
	// that was never verified.
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a /readyz racing the first-ever check answered %d %q; the cached answer was never verified, want 503",
			rec.Code, rec.Body.String())
	}

	// Complete the first check (it fails: the dependency is down) and confirm
	// the first caller was told the truth.
	close(ready.release)
	if code := <-firstDone; code != http.StatusServiceUnavailable {
		t.Fatalf("the first /readyz = %d, want 503 once the failing check returned", code)
	}
}
