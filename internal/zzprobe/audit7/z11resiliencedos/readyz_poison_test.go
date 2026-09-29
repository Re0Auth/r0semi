//go:build audit7

// Z11-1 regression guard: an anonymous caller's own cancellation must NOT poison
// the SHARED readiness result.
//
// internal/httpapi/health.go holds one readinessCache per process, and its whole
// justification (P1-4's fix) is that the exempted probe work is bounded and never
// answers 503 because of someone else's traffic (docs/operations.md: "probes answer
// from a bounded amount of work, and never a 503 because of load").
//
// The defect this guards against derived the dependency check from the caller's
// request context (`context.WithTimeout(ctx, readinessTimeout)` where ctx is
// r.Context(), which net/http cancels when the client's connection closes). A
// caller that opened /readyz and hung up while the check ran made the dependency
// return context.Canceled, and that error became the process-wide readiness answer
// for the next readinessTTL — a healthy instance pulled out of rotation by one
// unauthenticated connection per second, with no rate-limit budget spent.
//
// The fix runs the check on context.WithoutCancel(callerCtx) + readinessTimeout,
// so a caller's hangup never cancels it and context.Canceled is never cached as a
// verdict. This guard fires N anonymous connect-then-hangup requests, each with the
// check provably running, and requires every fresh /readyz to stay 200 and the
// dependency to have observed zero cancellations. Reverting the fix fails both.
package zzprobe_z11resiliencedos

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/httpapi"
)

// TestZ11CallerCancellationDoesNotPoisonReadiness is green only while the
// readiness check is detached from the caller's context. It was formerly
// TestZ11CallerCancellationPoisonsTheSharedReadinessResult, a finding-confirmation
// oracle that asserted the poison; it is now the regression guard for the fix.
func TestZ11CallerCancellationDoesNotPoisonReadiness(t *testing.T) {
	// The stand-in for `store.db.Ping`: a real dependency call that honours the
	// context it is given and takes a non-zero amount of time, the way a database
	// round trip does. It counts invocations, completions and cancellations, so the
	// probe can prove the hang-ups ran real checks and yet cancelled none.
	var calls, finished, cancels atomic.Int64
	ready := func(ctx context.Context) error {
		calls.Add(1)
		defer finished.Add(1)
		select {
		case <-ctx.Done():
			cancels.Add(1)
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return nil
		}
	}
	srv := miniAPI(t, miniConfig{Ready: httpapi.ReadinessProbe(ready)})

	// Positive control: with a live caller the check succeeds, so a healthy result
	// is possible at all and the cancellations below are attributable to hangups.
	if code, _, _ := get(t, srv.URL+"/readyz"); code != http.StatusOK {
		t.Fatalf("control: /readyz = %d against a healthy dependency, want 200", code)
	}
	if n := cancels.Load(); n != 0 {
		t.Fatalf("control: the dependency was cancelled %d time(s) with no caller hanging up", n)
	}
	calls.Store(0)
	finished.Store(0)

	// N anonymous connect-then-hangup requests. Each one outlives readinessTTL so
	// it starts a check of its own, and hangs up only once that check is provably
	// running — so each is a genuine attempt to cancel the shared check.
	const hangups = 3
	addr := srv.Listener.Addr().String()
	for i := 0; i < hangups; i++ {
		time.Sleep(1100 * time.Millisecond) // outlive readinessTTL
		base := calls.Load()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		if _, err := fmt.Fprintf(conn, "GET /readyz HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n"); err != nil {
			_ = conn.Close()
			t.Fatalf("write request %d: %v", i, err)
		}
		waitUntil(t, 2*time.Second, func() bool { return calls.Load() > base })
		if calls.Load() <= base {
			_ = conn.Close()
			t.Fatalf("hangup %d never started a dependency check", i)
		}
		_ = conn.Close()
		// Let the detached check finish before the next cycle, so each hangup is
		// measured against its own check.
		waitUntil(t, 2*time.Second, func() bool { return finished.Load() > base })
	}

	// What the kubelet would read on a fresh connection.
	code, _, body := get(t, srv.URL+"/readyz")
	t.Logf("after %d anonymous connect-then-hangup requests on /readyz: probe invocations=%d, "+
		"cancellations=%d, next /readyz (fresh connection, no credential) = %d %q",
		hangups, calls.Load(), cancels.Load(), code, body)
	if code != http.StatusOK {
		t.Errorf("a fresh /readyz answered %d (%q) after anonymous callers hung up against a healthy "+
			"dependency: the caller's cancellation reached the shared readiness cache and replaced a healthy "+
			"verdict for every caller, including the orchestrator's probe", code, body)
	}
	if n := cancels.Load(); n != 0 {
		t.Errorf("the dependency saw its context cancelled %d time(s) although every check ran on "+
			"context.WithoutCancel: the readiness probe is derived from the caller's request context again, "+
			"so any anonymous connect-then-hangup can end the process-wide check", n)
	}
}

// TestZ11ConcurrentReadinessCallsAreAllAdmitted is the positive control for the
// exemption itself: /readyz must never answer 503 because of load (the ruling
// the exemption rests on), so a saturated in-flight cap and an empty bucket must
// both leave it at 200. It also proves that a probe can reach the handler at
// unlimited concurrency, which is the half of Z11-1 that makes it anonymous.
func TestZ11ConcurrentReadinessCallsAreAllAdmitted(t *testing.T) {
	srv := miniAPI(t, miniConfig{MaxInFlight: 1})
	const n = 32
	var wg atomic.Int64
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Add(-1)
			resp, err := http.Get(srv.URL + "/readyz")
			if err != nil {
				codes <- -1
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	waitUntil(t, 5*time.Second, func() bool { return wg.Load() == 0 })
	close(codes)
	bad := 0
	for c := range codes {
		if c != http.StatusOK && c != http.StatusServiceUnavailable {
			t.Errorf("/readyz answered %d, want 200 or 503", c)
		}
		if c != http.StatusOK {
			bad++
		}
	}
	t.Logf("%d concurrent /readyz calls against max_in_flight=1: %d were not 200", n, bad)
	if bad != 0 {
		t.Errorf("%d of %d /readyz calls were refused while the in-flight cap was saturated: the exemption is gone",
			bad, n)
	}
}
