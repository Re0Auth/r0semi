//go:build audit7

// Z11-1: an anonymous caller's own cancellation poisons the SHARED readiness
// result.
//
// internal/httpapi/health.go holds one readinessCache per process. Its whole
// justification (P1-4's fix) is "probes are exempt from the limiter and the
// in-flight cap BECAUSE the exempted work is bounded" — at most one dependency
// check per readinessTTL, and never a 503 caused by someone else's traffic
// (docs/operations.md: "probes answer from a bounded amount of work, and never a
// 503 because of load").
//
// But `check` derives the probe's context from the REQUEST's context
// (health.go:122: `context.WithTimeout(ctx, readinessTimeout)` where ctx is
// r.Context()). net/http cancels a request's context when the client's
// connection closes. So a caller that opens /readyz and hangs up while the
// check is running makes the dependency call return context.Canceled, and that
// error is stored as the process-wide readiness answer for the next
// readinessTTL. Every /readyz in that window — including the kubelet's — is a
// 503 "not ready", which pulls a healthy instance out of rotation. The attacker
// needs no credential (probes are exempt from the limiter and the in-flight cap,
// so no budget either) and the failure is silent: the reason goes to slog.Debug
// (health.go:98).
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

// TestZ11CallerCancellationPoisonsTheSharedReadinessResult is red while the
// readiness check is derived from the caller's context.
func TestZ11CallerCancellationPoisonsTheSharedReadinessResult(t *testing.T) {
	// The stand-in for `store.db.Ping`: a real dependency call that honours the
	// context it is given and takes a non-zero amount of time, the way a database
	// round trip does. It reports what it saw, so the probe can print the error
	// the process cached.
	var calls atomic.Int64
	var lastErr atomic.Value
	ready := func(ctx context.Context) error {
		calls.Add(1)
		select {
		case <-ctx.Done():
			lastErr.Store(ctx.Err().Error())
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
			lastErr.Store("<nil: dependency reachable>")
			return nil
		}
	}
	srv := miniAPI(t, miniConfig{Ready: httpapi.ReadinessProbe(ready)})

	// The poison: one unauthenticated GET /readyz whose connection is closed
	// while the check is running. Nothing is read, nothing is authenticated, and
	// no rate-limit budget is spent (probes are exempt).
	addr := srv.Listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	if _, err := fmt.Fprintf(conn, "GET /readyz HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// Wait until the check is provably running before hanging up, so this is not
	// a race with request dispatch.
	waitUntil(t, 2*time.Second, func() bool { return calls.Load() >= 1 })
	_ = conn.Close()
	// Let the server notice the disconnect and the probe return.
	waitUntil(t, 2*time.Second, func() bool {
		v, _ := lastErr.Load().(string)
		return v == context.Canceled.Error()
	})

	// What the kubelet would read in the next readinessTTL.
	code := http.StatusOK
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		code, _, _ = get(t, srv.URL+"/readyz")
		if code != http.StatusOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cached, _ := lastErr.Load().(string)
	t.Logf("after one anonymous connect-then-hangup on /readyz: probe invocations=%d, cached dependency result=%q, "+
		"next /readyz (a fresh connection, no credential) = %d", calls.Load(), cached, code)
	if code != http.StatusServiceUnavailable {
		t.Errorf("a fresh /readyz answered %d; the caller's cancellation did not reach the shared cache. "+
			"If this is green, the mechanism is gone — re-derive the probe.", code)
	} else {
		t.Errorf("an anonymous caller made the process report NOT READY (503) for every caller, including the " +
			"orchestrator's probe: /readyz ran the dependency check on r.Context() (health.go:122), the caller hung " +
			"up, and context.Canceled was cached as this replica's readiness for readinessTTL. One connection per " +
			"second keeps a healthy instance out of rotation, and no rate limit applies (probes are exempt).")
	}

	// Control: with a live caller the same check succeeds, so the 503 above was
	// the cancellation and not a broken probe.
	time.Sleep(1100 * time.Millisecond) // outlive readinessTTL
	code, _, _ = get(t, srv.URL+"/readyz")
	cached, _ = lastErr.Load().(string)
	t.Logf("after the TTL, a live caller on a fresh connection: cached=%q, /readyz = %d", cached, code)
	if code != http.StatusOK {
		t.Errorf("the endpoint did not recover once the caller stayed connected: %d (cached %q). The probe cannot "+
			"attribute the 503 above to the cancellation.", code, cached)
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
