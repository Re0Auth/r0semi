//go:build audit7

// Z11-1 verification: reachability with a dependency check that is as fast as the
// real one.
//
// The reviewed probe uses a 300ms stand-in for `store.db.Ping` and closes the
// connection only after the check is provably running. Its own "未能到达" admits
// the real Ping is ~1ms, so the question this probe answers is whether the poison
// still lands when the dependency returns almost immediately — i.e. whether an
// attacker has to win a millisecond race or merely send-and-hang-up.
package zzprobe_z11verify

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/httpapi"
)

func hangupReadyz(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	if _, err := fmt.Fprintf(c, "GET /readyz HTTP/1.1\r\nHost: probe\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.Close()
}

// measurePoison runs `rounds` attempt cycles against one dependency timing and
// returns how many fresh /readyz reads (all from a different, live connection)
// were answered 503, how many checks ran, and how many of those saw a cancelled
// context.
func measurePoison(t *testing.T, work time.Duration, rounds int) (poisoned, checks, cancelled int) {
	t.Helper()
	var calls, canceled atomic.Int64
	ready := func(ctx context.Context) error {
		calls.Add(1)
		if err := ctx.Err(); err != nil {
			canceled.Add(1)
			return err
		}
		if work > 0 {
			time.Sleep(work)
		}
		if err := ctx.Err(); err != nil {
			canceled.Add(1)
			return err
		}
		return nil
	}
	srv := miniAPI(t, miniConfig{Ready: httpapi.ReadinessProbe(ready)})
	addr := srv.Listener.Addr().String()

	for i := 0; i < rounds; i++ {
		// Outlive readinessTTL so the next request must run the check itself.
		time.Sleep(1100 * time.Millisecond)
		hangupReadyz(t, addr)
		time.Sleep(60 * time.Millisecond)
		resp, err := http.Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatalf("read /readyz: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			poisoned++
		}
	}
	return poisoned, int(calls.Load()), int(canceled.Load())
}

// TestZ11VHangupPoisonNeedsNoSlowDependency is red (t.Errorf) if the poison lands
// with a realistic same-host dependency. It is a verification probe: either
// outcome is informative, and the failure message states which.
func TestZ11VHangupPoisonNeedsNoSlowDependency(t *testing.T) {
	const rounds = 8
	for _, tc := range []struct {
		name string
		work time.Duration
	}{
		{"instant (0s, like a hand-built Ping that returns at once)", 0},
		{"1ms (a same-host pgx Ping round trip)", time.Millisecond},
		{"300ms (the reviewed probe's stand-in)", 300 * time.Millisecond},
	} {
		poisoned, checks, cancelled := measurePoison(t, tc.work, rounds)
		t.Logf("dependency %-55s: %d/%d hangup cycles poisoned the next /readyz (checks=%d, cancelled=%d)",
			tc.name, poisoned, rounds, checks, cancelled)
		if poisoned > 0 {
			t.Errorf("reachability CONFIRMED for a %s dependency: %d of %d anonymous connect-then-hangup cycles left a "+
				"fresh, credential-free /readyz at 503 for the rest of the TTL", tc.name, poisoned, rounds)
		}
		// The poison could still land with `poisoned == 0` if the cancellation
		// stayed in play but the Canceled filter happened to hide it, so pin the
		// mechanism itself: the shared check must run on context.WithoutCancel, so
		// the dependency is never handed a context the caller's hangup cancelled.
		if cancelled != 0 {
			t.Errorf("the dependency observed %d cancelled context(s) for a %s dependency across %d hangup cycles, "+
				"want 0: context.WithoutCancel is not shielding the shared readiness check from the caller's hangup, "+
				"so a cancellation can still end the check and be recorded as the process's readiness",
				cancelled, tc.name, rounds)
		}
	}
}
