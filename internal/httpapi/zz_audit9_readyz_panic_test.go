package httpapi

import (
	"context"
	"testing"
)

// AUDIT9 / S10-2 — a panic in the readiness probe wedges /readyz at "checking".
//
// readinessCache.check sets c.running = true and creates c.settled before calling
// the probe, and clears them only on the normal return path (health.go:192-194).
// A probe that panics leaves running=true, settled unclosed and state still
// readinessUnknown. Every later caller then takes the `fresh || c.running` branch
// (health.go:163), waits readinessColdStartWait, and reports "checking" (503)
// forever — the healthy probe is never run again.
//
// Guard: pins the wedge. It fails the day check() recovers/resets state on the
// abnormal path (defer c.running=false / close(settled)), because the healthy
// probe would then run and the state would become ready.
func TestAudit9PanickingReadinessProbeWedgesReadinessAtChecking(t *testing.T) {
	var c readinessCache

	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_, _ = c.check(context.Background(), func(context.Context) error {
			panic("readiness dependency exploded")
		})
	}()
	if !panicked {
		t.Fatal("the probe panic did not propagate; the setup is wrong")
	}

	calls := 0
	state, err := c.check(context.Background(), func(context.Context) error {
		calls++
		return nil
	})
	if calls != 0 {
		t.Errorf("the healthy probe ran %d time(s) after the panicking one, want 0 "+
			"(a reset cache would run it)", calls)
	}
	if state != readinessUnknown {
		t.Errorf("readiness state = %v, want readinessUnknown: the cache is wedged at 'checking'", state)
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}
