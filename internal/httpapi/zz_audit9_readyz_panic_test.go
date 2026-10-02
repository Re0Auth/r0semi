package httpapi

import (
	"context"
	"testing"
)

// AUDIT9 / S10-2 — a panic in the readiness probe must not wedge /readyz at
// "checking".
//
// readinessCache.check sets c.running = true and creates c.settled before calling
// the probe. It used to clear them only on the normal return path, so a probe that
// panicked left running=true and settled unclosed with state still
// readinessUnknown. Every later caller then took the `fresh || c.running` branch,
// waited readinessColdStartWait and reported "checking" (503) forever — the
// healthy probe was never run again.
//
// This is the flipped guard: it fails if check() is ever changed back to reset
// the in-flight marker on the normal path only.
func TestAudit9PanickingReadinessProbeKeepsReadinessUsable(t *testing.T) {
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
	if calls != 1 {
		t.Errorf("the healthy probe ran %d time(s) after the panicking one, want 1 "+
			"(a wedged cache would run it 0 times)", calls)
	}
	if state != readinessReady {
		t.Errorf("readiness state = %v, want readinessReady: the cache must recover", state)
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

// TestS10_2ReadinessCacheRecoversAfterProbePanic is the finding's own probe: a
// panicking probe (caught by the caller) must release the in-flight marker so the
// next caller runs a real probe and records its verdict, rather than being told
// "checking" against a frozen readinessUnknown.
func TestS10_2ReadinessCacheRecoversAfterProbePanic(t *testing.T) {
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
	if calls != 1 {
		t.Errorf("the healthy probe was called %d time(s), want exactly 1 "+
			"(a wedged cache leaves running=true and never runs it)", calls)
	}
	if state != readinessReady {
		t.Errorf("readiness state = %v, want readinessReady", state)
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}
