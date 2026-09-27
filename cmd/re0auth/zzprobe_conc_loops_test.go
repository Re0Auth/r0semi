//go:build audit5

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/observability"
)

// --- Goroutine lifetime of every background loop ---
//
// docs/architecture.md 4.13 claims each background sweep loop "is bound to the
// same signal context and stops with the process". That is a property of each loop
// separately -- including the ones added later (the audit anchor and verify loops,
// and the in-memory OP janitor) -- so it is pinned here per loop rather than
// inferred from the group that starts them.
//
// These probes cancel the loop's context and require the loop to *return*. A
// ticker that is never stopped is a timer that keeps firing; a loop that does not
// observe its context is a goroutine that outlives the process's shutdown.

type zzProbeSweep struct{ n int }

func (s zzProbeSweep) SweepExpired() int { return s.n }

// zzProbeHead / zzProbeVerifier count calls, which main_test.go's stubs do not, so
// they are named apart from both of them. The counter is atomic because the loop
// runs on its own goroutine and the test reads it.
type zzProbeHead struct{ calls atomic.Int64 }

func (h *zzProbeHead) Head(context.Context) ([]byte, error) {
	h.calls.Add(1)
	return []byte{0x01, 0x02}, nil
}

type zzProbeVerifier struct{ calls atomic.Int64 }

func (v *zzProbeVerifier) Verify(context.Context) (audit.Verification, error) {
	v.calls.Add(1)
	return audit.Verification{OK: true, Chained: 1}, nil
}

func TestEveryBackgroundLoopReturnsWhenItsContextIsCancelled(t *testing.T) {
	cases := []struct {
		name string
		run  func(ctx context.Context)
	}{
		{"opJanitorLoop", func(ctx context.Context) {
			opJanitorLoop(ctx, zzProbeSweep{}, time.Hour)
		}},
		{"sweepLoop", func(ctx context.Context) {
			sweepLoop(ctx, func(context.Context) (int64, error) { return 0, nil }, time.Hour)
		}},
		{"anchorLoop", func(ctx context.Context) {
			anchorLoop(ctx, &zzProbeHead{}, time.Hour)
		}},
		{"auditVerifyLoop", func(ctx context.Context) {
			auditVerifyLoop(ctx, &zzProbeVerifier{}, observability.New(), time.Hour)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				tc.run(ctx)
				close(done)
			}()
			// Let the loop reach its select before cancelling.
			time.Sleep(10 * time.Millisecond)
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s did not return after its context was cancelled", tc.name)
			}
		})
	}
}

// The anchor loop records the chain head once at startup, not only on its hourly
// tick: a process that restarts often would otherwise never anchor, which is
// exactly the truncation window the anchor exists to close.
func TestTheAnchorLoopAnchorsAtStartupNotOnlyOnTheTick(t *testing.T) {
	head := &zzProbeHead{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		anchorLoop(ctx, head, time.Hour) // the first tick is an hour away
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for head.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if got := head.calls.Load(); got != 1 {
		t.Errorf("the anchor loop called Head %d times at startup, want exactly 1", got)
	}
}

// The verify loop does the same: an hourly walk that only starts an hour after
// boot leaves a fresh deployment with no verification evidence at all.
func TestTheAuditVerifyLoopVerifiesAtStartup(t *testing.T) {
	v := &zzProbeVerifier{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		auditVerifyLoop(ctx, v, observability.New(), time.Hour)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for v.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if got := v.calls.Load(); got != 1 {
		t.Errorf("the verify loop walked the chain %d times at startup, want exactly 1", got)
	}
}

// loopGroup's own semantics are already pinned by main_test.go
// (TestLoopGroupWaitsForTheBodyNotTheCancellation, TestLoopGroupWaitIsImmediate
// WhenEmpty); this file only adds the per-loop context observation above.
