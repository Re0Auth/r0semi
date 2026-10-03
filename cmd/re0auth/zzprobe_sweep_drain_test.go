//go:build audit5

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/observability"
)

// This file is the round-10 probe for R10-139 / R10-131: the Postgres expiry
// sweep removed at most sweepBatchSize rows per table per 15-minute tick, i.e.
// ~1.11 rows/second/table, while the public /oauth/authorize endpoint can write
// pending rows about 45x faster from a single address and every access token
// minted is an expiring row. The backlog therefore grew without bound.
//
// The fix is a drain: one tick keeps running the bounded, single-transaction
// cycle until it reports nothing left or its time budget is spent.

// r10ReadMain returns cmd/re0auth/main.go, the file being pinned.
func r10ReadMain(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	return string(src)
}

// TestR10TheSweepDrainsWithinATick is the assertion-level red probe: it reads the
// composition root and requires the drain to exist. It compiles against the
// unfixed tree, so the failure is an assertion, not a build error.
func TestR10TheSweepDrainsWithinATick(t *testing.T) {
	src := r10ReadMain(t)
	for _, want := range []string{
		"sweepDrainBudget",
		"drainSweep(ctx",
		"metrics.ObserveSweepSaturated()",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("R10-139/R10-131: cmd/re0auth/main.go has no %q, so one tick still runs exactly one "+
				"bounded cycle per table: sweepBatchSize/interval = 1.11 rows/second/table, below the "+
				"arrival rate of a single anonymous address", want)
		}
	}
	// The 15-minute schedule is a guard the audit6 control pins by literal; it must
	// survive the fix.
	if !strings.Contains(src, "sweepLoop(loopCtx, store.sweep, 15*time.Minute)") {
		t.Fatal("the Postgres sweep is no longer scheduled every 15 minutes")
	}
}

// TestR10DrainSweepDrainsABacklog is the behavioural half: a cycle that keeps
// reporting removals must be run repeatedly until it reports zero.
func TestR10DrainSweepDrainsABacklog(t *testing.T) {
	var pending atomic.Int64
	pending.Store(2500)
	var calls atomic.Int64
	cycle := func(context.Context) (int64, error) {
		calls.Add(1)
		n := pending.Load()
		if n == 0 {
			return 0, nil
		}
		removed := int64(1000)
		if n < removed {
			removed = n
		}
		pending.Add(-removed)
		return removed, nil
	}

	total, err := drainSweep(context.Background(), time.Minute, nil, cycle)
	if err != nil {
		t.Fatalf("drainSweep: %v", err)
	}
	if total != 2500 {
		t.Fatalf("drained %d rows, want 2500", total)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("ran the cycle %d times (1000,1000,500,0), want 4", got)
	}
}

// TestR10DrainSweepStopsAtItsDeadline pins the other half: a store that can never
// catch up must not loop forever or hold the ticker open — it reports saturation
// and returns.
func TestR10DrainSweepStopsAtItsDeadline(t *testing.T) {
	var calls atomic.Int64
	cycle := func(context.Context) (int64, error) {
		calls.Add(1)
		return 1, nil // never drains
	}

	start := time.Now()
	total, err := drainSweep(context.Background(), 120*time.Millisecond, nil, cycle)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("a saturated drain is not an error: %v", err)
	}
	if total < 1 {
		t.Fatalf("drainSweep reported %d rows removed", total)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("a saturated drain ran for %v; the budget must bound it", elapsed)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("the cycle ran %d time(s); a drain must repeat while rows remain", got)
	}
}

// TestR10DrainSweepHonoursCancellation ensures shutdown is not blocked by a
// saturated drain: the existing loop-lifetime probe requires sweepLoop to return
// when its context is cancelled.
func TestR10DrainSweepHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cycle := func(ctx context.Context) (int64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if _, err := drainSweep(ctx, time.Minute, nil, cycle); err == nil {
		t.Fatal("drainSweep ignored a cancelled context")
	}
}

// TestR10SweepSaturationIsObservable pins the signal: a sweep that cannot keep up
// must be visible, not silent.
func TestR10SweepSaturationIsObservable(t *testing.T) {
	m := observability.New()
	m.ObserveSweepSaturated()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	if out := rec.Body.String(); !strings.Contains(out, "re0auth_sweep_saturated_total") {
		t.Fatalf("the saturation counter is not exported:\n%s", out)
	}
}
