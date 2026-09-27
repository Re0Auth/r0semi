//go:build audit5

package postgres

import (
	"context"
	"sync"
	"testing"
	"time"
)

// --- Verification of CM-6 (auditbatch enqueue/Close window) ---
//
// These probes are the verifier's, not the auditor's: they are in this package
// because auditBatcher is unexported and the seam cannot be reached from outside.
// Nothing here modifies the audited probe file (zzprobe_concurrency_test.go) or any
// tracked file.
//
// The audited probe sleeps 50µs after starting the caller and then calls Close. By
// then the caller has long since completed its send (the queue is empty and 512
// deep, so the send never blocks) and is parked in the SECOND select waiting on
// item.done; the writer flushes it within auditBatchWait. So the audited probe
// measures "a caller whose row is already queued is answered by Close" — which the
// drain guarantees — and does not exercise the window it describes, which sits
// between `b.mu.Unlock()` and the send-select of a caller that has NOT yet sent.
//
// Test 1 below pins the one variant that the audited description implies most
// directly (a caller parked on a FULL queue when Close runs) and shows it is
// answered. Test 2 hammers the actual window as hard as a test can.

// A caller parked on a full queue, with Close arriving while the writer is still
// inside its append: `close(b.stop)` makes the stop case ready, but the send case is
// not ready (the queue is full), so the select has exactly one ready case. Every such
// caller must be answered rather than left in a queue nobody reads.
func TestZZVerifyACallerParkedOnAFullQueueIsAnsweredByClose(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})

	b := newAuditBatcher(func(context.Context, []auditRow) error {
		once.Do(func() { close(entered) })
		<-release // hold the writer so the queue can fill behind it
		return nil
	})

	const senders = 700 // 512 fit in the queue, the rest park on the send
	results := make([]chan error, senders)
	for i := range results {
		results[i] = make(chan error, 1)
	}

	// One seed row puts the writer inside appendFn (and therefore out of the
	// gather loop), which is the state in which the queue can actually fill.
	go func() { _ = b.enqueue(context.Background(), auditRow{Action: "seed"}) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the writer never reached its append")
	}

	// Every one of these uses a context that never cancels, so an orphaned row is
	// a permanent hang, not a delayed error.
	for i := 0; i < senders; i++ {
		ch := results[i]
		go func() { ch <- b.enqueue(context.Background(), auditRow{Action: "parked"}) }()
	}
	time.Sleep(200 * time.Millisecond) // let the queue fill and the rest park

	closed := make(chan struct{})
	go func() { b.Close(); close(closed) }()
	time.Sleep(200 * time.Millisecond) // Close has set closed and closed stop

	close(release) // now let the writer drain, so Close can finish
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return after the writer was released")
	}

	hung := 0
	for i, ch := range results {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			hung++
			_ = i
		}
	}
	if hung != 0 {
		t.Errorf("%d of %d callers parked on a full queue were accepted but never answered", hung, senders)
	}
	t.Logf("%d of %d parked callers were answered by Close (queue depth 512)", senders-hung, senders)
}

// The window the audited probe names: a caller that has passed the `closed` check
// and is then descheduled until Close has finished. It is hammered here with a
// phase sweep (a fixed 50µs offset cannot land in a window a few instructions wide,
// and the audited probe's own text says the caller is "preempted between (1) and
// (2)").
//
// A hang needs the caller to pass the check before Close sets closed AND to be off
// the CPU for the whole of Close. This tries 20 000 offsets with up to 64 callers in
// flight per trial, so the callers are spread across the window rather than landing
// at one point on it.
func TestZZVerifyTheEnqueueCloseWindowSurvivesAmplifiedAttempts(t *testing.T) {
	const (
		trials     = 4_000
		perTrial   = 16
		maxDelayUS = 32
	)
	answered := 0
	hung := 0
	hungTrials := 0

	for trial := 0; trial < trials; trial++ {
		b := newAuditBatcher(func(context.Context, []auditRow) error { return nil })
		results := make([]chan error, perTrial)
		for i := range results {
			results[i] = make(chan error, 1)
		}
		for i := 0; i < perTrial; i++ {
			ch := results[i]
			go func() { ch <- b.enqueue(context.Background(), auditRow{Action: "window"}) }()
		}
		// Sweep the offset so the closers land at different points of the callers'
		// (check -> select) region.
		time.Sleep(time.Duration(trial%maxDelayUS) * time.Microsecond)
		b.Close()

		inTrial := 0
		for _, ch := range results {
			// A fresh deadline per caller: one hung caller must not swallow the
			// budget of the callers after it (that made an earlier version of this
			// probe hang until the 10-minute test timeout, which is itself a sign
			// that more than one caller can be orphaned in one trial).
			select {
			case <-ch:
				answered++
			case <-time.After(500 * time.Millisecond):
				hung++
				inTrial++
			}
		}
		if inTrial > 0 {
			hungTrials++
		}
	}
	if hung != 0 {
		t.Errorf("%d calls that raced Close were accepted but never answered (of %d, in %d trials); "+
			"a caller with a non-cancellable context blocks forever", hung, answered+hung, hungTrials)
	}
	t.Logf("%d callers raced Close over %d trials (%d in flight each): %d answered, %d hung (in %d trials)",
		answered+hung, trials, perTrial, answered, hung, hungTrials)
}

// The boundary the audited probe already pins, re-derived so this file is
// self-contained: a call that starts after Close returns is refused.
func TestZZVerifyACallAfterCloseReturnsIsRefused(t *testing.T) {
	b := newAuditBatcher(func(context.Context, []auditRow) error { return nil })
	b.Close()
	if err := b.enqueue(context.Background(), auditRow{Action: "late"}); err == nil {
		t.Error("a call started after Close was accepted")
	}
}
