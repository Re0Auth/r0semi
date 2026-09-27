//go:build audit5

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"
)

// --- HYPOTHESIS CM-6: a caller can be accepted by the audit batcher after it has
// stopped, and then never answered ---
//
// enqueue checks `closed` under b.mu, releases it, and only then selects on the
// queue:
//
//	b.mu.Lock(); closed := b.closed; b.mu.Unlock()   // (1)
//	if closed { return errors.New(...) }
//	select {
//	case b.queue <- item:                            // (2)
//	case <-b.stop:  return errors.New("closed")
//	}
//	select { case err := <-item.done: ...; case <-ctx.Done(): ... }
//
// Close() sets closed, closes stop, and waits for the writer to drain and return.
// A caller preempted between (1) and (2) for the whole of Close finds both cases of
// its select ready — the queue is buffered, so the send succeeds immediately — and
// Go chooses uniformly at random. The send path puts the row in a channel nobody
// will ever read again, and the caller then blocks on item.done for as long as its
// context lives. memory.OIDCStore.CreateAccessToken, ApproveDevice and DenyDevice
// pass context.Background() to the audit sink (probe CM-2), so for those callers
// that is forever.
//
// The probe below asserts the safe property and PASSES: the window could not be
// hit in 200 trials, because the work between (1) and (2) is a few nanoseconds
// while Close does far more, so a preemption landing exactly there and lasting the
// whole of Close is rare. It is recorded as a hypothesis with the guard in place,
// not as a reproduced defect.

func TestAnEnqueueRacingCloseIsAlwaysAnswered(t *testing.T) {
	const trials = 200
	hung := 0
	for i := 0; i < trials; i++ {
		b := newAuditBatcher(func(context.Context, []auditRow) error { return nil })
		done := make(chan error, 1)
		go func() {
			// A context that never expires: what the in-memory OP store hands the
			// audit sink on the token and device-decision paths.
			done <- b.enqueue(context.Background(), auditRow{Action: "probe"})
		}()
		// Give the caller a chance to pass the closed check before Close runs.
		time.Sleep(50 * time.Microsecond)
		b.Close()

		select {
		case <-done:
		case <-time.After(250 * time.Millisecond):
			hung++
		}
	}
	if hung != 0 {
		t.Errorf("%d of %d calls that raced Close were accepted but never answered; "+
			"a caller with a non-cancellable context blocks forever", hung, trials)
	}
}

// The boundary the window sits just inside of, pinned so the two are read
// together: a call that starts after Close returns is refused, not left waiting.
func TestACallThatStartsAfterCloseIsRefused(t *testing.T) {
	b := newAuditBatcher(func(context.Context, []auditRow) error { return nil })
	b.Close()
	if err := b.enqueue(context.Background(), auditRow{Action: "late"}); err == nil {
		t.Error("a call started after Close was accepted")
	}
}

// A row whose caller has given up is still written: the writer owns it from the
// moment it is queued, which is the contract vault.Use depends on and the reason
// Close can answer "the log is closed" without losing a record.
//
// The interleaving is forced rather than raced: the append function tells the test
// the row is in the batch before the caller's context is cancelled, so "the row
// was never queued" cannot be mistaken for "the row was dropped".
func TestACancelledCallerStillGetsItsRowWritten(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	written := make(chan string, 1)
	b := newAuditBatcher(func(_ context.Context, rows []auditRow) error {
		close(started)
		<-release
		for _, r := range rows {
			written <- r.Action
		}
		return nil
	})
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.enqueue(ctx, auditRow{Action: "detached"}) }()

	<-started // the row is in the batch and the append is running
	cancel()  // the caller gives up

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the caller was answered with %v, want context.Canceled: an unconfirmed row must not be reported as written", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the caller was never answered")
	}

	close(release)
	select {
	case got := <-written:
		if got != "detached" {
			t.Fatalf("wrote %q, want detached", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an accepted row was dropped when its caller gave up")
	}
}

// Close drains what is queued rather than dropping it: a graceful stop must not
// turn a caller that is waiting for its write into a lost record.
func TestCloseWritesRowsThatWereAlreadyQueued(t *testing.T) {
	written := make(chan int, 64)
	b := newAuditBatcher(func(_ context.Context, rows []auditRow) error {
		written <- len(rows)
		return nil
	})
	// Queue without waiting for the answers: the batcher's writer picks these up
	// and Close has to finish them.
	const n = 8
	for i := 0; i < n; i++ {
		go func() { _ = b.enqueue(context.Background(), auditRow{Action: "queued"}) }()
	}
	time.Sleep(20 * time.Millisecond)
	b.Close()

	total := 0
	for {
		select {
		case k := <-written:
			total += k
			if total >= n {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Close left %d of %d queued rows unwritten", n-total, n)
		}
	}
}
