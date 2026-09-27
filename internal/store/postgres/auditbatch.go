package postgres

import (
	"context"
	"errors"
	"sync"
	"time"
)

// The chain head is a single row, and extending the chain takes a row lock on it.
// That serialisation is the design — two writers that each read the same
// predecessor would fork the chain — but it also means every audit write in the
// process waits behind the one in front of it, and vault.Use audits *before* it
// hands over a credential, so the data plane's reads inherit that queue.
//
// Batching does not remove the serialisation; it amortises it. One writer at a
// time still, but one lock acquisition and one round trip for a batch of rows
// instead of one per row. The chain stays a chain because a single goroutine
// drains the queue in order and commits one transaction per batch: the order rows
// are written in is the order they were enqueued, so no row can end up pointing at
// a predecessor that was written after it.
//
// The seam is a function rather than a *pgxpool.Pool, which is what lets the
// queueing — coalescing, ordering, error fan-out, shutdown — be tested without a
// database (see auditbatch_test.go).

const (
	// auditMaxBatch bounds one transaction. Rows beyond it wait for the next
	// batch: a batch is a lock hold, and an unbounded one would make the chain
	// head a long transaction rather than a cheap one.
	auditMaxBatch = 64
	// auditBatchWait is how long the writer waits for company once it has a row.
	// A millisecond is far below any client-visible latency and is enough for
	// concurrent writers to land in one batch.
	auditBatchWait = time.Millisecond
	// auditBatchTimeout bounds the transaction that writes a batch. The caller's
	// context is deliberately detached: the row must land even if the request that
	// produced it is gone, and this is the bound that keeps that from meaning
	// "wait for a pooled connection forever" (the same reasoning as
	// sessions.CommitCtx).
	auditBatchTimeout = 5 * time.Second
	// auditQueueDepth is how many callers may be waiting for a batch. Reaching it
	// means the audit write is the bottleneck; a caller that finds it full waits
	// rather than being refused, because refusing would fail the operation the
	// audit is a precondition of.
	auditQueueDepth = 512
)

// auditBatchItem is one queued row and the channel its caller waits on.
type auditBatchItem struct {
	row  auditRow
	ctx  context.Context
	done chan error
}

// auditBatcher coalesces concurrent appends into one transaction each.
//
// Timing lives in the append function rather than here: it is the function that
// knows how long the lock was held, and observing in both places would count every
// batch twice.
type auditBatcher struct {
	appendFn func(ctx context.Context, rows []auditRow) error

	queue   chan *auditBatchItem
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once

	// mu guards closed: a caller that enqueues after Close must be told, not left
	// waiting for a writer that has returned.
	mu     sync.Mutex
	closed bool
}

// newAuditBatcher starts the writer. appendFn writes a batch in order, in one
// transaction.
func newAuditBatcher(appendFn func(context.Context, []auditRow) error) *auditBatcher {
	b := &auditBatcher{
		appendFn: appendFn,
		queue:    make(chan *auditBatchItem, auditQueueDepth),
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	go b.run()
	return b
}

// enqueue hands one row to the writer and waits until it is durable, the row's
// context is cancelled, or the writer reports its own failure.
//
// A cancelled context means exactly one thing: this caller did not get its row
// confirmed. The row may still land — the writer owns it from the moment it is
// queued — which is why the error is returned rather than swallowed: vault.Use
// withholds the plaintext unless the access is confirmed, and "confirmed" is what
// this return value means.
func (b *auditBatcher) enqueue(ctx context.Context, row auditRow) error {
	// A caller that has already given up is answered before its row is queued, so
	// a cancelled request cannot add work to the log. (A caller whose context is
	// cancelled *while* waiting is the other case: its row may still land, and it
	// is told so by the error.)
	if err := ctx.Err(); err != nil {
		return err
	}

	item := &auditBatchItem{row: row, ctx: ctx, done: make(chan error, 1)}

	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return errors.New("postgres: audit: the log is closed")
	}

	select {
	case b.queue <- item:
	case <-b.stop:
		return errors.New("postgres: audit: the log is closed")
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-item.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run drains the queue until it is closed, then writes what is left.
func (b *auditBatcher) run() {
	defer close(b.stopped)
	for {
		select {
		case <-b.stop:
			b.drain()
			return
		case item := <-b.queue:
			b.flush(item)
		}
	}
}

// drain writes every row already queued, in order, and returns when the queue is
// empty. It runs during shutdown: a queued row is a caller waiting, and dropping
// it would turn a graceful stop into a lost audit record.
func (b *auditBatcher) drain() {
	for {
		select {
		case item := <-b.queue:
			b.flush(item)
		default:
			return
		}
	}
}

// flush writes first plus whatever else is waiting, in one transaction, and
// answers every caller in the batch.
func (b *auditBatcher) flush(first *auditBatchItem) {
	batch := make([]*auditBatchItem, 0, auditMaxBatch)
	batch = append(batch, first)

	// Give the requests already in flight a chance to join this transaction. Once
	// there is nothing left to wait for, go.
	timer := time.NewTimer(auditBatchWait)
	defer timer.Stop()
gather:
	for len(batch) < auditMaxBatch {
		select {
		case item := <-b.queue:
			batch = append(batch, item)
		case <-timer.C:
			break gather
		case <-b.stop:
			break gather
		}
	}

	rows := make([]auditRow, len(batch))
	for i, item := range batch {
		rows[i] = item.row
	}

	// Detached from the callers' cancellation, bounded by this batch's own
	// deadline: see auditBatchTimeout.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(first.ctx), auditBatchTimeout)
	err := b.appendFn(ctx, rows)
	cancel()

	for _, item := range batch {
		item.done <- err
	}
}

// Close stops the writer once it has written everything queued. Calls after it
// returns are refused rather than queued.
func (b *auditBatcher) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	b.mu.Unlock()

	b.once.Do(func() { close(b.stop) })
	<-b.stopped
}
