package postgres

// The append batcher is where the audit chain's serialisation is amortised, and
// it is deliberately decoupled from Postgres: appendFn is a plain function, so
// everything that could go wrong in the queue — lost rows, reordered rows,
// unbounded batches, a row dropped at shutdown — is asserted here rather than
// behind a database. The SQL itself is exercised by auditchain_test.go under
// TEST_DATABASE_URL.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a fake append function: it keeps every batch it was given, counts
// its calls, and can be made slow (so callers pile up and coalesce) or fallible.
type recorder struct {
	mu      sync.Mutex
	batches [][]string
	delay   time.Duration
	err     error
	gate    chan struct{}
}

func (r *recorder) append(_ context.Context, rows []auditRow) error {
	if r.gate != nil {
		<-r.gate
	}
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	batch := make([]string, len(rows))
	for i, row := range rows {
		batch[i] = row.Action
	}
	r.batches = append(r.batches, batch)
	return r.err
}

func (r *recorder) flatten() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, batch := range r.batches {
		out = append(out, batch...)
	}
	return out
}

func (r *recorder) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

func (r *recorder) largestBatch() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	largest := 0
	for _, batch := range r.batches {
		if len(batch) > largest {
			largest = len(batch)
		}
	}
	return largest
}

func rowNamed(name string) auditRow {
	return auditRow{OccurredAt: time.Unix(0, 0).UTC(), Action: name, Outcome: "ok"}
}

// Concurrent writers must all be answered and none lost, and the batch must be
// shared: the point of the batcher is that N callers cost one transaction.
//
// The order rows are written in is not asserted here, because it is not a property
// this level can have: concurrent callers reach the queue in whatever order the
// scheduler puts them, and the batcher's job is to record that order faithfully.
// TestBatcherWritesInCallOrder pins the ordering that *is* guaranteed.
func TestBatcherCoalescesConcurrentWriters(t *testing.T) {
	rec := &recorder{delay: 2 * time.Millisecond}
	b := newAuditBatcher(rec.append)
	defer b.Close()

	const writers = 100
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = b.enqueue(context.Background(), rowNamed(fmt.Sprintf("row-%03d", i)))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	got := rec.flatten()
	if len(got) != writers {
		t.Fatalf("rows written = %d, want %d", len(got), writers)
	}
	seen := make(map[string]bool, writers)
	for _, name := range got {
		if seen[name] {
			t.Fatalf("row %q was written twice", name)
		}
		seen[name] = true
	}
	if calls := rec.calls(); calls >= writers {
		t.Fatalf("append calls = %d for %d concurrent rows: nothing was coalesced", calls, writers)
	}
}

// Rows are written in the order the batcher accepted them, which is what each
// row's prev_hash is computed from: a reordered batch would produce a chain that
// verifies as broken.
func TestBatcherWritesInCallOrder(t *testing.T) {
	rec := &recorder{delay: time.Millisecond}
	b := newAuditBatcher(rec.append)
	defer b.Close()

	const rows = 20
	for i := 0; i < rows; i++ {
		if err := b.enqueue(context.Background(), rowNamed(fmt.Sprintf("row-%03d", i))); err != nil {
			t.Fatal(err)
		}
	}
	got := rec.flatten()
	if len(got) != rows {
		t.Fatalf("rows written = %d, want %d", len(got), rows)
	}
	for i, name := range got {
		if want := fmt.Sprintf("row-%03d", i); name != want {
			t.Fatalf("row %d = %q, want %q", i, name, want)
		}
	}
}

// A batch is a lock hold, so it is bounded. Writers beyond the bound wait for the
// next transaction rather than extending this one.
func TestBatcherBoundsBatchSize(t *testing.T) {
	gate := make(chan struct{})
	rec := &recorder{gate: gate}
	b := newAuditBatcher(rec.append)
	defer b.Close()

	const writers = auditMaxBatch*2 + 5
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := b.enqueue(context.Background(), rowNamed("row-"+strconv.Itoa(i))); err != nil {
				t.Errorf("enqueue: %v", err)
			}
		}(i)
	}
	// Let the writers fill the queue, then release the batches.
	for i := 0; i < 100; i++ {
		if len(rec.flatten()) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(gate)
	wg.Wait()

	if got := len(rec.flatten()); got != writers {
		t.Fatalf("rows written = %d, want %d", got, writers)
	}
	if largest := rec.largestBatch(); largest > auditMaxBatch {
		t.Fatalf("largest batch = %d, want at most %d", largest, auditMaxBatch)
	}
}

// A failed transaction fails every caller whose row was in it. Nobody is told a
// row is durable when it is not: that is the contract vault.Use relies on to
// withhold a secret.
func TestBatcherFansOutAnAppendFailure(t *testing.T) {
	boom := errors.New("connection refused")
	rec := &recorder{delay: 2 * time.Millisecond, err: boom}
	b := newAuditBatcher(rec.append)
	defer b.Close()

	const writers = 10
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = b.enqueue(context.Background(), rowNamed("row-"+strconv.Itoa(i)))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, boom) {
			t.Fatalf("writer %d error = %v, want the append failure", i, err)
		}
	}

	// The batcher is still usable: a transient database failure must not take the
	// audit log down for the life of the process.
	rec.mu.Lock()
	rec.err = nil
	rec.mu.Unlock()
	if err := b.enqueue(context.Background(), rowNamed("after")); err != nil {
		t.Fatalf("enqueue after a failure: %v", err)
	}
}

// Close waits for the row it already accepted. A queued row is a caller waiting
// for its write confirmed, and a graceful stop must not turn that into a lost
// record. Callers that arrive after Close are refused rather than left waiting for
// a writer that has returned — see the assertion at the end.
func TestBatcherCloseDrainsAnAcceptedRow(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	rec := &recorder{}
	b := newAuditBatcher(func(ctx context.Context, rows []auditRow) error {
		close(started)
		<-release
		return rec.append(ctx, rows)
	})

	done := make(chan error, 1)
	go func() { done <- b.enqueue(context.Background(), rowNamed("accepted")) }()
	<-started // the row is accepted and its batch is being written

	closed := make(chan struct{})
	go func() {
		b.Close()
		close(closed)
	}()
	close(release)

	if err := <-done; err != nil {
		t.Fatalf("an accepted row was not written: %v", err)
	}
	<-closed
	if got := rec.flatten(); len(got) != 1 || got[0] != "accepted" {
		t.Fatalf("rows written = %v, want the accepted one", got)
	}
	// A call after Close is refused, not left hanging against a stopped writer.
	if err := b.enqueue(context.Background(), rowNamed("late")); err == nil {
		t.Fatal("enqueue after Close was accepted")
	}
	if got := rec.flatten(); len(got) != 1 {
		t.Fatalf("a row was written after Close: %v", got)
	}
}

// A caller that has already given up does not hold a slot: the row is not
// accepted, and the batcher stays usable.
func TestBatcherRefusesACancelledCaller(t *testing.T) {
	rec := &recorder{}
	b := newAuditBatcher(rec.append)
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.enqueue(ctx, rowNamed("cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("enqueue with a cancelled context = %v, want context.Canceled", err)
	}
	if err := b.enqueue(context.Background(), rowNamed("live")); err != nil {
		t.Fatalf("enqueue after a cancelled caller: %v", err)
	}
	if got := rec.flatten(); len(got) != 1 || got[0] != "live" {
		t.Fatalf("rows written = %v, want just the live one", got)
	}
}

// The write is detached from the caller's cancellation: a request that hangs up
// mid-append must not cancel the transaction that records what it did. The caller
// is still told its row is unconfirmed — that is the fail-closed half — while the
// append that already started runs to completion on its own bound.
func TestBatcherWritesWithADetachedContext(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	// The append reports what it saw through a channel rather than a shared
	// variable. Sharing one would race: the caller can be answered from its own
	// cancellation while the append it queued is still running, so "the caller
	// returned" does not mean "the append finished".
	type view struct {
		err         error
		hasDeadline bool
	}
	observed := make(chan view, 1)
	b := newAuditBatcher(func(ctx context.Context, _ []auditRow) error {
		close(started)
		<-release
		// Sampled while the append is running: once it returns, flush cancels this
		// context on purpose, which says nothing about the caller's cancellation.
		_, hasDeadline := ctx.Deadline()
		observed <- view{err: ctx.Err(), hasDeadline: hasDeadline}
		return nil
	})
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.enqueue(ctx, rowNamed("detached")) }()

	<-started // the append is under way
	cancel()  // the caller hangs up
	close(release)

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the caller was answered %v, want context.Canceled: an unconfirmed row must not read as durable", err)
	}
	got := <-observed
	if got.err != nil {
		t.Fatalf("the append inherited the caller's cancellation: %v", got.err)
	}
	if !got.hasDeadline {
		t.Fatal("the append ran without a deadline, so a stuck transaction would never be cut")
	}
}

// The queue is bounded: a caller that finds it full waits, and is still answered
// once room appears. It is not refused, because refusing would fail the operation
// the audit is a precondition of.
func TestBatcherQueueIsBoundedButNeverRefuses(t *testing.T) {
	gate := make(chan struct{})
	rec := &recorder{gate: gate}
	b := newAuditBatcher(rec.append)
	defer b.Close()

	const writers = auditQueueDepth + 50
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := b.enqueue(context.Background(), rowNamed("row-"+strconv.Itoa(i))); err != nil {
				t.Errorf("enqueue %d: %v", i, err)
			}
		}(i)
	}
	close(gate)
	wg.Wait()

	if got := len(rec.flatten()); got != writers {
		t.Fatalf("rows written = %d, want %d", got, writers)
	}
}

// A batch is written in one call and the rows inside it keep their order, which is
// what each row's prev_hash is computed from.
func TestBatcherWritesABatchInOrder(t *testing.T) {
	rec := &recorder{delay: time.Millisecond}
	b := newAuditBatcher(rec.append)
	defer b.Close()

	for i := 0; i < 5; i++ {
		if err := b.enqueue(context.Background(), rowNamed("solo-"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.flatten(); strings.Join(got, ",") != "solo-0,solo-1,solo-2,solo-3,solo-4" {
		t.Fatalf("rows = %v, want them in order", got)
	}
}
