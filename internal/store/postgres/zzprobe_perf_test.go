//go:build audit5

package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// These probes measure two things about the durable audit path that no test in
// this package asserts, and that the repository's own audit benchmarks cannot
// separate from the database:
//
//   - the batcher's fixed collection window: every caller waits for it, so it is a
//     floor on the latency of every audited request, and the single writer's cycle
//     (window + commit) is a ceiling on the whole process's audit throughput;
//   - the cost of verifying one row of the chain, which is what decides whether
//     `Verify` can finish inside its statement timeout on a large table.
//
// The batcher probes inject the commit cost as a sleep, which is exactly the
// quantity the real Postgres benchmark measures — here it is a parameter, so the
// mechanism's ceiling can be read off a table instead of argued about.

func perfProbeRow(name string) auditRow {
	return auditRow{
		OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		Action:     name,
		Subject:    "pseudo_0123456789abcdef",
		Provider:   "probe",
		Outcome:    audit.OutcomeOK,
		Detail:     map[string]string{"client_id": "probe-client"},
	}
}

// TestPerfProbeAuditBatchLatencyFloor shows that a batch costs its window even
// when the append itself is instantaneous.
//
// It is the reason an audited request cannot be answered faster than the window:
// vault.Use audits before it hands over a credential (invariant I3), so the data
// plane's reads inherit this floor, and so does every token mint and revocation.
func TestPerfProbeAuditBatchLatencyFloor(t *testing.T) {
	instant := func(context.Context, []auditRow) error { return nil }
	b := newAuditBatcher(instant)
	defer b.Close()

	ctx := context.Background()
	const rounds = 20
	var total time.Duration
	var worst time.Duration
	for i := 0; i < rounds; i++ {
		start := time.Now()
		if err := b.enqueue(ctx, perfProbeRow("probe")); err != nil {
			t.Fatal(err)
		}
		d := time.Since(start)
		total += d
		if d > worst {
			worst = d
		}
	}
	mean := total / rounds
	t.Logf("append with an instant commit: mean=%s worst=%s (batcher window=%s)",
		mean.Round(time.Microsecond), worst.Round(time.Microsecond), auditBatchWait)

	if mean < auditBatchWait {
		t.Fatalf("mean append latency %s is below the %s collection window; "+
			"if the window was removed on purpose, update this probe and the note in "+
			"docs/capacity-planning.md §4", mean, auditBatchWait)
	}
}

// BenchmarkPerfProbeAuditBatchCeiling measures the process-wide audit throughput
// the batcher can sustain under a given commit cost. Read the table by row: the
// ceiling is the batch size divided by (window + commit), because one goroutine
// commits one batch at a time.
func BenchmarkPerfProbeAuditBatchCeiling(b *testing.B) {
	for _, commit := range []time.Duration{0, 2 * time.Millisecond, 10 * time.Millisecond} {
		b.Run("commit="+commit.String(), func(b *testing.B) {
			appendFn := func(context.Context, []auditRow) error {
				if commit > 0 {
					time.Sleep(commit)
				}
				return nil
			}
			batcher := newAuditBatcher(appendFn)
			defer batcher.Close()
			ctx := context.Background()

			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := batcher.enqueue(ctx, perfProbeRow("probe")); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

// BenchmarkPerfProbeVerifyRowCost measures the per-row work Verify does: the
// canonical re-encoding, the chain hash and the signature check.
func BenchmarkPerfProbeVerifyRowCost(b *testing.B) {
	logger := &AuditLogger{key: make([]byte, auditChainKeySize)}
	row := perfProbeRow("bench.append")
	prev := make([]byte, 32)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rowHash := chainHash(prev, row.canonical())
		if !hmacEqual(logger.sign(rowHash), logger.sign(rowHash)) {
			b.Fatal("signature mismatch")
		}
		prev = rowHash
	}
}

// hmacEqual mirrors the comparison Verify performs, without importing crypto/hmac
// twice in this file's reasoning.
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPerfProbeVerifyExtrapolation turns the per-row cost into the wall time a
// chain walk needs, and compares it with the bound the walk actually runs under.
//
// The estimate is CPU only: it excludes reading the rows out of Postgres, which
// on a table this size is at least as large a term (the query streams every
// column of every row). So the numbers below are a floor, not a forecast.
func TestPerfProbeVerifyExtrapolation(t *testing.T) {
	logger := &AuditLogger{key: make([]byte, auditChainKeySize)}
	row := perfProbeRow("verify.probe")
	prev := make([]byte, 32)

	const rounds = 20_000
	start := time.Now()
	for i := 0; i < rounds; i++ {
		rowHash := chainHash(prev, row.canonical())
		if !hmacEqual(logger.sign(rowHash), logger.sign(rowHash)) {
			t.Fatal("signature mismatch")
		}
		prev = rowHash
	}
	elapsed := time.Since(start)
	perRow := elapsed / rounds
	rowsPerSecond := float64(rounds) / elapsed.Seconds()
	t.Logf("verify: %s/row, %.0f rows/s single core, statement timeout %s",
		perRow.Round(time.Nanosecond), rowsPerSecond, verifyStatementTimeout)

	for _, rows := range []float64{1e5, 1e6, 1e7, 1e8} {
		cpuOnly := time.Duration(rows / rowsPerSecond * float64(time.Second))
		t.Logf("  %8.0e rows: %s of CPU alone", rows, cpuOnly.Round(time.Second))
	}

	// The guard: at a hundred million rows the walk cannot finish inside its own
	// statement timeout even before the rows are read, so S5 reports `error`
	// rather than either `ok` or `failed`.
	const hundredMillion = 1e8
	if got := time.Duration(hundredMillion / rowsPerSecond * float64(time.Second)); got <= verifyStatementTimeout {
		t.Fatalf("100M rows estimated at %s, which is inside the %s timeout; "+
			"the capacity note about Verify needs revisiting", got, verifyStatementTimeout)
	}
}

// TestPerfProbeAuditBatchIsSingleWriter shows the serialization directly: one
// goroutine commits one batch at a time, so the whole process's audit throughput
// is `64 / commit latency` however many callers are waiting. The table this prints
// is what "has the chain become the ceiling?" is answered from, without needing a
// database: the commit latency is the parameter, and the audit append duration
// histogram (`re0auth_audit_append_duration_seconds`) is where an operator reads
// the real value off.
func TestPerfProbeAuditBatchIsSingleWriter(t *testing.T) {
	const (
		writers = 64
		each    = 50
	)
	for _, commit := range []time.Duration{time.Millisecond, 5 * time.Millisecond, 20 * time.Millisecond} {
		var mu sync.Mutex
		var batches, rows int
		appendFn := func(_ context.Context, batch []auditRow) error {
			time.Sleep(commit)
			mu.Lock()
			batches++
			rows += len(batch)
			mu.Unlock()
			return nil
		}
		batcher := newAuditBatcher(appendFn)

		ctx := context.Background()
		start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < each; j++ {
					if err := batcher.enqueue(ctx, perfProbeRow("probe")); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)
		batcher.Close()

		mu.Lock()
		gotBatches, gotRows := batches, rows
		mu.Unlock()
		if gotRows != writers*each {
			t.Fatalf("wrote %d rows, want %d", gotRows, writers*each)
		}
		rate := float64(gotRows) / elapsed.Seconds()
		// Saturated, the queue is always deep enough to fill a batch, so the cycle
		// is the commit alone and the window costs nothing: this is the process-wide
		// ceiling, and more callers cannot raise it.
		ceiling := float64(auditMaxBatch) / commit.Seconds()
		avgBatch := float64(gotRows) / float64(gotBatches)
		t.Logf("commit=%-6s %5d rows in %4d batches over %8s = %7.0f rows/s (avg batch %.1f, ceiling %7.0f rows/s)",
			commit, gotRows, gotBatches, elapsed.Round(time.Millisecond), rate, avgBatch, ceiling)
		if avgBatch < float64(auditMaxBatch) {
			t.Fatalf("average batch %.1f is below the %d a saturated queue should fill; "+
				"the single-writer model in docs/capacity-planning.md §4 no longer holds", avgBatch, auditMaxBatch)
		}
		if rate > ceiling*1.2 {
			t.Fatalf("achieved %.0f rows/s, above the %.0f rows/s one committing writer can reach; "+
				"the batching model in docs/capacity-planning.md §4 is wrong", rate, ceiling)
		}
	}
}
