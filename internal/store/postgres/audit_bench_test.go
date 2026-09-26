package postgres

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// openBenchmarkDB is the shared fixture without the "CI must not skip" rule.
//
// That rule exists so a green *test* build cannot mean "the SQL never ran" — a
// guard that silently skips is worse than no guard. A benchmark is not a guard: it
// reports a number, and a number taken where there is no database does not exist.
// The bench job has no Postgres service, so these skip there; the test job has one
// and runs them, which is where the comparable numbers come from.
func openBenchmarkDB(b *testing.B) *DB {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		b.Skip("TEST_DATABASE_URL is not set; the audit-append measurement needs a database")
	}
	return openTestDBWith(b, DefaultPoolOptions())
}

// BenchmarkAuditAppend and BenchmarkAuditAppendParallel measure the one serialised
// step in the durable path: a chained audit write holds the chain-head row for its
// whole transaction, and it sits on the critical path of every vault-backed read —
// a credential use is audited before the secret is handed over, by design (I3).
//
// They exist so "has the serialisation become the ceiling?" can be answered with a
// number instead of an argument. Read the pair together: if the parallel run's
// ns/op is no better than the serial one, the lock — not the work — is setting the
// rate, and that equality is the inflection. From there, more connections or more
// replicas buy nothing; the conversation becomes about sharding the chain
// (docs/capacity-planning.md §4).
//
// They need a database (TEST_DATABASE_URL) and skip without one, like the rest of
// this package's tests. CI runs them in the job that has a Postgres service; the
// numbers there are the ones to compare across changes.
func BenchmarkAuditAppend(b *testing.B) { benchmarkAuditAppend(b, false) }

// BenchmarkAuditAppendParallel is the one that shows the ceiling: N goroutines
// appending at once against the same chain head.
func BenchmarkAuditAppendParallel(b *testing.B) { benchmarkAuditAppend(b, true) }

func benchmarkAuditAppend(b *testing.B, parallel bool) {
	db := openBenchmarkDB(b)
	logger, err := db.Audit(testAuditKey())
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	event := audit.Event{
		Action: "bench.append", Subject: "usr_bench", Provider: "bench", Outcome: audit.OutcomeOK,
	}

	b.ResetTimer()
	if !parallel {
		for i := 0; i < b.N; i++ {
			if err := logger.Record(ctx, event); err != nil {
				b.Fatal(err)
			}
		}
		return
	}

	// b.Fatal must not be called from a RunParallel goroutine, so the first error
	// is carried out instead of reported in place.
	var mu sync.Mutex
	var firstErr error
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := logger.Record(ctx, event); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}
	})
	if firstErr != nil {
		b.Fatal(firstErr)
	}
}
