//go:build audit7

// Zone-10 probes that need a real Postgres: the two halves of the audit store
// that the chain does not cover — the per-subject pseudonym cache, and insertions
// into the log.
//
// Both files live in one package on purpose: they share the "open a raw pool so
// the probe can tamper with what the product will not write" helper. Run this
// package alone (-p 1) when a database is available: the probes truncate the
// audit tables, so they must not share TEST_DATABASE_URL with another package's
// tests running concurrently.
package z10adminauditprivacy

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// probeDSN returns TEST_DATABASE_URL, skipping locally and failing in CI where a
// green build must mean the SQL ran. Same policy as internal/store/postgres's own
// fixture.
func probeDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI: the Postgres probes must not silently skip")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping the Postgres probes")
	}
	return dsn
}

// resetAuditTables empties the audit tables through a raw pool and re-seeds the
// chain head, which is what internal/store/postgres's fixture does for the same
// reason: truncating audit_events alone leaves a stale head and the next append
// fails its own verification.
func resetAuditTables(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx,
		`TRUNCATE audit_events, audit_chain, audit_subject_keys CASCADE`); err != nil {
		t.Fatalf("truncate audit tables: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_chain (only_row, head_hash) VALUES (true, '\x'::bytea)`); err != nil {
		t.Fatalf("re-seed chain head: %v", err)
	}
}
