package postgres

import (
	"context"
	"os"
	"testing"
	"time"
)

// A pool whose only connection is busy must make the next caller fail fast (at
// its context deadline) rather than hang. That is the whole reason the
// per-request context exists; a pool that blocks forever turns one slow query
// into an outage.
//
// The pool is pinned to a single connection so the exhaustion is deterministic.
// Migrations run on their own connection during Open, so the pool is only
// exhausted after the database is ready.
func TestPoolExhaustionFailsFast(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI: this test must not silently skip")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres integration test")
	}

	ctx := context.Background()
	db, err := Open(ctx, dsn, PoolOptions{MaxConns: 1, MinConns: 0})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	// Hold the single connection.
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if got := db.pool.Stat().AcquiredConns(); got != 1 {
		t.Fatalf("AcquiredConns = %d, want 1 while the sole connection is held", got)
	}

	// A store call now has to wait for a connection. With a short deadline it must
	// return promptly rather than block (the pool has no statement timeout here,
	// so without the context it would wait indefinitely).
	waitCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = db.Bindings().Get(waitCtx, "usr_x", "game", "source")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a query against a saturated pool returned no error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("a query against a saturated pool blocked for %v; it must fail at its deadline", elapsed)
	}

	// Release and confirm the pool recovers.
	conn.Release()
	if err := db.Ping(ctx); err != nil {
		t.Fatalf("pool did not recover after the connection was released: %v", err)
	}
}
