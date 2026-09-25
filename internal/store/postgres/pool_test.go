package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The test DSN is parsed, never dialled: building the configuration is a pure
// function, which is why these assertions need no database.
const poolTestDSN = "postgres://user:pass@127.0.0.1:5432/re0auth?sslmode=disable"

// Every bound must actually reach the driver. None of them is visible when it is
// wrong — a missing statement timeout looks exactly like a query that happened to
// be fast, and an unbounded pool looks exactly like a quiet one — so the mapping
// is asserted rather than read.
func TestPoolConfigAppliesEveryBound(t *testing.T) {
	cfg, err := poolConfig(poolTestDSN, DefaultPoolOptions())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.MaxConns != 16 {
		t.Errorf("MaxConns = %d, want 16", cfg.MaxConns)
	}
	if cfg.MinConns != 2 {
		t.Errorf("MinConns = %d, want 2", cfg.MinConns)
	}
	if cfg.ConnConfig.ConnectTimeout != 5*time.Second {
		t.Errorf("ConnectTimeout = %v, want 5s", cfg.ConnConfig.ConnectTimeout)
	}
	if cfg.MaxConnLifetime != time.Hour {
		t.Errorf("MaxConnLifetime = %v, want 1h", cfg.MaxConnLifetime)
	}
	if cfg.MaxConnIdleTime != 30*time.Minute {
		t.Errorf("MaxConnIdleTime = %v, want 30m", cfg.MaxConnIdleTime)
	}
	if cfg.HealthCheckPeriod != time.Minute {
		t.Errorf("HealthCheckPeriod = %v, want 1m", cfg.HealthCheckPeriod)
	}
	// Postgres takes statement_timeout in milliseconds as a string.
	if got := cfg.ConnConfig.RuntimeParams["statement_timeout"]; got != "30000" {
		t.Errorf("statement_timeout = %q, want %q", got, "30000")
	}
}

// A non-positive statement timeout is a deliberate "leave the server's setting
// alone", so nothing is sent. It is not the same as the default.
func TestPoolConfigOmitsStatementTimeoutWhenUnset(t *testing.T) {
	opts := DefaultPoolOptions()
	opts.StatementTimeout = 0

	cfg, err := poolConfig(poolTestDSN, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cfg.ConnConfig.RuntimeParams["statement_timeout"]; ok {
		t.Errorf("statement_timeout = %q, want it to be absent", got)
	}
}

// The zero PoolOptions is a bounded configuration rather than a silently
// unbounded one: where a zero cannot mean anything — a pool with no connections,
// a connect that never times out — the default is filled in.
//
// MinConns and StatementTimeout are deliberately passed through, because for them
// zero is a choice rather than an omission. The last assertion is what keeps this
// test from passing vacuously: it is only meaningful because their defaults are
// non-zero, so a zero surviving normalization is evidence of a decision.
func TestPoolOptionsNormalizedFillsOnlyWhatCannotBeZero(t *testing.T) {
	got := PoolOptions{}.normalized()
	d := DefaultPoolOptions()

	if got.MaxConns != d.MaxConns || got.ConnectTimeout != d.ConnectTimeout ||
		got.MaxConnLifetime != d.MaxConnLifetime || got.MaxConnIdleTime != d.MaxConnIdleTime ||
		got.HealthCheckPeriod != d.HealthCheckPeriod {
		t.Fatalf("zero value normalized to %+v; the unbounded fields were not filled from %+v", got, d)
	}
	if got.MinConns != 0 {
		t.Errorf("MinConns = %d, want 0 passed through (no warm connections is a choice)", got.MinConns)
	}
	if got.StatementTimeout != 0 {
		t.Errorf("StatementTimeout = %v, want 0 passed through", got.StatementTimeout)
	}
	if d.MinConns == 0 || d.StatementTimeout == 0 {
		t.Fatal("the defaults for MinConns and StatementTimeout are zero, so the pass-through proves nothing")
	}
}

func TestPoolOptionsNormalizedClampsMinConns(t *testing.T) {
	got := PoolOptions{MaxConns: 4, MinConns: 99}.normalized()
	if got.MinConns != 4 {
		t.Fatalf("MinConns = %d, want it clamped to MaxConns (4)", got.MinConns)
	}

	negative := PoolOptions{MinConns: -1}.normalized()
	if negative.MinConns != 0 {
		t.Fatalf("MinConns = %d, want 0", negative.MinConns)
	}
}

// A value that is not positive is skipped, so a deliberate "no statement
// timeout" is never turned into a negative millisecond count and sent.
func TestPoolOptionsNegativeStatementTimeoutIsNotSent(t *testing.T) {
	cfg, err := poolConfig(poolTestDSN, PoolOptions{StatementTimeout: -time.Second}.normalized())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cfg.ConnConfig.RuntimeParams["statement_timeout"]; ok {
		t.Errorf("statement_timeout = %q, want it to be absent", got)
	}
}

// PoolStats must reflect the pool's configuration: it is what the metrics layer
// exports, and *pgxpool.Stat has to satisfy observability.PoolStats for the
// composition root to compile at all. The pool is built from a DSN that is never
// dialled — pgxpool connects lazily — so this needs no database.
func TestPoolStatsReflectsPoolConfig(t *testing.T) {
	opts := DefaultPoolOptions()
	opts.MinConns = 0 // do not open any connection at construction
	cfg, err := poolConfig(poolTestDSN, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	if got := (&DB{pool: pool}).PoolStats().MaxConns(); got != 16 {
		t.Errorf("PoolStats().MaxConns() = %d, want 16", got)
	}
}
