package postgres

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// gooseVersion returns the highest applied migration version.
func gooseVersion(t *testing.T, db *DB) int64 {
	t.Helper()
	var v int64
	if err := db.pool.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&v); err != nil {
		t.Fatalf("read goose version: %v", err)
	}
	return v
}

// MigrateDown rolls back exactly one migration, and Migrate re-applies it. The
// down sections exist; this is the only place they run, so a broken Down would
// otherwise be discovered during the incident it is meant for.
func TestMigrateDownRollsBackOneStep(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI: this test must not silently skip")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres integration test")
	}

	ctx := context.Background()
	db, err := Open(ctx, dsn, DefaultPoolOptions())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	before := gooseVersion(t, db)
	if before == 0 {
		t.Fatal("no migration is applied; there is nothing to roll back")
	}

	if err := MigrateDown(ctx, dsn, DefaultPoolOptions()); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if after := gooseVersion(t, db); after >= before {
		t.Fatalf("version after down = %d, want < %d", after, before)
	}

	// Restore, so the schema is where the rest of the suite expects it.
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	if restored := gooseVersion(t, db); restored != before {
		t.Fatalf("version after re-up = %d, want %d", restored, before)
	}
}

// TestMigrateDownRefusesToDestroyTheAuditChain exercises, against a real
// Postgres, the guard MigrateDown runs before provider.Down (Z21-2 / ADR-0008
// §5). It drives the guard directly rather than through MigrateDown because the
// guard is a pure function of (goose version, one EXISTS query) and reaching
// version 13 through the public API would mean rolling the shared database back
// through a dozen later migrations and re-applying them — a lot of destructive
// work to reach a state this test can create in a schema of its own.
//
// It runs in its own schema so the tables the rest of the suite shares are never
// touched, and it skips wherever TEST_DATABASE_URL is unset.
func TestMigrateDownRefusesToDestroyTheAuditChain(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI: the Postgres integration tests must not silently skip")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres integration test")
	}

	const schema = "migrate_down_chain_test"
	ctx := context.Background()

	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatalf("open admin handle: %v", err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.WithoutCancel(ctx), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})

	// The migrations use unqualified names, so search_path decides where they
	// land. This is the same trick TestAdoptLegacyMigrations uses.
	cfg, err := pgx.ParseConfig(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.RuntimeParams["search_path"] = schema
	sqlDB := stdlib.OpenDB(*cfg)
	defer sqlDB.Close()
	if err := sqlDB.PingContext(ctx); err != nil {
		t.Fatalf("ping schema handle: %v", err)
	}

	dir, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("migrations dir: %v", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, dir)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	// Version 12 predates the chain columns. The guard must not touch
	// audit_events there, or it would fail on a column that does not exist.
	if _, err := provider.UpTo(ctx, 12); err != nil {
		t.Fatalf("apply migrations 1..12: %v", err)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != 12 {
		t.Fatalf("version = %d (%v), want 12", v, err)
	}
	if err := refuseAuditChainRollback(ctx, sqlDB, provider); err != nil {
		t.Errorf("the guard fired before the audit chain exists: %v", err)
	}

	// Version 13 with no chained rows: nothing to protect, so the rollback is
	// allowed. That is what keeps `-migrate-down` usable on a fresh database.
	if _, err := provider.UpTo(ctx, 13); err != nil {
		t.Fatalf("apply migration 13: %v", err)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != 13 {
		t.Fatalf("version = %d (%v), want 13", v, err)
	}
	if err := refuseAuditChainRollback(ctx, sqlDB, provider); err != nil {
		t.Errorf("the guard refused a chain that holds no chained rows: %v", err)
	}

	// One chained row is enough. This is the state 0013's old Down silently
	// destroyed: it dropped row_hash (NULL for every surviving row) and re-seeded
	// the head, after which Verify called the whole log Legacy and returned
	// OK=true.
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO audit_events (occurred_at, action, outcome, row_hash) VALUES (now(), 'test.chained', 'success', '\x01'::bytea)`); err != nil {
		t.Fatalf("insert chained audit row: %v", err)
	}
	err = refuseAuditChainRollback(ctx, sqlDB, provider)
	if err == nil {
		t.Fatal("the guard allowed a rollback of version 13 while a chained row exists")
	}
	for _, want := range []string{"13", "ADR-0008", "backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	// 0014 is refused on the same terms: its Down used to drop the only copy of
	// every per-subject pseudonym key.
	if _, err := provider.UpTo(ctx, 14); err != nil {
		t.Fatalf("apply migration 14: %v", err)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != 14 {
		t.Fatalf("version = %d (%v), want 14", v, err)
	}
	err = refuseAuditChainRollback(ctx, sqlDB, provider)
	if err == nil {
		t.Fatal("the guard allowed a rollback of version 14 while a chained row exists")
	}
	if !strings.Contains(err.Error(), "14") {
		t.Errorf("the version-14 refusal does not name 14: %v", err)
	}

	// And the predicate is the row, not the version: with the chained row gone
	// the refusal lifts, so an operator who genuinely has nothing to lose is not
	// blocked.
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM audit_events`); err != nil {
		t.Fatalf("clear audit_events: %v", err)
	}
	if err := refuseAuditChainRollback(ctx, sqlDB, provider); err != nil {
		t.Errorf("the guard refused with no chained rows left: %v", err)
	}
}
