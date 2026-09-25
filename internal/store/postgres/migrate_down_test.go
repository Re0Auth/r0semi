package postgres

import (
	"context"
	"os"
	"testing"
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
