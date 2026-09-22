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

// TestMigrationFilesAreGooseShaped guards the migration files without needing a
// database. It asserts the properties goose requires -- an Up annotation first,
// a Down section, and a parseable, strictly increasing version -- so a new file
// that forgets one fails here rather than at first startup against a real
// Postgres, where the failure is a half-migrated database.
func TestMigrationFilesAreGooseShaped(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	seen := make(map[int64]string)
	var last int64
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(body)
		if !strings.HasPrefix(strings.TrimSpace(text), "-- +goose Up") {
			t.Errorf("%s: must start with '-- +goose Up'", name)
		}
		if !strings.Contains(text, "-- +goose Down") {
			t.Errorf("%s: missing a '-- +goose Down' section", name)
		}
		version, err := goose.NumericComponent(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if prev, ok := seen[version]; ok {
			t.Errorf("%s: version %d is already used by %s", name, version, prev)
		}
		if version <= last {
			t.Errorf("%s: version %d is not greater than the previous %d", name, version, last)
		}
		seen[version] = name
		last = version
	}
	if len(seen) == 0 {
		t.Fatal("no migrations are embedded")
	}
}

// TestAdoptLegacyMigrations exercises the one-time bridge from the pre-goose
// `schema_migrations` table to goose's version table, and then lets goose apply
// the migrations the legacy table did not cover. It runs in its own schema, so
// it cannot disturb the tables the other integration tests share, and it skips
// wherever TEST_DATABASE_URL is unset.
func TestAdoptLegacyMigrations(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI: the Postgres integration tests must not silently skip")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres integration tests")
	}

	const schema = "legacy_adopt_test"
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

	// Point a dedicated handle at the scratch schema. The migrations use
	// unqualified table names, so search_path decides where they land.
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

	// Seed the legacy state accurately: really apply migrations 1..3 (as a
	// pre-goose database would have), then rewrite the bookkeeping into the
	// legacy `schema_migrations` shape. The tables exist; only the version
	// table changes.
	dir, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("migrations dir: %v", err)
	}
	firstProvider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, dir)
	if err != nil {
		t.Fatalf("first provider: %v", err)
	}
	if _, err := firstProvider.UpTo(ctx, 3); err != nil {
		t.Fatalf("apply migrations 1..3: %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `DROP TABLE goose_db_version`); err != nil {
		t.Fatalf("drop goose table: %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	for _, v := range []string{"0001_init.sql", "0002_vault.sql", "0003_federation.sql"} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, v); err != nil {
			t.Fatalf("seed %s: %v", v, err)
		}
	}

	// A fresh provider, exactly as a legacy database's first goose-enabled
	// startup would construct one.
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, dir)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if err := adoptLegacyMigrations(ctx, sqlDB, provider); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	var legacyExists bool
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&legacyExists); err != nil {
		t.Fatalf("detect legacy table: %v", err)
	}
	if legacyExists {
		t.Fatal("legacy table survived adoption")
	}

	var adopted int
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT count(*) FROM goose_db_version WHERE is_applied AND version_id IN (1, 2, 3)`).Scan(&adopted); err != nil {
		t.Fatalf("count adopted: %v", err)
	}
	if adopted != 3 {
		t.Fatalf("adopted %d legacy versions, want 3", adopted)
	}

	// Goose should now apply exactly the four migrations the legacy table did
	// not cover, leaving the schema complete.
	results, err := provider.Up(ctx)
	if err != nil {
		t.Fatalf("up: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("goose applied %d migrations, want 4", len(results))
	}

	var tables int
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname = $1`, schema).Scan(&tables); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if tables < 13 {
		t.Fatalf("schema has %d tables, want at least 13", tables)
	}
}
