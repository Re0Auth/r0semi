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

// splitMigrationDirections separates a migration file's Up section from its Down
// section, and stripMigrationComments removes `-- ...` line comments. The Down
// guard below needs both: the point of 0013/0014's Down is that the text that
// remains after stripping comments executes nothing, and a probe that read the
// doc comments as SQL could not tell that.
func splitMigrationDirections(body string) (up, down string) {
	if i := strings.Index(body, "-- +goose Down"); i >= 0 {
		return body[:i], body[i:]
	}
	return body, ""
}

func stripMigrationComments(body string) string {
	out := make([]string, 0, 64)
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// functionBody returns the source of the top-level function whose declaration
// starts with signature, up to the next top-level `func`. It is how the Go half
// of the guard below is scoped to the function it is about.
func functionBody(t *testing.T, src, signature string) string {
	t.Helper()
	i := strings.Index(src, signature)
	if i < 0 {
		t.Fatalf("postgres.go no longer declares %q", signature)
	}
	rest := src[i:]
	if j := strings.Index(rest[1:], "\nfunc "); j >= 0 {
		return rest[:j+1]
	}
	return rest
}

// TestAuditIntegrityMigrationsCannotBeRolledBack is the database-free guard for
// Z21-2 and ADR-0008 §5. It pins both halves of the fix:
//
//   - the shipped SQL: 0013's and 0014's Down sections execute nothing after
//     their comments are stripped, and both Ups are idempotent, because goose
//     deletes the version row for a Down that runs no statements and the next
//     Open() re-runs the Up against schema that already exists;
//   - the Go that refuses: MigrateDown calls refuseAuditChainRollback, which
//     fires for versions 13 and 14 exactly when a row with a non-NULL row_hash
//     survives.
//
// The failure it prevents is silent: the old Down dropped the chain columns and
// re-seeded the head, so after one Down/Up cycle every historical row read back
// as Legacy while Verify still returned OK=true.
func TestAuditIntegrityMigrationsCannotBeRolledBack(t *testing.T) {
	// Anti-vacuous control: the comment stripper must not be emptying every
	// Down section, or the "executes nothing" check below could never fail.
	control, err := fs.ReadFile(migrationsFS, "migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("read 0001_init.sql: %v", err)
	}
	_, controlDown := splitMigrationDirections(string(control))
	if strings.TrimSpace(stripMigrationComments(controlDown)) == "" {
		t.Fatal("control failed: the stripper emptied a Down section that does contain DDL")
	}

	for _, name := range []string{"0013_audit_chain.sql", "0014_audit_pseudonyms.sql"} {
		body, err := fs.ReadFile(migrationsFS, "migrations/"+name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		up, down := splitMigrationDirections(string(body))
		if strings.TrimSpace(down) == "" {
			t.Fatalf("%s: no Down section; this probe is reading the wrong text", name)
		}
		if rest := strings.TrimSpace(stripMigrationComments(down)); rest != "" {
			t.Errorf("%s: the Down section executes SQL (%q). This step is not reversible "+
				"(ADR-0008 §5): any DDL here drops the audit chain's hash columns, the chain "+
				"head or the only copy of the per-subject pseudonym keys, and re-applying the "+
				"Up cannot restore any of them. Keep the section comment-only and explain why.",
				name, rest)
		}

		upNoComments := strings.ToUpper(stripMigrationComments(up))

		// Every ADD COLUMN / CREATE TABLE / CREATE UNIQUE INDEX in the Up must be
		// the idempotent form. An empty Down means the next Open() re-runs the Up,
		// so a bare statement here is a startup failure waiting for the first
		// rollback: `column "row_hash" of relation "audit_events" already exists`.
		for _, pair := range []struct{ bare, idempotent string }{
			{"ADD COLUMN", "ADD COLUMN IF NOT EXISTS"},
			{"CREATE TABLE", "CREATE TABLE IF NOT EXISTS"},
			{"CREATE UNIQUE INDEX", "CREATE UNIQUE INDEX IF NOT EXISTS"},
		} {
			got, want := strings.Count(upNoComments, pair.bare), strings.Count(upNoComments, pair.idempotent)
			if got != want {
				t.Errorf("%s: the Up has %d %q statement(s) but only %d use %q; after a no-op "+
					"Down the next Open() re-runs the Up and a bare statement aborts with "+
					"`already exists`", name, got, pair.bare, want, pair.idempotent)
			}
		}

		if name == "0013_audit_chain.sql" {
			for _, want := range []string{
				"ALTER TABLE AUDIT_EVENTS ADD COLUMN IF NOT EXISTS PREV_HASH",
				"ALTER TABLE AUDIT_EVENTS ADD COLUMN IF NOT EXISTS ROW_HASH",
				"ALTER TABLE AUDIT_EVENTS ADD COLUMN IF NOT EXISTS SIGNATURE",
				"CREATE UNIQUE INDEX IF NOT EXISTS AUDIT_EVENTS_ROW_HASH_IDX",
				"CREATE TABLE IF NOT EXISTS AUDIT_CHAIN",
				"ON CONFLICT (ONLY_ROW) DO NOTHING",
			} {
				if !strings.Contains(upNoComments, want) {
					t.Errorf("%s: Up no longer contains %q; the Up must stay idempotent and must "+
						"not rewind a surviving chain head to the genesis hash", name, want)
				}
			}
		}
		if name == "0014_audit_pseudonyms.sql" {
			if !strings.Contains(upNoComments, "CREATE TABLE IF NOT EXISTS AUDIT_SUBJECT_KEYS") {
				t.Errorf("%s: Up is no longer `CREATE TABLE IF NOT EXISTS audit_subject_keys`", name)
			}
		}
	}

	src, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatalf("read postgres.go: %v", err)
	}
	text := string(src)

	downBody := functionBody(t, text, "func MigrateDown(")
	if !strings.Contains(downBody, "refuseAuditChainRollback(ctx, sqlDB, provider)") {
		t.Errorf("MigrateDown no longer calls refuseAuditChainRollback(ctx, sqlDB, provider) before " +
			"provider.Down: an empty Down protects the goose CLI but nothing stops `-migrate-down` " +
			"from stepping through 0013/0014 without the operator being told it is irreversible")
	}

	guard := functionBody(t, text, "func refuseAuditChainRollback(")
	for _, want := range []string{
		"provider.GetDBVersion(ctx)",
		"version != migrationAuditChain && version != migrationAuditPseudonyms",
		"FROM audit_events WHERE row_hash IS NOT NULL",
		"refusing to roll back migration %d",
	} {
		if !strings.Contains(guard, want) {
			t.Errorf("refuseAuditChainRollback no longer contains %q; the refusal must guard "+
				"versions 13 and 14 on surviving chained rows", want)
		}
	}
	// The guard is only about 13 and 14 if those constants still say so.
	flat := strings.Join(strings.Fields(text), " ")
	for _, want := range []string{"migrationAuditChain = 13", "migrationAuditPseudonyms = 14"} {
		if !strings.Contains(flat, want) {
			t.Errorf("postgres.go no longer declares %q; the refusal no longer guards the "+
				"audit-integrity migrations", want)
		}
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

	// Goose should now apply exactly the migrations the legacy table did not
	// cover (everything after version 3).
	entries, err := fs.ReadDir(dir, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var total int
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			total++
		}
	}
	results, err := provider.Up(ctx)
	if err != nil {
		t.Fatalf("up: %v", err)
	}
	if len(results) != total-3 {
		t.Fatalf("goose applied %d migrations, want %d", len(results), total-3)
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
