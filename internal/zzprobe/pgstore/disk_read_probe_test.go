//go:build audit5

package pgstore

// disk_read_probe_test.go is the anti-vacuous half of every claim in this
// package: it proves the probes read the shipped migration SQL **from disk**, and
// that they fail when what is on disk is wrong.
//
// Reading from disk is the mechanism this audit uses (see helpers_test.go):
//
//   - the probes are in `internal/zzprobe/pgstore`, so `go test` runs them with
//     that package directory as the working directory;
//   - the schema is therefore at `filepath.Join("..", "..", "store", "postgres",
//     "migrations", "*.sql")` — the constant `migrationsDir` in helpers_test.go,
//     the same string `filepath.Glob` is called with;
//   - every parser takes a directory parameter (`indexLeadingColsIn`,
//     `probeTableColsIn`, `migrationFilesIn`), which is what lets this file point
//     them at a damaged copy and require them to notice.
//
// Nothing is embedded, copied into the probe package, or exported from
// internal/store/postgres: the shipped package is not modified by this audit at
// all.
//
// Each test below is a control in both directions. It first requires the probe to
// pass on the real schema (so "it failed on the damaged copy" cannot be a probe
// that always fails), then requires it to fail on a one-edit mutation of that
// schema (so it cannot be a probe that always passes).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stagingMigrations copies the shipped migrations into a temp directory so a
// mutation can be applied without touching the repository.
func stagingMigrations(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	names := migrationFiles(t)
	copied := 0
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatalf("stage %s: %v", name, err)
		}
		copied++
	}
	if copied < 15 {
		// Anti-vacuous: a staging step that copied nothing would make every
		// mutation below a no-op and every sentinel a false pass.
		t.Fatalf("staged only %d migration files", copied)
	}
	return dir
}

// patchMigration replaces a literal in one file of the staged copy, failing if
// the literal was not found (so a mutation that silently does nothing cannot be
// mistaken for a probe that noticed).
func patchMigration(t *testing.T, dir, name, old, new string) {
	t.Helper()
	path := filepath.Join(dir, name)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged %s: %v", name, err)
	}
	if !strings.Contains(string(body), old) {
		t.Fatalf("staged %s does not contain %q; the sentinel's mutation is stale", name, old)
	}
	patched := strings.Replace(string(body), old, new, 1)
	if patched == string(body) {
		t.Fatalf("patching %s changed nothing", name)
	}
	if err := os.WriteFile(path, []byte(patched), 0o600); err != nil {
		t.Fatalf("write staged %s: %v", name, err)
	}
}

// TestMigrationsDirectoryResolves is the plainest form of the question: does the
// relative path actually find the shipped schema? It asserts the file count, so a
// path that resolved to an empty directory fails here rather than turning every
// other probe into a vacuous pass.
func TestMigrationsDirectoryResolves(t *testing.T) {
	abs, err := filepath.Abs(migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		t.Fatalf("the migrations directory does not resolve from the probe package's working directory: %v\n"+
			"(looked for %s)", err, abs)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", abs)
	}

	names := migrationFiles(t)
	if len(names) != 20 {
		t.Errorf("found %d migration files, want 20; update the probes if a migration was added or removed "+
			"(names: %v)", len(names), names)
	}
	// The schema's own anchor: the first and last migration must be readable and
	// non-trivial, which proves the path points at this project's migrations and
	// not at some other directory with .sql files in it.
	for _, want := range []string{"0001_init.sql", "0021_token_client_indexes.sql"} {
		if !contains(names, want) {
			t.Errorf("%s is missing from %s", want, abs)
		}
		body := readMigration(t, want)
		if !strings.Contains(body, "-- +goose Up") || !strings.Contains(body, "-- +goose Down") {
			t.Errorf("%s does not look like a goose migration", want)
		}
	}
	t.Logf("read %d migrations from %s", len(names), abs)
}

// TestProbesFailOnAMutationOfTheIndexSchema is the sentinel for the index
// inventory: remove `CREATE INDEX oauth_codes_subject_idx …` from migration 0012
// in a copy, and the index probe must report `oauth_codes.subject` as unindexed.
// The control run (undamaged copy) must pass first.
func TestProbesFailOnAMutationOfTheIndexSchema(t *testing.T) {
	names := []string{"oauth_codes"}

	// Control: the shipped schema passes.
	good := indexLeadingCols(t)
	for _, table := range names {
		if !good[table]["subject"] {
			t.Fatalf("the shipped schema already lacks %s.subject; the sentinel cannot distinguish anything", table)
		}
	}

	dir := stagingMigrations(t)
	patchMigration(t, dir, "0012_indexes.sql",
		"CREATE INDEX oauth_codes_subject_idx ON oauth_codes (subject);",
		"") // the index is gone from this copy

	damaged := indexLeadingColsIn(t, dir)
	for _, table := range names {
		if damaged[table]["subject"] {
			t.Errorf("after deleting the index definition, the probe still reports %s.subject as indexed: "+
				"the index inventory is not reading the SQL on disk", table)
		}
	}
	// And the rest of the schema must be unaffected, which shows the parse is
	// surgical rather than collapsing on a mutation.
	if !damaged["oauth_codes"]["expires_at"] {
		t.Error("deleting one index definition removed others from the parse; the parser is too fragile to trust")
	}
	t.Log("sentinel passed: deleting a CREATE INDEX from a staged copy makes the index probe report the gap")
}

// TestProbesFailOnAMutationOfTheErasureSchema is the sentinel for the erasure
// coverage probes: drop the `subject` column from a staged `session_subjects`
// table and the guard's detector must stop flagging that table.
func TestProbesFailOnAMutationOfTheErasureSchema(t *testing.T) {
	if !guardAccountColumn(accColsOf(t, "session_subjects")) {
		t.Fatal("the shipped session_subjects does not read as account-linked; the sentinel proves nothing")
	}

	dir := stagingMigrations(t)
	// The column is the first line of the table's block.
	patchMigration(t, dir, "0011_session_subjects.sql",
		"    subject    text NOT NULL", "    account_ref text NOT NULL")

	block := accColsOfIn(t, dir, "session_subjects")
	if guardAccountColumn(block) {
		t.Error("after renaming the account-reference column, the guard's detector still flags " +
			"session_subjects: the erasure probe is not reading the SQL on disk")
	}
	// The control in the other direction: the untouched tables are still flagged,
	// so the mutation did not simply break the parse.
	if !guardAccountColumn(accColsOfIn(t, dir, "oidc_access_tokens")) {
		t.Error("the staged parse stopped flagging an untouched table; the parser collapsed on the mutation")
	}
	t.Log("sentinel passed: renaming the account column in a staged copy makes the erasure detector miss it")
}

// TestProbesFailOnAMutationOfTheDownSection is the sentinel for the Down-section
// probes: delete one `DROP INDEX` from migration 0006's Down (which is a
// self-contained index migration, so its indexes are not carried away by a DROP
// TABLE) and the probe must report that index as surviving.
func TestProbesFailOnAMutationOfTheDownSection(t *testing.T) {
	const victim = "oauth_access_tokens_subject_idx"

	// Control: the shipped migration removes it.
	up, down := splitGoose(readMigration(t, "0006_grants.sql"))
	created, _ := objectsCreatedIn(up)
	if !contains(created, victim) {
		t.Fatalf("0006_grants.sql no longer creates %s; the sentinel's premise changed", victim)
	}
	if !objectsDroppedIn(down)[victim] {
		t.Fatalf("0006_grants.sql no longer drops %s; the premise changed", victim)
	}

	dir := stagingMigrations(t)
	patchMigration(t, dir, "0006_grants.sql",
		"DROP INDEX IF EXISTS oauth_access_tokens_subject_idx;", "")
	upD, downD := splitGoose(readMigrationIn(t, dir, "0006_grants.sql"))
	createdD, _ := objectsCreatedIn(upD)
	if !contains(createdD, victim) {
		t.Fatalf("the staged Up no longer creates %s", victim)
	}
	if objectsDroppedIn(downD)[victim] {
		t.Errorf("after deleting the DROP INDEX line, the probe still reports %s as dropped: the Down "+
			"parser is not reading the SQL on disk", victim)
	}
	t.Log("sentinel passed: deleting a DROP INDEX from a staged copy makes the Down probe report a survivor")
}

// TestClockScannerDistinguishesGoAndSQLClocks is the sentinel for the clock
// probe. That probe's whole finding is that a statement uses the DATABASE clock
// while the policy wants the store clock, so a scanner that could not tell
// `s.now()` from `now()` in SQL would report the opposite of the truth. This
// check pins the distinction on synthetic source: the pair below is unfair to a
// sloppy scanner and must be classified differently.
func TestClockScannerDistinguishesGoAndSQLClocks(t *testing.T) {
	sqlSide, goSide := classifyNowForTest(t, `x := `+"`SELECT a FROM t WHERE expires_at > now()`"+`
y := q(ctx, "SELECT a FROM t WHERE expires_at > $1", s.now())
`)
	if sqlSide != 1 {
		t.Errorf("the scanner found %d SQL-clock now() in the synthetic source, want 1", sqlSide)
	}
	if goSide != 1 {
		t.Errorf("the scanner missed the Go clock call s.now() (found %d); a statement using the store "+
			"clock would be reported as a violation", goSide)
	}
	t.Log("sentinel passed: one SQL now() and one Go s.now() on adjacent lines are classified differently")
}
