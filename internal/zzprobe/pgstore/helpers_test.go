//go:build audit5

package pgstore

// Shared helpers for the schema probes.
//
// # Where the schema text comes from
//
// The probes read the migration SQL **from disk**, at
// `internal/store/postgres/migrations/*.sql`, resolved relative to the package
// directory that `go test` runs the probe in
// (`internal/zzprobe/pgstore` → `../../store/postgres/migrations`).
//
// This is deliberate, and it replaced an earlier design that kept a byte-for-byte
// copy of the migrations inside the probe package (with a SHA-256 drift check).
// The copy worked, but it was a second thing that could go stale and it was one
// more artifact to maintain; reading the live files removes both problems and
// removes the temptation to add an export to a tracked production file so a probe
// could reach its unexported `embed.FS`. The shipped package is not modified by
// this audit at all.
//
// Reading from disk cannot drift: `TestMigrationsDirectoryResolves` proves the
// path resolves and holds the whole schema, and every parser here asserts that it
// found at least as many objects as the schema is known to contain — so a path
// that silently returned nothing fails loudly instead of passing vacuously.
// `disk_read_probe_test.go` adds the sharper anti-vacuous check: it runs the
// parsers against a damaged copy and requires them to fail.
//
// These parsers are written independently of the regexes inside
// internal/store/postgres, so a probe can disagree with the production guard —
// which is the only way a probe can find something the guard does not.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// migrationsDir is where the shipped migrations live, relative to the working
// directory of a test in this package (`go test` sets the working directory to
// the package directory).
const migrationsDir = "../../store/postgres/migrations"

// probeCreateTableRE captures a table name and its whole parenthesised column
// block. It is non-greedy to the first `);`, which is sound here because no
// column block in this schema contains a nested `);`, and the probes assert the
// parse found enough tables to prove it is working.
var probeCreateTableRE = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("[A-Za-z0-9_]+"|[A-Za-z0-9_]+)\s*\((.*?)\s*\)\s*;`)

// migrationFilesIn returns the sorted file names of every .sql file in dir.
//
// dir is a parameter rather than the constant so the anti-vacuous probes in
// disk_read_probe_test.go can point the same parsers at a deliberately damaged
// copy in a temp directory and require them to notice.
func migrationFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		t.Fatalf("glob %s/*.sql: %v", dir, err)
	}
	names := make([]string, 0, len(paths))
	for _, p := range paths {
		names = append(names, filepath.Base(p))
	}
	sort.Strings(names)
	if len(names) < 15 {
		t.Fatalf("found only %d .sql files under %s; the path resolution or the glob is broken, so every "+
			"assertion built on it would be vacuous", len(names), dir)
	}
	return names
}

// readMigrationIn reads one migration from dir. The path is the one production
// uses, so a probe cannot read a file the migration runner would not.
func readMigrationIn(t *testing.T, dir, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(dir, name), err)
	}
	if len(body) == 0 {
		t.Fatalf("%s is empty", name)
	}
	return string(body)
}

// migrationFiles and readMigration are the ordinary entry points, pinned to the
// shipped directory.
func migrationFiles(t *testing.T) []string { return migrationFilesIn(t, migrationsDir) }

func readMigration(t *testing.T, name string) string { return readMigrationIn(t, migrationsDir, name) }

// probeTableColsIn maps table -> column block for every CREATE TABLE in dir.
func probeTableColsIn(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, name := range migrationFilesIn(t, dir) {
		body := stripLineComments(readMigrationIn(t, dir, name))
		for _, m := range probeCreateTableRE.FindAllStringSubmatch(body, -1) {
			out[unquote(m[1])] = m[2]
		}
	}
	if len(out) < 15 {
		t.Fatalf("parsed only %d CREATE TABLE statements from %s; the parser is broken", len(out), dir)
	}
	return out
}

// probeTableCols is probeTableColsIn against the shipped migrations.
func probeTableCols(t *testing.T) map[string]string { return probeTableColsIn(t, migrationsDir) }

// accColsOfIn returns the column block of one table, failing the test if it is
// absent — so a probe can never pass by looking at nothing.
func accColsOfIn(t *testing.T, dir, table string) string {
	t.Helper()
	cols, ok := probeTableColsIn(t, dir)[table]
	if !ok {
		t.Fatalf("no CREATE TABLE for %q under %s", table, dir)
	}
	if strings.TrimSpace(cols) == "" {
		t.Fatalf("table %q parsed with an empty column block", table)
	}
	return cols
}

func accColsOf(t *testing.T, table string) string { return accColsOfIn(t, migrationsDir, table) }

// accColumnsInAllMigrations returns the set of tables whose CREATE TABLE
// declares a `subject` or `user_id` column (the same question the guard asks),
// plus the total number of tables parsed (so the caller can prove the parser
// worked).
func accColumnsInAllMigrations(t *testing.T) (found map[string]bool, tables int) {
	t.Helper()
	found = make(map[string]bool)
	all := probeTableCols(t)
	for table, cols := range all {
		tables++
		if guardAccountColumn(cols) {
			found[table] = true
		}
	}
	return found, tables
}

func mustCompile(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }

// guardAccountColumn reproduces, line for line, the detector the erasure guard
// uses (hasAccountColumn in internal/store/postgres/erasure_schema_test.go).
//
// It is a reproduction rather than a call because the guard's detector lives in
// a _test.go file and is therefore not reachable from a package outside it. The
// reproduction is what makes the coverage probes meaningful, and it is held
// honest by TestGuardReproductionAgreesWithTheGuard, which compares the verdicts
// for every table in the shipped schema to the guard's expected set — so a drift
// between this copy and the guard fails a test rather than silently weakening
// the probes.
//
// The algorithm, as written in the guard: strip `--` comment lines, then accept
// a line whose trimmed lowercased form is exactly `subject` or `user_id`, or
// begins with one of those followed by whitespace (so `subject_x` does not
// match).
func guardAccountColumn(cols string) bool {
	for _, line := range strings.Split(cols, "\n") {
		line = strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(line, "--") {
			continue
		}
		for _, col := range []string{"subject", "user_id"} {
			if line == col {
				return true
			}
			rest := strings.TrimPrefix(line, col)
			if rest != line {
				if r := strings.TrimLeft(rest, " \t"); r != rest && len(r) > 0 {
					return true
				}
			}
		}
	}
	return false
}
