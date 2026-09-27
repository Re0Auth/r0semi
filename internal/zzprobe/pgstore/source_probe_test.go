//go:build audit5

package pgstore

// Shared source-reading helpers for the probes that read Go code as well as
// migrations.
//
// Two directories are read from disk, both resolved relative to this package's
// working directory (which `go test` sets to the package directory):
//
//	adapterDir    ../.. /store/postgres        the Postgres store's Go files
//	migrationsDir ../.. /store/postgres/migrations   the schema (see helpers_test.go)
//
// They are constants rather than inline strings so the anti-vacuous sentinels in
// disk_read_probe_test.go and this file's own drift check can refer to the same
// location the probes use.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adapterDir is where the Postgres adapter's Go files live, relative to this
// package's working directory.
const adapterDir = "../../store/postgres"

// contains is a plain substring test, used by the probes that read file names and
// by the clock sentinel. strings.Contains would do; this exists because the
// sentinel also compares byte slices and keeping one helper avoids a surprising
// difference between the two call sites.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// classifyNowForTest runs the clock scanner over synthetic Go source and counts
// how many `now()` it classified as SQL (inside a backtick literal) and how many
// as Go (a store-clock call).
//
// It exists for TestClockScannerDistinguishesGoAndSQLClocks: the clock probe's
// entire finding is "this predicate uses the database clock where the policy
// wants the store clock", so a scanner that could not tell the two apart would
// report the opposite of the truth. This makes the distinction itself checkable.
func classifyNowForTest(t *testing.T, src string) (sqlSide, goSide int) {
	t.Helper()
	code := stripGoComments(src)
	sqlFound := scanSourceForSQLNow("synthetic.go", src)
	sqlSide = len(sqlFound)

	// Every `now()` in the source, minus the ones the scanner attributed to SQL,
	// is a Go-side occurrence. Counting rather than pattern-matching keeps the two
	// categories exhaustive by construction: a scanner that dropped an occurrence
	// entirely would show up as a Go-side count that is too high.
	total := len(sqlNowRE.FindAllString(code, -1))
	goSide = total - sqlSide
	if goSide < 0 {
		t.Fatalf("the scanner attributed %d occurrences but the source has only %d", sqlSide, total)
	}
	return sqlSide, goSide
}

// TestAdapterDirectoryResolves is the same check the migrations probes make,
// applied to the Go sources: the by-line citations in the report
// (`oidc.go:771`, `oauth.go:292`, …) are only meaningful if this path resolves to
// the file the report names.
func TestAdapterDirectoryResolves(t *testing.T) {
	abs, err := filepath.Abs(adapterDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"oidc.go", "oauth.go", "sessions.go", "sweep.go", "postgres.go"} {
		path := filepath.Join(abs, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("cannot read %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s is empty", path)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "package postgres") {
			t.Errorf("%s does not declare package postgres; the path does not point at the adapter", name)
		}
	}
	t.Logf("read the adapter's Go sources from %s", abs)
}
