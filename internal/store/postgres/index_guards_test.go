package postgres

import (
	"io/fs"
	"strings"
	"testing"
)

// migrationIndexes parses every CREATE INDEX in the embedded migrations and
// returns table -> the column list of each index on it. The parser is
// createIndexRE, shared with TestEverySweptTableHasADeadlineIndex so the two
// guards cannot drift apart.
func migrationIndexes(t *testing.T) map[string][]string {
	t.Helper()
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	indexed := make(map[string][]string)
	total := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range createIndexRE.FindAllStringSubmatch(string(body), -1) {
			indexed[m[1]] = append(indexed[m[1]], m[2])
			total++
		}
	}
	// Anti-vacuous: a broken parser would find nothing and pass every check below.
	if total < 15 {
		t.Fatalf("parsed only %d index definitions; the parser is broken", total)
	}
	return indexed
}

// indexCovers reports whether any of the index column lists includes col.
func indexCovers(lists []string, col string) bool {
	for _, cols := range lists {
		for _, c := range strings.Split(cols, ",") {
			if strings.TrimSpace(c) == col {
				return true
			}
		}
	}
	return false
}

// TestSessionSubjectSweepIsIndexed is the database-free half of the session
// sweep's guard.
//
// The sweep collects orphaned session_subjects rows by age (SweepExpired in
// sessions.go). created_at was added by migration 0015 for the grace period but
// never indexed, so the age predicate had no way in. A database-backed test can
// prove the delete works but cannot see the scan, so this parses the migrations —
// the same shape as TestEverySweptTableHasADeadlineIndex.
func TestSessionSubjectSweepIsIndexed(t *testing.T) {
	indexed := migrationIndexes(t)
	if !indexCovers(indexed["session_subjects"], "created_at") {
		t.Errorf("session_subjects has no index on created_at: the session sweep scans the table by " +
			"age every run (add a migration like 0019_session_subjects_created_at_idx.sql)")
	}
}

// TestAuditTimeRangeQueryIsIndexed is the database-free half of the audit read
// API's guard.
//
// auditread.go builds `occurred_at >= $` / `< $` with no other filter when the
// caller passes only a time window. Migration 0007 indexed (subject, occurred_at)
// and (action, occurred_at); a window-only query names neither leading column, so
// it had nothing to range-scan on.
func TestAuditTimeRangeQueryIsIndexed(t *testing.T) {
	indexed := migrationIndexes(t)
	if !indexCovers(indexed["audit_events"], "occurred_at") {
		t.Errorf("audit_events has no index on occurred_at: GET /v1/admin/audit?since=&until= scans " +
			"the whole log (add a migration like 0020_audit_events_occurred_at_idx.sql)")
	}
}
