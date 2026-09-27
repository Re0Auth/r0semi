//go:build audit5

package postgres

// zzprobe_audit_gap_test.go - a probe on the two erasure guards, not on the
// database. It needs no DB: it asks the same questions the guards ask, from
// inside the package, and records what neither of them can see.

import (
	"io/fs"
	"strings"
	"testing"
)

// TestZZAdmPseudonymKeyTableIsInvisibleToEveryErasureGuard asks the two guards
// about the one table that holds the link between an account and its audit
// history.
//
// audit_subject_keys has no subject/user_id column - its key column is `idx`,
// a keyed hash of the subject - so TestEverySubjectColumnIsHandledByErasure's
// migration parser cannot see it, the information_schema walk in
// TestAccountDeletionLeavesNoOrphans cannot see it either, and the only thing
// that clears it on erasure is lifecycle's Pseudonyms port, which the
// composition root fills through a runtime type assertion (pseudonymStore) that
// returns nil - silently - when the sink does not implement it.
func TestZZAdmPseudonymKeyTableIsInvisibleToEveryErasureGuard(t *testing.T) {
	// Reproduce the static guard's walk exactly, so "the guard misses it" is a
	// statement about the real guard and not about a paraphrase.
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	found := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range createTableRE.FindAllStringSubmatch(string(body), -1) {
			if hasAccountColumn(m[2]) {
				found[m[1]] = true
			}
		}
	}
	if len(found) < 8 {
		t.Fatalf("parsed only %d account-linked tables; the parser is broken", len(found))
	}

	if found["audit_subject_keys"] {
		t.Fatalf("the guard now sees audit_subject_keys; this probe is stale")
	}
	if hasAccountColumn("idx text  PRIMARY KEY,\nkey bytea NOT NULL") {
		t.Fatalf("hasAccountColumn matched a non-subject column; the probe is wrong")
	}

	_, handled := erasureHandledTables["audit_subject_keys"]
	_, ignored := accountTablesIgnored["audit_subject_keys"]
	if !handled && !ignored {
		t.Errorf("audit_subject_keys is the table that makes an erased account's audit history "+
			"linkable again (idx = HMAC(audit_key, \"subject-index/1\" || subject), key = the "+
			"per-subject pseudonym key), and no guard observes it: it has no subject/user_id "+
			"column, so neither the migration parser (%d account-linked tables found) nor the "+
			"information_schema walk in TestAccountDeletionLeavesNoOrphans counts it. "+
			"Its only clearing step is the lifecycle Pseudonyms port, which is optional in "+
			"lifecycle.New and filled by a runtime type assertion in cmd/re0auth. A deployment "+
			"that loses that assertion erases accounts successfully and silently keeps the link.",
			len(found))
	}
}
