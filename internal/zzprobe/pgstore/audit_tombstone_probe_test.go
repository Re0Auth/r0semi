//go:build audit5

package pgstore

// audit_tombstone_probe_test.go is the schema half of Z10-1=A.
//
// Z10-1: the in-process subject->key cache (auditpseudo.go) let an erasure
// performed by one replica do nothing on another, because the other replica's
// warm cache kept pseudonymising the erased subject. The fix is a tombstone row,
// written in the same transaction as the key deletion, that every replica
// consults before it answers from its cache.
//
// This probe reads the shipped migration on disk and requires the table, a
// supporting index and a Down that removes both. It is deliberately
// database-free: the shape of the row is decidable from the SQL, and the
// behavioral cross-replica proof needs a live Postgres (CI).
import (
	"strings"
	"testing"
)

func TestAuditSubjectTombstonesExist(t *testing.T) {
	const name = "0034_audit_subject_tombstones.sql"
	body := readMigration(t, name)
	up, down := splitGoose(body)
	if len(up) == 0 {
		t.Fatalf("%s has no Up section", name)
	}
	if len(down) == 0 {
		t.Fatalf("%s has no Down section; the migration must be self-consistent", name)
	}

	indexes, tables := objectsCreatedIn(up)
	if !contains(tables, "audit_subject_tombstones") {
		t.Fatalf("%s does not create audit_subject_tombstones; created tables = %v", name, tables)
	}
	if !contains(indexes, "audit_subject_tombstones_tombstoned_at_idx") {
		t.Fatalf("%s does not create audit_subject_tombstones_tombstoned_at_idx; created indexes = %v",
			name, indexes)
	}

	// The row is keyed by the keyed-hash subject index, exactly as
	// audit_subject_keys is: storing the raw subject here would make the
	// tombstone table a second copy of the account list and defeat the keyed
	// lookup the erasure path already uses.
	clean := stripLineComments(up)
	if !strings.Contains(clean, "idx") || strings.Contains(clean, "subject text") {
		t.Errorf("%s does not key the tombstone on the hashed `idx`; a raw subject column would "+
			"reintroduce the account list the pseudonym table exists to avoid", name)
	}

	dropped := objectsDroppedIn(down)
	if !dropped["audit_subject_tombstones"] {
		t.Errorf("%s's Down does not drop audit_subject_tombstones, so a full rollback leaves the "+
			"table behind and the next Up fails on `already exists`", name)
	}
	t.Log("sentinel passed: migration 0034 creates and drops the audit subject tombstone table")
}
