//go:build audit7

package z21verify

import (
	"strings"
	"testing"
)

// Z21V-1: 0014's Down destroys every per-subject pseudonym key.
//
// audit_subject_keys is the ONLY copy of the random per-subject keys; the doc
// comment on subjectKey (auditpseudo.go:109-114) states the invariant plainly —
// one key per subject, "Picking our own key after losing that race would give the
// same account two pseudonyms and split its history in two" — and the code defends
// it with INSERT ... ON CONFLICT DO NOTHING plus a re-read. 0014's Down drops the
// whole table, which forces exactly the split the code works to prevent: the next
// audit append for a live subject finds no row, mints a fresh random key, and every
// row written afterwards carries a different pseudonym than the same account's
// history.
//
// The operator-visible consequence is in auditread.go:46-65: `?subject=usr_…` is
// translated with loadKey(subject) into pseudonymOf(key, subject), so the admin
// read returns only the post-wipe rows — a silently truncated history, with no
// error, no marker and nothing in Verify to notice (all rows stay chain-valid).
//
// This is the same invariant as round 5's P2-3 / AUD-V1 (SignOut re-minting a key
// after an erasure) but a different trigger: a documented `-migrate-down` step.
func TestMigration0014DownDestroysEveryPseudonymKey(t *testing.T) {
	body := migrationText(t, "0014_audit_pseudonyms.sql")
	up, down := splitDirection(body)
	if down == "" {
		t.Fatalf("0014 has no Down section")
	}
	upNoComments := stripSQLComments(up)
	downNoComments := stripSQLComments(down)

	// Control: the table really is the key store this probe is about, and the Up
	// creates it empty (so nothing restores the keys after a Down/Up cycle).
	if !strings.Contains(upNoComments, "CREATE TABLE audit_subject_keys") {
		t.Fatalf("premise changed: 0014's Up no longer creates audit_subject_keys")
	}
	if strings.Contains(strings.ToUpper(upNoComments), "INSERT INTO AUDIT_SUBJECT_KEYS") {
		t.Logf("note: 0014's Up now repopulates audit_subject_keys; re-read Z21V-1")
	}
	if !strings.Contains(strings.ToUpper(downNoComments), "DROP TABLE IF EXISTS AUDIT_SUBJECT_KEYS") {
		t.Logf("FIXED: 0014's Down no longer drops audit_subject_keys")
		return
	}

	// Premise: the mint-on-missing path exists (so a wiped key table really does
	// produce a second pseudonym for the same account).
	pseudo := storeSource(t, "auditpseudo.go")
	for _, want := range []string{
		"INSERT INTO audit_subject_keys (idx, key) VALUES ($1, $2)",
		"case errors.Is(err, pgx.ErrNoRows):",
		"func pseudonymOf(key []byte, subject string) string",
	} {
		if !strings.Contains(pseudo, want) {
			t.Fatalf("premise changed: auditpseudo.go no longer contains %q", want)
		}
	}
	// Premise: the read path resolves a raw subject through that same key.
	read := storeSource(t, "auditread.go")
	if !strings.Contains(read, "key, err := l.loadKey(ctx, q.Subject)") ||
		!strings.Contains(read, `add("subject", "=", pseudonymOf(key, q.Subject))`) {
		t.Fatalf("premise changed: auditread.go no longer filters by the pseudonym derived from the key")
	}

	t.Errorf("PSEUDONYM HISTORY SPLIT: 0014's Down (0014_audit_pseudonyms.sql:41-42) drops " +
		"audit_subject_keys, the only copy of every per-subject pseudonym key, and 0014's Up re-creates " +
		"it empty. After the cycle auditpseudo.go:115-142 mints a fresh random key on the next append for " +
		"each live subject, so the same account's older rows keep a pseudonym nothing can recompute; " +
		"auditread.go:46-65 then answers `?subject=usr_…` with only the new rows. Silent, unrecoverable, " +
		"and it is precisely the split the code documents as forbidden.")
}
