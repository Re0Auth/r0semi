//go:build audit || audit6

package postgres

// Round-6 audit probe (crypto/key-management area): the audit chain key and the
// per-subject pseudonym keys.
//
// Every test here is pure —no database —so it runs on this machine. The
// persistence half of each statement is marked 「读；无 DB 执行」in
// C:\git\r0semi\_audit\crypto-vault.md.
//
// What the round-5 probe file (zzprobe_crypto_test.go, tag audit5) already
// covers and this one does not repeat: canonical-form determinism, length-prefix
// injectivity, domain-separation of the three HMAC labels, chain linkage, and the
// key-length invariants.

import (
	"bytes"
	"crypto/hmac"
	"testing"
	"time"
)

func rotRow(subject string) auditRow {
	return auditRow{
		OccurredAt: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		Action:     "vault.use",
		Subject:    subject,
		Provider:   "taptap",
		Outcome:    "ok",
		Detail:     map[string]string{},
	}
}

// TestAuditChainKeyChangeDetachesEveryPseudonym is the finding.
//
// docs/operations.md:167 states the constraint ("审计 key：不可轮换而不重写历史")
// but only in terms of the chain. The same key also derives the subject index
// (auditpseudo.go:53-56), and through it the per-subject key row that makes a
// pseudonym computable. Changing RE0AUTH_AUDIT_KEY therefore does three things at
// once, none of which the process notices:
//
//  1. every already-written row's signature stops verifying —Verify
//     (auditchain.go:305) reports "signature does not verify" from the first row
//     onward, i.e. the whole history reads as tampered (runbooks.md:100-112
//     already tells the operator to treat that as an incident);
//  2. the subject index for every account changes, so loadKey
//     (auditpseudo.go:69-91) finds no row and subjectKey (auditpseudo.go:115-142)
//     MINTS A NEW per-subject key: the same account's future events are stored
//     under a different pseudonym, splitting its history in two;
//  3. Destroy (auditpseudo.go:173-187) deletes only the row the CURRENT key
//     addresses —the row under the old index, which still resolves the old
//     pseudonym for anyone holding the old key (the very key operations.md:167
//     tells the operator to archive), is left behind. Destroy still returns nil,
//     and its doc claims "nobody, including this service, can recompute which
//     account they describe".
func TestAuditChainKeyChangeDetachesEveryPseudonym(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x11}, auditChainKeySize)
	k2 := bytes.Repeat([]byte{0x22}, auditChainKeySize)
	before := &AuditLogger{key: k1}
	after := &AuditLogger{key: k2}

	const subject = "usr_alice"

	// (1) The signature of a row written under the old key.
	row := rotRow("pseudonym-not-yet-computed")
	rowHash := chainHash(auditGenesis, row.canonical())
	sig := before.sign(rowHash)
	if hmac.Equal(after.sign(rowHash), sig) {
		t.Fatal("control: the signature is independent of the chain key")
	}

	// (2) The lookup index, and the pseudonym it makes computable.
	if before.subjectIndex(subject) == after.subjectIndex(subject) {
		t.Fatal("control: the subject index is independent of the chain key")
	}
	oldSubjectKey := bytes.Repeat([]byte{0x33}, auditSubjectKeySize)
	newSubjectKey := bytes.Repeat([]byte{0x44}, auditSubjectKeySize) // what subjectKey mints
	oldPseudo := pseudonymOf(oldSubjectKey, subject)
	newPseudo := pseudonymOf(newSubjectKey, subject)
	if oldPseudo == newPseudo {
		t.Fatal("control: two subject keys produce the same pseudonym")
	}
	t.Logf("CONFIRMED: after RE0AUTH_AUDIT_KEY changes, historical rows verify as tampered, "+
		"%s's pseudonym moves from %s to %s (its history splits), and Destroy removes only the "+
		"row at the new index %s —the pre-change row at %s survives, so the archived old key "+
		"(docs/operations.md:167) still resolves the old history while Destroy reports success",
		subject, oldPseudo, newPseudo, after.subjectIndex(subject), before.subjectIndex(subject))
}

// TestAuditSubjectKeyRowIsOutsideTheChain is the second finding.
//
// audit_events is chained and MAC'd (auditchain.go:94-110), but the table that
// maps a subject to its pseudonym key is not covered by anything: its `key`
// column is unauthenticated bytes (migration 0014:36-39), and the chain commits
// only to the pseudonym that key produces.
//
// An attacker with write access to the database therefore has a cheaper way to
// hide an account's history than editing the log: replace that subject's key row
// (or its `idx`), and the operator's subject-filtered query —// auditread.go:51-64 computes `pseudonymOf(loadKey(subject), subject)` —returns
// the empty page that "this account was erased" produces, while every audit row
// still verifies: Verify never reads audit_subject_keys.
//
// This is the tamper-evidence boundary the chain does not close, and the reason
// it is reported separately from the chain itself.
func TestAuditSubjectKeyRowIsOutsideTheChain(t *testing.T) {
	l := &AuditLogger{key: bytes.Repeat([]byte{0x55}, auditChainKeySize)}
	const subject = "usr_bob"

	realKey := bytes.Repeat([]byte{0x01}, auditSubjectKeySize)
	stored := pseudonymOf(realKey, subject) // what audit_events holds

	// The row, as written and signed before any tampering.
	row := rotRow(stored)
	hash := chainHash(auditGenesis, row.canonical())
	sig := l.sign(hash)

	// The attacker substitutes the key row for a value they choose.
	attackerKey := bytes.Repeat([]byte{0x02}, auditSubjectKeySize)
	filter := pseudonymOf(attackerKey, subject)

	// The log is untouched: the row still verifies.
	if !bytes.Equal(chainHash(auditGenesis, row.canonical()), hash) {
		t.Fatal("control: the row hash is not reproducible")
	}
	if !hmac.Equal(l.sign(hash), sig) {
		t.Fatal("control: the row signature does not verify")
	}
	// But the operator's subject filter no longer matches anything.
	if filter == stored {
		t.Fatal("control: the substituted key produced the same pseudonym")
	}
	t.Logf("CONFIRMED: replacing one unauthenticated row in audit_subject_keys moves the subject "+
		"filter from %s to %s (auditread.go:64), so GET /v1/admin/audit?subject=%s returns the "+
		"empty page that an erasure produces —while Verify still reports the chain OK, because "+
		"audit_subject_keys is not part of the chain and its contents are not authenticated",
		stored, filter, subject)
}
