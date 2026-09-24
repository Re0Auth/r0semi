package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
)

// TestAuditCanonicalIsDeterministic is the load-bearing property of the whole
// chain: the bytes a row is hashed over must not depend on anything but the row.
//
// Go map iteration is deliberately randomised, so a naive encoding of Detail
// produces a different hash on every run — and every row would then fail its own
// verification. This test builds the same logical row twice and requires byte
// equality, and separately requires that a different key order in the source map
// does not change the result.
func TestAuditCanonicalIsDeterministic(t *testing.T) {
	when := time.Date(2026, 3, 4, 5, 6, 7, 891234000, time.UTC)
	a := auditRow{
		OccurredAt: when, Action: "oauth.token", Subject: "usr_1",
		Provider: "oauth", Outcome: audit.OutcomeOK,
		Detail: map[string]string{"client_id": "cli", "request_id": "req_1", "scope": "account.id"},
	}
	// The same values inserted in a different order.
	b := auditRow{
		OccurredAt: when, Action: "oauth.token", Subject: "usr_1",
		Provider: "oauth", Outcome: audit.OutcomeOK,
		Detail: map[string]string{"scope": "account.id", "client_id": "cli", "request_id": "req_1"},
	}

	first := a.canonical()
	for i := 0; i < 50; i++ {
		if !bytes.Equal(first, a.canonical()) {
			t.Fatal("canonical bytes differ between calls on the same row")
		}
	}
	if !bytes.Equal(first, b.canonical()) {
		t.Fatal("canonical bytes depend on the source map's key order")
	}
}

// TestAuditCanonicalIsUnambiguous: length prefixes are what stop two different
// rows from hashing the same. Without them ("ab","c") and ("a","bc") collide.
func TestAuditCanonicalIsUnambiguous(t *testing.T) {
	base := auditRow{OccurredAt: time.Unix(0, 0).UTC(), Outcome: audit.OutcomeOK}
	left := base
	left.Action, left.Subject = "ab", "c"
	right := base
	right.Action, right.Subject = "a", "bc"

	if bytes.Equal(left.canonical(), right.canonical()) {
		t.Fatal("a field boundary is not encoded: two different rows hash the same")
	}
}

// TestAuditCanonicalCoversEveryField: dropping a field from the hash would let it
// be edited without detection, which is the whole point of the chain.
func TestAuditCanonicalCoversEveryField(t *testing.T) {
	base := auditRow{
		OccurredAt: time.Unix(1_700_000_000, 0).UTC(), Action: "a", Subject: "s",
		Provider: "p", Outcome: audit.OutcomeOK, Detail: map[string]string{"k": "v"},
	}
	baseline := base.canonical()

	for name, mutate := range map[string]func(*auditRow){
		"OccurredAt": func(r *auditRow) { r.OccurredAt = r.OccurredAt.Add(time.Second) },
		"Action":     func(r *auditRow) { r.Action = "b" },
		"Subject":    func(r *auditRow) { r.Subject = "t" },
		"Provider":   func(r *auditRow) { r.Provider = "q" },
		"Outcome":    func(r *auditRow) { r.Outcome = audit.OutcomeDenied },
		"Detail":     func(r *auditRow) { r.Detail = map[string]string{"k": "w"} },
	} {
		t.Run(name, func(t *testing.T) {
			row := base
			mutate(&row)
			if bytes.Equal(baseline, row.canonical()) {
				t.Errorf("changing %s does not change the canonical bytes", name)
			}
		})
	}
}

// TestAuditChainHashLinksToPredecessor: the linkage is what makes a deletion or a
// reorder detectable, so the same row under two different predecessors must hash
// differently.
func TestAuditChainHashLinksToPredecessor(t *testing.T) {
	row := auditRow{OccurredAt: time.Unix(0, 0).UTC(), Action: "a", Outcome: audit.OutcomeOK}
	c := row.canonical()
	one := chainHash([]byte("prev-1"), c)
	two := chainHash([]byte("prev-2"), c)
	if bytes.Equal(one, two) {
		t.Fatal("the row hash does not depend on its predecessor")
	}
	// And the genesis is the empty predecessor, not nil-or-empty indifferently.
	if !bytes.Equal(chainHash(auditGenesis, c), chainHash([]byte{}, c)) {
		t.Fatal("genesis hashing is inconsistent")
	}
}

// TestAuditSignatureDependsOnTheKey: the signature is the only part an attacker
// with full database access cannot reproduce.
func TestAuditSignatureDependsOnTheKey(t *testing.T) {
	rowHash := sha256.Sum256([]byte("row"))
	mine := &AuditLogger{key: bytes.Repeat([]byte{0x01}, 32)}
	theirs := &AuditLogger{key: bytes.Repeat([]byte{0x02}, 32)}

	if bytes.Equal(mine.sign(rowHash[:]), theirs.sign(rowHash[:])) {
		t.Fatal("the signature does not depend on the key")
	}
	if len(mine.sign(rowHash[:])) != sha256.Size {
		t.Fatalf("signature is %d bytes, want %d", len(mine.sign(rowHash[:])), sha256.Size)
	}
}

func TestNewAuditLoggerRejectsABadKey(t *testing.T) {
	if _, err := newAuditLogger(nil, testAuditKey()); err == nil {
		t.Error("a nil pool should be rejected")
	}
	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := newAuditLogger(nil, bytes.Repeat([]byte{1}, size)); err == nil {
			t.Errorf("a %d-byte key should be rejected", size)
		}
	}
}

// TestAuditChainRecordsAndVerifies is the end-to-end property: rows appended
// normally verify, and each kind of tampering is caught.
func TestAuditChainRecordsAndVerifies(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	for _, e := range []audit.Event{
		{Action: "oauth.token", Subject: "usr_1", Provider: "oauth", Outcome: audit.OutcomeOK,
			Detail: map[string]string{"client_id": "cli"}},
		{Action: "vault.use", Subject: "usr_1", Provider: "phigros.taptap", Outcome: audit.OutcomeOK},
		{Action: "account.delete", Subject: "usr_2", Provider: "account", Outcome: audit.OutcomeOK},
	} {
		if err := logger.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Chained != 3 {
		t.Fatalf("verification = %+v, want OK over 3 chained rows", v)
	}

	// An edited row must be caught: row_hash no longer recomputes. Targeted by
	// action rather than by subject, because the subject column holds a pseudonym.
	tag, err := db.pool.Exec(ctx,
		`UPDATE audit_events SET outcome = 'denied' WHERE action = 'vault.use'`)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("the edit touched %d rows, want exactly 1 (a no-op edit would prove nothing)",
			tag.RowsAffected())
	}
	v, err = logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatal("an edited row verified")
	}
	if v.Reason == "" || v.FirstBadID == 0 {
		t.Errorf("verification gave no reason: %+v", v)
	}
}

// TestAuditChainCatchesDeletion: removing a row from the middle breaks the
// linkage of the row that followed it.
func TestAuditChainCatchesDeletion(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := logger.Record(ctx, audit.Event{
			Action: "oauth.token", Subject: "usr_1", Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.pool.Exec(ctx, `
		DELETE FROM audit_events
		 WHERE id = (SELECT min(id) FROM audit_events)`); err != nil {
		t.Fatal(err)
	}

	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatal("a deleted row verified")
	}
}

// TestAuditChainCatchesAReSignWithTheWrongKey: an attacker who rewrites the whole
// chain can recompute every hash, but cannot produce a signature without the key.
// This is the scenario the HMAC exists for, and the one a plain hash chain misses.
func TestAuditChainCatchesAReSignWithTheWrongKey(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	if err := logger.Record(ctx, audit.Event{
		Action: "oauth.token", Subject: "usr_1", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatal(err)
	}

	// Rewrite the row and recompute a self-consistent hash — everything except the
	// signature, which needs the key.
	row := auditRow{
		OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		Action:     "oauth.token", Subject: "usr_1", Outcome: audit.OutcomeOK,
		Detail: map[string]string{},
	}
	// Read back the stored timestamp so the rewrite keeps the chain link honest.
	var stored time.Time
	if err := db.pool.QueryRow(ctx, `SELECT occurred_at FROM audit_events`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	row.OccurredAt = stored.UTC()
	forged := chainHash(auditGenesis, row.canonical())
	if _, err := db.pool.Exec(ctx, `
		UPDATE audit_events SET action = 'oauth.token', subject = 'usr_1', outcome = 'ok',
		       row_hash = $1, signature = $2 WHERE id = (SELECT min(id) FROM audit_events)`,
		forged, bytes.Repeat([]byte{0x00}, sha256.Size)); err != nil {
		t.Fatal(err)
	}

	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatal("a forged signature verified")
	}
	if v.Reason != "signature does not verify" {
		t.Errorf("reason = %q, want the signature check to fail", v.Reason)
	}
}

// TestAuditVerifyCountsLegacyRows: rows written before the chain are reported as
// uncovered rather than silently skipped.
func TestAuditVerifyCountsLegacyRows(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	// A row as the pre-0013 schema would have written it: no hashes.
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO audit_events (occurred_at, action, subject, provider, outcome, detail)
		VALUES (now(), 'legacy.event', 'usr_old', '', 'ok', '{}')`); err != nil {
		t.Fatal(err)
	}
	if err := logger.Record(ctx, audit.Event{
		Action: "oauth.token", Subject: "usr_new", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatal(err)
	}

	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("verification failed: %+v", v)
	}
	if v.Legacy != 1 || v.Chained != 1 {
		t.Fatalf("verification = %+v, want 1 legacy and 1 chained", v)
	}
}

// TestAuditVerifyRejectsAnUnchainedRowAfterTheChain: clearing a row's hash would
// otherwise downgrade it to "legacy" and skip it.
func TestAuditVerifyRejectsAnUnchainedRowAfterTheChain(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	if err := logger.Record(ctx, audit.Event{
		Action: "oauth.token", Subject: "usr_1", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO audit_events (occurred_at, action, subject, provider, outcome, detail)
		VALUES (now(), 'injected', 'usr_1', '', 'ok', '{}')`); err != nil {
		t.Fatal(err)
	}

	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatal("an unchained row inserted after the chain began verified")
	}
}
