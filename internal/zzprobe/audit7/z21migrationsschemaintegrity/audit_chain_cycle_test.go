//go:build audit7

package z21migrationsschemaintegrity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// This probe covers the audit chain's behaviour across a goose Down/Up cycle.
//
// The database is not available here, so the *mechanism* is taken from the
// shipped SQL and the model of Verify is taken line by line from
// internal/store/postgres/auditchain.go:258-331:
//
//	row_hash == NULL        -> counted Legacy, skipped
//	a row with row_hash but a non-empty prev_hash, while `started` is false
//	                        -> OK=false, "first chained row does not point at the genesis hash"
//	chained == 0 and head != empty
//	                        -> OK=false, "the chain head has advanced but no chained row was found"
//
// The state transition is taken from migration 0013's Down
// (migrations/0013_audit_chain.sql:50-55) and its Up (:30-32, :38-48), which is
// the whole of what `re0auth -migrate-down` and the next `Open()` do.

// These four strings are copied verbatim from the shipped product code so a
// rename in the source is caught here rather than silently modelled wrong.
var (
	verifyReasonFirstNotGenesis = "first chained row does not point at the genesis hash"
	verifyReasonHeadAdvanced    = "the chain head has advanced but no chained row was found: the chain metadata was cleared"
)

// chainedRow is the subset of an audit_events row the model needs.
type chainedRow struct {
	prevHash []byte
	rowHash  []byte
}

// modelVerify mirrors auditchain.go's walk closely enough to decide the two
// verdicts this probe cares about.
func modelVerify(rows []chainedRow, head []byte) (ok bool, reason string) {
	var (
		started bool
		chained int
	)
	for _, r := range rows {
		if r.rowHash == nil {
			if started {
				return false, "unchained row appears after the chain began"
			}
			continue
		}
		if !started {
			started = true
			if len(r.prevHash) != 0 {
				return false, verifyReasonFirstNotGenesis
			}
		}
		chained++
	}
	if chained == 0 && len(head) != 0 {
		return false, verifyReasonHeadAdvanced
	}
	return true, ""
}

func chainHash(prev, row []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(row)
	return h.Sum(nil)
}

// TestAuditVerifyModelIsNotVacuous pins the model itself: the code path that
// reports "first chained row does not point at the genesis hash" only exists if
// the model can both accept a healthy chain and reject a titled one.
func TestAuditVerifyModelIsNotVacuous(t *testing.T) {
	head := []byte{}
	r1 := chainedRow{prevHash: []byte{}, rowHash: []byte{1}}
	r2 := chainedRow{prevHash: []byte{1}, rowHash: []byte{2}}

	if ok, reason := modelVerify([]chainedRow{r1, r2}, head); !ok {
		t.Fatalf("model rejected a healthy chain: %s", reason)
	}
	// Control 1: a chain whose first row does not point at genesis.
	if ok, reason := modelVerify([]chainedRow{{prevHash: []byte{9}, rowHash: []byte{2}}}, head); ok ||
		reason != verifyReasonFirstNotGenesis {
		t.Fatalf("model accepted a title pointing away from genesis (ok=%v reason=%q)", ok, reason)
	}
	// Control 2: the head advanced but no row is chained.
	if ok, reason := modelVerify([]chainedRow{{}}, []byte{7}); ok || reason != verifyReasonHeadAdvanced {
		t.Fatalf("model accepted cleared chain metadata (ok=%v reason=%q)", ok, reason)
	}
	if head := chainHash(nil, []byte("row")); len(head) != 32 {
		t.Fatalf("chainHash produced %d bytes, want 32", len(head))
	}
}

// TestAuditChainSurvivesADownUpCycle is the Z21-2 probe, and it reads the
// migration's Down section from disk instead of hardcoding what it does. It has
// two branches:
//
//   - the Down executes DDL (the pre-fix state): the chain columns and the head
//     are dropped and re-seeded by the Up, every historical hash column comes
//     back NULL, Verify calls all of them Legacy, and OK is still true. RED.
//   - the Down executes nothing (the fixed state): the chain is untouched by the
//     cycle, which is only actually true if the Up is idempotent and does not
//     rewind a surviving head to genesis. The Up is asserted directly, because
//     modelVerify cannot see a head that was rewound: a chain whose rows are
//     still hashed verifies OK against any head as long as one row is chained.
func TestAuditChainSurvivesADownUpCycle(t *testing.T) {
	rows := []chainedRow{
		{ /* two pre-0013 rows, unchained legacy */ },
		{},
		{prevHash: []byte{}, rowHash: chainHash(nil, []byte("audit row 1"))},
		{prevHash: chainHash(nil, []byte("audit row 1")), rowHash: chainHash(chainHash(nil, []byte("audit row 1")), []byte("audit row 2"))},
	}
	headBefore := rows[len(rows)-1].rowHash

	if ok, reason := modelVerify(rows, headBefore); !ok {
		t.Fatalf("precondition: the healthy chain was rejected before the cycle: %s", reason)
	}

	raw := readAll(t, migrationFiles(t))
	body, ok := raw["0013_audit_chain.sql"]
	if !ok {
		t.Fatalf("0013_audit_chain.sql is not among the migration files; the locator is broken")
	}
	up, down := splitDirection(body)
	if strings.TrimSpace(down) == "" {
		t.Fatalf("0013 has no Down section; the probe is reading the wrong text")
	}

	// What the Down actually executes, read from the file. Comments are stripped
	// first: the fixed Down documents at length why it does nothing, and prose is
	// not SQL.
	executed := strings.TrimSpace(stripSQLComments(down))

	if executed != "" {
		// Pre-fix state. 0013's Down dropped audit_chain and the three
		// audit_events columns; no DROP or DELETE of audit_events appears
		// anywhere, so the rows survive with their chain metadata cleared. The Up
		// then re-seeds the head to the genesis hash rather than re-deriving it
		// from the surviving rows.
		after := make([]chainedRow, len(rows))
		for i := range after {
			after[i] = chainedRow{} // row_hash/prev_hash were dropped and re-added, so NULL
		}
		headAfter := []byte{} // 0013's Up seeds the genesis

		if ok, reason := modelVerify(after, headAfter); !ok {
			t.Errorf("REGRESSION NOT FLAGGED: model says the post-cycle log is bad (%s)", reason)
		} else {
			t.Errorf("AUDIT CHAIN LOST BY A DOWN/UP CYCLE (silently): 0013's Down still executes "+
				"%q, so after the cycle all %d chained rows read back as legacy (their hash "+
				"columns were dropped and re-added) and the re-created head is the genesis, so "+
				"Verify reports OK with every linkage and signature the chain held gone. The "+
				"next new row chains from genesis, forking from the historical rows.",
				strings.TrimSpace(executed), len(rows)-2)
		}

		// Control: if the chain metadata HAD survived, the head would not be the
		// genesis and the walk would notice something is wrong.
		if ok, _ := modelVerify(after, headBefore); ok {
			t.Errorf("control failed: the model called the lost metadata 'chained' as well")
		}
		return
	}

	// Fixed state: the Down executes nothing, so the modelled chain is unchanged
	// and Verify still passes. This half is a definition rather than a discovery —
	// the content of the green branch is the Up assertions below, because a no-op
	// Down is only safe if the re-run Up neither collides with nor rewinds the
	// objects that survived it.
	if ok, reason := modelVerify(rows, headBefore); !ok {
		t.Errorf("the chain was rejected after a no-op Down: %s", reason)
	}

	// goose deletes the version row for a Down that runs no statements, so the
	// next Open() re-runs this Up against the surviving objects. The Up must
	// therefore be idempotent and must not rewind a surviving head to genesis.
	upNoComments := strings.ToUpper(stripSQLComments(up))
	for _, want := range []string{
		"ALTER TABLE AUDIT_EVENTS ADD COLUMN IF NOT EXISTS PREV_HASH",
		"ALTER TABLE AUDIT_EVENTS ADD COLUMN IF NOT EXISTS ROW_HASH",
		"ALTER TABLE AUDIT_EVENTS ADD COLUMN IF NOT EXISTS SIGNATURE",
		"CREATE UNIQUE INDEX IF NOT EXISTS AUDIT_EVENTS_ROW_HASH_IDX",
		"CREATE TABLE IF NOT EXISTS AUDIT_CHAIN",
		"ON CONFLICT (ONLY_ROW) DO NOTHING",
	} {
		if !strings.Contains(upNoComments, want) {
			t.Errorf("the Down is a no-op but the Up is not idempotent: it no longer contains %q. "+
				"The next Open() re-runs this Up against the surviving schema, so a bare "+
				"statement fails with `already exists`, and an unconditional INSERT rewinds a "+
				"real surviving chain head to genesis.", want)
		}
	}
	for _, pair := range []struct{ bare, idempotent string }{
		{"ADD COLUMN", "ADD COLUMN IF NOT EXISTS"},
		{"CREATE TABLE", "CREATE TABLE IF NOT EXISTS"},
		{"CREATE UNIQUE INDEX", "CREATE UNIQUE INDEX IF NOT EXISTS"},
	} {
		if got, want := strings.Count(upNoComments, pair.bare), strings.Count(upNoComments, pair.idempotent); got != want {
			t.Errorf("the Up has %d %q statement(s) but only %d idempotent ones", got, pair.bare, want)
		}
	}
}

// TestDownDoesNotDropAuditRows is the source-level premise of the finding: the
// audit rows themselves are never deleted by any migration, so the data survives
// the cycle that destroys its tamper-evidence.
func TestDownDoesNotDropAuditRows(t *testing.T) {
	raw := readAll(t, migrationFiles(t))
	for name, body := range raw {
		_, down := splitDirection(body)
		for _, stmt := range strings.Split(stripSQLComments(down), ";") {
			u := strings.ToUpper(stmt)
			if strings.Contains(u, "DELETE") || strings.Contains(u, "TRUNCATE") {
				t.Errorf("%s: a Down section deletes rows (%q)", name, strings.TrimSpace(stmt))
			}
			if strings.Contains(u, "DROP TABLE") && !strings.Contains(u, "AUTHZ_REQUESTS") {
				t.Logf("%s: Down drops a table: %q", name, strings.TrimSpace(stmt))
			}
		}
	}

	// Positive control for the extractor: 0013's Up must create the objects its
	// Down used to drop (audit_chain, audit_events_row_hash_idx), or the scan
	// above is looking at the wrong text.
	up13, down13 := splitDirection(raw["0013_audit_chain.sql"])
	if strings.TrimSpace(up13) == "" {
		t.Fatalf("control failed: 0013 has no Up section")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS audit_chain",
		"CREATE UNIQUE INDEX IF NOT EXISTS audit_events_row_hash_idx",
	} {
		if !strings.Contains(strings.ToUpper(up13), strings.ToUpper(want)) {
			t.Fatalf("control failed: 0013's Up does not contain %q", want)
		}
	}
	// And its Down must execute nothing at all: that is the Z21-2 fix. A Down
	// that drops the chain columns silently destroys tamper-evidence (ADR-0008 §5).
	if got := strings.TrimSpace(stripSQLComments(down13)); got != "" {
		t.Fatalf("0013's Down executes SQL (%q); it must be a comment-only no-op", got)
	}

	// 0014's Down destroyed the per-subject keys, which are the only thing that
	// makes an erased account's audit history unlinkable (auditpseudo.go:167-186).
	// It must execute nothing too, and its Up must be idempotent so the next
	// Open()'s re-run does not collide.
	up14, down14 := splitDirection(raw["0014_audit_pseudonyms.sql"])
	if !strings.Contains(strings.ToUpper(up14), "CREATE TABLE IF NOT EXISTS AUDIT_SUBJECT_KEYS") {
		t.Fatalf("control failed: 0014's Up no longer creates audit_subject_keys idempotently")
	}
	if got := strings.TrimSpace(stripSQLComments(down14)); got != "" {
		t.Fatalf("0014's Down executes SQL (%q); it must be a comment-only no-op", got)
	}
	_ = hex.EncodeToString
	_ = hmac.New
}
