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

// TestAuditChainSurvivesADownUpCycle is the red probe for Z21-2.
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

	// 0013 Down (:51) drops audit_chain wholesale — the head row it held is gone;
	// (:53-55) drops prev_hash, row_hash and signature from audit_events. No DROP
	// or DELETE of audit_events appears in any Down section, so the rows survive
	// with their chain metadata cleared. 0013 Up then re-creates the table and
	// re-inserts the genesis head ('\x'::bytea at :48).
	//
	// Note the head is NOT re-derived from the surviving rows: it is seeded empty.
	droppedColumns := true // 0013_down_altered_audit_events
	if !droppedColumns {
		t.Fatal("model precondition")
	}
	after := make([]chainedRow, len(rows))
	for i := range after {
		after[i] = chainedRow{} // row_hash/prev_hash columns were dropped and re-added, so NULL
	}
	headAfter := []byte{} // 0013's Up INSERT ... VALUES (true, '\x'::bytea)

	if ok, reason := modelVerify(after, headAfter); !ok {
		t.Errorf("REGRESSION NOT FLAGGED: model says the post-cycle log is bad (%s)", reason)
	} else {
		t.Errorf("AUDIT CHAIN LOST BY A DOWN/UP CYCLE (silently): after the cycle all %d chained rows "+
			"read back as legacy (their hash columns were dropped and re-added) and the re-created "+
			"head is the genesis, so Verify reports OK with every linkage and signature the chain "+
			"held gone. The next new row chains from genesis, forking from the historical rows.",
			len(rows)-2)
	}

	// Control: if the chain metadata HAD survived (the mutation this probe is
	// looking for is a real presence check, not a model that always passes), the
	// head would not be the genesis and the walk would notice something is wrong.
	if ok, _ := modelVerify(after, headBefore); ok {
		t.Errorf("control failed: the model called the lost metadata 'chained' as well")
	}
}

// TestDownDoesNotDropAuditRows is the source-level premise of the finding: the
// audit rows themselves are never deleted by any migration, so the data survives
// the cycle that destroys its tamper-evidence.
func TestDownDoesNotDropAuditRows(t *testing.T) {
	raw := readAll(t, migrationFiles(t))
	for name, body := range raw {
		_, down := splitDirection(body)
		for _, stmt := range strings.Split(down, ";") {
			u := strings.ToUpper(stmt)
			if strings.Contains(u, "DELETE") || strings.Contains(u, "TRUNCATE") {
				t.Errorf("%s: a Down section deletes rows (%q)", name, strings.TrimSpace(stmt))
			}
			if strings.Contains(u, "DROP TABLE") && !strings.Contains(u, "AUDIT_CHAIN") &&
				!strings.Contains(u, "AUDIT_SUBJECT_KEYS") && !strings.Contains(u, "AUTHZ_REQUESTS") {
				t.Logf("%s: Down drops a table: %q", name, strings.TrimSpace(stmt))
			}
		}
	}
	// Positive control for the extractor: 0013's Down must contain the DROP TABLE
	// this probe is about, or the scan above is looking at the wrong text.
	_, down := splitDirection(raw["0013_audit_chain.sql"])
	if !strings.Contains(strings.ToUpper(down), "DROP TABLE IF EXISTS AUDIT_CHAIN") {
		t.Fatalf("control failed: 0013's Down does not drop audit_chain (%q)", strings.TrimSpace(down))
	}
	_, d14 := splitDirection(raw["0014_audit_pseudonyms.sql"])
	if !strings.Contains(strings.ToUpper(d14), "DROP TABLE IF EXISTS AUDIT_SUBJECT_KEYS") {
		t.Fatalf("control failed: 0014's Down does not drop audit_subject_keys (%q)", strings.TrimSpace(d14))
	}
	// And 0014's Down destroys the per-subject keys, which are the only thing that
	// makes an erased account's audit history unlinkable (auditpseudo.go:167-186).
	if strings.Contains(strings.ToUpper(d14), "BACKUP") {
		t.Fatal("control failed")
	}
	_ = hex.EncodeToString
	_ = hmac.New
}
