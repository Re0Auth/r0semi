package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// TestAuditVerifyRejectsAForgedUnsignedRowWithNoSealedCeiling is the live-Postgres
// half of the Z10-2 residual the source guard
// TestVerifyRejectsAnUnchainedRowWithNoSealedCeiling pins.
//
// legacy_ceiling_id is 0 both on a log that never had a pre-chain row and on a
// chain that has not started. A writer with DB write access can plant a row at
// id 0 with OVERRIDING SYSTEM VALUE; `id > legacyCeiling` is then `0 > 0`, false,
// and because no chained row has been walked yet the walk used to count the row
// as legacy and answer ok. The fix requires a non-zero ceiling for any NULL-hash
// row to be legacy. A database-backed test is the only way to exercise the
// identity override and the real ORDER BY id walk.
func TestAuditVerifyRejectsAForgedUnsignedRowWithNoSealedCeiling(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	// Control: the fixture re-seeds audit_chain with the column default, so
	// nothing is sealed as pre-chain. If this is not 0 the premise below is
	// wrong rather than the probe failing.
	var ceiling int64
	if err := db.pool.QueryRow(ctx,
		`SELECT legacy_ceiling_id FROM audit_chain WHERE only_row`).Scan(&ceiling); err != nil {
		t.Fatal(err)
	}
	if ceiling != 0 {
		t.Fatalf("the fixture left legacy_ceiling_id = %d, want 0; the probe's premise (no ceiling "+
			"sealed) does not hold", ceiling)
	}

	if err := logger.Record(ctx, audit.Event{
		Action: "oidc.token", Subject: "usr_1", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatal(err)
	}
	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Chained != 1 || v.Legacy != 0 {
		t.Fatalf("control: a fresh log verifies as %+v, want ok with one chained row", v)
	}

	// The forgery: an unsigned row at id 0, before the chain. The identity column
	// needs OVERRIDING SYSTEM VALUE; the schema is GENERATED ALWAYS.
	tag, err := db.pool.Exec(ctx, `
		INSERT INTO audit_events
			(id, occurred_at, action, subject, provider, outcome, detail)
		OVERRIDING SYSTEM VALUE
		VALUES (0, now(), 'admin.kill_switch', 'planted', 'admin', 'ok', '{}'::jsonb)`)
	if err != nil {
		t.Fatalf("plant the forged id-0 row: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("the forgery touched %d rows, want exactly 1; the probe would prove nothing", tag.RowsAffected())
	}

	v, err = logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Errorf("Verify reports ok=true (chained=%d legacy=%d) for a log containing an unsigned id-0 row "+
			"while legacy_ceiling_id is 0: `id > 0` is false and the chain has not started, so the row is "+
			"blessed as migration-era. Nothing was ever sealed as pre-chain, so no NULL-hash row can be "+
			"legitimate (Z10-2).", v.Chained, v.Legacy)
	}
	if !strings.Contains(v.Reason, "legacy ceiling") {
		t.Errorf("Verify failed for %q, not the legacy-ceiling check; re-derive this guard", v.Reason)
	}
}
