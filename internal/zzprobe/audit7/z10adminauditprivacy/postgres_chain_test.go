//go:build audit7

// Zone-10 probe: what the audit chain's Verify does not cover — a row that was
// never signed, and a chain head that names no row.
package z10adminauditprivacy

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
)

// TestZ10VerifyAcceptsAForgedUnsignedRowBeforeTheChainStarts.
//
// Verify counts every row whose row_hash is NULL that appears before the chain
// began as "legacy" and carries on. That is right for rows written before
// migration 0013 — but nothing bounds what "before the chain" is, and
// audit_events.id is an identity column an attacker with SQL access can override
// (OVERRIDING SYSTEM VALUE), so a forged row can be placed below the first chained
// row. The chain's own documentation (migration 0013) lists what it catches —
// editing, deleting mid-chain, reordering, rewriting — and insertion is not among
// them; there is nothing in the log that says which NULL-hash rows are genuinely
// pre-0013.
func TestZ10VerifyAcceptsAForgedUnsignedRowBeforeTheChainStarts(t *testing.T) {
	dsn := probeDSN(t)
	ctx := context.Background()
	resetAuditTables(t, ctx, dsn)

	db, err := postgres.Open(ctx, dsn, postgres.DefaultPoolOptions())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	logger, err := db.Audit(probeAuditKey())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	for i := 0; i < 2; i++ {
		if err := logger.Record(ctx, audit.Event{
			Action: "oidc.token", Subject: "", Provider: "oidc", Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.OK || v.Chained != 2 {
		t.Fatalf("control: a fresh log verifies as %+v, want ok with 2 chained rows", v)
	}

	// The forgery: a row nobody signed, placed below the first chained row. It
	// carries an action and an outcome of the attacker's choosing.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("raw pool: %v", err)
	}
	defer pool.Close()
	const planted = "planted-pseudonym"
	_, overrideErr := pool.Exec(ctx, `
		INSERT INTO audit_events
			(id, occurred_at, action, subject, provider, outcome, detail)
		OVERRIDING SYSTEM VALUE
		VALUES (0, now(), 'admin.kill_switch', $1, 'admin', 'ok', '{}'::jsonb)`, planted)
	if overrideErr != nil {
		// Fallback for a schema or server that refuses the explicit identity:
		// insert honestly, then move the row down past the chain start.
		if _, err := pool.Exec(ctx, `
			INSERT INTO audit_events (occurred_at, action, subject, provider, outcome, detail)
			VALUES (now(), 'admin.kill_switch', $1, 'admin', 'ok', '{}'::jsonb)`, planted); err != nil {
			t.Fatalf("the probe could not insert a row to forge (OVERRIDING SYSTEM VALUE: %v): %v", overrideErr, err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE audit_events SET id = 0 WHERE subject = $1`, planted); err != nil {
			t.Fatalf("the probe could not place the forged row before the chain (OVERRIDING SYSTEM VALUE: %v; "+
				"UPDATE id: %v); adapt the probe to the schema", overrideErr, err)
		}
		t.Logf("used the INSERT-then-UPDATE-id fallback (OVERRIDING SYSTEM VALUE said: %v)", overrideErr)
	}

	v, err = logger.Verify(ctx)
	if err != nil {
		t.Fatalf("verify after forgery: %v", err)
	}
	if v.OK {
		t.Errorf("Verify reports ok=true (chained=%d legacy=%d) for a log that now contains a row nobody signed, "+
			"inserted after the migration ran and placed before the chain start. It is accepted as \"legacy\" "+
			"because Verify treats every NULL row_hash before the first chained row as pre-0013. Nothing records "+
			"which rows were genuinely pre-0013, so a database-write attacker can plant audit entries "+
			"(an operator action, a consent decision) that the integrity check blesses.", v.Chained, v.Legacy)
	}
	if v.Legacy == 0 {
		t.Errorf("the forged row is not even counted as legacy (%+v); the probe did not insert what it thinks", v)
	}
}

// TestZ10VerifyDoesNotCheckTheHeadAgainstTheLastRow was the Z10-9 finding and is
// now its regression guard (the name is kept for the audit coverage matrix).
//
// Verify reads audit_chain.head_hash as a witness that rows were chained, but used
// to never compare it to the row hash the walk actually ended on, so a head
// pointing at a value that belongs to no row verified: the log looked intact while
// the anchor loop published a hash no row carried. Verify now compares the two
// (S09-6 / Z10-9), which is also what makes a deleted tail detectable without an
// external anchor.
func TestZ10VerifyDoesNotCheckTheHeadAgainstTheLastRow(t *testing.T) {
	dsn := probeDSN(t)
	ctx := context.Background()
	resetAuditTables(t, ctx, dsn)

	db, err := postgres.Open(ctx, dsn, postgres.DefaultPoolOptions())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	logger, err := db.Audit(probeAuditKey())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := logger.Record(ctx, audit.Event{
			Action: "oidc.token", Subject: "", Provider: "oidc", Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	realHead, err := logger.Head(ctx)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if len(realHead) == 0 {
		t.Fatalf("control: the chain head is still the genesis after three appends")
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("raw pool: %v", err)
	}
	defer pool.Close()
	planted := bytes.Repeat([]byte{0xde, 0xad}, 16)
	if _, err := pool.Exec(ctx,
		`UPDATE audit_chain SET head_hash = $1 WHERE only_row`, planted); err != nil {
		t.Fatalf("plant a head: %v", err)
	}

	head, err := logger.Head(ctx)
	if err != nil {
		t.Fatalf("head after tampering: %v", err)
	}
	if !bytes.Equal(head, planted) {
		t.Fatalf("control: Head returned %x, want the planted %x", head, planted)
	}

	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.OK {
		t.Errorf("Verify reports ok=true while the chain head (%x) is not the hash of the last chained row: "+
			"the head comparison Z10-9 added is gone, so a rewritten or truncated tail verifies and the "+
			"published anchor can name a value the log does not contain.", planted)
	}
	if !strings.Contains(v.Reason, "chain head") {
		t.Errorf("Verify failed for a reason other than the head comparison (%q); re-derive this guard", v.Reason)
	}
	// The planted head also makes the next append fail its own verification,
	// which is the state an operator would have to notice instead.
	if err := logger.Record(ctx, audit.Event{
		Action: "oidc.token", Subject: "", Provider: "oidc", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Logf("context: appending after the planted head failed with %v", err)
	} else if v2, verr := logger.Verify(ctx); verr == nil {
		t.Logf("context: the log now verifies as %+v (ok=%v reason=%q)", v2, v2.OK, v2.Reason)
	}
}
