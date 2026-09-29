//go:build audit7

// Zone-10 probe: a second instance's warm pseudonym cache survives an erasure
// performed by a different instance.
package z10adminauditprivacy

import (
	"bytes"
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/store/postgres"
)

// auditKey is a fixed 32-byte chain key, so a failure message is reproducible.
func probeAuditKey() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

// TestZ10SecondInstancesPseudonymCacheSurvivesAnErasureDoneElsewhere.
//
// docs/architecture.md §4.17 states three things that this probe tests together:
//
//   - "抹除 = 删掉 audit_subject_keys 里那一行。行没了，谁都算不出该 subject 的假名";
//   - "销毁之后同一 subject 若再来事件…会拿到新的 key、不同的假名";
//   - "跨进程缓存不破坏擦除…不可关联性来自密钥行不存在，与缓存无关".
//
// The third claim is the one that does not hold. loadKey returns a cached key
// without ever consulting the database, and Destroy evicts the cache of the
// process that runs it — no other process's. The shipped deployment runs
// replicas: 2 against one database, so the erasure and the reader are routinely
// different processes.
func TestZ10SecondInstancesPseudonymCacheSurvivesAnErasureDoneElsewhere(t *testing.T) {
	dsn := probeDSN(t)
	ctx := context.Background()
	resetAuditTables(t, ctx, dsn)

	// Two independent handles on one database: two instances.
	instanceA, err := postgres.Open(ctx, dsn, postgres.DefaultPoolOptions())
	if err != nil {
		t.Fatalf("open instance A: %v", err)
	}
	t.Cleanup(instanceA.Close)
	instanceB, err := postgres.Open(ctx, dsn, postgres.DefaultPoolOptions())
	if err != nil {
		t.Fatalf("open instance B: %v", err)
	}
	t.Cleanup(instanceB.Close)

	logA, err := instanceA.Audit(probeAuditKey())
	if err != nil {
		t.Fatalf("instance A audit: %v", err)
	}
	logB, err := instanceB.Audit(probeAuditKey())
	if err != nil {
		t.Fatalf("instance B audit: %v", err)
	}

	const subject = "usr_erased0000000000000000"
	if err := logA.Record(ctx, audit.Event{
		Action: "oidc.token", Subject: subject, Provider: "oidc", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatalf("record on A: %v", err)
	}

	// B reads the account's history: it resolves the subject through the database
	// and caches the key it finds.
	page, err := logB.Query(ctx, audit.Query{Subject: subject})
	if err != nil {
		t.Fatalf("query on B: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("control: B's first query returned %d rows, want 1: the subject filter did not resolve at all",
			len(page.Entries))
	}
	beforePseudo := page.Entries[0].Subject

	// The erasure runs somewhere else — instance A — and succeeds.
	if err := logA.Destroy(ctx, subject); err != nil {
		t.Fatalf("destroy on A: %v", err)
	}

	// B, which never learned about the erasure, is asked again.
	page, err = logB.Query(ctx, audit.Query{Subject: subject})
	if err != nil {
		t.Fatalf("query after destroy on B: %v", err)
	}
	if len(page.Entries) != 0 {
		t.Errorf("after instance A destroyed %s's pseudonym key, instance B still returned %d of its audit "+
			"rows (%s=%q): loadKey (auditpseudo.go) answers from B's process cache without consulting the "+
			"database, and Destroy only evicts the cache of the process that ran it. docs/architecture.md "+
			"§4.17 claims the opposite (\"跨进程缓存不破坏擦除…与缓存无关\") and docs/admin.md §5.1 promises "+
			"the subject filter returns an empty page once the key is destroyed.",
			subject, len(page.Entries), "subject", beforePseudo)
	}

	// And B keeps writing the old pseudonym, so the claim that a post-destroy
	// event "gets a new key and a different pseudonym" does not hold either.
	if err := logB.Record(ctx, audit.Event{
		Action: "vault.use", Subject: subject, Provider: "vault", Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatalf("record after destroy on B: %v", err)
	}
	page, err = logB.Query(ctx, audit.Query{Subject: subject})
	if err != nil {
		t.Fatalf("query the new row on B: %v", err)
	}
	for _, e := range page.Entries {
		if e.Action == "vault.use" {
			t.Errorf("an event recorded after the erasure was stored under the OLD pseudonym %q (same as the "+
				"pre-erasure row): instance B's cache re-links the account the erasure made unlinkable",
				e.Subject)
		}
	}
}
