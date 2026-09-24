package postgres

import (
	"context"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// recordN writes n events for one subject, spaced so the tests can tell them apart.
func recordN(t *testing.T, l *AuditLogger, subject, action string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Record(context.Background(), audit.Event{
			Action: action, Subject: subject, Provider: "oauth", Outcome: audit.OutcomeOK,
			Detail: map[string]string{"i": string(rune('a' + i))},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAuditQueryResolvesTheSubjectFilter: the caller names an account id, the
// column holds a pseudonym, and the translation has to happen — otherwise the
// filter matches nothing and an operator reading an empty page would conclude the
// account did nothing.
func TestAuditQueryResolvesTheSubjectFilter(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	recordN(t, logger, "usr_a", "oauth.token", 2)
	recordN(t, logger, "usr_b", "oauth.token", 3)

	page, err := logger.Query(ctx, audit.Query{Subject: "usr_a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(page.Entries))
	}
	// The rows describe the pseudonym, not the account id.
	for _, e := range page.Entries {
		if e.Subject == "usr_a" {
			t.Fatal("the raw account id leaked into a result")
		}
	}

	// An action filter combines with it.
	page, err = logger.Query(ctx, audit.Query{Subject: "usr_a", Action: "vault.use"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 0 {
		t.Fatalf("a non-matching action returned %d entries", len(page.Entries))
	}

	// No filter returns everything, newest first by id.
	page, err = logger.Query(ctx, audit.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 5 {
		t.Fatalf("unfiltered entries = %d, want 5", len(page.Entries))
	}
	for i := 1; i < len(page.Entries); i++ {
		if page.Entries[i-1].ID <= page.Entries[i].ID {
			t.Fatal("entries are not ordered newest first")
		}
	}
}

// TestAuditQueryOnAnUnknownSubjectIsEmptyAndSideEffectFree: a read must not mint a
// key. Minting state on a read would make "did anything happen?" mutate the log's
// own key store.
func TestAuditQueryOnAnUnknownSubjectIsEmptyAndSideEffectFree(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	page, err := logger.Query(ctx, audit.Query{Subject: "usr_never_seen"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(page.Entries))
	}
	var keys int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM audit_subject_keys`).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 0 {
		t.Fatalf("the read minted %d subject keys", keys)
	}
}

// TestAdversarialAuditNoKeyPageCarriesTheAppliedLimit: an empty page for a
// subject with no pseudonym key must carry the same page size as any other empty
// page. A zero limit there distinguished "no key exists" (never seen, or erased)
// from "the key exists but the filter matched nothing" — a one-bit
// account-existence oracle on the operator plane — and echoed a page size the API
// never applies.
func TestAdversarialAuditNoKeyPageCarriesTheAppliedLimit(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	noKey, err := logger.Query(ctx, audit.Query{Subject: "usr_never_seen"})
	if err != nil {
		t.Fatal(err)
	}
	if len(noKey.Entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(noKey.Entries))
	}
	if noKey.Limit != defaultAuditPage {
		t.Fatalf("no-key page limit = %d, want %d", noKey.Limit, defaultAuditPage)
	}

	// The same shape from a subject whose key exists but whose filter matches
	// nothing must be indistinguishable from it.
	recordN(t, logger, "usr_seen", "vault.use", 1)
	keyButEmpty, err := logger.Query(ctx, audit.Query{Subject: "usr_seen", Action: "no.such.action"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keyButEmpty.Entries) != 0 {
		t.Fatalf("filtered entries = %d, want 0", len(keyButEmpty.Entries))
	}
	if keyButEmpty.Limit != noKey.Limit {
		t.Fatalf("empty pages differ: with key limit=%d, without key limit=%d",
			keyButEmpty.Limit, noKey.Limit)
	}
}

// TestAuditQueryAfterDestroyReturnsNothing is the erasure property seen from the
// operator's side: the rows are still in the table, and the log can no longer say
// whose they are. The empty page is the correct answer, not a missing feature.
func TestAuditQueryAfterDestroyReturnsNothing(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	recordN(t, logger, "usr_gone", "vault.use", 2)
	page, err := logger.Query(ctx, audit.Query{Subject: "usr_gone"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("before destroy: %d entries, want 2", len(page.Entries))
	}

	if err := logger.Destroy(ctx, "usr_gone"); err != nil {
		t.Fatal(err)
	}

	page, err = logger.Query(ctx, audit.Query{Subject: "usr_gone"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 0 {
		t.Fatalf("after destroy: %d entries, want none", len(page.Entries))
	}
	// The rows themselves are untouched, and the chain still verifies.
	var rows int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("rows = %d: erasure must not delete audit rows", rows)
	}
	v, err := logger.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("chain after destroy = %+v", v)
	}
}

// TestAuditQueryPagesWithoutGapsOrRepeats: the cursor is an exclusive bound on id,
// so walking it must visit every row exactly once.
func TestAuditQueryPagesWithoutGapsOrRepeats(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()

	recordN(t, logger, "usr_a", "oauth.token", 5)

	seen := map[int64]bool{}
	cursor := int64(0)
	for page := 0; page < 10; page++ {
		p, err := logger.Query(ctx, audit.Query{Limit: 2, Before: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Entries {
			if seen[e.ID] {
				t.Fatalf("entry %d came back twice", e.ID)
			}
			seen[e.ID] = true
		}
		if p.NextBefore == 0 {
			break
		}
		cursor = p.NextBefore
	}
	if len(seen) != 5 {
		t.Fatalf("paging saw %d distinct entries, want 5", len(seen))
	}
}

// TestAuditQueryClampsThePageSize: one request must not be able to ask for the
// whole log, and the response must say what it actually applied.
func TestAuditQueryClampsThePageSize(t *testing.T) {
	db := openTestDB(t)
	logger := openAudit(t, db)
	ctx := context.Background()
	recordN(t, logger, "usr_a", "oauth.token", 3)

	page, err := logger.Query(ctx, audit.Query{Limit: maxAuditPage + 10_000})
	if err != nil {
		t.Fatal(err)
	}
	if page.Limit != maxAuditPage {
		t.Fatalf("applied limit = %d, want the %d ceiling", page.Limit, maxAuditPage)
	}

	page, err = logger.Query(ctx, audit.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Limit != defaultAuditPage {
		t.Fatalf("default limit = %d, want %d", page.Limit, defaultAuditPage)
	}
}
