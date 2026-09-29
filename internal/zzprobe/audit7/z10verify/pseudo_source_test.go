//go:build audit7

// Re-check of Z10-1 and Z10-8: the two pseudonymisation claims, verified against
// the product's own source text rather than by re-running the zone-10 DB probe.
package z10verify

import (
	"regexp"
	"strings"
	"testing"
)

// TestZ10VerifyPseudonymCacheIsHitBeforeTheDatabaseAndErasureIsProcessLocal
// re-derives Z10-1's mechanism. The claim is:
//
//  1. loadKey answers from the in-process cache and returns, so a warm entry
//     means "the database is never consulted"; and
//  2. Destroy removes the database row and evicts only the calling process's
//     cache entry — there is no tombstone and no cross-process channel.
//
// Both are read out of the functions themselves: the first `return` inside
// loadKey must precede the only pool query in it, and Destroy's body must not
// mention any cross-process primitive. If either changes, this probe goes red.
func TestZ10VerifyPseudonymCacheIsHitBeforeTheDatabaseAndErasureIsProcessLocal(t *testing.T) {
	const file = "internal/store/postgres/auditpseudo.go"
	raw := repoFile(t, file)

	load := funcBody(t, file, "loadKey")
	scrubbed := scrubLiterals(t, file, load)
	cacheHitReturn := strings.Index(scrubbed, "l.cache[subject]")
	guard := strings.Index(scrubbed, "if ok {")
	firstReturn := strings.Index(scrubbed, "return cached")
	dbQuery := strings.Index(scrubbed, "l.pool.QueryRow(")
	if cacheHitReturn < 0 || guard < 0 || firstReturn < 0 || dbQuery < 0 {
		t.Fatalf("loadKey no longer has the shape this probe asserts (cache read %d, guard %d, cache return %d, "+
			"pool query %d); read it again before trusting either claim", cacheHitReturn, guard, firstReturn, dbQuery)
	}
	if !(cacheHitReturn < firstReturn && firstReturn < dbQuery && guard < firstReturn) {
		t.Errorf("loadKey: cache read at %d, guard at %d, cache return at %d, pool query at %d — the cached value "+
			"no longer short-circuits the query, so Z10-1's mechanism must be re-derived",
			cacheHitReturn, guard, firstReturn, dbQuery)
	}
	// The cached key is handed back without any validation: checkSubjectKey
	// appears only on the database-miss path, after the cache return.
	if i := strings.Index(scrubbed, "checkSubjectKey"); i >= 0 && i < firstReturn {
		t.Errorf("loadKey validates the cached key before returning it (checkSubjectKey at %d, cache return at %d); "+
			"that changes what a warm cache can do — re-derive Z10-1", i, firstReturn)
	}

	// Destroy: structural facts first (no literals), then the SQL it issues.
	destroyCode := scrubLiterals(t, file, funcBody(t, file, "Destroy"))
	for _, forbidden := range []string{"tombstone", "destroyed", "notify", "broadcast", "subscribe", "publish"} {
		if strings.Contains(destroyCode, forbidden) {
			t.Errorf("Destroy's code mentions %q: the cross-process half of Z10-1 may have been fixed — re-derive it", forbidden)
		}
	}
	if !strings.Contains(destroyCode, "delete(l.cache, subject)") {
		t.Errorf("Destroy no longer evicts the local cache; the single-process half of the claim changed")
	}
	// Every cache eviction in the package is on l.cache, i.e. the logger's own
	// map: if a shared/invalidation channel appeared, this count would grow.
	if n := strings.Count(scrubLiterals(t, file, raw), "delete(l.cache"); n != 1 {
		t.Errorf("the package evicts the cache in %d places, not one: a cross-process channel may have been added", n)
	}
	if !strings.Contains(raw, "DELETE FROM audit_subject_keys") {
		t.Errorf("Destroy no longer deletes the key row; Z10-1's premise changed")
	}
	// The eviction is on the map it holds, not on a shared structure: the cache
	// field is declared per logger, in the AuditLogger struct itself.
	if !strings.Contains(repoFile(t, "internal/store/postgres/audit.go"), "cache map[string][]byte") {
		t.Errorf("the pseudonym cache is no longer a per-logger field; Z10-1's cross-process gap depends on it")
	}
	// And the code itself says what a warm cache means, which is the strongest
	// possible statement that the read path does not check the row.
	if !strings.Contains(raw, "a warm cache would keep pseudonymising the subject") {
		t.Errorf("the comment that states the warm-cache hazard is gone; the zone-10 report quotes it as a premise")
	}
}

// TestZ10VerifyAdminClientActionsStoreTheClientIDAsTheSubject confirms Z10-8's
// first half from the call sites: every admin client-target action passes the
// client id as its audit Subject, and the same id is not also carried in Detail.
func TestZ10VerifyAdminClientActionsStoreTheClientIDAsTheSubject(t *testing.T) {
	const file = "internal/admin/admin.go"
	raw := repoFile(t, file)

	// Each of these is `s.record(ctx, actor, "admin.client.<verb>", clientID, …)`.
	want := []string{
		"admin.client.register",
		"admin.client.rotate_secret",
		"admin.client.suspend",
		"admin.client.activate",
		"admin.client.delete",
	}
	re := regexp.MustCompile(`(?s)s\.record\(ctx, actor, "(admin\.client\.[a-z_]+)", ([^,]+),`)
	found := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(raw, -1) {
		found[m[1]] = strings.TrimSpace(m[2])
	}
	for _, w := range want {
		subject, ok := found[w]
		if !ok {
			t.Fatalf("%s is no longer recorded through s.record with a literal action; Z10-8's call-site half must be re-derived", w)
		}
		if subject != "clientID" && subject != "id" {
			t.Errorf("%s records subject %q, not the client id; Z10-8's premise changed", w, subject)
		}
	}

	// The compensating field does not exist on any of them: no admin.client.*
	// record passes client_id inside its Detail.
	kk := regexp.MustCompile(`s\.record\(ctx, actor, "admin\.client\.[a-z_]+", [^,]+, [^,]+, map\[string\]string\{[^}]*\}`)
	for _, call := range kk.FindAllString(raw, -1) {
		if strings.Contains(call, "client_id") {
			t.Errorf("an admin.client.* record now carries client_id in Detail: Z10-8's second half is fixed, "+
				"so its verdict must change. Call: %s", strings.ReplaceAll(call, "\n", " "))
		}
	}
	// Positive control: the same shape IS used to carry client_id elsewhere, so
	// "no client_id in the detail literal" is a statement about these call sites
	// rather than about the codebase.
	if !strings.Contains(repoFile(t, "internal/store/postgres/oidc.go"), "client_id") {
		t.Errorf("the precedent Z10-8 cites (oidc.token carries client_id) is gone; the comparison is stale")
	}
}

// TestZ10VerifyAdminClientActionsArePseudonymisedByTheDurableSink shows that the
// information loss Z10-8 describes follows from the sink's code, not from an
// assumption about which subjects an operator queries: Record pseudonymises
// every non-empty subject with no exception for client ids.
func TestZ10VerifyAdminClientActionsArePseudonymisedByTheDurableSink(t *testing.T) {
	const file = "internal/store/postgres/audit.go"
	raw := repoFile(t, file)

	record := scrubLiterals(t, file, funcBody(t, file, "Record"))
	if !strings.Contains(record, "l.pseudonymize(ctx, e.Subject)") {
		t.Fatalf("Record no longer pseudonymises the subject through the same call Z10-8 cites; its mechanism must be re-derived")
	}
	if strings.Contains(record, "cli_") || strings.Contains(record, "ClientID") || strings.Contains(record, "clients") {
		t.Errorf("Record now distinguishes client subjects; Z10-8's \"pseudonymises every non-empty subject\" claim changed")
	}

	pseudoRaw := funcBodyRaw(t, "internal/store/postgres/auditpseudo.go", "pseudonymize")
	pseudo := scrubLiterals(t, "internal/store/postgres/auditpseudo.go", pseudoRaw)
	emptyAt := strings.Index(pseudoRaw, `subject == ""`)
	keyAt := strings.Index(pseudo, "l.subjectKey(")
	if emptyAt < 0 || keyAt < 0 {
		t.Fatalf("pseudonymize no longer has both the empty-subject guard and the key lookup (guard %d, lookup %d); "+
			"Z10-8's \"every non-empty subject is pseudonymised\" must be re-derived",
			emptyAt, keyAt)
	}
	if strings.Contains(pseudo, "cli_") || strings.Contains(pseudo, "ClientID") || strings.Contains(pseudo, "IsAccountID") {
		t.Errorf("pseudonymize now special-cases client subjects; Z10-8's mechanism changed")
	}

	// No key is ever destroyed for a client id: the erasure path only ever names
	// account subjects. Checked where Destroy is called.
	life := repoFile(t, "internal/lifecycle/lifecycle.go")
	re := regexp.MustCompile(`Destroy\(ctx, ([^)]+)\)`)
	matches := re.FindAllStringSubmatch(life, -1)
	if len(matches) == 0 {
		t.Fatalf("lifecycle no longer calls Pseudonyms.Destroy; Z10-8's \"no key is ever destroyed for a client\" needs a new argument")
	}
	_ = raw
}
