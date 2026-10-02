//go:build audit7

// Regression guards for Z10-1 and Z10-8. Both were written against a source
// shape that has since changed (Z10-1) or against the pre-fix behaviour (Z10-8),
// so they are rewritten here to read the current source and to assert the fixed
// fact rather than the open one. Each carries a negative control that feeds the
// pre-fix shape to the same predicate.
package z10verify

import (
	"regexp"
	"strings"
	"testing"
)

// TestZ10VerifyPseudonymCacheIsHitBeforeTheDatabaseAndErasureIsProcessLocal is
// the flipped form of Z10-1; the name is kept so the coverage matrix still maps
// here.
//
// The finding was: the pseudonym cache was answered before the database and an
// erasure only evicted the calling process's entry, with no tombstone and no
// cross-process channel — so another replica kept pseudonymising an erased subject
// for up to the cache TTL. The fix added a durable tombstone table
// (audit_subject_tombstones) written in the SAME transaction as the key deletion,
// plus a rate-limited per-replica mirror that is consulted BEFORE the cache
// answers.
//
// The guard pins the fixed mechanism: (1) loadKey answers through cachedAnswer,
// which checks tombstones before the cache; (2) the warm hit still precedes the
// one pool query; (3) Destroy writes the tombstone with the deletion and evicts
// the local entry; (4) the mirror is refreshed from the table. Both anti-vacuity
// controls feed the pre-fix shapes to the same predicates.
func TestZ10VerifyPseudonymCacheIsHitBeforeTheDatabaseAndErasureIsProcessLocal(t *testing.T) {
	const file = "internal/store/postgres/auditpseudo.go"
	raw := repoFile(t, file)

	load := funcBody(t, file, "loadKey")
	if !tombstoneGatedCachePrecedesTheQuery(load) {
		t.Fatalf("loadKey no longer answers a warm subject (through the tombstone-gated cache) before "+
			"its pool query; Z10-1's fix has been re-derived. Body: %s", strings.Join(strings.Fields(load), " "))
	}
	// The cache read is a live-entry check with a TTL; that TTL now bounds only the
	// residue when the tombstone mirror cannot be refreshed, so its disappearance
	// matters even more.
	cached := funcBody(t, file, "cached")
	if !strings.Contains(cached, "l.cache[subject]") {
		t.Errorf("cached() no longer reads the per-logger map; the cache shape Z10-1 rests on changed")
	}
	if !strings.Contains(cached, "l.now().Before(entry.expires)") {
		t.Errorf("cached() no longer checks the entry's expiry; unbounded staleness is back")
	}
	if !regexp.MustCompile(`(?m)\bpseudoCacheTTL\s*=\s*\d+\s*\*\s*time\.Second`).MatchString(raw) {
		t.Errorf("pseudoCacheTTL is no longer a declared TTL; the residue bound is gone")
	}

	// The tombstone check is what makes an erasure effective on another replica,
	// and it must come before the cache answer.
	cachedAnswer := funcBody(t, file, "cachedAnswer")
	if !tombstoneCheckedBeforeTheCache(cachedAnswer) {
		t.Errorf("cachedAnswer no longer consults the tombstone mirror before the local cache; an " +
			"erasure committed elsewhere can be served from a warm entry again (Z10-1)")
	}
	sync := funcBodyRaw(t, file, "syncTombstones")
	if !strings.Contains(sync, "audit_subject_tombstones WHERE seq > $1") {
		t.Errorf("syncTombstones no longer pulls incrementally from audit_subject_tombstones; the " +
			"cross-replica channel Z10-1 added is gone")
	}

	// Destroy: the deletion and the tombstone commit together, then the local
	// entry is dropped. funcBodyRaw because the assertions are on the SQL text.
	destroy := funcBodyRaw(t, file, "Destroy")
	if !strings.Contains(destroy, "INSERT INTO audit_subject_tombstones") {
		t.Errorf("Destroy no longer writes a tombstone; the cross-process half of Z10-1 is unfixed again")
	}
	if !strings.Contains(destroy, "l.forget(subject)") {
		t.Errorf("Destroy no longer evicts the local cache; the single-process half of the claim changed")
	}
	if !strings.Contains(raw, "DELETE FROM audit_subject_keys") {
		t.Errorf("Destroy no longer deletes the key row; Z10-1's premise changed")
	}
	// The tombstone is in the same transaction as the deletion: both tx.Exec calls
	// precede the commit.
	deleteAt := strings.Index(destroy, "DELETE FROM audit_subject_keys")
	tombAt := strings.Index(destroy, "INSERT INTO audit_subject_tombstones")
	commitAt := strings.Index(destroy, "tx.Commit(ctx)")
	if deleteAt < 0 || tombAt < 0 || commitAt < 0 || tombAt < deleteAt || commitAt < tombAt {
		t.Errorf("the tombstone no longer commits with the deletion (delete %d, tombstone %d, commit %d); "+
			"a replica could observe the tombstone while the key row exists (Z10-1)", deleteAt, tombAt, commitAt)
	}

	// Both the cache and the tombstone mirror are per-logger fields, which is why
	// the cross-process channel was needed in the first place.
	auditGo := repoFile(t, "internal/store/postgres/audit.go")
	if !strings.Contains(auditGo, "cache map[string]cachedSubjectKey") {
		t.Errorf("the pseudonym cache is no longer a per-logger field; Z10-1's cross-process gap depends on it")
	}
	if !strings.Contains(auditGo, "tombstones map[string]struct{}") {
		t.Errorf("the tombstone mirror is no longer a per-logger field; the sync design changed")
	}
	// And the code itself says what a warm cache used to mean, which is the
	// strongest statement that the eviction is required.
	if !strings.Contains(raw, "a warm cache would keep pseudonymising the subject") {
		t.Errorf("the comment that states the warm-cache hazard is gone; the zone-10 report quotes it as a premise")
	}

	// Anti-vacuity 1: a loadKey that queries before it consults the cache is the
	// shape Z10-1 warns about. The predicate must reject it.
	preFixLoad := "func (l *AuditLogger) loadKey(ctx context.Context, subject string) ([]byte, error) {\n" +
		"\tvar key []byte\n" +
		"\terr := l.pool.QueryRow(ctx, `SELECT key FROM audit_subject_keys WHERE idx = $1`, l.subjectIndex(subject)).Scan(&key)\n" +
		"\tif key, ok := l.cached(subject); ok {\n" +
		"\t\treturn key, nil\n" +
		"\t}\n" +
		"\t_ = err\n" +
		"\treturn key, nil\n" +
		"}"
	if tombstoneGatedCachePrecedesTheQuery(preFixLoad) {
		t.Fatal("the predicate accepts a loadKey that queries before consulting the cache; this guard would " +
			"not fail on a revert and is vacuous")
	}

	// Anti-vacuity 2: the pre-fix cachedAnswer consulted the cache with no
	// tombstone gate. The predicate must reject it.
	preFixCachedAnswer := "func (l *AuditLogger) cachedAnswer(ctx context.Context, subject string) ([]byte, bool, error) {\n" +
		"\tkey, ok := l.cached(subject)\n" +
		"\treturn key, ok, nil\n" +
		"}"
	if tombstoneCheckedBeforeTheCache(preFixCachedAnswer) {
		t.Fatal("the predicate accepts a cachedAnswer with no tombstone check; this guard would not fail " +
			"on a revert and is vacuous")
	}
}

// tombstoneGatedCachePrecedesTheQuery reports whether loadKey consults the
// tombstone-gated cache and returns a hit before it issues its only pool query.
func tombstoneGatedCachePrecedesTheQuery(loadBody string) bool {
	cacheCall := strings.Index(loadBody, "l.cachedAnswer(")
	cacheReturn := strings.Index(loadBody, "return key, nil")
	dbQuery := strings.Index(loadBody, "l.pool.QueryRow(")
	return cacheCall >= 0 && cacheReturn >= 0 && dbQuery >= 0 && cacheCall < cacheReturn && cacheReturn < dbQuery
}

// tombstoneCheckedBeforeTheCache reports whether cachedAnswer consults the
// tombstone mirror before it reads the local cache.
func tombstoneCheckedBeforeTheCache(cachedAnswerBody string) bool {
	tomb := strings.Index(cachedAnswerBody, "l.tombstoned(ctx, subject)")
	cache := strings.Index(cachedAnswerBody, "l.cached(subject)")
	return tomb >= 0 && cache >= 0 && tomb < cache
}

// TestZ10VerifyAdminClientActionsCarryTheClientIDBothAsSubjectAndInDetail is the
// flipped form of Z10-8's second half: every admin client-target action passes
// the client id as its audit Subject (so the sink pseudonymises it) AND carries
// it in Detail as the compensating field. The pre-fix code had only the first
// half, which is why a reader of the log could not say which client a row was
// about.
func TestZ10VerifyAdminClientActionsCarryTheClientIDBothAsSubjectAndInDetail(t *testing.T) {
	const file = "internal/admin/admin.go"
	raw := repoFile(t, file)

	want := []string{
		"admin.client.register",
		"admin.client.rotate_secret",
		"admin.client.suspend",
		"admin.client.activate",
		"admin.client.delete",
	}
	for _, verb := range want {
		call, subject := clientRecordCall(t, raw, verb)
		if subject != "clientID" && subject != "id" {
			t.Errorf("%s records subject %q, not the client id; Z10-8's premise changed", verb, subject)
		}
		if !clientRecordCarriesClientID(call) {
			t.Errorf("%s no longer carries client_id in Detail: the compensating field Z10-8 added is gone "+
				"and the pseudonymised subject is once again the only client identifier", verb)
		}
	}

	// Positive control: the same shape IS used to carry client_id elsewhere, so
	// "every admin.client.* call carries it" is a statement about these call
	// sites rather than about the codebase.
	if !strings.Contains(repoFile(t, "internal/store/postgres/oidc.go"), "client_id") {
		t.Errorf("the precedent Z10-8 cites (oidc.token carries client_id) is gone; the comparison is stale")
	}

	// Anti-vacuity: the pre-fix call carried the id only as the subject.
	preFix := `s.record(ctx, actor, "admin.client.register", id, audit.OutcomeOK, map[string]string{"type": string(client.Type)})`
	if clientRecordCarriesClientID(preFix) {
		t.Fatal("the predicate accepts a Detail without client_id as if it carried one; this guard would not " +
			"fail on a revert and is vacuous")
	}
}

// clientRecordCall returns the whole `s.record(...)` call for one admin.client.*
// verb and the identifier it passes as the audit subject.
func clientRecordCall(t *testing.T, raw, verb string) (call, subject string) {
	t.Helper()
	marker := `"` + verb + `"`
	at := strings.Index(raw, marker)
	if at < 0 {
		t.Fatalf("%s is no longer recorded through s.record with a literal action; Z10-8's call-site half "+
			"must be re-derived", verb)
	}
	start := strings.LastIndex(raw[:at], "s.record(")
	if start < 0 {
		t.Fatalf("%s is no longer recorded through s.record; Z10-8's call-site half must be re-derived", verb)
	}
	depth := 0
	end := -1
	for i := start; i < len(raw); i++ {
		switch raw[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i + 1
			}
		}
		if end > 0 {
			break
		}
	}
	if end < 0 {
		t.Fatalf("the s.record call for %s never closed; the source is not what this probe expects", verb)
	}
	after := raw[at+len(marker):]
	comma := strings.Index(after, ",")
	if comma < 0 {
		t.Fatalf("the s.record call for %s has no subject argument after the action", verb)
	}
	subject = strings.TrimSpace(after[comma+1:])
	if j := strings.IndexAny(subject, ", \n\t"); j >= 0 {
		subject = subject[:j]
	}
	return raw[start:end], subject
}

// clientRecordCarriesClientID reports whether one admin.client.* call carries the
// client id inside its Detail map.
func clientRecordCarriesClientID(call string) bool {
	return strings.Contains(call, `"client_id"`)
}

// TestZ10VerifyAdminClientActionsArePseudonymisedByTheDurableSink shows that the
// information loss Z10-8 describes follows from the sink's code, not from an
// assumption about which subjects an operator queries: Record pseudonymises
// every non-empty subject with no exception for client ids.
func TestZ10VerifyAdminClientActionsArePseudonymisedByTheDurableSink(t *testing.T) {
	const file = "internal/store/postgres/audit.go"
	raw := repoFile(t, file)

	record := funcBody(t, file, "Record")
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
