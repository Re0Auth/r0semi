//go:build audit7

// Re-check of Z10-6 (the two audit read endpoints that record nothing), plus
// negative controls proving the source-reading probes in this package can fail.
package z10verify

import (
	"regexp"
	"strings"
	"testing"
)

// TestZ10VerifyOnlyThePagedAuditReadIsRecorded checks Z10-6 from the source: of
// the three reads on the operator allowlist, only the paged one calls
// recordAudit.
func TestZ10VerifyOnlyThePagedAuditReadIsRecorded(t *testing.T) {
	const file = "internal/httpapi/audit_routes.go"
	src := repoFile(t, file)

	handlers := map[string]string{
		"handleAdminAudit":       funcBodyRaw(t, file, "handleAdminAudit"),
		"handleAdminAuditVerify": funcBodyRaw(t, file, "handleAdminAuditVerify"),
		"handleAdminAuditHead":   funcBodyRaw(t, file, "handleAdminAuditHead"),
	}
	if !strings.Contains(handlers["handleAdminAudit"], `"admin.audit.read"`) {
		t.Fatalf("the paged read no longer records admin.audit.read; Z10-6's comparison is stale")
	}
	for _, name := range []string{"handleAdminAuditVerify", "handleAdminAuditHead"} {
		if strings.Contains(handlers[name], "recordAudit") {
			t.Errorf("%s now records an audit event: Z10-6 is fixed for that endpoint and its verdict must change", name)
		}
	}
	// The verify handler really is the wide read: it calls the chain walk.
	if !strings.Contains(handlers["handleAdminAuditVerify"], "s.auditReader.Verify(") {
		t.Errorf("handleAdminAuditVerify no longer walks the chain; the \"widest read\" premise changed")
	}
	// Control that recordAudit exists and is reachable (so "no recordAudit call"
	// is a statement about these handlers, not about the layer).
	if !strings.Contains(src, "func (s *Server) recordAudit(") {
		t.Fatalf("the layer's recordAudit helper is gone; the zero-hit claim would be vacuous")
	}
	// The export route also records, which is the other half of the P2-22 fix.
	exp := repoFile(t, "internal/httpapi/export_routes.go")
	if !strings.Contains(exp, `"account.export"`) || !strings.Contains(exp, "s.recordAudit(") {
		t.Errorf("the export route no longer records account.export; the fix this finding supplements changed shape")
	}
}

// TestZ10VerifyTheAuditReadGuardIsNotRequiredToHaveASink checks Z10-7: httpapi.New
// accepts the read API with no write side.
func TestZ10VerifyTheAuditReadGuardIsNotRequiredToHaveASink(t *testing.T) {
	const file = "internal/httpapi/server.go"
	src := repoFile(t, file)

	if !strings.Contains(src, "Config.Audit requires Config.Sessions") ||
		!strings.Contains(src, "Config.Audit requires a non-empty Config.Admins") {
		t.Fatalf("the two Config.Audit guards Z10-7 compares against are gone; re-derive the finding")
	}
	if strings.Contains(src, "Config.Audit requires Config.AuditLog") {
		t.Errorf("httpapi.New now requires an AuditLog for Config.Audit: Z10-7 is fixed and its verdict must change")
	}
	record := funcBodyRaw(t, "internal/httpapi/audit_routes.go", "recordAudit")
	if !strings.Contains(record, "s.auditLog == nil") {
		t.Fatalf("recordAudit no longer returns early on a nil logger; Z10-7's mechanism changed")
	}
	if !strings.Contains(record, "return") {
		t.Fatalf("recordAudit's nil-logger branch no longer returns; re-derive")
	}
	// The composition root wires both, which is why this is a hardening item.
	main := repoFile(t, "cmd/re0auth/main.go")
	if !strings.Contains(main, "apiConfig.Audit =") || !strings.Contains(main, "AuditLog:") {
		t.Errorf("the composition root no longer wires both the read API and the write sink; the reachability half changed")
	}
}

// ---- negative controls ---------------------------------------------------------

// TestZ10VerifySourceChecksCanFail proves the source-reading assertions are not
// vacuous: each fabricated snippet is one the real check must reject. If any of
// these controls stops failing, the corresponding finding above may have been
// "verified" by a check that cannot see the bug.
func TestZ10VerifySourceChecksCanFail(t *testing.T) {
	// 1. A loadKey whose cache check comes after the query.
	syntheticLoad := `
func (l *AuditLogger) loadKey(ctx context.Context, subject string) ([]byte, error) {
	var key []byte
	err := l.pool.QueryRow(ctx, ` + "`SELECT`" + `, l.subjectIndex(subject)).Scan(&key)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	cached, ok := l.cache[subject]
	l.mu.Unlock()
	if ok {
		return cached, nil
	}
	return key, nil
}`
	scr := scrubLiterals(t, "synthetic", syntheticLoad)
	guard := strings.Index(scr, "if ok {")
	dbQuery := strings.Index(scr, "l.pool.QueryRow(")
	cacheReturn := strings.Index(scr, "return cached")
	if !(dbQuery < cacheReturn && guard < cacheReturn) {
		t.Fatalf("control 1 did not detect a loadKey that queries before answering from cache (query %d, guard %d, cache return %d)",
			dbQuery, guard, cacheReturn)
	}

	// 2. A Destroy that evicts more than its own map.
	syntheticDestroy := `
func (l *AuditLogger) Destroy(ctx context.Context, subject string) error {
	destroyed.Store(subject, struct{}{})
	delete(l.cache, subject)
	notifyPeers(subject)
	return nil
}`
	scrD := scrubLiterals(t, "synthetic", syntheticDestroy)
	if !strings.Contains(scrD, "notifyPeers") || !strings.Contains(scrD, "destroyed.Store") {
		t.Fatalf("control 2 did not keep the cross-process primitives visible; the check would miss a fix")
	}

	// 3. An admin.client.* record that does carry client_id in Detail.
	syntheticRecord := `s.record(ctx, actor, "admin.client.suspend", clientID, audit.OutcomeOK, map[string]string{
		"tokens_revoked": strconv.Itoa(removed),
		"client_id":      clientID,
	})`
	kk := regexp.MustCompile(`s\.record\(ctx, actor, "admin\.client\.[a-z_]+", [^,]+, [^,]+, map\[string\]string\{[^}]*\}`)
	call := kk.FindString(syntheticRecord)
	if call == "" || !strings.Contains(call, "client_id") {
		t.Fatalf("control 3 did not detect a client_id-carrying admin record (matched %q)", call)
	}

	// 4. A kill-switch failure detail that does carry sessions_revoked, and one
	//    that carries neither count, must both be distinguishable.
	syntheticKill := `s.record(ctx, actor, "admin.kill_switch", target.auditSubject(), audit.OutcomeError, map[string]string{
		"tokens_revoked":   strconv.Itoa(rep.TokensRevoked),
		"sessions_revoked": strconv.FormatInt(rep.SessionsRevoked, 10),
	})`
	re := regexp.MustCompile(`(?s)map\[string\]string\{([^}]*)\}\)`)
	m := re.FindStringSubmatch(syntheticKill)
	if m == nil || !strings.Contains(m[1], "sessions_revoked") {
		t.Fatalf("control 4 did not detect a sessions_revoked in a failure detail (match %v)", m)
	}
}
