//go:build audit7

// Re-check of Z10-6 (the two audit read endpoints that record nothing), plus
// negative controls proving the source-reading probes in this package can fail.
package z10verify

import (
	"strings"
	"testing"
)

// TestZ10VerifyOnlyThePagedAuditReadIsRecorded started as the Z10-6 finding: of
// the three reads on the operator allowlist, only the paged one called
// recordAudit, so the chain walk and the head read — both statements about the
// integrity of the whole log — left no record. The fix records all three; this is
// now the regression guard for it (name kept for the audit coverage matrix).
func TestZ10VerifyOnlyThePagedAuditReadIsRecorded(t *testing.T) {
	const file = "internal/httpapi/audit_routes.go"
	src := repoFile(t, file)

	handlers := map[string]string{
		"handleAdminAudit":       funcBodyRaw(t, file, "handleAdminAudit"),
		"handleAdminAuditVerify": funcBodyRaw(t, file, "handleAdminAuditVerify"),
		"handleAdminAuditHead":   funcBodyRaw(t, file, "handleAdminAuditHead"),
	}
	// Z10-6 guard: every operator read of the log leaves a record naming its own
	// action. The control below (recordAudit exists and is reachable) keeps "the
	// handler does not call it" a statement about the handler.
	for name, action := range map[string]string{
		"handleAdminAudit":       `"admin.audit.read"`,
		"handleAdminAuditVerify": `"admin.audit.verify"`,
		"handleAdminAuditHead":   `"admin.audit.head"`,
	} {
		if !strings.Contains(handlers[name], "recordAudit") || !strings.Contains(handlers[name], action) {
			t.Errorf("%s no longer records %s: Z10-6 regressed, so this read of the whole log leaves no trace",
				name, action)
		}
	}
	// The verify handler really is the wide read: it calls the chain walk.
	if !strings.Contains(handlers["handleAdminAuditVerify"], "s.auditReader.Verify(") {
		t.Errorf("handleAdminAuditVerify no longer walks the chain; the \"widest read\" premise changed")
	}
	// Control that recordAudit exists and is reachable (so the check above is a
	// statement about these handlers, not about the layer).
	if !strings.Contains(src, "func (s *Server) recordAudit(") {
		t.Fatalf("the layer's recordAudit helper is gone; the check would be vacuous")
	}
	// The export route also records, which is the other half of the P2-22 fix.
	exp := repoFile(t, "internal/httpapi/export_routes.go")
	if !strings.Contains(exp, `"account.export"`) || !strings.Contains(exp, "s.recordAudit(") {
		t.Errorf("the export route no longer records account.export; the fix this finding supplements changed shape")
	}
}

// TestZ10VerifyTheAuditReadGuardIsNotRequiredToHaveASink started as the Z10-7
// finding: httpapi.New accepted the read API with no write side, so the P2-22
// records became silent no-ops. The constructor now requires Config.AuditLog; this
// is the source-level regression guard (name kept for the audit coverage matrix).
func TestZ10VerifyTheAuditReadGuardIsNotRequiredToHaveASink(t *testing.T) {
	const file = "internal/httpapi/server.go"
	src := repoFile(t, file)

	if !strings.Contains(src, "Config.Audit requires Config.Sessions") ||
		!strings.Contains(src, "Config.Audit requires a non-empty Config.Admins") {
		t.Fatalf("the two Config.Audit guards Z10-7 compares against are gone; re-derive the finding")
	}
	// Z10-7 guard: a read API with no write sink is refused at construction.
	if !strings.Contains(src, "Config.Audit requires Config.AuditLog") {
		t.Errorf("httpapi.New no longer requires an AuditLog for Config.Audit: Z10-7 regressed and the " +
			"read API's own records can silently become no-ops in a configuration that looks wired")
	}
	// The write path still declines a nil logger; the constructor guard is what
	// makes that branch unreachable through Config.Audit. The nil check lives in
	// recordAuditOutcome, which recordAudit delegates to.
	record := funcBodyRaw(t, "internal/httpapi/audit_routes.go", "recordAuditOutcome")
	if !strings.Contains(record, "s.auditLog == nil") {
		t.Fatalf("recordAuditOutcome no longer returns early on a nil logger; Z10-7's mechanism changed")
	}
	if !strings.Contains(record, "return") {
		t.Fatalf("recordAuditOutcome's nil-logger branch no longer returns; re-derive")
	}
	// The composition root wires both, which is why this is a hardening item.
	main := repoFile(t, "cmd/re0auth/main.go")
	if !strings.Contains(main, "apiConfig.Audit =") || !strings.Contains(main, "AuditLog:") {
		t.Errorf("the composition root no longer wires both the read API and the write sink; the reachability half changed")
	}
}

// ---- negative controls ---------------------------------------------------------

// TestZ10VerifySourceChecksCanFail proves the source-reading assertions are not
// vacuous: each fabricated snippet is the pre-fix shape the rewritten guards in
// killswitch_source_test.go / pseudo_source_test.go must reject. If any of these
// controls stops failing, the corresponding guard may have been "verified" by a
// check that cannot see a revert.
func TestZ10VerifySourceChecksCanFail(t *testing.T) {
	// 1. A loadKey whose cache check comes after the query.
	syntheticLoad := `
func (l *AuditLogger) loadKey(ctx context.Context, subject string) ([]byte, error) {
	var key []byte
	err := l.pool.QueryRow(ctx, ` + "`SELECT`" + `, l.subjectIndex(subject)).Scan(&key)
	if err != nil {
		return nil, err
	}
	cached, ok := l.cached(subject)
	if ok {
		return cached, nil
	}
	return key, nil
}`
	if cacheHitPrecedesTheQuery(syntheticLoad) {
		t.Fatalf("control 1 did not detect a loadKey that queries before answering from cache")
	}

	// 2. A Destroy that evicts more than its own map must keep the cross-process
	// primitives visible to the structural scan.
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

	// 3. The pre-fix admin.client.* record: the id is the (pseudonymised) subject
	// and there is no compensating client_id in Detail.
	syntheticRecord := `s.record(ctx, actor, "admin.client.register", id, audit.OutcomeOK, map[string]string{"type": "confidential"})`
	if _, subject := clientRecordCall(t, syntheticRecord, "admin.client.register"); subject != "id" {
		t.Fatalf("control 3 did not read the pre-fix subject (got %q)", subject)
	}
	if clientRecordCarriesClientID(syntheticRecord) {
		t.Fatalf("control 3 did not detect a client_id-less admin record; the Z10-8 guard would be vacuous")
	}

	// 4. The pre-fix kill-switch failure detail: inline, tokens only.
	syntheticKill := `s.record(ctx, actor, "admin.kill_switch", target.auditSubject(), audit.OutcomeError, ` +
		`map[string]string{"tokens_revoked": strconv.Itoa(rep.TokensRevoked)})`
	if killSwitchRecordsThroughKillDetail(syntheticKill) {
		t.Fatalf("control 4 did not detect an inline partial kill-switch Detail; the Z10V-1 guard would be vacuous")
	}

	// 5. The pre-fix Report, with no sessions-unavailable marker.
	syntheticReport := `type Report struct {
	BindingsUnavailable bool ` + "`json:\"bindings_unavailable,omitempty\"`" + `
}`
	if sessionUnavailableMarkerPresent(syntheticReport) {
		t.Fatalf("control 5 did not detect a Report without the sessions marker; the Z10-4 guard would be vacuous")
	}

	// 6. The pre-fix shutdown loop: every endpoint drained from the shared budget.
	syntheticServe := `
	for _, ep := range endpoints {
		if e := ep.server.Shutdown(drainCtx); e != nil {
			_ = ep.server.Close()
		}
	}`
	if operationalListenerBypassesTheSharedDrain(syntheticServe) {
		t.Fatalf("control 6 did not detect the shared drain; the Z10V-2 guard would be vacuous")
	}
}
