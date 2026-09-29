//go:build audit7

// Zone-10 probes: which reads of the audit log leave a record behind.
package z10adminauditprivacy

import (
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// TestZ10AuditVerifyIsNotRecordedWhileThePagedReadIs.
//
// The round-5 fix for "reading the audit log leaves no trace" (P2-22) added
// `admin.audit.read` to GET /v1/admin/audit, and its own comment states the
// reasoning: "Opening this window is itself auditable: it is the widest read of
// personal data the service offers, and before this nothing recorded that it
// happened." Verify — mounted right next to it, same allowlist — walks every
// chained row in the log to decide whether it was tampered with, so it reads more
// than one page does and still leaves nothing at all.
func TestZ10AuditVerifyIsNotRecordedWhileThePagedReadIs(t *testing.T) {
	reader := &probeAuditReader{
		page: audit.Page{
			Entries: []audit.Entry{{
				ID: 1, Action: "admin.kill_switch", Subject: "pseudonym",
				Provider: "admin", Outcome: "ok", Detail: map[string]string{},
			}},
			Limit: 100,
		},
		verification: audit.Verification{OK: true, Chained: 1},
		head:         []byte{0xaa, 0xbb},
	}
	env := newProbeEnv(t, probeOptions{AuditReader: reader})

	b := env.newBrowser()
	if got := b.signIn(adminUpstream); got != string(env.adminUser) {
		t.Fatalf("signed in as %q, want the allowlisted operator %q", got, env.adminUser)
	}

	// Control: the paged read is recorded, and the request really reached the
	// reader.
	before := len(env.auditEvents())
	resp := b.get("/v1/admin/audit")
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/admin/audit = %d (%s), want 200", resp.StatusCode, body)
	}
	if len(reader.queries) != 1 {
		t.Fatalf("the reader was queried %d times, want 1", len(reader.queries))
	}
	afterRead := len(env.auditEvents())
	if afterRead <= before {
		t.Fatalf("control does not hold: GET /v1/admin/audit added no audit event (%d -> %d)", before, afterRead)
	}

	// The case under test.
	resp = b.get("/v1/admin/audit/verify")
	body = bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/admin/audit/verify = %d (%s), want 200", resp.StatusCode, body)
	}
	if reader.verified != 1 {
		t.Fatalf("Verify was called %d times, want 1: the probe did not reach the chain walk", reader.verified)
	}
	afterVerify := len(env.auditEvents())
	if afterVerify == afterRead {
		t.Errorf("GET /v1/admin/audit/verify walked every chained row (%d covered) and left no audit record "+
			"(events %d -> %d), while the much narrower paged read of the same log is recorded as "+
			"admin.audit.read. The fix for \"reading the log leaves no trace\" covers one of the two reads.",
			reader.verification.Chained, afterRead, afterVerify)
	}

	// The head is the third read on the same allowlist and behaves the same way.
	resp = b.get("/v1/admin/audit/head")
	body = bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/admin/audit/head = %d (%s), want 200", resp.StatusCode, body)
	}
	if reader.headed != 1 {
		t.Fatalf("Head was called %d times, want 1", reader.headed)
	}
	if got := len(env.auditEvents()); got == afterVerify {
		t.Errorf("GET /v1/admin/audit/head also left no audit record (events still %d)", got)
	}
	if got := len(env.actionsIn("admin.audit.read")); got == 0 {
		t.Fatalf("no admin.audit.read event exists at all; the probe's premise is broken")
	}
}

// TestZ10AuditReadRecordCarriesNoQueriedSubject.
//
// The guard half of the same fix: the record must not name the account that was
// queried, because a raw usr_ in a Detail value survives pseudonymisation and the
// erasure-aware reader is exactly what must not re-link a destroyed account. The
// filters are recorded as shapes, not values.
func TestZ10AuditReadRecordCarriesNoQueriedSubject(t *testing.T) {
	reader := &probeAuditReader{
		page: audit.Page{Entries: []audit.Entry{}, Limit: 10},
	}
	env := newProbeEnv(t, probeOptions{AuditReader: reader})

	b := env.newBrowser()
	if got := b.signIn(adminUpstream); got != string(env.adminUser) {
		t.Fatalf("signed in as %q, want %q", got, env.adminUser)
	}
	const victim = "usr_victim0000000000000000"
	resp := b.get("/v1/admin/audit?subject=" + victim + "&action=oidc.token&limit=10")
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/admin/audit?subject=… = %d (%s), want 200", resp.StatusCode, body)
	}
	if len(reader.queries) != 1 || reader.queries[0].Subject != victim {
		t.Fatalf("the subject filter did not reach the reader: %+v", reader.queries)
	}

	events := env.actionsIn("admin.audit.read")
	if len(events) != 1 {
		t.Fatalf("admin.audit.read events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Subject != string(env.adminUser) {
		t.Errorf("the read record's subject = %q, want the operator %q", ev.Subject, env.adminUser)
	}
	for k, v := range ev.Detail {
		if v == victim || v == "oidc.token" {
			t.Errorf("the read record carries the queried value verbatim: detail[%q] = %q; the filters are "+
				"supposed to be recorded as shapes", k, v)
		}
	}
}
