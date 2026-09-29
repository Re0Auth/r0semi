//go:build audit7

// Zone-10 probes: what the Kill Switch's report says when one half of it is not
// wired, and what the endpoint returns when a sweep fails part way.
package z10adminauditprivacy

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// TestZ10KillSwitchAllIsSilentAboutAMissingSessionRevoker.
//
// The operator plane's own rule — stated in admin.Report's doc comment and
// implemented for bindings by `bindings_unavailable` — is that "no X existed" and
// "this deployment cannot sweep X" must never look identical. `all` and `subject`
// have a session dimension as well, and a deployment with no SessionRevoker
// leaves it out with no marker at all: the responder reads
// `sessions_revoked: 0`, which is exactly the hollow zero the rule forbids.
//
// The control half of this probe is in the same request: the same missing-port
// case for bindings DOES carry its marker, so the report format can express the
// distinction and the probe is not asserting against a report that says nothing.
func TestZ10KillSwitchAllIsSilentAboutAMissingSessionRevoker(t *testing.T) {
	// Control first: with a session revoker wired, the number is the port's.
	wired := newProbeEnv(t, probeOptions{Sessions: &probeSessions{n: 3}})
	b := wired.newBrowser()
	if got := b.signIn(adminUpstream); got != string(wired.adminUser) {
		t.Fatalf("signed in as %q, want the allowlisted operator %q", got, wired.adminUser)
	}
	resp := b.do(http.MethodPost, "/v1/admin/kill_switch", `{"target":"all"}`, jsonHeaders(b.csrf()))
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kill_switch all = %d (%s), want 200", resp.StatusCode, body)
	}
	if got := mustJSON(t, body)["sessions_revoked"]; got != float64(3) {
		t.Fatalf("control: sessions_revoked = %v, want 3 (the wired port); report: %s", got, body)
	}

	// The case under test: the deployment has no session revoker.
	env := newProbeEnv(t, probeOptions{})
	b = env.newBrowser()
	if got := b.signIn(adminUpstream); got != string(env.adminUser) {
		t.Fatalf("signed in as %q, want the allowlisted operator %q", got, env.adminUser)
	}
	resp = b.do(http.MethodPost, "/v1/admin/kill_switch", `{"target":"all"}`, jsonHeaders(b.csrf()))
	body = bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kill_switch all = %d (%s), want 200", resp.StatusCode, body)
	}
	report := mustJSON(t, body)

	// Anti-vacuity: this very report already carries the equivalent marker for the
	// other port it is missing, so the shape it needs is one it already uses.
	if report["bindings_unavailable"] != true {
		t.Fatalf("control: bindings_unavailable = %v, want true: this deployment has no Bindings port either, "+
			"so the report must be able to say so (report: %s)", report["bindings_unavailable"], body)
	}
	if got := report["sessions_revoked"]; got != float64(0) {
		t.Fatalf("sessions_revoked = %v, want 0 (no revoker is wired)", got)
	}
	if report["sessions_unavailable"] != true {
		t.Errorf("KillSwitch(all) on a deployment with no session revoker reports sessions_revoked=0 and nothing "+
			"else: an incident responder cannot tell \"no sessions existed\" from \"this deployment cannot cut "+
			"sessions\", while the same request DOES carry bindings_unavailable=true for its other missing port "+
			"(report: %s). lifecycle.Result.SessionScoped exists for exactly this reason on the erasure path.",
			body)
	}
}

// TestZ10KillSwitchDropsThePartialSummaryWhenASweepFails.
//
// docs/admin.md §4.2 ("扫描形态") and the binding sweep's own doc comment promise
// that a failed enumeration "returns the finished summary together with the
// error". The service does keep that promise: admin.KillSwitch returns
// (rep, err) with the counts it already cut. The HTTP layer does not — on any
// error it writes a problem+json body with no counts at all, so the responder
// loses the one number a Kill Switch exists to produce.
func TestZ10KillSwitchDropsThePartialSummaryWhenASweepFails(t *testing.T) {
	tokens := &probeTokens{removed: 7}
	sessions := &probeSessions{n: 2}
	bindings := &probeBindings{err: errors.New("source unreachable")}
	env := newProbeEnv(t, probeOptions{Tokens: tokens, Sessions: sessions, Bindings: bindings})

	b := env.newBrowser()
	if got := b.signIn(adminUpstream); got != string(env.adminUser) {
		t.Fatalf("signed in as %q, want the allowlisted operator %q", got, env.adminUser)
	}
	resp := b.do(http.MethodPost, "/v1/admin/kill_switch",
		`{"target":"subject","subject":"usr_target"}`, jsonHeaders(b.csrf()))
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("kill_switch subject = %d (%s), want 500: the binding sweep failed", resp.StatusCode, body)
	}

	// The sweep really ran and really failed, and the service really had the
	// counts: they are in the audit row the service wrote for the failed attempt.
	if tokens.calls == 0 || sessions.calls == 0 || bindings.calls == 0 {
		t.Fatalf("not every port was called (tokens=%d sessions=%d bindings=%d)", tokens.calls, sessions.calls, bindings.calls)
	}
	events := env.actionsIn("admin.kill_switch")
	if len(events) != 1 {
		t.Fatalf("admin.kill_switch events = %d, want 1: %+v", len(events), events)
	}
	if events[0].Outcome != audit.OutcomeError {
		t.Fatalf("the failed sweep was recorded as outcome=%q, want %q", events[0].Outcome, audit.OutcomeError)
	}
	if got := events[0].Detail["tokens_revoked"]; got != "7" {
		t.Fatalf("the audit row does not carry the tokens already revoked (detail %+v); the probe needs that "+
			"number to prove the service had it", events[0].Detail)
	}

	if !strings.Contains(body, "tokens_revoked") {
		t.Errorf("the failed Kill Switch answered %q: the counts it already cut (tokens_revoked=7, "+
			"sessions_revoked=2, recorded in the audit row) are absent from the response, although "+
			"docs/admin.md §4.2 promises \"枚举失败时返回已完成的摘要与错误\". An incident responder cannot tell "+
			"what was already cut.", strings.TrimSpace(body))
	}
}
