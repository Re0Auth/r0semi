package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
)

// This file is the probe set for the P3-low fixes that live in internal/httpapi.
// Each test names the finding it guards and states, in its own comment, what the
// code did before the fix — so a regression reads as "the finding is back" rather
// than as an unexplained failure.

// TestP3S03_5MissingAccountTearsDownTheSession guards S03-5 and Z07-7.
//
// Before the fix a session whose account row was gone answered 500
// internal_error on every session-scoped read, for as long as the stale cookie
// lived. The session is now destroyed and the caller told it is unauthenticated.
// The second half of the walk is what proves the teardown: with the account row
// restored, the old cookie must still be unauthenticated.
func TestP3S03_5MissingAccountTearsDownTheSession(t *testing.T) {
	for _, path := range []string{"/v1/sessions/current", "/v1/account/export", "/v1/identities"} {
		t.Run(path, func(t *testing.T) {
			env := newDeleteEnv(t)
			ctx := context.Background()

			browser := newBrowser(t)
			signIn(t, browser, env.base)
			uid, err := env.accounts.FindByIdentity(ctx, idp.GitHub, "42")
			if err != nil {
				t.Fatal(err)
			}

			resp := getURL(t, browser, env.base+path)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("control GET %s = %d, want 200", path, resp.StatusCode)
			}

			// The account row disappears while the browser keeps its session, which
			// is the window an erasure opens between dropping the row and the
			// session's own store noticing.
			if err := env.accounts.DeleteUser(ctx, uid); err != nil {
				t.Fatal(err)
			}

			resp = getURL(t, browser, env.base+path)
			body := decodeResp(t, resp)
			if resp.StatusCode != http.StatusUnauthorized || body["code"] != "unauthenticated" {
				t.Errorf("GET %s with a session for a missing account = %d (%v), want 401 unauthenticated",
					path, resp.StatusCode, body["code"])
			}

			// Put the account back. If the session had merely been refused while the
			// row was missing — rather than destroyed — this request would succeed.
			if _, _, err := env.accounts.CreateWithIdentity(ctx, idp.Identity{
				Provider: idp.GitHub, Subject: "42", DisplayName: "Octo",
			}); err != nil {
				t.Fatal(err)
			}
			resp = getURL(t, browser, env.base+path)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("GET %s after the account came back = %d, want 401: the stale session was not destroyed",
					path, resp.StatusCode)
			}
		})
	}
}

// TestP3Z07_6SignOutWithoutASessionIsUnauthenticated guards Z07-6.
//
// Before the fix sign_out checked CSRF first, so a caller with no session at all
// got 403 invalid_request — the plane's only write endpoint that did. The
// frontend reads the problem code, not the status, so `unauthenticated` is what
// sends it to sign-in.
func TestP3Z07_6SignOutWithoutASessionIsUnauthenticated(t *testing.T) {
	env := newDeleteEnv(t)

	req, err := http.NewRequest(http.MethodPost, env.base+"/v1/sessions/sign_out", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := doReq(t, newBrowser(t), req)
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusUnauthorized || body["code"] != "unauthenticated" {
		t.Errorf("sign_out with no session = %d (%v), want 401 unauthenticated", resp.StatusCode, body["code"])
	}

	// Control: a signed-in browser that omits the token is still a CSRF refusal, so
	// the check above is about the ordering and not a disabled CSRF guard.
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	req, err = http.NewRequest(http.MethodPost, env.base+"/v1/sessions/sign_out", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp = doReq(t, browser, req)
	body = decodeResp(t, resp)
	if resp.StatusCode != http.StatusForbidden || body["code"] != "invalid_request" {
		t.Errorf("sign_out without CSRF = %d (%v), want 403 invalid_request", resp.StatusCode, body["code"])
	}
}

// TestP3Z07_5DeviceDecisionNormalizesTheUserCode guards Z07-5.
//
// The verification page binds the normalised spelling, so the decision must look
// the handle up under it too. Before the fix the decision was looked up with the
// caller's exact bytes, and the device's printed (hyphenated) spelling answered
// 404 for a code the same browser had just been shown as pending.
func TestP3Z07_5DeviceDecisionNormalizesTheUserCode(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)

	resp := postForm(t, browser, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"},
		"scope":     {"account.id"},
	})
	start := decodeResp(t, resp)
	code, _ := start["user_code"].(string)
	if code == "" {
		t.Fatalf("device_authorization issued no user_code: %v", start)
	}

	signIn(t, browser, base)
	view := decodeResp(t, getURL(t, browser, base+"/v1/device/verification?user_code="+url.QueryEscape(code)))
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("verification view carried no csrf token: %v", view)
	}

	// The user retypes the code without the separator and in lower case.
	spelling := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	decision, _ := json.Marshal(map[string]any{
		"user_code": spelling,
		"decision":  "approve",
		"scopes":    []string{"account.id"},
	})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(decision))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp = doReq(t, browser, req)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Errorf("decision for %q (issued as %q) = %d: %s", spelling, code, resp.StatusCode, raw)
	}
	resp.Body.Close()
}

// TestP3Z08_7DeviceDecisionRefusesAnUnknownDecision guards Z08-7.
//
// Before the fix any decision other than "approve" was read as a denial, so a
// typo both answered "denied" and consumed the user code. The second half of the
// walk is the proof: the code must still be decidable after the refusal.
func TestP3Z08_7DeviceDecisionRefusesAnUnknownDecision(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)

	resp := postForm(t, browser, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"},
		"scope":     {"account.id"},
	})
	start := decodeResp(t, resp)
	code, _ := start["user_code"].(string)
	if code == "" {
		t.Fatalf("device_authorization issued no user_code: %v", start)
	}

	signIn(t, browser, base)
	view := decodeResp(t, getURL(t, browser, base+"/v1/device/verification?user_code="+url.QueryEscape(code)))
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("verification view carried no csrf token: %v", view)
	}

	post := func(decision string) (int, map[string]any) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"user_code": code, "decision": decision})
		req, err := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		resp := doReq(t, browser, req)
		return resp.StatusCode, decodeResp(t, resp)
	}

	if status, body := post("aprove"); status != http.StatusBadRequest || body["code"] != "invalid_request" {
		t.Errorf("unknown decision = %d (%v), want 400 invalid_request", status, body["code"])
	}
	if status, body := post("deny"); status != http.StatusOK || body["state"] != "denied" {
		t.Errorf("deny after a refused decision = %d (%v), want 200 denied: the refused request consumed the code",
			status, body["state"])
	}
}

// TestP3S03_6AdminAuthorityFollowsTheAccount guards S03-6.
//
// The operator allowlist is a static map over session subjects, so before the
// fix a session that outlived its account row still reached the operator plane.
func TestP3S03_6AdminAuthorityFollowsTheAccount(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	resp := getURL(t, browser, env.base+"/v1/admin/clients")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control GET /v1/admin/clients = %d, want 200", resp.StatusCode)
	}

	if err := env.accounts.DeleteUser(context.Background(), env.adminID); err != nil {
		t.Fatal(err)
	}

	resp = getURL(t, browser, env.base+"/v1/admin/clients")
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusUnauthorized || body["code"] != "unauthenticated" {
		t.Errorf("admin read with a session for a missing account = %d (%v), want 401 unauthenticated",
			resp.StatusCode, body["code"])
	}
}

// TestP3S13_9OversizedChunkedBodyIsAPlane413 guards S13-9.
//
// A chunked body declares no length, so the middleware's pre-check cannot see it
// and the cap is enforced while reading. Before the fix the handler's io.LimitReader
// stopped one read short of the reader's overflow error, and the truncated body
// was reported as 400 "malformed JSON body" — a different answer for the same
// oversized request depending on how the client framed it.
func TestP3S13_9OversizedChunkedBodyIsAPlane413(t *testing.T) {
	base, _ := newFlowEnv(t)

	browser := newBrowser(t)
	signIn(t, browser, base)
	csrf, _ := decodeResp(t, getURL(t, browser, base+"/v1/sessions/current"))["csrf_token"].(string)
	if csrf == "" {
		t.Fatal("no CSRF token in the session view")
	}

	// An authenticated request, so the handler actually reads the body: a chunked
	// body declares no length, the middleware's pre-check cannot see it, and the
	// cap is enforced while reading.
	big := strings.NewReader(strings.Repeat(" ", 70<<10) + `{"decision":"deny"}`)
	req, err := http.NewRequest(http.MethodPost, base+"/v1/device/decision", io.NopCloser(big))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.ContentLength = -1 // unknown length: the request goes out chunked
	resp := doReq(t, browser, req)
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || body["code"] != "invalid_request" {
		t.Errorf("chunked oversized body = %d (%v), want 413 invalid_request", resp.StatusCode, body["code"])
	}
	if body["detail"] != "request body too large" {
		t.Errorf("chunked oversized body detail = %v, want the middleware's", body["detail"])
	}

	// Control: a small malformed body is still a 400, so the 413 above is about the
	// size and not a blanket change of the error class.
	req, err = http.NewRequest(http.MethodPost, base+"/v1/device/decision", strings.NewReader(`{"decision":`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp = doReq(t, browser, req)
	body = decodeResp(t, resp)
	if resp.StatusCode != http.StatusBadRequest || body["detail"] != "malformed JSON body" {
		t.Errorf("small malformed body = %d (%v), want 400 malformed JSON body", resp.StatusCode, body["detail"])
	}
}

// TestP3Z10_6AuditWalksLeaveARecord guards Z10-6.
//
// The paged read already recorded admin.audit.read; the chain walk and the head
// read — the two widest statements about the whole log — left nothing. Both now
// write a record whose subject is the operator, never the queried account.
func TestP3Z10_6AuditWalksLeaveARecord(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	for _, path := range []string{"/v1/admin/audit/verify", "/v1/admin/audit/head"} {
		resp := getURL(t, browser, env.base+path)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}

	got := map[string]string{}
	for _, e := range env.auditLog.Events() {
		got[e.Action] = e.Outcome
	}
	for _, action := range []string{"admin.audit.verify", "admin.audit.head"} {
		outcome, ok := got[action]
		if !ok {
			t.Errorf("%s left no audit record", action)
			continue
		}
		if outcome != audit.OutcomeOK {
			t.Errorf("%s recorded outcome %q, want %q", action, outcome, audit.OutcomeOK)
		}
	}
}

// TestP3Z10_7AuditReadRequiresAWriteSide guards Z10-7.
//
// With the read API configured and no write side, every operator-plane record was
// a silent no-op: recordAudit returns early on a nil logger. The pair is now
// required together.
func TestP3Z10_7AuditReadRequiresAWriteSide(t *testing.T) {
	cfg := newFullConfig(t)
	if cfg.Audit == nil {
		t.Fatal("the fixture no longer wires the audit read API; this probe is vacuous")
	}
	cfg.AuditLog = nil
	if _, err := New(cfg); err == nil {
		t.Error("New accepted Config.Audit with no Config.AuditLog: the operator-plane records would be silent no-ops")
	}

	// Control: the complete pair is still accepted, so the refusal is about the
	// missing sink and not about the audit read API itself.
	cfg.AuditLog = audit.NewMemoryLogger()
	if _, err := New(cfg); err != nil {
		t.Errorf("New rejected a complete audit wiring: %v", err)
	}
}

// TestP3S11_8ExportNoticeNamesEveryOmission guards S11-8.
//
// The document is the account's profile, connections and grants — not everything
// the service holds. The notice used to disclaim credentials alone, which made
// the absent sessions, issued tokens and audit history read as an oversight
// rather than a decision.
func TestP3S11_8ExportNoticeNamesEveryOmission(t *testing.T) {
	env := newDeleteEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	view := decodeResp(t, getURL(t, browser, env.base+"/v1/account/export"))
	notice, _ := view["notice"].(map[string]any)
	reason, _ := notice["reason"].(string)
	if reason == "" {
		t.Fatalf("the export carries no notice reason: %v", notice)
	}
	low := strings.ToLower(reason)
	for _, want := range []string{"session", "issued", "audit history"} {
		if !strings.Contains(low, want) {
			t.Errorf("the export notice does not name %q among the deliberate omissions: %q", want, reason)
		}
	}
}

// TestP3G11ReadyzFailsClosedWhileTheFirstCheckIsRunning guards G-11 and 22-1
// (the same defect, filed twice).
//
// Before the fix a caller that arrived while the first-ever readiness check was
// still running was answered from the cache's zero value — err == nil, which
// /readyz rendered as 200 ok, claiming a dependency nobody had reached yet.
func TestP3G11ReadyzFailsClosedWhileTheFirstCheckIsRunning(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := healthServer(t, func(context.Context) error {
		close(entered)
		<-release
		return nil
	}, nil)
	h := srv.Handler()

	first := make(chan int, 1)
	go func() { first <- probe(t, h, "/readyz", "").Code }()
	<-entered

	// No verdict has ever been produced and the only check is still running, so
	// there is nothing honest to answer from.
	rec := probe(t, h, "/readyz", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d while the first check is still running and no verdict exists, want 503",
			rec.Code)
	}
	if got := rec.Body.String(); got != "checking\n" {
		t.Errorf("/readyz body = %q, want %q", got, "checking\n")
	}

	close(release)
	if code := <-first; code != http.StatusOK {
		t.Errorf("the check that ran answered %d for a healthy dependency, want 200", code)
	}
}
