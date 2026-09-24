package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func postForm(t *testing.T, c *http.Client, target string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doReq(t, c, req)
}

// TestDeviceAuthorizationEndToEnd walks RFC 8628 end to end over HTTP: a public
// client starts an authorization, the user signs in on the verification page and
// approves, and the token endpoint then issues tokens.
func TestDeviceAuthorizationEndToEnd(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)

	// 1. The device asks for a device_code.
	resp := postForm(t, browser, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"},
		"scope":     {"account.id phigros.score.read"},
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("device_authorization = %d: %s", resp.StatusCode, body)
	}
	start := decodeResp(t, resp)
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_authorization = %v", start)
	}
	if start["verification_uri"] != "https://re0auth.test/app/device" {
		t.Fatalf("verification_uri = %v", start["verification_uri"])
	}
	complete, _ := start["verification_uri_complete"].(string)
	if !strings.Contains(complete, "user_code=") {
		t.Fatalf("verification_uri_complete = %v", complete)
	}

	// 2. Polling before approval is a protocol error, not a token.
	pending := postForm(t, browser, base+"/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"cli"},
	})
	if pending.StatusCode != http.StatusBadRequest {
		t.Fatalf("pending poll = %d", pending.StatusCode)
	}
	if body := decodeResp(t, pending); body["error"] != "authorization_pending" {
		t.Fatalf("pending poll = %v", body)
	}

	// 3. The user signs in and loads the verification page.
	signIn(t, browser, base)
	resp = getURL(t, browser, base+"/v1/device/verification?user_code="+url.QueryEscape(userCode))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("verification page = %d: %s", resp.StatusCode, body)
	}
	view := decodeResp(t, resp)
	csrf, _ := view["csrf_token"].(string)
	client, _ := view["client"].(map[string]any)
	if view["state"] != "pending" || csrf == "" || client["name"] != "Phi CLI" {
		t.Fatalf("verification view = %v", view)
	}

	// 4. Approve.
	decision, _ := json.Marshal(map[string]any{
		"user_code": userCode,
		"decision":  "approve",
		"scopes":    []string{"account.id", "phigros.score.read"},
	})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(decision))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp = doReq(t, browser, req)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("decision = %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// 5. The token endpoint now issues tokens.
	resp = postForm(t, browser, base+"/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"cli"},
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token = %d: %s", resp.StatusCode, body)
	}
	tokens := decodeResp(t, resp)
	if tokens["access_token"] == "" || tokens["token_type"] != "Bearer" {
		t.Fatalf("tokens = %v", tokens)
	}
}

// The verification GET binds the code to the session and carries no CSRF token.
// That is recorded here as a decision rather than left as an accident, because the
// obvious fixes are worse than the gap:
//
//   - it cannot elevate privilege. Approving needs a CSRF token and a signed-in
//     session of its own, so an attacker who induces this GET still cannot decide
//     anything;
//   - requiring CSRF here would be circular: this response is where the frontend
//     obtains the CSRF token it uses for the decision;
//   - what it does allow is planting handle_device_<code> keys in a signed-in
//     session, one per cross-site top-level navigation, and the page the victim
//     lands on shows the client and the scopes about to be approved.
//
// Moving the binding to the decision POST would drop the guarantee that the code
// the user approved is one this browser displayed. That is a design call, not a
// hardening step, so the behaviour is pinned rather than changed.
func TestDeviceVerificationBindsWithoutCSRF(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)

	start := decodeResp(t, postForm(t, browser, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"}, "scope": {"account.id"},
	}))
	code, _ := start["user_code"].(string)
	if code == "" {
		t.Fatal("no user_code was issued")
	}

	signIn(t, browser, base)

	// A GET a cross-site navigation could make: no CSRF header at all.
	resp := getURL(t, browser, base+"/v1/device/verification?user_code="+url.QueryEscape(code))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verification = %d, want 200", resp.StatusCode)
	}
	csrf, _ := decodeResp(t, resp)["csrf_token"].(string)

	// It bound, so the decision succeeds — the pinned behaviour. The decision
	// still had to present the CSRF token from this same session.
	body, _ := json.Marshal(map[string]any{
		"user_code": code,
		"decision":  "approve",
		"scopes":    []string{"account.id"},
	})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	decided, err := browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer decided.Body.Close()
	if decided.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(decided.Body)
		t.Fatalf("decision = %d: %s", decided.StatusCode, raw)
	}
}

// The verification page is a browser surface: it must require a session, and a
// code loaded in one browser must not be approvable from another.
func TestDeviceDecisionIsBoundToBrowser(t *testing.T) {
	base, _ := newFlowEnv(t)
	mine := newBrowser(t)
	other := newBrowser(t)

	// "mine" starts and loads a code, binding it to its session.
	startA := decodeResp(t, postForm(t, mine, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"}, "scope": {"account.id"},
	}))
	codeA, _ := startA["user_code"].(string)
	signIn(t, mine, base)
	if resp := getURL(t, mine, base+"/v1/device/verification?user_code="+url.QueryEscape(codeA)); resp.StatusCode != http.StatusOK {
		t.Fatalf("mine verification page = %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Anonymous access to the verification page is refused.
	if resp := getURL(t, newBrowser(t), base+"/v1/device/verification?user_code="+url.QueryEscape(codeA)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous verification page = %d, want 401", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// "other" signs in and loads its OWN code so it holds a valid CSRF token;
	// deciding for "mine"'s code must still fail, because the code is bound to
	// the session that loaded it.
	startB := decodeResp(t, postForm(t, other, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"}, "scope": {"account.id"},
	}))
	codeB, _ := startB["user_code"].(string)
	signIn(t, other, base)
	resp := getURL(t, other, base+"/v1/device/verification?user_code="+url.QueryEscape(codeB))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("other verification page = %d", resp.StatusCode)
	}
	csrf, _ := decodeResp(t, resp)["csrf_token"].(string)

	body, _ := json.Marshal(map[string]any{"user_code": codeA, "decision": "approve"})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp = doReq(t, other, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-browser decision = %d, want 404", resp.StatusCode)
	}
}

func TestDeviceAuthorizationRejectsUnknownClient(t *testing.T) {
	base, _ := newFlowEnv(t)
	resp := postForm(t, newBrowser(t), base+"/oauth/device_authorization", url.Values{
		"client_id": {"ghost"}, "scope": {"account.id"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown client = %d, want 401", resp.StatusCode)
	}
}
