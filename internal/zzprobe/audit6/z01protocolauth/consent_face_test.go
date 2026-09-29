//go:build audit6

// Zone-01 findings on the consent face: what an interactive authorization can
// and cannot complete, and what prompt=none / prompt=login actually do to a
// signed-in session.
package z01protocolauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 01-1 · A request whose scope set is entirely OIDC protocol scopes — the
// default request of every standard relying party ("openid profile email") —
// cannot be approved: the consent screen renders no scope at all, and the only
// decision body that screen can build is refused by the server. The authorize
// entrance accepts the request (StandardOIDCScope bypasses the catalogue
// check), the pending request is allocated, and then the flow dead-ends.
//
// What the attacker gets is nothing; what the deployment gets is an OP that
// cannot serve the pure-OIDC relying parties that ADR-0001's positioning
// ("对下游：标准 OIDC，一次接入拿到 id_token/userinfo") says it exists to serve.
func TestProbeProtocolOnlyScopesCannotBeApproved(t *testing.T) {
	e := newStack(t)
	browser := newBrowser(t)
	e.signIn(t, browser)

	// The most standard OIDC request there is.
	handle := e.authorize(t, browser, "openid profile email", nil)

	view := e.consentView(t, browser, handle)
	scopes, _ := view["scopes"].([]any)
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("consent view without a csrf token: %v", view)
	}
	if len(scopes) != 0 {
		t.Fatalf("expected the protocol-only request to render no catalogue scopes, got %v", scopes)
	}

	// The consent page's own logic (web/src/routes/consent/+page.svelte) builds
	// the approve body from exactly the scopes it rendered:
	//
	//	granted = request.scopes.filter(selected).map(s => s.scope)   // == []
	//	scopes: decision === 'approve' ? granted : undefined           // []
	//	canApprove = granted.length > 0 && ...                         // false
	//
	// so `{"decision":"approve","scopes":[]}` is the only shape the UI can
	// send, and the button that would send it never enables. The server
	// refuses that shape: the empty-approval refusal the round-5 suite pinned
	// as correct (for a request that HAD catalogue scopes) also closes the only
	// door a protocol-only request has.
	resp, body := e.decide(t, browser, handle, csrf, map[string]any{
		"decision": "approve",
		"scopes":   []string{},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("an authorization whose requested scopes are all protocol scopes (openid profile email) "+
			"is accepted by /oauth/authorize but can never be approved: the consent screen renders zero scopes, "+
			"its approve button stays disabled (canApprove requires granted.length > 0), and the API refuses "+
			"the empty scope array that is all the screen could echo back — status %d, body %v",
			resp.StatusCode, body)
	}
}

// 01-1 control · The same request with one catalogue scope completes
// normally, so the dead end above is about the scope set, not a broken
// environment. This probe is expected to stay green.
func TestProbeMixedScopesStillComplete(t *testing.T) {
	e := newStack(t)
	browser := newBrowser(t)
	e.signIn(t, browser)

	handle := e.authorize(t, browser, "openid profile email account.id", nil)
	view := e.consentView(t, browser, handle)
	scopes, _ := view["scopes"].([]any)
	csrf, _ := view["csrf_token"].(string)
	if len(scopes) != 1 {
		t.Fatalf("control consent view scopes = %v, want [account.id]", scopes)
	}
	resp, body := e.decide(t, browser, handle, csrf, map[string]any{
		"decision": "approve",
		"scopes":   []string{"account.id"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control decision = %d %v", resp.StatusCode, body)
	}
	redirect, _ := body["redirect_to"].(string)
	if e.followCallback(t, browser, redirect) == "" {
		t.Fatal("control flow produced no code")
	}
}

// 01-1 (device half) · The device verification page has the same gate: a
// device authorization whose scopes are all protocol scopes renders an empty
// scope list, and its canApprove requires granted.length > 0.
func TestProbeProtocolOnlyDeviceFlowCannotBeApproved(t *testing.T) {
	e := newStack(t)
	browser := newBrowser(t)
	e.signIn(t, browser)

	_, userCode := e.deviceAuth(t, e.cli, []string{"openid"})

	resp := e.get(t, browser, e.server.URL+"/v1/device/verification?user_code="+url.QueryEscape(userCode))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verification view = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	view := decodeJSON(t, e.body(t, resp))
	scopes, _ := view["scopes"].([]any)
	if len(scopes) != 0 {
		t.Fatalf("expected the protocol-only device request to render no scopes, got %v", scopes)
	}
	// web/src/routes/device/+page.svelte: canApprove = granted.length > 0 && …
	t.Errorf("a device authorization whose scopes are all protocol scopes shows an empty scope " +
		"list and an approve button that can never enable — the standard OIDC device request " +
		"(scope=openid) is accepted at /oauth/device_authorization but can never be approved")
}

// 01-3 · prompt=none with a live session renders the interactive consent page
// instead of answering through the redirect. OIDC Core §3.1.2.1: a request with
// prompt=none MUST NOT display any authentication or consent user interface
// pages; when the OP needs consent it cannot obtain silently it MUST return
// error=consent_required. Re0Auth has no pre-stored consent (every request
// goes through the consent screen), so prompt=none with a session can never be
// satisfied silently — and still it renders UI. O-8a implemented only the
// no-session half (login_required); this is the other half of the same MUST.
func TestProbePromptNoneWithASessionRendersTheConsentUI(t *testing.T) {
	e := newStack(t)
	browser := newBrowser(t)
	e.signIn(t, browser)

	// prompt=none on a request this OP can only answer interactively (it has
	// no stored consent to fall back on) must come back through the redirect
	// with error=consent_required. Instead the browser is handed the consent
	// page — inside a hidden iframe, a silent-auth RP now renders the OP's UI
	// and never receives an error.
	handle := e.authorize(t, browser, "openid account.id", url.Values{"prompt": {"none"}})
	t.Logf("prompt=none with a live session went straight to the interactive consent plane (handle %q)", handle)
	if handle != "" {
		t.Errorf("prompt=none with a live session rendered the interactive consent UI (handle %q): "+
			"OIDC Core §3.1.2.1 requires error=consent_required through the redirect_uri whenever the "+
			"OP must not display UI — and this OP always needs consent, so it can never answer a "+
			"silent request as satisfied", handle)
	}

	// Control: without a session the same request is answered correctly (the
	// O-8a half the fix did implement).
	anon := newBrowser(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.cli},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {"openid account.id"},
		"state":                 {"st-none"},
		"code_challenge":        {pkceChallenge(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
		"prompt":                {"none"},
	}
	resp := e.get(t, anon, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("anonymous prompt=none = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != "app.example" || loc.Query().Get("error") != "login_required" {
		t.Fatalf("anonymous prompt=none redirected to %s", loc)
	}
}

// 01-6 · prompt=login and max_age are accepted at the entrance and silently
// dropped. OIDC Core §3.1.2.1: prompt=login — "the OP MUST prompt the
// end-user for re-authentication"; max_age — "the OP MUST re-authenticate the
// End-User" when the last auth is older. Neither the wrapper nor the storage
// keeps MaxAge (oidcstore.AuthRequest has no field for it), and prompt=login
// never re-enters the login plane: a signed-in browser completes the whole
// authorization with the original session, and the id_token's auth_time is
// the original sign-in.
func TestProbePromptLoginAndMaxAgeDoNotForceReauthentication(t *testing.T) {
	e := newStack(t)
	browser := newBrowser(t)
	e.signIn(t, browser)

	// Enough for the seconds-granularity auth_time to fall strictly behind the
	// authorization request.
	time.Sleep(1100 * time.Millisecond)
	authorizeAt := time.Now()

	handle := e.authorize(t, browser, "openid account.id",
		url.Values{"prompt": {"login"}, "max_age": {"0"}})

	// The flow must have re-entered the login plane. It did not: the consent
	// view answers 200 for the still-signed-in session — the request was
	// ready for a decision without any authentication happening after
	// prompt=login asked for one.
	view := e.consentView(t, browser, handle)
	csrf, _ := view["csrf_token"].(string)
	resp, body := e.decide(t, browser, handle, csrf, map[string]any{
		"decision": "approve",
		"scopes":   []string{"account.id"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decision = %d %v", resp.StatusCode, body)
	}
	redirect, _ := body["redirect_to"].(string)
	tokens := e.exchange(t, e.followCallback(t, browser, redirect))

	idToken, _ := tokens["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token: %v", tokens)
	}
	claims := idTokenClaims(t, idToken)
	authTime, _ := claims["auth_time"].(float64)
	t.Logf("prompt=login flow completed; id_token auth_time = %d, authorize at %d",
		int64(authTime), authorizeAt.Unix())

	if int64(authTime) < authorizeAt.Unix() {
		t.Errorf("prompt=login + max_age=0 completed with the ORIGINAL session's auth_time "+
			"(auth_time=%d < authorize=%d): no re-authentication was forced, and the id_token is the "+
			"proof — an RP asking for step-up auth silently gets a token from a session that could be "+
			"hours old", int64(authTime), authorizeAt.Unix())
	}

	// Control: an anonymous browser is still gated — the same view answers
	// 401 without a session, so the entrance itself works.
	anon := newBrowser(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.cli},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {"openid account.id"},
		"state":                 {"st-anon"},
		"code_challenge":        {pkceChallenge(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
	}
	resp = e.get(t, anon, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("anonymous authorize = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	anonHandle := loc.Query().Get("id")
	if anonHandle == "" {
		t.Fatalf("no handle in %s", loc)
	}
	resp = e.get(t, anon, e.server.URL+"/v1/authorization_requests/"+anonHandle)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous consent view = %d, want 401: %s", resp.StatusCode, e.body(t, resp))
	}
}
