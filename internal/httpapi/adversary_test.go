// Guards for the findings of the second adversarial audit (docs/security-audit-2.md).
//
// Each of these failed before its fix and passes now. They live together so the
// audit and its guards stay in one place, and each test names the finding it pins.
package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
)

func recorderJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// Finding A1-1: the device flow hands out a scope the client was never
// registered for.
//
// `validateAuthorize` enforces the client's scope allowance on the authorize
// route, but `POST /oauth/device_authorization` never passes through it: the
// library stores the requested scopes verbatim and r0semi's own pre-flight only
// runs for GET /oauth/authorize. So a client registered for `account.id` alone
// can ask for — and, once a user approves, receive — any catalogue scope.
func TestAdversarialDeviceAuthorizationRefusesUnregisteredScope(t *testing.T) {
	env := newTestEnv(t)
	// Registered for exactly one scope.
	env.register(t, "clientscope", oauth.ClientPublic, "", []oauth.Scope{oauth.ScopeAccountID})

	form := url.Values{
		"client_id": {"clientscope"},
		"scope":     {"account.id phigros.score.read"},
	}
	rec := env.do(http.MethodPost, "/oauth/device_authorization", form.Encode(), nil)

	if rec.Code == http.StatusOK {
		t.Fatalf("a client registered for account.id obtained a device code for an "+
			"unregistered scope: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_scope", rec.Code)
	}
	if body := recorderJSON(t, rec); body["error"] != "invalid_scope" {
		t.Errorf("error = %v, want invalid_scope", body["error"])
	}
}

// Finding A1-2: POST /oauth/authorize skips the whole pre-flight, so a
// confidential client gets an authorization code with no PKCE binding.
//
// `internal/oidchttp` runs its client/redirect/PKCE/scope checks only when
// `r.Method == GET && path == /oauth/authorize`. The library's authorize handler
// is registered without a method constraint and reads from `r.Form` (which
// includes a POST body), so a POST reaches it unchecked. The library only
// *requires* PKCE at exchange for `AuthMethodNone`, so a confidential client's
// code can be redeemed by anyone holding the client secret, with no verifier.
func TestAdversarialPostAuthorizeRequiresPKCE(t *testing.T) {
	env := newTestEnv(t)
	const secret = "s3cret"
	env.register(t, "conf", oauth.ClientConfidential, secret, []oauth.Scope{oauth.ScopeAccountID})

	// The same request issueCode builds, sent as a POST and with NO code_challenge.
	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"conf"},
		"redirect_uri":  {"https://app.example/cb"},
		"scope":         {"account.id"},
		"state":         {"st"},
	}
	rec := env.do(http.MethodPost, "/oauth/authorize", form.Encode(), nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	// The GET route answers this with error=invalid_request.
	if loc.Query().Get("error") == "" && !strings.Contains(loc.Path, "/login") {
		t.Fatalf("unexpected redirect %q", loc.String())
	}
	if !strings.Contains(loc.Path, "/login") {
		// It was refused — the finding does not reproduce.
		return
	}

	// The request was accepted. Drive it to a code and redeem it with no verifier.
	handle := loc.Query().Get("authRequestID")
	if handle == "" {
		t.Fatalf("no authRequestID in %q", loc.String())
	}
	if err := env.store.CompleteLogin(context.Background(), handle, "user-1", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	cb := env.do(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(handle), "", nil)
	cbLoc, err := url.Parse(cb.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cbLoc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", cbLoc.String())
	}

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("conf:"+secret))
	rec = env.do(http.MethodPost, "/oauth/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://app.example/cb"},
		// deliberately no code_verifier
	}.Encode(), map[string]string{"Authorization": basic})
	if rec.Code == http.StatusOK {
		t.Fatalf("a code obtained by POST was exchanged with no code_verifier: %s", rec.Body.String())
	}
}

// Finding A1-3: POST /oauth/authorize narrows an unregistered scope silently
// instead of refusing it, which is what the GET route and decision record O-7
// both promise.
func TestAdversarialPostAuthorizeRejectsUnregisteredScope(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "web", oauth.ClientPublic, "", []oauth.Scope{oauth.ScopeAccountID})

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"web"},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {"account.id phigros.b30.read"},
		"state":                 {"st"},
		"code_challenge":        {pkce("verifier-verifier-verifier-verifier-verifier-extra")},
		"code_challenge_method": {"S256"},
	}

	// The GET route refuses it.
	getRec := env.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), "", nil)
	getLoc, _ := url.Parse(getRec.Header().Get("Location"))
	if getLoc.Query().Get("error") == "" {
		t.Fatalf("GET did not refuse an unregistered scope (the baseline moved): %q", getLoc.String())
	}

	// The POST route does not.
	postRec := env.do(http.MethodPost, "/oauth/authorize", q.Encode(), nil)
	postLoc, _ := url.Parse(postRec.Header().Get("Location"))
	if postLoc.Query().Get("error") == "" {
		t.Errorf("POST silently accepted an unregistered scope: %q (GET refused it with %q)",
			postLoc.String(), getLoc.Query().Get("error"))
	}
}

// Finding A2-1: the bind callback checks that the handle belongs to this BROWSER
// but not that it belongs to this ACCOUNT, so a second account in the same browser
// can consume the first one's flow.
//
// `handleBindCallback` calls `sessions.Bound` and never `sessions.OwnerMatches`,
// while both sibling handlers (`handleAuthorizationDecision`, the device decision)
// check both. `Bind` records the owner, and `OwnerMatches` documents that this is
// exactly its purpose, so the tag is there and simply not consulted. The victim's
// flow is destroyed: `Unbind` removes the session handle and `CompleteBind`
// consumes the flow row before its own weaker `flow.User != user` check refuses
// the binding. The result is a cross-account denial of the victim's own binding.
func TestAdversarialBindCallbackRejectsAnotherAccount(t *testing.T) {
	upstream := newFakeUpstream(t)
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", DisplayName: "Fake", Issuer: upstream.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []federation.Resource{{
			Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fed, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: federation.NewMemoryBindingStore(),
		Vault: newTestVault(t), Doer: upstream.Client(), BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := newFlowEnvWith(t, fed)
	browser := newBrowser(t)

	// Account A starts a bind flow.
	signInAs(t, browser, base, "a")
	start := getURL(t, browser, base+"/bind?game=phigros&source=fake")
	if start.StatusCode != http.StatusFound {
		t.Fatalf("bind start = %d", start.StatusCode)
	}
	upstreamURL, err := url.Parse(start.Header.Get("Location"))
	start.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	state := upstreamURL.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in %q", upstreamURL.String())
	}
	callback := base + "/auth/upstream/phigros/fake/callback?state=" + url.QueryEscape(state) + "&code=c"

	// Account B takes over the same browser and tries A's callback.
	signInAs(t, browser, base, "b")
	byB := getURL(t, browser, callback)
	byB.Body.Close()
	if byB.StatusCode != http.StatusBadRequest {
		t.Errorf("another account acted on A's bind handle: got %d, want 400 (the same "+
			"answer as an unknown handle — a 303 confirms the handle exists and was consumed)",
			byB.StatusCode)
	}

	// A must still be able to finish.
	signInAs(t, browser, base, "a")
	byA := getURL(t, browser, callback)
	byA.Body.Close()
	if byA.StatusCode != http.StatusSeeOther {
		t.Errorf("the owner can no longer finish their own bind flow: got %d, want 303", byA.StatusCode)
	}
}

// Finding A4-1: POST /oauth/revoke with a refresh token answers 200 and revokes
// nothing, so a leaked refresh token survives its own revocation.
//
// `GetRefreshTokenInfo` returns the *access* token's id hash, and the library
// feeds that value back into `RevokeToken`, which re-hashes it and matches
// nothing — falling through to the RFC 7009 "already invalid" branch, which
// returns success.
func TestAdversarialRevokeWithRefreshTokenActuallyRevokes(t *testing.T) {
	env := newTestEnv(t)
	const secret = "s3cret"
	env.register(t, "conf", oauth.ClientConfidential, secret, []oauth.Scope{oauth.ScopeAccountID})
	const verifier = "verifier-verifier-verifier-verifier-verifier"

	// offline_access is what makes the OP issue a refresh token.
	scopes := []oauth.Scope{oauth.ScopeAccountID, oauth.Scope("offline_access")}
	code := env.issueCode(t, "conf", scopes, verifier)
	exchanged := env.exchange(t, "conf", secret, code, verifier, nil)
	if exchanged.Code != http.StatusOK {
		t.Fatalf("exchange = %d: %s", exchanged.Code, exchanged.Body.String())
	}
	refresh, _ := recorderJSON(t, exchanged)["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("no refresh token issued")
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("conf:"+secret))

	// Revoke it the way a client does, with the hint.
	rec := env.do(http.MethodPost, "/oauth/revoke", url.Values{
		"token":           {refresh},
		"token_type_hint": {"refresh_token"},
	}.Encode(), map[string]string{"Authorization": basic})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body.String())
	}

	// It must no longer work.
	rec = env.do(http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	}.Encode(), map[string]string{"Authorization": basic})
	if rec.Code == http.StatusOK {
		t.Fatalf("the revoked refresh token still mints tokens: %s", rec.Body.String())
	}
}
