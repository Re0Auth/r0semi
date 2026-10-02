//go:build audit6

// Zone-01 findings on the consent face: what an interactive authorization can
// and cannot complete, and what prompt=none / prompt=login actually do to a
// signed-in session.
//
// Every red probe in this file has been REPOSITIONED: the finding it demonstrated
// was fixed, so the probe now guards the fixed behaviour under its original name
// (a "regression guard", per the round-6 truthfulness rule). Where a fixture
// rather than production caused the red, the fixture was brought back to the
// production shape and the probe measures the real boundary.
package z01protocolauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// scopeEntry returns the rendered scope object for a scope name.
func scopeEntry(t *testing.T, scopes []any, name string) map[string]any {
	t.Helper()
	for _, raw := range scopes {
		entry, ok := raw.(map[string]any)
		if ok && entry["scope"] == name {
			return entry
		}
	}
	t.Fatalf("scope %q is not rendered; the display set must cover the grant set: %v", name, scopes)
	return nil
}

// assertSystemRequired checks the A-FE-3 placeholder: a requested scope the
// catalogue does not describe is shown as system-required (never dropped, never
// offered as a user-selectable catalogue scope).
func assertSystemRequired(t *testing.T, entry map[string]any) {
	t.Helper()
	if entry["title"] != "系统必需" {
		t.Fatalf("catalogue-less scope %v rendered without the system-required placeholder: %v", entry["scope"], entry)
	}
	if entry["explicit_consent"] != false {
		t.Fatalf("the system-required placeholder must not claim explicit_consent: %v", entry)
	}
	if d, _ := entry["description"].(string); d == "" {
		t.Fatalf("the system-required placeholder carries no description: %v", entry)
	}
}

// handleFromReauth pulls the consent handle out of the /auth/reauth redirect the
// login boundary builds (`return_to=/app/consent?id=…`).
func handleFromReauth(t *testing.T, loc *url.URL) string {
	t.Helper()
	returnTo := loc.Query().Get("return_to")
	if returnTo == "" {
		t.Fatalf("the re-authentication redirect carries no return_to: %s", loc)
	}
	consent, err := url.Parse(returnTo)
	if err != nil {
		t.Fatal(err)
	}
	id := consent.Query().Get("id")
	if id == "" {
		t.Fatalf("return_to %q carries no consent handle", returnTo)
	}
	return id
}

// 01-1 · A-FE-3/A-FE-V1 (fixed — now a regression guard, name kept for the
// coverage matrix). A request whose scope set is entirely OIDC protocol scopes —
// the default request of every standard relying party ("openid profile email") —
// used to dead-end: the consent screen rendered zero scopes (the catalogue did
// not describe them) while the server still carried them through, so the only
// decision body the screen could build was an empty scope array that the API
// refused.
//
// The fix renders every granted scope: a scope with no descriptor gets the
// explicit system-required placeholder, so the display set covers the grant set
// (A-FE-3). The probe now asserts that placeholder AND that the standard request
// completes end to end with an id_token.
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
	if len(scopes) != 3 {
		t.Fatalf("the protocol-only request rendered %d scopes, want all three requested scopes "+
			"(the display set must cover the grant set): %v", len(scopes), scopes)
	}
	for _, name := range []string{"openid", "profile", "email"} {
		assertSystemRequired(t, scopeEntry(t, scopes, name))
	}

	// The consent page builds its approve body from exactly the scopes it
	// rendered (granted.length > 0), so this is the shape the UI sends — and it
	// must be accepted.
	resp, body := e.decide(t, browser, handle, csrf, map[string]any{
		"decision": "approve",
		"scopes":   []string{"openid", "profile", "email"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an authorization whose requested scopes are all protocol scopes (openid profile email) "+
			"is accepted by /oauth/authorize but cannot be approved: the consent screen renders them as "+
			"system-required and the decision is refused — status %d, body %v", resp.StatusCode, body)
	}
	redirect, _ := body["redirect_to"].(string)
	if redirect == "" {
		t.Fatalf("approval answered without a redirect_to: %v", body)
	}
	code := e.followCallback(t, browser, redirect)
	if code == "" {
		t.Fatal("the protocol-only flow produced no code")
	}
	// openid must survive the round trip: a standard relying party needs its
	// id_token, which is what ADR-0001's positioning promises.
	tokens := e.exchange(t, code)
	if idToken, _ := tokens["id_token"].(string); idToken == "" {
		t.Errorf("the protocol-only approval issued no id_token although openid was requested: %v", tokens)
	}
}

// 01-1 control · The same request with one catalogue scope completes normally
// and now renders the catalogue scope ALONGSIDE the three protocol placeholders
// (A-FE-3 made the display set cover the grant set in both cases).
func TestProbeMixedScopesStillComplete(t *testing.T) {
	e := newStack(t)
	browser := newBrowser(t)
	e.signIn(t, browser)

	handle := e.authorize(t, browser, "openid profile email account.id", nil)
	view := e.consentView(t, browser, handle)
	scopes, _ := view["scopes"].([]any)
	csrf, _ := view["csrf_token"].(string)
	if len(scopes) != 4 {
		t.Fatalf("control consent view scopes = %v, want the three protocol scopes plus account.id", scopes)
	}
	for _, name := range []string{"openid", "profile", "email"} {
		assertSystemRequired(t, scopeEntry(t, scopes, name))
	}
	account := scopeEntry(t, scopes, "account.id")
	if account["title"] == "系统必需" || account["title"] == "" {
		t.Fatalf("account.id was rendered without its catalogue descriptor: %v", account)
	}
	resp, body := e.decide(t, browser, handle, csrf, map[string]any{
		"decision": "approve",
		"scopes":   []string{"openid", "profile", "email", "account.id"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control decision = %d %v", resp.StatusCode, body)
	}
	redirect, _ := body["redirect_to"].(string)
	if e.followCallback(t, browser, redirect) == "" {
		t.Fatal("control flow produced no code")
	}
}

// 01-1 (device half) · A-FE-V1 (fixed — now a regression guard). The device
// verification page had the same gate: a device authorization whose scopes are
// all protocol scopes rendered an empty scope list, so its canApprove
// (`granted.length > 0`) could never enable. The proto scope is now rendered as
// system-required, and the device decision the page builds completes.
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
	if len(scopes) != 1 {
		t.Fatalf("the protocol-only device request rendered %d scopes, want openid as system-required: %v", len(scopes), scopes)
	}
	assertSystemRequired(t, scopeEntry(t, scopes, "openid"))
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("device verification view without a csrf token: %v", view)
	}

	// The device page's canApprove is `granted.length > 0` over the rendered
	// (and by default selected) scopes, so this is the decision it can now send.
	dresp, dbody := e.decideDevice(t, browser, csrf, map[string]any{
		"user_code": userCode,
		"decision":  "approve",
		"scopes":    []string{"openid"},
	})
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("a device authorization whose scopes are all protocol scopes (scope=openid) is accepted "+
			"at /oauth/device_authorization but cannot be approved — status %d, body %v", dresp.StatusCode, dbody)
	}
	if dbody["state"] != "approved" {
		t.Fatalf("device decision state = %v, want approved", dbody["state"])
	}
}

// 01-3 · S02-2 (fixed — now a regression guard, name kept). prompt=none with a
// live session used to render the interactive consent page. OIDC Core §3.1.2.1:
// a request with prompt=none MUST NOT display any authentication or consent user
// interface pages; when the OP must obtain consent it cannot get silently it
// MUST return error=consent_required. Re0Auth has no pre-stored consent, so a
// silent request can NEVER be satisfied silently — the correct answer is always
// consent_required through the redirect.
func TestProbePromptNoneWithASessionRendersTheConsentUI(t *testing.T) {
	e := newStack(t)
	browser := newBrowser(t)
	e.signIn(t, browser)

	loc := e.authorizeLocation(t, browser, "openid account.id", url.Values{"prompt": {"none"}})
	if loc.Host != "app.example" {
		t.Fatalf("prompt=none with a live session redirected to %s, want the client's registered callback", loc)
	}
	if got := loc.Query().Get("error"); got != "consent_required" {
		t.Errorf("prompt=none with a live session answered error=%q (%s), want consent_required: this OP "+
			"has no pre-existing consent to reuse, so the silent request must fail closed through the "+
			"redirect instead of rendering the interactive consent UI", got, loc)
	}
	if got := loc.Query().Get("iss"); got == "" {
		t.Errorf("the consent_required redirect carries no iss (RFC 9207 §2): %s", loc)
	}

	// Control: without a session the same request is answered with
	// login_required (the O-8a half), so the answer above is about consent and
	// not a blanket refusal.
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
	aloc, _ := url.Parse(resp.Header.Get("Location"))
	if aloc.Host != "app.example" || aloc.Query().Get("error") != "login_required" {
		t.Fatalf("anonymous prompt=none redirected to %s", aloc)
	}
}

// 01-6 · S02-1/O-8b (fixed — now a regression guard, name kept). prompt=login
// and max_age used to be accepted at the entrance and silently dropped: a
// signed-in browser completed the whole authorization with the original session
// and the id_token carried the original auth_time, so an RP asking for step-up
// authentication silently got a token from a session that could be hours old.
//
// The fix has two halves, and this probe measures both:
//   - the login boundary sends a freshness-bound request through the identity
//     provider (/auth/reauth → /auth/{provider}/start?mode=login) instead of to
//     the consent screen, and
//   - the store refuses CompleteLogin on a recorded authentication that does not
//     satisfy the bound (oidcstore.ErrReauthenticationRequired, never a
//     fabricated auth_time); a real re-authentication completes it and the
//     id_token carries that recorded time.
//
// The stack fixture's login hook was brought back to the production shape
// (cmd/re0auth openOIDC) before this was measured: the red it used to produce was
// the fixture omitting the freshness branch.
func TestProbePromptLoginAndMaxAgeDoNotForceReauthentication(t *testing.T) {
	e := newStack(t)
	browser := newBrowser(t)
	e.signIn(t, browser)

	// Enough for the seconds-granularity auth_time to fall strictly behind the
	// authorization request.
	time.Sleep(1100 * time.Millisecond)

	for name, extra := range map[string]url.Values{
		"prompt=login": {"prompt": {"login"}},
		"max_age=0":    {"max_age": {"0"}},
	} {
		t.Run(name, func(t *testing.T) {
			loc := e.authorizeLocation(t, browser, "openid account.id", extra)
			if loc.Path != "/auth/reauth" {
				t.Fatalf("%s reached %s instead of the re-authentication entrance: the login boundary "+
					"must send a request whose freshness the session cannot prove through the identity "+
					"provider (S02-1/O-8b), not to the consent screen", name, loc)
			}
			id := handleFromReauth(t, loc)

			// The store's half: the prior session's authentication cannot
			// complete the request, and the refusal leaves it undecided.
			stale := time.Now().Add(-2 * time.Hour)
			if err := e.store.SetAuthTime(context.Background(), id, stale); err != nil {
				t.Fatal(err)
			}
			err := e.store.CompleteLogin(context.Background(), id, "usr_z01", []string{"openid", "account.id"})
			if !errors.Is(err, oidcstore.ErrReauthenticationRequired) {
				t.Fatalf("%s: completing on a two-hour-old session = %v, want oidcstore.ErrReauthenticationRequired", name, err)
			}
			if ar, aerr := e.store.AuthRequestByID(context.Background(), id); aerr != nil || ar.Done() {
				t.Fatalf("%s: the refused completion left the request decided: done=%v err=%v",
					name, ar != nil && ar.Done(), aerr)
			}

			// A real re-authentication satisfies it, and the id_token carries the
			// recorded time rather than the consent-decision clock.
			fresh := time.Now().Add(-2 * time.Second)
			if err := e.store.SetAuthTime(context.Background(), id, fresh); err != nil {
				t.Fatal(err)
			}
			if err := e.store.CompleteLogin(context.Background(), id, "usr_z01",
				withOfflineAccess([]string{"openid", "account.id"})); err != nil {
				t.Fatalf("%s: completing after a fresh authentication: %v", name, err)
			}
			code := e.followCallback(t, browser, "/oauth/authorize/callback?id="+url.QueryEscape(id))
			tokens := e.exchange(t, code)
			raw, _ := tokens["id_token"].(string)
			if raw == "" {
				t.Fatalf("%s: no id_token: %v", name, tokens)
			}
			claims := idTokenClaims(t, raw)
			at, _ := claims["auth_time"].(float64)
			got := time.Unix(int64(at), 0).UTC()
			if got.Sub(fresh) < -time.Minute || got.Sub(fresh) > time.Minute {
				t.Errorf("%s: id_token auth_time = %s, want the recorded re-authentication %s — the "+
					"id_token must never advertise a fresh authentication that never happened", name, got, fresh)
			}
		})
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
	resp := e.get(t, anon, e.server.URL+"/oauth/authorize?"+q.Encode())
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
