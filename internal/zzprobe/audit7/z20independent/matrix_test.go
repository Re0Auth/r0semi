//go:build audit7

// Z20-INDEPENDENT matrix probes: subject x client x scope x resource.
//
// These are the angles the zone-20 report did NOT cover with a named probe
// (cross-subject reads, the operator allowlist, consent/device/refresh scope
// widening, the public source listing, and flow ownership). Each one records
// whether the invariant holds or breaks; a break is a finding, a hold is a guard.
package zzprobe_z20independent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/oauth"
)

// TestZ20I101CrossSubjectReadIsKeyedOnTheTokenSubject (matrix cell: subject x resource).
//
// Only `usr_victim` has a binding. A valid token for a DIFFERENT subject that
// carries the very scope the resource requires must not reach the source.
func TestZ20I101CrossSubjectReadIsKeyedOnTheTokenSubject(t *testing.T) {
	e := newZAEnv(t, zAOpts{})

	attacker := e.zMintToken(zClientPublic, zOther, "phigros.profile.read")
	victim := e.zMintToken(zClientPublic, zVictim, "phigros.profile.read")
	if attacker == "" || victim == "" {
		t.Fatal("control: no tokens minted")
	}

	// Control: the victim's own token is served, so the route is reachable.
	st, _, body := e.zGet("/v1/games/"+zGame+"/profile", victim)
	t.Logf("victim token -> %d %s", st, body)
	if st != http.StatusOK || !bytes.Contains(body, []byte(zProfileMarker)) {
		t.Fatalf("control: the bound subject's own token was not served (%d %s)", st, body)
	}
	beforeCalls := len(e.up.calls())

	// The claim: the same scope, a different subject.
	st, _, body = e.zGet("/v1/games/"+zGame+"/profile", attacker)
	t.Logf("other subject, same scope -> %d %s", st, body)
	if st == http.StatusOK && bytes.Contains(body, []byte(zProfileMarker)) {
		t.Errorf("the data plane served a subject with no binding for this source (%d): %s", st, body)
	}
	if st != http.StatusConflict {
		t.Errorf("an unbound subject answered %d, want 409 source_not_bound", st)
	}
	if len(e.up.calls()) != beforeCalls {
		t.Errorf("the upstream was reached for an unbound subject: %v", e.up.calls())
	}
}

// TestZ20I102BearerTokenCannotReadSessionScopedRoutes (matrix cell: subject x route).
func TestZ20I102BearerTokenCannotReadSessionScopedRoutes(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)
	e.zSignInAs(b, "c")

	token := e.zMintToken(zClientPublic, zVictim, "account.id", "phigros.profile.read")

	// Control: /v1/me is bearer-scoped and works.
	if st, _, _ := e.zGet("/v1/me", token); st != http.StatusOK {
		t.Fatalf("control: /v1/me with a live token = %d", st)
	}
	// Control: the signed-in browser can read the session-scoped views.
	for _, path := range []string{"/v1/grants", "/v1/bindings", "/v1/identities", "/v1/account/export"} {
		if st, _, body := e.zGetBrowser(b, path); st != http.StatusOK {
			t.Fatalf("control: %s in the signed-in browser = %d %s", path, st, body)
		}
	}

	for _, path := range []string{"/v1/grants", "/v1/bindings", "/v1/identities", "/v1/account/export", "/v1/sessions/current"} {
		st, _, body := e.zGet(path, token)
		t.Logf("bearer-only %s -> %d", path, st)
		if st != http.StatusUnauthorized {
			t.Errorf("%s accepted a bearer token (%d): a client must not enumerate the "+
				"user's other clients or connections. body=%s", path, st, body)
		}
	}
}

// TestZ20I103AccountSwitchInOneBrowserDoesNotLeakTheOtherSubject (matrix cell: subject x session).
func TestZ20I103AccountSwitchInOneBrowserDoesNotLeakTheOtherSubject(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)

	e.zSignInAs(b, "c")
	first := e.zCurrentSessionID(b)
	_, _, firstBody := e.zGetBrowser(b, "/v1/account/export")
	firstExport := zJSON(t, firstBody)
	firstProfile, _ := firstExport["profile"].(map[string]any)
	firstIDs := zIdentityIDs(firstExport)

	e.zSignInAs(b, "second-account")
	second := e.zCurrentSessionID(b)
	if second == first {
		t.Fatalf("control: the account switch did not change the subject (%q)", second)
	}
	_, _, secondBody := e.zGetBrowser(b, "/v1/account/export")
	secondExport := zJSON(t, secondBody)
	secondProfile, _ := secondExport["profile"].(map[string]any)

	t.Logf("subject 1 = %s, subject 2 = %s", first, second)
	if got, _ := firstProfile["user_id"].(string); got != first {
		t.Errorf("export under subject 1 named %q", got)
	}
	if got, _ := secondProfile["user_id"].(string); got != second {
		t.Errorf("export after the switch named %q, want %q", got, second)
	}
	for id := range zIdentityIDs(secondExport) {
		if firstIDs[id] {
			t.Errorf("the second subject's export carries the first subject's identity %q", id)
		}
	}
	if got := len(zIdentityIDs(secondExport)); got != 1 {
		t.Errorf("the switched account has %d identities, want 1: %v", got, zIdentityIDs(secondExport))
	}
}

// TestZ20I104ConsentDecisionCannotWidenTheRequestedScope (matrix cell: scope x consent).
func TestZ20I104ConsentDecisionCannotWidenTheRequestedScope(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)
	e.zSignInAs(b, "c")

	// Control: approving exactly what was requested yields a code, and the
	// exchanged token holds exactly that (plus the protocol no-op).
	code, ds, db := e.zConsentCode(b, zClientPublic, "account.id", []string{"account.id"})
	if ds != http.StatusOK {
		t.Fatalf("control: approving the requested scope = %d %s", ds, db)
	}
	st, tok, body := e.zExchange(zClientPublic, "", code)
	if st != http.StatusOK {
		t.Fatalf("control: exchange = %d %s", st, body)
	}
	at := zTokenString(t, tok)
	if scopes := zMeScopes(t, e, at); !zHasScope(scopes, "account.id") || zHasScope(scopes, "phigros.score.read") {
		t.Fatalf("control: the issued token's scopes = %v", scopes)
	}

	// Attack 1: ask for a scope the client IS registered for but the request did
	// not include.
	b2 := zBrowser(t)
	e.zSignInAs(b2, "c")
	code, ds, db = e.zConsentCode(b2, zClientPublic, "account.id", []string{"account.id", "phigros.score.read"})
	t.Logf("decision widening to phigros.score.read -> %d %s", ds, db)
	if ds == http.StatusOK {
		if st, tok, _ := e.zExchange(zClientPublic, "", code); st == http.StatusOK {
			scopes := zMeScopes(t, e, zTokenString(t, tok))
			t.Errorf("the consent decision WIDENED the granted set beyond the request: %v", scopes)
		}
	}

	// Attack 2: a scope the client is not registered for at all.
	b3 := zBrowser(t)
	e.zSignInAs(b3, "c")
	code, ds, db = e.zConsentCode(b3, zClientPublic, "account.id", []string{"account.id", "phigros.b30.read"})
	t.Logf("decision widening to an unregistered scope -> %d %s", ds, db)
	if ds == http.StatusOK {
		if st, tok, _ := e.zExchange(zClientPublic, "", code); st == http.StatusOK {
			scopes := zMeScopes(t, e, zTokenString(t, tok))
			t.Errorf("the consent decision granted a scope the client is not registered for: %v", scopes)
		}
	}
}

// TestZ20I105DeviceDecisionCannotWidenTheRequestedScope (matrix cell: scope x device).
func TestZ20I105DeviceDecisionCannotWidenTheRequestedScope(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)
	e.zSignInAs(b, "c")

	// Control: an approval that narrows to the requested scope yields exactly it.
	uc, dc := e.zDeviceStartFull(t, "account.id phigros.profile.read")
	if st, _, body := e.zGetBrowser(b, "/v1/device/verification?user_code="+url.QueryEscape(uc)); st != http.StatusOK {
		t.Fatalf("device verification = %d %s", st, body)
	}
	_, viewBody := e.zDeviceView(t, b, uc)
	csrf, _ := zJSON(t, viewBody)["csrf_token"].(string)
	st, db := e.zPostJSON(b, "/v1/device/decision",
		map[string]any{"user_code": uc, "decision": "approve",
			"scopes": []string{"account.id", "phigros.profile.read"}}, csrf)
	if st != http.StatusOK {
		t.Fatalf("control: device approval = %d %s", st, db)
	}
	dst, dtok, dbody := e.zDevicePoll(dc)
	if dst != http.StatusOK {
		t.Fatalf("control: device poll = %d %s", dst, dbody)
	}
	scopes := zMeScopes(t, e, zTokenString(t, dtok))
	t.Logf("device token scopes = %v", scopes)
	if zHasScope(scopes, "phigros.score.read") {
		t.Errorf("the device grant issued a scope that was never requested: %v", scopes)
	}

	// Attack: approve a registered scope the device request did not ask for.
	uc2, dc2 := e.zDeviceStartFull(t, "account.id phigros.profile.read")
	if st, _, body := e.zGetBrowser(b, "/v1/device/verification?user_code="+url.QueryEscape(uc2)); st != http.StatusOK {
		t.Fatalf("device verification = %d %s", st, body)
	}
	_, viewBody = e.zDeviceView(t, b, uc2)
	csrf, _ = zJSON(t, viewBody)["csrf_token"].(string)
	st, db = e.zPostJSON(b, "/v1/device/decision",
		map[string]any{"user_code": uc2, "decision": "approve",
			"scopes": []string{"account.id", "phigros.score.read"}}, csrf)
	t.Logf("device decision widening to phigros.score.read -> %d %s", st, db)
	if st == http.StatusOK {
		if dst, dtok, _ := e.zDevicePoll(dc2); dst == http.StatusOK {
			scopes := zMeScopes(t, e, zTokenString(t, dtok))
			t.Errorf("the device decision WIDENED the granted set beyond the request: %v", scopes)
		}
	}
}

// TestZ20I106RefreshCannotWidenTheGrantedScope (matrix cell: scope x refresh).
func TestZ20I106RefreshCannotWidenTheGrantedScope(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	toks := e.zMintTokens(zClientPublic, zVictim, "account.id")
	rt, _ := toks["refresh_token"].(string)
	if rt == "" {
		t.Fatal("control: no refresh token")
	}

	// Control: a refresh with no scope argument succeeds and keeps the set.
	st, body := e.zPostForm("/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {zClientPublic},
		"refresh_token": {rt},
	}, "")
	if st != http.StatusOK {
		t.Fatalf("control: refresh = %d %s", st, body)
	}
	var first zATokens
	_ = json.Unmarshal(body, &first)
	if scopes := zMeScopes(t, e, first.AccessToken()); zHasScope(scopes, "phigros.score.read") {
		t.Fatalf("control: the refresh already held an unrequested scope: %v", scopes)
	}
	rt2, _ := first["refresh_token"].(string)

	// The claim: a refresh must not widen.
	st, body = e.zPostForm("/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {zClientPublic},
		"refresh_token": {rt2},
		"scope":         {"account.id phigros.score.read"},
	}, "")
	t.Logf("refresh requesting a wider scope -> %d %s", st, body)
	var second zATokens
	_ = json.Unmarshal(body, &second)
	if st == http.StatusOK {
		scopes := zMeScopes(t, e, second.AccessToken())
		if zHasScope(scopes, "phigros.score.read") {
			t.Errorf("a refresh WIDENED the granted scope set: %v", scopes)
		}
		t.Logf("refresh answered 200 but narrowed/ignored: scopes=%v", scopes)
	}
}

// TestZ20I107AdminAllowlistIsExact (matrix cell: subject x operator plane).
//
// The allowlist is a map lookup on the exact account id. Every near-miss
// spelling must therefore be refused, and the refusal must not be a 403 that
// confirms the plane exists.
func TestZ20I107AdminAllowlistIsExact(t *testing.T) {
	stack := newZAStack(t, zAOpts{})
	b := zBrowser(t)

	// A server with an allowlist that can never match, purely to sign in on.
	probe := stack.serve([]account.UserID{"usr_nobody_matches_this"})
	st, _, body := probe.zGetBrowser(b, "/v1/admin/clients")
	t.Logf("signed-out /v1/admin/clients -> %d %s", st, body)
	if st != http.StatusUnauthorized {
		t.Errorf("an unauthenticated admin call answered %d, want 401", st)
	}
	probe.zSignInAs(b, "c")
	admin := probe.zCurrentSessionID(b)
	t.Logf("operator account id = %s", admin)

	exact := stack.serve([]account.UserID{account.UserID(admin)})
	zCarryCookies(t, b, probe.srv.URL, exact.srv.URL)
	if st, _, body := exact.zGetBrowser(b, "/v1/admin/clients"); st != http.StatusOK {
		t.Fatalf("control: the exact allowlisted subject = %d %s", st, body)
	}

	nearMisses := map[string]account.UserID{
		"trailing space": account.UserID(admin + " "),
		"leading space":  account.UserID(" " + admin),
		"upper case":     account.UserID(strings.ToUpper(admin)),
		"prefix":         account.UserID(zDropLast(admin)),
		"appended char":  account.UserID(admin + "x"),
		"percent-escape": account.UserID("%" + admin),
	}
	for name, allowed := range nearMisses {
		if string(allowed) == admin {
			continue
		}
		srv := stack.serve([]account.UserID{allowed})
		zCarryCookies(t, b, probe.srv.URL, srv.srv.URL)
		st, _, body := srv.zGetBrowser(b, "/v1/admin/clients")
		t.Logf("allowlist %-15s (%q) -> %d", name, string(allowed), st)
		if st != http.StatusNotFound {
			t.Errorf("the allowlist matched a near miss (%s: %q) and answered %d, want 404: %s",
				name, string(allowed), st, body)
		}
	}

	// A different account, signed in, is not an operator either.
	plain := stack.serve([]account.UserID{account.UserID(admin)})
	probe.zSignInAs(b, "someone-else")
	zCarryCookies(t, b, probe.srv.URL, plain.srv.URL)
	other := probe.zCurrentSessionID(b)
	if other == admin {
		t.Fatalf("control: the second sign-in did not change the subject")
	}
	if st, _, body := plain.zGetBrowser(b, "/v1/admin/clients"); st != http.StatusNotFound {
		t.Errorf("a signed-in non-operator answered %d, want 404: %s", st, body)
	}
}

// TestZ20I108PublicSourceListingDisclosesNoUpstreamCredential (matrix cell: client x public read).
func TestZ20I108PublicSourceListingDisclosesNoUpstreamCredential(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	for _, path := range []string{"/v1/sources", "/v1/games/" + zGame + "/sources"} {
		st, _, body := e.zGet(path, "")
		if st != http.StatusOK {
			t.Fatalf("%s = %d %s", path, st, body)
		}
		for _, secret := range []string{zUpClientSecret, zUpToken} {
			if bytes.Contains(body, []byte(secret)) {
				t.Errorf("%s (public, unauthenticated) discloses %q: %s", path, secret, body)
			}
		}
		t.Logf("%s -> %d (%d bytes, no credential)", path, st, len(body))
	}
}

// TestZ20I109NormalizedGateRequiresEveryCandidateSourcesScope (matrix cell: resource x source).
//
// Two sources declare the SAME resource name with DIFFERENT scopes. The read is
// served by whichever candidates() picks, so the gate must require the scope of
// every candidate, and pinning must be the only way to ask for one source.
func TestZ20I109NormalizedGateRequiresEveryCandidateSourcesScope(t *testing.T) {
	e := newZAEnv(t, zAOpts{
		TwoSources: true,
		ClientScopes: []oauth.Scope{
			oauth.ScopeAccountID, oauth.ScopePhigrosProfile,
			oauth.ScopePhigrosScore, oauth.ScopePhigrosB30,
		},
	})

	scoreOnly := e.zMintToken(zClientPublic, zVictim, "phigros.score.read")
	both := e.zMintToken(zClientPublic, zVictim, "phigros.score.read", "phigros.b30.read")
	if scoreOnly == "" || both == "" {
		t.Fatal("control: no tokens")
	}

	// Control: pinning to the source whose scope the token holds is served.
	st, hdr, body := e.zGet("/v1/games/"+zGame+"/scores?source="+zSource, scoreOnly)
	t.Logf("pinned %s with its own scope -> %d %s", zSource, st, body)
	if st != http.StatusOK || hdr.Get("Re0Auth-Source") != zSource {
		t.Fatalf("control: pinned read = %d (%s) source=%q", st, body, hdr.Get("Re0Auth-Source"))
	}
	// Control: the OTHER source's scope is still required when it is pinned.
	st, _, body = e.zGet("/v1/games/"+zGame+"/scores?source="+zSourceB, scoreOnly)
	t.Logf("pinned %s with the wrong source's scope -> %d %s", zSourceB, st, body)
	if st != http.StatusForbidden {
		t.Errorf("pinning %s answered %d for a token without its scope, want 403", zSourceB, st)
	}

	// The claim: unpinned, the scope of BOTH candidates is required.
	st, _, body = e.zGet("/v1/games/"+zGame+"/scores", scoreOnly)
	t.Logf("unpinned with one source's scope -> %d %s", st, body)
	if st != http.StatusForbidden {
		t.Errorf("the unpinned read answered %d for a token holding only ONE candidate's "+
			"scope, want 403 (the gate must be computed from the object that serves)", st)
	}
	// And with both, it is served by the preferred candidate.
	st, hdr, body = e.zGet("/v1/games/"+zGame+"/scores", both)
	t.Logf("unpinned with both scopes -> %d source=%q %s", st, hdr.Get("Re0Auth-Source"), body)
	if st != http.StatusOK {
		t.Errorf("the unpinned read with every candidate's scope answered %d, want 200: %s", st, body)
	}
}

// TestZ20I110LinkFlowCannotBeHijackedByALaterSignIn (matrix cell: subject x flow ownership).
//
// The consent and device handles are `Bound` + `OwnerMatches`. The login plane's
// link flow has no owner tag, so the question is whether a later sign-in can make
// a pending link callback act as the new account. This probe tries it.
func TestZ20I110LinkFlowCannotBeHijackedByALaterSignIn(t *testing.T) {
	e := newZAEnv(t, zAOpts{})
	b := zBrowser(t)

	// Control: a link flow completed in place links the identity.
	e.zSignInAs(b, "c")
	linkState := e.zStartFlow(t, b, "link")
	if st, body := e.zFinishFlow(t, b, linkState, "linked-identity"); st != http.StatusSeeOther {
		t.Fatalf("control: a proper link flow answered %d %s", st, body)
	}
	idA := e.zCurrentSessionID(b)
	if got := e.zIdentityCount(t, b); got != 2 {
		t.Fatalf("control: after linking, %d identities, want 2", got)
	}

	// The attack shape: start a link flow as A, then sign a DIFFERENT account into
	// the same browser, then replay A's link callback.
	e.zSignInAs(b, "another-account")
	idB := e.zCurrentSessionID(b)
	if idB == idA {
		t.Fatalf("control: the sign-in did not change the subject")
	}
	stolen := e.zStartFlow(t, b, "link")
	// A later login overwrites the session's flow state, exactly as /auth does.
	e.zSignInAs(b, "third-account")
	idC := e.zCurrentSessionID(b)
	st, body := e.zFinishFlow(t, b, stolen, "hijacked-identity")
	t.Logf("replaying a superseded link callback (started by %s, session now %s) -> %d %s",
		idB, idC, st, body)
	if st == http.StatusSeeOther {
		t.Errorf("a superseded link callback still completed: the flow is not bound to the "+
			"account it was started for (%d %s)", st, body)
	}
	if got := e.zIdentityCount(t, b); got != 1 {
		t.Errorf("the %s session ended with %d identities, want 1 (nothing was linked)", idC, got)
	}
}

// --- helpers ------------------------------------------------------------------

func zIdentityIDs(export map[string]any) map[string]bool {
	out := map[string]bool{}
	items, _ := export["identities"].([]any)
	for _, raw := range items {
		if m, ok := raw.(map[string]any); ok {
			if id, ok := m["id"].(string); ok {
				out[id] = true
			}
		}
	}
	return out
}

func zHasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// zMeScopes reads the token's scope set off /v1/me, which is the surface a client
// actually sees.
func zMeScopes(t *testing.T, e *zAEnv, token string) []string {
	t.Helper()
	st, _, body := e.zGet("/v1/me", token)
	if st != http.StatusOK {
		t.Fatalf("/v1/me = %d %s", st, body)
	}
	raw, _ := zJSON(t, body)["scopes"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// zDeviceStartFull starts a device authorization and returns both codes.
func (e *zAEnv) zDeviceStartFull(t *testing.T, scope string) (userCode, deviceCode string) {
	t.Helper()
	status, body := e.zPostForm("/oauth/device_authorization",
		url.Values{"client_id": {zClientPublic}, "scope": {scope}}, "")
	if status != http.StatusOK {
		t.Fatalf("device_authorization = %d: %s", status, body)
	}
	var dev struct {
		UserCode   string `json:"user_code"`
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal(body, &dev); err != nil || dev.UserCode == "" || dev.DeviceCode == "" {
		t.Fatalf("no device codes: %s (%v)", body, err)
	}
	return dev.UserCode, dev.DeviceCode
}

// zDevicePoll is the RFC 8628 §3.4 device_code grant.
func (e *zAEnv) zDevicePoll(deviceCode string) (int, zATokens, []byte) {
	e.t.Helper()
	st, body := e.zPostForm("/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {zClientPublic},
	}, "")
	var tok zATokens
	_ = json.Unmarshal(body, &tok)
	return st, tok, body
}

// zStartFlow begins a login-plane flow and returns the state it stored.
func (e *zAEnv) zStartFlow(t *testing.T, b *http.Client, mode string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		e.srv.URL+"/auth/github/start?mode="+url.QueryEscape(mode)+"&return_to=%2F", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := e.zDo(b, req)
	loc := resp.Header.Get("Location")
	st, _, body := zDrain(t, resp)
	if st != http.StatusFound {
		t.Fatalf("flow start (%s) = %d %s", mode, st, body)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in %q", loc)
	}
	return state
}

// zFinishFlow redeems a state with an authorization code.
func (e *zAEnv) zFinishFlow(t *testing.T, b *http.Client, state, code string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		e.srv.URL+"/auth/github/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := e.zDo(b, req)
	st, _, body := zDrain(t, resp)
	return st, body
}

func (e *zAEnv) zIdentityCount(t *testing.T, b *http.Client) int {
	t.Helper()
	st, _, body := e.zGetBrowser(b, "/v1/identities")
	if st != http.StatusOK {
		t.Fatalf("/v1/identities = %d %s", st, body)
	}
	items, _ := zJSON(t, body)["data"].([]any)
	return len(items)
}

// e2SignIn signs a browser in through the real login plane.
func (e *zAStack) e2SignIn(env *zAEnv, b *http.Client, code string) {
	e.t.Helper()
	env.zSignInAs(b, code)
}

// zDropLast shortens an id by one byte, for the "prefix of a valid id" near miss.
func zDropLast(s string) string {
	if len(s) < 2 {
		return s + "z"
	}
	return s[:len(s)-1]
}

// zTokenString reads an access token out of a decoded token response.
func zTokenString(t *testing.T, tok map[string]any) string {
	t.Helper()
	at, _ := tok["access_token"].(string)
	if at == "" {
		t.Fatalf("no access_token in %v", tok)
	}
	return at
}

// keep the unused-import checker honest while the probe set evolves.
var (
	_ = oauth.ScopeAccountID
	_ = strings.TrimSpace
)
