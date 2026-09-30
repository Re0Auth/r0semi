//go:build audit5

package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func pkce(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// PROBE 9 — the redirect_uri gate is exact, and its refusals do not redirect.
//
// Both halves matter and they are different properties:
//
//   - exactness: Client.AllowsRedirect (oauth/client.go:159) is `r == uri`, and the
//     library's own check adds globs only for a client implementing
//     HasRedirectGlobs (op.ProviderClient does not), so no extension is accepted;
//   - the failure SHAPE: an unregistered redirect_uri must be answered with an
//     OAuth JSON error and NEVER with a redirect, or the OP becomes an open
//     redirector that also hands out error_description to arbitrary hosts
//     (internal/oidchttp/oidchttp.go validateAuthorize does this correctly, and
//     the check is what makes the later redirect-based refusals safe).
func TestProbeRedirectURIMustMatchExactlyAndRefusalsDoNotRedirect(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	const registered = "https://client.example/cb"

	base := func(redirect string) url.Values {
		return url.Values{
			"response_type":         {"code"},
			"client_id":             {e.webID},
			"redirect_uri":          {redirect},
			"scope":                 {"account.id"},
			"state":                 {"state-probe"},
			"code_challenge":        {pkce(strings.Repeat("v", 64))},
			"code_challenge_method": {"S256"},
		}
	}

	// Control: the registered URI is accepted (302 to the login plane).
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+base(registered).Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("control failed: the registered redirect_uri was refused: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?") {
		t.Fatalf("control failed: the registered redirect_uri did not reach the login plane: %q", loc)
	}

	extensions := map[string]string{
		"appended query":        registered + "?next=https://evil.example",
		"appended fragment":     registered + "#frag",
		"appended path":         registered + "/../evil",
		"trailing slash":        registered + "/",
		"prefix":                "https://client.example/c",
		"case-folded host":      "https://CLIENT.example/cb",
		"explicit default port": "https://client.example:443/cb",
		"other port":            "https://client.example:8443/cb",
		"scheme downgrade":      "http://client.example/cb",
		"userinfo at-sign":      "https://client.example@evil.example/cb",
		"percent-encoded path":  "https://client.example/%63b",
		"percent-encoded host":  "https://client%2eexample/cb",
		"doubled slash":         "https://client.example//cb",
		"backslash":             "https://client.example\\cb",
		"leading space":         " " + registered,
		"trailing space":        registered + " ",
		"newline suffix":        registered + "\n",
		"uppercase scheme":      "HTTPS://client.example/cb",
		"empty":                 "",
	}
	for name, redirect := range extensions {
		t.Run(name, func(t *testing.T) {
			resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+base(redirect).Encode())
			body := bodyOf(t, resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("redirect_uri %q was not refused with 400 (got %d, Location %q): %s",
					redirect, resp.StatusCode, resp.Header.Get("Location"), body)
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Fatalf("redirect_uri %q was answered with a redirect to %q: an unvalidated redirect", redirect, loc)
			}
		})
	}

	// The same exactness has to hold at the token endpoint, where the comparison is
	// against the value stored on the authorization request
	// (pkg/op/token_code.go ValidateAccessTokenRequest) rather than the registry.
	tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
	_ = tokens
	if status := exchangeWithRedirect(t, e, registered+"?x=1"); status == http.StatusOK {
		t.Fatal("the token endpoint accepted an extended redirect_uri")
	}
	if status := exchangeWithRedirect(t, e, registered); status != http.StatusOK {
		t.Fatalf("control failed: the exact redirect_uri was refused at the token endpoint: %d", status)
	}
}

// exchangeWithRedirect runs a fresh code flow and exchanges the code with the
// given redirect_uri, returning the token endpoint's status.
func exchangeWithRedirect(t *testing.T, e env, redirect string) int {
	t.Helper()
	verifier := strings.Repeat("r", 64)
	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {"account.id"},
		"state":                 {"state-probe"},
		"code_challenge":        {pkce(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+authz.Encode())
	login, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID: %q", resp.Header.Get("Location"))
	}
	if err := e.store.CompleteLogin(t.Context(), id, "usr_probe", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %s", cb)
	}
	_, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	return status
}

// PROBE 10 — the authorization code lifecycle: single use, bound to the client,
// to the redirect_uri, to the verifier and to the subject.
func TestProbeAuthorizationCodeLifecycle(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	const redirect = "https://client.example/cb"
	verifier := strings.Repeat("c", 64)

	issue := func(t *testing.T, scopes []string, subject string) string {
		t.Helper()
		authz := url.Values{
			"response_type":         {"code"},
			"client_id":             {e.webID},
			"redirect_uri":          {redirect},
			"scope":                 {strings.Join(scopes, " ")},
			"state":                 {"state-probe"},
			"code_challenge":        {pkce(verifier)},
			"code_challenge_method": {"S256"},
		}
		resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+authz.Encode())
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("authorize: %d %s", resp.StatusCode, bodyOf(t, resp))
		}
		login, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		id := login.Query().Get("authRequestID")
		if err := e.store.CompleteLogin(t.Context(), id, subject, scopes); err != nil {
			t.Fatal(err)
		}
		resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("callback: %d %s", resp.StatusCode, bodyOf(t, resp))
		}
		cb, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		code := cb.Query().Get("code")
		if code == "" {
			t.Fatalf("no code: %s", cb)
		}
		return code
	}

	// Control: a well-formed exchange works, so every refusal below is the check
	// and not a broken flow.
	good := issue(t, []string{"account.id", "offline_access"}, "usr_probe")
	first, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {good},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("control failed: a well-formed exchange was refused: %d %v", status, first)
	}

	// Replay: the same code again.
	if replay, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {good},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	}); status == http.StatusOK {
		t.Fatalf("the authorization code was replayed: %v", replay)
	}

	// Bound to the client: another registered confidential client with its OWN
	// correct secret cannot redeem it.
	other := issue(t, []string{"account.id"}, "usr_probe")
	if stolen, status := e.postToken(t, e.narrowID, e.narrowSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {other},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	}); status == http.StatusOK {
		t.Fatalf("a code issued to one client was redeemed by another: %v", stolen)
	}

	// Bound to the verifier: a wrong verifier must fail...
	wrong := issue(t, []string{"account.id"}, "usr_probe")
	if got, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {wrong},
		"redirect_uri":  {redirect},
		"code_verifier": {strings.Repeat("d", 64)},
	}); status != http.StatusBadRequest {
		t.Fatalf("a wrong code_verifier was accepted: %d %v", status, got)
	}
	// ...and no verifier at all must fail too. The library checks PKCE for every
	// client here (pkg/op/token_code.go AuthorizeCodeClient calls
	// AuthorizeCodeChallenge unconditionally), which is why this is a guard: the
	// sibling implementation LegacyServer.CodeExchange skips the check for a
	// confidential client, so the property depends on which registration path is
	// wired.
	none := issue(t, []string{"account.id"}, "usr_probe")
	if got, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {none},
		"redirect_uri": {redirect},
	}); status == http.StatusOK {
		t.Fatalf("a code was exchanged with no code_verifier at all: %v", got)
	}

	// This plane is the WRAPPED OP (internal/oidchttp over internal/store/memory's
	// OIDCStore), not the Upstream Kit engine: its op.Storage AuthRequestByCode is
	// a consume-on-read, so a failed exchange here still burns the code. That is
	// the OP's own fail-closed direction, and it is a different implementation
	// from the PUBLIC oauth library KIT-4 fixes — the kit's non-burn guard lives in
	// oauth/as_test.go and internal/zzprobe/protocol/kit. The guard below records
	// the OP's direction so a change in it is not mistaken for a regression here.
	burned := issue(t, []string{"account.id"}, "usr_probe")
	if got, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {burned},
		"redirect_uri":  {redirect},
		"code_verifier": {strings.Repeat("e", 64)},
	}); status == http.StatusOK {
		t.Fatalf("a wrong verifier was accepted: %v", got)
	}
	if got, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {burned},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	}); status == http.StatusOK {
		t.Fatalf("the code survived a failed exchange: %v", got)
	}
}

// PROBE 11 — the refresh grant cannot widen scope, by any spelling.
func TestProbeRefreshGrantCannotWidenScope(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "phigros.score.read", "offline_access"}))
	if tokens.RefreshToken == "" {
		t.Fatalf("no refresh token: %+v", tokens)
	}

	refresh := func(t *testing.T, extra url.Values) (map[string]any, int, string) {
		t.Helper()
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {tokens.RefreshToken},
		}
		for k, v := range extra {
			form[k] = v
		}
		resp, raw := e.postForm(t, "/oauth/token", form, e.webID, e.webSec)
		return decodeJSON(t, raw), resp.StatusCode, string(raw)
	}

	// Control: a subset refresh works and reports only what it asked for.
	got, status, raw := refresh(t, url.Values{"scope": {"account.id"}})
	if status != http.StatusOK {
		t.Fatalf("control failed: a narrowing refresh was refused: %d %s", status, raw)
	}
	if scope, _ := got["scope"].(string); scope != "account.id" {
		t.Fatalf("control failed: the narrowed scope is %q, want account.id", scope)
	}
	if _, ok := got["id_token"]; ok {
		t.Fatalf("a refresh without openid returned an id_token: %s", raw)
	}

	// Fresh tokens for the widening attempts: the narrowing refresh above rotated
	// the presented token, so each attempt needs its own.
	for name, scopes := range map[string]string{
		"unregistered scope":    "openid account.id phigros.score.read other.game.read",
		"comma separated":       "openid,account.id,phigros.score.read",
		"json-ish array":        `["openid","account.id"]`,
		"empty element":         "openid account.id ",
		"offline_access only":   "offline_access",
		"openid only":           "openid",
		"uppercase openid":      "OPENID account.id",
		"trailing newline":      "openid account.id\n",
		"tab separated":         "openid\taccount.id",
		"array-like scope[]":    "account.id",
		"duplicate in one list": "account.id account.id account.id",
	} {
		t.Run(name, func(t *testing.T) {
			fresh := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "offline_access"}))
			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {fresh.RefreshToken},
				"scope":         {scopes},
			}
			if name == "array-like scope[]" {
				form = url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {fresh.RefreshToken},
					"scope[]":       {scopes},
				}
			}
			resp, raw := e.postForm(t, "/oauth/token", form, e.webID, e.webSec)
			payload := decodeJSON(t, raw)
			if resp.StatusCode == http.StatusOK {
				// Succeeding is only acceptable when the granted set is a subset of
				// what the refresh token already carried.
				granted, _ := payload["scope"].(string)
				for _, s := range strings.Fields(granted) {
					if s != "openid" && s != "account.id" && s != "offline_access" {
						t.Fatalf("%s: the refresh widened the grant to %q: %s", name, granted, raw)
					}
				}
			}
		})
	}

	// Duplicate scope parameters are refused outright by the wrapper.
	fresh := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "offline_access"}))
	dupResp, dupRaw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {fresh.RefreshToken},
		"scope":         {"account.id", "phigros.score.read"},
	}, e.webID, e.webSec)
	if dupResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a duplicated scope parameter was accepted: %d %s", dupResp.StatusCode, dupRaw)
	}
}

// PROBE 12 — client authentication at the token endpoint: which of the advertised
// methods actually work, and what a missing or wrong secret does.
func TestProbeClientAuthenticationAtTheTokenEndpoint(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	fresh := func(t *testing.T) string {
		t.Helper()
		return asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"})).RefreshToken
	}

	// client_secret_basic, the fixture's normal path.
	if _, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {fresh(t)},
	}); status != http.StatusOK {
		t.Fatalf("control failed: client_secret_basic was refused: %d", status)
	}

	// client_secret_post: the discovery document advertises it for the token
	// endpoint (internal/oidchttp/oidchttp.go overrides), so it must work.
	resp, raw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {fresh(t)},
		"client_id": {e.webID}, "client_secret": {e.webSec},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("client_secret_post was refused at the token endpoint: %d %s", resp.StatusCode, raw)
	}

	// A confidential client with no secret, and with the wrong one.
	for name, basic := range map[string]struct{ id, secret string }{
		"no secret":    {e.webID, ""},
		"wrong secret": {e.webID, "definitely-not-it"},
	} {
		resp, raw := e.postForm(t, "/oauth/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {fresh(t)},
		}, basic.id, basic.secret)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("a confidential client with %s was answered %d: %s", name, resp.StatusCode, raw)
		}
	}

	// A confidential client that presents a secret in the body while Basic carries
	// another identity is the two-identity case, already pinned above.
	//
	// A PUBLIC client that presents an Authorization header at all: the library
	// reads the Basic identity as "authenticated" because
	// AuthorizeClientIDSecret returns nil for a non-confidential client
	// (internal/store/memory/oidc.go), and then refuses the device grant for it
	// (pkg/op/device.go wants authenticated == IsConfidentialType). Recording the
	// shape rather than asserting a fix: it is an interop trap, not an escalation.
	dev := asTokens(t, e.codeFlowAs(t, e.deviceID, "", "https://device.example/cb",
		[]string{"account.id"}, "usr_probe"))
	_ = dev
	resp, raw = e.postForm(t, "/oauth/device_authorization",
		url.Values{"scope": {"account.id"}}, e.deviceID, "anything")
	if resp.StatusCode == http.StatusOK {
		t.Logf("a public client authenticating with Basic was accepted by device_authorization")
	} else {
		t.Logf("a public client authenticating with Basic got %d: %s", resp.StatusCode, raw)
	}
}

// PROBE 13 — the device flow's anonymous and cross-client shapes.
func TestProbeDeviceFlowClientBinding(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	// No client_id at all: must not mint a device_code.
	resp, raw := e.postForm(t, "/oauth/device_authorization", url.Values{"scope": {"account.id"}}, "", "")
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("device_authorization without a client = %d %s", resp.StatusCode, raw)
	}

	// Control: the honest request works.
	resp, raw = e.postForm(t, "/oauth/device_authorization",
		url.Values{"client_id": {e.deviceID}, "scope": {"account.id"}}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control failed: %d %s", resp.StatusCode, raw)
	}
	issued := decodeJSON(t, raw)
	deviceCode, _ := issued["device_code"].(string)
	if deviceCode == "" {
		t.Fatalf("no device_code in %s", raw)
	}
	if userCode, _ := issued["user_code"].(string); userCode == "" {
		t.Fatalf("no user_code in %s", raw)
	}

	// Polling before approval is authorization_pending, not a token.
	poll := func(clientID string) (int, string) {
		t.Helper()
		r, body := e.postForm(t, "/oauth/token", url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
			"client_id":   {clientID},
		}, "", "")
		return r.StatusCode, string(body)
	}
	status, body := poll(e.deviceID)
	if status != http.StatusBadRequest || !strings.Contains(body, "authorization_pending") {
		t.Fatalf("an unapproved poll answered %d %s", status, body)
	}

	// Another client polling the same device_code must not learn anything or mint.
	status, body = poll(e.narrowID)
	if status == http.StatusOK {
		t.Fatalf("another client minted tokens from someone else's device_code: %s", body)
	}
	t.Logf("a foreign client polling the device_code got %d %s", status, body)

	// Polling again immediately is the RFC 8628 §3.5 throttle.
	status, body = poll(e.deviceID)
	if !strings.Contains(body, "slow_down") {
		t.Logf("the second immediate poll answered %d %s (slow_down is enforced in the store)", status, body)
	}
}

// PROBE 14 — the device flow's id_token is missing `sub` in exactly the same way
// as the code flow's (see PROBE 6), and the flow still hands it out.
func TestProbeDeviceFlowIDTokenIsAlsoMissingTheSubject(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	resp, raw := e.postForm(t, "/oauth/device_authorization", url.Values{
		"client_id": {e.deviceID},
		"scope":     {"openid account.id offline_access"},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization = %d %s", resp.StatusCode, raw)
	}
	issued := decodeJSON(t, raw)
	deviceCode, _ := issued["device_code"].(string)
	userCode, _ := issued["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_authorization answered %s", raw)
	}

	// The human approves, through the same store call the consent route makes.
	if err := e.store.ApproveDevice(t.Context(), userCode, "usr_probe", nil); err != nil {
		t.Fatalf("approval: %v", err)
	}

	pollResp, pollRaw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {e.deviceID},
	}, "", "")
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("device poll = %d %s", pollResp.StatusCode, pollRaw)
	}
	tokens := asTokens(t, decodeJSON(t, pollRaw))
	if tokens.IDToken == "" {
		t.Fatalf("the device grant issued no id_token: %s", pollRaw)
	}
	claims := idTokenClaims(t, tokens.IDToken)
	if _, ok := claims["sub"]; !ok {
		t.Errorf("the device flow's id_token has no `sub` either (claims: %v)", keysOf(claims))
	}

	// And the device id_token is a bearer token at userinfo, like any other JWS.
	req, err := http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokens.IDToken)
	uiResp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("userinfo with the device id_token: %d %s", uiResp.StatusCode, bodyOf(t, uiResp))
}
