//go:build audit6

// Zone-01 regression and hardening probes: the round-5 fixes that must still
// hold (P0-1 sub, P0-5 parameter parsing, P2-24 prompt=none, the redirect
// exact-match), plus the attack variants round 5 did not try. Everything in
// this file is expected to stay GREEN unless a fix regressed — these are the
// "probed and held" results for the report.
package z01protocolauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// P0-1 regression · the id_token carries sub on every issuing path the zone
// owns: the authorization-code grant and the device grant.
func TestRegressionIDTokenSubjectOnCodeAndDeviceGrants(t *testing.T) {
	e := newPlane(t, planeOptions{})

	_, idToken := e.codeFlow(t, []string{"openid", "account.id"}, nil)
	claims := idTokenClaims(t, idToken)
	if sub, _ := claims["sub"].(string); sub != "usr_z01" {
		t.Errorf("code-flow id_token sub = %q, want usr_z01 (P0-1 regressed)", sub)
	}

	// Device grant.
	deviceCode, userCode := e.deviceAuth(t, e.deviceID, "", "", []string{"openid", "account.id"})
	e.approveDevice(t, userCode)
	resp, body, raw := e.pollDevice(t, deviceCode, "", "", url.Values{"client_id": {e.deviceID}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device poll = %d %s", resp.StatusCode, raw)
	}
	devIDToken, _ := body["id_token"].(string)
	if devIDToken == "" {
		t.Fatal("device grant issued no id_token despite the openid scope")
	}
	claims = idTokenClaims(t, devIDToken)
	if sub, _ := claims["sub"].(string); sub != "usr_z01" {
		t.Errorf("device-grant id_token sub = %q, want usr_z01 (P0-1 regressed)", sub)
	}
}

// P0-5 regression · malformed parameter sets are refused on every endpoint,
// not silently re-read with a different view. Round 5 broke this with an
// unparsable body; these are the variants it did not try.
func TestRegressionMalformedParameterSetsAreRefused(t *testing.T) {
	e := newPlane(t, planeOptions{})

	// A charset-suffixed content type is still form data — the body must be
	// parsed, and an unparsable one refused.
	req, _ := http.NewRequest(http.MethodPost, e.server.URL+"/oauth/token",
		strings.NewReader("x=%zz&grant_type=authorization_code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw := e.body(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unparsable body with charset content type = %d %s, want 400 (P0-5 regressed)",
			resp.StatusCode, raw)
	}

	// A multipart body is not form data: ParseForm leaves the parameter set
	// empty, and every gate must see exactly that (fail closed).
	mp := strings.NewReader("--b\r\nContent-Disposition: form-data; name=\"grant_type\"\r\n\r\nauthorization_code\r\n--b--\r\n")
	req, _ = http.NewRequest(http.MethodPost, e.server.URL+"/oauth/token", mp)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw = e.body(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("multipart parameter smuggling = %d %s, want a refused request (grant_type must not be read)",
			resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), "access_token") {
		t.Errorf("multipart body minted a token: %s", raw)
	}

	// Repeated parameters, in both spellings the entrance accepts.
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.deviceID},
		"redirect_uri":          {"https://device.example/cb"},
		"state":                 {"st"},
		"code_challenge":        {pkceChallenge(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
	}
	dup := url.Values{}
	for k, v := range q {
		dup[k] = v
	}
	dup["scope"] = []string{"openid", "account.id"} // ?scope=openid&scope=account.id
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+dup.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("repeated scope parameter = %d, want 400 (P0-5 regressed)", resp.StatusCode)
	}
	e.body(t, resp)

	// POST authorize with the scope in the query string AND the body.
	body := url.Values{}
	for k, v := range q {
		body[k] = v
	}
	body.Set("scope", "account.id")
	req, _ = http.NewRequest(http.MethodPost,
		e.server.URL+"/oauth/authorize?scope=openid", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("scope split across query and body = %d, want 400 (repeated parameter)",
			resp.StatusCode)
	}
	e.body(t, resp)
}

// P2-24 regression · prompt=none without a session answers login_required
// through the redirect, with iss, and never touches the interactive plane.
func TestRegressionPromptNoneWithoutASession(t *testing.T) {
	e := newPlane(t, planeOptions{})
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {"account.id"},
		"state":                 {"st-none"},
		"code_challenge":        {pkceChallenge(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
		"prompt":                {"none"},
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("prompt=none = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != "client.example" || loc.Query().Get("error") != "login_required" {
		t.Errorf("prompt=none redirected to %s (P2-24 regressed)", loc)
	}
	if loc.Query().Get("iss") == "" {
		t.Errorf("the login_required refusal carries no iss")
	}

	// prompt=none combined with another value is refused, in both spellings
	// the parameter parser accepts.
	for _, prompt := range []string{"none login", "login none"} {
		q.Set("prompt", prompt)
		resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("prompt=%q = %d", prompt, resp.StatusCode)
		}
		loc, _ = url.Parse(resp.Header.Get("Location"))
		if loc.Query().Get("error") != "invalid_request" {
			t.Errorf("prompt=%q answered error=%q, want invalid_request", prompt, loc.Query().Get("error"))
		}
		e.body(t, resp)
	}
}

// redirect variants round 5 did not try. The exact-match guard must refuse
// every one of them without redirecting (no open redirect, no confusion).
func TestRegressionRedirectURIVariantsAreRefused(t *testing.T) {
	e := newPlane(t, planeOptions{})
	verifier := strings.Repeat("v", 64)

	variants := []string{
		// scheme and host spellings
		"HTTPS://client.example/cb",
		"https://CLIENT.example/cb",
		"https://client.example:443/cb",          // default port equivalence
		"https://clie%6Et.example/cb",            // percent-encoded host
		"https://xn--lient.example/cb",           // punycode lookalike
		"https://cliënt.example/cb",              // IDN lookalike
		"//client.example/cb",                    // scheme-relative
		"https://client.example@evil.example/cb", // userinfo
		"https://[::1]/cb",                       // IPv6 literal
		// path spellings
		"https://client.example/cb/",
		"https://client.example//cb",
		"https://client.example/cb\\..\\..\\evil",
		"https://client.example/cb%2F..%2Fcb",
		"https://client.example/cb%0A",
		"https://client.example/cb%09",
		// query and fragment
		"https://client.example/cb?x=1",
		"https://client.example/cb#f",
		"https://client.example/cb;",
		// plain downgrade of a https registration
		"http://client.example/cb",
	}
	for _, variant := range variants {
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {e.webID},
			"redirect_uri":          {variant},
			"scope":                 {"account.id"},
			"state":                 {"st-redirect"},
			"code_challenge":        {pkceChallenge(verifier)},
			"code_challenge_method": {"S256"},
		}
		resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
		raw := e.body(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("redirect_uri %q = %d %s, want 400", variant, resp.StatusCode, raw)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Errorf("redirect_uri %q was answered with a redirect to %q — the refusal must not redirect",
				variant, loc)
		}
	}
}

// PKCE entrance and exchange syntax: S256 only, 43–128 unreserved characters,
// refused through the validated redirect, and a malformed verifier refused at
// the token endpoint before anything is hashed.
func TestRegressionPKCESyntaxAndMethod(t *testing.T) {
	e := newPlane(t, planeOptions{})

	authorize := func(challenge, method string) (*http.Response, string) {
		q := url.Values{
			"response_type":  {"code"},
			"client_id":      {e.webID},
			"redirect_uri":   {"https://client.example/cb"},
			"scope":          {"account.id"},
			"state":          {"st-pkce"},
			"code_challenge": {challenge},
		}
		if method != "" {
			q.Set("code_challenge_method", method)
		}
		resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
		return resp, resp.Header.Get("Location")
	}

	for _, tc := range []struct {
		name, challenge, method string
		wantError               string
	}{
		{"plain method", pkceChallenge(strings.Repeat("v", 64)), "plain", "invalid_request"},
		{"missing method", pkceChallenge(strings.Repeat("v", 64)), "", "invalid_request"},
		{"short challenge", strings.Repeat("a", 42), "S256", "invalid_request"},
		{"long challenge", strings.Repeat("a", 129), "S256", "invalid_request"},
		{"bad charset", strings.Repeat("+", 43), "S256", "invalid_request"},
		{"unicode charset", strings.Repeat("é", 43), "S256", "invalid_request"},
	} {
		resp, loc := authorize(tc.challenge, tc.method)
		if resp.StatusCode != http.StatusFound {
			t.Errorf("%s: authorize = %d %s", tc.name, resp.StatusCode, e.body(t, resp))
			continue
		}
		parsed, _ := url.Parse(loc)
		if got := parsed.Query().Get("error"); got != tc.wantError {
			t.Errorf("%s: error = %q (loc %s), want %q", tc.name, got, loc, tc.wantError)
		}
		if parsed.Host != "client.example" {
			t.Errorf("%s: refusal redirected to %q", tc.name, loc)
		}
	}

	// Malformed verifier at the exchange: refused as a request error, not
	// hashed and compared.
	resp, raw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {strings.Repeat("+", 43)},
	}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed code_verifier = %d %s, want 400", resp.StatusCode, raw)
	}
}

// The authorization code is bound to client + redirect + verifier. This is the
// WRAPPED OP plane (internal/oidchttp over the OP store), whose AuthRequestByCode
// is a consume-on-read, so an error path burns the code here (single-use holds
// even when the exchange fails). That is the OP's fail-closed direction and a
// different implementation from the Upstream Kit's oauth library, whose KIT-4 fix
// makes a failed binding cost nothing; the kit's guard is in
// internal/zzprobe/protocol/kit TestC1/C2 and oauth/as_test.go.
func TestRegressionCodeBindingAndSingleUseOnFailure(t *testing.T) {
	e := newPlane(t, planeOptions{})

	// Complete a consent by hand so we hold a code.
	verifier := strings.Repeat("v", 64)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {"openid account.id"},
		"state":                 {"st-code"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	login, _ := url.Parse(resp.Header.Get("Location"))
	id := login.Query().Get("authRequestID")
	if err := e.store.CompleteLogin(t.Context(), id, "usr_z01", []string{"openid", "account.id"}); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	cb, _ := url.Parse(resp.Header.Get("Location"))
	code := cb.Query().Get("code")

	// Another client's exchange is refused…
	resp2, raw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {verifier},
	}, e.deviceID, "")
	if resp2.StatusCode == http.StatusOK {
		t.Fatalf("a public client exchanged another client's code: %s", raw)
	}
	// …and burned it: the right exchange now fails too.
	resp3, raw3 := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {verifier},
	}, e.webID, e.webSec)
	if resp3.StatusCode == http.StatusOK {
		t.Fatalf("the code survived a failed exchange: %s", raw3)
	}
	if !strings.Contains(string(raw3), "invalid_grant") {
		t.Logf("second exchange answered %d %s", resp3.StatusCode, raw3)
	}
}

// The `request` parameter is refused through the redirect; `request_uri` is
// never fetched (no SSRF surface) and the request proceeds on its own
// parameters.
func TestRegressionRequestParamIsRefusedAndRequestURIIsNeverFetched(t *testing.T) {
	e := newPlane(t, planeOptions{})

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {"account.id"},
		"state":                 {"st-req"},
		"code_challenge":        {pkceChallenge(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
		"request":               {"eyJhbGciOiJub25lIn0.e30."},
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("request param = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if got := loc.Query().Get("error"); got != "request_not_supported" {
		t.Errorf("request param error = %q (loc %s), want request_not_supported", got, loc)
	}

	// request_uri points at a host that does not exist; if anything fetched it
	// the request would fail. It must simply be ignored (no fetch, no error
	// about the unresolvable host) and the flow must continue on its own
	// parameters.
	q.Del("request")
	q.Set("request_uri", "https://no-such-host-z01.invalid/req.jwt")
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("request_uri = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "authRequestID=") {
		t.Errorf("request_uri was not silently ignored: %q", loc)
	}
}

// Repeated scope values inside one parameter are harmless (no widening, no
// error), and the flow completes with the granted set.
func TestRegressionRepeatedScopeValuesInsideOneParameter(t *testing.T) {
	e := newPlane(t, planeOptions{})
	tokens, _ := e.codeFlow(t, []string{"openid", "openid", "account.id"}, nil)
	scope, _ := tokens["scope"].(string)
	if !strings.Contains(scope, "account.id") {
		t.Fatalf("repeated intra-parameter scopes broke the flow: %v", tokens)
	}
	t.Logf("scope=%q", scope)
}

// 01-7 · The id_token issued by the refresh grant carries no nonce. OIDC Core
// §12.2: "If an ID Token is returned as a result of a token refresh request,
// … its nonce Claim Value MUST be the same as it was in the ID Token issued
// when the original authentication occurred." The refresh path's request type
// (oidcstore.RefreshRequest) has no nonce, and neither store persists one, so
// every refreshed id_token drops the claim an RP may be keying on.
func TestProbeRefreshedIDTokenLosesTheNonce(t *testing.T) {
	e := newPlane(t, planeOptions{})

	tokens, idToken := e.codeFlow(t, []string{"openid", "account.id"}, nil)
	claims := idTokenClaims(t, idToken)
	nonce, _ := claims["nonce"].(string)
	if nonce != "nonce-z01" {
		t.Fatalf("the code-flow id_token lost its nonce before the probe could start: %v", claims)
	}

	refresh, _ := tokens["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("the flow issued no refresh token (offline_access re-attach broken)")
	}
	resp, raw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh = %d %s", resp.StatusCode, raw)
	}
	out := decodeJSON(t, raw)
	newIDToken, _ := out["id_token"].(string)
	if newIDToken == "" {
		t.Fatal("the refresh grant issued no id_token despite the openid scope")
	}
	newClaims := idTokenClaims(t, newIDToken)
	if newNonce, _ := newClaims["nonce"].(string); newNonce != nonce {
		t.Errorf("the refreshed id_token dropped the nonce (got %q, want %q): OIDC Core §12.2 "+
			"requires the refreshed ID Token to carry the original nonce, and an RP that checks it "+
			"breaks on every refresh", newNonce, nonce)
	}
}
