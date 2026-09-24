package oidchttp

// Adversarial guards for the seam between the third-party OpenID Provider library
// and this wrapper (round 3, area 1). Each test names the finding it pins; it
// failed before the fix and passes after, so it guards the fix the way any other
// test guards its subject.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

func adversaryBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func adversaryPost(t *testing.T, f fixture, path string, form url.Values) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return noRedirect.Do(req)
}

// adversaryCode drives a full authorize round trip and returns the code, so the
// token-endpoint probes below exercise a real exchange rather than a stub.
func adversaryCode(t *testing.T, f fixture, scopes []string, challenge string) string {
	t.Helper()
	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"state-1234567890"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatal("authorize ->", resp.StatusCode)
	}
	login, _ := url.Parse(resp.Header.Get("Location"))
	id := login.Query().Get("authRequestID")
	if len(id) == 0 {
		t.Fatal("no authRequestID in ", resp.Header.Get("Location"))
	}
	if err := f.store.CompleteLogin(context.Background(), id, "usr_1", scopes); err != nil {
		t.Fatal(err)
	}
	resp = get(t, noRedirect, f.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	if resp.StatusCode != http.StatusFound {
		t.Fatal("callback ->", resp.StatusCode)
	}
	cb, _ := url.Parse(resp.Header.Get("Location"))
	code := cb.Query().Get("code")
	if len(code) == 0 {
		t.Fatal("no code in ", cb.String())
	}
	return code
}

// The library registers the device endpoint with no method constraint and reads
// `r.Form`, so a pre-flight that only ran for POST was not a gate: a GET minted a
// device authorization for a scope the client was never registered for. After the
// fix both methods must be refused.
func TestAdversarialDeviceAuthorizationPrecheckIsMethodIndependent(t *testing.T) {
	f := newFixture(t)
	form := url.Values{
		"client_id": {f.deviceID},
		"scope":     {"phigros.score.read"}, // registered to the web client only
	}

	resp, err := http.PostForm(f.server.URL+"/oauth/device_authorization", form)
	if err != nil {
		t.Fatal(err)
	}
	if body := adversaryBody(t, resp); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST device_authorization with an unregistered scope = %d, want 400: %s",
			resp.StatusCode, body)
	}

	resp, err = http.Get(f.server.URL + "/oauth/device_authorization?" + form.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if body := adversaryBody(t, resp); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET device_authorization minted an authorization for an unregistered scope: %d %s",
			resp.StatusCode, body)
	}
}

// The token response contract (no `id_token` without `openid`; `Cache-Control:
// no-store`) was applied only on POST, while the library accepts the exchange on
// any method. A GET response must be sanitized exactly like a POST one.
func TestAdversarialTokenEndpointContractIsMethodIndependent(t *testing.T) {
	f := newFixture(t)
	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	scopes := []string{"account.id"} // no openid: no id_token is permitted

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {adversaryCode(t, f, scopes, challenge)},
		"client_id":     {f.webID},
		"client_secret": {"s3cret"},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {verifier},
	}

	postResp, err := http.PostForm(f.server.URL+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	postBody := adversaryBody(t, postResp)
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/token = %d: %s", postResp.StatusCode, postBody)
	}
	if postResp.Header.Get("Cache-Control") != "no-store" {
		t.Error("POST /oauth/token is missing Cache-Control: no-store")
	}

	form.Set("code", adversaryCode(t, f, scopes, challenge))
	getResp, err := http.Get(f.server.URL + "/oauth/token?" + form.Encode())
	if err != nil {
		t.Fatal(err)
	}
	getBody := adversaryBody(t, getResp)
	if getResp.StatusCode != http.StatusOK {
		// A refusal is also safe; only a successful-but-unsanitized response is a
		// hole.
		t.Logf("GET /oauth/token refused with %d: %s", getResp.StatusCode, getBody)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(getBody, &payload); err != nil {
		t.Fatalf("GET /oauth/token returned non-JSON: %s", getBody)
	}
	if _, ok := payload["id_token"]; ok {
		t.Fatalf("GET /oauth/token returned an id_token without the openid scope: %s", getBody)
	}
	if getResp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("GET /oauth/token returned a token without Cache-Control: no-store: %v", getResp.Header)
	}
}

// A protected resource's 401 must carry an RFC 6750 Bearer challenge, so a
// standard RP can tell "this token is bad, refresh it" from a transport error.
// userinfo is such a resource; neither the library nor this package's client-auth
// 401 writer produced the right challenge.
func TestAdversarialUserinfoUnauthorizedCarriesABearerChallenge(t *testing.T) {
	f := newFixture(t)
	resp := get(t, noRedirect, f.server.URL+"/oauth/userinfo")
	body := adversaryBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo without a token = %d, want 401: %s", resp.StatusCode, body)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Bearer") || !strings.Contains(challenge, `error="invalid_token"`) {
		t.Fatalf("userinfo 401 challenge = %q, want a Bearer challenge with error=\"invalid_token\"", challenge)
	}
}

// Without Clients and Registry every pre-flight this wrapper adds is disabled and
// the request falls through to the library's unguarded defaults. That is a
// fail-open configuration, so New refuses it rather than building a plane that
// silently checks nothing.
func TestAdversarialNewRequiresClientsAndRegistry(t *testing.T) {
	f := newFixture(t)
	base := Config{
		Issuer:        "https://issuer.test",
		Storage:       f.store,
		CryptoKey:     [32]byte{1, 2, 3},
		CryptoKeyID:   "test",
		AllowInsecure: true,
	}
	if _, err := New(base); err == nil {
		t.Fatal("New accepted a config without Clients/Registry: the pre-flights would be disabled")
	}
	base.Clients = oauth.NewMemoryClientRegistry()
	base.Registry = oauth.DefaultRegistry()
	if _, err := New(base); err != nil {
		t.Fatalf("New refused a complete config: %v", err)
	}
}

// TestSeamProbesHeld records the seam probes that did not break, so a later pass
// does not repeat them. It is a guard, not a formality: each assertion is one a
// regression would flip.
func TestSeamProbesHeld(t *testing.T) {
	f := newFixture(t)

	// POST /oauth/authorize is pre-flighted (the round-2 fix) — the scope gate.
	resp, err := adversaryPost(t, f, "/oauth/authorize", url.Values{
		"response_type":         {"code"},
		"client_id":             {f.deviceID},
		"redirect_uri":          {"https://device.example/cb"},
		"scope":                 {"phigros.score.read"},
		"code_challenge":        {"c"},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	loc := resp.Header.Get("Location")
	body := adversaryBody(t, resp)
	if resp.StatusCode != http.StatusFound || !strings.Contains(loc, "error=invalid_scope") {
		t.Fatalf("POST /oauth/authorize bypassed the scope pre-flight: %d %s %s", resp.StatusCode, loc, body)
	}

	// ...and the PKCE gate, for a confidential client.
	resp, err = adversaryPost(t, f, "/oauth/authorize", url.Values{
		"response_type": {"code"},
		"client_id":     {f.webID},
		"redirect_uri":  {"https://client.example/cb"},
		"scope":         {"account.id"},
		"state":         {"s2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	loc = resp.Header.Get("Location")
	body = adversaryBody(t, resp)
	if resp.StatusCode != http.StatusFound || !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("POST /oauth/authorize accepted a request with no code_challenge: %d %s %s", resp.StatusCode, loc, body)
	}

	// Discovery: both documents agree and neither advertises end_session (O-9).
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		r := get(t, noRedirect, f.server.URL+path)
		b := adversaryBody(t, r)
		var js map[string]any
		if err := json.Unmarshal(b, &js); err != nil {
			t.Fatalf("discovery is not JSON at %s: %s", path, b)
		}
		if _, ok := js["end_session_endpoint"]; ok {
			t.Fatalf("discovery still advertises end_session at %s", path)
		}
	}

	// Protocol-plane failures keep the OAuth shape even where the library writes
	// plain text.
	for _, path := range []string{"/oauth/introspect", "/oauth/revoke"} {
		r, err := http.PostForm(f.server.URL+path, url.Values{"token": {"x"}})
		if err != nil {
			t.Fatal(err)
		}
		b := adversaryBody(t, r)
		if r.StatusCode >= 400 {
			var js map[string]any
			if err := json.Unmarshal(b, &js); err != nil {
				t.Fatalf("%s answered a non-JSON failure: %d %s", path, r.StatusCode, b)
			}
			if _, ok := js["error"].(string); !ok {
				t.Fatalf("%s answered a failure outside the protocol plane shape: %s", path, b)
			}
		}
	}
}
