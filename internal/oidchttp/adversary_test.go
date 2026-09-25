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
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// logCapture keeps every record written to the default logger as rendered text,
// so a test can assert over the whole line rather than over the fields it
// remembered to check.
type logCapture struct {
	mu   sync.Mutex
	text strings.Builder
}

func (h *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slog.NewTextHandler(&h.text, nil).Handle(context.Background(), r)
}

func (h *logCapture) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logCapture) WithGroup(string) slog.Handler      { return h }

func (h *logCapture) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.text.String()
}

// captureDefaultLog swaps the process default logger for a capturing one and
// restores it afterwards. This package has no parallel tests, so the swap is safe.
func captureDefaultLog(t *testing.T) *logCapture {
	t.Helper()
	cap := &logCapture{}
	prev := slog.Default()
	slog.SetDefault(slog.New(cap))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return cap
}

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

// The library registers protocol endpoints without a method constraint, so a
// GET used to be a working exchange and put codes/tokens into URLs. These
// endpoints are now POST-only per their RFCs; a GET is refused before any
// pre-flight or handler can see it.
func TestAdversarialDeviceAuthorizationRejectsGET(t *testing.T) {
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
	if body := adversaryBody(t, resp); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET device_authorization = %d, want 405: %s", resp.StatusCode, body)
	} else if !strings.Contains(string(body), `"error"`) {
		t.Fatalf("GET device_authorization refusal is not an OAuth error body: %s", body)
	}
}

// A GET to the token endpoint must not exchange a code at all. Before this
// guard the library accepted it and the code ended up in the URL/logs.
func TestAdversarialTokenEndpointRejectsGET(t *testing.T) {
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
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /oauth/token = %d, want 405: %s", getResp.StatusCode, getBody)
	}
	if strings.Contains(string(getBody), "access_token") || strings.Contains(string(getBody), "refresh_token") {
		t.Fatalf("GET /oauth/token returned a token: %s", getBody)
	}
}

// Introspection and revocation are POST-only too, for the same reason: the token
// under inspection must not be carried in a URL.
func TestAdversarialIntrospectionAndRevocationRejectGET(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/oauth/introspect", "/oauth/revoke"} {
		resp, err := http.Get(f.server.URL + path + "?token=secret-token")
		if err != nil {
			t.Fatal(err)
		}
		body := adversaryBody(t, resp)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d, want 405: %s", path, resp.StatusCode, body)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("GET %s refusal is not JSON: %s", path, body)
		}
		if _, ok := payload["error"].(string); !ok {
			t.Fatalf("GET %s refusal is not an OAuth error: %s", path, body)
		}
	}
}

// RFC 6749 §3.1 forbids repeated request parameters. The library's decoder
// takes the last value, so a duplicate let validation and use disagree.
func TestAdversarialDuplicateParametersAreRejected(t *testing.T) {
	f := newFixture(t)
	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Duplicate client_id on the authorize entrance.
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.webID, f.deviceID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {"account.id"},
		"state":                 {"st"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+q.Encode())
	body := adversaryBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate client_id = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "error") {
		t.Fatalf("duplicate refusal is not an OAuth error: %s", body)
	}

	// Duplicate code on the token endpoint.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"one", "two"},
		"client_id":     {f.webID},
		"client_secret": {"s3cret"},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {verifier},
	}
	resp, err := http.PostForm(f.server.URL+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	body = adversaryBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate code = %d, want 400: %s", resp.StatusCode, body)
	}
}

// RFC 7636 §4.1/§4.2: challenge and verifier are 43–128 unreserved characters.
// The library only compares hashes, so a malformed value was accepted and stored.
func TestAdversarialMalformedPKCEValuesAreRejected(t *testing.T) {
	f := newFixture(t)

	// A 42-character challenge is one short of the minimum.
	short := strings.Repeat("c", 42)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {"account.id"},
		"state":                 {"st"},
		"code_challenge":        {short},
		"code_challenge_method": {"S256"},
	}
	resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		body := adversaryBody(t, resp)
		t.Fatalf("authorize status = %d, want 302: %s", resp.StatusCode, body)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("malformed challenge was accepted: %s", loc)
	}

	// A malformed verifier is refused before the exchange is attempted.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"anything"},
		"client_id":     {f.webID},
		"client_secret": {"s3cret"},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {"too-short"},
	}
	tokenResp, err := http.PostForm(f.server.URL+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	body := adversaryBody(t, tokenResp)
	if tokenResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed verifier status = %d, want 400: %s", tokenResp.StatusCode, body)
	}
	if !strings.Contains(string(body), "code_verifier") {
		t.Fatalf("refusal does not name the verifier: %s", body)
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
		"code_challenge":        {strings.Repeat("c", 43)},
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

// Round 4, audit-3's A3-4 hypothesis — now CONFIRMED and fixed.
//
// The device pre-flight must validate the client the library will actually bill.
// The wrapper read `client_id` from the FORM and only fell back to Basic, while
// the library does the reverse (pkg/op/client.go ClientIDFromRequest) and ignores
// the form's value outright whenever Basic is present. So a confidential client
// registered for one narrow scope could name a BROADER client in the body,
// authenticate as itself with Basic, sail through this wrapper's scope check, and
// be issued a device code for a scope it was never registered for. Round 4 took
// that all the way to a live access token.
//
// A single-identity probe cannot see this: both existing device guards used one
// client, which is why the mismatch survived two rounds.
func TestAdversarialDeviceAuthorizationRefusesTwoClientIdentities(t *testing.T) {
	f := newFixture(t)

	deviceRequest := func(t *testing.T, form url.Values, basicID, basicSecret string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, f.server.URL+"/oauth/device_authorization",
			strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basicID != "" {
			req.SetBasicAuth(basicID, basicSecret)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp, adversaryBody(t, resp)
	}

	// The escalation: the narrow confidential client names the broad client in the
	// body and asks for the broad client's scope. Before the fix this answered 200
	// with a device_code, because the wrapper checked the named client and the
	// library billed the authenticated one.
	resp, body := deviceRequest(t,
		url.Values{"client_id": {f.webID}, "scope": {"phigros.score.read"}},
		f.narrowID, "nsecret")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a narrow confidential client obtained a device authorization for another client's scope: %d %s",
			resp.StatusCode, body)
	}

	// Even a scope the authenticated client IS registered for is refused, because
	// the request claims two identities and preferring either is how the mismatch
	// stayed invisible. This is the assertion that pins the rule rather than the
	// symptom.
	resp, body = deviceRequest(t,
		url.Values{"client_id": {f.webID}, "scope": {"account.id"}},
		f.narrowID, "nsecret")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a device request naming two different clients was accepted: %d %s", resp.StatusCode, body)
	}

	// The honest paths still work: Basic alone, and the form alone for a public
	// client. A fix that refused these would be a different bug.
	resp, body = deviceRequest(t, url.Values{"scope": {"account.id"}}, f.narrowID, "nsecret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a confidential client authenticating with Basic alone was refused: %d %s", resp.StatusCode, body)
	}
	resp, body = deviceRequest(t, url.Values{"client_id": {f.deviceID}, "scope": {"account.id"}}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a public client naming itself in the body was refused: %d %s", resp.StatusCode, body)
	}
}

// Round 4, the seam round 3 named as unaudited: the third-party library logs
// through the process's DEFAULT slog handler, which this binary configures.
//
// Enumerating what it writes (zitadel/oidc v3.51.3):
//
//   - pkg/op/error.go logs `oidc_error`, whose LogValue (pkg/oidc/error.go)
//     includes `description` and the whole `parent` chain. On the paths this
//     wrapper uses, `DefaultToServerError(err, err.Error())` sets that description
//     to the error text the storage returned — so the log carries whatever this
//     service puts in an error, verbatim.
//   - pkg/oidc/authorization.go LogValue logs scopes, response_type, client_id and
//     redirect_uri, and NOT code_challenge or state.
//
// Neither is a defect in itself. What it means is that the invariant "no error
// string may contain a credential" now protects the log as well as the wire, and
// that is exactly the kind of reasoning that belongs in a test rather than in a
// paragraph.
func TestAdversarialProtocolErrorsDoNotLogCredentials(t *testing.T) {
	f := newFixture(t)

	// Distinctive, so a hit in the log can only be the value fed in below.
	const codeSecret = "SECRET-AUTHZ-CODE-0001"
	const refreshSecret = "SECRET-REFRESH-0002"
	const bearerSecret = "SECRET-BEARER-0003"

	cap := captureDefaultLog(t)

	postForm := func(path string, form url.Values) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, f.server.URL+path, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = adversaryBody(t, resp)
	}

	// Each credential through the endpoint that consumes it.
	postForm("/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {codeSecret},
		"client_id": {f.webID}, "client_secret": {"s3cret"},
		"redirect_uri": {"https://client.example/cb"},
	})
	postForm("/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshSecret},
		"client_id": {f.webID}, "client_secret": {"s3cret"},
	})
	postForm("/oauth/introspect", url.Values{
		"token": {bearerSecret}, "client_id": {f.webID}, "client_secret": {"s3cret"},
	})
	postForm("/oauth/revoke", url.Values{
		"token": {bearerSecret}, "client_id": {f.webID}, "client_secret": {"s3cret"},
	})
	// A device poll too: the record lookup is the one that takes the code.
	postForm("/oauth/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {codeSecret},
		"client_id": {f.deviceID},
	})

	logged := cap.String()
	if strings.TrimSpace(logged) == "" {
		t.Fatal("nothing was logged, so this guard would pass vacuously")
	}
	for _, secret := range []string{codeSecret, refreshSecret, bearerSecret, "s3cret"} {
		if strings.Contains(logged, secret) {
			t.Errorf("a credential reached the log (%q):\n%s", secret, logged)
		}
	}
}
