package oidchttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func randSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type fixture struct {
	server   *httptest.Server
	handler  *Handler
	store    *memory.OIDCStore
	webID    string
	deviceID string
	// narrowID is a CONFIDENTIAL client registered for one narrow scope. Audit-3
	// named its absence as the reason the device-flow client-identity hypothesis
	// could not be reproduced; round 4 needed exactly this shape.
	narrowID string
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	ctx := context.Background()

	suffix := randSuffix()
	webID, deviceID := "http-web-"+suffix, "http-device-"+suffix
	narrowID := "http-narrow-" + suffix

	clients := oauth.NewMemoryClientRegistry()
	web, err := oauth.NewClient(webID, "Web", oauth.ClientConfidential, "s3cret",
		[]string{"https://client.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	device, err := oauth.NewClient(deviceID, "Device", oauth.ClientPublic, "",
		[]string{"https://device.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := oauth.NewClient(narrowID, "Narrow", oauth.ClientConfidential, "nsecret",
		[]string{"https://narrow.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []oauth.Client{web, device, narrow} {
		if err := clients.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("http-test", key),
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("0123456789abcdef0123456789abcdef"))

	var scopes []string
	for _, d := range oauth.DefaultDescriptors() {
		scopes = append(scopes, d.Scope.String())
	}

	handler, err := New(Config{
		Storage:       store,
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "test",
		Scopes:        scopes,
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return fixture{server: srv, handler: handler, store: store, webID: webID, deviceID: deviceID, narrowID: narrowID}
}

func get(t testing.TB, client *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return resp
}

func postToken(t testing.TB, srv, clientID, secret string, form url.Values) (map[string]any, int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(clientID, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return out, resp.StatusCode
}

// codeFlow runs authorize -> login+consent -> callback -> token.
func codeFlow(t testing.TB, f fixture, scopes []string) map[string]any {
	t.Helper()
	ctx := context.Background()

	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"state-1234567890"},
		"nonce":                 {"nonce-1234567890"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d: %s", resp.StatusCode, b)
	}
	login, _ := url.Parse(resp.Header.Get("Location"))
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %s", resp.Header.Get("Location"))
	}
	if err := f.store.CompleteLogin(ctx, id, "usr_1", scopes); err != nil {
		t.Fatal(err)
	}

	resp = get(t, noRedirect, f.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status = %d: %s", resp.StatusCode, b)
	}
	cb, _ := url.Parse(resp.Header.Get("Location"))
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", cb)
	}
	// RFC 9207: an authorization response must identify its issuer.
	if got := cb.Query().Get("iss"); got != f.server.URL {
		t.Fatalf("authorization response iss = %q, want %q", got, f.server.URL)
	}

	tokens, status := postToken(t, f.server.URL, f.webID, "s3cret", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("token status = %d: %v", status, tokens)
	}
	return tokens
}

// O-1: OIDC discovery is served, and the RFC 8414 alias is byte-identical.
func TestDiscoveryAndKeys(t *testing.T) {
	f := newFixture(t)

	oidcResp := get(t, noRedirect, f.server.URL+OIDCDiscoveryPath)
	oidcBody, _ := io.ReadAll(oidcResp.Body)
	oidcResp.Body.Close()
	if oidcResp.StatusCode != http.StatusOK {
		t.Fatalf("OIDC discovery status = %d", oidcResp.StatusCode)
	}
	if cc := oidcResp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Fatalf("discovery Cache-Control = %q, want an explicit max-age", cc)
	}
	var disc map[string]any
	if err := json.Unmarshal(oidcBody, &disc); err != nil {
		t.Fatal(err)
	}
	for key, suffix := range map[string]string{
		"authorization_endpoint": "/oauth/authorize",
		"token_endpoint":         "/oauth/token",
		"jwks_uri":               "/oauth/keys",
		"userinfo_endpoint":      "/oauth/userinfo",
	} {
		got, _ := disc[key].(string)
		if !strings.HasSuffix(got, suffix) {
			t.Fatalf("%s = %q, want suffix %q", key, got, suffix)
		}
	}
	// O-9: RP-initiated logout is deliberately not offered, so it must not be
	// advertised either. The library would advertise it by default.
	if _, ok := disc["end_session_endpoint"]; ok {
		t.Fatal("discovery advertises end_session_endpoint, which ADR-0001 O-9 says is out of contract")
	}
	// RFC 9207: the issuer parameter is emitted, so it must be advertised.
	if disc["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("authorization_response_iss_parameter_supported = %v, want true", disc["authorization_response_iss_parameter_supported"])
	}
	// The library's defaults advertise implicit/hybrid and unsupported grants.
	if got := disc["response_types_supported"]; got != nil {
		if types, _ := got.([]any); len(types) != 1 || types[0] != "code" {
			t.Fatalf("response_types_supported = %v, want [code]", got)
		}
	}
	if grants, _ := disc["grant_types_supported"].([]any); len(grants) != 3 {
		t.Fatalf("grant_types_supported = %v, want the three implemented grants", disc["grant_types_supported"])
	}

	rfcResp := get(t, noRedirect, f.server.URL+RFC8414Path)
	rfcBody, _ := io.ReadAll(rfcResp.Body)
	rfcResp.Body.Close()
	if rfcResp.StatusCode != http.StatusOK {
		t.Fatalf("RFC 8414 status = %d", rfcResp.StatusCode)
	}
	if string(rfcBody) != string(oidcBody) {
		t.Fatal("RFC 8414 alias differs from OIDC discovery")
	}

	keysResp := get(t, noRedirect, f.server.URL+"/oauth/keys")
	keysBody, _ := io.ReadAll(keysResp.Body)
	keysResp.Body.Close()
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(keysBody, &jwks); err != nil {
		t.Fatalf("jwks: %v (%s)", err, keysBody)
	}
	if len(jwks.Keys) == 0 || jwks.Keys[0].Kty != "RSA" || jwks.Keys[0].Alg != "RS256" {
		t.Fatalf("jwks = %s", keysBody)
	}
}

// O-2: id_token is gated on the openid scope.
func TestIDTokenGating(t *testing.T) {
	f := newFixture(t)

	without := codeFlow(t, f, []string{"account.id"})
	if _, ok := without["id_token"]; ok {
		t.Fatal("id_token returned without openid scope")
	}
	if without["access_token"] == nil {
		t.Fatalf("no access token: %v", without)
	}

	with := codeFlow(t, f, []string{"openid", "account.id"})
	if token, ok := with["id_token"].(string); !ok || token == "" {
		t.Fatalf("id_token missing with openid scope: %v", with)
	}
}

// O-3: userinfo returns sub and nothing else.
func TestUserinfoReturnsOnlySub(t *testing.T) {
	f := newFixture(t)
	tokens := codeFlow(t, f, []string{"account.id", "phigros.score.read"})
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatal("no access token")
	}

	req, _ := http.NewRequest(http.MethodGet, f.server.URL+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d: %s", resp.StatusCode, body)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "usr_1" {
		t.Fatalf("sub = %v", claims["sub"])
	}
	if len(claims) != 1 {
		t.Fatalf("userinfo leaked claims: %v", claims)
	}
}

// sanitizeTokenResponse is pure; it runs without a database and locks the two
// contract points the library would otherwise violate.
func TestSanitizeTokenResponse(t *testing.T) {
	var got map[string]any

	out := sanitizeTokenResponse([]byte(`{"access_token":"at","scope":"account.id offline_access","id_token":"jwt"}`))
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["id_token"]; ok {
		t.Fatal("id_token kept without openid scope")
	}
	if got["scope"] != "account.id" {
		t.Fatalf("scope = %v, want account.id (offline_access hidden)", got["scope"])
	}

	out = sanitizeTokenResponse([]byte(`{"access_token":"at","scope":"openid account.id offline_access","id_token":"jwt"}`))
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["id_token"] != "jwt" {
		t.Fatal("id_token dropped despite openid scope")
	}
	if got["scope"] != "openid account.id" {
		t.Fatalf("scope = %v, want openid account.id", got["scope"])
	}
}

// The consent interaction: describe, narrow on approve, and deny with a proper
// error redirect.
func TestConsentInteraction(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	newReq := func() op.AuthRequest {
		ar, err := f.store.CreateAuthRequest(ctx, &oidc.AuthRequest{
			ClientID:     f.webID,
			RedirectURI:  "https://client.example/cb",
			ResponseType: oidc.ResponseTypeCode,
			Scopes:       oidc.SpaceDelimitedArray{"account.id", "phigros.score.read"},
			State:        "state-1234567890",
		}, "")
		if err != nil {
			t.Fatal(err)
		}
		return ar
	}

	described := newReq()
	view, err := f.handler.DescribeAuthorization(ctx, described.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if view.ClientID != f.webID || view.ClientName == "" || len(view.Scopes) != 2 {
		t.Fatalf("view = %+v", view)
	}

	// Approval cannot widen the requested scopes.
	if _, err := f.handler.ApproveAuthorization(ctx, described.GetID(), "usr_1",
		[]oauth.Scope{oauth.ScopePhigrosB30}, nil); err == nil {
		t.Fatal("widening approval accepted")
	}

	redirect, err := f.handler.ApproveAuthorization(ctx, described.GetID(), "usr_1",
		[]oauth.Scope{oauth.ScopeAccountID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(redirect, "/oauth/authorize/callback?id=") {
		t.Fatalf("approve redirect = %q", redirect)
	}
	done, err := f.store.AuthRequestByID(ctx, described.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if !done.Done() || done.GetSubject() != "usr_1" ||
		!containsString(done.GetScopes(), "account.id") ||
		!containsString(done.GetScopes(), oidc.ScopeOfflineAccess) {
		t.Fatalf("completed request = done=%v subject=%q scopes=%v", done.Done(), done.GetSubject(), done.GetScopes())
	}

	// Denial redirects to the client with the error and state, and discards the
	// request.
	denied := newReq()
	denyRedirect, err := f.handler.DenyAuthorization(ctx, denied.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(denyRedirect, "error=access_denied") || !strings.Contains(denyRedirect, "state=state-1234567890") {
		t.Fatalf("deny redirect = %q", denyRedirect)
	}
	if _, err := f.store.AuthRequestByID(ctx, denied.GetID()); err == nil {
		t.Fatal("denied request was not discarded")
	}
}

// O-7 says an unknown or unauthorised scope must be an error, not a silent
// narrowing. The OIDC-standard scopes are the documented exception: the engine
// accepts them for every relying party. But accepting one the *catalogue* cannot
// describe must not turn into a failure later, in the middle of consent.
func TestApproveToleratesStandardOIDCScopes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Exactly what a stock OIDC relying party asks for.
	scopes := []string{"openid", "email", "account.id"}
	ar, err := f.store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     f.webID,
		RedirectURI:  "https://client.example/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       oidc.SpaceDelimitedArray(scopes),
		State:        "state-1234567890",
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	// The consent screen submits back what it was able to render.
	if _, err := f.handler.ApproveAuthorization(ctx, ar.GetID(), "usr_1",
		[]oauth.Scope{"openid", "email", "account.id"}, nil); err != nil {
		t.Fatalf("approving a standard OIDC scope set failed: %v", err)
	}
}

// The consent screen renders the catalogue, and `openid` is not in it — it is a
// protocol flag, not a data permission. So the screen never echoes it back, and
// if the decision then replaces the request's scopes with the echoed list, the
// authorization silently stops being an OpenID one: no `openid`, therefore no
// id_token, for a client that asked for exactly that. The round trip must not be
// able to drop it.
func TestApproveKeepsOpenIDWhenTheConsentScreenOmitsIt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	ar, err := f.store.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     f.webID,
		RedirectURI:  "https://client.example/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       oidc.SpaceDelimitedArray{"openid", "account.id"},
		State:        "state-1234567890",
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	// What the screen can render is only the catalogue scope.
	if _, err := f.handler.ApproveAuthorization(ctx, ar.GetID(), "usr_1",
		[]oauth.Scope{oauth.ScopeAccountID}, nil); err != nil {
		t.Fatal(err)
	}

	done, err := f.store.AuthRequestByID(ctx, ar.GetID())
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(done.GetScopes(), oidc.ScopeOpenID) {
		t.Fatalf("granted scopes = %v, want openid preserved (otherwise no id_token)", done.GetScopes())
	}
	if !containsString(done.GetScopes(), "account.id") {
		t.Fatalf("granted scopes = %v, want the approved catalogue scope", done.GetScopes())
	}
}

// The refresh grant had no test in this package at all, so rotation was never
// exercised end to end — which is how a two-step read-then-rotate could go
// unnoticed. This asserts the ordinary path (a presented token is rotated and the
// replacement works) so that tightening rotation into a claim cannot silently
// break refreshing; the concurrent case is pinned deterministically in the store
// tests, where the interleaving can be written out instead of raced.
func TestRefreshGrantRotatesAndSpendsTheOldToken(t *testing.T) {
	f := newFixture(t)
	// offline_access is what makes the engine issue a refresh token at all.
	tokens := codeFlow(t, f, []string{"openid", "account.id", "offline_access"})
	first, _ := tokens["refresh_token"].(string)
	if first == "" {
		t.Fatalf("the code flow issued no refresh token: %v", tokens)
	}

	refresh := func(token string) (map[string]any, int) {
		return postToken(t, f.server.URL, f.webID, "s3cret", url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
		})
	}

	rotated, status := refresh(first)
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d: %v", status, rotated)
	}
	second, _ := rotated["refresh_token"].(string)
	if second == "" || second == first {
		t.Fatalf("rotation did not happen: first=%q second=%q", first, second)
	}

	// Spent, not merely superseded. The refusal must be a protocol error the
	// client can act on: 400 invalid_grant, not 500 server_error.
	replay, status := refresh(first)
	if status == http.StatusOK {
		t.Fatal("the spent refresh token was accepted a second time")
	}
	if status != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400: %v", status, replay)
	}
	if replay["error"] != "invalid_grant" {
		t.Fatalf("replay error = %v, want invalid_grant", replay["error"])
	}
	// And the replacement is the live one, so the fix did not simply refuse
	// everything.
	if _, status := refresh(second); status != http.StatusOK {
		t.Fatalf("the replacement refresh token was rejected: %d", status)
	}
}

// The ID token was never decoded by a test: every claim except `sub` was
// asserted only in prose. This pins the actual JWT payload, so a library upgrade
// or a signing change cannot silently drop iss/aud/azp/nonce/hashes.
func TestIDTokenClaims(t *testing.T) {
	f := newFixture(t)
	tokens := codeFlow(t, f, []string{"openid", "account.id"})
	raw, _ := tokens["id_token"].(string)
	if raw == "" {
		t.Fatalf("no id_token issued: %v", tokens)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != f.server.URL {
		t.Fatalf("iss = %v, want %q", claims["iss"], f.server.URL)
	}
	if claims["azp"] != f.webID {
		t.Fatalf("azp = %v, want %q", claims["azp"], f.webID)
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != f.webID {
			t.Fatalf("aud = %q, want %q", aud, f.webID)
		}
	case []any:
		if len(aud) != 1 || aud[0] != f.webID {
			t.Fatalf("aud = %v, want [%q]", aud, f.webID)
		}
	default:
		t.Fatalf("aud has unexpected type %T", claims["aud"])
	}
	if claims["nonce"] != "nonce-1234567890" {
		t.Fatalf("nonce = %v, want the authorize nonce", claims["nonce"])
	}
	authTime, ok := claims["auth_time"].(float64)
	if !ok || authTime <= 0 {
		t.Fatalf("auth_time = %v, want a positive number", claims["auth_time"])
	}
	for _, claim := range []string{"at_hash", "c_hash"} {
		if s, _ := claims[claim].(string); s == "" {
			t.Fatalf("%s is missing from the id_token claims", claim)
		}
	}
}

// OIDC Discovery 1.0 §3 requires `openid` to be supported and says the scopes
// defined in OpenID Core SHOULD be listed when they are supported. A relying
// party that negotiates from `scopes_supported` must be able to discover
// `openid`, or it will never request it — and so never receive an id_token.
func TestDiscoveryAdvertisesCoreOIDCScopes(t *testing.T) {
	f := newFixture(t)

	resp := get(t, noRedirect, f.server.URL+OIDCDiscoveryPath)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	var disc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatal(err)
	}
	raw, _ := disc["scopes_supported"].([]any)
	advertised := make(map[string]bool, len(raw))
	for _, s := range raw {
		if name, ok := s.(string); ok {
			advertised[name] = true
		}
	}
	// The catalogue's own scope must survive alongside the two added core scopes.
	for _, want := range []string{"openid", "offline_access", "account.id"} {
		if !advertised[want] {
			t.Errorf("scopes_supported is missing %q (got %v)", want, raw)
		}
	}
}

// OAuth 2.1 requires PKCE on every authorization code request, confidential
// clients included. The fixture's web client is confidential, so this is exactly
// the case the engine would otherwise let through.
func TestAuthorizeRequiresPKCE(t *testing.T) {
	f := newFixture(t)

	authz := func() url.Values {
		return url.Values{
			"response_type": {"code"},
			"client_id":     {f.webID},
			"redirect_uri":  {"https://client.example/cb"},
			"scope":         {"account.id"},
			"state":         {"state-1234567890"},
		}
	}
	assertRejected := func(t *testing.T, v url.Values, what string) {
		t.Helper()
		resp := get(t, noRedirect, f.server.URL+"/oauth/authorize?"+v.Encode())
		defer resp.Body.Close()
		// A redirect, not a 400 body: once redirect_uri is validated, RFC 6749
		// §4.1.2.1 says the client is told through the redirect.
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("%s: status = %d, want a redirect back to the client", what, resp.StatusCode)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if loc.Query().Get("error") != "invalid_request" {
			t.Fatalf("%s: Location = %q, want error=invalid_request", what, resp.Header.Get("Location"))
		}
		if loc.Query().Get("state") != "state-1234567890" {
			t.Fatalf("%s: state was not echoed: %q", what, loc)
		}
	}

	assertRejected(t, authz(), "no challenge at all")

	plain := authz()
	plain.Set("code_challenge", "a-challenge-that-is-not-hashed")
	plain.Set("code_challenge_method", "plain")
	assertRejected(t, plain, "plain challenge method")
}
