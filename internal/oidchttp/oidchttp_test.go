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
	"os"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/Re0Auth/r0semi/internal/store/postgres"
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
	store    *postgres.OIDCStore
	webID    string
	deviceID string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI")
		}
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres-backed OIDC tests")
	}

	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	suffix := randSuffix()
	webID, deviceID := "http-web-"+suffix, "http-device-"+suffix

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
	for _, c := range []oauth.Client{web, device} {
		if err := db.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.OIDC(db.Clients(), postgres.OIDCOptions{
		Registry: oauth.DefaultRegistry(),
		Signer:   postgres.NewOIDCSigner("http-test", key),
		Login: func(id string) string {
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
		Clients:       db.Clients(),
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return fixture{server: srv, handler: handler, store: store, webID: webID, deviceID: deviceID}
}

func get(t *testing.T, client *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return resp
}

func postToken(t *testing.T, srv, clientID, secret string, form url.Values) (map[string]any, int) {
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
func codeFlow(t *testing.T, f fixture, scopes []string) map[string]any {
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
	if !done.Done() || done.GetSubject() != "usr_1" || len(done.GetScopes()) != 1 {
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
