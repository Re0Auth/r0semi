package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/oauth"
)

const testIssuer = "https://auth.test"

type testEnv struct {
	srv     *Server
	as      oauth.Service
	clients *oauth.MemoryClientRegistry
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: testIssuer,
		Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Issuer: testIssuer, AS: as})
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{srv: srv, as: as, clients: clients}
}

func (e *testEnv) register(t *testing.T, id string, typ oauth.ClientType, secret string, scopes []oauth.Scope) {
	t.Helper()
	c, err := oauth.NewClient(id, id, typ, secret, []string{"https://app.example/cb"}, scopes)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.clients.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// issueCode drives the service-side authorize step; the browser consent UI does
// not exist yet.
func (e *testEnv) issueCode(t *testing.T, clientID string, scopes []oauth.Scope, verifier string) string {
	t.Helper()
	resp, err := e.as.Authorize(context.Background(), oauth.AuthorizationRequest{
		ClientID:            clientID,
		RedirectURI:         "https://app.example/cb",
		Subject:             "user-1",
		Scopes:              scopes,
		CodeChallenge:       pkce(verifier),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Code
}

func (e *testEnv) do(method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (e *testEnv) exchange(t *testing.T, clientID, secret, code, verifier string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {"https://app.example/cb"},
		"code_verifier": {verifier},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	return e.do(http.MethodPost, "/oauth/token", form.Encode(), headers)
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode json: %v (body=%s)", err, rec.Body.String())
	}
	return m
}

func TestAuthorizationServerMetadata(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(http.MethodGet, "/.well-known/oauth-authorization-server", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	doc := decodeJSON(t, rec)
	if doc["issuer"] != testIssuer {
		t.Fatalf("issuer = %v", doc["issuer"])
	}
	if doc["token_endpoint"] != testIssuer+"/oauth/token" {
		t.Fatalf("token_endpoint = %v", doc["token_endpoint"])
	}
	if methods, _ := doc["code_challenge_methods_supported"].([]any); len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v", doc["code_challenge_methods_supported"])
	}
	// Every advertised capability must be real. device_authorization is
	// implemented (RFC 8628); DPoP is not, so it must not be advertised -- a
	// client that sent a DPoP proof would silently get a plain bearer token.
	if doc["device_authorization_endpoint"] != testIssuer+"/oauth/device_authorization" {
		t.Fatalf("device_authorization_endpoint = %v", doc["device_authorization_endpoint"])
	}
	if _, ok := doc["dpop_signing_alg_values_supported"]; ok {
		t.Fatal("the metadata advertises DPoP, which is not implemented")
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(http.MethodGet, "/.well-known/oauth-protected-resource", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	doc := decodeJSON(t, rec)
	if doc["resource"] != testIssuer {
		t.Fatalf("resource = %v", doc["resource"])
	}
	servers, _ := doc["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != testIssuer {
		t.Fatalf("authorization_servers = %v", doc["authorization_servers"])
	}
}

func TestAuthorizationCodeFlowOverHTTP(t *testing.T) {
	env := newTestEnv(t)
	scope := []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore}
	env.register(t, "app", oauth.ClientPublic, "", scope)

	const verifier = "verifier-verifier-verifier-verifier"
	code := env.issueCode(t, "app", scope, verifier)

	rec := env.exchange(t, "app", "", code, verifier, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("missing no-store headers: %v", rec.Header())
	}
	tok := decodeJSON(t, rec)
	at, _ := tok["access_token"].(string)
	if at == "" || tok["token_type"] != "Bearer" {
		t.Fatalf("token = %v", tok)
	}

	rec = env.do(http.MethodGet, "/v1/me", "", map[string]string{"Authorization": "Bearer " + at})
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d body = %s", rec.Code, rec.Body.String())
	}
	me := decodeJSON(t, rec)
	if me["id"] != "user-1" || me["client_id"] != "app" {
		t.Fatalf("me = %v", me)
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("missing X-Request-Id")
	}
}

// The protocol plane must never emit problem+json.
func TestTokenErrorUsesOAuthFormat(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "app", oauth.ClientPublic, "", []oauth.Scope{oauth.ScopeAccountID})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"app"},
		"code":          {"does-not-exist"},
		"redirect_uri":  {"https://app.example/cb"},
		"code_verifier": {"v"},
	}
	rec := env.do(http.MethodPost, "/oauth/token", form.Encode(), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeJSON(t, rec)
	if body["error"] == nil {
		t.Fatalf("missing oauth error field: %v", body)
	}
	if body["type"] != nil || body["code"] != nil {
		t.Fatalf("protocol plane leaked problem+json: %v", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
}

// The business plane must never emit an OAuth error body.
func TestBusinessErrorUsesProblemFormat(t *testing.T) {
	env := newTestEnv(t)

	rec := env.do(http.MethodGet, "/v1/me", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content-type = %q", ct)
	}
	body := decodeJSON(t, rec)
	if body["code"] != "unauthenticated" {
		t.Fatalf("code = %v", body["code"])
	}
	if body["error"] != nil {
		t.Fatalf("business plane leaked oauth error: %v", body)
	}
	if body["request_id"] == "" || body["request_id"] == nil {
		t.Fatalf("missing request_id: %v", body)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate on 401")
	}
}

func TestInsufficientScopeIsForbidden(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "scoreonly", oauth.ClientPublic, "", []oauth.Scope{oauth.ScopePhigrosScore})

	const verifier = "verifier-verifier-verifier-verifier"
	code := env.issueCode(t, "scoreonly", []oauth.Scope{oauth.ScopePhigrosScore}, verifier)
	tok := decodeJSON(t, env.exchange(t, "scoreonly", "", code, verifier, nil))
	at, _ := tok["access_token"].(string)

	rec := env.do(http.MethodGet, "/v1/me", "", map[string]string{"Authorization": "Bearer " + at})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	body := decodeJSON(t, rec)
	if body["code"] != "scope_not_granted" || body["required_scope"] != "account.id" {
		t.Fatalf("problem = %v", body)
	}
}

func TestUnknownEndpointsArePlaneSpecific(t *testing.T) {
	env := newTestEnv(t)

	rec := env.do(http.MethodGet, "/oauth/nope", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("oauth 404 status = %d", rec.Code)
	}
	if body := decodeJSON(t, rec); body["error"] == nil || body["type"] != nil {
		t.Fatalf("expected oauth 404 body, got %v", body)
	}

	rec = env.do(http.MethodGet, "/v1/nope", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("v1 404 status = %d", rec.Code)
	}
	if body := decodeJSON(t, rec); body["type"] == nil || body["error"] != nil {
		t.Fatalf("expected problem 404 body, got %v", body)
	}
}

func TestRequestIDIsEchoed(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(http.MethodGet, "/v1/me", "", map[string]string{"X-Request-Id": "req_custom"})
	if got := rec.Header().Get("X-Request-Id"); got != "req_custom" {
		t.Fatalf("X-Request-Id = %q", got)
	}
}

func TestIntrospectAndRevoke(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "conf", oauth.ClientConfidential, "s3cret", []oauth.Scope{oauth.ScopeAccountID})

	const verifier = "verifier-verifier-verifier-verifier"
	code := env.issueCode(t, "conf", []oauth.Scope{oauth.ScopeAccountID}, verifier)
	tok := decodeJSON(t, env.exchange(t, "conf", "s3cret", code, verifier, nil))
	at, _ := tok["access_token"].(string)

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("conf:s3cret"))
	form := url.Values{"token": {at}}

	rec := env.do(http.MethodPost, "/oauth/introspect", form.Encode(), map[string]string{"Authorization": basic})
	if rec.Code != http.StatusOK {
		t.Fatalf("introspect status = %d body = %s", rec.Code, rec.Body.String())
	}
	info := decodeJSON(t, rec)
	if info["active"] != true || info["sub"] != "user-1" || info["scope"] != "account.id" {
		t.Fatalf("introspect = %v", info)
	}

	rec = env.do(http.MethodPost, "/oauth/revoke", form.Encode(), map[string]string{"Authorization": basic})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d", rec.Code)
	}

	rec = env.do(http.MethodPost, "/oauth/introspect", form.Encode(), map[string]string{"Authorization": basic})
	if info := decodeJSON(t, rec); info["active"] != false {
		t.Fatalf("after revoke introspect = %v", info)
	}
}

func TestIntrospectRequiresClientAuth(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(http.MethodPost, "/oauth/introspect", url.Values{"token": {"x"}}.Encode(), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if body := decodeJSON(t, rec); body["error"] != "invalid_client" {
		t.Fatalf("body = %v", body)
	}
}

func TestConfidentialTokenUsesBasicAuth(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "conf", oauth.ClientConfidential, "s3cret", []oauth.Scope{oauth.ScopeAccountID})

	const verifier = "verifier-verifier-verifier-verifier"
	code := env.issueCode(t, "conf", []oauth.Scope{oauth.ScopeAccountID}, verifier)

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("conf:s3cret"))
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example/cb"},
		"code_verifier": {verifier},
	}
	rec := env.do(http.MethodPost, "/oauth/token", form.Encode(), map[string]string{"Authorization": basic})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if body := decodeJSON(t, rec); body["access_token"] == nil || body["access_token"] == "" {
		t.Fatalf("body = %v", body)
	}
}

func TestAuthorizeEndpointIsTemporarilyUnavailable(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(http.MethodGet, "/oauth/authorize", "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	if body := decodeJSON(t, rec); body["error"] != "temporarily_unavailable" {
		t.Fatalf("body = %v", body)
	}
}

// Without session configuration the session and /auth routes are absent.
func TestSessionRoutesAbsentWithoutConfig(t *testing.T) {
	env := newTestEnv(t)

	rec := env.do(http.MethodGet, "/v1/sessions/current", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("sessions status = %d, want 404", rec.Code)
	}
	if body := decodeJSON(t, rec); body["code"] != "not_found" {
		t.Fatalf("body = %v", body)
	}

	rec = env.do(http.MethodGet, "/auth/github/start", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("auth status = %d, want 404", rec.Code)
	}
}

func TestSessionRoutesMountedWithConfig(t *testing.T) {
	as, err := oauth.NewService(oauth.NewMemoryClientRegistry(), oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: testIssuer,
		Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	accounts := account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: false})
	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: testIssuer,
		Credentials:  []idp.Credentials{{Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Issuer: testIssuer, AS: as, Sessions: manager, Accounts: accounts, Auth: handler})
	if err != nil {
		t.Fatal(err)
	}

	// The session endpoint is mounted and answers in the business format.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/sessions/current", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content-type = %q", ct)
	}
	if body := decodeJSON(t, rec); body["code"] != "unauthenticated" {
		t.Fatalf("body = %v", body)
	}

	// The /auth plane is mounted and redirects to the provider.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/github/start", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("auth status = %d, want 302", rec.Code)
	}
}

func TestAuthRequiresSessions(t *testing.T) {
	as, err := oauth.NewService(oauth.NewMemoryClientRegistry(), oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: testIssuer,
		Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Issuer: testIssuer, AS: as, Auth: &auth.Handler{}}); err == nil {
		t.Fatal("accepted Auth without Sessions")
	}
}
