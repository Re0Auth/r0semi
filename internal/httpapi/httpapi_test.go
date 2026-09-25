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

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

const testIssuer = "https://auth.test"

type testEnv struct {
	srv     *Server
	store   *memory.OIDCStore
	handler *oidchttp.Handler
	clients *oauth.MemoryClientRegistry
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	handler, store := newOPBackend(t, testIssuer, clients, nil)
	srv, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              handler,
		TokenIntrospector: handler,
		GrantStore:        store,
		DeviceStore:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{srv: srv, store: store, handler: handler, clients: clients}
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

// issueCode drives the OpenID Provider's authorize step up to the code: it
// starts the request, completes the login (as the consent screen would), and
// follows the OP callback to the client redirect.
func (e *testEnv) issueCode(t *testing.T, clientID string, scopes []oauth.Scope, verifier string) string {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {strings.Join(scopeStrings(scopes), " ")},
		"state":                 {"st"},
		"code_challenge":        {pkce(verifier)},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %q", loc)
	}
	if err := e.store.CompleteLogin(context.Background(), id, "user-1", scopeStrings(scopes)); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	cb, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", cb)
	}
	return code
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

	// Metadata is a negotiated contract, so it must describe this deployment
	// rather than the library's full capability set. Only the code response type,
	// and only code/refresh/device grants, are actually implemented.
	assertStringSet(t, doc["response_types_supported"], []string{"code"}, "response_types_supported")
	assertStringSet(t, doc["grant_types_supported"],
		[]string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"grant_types_supported")
	assertStringSet(t, doc["claims_supported"], []string{"sub"}, "claims_supported")
	assertStringSet(t, doc["token_endpoint_auth_methods_supported"],
		[]string{"none", "client_secret_basic", "client_secret_post"},
		"token_endpoint_auth_methods_supported")
	for _, removed := range []string{
		"registration_endpoint",
		"check_session_iframe",
		"end_session_endpoint",
		"token_endpoint_auth_signing_alg_values_supported",
		"userinfo_signing_alg_values_supported",
	} {
		if _, ok := doc[removed]; ok {
			t.Fatalf("metadata advertises %s, which is not implemented", removed)
		}
	}
}

// assertStringSet checks a discovery list against an exact expected set,
// independent of order.
func assertStringSet(t *testing.T, value any, want []string, field string) {
	t.Helper()
	raw, ok := value.([]any)
	if !ok {
		t.Fatalf("%s = %v, want an array", field, value)
	}
	got := make(map[string]bool, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%s contains a non-string: %v", field, v)
		}
		got[s] = true
	}
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want exactly %v", field, raw, want)
	}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("%s = %v, missing %q", field, raw, w)
		}
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

	const verifier = "verifier-verifier-verifier-verifier-verifier"
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

	const verifier = "verifier-verifier-verifier-verifier-verifier"
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
	// RFC 6750 §3.1: the challenge is how a standard client tells "your token is
	// too narrow" from "your token is no good", and which scope it needs.
	if got, want := rec.Header().Get("WWW-Authenticate"), `Bearer error="insufficient_scope", scope="account.id"`; got != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// The challenge has two shapes: one that names the missing scope, and one for a
// requirement that is a set (the raw proxy accepts any of a source's resource
// scopes). The scope parameter is optional in RFC 6750 §3.1, so the second omits
// it rather than inventing a value.
func TestInsufficientScopeChallengeShapes(t *testing.T) {
	env := newTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/games/phigros/b30", nil)

	named := httptest.NewRecorder()
	env.srv.insufficientScope(named, req, "phigros.b30.read", "detail")
	if got, want := named.Header().Get("WWW-Authenticate"), `Bearer error="insufficient_scope", scope="phigros.b30.read"`; got != want {
		t.Fatalf("named WWW-Authenticate = %q, want %q", got, want)
	}
	if body := decodeJSON(t, named); body["required_scope"] != "phigros.b30.read" {
		t.Fatalf("named problem = %v", body)
	}

	anonymous := httptest.NewRecorder()
	env.srv.insufficientScope(anonymous, req, "", "detail")
	if got, want := anonymous.Header().Get("WWW-Authenticate"), `Bearer error="insufficient_scope"`; got != want {
		t.Fatalf("set-valued WWW-Authenticate = %q, want %q", got, want)
	}
	if body := decodeJSON(t, anonymous); body["required_scope"] != nil {
		t.Fatalf("required_scope was invented for a set-valued requirement: %v", body)
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

	const verifier = "verifier-verifier-verifier-verifier-verifier"
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
	// The provider writes this particular error as text, but it is still the
	// protocol plane: it must not be problem+json, and it must name the failure.
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "problem+json") {
		t.Fatalf("protocol plane leaked problem+json: %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("body = %q, want it to name invalid_client", rec.Body.String())
	}
}

func TestConfidentialTokenUsesBasicAuth(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "conf", oauth.ClientConfidential, "s3cret", []oauth.Scope{oauth.ScopeAccountID})

	const verifier = "verifier-verifier-verifier-verifier-verifier"
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
	accounts := account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: false})
	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: testIssuer,
		Credentials:  []idp.Credentials{{Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}
	opHandler, store := newOPBackend(t, testIssuer, oauth.NewMemoryClientRegistry(), manager)
	srv, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Authorization:     opHandler,
		Sessions:          manager,
		Accounts:          accounts,
		Auth:              authHandler,
	})
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
	opHandler, store := newOPBackend(t, testIssuer, oauth.NewMemoryClientRegistry(), nil)
	if _, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Auth:              &auth.Handler{},
	}); err == nil {
		t.Fatal("accepted Auth without Sessions")
	}
}
