package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// The capacity benchmarks. They measure the two paths that bound how many
// downstream calls this service can answer per second: resolving an opaque bearer
// token through introspection for the business plane, and the token endpoint's
// introspection call itself. Everything else on the hot path (session loading,
// JSON encoding, the middleware chain) is included, because a number that
// excludes half the request is not a capacity number.
//
// Run with: make bench

// benchEnv is a fully mounted server plus a live access token and the client's
// secret, built once per benchmark. The client is confidential so the same token
// can be introspected with its own credentials — a client may always introspect
// its own tokens.
type benchEnv struct {
	handler *Server
	token   string
	basic   string
}

func newBenchEnv(b *testing.B) benchEnv {
	b.Helper()
	// The access log writes one line per request, including the setup requests
	// below, and its output interleaves with the benchmark result lines. Discard
	// it: the number is what this file is for, and the log is already covered by
	// its own test.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	metrics := observability.New()
	clients := oauth.NewMemoryClientRegistry()
	handler, store := newOPBackend(b, testIssuer, clients, nil, metrics)
	srv, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              handler,
		TokenIntrospector: handler,
		GrantStore:        store,
		DeviceStore:       store,
		Metrics:           metrics,
	})
	if err != nil {
		b.Fatal(err)
	}

	const clientID = "app"
	const secret = "s3cret"
	scopes := []oauth.Scope{oauth.ScopeAccountID}
	client, err := oauth.NewClient(clientID, "App", oauth.ClientConfidential, secret,
		[]string{"https://app.example/cb"}, scopes)
	if err != nil {
		b.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		b.Fatal(err)
	}

	const verifier = "verifier-verifier-verifier-verifier-verifier"
	code := benchIssueCode(b, srv, store, clientID, verifier, scopes)
	token := benchExchange(b, srv, clientID, secret, code, verifier)
	return benchEnv{
		handler: srv,
		token:   token,
		basic:   "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)),
	}
}

// benchIssueCode drives authorize → login → callback to a code, the same way the
// test suite does, so the benchmark's token is one the real flow produced.
func benchIssueCode(b *testing.B, srv *Server, store *memory.OIDCStore, clientID, verifier string, scopes []oauth.Scope) string {
	b.Helper()
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
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		b.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		b.Fatal(err)
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		b.Fatalf("no authRequestID in %q", loc)
	}
	if err := store.CompleteLogin(context.Background(), id, "user-1", scopeStrings(scopes)); err != nil {
		b.Fatal(err)
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	if rec.Code != http.StatusFound {
		b.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	cb, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		b.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		b.Fatalf("no code in %q", cb)
	}
	return code
}

func benchExchange(b *testing.B, srv *Server, clientID, secret, code, verifier string) string {
	b.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"code":          {code},
		"redirect_uri":  {"https://app.example/cb"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		b.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		b.Fatal(err)
	}
	if tok.AccessToken == "" {
		b.Fatal("token response carried no access token")
	}
	return tok.AccessToken
}

// BenchmarkBusinessPlaneBearerMe is the hot authenticated read: an opaque bearer
// token resolved through introspection, then /v1/me answered as problem+json-safe
// JSON. It is what a downstream tool hits most and what the business plane's
// capacity is bounded by.
func BenchmarkBusinessPlaneBearerMe(b *testing.B) {
	env := newBenchEnv(b)
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+env.token)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		env.handler.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("GET /v1/me = %d: %s", rec.Code, rec.Body.String())
		}
	}
}

// BenchmarkProtocolIntrospect is the token endpoint's introspection call: the
// protocol-plane read a resource server makes on every downstream request. It is
// a pure read — no state is written — so it measures the lookup and the JSON
// answer rather than token minting.
func BenchmarkProtocolIntrospect(b *testing.B) {
	env := newBenchEnv(b)
	form := url.Values{"token": {env.token}}.Encode()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", env.basic)
		rec := httptest.NewRecorder()
		env.handler.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("introspect = %d: %s", rec.Code, rec.Body.String())
		}
	}
}

// BenchmarkProtocolDiscovery measures a discovery document fetch. It is cheap to
// serve but polled by every client on a cold start, so it is worth a number.
func BenchmarkProtocolDiscovery(b *testing.B) {
	env := newBenchEnv(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		env.handler.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
		if rec.Code != http.StatusOK {
			b.Fatalf("discovery = %d", rec.Code)
		}
	}
}
