package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/oauth"
)

// newLimitedServer builds a server with a one-token bucket, so the first request
// from a client address succeeds and every one after it is throttled.
func newLimitedServer(t *testing.T) *httptest.Server {
	t.Helper()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	opHandler, store := newOPBackend(t, "https://re0auth.test", clients, nil)
	api, err := New(Config{
		Issuer:            "https://re0auth.test",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Limiter:           ratelimit.New(0.001, 1), // effectively one request per client address
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// The business plane must answer a throttled request with problem+json, and the
// protocol plane with an OAuth error. A limiter that blurred the two would break
// the plane invariant the whole design rests on.
func TestRateLimitUsesEachPlanesErrorShape(t *testing.T) {
	srv := newLimitedServer(t)

	first, err := http.Get(srv.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first request = %d, want 401", first.StatusCode)
	}

	second, err := http.Get(srv.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", second.StatusCode)
	}
	if second.Header.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	if ct := second.Header.Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("content-type = %q, want problem+json", ct)
	}
	var problem map[string]any
	if err := json.NewDecoder(second.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem["code"] != "rate_limited" {
		t.Fatalf("problem = %v", problem)
	}
}

// One bucket per (plane, address). The harm a single bucket did is concrete: every
// client in this test comes from one address (the test server sees 127.0.0.1), which
// is what a NAT looks like, so a flood of business-plane reads used to spend the
// budget the same address needed to reach the token endpoint.
//
// The order matters for the same reason the fix does: the second business request
// asserts the bucket is actually empty — without it, a limiter that silently stopped
// working would make the protocol assertion below pass for the wrong reason.
func TestRateLimitIsolatesPlanesPerAddress(t *testing.T) {
	srv := newLimitedServer(t)

	first, err := http.Get(srv.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first business request = %d, want 401", first.StatusCode)
	}

	spent, err := http.Get(srv.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	spent.Body.Close()
	if spent.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the business bucket was not exhausted: %d, want 429", spent.StatusCode)
	}

	// The same address, a different plane: sign-in is not collateral damage.
	resp, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
		"grant_type": {"bogus"}, "client_id": {"cli"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatal("a flood on the business plane locked the same address out of the protocol plane")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("protocol request = %d, want the handler's 400", resp.StatusCode)
	}
}

func TestRateLimitProtocolPlaneUsesOAuthError(t *testing.T) {
	srv := newLimitedServer(t)

	post := func() *http.Response {
		resp, err := http.PostForm(srv.URL+"/oauth/token", url.Values{
			"grant_type": {"bogus"}, "client_id": {"cli"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	first := post()
	first.Body.Close()
	if first.StatusCode != http.StatusBadRequest {
		t.Fatalf("first request = %d, want 400", first.StatusCode)
	}

	second := post()
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", second.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(second.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "temporarily_unavailable" {
		t.Fatalf("body = %v", body)
	}
	// A protocol-plane body carries error/error_description only.
	if _, leaked := body["code"]; leaked {
		t.Fatalf("protocol plane leaked a problem field: %v", body)
	}
}

// A rejected request at the root of the protocol namespace must answer like
// everything under it. The trailing slash is not something a client has to know:
// `/oauth` is a URL somebody types, and the shared middleware used to classify it
// as the business plane while the router treated it as the protocol subtree.
func TestRateLimitAtTheProtocolNamespaceRoot(t *testing.T) {
	for _, path := range []string{"/oauth", "/.well-known"} {
		t.Run(path, func(t *testing.T) {
			env := newTestEnv(t)
			limited, err := New(Config{
				Issuer:            testIssuer,
				OIDC:              env.handler,
				TokenIntrospector: env.handler,
				GrantStore:        env.store,
				DeviceStore:       env.store,
				Limiter:           ratelimit.New(0.001, 1),
			})
			if err != nil {
				t.Fatal(err)
			}
			do := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.RemoteAddr = "203.0.113.7:1234"
				rec := httptest.NewRecorder()
				limited.Handler().ServeHTTP(rec, req)
				return rec
			}
			do() // spend the single token
			rec := do()
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("second request = %d, want 429", rec.Code)
			}
			assertOAuthPlane(t, rec)
		})
	}
}

// The RateLimit-* headers let a client back off before it is rejected rather than
// after, which is the whole point of publishing the bucket state.
func TestRateLimitHeadersExposeTheBucket(t *testing.T) {
	env := newTestEnv(t)
	limited, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              env.handler,
		TokenIntrospector: env.handler,
		GrantStore:        env.store,
		DeviceStore:       env.store,
		Limiter:           ratelimit.New(1, 5),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.RemoteAddr = "203.0.113.11:1234"
	rec := httptest.NewRecorder()
	limited.Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("RateLimit-Limit"); got != "5" {
		t.Fatalf("RateLimit-Limit = %q, want 5", got)
	}
	if got := rec.Header().Get("RateLimit-Remaining"); got == "" {
		t.Fatal("RateLimit-Remaining is missing")
	}
	if got := rec.Header().Get("RateLimit-Reset"); got == "" {
		t.Fatal("RateLimit-Reset is missing")
	}
}

// The in-flight cap is the inbound bulkhead: when it is full, a request is
// refused in its own plane's shape rather than queued without bound.
func TestInFlightCapRefusesInPlaneShape(t *testing.T) {
	s := &Server{maxInFlight: 1}
	block := make(chan struct{})
	release := make(chan struct{})
	handler := s.withInFlightLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(block)
		<-release
		w.WriteHeader(http.StatusOK)
	}))

	go func() {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}()
	<-block

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated request = %d, want 503", rec.Code)
	}
	assertProblemPlane(t, rec)
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
	close(release)
}

// A well-formed traceparent is adopted as this request's trace id; an invalid one
// is ignored rather than rejected, and a fresh id is generated.
func TestTraceparentIsAdoptedOrReplaced(t *testing.T) {
	const incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	var got string
	handler := withTrace(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = traceID(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("traceparent", incoming)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace id = %q, want the incoming trace id", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("traceparent", "not-a-traceparent")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if len(got) != 32 {
		t.Fatalf("invalid traceparent was not replaced with a generated id: %q", got)
	}
}
