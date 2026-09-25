package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/oauth"
)

// The domain signals are only worth having if they are actually reached by a
// request that goes through the assembled server. The observability package's own
// tests prove the vectors record and export; this proves the wiring, which is the
// half that a compile error cannot catch — a signal that is declared but never
// called reads zero forever and looks exactly like "nothing happened".
func TestBusinessMetricsFireThroughTheServer(t *testing.T) {
	metrics := observability.New()
	clients := oauth.NewMemoryClientRegistry()
	handler, store := newOPBackend(t, testIssuer, clients, nil, metrics)
	srv, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              handler,
		TokenIntrospector: handler,
		GrantStore:        store,
		DeviceStore:       store,
		Metrics:           metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{srv: srv, store: store, handler: handler, clients: clients}
	env.register(t, "app", oauth.ClientPublic, "", []oauth.Scope{oauth.ScopeAccountID})

	const verifier = "verifier-verifier-verifier-verifier-verifier"

	// A successful exchange: the issuance signal.
	code := env.issueCode(t, "app", []oauth.Scope{oauth.ScopeAccountID}, verifier)
	if rec := env.exchange(t, "app", "", code, verifier, nil); rec.Code != http.StatusOK {
		t.Fatalf("exchange = %d: %s", rec.Code, rec.Body.String())
	}

	// A failed exchange: the error signal, by OAuth error code.
	bad := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"app"},
		"code":          {"does-not-exist"},
		"redirect_uri":  {"https://app.example/cb"},
		"code_verifier": {verifier},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(bad.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("a bogus authorization code produced a token")
	}

	body := scrapeMetrics(t, metrics)
	for _, want := range []string{
		`re0auth_tokens_issued_total{grant_type="authorization_code"} 1`,
		`re0auth_token_errors_total{error="invalid_grant",grant_type="authorization_code"} 1`,
		`re0auth_http_requests_total{method="POST",plane="protocol"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition is missing %q\n--- exposition ---\n%s", want, body)
		}
	}
}

// scrapeMetrics reads the exposition out of an observability set, the way a
// scraper would.
func scrapeMetrics(t *testing.T, m *observability.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d", rec.Code)
	}
	return rec.Body.String()
}
