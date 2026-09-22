package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// assertSecurityHeaders checks the headers that every response must carry,
// whatever the plane and whatever the outcome.
func assertSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	for _, want := range []struct{ name, value string }{
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "no-referrer"},
		{"X-Frame-Options", "DENY"},
		{"Content-Security-Policy", cspFrameAncestorsNone},
	} {
		if got := h.Get(want.name); got != want.value {
			t.Errorf("%s = %q, want %q", want.name, got, want.value)
		}
	}
}

// The headers must appear on every response on both planes, including the ones
// no handler produces. A consent screen that silently lost frame-ancestors
// would be the whole point of this test failing.
func TestSecurityHeadersCoverBothPlanes(t *testing.T) {
	env := newTestEnv(t)
	cases := []struct {
		method, target string
		wantStatus     int
	}{
		{http.MethodGet, "/.well-known/oauth-authorization-server", http.StatusOK},
		{http.MethodPost, "/oauth/token", http.StatusBadRequest}, // protocol-plane error
		{http.MethodGet, "/oauth/nope", http.StatusNotFound},     // protocol-plane 404
		{http.MethodGet, "/v1/me", http.StatusUnauthorized},      // business plane, no token
		{http.MethodGet, "/v1/nope", http.StatusNotFound},        // business-plane 404
		{http.MethodGet, "/nope", http.StatusNotFound},           // root 404
	}
	for _, tc := range cases {
		rec := env.do(tc.method, tc.target, "", nil)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.target, rec.Code, tc.wantStatus)
		}
		assertSecurityHeaders(t, rec.Header())
		// This env leaves Config.Secure unset, so HSTS must not be advertised:
		// sending it from a plain-HTTP server would be a claim it cannot back.
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("%s %s: HSTS = %q with Secure unset", tc.method, tc.target, got)
		}
	}
}

// HSTS is advertised only when the deployment declares itself https.
func TestHSTSOnlyOnSecureDeployments(t *testing.T) {
	env := newTestEnv(t)
	secure, err := New(Config{Issuer: testIssuer, AS: env.as, Secure: true})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	secure.Handler().ServeHTTP(rec, req)

	if got := rec.Header().Get("Strict-Transport-Security"); got != hstsValue {
		t.Fatalf("HSTS = %q, want %q", got, hstsValue)
	}
	// includeSubDomains and preload are deliberately absent: they are domain-wide
	// commitments that can break unrelated subdomains, so they belong to a
	// deployment's edge policy and not to this binary. Locked in so a drive-by
	// "hardening" commit has to argue for itself.
	if got := rec.Header().Get("Strict-Transport-Security"); strings.Contains(got, "includeSubDomains") || strings.Contains(got, "preload") {
		t.Errorf("HSTS = %q must not carry includeSubDomains or preload", got)
	}
	assertSecurityHeaders(t, rec.Header())
}

// The headers sit outside the limiter, so a throttled request still carries
// them. It must also carry a request id: that response never reaches a handler,
// and it is the one a caller is most likely to report.
func TestSecurityHeadersOnRateLimitedResponse(t *testing.T) {
	env := newTestEnv(t)
	limited, err := New(Config{
		Issuer:  testIssuer,
		AS:      env.as,
		Limiter: ratelimit.New(0.001, 1), // one token, effectively no refill
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
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
	assertSecurityHeaders(t, rec.Header())
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("a throttled response must still carry a request id")
	}
}
