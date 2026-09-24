package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// A panic must not drop the connection. net/http's own handling is to log the
// panic and close, so the caller gets nothing at all; a crash has to answer in the
// format of the plane it happened on, and the two planes never borrow each
// other's.
//
// Before this, only /v1 had a recoverer. The protocol plane, the login plane, the
// frontend and the catch-all had none.
func TestPanicRecoveryAnswersInTheRightShape(t *testing.T) {
	env := newTestEnv(t)
	boom := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })

	t.Run("protocol", func(t *testing.T) {
		rec := httptest.NewRecorder()
		recoverProtocol(boom).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/token", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		assertOAuthPlane(t, rec)
		if body := decodeJSON(t, rec); body["error"] == nil {
			t.Fatalf("no OAuth error field: %v", body)
		}
	})

	t.Run("business", func(t *testing.T) {
		rec := httptest.NewRecorder()
		recoverBusiness(env.srv, boom).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		assertProblemPlane(t, rec)
	})

	t.Run("neither plane", func(t *testing.T) {
		rec := httptest.NewRecorder()
		recoverBrowser(boom).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/github/start", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		// Neither plane's format: that decision is still open (docs/api-design.md §6),
		// and answering problem+json here would make it by accident.
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
			t.Fatalf("content-type = %q, want text/plain", ct)
		}
		if body := decodeBody(t, rec); body != nil {
			t.Fatalf("expected no JSON body, got %v", body)
		}
	})
}

// The protocol recoverer must be wired to the protocol handler, not merely exist:
// this drives a panicking provider through the real Handler().
func TestProtocolPanicIsCaughtInTheWiring(t *testing.T) {
	clients := oauth.NewMemoryClientRegistry()
	handler, store := newOPBackend(t, testIssuer, clients, nil)
	srv, err := New(Config{
		Issuer:            testIssuer,
		OIDC:              http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
		TokenIntrospector: handler,
		GrantStore:        store,
		DeviceStore:       store,
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (a panic must not escape as a closed connection)", rec.Code)
	}
	// It must be the *protocol* recoverer that answered. Asserting only "not
	// problem+json" would pass even with this recoverer removed, because the
	// outermost browser recoverer also answers 500 — in text/plain. The body is
	// what tells the two apart.
	body := decodeBody(t, rec)
	if body == nil || body["error"] == nil {
		t.Fatalf("body is not an OAuth error object, so the wrong recoverer answered: %q", rec.Body.String())
	}
	assertOAuthPlane(t, rec)
}
