package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// A form endpoint must not be makeable into a memory amplifier. The standard
// library's own limit is 10 MB, which is a lot to spend on a request whose real
// size is a few hundred bytes.
func TestBodyLimitOnTheProtocolPlane(t *testing.T) {
	env := newTestEnv(t)

	// A declared length over the cap is refused before anything is read.
	rec := env.do("POST", "/oauth/token", strings.Repeat("x", oauth.MaxFormBytes+1), nil)
	if rec.Code != 413 {
		t.Fatalf("oversized token request = %d, want 413", rec.Code)
	}
	// And in the protocol plane's own shape, not a bare HTTP error: a client that
	// parses OAuth errors would otherwise be the one exception in the service.
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want JSON", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"error"`) || strings.Contains(body, `"code"`) {
		t.Fatalf("body = %s, want an OAuth error and no problem fields", body)
	}
}

// The same cap, rendered the other plane's way. Both bodies are the same size and
// the two answers must not be.
func TestBodyLimitOnTheBusinessPlane(t *testing.T) {
	env := newTestEnv(t)

	rec := env.do("POST", "/v1/device/decision", strings.Repeat("x", oauth.MaxFormBytes+1), nil)
	if rec.Code != 413 {
		t.Fatalf("oversized business request = %d, want 413", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("Content-Type = %q, want problem+json", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"code"`) {
		t.Fatalf("body = %s, want a problem document", body)
	}
}

// A body inside the cap must reach its handler unchanged: a limit that broke
// ordinary requests would be worse than no limit.
func TestBodyLimitLetsNormalRequestsThrough(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do("POST", "/oauth/token", "grant_type=bogus&client_id=cli", nil)
	// Reached the handler, which rejected the grant type on its own terms.
	if rec.Code != 400 {
		t.Fatalf("normal request = %d, want 400 from the handler", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "unsupported_grant_type") {
		t.Fatalf("body = %s, want the handler's own error", body)
	}
}

// A chunked body declares no length, so the cap has to be enforced while reading
// rather than up front. The form parse then fails part-way, which the handler
// reports in its own terms — a different path to the same refusal.
func TestBodyLimitHandlesAnUndeclaredLength(t *testing.T) {
	env := newTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(strings.Repeat("x", oauth.MaxFormBytes+1)))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	// Without this, ParseForm does not read the body at all — it has no content
	// type to decide how — and the cap would never be exercised.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("chunked oversized request = %d, want 400", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "invalid_request") {
		t.Fatalf("body = %s, want an OAuth error", body)
	}
}
