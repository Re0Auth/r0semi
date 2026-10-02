package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
)

// Every business-plane response is authenticated and per-person, so none of them
// may be cached — not by a shared cache in front of the deployment, and not by the
// browser.
//
// The two that made this concrete: the session bootstrap and the admin client list
// hand out a CSRF token, and the account export is the whole of somebody's account.
// Before this, only the protocol plane set `no-store`; the business plane set no
// Cache-Control at all, and there is no Vary either, so an intermediary had no key
// that distinguishes one account's response from another's.
func TestBusinessPlaneResponsesAreNotCached(t *testing.T) {
	base, browser, _, _, _, _, _ := newBindEnv(t)
	signIn(t, browser, base)

	for _, path := range []string{
		"/v1/sessions/current",
		"/v1/account/export",
		"/v1/identities",
		"/v1/grants",
		"/v1/bindings",
		"/v1/sources",
		"/v1/idp/providers",
	} {
		t.Run(path, func(t *testing.T) {
			resp := getURL(t, browser, base+path)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 (the assertion below needs a body to protect)", resp.StatusCode)
			}
			// no-store must be one of the directives, not the whole value: the
			// responses carrying a CSRF token also carry no-transform (S10-4).
			if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
				t.Errorf("Cache-Control = %q, want it to contain no-store", got)
			}
		})
	}
}

// The 200 endpoints above are not the whole business plane. The limiter's 429 and
// the body limit's 413 are written by middlewares that sit OUTSIDE the /v1 sub-mux,
// so the plane wrapper never sees them and the directive has to come from
// writeProblem itself. Before that, the guard above passed while every refusal on
// the plane went out cacheable.
func TestBusinessPlaneRejectionsAreNotCached(t *testing.T) {
	cfg := newFullConfig(t)
	cfg.Limiter = ratelimit.New(0.001, 1)
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	do := func(peer, method, target string, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// 429: one token per peer, never refilled.
	peer := "203.0.113.7:1234"
	do(peer, http.MethodGet, "/v1/me", "")
	rec := do(peer, http.MethodGet, "/v1/me", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second /v1/me = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("business 429 Cache-Control = %q, want no-store", got)
	}

	// 413: over oauth.MaxFormBytes, from a peer whose bucket is still full.
	big := strings.Repeat("x", 100<<10)
	rec = do("203.0.113.8:1234", http.MethodPost, "/v1/me", big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized /v1/me = %d, want 413", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("business 413 Cache-Control = %q, want no-store", got)
	}
}
