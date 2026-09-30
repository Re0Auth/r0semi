package tapsign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// AUDIT9 / S07-1 — credential-bearing requests trust the injected Doer's redirect
// policy, and net/http's default policy copies CUSTOM auth headers across hosts.
//
// tapsign sends the long-lived session token as X-LC-Session and the app key as
// X-LC-Key (client.go:114-126). With an *http.Client whose CheckRedirect is nil —
// the stdlib default, and what many callers inject — net/http follows the redirect.
// Its copier (makeHeadersCopier) only drops the FIXED sensitive set
// (Authorization, WWW-Authenticate, Cookie, Cookie2, Proxy-Authorization,
// Proxy-Authenticate) when the host changes; every other header, including these
// custom ones, is copied to the new origin.
//
// Guard: pins the leak. It fails once the outbound client refuses cross-origin
// redirects (or strips custom credential headers), which is the recommended fix.
func TestAudit9CredentialHeadersLeakToACrossHostRedirect(t *testing.T) {
	var leaked http.Header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// A different HOSTNAME for the same loopback address, so net/http sees a
	// cross-host redirect and applies its cross-domain header policy.
	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL+"/users/me", http.StatusFound)
	}))
	defer origin.Close()

	logger := audit.NewMemoryLogger()
	c := newClient(
		Config{BaseURL: origin.URL, AppID: "test-app", AppKey: "test-key"},
		origin.Client(), // CheckRedirect is nil: the stdlib default policy
		logger,
	)
	if err := c.Verify(context.Background(), testCred()); err != nil {
		t.Fatalf("Verify through a redirect: %v", err)
	}
	if leaked == nil {
		t.Fatal("the redirect target was never reached")
	}

	if got := leaked.Get("X-LC-Session"); got != "test-session-token" {
		t.Errorf("X-LC-Session at the redirect target = %q, want the session token copied "+
			"(the credential leak)", got)
	}
	if got := leaked.Get("X-LC-Key"); got != "test-key" {
		t.Errorf("X-LC-Key at the redirect target = %q, want the app key copied", got)
	}
}
