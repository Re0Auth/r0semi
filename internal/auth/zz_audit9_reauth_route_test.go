package auth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// AUDIT9 / S02-1 — the re-authentication bounce.
//
// The OP's login boundary cannot name an identity provider; only the account store
// knows which identities the signed-in user has. /auth/reauth is the browser-facing
// half of the fix: it resolves the primary identity's provider and starts an
// ordinary login flow pointed at it, returning to the consent screen the caller
// named.
func TestAudit9ReauthRedirectsThroughThePrimaryProvider(t *testing.T) {
	h := newHarness(t)
	h.login(t, "github")

	resp := h.get(t, h.server.URL+"/auth/reauth?return_to="+url.QueryEscape("/app/consent?id=abc"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("reauth = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/auth/github/start" {
		t.Fatalf("reauth redirected to %q, want the primary provider's start", loc.Path)
	}
	if got := loc.Query().Get("mode"); got != "login" {
		t.Errorf("mode = %q, want login", got)
	}
	if got := loc.Query().Get("return_to"); got != "/app/consent?id=abc" {
		t.Errorf("return_to = %q, want the consent screen", got)
	}
	if strings.Contains(resp.Header.Get("Location"), "//") && !strings.HasPrefix(resp.Header.Get("Location"), "/auth/") {
		t.Errorf("reauth built an off-origin target: %q", resp.Header.Get("Location"))
	}
}

// Without a session there is nothing to re-authenticate: the endpoint refuses
// rather than choosing a provider for an anonymous caller.
func TestAudit9ReauthRequiresASession(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, h.server.URL+"/auth/reauth?return_to=/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous reauth = %d, want 401", resp.StatusCode)
	}
}
