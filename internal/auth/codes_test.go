package auth

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
)

// Every code the login plane can redirect with must have a sentence in the SPA's
// message map.
//
// The two lists live in different languages and they HAD drifted: a provider
// refusal redirected `denied` while the map — and the documented contract, and the
// browser suite — read `access_denied`, so a person who cancelled a login got the
// generic "登录没有完成（denied）。" with a raw code in it. Nothing in this package
// pinned the value, which is how it survived.
//
// The map is read from the source rather than duplicated here on purpose: a copy in
// Go would be a third list to keep in sync, which is the problem, not the fix.
func TestLoginFailureCodesAreExplainedByTheFrontend(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "routes", "+page.svelte"))
	if err != nil {
		t.Fatalf("read the SPA's message map: %v", err)
	}
	page := string(raw)

	if len(redirectCodes) < 5 {
		t.Fatalf("only %d redirect codes are declared; this test would be nearly vacuous", len(redirectCodes))
	}
	for _, code := range redirectCodes {
		if !strings.Contains(page, "'"+code+"'") {
			t.Errorf("the login plane redirects error=%s, which +page.svelte has no sentence for "+
				"(a person would see the raw code)", code)
		}
	}
}

// Every code this package can put in an audit record or a metric label must be
// classified, so a new one cannot silently land in the "denied" bucket.
func TestEveryLoginCodeHasAnOutcome(t *testing.T) {
	for _, code := range redirectCodes {
		if _, ok := loginCodes[code]; !ok {
			t.Errorf("redirect code %q has no audit outcome", code)
		}
	}
	for _, code := range []string{codeUnknownProvider, codeInvalidState, codeProviderMismatch} {
		if _, ok := loginCodes[code]; !ok {
			t.Errorf("audit-only code %q has no audit outcome", code)
		}
	}
	if got := outcomeFor("a_code_nobody_classified"); got == "denied" {
		t.Fatal("an unclassified code is reported as a denial")
	}
}

// A provider that refuses comes back with `error`, not a code, and the person has
// to end up somewhere that explains it — with the documented code in the URL, which
// is what the SPA and the browser suite both read.
func TestProviderDenialRedirectsWithTheDocumentedCode(t *testing.T) {
	h := newHarness(t)

	resp := h.get(t, h.server.URL+"/auth/github/start?return_to=/app/sources")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d", resp.StatusCode)
	}
	state := stateOf(t, resp)
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/github/callback?error=access_denied&state="+state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("denied callback status = %d, want a redirect back", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error="+codeAccessDenied) {
		t.Fatalf("Location = %q, want error=%s", loc, codeAccessDenied)
	}

	// A refused login creates nothing: no account for the provider's subject, and
	// no session.
	if _, err := h.accounts.FindByIdentity(context.Background(), idp.GitHub, "42"); err == nil {
		t.Fatal("a refused login created an account")
	}
	resp = h.get(t, h.server.URL+"/whoami")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("/whoami = %d after a refused login, want no session", resp.StatusCode)
	}
}
