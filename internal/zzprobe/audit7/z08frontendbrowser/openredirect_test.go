//go:build audit7

// Z08V-1: the browser plane's open-redirect surface, probed where it can
// actually be reached.
//
// The probe that used to claim this (TestZ08RealProcessOpenRedirectSurface, in
// realproc_test.go) drove the memory-mode binary with hostile return_to values.
// That binary has no identity provider configured, so every one of those
// requests was answered 404 and the flow never reached the redirect sink; the
// assertion about Location was green no matter what the sink did. This file
// probes the same property on the fully wired fixture — httpapi.New + Config with
// internal/testoidc as the configured provider — so start -> provider callback ->
// final 303 really runs, and a benign return_to proves the sink is reached before
// any hostile value is tried.
package z08frontendbrowser

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// z08SignInWithReturnTo drives the real /auth/<provider> flow with an explicit
// return_to, exactly as a browser would: start, echo the provider nonce, callback.
// It returns the server's final redirect Location — the redirect sink under test.
func z08SignInWithReturnTo(t *testing.T, b *browser, returnTo string) string {
	t.Helper()
	target := "/auth/" + string(z08Provider) + "/start?return_to=" + url.QueryEscape(returnTo)
	resp := b.get(target)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start (return_to=%q) = %d (%s), want 302", returnTo, resp.StatusCode, bodyOf(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	b.env.oidc.SetNonce(loc.Query().Get("nonce"))
	state := loc.Query().Get("state")
	resp.Body.Close()
	if state == "" {
		t.Fatalf("start (return_to=%q): the authorize URL carried no state", returnTo)
	}

	resp = b.get("/auth/" + string(z08Provider) + "/callback?code=c&state=" + url.QueryEscape(state))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback (return_to=%q) = %d (%s), want 303", returnTo, resp.StatusCode, bodyOf(t, resp))
	}
	out := resp.Header.Get("Location")
	resp.Body.Close()
	return out
}

// TestZ08OpenRedirectSurfaceOnTheAuthFlow completes the real login flow with
// hostile return_to values and asserts the final redirect stays on this origin.
//
// The positive control runs first: a benign return_to must come back out of the
// callback in the Location. Without it, every hostile case could pass by never
// reaching a redirect at all — the exact fake-green the real-process version was.
func TestZ08OpenRedirectSurfaceOnTheAuthFlow(t *testing.T) {
	env := newZ08Env(t, z08Options{})
	base, err := url.Parse(env.server.URL)
	if err != nil {
		t.Fatal(err)
	}

	benign := z08SignInWithReturnTo(t, env.newBrowser(), "/app/consent?id=abc")
	t.Logf("benign return_to -> Location %q", benign)
	if !strings.Contains(benign, "/app/consent") || !strings.Contains(benign, "id=abc") {
		t.Fatalf("positive control failed: a benign return_to did not survive the flow (Location %q), so the "+
			"hostile cases below would not be testing the redirect sink at all", benign)
	}

	for _, hostile := range []string{
		"//evil.example",
		"///evil.example/x",
		"https://evil.example/x",
		`/\\evil.example`,
		"/%09/evil.example",
		"javascript:alert(1)",
		"//evil.example/%2e%2e/x",
		"http://evil.example:80/x",
	} {
		loc := z08SignInWithReturnTo(t, env.newBrowser(), hostile)
		resolved, err := url.Parse(loc)
		if err != nil {
			t.Errorf("return_to %q produced an unparsable Location %q: %v", hostile, loc, err)
			continue
		}
		// The property is "still this origin", not "the bytes are gone": a value
		// like `/%09/evil.example` legitimately survives as a same-origin path (the
		// tab is inside the path, not a second slash), so a substring heuristic
		// would flag a redirect that cannot leave the origin. Resolving the
		// Location against the server's own URL is the actual question.
		abs := base.ResolveReference(resolved)
		if !strings.EqualFold(abs.Host, base.Host) {
			t.Errorf("return_to %q produced Location %q, which resolves to host %q: the login redirect left "+
				"this origin", hostile, loc, abs.Host)
		}
		if strings.HasPrefix(strings.TrimSpace(loc), "javascript:") {
			t.Errorf("return_to %q produced a javascript: Location %q", hostile, loc)
		}
		t.Logf("return_to %-28q -> Location %q", hostile, loc)
	}
}
