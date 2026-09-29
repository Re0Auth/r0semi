//go:build audit7

// Zone-10 guards: who gets into the operator plane, and how the plane behaves
// when the allowlist is a near miss.
package z10adminauditprivacy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
)

// TestZ10AdminAllowlistIsAnExactMatchNotACaseFoldOrPrefix.
//
// The allowlist is a map lookup on the session's account id, so nothing about it
// should fold case, trim whitespace or match a prefix. This probe puts near
// misses in the allowlist instead of the real id: if any of them matched, the
// operator would get in, and that would be a self-inflicted privilege escalation
// from a typo or a copy-paste.
func TestZ10AdminAllowlistIsAnExactMatchNotACaseFoldOrPrefix(t *testing.T) {
	env := newProbeEnv(t, probeOptions{
		AdminsFunc: func(u account.UserID) []account.UserID {
			return []account.UserID{
				account.UserID(strings.ToUpper(string(u))),
				account.UserID(" " + string(u)),
				account.UserID(string(u) + " "),
				account.UserID(string(u) + "x"),
				account.UserID(string(u)[:len(u)-1]),
			}
		},
	})
	b := env.newBrowser()
	if got := b.signIn(adminUpstream); got != string(env.adminUser) {
		t.Fatalf("signed in as %q, want %q", got, env.adminUser)
	}
	resp := b.get("/v1/admin/clients")
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /v1/admin/clients = %d (%s) for an account whose id is only a near miss of every allowlist "+
			"entry (upper case, surrounding space, prefix, suffix): the allowlist is not an exact match",
			resp.StatusCode, strings.TrimSpace(body))
	}

	// Control: the very same request succeeds when the allowlist holds the real id.
	ok := newProbeEnv(t, probeOptions{})
	ob := ok.newBrowser()
	if got := ob.signIn(adminUpstream); got != string(ok.adminUser) {
		t.Fatalf("control sign-in: got %q, want %q", got, ok.adminUser)
	}
	resp = ob.get("/v1/admin/clients")
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("control: GET /v1/admin/clients = %d (%s), want 200", resp.StatusCode, body)
	}
}

// TestZ10EveryAdminRouteIsShutToAnonymousAndNonAdmins.
//
// One probe per population per route family, with the operator's own 200 as the
// positive control: without that control a "404/401" result would also be
// produced by a route that is simply not mounted.
func TestZ10EveryAdminRouteIsShutToAnonymousAndNonAdmins(t *testing.T) {
	reader := &probeAuditReader{
		page:         audit.Page{Entries: []audit.Entry{}, Limit: 10},
		verification: audit.Verification{OK: true},
		head:         []byte{0x01},
	}
	env := newProbeEnv(t, probeOptions{AuditReader: reader})

	routes := []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/clients"},
		{http.MethodPost, "/v1/admin/clients"},
		{http.MethodPost, "/v1/admin/clients/cli/suspend"},
		{http.MethodPost, "/v1/admin/clients/cli/activate"},
		{http.MethodPost, "/v1/admin/clients/cli/rotate_secret"},
		{http.MethodDelete, "/v1/admin/clients/cli"},
		{http.MethodPost, "/v1/admin/kill_switch"},
		{http.MethodGet, "/v1/admin/audit"},
		{http.MethodGet, "/v1/admin/audit/verify"},
		{http.MethodGet, "/v1/admin/audit/head"},
	}

	// Anonymous.
	anon := env.newBrowser()
	for _, rt := range routes {
		resp := anon.do(rt.method, rt.path, "{}", nil)
		body := bodyOf(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s = %d (%s), want 401", rt.method, rt.path, resp.StatusCode, strings.TrimSpace(body))
		}
	}

	// Signed in, not an operator.
	other := env.newBrowser()
	otherID := other.signIn("not-an-operator")
	if otherID == string(env.adminUser) {
		t.Fatalf("the second identity resolved to the operator account %q", otherID)
	}
	csrf := other.csrf()
	for _, rt := range routes {
		resp := other.do(rt.method, rt.path, "{}", jsonHeaders(csrf))
		body := bodyOf(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("non-admin %s %s = %d (%s), want 404: the plane must not be advertised to a signed-in "+
				"account that cannot use it (docs/admin.md §0)", rt.method, rt.path, resp.StatusCode, strings.TrimSpace(body))
			continue
		}
		if !strings.Contains(body, "unknown resource") {
			t.Errorf("non-admin %s %s = 404 but the body is %q, want the same problem+json an unknown path gets",
				rt.method, rt.path, strings.TrimSpace(body))
		}
	}

	// Control: the operator reaches the handlers. GET is enough to prove the
	// routes are mounted and the gate is what refused the others.
	admin := env.newBrowser()
	if got := admin.signIn(adminUpstream); got != string(env.adminUser) {
		t.Fatalf("signed in as %q, want %q", got, env.adminUser)
	}
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/clients"},
		{http.MethodGet, "/v1/admin/audit"},
		{http.MethodGet, "/v1/admin/audit/verify"},
		{http.MethodGet, "/v1/admin/audit/head"},
	} {
		resp := admin.do(rt.method, rt.path, "", nil)
		body := bodyOf(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("control: operator %s %s = %d (%s), want 200", rt.method, rt.path, resp.StatusCode, strings.TrimSpace(body))
		}
	}

	// Observation, not an assertion: an undeclared verb is answered by the
	// business-plane dispatch before any gate runs, so even an anonymous caller
	// gets 405 plus the route's Allow set instead of the documented 401/404.
	// (This is round-5 AUD-4; it is recorded here as still-live context, not as a
	// new finding.)
	for _, rt := range []struct{ method, path string }{
		{http.MethodPut, "/v1/admin/clients"},
		{http.MethodPatch, "/v1/admin/audit"},
		{http.MethodDelete, "/v1/admin/kill_switch"},
	} {
		resp := anon.do(rt.method, rt.path, "", nil)
		_ = bodyOf(t, resp)
		t.Logf("context: anonymous %s %s = %d Allow=%q", rt.method, rt.path, resp.StatusCode, resp.Header.Get("Allow"))
	}
}
