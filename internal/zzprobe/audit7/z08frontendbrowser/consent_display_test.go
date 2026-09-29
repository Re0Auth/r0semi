//go:build audit7

// Consent-screen probes: what the screen displays versus what the token actually
// carries, driven end to end through the real OP (authorize -> consent decision
// -> callback -> token) so the comparison is between two wire artefacts rather
// than between two readings of the same struct.
package z08frontendbrowser

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// protocolScopes is the set the consent screen deliberately does not render: the
// OIDC flags the catalogue does not describe (O-3 / O-6).
var protocolScopes = map[string]bool{
	"openid": true, "profile": true, "email": true, "phone": true,
	"address": true, "offline_access": true,
}

// displayedScopes asks the product what the consent screen would render for a
// pending authorization request.
func displayedScopes(t *testing.T, b *browser, requested []string) (id string, displayed []string) {
	t.Helper()
	const verifier = "verifier-verifier-verifier-verifier-verifier"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {z08ClientID},
		"redirect_uri":          {z08Redirect},
		"scope":                 {strings.Join(requested, " ")},
		"state":                 {"st"},
		"code_challenge":        {pkceSum(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp := b.get("/oauth/authorize?" + q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	id = loc.Query().Get("authRequestID")
	if id == "" {
		id = loc.Query().Get("id")
	}
	if id == "" {
		t.Fatalf("no auth request id in %q", loc)
	}
	view := b.get("/v1/authorization_requests/" + url.PathEscape(id))
	if view.StatusCode != http.StatusOK {
		t.Fatalf("consent view = %d: %s", view.StatusCode, bodyOf(t, view))
	}
	var body struct {
		Scopes []struct {
			Scope string `json:"scope"`
		} `json:"scopes"`
	}
	if err := json.NewDecoder(view.Body).Decode(&body); err != nil {
		view.Body.Close()
		t.Fatal(err)
	}
	view.Body.Close()
	for _, s := range body.Scopes {
		displayed = append(displayed, s.Scope)
	}
	if len(displayed) == 0 {
		t.Fatal("the consent view displayed no scopes at all; the comparison would be vacuous")
	}
	return id, displayed
}

// tokenScopes reads the scopes the issued access token actually carries, through
// the OP's own introspection rather than through the business plane's
// scope-rendering path: using /v1/grants here would measure the very view under
// test and could not detect a scope that view drops.
func tokenScopes(t *testing.T, env *z08Env, access string) []string {
	t.Helper()
	info, err := env.op.Introspect(context.Background(), access)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if !info.Active {
		t.Fatalf("the token the flow just issued is not active: %+v", info)
	}
	out := make([]string, 0, len(info.Scopes))
	for _, s := range info.Scopes {
		out = append(out, s.String())
	}
	return out
}

// TestZ08ConsentScreenDisplaysEveryDescribedScopeItGrantsOnce approves a request
// the way the SPA does - sending back exactly the displayed set - and compares
// the granted set against what the screen displayed. Everything granted beyond
// the display must be a protocol flag the catalogue deliberately does not
// describe.
func TestZ08ConsentScreenDisplaysEveryDescribedScopeItGrantsOnce(t *testing.T) {
	env := newZ08Env(t, z08Options{})
	b := env.newBrowser()
	b.signIn()

	requested := []string{"account.id", "phigros.profile.read", "openid"}
	_, displayed := displayedScopes(t, b, requested)
	t.Logf("displayed: %v", displayed)

	tokens := b.z08CodeFlow(t, requested, displayed)
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %v", tokens)
	}
	granted := tokenScopes(t, env, access)
	t.Logf("granted: %v", granted)

	if len(granted) == 0 {
		t.Fatal("introspection reported no scopes; the comparison would be vacuous")
	}
	seen := map[string]bool{}
	for _, s := range displayed {
		seen[s] = true
	}
	for _, g := range granted {
		if protocolScopes[g] || seen[g] {
			continue
		}
		t.Errorf("the token carries %q, which the consent screen never displayed: "+
			"the screen shows %v and the grant is %v", g, displayed, granted)
	}
}

// TestZ08ConsentScreenCannotShowLessThanItGrantsWhenTheTwoRegistriesDiffer is the
// shape above with the registries deliberately out of step: the authorization
// engine knows a scope the business plane's registry (httpapi.Config.Scopes, the
// one scopeViews renders through) does not.
//
// It is not reachable from cmd/re0auth today, which passes the same
// oauth.DefaultRegistry to both. It is here because nothing pins that equality,
// and the failure mode is the one this screen exists to prevent.
func TestZ08ConsentScreenCannotShowLessThanItGrantsWhenTheTwoRegistriesDiffer(t *testing.T) {
	reg, err := oauth.NewRegistry(append(oauth.DefaultDescriptors(), oauth.Descriptor{
		Scope:       "z08.extra.read",
		Title:       "Z08 extra",
		Description: "a described scope the business registry does not know about",
		Risk:        oauth.RiskHigh,
	})...)
	if err != nil {
		t.Fatal(err)
	}
	env := newZ08Env(t, z08Options{
		OPRegistry:   reg,
		ClientScopes: []oauth.Scope{"account.id", "z08.extra.read"},
		// Config.Scopes is left at the package default on purpose.
	})
	b := env.newBrowser()
	b.signIn()

	requested := []string{"account.id", "z08.extra.read"}
	_, displayed := displayedScopes(t, b, requested)
	t.Logf("displayed: %v", displayed)

	// The documented "omit scopes to grant the whole request" form, which is what
	// a non-SPA caller uses.
	tokens := b.z08CodeFlow(t, requested, nil)
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %v", tokens)
	}
	granted := tokenScopes(t, env, access)
	t.Logf("granted: %v", granted)

	seen := map[string]bool{}
	for _, s := range displayed {
		seen[s] = true
	}
	for _, g := range granted {
		if protocolScopes[g] || seen[g] {
			continue
		}
		t.Errorf("the token carries %q while the consent screen displayed %v: a described scope the "+
			"business plane's registry does not know is silently omitted from the screen (scopeViews() "+
			"skips it) and then granted anyway when the scopes field is omitted", g, displayed)
	}
}

// TestZ08ConsentDecisionCannotWidenTheRequest is the positive control for the
// two probes above: the decision endpoint is not a way to add a permission.
func TestZ08ConsentDecisionCannotWidenTheRequest(t *testing.T) {
	env := newZ08Env(t, z08Options{})
	b := env.newBrowser()
	b.signIn()

	requested := []string{"account.id", "openid"}
	id, _ := displayedScopes(t, b, requested)

	body, _ := json.Marshal(map[string]any{
		"decision": "approve",
		"scopes":   []string{"account.id", "phigros.profile.read"},
	})
	resp := b.do(http.MethodPost, "/v1/authorization_requests/"+url.PathEscape(id)+"/decision",
		string(body), map[string]string{"Content-Type": "application/json", "X-CSRF-Token": b.csrf()})
	raw := bodyOf(t, resp)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a decision that named a scope the client never requested was accepted: %s", raw)
	}
	t.Logf("widening decision -> %d %s", resp.StatusCode, raw)
}
