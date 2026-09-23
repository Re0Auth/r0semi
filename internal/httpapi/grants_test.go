package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// grantFlow runs the whole browser round trip — sign in, authorize, consent,
// exchange — and returns the account id plus the tokens the client ended up with.
//
// The grants tests therefore read access that was really issued through the
// protocol, rather than token rows written by hand into a store: a grant derived
// from fabricated rows would prove nothing about whether the real flow produces
// one.
func grantFlow(t *testing.T, browser *http.Client, base, verifier, scope string) (string, string, string) {
	t.Helper()
	handle := authorize(t, browser, base, verifier, scope, "st-grant")

	view := decodeResp(t, getURL(t, browser, base+"/v1/authorization_requests/"+handle))
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("no CSRF token in the consent view: %v", view)
	}

	body, _ := json.Marshal(map[string]any{"decision": "approve", "scopes": strings.Fields(scope)})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/authorization_requests/"+handle+"/decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	decided := decodeResp(t, doReq(t, browser, req))

	redirectTo, _ := decided["redirect_to"].(string)
	if strings.HasPrefix(redirectTo, "/") {
		redirectTo = base + redirectTo
	}
	cbResp := getURL(t, browser, redirectTo)
	target, err := url.Parse(cbResp.Header.Get("Location"))
	cbResp.Body.Close()
	if err != nil || target.Query().Get("code") == "" {
		t.Fatalf("no authorization code in %q (error %v)", redirectTo, err)
	}

	resp, err := http.PostForm(base+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cli"},
		"code":          {target.Query().Get("code")},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://app.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange = %d", resp.StatusCode)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("token response carried no access token")
	}
	return tokens.AccessToken, tokens.Scope, csrf
}

func currentUserID(t *testing.T, browser *http.Client, base string) string {
	t.Helper()
	view := decodeResp(t, getURL(t, browser, base+"/v1/sessions/current"))
	id, _ := view["user_id"].(string)
	if id == "" {
		t.Fatalf("no user id in the session view: %v", view)
	}
	return id
}

func grantsOf(t *testing.T, browser *http.Client, base string) []map[string]any {
	t.Helper()
	resp := getURL(t, browser, base+"/v1/grants")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/grants = %d", resp.StatusCode)
	}
	body := decodeResp(t, resp)
	data, ok := body["data"].([]any)
	if !ok {
		t.Fatalf("grants body has no data array: %v", body)
	}
	out := make([]map[string]any, 0, len(data))
	for _, item := range data {
		g, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("grant entry is not an object: %v", item)
		}
		out = append(out, g)
	}
	return out
}

// The grants view is the account page's, and it names the user's other clients.
// A client asking with its own token must not be able to read it.
func TestGrantsRequireASession(t *testing.T) {
	base, _ := newFlowEnv(t)
	resp := getURL(t, newBrowser(t), base+"/v1/grants")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /v1/grants = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGrantsListsWhatWasGranted(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)

	// Nothing granted yet: an empty array, not null. A client that has to special
	// case "the list is missing" for an empty list is a client that will get it
	// wrong.
	resp := getURL(t, browser, base+"/v1/grants")
	raw := decodeResp(t, resp)
	if _, ok := raw["data"].([]any); !ok {
		t.Fatalf("empty grants = %v, want an empty array", raw)
	}
	if len(grantsOf(t, browser, base)) != 0 {
		t.Fatal("a grant appeared before anything was authorized")
	}

	_, scope, _ := grantFlow(t, browser, base, "verifier-verifier-verifier-verifier", "account.id phigros.score.read")
	if !strings.Contains(scope, "account.id") {
		t.Fatalf("scope = %q", scope)
	}

	grants := grantsOf(t, browser, base)
	if len(grants) != 1 {
		t.Fatalf("grants = %v, want one", grants)
	}
	g := grants[0]
	if g["client_id"] != "cli" || g["client_name"] != "Phi CLI" {
		t.Errorf("grant names the wrong client: %v", g)
	}
	if g["has_refresh"] != true {
		t.Errorf("has_refresh = %v, want true", g["has_refresh"])
	}
	scopes, _ := g["scopes"].([]any)
	if len(scopes) != 2 {
		t.Fatalf("grant scopes = %v", scopes)
	}
	// The view carries the catalogue's wording, so the page can explain itself
	// without a second lookup.
	first, _ := scopes[0].(map[string]any)
	if first["description"] == "" {
		t.Errorf("scope view is missing its catalogue text: %v", first)
	}
}

func TestRevokeGrantRequiresCSRF(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)
	grantFlow(t, browser, base, "verifier-verifier-verifier-verifier", "account.id")

	req, _ := http.NewRequest(http.MethodDelete, base+"/v1/grants/cli", nil)
	resp := doReq(t, browser, req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE without CSRF = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	if len(grantsOf(t, browser, base)) != 1 {
		t.Fatal("a refused revocation still revoked something")
	}
}

func TestRevokeGrantEndsTheAccess(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)
	access, _, csrf := grantFlow(t, browser, base, "verifier-verifier-verifier-verifier", "account.id")

	// The token works.
	me, _ := http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	me.Header.Set("Authorization", "Bearer "+access)
	if resp := doReq(t, browser, me); resp.StatusCode != http.StatusOK {
		t.Fatalf("the token did not work before revocation: %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	revoke, _ := http.NewRequest(http.MethodDelete, base+"/v1/grants/cli", nil)
	revoke.Header.Set("X-CSRF-Token", csrf)
	if resp := doReq(t, browser, revoke); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /v1/grants/cli = %d, want 204", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// The token does not, which is what makes "revoked" mean something.
	again, _ := http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	again.Header.Set("Authorization", "Bearer "+access)
	if resp := doReq(t, browser, again); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a revoked token still worked: %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	if len(grantsOf(t, browser, base)) != 0 {
		t.Fatal("the grant is still listed after revocation")
	}

	// Idempotent: revoking again is the same answer, so a retry after a dropped
	// response is not an error the caller has to reason about.
	repeat, _ := http.NewRequest(http.MethodDelete, base+"/v1/grants/cli", nil)
	repeat.Header.Set("X-CSRF-Token", csrf)
	if resp := doReq(t, browser, repeat); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("second DELETE = %d, want 204", resp.StatusCode)
	} else {
		resp.Body.Close()
	}
}

// Revoking a client that holds nothing must not disturb the one that does. The
// endpoint cannot tell "you have no grant with them" from "already revoked", and
// it should not try: both mean the caller is done.
func TestRevokeGrantIgnoresClientsWithNothingToRevoke(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)
	access, _, csrf := grantFlow(t, browser, base, "verifier-verifier-verifier-verifier", "account.id")

	revoke, _ := http.NewRequest(http.MethodDelete, base+"/v1/grants/someone-else", nil)
	revoke.Header.Set("X-CSRF-Token", csrf)
	if resp := doReq(t, browser, revoke); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoking an unrelated client = %d, want 204", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	me, _ := http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	me.Header.Set("Authorization", "Bearer "+access)
	if resp := doReq(t, browser, me); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoking an unrelated client broke this one: %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}
}
