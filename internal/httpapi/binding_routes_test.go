package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/oauth"
)

// connectSource runs the whole bind flow through the browser-facing endpoints and
// returns the account id. The bindings tests therefore read a binding that the
// real flow produced, not one written into a store by hand.
func connectSource(t *testing.T, base string, client *http.Client) string {
	t.Helper()
	resp := getURL(t, client, base+"/bind?game=phigros&source=fake&return_to=/app/sources")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("bind start = %d", resp.StatusCode)
	}
	authorizeURL := resp.Header.Get("Location")
	resp.Body.Close()

	resp = getURL(t, client, authorizeURL)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("upstream authorize = %d", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")
	resp.Body.Close()

	resp = getURL(t, client, callbackURL)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("bind callback = %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/app/sources" {
		t.Fatalf("return = %q", loc)
	}
	resp.Body.Close()
	return ""
}

func bindingsOf(t *testing.T, base string, client *http.Client) []map[string]any {
	t.Helper()
	resp := getURL(t, client, base+"/v1/bindings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/bindings = %d", resp.StatusCode)
	}
	body := decodeResp(t, resp)
	data, ok := body["data"].([]any)
	if !ok {
		t.Fatalf("bindings body has no data array: %v", body)
	}
	out := make([]map[string]any, 0, len(data))
	for _, item := range data {
		b, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("binding entry is not an object: %v", item)
		}
		out = append(out, b)
	}
	return out
}

// The bindings view names the account's connections. A client asking with its own
// token has no business reading it.
func TestBindingsRequireASession(t *testing.T) {
	base, _, _, _, _, _, _ := newBindEnv(t)
	resp := getURL(t, newBrowser(t), base+"/v1/bindings")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /v1/bindings = %d, want 401", resp.StatusCode)
	}
}

func TestBindingsShowWhatIsConnected(t *testing.T) {
	base, client, _, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)

	// Nothing connected: an empty array, not null.
	resp := getURL(t, client, base+"/v1/bindings")
	if _, ok := decodeResp(t, resp)["data"].([]any); !ok {
		t.Fatal("empty bindings was not an array")
	}

	connectSource(t, base, client)

	bindings := bindingsOf(t, base, client)
	if len(bindings) != 1 {
		t.Fatalf("bindings = %v, want one", bindings)
	}
	got := bindings[0]
	if got["game"] != "phigros" || got["source"] != "fake" {
		t.Errorf("binding names the wrong source: %v", got)
	}
	// The name comes from this deployment's registry, so a source cannot rename
	// itself on a page the user is asked to trust.
	if got["display_name"] != "Fake" {
		t.Errorf("display_name = %v, want the registry's name", got["display_name"])
	}
	if got["token_class"] != "revocable" {
		t.Errorf("token_class = %v", got["token_class"])
	}
	// And crucially, no credential is anywhere in the payload.
	for key := range got {
		switch key {
		case "access_token", "refresh_token", "token", "secret":
			t.Errorf("the bindings view leaked a credential under %q", key)
		}
	}
}

func TestUnbindRequiresCSRF(t *testing.T) {
	base, client, _, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)
	connectSource(t, base, client)

	req, _ := http.NewRequest(http.MethodDelete, base+"/v1/bindings/phigros/fake", nil)
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE without CSRF = %d, want 403", resp.StatusCode)
	}
	if len(bindingsOf(t, base, client)) != 1 {
		t.Fatal("a refused unbind still disconnected something")
	}
}

func TestUnbindDisconnectsAndReportsTheSource(t *testing.T) {
	base, client, accounts, _, h, store, _ := newBindEnv(t)
	signIn(t, client, base)
	connectSource(t, base, client)

	uid, err := accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}
	at := mintToken(t, h, store, "cli", string(uid), oauth.ScopePhigrosProfile)

	// The data plane works while connected.
	if resp := authedGet(t, base+"/v1/games/phigros/profile", at); resp.StatusCode != http.StatusOK {
		t.Fatalf("profile before unbind = %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	csrf := sessionCSRF(t, base, client)
	req, _ := http.NewRequest(http.MethodDelete, base+"/v1/bindings/phigros/fake", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	resp := doReq(t, client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /v1/bindings/phigros/fake = %d, want 200", resp.StatusCode)
	}
	// 200 with a body, not 204: the source's half of the job is part of the
	// answer, and reporting a bare success would overstate what happened.
	body := decodeResp(t, resp)
	if body["upstream"] != "done" {
		t.Fatalf("upstream = %v (%v), want done", body["upstream"], body["upstream_error"])
	}

	if len(bindingsOf(t, base, client)) != 0 {
		t.Fatal("the binding is still listed after disconnecting")
	}

	// And the data plane says so, which is what makes it a real disconnection.
	resp = authedGet(t, base+"/v1/games/phigros/profile", at)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("profile after unbind = %d, want 409 source_not_bound", resp.StatusCode)
	}
	problem := decodeResp(t, resp)
	if problem["code"] != "source_not_bound" || problem["bind_url"] == "" {
		t.Fatalf("problem = %v, want a bind_url to send the user back", problem)
	}
}

func TestUnbindUnknownSourceAndUnknownBinding(t *testing.T) {
	base, client, _, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)
	csrf := sessionCSRF(t, base, client)

	// A source this deployment does not have.
	req, _ := http.NewRequest(http.MethodDelete, base+"/v1/bindings/phigros/nope", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	resp := doReq(t, client, req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown source = %d, want 404", resp.StatusCode)
	}

	// A source it does have, with nothing bound. Not an error: the state the
	// caller asked for already holds.
	req, _ = http.NewRequest(http.MethodDelete, base+"/v1/bindings/phigros/fake", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	resp = doReq(t, client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nothing bound = %d, want 200", resp.StatusCode)
	}
	if body := decodeResp(t, resp); body["upstream"] != "nothing" {
		t.Fatalf("upstream = %v, want nothing", body["upstream"])
	}
}

// sessionCSRF reads the token the frontend would send on a write.
func sessionCSRF(t *testing.T, base string, client *http.Client) string {
	t.Helper()
	view := decodeResp(t, getURL(t, client, base+"/v1/sessions/current"))
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("no CSRF token in the session view: %v", view)
	}
	return csrf
}
