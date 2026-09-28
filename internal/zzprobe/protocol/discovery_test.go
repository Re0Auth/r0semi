//go:build audit5

package protocol

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// PROBE 15 (FIXED) — `response_mode=form_post` is refused, so every authorization
// response this server produces can carry RFC 9207 `iss`.
//
// Was: form_post was accepted and the library rendered it as a 200 HTML form,
// which the `iss` annotation (a Location-header rewrite) never reached, while the
// discovery document advertised `authorization_response_iss_parameter_supported`.
// ADR-0005 §6 requires the authorization response to carry `iss` and §5 requires
// the document to advertise only real capabilities; both are satisfied by offering
// only `query` and refusing the rest. This is now a positive guard: form_post is
// refused through the registered redirect with `iss` on the refusal, and the
// default query mode still succeeds carrying `iss`.
func TestProbeFormPostIsRefusedSoEveryResponseCarriesIss(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	authz := authValues(e, "https://client.example/cb", []string{"account.id"})
	authz.Set("response_mode", "form_post")
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize with response_mode=form_post = %d, want a 302 refusal: %s",
			resp.StatusCode, bodyOf(t, resp))
	}
	loc, err := parseLocation(t, resp)
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("refusal error = %q, want invalid_request", got)
	}
	// ADR-0005 §6: failures carry `iss` too.
	if loc.Query().Get("iss") == "" {
		t.Error("the form_post refusal carries no `iss`, which ADR-0005 §6 requires on failures as well")
	}
	// And it must never have reached the login/consent handoff.
	if strings.Contains(resp.Header.Get("Location"), "authRequestID=") {
		t.Error("the refused request still allocated a pending auth request and started the login handoff")
	}

	// Control for the shape: the default (query) mode completes and its
	// authorization response carries `iss` — the property form_post could not meet.
	control := authValues(e, "https://client.example/cb", []string{"account.id"})
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+control.Encode())
	login, err := parseLocation(t, resp)
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %q", resp.Header.Get("Location"))
	}
	if err := e.store.CompleteLogin(t.Context(), id, "usr_probe", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+urlQueryEscape(id))
	loc, err = parseLocation(t, resp)
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("the query-mode callback carried no code: %s", resp.Header.Get("Location"))
	}
	if loc.Query().Get("iss") == "" {
		t.Errorf("the query-mode authorization response carries no `iss`: %s", resp.Header.Get("Location"))
	}
}

// PROBE 16 (FIXED) — `prompt=none` now returns `login_required` when there is no
// session, instead of sending an interactive client to the login page.
//
// Was: nothing in the repository read `prompt`, so a silent authorization request
// was treated as an ordinary interactive one and the browser was redirected to
// /login?… — a hidden-iframe RP rendered the OP's login page inside the frame and
// never received an error (and left a 30-minute pending request behind). OIDC Core
// 1.0 §3.1.2.1 requires `error=login_required` to the client when the End-User is
// not already authenticated.
func TestProbePromptNoneReturnsLoginRequired(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	withPrompt := authValues(e, "https://client.example/cb", []string{"account.id"})
	withPrompt.Set("prompt", "none")
	withPrompt.Set("state", "state-probe-none")
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+withPrompt.Encode())
	loc := resp.Header.Get("Location")
	t.Logf("prompt=none answered %d %q", resp.StatusCode, loc)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("prompt=none = %d, want a 302 back to the client", resp.StatusCode)
	}
	redirect, err := parseLocation(t, resp)
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Host != "client.example" {
		t.Fatalf("prompt=none redirected to %q, want the registered client", redirect.Host)
	}
	if got := redirect.Query().Get("error"); got != "login_required" {
		t.Errorf("prompt=none error = %q, want login_required (no session)", got)
	}
	if redirect.Query().Get("iss") == "" {
		t.Error("the prompt=none refusal carries no `iss`; ADR-0005 §6 says failures carry it too")
	}
	if strings.HasPrefix(loc, "/login?") {
		t.Errorf("prompt=none reached the interactive login plane: %q", loc)
	}

	// Control: the same request without prompt still reaches the login plane, so
	// the refusal above is about `prompt`, not a broken authorize.
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+
		authValues(e, "https://client.example/cb", []string{"account.id"}).Encode())
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?") {
		t.Fatalf("control failed: a plain authorize no longer reaches the login plane: %d %q",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// The other half: with a live session, `prompt=none` is satisfied and proceeds to
// consent rather than returning an error.
func TestProbePromptNoneWithASessionProceeds(t *testing.T) {
	signedIn := "usr_probe"
	e := newEnv(t, envOptions{issuer: "https://issuer.probe", sessionUser: &signedIn})

	withPrompt := authValues(e, "https://client.example/cb", []string{"account.id"})
	withPrompt.Set("prompt", "none")
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+withPrompt.Encode())
	loc := resp.Header.Get("Location")
	t.Logf("prompt=none with a session answered %d %q", resp.StatusCode, loc)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("prompt=none with a session = %d, want a 302 to consent", resp.StatusCode)
	}
	if strings.Contains(loc, "error=login_required") {
		t.Errorf("prompt=none returned login_required despite a live session: %q", loc)
	}
	if !strings.Contains(loc, "authRequestID=") {
		t.Errorf("prompt=none with a session did not start the consent flow: %q", loc)
	}
}

// PROBE 17 — the discovery document's endpoint list is honest, and the JWKS holds
// no private material. This is the sweep that found PROBE 2's shape; it asserts the
// weaker property (every advertised endpoint exists and refuses an anonymous POST
// rather than 404ing) so an endpoint that is advertised but not mounted fails here.
func TestProbeAdvertisedEndpointsExistAndTheJWKSIsPublicOnly(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	resp := e.get(t, noRedirect, e.server.URL+"/.well-known/openid-configuration")
	disc := decodeJSON(t, bodyOf(t, resp))

	endpoints := []string{
		"authorization_endpoint", "token_endpoint", "introspection_endpoint",
		"userinfo_endpoint", "revocation_endpoint", "jwks_uri",
		"device_authorization_endpoint",
	}
	for _, key := range endpoints {
		raw, ok := disc[key].(string)
		if !ok || raw == "" {
			t.Fatalf("discovery does not advertise %s: %v", key, disc[key])
		}
		path := strings.TrimPrefix(raw, "https://issuer.probe")
		req, err := http.NewRequest(http.MethodPost, e.server.URL+path, strings.NewReader(""))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		probe, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := bodyOf(t, probe)
		if probe.StatusCode == http.StatusNotFound {
			t.Errorf("%s advertises %s but it is not mounted: %d %s", key, raw, probe.StatusCode, body)
		}
		// Every failure has to stay in the protocol plane's shape.
		if probe.StatusCode >= 400 {
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Errorf("%s answered a non-JSON failure: %d %s", raw, probe.StatusCode, body)
			} else if _, ok := payload["error"].(string); !ok {
				t.Errorf("%s answered outside the protocol plane's error shape: %s", raw, body)
			}
		}
	}

	// The JWKS: public parameters only.
	keysResp := e.get(t, noRedirect, e.server.URL+"/oauth/keys")
	keysBody := bodyOf(t, keysResp)
	if strings.Contains(string(keysBody), `"d"`) || strings.Contains(string(keysBody), `"p"`) ||
		strings.Contains(string(keysBody), `"q"`) || strings.Contains(string(keysBody), `"private"`) {
		t.Errorf("the JWKS looks like it carries private material: %s", keysBody)
	}
	var sets struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(keysBody, &sets); err != nil {
		t.Fatal(err)
	}
	if len(sets.Keys) == 0 {
		t.Fatalf("the JWKS is empty: %s", keysBody)
	}
	seen := map[string]bool{}
	for _, k := range sets.Keys {
		kid, _ := k["kid"].(string)
		if kid == "" {
			t.Errorf("a published key has no kid: %v", k)
		}
		if seen[kid] {
			t.Errorf("the JWKS publishes two keys with kid %q: %s", kid, keysBody)
		}
		seen[kid] = true
		if k["kty"] != "RSA" || k["alg"] != "RS256" {
			t.Errorf("a published key is not an RS256 RSA public key: %v", k)
		}
	}
}
