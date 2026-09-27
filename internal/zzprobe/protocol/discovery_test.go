//go:build audit5

package protocol

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// PROBE 15 — `response_mode=form_post` is accepted, and the authorization
// response it produces carries no RFC 9207 `iss`.
//
// ADR-0005 point 6 requires the authorization response to carry `iss` "成功与失败都带"
// and the discovery document advertises
// `authorization_response_iss_parameter_supported: true`
// (internal/oidchttp/oidchttp.go stripUnsupportedDiscoveryFields). The wrapper adds
// it only to a 3xx redirect (`isAuthorizationResponse(...) && bw.status >= 300 &&
// bw.status < 400`), while the library renders a 200 HTML page for form_post
// (pkg/op/auth_request.go AuthResponseCode -> handleFormPostResponse). So the one
// client that negotiated `iss` for mix-up protection gets a response without it —
// and discovery never advertises `response_modes_supported` at all, so the same
// client cannot discover that form_post exists.
func TestProbeFormPostAuthorizationResponseHasNoIss(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	authz := authValues(e, "https://client.example/cb", []string{"account.id"})
	authz.Set("response_mode", "form_post")
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d %s", resp.StatusCode, bodyOf(t, resp))
	}
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
	page := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the form_post callback = %d: %s", resp.StatusCode, page)
	}
	if !strings.Contains(string(page), "<form") {
		t.Fatalf("the callback did not render a form, so this probe is aimed at nothing: %s", page)
	}
	if !strings.Contains(string(page), "code") || !strings.Contains(string(page), "state") {
		t.Fatalf("the form does not carry the authorization response: %s", page)
	}
	if strings.Contains(string(page), "iss") {
		t.Skipf("the form_post response now carries iss: %s", page)
	}
	t.Errorf("the form_post authorization response has no `iss` parameter while discovery advertises iss support: %s", page)

	// Control for the shape: the same request in the default (query) mode is a
	// redirect that DOES carry iss, which is why the wrapper's condition is the seam.
	control := authValues(e, "https://client.example/cb", []string{"account.id"})
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+control.Encode())
	login, err = parseLocation(t, resp)
	if err != nil {
		t.Fatal(err)
	}
	id = login.Query().Get("authRequestID")
	if err := e.store.CompleteLogin(t.Context(), id, "usr_probe", []string{"account.id"}); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+urlQueryEscape(id))
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "iss=") {
		t.Fatalf("control failed: the query-mode redirect has no iss either: %q", loc)
	}
	t.Logf("query mode: %s", loc)
}

// PROBE 16 — `prompt=none` is not implemented anywhere.
//
// OIDC Core 1.0 §3.1.2.1: when `prompt=none` is sent and the End-User is not
// already authenticated, the OP MUST return `error=login_required` to the client.
// Nothing in this repository mentions `prompt` at all
// (`grep -r 'prompt' internal/` finds only the library's own prompt handling, which
// merely maps `prompt=login` to max_age=0 — pkg/op/auth_request.go
// ValidateAuthReqPrompt), so the request is treated as an ordinary interactive one
// and the browser is sent to the login page. A client doing silent
// authentication with a hidden iframe therefore renders the OP's login page inside
// the frame and never receives an error.
func TestProbePromptNoneIsIgnored(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	withPrompt := authValues(e, "https://client.example/cb", []string{"account.id"})
	withPrompt.Set("prompt", "none")
	withPrompt.Set("state", "state-probe-none")
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+withPrompt.Encode())
	loc := resp.Header.Get("Location")
	t.Logf("prompt=none answered %d %q", resp.StatusCode, loc)

	if resp.StatusCode == http.StatusFound && strings.HasPrefix(loc, "/login?") {
		t.Errorf("prompt=none redirected the browser to the interactive login page instead of error=login_required: %q", loc)
	}
	if strings.Contains(loc, "login_required") {
		t.Skipf("prompt=none is now answered with login_required: %q", loc)
	}

	// The control: the same request without prompt reaches the login plane, so the
	// finding is that `prompt` changed nothing.
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+
		authValues(e, "https://client.example/cb", []string{"account.id"}).Encode())
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?") {
		t.Fatalf("control failed: a plain authorize no longer reaches the login plane: %d %q",
			resp.StatusCode, resp.Header.Get("Location"))
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
