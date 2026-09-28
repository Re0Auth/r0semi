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
