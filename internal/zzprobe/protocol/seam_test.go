//go:build audit5

package protocol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// PROBE 1 — the introspection allowlist is checked against a client id, and a
// PUBLIC client authenticates with no secret at all. This probe now asserts the
// refusal, because that is the property that must hold.
//
// internal/store/memory/oidc.go AuthorizeClientIDSecret returns nil for any
// secret when the client is not confidential (`c.Type == ClientConfidential &&`
// guards the only verification), and the library's introspection handler treats
// that nil as "authenticated" (pkg/op/client.go ClientBasicAuth ->
// pkg/op/token_intospection.go ParseTokenIntrospectionRequest requires
// `authenticated`). So if the deployment's resource-server allowlist names a
// public client — and nothing in the config, the docs or the wrapper's Config
// said it must not — then anyone on the network can send
//
//	Authorization: Basic base64(<public-client-id>:)
//
// and receive the full introspection record of ANY token in the deployment.
//
// The refusal has to be made at this layer: the lax `return nil` is required at the
// token endpoint, where a public client names itself and keeps no secret, so the
// endpoint that authorizes by authentication alone cannot borrow that rule
// (internal/oidchttp refuseIntrospectionByANonConfidentialClient). The control
// cases keep this non-vacuous: a confidential allowlist entry still works with its
// secret, and an unknown client id is still 401.
func TestProbeIntrospectionAllowlistWithAPublicClientIsAnonymousRead(t *testing.T) {
	// One deployment shape, two mounts: the victim's token is minted once, on the
	// mount WITHOUT the allowlist, and then introspected through both.
	denied := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	allowed := denied.withIntrospection(t, []string{denied.deviceID})

	tokens := asTokens(t, denied.codeFlow(t, []string{"openid", "account.id", "phigros.score.read"}))
	if tokens.AccessToken == "" {
		t.Fatal("no access token minted, so the probe would be vacuous")
	}

	introspect := func(e env, basicID, basicSecret string) (int, string, map[string]any) {
		t.Helper()
		resp, raw := e.postForm(t, "/oauth/introspect",
			url.Values{"token": {tokens.AccessToken}}, basicID, basicSecret)
		var payload map[string]any
		_ = json.Unmarshal(raw, &payload)
		return resp.StatusCode, string(raw), payload
	}

	// The escalation that must no longer happen: the PUBLIC client's id, with a
	// secret it does not have, and with none at all.
	for _, secret := range []string{"not-the-secret", ""} {
		status, raw, payload := introspect(allowed, allowed.deviceID, secret)
		if status == http.StatusOK && payload["active"] == true {
			t.Errorf("the public client introspected another client's token (secret %q): %s", secret, raw)
		}
		if status != http.StatusUnauthorized {
			t.Errorf("the public client's introspection answered %d (secret %q), want 401: %s", status, secret, raw)
		}
		if strings.Contains(raw, "phigros.score.read") || strings.Contains(raw, "usr_probe") {
			t.Errorf("the refusal leaked the token's facts: %s", raw)
		}
	}
	t.Logf("a public client on the allowlist is refused at /oauth/introspect")

	// Control 1: the rule is about the caller, not the list — with no allowlist the
	// same public caller is refused the same way.
	status, raw, _ := introspect(denied, denied.deviceID, "not-the-secret")
	if status != http.StatusUnauthorized {
		t.Fatalf("control failed: without the allowlist the public client got %d %s", status, raw)
	}

	// Control 2: the honest path still works, so the endpoint is not simply closed
	// — a CONFIDENTIAL client introspects its own token.
	status, raw, payload := introspect(denied, denied.webID, denied.webSec)
	if status != http.StatusOK || payload["active"] != true {
		t.Fatalf("control failed: the issuing confidential client got %d %s", status, raw)
	}

	// Control 3: a client id that does not exist is refused outright, so the
	// refusals above are about the client type rather than a missing auth step.
	status, raw, _ = introspect(allowed, "no-such-client-id", "x")
	if status != http.StatusUnauthorized {
		t.Fatalf("control failed: an unknown client id got %d %s, want 401", status, raw)
	}
}

// PROBE 1b — the same shape, stated positively: a CONFIDENTIAL client in the
// allowlist cannot be impersonated (its secret is really checked), so the
// escalation above is specifically about public clients.
func TestProbeConfidentialAllowlistEntryStillNeedsItsSecret(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	e = e.withIntrospection(t, []string{e.webID})

	tokens := asTokens(t, e.codeFlow(t, []string{"account.id", "phigros.score.read"}))

	resp, raw := e.postForm(t, "/oauth/introspect",
		url.Values{"token": {tokens.AccessToken}}, e.webID, "wrong-secret")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a confidential allowlist entry accepted a wrong secret: %d %s", resp.StatusCode, raw)
	}
	resp, raw = e.postForm(t, "/oauth/introspect",
		url.Values{"token": {tokens.AccessToken}}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the honest path is broken: %d %s", resp.StatusCode, raw)
	}
	if got := decodeJSON(t, raw)["active"]; got != true {
		t.Fatalf("the honest path did not introspect: %s", raw)
	}
}

// PROBE 1c — a public client in the ALLOWLIST is also the whole reason the
// wrapper's `callerClientID` cannot be trusted as an identity: it returns the
// Basic username verbatim, and the library returns the same string. Both are
// "the public client's id", which anyone knows.
func TestProbePublicClientIDIsNotASecret(t *testing.T) {
	e := newEnv(t, envOptions{})
	// The device client is public; its id is the only thing the protocol needs.
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/oauth/device_authorization",
		strings.NewReader(url.Values{"client_id": {e.deviceID}, "scope": {"account.id"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a public client naming itself was refused: %d %s", resp.StatusCode, bodyOf(t, resp))
	}
}

// PROBE 2 (FIXED) — the introspection advertisement now matches the endpoint.
//
// Was: discovery advertised `client_secret_post` for introspection, but the
// library serves introspection through ClientIDFromRequest, whose form struct has
// only `client_id` and the client_assertion fields — no `client_secret` — so a
// posted secret was never seen and the endpoint answered 401. ADR-0005 §5 ("发现
// 文档只声明真实能力") is what that violated. The advertisement is now
// `["client_secret_basic"]` (internal/oidchttp/oidchttp.go overrides), so this is
// a positive guard: Basic is offered and works, a posted secret is refused, and
// the revocation endpoint — which really does read a posted secret — is the
// control that the request shape is well formed.
func TestProbeIntrospectionAdvertisesOnlyBasicAndRefusesPostedSecrets(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	resp := e.get(t, noRedirect, e.server.URL+"/.well-known/openid-configuration")
	disc := decodeJSON(t, bodyOf(t, resp))
	methods, _ := disc["introspection_endpoint_auth_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "client_secret_basic" {
		t.Fatalf("introspection_endpoint_auth_methods_supported = %v, want [client_secret_basic]: "+
			"the endpoint only accepts Basic, so advertising anything else is a lie a negotiating "+
			"client discovers as a 401", methods)
	}

	tokens := asTokens(t, e.codeFlow(t, []string{"account.id"}))

	// The advertised method works.
	resp, raw := e.postForm(t, "/oauth/introspect",
		url.Values{"token": {tokens.AccessToken}}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspection refused Basic, the one advertised method: %d %s", resp.StatusCode, raw)
	}

	// And the un-advertised one must NOT work, or the document understates.
	resp, raw = e.postForm(t, "/oauth/introspect", url.Values{
		"token":         {tokens.AccessToken},
		"client_id":     {e.webID},
		"client_secret": {e.webSec},
	}, "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("introspection accepted a posted secret (%d) while the document does not advertise "+
			"client_secret_post: either advertise it or refuse it: %s", resp.StatusCode, raw)
	}

	// Control: the same POST shape works where the protocol really supports it, so
	// the refusal above is about the endpoint, not a malformed request.
	resp, raw = e.postForm(t, "/oauth/revoke", url.Values{
		"token":         {tokens.AccessToken},
		"client_id":     {e.webID},
		"client_secret": {e.webSec},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control failed: revocation refused client_secret_post, which it advertises: %d %s", resp.StatusCode, raw)
	}
	_ = json.Valid(raw)
}

// PROBE 4 — userinfo answers for access tokens that were never OpenID
// authorizations.
//
// O-2 (docs/oidc-decision.md) is enforced on the token response only
// (sanitizeTokenResponse strips the id_token without `openid`), and
// pkg/op/userinfo.go never consults the scopes at all: SetUserinfoFromToken
// receives the decrypted subject and this project's implementation copies it
// (internal/store/memory/oidc.go). So the same `sub` O-2 exists to withhold is
// available from the other endpoint to a client that never asked for `openid`.
// The package's own TestUserinfoReturnsOnlySub asserts exactly this, so it is a
// deliberate shape rather than an oversight — reported as a judgement, with the
// probe kept as the guard.
func TestProbeUserinfoAnswersWithoutOpenIDScope(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	tokens := asTokens(t, e.codeFlow(t, []string{"account.id"}))
	if tokens.IDToken != "" {
		t.Fatalf("O-2 is broken before userinfo is even reached: an id_token came back without openid")
	}
	if strings.Contains(tokens.Scope, "openid") {
		t.Fatalf("the grant claims openid: %q", tokens.Scope)
	}

	req, err := http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	claims := decodeJSON(t, bodyOf(t, resp))
	if resp.StatusCode != http.StatusOK || claims["sub"] != "usr_probe" {
		t.Fatalf("userinfo refused a non-openid token (different from reported): %d %v", resp.StatusCode, claims)
	}
	t.Logf("a token whose scope is %q yields userinfo %v", tokens.Scope, claims)
}

// PROBE 5 — discovery is rendered per request Host, and a forged Host cannot fix
// the document another Host is served.
//
// 【原为发现演示，现为回归守卫】This probe used to demonstrate the opposite: that
// serveDiscovery cached by request path alone, so the FIRST caller's Host fixed
// the advertised issuer — and every endpoint URL in the document, including
// jwks_uri — for the life of the handler. S02-5 / P-03 fixed exactly that:
// `discoveryDoc` now records the issuer it was rendered for and a cache hit is
// served only when it matches the request's issuer
// (internal/oidchttp/oidchttp.go:315-359). The probe is now the regression guard
// for that check.
//
// What it pins, in order:
//  1. the dynamic issuer still follows the Host header (the premise of the
//     poisoning shape — without it this probe would be aimed at nothing);
//  2. a second Host asking the same path is answered with ITS OWN document, not
//     the first Host's cached one;
//  3. the first Host's own fetch is likewise re-rendered, so neither Host can
//     inherit the other's document;
//  4. the RFC 8414 alias shares the OIDC document's cache entry (serveDiscovery
//     renders the OIDC path for both) and is subject to the same issuer check,
//     and the document is still publicly cacheable.
//
// Note the reachability caveat it always carried: cmd/re0auth always sets
// Config.Issuer (config.go rejects an empty one), so the dynamic shape is the
// development/test shape; the probe documents the property for the shape the
// wrapper supports and the test suite uses.
func TestProbeDiscoveryIsCachedFromTheFirstRequestsHost(t *testing.T) {
	e := newEnv(t, envOptions{}) // dynamic issuer, like the package's own fixture

	fetch := func(host string) (map[string]any, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, e.server.URL+"/.well-known/openid-configuration", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return decodeJSON(t, bodyOf(t, resp)), resp.Header.Get("Cache-Control")
	}

	// 1. The Host still drives the issuer. This is the premise; if it ever stops
	// holding, the probe must fail loudly rather than pass vacuously.
	poisoned, _ := fetch("attacker.example")
	poisonedIssuer, _ := poisoned["issuer"].(string)
	if !strings.Contains(poisonedIssuer, "attacker.example") {
		t.Fatalf("the dynamic issuer does not follow the Host header, so this probe is aimed at nothing: %v", poisoned["issuer"])
	}
	t.Logf("first fetch (Host: attacker.example) -> issuer=%v authorization_endpoint=%v jwks_uri=%v",
		poisoned["issuer"], poisoned["authorization_endpoint"], poisoned["jwks_uri"])

	// 2/3. S02-5: the cached entry is not served across issuers.
	honest, honestCC := fetch("re0auth.example")
	honestIssuer, _ := honest["issuer"].(string)
	if strings.Contains(honestIssuer, "attacker.example") {
		t.Errorf("a second Host was handed the first Host's cached document: issuer=%v jwks_uri=%v",
			honest["issuer"], honest["jwks_uri"])
	}
	if !strings.Contains(honestIssuer, "re0auth.example") {
		t.Errorf("the second Host's document does not name its own issuer: %v", honest["issuer"])
	}
	t.Logf("second fetch (Host: re0auth.example) -> issuer=%v jwks_uri=%v cache-control=%q",
		honest["issuer"], honest["jwks_uri"], honestCC)

	again, _ := fetch("attacker.example")
	if got, _ := again["issuer"].(string); got != poisonedIssuer {
		t.Errorf("the first Host's document was not re-rendered for it either: %v vs %v", got, poisonedIssuer)
	}

	// 4. The RFC 8414 alias shares the OIDC document's cache entry AND its issuer
	// check: a third Host must render its own document rather than borrow either
	// cached one.
	req, err := http.NewRequest(http.MethodGet, e.server.URL+"/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "second-attacker.example"
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	alias := decodeJSON(t, bodyOf(t, resp))
	aliasIssuer, _ := alias["issuer"].(string)
	if !strings.Contains(aliasIssuer, "second-attacker.example") {
		t.Errorf("the alias borrowed another Host's document instead of rendering for its own: %v", alias["issuer"])
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Fatalf("discovery is no longer publicly cacheable: %q", cc)
	}
	t.Logf("the RFC 8414 alias renders for its own Host: issuer=%v cache-control=%q",
		alias["issuer"], resp.Header.Get("Cache-Control"))
}
