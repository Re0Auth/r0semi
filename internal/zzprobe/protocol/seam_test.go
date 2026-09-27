//go:build audit5

package protocol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// PROBE 1 — the introspection allowlist is checked against a client id, but a
// PUBLIC client authenticates with no secret at all.
//
// internal/store/memory/oidc.go AuthorizeClientIDSecret returns nil for any
// secret when the client is not confidential (`c.Type == ClientConfidential &&`
// guards the only verification), and the library's introspection handler treats
// that nil as "authenticated" (pkg/op/client.go ClientBasicAuth ->
// pkg/op/token_intospection.go ParseTokenIntrospectionRequest requires
// `authenticated`). So if the deployment's resource-server allowlist names a
// public client — and nothing in the config, the docs or the wrapper's Config
// says it must not — then anyone on the network can send
//
//	Authorization: Basic base64(<public-client-id>:garbage)
//
// and receive the full introspection record of ANY token in the deployment.
//
// The control cases below are what make this non-vacuous: the same request
// without the allowlist answers active=false, and a non-existent client id is
// refused with 401.
func TestProbeIntrospectionAllowlistWithAPublicClientIsAnonymousRead(t *testing.T) {
	// One deployment shape, two mounts: the victim's token is minted once, on the
	// mount WITHOUT the allowlist, and then introspected through both.
	denied := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	allowed := denied.withIntrospection(t, []string{denied.deviceID})

	tokens := asTokens(t, denied.codeFlow(t, []string{"openid", "account.id", "phigros.score.read"}))
	if tokens.AccessToken == "" {
		t.Fatal("no access token minted, so the probe would be vacuous")
	}

	introspect := func(e env, basicID, basicSecret string) (int, map[string]any) {
		t.Helper()
		resp, raw := e.postForm(t, "/oauth/introspect",
			url.Values{"token": {tokens.AccessToken}}, basicID, basicSecret)
		return resp.StatusCode, decodeJSON(t, raw)
	}

	// The escalation: the PUBLIC client's id with a secret it does not have.
	status, payload := introspect(allowed, allowed.deviceID, "not-the-secret")
	if status != http.StatusOK {
		t.Fatalf("introspect as the public client = %d: %v", status, payload)
	}
	if payload["active"] != true {
		t.Fatalf("the public client could not introspect; finding not reproduced: %v", payload)
	}
	if got, _ := payload["scope"].(string); !strings.Contains(got, "phigros.score.read") {
		t.Fatalf("cross-client introspection did not leak the scope: %v", payload)
	}
	if got, _ := payload["sub"].(string); got == "" {
		t.Fatalf("cross-client introspection did not leak the subject: %v", payload)
	}
	t.Logf("public client %q read another client's token: active=%v scope=%v sub=%v",
		allowed.deviceID, payload["active"], payload["scope"], payload["sub"])

	// An empty secret is enough, which is what "no credential at all" looks like.
	status, payload = introspect(allowed, allowed.deviceID, "")
	if status != http.StatusOK || payload["active"] != true {
		t.Fatalf("an empty secret was not enough: %d %v", status, payload)
	}

	// Control 1: with no allowlist the same request sees nothing.
	status, payload = introspect(denied, denied.deviceID, "not-the-secret")
	if status != http.StatusOK || payload["active"] != false {
		t.Fatalf("control failed: without the allowlist the public client got %d %v", status, payload)
	}

	// Control 2: a client id that does not exist is refused outright, so the
	// anonymous read above is the allowlist, not a missing authentication step.
	status, payload = introspect(allowed, "no-such-client-id", "x")
	if status != http.StatusUnauthorized {
		t.Fatalf("control failed: an unknown client id got %d %v, want 401", status, payload)
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

// PROBE 2 — the discovery document advertises `client_secret_post` for the
// introspection endpoint, but the endpoint only ever reads HTTP Basic.
//
// internal/oidchttp/oidchttp.go's overrides set
// introspection_endpoint_auth_methods_supported = [client_secret_basic,
// client_secret_post]. The library's own answer was [client_secret_basic]
// (pkg/op/discovery.go AuthMethodsIntrospectionEndpoint), which is the truthful
// one: pkg/op/token_intospection.go ParseTokenIntrospectionRequest goes through
// ClientIDFromRequest, whose form struct (pkg/op/client.go clientData) has only
// `client_id` and the client_assertion fields — there is no `client_secret`
// field, so a posted secret is never seen, `authenticated` stays false and the
// endpoint answers 401. ADR-0005 point 5 ("发现文档只声明真实能力") is what this
// violates. The revocation endpoint, by contrast, does read the posted secret
// (pkg/op/token_revocation.go), which is the control that shows the probe sends a
// well-formed request.
func TestProbeDiscoveryAdvertisesClientSecretPostForIntrospection(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	resp := e.get(t, noRedirect, e.server.URL+"/.well-known/openid-configuration")
	disc := decodeJSON(t, bodyOf(t, resp))
	methods, _ := disc["introspection_endpoint_auth_methods_supported"].([]any)
	advertised := map[string]bool{}
	for _, m := range methods {
		if s, ok := m.(string); ok {
			advertised[s] = true
		}
	}
	if !advertised["client_secret_post"] {
		t.Skipf("discovery no longer advertises client_secret_post for introspection: %v", methods)
	}
	t.Logf("discovery advertises %v for introspection", methods)

	tokens := asTokens(t, e.codeFlow(t, []string{"account.id"}))

	// What the advertisement promises: a posted secret authenticates.
	resp, raw := e.postForm(t, "/oauth/introspect", url.Values{
		"token":         {tokens.AccessToken},
		"client_id":     {e.webID},
		"client_secret": {e.webSec},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("introspection refused a documented client_secret_post authentication: %d %s", resp.StatusCode, raw)
	}

	// Control: the same POST shape works where the protocol really supports it.
	resp, raw = e.postForm(t, "/oauth/revoke", url.Values{
		"token":         {tokens.AccessToken},
		"client_id":     {e.webID},
		"client_secret": {e.webSec},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control failed: revocation refused client_secret_post too: %d %s", resp.StatusCode, raw)
	}

	// And Basic on introspection still works, so the endpoint is not simply broken.
	resp, raw = e.postForm(t, "/oauth/introspect",
		url.Values{"token": {tokens.AccessToken}}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control failed: introspection refused Basic: %d %s", resp.StatusCode, raw)
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

// PROBE 5 — the discovery document is rendered once, from whichever Host asked
// first, and then served to everybody.
//
// internal/oidchttp/oidchttp.go serveDiscovery caches by request path for the
// life of the handler, and New() falls back to op.IssuerFromHost when Config.Issuer
// is empty — the "dynamic deployments" the Config comment names. The rendered
// document's issuer and every endpoint URL come from that first request's Host,
// and the response is then handed out with `Cache-Control: public, max-age=300`.
// cmd/re0auth always sets an issuer (config.go rejects an empty one), so this is
// not reachable in the shipped binary; the probe documents the trap for the
// dynamic shape the wrapper supports and the test suite uses.
func TestProbeDiscoveryIsCachedFromTheFirstRequestsHost(t *testing.T) {
	e := newEnv(t, envOptions{}) // dynamic issuer, like the package's own fixture

	fetch := func(host string) map[string]any {
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
		return decodeJSON(t, bodyOf(t, resp))
	}

	poisoned := fetch("attacker.example")
	if got, _ := poisoned["issuer"].(string); !strings.Contains(got, "attacker.example") {
		t.Fatalf("the dynamic issuer does not follow the Host header, so this probe is aimed at nothing: %v", poisoned["issuer"])
	}
	t.Logf("first fetch (Host: attacker.example) -> issuer=%v authorization_endpoint=%v jwks_uri=%v",
		poisoned["issuer"], poisoned["authorization_endpoint"], poisoned["jwks_uri"])

	honest := fetch("re0auth.example")
	if got, _ := honest["issuer"].(string); got != poisoned["issuer"] {
		t.Fatalf("discovery is not cached; the poisoning shape does not hold: %v vs %v", got, poisoned["issuer"])
	}
	if got, _ := honest["jwks_uri"].(string); !strings.Contains(got, "attacker.example") {
		t.Fatalf("the cached document is not the poisoned one: %v", got)
	}
	t.Logf("every later fetch is answered with the attacker's issuer, including jwks_uri=%v", honest["jwks_uri"])

	// The RFC 8414 alias shares the OIDC document's cache entry — serveDiscovery
	// with RFC8414Path renders (and looks up) the OIDC path — so ONE request with a
	// spoofed Host poisons BOTH published documents.
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
	if got, _ := alias["issuer"].(string); got != poisoned["issuer"] {
		t.Fatalf("the alias rendered its own document instead of sharing the cache: %v vs %v",
			got, poisoned["issuer"])
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Fatalf("discovery is no longer publicly cacheable: %q", cc)
	}
	t.Logf("the RFC 8414 alias serves the same poisoned document: issuer=%v cache-control=%q",
		alias["issuer"], resp.Header.Get("Cache-Control"))
}
