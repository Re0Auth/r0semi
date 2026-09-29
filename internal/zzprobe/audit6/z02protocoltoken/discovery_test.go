//go:build audit6

package z02protocoltoken

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidcstore"
)

// Z02-18 guards — the discovery document advertises only what the endpoints
// do (ADR-0005 §5), and the two well-known locations serve the same document.
// The auth-method matrices per endpoint are behaviorally probed in the token,
// introspection and revocation files; this pins the document itself and the
// JWKS that backs it.
func TestZ02DiscoveryAdvertisesReality(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	oidcResp := e.get(t, noRedirect, e.server.URL+"/.well-known/openid-configuration")
	oidcBody := bodyOf(t, oidcResp)
	if oidcResp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", oidcResp.StatusCode)
	}
	if cc := oidcResp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("discovery Cache-Control = %q, want an explicit max-age", cc)
	}
	disc := decodeJSON(t, oidcBody)

	for key, suffix := range map[string]string{
		"authorization_endpoint": "/oauth/authorize",
		"token_endpoint":         "/oauth/token",
		"jwks_uri":               "/oauth/keys",
		"userinfo_endpoint":      "/oauth/userinfo",
		"introspection_endpoint": "/oauth/introspect",
		"revocation_endpoint":    "/oauth/revoke",
	} {
		got, _ := disc[key].(string)
		if !strings.HasSuffix(got, suffix) {
			t.Errorf("%s = %q, want suffix %q", key, got, suffix)
		}
	}

	// O-9: nothing outside the contract may be advertised.
	for _, key := range []string{
		"end_session_endpoint", "registration_endpoint", "check_session_iframe",
		"request_object_signing_alg_values_supported",
	} {
		if _, ok := disc[key]; ok {
			t.Errorf("discovery advertises %s, which is out of contract", key)
		}
	}

	// The capability overrides.
	if modes, _ := disc["response_modes_supported"].([]any); len(modes) != 1 || modes[0] != "query" {
		t.Errorf("response_modes_supported = %v, want [query]", disc["response_modes_supported"])
	}
	if types, _ := disc["response_types_supported"].([]any); len(types) != 1 || types[0] != "code" {
		t.Errorf("response_types_supported = %v, want [code]", disc["response_types_supported"])
	}
	grants, _ := disc["grant_types_supported"].([]any)
	if len(grants) != 3 {
		t.Errorf("grant_types_supported = %v, want the three implemented grants", disc["grant_types_supported"])
	} else {
		want := map[string]bool{
			"authorization_code": true, "refresh_token": true,
			"urn:ietf:params:oauth:grant-type:device_code": true,
		}
		for _, g := range grants {
			name, _ := g.(string)
			if !want[name] {
				t.Errorf("grant_types_supported advertises %q, which is not implemented", name)
			}
			delete(want, name)
		}
		for left := range want {
			t.Errorf("grant_types_supported is missing %q, which is implemented", left)
		}
	}
	if claims, _ := disc["claims_supported"].([]any); len(claims) != 1 || claims[0] != "sub" {
		t.Errorf("claims_supported = %v, want [sub]", disc["claims_supported"])
	}
	if got, _ := disc["authorization_response_iss_parameter_supported"].(bool); !got {
		t.Errorf("authorization_response_iss_parameter_supported = %v, want true", disc["authorization_response_iss_parameter_supported"])
	}
	if methods, _ := disc["introspection_endpoint_auth_methods_supported"].([]any); len(methods) != 1 || methods[0] != "client_secret_basic" {
		t.Errorf("introspection_endpoint_auth_methods_supported = %v, want [client_secret_basic]",
			disc["introspection_endpoint_auth_methods_supported"])
	}
	for key, want := range map[string]int{"token_endpoint_auth_methods_supported": 3, "revocation_endpoint_auth_methods_supported": 3} {
		methods, _ := disc[key].([]any)
		if len(methods) != want {
			t.Errorf("%s = %v, want %d entries", key, disc[key], want)
		}
		for _, m := range methods {
			if m != "none" && m != "client_secret_basic" && m != "client_secret_post" {
				t.Errorf("%s advertises %q", key, m)
			}
		}
	}
	// The scopes a relying party must be able to discover.
	rawScopes, _ := disc["scopes_supported"].([]any)
	have := map[string]bool{}
	for _, s := range rawScopes {
		if name, ok := s.(string); ok {
			have[name] = true
		}
	}
	for _, want := range []string{"openid", "offline_access", "account.id"} {
		if !have[want] {
			t.Errorf("scopes_supported is missing %q", want)
		}
	}
	// The RFC 8414 alias is byte-identical.
	rfcResp := e.get(t, noRedirect, e.server.URL+"/.well-known/oauth-authorization-server")
	rfcBody := bodyOf(t, rfcResp)
	if string(rfcBody) != string(oidcBody) {
		t.Error("the RFC 8414 alias differs from the OIDC discovery document")
	}

	// RFC 9207: an authorization response — success and error alike — names
	// the issuer. The error leg is checked here (the success leg is asserted
	// inside codeFlow).
	q := "response_type=code&client_id=" + e.webID +
		"&redirect_uri=" + strings.ReplaceAll("https://client.example/cb", ":", "%3A") +
		"&scope=made.up.scope&state=st&code_challenge=" + strings.Repeat("c", 43) +
		"&code_challenge_method=S256"
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q)
	loc := resp.Header.Get("Location")
	_ = bodyOf(t, resp)
	if !strings.Contains(loc, "iss=") {
		t.Errorf("an invalid_scope refusal carries no iss: %q", loc)
	}
}

// Z02-19 guards — the JWKS publishes only public material, one key per kid,
// RS256 for both use and alg, and a rotation's retired keys appear alongside
// the current one (the overlap that keeps old id_tokens verifiable).
func TestZ02JWKSPublishesPublicMaterialOnly(t *testing.T) {
	e := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02"})

	resp := e.get(t, noRedirect, e.server.URL+"/oauth/keys")
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keys status = %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("keys Cache-Control = %q, want an explicit max-age", cc)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("jwks: %v (%s)", err, body)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("jwks has %d keys, want the fixture's one", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" {
		t.Errorf("jwks key = %v", k)
	}
	if _, has := k["kid"].(string); !has || k["kid"] == "" {
		t.Errorf("jwks key has no kid: %v", k)
	}
	for _, leak := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, has := k[leak]; has {
			t.Errorf("jwks leaks the private parameter %q", leak)
		}
	}

	// A rotation: the current key plus a retired public key. The retired key
	// must be published (it verifies previously issued id_tokens) and must
	// carry no private material either.
	current, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	old, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := oidcstore.NewSigner("z02-current", current).
		WithRetired(oidcstore.RetiredSigningKey{ID: "z02-retired", Public: &old.PublicKey})
	if err := oidcstore.ValidateSigner(signer); err != nil {
		t.Fatal(err)
	}
	rotated := newZoneEnv(t, zoneOptions{issuer: "https://issuer.z02", signer: signer})

	resp = rotated.get(t, noRedirect, rotated.server.URL+"/oauth/keys")
	body = bodyOf(t, resp)
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("rotated jwks: %v (%s)", err, body)
	}
	kids := map[string]bool{}
	for _, k := range jwks.Keys {
		id, _ := k["kid"].(string)
		if kids[id] {
			t.Errorf("jwks publishes kid %q twice", id)
		}
		kids[id] = true
		if _, leak := k["d"]; leak {
			t.Errorf("the rotated jwks leaks a private exponent for kid %q", id)
		}
	}
	if !kids["z02-current"] || !kids["z02-retired"] {
		t.Errorf("the rotated jwks does not publish both kids: %v", kids)
	}
}
