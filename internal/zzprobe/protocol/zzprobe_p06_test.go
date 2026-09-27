//go:build audit5

package protocol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/oidchttp"
)

// The dedicated guard for P0-6: introspection authorizes by client authentication
// alone, so a caller that has no secret to authenticate with must be refused.
//
// The mechanism P0-6 recorded: the storage's `AuthorizeClientIDSecret` verifies a
// secret ONLY for a confidential client
//
//	if c.Type == oauth.ClientConfidential && !c.Authenticate(clientSecret) { … }
//	return nil
//
// so for a public client it answers nil — "authenticated" — for any secret,
// including none. The library treats that nil as authentication. With a public
// client id on the introspection allowlist, `Authorization: Basic
// base64("<public id>:")` therefore read the full record of ANY token in the
// deployment: active, scope, sub, client_id and exp. A public client's id is not a
// credential — it is printed in the client binary and in every authorization URL.
//
// The refusal is 401 `invalid_client` (RFC 7662 §2.1: the caller authenticates as a
// protected resource), not `active=false`: a caller who cannot authenticate is a
// different failure from a token that is not live, and answering `active=false`
// would leave a misconfigured resource server silently unable to introspect
// anything.
func TestZZProbeIntrospectionNeedsAConfidentialClient(t *testing.T) {
	// One deployment shape, two mounts: the allowlist is the only difference, so a
	// pass cannot come from the request being malformed.
	plain := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	allowed := plain.withIntrospection(t, []string{plain.deviceID})

	tokens := asTokens(t, plain.codeFlow(t, []string{"openid", "account.id", "phigros.score.read"}))
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

	// Controls: an honest confidential caller still sees its own token, and an
	// allowlisted confidential resource server still sees another client's.
	status, raw, payload := introspect(plain, plain.webID, plain.webSec)
	if status != http.StatusOK || payload["active"] != true {
		t.Fatalf("control failed: the issuing confidential client got %d %s", status, raw)
	}
	resourceServer := plain.rebuild(t, func(cfg *oidchttp.Config) {
		cfg.IntrospectionClients = []string{plain.narrowID}
	})
	status, raw, payload = introspect(resourceServer, plain.narrowID, plain.narrowSec)
	if status != http.StatusOK || payload["active"] != true {
		t.Fatalf("control failed: an allowlisted CONFIDENTIAL client got %d %s", status, raw)
	}
	if got, _ := payload["scope"].(string); !strings.Contains(got, "phigros.score.read") {
		t.Fatalf("control failed: the allowlisted resource server did not see the scopes: %s", raw)
	}

	// The escalation: the PUBLIC client's id, allowlisted, with no usable secret.
	for _, secret := range []string{"", "not-the-secret"} {
		status, raw, payload = introspect(allowed, allowed.deviceID, secret)
		if status == http.StatusOK && payload["active"] == true {
			t.Errorf("a public client (secret %q) introspected another client's token: %d %s", secret, status, raw)
		}
		if status != http.StatusUnauthorized {
			t.Errorf("a public client (secret %q) was answered %d, want 401 invalid_client: %s", secret, status, raw)
		}
		if strings.Contains(raw, "phigros.score.read") || strings.Contains(raw, "usr_probe") {
			t.Errorf("the refusal leaked the token's facts: %s", raw)
		}
		if !strings.Contains(raw, "invalid_client") {
			t.Errorf("the refusal does not name invalid_client: %s", raw)
		}
	}

	// The same caller with no allowlist is refused too: the rule is about the
	// caller, not about the list it happens to be on.
	status, raw, _ = introspect(plain, plain.deviceID, "")
	if status != http.StatusUnauthorized {
		t.Errorf("a public client without an allowlist was answered %d, want 401: %s", status, raw)
	}

	// And the refusal is not a blanket one: an unknown id is still 401, and the
	// honest confidential paths above still answer.
	status, raw, _ = introspect(allowed, "no-such-client-id", "x")
	if status != http.StatusUnauthorized {
		t.Errorf("an unknown client id was answered %d, want 401: %s", status, raw)
	}
}
