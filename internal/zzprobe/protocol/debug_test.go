//go:build audit5

package protocol

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Debug helper for PROBE 3: what exactly does the OP return for each bearer?
func TestDebugIDTokenBearer(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	tok := asTokens(t, e.codeFlow(t, []string{"openid", "account.id"}))

	parts := strings.Split(tok.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %q", tok.IDToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("id_token header: %s", parts[0])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	t.Logf("id_token claims: %v", claims)

	for _, bearer := range []string{tok.AccessToken, tok.IDToken, tok.AccessToken[:20] + "x"} {
		req, err := http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw := bodyOf(t, resp)
		label := bearer
		if len(label) > 24 {
			label = label[:24] + "..."
		}
		t.Logf("userinfo as %s -> %d %s", label, resp.StatusCode, raw)
	}
}
