//go:build audit5

package verifyprotocol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The report's guard list claims "redirect_uri 精确匹配 19 种扩展全部被拒". This
// spot-check replays the property with variants the report did NOT list, chosen
// so that each one is *semantically* the registered URI but textually different —
// the only shape that actually tests exactness (a variant that also fails to
// parse proves nothing about the comparison).
func TestVerifyRedirectURIExactnessWithNewVariants(t *testing.T) {
	e := newOPEnv(t)
	const registered = "https://client.example/cb"

	// Control: the registered value reaches the login plane.
	resp := e.get(t, e.server.URL+"/oauth/authorize?"+e.authValues(registered, []string{"account.id"}).Encode())
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?") {
		t.Fatalf("control failed: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_ = bodyOf(t, resp)

	variants := map[string]string{
		"dot-segment round trip":   "https://client.example/cb/../cb",
		"trailing dot on host":     "https://client.example./cb",
		"uppercase everything":     "HTTPS://CLIENT.EXAMPLE/CB",
		"empty query":              registered + "?",
		"empty fragment":           registered + "#",
		"percent-encoded NUL":      registered + "%00",
		"semicolon path param":     "https://client.example/cb;x=1",
		"double-encoded slash":     "https://client.example/%252fcb",
		"tab inside":               "https://client.example/c\tb",
		"trailing newline encoded": registered + "%0a",
		"userinfo":                 "https://u:p@client.example/cb",
		"ipv4 form of same host":   "https://93.184.216.34/cb",
		"scheme plus colon":        "https://client.example:443/cb",
	}
	for name, redirect := range variants {
		t.Run(name, func(t *testing.T) {
			resp := e.get(t, e.server.URL+"/oauth/authorize?"+e.authValues(redirect, []string{"account.id"}).Encode())
			body := bodyOf(t, resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("variant %q was not refused with 400 (got %d, Location %q): %s",
					redirect, resp.StatusCode, resp.Header.Get("Location"), body)
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Fatalf("variant %q was answered with a redirect to %q", redirect, loc)
			}
		})
	}
}

// The same property at the token endpoint, where the comparison is against the
// value stored on the authorization request rather than the registry.
func TestVerifyTokenEndpointRedirectURIStaysExact(t *testing.T) {
	e := newOPEnv(t)
	for _, tc := range []struct {
		name     string
		redirect string
		wantOK   bool
	}{
		{"exact (control)", "https://client.example/cb", true},
		{"dot-segment round trip", "https://client.example/cb/../cb", false},
		{"empty query", "https://client.example/cb?", false},
		{"trailing dot on host", "https://client.example./cb", false},
		{"semicolon path param", "https://client.example/cb;x=1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, verifier := e.code(t, []string{"account.id"})
			out, status := e.postToken(t, url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {tc.redirect},
				"code_verifier": {verifier},
			})
			if tc.wantOK {
				if status != http.StatusOK {
					t.Fatalf("control: the exact redirect_uri was refused: %d %v", status, out)
				}
				return
			}
			if status == http.StatusOK {
				t.Fatalf("the token endpoint accepted redirect_uri %q: %v", tc.redirect, out)
			}
		})
	}
}

// "refresh cannot escalate": try to widen the grant with variants the report's
// probe did not use. Any 200 whose scope contains a scope that was never granted
// is a widening.
func TestVerifyRefreshCannotEscalateWithUnlistedVariants(t *testing.T) {
	e := newOPEnv(t)
	first := e.tokens(t, []string{"account.id", "offline_access"})
	refresh, _ := first["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token in %v", first)
	}

	for _, scope := range []string{
		"phigros.score.read",
		" account.id phigros.score.read",
		"account.id\tphigros.score.read",
		"account.id  phigros.score.read",
		"ACCOUNT.ID phigros.score.read",
		"account.id,phigros.score.read",
		"account.id;phigros.score.read",
		"phigros.score.read account.id",
		"account.id\u00a0phigros.score.read",
		"account.id phigros.score.read phigros.score.read",
	} {
		t.Run(scope, func(t *testing.T) {
			out, status := e.postToken(t, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refresh},
				"scope":         {scope},
			})
			if status != http.StatusOK {
				return // refused: no widening
			}
			got, _ := out["scope"].(string)
			for _, s := range strings.Fields(got) {
				if s != "account.id" && s != "openid" && s != "offline_access" {
					t.Fatalf("refresh with scope %q returned a scope that was never granted: %q", scope, got)
				}
			}
		})
	}

	// Control: a subset refresh still works, so the refusals above are not the
	// endpoint being broken.
	out, status := e.postToken(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"scope":         {"account.id"},
	})
	if status != http.StatusOK {
		t.Fatalf("control failed: a subset refresh was refused: %d %v", status, out)
	}
}

// "JWKS 只含公开参数" plus the property the report did not pin: the kid the
// id_token is signed with must be a key the JWKS actually publishes.
func TestVerifyJWKSIsPublicOnlyAndMatchesTheSigningKid(t *testing.T) {
	e := newOPEnv(t)

	resp := e.get(t, e.server.URL+"/oauth/keys")
	raw := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("JWKS = %d", resp.StatusCode)
	}
	lower := strings.ToLower(string(raw))
	for _, secret := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`, `"private"`, `"k"`} {
		if strings.Contains(lower, secret) {
			t.Fatalf("the JWKS publishes %s: %s", secret, raw)
		}
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("expected exactly one published key, got %d: %s", len(set.Keys), raw)
	}
	key := set.Keys[0]
	kid, _ := key["kid"].(string)
	if kid == "" || key["kty"] != "RSA" || key["alg"] != "RS256" {
		t.Fatalf("unexpected published key: %v", key)
	}

	// The issued id_token's header must name that key, or a client cannot select it.
	out := e.tokens(t, []string{"openid", "account.id"})
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in %v", out)
	}
	head, err := base64URLDecode(strings.Split(idToken, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(head, &header); err != nil {
		t.Fatal(err)
	}
	if header["kid"] != kid {
		t.Fatalf("the id_token is signed with kid %v but the JWKS publishes %q", header["kid"], kid)
	}
	if header["alg"] != "RS256" {
		t.Fatalf("the id_token alg is %v", header["alg"])
	}
	// Claim spot-check: the report says userinfo carries sub while the id_token
	// does not (PROTO-2). One lookup, no dependency on the report's fixture.
	if _, ok := idTokenClaims(t, idToken)["sub"]; ok {
		t.Logf("the id_token now carries sub; PROTO-2 may be fixed")
	}
}

// Anti-vacuity for PROTO-3b: userinfo must not be a blanket 200. If a garbage
// bearer were answered 200, the "it accepts an expired token" result would be
// explained by the endpoint never looking at anything.
func TestVerifyUserinfoRefusesGarbageBearer(t *testing.T) {
	e := newOPEnv(t)

	bearer := func(hdr string) int {
		req, err := http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
		if err != nil {
			t.Fatal(err)
		}
		if hdr != "" {
			req.Header.Set("Authorization", "Bearer "+hdr)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = bodyOf(t, resp)
		return resp.StatusCode
	}

	if got := bearer(""); got == http.StatusOK {
		t.Fatalf("userinfo answered %d with no bearer at all", got)
	}
	if got := bearer("not-a-token"); got == http.StatusOK {
		t.Fatalf("userinfo answered %d for a garbage bearer", got)
	}
	out := e.tokens(t, []string{"openid", "account.id"})
	at, _ := out["access_token"].(string)
	if at == "" {
		t.Fatal("no access token")
	}
	if got := bearer(at); got != http.StatusOK {
		t.Fatalf("control failed: a live access token was refused with %d", got)
	}
	// A one-character edit to the ciphertext must not survive AEAD.
	edited := at[:len(at)-2] + "AA"
	if edited == at {
		t.Fatal("probe bug: the edit did not change the token")
	}
	if got := bearer(edited); got == http.StatusOK {
		t.Fatalf("userinfo answered %d for a tampered access token", got)
	}
}
