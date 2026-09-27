//go:build audit5

package protocol

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// PROBE 6 — every id_token this OP issues has NO `sub` claim.
//
// OIDC Core 1.0 §2 makes `sub` REQUIRED in the ID Token; this project's own
// decision record says `sub` is the Re0Auth `usr_…` (docs/oidc-decision.md O-4)
// and the threat model calls the identity claim the reason the OP exists
// (threat-model.md A8/B7).
//
// The mechanism is in the seam, not in the library's defaults:
//
//   - pkg/op/token.go CreateIDToken fills a `new(oidc.UserInfo)` by calling
//     storage.SetUserinfoFromScopes(...) and then calls claims.SetUserInfo(userInfo);
//   - pkg/oidc/token.go:158 SetUserInfo does `t.Subject = i.Subject` — it ASSIGNS,
//     it does not merge — so whatever the store left in userInfo.Subject becomes
//     the id_token's `sub`;
//   - this project's SetUserinfoFromScopes is a deliberate no-op stub in BOTH
//     stores (`// implements op.Storage (deprecated upstream; no-op)` —
//     internal/store/memory/oidc.go:685, internal/store/postgres/oidc.go:577),
//     so userInfo.Subject is "".
//
// The two removals that would stop the wipe (`removeUserinfoScopes` dropping
// every scope, or the empty-scope branch) do not apply: the granted set always
// contains protocol scopes.
func TestProbeIDTokenIsMissingTheSubjectClaim(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})

	// Every path that can produce an id_token: the code exchange and the refresh.
	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "offline_access"}))
	if tokens.IDToken == "" {
		t.Fatalf("no id_token to inspect: %+v", tokens)
	}
	assertIDTokenSubject(t, "authorization_code", tokens.IDToken, "usr_probe")

	if tokens.RefreshToken == "" {
		t.Fatal("no refresh token, so the refresh path cannot be probed")
	}
	refreshedRaw, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
	})
	if status != http.StatusOK {
		t.Fatalf("the refresh was refused: %d %v", status, refreshedRaw)
	}
	refreshed := asTokens(t, refreshedRaw)
	if refreshed.IDToken == "" {
		t.Fatalf("the refresh minted no id_token: %+v", refreshed)
	}
	assertIDTokenSubject(t, "refresh_token", refreshed.IDToken, "usr_probe")

	// The control that makes this a seam and not a general "no identity anywhere":
	// userinfo, which reads the subject from the token record instead of from a
	// UserInfo object, reports the right subject.
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
	if claims["sub"] != "usr_probe" {
		t.Fatalf("control failed: userinfo does not carry the subject either: %v", claims)
	}
	t.Logf("userinfo carries sub=%v while the id_token does not", claims["sub"])
}

// PROBE 7 — a bearer that is not an access token is accepted at userinfo.
//
// getTokenIDAndSubject (pkg/op/userinfo.go:91) falls back to VerifyAccessToken
// when JWE decryption fails, and VerifyAccessToken's first step is
// oidc.DecryptToken, which is `return tokenString, nil // TODO: impl`
// (pkg/oidc/verifier.go:110). A plain JWS therefore goes straight to the
// signature check — against THIS OP's signing key, which is exactly the key that
// signed the id_token. So `Authorization: Bearer <id_token>` authenticates:
// today the answer is `200 {}` only because PROBE 6 removed the subject; the
// moment `sub` is restored (which OIDC requires), the same request answers
// `200 {"sub":"usr_…"}`.
//
// That makes the id_token a bearer credential for a protected resource: it is
// handed to every RP, RPs store and forward it, and it cannot be revoked —
// /oauth/revoke takes the JWTID path, an id_token has no `jti`, so RevokeToken
// matches nothing and RFC 7009's unknown-token-is-success answers 200.
func TestProbeNonAccessTokenJWSIsAcceptedAtUserinfo(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id"}))

	userinfo := func(bearer string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, decodeJSON(t, bodyOf(t, resp))
	}

	// Controls: this endpoint does refuse a tampered opaque token and junk.
	if status, _ := userinfo(tokens.AccessToken[:len(tokens.AccessToken)-2] + "xx"); status != http.StatusUnauthorized {
		t.Fatalf("control failed: a tampered access token answered %d", status)
	}
	if status, _ := userinfo("not-a-token-at-all"); status != http.StatusUnauthorized {
		t.Fatalf("control failed: junk answered %d", status)
	}

	status, claims := userinfo(tokens.IDToken)
	if status != http.StatusOK {
		t.Fatalf("the id_token was refused at userinfo (behaviour changed): %d %v", status, claims)
	}
	t.Logf("the id_token is accepted as a bearer access token: %d %v (subject empty only because PROBE 6 dropped it)",
		status, claims)

	// And revoking "it" is the RFC 7009 no-op: 200, nothing deleted, still usable.
	resp, raw := e.postForm(t, "/oauth/revoke", url.Values{"token": {tokens.IDToken}}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoking an id_token answered %d %s", resp.StatusCode, raw)
	}
	if status, _ := userinfo(tokens.IDToken); status != http.StatusOK {
		t.Fatalf("revoking the id_token actually worked (behaviour changed): %d", status)
	}

	// The boundary of the impact: the business plane's introspector does NOT have
	// the JWT fallback (internal/oidchttp/oidchttp.go Introspect only decrypts), so
	// /v1 rejects the id_token. The confusion is confined to the protocol plane's
	// own userinfo endpoint.
	info, err := e.handler.Introspect(t.Context(), tokens.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active {
		t.Fatalf("the id_token is also active at the business-plane introspector: %+v", info)
	}
	live, err := e.handler.Introspect(t.Context(), tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !live.Active {
		t.Fatalf("control failed: the real access token is not active: %+v", live)
	}
	t.Logf("business-plane introspector: id_token active=%v, access_token active=%v", info.Active, live.Active)
}

func assertIDTokenSubject(t *testing.T, grant, raw, want string) {
	t.Helper()
	claims := idTokenClaims(t, raw)
	got, present := claims["sub"]
	if !present {
		t.Errorf("%s: the id_token has no `sub` claim at all (claims: %v)", grant, keysOf(claims))
		return
	}
	if got != want {
		t.Errorf("%s: id_token sub = %v, want %q", grant, got, want)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mustTokens(t *testing.T, tok map[string]any, status int) map[string]any {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("token endpoint answered %d: %v", status, tok)
	}
	return tok
}

var _ = mustTokens

// PROBE 8 — a request may not declare two client identities, on ANY endpoint the
// library authenticates with Basic. The device endpoint's half of this rule is
// pinned by TestAdversarialDeviceAuthorizationRefusesTwoClientIdentities; the
// token, introspection and revocation halves (internal/oidchttp/oidchttp.go:462)
// have no guard at all, and they are the three the library resolves the other way
// round (pkg/op/client.go ClientBasicAuth wins over the form).
func TestProbeTwoClientIdentitiesAreRefusedOnTheAuthenticatedEndpoints(t *testing.T) {
	e := newEnv(t, envOptions{issuer: "https://issuer.probe"})
	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "offline_access"}))

	cases := []struct {
		name string
		path string
		form url.Values
	}{
		{"token/refresh", "/oauth/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
			"client_id": {e.narrowID},
		}},
		{"introspect", "/oauth/introspect", url.Values{
			"token": {tokens.AccessToken}, "client_id": {e.narrowID},
		}},
		{"revoke", "/oauth/revoke", url.Values{
			"token": {tokens.AccessToken}, "client_id": {e.narrowID},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The authenticated identity is the web client; the form names another.
			resp, raw := e.postForm(t, tc.path, tc.form, e.webID, e.webSec)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s accepted two client identities: %d %s", tc.path, resp.StatusCode, raw)
			}
			if !strings.Contains(string(raw), "client_id does not match") {
				t.Logf("%s refused with: %s", tc.path, raw)
			}
		})
	}

	// The honest paths stay usable, so the guard is not a blanket refusal.
	resp, raw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control failed: Basic alone was refused: %d %s", resp.StatusCode, raw)
	}
	// ...including naming the SAME client in both places, which the rule permits.
	second := asTokens(t, e.codeFlow(t, []string{"account.id", "offline_access"}))
	resp, raw = e.postForm(t, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {second.RefreshToken},
		"client_id": {e.webID},
	}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control failed: the same client named twice was refused: %d %s", resp.StatusCode, raw)
	}
}
