//go:build audit5

package protocol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The paired guard for P0-1 and P0-2, which the audit's ordering constraint makes
// one change: fixing P0-1 alone turns the id_token from a silent `{}` at userinfo
// into a usable identity bearer, so the subject claim and the bearer separation
// have to land together.
//
// P0-1 — every id_token this OP mints must carry `sub` = the logged-in `usr_…`.
// The mechanism was a no-op `SetUserinfoFromScopes` on both stores: the library
// fills a fresh `oidc.UserInfo` through it and then ASSIGNS `sub` from
// `UserInfo.Subject` (pkg/op/token.go CreateIDToken ->
// pkg/oidc/token.go SetUserInfo), so "no-op" meant "wipe the subject".
//
// P0-2 — an id_token must not authenticate at /oauth/userinfo, and a dead access
// token must not either. Two independent halves are pinned below: the boundary
// refusal of the compact-JWS shape the library's decryption fallback would verify,
// and the storage lookup that decides liveness.
func TestZZProbeIDTokenSubjectAndNonAccessTokenBearer(t *testing.T) {
	clock := newTestClock()
	e := newEnv(t, envOptions{issuer: "https://issuer.probe", now: clock.Now, clock: clock})

	userinfo := func(bearer string) (int, http.Header, map[string]any) {
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
		raw := bodyOf(t, resp)
		var claims map[string]any
		_ = json.Unmarshal(raw, &claims)
		return resp.StatusCode, resp.Header, claims
	}

	// --- P0-1: the subject on every issuance path -------------------------

	tokens := asTokens(t, e.codeFlow(t, []string{"openid", "account.id", "offline_access"}))
	if tokens.IDToken == "" {
		t.Fatal("the code exchange minted no id_token")
	}
	assertIDTokenSubject(t, "authorization_code", tokens.IDToken, "usr_probe")

	if tokens.RefreshToken == "" {
		t.Fatal("no refresh token, so the refresh path cannot be probed")
	}
	refreshed := asTokens(t, mustPost(t, e, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
	}, e.webID, e.webSec))
	assertIDTokenSubject(t, "refresh_token", refreshed.IDToken, "usr_probe")

	// The device grant reaches CreateIDToken through the same seam.
	deviceTokens := deviceGrant(t, e, "usr_probe")
	assertIDTokenSubject(t, "device_code", deviceTokens.IDToken, "usr_probe")

	// --- P0-2, first half: the id_token is not a bearer credential -------

	if tokens.IDToken != "" && !isThreeSegmentCompactJWS(tokens.IDToken) {
		t.Fatalf("the id_token is not a compact JWS, so this probe is aimed at nothing: %q", tokens.IDToken)
	}
	status, header, _ := userinfo(tokens.IDToken)
	if status == http.StatusOK {
		t.Errorf("the id_token authenticates at /oauth/userinfo: %d", status)
	}
	if status != http.StatusUnauthorized {
		t.Errorf("the id_token was refused with %d, want 401 (RFC 6750 §3.1)", status)
	}
	if challenge := header.Get("WWW-Authenticate"); !strings.HasPrefix(challenge, "Bearer ") ||
		!strings.Contains(challenge, "invalid_token") {
		t.Errorf("the refusal carries no Bearer invalid_token challenge: %q", challenge)
	}
	// The device id_token is the same shape and must be refused the same way.
	if status, _, _ := userinfo(deviceTokens.IDToken); status == http.StatusOK {
		t.Errorf("the device-grant id_token authenticates at /oauth/userinfo: %d", status)
	}

	// --- P0-2, second half: a dead access token is refused ---------------

	if status, _, claims := userinfo(tokens.AccessToken); status != http.StatusOK || claims["sub"] != "usr_probe" {
		t.Fatalf("control failed: the live access token is refused: %d %v", status, claims)
	}

	// Expiry: the access TTL is an hour, so two hours is past it.
	clock.Advance(2 * time.Hour)
	if status, _, claims := userinfo(tokens.AccessToken); status == http.StatusOK {
		t.Errorf("userinfo answered for an EXPIRED access token: %d %v", status, claims)
	}

	// Revocation: mint a fresh one, then revoke it the way a user would.
	fresh := asTokens(t, e.codeFlow(t, []string{"openid", "account.id"}))
	if status, _, _ := userinfo(fresh.AccessToken); status != http.StatusOK {
		t.Fatalf("control failed: the fresh token is refused: %d", status)
	}
	resp, raw := e.postForm(t, "/oauth/revoke", url.Values{"token": {fresh.AccessToken}}, e.webID, e.webSec)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revocation answered %d: %s", resp.StatusCode, raw)
	}
	status, header, claims := userinfo(fresh.AccessToken)
	if status == http.StatusOK {
		t.Errorf("userinfo answered for a REVOKED access token: %d %v", status, claims)
	}
	if status != http.StatusUnauthorized {
		t.Errorf("the revoked token was refused with %d, want 401", status)
	}
	if challenge := header.Get("WWW-Authenticate"); !strings.Contains(challenge, "invalid_token") {
		t.Errorf("the revoked-token refusal carries no invalid_token challenge: %q", challenge)
	}

	// An unknown and a malformed bearer stay 401, so the refusal is not narrower
	// than it was.
	for _, junk := range []string{"not-a-token-at-all", "a.b.c", fresh.AccessToken[:len(fresh.AccessToken)-2] + "xx"} {
		if status, _, _ := userinfo(junk); status != http.StatusUnauthorized {
			t.Errorf("bearer %q answered %d, want 401", junk, status)
		}
	}

	// The business plane's introspector is unaffected in both directions, so the
	// two planes still agree about what is live.
	if info, err := e.handler.Introspect(t.Context(), fresh.AccessToken); err != nil || info.Active {
		t.Errorf("the business plane still calls the revoked token active: %+v err=%v", info, err)
	}
}

// mustPost posts a form and insists on 200, so a probe failure names the step.
func mustPost(t *testing.T, e env, path string, form url.Values, basicID, basicSecret string) map[string]any {
	t.Helper()
	resp, raw := e.postForm(t, path, form, basicID, basicSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s = %d %s", path, resp.StatusCode, raw)
	}
	return decodeJSON(t, raw)
}

// deviceGrant drives the RFC 8628 grant to a token response, with the human
// approval going through the same store call the device route makes.
func deviceGrant(t *testing.T, e env, subject string) tokenJSON {
	t.Helper()
	resp, raw := e.postForm(t, "/oauth/device_authorization", url.Values{
		"client_id": {e.deviceID},
		"scope":     {"openid account.id offline_access"},
	}, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization = %d %s", resp.StatusCode, raw)
	}
	issued := decodeJSON(t, raw)
	deviceCode, _ := issued["device_code"].(string)
	userCode, _ := issued["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_authorization answered %s", raw)
	}
	if err := e.store.DecideDeviceAuthorization(t.Context(), userCode, subject, true, nil, nil); err != nil {
		t.Fatalf("approval: %v", err)
	}
	pollResp, pollRaw := e.postForm(t, "/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {e.deviceID},
	}, "", "")
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("device poll = %d %s", pollResp.StatusCode, pollRaw)
	}
	return asTokens(t, decodeJSON(t, pollRaw))
}

// isThreeSegmentCompactJWS is the probe's own shape test, written independently of
// the package under test so a bug in its helper cannot make this guard pass.
func isThreeSegmentCompactJWS(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}
