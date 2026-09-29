//go:build audit6

// Finding 05-2: an approved device_code still mints tokens after the lifetime
// the server advertised has passed.
//
// The library's CheckDeviceAuthorizationState (pkg/op/device.go:317-326) only
// judges state.Expires for a PENDING code; a Done code is handed straight to
// the mint. The store is therefore the only place that can refuse an approved
// code past its deadline — and neither backend's GetDeviceAuthorizatonState
// checks expires_at on the done branch:
//
//	memory/oidc.go    GetDeviceAuthorizatonState: `if d.done && !d.denied { delete; return st }`
//	postgres/oidc.go  `DELETE FROM oidc_devices WHERE ... AND done = true AND denied = false`
//
// (memory half exercised here; the Postgres half is the same shape by
// reading — no database is available in this environment.) Until the janitor
// runs (every 5 minutes in memory mode, 15 for the Postgres sweep), the
// device_code holder can redeem it after the advertised expiry_in.
package z05memstore

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The safe property, asserted at the real token endpoint: after the store's
// clock passes the device authorization's expiry, redeeming the device_code
// must be refused (RFC 8628 §3.5 expired_token). It currently mints a full
// access/refresh pair, so this probe is red.
func TestDeviceCodePastItsAdvertisedExpiryStillMintsTokens(t *testing.T) {
	e := newEnv(t, nil)

	start := e.deviceStart(t, "openid account.id")
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	expiresIn, _ := start["expires_in"].(float64)
	if deviceCode == "" || userCode == "" || expiresIn <= 0 {
		t.Fatalf("device_authorization response lacks codes: %v", start)
	}

	// The user approves while the code is unexpired (the store clock still
	// agrees with the wall clock the library wrote the deadline with).
	if err := e.store.DecideDeviceAuthorization(t.Context(), userCode, "usr_probe", true, nil, nil); err != nil {
		t.Fatalf("approving the pending device code failed: %v", err)
	}

	// Past the advertised lifetime: the store's clock is now beyond the
	// expires_at the library wrote for this device code.
	e.clock.Advance(time.Duration(expiresIn)*time.Second + time.Minute)

	rec := e.devicePoll(deviceCode)
	if rec.Code != http.StatusOK {
		t.Fatalf("UNEXPECTED: redeeming an expired device_code was refused: %d %s",
			rec.Code, rec.Body.String())
	}
	// The finding: a 200 with a live token pair minted from an expired code.
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatalf("token response does not parse: %v (%s)", err, rec.Body.String())
	}
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("token response lacks the pair: %v", tok)
	}

	// And the minted access token is a live capability at userinfo: the
	// expired device code produced a working identity bearer.
	if req := probeBearer(t, e, access); req.Code != http.StatusOK {
		t.Fatalf("UNEXPECTED: the minted token was not usable at userinfo: %d %s",
			req.Code, req.Body.String())
	}

	// The assertion the guard should satisfy once fixed: redemption past the
	// deadline must not mint. Red until then.
	t.Errorf("a device_code redeemed %s past its advertised expiry minted a full "+
		"access/refresh pair (access_token len=%d) and the access token answered "+
		"userinfo with 200 — expected expired_token", time.Duration(expiresIn)*time.Second+time.Minute, len(access))
}

// Control: the same flow without advancing the clock mints, so a red probe
// above cannot be "the device flow never worked in this fixture".
func TestDeviceCodeRedeemsWithinItsLifetime(t *testing.T) {
	e := newEnv(t, nil)

	start := e.deviceStart(t, "openid account.id")
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_authorization response lacks codes: %v", start)
	}
	if err := e.store.DecideDeviceAuthorization(t.Context(), userCode, "usr_probe", true, nil, nil); err != nil {
		t.Fatalf("approving the pending device code failed: %v", err)
	}

	rec := e.devicePoll(deviceCode)
	if rec.Code != http.StatusOK {
		t.Fatalf("redeeming an unexpired approved device_code = %d: %s", rec.Code, rec.Body.String())
	}
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	if tok["access_token"] == "" {
		t.Fatalf("no access token in the in-lifetime response: %v", tok)
	}
	// P0-1 regression on the same response: the id_token carries the subject.
	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in the device response despite the openid scope: %v", tok)
	}
	if sub := claimOf(t, idToken, "sub"); sub != "usr_probe" {
		t.Fatalf("id_token sub = %q, want usr_probe (P0-1 regression)", sub)
	}
}

// claimOf decodes one claim out of a compact JWT's payload without verifying
// it: the signature was already verified end to end by reaching it through
// the real token endpoint.
func claimOf(t *testing.T, token string, claim string) any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("id_token payload does not decode: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("id_token payload does not parse: %v", err)
	}
	return claims[claim]
}

// probeBearer performs GET /oauth/userinfo with the given bearer.
func probeBearer(t *testing.T, e *env, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}
