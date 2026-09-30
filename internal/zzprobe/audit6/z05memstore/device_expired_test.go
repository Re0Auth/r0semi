//go:build audit6

// G-7 guard: an approved device_code must not mint past the lifetime the server
// advertised.
//
// The library's CheckDeviceAuthorizationState (pkg/op/device.go:317-326) only
// judges state.Expires for a PENDING code; a Done code is handed straight to
// the mint. The store is therefore the only place that can refuse an approved
// code past its deadline. Both backends now carry the expiry predicate on the
// done branch, and the memory store additionally clears Done on the consumed
// record so the library's Done-before-Expires order falls through to a refusal:
//
//	memory/oidc.go    GetDeviceAuthorizatonState: expired done record → Done=false
//	postgres/oidc.go  claim ... AND expires_at > $3, plus the fall-through delete
//
// This probe previously encoded the finding (it FATALed when the poll was
// refused); it is inverted here into the guard.
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

// After the store's clock passes the device authorization's expiry, redeeming
// the device_code must be refused (RFC 8628 §3.5) and the refusal must carry no
// tokens.
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
	if rec.Code == http.StatusOK {
		t.Fatalf("a device_code redeemed %s past its advertised expiry minted a token response: %d %s",
			time.Duration(expiresIn)*time.Second+time.Minute, rec.Code, rec.Body.String())
	}
	// A refusal must not smuggle a usable pair in its body.
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatalf("refusal body does not parse as JSON: %v (%s)", err, rec.Body.String())
	}
	if tok["access_token"] != nil || tok["refresh_token"] != nil {
		t.Fatalf("the expired-code refusal still carried tokens: %v", tok)
	}
	t.Logf("expired approved device_code refused: %d %s", rec.Code, rec.Body.String())
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
