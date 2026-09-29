//go:build audit6

// P0-1 / P0-2 regression, memory backend, end to end through the real token
// endpoint: the id_token minted by the device grant carries the subject
// (02dd448), and the access token the same grant minted works at userinfo
// while an unrelated bearer does not. The Postgres twin is identical by
// reading (SetUserinfoFromScopes sets userinfo.Subject in both).
package z05memstore

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestDeviceGrantIDTokenCarriesSubjectAndTheBearerWorksAtUserinfo(t *testing.T) {
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
		t.Fatalf("device token poll = %d: %s", rec.Code, rec.Body.String())
	}
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}

	// P0-1: the id_token's sub is the signed-in subject, not the empty value
	// claims.SetUserInfo assigns when the callback is a no-op.
	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in the response despite the openid scope: %v", tok)
	}
	if sub := claimOf(t, idToken, "sub"); sub != "usr_probe" {
		t.Fatalf("P0-1 regression: id_token sub = %v, want usr_probe", sub)
	}

	// P0-2 (store half): the opaque access token works at userinfo.
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token in the response: %v", tok)
	}
	rec = probeBearer(t, e, access)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo with the minted access token = %d: %s", rec.Code, rec.Body.String())
	}
	var ui map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &ui); err != nil {
		t.Fatal(err)
	}
	if ui["sub"] != "usr_probe" {
		t.Fatalf("userinfo sub = %v, want usr_probe", ui["sub"])
	}

	// And a made-up bearer is refused rather than answered with a subject.
	rec = probeBearer(t, e, "definitely-not-a-token-this-op-issued")
	if rec.Code == http.StatusOK {
		t.Fatalf("userinfo answered 200 for a bearer this OP never issued: %s", rec.Body.String())
	}
}
