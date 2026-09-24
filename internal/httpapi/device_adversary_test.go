package httpapi

// Adversarial guards for the RFC 8628 device flow (round 3, area 3). Each test
// names the finding it pins; the first three failed before the fix and pass
// after, the rest pin behaviour that held so a later pass does not repeat them.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

func deviceEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	env.register(t, "cli", oauth.ClientPublic, "", []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	return env
}

func startDevice(t *testing.T, env *testEnv, scope string) (deviceCode, userCode string) {
	t.Helper()
	form := url.Values{"client_id": {"cli"}, "scope": {scope}}
	rec := env.do(http.MethodPost, "/oauth/device_authorization", form.Encode(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("device_authorization was refused: %d", rec.Code)
	}
	doc := decodeJSON(t, rec)
	deviceCode, _ = doc["device_code"].(string)
	userCode, _ = doc["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_authorization carried no codes: %v", doc)
	}
	return deviceCode, userCode
}

func pollDevice(t *testing.T, env *testEnv, deviceCode string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"cli"},
	}
	rec := env.do(http.MethodPost, "/oauth/token", form.Encode(), nil)
	return rec.Code, decodeJSON(t, rec)
}

func meSubject(t *testing.T, env *testEnv, token string) (int, string) {
	t.Helper()
	rec := env.do(http.MethodGet, "/v1/me", "", map[string]string{"Authorization": "Bearer " + token})
	if rec.Code != http.StatusOK {
		return rec.Code, ""
	}
	id, _ := decodeJSON(t, rec)["id"].(string)
	return rec.Code, id
}

// A device code is single use. The library reads the state once, right before it
// mints, and has no consume step of its own; without the store consuming it, a
// held device_code kept minting fresh access/refresh pairs for its whole TTL.
func TestAdversarialDeviceCodeIsSingleUse(t *testing.T) {
	env := deviceEnv(t)
	ctx := context.Background()
	dc, uc := startDevice(t, env, "account.id")
	if err := env.store.ApproveDevice(ctx, uc, "usr_1", nil); err != nil {
		t.Fatal("approve was refused")
	}

	status1, first := pollDevice(t, env, dc)
	if status1 != http.StatusOK {
		t.Fatalf("the first exchange was refused: %d %v", status1, first)
	}
	token1, _ := first["access_token"].(string)
	if token1 == "" {
		t.Fatal("the first exchange minted no access token")
	}

	status2, second := pollDevice(t, env, dc)
	if status2 == http.StatusOK {
		t.Fatalf("a second exchange of the same device code minted another token: %v", second)
	}
}

// Revocation must reach the device code, not only the tokens it minted. An empty
// TokenFilter is what the Kill Switch `all` target uses; before the fix the next
// poll minted a fresh live token pair, silently undoing the revocation.
func TestAdversarialDeviceCodeIsRevokedByBulkRevocation(t *testing.T) {
	env := deviceEnv(t)
	ctx := context.Background()
	dc, uc := startDevice(t, env, "account.id")
	if err := env.store.ApproveDevice(ctx, uc, "usr_1", nil); err != nil {
		t.Fatal("approve was refused")
	}
	status1, first := pollDevice(t, env, dc)
	if status1 != http.StatusOK {
		t.Fatalf("the first exchange was refused: %d %v", status1, first)
	}
	token1, _ := first["access_token"].(string)

	removed, err := env.store.RevokeTokens(ctx, oauth.TokenFilter{})
	if err != nil {
		t.Fatal("bulk revocation failed")
	}
	if removed == 0 {
		t.Fatal("bulk revocation removed nothing")
	}
	if code, _ := meSubject(t, env, token1); code != http.StatusUnauthorized {
		t.Error("a revoked access token still authenticates")
	}
	status2, second := pollDevice(t, env, dc)
	if status2 == http.StatusOK {
		token2, _ := second["access_token"].(string)
		code, sub := meSubject(t, env, token2)
		if code == http.StatusOK {
			t.Errorf("the device code minted a fresh LIVE token after revocation; subject %s", sub)
		}
	}
}

// The user-facing half: the revoke button calls RevokeGrant with a client filter,
// and a device code for that client must stop working too.
func TestAdversarialDeviceCodeIsRevokedByTheRevokeButton(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)

	start := decodeResp(t, postForm(t, browser, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"}, "scope": {"account.id"},
	}))
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)

	view := decodeResp(t, getURL(t, browser, base+"/v1/device/verification?user_code="+url.QueryEscape(userCode)))
	csrf, _ := view["csrf_token"].(string)
	body, _ := json.Marshal(map[string]any{"user_code": userCode, "decision": "approve", "scopes": []string{"account.id"}})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	dec := doReq(t, browser, req)
	if dec.StatusCode != http.StatusOK {
		dec.Body.Close()
		t.Fatal("the approval was refused")
	}
	dec.Body.Close()

	first := decodeResp(t, postForm(t, browser, base+"/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"cli"},
	}))
	token1, _ := first["access_token"].(string)
	if token1 == "" {
		t.Fatal("the first exchange minted no token")
	}

	del, _ := http.NewRequest(http.MethodDelete, base+"/v1/grants/cli", nil)
	del.Header.Set("X-CSRF-Token", csrf)
	resp := doReq(t, browser, del)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("the revoke = %d, want 204", resp.StatusCode)
	}

	mereq, _ := http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	mereq.Header.Set("Authorization", "Bearer "+token1)
	if me := doReq(t, browser, mereq); me.StatusCode != http.StatusUnauthorized {
		me.Body.Close()
		t.Error("the revoked token still works")
	} else {
		me.Body.Close()
	}

	second := postForm(t, browser, base+"/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"cli"},
	})
	defer second.Body.Close()
	if second.StatusCode == http.StatusOK {
		t.Error("the device code minted a token after the user revoked the grant")
	}
}

// A recorded denial must outrank an approval whichever order the two writes land
// in: the library tests Denied before Done, and this pins that the store does not
// let a later approval erase a denial.
func TestAdversarialDeviceDenyWinsWhicheverWriteOrder(t *testing.T) {
	orders := []string{"deny then approve", "approve then deny"}
	for _, order := range orders {
		t.Run(order, func(t *testing.T) {
			env := deviceEnv(t)
			ctx := context.Background()
			dc, uc := startDevice(t, env, "account.id")
			if order == orders[0] {
				if err := env.store.DenyDevice(ctx, uc); err != nil {
					t.Fatal("deny was refused")
				}
				_ = env.store.ApproveDevice(ctx, uc, "usr_1", nil)
			} else {
				if err := env.store.ApproveDevice(ctx, uc, "usr_1", nil); err != nil {
					t.Fatal("approve was refused")
				}
				if err := env.store.DenyDevice(ctx, uc); err != nil {
					t.Fatal("deny was refused")
				}
			}
			status, doc := pollDevice(t, env, dc)
			if status == http.StatusOK {
				t.Fatalf("a denied device authorization still minted a token: %v", doc)
			}
		})
	}
}

// The token's subject is whatever the approver's session said — never a
// request-supplied value, and never empty. Two approvals race, so the winner is
// either approver; what must never happen is a third party.
func TestAdversarialDeviceTokenSubjectIsAlwaysAnApprover(t *testing.T) {
	env := deviceEnv(t)
	ctx := context.Background()
	dc, uc := startDevice(t, env, "account.id")
	if err := env.store.ApproveDevice(ctx, uc, "usr_1", nil); err != nil {
		t.Fatal("first approve was refused")
	}
	_ = env.store.ApproveDevice(ctx, uc, "usr_2", nil)

	status, doc := pollDevice(t, env, dc)
	if status != http.StatusOK {
		t.Fatalf("no token was issued after approval: %d %v", status, doc)
	}
	token, _ := doc["access_token"].(string)
	code, sub := meSubject(t, env, token)
	if code != http.StatusOK {
		t.Fatalf("the minted token does not work: %d", code)
	}
	if sub != "usr_1" && sub != "usr_2" {
		t.Fatalf("the token subject is not an approver: %q", sub)
	}
}

// The subject is the account that approved, taken from its session, and the token
// is bound to the client that started the flow.
func TestAdversarialDeviceTokenSubjectIsTheApprovingBrowser(t *testing.T) {
	base, _ := newFlowEnv(t)
	cli := newBrowser(t)
	victim := newBrowser(t)
	start := decodeResp(t, postForm(t, cli, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"}, "scope": {"account.id"},
	}))
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)

	signInAs(t, victim, base, "v")
	want, _ := decodeResp(t, getURL(t, victim, base+"/v1/sessions/current"))["user_id"].(string)
	view := decodeResp(t, getURL(t, victim, base+"/v1/device/verification?user_code="+url.QueryEscape(userCode)))
	csrf, _ := view["csrf_token"].(string)
	body, _ := json.Marshal(map[string]any{"user_code": userCode, "decision": "approve", "scopes": []string{"account.id"}})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	dresp := doReq(t, victim, req)
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatal("the approval was refused")
	}

	tok := decodeResp(t, postForm(t, cli, base+"/oauth/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"cli"},
	}))
	at, _ := tok["access_token"].(string)
	if at == "" {
		t.Fatal("the CLI got no token")
	}
	mereq, _ := http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	mereq.Header.Set("Authorization", "Bearer "+at)
	me := decodeResp(t, doReq(t, cli, mereq))
	if me["id"] != want {
		t.Error("the token subject is not the account that approved")
	}
	if me["client_id"] != "cli" {
		t.Error("the token is not bound to the client that started the flow")
	}
}

// Neither device endpoint answers an anonymous caller, and neither distinguishes
// a live user_code from a dead one without a session.
func TestAdversarialDeviceEndpointsAreNotAnonymousOracles(t *testing.T) {
	base, _ := newFlowEnv(t)
	anon := newBrowser(t)
	start := decodeResp(t, postForm(t, anon, base+"/oauth/device_authorization", url.Values{
		"client_id": {"cli"}, "scope": {"account.id"},
	}))
	live, _ := start["user_code"].(string)

	for _, code := range []string{live, "ZZZZ-ZZZZ"} {
		resp := getURL(t, anon, base+"/v1/device/verification?user_code="+url.QueryEscape(code))
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Error("an anonymous browser was served the device verification page")
		}
		resp.Body.Close()
	}
	body, _ := json.Marshal(map[string]any{"user_code": live, "decision": "approve"})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/device/decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "x")
	dresp := doReq(t, anon, req)
	dresp.Body.Close()
	if dresp.StatusCode == http.StatusOK {
		t.Error("an anonymous decision was accepted")
	}
}
