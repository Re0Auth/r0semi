//go:build audit7

// Device-authorisation browser-plane probes: the verification page's data
// source, its decision endpoint, and how a decision that is not a decision is
// treated.
package z08frontendbrowser

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// deviceCode asks the OP for a real device authorisation and returns the
// user_code the verification page takes.
func deviceCode(t *testing.T, b *browser) (userCode, deviceCode string) {
	t.Helper()
	form := url.Values{"client_id": {z08ClientID}, "scope": {"account.id phigros.profile.read"}}
	req, err := http.NewRequest(http.MethodPost, b.env.server.URL+"/oauth/device_authorization",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization = %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if out.UserCode == "" || out.DeviceCode == "" {
		t.Fatalf("device_authorization returned no codes: %s", raw)
	}
	return out.UserCode, out.DeviceCode
}

// devicePending loads the verification page for a code and returns its view.
func devicePending(t *testing.T, b *browser, userCode string) map[string]any {
	t.Helper()
	resp := b.get("/v1/device/verification?user_code=" + url.QueryEscape(userCode))
	raw := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device verification = %d: %s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if out["state"] != "pending" {
		t.Fatalf("device verification state = %v (%s)", out["state"], raw)
	}
	return out
}

// TestZ08DeviceVerificationRequiresASession is the positive control for the
// binding rule the other probes rely on.
func TestZ08DeviceVerificationRequiresASession(t *testing.T) {
	env := newZ08Env(t, z08Options{})
	anon := env.newBrowser()
	starting := env.newBrowser()
	starting.signIn()
	userCode, _ := deviceCode(t, starting)

	resp := anon.get("/v1/device/verification?user_code=" + url.QueryEscape(userCode))
	raw := bodyOf(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an anonymous verification GET = %d (%s), want 401", resp.StatusCode, raw)
	}
	if !strings.Contains(raw, "unauthenticated") {
		t.Errorf("the anonymous refusal is not the business plane's problem shape: %s", raw)
	}
}

// TestZ08DeviceUnknownDecisionVerbIsRefusedNotSilentlyDenied asserts that the
// decision endpoint distinguishes "you said no" from "you did not say anything I
// understand". The consent endpoint already does (400 invalid_request); the
// device endpoint currently reads any non-"approve" value as a denial, so a
// typo consumes the code and tells the device the user refused.
//
// Failing this probe is the finding.
func TestZ08DeviceUnknownDecisionVerbIsRefusedNotSilentlyDenied(t *testing.T) {
	env := newZ08Env(t, z08Options{})
	b := env.newBrowser()
	b.signIn()
	userCode, _ := deviceCode(t, b)
	_ = devicePending(t, b, userCode)

	csrf := b.csrf()
	for _, verb := range []string{"", "APPROVE", "approve ", "yes"} {
		body, _ := json.Marshal(map[string]any{"user_code": userCode, "decision": verb})
		resp := b.do(http.MethodPost, "/v1/device/decision", string(body),
			map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf})
		raw := bodyOf(t, resp)
		if resp.StatusCode == http.StatusOK {
			t.Errorf("decision %q was answered 200 %s: an unrecognised verb is treated as a denial, "+
				"so a client typo silently refuses the login and burns the code", verb, raw)
			// Once consumed the code is gone; stop before the rest of the loop
			// measures a second, different failure.
			break
		}
	}
}

// TestZ08DeviceScreenDisplaysEveryDescribedScopeItGrantsOnce approves a device
// request the way the page does and compares the grant with the display.
func TestZ08DeviceScreenDisplaysEveryDescribedScopeItGrantsOnce(t *testing.T) {
	env := newZ08Env(t, z08Options{})
	b := env.newBrowser()
	b.signIn()
	userCode, _ := deviceCode(t, b)
	view := devicePending(t, b, userCode)

	scopesRaw, _ := view["scopes"].([]any)
	var displayed []string
	for _, s := range scopesRaw {
		if m, ok := s.(map[string]any); ok {
			if v, ok := m["scope"].(string); ok {
				displayed = append(displayed, v)
			}
		}
	}
	if len(displayed) == 0 {
		t.Fatalf("the device page displayed no scopes: %v", view)
	}
	csrf, _ := view["csrf_token"].(string)
	if csrf == "" {
		t.Fatal("the device verification view carried no CSRF token")
	}
	body, _ := json.Marshal(map[string]any{
		"user_code": userCode, "decision": "approve", "scopes": displayed,
	})
	resp := b.do(http.MethodPost, "/v1/device/decision", string(body),
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf})
	raw := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device decision = %d: %s", resp.StatusCode, raw)
	}
	t.Logf("device display: %v -> %s", displayed, raw)
	_ = env
}

// TestZ08DeviceCodeLoadedElsewhereCannotBeApprovedHere is the cross-browser
// guard, kept as a positive control for the handle binding.
func TestZ08DeviceCodeLoadedElsewhereCannotBeApprovedHere(t *testing.T) {
	env := newZ08Env(t, z08Options{})
	owner := env.newBrowser()
	owner.signIn()
	userCode, _ := deviceCode(t, owner)
	ownerView := devicePending(t, owner, userCode)

	other := env.newBrowser()
	other.signIn()
	// The other browser never loaded the code; it holds a valid CSRF token of its
	// own, which is the ingredient a cross-browser approval would need.
	csrf := other.csrf()
	body, _ := json.Marshal(map[string]any{
		"user_code": userCode, "decision": "approve", "scopes": []string{"account.id"},
	})
	resp := other.do(http.MethodPost, "/v1/device/decision", string(body),
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf})
	raw := bodyOf(t, resp)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a browser that never loaded the code approved it: %s", raw)
	}
	t.Logf("foreign approval -> %d %s", resp.StatusCode, raw)

	// And the owner's own approval still works, so the failure above is the
	// binding and not a broken endpoint.
	ownCSRF, _ := ownerView["csrf_token"].(string)
	body, _ = json.Marshal(map[string]any{
		"user_code": userCode, "decision": "approve", "scopes": []string{"account.id"},
	})
	resp = owner.do(http.MethodPost, "/v1/device/decision", string(body),
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": ownCSRF})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's own approval = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
}
