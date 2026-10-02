package oidchttp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/oauth"
)

// G-10 (docs/issues/P2-medium.md): the device grant's poll resolves its client
// from HTTP Basic or a JWT assertion only (zitadel/oidc pkg/op/device.go
// ClientIDFromRequest), so the client_secret_post method this token endpoint
// advertises was refused — after the approved device_code had already been
// consumed by CheckDeviceAuthorizationState. These are the default-suite tests
// for the boundary fix in oidchttp.go: a confidential client may post its
// secret, a missing or wrong secret is a 401 that burns nothing, and the public
// "none" method keeps working.

// startDeviceAuthz runs the device_authorization leg. basicID/secret may be
// empty for a public client, which names itself in the body only.
func startDeviceAuthz(t testing.TB, f fixture, clientID, basicID, secret string, scopes []string) (deviceCode, userCode string) {
	t.Helper()
	form := url.Values{"client_id": {clientID}, "scope": {strings.Join(scopes, " ")}}
	req, err := http.NewRequest(http.MethodPost, f.server.URL+"/oauth/device_authorization",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization = %d: %s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("device_authorization body does not parse: %v (%s)", err, raw)
	}
	deviceCode, _ = out["device_code"].(string)
	userCode, _ = out["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_authorization lacks codes: %v", out)
	}
	return deviceCode, userCode
}

// pollDeviceGrant posts the device_code grant to the token endpoint. basicID
// empty means no Basic header (the posted-secret or none shapes).
func pollDeviceGrant(t testing.TB, f fixture, form url.Values, basicID, secret string) (map[string]any, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.server.URL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode
}

func approvedDeviceCode(t testing.TB, f fixture, clientID, basicID, secret string) string {
	t.Helper()
	deviceCode, userCode := startDeviceAuthz(t, f, clientID, basicID, secret, []string{"account.id"})
	if err := f.store.ApproveDevice(context.Background(), userCode, "usr_1", nil); err != nil {
		t.Fatalf("approve device: %v", err)
	}
	return deviceCode
}

func TestDeviceGrantPollAcceptsAdvertisedClientSecretPost(t *testing.T) {
	f := newFixture(t)
	deviceCode := approvedDeviceCode(t, f, f.webID, f.webID, "s3cret")

	body, status := pollDeviceGrant(t, f, url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {f.webID},
		"client_secret": {"s3cret"},
	}, "", "")
	if status != http.StatusOK {
		t.Fatalf("the device poll refused the advertised client_secret_post method: %d %v", status, body)
	}
	if tok, _ := body["access_token"].(string); tok == "" {
		t.Fatalf("the accepted post-method poll returned no access token: %v", body)
	}
}

func TestDeviceGrantPollRefusesUnusableSecretWithoutBurningTheCode(t *testing.T) {
	f := newFixture(t)
	deviceCode := approvedDeviceCode(t, f, f.webID, f.webID, "s3cret")

	base := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {f.webID},
	}

	// Missing secret: 401 invalid_client, with no store call.
	body, status := pollDeviceGrant(t, f, base, "", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("a poll with a missing secret = %d %v, want 401", status, body)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("missing-secret error = %v, want invalid_client", body)
	}

	// Wrong secret: the same 401.
	wrong := url.Values{}
	for k, v := range base {
		wrong[k] = v
	}
	wrong.Set("client_secret", "not-the-secret")
	body, status = pollDeviceGrant(t, f, wrong, "", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("a poll with a wrong secret = %d %v, want 401", status, body)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("wrong-secret error = %v, want invalid_client", body)
	}

	// The proof that neither refusal burned the approved device_code: the SAME
	// code still redeems with Basic.
	body, status = pollDeviceGrant(t, f, base, f.webID, "s3cret")
	if status != http.StatusOK {
		t.Fatalf("the refused polls burned the approved device_code: Basic re-poll = %d %v", status, body)
	}
	if tok, _ := body["access_token"].(string); tok == "" {
		t.Fatalf("the recovery poll returned no access token: %v", body)
	}
}

// TestDeviceAuthorizationAcceptsFormURLEncodedBasicSecret pins RFC 6749 §2.3.1
// at the device authorization endpoint: the Basic credentials are
// form-urlencoded before base64, so a compliant secret containing ' ', '+', '%'
// or '&' reaches the server percent-encoded. The pre-flight decoded only the
// username, hashed the still-escaped secret, and refused the client with a 401.
func TestDeviceAuthorizationAcceptsFormURLEncodedBasicSecret(t *testing.T) {
	f := newFixture(t)

	// A literal secret whose characters all have a form-urlencoded form: '+' and
	// '%' both force an escape, so an undecoded comparison cannot accidentally
	// match.
	const secret = "pass+word%end"
	id := "http-encsec-" + randSuffix()
	client, err := oauth.NewClient(id, "Encoded Secret", oauth.ClientConfidential, secret,
		[]string{"https://client.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.handler.clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}

	deviceAuthz := func(basicID, basicSecret string) (int, map[string]any) {
		t.Helper()
		form := url.Values{"scope": {"account.id"}}
		req, err := http.NewRequest(http.MethodPost, f.server.URL+"/oauth/device_authorization",
			strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(basicID, basicSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}

	// The compliant client: both halves percent-encoded, exactly as §2.3.1
	// describes.
	status, body := deviceAuthz(url.QueryEscape(id), url.QueryEscape(secret))
	if status != http.StatusOK {
		t.Fatalf("the form-urlencoded Basic secret was refused: %d %v", status, body)
	}
	if code, _ := body["device_code"].(string); code == "" {
		t.Fatalf("accepted device_authorization returned no device_code: %v", body)
	}

	// Control: the same client with the secret left unencoded is NOT its secret.
	// The fix decodes the pair; it does not stop checking it.
	status, body = deviceAuthz(url.QueryEscape(id), secret)
	if status != http.StatusUnauthorized {
		t.Fatalf("an unencoded Basic secret = %d %v, want 401", status, body)
	}
}

func TestDeviceGrantPollKeepsThePublicNoneMethod(t *testing.T) {
	f := newFixture(t)
	deviceCode := approvedDeviceCode(t, f, f.deviceID, "", "")

	body, status := pollDeviceGrant(t, f, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {f.deviceID},
	}, "", "")
	if status != http.StatusOK {
		t.Fatalf("the public none-method device poll = %d %v, want 200", status, body)
	}
	if tok, _ := body["access_token"].(string); tok == "" {
		t.Fatalf("the none-method poll returned no access token: %v", body)
	}
}
