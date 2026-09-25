package httpapi

import (
	"context"
	"net/http"
	"testing"
)

// Rotating a confidential client's secret issues a new one and retires the old:
// the client id and its grants survive, which is the whole point of rotation.
func TestAdminRotateClientSecret(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/clients", csrf, map[string]any{
		"name":          "Rot App",
		"type":          "confidential",
		"redirect_uris": []string{"https://rot.example/cb"},
		"scopes":        []string{"openid"},
	})
	reg := decodeResp(t, resp)
	client, _ := reg["client"].(map[string]any)
	clientID, _ := client["client_id"].(string)
	oldSecret, _ := reg["client_secret"].(string)
	if clientID == "" || oldSecret == "" {
		t.Fatalf("register = %v", reg)
	}

	resp = adminJSON(t, browser, http.MethodPost,
		env.base+"/v1/admin/clients/"+clientID+"/rotate_secret", csrf, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate = %d, want 200", resp.StatusCode)
	}
	body := decodeResp(t, resp)
	newSecret, _ := body["client_secret"].(string)
	if newSecret == "" || newSecret == oldSecret {
		t.Fatalf("rotate returned no new secret: %v", body)
	}

	stored, err := env.clients.Get(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Authenticate(newSecret) {
		t.Error("the new secret does not authenticate the client")
	}
	if stored.Authenticate(oldSecret) {
		t.Error("the old secret still authenticates the client after rotation")
	}
}

// A public client has no secret to rotate; the endpoint says so rather than
// inventing one the client could not use.
func TestAdminRotateSecretRejectsPublicClient(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	// The seeded client "cli" is public.
	resp := adminJSON(t, browser, http.MethodPost,
		env.base+"/v1/admin/clients/cli/rotate_secret", csrf, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("rotate public client = %d, want 409", resp.StatusCode)
	}
}
