package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/vault"
)

// bindingEnv is a federation service plus the stores a test needs to bind a
// source by hand, mirroring what the binding flow does in production.
type bindingEnv struct {
	service  federation.Service
	bindings *federation.MemoryBindingStore
	vault    vault.Service
}

func newBindingEnv(t *testing.T) bindingEnv {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("test", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	reg, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", DisplayName: "Fake Source",
		Issuer: "https://up.example", TokenClass: "revocable",
		Resources: []federation.Resource{{
			Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	svc, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: bindings, Vault: v,
		Doer: http.DefaultClient, BaseURL: "https://re0auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return bindingEnv{service: svc, bindings: bindings, vault: v}
}

// bind connects the fake source for one account, which is what the consent
// screen's "connect" button eventually produces.
func (e bindingEnv) bind(t *testing.T, user account.UserID) {
	t.Helper()
	b := federation.Binding{User: user, Game: "phigros", Source: "fake", Version: 1}
	if err := e.bindings.Put(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := e.vault.Enroll(context.Background(), federation.BindingIdentity(b), []byte(`{"access_token":"t"}`), nil); err != nil {
		t.Fatal(err)
	}
}

// bindingVerifier is long enough for PKCE and unique to these tests.
const bindingVerifier = "verifier-verifier-verifier-verifier-verifier"

// missingBindingOf extracts the first missing binding from a consent view.
func missingBindingOf(t *testing.T, view map[string]any) map[string]any {
	t.Helper()
	items, ok := view["missing_bindings"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("missing_bindings = %v, want one entry", view["missing_bindings"])
	}
	entry, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("missing binding is not an object: %v", items[0])
	}
	return entry
}

// A consent request for a scope that needs a data source the account has not
// connected must say so, and carry a link back to this consent screen.
func TestAuthorizationRequestReportsMissingBinding(t *testing.T) {
	env := newBindingEnv(t)
	base, _ := newFlowEnvWith(t, env.service)
	browser := newBrowser(t)
	signIn(t, browser, base)

	handle := authorize(t, browser, base, bindingVerifier, "account.id phigros.score.read", "st-bind")
	resp := getURL(t, browser, base+"/v1/authorization_requests/"+handle)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("consent status = %d", resp.StatusCode)
	}
	entry := missingBindingOf(t, decodeResp(t, resp))

	if entry["game"] != "phigros" || entry["source"] != "fake" || entry["display_name"] != "Fake Source" {
		t.Fatalf("missing binding = %v", entry)
	}
	scopes, _ := entry["scopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "phigros.score.read" {
		t.Fatalf("missing binding scopes = %v", entry["scopes"])
	}

	bindURL, _ := entry["bind_url"].(string)
	u, err := url.Parse(bindURL)
	if err != nil {
		t.Fatalf("bind_url %q: %v", bindURL, err)
	}
	if u.Path != "/bind" || u.Query().Get("game") != "phigros" || u.Query().Get("source") != "fake" {
		t.Fatalf("bind_url = %s", u)
	}
	// The return trip has to land back on this exact pending request, or the
	// user is dropped on a fresh consent screen with no handle.
	if !strings.Contains(u.Query().Get("return_to"), handle) {
		t.Fatalf("bind_url does not return to the consent handle: %s", u.Query().Get("return_to"))
	}
}

// Once the source is connected, the same request no longer asks for anything.
func TestAuthorizationRequestNoMissingBindingWhenConnected(t *testing.T) {
	env := newBindingEnv(t)
	base, accounts := newFlowEnvWith(t, env.service)
	browser := newBrowser(t)
	signIn(t, browser, base)

	uid, err := accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}
	env.bind(t, uid)

	handle := authorize(t, browser, base, bindingVerifier, "account.id phigros.score.read", "st-bound")
	resp := getURL(t, browser, base+"/v1/authorization_requests/"+handle)
	view := decodeResp(t, resp)
	items, _ := view["missing_bindings"].([]any)
	if len(items) != 0 {
		t.Fatalf("missing_bindings = %v, want none for a bound source", view["missing_bindings"])
	}
}

// A scope that needs no data source never produces a binding prompt.
func TestAuthorizationRequestNoBindingForAccountScope(t *testing.T) {
	env := newBindingEnv(t)
	base, _ := newFlowEnvWith(t, env.service)
	browser := newBrowser(t)
	signIn(t, browser, base)

	handle := authorize(t, browser, base, bindingVerifier, "account.id", "st-account")
	resp := getURL(t, browser, base+"/v1/authorization_requests/"+handle)
	view := decodeResp(t, resp)
	items, _ := view["missing_bindings"].([]any)
	if len(items) != 0 {
		t.Fatalf("missing_bindings = %v, want none", view["missing_bindings"])
	}
}
