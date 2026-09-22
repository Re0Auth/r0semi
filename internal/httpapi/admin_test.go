package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/authz"
	"github.com/Re0Auth/r0semi/oauth"
)

type adminEnv struct {
	base    string
	adminID account.UserID
	clients *oauth.MemoryClientRegistry
	tokens  *oauth.MemoryStore
}

// revokingBindings stands in for the federation service in the operator tests.
type revokingBindings struct{ total int }

func (r *revokingBindings) RevokeAllBindings(context.Context) (admin.BindingOutcome, error) {
	return admin.BindingOutcome{Total: r.total, Revoked: r.total}, nil
}

func (r *revokingBindings) RevokeSubjectBindings(context.Context, string) (admin.BindingOutcome, error) {
	return admin.BindingOutcome{Total: 1, Revoked: 1}, nil
}

// newAdminEnv builds the stack with an operator plane. When allow is true the
// pre-created account (GitHub subject "42", the identity the fake IdP returns) is
// on the allowlist; otherwise nobody is.
func newAdminEnv(t *testing.T, allow bool) adminEnv {
	t.Helper()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
		case "/github/user":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(42), "login": "octocat", "name": "Octo"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)

	ctx := context.Background()
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "Phi CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	tokens := oauth.NewMemoryStore()
	as, err := oauth.NewService(clients, tokens, audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://re0auth.test", Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   fake.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL: fake.URL + "/github/authorize", TokenURL: fake.URL + "/github/token", UserInfoURL: fake.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	accounts := account.NewMemoryStore()
	user, _, err := accounts.CreateWithIdentity(ctx, idp.Identity{Provider: idp.GitHub, Subject: "42", DisplayName: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	manager := auth.NewManager(auth.Options{Secure: false})
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}
	azSvc, err := authz.NewService(as, authz.NewMemoryStore(), authz.Config{})
	if err != nil {
		t.Fatal(err)
	}
	adminSvc, err := admin.New(admin.Config{
		Clients: clients, Tokens: tokens, Bindings: &revokingBindings{total: 2}, Audit: audit.NewMemoryLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	admins := []account.UserID{"usr_nobody"}
	if allow {
		admins = []account.UserID{user.ID}
	}
	api, err := New(Config{
		Issuer: "https://re0auth.test", AS: as,
		Sessions: manager, Accounts: accounts, Auth: authHandler, Authz: azSvc,
		Admin: adminSvc, Admins: admins,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	return adminEnv{base: server.URL, adminID: user.ID, clients: clients, tokens: tokens}
}

// adminJSON sends a JSON body with the session's CSRF token. An empty csrf omits
// the header, which is how the CSRF test produces a rejection.
func adminJSON(t *testing.T, c *http.Client, method, target, csrf string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, target, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return doReq(t, c, req)
}

// A signed-in account that is not on the allowlist sees the same 404 as an
// unknown path: the operator plane is not advertised to it.
func TestAdminPlaneIsHiddenFromNonAdmins(t *testing.T) {
	env := newAdminEnv(t, false)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	resp := getURL(t, browser, env.base+"/v1/admin/clients")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-admin GET /v1/admin/clients = %d, want 404", resp.StatusCode)
	}
}

func TestAdminRegisterListSuspendDelete(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	// Register a confidential client; the secret comes back exactly once.
	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/clients", csrf, map[string]any{
		"name":          "New App",
		"type":          "confidential",
		"redirect_uris": []string{"https://new.example/cb"},
		"scopes":        []string{"openid"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d, want 201: %v", resp.StatusCode, decodeResp(t, resp))
	}
	body := decodeResp(t, resp)
	secret, _ := body["client_secret"].(string)
	clientView, _ := body["client"].(map[string]any)
	clientID, _ := clientView["client_id"].(string)
	if secret == "" || clientID == "" {
		t.Fatalf("register response = %v", body)
	}

	// It is active in the inventory, and the secret authenticates it.
	list := decodeResp(t, getURL(t, browser, env.base+"/v1/admin/clients"))
	if len(list["data"].([]any)) != 2 {
		t.Fatalf("inventory = %v, want the seeded client and the new one", list["data"])
	}
	stored, err := env.clients.Get(context.Background(), clientID)
	if err != nil || !stored.Authenticate(secret) {
		t.Fatalf("stored client does not accept the issued secret: %v", err)
	}

	// Suspend: it disappears from the protocol plane but stays in the inventory.
	if resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/clients/"+clientID+"/suspend", csrf, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("suspend = %d, want 204", resp.StatusCode)
	}
	if _, err := env.clients.Get(context.Background(), clientID); err == nil {
		t.Fatal("suspended client still resolves")
	}
	suspended := decodeResp(t, getURL(t, browser, env.base+"/v1/admin/clients"))
	found := false
	for _, raw := range suspended["data"].([]any) {
		row := raw.(map[string]any)
		if row["client_id"] == clientID {
			found = true
			if row["status"] != "suspended" {
				t.Fatalf("status = %v, want suspended", row["status"])
			}
		}
	}
	if !found {
		t.Fatal("suspended client missing from the inventory")
	}

	if resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/clients/"+clientID+"/activate", csrf, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("activate = %d, want 204", resp.StatusCode)
	}
	if _, err := env.clients.Get(context.Background(), clientID); err != nil {
		t.Fatalf("reactivated client: %v", err)
	}

	if resp := adminJSON(t, browser, http.MethodDelete, env.base+"/v1/admin/clients/"+clientID, csrf, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", resp.StatusCode)
	}
	if _, err := env.clients.Get(context.Background(), clientID); err == nil {
		t.Fatal("deleted client still resolves")
	}
}

func TestAdminWritesRequireCSRF(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/clients", "", map[string]any{
		"name": "No CSRF", "type": "public",
		"redirect_uris": []string{"https://new.example/cb"}, "scopes": []string{"openid"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("register without CSRF = %d, want 403", resp.StatusCode)
	}
}

func TestAdminKillSwitchReportsWhatItCut(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	ctx := context.Background()
	if err := env.tokens.SaveAccess(ctx, "at-1", oauth.AccessToken{ClientID: "cli", Subject: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if err := env.tokens.SaveRefresh(ctx, "rt-1", oauth.RefreshToken{ClientID: "cli", Subject: "usr_1"}); err != nil {
		t.Fatal(err)
	}

	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/kill_switch", csrf, map[string]any{"target": "all"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kill switch = %d, want 200: %v", resp.StatusCode, decodeResp(t, resp))
	}
	rep := decodeResp(t, resp)
	if rep["tokens_revoked"].(float64) != 2 {
		t.Fatalf("tokens_revoked = %v, want 2", rep["tokens_revoked"])
	}
	if len(mustRecords(t, env.tokens, "usr_1")) != 0 {
		t.Fatal("tokens survived the kill switch")
	}
}

func TestAdminKillSwitchRejectsMissingTarget(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/kill_switch", csrf, map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("kill switch without target = %d, want 400", resp.StatusCode)
	}
}

// The bindings target revokes bindings only: the report carries the binding
// outcome and no token was touched.
func TestAdminKillSwitchBindingsTarget(t *testing.T) {
	env := newAdminEnv(t, true)
	browser := newBrowser(t)
	signIn(t, browser, env.base)
	csrf := sessionCSRF(t, env.base, browser)

	ctx := context.Background()
	if err := env.tokens.SaveAccess(ctx, "at-1", oauth.AccessToken{ClientID: "cli", Subject: "usr_1"}); err != nil {
		t.Fatal(err)
	}

	resp := adminJSON(t, browser, http.MethodPost, env.base+"/v1/admin/kill_switch", csrf, map[string]any{"target": "bindings"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bindings kill switch = %d, want 200: %v", resp.StatusCode, decodeResp(t, resp))
	}
	rep := decodeResp(t, resp)
	if rep["tokens_revoked"].(float64) != 0 {
		t.Fatalf("a bindings-only switch revoked %v tokens", rep["tokens_revoked"])
	}
	bindings, ok := rep["bindings"].(map[string]any)
	if !ok || bindings["total"].(float64) != 2 || bindings["revoked"].(float64) != 2 {
		t.Fatalf("bindings report = %v", rep["bindings"])
	}
}

func mustRecords(t *testing.T, s *oauth.MemoryStore, subject string) []oauth.GrantRecord {
	t.Helper()
	recs, err := s.ListBySubject(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}
