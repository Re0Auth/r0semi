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
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

// stubDeleter satisfies Config.Deleter for tests that only need the route to be
// mounted (the OpenAPI and plane guards). No test asserts on what it did.
type stubDeleter struct{}

func (stubDeleter) DeleteAccount(context.Context, account.UserID, account.UserID) (lifecycle.Result, error) {
	return lifecycle.Result{}, nil
}

// deleteEnv is a full browser-facing stack with account erasure wired to a real
// lifecycle.Deleter over in-memory stores, so the handler test exercises the same
// orchestration production runs rather than a fake of it.
type deleteEnv struct {
	base     string
	accounts *account.MemoryStore
	vault    vault.Repo
	bindings *federation.MemoryBindingStore
	logger   *audit.MemoryLogger
}

func newDeleteEnv(t *testing.T) deleteEnv {
	t.Helper()
	ctx := context.Background()

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

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, client); err != nil {
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
	manager := auth.NewManager(auth.Options{Secure: false})
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}
	opHandler, store := newOPBackend(t, "https://re0auth.test", clients, manager)

	creds := vault.NewMemoryRepo()
	bindings := federation.NewMemoryBindingStore()
	logger := audit.NewMemoryLogger()
	deleter, err := lifecycle.New(lifecycle.Config{
		Accounts: accounts,
		Tokens:   store,
		Vault:    creds,
		Bindings: eraseFederation{},
		OIDC:     store,
		Flows:    federation.NewMemoryBindFlowStore(),
		Audit:    logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)

	api, err := New(Config{
		Issuer:            srv.URL,
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Authorization:     opHandler,
		Sessions:          manager,
		Accounts:          accounts,
		Auth:              authHandler,
		Deleter:           deleter,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = api.Handler()

	return deleteEnv{base: srv.URL, accounts: accounts, vault: creds, bindings: bindings, logger: logger}
}

// eraseFederation is a federation service with no sources: RevokeUserBindings has
// nothing to do, which is the honest shape for a test deployment with no data
// sources.
type eraseFederation struct{}

func (eraseFederation) RevokeUserBindings(context.Context, account.UserID) (lifecycle.BindingOutcome, error) {
	return lifecycle.BindingOutcome{}, nil
}

// deleteReq sends a DELETE /v1/account with the given acknowledgement and CSRF,
// returning the response and its decoded body.
func deleteReq(t *testing.T, c *http.Client, base, csrf, ack string) (*http.Response, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"acknowledge": ack})
	req, _ := http.NewRequest(http.MethodDelete, base+"/v1/account", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp := doReq(t, c, req)
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return resp, out
}

// csrfFor signs in and returns the CSRF token from the session bootstrap.
func csrfFor(t *testing.T, browser *http.Client, base string) string {
	t.Helper()
	signIn(t, browser, base)
	view := decodeResp(t, getURL(t, browser, base+"/v1/sessions/current"))
	token, _ := view["csrf_token"].(string)
	if token == "" {
		t.Fatalf("no CSRF token in the session view: %v", view)
	}
	return token
}

// TestDeleteAccountEndToEnd erases a signed-in account and checks the account row
// and its identities are actually gone, not merely that the handler answered 200.
func TestDeleteAccountEndToEnd(t *testing.T) {
	env := newDeleteEnv(t)
	browser := newBrowser(t)
	csrf := csrfFor(t, browser, env.base)

	uid, err := env.accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}

	resp, body := deleteReq(t, browser, env.base, csrf, deleteAccountAcknowledgement)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d: %v", resp.StatusCode, body)
	}

	// The account row and its identity are gone.
	if _, err := env.accounts.GetUser(context.Background(), uid); err == nil {
		t.Error("the account still exists after erasure")
	}
	if id, err := env.accounts.FindByIdentity(context.Background(), idp.GitHub, "42"); err == nil {
		t.Errorf("the identity still resolves to %s after erasure", id)
	}

	// The erasure is audited.
	events := env.logger.Events()
	if len(events) != 1 || events[0].Action != "account.delete" || events[0].Outcome != audit.OutcomeOK {
		t.Errorf("audit trail = %+v, want one account.delete ok", events)
	}
}

// TestDeleteAccountRequiresTheAcknowledgement: deletion is irreversible, so it
// cannot happen because a client sent a bare DELETE. The exact string is required.
func TestDeleteAccountRequiresTheAcknowledgement(t *testing.T) {
	env := newDeleteEnv(t)
	browser := newBrowser(t)
	csrf := csrfFor(t, browser, env.base)

	for name, ack := range map[string]string{
		"missing": "",
		"wrong":   "yes",
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := deleteReq(t, browser, env.base, csrf, ack)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("delete = %d, want 400", resp.StatusCode)
			}
			if body["code"] != "invalid_request" {
				t.Errorf("code = %v, want invalid_request", body["code"])
			}
		})
	}

	// The account must still be there: a rejected request erases nothing.
	if _, err := env.accounts.FindByIdentity(context.Background(), idp.GitHub, "42"); err != nil {
		t.Errorf("a rejected deletion removed the account: %v", err)
	}
}

// TestDeleteAccountRequiresCSRF: it is a write on the account, so it needs the
// token like every other write.
func TestDeleteAccountRequiresCSRF(t *testing.T) {
	env := newDeleteEnv(t)
	browser := newBrowser(t)
	csrfFor(t, browser, env.base)

	resp, body := deleteReq(t, browser, env.base, "", deleteAccountAcknowledgement)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("delete = %d, want 403", resp.StatusCode)
	}
	if body["code"] != "invalid_request" {
		t.Errorf("code = %v, want invalid_request", body["code"])
	}
}

// TestDeleteAccountRequiresASession.
func TestDeleteAccountRequiresASession(t *testing.T) {
	env := newDeleteEnv(t)
	resp, body := deleteReq(t, newBrowser(t), env.base, "whatever", deleteAccountAcknowledgement)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("delete = %d, want 401", resp.StatusCode)
	}
	if body["code"] != "unauthenticated" {
		t.Errorf("code = %v, want unauthenticated", body["code"])
	}
}

// TestDeleteAccountIsAbsentWhenNotConfigured: a deployment that does not wire a
// deleter must not advertise the endpoint. It falls to the business-plane
// catch-all, which is a 404 problem+json like any other unknown resource.
func TestDeleteAccountIsAbsentWhenNotConfigured(t *testing.T) {
	env := newTestEnv(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/account", nil)
	env.srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when no deleter is configured", rec.Code)
	}
	for _, rt := range env.srv.specRoutes() {
		if rt.Pattern == "/v1/account" {
			t.Fatal("/v1/account is in specRoutes without a deleter")
		}
	}
}
