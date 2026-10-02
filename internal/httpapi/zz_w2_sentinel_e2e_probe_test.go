package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// w2Clock is a settable clock, so the probe can age a pending consent handle past
// its deadline instead of sleeping through it. It is read on every store call,
// hence the atomic.
type w2Clock struct{ now atomic.Int64 }

func newW2Clock() *w2Clock {
	c := new(w2Clock)
	c.now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *w2Clock) Now() time.Time { return time.Unix(0, c.now.Load()).UTC() }

func (c *w2Clock) Advance(d time.Duration) { c.now.Add(int64(d)) }

// w2SentinelEnv is the production shape for S04-7's end-to-end probe: the real
// memory OP store (on a clock the probe owns), the real oidchttp handler wired as
// the consent interaction, and the real httpapi server in front of it. Nothing in
// the seam is substituted, so the sentinel the browser's status code depends on
// has to travel from the store through the engine to the HTTP classification.
type w2SentinelEnv struct {
	base    string
	clock   *w2Clock
	clients *oauth.MemoryClientRegistry
	logger  *audit.MemoryLogger
}

func newW2SentinelEnv(t *testing.T) *w2SentinelEnv {
	t.Helper()

	// The fake IdP exists only so the browser can sign in; the consent path under
	// test never talks to it.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github/token":
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at:" + r.PostFormValue("code"), "token_type": "Bearer", "expires_in": 3600})
		case "/github/user":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "octocat", "name": "Octo"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "Phi CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   provider.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL: provider.URL + "/github/authorize", TokenURL: provider.URL + "/github/token",
			UserInfoURL: provider.URL + "/github/user",
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

	clock := newW2Clock()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("w2", key),
		Now:      clock.Now,
		// The same browser binding the composition root installs, so the consent
		// handlers recognise the handle they are given.
		Login: func(ctx context.Context, id string) string {
			manager.Bind(ctx, "authz", id)
			return "/app/consent?id=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	opHandler, err := oidchttp.New(oidchttp.Config{
		Issuer:        "https://re0auth.test",
		Storage:       store,
		CryptoKey:     testCryptoKey(),
		CryptoKeyID:   "test",
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}

	logger := audit.NewMemoryLogger()
	api, err := New(Config{
		Issuer:            "https://re0auth.test",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Authorization:     opHandler,
		Sessions:          manager,
		Accounts:          accounts,
		Auth:              authHandler,
		AuditLog:          logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	return &w2SentinelEnv{base: server.URL, clock: clock, clients: clients, logger: logger}
}

// TestW2SentinelEndToEnd pins S04-7 across the whole real stack, one status code
// per outcome, because that mapping is exactly what the sentinel exists for:
//
//   - a live handle is 200 (the control that keeps the probe from passing on a
//     plane that refuses everything);
//   - a handle past its deadline is 400 invalid_request — the caller's situation;
//   - a failure of the client registry the describe path consults is 500
//     internal_error, audited, and leaks no store text. In the composition root
//     that registry is store-backed (cmd/re0auth passes store.clients), so this is
//     the store outage the 400 must never be used for.
func TestW2SentinelEndToEnd(t *testing.T) {
	env := newW2SentinelEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, env.base)

	const verifier = "verifier-verifier-verifier-verifier-verifier"

	// 1. Live handle: 200.
	live := authorize(t, browser, env.base, verifier, "account.id", "st-w2-live")
	resp := getURL(t, browser, env.base+"/v1/authorization_requests/"+live)
	if resp.StatusCode != http.StatusOK {
		body := decodeResp(t, resp)
		t.Fatalf("live handle = %d (%v), want 200", resp.StatusCode, body)
	}
	resp.Body.Close()

	// 2. Expired handle: the real store adjudicates the deadline on the read, and
	// the sentinel it returns must reach the browser as 400 invalid_request.
	stale := authorize(t, browser, env.base, verifier, "account.id", "st-w2-stale")
	env.clock.Advance(31 * time.Minute) // default requestTTL is 30m
	resp = getURL(t, browser, env.base+"/v1/authorization_requests/"+stale)
	body := decodeResp(t, resp)
	if resp.StatusCode != http.StatusBadRequest || body["code"] != "invalid_request" {
		t.Fatalf("expired handle = %d (%v), want 400 invalid_request (S04-7)", resp.StatusCode, body)
	}

	// 3. Store fault: the client lookup fails for a handle the store still holds.
	// It is not the caller's situation, so it must be 500 + an audit row, and the
	// refusal must not name the client or carry the engine's error text.
	fault := authorize(t, browser, env.base, verifier, "account.id", "st-w2-fault")
	if err := env.clients.SetStatus(context.Background(), "cli", oauth.ClientSuspended); err != nil {
		t.Fatal(err)
	}
	resp = getURL(t, browser, env.base+"/v1/authorization_requests/"+fault)
	body = decodeResp(t, resp)
	if resp.StatusCode != http.StatusInternalServerError || body["code"] != "internal_error" {
		t.Fatalf("store fault = %d (%v), want 500 internal_error (S04-7)", resp.StatusCode, body)
	}
	if detail, _ := body["detail"].(string); strings.Contains(detail, "cli") || strings.Contains(detail, "not found") {
		t.Fatalf("the 500 leaked the engine's internals: %q", detail)
	}

	recorded := false
	for _, e := range env.logger.Events() {
		if e.Action == "auth.authorization.fault" && e.Outcome == audit.OutcomeError {
			recorded = true
			if e.Detail["operation"] != "describe" {
				t.Errorf("audit detail operation = %q, want describe", e.Detail["operation"])
			}
		}
	}
	if !recorded {
		t.Fatalf("the store fault was not audited: %+v", env.logger.Events())
	}
}
