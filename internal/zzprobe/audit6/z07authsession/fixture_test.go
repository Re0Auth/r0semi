//go:build audit6

// Fixtures for the round-6 identity / session / account-lifecycle probes.
//
// Everything is assembled from exported surfaces (httpapi.New + Config and the
// packages behind it) plus internal/testoidc, so these probes observe the same
// wiring the composition root builds rather than the product's own in-package
// test helpers. No tracked file is modified.
package z07authsession

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/internal/testoidc"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	probeIssuer   = "https://re0auth.test"
	probeRedirect = "https://app.example/cb"
	probeClientID = "cli"
	// probeProvider is a custom OIDC provider name, which makes testoidc the
	// login provider (a custom provider must be OIDC; idp.Registry enforces it).
	probeProvider = idp.Provider("probeidp")
)

// probeOptions tunes one environment. Everything is optional.
type probeOptions struct {
	// Ready, when set, is httpapi's readiness probe. A probe that blocks is how
	// these tests hold one request in flight while another runs.
	Ready httpapi.ReadinessProbe
	// Deleter overrides the account eraser.
	Deleter httpapi.AccountDeleter
	// Pseudonyms fails the erasure's last step when non-nil.
	Pseudonyms lifecycle.PseudonymDestroyer
	// Sessions overrides the session store/index/revoker wiring.
	Manager *auth.Manager
}

// probeEnv is one fully wired server plus the handles a probe needs to inspect
// it.
type probeEnv struct {
	t        *testing.T
	server   *httptest.Server
	handler  http.Handler
	manager  *auth.Manager
	accounts *account.MemoryStore
	oidc     *testoidc.Server
	opStore  *memory.OIDCStore
	audit    *audit.MemoryLogger
	clients  *oauth.MemoryClientRegistry
	fed      federation.Service
	vaultSvc vault.Service
	repo     *vault.MemoryRepo
	flows    *federation.MemoryBindFlowStore
	issuer   string
}

// probeHandler is the httpapi handler wrapped in a real server, with a cookie
// jar, so a probe drives the product over HTTP exactly as a browser would.
func newProbeEnv(t *testing.T, opts probeOptions) *probeEnv {
	t.Helper()

	oidc := testoidc.New()
	t.Cleanup(oidc.Close)

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: probeIssuer,
		HTTPClient:   oidc.Client(),
		Credentials: []idp.Credentials{{
			Provider:     probeProvider,
			ClientID:     "cid",
			ClientSecret: "sec",
			Issuer:       oidc.URL,
		}},
	})
	if err != nil {
		t.Fatalf("idp.NewRegistry: %v", err)
	}

	auditLog := audit.NewMemoryLogger()
	accounts := account.NewMemoryStore()
	manager := opts.Manager
	if manager == nil {
		manager = auth.NewManager(auth.Options{Secure: false, Audit: auditLog})
	}
	authHandler, err := auth.NewHandler(manager, registry, accounts, auth.WithAudit(auditLog))
	if err != nil {
		t.Fatalf("auth.NewHandler: %v", err)
	}

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient(probeClientID, "CLI", oauth.ClientPublic, "",
		[]string{probeRedirect},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosProfile})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}

	opHandler, opStore := newProbeOP(t, clients, manager)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	t.Cleanup(upstream.Close)
	sources, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", DisplayName: "Fake", Issuer: upstream.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []federation.Resource{{
			Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read",
		}},
	})
	if err != nil {
		t.Fatalf("federation.NewRegistry: %v", err)
	}

	repo := vault.NewMemoryRepo()
	wrapper, err := vault.NewLocalKeyWrapper("probe", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	vaultSvc, err := vault.NewService(repo, wrapper, auditLog)
	if err != nil {
		t.Fatal(err)
	}
	flows := federation.NewMemoryBindFlowStore()
	fed, err := federation.NewService(federation.Config{
		Registry: sources,
		Bindings: federation.NewMemoryBindingStore(),
		Vault:    vaultSvc,
		Flows:    flows,
		Doer:     upstream.Client(),
		BaseURL:  probeIssuer,
	})
	if err != nil {
		t.Fatalf("federation.NewService: %v", err)
	}

	cfg := httpapi.Config{
		Issuer:            probeIssuer,
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        opStore,
		DeviceStore:       opStore,
		Authorization:     opHandler,
		Sessions:          manager,
		Accounts:          accounts,
		Auth:              authHandler,
		Federation:        fed,
		AuditLog:          auditLog,
		Ready:             opts.Ready,
	}
	if opts.Deleter != nil {
		cfg.Deleter = opts.Deleter
	} else {
		cfg.Deleter = newProbeDeleter(t, accounts, opStore, repo, flows, opts.Pseudonyms, auditLog)
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	server := httptest.NewServer(srv.Handler())
	t.Cleanup(server.Close)

	return &probeEnv{
		t: t, server: server, handler: srv.Handler(), manager: manager,
		accounts: accounts, oidc: oidc, opStore: opStore, audit: auditLog,
		clients: clients, fed: fed, vaultSvc: vaultSvc, repo: repo, flows: flows,
		issuer: probeIssuer,
	}
}

// newProbeDeleter builds the erasure orchestrator the way cmd/re0auth does: the
// storage ports directly, the OP store for non-token state, and the bind-flow
// store. Pseudonyms is whatever the probe injected.
func newProbeDeleter(
	t *testing.T,
	accounts *account.MemoryStore,
	opStore *memory.OIDCStore,
	repo *vault.MemoryRepo,
	flows *federation.MemoryBindFlowStore,
	pseudonyms lifecycle.PseudonymDestroyer,
	auditLog audit.Logger,
) *lifecycle.Deleter {
	t.Helper()
	d, err := lifecycle.New(lifecycle.Config{
		Accounts:   accounts,
		Tokens:     oauth.TokenAdmins{opStore},
		Vault:      repo,
		OIDC:       opStore,
		Flows:      flows,
		Pseudonyms: pseudonyms,
		Audit:      auditLog,
	})
	if err != nil {
		t.Fatalf("lifecycle.New: %v", err)
	}
	return d
}

// newProbeOP builds the OpenID Provider the way openOIDC does.
func newProbeOP(t *testing.T, clients oauth.ClientRegistry, manager *auth.Manager) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("probe", key),
		Login: func(_ context.Context, id string) string {
			return "/app/consent?id=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("0123456789abcdef0123456789abcdef"))
	h, err := oidchttp.New(oidchttp.Config{
		Issuer:        probeIssuer,
		Storage:       store,
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "probe",
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
		Sessions:      sessionLookup{manager},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, store
}

// sessionLookup is cmd/re0auth's adapter, reproduced here because the probe must
// not depend on package-internal test helpers.
type sessionLookup struct{ m *auth.Manager }

func (s sessionLookup) User(ctx context.Context) (string, bool) {
	u, ok := s.m.User(ctx)
	return string(u), ok
}

// browser is one cookie jar over the server: a distinct browser, so two of them
// can hold two sessions of the same account.
type browser struct {
	t      *testing.T
	env    *probeEnv
	client *http.Client
}

func (e *probeEnv) newBrowser() *browser {
	e.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return &browser{
		t: e.t, env: e,
		client: &http.Client{
			Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// do performs one request. body may be empty.
func (b *browser) do(method, target string, body string, hdr map[string]string) *http.Response {
	b.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, b.env.server.URL+target, rdr)
	if err != nil {
		b.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, target, err)
	}
	return resp
}

// get follows nothing; the caller reads the status and Location.
func (b *browser) get(target string) *http.Response { return b.do(http.MethodGet, target, "", nil) }

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sessionCookie returns the live session cookie the jar currently holds, or "".
func (b *browser) sessionCookie() string {
	b.t.Helper()
	for _, c := range b.client.Jar.Cookies(mustURL(b.t, b.env.server.URL)) {
		if strings.Contains(c.Name, "session") && c.Value != "" {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// signIn drives the real /auth flow: start, echo the nonce, callback. It asserts
// the flow succeeded and returns the account id.
func (b *browser) signIn(provider idp.Provider) string {
	b.t.Helper()
	b.signInOrFail(provider, "")
	return b.whoami()
}

// signInOrFail returns the callback's Location on success.
func (b *browser) signInOrFail(provider idp.Provider, mode string) string {
	b.t.Helper()
	target := "/auth/" + string(provider) + "/start"
	if mode != "" {
		target += "?mode=" + mode
	}
	resp := b.get(target)
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("start = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	b.env.oidc.SetNonce(loc.Query().Get("nonce"))
	state := loc.Query().Get("state")
	resp.Body.Close()
	if state == "" {
		b.t.Fatal("the authorize URL carried no state")
	}

	resp = b.get("/auth/" + string(provider) + "/callback?code=c&state=" + url.QueryEscape(state))
	if resp.StatusCode != http.StatusSeeOther {
		b.t.Fatalf("callback = %d (%s), want 303", resp.StatusCode, bodyOf(b.t, resp))
	}
	out := resp.Header.Get("Location")
	resp.Body.Close()
	return out
}

// whoami reads the signed-in account id from the business plane's session
// bootstrap endpoint, which is the product's own answer to "who is this".
func (b *browser) whoami() string {
	b.t.Helper()
	resp := b.get("/v1/sessions/current")
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("/v1/sessions/current = %d (%s)", resp.StatusCode, bodyOf(b.t, resp))
	}
	var out struct {
		UserID    string `json:"user_id"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal([]byte(bodyOf(b.t, resp)), &out); err != nil {
		b.t.Fatal(err)
	}
	if out.UserID == "" {
		b.t.Fatal("/v1/sessions/current carried no user_id")
	}
	return out.UserID
}

// csrf returns the session's CSRF token by asking the product for it.
func (b *browser) csrf() string {
	b.t.Helper()
	resp := b.get("/v1/sessions/current")
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("/v1/sessions/current = %d (%s)", resp.StatusCode, bodyOf(b.t, resp))
	}
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal([]byte(bodyOf(b.t, resp)), &out); err != nil {
		b.t.Fatal(err)
	}
	if out.CSRFToken == "" {
		b.t.Fatal("no CSRF token was issued")
	}
	return out.CSRFToken
}

// status is one request's status code with the body discarded.
func (b *browser) status(method, target, body string, hdr map[string]string) int {
	b.t.Helper()
	resp := b.do(method, target, body, hdr)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// setIdentity changes the subject the fake provider asserts, so one provider can
// stand for several different people.
func (e *probeEnv) setIdentity(subject string) {
	e.oidc.SetIdentity(subject, "Probe "+subject, subject+"@example.test")
}

// pkceSum is the S256 challenge for a verifier, as the client would compute it.
func pkceSum(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// fixedClock is a settable clock for probes that need a session's recorded
// authentication time to be old.
type fixedClock struct {
	mu  chan struct{}
	now time.Time
}

func newFixedClock(at time.Time) *fixedClock {
	c := &fixedClock{mu: make(chan struct{}, 1), now: at}
	c.mu <- struct{}{}
	return c
}

func (c *fixedClock) Now() time.Time {
	<-c.mu
	v := c.now
	c.mu <- struct{}{}
	return v
}
