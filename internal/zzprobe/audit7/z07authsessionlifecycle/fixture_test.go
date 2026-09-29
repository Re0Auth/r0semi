//go:build audit7

// Fixture for the round-7 zone-07 (session / account / identity / erasure)
// probes.
//
// Everything is assembled from exported surfaces only — httpapi.New + Config,
// internal/auth, internal/account, internal/lifecycle, internal/federation,
// vault, and internal/testoidc — so a probe observes the same wiring the
// composition root (cmd/re0auth) builds. The login hook binds the consent handle
// to the browser and stamps auth_time, exactly as openOIDC does. No tracked file
// is modified.
package z07authsessionlifecycle

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
	"sync"
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
	// login provider (a custom provider must be OIDC).
	probeProvider = idp.Provider("probeidp")
	// probeTTL is the pending-consent handle lifetime the composition root
	// configures (cmd/re0auth/config.go: authorizationRequestTTL).
	probeTTL = 30 * time.Minute
)

// probeClock is a settable clock handed to the OP store, so a probe can decide
// when a record's deadline has passed instead of sleeping on it. The HTTP plane
// and the session store keep real time; only the OP store's own judgment moves.
type probeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newProbeClock() *probeClock { return &probeClock{now: time.Now()} }

func (c *probeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the OP store's clock forward.
func (c *probeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// probeOptions tunes one environment. Everything is optional.
type probeOptions struct {
	// RequestTTL overrides the pending-consent handle lifetime.
	RequestTTL time.Duration
	// Clock overrides the OP store's clock.
	Clock *probeClock
	// Secure turns on the Secure cookie attribute (and the __Host- prefix).
	Secure bool
	// CookieName overrides the session cookie name, as `server.cookie_name`
	// would.
	CookieName string
	// Manager overrides the session manager.
	Manager *auth.Manager
	// Deleter overrides the account eraser.
	Deleter httpapi.AccountDeleter
	// Pseudonyms, when non-nil, is the erasure's last step.
	Pseudonyms lifecycle.PseudonymDestroyer
	// SessionRevoker, when non-nil, is wired into the erasure so it can drop the
	// account's browser sessions (the production shape; the memory development
	// store has none).
	SessionRevoker lifecycle.SessionRevoker
	// BindFederation omits the federation service when false, so the erasure has
	// no binding step.
	NoFederation bool
}

// probeEnv is one fully wired server plus the handles a probe needs.
type probeEnv struct {
	t        *testing.T
	server   *httptest.Server
	handler  http.Handler
	manager  *auth.Manager
	accounts *account.MemoryStore
	oidc     *testoidc.Server
	opStore  *memory.OIDCStore
	clock    *probeClock
	audit    *audit.MemoryLogger
	clients  *oauth.MemoryClientRegistry
	fed      federation.Service
	repo     *vault.MemoryRepo
	flows    *federation.MemoryBindFlowStore
	issuer   string
	deleter  lifecycle.Deleter
}

// newProbeEnv builds the whole stack.
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
		manager = auth.NewManager(auth.Options{
			Secure: opts.Secure, CookieName: opts.CookieName, Audit: auditLog,
		})
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

	clock := opts.Clock
	if clock == nil {
		clock = newProbeClock()
	}
	ttl := opts.RequestTTL
	if ttl <= 0 {
		ttl = probeTTL
	}
	opHandler, opStore := newProbeOP(t, clients, manager, ttl, clock)

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

	var fed federation.Service
	if !opts.NoFederation {
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
		fed, err = federation.NewService(federation.Config{
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
	}
	if opts.Deleter != nil {
		cfg.Deleter = opts.Deleter
	} else {
		cfg.Deleter = newProbeDeleter(t, accounts, opStore, repo, flows, opts, auditLog)
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	server := httptest.NewServer(srv.Handler())
	t.Cleanup(server.Close)

	return &probeEnv{
		t: t, server: server, handler: srv.Handler(), manager: manager,
		accounts: accounts, oidc: oidc, opStore: opStore, clock: clock,
		audit: auditLog, clients: clients, fed: fed, repo: repo, flows: flows,
		issuer: probeIssuer,
	}
}

// newProbeDeleter builds the erasure orchestrator the way cmd/re0auth does:
// storage ports directly, the OP store for non-token state, the bind-flow store,
// and (only when asked) a session revoker.
func newProbeDeleter(
	t *testing.T,
	accounts *account.MemoryStore,
	opStore *memory.OIDCStore,
	repo *vault.MemoryRepo,
	flows *federation.MemoryBindFlowStore,
	opts probeOptions,
	auditLog audit.Logger,
) *lifecycle.Deleter {
	t.Helper()
	d, err := lifecycle.New(lifecycle.Config{
		Accounts:   accounts,
		Tokens:     oauth.TokenAdmins{opStore},
		Vault:      repo,
		OIDC:       opStore,
		Flows:      flows,
		Sessions:   opts.SessionRevoker,
		Pseudonyms: opts.Pseudonyms,
		Audit:      auditLog,
	})
	if err != nil {
		t.Fatalf("lifecycle.New: %v", err)
	}
	return d
}

// newProbeOP builds the OpenID Provider the way openOIDC does: the login hook
// binds the consent handle to the browser session and stamps auth_time.
func newProbeOP(t *testing.T, clients oauth.ClientRegistry, manager *auth.Manager, ttl time.Duration, clock *probeClock) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Declared first because the login hook closes over it and is itself handed
	// to the constructor.
	var store *memory.OIDCStore
	store, err = memory.NewOIDCStore(memory.OIDCOptions{
		Clients:    clients,
		Registry:   oauth.DefaultRegistry(),
		Signer:     oidcstore.NewSigner("probe", key),
		RequestTTL: ttl,
		Now:        clock.Now,
		Login: func(ctx context.Context, id string) string {
			manager.Bind(ctx, "authz", id)
			if at, ok := manager.AuthenticatedAt(ctx); ok {
				_ = store.SetAuthTime(ctx, id, at)
			}
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

// sessionLookup is cmd/re0auth's adapter, reproduced here so the probe does not
// depend on package-internal helpers.
type sessionLookup struct{ m *auth.Manager }

func (s sessionLookup) User(ctx context.Context) (string, bool) {
	u, ok := s.m.User(ctx)
	return string(u), ok
}

// browser is one cookie jar over the server: a distinct browser, so two of them
// hold two sessions.
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

func (b *browser) do(method, target, body string, hdr map[string]string) *http.Response {
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

func (b *browser) get(target string) *http.Response { return b.do(http.MethodGet, target, "", nil) }

// status is one request's status code with the body discarded.
func (b *browser) status(method, target, body string, hdr map[string]string) int {
	b.t.Helper()
	resp := b.do(method, target, body, hdr)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// cookies returns the live cookies the jar holds for the probe server.
func (b *browser) cookies() []*http.Cookie {
	b.t.Helper()
	return b.client.Jar.Cookies(mustURL(b.t, b.env.server.URL))
}

// sessionCookie returns the live session cookie as a "name=value" pair, or "".
func (b *browser) sessionCookie() string {
	b.t.Helper()
	for _, c := range b.cookies() {
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
// the flow succeeded and returns the callback's Location.
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

// signIn signs in and returns the account id.
func (b *browser) signIn(provider idp.Provider) string {
	b.t.Helper()
	b.signInOrFail(provider, "")
	return b.whoami()
}

// whoami reads the signed-in account id from the session bootstrap endpoint.
func (b *browser) whoami() string {
	b.t.Helper()
	return b.currentSession().UserID
}

type sessionView struct {
	UserID    string `json:"user_id"`
	CSRFToken string `json:"csrf_token"`
}

// currentSession reads /v1/sessions/current, failing if it is not 200.
func (b *browser) currentSession() sessionView {
	b.t.Helper()
	resp := b.get("/v1/sessions/current")
	body := bodyOf(b.t, resp)
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("/v1/sessions/current = %d (%s)", resp.StatusCode, body)
	}
	var out sessionView
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		b.t.Fatal(err)
	}
	if out.UserID == "" {
		b.t.Fatal("/v1/sessions/current carried no user_id")
	}
	return out
}

// csrf returns the session's CSRF token by asking the product for it.
func (b *browser) csrf() string {
	b.t.Helper()
	tok := b.currentSession().CSRFToken
	if tok == "" {
		b.t.Fatal("no CSRF token was issued")
	}
	return tok
}

// setIdentity changes the subject the fake provider asserts, so one provider can
// stand for several different people.
func (e *probeEnv) setIdentity(subject string) {
	e.oidc.SetIdentity(subject, "Probe "+subject, subject+"@example.test")
}

// authorize starts a real /oauth/authorize request with PKCE and returns the
// pending consent handle (the op auth request id) and the authorize response.
func (b *browser) authorize(verifier, state string) (string, *http.Response) {
	b.t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {probeClientID},
		"redirect_uri":          {probeRedirect},
		"scope":                 {oauth.ScopeAccountID.String()},
		"state":                 {state},
		"code_challenge":        {pkceSum(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp := b.get("/oauth/authorize?" + q.Encode())
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("authorize = %d (%s), want 302", resp.StatusCode, bodyOf(b.t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	resp.Body.Close()
	id := loc.Query().Get("id")
	if id == "" {
		b.t.Fatalf("the authorize redirect carried no consent handle: %q", loc.String())
	}
	return id, resp
}

// completeAuthorize approves a consent handle and follows the OP callback,
// returning the authorization code the client would exchange.
func (b *browser) completeAuthorize(id, csrf, verifier, state string) string {
	b.t.Helper()
	resp := b.get("/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {probeClientID},
		"redirect_uri":          {probeRedirect},
		"scope":                 {oauth.ScopeAccountID.String()},
		"state":                 {state},
		"code_challenge":        {pkceSum(verifier)},
		"code_challenge_method": {"S256"},
	}.Encode())
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("authorize = %d (%s)", resp.StatusCode, bodyOf(b.t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	resp.Body.Close()
	handle := loc.Query().Get("id")
	if id != "" && handle != id {
		b.t.Fatalf("consent handle = %q, want %q", handle, id)
	}

	code, redirect := b.approveConsent(handle, csrf)
	if code != http.StatusOK || redirect == "" {
		b.t.Fatalf("approve = %d (%s)", code, redirect)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		b.t.Fatal(err)
	}
	cb := b.get(u.RequestURI())
	if cb.StatusCode != http.StatusFound {
		b.t.Fatalf("authorize callback = %d (%s)", cb.StatusCode, bodyOf(b.t, cb))
	}
	back, err := url.Parse(cb.Header.Get("Location"))
	cb.Body.Close()
	if err != nil {
		b.t.Fatal(err)
	}
	got := back.Query().Get("code")
	if got == "" {
		b.t.Fatalf("no code in %q", back.String())
	}
	return got
}

// exchangeCode redeems an authorization code for a token response.
func (b *browser) exchangeCode(code, verifier string) map[string]any {
	b.t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {probeClientID},
		"code":          {code},
		"redirect_uri":  {probeRedirect},
		"code_verifier": {verifier},
	}
	resp := b.do(http.MethodPost, "/oauth/token", form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	body := bodyOf(b.t, resp)
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("token = %d (%s)", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		b.t.Fatal(err)
	}
	return out
}

// accountUserID narrows a string back to the account id type, so a probe can ask
// the store directly about a subject it saw on the wire.
func accountUserID(s string) account.UserID { return account.UserID(s) }

// identityIDs returns the identity ids the store holds for an account, so a probe
// can try to act on somebody else's.
func (e *probeEnv) identityIDs(user string) []string {
	e.t.Helper()
	idents, err := e.accounts.Identities(context.Background(), accountUserID(user))
	if err != nil {
		e.t.Fatalf("Identities(%s): %v", user, err)
	}
	out := make([]string, 0, len(idents))
	for _, id := range idents {
		out = append(out, string(id.ID))
	}
	return out
}

// pkceSum is the S256 challenge for a verifier, as the client would compute it.
func pkceSum(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
