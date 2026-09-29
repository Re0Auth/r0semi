//go:build audit7

// Fixtures for the round-7 frontend / browser-plane probes.
//
// Everything is assembled from exported surfaces (httpapi.New + Config and the
// packages behind it) plus internal/testoidc, so these probes observe the same
// wiring the composition root builds rather than the product's own in-package
// test helpers. No tracked file is modified.
//
// The frontend is the real embedded build (webui.FS) when one is present;
// probes that need the real shell assert that rather than silently testing a
// placeholder. Handler-level routing probes use their own synthetic fs.FS so
// they are deterministic on a machine that never ran `pnpm run build`.
package z08frontendbrowser

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
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
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/internal/testoidc"
	"github.com/Re0Auth/r0semi/internal/webui"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	z08Issuer   = "https://re0auth.test"
	z08Redirect = "https://app.example/cb"
	z08ClientID = "cli"
	// z08Provider is a custom OIDC provider name, which makes testoidc the
	// login provider (a custom provider must be OIDC; idp.Registry enforces it).
	z08Provider = idp.Provider("z08idp")
)

// z08Options tunes one environment. Everything is optional.
type z08Options struct {
	// Scopes overrides httpapi.Config.Scopes, which is the registry the consent
	// screen renders through. Nil means the package default. It is separate from
	// the OP's own registry on purpose: one probe is about the two disagreeing.
	Scopes *oauth.Registry
	// OPRegistry overrides the registry the authorization engine resolves
	// scopes through. Nil means oauth.DefaultRegistry().
	OPRegistry *oauth.Registry
	// ClientScopes overrides the scopes the registered client is allowed.
	ClientScopes []oauth.Scope
	// Admins, when non-empty, mounts the operator plane for that account id.
	Admins []account.UserID
	// AdminWindow is Config.AdminReauthWindow; zero disables the re-auth check.
	AdminWindow time.Duration
	// Frontend overrides the embedded build; nil means webui.FS().
	Frontend fs.FS
	// NoFrontend leaves Config.Frontend nil, so /app is not mounted at all.
	NoFrontend bool
	// Manager reuses a session manager, so a second environment can see the
	// first environment's signed-in session.
	Manager *auth.Manager
	// Accounts reuses the account store the reused Manager's sessions point at.
	Accounts *account.MemoryStore
}

// z08Env is one fully wired server plus the handles a probe needs.
type z08Env struct {
	t        *testing.T
	server   *httptest.Server
	handler  http.Handler
	manager  *auth.Manager
	accounts *account.MemoryStore
	oidc     *testoidc.Server
	opStore  *memory.OIDCStore
	op       *oidchttp.Handler
	audit    *audit.MemoryLogger
	clients  *oauth.MemoryClientRegistry
	fed      federation.Service
	issuer   string
}

// newZ08Env builds the environment.
func newZ08Env(t *testing.T, opts z08Options) *z08Env {
	t.Helper()

	oidc := testoidc.New()
	t.Cleanup(oidc.Close)

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: z08Issuer,
		HTTPClient:   oidc.Client(),
		Credentials: []idp.Credentials{{
			Provider:     z08Provider,
			ClientID:     "cid",
			ClientSecret: "sec",
			Issuer:       oidc.URL,
		}},
	})
	if err != nil {
		t.Fatalf("idp.NewRegistry: %v", err)
	}

	auditLog := audit.NewMemoryLogger()
	accounts := opts.Accounts
	if accounts == nil {
		accounts = account.NewMemoryStore()
	}
	manager := opts.Manager
	if manager == nil {
		manager = auth.NewManager(auth.Options{Secure: false, Audit: auditLog})
	}
	authHandler, err := auth.NewHandler(manager, registry, accounts, auth.WithAudit(auditLog))
	if err != nil {
		t.Fatalf("auth.NewHandler: %v", err)
	}

	clientScopes := opts.ClientScopes
	if clientScopes == nil {
		clientScopes = []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosProfile, oauth.ScopePhigrosScore}
	}
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient(z08ClientID, "Phi CLI", oauth.ClientPublic, "",
		[]string{z08Redirect}, clientScopes)
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}

	opRegistry := opts.OPRegistry
	if opRegistry == nil {
		opRegistry = oauth.DefaultRegistry()
	}
	opHandler, opStore := newZ08OP(t, clients, manager, opRegistry)

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
		BaseURL:  z08Issuer,
	})
	if err != nil {
		t.Fatalf("federation.NewService: %v", err)
	}

	cfg := httpapi.Config{
		Issuer:            z08Issuer,
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
		Scopes:            opts.Scopes,
		AdminReauthWindow: opts.AdminWindow,
	}
	if len(opts.Admins) > 0 {
		svc, err := admin.New(admin.Config{
			Clients: clients,
			Tokens:  oauth.TokenAdmins{opStore},
			Audit:   auditLog,
		})
		if err != nil {
			t.Fatalf("admin.New: %v", err)
		}
		cfg.Admin = svc
		cfg.Admins = opts.Admins
	}
	deleter, err := lifecycle.New(lifecycle.Config{
		Accounts: accounts,
		Tokens:   oauth.TokenAdmins{opStore},
		Vault:    repo,
		OIDC:     opStore,
		Flows:    flows,
		Audit:    auditLog,
	})
	if err != nil {
		t.Fatalf("lifecycle.New: %v", err)
	}
	cfg.Deleter = deleter
	if !opts.NoFrontend {
		cfg.Frontend = opts.Frontend
		if cfg.Frontend == nil {
			cfg.Frontend = webui.FS()
		}
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	server := httptest.NewServer(srv.Handler())
	t.Cleanup(server.Close)

	return &z08Env{
		t: t, server: server, handler: srv.Handler(), manager: manager,
		accounts: accounts, oidc: oidc, opStore: opStore, op: opHandler, audit: auditLog,
		clients: clients, fed: fed, issuer: z08Issuer,
	}
}

// newZ08OP builds the OpenID Provider the way openOIDC does.
func newZ08OP(t *testing.T, clients oauth.ClientRegistry, manager *auth.Manager, registry *oauth.Registry) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	scopes := make([]string, 0, len(registry.Descriptors()))
	for _, d := range registry.Descriptors() {
		scopes = append(scopes, d.Scope.String())
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: registry,
		Signer:   oidcstore.NewSigner("probe", key),
		Login: func(ctx context.Context, id string) string {
			// cmd/re0auth's login closure binds the pending request to the
			// browser that started it ("authz" is httpapi's authzBindKind, which
			// is unexported there and shared with the consent screen).
			manager.Bind(ctx, "authz", id)
			return "/app/consent?id=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("0123456789abcdef0123456789abcdef"))
	h, err := oidchttp.New(oidchttp.Config{
		Issuer:        z08Issuer,
		Storage:       store,
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "probe",
		AllowInsecure: true,
		Scopes:        scopes,
		Clients:       clients,
		Registry:      registry,
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

// browser is one cookie jar over the server: a distinct browser.
type browser struct {
	t      *testing.T
	env    *z08Env
	client *http.Client
}

func (e *z08Env) newBrowser() *browser {
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

// signIn drives the real /auth flow: start, echo the nonce, callback.
func (b *browser) signIn() string {
	b.t.Helper()
	b.signInOrFail("")
	return b.whoami()
}

func (b *browser) signInOrFail(mode string) string {
	b.t.Helper()
	target := "/auth/" + string(z08Provider) + "/start"
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
	resp = b.get("/auth/" + string(z08Provider) + "/callback?code=c&state=" + url.QueryEscape(state))
	if resp.StatusCode != http.StatusSeeOther {
		b.t.Fatalf("callback = %d (%s), want 303", resp.StatusCode, bodyOf(b.t, resp))
	}
	out := resp.Header.Get("Location")
	resp.Body.Close()
	return out
}

// whoami reads the signed-in account id from the session bootstrap endpoint.
func (b *browser) whoami() string {
	b.t.Helper()
	resp := b.get("/v1/sessions/current")
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("/v1/sessions/current = %d (%s)", resp.StatusCode, bodyOf(b.t, resp))
	}
	var out struct {
		UserID string `json:"user_id"`
	}
	raw := bodyOf(b.t, resp)
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		b.t.Fatal(err)
	}
	if out.UserID == "" {
		b.t.Fatalf("/v1/sessions/current carried no user_id: %s", raw)
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
	raw := bodyOf(b.t, resp)
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		b.t.Fatal(err)
	}
	if out.CSRFToken == "" {
		b.t.Fatal("no CSRF token was issued")
	}
	return out.CSRFToken
}

// status performs one request and returns only the status code.
func (b *browser) status(method, target, body string, hdr map[string]string) int {
	b.t.Helper()
	resp := b.do(method, target, body, hdr)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// pkceSum is the S256 challenge for a verifier, as a client would compute it.
func pkceSum(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// z08CodeFlow drives the real OP from /oauth/authorize to a token response and
// returns the decoded token response body. login narrows the scopes the consent
// decision grants; nil means "grant everything the request asked for", which is
// what a caller that omits the `scopes` field gets.
func (b *browser) z08CodeFlow(t *testing.T, requested []string, grant []string) map[string]any {
	t.Helper()
	const verifier = "verifier-verifier-verifier-verifier-verifier"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {z08ClientID},
		"redirect_uri":          {z08Redirect},
		"scope":                 {strings.Join(requested, " ")},
		"state":                 {"st"},
		"code_challenge":        {pkceSum(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp := b.get("/oauth/authorize?" + q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		id = loc.Query().Get("id")
	}
	if id == "" {
		t.Fatalf("no auth request id in %q", loc)
	}
	// The consent screen's own decision endpoint, with the session's CSRF token.
	body, _ := json.Marshal(map[string]any{"decision": "approve", "scopes": grant})
	dec := b.do(http.MethodPost, "/v1/authorization_requests/"+url.PathEscape(id)+"/decision",
		string(body), map[string]string{"Content-Type": "application/json", "X-CSRF-Token": b.csrf()})
	if dec.StatusCode != http.StatusOK {
		t.Fatalf("decision = %d: %s", dec.StatusCode, bodyOf(t, dec))
	}
	var redirect struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal([]byte(bodyOf(t, dec)), &redirect); err != nil {
		t.Fatal(err)
	}
	// The decision hands back the OP's own callback, which is what mints the code.
	cbResp := b.get(redirect.RedirectTo)
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize callback %s = %d: %s", redirect.RedirectTo, cbResp.StatusCode, bodyOf(t, cbResp))
	}
	final := cbResp.Header.Get("Location")
	cbResp.Body.Close()
	cb, err := url.Parse(final)
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", final)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {z08ClientID},
		"code":          {code},
		"redirect_uri":  {z08Redirect},
		"code_verifier": {verifier},
	}
	tokReq, _ := http.NewRequest(http.MethodPost, b.env.server.URL+"/oauth/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tr, err := b.client.Do(tokReq)
	if err != nil {
		t.Fatal(err)
	}
	raw := bodyOf(t, tr)
	if tr.StatusCode != http.StatusOK {
		t.Fatalf("token = %d: %s", tr.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
