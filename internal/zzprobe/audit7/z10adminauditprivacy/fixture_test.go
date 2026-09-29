//go:build audit7

// Fixtures for the round-7 zone-10 probes (operator plane / audit / privacy).
//
// Everything is assembled from exported surfaces (httpapi.New + Config and the
// packages behind it) plus internal/testoidc, so these probes observe the wiring
// the composition root builds rather than the product's own in-package test
// helpers. No tracked file is modified.
package z10adminauditprivacy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/observability"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/internal/testoidc"
	"github.com/Re0Auth/r0semi/oauth"
)

const (
	probeIssuer   = "https://re0auth.test"
	probeRedirect = "https://app.example/cb"
	probeClientID = "cli"
	// probeProvider is a custom OIDC provider name, which makes testoidc the
	// login provider (a custom provider must be OIDC; idp.Registry enforces it).
	probeProvider = idp.Provider("probeidp")
	// adminUpstream is the upstream subject the fixture makes the operator. The
	// account is created before httpapi.New so the allowlist can name a real id.
	adminUpstream = "admin-upstream-sub"
)

// ---- ports the operator plane is wired to -------------------------------------

// probeTokens is the bulk token revoker.
type probeTokens struct {
	removed int
	err     error
	calls   int
}

func (p *probeTokens) RevokeTokens(context.Context, oauth.TokenFilter) (int, error) {
	p.calls++
	return p.removed, p.err
}

type probeSessions struct {
	n     int64
	calls int
}

func (p *probeSessions) RevokeAllSessions(context.Context) (int64, error) {
	p.calls++
	return p.n, nil
}

func (p *probeSessions) RevokeSubjectSessions(context.Context, string) (int64, error) {
	p.calls++
	return p.n, nil
}

type probeBindings struct {
	outcome admin.BindingOutcome
	err     error
	calls   int
}

func (p *probeBindings) RevokeAllBindings(context.Context) (admin.BindingOutcome, error) {
	p.calls++
	return p.outcome, p.err
}

func (p *probeBindings) RevokeSubjectBindings(context.Context, string) (admin.BindingOutcome, error) {
	p.calls++
	return p.outcome, p.err
}

type probeFlows struct{ n int }

func (p *probeFlows) PurgeUserFlows(context.Context, string) (int, error) { return p.n, nil }

// probeAuditReader is the operator read API's seam over the durable sink.
type probeAuditReader struct {
	page         audit.Page
	verification audit.Verification
	head         []byte
	err          error

	queries  []audit.Query
	verified int
	headed   int
}

func (r *probeAuditReader) Query(_ context.Context, q audit.Query) (audit.Page, error) {
	r.queries = append(r.queries, q)
	return r.page, r.err
}

func (r *probeAuditReader) Verify(context.Context) (audit.Verification, error) {
	r.verified++
	return r.verification, r.err
}

func (r *probeAuditReader) Head(context.Context) ([]byte, error) {
	r.headed++
	return r.head, r.err
}

// ---- the environment ----------------------------------------------------------

type probeOptions struct {
	// Tokens, Sessions, Bindings and Flows are the operator plane's ports. A nil
	// port is what a deployment that cannot do that thing leaves out.
	Tokens   admin.Revoker
	Sessions admin.SessionRevoker
	Bindings admin.Bindings
	Flows    admin.FlowPurger
	// AdminsFunc turns the operator's real account id into the allowlist. The
	// default is exactly that one id; a probe can return a near miss instead.
	AdminsFunc func(account.UserID) []account.UserID
	// AuditReader, when set, mounts /v1/admin/audit, /verify and /head.
	AuditReader httpapi.AuditReader
	// Metrics, when set, instruments the server.
	Metrics *observability.Metrics
}

type probeEnv struct {
	t        *testing.T
	server   *httptest.Server
	manager  *auth.Manager
	accounts *account.MemoryStore
	oidc     *testoidc.Server
	auditLog *audit.MemoryLogger
	clients  *oauth.MemoryClientRegistry
	opStore  *memory.OIDCStore
	tokens   *probeTokens

	// adminUser is the account id the allowlist names when AdminsFunc is nil.
	adminUser account.UserID
	metrics   *observability.Metrics
}

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
	// The operator's account exists before the server is built, so the allowlist
	// can contain a real usr_ rather than a guess.
	adminRec, _, err := accounts.CreateWithIdentity(context.Background(), idp.Identity{
		Provider: probeProvider, Subject: adminUpstream,
		DisplayName: "Admin", Email: "admin@example.test",
	})
	if err != nil {
		t.Fatalf("create the operator account: %v", err)
	}
	adminUser := adminRec.ID

	manager := auth.NewManager(auth.Options{Secure: false, Audit: auditLog})
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

	tokens := &probeTokens{removed: 7}
	var adminTokens admin.Revoker = tokens
	if opts.Tokens != nil {
		adminTokens = opts.Tokens
		tokens = nil
	}
	adminSvc, err := admin.New(admin.Config{
		Clients:  clients,
		Tokens:   adminTokens,
		Sessions: opts.Sessions,
		Bindings: opts.Bindings,
		Flows:    opts.Flows,
		Audit:    auditLog,
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	admins := []account.UserID{adminUser}
	if opts.AdminsFunc != nil {
		admins = opts.AdminsFunc(adminUser)
	}

	cfg := httpapi.Config{
		Issuer:            probeIssuer,
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        opStore,
		DeviceStore:       opStore,
		Sessions:          manager,
		Accounts:          accounts,
		Auth:              authHandler,
		AuditLog:          auditLog,
		Metrics:           opts.Metrics,
		Admin:             adminSvc,
		Admins:            admins,
		Audit:             opts.AuditReader,
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	server := httptest.NewServer(srv.Handler())
	t.Cleanup(server.Close)

	return &probeEnv{
		t: t, server: server, manager: manager, accounts: accounts, oidc: oidc,
		auditLog: auditLog, clients: clients, opStore: opStore, tokens: tokens,
		adminUser: adminUser, metrics: opts.Metrics,
	}
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

// ---- browsers -----------------------------------------------------------------

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

func mustJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, body)
	}
	return out
}

// signIn drives the real /auth flow: start, echo the nonce, callback. It asserts
// the flow succeeded and returns the account id.
func (b *browser) signIn(upstreamSubject string) string {
	b.t.Helper()
	b.env.oidc.SetIdentity(upstreamSubject, "Probe "+upstreamSubject, upstreamSubject+"@example.test")

	resp := b.get("/auth/" + string(probeProvider) + "/start")
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

	resp = b.get("/auth/" + string(probeProvider) + "/callback?code=c&state=" + url.QueryEscape(state))
	if resp.StatusCode != http.StatusSeeOther {
		b.t.Fatalf("callback = %d (%s), want 303", resp.StatusCode, bodyOf(b.t, resp))
	}
	resp.Body.Close()
	return b.whoami()
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

// jsonHeaders is the shape every business-plane write carries.
func jsonHeaders(csrf string) map[string]string {
	return map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf}
}

// auditEvents returns a copy of the whole in-memory log, oldest first.
func (e *probeEnv) auditEvents() []audit.Event { return e.auditLog.Events() }

// actionsIn returns the events whose action is one of the named ones.
func (e *probeEnv) actionsIn(names ...string) []audit.Event {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	var out []audit.Event
	for _, ev := range e.auditEvents() {
		if want[ev.Action] {
			out = append(out, ev)
		}
	}
	return out
}
