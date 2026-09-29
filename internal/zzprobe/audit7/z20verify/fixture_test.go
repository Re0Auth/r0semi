//go:build audit7

// Independent fixture for the zone-20 verification probes. It is deliberately a
// separate assembly from the reviewed package: same exported constructors
// (httpapi.New + oidchttp.New + memory store + federation service + vault), but
// the upstream records the FULL request URL, which is what lets a verification
// probe prove that two entrances address the same upstream endpoint.
package zzprobe_z20verify

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
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	vIssuer   = "https://verify.test"
	vRedirect = "https://app.example/cb"
	vClientID = "cli"
	vSubject  = "usr_v"
	vGame     = "phigros"
	vMarker   = `{"marker":"Z20V"}`
)

type vUpstream struct {
	mu   sync.Mutex
	urls []string
}

func (u *vUpstream) record(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.urls = append(u.urls, r.URL.String())
}

func (u *vUpstream) snapshot() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.urls...)
}

func (u *vUpstream) count(suffix string) int {
	n := 0
	for _, s := range u.snapshot() {
		if strings.HasSuffix(s, suffix) {
			n++
		}
	}
	return n
}

type vOptions struct {
	// Sources builds the registry once the upstream URL is known. Default is a
	// single source whose raw_base is its issuer (the same URL for both planes).
	Sources func(upstream string) []federation.Source
	// Registry replaces the scope catalogue.
	Registry *oauth.Registry
	// ClientScopes overrides the probe client's registered scopes.
	ClientScopes []oauth.Scope
	// IntrospectionClients is the resource-server allowlist.
	IntrospectionClients []string
	// ExtraPublicIDs registers extra public clients.
	ExtraPublicIDs []string
	// ConfidentialID, when set, registers a confidential client with that id.
	ConfidentialID     string
	ConfidentialSecret string
}

type vEnv struct {
	t        *testing.T
	server   *httptest.Server
	handler  http.Handler
	store    *memory.OIDCStore
	audit    *audit.MemoryLogger
	upstream *vUpstream
	clients  *oauth.MemoryClientRegistry
}

func vDefaultSources(upstream string) []federation.Source {
	return []federation.Source{{
		Game: vGame, Name: "fake", DisplayName: "Fake",
		Issuer: upstream, RawBase: upstream,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
			{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"},
		},
	}}
}

func newVEnv(t *testing.T, opts vOptions) *vEnv {
	t.Helper()
	ctx := context.Background()

	auditLog := audit.NewMemoryLogger()
	up := &vUpstream{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, vMarker)
	}))
	t.Cleanup(upstream.Close)

	buildSources := opts.Sources
	if buildSources == nil {
		buildSources = vDefaultSources
	}
	sources := buildSources(upstream.URL)
	reg, err := federation.NewRegistry(sources...)
	if err != nil {
		t.Fatalf("federation.NewRegistry: %v", err)
	}

	binds := federation.NewMemoryBindingStore()
	wrapper, err := vault.NewLocalKeyWrapper("verify", bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	vaultSvc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, auditLog)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := json.Marshal(map[string]string{"access_token": "up-token", "refresh_token": ""})
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range sources {
		b := federation.Binding{
			User: account.UserID(vSubject), Game: src.Game, Source: src.Name,
			TokenType: "Bearer", Version: 1, Expiry: time.Now().Add(time.Hour),
		}
		if err := binds.Put(ctx, b); err != nil {
			t.Fatal(err)
		}
		if err := vaultSvc.Enroll(ctx, federation.BindingIdentity(b), pair, nil); err != nil {
			t.Fatal(err)
		}
	}

	fed, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: binds, Vault: vaultSvc,
		Doer: upstream.Client(), HTTPClient: upstream.Client(),
		BaseURL: vIssuer,
	})
	if err != nil {
		t.Fatalf("federation.NewService: %v", err)
	}

	scopeRegistry := opts.Registry
	if scopeRegistry == nil {
		scopeRegistry = oauth.DefaultRegistry()
	}
	clientScopes := opts.ClientScopes
	if clientScopes == nil {
		clientScopes = []oauth.Scope{
			oauth.ScopeAccountID, oauth.ScopePhigrosProfile, oauth.ScopePhigrosScore,
		}
	}
	clients := oauth.NewMemoryClientRegistry()
	cli, err := oauth.NewClient(vClientID, "CLI", oauth.ClientPublic, "", []string{vRedirect}, clientScopes)
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, cli); err != nil {
		t.Fatal(err)
	}
	for _, id := range opts.ExtraPublicIDs {
		extra, err := oauth.NewClient(id, "Extra", oauth.ClientPublic, "", []string{vRedirect}, clientScopes)
		if err != nil {
			t.Fatal(err)
		}
		if err := clients.Create(ctx, extra); err != nil {
			t.Fatal(err)
		}
	}
	if opts.ConfidentialID != "" {
		secret := opts.ConfidentialSecret
		if secret == "" {
			secret = "conf-secret"
		}
		conf, err := oauth.NewClient(opts.ConfidentialID, "Conf", oauth.ClientConfidential, secret,
			[]string{vRedirect}, clientScopes)
		if err != nil {
			t.Fatal(err)
		}
		if err := clients.Create(ctx, conf); err != nil {
			t.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients: clients, Registry: scopeRegistry, Signer: oidcstore.NewSigner("v", key),
		Audit: auditLog,
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatalf("memory.NewOIDCStore: %v", err)
	}
	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("verify0123456789abcdef01234567"))
	opHandler, err := oidchttp.New(oidchttp.Config{
		Issuer: vIssuer, Storage: store, CryptoKey: cryptoKey, CryptoKeyID: "v",
		AllowInsecure: true, Clients: clients, Registry: scopeRegistry, Consent: store,
		IntrospectionClients: opts.IntrospectionClients,
	})
	if err != nil {
		t.Fatalf("oidchttp.New: %v", err)
	}
	api, err := httpapi.New(httpapi.Config{
		Issuer: vIssuer, OIDC: opHandler, TokenIntrospector: opHandler,
		GrantStore: store, DeviceStore: store, Federation: fed,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	return &vEnv{t: t, server: server, handler: api.Handler(), store: store,
		audit: auditLog, upstream: up, clients: clients}
}

func vPKCE(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const vVerifier = "verifier-verifier-verifier-verifier-verifier"

// vStartAuthorize issues an authorization request and returns its id.
func (e *vEnv) vStartAuthorize(subject string, scopes ...string) string {
	e.t.Helper()
	requested := append(append([]string(nil), scopes...), "offline_access")
	q := url.Values{
		"response_type": {"code"}, "client_id": {vClientID}, "redirect_uri": {vRedirect},
		"scope": {strings.Join(requested, " ")}, "state": {"st-v"},
		"code_challenge": {vPKCE(vVerifier)}, "code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		e.t.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		e.t.Fatalf("no authRequestID in %q", loc)
	}
	return id
}

// vComplete runs CompleteLogin with the requested scope set (the consent
// approval the httpapi route performs).
func (e *vEnv) vComplete(id, subject string, scopes ...string) {
	e.t.Helper()
	requested := append(append([]string(nil), scopes...), "offline_access")
	if err := e.store.CompleteLogin(context.Background(), id, subject, requested); err != nil {
		e.t.Fatalf("CompleteLogin: %v", err)
	}
}

// vCallback drives the authorize callback and returns the code.
func (e *vEnv) vCallback(id string) string {
	e.t.Helper()
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	if rec.Code != http.StatusFound {
		e.t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	cb, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		e.t.Fatalf("no code in %q", cb)
	}
	return code
}

func (e *vEnv) vExchange(code, clientID string) (int, []byte) {
	e.t.Helper()
	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {code}, "redirect_uri": {vRedirect}, "code_verifier": {vVerifier},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *vEnv) mintToken(subject string, scopes ...string) string {
	e.t.Helper()
	return e.mintTokenFor(vClientID, subject, scopes...)
}

func (e *vEnv) mintTokenFor(clientID, subject string, scopes ...string) string {
	e.t.Helper()
	id := e.vStartAuthorize(subject, scopes...)
	e.vComplete(id, subject, scopes...)
	code := e.vCallback(id)
	status, body := e.vExchange(code, clientID)
	if status != http.StatusOK {
		e.t.Fatalf("token = %d: %s", status, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		e.t.Fatalf("no access token: %s (err=%v)", body, err)
	}
	return out.AccessToken
}

func (e *vEnv) vGet(path, token string) (int, http.Header, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.server.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := e.server.Client().Do(req)
	if err != nil {
		e.t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, body
}

func (e *vEnv) vPostForm(path string, form url.Values, rawAuth string) (int, []byte) {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rawAuth != "" {
		req.Header.Set("Authorization", rawAuth)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func vBasic(rawUser, rawPassword string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(rawUser+":"+rawPassword))
}

func (e *vEnv) vEvents(action string) []audit.Event {
	e.t.Helper()
	var out []audit.Event
	for _, ev := range e.audit.Events() {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

// vRegistryWith adds extra descriptors to the shipped catalogue.
func vRegistryWith(t *testing.T, extra ...oauth.Descriptor) *oauth.Registry {
	t.Helper()
	reg, err := oauth.NewRegistry(append(oauth.DefaultDescriptors(), extra...)...)
	if err != nil {
		t.Fatalf("oauth.NewRegistry: %v", err)
	}
	return reg
}

// vTwoSources is two sources of one game both serving `scores`, each with its
// own scope, so a probe can test whether the normalized gate really demands the
// scope of EVERY candidate (the reviewed report's guard claim).
func vTwoSources(upstream string) []federation.Source {
	return []federation.Source{
		{
			Game: vGame, Name: "alpha", DisplayName: "Alpha",
			Issuer: upstream, RawBase: upstream,
			ClientID: "a", ClientSecret: "a", TokenClass: "revocable",
			Resources: []federation.Resource{{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"}},
		},
		{
			Game: vGame, Name: "beta", DisplayName: "Beta",
			Issuer: upstream, RawBase: upstream,
			ClientID: "b", ClientSecret: "b", TokenClass: "revocable",
			Resources: []federation.Resource{{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score2.read"}},
		},
	}
}
