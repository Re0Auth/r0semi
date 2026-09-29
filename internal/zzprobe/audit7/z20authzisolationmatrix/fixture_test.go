//go:build audit7

// Fixture for the round-7 zone-20 probes (authorization isolation matrix).
//
// It is assembled from exported surfaces only — httpapi.New + Config,
// internal/oidchttp, internal/store/memory, internal/federation, vault, oauth —
// so a probe observes the wiring the composition root builds, not a private
// helper. The upstream data source is a real httptest server, reached through
// the real outbound client and the real binding store.
package zzprobe_z20authzisolationmatrix

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
	zIssuer   = "https://re0auth.test"
	zRedirect = "https://app.example/cb"
	zClientID = "cli"
	zSubject  = "usr_victim"
	zGame     = "phigros"
	zSource   = "fake"
	// zUpstreamToken is what the vault holds for the binding; the upstream
	// server asserts it arrived, so a probe can tell "the request was made as
	// this user" from "the gate refused it".
	zUpstreamToken = "up-token-victim"
	// zScoreBody is the payload the upstream answers for the score resource.
	// Its marker is what a probe looks for in a response body it must not see.
	zScoreBody = `{"data":[{"song":"secret-song","score":1000000}],"marker":"Z20-SCORES"}`
)

// zUpstream records which paths were reached and with which bearer, so a probe
// can prove the data plane really called the source.
type zUpstream struct {
	mu    sync.Mutex
	paths []string
	authz []string
}

func (u *zUpstream) record(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.paths = append(u.paths, r.URL.Path)
	u.authz = append(u.authz, r.Header.Get("Authorization"))
}

func (u *zUpstream) hit(path string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, p := range u.paths {
		if p == path {
			return true
		}
	}
	return false
}

func (u *zUpstream) calls() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.paths...)
}

// zEnv is one fully wired server: protocol plane, business plane, data plane and
// the upstream source behind it.
type zEnv struct {
	t        *testing.T
	server   *httptest.Server
	handler  http.Handler
	op       *oidchttp.Handler
	store    *memory.OIDCStore
	clients  *oauth.MemoryClientRegistry
	audit    *audit.MemoryLogger
	upstream *zUpstream
	registry *oauth.Registry
}

// zOptions tunes one environment. The zero value is the canonical one.
type zOptions struct {
	// Registry replaces the scope catalogue. Used by the probe that needs an
	// ExplicitConsent descriptor, because the shipped catalogue has none.
	Registry *oauth.Registry
	// ClientScopes overrides what the probe client is registered for.
	ClientScopes []oauth.Scope
	// ClientType/ClientSecret build a confidential client instead of a public
	// one.
	Confidential bool
	ClientSecret string
	// RawBase overrides the source's native API root. Empty means "the source's
	// issuer", which is the config that makes the raw path and the normalized
	// path address the same URL.
	RawBase string
	// IntrospectionClients is the deployment's resource-server allowlist
	// (oidchttp.Config.IntrospectionClients / server.introspection_clients).
	IntrospectionClients []string
	// ExtraPublicIDs registers additional public clients, so a probe can put two
	// clients in the same deployment.
	ExtraPublicIDs []string
}

// zCriticalScope is a catalogue scope the shipped descriptor set does not have.
// It exists only so a probe can put an ExplicitConsent descriptor into the
// registry: the shipped catalogue deliberately contains none
// (oauth/scope.go:126-131, oauth/scope_test.go:31), which is exactly why
// `_audit/protocol.md` P-02 could not be probed.
const zCriticalScope = oauth.Scope("phigros.secret.read")

// zRegistryWithCritical is the default catalogue plus one ExplicitConsent
// descriptor.
func zRegistryWithCritical(t *testing.T) *oauth.Registry {
	t.Helper()
	reg, err := oauth.NewRegistry(append(oauth.DefaultDescriptors(), oauth.Descriptor{
		Scope: zCriticalScope, Title: "读取 Phigros 机密", Description: "probe descriptor",
		Risk: oauth.RiskCritical, ExplicitConsent: true,
	})...)
	if err != nil {
		t.Fatalf("oauth.NewRegistry: %v", err)
	}
	return reg
}

func newZEnv(t *testing.T, opts zOptions) *zEnv {
	t.Helper()
	ctx := context.Background()

	auditLog := audit.NewMemoryLogger()
	up := &zUpstream{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, zScoreBody)
	}))
	t.Cleanup(upstream.Close)

	rawBase := opts.RawBase
	if rawBase == "" {
		// The source's native API root IS its issuer: the raw passthrough then
		// addresses the very URL the normalized route addresses.
		rawBase = upstream.URL
	}
	reg, err := federation.NewRegistry(federation.Source{
		Game: zGame, Name: zSource, DisplayName: "Fake",
		Issuer: upstream.URL, RawBase: rawBase,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
			{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"},
		},
	})
	if err != nil {
		t.Fatalf("federation.NewRegistry: %v", err)
	}

	binds := federation.NewMemoryBindingStore()
	binding := federation.Binding{
		User: account.UserID(zSubject), Game: zGame, Source: zSource,
		TokenType: "Bearer", Version: 1, Expiry: time.Now().Add(time.Hour),
	}
	if err := binds.Put(ctx, binding); err != nil {
		t.Fatal(err)
	}

	wrapper, err := vault.NewLocalKeyWrapper("probe", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	vaultSvc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, auditLog)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := json.Marshal(map[string]string{
		"access_token": zUpstreamToken, "refresh_token": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := vaultSvc.Enroll(ctx, federation.BindingIdentity(binding), pair, nil); err != nil {
		t.Fatal(err)
	}

	fed, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: binds, Vault: vaultSvc,
		Doer: upstream.Client(), HTTPClient: upstream.Client(),
		BaseURL: zIssuer,
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
	typ, secret := oauth.ClientPublic, ""
	if opts.Confidential {
		typ, secret = oauth.ClientConfidential, opts.ClientSecret
		if secret == "" {
			secret = "cli-secret"
		}
	}
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient(zClientID, "CLI", typ, secret, []string{zRedirect}, clientScopes)
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	for _, id := range opts.ExtraPublicIDs {
		extra, err := oauth.NewClient(id, "Extra", oauth.ClientPublic, "", []string{zRedirect}, clientScopes)
		if err != nil {
			t.Fatal(err)
		}
		if err := clients.Create(ctx, extra); err != nil {
			t.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: scopeRegistry,
		Signer:   oidcstore.NewSigner("probe", key),
		Audit:    auditLog,
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatalf("memory.NewOIDCStore: %v", err)
	}
	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("0123456789abcdef0123456789abcdef"))
	opHandler, err := oidchttp.New(oidchttp.Config{
		Issuer:               zIssuer,
		Storage:              store,
		CryptoKey:            cryptoKey,
		CryptoKeyID:          "probe",
		AllowInsecure:        true,
		Clients:              clients,
		Registry:             scopeRegistry,
		Consent:              store,
		IntrospectionClients: opts.IntrospectionClients,
	})
	if err != nil {
		t.Fatalf("oidchttp.New: %v", err)
	}

	api, err := httpapi.New(httpapi.Config{
		Issuer:            zIssuer,
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Federation:        fed,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)

	return &zEnv{
		t: t, server: server, handler: api.Handler(), op: opHandler, store: store,
		clients: clients, audit: auditLog, upstream: up, registry: scopeRegistry,
	}
}

func zPKCE(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// zMintToken drives the real authorization-code + PKCE flow. The consent
// decision goes through the same store call the consent route makes
// (httpapi's decision handler calls ConsentStore.CompleteLogin), and the code is
// exchanged at the real token endpoint, so the library's own post-mint
// DeleteAuthRequest runs exactly as it does in production.
func (e *zEnv) mintToken(subject string, scopes ...string) string {
	e.t.Helper()
	return e.mintTokens(subject, scopes...).AccessToken
}

type zTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

func (e *zEnv) mintTokens(subject string, scopes ...string) zTokens {
	e.t.Helper()
	return e.mintTokensFor(zClientID, subject, scopes...)
}

// mintTokensFor is mintTokens for a named client, so a probe can give a second
// client its own grant.
func (e *zEnv) mintTokensFor(clientID, subject string, scopes ...string) zTokens {
	e.t.Helper()
	const verifier = "verifier-verifier-verifier-verifier-verifier"
	requested := append(append([]string(nil), scopes...), "offline_access")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {zRedirect},
		"scope":                 {strings.Join(requested, " ")},
		"state":                 {"st-z20"},
		"code_challenge":        {zPKCE(verifier)},
		"code_challenge_method": {"S256"},
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
		e.t.Fatalf("no auth request id in %q", loc)
	}
	if err := e.store.CompleteLogin(context.Background(), id, subject, requested); err != nil {
		e.t.Fatalf("CompleteLogin: %v", err)
	}
	rec = httptest.NewRecorder()
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
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {zRedirect},
		"code_verifier": {verifier},
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var out zTokens
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.AccessToken == "" {
		e.t.Fatalf("no access token: %s (err=%v)", rec.Body.String(), err)
	}
	return out
}

// zGet performs an authenticated GET against the mounted server.
func (e *zEnv) zGet(path, token string) (int, http.Header, []byte) {
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

// zEvents returns the audit sink's events whose action matches.
func (e *zEnv) zEvents(action string) []audit.Event {
	e.t.Helper()
	var out []audit.Event
	for _, ev := range e.audit.Events() {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

// zPostForm posts a form with an explicit, raw Authorization header, so a probe
// can put Basic userinfo bytes on the wire that Request.SetBasicAuth cannot
// produce (it encodes, and the guard and the library decode differently).
func (e *zEnv) zPostForm(path string, form url.Values, rawAuth string) (int, []byte) {
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

// zBasicHeader builds the exact Authorization header bytes for a raw (not
// percent-encoded) userinfo pair.
func zBasicHeader(rawUser, rawPassword string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(rawUser+":"+rawPassword))
}
