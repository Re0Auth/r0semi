//go:build audit7

// Package zzprobe_z09federationdataplane — round-7 audit probes, area Z09
// (federation data plane, egress, SSRF, binding lifecycle).
//
// The data-plane probes drive the REAL HTTP surface: internal/httpapi mounted on
// an httptest server, with the real OP handler (internal/oidchttp) behind it and
// access tokens minted through the real authorize -> callback -> token flow. A
// probe that goes red here is red at the boundary an attacker reaches, not at an
// internal function.
package zzprobe_z09federationdataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/httpclient"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

// zzRedirect is the redirect URI the probe client registers, and therefore the
// one the minted tokens are issued against.
const zzRedirect = "https://app.example/cb"

// zzMaxBody mirrors federation's own cap (service.go: maxBody = 4 << 20). It is
// restated here so the probe can state "the upstream wrote more than this and the
// service answered 200 anyway" without reaching into the package.
const zzMaxBody = 4 << 20

// newTestVault is a real in-memory vault with a fixed local KEK, so the vault's
// audit-before-use and zeroization behaviour is present rather than stubbed.
func newTestVault(t *testing.T) vault.Service {
	t.Helper()
	wrapper, err := vault.NewLocalKeyWrapper("probe", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// mustPair encodes a binding secret exactly as federation.bindingSecret does.
func mustPair(t *testing.T, access, refresh string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func zzCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

func zzOPBackend(t *testing.T, issuer string, clients oauth.ClientRegistry) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	registry := zzScopeRegistry(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: registry,
		Signer:   oidcstore.NewSigner("test", key),
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := oidchttp.New(oidchttp.Config{
		Issuer:        issuer,
		Storage:       store,
		CryptoKey:     zzCryptoKey(),
		CryptoKeyID:   "test",
		AllowInsecure: true,
		Clients:       clients,
		Registry:      registry,
		Consent:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, store
}

// zzScopeRegistry is the shipped catalogue plus the raw-passthrough scope for
// zzGame.
//
// The composition root registers one `<game>.raw.read` per configured game with a
// raw_base (cmd/re0auth/main.go rawScopeDescriptors), and the data-plane probes
// here drive raw endpoints that have one. Since Z20-2 that explicit scope is the
// only thing that opens raw, so without this descriptor the OP refuses the scope
// at authorize time and no probe could reach the raw success path.
func zzScopeRegistry(t *testing.T) *oauth.Registry {
	t.Helper()
	reg, err := oauth.NewRegistry(append(oauth.DefaultDescriptors(), oauth.Descriptor{
		Scope: oauth.Scope(oauth.RawScope(zzGame)), Title: "读取 " + zzGame + " 原生接口",
		Description: "probe descriptor: the explicit scope the raw passthrough requires",
		Risk:        oauth.RiskHigh,
	})...)
	if err != nil {
		t.Fatalf("oauth.NewRegistry: %v", err)
	}
	return reg
}

func zzPKCE(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// zzMintToken drives the real authorization-code + PKCE flow, so the token the
// data plane sees is one the OP really issued for the scopes asked for.
func zzMintToken(t *testing.T, h http.Handler, store *memory.OIDCStore, clientID, subject string, scopes ...string) string {
	t.Helper()
	const verifier = "verifier-verifier-verifier-verifier-verifier"
	requested := append(append([]string(nil), scopes...), "offline_access")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {zzRedirect},
		"scope":                 {strings.Join(requested, " ")},
		"state":                 {"st"},
		"code_challenge":        {zzPKCE(verifier)},
		"code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no auth request id in %q", loc)
	}
	if err := store.CompleteLogin(context.Background(), id, subject, requested); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	cb, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", cb)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {zzRedirect},
		"code_verifier": {verifier},
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.AccessToken == "" {
		t.Fatalf("no access token: %s (err=%v)", rec.Body.String(), err)
	}
	return body.AccessToken
}

// zzBind is one pre-existing binding the harness enrolls before serving.
type zzBind struct {
	User    string
	Game    string
	Source  string
	Access  string
	Refresh string
	Expiry  time.Time
}

// zzHarness mounts the real HTTP surface over reg, with every binding in binds
// already enrolled in the vault, and returns the server plus a minter.
//
// It is the fixture every data-plane probe here uses: the token is minted by the
// real OP, the scope gate is the real handler's, and the upstream is a real
// httptest server reached through the real outbound client.
func zzHarness(t *testing.T, reg *federation.Registry, binds []zzBind, tune func(*federation.Config)) (*httptest.Server, func(subject string, scopes ...string) string) {
	t.Helper()
	ctx := context.Background()

	store := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	for _, b := range binds {
		binding := federation.Binding{
			User: account.UserID(b.User), Game: b.Game, Source: b.Source,
			Version: 1, HasRefresh: b.Refresh != "", Expiry: b.Expiry,
		}
		if err := store.Put(ctx, binding); err != nil {
			t.Fatal(err)
		}
		if err := v.Enroll(ctx, federation.BindingIdentity(binding), mustPair(t, b.Access, b.Refresh), nil); err != nil {
			t.Fatal(err)
		}
	}

	// The composition root's wiring (cmd/re0auth/main.go:492-508), defaults
	// included: the same pooled transport, the same 20s per-call timeout, and the
	// same per-host breaker. A probe that measures breaker behaviour must therefore
	// measure the shipped configuration rather than a bare client.
	hc := httpclient.NewOutboundClient(httpclient.OutboundConfig{
		Breaker: &httpclient.BreakerOptions{},
	})
	cfg := federation.Config{
		Registry: reg, Bindings: store, Vault: v,
		Doer: hc, HTTPClient: hc,
		BaseURL: "https://re0auth.test",
	}
	if tune != nil {
		tune(&cfg)
	}
	fed, err := federation.NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// The client is registered for every scope any configured source declares, so
	// each probe can mint a token for exactly one source's scope and watch what
	// the gate does with it. The game's raw scope is added too: the composition
	// root registers it for every game with a raw_base, and since Z20-2 it is the
	// only thing that opens a raw path.
	seen := map[oauth.Scope]bool{}
	var allowed []oauth.Scope
	for _, src := range reg.AllSources() {
		for _, res := range src.Resources {
			if res.Scope == "" || seen[oauth.Scope(res.Scope)] {
				continue
			}
			seen[oauth.Scope(res.Scope)] = true
			allowed = append(allowed, oauth.Scope(res.Scope))
		}
	}
	rawScope := oauth.Scope(oauth.RawScope(zzGame))
	if !seen[rawScope] {
		seen[rawScope] = true
		allowed = append(allowed, rawScope)
	}
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "", []string{zzRedirect}, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, client); err != nil {
		t.Fatal(err)
	}

	opHandler, oidcStore := zzOPBackend(t, "https://re0auth.test", clients)
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        oidcStore,
		DeviceStore:       oidcStore,
		Federation:        fed,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	mint := func(subject string, scopes ...string) string {
		return zzMintToken(t, api.Handler(), oidcStore, "cli", subject, scopes...)
	}
	return srv, mint
}

// zzGet performs an authenticated GET and returns the status, one named header
// and the body.
func zzGet(t *testing.T, client *http.Client, url, token string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, resp.Header, buf.Bytes()
}
