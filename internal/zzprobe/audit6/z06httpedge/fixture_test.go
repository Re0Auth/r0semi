//go:build audit6

// Fixtures for the round-6 HTTP-edge probes. Everything is built from exported
// surfaces only (httpapi.New + Config and the packages behind it), so a bug in
// the product's own in-package test helpers cannot leak into what these probes
// observe. No tracked file is modified.
package z06httpedge

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
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	edgeIssuer   = "https://re0auth.test"
	edgeRedirect = "https://app.example/cb"
	// noRefill is "one token, effectively never refilled": with this rate a
	// second admitted request on the same bucket key means the key was given a
	// brand-new bucket.
	noRefill = 0.001
)

// stubIntrospector and friends satisfy httpapi's seams without any storage, for
// probes that only exercise middleware and routing.
type stubIntrospector struct{}

func (stubIntrospector) Introspect(context.Context, string) (oauth.TokenInfo, error) {
	return oauth.TokenInfo{}, context.DeadlineExceeded
}

type stubGrants struct{}

func (stubGrants) Grants(context.Context, string) ([]oauth.Grant, error) { return nil, nil }
func (stubGrants) RevokeGrant(context.Context, string, string) error     { return nil }

type stubDevices struct{}

func (stubDevices) DescribeDeviceAuthorization(context.Context, string) (oauth.DeviceAuthorization, error) {
	return oauth.DeviceAuthorization{}, context.Canceled
}

func (stubDevices) DecideDeviceAuthorization(context.Context, string, string, bool, []oauth.Scope, []oauth.Scope) error {
	return context.Canceled
}

// edgeConfig is the minimal httpapi.Config that httpapi.New accepts.
func edgeConfig() httpapi.Config {
	return httpapi.Config{
		Issuer:            edgeIssuer,
		OIDC:              http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		TokenIntrospector: stubIntrospector{},
		GrantStore:        stubGrants{},
		DeviceStore:       stubDevices{},
	}
}

// edgeServer builds a real httpapi.Server around the given tweak. The OIDC
// handler is a stub, so probes that need the provider's real answers use
// newRealOP instead.
func edgeServer(t *testing.T, tweak func(*httpapi.Config)) *httpapi.Server {
	t.Helper()
	cfg := edgeConfig()
	if tweak != nil {
		tweak(&cfg)
	}
	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	return srv
}

// edgeCall runs one in-process request through the handler.
func edgeCall(t *testing.T, h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// trustedPrefixes parses CIDRs for Config.TrustedProxies.
func trustedPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

// edgeCryptoKey satisfies oidchttp.Config.CryptoKey without a real key.
func edgeCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

// newRealOP builds the OpenID Provider the way cmd/re0auth's openOIDC does, so
// probes that need the provider's real verbs (discovery, token) see them.
func newRealOP(t *testing.T, clients oauth.ClientRegistry) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	return newRealOPWithRegistry(t, clients, oauth.DefaultRegistry())
}

// rawScopeFor is the explicit scope that gates a game's raw passthrough,
// spelled through the production helper so the probe cannot drift from it.
func rawScopeFor(game string) oauth.Scope { return oauth.Scope(oauth.RawScope(game)) }

// rawScopeRegistry is the default catalogue extended with one game's raw scope,
// so the real OP will grant it. The raw gate requires this explicit scope
// (Z20-2): a token minted for a resource scope alone is refused with 403, which
// is what a raw probe that only asked for phigros.profile.read used to measure
// instead of the routing behaviour it was written for.
func rawScopeRegistry(t *testing.T, game string) *oauth.Registry {
	t.Helper()
	reg, err := oauth.NewRegistry(append(oauth.DefaultDescriptors(), oauth.Descriptor{
		Scope:       rawScopeFor(game),
		Title:       "Raw API",
		Description: "verbatim passthrough to a source's native API",
		Risk:        oauth.RiskMedium,
	})...)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// newRealOPWithRegistry is newRealOP with an explicit scope catalogue, for
// probes that exercise a scope the built-in catalogue does not carry.
func newRealOPWithRegistry(t *testing.T, clients oauth.ClientRegistry, registry *oauth.Registry) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: registry,
		Signer:   oidcstore.NewSigner("probe", key),
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := oidchttp.New(oidchttp.Config{
		Issuer:        edgeIssuer,
		Storage:       store,
		CryptoKey:     edgeCryptoKey(),
		CryptoKeyID:   "probe",
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

// edgeVault builds a vault service with a local key wrapper, the same shape the
// product's tests use, so the federation wiring can enroll a binding.
func edgeVault(t *testing.T) vault.Service {
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

// bindingPair encodes a binding secret exactly as federation.bindingSecret
// does, so the vault payload is the real shape rather than a guess.
func bindingPair(access, refresh string) []byte {
	payload, _ := json.Marshal(map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
	return payload
}

// rawEnv wires the real HTTP surface with one source that has a raw base, a
// bound user, and a minted bearer token, so raw-path probes run end to end
// (authorize -> login -> callback -> token exchange) through the real OP.
//
// upstream is the source's handler; upstreamHit records the raw path of each
// request the source saw.
func rawEnv(t *testing.T, upstream http.HandlerFunc) (h http.Handler, token string, upstreamHit *[]string) {
	t.Helper()
	var hits []string
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		upstream(w, r)
	}))
	t.Cleanup(src.Close)

	registry, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "src", DisplayName: "Src", Issuer: src.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		RawBase: src.URL + "/v1",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	binding := federation.Binding{User: "usr_test", Game: "phigros", Source: "src", Version: 1}
	if err := bindings.Put(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	v := edgeVault(t)
	if err := v.Enroll(context.Background(), federation.BindingIdentity(binding), bindingPair("tok", "rt"), nil); err != nil {
		t.Fatal(err)
	}
	fed, err := federation.NewService(federation.Config{
		Registry: registry, Bindings: bindings, Vault: v,
		Doer: src.Client(), HTTPClient: src.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The raw route's gate is the explicit `<game>.raw.read` scope (Z20-2), not a
	// resource scope: the client is registered for it and the catalogue carries
	// it, so the token this fixture mints actually opens the passthrough.
	scopes := rawScopeRegistry(t, "phigros")
	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "", []string{edgeRedirect},
		[]oauth.Scope{oauth.ScopePhigrosProfile, rawScopeFor("phigros")})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	opHandler, store := newRealOPWithRegistry(t, clients, scopes)
	api, err := httpapi.New(httpapi.Config{
		Issuer: edgeIssuer, OIDC: opHandler,
		TokenIntrospector: opHandler, GrantStore: store, DeviceStore: store,
		Federation: fed, Scopes: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api.Handler(), mintToken(t, api.Handler(), store, "cli", "usr_test",
		oauth.ScopePhigrosProfile.String(), rawScopeFor("phigros").String()), &hits
}

// mintToken drives the real authorize/callback/token exchange and returns a
// live bearer token for the given subject and scopes.
func mintToken(t *testing.T, h http.Handler, store *memory.OIDCStore, clientID, subject string, scopes ...string) string {
	t.Helper()
	const verifier = "verifier-verifier-verifier-verifier-verifier"
	requested := append(append([]string(nil), scopes...), "offline_access")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {edgeRedirect},
		"scope":                 {strings.Join(requested, " ")},
		"state":                 {"st"},
		"code_challenge":        {pkceSum(verifier)},
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
		"redirect_uri":  {edgeRedirect},
		"code_verifier": {verifier},
	}
	rec = httptest.NewRecorder()
	tokReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, tokReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" {
		t.Fatal("no access token in the token response")
	}
	return resp.AccessToken
}

func pkceSum(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
