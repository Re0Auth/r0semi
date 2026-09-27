//go:build audit5

// Package protocol holds the adversarial probes for the protocol plane
// (OIDC / OAuth correctness and abuse resistance) of Re0Auth.
//
// Every probe here attacks through a real entry point: a real *oidchttp.Handler
// mounted on an httptest.Server, backed by the in-memory OP store. Nothing is
// stubbed that the production path does not stub.
package protocol

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// noRedirect keeps the probe looking at the redirect itself instead of following
// it into the client's (nonexistent) callback.
var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// env is one mounted protocol plane plus the handles a probe needs.
type env struct {
	server  *httptest.Server
	handler *oidchttp.Handler
	store   *memory.OIDCStore
	clients *oauth.MemoryClientRegistry
	// webID is a CONFIDENTIAL client registered for account.id + phigros.score.read.
	webID     string
	webSec    string
	deviceID  string
	narrowID  string
	narrowSec string

	// kept so a probe can rebuild the handler with a different Config on the same
	// store — how the introspection allowlist is varied without a second fixture.
	issuer    string
	cryptoKey [32]byte
	scopes    []string
}

// withIntrospection mounts a second handler, on the same store and the same
// registered clients, whose introspection allowlist is ids. It is how PROBE 1
// compares "allowlisted" with "not allowlisted" on one deployment shape.
func (e env) withIntrospection(t *testing.T, ids []string) env {
	t.Helper()
	return e.rebuild(t, func(cfg *oidchttp.Config) {
		cfg.IntrospectionClients = ids
	})
}

// withCrypto mounts a second handler on the same store with a different token
// encryption key and a different set of retired keys: the token-key half of a
// rotation, which is the only way to observe what a rotation does to tokens that
// were minted before it.
func (e env) withCrypto(t *testing.T, key [32]byte, id string, retired []oidchttp.RetiredTokenKey) env {
	t.Helper()
	return e.rebuild(t, func(cfg *oidchttp.Config) {
		cfg.CryptoKey = key
		cfg.CryptoKeyID = id
		cfg.RetiredTokenKeys = retired
	})
}

func (e env) rebuild(t *testing.T, mutate func(*oidchttp.Config)) env {
	t.Helper()
	cfg := oidchttp.Config{
		Issuer:        e.issuer,
		Storage:       e.store,
		CryptoKey:     e.cryptoKey,
		CryptoKeyID:   "probe",
		Scopes:        e.scopes,
		AllowInsecure: true,
		Clients:       e.clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       e.store,
	}
	mutate(&cfg)
	handler, err := oidchttp.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	out := e
	out.server = srv
	out.handler = handler
	return out
}

// envOptions tweaks what a probe deploys. Everything unset keeps the shape the
// oidchttp fixture uses, so a probe that changes nothing attacks the same plane
// the package's own tests do.
type envOptions struct {
	// issuer, when empty, leaves the handler in its dynamic-issuer shape (issuer
	// derived from the request Host) — the shape newFixture uses.
	issuer string
	// introspectionClients is the resource-server allowlist.
	introspectionClients []string
	// cryptoKey overrides the token-encryption key, so a probe can deploy two
	// handlers that genuinely do not share one.
	cryptoKey *[32]byte
	// now supplies the store's clock. nil means time.Now.
	now func() time.Time
	// clock is filled with a test-controlled clock when now is set, so a probe can
	// advance it.
	clock *testClock
}

// testClock is a clock a probe can move, so an access token's expiry can be
// reached without waiting an hour.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock { return &testClock{now: time.Now().UTC()} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newEnv(t *testing.T, opts envOptions) env {
	t.Helper()
	ctx := context.Background()

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	tag := hex.EncodeToString(suffix)
	webID, deviceID, narrowID := "probe-web-"+tag, "probe-device-"+tag, "probe-narrow-"+tag
	const webSec, narrowSec = "probe-web-secret", "probe-narrow-secret"

	clients := oauth.NewMemoryClientRegistry()
	web, err := oauth.NewClient(webID, "Probe Web", oauth.ClientConfidential, webSec,
		[]string{"https://client.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	device, err := oauth.NewClient(deviceID, "Probe Device", oauth.ClientPublic, "",
		[]string{"https://device.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := oauth.NewClient(narrowID, "Probe Narrow", oauth.ClientConfidential, narrowSec,
		[]string{"https://narrow.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []oauth.Client{web, device, narrow} {
		if err := clients.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("probe-kid", key),
		Now:      opts.now,
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	if opts.cryptoKey != nil {
		cryptoKey = *opts.cryptoKey
	} else {
		copy(cryptoKey[:], []byte("probe0123456789abcdef0123456789a"))
	}

	var scopes []string
	for _, d := range oauth.DefaultDescriptors() {
		scopes = append(scopes, d.Scope.String())
	}

	handler, err := oidchttp.New(oidchttp.Config{
		Issuer:               opts.issuer,
		Storage:              store,
		CryptoKey:            cryptoKey,
		CryptoKeyID:          "probe",
		Scopes:               scopes,
		AllowInsecure:        true,
		Clients:              clients,
		Registry:             oauth.DefaultRegistry(),
		Consent:              store,
		IntrospectionClients: opts.introspectionClients,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return env{
		server: srv, handler: handler, store: store, clients: clients,
		webID: webID, webSec: webSec, deviceID: deviceID,
		narrowID: narrowID, narrowSec: narrowSec,
		issuer: opts.issuer, cryptoKey: cryptoKey, scopes: scopes,
	}
}

func (e env) codeFlow(t *testing.T, scopes []string) map[string]any {
	t.Helper()
	return e.codeFlowAs(t, e.webID, e.webSec, "https://client.example/cb", scopes, "usr_probe")
}

// codeFlowAs drives a full authorize -> consent -> callback -> token round trip
// for one client, so a probe exercises a real exchange rather than a stub.
func (e env) codeFlowAs(t *testing.T, clientID, secret, redirect string, scopes []string, subject string) map[string]any {
	t.Helper()
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"state-probe-0001"},
		"nonce":                 {"nonce-probe-0001"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	login, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %s", resp.Header.Get("Location"))
	}
	if err := e.store.CompleteLogin(t.Context(), id, subject, scopes); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", cb)
	}

	tokens, status := e.postToken(t, clientID, secret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("token status = %d: %v", status, tokens)
	}
	return tokens
}

func (e env) get(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return resp
}

// postForm sends a form POST and returns the response with its body already read
// into the second value.
func (e env) postForm(t *testing.T, path string, form url.Values, basicID, basicSecret string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, bodyOf(t, resp)
}

func (e env) postToken(t *testing.T, clientID, secret string, form url.Values) (map[string]any, int) {
	t.Helper()
	resp, raw := e.postForm(t, "/oauth/token", form, clientID, secret)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode
}

// tokenJSON is the response of a token exchange, decoded.
type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

func asTokens(t *testing.T, raw map[string]any) tokenJSON {
	t.Helper()
	blob, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var out tokenJSON
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func bodyOf(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not JSON: %s", raw)
	}
	return out
}

// authValues is a well-formed authorize request for the environment's
// confidential client, so a probe can vary one parameter at a time.
func authValues(e env, redirect string, scopes []string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {e.webID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"state-probe"},
		"nonce":                 {"nonce-probe"},
		"code_challenge":        {pkceValue(strings.Repeat("v", 64))},
		"code_challenge_method": {"S256"},
	}
}

func pkceValue(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func parseLocation(t *testing.T, resp *http.Response) (*url.URL, error) {
	t.Helper()
	return url.Parse(resp.Header.Get("Location"))
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// idTokenClaims decodes a compact JWS payload without verifying it: the probes
// inspect what was ISSUED, and the signature is the OP's own.
func idTokenClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return decodeJSON(t, payload)
}
