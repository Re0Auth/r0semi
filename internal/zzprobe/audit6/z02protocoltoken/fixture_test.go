//go:build audit6

package z02protocoltoken

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

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// noRedirect keeps a probe looking at the redirect itself instead of following
// it into the client's (nonexistent) callback.
var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// zoneEnv is one mounted protocol plane plus the handles a probe needs. It is
// assembled only from exported constructors — the same ones cmd/re0auth's
// openOIDC composes — so every attack goes through the real handler.
type zoneEnv struct {
	server  *httptest.Server
	handler *oidchttp.Handler
	store   *memory.OIDCStore
	clients *oauth.MemoryClientRegistry

	webID     string // confidential, registered for account.id + phigros.score.read
	webSec    string
	deviceID  string // public, registered for account.id
	narrowID  string // confidential, registered for account.id only
	narrowSec string

	issuer    string
	cryptoKey [32]byte
}

// rebuild mounts a second handler on the same store and registry with a
// mutated Config — how a probe varies the introspection allowlist without
// rebuilding the deployment underneath it.
func (e zoneEnv) rebuild(t *testing.T, mutate func(*oidchttp.Config)) zoneEnv {
	t.Helper()
	cfg := oidchttp.Config{
		Issuer:        e.issuer,
		Storage:       e.store,
		CryptoKey:     e.cryptoKey,
		CryptoKeyID:   "probe",
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

func (e zoneEnv) withIntrospection(t *testing.T, ids []string) zoneEnv {
	t.Helper()
	return e.rebuild(t, func(cfg *oidchttp.Config) { cfg.IntrospectionClients = ids })
}

// zoneOptions tweaks what a probe deploys.
type zoneOptions struct {
	issuer               string
	introspectionClients []string
	now                  func() time.Time
	// signer overrides the store's signing key set, so a probe can deploy a
	// rotation (a current key plus retired public keys) and read the JWKS.
	signer *oidcstore.Signer
}

// testClock is a clock a probe can move, so a token's expiry is reached
// without waiting an hour and a session's sign-in is made stale on demand.
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

// newZoneEnv deploys the protocol plane with three clients and the default
// scope catalogue. The clock, when set, is the store's clock.
func newZoneEnv(t *testing.T, opts zoneOptions) zoneEnv {
	t.Helper()
	ctx := context.Background()

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	tag := hex.EncodeToString(suffix)
	webID, deviceID, narrowID := "z02-web-"+tag, "z02-device-"+tag, "z02-narrow-"+tag
	const webSec, narrowSec = "z02-web-secret", "z02-narrow-secret"

	clients := oauth.NewMemoryClientRegistry()
	web, err := oauth.NewClient(webID, "Z02 Web", oauth.ClientConfidential, webSec,
		[]string{"https://client.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	device, err := oauth.NewClient(deviceID, "Z02 Device", oauth.ClientPublic, "",
		[]string{"https://device.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := oauth.NewClient(narrowID, "Z02 Narrow", oauth.ClientConfidential, narrowSec,
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
	signer := opts.signer
	if signer == nil {
		signer = oidcstore.NewSigner("z02-kid", key)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   signer,
		Now:      opts.now,
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("z02probe0123456789abcdef0123456"))

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
	return zoneEnv{
		server: srv, handler: handler, store: store, clients: clients,
		webID: webID, webSec: webSec, deviceID: deviceID,
		narrowID: narrowID, narrowSec: narrowSec,
		issuer: opts.issuer, cryptoKey: cryptoKey,
	}
}

// codeFlow drives authorize -> consent -> callback -> token for the
// confidential web client, returning the raw token response.
func (e zoneEnv) codeFlow(t *testing.T, scopes []string) map[string]any {
	t.Helper()
	return e.codeFlowAs(t, e.webID, e.webSec, "https://client.example/cb", scopes, "usr_z02", "nonce-z02")
}

// codeFlowAs is codeFlow for one client. authTime, when non-zero, is recorded
// on the request the way cmd/re0auth's login hook records the session's real
// sign-in time (cmd/re0auth/main.go:1292-1303 calls SetAuthTime with
// sessions.AuthenticatedAt before the consent page is shown).
func (e zoneEnv) codeFlowAs(t *testing.T, clientID, secret, redirect string, scopes []string, subject, nonce string) map[string]any {
	t.Helper()
	return e.codeFlowWithAuthTime(t, clientID, secret, redirect, scopes, subject, nonce, time.Time{})
}

func (e zoneEnv) codeFlowWithAuthTime(t *testing.T, clientID, secret, redirect string, scopes []string, subject, nonce string, authTime time.Time) map[string]any {
	t.Helper()
	ctx := context.Background()
	verifier := strings.Repeat("v", 64)
	challenge := pkceValue(verifier)

	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"state-z02"},
		"nonce":                 {nonce},
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
	if !authTime.IsZero() {
		if err := e.store.SetAuthTime(ctx, id, authTime); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.store.CompleteLogin(ctx, id, subject, scopes); err != nil {
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

// authorizeCode runs only the authorize leg and returns the code plus the
// pending request id, so a probe can attack the exchange itself.
func (e zoneEnv) authorizeCode(t *testing.T, clientID, redirect string, scopes []string, subject string) (code, requestID string) {
	t.Helper()
	ctx := context.Background()
	verifier := strings.Repeat("v", 64)
	authz := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"state-z02"},
		"code_challenge":        {pkceValue(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+authz.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	login, _ := url.Parse(resp.Header.Get("Location"))
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %s", resp.Header.Get("Location"))
	}
	if err := e.store.CompleteLogin(ctx, id, subject, scopes); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	cb, _ := url.Parse(resp.Header.Get("Location"))
	return cb.Query().Get("code"), id
}

func (e zoneEnv) get(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return resp
}

// postForm sends a form POST. basicID may contain literal percent-escapes:
// req.SetBasicAuth does no escaping of its own, so what goes on the wire is
// exactly the string handed here.
func (e zoneEnv) postForm(t *testing.T, path string, form url.Values, basicID, basicSecret string) (*http.Response, []byte) {
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

func (e zoneEnv) postToken(t *testing.T, clientID, secret string, form url.Values) (map[string]any, int) {
	t.Helper()
	resp, raw := e.postForm(t, "/oauth/token", form, clientID, secret)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode
}

func (e zoneEnv) refresh(t *testing.T, clientID, secret, token string) (map[string]any, int) {
	t.Helper()
	return e.postToken(t, clientID, secret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
	})
}

// deviceFlow drives device_authorization -> (in-process approval, the
// /v1/device/decision leg's store call) -> the device_code token grant.
func (e zoneEnv) deviceFlow(t *testing.T, clientID, basicID, basicSecret string, scopes []string, subject string) (map[string]any, int, []byte) {
	t.Helper()
	resp, raw := e.postForm(t, "/oauth/device_authorization", url.Values{
		"client_id": {clientID},
		"scope":     {strings.Join(scopes, " ")},
	}, basicID, basicSecret)
	if resp.StatusCode != http.StatusOK {
		return decodeJSON(t, raw), resp.StatusCode, raw
	}
	var deviceResp struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		Interval   int    `json:"interval"`
	}
	if err := json.Unmarshal(raw, &deviceResp); err != nil {
		t.Fatal(err)
	}
	if err := e.store.DecideDeviceAuthorization(context.Background(), deviceResp.UserCode, subject, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	// The memory store throttles a poll that comes sooner than the advertised
	// interval, so sleep past it before the first poll.
	time.Sleep(time.Duration(deviceResp.Interval+1) * time.Second)
	tokenForm := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceResp.DeviceCode},
	}
	if basicID == "" {
		// A public client names itself in the body: there is no Basic header
		// and no secret, which is the "none" authentication method.
		tokenForm.Set("client_id", clientID)
	}
	tokens, status := e.postToken(t, basicID, basicSecret, tokenForm)
	return tokens, status, nil
}

// userinfo asks the userinfo endpoint for one bearer.
func (e zoneEnv) userinfo(t *testing.T, bearer string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.server.URL+"/oauth/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, decodeJSON(t, bodyOf(t, resp))
}

// introspect posts a token to /oauth/introspect with the given Basic identity,
// returning status, the decoded body, and the raw body text.
func (e zoneEnv) introspect(t *testing.T, token, basicID, basicSecret string) (int, map[string]any, string) {
	t.Helper()
	resp, raw := e.postForm(t, "/oauth/introspect", url.Values{"token": {token}}, basicID, basicSecret)
	return resp.StatusCode, decodeJSON(t, raw), string(raw)
}

// tokenJSON is the response of a token exchange, decoded.
type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
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

func pkceValue(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

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

// asEngine builds the hand-rolled oauth.Service (the Upstream Kit engine) on
// the same client registry, so a probe can check the AS-side Introspect and
// Revoke semantics — b5f01da's territory — with real calls.
func (e zoneEnv) asEngine(t *testing.T) oauth.Service {
	t.Helper()
	svc, err := oauth.NewService(e.clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: "https://as.z02",
		Scopes: oauth.DefaultRegistry(),
		Now:    func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}
