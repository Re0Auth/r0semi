//go:build audit6

// Two environments, both real: a bare protocol plane (the *oidchttp.Handler on
// an httptest server, the shape internal/oidchttp's own tests use) and the full
// httpapi stack (sessions, the fake-GitHub IdP login plane, the consent and
// device routes) — the shape internal/httpapi's flow tests use. Nothing is
// stubbed that production does not stub: the identity provider is faked at the
// network edge, which is the project's own e2e convention; PKCE, code exchange
// and every store are real.
package z01protocolauth

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
	"github.com/Re0Auth/r0semi/internal/httpapi"
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

// clockStub is a store clock a probe can advance, so an expiry can be reached
// without waiting for it. It is the same seam internal/store/memory's own tests
// use (OIDCOptions.Now).
type clockStub struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clockStub { return &clockStub{now: time.Now().UTC()} }

func (c *clockStub) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clockStub) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func randSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// planeEnv: the protocol plane alone.
// ---------------------------------------------------------------------------

// planeEnv is one mounted protocol plane plus the handles a probe needs.
type planeEnv struct {
	server  *httptest.Server
	handler *oidchttp.Handler
	store   *memory.OIDCStore
	clients *oauth.MemoryClientRegistry
	audit   *audit.MemoryLogger
	clock   *clockStub
	// web is CONFIDENTIAL, registered for account.id + phigros.score.read;
	// device is PUBLIC, registered for account.id.
	webID, webSec  string
	deviceID, devS string
}

type planeOptions struct {
	// now, when set, replaces the store clock and is returned in clock.
	now *clockStub
	// withAudit attaches a memory audit logger to the store.
	withAudit bool
	// sessionUser wires a SessionLookup reporting that account as signed in.
	sessionUser string
}

// probeSessionLookup is a SessionLookup with a fixed answer.
type probeSessionLookup struct{ user string }

func (p probeSessionLookup) User(context.Context) (string, bool) {
	return p.user, p.user != ""
}

func newPlane(t *testing.T, opts planeOptions) *planeEnv {
	t.Helper()
	ctx := context.Background()
	tag := randSuffix()

	clients := oauth.NewMemoryClientRegistry()
	web, err := oauth.NewClient("z01-web-"+tag, "Z01 Web", oauth.ClientConfidential, "web-secret",
		[]string{"https://client.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	device, err := oauth.NewClient("z01-device-"+tag, "Z01 Device", oauth.ClientPublic, "",
		[]string{"https://device.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []oauth.Client{web, device} {
		if err := clients.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var logger *audit.MemoryLogger
	if opts.withAudit {
		logger = audit.NewMemoryLogger()
	}
	var now func() time.Time
	if opts.now != nil {
		now = opts.now.Now
	}
	storeOpts := memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("z01-kid", key),
		Now:      now,
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	}
	if logger != nil {
		storeOpts.Audit = logger
	}
	store, err := memory.NewOIDCStore(storeOpts)
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("z01probe0123456789abcdef0123456"))

	var scopes []string
	for _, d := range oauth.DefaultDescriptors() {
		scopes = append(scopes, d.Scope.String())
	}

	var sessions oidchttp.SessionLookup
	if opts.sessionUser != "" {
		sessions = probeSessionLookup{user: opts.sessionUser}
	}
	handler, err := oidchttp.New(oidchttp.Config{
		Issuer:        "https://issuer.z01",
		Storage:       store,
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "z01",
		Scopes:        scopes,
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
		Sessions:      sessions,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &planeEnv{
		server: srv, handler: handler, store: store, clients: clients,
		audit: logger, clock: opts.now,
		webID: web.ID, webSec: "web-secret",
		deviceID: device.ID,
	}
}

// codeFlow drives authorize -> consent -> callback -> token for the
// confidential client, returning the decoded token response.
func (e *planeEnv) codeFlow(t *testing.T, scopes []string, extra url.Values) (map[string]any, string) {
	t.Helper()
	verifier := strings.Repeat("v", 64)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.webID},
		"redirect_uri":          {"https://client.example/cb"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {"state-z01"},
		"nonce":                 {"nonce-z01"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	resp := e.get(t, noRedirect, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	login, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := login.Query().Get("authRequestID")
	if id == "" {
		t.Fatalf("no authRequestID in %s", resp.Header.Get("Location"))
	}
	if err := e.store.CompleteLogin(t.Context(), id, "usr_z01",
		withOfflineAccess(scopes)); err != nil {
		t.Fatal(err)
	}
	resp = e.get(t, noRedirect, e.server.URL+"/oauth/authorize/callback?id="+url.QueryEscape(id))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", cb)
	}
	tokens, status := e.postToken(t, e.webID, e.webSec, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("token status = %d: %v", status, tokens)
	}
	idToken, _ := tokens["id_token"].(string)
	return tokens, idToken
}

// deviceAuth creates a device authorization for the given client and returns
// the device_code and user_code.
func (e *planeEnv) deviceAuth(t *testing.T, clientID, basicUser, basicSecret string, scopes []string) (deviceCode, userCode string) {
	t.Helper()
	form := url.Values{"client_id": {clientID}, "scope": {strings.Join(scopes, " ")}}
	resp, raw := e.postForm(t, "/oauth/device_authorization", form, basicUser, basicSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization = %d %s", resp.StatusCode, raw)
	}
	out := decodeJSON(t, raw)
	deviceCode, _ = out["device_code"].(string)
	userCode, _ = out["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_authorization answered %s", raw)
	}
	return deviceCode, userCode
}

// approveDevice approves a user code through the same store call the
// verification route's decision makes.
func (e *planeEnv) approveDevice(t *testing.T, userCode string) {
	t.Helper()
	if err := e.store.DecideDeviceAuthorization(t.Context(), userCode, "usr_z01", true, nil, nil); err != nil {
		t.Fatalf("device approval: %v", err)
	}
}

// pollDevice polls the device grant at the token endpoint.
func (e *planeEnv) pollDevice(t *testing.T, deviceCode string, basicUser, basicSecret string, extraForm url.Values) (*http.Response, map[string]any, []byte) {
	t.Helper()
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	}
	for k, vs := range extraForm {
		form[k] = vs
	}
	resp, raw := e.postForm(t, "/oauth/token", form, basicUser, basicSecret)
	return resp, decodeJSON(t, raw), raw
}

func (e *planeEnv) get(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return resp
}

func (e *planeEnv) postForm(t *testing.T, path string, form url.Values, basicID, basicSecret string) (*http.Response, []byte) {
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
	return resp, e.body(t, resp)
}

func (e *planeEnv) postToken(t *testing.T, clientID, secret string, form url.Values) (map[string]any, int) {
	t.Helper()
	resp, raw := e.postForm(t, "/oauth/token", form, clientID, secret)
	return decodeJSON(t, raw), resp.StatusCode
}

func (e *planeEnv) body(t *testing.T, resp *http.Response) []byte {
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

// withOfflineAccess mirrors what ApproveAuthorization does before
// CompleteLogin: the consent decision always re-attaches the OIDC
// offline_access scope (ADR-0001 O-6), which is what makes the code flow
// issue a refresh token.
func withOfflineAccess(scopes []string) []string {
	for _, s := range scopes {
		if s == "offline_access" {
			return scopes
		}
	}
	return append(append([]string(nil), scopes...), "offline_access")
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

// ---------------------------------------------------------------------------
// stackEnv: the full httpapi stack with sessions and the consent routes.
// ---------------------------------------------------------------------------

// stackEnv is the whole service: OP protocol plane, session manager, the fake
// GitHub IdP login plane, and the business-plane consent/device routes.
type stackEnv struct {
	server   *httptest.Server
	accounts *account.MemoryStore
	store    *memory.OIDCStore
	sessions *auth.Manager
	clients  *oauth.MemoryClientRegistry
	audit    *audit.MemoryLogger
	// cli is a PUBLIC downstream client registered for account.id and
	// phigros.score.read at https://app.example/cb.
	cli string
}

// stackSessionLookup adapts auth.Manager to oidchttp.SessionLookup, the way
// cmd/re0auth's sessionLookupAdapter does.
type stackSessionLookup struct{ m *auth.Manager }

func (s stackSessionLookup) User(ctx context.Context) (string, bool) {
	u, ok := s.m.User(ctx)
	return string(u), ok
}

func newStack(t *testing.T) *stackEnv {
	t.Helper()
	ctx := context.Background()
	tag := randSuffix()

	// The fake GitHub IdP: /token mints an access token naming the code, and
	// /user derives the account from it. Same convention as internal/httpapi's
	// own flow tests — the identity provider is faked at the network edge, on
	// purpose, and everything behind the login is real.
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github/token":
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at:" + r.PostFormValue("code"), "token_type": "Bearer", "expires_in": 3600})
		case "/github/user":
			id, login := float64(42), "octocat"
			authHeader := r.Header.Get("Authorization")
			const prefix = "Bearer at:"
			if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
				if code := authHeader[len(prefix):]; code != "" && code != "c" {
					var sum int64
					for _, b := range []byte(code) {
						sum += int64(b)
					}
					id, login = float64(sum), "u-"+code
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "login": login, "name": "Octo"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)

	clients := oauth.NewMemoryClientRegistry()
	cliID := "z01-cli-" + tag
	cli, err := oauth.NewClient(cliID, "Z01 CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"},
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, cli); err != nil {
		t.Fatal(err)
	}

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   fake.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL:     fake.URL + "/github/authorize",
			TokenURL:    fake.URL + "/github/token",
			UserInfoURL: fake.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	accounts := account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: false})
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewMemoryLogger()

	// The login hook is the production shape (cmd/re0auth openOIDC, S02-1/O-8b):
	// the handle is bound to the browser session, the session's real
	// authentication time is recorded on the pending request so the id_token's
	// auth_time is the login and not the consent decision — and a request that
	// asked for a fresh authentication the session cannot prove is sent through
	// the identity provider again instead of to the consent screen.
	//
	// The freshness branch is not optional garnish: a fixture that omitted it
	// measured its own omission (the login hook never re-entered the login
	// plane), which is exactly the false positive this probe set exists to avoid.
	var store *memory.OIDCStore
	login := func(ctx context.Context, id string) string {
		manager.Bind(ctx, "authz", id)
		consent := "/app/consent?id=" + url.QueryEscape(id)
		if at, ok := manager.AuthenticatedAt(ctx); ok {
			ar, err := store.AuthRequestByID(ctx, id)
			if err != nil {
				t.Logf("AuthRequestByID: %v", err)
			} else if fresh, ok := ar.(interface {
				FreshnessNeeded(at, now time.Time) bool
			}); ok && fresh.FreshnessNeeded(at, time.Now()) {
				// Same target cmd/re0auth's login hook builds.
				return "/auth/reauth?return_to=" + url.QueryEscape(consent)
			}
			if err := store.SetAuthTime(ctx, id, at); err != nil {
				t.Logf("SetAuthTime: %v", err)
			}
		}
		return consent
	}
	storeOpts := memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("z01-kid", key),
		Login:    login,
	}
	if logger != nil {
		storeOpts.Audit = logger
	}
	store, err = memory.NewOIDCStore(storeOpts)
	if err != nil {
		t.Fatal(err)
	}

	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("z01probe0123456789abcdef0123456"))
	var scopes []string
	for _, d := range oauth.DefaultDescriptors() {
		scopes = append(scopes, d.Scope.String())
	}
	opHandler, err := oidchttp.New(oidchttp.Config{
		Issuer:        "https://re0auth.test",
		Storage:       store,
		CryptoKey:     cryptoKey,
		CryptoKeyID:   "z01",
		Scopes:        scopes,
		AllowInsecure: true,
		Clients:       clients,
		Registry:      oauth.DefaultRegistry(),
		Consent:       store,
		Sessions:      stackSessionLookup{m: manager},
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := httpapi.New(httpapi.Config{
		Issuer:            "https://re0auth.test",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Authorization:     opHandler,
		Sessions:          manager,
		Accounts:          accounts,
		Auth:              authHandler,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	return &stackEnv{
		server: server, accounts: accounts, store: store, sessions: manager,
		clients: clients, audit: logger, cli: cliID,
	}
}

// newBrowser is a cookie-jarring client that does not follow redirects.
func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// signIn completes a full external-IdP login for this browser.
func (e *stackEnv) signIn(t *testing.T, c *http.Client) {
	t.Helper()
	resp := e.get(t, c, e.server.URL+"/auth/github/start")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login start = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	e.body(t, resp)
	resp = e.get(t, c, e.server.URL+"/auth/github/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login callback = %d: %s", resp.StatusCode, e.body(t, resp))
	}
}

// authorize starts an authorization request from this browser and returns the
// consent handle the redirect carried. It fails when the answer was not a
// consent handle; use authorizeLocation to read the raw redirect (a
// freshness-bound request is answered with /auth/reauth, not a handle).
func (e *stackEnv) authorize(t *testing.T, c *http.Client, scope string, extra url.Values) string {
	t.Helper()
	loc := e.authorizeLocation(t, c, scope, extra)
	handle := loc.Query().Get("id")
	if handle == "" {
		t.Fatalf("no consent handle in %q", loc)
	}
	return handle
}

// authorizeLocation starts an authorization request from this browser and
// returns the raw Location the protocol plane answered with. It asserts nothing
// about the shape of that Location beyond "a redirect", because the two legal
// answers are the consent handle (`?id=…`) and the re-authentication entrance
// (`/auth/reauth?return_to=…`, S02-1).
func (e *stackEnv) authorizeLocation(t *testing.T, c *http.Client, scope string, extra url.Values) *url.URL {
	t.Helper()
	verifier := strings.Repeat("v", 64)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.cli},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {scope},
		"state":                 {"state-z01"},
		"nonce":                 {"nonce-z01"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	resp := e.get(t, c, e.server.URL+"/oauth/authorize?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	e.body(t, resp)
	return loc
}

// consentView fetches the consent screen's data.
func (e *stackEnv) consentView(t *testing.T, c *http.Client, handle string) map[string]any {
	t.Helper()
	resp := e.get(t, c, e.server.URL+"/v1/authorization_requests/"+handle)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("consent view = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	return decodeJSON(t, e.body(t, resp))
}

// decide posts the consent decision. A nil scopes map omits the key.
func (e *stackEnv) decide(t *testing.T, c *http.Client, handle, csrf string, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost,
		e.server.URL+"/v1/authorization_requests/"+handle+"/decision", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return resp, map[string]any{"_raw": string(b)}
	}
	return resp, out
}

// decideDevice posts a device decision, the exact call the device page's
// approve button makes.
func (e *stackEnv) decideDevice(t *testing.T, c *http.Client, csrf string, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost,
		e.server.URL+"/v1/device/decision", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return resp, map[string]any{"_raw": string(b)}
	}
	return resp, out
}

// followCallback completes the OP callback leg the decision redirect points
// at, and returns the authorization code delivered to the client.
func (e *stackEnv) followCallback(t *testing.T, c *http.Client, redirectTo string) (code string) {
	t.Helper()
	if strings.HasPrefix(redirectTo, "/") {
		redirectTo = e.server.URL + redirectTo
	}
	resp := e.get(t, c, redirectTo)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d: %s", resp.StatusCode, e.body(t, resp))
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code = cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", cb)
	}
	return code
}

// deviceAuth starts a device authorization through the protocol plane.
func (e *stackEnv) deviceAuth(t *testing.T, clientID string, scopes []string) (deviceCode, userCode string) {
	t.Helper()
	form := url.Values{"client_id": {clientID}, "scope": {strings.Join(scopes, " ")}}
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/oauth/device_authorization",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization = %d %s", resp.StatusCode, b)
	}
	out := decodeJSON(t, b)
	deviceCode, _ = out["device_code"].(string)
	userCode, _ = out["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_authorization answered %s", b)
	}
	return deviceCode, userCode
}

// exchange swaps the code at the token endpoint (public client, PKCE).
func (e *stackEnv) exchange(t *testing.T, code string) map[string]any {
	t.Helper()
	verifier := strings.Repeat("v", 64)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {e.cli},
		"code":          {code},
		"redirect_uri":  {"https://app.example/cb"},
		"code_verifier": {verifier},
	}.Encode()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/oauth/token", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := decodeJSON(t, b)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange = %d: %s", resp.StatusCode, b)
	}
	return out
}

func (e *stackEnv) get(t *testing.T, c *http.Client, target string) *http.Response {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}

func (e *stackEnv) body(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
