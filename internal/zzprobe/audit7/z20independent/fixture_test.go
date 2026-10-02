//go:build audit7

// Z20-INDEPENDENT fixture: one self-contained, fully wired stack.
//
// Nothing here is shared with internal/zzprobe/audit7/z20authzisolationmatrix
// (the zone-20 agent's own fixture): a cross-check that reuses the author's
// helper cannot catch a bug in that helper. Every piece is built from exported
// surfaces, so a probe observes what cmd/re0auth wires, not a private helper.
package zzprobe_z20independent

import (
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
	"github.com/Re0Auth/r0semi/internal/admin"
	"github.com/Re0Auth/r0semi/internal/auth"
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
	zGame     = "phigros"
	zSource   = "fake"
	zSourceB  = "beta"

	zClientPublic = "cli"
	zClientOther  = "cli2"
	zClientConf   = "conf"
	zConfSecret   = "conf-secret-6b1c9a"

	zVictim = "usr_victim"
	zOther  = "usr_other"

	// The upstream credentials are distinctive so a probe can search a response
	// body for them; they must never surface on the public source listing.
	zUpToken        = "up-token-4e2a"
	zUpClientID     = "zA-upstream-client-7d"
	zUpClientSecret = "zA-upstream-secret-9f3"
	zScoresMarker   = "Z20I-SCORES"
	zProfileMarker  = "Z20I-PROFILE"
	// zNativeMarker marks the source's own API, which lives outside the
	// normalized /resources/{name} namespace when raw_base is a sub-path.
	zNativeMarker    = "Z20I-NATIVE"
	zUpstreamTimeout = 5 * time.Second
)

// zAUpstream is the configured data source's native API. It records every call
// so a probe can tell "the gate refused" from "the data plane never tried".
type zAUpstream struct {
	mu    sync.Mutex
	paths []string
	authz []string
}

func (u *zAUpstream) record(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.paths = append(u.paths, r.URL.Path)
	u.authz = append(u.authz, r.Header.Get("Authorization"))
}

func (u *zAUpstream) calls() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.paths...)
}

func (u *zAUpstream) hit(path string) bool {
	for _, p := range u.calls() {
		if p == path {
			return true
		}
	}
	return false
}

// zAOpts tunes a stack. The zero value is the canonical single-source deployment.
type zAOpts struct {
	// Registry replaces the scope catalogue (for ExplicitConsent probes).
	Registry *oauth.Registry
	// ClientScopes overrides what zClientPublic is registered for.
	ClientScopes []oauth.Scope
	// TwoSources adds `beta`, which declares the SAME resource name `scores`
	// with a DIFFERENT scope, so the "gate computed from the source that serves"
	// question can be asked directly.
	TwoSources bool
	// IntrospectionClients is the deployment's resource-server allowlist.
	IntrospectionClients []string
	// BindFor names the subjects that get a binding. Default: zVictim only.
	BindFor []string
	// RawBaseSuffix is appended to the source's issuer to form raw_base. Empty
	// means raw_base == issuer (the raw path and the normalized path address the
	// same upstream URL). "/v1" mirrors the shape
	// config/re0auth.example.toml:363 ships, where the native API is a sub-path
	// and the two surfaces do NOT overlap.
	RawBaseSuffix string
}

// zAStack is the process-wide half of the fixture: stores, clients, the OP and
// the data plane. Several HTTP servers can be built over one stack, which is
// what lets the admin-allowlist probe vary ONLY the allowlist.
type zAStack struct {
	t          *testing.T
	audit      *audit.MemoryLogger
	up         *zAUpstream
	clients    *oauth.MemoryClientRegistry
	accounts   *account.MemoryStore
	sessions   *auth.Manager
	store      *memory.OIDCStore
	op         *oidchttp.Handler
	fed        federation.Service
	bindings   *federation.MemoryBindingStore
	registry   *oauth.Registry
	authHandle *auth.Handler
}

// zAEnv is one mounted HTTP surface over a stack.
type zAEnv struct {
	*zAStack
	srv     *httptest.Server
	handler http.Handler
}

// zARevoker is the token half of the operator plane. The probes here only ever
// read /v1/admin/clients, so a no-op implementation is honest and keeps the
// fixture free of a second token engine.
type zARevoker struct{}

func (zARevoker) RevokeTokens(context.Context, oauth.TokenFilter) (int, error) { return 0, nil }

func newZAStack(t *testing.T, opts zAOpts) *zAStack {
	t.Helper()
	ctx := context.Background()

	auditLog := audit.NewMemoryLogger()
	up := &zAUpstream{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.record(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/resources/scores":
			_, _ = io.WriteString(w, `{"marker":"`+zScoresMarker+`","data":[]}`)
		case r.URL.Path == "/resources/profile":
			_, _ = io.WriteString(w, `{"marker":"`+zProfileMarker+`","rks":12.34}`)
		default:
			// The source's NATIVE api, a different surface from the normalized
			// /resources/{name} namespace the proxy exposes.
			_, _ = io.WriteString(w, `{"marker":"`+zNativeMarker+`","path":"`+r.URL.Path+`"}`)
		}
	}))
	t.Cleanup(upstream.Close)

	rawBase := upstream.URL + opts.RawBaseSuffix
	sources := []federation.Source{{
		Game: zGame, Name: zSource, DisplayName: "Fake",
		Issuer: upstream.URL, RawBase: rawBase,
		ClientID: zUpClientID, ClientSecret: zUpClientSecret, TokenClass: "revocable",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
			{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.score.read"},
		},
	}}
	if opts.TwoSources {
		sources = append(sources, federation.Source{
			Game: zGame, Name: zSourceB, DisplayName: "Beta",
			Issuer: upstream.URL, RawBase: rawBase,
			ClientID: zUpClientID, ClientSecret: zUpClientSecret, TokenClass: "revocable",
			Resources: []federation.Resource{
				// The same resource name, a DIFFERENT scope: which source serves
				// `scores` is decided by candidates(), not by config order.
				{Name: "scores", Schema: "re0auth.phigros.scores/1", Scope: "phigros.b30.read"},
			},
		})
	}
	reg, err := federation.NewRegistry(sources...)
	if err != nil {
		t.Fatalf("federation.NewRegistry: %v", err)
	}

	bindSubjects := opts.BindFor
	if len(bindSubjects) == 0 {
		bindSubjects = []string{zVictim}
	}
	binds := federation.NewMemoryBindingStore()
	wrapper, err := vault.NewLocalKeyWrapper("z20i", make([]byte, 32))
	if err != nil {
		t.Fatalf("vault.NewLocalKeyWrapper: %v", err)
	}
	vaultSvc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, auditLog)
	if err != nil {
		t.Fatalf("vault.NewService: %v", err)
	}
	enroll := func(user, source string) {
		b := federation.Binding{
			User: account.UserID(user), Game: zGame, Source: source,
			TokenType: "Bearer", HasRefresh: true, Version: 7,
			Expiry: time.Now().Add(time.Hour),
		}
		if err := binds.Put(ctx, b); err != nil {
			t.Fatalf("bindings.Put: %v", err)
		}
		secret, err := json.Marshal(map[string]string{"access_token": zUpToken})
		if err != nil {
			t.Fatal(err)
		}
		if err := vaultSvc.Enroll(ctx, federation.BindingIdentity(b), secret, nil); err != nil {
			t.Fatalf("vault.Enroll: %v", err)
		}
	}
	for _, user := range bindSubjects {
		enroll(user, zSource)
		if opts.TwoSources {
			enroll(user, zSourceB)
		}
	}

	fed, err := federation.NewService(federation.Config{
		Registry: reg, Bindings: binds, Vault: vaultSvc,
		Doer: upstream.Client(), HTTPClient: upstream.Client(), BaseURL: zIssuer,
	})
	if err != nil {
		t.Fatalf("federation.NewService: %v", err)
	}

	clientScopes := opts.ClientScopes
	if clientScopes == nil {
		clientScopes = []oauth.Scope{
			oauth.ScopeAccountID, oauth.ScopePhigrosProfile, oauth.ScopePhigrosScore,
			oauth.Scope(oauth.RawScope(zGame)),
		}
	}
	clients := oauth.NewMemoryClientRegistry()
	mk := func(id, name string, typ oauth.ClientType, secret string, scopes []oauth.Scope) {
		c, err := oauth.NewClient(id, name, typ, secret, []string{zRedirect}, scopes)
		if err != nil {
			t.Fatalf("oauth.NewClient(%s): %v", id, err)
		}
		if err := clients.Create(ctx, c); err != nil {
			t.Fatalf("clients.Create(%s): %v", id, err)
		}
	}
	mk(zClientPublic, "Phi CLI", oauth.ClientPublic, "", clientScopes)
	mk(zClientOther, "Other", oauth.ClientPublic, "", []oauth.Scope{oauth.ScopeAccountID})
	mk(zClientConf, "Confidential", oauth.ClientConfidential, zConfSecret,
		[]oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})

	// A fake GitHub whose subject is derived from the authorization code, so a
	// test can put two different accounts into one browser.
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github/token":
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at:" + r.PostFormValue("code"), "token_type": "Bearer", "expires_in": 3600})
		case "/github/user":
			id, login := float64(1042), "octocat"
			auth := r.Header.Get("Authorization")
			const prefix = "Bearer at:"
			if strings.HasPrefix(auth, prefix) {
				if code := strings.TrimPrefix(auth, prefix); code != "" && code != "c" {
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

	idpRegistry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: zIssuer,
		HTTPClient:   fake.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL: fake.URL + "/github/authorize", TokenURL: fake.URL + "/github/token",
			UserInfoURL: fake.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatalf("idp.NewRegistry: %v", err)
	}

	accounts := account.NewMemoryStore()
	sessions := auth.NewManager(auth.Options{Secure: false})
	authHandle, err := auth.NewHandler(sessions, idpRegistry, accounts)
	if err != nil {
		t.Fatalf("auth.NewHandler: %v", err)
	}

	scopeRegistry := opts.Registry
	if scopeRegistry == nil {
		scopeRegistry = zRegistryWithRaw(t)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: scopeRegistry,
		Signer:   oidcstore.NewSigner("z20i", key),
		Audit:    auditLog,
		Login: func(ctx context.Context, id string) string {
			// Exactly what cmd/re0auth does: bind the handle to the browser.
			sessions.Bind(ctx, "authz", id)
			return "/app/consent?id=" + url.QueryEscape(id)
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
		CryptoKeyID:          "z20i",
		AllowInsecure:        true,
		Clients:              clients,
		Registry:             scopeRegistry,
		Consent:              store,
		IntrospectionClients: opts.IntrospectionClients,
	})
	if err != nil {
		t.Fatalf("oidchttp.New: %v", err)
	}

	return &zAStack{
		t: t, audit: auditLog, up: up, clients: clients, accounts: accounts,
		sessions: sessions, store: store, op: opHandler, fed: fed, bindings: binds,
		registry: scopeRegistry, authHandle: authHandle,
	}
}

// serve mounts a server over the stack. Admin is mounted only when admins is
// non-empty, exactly as httpapi.New requires.
func (s *zAStack) serve(admins []account.UserID) *zAEnv {
	s.t.Helper()
	cfg := httpapi.Config{
		Issuer:            zIssuer,
		OIDC:              s.op,
		TokenIntrospector: s.op,
		GrantStore:        s.store,
		DeviceStore:       s.store,
		Authorization:     s.op,
		Sessions:          s.sessions,
		Accounts:          s.accounts,
		Auth:              s.authHandle,
		Federation:        s.fed,
	}
	if len(admins) > 0 {
		svc, err := admin.New(admin.Config{Clients: s.clients, Tokens: zARevoker{}, Audit: s.audit})
		if err != nil {
			s.t.Fatalf("admin.New: %v", err)
		}
		cfg.Admin = svc
		cfg.Admins = admins
	}
	api, err := httpapi.New(cfg)
	if err != nil {
		s.t.Fatalf("httpapi.New: %v", err)
	}
	h := api.Handler()
	srv := httptest.NewServer(h)
	s.t.Cleanup(srv.Close)
	return &zAEnv{zAStack: s, srv: srv, handler: h}
}

// newZAEnv is the common case: one stack, one server, no operator plane.
func newZAEnv(t *testing.T, opts zAOpts) *zAEnv {
	t.Helper()
	return newZAStack(t, opts).serve(nil)
}

// zRegistryWithRaw is the default catalogue plus the raw-passthrough scope this
// fixture's sources advertise.
//
// The composition root registers one `<game>.raw.read` per configured game with a
// raw_base (cmd/re0auth/main.go rawScopeDescriptors), and every source here has
// one, so a cross-check that mints a raw token needs the same descriptor. Without
// it the OP refuses the scope at authorize time and the probe could never express
// "raw is allowed" (Z20-2).
func zRegistryWithRaw(t *testing.T) *oauth.Registry {
	t.Helper()
	reg, err := oauth.NewRegistry(append(oauth.DefaultDescriptors(), oauth.Descriptor{
		Scope: oauth.Scope(oauth.RawScope(zGame)), Title: "读取 " + zGame + " 原生接口",
		Description: "probe descriptor: the explicit scope the raw passthrough requires",
		Risk:        oauth.RiskHigh,
	})...)
	if err != nil {
		t.Fatalf("oauth.NewRegistry: %v", err)
	}
	return reg
}

// zBrowser returns a client with a cookie jar that does NOT follow redirects, so
// every leg of a flow is observable.
func zBrowser(t *testing.T) *http.Client {
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

// zCarryCookies copies one browser's cookies onto another env's origin. Two
// httptest servers on 127.0.0.1 differ only by port, and Go's cookiejar keys on
// host, but copying makes the intent explicit rather than relying on that.
func zCarryCookies(t *testing.T, b *http.Client, from, to string) {
	t.Helper()
	uFrom, err := url.Parse(from)
	if err != nil {
		t.Fatal(err)
	}
	uTo, err := url.Parse(to)
	if err != nil {
		t.Fatal(err)
	}
	b.Jar.SetCookies(uTo, b.Jar.Cookies(uFrom))
}

func zPKCE(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const zVerifier = "verifier-verifier-verifier-verifier-verifier"

// zDo runs a request, refusing to follow redirects.
func (e *zAEnv) zDo(b *http.Client, req *http.Request) *http.Response {
	e.t.Helper()
	if b == nil {
		b = e.srv.Client()
	}
	resp, err := b.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	return resp
}

// zGet performs a bearer-authenticated GET against the mounted server.
func (e *zAEnv) zGet(path, token string) (int, http.Header, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp := e.zDo(nil, req)
	return zDrain(e.t, resp)
}

// zGetBrowser performs a session-carrying GET.
func (e *zAEnv) zGetBrowser(b *http.Client, path string) (int, http.Header, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp := e.zDo(b, req)
	return zDrain(e.t, resp)
}

// zPostForm posts a form with an explicit raw Authorization header, so a probe
// can put Basic userinfo bytes on the wire that SetBasicAuth cannot produce.
func (e *zAEnv) zPostForm(path string, form url.Values, rawAuth string) (int, []byte) {
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

// zPostJSON posts a JSON body with the session's CSRF token.
func (e *zAEnv) zPostJSON(b *http.Client, path string, body map[string]any, csrf string) (int, []byte) {
	e.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(string(raw)))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp := e.zDo(b, req)
	_, _, out := zDrain(e.t, resp)
	return resp.StatusCode, out
}

func zDrain(t *testing.T, resp *http.Response) (int, http.Header, []byte) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, body
}

func zBasicHeader(rawUser, rawPassword string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(rawUser+":"+rawPassword))
}

func zJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return m
}

// zSignInAs drives the real login plane with an authorization code the fake IdP
// turns into a subject.
func (e *zAEnv) zSignInAs(b *http.Client, code string) string {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/auth/github/start", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp := e.zDo(b, req)
	loc := resp.Header.Get("Location")
	_, _, _ = zDrain(e.t, resp)
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("login start = %d", resp.StatusCode)
	}
	u, err := url.Parse(loc)
	if err != nil {
		e.t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		e.t.Fatalf("no state in %q", loc)
	}
	req, err = http.NewRequest(http.MethodGet,
		e.srv.URL+"/auth/github/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp = e.zDo(b, req)
	_, _, _ = zDrain(e.t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("login callback = %d", resp.StatusCode)
	}
	return state
}

// zCurrentSessionID returns the signed-in account id.
func (e *zAEnv) zCurrentSessionID(b *http.Client) string {
	e.t.Helper()
	status, _, body := e.zGetBrowser(b, "/v1/sessions/current")
	if status != http.StatusOK {
		e.t.Fatalf("/v1/sessions/current = %d: %s", status, body)
	}
	id, _ := zJSON(e.t, body)["user_id"].(string)
	if id == "" {
		e.t.Fatalf("no user_id in %s", body)
	}
	return id
}

// zAuthorize starts the authorize leg and returns the consent handle.
func (e *zAEnv) zAuthorize(b *http.Client, clientID, scope, state string) (id string, status int, body []byte) {
	e.t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {zRedirect},
		"scope":                 {scope},
		"state":                 {state},
		"code_challenge":        {zPKCE(zVerifier)},
		"code_challenge_method": {"S256"},
	}.Encode()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/oauth/authorize?"+q, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp := e.zDo(b, req)
	loc := resp.Header.Get("Location")
	code, _, out := zDrain(e.t, resp)
	if code != http.StatusFound {
		return "", code, out
	}
	u, err := url.Parse(loc)
	if err != nil {
		e.t.Fatal(err)
	}
	handle := u.Query().Get("id")
	if handle == "" {
		handle = u.Query().Get("authRequestID")
	}
	return handle, code, []byte(loc)
}

// zExchange swaps an authorization code for tokens at the real token endpoint.
func (e *zAEnv) zExchange(clientID, secret, code string) (int, map[string]any, []byte) {
	e.t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {zRedirect},
		"code_verifier": {zVerifier},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	status, body := e.zPostForm("/oauth/token", form, "")
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return status, m, body
}

// zConsentCode drives the WHOLE interactive path: sign in, authorize, read the
// consent view, decide, follow the callback, exchange the code. It is the entry
// point the browser actually uses, so a probe here is not testing a helper.
func (e *zAEnv) zConsentCode(b *http.Client, clientID, scope string, approved []string) (code string, decisionStatus int, decisionBody []byte) {
	e.t.Helper()
	handle, status, body := e.zAuthorize(b, clientID, scope, "st-z20i")
	if status != http.StatusFound || handle == "" {
		e.t.Fatalf("authorize = %d %s", status, body)
	}
	viewStatus, _, viewBody := e.zGetBrowser(b, "/v1/authorization_requests/"+url.PathEscape(handle))
	if viewStatus != http.StatusOK {
		e.t.Fatalf("consent view = %d %s", viewStatus, viewBody)
	}
	csrf, _ := zJSON(e.t, viewBody)["csrf_token"].(string)
	decision := map[string]any{"decision": "approve"}
	if approved != nil {
		decision["scopes"] = approved
	}
	ds, db := e.zPostJSON(b, "/v1/authorization_requests/"+url.PathEscape(handle)+"/decision", decision, csrf)
	if ds != http.StatusOK {
		return "", ds, db
	}
	redirect, _ := zJSON(e.t, db)["redirect_to"].(string)
	if redirect == "" {
		e.t.Fatalf("no redirect_to in %s", db)
	}
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+redirect, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp := e.zDo(b, req)
	loc := resp.Header.Get("Location")
	_, _, cbBody := zDrain(e.t, resp)
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("callback = %d %s", resp.StatusCode, cbBody)
	}
	u, err := url.Parse(loc)
	if err != nil {
		e.t.Fatal(err)
	}
	got := u.Query().Get("code")
	if got == "" {
		e.t.Fatalf("no code in %q", loc)
	}
	return got, ds, db
}

// zMintToken issues an access token for an arbitrary subject by completing the
// authorization request directly, the way httpapi's consent decision does. It is
// the shortcut for probes that are not about the consent UI.
func (e *zAEnv) zMintToken(clientID, subject string, scopes ...string) string {
	e.t.Helper()
	return e.zMintTokens(clientID, subject, scopes...).AccessToken()
}

type zATokens map[string]any

func (t zATokens) AccessToken() string {
	s, _ := t["access_token"].(string)
	return s
}

func (e *zAEnv) zMintTokens(clientID, subject string, scopes ...string) zATokens {
	e.t.Helper()
	requested := append(append([]string(nil), scopes...), "offline_access")
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {zRedirect},
		"scope":                 {strings.Join(requested, " ")},
		"state":                 {"st-z20i-mint"},
		"code_challenge":        {zPKCE(zVerifier)},
		"code_challenge_method": {"S256"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q, nil)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		e.t.Fatalf("mint authorize = %d: %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	id := u.Query().Get("id")
	if id == "" {
		id = u.Query().Get("authRequestID")
	}
	if id == "" {
		e.t.Fatalf("no handle in %q", rec.Header().Get("Location"))
	}
	if err := e.store.CompleteLogin(context.Background(), id, subject, requested); err != nil {
		e.t.Fatalf("CompleteLogin: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil)
	rec = httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		e.t.Fatalf("mint callback = %d: %s", rec.Code, rec.Body.String())
	}
	cb, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		e.t.Fatalf("no code in %q", cb)
	}
	status, tok, body := e.zExchange(clientID, "", code)
	if status != http.StatusOK {
		e.t.Fatalf("mint token = %d: %s", status, body)
	}
	return zATokens(tok)
}

// zEvents returns the audit sink's events with the given action.
func (e *zAEnv) zEvents(action string) []audit.Event {
	e.t.Helper()
	var out []audit.Event
	for _, ev := range e.audit.Events() {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}
