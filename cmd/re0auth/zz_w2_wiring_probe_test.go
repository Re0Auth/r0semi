package main

// Production-wiring probes for the three findings whose handler side was already
// implemented but whose composition root was not connected (w2):
//
//   - Z20-2: the raw passthrough's explicit `<game>.raw.read` scope is registered
//     from the configured sources, so the OP can grant it and a client without it
//     is refused with 403 by the data-plane gate.
//   - Z07-9: the account erasure step-up window is resolved from configuration and
//     copied onto the HTTP server, so DELETE /v1/account answers 200 inside the
//     window and 403 reauth_required past it.
//   - S08-7: the graceful-shutdown drain is at least the data plane's own
//     deadline, and the pod's grace period covers the whole sequential stack.
//
// Each probe drives the production function the composition root calls
// (registerRawScopes / applyReauthWindows), not a copy of it, so a wiring change
// that forgets the composition root turns these red.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/lifecycle"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

const (
	w2Issuer   = "https://w2.test"
	w2Redirect = "https://app.example/cb"
	w2ClientID = "cli"
	w2Subject  = "usr_w2"
	w2Game     = "phigros"
	w2Verifier = "verifier-verifier-verifier-verifier-verifier"
)

// ---------------------------------------------------------------------------
// Z20-2: <game>.raw.read registration
// ---------------------------------------------------------------------------

// w2RawEnv is a fully wired stack (real OP + real data plane) built the way the
// composition root builds one, over the catalogue the composition root's own
// registration step produced.
type w2RawEnv struct {
	handler  http.Handler
	store    *memory.OIDCStore
	registry *oauth.Registry
}

// w2OPBackend builds the OP handler and its store around a given catalogue and
// client set. It mirrors openOIDC's essential wiring.
func w2OPBackend(t *testing.T, registry *oauth.Registry, clients oauth.ClientRegistry) (*oidchttp.Handler, *memory.OIDCStore) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: registry,
		Signer:   oidcstore.NewSigner("w2", key),
		Audit:    audit.NewMemoryLogger(),
		Login: func(_ context.Context, id string) string {
			return "/login?authRequestID=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatalf("memory.NewOIDCStore: %v", err)
	}
	var cryptoKey [32]byte
	copy(cryptoKey[:], []byte("w2w2w2w2w2w2w2w2w2w2w2w2w2w2w2w2"))
	handler, err := oidchttp.New(oidchttp.Config{
		Issuer: w2Issuer, Storage: store, CryptoKey: cryptoKey, CryptoKeyID: "w2",
		AllowInsecure: true, Clients: clients, Registry: registry, Consent: store,
	})
	if err != nil {
		t.Fatalf("oidchttp.New: %v", err)
	}
	return handler, store
}

func newW2RawEnv(t *testing.T, clientScopes []oauth.Scope) *w2RawEnv {
	t.Helper()
	ctx := context.Background()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"marker":"w2"}`)
	}))
	t.Cleanup(upstream.Close)

	// One source with a raw_base (so the game offers raw) and no second source, so
	// the catalogue should hold exactly one raw scope.
	sources := []federation.Source{{
		Game: w2Game, Name: "fake", DisplayName: "Fake",
		Issuer: upstream.URL, RawBase: upstream.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []federation.Resource{
			{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"},
		},
	}}
	fedReg, err := federation.NewRegistry(sources...)
	if err != nil {
		t.Fatalf("federation.NewRegistry: %v", err)
	}

	binds := federation.NewMemoryBindingStore()
	wrapper, err := vault.NewLocalKeyWrapper("w2", bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	vaultSvc, err := vault.NewService(vault.NewMemoryRepo(), wrapper, audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := json.Marshal(map[string]string{"access_token": "up-token", "refresh_token": ""})
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range sources {
		b := federation.Binding{
			User: account.UserID(w2Subject), Game: src.Game, Source: src.Name,
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
		Registry: fedReg, Bindings: binds, Vault: vaultSvc,
		Doer: upstream.Client(), HTTPClient: upstream.Client(), BaseURL: w2Issuer,
	})
	if err != nil {
		t.Fatalf("federation.NewService: %v", err)
	}

	// The catalogue the production registration step builds.
	registry := oauth.DefaultRegistry()
	if err := registerRawScopes(registry, sources); err != nil {
		t.Fatalf("registerRawScopes: %v", err)
	}

	clients := oauth.NewMemoryClientRegistry()
	cli, err := oauth.NewClient(w2ClientID, "CLI", oauth.ClientPublic, "", []string{w2Redirect}, clientScopes)
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, cli); err != nil {
		t.Fatal(err)
	}

	op, store := w2OPBackend(t, registry, clients)
	api, err := httpapi.New(httpapi.Config{
		Issuer: w2Issuer, OIDC: op, TokenIntrospector: op,
		GrantStore: store, DeviceStore: store, Federation: fed,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}
	return &w2RawEnv{handler: api.Handler(), store: store, registry: registry}
}

// w2Authorize starts an authorization-code flow. It returns the pending request
// id on acceptance, or the OAuth error code the OP redirected with on refusal;
// exactly one of the two is non-empty.
func w2Authorize(t *testing.T, h http.Handler, scopes ...string) (string, string) {
	t.Helper()
	requested := append(append([]string(nil), scopes...), "offline_access")
	sum := sha256.Sum256([]byte(w2Verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {w2ClientID}, "redirect_uri": {w2Redirect},
		"scope": {strings.Join(requested, " ")}, "state": {"st"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		return "", rec.Body.String()
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if e := loc.Query().Get("error"); e != "" {
		return "", e
	}
	id := loc.Query().Get("authRequestID")
	if id == "" {
		id = loc.Query().Get("id")
	}
	if id == "" {
		t.Fatalf("no authorization request id in %q", loc)
	}
	return id, ""
}

// w2MintToken runs the real authorization-code flow and returns an access token
// carrying exactly the granted scopes.
func w2MintToken(t *testing.T, h http.Handler, store *memory.OIDCStore, scopes ...string) string {
	t.Helper()
	requested := append(append([]string(nil), scopes...), "offline_access")
	id, refused := w2Authorize(t, h, scopes...)
	if id == "" {
		t.Fatalf("authorize with %v was refused: %s", scopes, refused)
	}
	if err := store.CompleteLogin(context.Background(), id, w2Subject, requested); err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize/callback?id="+url.QueryEscape(id), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	cb, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	authCode := cb.Query().Get("code")
	if authCode == "" {
		t.Fatalf("no code in %q", cb)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {w2ClientID},
		"code": {authCode}, "redirect_uri": {w2Redirect}, "code_verifier": {w2Verifier},
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	at, _ := tok["access_token"].(string)
	if at == "" {
		t.Fatalf("no access token in %v", tok)
	}
	return at
}

func w2GetRaw(t *testing.T, h http.Handler, token string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/games/"+w2Game+"/sources/fake/raw/native/scores", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// TestW2RawScopeIsRegisteredPerConfiguredGame is the registration half: the
// catalogue gets `<game>.raw.read` for every game that offers raw and for no
// other game.
func TestW2RawScopeIsRegisteredPerConfiguredGame(t *testing.T) {
	sources := []federation.Source{
		{Game: "phigros", Name: "a", Issuer: "https://a.example", RawBase: "https://a.example/v1", ClientID: "c", ClientSecret: "s"},
		{Game: "arcaea", Name: "b", Issuer: "https://b.example", ClientID: "c", ClientSecret: "s"}, // no raw_base
	}

	// Control: the static catalogue does not carry the scope, so a green result
	// below cannot be the catalogue having had it all along.
	if _, ok := oauth.DefaultRegistry().Get(oauth.Scope(oauth.RawScope("phigros"))); ok {
		t.Fatal("control failed: the default catalogue already carries phigros.raw.read")
	}

	descs := rawScopeDescriptors(sources)
	if len(descs) != 1 || descs[0].Scope.String() != oauth.RawScope("phigros") {
		t.Fatalf("rawScopeDescriptors = %v, want exactly [phigros.raw.read]", descs)
	}

	registry := oauth.DefaultRegistry()
	if err := registerRawScopes(registry, sources); err != nil {
		t.Fatalf("registerRawScopes: %v", err)
	}
	if _, ok := registry.Get(oauth.Scope(oauth.RawScope("phigros"))); !ok {
		t.Fatal("phigros.raw.read was not registered, so no client could ever be granted it")
	}
	if _, ok := registry.Get(oauth.Scope(oauth.RawScope("arcaea"))); ok {
		t.Fatal("arcaea has no raw_base yet got a raw scope: the catalogue advertises a capability no endpoint backs")
	}
	if _, err := registry.Resolve([]oauth.Scope{oauth.Scope(oauth.RawScope("phigros"))}, w2ClientID); err != nil {
		t.Fatalf("the wired catalogue refuses its own raw scope: %v", err)
	}
}

// TestW2RawScopeReachesTheDataPlaneThroughTheProductionCatalogue is the end-to-end
// half: through the OP the composition root builds, a client listed for the raw
// scope obtains a token that the raw route serves (200), and a token that does not
// carry it is refused with 403 before any upstream call.
func TestW2RawScopeReachesTheDataPlaneThroughTheProductionCatalogue(t *testing.T) {
	env := newW2RawEnv(t, []oauth.Scope{
		oauth.ScopeAccountID, oauth.ScopePhigrosProfile, oauth.Scope(oauth.RawScope(w2Game)),
	})

	rawToken := w2MintToken(t, env.handler, env.store, oauth.RawScope(w2Game))
	if status, body := w2GetRaw(t, env.handler, rawToken); status != http.StatusOK {
		t.Fatalf("raw with the granted scope = %d: %v", status, body)
	}

	profileToken := w2MintToken(t, env.handler, env.store, oauth.ScopePhigrosProfile.String())
	status, body := w2GetRaw(t, env.handler, profileToken)
	if status != http.StatusForbidden {
		t.Fatalf("raw with only the profile scope = %d: %v", status, body)
	}
	if body["code"] != "scope_not_granted" || body["required_scope"] != oauth.RawScope(w2Game) {
		t.Fatalf("refusal = %v, want scope_not_granted naming %s", body, oauth.RawScope(w2Game))
	}

	// And the scope is per game, not a blanket grant: a game that is not
	// configured cannot even be asked for through the OP.
	if id, refused := w2Authorize(t, env.handler, oauth.RawScope("arcaea")); id != "" {
		t.Fatalf("the OP accepted an unregistered game's raw scope")
	} else if refused != "invalid_scope" {
		t.Fatalf("unregistered game's raw scope refused with %q, want invalid_scope", refused)
	}
}

// ---------------------------------------------------------------------------
// Z07-9: account erasure step-up window
// ---------------------------------------------------------------------------

// w2Deleter records that an erasure was attempted, so a refused request can be
// shown not to have reached the store.
type w2Deleter struct{ calls int }

func (d *w2Deleter) DeleteAccount(context.Context, account.UserID, account.UserID) (lifecycle.Result, error) {
	d.calls++
	return lifecycle.Result{}, nil
}

type w2AccountEnv struct {
	handler  http.Handler
	cookie   *http.Cookie
	csrf     string
	deleter  *w2Deleter
	accounts *account.MemoryStore
}

func newW2AccountEnv(t *testing.T, window time.Duration) *w2AccountEnv {
	t.Helper()
	ctx := context.Background()

	clients := oauth.NewMemoryClientRegistry()
	cli, err := oauth.NewClient(w2ClientID, "CLI", oauth.ClientPublic, "", []string{w2Redirect},
		[]oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, cli); err != nil {
		t.Fatal(err)
	}
	op, store := w2OPBackend(t, oauth.DefaultRegistry(), clients)

	accounts := account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: false})
	deleter := &w2Deleter{}
	api, err := httpapi.New(httpapi.Config{
		Issuer: w2Issuer, OIDC: op, TokenIntrospector: op,
		GrantStore: store, DeviceStore: store,
		Sessions: manager, Accounts: accounts, Deleter: deleter,
		AccountReauthWindow: window,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}

	// Sign in and read the session's CSRF token, exactly the values a browser
	// would hold after signing in.
	var csrf string
	rec := httptest.NewRecorder()
	manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := manager.SignIn(r.Context(), w2Subject); err != nil {
			t.Errorf("SignIn: %v", err)
		}
		csrf = manager.CSRFToken(r.Context())
		_, _ = io.WriteString(w, "signed in")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("signing in wrote no session cookie")
	}
	if csrf == "" {
		t.Fatal("signing in produced no CSRF token")
	}
	return &w2AccountEnv{handler: api.Handler(), cookie: cookies[0], csrf: csrf, deleter: deleter, accounts: accounts}
}

func (e *w2AccountEnv) deleteAccount(t *testing.T) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/v1/account",
		strings.NewReader(`{"acknowledge":"deletes_my_account"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", e.csrf)
	req.AddCookie(e.cookie)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// w2LoadConfig resolves a config file with the minimum a loadConfig call needs.
func w2LoadConfig(t *testing.T, body string) settings {
	t.Helper()
	cfg, err := w2LoadConfigErr(t, body)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func w2LoadConfigErr(t *testing.T, body string) (settings, error) {
	t.Helper()
	t.Setenv("RE0AUTH_ISSUER", w2Issuer)
	t.Setenv("RE0AUTH_COOKIE_SECURE", "true")
	t.Setenv("RE0AUTH_KEK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("DATABASE_URL", "")
	t.Setenv("RE0AUTH_AUDIT_KEY", "")
	path := filepath.Join(t.TempDir(), "re0auth.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadConfig(path)
}

func TestW2AccountReauthWindowIsWiredFromConfig(t *testing.T) {
	const base = "[server]\nissuer = \"https://w2.test\"\ncookie_secure = true\n"
	t.Setenv("RE0AUTH_ACCOUNT_REAUTH_WINDOW", "")

	// The default is the operator window's magnitude.
	if cfg := w2LoadConfig(t, base); cfg.AccountReauthWindow != defaultAdminReauthWindow {
		t.Fatalf("default account window = %v, want %v", cfg.AccountReauthWindow, defaultAdminReauthWindow)
	}
	// The file sets it...
	if cfg := w2LoadConfig(t, base+"[account]\nreauth_window = \"1h\"\n"); cfg.AccountReauthWindow != time.Hour {
		t.Fatalf("file window = %v, want 1h", cfg.AccountReauthWindow)
	}
	// ...the environment overrides the file (including the disabling 0)...
	t.Setenv("RE0AUTH_ACCOUNT_REAUTH_WINDOW", "0")
	if cfg := w2LoadConfig(t, base+"[account]\nreauth_window = \"1h\"\n"); cfg.AccountReauthWindow != 0 {
		t.Fatalf("env window = %v, want 0 (disabled)", cfg.AccountReauthWindow)
	}
	// ...and a negative value is refused rather than silently disabling the check.
	t.Setenv("RE0AUTH_ACCOUNT_REAUTH_WINDOW", "-1m")
	if _, err := w2LoadConfigErr(t, base); err == nil {
		t.Fatal("a negative account.reauth_window was accepted")
	}
}

// TestW2AccountReauthWindowBehaviourFollowsTheResolvedSetting is the behavioural
// half: the value the production copy step puts on the server config is the value
// the delete route enforces.
func TestW2AccountReauthWindowBehaviourFollowsTheResolvedSetting(t *testing.T) {
	const base = "[server]\nissuer = \"https://w2.test\"\ncookie_secure = true\n"
	t.Setenv("RE0AUTH_ACCOUNT_REAUTH_WINDOW", "")

	t.Run("inside the window the erasure succeeds", func(t *testing.T) {
		cfg := w2LoadConfig(t, base+"[account]\nreauth_window = \"15m\"\n")
		var apiConfig httpapi.Config
		applyReauthWindows(&apiConfig, cfg)
		if apiConfig.AccountReauthWindow != 15*time.Minute {
			t.Fatalf("applyReauthWindows left AccountReauthWindow = %v, want 15m", apiConfig.AccountReauthWindow)
		}
		env := newW2AccountEnv(t, apiConfig.AccountReauthWindow)
		status, body := env.deleteAccount(t)
		if status != http.StatusOK {
			t.Fatalf("delete inside the window = %d: %v", status, body)
		}
		if env.deleter.calls != 1 {
			t.Fatalf("deleter called %d times, want 1", env.deleter.calls)
		}
	})

	t.Run("past the window the erasure is refused and nothing is deleted", func(t *testing.T) {
		cfg := w2LoadConfig(t, base+"[account]\nreauth_window = \"1ns\"\n")
		var apiConfig httpapi.Config
		applyReauthWindows(&apiConfig, cfg)
		env := newW2AccountEnv(t, apiConfig.AccountReauthWindow)
		// The sign-in happened while the environment was being built; a 1ns window
		// has already passed.
		time.Sleep(2 * time.Millisecond)
		status, body := env.deleteAccount(t)
		if status != http.StatusForbidden || body["code"] != "reauth_required" {
			t.Fatalf("delete past the window = %d (%v), want 403 reauth_required", status, body)
		}
		if env.deleter.calls != 0 {
			t.Fatalf("a refused erasure still reached the deleter (%d calls)", env.deleter.calls)
		}
	})
}

// ---------------------------------------------------------------------------
// S08-7: shutdown drain budget
// ---------------------------------------------------------------------------

// TestW2ShutdownDrainOutlastsTheDataPlaneTimeout guards the relation the drain
// exists for: a request the data plane admitted must finish inside the drain, and
// the pod's grace period must cover the whole sequential shutdown stack.
func TestW2ShutdownDrainOutlastsTheDataPlaneTimeout(t *testing.T) {
	if shutdownTimeout < dataPlaneTimeout {
		t.Errorf("shutdownTimeout (%v) is shorter than dataPlaneTimeout (%v): the drain cuts off "+
			"exactly the slow data-plane read the deadline exists to answer with a readable 504 (S08-7)",
			shutdownTimeout, dataPlaneTimeout)
	}

	grace := w2GracePeriod(t)
	auditDrain := w2AuditDrainTimeout(t)
	stack := endpointRemovalWait + shutdownTimeout + auditDrain
	if stack > grace {
		t.Errorf("the sequential shutdown stack (%v + %v + %v = %v) outlasts "+
			"terminationGracePeriodSeconds (%v): the audit drain starts only after the HTTP drain, "+
			"so the pod is SIGKILLed with rows still queued",
			endpointRemovalWait, shutdownTimeout, auditDrain, stack, grace)
	}
}

func w2RepoFile(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

func w2GracePeriod(t *testing.T) time.Duration {
	t.Helper()
	yaml := w2RepoFile(t, filepath.Join("deploy", "k8s", "base", "deployment.yaml"))
	m := regexp.MustCompile(`terminationGracePeriodSeconds:\s*(\d+)`).FindStringSubmatch(yaml)
	if m == nil {
		t.Fatal("terminationGracePeriodSeconds not found in deployment.yaml; the probe is stale")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return time.Duration(n) * time.Second
}

func w2AuditDrainTimeout(t *testing.T) time.Duration {
	t.Helper()
	src := w2RepoFile(t, filepath.Join("internal", "store", "postgres", "auditbatch.go"))
	m := regexp.MustCompile(`auditDrainTimeout\s*=\s*(\d+)\s*\*\s*time\.Second`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("auditDrainTimeout not found in auditbatch.go; the probe is stale")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return time.Duration(n) * time.Second
}

// ---------------------------------------------------------------------------
// The composition root actually calls the seams the probes above exercise
// ---------------------------------------------------------------------------

// w2FuncBody returns the body of a top-level function in a Go file, located with
// the parser so braces inside string literals or comments cannot fool it.
func w2FuncBody(t *testing.T, path, name string) string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(src[start:end])
	}
	t.Fatalf("%s no longer declares %s; this probe would be vacuous", path, name)
	return ""
}

// TestW2CompositionRootInvokesTheWiringSeams is the half the behavioural probes
// cannot see: registerRawScopes and applyReauthWindows are correct, but if the
// composition root never calls them the deployment is unchanged. A probe that only
// calls the helper itself would stay green through exactly that mistake.
func TestW2CompositionRootInvokesTheWiringSeams(t *testing.T) {
	if body := w2FuncBody(t, "main.go", "openOIDC"); !strings.Contains(body, "registerRawScopes(registry, cfg.sources)") {
		t.Error("openOIDC no longer registers the raw scopes from the configured sources: the OP would " +
			"refuse `<game>.raw.read` as unknown and the raw passthrough would answer 403 to every real " +
			"caller (Z20-2)")
	}
	if body := w2FuncBody(t, "main.go", "run"); !strings.Contains(body, "applyReauthWindows(&apiConfig, cfg)") {
		t.Error("run no longer copies the resolved step-up windows onto the HTTP server config: " +
			"DELETE /v1/account would accept a stale cookie (Z07-9)")
	}
}
