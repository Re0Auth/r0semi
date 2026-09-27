package httpapi

import (
	"context"
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

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
	"github.com/Re0Auth/r0semi/vault"
)

type challengeStore struct {
	mu sync.Mutex
	m  map[string]string
}

// newFakeUpstream is a minimal OAuth 2.0 source plus one resource, enough to
// drive the binding flow end to end.
func newFakeUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	store := &challengeStore{m: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize":
			q := r.URL.Query()
			code := "code-" + q.Get("state")
			store.mu.Lock()
			store.m[code] = q.Get("code_challenge")
			store.mu.Unlock()

			redirect := q.Get("redirect_uri")
			sep := "?"
			if strings.Contains(redirect, "?") {
				sep = "&"
			}
			http.Redirect(w, r, redirect+sep+"code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)

		case "/oauth/token":
			_ = r.ParseForm()
			store.mu.Lock()
			challenge := store.m[r.PostForm.Get("code")]
			store.mu.Unlock()
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "up-token", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt",
			})

		case "/oauth/revoke":
			// RFC 7009. A real source has this endpoint, so the fake has it too —
			// without it every unbind in these tests would report the source as
			// unreachable and the success path would never be exercised.
			_ = r.ParseForm()
			if r.PostForm.Get("token") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)

		case "/oauth/cascade_revocation":
			// The upstream-session revocation. Same shape as RFC 7009, different
			// effect; the fake only has to prove the call arrives.
			_ = r.ParseForm()
			if r.PostForm.Get("token") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)

		case "/resources/profile":
			if r.Header.Get("Authorization") != "Bearer up-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"game":"phigros","user_id":"x","rks":12.34}`))

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// bindEnvParts is newBindEnv's wiring kept addressable. A test can rebuild the
// HTTP surface against a different federation registry (handlerWithRegistry),
// which is the only way to reach "the binding outlived its source" end to end:
// the session, account and vault stay the ones that produced the binding, and
// only the source entry disappears.
type bindEnvParts struct {
	base     string
	client   *http.Client
	accounts *account.MemoryStore
	bindings *federation.MemoryBindingStore
	store    *memory.OIDCStore
	vault    vault.Service
	upstream *httptest.Server
	manager  *auth.Manager
	auth     *auth.Handler
	op       *oidchttp.Handler
	api      *Server
	handler  http.Handler
}

// newBindEnv wires the IdP login plane, the OpenID Provider, and the federation
// plane against a fake IdP and a fake upstream source. It returns the run
// handler and OP store so a test can mint a token through the real code flow.
func newBindEnv(t *testing.T) (string, *http.Client, *account.MemoryStore, *federation.MemoryBindingStore, http.Handler, *memory.OIDCStore, vault.Service) {
	t.Helper()
	p := newBindEnvParts(t)
	return p.base, p.client, p.accounts, p.bindings, p.handler, p.store, p.vault
}

func newBindEnvParts(t *testing.T) *bindEnvParts {
	t.Helper()

	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
		case "/github/user":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(42), "login": "octocat", "name": "Octo"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idpSrv.Close)

	p := &bindEnvParts{upstream: newFakeUpstream(t)}

	// The server dispatches through p.handler on every request, so a test can swap
	// the surface (see handlerWithRegistry) without a second port, which would
	// break the port-agnostic session cookie.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	p.base = srv.URL

	idpRegistry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: srv.URL,
		HTTPClient:   idpSrv.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL: idpSrv.URL + "/github/authorize", TokenURL: idpSrv.URL + "/github/token", UserInfoURL: idpSrv.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	p.accounts = account.NewMemoryStore()
	p.manager = auth.NewManager(auth.Options{Secure: false})
	p.auth, err = auth.NewHandler(p.manager, idpRegistry, p.accounts)
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	apiClient, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopePhigrosProfile})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), apiClient); err != nil {
		t.Fatal(err)
	}

	p.bindings = federation.NewMemoryBindingStore()
	p.vault = newTestVault(t)
	p.op, p.store = newOPBackend(t, srv.URL, clients, p.manager)

	p.api = p.handlerWithRegistry(t, bindSourceRegistry(t, p.upstream.URL))
	p.handler = p.api.Handler()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	p.client = &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return p
}

// bindSourceRegistry is the deployment's source list, with the fake upstream
// described exactly as a deployment would describe it after reading its discovery
// document.
func bindSourceRegistry(t *testing.T, issuer string) *federation.Registry {
	t.Helper()
	registry, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", DisplayName: "Fake", Issuer: issuer,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		CascadeRevocationEndpoint: issuer + "/oauth/cascade_revocation",
		Resources:                 []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// handlerWithRegistry rebuilds the HTTP surface against a federation service whose
// registry is `registry`, sharing every other store with p — same session, same
// account, same vault. It is how a test removes a source from the configuration
// while the binding it describes stays on disk.
func (p *bindEnvParts) handlerWithRegistry(t *testing.T, registry *federation.Registry) *Server {
	t.Helper()
	fed, err := federation.NewService(federation.Config{
		Registry: registry, Bindings: p.bindings, Vault: p.vault,
		Doer: p.upstream.Client(), BaseURL: p.base,
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(Config{
		Issuer:            p.base,
		OIDC:              p.op,
		TokenIntrospector: p.op,
		GrantStore:        p.store,
		DeviceStore:       p.store,
		Authorization:     p.op,
		Sessions:          p.manager,
		Accounts:          p.accounts,
		Auth:              p.auth,
		Federation:        fed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api
}

// The full bind journey: sign in -> /bind -> upstream authorizes -> callback ->
// the binding exists -> the data plane works.
func TestSourceBindingEndToEnd(t *testing.T) {
	base, client, accounts, bindings, h, store, v := newBindEnv(t)
	signIn(t, client, base)

	uid, err := accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}

	// Start the bind flow.
	resp := getURL(t, client, base+"/bind?game=phigros&source=fake&return_to=/dashboard")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("bind start = %d", resp.StatusCode)
	}
	authorizeURL := resp.Header.Get("Location")
	resp.Body.Close()
	if !strings.Contains(authorizeURL, "/oauth/authorize") {
		t.Fatalf("authorize url = %q", authorizeURL)
	}

	// The upstream authorizes and redirects back to Re0Auth.
	resp = getURL(t, client, authorizeURL)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("upstream authorize = %d", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")
	resp.Body.Close()
	if !strings.Contains(callbackURL, "/auth/upstream/phigros/fake/callback") {
		t.Fatalf("callback = %q", callbackURL)
	}

	// The callback stores the binding and returns the browser.
	resp = getURL(t, client, callbackURL)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Fatalf("return = %q", loc)
	}
	resp.Body.Close()

	stored, err := bindings.Get(context.Background(), uid, "phigros", "fake")
	if err != nil {
		t.Fatal(err)
	}
	// The upstream token lives in the vault, never in the binding store.
	if got := bindingToken(t, v, stored); got != "up-token" {
		t.Fatalf("vault secret = %q", got)
	}

	// The data plane now works.
	at := mintToken(t, h, store, "cli", string(uid), oauth.ScopePhigrosProfile)
	resp = authedGet(t, base+"/v1/games/phigros/profile", at)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile status = %d", resp.StatusCode)
	}
	if body := decodeResp(t, resp); body["rks"] != 12.34 {
		t.Fatalf("body = %v", body)
	}
}

func TestBindRequiresSignIn(t *testing.T) {
	base, _, _, _, _, _, _ := newBindEnv(t)
	resp := getURL(t, newBrowser(t), base+"/bind?game=phigros&source=fake")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestBindCallbackRejectsUnknownState(t *testing.T) {
	base, client, _, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)

	resp := getURL(t, client, base+"/auth/upstream/phigros/fake/callback?code=x&state=forged")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// The HTTP half of the orphaned-binding fix. A binding can outlive its source's
// entry in the configuration; GET /v1/bindings reports that with configured:false
// and promises it can still be disconnected. Before the fix the endpoint answered
// 404 (ErrUnknownSource was returned before the binding was ever read), so the
// upstream token and its vault secret could only be cleared by an operator.
func TestUnbindOrphanedBindingEndToEnd(t *testing.T) {
	p := newBindEnvParts(t)
	signIn(t, p.client, p.base)
	ctx := context.Background()

	uid, err := p.accounts.FindByIdentity(ctx, idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}

	// Bind through the shipped flow, so the row and its secret are the ones the
	// real code produces.
	resp := getURL(t, p.client, p.base+"/bind?game=phigros&source=fake&return_to=/dashboard")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("bind start = %d", resp.StatusCode)
	}
	authorizeURL := resp.Header.Get("Location")
	resp.Body.Close()
	resp = getURL(t, p.client, authorizeURL)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("upstream authorize = %d", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")
	resp.Body.Close()
	resp = getURL(t, p.client, callbackURL)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d", resp.StatusCode)
	}
	resp.Body.Close()

	binding, err := p.bindings.Get(ctx, uid, "phigros", "fake")
	if err != nil {
		t.Fatalf("the binding was not stored: %v", err)
	}

	// Reconfigure without the source. The row and the vault secret stay; only the
	// description of the source is gone.
	other, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "other", DisplayName: "Other", Issuer: p.upstream.URL,
		TokenClass: "revocable",
		Resources:  []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.api = p.handlerWithRegistry(t, other)
	p.handler = p.api.Handler()

	csrf, _ := decodeResp(t, getURL(t, p.client, p.base+"/v1/sessions/current"))["csrf_token"].(string)
	if csrf == "" {
		t.Fatal("no CSRF token on the session view")
	}
	req, err := http.NewRequest(http.MethodDelete, p.base+"/v1/bindings/phigros/fake", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	resp = doReq(t, p.client, req)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("DELETE an orphaned binding = %d, want 200: %s", resp.StatusCode, body)
	}
	if body := decodeResp(t, resp); body["upstream"] != "nothing" {
		t.Fatalf("upstream = %v, want nothing (there is no source left to ask)", body["upstream"])
	}

	if _, err := p.bindings.Get(ctx, uid, "phigros", "fake"); err == nil {
		t.Error("the orphaned binding row survived")
	}
	if exists, _ := p.vault.Exists(ctx, federation.BindingIdentity(binding)); exists {
		t.Error("the orphaned binding secret survived")
	}
}
