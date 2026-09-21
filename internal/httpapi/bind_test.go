package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/federation"
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

// newBindEnv wires the IdP login plane, the OAuth AS, and the federation plane
// against a fake IdP and a fake upstream source.
func newBindEnv(t *testing.T) (string, *http.Client, *account.MemoryStore, *federation.MemoryBindingStore, oauth.Service, vault.Service) {
	t.Helper()
	ctx := context.Background()

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

	upstream := newFakeUpstream(t)

	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

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

	accounts := account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: false})
	authHandler, err := auth.NewHandler(manager, idpRegistry, accounts)
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	apiClient, err := oauth.NewClient("cli", "CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopePhigrosProfile})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(ctx, apiClient); err != nil {
		t.Fatal(err)
	}
	as, err := oauth.NewService(clients, oauth.NewMemoryStore(), audit.NewMemoryLogger(), oauth.Config{
		Issuer: srv.URL, Scopes: oauth.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}

	registry, err := federation.NewRegistry(federation.Source{
		Game: "phigros", Name: "fake", DisplayName: "Fake", Issuer: upstream.URL,
		ClientID: "cid", ClientSecret: "sec", TokenClass: "revocable",
		Resources: []federation.Resource{{Name: "profile", Schema: "re0auth.phigros.profile/1", Scope: "phigros.profile.read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := federation.NewMemoryBindingStore()
	v := newTestVault(t)
	fed, err := federation.NewService(federation.Config{
		Registry: registry, Bindings: bindings, Vault: v, Doer: upstream.Client(), BaseURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	api, err := New(Config{
		Issuer: srv.URL, AS: as,
		Sessions: manager, Accounts: accounts, Auth: authHandler, Federation: fed,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler = api.Handler()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return srv.URL, client, accounts, bindings, as, v
}

// The full bind journey: sign in -> /bind -> upstream authorizes -> callback ->
// the binding exists -> the data plane works.
func TestSourceBindingEndToEnd(t *testing.T) {
	base, client, accounts, bindings, as, v := newBindEnv(t)
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
	at := mintToken(t, as, "cli", string(uid), oauth.ScopePhigrosProfile)
	resp = authedGet(t, base+"/v1/games/phigros/profile", at)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile status = %d", resp.StatusCode)
	}
	if body := decodeResp(t, resp); body["rks"] != 12.34 {
		t.Fatalf("body = %v", body)
	}
}

func TestBindRequiresSignIn(t *testing.T) {
	base, _, _, _, _, _ := newBindEnv(t)
	resp := getURL(t, newBrowser(t), base+"/bind?game=phigros&source=fake")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestBindCallbackRejectsUnknownState(t *testing.T) {
	base, client, _, _, _, _ := newBindEnv(t)
	signIn(t, client, base)

	resp := getURL(t, client, base+"/auth/upstream/phigros/fake/callback?code=x&state=forged")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
