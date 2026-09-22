package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/testoidc"
)

type harness struct {
	server   *httptest.Server
	manager  *Manager
	accounts *account.MemoryStore
	client   *http.Client
	// oidc is the fake OpenID Provider behind the Google login. Tests must echo
	// its nonce, because Google is an OIDC provider and its id_token is verified.
	oidc *testoidc.Server
}

// fakeIDP serves, per provider, a token endpoint and a userinfo endpoint.
func fakeIDP(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		provider, action := parts[0], parts[1]
		switch action {
		case "token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at-" + provider, "token_type": "Bearer", "expires_in": 3600,
			})
		case "user":
			w.Header().Set("Content-Type", "application/json")
			switch provider {
			case "github":
				_ = json.NewEncoder(w).Encode(map[string]any{"id": float64(42), "login": "octocat", "name": "Octo"})
			case "google":
				_ = json.NewEncoder(w).Encode(map[string]any{"sub": "go-777", "name": "Alice", "email": "alice@example.com"})
			case "discord":
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "dc-555", "username": "bob"})
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fake := fakeIDP(t)
	oidc := testoidc.New()
	t.Cleanup(oidc.Close)

	// Google is an OIDC provider: it is served by a fake OpenID Provider that
	// signs a real id_token. GitHub and Discord are not, so they keep the
	// userinfo stub.
	creds := []idp.Credentials{
		{
			Provider: idp.Google, ClientID: "cid-google", ClientSecret: "sec",
			AuthURL:  oidc.URL + "/authorize",
			TokenURL: oidc.URL + "/token",
			Issuer:   oidc.URL,
		},
	}
	for _, p := range []idp.Provider{idp.GitHub, idp.Discord} {
		creds = append(creds, idp.Credentials{
			Provider: p, ClientID: "cid-" + string(p), ClientSecret: "sec",
			AuthURL:     fake.URL + "/" + string(p) + "/authorize",
			TokenURL:    fake.URL + "/" + string(p) + "/token",
			UserInfoURL: fake.URL + "/" + string(p) + "/user",
		})
	}
	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   fake.Client(),
		Credentials:  creds,
	})
	if err != nil {
		t.Fatal(err)
	}

	manager := NewManager(Options{Secure: false})
	accounts := account.NewMemoryStore()
	handler, err := NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	handler.Register(mux)
	mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
		if uid, ok := manager.User(r.Context()); ok {
			_, _ = w.Write([]byte(uid))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /csrf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(manager.CSRFToken(r.Context())))
	})
	mux.HandleFunc("POST /check", func(w http.ResponseWriter, r *http.Request) {
		if manager.ValidCSRF(r) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})

	server := httptest.NewServer(manager.LoadAndSave(mux))
	t.Cleanup(server.Close)

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
	return &harness{server: server, manager: manager, accounts: accounts, client: client, oidc: oidc}
}

func (h *harness) get(t *testing.T, target string) *http.Response {
	t.Helper()
	resp, err := h.client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func stateOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	return paramOf(t, resp, "state")
}

// nonceOf returns the OIDC nonce a provider redirect carries.
func nonceOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	return paramOf(t, resp, "nonce")
}

func paramOf(t *testing.T, resp *http.Response, key string) string {
	t.Helper()
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location %q: %v", loc, err)
	}
	return u.Query().Get(key)
}

// login runs start+callback for a provider and asserts success. For an OIDC
// provider it makes the fake provider echo the nonce the flow sent.
func (h *harness) login(t *testing.T, provider string) {
	t.Helper()
	resp := h.get(t, h.server.URL+"/auth/"+provider+"/start")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d", resp.StatusCode)
	}
	state := stateOf(t, resp)
	if provider == "google" {
		h.oidc.SetNonce(nonceOf(t, resp))
	}
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/"+provider+"/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusSeeOther {
		body := readBody(t, resp)
		t.Fatalf("callback status = %d body = %s", resp.StatusCode, body)
	}
	resp.Body.Close()
}

func TestLoginFlowCreatesAccountAndSession(t *testing.T) {
	h := newHarness(t)

	resp := h.get(t, h.server.URL+"/auth/github/start?return_to=/consent%3Fid%3Dabc")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("code_challenge_method") != "S256" || loc.Query().Get("state") == "" {
		t.Fatalf("authorize URL = %s", loc)
	}
	state := loc.Query().Get("state")
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/github/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/consent?id=abc" {
		t.Fatalf("return_to = %q", got)
	}
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/whoami")
	uid := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(uid, "usr_") {
		t.Fatalf("whoami = %d %q", resp.StatusCode, uid)
	}

	stored, err := h.accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil || string(stored) != uid {
		t.Fatalf("account lookup = %q, %v; whoami = %q", stored, err, uid)
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, h.server.URL+"/auth/github/callback?code=c&state=forged")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestReturnToIsSanitized(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, h.server.URL+"/auth/github/start?return_to=//evil.example")
	state := stateOf(t, resp)
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/github/callback?code=c&state="+state)
	defer resp.Body.Close()
	if got := resp.Header.Get("Location"); got != "/" {
		t.Fatalf("open redirect: Location = %q", got)
	}
}

func TestSecondLoginReusesAccount(t *testing.T) {
	h := newHarness(t)
	h.login(t, "github")
	stored, err := h.accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}

	h.login(t, "github")
	again, err := h.accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil || again != stored {
		t.Fatalf("second login created a new account: %q vs %q", again, stored)
	}
}

func TestLinkAddsIdentityToCurrentUser(t *testing.T) {
	h := newHarness(t)
	h.login(t, "github")
	uid, _ := h.accounts.FindByIdentity(context.Background(), idp.GitHub, "42")

	resp := h.get(t, h.server.URL+"/auth/google/start?mode=link&return_to=/linked")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("link start status = %d", resp.StatusCode)
	}
	state := stateOf(t, resp)
	h.oidc.SetNonce(nonceOf(t, resp))
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/google/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/linked" {
		t.Fatalf("link callback = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	list, err := h.accounts.Identities(context.Background(), uid)
	if err != nil || len(list) != 2 {
		t.Fatalf("identities = %v, %v; want 2", list, err)
	}
}

// I-3 through the HTTP plane: linking an identity owned by another user is
// refused rather than silently merged.
func TestLinkRejectsTakenIdentity(t *testing.T) {
	h := newHarness(t)
	if _, _, err := h.accounts.CreateWithIdentity(context.Background(), idp.Identity{
		Provider: idp.Discord, Subject: "dc-555", DisplayName: "bob",
	}); err != nil {
		t.Fatal(err)
	}
	h.login(t, "github")

	resp := h.get(t, h.server.URL+"/auth/discord/start?mode=link")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d", resp.StatusCode)
	}
	state := stateOf(t, resp)
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/discord/callback?code=c&state="+state)
	defer resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=identity_taken") {
		t.Fatalf("Location = %q, want identity_taken", loc)
	}
}

func TestLinkRequiresSignIn(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, h.server.URL+"/auth/google/start?mode=link")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestCSRFTokenRoundTrip(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, h.server.URL+"/csrf")
	token := readBody(t, resp)
	if token == "" {
		t.Fatal("empty csrf token")
	}

	// A write without the token is refused.
	req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/check", nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without token: status = %d, want 403", resp.StatusCode)
	}

	// With the matching token it succeeds.
	req, _ = http.NewRequest(http.MethodPost, h.server.URL+"/check", nil)
	req.Header.Set("X-CSRF-Token", token)
	resp, err = h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("with token: status = %d, want 204", resp.StatusCode)
	}
}

type rememberedToken struct{ token, subject string }

type fakeIndex struct {
	remembered []rememberedToken
	forgotten  []string
}

func (f *fakeIndex) Remember(_ context.Context, token, subject string) error {
	f.remembered = append(f.remembered, rememberedToken{token: token, subject: subject})
	return nil
}

func (f *fakeIndex) Forget(_ context.Context, token string) error {
	f.forgotten = append(f.forgotten, token)
	return nil
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "r0semi_session" && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	t.Fatal("no live session cookie was set")
	return nil
}

// Signing in records the new token against the account, and signing out forgets
// it. Without this, a kill switch could sign the whole deployment out but never
// one account.
func TestSignInAndSignOutKeepTheSubjectIndex(t *testing.T) {
	index := &fakeIndex{}
	manager := NewManager(Options{Secure: false, Index: index})
	next := func(after func(ctx context.Context)) http.Handler {
		return manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			after(r.Context())
		}))
	}

	rec := httptest.NewRecorder()
	next(func(ctx context.Context) {
		if err := manager.SignIn(ctx, "usr_1"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if len(index.remembered) != 1 || index.remembered[0].subject != "usr_1" {
		t.Fatalf("remembered = %+v", index.remembered)
	}
	signedIn := index.remembered[0].token
	if signedIn == "" {
		t.Fatal("the index recorded an empty token")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie(t, rec))
	rec2 := httptest.NewRecorder()
	next(func(ctx context.Context) {
		if err := manager.SignOut(ctx); err != nil {
			t.Errorf("sign out: %v", err)
		}
	}).ServeHTTP(rec2, req)

	if len(index.forgotten) != 1 || index.forgotten[0] != signedIn {
		t.Fatalf("forgotten = %+v, want the signed-in token", index.forgotten)
	}
}

// A session that cannot be indexed must not be handed out: an operator has to be
// able to reach every session an account holds.
type failingIndex struct{}

func (failingIndex) Remember(context.Context, string, string) error { return errors.New("index down") }
func (failingIndex) Forget(context.Context, string) error           { return nil }

func TestSignInDestroysTheSessionWhenTheIndexFails(t *testing.T) {
	manager := NewManager(Options{Secure: false, Index: failingIndex{}})
	rec := httptest.NewRecorder()
	var signInErr error
	manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signInErr = manager.SignIn(r.Context(), "usr_1")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if signInErr == nil {
		t.Fatal("SignIn succeeded with a failing index")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "r0semi_session" && c.Value != "" && c.MaxAge >= 0 {
			t.Fatal("a live session cookie was written despite the index failure")
		}
	}
}
