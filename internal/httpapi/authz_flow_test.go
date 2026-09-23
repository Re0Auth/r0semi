package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/oauth"
)

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

// newFlowEnv assembles the whole stack: oauth AS, session/auth plane, and the
// authorization-interaction API, backed by a fake GitHub IdP.
func newFlowEnv(t *testing.T) (base string, accounts *account.MemoryStore) {
	return newFlowEnvWith(t, nil)
}

// newFlowEnvWith is newFlowEnv plus an optional federation service, so tests can
// exercise the binding-aware consent path without every existing test having to
// stand up a data source.
func newFlowEnvWith(t *testing.T, fed federation.Service) (base string, accounts *account.MemoryStore) {
	t.Helper()

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Cleanup(fake.Close)

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "Phi CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID, oauth.ScopePhigrosScore})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   fake.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
			AuthURL: fake.URL + "/github/authorize", TokenURL: fake.URL + "/github/token", UserInfoURL: fake.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	accounts = account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: false})
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}
	opHandler, store := newOPBackend(t, "https://re0auth.test", clients, manager)
	api, err := New(Config{
		Issuer:            "https://re0auth.test",
		OIDC:              opHandler,
		TokenIntrospector: opHandler,
		GrantStore:        store,
		DeviceStore:       store,
		Authorization:     opHandler,
		Sessions:          manager,
		Accounts:          accounts,
		Auth:              authHandler,
		Federation:        fed,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	return server.URL, accounts
}

func doReq(t *testing.T, c *http.Client, req *http.Request) *http.Response {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getURL(t *testing.T, c *http.Client, target string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return doReq(t, c, req)
}

func decodeResp(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return m
}

func signIn(t *testing.T, c *http.Client, base string) {
	t.Helper()
	resp := getURL(t, c, base+"/auth/github/start")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")
	resp.Body.Close()

	resp = getURL(t, c, base+"/auth/github/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func authorize(t *testing.T, c *http.Client, base, verifier, scope, state string) string {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"cli"},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {scope},
		"state":                 {state},
		"code_challenge":        {pkce(verifier)},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp := getURL(t, c, base+"/oauth/authorize?"+q)
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status = %d body = %s", resp.StatusCode, body)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	handle := loc.Query().Get("id")
	if handle == "" {
		t.Fatalf("consent handle not in %q", loc)
	}
	return handle
}

// The full browser round trip: sign in -> authorize -> consent -> decide ->
// exchange the code -> call a scoped resource.
func TestAuthorizationInteractionEndToEnd(t *testing.T) {
	base, accounts := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)

	uid, err := accounts.FindByIdentity(context.Background(), idp.GitHub, "42")
	if err != nil {
		t.Fatal(err)
	}

	const verifier = "verifier-verifier-verifier-verifier-verifier"
	handle := authorize(t, browser, base, verifier, "account.id phigros.score.read", "st-1")

	// Consent screen data.
	resp := getURL(t, browser, base+"/v1/authorization_requests/"+handle)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("consent data status = %d", resp.StatusCode)
	}
	view := decodeResp(t, resp)
	csrf, _ := view["csrf_token"].(string)
	client, _ := view["client"].(map[string]any)
	scopes, _ := view["scopes"].([]any)
	if csrf == "" || client["name"] != "Phi CLI" || len(scopes) != 2 {
		t.Fatalf("consent view = %v", view)
	}

	// Decision.
	decisionBody, _ := json.Marshal(map[string]any{
		"decision": "approve",
		"scopes":   []string{"account.id", "phigros.score.read"},
	})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/authorization_requests/"+handle+"/decision", bytes.NewReader(decisionBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp = doReq(t, browser, req)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("decision status = %d body = %s", resp.StatusCode, body)
	}
	decision := decodeResp(t, resp)
	redirectTo, _ := decision["redirect_to"].(string)
	if redirectTo == "" {
		t.Fatalf("redirect_to = %q", redirectTo)
	}
	// In OP mode redirect_to is the provider callback; following it is what
	// issues the code and redirects to the client.
	if strings.HasPrefix(redirectTo, "/") {
		redirectTo = base + redirectTo
	}
	cbResp := getURL(t, browser, redirectTo)
	if cbResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(cbResp.Body)
		t.Fatalf("callback status = %d body = %s", cbResp.StatusCode, body)
	}
	ru, err := url.Parse(cbResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("callback location: %v", err)
	}
	cbResp.Body.Close()
	code := ru.Query().Get("code")
	if code == "" || ru.Query().Get("state") != "st-1" {
		t.Fatalf("redirect_to = %q", ru)
	}

	// Exchange the code.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cli"},
		"code":          {code},
		"redirect_uri":  {"https://app.example/cb"},
		"code_verifier": {verifier},
	}.Encode()
	req, _ = http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp = doReq(t, browser, req)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token status = %d body = %s", resp.StatusCode, body)
	}
	tok := decodeResp(t, resp)
	accessToken, _ := tok["access_token"].(string)
	if accessToken == "" {
		t.Fatal("no access token issued")
	}

	// Use it.
	req, _ = http.NewRequest(http.MethodGet, base+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp = doReq(t, browser, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d", resp.StatusCode)
	}
	me := decodeResp(t, resp)
	if me["id"] != string(uid) {
		t.Fatalf("me.id = %v, want %v", me["id"], uid)
	}
}

// A handle is bound to the browser that created it.
func TestAuthorizationHandleIsBoundToBrowser(t *testing.T) {
	base, _ := newFlowEnv(t)

	first := newBrowser(t)
	signIn(t, first, base)
	handle := authorize(t, first, base, "verifier-verifier-verifier-verifier", "account.id", "st")

	// A second browser signs in as the same user but never started this request.
	second := newBrowser(t)
	signIn(t, second, base)
	resp := getURL(t, second, base+"/v1/authorization_requests/"+handle)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-browser handle status = %d, want 404", resp.StatusCode)
	}
}

func TestConsentRequiresSignIn(t *testing.T) {
	base, _ := newFlowEnv(t)
	owner := newBrowser(t)
	signIn(t, owner, base)
	handle := authorize(t, owner, base, "verifier-verifier-verifier-verifier", "account.id", "st")

	anon := newBrowser(t)
	resp := getURL(t, anon, base+"/v1/authorization_requests/"+handle)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestDecisionRequiresCSRF(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	signIn(t, browser, base)
	handle := authorize(t, browser, base, "verifier-verifier-verifier-verifier", "account.id", "st")

	body := strings.NewReader(`{"decision":"approve"}`)
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/authorization_requests/"+handle+"/decision", body)
	req.Header.Set("Content-Type", "application/json")
	resp := doReq(t, browser, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// An unknown client is a JSON OAuth error, never a redirect.
func TestAuthorizeUnknownClientUsesOAuthError(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"ghost"},
		"redirect_uri":          {"https://evil.example/cb"},
		"scope":                 {"account.id"},
		"code_challenge":        {pkce("v")},
		"code_challenge_method": {"S256"},
	}.Encode()
	resp := getURL(t, browser, base+"/oauth/authorize?"+q)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body := decodeResp(t, resp)
	if body["error"] == nil || body["type"] != nil {
		t.Fatalf("body = %v", body)
	}
}

// A scope the client may not request is reported back to the client's redirect
// URI, which has already been validated by that point.
func TestAuthorizeBadScopeRedirectsToClient(t *testing.T) {
	base, _ := newFlowEnv(t)
	browser := newBrowser(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"cli"},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {"phigros.b30.read"},
		"state":                 {"st-err"},
		"code_challenge":        {pkce("v")},
		"code_challenge_method": {"S256"},
	}.Encode()
	resp := getURL(t, browser, base+"/oauth/authorize?"+q)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != "app.example" || loc.Query().Get("error") != "invalid_scope" || loc.Query().Get("state") != "st-err" {
		t.Fatalf("redirect = %s", loc)
	}
}
