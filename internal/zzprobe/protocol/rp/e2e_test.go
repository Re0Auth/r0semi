//go:build audit5

package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/auth"
	"github.com/Re0Auth/r0semi/internal/httpapi"
	"github.com/Re0Auth/r0semi/internal/oidchttp"
	"github.com/Re0Auth/r0semi/internal/oidcstore"
	"github.com/Re0Auth/r0semi/internal/store/memory"
	"github.com/Re0Auth/r0semi/oauth"
)

// rpEnv is the whole browser-facing stack with a fake GitHub in the IdP slot:
// /auth/{provider}/start and /auth/{provider}/callback are the real routes, so
// the state/nonce/verifier plumbing under test is the shipped one.
type rpEnv struct {
	base     string
	accounts *account.MemoryStore
}

func newRPEnv(t *testing.T) *rpEnv {
	t.Helper()
	env, _ := newRPEnvWithStore(t, nil)
	return env
}

// newRPEnvWithStore is newRPEnv with the session store handed back, so a probe
// can read what a browser's session actually kept.
func newRPEnvWithStore(t *testing.T, sessions scs.Store) (*rpEnv, scs.Store) {
	t.Helper()
	if sessions == nil {
		sessions = memstore.New()
	}
	// The fake IdP: the authorization code is the channel a test uses to choose
	// which subject the provider reports.
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/idp/token":
			_ = r.ParseForm()
			writeJSON(w, map[string]any{
				"access_token": "at:" + r.PostFormValue("code"), "token_type": "Bearer", "expires_in": 3600,
			})
		case "/idp/user":
			code := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer at:")
			id, login := 42, "octocat"
			if code != "" && code != "c" {
				var sum int64
				for _, b := range []byte(code) {
					sum += int64(b)
				}
				id, login = int(sum), "u-"+code
			}
			writeJSON(w, map[string]any{"id": id, "login": login, "name": "Octo"})
		case "/idp2/token":
			_ = r.ParseForm()
			writeJSON(w, map[string]any{
				"access_token": "at:" + r.PostFormValue("code"), "token_type": "Bearer", "expires_in": 3600,
			})
		case "/idp2/user":
			writeJSON(w, map[string]any{"id": "discord-1", "username": "second-provider"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)

	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   fake.Client(),
		Credentials: []idp.Credentials{
			{
				Provider: idp.GitHub, ClientID: "cid", ClientSecret: "sec",
				AuthURL: fake.URL + "/idp/authorize", TokenURL: fake.URL + "/idp/token", UserInfoURL: fake.URL + "/idp/user",
			},
			{
				Provider: idp.Discord, ClientID: "cid2", ClientSecret: "sec2",
				AuthURL: fake.URL + "/idp2/authorize", TokenURL: fake.URL + "/idp2/token", UserInfoURL: fake.URL + "/idp2/user",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	accounts := account.NewMemoryStore()
	manager := auth.NewManager(auth.Options{Secure: false, Store: sessions})
	authHandler, err := auth.NewHandler(manager, registry, accounts)
	if err != nil {
		t.Fatal(err)
	}

	clients := oauth.NewMemoryClientRegistry()
	client, err := oauth.NewClient("cli", "Phi CLI", oauth.ClientPublic, "",
		[]string{"https://app.example/cb"}, []oauth.Scope{oauth.ScopeAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(context.Background(), client); err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewOIDCStore(memory.OIDCOptions{
		Clients:  clients,
		Registry: oauth.DefaultRegistry(),
		Signer:   oidcstore.NewSigner("test", key),
		Login: func(ctx context.Context, id string) string {
			manager.Bind(ctx, "authz", id)
			return "/app/consent?id=" + url.QueryEscape(id)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	opHandler, err := oidchttp.New(oidchttp.Config{
		Issuer: "https://re0auth.test", Storage: store, CryptoKey: rpCryptoKey(), CryptoKeyID: "test",
		AllowInsecure: true, Clients: clients, Registry: oauth.DefaultRegistry(), Consent: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := httpapi.New(httpapi.Config{
		Issuer: "https://re0auth.test", OIDC: opHandler, TokenIntrospector: opHandler,
		GrantStore: store, DeviceStore: store, Authorization: opHandler,
		Sessions: manager, Accounts: accounts, Auth: authHandler,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &rpEnv{base: srv.URL, accounts: accounts}, sessions
}

func rpCryptoKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("0123456789abcdef0123456789abcdef"))
	return k
}

func rpBrowser(t *testing.T) *http.Client {
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

func rpGet(t *testing.T, c *http.Client, target string) *http.Response {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// rpStart asks the IdP plane for an authorization URL and returns its state.
func rpStart(t *testing.T, c *http.Client, base, provider, query string) (state string, status int) {
	t.Helper()
	target := base + "/auth/" + provider + "/start"
	if query != "" {
		target += "?" + query
	}
	resp := rpGet(t, c, target)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		return "", resp.StatusCode
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("state"), resp.StatusCode
}

// rpCallback drives the real callback route and returns status, Location and body.
func rpCallback(t *testing.T, c *http.Client, base, provider, query string) (int, string, string) {
	t.Helper()
	resp := rpGet(t, c, base+"/auth/"+provider+"/callback?"+query)
	defer func() { _ = resp.Body.Close() }()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	return resp.StatusCode, resp.Header.Get("Location"), string(body[:n])
}

// rpSignedIn reports the session's user id, or "" when there is none.
func rpSignedIn(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	resp := rpGet(t, c, base+"/v1/sessions/current")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	id, _ := body["user_id"].(string)
	return id
}

func rpIdentityProviders(t *testing.T, c *http.Client, base string) []string {
	t.Helper()
	resp := rpGet(t, c, base+"/v1/identities")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body struct {
		Data []struct {
			Provider string `json:"provider"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(body.Data))
	for _, d := range body.Data {
		out = append(out, d.Provider)
	}
	return out
}

// The login CSRF / fixation direction that has to keep working: an attacker who
// starts the flow in their own browser cannot make a victim's browser complete
// it. The state is stored server-side in the session, so a callback carrying the
// attacker's state is not the victim's flow.
func TestRPLoginStateFromAnotherBrowserIsRefused(t *testing.T) {
	env := newRPEnv(t)
	attacker := rpBrowser(t)
	victim := rpBrowser(t)

	state, status := rpStart(t, attacker, env.base, "github", "")
	if status != http.StatusFound || state == "" {
		t.Fatalf("start: status=%d state=%q", status, state)
	}

	code, loc, body := rpCallback(t, victim, env.base, "github", "code=c&state="+url.QueryEscape(state))
	if code != http.StatusBadRequest {
		t.Errorf("victim completing the attacker's flow = %d, want 400 (loc=%q body=%q)", code, loc, body)
	}
	if got := rpSignedIn(t, victim, env.base); got != "" {
		t.Errorf("the victim was signed in by the attacker's state: user_id=%q", got)
	}

	// Anti-vacuity: the browser that started the flow completes it.
	code, loc, body = rpCallback(t, attacker, env.base, "github", "code=c&state="+url.QueryEscape(state))
	if code != http.StatusSeeOther {
		t.Fatalf("control callback = %d loc=%q body=%q", code, loc, body)
	}
	if rpSignedIn(t, attacker, env.base) == "" {
		t.Fatal("control: the starting browser was not signed in, so the refusal above proves nothing")
	}
}

// The state must be consumed by the callback it belongs to.
func TestRPLoginStateIsSingleUse(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)

	state, status := rpStart(t, browser, env.base, "github", "")
	if status != http.StatusFound {
		t.Fatalf("start = %d", status)
	}
	callback := "code=c&state=" + url.QueryEscape(state)
	code, loc, body := rpCallback(t, browser, env.base, "github", callback)
	if code != http.StatusSeeOther {
		t.Fatalf("control callback = %d loc=%q body=%q", code, loc, body)
	}
	user := rpSignedIn(t, browser, env.base)
	if user == "" {
		t.Fatal("control: not signed in")
	}

	// Replay the exact callback. A second success would mean one provider code
	// can be redeemed twice through this plane.
	code, loc, body = rpCallback(t, browser, env.base, "github", callback)
	if code == http.StatusSeeOther {
		t.Errorf("the same callback was accepted twice (loc=%q)", loc)
	}
	if got := rpSignedIn(t, browser, env.base); got != user {
		t.Errorf("session changed on replay: %q -> %q", user, got)
	}
}

// A state minted for one provider must not complete at another provider's
// callback, or a deployment's second provider is a way around the first one's
// flow bookkeeping.
//
// The second half of the property: a refused callback must not *consume* the
// flow it was refused for. It does here (clearFlow runs before the provider is
// compared), which costs the browser its pending login.
func TestRPLoginStateIsBoundToItsProvider(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)

	state, status := rpStart(t, browser, env.base, "github", "")
	if status != http.StatusFound {
		t.Fatalf("start = %d", status)
	}
	query := "code=c&state=" + url.QueryEscape(state)
	code, loc, body := rpCallback(t, browser, env.base, "discord", query)
	if code != http.StatusBadRequest {
		t.Errorf("github state used at the discord callback = %d, want 400 (loc=%q body=%q)", code, loc, body)
	}
	if rpSignedIn(t, browser, env.base) != "" {
		t.Error("the wrong-provider callback signed somebody in")
	}

	// The state belongs to github, so the github callback must still work.
	if code, loc, body = rpCallback(t, browser, env.base, "github", query); code != http.StatusSeeOther {
		t.Errorf("the refused callback consumed the pending flow: github callback = %d loc=%q body=%q", code, loc, body)
	}
}

// return_to is request data on its way into a redirect. The property is
// same-origin, which is not the same as "does not mention another host": a path
// may contain any string it likes as long as the authority cannot change.
func TestRPLoginReturnToCannotLeaveTheOrigin(t *testing.T) {
	env := newRPEnv(t)
	base, err := url.Parse(env.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, returnTo := range []string{
		"//evil.example",
		"https://evil.example/",
		`/\evil.example`,
		"/%09/evil.example",
		"\\\\evil.example",
		"evil.example",
		"https://evil.example@127.0.0.1/",
		"//evil.example/\\@127.0.0.1",
	} {
		browser := rpBrowser(t)
		state, status := rpStart(t, browser, env.base, "github", "return_to="+url.QueryEscape(returnTo))
		if status != http.StatusFound {
			t.Fatalf("return_to=%q: start = %d", returnTo, status)
		}
		code, loc, _ := rpCallback(t, browser, env.base, "github", "code=c&state="+url.QueryEscape(state))
		if code != http.StatusSeeOther {
			t.Fatalf("return_to=%q: callback = %d", returnTo, code)
		}
		resolved, err := base.Parse(loc)
		if err != nil {
			t.Errorf("return_to=%q produced an unparseable redirect %q: %v", returnTo, loc, err)
			continue
		}
		if resolved.Host != base.Host || resolved.Scheme != base.Scheme {
			t.Errorf("return_to=%q landed the browser off-origin at %q", returnTo, resolved)
		}
	}

	// Anti-vacuity: a legitimate relative path is preserved, not flattened to /.
	browser := rpBrowser(t)
	state, _ := rpStart(t, browser, env.base, "github", "return_to="+url.QueryEscape("/app/dashboard?x=1"))
	_, loc, _ := rpCallback(t, browser, env.base, "github", "code=c&state="+url.QueryEscape(state))
	if loc != "/app/dashboard?x=1" {
		t.Fatalf("control: a legitimate return_to became %q", loc)
	}
}

// The provider's own error values are attacker-influenced text. They must not
// reach a redirect or an HTML body.
func TestRPLoginProviderErrorIsNotReflected(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)

	state, status := rpStart(t, browser, env.base, "github", "")
	if status != http.StatusFound {
		t.Fatalf("start = %d", status)
	}
	payload := "<script>alert(1)</script>"
	query := "state=" + url.QueryEscape(state) +
		"&error=" + url.QueryEscape(payload) +
		"&error_description=" + url.QueryEscape(payload) +
		"&error_uri=" + url.QueryEscape("javascript:"+payload)
	code, loc, body := rpCallback(t, browser, env.base, "github", query)
	if strings.Contains(loc, "script") || strings.Contains(body, "script") || strings.Contains(loc, "javascript") {
		t.Errorf("the provider's error text was reflected: status=%d loc=%q body=%q", code, loc, body)
	}
	// Anti-vacuity: the refusal path was reached, with the bounded code.
	if !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("the provider-error branch was not reached: loc=%q body=%q", loc, body)
	}
}

// A callback with neither code nor error is not a login.
func TestRPLoginCallbackNeedsACode(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)
	state, _ := rpStart(t, browser, env.base, "github", "")

	code, loc, body := rpCallback(t, browser, env.base, "github", "state="+url.QueryEscape(state))
	if code != http.StatusSeeOther || !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("callback without a code = %d loc=%q body=%q", code, loc, body)
	}
	if rpSignedIn(t, browser, env.base) != "" {
		t.Error("a callback without a code signed somebody in")
	}
}

// mode is flow state and lives in the session: a callback cannot talk this
// browser into (or out of) linking by adding a query parameter.
func TestRPLoginModeComesFromTheSessionNotTheQuery(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)

	// A login-mode flow whose callback claims mode=link must still be a login.
	state, _ := rpStart(t, browser, env.base, "github", "")
	code, loc, body := rpCallback(t, browser, env.base, "github", "code=c&state="+url.QueryEscape(state)+"&mode=link")
	if code != http.StatusSeeOther {
		t.Fatalf("login with mode=link in the query = %d loc=%q body=%q", code, loc, body)
	}
	user := rpSignedIn(t, browser, env.base)
	if user == "" {
		t.Fatal("the login-mode flow did not sign in")
	}

	// A link-mode flow whose callback claims mode=login must still link: the
	// session must stay on the same account.
	state, status := rpStart(t, browser, env.base, "github", "mode=link")
	if status != http.StatusFound {
		t.Fatalf("link start = %d", status)
	}
	code, loc, body = rpCallback(t, browser, env.base, "github", "code=zz&state="+url.QueryEscape(state)+"&mode=login")
	if code != http.StatusSeeOther {
		t.Fatalf("link callback = %d loc=%q body=%q", code, loc, body)
	}
	if got := rpSignedIn(t, browser, env.base); got != user {
		t.Errorf("a link-mode callback switched the session's account: %q -> %q", user, got)
	}
	providers := rpIdentityProviders(t, browser, env.base)
	if len(providers) != 2 {
		t.Errorf("identities after linking = %v, want two", providers)
	}
}

// Linking is a signed-in operation.
func TestRPLinkModeRequiresASignIn(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)

	resp := rpGet(t, browser, env.base+"/auth/github/start?mode=link")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("link start while signed out = %d, want 401", resp.StatusCode)
	}
	// Anti-vacuity: the same route without mode=link redirects.
	if _, status := rpStart(t, browser, env.base, "github", ""); status != http.StatusFound {
		t.Errorf("control login start = %d", status)
	}
}

// The provider segment of the path is request data. It selects a configured
// client; it must not be usable to move, or to reach, anything else.
func TestRPLoginProviderSegmentCannotEscape(t *testing.T) {
	env := newRPEnv(t)
	browser := rpBrowser(t)
	for _, provider := range []string{"nope", "a%2Fb", "..%2F..%2Fevil", "GitHub", "github%00", "%2e%2e"} {
		resp := rpGet(t, browser, env.base+"/auth/"+provider+"/start")
		if resp.StatusCode == http.StatusFound {
			loc := resp.Header.Get("Location")
			if !strings.HasPrefix(loc, "http://127.0.0.1") && !strings.Contains(loc, "/idp/authorize") {
				t.Errorf("provider segment %q redirected to %q", provider, loc)
			}
			if !strings.Contains(loc, "github") && !strings.Contains(loc, "discord") {
				t.Errorf("provider segment %q was accepted: %q", provider, loc)
			}
		}
		_ = resp.Body.Close()
	}
}

// What a completed login leaves in the session. The flow's state and verifier
// must be gone; the nonce is the one key clearFlow does not know about, because
// flowKeys omits keyFlowNonce (internal/auth/auth.go:41 vs :44).
func TestRPLoginLeavesNoFlowValuesInTheSession(t *testing.T) {
	env, store := newRPEnvWithStore(t, nil)
	browser := rpBrowser(t)

	state, status := rpStart(t, browser, env.base, "github", "")
	if status != http.StatusFound {
		t.Fatalf("start = %d", status)
	}
	if code, loc, body := rpCallback(t, browser, env.base, "github", "code=c&state="+url.QueryEscape(state)); code != http.StatusSeeOther {
		t.Fatalf("callback = %d loc=%q body=%q", code, loc, body)
	}
	if rpSignedIn(t, browser, env.base) == "" {
		t.Fatal("not signed in, so there is no session to inspect")
	}

	mem, ok := store.(*memstore.MemStore)
	if !ok {
		t.Skipf("session store is %T, not the in-memory one", store)
	}
	all, err := mem.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("the session store is empty: the probe did not observe a session")
	}
	var dump strings.Builder
	for _, b := range all {
		dump.Write(b)
	}
	raw := dump.String()
	if !strings.Contains(raw, "usr") {
		t.Fatalf("the stored session does not look like a session: %q", raw)
	}
	for _, key := range []string{"flow_state", "flow_verifier", "flow_provider", "flow_mode", "flow_return_to"} {
		if strings.Contains(raw, key) {
			t.Errorf("the completed login left %q in the session", key)
		}
	}
	if strings.Contains(raw, "flow_nonce") {
		t.Errorf("the completed login left flow_nonce in the session (flowKeys omits keyFlowNonce): %q", raw)
	}
}

// Anti-vacuity for the whole file: the ordinary signed-in flow works and the
// account is keyed by (provider, subject).
func TestRPLoginControlCreatesAndReusesOneAccount(t *testing.T) {
	env := newRPEnv(t)

	first := rpBrowser(t)
	state, _ := rpStart(t, first, env.base, "github", "")
	if code, loc, body := rpCallback(t, first, env.base, "github", "code=c&state="+url.QueryEscape(state)); code != http.StatusSeeOther {
		t.Fatalf("first callback = %d loc=%q body=%q", code, loc, body)
	}
	user := rpSignedIn(t, first, env.base)
	if user == "" {
		t.Fatal("not signed in")
	}

	second := rpBrowser(t)
	state, _ = rpStart(t, second, env.base, "github", "")
	if code, loc, body := rpCallback(t, second, env.base, "github", "code=c&state="+url.QueryEscape(state)); code != http.StatusSeeOther {
		t.Fatalf("second callback = %d loc=%q body=%q", code, loc, body)
	}
	if got := rpSignedIn(t, second, env.base); got != user {
		t.Fatalf("the same provider subject produced two accounts: %q and %q", user, got)
	}
}
