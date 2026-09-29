//go:build audit || audit6

package auth

// Audit probes for the identity/session/CSRF area (round 6).
//
// Everything here is an audit artifact: it observes what the production code
// does today. Nothing in the production tree is touched.
//
//	Naming: TestZZAudit* so the probes sort away from the suite's own tests.

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
	"github.com/Re0Auth/r0semi/internal/testoidc"
)

// ---------------------------------------------------------------------------
// helpers (self-contained; the suite's own helpers are left untouched)
// ---------------------------------------------------------------------------

// zzCookieValue returns the live session cookie a response wrote, or "".
func zzCookieValue(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			return c.Value
		}
	}
	return ""
}

func zzCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

// zzAuditEnv is a minimal /auth plane plus a probe route that dumps the session's
// key set, so a test can see exactly which flow keys survived a callback.
func zzAuditEnv(t *testing.T) (srv *httptest.Server, m *Manager, client *http.Client, oidc *testoidc.Server) {
	t.Helper()
	fake := fakeIDP(t)
	oidc = testoidc.New()
	t.Cleanup(oidc.Close)

	creds := []idp.Credentials{{
		Provider: idp.Google, ClientID: "cid-google", ClientSecret: "sec",
		AuthURL: oidc.URL + "/authorize", TokenURL: oidc.URL + "/token", Issuer: oidc.URL,
	}}
	for _, p := range []idp.Provider{idp.GitHub, idp.Discord} {
		creds = append(creds, idp.Credentials{
			Provider: p, ClientID: "cid-" + string(p), ClientSecret: "sec",
			AuthURL:     fake.URL + "/" + string(p) + "/authorize",
			TokenURL:    fake.URL + "/" + string(p) + "/token",
			UserInfoURL: fake.URL + "/" + string(p) + "/user",
		})
	}
	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test", HTTPClient: fake.Client(), Credentials: creds,
	})
	if err != nil {
		t.Fatal(err)
	}
	m = NewManager(Options{Secure: false})
	handler, err := NewHandler(m, registry, account.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	mux.HandleFunc("GET /zz/keys", func(w http.ResponseWriter, r *http.Request) {
		keys := m.sessions.Keys(r.Context())
		_, _ = w.Write([]byte(strings.Join(keys, ",")))
	})
	mux.HandleFunc("GET /zz/whoami", func(w http.ResponseWriter, r *http.Request) {
		if u, ok := m.User(r.Context()); ok {
			_, _ = w.Write([]byte(u))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("POST /zz/csrf", func(w http.ResponseWriter, r *http.Request) {
		if m.ValidCSRF(r) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	srv = httptest.NewServer(m.LoadAndSave(mux))
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return srv, m, client, oidc
}

func zzGet(t *testing.T, c *http.Client, target string) *http.Response {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func zzText(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func zzParam(t *testing.T, resp *http.Response, key string) string {
	t.Helper()
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	return u.Query().Get(key)
}

// ---------------------------------------------------------------------------
// 1. cookie shape
// ---------------------------------------------------------------------------

// TestZZAuditSessionCookieShape pins every attribute the cookie carries, and the
// name it carries them under, for both deployment shapes.
func TestZZAuditSessionCookieShape(t *testing.T) {
	for _, tc := range []struct {
		secure   bool
		wantName string
	}{{true, "__Host-r0semi_session"}, {false, "r0semi_session"}} {
		m := NewManager(Options{Secure: tc.secure})
		rec := httptest.NewRecorder()
		m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.sessions.Put(r.Context(), "probe", "1")
		})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://re0auth.test/", nil))

		c := zzCookie(rec)
		if c == nil {
			t.Fatalf("secure=%v: no live session cookie", tc.secure)
		}
		t.Logf("secure=%v cookie=%s HttpOnly=%v Secure=%v SameSite=%v Path=%q Domain=%q",
			tc.secure, c.Name, c.HttpOnly, c.Secure, c.SameSite, c.Path, c.Domain)

		if c.Name != tc.wantName {
			t.Errorf("secure=%v: name = %q, want %q", tc.secure, c.Name, tc.wantName)
		}
		if !c.HttpOnly {
			t.Errorf("secure=%v: HttpOnly is off", tc.secure)
		}
		if c.Secure != tc.secure {
			t.Errorf("secure=%v: Secure = %v", tc.secure, c.Secure)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("secure=%v: SameSite = %v, want Lax", tc.secure, c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("secure=%v: Path = %q, want /", tc.secure, c.Path)
		}
		if c.Domain != "" {
			t.Errorf("secure=%v: Domain = %q, want empty", tc.secure, c.Domain)
		}
		// The contract (docs/account-model.md:123) names the cookie
		// __Host-r0semi_session unconditionally; the branch that drops the prefix
		// for a non-Secure cookie is what this records.
		if !tc.secure && strings.HasPrefix(c.Name, "__Host-") {
			t.Errorf("unexpected __Host- prefix on a non-Secure cookie")
		}
	}
}

// ---------------------------------------------------------------------------
// 2. session lifecycle: rotation on sign-in, server-side death on sign-out
// ---------------------------------------------------------------------------

// TestZZAuditSignInRotatesTheCookieAndKillsTheOldToken is the session-fixation
// question: a pre-login cookie must not become an authenticated one, and the
// pre-login token must not keep working afterwards.
func TestZZAuditSignInRotatesTheCookieAndKillsTheOldToken(t *testing.T) {
	m := NewManager(Options{Secure: false})

	// A pre-login browser: the handle/consent flow puts state in the session
	// before anyone signs in, which is what makes this cookie valuable.
	rec := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Bind(r.Context(), "authz", "arq_prefixation")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	pre := zzCookieValue(rec)
	if pre == "" {
		t.Fatal("no pre-login session cookie")
	}

	signInReq := httptest.NewRequest(http.MethodGet, "/", nil)
	signInReq.AddCookie(&http.Cookie{Name: "r0semi_session", Value: pre})
	signInRec := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), "usr_victim"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	})).ServeHTTP(signInRec, signInReq)
	post := zzCookieValue(signInRec)
	if post == "" {
		t.Fatal("sign-in wrote no session cookie")
	}
	t.Logf("pre-login token=%s... post-login token=%s...", pre[:8], post[:8])
	if post == pre {
		t.Fatal("SignIn did not rotate the session token")
	}

	// The pre-login token must not authenticate, and must no longer resolve to
	// the session at all (scs deletes it in the store).
	old := httptest.NewRequest(http.MethodGet, "/", nil)
	old.AddCookie(&http.Cookie{Name: "r0semi_session", Value: pre})
	oldRec := httptest.NewRecorder()
	var who string
	m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := m.User(r.Context())
		if ok {
			who = string(u)
		}
		// The pre-login handle must not have survived under the old token either.
		if m.Bound(r.Context(), "authz", "arq_prefixation") {
			who = "handle-survived"
		}
	})).ServeHTTP(oldRec, old)
	if who != "" {
		t.Fatalf("the pre-login token still resolved to %q", who)
	}
}

// TestZZAuditSignOutDeletesServerSideState: the destroy must be a store delete,
// not only an expired Set-Cookie.
func TestZZAuditSignOutDeletesServerSideState(t *testing.T) {
	m := NewManager(Options{Secure: false})
	rec := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), "usr_1"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	live := zzCookie(rec)

	outReq := httptest.NewRequest(http.MethodGet, "/", nil)
	outReq.AddCookie(live)
	outRec := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.SignOut(r.Context()); err != nil {
			t.Errorf("sign out: %v", err)
		}
	})).ServeHTTP(outRec, outReq)

	// The response expires the cookie...
	var cleared bool
	for _, c := range outRec.Result().Cookies() {
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
			cleared = true
		}
	}
	if !cleared {
		t.Error("SignOut wrote no cookie-clearing Set-Cookie")
	}

	// ...and the token itself is gone from the store, so replaying it is not a
	// session. A store-level delete is what makes this true even for an attacker
	// who kept a copy of the value.
	replay := httptest.NewRequest(http.MethodGet, "/", nil)
	replay.AddCookie(live)
	var still bool
	m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := m.User(r.Context()); ok {
			still = true
		}
	})).ServeHTTP(httptest.NewRecorder(), replay)
	if still {
		t.Fatal("the signed-out token still authenticates")
	}
}

// ---------------------------------------------------------------------------
// 3. CSRf: cross-session rejection, comparison shape
// ---------------------------------------------------------------------------

// TestZZAuditCSRFTokenIsSessionBound: one session's token must not work in
// another, and no near-miss may pass.
func TestZZAuditCSRFTokenIsSessionBound(t *testing.T) {
	m := NewManager(Options{Secure: false})
	newSession := func() (string, string) {
		rec := httptest.NewRecorder()
		var token string
		m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token = m.CSRFToken(r.Context())
			if err := m.SignIn(r.Context(), account.UserID("usr_"+token[:6])); err != nil {
				t.Errorf("sign in: %v", err)
			}
		})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return token, zzCookieValue(rec)
	}
	tokenA, cookieA := newSession()
	tokenB, cookieB := newSession()
	if tokenA == tokenB {
		t.Fatal("two sessions were issued the same CSRF token")
	}
	t.Logf("tokenA=%s tokenB=%s", tokenA[:8], tokenB[:8])

	post := func(cookie, token string) int {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: "r0semi_session", Value: cookie})
		if token != "" {
			req.Header.Set("X-CSRF-Token", token)
		}
		rec := httptest.NewRecorder()
		m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.ValidCSRF(r) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})).ServeHTTP(rec, req)
		return rec.Code
	}

	if got := post(cookieA, tokenA); got != http.StatusNoContent {
		t.Errorf("own token = %d, want 204", got)
	}
	if got := post(cookieB, tokenA); got != http.StatusForbidden {
		t.Errorf("session A's token in session B = %d, want 403", got)
	}
	for _, near := range []string{
		tokenA[:len(tokenA)-1],           // truncated
		tokenA[:len(tokenA)-1] + "0",     // last byte changed
		strings.ToUpper(tokenA),          // case flipped
		strings.Repeat("0", len(tokenA)), // right shape, wrong value
		tokenA + "0",                     // longer
	} {
		if got := post(cookieA, near); got != http.StatusForbidden {
			t.Errorf("near-miss token %q = %d, want 403", near, got)
		}
	}
	if got := post(cookieA, ""); got != http.StatusForbidden {
		t.Errorf("absent token = %d, want 403", got)
	}
}

// TestZZAuditCSRFTokenSurvivesSessionRotation records that the CSRF token is not
// rotated with the session id, and that it is therefore not a second fixation
// surface: it is only ever handed out inside an authenticated response.
func TestZZAuditCSRFTokenSurvivesSessionRotation(t *testing.T) {
	m := NewManager(Options{Secure: false})
	var before string
	rec := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		before = m.CSRFToken(r.Context())
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	pre := zzCookieValue(rec)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "r0semi_session", Value: pre})
	rec2 := httptest.NewRecorder()
	var after string
	m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), "usr_1"); err != nil {
			t.Errorf("sign in: %v", err)
		}
		after = m.CSRFToken(r.Context())
	})).ServeHTTP(rec2, req)
	if after != before {
		t.Logf("the CSRF token DID rotate with the session id (%s -> %s)", before[:8], after[:8])
	} else {
		t.Logf("the CSRF token is carried across the session-id rotation (%s)", before[:8])
	}
	if zzCookieValue(rec2) == pre {
		t.Fatal("the session id did not rotate")
	}
}

// ---------------------------------------------------------------------------
// 4. flow state: single use, single slot, and what clearFlow leaves behind
// ---------------------------------------------------------------------------

// TestZZAuditCallbackLeavesTheNonceInTheSession drives a whole login and then
// asks the session which keys survived. flowKeys (auth.go:44) omits keyFlowNonce.
func TestZZAuditCallbackLeavesTheNonceInTheSession(t *testing.T) {
	srv, _, client, _ := zzAuditEnv(t)

	resp := zzGet(t, client, srv.URL+"/auth/github/start")
	state := zzParam(t, resp, "state")
	resp.Body.Close()

	resp = zzGet(t, client, srv.URL+"/auth/github/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d", resp.StatusCode)
	}
	resp.Body.Close()

	keys := zzText(t, zzGet(t, client, srv.URL+"/zz/keys"))
	t.Logf("session keys after a successful login: %q", keys)
	if strings.Contains(keys, keyFlowNonce) {
		t.Errorf("flow_nonce survived clearFlow; flowKeys (auth.go:44) does not list it")
	}
	for _, k := range []string{keyFlowState, keyFlowProvider, keyFlowMode, keyFlowReturnTo, keyFlowVerifier} {
		if strings.Contains(keys, k) {
			t.Errorf("%s survived clearFlow", k)
		}
	}
}

// TestZZAuditStateIsSingleUseAndFlowKeysAreSingleSlot: a second start replaces the
// first flow's state, which is what makes "the account switched mid-flow" and
// "two interleaved link flows" unreachable through this plane.
func TestZZAuditStateIsSingleUseAndFlowKeysAreSingleSlot(t *testing.T) {
	srv, _, client, _ := zzAuditEnv(t)

	// A is signed in through github.
	resp := zzGet(t, client, srv.URL+"/auth/github/start")
	stateA := zzParam(t, resp, "state")
	resp.Body.Close()
	resp = zzGet(t, client, srv.URL+"/auth/github/callback?code=c&state="+stateA)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first login = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// A starts a LINK flow for google and leaves it pending.
	resp = zzGet(t, client, srv.URL+"/auth/google/start?mode=link")
	linkState := zzParam(t, resp, "state")
	resp.Body.Close()
	if linkState == "" {
		t.Fatal("no state on the link start")
	}

	// A second start - which is what any account switch needs, because SignIn is
	// only ever reached from a callback - overwrites the single flow slot.
	resp = zzGet(t, client, srv.URL+"/auth/github/start")
	secondState := zzParam(t, resp, "state")
	resp.Body.Close()
	if secondState == linkState {
		t.Fatal("two starts produced the same state")
	}

	// The pending link flow is now unusable: its state is gone.
	resp = zzGet(t, client, srv.URL+"/auth/google/callback?code=c&state="+linkState)
	body := zzText(t, resp)
	t.Logf("callback with the clobbered link state = %d %s", resp.StatusCode, strings.TrimSpace(body))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("clobbered link state = %d, want 400", resp.StatusCode)
	}

	// The replacement flow is the one that is now live.
	resp = zzGet(t, client, srv.URL+"/auth/github/callback?code=c&state="+secondState)
	resp.Body.Close()
}

// TestZZAuditCallbackClearsFlowBeforeAnyFailure shows the state is consumed even
// when the callback then fails on the provider's error parameter: replay is not
// possible once the state has been seen.
func TestZZAuditCallbackConsumesStateEvenOnProviderError(t *testing.T) {
	srv, _, client, _ := zzAuditEnv(t)

	resp := zzGet(t, client, srv.URL+"/auth/github/start")
	state := zzParam(t, resp, "state")
	resp.Body.Close()

	resp = zzGet(t, client, srv.URL+"/auth/github/callback?state="+state+"&error=access_denied")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("provider-error callback = %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	t.Logf("provider refusal redirected to %q", loc)

	resp = zzGet(t, client, srv.URL+"/auth/github/callback?code=c&state="+state)
	body := zzText(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed state = %d (%s), want 400", resp.StatusCode, strings.TrimSpace(body))
	}
}

// ---------------------------------------------------------------------------
// 5. every session write is a whole-session write
// ---------------------------------------------------------------------------

// countingStore records how many times a session was committed and the size of
// the largest payload. scs sets IdleTimeout in Manager, and scs marks a loaded
// session Modified whenever IdleTimeout > 0 (scs data.go:78-83), so a plain read
// is expected to re-commit.
type countingStore struct {
	mu      sync.Mutex
	commits int
	maxLen  int
	data    map[string][]byte
}

func newCountingStore() *countingStore { return &countingStore{data: map[string][]byte{}} }

func (s *countingStore) Find(token string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[token]
	return b, ok, nil
}

func (s *countingStore) Commit(token string, b []byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commits++
	if len(b) > s.maxLen {
		s.maxLen = len(b)
	}
	s.data[token] = append([]byte(nil), b...)
	return nil
}

func (s *countingStore) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
	return nil
}

// TestZZAuditEveryRequestRewritesTheWholeSession measures the amplifier behind
// the session-size bound: one GET that reads the session costs one whole-session
// store write.
func TestZZAuditEveryRequestRewritesTheWholeSession(t *testing.T) {
	store := newCountingStore()
	m := NewManager(Options{Secure: false, Store: store})
	mux := http.NewServeMux()
	mux.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		_, _ = m.User(r.Context()) // a pure read: no Put, no Remove
	})
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), "usr_1"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	})
	srv := httptest.NewServer(m.LoadAndSave(mux))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(srv.URL + "/signin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	store.mu.Lock()
	afterSignIn := store.commits
	store.mu.Unlock()

	for i := 0; i < 3; i++ {
		resp, err := client.Get(srv.URL + "/read")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	store.mu.Lock()
	afterReads, maxLen := store.commits, store.maxLen
	store.mu.Unlock()
	t.Logf("commits: %d after sign-in, %d after 3 read-only requests; largest payload %d bytes",
		afterSignIn, afterReads, maxLen)
	if afterReads-afterSignIn != 3 {
		t.Errorf("read-only requests committed the session %d times, want 3 (IdleTimeout>0 makes every load Modified)",
			afterReads-afterSignIn)
	}
}

// TestZZAuditBindAcceptsAnUnboundedID records the other half of the same
// amplifier: the per-kind cap bounds the COUNT of handles, never their bytes.
func TestZZAuditBindAcceptsAnUnboundedID(t *testing.T) {
	store := newCountingStore()
	m := NewManager(Options{Secure: false, Store: store})
	mux := http.NewServeMux()
	mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), "usr_1"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	})
	mux.HandleFunc("/bind", func(w http.ResponseWriter, r *http.Request) {
		m.Bind(r.Context(), "device", r.URL.Query().Get("id"))
	})
	srv := httptest.NewServer(m.LoadAndSave(mux))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(srv.URL + "/signin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	pad := strings.Repeat("-", 16<<10)
	for i := 0; i < 3; i++ {
		resp, err := client.Get(srv.URL + "/bind?id=" + url.QueryEscape(strings.Repeat("-", i+1)+pad+"WDJBMJHT"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	store.mu.Lock()
	maxLen := store.maxLen
	store.mu.Unlock()
	t.Logf("largest committed session after 3 padded binds: %d bytes", maxLen)
	if maxLen < 16<<10 {
		t.Fatalf("the padded handle did not reach the store: max %d bytes", maxLen)
	}
}
