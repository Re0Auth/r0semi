package auth

// P3 probes for the auth plane (batch S03-2/3/4/9, Z07-4, RP-6, RP-8, k6).
//
// Every test here is written to be red against the code as it was before the fix
// and green after it. They live in the default suite (no build tag) so the
// focused command
//
//	go test ./internal/auth/ ./internal/admin/ -count=1
//
// covers them.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2/memstore"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/idp"
	"github.com/Re0Auth/r0semi/internal/account"
)

// ---------------------------------------------------------------------------
// shared fixtures
// ---------------------------------------------------------------------------

// storeGate is an scs.Store whose Delete can be turned into a failure. That is
// the only way RenewToken (SignIn) and Destroy (EndSession) fail, and both
// failure paths are what S03-2 / S03-3 are about.
type storeGate struct {
	inner *memstore.MemStore
	mu    sync.Mutex
	fail  bool
}

func newStoreGate() *storeGate { return &storeGate{inner: memstore.New()} }

func (s *storeGate) setFailing(v bool) {
	s.mu.Lock()
	s.fail = v
	s.mu.Unlock()
}

func (s *storeGate) Find(token string) ([]byte, bool, error) { return s.inner.Find(token) }

func (s *storeGate) Commit(token string, b []byte, expiry time.Time) error {
	return s.inner.Commit(token, b, expiry)
}

func (s *storeGate) Delete(token string) error {
	s.mu.Lock()
	failing := s.fail
	s.mu.Unlock()
	if failing {
		return errors.New("probe: session store refused the delete")
	}
	return s.inner.Delete(token)
}

// failingAuditLogger fails every write, which is what puts recordAudit on its
// slog.Error branch (k6).
type failingAuditLogger struct{}

func (failingAuditLogger) Record(context.Context, audit.Event) error {
	return errors.New("probe: audit sink down")
}

// captureSlog redirects the default logger for the duration of the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// ---------------------------------------------------------------------------
// S03-2
// ---------------------------------------------------------------------------

// TestP3S032SignInLeavesNoLiveSessionWhenRenewalFails.
//
// SignIn records the account before RenewToken. When the rotation fails the
// session is still live under its OLD token — and that token was already dropped
// from the index (or, for a pre-login session, was never in it), so an operator
// can no longer reach the authenticated session by subject. The authenticated
// values must not survive.
func TestP3S032SignInLeavesNoLiveSessionWhenRenewalFails(t *testing.T) {
	store := newStoreGate()
	m := NewManager(Options{Secure: false, Store: store})

	// RenewToken only touches the store when the session already has a token, so
	// the failure needs a live pre-login session first.
	seed := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		m.sessions.Put(r.Context(), "seed", "1")
	})).ServeHTTP(seed, httptest.NewRequest(http.MethodGet, "/", nil))
	pre := sessionCookie(t, seed)

	store.setFailing(true)
	signInRec := httptest.NewRecorder()
	var signErr error
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(pre)
	m.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		signErr = m.SignIn(r.Context(), "usr_1")
		if u, ok := m.User(r.Context()); ok {
			t.Errorf("SignIn returned %v yet the in-request session still authenticates as %q", signErr, u)
		}
	})).ServeHTTP(signInRec, req)

	if signErr == nil {
		t.Fatal("SignIn reported success although the session store refused the token rotation")
	}

	// Whatever live cookie the failed sign-in wrote must not authenticate: a
	// session the index never saw is a session no subject sweep can reach.
	var replay string
	for _, c := range signInRec.Result().Cookies() {
		if c.Name == "r0semi_session" && c.Value != "" && c.MaxAge >= 0 {
			replay = c.Value
		}
	}
	if replay == "" {
		return // the response cleared the cookie: nothing can authenticate
	}
	replayReq := httptest.NewRequest(http.MethodGet, "/", nil)
	replayReq.AddCookie(&http.Cookie{Name: "r0semi_session", Value: replay})
	m.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if u, ok := m.User(r.Context()); ok {
			t.Errorf("a session that could not be indexed still authenticates as %q (token %q)", u, replay)
		}
	})).ServeHTTP(httptest.NewRecorder(), replayReq)
}

// ---------------------------------------------------------------------------
// S03-3
// ---------------------------------------------------------------------------

// TestP3S033EndSessionKeepsTheIndexEntryWhenDestroyFails.
//
// EndSession drops the index entry first. When Destroy then fails, the session
// is still live in the store but no longer indexed — an unrevocable live session.
// The entry must stay until the store confirms the session is gone.
func TestP3S033EndSessionKeepsTheIndexEntryWhenDestroyFails(t *testing.T) {
	store := newStoreGate()
	index := &fakeIndex{}
	m := NewManager(Options{Secure: false, Store: store, Index: index})

	rec := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), "usr_1"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	live := sessionCookie(t, rec)

	store.setFailing(true)
	var endErr error
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(live)
	m.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		endErr = m.EndSession(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), req)

	if endErr == nil {
		t.Fatal("EndSession reported success although the session store refused the delete")
	}
	for _, token := range index.forgotten {
		if token == live.Value {
			t.Errorf("EndSession forgot the index entry for a session the store still holds (token %q): "+
				"the live session can no longer be revoked by subject", live.Value)
		}
	}
}

// ---------------------------------------------------------------------------
// S03-4
// ---------------------------------------------------------------------------

// raceSignupStore models the concurrent first login: the identity is absent on
// the first lookup, the insert loses to the other request (ErrIdentityTaken),
// and the identity is present when the handler looks again.
type raceSignupStore struct {
	*account.MemoryStore
	mu      sync.Mutex
	lookups int
}

func (s *raceSignupStore) FindByIdentity(ctx context.Context, provider idp.Provider, subject string) (account.UserID, error) {
	s.mu.Lock()
	s.lookups++
	first := s.lookups == 1
	s.mu.Unlock()
	if first {
		return "", account.ErrNotFound
	}
	return s.MemoryStore.FindByIdentity(ctx, provider, subject)
}

func (s *raceSignupStore) CreateWithIdentity(ctx context.Context, in idp.Identity) (account.User, account.Identity, error) {
	_, _, err := s.MemoryStore.CreateWithIdentity(ctx, in)
	if err != nil {
		return account.User{}, account.Identity{}, err
	}
	// The row exists now, but this request lost the race: the other request is
	// the one that created it.
	return account.User{}, account.Identity{}, account.ErrIdentityTaken
}

// newRaceStoreHarness serves the /auth plane over the given account store.
func newRaceStoreHarness(t *testing.T, store account.Store) (*httptest.Server, *http.Client) {
	t.Helper()
	fake := fakeIDP(t)
	registry, err := idp.NewRegistry(idp.RegistryConfig{
		RedirectBase: "https://re0auth.test",
		HTTPClient:   fake.Client(),
		Credentials: []idp.Credentials{{
			Provider: idp.GitHub, ClientID: "cid-github", ClientSecret: "sec",
			AuthURL:     fake.URL + "/github/authorize",
			TokenURL:    fake.URL + "/github/token",
			UserInfoURL: fake.URL + "/github/user",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(Options{Secure: false})
	handler, err := NewHandler(m, registry, store)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	srv := httptest.NewServer(m.LoadAndSave(mux))
	t.Cleanup(srv.Close)

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
	return srv, client
}

// TestP3S034ConcurrentFirstLoginRetriesTheLookup.
//
// The lookup says "no such identity", the insert loses the race, and the handler
// reports signup_failed without looking again. A concurrent first login of the
// same identity must complete on the account the winner created.
func TestP3S034ConcurrentFirstLoginRetriesTheLookup(t *testing.T) {
	srv, client := newRaceStoreHarness(t, &raceSignupStore{MemoryStore: account.NewMemoryStore()})

	resp, err := client.Get(srv.URL + "/auth/github/start?return_to=/app")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	resp.Body.Close()
	if state == "" {
		t.Fatal("start redirected without a state")
	}

	resp, err = client.Get(srv.URL + "/auth/github/callback?code=c&state=" + state)
	if err != nil {
		t.Fatal(err)
	}
	location := resp.Header.Get("Location")
	status := resp.StatusCode
	resp.Body.Close()

	if strings.Contains(location, "error=") {
		t.Errorf("a login whose account was created concurrently was reported as a failure: Location = %q", location)
	}
	if status != http.StatusSeeOther || location != "/app" {
		t.Errorf("callback = %d Location = %q, want 303 /app", status, location)
	}
}

// ---------------------------------------------------------------------------
// S03-9 / RP-8
// ---------------------------------------------------------------------------

// flowKeysWrittenByStart is every flow value handleStart stores in the session.
var flowKeysWrittenByStart = []string{
	keyFlowState, keyFlowProvider, keyFlowMode, keyFlowReturnTo, keyFlowVerifier, keyFlowNonce,
}

// TestP3S039ClearFlowRemovesTheOidcNonce.
//
// clearFlow iterates flowKeys, and flowKeys omits keyFlowNonce, so the OIDC
// nonce outlives the flow it belongs to.
func TestP3S039ClearFlowRemovesTheOidcNonce(t *testing.T) {
	m := NewManager(Options{Secure: false})
	jar := testJar(t)
	h := &Handler{manager: m}

	serveInSession(t, m, jar, func(ctx context.Context) any {
		for _, k := range flowKeysWrittenByStart {
			m.sessions.Put(ctx, k, "probe")
		}
		return nil
	})

	left := serveInSession(t, m, jar, func(ctx context.Context) []string {
		h.clearFlow(ctx)
		return m.sessions.Keys(ctx)
	})
	for _, k := range flowKeysWrittenByStart {
		if slices.Contains(left, k) {
			t.Errorf("clearFlow left %s in the session (keys: %v)", k, left)
		}
	}
}

// TestP3RP8LoginLeavesNoFlowValuesInTheSession is the same defect seen from the
// outside: drive a whole login and ask the session which keys survived.
func TestP3RP8LoginLeavesNoFlowValuesInTheSession(t *testing.T) {
	h := newHarness(t)
	h.login(t, "github")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Join(h.manager.sessions.Keys(r.Context()), ",")))
	})
	srv := httptest.NewServer(h.manager.LoadAndSave(mux))
	defer srv.Close()

	resp, err := h.client.Get(srv.URL + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	keys := readBody(t, resp)
	if strings.Contains(keys, keyFlowNonce) {
		t.Errorf("flow_nonce survived a completed login: session keys %q", keys)
	}
	for _, k := range []string{keyFlowState, keyFlowProvider, keyFlowMode, keyFlowReturnTo, keyFlowVerifier} {
		if slices.Contains(strings.Split(keys, ","), k) {
			t.Errorf("%s survived a completed login: session keys %q", k, keys)
		}
	}
}

// ---------------------------------------------------------------------------
// RP-6
// ---------------------------------------------------------------------------

// TestP3RP6AWrongProviderCallbackDoesNotBurnThePendingLogin.
//
// handleCallback reads the flow, then clears it, then compares the provider. A
// callback that names the wrong provider — carrying the state of a pending login
// — therefore destroys that login. The comparison must come first; the state is
// single-use only once the callback is confirmed to belong to the flow.
func TestP3RP6AWrongProviderCallbackDoesNotBurnThePendingLogin(t *testing.T) {
	h := newHarness(t)

	resp := h.get(t, h.server.URL+"/auth/github/start?return_to=/app")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start = %d, want 302", resp.StatusCode)
	}
	state := stateOf(t, resp)
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/discord/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cross-provider callback = %d, want 400 provider_mismatch", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/github/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/app" {
		t.Errorf("the pending login was burned by a wrong-provider callback: the correct callback = %d %q",
			resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()
}

// TestP3RP6AProviderRefusalStillConsumesTheState is the guard on the other side
// of the same ordering: a callback the flow DOES belong to — the provider
// refused — must still spend the single-use state, or the state could be replayed
// with a code.
func TestP3RP6AProviderRefusalStillConsumesTheState(t *testing.T) {
	h := newHarness(t)

	resp := h.get(t, h.server.URL+"/auth/github/start?return_to=/app")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start = %d, want 302", resp.StatusCode)
	}
	state := stateOf(t, resp)
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/github/callback?state="+state+"&error=access_denied")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("provider refusal = %d, want a redirect back", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.get(t, h.server.URL+"/auth/github/callback?code=c&state="+state)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("the state of a refused login was still usable for a code callback: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// Z07-4
// ---------------------------------------------------------------------------

// TestP3Z074ConcurrentFirstCSRFReadersAgreeOnOneToken.
//
// CSRFToken is a read-then-write. Two requests that both load the same session
// before either has committed a token both mint one, and only the last writer's
// value is the one ValidCSRF will compare against — so one of the two callers is
// handed a token the server rejects. The value must be a function of the session,
// not of which request happened to write last.
func TestP3Z074ConcurrentFirstCSRFReadersAgreeOnOneToken(t *testing.T) {
	m := NewManager(Options{Secure: false})

	rec := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), "usr_1"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	cookie := sessionCookie(t, rec)

	// Two in-request snapshots of the same session, both taken before either
	// commits a CSRF token: exactly the state two parallel first readers see.
	ctxA, err := m.sessions.Load(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := m.sessions.Load(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	a := m.CSRFToken(ctxA)
	b := m.CSRFToken(ctxB)
	if a == "" || b == "" {
		t.Fatal("a first reader was handed an empty CSRF token")
	}
	if a != b {
		t.Errorf("two first readers of one session were handed different CSRF tokens (%q vs %q): "+
			"all but the last writer's value is rejected by ValidCSRF, so the write from one of them fails", a, b)
	}

	// The value must still differ per session: it is derived from the session,
	// not a constant.
	other := NewManager(Options{Secure: false})
	otherRec := httptest.NewRecorder()
	var otherToken string
	other.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		otherToken = other.CSRFToken(r.Context())
	})).ServeHTTP(otherRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if otherToken == a {
		t.Error("two different sessions were handed the same CSRF token")
	}
}

// ---------------------------------------------------------------------------
// k6
// ---------------------------------------------------------------------------

// TestP3K6AuditFailureLogCarriesNoAccountID: when the audit write fails, the
// process log must name the action, never the account whose record could not be
// written — the pseudonym-key destruction cannot reach a raw usr_ left in a log.
func TestP3K6AuditFailureLogCarriesNoAccountID(t *testing.T) {
	log := captureSlog(t)

	m := NewManager(Options{Secure: false, Audit: failingAuditLogger{}})
	rec := httptest.NewRecorder()
	m.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if err := m.SignIn(r.Context(), "usr_secret"); err != nil {
			t.Errorf("sign in: %v", err)
		}
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie(t, rec))
	m.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_ = m.SignOut(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), req)

	logged := log.String()
	if !strings.Contains(logged, "auth audit record failed") {
		t.Fatalf("the audit write failure was not logged; the probe would be vacuous: %q", logged)
	}
	if strings.Contains(logged, "usr_secret") {
		t.Errorf("the process log carried the account id: %q", logged)
	}
}
