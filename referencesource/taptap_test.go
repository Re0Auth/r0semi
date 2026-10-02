package referencesource_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/audit"
	"github.com/Re0Auth/r0semi/internal/federation"
	"github.com/Re0Auth/r0semi/referencesource"
	"github.com/Re0Auth/r0semi/tapsign"
	"github.com/Re0Auth/r0semi/taptapoauth"
	"github.com/Re0Auth/r0semi/vault"
)

// fakeTapTap stands in for TapTap's device-code, token, user-info and LeanCloud
// endpoints. It is the whole point of slice 2 being verifiable without network:
// the real TapTap dialect is exercised, only the far end is fake.
type fakeTapTap struct {
	*httptest.Server

	mu       sync.Mutex
	approved bool
}

func newFakeTapTap(t *testing.T) *fakeTapTap {
	t.Helper()
	f := &fakeTapTap{}
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, _ *http.Request) {
		replyJSON(w, map[string]any{"success": true, "data": map[string]any{
			"device_code":      "dc-1",
			"verification_url": f.URL + "/approve",
			"user_code":        "uc-1",
			"interval":         1,
			"expires_in":       300,
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// A GET here is the MAC-signed user-info call.
		if r.Method == http.MethodGet {
			replyJSON(w, map[string]any{"success": true, "data": map[string]any{
				"openid": "openid-1", "unionid": "union-1",
			}})
			return
		}
		f.mu.Lock()
		approved := f.approved
		f.mu.Unlock()
		if !approved {
			replyJSON(w, map[string]any{"success": false, "data": map[string]any{
				"error": "authorization_pending", "error_description": "waiting",
			}})
			return
		}
		replyJSON(w, map[string]any{"success": true, "data": map[string]any{
			"kid": "kid-1", "mac_key": "mac-1",
		}})
	})
	mux.HandleFunc("/users", func(w http.ResponseWriter, _ *http.Request) {
		replyJSON(w, map[string]any{"sessionToken": "sess-1", "objectId": "obj-1"})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeTapTap) approve() {
	f.mu.Lock()
	f.approved = true
	f.mu.Unlock()
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	// Start at wall-clock now: taptapoauth computes ExpiresAt from the real
	// clock, so the two must share a baseline.
	return &fakeClock{t: time.Now()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTapTapSource(t *testing.T) (*referencesource.Source, *httptest.Server, *fakeTapTap, *fakeClock, referencesource.Deps) {
	t.Helper()
	tap := newFakeTapTap(t)
	clock := newFakeClock()

	enroller, err := taptapoauth.NewService(taptapoauth.Config{
		DeviceCodeEndpoint: tap.URL + "/device/code",
		TokenEndpoint:      tap.URL + "/token",
		UserInfoEndpoint:   tap.URL + "/token",
		ClientID:           "test-client",
	}, tap.Client())
	if err != nil {
		t.Fatal(err)
	}
	redeem, err := tapsign.NewService(tapsign.Config{
		BaseURL: tap.URL, AppID: "app", AppKey: "key",
	}, tap.Client(), audit.NewMemoryLogger())
	if err != nil {
		t.Fatal(err)
	}

	vaultSvc := newVault(t)
	login, err := referencesource.NewTapTapLogin(referencesource.TapTapConfig{
		Now: clock.Now,
	}, referencesource.TapTapDeps{Enroller: enroller, Redeem: redeem})
	if err != nil {
		t.Fatal(err)
	}

	deps := referencesource.Deps{
		Logins: []referencesource.Login{login},
		Vault:  vaultSvc,
		Reader: referencesource.StaticReader{"profile": map[string]any{"game": "phigros", "rks": 15.2}},
	}
	src, srv := startSource(t, deps)
	return src, srv, tap, clock, deps
}

// TestTapTapLoginEndToEnd runs the whole thing: a user scans a TapTap QR code at
// the source, Re0Auth binds over OAuth 2.0, and data flows -- with Re0Auth never
// seeing TapTap.
func TestTapTapLoginEndToEnd(t *testing.T) {
	src, srv, tap, clock, deps := newTapTapSource(t)
	if src.Discovery().Source != source {
		t.Fatalf("discovery source = %q", src.Discovery().Source)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// The visitor is anonymous until the QR is approved.
	challenge := startLogin(t, browser, srv.URL)
	if progress := pollLogin(t, browser, srv.URL, challenge.ID); progress.State != "pending" {
		t.Fatalf("state = %q, want pending", progress.State)
	}

	tap.approve()
	clock.advance(2 * time.Second)
	progress := pollLogin(t, browser, srv.URL, challenge.ID)
	if progress.State != "confirmed" || progress.Subject != "openid-1" {
		t.Fatalf("progress = %+v", progress)
	}

	// The credential is stored under the SOURCE's account (the TapTap openid),
	// not under Re0Auth's usr_ id.
	exists, err := deps.Vault.Exists(context.Background(), vault.Identity{Subject: "openid-1", Provider: "phigros"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("the source did not store the TapTap credential")
	}

	// The session now satisfies the Kit's Consent hook, so Re0Auth can bind and
	// fetch -- over OAuth 2.0, with no TapTap knowledge.
	fed, _ := newFederation(t, srv)
	binding := bindWithBrowser(t, fed, browser)
	if binding.Version == 0 {
		t.Fatal("bind produced no binding metadata")
	}

	res, err := fed.Fetch(context.Background(), federation.FetchRequest{User: "usr_1", Game: game, Resource: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != source || res.Degraded {
		t.Fatalf("fetch = %+v", res)
	}
	var profile map[string]any
	if err := json.Unmarshal(res.Data, &profile); err != nil {
		t.Fatal(err)
	}
	if profile["game"] != "phigros" {
		t.Fatalf("payload = %v", profile)
	}
}

// Without a session the authorize endpoint must deny, even with a valid client.
func TestTapTapAuthorizeWithoutSessionIsDenied(t *testing.T) {
	_, srv, _, _, _ := newTapTapSource(t)
	fed, _ := newFederation(t, srv)

	jar, _ := cookiejar.New(nil)
	anonymous := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	challenge, err := fed.BeginBind(context.Background(), "usr_1", game, source, "/")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := anonymous.Get(challenge.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// A login attempt that has expired must not confirm.
func TestTapTapLoginExpires(t *testing.T) {
	_, srv, tap, clock, _ := newTapTapSource(t)
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}

	challenge := startLogin(t, browser, srv.URL)
	tap.approve()
	clock.advance(20 * time.Minute) // beyond the device code's expires_in

	if progress := pollLogin(t, browser, srv.URL, challenge.ID); progress.State != "expired" {
		t.Fatalf("state = %q, want expired", progress.State)
	}
}

func startLogin(t *testing.T, browser *http.Client, baseURL string) referencesource.LoginChallenge {
	t.Helper()
	resp, err := browser.Post(baseURL+"/login/taptap/challenge", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge status = %d", resp.StatusCode)
	}
	var challenge referencesource.LoginChallenge
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.ID == "" || challenge.VerificationURL == "" {
		t.Fatalf("challenge = %+v", challenge)
	}
	return challenge
}

func pollLogin(t *testing.T, browser *http.Client, baseURL, id string) referencesource.LoginProgress {
	t.Helper()
	resp, err := browser.Get(baseURL + "/login/taptap/poll?id=" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll status = %d", resp.StatusCode)
	}
	var progress referencesource.LoginProgress
	if err := json.NewDecoder(resp.Body).Decode(&progress); err != nil {
		t.Fatal(err)
	}
	return progress
}

// bindWithBrowser binds using a browser that carries the source's session
// cookie, which is what makes the Kit's Consent hook succeed.
func bindWithBrowser(t *testing.T, fed federation.Service, browser *http.Client) federation.Binding {
	t.Helper()
	challenge, err := fed.BeginBind(context.Background(), "usr_1", game, source, "/")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := browser.Get(challenge.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	code, state := loc.Query().Get("code"), loc.Query().Get("state")
	if code == "" {
		t.Fatalf("no code in redirect %s", loc)
	}
	binding, _, err := fed.CompleteBind(context.Background(), "usr_1", state, code)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func replyJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

// offlineEnroller is a device-authorization enroller that never touches the
// network: every Start succeeds with a long-lived pending authorization.
type offlineEnroller struct{}

func (offlineEnroller) Start(context.Context) (taptapoauth.DeviceAuth, error) {
	return taptapoauth.DeviceAuth{
		DeviceID:        "device-1",
		DeviceCode:      "dc-1",
		UserCode:        "uc-1",
		VerificationURL: "https://taptap.example/approve",
		Interval:        time.Second,
		ExpiresAt:       time.Now().Add(time.Hour),
	}, nil
}

func (offlineEnroller) Poll(context.Context, taptapoauth.DeviceAuth) (tapsign.TapTapToken, error) {
	return tapsign.TapTapToken{}, errors.New("not approved")
}

// offlineRedeem satisfies tapsign.Service; the flood test never reaches it.
type offlineRedeem struct{}

func (offlineRedeem) Verify(context.Context, tapsign.Credential) error { return nil }
func (offlineRedeem) Rotate(context.Context, tapsign.Credential) (tapsign.Credential, error) {
	return tapsign.Credential{}, nil
}
func (offlineRedeem) Revoke(context.Context, tapsign.Credential) error { return nil }
func (offlineRedeem) Redeem(context.Context, tapsign.TapTapToken) (tapsign.Credential, error) {
	return tapsign.Credential{}, nil
}

// TestS06_5TapTapChallengeFloodIsCapped floods the unauthenticated challenge
// route with an offline enroller. On the unfixed code all 4096 requests return
// 200 and the attempts map holds 4096 entries; once capped, the tail is refused
// with 429 rather than being admitted.
func TestS06_5TapTapChallengeFloodIsCapped(t *testing.T) {
	login, err := referencesource.NewTapTapLogin(
		referencesource.TapTapConfig{},
		referencesource.TapTapDeps{Enroller: offlineEnroller{}, Redeem: offlineRedeem{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	login.Mount(mux, func(context.Context, referencesource.Principal) error { return nil })

	const challenges = 4096
	refused := 0
	for i := 0; i < challenges; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login/taptap/challenge", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
		case http.StatusTooManyRequests:
			if rec.Header().Get("Retry-After") == "" {
				t.Fatalf("challenge %d = 429 without Retry-After", i)
			}
			refused++
		default:
			t.Fatalf("challenge %d = %d, want 200 or 429: %s", i, rec.Code, rec.Body.String())
		}
	}
	if refused == 0 {
		t.Fatalf("%d challenges all returned 200: the pending-attempt map is unbounded", challenges)
	}
}
