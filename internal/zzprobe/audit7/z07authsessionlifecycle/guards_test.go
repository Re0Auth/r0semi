//go:build audit7

package z07authsessionlifecycle

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/auth"
)

// laggyStore is an scs.Store with a realistic per-operation cost. The in-memory
// development store commits instantly; the Postgres one is a network round trip.
// Widening the window is what makes the concurrent-read window observable.
type laggyStore struct {
	*z07Store
	lag time.Duration
}

func (s *laggyStore) Find(token string) ([]byte, bool, error) {
	time.Sleep(s.lag)
	return s.z07Store.Find(token)
}

func (s *laggyStore) Commit(token string, b []byte, expiry time.Time) error {
	time.Sleep(s.lag)
	return s.z07Store.Commit(token, b, expiry)
}

// TestZ07ConcurrentCSRFTokenCreationHandsOutTokensTheServerWillReject.
//
// auth.Manager.CSRFToken (auth.go:238-245) is a read-then-write with no
// serialization: two requests that both see an empty key both mint a token and
// both commit the session, so all but the last writer hand the browser a token
// that no longer matches the stored one. Nothing is corrupt — the write is
// refused with 403 — but a frontend that fetches its bootstrap
// (/v1/sessions/current) and its consent view
// (/v1/authorization_requests/{id}) in parallel can be handed two different
// tokens and then have its decision refused. The window is one store round trip,
// which is exactly what the durable store costs.
func TestZ07ConcurrentCSRFTokenCreationHandsOutTokensTheServerWillReject(t *testing.T) {
	inner := newZ07Store()
	store := &laggyStore{z07Store: inner, lag: 40 * time.Millisecond}
	manager := auth.NewManager(auth.Options{Secure: false, Store: store})
	env := newProbeEnv(t, probeOptions{Manager: manager})

	b := env.newBrowser()
	// Sign in without reading /v1/sessions/current: that read is itself the
	// first consumer of the CSRF token, and it would populate the key before the
	// concurrent readers ran.
	b.signInOrFail(probeProvider, "")
	// No CSRF token exists yet in this session: nothing has read it.

	const readers = 4
	tokens := make([]string, readers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp := b.get("/v1/sessions/current")
			body := bodyOf(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("sessions/current = %d (%s)", resp.StatusCode, body)
				return
			}
			tokens[i] = extractCSRF(body)
		}(i)
	}
	close(start)
	wg.Wait()

	distinct := map[string]bool{}
	for i, tok := range tokens {
		t.Logf("reader %d token %.8q", i, tok)
		if tok != "" {
			distinct[tok] = true
		}
	}
	t.Logf("%d concurrent first-readers received %d distinct CSRF tokens", readers, len(distinct))
	if len(distinct) <= 1 {
		t.Skipf("the window did not open: all readers saw one token")
	}

	accepted := 0
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		got := b.status(http.MethodPost, "/v1/sessions/sign_out", "", map[string]string{"X-CSRF-Token": tok})
		if got == http.StatusNoContent {
			accepted++
		}
	}
	if accepted >= len(distinct) {
		t.Fatalf("every distinct token was accepted, so the store did not serialize them")
	}
	t.Errorf("%d of the %d distinct tokens handed to the same browser were rejected by the server "+
		"(only %d validated): CSRF token creation is a last-writer-wins race across one store round trip, "+
		"so a frontend that reads its token from two endpoints in parallel can be refused",
		len(distinct)-accepted, len(distinct), accepted)
}

func extractCSRF(body string) string {
	const key = `"csrf_token":"`
	i := strings.Index(body, key)
	if i < 0 {
		return ""
	}
	rest := body[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// TestZ07SignOutIsAServerSideDeleteNotJustAnExpiredCookie: replay the live cookie
// after a sign-out over the real server.
func TestZ07SignOutIsAServerSideDeleteNotJustAnExpiredCookie(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	b.signIn(probeProvider)
	csrf := b.csrf()
	live := b.sessionCookie()
	if live == "" {
		t.Fatal("no live session cookie")
	}
	if got := b.status(http.MethodPost, "/v1/sessions/sign_out", "", map[string]string{"X-CSRF-Token": csrf}); got != http.StatusNoContent {
		t.Fatalf("sign_out = %d", got)
	}

	// Replay from a cookie-less browser so the jar's cleared cookie cannot hide
	// the answer.
	replay := env.newBrowser()
	req, err := http.NewRequest(http.MethodGet, env.server.URL+"/v1/sessions/current", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", live)
	resp, err := replay.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the signed-out session value still authenticates: %d (%s)", resp.StatusCode, body)
	}
}

// TestZ07ConsentHandleIsSingleUse: a decided handle cannot be described or
// decided again, so a replay of the consent POST finds nothing.
func TestZ07ConsentHandleIsSingleUse(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	b.signIn(probeProvider)
	csrf := b.csrf()

	id, _ := b.authorize("verifier-single-use", "st-single")
	if code, body := b.describeConsent(id); code != http.StatusOK {
		t.Fatalf("describe = %d (%s)", code, body)
	}
	if code, redirect := b.approveConsent(id, csrf); code != http.StatusOK || redirect == "" {
		t.Fatalf("approve = %d (%s)", code, redirect)
	}
	// The handle is consumed on approval.
	for _, probe := range []struct {
		name string
		fn   func() int
	}{
		{"describe again", func() int { c, _ := b.describeConsent(id); return c }},
		{"approve again", func() int { c, _ := b.approveConsent(id, csrf); return c }},
		{"deny", func() int {
			return b.status(http.MethodPost, "/v1/authorization_requests/"+url.PathEscape(id)+"/decision",
				`{"decision":"deny"}`,
				map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf})
		}},
	} {
		if got := probe.fn(); got == http.StatusOK {
			t.Errorf("%s on a consumed consent handle = 200", probe.name)
		} else {
			t.Logf("%s on a consumed consent handle = %d", probe.name, got)
		}
	}
}

// TestZ07BindHandleIsOwnedByTheAccountThatStartedIt is the federation half of
// ADR-0004, at the real entry point. It works without a reachable upstream
// because the callback's ownership check runs before any network call.
func TestZ07BindHandleIsOwnedByTheAccountThatStartedIt(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()

	env.setIdentity("bind-a")
	b.signIn(probeProvider)

	resp := b.get("/bind?game=phigros&source=fake")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("bind start = %d (%s)", resp.StatusCode, bodyOf(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatalf("the bind redirect carried no state: %q", loc.String())
	}
	t.Logf("bind started with state %s…", state[:6])

	// Same browser, second account, no sign-out.
	env.setIdentity("bind-b")
	b.signIn(probeProvider)

	got := b.status(http.MethodGet, "/auth/upstream/phigros/fake/callback?state="+url.QueryEscape(state)+"&code=c", "", nil)
	if got != http.StatusBadRequest {
		t.Errorf("account B completed account A's bind flow: callback = %d, want 400", got)
	} else {
		t.Logf("account B is refused A's bind handle with 400, as designed")
	}
}

// TestZ07ExportIsPersonalAndUncacheable: the export is a GET, so a cross-site
// top-level navigation does send the session cookie (SameSite=Lax). What keeps it
// private is that the response cannot be read cross-origin and must not be
// cached.
func TestZ07ExportIsPersonalAndUncacheable(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	user := b.signIn(probeProvider)

	resp := b.get("/v1/account/export")
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d (%s)", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control on the account export = %q, want no-store", got)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options on the account export = %q, want DENY", got)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Errorf("Content-Type = %q", got)
	}
	if !strings.Contains(body, user) {
		t.Errorf("the export does not name the signed-in account")
	}
	// No credential may be in it: the notice says so, and the view builders are
	// shared with the list endpoints.
	for _, forbidden := range []string{"access_token", "refresh_token", "client_secret", "stoken"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the export contains %q", forbidden)
		}
	}

	// A cookie-less caller gets nothing.
	bare := env.newBrowser()
	if got := bare.status(http.MethodGet, "/v1/account/export", "", nil); got != http.StatusUnauthorized {
		t.Errorf("the export without a session = %d, want 401", got)
	}
}
