//go:build audit7

package z07authsessionlifecycle

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Re0Auth/r0semi/internal/auth"
)

// z07Store is an scs.Store that counts how many server-side session rows the
// service committed, so a probe can attribute storage to a request that never
// authenticated.
type z07Store struct {
	mu      sync.Mutex
	commits int
	deletes int
	maxLen  int
	data    map[string][]byte
}

func newZ07Store() *z07Store { return &z07Store{data: map[string][]byte{}} }

func (s *z07Store) Find(token string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[token]
	return b, ok, nil
}

func (s *z07Store) Commit(token string, b []byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commits++
	if len(b) > s.maxLen {
		s.maxLen = len(b)
	}
	s.data[token] = append([]byte(nil), b...)
	return nil
}

func (s *z07Store) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	delete(s.data, token)
	return nil
}

func (s *z07Store) counts() (commits, deletes, maxLen int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commits, s.deletes, s.maxLen
}

// TestZ07SessionCookieShapeOverARealServer pins every cookie attribute on the
// wire, in both deployment shapes, and records the one branch that drops the
// __Host- prefix.
func TestZ07SessionCookieShapeOverARealServer(t *testing.T) {
	for _, tc := range []struct {
		secure   bool
		wantName string
	}{
		{true, "__Host-r0semi_session"},
		{false, "r0semi_session"},
	} {
		env := newProbeEnv(t, probeOptions{Secure: tc.secure})
		b := env.newBrowser()
		// A real anonymous flow start writes session state, so a Set-Cookie must
		// follow.
		resp := b.get("/auth/" + string(probeProvider) + "/start")
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("start = %d", resp.StatusCode)
		}
		var got *http.Cookie
		for _, c := range resp.Cookies() {
			if strings.Contains(c.Name, "session") {
				got = c
			}
		}
		if got == nil {
			t.Fatalf("secure=%v: the flow start wrote no session cookie", tc.secure)
		}
		t.Logf("secure=%v cookie=%s HttpOnly=%v Secure=%v SameSite=%v Path=%q Domain=%q",
			tc.secure, got.Name, got.HttpOnly, got.Secure, got.SameSite, got.Path, got.Domain)

		if got.Name != tc.wantName {
			t.Errorf("secure=%v: cookie name = %q, want %q", tc.secure, got.Name, tc.wantName)
		}
		if !got.HttpOnly {
			t.Errorf("secure=%v: HttpOnly is off", tc.secure)
		}
		if got.Secure != tc.secure {
			t.Errorf("secure=%v: Secure = %v", tc.secure, got.Secure)
		}
		if got.SameSite != http.SameSiteLaxMode {
			t.Errorf("secure=%v: SameSite = %v, want Lax", tc.secure, got.SameSite)
		}
		if got.Path != "/" {
			t.Errorf("secure=%v: Path = %q, want /", tc.secure, got.Path)
		}
		if got.Domain != "" {
			t.Errorf("secure=%v: Domain = %q, want empty (a Domain would defeat __Host-)", tc.secure, got.Domain)
		}
	}
}

// TestZ07SignOutAnswersForbiddenToARequestThatHasNoSession — 原为发现演示，现为回归守卫.
//
// It used to record an inconsistency the plane's own contract made visible: every
// other write on the account answered 401 "unauthenticated" to a caller with no
// session, while POST /v1/sessions/sign_out answered 403 "missing or invalid CSRF
// token", because it checked CSRF before the session. No CSRF token can exist
// without a session, so the 403 branch was the only one an anonymous caller could
// reach (Z07-6).
//
// The endpoint now checks the session first and answers 401 like every other
// unauthenticated write. This probe is the regression guard for that ordering: an
// anonymous sign_out is refused as unauthenticated and must NOT be answered 403
// for a CSRF token the caller could never have obtained.
func TestZ07SignOutAnswersForbiddenToARequestThatHasNoSession(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()

	type probe struct {
		method, target, body string
		hdr                  map[string]string
	}
	jsonHdr := map[string]string{"Content-Type": "application/json"}

	cases := []struct {
		name string
		p    probe
		want int
		note string
	}{
		{
			name: "sign_out", want: http.StatusUnauthorized,
			p:    probe{http.MethodPost, "/v1/sessions/sign_out", "", nil},
			note: "the session is checked before CSRF (Z07-6)",
		},
		{
			name: "delete_account", want: http.StatusUnauthorized,
			p:    probe{http.MethodDelete, "/v1/account", `{"acknowledge":"deletes_my_account"}`, jsonHdr},
			note: "the session is checked first",
		},
		{
			name: "unlink_identity", want: http.StatusUnauthorized,
			p: probe{http.MethodDelete, "/v1/identities/idn_x", "", nil},
		},
		{
			name: "revoke_grant", want: http.StatusUnauthorized,
			p: probe{http.MethodDelete, "/v1/grants/cli", "", nil},
		},
		{
			name: "authorization_decision", want: http.StatusUnauthorized,
			p: probe{http.MethodPost, "/v1/authorization_requests/x/decision", `{"decision":"approve"}`, jsonHdr},
		},
		{
			name: "device_decision", want: http.StatusUnauthorized,
			p: probe{http.MethodPost, "/v1/device/decision", `{"user_code":"AAAA-AAAA","decision":"approve"}`, jsonHdr},
		},
	}

	var signOutStatus int
	for _, tc := range cases {
		got := b.status(tc.p.method, tc.p.target, tc.p.body, tc.p.hdr)
		if tc.name == "sign_out" {
			signOutStatus = got
		}
		if got != tc.want {
			t.Errorf("%s = %d, want %d (%s)", tc.name, got, tc.want, tc.note)
			continue
		}
		t.Logf("%s = %d as expected", tc.name, got)
	}
	if signOutStatus == http.StatusForbidden {
		t.Errorf("POST /v1/sessions/sign_out with no session at all = 403 (CSRF): the endpoint must " +
			"refuse an anonymous caller as unauthenticated, because no CSRF token can exist without a session")
	}
	if signOutStatus != http.StatusUnauthorized {
		t.Errorf("POST /v1/sessions/sign_out with no session = %d, want 401 unauthenticated", signOutStatus)
	}
}

// TestZ07SessionIdRotationOnSignIn is the session-fixation guard: the pre-login
// id must not become the authenticated one, and the pre-login value must not
// keep resolving.
func TestZ07SessionIdRotationOnSignIn(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()

	// A pre-login browser: the login plane puts flow state in the session, which
	// is what makes the cookie valuable to a fixator.
	resp := b.get("/auth/" + string(probeProvider) + "/start")
	resp.Body.Close()
	pre := b.sessionCookie()
	if pre == "" {
		t.Fatal("no pre-login session cookie")
	}

	b.signIn(probeProvider)
	post := b.sessionCookie()
	if post == "" {
		t.Fatal("no post-login session cookie")
	}
	if post == pre {
		t.Fatalf("the session id did not rotate on sign-in (%s)", pre)
	}

	// Replay the pre-login value in a second browser (its own jar, so the live
	// cookie is not sent).
	other := env.newBrowser()
	req, err := http.NewRequest(http.MethodGet, env.server.URL+"/v1/sessions/current", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", pre)
	otherResp, err := other.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer otherResp.Body.Close()
	if otherResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the pre-login session value still authenticates: /v1/sessions/current = %d",
			otherResp.StatusCode)
	}
}

// TestZ07NoCSRFTokenIsHandedOutBeforeSignIn is the CSRF-fixation guard. The
// token survives scs.RenewToken (auth.go:238-255 never rotates it), so the only
// thing that keeps a fixator from learning the victim's token is that no
// unauthenticated response carries one. This enumerates every endpoint that
// could.
func TestZ07NoCSRFTokenIsHandedOutBeforeSignIn(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()

	for _, target := range []string{
		"/v1/sessions/current",
		"/v1/authorization_requests/x",
		"/v1/device/verification",
		"/v1/identities",
		"/v1/grants",
		"/v1/account/export",
		"/v1/bindings",
		"/v1/idp/providers",
		"/v1/me",
	} {
		resp := b.get(target)
		body := bodyOf(t, resp)
		if strings.Contains(body, "csrf_token") {
			t.Errorf("GET %s handed an unauthenticated caller a csrf_token (status %d): %s",
				target, resp.StatusCode, body)
			continue
		}
		t.Logf("GET %s = %d, no csrf_token", target, resp.StatusCode)
	}
}

// TestZ07CSRFTokenIsRebornWithANewSession: destroying the session and signing in
// again must not reuse the old token, so a token learned from a previous session
// is worthless.
func TestZ07CSRFTokenIsRebornWithANewSession(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	b.signIn(probeProvider)
	first := b.csrf()

	if got := b.status(http.MethodPost, "/v1/sessions/sign_out", "", map[string]string{"X-CSRF-Token": first}); got != http.StatusNoContent {
		t.Fatalf("sign_out = %d, want 204", got)
	}

	b.signIn(probeProvider)
	second := b.csrf()
	if second == first {
		t.Errorf("the CSRF token survived a full sign-out/sign-in cycle (%s)", first)
	} else {
		t.Logf("the CSRF token changed across sign-out/sign-in")
	}
	// The old value must no longer validate.
	if got := b.status(http.MethodPost, "/v1/sessions/sign_out", "", map[string]string{"X-CSRF-Token": first}); got != http.StatusForbidden {
		t.Errorf("the pre-sign-out CSRF token still validates: %d", got)
	}
}

// TestZ07UnsafeMethodsAreRefusedWithoutTheCSRFHeader walks every write endpoint
// with a live session and no token: each must fail closed, and none may perform
// its action.
func TestZ07UnsafeMethodsAreRefusedWithoutTheCSRFHeader(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	user := b.signIn(probeProvider)

	jsonHdr := map[string]string{"Content-Type": "application/json"}
	writes := []struct {
		name, method, target, body string
		hdr                        map[string]string
	}{
		{"sign_out", http.MethodPost, "/v1/sessions/sign_out", "", nil},
		{"delete_account", http.MethodDelete, "/v1/account", `{"acknowledge":"deletes_my_account"}`, jsonHdr},
		{"unlink_identity", http.MethodDelete, "/v1/identities/idn_x", "", nil},
		{"revoke_grant", http.MethodDelete, "/v1/grants/cli", "", nil},
		{"unbind", http.MethodDelete, "/v1/bindings/phigros/fake", "", nil},
		{"cascade_revocation", http.MethodPost, "/v1/bindings/phigros/fake/cascade_revocation",
			`{"acknowledge":"signs_out_all_devices"}`, jsonHdr},
		{"authorization_decision", http.MethodPost, "/v1/authorization_requests/x/decision",
			`{"decision":"approve"}`, jsonHdr},
		{"device_decision", http.MethodPost, "/v1/device/decision",
			`{"user_code":"AAAA-AAAA","decision":"approve"}`, jsonHdr},
	}
	for _, w := range writes {
		got := b.status(w.method, w.target, w.body, w.hdr)
		if got != http.StatusForbidden {
			t.Errorf("%s without X-CSRF-Token = %d, want 403", w.name, got)
			continue
		}
		t.Logf("%s refused with 403 as designed", w.name)
	}

	// The session must be intact: nothing above was allowed to act.
	resp := b.get("/v1/sessions/current")
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, user) {
		t.Fatalf("the session did not survive the refused writes: %d %s", resp.StatusCode, body)
	}
}

// TestZ07AnonymousTrafficDoesNotAllocateServerSideSessionRows measures the
// storage a completely unauthenticated caller can cause. A session row that
// survives for the session lifetime would be an anonymous amplification; a
// public read must not create one.
func TestZ07AnonymousTrafficDoesNotAllocateServerSideSessionRows(t *testing.T) {
	store := newZ07Store()
	manager := auth.NewManager(auth.Options{Secure: false, Store: store})
	env := newProbeEnv(t, probeOptions{Manager: manager})
	b := env.newBrowser()

	before, _, _ := store.counts()

	// Three public/unauthenticated reads that need no session at all.
	for _, target := range []string{"/v1/idp/providers", "/.well-known/openid-configuration", "/healthz"} {
		resp := b.get(target)
		resp.Body.Close()
	}
	afterPublic, _, _ := store.counts()
	if afterPublic != before {
		t.Errorf("unauthenticated reads to session-free endpoints committed %d server-side session rows "+
			"(a durable row per anonymous request, held for the session lifetime)",
			afterPublic-before)
	} else {
		t.Logf("three anonymous session-free reads committed no session rows")
	}

	// The control: an anonymous flow start genuinely needs server-side state, so
	// it must commit (otherwise the counting store is simply not wired).
	resp := b.get("/auth/" + string(probeProvider) + "/start")
	resp.Body.Close()
	afterStart, _, _ := store.counts()
	if afterStart == afterPublic {
		t.Fatalf("an anonymous /auth start committed no session row: the probe is not measuring the store")
	}
	t.Logf("anonymous /auth start committed %d session row(s)", afterStart-afterPublic)
}

// TestZ07SignOutLeavesTheIssuedTokensAlive records the documented boundary:
// POST /v1/sessions/sign_out ends the browser session only (docs/account-model.md
// §, "清 Cookie、失效服务端会话"); the OP tokens keep working until their own TTL.
// Revoking them is a separate, explicit action (DELETE /v1/grants/{client_id}).
func TestZ07SignOutLeavesTheIssuedTokensAlive(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()
	b.signIn(probeProvider)
	csrf := b.csrf()

	// RFC 7636: a verifier is 43–128 unreserved characters.
	const verifier = "verifier-token-for-the-signout-liveness-probe-0000000000"
	code := b.completeAuthorize("", csrf, verifier, "st-token")
	tok := b.exchangeCode(code, verifier)
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token in %v", tok)
	}
	authz := map[string]string{"Authorization": "Bearer " + access}

	if got := b.status(http.MethodGet, "/v1/me", "", authz); got != http.StatusOK {
		t.Fatalf("GET /v1/me with a fresh access token = %d, want 200", got)
	}
	if got := b.status(http.MethodPost, "/v1/sessions/sign_out", "", map[string]string{"X-CSRF-Token": csrf}); got != http.StatusNoContent {
		t.Fatalf("sign_out = %d", got)
	}
	// The browser session is gone...
	if got := b.status(http.MethodGet, "/v1/grants", "", nil); got != http.StatusUnauthorized {
		t.Errorf("GET /v1/grants after sign-out = %d, want 401", got)
	}
	// ...but the issued access token is a different thing and still works. This
	// is the documented boundary (sign-out is not a token revocation), recorded
	// so a regression that silently changes it would be visible.
	if got := b.status(http.MethodGet, "/v1/me", "", authz); got == http.StatusOK {
		t.Logf("sign-out left the issued access token live, as documented: sign-out ends the browser " +
			"session; revoking a client's access is DELETE /v1/grants/{client_id}")
	} else {
		t.Logf("the access token stopped working after sign-out: /v1/me = %d", got)
	}
}

// TestZ07ConsentHandleCannotBeApprovedByAnotherAccountInTheSameBrowser is the
// ADR-0004 guard, driven through the real business plane: account A starts an
// authorization, account B signs in on the same browser without a sign-out, and
// B must not be able to describe or approve A's handle — while B's own handle
// must still work, so this is ownership and not a blanket refusal.
func TestZ07ConsentHandleCannotBeApprovedByAnotherAccountInTheSameBrowser(t *testing.T) {
	env := newProbeEnv(t, probeOptions{})
	b := env.newBrowser()

	env.setIdentity("alpha")
	b.signIn(probeProvider)
	aHandle, _ := b.authorize("verifier-a", "st-a")

	// Same browser, second account, no sign-out: SignIn rotates the session id
	// and, by design, keeps the session's values.
	env.setIdentity("beta")
	beta := b.signIn(probeProvider)
	csrf := b.csrf()

	if code, body := b.describeConsent(aHandle); code != http.StatusNotFound {
		t.Errorf("account B described account A's consent handle: %d (%s)", code, body)
	} else {
		t.Logf("A's handle is 404 to B, as designed")
	}
	if code, redirect := b.approveConsent(aHandle, csrf); code != http.StatusNotFound {
		t.Errorf("account B approved account A's consent handle: %d (%s)", code, redirect)
	} else {
		t.Logf("A's handle is not approvable by B, as designed")
	}

	// Positive control: B's own handle works.
	betaHandle, _ := b.authorize("verifier-b", "st-b")
	if code, body := b.describeConsent(betaHandle); code != http.StatusOK {
		t.Fatalf("B could not describe its own handle: %d (%s)", code, body)
	}
	if code, redirect := b.approveConsent(betaHandle, csrf); code != http.StatusOK || redirect == "" {
		t.Fatalf("B could not approve its own handle: %d (%s)", code, redirect)
	}
	t.Logf("B approved its own handle as account %s", beta)
}
