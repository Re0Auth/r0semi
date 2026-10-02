package tapsign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/audit"
)

// AUDIT9 / S07-1 — credential-bearing requests must not trust the injected Doer's
// redirect policy: net/http's default policy copies CUSTOM auth headers across
// hosts, and a 307/308 replays the form body verbatim.
//
// tapsign sends the long-lived session token as X-LC-Session and the app key as
// X-LC-Key (client.go). With an *http.Client whose CheckRedirect is nil — the
// stdlib default, and what many callers inject — net/http follows the redirect
// and its header copier keeps every header outside its fixed sensitive set.
//
// This was a leak demonstrator and is now the regression guard: after the fix the
// constructor wraps the Doer in httpclient.RedirectGuard, so the hop is refused.
func TestAudit9CredentialHeadersDoNotFollowACrossHostRedirect(t *testing.T) {
	origin, _, leaked := redirectPair(t)
	c := newClient(
		Config{BaseURL: origin.URL, AppID: "test-app", AppKey: "test-key"},
		origin.Client(), // CheckRedirect is nil: the stdlib default policy
		audit.NewMemoryLogger(),
	)

	if err := c.Verify(context.Background(), testCred()); err == nil {
		t.Fatalf("Verify followed a cross-host redirect; the target saw X-LC-Session=%q X-LC-Key=%q",
			leaked.Get("X-LC-Session"), leaked.Get("X-LC-Key"))
	}
	if leaked != nil {
		if got := leaked.Get("X-LC-Session"); got != "" {
			t.Errorf("X-LC-Session reached the redirect target: %q", got)
		}
		if got := leaked.Get("X-LC-Key"); got != "" {
			t.Errorf("X-LC-Key reached the redirect target: %q", got)
		}
	}
}

// The control: with the guard removed the same bare client and the same redirect
// DO copy both custom headers. Without it the guard test above would pass for the
// wrong reason (a redirect that never happened).
func TestAudit9ControlABareClientStillLeaks(t *testing.T) {
	origin, _, leaked := redirectPair(t)
	req, err := http.NewRequest(http.MethodGet, origin.URL+"/users/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-LC-Id", "test-app")
	req.Header.Set("X-LC-Key", "test-key")
	req.Header.Set("X-LC-Session", "test-session-token")

	// The very Doer the adapter was handed, without the constructor's guard.
	resp, err := origin.Client().Do(req)
	if err != nil {
		t.Fatalf("the bare client did not follow the redirect: %v", err)
	}
	_ = resp.Body.Close()
	if leaked == nil || leaked.Get("X-LC-Session") == "" {
		t.Fatal("control: the bare client did not copy the custom header, so the guard proves nothing")
	}
}

// redirectPair starts an origin that 302s to a DIFFERENT HOSTNAME on the same
// loopback address (so net/http sees a cross-host redirect), and a target that
// records the headers it was sent.
func redirectPair(t *testing.T) (origin, target *httptest.Server, leaked *http.Header) {
	t.Helper()
	var got http.Header
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL+"/users/me", http.StatusFound)
	}))
	t.Cleanup(origin.Close)
	return origin, target, &got
}
