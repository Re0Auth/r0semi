package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Re0Auth/r0semi/internal/ratelimit"
	"github.com/Re0Auth/r0semi/internal/webui"
)

// withFrontend mounts a stand-in build on an otherwise fully wired server.
func withFrontend(t *testing.T, fsys fstest.MapFS) *Server {
	t.Helper()
	cfg := newFullConfig(t)
	// The route shape is what is under test here, not the limiter.
	cfg.Limiter = nil
	cfg.Frontend = fsys
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func testFrontend() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                    {Data: []byte("<!doctype html><title>app shell</title>")},
		"_app/immutable/entry/start.js": {Data: []byte("export const a = 1")},
	}
}

func status(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// Signing in must not deliver the user to a 404.
//
// The login plane's return_to defaults to "/", so the root has to lead somewhere
// real whenever there is a frontend to lead to. Nothing else in the test suite
// noticed this: the Go tests assert status codes on the login redirect, and the
// 404 is one hop further along, in a browser.
func TestRootRedirectsToFrontend(t *testing.T) {
	srv := withFrontend(t, testFrontend())
	rec := status(t, srv.Handler(), "/")
	if rec.Code != http.StatusFound {
		t.Fatalf("GET / = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != webui.BasePath+"/" {
		t.Fatalf("Location = %q, want %q", got, webui.BasePath+"/")
	}
}

// Without a frontend the root stays a 404: there is no page there, and inventing
// one would hide a misconfiguration rather than report it.
func TestRootStaysNotFoundWithoutFrontend(t *testing.T) {
	srv := newTestEnv(t).srv
	if rec := status(t, srv.Handler(), "/"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET / = %d, want 404", rec.Code)
	}
}

// The client router needs the shell for paths that are not files. The risk of
// granting that is that the mount starts swallowing API 404s, so the API's own
// error shapes are asserted here to prove it does not.
//
// The root path is neither plane and answers plain text (see
// docs/browser-plane-decision.md). What matters for this test is unchanged: it is
// not the shell.
func TestFrontendMountDoesNotSwallowAPIRoutes(t *testing.T) {
	srv := withFrontend(t, testFrontend())
	handler := srv.Handler()

	cases := []struct {
		target      string
		wantType    string
		wantBody    string
		description string
	}{
		{"/app/consent", "text/html", "app shell", "a client route renders the shell"},
		{"/app/anything/at/all", "text/html", "app shell", "an unknown client route still renders the shell"},
		{"/v1/nope", "problem+json", "", "an unknown business-plane path is still problem+json"},
		{"/oauth/nope", "application/json", "", "an unknown protocol-plane path is still an OAuth error"},
		{"/nope", "text/plain", "", "an unknown root path is on no plane, and is not the shell"},
	}
	for _, tc := range cases {
		rec := status(t, handler, tc.target)
		if got := rec.Header().Get("Content-Type"); !strings.Contains(got, tc.wantType) {
			t.Errorf("%s: %s Content-Type = %q, want it to contain %q", tc.description, tc.target, got, tc.wantType)
		}
		if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Errorf("%s: %s body = %q, want it to contain %q", tc.description, tc.target, rec.Body.String(), tc.wantBody)
		}
	}
}

// The header must not restate what the build's own <meta> policy already says.
//
// Both are enforced when both are present, so a header directive that the meta
// policy allows by hash — `script-src 'self'` without the hash, say — silently
// wins and blocks the app's bootstrap. The symptom is a blank page, not a
// policy error anyone would see, so the shape is asserted here rather than left
// to review.
func TestFrontendHTMLPolicyAddsNothingItShouldNot(t *testing.T) {
	srv := withFrontend(t, testFrontend())
	html := status(t, srv.Handler(), "/app/consent")
	got := html.Header().Get("Content-Security-Policy")

	if !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("shell CSP = %q, must forbid framing", got)
	}
	// The rest belongs to SvelteKit, which is the only party that knows the
	// hashes it emitted.
	for _, forbidden := range []string{"script-src", "style-src", "default-src", "connect-src"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("shell CSP restates %q, which would override the build's meta policy: %q", forbidden, got)
		}
	}
}

// The API's JSON keeps its own single-directive policy, unchanged by a frontend
// being mounted.
func TestFrontendLeavesAPIPolicyAlone(t *testing.T) {
	srv := withFrontend(t, testFrontend())
	json := status(t, srv.Handler(), "/v1/nope")
	if got := json.Header().Get("Content-Security-Policy"); got != cspFrameAncestorsNone {
		t.Fatalf("api CSP = %q, want %q", got, cspFrameAncestorsNone)
	}
}

// A rate-limited browser request must still be answered in the plane's shape, and
// the frontend must not change that.
func TestFrontendDoesNotChangePlaneErrors(t *testing.T) {
	cfg := newFullConfig(t)
	cfg.Limiter = ratelimit.New(0.001, 1)
	cfg.Frontend = testFrontend()
	limited, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := limited.Handler()

	// Spend the token, then assert the shape of the rejection.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		handler.ServeHTTP(rec, req)
		if i == 1 {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("second request = %d, want 429", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "problem+json") {
				t.Fatalf("Content-Type = %q, want problem+json", got)
			}
		}
	}
}
