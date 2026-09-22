package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

// viteBaseRe finds `base: '/app'` in the Vite config, tolerating quote style and
// whitespace so that reformatting the config does not fail this test.
var viteBaseRe = regexp.MustCompile(`base:\s*['"]([^'"]+)['"]`)

// The mount prefix and the build prefix must be the same string, and nothing will
// tell us if they stop being. A frontend built for /app but served at /foo still
// loads its shell; the client router then looks for /foo/consent, finds no route
// matching the baked-in base, and renders nothing. A blank page is not a useful
// failure mode, so the two files are compared here instead.
func TestBasePathMatchesViteConfig(t *testing.T) {
	raw, err := os.ReadFile("../../web/vite.config.ts")
	if err != nil {
		t.Fatalf("read web/vite.config.ts: %v", err)
	}
	m := viteBaseRe.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("web/vite.config.ts sets no paths.base; the app would be built for the " +
			"root, which is where the protocol plane lives")
	}
	if m[1] != BasePath {
		t.Fatalf("web/vite.config.ts builds for %q but this package mounts at %q", m[1], BasePath)
	}
}

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                    {Data: []byte("<!doctype html><title>shell</title>")},
		"_app/immutable/entry/start.js": {Data: []byte("export const a = 1")},
		"_app/immutable/assets/app.css": {Data: []byte("body{}")},
	}
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestHandlerServesFilesAndFallsBackToShell(t *testing.T) {
	h := Handler(testFS())

	cases := []struct {
		target      string
		wantBody    string
		wantCache   string
		wantCSP     bool
		description string
	}{
		{"/app/", "shell", "no-cache", true, "the mount root"},
		{"/app/consent", "shell", "no-cache", true, "a client route: no file, so the shell"},
		{"/app/device", "shell", "no-cache", true, "another client route"},
		{"/app/nothing/here", "shell", "no-cache", true, "an unknown path still gets the shell"},
		{"/app/_app/immutable/entry/start.js", "export const a", "public, max-age=31536000, immutable", false, "a hashed asset"},
		{"/app/_app/immutable/assets/app.css", "body{}", "public, max-age=31536000, immutable", false, "another hashed asset"},
	}
	for _, tc := range cases {
		rec := get(t, h, tc.target)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %s = %d, want 200", tc.description, tc.target, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.wantBody) {
			t.Errorf("%s: %s body = %q, want it to contain %q", tc.description, tc.target, rec.Body.String(), tc.wantBody)
		}
		if got := rec.Header().Get("Cache-Control"); got != tc.wantCache {
			t.Errorf("%s: %s Cache-Control = %q, want %q", tc.description, tc.target, got, tc.wantCache)
		}
		if got := rec.Header().Get("Content-Security-Policy") == shellCSP; got != tc.wantCSP {
			t.Errorf("%s: %s CSP set = %v, want %v", tc.description, tc.target, got, tc.wantCSP)
		}
	}
}

// A traversal must not escape the embedded filesystem.
//
// Two independent things stop it, which is why the expected outcome is a flat
// rejection rather than the shell:
//
//   - our own path.Clean turns ".." into an ordinary missing name, and
//     fs.Stat would reject a name that still contained one;
//   - net/http's file server independently errors on any request path containing
//     "..", before it looks at the name it was handed.
//
// In production a ".." never reaches here at all, because ServeMux cleans the
// path first. This is the layer underneath that.
func TestHandlerNeutralizesTraversal(t *testing.T) {
	h := Handler(testFS())
	for _, target := range []string{
		"/app/../../../etc/passwd",
		"/app/_app/../../../../index.html",
		"/app/..%2f..%2fetc/passwd",
	} {
		rec := httptest.NewRecorder()
		// Deliberately no URL.Path override: the request parser decodes %2f into a
		// separator, which is what a real server sees. Handing the handler an
		// encoded path directly would be testing a request that cannot arrive.
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400 (refused)", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "root:") {
			t.Errorf("%s escaped the embedded filesystem", target)
		}
	}
}

// There are no directory listings: a path that names a directory is not a file,
// so it answers with the shell.
func TestHandlerDoesNotListDirectories(t *testing.T) {
	rec := get(t, Handler(testFS()), "/app/_app/immutable")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with the shell", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "shell") {
		t.Fatalf("body = %q, want the shell rather than a listing", rec.Body.String())
	}
}

func TestHandlerRejectsWrites(t *testing.T) {
	rec := httptest.NewRecorder()
	h := Handler(testFS())
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/app/consent", strings.NewReader("x")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q", got)
	}
}

// A binary built without the frontend must say so, not 404 or serve an empty page.
func TestUnbuiltFrontendExplainsItself(t *testing.T) {
	unbuilt := fstest.MapFS{".gitkeep": {Data: []byte("placeholder")}}
	if Built(unbuilt) {
		t.Fatal("Built reported a frontend that is not there")
	}
	rec := get(t, Handler(unbuilt), "/app/consent")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "npm run build") {
		t.Fatalf("body = %q, want the build instructions", body)
	}
}

// The embedded filesystem is what ships, so it has to be readable. This is also
// the test that fails if the placeholder is ever removed and the embed directive
// stops matching anything, which would break `go build` for everyone.
func TestEmbeddedFSAccessible(t *testing.T) {
	fsys := FS()
	if fsys == nil {
		t.Fatal("FS returned nil")
	}
	if _, err := fsys.Open("."); err != nil {
		t.Fatalf("open embedded root: %v", err)
	}
}
