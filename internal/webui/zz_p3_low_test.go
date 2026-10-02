package webui

// P3 probes for the static surface: the shell's cache validator (S12-8 /
// A-FE-1), Range on a document (A-FE-2), the document policy on every HTML
// response (A-FE-6), the default cache directive (Z08-3), Vary on immutable
// assets (Z08-5), and how many filesystem lookups one request costs (S12-11).
//
// They carry no build tag: `go test ./internal/webui/` runs them. Each one is
// written to fail on the code as it stood before its fix, so the red run is the
// evidence for the green one.

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/alexedwards/scs/v2"
)

// --- S12-8 / A-FE-1: the shell must carry a cache validator ----------------

// A `no-cache` response is revalidated on every navigation. Without a validator
// there is nothing to revalidate against, so each load transfers the whole
// document; with one, the server answers 304 and sends no body.
func TestP3ShellCarriesAStrongValidator(t *testing.T) {
	h := Handler(testFS())

	first := get(t, h, "/app/consent")
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatalf("the shell is served %q with no ETag, so `no-cache` can never become a 304 "+
			"and every navigation re-sends the %d-byte document",
			first.Header().Get("Cache-Control"), first.Body.Len())
	}
	if strings.HasPrefix(tag, "W/") || !strings.HasPrefix(tag, `"`) || !strings.HasSuffix(tag, `"`) {
		t.Fatalf("ETag = %q, want a strong, quoted validator (a weak one cannot serve a range)", tag)
	}
	if again := get(t, h, "/app/consent").Header().Get("ETag"); again != tag {
		t.Fatalf("the validator is not stable across requests: %q then %q", tag, again)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/app/consent", nil)
	req.Header.Set("If-None-Match", tag)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match with the server's own ETag = %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("the 304 carried a %d-byte body", rec.Body.Len())
	}

	// The validator identifies the bytes: a different shell must not reuse it.
	other := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>a different shell</title>")}}
	otherTag := get(t, Handler(other), "/app/").Header().Get("ETag")
	if otherTag == "" || otherTag == tag {
		t.Errorf("a different shell reports ETag %q; want a different one from %q", otherTag, tag)
	}
}

// --- A-FE-2: a Range must not hand out half a document ---------------------

// The shell is one representation, not a byte range: a client that asked for a
// range would otherwise receive the document without the <meta> policy that
// governs the script inside it. Hashed assets keep range support -- resuming a
// large file is legitimate.
func TestP3RangeCannotTruncateTheShell(t *testing.T) {
	h := Handler(testFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/app/consent", nil)
	req.Header.Set("Range", "bytes=0-3")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Range on the shell = %d (Content-Range %q), want 200 with the whole document",
			rec.Code, rec.Header().Get("Content-Range"))
	}
	if rec.Header().Get("Content-Range") != "" {
		t.Errorf("a 200 carried Content-Range %q", rec.Header().Get("Content-Range"))
	}
	if !strings.Contains(rec.Body.String(), "</title>") {
		t.Errorf("the shell body was truncated to %q", rec.Body.String())
	}

	// Anti-vacuity: the asset next door still answers a range, so this is a
	// decision about documents and not a handler that ignores Range everywhere.
	asset := httptest.NewRecorder()
	assetReq := httptest.NewRequest(http.MethodGet, "/app/_app/immutable/entry/start.js", nil)
	assetReq.Header.Set("Range", "bytes=0-6")
	h.ServeHTTP(asset, assetReq)
	if asset.Code != http.StatusPartialContent {
		t.Errorf("Range on an asset = %d, want 206 (range support must survive)", asset.Code)
	}
	if got := asset.Body.String(); got != "export " {
		t.Errorf("asset range body = %q, want %q", got, "export ")
	}
}

// --- A-FE-6: the framing guard belongs on every document -------------------

// The package keys its policy on the file being text/html, not on the file being
// named index.html: a build that ships a second document would otherwise send it
// with no framing policy at all.
func TestP3EveryHTMLDocumentCarriesTheFramingGuard(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte("<!doctype html><title>shell</title>")},
		"extra.html": {Data: []byte("<!doctype html><title>extra</title>")},
		"plain.txt":  {Data: []byte("text")},
	}
	h := Handler(fsys)

	for _, tc := range []struct {
		target   string
		wantCSP  bool
		wantType string
	}{
		{"/app/", true, "text/html"},
		{"/app/consent", true, "text/html"},
		{"/app/extra.html", true, "text/html"},
		{"/app/plain.txt", false, "text/plain"},
	} {
		rec := get(t, h, tc.target)
		got := rec.Header().Get("Content-Security-Policy")
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), tc.wantType) {
			t.Errorf("%s: Content-Type = %q, want %q", tc.target, rec.Header().Get("Content-Type"), tc.wantType)
		}
		if hasCSP := strings.Contains(got, "frame-ancestors 'none'"); hasCSP != tc.wantCSP {
			t.Errorf("%s: CSP = %q, want a frame-ancestors directive: %v", tc.target, got, tc.wantCSP)
		}
		// The header must never restate a directive the build's <meta> policy
		// already carries: both are enforced, so a restated script-src would
		// block the app's bootstrap by hash.
		for _, forbidden := range []string{"script-src", "style-src", "default-src", "connect-src"} {
			if strings.Contains(got, forbidden) {
				t.Errorf("%s: the header restates %q: %q", tc.target, forbidden, got)
			}
		}
	}
}

// --- Z08-3: every static file states how it may be cached ------------------

// Only two names used to be classified: a hashed asset and the shell. Everything
// else (the favicon, the app's robots.txt copy, the version document the client
// polls) went out with no directive, leaving freshness to each browser's
// heuristic. The default is now "not cacheable without revalidation", the one
// document that exists to be re-read is no-store, and the hashed assets keep
// their immutable year.
func TestP3EveryStaticFileDeclaresACachePolicy(t *testing.T) {
	fsys := testFS()
	fsys["favicon.svg"] = &fstest.MapFile{Data: []byte("<svg/>")}
	fsys["robots.txt"] = &fstest.MapFile{Data: []byte("User-agent: *\nDisallow: /app/\n")}
	fsys["_app/version.json"] = &fstest.MapFile{Data: []byte(`{"version":"1"}`)}
	h := Handler(fsys)

	for target, want := range map[string]string{
		"/app/":                              "no-cache",
		"/app/consent":                       "no-cache",
		"/app/favicon.svg":                   "no-cache",
		"/app/robots.txt":                    "no-cache",
		"/app/_app/version.json":             "no-store",
		"/app/_app/immutable/entry/start.js": "public, max-age=31536000, immutable",
	} {
		rec := get(t, h, target)
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", target, rec.Code)
			continue
		}
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control = %q, want %q", target, got, want)
		}
	}
}

// --- Z08-5: an immutable asset must not vary on the session cookie ---------

// The composition root wraps the whole tree in scs's LoadAndSave, which adds
// Vary: Cookie to every response before any handler runs. On a content-hashed,
// user-independent asset that makes a shared cache key one copy per cookie value
// (or refuse to store it), so `immutable` only ever means anything in the
// browser that already holds the asset.
//
// The real middleware is used, not a stand-in: the point is the interaction.
func TestP3ImmutableAssetsDoNotVaryOnTheSessionCookie(t *testing.T) {
	h := scs.New().LoadAndSave(Handler(testFS()))

	asset := get(t, h, "/app/_app/immutable/entry/start.js")
	if got := strings.Join(asset.Header().Values("Vary"), ", "); strings.Contains(got, "Cookie") {
		t.Errorf("the immutable asset is served with Vary %q: the session cookie is not part of what "+
			"this response depends on, and a shared cache keys the asset on it", got)
	}

	// Anti-vacuity: the middleware was in the chain, so the shell (whose body a
	// cache may legitimately key on the session) still carries the token.
	shell := get(t, h, "/app/consent")
	if got := strings.Join(shell.Header().Values("Vary"), ", "); !strings.Contains(got, "Cookie") {
		t.Fatalf("the session middleware added no Vary: Cookie (%q); this probe would be vacuous", got)
	}
}

// --- S12-11: one request must not redo the build's own bookkeeping ---------

// countingFS counts the lookups this package asks of the filesystem. ServeFileFS
// opens the file itself, which is inherent to serving it; anything beyond that is
// this package deciding again, per request, something that cannot change while
// the process runs.
type countingFS struct {
	fs.FS
	lookups atomic.Int64
}

func (f *countingFS) Open(name string) (fs.File, error) {
	f.lookups.Add(1)
	return f.FS.Open(name)
}

func (f *countingFS) Stat(name string) (fs.FileInfo, error) {
	f.lookups.Add(1)
	return fs.Stat(f.FS, name)
}

func TestP3StaticRequestsDoNotRestatTheBuildPerRequest(t *testing.T) {
	fsys := &countingFS{FS: testFS()}
	h := Handler(fsys)

	// Whether there is a build at all is a property of the embedded tree, not of
	// the request: it is answered once, when the handler is built.
	built := fsys.lookups.Load()
	if built != 1 {
		t.Errorf("building the handler made %d filesystem lookups, want exactly 1 "+
			"(the build-present check)", built)
	}

	const requests = 8
	for i := 0; i < requests; i++ {
		get(t, h, "/app/_app/immutable/entry/start.js")
	}
	perRequest := float64(fsys.lookups.Load()-built) / requests
	t.Logf("%d asset requests made %.2f filesystem lookups each", requests, perRequest)
	if perRequest > 2 {
		t.Errorf("an asset request makes %.2f filesystem lookups; want the file check and the file "+
			"server's own open, so at most 2", perRequest)
	}
}
