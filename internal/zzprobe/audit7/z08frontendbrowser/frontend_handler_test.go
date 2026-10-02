//go:build audit7

// Handler-level probes for the SPA mount. They drive the composed httpapi server
// with a synthetic build tree, so what is observed is the production middleware
// chain (plane routing, the global header set, compression) plus
// internal/webui.Handler's own cache/CSP decisions.
//
// The tree is synthetic on purpose (testing/fstest.MapFS) so the probes are
// deterministic on a machine that never ran `pnpm run build`; the real embedded
// build is exercised separately by shell_csp_test.go.
package z08frontendbrowser

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// rec is one observed response.
type rec struct {
	code   int
	header http.Header
	body   string
}

// doRec issues one in-process request against a handler.
func doRec(t *testing.T, h http.Handler, method, target string, hdr map[string]string) *rec {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return &rec{code: rr.Code, header: rr.Header(), body: rr.Body.String()}
}

// z08FS is a miniature build tree with the shape the real one has: a shell,
// hashed immutable assets, and two root-level files.
func z08FS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {Data: []byte(`<!doctype html><html><head>` +
			`<meta http-equiv="content-security-policy" content="script-src 'self' 'sha256-AAA='">` +
			`</head><body>shell</body></html>`)},
		"_app/immutable/entry/start.abc.js": {Data: []byte("export const a = 1;")},
		"_app/immutable/assets/0.abc.css":   {Data: []byte("body{}")},
		"_app/version.json":                 {Data: []byte(`{"version":"1"}`)},
		"favicon.svg":                       {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
		"robots.txt":                        {Data: []byte("User-agent: *\nDisallow: /app/\n")},
	}
}

// z08Mounted builds a real httpapi.Server whose /app mount serves fsys.
func z08Mounted(t *testing.T, fsys fs.FS) http.Handler {
	t.Helper()
	return newZ08Env(t, z08Options{Frontend: fsys}).handler
}

// TestZ08StaticServingSurvey records what the composed server answers for the
// static surface. It is a survey; the invariants are asserted by the probes that
// follow it.
func TestZ08StaticServingSurvey(t *testing.T) {
	h := z08Mounted(t, z08FS())
	for _, tc := range []struct {
		method string
		target string
	}{
		{http.MethodGet, "/app/"},
		{http.MethodGet, "/app"},
		{http.MethodGet, "/app/index.html"},
		{http.MethodGet, "/app/grants"},
		{http.MethodGet, "/app/anything/at/all?q=1"},
		{http.MethodGet, "/app/_app/immutable/entry/start.abc.js"},
		{http.MethodGet, "/app/_app/immutable/entry/start.MISSING.js"},
		{http.MethodGet, "/app/_app/immutable/assets/0.abc.css"},
		{http.MethodGet, "/app/_app/version.json"},
		{http.MethodGet, "/app/favicon.svg"},
		{http.MethodGet, "/app/robots.txt"},
		{http.MethodGet, "/app/_app/"},
		{http.MethodGet, "/app/_app/immutable/"},
		{http.MethodHead, "/app/"},
		{http.MethodPost, "/app/"},
		{http.MethodPut, "/app/index.html"},
		{http.MethodOptions, "/app/"},
		{http.MethodGet, "/robots.txt"},
	} {
		r := doRec(t, h, tc.method, tc.target, nil)
		t.Logf("%-7s %-46s -> %d ct=%q cc=%q vary=%q etag=%q lm=%q allow=%q csp=%q len=%d",
			tc.method, tc.target, r.code, r.header.Get("Content-Type"),
			r.header.Get("Cache-Control"), r.header.Get("Vary"),
			r.header.Get("ETag"), r.header.Get("Last-Modified"),
			r.header.Get("Allow"), r.header.Get("Content-Security-Policy"),
			len(r.body))
	}
}

// TestZ08TraversalMatrixSurvey records how the mount answers traversal and
// encoded spellings. Every case must be answered by a real handler (not by
// net/http's own malformed-request path), which is the anti-vacuous control for
// the negative result.
func TestZ08TraversalMatrixSurvey(t *testing.T) {
	h := z08Mounted(t, z08FS())
	reached := 0
	for _, target := range []string{
		"/app/../../etc/passwd",
		"/app/..%2f..%2fetc/passwd",
		"/app/%2e%2e/%2e%2e/etc/passwd",
		"/app/../oauth/token",
		"/app/../v1/me",
		"/app/..%2Foauth/token",
		"/app//oauth/token",
		"/app/_app/immutable/../../../index.html",
		"/app/_app/immutable/..%2f..%2f..%2findex.html",
		"/app/./././grants",
		"/application/oauth/token",
		"/app%2Foauth/token",
	} {
		r := doRec(t, h, http.MethodGet, target, nil)
		if r.code != 0 {
			reached++
		}
		for _, h := range []string{"app/../../etc/passwd", "root:", "BEGIN OPENSSH", "[core]"} {
			if strings.Contains(r.body, h) {
				t.Errorf("%s leaked %q: %s", target, h, firstLine(r.body))
			}
		}
		t.Logf("%-52s -> %d ct=%q loc=%q body=%q", target, r.code,
			r.header.Get("Content-Type"), r.header.Get("Location"), firstLine(r.body))
	}
	if reached == 0 {
		t.Fatal("no traversal case reached a handler; the walk is vacuous")
	}
}

// TestZ08MissingImmutableAssetIsNotASilentShell — 原为发现演示，现为回归守卫（按裁定）.
//
// The probe used to assert the opposite: that a URL under the hashed-asset
// namespace naming no file is NOT answered with the shell. That behaviour is a
// ruled-with-intent property, not a defect: a missing hashed asset is answered
// 200 with the SPA shell. The ruling is recorded at
// docs/security-audit-7.md:302 (Z08-1 is NOT-A-FINDING — round 5's V-2 already
// pinned "缺失散列资产回 200 shell 而非 404") and docs/issues/not-doing.md:48
// (A-FE-V2: 缺失的散列资产回 200 shell 而非 404 —— 已被钉成性质，不要再作为缺陷上报).
//
// The guard asserts the ruled shape directly: the fallback is 200 + text/html and
// its body IS the shell, by decision. The anti-vacuity control compares the body
// with the shell served at /app/, so a bodyless or 404 answer fails here instead
// of passing as "not a silent shell".
func TestZ08MissingImmutableAssetIsNotASilentShell(t *testing.T) {
	h := z08Mounted(t, z08FS())

	shell := doRec(t, h, http.MethodGet, "/app/", nil)
	if shell.code != http.StatusOK || !strings.Contains(shell.header.Get("Content-Type"), "text/html") {
		t.Fatalf("anti-vacuity: the shell itself is not served as 200 text/html (%d %q)",
			shell.code, shell.header.Get("Content-Type"))
	}
	if len(shell.body) == 0 {
		t.Fatalf("anti-vacuity: the shell body is empty, so the comparison below proves nothing")
	}

	r := doRec(t, h, http.MethodGet, "/app/_app/immutable/entry/start.DEADBEEF.js", nil)
	t.Logf("missing immutable asset -> %d ct=%q len=%d", r.code, r.header.Get("Content-Type"), len(r.body))
	if r.code != http.StatusOK {
		t.Errorf("a missing hashed asset answered %d, want the ruled 200 shell fallback "+
			"(docs/security-audit-7.md:302, docs/issues/not-doing.md:48)", r.code)
	}
	if ct := r.header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("a missing hashed asset answered %q, want the ruled text/html shell fallback", ct)
	}
	if r.body != shell.body {
		t.Errorf("the answer to a missing hashed asset is not the shell byte-for-byte "+
			"(missing=%d bytes, shell=%d bytes)", len(r.body), len(shell.body))
	}
}

// TestZ08ShellIsRevalidatableWithoutRefetching asserts that a response the
// handler marks `no-cache` carries a validator, so a returning browser can get a
// 304 instead of the whole document. `no-cache` means "revalidate"; with no ETag
// and no Last-Modified there is nothing to revalidate against.
func TestZ08ShellIsRevalidatableWithoutRefetching(t *testing.T) {
	h := z08Mounted(t, z08FS())
	r := doRec(t, h, http.MethodGet, "/app/", nil)
	if r.header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("the shell is not no-cache (%q); this probe is about revalidation",
			r.header.Get("Cache-Control"))
	}
	if r.header.Get("ETag") == "" && r.header.Get("Last-Modified") == "" {
		t.Errorf("the shell answers %q with neither ETag nor Last-Modified, so `no-cache` can never "+
			"become a 304: every navigation and every refresh re-sends the whole document (%d bytes here)",
			r.header.Get("Cache-Control"), len(r.body))
	}
}

// TestZ08ImmutableAssetIsConditionallyFetchable is the asset half of the same
// question: a year-long immutable cache with no validator is fine, but the
// probe records whether any validator exists at all.
func TestZ08ImmutableAssetIsConditionallyFetchable(t *testing.T) {
	h := z08Mounted(t, z08FS())
	r := doRec(t, h, http.MethodGet, "/app/_app/immutable/entry/start.abc.js", nil)
	if cc := r.header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("a path under _app/immutable/ did not get an immutable cache directive: %q", cc)
	}
	t.Logf("immutable asset ct=%q cc=%q etag=%q lm=%q", r.header.Get("Content-Type"),
		r.header.Get("Cache-Control"), r.header.Get("ETag"), r.header.Get("Last-Modified"))
}

// TestZ08NonShellStaticFilesDeclareACachePolicy asserts that every static file
// the handler can serve says how long it may be cached. Only two names are
// covered by setCacheHeaders; anything else inherits no directive at all, which
// leaves the decision to each browser's heuristic.
func TestZ08NonShellStaticFilesDeclareACachePolicy(t *testing.T) {
	h := z08Mounted(t, z08FS())
	for _, target := range []string{"/app/favicon.svg", "/app/_app/version.json", "/robots.txt"} {
		r := doRec(t, h, http.MethodGet, target, nil)
		if r.code != http.StatusOK {
			t.Errorf("%s = %d, the probe is not reaching a file", target, r.code)
			continue
		}
		if r.header.Get("Cache-Control") == "" {
			t.Errorf("%s is served with no Cache-Control at all (ct=%q): the response states no "+
				"freshness, so caches fall back to a heuristic and different browsers disagree",
				target, r.header.Get("Content-Type"))
		}
	}
}

// TestZ08EveryBrowserPlaneResponseCarriesTheFramingGuard asserts the clickjacking
// guard is present on the browser plane's failures too, not just on the shell.
func TestZ08EveryBrowserPlaneResponseCarriesTheFramingGuard(t *testing.T) {
	h := z08Mounted(t, z08FS())
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/app/"},
		{http.MethodGet, "/app/consent"},
		{http.MethodGet, "/app/_app/immutable/entry/start.MISSING.js"},
		{http.MethodPost, "/app/"},
		{http.MethodGet, "/nope"},
		{http.MethodGet, "/robots.txt"},
	} {
		r := doRec(t, h, tc.method, tc.target, nil)
		if r.header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s %s: X-Frame-Options = %q, want DENY", tc.method, tc.target, r.header.Get("X-Frame-Options"))
		}
		if !strings.Contains(r.header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s %s: Content-Security-Policy = %q, want frame-ancestors 'none'",
				tc.method, tc.target, r.header.Get("Content-Security-Policy"))
		}
	}
}

// TestZ08RangeOnTheShellCannotSpliceAssets records that Range requests are
// answered for whatever name the fallback chose. The assertion is that a range
// request must not turn a missing asset into a 206 of the shell, because a client
// that trusts Content-Range would splice HTML.
func TestZ08RangeOnTheShellCannotSpliceAssets(t *testing.T) {
	h := z08Mounted(t, z08FS())
	r := doRec(t, h, http.MethodGet, "/app/_app/immutable/entry/start.MISSING.js",
		map[string]string{"Range": "bytes=0-9"})
	t.Logf("range over a missing asset -> %d ct=%q cr=%q len=%d",
		r.code, r.header.Get("Content-Type"), r.header.Get("Content-Range"), len(r.body))
	if r.code == http.StatusPartialContent {
		t.Errorf("a range request for a missing asset was answered %d %q (Content-Range %q): "+
			"the client asked for bytes of a script and got bytes of the shell",
			r.code, r.header.Get("Content-Type"), r.header.Get("Content-Range"))
	}
}

// TestZ08WrongMethodUnderTheMountIsRefusedWithAllow asserts the mount's own verb
// gate, which is the browser plane's answer and must not be a problem+json body.
func TestZ08WrongMethodUnderTheMountIsRefusedWithAllow(t *testing.T) {
	h := z08Mounted(t, z08FS())
	r := doRec(t, h, http.MethodPost, "/app/", nil)
	if r.code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /app/ = %d, want 405", r.code)
	}
	if r.header.Get("Allow") == "" {
		t.Errorf("405 without Allow")
	}
	if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("405 Content-Type = %q, want text/plain (the browser plane's shape)", ct)
	}
}

// TestZ08DirectoryUnderTheMountIsNotListed asserts a directory name is treated as
// "not a file", so the build cannot be enumerated.
func TestZ08DirectoryUnderTheMountIsNotListed(t *testing.T) {
	h := z08Mounted(t, z08FS())
	for _, target := range []string{"/app/_app/", "/app/_app/immutable/", "/app/_app/immutable/assets/"} {
		r := doRec(t, h, http.MethodGet, target, nil)
		if strings.Contains(r.body, "start.abc.js") || strings.Contains(r.body, "<a href") {
			t.Errorf("%s: the response enumerates the build: %q", target, firstLine(r.body))
		}
	}
}

// TestZ08ImmutableAssetsDoNotVaryOnTheSessionCookie asserts the one thing that
// has to be true for `public, max-age=31536000, immutable` to mean anything past
// the browser: the response must not be keyed on the session cookie. The session
// middleware (alexedwards/scs v2 LoadAndSave) adds `Vary: Cookie` to every
// response on the tree before any handler runs, and a shared cache that honours
// Vary then stores one copy per distinct Cookie value — or, more commonly,
// refuses to store the response at all.
//
// Failing this probe is the finding.
func TestZ08ImmutableAssetsDoNotVaryOnTheSessionCookie(t *testing.T) {
	h := z08Mounted(t, z08FS())
	hashed := "/app/_app/immutable/entry/start.abc.js"
	r := doRec(t, h, http.MethodGet, hashed, map[string]string{"Accept-Encoding": "gzip"})
	if cc := r.header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("%s: Cache-Control = %q; this probe is about what cancels that directive", hashed, cc)
	}
	if vary := r.header.Get("Vary"); strings.Contains(vary, "Cookie") {
		t.Errorf("%s is served with Cache-Control %q and Vary %q: the session middleware adds Vary: Cookie "+
			"to every response before any handler runs, so a shared cache keys a content-hashed, "+
			"user-independent asset on the session cookie — the immutable directive survives only in the "+
			"browser that already has it",
			hashed, r.header.Get("Cache-Control"), vary)
	}
	if vary := r.header.Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("%s: Vary = %q, want Accept-Encoding (the body is compressed)", hashed, vary)
	}
	// The shell's cache directive is no-cache, so Vary: Cookie there is harmless.
	// Record it so the asymmetry is visible rather than assumed.
	shell := doRec(t, h, http.MethodGet, "/app/", nil)
	t.Logf("shell Cache-Control=%q Vary=%q; asset Cache-Control=%q Vary=%q",
		shell.header.Get("Cache-Control"), shell.header.Get("Vary"),
		r.header.Get("Cache-Control"), r.header.Get("Vary"))
}

// TestZ08StaticSurfaceCarriesNosniff records the defensive header on the static
// surface, where the raw proxy's pass-through Content-Type makes it matter.
func TestZ08StaticSurfaceCarriesNosniff(t *testing.T) {
	h := z08Mounted(t, z08FS())
	for _, target := range []string{"/app/", "/app/_app/immutable/entry/start.abc.js", "/app/_app/immutable/entry/nope.js", "/robots.txt", "/nope"} {
		r := doRec(t, h, http.MethodGet, target, nil)
		if got := r.header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", target, got)
		}
		if got := r.header.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q, want no-referrer", target, got)
		}
	}
}

// firstLine truncates a body for logging.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 90 {
		s = s[:90] + "..."
	}
	return s
}
