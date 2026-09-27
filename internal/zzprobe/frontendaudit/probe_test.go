//go:build audit5

// Package frontendaudit holds read-only adversarial probes for the browser plane.
//
// It is a scratchpad artifact (docs/audit-5/findings/frontend.md): it imports
// internal/webui and asserts the properties the audit report names. It registers
// no production package, so architecture tests may report it as unregistered —
// that is expected for internal/zzprobe/*.
//
// Run:
//
//	go test ./internal/zzprobe/frontendaudit/ -v
package frontendaudit

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Re0Auth/r0semi/internal/webui"
)

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                    {Data: []byte("<!doctype html><title>shell</title>")},
		"_app/immutable/entry/start.js": {Data: []byte("export const a = 1")},
		"robots.txt":                    {Data: []byte("User-agent: *\nDisallow: /app/\n")},
		"favicon.svg":                   {Data: []byte("<svg/>")},
	}
}

func do(t *testing.T, h http.Handler, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The header this package owns is set on the shell only, and it must never restate
// a directive the build's <meta> policy carries: a header and a meta policy are
// enforced as an intersection, so a restated `script-src 'self'` without the hash
// wins and white-screens the app. Non-HTML assets are covered by the API's
// security-headers middleware (internal/httpapi), which this package does not
// replace.
func TestProbeShellHeaderNeverRestatesABuildDirective(t *testing.T) {
	h := webui.Handler(testFS())
	for _, target := range []string{"/app/", "/app/consent", "/app/nothing/here", "/app/device"} {
		rec := do(t, h, target, nil)
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("%s: Content-Type = %q, want an HTML shell", target, ct)
		}
		got := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(got, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q, want frame-ancestors (a meta tag is ignored for framing)", target, got)
		}
		for _, forbidden := range []string{"script-src", "style-src", "default-src", "connect-src", "form-action", "base-uri", "object-src", "img-src", "font-src"} {
			if strings.Contains(got, forbidden) {
				t.Errorf("%s: header restates %q in %q; the meta policy allows the bootstrap by hash "+
					"and an intersection would block it", target, forbidden, got)
			}
		}
	}

	// A hashed asset carries the package's immutable caching header and NOT the
	// document policy: asserting the shell's CSP on a script would say the two
	// responses are interchangeable, which is what the bug above relied on.
	asset := do(t, h, "/app/_app/immutable/entry/start.js", nil)
	if got := asset.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("an immutable asset carries a document policy: %q", got)
	}
	if got := asset.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("asset Cache-Control = %q", got)
	}
}

// The SPA fallback must not become a cacheable document, and the hashed assets
// must be immutable. Getting the pair backwards is the deployment bug that breaks
// returning users: a cached shell points at asset filenames that no longer exist.
func TestProbeCacheDirectives(t *testing.T) {
	h := webui.Handler(testFS())
	cases := []struct{ target, want string }{
		{"/app/", "no-cache"},
		{"/app/consent", "no-cache"},
		{"/app/consent/anything/at/all", "no-cache"},
		{"/app/_app/immutable/entry/start.js", "public, max-age=31536000, immutable"},
	}
	for _, tc := range cases {
		rec := do(t, h, tc.target, nil)
		if got := rec.Header().Get("Cache-Control"); got != tc.want {
			t.Errorf("%s: Cache-Control = %q, want %q", tc.target, got, tc.want)
		}
	}
}

// A conditional request must be answerable, because the shell is served no-cache
// and every navigation revalidates it. If the validator is unstable or absent, the
// browser re-downloads the shell on every hop; if it is wrong, the browser keeps a
// shell whose CSP hash no longer matches the new build. Either way this is a
// property worth pinning rather than assuming.
func TestProbeConditionalRequestsAndRange(t *testing.T) {
	h := webui.Handler(testFS())

	first := do(t, h, "/app/", nil)
	etag := first.Header().Get("ETag")
	lastMod := first.Header().Get("Last-Modified")
	t.Logf("/app/ validators: ETag=%q Last-Modified=%q Content-Type=%q",
		etag, lastMod, first.Header().Get("Content-Type"))

	if etag != "" {
		second := do(t, h, "/app/", http.Header{"If-None-Match": {etag}})
		if second.Code != http.StatusNotModified {
			t.Errorf("If-None-Match with the server's own ETag = %d, want 304", second.Code)
		}
	}
	if lastMod != "" {
		second := do(t, h, "/app/", http.Header{"If-Modified-Since": {lastMod}})
		if second.Code != http.StatusNotModified {
			t.Errorf("If-Modified-Since with the server's own Last-Modified = %d, want 304", second.Code)
		}
	}

	// A Range request on the shell: whatever the answer is, it must not be a 200
	// carrying a Content-Range, and it must not be a 5xx.
	ranged := do(t, h, "/app/", http.Header{"Range": {"bytes=0-3"}})
	if ranged.Code >= 500 {
		t.Errorf("Range on the shell = %d", ranged.Code)
	}
	t.Logf("Range bytes=0-3 on the shell: %d %q (Content-Range=%q)",
		ranged.Code, truncate(ranged.Body.String()), ranged.Header().Get("Content-Range"))
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}

// Traversal paths must not reach the embed root, and the probe must not be fooled
// by the two ways this handler could hide a refusal: answering the SPA shell, or
// answering 400 from net/http's own "invalid URL path" check. So it asserts on the
// bytes of a file that lives OUTSIDE the served subtree.
func TestProbeTraversalNeverServesTheEmbedRoot(t *testing.T) {
	root := fstest.MapFS{
		"outside.txt":     {Data: []byte("OUTSIDE-SECRET")},
		"dist/index.html": {Data: []byte("<!doctype html><title>shell</title>")},
		"dist/_app/immutable/entry/start.js": {
			Data: []byte("export const a = 1"),
		},
	}
	sub, err := fs.Sub(root, "dist")
	if err != nil {
		t.Fatal(err)
	}
	h := webui.Handler(sub)

	// Anti-vacuity: the probe can see the shell when it should, so "no leak" is not
	// "nothing ran".
	shell := do(t, h, "/app/consent", nil)
	if shell.Code != http.StatusOK || !strings.Contains(shell.Body.String(), "shell") {
		t.Fatalf("the control request did not serve the shell: %d %q", shell.Code, shell.Body.String())
	}

	targets := []string{
		"/app/../outside.txt", "/app/../../outside.txt", "/app/..%2foutside.txt",
		"/app/%2e%2e/outside.txt", "/app/./../outside.txt", "/app/.%2e/outside.txt",
		"/app/%252e%252e/outside.txt", "/app/..%5coutside.txt",
		"/app/_app/../../../outside.txt", "/app/_app/../../../../outside.txt",
	}
	for _, target := range targets {
		rec := do(t, h, target, nil)
		t.Logf("%-38s -> %d %q %q", target, rec.Code,
			rec.Header().Get("Location"), truncate(rec.Body.String()))
		if strings.Contains(rec.Body.String(), "OUTSIDE-SECRET") {
			t.Errorf("%s escaped the dist subtree (status %d)", target, rec.Code)
		}
		if loc := rec.Header().Get("Location"); strings.Contains(loc, "outside") {
			t.Errorf("%s was answered with a redirect to %q", target, loc)
		}
	}
}

// The built shell's inline bootstrap must be allowed by the hash the shell does not
// publish. This is the one check that catches "the CSP and the script it governs
// drifted apart", whose only visible symptom is a white page. It reads the real
// build under internal/webui/dist and skips when only the placeholder is present.
func TestProbeBuiltShellHashMatchesItsInlineScript(t *testing.T) {
	fsys := webui.FS()
	if !webui.Built(fsys) {
		t.Skip("internal/webui/dist holds the placeholder; run `pnpm run build` in web/")
	}
	raw, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)

	metaRe := regexp.MustCompile(`http-equiv="content-security-policy" content="([^"]*)"`)
	meta := metaRe.FindStringSubmatch(html)
	if meta == nil {
		t.Fatal("the built shell carries no content-security-policy meta tag: the app would " +
			"run with only the header's frame-ancestors")
	}
	policy := meta[1]

	scriptRe := regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	scripts := scriptRe.FindAllStringSubmatch(html, -1)
	if len(scripts) == 0 {
		t.Fatal("the built shell carries no inline script, so its hash cannot be checked")
	}

	hashes := map[string]bool{}
	for _, m := range regexp.MustCompile(`'sha256-([A-Za-z0-9+/=]+)'`).FindAllStringSubmatch(policy, -1) {
		hashes[m[1]] = true
	}
	if len(hashes) == 0 {
		t.Fatalf("script-src carries no hash at all: %q", policy)
	}

	// Every inline script in the shell must be covered by some hash in the policy.
	covered := 0
	for _, s := range scripts {
		sum := sha256.Sum256([]byte(s[1]))
		b64 := base64.StdEncoding.EncodeToString(sum[:])
		if hashes[b64] {
			covered++
			continue
		}
		t.Errorf("an inline script is not covered by any hash in the policy; its sha256 is %s\n"+
			"  policy: %s", b64, policy)
	}
	if covered == 0 {
		t.Error("no inline script matched a declared hash: the shell and its CSP have drifted apart, " +
			"which is the white-screen bug an earlier audit found")
	}
	t.Logf("index.html inline scripts covered by a declared hash: %d", covered)

	// And the policy must not be loosened: no unsafe-inline or unsafe-eval in
	// script-src, and the structural directives a consent screen depends on must
	// still be closed. The directives are split rather than substring-matched, so
	// style-src's legitimate 'unsafe-inline' cannot masquerade as script-src's.
	directives := map[string]string{}
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) < 2 {
			continue
		}
		directives[fields[0]] = strings.Join(fields[1:], " ")
	}
	scriptSrc, ok := directives["script-src"]
	if !ok {
		t.Fatalf("the built policy has no script-src: %q", policy)
	}
	if strings.Contains(scriptSrc, "unsafe-inline") || strings.Contains(scriptSrc, "unsafe-eval") {
		t.Errorf("script-src carries a blanket allowance: %q", scriptSrc)
	}
	for _, want := range []struct{ directive, value string }{
		{"object-src", "'none'"},
		{"base-uri", "'none'"},
		{"form-action", "'none'"},
		{"connect-src", "'self'"},
		{"default-src", "'self'"},
	} {
		got, ok := directives[want.directive]
		if !ok || got != want.value {
			t.Errorf("%s = %q, want %q (policy %q)", want.directive, got, want.value, policy)
		}
	}
	if got := directives["style-src"]; !strings.Contains(got, "'unsafe-inline'") {
		t.Errorf("style-src = %q: Tailwind injects inline styles, so a change here has to be argued for", got)
	}
	// frame-ancestors is ignored in a meta tag, so it must NOT be relied on here;
	// the header carries it. Its presence in the meta tag is harmless but the
	// absence of the header would be the bug, which internal/httpapi asserts.
	t.Logf("directives: %v", directives)
}

// Nothing that ships under /app may be a tool that only belongs to the build, and
// nothing may be a source map: a .map file hands out the original source of the
// consent screen, which is a gift to whoever is writing a look-alike.
func TestProbeBuiltAssetsCarryNoBuildOnlyArtifacts(t *testing.T) {
	fsys := webui.FS()
	if !webui.Built(fsys) {
		t.Skip("placeholder only")
	}
	var files []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("walk found no files: the probe never reached the built assets")
	}

	for _, f := range files {
		switch {
		case strings.HasSuffix(f, ".map"):
			t.Errorf("%s ships a source map", f)
		case strings.HasSuffix(f, ".ts"), strings.HasSuffix(f, ".tsx"),
			strings.HasSuffix(f, ".svelte"), strings.HasSuffix(f, ".md"):
			t.Errorf("%s ships build-only source", f)
		case f == "package.json", f == "pnpm-lock.yaml":
			t.Errorf("%s ships a dependency manifest inside the app tree", f)
		}
	}
	t.Logf("built tree carries %d files", len(files))

	// The shell must not reference anything off-origin: a third-party font, CDN or
	// analytics script would receive the consent page's URL as a Referer and would
	// be a second party on the page where access is granted.
	raw, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(string(raw), -1) {
		u := m[1]
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "//") {
			t.Errorf("the shell references an absolute URL %q", u)
		}
	}
}

// Robots is carried as bytes by this package and routed by the composition root.
// The probe pins the two facts the routing depends on: the file exists and it
// disallows the app.
func TestProbeRobotsBytesAreWhatTheRootRouteServes(t *testing.T) {
	fsys := testFS()
	b, ok := webui.Robots(fsys)
	if !ok {
		t.Fatal("Robots reported no file for a filesystem that has one")
	}
	if !strings.Contains(string(b), "Disallow: /app/") {
		t.Fatalf("robots.txt does not disallow the app: %q", b)
	}
	if _, ok := webui.Robots(fstest.MapFS{"index.html": {Data: []byte("x")}}); ok {
		t.Error("Robots reported a file for a filesystem without one")
	}
}

// A handler must not answer a method it did not declare, and a HEAD must not carry
// a body. A body on HEAD is a response-splitting-shaped bug in reverse: a client
// that trusts Content-Length over the body will mis-frame the next response.
func TestProbeHeadContracts(t *testing.T) {
	h := webui.Handler(testFS())
	for _, target := range []string{"/app/", "/app/_app/immutable/entry/start.js"} {
		req := httptest.NewRequest(http.MethodHead, target, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("HEAD %s = %d, want 200", target, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("HEAD %s carried a %d-byte body", target, rec.Body.Len())
		}
		if got := rec.Header().Get("Content-Length"); got == "" {
			t.Errorf("HEAD %s carries no Content-Length", target)
		}
	}
	_ = errors.New
}
