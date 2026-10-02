//go:build audit5

// Package verifyfrontend holds the verifier's read-only probes for
// docs/audit-5/findings/frontend-VERIFIED.md.
//
// These probes started as discovery probes for the frontend findings. The fixes
// for A-FE-1/A-FE-2/A-FE-6/Z08-3/Z08-5 have since landed, so the probes are
// regression guards now: they assert the fixed properties and fail if a fix is
// reverted. Where a guard needs a positive control (range support must survive on
// assets, a different shell must still 200), that control is built in.
//
// Run:
//
//	go test -tags audit5 ./internal/zzprobe/verifyfrontend/ -v
package verifyfrontend

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Re0Auth/r0semi/internal/webui"
)

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

// Guard for A-FE-6: every HTML document the package serves gets the framing
// policy, keyed on the response's type rather than on the file being *named*
// index.html. Originally this was the discovery probe that pinned the opposite:
// only index.html received a policy, so a build that shipped a second document
// sent it with no framing guard at all.
func TestVWhichResponsesGetTheDocumentPolicy(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":                 {Data: []byte("<!doctype html><title>shell</title>")},
		"extra.html":                 {Data: []byte("<!doctype html><title>extra</title>")},
		"plain.txt":                  {Data: []byte("text")},
		"_app/immutable/chunks/a.js": {Data: []byte("export const a=1")},
	}
	h := webui.Handler(fsys)
	for _, tc := range []struct {
		target    string
		wantCT    string
		wantCSPIs bool
	}{
		{"/app/", "text/html", true},
		{"/app/consent", "text/html", true},
		{"/app/extra.html", "text/html", true}, // A-FE-6 guard: any HTML document gets the framing policy
		{"/app/plain.txt", "text/plain", false},
		{"/app/_app/immutable/chunks/a.js", "text/javascript", false},
	} {
		rec := do(t, h, tc.target, nil)
		ct := rec.Header().Get("Content-Type")
		csp := rec.Header().Get("Content-Security-Policy")
		t.Logf("%-34s -> %d ct=%q csp=%q", tc.target, rec.Code, ct, csp)
		if !strings.HasPrefix(ct, tc.wantCT) {
			t.Errorf("%s: Content-Type = %q, want %q", tc.target, ct, tc.wantCT)
		}
		if got := strings.Contains(csp, "frame-ancestors 'none'"); got != tc.wantCSPIs {
			t.Errorf("%s: CSP = %q, want a frame-ancestors 'none' policy: %v", tc.target, csp, tc.wantCSPIs)
		}
	}

	// The other text/html this package can emit is the not-built explanation,
	// which can only be reached by a binary that embeds the placeholder. It must
	// therefore justify needing no script policy: it must carry no script.
	notBuilt := do(t, webui.Handler(fstest.MapFS{}), "/app/", nil)
	body := notBuilt.Body.String()
	t.Logf("not-built response: %d ct=%q csp=%q", notBuilt.Code, notBuilt.Header().Get("Content-Type"), notBuilt.Header().Get("Content-Security-Policy"))
	if notBuilt.Code != http.StatusServiceUnavailable {
		t.Errorf("not-built status = %d, want 503", notBuilt.Code)
	}
	if !strings.HasPrefix(notBuilt.Header().Get("Content-Type"), "text/html") {
		t.Errorf("not-built Content-Type = %q", notBuilt.Header().Get("Content-Type"))
	}
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Errorf("the not-built page carries a script, so losing script-src on it is not free")
	}
}

// The real build must contain exactly one HTML document, so that "any text/html
// response" and "a response named index.html" are the same set in a shipped
// binary — which is what makes the naming-based rule above harmless today.
func TestVTheRealBuildContainsExactlyOneHTMLDocument(t *testing.T) {
	fsys := webui.FS()
	if !webui.Built(fsys) {
		t.Skip("placeholder only")
	}
	var html []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm")) {
			html = append(html, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("html documents in the built tree: %v", html)
	if len(html) != 1 || html[0] != "index.html" {
		t.Errorf("the built tree serves %v as HTML; the policy rule keys on the name index.html", html)
	}
}

// Guard for A-FE-1/S12-8: the shell is no-cache but DOES carry a strong ETag, so
// a conditional request can be answered with a 304 and no body. Originally this
// probe pinned the opposite claim — that the shell had no validator at all and
// every navigation re-transferred the document. The name is kept for the audit
// coverage matrix.
func TestVShellCannotBeConditionallyValidatedAtAll(t *testing.T) {
	h := webui.Handler(webui.FS())
	first := do(t, h, "/app/consent", nil)
	cc := first.Header().Get("Cache-Control")
	etag := first.Header().Get("ETag")
	lm := first.Header().Get("Last-Modified")
	t.Logf("shell: Cache-Control=%q ETag=%q Last-Modified=%q", cc, etag, lm)
	if cc != "no-cache" {
		t.Errorf("shell Cache-Control = %q; the report's analysis of its risk depends on no-cache", cc)
	}
	if etag == "" {
		t.Errorf("the shell carries no ETag: A-FE-1/S12-8 regressed, so a `no-cache` response can never " +
			"become a 304 and every navigation re-sends the whole document")
	}
	if strings.HasPrefix(etag, "W/") {
		t.Errorf("shell ETag = %q is a weak validator; the shell is served with ranges disabled so a "+
			"strong validator is what revalidation needs", etag)
	}
	// The validator is usable: a matching If-None-Match is answered 304 with no
	// body, and a non-matching one still transfers the document.
	rec := do(t, h, "/app/consent", http.Header{"If-None-Match": {etag}})
	t.Logf("If-None-Match: %s -> %d len=%d", etag, rec.Code, rec.Body.Len())
	if rec.Code != http.StatusNotModified {
		t.Errorf("If-None-Match with the server's own ETag = %d, want 304", rec.Code)
	}
	for _, header := range []http.Header{
		{"If-None-Match": {`"x"`}},
		{"If-Modified-Since": {"Wed, 21 Oct 2015 07:28:00 GMT"}},
		{"If-Range": {`"x"`}},
	} {
		rec := do(t, h, "/app/consent", header)
		t.Logf("conditional %v -> %d len=%d", header, rec.Code, rec.Body.Len())
		if rec.Code == http.StatusNotModified {
			t.Errorf("%v produced a 304 with a validator the server never issued", header)
		}
	}
	// The asset next door is the control: it carries an immutable directive, so
	// the pair is not "this handler never sets cache headers".
	assetPath := regexp.MustCompile(`/app/_app/immutable/[A-Za-z0-9._/-]+\.js`).FindString(first.Body.String())
	if assetPath == "" {
		t.Fatal("the shell names no immutable asset; the cache-header control would be vacuous")
	}
	asset := do(t, h, assetPath, nil)
	t.Logf("asset: %d Cache-Control=%q ETag=%q", asset.Code, asset.Header().Get("Cache-Control"), asset.Header().Get("ETag"))
	if !strings.Contains(asset.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("asset Cache-Control = %q, want immutable", asset.Header().Get("Cache-Control"))
	}
}

// Guard for A-FE-2: a client-chosen Range cannot strip the shell's <meta> policy
// while keeping its inline bootstrap — a document request is answered with the
// whole representation, 200 and no Content-Range. Range support survives on the
// hashed assets, which is the positive control. Originally this probe reproduced
// the truncation (206) and recorded that the header policy was all that remained.
func TestVRangeCanStripTheMetaPolicyButKeepTheScript(t *testing.T) {
	fsys := webui.FS()
	if !webui.Built(fsys) {
		t.Skip("placeholder only")
	}
	raw, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	// The byte just past the </meta>-equivalent: the policy lives in one long
	// <meta ...> tag, so the range has to begin after its closing '>'.
	at := strings.Index(html, "content-security-policy")
	if at < 0 {
		t.Fatal("the built shell carries no meta policy")
	}
	close := strings.IndexByte(html[at:], '>')
	if close < 0 {
		t.Fatal("the meta tag is unterminated")
	}
	metaEnd := at + close + 1
	// Start the range just after the meta tag so the prefix that carries the
	// policy would be discarded if the range were honored.
	start := metaEnd
	h := webui.Handler(fsys)
	rec := do(t, h, "/app/consent", http.Header{"Range": {"bytes=" + itoa(start) + "-"}})
	body := rec.Body.String()
	t.Logf("Range bytes=%d- -> %d Content-Range=%q len=%d meta=%v script=%v",
		start, rec.Code, rec.Header().Get("Content-Range"), len(body),
		strings.Contains(body, "content-security-policy"), strings.Contains(body, "<script"))
	if rec.Code != http.StatusOK {
		t.Errorf("Range on the shell = %d, want 200 with the whole document (the range must be ignored)", rec.Code)
	}
	if cr := rec.Header().Get("Content-Range"); cr != "" {
		t.Errorf("a 200 for the shell carried Content-Range %q", cr)
	}
	if !strings.Contains(body, "content-security-policy") {
		t.Errorf("the served document lost its <meta> policy: the Range truncated the shell (A-FE-2 regressed)")
	}
	if !strings.Contains(body, "<script") {
		t.Errorf("the served document carries no script; the fixture is not the shell")
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("header policy = %q", got)
	}

	// Positive control: a hashed asset still honors a Range, so this is a
	// decision about documents, not a handler that ignores Range everywhere.
	asset := regexp.MustCompile(`/app/_app/immutable/[A-Za-z0-9._/-]+\.js`).FindString(html)
	if asset == "" {
		t.Fatal("the shell names no immutable asset; the range control would be vacuous")
	}
	arec := do(t, h, asset, http.Header{"Range": {"bytes=0-6"}})
	t.Logf("Range on asset %s -> %d Content-Range=%q", asset, arec.Code, arec.Header().Get("Content-Range"))
	if arec.Code != http.StatusPartialContent {
		t.Errorf("Range on an asset = %d, want 206 (range support must survive on content-hashed files)", arec.Code)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// A shell that names an asset a later deploy dropped does not get a 404: the
// handler rewrites every non-file path to the shell, so the request is answered
// with 200 and an HTML body. The report's A-FE-9 failure chain states the
// opposite, so the fact is worth pinning either way.
func TestVMissingAssetIsAnsweredWithTheShellNotA404(t *testing.T) {
	h := webui.Handler(webui.FS())
	for _, target := range []string{
		"/app/_app/immutable/entry/start.DELETEDBYDEPLOY.js",
		"/app/_app/immutable/chunks/gone.js",
		"/app/nothing-here.png",
	} {
		rec := do(t, h, target, nil)
		t.Logf("%-52s -> %d ct=%q cc=%q html=%v",
			target, rec.Code, rec.Header().Get("Content-Type"),
			rec.Header().Get("Cache-Control"), strings.HasPrefix(rec.Body.String(), "<!doctype html"))
		if rec.Code != http.StatusOK {
			t.Errorf("%s -> %d, want 200 (the fallback answers every non-file path)", target, rec.Code)
		}
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s: Content-Type = %q, want text/html", target, rec.Header().Get("Content-Type"))
		}
	}
}
