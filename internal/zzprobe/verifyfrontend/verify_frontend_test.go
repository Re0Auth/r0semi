//go:build audit5

// Package verifyfrontend holds the verifier's read-only probes for
// docs/audit-5/findings/frontend-VERIFIED.md.
//
// It exists to settle four things the verified report asserts or implies, by
// execution rather than by reading:
//
//   - which responses the package gives a document policy, and what the *only*
//     other text/html response in a built binary is;
//   - that the shell can never be conditionally validated (no ETag, no
//     Last-Modified, and therefore no possible 304) while still being no-cache,
//     which is what makes a browser fetch fresh bytes on every navigation;
//   - that a Range a client chooses can strip the shell's <meta> policy while
//     keeping its inline script;
//   - that a missing hashed asset is answered with the shell (200, text/html),
//     not with a 404.
//
// Run:
//
//	go test ./internal/zzprobe/verifyfrontend/ -v
package verifyfrontend

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
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

// A package that serves more than one HTML document must not rely on the file
// being *named* index.html to decide whether the response gets a document policy.
// This probe states which of those two the package does.
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
		{"/app/extra.html", "text/html", false}, // the report's A-FE-6 claim, pinned
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
		if got := csp != ""; got != tc.wantCSPIs {
			t.Errorf("%s: CSP = %q, want a policy: %v", tc.target, csp, tc.wantCSPIs)
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

// no-cache without a validator: the shell cannot be reused, and it also cannot be
// revalidated, so every navigation transfers the body. The probe asserts the
// second half as a property (no header value can produce a 304), because that is
// what bounds the risk the report describes.
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
	if etag != "" || lm != "" {
		t.Logf("a validator appeared (%q %q): the finding is fixed; assert 304 instead", etag, lm)
	}
	// Any conditional request at all still transfers a full 200 body.
	for _, header := range []http.Header{
		{"If-None-Match": {`"x"`}},
		{"If-Modified-Since": {"Wed, 21 Oct 2015 07:28:00 GMT"}},
		{"If-Range": {`"x"`}},
	} {
		rec := do(t, h, "/app/consent", header)
		t.Logf("conditional %v -> %d len=%d", header, rec.Code, rec.Body.Len())
		if rec.Code == http.StatusNotModified {
			t.Errorf("%v produced a 304 the server never promised: a validator exists somewhere", header)
		}
	}
	// The asset next door is the control: it does carry a validator-free but
	// immutable directive, so the pair is not "this handler never sets headers".
	asset := do(t, h, "/app/_app/immutable/entry/start.BmJmelwx.js", nil)
	t.Logf("asset: %d Cache-Control=%q", asset.Code, asset.Header().Get("Cache-Control"))
}

// A client chooses the byte range, so it can choose to receive the shell without
// its <meta> policy but with its inline bootstrap. The probe records that the
// mechanism is real (the report's A-FE-2), and that the header policy is still
// the only thing left on such a response.
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
	// policy is discarded, while the inline script (much later) survives.
	start := metaEnd
	h := webui.Handler(fsys)
	rec := do(t, h, "/app/consent", http.Header{"Range": {"bytes=" + itoa(start) + "-"}})
	body := rec.Body.String()
	t.Logf("Range bytes=%d- -> %d Content-Range=%q len=%d meta=%v script=%v",
		start, rec.Code, rec.Header().Get("Content-Range"), len(body),
		strings.Contains(body, "content-security-policy"), strings.Contains(body, "<script"))
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("Range on the shell = %d, want 206", rec.Code)
	}
	if strings.Contains(body, "content-security-policy") {
		t.Errorf("the truncated document still carries the meta policy, so the mechanism did not reproduce")
	}
	if !strings.Contains(body, "<script") {
		t.Errorf("the truncated document carries no script, so nothing would run with a missing policy")
	}
	// The header is now the whole policy, and it is one directive.
	t.Logf("header policy on the partial response: %q", rec.Header().Get("Content-Security-Policy"))
	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("header policy = %q", got)
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
