//go:build audit7

// Real-shell CSP probes. They run against the embedded frontend build
// (internal/webui/dist via webui.FS) and recompute, from the bytes the server
// actually sends, the hash the policy has to allow. That is the invariant whose
// violation made the app render blank once: a header restating script-src
// without the build's hash silently blocked SvelteKit's inline bootstrap.
//
// They skip — loudly — when the checkout has no frontend build, because a
// placeholder shell proves nothing about the policy.
package z08frontendbrowser

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/webui"
)

// z08Shell returns the served shell document, or skips if there is no build.
func z08Shell(t *testing.T) (header http.Header, body string) {
	t.Helper()
	fsys := webui.FS()
	if !webui.Built(fsys) {
		t.Skip("no frontend build in this checkout (internal/webui/dist holds the placeholder): " +
			"run `cd web && pnpm run build`, then re-run; the CSP claims below cannot be checked against a shell that does not exist")
	}
	h := z08Mounted(t, fsys)
	r := doRec(t, h, http.MethodGet, "/app/consent", nil)
	if r.code != http.StatusOK {
		t.Fatalf("GET /app/consent = %d", r.code)
	}
	if !strings.Contains(r.body, "<!doctype html") {
		t.Fatalf("the mount did not answer with a document: %q", firstLine(r.body))
	}
	return r.header, r.body
}

// cspDirectives splits a policy into directive -> sources.
func cspDirectives(policy string) map[string][]string {
	out := make(map[string][]string)
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		out[fields[0]] = fields[1:]
	}
	return out
}

var (
	z08MetaCSP  = regexp.MustCompile(`(?i)<meta[^>]+http-equiv="content-security-policy"[^>]+content="([^"]*)"`)
	z08InlineJS = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
)

// TestZ08ServedShellMetaCSPAllowsItsOwnInlineScripts is the regression guard for
// the blank-page build: every inline script in the document must be covered by
// the policy's own script-src, either by a hash or by 'self'-safe means.
func TestZ08ServedShellMetaCSPAllowsItsOwnInlineScripts(t *testing.T) {
	_, body := z08Shell(t)
	m := z08MetaCSP.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the served shell carries no <meta http-equiv=content-security-policy>: " +
			"the only policy left would be the header's single directive")
	}
	d := cspDirectives(m[1])
	script, ok := d["script-src"]
	if !ok {
		t.Fatalf("the meta policy has no script-src: %v", d)
	}
	if !hasToken(script, "'self'") {
		t.Errorf("script-src does not allow 'self': %v", script)
	}
	for _, bad := range []string{"'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:", "data:"} {
		if hasToken(script, bad) {
			t.Errorf("script-src carries %s: %v", bad, script)
		}
	}
	scripts := z08InlineJS.FindAllStringSubmatch(body, -1)
	if len(scripts) == 0 {
		t.Fatal("the served shell has no inline <script>; the hash assertion would be vacuous")
	}
	allowed := 0
	for _, s := range scripts {
		sum := sha256.Sum256([]byte(s[1]))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if hasToken(script, want) {
			allowed++
			continue
		}
		t.Errorf("an inline script in the served shell is not covered by script-src %v; "+
			"its hash is %s and the browser will block it", script, want)
	}
	if allowed == 0 {
		t.Errorf("no inline script hash in the policy matched the served bytes: %v", script)
	}
	t.Logf("meta policy: %s", m[1])
	t.Logf("%d inline scripts, %d matched a script-src hash", len(scripts), allowed)
}

// TestZ08ServedShellMetaCSPHasTheNonNegotiableDirectives pins the directives a
// document of this kind must not lose.
func TestZ08ServedShellMetaCSPHasTheNonNegotiableDirectives(t *testing.T) {
	_, body := z08Shell(t)
	m := z08MetaCSP.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no meta CSP in the served shell")
	}
	d := cspDirectives(m[1])
	for _, tc := range []struct {
		name   string
		want   string
		reason string
	}{
		{"base-uri", "'none'", "a <base> tag injected into the document would retarget every relative URL"},
		{"form-action", "'none'", "the app submits no native form; a form would be a way to send data out"},
		{"object-src", "'none'", "plugins are a script-execution path script-src does not cover on old browsers"},
		{"default-src", "'self'", "the fallback for every directive that is not spelled out"},
		{"connect-src", "'self'", "the app talks to /v1 and nowhere else"},
	} {
		got, ok := d[tc.name]
		if !ok {
			t.Errorf("the meta policy has no %s (%s): %v", tc.name, tc.reason, d)
			continue
		}
		if !hasToken(got, tc.want) {
			t.Errorf("%s = %v, want %s (%s)", tc.name, got, tc.want, tc.reason)
		}
	}
	// No directive may name a third-party origin.
	for name, sources := range d {
		for _, s := range sources {
			if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
				t.Errorf("%s names a third-party origin %q", name, s)
			}
		}
	}
}

// TestZ08ShellMetaCSPPrecedesEveryScriptItMustGovern is the one ordering rule a
// <meta> policy has that a header policy does not: it applies only to what comes
// after it in the document. If a future build moved the tag below the bootstrap,
// the inline script would run with no script-src at all.
func TestZ08ShellMetaCSPPrecedesEveryScriptItMustGovern(t *testing.T) {
	_, body := z08Shell(t)
	metas := z08MetaCSP.FindAllStringIndex(body, -1)
	if len(metas) != 1 {
		t.Fatalf("the served shell carries %d meta content-security-policy tags; two policies are "+
			"intersected, so a stale one can silently tighten the app", len(metas))
	}
	firstScript := strings.Index(strings.ToLower(body), "<script")
	if firstScript < 0 {
		t.Fatal("the shell has no script element")
	}
	if metas[0][1] > firstScript {
		t.Errorf("the meta policy ends at byte %d, after the first <script> at byte %d: everything before a "+
			"meta policy is ungoverned by it", metas[0][1], firstScript)
	}
	head := strings.Index(strings.ToLower(body), "</head>")
	if head >= 0 && metas[0][1] > head {
		t.Errorf("the meta policy is outside <head>")
	}
	t.Logf("meta policy at bytes %v, first script at %d, </head> at %d", metas[0], firstScript, head)
}

// TestZ08ServedShellImageSourcesExcludeThirdParties pins the one directive whose
// looseness would leak a request to a provider the user did not choose.
func TestZ08ServedShellImageSourcesExcludeThirdParties(t *testing.T) {
	_, body := z08Shell(t)
	m := z08MetaCSP.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no meta CSP in the served shell")
	}
	d := cspDirectives(m[1])
	img := d["img-src"]
	if len(img) == 0 {
		t.Logf("img-src is unset and falls back to default-src %v", d["default-src"])
		return
	}
	if !hasToken(img, "'self'") {
		t.Errorf("img-src = %v, want 'self'", img)
	}
	for _, s := range img {
		if s != "'self'" && s != "data:" {
			t.Errorf("img-src allows %q, which is a cross-origin image load (a tracking pixel the user "+
				"did not ask for)", s)
		}
	}
}

// TestZ08FramingGuardComesFromTheHeaderNotTheMeta records the asymmetry the
// webui package documents: frame-ancestors is ignored in a meta tag, so the
// header has to carry it and the meta tag must not pretend to.
func TestZ08FramingGuardComesFromTheHeaderNotTheMeta(t *testing.T) {
	header, body := z08Shell(t)
	m := z08MetaCSP.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no meta CSP in the served shell")
	}
	if strings.Contains(strings.ToLower(m[1]), "frame-ancestors") {
		t.Errorf("the meta policy states frame-ancestors, which browsers ignore in a <meta> tag: %s", m[1])
	}
	if got := header.Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Errorf("the header policy is %q; without frame-ancestors there the document is frameable", got)
	}
	if got := header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

// TestZ08ServedShellIsTheBuildOutput checks that what is served is the built
// document itself — no injection, no templating. The webui package promises
// this, and it is the property that keeps frontend build output off the path
// that decides what the consent screen says.
func TestZ08ServedShellIsTheBuildOutput(t *testing.T) {
	_, body := z08Shell(t)
	raw, err := fs.ReadFile(webui.FS(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != body {
		t.Errorf("the served document is not the embedded index.html byte for byte (%d vs %d bytes)",
			len(body), len(raw))
	}
}

func hasToken(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
