//go:build audit7

// Sink and asset-origin probes for the frontend. They scan two artefacts the
// browser actually consumes: the built bundle (webui.FS) and the app's own
// source. Each scan carries a positive control, because a search that finds
// nothing has to prove it was reading code at all.
package z08frontendbrowser

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Re0Auth/r0semi/internal/webui"
)

// jsSinks are the browser-side sinks an XSS or a token thief would need. None of
// them has a legitimate use in this app: every credential is a same-origin
// cookie the browser attaches itself.
var jsSinks = []string{
	"localStorage",
	"sessionStorage",
	"document.cookie",
	"postMessage",
	"innerHTML",
	"outerHTML",
	"insertAdjacentHTML",
	"eval(",
	"new Function",
	"dangerouslySetInnerHTML",
}

// TestZ08AppSourceHasNoClientSideSinkAndNeverStoresACredential scans web/src.
func TestZ08AppSourceHasNoClientSideSinkAndNeverStoresACredential(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "web", "src")

	var files []string
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(p) {
		case ".ts", ".svelte", ".html":
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("the app source is the subject of this scan: %v", err)
	}
	if len(files) < 10 {
		t.Fatalf("only %d source files found under %s", len(files), src)
	}

	// Positive control: the scan must find something that is definitely there.
	api, err := os.ReadFile(filepath.Join(src, "lib", "api.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(api), "fetch(") {
		t.Fatal("the scan cannot see fetch( in web/src/lib/api.ts; it is not reading the app's code")
	}

	scanned := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		rel, _ := filepath.Rel(root, f)
		code := stripComments(string(b))
		for _, sink := range jsSinks {
			if strings.Contains(code, sink) {
				t.Errorf("%s mentions %s: the app has no legitimate use for it, and every credential it "+
					"holds is a cookie the browser attaches itself", rel, sink)
			}
		}
		for _, pat := range []string{`\{@html`, `{@html`} {
			if strings.Contains(code, pat) {
				t.Errorf("%s uses %s: unescaped markup is the one injection sink Svelte offers", rel, pat)
			}
		}
	}
	t.Logf("scanned %d app source files for %d sinks; none present in code (comments excluded)", scanned, len(jsSinks))
}

// stripComments removes line and block comments, so a sink named in prose (this
// package's own api.ts explains that it stores nothing in localStorage) is not
// counted as a use.
func stripComments(src string) string {
	var out strings.Builder
	inBlock := false
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if inBlock {
			if i := strings.Index(t, "*/"); i >= 0 {
				inBlock = false
				t = t[i+2:]
			} else {
				continue
			}
		}
		if strings.HasPrefix(t, "//") {
			continue
		}
		if i := strings.Index(line, "/*"); i >= 0 {
			if j := strings.Index(line[i:], "*/"); j >= 0 {
				line = line[:i] + line[i+j+2:]
			} else {
				line = line[:i]
				inBlock = true
			}
		}
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// TestZ08BuiltBundleLoadsNoThirdPartyResource scans the built CSS and shell for
// an origin that is not this one. A consent screen that fetches a font or an
// image from someone else tells that someone the user is looking at it.
func TestZ08BuiltBundleLoadsNoThirdPartyResource(t *testing.T) {
	fsys := webui.FS()
	if !webui.Built(fsys) {
		t.Skip("no frontend build in this checkout; run `cd web && pnpm run build` first")
	}
	var cssFiles int
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".css") {
			return err
		}
		cssFiles++
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		text := string(b)
		if strings.Contains(text, "fetch(") {
			t.Fatal("the CSS walk is reading something other than CSS")
		}
		for _, m := range regexp.MustCompile(`url\(\s*['"]?(https?:)?//[^)]*\)`).FindAllString(text, -1) {
			t.Errorf("%s loads %s", p, m)
		}
		if regexp.MustCompile(`@import\s+url\(\s*['"]?https?:`).MatchString(text) {
			t.Errorf("%s imports a stylesheet from another origin", p)
		}
		if strings.Contains(text, "@font-face") {
			t.Errorf("%s declares a font", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cssFiles == 0 {
		t.Fatal("no CSS was scanned; the probe would be vacuous")
	}

	// The shell's own outbound references must all be under /app.
	shell, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(string(shell), -1)
	if len(refs) == 0 {
		t.Fatal("the shell references nothing; the probe would be vacuous")
	}
	for _, m := range refs {
		u := m[1]
		if strings.Contains(u, "sveltekit") || u == "" {
			continue
		}
		if !strings.HasPrefix(u, "/app/") && !strings.HasPrefix(u, "data:") {
			t.Errorf("the shell references %q, which is not under /app", u)
		}
	}
	t.Logf("scanned %d CSS files and %d shell references; nothing leaves the origin", cssFiles, len(refs))
}

// TestZ08BuiltBundleDoesNotPersistSecretsInWebStorage asserts on the built bytes
// what the source scan asserts on the source: the credential path uses cookies,
// so no app code touches web storage.
//
// The SvelteKit runtime ships sessionStorage-backed helpers (they appear in the
// bundle), so the assertion is about the app's own entry points and about what
// carries a secret. The positive control is that the bundle really does contain
// the app's API client.
func TestZ08BuiltBundleDoesNotPersistSecretsInWebStorage(t *testing.T) {
	fsys := webui.FS()
	if !webui.Built(fsys) {
		t.Skip("no frontend build in this checkout; run `cd web && pnpm run build` first")
	}
	var all strings.Builder
	nodes, err := fs.Glob(fsys, "_app/immutable/*/*.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) == 0 {
		t.Fatal("no built JS chunks found")
	}
	for _, p := range nodes {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
	}
	bundle := all.String()
	if !strings.Contains(bundle, "/v1/") || !strings.Contains(bundle, "fetch(") {
		t.Fatal("the bundle does not contain the app's API client; the scan is not reading the app")
	}
	if !strings.Contains(bundle, "AbortController") {
		t.Fatal("the bundle does not contain the app's request timeout; the scan is not reading api.ts")
	}
	// The route chunks are the app's own code; the entry/chunk runtime carries
	// SvelteKit's helpers, which are not called by any route.
	routeNodes, err := fs.Glob(fsys, "_app/immutable/nodes/*.js")
	if err != nil || len(routeNodes) == 0 {
		t.Fatalf("no route chunks found: %v", err)
	}
	for _, p := range routeNodes {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			t.Fatal(err)
		}
		for _, sink := range []string{"localStorage", "sessionStorage", "document.cookie", "postMessage", "innerHTML"} {
			if strings.Contains(string(b), sink) {
				t.Errorf("route chunk %s contains %s", p, sink)
			}
		}
	}
	t.Logf("%d route chunks scanned; the API client with its timeout is present in the bundle", len(routeNodes))
}
