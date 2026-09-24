// Package webui serves the built frontend.
//
// The frontend is a static single-page app: SvelteKit with adapter-static and a
// fallback shell, mounted under BasePath on the same origin as the API. It is
// embedded into the binary rather than read from disk so that deploying Re0Auth
// stays "copy one file", which is most of the reason it is a Go binary at all.
//
// What this package deliberately does NOT do: it never injects data, never
// templates, and never rewrites the shell. Everything the app displays it fetches
// from /v1 with the session cookie the browser already holds. Injecting anything
// here would put frontend build output on the path that decides what a consent
// screen says, which is the one place it must not be.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// BasePath is the URL prefix the app is mounted at.
//
// It must equal `paths.base` in web/vite.config.ts: the client router and every
// asset URL are generated with that value baked in. A mismatch does not fail
// loudly — the shell still loads and then routes to nothing — so a test reads
// that config and compares, rather than trusting two files to stay in step.
const BasePath = "/app"

// shellCSP is the only part of the app's policy that a header may carry.
//
// A document can be governed by both a header policy and a <meta> policy, and
// when it is, **both are enforced**. The header cannot loosen the meta tag, but
// it can silently tighten it — and that is not a theoretical hazard. An earlier
// version of this constant restated the whole policy, including
// `script-src 'self'` with no hash. SvelteKit's meta tag allows its inline
// bootstrap script by hash; the header did not, so the header won, the bootstrap
// was blocked, and the app rendered as a blank page. No test caught it, because
// every test was looking at the header.
//
// So: anything the build already expresses belongs in the meta tag, and this is
// the one directive that must live here because browsers ignore frame-ancestors
// in a <meta> tag.
const shellCSP = "frame-ancestors 'none'"

//go:embed all:dist
var embedded embed.FS

// FS returns the embedded frontend build.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		// Unreachable unless the embed directive and this name disagree, which is a
		// compile-time property. A panic states that plainly instead of returning a
		// nil FS that would look like "the frontend was not built".
		panic("webui: embedded dist is missing: " + err.Error())
	}
	return sub
}

// Built reports whether fsys holds a frontend build, as opposed to the
// placeholder that keeps `go build` working for someone who only has Go.
func Built(fsys fs.FS) bool {
	_, err := fs.Stat(fsys, "index.html")
	return err == nil
}

// Handler serves the app from fsys under BasePath.
//
// The routing rule, in full: a path naming an existing file is served that file;
// anything else is answered with the SPA shell and the client router takes over.
// Two consequences are worth being explicit about.
//
//   - An unknown path under the mount answers 200 with the shell, not 404. That is
//     what a client-side router requires, and it is exactly why this handler must
//     stay pinned to its own prefix: mounted any wider, it would swallow the
//     API's 404s and turn them into HTML.
//   - With no build present, a plain explanation is served instead. Every Go
//     command has to work for someone who has not run npm, so the embed is
//     satisfied by a placeholder committed to the tree rather than by a build
//     step. CI builds the real frontend and asserts the shell exists, so the
//     placeholder cannot be the thing that gets tested.
func Handler(fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !Built(fsys) {
			writeNotBuilt(w)
			return
		}

		// Clean before opening, so a traversal attempt collapses into an ordinary
		// missing name and falls through to the shell rather than escaping fsys.
		name := path.Clean("/" + strings.TrimPrefix(r.URL.Path, BasePath))
		name = strings.TrimPrefix(name, "/")

		// The shell answers for itself and for anything that is not a file. Note
		// that a directory is not a file: there are no directory listings, and a
		// path like /app/_app would otherwise enumerate the build.
		if name == "" || name == "." || !isFile(fsys, name) {
			name = "index.html"
		}

		if name == "index.html" {
			// Set, not Add: this handler owns its own document's policy even when it is
			// wrapped by the API's middleware, which sets the same single directive.
			w.Header().Set("Content-Security-Policy", shellCSP)
		}
		setCacheHeaders(w, name)
		http.ServeFileFS(w, r, fsys, "/"+name)
	})
}

func isFile(fsys fs.FS, name string) bool {
	info, err := fs.Stat(fsys, name)
	return err == nil && !info.IsDir()
}

// setCacheHeaders caches hashed assets forever and the shell not at all.
//
// Getting this backwards is a subtle and expensive bug: a cached shell would
// keep pointing at asset filenames that no longer exist, so a deployment would
// break for returning users until they hard-refreshed.
func setCacheHeaders(w http.ResponseWriter, name string) {
	switch {
	case strings.HasPrefix(name, "_app/immutable/"):
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	case name == "index.html":
		w.Header().Set("Cache-Control", "no-cache")
	}
}

// writeNotBuilt explains an unbuilt frontend. It is plain HTML with no styling
// from the app, because the app is what is missing.
func writeNotBuilt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Re0Auth frontend not built</title></head>
<body style="font-family:system-ui;max-width:38rem;margin:4rem auto;padding:0 1rem;line-height:1.6">
<h1>Frontend not built</h1>
<p>This binary was built without the frontend, so there is no page here. The API
is unaffected and still available under <code>/oauth/</code> and <code>/v1/</code>.</p>
<pre><code>cd web &amp;&amp; pnpm install --frozen-lockfile &amp;&amp; pnpm run build</code></pre>
<p>then rebuild the Go binary. <code>make web</code> at the repository root does both.</p>
</body></html>
`))
}
