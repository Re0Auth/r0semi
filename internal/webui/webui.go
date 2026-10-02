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
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
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

// shellName is the build's fallback document. It is the file a path that names
// nothing is answered with, and the only document whose cache validator this
// package can compute -- the digest its own bytes produce.
const shellName = "index.html"

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

// Robots returns the robots.txt that ships with the build, if there is one.
//
// The file is written for the root of the origin, and adapter-static copies it
// under the app's prefix — where no crawler looks, so its Disallow is never read.
// Serving it is a routing decision and belongs to the composition root; carrying
// the bytes is this package's, so there is one copy of the file rather than a
// second one written in Go that can drift.
func Robots(fsys fs.FS) ([]byte, bool) {
	b, err := fs.ReadFile(fsys, "robots.txt")
	if err != nil {
		return nil, false
	}
	return b, true
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
	// Whether there is a build at all is a property of the tree, not of the
	// request: answering it once here is what keeps an asset request from
	// re-statting the embedded filesystem for a fact that cannot change while the
	// process runs (S12-11). The method gate stays inside, so an unbuilt binary
	// still answers a write with 405 rather than 503.
	if !Built(fsys) {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			writeNotBuilt(w)
		})
	}

	// The shell's validator is computed once from the bytes that will be served:
	// the embedded shell cannot change while the process runs (S12-8 / A-FE-1).
	var shell shellValidator

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
			name = shellName
		}

		if isHTMLDocument(name) {
			// Set, not Add: this handler owns its own document's policy even when it is
			// wrapped by the API's middleware, which sets the same single directive.
			//
			// The rule is the response's type, not the name index.html (A-FE-6): a
			// build that ships a second document gets the same framing guard. What
			// the header must NOT carry is anything the build's <meta> policy already
			// states -- the two are enforced as an intersection.
			w.Header().Set("Content-Security-Policy", shellCSP)
			// A document is one representation, not a byte range (A-FE-2): cut into
			// ranges it could arrive without the <meta> policy that governs the script
			// inside it. The request is cloned so the caller's own does not change.
			r = r.Clone(r.Context())
			r.Header.Del("Range")
			r.Header.Del("If-Range")
			// Only the shell gets this validator: it is the digest of index.html, so
			// pinning it to any other document would let a 304 stand in for bytes
			// that changed.
			if name == shellName {
				if tag := shell.etag(fsys); tag != "" {
					w.Header().Set("ETag", tag)
				}
			}
		}
		setCacheHeaders(w, name)
		if strings.HasPrefix(name, "_app/immutable/") {
			// The session middleware adds `Vary: Cookie` to every response on the
			// tree before any handler runs, which keys a content-hashed,
			// user-independent asset on the session cookie and cancels the immutable
			// directive for any shared cache (Z08-5). The representation does not
			// depend on the cookie, so the token is dropped here; the compression
			// layer outside this handler adds `Accept-Encoding` back if it applies.
			w.Header().Del("Vary")
		}
		// name was cleaned above and only reaches "index.html" or a file that
		// fs.Stat confirmed inside fsys; the server is an fs.FS, not the host
		// filesystem, so there is no path to escape to. G703 cannot see the
		// isFile/fs.FS guard through ServeFileFS's signature.
		http.ServeFileFS(w, r, fsys, "/"+name) //nolint:gosec // G703: name is cleaned and confined to the embedded fs.FS
	})
}

// shellValidator holds the SPA shell's strong ETag, computed from the bytes that
// will be served the first time a document is requested.
//
// `Cache-Control: no-cache` means "revalidate"; with no validator there is
// nothing to revalidate against, so every navigation re-sent the whole document
// (S12-8 / A-FE-1). The shell is embedded and therefore immutable for the life of
// the process, so one read and one hash are enough, and the value only changes
// when a new build is deployed.
type shellValidator struct {
	once sync.Once
	tag  string
}

func (v *shellValidator) etag(fsys fs.FS) string {
	v.once.Do(func() {
		raw, err := fs.ReadFile(fsys, shellName)
		if err != nil {
			// No readable shell means nothing to validate; ServeFileFS will report
			// the same condition as a 404 rather than a second failure here.
			return
		}
		sum := sha256.Sum256(raw)
		v.tag = `"` + hex.EncodeToString(sum[:16]) + `"`
	})
	return v.tag
}

// isHTMLDocument reports whether a served name is a document rather than an
// asset, by extension. The served file's own type is what decides whether the
// response gets a document policy.
func isHTMLDocument(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".htm":
		return true
	default:
		return false
	}
}

func isFile(fsys fs.FS, name string) bool {
	info, err := fs.Stat(fsys, name)
	return err == nil && !info.IsDir()
}

// setCacheHeaders caches hashed assets forever and everything else not at all.
//
// Getting the default backwards is a subtle and expensive bug: a cached shell
// would keep pointing at asset filenames that no longer exist, so a deployment
// would break for returning users until they hard-refreshed. Leaving a file
// unclassified was the other half of that bug in the opposite direction
// (Z08-3): it inherited no directive at all, so each browser chose a freshness
// heuristic for the favicon, the app's robots.txt copy and the version document
// the client polls. Only `_app/immutable/` is content-addressed and safe to pin
// for a year; the version document exists to be re-read, so it is not stored; a
// document must be revalidated (and now has an ETag to revalidate with).
func setCacheHeaders(w http.ResponseWriter, name string) {
	switch {
	case strings.HasPrefix(name, "_app/immutable/"):
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	case name == "_app/version.json":
		w.Header().Set("Cache-Control", "no-store")
	default:
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
