import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig, type Plugin } from 'vite';

// In development the browser is on the Vite origin (:5173) while the API is the
// Go binary on :8080, so the Go plane's paths are proxied. Everything the app
// fetches is a relative path like `/v1/...`, which means without this it would
// all hit Vite and 404.
//
// The issuer must then be the Vite origin (`RE0AUTH_ISSUER=http://localhost:5173`),
// so that the session cookie is written for the host the app is read from. A
// mismatch logs the user straight back out. See web/README.md.
const apiTarget = 'http://127.0.0.1:8080';
const apiPaths = ['/v1', '/oauth', '/.well-known', '/auth', '/bind'];

// The Go binary answers `/` with a 302 to `/app/`. In development `/` is served
// by Vite, so a login that returns to `return_to=/` (the default) would land on a
// 404. Mirroring the redirect keeps the dev flow identical to production.
function devRootRedirect(): Plugin {
	return {
		name: 're0auth-dev-root-redirect',
		configureServer(server) {
			server.middlewares.use((req, res, next) => {
				// The minimal IncomingMessage this project resolves without
				// @types/node has no `url`; it is present at runtime.
				const path = (req as { url?: string }).url;
				if (path === '/' || path === '') {
					res.writeHead(302, { Location: '/app/' });
					res.end();
				} else {
					next();
				}
			});
		}
	};
}

export default defineConfig({
	server: {
		proxy: Object.fromEntries(apiPaths.map((path) => [path, apiTarget]))
	},
	plugins: [
		devRootRedirect(),
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// A static SPA served by the Go binary out of an embedded filesystem.
			//
			//   fallback: 'index.html' -- the whole app is client-rendered, so every
			//   route under /app is answered by one shell and the client router picks
			//   the page. That keeps the Go side dumb: it serves a file if one exists
			//   and the shell otherwise, and adding a route never touches Go.
			//
			//   base: '/app' -- the app lives at /app/* on the same origin as the API,
			//   so the session cookie is sent without CORS and without a proxy. It
			//   must never be mountable at the root: "/" is the protocol plane's
			//   neighbourhood, and a frontend route that shadowed /oauth or
			//   /.well-known would be a security bug, not a routing one.
			adapter: adapter({
				// Straight into the Go package that embeds it. go:embed cannot reach
				// outside its own directory, and a copy step is a thing that silently
				// stops running, so the build writes where the binary reads.
				pages: '../internal/webui/dist',
				assets: '../internal/webui/dist',
				fallback: 'index.html',
				precompress: false,
				strict: false
			}),

			paths: {
				base: '/app'
			},

			// A Content-Security-Policy for the app's HTML, emitted by SvelteKit as
			// hashes for the inline bootstrap script it has to inject.
			//
			// Why not just write the header in Go: that header cannot include these
			// hashes, because they change with every build, and the alternative is
			// 'unsafe-inline' for scripts — which on a consent screen is the whole
			// ballgame. SvelteKit knows what it emitted, so it is the only party that
			// can produce this correctly.
			//
			// The Go side still sends its own single-directive header
			// (frame-ancestors 'none'; see internal/webui). Two policies are enforced
			// as an intersection, and frame-ancestors is ignored in a meta tag, which
			// is why that one has to come from a header.
			csp: {
				mode: 'hash',
				directives: {
					'default-src': ['self'],
					'script-src': ['self'],
					'style-src': ['self', 'unsafe-inline'],
					'img-src': ['self', 'data:'],
					'font-src': ['self'],
					// The app talks to /v1 on its own origin and nowhere else.
					'connect-src': ['self'],
					// No page here submits a native form; every action is a fetch.
					'form-action': ['none'],
					'base-uri': ['none'],
					'object-src': ['none'],
					'frame-ancestors': ['none']
				}
			}
		})
	]
});
