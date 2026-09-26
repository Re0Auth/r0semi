# Re0Auth frontend (`web/`)

A **pure client-side SPA** (SvelteKit + `adapter-static`). It is built straight
into `internal/webui/dist` and embedded into the Go binary, so a deployment stays
"copy one file" and there is no separate frontend server in production.

Two facts shape everything here:

- `paths.base` is **`/app`** and must equal `internal/webui.BasePath`. The app
  lives under `/app/*` on the same origin as the API; the protocol plane
  (`/oauth`, `/.well-known`) stays in Go and is never shadowed.
- Every request the app makes is a **relative path** (`/v1/...`, `/oauth/...`).
  In production that is the same origin, so no CORS and no proxy; in development
  Vite proxies those paths to the Go binary.

## Run it, embedded (what ships)

```sh
cd web && pnpm install --frozen-lockfile && pnpm run build     # writes ../internal/webui/dist
cd .. && go run ./cmd/re0auth          # http://127.0.0.1:8080/app/
```

Nothing else to start. The binary embeds whatever is in `internal/webui/dist` **at
build time**, so rebuild after frontend changes — or use the dev server below.

## Run it, dev server with hot reload

Vite on `:5173`, proxying the Go plane to a re0auth already running on `:8080`.

```sh
# 1. the backend, with the issuer set to the Vite origin
RE0AUTH_ISSUER=http://localhost:5173 go run ./cmd/re0auth

# 2. the frontend, in another terminal
cd web && pnpm run dev        # or, from the repo root: make play
# open http://localhost:5173/app/
```

**The issuer must be the Vite origin.** The session cookie is written for the
host the *browser* sees; login redirects go through `{issuer}/auth/...`. If the
issuer were `:8080` while the app is read from `:5173`, the cookie would be set on
`:8080` and never sent with the app's requests — the login would appear to work and
then silently drop you back out.

Register the OAuth app's redirect URI to match:

```
http://localhost:5173/auth/<provider>/callback
```

`vite.config.ts` proxies `/v1`, `/oauth`, `/.well-known`, `/auth` and `/bind` to
`http://127.0.0.1:8080`, and mirrors Go's `/` → `/app/` redirect so a login that
returns to `return_to=/` lands on the app rather than a 404.

> Alternative that needs no OAuth-app change: leave the issuer at its configured
> value (`:8080`), sign in there, then open `http://127.0.0.1:5173/app/`. Cookies
> are scoped per **host**, not per port, so `127.0.0.1:8080` and
> `127.0.0.1:5173` share the same session.

## Checks and tests

```sh
pnpm run check        # svelte-check (types)
pnpm run build && pnpm run check:bundle   # the SPA's weight budget (see below)
pnpm run test:e2e     # Playwright; builds and starts its own re0auth + fake IdP
```

`check:bundle` measures what actually ships — the SPA is embedded in every binary
and image, so its weight is paid by every deployment. The budget lives in
`scripts/check-bundle-size.mjs` and is raised deliberately (in a commit that says
why) rather than nudged to make a red build green. It refuses to measure the embed
placeholder: a budget that passes on an empty directory is worse than no budget, so
run it after a build.

The e2e suite (`web/e2e/`) is where the login, consent, device and binding flows
are covered end to end, through the real shipping code, with a fake IdP at the
network edge rather than a test-only bypass inside re0auth.

## Visual regression

```sh
pnpm run test:visual          # compare against this platform's baselines
pnpm run test:visual:update   # make or refresh them
```

Screenshot baselines are bound to the **platform** — font rasterisation and
scrollbar width differ between Linux, macOS and Windows — so the file name carries
it and two sets can coexist. `pnpm run test:e2e` skips them (the `@visual` tag): a
visual test with no baseline for the current platform fails by definition.

The Linux set, which is the one CI would compare against, comes from the
`visual-baselines` workflow (manual dispatch). It runs `test:visual:update` and
uploads `web/e2e/*-snapshots/**` as an artifact, and it commits **nothing**: a
token that can push can rewrite history, and "artifact plus one reviewed commit"
reaches the same place without that. Two steps:

1. Actions → *visual baselines* → Run workflow, then download
   `visual-baselines-linux`;
2. commit the `*-linux.png` files into each spec's `-snapshots` directory, then add
   a `pnpm run test:visual` step to the CI job — that is what turns the comparison
   into a gate.

## Layout

| Path | What |
|---|---|
| `src/routes/+page.svelte` | Account page: sign in, linked identities, sign out |
| `src/routes/consent`, `device`, `grants`, `sources` | The rest of the app |
| `src/lib/api.ts` | The only place that talks to `/v1` |
| `src/lib/components/` | UI (including `SignIn.svelte`) |
| `e2e/` | Playwright specs and the fake IdP/server harness |
