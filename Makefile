# Re0Auth build entry points.
#
# The Go module builds on its own. `go build ./cmd/re0auth` works with no Node
# installed at all, because internal/webui embeds a placeholder when the frontend
# has not been built and the server answers /app with an explanation instead of a
# blank page. The `web` target replaces that placeholder with the real app.
#
# So `make` is how you get a *complete* binary, and `go build` is how you get one
# that is honest about being incomplete.

.PHONY: all web build test check e2e play clean

all: web build

# Build the frontend straight into the directory the Go binary embeds.
web:
	cd web && pnpm install --frozen-lockfile && pnpm run build
	@# The placeholder that keeps the embed compiling has no index.html, so its
	@# presence is proof that a real build reached the embed directory.
	@test -f internal/webui/dist/index.html || { echo "frontend build did not land in internal/webui/dist"; exit 1; }

build:
	go build ./cmd/re0auth ./cmd/referencesource

test:
	go test ./...

# Browser tests. They build and start their own re0auth plus a fake identity
# provider, so nothing else needs to be running — and there is no test-only way
# to obtain a session, which is why the suite is worth having.
e2e: web
	cd web && pnpm exec playwright install chromium && pnpm exec playwright test

check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not gofmt'd:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	# The dependency firewall. `go test ./...` also runs it; here it is explicit
	# so `make check` fails on a layering violation without running the full suite.
	go test ./internal/archtest/
	cd web && pnpm run check

# Frontend dev server with hot reload (Vite on :5173).
#
# It proxies /v1, /oauth, /.well-known, /auth and /bind to a re0auth already
# running on :8080, so start that first — with the issuer set to the Vite origin,
# because the session cookie is written for whatever host the browser sees:
#
#   RE0AUTH_ISSUER=http://localhost:5173 go run ./cmd/re0auth &
#   make play
#   # then open http://localhost:5173/app/
#
# The OAuth app's redirect URI must match: http://localhost:5173/auth/<provider>/callback.
# (To keep the :8080 callback instead, leave the issuer alone and open the dev
# server at http://127.0.0.1:5173/app/ after signing in; cookies are per host, not
# per port, so :8080 and :5173 share them.)
play:
	cd web && pnpm run dev

clean:
	rm -rf web/node_modules web/.svelte-kit
