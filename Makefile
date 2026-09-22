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
	cd web && npm ci && npm run build
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
	cd web && npx playwright install chromium && npx playwright test

check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not gofmt'd:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	cd web && npm run check

# Frontend dev server on :5173, proxying nothing: it talks to a re0auth already
# running on :8080. Both must agree on the issuer, and the session cookie has to
# be shared, so start re0auth with RE0AUTH_ISSUER=http://localhost:5173/app and
# visit the app through Vite rather than through Go.
play:
	cd web && npm run dev

clean:
	rm -rf web/node_modules web/.svelte-kit
