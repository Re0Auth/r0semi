# Re0Auth build entry points.
#
# The Go module builds on its own. `go build ./cmd/re0auth` works with no Node
# installed at all, because internal/webui embeds a placeholder when the frontend
# has not been built and the server answers /app with an explanation instead of a
# blank page. The `web` target replaces that placeholder with the real app.
#
# So `make` is how you get a *complete* binary, and `go build` is how you get one
# that is honest about being incomplete.

.PHONY: all web build test check e2e play dist checksums release clean

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

# Release artifacts: one archive per platform, each carrying the example config,
# the licence and the pre-release warning.
#
# `release` depends on `web` for the reason the header gives, and asserts the
# result: the Go binaries embed internal/webui/dist, so packaging before the
# frontend is built would ship a binary whose /app answers "Frontend not built".
# The placeholder has no index.html, which is what makes the assertion possible.
#
# Split into two targets so the compile-and-archive half can be run and inspected
# on its own; `release` adds the checksums a published artifact must carry.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
RELEASE_PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
ZIP ?= zip
# sha256sum is coreutils; macOS ships shasum instead.
SHA256 ?= $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256")

dist: web
	@test -f internal/webui/dist/index.html || { echo "refusing to package: the embedded frontend is the placeholder"; exit 1; }
	rm -rf dist && mkdir -p dist
	@for platform in $(RELEASE_PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		name="re0auth_$(VERSION)_$${os}_$${arch}"; \
		echo "  $$name"; \
		mkdir -p "dist/$$name"; \
		ext=""; [ "$$os" = windows ] && ext=".exe"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o "dist/$$name/re0auth$$ext" ./cmd/re0auth || exit 1; \
		cp config/re0auth.example.toml LICENSE NOTICE README.md SECURITY.md "dist/$$name/"; \
		if [ "$$os" = windows ]; then \
			(cd dist && $(ZIP) -qr "$$name.zip" "$$name") || exit 1; \
		else \
			tar -czf "dist/$$name.tar.gz" -C dist "$$name" || exit 1; \
		fi; \
		rm -rf "dist/$$name"; \
	done
	@echo "packaged $(VERSION):"; ls -1 dist

# Requires sha256sum (coreutils) or shasum (macOS), and zip for the Windows
# archives. CI runs on ubuntu-latest, where all three exist; a Windows checkout
# can build the project but not cut a release.
checksums: dist
	@cd dist && $(SHA256) re0auth_$(VERSION)_* > SHA256SUMS && echo "checksums: $$(wc -l < SHA256SUMS) file(s)"

release: dist checksums

clean:
	rm -rf web/node_modules web/.svelte-kit dist
