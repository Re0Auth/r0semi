# Re0Auth build entry points.
#
# The Go module builds on its own. `go build ./cmd/re0auth` works with no Node
# installed at all, because internal/webui embeds a placeholder when the frontend
# has not been built and the server answers /app with an explanation instead of a
# blank page. The `web` target replaces that placeholder with the real app.
#
# So `make` is how you get a *complete* binary, and `go build` is how you get one
# that is honest about being incomplete.

.PHONY: all web build test bench check lint load e2e play dist sbom checksums release docker clean bundle

all: web build

# Build the frontend straight into the directory the Go binary embeds.
web:
	cd web && pnpm install --frozen-lockfile && pnpm run build
	@# The placeholder that keeps the embed compiling has no index.html, so its
	@# presence is proof that a real build reached the embed directory.
	@test -f internal/webui/dist/index.html || { echo "frontend build did not land in internal/webui/dist"; exit 1; }

build:
	go build ./cmd/re0auth ./cmd/referencesource

# The SPA's weight budget. It depends on `web` because it measures what the build
# produced: the script refuses to measure the embed placeholder, since a budget
# that passes on an empty directory is worse than no budget. CI runs the same
# check right after its own build.
bundle: web
	cd web && pnpm run check:bundle

test:
	go test ./...

# Statement coverage, per package, lowest first — the same table CI writes to its
# job summary, from the same code (cmd/covertable), so the two cannot drift. The
# Postgres tests skip without TEST_DATABASE_URL, so a local run reads lower than
# CI's; both are honest about what they actually ran.
cover:
	go test -count=1 -covermode=atomic -coverprofile=coverage.out ./...
	go run ./cmd/covertable coverage.out
	@rm -f coverage.out

# Capacity benchmarks. They build their own server on the in-memory stores, so
# no database is needed. The numbers are reported, not asserted: a benchmark gate
# that fails on a slow machine is a gate people delete. CI runs this to prove the
# benchmarks still execute — a benchmark whose fixture stopped compiling is a
# number that silently stopped existing — and its floor is "results were
# produced", not a threshold.
bench:
	go test -run '^$$' -bench . -benchmem ./...

# The capacity profile: concurrent load against a real HTTP server on the in-memory
# stores, reporting throughput and the latency tail rather than ns/op. Like `bench`
# it reports instead of thresholding — a capacity gate that fails on a slow runner
# is a gate people delete — but the run itself fails if it completed no work, so a
# green result cannot mean "nothing was measured".
#
# RE0AUTH_LOAD_SECONDS / RE0AUTH_LOAD_WORKERS tune it; the defaults (10s, 8) are
# what CI runs. Numbers from a run go into docs/capacity-planning.md's framing:
# in-memory stores make this a ceiling, not a promise.
load:
	RE0AUTH_LOAD_PROFILE=1 go test -count=1 -v -run TestLoadProfile ./internal/httpapi/

# Browser tests. They build and start their own re0auth plus a fake identity
# provider, so nothing else needs to be running — and there is no test-only way
# to obtain a session, which is why the suite is worth having.
e2e: web
	cd web && pnpm exec playwright install chromium && pnpm exec playwright test

check: lint
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not gofmt'd:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	# The dependency firewall. `go test ./...` also runs it; here it is explicit
	# so `make check` fails on a layering violation without running the full suite.
	go test ./internal/archtest/
	cd web && pnpm run check

# Static analysis, the same linter the CI job of the same name runs. The version
# is pinned to what that job installs (v2.14.0): a newer one may be installed by
# hand, but the gate people run locally has to be the gate CI will apply.
#
# It is a hard requirement of `check`, not "run it if you have it". The point of
# `check` is that green here means green in CI, and a gate that quietly skips the
# linter is the same failure mode as a test that skips when a dependency is
# missing — which is exactly what this target was added to stop.
LINT ?= golangci-lint
lint:
	@command -v $(LINT) >/dev/null 2>&1 || { \
		echo "golangci-lint is not on PATH; install the version CI pins with:"; \
		echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0"; \
		exit 1; }
	$(LINT) run --timeout=5m ./...

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
# Split into targets so each half can be run and inspected on its own. The chain
# is a dependency chain rather than a list of steps on purpose: `dist` wipes the
# output directory, so an SBOM produced before it would be deleted, and a release
# assembled by hand in the wrong order is exactly the kind of mistake an ordering
# someone has to remember invites. `release` is the whole thing: archives, the
# SBOM, and checksums that cover both.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
RELEASE_PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
ZIP ?= zip
# sha256sum is coreutils; macOS ships shasum instead.
SHA256 ?= $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256")
# The SBOM generator. Pinned here and in the release workflow; a newer one may be
# installed by hand, but a release does not float on an upstream tag.
#   go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
SBOM ?= cyclonedx-gomod

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

# The software bill of materials: a CycloneDX inventory of every module linked
# into the binaries.
#
# It is generated from the module graph rather than from one built binary, because
# the dependency set is identical on all six platforms — the Go toolchain links
# statically, so there is no per-platform difference to record.
#
# The file is named so the checksum glob below matches it. A checksum file that
# silently skips a published artifact is worse than none, because it looks
# complete; and the `-s` test refuses an empty one for the same reason — an SBOM
# with no components would pass every other check in this file.
sbom: dist
	@command -v $(SBOM) >/dev/null 2>&1 || { \
		echo "the SBOM generator is not on PATH; install it with:"; \
		echo "  go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0"; \
		exit 1; }
	$(SBOM) mod -json -output "dist/re0auth_$(VERSION)_sbom.cdx.json"
	@test -s "dist/re0auth_$(VERSION)_sbom.cdx.json" || { echo "refusing to ship an empty SBOM"; exit 1; }
	@echo "sbom: dist/re0auth_$(VERSION)_sbom.cdx.json"

# Requires sha256sum (coreutils) or shasum (macOS), and zip for the Windows
# archives. CI runs on ubuntu-latest, where all three exist; a Windows checkout
# can build the project but not cut a release.
checksums: sbom
	@cd dist && $(SHA256) re0auth_$(VERSION)_* > SHA256SUMS && echo "checksums: $$(wc -l < SHA256SUMS) file(s)"

release: dist sbom checksums

# Container image. There is no registry and no push here: this builds the image
# from the same source the release archives come from, for a deployment to tag
# and push itself. The Dockerfile takes the target platform from the build, so
# multi-arch is a `docker buildx build --platform` flag away rather than a change
# to any of this.
IMAGE ?= re0auth
docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

clean:
	rm -rf web/node_modules web/.svelte-kit dist
