# syntax=docker/dockerfile:1

# A multi-stage build producing a small, non-root, static image.
#
# The frontend is built first because the Go binary embeds it (internal/webui
# uses //go:embed): a backend stage that ran before the frontend would compile
# the placeholder and ship a binary whose /app explains that it was not built.
# The stages are ordered so that mistake is impossible rather than remembered.

# ---- frontend -------------------------------------------------------------
# Base images are pinned by digest, not tag: a tag can move under the build, and
# the digest is what makes "the same Dockerfile" produce the same toolchain.
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS web
WORKDIR /src
# corepack resolves pnpm from the `packageManager` field in web/package.json, so
# the container uses the same version as CI and a laptop — not whatever `latest`
# means on the day it is built.
RUN corepack enable
# Only the manifest and lockfile first, so this layer is cached until either
# changes; the source that follows does not invalidate the dependency install.
COPY web/package.json web/pnpm-lock.yaml ./web/
RUN cd web && pnpm install --frozen-lockfile
COPY web/ ./web/
# adapter-static writes to ../internal/webui/dist, which is where //go:embed
# reads. Make the parent first so the build never depends on it existing.
RUN mkdir -p internal/webui/dist
# svelte-kit sync generates the route/type files the build reads. It is run
# explicitly because the install above happened while only the manifest was
# present, so the `prepare` script it triggers had nothing to sync (it is written
# `|| echo ''` precisely so that is not fatal).
RUN cd web && pnpm exec svelte-kit sync
RUN cd web && pnpm run build
# index.html is absent from the placeholder but present in a real build, so this
# is the assertion that a real frontend reached the embed directory.
RUN test -f internal/webui/dist/index.html

# ---- backend --------------------------------------------------------------
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The built frontend replaces whatever the source tree held (the placeholder).
COPY --from=web /src/internal/webui/dist ./internal/webui/dist
RUN test -f internal/webui/dist/index.html
# VERSION stamps the binary the same way `make release` does, so `re0auth
# -version` and the startup log answer "which build is this" in an image too.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/re0auth ./cmd/re0auth

# ---- runtime --------------------------------------------------------------
# scratch, not a distroless base: the binary is static (CGO_ENABLED=0), so the
# runtime filesystem needs exactly two things — the binary and the CA bundle for
# outbound TLS. A scratch image has no shell, package manager, libc or OS files,
# and no base-image digest that can drift. The CA bundle is copied from the
# pinned build stage, so it is the same trust store the binary was built against.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/re0auth /re0auth
# Numeric uid 65532 is the conventional nonroot id; scratch has no passwd file,
# so it stays unnamed. The process cannot write over its own image.
USER 65532:65532

# The container listens on all interfaces; the process default (127.0.0.1:8080)
# would be unreachable from outside the container. The issuer, the keys and the
# database DSN are deployment-specific and required — see README "快速开始" — so
# they are supplied at run time, never baked in.
ENV RE0AUTH_ADDR=0.0.0.0:8080
EXPOSE 8080

# No HEALTHCHECK: scratch has no shell or curl to run one with. Point the
# orchestrator at GET /healthz (liveness) and GET /readyz (readiness) instead;
# those are the endpoints this service actually promises.
ENTRYPOINT ["/re0auth"]
