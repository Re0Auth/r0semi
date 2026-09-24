# syntax=docker/dockerfile:1

# A multi-stage build producing a small, non-root, static image.
#
# The frontend is built first because the Go binary embeds it (internal/webui
# uses //go:embed): a backend stage that ran before the frontend would compile
# the placeholder and ship a binary whose /app explains that it was not built.
# The stages are ordered so that mistake is impossible rather than remembered.

# ---- frontend -------------------------------------------------------------
FROM node:24-alpine AS web
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
FROM golang:1.27-alpine AS build
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
# distroless/static: no shell, no package manager, no libc (the binary is static),
# and it carries the CA certificates outbound TLS needs. `nonroot` runs as uid
# 65532, so the process cannot write over its own image.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/re0auth /re0auth

# The container listens on all interfaces; the process default (127.0.0.1:8080)
# would be unreachable from outside the container. The issuer, the keys and the
# database DSN are deployment-specific and required — see README "快速开始" — so
# they are supplied at run time, never baked in.
ENV RE0AUTH_ADDR=0.0.0.0:8080
EXPOSE 8080

# No HEALTHCHECK: distroless has no shell or curl to run one with. Point the
# orchestrator at GET /healthz (liveness) and GET /readyz (readiness) instead;
# those are the endpoints this service actually promises.
ENTRYPOINT ["/re0auth"]
