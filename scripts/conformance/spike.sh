#!/usr/bin/env bash
# OIDF Conformance Suite connectivity spike (step 3 of the launch plan).
#
# Proves the wiring the real run depends on, one milestone at a time:
#   1. the OP serves discovery over plain HTTP on the runner;
#   2. Caddy terminates TLS for the issuer name and reverses to the OP;
#   3. the host can fetch discovery through Caddy with a self-signed certificate;
#   4. a CONTAINER on the same bridge can do the same with Caddy's root CA —
#      which is the path the conformance suite container will use;
#   5. the suite image starts and its REST API answers.
#
# It deliberately stops short of asserting a plan result: the plan name, variant
# and client configuration come from the suite, and pinning those before the first
# observed run would be guessing. `CONFORMANCE_PLAN_JSON`, when set to a file,
# posts that payload to /api/runner and reports the outcome.
#
# Requires Docker. Windows/macOS developers: run it under WSL2 or a Linux host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
CADDY_NAME=re0auth-spike-caddy
SUITE_NAME=re0auth-spike-suite
OP_PID=""

log()  { printf 'spike: %s\n' "$*"; }
fail() { printf 'spike: FAIL — %s\n' "$*" >&2; exit 1; }

# Milestones are recorded as well as logged: the workflow turns this file into the
# run's step summary, which is what "check last night's report" actually reads.
MILESTONES="${WORK}/milestones.txt"
pass() { printf 'PASS %s\n' "$*" | tee -a "${MILESTONES}"; log "$*"; }
warn() { printf 'WARN %s\n' "$*" | tee -a "${MILESTONES}"; log "$*"; }

cleanup() {
  [[ -n "${OP_PID}" ]] && kill "${OP_PID}" 2>/dev/null || true
  docker rm -f "${CADDY_NAME}" "${SUITE_NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

command -v docker >/dev/null || fail "docker is required (the local Windows host has none)"
command -v openssl >/dev/null || fail "openssl is required"
command -v curl >/dev/null || fail "curl is required"
# CI images have python3; a WSL/desktop shell may only have python, or may have a
# Microsoft Store shim that `command -v` finds but cannot execute. Probe, don't assume.
PYTHON=""
for candidate in python3 python; do
  if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import sys' >/dev/null 2>&1; then
    PYTHON="${candidate}"
    break
  fi
done
[[ -n "${PYTHON}" ]] || fail "a working python3 (or python) is required"

ISSUER="https://re0auth.test:8443"
PUBLIC_PORT=8443
SUITE_PORT=9443
OP_PORT=8080

# ---- material ---------------------------------------------------------------
log "generating keys"
head -c 32 /dev/urandom | base64 -w0 > "${WORK}/kek"
head -c 32 /dev/urandom | base64 -w0 > "${WORK}/token-key"
# The OP reads a PKCS#8 DER key. `genpkey -outform DER` emits PKCS#1 for RSA on
# some OpenSSL builds, which the OP refuses with "use ParsePKCS1PrivateKey"; going
# through `pkcs8 -topk8 -nocrypt` produces PKCS#8 on every version.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -outform DER 2>/dev/null \
  | base64 -w0 > "${WORK}/signing-key"

export RE0AUTH_KEK="$(cat "${WORK}/kek")"
export RE0AUTH_OIDC_TOKEN_KEY="$(cat "${WORK}/token-key")"
export RE0AUTH_OIDC_SIGNING_KEY="$(cat "${WORK}/signing-key")"
export RE0AUTH_ISSUER="${ISSUER}"
export RE0AUTH_COOKIE_SECURE=true
export CONFORMANCE_CLIENT_SECRET="${CONFORMANCE_CLIENT_SECRET:-spike-secret}"
export RE0AUTH_CLIENT_SECRET="${CONFORMANCE_CLIENT_SECRET}"

# The suite's redirect URI is generated per deployment; override it with
# CONFORMANCE_REDIRECT_URI once the suite shows you its client configuration.
REDIRECT_URI="${CONFORMANCE_REDIRECT_URI:-https://localhost:${SUITE_PORT}/test/a/conformance/callback}"
# `[client]` keys come from cmd/re0auth/config.go's clientSection: id, name,
# secret_env, redirect_uris, scopes. `client_id` belongs to [idp.*] and is an
# unknown key here, which the config loader refuses by design.
cat > "${WORK}/re0auth.toml" <<TOMLEOF
[server]
issuer = "${ISSUER}"
addr   = "0.0.0.0:${OP_PORT}"
cookie_secure = true

[client]
id = "conformance"
secret_env   = "RE0AUTH_CLIENT_SECRET"
redirect_uris = ["${REDIRECT_URI}"]
TOMLEOF

# ---- 1. the OP --------------------------------------------------------------
log "building and starting the OP"
( cd "${ROOT}" && go build -o "${WORK}/re0auth" ./cmd/re0auth )
"${WORK}/re0auth" -config "${WORK}/re0auth.toml" > "${WORK}/op.log" 2>&1 &
OP_PID=$!

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${OP_PORT}/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS "http://127.0.0.1:${OP_PORT}/healthz" >/dev/null \
  || { cat "${WORK}/op.log"; fail "the OP never became healthy"; }
pass "milestone 1: the OP answers /healthz on :${OP_PORT}"
# ---- 2. Caddy terminates TLS ------------------------------------------------
log "starting Caddy (self-signed 'tls internal')"
cat > "${WORK}/Caddyfile" <<CADDYEOF
${ISSUER#https://} {
	tls internal
	reverse_proxy host.docker.internal:${OP_PORT}
}
CADDYEOF
docker run -d --name "${CADDY_NAME}" \
  --add-host host.docker.internal:host-gateway \
  -p "${PUBLIC_PORT}:8443" \
  -v "${WORK}/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2 >/dev/null

for _ in $(seq 1 40); do
  if curl -fsSk "${ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsSk "${ISSUER}/.well-known/openid-configuration" >/dev/null \
  || { docker logs "${CADDY_NAME}"; fail "Caddy never served the discovery document"; }
pass "milestones 2/3: discovery is served over TLS through Caddy"

# ---- 4. the container-to-OP path with Caddy's own CA ------------------------
log "extracting Caddy's root CA"
docker cp "${CADDY_NAME}:/data/caddy/pki/authorities/local/root.crt" "${WORK}/caddy-root.crt"
docker run --rm \
  --add-host re0auth.test:host-gateway \
  -v "${WORK}/caddy-root.crt:/etc/ssl/certs/caddy-root.crt:ro" \
  curlimages/curl:latest \
  -fsS --cacert /etc/ssl/certs/caddy-root.crt "${ISSUER}/.well-known/openid-configuration" >/dev/null
pass "milestone 4: a container reaches the OP over TLS with the spike CA"

# ---- 4b. a suite image that trusts the spike CA -----------------------------
# The suite runs on the JVM, whose trust store is its own `cacerts`; mounting a
# PEM into the container does nothing for it. Derive an image that imports Caddy's
# root CA, so the suite will accept the self-signed issuer. A build failure falls
# back to the upstream image so the connectivity milestones below still report.
SUITE_IMAGE="openid/conformance-suite"
log "building a suite image that trusts the spike CA"
# A clean build context: the working directory also holds the generated keys, and
# a build context is shipped to the daemon whole.
mkdir -p "${WORK}/suite-image"
cp "${WORK}/caddy-root.crt" "${WORK}/suite-image/caddy-root.crt"
cat > "${WORK}/suite-image/Dockerfile" <<'DOCKEREOF'
FROM openid/conformance-suite
USER root
COPY caddy-root.crt /tmp/re0auth-spike-ca.crt
RUN set -eux; \
    ks="${JAVA_HOME:-/opt/java/openjdk}/lib/security/cacerts"; \
    keytool -importcert -noprompt -trustcacerts \
      -alias re0auth-spike -file /tmp/re0auth-spike-ca.crt \
      -keystore "${ks}" -storepass changeit
DOCKEREOF
if docker build -t re0auth-conformance-spike:local -f "${WORK}/suite-image/Dockerfile" "${WORK}/suite-image" > "${WORK}/suite-build.log" 2>&1; then
  SUITE_IMAGE="re0auth-conformance-spike:local"
  pass "milestone 4b: a CA-trusting suite image was built"
else
  warn "milestone 4b: building the CA-trusting image failed; using the upstream image"
  tail -n 20 "${WORK}/suite-build.log" || true
fi

# ---- 5. the suite itself ----------------------------------------------------
log "starting the conformance suite (${SUITE_IMAGE})"
docker run -d --name "${SUITE_NAME}" \
  --add-host re0auth.test:host-gateway \
  -p "${SUITE_PORT}:8443" \
  "${SUITE_IMAGE}" >/dev/null

for _ in $(seq 1 60); do
  if curl -fsSk "https://localhost:${SUITE_PORT}/api/runner/available" >/dev/null 2>&1; then break; fi
  sleep 1
done

API="https://localhost:${SUITE_PORT}"
if curl -fsSk "${API}/api/runner/available" > "${WORK}/available.json" 2>/dev/null; then
  pass "milestone 5: the suite REST API answers on :${SUITE_PORT}"
  log "available plans written to ${WORK}/available.json (first 40 lines):"
  head -n 40 "${WORK}/available.json" || true
else
  docker logs "${SUITE_NAME}" | tail -n 40 || true
  fail "the suite API never answered; inspect its log above"
fi

# ---- optional: run a plan, and wait for its verdict -------------------------
# The suite has used `id`/`testId`/`test_id` and `status`/`result` across versions.
# Reading whichever appears keeps this spike working across releases instead of
# pinning knowledge it cannot verify here.
json_field() { # <file> <key>...
  "${PYTHON}" - "$@" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("")
    raise SystemExit
for key in sys.argv[2:]:
    value = data.get(key)
    if value not in (None, ""):
        print(value if isinstance(value, str) else json.dumps(value))
        break
else:
    print("")
PY
}

PLAN_STATUS="not-run"
PLAN_RESULT=""
if [[ -n "${CONFORMANCE_PLAN_JSON:-}" && -f "${CONFORMANCE_PLAN_JSON}" ]]; then
  log "posting CONFORMANCE_PLAN_JSON to /api/runner"
  curl -fsSk -X POST "${API}/api/runner" \
    -H 'Content-Type: application/json' \
    --data-binary "@${CONFORMANCE_PLAN_JSON}" > "${WORK}/run.json"
  RUN_ID="$(json_field "${WORK}/run.json" id testId test_id)"
  if [[ -z "${RUN_ID}" ]]; then
    warn "the suite returned no run id: $(cat "${WORK}/run.json")"
    PLAN_STATUS="not-started"
  else
    pass "milestone 6: plan run ${RUN_ID} created"
    PLAN_STATUS="RUNNING"
    deadline=$(( SECONDS + ${CONFORMANCE_TIMEOUT_SECONDS:-600} ))
    while (( SECONDS < deadline )); do
      curl -fsSk "${API}/api/runner/${RUN_ID}" > "${WORK}/run-status.json" 2>/dev/null || true
      PLAN_STATUS="$(json_field "${WORK}/run-status.json" status)"
      case "${PLAN_STATUS}" in
        FINISHED|INTERRUPTED|STOPPED) break ;;
      esac
      sleep 2
    done
    PLAN_RESULT="$(json_field "${WORK}/run-status.json" result summary)"
    if [[ "${PLAN_STATUS}" == "FINISHED" ]]; then
      case "${PLAN_RESULT}" in
        SUCCESS|WARNING|REVIEW|SKIPPED|"")
          pass "milestone 7: plan finished (result=${PLAN_RESULT:-unknown})" ;;
        *)
          if [[ "${CONFORMANCE_REQUIRE_PLAN:-0}" == "1" ]]; then
            fail "plan finished with result=${PLAN_RESULT}"
          fi
          warn "plan finished with result=${PLAN_RESULT}" ;;
      esac
    else
      if [[ "${CONFORMANCE_REQUIRE_PLAN:-0}" == "1" ]]; then
        fail "plan did not finish within ${CONFORMANCE_TIMEOUT_SECONDS:-600}s (status=${PLAN_STATUS})"
      fi
      warn "plan did not finish within ${CONFORMANCE_TIMEOUT_SECONDS:-600}s (status=${PLAN_STATUS})"
    fi
  fi
else
  warn "no CONFORMANCE_PLAN_JSON supplied; connectivity only (no plan was run)"
fi

# ---- artifacts and the report the nightly routine reads ---------------------
# The catalogue is the authority for a plan payload (test name, variant, config),
# so surface it where the dispatcher will actually look: the run summary.
plan_names() {
  "${PYTHON}" - "${WORK}/available.json" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit
if isinstance(data, dict):
    names = list(data.keys())
elif isinstance(data, list):
    names = [d.get("testName") or d.get("name") or "?" for d in data]
else:
    names = []
for name in names[:40]:
    print(name)
PY
}

if [[ -n "${SPIKE_ARTIFACTS:-}" ]]; then
  mkdir -p "${SPIKE_ARTIFACTS}"
  cp "${WORK}/available.json" "${WORK}/run.json" "${WORK}/run-status.json" "${SPIKE_ARTIFACTS}/" 2>/dev/null || true
  docker logs "${SUITE_NAME}" > "${SPIKE_ARTIFACTS}/suite.log" 2>&1 || true
  docker logs "${CADDY_NAME}" > "${SPIKE_ARTIFACTS}/caddy.log" 2>&1 || true
  {
    echo "## OIDF conformance spike"
    echo
    echo "| result | milestone |"
    echo "|---|---|"
    while IFS= read -r line; do
      printf '| %s | %s |\n' "${line%% *}" "${line#* }"
    done < "${MILESTONES}"
    echo
    printf 'Plan: %s%s\n' "${PLAN_STATUS}" "${PLAN_RESULT:+ (${PLAN_RESULT})}"
    echo
    printf 'Suite: %s | issuer %s | seeded redirect_uri `%s`\n' "${SUITE_IMAGE}" "${ISSUER}" "${REDIRECT_URI}"
    if [[ "${PLAN_STATUS}" == "not-run" ]]; then
      echo
      echo "No plan payload was supplied. This run proved connectivity; pick a plan below,"
      echo "then dispatch again with \`plan_json\` (see scripts/conformance/plans/README.md)."
      echo
      echo "### Available plans (first 40; full list in available.json)"
      echo
      plan_names | sed 's/^/- `/; s/$/`/'
    fi
  } > "${SPIKE_ARTIFACTS}/summary.md"
  cat "${SPIKE_ARTIFACTS}/summary.md" || true
fi

log "spike finished"
