#!/usr/bin/env bash
# Local verification of the conformance spike's OP config (no Docker). It mirrors
# the "material" and milestone-1 blocks of scripts/conformance/spike.sh — keep the
# two in step when either changes; the point is to catch a config the OP refuses
# before spending a CI round trip on it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

WORK="$(mktemp -d)"
trap 'kill "${OP_PID:-}" 2>/dev/null || true; rm -rf "${WORK}"' EXIT

head -c 32 /dev/urandom | base64 -w0 > "${WORK}/kek"
head -c 32 /dev/urandom | base64 -w0 > "${WORK}/token-key"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -outform DER 2>/dev/null \
  | base64 -w0 > "${WORK}/signing-key"

export RE0AUTH_KEK="$(cat "${WORK}/kek")"
export RE0AUTH_OIDC_TOKEN_KEY="$(cat "${WORK}/token-key")"
export RE0AUTH_OIDC_SIGNING_KEY="$(cat "${WORK}/signing-key")"
export RE0AUTH_ISSUER="https://re0auth.test:8443"
export RE0AUTH_COOKIE_SECURE=true
export RE0AUTH_CLIENT_SECRET="spike-secret"
REDIRECT_URI="https://localhost:9443/test/a/conformance/callback"

cat > "${WORK}/re0auth.toml" <<TOMLEOF
[server]
issuer = "${RE0AUTH_ISSUER}"
addr   = "0.0.0.0:8080"
cookie_secure = true

[client]
id = "conformance"
secret_env = "RE0AUTH_CLIENT_SECRET"
redirect_uris = ["${REDIRECT_URI}"]
TOMLEOF

go build -o "${WORK}/re0auth.exe" ./cmd/re0auth
"${WORK}/re0auth.exe" -config "${WORK}/re0auth.toml" > "${WORK}/op.log" 2>&1 &
OP_PID=$!

ok=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:8080/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 0.5
done
if [ "${ok}" -eq 1 ]; then
  echo "MILESTONE1_PASS"
  curl -fsS "http://127.0.0.1:8080/.well-known/openid-configuration" | head -c 200; echo
else
  echo "MILESTONE1_FAIL"
  tail -n 30 "${WORK}/op.log"
  exit 1
fi
