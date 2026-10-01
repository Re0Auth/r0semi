#!/usr/bin/env bash
# Self-check for scripts/conformance/dispatch.sh — dry-run only, no token, no
# network. It pins the argument parsing and the REST payload the script would send,
# because dispatch.sh's whole job is that payload.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

SCRIPT=scripts/conformance/dispatch.sh

"${SCRIPT}" --help >/dev/null || { echo "FAIL: --help exited non-zero"; exit 1; }

run_dry() { bash "${SCRIPT}" --dry-run "$@"; }
body_of() { grep -o 'body {.*' <<<"$1" | head -n 1; }

# 1. Defaults: the ready-made plan, the whole plan's modules, the conformance workflow.
out="$(run_dry)"
grep -q 'POST https://api.github.com/repos/Re0Auth/r0semi/actions/workflows/conformance.yml/dispatches' <<<"${out}" \
  || { echo "FAIL: wrong dispatch endpoint"; echo "${out}"; exit 1; }
body="$(body_of "${out}")"
grep -q '"plan_json": "scripts/conformance/plans/oidcc-basic.json"' <<<"${body}" \
  || { echo "FAIL: default plan_json missing from ${body}"; exit 1; }
grep -q '"max_modules": "0"' <<<"${body}" \
  || { echo "FAIL: default max_modules missing from ${body}"; exit 1; }
grep -q '"ref": "main"' <<<"${body}" || { echo "FAIL: ref missing from ${body}"; exit 1; }
if grep -q 'require_plan' <<<"${body}"; then
  echo "FAIL: require_plan was sent although it was not asked for: ${body}"; exit 1
fi

# 2. Flags override, and the boolean input is sent as the string "true" (the REST API
#    takes every workflow_dispatch input as a string).
out="$(run_dry --max-modules 5 --redirect-uri 'https://suite.example/cb' --require-plan --ref test-branch)"
body="$(body_of "${out}")"
grep -q '"max_modules": "5"' <<<"${body}" || { echo "FAIL: --max-modules ignored: ${body}"; exit 1; }
grep -q '"redirect_uri": "https://suite.example/cb"' <<<"${body}" \
  || { echo "FAIL: --redirect-uri ignored: ${body}"; exit 1; }
grep -q '"require_plan": "true"' <<<"${body}" || { echo "FAIL: --require-plan ignored: ${body}"; exit 1; }
grep -q '"ref": "test-branch"' <<<"${body}" || { echo "FAIL: --ref ignored: ${body}"; exit 1; }

# 3. Positional key=value form.
out="$(bash "${SCRIPT}" plan_json=scripts/conformance/plans/oidcc-basic.json max_modules=3 --dry-run)"
body="$(body_of "${out}")"
grep -q '"max_modules": "3"' <<<"${body}" || { echo "FAIL: positional max_modules ignored: ${body}"; exit 1; }

# 4. An unknown argument is a refusal, not a silently ignored flag.
if bash "${SCRIPT}" --dry-run --nonsense >/dev/null 2>&1; then
  echo "FAIL: an unknown argument was accepted"; exit 1
fi

# 5. Dry-run must never need a credential.
out="$(env -u GH_TOKEN -u GITHUB_TOKEN bash "${SCRIPT}" --dry-run)"
grep -q 'dry run' <<<"${out}" || { echo "FAIL: dry run without a token failed"; echo "${out}"; exit 1; }

echo "dispatch.sh self-check OK"
