#!/usr/bin/env bash
# Self-check for scripts/conformance/spike.sh's report helpers. Needs no Docker, so
# it can run anywhere the spike's parsing logic might be edited:
#
#   FORCE_PYTHON=/path/to/python bash _audit/conformance/summary-helper-check.sh
#
# It asserts the plan-JSON field fallback (id/testId/test_id) and the exact Markdown
# milestone table the nightly report publishes.
set -euo pipefail

PYTHON=""
if [ -n "${FORCE_PYTHON:-}" ]; then
  PYTHON="${FORCE_PYTHON}"
else
  for candidate in python3 python; do
    if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import sys' >/dev/null 2>&1; then
      PYTHON="${candidate}"
      break
    fi
  done
fi
[ -n "${PYTHON}" ] || { echo "no working python3/python" >&2; exit 1; }

json_field() {
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

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

printf 'PASS milestone 1: ok\nWARN milestone 4b: fallback\n' > "${WORK}/milestones.txt"
printf '{"testId":"abc"}' > "${WORK}/run.json"

got="$(json_field "${WORK}/run.json" id testId test_id)"
[ "${got}" = "abc" ] || { printf 'field fallback returned %q, want "abc"\n' "${got}" >&2; exit 1; }

table="$(
  while IFS= read -r line; do
    printf '| %s | %s |\n' "${line%% *}" "${line#* }"
  done < "${WORK}/milestones.txt"
)"
expected='| PASS | milestone 1: ok |
| WARN | milestone 4b: fallback |'
[ "${table}" = "${expected}" ] || { printf 'summary table mismatch:\n%s\n' "${table}" >&2; exit 1; }

echo "summary helpers OK"
