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

plan_names() {
  "${PYTHON}" - "$1" <<'PY'
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

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

printf 'PASS milestone 1: ok\nWARN milestone 4b: fallback\n' > "${WORK}/milestones.txt"
printf '{"testId":"abc"}' > "${WORK}/run.json"

got="$(json_field "${WORK}/run.json" id testId test_id)"
[ "${got}" = "abc" ] || { printf 'field fallback returned %q, want "abc"\n' "${got}" >&2; exit 1; }

# The catalogue has been an object of plan-name -> metadata, and a list of objects.
printf '{"oidcc-basic-certification-test-plan":{},"fapi2-security-profile":{}}' > "${WORK}/avail-dict.json"
printf '[{"testName":"oidcc-basic-certification-test-plan"},{"name":"oidcc-server"}]' > "${WORK}/avail-list.json"
dict_names="$(plan_names "${WORK}/avail-dict.json" | tr -d '\r' | tr '\n' ',')"
[ "${dict_names}" = "oidcc-basic-certification-test-plan,fapi2-security-profile," ] || {
  printf 'dict catalogue names = %q\n' "${dict_names}" >&2; exit 1; }
list_names="$(plan_names "${WORK}/avail-list.json" | tr -d '\r' | tr '\n' ',')"
[ "${list_names}" = "oidcc-basic-certification-test-plan,oidcc-server," ] || {
  printf 'list catalogue names = %q\n' "${list_names}" >&2; exit 1; }

table="$(
  while IFS= read -r line; do
    printf '| %s | %s |\n' "${line%% *}" "${line#* }"
  done < "${WORK}/milestones.txt"
)"
expected='| PASS | milestone 1: ok |
| WARN | milestone 4b: fallback |'
[ "${table}" = "${expected}" ] || { printf 'summary table mismatch:\n%s\n' "${table}" >&2; exit 1; }

# The plan-module table the run summary renders from plan-run.json.
printf '{"modules":[{"testModule":"m-one","status":"FINISHED","result":"SUCCESS"},{"testModule":"m-two","status":"INTERRUPTED","result":"FAILURE"}]}' > "${WORK}/plan-run.json"
modules="$(
  "${PYTHON}" - "${WORK}/plan-run.json" <<'PY' | tr -d '\r'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit
for module in data.get("modules") or []:
    print("| %s | %s | %s |" % (module.get("testModule", "?"),
                                module.get("status", "?"),
                                module.get("result", "?")))
PY
)"
expected_modules='| m-one | FINISHED | SUCCESS |
| m-two | INTERRUPTED | FAILURE |'
[ "${modules}" = "${expected_modules}" ] || { printf 'module table mismatch:\n%s\n' "${modules}" >&2; exit 1; }

echo "summary helpers OK"
