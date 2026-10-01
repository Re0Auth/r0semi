#!/usr/bin/env bash
# Dispatch the conformance workflow, wait for it, fetch its artifact and print the
# verdict — one command instead of push -> web dispatch -> download -> read.
#
#   scripts/conformance/dispatch.sh                     # full Basic OP plan
#   scripts/conformance/dispatch.sh --max-modules 5     # fast smoke run
#   scripts/conformance/dispatch.sh --dry-run           # print, call nothing
#   scripts/conformance/dispatch.sh plan_json=... max_modules=0
#
# It uses the REST API directly, so it needs no `gh`. Credentials, in order:
#   1. GH_TOKEN / GITHUB_TOKEN in the environment;
#   2. `gh auth token`, when the gh CLI is installed and logged in.
# The token needs `workflow` (classic PAT) or "Actions: read and write"
# (fine-grained). Artifact download needs it too, even for a public repository.
#
# Exit codes:
#   0  the run finished and the plan passed (or no plan was requested);
#   2  the run finished but the plan did not pass;
#   1  an operational failure (no token, dispatch refused, timeout, download).
set -euo pipefail

REPO="${CONFORMANCE_REPO:-Re0Auth/r0semi}"
WORKFLOW="${CONFORMANCE_WORKFLOW:-conformance.yml}"
REF="${CONFORMANCE_REF:-main}"
PLAN_JSON="${CONFORMANCE_PLAN_JSON:-scripts/conformance/plans/oidcc-basic.json}"
MAX_MODULES="${CONFORMANCE_PLAN_MAX_MODULES:-0}"
REDIRECT_URI="${CONFORMANCE_REDIRECT_URI:-}"
REQUIRE_PLAN="${CONFORMANCE_REQUIRE_PLAN:-0}"
ARTIFACT="${CONFORMANCE_ARTIFACT:-conformance-spike}"
OUT_DIR="conformance-runs/$(date -u +%Y%m%dT%H%M%SZ)"
INTERVAL="${CONFORMANCE_POLL_SECONDS:-15}"
TIMEOUT="${CONFORMANCE_WAIT_SECONDS:-3600}"
DRY_RUN=0
REQUIRE_PASS=0
NO_DOWNLOAD=0
SELF_TEST=0

log()  { printf 'dispatch: %s\n' "$*"; }
warn() { printf 'dispatch: WARN — %s\n' "$*" >&2; }
fail() { printf 'dispatch: FAIL — %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# ---- arguments --------------------------------------------------------------
while (( $# )); do
  case "$1" in
    --repo)          REPO="$2"; shift 2 ;;
    --workflow)      WORKFLOW="$2"; shift 2 ;;
    --ref)           REF="$2"; shift 2 ;;
    --plan-json)     PLAN_JSON="$2"; shift 2 ;;
    --max-modules)   MAX_MODULES="$2"; shift 2 ;;
    --redirect-uri)  REDIRECT_URI="$2"; shift 2 ;;
    --require-plan)  REQUIRE_PLAN=1; shift ;;
    --out)           OUT_DIR="$2"; shift 2 ;;
    --artifact)      ARTIFACT="$2"; shift 2 ;;
    --interval)      INTERVAL="$2"; shift 2 ;;
    --timeout)       TIMEOUT="$2"; shift 2 ;;
    --dry-run)       DRY_RUN=1; shift ;;
    --self-test)     SELF_TEST=1; shift ;;
    --require-pass)  REQUIRE_PASS=1; shift ;;
    --no-download)   NO_DOWNLOAD=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    plan_json=*)     PLAN_JSON="${1#plan_json=}"; shift ;;
    max_modules=*)   MAX_MODULES="${1#max_modules=}"; shift ;;
    redirect_uri=*)  REDIRECT_URI="${1#redirect_uri=}"; shift ;;
    require_plan=*)  REQUIRE_PLAN="${1#require_plan=}"; shift ;;
    *)               fail "unknown argument '$1' (see --help)" ;;
  esac
done

command -v curl >/dev/null || fail "curl is required"
PYTHON=""
for candidate in python3 python; do
  if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import sys' >/dev/null 2>&1; then
    PYTHON="${candidate}"
    break
  fi
done
[[ -n "${PYTHON}" ]] || fail "a working python3 (or python) is required"
# This machine's Python defaults its text I/O to the locale codec (GBK on a Chinese
# Windows install) while every API response here is UTF-8: `json.load(sys.stdin)`
# died with "Expecting ',' delimiter" after GBK mangled a non-ASCII commit author.
# Force UTF-8 for every child instead of depending on the locale.
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

# The dispatch body: every input is a string in the REST API.
INPUTS="$("$PYTHON" -c '
import json, sys
plan, maxmods, redirect, require = sys.argv[1:5]
inputs = {"plan_json": plan, "max_modules": maxmods}
if redirect:
    inputs["redirect_uri"] = redirect
if require not in ("", "0"):
    inputs["require_plan"] = "true"
print(json.dumps({"ref": sys.argv[5], "inputs": inputs}))
' "${PLAN_JSON}" "${MAX_MODULES}" "${REDIRECT_URI}" "${REQUIRE_PLAN}" "${REF}")"

if (( SELF_TEST )); then
  # The run lookup used to split its fields on spaces, so an empty conclusion
  # (a run still in progress) shifted every later column and the run URL came out
  # empty. Pipe-delimited fields keep their positions; this pins that.
  picked="12345|in_progress||https://github.com/o/r/actions/runs/12345"
  IFS='|' read -r rid rstatus rconclusion rurl <<<"${picked}"
  if [[ "${rid}" != "12345" || "${rstatus}" != "in_progress" || -n "${rconclusion}" \
        || "${rurl}" != "https://github.com/o/r/actions/runs/12345" ]]; then
    fail "self-test: run-pick parse failed for '${picked}'"
  fi
  log "self-test OK"
  exit 0
fi

if (( DRY_RUN )); then
  log "dry run — the workflow was NOT dispatched"
  log "  repo       ${REPO}"
  log "  workflow   ${WORKFLOW}"
  log "  ref        ${REF}"
  log "  plan_json  ${PLAN_JSON:-<empty>}"
  log "  max_modules ${MAX_MODULES}"
  log "  redirect_uri ${REDIRECT_URI:-<script default>}"
  log "  require_plan ${REQUIRE_PLAN}"
  log "  artifact   ${ARTIFACT}"
  log "  out        ${OUT_DIR}"
  log "  POST https://api.github.com/repos/${REPO}/actions/workflows/${WORKFLOW}/dispatches"
  log "  body ${INPUTS}"
  exit 0
fi

# ---- credentials ------------------------------------------------------------
# gh may be installed but absent from this shell's PATH (a Git Bash opened before
# the installer ran, or a non-interactive shell), so the Windows default location is
# tried too rather than falling through to "no credential".
GH_BIN="$(command -v gh 2>/dev/null || true)"
if [[ -z "${GH_BIN}" && -x "/c/Program Files/GitHub CLI/gh.exe" ]]; then
  GH_BIN="/c/Program Files/GitHub CLI/gh.exe"
fi

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -z "${TOKEN}" && -n "${GH_BIN}" ]]; then
  TOKEN="$("${GH_BIN}" auth token 2>/dev/null || true)"
fi
[[ -n "${TOKEN}" ]] || fail "no credential: set GH_TOKEN (needs the 'workflow' scope) or install and log in to the gh CLI"

API="https://api.github.com"
api() { # <method> <path> [json-body]
  local method="$1" path="$2" data="${3:-}"
  if [[ -n "${data}" ]]; then
    curl -fsS -X "${method}" \
      -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" \
      --data "${data}" "${API}${path}"
  else
    curl -fsS -X "${method}" \
      -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" \
      "${API}${path}"
  fi
}

# ---- dispatch ---------------------------------------------------------------
log "dispatching ${WORKFLOW} on ${REF} (plan_json=${PLAN_JSON:-<empty>}, max_modules=${MAX_MODULES})"
DISPATCH_AT="$(date -u +%s)"
api POST "/repos/${REPO}/actions/workflows/${WORKFLOW}/dispatches" "${INPUTS}" >/dev/null \
  || fail "the dispatch was refused: check the token's 'workflow' scope and that ${WORKFLOW} has workflow_dispatch"

# ---- find the run -----------------------------------------------------------
# The cron also triggers this workflow, so the run is matched by event, branch and
# creation time rather than assumed to be the newest.
RUN_ID=""
RUN_URL=""
for _ in $(seq 1 24); do
  RUNS="$(api GET "/repos/${REPO}/actions/workflows/${WORKFLOW}/runs?event=workflow_dispatch&branch=${REF}&per_page=10" || true)"
  if [[ -n "${RUNS}" ]]; then
    picked="$("$PYTHON" -c '
import datetime, json, sys
cut = float(sys.argv[1])
best = None
for run in json.load(sys.stdin).get("workflow_runs", []):
    stamp = run.get("created_at") or ""
    try:
        when = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except ValueError:
        continue
    if when >= cut and (best is None or when > best[0]):
        best = (when, run["id"], run.get("status") or "", run.get("conclusion") or "", run["html_url"])
print("%s|%s|%s|%s" % best[1:] if best else "")
' "$(( DISPATCH_AT - 15 ))" <<<"${RUNS}")"
    if [[ -n "${picked}" ]]; then
      # Pipe-delimited: an empty conclusion (a run still in progress) would shift
      # every later column if the fields were whitespace-separated.
      IFS='|' read -r RUN_ID RUN_STATUS _ RUN_URL <<<"${picked}"
      break
    fi
  fi
  sleep 5
done
[[ -n "${RUN_ID}" ]] || fail "the dispatched run never appeared (token may lack Actions: read)"

RUN_URL="${RUN_URL:-https://github.com/${REPO}/actions/runs/${RUN_ID}}"
log "run ${RUN_ID}: ${RUN_URL}"
STARTED="$(date -u +%s)"

# ---- wait -------------------------------------------------------------------
while :; do
  RUN_JSON="$(api GET "/repos/${REPO}/actions/runs/${RUN_ID}" || true)"
  if [[ -z "${RUN_JSON}" ]]; then
    log "poll failed (network or API); retrying in ${INTERVAL}s"
    sleep "${INTERVAL}"
    continue
  fi
  read -r run_status run_conclusion <<<"$("$PYTHON" -c '
import json, sys
run = json.load(sys.stdin)
print(run.get("status", ""), run.get("conclusion") or "-")
' <<<"${RUN_JSON}")"
  elapsed=$(( $(date -u +%s) - STARTED ))
  log "[$(printf '%4d' "${elapsed}")s] status=${run_status} conclusion=${run_conclusion}"
  if [[ "${run_status}" == "completed" ]]; then break; fi
  if (( elapsed > TIMEOUT )); then
    fail "the run did not finish within ${TIMEOUT}s — still ${run_status}: ${RUN_URL}"
  fi
  sleep "${INTERVAL}"
done

if [[ "${run_conclusion}" != "success" ]]; then
  warn "the workflow finished with conclusion=${run_conclusion} (the spike step is report-only, so a red plan does not fail the job)"
  warn "job log: ${RUN_URL}"
fi

# ---- artifact ---------------------------------------------------------------
(( NO_DOWNLOAD )) && { log "--no-download set; stopping after the verdict"; exit 0; }

ARTIFACT_ID="$(api GET "/repos/${REPO}/actions/runs/${RUN_ID}/artifacts" | "$PYTHON" -c '
import json, sys
want = sys.argv[1]
for art in json.load(sys.stdin).get("artifacts", []):
    if art.get("name") == want:
        print(art["id"])
        break
' "${ARTIFACT}")"
if [[ -z "${ARTIFACT_ID}" ]]; then
  warn "no '${ARTIFACT}' artifact on this run (the job may have died before uploading)"
  warn "summary without an artifact: ${RUN_URL}"
  exit 1
fi

mkdir -p "${OUT_DIR}"
ZIP="$(mktemp)"
log "downloading artifact ${ARTIFACT} (id ${ARTIFACT_ID}) into ${OUT_DIR}"
curl -fsSL -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" \
  -o "${ZIP}" "${API}/repos/${REPO}/actions/artifacts/${ARTIFACT_ID}/zip" \
  || fail "the artifact download failed (the token needs Actions: read)"
"$PYTHON" -c '
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2])
' "${ZIP}" "${OUT_DIR}"
rm -f "${ZIP}"

# upload-artifact stores the directory's contents at the archive root; tolerate the
# other layout too, so this works if that ever changes.
if [[ ! -f "${OUT_DIR}/summary.md" && -f "${OUT_DIR}/conformance-artifacts/summary.md" ]]; then
  OUT_DIR="${OUT_DIR}/conformance-artifacts"
fi

# ---- verdict ----------------------------------------------------------------
echo
if [[ -f "${OUT_DIR}/summary.md" ]]; then
  cat "${OUT_DIR}/summary.md"
else
  warn "no summary.md in the artifact"
fi

PLAN_RESULT="not-run"
if [[ -f "${OUT_DIR}/plan-run.json" ]]; then
  echo
  "$PYTHON" - "${OUT_DIR}/plan-run.json" <<'PY'
import json, sys
from collections import Counter
data = json.load(open(sys.argv[1], encoding="utf-8"))
modules = data.get("modules") or []
print("Plan: %s (%s)" % (data.get("status"), data.get("result")))
print("Modules: " + ", ".join("%s=%d" % (r, n) for r, n in sorted(
    Counter(m.get("result") or "no-verdict" for m in modules).items())))
for module in modules:
    if module.get("result") in ("PASSED", "SKIPPED"):
        continue
    why = (module.get("messages") or [""])[0] if module.get("messages") else ""
    tag = module.get("interactive") or module.get("divergence") or ""
    print("  %-12s %-11s %-9s %s %s" % (module.get("status"), module.get("result"),
                                        tag, module.get("testModule"), why[:110]))
PY
  PLAN_RESULT="$("$PYTHON" -c '
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("result") or "not-run")
' "${OUT_DIR}/plan-run.json")"
fi

echo
log "artifacts: ${OUT_DIR}"
log "plan verdict: ${PLAN_RESULT}"

if [[ "${PLAN_RESULT}" == "PASSED" ]]; then exit 0; fi
if [[ "${PLAN_RESULT}" == "not-run" && (( ! REQUIRE_PASS )) ]]; then exit 0; fi
exit 2
