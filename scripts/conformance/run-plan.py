#!/usr/bin/env python3
"""Run one OpenID conformance test plan through the suite's REST API.

The suite's own `scripts/run-test-plan.py` is a large CI harness; this is the small
version the connectivity spike needs, written from the suite's OpenAPI document and
source. It mirrors the parts that matter for an OP test:

    POST /api/plan?planName=<plan>&variant=<json>    body: the test configuration
    POST /api/runner?test=<module>&plan=<planId>     no body; `variant` only when
                                                     the plan left one to choose
    GET  /api/runner/<testId>/wait-state?states=...  long-poll the module state
    GET  /api/runner/browser/<testId>                front-channel URLs to visit
    POST /api/runner/browser/<testId>/visit?url=...  report one as visited
    GET  /api/info/<testId>                          final status + result
    GET  /api/log/<testId>                           why a module failed

Modules run **one at a time**: creating a whole plan's worth at once interrupts the
suite's own configuration (observed on the first real run: 30 of 35 modules ended
INTERRUPTED with no result).

Payload shape (our own wrapper, not the suite's):

    {
      "planName": "oidcc-basic-certification-test-plan",
      "variant": {"client_registration": "static_client"},   # optional
      "config":  {"alias": "...", "server": {...}, "client": {...}}
    }

Prints one JSON object on stdout:

    {"status": "FINISHED"|"FAILED", "result": "SUCCESS"|..., "planId": "...",
     "modules": [{"testModule": ..., "testId": ..., "status": ..., "result": ...,
                  "messages": [...]}]}

Exit code 0 when every module result is SUCCESS/WARNING/REVIEW/SKIPPED, 2 otherwise.
"""

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TERMINAL_OK = {"SUCCESS", "WARNING", "REVIEW", "SKIPPED"}
TERMINAL_STATUSES = {"FINISHED", "INTERRUPTED", "STOPPED"}
LOG_INTERESTING = {"FAILURE", "ERROR", "WARNING"}


def context(insecure):
    return ssl._create_unverified_context() if insecure else None


def request(api, method, path, body=None, query=None, insecure=False):
    url = api.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif method == "POST":
        # A plan-sourced test must NOT carry a body: createTest rejects any
        # configuration when `plan` is present. Content-Type is still declared so
        # the controller's consumes=application/json matches.
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60, context=context(insecure)) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", "replace")
        raise RuntimeError("%s %s -> HTTP %s: %s" % (method, url, err.code, raw[:600])) from None
    except urllib.error.URLError as err:
        raise RuntimeError("cannot reach %s: %s" % (url, err.reason)) from None
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        raise RuntimeError("%s %s -> non-JSON response: %s" % (method, url, raw[:300])) from None


def fetch_front_channel(url, insecure):
    """Drive one front-channel URL the way a browser would: follow every redirect."""
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(),
        urllib.request.HTTPSHandler(context=context(insecure)),
    )
    req = urllib.request.Request(url, headers={"User-Agent": "r0semi-conformance-spike"})
    with opener.open(req, timeout=60) as resp:
        return resp.status, resp.geturl()


def module_list(plan_response):
    """The plan response has carried `modules` (and `testModules`) across versions."""
    for key in ("modules", "testModules", "tests"):
        value = plan_response.get(key)
        if isinstance(value, list):
            return value
    return []


def module_name(entry):
    if isinstance(entry, str):
        return entry
    for key in ("testModule", "testName", "module", "name"):
        value = entry.get(key)
        if value:
            return value
    return None


def wait_state(api, test_id, insecure, states, timeout_ms=15000):
    response = request(api, "GET", "/api/runner/%s/wait-state" % urllib.parse.quote(test_id),
                       query={"states": ",".join(states), "timeoutMs": str(timeout_ms)},
                       insecure=insecure)
    return response.get("state") or ""


def visit_front_channel(api, test_id, insecure):
    """Visit every URL the module is waiting on and report each as visited."""
    try:
        browser = request(api, "GET", "/api/runner/browser/" + urllib.parse.quote(test_id),
                          insecure=insecure)
    except RuntimeError:
        return 0
    urls = browser.get("urls") or []
    visited = 0
    for entry in urls:
        url = entry.get("url") if isinstance(entry, dict) else entry
        if not url or not isinstance(url, str):
            continue
        try:
            fetch_front_channel(url, insecure)
        except Exception as err:  # noqa: BLE001 - the suite must still be told we tried
            print("visit %s failed: %s" % (url, err), file=sys.stderr)
        try:
            request(api, "POST", "/api/runner/browser/%s/visit" % urllib.parse.quote(test_id),
                    query={"url": url}, insecure=insecure)
            visited += 1
        except RuntimeError as err:
            print("could not report visit: %s" % err, file=sys.stderr)
    return visited


def module_messages(api, test_id, insecure, limit=4):
    """The suite's log lines that explain a non-success: FAILURE/ERROR/WARNING."""
    try:
        entries = request(api, "GET", "/api/log/" + urllib.parse.quote(test_id), insecure=insecure)
    except RuntimeError:
        return []
    if not isinstance(entries, list):
        return []
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("result") not in LOG_INTERESTING:
            continue
        text = entry.get("msg") or entry.get("description") or entry.get("src") or ""
        if text:
            out.append(str(text)[:300])
        if len(out) >= limit:
            break
    return out


def run_module(api, plan_id, entry, insecure, deadline, module_timeout):
    name = module_name(entry)
    if not name:
        return None
    query = {"test": name, "plan": plan_id}
    variant = entry.get("variant") if isinstance(entry, dict) else None
    if variant:
        query["variant"] = json.dumps(variant)
    created = request(api, "POST", "/api/runner", query=query, insecure=insecure)
    test_id = created.get("id") or created.get("testId")
    if not test_id:
        return {"testModule": name, "status": "INTERRUPTED", "result": None,
                "messages": ["test creation returned no id: %s" % created]}

    module_deadline = min(deadline, time.time() + module_timeout)
    status = ""
    while time.time() < module_deadline:
        status = wait_state(api, test_id, insecure,
                            ["CONFIGURED", "WAITING", "FINISHED", "INTERRUPTED", "STOPPED"])
        if status in TERMINAL_STATUSES:
            break
        if status == "WAITING":
            if visit_front_channel(api, test_id, insecure) == 0:
                time.sleep(2)
            continue
        # CONFIGURED (or an empty long-poll timeout): wait again.
    info = request(api, "GET", "/api/info/" + urllib.parse.quote(test_id), insecure=insecure)
    status = info.get("status") or status
    result = info.get("result")
    module = {"testModule": name, "testId": test_id, "status": status, "result": result}
    if result not in TERMINAL_OK:
        module["messages"] = module_messages(api, test_id, insecure)
    return module


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True, help="suite base URL, e.g. https://oidf-suite:8443")
    ap.add_argument("--payload", required=True, help="plan payload JSON file")
    ap.add_argument("--timeout", type=int, default=1800, help="seconds for the whole plan")
    ap.add_argument("--module-timeout", type=int, default=180, help="seconds per module")
    ap.add_argument("--max-modules", type=int, default=0, help="0 = every module in the plan")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed front)")
    args = ap.parse_args()

    with open(args.payload, encoding="utf-8") as fh:
        payload = json.load(fh)
    if not payload.get("planName"):
        print(json.dumps({"status": "FAILED", "result": "payload has no planName"}))
        return 2

    query = {"planName": payload["planName"]}
    if payload.get("variant"):
        query["variant"] = json.dumps(payload["variant"])
    plan = request(args.api, "POST", "/api/plan", body=payload.get("config", {}),
                   query=query, insecure=args.insecure)
    plan_id = plan.get("id") or plan.get("planId")
    if not plan_id:
        print(json.dumps({"status": "FAILED", "result": "plan creation returned no id: %s" % plan}))
        return 2

    modules = module_list(plan)
    if args.max_modules > 0:
        modules = modules[:args.max_modules]
    if not modules:
        print(json.dumps({"status": "FAILED", "result": "the plan listed no modules: %s" % plan}))
        return 2

    deadline = time.time() + args.timeout
    results = []
    for entry in modules:
        if time.time() >= deadline:
            results.append({"testModule": module_name(entry), "status": "INTERRUPTED",
                            "result": None, "messages": ["plan deadline reached before this module"]})
            continue
        try:
            result = run_module(args.api, plan_id, entry, args.insecure, deadline, args.module_timeout)
        except RuntimeError as err:
            result = {"testModule": module_name(entry), "status": "INTERRUPTED", "result": None,
                      "messages": [str(err)]}
        if result:
            results.append(result)

    ok = all(module.get("result") in TERMINAL_OK for module in results)
    if ok:
        overall = "SUCCESS"
    else:
        # Name the reason: the first non-success result, or FAILED when a module
        # never produced one (INTERRUPTED with no verdict).
        overall = next((module.get("result") for module in results
                        if module.get("result") and module.get("result") not in TERMINAL_OK),
                       "FAILED")
    print(json.dumps({
        "status": "FINISHED",
        "result": overall,
        "planId": plan_id,
        "modules": results,
    }))
    return 0 if ok else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:  # noqa: BLE001 - the spike wants the reason, not a trace
        print(json.dumps({"status": "FAILED", "result": str(err)}))
        sys.exit(2)
