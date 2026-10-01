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


def visit_front_channel(api, test_id, insecure, seen):
    """Visit the URLs the module is waiting on; report each as visited.

    Returns (outcomes, new_count, urls): outcomes are human-readable lines for the
    report, new_count counts URLs not seen before, and urls is the full list so the
    caller can remember it.
    """
    try:
        browser = request(api, "GET", "/api/runner/browser/" + urllib.parse.quote(test_id),
                          insecure=insecure)
    except RuntimeError as err:
        return ["browser status unavailable: %s" % err], 0, []
    raw_urls = browser.get("urls") or []
    urls = [entry.get("url") if isinstance(entry, dict) else entry for entry in raw_urls]
    urls = [url for url in urls if url and isinstance(url, str)]
    outcomes = []
    new = 0
    for url in urls:
        if url not in seen:
            new += 1
        try:
            status, final = fetch_front_channel(url, insecure)
            outcomes.append("visited %s -> %s %s" % (url, status, final))
        except Exception as err:  # noqa: BLE001 - the suite must still be told we tried
            outcomes.append("visit %s failed: %s" % (url, err))
        try:
            request(api, "POST", "/api/runner/browser/%s/visit" % urllib.parse.quote(test_id),
                    query={"url": url}, insecure=insecure)
        except RuntimeError as err:
            outcomes.append("could not report visit of %s: %s" % (url, err))
    if not urls:
        outcomes.append("the suite offered no front-channel URL")
    return outcomes, new, urls


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


def run_module(api, plan_id, entry, insecure, deadline, module_timeout, visit_rounds):
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
    visits = []
    seen = set()
    stuck = 0
    stuck_exit = False
    while time.time() < module_deadline:
        status = wait_state(api, test_id, insecure,
                            ["CONFIGURED", "WAITING", "FINISHED", "INTERRUPTED", "STOPPED"])
        if status in TERMINAL_STATUSES:
            break
        if status == "WAITING":
            outcomes, new, urls = visit_front_channel(api, test_id, insecure, seen)
            seen.update(urls)
            visits.extend(outcomes)
            # A round that offers nothing new means the module is not moving; stop
            # burning the per-module budget and say so, instead of waiting it out.
            stuck = 0 if new else stuck + 1
            if stuck >= visit_rounds:
                stuck_exit = True
                break
            continue
        # CONFIGURED (or an empty long-poll timeout): wait again.
    info = request(api, "GET", "/api/info/" + urllib.parse.quote(test_id), insecure=insecure)
    result = info.get("result")
    # The suite keeps a module at WAITING when the front channel never completed it,
    # which is exactly the case worth reporting as interrupted.
    status = "INTERRUPTED" if stuck_exit else (info.get("status") or status)
    module = {"testModule": name, "testId": test_id, "status": status, "result": result}
    if visits:
        module["visits"] = visits[-8:]
    if result not in TERMINAL_OK:
        messages = module_messages(api, test_id, insecure)
        if stuck_exit:
            messages.insert(0, "stayed WAITING after %d front-channel rounds with nothing new"
                            % visit_rounds)
        # A request the suite deliberately sends without PKCE meets a policy this
        # repository chose: mandatory PKCE S256 for every client
        # (docs/api-design.md §207). Name it, so it is not read as an OP bug.
        if any("error=invalid_request" in v and "code_challenge" in v for v in visits):
            module["divergence"] = "pkce-required"
            messages.insert(0, "POLICY DIVERGENCE: the suite sent no code_challenge while "
                               "Re0Auth mandates PKCE S256 for every client (docs/api-design.md §207)")
        module["messages"] = messages + [v for v in visits[-4:] if v not in messages]
    return module


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True, help="suite base URL, e.g. https://oidf-suite:8443")
    ap.add_argument("--payload", required=True, help="plan payload JSON file")
    ap.add_argument("--timeout", type=int, default=1800, help="seconds for the whole plan")
    ap.add_argument("--module-timeout", type=int, default=180, help="seconds per module")
    ap.add_argument("--visit-rounds", type=int, default=3,
                    help="stop a module after this many front-channel rounds that offer nothing new")
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
            result = run_module(args.api, plan_id, entry, args.insecure, deadline,
                                args.module_timeout, args.visit_rounds)
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
