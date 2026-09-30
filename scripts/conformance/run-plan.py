#!/usr/bin/env python3
"""Run one OpenID conformance test plan through the suite's REST API.

The suite's own `scripts/run-test-plan.py` is a large CI harness; this is the small
version the connectivity spike needs, written from the suite's OpenAPI document and
source:

    POST /api/plan?planName=<plan>&variant=<json>   body: the test configuration
    POST /api/runner?test=<module>&plan=<planId>    no body when the test comes
                                                    from a plan
    GET  /api/info/<testId>                         status + result

Payload shape (our own wrapper, not the suite's):

    {
      "planName": "oidcc-basic-certification-test-plan",
      "variant": {"response_type": "code", ...},   # optional
      "config":  {"alias": "...", "server": {...}, "client": {...}}
    }

Prints one JSON object on stdout:

    {"status": "FINISHED"|"FAILED", "result": "SUCCESS"|..., "planId": "...",
     "modules": [{"testModule": ..., "testId": ..., "status": ..., "result": ...}]}

Exit code 0 when every module result is SUCCESS/WARNING/REVIEW/SKIPPED (or the
module never ran because the plan run itself failed), 2 otherwise.
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
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True, help="suite base URL, e.g. https://oidf-suite:8443")
    ap.add_argument("--payload", required=True, help="plan payload JSON file")
    ap.add_argument("--timeout", type=int, default=900, help="seconds to wait for all modules")
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

    created = []
    for entry in module_list(plan):
        name = module_name(entry)
        if not name:
            continue
        response = request(args.api, "POST", "/api/runner", query={"test": name, "plan": plan_id},
                           insecure=args.insecure)
        test_id = response.get("id") or response.get("testId")
        if not test_id:
            print(json.dumps({"status": "FAILED",
                              "result": "test creation for %s returned no id: %s" % (name, response)}))
            return 2
        created.append({"testModule": name, "testId": test_id})

    if not created:
        print(json.dumps({"status": "FAILED", "result": "the plan listed no modules: %s" % plan}))
        return 2

    deadline = time.time() + args.timeout
    done = {}
    while time.time() < deadline and len(done) < len(created):
        for module in created:
            if module["testId"] in done:
                continue
            info = request(args.api, "GET", "/api/info/" + urllib.parse.quote(module["testId"]),
                           insecure=args.insecure)
            module["status"] = info.get("status")
            module["result"] = info.get("result")
            if module["status"] in TERMINAL_STATUSES:
                done[module["testId"]] = True
        if len(done) < len(created):
            time.sleep(3)

    ok = True
    for module in created:
        if module.get("result") not in TERMINAL_OK:
            ok = False
    overall = "SUCCESS" if ok else (created[0].get("result") or "FAILED")
    print(json.dumps({
        "status": "FINISHED",
        "result": overall,
        "planId": plan_id,
        "modules": created,
    }))
    return 0 if ok else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:  # noqa: BLE001 - the spike wants the reason, not a trace
        print(json.dumps({"status": "FAILED", "result": str(err)}))
        sys.exit(2)
