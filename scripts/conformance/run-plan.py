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
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The suite's Result enum is PASSED / FAILED / WARNING / REVIEW / SKIPPED
# (TestModule.Result). "SUCCESS" is kept as an alias for older releases.
TERMINAL_OK = {"PASSED", "SUCCESS", "WARNING", "REVIEW", "SKIPPED"}
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


def new_browser(insecure):
    """A browser-like opener: its own cookie jar, so the callback's session cookie is
    sent with the implicit submission exactly as a real browser would."""
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(),
        urllib.request.HTTPSHandler(context=context(insecure)),
    )


def fetch_front_channel(url, insecure, opener=None):
    """Drive one front-channel URL the way a browser would: follow every redirect.

    Returns (status, final_url, body). The body matters: the suite's callback does
    not finish the flow itself, it returns a page whose JavaScript posts the URL
    fragment back to a one-time /implicit/<random> URL (see submit_implicit_page).
    """
    opener = opener or new_browser(insecure)
    req = urllib.request.Request(url, headers={"User-Agent": "r0semi-conformance-spike"})
    with opener.open(req, timeout=60) as resp:
        return resp.status, resp.geturl(), resp.read().decode("utf-8", "replace")


# The suite's implicitCallback page submits with a literal JS call; both quote styles
# appear across versions, and Thymeleaf renders the URL inline.
IMPLICIT_SUBMIT_RE = re.compile(r"""xhr\.open\(\s*['"]POST['"]\s*,\s*(['"])(?P<url>[^'"]+)\1""")


def submit_implicit_page(final_url, body, insecure, opener=None):
    """Run the one piece of JavaScript our HTTP client cannot: the suite's callback
    returns `implicitCallback`, whose script POSTs `window.location.hash` to a
    one-time /implicit/<random> endpoint. Without that POST the module stays WAITING
    forever and the authorization code is never exchanged.

    Returns a status line for the report, or None when the page is not that one.
    """
    match = IMPLICIT_SUBMIT_RE.search(body or "")
    if not match:
        return None
    # Thymeleaf renders the inline JavaScript string as a JSON literal, so the URL
    # arrives with escaped slashes (`https:\/\/host\/path`). Decoding it is not
    # cosmetic: using the raw text produced a path full of backslashes, which Tomcat
    # rejected as an invalid request target (HTTP 400).
    raw = match.group("url")
    try:
        decoded = json.loads('"%s"' % raw)
    except ValueError:
        decoded = raw.replace("\\/", "/")
    # A browser resolves the script's URL against the page it came from; the suite
    # renders it relatively (base_url + "/implicit/<random>"), and urllib would
    # otherwise fail with "no host given".
    submit_url = urllib.parse.urljoin(final_url, decoded)
    if not urllib.parse.urlsplit(submit_url).netloc:
        return "implicit submit skipped: unresolvable URL %r (page %s)" % (decoded, final_url)
    fragment = urllib.parse.urlsplit(final_url).fragment
    origin_note = "" if decoded == submit_url else " (page said %r)" % decoded
    # The page's XHR sends text/plain; if the deployment rejects that, a form-encoded
    # retry is the next shape a browser-adjacent client would try, and both outcomes
    # go into the report so the next run is diagnosable either way.
    opener = opener or new_browser(insecure)
    last = None
    for content_type in ("text/plain", "application/x-www-form-urlencoded"):
        req = urllib.request.Request(submit_url, data=fragment.encode("utf-8"), method="POST",
                                     headers={"Content-Type": content_type})
        try:
            with opener.open(req, timeout=30) as resp:
                return "implicit submit %s%s (%s, fragment %d bytes) -> %s" % (
                    submit_url, origin_note, content_type, len(fragment), resp.status)
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace")[:300]
            last = "implicit submit %s%s (%s) -> HTTP %s: %s" % (
                submit_url, origin_note, content_type, err.code, detail)
            if err.code != 400:
                return last
        except urllib.error.URLError as err:
            return "implicit submit %s%s (%s) failed: %s" % (
                submit_url, origin_note, content_type, err.reason)
    return last


def module_human_step(api, test_id, insecure):
    """The suite's placeholder entries, i.e. work only a person can do.

    A module waiting on one is not stuck on the OP. The line can be anywhere in the
    log (oidcc-prompt-login's "a screenshot of this must be uploaded" sits before
    several later SUCCESS entries), so the whole log is scanned rather than its
    tail. Returns the suite's own sentence, or "".
    """
    try:
        entries = request(api, "GET", "/api/log/" + urllib.parse.quote(test_id), insecure=insecure)
    except RuntimeError:
        return ""
    if not isinstance(entries, list):
        return ""
    pattern = re.compile(r"screenshot|upload|paste|placeholder|must ask the user|"
                         r"manually|on the browser", re.IGNORECASE)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        message = str(entry.get("msg") or "")
        if entry.get("result") == "REVIEW" and message:
            return message[:200]
        if pattern.search(json.dumps(entry)):
            return message[:200] or "the suite is waiting for a human"
    return ""


def dump_module_log(api, test_id, log_dir, insecure, name):
    """Write a module's full suite log into the artifact.

    The run summary can only carry a few lines, and a WARNING/FAILED reason like
    "Invalid http status" needs the request the suite actually sent. `GET /api/log/
    <id>` has it; keeping the file next to plan-run.json makes the next round
    diagnosable without another run.
    """
    if not log_dir:
        return
    try:
        entries = request(api, "GET", "/api/log/" + urllib.parse.quote(test_id), insecure=insecure)
    except RuntimeError as err:
        entries = [{"result": "ERROR", "msg": "could not fetch the suite log: %s" % err}]
    try:
        os.makedirs(log_dir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name or "module")
        with open(os.path.join(log_dir, "%s.%s.json" % (safe, test_id)), "w",
                  encoding="utf-8") as fh:
            json.dump(entries, fh, indent=1)
    except OSError as err:
        print("could not write the suite log for %s: %s" % (name, err), file=sys.stderr)


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


def visit_front_channel(api, test_id, insecure, seen, delay=0.0):
    """Visit the URLs the module is waiting on; report each as visited.

    Returns (outcomes, new_count, urls): outcomes are human-readable lines for the
    report, new_count counts URLs not seen before, and urls is the full list so the
    caller can remember it.

    `delay` simulates a page load. The suite tells the test "go to this URL" and the
    test registers its callback condition on its next step; a synchronous fetch can
    deliver the authorization response before that condition exists, and the code is
    then dropped while the module waits forever. A real browser takes long enough
    that this never happens, so a short pause is the faithful emulation.
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
        if url in seen:
            # Already driven: re-fetching would start a second authorization for a
            # module that is simply slow, not stuck.
            continue
        new += 1
        if delay:
            time.sleep(delay)
        # One browser per visit: the fetch and the implicit submission share its
        # cookie jar, which is what a real browser does with the session the callback
        # page may set.
        browser = new_browser(insecure)
        try:
            status, final, body = fetch_front_channel(url, insecure, browser)
            outcomes.append("visited %s -> %s %s" % (url, status, final))
            implicit = submit_implicit_page(final, body, insecure, browser)
            if implicit:
                outcomes.append(implicit)
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


def module_messages(api, test_id, insecure, limit=6, include_info=False):
    """The suite's log lines that explain a module: FAILURE/ERROR/WARNING, and
    optionally INFO as well (the tail), for a module stuck before any verdict."""
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
        if not include_info and entry.get("result") not in LOG_INTERESTING:
            continue
        text = entry.get("msg") or entry.get("description") or entry.get("src") or ""
        if text:
            out.append(str(text)[:300])
    return out[-limit:] if include_info else out[:limit]


def run_module(api, plan_id, entry, insecure, deadline, module_timeout, visit_rounds, visit_delay):
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
    idle = 0
    stuck_exit = False
    while time.time() < module_deadline:
        # Long-poll for a TERMINAL state first. Asking for WAITING as well would
        # return instantly (the suite answers immediately when the status already
        # matches), so four "rounds" could elapse in milliseconds and the module
        # would be abandoned before its callback had been processed.
        state = wait_state(api, test_id, insecure, ["FINISHED", "INTERRUPTED", "STOPPED"],
                           timeout_ms=10000)
        if state in TERMINAL_STATUSES:
            status = state
            break
        # Not terminal: offer any front-channel URL it is waiting on. A module that
        # is RUNNING (a second authorization, a userinfo round) is making progress
        # and must not be given up on; only a WAITING module with nothing new to
        # visit is genuinely stuck.
        current = request(api, "GET", "/api/info/" + urllib.parse.quote(test_id),
                          insecure=insecure).get("status")
        outcomes, new, urls = visit_front_channel(api, test_id, insecure, seen, visit_delay)
        seen.update(urls)
        visits.extend(outcomes)
        if new:
            idle = 0
            continue
        if current == "WAITING":
            idle += 1
            if idle >= visit_rounds:
                stuck_exit = True
                break
        else:
            idle = 0
        time.sleep(2)
    info = request(api, "GET", "/api/info/" + urllib.parse.quote(test_id), insecure=insecure)
    result = info.get("result")
    # The suite keeps a module at WAITING when the front channel never completed it,
    # which is exactly the case worth reporting as interrupted.
    status = "INTERRUPTED" if stuck_exit else (info.get("status") or status)
    module = {"testModule": name, "testId": test_id, "status": status, "result": result}
    if visits:
        module["visits"] = visits[-8:]
    # Anything that is not a clean PASSED carries reasons worth keeping: a WARNING
    # from the suite names what it was unhappy about, and a FAILED/INTERRUPTED one
    # names the failure.
    if result != "PASSED":
        messages = module_messages(api, test_id, insecure)
        if stuck_exit:
            # The test's own log tail (INFO included) is what says whether the
            # callback was ingested or the flow stopped one step earlier.
            messages.insert(0, "stayed WAITING after %d idle front-channel rounds" % visit_rounds)
            tail = module_messages(api, test_id, insecure, limit=6, include_info=True)
            messages += tail
            # Some modules deliberately stop for a human: a screenshot of an error
            # page, a pasted URI, a confirmation that a page was shown. Name that,
            # so it is not read as a protocol bug.
            human = module_human_step(api, test_id, insecure)
            if human:
                module["interactive"] = "human-step"
                messages.insert(0, "INTERACTIVE STEP: the suite is waiting for a human: " + human)
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
    ap.add_argument("--visit-delay", type=float, default=1.0,
                    help="seconds to pause before fetching a front-channel URL (emulates a page load)")
    ap.add_argument("--log-dir", default="",
                    help="directory to write the full suite log of every non-PASSED module into")
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
                                args.module_timeout, args.visit_rounds, args.visit_delay)
        except RuntimeError as err:
            result = {"testModule": module_name(entry), "status": "INTERRUPTED", "result": None,
                      "messages": [str(err)]}
        if result:
            results.append(result)
            if result.get("result") != "PASSED":
                dump_module_log(args.api, result.get("testId"), args.log_dir, args.insecure,
                                result.get("testModule"))

    ok = all(module.get("result") in TERMINAL_OK for module in results)
    if ok:
        # The suite's own word for a clean run (TestModule.Result.PASSED).
        overall = "PASSED"
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
