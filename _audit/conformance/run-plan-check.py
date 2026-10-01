#!/usr/bin/env python3
"""Self-check for scripts/conformance/run-plan.py, with no Docker or suite.

Starts a stub that mimics the suite endpoints the runner uses — plan creation, test
creation, the wait-state long poll, the front-channel browser URLs, the per-test log —
then asserts three verdicts:

* every module succeeds            -> exit 0, result SUCCESS, front channel visited
* a module FAILURE                 -> exit 2, result FAILURE, with its log message
* a module stuck on a request the suite sent without PKCE -> exit 2, INTERRUPTED,
  tagged `divergence: pkce-required`

    python _audit/conformance/run-plan-check.py
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESULT = {"value": "SUCCESS"}
WAIT_ALWAYS = {"value": False}
DIVERGE = {"value": False}
WAITED = defaultdict(int)
VISITED = []
IMPLICIT = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the check quiet
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, status=204):
        self.send_response(status)
        self.end_headers()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        query = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        if path.startswith("/api/plan"):
            self._json({"id": "plan-1", "modules": [{"testModule": "m-one"}, {"testModule": "m-two"}]})
        elif path.startswith("/api/runner/browser/") and path.endswith("/visit"):
            VISITED.append(path)
            self._empty()
        elif path.startswith("/implicit/"):
            # The page's JavaScript would POST here; the runner has to do it instead.
            IMPLICIT.append(path)
            self._empty()
        elif path.startswith("/api/runner"):
            test = (query.get("test") or ["?"])[0]
            self._json({"id": "t-" + test})
        else:
            self._empty(404)

    def do_GET(self):
        if self.path.startswith("/api/runner/") and "/wait-state" in self.path:
            test = self.path.split("/api/runner/", 1)[1].split("/", 1)[0]
            WAITED[test] += 1
            if WAIT_ALWAYS["value"]:
                self._json({"state": "WAITING"})
            else:
                # WAITING once, so the runner must visit the front channel, then finish.
                self._json({"state": "FINISHED" if WAITED[test] > 1 else "WAITING"})
        elif self.path.startswith("/api/runner/browser/"):
            test = self.path.split("/api/runner/browser/", 1)[1]
            self._json({"id": test,
                        "urls": ["http://127.0.0.1:%d/front" % self.server.server_address[1]],
                        "visited": []})
        elif self.path.startswith("/api/info/"):
            # A module the suite never completes carries no result at all.
            self._json({"status": "WAITING" if WAIT_ALWAYS["value"] else "FINISHED",
                        "result": None if WAIT_ALWAYS["value"] else RESULT["value"]})
        elif self.path.startswith("/api/log/"):
            if RESULT["value"] == "FAILURE":
                self._json([{"result": "FAILURE", "msg": "stub failure reason"},
                            {"result": "INFO", "msg": "ignored"}])
            else:
                self._json([{"result": "INFO", "msg": "ok"}])
        elif self.path == "/front":
            if DIVERGE["value"]:
                self.send_response(302)
                self.send_header(
                    "Location",
                    "http://127.0.0.1:%d/cb?error=invalid_request&error_description=code_challenge+is+required"
                    % self.server.server_address[1])
                self.end_headers()
            else:
                # The suite's implicitCallback page: the flow only advances when the
                # JavaScript POST runs, which the runner must emulate. The URL is
                # deliberately RELATIVE, exactly as the suite renders it, so the
                # check also pins the browser-style urljoin resolution.
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                page = ("<html><script>"
                        "xhr.open('POST', \"/implicit/abc\", true);"
                        "xhr.send(window.location.hash);</script></html>")
                body = page.encode("utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        elif self.path.startswith("/cb"):
            self._json({"done": True})
        else:
            self._json({}, 404)


def run_runner(api, payload_path):
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return subprocess.run(
        [sys.executable, "scripts/conformance/run-plan.py", "--api", api, "--payload", payload_path,
         "--module-timeout", "20", "--visit-rounds", "2", "--visit-delay", "0"],
        capture_output=True, text=True, cwd=root)


def parse(proc):
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as err:  # noqa: BLE001
        print("FAIL: output is not JSON: %s (%s)" % (proc.stdout, err))
        return None


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    api = "http://127.0.0.1:%d" % server.server_address[1]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump({"planName": "oidcc-basic-certification-test-plan",
                   "variant": {"client_registration": "static_client"},
                   "config": {"alias": "conformance"}}, fh)
        payload = fh.name

    ok = True

    # 1. Everything succeeds.
    RESULT["value"] = "SUCCESS"
    proc = run_runner(api, payload)
    out = parse(proc)
    if proc.returncode != 0 or not out or out.get("result") != "SUCCESS" or len(out.get("modules") or []) != 2:
        print("FAIL success case: rc=%s out=%s" % (proc.returncode, out))
        ok = False
    if not VISITED:
        print("FAIL: the runner never visited a front-channel URL")
        ok = False
    if not IMPLICIT:
        print("FAIL: the runner did not run the implicitCallback page's POST")
        ok = False

    # 2. A module fails: the log message must reach the report.
    WAITED.clear()
    VISITED.clear()
    IMPLICIT.clear()
    RESULT["value"] = "FAILURE"
    proc = run_runner(api, payload)
    out = parse(proc)
    messages = [m for module in (out or {}).get("modules") or [] for m in (module.get("messages") or [])]
    if proc.returncode != 2 or not out or out.get("result") != "FAILURE" \
            or not any("stub failure reason" in m for m in messages):
        print("FAIL failure case: rc=%s out=%s" % (proc.returncode, out))
        ok = False

    # 3. A module the suite will never complete because it sent no PKCE: stuck, named
    #    as a policy divergence rather than an OP bug.
    WAITED.clear()
    VISITED.clear()
    IMPLICIT.clear()
    RESULT["value"] = "SUCCESS"
    WAIT_ALWAYS["value"] = True
    DIVERGE["value"] = True
    proc = run_runner(api, payload)
    out = parse(proc)
    modules = (out or {}).get("modules") or []
    diverged = [m for m in modules if m.get("divergence") == "pkce-required"]
    if proc.returncode != 2 or not diverged \
            or not any("POLICY DIVERGENCE" in m for m in (diverged[0].get("messages") or [])):
        print("FAIL divergence case: rc=%s out=%s" % (proc.returncode, out))
        ok = False

    os.unlink(payload)
    server.shutdown()

    if not ok:
        return 1
    print("run-plan.py self-check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
