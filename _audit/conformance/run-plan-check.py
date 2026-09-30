#!/usr/bin/env python3
"""Self-check for scripts/conformance/run-plan.py, with no Docker or suite.

Starts a stub that mimics the suite endpoints the runner uses — plan creation, test
creation, the wait-state long poll, the front-channel browser URLs, the per-test log —
then asserts the runner's two verdicts: a plan whose modules all succeed exits 0, one
with a FAILURE exits 2 and carries the failure message. It also asserts the runner
actually visited the front-channel URL it was told about.

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
WAITED = defaultdict(int)
VISITED = []


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
        elif path.startswith("/api/runner"):
            test = (query.get("test") or ["?"])[0]
            self._json({"id": "t-" + test})
        else:
            self._empty(404)

    def do_GET(self):
        if self.path.startswith("/api/runner/") and "/wait-state" in self.path:
            test = self.path.split("/api/runner/", 1)[1].split("/", 1)[0]
            WAITED[test] += 1
            # WAITING once, so the runner must visit the front channel, then finish.
            self._json({"state": "FINISHED" if WAITED[test] > 1 else "WAITING"})
        elif self.path.startswith("/api/runner/browser/"):
            test = self.path.split("/api/runner/browser/", 1)[1]
            self._json({"id": test,
                        "urls": ["http://127.0.0.1:%d/front" % self.server.server_address[1]],
                        "visited": []})
        elif self.path.startswith("/api/info/"):
            self._json({"status": "FINISHED", "result": RESULT["value"]})
        elif self.path.startswith("/api/log/"):
            if RESULT["value"] == "FAILURE":
                self._json([{"result": "FAILURE", "msg": "stub failure reason"},
                            {"result": "INFO", "msg": "ignored"}])
            else:
                self._json([{"result": "INFO", "msg": "ok"}])
        elif self.path == "/front":
            self._json({"ok": True})
        else:
            self._json({}, 404)


def run_case(api, payload_path, expect_rc, expect_result, expect_messages):
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    proc = subprocess.run(
        [sys.executable, "scripts/conformance/run-plan.py", "--api", api, "--payload", payload_path],
        capture_output=True, text=True, cwd=root)
    if proc.returncode != expect_rc:
        print("FAIL: exit %s, want %s\nstdout=%s\nstderr=%s" % (proc.returncode, expect_rc,
                                                                proc.stdout, proc.stderr))
        return False
    try:
        out = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as err:  # noqa: BLE001
        print("FAIL: output is not JSON: %s (%s)" % (proc.stdout, err))
        return False
    if out.get("result") != expect_result:
        print("FAIL: result %r, want %r" % (out.get("result"), expect_result))
        return False
    modules = out.get("modules") or []
    if len(modules) != 2:
        print("FAIL: expected two modules, got %s" % (modules,))
        return False
    if expect_messages:
        if not any(expect_messages in (m.get("messages") or [""])[0] for m in modules):
            print("FAIL: failure messages missing: %s" % (modules,))
            return False
    if not VISITED:
        print("FAIL: the runner never visited a front-channel URL")
        return False
    return True


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
    RESULT["value"] = "SUCCESS"
    ok &= run_case(api, payload, 0, "SUCCESS", "")
    WAITED.clear()
    VISITED.clear()
    RESULT["value"] = "FAILURE"
    ok &= run_case(api, payload, 2, "FAILURE", "stub failure reason")
    os.unlink(payload)
    server.shutdown()

    if not ok:
        return 1
    print("run-plan.py self-check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
