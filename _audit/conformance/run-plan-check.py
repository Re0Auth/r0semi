#!/usr/bin/env python3
"""Self-check for scripts/conformance/run-plan.py, with no Docker or suite.

Starts a stub that mimics the three suite endpoints the runner uses, then asserts the
runner's two verdicts: a plan whose modules all succeed exits 0, one with a FAILURE
exits 2. Run it directly:

    python _audit/conformance/run-plan-check.py
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESULT = {"value": "SUCCESS"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the check quiet
        pass

    def _send(self, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.startswith("/api/plan"):
            self._send({"id": "plan-1", "modules": [{"testModule": "m-one"}, {"testModule": "m-two"}]})
        elif self.path.startswith("/api/runner"):
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            test = [p.split("=", 1)[1] for p in query.split("&") if p.startswith("test=")][0]
            self._send({"id": "t-" + test})
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/info/"):
            self._send({"status": "FINISHED", "result": RESULT["value"]})
        else:
            self.send_response(404)
            self.end_headers()


def run_case(api, payload_path, expect_rc, expect_result):
    proc = subprocess.run(
        [sys.executable, "scripts/conformance/run-plan.py", "--api", api, "--payload", payload_path],
        capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    if proc.returncode != expect_rc:
        print("FAIL: exit %s, want %s\nstdout=%s\nstderr=%s" % (proc.returncode, expect_rc, proc.stdout, proc.stderr))
        return False
    try:
        out = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as err:  # noqa: BLE001
        print("FAIL: output is not JSON: %s (%s)" % (proc.stdout, err))
        return False
    if out.get("result") != expect_result:
        print("FAIL: result %r, want %r" % (out.get("result"), expect_result))
        return False
    if len(out.get("modules") or []) != 2:
        print("FAIL: expected two modules, got %s" % (out.get("modules"),))
        return False
    return True


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    api = "http://127.0.0.1:%d" % server.server_address[1]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump({"planName": "oidcc-basic-certification-test-plan",
                   "variant": {"response_type": "code"},
                   "config": {"alias": "conformance"}}, fh)
        payload = fh.name

    ok = True
    RESULT["value"] = "SUCCESS"
    ok &= run_case(api, payload, 0, "SUCCESS")
    RESULT["value"] = "FAILURE"
    ok &= run_case(api, payload, 2, "FAILURE")
    os.unlink(payload)
    server.shutdown()

    if not ok:
        return 1
    print("run-plan.py self-check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
