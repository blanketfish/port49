"""The library against the real port49 binary, built here: no hand-written JSON for what it can print.

With no agent listening the CLI answers for itself. For the rest, a stdlib stub stands in for the
agent's Unix socket (the CLI calls only POST /token and GET /status), so the real CLI renders the
permit and every failure shape the library reads. A host with no Go toolchain skips these; make
test has one."""

import http.server
import io
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from port49 import (Agent, Denied, DeviceFault, KeyUnavailable, MFARequired, NoAgent, Port49Error,  # noqa: E402
                    SessionOver, Temporary)

REPO = os.path.join(HERE, "..", "..", "..")

PERMIT = {"device": "leaf1", "verdict": "permit", "address": "10.0.0.11", "platform": "arista_eos",
          "username": "alice", "login": "LOGINTOKEN", "enable": "ENABLETOKEN",
          "expires_at": "2026-10-13T10:00:00Z", "session_expires_at": "2026-10-13T18:00:00Z"}

ANSWERS = {  # name: (HTTP status, JSON body) the stub agent gives POST /token
    "permit": (200, PERMIT),
    "deny": (200, {"device": "leaf1", "verdict": "deny", "reason": "no_grants_matched", "detail": "d"}),
    "item_fault": (200, {"device": "leaf1", "error": "device_unconfigured", "detail": "no such device"}),
    "session_over": (410, {"error": "session_over", "detail": "ended"}),
    "revoked": (410, {"error": "credential_revoked", "detail": "since x"}),
    "revocation_running": (503, {"error": "revocation_running", "detail": "busy"}),
    "broker_unavailable": (503, {"error": "broker_unavailable", "detail": "down"}),
    "touch_timeout": (409, {"error": "touch_timeout", "detail": "no touch"}),
    # A device that asks for a touch from an agent with no touch key: the CLI's per_login_mfa_required,
    # whatever the terminal (hardware_key_touch only: idp_mfa would depend on stdin being one).
    "mfa": (428, {"device": "leaf1", "challenge": "CHALLENGE", "accept": ["hardware_key_touch"],
                  "reuse_for_seconds": 900, "reuse_from": "scope core"}),
}
STATUS = {"mfa": (200, {})}  # GET /status; every other answer leaves it a 404


class StubHandler(http.server.BaseHTTPRequestHandler):
    def address_string(self):
        return "unix"

    def log_message(self, *args):
        pass

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        status, obj = {"/token": self.server.answer, "/status": self.server.status}.get(
            self.path, (404, {"error": "not_found"}))
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _answer


class StubAgent(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    answer = ANSWERS["permit"]
    status = (404, {"error": "not_found"})


class RealCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        go = shutil.which("go")
        if go is None:
            raise unittest.SkipTest("no go toolchain to build the port49 binary")
        cls.dir = tempfile.mkdtemp()
        cls.binary = os.path.join(cls.dir, "port49")
        built = subprocess.run([go, "build", "-o", cls.binary, "./cmd/port49"], cwd=REPO,
                               env={**os.environ, "CGO_ENABLED": "0"}, capture_output=True, text=True)
        if built.returncode != 0:
            raise AssertionError("go build ./cmd/port49 failed:\n" + built.stderr)
        cls.socket = os.path.join(cls.dir, "no-agent.sock")
        cls.stub_socket = os.path.join(cls.dir, "stub.sock")
        cls.stub = StubAgent(cls.stub_socket, StubHandler)
        threading.Thread(target=cls.stub.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.stub.shutdown()
        cls.stub.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def at(self, sock):
        """Point the CLI at the agent on sock, the way the tests do (no flag names it)."""
        os.environ["PORT49_TEST_AGENT_SOCKET"] = sock
        self.addCleanup(os.environ.pop, "PORT49_TEST_AGENT_SOCKET", None)

    def agent(self):
        self.at(self.socket)
        return Agent(port49=self.binary, stderr=io.StringIO())

    def stubbed(self, name, attempts=1):
        self.stub.answer = ANSWERS[name]
        self.stub.status = STATUS.get(name, (404, {"error": "not_found"}))
        self.at(self.stub_socket)
        return Agent(port49=self.binary, stderr=io.StringIO(), attempts=attempts)

    def test_no_agent_is_no_agent(self):
        with self.assertRaises(NoAgent) as cm:
            self.agent().token("leaf1")
        self.assertEqual((cm.exception.code, cm.exception.device), ("no_agent", "leaf1"))
        self.assertIn("no agent is listening", cm.exception.detail)

    def test_a_sweep_stops_at_no_agent(self):
        with self.assertRaises(NoAgent):
            self.agent().tokens(["leaf1", "leaf2"])

    def test_identity_with_no_agent_says_so(self):
        with self.assertRaises(Port49Error) as cm:
            self.agent().identity()
        self.assertIn("no agent", cm.exception.detail)

    def test_the_real_permit_is_a_token(self):
        tok = self.stubbed("permit").token("leaf1", enable=True)
        self.assertEqual((tok.device, tok.address, tok.platform, tok.username),
                         ("leaf1", "10.0.0.11", "arista_eos", "alice"))
        self.assertEqual((tok.login, tok.enable), ("LOGINTOKEN", "ENABLETOKEN"))
        self.assertEqual((tok.expires_at, tok.session_expires_at), ("2026-10-13T10:00:00Z", "2026-10-13T18:00:00Z"))
        self.assertNotIn("LOGINTOKEN", repr(tok))

    def test_the_real_failure_shapes_are_their_classes(self):
        for name, cls, code in [("deny", Denied, "no_grants_matched"),
                                ("item_fault", DeviceFault, "device_unconfigured"),
                                ("session_over", SessionOver, "session_over"),
                                ("revoked", SessionOver, "credential_revoked"),
                                ("revocation_running", Temporary, "revocation_running"),
                                ("broker_unavailable", Temporary, "broker_unavailable"),
                                ("touch_timeout", KeyUnavailable, "touch_timeout")]:
            with self.assertRaises(cls, msg=name) as cm:
                self.stubbed(name).token("leaf1")
            self.assertEqual((cm.exception.code, cm.exception.device), (code, "leaf1"), name)

    def test_the_real_mfa_required_carries_its_requirement(self):
        with self.assertRaises(MFARequired) as cm:
            self.stubbed("mfa").token("leaf1")
        e = cm.exception
        self.assertEqual((e.code, e.device), ("per_login_mfa_required", "leaf1"))
        self.assertEqual(e.requirement["accept"], ["hardware_key_touch"])
        self.assertEqual(e.requirement["reuse_for_seconds"], 900)
        self.assertNotIn("challenge", e.requirement)
        self.assertNotIn("CHALLENGE", str(e) + repr(e.__dict__))

    def test_a_real_mfa_required_is_collected_by_a_sweep(self):
        res = self.stubbed("mfa").tokens(["leaf1", "leaf2"])
        self.assertEqual((list(res.tokens), sorted(res.refused)), ([], ["leaf1", "leaf2"]))
        self.assertEqual(res.refused["leaf1"].per_login_mfa["accept"], ["hardware_key_touch"])
        self.assertIsInstance(res.refused["leaf2"].exception(), MFARequired)

    def test_a_real_item_fault_does_not_stop_a_sweep(self):
        res = self.stubbed("item_fault").tokens(["leaf1", "leaf2"])
        self.assertEqual((list(res.tokens), sorted(res.refused)), ([], ["leaf1", "leaf2"]))
        self.assertEqual(res.refused["leaf1"].error, "device_unconfigured")


if __name__ == "__main__":
    unittest.main()
