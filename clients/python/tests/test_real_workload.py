"""Workload against the real port49 binary, built here, over mTLS to a stub broker.

The stub is an ssl-wrapped stdlib HTTP server with a throwaway CA (made with the openssl CLI) that
demands a client certificate, as the broker does; the real `port49 workload token` renders every
shape the library reads: finished, all denied, nothing selected, and stopped by 75, 77 and 1. A host
with no Go toolchain or no openssl skips these; make test has both. The connection_changed stop
(a touch whose connection moved) needs a hardware key and is covered by the fake CLI's tests only."""

import http.server
import io
import json
import os
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from port49 import BrokerRefused, MFARequired, Port49Error, Temporary, Workload  # noqa: E402

REPO = os.path.join(HERE, "..", "..", "..")
PRINCIPAL = "spiffe://corp.example.com/host/oxidized-01"


def permit(device):
    return {"device": device, "verdict": "permit", "address": "10.0.0.1", "platform": "arista_eos",
            "username": "svc-oxidized", "login": "TOKEN-" + device, "expires_at": "2026-10-08T03:00:00Z"}


def mixed(req):
    """The broker's answer to a mint by name: fw1 is denied, core1 wants a touch, the rest are permitted."""
    items = []
    for d in req["devices"]:
        if d == "fw1":
            items.append({"device": d, "verdict": "deny", "reason": "no_grants_matched"})
        elif d == "core1":
            items.append({"device": d, "verdict": "deny", "reason": "per_login_mfa_required",
                          "per_login_mfa": {"device": d, "challenge": "CHALLENGE", "accept": ["hardware_key_touch"],
                                            "reuse_for_seconds": 900}})
        else:
            items.append(permit(d))
    return 200, {"principal": PRINCIPAL, "subject": "svc_oxidized", "results": items}


def stop_at(bad, status):
    def answer(req):
        if req["devices"][0] == bad:
            return status, {"error": "bad_request", "detail": "BODY-WORDS"}
        return mixed(req)
    return answer


class Broker(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    batch_max = 100
    mint = staticmethod(mixed)

    def handle_error(self, request, client_address):
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _answer(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/v1/config":
            status, obj = 200, {"batch_max": self.server.batch_max}
        elif self.path == "/v1/identity":
            status, obj = 200, {"principal": PRINCIPAL, "method": "cert", "subject": "svc_oxidized"}
        elif self.path == "/v1/tokens":
            req = json.loads(body)
            self.server.requests.append(req)
            status, obj = self.server.mint(req)
        else:
            status, obj = 404, {"error": "not_found"}
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _answer


def openssl(*args):
    done = subprocess.run(["openssl", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise AssertionError("openssl " + " ".join(args) + " failed:\n" + done.stderr)


def issue(directory, name, subject_alt_name, usage):
    """A leaf under the CA made in directory: name.pem and name.key."""
    key, csr, pem, ext = (os.path.join(directory, name + s) for s in (".key", ".csr", ".pem", ".ext"))
    with open(ext, "w", encoding="utf-8") as f:
        f.write(f"subjectAltName={subject_alt_name}\nextendedKeyUsage={usage}\nbasicConstraints=CA:FALSE\n")
    openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", csr,
            "-subj", "/CN=" + name)
    openssl("x509", "-req", "-in", csr, "-CA", os.path.join(directory, "ca.pem"), "-CAkey",
            os.path.join(directory, "ca.key"), "-CAcreateserial", "-out", pem, "-days", "2", "-extfile", ext)


class RealWorkload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        go = shutil.which("go")
        if go is None or shutil.which("openssl") is None:
            raise unittest.SkipTest("no go toolchain or openssl to build the binary and its throwaway CA")
        cls.dir = tempfile.mkdtemp()
        cls.binary = os.path.join(cls.dir, "port49")
        built = subprocess.run([go, "build", "-o", cls.binary, "./cmd/port49"], cwd=REPO,
                               env={**os.environ, "CGO_ENABLED": "0"}, capture_output=True, text=True)
        if built.returncode != 0:
            raise AssertionError("go build ./cmd/port49 failed:\n" + built.stderr)
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout",
                os.path.join(cls.dir, "ca.key"), "-out", os.path.join(cls.dir, "ca.pem"), "-subj", "/CN=workloads",
                "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=keyCertSign")
        issue(cls.dir, "broker", "IP:127.0.0.1", "serverAuth")
        issue(cls.dir, "w", "URI:" + PRINCIPAL, "clientAuth")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(os.path.join(cls.dir, "broker.pem"), os.path.join(cls.dir, "broker.key"))
        ctx.load_verify_locations(os.path.join(cls.dir, "ca.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        cls.broker = Broker(("127.0.0.1", 0), Handler)
        cls.broker.socket = ctx.wrap_socket(cls.broker.socket, server_side=True)
        threading.Thread(target=cls.broker.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.broker.shutdown()
        cls.broker.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def workload(self, mint=mixed, batch_max=100, attempts=1):
        self.broker.mint, self.broker.batch_max, self.broker.requests = staticmethod(mint), batch_max, []
        w = Workload(f"https://127.0.0.1:{self.broker.server_address[1]}", os.path.join(self.dir, "ca.pem"),
                     os.path.join(self.dir, "w.pem"), os.path.join(self.dir, "w.key"), port49=self.binary,
                     deadline=1, stderr=io.StringIO(), attempts=attempts)
        w._sleep = lambda s: None
        return w

    def test_identity(self):
        self.assertEqual(self.workload().identity()["principal"], PRINCIPAL)

    def test_a_finished_run_with_refusals_returns(self):
        res = self.workload().tokens(["leaf1", "fw1", "core1"])
        self.assertEqual(list(res.tokens), ["leaf1"])
        self.assertEqual(res.tokens["leaf1"].login, "TOKEN-leaf1")
        self.assertEqual(res.refused["fw1"].reason, "no_grants_matched")
        self.assertEqual(res.refused["core1"].per_login_mfa["accept"], ["hardware_key_touch"])
        self.assertIsInstance(res.refused["core1"].exception(), MFARequired)
        self.assertNotIn("CHALLENGE", repr(res))

    def test_every_device_denied_returns(self):
        res = self.workload().tokens(["fw1"])
        self.assertEqual((res.tokens, list(res.refused)), ({}, ["fw1"]))

    def test_a_scope_selecting_nothing_returns_empty(self):
        res = self.workload(lambda req: (200, {"principal": PRINCIPAL, "subject": "svc_oxidized", "results": []})
                            ).tokens(scope="none")
        self.assertEqual((res.tokens, res.refused), ({}, {}))

    def test_stopped_by_75_raises_temporary_naming_what_was_left(self):
        with self.assertRaises(Temporary) as cm:
            self.workload(stop_at("leaf2", 503), batch_max=1).tokens(["fw1", "leaf1", "leaf2", "leaf3"])
        e = cm.exception
        self.assertEqual(e.code, "broker_unavailable")
        self.assertEqual(list(e.results.tokens), ["leaf1"])
        self.assertEqual(sorted(e.results.refused), ["fw1", "leaf2", "leaf3"])
        self.assertEqual(e.results.refused["leaf3"].error, "broker_unavailable")
        self.assertNotIn("BODY-WORDS", str(e) + repr(e.results))

    def test_stopped_by_77_raises_broker_refused(self):
        with self.assertRaises(BrokerRefused) as cm:
            self.workload(stop_at("leaf2", 400), batch_max=1).tokens(["fw1", "leaf1", "leaf2", "leaf3"])
        self.assertEqual(cm.exception.code, "broker_refused")
        self.assertEqual(list(cm.exception.results.tokens), ["leaf1"])
        self.assertEqual(sorted(cm.exception.results.refused), ["fw1", "leaf2", "leaf3"])

    def test_stopped_by_1_raises_port49_error(self):
        with self.assertRaises(Port49Error) as cm:
            self.workload(stop_at("leaf2", 500), batch_max=1).tokens(["leaf1", "leaf2"])
        self.assertEqual(cm.exception.code, "agent_error")
        self.assertNotIsInstance(cm.exception, (Temporary, BrokerRefused))
        self.assertEqual(list(cm.exception.results.tokens), ["leaf1"])

    def test_a_scope_sweep_that_stops_raises(self):
        def first_page_only(req):
            if req.get("after"):
                return 400, {"error": "bad_request", "detail": "BODY-WORDS"}
            return 200, {"principal": PRINCIPAL, "subject": "svc_oxidized", "next": "leaf1", "results": [permit("leaf1")]}
        with self.assertRaises(BrokerRefused) as cm:
            self.workload(first_page_only).tokens(scope="dc")
        self.assertEqual(list(cm.exception.results.tokens), ["leaf1"])
        self.assertEqual(len(self.broker.requests), 2)  # minted a page: not run again

    def test_a_retry_mints_only_what_was_left(self):
        failed = []

        def flaky(req):
            if req["devices"][0] == "leaf2" and not failed:
                failed.append(1)
                return 503, {"error": "broker_unavailable"}
            return mixed(req)
        res = self.workload(flaky, batch_max=1, attempts=2).tokens(["leaf1", "leaf2", "leaf3"])
        self.assertEqual(sorted(res.tokens), ["leaf1", "leaf2", "leaf3"])
        self.assertEqual(res.refused, {})
        asked = [r["devices"] for r in self.broker.requests]
        self.assertEqual(asked.count(["leaf1"]), 1)  # never minted twice
        self.assertIn(["leaf2"], asked)
        self.assertEqual(asked.count(["leaf3"]), 1)


if __name__ == "__main__":
    unittest.main()
