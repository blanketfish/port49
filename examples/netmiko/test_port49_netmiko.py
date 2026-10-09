"""The Netmiko example's test (plan 9a, Task 7): a fake port49 and a fake
Netmiko, so it runs with neither installed."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

captured = {}


class FakeConnectHandler:
    def __init__(self, **kw):
        captured.update(kw)
        with open(kw["alt_key_file"], encoding="ascii") as f:
            captured["known_hosts"] = f.read()
        captured["mode"] = stat.S_IMODE(os.stat(kw["alt_key_file"]).st_mode)
        captured["dir_mode"] = stat.S_IMODE(os.stat(os.path.dirname(kw["alt_key_file"])).st_mode)


sys.modules["netmiko"] = types.SimpleNamespace(ConnectHandler=FakeConnectHandler)

import port49_netmiko  # noqa: E402

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
OTHER = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJm"


class Example(unittest.TestCase):
    def setUp(self):
        captured.clear()
        self.dir = tempfile.mkdtemp()
        self.pins = os.path.join(self.dir, "known_hosts")
        self.write_pins("# pinned by port49\n\nspine2 " + OTHER + "\nLeaf1 " + KEY + "\n")
        self.argv = os.path.join(self.dir, "argv")
        item = {"device": "leaf1", "verdict": "permit", "address": "10.0.0.11", "platform": "arista_eos",
                "username": "alice", "login": "LOGINTOKEN"}
        self.port49 = os.path.join(self.dir, "port49")
        with open(self.port49, "w", encoding="ascii") as f:
            f.write("#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + self.argv + "'\necho '" + json.dumps(item) + "'\n")
        os.chmod(self.port49, 0o755)

    def write_pins(self, text):
        with open(self.pins, "w", encoding="ascii") as f:
            f.write(text)
        os.chmod(self.pins, 0o600)  # whatever the umask: a group-writable file is refused

    def test_it_logs_in_with_the_token_and_checks_the_pinned_key(self):
        port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
        self.assertEqual(captured["host"], "10.0.0.11")
        self.assertEqual(captured["username"], "alice")
        self.assertEqual(captured["password"], "LOGINTOKEN")
        self.assertEqual(captured["device_type"], "arista_eos")
        self.assertTrue(captured["ssh_strict"])
        self.assertFalse(captured["system_host_keys"])
        self.assertFalse(captured["use_keys"])
        self.assertFalse(captured["allow_agent"])
        # The pin, and only that device's, under the address Netmiko connects to. The
        # pins file spells the name "Leaf1": names match without regard to case.
        self.assertEqual(captured["known_hosts"], "10.0.0.11 " + KEY + "\n")
        self.assertEqual(captured["mode"], 0o600)
        self.assertEqual(captured["dir_mode"], 0o700)
        self.assertFalse(os.path.exists(captured["alt_key_file"]))
        self.assertFalse(os.path.exists(os.path.dirname(captured["alt_key_file"])))
        with open(self.argv, encoding="ascii") as f:
            self.assertEqual(f.read(), "token\n--json\nleaf1\n")

    def test_the_name_given_matches_without_regard_to_case(self):
        self.write_pins("leaf1 " + KEY + "\n")
        port49_netmiko.connect("LEAF1", port49=self.port49, pins=self.pins)
        self.assertEqual(captured["known_hosts"], "10.0.0.11 " + KEY + "\n")

    def test_the_temp_file_goes_when_netmiko_fails(self):
        def boom(**kw):
            captured["alt_key_file"] = kw["alt_key_file"]
            raise OSError("connection refused")

        real = sys.modules["netmiko"].ConnectHandler
        sys.modules["netmiko"].ConnectHandler = boom
        try:
            with self.assertRaises(OSError):
                port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
        finally:
            sys.modules["netmiko"].ConnectHandler = real
        self.assertFalse(os.path.exists(captured["alt_key_file"]))
        self.assertFalse(os.path.exists(os.path.dirname(captured["alt_key_file"])))

    def test_no_pin_mints_nothing(self):
        with self.assertRaises(RuntimeError):
            port49_netmiko.connect("spine1", port49=self.port49, pins=self.pins)
        self.assertFalse(os.path.exists(self.argv))

    def test_a_missing_pins_file_mints_nothing(self):
        with self.assertRaises(RuntimeError):
            port49_netmiko.connect("leaf1", port49=self.port49, pins=os.path.join(self.dir, "nope"))
        self.assertFalse(os.path.exists(self.argv))

    def test_a_pins_file_others_can_write_mints_nothing(self):
        os.chmod(self.pins, 0o664)
        with self.assertRaises(RuntimeError):
            port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
        self.assertFalse(os.path.exists(self.argv))

    def test_a_line_port49_cannot_fully_parse_refuses_the_whole_file(self):
        # Each of these is a line OpenSSH would read differently from a plain "name key"; the
        # valid leaf1 pin beside it is not trusted either, and nothing is minted.
        bad = {
            "pattern": "leaf* " + KEY,
            "comma list": "leaf1,leaf2 " + KEY,
            "hashed": "|1|c2FsdA==|aGFzaA== " + KEY,
            "marker": "@revoked leaf1 " + KEY,
            "cert authority": "@cert-authority leaf1 " + KEY,
            "negation": "!leaf1 " + KEY,
            "port form": "[leaf1]:2222 " + KEY,
            "no key": "spine9",
            "bad key": "spine9 ssh-ed25519 not*base64",
            "type mismatch": "spine9 ssh-rsa " + KEY.split()[1],
        }
        for name, line in bad.items():
            with self.subTest(name):
                self.write_pins("leaf1 " + KEY + "\n" + line + "\n")
                with self.assertRaises(RuntimeError) as cm:
                    port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
                self.assertIn("line 2", str(cm.exception))
                self.assertIn(self.pins, str(cm.exception))
                self.assertFalse(os.path.exists(self.argv))

    def test_the_token_is_not_in_an_error(self):
        self.write_pins("leaf1 " + KEY + "\n")
        with open(self.port49, "w", encoding="ascii") as f:
            f.write("#!/bin/sh\necho '{\"address\": \"10.0.0.11\", \"platform\": \"nope\", "
                    "\"username\": \"alice\", \"login\": \"LOGINTOKEN\"}'\n")
        with self.assertRaises(RuntimeError) as cm:
            port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def fake_port49(self, script):
        with open(self.port49, "w", encoding="ascii") as f:
            f.write("#!/bin/sh\n" + script)

    def test_port49s_own_explanation_reaches_the_operator(self):
        # port49 token explains a failure on stderr only. It must reach the operator's stderr,
        # not be captured: the raised error carries neither it nor a token.
        self.write_pins("leaf1 " + KEY + "\n")
        self.fake_port49("echo 'no agent at /run/port49.sock; run port49 login' >&2\nexit 1\n")
        err_path = os.path.join(self.dir, "stderr")
        saved = os.dup(2)
        with open(err_path, "w", encoding="ascii") as err:
            os.dup2(err.fileno(), 2)
            try:
                with self.assertRaises(subprocess.CalledProcessError) as cm:
                    port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
            finally:
                os.dup2(saved, 2)
                os.close(saved)
        with open(err_path, encoding="ascii") as f:
            self.assertIn("run port49 login", f.read())
        self.assertIsNone(cm.exception.stderr)
        self.assertNotIn("LOGINTOKEN", str(cm.exception) + repr(cm.exception))

    def test_port49_not_on_path_says_so(self):
        self.write_pins("leaf1 " + KEY + "\n")
        with self.assertRaises(RuntimeError) as cm:
            port49_netmiko.connect("leaf1", port49=os.path.join(self.dir, "no-such-port49"), pins=self.pins)
        self.assertIn("port49 is not on PATH", str(cm.exception))
        self.assertIn("port49=", str(cm.exception))

    def test_a_host_key_mismatch_names_the_device_and_the_fix(self):
        # Netmiko wraps Paramiko's BadHostKeyException; its message is the only thing it keeps.
        class NetmikoTimeoutException(Exception):
            pass

        def mismatch(**kw):
            raise NetmikoTimeoutException(
                "Host key for server '10.0.0.11' does not match: got 'AAAA', expected 'BBBB'")

        real = sys.modules["netmiko"].ConnectHandler
        sys.modules["netmiko"].ConnectHandler = mismatch
        try:
            with self.assertRaises(RuntimeError) as cm:
                port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
        finally:
            sys.modules["netmiko"].ConnectHandler = real
        self.assertIn("leaf1", str(cm.exception))
        self.assertIn("port49 devices trust --replace leaf1", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))
        self.assertIsInstance(cm.exception.__cause__, NetmikoTimeoutException)

    def test_another_connection_failure_passes_through(self):
        def refused(**kw):
            raise OSError("connection refused")

        real = sys.modules["netmiko"].ConnectHandler
        sys.modules["netmiko"].ConnectHandler = refused
        try:
            with self.assertRaises(OSError):
                port49_netmiko.connect("leaf1", port49=self.port49, pins=self.pins)
        finally:
            sys.modules["netmiko"].ConnectHandler = real


if __name__ == "__main__":
    unittest.main()
