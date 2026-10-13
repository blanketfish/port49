import io
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import fakeport49 as fake  # noqa: E402
from port49 import (Agent, BrokerRefused, Denied, KeyUnavailable, MFARequired, NoAgent,  # noqa: E402
                    NotInstalled, Port49Error, Refusal, SessionOver, Temporary)
from port49 import DeviceFault  # noqa: E402
from port49 import client  # noqa: E402

REPO = os.path.join(HERE, "..", "..", "..")

PERMIT = fake.item(device="leaf1", verdict="permit", address="10.0.0.11", platform="arista_eos",
                   username="alice", login="LOGINTOKEN", enable="ENABLETOKEN", expires_at="2026-10-13T10:00:00Z")


def eval_item(line):
    import json
    return json.loads(line)


def spec_codes():
    """The CLI codes spec decision 46 lists for `port49 token --json`, read from the spec itself."""
    with open(os.path.join(REPO, "docs", "design", "2026-08-23-policy-engine-spec.md"), encoding="utf-8") as f:
        text = f.read()
    start = text.index("the\nCLI's codes `no_agent`")
    end = text.index("Two share a", start)
    codes = set(re.findall(r"`([a-z][a-z_]*)`", text[start:end]))
    codes.discard("per_login_mfa")  # a field of the failure, not a code
    return codes


def go_codes():
    """The fail* code constants of cmd/port49/mint.go."""
    with open(os.path.join(REPO, "cmd", "port49", "mint.go"), encoding="utf-8") as f:
        codes = set(re.findall(r'^\s*fail[A-Za-z]+\s*=\s*"([a-z_]+)"', f.read(), re.M))
    with open(os.path.join(REPO, "internal", "agent", "keyerror.go"), encoding="utf-8") as f:
        # the key codes agent.KeyCode returns
        return codes | set(re.findall(r'^\s*code[A-Z][A-Za-z]+\s*=\s*"([a-z_]+)"', f.read(), re.M))


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.err = io.StringIO()
        self.slept = []

    def agent(self, *answers, **kw):
        a = Agent(port49=fake.make(self.dir, list(answers)), stderr=self.err, **kw)
        a._sleep = self.slept.append
        return a

    def test_a_token_through_the_cli(self):
        tok = self.agent({"stdout": PERMIT}).token("leaf1", enable=True, ttl=300)
        self.assertEqual((tok.address, tok.username, tok.login, tok.enable), ("10.0.0.11", "alice", "LOGINTOKEN", "ENABLETOKEN"))
        self.assertEqual(fake.argvs(self.dir), [["token", "--json", "--enable", "--ttl", "300s", "--", "leaf1"]])

    def test_a_socket_goes_after_the_subcommand(self):
        self.agent({"stdout": PERMIT}, socket="/run/p49.sock").token("leaf1")
        self.assertEqual(fake.argvs(self.dir), [["token", "--socket", "/run/p49.sock", "--json", "--", "leaf1"]])

    def test_a_deny_is_denied_with_its_reason(self):
        a = self.agent({"stdout": fake.item(device="leaf1", verdict="deny", reason="no_grants_matched", detail="d"), "code": 1})
        with self.assertRaises(Denied) as cm:
            a.token("leaf1")
        self.assertEqual((cm.exception.reason, cm.exception.device), ("no_grants_matched", "leaf1"))

    def test_each_code_is_its_class(self):
        for code, cls in [("no_agent", NoAgent), ("agent_too_old", NoAgent), ("session_over", SessionOver),
                          ("credential_revoked", SessionOver), ("per_login_mfa_required", MFARequired),
                          ("touch_timeout", KeyUnavailable), ("key_locked", KeyUnavailable),
                          ("key_absent", KeyUnavailable), ("broker_refused", BrokerRefused),
                          ("broker_unavailable", Temporary), ("revocation_running", Temporary),
                          ("connection_changed", Temporary), ("agent_error", Port49Error)]:
            a = self.agent({"stdout": fake.item(device="leaf1", error=code, detail="words"), "code": 1})
            with self.assertRaises(cls, msg=code) as cm:
                a.token("leaf1")
            self.assertEqual(cm.exception.code, code)

    def test_every_code_the_cli_prints_has_a_class(self):
        """The spec's table and the Go constants name the codes; a code in either with no class here fails."""
        codes = spec_codes() | go_codes()
        self.assertIn("broker_unavailable", codes)  # the read found the table
        self.assertIn("touch_timeout", codes)
        # agent_error is the plain Port49Error on purpose, no_token a DeviceFault: both are decided in error_for.
        plain = {"no_token", "agent_error"}
        missing = sorted(c for c in codes if c not in client.CLASSES and c not in plain)
        self.assertIsInstance(client.error_for({"device": "d", "error": "no_token"}), DeviceFault)
        self.assertIs(type(client.error_for({"device": "d", "error": "agent_error"})), Port49Error)
        self.assertEqual(missing, [], "codes with no class in client.CLASSES")
        self.assertLessEqual(set(client.CLASSES), codes, "a class for a code the CLI does not print")
        self.assertLessEqual(client.RETRIED, set(client.CLASSES))

    def test_a_requirement_carries_what_it_accepts(self):
        a = self.agent({"stdout": fake.item(device="core1", error="per_login_mfa_required", detail="d",
                                            per_login_mfa={"accept": ["idp_mfa"], "reuse_for_seconds": 900}), "code": 1})
        with self.assertRaises(MFARequired) as cm:
            a.token("core1")
        self.assertEqual(cm.exception.requirement["accept"], ["idp_mfa"])
        self.assertIn("port49 token core1", str(cm.exception))

    def test_a_deny_for_a_second_factor_is_mfa_required(self):
        # The CLI never prints this shape from `token --json` (Task 5 gives the code instead), but a
        # workload's refused item has it: Refusal.exception() is the path (K9).
        r = Refusal("core1", "deny", "per_login_mfa_required", None, "",
                    {"accept": ["hardware_key_touch"], "reuse_for_seconds": 900})
        e = r.exception()
        self.assertIsInstance(e, MFARequired)
        self.assertEqual((e.reason, e.requirement["accept"]), ("per_login_mfa_required", ["hardware_key_touch"]))

    def test_only_what_sent_nothing_is_retried(self):
        busy = {"stdout": fake.item(device="leaf1", error="revocation_running", detail="d"), "code": 1}
        tok = self.agent(busy, busy, {"stdout": PERMIT}).token("leaf1")
        self.assertEqual(tok.login, "LOGINTOKEN")
        self.assertEqual(self.slept, [1, 2])
        with self.assertRaises(Temporary):
            self.agent(busy, busy, busy, {"stdout": PERMIT}).token("leaf1")
        self.assertEqual(len(fake.argvs(self.dir)), 3)  # bounded: attempts=3, the fourth answer never asked for
        for code, cls in [("touch_timeout", KeyUnavailable), ("key_locked", KeyUnavailable),
                          ("key_absent", KeyUnavailable), ("broker_refused", BrokerRefused),
                          ("session_over", SessionOver), ("per_login_mfa_required", MFARequired)]:
            once = {"stdout": fake.item(device="leaf1", error=code, detail="d"), "code": 1}
            with self.assertRaises(cls, msg=code):
                self.agent(once, {"stdout": PERMIT}).token("leaf1")
            self.assertEqual(len(fake.argvs(self.dir)), 1, code)
        deny = {"stdout": fake.item(device="leaf1", verdict="deny", reason="no_grants_matched"), "code": 1}
        with self.assertRaises(Denied):
            self.agent(deny, {"stdout": PERMIT}).token("leaf1")
        self.assertEqual(len(fake.argvs(self.dir)), 1)

    def test_a_broker_outage_is_retried_with_backoff(self):
        down = {"stdout": fake.item(device="leaf1", error="broker_unavailable", detail="d"), "code": 1}
        changed = {"stdout": fake.item(device="leaf1", error="connection_changed", detail="d"), "code": 1}
        self.assertEqual(self.agent(down, changed, {"stdout": PERMIT}).token("leaf1").login, "LOGINTOKEN")
        self.assertEqual(self.slept, [1, 2])
        self.slept.clear()
        with self.assertRaises(Temporary) as cm:
            self.agent(down, attempts=4).token("leaf1")
        self.assertEqual(cm.exception.code, "broker_unavailable")
        self.assertEqual(self.slept, [1, 2, 4])  # doubling, and one fewer sleep than attempts
        self.assertEqual(len(fake.argvs(self.dir)), 4)

    def test_tokens_collects_denies_and_stops_at_anything_else(self):
        deny = {"stdout": fake.item(device="leaf2", verdict="deny", reason="no_grants_matched"), "code": 1}
        res = self.agent({"stdout": PERMIT}, deny).tokens(["leaf1", "leaf2"])
        self.assertEqual((list(res.tokens), list(res.refused)), (["leaf1"], ["leaf2"]))
        self.assertEqual(res.refused["leaf2"].reason, "no_grants_matched")
        with self.assertRaises(Denied):
            res.raise_for_refused()
        with self.assertRaises(NoAgent):
            self.agent({"stdout": fake.item(device="leaf1", error="no_agent"), "code": 1}).tokens(["leaf1", "leaf2"])

    def test_tokens_collects_a_device_that_wants_a_second_factor(self):
        # One device's condition, not the run's: the other devices still get their tokens.
        mfa = {"stdout": fake.item(device="core1", error="per_login_mfa_required", detail="d",
                                   per_login_mfa={"accept": ["idp_mfa"], "reuse_for_seconds": 900}), "code": 1}
        res = self.agent(mfa, {"stdout": PERMIT}).tokens(["core1", "leaf1"])
        self.assertEqual((list(res.tokens), list(res.refused)), (["leaf1"], ["core1"]))
        with self.assertRaises(MFARequired) as cm:
            res.raise_for_refused()
        self.assertEqual(cm.exception.requirement["accept"], ["idp_mfa"])

    def test_one_device_the_broker_could_not_decide_does_not_stop_the_sweep(self):
        for code in ["device_unconfigured", "attribute_too_long", "attribute_unsafe", "broker_error", "no_token"]:
            fault = {"stdout": fake.item(device="leaf1", error=code, detail="d"), "code": 1}
            res = self.agent(fault, {"stdout": fake.item(**{**eval_item(PERMIT), "device": "leaf2"})}).tokens(["leaf1", "leaf2"])
            self.assertEqual((list(res.tokens), list(res.refused)), (["leaf2"], ["leaf1"]), code)
            self.assertEqual(res.refused["leaf1"].error, code)
            with self.assertRaises(DeviceFault) as cm:
                res.raise_for_refused()
            self.assertEqual(cm.exception.code, code)

    def test_a_stopped_sweep_keeps_what_it_minted(self):
        gone = {"stdout": fake.item(device="leaf2", error="session_over"), "code": 1}
        with self.assertRaises(SessionOver) as cm:
            self.agent({"stdout": PERMIT}, gone).tokens(["leaf1", "leaf2"])
        self.assertEqual(list(cm.exception.results.tokens), ["leaf1"])

    def test_a_traceback_with_locals_holds_no_token(self):
        import traceback
        a = self.agent({"stdout": fake.item(verdict="permit", login="LOGINTOKEN", extra=1), "code": 1})
        try:
            a.token("leaf1")
        except Port49Error as e:
            text = "".join(traceback.TracebackException(type(e), e, e.__traceback__, capture_locals=True).format())
        self.assertNotIn("LOGINTOKEN", text)

    def test_a_wrapper_that_leaves_a_grandchild_does_not_hold_the_timeout(self):
        import time
        wrap = os.path.join(self.dir, "wrap")
        with open(wrap, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nsleep 8 &\nsleep 8\n")
        os.chmod(wrap, 0o700)
        began = time.monotonic()
        with self.assertRaises(Port49Error) as cm:
            Agent(port49=wrap, stderr=self.err, timeout=0.3).token("leaf1")
        self.assertEqual(cm.exception.code, "timeout")
        self.assertLess(time.monotonic() - began, 4)

    def test_a_sink_that_takes_no_text_does_not_stall_the_run(self):
        noisy = {"stdout": PERMIT, "stderr": "x" * 300000}
        with open(os.path.join(self.dir, "sink"), "wb") as sink:
            tok = Agent(port49=fake.make(self.dir, [noisy]), stderr=sink, timeout=20).token("leaf1")
        self.assertEqual(tok.login, "LOGINTOKEN")

    def test_an_answer_larger_than_a_megabyte_is_no_answer(self):
        big = {"stdout": PERMIT.rstrip("\n")[:-1] + ', "pad": "' + "x" * (1 << 21) + '"}\n'}
        with self.assertRaises(Port49Error) as cm:
            self.agent(big).token("leaf1")
        self.assertEqual(cm.exception.code, "exit_0")

    def test_a_character_across_two_reads_is_whole(self):
        word = "€" * 5000  # 3 bytes each: a 4096-byte read splits one
        self.agent({"stdout": PERMIT, "stderr": word}).token("leaf1")
        self.assertEqual(self.err.getvalue(), word)

    def test_stderr_reaches_the_person(self):
        self.agent({"stdout": PERMIT, "stderr": "port49: touch your key now\n"}).token("leaf1")
        self.assertIn("touch your key now", self.err.getvalue())

    def test_no_token_in_repr_errors_or_a_bad_answer(self):  # Review Focus 5
        tok = self.agent({"stdout": PERMIT}).token("leaf1")
        self.assertNotIn("LOGINTOKEN", repr(tok) + str(tok))
        self.assertNotIn("ENABLETOKEN", repr(tok) + str(tok))
        a = self.agent({"stdout": "LOGINTOKEN not json", "code": 0})
        with self.assertRaises(Port49Error) as cm:
            a.token("leaf1")
        self.assertNotIn("LOGINTOKEN", str(cm.exception) + repr(cm.exception.__dict__) + repr(cm.exception))
        a = self.agent({"stdout": fake.item(device="leaf1", verdict="permit", login=""), "code": 0})
        with self.assertRaises(Port49Error):
            a.token("leaf1")
        # An answer that parses but is not an item, with a token in it.
        a = self.agent({"stdout": fake.item(verdict="permit", login="LOGINTOKEN", extra=1), "code": 1})
        with self.assertRaises(Port49Error) as cm:
            a.token("leaf1")
        self.assertNotIn("LOGINTOKEN", str(cm.exception) + repr(cm.exception.__dict__))

    def test_a_flag_shaped_device_is_a_name(self):
        self.agent({"stdout": PERMIT}).token("--socket=/tmp/x")
        self.assertEqual(fake.argvs(self.dir)[0][-2:], ["--", "--socket=/tmp/x"])

    def test_a_run_past_its_timeout_is_ended(self):
        with self.assertRaises(Port49Error) as cm:
            self.agent({"stdout": PERMIT, "sleep": 30}, timeout=0.3).token("leaf1")
        self.assertEqual(cm.exception.code, "timeout")
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_no_port49(self):
        with self.assertRaises(NotInstalled):
            Agent(port49=os.path.join(self.dir, "none"), stderr=self.err).token("leaf1")

    def test_identity(self):
        a = self.agent({"stdout": '{"principal": "user:alice", "subjects": ["netops"]}\n'})
        self.assertEqual(a.identity()["principal"], "user:alice")
        self.assertEqual(fake.argvs(self.dir), [["identity", "--json"]])


if __name__ == "__main__":
    unittest.main()
