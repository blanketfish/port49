import copy
import io
import json
import os
import pickle
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import fakeport49 as fake  # noqa: E402
from port49 import BrokerRefused, Final, MFARequired, Port49Error, Temporary, Workload  # noqa: E402

TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")


def golden(name):
    """The CLI's own stdout, as Task 6's Go tests check it byte for byte (pre-flight I3)."""
    with open(os.path.join(TESTDATA, name), encoding="utf-8") as f:
        return f.read()


MINTED = {"principal": "spiffe://corp/oxidized", "results": [
    {"device": "leaf1", "verdict": "permit", "address": "10.0.0.11", "platform": "arista_eos",
     "username": "svc", "login": "LOGINTOKEN", "expires_at": "2026-10-13T10:00:00Z"}],
    "refused": [{"device": "leaf2", "verdict": "deny", "reason": "no_grants_matched"},
                {"device": "core1", "verdict": "deny", "reason": "per_login_mfa_required",
                 "per_login_mfa": {"accept": ["hardware_key_touch"], "reuse_for_seconds": 900}}]}


def permit(device, token):
    return {"device": device, "verdict": "permit", "address": "10.0.0.9", "platform": "arista_eos", "username": "svc",
            "login": token, "expires_at": "2026-10-13T10:00:00Z"}


def stopped(code, left, minted=(), denied=()):
    """A stopped run as Task 6's stopOf prints it: the unminted devices in refused under the stopping code."""
    return json.dumps({"principal": "p", "subject": "s", "results": [permit(d, "TOK-" + d) for d in minted],
                       "refused": [{"device": d, "verdict": "deny", "reason": "no_grants_matched"} for d in denied] +
                                  [{"device": d, "error": code, "detail": "fixed words"} for d in left],
                       "stopped": code})


class WorkloadTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.err = io.StringIO()
        self.slept = []

    def workload(self, *answers, **kw):
        w = Workload("https://broker:8443", "/ca.pem", "/w.pem", "/w.key", port49=fake.make(self.dir, list(answers)),
                     stderr=self.err, **kw)
        w._sleep = self.slept.append
        return w

    def test_devices_go_in_a_file_and_results_come_back_per_item(self):
        res = self.workload({"stdout": json.dumps(MINTED), "code": 1}).tokens(["leaf1", "leaf2", "core1"], purpose="backup")
        self.assertEqual(res.tokens["leaf1"].login, "LOGINTOKEN")
        self.assertEqual(res.refused["leaf2"].reason, "no_grants_matched")
        self.assertEqual(res.refused["core1"].per_login_mfa["accept"], ["hardware_key_touch"])
        self.assertIsInstance(res.refused["core1"].exception(), MFARequired)  # as Agent raises it (M7)
        argv = fake.argvs(self.dir)[0]
        self.assertEqual(argv[:2], ["workload", "token"])
        self.assertIn("--devices-file", argv)
        self.assertEqual(argv[argv.index("--format") + 1], "json")
        self.assertNotIn("leaf1", argv)  # names travel in the file, never a flag
        self.assertEqual(fake.device_files(self.dir), [["leaf1", "leaf2", "core1"]])

    def test_a_scope(self):
        self.workload({"stdout": json.dumps(MINTED)}).tokens(scope="core")
        argv = fake.argvs(self.dir)[0]
        self.assertEqual(argv[argv.index("--scope") + 1], "core")

    def test_devices_or_a_scope_not_both_not_neither_not_none(self):
        w = self.workload({"stdout": json.dumps(MINTED)})
        for kw in [{}, {"devices": ["a"], "scope": "s"}, {"devices": []}, {"devices": ["a\nb"]}]:
            with self.assertRaises(ValueError, msg=str(kw)):
                w.tokens(**kw)
        self.assertEqual(fake.argvs(self.dir), [])

    def test_every_device_denied_is_results_not_an_exception(self):
        res = self.workload({"stdout": golden("workload_every_device_denied.json"), "code": 77}).tokens(["fw1"])
        self.assertEqual((res.tokens, list(res.refused)), ({}, ["fw1"]))
        self.assertEqual(res.refused["fw1"].reason, "no_grants_matched")

    def test_a_scope_selecting_nothing_is_empty(self):
        res = self.workload({"stdout": golden("workload_empty_sweep.json"), "code": 77}).tokens(scope="none")
        self.assertEqual((res.tokens, res.refused), ({}, {}))

    def test_a_null_list_is_an_empty_one(self):  # a CLI before Task 6's fix printed "results": null
        res = self.workload({"stdout": '{"principal": "p", "results": null, "refused": null}', "code": 77}).tokens(["x"])
        self.assertEqual((res.tokens, res.refused), ({}, {}))

    def test_75_is_temporary_with_what_was_minted(self):
        with self.assertRaises(Temporary) as cm:
            self.workload({"stdout": json.dumps(MINTED), "code": 75}).tokens(["leaf1", "leaf9"])
        self.assertIn("leaf1", cm.exception.results.tokens)
        self.assertEqual(len(fake.argvs(self.dir)), 1)  # no "stopped" to say what is left: never rerun

    def test_77_with_no_answer_is_final(self):
        with self.assertRaises(Final) as cm:
            self.workload({"stderr": "port49 workload token: the certificate expired at …\n", "code": 77}).tokens(["leaf1"])
        self.assertIn("certificate expired", str(cm.exception))
        self.assertEqual(len(fake.argvs(self.dir)), 1)

    def test_flags_reach_the_cli(self):
        self.workload({"stdout": json.dumps(MINTED)}, touch_key="pkcs11:id=%02", deadline=120, broker_crl="require"
                      ).tokens(["leaf1"], enable=True, ttl=600)
        argv = fake.argvs(self.dir)[0]
        for flag, value in [("--touch-key", "pkcs11:id=%02"), ("--deadline", "120s"), ("--broker-crl", "require"),
                            ("--ttl", "600s")]:
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--enable", argv)

    def test_no_token_in_errors(self):
        with self.assertRaises(Port49Error) as cm:
            self.workload({"stdout": "LOGINTOKEN{", "code": 0}).tokens(["leaf1"])
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_identity(self):
        obj = {"principal": "spiffe://corp/oxidized", "method": "cert", "subject": "svc"}
        self.assertEqual(self.workload({"stdout": json.dumps(obj)}).identity(), obj)
        argv = fake.argvs(self.dir)[0]
        self.assertEqual(argv[:2], ["workload", "identity"])
        self.assertIn("--json", argv)

    def test_identity_that_cannot_be_had_is_the_codes_class(self):
        with self.assertRaises(Final):
            self.workload({"stderr": "port49 workload identity: the broker answered 403\n", "code": 77}).identity()
        with self.assertRaises(Temporary):
            self.workload({"stderr": "port49 workload identity: no answer\n", "code": 75}).identity()
        with self.assertRaises(Port49Error) as cm:
            self.workload({"stderr": "port49 workload identity: bad flag\n", "code": 2}).identity()
        self.assertNotIsInstance(cm.exception, (Final, Temporary))

    # A run that stopped never returns normally (the controller's ruling on decision 46 ruling 10).

    def test_a_stopped_run_raises_the_class_of_its_code_with_what_was_minted(self):
        for code, exit_code, cls in [("broker_unavailable", 75, Temporary), ("connection_changed", 75, Temporary),
                                     ("broker_refused", 77, BrokerRefused)]:
            with self.assertRaises(cls, msg=code) as cm:
                self.workload({"stdout": stopped(code, ["leaf2"], minted=["leaf1"], denied=["fw1"]),
                               "code": exit_code}, attempts=1).tokens(["fw1", "leaf1", "leaf2"])
            e = cm.exception
            self.assertEqual(e.code, code)
            self.assertEqual(list(e.results.tokens), ["leaf1"], code)
            self.assertEqual(e.results.tokens["leaf1"].login, "TOK-leaf1")
            self.assertEqual(sorted(e.results.refused), ["fw1", "leaf2"], code)  # the left are named
            self.assertNotIn("TOK-leaf1", str(e) + repr(e) + repr(e.args))

    def test_a_stopped_run_with_the_agent_code_is_a_port49_error(self):
        with self.assertRaises(Port49Error) as cm:
            self.workload({"stdout": stopped("agent_error", ["leaf2"], minted=["leaf1"]), "code": 1},
                          attempts=3).tokens(["leaf1", "leaf2"])
        self.assertEqual(cm.exception.code, "agent_error")
        self.assertEqual(list(cm.exception.results.tokens), ["leaf1"])
        self.assertEqual(len(fake.argvs(self.dir)), 1)  # not Temporary: not run again

    def test_a_stopped_run_is_an_error_whatever_the_exit_code(self):
        with self.assertRaises(Temporary):
            self.workload({"stdout": stopped("broker_unavailable", ["leaf1"]), "code": 0}, attempts=1).tokens(["leaf1"])

    def test_a_stopped_run_with_an_unknown_code_is_a_port49_error(self):
        with self.assertRaises(Port49Error) as cm:
            self.workload({"stdout": stopped("something_new", ["leaf1"]), "code": 1}, attempts=1).tokens(["leaf1"])
        self.assertNotIsInstance(cm.exception, (Temporary, Final))
        self.assertEqual(cm.exception.code, "something_new")

    def test_a_stopped_scope_sweep_raises_though_it_names_nothing_left(self):
        out = json.dumps({"principal": "p", "results": [permit("leaf1", "TOK-leaf1")], "refused": [],
                          "stopped": "broker_refused"})
        with self.assertRaises(BrokerRefused) as cm:
            self.workload({"stdout": out, "code": 1}, attempts=1).tokens(scope="dc")
        self.assertEqual(list(cm.exception.results.tokens), ["leaf1"])

    def test_a_stopped_runs_error_pickles_and_copies_without_its_tokens(self):
        with self.assertRaises(Temporary) as cm:
            self.workload({"stdout": stopped("broker_unavailable", ["leaf2"], minted=["leaf1"]), "code": 75},
                          attempts=1).tokens(["leaf1", "leaf2"])
        for e in (pickle.loads(pickle.dumps(cm.exception)), copy.deepcopy(cm.exception), copy.copy(cm.exception)):
            self.assertEqual(e.results.tokens, {"leaf1": None})
            self.assertEqual(e.code, "broker_unavailable")
        self.assertEqual(cm.exception.results.tokens["leaf1"].login, "TOK-leaf1")  # the original keeps its own

    # Retries: only Temporary, only what can be run again without minting twice.

    def test_a_retry_of_a_stopped_named_sweep_mints_only_the_unminted(self):
        w = self.workload({"stdout": stopped("broker_unavailable", ["leaf2", "leaf3"], minted=["leaf1"], denied=["fw1"]),
                           "code": 75},
                          {"stdout": json.dumps({"principal": "p", "results": [permit("leaf2", "TOK-leaf2"),
                                                                              permit("leaf3", "TOK-leaf3")],
                                                 "refused": []}), "code": 0})
        res = w.tokens(["fw1", "leaf1", "leaf2", "leaf3"])
        self.assertEqual(fake.device_files(self.dir), [["fw1", "leaf1", "leaf2", "leaf3"], ["leaf2", "leaf3"]])
        self.assertEqual(sorted(res.tokens), ["leaf1", "leaf2", "leaf3"])
        self.assertEqual(list(res.refused), ["fw1"])  # the first run's deny stands; no stale "left" entries
        self.assertEqual(self.slept, [1])

    def test_a_retry_that_stops_again_raises_with_everything_so_far(self):
        w = self.workload({"stdout": stopped("connection_changed", ["leaf2", "leaf3"], minted=["leaf1"]), "code": 75},
                          {"stdout": stopped("connection_changed", ["leaf3"], minted=["leaf2"]), "code": 75},
                          attempts=2)
        with self.assertRaises(Temporary) as cm:
            w.tokens(["leaf1", "leaf2", "leaf3"])
        self.assertEqual(fake.device_files(self.dir), [["leaf1", "leaf2", "leaf3"], ["leaf2", "leaf3"]])
        self.assertEqual(sorted(cm.exception.results.tokens), ["leaf1", "leaf2"])
        self.assertEqual(list(cm.exception.results.refused), ["leaf3"])

    def test_attempts_are_bounded_and_back_off(self):
        w = self.workload({"stdout": stopped("broker_unavailable", ["leaf1"]), "code": 75}, attempts=4)
        with self.assertRaises(Temporary):
            w.tokens(["leaf1"])
        self.assertEqual(len(fake.argvs(self.dir)), 4)
        self.assertEqual(self.slept, [1, 2, 4])

    def test_a_run_that_sent_nothing_is_retried(self):
        w = self.workload({"stderr": "port49 workload token: cannot reach the broker\n", "code": 75},
                          {"stdout": json.dumps(MINTED), "code": 1})
        self.assertEqual(sorted(w.tokens(["leaf1", "leaf2", "core1"]).tokens), ["leaf1"])
        self.assertEqual(len(fake.argvs(self.dir)), 2)

    def test_a_scope_sweep_that_sent_nothing_is_retried_whole(self):
        w = self.workload({"stderr": "no answer\n", "code": 75}, {"stdout": json.dumps(MINTED), "code": 1})
        w.tokens(scope="core")
        self.assertEqual(len(fake.argvs(self.dir)), 2)

    def test_a_scope_sweep_that_minted_before_it_stopped_is_not_rerun(self):
        # It cannot name what it left, and a rerun would mint the first page again.
        out = json.dumps({"principal": "p", "results": [permit("leaf1", "TOK-leaf1")], "refused": [],
                          "stopped": "broker_unavailable"})
        with self.assertRaises(Temporary) as cm:
            self.workload({"stdout": out, "code": 75}).tokens(scope="dc")
        self.assertEqual(len(fake.argvs(self.dir)), 1)
        self.assertEqual(list(cm.exception.results.tokens), ["leaf1"])

    def test_nothing_final_is_retried(self):
        for ans in [{"stderr": "x\n", "code": 77}, {"stderr": "x\n", "code": 2}, {"stderr": "x\n", "code": 1},
                    {"stdout": stopped("broker_refused", ["leaf1"]), "code": 77}]:
            self.dir = tempfile.mkdtemp()
            with self.assertRaises(Port49Error):
                self.workload(ans).tokens(["leaf1"])
            self.assertEqual(len(fake.argvs(self.dir)), 1, ans)
        self.assertEqual(self.slept, [])

    def test_no_token_in_a_retried_runs_errors(self):
        w = self.workload({"stdout": stopped("broker_unavailable", ["leaf2"], minted=["leaf1"]), "code": 75},
                          {"stdout": "TOK-leaf2 not json", "code": 0})
        with self.assertRaises(Port49Error) as cm:
            w.tokens(["leaf1", "leaf2"])
        text = str(cm.exception) + repr(cm.exception) + repr(cm.exception.args)
        self.assertNotIn("TOK-", text)


if __name__ == "__main__":
    unittest.main()
