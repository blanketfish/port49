import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class AnsibleError(Exception):
    pass


class LookupBase:
    def __init__(self, *a, **kw):
        self._opts = {}

    def set_options(self, var_options=None, direct=None):
        self._opts = dict(direct or {})

    def get_option(self, name):
        return self._opts.get(name)


WARNINGS = []


class Display:
    def warning(self, msg, *a, **kw):
        WARNINGS.append(msg)


for name, mod in {"ansible": types.ModuleType("ansible"), "ansible.errors": types.SimpleNamespace(AnsibleError=AnsibleError),
                  "ansible.utils": types.ModuleType("ansible.utils"),
                  "ansible.utils.display": types.SimpleNamespace(Display=Display),
                  "ansible.plugins": types.ModuleType("ansible.plugins"),
                  "ansible.plugins.lookup": types.SimpleNamespace(LookupBase=LookupBase)}.items():
    sys.modules[name] = mod

import importlib.util  # noqa: E402

import port49  # noqa: E402  (clients/python/src on PYTHONPATH)

# Loaded by path: the standard library's `token` is imported already (unittest
# imports traceback, which imports tokenize), so `import token` would not
# reach the plugin.
_spec = importlib.util.spec_from_file_location(
    "port49_lookup_token", os.path.join(HERE, "..", "..", "plugins", "lookup", "token.py"))
plugin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin)

TOK = port49.Token("leaf1", "10.0.0.11", "arista_eos", "alice", "LOGINTOKEN", "ENABLETOKEN")


class Calls:
    def __init__(self):
        self.agent, self.workload = [], []


class Plugin(unittest.TestCase):
    def setUp(self):
        self.calls = Calls()
        calls = self.calls

        class FakeAgent:
            def __init__(self, **kw):
                calls.agent.append(("init", kw))

            def token(self, device, enable=False, ttl=None):
                calls.agent.append(("token", device, enable, ttl))
                if device == "denied":
                    raise port49.Denied("no_grants_matched", "no grant", device, reason="no_grants_matched")
                if device == "fault":
                    raise port49.DeviceFault("device_unconfigured", "the device has no platform", device)
                return TOK

        class FakeWorkload:
            def __init__(self, *a, **kw):
                calls.workload.append(("init", a, kw))

            def tokens(self, devices=None, enable=False, ttl=None, **kw):
                calls.workload.append(("tokens", list(devices)))
                return port49.MintResults({"leaf1": TOK}, {"leaf2": port49.Refusal("leaf2", "deny", "no_grants_matched", None, "")})

        self.patches = [(plugin, "_agent", FakeAgent), (plugin, "_workload", FakeWorkload)]
        self.saved = [(o, n, getattr(o, n)) for o, n, _ in self.patches]
        for o, n, v in self.patches:
            setattr(o, n, v)

    def tearDown(self):
        for o, n, v in self.saved:
            setattr(o, n, v)
        del WARNINGS[:]

    def lookup(self, terms, **kw):
        return plugin.LookupModule().run(terms, variables={}, **kw)

    def test_the_login_token_by_default(self):
        self.assertEqual(self.lookup(["leaf1"]), ["LOGINTOKEN"])

    def test_fields(self):
        self.assertEqual(self.lookup(["leaf1"], field="username"), ["alice"])
        self.assertEqual(self.lookup(["leaf1"], field="enable", enable=True), ["ENABLETOKEN"])
        self.assertEqual(self.lookup(["leaf1"], field="all")[0]["login"], "LOGINTOKEN")
        with self.assertRaises(AnsibleError):
            self.lookup(["leaf1"], field="enable")  # no enable token asked for

    def test_workload_mode_is_one_run(self):
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["leaf1", "leaf2"], broker="https://b", broker_ca="/ca", cert="/c", key="/k")
        self.assertEqual(self.calls.workload[-1], ("tokens", ["leaf1", "leaf2"]))
        self.assertIn("leaf2", str(cm.exception))
        self.assertIn("no_grants_matched", str(cm.exception))

    def test_errors_never_carry_the_token(self):  # Review Focus 5
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["leaf1", "denied"])
        self.assertIn("no_grants_matched", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))
        # Nor does the chain: the library's exception is not kept as __cause__ or __context__.
        self.assertIsNone(cm.exception.__cause__)
        self.assertTrue(cm.exception.__suppress_context__)

    def test_half_a_workload_is_refused(self):
        with self.assertRaises(AnsibleError):
            self.lookup(["leaf1"], broker="https://b")

    def test_options_reach_the_library_and_nothing_reruns(self):
        self.lookup(["leaf1"], enable=True, ttl=120, port49="/opt/p49", socket="/run/s")
        self.assertEqual(self.calls.agent[0], ("init", {"port49": "/opt/p49", "socket": "/run/s"}))
        self.assertEqual(self.calls.agent[1], ("token", "leaf1", True, 120))
        with self.assertRaises(AnsibleError):
            self.lookup(["denied"])
        self.assertEqual(sum(1 for c in self.calls.agent if c[0] == "token"), 2)  # a deny is one call, no retry here

    def test_a_workload_deny_for_one_device_names_the_code(self):
        # The run refused leaf2: the lookup for leaf2 fails with the code.
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["leaf2"], broker="https://b", broker_ca="/ca", cert="/c", key="/k")
        self.assertIn("leaf2", str(cm.exception))
        self.assertIn("no_grants_matched", str(cm.exception))


    def test_every_error_names_its_code(self):  # I2
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["fault"])
        self.assertIn("device_unconfigured", str(cm.exception))
        self.assertIn("the device has no platform", str(cm.exception))
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["denied"])
        self.assertNotIn("[no_grants_matched]", str(cm.exception))  # already named: not repeated

    def test_the_error_is_also_a_warning(self):  # I1: ansible-core 2.16-2.18 censor a no_log failure
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["fault"])
        self.assertEqual(WARNINGS, [str(cm.exception)])
        self.assertNotIn("LOGINTOKEN", WARNINGS[0])

    def test_workload_options_alone_are_refused(self):  # m3
        for kw in ({"touch_key": "pkcs11:x"}, {"deadline": 5}, {"broker": "https://b", "broker_ca": "", "cert": "", "key": ""}):
            with self.assertRaises(AnsibleError, msg=str(kw)):
                self.lookup(["leaf1"], **kw)
        self.assertEqual(self.calls.agent, [])  # never fell back to the agent

    def test_a_device_the_answer_left_out_is_named(self):  # m4
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["leaf3"], broker="https://b", broker_ca="/ca", cert="/c", key="/k")
        self.assertIn("leaf3", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
