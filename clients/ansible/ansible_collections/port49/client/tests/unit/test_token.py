import os
import shutil
import subprocess
import sys
import tempfile
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
from port49 import hostkeys  # noqa: E402

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


class PluginCase(unittest.TestCase):
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
                if device.startswith("evil"):
                    raise port49.Denied("no_grants_matched", "d\x1b[2J", device, reason="r\x07", verdict="deny\n")
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


class Plugin(PluginCase):

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

    def test_no_control_byte_reaches_the_warning_or_the_error(self):  # a name from inventory
        evil = "evil\x1b]0;PWNED\x07\x1b[2J\n\r\x9b\x7f"
        with self.assertRaises(AnsibleError) as cm:
            self.lookup([evil])
        for text in (WARNINGS[0], str(cm.exception)):
            self.assertTrue(all(c.isprintable() for c in text), repr(text))
            self.assertIn("evil", text)
        self.assertEqual(WARNINGS[0], str(cm.exception))
        # the lookup's own errors too: a workload device name nobody answered for
        del WARNINGS[:]
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["leaf9\x1b[2J"], broker="https://b", broker_ca="/ca", cert="/c", key="/k")
        self.assertTrue(all(c.isprintable() for c in WARNINGS[0] + str(cm.exception)))

    def test_workload_options_alone_are_refused(self):  # m3
        for kw in ({"touch_key": "pkcs11:x"}, {"deadline": 5}, {"broker": "https://b", "broker_ca": "", "cert": "", "key": ""}):
            with self.assertRaises(AnsibleError, msg=str(kw)):
                self.lookup(["leaf1"], **kw)
        self.assertEqual(self.calls.agent, [])  # never fell back to the agent

    def test_a_device_the_answer_left_out_is_named(self):  # m4
        with self.assertRaises(AnsibleError) as cm:
            self.lookup(["leaf3"], broker="https://b", broker_ca="/ca", cert="/c", key="/k")
        self.assertIn("leaf3", str(cm.exception))

    def test_the_doc_names_libssh_for_host_key_auto_add(self):  # review I2, L66 (c)
        # libssh accepted a changed key under host_key_auto_add and presented the token; paramiko
        # refused it before authentication. The doc and the README must name the same ssh_type.
        readme = os.path.join(HERE, "..", "..", "README.md")
        with open(readme) as f:
            text = f.read()
        self.assertIn("Never set `host_key_auto_add` with `ansible_network_cli_ssh_type: libssh`", text)
        doc = " ".join(plugin.DOCUMENTATION.split())
        self.assertRegex(doc, r"never set it with C\(ansible_network_cli_ssh_type=libssh\)")
        self.assertNotIn("ssh_type=paramiko", doc)


NETWORK_CLI = "ansible.netcommon.network_cli"


class Undefined(Exception):
    """Not a KeyError, TypeError or AttributeError, as ansible-core's undefined-variable errors are not."""


class HostVars:
    """ansible-core 2.21.4's HostVars: `in` asks the inventory, and indexing a host outside it gives an
    undefined marker, not a KeyError, whose .get fails the template ("hostvars['srx1']")."""

    def __init__(self, hosts):
        self.hosts = hosts

    def __contains__(self, host):
        return host in self.hosts

    def __getitem__(self, host):
        if host in self.hosts:
            return self.hosts[host]
        marker = types.SimpleNamespace()
        marker.get = lambda *a: (_ for _ in ()).throw(Undefined(f"hostvars[{host!r}]"))
        return marker


ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


@unittest.skipUnless(shutil.which("ssh") and shutil.which("ssh-keygen"), "needs OpenSSH's ssh and ssh-keygen")
class HostKeys(PluginCase):
    """Plan 9f Task 2: network_cli's host keys are checked and copied before a mint (R1 to R5)."""

    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.home = os.path.join(self.dir, "home")
        os.makedirs(os.path.join(self.home, ".ssh"))
        old = os.environ.get("HOME")
        os.environ["HOME"] = self.home
        self.addCleanup(lambda: os.environ.__setitem__("HOME", old) if old is not None else os.environ.pop("HOME"))
        self.kh = os.path.join(self.home, ".ssh", "known_hosts")  # the lookup's default known_hosts_file
        self.names = os.path.join(self.dir, "port49_known_hosts")  # the first UserKnownHostsFile
        self.use_ssh_config()
        self.hostvars = {"leaf1": {"ansible_connection": NETWORK_CLI, "ansible_host": "10.0.0.11"},
                         "leaf2": {"ansible_connection": NETWORK_CLI, "ansible_host": "10.0.0.12"}}

    def use_ssh_config(self, *lines, user=None):
        # ssh reads ~/.ssh/config through the passwd home, not $HOME: the test names its own config.
        cfg = os.path.join(self.dir, "ssh_config")
        self.put(cfg, "\n".join([f"UserKnownHostsFile {user or self.names}", "GlobalKnownHostsFile /dev/null",
                                 *lines]) + "\n")
        saved = plugin._ssh_options
        plugin._ssh_options = lambda: {"ssh_config": cfg}
        self.addCleanup(setattr, plugin, "_ssh_options", saved)

    def put(self, path, text):
        with open(path, "w", encoding="ascii") as f:
            f.write(text)

    def read(self, path):
        try:
            with open(path, encoding="ascii") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def newkey(self, name, keytype="ed25519"):
        path = os.path.join(self.dir, name)
        subprocess.run(["ssh-keygen", "-q", "-t", keytype, "-N", "", "-f", path], check=True)
        return self.read(path + ".pub").split()[0] + " " + self.read(path + ".pub").split()[1]

    def run_lookup(self, terms, variables=None, **kw):
        variables = {"inventory_hostname": "leaf1", "hostvars": self.hostvars} if variables is None else variables
        return plugin.LookupModule().run(terms, variables=variables, **kw)

    def minted(self):
        return [c for c in self.calls.agent if c[0] == "token"]

    def refused(self, terms=("leaf1",), **kw):
        with self.assertRaises(AnsibleError) as cm:
            self.run_lookup(list(terms), **kw)
        self.assertEqual(WARNINGS, [str(cm.exception)])
        for text in (str(cm.exception), *WARNINGS):
            self.assertNotIn("LOGINTOKEN", text)
            self.assertNotIn("ENABLETOKEN", text)
        return str(cm.exception)

    def test_case_1_files_the_names_key_under_the_address_then_mints(self):
        self.put(self.names, f"leaf1 {ED}\n")
        self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")
        self.assertEqual(len(self.minted()), 1)

    def test_case_2_a_mismatch_refuses_before_any_mint(self):
        other = self.newkey("other")
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        said = self.refused()
        self.assertIn("[host_key_changed]", said)
        self.assertIn("leaf1", said)
        self.assertIn("10.0.0.11", said)
        self.assertIn(hostkeys.fingerprint(ED), said)
        self.assertIn(hostkeys.fingerprint(other), said)
        self.assertIn(f"ssh-keygen -R 10.0.0.11 -f {self.kh}", said)
        self.assertEqual(self.calls.agent, [])  # not even the agent was built
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {other}\n")

    def test_the_clearing_command_names_the_bracketed_entry_of_a_non_default_port(self):
        other = self.newkey("other")
        self.hostvars["leaf1"]["ansible_port"] = 830
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"[10.0.0.11]:830 {other}\n")
        self.assertIn(f"ssh-keygen -R '[10.0.0.11]:830' -f {self.kh}", self.refused())  # zsh would glob it bare

    def test_the_clearing_command_quotes_a_file_with_a_space(self):
        other = self.newkey("other")
        spaced = os.path.join(self.dir, "my known_hosts")
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(spaced, f"10.0.0.11 {other}\n")
        self.assertIn(f"-f '{spaced}'", self.refused(known_hosts_file=spaced))

    def test_case_2_a_match_mints_and_writes_nothing(self):
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {ED}\n")
        self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")

    def test_case_2_a_type_the_address_lacks_is_appended_and_only_it(self):
        ec = self.newkey("ec", "ecdsa")
        self.put(self.names, f"leaf1 {ED}\nleaf1 {ec}\n")
        self.put(self.kh, f"10.0.0.11 {ED}\n")
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n10.0.0.11 {ec}\n")

    def test_case_2_a_type_the_name_lacks_is_left_alone(self):
        ec = self.newkey("ec", "ecdsa")
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {ED}\n10.0.0.11 {ec}\n")
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n10.0.0.11 {ec}\n")
        self.assertEqual(self.read(self.names), f"leaf1 {ED}\n")

    def test_case_3_the_addresses_key_is_copied_under_the_name(self):
        self.put(self.kh, f"10.0.0.11 {ED}\n")
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.names), f"leaf1 {ED}\n")
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")
        self.assertEqual(len(self.minted()), 1)

    def test_case_4_a_first_contact_writes_nothing_and_mints(self):
        self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])
        self.assertIsNone(self.read(self.kh))
        self.assertIsNone(self.read(self.names))

    def test_a_revoked_address_key_refuses_with_no_mint(self):
        self.put(self.kh, f"10.0.0.11 {ED}\n@revoked * {ED}\n")
        self.assertIn("[host_key_revoked]", self.refused())
        self.assertEqual(self.calls.agent, [])

    def test_a_key_revoked_by_revoked_host_keys_refuses_with_no_mint(self):
        bad = self.newkey("bad")
        krl = os.path.join(self.dir, "krl")
        subprocess.run(["ssh-keygen", "-q", "-k", "-f", krl, os.path.join(self.dir, "bad.pub")], check=True)
        self.use_ssh_config(f"RevokedHostKeys {krl}")
        self.put(self.kh, f"10.0.0.11 {bad}\n")
        self.assertIn("[host_key_revoked]", self.refused())
        self.assertEqual(self.calls.agent, [])

    def test_a_revoked_key_of_the_name_is_not_copied(self):
        good = self.newkey("good", "ecdsa")
        self.put(self.names, f"leaf1 {ED}\nleaf1 {good}\n@revoked * {ED}\n")
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {good}\n")

    def test_another_connection_does_nothing_to_the_file(self):
        other = self.newkey("other")
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        for conn in ("ssh", "netconf", None):
            self.hostvars["leaf1"].pop("ansible_connection", None)
            if conn:
                self.hostvars["leaf1"]["ansible_connection"] = conn
            self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"], conn)
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {other}\n")
        self.assertEqual(self.read(self.names), f"leaf1 {ED}\n")

    def test_plain_network_cli_counts_and_the_plays_connection_is_the_fallback(self):
        self.put(self.names, f"leaf1 {ED}\n")
        self.hostvars["leaf1"]["ansible_connection"] = "network_cli"
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")
        os.remove(self.kh)
        del self.hostvars["leaf1"]["ansible_connection"]
        self.run_lookup(["leaf1"], variables={"inventory_hostname": "leaf1", "hostvars": self.hostvars,
                                              "ansible_connection": NETWORK_CLI})
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")

    def test_workload_mode_with_one_conflicting_device_mints_nothing(self):
        other = self.newkey("other")
        self.put(self.names, f"leaf1 {ED}\nleaf2 {ED}\n")
        self.put(self.kh, f"10.0.0.12 {other}\n")
        said = self.refused(("leaf1", "leaf2"), broker="https://b", broker_ca="/ca", cert="/c", key="/k")
        self.assertIn("leaf2", said)
        self.assertEqual([c for c in self.calls.workload if c[0] == "tokens"], [])
        self.assertEqual(self.calls.workload, [])  # the broker was not even built

    def test_a_non_default_port_files_the_bracketed_address(self):
        self.hostvars["leaf1"]["ansible_port"] = 830
        self.put(self.names, f"leaf1 {ED}\n")
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"[10.0.0.11]:830 {ED}\n")
        self.hostvars["leaf1"]["ansible_port"] = "830"  # a string from inventory
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"[10.0.0.11]:830 {ED}\n")

    def test_another_devices_hostvars_are_used(self):
        self.put(self.names, f"leaf2 {ED}\n")
        self.run_lookup(["leaf2"])
        self.assertEqual(self.read(self.kh), f"10.0.0.12 {ED}\n")

    def test_a_device_without_ansible_host_uses_its_name_as_the_address(self):
        self.hostvars["leaf1"].pop("ansible_host")
        self.put(self.names, f"leaf1 {ED}\n")
        self.use_ssh_config(user=self.names)
        self.run_lookup(["leaf1"], known_hosts_file=self.kh)
        self.assertEqual(self.read(self.kh), f"leaf1 {ED}\n")

    def test_the_known_hosts_file_option_names_the_addresss_file(self):
        mine = os.path.join(self.dir, "ansible_known_hosts")
        self.put(self.names, f"leaf1 {ED}\n")
        self.run_lookup(["leaf1"], known_hosts_file=mine)
        self.assertEqual(self.read(mine), f"10.0.0.11 {ED}\n")
        self.assertIsNone(self.read(self.kh))

    def test_hashed_names_are_found_and_copies_are_hashed(self):
        self.use_ssh_config("HashKnownHosts yes")
        self.put(self.names, f"{hostkeys.hashed('leaf1')} {ED}\n")
        self.run_lookup(["leaf1"])
        line = self.read(self.kh)
        self.assertTrue(line.startswith("|1|") and line.endswith(f" {ED}\n"), line)
        self.assertEqual(hostkeys.filed("10.0.0.11", [self.kh])[0], [ED])
        before = self.read(self.kh)
        self.run_lookup(["leaf1"])  # the hashed address is found again: nothing is added
        self.assertEqual(self.read(self.kh), before)

    def test_cert_authority_lines_are_not_keys_and_are_not_copied(self):
        self.put(self.names, f"@cert-authority leaf1 {ED}\n")
        self.put(self.kh, f"@cert-authority 10.0.0.11 {ED}\n")
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"@cert-authority 10.0.0.11 {ED}\n")
        self.assertEqual(self.read(self.names), f"@cert-authority leaf1 {ED}\n")

    def test_a_device_name_known_hosts_would_misread_is_refused(self):
        self.hostvars["leaf*"] = {"ansible_connection": NETWORK_CLI}
        self.assertIn("[device_name]", self.refused(("leaf*",)))
        self.assertEqual(self.calls.agent, [])

    def test_an_address_known_hosts_cannot_hold_is_refused(self):
        self.hostvars["leaf1"]["ansible_host"] = "10.0.0.11 evil"
        self.assertIn("cannot be written to known_hosts as an address", self.refused())
        self.assertEqual(self.calls.agent, [])

    def test_ansible_ssh_port_is_read_after_ansible_port(self):  # final fix round, m4
        self.put(self.names, f"leaf1 {ED}\n")
        self.hostvars["leaf1"]["ansible_ssh_port"] = 830
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"[10.0.0.11]:830 {ED}\n")
        os.remove(self.kh)
        self.hostvars["leaf1"]["ansible_port"] = 2222  # ansible_port wins
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"[10.0.0.11]:2222 {ED}\n")

    def test_a_port_that_is_not_a_number_is_refused(self):
        self.hostvars["leaf1"]["ansible_port"] = "ssh"
        self.refused()
        self.assertEqual(self.calls.agent, [])

    def test_another_device_does_not_take_the_current_hosts_address_or_port(self):  # fix round 1, I1
        del self.hostvars["leaf2"]["ansible_host"]
        self.put(self.names, f"leaf2 {ED}\n")
        self.run_lookup(["leaf2"], variables={"inventory_hostname": "leaf1", "hostvars": self.hostvars,
                                              "ansible_host": "10.0.0.11", "ansible_port": 830})
        self.assertEqual(self.read(self.kh), f"leaf2 {ED}\n")

    def test_a_device_missing_from_hostvars_is_its_name_on_port_22(self):  # fix round 1, I1
        self.put(self.names, f"leaf3 {ED}\n")
        self.run_lookup(["leaf3"], variables={"inventory_hostname": "leaf3", "hostvars": self.hostvars,
                                              "ansible_connection": NETWORK_CLI, "ansible_host": "10.0.0.11"})
        self.assertEqual(self.read(self.kh), f"leaf3 {ED}\n")

    def test_another_devices_check_does_not_use_the_current_hosts_connection(self):  # final fix round, I2
        other = self.newkey("other")
        del self.hostvars["leaf1"]["ansible_connection"]  # leaf1 gets network_cli from its own play's keyword
        self.hostvars["leaf1"]["ansible_network_os"] = "arista.eos.eos"
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        said = self.refused(variables={"inventory_hostname": "localhost", "hostvars": self.hostvars,
                                       "ansible_connection": "local"})  # a `hosts: localhost` play
        self.assertIn("[host_key_changed]", said)
        self.assertEqual(self.calls.agent, [])

    def test_a_device_that_is_not_the_current_host_with_nothing_visible_is_not_checked(self):  # final fix round, I2
        self.hostvars["leaf1"] = {"ansible_host": "10.0.0.11"}
        self.put(self.names, f"leaf1 {ED}\n")
        self.run_lookup(["leaf1"], variables={"inventory_hostname": "localhost", "hostvars": self.hostvars,
                                              "ansible_connection": NETWORK_CLI, "ansible_network_os": "eos"})
        self.assertIsNone(self.read(self.kh))

    def test_the_current_hosts_own_keywords_still_count_for_itself(self):  # final fix round, I2
        del self.hostvars["leaf1"]["ansible_connection"]
        self.put(self.names, f"leaf1 {ED}\n")
        self.run_lookup(["leaf1"], variables={"inventory_hostname": "leaf1", "hostvars": self.hostvars,
                                              "ansible_connection": NETWORK_CLI})
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")

    def test_the_plays_network_cli_beats_the_current_hosts_inventory_connection(self):  # review fix round 1, m1
        # Ansible's play vars override inventory host_vars: an inventory ssh under a play's network_cli
        # connects with network_cli, so the check must run. Any source saying network_cli counts (fail closed).
        other = self.newkey("other")
        self.hostvars["leaf1"]["ansible_connection"] = "ssh"
        self.put(self.names, f"leaf1 {ED}\nsrx1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        for hostvars in (self.hostvars, HostVars(self.hostvars)):
            with self.subTest(stub=isinstance(hostvars, HostVars)):
                WARNINGS.clear()
                said = self.refused(variables={"inventory_hostname": "leaf1", "hostvars": hostvars,
                                               "ansible_connection": NETWORK_CLI})
                self.assertIn("[host_key_changed]", said)
                WARNINGS.clear()
                said = self.refused(("srx1",), variables={"inventory_hostname": "leaf1", "hostvars": hostvars,
                                                          "ansible_connection": "network_cli"})
                self.assertIn("[host_key_uncheckable]", said)
        self.assertEqual(self.calls.agent, [])

    def test_an_untemplated_connection_is_checked(self):  # review fix round 2, r1
        # ansible-core (seen on 2.16.19 and 2.21.4) may give a lookup "{{ conn }}" unrendered: it might be network_cli, so check.
        other = self.newkey("other")
        self.put(self.names, f"leaf1 {ED}\nleaf2 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n10.0.0.12 {other}\n")
        for raw in ("{{ conn }}", "{%if x%}network_cli{%endif%}", " {{conn}}"):
            with self.subTest(raw=raw):
                self.hostvars["leaf1"].pop("ansible_connection", None)
                WARNINGS.clear()
                said = self.refused(variables={"inventory_hostname": "leaf1", "hostvars": self.hostvars,
                                               "ansible_connection": raw})
                self.assertIn("[host_key_changed]", said)
                self.hostvars["leaf2"]["ansible_connection"] = raw  # another device's own, untemplated
                WARNINGS.clear()
                self.assertIn("[host_key_changed]", self.refused(("leaf2",)))
                self.hostvars["leaf1"]["ansible_connection"] = NETWORK_CLI
        self.assertEqual(self.calls.agent, [])

    def test_the_inventorys_network_cli_still_counts_under_a_plays_other_connection(self):  # fail closed
        other = self.newkey("other")
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        said = self.refused(variables={"inventory_hostname": "leaf1", "hostvars": self.hostvars,
                                       "ansible_connection": "ssh"})
        self.assertIn("[host_key_changed]", said)
        self.assertEqual(self.calls.agent, [])

    def test_a_term_outside_the_inventory_mints_when_the_current_host_is_not_on_network_cli(self):  # L66 e2
        self.hostvars["l66a"] = {"ansible_connection": "ssh", "ansible_host": "10.0.0.13", "p49_name": "srx1"}
        self.put(self.names, f"srx1 {ED}\n")
        for hostvars in (HostVars(self.hostvars), self.hostvars):
            self.assertEqual(self.run_lookup(["srx1"], variables={"inventory_hostname": "l66a", "hostvars": hostvars,
                                                                  "ansible_connection": "ssh"}), ["LOGINTOKEN"])
        self.assertEqual(len(self.minted()), 2)
        self.assertIsNone(self.read(self.kh))

    def test_a_term_outside_the_inventory_refuses_when_the_current_host_is_on_network_cli(self):
        # The address network_cli dials is the current host's, but the term is another name: R2's address
        # (ansible_host, else the inventory name) does not exist for it, and checking nothing would hand
        # the token to whatever answers. Fail closed, before the mint.
        self.put(self.names, f"srx1 {ED}\n")
        for hostvars, play in ((HostVars(self.hostvars), {}), (self.hostvars, {}),
                               (HostVars({"leaf1": {"ansible_host": "10.0.0.11"}}), {"ansible_connection": NETWORK_CLI}),
                               (HostVars({"leaf1": {"ansible_host": "10.0.0.11"}}), {"ansible_network_os": "eos"})):
            with self.subTest(play=play, stub=isinstance(hostvars, HostVars)):
                WARNINGS.clear()
                said = self.refused(("srx1",), variables={"inventory_hostname": "leaf1", "hostvars": hostvars, **play})
                self.assertIn("[host_key_uncheckable]", said)
                self.assertIn("port49: srx1: not a host in Ansible's inventory, and leaf1 connects with network_cli", said)
        self.assertEqual(self.calls.agent, [])
        self.assertIsNone(self.read(self.kh))

    def test_an_inventory_host_is_checked_through_ansibles_hostvars(self):
        self.put(self.names, f"leaf2 {ED}\n")
        self.run_lookup(["leaf2"], variables={"inventory_hostname": "leaf1", "hostvars": HostVars(self.hostvars)})
        self.assertEqual(self.read(self.kh), f"10.0.0.12 {ED}\n")

    def test_case_3_without_a_user_known_hosts_file_warns_and_mints(self):  # fix round 1, I2
        self.use_ssh_config(user="none")
        self.put(self.kh, f"10.0.0.11 {ED}\n")
        self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])
        self.assertEqual(len(self.minted()), 1)
        self.assertEqual(len(WARNINGS), 1)
        self.assertIn("leaf1", WARNINGS[0])
        self.assertNotIn("LOGINTOKEN", WARNINGS[0])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")

    def test_case_3_into_an_unwritable_file_warns_and_mints(self):  # fix round 1, I2
        blocker = os.path.join(self.dir, "blocker")
        self.put(blocker, "")
        self.use_ssh_config(user=os.path.join(blocker, "known_hosts"))
        self.put(self.kh, f"10.0.0.11 {ED}\n")
        self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])
        self.assertEqual((len(self.minted()), len(WARNINGS)), (1, 1))

    def test_a_case_1_write_that_fails_still_refuses(self):  # only the name copy is a courtesy
        blocker = os.path.join(self.dir, "blocker")
        self.put(blocker, "")
        self.put(self.names, f"leaf1 {ED}\n")
        self.assertIn("[host_keys_not_kept]", self.refused(known_hosts_file=os.path.join(blocker, "kh")))
        self.assertEqual(self.calls.agent, [])

    def test_without_ansible_connection_a_network_os_means_network_cli(self):  # fix round 1, gating
        del self.hostvars["leaf1"]["ansible_connection"]
        self.hostvars["leaf1"]["ansible_network_os"] = "arista.eos.eos"
        self.put(self.names, f"leaf1 {ED}\n")
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")
        os.remove(self.kh)
        del self.hostvars["leaf1"]["ansible_network_os"]  # the play's network os, for a device with none of its own
        self.run_lookup(["leaf1"], variables={"inventory_hostname": "leaf1", "hostvars": self.hostvars,
                                              "ansible_network_os": "arista.eos.eos"})
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")

    def test_a_visible_other_connection_beats_a_network_os(self):  # fix round 1, gating
        other = self.newkey("other")
        self.hostvars["leaf1"].update(ansible_connection="ansible.netcommon.netconf", ansible_network_os="junipernetworks.junos.junos")
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])

    def test_no_connection_and_no_network_os_does_nothing(self):  # fix round 1, gating
        del self.hostvars["leaf1"]["ansible_connection"]
        self.put(self.names, f"leaf1 {ED}\n")
        self.run_lookup(["leaf1"])
        self.assertIsNone(self.read(self.kh))

    def test_an_address_with_two_keys_of_a_type_matches_if_one_is_the_names(self):  # fix round 2, M1
        other = self.newkey("other")
        self.put(self.names, f"leaf1 {ED}\n")
        for text in (f"10.0.0.11 {other}\n10.0.0.11 {ED}\n", f"10.0.0.11 {ED}\n10.0.0.11 {other}\n"):  # either order
            self.put(self.kh, text)
            self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])
            self.assertEqual(self.read(self.kh), text)

    def test_an_address_with_two_keys_of_a_type_refuses_if_none_is_the_names(self):  # fix round 2, M1
        a, b = self.newkey("a"), self.newkey("b")
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {a}\n10.0.0.11 {b}\n")
        self.assertIn("[host_key_changed]", self.refused())

    def test_a_revoked_line_for_the_address_in_another_ssh_file_refuses(self):  # fix round 2, M2
        extra = os.path.join(self.dir, "global_known_hosts")
        self.put(extra, f"@revoked 10.0.0.11 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {ED}\n")
        self.use_ssh_config(user=self.names)
        cfg = os.path.join(self.dir, "ssh_config")
        self.put(cfg, f"UserKnownHostsFile {self.names}\nGlobalKnownHostsFile {extra}\n")
        self.assertIn("[host_key_revoked]", self.refused())
        self.assertEqual(self.calls.agent, [])

    def alias(self, *extra):
        self.use_ssh_config("Host leaf1", "HostKeyAlias corp-leaf1", *extra)

    def test_a_host_key_alias_keys_are_the_names_keys(self):  # final fix round, I1
        other = self.newkey("other")
        self.alias()
        self.put(self.names, f"corp-leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        self.assertIn("[host_key_changed]", self.refused())
        self.assertEqual(self.calls.agent, [])
        self.put(self.kh, "")
        self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])  # filed under the alias: copied to the address
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")
        self.assertEqual(self.read(self.names), f"corp-leaf1 {ED}\n")  # nothing filed under the bare name

    def test_a_name_and_its_alias_that_disagree_refuse_naming_both(self):  # final fix round, I1
        other = self.newkey("other")
        self.alias()
        self.put(self.names, f"leaf1 {ED}\ncorp-leaf1 {other}\n")
        said = self.refused()
        self.assertIn("[host_key_changed]", said)
        for text in ("leaf1", "corp-leaf1", hostkeys.fingerprint(ED), hostkeys.fingerprint(other)):
            self.assertIn(text, said)
        self.assertEqual(self.calls.agent, [])
        self.assertIsNone(self.read(self.kh))

    def test_a_name_and_its_alias_that_agree_mint(self):  # final fix round, I1
        self.alias()
        self.put(self.names, f"leaf1 {ED}\ncorp-leaf1 {ED}\n")
        self.assertEqual(self.run_lookup(["leaf1"]), ["LOGINTOKEN"])
        self.assertEqual(self.read(self.kh), f"10.0.0.11 {ED}\n")

    def test_case_3_with_an_alias_files_the_copy_under_the_port49_name(self):  # final fix round, I1
        self.alias()
        self.put(self.kh, f"10.0.0.11 {ED}\n")
        self.run_lookup(["leaf1"])
        self.assertEqual(self.read(self.names), f"leaf1 {ED}\n")

    def test_a_known_hosts_command_refuses_before_any_mint(self):  # final fix round, I1
        self.use_ssh_config("KnownHostsCommand /bin/true %H")
        said = self.refused()
        self.assertIn("[host_key_uncheckable]", said)
        self.assertIn("KnownHostsCommand", said)
        self.assertIn("leaf1", said)
        self.assertEqual(self.calls.agent, [])

    def test_an_alias_known_hosts_would_misread_is_refused(self):  # final fix round, I1
        self.use_ssh_config("Host leaf1", "HostKeyAlias corp,leaf1")
        self.assertIn("[host_key_uncheckable]", self.refused())
        self.assertEqual(self.calls.agent, [])

    def test_a_name_whose_only_key_is_revoked_refuses_naming_the_device(self):  # final fix round, m1
        other = self.newkey("other")
        self.put(self.names, f"leaf1 {ED}\n@revoked * {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        said = self.refused()
        self.assertIn("[host_key_revoked]", said)
        self.assertIn("leaf1", said)
        self.assertEqual(self.calls.agent, [])
        self.assertEqual(self.read(self.names), f"leaf1 {ED}\n@revoked * {ED}\n")

    def test_the_revoked_refusal_names_the_key_and_the_clearing_command(self):  # final fix round, m3
        self.put(self.kh, f"10.0.0.11 {ED}\n@revoked * {ED}\n")
        said = self.refused()
        self.assertIn(hostkeys.fingerprint(ED), said)
        self.assertIn(f"ssh-keygen -R 10.0.0.11 -f {self.kh}", said)

    def test_an_address_known_hosts_would_read_as_a_pattern_is_an_address_error(self):  # final fix round, m2
        for bad in ("a,b", "a*", "a?", "!a", "@a", "|a"):
            del WARNINGS[:]
            self.hostvars["leaf1"]["ansible_host"] = bad
            said = self.refused()
            self.assertIn("cannot be written to known_hosts as an address", said, bad)
            self.assertNotIn("port49 takes devices named", said, bad)
            self.assertIn("leaf1", said)
        self.assertEqual(self.calls.agent, [])

    def test_no_output_carries_the_token(self):
        other = self.newkey("other")
        self.put(self.names, f"leaf1 {ED}\n")
        self.put(self.kh, f"10.0.0.11 {other}\n")
        self.refused()
        for path in (self.kh, self.names):
            self.assertNotIn("LOGINTOKEN", self.read(path))


if __name__ == "__main__":
    unittest.main()
