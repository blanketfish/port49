"""The lookup under a real ansible-core, against a fake port49 CLI.

Skipped unless PORT49_TEST_ANSIBLE_PLAYBOOK names an ansible-playbook (a throwaway venv's;
`make test` needs no Ansible). The network_cli case also needs ansible.netcommon, found in that
venv or under PORT49_TEST_ANSIBLE_COLLECTIONS (a collections path), and is skipped without it
(failed, when that variable is set).
The run uses a temporary HOME, and nss_wrapper (libnss-wrapper) gives the user a passwd entry with that
same home: libssh, which network_cli uses when ansible-pylibssh is installed, takes its home from the
passwd entry, not $HOME, so without the wrapper it would read the operator's ~/.ssh. A test that needs
the wrapper is skipped without it (failed when PORT49_TEST_ANSIBLE_COLLECTIONS is set, as in CI), and
checks, before running Ansible, that the interpreter sees the private home. Keys are never looked for.
"""
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTIONS = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))  # clients/ansible
LIBRARY = os.path.abspath(os.path.join(COLLECTIONS, "..", "python", "src"))
README = os.path.abspath(os.path.join(HERE, "..", "..", "README.md"))
PLAYBOOK = os.environ.get("PORT49_TEST_ANSIBLE_PLAYBOOK")
EXTRA_COLLECTIONS = os.environ.get("PORT49_TEST_ANSIBLE_COLLECTIONS", "")

LOGIN, ENABLE = "REALLOGINTOKEN-7f3a", "REALENABLETOKEN-91c2"

# A port49 that permits leaf1, denies denied1, and has an MFA-asking mfa1; the token never in argv.
FAKE = """#!{python}
import json, sys
a = sys.argv[1:]
if "--" not in a:
    sys.exit(2)
device = a[a.index("--") + 1]
with open({log!r}, "a") as f:
    f.write(json.dumps(a) + "\\n")
if device == "denied1":
    print(json.dumps({{"device": device, "verdict": "deny", "reason": "no_grants_matched", "detail": "no grant"}}))
    sys.exit(1)
print(json.dumps({{"device": device, "verdict": "permit", "address": "10.0.0.11", "platform": "arista_eos",
                   "username": "alice", "login": {login!r}, "enable": {enable!r}, "expires_at": "2026-10-13T10:00:00Z"}}))
"""

INVENTORY = """all:
  hosts:
    leaf1: {ansible_connection: local}
    denied1: {ansible_connection: local}
"""

PLAY = """- hosts: all
  gather_facts: false
  tasks:
    - name: mint
      ansible.builtin.set_fact:
        port49: "{{{{ lookup('port49.client.token', inventory_hostname, field='all', enable=true, port49='{fake}') }}}}"
      no_log: {no_log}
    - name: use it
      ansible.builtin.debug:
        msg: "login is {{{{ port49.login | length }}}} long, user {{{{ port49.username }}}}"
"""


NSS_LIB = next((p for p in ("/usr/lib/x86_64-linux-gnu/libnss_wrapper.so", "/usr/lib/aarch64-linux-gnu/libnss_wrapper.so",
                             "/usr/lib/libnss_wrapper.so", "/usr/lib64/libnss_wrapper.so") if os.path.exists(p)), None)


def private_env(tmp):
    """The environment of every command here: HOME in tmp, and (when libnss-wrapper is installed) a passwd
    entry whose home is the same directory, so libssh does not reach the operator's ~/.ssh."""
    home = os.path.join(tmp, "home")
    os.makedirs(home, exist_ok=True)
    collections = COLLECTIONS + (":" + EXTRA_COLLECTIONS if EXTRA_COLLECTIONS else "")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": home, "ANSIBLE_HOME": os.path.join(home, ".ansible"),
           "ANSIBLE_COLLECTIONS_PATH": collections, "PYTHONPATH": LIBRARY, "ANSIBLE_NOCOLOR": "1",
           "ANSIBLE_LOCAL_TEMP": os.path.join(tmp, "local"), "ANSIBLE_FORKS": "2",
           # network_cli's socket lives here; a long TMPDIR would pass AF_UNIX's limit.
           "ANSIBLE_PERSISTENT_CONTROL_PATH_DIR": os.path.join(tmp, "pc"),
           # Neither client may offer a key of the operator's.
           "ANSIBLE_LIBSSH_LOOK_FOR_KEYS": "False", "ANSIBLE_PARAMIKO_LOOK_FOR_KEYS": "False",
           "PYTHONDONTWRITEBYTECODE": "1"}
    if NSS_LIB:
        uid, gid = os.getuid(), os.getgid()
        passwd, group = os.path.join(tmp, "nss_passwd"), os.path.join(tmp, "nss_group")
        with open(passwd, "w", encoding="utf-8") as f:
            f.write("root:x:0:0:root:/root:/bin/sh\n" + (f"test:x:{uid}:{gid}:test:{home}:/bin/sh\n" if uid else ""))
        with open(group, "w", encoding="utf-8") as f:
            f.write("root:x:0:\n" + (f"test:x:{gid}:\n" if gid else ""))
        env.update({"LD_PRELOAD": NSS_LIB, "NSS_WRAPPER_PASSWD": passwd, "NSS_WRAPPER_GROUP": group})
    return env


def run(tmp, *argv):
    """Run an Ansible command under a HOME inside tmp; returns (exit code, stdout and stderr)."""
    env = private_env(tmp)
    # Through a pipe: ansible refuses a non-blocking stderr.
    ran = subprocess.run(list(argv), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, timeout=120, cwd=tmp)
    return ran.returncode, ran.stdout


@unittest.skipUnless(PLAYBOOK and os.path.exists(PLAYBOOK), "set PORT49_TEST_ANSIBLE_PLAYBOOK to run under real ansible-core")
class RealAnsible(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="port49-ansible-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.log = os.path.join(self.tmp, "argv.log")
        self.fake = os.path.join(self.tmp, "port49")
        with open(self.fake, "w", encoding="utf-8") as f:
            f.write(FAKE.format(python=sys.executable, log=self.log, login=LOGIN, enable=ENABLE))
        os.chmod(self.fake, stat.S_IRWXU)
        with open(os.path.join(self.tmp, "inv.yml"), "w", encoding="utf-8") as f:
            f.write(INVENTORY)

    def play(self, no_log, *flags):
        path = os.path.join(self.tmp, "play.yml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(PLAY.format(fake=self.fake, no_log="true" if no_log else "false"))
        return run(self.tmp, PLAYBOOK, "-i", os.path.join(self.tmp, "inv.yml"), path, *flags)

    def test_the_token_is_in_no_output_at_any_verbosity(self):
        for flags in ((), ("-v",), ("-vvv",), ("-vvvvv",)):
            code, out = self.play(True, *flags)
            self.assertNotIn(LOGIN, out, flags)
            self.assertNotIn(ENABLE, out, flags)
        with open(self.log, encoding="utf-8") as f:
            self.assertNotIn(LOGIN, f.read())  # nor in the CLI's argv

    def test_the_token_reaches_the_play(self):
        code, out = self.play(True)
        self.assertIn(f"login is {len(LOGIN)} long, user alice", out)

    def test_a_no_log_failure_still_shows_the_code(self):
        # ansible-core 2.16 to 2.18 censor a failed no_log task's message: the lookup's warning carries the code.
        code, out = self.play(True)
        self.assertNotEqual(code, 0)
        self.assertIn("no_grants_matched", out)
        self.assertNotIn(LOGIN, out)

    def test_a_deny_fails_that_host_only_and_names_the_code(self):
        code, out = self.play(False)
        self.assertNotEqual(code, 0)
        self.assertIn("login is", out)  # leaf1 went on to use its token
        self.assertIn("denied1", out)
        self.assertIn("no_grants_matched", out)
        recap = out.split("PLAY RECAP")[1]
        leaf = [l for l in recap.splitlines() if l.startswith("leaf1")][0]
        denied = [l for l in recap.splitlines() if l.startswith("denied1")][0]
        self.assertIn("failed=0", leaf)
        self.assertIn("failed=1", denied)

    def test_a_port49_name_outside_the_inventory_mints(self):  # L66 e2's shape: an alias for the inventory name
        with open(os.path.join(self.tmp, "inv.yml"), "w", encoding="utf-8") as f:
            f.write("all:\n  hosts:\n    l66a: {ansible_connection: local, p49_name: leaf1}\n")
        path = os.path.join(self.tmp, "play.yml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(PLAY.format(fake=self.fake, no_log="true").replace("inventory_hostname", "p49_name"))
        code, out = run(self.tmp, PLAYBOOK, "-i", os.path.join(self.tmp, "inv.yml"), path)
        self.assertNotIn("Error while resolving", out)  # ansible-core 2.21: hostvars['leaf1'] was undefined
        self.assertIn(f"login is {len(LOGIN)} long, user alice", out)
        self.assertEqual(code, 0, out)


# The README's "mint once per host per play" play stands; its tasks are replaced by two that need no
# device: one that templates the connection variables, and one that connects to a closed port.
NETWORK_TASKS = """  tasks:
    - name: the fact reaches the connection variables
      ansible.builtin.debug:
        msg: "user {{ ansible_user }}"
    - name: the next task connects
      ansible.netcommon.cli_command:
        command: show version
      no_log: true
"""


def readme_play(fake):
    """The README's mint-once play, split into (the play up to `vars:`, the vars lines), the mint
    pointed at the fake port49."""
    with open(README, encoding="utf-8") as f:
        section = f.read().split("## Use: mint once per host per play", 1)[1]
    play = re.search(r"```yaml\n(.*?)```", section, re.S).group(1)
    if play.count("enable=true)") != 1 or "  vars:\n" not in play or "  tasks:\n" not in play:
        raise AssertionError("the README's mint-once play changed shape; update readme_play")
    play = play.replace("enable=true)", f"enable=true, port49='{fake}')")
    head, rest = play.split("  vars:\n", 1)
    return head, rest.split("  tasks:\n", 1)[0]


def closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(PLAYBOOK and os.path.exists(PLAYBOOK), "set PORT49_TEST_ANSIBLE_PLAYBOOK to run under real ansible-core")
class RealAnsibleNetworkCLI(unittest.TestCase):
    """Under network_cli, ansible-core templates ansible_user into the remote_user keyword for every
    task, the mint's set_fact included, before the fact exists (2.21.4: "Error processing keyword
    'remote_user': 'port49' is undefined"). The README's play must survive that, with its connection
    variables in the play's vars or in inventory."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="port49-ansible-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # network_cli loads the play's network OS at the mint's set_fact, so both are needed.
        code, out = run(self.tmp, os.path.join(os.path.dirname(PLAYBOOK), "ansible-galaxy"), "collection", "list",
                        "--format", "json")
        try:
            found = set().union(*json.loads(out[out.find("{"):]).values())
        except (ValueError, TypeError):
            found = set()
        missing = {"ansible.netcommon", "arista.eos"} - found
        if code != 0 or missing:
            why = f"{', '.join(sorted(missing)) or 'ansible-galaxy'} not found"
            if EXTRA_COLLECTIONS:  # named, so expected: CI must not pass on a skip
                self.fail(f"{why} under PORT49_TEST_ANSIBLE_COLLECTIONS")
            self.skipTest(f"{why}; set PORT49_TEST_ANSIBLE_COLLECTIONS")
        # libssh takes its home from the passwd entry: prove the private home is it before connecting.
        if not NSS_LIB:
            if EXTRA_COLLECTIONS:
                self.fail("libnss-wrapper is not installed: libssh would read the operator's ~/.ssh")
            self.skipTest("libnss-wrapper is not installed: libssh would read the operator's ~/.ssh")
        code, out = run(self.tmp, sys.executable, "-I", "-B", "-c", "import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)")
        if code != 0 or out.strip() != os.path.join(self.tmp, "home"):
            self.fail(f"under nss_wrapper the passwd home is {out.strip()!r}, not the private home; nothing is run")
        self.log = os.path.join(self.tmp, "argv.log")
        self.fake = os.path.join(self.tmp, "port49")
        with open(self.fake, "w", encoding="utf-8") as f:
            f.write(FAKE.format(python=sys.executable, log=self.log, login=LOGIN, enable=ENABLE))
        os.chmod(self.fake, stat.S_IRWXU)

    def play(self, in_inventory):
        head, vars_lines = readme_play(self.fake)
        host = f"          ansible_host: 127.0.0.1\n          ansible_port: {closed_port()}\n" \
               "          ansible_connect_timeout: 5\n          ansible_command_timeout: 10\n"
        if in_inventory:  # the L66 harness's shape: the connection variables are the host's
            host += "".join("      " + line + "\n" for line in vars_lines.splitlines() if line.strip())
            play = head + NETWORK_TASKS
        else:
            play = head + "  vars:\n" + vars_lines + NETWORK_TASKS
        inventory = "all:\n  children:\n    leaves:\n      hosts:\n        leaf1:\n" + host
        for name, text in (("inv.yml", inventory), ("play.yml", play)):
            with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as f:
                f.write(text)
        return run(self.tmp, PLAYBOOK, "-i", os.path.join(self.tmp, "inv.yml"), os.path.join(self.tmp, "play.yml"))

    def test_the_mint_once_play_templates_its_connection_from_the_fact(self):
        for in_inventory in (False, True):
            with self.subTest(in_inventory=in_inventory):
                code, out = self.play(in_inventory)
                self.assertNotIn("is undefined", out)
                self.assertIn("user alice", out)  # the fact reached ansible_user
                self.assertIn("TASK [the next task connects]", out)
                recap = out.split("PLAY RECAP")[1]
                self.assertRegex(recap, r"leaf1\s*:\s*ok=2\s.*failed=1")  # the closed port, not the mint
                self.assertNotIn(LOGIN, out)
                self.assertNotIn(ENABLE, out)
        with open(self.log, encoding="utf-8") as f:
            self.assertEqual(len(f.readlines()), 2)  # one mint per run

    def mismatched_run(self, host_lines, vars_lines):
        """Run the README's play against leaf1 at a closed port, with a key filed under leaf1 and another under
        its address, so a check that runs refuses host_key_changed before any mint."""
        head, _ = readme_play(self.fake)
        port = closed_port()
        keys = []
        for name in ("name_key", "addr_key"):
            path = os.path.join(self.tmp, name)
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True,
                           stdout=subprocess.DEVNULL)
            with open(path + ".pub", encoding="ascii") as f:
                keys.append(" ".join(f.read().split()[:2]))
        os.makedirs(os.path.join(self.tmp, "home", ".ssh"), mode=0o700, exist_ok=True)
        with open(os.path.join(self.tmp, "home", ".ssh", "known_hosts"), "w", encoding="ascii") as f:
            f.write(f"leaf1 {keys[0]}\n[127.0.0.1]:{port} {keys[1]}\n")
        inventory = ("all:\n  children:\n    leaves:\n      hosts:\n        leaf1:\n"
                     f"          ansible_host: 127.0.0.1\n          ansible_port: {port}\n"
                     + "".join(f"          {line}\n" for line in host_lines))
        play = head + "  vars:\n" + vars_lines + NETWORK_TASKS
        for name, text in (("inv.yml", inventory), ("play.yml", play)):
            with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as f:
                f.write(text)
        return run(self.tmp, PLAYBOOK, "-i", os.path.join(self.tmp, "inv.yml"), os.path.join(self.tmp, "play.yml"))

    def assert_checked(self, code, out):
        self.assertNotEqual(code, 0)
        self.assertIn("[host_key_changed]", out)
        self.assertNotIn("TASK [the next task connects]", out)
        self.assertFalse(os.path.exists(self.log))  # nothing minted

    def test_the_plays_network_cli_over_an_inventory_ssh_is_checked(self):  # review fix round 1, m1
        # Play vars override inventory host_vars, so Ansible connects with network_cli: the lookup must check
        # the address's key, refuse the one that differs from the name's, and mint nothing.
        _, vars_lines = readme_play(self.fake)
        self.assertIn("ansible_connection: ansible.netcommon.network_cli", vars_lines)
        self.assert_checked(*self.mismatched_run(["ansible_connection: ssh"], vars_lines))

    def test_a_templated_play_connection_is_checked(self):  # review fix round 2, r1
        # ansible-core 2.16 to 2.18 may hand a lookup the play's ansible_connection untemplated ("{{ conn }}").
        _, vars_lines = readme_play(self.fake)
        vars_lines = vars_lines.replace("ansible_connection: ansible.netcommon.network_cli",
                                        'ansible_connection: "{{ conn }}"')
        self.assertIn("{{ conn }}", vars_lines)
        self.assert_checked(*self.mismatched_run(["conn: ansible.netcommon.network_cli"], vars_lines))

    def test_a_port49_name_outside_the_inventory_fails_closed(self):
        # network_cli dials leaf1's address, but the term names another device: nothing says whose key that
        # address must hold, so the lookup refuses before any mint rather than skip the check.
        head, vars_lines = readme_play(self.fake)
        play = head.replace("inventory_hostname", "'srx1'") + "  vars:\n" + vars_lines + NETWORK_TASKS
        inventory = ("all:\n  children:\n    leaves:\n      hosts:\n        leaf1:\n"
                     f"          ansible_host: 127.0.0.1\n          ansible_port: {closed_port()}\n")
        for name, text in (("inv.yml", inventory), ("play.yml", play)):
            with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as f:
                f.write(text)
        code, out = run(self.tmp, PLAYBOOK, "-i", os.path.join(self.tmp, "inv.yml"), os.path.join(self.tmp, "play.yml"))
        self.assertNotEqual(code, 0)
        self.assertNotIn("hostvars['srx1']", out)  # ansible-core 2.21's undefined marker, the regression
        # 2.16 wraps a warning's lines: compare with whitespace collapsed.
        self.assertIn("port49: srx1: not a host in Ansible's inventory, and leaf1 connects with network_cli",
                      " ".join(out.split()))
        self.assertIn("[host_key_uncheckable]", out)
        self.assertNotIn("TASK [the next task connects]", out)
        self.assertFalse(os.path.exists(self.log))  # nothing minted


if __name__ == "__main__":
    unittest.main()
