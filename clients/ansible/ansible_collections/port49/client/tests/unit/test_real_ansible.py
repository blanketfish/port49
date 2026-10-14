"""The lookup under a real ansible-core, against a fake port49 CLI.

Skipped unless PORT49_TEST_ANSIBLE_PLAYBOOK names an ansible-playbook (a throwaway venv's;
`make test` needs no Ansible). The run uses a temporary HOME, so nothing of the operator's
~/.ansible or ~/.ssh is read or written.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTIONS = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))  # clients/ansible
LIBRARY = os.path.abspath(os.path.join(COLLECTIONS, "..", "python", "src"))
PLAYBOOK = os.environ.get("PORT49_TEST_ANSIBLE_PLAYBOOK")

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
        home = os.path.join(self.tmp, "home")
        os.makedirs(home, exist_ok=True)
        env = {"PATH": os.environ.get("PATH", ""), "HOME": home, "ANSIBLE_HOME": os.path.join(home, ".ansible"),
               "ANSIBLE_COLLECTIONS_PATH": COLLECTIONS, "PYTHONPATH": LIBRARY, "ANSIBLE_NOCOLOR": "1",
               "ANSIBLE_LOCAL_TEMP": os.path.join(self.tmp, "local"), "ANSIBLE_FORKS": "2",
               "PYTHONDONTWRITEBYTECODE": "1"}
        # Through a pipe: ansible refuses a non-blocking stderr.
        ran = subprocess.run([PLAYBOOK, "-i", os.path.join(self.tmp, "inv.yml"), path, *flags], env=env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, timeout=120, cwd=self.tmp)
        return ran.returncode, ran.stdout

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


if __name__ == "__main__":
    unittest.main()
