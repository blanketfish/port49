"""Real Netmiko: when its ConnectHandler raises in __init__ (a session_log in a directory that is not there, a
session_log of a type it refuses), connect leaves no filter holding the token on Netmiko's logger (#56). Netmiko
4.8.0 adds that filter, to mask the token in its logs, before that work, and takes it off only in disconnect().
Run by test_netmiko_real.py, which skips without Netmiko and Paramiko. Prints a line per failure, and exits 1
if there was one. The token is made now and never printed."""

import logging
import os
import secrets
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import netmiko  # noqa: E402, F401  (the real one, not the unit tests' stand-in)

from port49 import Token, hostkeys  # noqa: E402
from port49 import netmiko as p49netmiko  # noqa: E402


class OneShotAgent:
    """token() pops from a list and keeps no reference, as a real Agent keeps no token."""

    def __init__(self, tokens):
        self.tokens = tokens

    def token(self, device, enable=False, ttl=None):
        return self.tokens.pop()


def holds(secret):
    log = logging.getLogger("netmiko")
    found = []
    for owner in [log] + list(log.handlers):
        for f in owner.filters:
            found.append(secret in repr(getattr(f, "no_log", {})) or any(
                v == secret for v in getattr(f, "no_log", {}).values()))
    return any(found)


def main():
    login, enable = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
    work = tempfile.mkdtemp(prefix="port49-log-")
    failures = []
    kh = hostkeys.KnownHosts("leaf1", ("ssh-ed25519 AAAA1",), (), (), "", False, False, "/dev/null")
    original = hostkeys.lookup
    hostkeys.lookup = lambda *a, **k: kh
    try:
        for label, session_log, exc in (("a missing directory", os.path.join(work, "no", "s.log"), OSError),
                                        ("an unsupported type", 12345, ValueError)):
            before = len(logging.getLogger("netmiko").filters)
            agent = OneShotAgent([Token("leaf1", "10.0.0.11", "arista_eos", "alice", login, enable)])
            try:
                p49netmiko.connect("leaf1", agent=agent, session_log=session_log)
            except exc:
                pass
            except Exception as e:
                failures.append(f"{label}: raised {type(e).__name__}, not {exc.__name__}")
            else:
                failures.append(f"{label}: connect did not raise")
            if holds(login) or holds(enable):
                failures.append(f"{label}: a filter on Netmiko's logger still holds the token")
            if len(logging.getLogger("netmiko").filters) != before:
                failures.append(f"{label}: the logger's filters changed")
    finally:
        hostkeys.lookup = original
        shutil.rmtree(work, ignore_errors=True)
    for line in failures:
        print(line)
    return 1 if failures else 0


sys.exit(main())
