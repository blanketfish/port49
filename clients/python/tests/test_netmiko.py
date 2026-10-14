import io
import os
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

captured = {}
EVENTS = []      # "filed" and "authenticated", in the order they happened
NEXT_ERROR = []  # what the next connection raises, as Paramiko would
PRESENTED = ("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")


class BadHostKeyException(Exception):
    pass


class FakeConnection:
    """Netmiko 4.7.0's shape: with auto_connect=False nothing connects until _open, and key_policy is
    Paramiko's AutoAddPolicy or RejectPolicy as ssh_strict says, until the caller sets another."""

    def __init__(self, **kw):
        captured.clear()
        EVENTS.clear()
        captured.update(kw)
        self.kw = kw
        self.key_policy = "RejectPolicy" if kw["ssh_strict"] else "AutoAddPolicy"
        if not kw.get("auto_connect", True):
            return
        self._open()

    def _open(self):
        with open(self.kw["alt_key_file"], encoding="ascii") as f:
            captured["known_hosts"] = f.read()
        captured["mode"] = stat.S_IMODE(os.stat(self.kw["alt_key_file"]).st_mode)
        captured["policy"] = self.key_policy
        if NEXT_ERROR:
            raise NEXT_ERROR.pop()
        key = types.SimpleNamespace(get_name=lambda: PRESENTED[0], get_base64=lambda: PRESENTED[1])
        if not captured["known_hosts"]:
            # Paramiko: no key held for the address, so the policy is asked, after the key exchange
            # and before authentication.
            self.key_policy.missing_host_key(None, self.kw["host"], key)
        EVENTS.append("authenticated")

    def disconnect(self):
        captured["disconnected"] = True


sys.modules["netmiko"] = types.SimpleNamespace(ConnectHandler=lambda **kw: FakeConnection(**kw))

from port49 import HostKeyError, Token, hostkeys  # noqa: E402
from port49 import netmiko as p49netmiko  # noqa: E402

TOKEN = Token("leaf1", "10.0.0.11", "arista_eos", "alice", "LOGINTOKEN", "ENABLETOKEN")


class FakeAgent:
    def __init__(self, token=TOKEN):
        self.token_ = token
        self.asked = []

    def token(self, device, enable=False, ttl=None):
        self.asked.append((device, enable))
        return self.token_


def known(*keys, authorities=(), revoked=(), strict=False):
    return hostkeys.KnownHosts("leaf1", tuple(keys), tuple(authorities), tuple(revoked), "", strict, False,
                               "/dev/null")


class NetmikoTest(unittest.TestCase):
    def connect(self, kh, device="leaf1", agent=None, **kw):
        remembered = []

        def remember(k, t, b, stderr=None):
            remembered.append((k.name, t, b))
            EVENTS.append("filed")

        with mock.patch.object(hostkeys, "lookup", return_value=kh), \
                mock.patch.object(hostkeys, "remember", side_effect=remember):
            conn = p49netmiko.connect(device, agent=agent or FakeAgent(), **kw)
        return conn, remembered

    def test_a_known_key_is_the_only_key(self):
        _, remembered = self.connect(known("ssh-ed25519 AAAA1"))
        self.assertTrue(captured["ssh_strict"])
        self.assertFalse(captured["auto_connect"])
        self.assertEqual(captured["policy"], "RejectPolicy")
        self.assertEqual(captured["known_hosts"], "10.0.0.11 ssh-ed25519 AAAA1\n")
        self.assertEqual(captured["mode"], 0o600)
        self.assertFalse(os.path.exists(captured["alt_key_file"]))
        self.assertFalse(captured["system_host_keys"] or captured["use_keys"] or captured["allow_agent"])
        self.assertEqual((captured["username"], captured["password"], captured["secret"]), ("alice", "LOGINTOKEN", "ENABLETOKEN"))
        self.assertEqual(remembered, [])

    def test_a_first_contact_is_filed_under_the_name_before_authentication(self):  # pre-flight C1
        _, remembered = self.connect(known())
        self.assertFalse(captured["ssh_strict"])
        self.assertIsInstance(captured["policy"], p49netmiko.FirstContact)
        self.assertEqual(captured["known_hosts"], "")
        self.assertEqual(remembered, [("leaf1", PRESENTED[0], PRESENTED[1])])
        self.assertEqual(EVENTS, ["filed", "authenticated"])

    def test_a_revoked_key_at_first_contact_is_refused_before_auth(self):  # Review Focus 6; pre-flight C1
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known(revoked=(" ".join(PRESENTED),)))
        self.assertEqual(cm.exception.code, "host_key_revoked")
        self.assertEqual(EVENTS, [])  # neither filed nor authenticated
        self.assertTrue(captured.get("disconnected"))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_another_port_is_filed_in_brackets_for_paramiko(self):
        self.connect(known("ssh-ed25519 AAAA1"), port=2222)
        self.assertEqual(captured["known_hosts"], "[10.0.0.11]:2222 ssh-ed25519 AAAA1\n")

    def test_a_key_of_another_type_under_a_known_name_is_refused(self):  # Review Focus 1
        # Paramiko, holding the filed RSA key for the address, raises BadHostKeyException for an
        # Ed25519 one: our_key is None, so it compares against the first key held (client.py:461-466).
        NEXT_ERROR.append(BadHostKeyException("Host key for server '10.0.0.11' does not match: got 'AAAAC3', "
                                              "expected 'AAAAB3'"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-rsa AAAAB3"))
        self.assertTrue(captured["ssh_strict"])
        self.assertEqual(captured["known_hosts"], "10.0.0.11 ssh-rsa AAAAB3\n")
        self.assertIn("ssh-keygen -R leaf1", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_an_address_moved_to_another_host_is_refused(self):  # Review Focus 2
        NEXT_ERROR.append(BadHostKeyException("Host key for server '10.0.0.11' does not match: got 'AAAA9', "
                                              "expected 'AAAA1'"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-ed25519 AAAA1"))
        self.assertIn("is not the one 10.0.0.11 presents", str(cm.exception))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))

    def test_a_certificate_authority_alone_is_refused_before_connecting(self):
        captured.clear()
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known(authorities=("@cert-authority leaf* ssh-ed25519 AAAA",)))
        self.assertEqual(captured, {})
        self.assertIn("cannot check", str(cm.exception))

    def test_strict_yes_with_nothing_known_is_refused_before_connecting(self):
        captured.clear()
        with self.assertRaises(HostKeyError):
            self.connect(known(strict=True))
        self.assertEqual(captured, {})

    def test_a_bad_name_is_refused_before_minting(self):  # pre-flight I6, M14
        agent = FakeAgent()
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known(), device="leaf*", agent=agent)
        self.assertEqual((cm.exception.code, agent.asked), ("device_name", []))

    def test_the_security_options_cannot_be_overridden(self):  # pre-flight M16 adds sock and ssh_config_file; N4 ip
        for kw in ("ssh_strict", "sock", "ssh_config_file", "auto_connect", "ip"):
            with self.assertRaises(ValueError, msg=kw):
                self.connect(known("ssh-ed25519 AAAA1"), **{kw: None})

    def test_a_filed_key_stays_the_only_key_under_the_name_check(self):
        # lookup is asked for the address the token names, the port, and the user it logs in as
        with mock.patch.object(hostkeys, "lookup", return_value=known("ssh-ed25519 AAAA1")) as look:
            p49netmiko.connect("leaf1", agent=FakeAgent(), ssh_config="/x/cfg", port=2222)
        look.assert_called_once_with("leaf1", "10.0.0.11", port=2222, username="alice", ssh_config="/x/cfg")

    def test_a_platform_without_a_netmiko_type_is_refused(self):
        odd = Token("leaf1", "10.0.0.11", "fortios", "alice", "LOGINTOKEN", None)
        with self.assertRaises(ValueError) as cm:
            self.connect(known(), agent=FakeAgent(odd))
        self.assertNotIn("LOGINTOKEN", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
