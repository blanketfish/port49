import io
import json
import os
import secrets
import shutil
import socket
import stat
import sys
import tempfile
import threading
import traceback
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

captured = {}
EVENTS = []      # "filed" and "authenticated", in the order they happened
CLIENT = {}      # what the fake's _build_ssh_client returns
NEXT_ERROR = []  # what the next connection raises, as Paramiko would
PRESENTED = ("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")
AUTH_FAILS = []  # set: the next _open fails in a frame that holds the password, as Paramiko's auth does


def _authenticate(password):
    raise Exception("Authentication to device failed.")


def _raise_holding(password, exc):
    """Raise exc from a frame that holds the password, as a refusal inside Paramiko's key exchange does."""
    raise exc


try:
    import paramiko
except ImportError:  # the real-Paramiko test skips
    paramiko = None

REAL_SERVER = []  # set: the port of a local SSH server; the next _open logs in to it with real Paramiko


def _paramiko_login(kw, port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username=kw["username"], password=kw["password"],
                   look_for_keys=False, allow_agent=False, timeout=10, auth_timeout=10, banner_timeout=10)


if paramiko is not None:
    class RefusesPasswords(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            return paramiko.AUTH_FAILED


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
        self.alt_host_keys, self.alt_key_file = kw["alt_host_keys"], kw["alt_key_file"]
        self.disabled_algorithms = dict(kw.get("disabled_algorithms") or {"pubkeys": ["rsa-sha2-256"]})
        self.key_policy = "RejectPolicy" if kw["ssh_strict"] else "AutoAddPolicy"
        if not kw.get("auto_connect", True):
            return
        self._open()

    def reconnect(self, presented=PRESENTED):
        """What establish_connection() and SCPConn do later (base_connection.py _build_ssh_client): the
        alt key file is loaded only if alt_host_keys is set and the file is still there; a key held for the
        address is compared (Paramiko raises BadHostKeyException), and with none held the policy is asked."""
        held = ""
        if self.alt_host_keys and os.path.isfile(self.alt_key_file):
            with open(self.alt_key_file, encoding="ascii") as f:
                held = f.read()
        key = types.SimpleNamespace(get_name=lambda: presented[0], get_base64=lambda: presented[1])
        if held:
            if f"{presented[0]} {presented[1]}" not in held:
                raise BadHostKeyException("Host key for server '10.0.0.11' does not match")
            return
        policy = self.key_policy
        if isinstance(policy, str):  # Paramiko's RejectPolicy with nothing held
            raise Exception("Server '10.0.0.11' not found in known_hosts")
        policy.missing_host_key(None, self.kw["host"], key)

    def _build_ssh_client(self):
        return CLIENT["c"]  # Netmiko's own: a Paramiko client with no host keys loaded

    def _open(self):
        with open(self.kw["alt_key_file"], encoding="ascii") as f:
            captured["known_hosts"] = f.read()
        captured["mode"] = stat.S_IMODE(os.stat(self.kw["alt_key_file"]).st_mode)
        captured["policy"] = self.key_policy
        captured["disabled"] = {k: list(v) for k, v in self.disabled_algorithms.items()}
        if NEXT_ERROR:
            _raise_holding(self.kw["password"], NEXT_ERROR.pop())
        key = types.SimpleNamespace(get_name=lambda: PRESENTED[0], get_base64=lambda: PRESENTED[1])
        # Paramiko: the key the connection accepted
        self.remote_conn_pre = types.SimpleNamespace(
            get_transport=lambda: types.SimpleNamespace(get_remote_server_key=lambda: key))
        if not captured["known_hosts"]:
            # Paramiko: no key held for the address, so the policy is asked, after the key exchange
            # and before authentication.
            self.key_policy.missing_host_key(None, self.kw["host"], key)
        if AUTH_FAILS:
            AUTH_FAILS.pop()
            _authenticate(self.kw["password"])
        if REAL_SERVER:
            _paramiko_login(self.kw, REAL_SERVER.pop())
        EVENTS.append("authenticated")

    def disconnect(self):
        captured["disconnected"] = True


sys.modules["netmiko"] = types.SimpleNamespace(ConnectHandler=lambda **kw: FakeConnection(**kw))

import fakeport49 as fake  # noqa: E402
from port49 import (Agent, Denied, DeviceFault, HostKeyError, MFARequired, NoAgent, Temporary, Token,  # noqa: E402
                    Workload, hostkeys)
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


# The connection's own attributes Netmiko logs in with (and the stand-in's copy of its kwargs). Real
# Paramiko keeps the token too, at conn.remote_conn_pre._transport.auth_handler.password: the same
# exposure as conn.password. Whoever holds conn can read it there, by design; the test's scope is
# closures and tracebacks, not that.
NETMIKO_HOLDS = {"password", "secret", "kw"}


def reaches(root, secret, skip=()):
    """Whether secret is reachable from root through attributes, containers, bound methods and closures,
    root's skip attributes aside: what a caller could read off it."""
    seen, todo = set(), [root]
    while todo:
        obj = todo.pop()
        if id(obj) in seen or isinstance(obj, (types.ModuleType, type)):
            continue
        seen.add(id(obj))
        if isinstance(obj, str):
            if secret in obj:
                return True
            continue
        if isinstance(obj, (bytes, bytearray)):
            if secret.encode() in obj:
                return True
            continue
        if isinstance(obj, dict):
            todo += [x for kv in obj.items() for x in kv]
        elif isinstance(obj, (list, tuple, set, frozenset)):
            todo += list(obj)
        if isinstance(obj, types.FunctionType):
            for cell in obj.__closure__ or ():
                try:
                    todo.append(cell.cell_contents)
                except ValueError:  # an empty cell
                    pass
            todo += [obj.__defaults__, obj.__kwdefaults__]
        elif isinstance(obj, types.MethodType):
            todo += [obj.__self__, obj.__func__]
        d = getattr(obj, "__dict__", None)
        if isinstance(d, dict):
            todo += [v for k, v in d.items() if not (obj is root and k in skip)]
        for slot in getattr(type(obj), "__slots__", ()):
            todo.append(getattr(obj, slot, None))
    return False


def frame_locals(exc):
    """repr of every local of every frame in exc's traceback and in its causes' and contexts', shown or
    suppressed."""
    out, todo, seen = [], [exc], set()
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        tb = e.__traceback__
        while tb is not None:
            out.append(repr(tb.tb_frame.f_locals))
            tb = tb.tb_next
        todo += [e.__cause__, e.__context__]
    return "\n".join(out)


def permitted(login, enable=None):
    """`port49 workload token --format json`'s answer for leaf1, permitted."""
    it = {"device": "leaf1", "verdict": "permit", "address": "10.0.0.11", "platform": "arista_eos",
          "username": "svc", "login": login, "expires_at": "2026-11-09T10:00:00Z"}
    if enable:
        it["enable"] = enable
    return {"stdout": json.dumps({"principal": "spiffe://example.com/agent/ro", "results": [it], "refused": []})}


def refused(item, code=77):
    return {"stdout": json.dumps({"principal": "spiffe://example.com/agent/ro", "results": [], "refused": [item]}),
            "code": code}


class NetmikoTest(unittest.TestCase):
    def workload(self, *answers):
        self.fake_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.fake_dir, True)  # the fake's answers hold the made-up tokens
        self.err = io.StringIO()
        return Workload("https://broker.example.com:8443", "/ca.pem", "/w.pem", "/w.key",
                        port49=fake.make(self.fake_dir, list(answers)), stderr=self.err, timeout=30)

    def made(self):
        self.login, self.enable = secrets.token_urlsafe(18), secrets.token_urlsafe(18)

    def test_a_workload_mints_once_by_workload_token_and_logs_in_with_it(self):  # #56
        self.made()
        conn, _ = self.connect(known("ssh-ed25519 AAAA1"), workload=self.workload(permitted(self.login, self.enable)),
                               enable=True)
        argvs = fake.argvs(self.fake_dir)
        self.assertEqual(len(argvs), 1)
        self.assertEqual(argvs[0][:2], ["workload", "token"])
        self.assertIn("--enable", argvs[0])
        self.assertEqual(fake.device_files(self.fake_dir), [["leaf1"]])
        self.assertTrue((captured["host"], captured["username"], captured["password"], captured["secret"]) ==
                        ("10.0.0.11", "svc", self.login, self.enable), "Netmiko not given the minted login")
        self.lookup.assert_called_once_with("leaf1", "10.0.0.11", port=22, username="svc", ssh_config=None)
        for name in ("login", "enable"):
            self.assertFalse(reaches(conn, getattr(self, name), NETMIKO_HOLDS), f"{name} reachable from conn")
            self.assertFalse(getattr(self, name) in self.err.getvalue(), f"{name} on stderr")

    def test_a_workloads_failure_after_the_mint_leaves_no_token_in_a_traceback(self):  # #56
        self.made()
        AUTH_FAILS.append(True)
        with self.assertRaises(Exception) as cm:
            self.connect(known("ssh-ed25519 AAAA1"), workload=self.workload(permitted(self.login)))
        self.assertFalse(self.login in frame_locals(cm.exception), "the login in a frame's locals")

    def test_a_workloads_refusal_raises_what_an_agents_does_before_connecting(self):  # #56
        mfa = {"accept": ["hardware_key_touch"], "reuse_for_seconds": 900}
        for item, cls in [
                ({"device": "leaf1", "verdict": "deny", "reason": "no_grants_matched"}, Denied),
                ({"device": "leaf1", "verdict": "deny", "reason": "per_login_mfa_required", "per_login_mfa": mfa},
                 MFARequired),
                ({"device": "leaf1", "error": "device_unconfigured", "detail": "fixed words"}, DeviceFault)]:
            captured.clear()
            with self.assertRaises(cls, msg=item) as cm:
                self.connect(known("ssh-ed25519 AAAA1"), workload=self.workload(refused(item)))
            self.assertEqual((cm.exception.device, captured), ("leaf1", {}), item)
            self.assertEqual(len(fake.argvs(self.fake_dir)), 1)
        # the deny's reason, as on the Agent path
        with self.assertRaises(Denied) as cm:
            self.connect(known(), workload=self.workload(refused({"device": "leaf1", "verdict": "deny",
                                                                   "reason": "no_grants_matched"})))
        self.assertEqual(cm.exception.reason, "no_grants_matched")

    def test_a_stopped_workload_run_keeps_no_token_on_its_error(self):  # #56, Ruling 4
        self.made()
        answer = {"stdout": json.dumps({"principal": "p", "results": json.loads(permitted(self.login)["stdout"])["results"],
                                        "refused": [], "stopped": "broker_unavailable"}), "code": 75}
        captured.clear()
        with self.assertRaises(Temporary) as cm:
            self.connect(known("ssh-ed25519 AAAA1"), workload=self.workload(answer))
        self.assertEqual(cm.exception.results.tokens, {"leaf1": None})  # the name stays, the token does not
        self.assertFalse(reaches(cm.exception, self.login), "the login reachable from the error")
        self.assertFalse(self.login in str(cm.exception) + repr(cm.exception) + repr(cm.exception.args),
                         "the login in the error's message")  # reaches() does not follow .args
        self.assertEqual(captured, {})

    def test_agent_and_workload_together_or_crossed_are_refused_before_minting(self):  # #56, Ruling 2
        agent = FakeAgent()
        w = self.workload(permitted("unused"))
        with self.assertRaises(ValueError):
            p49netmiko.connect("leaf1", agent=agent, workload=w)
        with self.assertRaises(TypeError):
            p49netmiko.connect("leaf1", agent=w)
        with self.assertRaises(TypeError):
            p49netmiko.connect("leaf1", workload=agent)
        self.assertEqual((fake.argvs(self.fake_dir), agent.asked), ([], []))

    def test_no_agent_and_no_workload_names_workload(self):  # #56, Ruling 2
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        none = Agent(port49=fake.make(d, [{"stdout": fake.item(device="leaf1", error="no_agent",
                                                                detail="no agent answers: run port49 login"),
                                            "code": 1}]), stderr=io.StringIO())
        with mock.patch.object(p49netmiko, "Agent", lambda: none):
            with self.assertRaises(NoAgent) as cm:
                p49netmiko.connect("leaf1")
        self.assertEqual(cm.exception.code, "no_agent")
        self.assertIn("workload=port49.Workload(...)", str(cm.exception))
        with self.assertRaises(NoAgent) as cm:  # an agent the caller chose: its own words only
            p49netmiko.connect("leaf1", agent=none)
        self.assertNotIn("workload=", str(cm.exception))

    def minted(self):
        """A FakeAgent with tokens made now. They live on self, never in a test's local: the test's own
        frame is in the traceback the tests read."""
        self.login, self.enable = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
        return FakeAgent(Token("leaf1", "10.0.0.11", "arista_eos", "alice", self.login, self.enable))

    def test_the_connection_holds_the_token_only_where_netmiko_logs_in_with_it(self):  # #56
        for kh in (known("ssh-ed25519 AAAA1"), known()):  # a known key, and a first contact
            conn, _ = self.connect(kh, agent=self.minted(), enable=True)
            self.assertTrue(captured["password"] == self.login and captured["secret"] == self.enable,
                            "Netmiko not given the minted login and enable")
            for name in ("login", "enable"):  # no loop variable holds a token
                self.assertFalse(reaches(conn, getattr(self, name), NETMIKO_HOLDS), f"{name} reachable: {kh.keys}")

    def test_a_failure_after_the_mint_leaves_no_token_in_a_traceback(self):  # #56
        AUTH_FAILS.append(True)
        # try/except, not assertRaises: assertRaises strips the traceback, which is what is under test.
        try:
            self.connect(known("ssh-ed25519 AAAA1"), agent=self.minted())
        except Exception as e:
            caught = e
        else:
            self.fail("connect did not raise")
        e = caught
        text = "".join(traceback.TracebackException.from_exception(e, capture_locals=True).format())
        # No loop variable holding a token: this frame is in the traceback frame_locals reads. And the
        # assertions are on booleans, so a failure prints no token.
        for name in ("login", "enable"):
            self.assertFalse(getattr(self, name) in text, f"{name} in the formatted traceback")
            self.assertFalse(getattr(self, name) in frame_locals(e), f"{name} in a frame's locals")
            self.assertFalse(getattr(self, name) in str(e) + repr(e) + repr(e.args), f"{name} in the exception")
        self.assertIn("_authenticate", text)  # the frames stay, file and line; only their locals go

    @unittest.skipIf(paramiko is None, "paramiko is not importable here")
    def test_a_real_paramiko_auth_failure_leaves_no_token_in_any_frame(self):  # #56
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        key = paramiko.RSAKey.generate(2048)  # made now; no key file
        transports = []

        def serve():
            try:
                peer, _ = sock.accept()
                t = paramiko.Transport(peer)
                transports.append(t)
                t.add_server_key(key)
                t.start_server(server=RefusesPasswords())
                t.join(20)
            except Exception:
                pass

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        def stop():
            sock.close()
            for t in transports:
                t.close()
            th.join(5)
        self.addCleanup(stop)
        REAL_SERVER.append(sock.getsockname()[1])
        try:
            self.connect(known("ssh-ed25519 AAAA1"), agent=self.minted())
        except Exception as e:
            caught = e
        else:
            self.fail("connect did not raise")
        self.assertEqual(type(caught).__name__, "AuthenticationException")
        text = "".join(traceback.TracebackException.from_exception(caught, capture_locals=True).format())
        for name in ("login", "enable"):
            self.assertFalse(getattr(self, name) in frame_locals(caught), f"{name} in a frame's locals")
            self.assertFalse(getattr(self, name) in text, f"{name} in the formatted traceback")
        self.assertTrue("paramiko" in text, "paramiko's frames are in the chain")  # the frames are real ones

    def test_a_generator_frame_in_the_chain_is_left_alone(self):  # #56: 3.10-3.12 finalize a suspended one
        def gen():
            held = "x"  # noqa: F841
            yield 1
            raise KeyError("from a generator")

        def run():
            g = gen()
            next(g)
            next(g)
        try:
            run()
        except KeyError as e:
            caught = e
        p49netmiko._clear_frames(caught, None)  # must not raise
        tb = caught.__traceback__
        self.assertEqual(tb.tb_next.tb_next.tb_frame.f_locals.get("held"), "x")  # the generator's kept
        self.assertEqual(tb.tb_next.tb_frame.f_locals, {})  # a plain frame's cleared

    def test_a_host_key_refusal_leaves_no_token_in_its_suppressed_context(self):  # #56
        NEXT_ERROR.append(BadHostKeyException("Host key for server '10.0.0.11' does not match"))
        try:  # not assertRaises, which strips the traceback
            self.connect(known("ssh-ed25519 AAAA1"), agent=self.minted())
        except HostKeyError as e:
            caught = e
        else:
            self.fail("connect did not raise")
        self.assertIsNotNone(caught.__context__)
        self.assertFalse(self.login in frame_locals(caught), "the login token in a frame's locals")

    def test_a_callers_own_exception_keeps_its_frames(self):  # #56: the clearing stops at connect
        def caller_fails():
            mine = "kept"  # noqa: F841
            raise KeyError("the caller's own")
        try:
            caller_fails()
        except KeyError as outer:
            AUTH_FAILS.append(True)
            with self.assertRaises(Exception):
                self.connect(known("ssh-ed25519 AAAA1"), agent=self.minted())
            self.assertEqual(outer.__traceback__.tb_next.tb_frame.f_locals.get("mine"), "kept")

    def connect(self, kh, device="leaf1", agent=None, workload=None, **kw):
        remembered = []

        def remember(k, t, b, stderr=None, **_):
            remembered.append((k.name, t, b))
            EVENTS.append("filed")

        # Kept for the whole test: the connection's pin looks the file up again at each reconnect.
        patchers = [mock.patch.object(hostkeys, "lookup", return_value=kh),
                    mock.patch.object(hostkeys, "remember", side_effect=remember)]
        self.lookup = patchers[0].start()
        patchers[1].start()
        for p in patchers:
            self.addCleanup(p.stop)
        if workload is None:
            agent = agent or FakeAgent()
        conn = p49netmiko.connect(device, agent=agent, workload=workload, **kw)
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
        self.assertTrue((captured["username"], captured["password"], captured["secret"]) ==
                        ("alice", "LOGINTOKEN", "ENABLETOKEN"), "Netmiko not given the minted login")
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
        self.assertFalse("LOGINTOKEN" in str(cm.exception), "the token in the error")

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
        self.assertFalse("LOGINTOKEN" in str(cm.exception), "the token in the error")

    def test_an_address_moved_to_another_host_is_refused(self):  # Review Focus 2
        NEXT_ERROR.append(BadHostKeyException("Host key for server '10.0.0.11' does not match: got 'AAAA9', "
                                              "expected 'AAAA1'"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-ed25519 AAAA1"))
        self.assertIn("is not the one 10.0.0.11 presents", str(cm.exception))
        self.assertFalse("LOGINTOKEN" in str(cm.exception), "the token in the error")

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

    # Fix round 1.

    OTHER = ("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIIMPOSTORIMPOSTORIMPOSTORIMPOSTORIMPOSTORIMPO")

    def test_a_reconnect_after_a_first_contact_accepts_only_the_filed_key(self):  # C1
        conn, remembered = self.connect(known())
        self.assertFalse(conn.alt_host_keys)
        self.lookup.return_value = known(" ".join(PRESENTED))  # the file now holds what was filed
        conn.reconnect(PRESENTED)  # the filed key: accepted
        with self.assertRaises(HostKeyError) as cm:
            conn.reconnect(self.OTHER)
        self.assertEqual(cm.exception.code, "host_key_changed")
        self.assertEqual(remembered, [("leaf1", PRESENTED[0], PRESENTED[1])])  # nothing new filed

    def test_a_reconnect_after_a_known_key_connect_accepts_only_the_filed_key(self):  # C1
        key = " ".join(PRESENTED)
        conn, remembered = self.connect(known(key))
        self.assertFalse(conn.alt_host_keys)
        conn.reconnect(PRESENTED)
        with self.assertRaises(HostKeyError) as cm:
            conn.reconnect(self.OTHER)
        self.assertEqual(cm.exception.code, "host_key_changed")
        self.assertEqual(remembered, [])

    def test_a_recreated_temp_known_hosts_is_not_trusted(self):  # C1: the deleted-path attack
        conn, _ = self.connect(known(" ".join(PRESENTED)))
        path = captured["alt_key_file"]  # what the connection was built with, now removed
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii") as f:
            f.write("10.0.0.11 " + " ".join(self.OTHER) + "\n")
        conn.alt_key_file = path  # even if something pointed back at it
        self.addCleanup(shutil.rmtree, os.path.dirname(path), True)
        with self.assertRaises(HostKeyError):
            conn.reconnect(self.OTHER)

    def test_the_pin_is_the_key_the_connect_accepted(self):  # M1, fix round 3: not every filed key
        conn, _ = self.connect(known("ssh-ed25519 AAAA1", " ".join(PRESENTED)))
        conn.reconnect(PRESENTED)
        with self.assertRaises(HostKeyError):
            conn.reconnect(("ssh-ed25519", "AAAA1"))  # filed, but not what the device presented

    # Fix round 3.

    def test_only_the_filed_key_types_are_negotiated(self):  # N1: OpenSSH 8.8+ does not offer ssh-rsa
        self.connect(known("ssh-rsa QUJD"))
        off = set(captured["disabled"]["keys"])
        self.assertEqual(off, {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"})
        # RSA filed: rsa-sha2-512, rsa-sha2-256 and ssh-rsa stay
        self.assertEqual(captured["disabled"]["pubkeys"], ["rsa-sha2-256"])  # Netmiko's own entry is kept
        self.connect(known("ssh-ed25519 QUJD", "ecdsa-sha2-nistp256 QUJD"))
        self.assertEqual(set(captured["disabled"]["keys"]), {"ssh-rsa", "rsa-sha2-512", "rsa-sha2-256",
                                                             "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"})
        self.connect(known("ssh-rsa QUJD"), disabled_algorithms={"keys": ["ssh-dss", "x-callers"]})
        self.assertIn("x-callers", captured["disabled"]["keys"])  # the caller's own list is merged
        self.connect(known())  # a first contact: nothing is filed, so nothing is narrowed
        self.assertNotIn("keys", captured["disabled"])

    def test_a_rebuilt_clients_host_key_mismatch_is_a_host_key_error(self):  # remap
        conn, _ = self.connect(known(" ".join(PRESENTED)))

        class Client:
            def __init__(self, err):
                self.err = err

            def get_host_keys(self):
                return types.SimpleNamespace(add=lambda *a: None)

            def connect(self, *a, **k):
                raise self.err

        class PKey:
            @staticmethod
            def from_type_string(keytype, blob):
                return (keytype, blob)

        errors = (BadHostKeyException("Host key for server '10.0.0.11' does not match: got 'a', expected 'b'"),
                  Exception("Incompatible ssh peer (no acceptable host key)"))
        for err in errors:
            CLIENT["c"] = Client(err)
            with mock.patch.dict(sys.modules, {"paramiko": types.SimpleNamespace(PKey=PKey)}):
                client = conn._build_ssh_client()
                with self.assertRaises(HostKeyError) as cm:
                    client.connect("10.0.0.11")
            self.assertEqual(cm.exception.code, "host_key_changed", str(err))
        CLIENT["c"] = Client(OSError("unreachable"))  # anything else passes through unchanged
        with mock.patch.dict(sys.modules, {"paramiko": types.SimpleNamespace(PKey=PKey)}):
            with self.assertRaises(OSError):
                conn._build_ssh_client().connect("10.0.0.11")

    def test_a_key_type_paramiko_cannot_load_is_not_a_changed_key(self):  # M2
        NEXT_ERROR.append(Exception("Server '10.0.0.11' not found in known_hosts"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-dss AAAA1"))
        self.assertEqual(cm.exception.code, "host_key_uncheckable")
        self.assertNotIn("ssh-keygen -R", str(cm.exception))
        self.assertNotIn("has not changed", str(cm.exception))  # N4: it cannot know
        self.assertIn("could not be compared", str(cm.exception))

    def test_a_dsa_only_filed_key_disables_nothing(self):  # review M2: Paramiko 5 offers no ssh-dss
        self.assertEqual(p49netmiko.host_key_algorithms_off(["ssh-dss AAAA"]), [])
        self.assertEqual(p49netmiko.host_key_algorithms_off(["ssh-dss AAAA", "sk-ssh-ed25519@openssh.com AAAA"]), [])
        self.assertNotIn("ssh-dss", p49netmiko._HOST_KEY_ALGORITHMS)
        self.connect(known("ssh-dss AAAA1"))
        self.assertEqual(captured["disabled"]["keys"], [])  # so the kex is not starved of every algorithm

    def test_no_acceptable_host_key_with_nothing_filed_is_uncheckable(self):  # review M3
        NEXT_ERROR.append(Exception("Incompatible ssh peer (no acceptable host key)"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known())
        self.assertEqual(cm.exception.code, "host_key_uncheckable")
        self.assertIn("port49 ssh", str(cm.exception))
        self.assertNotIn("ssh-keygen -R", str(cm.exception))  # nothing is filed to remove
        NEXT_ERROR.append(Exception("Incompatible ssh peer (no acceptable host key)"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-ed25519 AAAA1"))  # a key is filed: still the changed-key refusal
        self.assertEqual(cm.exception.code, "host_key_changed")

    def test_no_acceptable_host_key_with_only_unloadable_types_filed_is_uncheckable(self):  # 9d minor N1
        # Paramiko 5 offers no ssh-dss, so a device offering only DSA can never be checked against its filed DSA
        # key: that is not a changed key.
        for filed in (("ssh-dss AAAA1",), ("ssh-dss AAAA1", "sk-ssh-ed25519@openssh.com AAAA2")):
            NEXT_ERROR.append(Exception("Incompatible ssh peer (no acceptable host key)"))
            with self.assertRaises(HostKeyError) as cm:
                self.connect(known(*filed))
            self.assertEqual(cm.exception.code, "host_key_uncheckable", filed)
            self.assertIn("port49 ssh", str(cm.exception))
            self.assertNotIn("ssh-keygen -R", str(cm.exception))
        NEXT_ERROR.append(Exception("Incompatible ssh peer (no acceptable host key)"))
        with self.assertRaises(HostKeyError) as cm:
            self.connect(known("ssh-dss AAAA1", "ssh-ed25519 AAAA2"))  # a checkable type is filed: still changed
        self.assertEqual(cm.exception.code, "host_key_changed")

    # Fix round 2.

    def test_a_key_revoked_since_the_connect_is_refused_on_a_reconnect(self):  # N3
        key = " ".join(PRESENTED)
        conn, _ = self.connect(known(key))
        conn.reconnect(PRESENTED)
        self.lookup.return_value = known(revoked=(key,))  # an @revoked line, filed since: key dropped
        with self.assertRaises(HostKeyError) as cm:
            conn.reconnect(PRESENTED)
        self.assertEqual(cm.exception.code, "host_key_revoked")
        self.lookup.side_effect = HostKeyError("host_key_revoked", "every key filed is revoked")
        with self.assertRaises(HostKeyError) as cm:
            conn.reconnect(PRESENTED)
        self.assertEqual(cm.exception.code, "host_key_revoked")

    def test_a_rebuilt_client_holds_the_pinned_keys(self):  # N1, with a stand-in for paramiko
        added = []

        class HostKeys:
            def add(self, hostname, keytype, key):
                added.append((hostname, keytype, key))

        class Client:
            def get_host_keys(self):
                return HostKeys()

        class PKey:
            @staticmethod
            def from_type_string(keytype, blob):
                return ("key", keytype, blob)

        with mock.patch.dict(sys.modules, {"paramiko": types.SimpleNamespace(PKey=PKey)}):
            p49netmiko._load_pinned(Client(), "[10.0.0.11]:2222", {"ssh-rsa QUJD", "ssh-dss AAAA"})
        self.assertIn(("[10.0.0.11]:2222", "ssh-rsa", ("key", "ssh-rsa", b"ABC")), added)

    def test_connect_wraps_the_clients_rebuild(self):  # N1
        conn, _ = self.connect(known(" ".join(PRESENTED)))
        built = []

        class Client:
            def get_host_keys(self):
                return types.SimpleNamespace(add=lambda *a: built.append(a))

        class PKey:
            @staticmethod
            def from_type_string(keytype, blob):
                return (keytype, blob)

        CLIENT["c"] = Client()
        with mock.patch.dict(sys.modules, {"paramiko": types.SimpleNamespace(PKey=PKey)}):
            self.assertIs(conn._build_ssh_client(), CLIENT["c"])
        self.assertEqual(len(built), 1)
        self.assertEqual(built[0][0], "10.0.0.11")
        # a key revoked since: nothing is built that can connect
        self.lookup.return_value = known(revoked=(" ".join(PRESENTED),))
        with mock.patch.dict(sys.modules, {"paramiko": types.SimpleNamespace(PKey=PKey)}):
            with self.assertRaises(HostKeyError) as cm:
                conn._build_ssh_client()
        self.assertEqual(cm.exception.code, "host_key_revoked")

    def test_remember_and_the_recheck_use_the_given_ssh_keygen(self):  # N4
        seen = []
        fc = p49netmiko.FirstContact(known(), "leaf1", ssh_keygen="/x/fake-keygen")
        key = types.SimpleNamespace(get_name=lambda: PRESENTED[0], get_base64=lambda: PRESENTED[1])
        with mock.patch.object(hostkeys, "remember", side_effect=lambda *a, **k: seen.append(k)), \
                mock.patch.object(hostkeys, "is_revoked", side_effect=lambda *a, **k: seen.append(k) or False):
            fc.missing_host_key(None, "10.0.0.11", key)
        self.assertTrue(all(k.get("ssh_keygen") == "/x/fake-keygen" for k in seen) and len(seen) == 2)

    def test_a_port_that_is_not_a_number_is_refused(self):  # M8
        with self.assertRaises(ValueError):
            self.connect(known("ssh-ed25519 AAAA1"), port=None)

    @unittest.skipUnless(__import__("shutil").which("ssh"), "needs OpenSSH's ssh")
    def test_a_first_contact_behind_a_bastion_never_dials(self):  # I2, the 3am case
        with tempfile.TemporaryDirectory() as d:
            for setting in ("ProxyJump bastion-a", "ProxyCommand nc %h %p", "Port 2222"):
                cfg = os.path.join(d, "ssh_config")
                with open(cfg, "w", encoding="ascii") as f:
                    f.write(f"UserKnownHostsFile {d}/kh\nGlobalKnownHostsFile /dev/null\n{setting}\n")
                captured.clear()
                with self.assertRaises(HostKeyError, msg=setting) as cm:
                    p49netmiko.connect("leaf1", agent=FakeAgent(), ssh_config=cfg)
                self.assertEqual(captured, {}, setting)
                self.assertEqual(cm.exception.code, "host_key_uncheckable")
                self.assertIn("port49 ssh", str(cm.exception))
                self.assertNotIn("ssh-keygen -R", str(cm.exception))
                self.assertFalse(os.path.exists(f"{d}/kh"))

    def test_the_security_options_cannot_be_overridden(self):  # pre-flight M16 adds sock and ssh_config_file; N4 ip
        for kw in ("ssh_strict", "sock", "ssh_config_file", "auto_connect", "ip", "pkey", "key_file"):
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
        self.assertFalse("LOGINTOKEN" in str(cm.exception), "the token in the error")


if __name__ == "__main__":
    unittest.main()
