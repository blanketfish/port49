"""Real Netmiko and Paramiko against (1) a local Paramiko SSH server that offers what OpenSSH 8.8 and later
offer (no ssh-rsa), and (2) a real OpenSSH sshd run as the current user on a high port. Run by
test_netmiko_real.py, which skips without Netmiko, Paramiko and ssh-keygen; part 2 is skipped without sshd.

Part 1 logs in: a reconnect and an SCP on a connect()ed connection negotiate the filed key type and succeed, and
a key that is not the filed one is refused before any authentication, as a HostKeyError. An unprivileged sshd
cannot check a password, so part 2 reaches the host key check and goes no further: "accepted" there is an
authentication failure (the key was accepted, the login refused), and "refused" is a HostKeyError with no login
attempt in sshd's log. Neither server records the password it got beyond whether it was the token."""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import netmiko  # noqa: E402
import paramiko  # noqa: E402
from netmiko.scp_handler import SCPConn  # noqa: E402

from port49 import HostKeyError, Token, hostkeys  # noqa: E402
from port49 import netmiko as p49netmiko  # noqa: E402

WORK = tempfile.mkdtemp(prefix="port49-e2e-")
failures = []


def keygen(name, kind):
    path = os.path.join(WORK, name)
    subprocess.run(["ssh-keygen", "-q", "-t", kind, "-N", "", "-f", path], check=True)
    cls = paramiko.RSAKey if kind == "rsa" else paramiko.Ed25519Key
    return cls.from_private_key_file(path)


KEYS = {"RSA": keygen("rsa", "rsa"), "RSA2": keygen("rsa2", "rsa"), "ED": keygen("ed", "ed25519")}
SERVE = {"keys": ["RSA", "ED"]}
AUTH = []


class Server(paramiko.ServerInterface):
    def get_allowed_auths(self, u):
        return "password"

    def check_auth_password(self, u, p):
        AUTH.append(p == "LOGINTOKEN")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, cid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, ch):
        return True


def shell(ch):
    try:
        ch.send(b"leaf1#")
        buf = b""
        while True:
            d = ch.recv(1024)
            if not d:
                return
            buf += d
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.rstrip(b"\r")
                extra = b"\r\nWidth set to 511 columns." if line.startswith(b"terminal width") else (
                    b"\r\nPagination disabled." if line.startswith(b"terminal length") else b"")
                ch.send(line + extra + b"\r\nleaf1#")
    except Exception:
        pass


def serve(sock):
    while True:
        c, _ = sock.accept()

        def run(c=c):
            # OpenSSH 8.8 and later do not offer ssh-rsa as a host-key algorithm.
            t = paramiko.Transport(c, disabled_algorithms={"keys": ["ssh-rsa"]})
            for k in SERVE["keys"]:
                t.add_server_key(KEYS[k])
            try:
                t.start_server(server=Server())
                ch = t.accept(10)
                if ch:
                    shell(ch)
            except Exception:
                pass

        threading.Thread(target=run, daemon=True).start()


ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(20)
PORT = ls.getsockname()[1]
threading.Thread(target=serve, args=(ls,), daemon=True).start()


class Agent:
    def token(self, device, enable=False, ttl=None):
        return Token("leaf1", "127.0.0.1", "arista_eos", "alice", "LOGINTOKEN", "")


KH = os.path.join(WORK, "kh")
CFG = os.path.join(WORK, "cfg")
with open(CFG, "w", encoding="ascii") as f:
    f.write(f"UserKnownHostsFile {KH}\nGlobalKnownHostsFile /dev/null\n")


def pub(k):
    return f"{k.get_name()} {k.get_base64()}"


def connect(port=PORT):
    return p49netmiko.connect("leaf1", agent=Agent(), ssh_config=CFG, port=port, fast_cli=True, conn_timeout=5)


def accepted(label, fn):
    before = len(AUTH)
    try:
        fn()
    except Exception as e:
        failures.append(f"{label}: refused ({type(e).__name__}); wanted accepted")
        return
    if AUTH[before:] != [True]:
        failures.append(f"{label}: accepted without exactly one token login: {AUTH[before:]}")


def refused(label, fn, code="host_key_changed"):
    before = len(AUTH)
    try:
        fn()
    except HostKeyError as e:
        if e.code != code:
            failures.append(f"{label}: HostKeyError {e.code}; wanted {code}")
        if AUTH[before:]:
            failures.append(f"{label}: the server saw an authentication attempt")
        return
    except Exception as e:
        failures.append(f"{label}: {type(e).__name__}, not a HostKeyError")
        return
    failures.append(f"{label}: accepted; wanted refused")


def scp(conn):
    SCPConn(conn).close()


def file_keys(*lines):
    with open(KH, "w", encoding="ascii") as f:
        f.write("".join(f"{line}\n" for line in lines))


# Part 1: a Paramiko server.
try:
    # Only the device's RSA key is filed, and it also offers Ed25519.
    file_keys(f"leaf1 {pub(KEYS['RSA'])}")
    SERVE["keys"] = ["RSA", "ED"]
    conn = None

    def first():
        global conn
        conn = connect()

    accepted("connect, filed RSA, device also offers ed25519", first)
    if conn is not None:
        accepted("reconnect, filed RSA, device also offers ed25519", conn.establish_connection)
        accepted("SCP, filed RSA, device also offers ed25519", lambda: scp(conn))
        SERVE["keys"] = ["RSA2", "ED"]
        refused("reconnect, another RSA key", conn.establish_connection)
        refused("SCP, another RSA key", lambda: scp(conn))
        SERVE["keys"] = ["RSA", "ED"]
        accepted("reconnect, the filed key again", conn.establish_connection)
        # revoked since the connect: refused before any dial, so before authentication
        with open(KH, "a", encoding="ascii") as f:
            f.write(f"@revoked * {pub(KEYS['RSA'])}\n")
        refused("reconnect, key revoked since", conn.establish_connection, "host_key_revoked")
        refused("SCP, key revoked since", lambda: scp(conn), "host_key_revoked")
        conn.disconnect()
        with open(KH, encoding="ascii") as f:
            if f.read() != f"leaf1 {pub(KEYS['RSA'])}\n@revoked * {pub(KEYS['RSA'])}\n":
                failures.append("known_hosts changed")

    # A rotation left two RSA keys filed; the device presents the one filed first. The connect pins it, so a
    # reconnect and an SCP succeed whichever order the keys sort in.
    real = min(("RSA", "RSA2"), key=lambda n: KEYS[n].get_base64())
    other = "RSA2" if real == "RSA" else "RSA"
    file_keys(f"leaf1 {pub(KEYS[real])}", f"leaf1 {pub(KEYS[other])}")
    SERVE["keys"] = [real, "ED"]
    conn = None
    accepted("connect, two RSA keys filed", first)
    if conn is not None:
        accepted("reconnect, two RSA keys filed", conn.establish_connection)
        accepted("SCP, two RSA keys filed", lambda: scp(conn))
        conn.disconnect()
finally:
    pass


# Part 2: a real OpenSSH sshd.
def sshd_part():
    sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if os.access("/usr/sbin/sshd", os.X_OK) else None)
    if not sshd:
        return
    d = os.path.join(WORK, "sshd")
    os.mkdir(d)
    for name, kind in (("h_rsa", "rsa"), ("h_ed", "ed25519")):
        subprocess.run(["ssh-keygen", "-q", "-t", kind, "-N", "", "-f", os.path.join(d, name)], check=True)

    def pubfile(name):
        with open(os.path.join(d, name + ".pub"), encoding="ascii") as f:
            return " ".join(f.read().split()[:2])

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    sp = probe.getsockname()[1]
    probe.close()
    cfg, log = os.path.join(d, "sshd_config"), os.path.join(d, "log")
    base = (f"Port {sp}\nListenAddress 127.0.0.1\nHostKey {d}/h_rsa\nHostKey {d}/h_ed\nPidFile {d}/pid\n"
            "UsePAM no\nStrictModes no\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\n")
    # sshd 9.8 and later penalise a source after failed logins; 8.5 does not know the option.
    for extra in ("PerSourcePenalties no\nMaxStartups 100:30:200\n", "MaxStartups 100:30:200\n"):
        with open(cfg, "w", encoding="ascii") as f:
            f.write(base + extra)
        if subprocess.run([sshd, "-t", "-f", cfg], capture_output=True).returncode == 0:
            break
    proc = subprocess.Popen([sshd, "-D", "-f", cfg, "-E", log], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if proc.poll() is not None:
                print("sshd would not start as this user: its part is skipped", file=sys.stderr)
                return
            try:
                socket.create_connection(("127.0.0.1", sp), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            print("sshd did not listen: its part is skipped", file=sys.stderr)
            return

        def attempts():
            time.sleep(0.3)  # sshd logs a moment after the connection ends
            with open(log, encoding="utf-8", errors="replace") as f:
                return len(re.findall(r"Invalid user|Failed password", f.read()))

        captured = []
        real_handler = netmiko.ConnectHandler

        def spy(**kw):
            c = real_handler(**kw)
            captured.append(c)
            return c

        netmiko.ConnectHandler = spy
        rsa, ed = pubfile("h_rsa"), pubfile("h_ed")
        wrong = pub(KEYS["RSA2"])

        def passed(label, fn):
            """The host key was accepted: only the login (which an unprivileged sshd cannot check) failed."""
            before = attempts()
            try:
                fn()
            except HostKeyError as e:
                failures.append(f"sshd {label}: HostKeyError {e.code}; wanted past the host key check")
                return
            except Exception as e:
                if "Authentication" not in type(e).__name__:
                    failures.append(f"sshd {label}: {type(e).__name__}, not an authentication failure")
                    return
            if attempts() <= before:
                failures.append(f"sshd {label}: no login attempt reached sshd")

        def blocked(label, fn):
            before = attempts()
            try:
                fn()
            except HostKeyError as e:
                if e.code != "host_key_changed":
                    failures.append(f"sshd {label}: HostKeyError {e.code}; wanted host_key_changed")
            except Exception as e:
                failures.append(f"sshd {label}: {type(e).__name__}, not a HostKeyError")
            else:
                failures.append(f"sshd {label}: accepted; wanted refused")
            if attempts() != before:
                failures.append(f"sshd {label}: sshd saw a login attempt")

        for label, filed in (("RSA filed, both offered", rsa), ("ed25519 filed, both offered", ed)):
            file_keys(f"leaf1 {filed}")
            passed(f"connect, {label}", lambda: connect(sp))
        file_keys(f"leaf1 {wrong}")
        blocked("connect, another RSA key filed", lambda: connect(sp))

        # Rebuilds. An unprivileged sshd cannot accept the token, so the connect never finishes and never pins;
        # the pin connect makes after a login is applied to the conn that was built.
        file_keys(f"leaf1 {rsa}")
        passed("connect, RSA filed", lambda: connect(sp))
        conn = captured[-1]
        field = f"[127.0.0.1]:{sp}"

        def pinned(key):
            kh = hostkeys.KnownHosts("leaf1", (key,), (), (), "", False, False, KH)
            p49netmiko._pin(conn, kh, {key}, "leaf1", field, lambda: kh)

        pinned(rsa)
        passed("reconnect, RSA pinned, both offered", conn.establish_connection)
        passed("SCP, RSA pinned, both offered", lambda: scp(conn))
        pinned(wrong)
        blocked("reconnect, another RSA key pinned", conn.establish_connection)
        blocked("SCP, another RSA key pinned", lambda: scp(conn))
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


try:
    sshd_part()
finally:
    shutil.rmtree(WORK, ignore_errors=True)

for line in failures:
    print("FAIL", line)
sys.exit(1 if failures else 0)
