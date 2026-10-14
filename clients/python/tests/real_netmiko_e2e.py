"""Real Netmiko and Paramiko against a local Paramiko SSH server (run by test_netmiko_real.py, which skips
without them): a reconnect and an SCP on a connect()ed connection negotiate the filed key type, and a key that
is not the filed one is refused before any authentication. The server records whether the password it got was
the token, never the password."""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import paramiko  # noqa: E402
from netmiko.scp_handler import SCPConn  # noqa: E402

from port49 import Token  # noqa: E402
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
            t = paramiko.Transport(c)
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


def connect():
    return p49netmiko.connect("leaf1", agent=Agent(), ssh_config=CFG, port=PORT, fast_cli=True, conn_timeout=5)


def accepted(label, fn):
    before = len(AUTH)
    try:
        fn()
    except Exception as e:
        failures.append(f"{label}: refused ({type(e).__name__}); wanted accepted")
        return
    if AUTH[before:] != [True]:
        failures.append(f"{label}: accepted without exactly one token login: {AUTH[before:]}")


def refused(label, fn):
    before = len(AUTH)
    try:
        fn()
    except Exception:
        if AUTH[before:]:
            failures.append(f"{label}: the server saw an authentication attempt")
        return
    failures.append(f"{label}: accepted; wanted refused")


def scp(conn):
    SCPConn(conn).close()


try:
    # Only the device's RSA key is filed, and it also offers Ed25519.
    with open(KH, "w", encoding="ascii") as f:
        f.write(f"leaf1 {pub(KEYS['RSA'])}\n")
    conn = connect()
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
    refused("reconnect, key revoked since", conn.establish_connection)
    refused("SCP, key revoked since", lambda: scp(conn))
    conn.disconnect()
    with open(KH, encoding="ascii") as f:
        if f.read() != f"leaf1 {pub(KEYS['RSA'])}\n@revoked * {pub(KEYS['RSA'])}\n":
            failures.append("known_hosts changed")
finally:
    shutil.rmtree(WORK, ignore_errors=True)

for line in failures:
    print("FAIL", line)
sys.exit(1 if failures else 0)
