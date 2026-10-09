"""Netmiko through port49 (design §17, "Integration examples"; plan 9a).

`port49 token --json DEVICE` mints through your agent and prints the
broker's answer on stdout: the username to present beside the token, the
token, the device's address and its platform. The token is never in argv or
the environment, and this module never prints it.

The device's SSH host key is checked against the key port49 pinned for it
with `port49 devices trust DEVICE`; a key never seen is never accepted
(design §17). Netmiko looks a key up by the address it connects to, so the
pin, which port49 keeps under the device's inventory name, is written under
the address the broker gave, to a private temporary file for this one
connection.
"""

import base64
import binascii
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile

# port49's platform names to Netmiko's device types.
DEVICE_TYPES = {
    "arista_eos": "arista_eos",
    "cisco_nxos": "cisco_nxos",
    "cisco_iosxe": "cisco_xe",
    "juniper_junos": "juniper_junos",
}

# The host fields port49 pins (internal/hostkeys ValidName): no pattern, list, hash or negation.
VALID_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def pins_path():
    """port49's pinned host keys file: $XDG_CONFIG_HOME/port49/known_hosts."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "port49", "known_hosts")


def check_private(path):
    """Refuse a pins file, or its directory, that anyone but you or root can write, as port49 itself does
    (policy engine spec §13 decision 42 ruling 6): whoever can write it chooses which keys are accepted.
    port49 also checks every directory above; this example checks the file and its own directory only."""
    for p in (path, os.path.dirname(os.path.abspath(path))):
        st = os.lstat(p)
        if p == path and not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"{p} is not a regular file; port49's pins are read only from one")
        if st.st_uid not in (os.getuid(), 0) or st.st_mode & 0o022:
            raise RuntimeError(f"{p} can be written by someone other than you; port49 refuses it, and so does this example")


def why_unparseable(line):
    """Why a pins line is not a plain "name key", or None if it is. Anything else OpenSSH
    would read differently from port49, so the whole file is refused rather than skipped."""
    fields = line.split()
    if fields[0].startswith("@"):
        return f"it carries the marker {fields[0]}"
    if len(fields) < 3:
        return "it is not 'name keytype key'"
    if not VALID_NAME.match(fields[0]):
        return f"its host field {fields[0]!r} is a pattern, a list, a hash, a negation or a port form"
    try:
        blob = base64.b64decode(fields[2], validate=True)
        (n,) = struct.unpack(">I", blob[:4])
        embedded = blob[4:4 + n].decode("ascii")
    except (binascii.Error, struct.error, UnicodeDecodeError):
        return "its key does not parse"
    if embedded != fields[1]:
        return "its key type does not match its key"
    return None


def pinned_keys(device, pins=None):
    """The keys pinned for device, whose name matches without regard to case, as OpenSSH's does.
    A file with a line this cannot fully parse is refused whole, naming the line."""
    pins = pins or pins_path()
    if not os.path.exists(pins):
        return []
    check_private(pins)
    keys = []
    with open(pins, encoding="ascii", errors="replace") as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            why = why_unparseable(line)
            if why:
                raise RuntimeError(
                    f"{pins}: line {number}: {why}: port49 owns this file and OpenSSH would read this line "
                    "differently, so this example will not guess. Remove it, or move it to ~/.ssh/known_hosts")
            fields = line.split()
            if fields[0].lower() == device.lower():
                keys.append(fields[1] + " " + fields[2])
    return keys


def token(device, enable=False, port49="port49"):
    """The broker's answer for device, minted through your agent."""
    cmd = [port49, "token", "--json"] + (["--enable"] if enable else []) + [device]
    # stdout only: port49 writes the token there and explains every failure on stderr
    # ("run port49 login", a deny's reason), which is left to reach the operator's terminal.
    try:
        out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True).stdout
    except FileNotFoundError:
        raise RuntimeError("port49 is not on PATH (or pass port49=<path>)") from None
    try:
        return json.loads(out)
    except ValueError:
        raise RuntimeError(f"{port49} token --json {device} printed something that is not JSON") from None


def is_host_key_mismatch(exc):
    """Whether exc, or what it wraps, is Paramiko's BadHostKeyException. Netmiko may wrap it in its
    own timeout or authentication exception, so the chain is walked, by type name and then by the
    message Paramiko gives ("Host key for server ... does not match")."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if type(exc).__name__ == "BadHostKeyException" or ("Host key for server" in str(exc) and "does not match" in str(exc)):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def connect(device, enable=False, port49="port49", pins=None):
    """A Netmiko connection to device, logged in with a fresh token."""
    from netmiko import ConnectHandler

    keys = pinned_keys(device, pins)
    if not keys:
        raise RuntimeError(f"no host key is pinned for {device}: run 'port49 devices trust {device}' first")
    tok = token(device, enable, port49)
    device_type = DEVICE_TYPES.get(tok.get("platform"))
    if device_type is None:
        raise RuntimeError(f"{device}: platform {tok.get('platform')!r} has no Netmiko device type in this example")
    address = tok["address"]
    # mkdtemp makes the directory 0700 and the file inside is made 0600, so the pin is private
    # to this user for the connection's life.
    tmp = tempfile.mkdtemp(prefix="port49-")
    try:
        known = os.path.join(tmp, "known_hosts")
        fd = os.open(known, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            for k in keys:
                f.write(f"{address} {k}\n")
        try:
            return ConnectHandler(
                device_type=device_type,
                host=address,
                username=tok["username"],
                password=tok["login"],
                secret=tok.get("enable", ""),
                ssh_strict=True,           # a key not in the file is refused
                system_host_keys=False,    # ~/.ssh/known_hosts is not consulted
                alt_host_keys=True,
                alt_key_file=known,
                use_keys=False,            # spec §15 L51: refused keys count against the device's limit
                allow_agent=False,
            )
        except Exception as e:
            if is_host_key_mismatch(e):
                # Never the original's text: only the device and the fix.
                raise RuntimeError(
                    f"{device}: the SSH host key does not match the pin. If the device's key changed on purpose, "
                    f"compare its key on the console (NX-OS prints a fingerprint, the others the key; see "
                    f"'port49 devices trust' help) and run 'port49 devices trust --replace {device}'") from e
            raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
