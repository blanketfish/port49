"""Netmiko through port49 (design §17; decision 46 rulings 13 and 16).

The token comes from your agent through `port49 token --json`; the device's key
is OpenSSH's known_hosts entry under its inventory name: the only key accepted
once filed, and filed at first contact, before authentication, unless revoked.
The token is never printed."""

import os
import shutil
import sys
import tempfile

from . import hostkeys
from .client import Agent
from .errors import HostKeyError

DEVICE_TYPES = {"arista_eos": "arista_eos", "cisco_nxos": "cisco_nxos", "cisco_iosxe": "cisco_xe",
                "juniper_junos": "juniper_junos"}

# What connect sets and a caller may not: host keys, and no key offered (L51: every refused key counts
# against the device's login-attempt limit); and ssh_config_file and sock, either of which could steer
# Paramiko to another host than the address the key was checked for (pre-flight M16); and ip, which Netmiko
# sets self.host from before host (base_connection.py:346-349), so a caller's ip= would do the same (N4).
OWNED = {"ssh_strict", "system_host_keys", "alt_host_keys", "alt_key_file", "use_keys", "allow_agent", "host",
         "username", "password", "secret", "device_type", "auto_connect", "ssh_config_file", "sock", "ip"}


class FirstContact:
    """Paramiko's missing-host-key policy for a device with no key filed (decision 46 ruling 13). Paramiko
    calls it with the key the device presented, after the key exchange and before any authentication
    (Paramiko 4.0.0 client.py:455-460), so the token never goes to a key refused here. A key an @revoked
    line or the operator's RevokedHostKeys revokes is refused; any other is filed under the inventory name,
    as OpenSSH's accept-new files it, before the login goes on."""

    def __init__(self, kh, device, stderr=None):
        self.kh, self.device, self.stderr = kh, device, stderr

    def missing_host_key(self, client, hostname, key):
        keytype, key_b64 = key.get_name(), key.get_base64()
        if hostkeys.is_revoked(self.kh, keytype, key_b64):
            raise HostKeyError("host_key_revoked", f"{hostname} presents a {keytype} key that is revoked (an "
                               f"@revoked line, or your RevokedHostKeys): it was not filed, and the token was not "
                               f"sent", self.device)
        hostkeys.remember(self.kh, keytype, key_b64, stderr=self.stderr)


def is_host_key_failure(exc):
    """Whether exc, or what it wraps, is Paramiko refusing the host key: BadHostKeyException, for a changed
    key and for a key of another type alike while any key is held for the address (Paramiko 4.0.0
    client.py:461-466), or an SSHException saying the server is not in known_hosts (RejectPolicy, should
    nothing be held). Netmiko may wrap either, so the chain is walked."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        text = str(exc)
        if type(exc).__name__ == "BadHostKeyException" or ("Host key for server" in text and "does not match" in text) \
                or "not found in known_hosts" in text:
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def connect(device, *, enable=False, agent=None, ssh_config=None, **netmiko_kwargs):
    from netmiko import ConnectHandler

    owned = OWNED & set(netmiko_kwargs)
    if owned:
        raise ValueError(f"port49.netmiko.connect sets {', '.join(sorted(owned))} itself")
    if not hostkeys.valid_name(device):
        # Before the mint: nothing is minted for a name known_hosts would misread (pre-flight I6, M14).
        raise HostKeyError("device_name", f"{str(device)[:64]!r}: {hostkeys.NAME_RULE}")
    tok = (agent or Agent()).token(device, enable=enable)
    device_type = DEVICE_TYPES.get(tok.platform)
    if device_type is None:
        raise ValueError(f"{device}: platform {tok.platform!r} has no Netmiko device type here")
    port = int(netmiko_kwargs.get("port", 22))
    # After the mint, since ssh -G reads the address it gives (Match host): a refusal from here on leaves
    # the token unused, to expire.
    kh = hostkeys.lookup(device, tok.address, port=port, username=tok.username, ssh_config=ssh_config)
    if not kh.keys and kh.authorities:
        raise HostKeyError("host_key_uncheckable", f"a {kh.authorities[0].split()[0]} line in your known_hosts "
                           f"covers {kh.name}, and Paramiko cannot check a host certificate: file the device's own "
                           f"key under {kh.name}, or use port49 ssh", device)
    if not kh.keys and kh.strict:
        raise HostKeyError("host_key_unknown", f"no key is filed under {kh.name} and your ssh_config says "
                           f"StrictHostKeyChecking yes", device)
    field = tok.address if port == 22 else f"[{tok.address}]:{port}"
    tmp = tempfile.mkdtemp(prefix="port49-")  # 0700; the file inside is 0600
    try:
        known = os.path.join(tmp, "known_hosts")
        fd = os.open(known, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write("".join(f"{field} {k}\n" for k in kh.keys))
        conn = ConnectHandler(device_type=device_type, host=tok.address, username=tok.username,
                              password=tok.login, secret=tok.enable or "",
                              ssh_strict=bool(kh.keys), system_host_keys=False, alt_host_keys=True,
                              alt_key_file=known, use_keys=False, allow_agent=False, auto_connect=False,
                              **netmiko_kwargs)
        if not kh.keys:
            # A first contact: the presented key is checked and filed before authentication, not after
            # the login (pre-flight C1).
            conn.key_policy = FirstContact(kh, device, stderr=sys.stderr)
        try:
            conn._open()  # what auto_connect=True runs: the connection, then the session's preparation
        except BaseException as e:
            try:
                conn.disconnect()
            except Exception:
                pass
            if isinstance(e, HostKeyError):
                raise
            if is_host_key_failure(e):
                raise HostKeyError("host_key_changed", f"the key filed under {kh.name} is not the one {tok.address} "
                                   f"presents: either the device's key changed, or the address is not the device. "
                                   f"Verify the key on its console, then run 'ssh-keygen -R {kh.name}'", device) from None
            raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return conn
