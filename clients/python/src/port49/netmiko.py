"""Netmiko through port49 (design §17; decision 46 rulings 13 and 16).

The token comes from your agent through `port49 token --json`; the device's key
is OpenSSH's known_hosts entry under its inventory name: the only key accepted
once filed, and filed at first contact, before authentication, unless revoked.
The token is never printed."""

import base64
import inspect
import os
import shutil
import sys
import tempfile
import traceback

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
         "username", "password", "secret", "device_type", "auto_connect", "ssh_config_file", "sock", "ip",
         "pkey", "key_file"}  # Paramiko tries both even with look_for_keys off (M6)


class FirstContact:
    """Paramiko's missing-host-key policy for a device with no key filed (decision 46 ruling 13). Paramiko
    calls it with the key the device presented, after the key exchange and before any authentication
    (Paramiko 4.0.0 client.py:455-460), so the token never goes to a key refused here. A key an @revoked
    line or the operator's RevokedHostKeys revokes is refused; any other is filed under the inventory name,
    as OpenSSH's accept-new files it, before the login goes on."""

    def __init__(self, kh, device, stderr=None, ssh_keygen="ssh-keygen"):
        self.kh, self.device, self.stderr, self.ssh_keygen = kh, device, stderr, ssh_keygen
        self.filed = None  # "type base64" of the key this policy filed

    def missing_host_key(self, client, hostname, key):
        keytype, key_b64 = key.get_name(), key.get_base64()
        if hostkeys.is_revoked(self.kh, keytype, key_b64, ssh_keygen=self.ssh_keygen):
            raise HostKeyError("host_key_revoked", f"{hostname} presents a {keytype} key that is revoked (an "
                               f"@revoked line, or your RevokedHostKeys): it was not filed, and the token was not "
                               f"sent", self.device)
        hostkeys.remember(self.kh, keytype, key_b64, stderr=self.stderr, ssh_keygen=self.ssh_keygen)
        self.filed = f"{keytype} {key_b64}"


class Pinned:
    """The key policy of the connection connect returns, for every later SSH connection it makes (Netmiko's
    establish_connection() after a drop, SCPConn): no host keys are loaded, so Paramiko asks this for each,
    and it accepts only a key filed under the device's name, held in memory (fix round 1, C1). Nothing is
    filed here."""

    def __init__(self, keys, name, device=None, refresh=None):
        self.keys, self.name, self.device, self.refresh = frozenset(keys), name, device, refresh

    def current(self):
        """The pinned keys that are still filed and not revoked, read afresh (an @revoked line or a
        RevokedHostKeys entry added since the connect is honoured at the next one; fix round 2, N3). Raises
        when none is left."""
        if self.refresh is None:
            return self.keys
        kh = self.refresh()  # raises host_key_revoked when every key filed is revoked
        live = self.keys & set(kh.keys)
        if not live:
            revoked = any(hostkeys.is_revoked(kh, *k.split(" ", 1)) for k in self.keys)
            raise HostKeyError("host_key_revoked" if revoked else "host_key_unknown",
                               f"no key this connection was made with is filed under {self.name} and unrevoked "
                               f"any more; verify the device's key on its console", self.device)
        return live

    def missing_host_key(self, client, hostname, key):
        if f"{key.get_name()} {key.get_base64()}" not in self.current():
            raise HostKeyError("host_key_changed", f"{hostname} presents a key that is not one filed under "
                               f"{self.name}: either the device's key changed, or this is not the device. Verify the "
                               f"key on its console", self.device)


def _load_pinned(client, field, keys):
    """Hold keys in client's host keys under field, so Paramiko offers the filed key types first and compares
    the key itself, as on the first connect (fix round 2, N1). A type Paramiko cannot load is skipped."""
    import paramiko

    held = client.get_host_keys()
    for k in sorted(keys):
        keytype, blob = k.split(" ", 1)
        try:
            held.add(field, keytype, paramiko.PKey.from_type_string(keytype, base64.b64decode(blob)))
        except Exception:
            continue


def _chain_text(exc):
    seen, texts = set(), []
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        texts.append((type(exc).__name__, str(exc)))
        exc = exc.__cause__ or exc.__context__
    return texts


def is_key_type_unloadable(exc):
    """Whether exc is RejectPolicy's "not found in known_hosts" with no changed key behind it: every key filed
    is of a type Paramiko cannot load (ssh-dss, sk-*), so nothing was held for the address (M2)."""
    texts = _chain_text(exc)
    return any("not found in known_hosts" in t for _, t in texts) and not any(
        n == "BadHostKeyException" or ("Host key for server" in t and "does not match" in t) for n, t in texts)


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
                or "not found in known_hosts" in text or "no acceptable host key" in text:
            return True
        exc = exc.__cause__ or exc.__context__
    return False


# Every host-key algorithm Paramiko 4 and 5 offer, and the one key type each belongs to. ssh-dss is not
# among them (Paramiko 5 does not offer it), so a DSA-only filed key narrows nothing.
_HOST_KEY_ALGORITHMS = {"ssh-ed25519": "ssh-ed25519", "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256",
                        "ecdsa-sha2-nistp384": "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521": "ecdsa-sha2-nistp521",
                        "rsa-sha2-512": "ssh-rsa", "rsa-sha2-256": "ssh-rsa", "ssh-rsa": "ssh-rsa"}


def _checkable_filed(keys):
    """Whether any of keys ("type base64") is of a type Paramiko can load and check a host key against."""
    return any(k.split(" ", 1)[0] in _HOST_KEY_ALGORITHMS.values() for k in keys)


def host_key_algorithms_off(keys):
    """The host-key algorithms to disable so that only the key types filed in keys ("type base64") are
    negotiated (fix round 3, N1). Paramiko puts a held key's name first in its list, and for RSA that is
    ssh-rsa, which OpenSSH 8.8 and later do not offer: the server then settles on ed25519, which is not the filed
    type, and the connection is refused although the device is the right one. ssh-rsa filed allows all three
    RSA algorithms. Nothing is disabled when no filed type is one Paramiko offers."""
    filed = {k.split(" ", 1)[0] for k in keys}
    off = sorted(a for a, t in _HOST_KEY_ALGORITHMS.items() if t not in filed)
    return off if len(off) < len(_HOST_KEY_ALGORITHMS) else []


def _pin(conn, kh, accepted, device, field, refresh):
    """From here on every client conn builds (a reconnect, SCP) takes the key conn's connect accepted, and
    nothing else: the temp known_hosts goes, the pinned key is loaded into the new client (so the filed key type
    is the one negotiated), the files are read again (a key revoked or removed since is not loaded; with none
    left nothing connects), and a host-key mismatch is a HostKeyError, which Netmiko lets through, not the
    timeout it reports an SSHException as, or Paramiko's own exception (fix rounds 1 to 3)."""
    conn.alt_host_keys, conn.alt_key_file = False, ""
    pin = conn.key_policy = Pinned(accepted, kh.name, device, refresh=refresh)
    build = conn._build_ssh_client

    def rebuild():
        client = build()
        _load_pinned(client, field, pin.current())
        inner = getattr(client, "connect", None)
        if inner is not None:
            def connect_(*args, **kwargs):
                try:
                    return inner(*args, **kwargs)
                except Exception as e:
                    if isinstance(e, HostKeyError) or not is_host_key_failure(e):
                        raise
                    raise HostKeyError("host_key_changed", _CHANGED.format(name=kh.name, address=field),
                                       device) from None
            client.connect = connect_
        return client

    conn._build_ssh_client = rebuild
    return pin


_CHANGED = ("the key {address} presents is not the one filed under {name}: either the device's key changed, or "
            "the address is not the device. Verify the key on its console, then run 'ssh-keygen -R {name}'")


_SUSPENDABLE = inspect.CO_GENERATOR | inspect.CO_COROUTINE | inspect.CO_ASYNC_GENERATOR


def _clear_frames(exc, stop):
    """Clear the locals of every frame in exc's traceback, and in its causes' and contexts', up to stop: the
    exception the caller was handling when it called connect, whose frames are the caller's. connect's
    frames held the token, and Paramiko's hold it as the password; a traceback printed with its locals, or
    an error tracker that records them, shows none of it. Files and line numbers stay."""
    todo, seen = [exc], set()
    while todo:
        e = todo.pop()
        if e is None or e is stop or id(e) in seen:
            continue
        seen.add(id(e))
        tb = e.__traceback__
        while tb is not None:
            frame = tb.tb_frame
            # A generator's or coroutine's frame is left alone: on Python 3.10 to 3.12, clear() on a suspended
            # one finalizes the generator (3.13 raises instead). Connect's frames and the libraries' on the
            # login path are plain functions.
            if not frame.f_code.co_flags & _SUSPENDABLE:
                try:
                    frame.clear()
                except RuntimeError:  # still executing: connect's own
                    pass
            tb = tb.tb_next
        todo += [e.__cause__, e.__context__]


def connect(device, *, enable=False, agent=None, ssh_config=None, **netmiko_kwargs):
    """A Netmiko connection to device, logged in with a port49 token from agent (default Agent(): a
    person's). The token goes to Netmiko, as its password and secret, and nowhere else: no return value,
    closure, exception or traceback local of connect's holds it."""
    outer = sys.exc_info()[1]
    try:
        return _connect(device, enable, agent, ssh_config, netmiko_kwargs)
    except BaseException as e:
        _clear_frames(e, outer)
        raise


def _connect(device, enable, agent, ssh_config, netmiko_kwargs):
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
    address, username = tok.address, tok.username
    try:
        port = int(netmiko_kwargs.get("port", 22))
    except (TypeError, ValueError):
        raise ValueError("port must be a number") from None
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
        if kh.keys:
            # Only the filed key types are negotiated, on this connect and on every rebuild (Netmiko passes
            # disabled_algorithms to each); the caller's own entries are kept.
            disabled = dict(getattr(conn, "disabled_algorithms", None) or {})
            disabled["keys"] = sorted(set(disabled.get("keys") or ()) | set(host_key_algorithms_off(kh.keys)))
            conn.disabled_algorithms = disabled
        first = None
        if not kh.keys:
            # A first contact: the presented key is checked and filed before authentication, not after
            # the login (pre-flight C1).
            first = conn.key_policy = FirstContact(kh, device, stderr=sys.stderr)
        try:
            conn._open()  # what auto_connect=True runs: the connection, then the session's preparation
            # Every later connection of conn (a reconnect, SCP) takes the filed key only, from memory: the
            # temp file goes, and nothing may name it (fix round 1, C1).
            # The key the connect accepted, not every key filed (a rotation can leave two of one type).
            accepted = set(kh.keys) or ({first.filed} if first and first.filed else set())
            try:
                key = conn.remote_conn_pre.get_transport().get_remote_server_key()
                accepted = {f"{key.get_name()} {key.get_base64()}"}
            except Exception:
                pass
            _pin(conn, kh, accepted, device, field, lambda: hostkeys.lookup(
                device, address, port=port, username=username, ssh_config=ssh_config))
        except BaseException as e:
            try:
                conn.disconnect()
            except Exception:
                pass
            if isinstance(e, HostKeyError):
                raise
            if is_key_type_unloadable(e):
                raise HostKeyError("host_key_uncheckable", f"Paramiko held no key for {tok.address}: the keys filed "
                                   f"under {kh.name} may be of a type it cannot load (ssh-dss, a security-key type), "
                                   f"so the key the device presented could not be compared with them; the token was "
                                   f"not sent. Use port49 ssh for this device", device) from None
            if not _checkable_filed(kh.keys) and any("no acceptable host key" in t for _, t in _chain_text(e)):
                # Nothing checkable is filed (nothing, or only types Paramiko cannot load), so nothing is known
                # to have changed: the device offers only key types Paramiko cannot check (DSA, a security-key
                # type).
                raise HostKeyError("host_key_uncheckable", f"{tok.address} offers no host-key type Paramiko can "
                                   f"check; the token was not sent. Use port49 ssh for this device", device) from None
            if is_host_key_failure(e):
                raise HostKeyError("host_key_changed", f"the key filed under {kh.name} is not the one {tok.address} "
                                   f"presents: either the device's key changed, or the address is not the device. "
                                   f"Verify the key on its console, then run 'ssh-keygen -R {kh.name}'", device) from None
            raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return conn
