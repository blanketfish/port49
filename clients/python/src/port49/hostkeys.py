"""Host keys for the Python client (decision 46 ruling 13): OpenSSH's own
files and settings, read through OpenSSH's own tools, and accept-new under
the device's inventory name, the name `port49 ssh` files keys under.

`ssh -G` reads the operator's ssh_config as ssh would; `ssh-keygen -F` finds
the lines filed under a name, hashed or not, patterns included; `ssh-keygen -Q`
reads a RevokedHostKeys file. Nothing here parses ssh_config, matches
known_hosts patterns or reads a KRL itself. What this client cannot honour as
ssh would (a KnownHostsCommand, a RevokedHostKeys ssh-keygen cannot read, a
known_hosts setting that cannot be told apart from another) is refused, never
passed. The refusals follow `port49 ssh`'s (cmd/port49/ssh.go), so the two
clients agree on what is unsafe."""

import base64
import fcntl
import hashlib
import hmac
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace

from . import _run
from .errors import HostKeyError

# Decision 42 ruling 8, `port49 ssh`'s sshName: known_hosts reads '*', '?', '!', ',' and '[' as patterns, and a
# leading '@' or '|' as a marker or a hash, so a name holding one could file a key for other devices.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
NAME_RULE = ("port49 takes devices named with letters, digits, '.', '_' and '-' only (decision 42 ruling 8), since "
             "the name is written into your known_hosts; use `port49 token` and your own client for it")

# A UserKnownHostsFile that keeps nothing.
_KEEPS_NOTHING = ("/dev/null", "none")

# An operator's HostKeyAlias is filed as it is, so it may not read as a pattern, a marker or a hash, or hold space.
_ALIAS_UNSAFE = re.compile(r"[\s\x00-\x1f\x7f*?!,\[\]]|^[@|]")


# A key type or a base64 blob, as it is written to known_hosts.
_TOKEN = re.compile(r"[A-Za-z0-9@.+/=-]+")


@dataclass(frozen=True)
class KnownHosts:
    name: str
    keys: tuple
    authorities: tuple
    revoked: tuple
    krl: str
    strict: bool
    hash_names: bool
    write_to: str


def valid_name(device):
    """Whether device can be written into known_hosts as a host field, as `port49 ssh`'s sshName says."""
    return isinstance(device, str) and _NAME.fullmatch(device) is not None


def _passwd_home():
    """The home in the passwd entry, which is what ssh's `~` is; $HOME is the caller's to set, and is not it."""
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError):
        return ""


def _expand(fields, home):
    """fields with ssh's `~`, `%d` and `%%` expanded: `ssh -G` prints GlobalKnownHostsFile verbatim (Task 2)."""
    out = []
    for f in fields:
        if f == "~" or f.startswith("~/"):
            f = home + f[1:]
        out.append(re.sub(r"%[d%]", lambda m: home if m.group(0) == "%d" else "%", f))
    return out


def _ssh_g(device, address, port, username, ssh_config, ssh):
    # As `port49 ssh` runs it (sshPolicy): HostName double-quoted with each '%' doubled, since ssh expands
    # %-tokens in it (an IPv6 zone's "%eth0"), and -l, so a `Match user` block reads as it does for the login.
    # Run in this process's environment and with no command, as the Netmiko connection will be.
    argv = [ssh, "-G"] + (["-F", ssh_config] if ssh_config else [])
    argv += ["-o", 'HostName="' + address.replace("%", "%%") + '"'] + (["-l", username] if username else [])
    argv += (["-p", str(port)] if port and port != 22 else []) + ["--", device]
    try:
        out = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
                             check=True).stdout
    except subprocess.CalledProcessError as e:
        said = _run.printable((e.stderr or "").strip(), 300) or f"exit {e.returncode}"
        raise HostKeyError("ssh_config_unread", f"{ssh} -G could not read your ssh_config: {said}", device) from None
    except (OSError, subprocess.SubprocessError) as e:
        raise HostKeyError("ssh_config_unread", f"{ssh} -G could not read your ssh_config: {e}", device) from None
    conf = {}
    for line in out.splitlines():
        k, _, v = line.partition(" ")
        conf[k] = v.strip()
    return conf


def _cannot_keep(first, home):
    """Why the file ssh files a first contact's key in cannot keep it, or "": as `port49 ssh`'s
    knownHostsCannotKeep. It must resolve to a regular file the user can write, or to nothing in an existing
    directory the user can write (ssh makes ~/.ssh in the passwd home as well). /dev/null however written or
    linked, a FIFO, a directory, a dangling link and an unwritable file keep nothing."""
    try:
        resolved = os.path.realpath(first, strict=True)
    except FileNotFoundError:
        if os.path.lexists(first):
            return "it is a link to nothing"
        parent = os.path.dirname(first)
        try:
            real_parent = os.path.realpath(parent, strict=True)
        except FileNotFoundError:
            if home and parent == os.path.join(home, ".ssh") and os.access(home, os.W_OK):
                return ""
            return "its directory does not exist"
        except OSError as e:
            return e.strerror or "its directory cannot be read"
        if not os.path.isdir(real_parent) or not os.access(real_parent, os.W_OK | os.X_OK):
            return f"you cannot create it in {_run.printable(real_parent, 200)}"
        return ""
    except OSError as e:
        return e.strerror or "it cannot be resolved"
    at = f"it is {_run.printable(resolved, 200)}, and " if resolved != first else ""
    try:
        mode = os.stat(resolved).st_mode
    except OSError as e:
        return at + (e.strerror or "it cannot be read")
    if not stat.S_ISREG(mode):
        return at + "that is not a regular file"
    if not os.access(resolved, os.W_OK):
        return at + "you cannot write it"
    return ""


def _read_file(name, path, ssh_keygen, device=None):
    """The (keys, authorities, revoked) that ssh-keygen -F finds under name in one known_hosts file."""
    keys, authorities, revoked = [], [], []
    if not os.path.isfile(path):
        return keys, authorities, revoked
    try:
        r = subprocess.run([ssh_keygen, "-F", name, "-f", path], stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as e:
        raise HostKeyError("known_hosts_unread", f"{ssh_keygen} -F {name} -f {path}: {e}", device) from None
    if r.returncode not in (0, 1):
        raise HostKeyError("known_hosts_unread", f"{ssh_keygen} -F {name} -f {path}: "
                           f"{_run.printable(r.stderr.strip(), 300)}", device)
    for line in r.stdout.splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if fields[0] == "@revoked":
            if len(fields) >= 4:
                revoked.append(f"{fields[2]} {fields[3]}")
        elif fields[0].startswith("@"):
            authorities.append(line)
        elif len(fields) >= 3:
            keys.append(f"{fields[1]} {fields[2]}")
    return keys, authorities, revoked


def lookup(device, address, *, port=22, username=None, ssh_config=None, ssh="ssh", ssh_keygen="ssh-keygen"):
    """What OpenSSH's files hold for device, as ssh reads them, with every revoked key dropped. Refuses,
    before anything connects, what this client cannot honour as ssh does (decision 46 ruling 13)."""
    if not valid_name(device):
        raise HostKeyError("device_name", f"{str(device)[:64]!r}: {NAME_RULE}")  # repr: no newline, no escape
    if '"' in address or "\n" in address:
        raise HostKeyError("address", "the broker gives an address ssh cannot be handed; tell the operator", device)
    conf = _ssh_g(device, address, port, username, ssh_config, ssh)
    command = conf.get("knownhostscommand", "")
    if command and command != "none":
        raise HostKeyError("host_key_uncheckable", "your ssh_config sets KnownHostsCommand, which this client cannot "
                           "run as ssh does, and reading past it could accept a key ssh refuses: use port49 ssh for "
                           "this device, or file its key in a known_hosts file", device)
    # Paramiko dials the address at the given port and follows no proxy: where ssh would go through a bastion,
    # the key it filed or checked would be another host's. Refused, not guessed (fix round 1, I2).
    for setting in ("proxyjump", "proxycommand"):
        if conf.get(setting, "none") != "none":
            raise HostKeyError("host_key_uncheckable", f"your ssh_config reaches {device} through "
                               f"{'ProxyJump' if setting == 'proxyjump' else 'ProxyCommand'}, which this client "
                               f"cannot follow, so a key it filed or checked could be another host's: use port49 ssh "
                               f"for this device", device)
    # Nor does Paramiko bind a source address or interface: on a host with a VRF per site, the default route
    # can reach another site's address (fix round 2, N2).
    for setting, label in (("bindinterface", "BindInterface"), ("bindaddress", "BindAddress")):
        if conf.get(setting, ""):  # a literal "none" is bound as a name, and ssh fails to connect (10.2p1)
            raise HostKeyError("host_key_uncheckable", f"your ssh_config sets {label} for {device}, which this "
                               f"client cannot honour, so the address could be reached over another route than ssh "
                               f"takes: use port49 ssh for this device", device)
    try:
        resolved_port = int(conf.get("port", port))
    except ValueError:
        resolved_port = -1
    if resolved_port != port:
        raise HostKeyError("host_key_uncheckable", f"your ssh_config sets Port {_run.printable(conf.get('port', ''), 16)}"
                           f" for {device} but this client would dial port {port}, a different service: pass "
                           f"port={resolved_port} to connect, or use port49 ssh for this device", device)
    alias = conf.get("hostkeyalias", "")
    if alias and (_ALIAS_UNSAFE.search(alias) or len(alias) > 253):
        raise HostKeyError("host_key_uncheckable", f"your ssh_config's HostKeyAlias {_run.printable(alias, 64)!r} "
                           f"would be filed in known_hosts as a pattern or a marker: use a plain alias, or port49 "
                           f"ssh", device)
    name = alias or device.lower()
    strict = conf.get("stricthostkeychecking") in ("true", "yes")
    home = _passwd_home()
    # 8.5p1 prints no userknownhostsfile line for `none` (Task 2).
    user_value = conf.get("userknownhostsfile", "none")
    user = user_value.split()
    # -G prints a path with a space unquoted, so a value is told from a path holding a space only if every
    # field is an absolute path (-G expands ~ and %d): anything else is refused.
    if any(p != "none" and not p.startswith("/") for p in user) or not user:
        raise HostKeyError("host_key_uncheckable" if strict else "host_keys_not_kept",
                           f"your ssh_config's UserKnownHostsFile {_run.printable(user_value, 200)!r} cannot be told "
                           f"from a list: a path with a space, or a relative path; use absolute paths without "
                           f"spaces", device)
    kept = [p for p in user if p not in _KEEPS_NOTHING]
    if not strict:
        why = "it names no file" if user[0] == "none" else _cannot_keep(user[0], home)
        if why:
            raise HostKeyError("host_keys_not_kept", f"your ssh_config keeps no host keys for {device} "
                               f"(UserKnownHostsFile {_run.printable(user_value, 200)}: {why}): every connection would "
                               f"be a first contact, and a host at the device's address would get the token; point the "
                               f"first UserKnownHostsFile for port49 devices at a file you can write, or set "
                               f"StrictHostKeyChecking yes with a managed GlobalKnownHostsFile", device)
    glob_value = conf.get("globalknownhostsfile", "")
    glob = [p for p in _expand(glob_value.split(), home) if p not in _KEEPS_NOTHING]
    for p in glob:
        if not p.startswith("/") or "%" in p:
            raise HostKeyError("host_key_uncheckable", f"your ssh_config's GlobalKnownHostsFile "
                               f"{_run.printable(glob_value, 200)!r} holds a path this client cannot resolve as ssh "
                               f"does (a relative path, or a % token): use absolute paths, or port49 ssh", device)
    krl = conf.get("revokedhostkeys", "")
    if krl == "none":
        krl = ""
    if krl:
        krl = _expand([krl], home)[0]
        if not krl.startswith("/") or "%" in krl:
            raise HostKeyError("host_key_uncheckable", f"your ssh_config's RevokedHostKeys "
                               f"{_run.printable(krl, 200)!r} is not an absolute path this client can read as ssh "
                               f"does; use port49 ssh", device)
    keys, authorities, revoked = [], [], []
    for path in kept + glob:
        k, a, r = _read_file(name, path, ssh_keygen, device)
        keys += k
        authorities += a
        revoked += r
    kh = KnownHosts(name, (), tuple(authorities), tuple(dict.fromkeys(revoked)), krl, strict,
                    conf.get("hashknownhosts") == "yes", kept[0] if kept else "")
    filed = tuple(k for k in dict.fromkeys(keys) if not is_revoked(kh, *k.split(" ", 1), ssh_keygen=ssh_keygen))
    if keys and not filed:
        raise HostKeyError("host_key_revoked", f"every key filed under {name} is revoked (an @revoked line, or your "
                           f"RevokedHostKeys): verify the device's key on its console before filing another", device)
    return replace(kh, keys=filed)


def is_revoked(kh, keytype, key_b64, *, ssh_keygen="ssh-keygen"):
    """Whether an @revoked line matching kh.name, or the operator's RevokedHostKeys, revokes the key, as ssh
    would refuse it. A RevokedHostKeys that ssh-keygen -Q cannot read is refused, never passed."""
    if f"{keytype} {key_b64}" in kh.revoked:
        return True
    if not kh.krl:
        return False
    why = ""
    with tempfile.TemporaryDirectory(prefix="port49-") as tmp:
        pub = os.path.join(tmp, "key.pub")
        with open(pub, "w", encoding="ascii") as f:
            f.write(f"{keytype} {key_b64}\n")
        try:
            r = subprocess.run([ssh_keygen, "-Q", "-f", kh.krl, pub], stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as e:
            r, why = None, str(e)
    if r is not None:
        if r.returncode in (0, 1):  # measured on 10.2p1: 0 not revoked, 1 revoked
            return r.returncode == 1
        why = _run.printable(r.stderr.strip(), 300) or f"exit {r.returncode}"
    raise HostKeyError("host_key_uncheckable", f"{ssh_keygen} -Q could not read your RevokedHostKeys {kh.krl} "
                       f"({why}), so no key can be checked against it. ssh honours a plain key list there, but "
                       f"this client needs a KRL (ssh-keygen -k); or use port49 ssh for this device")


def hashed(name, salt=None):
    """name as OpenSSH's HashKnownHosts writes it: |1|base64(salt)|base64(HMAC-SHA1(salt, name))."""
    salt = salt if salt is not None else os.urandom(20)
    mac = hmac.new(salt, name.encode("utf-8"), hashlib.sha1).digest()
    return f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(mac).decode()}"


def filed(name, paths, *, ssh_keygen="ssh-keygen"):
    """The (keys, revoked) filed under name across paths, each "<type> <b64>", deduplicated in order. A
    @cert-authority line is not a key and is left out; a path that is not a file holds nothing."""
    keys, revoked = [], []
    for path in paths:
        k, _, r = _read_file(name, path, ssh_keygen)
        keys += k
        revoked += r
    return list(dict.fromkeys(keys)), list(dict.fromkeys(revoked))


def address_entry(address, port):
    """address as known_hosts files it: bare for port 22, else [address]:port."""
    if not isinstance(address, str) or not address or re.search(r'[\s"\x00-\x1f\x7f]', address):
        raise HostKeyError("address", f"{str(address)[:64]!r} cannot be written to known_hosts as an address")
    return address if port == 22 else f"[{address}]:{port}"


def known_files(name, *, ssh="ssh", ssh_config=None):
    """(paths, write_to, hash_names): the known_hosts files `ssh -G name` names (user then global, ~ expanded),
    the first user file, which is where ssh files a key, and HashKnownHosts."""
    conf = _ssh_g(name, name, 22, None, ssh_config, ssh)
    home = _passwd_home()
    user = [p for p in _expand(conf.get("userknownhostsfile", "").split(), home) if p not in _KEEPS_NOTHING]
    glob = [p for p in _expand(conf.get("globalknownhostsfile", "").split(), home) if p not in _KEEPS_NOTHING]
    return user + glob, user[0] if user else "", conf.get("hashknownhosts") == "yes"


def fingerprint(key):
    """SHA256:<unpadded base64> of a key ("<type> <b64>" or the bare blob), as ssh-keygen -lf prints it."""
    try:
        blob = base64.b64decode(key.split()[-1], validate=True)
    except (ValueError, IndexError):
        raise HostKeyError("host_key_uncheckable", "a key that is not base64 cannot be fingerprinted") from None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def append(path, host, keys, *, hash_names, ssh_keygen="ssh-keygen", revoked=None,
           refuse_other_types=False):
    """File each of keys ("<type> <b64>") under host in path: one O_APPEND write of whole lines, as ssh does,
    under a flock, so concurrent writers never interleave. Under the lock the file is read again: a key already
    filed is skipped, and a different key of the same type filed under host is host_key_changed, not filed
    beside it (OpenSSH would trust both). With refuse_other_types, a key of any other type filed under host
    refuses as well: a first contact must not be filed beside what is known. A copy of a key the name already
    trusts leaves it off. revoked, if given, says which filed keys no longer count. Returns the keys written."""
    if not path:
        raise HostKeyError("host_keys_not_kept", f"no known_hosts file to file the key under {host} in")
    # What is written is checked here as well: no pattern, marker or second line.
    if isinstance(host, str) and re.search(r'[\s"]', host):
        raise HostKeyError("address", f"{str(host)[:64]!r} cannot be written to known_hosts as an address")
    if not host or len(host) > 253 or re.search(r"[\s\x00-\x1f\x7f*?!,]|^[@|]", host):
        raise HostKeyError("device_name", f"{str(host)[:64]!r}: {NAME_RULE}")
    pairs = []
    for key in dict.fromkeys(keys):
        t, _, b = key.partition(" ")
        if not _TOKEN.fullmatch(t) or not _TOKEN.fullmatch(b):
            raise HostKeyError("host_key_uncheckable", "the device presented a key that cannot be written to known_hosts")
        pairs.append((t, b))
    written = []
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            # One writer at a time (other workers of this client; ssh takes no lock), so what is read below is
            # what the write follows.
            fcntl.flock(fd, fcntl.LOCK_EX)
            have = [k for k in filed(host, [path], ssh_keygen=ssh_keygen)[0]
                    if not (revoked and revoked(k))]
            have_types = {k.split(" ", 1)[0]: k for k in have}
            out = b""
            for t, b in pairs:
                key = f"{t} {b}"
                if key in have:
                    continue
                if (have and refuse_other_types) or t in have_types:
                    raise HostKeyError("host_key_changed", f"a key was filed under {host} while {host} was being "
                                       f"reached, and it is not the one presented: the key presented was not filed. "
                                       f"Verify the device's key on its console")
                name = hashed(host) if hash_names else host
                out += f"{name} {t} {b}\n".encode("ascii")
                written.append(key)
            if out:
                size = os.fstat(fd).st_size
                if size and os.pread(fd, 1, size - 1) != b"\n":
                    out = b"\n" + out  # as OpenSSH 10.2p1 does: the last entry stays a whole line
                if os.write(fd, out) != len(out):
                    raise OSError("short write")
        finally:
            os.close(fd)
    except OSError as e:
        raise HostKeyError("host_keys_not_kept", f"could not file the key under {host} in {path}: "
                           f"{e.strerror or e}") from None
    return written


def remember(kh, keytype, key_b64, stderr=None, *, ssh_keygen="ssh-keygen"):
    """File a first contact's key under kh.name (see append). Said on stderr as OpenSSH says it."""
    if not kh.write_to:
        raise HostKeyError("host_keys_not_kept", f"no known_hosts file to file the key under {kh.name} in")
    written = append(kh.write_to, kh.name, [f"{keytype} {key_b64}"], hash_names=kh.hash_names, ssh_keygen=ssh_keygen,
                     revoked=lambda k: is_revoked(kh, *k.split(" ", 1), ssh_keygen=ssh_keygen),
                     refuse_other_types=True)
    if written:
        print(f"port49: permanently added '{kh.name}' ({keytype}) to {kh.write_to}", file=stderr or sys.stderr)
