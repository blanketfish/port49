DOCUMENTATION = r"""
name: token
author: port49 contributors
short_description: Mint a port49 device token
description:
  - Mints a single-use device token for each device named, through the port49 CLI
    (C(port49 token --json) with your agent, or C(port49 workload token) with a workload certificate).
  - Each call is a mint. Mint once per host per play in a C(set_fact) with C(no_log), not in
    C(ansible_password), which Ansible templates at every task. Never use C(cacheable) on that C(set_fact).
  - Needs the port49 Python library on the controller (C(pip install ./clients/python) from the port49 repository).
  - Host keys are Ansible's own, and C(network_cli) keys them by C(ansible_host), not by the port49 name.
    For a C(network_cli) device the lookup checks the address's key against the name's before it mints,
    and refuses a changed or revoked key; see the collection README. It cannot see a key that changes later
    in a run, so see the README before setting C(host_key_auto_add), and never set it with
    C(ansible_network_cli_ssh_type=libssh), which accepted a changed key and presented the token (L66 (c)).
options:
  _terms:
    description: Device names as port49's inventory knows them.
    required: true
    type: list
    elements: str
  field:
    description: What to return per device.
    type: str
    default: login
    choices: [login, enable, username, address, platform, all]
  enable:
    description: Mint an enable token too.
    type: bool
    default: false
  ttl:
    description: The lifetime asked for, in seconds. The broker clamps it.
    type: int
  port49:
    description: The port49 CLI.
    type: str
    default: port49
  broker:
    description: Workload mode, the broker URL.
    type: str
  broker_ca:
    description: Workload mode, the broker's CA.
    type: path
  cert:
    description: Workload mode, the certificate.
    type: path
  key:
    description: Workload mode, the key or a key reference.
    type: str
  touch_key:
    description: Workload mode, a touch key reference.
    type: str
  deadline:
    description: Workload mode, how long to retry the broker, in seconds.
    type: int
  known_hosts_file:
    description:
      - The file C(network_cli) keeps a device's address in. Only a device whose C(ansible_connection) is
        C(network_cli) or C(ansible.netcommon.network_cli), or that has none visible but an C(ansible_network_os),
        is checked, before any token is minted. For the current host, an C(ansible_connection) of C(network_cli) in
        either its inventory or its play's vars counts.
      - A device that is not a host in Ansible's inventory has no address to check, so minting it on a host that
        connects with C(network_cli) refuses with C(host_key_uncheckable). Name the inventory host by its port49 name.
      - The address (C(ansible_host), else the inventory name; C([address]:port) when C(ansible_port) is not 22)
        is checked against the keys filed under the port49 name in your ssh files. A key the address lacks is
        filed there, and a different key of the same type refuses with C(host_key_changed). When only the address
        has a key, it is also filed under the name.
    type: path
    default: ~/.ssh/known_hosts
"""

EXAMPLES = r"""
- name: one mint per host
  ansible.builtin.set_fact:
    port49: "{{ lookup('port49.client.token', inventory_hostname, field='all') }}"
  no_log: true
"""

RETURN = r"""
_raw:
  description: One value per device, the field asked for (a dict for C(all)).
  type: list
"""

import os
import shlex

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

NETWORK_CLI = ("network_cli", "ansible.netcommon.network_cli")
WORKLOAD = ("broker", "broker_ca", "cert", "key")
WORKLOAD_ONLY = ("touch_key", "deadline")


def _agent(**kw):
    import port49
    return port49.Agent(**kw)


def _workload(*a, **kw):
    import port49
    return port49.Workload(*a, **kw)


def _ssh_options():
    """Extra arguments for the library's ssh calls (a test points them at its own ssh_config)."""
    return {}


def _warn(message):
    """Warn with message, its non-printable characters made '?'; returns the clean text."""
    message = "".join(c if c.isprintable() else "?" for c in str(message))
    Display().warning(message)
    return message


def _fail(message):
    """Warn, then raise: ansible-core 2.16 to 2.18 censor a failed no_log task's message, and a warning
    is shown beside the censored result. The message is token-free by construction, and it is the one
    place every message passes, so it is also where a device name from inventory (or any field the
    CLI echoed) loses its terminal control bytes: each non-printable character, newline included,
    becomes '?'. The warning and the raised error carry the same clean text."""
    raise AnsibleError(_warn(message)) from None


def _value(tok, field):
    if field == "all":
        return {"device": tok.device, "address": tok.address, "platform": tok.platform, "username": tok.username,
                "login": tok.login, "enable": tok.enable, "expires_at": tok.expires_at}
    value = getattr(tok, field)
    if value is None:
        _fail(f"port49: {tok.device}: no {field} token was minted; pass enable=true")
    return value


def _in_inventory(variables, device):
    """Whether device is a host in Ansible's inventory. HostVars answers `in` from the inventory; indexing a
    host outside it gives an undefined marker in ansible-core 2.21, not a KeyError, so ask this first."""
    try:
        return device in variables["hostvars"]
    except (KeyError, TypeError):
        return False


def _hostvar(variables, device, name):
    """The variable name of device, from its own hostvars only (None if it has none)."""
    if not _in_inventory(variables, device):
        return None
    try:
        return variables["hostvars"][device].get(name)
    except (KeyError, TypeError, AttributeError):
        return None


def _visible(variables, device, name):
    """The variable name as device sees it: its own hostvars, and the lookup's variables (the play's keywords
    and the current host's) only when device is the current host. Another device's play is not visible here."""
    value = _hostvar(variables, device, name)
    if value is None and device == variables.get("inventory_hostname"):
        value = variables.get(name)
    return value


def _is_network_cli(variables, device):
    """Whether device connects with network_cli: its ansible_connection, else its play's. A play's `connection:`
    keyword may not reach a lookup as a variable, so with none visible, an ansible_network_os (which network_cli
    always needs) says so. Checking a device that is not network_cli only files a key the name already trusts.
    For the current host both its hostvars and the lookup's variables (where a play's vars override host_vars, as
    in Ansible) are read, and either one naming network_cli counts: the check runs whenever Ansible might connect
    with it."""
    connections = [_hostvar(variables, device, "ansible_connection")]
    if device == variables.get("inventory_hostname"):
        connections.append(variables.get("ansible_connection"))
    connections = [c for c in connections if c]
    if connections:
        return any(_might_be_network_cli(c) for c in connections)
    return bool(_visible(variables, device, "ansible_network_os"))


def _might_be_network_cli(connection):
    """Whether a connection value is, or may render to, network_cli. A lookup can be handed a play's
    `ansible_connection: "{{ conn }}"` unrendered (measured on ansible-core 2.16.19 and 2.21.4), and what it
    renders to cannot be known here: a value still holding a Jinja expression or statement counts."""
    text = str(connection)
    return text in NETWORK_CLI or "{{" in text or "{%" in text


def _check_host_keys(device, variables, known_hosts_file):
    """Plan 9f R2: before a mint for a network_cli device, check the address's keys in known_hosts_file against
    the keys filed under the port49 name, and copy what is missing either way. Refuses, before anything is
    minted, a key of the address that differs from the name's (host_key_changed) or is revoked. Raises the
    library's HostKeyError; the caller's handler makes it the lookup's error."""
    import port49
    from port49 import hostkeys
    if not _is_network_cli(variables, device):
        current = variables.get("inventory_hostname")
        # A term that is no inventory host has no address of its own (R2: ansible_host, else the inventory name),
        # but the current host's network_cli connection will present the token to the current host's address.
        # Neither the name's address nor the current host's is known to be the device's: refuse, never skip.
        if device != current and not _in_inventory(variables, device) and _is_network_cli(variables, current):
            raise port49.HostKeyError(
                "host_key_uncheckable", f"not a host in Ansible's inventory, and {current} connects with "
                f"network_cli, so the lookup cannot tell which address's key to check against this name's: "
                f"name the inventory host by its port49 name and mint for inventory_hostname", device)
        return
    if not hostkeys.valid_name(device):
        raise port49.HostKeyError("device_name", f"{str(device)[:64]!r}: {hostkeys.NAME_RULE}")
    name = device.lower()
    address = str(_hostvar(variables, device, "ansible_host") or device)
    try:
        port = int(_hostvar(variables, device, "ansible_port") or _hostvar(variables, device, "ansible_ssh_port") or 22)
    except (TypeError, ValueError):
        raise port49.HostKeyError("address", "ansible_port is not a number", device) from None
    try:
        entry = hostkeys.address_entry(address, port)
    except port49.HostKeyError as e:
        raise port49.HostKeyError(e.code, e.detail, device) from None
    ssh = _ssh_options()
    alias, command = hostkeys.key_alias(name, **ssh)
    if command:  # as hostkeys.lookup refuses it: reading past a KnownHostsCommand could accept a key ssh refuses
        raise port49.HostKeyError("host_key_uncheckable", "your ssh_config sets KnownHostsCommand, which the lookup "
                                  "cannot run as ssh does, so it cannot tell whether the address's key is the "
                                  "device's: remove it for this device, or use port49 ssh", device)
    paths, write_to, hash_names = hostkeys.known_files(name, **ssh)
    krl = hostkeys.revoked_keys_file(name, **ssh)
    # The name's keys are the port49 name's and, if the operator's ssh_config gives the device a HostKeyAlias
    # (which port49 ssh lets stand), the alias's: ssh reads the alias, so that is where its keys live.
    name_keys, name_revoked = hostkeys.filed(name, paths)
    alias_keys = []
    if alias and alias != name:
        alias_keys, alias_revoked = hostkeys.filed(alias, paths)
        name_revoked = name_revoked + [r for r in alias_revoked if r not in name_revoked]
    addr_keys, addr_revoked = hostkeys.filed(entry, [known_hosts_file])
    addr_revoked += hostkeys.filed(entry, paths)[1]  # an @revoked line for the address in the ssh files counts too

    def revoked(revoked_lines, key):
        kh = hostkeys.KnownHosts(name=name, keys=(), authorities=(), revoked=tuple(revoked_lines), krl=krl,
                                 strict=False, hash_names=hash_names, write_to=write_to)
        return hostkeys.is_revoked(kh, *key.split(" ", 1))

    def append(path, host, keys):  # the library's refusals carry no device: this one does
        try:
            return hostkeys.append(path, host, keys, hash_names=hash_names,
                                   revoked=lambda k: revoked(name_revoked, k))
        except port49.HostKeyError as e:
            if e.code == "host_keys_not_kept":
                raise
            raise port49.HostKeyError(e.code, e.detail, device) from None

    if any(revoked(addr_revoked + name_revoked, k) for k in addr_keys):
        key = next(k for k in addr_keys if revoked(addr_revoked + name_revoked, k))
        raise port49.HostKeyError("host_key_revoked", f"the key {hostkeys.fingerprint(key)} filed for {address} is "
                                  f"revoked (an @revoked line, or your RevokedHostKeys): verify the device's key on "
                                  f"its console before filing another; to drop the address's entry, "
                                  f"ssh-keygen -R {shlex.quote(entry)} -f {shlex.quote(known_hosts_file)}", device)
    both = name_keys + [k for k in alias_keys if k not in name_keys]
    if both and all(revoked(name_revoked, k) for k in both):  # as hostkeys.lookup: nothing left to trust
        raise port49.HostKeyError("host_key_revoked", f"every key filed under {device} is revoked (an @revoked line, "
                                  f"or your RevokedHostKeys): verify the device's key on its console before filing "
                                  f"another", device)
    name_keys = [k for k in name_keys if not revoked(name_revoked, k)]
    alias_keys = [k for k in alias_keys if not revoked(name_revoked, k)]
    split = _differing(name_keys, alias_keys)
    if split:
        seen = "; ".join(f"{k.split(' ', 1)[0]}: {name} has {hostkeys.fingerprint(k)}, {alias} has "
                         f"{hostkeys.fingerprint(a)}" for k, a in split)
        raise port49.HostKeyError(
            "host_key_changed", f"the keys filed for {device} disagree with the keys filed for its HostKeyAlias "
            f"{alias} ({seen}). Verify the device's key on its console, then clear the stale entry with "
            f"ssh-keygen -R", device)
    name_keys = name_keys + [k for k in alias_keys if k not in name_keys]
    if name_keys and not addr_keys:
        append(known_hosts_file, entry, name_keys)
    elif name_keys:
        have = {}
        for k in addr_keys:
            have.setdefault(k.split(" ", 1)[0], []).append(k)
        changed = _differing(name_keys, addr_keys)
        if changed:
            seen = "; ".join(f"{k.split(' ', 1)[0]}: {device} has {hostkeys.fingerprint(k)}, {address} has "
                             f"{hostkeys.fingerprint(a)}" for k, a in changed)
            raise port49.HostKeyError(
                "host_key_changed", f"the key filed for {address} is not the key filed for {device} ({seen}). "
                f"Verify the device's key on its console; if the address now belongs to this device, clear the "
                f"old entry with: ssh-keygen -R {shlex.quote(entry)} -f "
                f"{shlex.quote(known_hosts_file)}", device)
        append(known_hosts_file, entry, [k for k in name_keys if k.split(" ", 1)[0] not in have])
    elif addr_keys:
        try:  # a courtesy: without it the next address change is a first contact, which is today's behaviour
            append(write_to, name, addr_keys)
        except port49.HostKeyError as e:
            if e.code != "host_keys_not_kept":
                raise
            _warn(f"port49: {device}: the key filed for {address} could not be copied under {device}, so a later "
                  f"address change will be a first contact again: {e.detail}")


def _differing(want, have):
    """[(a key of want, a key of have)] for each key type both hold where none of have's keys of the type is one
    of want's: a type matches when any of the keys of it is shared."""
    by_type = {}
    for k in have:
        by_type.setdefault(k.split(" ", 1)[0], []).append(k)
    out = []
    for t in dict.fromkeys(k.split(" ", 1)[0] for k in want):
        mine = [k for k in want if k.split(" ", 1)[0] == t]
        if t in by_type and not set(by_type[t]) & set(mine):
            out.append((mine[0], by_type[t][0]))
    return out


class LookupModule(LookupBase):
    # Nothing here puts a token in an error: the library's exceptions carry a code, a detail and a
    # device, never the CLI's stdout, and `from None` drops the chain. Ansible itself prints a lookup's
    # value nowhere but in a task result, which `no_log` on the set_fact censors (README, "Secrets").
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        try:
            import port49
        except ImportError:
            _fail("the port49 lookup needs the port49 Python library on the controller: "
                  "pip install ./clients/python from the port49 repository")
        opt = self.get_option
        field, enable, ttl = opt("field") or "login", bool(opt("enable")), opt("ttl")
        if field == "enable" and not enable:
            _fail("port49: field=enable needs enable=true: no enable token is minted without it")
        # Present counts, even when empty (an unset variable): never fall back to the agent as the person.
        given = [k for k in WORKLOAD if opt(k) is not None]
        if given and (len(given) != len(WORKLOAD) or not all(opt(k) for k in given)):
            _fail(f"port49: workload mode needs {', '.join(WORKLOAD)}, none empty; given {', '.join(given)}")
        if not given and any(opt(k) is not None for k in WORKLOAD_ONLY):
            _fail(f"port49: {' and '.join(WORKLOAD_ONLY)} are workload mode options: give {', '.join(WORKLOAD)} too")
        try:
            known_hosts = os.path.expanduser(opt("known_hosts_file") or "~/.ssh/known_hosts")
            for d in terms:  # every device, before the one mint (R4)
                _check_host_keys(d, variables or {}, known_hosts)
            if given:
                wl = _workload(opt("broker"), opt("broker_ca"), opt("cert"), opt("key"), touch_key=opt("touch_key"),
                               port49=opt("port49") or "port49", deadline=opt("deadline"))
                res = wl.tokens(devices=list(terms), enable=enable, ttl=ttl)
                for d in terms:
                    if d in res.refused:
                        raise res.refused[d].exception()
                    if d not in res.tokens:
                        _fail(f"port49: {d}: the CLI's answer left this device out")
                return [_value(res.tokens[d], field) for d in terms]
            agent = _agent(port49=opt("port49") or "port49")
            return [_value(agent.token(d, enable=enable, ttl=ttl), field) for d in terms]
        except port49.Port49Error as e:
            said = str(e)
            _fail(said if e.code in said else f"{said} [{e.code}]")
        except ValueError as e:  # a device name the library refuses to hand the CLI
            _fail(f"port49: {e}")
