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
  - Host keys are Ansible's own, and C(network_cli) keys them by C(ansible_host), not by the port49 name;
    see the collection README before setting C(host_key_auto_add), and never set it with
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
  socket:
    description: The agent's socket.
    type: str
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
        C(network_cli) or C(ansible.netcommon.network_cli) is checked, before any token is minted.
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


def _hostvar(variables, device, name):
    """The variable name of device, from its own hostvars only (None if it has none)."""
    try:
        return variables["hostvars"][device].get(name)
    except (KeyError, TypeError, AttributeError):
        return None


def _is_network_cli(variables, device):
    """Whether device connects with network_cli: its ansible_connection, else the play's. A play's `connection:`
    keyword may not reach a lookup as a variable, so with none visible, an ansible_network_os (which network_cli
    always needs) says so. Checking a device that is not network_cli only files a key the name already trusts."""
    connection = _hostvar(variables, device, "ansible_connection") or variables.get("ansible_connection")
    if connection:
        return connection in NETWORK_CLI
    return bool(_hostvar(variables, device, "ansible_network_os") or variables.get("ansible_network_os"))


def _check_host_keys(device, variables, known_hosts_file):
    """Plan 9f R2: before a mint for a network_cli device, check the address's keys in known_hosts_file against
    the keys filed under the port49 name, and copy what is missing either way. Refuses, before anything is
    minted, a key of the address that differs from the name's (host_key_changed) or is revoked. Raises the
    library's HostKeyError; the caller's handler makes it the lookup's error."""
    import port49
    from port49 import hostkeys
    if not _is_network_cli(variables, device):
        return
    if not hostkeys.valid_name(device):
        raise port49.HostKeyError("device_name", f"{str(device)[:64]!r}: {hostkeys.NAME_RULE}")
    name = device.lower()
    address = str(_hostvar(variables, device, "ansible_host") or device)
    try:
        port = int(_hostvar(variables, device, "ansible_port") or 22)
    except (TypeError, ValueError):
        raise port49.HostKeyError("address", "ansible_port is not a number", device) from None
    entry = hostkeys.address_entry(address, port)
    ssh = _ssh_options()
    paths, write_to, hash_names = hostkeys.known_files(name, **ssh)
    krl = hostkeys.revoked_keys_file(name, **ssh)
    name_keys, name_revoked = hostkeys.filed(name, paths)
    addr_keys, addr_revoked = hostkeys.filed(entry, [known_hosts_file])

    def revoked(revoked_lines, key):
        kh = hostkeys.KnownHosts(name, (), (), tuple(revoked_lines), krl, False, hash_names, write_to)
        return hostkeys.is_revoked(kh, *key.split(" ", 1))

    if any(revoked(addr_revoked + name_revoked, k) for k in addr_keys):
        raise port49.HostKeyError("host_key_revoked", f"a key filed for {address} is revoked (an @revoked line, or "
                                  f"your RevokedHostKeys): verify the device's key on its console before filing "
                                  f"another", device)
    name_keys = [k for k in name_keys if not revoked(name_revoked, k)]
    if name_keys and not addr_keys:
        hostkeys.append(known_hosts_file, entry, name_keys, hash_names=hash_names)
    elif name_keys:
        have = {k.split(" ", 1)[0]: k for k in addr_keys}
        changed = [(k, have[k.split(" ", 1)[0]]) for k in name_keys
                   if k.split(" ", 1)[0] in have and have[k.split(" ", 1)[0]] != k]
        if changed:
            seen = "; ".join(f"{k.split(' ', 1)[0]}: {device} has {hostkeys.fingerprint(k)}, {address} has "
                             f"{hostkeys.fingerprint(a)}" for k, a in changed)
            raise port49.HostKeyError(
                "host_key_changed", f"the key filed for {address} is not the key filed for {device} ({seen}). "
                f"Verify the device's key on its console; if the address now belongs to this device, clear the "
                f"old entry with: ssh-keygen -R {shlex.quote(entry)} -f "
                f"{shlex.quote(known_hosts_file)}", device)
        hostkeys.append(known_hosts_file, entry, [k for k in name_keys if k.split(" ", 1)[0] not in have],
                        hash_names=hash_names)
    elif addr_keys:
        try:  # a courtesy: without it the next address change is a first contact, which is today's behaviour
            hostkeys.append(write_to, name, addr_keys, hash_names=hash_names)
        except port49.HostKeyError as e:
            if e.code != "host_keys_not_kept":
                raise
            _warn(f"port49: {device}: the key filed for {address} could not be copied under {device}, so a later "
                  f"address change will be a first contact again: {e.detail}")


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
            agent = _agent(port49=opt("port49") or "port49", socket=opt("socket"))
            return [_value(agent.token(d, enable=enable, ttl=ttl), field) for d in terms]
        except port49.Port49Error as e:
            said = str(e)
            _fail(said if e.code in said else f"{said} [{e.code}]")
        except ValueError as e:  # a device name the library refuses to hand the CLI
            _fail(f"port49: {e}")
