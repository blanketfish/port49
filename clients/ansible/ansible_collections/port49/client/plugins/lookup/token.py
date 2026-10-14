DOCUMENTATION = r"""
name: token
author: port49 contributors
short_description: Mint a port49 device token
description:
  - Mints a single-use device token for each device named, through the port49 CLI
    (C(port49 token --json) with your agent, or C(port49 workload token) with a workload certificate).
  - Each call is a mint. Mint once per host per play in a C(set_fact) with C(no_log), not in
    C(ansible_password), which Ansible templates at every task.
  - Needs the port49 Python library on the controller (C(pip install port49)).
  - Host keys are Ansible's own, and C(network_cli) keys them by C(ansible_host), not by the port49 name;
    see the collection README before setting C(host_key_auto_add), and never set it with C(ssh_type=paramiko).
options:
  _terms: {description: Device names as port49's inventory knows them., required: true, type: list, elements: str}
  field:
    description: What to return per device.
    type: str
    default: login
    choices: [login, enable, username, address, platform, all]
  enable: {description: Mint an enable token too., type: bool, default: false}
  ttl: {description: The lifetime asked for, in seconds; the broker clamps it., type: int}
  port49: {description: The port49 CLI., type: str, default: port49}
  socket: {description: The agent's socket., type: str}
  broker: {description: Workload mode, the broker URL., type: str}
  broker_ca: {description: Workload mode, the broker's CA., type: path}
  cert: {description: Workload mode, the certificate., type: path}
  key: {description: Workload mode, the key or a key reference., type: str}
  touch_key: {description: Workload mode, a touch key reference., type: str}
  deadline: {description: Workload mode, how long to retry the broker, in seconds., type: int}
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

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

WORKLOAD = ("broker", "broker_ca", "cert", "key")


def _agent(**kw):
    import port49
    return port49.Agent(**kw)


def _workload(*a, **kw):
    import port49
    return port49.Workload(*a, **kw)


def _value(tok, field):
    if field == "all":
        return {"device": tok.device, "address": tok.address, "platform": tok.platform, "username": tok.username,
                "login": tok.login, "enable": tok.enable, "expires_at": tok.expires_at}
    value = getattr(tok, field)
    if value is None:
        raise AnsibleError(f"port49: {tok.device}: no {field} token was minted; pass enable=true")
    return value


class LookupModule(LookupBase):
    # Nothing here puts a token in an error: the library's exceptions carry a code, a detail and a
    # device, never the CLI's stdout, and `from None` drops the chain. Ansible itself prints a lookup's
    # value nowhere but in a task result, which `no_log` on the set_fact censors (README, "Secrets").
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        try:
            import port49
        except ImportError:
            raise AnsibleError("the port49 lookup needs the port49 Python library on the controller: "
                               "pip install port49 (clients/python in the port49 repository)") from None
        opt = self.get_option
        field, enable, ttl = opt("field") or "login", bool(opt("enable")), opt("ttl")
        if field == "enable" and not enable:
            raise AnsibleError("port49: field=enable needs enable=true: no enable token is minted without it")
        given = [k for k in WORKLOAD if opt(k)]
        try:
            if given and len(given) != len(WORKLOAD):
                raise AnsibleError(f"port49: workload mode needs {', '.join(WORKLOAD)}; given only {', '.join(given)}")
            if given:
                wl = _workload(opt("broker"), opt("broker_ca"), opt("cert"), opt("key"), touch_key=opt("touch_key"),
                               port49=opt("port49") or "port49", deadline=opt("deadline"))
                res = wl.tokens(devices=list(terms), enable=enable, ttl=ttl)
                for d in terms:
                    if d in res.refused:
                        raise res.refused[d].exception()
                return [_value(res.tokens[d], field) for d in terms]
            agent = _agent(port49=opt("port49") or "port49", socket=opt("socket"))
            return [_value(agent.token(d, enable=enable, ttl=ttl), field) for d in terms]
        except port49.Port49Error as e:
            raise AnsibleError(str(e)) from None
        except ValueError as e:  # a device name the library refuses to hand the CLI
            raise AnsibleError(f"port49: {e}") from None
