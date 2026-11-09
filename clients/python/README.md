# port49 for Python

Device tokens from the port49 agent, for scripts, Nornir and Netmiko. The library drives the
`port49` CLI (not the API or the agent socket), so a hardware key, its PIN, a touch and
`per_login_mfa` take the one path they take at a terminal. Python 3.10 or later; standard
library only.

## Install

```
pip install ./clients/python            # the library
pip install './clients/python[netmiko]' # and Netmiko, for port49.netmiko
```

`port49` must be on `PATH` (or pass `Agent(port49="/opt/port49/bin/port49")`), and `port49 login`
must have started an agent.

## Use

```python
from port49 import Agent, Denied, MFARequired

agent = Agent()
print(agent.identity()["principal"])

tok = agent.token("leaf1", enable=True, ttl=300)
# tok.address, tok.username, tok.login, tok.enable (login and enable are not in repr)

res = agent.tokens(["leaf1", "leaf2", "core1"])   # one mint per device, in turn
res.tokens      # {device: Token}
res.refused     # {device: Refusal}: denies, and devices that want a second factor
res.raise_for_refused()
```

### A machine's tokens: `Workload`

For a service with a workload certificate (Oxidized, a backup job), `Workload` drives
`port49 workload token`, which reads the certificate and key at every run:

```python
from port49 import Workload

w = Workload(broker="https://broker.example.com:8443", broker_ca="/etc/port49/ca.pem",
             cert="/etc/port49/w.pem", key="/etc/port49/w.key")
print(w.identity()["principal"])
res = w.tokens(scope="backup")                       # every device the scope selects that you hold a grant on
res = w.tokens(["leaf1", "leaf2"], purpose="nightly backup")
res.tokens      # {device: Token}
res.refused     # {device: Refusal}: denies, and devices that want a second factor
```

Pass `touch_key=` (a `pkcs11:` reference with a `pin-source`), `broker_crl=` and `deadline=`
(seconds) to reach the CLI's flags of those names.

- A scope that selects nothing returns empty `tokens` and `refused`. So does a run where every
  device was denied (the CLI exits 77 for that): the denies are in `refused`, and nothing raises.
- A run that **stopped** before it finished never returns: the CLI says so (`stopped`), and the
  library raises the class of that code (`broker_unavailable` and `connection_changed` are
  `Temporary`, `broker_refused` is `BrokerRefused`, `agent_error` is `Port49Error`). The tokens
  minted so far are on `.results`, and every device the run left is in `.results.refused` under
  the stopping code. No answer at all is `Temporary` for exit 75 and `Final` for exit 77 (the
  certificate expired: nothing can mint until someone acts).
- **The library never reruns a workload run**, not even on `Temporary`. The CLI already retries
  each page within its `--deadline` under one Idempotency-Key; when that runs out, the page in
  flight may already be minted at the broker with its answer lost, and a new run has a new key,
  so it would mint that page's devices again. Deciding to run again is yours: `.results.refused`
  names the devices a stopped run left. A rerun of a scope sweep, which cannot name what it left,
  mints every page again, the ones already minted included.
- The answer holds a token for every device and is read whole, up to 64 MiB (some 200,000
  devices). Larger raises `Port49Error` with code `answer_too_large` (the run may have minted):
  split the sweep, or have the CLI write the tokens with `--out`.
- A device name may not be empty, padded with whitespace, start with `#` or hold a line break
  (`ValueError`): the CLI would trim or skip it.

## Errors

Every exception is a `Port49Error` with `.code`, `.detail` and `.device`.

| CLI code | Class | What to do |
|---|---|---|
| `not_installed` | `NotInstalled` | Install port49 or pass `port49=`. |
| `no_agent`, `agent_too_old` | `NoAgent` | Run `port49 login`. |
| `session_over`, `credential_revoked` | `SessionOver` | Run `port49 login` again. |
| a deny (`verdict: deny`) | `Denied` (`.reason` is the broker's reason, `.verdict`) | Ask for the grant; not retried. |
| `per_login_mfa_required` | `MFARequired` (`.requirement`) | A person runs `port49 ssh DEVICE` at a terminal; one proof covers their agent's further logins for the requirement's `reuse_for_seconds`. An agent stops and asks a person. |
| `touch_timeout`, `key_locked`, `key_absent` | `KeyUnavailable` | Touch the key, unlock it, or plug it in; not retried. |
| `broker_refused` | `BrokerRefused` | The broker refused a proof, or its certificate was refused; not retried. |
| `revocation_running`, `connection_changed` | `Temporary` | Retried by `Agent`; see below. `Workload` never reruns a run: run it again later. |
| `broker_unavailable` | `Temporary` | Not retried: the request may have reached the broker and minted. Run it again when the broker is back. |
| `device_unconfigured`, `attribute_too_long`, `attribute_unsafe`, `broker_error`, `no_token` | `DeviceFault` | The broker could not decide this one device (or minted it no token). Fix its inventory entry (`device_unconfigured`, `attribute_*`), or read the broker's log (`broker_error`, `no_token`). Other devices are unaffected. |
| `agent_error`, `exit_N`, `timeout` | `Port49Error` | Read `.detail`. |
| `answer_too_large` | `Port49Error` | The CLI's answer passed the library's 64 MiB cap: the tokens may be minted but are not read. Split the sweep, or use `port49 workload token --out`. |

An error the runner raised before reading an answer (`not_installed`, `timeout`,
`answer_too_large`) has no `.results`: what was minted is unknown, not empty.

`tokens()` collects what belongs to one device (a deny, a second factor, a `DeviceFault`) into
`refused`, so one device never stops a sweep. Test a refusal with `r.per_login_mfa is not None` or
`isinstance(r.exception(), MFARequired)`, not `r.error`: the same second-factor condition comes
from the CLI's code (`error`) or from a broker deny (`reason`). Anything else stops the sweep, and
the exception's `.results` holds the tokens minted so far, so a rerun need not mint them again.

`.results` holds live tokens: use it in the process that caught the error, and do not log or
serialize it. `str`, `repr`, pickle and `copy` of the exception leave the tokens out (a rebuilt
exception has the device names and `None` for each token), but `vars(e)` and `e.results` itself
are the real thing.

## Netmiko and host keys

```python
from port49 import Workload
from port49.netmiko import connect

conn = connect("leaf1", enable=True)    # a person's token, through the agent `port49 login` started
w = Workload(broker="https://broker.example.com:8443", broker_ca="/etc/port49/ca.pem",
             cert="/etc/port49/w.pem", key="/etc/port49/w.key")
conn = connect("leaf1", workload=w)     # a machine's token, through `port49 workload token`
# a Netmiko connection either way; extra keyword arguments pass to Netmiko
```

- `workload=` runs `port49 workload token` once for the one device, and never again (a workload run is never
  rerun). A refusal raises what the agent path raises: `Denied`, `MFARequired` (a device that asks for a second
  factor the run did not prove), `DeviceFault`. A stopped run raises its code's class, and its `.results` names
  the device and holds no token.
- `agent=` and `workload=` together are a `ValueError`. A `Workload` as `agent=`, or anything but a `Workload`
  as `workload=`, is a `TypeError`. All three are raised before anything is minted. With neither, `connect`
  uses `Agent()`, and with no agent running raises `NoAgent`, naming `workload=`.
- Host keys are the same on both paths, below.

port49 stores no host key. `connect` keeps the device's key in your OpenSSH `known_hosts`, under
the device's inventory name (your `HostKeyAlias` if you set one), the entry `port49 ssh` uses. It
reads your ssh_config through `ssh -G` and the key files through `ssh-keygen -F`, and parses
neither itself.

- No key filed: the key the device presents is filed before the token is sent (accept-new). Many
  workers reaching a new device at once each write one whole line.
- A key filed: the only key accepted. A changed key, a key of another type, or another host at the
  address is `HostKeyError` (`host_key_changed`) before the token is sent; the message gives
  `ssh-keygen -R NAME`.
- Your `StrictHostKeyChecking yes` stands: nothing is filed, and a device with no key filed is
  refused (`host_key_unknown`).

Refused, with the setting named, and never filed past:

| Code | When |
|---|---|
| `device_name` | A name known_hosts would read as a pattern or a marker (`leaf*`, `a,b`, `@x`, ...). Checked before the mint. |
| `ssh_config_unread` | `ssh -G` failed on your ssh_config. |
| `known_hosts_unread` | `ssh-keygen -F` failed on a known_hosts file. |
| `host_key_uncheckable` | A `KnownHostsCommand` (use `port49 ssh`); a `RevokedHostKeys` that `ssh-keygen -Q` cannot read (a plain key list, which ssh honours and this client does not: make a KRL with `ssh-keygen -k`); a path in `GlobalKnownHostsFile` or `UserKnownHostsFile` that cannot be resolved; a host covered only by `@cert-authority`, which Paramiko cannot check; a `ProxyJump` or `ProxyCommand` (Paramiko dials the address itself, so a key filed or checked could be another host's: use `port49 ssh`); a `Port` that is not the one `connect` dials (`port=`); a `BindAddress` or `BindInterface` (Paramiko takes the default route); keys filed only in types Paramiko cannot load (`ssh-dss`, `sk-*`); a device with nothing filed that offers only types Paramiko cannot check; in the Ansible lookup, a port49 name that is not an inventory host, minted on a host that connects with `network_cli` (mint for `inventory_hostname`). |
| `host_keys_not_kept` | Under accept-new, the first `UserKnownHostsFile` is `/dev/null`, `none`, a link to either, or not a file you can write (or create). Every connection would be a first contact. |
| `host_key_revoked` | An `@revoked` line or `RevokedHostKeys` names the key, filed beside your entry or presented at first contact. |
| `host_key_unknown`, `host_key_changed` | As above. |

Only the host-key types filed under the name are negotiated, on the first connect and on every
rebuild (so OpenSSH 8.8 and later, which do not offer `ssh-rsa`, still present the filed RSA key).

The returned connection keeps the key its connect accepted, in memory. A reconnect
(`establish_connection()`) or an SCP transfer on it loads that key into the new Paramiko client,
looks the files up again (a key revoked or removed since is not loaded, and with none left nothing
connects), and refuses any other key before authenticating. Every such refusal is
`HostKeyError` with code `host_key_changed` (or `host_key_revoked`), never Netmiko's
`NetmikoTimeoutException` and never Paramiko's `BadHostKeyException`. Initially Paramiko compares
against the first key of the presented type, so after a rotation that appended a second key of one
type, `connect` can refuse with `host_key_changed` until the old line is removed.

A refusal after the mint leaves that token unused; it expires. That Paramiko refuses a wrong key
before it authenticates was measured on 2026-10-14 (`tests/lab/results/L65-<platform>.md`).

## What is retried, and why

`token` runs again, at most `attempts` times (default 3) with a 1 s, 2 s, 4 s ... wait between,
only for a code that means nothing was sent to mint with: `revocation_running` (a revocation
sweep is on) and `connection_changed`. A `connection_changed` retry asks for a second touch,
since the touch is bound to the connection that changed.

Never retried: `broker_unavailable` (the request may have reached the broker before it died, and
a rerun would mint again and hold another candidate slot until the first token expires; it is
`Temporary`, so the caller decides), a key or PIN failure (a locked key would burn its tries),
`touch_timeout` (the person did not touch; running again would only prompt them again unasked),
a deny, `broker_refused`, a lost session.

## Secrets

The token is never in argv, the environment, a log or a `repr`. It is read from the CLI's stdout
and handed to Netmiko (or Ansible) only. `connect`'s connection holds it only as Netmiko's `password` and
`secret`, which Netmiko logs in again with. An exception `connect` raises has no locals left in the frames of
its traceback, or of the tracebacks it chains, below `connect`, so a traceback printed with its locals shows no
token. Netmiko masks the token in its DEBUG log and session log; everything else the session sends is logged in
full, so keep DEBUG off in production. No exception, `repr` or failed-parse error carries the
CLI's stdout. The CLI's stderr (a touch prompt, a sign-in URL) is passed to your stderr as it
comes; pass `Agent(stderr=file)` to send it elsewhere.
