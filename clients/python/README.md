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

## Errors

Every exception is a `Port49Error` with `.code`, `.detail` and `.device`.

| CLI code | Class | What to do |
|---|---|---|
| `not_installed` | `NotInstalled` | Install port49 or pass `port49=`. |
| `no_agent`, `agent_too_old` | `NoAgent` | Run `port49 login`. |
| `session_over`, `credential_revoked` | `SessionOver` | Run `port49 login` again. |
| a deny (`verdict: deny`) | `Denied` (`.reason` is the broker's reason, `.verdict`) | Ask for the grant; not retried. |
| `per_login_mfa_required` | `MFARequired` (`.requirement`) | Run `port49 token DEVICE` at a terminal; one proof covers this agent's further logins for the requirement's `reuse_for_seconds`. |
| `touch_timeout`, `key_locked`, `key_absent` | `KeyUnavailable` | Touch the key, unlock it, or plug it in; not retried. |
| `broker_refused` | `BrokerRefused` | The broker refused a proof, or its certificate was refused; not retried. |
| `revocation_running`, `connection_changed`, `broker_unavailable` | `Temporary` | Retried; see below. |
| `device_unconfigured`, `attribute_too_long`, `attribute_unsafe`, `broker_error`, `no_token` | `DeviceFault` | The broker could not decide this one device (or minted it no token). Fix its inventory entry (`device_unconfigured`, `attribute_*`), or read the broker's log (`broker_error`, `no_token`). Other devices are unaffected. |
| `agent_error`, `exit_N`, `timeout` | `Port49Error` | Read `.detail`. |

`tokens()` collects what belongs to one device (a deny, a second factor, a `DeviceFault`) into
`refused`, so one device never stops a sweep. Test a refusal with `r.per_login_mfa is not None` or
`isinstance(r.exception(), MFARequired)`, not `r.error`: the same second-factor condition comes
from the CLI's code (`error`) or from a broker deny (`reason`). Anything else stops the sweep, and
the exception's `.results` holds the tokens minted so far, so a rerun need not mint them again.

`.results` holds live tokens: use it in the process that caught the error, and do not log or
serialize it. `str`, `repr`, pickle and `copy` of the exception leave the tokens out (a rebuilt
exception has the device names and `None` for each token), but `vars(e)` and `e.results` itself
are the real thing.

## What is retried, and why

`token` runs again, at most `attempts` times (default 3) with a 1 s, 2 s, 4 s ... wait between,
only for a code that means nothing was sent to mint with or the broker did not answer:
`revocation_running` (a revocation sweep is on), `connection_changed` and `broker_unavailable`
(an outage or a 503). A `connection_changed` retry asks for a second touch, since the touch is
bound to the connection that changed.

Never retried: a key or PIN failure (a locked key would burn its tries), `touch_timeout` (the
person did not touch; running again would only prompt them again unasked), a deny,
`broker_refused`, a lost session.

## Secrets

The token is never in argv, the environment, a log or a `repr`. It is read from the CLI's stdout
and handed to Netmiko (or Ansible) only. No exception, `repr` or failed-parse error carries the
CLI's stdout. The CLI's stderr (a touch prompt, a sign-in URL) is passed to your stderr as it
comes; pass `Agent(stderr=file)` to send it elsewhere.
