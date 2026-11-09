---
title: AI agents quick start
description: Letting an AI agent operate network devices through port49 with its own identity, and what it reads back when a device refuses it.
---

# AI agents quick start

An AI agent that runs commands on network devices is a workload: a program with no person at the keyboard.
port49 treats it like one. It gets an identity of its own, a grant of its own, and a record of its own in the
decision log. This page is for the operator who sets that up, and for the agent that reads it before it acts.
Every sentence is an instruction, so it says what to do and what never to do.

## The rules

1. **The agent never holds a person's login.** It does not run `port49 login`, and it is never started from
   a person's shell with that person's agent running. A command it ran there would be recorded under the
   person, and the person's grants would be the agent's.
2. **The agent has a subject of its own, with the narrowest roles.** The subject names the agent's one
   identity: a workload certificate (`spiffe://<trust domain>/<path>`), a Kubernetes service account
   (`system:serviceaccount:<namespace>:<name>`) or a machine OIDC client (`app:<client_id>`). Give it a
   read-only role first and widen it only when a human decides to. See
   [Workloads](../admin/workloads.md) and [Roles and grants](../admin/roles-and-grants.md#machine_group).
3. **The tooling mints and presents the token. The token never enters the agent's context.** Use the Ansible
   lookup, which reads the token from the `port49` command and hands it to the connection and nowhere else, or
   the Python library's `port49.netmiko.connect` with a `port49.Workload`, which mints with the agent's own
   certificate and hands the token to the Netmiko connection and nowhere else ([step 4b](#4b-or-run-it-from-python)).
   Never use `port49.Agent`, and never call `connect` without `workload=`: both use a person's session. Never run
   `port49 token`, `port49 workload token` or `port49 ssh` in a shell: on success they print the token (and
   `port49 token --json` the broker's whole answer, token included) on standard output, which is the
   transcript, or they use a person's login. Never print, log or `cat` a token, a certificate's key file, a
   password, an ID token, or a dump of the environment, and keep `no_log: true` on every Ansible task that
   holds one. The agent passes the key file's path to the tooling and never opens it.
4. **A refusal arrives as a reason code.** The agent reads the code from its tooling and stops. It never
   retries a deny, and it never tries another device, another identity or a person's login to get round it.
   The next section says where the code appears on each path.
5. **Every command is recorded under the agent's principal.** See [what is recorded](#5-what-is-recorded).
6. **A device that asks for a person's second factor stays human: the agent's subject has no grant on it.**
   A `per_login_mfa` requirement does not keep an agent off a device on its own. See
   [per_login_mfa_required devices](#per_login_mfa_required-devices-stay-human).

## How a refusal reaches the agent

A refusal is a deny with a reason code from the closed list in [Reason codes](../reference/reason-codes.md).
Read it from the tooling the agent already runs. These are the four paths, and what each one carries.

| Path | What the agent sees | Where the code is |
|---|---|---|
| `port49 ssh:` | `port49 ssh: <device>: deny <reason>: <detail>` on standard error | in the line |
| `port49 workload token:` | `port49 workload token: <device>: deny <reason>: <detail>` on standard error | in the line |
| The Python library | a `Denied` whose message is `port49: <device>: deny <reason>: <detail>` | `.reason` and `.code`, and in the message |
| The Ansible lookup | the failed task's error, `port49: <device>: deny <reason>: <detail>` | the message always holds it, but where you find it depends on the ansible-core version (below) |

Three things about that table.

- **`port49 ssh:` is a person's path, not the agent's.** `port49 ssh` mints through the agent that
  `port49 login` started, which holds a person's session; with no such agent it prints a line that also
  starts `port49 ssh:`. An agent with its own identity runs neither. If an agent ever reports a line that
  starts `port49 ssh:`, it ran `port49 ssh`, which is a person's path (rule 1): stop, and tell a human.
- **On ansible-core 2.16 to 2.18 the code is in the warning.** Those versions censor the message of a failed
  `no_log` task and show only `censored`. The lookup also raises the same message as a `[WARNING]` line, printed
  beside the censored result: read the code there. On 2.19 and later the task's error holds it.
- **A second factor is the one refusal whose message may not hold the code, and it names a person's step.**
  A device that asks for a proof the agent cannot give is `per_login_mfa_required`. The Python `MFARequired`
  message reads
  ``port49: <device>: asks for <methods> at each login, and it could not be given here (<detail>); a person
  must give it, so an agent stops here and asks one: at a terminal, a person's `port49 ssh <device>` proves it,
  and the proof covers their port49 agent's further logins for its reuse_for; a workload's proof is a person's touch
  on its touch_key``,
  and the Ansible lookup raises that same text with `[per_login_mfa_required]` appended when the detail does
  not hold the code. **`port49 ssh` is a person's path (rule 1). An agent runs neither it nor `port49 token`.**
  It stops and asks a human. Read `.code` and `.reason` in Python, not the advice.

In Python, a sweep puts each refusal in `res.refused` instead of raising, so one device does not stop the
rest. Read the code there:

```python
import port49

workload = port49.Workload(broker="https://broker.example.com:8443", broker_ca="/etc/port49/ca.pem",
                           cert="/etc/port49/agent-cert.pem", key="/etc/port49/agent-key.pem")
res = workload.tokens(["leaf1", "core1"])
for device, refusal in res.refused.items():
    print(device, refusal.reason or refusal.error)   # a code, never a token
```

`port49.Workload` presents the agent's own certificate. `port49.Agent` presents whatever person logged in on
the machine, so an agent never constructs one. Never print `res` or `res.tokens`, and never take a token out of
them for a connection of the agent's own: to run a command, use `connect` ([step 4b](#4b-or-run-it-from-python)),
which mints for itself.

## `per_login_mfa_required` devices stay human

A device can require a proof at each login: a touch on a hardware key, or a fresh sign-in at the identity
provider (see [Roles and grants](../admin/roles-and-grants.md#per_login_mfa)). Keep those devices for people.
Two things in the code decide how that works for an agent, and the second is easy to get wrong.

- **A machine is exempt from the requirement by default.** A `per_login_mfa` level applies to a workload
  only when it says `applies_to_machines: true` (spec §5.1.5). So a requirement alone does **not** keep an
  agent off the device. An agent whose subject is granted there is minted a token, and nothing asks it for a
  proof. What keeps it off is that **no grant of the agent's subject reaches the device**. For the agent
  that is `deny no_grants_matched`, as the worked example below shows.
- **With `applies_to_machines: true` an agent cannot meet it.** A workload proves only with
  `hardware_key_touch`, from a PKCS#11 key and a touch key on one token. A person touches that key; an agent
  has nobody to touch it. Without the proof the mint is `deny per_login_mfa_required`, and a Kubernetes
  service account has no key to touch, so it is never proved at all. A requirement the broker cannot
  verify for the device is `deny per_login_mfa_unavailable`. All three codes are in
  `internal/decision/reasons.go` and spec §5.7.

What the agent does on either code: stop, name the device and the code, and ask a human. It never looks for a
touch key, never asks for a PIN, never starts a sign-in, and never runs `port49 token`, nor the
`port49 ssh` that the `MFARequired` message names for a person.

## The worked example: one read-only agent

One agent, `netops-readonly`, may run `show` commands on `leaf1` and nothing on `core1`. The agent's identity
is a workload certificate with the SPIFFE ID `spiffe://example.com/agent/netops-readonly`. Every value here is
a placeholder.

### 1. Identity, subject and grant

The human who administers the policy writes this. The subject lists the agent's one identity and its device
username, and the grant ties it to the `dc_fabric` scope with the read-only role.

```yaml
platform_set: 1.3.0

keys:
  core:
    current: {version: 1, secret_ref: "file:/run/port49/keys/core-v1"}

key_groups:
  - {match: {cidr: 192.0.2.0/24}, key_ref: core}

scopes:
  - name: dc_fabric
    match: {site: [dc1], role: [leaf]}
    on_missing: exclude

roles:
  - name: read_only
    privilege: readonly
    permit:
      - "show version"
      - "show interfaces status"
      - "show ip interface brief"
      - "show ip bgp summary"
      - "show lldp neighbors"
      - "terminal length *"
    deny:
      - "show running-config **"
      - "show startup-config **"
      - "show tech-support **"
      - "show session-config **"
    max_session_age: 1h

subjects:
  - name: agent_readonly
    identity: ["spiffe://example.com/agent/netops-readonly"]
    username: svc-agent-ro
    token_ttl: 120s

grants:
  - {subject: agent_readonly, scope: dc_fabric, roles: [read_only]}

tests:
  - {subject: agent_readonly, device: leaf1, command: "show version", expect: permit}
  - {subject: agent_readonly, device: leaf1, command: "configure terminal", expect: deny}
  - {subject: agent_readonly, device: leaf1, command: "show running-config", expect: deny}
  - {subject: agent_readonly, device: leaf1, command: "show startup-config", expect: deny}
  - {subject: agent_readonly, device: leaf1, command: "show tech-support", expect: deny}
  - {subject: agent_readonly, device: leaf1, command: "show session-config", expect: deny}
  - {subject: agent_readonly, device: core1, command: "show version", expect: deny}
```

The permits are an allow-list of the `show` commands the agent needs, not `show **`. A `show` that prints the
device's configuration (`show running-config`, `show startup-config`, `show tech-support`) prints its AAA lines
and its local users' secrets, and the output lands in the agent's context. So the role also denies each of
them. The allow-list is the fence. Over SSH the denies also hold if someone later widens the permit to
`show **` (re-run with that permit, each of the four is `deny no_permit_dominates_deny`), because an
interactive SSH session on `arista_eos` sends the command with its words spelled out: `sh run` reaches port49 as
`show running-config` ([L21-arista_eos.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L21-arista_eos.md);
`expands_abbreviations: true` in `platforms/1.3.0/arista_eos.yaml`). EOS ships no policy class for
configuration views, so the denies name the commands. Add the equivalents of your own platform from its
[device page](../admin/devices/index.md) before you grant it.

!!! warning "Unmeasured"
    Whether EOS sends a command spelled out over eAPI or NETCONF is unknown, because the lab measured an
    interactive SSH session only. Over a transport that sends `show run` as typed, a full-word deny may not bind,
    and a role widened to `show **` would permit it. The allow-list is what protects the agent there.

The agent connects over SSH only: Ansible `network_cli` or Netmiko through `port49.netmiko.connect`, never eAPI,
`httpapi` or NETCONF. If a play or a script would use another transport, stop and ask a human.

The inventory has both devices, and only `leaf1` is in the scope:

```yaml
devices:
  - {name: leaf1, platform: arista_eos, addresses: [192.0.2.1], attributes: {site: dc1, role: leaf}}
  - {name: core1, platform: arista_eos, addresses: [192.0.2.2], attributes: {site: dc1, role: core}}
```

### 2. Check the policy before it is merged

```sh
port49 policy test --policy policy.yaml --inventory inventory.yaml
```

```text
platform_set: 1.3.0
keys: checked against the default key_secret_refs (env: variables starting PORT49_KEY_, file: under /run/port49/keys); pass --config to check port49d.yaml's
PASS agent_readonly on leaf1: "show version" -> permit permit_dominates
PASS agent_readonly on leaf1: "configure terminal" -> deny no_rule_matched
PASS agent_readonly on leaf1: "show running-config" -> deny no_rule_matched
PASS agent_readonly on leaf1: "show startup-config" -> deny no_rule_matched
PASS agent_readonly on leaf1: "show tech-support" -> deny no_rule_matched
PASS agent_readonly on leaf1: "show session-config" -> deny no_rule_matched
PASS agent_readonly on core1: "show version" -> deny no_grants_matched
7 tests, 0 failed; 0 shadowed denies, 0 unacknowledged; 0 quarantined, 0 projection refusals
```

The last line is the point: the agent has no grant on `core1`, so a refusal there is
`no_grants_matched`. Keep a test like it for every device that stays human. A human reads this output and
merges the policy ([the runbook](setup-runbook.md#stop-and-ask-a-human) says why the agent does not).

### 3. The agent's own check

```sh
port49 explain --policy policy.yaml --inventory inventory.yaml --subject agent_readonly \
  --device leaf1 --command "show version"
```

```text
permit permit_dominates
  subject     agent_readonly
  device      leaf1 (arista_eos)
  grants      dc_fabric [read_only]
  roles       read_only
  level       readonly; max_privilege none
  session     max_session_age 1h0m0s (the least of its roles')
  per_login_mfa none
  command     show version
  rule        show version (read_only) [3 3]
note: arista_eos does not declare config_commands: whether a command typed in configuration mode is sent to port49 at all is unmeasured, so if this is a configuration-mode command the device may apply it whatever this answer says (spec §9, §12)
```

`port49 explain` is offline, prints no secret, and exits 0 for a permit or a deny. Read its first line.

### 4. Run a `show` command through the Ansible lookup

The play mints once, in a `set_fact` with `no_log: true`, in workload mode: the four of `broker`, `broker_ca`,
`cert` and `key` make the lookup run `port49 workload token` instead of any person's agent. The agent's
certificate and key stay in files that only it can read. Never open them.

```yaml
- hosts: leaf1
  gather_facts: false
  pre_tasks:
    - name: mint this host's token
      ansible.builtin.set_fact:
        port49: "{{ lookup('port49.client.token', inventory_hostname, field='all',
                           broker='https://broker.example.com:8443', broker_ca='/etc/port49/ca.pem',
                           cert='/etc/port49/agent-cert.pem', key='/etc/port49/agent-key.pem') }}"
      no_log: true
  vars:
    ansible_connection: ansible.netcommon.network_cli
    ansible_network_os: arista.eos.eos
    ansible_user: "{{ port49.username | default(omit) }}"
    ansible_password: "{{ port49.login | default(omit) }}"
    ansible_look_for_keys: false
  tasks:
    - name: show version
      arista.eos.eos_command:
        commands: ["show version"]
      register: out
      no_log: true
    - name: the command's output, and only that
      ansible.builtin.debug:
        var: out.stdout_lines
```

The command task keeps `no_log: true` because it receives `ansible_password`, so Ansible censors its own
result. `register: out` keeps the result in a variable, and the `debug` prints one key of it, the command's
output, which holds no token. Never drop `no_log` from the mint or the command task to see output, and never
`debug` `port49`, `out` or `ansible_password`. Keep `gather_facts: false`, keep the mint first, and keep
`| default(omit)` exactly as shown, for the reasons on
[Install the clients](../operate/install/clients.md#the-ansible-collection).

If the mint is refused, the play stops for that host. On ansible-core 2.19 and later the error ends with the
code, for example `port49: core1: deny no_grants_matched: <detail>`. On 2.16 to 2.18 the task shows only
`censored` and the same text is in the `[WARNING]` line beside it. Report that line and stop. Leave out any of
`broker`, `broker_ca`, `cert` and `key` and the lookup would use a person's agent instead of the agent's
certificate, so always give all four. The Python `Workload` and this lookup take a certificate and key, and no
token file; a Kubernetes service-account agent is a human's setup ([Workloads](../admin/workloads.md#kubernetes-service-accounts)).

### 4b. Or run it from Python

`port49.netmiko.connect` with `workload=` mints through `port49 workload token` with the agent's certificate,
checks the device's host key under its inventory name before the token is sent
([Install the clients](../operate/install/clients.md#netmiko-and-host-keys)), and returns a Netmiko
connection. The token is in no return value, exception or traceback.

```python
import port49
from port49.netmiko import connect

workload = port49.Workload(broker="https://broker.example.com:8443", broker_ca="/etc/port49/ca.pem",
                           cert="/etc/port49/agent-cert.pem", key="/etc/port49/agent-key.pem")
try:
    conn = connect("leaf1", workload=workload)
except port49.Port49Error as e:
    print(e.device, e.code)   # a code, never a token
    raise SystemExit(1)
try:
    print(conn.send_command("show version"))   # the command's output, and only that
finally:
    conn.disconnect()
```

A refusal raises before anything connects: `Denied`, whose `.code` and `.reason` are the reason code, or
`MFARequired` for a device that asks for a person's second factor ([above](#per_login_mfa_required-devices-stay-human)).
Report the code and stop. Netmiko keeps the token on the connection as `password` (and `secret` with
`enable=True`) to log in again, so never print `conn`, `vars(conn)` or either attribute. Never call
`connect` without `workload=`: with none it uses a person's agent (rule 1), and with no person's agent it
raises `NoAgent`. Each `connect` runs `port49 workload token` once for its one device and never again.

### 5. What is recorded

Each command the device asks about reaches `port49d`, which writes one `authorize_command` record
([Decision log](../reference/decision-log.md)). The agent's records carry its principal, the command as
`request.vector` and the subject that matched, `policy.subject`, which here is `agent_readonly`. The
principal in them is `spiffe://example.com/agent/netops-readonly`, never a person's, so a query on it
returns the agent's commands and nothing else. A denied command is recorded too, with its reason.

## What the agent never does

- Never runs `port49 login`, `port49 ssh`, `port49 token` or `port49 workload token`, and never reads a file
  under the secrets directories ([Secrets](../operate/secrets.md)).
- Never constructs `port49.Agent`, and never calls `port49.netmiko.connect` without `workload=`.
- Never runs a command that prints the device's configuration unsanitized (`show running-config`,
  `show startup-config`, `show tech-support`, or the platform's equivalents).
- Never retries a deny, and never widens its own policy, grant or role.
- Never touches a device's AAA configuration. That is a human's change, from the page for the device's
  platform ([Devices](../admin/devices/index.md)).

The steps that set all this up, in order, with the check after each, are in the
[setup runbook](setup-runbook.md).
