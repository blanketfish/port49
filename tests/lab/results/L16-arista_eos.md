# L16 — arista_eos

- **Date measured:** 2026-09-21
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L16-arista_eos.pcap` — 1664 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L16-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether a custom role delivered by name over TACACS+ takes effect on EOS and NX-OS; whether a command that role forbids is refused locally and whether the device still sends a per-command authorization request for it; which wins when the device's role and port49 disagree, in both directions; two roles at once; a role the device does not have; no role attribute at all; the accepted spellings of the attribute; and the `priv-lvl=N` to role mapping.

## Correction, 2026-09-22 — read this before the section below

**The reading "vEOS does not apply a role" was an artefact of the attribute NAME, not a property of
EOS.** Every variant of the 2026-09-21 run below spelled the attribute `shell:roles`, which is NX-OS's
spelling. EOS reads the **bare** attribute `roles=<name>`, which that run never sent. Sent by its own
name it is applied, the device reports it, and under local command authorization it is the operator's
real privilege — measured 2026-09-22 and written up in
*"The bare `roles` attribute, and `priv-lvl` mandatory against optional"* at the end of this file.

Everything measured below stands and none of it is withdrawn: `shell:roles*` really does nothing on
this platform, `shell:roles=` sent mandatory really does end the session, and port49's per-command
deny really does bind. What was wrong was the sentence generalising from them, in this file's
question 1 and in the spec row that quoted it. Wherever the text below says a role "did not take
effect" or was "not applied", read **`shell:roles` did not take effect** — the claim was never tested
against the attribute Arista actually reads.

## Observation

The device holds one custom role, defined for this test and removed afterwards:

```
role p49-noc
10 deny command show version
20 permit command .*
exit
```

It permits everything and denies exactly one command, so one variable separates the two probes that matter. The three probes are `show version` (the role denies it, port49 permits it), `show clock` (the role permits it, port49 denies it — it is the last entry of `lab.deny_prefixes`), and `show hostname` (both permit it, the control). Each variant below is one set of reply attributes, one daemon restart and one token login.

### no role attribute at all

the control. Whatever the device does here is what a role delivery has to be measured against, and it is also what port49 sends today on every platform but NX-OS.

Reply attributes: `["priv-lvl=15"]`

`show users detail` — the `Role` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:01:32        local                           
42            alice07        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.fcce.b8ad
System MAC address: 0c00.fcce.b8ad

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 2 minutes
Total memory: 1979668 kB
Free memory: 650500 kB

leaf1#
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Hostname: leaf1
FQDN:     leaf1
leaf1#
```


### `shell:roles*<role>` — bare, OPTIONAL

the spelling `tests/lab/port49d-lab.yaml` has been sending since the N9Kv asked for it, with the custom role in place of `network-admin`. Nothing has ever checked that the device applies it.

Reply attributes: `["priv-lvl=15", "shell:roles*p49-noc"]`

`show users detail` — the `Role` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:01:44        local                           
43            alice08        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.fcce.b8ad
System MAC address: 0c00.fcce.b8ad

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 2 minutes
Total memory: 1979668 kB
Free memory: 651256 kB

leaf1#
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Hostname: leaf1
FQDN:     leaf1
leaf1#
```


### `shell:roles=<role>` — bare, MANDATORY

the same attribute sent as mandatory. RFC 8907 §8.2 says a device that does not understand a mandatory argument must fail the authorization, so this variant also asks whether the device understands it at all.

Reply attributes: `["priv-lvl=15", "shell:roles=p49-noc"]`

**The session never opened.**

```
none of ["leaf1#" "leaf1>"] appeared on the SSH CLI as alice09 within 45s; what it said was:
Authorization denied: 

```


### inside `cisco-av-pair`

the spelling Cisco documentation uses for NX-OS. If both work the adapter has a choice; if only one does, plan 5 has no choice at all.

Reply attributes: `["priv-lvl=15", "cisco-av-pair*shell:roles=\"p49-noc\""]`

**The session never opened.**

```
none of ["leaf1#" "leaf1>"] appeared on the SSH CLI as alice10 within 45s; what it said was:
Authorization denied: 

```


### two roles at once

NX-OS documents a union with permit winning. If that holds, a role delivered alongside a permissive one is not a restriction, which is the whole point of delivering it.

Reply attributes: `["priv-lvl=15", "shell:roles*\"p49-noc network-operator\""]`

`show users detail` — the `Role` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:03:37        local                           
46            alice11        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.fcce.b8ad
System MAC address: 0c00.fcce.b8ad

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 4 minutes
Total memory: 1979668 kB
Free memory: 712572 kB

leaf1#
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Hostname: leaf1
FQDN:     leaf1
leaf1#
```


### a role the device does not have

the 3am case: a policy names a role that was renamed or never created on this device. Does the operator get no privileges, all of them, or no session?

Reply attributes: `["priv-lvl=15", "shell:roles*p49-nosuchrole"]`

`show users detail` — the `Role` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:03:49        local                           
47            alice12        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.fcce.b8ad
System MAC address: 0c00.fcce.b8ad

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 4 minutes
Total memory: 1979668 kB
Free memory: 711540 kB

leaf1#
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Hostname: leaf1
FQDN:     leaf1
leaf1#
```


### `priv-lvl=1` alone

the privilege-level path rather than the role path, for the mapping half of this row. On NX-OS this is only meaningful with `feature privilege`, and this lab does not configure it, so what the device does with it here is itself the finding.

Reply attributes: `["priv-lvl=1"]`

`show users detail` — the `Role` column names the role EOS believes this session holds:

```
% Invalid input (privileged mode required)
leaf1>
```

`show version` (the custom role DENIES this; port49 permits it) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.fcce.b8ad
System MAC address: 0c00.fcce.b8ad

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 4 minutes
Total memory: 1979668 kB
Free memory: 712304 kB

leaf1>
```

`show clock` (the custom role permits this; port49 DENIES it) — port49 answered **deny no_permit_dominates_deny**, 1 authorization request(s); the device said:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1>
```

`show hostname` (both permit this — the control) — port49 answered **permit permit_dominates**, 1 authorization request(s); the device said:

```
Hostname: leaf1
FQDN:     leaf1
leaf1>
```


## Every variant side by side

| reply attributes | session | role reported | `show version` (role denies) | `show clock` (port49 denies) | `show hostname` (control) |
|---|---|---|---|---|---|
| no role attribute at all | opened | (see the variant above) | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| `shell:roles*<role>` — bare, OPTIONAL | opened | (see the variant above) | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| `shell:roles=<role>` — bare, MANDATORY | **no session** | — | — | — | — |
| inside `cisco-av-pair` | **no session** | — | — | — | — |
| two roles at once | opened | (see the variant above) | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| a role the device does not have | opened | (see the variant above) | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |
| `priv-lvl=1` alone | opened | (see the variant above) | ran; 1 req; permit permit_dominates | **refused**; 1 req; deny no_permit_dominates_deny | ran; 1 req; permit permit_dominates |

## What this answers

**1.** Measured: delivering role `p49-noc` **as `shell:roles*p49-noc`** did NOT take effect: the command the role denies ran anyway, and `show users detail` named the session `<unknown>`. That is a finding about the attribute `shell:roles`, and it stands. It is **not** a finding about role delivery on EOS: the bare attribute `roles=p49-noc` was never sent in this run, and when it was sent on 2026-09-22 the device applied it (see the correction at the top of this file).

Sent:

```
show version
```

The device replied:

```
Arista vEOS-lab
Hardware version: 
Serial number: 
Hardware MAC address: 0c00.fcce.b8ad
System MAC address: 0c00.fcce.b8ad

Software image version: 4.31.2F
Architecture: x86_64
Internal build version: 4.31.2F-35442176.4312F
Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc
Image format version: 1.0
Image optimization: None

Uptime: 2 minutes
Total memory: 1979668 kB
Free memory: 651256 kB

leaf1#
```

**3. port49's deny wins over the role's permit.** `show clock` is permitted by the role and denied by port49 (`deny no_permit_dominates_deny`), and the device refused it. So a per-command deny is real on this platform whatever the role says.

Every other question — the spellings, two roles at once, an absent role, `priv-lvl=1` — is answered by the table above, cell by cell, and each cell is what that variant's session did.

## The bare `roles` attribute, and `priv-lvl` mandatory against optional
- **Date measured:** 2026-09-22
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Capture:** `tests/lab/evidence/L16-eos-roles-arista_eos.pcap` — 4671 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L16-eos-roles-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

Every variant of the 2026-09-21 run above spelled the attribute `shell:roles`, which is NX-OS's name for it. **This section sends the BARE name, `roles`**, which is what Arista reads and what the owner runs in production, and it asks `priv-lvl` MANDATORY against OPTIONAL as well -- the owner reports that an optional `priv-lvl*` is ignored here and the session is left at level 1. Neither had ever been sent to this device.

Each variant below is one set of reply attributes, one daemon restart and one token login. Per session: the prompt the login produced, `show users detail` for the role the device names for this user, `show privilege` for the level it reports, `configure` and `hostname leaf1` for whether the session can change the device, and `show clock` -- the last entry of `lab.deny_prefixes` -- for whether port49's per-command deny still binds. The custom role from the section above is defined for the run and removed after it:

```
role p49-noc
10 deny command show version
20 permit command .*
exit
```

### `priv-lvl=15` alone — the control

what `tests/lab/port49d-lab.yaml` sends to this platform today, minus the `shell:roles*` the 2026-09-21 run showed does nothing here. Whatever role and privilege level this produces is the baseline every row below has to differ from before anything can be claimed about the `roles` attribute.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:00:11        local                           
5             alice01        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl=15` + `roles=network-operator` — MANDATORY

**the question.** The bare attribute name the owner runs in production, sent MANDATORY as they send it, with a read-only role against an administrative privilege level. If the device names `network-operator` here and `network-admin` in the control, the 2026-09-21 reading was an artefact of the `shell:` prefix and nothing else.

Reply attributes: `["priv-lvl=15", "roles=network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                  TTY        State       Duration       Auth               Remote Host  
------------- -------------- ---------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin          con0       E           0:00:23        local                           
6             alice02        network-operator       vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl=15` + `roles*network-operator` — OPTIONAL

the same attribute sent OPTIONAL -- the case the owner could not remember. RFC 8907 §8.2 lets a device ignore an optional argument it does not understand, and this platform has already been seen ending a session over one (`cisco-av-pair*`), so the flag is not a formality here.

Reply attributes: `["priv-lvl=15", "roles*network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                  TTY        State       Duration       Auth               Remote Host  
------------- -------------- ---------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin          con0       E           0:00:36        local                           
7             alice03        network-operator       vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `roles=network-operator` alone, no `priv-lvl`

the role with no privilege level in the reply at all. This is the shape an adapter would send under a "roles only" rule, so it is also the variant that says whether that rule is safe to ship on EOS -- and what privilege level a session lands on when nothing names one.

Reply attributes: `["roles=network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1>`.

`show users detail` — **the device refused it**, so this variant measures no role at all. What it said, verbatim:

```
% Invalid input (privileged mode required)
leaf1>
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 1
leaf1>
```

`configure` (does the session reach configuration mode at all) — the device **refused** it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
% Invalid input (privileged mode required)
leaf1>
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — **not typed**: the session never reached configuration mode, so this command was not typed.

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=1`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1>
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show privilege -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl*2` alone — OPTIONAL

the owner's second production reading: an OPTIONAL `priv-lvl*` is ignored on EOS and the session is left at level 1. Nothing in this lab has ever sent `priv-lvl` optional to any platform, so this is the first time it is asked.

Reply attributes: `["priv-lvl*2"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:01:00        local                           
9             alice05        <unknown>           vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 2
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=2`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=2`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=2`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl=2` alone — MANDATORY

the same level sent MANDATORY, which is the half that makes the row above a measurement rather than a curiosity: two replies one argument flag apart, on the same device in the same minute.

Reply attributes: `["priv-lvl=2"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:01:13        local                           
10            alice06        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 2
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=2`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=2`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=2`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl=15` + `roles=p49-noc`

a CUSTOM role rather than a built-in one. A built-in name might be resolved by a table the custom ones are not in, and a custom role is what plan 5 would actually deliver.

Reply attributes: `["priv-lvl=15", "roles=p49-noc"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:01:25        local                           
11            alice07        p49-noc             vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl=15` + `roles="p49-noc network-operator"` — quoted

two roles in one value, in the quoted form NX-OS takes. NX-OS delivers these as a union with permit winning, which would make a restrictive role delivered beside a permissive one no restriction at all. Whether EOS does the same, takes one of them, or takes neither is unmeasured -- and so is whether it strips the quotes, which the two rows after this one are here to separate.

Reply attributes: `["priv-lvl=15", "roles=\"p49-noc network-operator\""]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                            TTY        State       Duration       Auth               Remote Host  
------------- -------------- -------------------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin                    con0       E           0:01:38        local                           
12            alice08        "p49-noc network-operator"       vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl=15` + `roles=p49-noc network-operator` — unquoted

the same two roles with no quotes around them. A TACACS+ argument is one string to its end, so the space needs no quoting on the wire; if the quoted row above comes back with a quote character inside the role name, this row is the one that says what the device does with the pair itself.

Reply attributes: `["priv-lvl=15", "roles=p49-noc network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                          TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------------------ ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin                  con0       E           0:01:50        local                           
13            alice09        p49-noc network-operator       vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl=15` + `roles=p49-noc,network-operator` — comma

the same two roles comma-separated, the third spelling a fleet might have in its server definition. Three spellings of one intention, one deploy: whichever the device takes is the one an adapter may send, and "none of them" is an answer too.

Reply attributes: `["priv-lvl=15", "roles=p49-noc,network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                          TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------------------ ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin                  con0       E           0:02:03        local                           
14            alice10        p49-noc,network-operator       vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


### `priv-lvl=15` + `roles=p49-nosuchrole`

the 3am case: a policy names a role that was renamed or never created on this device. Does the operator get no privileges, all of them, or no session? On NX-OS the answer is a silent degradation to `network-operator`, which is the safe direction and invisible to port49.

Reply attributes: `["priv-lvl=15", "roles=p49-nosuchrole"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                TTY        State       Duration       Auth               Remote Host  
------------- -------------- -------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin        con0       E           0:02:15        local                           
15            alice11        p49-nosuchrole       vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **permit permit_dominates** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **deny no_permit_dominates_deny** over 1 authorization request(s), asserting `privilege=15`. Verbatim:

```
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#
```

Every command authorization port49 answered in this session, as it arrived:

```
terminal length 0 -> permit permit_dominates
show users detail -> permit permit_dominates
show privilege -> permit permit_dominates
configure -> permit permit_dominates
hostname leaf1 -> permit permit_dominates
show clock -> deny no_permit_dominates_deny
```


#### Every variant side by side

| reply attributes | session | role the device reports | privilege | config mode | `hostname` accepted | `show clock` | port49 asked |
|---|---|---|---|---|---|---|---|
| `priv-lvl=15` alone — the control | opened (`leaf1#`) | `<unknown>` | `15` | entered | yes | refused | 3 req |
| `priv-lvl=15` + `roles=network-operator` — MANDATORY | opened (`leaf1#`) | `network-operator` | `15` | entered | yes | refused | 3 req |
| `priv-lvl=15` + `roles*network-operator` — OPTIONAL | opened (`leaf1#`) | `network-operator` | `15` | entered | yes | refused | 3 req |
| `roles=network-operator` alone, no `priv-lvl` | opened (`leaf1>`) | **not measured** (the device refused the command) | `1` | **refused** | — | refused | 1 req |
| `priv-lvl*2` alone — OPTIONAL | opened (`leaf1#`) | `<unknown>` | `2` | entered | yes | refused | 3 req |
| `priv-lvl=2` alone — MANDATORY | opened (`leaf1#`) | `<unknown>` | `2` | entered | yes | refused | 3 req |
| `priv-lvl=15` + `roles=p49-noc` | opened (`leaf1#`) | `p49-noc` | `15` | entered | yes | refused | 3 req |
| `priv-lvl=15` + `roles="p49-noc network-operator"` — quoted | opened (`leaf1#`) | `"p49-noc network-operator"` | `15` | entered | yes | refused | 3 req |
| `priv-lvl=15` + `roles=p49-noc network-operator` — unquoted | opened (`leaf1#`) | `p49-noc network-operator` | `15` | entered | yes | refused | 3 req |
| `priv-lvl=15` + `roles=p49-noc,network-operator` — comma | opened (`leaf1#`) | `p49-noc,network-operator` | `15` | entered | yes | refused | 3 req |
| `priv-lvl=15` + `roles=p49-nosuchrole` | opened (`leaf1#`) | `p49-nosuchrole` | `15` | entered | yes | refused | 3 req |

#### Phase B — the same question with port49 out of the command path

10 of the 11 sessions above configured the device, whatever role it named for them. That is `aaa authorization commands all default group port49 local` sending every command to a lab authorizer that permits everything, so the role is never consulted -- not the role failing to arrive. Phase B points the command-authorization method list at the device's own role database:

```
aaa authorization commands all default local
```

and puts it back afterwards. `aaa authorization exec` is left pointed at port49 throughout, because a token operator has no local account and moving it would refuse every login.


### `priv-lvl=15` + `roles=network-admin`, command authorization LOCAL

the administrative role delivered by the bare attribute, with the device authorizing its own commands. If this session configures the device and the one below does not, the role port49 sends is real privilege on a device that enforces it -- not a label.

Reply attributes: `["priv-lvl=15", "roles=network-admin"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:02:30        local                           
17            alice12        network-admin       vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
leaf1(config)#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
leaf1(config)#
```

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
Tue Sep 22 02:29:01 2026
Timezone: UTC
Clock source: local
leaf1#
```

**No command authorization reached port49 in this session at all.**


### `priv-lvl=15` + `roles=network-operator`, command authorization LOCAL

the read-only role, same method list, same minute, one attribute value apart from the row above.

Reply attributes: `["priv-lvl=15", "roles=network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                  TTY        State       Duration       Auth               Remote Host  
------------- -------------- ---------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin          con0       E           0:02:42        local                           
18            alice13        network-operator       vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device **refused** it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
% Authorization denied for command 'configure'
leaf1#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — **not typed**: the session never reached configuration mode, so this command was not typed.

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
Tue Sep 22 02:29:13 2026
Timezone: UTC
Clock source: local
leaf1#
```

**No command authorization reached port49 in this session at all.**


### `priv-lvl=15` alone, command authorization LOCAL

the control: no role in the reply at all. `configs/eos-startup.cfg` already records that an EOS account with `privilege 15` and NO role falls to the default role, which refuses `configure`, so this row is expected to be refused -- and it is what stops a refusal in the row above from being read as the role binding when it is really every remote session being refused.

Reply attributes: `["priv-lvl=15"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — **the device refused it**, so this variant measures no role at all. What it said, verbatim:

```
% Authorization denied for command 'show users detail': Unknown role
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
% Authorization denied for command 'show privilege': Unknown role
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device **refused** it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
% Authorization denied for command 'configure': Unknown role
leaf1#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — **not typed**: the session never reached configuration mode, so this command was not typed.

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device **refused** it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
% Authorization denied for command 'show clock': Unknown role
leaf1#
```

**No command authorization reached port49 in this session at all.**


### `priv-lvl=15` + `roles=p49-nosuchrole`, command authorization LOCAL

the 3am case, asked where it means something. Phase A's unknown-role session ran every command, but port49 was answering all of them, so that row says nothing about what the operator can do. Here the device is the one deciding, and a policy that names a role this device does not have is a policy an operator is holding at 3am.

Reply attributes: `["priv-lvl=15", "roles=p49-nosuchrole"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                TTY        State       Duration       Auth               Remote Host  
------------- -------------- -------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin        con0       E           0:03:06        local                           
20            alice15        p49-nosuchrole       vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device **refused** it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
% Authorization denied for command 'configure'
leaf1#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — **not typed**: the session never reached configuration mode, so this command was not typed.

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
Tue Sep 22 02:29:37 2026
Timezone: UTC
Clock source: local
leaf1#
```

**No command authorization reached port49 in this session at all.**


### `priv-lvl=15` + `roles=p49-noc network-operator`, command authorization LOCAL

the two-role question asked where it has an answer. Phase A measured which names the device REPORTS; only here does it matter which rules apply. `p49-noc` permits every command and `network-operator` is read-only, so if this session configures the device the union takes the permit -- and a restrictive role delivered beside a permissive one is no restriction at all, which is the whole point of delivering one.

Reply attributes: `["priv-lvl=15", "roles=p49-noc network-operator"]`

port49 answered the session authorization **permit context_matched**; the device asserted `session.privilege=1` on the request.

The login itself landed on `leaf1#`.

`show users detail` — the `Roles` column names the role EOS believes this session holds:

```
Session       Username       Roles                          TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------------------ ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin                  con0       E           0:03:18        local                           
21            alice16        p49-noc network-operator       vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

`show privilege` — the device's own word for the privilege level:

```
Current privilege level is 15
leaf1#
```

`configure` (does the session reach configuration mode at all) — the device **refused** it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
% Authorization denied for command 'configure'
leaf1#
```

`hostname leaf1` (the configuration command itself, writing the value the device already holds) — **not typed**: the session never reached configuration mode, so this command was not typed.

`show clock` (port49 denies this by prefix; whether the device still refuses it says whether a per-command deny binds under this reply) — the device accepted it; port49 answered **nothing (no authorization request reached port49)** over 0 authorization request(s). Verbatim:

```
Tue Sep 22 02:29:49 2026
Timezone: UTC
Clock source: local
leaf1#
```

**No command authorization reached port49 in this session at all.**


#### Every variant side by side

| reply attributes | session | role the device reports | privilege | config mode | `hostname` accepted | `show clock` | port49 asked |
|---|---|---|---|---|---|---|---|
| `priv-lvl=15` + `roles=network-admin`, command authorization LOCAL | opened (`leaf1#`) | `network-admin` | `15` | entered | yes | **ran** | 0 req |
| `priv-lvl=15` + `roles=network-operator`, command authorization LOCAL | opened (`leaf1#`) | `network-operator` | `15` | **refused** | — | **ran** | 0 req |
| `priv-lvl=15` alone, command authorization LOCAL | opened (`leaf1#`) | **not measured** (the device refused the command) | (not reported) | **refused** | — | refused | 0 req |
| `priv-lvl=15` + `roles=p49-nosuchrole`, command authorization LOCAL | opened (`leaf1#`) | `p49-nosuchrole` | `15` | **refused** | — | **ran** | 0 req |
| `priv-lvl=15` + `roles=p49-noc network-operator`, command authorization LOCAL | opened (`leaf1#`) | `p49-noc network-operator` | `15` | **refused** | — | **ran** | 0 req |

#### What this answers

**1. The bare `roles` attribute IS applied, and the 2026-09-21 reading was an artefact of the attribute name.** `roles=network-operator` sent mandatory puts the session on `network-operator`; the same reply with the attribute removed puts it on `<unknown>`, on the same device minutes apart. The device's own words:

```
Session       Username       Roles                  TTY        State       Duration       Auth               Remote Host  
------------- -------------- ---------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin          con0       E           0:00:23        local                           
6             alice02        network-operator       vty4       E           0:00:00        group port49       172.100.100.1
leaf1#
```

and the control:

```
Session       Username       Roles               TTY        State       Duration       Auth               Remote Host  
------------- -------------- ------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin       con0       E           0:00:11        local                           
5             alice01        <unknown>           vty4       E           0:00:01        group port49       172.100.100.1
leaf1#
```

Everything the earlier section measured stands -- `shell:roles` really does nothing here -- but "vEOS does not apply a role" was a statement about the spelling `shell:roles`, not about EOS.

**2. The argument flag does not change it.** Optional and mandatory both name `network-operator`, and the session opened either way. RFC 8907 §8.2's distinction decides whether a device may ignore an attribute; this device ignores `roles` under neither flag.

**3. The role alone, with no `priv-lvl` in the reply, lands the session at privilege `1`.** port49 answered the session authorization `permit context_matched`, the session opened on `leaf1>`, and the role it holds is nothing this run can read: the device refused `show users detail`. **Which is the finding: at privilege `1` the device refuses `show users detail` outright, so a reply that names a role and no privilege level produces a session whose role cannot be read -- by this test or by the operator holding it.** Whether the role arrived and is simply unreadable, or never arrived, is NOT separated by this row; what is measured is that dropping `priv-lvl` costs the session its privilege level. An adapter for EOS therefore sends both attributes, which is the opposite of the NX-OS rule.

**4. The argument flag on `priv-lvl` makes no difference here.** Optional and mandatory both leave the session at level `2`, on `leaf1#` and `leaf1#`. The owner's production reading -- that an optional `priv-lvl*` is ignored and level 1 assumed -- does **not** reproduce on this image.

**5. A custom role behaves like a built-in one here:** `roles=p49-noc` names `p49-noc` and reports privilege `15`. That is the shape plan 5 would deliver.

**6. Two roles in one value, three spellings.** `priv-lvl=15` + `roles="p49-noc network-operator"` — quoted names `"p49-noc network-operator"`. `priv-lvl=15` + `roles=p49-noc network-operator` — unquoted names `p49-noc network-operator`. `priv-lvl=15` + `roles=p49-noc,network-operator` — comma names `p49-noc,network-operator`. **The quoted spelling is a trap:** the device kept the quote character as part of the role name rather than stripping it, so a reply copied from an NX-OS server definition names a role no device has. The unquoted spelling is the one that arrives as two names separated by a space, which is what the device's own column shows. **Whether that is a union or only a label with a space in it is not decided here** -- port49 answered every command in these sessions -- and finding 11 below asks it where the device is the one authorizing.

**7. A role the device does not have** is reported back as `p49-nosuchrole`, with privilege `15`, and the session still opened. The device does not degrade the name to anything: it repeats what it was sent. port49 cannot tell it happened either -- the reply it sent and the record it wrote are identical to the case where the role exists. What that costs the operator is phase B's question, not this one's, because here port49 answered every command.

**8. port49's per-command deny binds under every one of these replies.** `show clock` was refused in all 11 sessions that opened, whatever role the device named and whatever privilege level it reported. A per-command deny is real on this platform however the session was delivered.

**9. With port49 out of the command path, the delivered role is real privilege.** Measured: Under `aaa authorization commands all default local`, a session delivered `roles=network-operator` CANNOT change the device: `configure` is refused. The same reply naming `network-admin` runs it. So the role the bare attribute delivers is what the device enforces once the device is the one enforcing.

Sent:

```
reply attributes ["priv-lvl=15", "roles=network-operator"]
then, in the session:
configure
```

The device replied:

```
% Authorization denied for command 'configure'
leaf1#
```

The administrative role, same method list, same minute, the same command:

```
leaf1(config)#
```

And the no-role control, which `configs/eos-startup.cfg` predicts falls to the default role: `configure` was **refused**.

```
% Authorization denied for command 'configure': Unknown role
leaf1#
```

**10. The 3am case: an unknown role name is a session that can do nothing.** Measured: Under `aaa authorization commands all default local`, a session delivered `roles=p49-nosuchrole` CANNOT change the device. The session opens, the device reports the role by the name it was sent, and the commands are refused. So on EOS a policy naming a role that was renamed or never created leaves the operator with a session and no privileges -- the safe direction, and invisible to port49, which sent a reply identical to the working case.

Sent:

```
reply attributes ["priv-lvl=15", "roles=p49-nosuchrole"]
then, in the session:
configure
```

The device replied:

```
% Authorization denied for command 'configure'
leaf1#
```

Even `show clock`, which needs no privilege, was accepted:

```
Tue Sep 22 02:29:37 2026
Timezone: UTC
Clock source: local
leaf1#
```

**11. Two roles do not take the permit here.** The device reports this session as `p49-noc network-operator` and refused `configure` under local command authorization, exactly as the read-only role alone was refused:

```
% Authorization denied for command 'configure'
leaf1#
```

So the permissive half of the pair did not carry it, and a union with permit winning is NOT what this image does.

**The adapter rule this supports: on EOS send the BARE attribute `roles=<name>`, not `shell:roles`.** The bare name puts the session on `network-operator` where the same reply without it gives `<unknown>`; the `shell:` spelling the earlier section measured does nothing here and its mandatory form ends the session outright. Either argument flag delivers it, so the mandatory form the owner runs is a choice and not a requirement. The flag on `priv-lvl` makes no difference on this image -- optional and mandatory both reach level `2` -- so the owner's production reading about an ignored `priv-lvl*` is not reproduced here and an adapter rule should not rest on it. **Both attributes go in the reply, which is the opposite of the NX-OS rule:** the role with no `priv-lvl` beside it opens a session at level `1` on `leaf1>`, against level `15` on `leaf1#` when the level is sent too. On NX-OS `priv-lvl` is inert beside a role and an adapter drops it; on EOS dropping it costs the operator their privilege level. One reply cannot serve both platforms. **Phase B is what makes this a privilege claim rather than a labelling one:** with the device authorizing its own commands, the reply naming `network-operator` is refused `configure` and the one naming `network-admin` runs it. The role port49 sends is the operator's real privilege on a device that enforces it, which is the state a fleet is in before port49 owns command authorization.

Every other cell -- the privilege the device asserted on each request, how many authorization requests each command cost, what each session was told -- is in the tables above, and each one is what that variant's session did on vEOS-lab 4.31.2F (image tagged 4.32.2F).
