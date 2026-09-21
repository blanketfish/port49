# L16 — arista_eos

- **Date measured:** 2026-09-21
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L16-arista_eos.pcap` — 1664 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L16-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether a custom role delivered by name over TACACS+ takes effect on EOS and NX-OS; whether a command that role forbids is refused locally and whether the device still sends a per-command authorization request for it; which wins when the device's role and port49 disagree, in both directions; two roles at once; a role the device does not have; no role attribute at all; the accepted spellings of the attribute; and the `priv-lvl=N` to role mapping.

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

**1.** Measured: delivering role `p49-noc` by name did NOT take effect: the command the role denies ran anyway. Whatever the device reported for `show users detail`, the role's rules were not applied to this session.

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

