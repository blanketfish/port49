# L22-carried — arista_eos

- **Date measured:** 2026-09-24
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L22-carried-arista_eos.pcap` — 1041 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L22-carried-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

The measurements carried into Task 17 beside the adapters' replies: `port49 devices check-config` against the node's own running configuration; on EOS the identity `priv-lvl=1` + `roles=network-operator` gives; on NX-OS whether the quoted optional `shell:roles*"<role>"` alone sets the role; at fallback, `clear counters` and `clear ip bgp *` beside the configuration change under operator's reply and admin's; and on IOS-XE whether a level-7 command reaches port49 without `aaa authorization commands 7` (plan 5a, Task 17; spec §6, §15 L22; decision 25).

## Observation

### check-config against the device's own running configuration

`show running-config` (lab), 55 lines, redacted copy `tests/lab/evidence/L22-config-arista_eos-lab-1.txt`:

check-config on the raw capture, exit 1:

```
CONFIG: <capture>:39: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
2 local accounts, 1 usernames served on leaf1 (arista_eos), 1 findings
```

check-config on the redacted copy, exit 1:

```
CONFIG: <capture>:39: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
2 local accounts, 1 usernames served on leaf1 (arista_eos), 1 findings
```


### EOS: `priv-lvl=1` + `roles=network-operator` (readonly's rendering)

Session `alice10`, held open with a pty (the request's privilege on the session authorization: `1`).

In it:

```
show privilege
[?1h=Current privilege level is 1
[K[?1l>leaf1>
show users detail
% Invalid input (privileged mode required)
leaf1>
```

`show users detail` from a second session, `alice11`, at admin's reply (`priv-lvl=15`, `roles=network-admin`):

```
Session Username Roles            TTY  State Duration Auth         Remote Host  
------- -------- ---------------- ---- ----- -------- ------------ -------------
1       admin    network-admin    con0 E     0:01:20  local                     
14      alice10  network-operator vty4 E     0:00:04  group port49 172.100.100.1
15      alice11  network-admin    ssh  E     0:00:00  group port49 172.100.100.1
```

### EOS: `home-directory*/home/port49` beside admin's reply, again

| reply | session | identity | `clear counters` | `configure terminal` | `show version` |
|---|---|---|---|---|---|
| `priv-lvl=15`, `roles=network-admin`, `home-directory*/home/port49` | opened | `Current privilege level is 15` | sent to port49 | sent to port49 | permitted by port49 |

### Fallback, each command typed after port49d stopped under the open session

Each command's verbatim reply, from the line typed to the next prompt. The device's command method list ends in `local` (tests/lab/configs/*-startup.cfg).

#### operator: `priv-lvl=15`, `roles=network-operator`

Session `alice13`, before port49d stopped:

```
show privilege
Current privilege level is 15
leaf1#
```

| typed | reply after port49d stopped |
|---|---|
| `clear counters` | `clear counters ⏎ leaf1#` |
| `clear ip bgp *` | `clear ip bgp * ⏎ % BGP inactive ⏎ leaf1#` |
| `configure terminal` | `configure terminal ⏎ % Authorization denied for command 'configure terminal' ⏎ leaf1#` |
| `hostname leaf1` | `hostname leaf1 ⏎ % Invalid input ⏎ leaf1#` |
| `end` | `end ⏎ % Invalid input ⏎ leaf1#` |

#### admin: `priv-lvl=15`, `roles=network-admin`

Session `alice14`, before port49d stopped:

```
show privilege
Current privilege level is 15
leaf1#
```

| typed | reply after port49d stopped |
|---|---|
| `clear counters` | `clear counters ⏎ leaf1#` |
| `clear ip bgp *` | `clear ip bgp * ⏎ % BGP inactive ⏎ leaf1#` |
| `configure terminal` | `configure terminal ⏎ leaf1(config)#` |
| `hostname leaf1` | `hostname leaf1 ⏎ leaf1(config)#` |
| `end` | `end ⏎ leaf1#` |


