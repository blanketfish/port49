# L22-carried — cisco_nxos

- **Date measured:** 2026-11-06
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L22-carried-cisco_nxos.pcap` — 1384 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L22-carried-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,nxos,iosxe`, `-run ^(TestAdapterReplies|TestAdapterCarried)$`

## Claim

The measurements carried into Task 17 beside the adapters' replies: `port49 devices check-config` against the node's own running configuration; on EOS the identity `priv-lvl=1` + `roles=network-operator` gives; on NX-OS whether the quoted optional `shell:roles*"<role>"` alone sets the role; at fallback, `clear counters` and `clear ip bgp *` beside the configuration change under operator's reply and admin's; and on IOS-XE whether a level-7 command reaches port49 without `aaa authorization commands 7` (plan 5a, Task 17; spec §6, §15 L22; decision 25).

## Observation

### check-config against the device's own running configuration

`show running-config` (lab), 189 lines, redacted copy `tests/lab/evidence/L22-config-cisco_nxos-lab-1.txt`:

check-config on the raw capture, exit 0:

```
3 local accounts, 1 usernames served on nx1 (cisco_nxos), 0 findings
```

check-config on the redacted copy, exit 0:

```
3 local accounts, 1 usernames served on nx1 (cisco_nxos), 0 findings
```

`show running-config aaa` (lab), 10 lines, redacted copy `tests/lab/evidence/L22-config-cisco_nxos-lab-2.txt`:

check-config on the raw capture, exit 0:

```
0 local accounts, 1 usernames served on nx1 (cisco_nxos), 0 findings
```

check-config on the redacted copy, exit 0:

```
0 local accounts, 1 usernames served on nx1 (cisco_nxos), 0 findings
```


### NX-OS: the role alone, quoted optional spelling

| reply | session | identity | `clear counters` | `configure terminal` | `show version` |
|---|---|---|---|---|---|
| `shell:roles*"network-operator"` | opened | `roles:network-operator` | sent to port49 | sent to port49 | permitted by port49 |
| `shell:roles*"network-admin"` | opened | `roles:network-admin` | sent to port49 | sent to port49 | permitted by port49 |

### Fallback, each command typed after port49d stopped under the open session

Each command's verbatim reply, from the line typed to the next prompt. The device's command method list ends in `local` (tests/lab/configs/*-startup.cfg).

#### operator: `shell:roles*network-operator`

Session `alice03`, before port49d stopped:

```
show user-account alice03
user:alice03
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1#
```

| typed | reply after port49d stopped |
|---|---|
| `clear counters` | `clear counters ⏎ % Permission denied for the role ⏎ nx1#` |
| `clear ip bgp *` | `clear ip bgp * ⏎ % Permission denied for the role ⏎ nx1#` |
| `configure terminal` | `configure terminal ⏎ Enter configuration commands, one per line. End with CNTL/Z. ⏎ nx1(config)#` |
| `hostname nx1` | `hostname nx1 ⏎ % Permission denied for the role ⏎ nx1(config)#` |
| `end` | `end ⏎ nx1#` |

#### admin: `shell:roles*network-admin`

Session `alice04`, before port49d stopped:

```
show user-account alice04
user:alice04
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1#
```

| typed | reply after port49d stopped |
|---|---|
| `clear counters` | `clear counters ⏎  (no prompt within 45s)` |
| `clear ip bgp *` | `clear ip bgp * ⏎  (no prompt within 45s)` |
| `configure terminal` | `configure terminal ⏎ error: clearing pfstat counters ⏎ nx1# clear ip bgp * ⏎ nx1# configure terminal ⏎ Enter configuration commands, one per line. End with CNTL/Z. ⏎ nx1(config)#` |
| `hostname nx1` | `hostname nx1 ⏎ nx1(config)#` |
| `end` | `end ⏎ nx1#` |


