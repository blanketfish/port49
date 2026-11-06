# L22-carried — cisco_iosxe

- **Date measured:** 2026-11-06
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L22-carried-cisco_iosxe.pcap` — 966 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L22-carried-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,nxos,iosxe`, `-run ^(TestAdapterReplies|TestAdapterCarried)$`

## Claim

The measurements carried into Task 17 beside the adapters' replies: `port49 devices check-config` against the node's own running configuration; on EOS the identity `priv-lvl=1` + `roles=network-operator` gives; on NX-OS whether the quoted optional `shell:roles*"<role>"` alone sets the role; at fallback, `clear counters` and `clear ip bgp *` beside the configuration change under operator's reply and admin's; and on IOS-XE whether a level-7 command reaches port49 without `aaa authorization commands 7` (plan 5a, Task 17; spec §6, §15 L22; decision 25).

## Observation

### check-config against the device's own running configuration

`show running-config` (lab), 255 lines, redacted copy `tests/lab/evidence/L22-config-cisco_iosxe-lab-1.txt`:

check-config on the raw capture, exit 1:

```
CONFIG: <capture>:40: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
2 local accounts, 1 usernames served on xe1 (cisco_iosxe), 1 findings
```

check-config on the redacted copy, exit 1:

```
CONFIG: <capture>:40: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
2 local accounts, 1 usernames served on xe1 (cisco_iosxe), 1 findings
```

`show running-config | section aaa` (lab), 18 lines, redacted copy `tests/lab/evidence/L22-config-cisco_iosxe-lab-2.txt`:

check-config on the raw capture, exit 1:

```
CONFIG: <capture>:8: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
MISSING: <capture>: privilege exec level 7 clear counters: the configuration does not carry this line, and the cisco_iosxe adapter's renderings depend on it: without it a level is not what the adapter says it is (spec §6; the platform set's line: port49 platform show --set 1.0.0 cisco_iosxe)
note: the configuration has no hostname line, so it may be a partial capture (| section ...): a MISSING line may be in the part left out; check-config reads the whole show running-config
0 local accounts, 1 usernames served on xe1 (cisco_iosxe), 2 findings
```

check-config on the redacted copy, exit 1:

```
CONFIG: <capture>:8: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
MISSING: <capture>: privilege exec level 7 clear counters: the configuration does not carry this line, and the cisco_iosxe adapter's renderings depend on it: without it a level is not what the adapter says it is (spec §6; the platform set's line: port49 platform show --set 1.0.0 cisco_iosxe)
note: the configuration has no hostname line, so it may be a partial capture (| section ...): a MISSING line may be in the part left out; check-config reads the whole show running-config
0 local accounts, 1 usernames served on xe1 (cisco_iosxe), 2 findings
```


### Fallback, each command typed after port49d stopped under the open session

Each command's verbatim reply, from the line typed to the next prompt. The device's command method list ends in `local` (tests/lab/configs/*-startup.cfg).

#### operator: `priv-lvl=7`

Session `alice01`, before port49d stopped:

```
show privilege
Current privilege level is 7
xe1#
```

| typed | reply after port49d stopped |
|---|---|
| `clear counters` | `clear counters ⏎ % Authorization failed. ⏎  ⏎ xe1#` |
| `clear ip bgp *` | `clear ip bgp * ⏎             ^ ⏎ % Invalid input detected at '^' marker. ⏎  ⏎ xe1#` |
| `configure terminal` | `configure terminal ⏎        ^ ⏎ % Invalid input detected at '^' marker. ⏎  ⏎ xe1#` |
| `hostname xe1` | `hostname xe1 ⏎      ^ ⏎ % Invalid input detected at '^' marker. ⏎  ⏎ xe1#` |
| `end` | `end ⏎ % Authorization failed. ⏎       ^ ⏎ % Invalid input detected at '^' marker. ⏎  ⏎ xe1#` |

#### admin: `priv-lvl=15`

Session `alice02`, before port49d stopped:

```
show privilege
Current privilege level is 15
xe1#
```

| typed | reply after port49d stopped |
|---|---|
| `clear counters` | `clear counters ⏎ % Authorization failed. ⏎  ⏎ xe1#` |
| `clear ip bgp *` | `clear ip bgp * ⏎ % Authorization failed. ⏎  ⏎ xe1#` |
| `configure terminal` | `configure terminal ⏎ % Authorization failed. ⏎  ⏎ xe1#` |
| `hostname xe1` | `hostname xe1 ⏎      ^ ⏎ % Invalid input detected at '^' marker. ⏎  ⏎ xe1#` |
| `end` | `end ⏎ % Authorization failed. ⏎       ^ ⏎ % Invalid input detected at '^' marker. ⏎  ⏎ xe1#` |


### IOS-XE: level 7 without `aaa authorization commands 7 default group port49 local`

`show running-config` (no-commands-7), 292 lines, redacted copy `tests/lab/evidence/L22-config-cisco_iosxe-no-commands-7-1.txt`:

check-config on the raw capture, exit 1:

```
CONFIG: <capture>:40: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
MISSING: <capture>: aaa authorization commands 7 default group port49 local: the configuration does not carry this line, and the cisco_iosxe adapter's renderings depend on it: without it a level is not what the adapter says it is (spec §6; the platform set's line: port49 platform show --set 1.0.0 cisco_iosxe)
2 local accounts, 1 usernames served on xe1 (cisco_iosxe), 2 findings
```

check-config on the redacted copy, exit 1:

```
CONFIG: <capture>:40: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
MISSING: <capture>: aaa authorization commands 7 default group port49 local: the configuration does not carry this line, and the cisco_iosxe adapter's renderings depend on it: without it a level is not what the adapter says it is (spec §6; the platform set's line: port49 platform show --set 1.0.0 cisco_iosxe)
2 local accounts, 1 usernames served on xe1 (cisco_iosxe), 2 findings
```

`show running-config | section aaa` (no-commands-7), 17 lines, redacted copy `tests/lab/evidence/L22-config-cisco_iosxe-no-commands-7-2.txt`:

check-config on the raw capture, exit 1:

```
CONFIG: <capture>:8: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
MISSING: <capture>: aaa authorization commands 7 default group port49 local: the configuration does not carry this line, and the cisco_iosxe adapter's renderings depend on it: without it a level is not what the adapter says it is (spec §6; the platform set's line: port49 platform show --set 1.0.0 cisco_iosxe)
MISSING: <capture>: privilege exec level 7 clear counters: the configuration does not carry this line, and the cisco_iosxe adapter's renderings depend on it: without it a level is not what the adapter says it is (spec §6; the platform set's line: port49 platform show --set 1.0.0 cisco_iosxe)
note: the configuration has no hostname line, so it may be a partial capture (| section ...): a MISSING line may be in the part left out; check-config reads the whole show running-config
0 local accounts, 1 usernames served on xe1 (cisco_iosxe), 3 findings
```

check-config on the redacted copy, exit 1:

```
CONFIG: <capture>:8: aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted»: enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)
MISSING: <capture>: aaa authorization commands 7 default group port49 local: the configuration does not carry this line, and the cisco_iosxe adapter's renderings depend on it: without it a level is not what the adapter says it is (spec §6; the platform set's line: port49 platform show --set 1.0.0 cisco_iosxe)
MISSING: <capture>: privilege exec level 7 clear counters: the configuration does not carry this line, and the cisco_iosxe adapter's renderings depend on it: without it a level is not what the adapter says it is (spec §6; the platform set's line: port49 platform show --set 1.0.0 cisco_iosxe)
note: the configuration has no hostname line, so it may be a partial capture (| section ...): a MISSING line may be in the part left out; check-config reads the whole show running-config
0 local accounts, 1 usernames served on xe1 (cisco_iosxe), 3 findings
```

Operator's reply `priv-lvl=7`, session `alice03`, the commands typed in one pty session (IOS-XE runs one exec channel per connection):

`show privilege`:

```
Current privilege level is 7
```

`clear counters`:

```
Clear "show interface" counters on all interfaces [confirm]n
```

`show version`:

```
Cisco IOS XE Software, Version 17.13.01a …
```

Every `authorize_command` record port49 wrote for the session:

| vector | verdict | reason |
|---|---|---|
| `terminal length 0` | permit | permit_dominates |
| `show privilege` | permit | permit_dominates |
| `show version` | permit | permit_dominates |

