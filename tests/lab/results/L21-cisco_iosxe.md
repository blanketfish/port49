# L21 — cisco_iosxe

- **Date measured:** 2026-09-24
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L21-cisco_iosxe.pcap` — 550 packets, all to or from the lab subnet; taken by hand, no loopback probes
- **Transport:** SSH, interactive session, seeded token `u041`, session reply `priv-lvl=15`
- **Method:** by hand; `tests/lab/configs/iosxe-startup.cfg` (`aaa authorization commands 1|15 default group port49 local`, `aaa authorization config-commands`, `aaa accounting commands 1|15 default start-stop group port49`)

## Claim

Whether each platform sends the command words the operator typed (`sh run`) or the resolved ones
(`show running-config`) on a per-command authorization request, and on the accounting record for
it (spec §15, L21).

## Answer

**Resolved, on both.** IOS-XE expands every abbreviation to the parser's full keywords before it
asks port49, and writes the same full keywords in the accounting record. It goes further than
expansion: an interface name typed as `Gi1` arrives as two arguments, `GigabitEthernet` and `1`.
An abbreviation of a word a port49 deny names is caught by that deny: `sh clock` was denied as
`show clock`.

## Observation

Typed, in one session (the device's echo, `terminal length 0` first):

```
xe1#sh ver
Cisco IOS XE Software, Version 17.13.01a
...
xe1#sh ip int br
...
xe1#sho run
...
xe1#sh clock
port49: denied by lab_deny (show clock); see 'port49 explain'
xe1#show clock
port49: denied by lab_deny (show clock); see 'port49 explain'
xe1#sh privilege
Current privilege level is 15
xe1#conf t
Enter configuration commands, one per line.  End with CNTL/Z.
xe1(config)#hostn xe1
xe1(config)#int Gi1
xe1(config-if)#desc p49-l21
xe1(config-if)#no desc
xe1(config-if)#exit
xe1(config)#end
```

What reached port49, per typed line — the authorization request's AV pairs, then the accounting
STOP record's `cmd`:

| typed | authorization request | accounting `cmd` |
|---|---|---|
| `sh ver` | `cmd=show cmd-arg=version cmd-arg=<cr>` | `show version <cr>` |
| `sh ip int br` | `cmd=show cmd-arg=ip cmd-arg=interface cmd-arg=brief cmd-arg=<cr>` | `show ip interface brief <cr>` |
| `sho run` | `cmd=show cmd-arg=running-config cmd-arg=<cr>` | `show running-config <cr>` |
| `sh clock` | `cmd=show cmd-arg=clock cmd-arg=<cr>` — **denied** `no_permit_dominates_deny` by `lab_deny (show clock)` | none (the command did not run) |
| `show clock` | `cmd=show cmd-arg=clock cmd-arg=<cr>` — denied, same record | none |
| `sh privilege` | `cmd=show cmd-arg=privilege cmd-arg=<cr>` | `show privilege <cr>` |
| `conf t` | `cmd=configure cmd-arg=terminal cmd-arg=<cr>` | `configure terminal <cr>` |
| `hostn xe1` | `cmd=hostname cmd-arg=xe1 cmd-arg=<cr>` | `hostname xe1 <cr>` |
| `int Gi1` | `cmd=interface cmd-arg=GigabitEthernet cmd-arg=1 cmd-arg=<cr>` | `interface GigabitEthernet 1 <cr>` |
| `desc p49-l21` | `cmd=description cmd-arg=p49-l21 cmd-arg=<cr>` | `description p49-l21 <cr>` |
| `no desc` | `cmd=no cmd-arg=description cmd-arg=<cr>` | `no description <cr>` |
| `exit`, `end` | no request | no record |

Every request carried `service=shell`; the accounting records carried `task_id`, `timezone=UTC`,
`service=shell`, `priv-lvl` (1 for the level-1 `show` commands, 15 for the rest) and `cmd`. The
`sh clock` denial is the only line whose words the device might have sent unexpanded; it sent
`show clock`, byte for byte what the full spelling produced.

## Reading

- `expands_abbreviations` for `cisco_iosxe` can be `true` for SSH command authorization and
  accounting, on this image.
- The interface-name split (`GigabitEthernet`, `1`) is a normalization fact spec §3 does not yet
  mention: a rule written `interface GigabitEthernet1` does not match what this device sends.

*Unmeasured:* abbreviations over any transport but interactive SSH; abbreviations inside a pipe
(IOS-XE drops the pipe from the request entirely, `tests/lab/results/L2-cisco_iosxe.md`); other
interface types and subinterfaces; IOS-XE releases other than 17.13.01a.
