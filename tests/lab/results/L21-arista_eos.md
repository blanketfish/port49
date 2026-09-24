# L21 — arista_eos

- **Date measured:** 2026-09-24
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F; `show version`: `Software image version: 4.31.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L21-arista_eos.pcap` — 586 packets, all to or from the lab subnet; taken by hand, no loopback probes
- **Transport:** SSH, interactive session, seeded token `u001`, session reply `priv-lvl=15`
- **Method:** by hand; `tests/lab/configs/eos-startup.cfg` (`aaa authorization commands all default group port49 local`, `aaa accounting commands all default start-stop group port49`)

## Claim

Whether each platform sends the command words the operator typed (`sh run`) or the resolved ones
(`show running-config`) on a per-command authorization request, and on the accounting record for
it (spec §15, L21).

## Answer

**Resolved, on both.** vEOS expands every abbreviation before it asks port49 and writes the full
keywords in the accounting record; an interface typed `Et1` arrives as the single argument
`Ethernet1`. `sh clock` was denied by the `show clock` deny, and the device's own refusal line
quotes the resolved command: `% Authorization denied for command 'show clock'`.

## Observation

Typed, in one session (the device's echo):

```
leaf1#sh ver
Arista vEOS-lab
...
leaf1#sh ip int br
...
leaf1#sho run
...
leaf1#sh clock
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#show clock
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
leaf1#sh privilege
Current privilege level is 15
leaf1#conf t
leaf1(config)#hostn leaf1
leaf1(config)#int Et1
! Interface does not exist. The configuration will not take effect until the module is inserted.
leaf1(config-if-Et1)#desc p49-l21
leaf1(config-if-Et1)#no desc
leaf1(config-if-Et1)#exit
leaf1(config)#end
```

(This vEOS has no data interfaces; `Ethernet1` is accepted as configuration for an absent module.)

| typed | authorization request | accounting `cmd` |
|---|---|---|
| `sh ver` | `cmd=show cmd-arg=version cmd-arg=<cr>` | `show version <cr>` |
| `sh ip int br` | `cmd=show cmd-arg=ip cmd-arg=interface cmd-arg=brief cmd-arg=<cr>` | `show ip interface brief <cr>` |
| `sho run` | `cmd=show cmd-arg=running-config cmd-arg=<cr>` | `show running-config <cr>` |
| `sh clock` | `cmd=show cmd-arg=clock cmd-arg=<cr>` — **denied** `no_permit_dominates_deny` | none |
| `show clock` | `cmd=show cmd-arg=clock cmd-arg=<cr>` — denied, same record | none |
| `sh privilege` | `cmd=show cmd-arg=privilege cmd-arg=<cr>` | `show privilege <cr>` |
| `conf t` | `cmd=configure cmd-arg=terminal cmd-arg=<cr>` | `configure terminal <cr>` |
| `hostn leaf1` | `cmd=hostname cmd-arg=leaf1 cmd-arg=<cr>` | `hostname leaf1 <cr>` |
| `int Et1` | `cmd=interface cmd-arg=Ethernet1 cmd-arg=<cr>` | `interface Ethernet1 <cr>` |
| `desc p49-l21` | `cmd=description cmd-arg=p49-l21 cmd-arg=<cr>` | `description p49-l21 <cr>` |
| `no desc` | `cmd=no cmd-arg=description cmd-arg=<cr>` | `no description <cr>` |
| `exit`, `end`, `exit` | no request | `exit <cr>`, `end <cr>`, `exit <cr>` |

Every request carried `service=shell`; the accounting STOP records carried `task_id`,
`service=shell`, `priv-lvl=15`, `start_time`, `timezone=UTC` and `cmd`. vEOS accounts `exit` and
`end` without authorizing them, which IOS-XE does not do (`L21-cisco_iosxe.md`).

## Reading

- `expands_abbreviations` for `arista_eos` can be `true` for SSH command authorization and
  accounting, on this image.
- Interface names arrive joined (`Ethernet1`), unlike IOS-XE's split (`GigabitEthernet`, `1`), so
  a normalization rule for interface arguments is per platform.

*Unmeasured:* abbreviations sent over eAPI and NETCONF;
abbreviations inside a pipe; EOS releases other than 4.31.2F.
