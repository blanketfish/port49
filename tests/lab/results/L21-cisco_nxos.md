# L21 — cisco_nxos

- **Date measured:** 2026-09-24
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`; `show version`: `NXOS: version 10.4(2) [Feature Release]`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L21-cisco_nxos.pcap` — 500 packets, all to or from the lab subnet; taken by hand, no loopback probes
- **Transport:** SSH, interactive session, seeded token `u001`, session reply `shell:roles*network-admin`
- **Method:** by hand; `tests/lab/configs/nxos-startup.cfg` (`aaa authorization commands default group port49 local`, `aaa authorization config-commands default group port49 local`, `aaa accounting default group port49`)

## Claim

Whether each platform sends the command words the operator typed (`sh run`) or the resolved ones
(`show running-config`) on a per-command authorization request, and on the accounting record for
it (spec §15, L21).

## Answer

**Resolved, on both.** The N9Kv expands every abbreviation before it asks port49; `int e1/1`
arrives as the single argument `Ethernet1/1`; `sh clock` was denied by the `show clock` deny. Its
accounting records only configuration commands, and records each one resolved, as the whole
configuration path: `configure terminal ; interface Ethernet1/1 ; description p49-l21 (SUCCESS)`.

## Observation

Typed, in one session (the device's echo):

```
nx1# sh clock
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# show clock
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1# sh user-account
user:admin
        this user account has no expiry date
...
nx1# conf t
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# hostn nx1
nx1(config)# int e1/1
nx1(config-if)# desc p49-l21
nx1(config-if)# no desc
nx1(config-if)# exit
nx1(config)# end
```

(`sh ver`, `sh ip int br` and `sho run` printed their full output before these.)

| typed | authorization request | accounting `cmd` |
|---|---|---|
| `terminal length 0` | `cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>` | `terminal length 0 (SUCCESS)` |
| `sh ver` | `cmd=show cmd-arg=version cmd-arg=<cr>` | none |
| `sh ip int br` | `cmd=show cmd-arg=ip cmd-arg=interface cmd-arg=brief cmd-arg=<cr>` | none |
| `sho run` | `cmd=show cmd-arg=running-config cmd-arg=<cr>` | none |
| `sh clock` | `cmd=show cmd-arg=clock cmd-arg=<cr>` — **denied** `no_permit_dominates_deny` | none |
| `show clock` | `cmd=show cmd-arg=clock cmd-arg=<cr>` — denied, same record | none |
| `sh user-account` | `cmd=show cmd-arg=user-account cmd-arg=<cr>` | none |
| `conf t` | `cmd=configure cmd-arg=terminal cmd-arg=<cr>` | (folded into the next line's record) |
| `hostn nx1` | `cmd=hostname cmd-arg=nx1 cmd-arg=<cr>` | `configure terminal ; hostname nx1 (SUCCESS)` |
| `int e1/1` | `cmd=interface cmd-arg=Ethernet1/1 cmd-arg=<cr>` | `configure terminal ; interface Ethernet1/1 (REDIRECT)` and `... (SUCCESS)` |
| `desc p49-l21` | `cmd=description cmd-arg=p49-l21 cmd-arg=<cr>` | `configure terminal ; interface Ethernet1/1 ; description p49-l21 (REDIRECT)` and `... (SUCCESS)` |
| `no desc` | `cmd=no cmd-arg=description cmd-arg=<cr>` | `configure terminal ; interface Ethernet1/1 ; no description (REDIRECT)` and `... (SUCCESS)` |
| `exit` | no request | none |
| `end` | `cmd=end cmd-arg=<cr>` | none |

Every request carried `service=shell`; every accounting record carried
`task_id=172.100.100.1@pts/3`, `start_time`, `timezone=UTC`, `service=none` and `cmd`. None of
the `show` commands produced an accounting record; `terminal length 0` did.

## Reading

- `expands_abbreviations` for `cisco_nxos` can be `true` for SSH command authorization and
  accounting, on this image.
- The accounting `cmd` is not the authorized command: it is the configuration path joined with
  ` ; ` plus a `(SUCCESS)` or `(REDIRECT)` suffix, and it is written twice for a command that
  enters or stays in a submode. A reconciliation that joins accounting to authorization by command
  text has to strip both on this platform (spec §5.8, §9).
- NX-OS authorizes `end` and not `exit`; IOS-XE authorizes neither and vEOS accounts both
  without authorizing them (`L21-cisco_iosxe.md`, `L21-arista_eos.md`).

*Unmeasured:* NX-API and NETCONF; abbreviations inside a pipe; NX-OS releases other than 10.4(2)F.
