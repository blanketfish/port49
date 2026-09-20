# L2 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/captures/L2-cisco_nxos.pcap` — 240 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L2-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates.

## Observation

Command `show clock` was denied by the lab authorizer with a 61-character `server_msg`:

```
port49: denied by lab_deny (show clock); see 'port49 explain'
```

**The operator saw it: NOT displayed.**

What the device printed for the denied command (login as `alice06`):

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)

Cmd exec error.
```

### Truncation length

Not measured, and the reason is itself an observation. The operator typed a 171-character line, but the device did not send that line for authorization, so port49 never built a long `server_msg` to truncate. What the device actually asked port49 to authorize:

```
"show clock"
"end"
```

The device printed:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)

Cmd exec error.
```

