# L2 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L2-arista_eos.pcap` — 208 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L2-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates.

## Observation

Command `show clock` was denied by the lab authorizer with a 61-character `server_msg`:

```
port49: denied by lab_deny (show clock); see 'port49 explain'
```

**The operator saw it: displayed.**

What the device printed for the denied command (login as `alice05`):

```

> show clock
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' at line 1
```

### Truncation length

Not measured, and the reason is itself an observation. The operator typed a 171-character line, but the device did not send that line for authorization, so port49 never built a long `server_msg` to truncate. What the device actually asked port49 to authorize:

```
"show clock"
```

The device printed:

```

> show clock | include AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' at line 1
```

