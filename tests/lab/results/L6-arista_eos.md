# L6 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L6-arista_eos.pcap` — 124 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L6-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next.

## Observation

One SSH login that ran `show version` and disconnected. Login began 2026-09-20T16:40:31.250285076Z UTC; the connection closed 2026-09-20T16:40:31.542578245Z UTC.

- Exec **START**: arrived 194ms after the login began.
- Exec **STOP**: arrived 2ms after the session closed.

Accounting records in the window: start=1, stop=2 (an exec record is one that carries no command at all, as on EOS, or carries only `login` or `logout`, as on Junos; anything else is a per-command record).

All accounting AV pairs, in arrival order:

```
2026-09-20T16:40:31.444Z flags=start attribution=resolved raw=[task_id=26 service=shell start_time=1789922430 timezone=UTC]
2026-09-20T16:40:31.525Z flags=stop attribution=resolved raw=[task_id=27 service=shell priv-lvl=15 start_time=1789922430 timezone=UTC cmd=show version <cr>]
2026-09-20T16:40:31.545Z flags=stop attribution=resolved raw=[task_id=26 service=shell start_time=1789922430 timezone=UTC elapsed_time=1]
```

Retry-to-the-next-server behavior is not measured here: this lab has a single TACACS+ server, so nothing in this run shows what the device does when one is unreachable.
