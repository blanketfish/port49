# L6 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/captures/L6-cisco_nxos.pcap` — 118 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L6-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next.

## Observation

One SSH login that ran `show version` and disconnected. Login began 2026-09-20T17:21:24.020298353Z UTC; the connection closed 2026-09-20T17:21:24.385382601Z UTC.

- Exec **START**: arrived 332ms after the login began.
- Exec **STOP**: arrived -7ms after the session closed.

Accounting records in the window: start=1, stop=1 (an exec record is one that carries no command at all, as on EOS, or carries only `login` or `logout`, as on Junos; anything else is a per-command record).

All accounting AV pairs, in arrival order:

```
2026-09-20T17:21:24.352Z flags=start attribution=resolved raw=[task_id=172.100.100.1@ssh.19081 start_time=1789924880 timezone=UTC service=none]
2026-09-20T17:21:24.378Z flags=stop attribution=resolved raw=[task_id=172.100.100.1@ssh.19081 start_time=1789924880 timezone=UTC stop_time=1789924880 service=none]
```

Retry-to-the-next-server behavior is not measured here: this lab has a single TACACS+ server, so nothing in this run shows what the device does when one is unreachable.
