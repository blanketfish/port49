# L6 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L6-arista_eos.pcap` — 124 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L6-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next.

## Observation

One SSH login that ran `show version` and disconnected. Login began 2026-09-20T18:12:59.512653486Z UTC; the connection closed 2026-09-20T18:12:59.801301795Z UTC.

- Exec **START**: arrived 191ms after the login began.
- Exec **STOP**: arrived 3ms after the session closed.

Accounting records in the window: start=1, stop=2 (an exec record is one that carries no command at all, as on EOS, or carries only `login` or `logout`, as on Junos; anything else is a per-command record).

All accounting AV pairs, in arrival order:

```
2026-09-20T18:12:59.704Z flags=start attribution=resolved raw=[task_id=32 service=shell start_time=1789927979 timezone=UTC]
2026-09-20T18:12:59.785Z flags=stop attribution=resolved raw=[task_id=33 service=shell priv-lvl=15 start_time=1789927979 timezone=UTC cmd=show version <cr>]
2026-09-20T18:12:59.804Z flags=stop attribution=resolved raw=[task_id=32 service=shell start_time=1789927979 timezone=UTC elapsed_time=1]
```

Retry-to-the-next-server behavior is not measured here: this lab has a single TACACS+ server, so nothing in this run shows what the device does when one is unreachable.
