# L6 — juniper_vjunos-router

- **Date measured:** 2026-09-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L6-juniper_vjunos-router.pcap` — 104 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L6-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next.

## Observation

One SSH login that ran `show version` and disconnected. Login began 2026-09-20T07:40:27.455968351Z UTC; the connection closed 2026-09-20T07:40:27.63086073Z UTC.

- Exec **START**: arrived 4.403s after the login began.
- Exec **STOP**: arrived 4.231s after the session closed.

Accounting records in the window: start=1, stop=2 (an exec record is one that carries no command at all, as on EOS, or carries only `login` or `logout`, as on Junos; anything else is a per-command record).

All accounting AV pairs, in arrival order:

```
2026-09-20T07:40:31.859Z flags=start attribution=unattributed raw=[task_id=1 service=shell session_pid = 14717 cmd=login]
2026-09-20T07:40:31.861Z flags=stop attribution=unattributed raw=[task_id=2 service=shell session_pid = 14717 cmd=show version <cr>]
2026-09-20T07:40:31.862Z flags=stop attribution=unattributed raw=[task_id=1 service=shell session_pid = 14717 elapsed_time=0 cmd=logout]
```

Retry-to-the-next-server behavior is not measured here: this lab has a single TACACS+ server, so nothing in this run shows what the device does when one is unreachable.
