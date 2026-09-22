# L5 — juniper_vjunos-router

- **Date measured:** 2026-09-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L5-juniper_vjunos-router.pcap` — 104 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L5-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Which platforms send accounting WATCHDOG, how often, and with or without arguments.

## Observation

**0 WATCHDOG records** over a 2m30s idle interactive session (login at 2026-09-20T07:37:25Z UTC).

This platform sent no WATCHDOG at all in that window. It did send accounting: start=1, stop=2
