# L5 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/captures/L5-cisco_nxos.pcap` — 80 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L5-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Which platforms send accounting WATCHDOG, how often, and with or without arguments.

## Observation

**0 WATCHDOG records** over a 2m30s idle interactive session (login at 2026-09-20T17:18:22Z UTC).

This platform sent no WATCHDOG at all in that window. It did send accounting: start=1, stop=1
