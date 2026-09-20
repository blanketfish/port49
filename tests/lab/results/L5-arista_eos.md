# L5 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L5-arista_eos.pcap` — 84 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L5-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Which platforms send accounting WATCHDOG, how often, and with or without arguments.

## Observation

**0 WATCHDOG records** over a 2m30s idle interactive session (login at 2026-09-20T16:37:29Z UTC).

This platform sent no WATCHDOG at all in that window. It did send accounting: start=1, stop=1
