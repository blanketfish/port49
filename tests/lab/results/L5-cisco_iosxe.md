# L5 — cisco_iosxe

- **Date measured:** 2026-09-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/captures/L5-cisco_iosxe.pcap` — 84 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L5-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Which platforms send accounting WATCHDOG, how often, and with or without arguments.

## Observation

**0 WATCHDOG records** over a 2m30s idle interactive session (login at 2026-09-20T19:17:24Z UTC).

This platform sent no WATCHDOG at all in that window. It did send accounting: start=1, stop=1
