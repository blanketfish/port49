# L5 — juniper_vsrx

- **Date measured:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/captures/L5-juniper_vsrx.pcap` — 104 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L5-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH
- **Caveat:** could not confirm the startup config was applied: breakglass never logged in within 8m54.675033002s (last error: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain)

## Claim

Which platforms send accounting WATCHDOG, how often, and with or without arguments.

## Observation

**0 WATCHDOG records** over a 2m30s idle interactive session (login at 2026-09-20T07:51:33Z UTC).

This platform sent no WATCHDOG at all in that window. It did send accounting: start=1, stop=2
