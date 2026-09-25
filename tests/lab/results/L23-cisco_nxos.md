# L23 — cisco_nxos

- **Date measured:** 2026-09-25
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L23-cisco_nxos.pcap` — 1879 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L23-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether home-directory, idletime and timeout, each beside readonly's reply, leave the session readonly's: the same identity, the same reach for `clear counters` and `configure terminal`, and a permitted `show version` (spec §6, §15 L23; 5a final review M3).

## Observation

Control, readonly's reply `shell:roles*network-operator`: identity `roles:network-operator`, `clear counters` sent to port49, `configure terminal` sent to port49, `show version` permitted by port49.

| attribute | session | identity | `clear counters` | `configure terminal` | `show version` | inert |
|---|---|---|---|---|---|---|
| `home-directory*/home/port49` | opened | roles:network-operator | sent to port49 | sent to port49 | permitted by port49 | yes |
| `idletime*30` | opened | roles:network-operator | sent to port49 | sent to port49 | permitted by port49 | yes |
| `timeout*480` | opened | roles:network-operator | sent to port49 | sent to port49 | permitted by port49 | yes |

