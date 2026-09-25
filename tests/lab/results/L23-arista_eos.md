# L23 — arista_eos

- **Date measured:** 2026-09-25
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L23-arista_eos.pcap` — 936 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L23-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether home-directory, idletime and timeout, each beside readonly's reply, leave the session readonly's: the same identity, the same reach for `clear counters` and `configure terminal`, and a permitted `show version` (spec §6, §15 L23; 5a final review M3).

## Observation

Control, readonly's reply `priv-lvl=1`, `roles=network-operator`: identity `Current privilege level is 1`, `clear counters` refused by the device, `configure terminal` refused by the device, `show version` permitted by port49.

| attribute | session | identity | `clear counters` | `configure terminal` | `show version` | inert |
|---|---|---|---|---|---|---|
| `home-directory*/home/port49` | opened | Current privilege level is 1 | refused by the device | refused by the device | permitted by port49 | yes |
| `idletime*30` | opened | Current privilege level is 1 | refused by the device | refused by the device | permitted by port49 | yes |
| `timeout*480` | opened | Current privilege level is 1 | refused by the device | refused by the device | permitted by port49 | yes |

