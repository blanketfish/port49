# L23 — cisco_nxos

- **Date measured:** 2026-11-06
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L23-cisco_nxos.pcap` — 1879 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L23-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,nxos`, `-run ^TestL23InertBesideReadonly$`

## Claim

Whether home-directory, idletime and timeout, each beside readonly's reply, leave the session readonly's: the same identity, the same reach for `clear counters` and `configure terminal`, and a permitted `show version` (spec §6, §15 L23; 5a final review M3).

## Observation

Control, readonly's reply `shell:roles*network-operator`: identity `roles:network-operator`, `clear counters` sent to port49, `configure terminal` sent to port49, `show version` permitted by port49.

On cisco_nxos both ceiling commands reach port49 at readonly and at admin alike, so the `clear counters` and `configure terminal` columns cannot show a raise here: the verdict rests on the identity the device reports. That column moves on this image: admin's reply reports `roles:network-admin` (`tests/lab/results/L22-cisco_nxos.md`, the admin row).

| attribute | session | identity | `clear counters` | `configure terminal` | `show version` | inert |
|---|---|---|---|---|---|---|
| `home-directory*/home/port49` | opened | roles:network-operator | sent to port49 | sent to port49 | permitted by port49 | yes |
| `idletime*30` | opened | roles:network-operator | sent to port49 | sent to port49 | permitted by port49 | yes |
| `timeout*480` | opened | roles:network-operator | sent to port49 | sent to port49 | permitted by port49 | yes |

