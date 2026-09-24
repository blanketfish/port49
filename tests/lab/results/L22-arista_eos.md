# L22 — arista_eos

- **Date measured:** 2026-09-24
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L22-arista_eos.pcap` — 2344 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L22-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Each built-in adapter's reply at readonly, operator and admin is applied by the device as the adapter says — the privilege or role the device reports, and which of `clear counters` and `configure terminal` it sends port49 at all; which candidate inert attributes leave admin's session unchanged; and, with port49d stopped under an open session, that operator's reply cannot change the configuration where admin's can (plan 5a, Task 17; spec §6, §8, §15 L22; decision 25).

## Observation

| level | reply | session | identity | `clear counters` | `configure terminal` | bare `show interface` |
|---|---|---|---|---|---|---|
| readonly | `priv-lvl=1`, `roles=network-operator` | opened | Current privilege level is 1 | refused by the device | refused by the device | — |
| operator | `priv-lvl=15`, `roles=network-operator` | opened | Current privilege level is 15 | sent to port49 | sent to port49 | — |
| admin | `priv-lvl=15`, `roles=network-admin` | opened | Current privilege level is 15 | sent to port49 | sent to port49 | — |

### Inert candidates, each beside admin's reply

| attribute | session | identity | `clear counters` | `configure terminal` | `show version` | inert |
|---|---|---|---|---|---|---|
| `home-directory*/home/port49` | opened | Current privilege level is 15 | sent to port49 | sent to port49 | permitted by port49 | yes |
| `idletime*30` | opened | Current privilege level is 15 | sent to port49 | sent to port49 | permitted by port49 | yes |
| `timeout*480` | opened | Current privilege level is 15 | sent to port49 | sent to port49 | permitted by port49 | yes |

### Fallback: port49d stopped under an open session

| level | reply | `configure terminal`, then `hostname leaf1` | transcript after port49d stopped |
|---|---|---|---|
| operator | `priv-lvl=15`, `roles=network-operator` | refused | `configure terminal ⏎ % Authorization denied for command 'configure terminal' ⏎ leaf1#hostname leaf1 ⏎ % Invalid input ⏎ leaf1#end ⏎ % Invalid input ⏎ leaf1#exit` |
| admin | `priv-lvl=15`, `roles=network-admin` | **accepted** | `configure terminal ⏎ leaf1(config)#hostname leaf1 ⏎ leaf1(config)#end ⏎ leaf1#exit` |

