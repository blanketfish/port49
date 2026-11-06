# L22 — cisco_nxos

- **Date measured:** 2026-11-06
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L22-cisco_nxos.pcap` — 3472 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L22-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,nxos,iosxe`, `-run ^(TestAdapterReplies|TestAdapterCarried)$`

## Claim

Each built-in adapter's reply at readonly, operator and admin is applied by the device as the adapter says — the privilege or role the device reports, and which of `clear counters` and `configure terminal` it sends port49 at all; which candidate inert attributes leave admin's session unchanged; and, with port49d stopped under an open session, that operator's reply cannot change the configuration where admin's can (plan 5a, Task 17; spec §6, §8, §15 L22; decision 25).

## Observation

| level | reply | session | identity | `clear counters` | `configure terminal` | bare `show interface` |
|---|---|---|---|---|---|---|
| readonly | `shell:roles*network-operator` | opened | roles:network-operator | sent to port49 | sent to port49 | `mgmt0 is up` |
| operator | `shell:roles*network-operator` | opened | roles:network-operator | sent to port49 | sent to port49 | `mgmt0 is up` |
| admin | `shell:roles*network-admin` | opened | roles:network-admin | sent to port49 | sent to port49 | `mgmt0 is up` |

### Inert candidates, each beside admin's reply

| attribute | session | identity | `clear counters` | `configure terminal` | `show version` | inert |
|---|---|---|---|---|---|---|
| `home-directory*/home/port49` | not observed (show interface: deadline) | roles:network-admin | sent to port49 | sent to port49 | permitted by port49 | not observed |
| `idletime*30` | opened | roles:network-admin | sent to port49 | sent to port49 | permitted by port49 | yes |
| `timeout*480` | opened | roles:network-admin | sent to port49 | sent to port49 | permitted by port49 | yes |

### Fallback: port49d stopped under an open session

| level | reply | `configure terminal`, then `hostname nx1` | transcript after port49d stopped |
|---|---|---|---|
| operator | `shell:roles*network-operator` | refused | `configure terminal ⏎ Enter configuration commands, one per line. End with CNTL/Z. ⏎ nx1(config)# hostname nx1 ⏎ % Permission denied for the role ⏎ nx1(config)# end ⏎ nx1# exit` |
| admin | `shell:roles*network-admin` | **accepted** | `configure terminal ⏎ Enter configuration commands, one per line. End with CNTL/Z. ⏎ nx1(config)# hostname nx1 ⏎ nx1(config)# end ⏎ nx1# exit` |

