# L22 — cisco_iosxe

- **Date measured:** 2026-11-06
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L22-cisco_iosxe.pcap` — 2477 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L22-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,nxos,iosxe`, `-run ^(TestAdapterReplies|TestAdapterCarried)$`

## Claim

Each built-in adapter's reply at readonly, operator and admin is applied by the device as the adapter says — the privilege or role the device reports, and which of `clear counters` and `configure terminal` it sends port49 at all; which candidate inert attributes leave admin's session unchanged; and, with port49d stopped under an open session, that operator's reply cannot change the configuration where admin's can (plan 5a, Task 17; spec §6, §8, §15 L22; decision 25).

## Observation

| level | reply | session | identity | `clear counters` | `configure terminal` | bare `show interface` |
|---|---|---|---|---|---|---|
| readonly | `priv-lvl=1` | opened | Current privilege level is 1 | refused by the device | refused by the device | — |
| operator | `priv-lvl=7` | opened | Current privilege level is 7 | sent to port49 | refused by the device | — |
| admin | `priv-lvl=15` | opened | Current privilege level is 15 | sent to port49 | sent to port49 | — |

### Inert candidates, each beside admin's reply

| attribute | session | identity | `clear counters` | `configure terminal` | `show version` | inert |
|---|---|---|---|---|---|---|
| `home-directory*/home/port49` | refused: none of ["xe1#" "xe1>"] appeared on the SSH CLI as alice05 within 1m0s; what it said was: % Authorization failed. |  | not observed | not observed | not observed | no |
| `idletime*30` | opened | Current privilege level is 15 | sent to port49 | sent to port49 | permitted by port49 | yes |
| `timeout*480` | opened | Current privilege level is 15 | sent to port49 | sent to port49 | permitted by port49 | yes |

### Fallback: port49d stopped under an open session

| level | reply | `configure terminal`, then `hostname xe1` | transcript after port49d stopped |
|---|---|---|---|
| operator | `priv-lvl=7` | refused | `configure terminal ⏎ ^ ⏎ % Invalid input detected at '^' marker. ⏎ ⏎ xe1#hostname xe1 ⏎ ^ ⏎ % Invalid input detected at '^' marker. ⏎ ⏎ xe1#end ⏎ % Authorization failed. ⏎ ^ ⏎ % Invalid input detected at '^' marker. ⏎ ⏎ xe1#exit` |
| admin | `priv-lvl=15` | refused | `configure terminal ⏎ % Authorization failed. ⏎ ⏎ xe1#hostname xe1 ⏎ ^ ⏎ % Invalid input detected at '^' marker. ⏎ ⏎ xe1#end ⏎ % Authorization failed. ⏎ ^ ⏎ % Invalid input detected at '^' marker. ⏎ ⏎ xe1#exit` |

