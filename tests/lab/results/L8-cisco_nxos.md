# L8 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L8-cisco_nxos.pcap` — 240 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L8-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

The maximum password length each platform accepts at an interactive prompt and via PAP.

## Observation

A seeded token of each length, each under its own username, presented at the SSH password prompt:

| length | reached port49 | verdict | reason | SSH result |
|---|---|---|---|---|
| 30 | yes | permit | `token_redeemed` | logged in |
| 64 | yes | permit | `token_redeemed` | logged in |
| 128 | no | — | `—` | rejected |
| 138 | no | — | `—` | rejected |

**Longest password that arrived intact: 64 characters.**

How to read this: `token_redeemed` means the full password reached port49 byte for byte. `token_not_found` means the device did send a password under this username and no seeded token matched it, so the device altered or truncated what was typed. Truncation cannot land anywhere else: the receipt key carries the credential hash (spec §13, decision 15), so a truncated password finds no receipt at all rather than colliding with one. No record at all means the device refused the password locally and sent nothing.

The 30-character handle the design document depends on: **accepted**.

PAP is not measured here; this is the interactive SSH prompt only.
