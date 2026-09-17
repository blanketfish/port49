# L8 — arista_eos

- **Date measured:** 2026-09-17
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L8-arista_eos.pcap` — 496 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L8-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

The maximum password length each platform accepts at an interactive prompt and via PAP.

## Observation

A seeded token of each length, each under its own username, presented at the SSH password prompt:

| length | reached port49 | verdict | reason | SSH result |
|---|---|---|---|---|
| 30 | yes | permit | `token_redeemed` | logged in |
| 64 | yes | permit | `token_redeemed` | logged in |
| 128 | yes | permit | `token_redeemed` | logged in |
| 138 | yes | permit | `token_redeemed` | logged in |

**Longest password that arrived intact: 138 characters.**

How to read this: `token_redeemed` means the full password reached port49 byte for byte. `credential_mismatch` means the username arrived but the password did not match what was seeded, so the device altered or truncated it. `token_not_found` or no record at all means the device refused the password before sending anything.

The 30-character handle the design document depends on: **accepted**.

PAP is not measured here; this is the interactive SSH prompt only.
