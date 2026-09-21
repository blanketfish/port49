# L8 — juniper_vjunos-router

- **Date measured:** 2026-09-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L8-juniper_vjunos-router.pcap` — 176 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L8-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
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
