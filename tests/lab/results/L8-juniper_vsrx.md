# L8 — juniper_vsrx

- **Date measured:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/captures/L8-juniper_vsrx.pcap` — 176 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L8-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH
- **Caveat:** could not confirm the startup config was applied: breakglass never logged in within 8m54.675033002s (last error: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain)

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
