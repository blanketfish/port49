# L78-vJunos-router-23.4R2-S2.1 — juniper_vjunos-router

- **Date measured:** 2026-10-21
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L78-vJunos-router-23.4R2-S2.1-juniper_vjunos-router.pcap` — 1938 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L78-vJunos-router-23.4R2-S2.1-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `33bdc8dc5ea238f770d7ae9b3bb71a6383da25cd`, `PORT49_LAB_PLATFORMS=vjunos`, `-run ^TestL78$`

## Claim

Whether Junos locks a user out when a permit session reply totals more than 255 bytes with every attribute at most 255 (spec §15 L78), on vJunos-router 23.4R2-S2.1. This measures a VM and closes nothing.

## Observation

Steps, each a role the projection renders to about the target size, run through a broker-minted token login (`qual01`, `show version`) with break-glass proved before it and after it. "Reply bytes" is the sum of the attribute lengths in the `authorize_session` record's `reply.attributes` (user-permissions, deny-commands, allow-commands, each at most 255). "Target" is the brief's total. The 400 and 600 roles' deny-commands would pass 255, so the projection fails closed (decision 26) and `port49 policy test` refuses those policies with exit 1. Those two rows are therefore not a normal grant: the records carry reason `projection_fail_closed` and the reply `user-permissions=network`, `deny-commands=^.*$` and an allow of ping, traceroute, telnet, ssh and mtrace only. The login worked, and the device refused `show version` (its first line is in the login column): deny-all stopped the command.

| target | reply bytes (attributes) | login | break-glass after |
|---|---|---|---|
| 200 | 208 (40 + 141 + 27) | logged in and ran `show version` after a 208-byte reply; the device's first line: `Hostname: srx1` | logged in |
| 240 | 240 (40 + 141 + 59) | logged in and ran `show version` after a 240-byte reply; the device's first line: `Hostname: srx1` | logged in |
| 256 | 258 (40 + 172 + 46) | logged in and ran `show version` after a 258-byte reply; the device's first line: `Hostname: srx1` | logged in |
| 300 | 299 (40 + 213 + 46) | logged in and ran `show version` after a 299-byte reply; the device's first line: `Hostname: srx1` | logged in |
| 375 | 375 (40 + 253 + 82) | logged in and ran `show version` after a 375-byte reply; the device's first line: `Hostname: srx1` | logged in |
| 400 | 124 (24 + 18 + 82) | logged in; `show version` refused (deny-all) after a 124-byte reply; the device's first line: `error: unknown command: show` | logged in |
| 600 | 124 (24 + 18 + 82) | logged in; `show version` refused (deny-all) after a 124-byte reply; the device's first line: `error: unknown command: show` | logged in |

Break-glass (`breakglass`, local password) around the steps:

| when | result |
|---|---|
| before any step | logged in and ran them |
| before 200 | logged in and ran them |
| after 200 | logged in and ran them |
| before 240 | logged in and ran them |
| after 240 | logged in and ran them |
| before 256 | logged in and ran them |
| after 256 | logged in and ran them |
| before 300 | logged in and ran them |
| after 300 | logged in and ran them |
| before 375 | logged in and ran them |
| after 375 | logged in and ran them |
| before 400 | logged in and ran them |
| after 400 | logged in and ran them |
| before 600 | logged in and ran them |
| after 600 | logged in and ran them |

**Result: no lockout up to 375 bytes on vJunos-router 23.4R2-S2.1; open for hardware Junos.** L78 stays open: hardware Junos is unmeasured, and decision 48's 255-byte budget stays.

Evidence: `tests/lab/evidence/L78-vJunos-router-23.4R2-S2.1-juniper_vjunos-router/decisions.jsonl` (whitelisted decision records).

