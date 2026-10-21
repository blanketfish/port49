# L78-vJunos-router-26.2R1.7 — juniper_vjunos-router

- **Date measured:** 2026-10-21
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 26.2R1.7 (`vrnetlab/juniper_vjunos-router:26.2R1.7`)
- **Topology:** `tests/lab/topologies/vjunos26.clab.yml`
- **Capture:** `tests/lab/evidence/L78-vJunos-router-26.2R1.7-juniper_vjunos-router.pcap` — 1838 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L78-vJunos-router-26.2R1.7-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `3ecac848e2e07f8e820f18c557976bdda0c42745`, `PORT49_LAB_PLATFORMS=vjunos26`, `-run ^TestL78$`

## Claim

Whether Junos locks a user out when a permit session reply totals more than 255 bytes with every attribute at most 255 (spec §15 L78), on vJunos-router 26.2R1.7. This measures a VM and closes nothing.

## Observation

Steps, each a role the projection renders to about the target size, run through a broker-minted token login (`qual01`, `show version`) with break-glass proved before it and after it. "Reply bytes" is the sum of the attribute lengths in the `authorize_session` record's `reply.attributes` (user-permissions, deny-commands, allow-commands, each at most 255). "Target" is the brief's total; where the projection cannot carry it the deny-commands value would pass 255 and the reply falls back to the narrow shape, so the reply is smaller than the target.

| target | reply bytes (attributes) | login | break-glass after |
|---|---|---|---|
| 200 | 208 (40 + 141 + 27) | logged in and ran `show version` after a 208-byte reply | logged in |
| 240 | 240 (40 + 141 + 59) | logged in and ran `show version` after a 240-byte reply | logged in |
| 256 | 258 (40 + 172 + 46) | logged in and ran `show version` after a 258-byte reply | logged in |
| 300 | 299 (40 + 213 + 46) | logged in and ran `show version` after a 299-byte reply | logged in |
| 375 | 375 (40 + 253 + 82) | logged in and ran `show version` after a 375-byte reply | logged in |
| 400 | 124 (24 + 18 + 82) | logged in and ran `show version` after a 124-byte reply | logged in |
| 600 | 124 (24 + 18 + 82) | logged in and ran `show version` after a 124-byte reply | logged in |

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

**Result: no lockout up to 375 bytes on vJunos-router 26.2R1.7; open for hardware Junos.** L78 stays open: hardware Junos is unmeasured, and decision 48's 255-byte budget stays.

Evidence: `tests/lab/evidence/L78-vJunos-router-26.2R1.7-juniper_vjunos-router/decisions.jsonl` (whitelisted decision records).

