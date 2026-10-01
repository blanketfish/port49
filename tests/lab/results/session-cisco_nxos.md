# session — cisco_nxos

- **Date measured:** 2026-10-01
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Image ID:** `sha256:d8297de1c034164cc3d9ceaee7b1352153302b0b60dbbeefdbdddc4fa62fb9cb`
- **Run:** at commit 4bd3100, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=nxos go test -tags lab ./tests/lab/ -run 'TestSessionLifetime|TestL2Truncation' -count=1 -timeout 90m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/session-cisco_nxos.pcap` — 240 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/session-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Spec §13 decision 33, its session clauses. **The warning** rides on permits within `session.ceiling_warning` of the ceiling, to the platforms L34 finds show it and any an operator lists (`session.ceiling_warning_platforms`), and on `port49 token`'s stderr everywhere. **Past the ceiling** a context is kept through the grace window and deleted at its first authorization after it, and the store refuses to extend one past it. **The refresh** is a single-use 60s nonce signed over the connection's TLS exporter value; it extends only contexts the policy in force has just judged and kept, and only an operator's `port49 refresh` or `port49 login` triggers it.

## Observation

Run at a 6m `max_session_age` (`tests/lab/slice/session-policy.yaml`), `session.ceiling_warning: 2m`, `session.grace_window: 2m`. `port49 login` at 21:08:26.194Z; the token's ceiling ran from the held connection's handshake.

| Step | The device | The record |
|---|---|---|
| 3. login inside the warning | reached a prompt; **the warning was not observed** before it (the text before the prompt: `Cisco NX-OS Software Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved. Nexus 9000v software ("Nexus 9000v Software") and related documentation, …`) | permit context_matched, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| 4. `show version` inside the warning | its output appeared in 700ms; port49's text: no port49 text and no refusal; the record: permit permit_dominates, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| 5. `port49 refresh`, then `show version` | refresh: `refreshed at 2026-10-01T21:12:37Z; this login lasts until 2026-10-02T09:12:37Z nx1 (slice01) extended to 2026-10-01T21:18:37Z`; `show version`: its output appeared in 700ms; port49's text: no port49 text and no refusal; the record: permit permit_dominates, server_msg `(none)` |
| 6. `show version` at the ceiling + 10 s (21:18:47.000Z) | refused in 100ms; the device printed `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)`; the record: deny session_expired, server_msg `port49: session expired - run 'port49 refresh' (or 'port49 login') within 2m to resume` |
| 7. `port49 refresh` inside the grace window, then `show version` | refresh: `refreshed at 2026-10-01T21:18:47Z; this login lasts until 2026-10-02T09:18:47Z nx1 (slice01) extended to 2026-10-01T21:24:47Z`; `show version`: its output appeared in 700ms; port49's text: no port49 text and no refusal; the record: permit permit_dominates, server_msg `(none)` |
| 8. `show version` at the new ceiling + the grace window + 10 s (21:26:57.000Z) | refused in 100ms; the device printed `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)`; the record: deny session_expired, server_msg `port49: session ended - get a new token ('port49 token') and log in again` |
| 8. `port49 refresh` after it | `refreshed at 2026-10-01T21:26:57Z; this login lasts until 2026-10-02T09:26:57Z no live device session to extend`; 0 refresh record(s) |
| 8. `show version` once more | refused in 100ms; the device printed `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)`; the record: deny context_missing, server_msg `port49: this session was not authenticated by port49` |

Records from `port49 login` on: `event=account` ×2; `event=authorize_command reason=context_missing` ×1; `event=authorize_command reason=permit_dominates` ×4; `event=authorize_command reason=session_expired` ×2; `event=authorize_session reason=context_matched` ×1; `event=mint reason=grants_matched` ×1; `event=redeem reason=token_redeemed` ×1; `event=refresh reason=grants_matched` ×2.
port49d, port49 and port49-inventory built from `4bd3100` (`make build`).

