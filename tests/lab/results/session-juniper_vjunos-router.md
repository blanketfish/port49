# session — juniper_vjunos-router

- **Date measured:** 2026-10-01
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Image ID:** `sha256:9e62ec961b57369bb35379a404503cf13baf788af70fdba9a6d49c3f4e7a203c`
- **Run:** at commit 6dece62, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run 'TestSessionLifetime|TestL2Truncation' -count=1 -timeout 90m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/session-juniper_vjunos-router.pcap` — 244 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/session-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Spec §13 decision 33, its session clauses. **The warning** rides on permits within `session.ceiling_warning` of the ceiling, to the platforms L34 finds show it and any an operator lists (`session.ceiling_warning_platforms`), and on `port49 token`'s stderr everywhere. **Past the ceiling** a context is kept through the grace window and deleted at its first authorization after it, and the store refuses to extend one past it. **The refresh** is a single-use 60s nonce signed over the connection's TLS exporter value; it extends only contexts the policy in force has just judged and kept, and only an operator's `port49 refresh` or `port49 login` triggers it.

## Observation

Run at a 6m `max_session_age` (`tests/lab/slice/session-policy.yaml`), `session.ceiling_warning: 2m`, `session.grace_window: 2m`. `port49 login` at 21:54:13.997Z; the token's ceiling ran from the held connection's handshake.

| Step | The device | The record |
|---|---|---|
| 3. login inside the warning | reached a prompt; **the warning was not observed** before it (the text before the prompt: `--- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil slice01@`) | permit context_matched, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| 4. `show version` inside the warning | its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 5. `port49 refresh`, then `show version` | refresh: `refreshed at 2026-10-01T21:58:24Z; this login lasts until 2026-10-02T09:58:24Z srx1 (slice01) extended to 2026-10-01T22:04:24Z, not reached: the device keeps it…`; `show version`: its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 6. `show version` at the ceiling + 10 s (22:04:34.000Z) | its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 7. `port49 refresh` inside the grace window, then `show version` | refresh: `refreshed at 2026-10-01T22:04:34Z; this login lasts until 2026-10-02T10:04:34Z srx1 (slice01) extended to 2026-10-01T22:10:34Z, not reached: the device keeps it…`; `show version`: its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 8. `show version` at the new ceiling + the grace window + 10 s (22:12:44.000Z) | its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 8. `port49 refresh` after it | `refreshed at 2026-10-01T22:12:44Z; this login lasts until 2026-10-02T10:12:44Z srx1 (slice01) past the grace window, not resumed: log in again there, not reache…`; 1 refresh record(s) |

Records from `port49 login` on: `event=account` ×6; `event=authorize_session reason=context_matched` ×1; `event=mint reason=grants_matched` ×1; `event=redeem reason=token_redeemed` ×1; `event=refresh reason=grants_matched` ×2; `event=refresh reason=session_expired` ×1.

On Junos the session reply at login is the one `server_msg` the device is ever sent (decision 21): Junos authorizes no command with port49, so the command rows say only whether `show version` ran, and the ceiling and the grace window are read off the refresh's answer and the records.

port49d, port49 and port49-inventory built from `6dece62` (`make build`).

