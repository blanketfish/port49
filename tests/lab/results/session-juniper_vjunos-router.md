# session — juniper_vjunos-router

- **Date measured:** 2026-11-06
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/session-juniper_vjunos-router.pcap` — 864 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/session-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestSessionLifetime$`

## Claim

Spec §13 decision 33, its session clauses. **The warning** rides on permits within `session.ceiling_warning` of the ceiling, to the platforms L34 finds show it and any an operator lists (`session.ceiling_warning_platforms`), and on `port49 token`'s stderr everywhere. **Past the ceiling** a context is kept through the grace window and deleted at its first authorization after it, and the store refuses to extend one past it. **The refresh** is a single-use 60s nonce signed over the connection's TLS exporter value; it extends only contexts the policy in force has just judged and kept, and only an operator's `port49 refresh` or `port49 login` triggers it.

## Observation

Run at a 6m `max_session_age` (`tests/lab/slice/session-policy.yaml`), `session.ceiling_warning: 2m`, `session.grace_window: 2m`. `port49 login` at 02:05:27.375Z; the token's ceiling ran from the held connection's handshake.

| Step | The device | The record |
|---|---|---|
| 3. login inside the warning | reached a prompt; **the warning was not observed** before it (the text before the prompt: `--- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil slice01@`) | permit context_matched, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| 4. `show version` inside the warning | its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 5. `port49 refresh`, then `show version` | refresh: `refreshed at 2026-11-06T02:09:38Z; this login lasts until 2026-11-06T14:09:38Z srx1 (slice01) extended to 2026-11-06T02:15:38Z, not reached: the device keeps it…`; `show version`: its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 6. `show version` at the ceiling + 10 s (02:15:48.000Z) | its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 7. `port49 refresh` inside the grace window, then `show version` | refresh: `refreshed at 2026-11-06T02:15:48Z; this login lasts until 2026-11-06T14:15:48Z srx1 (slice01) extended to 2026-11-06T02:21:48Z, not reached: the device keeps it…`; `show version`: its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 8. `show version` at the new ceiling + the grace window + 10 s (02:23:58.000Z) | its output appeared in 200ms; port49's text: no port49 text and no refusal; port49 was not asked (decision 21) |
| 8. `port49 refresh` after it | `refreshed at 2026-11-06T02:23:58Z; this login lasts until 2026-11-06T14:23:58Z srx1 (slice01) past the grace window, not resumed: log in again there, not reache…`; 1 refresh record(s) |

`port49 refresh`'s output in full (raw: `tests/lab/evidence/session-refresh-juniper_vjunos-router.txt`), at step 5:

```
refreshed at 2026-11-06T02:09:38Z; this login lasts until 2026-11-06T14:09:38Z
  srx1 (slice01)  extended to 2026-11-06T02:15:38Z, not reached: the device keeps its own session
```

At step 7:

```
refreshed at 2026-11-06T02:15:48Z; this login lasts until 2026-11-06T14:15:48Z
  srx1 (slice01)  extended to 2026-11-06T02:21:48Z, not reached: the device keeps its own session
```

At step 8:

```
refreshed at 2026-11-06T02:23:58Z; this login lasts until 2026-11-06T14:23:58Z
  srx1 (slice01)  past the grace window, not resumed: log in again there, not reached: the device keeps its own session
```

**Not exercised here:** a nonce used twice, a challenge answered on another connection, the 10 s rate limit, and a refresh triggered by anything but an operator's `port49 refresh`. Those clauses are unit-tested (plan 7b, Tasks 6–8); these notes are not evidence for them.

Records from `port49 login` on: `event=account` ×6; `event=authorize_session reason=context_matched` ×1; `event=mint reason=grants_matched` ×1; `event=redeem reason=token_redeemed` ×1; `event=refresh reason=grants_matched` ×2; `event=refresh reason=session_expired` ×1.

On Junos the session reply at login is the one `server_msg` the device is ever sent (decision 21): Junos authorizes no command with port49, so the command rows say only whether `show version` ran, and the ceiling and the grace window are read off the refresh's answer and the records.

port49d, port49 and port49-inventory built from `a158aaf8` (`make build`).

