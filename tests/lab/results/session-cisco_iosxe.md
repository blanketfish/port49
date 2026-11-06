# session — cisco_iosxe

- **Date measured:** 2026-11-06
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/session-cisco_iosxe.pcap` — 338 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/session-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestSessionLifetime$`

## Claim

Spec §13 decision 33, its session clauses. **The warning** rides on permits within `session.ceiling_warning` of the ceiling, to the platforms L34 finds show it and any an operator lists (`session.ceiling_warning_platforms`), and on `port49 token`'s stderr everywhere. **Past the ceiling** a context is kept through the grace window and deleted at its first authorization after it, and the store refuses to extend one past it. **The refresh** is a single-use 60s nonce signed over the connection's TLS exporter value; it extends only contexts the policy in force has just judged and kept, and only an operator's `port49 refresh` or `port49 login` triggers it.

## Observation

Run at a 6m `max_session_age` (`tests/lab/slice/session-policy.yaml`), `session.ceiling_warning: 2m`, `session.grace_window: 2m`. `port49 login` at 03:08:18.657Z; the token's ceiling ran from the held connection's handshake.

| Step | The device | The record |
|---|---|---|
| 3. login inside the warning | reached a prompt; before it the device showed `port49: session ends in 2m - run 'port49 refresh'` | permit context_matched, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| 4. `show version` inside the warning | its output appeared in 300ms; port49's text: `port49: session ends in 2m - run 'port49 refresh'`; the record: permit permit_dominates, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| 5. `port49 refresh`, then `show version` | refresh: `refreshed at 2026-11-06T03:12:29Z; this login lasts until 2026-11-06T15:12:29Z xe1 (slice01) extended to 2026-11-06T03:18:29Z`; `show version`: its output appeared in 300ms; port49's text: no port49 text and no refusal; the record: permit permit_dominates, server_msg `(none)` |
| 6. `show version` at the ceiling + 10 s (03:18:39.000Z) | refused in 300ms; the device printed `port49: session expired - run 'port49 refresh' (or 'port49 login') within 2m to resume`; the record: deny session_expired, server_msg `port49: session expired - run 'port49 refresh' (or 'port49 login') within 2m to resume` |
| 7. `port49 refresh` inside the grace window, then `show version` | refresh: `refreshed at 2026-11-06T03:18:39Z; this login lasts until 2026-11-06T15:18:39Z xe1 (slice01) extended to 2026-11-06T03:24:39Z`; `show version`: its output appeared in 300ms; port49's text: no port49 text and no refusal; the record: permit permit_dominates, server_msg `(none)` |
| 8. `show version` at the new ceiling + the grace window + 10 s (03:26:49.000Z) | refused in 300ms; the device printed `port49: session ended - get a new token ('port49 token') and log in again`; the record: deny session_expired, server_msg `port49: session ended - get a new token ('port49 token') and log in again` |
| 8. `port49 refresh` after it | `refreshed at 2026-11-06T03:26:49Z; this login lasts until 2026-11-06T15:26:49Z no live device session to extend`; 0 refresh record(s) |
| 8. `show version` once more | refused in 300ms; the device printed `port49: this session was not authenticated by port49`; the record: deny context_missing, server_msg `port49: this session was not authenticated by port49` |

`port49 refresh`'s output in full (raw: `tests/lab/evidence/session-refresh-cisco_iosxe.txt`), at step 5:

```
refreshed at 2026-11-06T03:12:29Z; this login lasts until 2026-11-06T15:12:29Z
  xe1 (slice01)  extended to 2026-11-06T03:18:29Z
```

At step 7:

```
refreshed at 2026-11-06T03:18:39Z; this login lasts until 2026-11-06T15:18:39Z
  xe1 (slice01)  extended to 2026-11-06T03:24:39Z
```

At step 8:

```
refreshed at 2026-11-06T03:26:49Z; this login lasts until 2026-11-06T15:26:49Z
  no live device session to extend
```

**Not exercised here:** a nonce used twice, a challenge answered on another connection, the 10 s rate limit, and a refresh triggered by anything but an operator's `port49 refresh`. Those clauses are unit-tested (plan 7b, Tasks 6–8); these notes are not evidence for them.

Records from `port49 login` on: `event=account` ×5; `event=authorize_command reason=context_missing` ×1; `event=authorize_command reason=permit_dominates` ×4; `event=authorize_command reason=session_expired` ×2; `event=authorize_session reason=context_matched` ×1; `event=mint reason=grants_matched` ×1; `event=redeem reason=token_redeemed` ×1; `event=refresh reason=grants_matched` ×2.
port49d, port49 and port49-inventory built from `a158aaf8` (`make build`).

