# directory-e2e — juniper_vjunos-router

- **Date measured:** 2026-10-06
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/directory-e2e-juniper_vjunos-router.pcap` — 815 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/directory-e2e-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `f8f049dd8cd5f253be41476204f86d5cd06fe947`, `PORT49_LAB_PLATFORMS=vjunos`, `-run ^TestDirectoryEndToEnd$`

## Claim

A person whose certificate maps to a directory entry is granted through a nested group (alice ∈ g-leaf ∈ g-mid ∈ netops-oncall) and logs in to the device with the token the broker minted; a member removed from the chain loses the open session at the broker's next scheduled refresh; with the directory down, the broker mints from the stored membership within directory.grace and the open session's commands are permitted until session.staleness_ceiling, then denied context_stale; when the directory returns the scheduled refresh stamps the context and the same session resumes; a broker restarted during the outage still mints for a principal it has stored, and refuses one it has never verified directory_unavailable (plan 7g Task 18; policy engine spec §14).

## Observation

Directory: OpenLDAP (`@(#) $OpenLDAP: slapd 2.5.13+dfsg-5 (Feb 8 2023 01:56:12) $`), image `port49lab/openldap:bookworm` (port49lab/openldap@sha256:e5ee1f178c6d1e471dd5614547c1e258ee56840644f2b36846fef00e18f86660), on the compose network as `openldap`, the broker bound by EXTERNAL over LDAPS. Configuration: `refresh_interval: 1m0s`, `directory.grace: 3m0s`, `session.staleness_ceiling: 3m0s`, `nested_groups: recursive` (OpenLDAP answers in_chain empty, L42), `certificate_mapping: san_email` (weak, pinned to the users CA), `prewarm: {interval: 5m}`. The lab policy grants `netops-oncall` (a group subject) and bob (an identity subject, no `username:`) `network_admin` on every device. The directory is stopped and started with `docker compose stop`/`start`; its entrypoint keeps the seeded data and every entryUUID across a restart (a reloaded fixture would change them, which the pin refuses).

| step | observed |
|---|---|
| 1a. alice's certificate, `port49 login`, `port49 token` for srx1 | `mint permit grants_matched, policy.subject netops_oncall, auth.directory.source fresh` |
| 1b. SSH as alice with the token, `show version` | `the session opened; permitted in 200ms (the version line printed); Junos authorizes no command (decision 21), so no ctx_id` |
| 2a. g-mid's members before | `g-leaf (err <nil>)` |
| 2b. `ldapmodify` removes g-leaf from g-mid | `g-mid's members now: nobody (err <nil>)` |
| 2c. the broker's refresh | `'refresh deny no_grants_matched' for alice's ctx_id QPSRXMXDHBZUVSNJ 1m17.8s after the removal (bound 1m30s); session.unreached true` |
| 2d. the open session's next `show version` (Junos: decision 21) | `permitted in 200ms (the version line printed)` |
| 2e. the membership is put back | `g-mid's members: g-leaf (err <nil>)` |
| 3a. alice logs in again (fresh token), `show version` | `permitted in 200ms (the version line printed); ctx_id` |
| 3b. the directory is stopped; a second `port49 token` for srx1 | `minted true 100ms after the stop; mint permit grants_matched, policy.subject netops_oncall, auth.directory.source grace; the broker said: port49-broker: directory: user:alice@corp.example.com minted from a membership verified 0s ago (grace)` |
| 3c. Junos: the open session through the outage (decision 21) | `permitted in 200ms (the version line printed); context_stale is a command authorization, which Junos does not send` |
| 3e. a `port49 token` 3m46.1s after the stop, past grace | `minted false; port49 token: broker_error: agent: the broker is unavailable just now (directory_unavailable): no directory server answered and no membership verified within the grace window is held; the agent retrie...` |
| 4a. the directory is started again: the scheduled pass | `port49_directory_refresh_last_complete_timestamp_seconds moved from 1791251240 to 1791251540 1m12.4s after the start (1m12.3s after its fixture loaded; bound 2m30s = refresh_interval + the breaker's probe_interval + 30s, since the breaker the outage opened is closed only by its health check); refresh records for alice since the start: 0` |
| 4b. Junos: a fresh login after the return (the open session sends no command) | `permitted in 200ms (the version line printed)` |
| 5a. the broker's stored memberships (mb/ keys), before the outage | `alice true, bob false (2 key(s); err <nil>)` |
| 5b. the directory stopped, `docker compose restart port49-broker` | `/readyz 200 3s after the restart` |
| 5c. alice: `port49 login`, `port49 token` after the restart, within grace | `minted true (); mint permit grants_matched, policy.subject netops_oncall, auth.directory.source grace` |
| 5d. bob (never logged in, so no membership is stored): `port49 login`, `port49 token` | `port49 login: the agent exited (exit status 1); the end of /tmp/p49dir1734959916/a/agent.log: port49 agent: connecting to https://127.0.0.1:8449 port49 agent: the broker is unavailable just now (directory_unavailable): no directory server answered and no membership verified within the grace window i...` |

