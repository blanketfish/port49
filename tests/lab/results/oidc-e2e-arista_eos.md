# oidc-e2e — arista_eos

- **Date measured:** 2026-11-05
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/oidc-e2e-arista_eos.pcap` — 675 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/oidc-e2e-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `d214c2d9271d66749e94c5d29fab5d9a6483870f-dirty`, `PORT49_LAB_PLATFORMS=eos`, `-run ^TestOIDCEndToEnd$`

## Claim

A person who logs in at Keycloak exchanges the ID token for a certificate at POST /v1/certificate (a person's ID token is no caller's credential, decision 56 ruling 4), mints a token from the broker with that certificate and logs in to the device with it; a logout at Keycloak reaches the broker by back-channel and the open session's next command is denied credential_revoked; a new login once clock_skew has passed works (an immediate one is refused, for the sub record every Keycloak logout writes); and a client-credentials token of the listed client mints for the machine subject (plan 7h Task 16; policy engine spec §14); Keycloak's admin sign-out of a user holding two sessions sends one logout token naming one session and the subject, and the broker ends both sessions (ruling 13, spec §5.1.4); and a burst of eight back-channel logouts, one per session ended back to back, all reach the broker and all apply, none lost to a reused connection (plan 7h final review F1). The refresh of an open session by a prompt=login ID token at POST /v1/refresh is retired with the bearer refresh; the certificate's refresh is L56's.

## Observation

| step | observed |
|---|---|
| 1a. Keycloak login with a nonce bound to a fresh key, POST /v1/certificate with the ID token as bearer | `200 user:alice@corp.example.com: certificate issued` |
| 1b. POST /v1/tokens by the issued certificate | `200 user:alice@corp.example.com: permit as alice` |
| 1c. SSH as alice with the token, `show version` | `permitted in 100ms (the version line printed)` |
| 2a. RP-initiated logout at Keycloak; the broker's revoke record | `{"at":"2026-11-05T08:02:21.996Z","by":"sid","contexts":1,"oidc_issuer":"https://keycloak.port49.lab:18443/realms/port49-lab","origin":"backchannel_logout https://keycloak.port49.lab:18443/realms/port49-lab","sid":"fd6c2297-ea0f-6913-a6ff-fe5dcef6d39c"}` |
| 2b. the open session's next `show version` | `refused in 100ms, the device printed '% Authorization denied for command 'show version': port49: this session was revoked - log in again'; port49d: deny credential_revoked` |
| 2c. the ended session's certificate mints again | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:02:21Z (back-channel logout); log in again from 2026-11-05T08:03:22Z` |
| 3-. a new Keycloak login at once after the logout, POST /v1/certificate with its ID token | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:02:21Z (back-channel logout); log in again from 2026-11-05T08:03:22Z` |
| 3a. a new Keycloak login after clock_skew, its exchange and a new mint | `200 user:alice@corp.example.com: permit as alice` |
| 3b. SSH as alice with it, `show version` | `permitted in 100ms (the version line printed)` |
| 4, 4b, 4a. a prompt=login ID token at POST /v1/refresh | `not measured: retired with the bearer refresh (decision 56 ruling 4); the certificate's refresh is L56's` |
| 5. client-credentials token, POST /v1/tokens | `200 app:port49-svc: permit as svc-backup` |
| 6a. two fresh Keycloak logins as bob, a certificate for each and a mint with it | `both minted; two different sids` |
| 6b. the broker's revoke records after admin sign-out | `revoke by sid (session 2 of 2), then revoke by sub (the user's); origin backchannel_logout <issuer>` |
| 6c. session 1 of 2's certificate mints again | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:28Z (back-channel logout); log in again from 2026-11-05T08:04:29Z` |
| 6c. session 2 of 2's certificate mints again | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:28Z (back-channel logout); log in again from 2026-11-05T08:04:29Z` |
| 6e. logout tokens Keycloak sent for the one sign-out | `1 logout request(s) answered; 1 revoke record(s) by sid` |
| 6d. Keycloak's log in the window | `no back-channel delivery failure` |
| 7a. eight fresh Keycloak logins as carol, a certificate for each and a mint with it | `all eight minted` |
| 7b. eight admin session ends back to back; the broker's revoke records by sid | `a revoke by sid for each of the eight burst sessions within 30s; origin backchannel_logout <issuer>` |
| 7c. port49_oidc_logouts_total gained | `8 logouts answered: 1 applied, 7 found nothing to end, 0 any other outcome (of 8 ended)` |
| 7d. burst session 1 of 8's certificate mints again (refused by its session's logout) | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:29Z (back-channel logout); log in again from 2026-11-05T08:04:30Z` |
| 7d. burst session 2 of 8's certificate mints again (refused by its session's logout) | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:29Z (back-channel logout); log in again from 2026-11-05T08:04:30Z` |
| 7d. burst session 3 of 8's certificate mints again (refused by its session's logout) | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:29Z (back-channel logout); log in again from 2026-11-05T08:04:30Z` |
| 7d. burst session 4 of 8's certificate mints again (refused by its session's logout) | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:29Z (back-channel logout); log in again from 2026-11-05T08:04:30Z` |
| 7d. burst session 5 of 8's certificate mints again (refused by its session's logout) | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:29Z (back-channel logout); log in again from 2026-11-05T08:04:30Z` |
| 7d. burst session 6 of 8's certificate mints again (refused by its session's logout) | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:29Z (back-channel logout); log in again from 2026-11-05T08:04:30Z` |
| 7d. burst session 7 of 8's certificate mints again (refused by its session's logout) | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:29Z (back-channel logout); log in again from 2026-11-05T08:04:30Z` |
| 7d. burst session 8 of 8's certificate mints again (refused by its session's logout) | `401 credential_revoked: your identity provider ended your sessions at 2026-11-05T08:03:29Z (back-channel logout); log in again from 2026-11-05T08:04:30Z` |
| 7e. Keycloak's log in the window | `no back-channel delivery failure` |

