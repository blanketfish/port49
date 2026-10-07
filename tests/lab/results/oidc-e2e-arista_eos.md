# oidc-e2e — arista_eos

- **Date measured:** 2026-10-07
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/oidc-e2e-arista_eos.pcap` — 735 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/oidc-e2e-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `4aa4cb689a52f7d5f99982368e6d2350e8d21886`, `PORT49_LAB_PLATFORMS=eos`, `-run TestOIDCEndToEnd`

## Claim

A person who logs in at Keycloak mints a token from the broker with the ID token as a bearer and logs in to the device with it; a logout at Keycloak reaches the broker by back-channel and the open session's next command is denied credential_revoked; a new login after it works; a prompt=login refresh answering the broker's challenge extends the open session from the fresh auth_time, while a plain SSO login answering one is refused refresh_not_fresh; and a client-credentials token of the listed client mints for the machine subject (plan 7h Task 16; policy engine spec §14).

## Observation

| step | observed |
|---|---|
| 1a. Keycloak login, POST /v1/tokens with the ID token as bearer | `200 user:alice@corp.example.com: permit as alice` |
| 1b. SSH as alice with the token, `show version` | `permitted in 100ms (the version line printed)` |
| 2a. RP-initiated logout at Keycloak; the broker's revoke record | `{"at":"2026-10-07T06:59:16.229Z","by":"sid","contexts":1,"oidc_issuer":"https://keycloak.port49.lab:18443/realms/port49-lab","origin":"backchannel_logout https://keycloak.port49.lab:18443/realms/port49-lab","sid":"6bf451b8-fa3d-3d34-2311-18bd3536731d"}` |
| 2b. the open session's next `show version` | `refused in 100ms, the device printed '% Authorization denied for command 'show version': port49: this session was revoked - log in again'; port49d: deny credential_revoked` |
| 2c. the ended session's ID token mints again | `401 credential_revoked: your identity provider ended this session at 2026-10-07T06:59:16Z (back-channel logout); log in again` |
| 3a. a new Keycloak login, a new mint | `200 user:alice@corp.example.com: permit as alice` |
| 3b. SSH as alice with it, `show version` | `permitted in 100ms (the version line printed)` |
| 4b. a challenge, a plain SSO login with its nonce, `POST /v1/refresh` | `password asked: false; 401 refresh_not_fresh: your identity provider did not authenticate you again (prompt=login was not honoured); the session was not extended` |
| 4. `POST /v1/refresh/challenge`, a prompt=login login with its nonce, `POST /v1/refresh` | `password asked: true; 200 auth_time 2026-10-07T07:00:43Z; sessions: leaf1/alice extended` |
| 4a. the extended session's next `show version` | `permitted in 100ms (the version line printed)` |
| 5. client-credentials token, POST /v1/tokens | `200 app:port49-svc: permit as svc-backup` |

