# L46 — keycloak

- **Date measured:** 2026-10-07
- **Run:** commit `15f1699c7bd7bd0673d317cc0d6931b8091ffc3a`, `PORT49_LAB_PLATFORMS=`, `-run TestL45|TestL46`
- **Platform:** Keycloak, as a container on `tests/lab/oidc/compose.yaml` (no network device)
- **Image version:** Keycloak 26.4.7 JVM: 21.0.9 (Red Hat, Inc. OpenJDK 64-Bit Server VM 21.0.9+10-LTS) OS: Linux 7.0.0-31-generic amd64; image quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007
- **Capture:** `tests/lab/evidence/L46-keycloak.json`: one JSON line per request or token, with the JWS header and claims decoded and the signature dropped (the wire is TLS, so a pcap would be encrypted).
- **Credentials:** none here or in the evidence: the admin password is generated per run and never printed; the lab user's password and the service secret are the realm file's published lab values.

## Claim

On Keycloak, with an SSO session live: whether a plain second authorization request reuses it (the control); whether one with prompt=login makes the person enter their password again; whether the new ID token's auth_time is the new authentication's; whether it carries the request's nonce; whether its sid is the old session's; what a refresh-token grant's ID token carries (auth_time, nonce, sid); max_age=0 against prompt=login; the ID token's preferred_username for a user created as "alice"; and which of auth_time, sid, nonce, scp, amr, idtyp, azp, client_id and sub a client-credentials access token carries beside a person's access token (policy engine spec §15 L46; §5.6; §13 decision 39 rulings 15, 21 and 23).

## Observation

| step | password asked | auth_time | nonce | sid |
|---|---|---|---|---|
| 1. first login, nonce n-first | true | 2026-10-07T06:21:51Z | "n-first" | d97517b7-c4d0-ce8c-94b1-807ed14ee6bd |
| 1b. plain second login (control), nonce n-reuse | false | 2026-10-07T06:21:51Z | "n-reuse" | d97517b7-c4d0-ce8c-94b1-807ed14ee6bd |
| 2. prompt=login, nonce n-again | true | 2026-10-07T06:21:58Z | "n-again" | d97517b7-c4d0-ce8c-94b1-807ed14ee6bd |
| 3. refresh-token grant | false | 2026-10-07T06:21:58Z | "" | d97517b7-c4d0-ce8c-94b1-807ed14ee6bd |
| 4. max_age=0, nonce n-maxage | true | 2026-10-07T06:22:04Z | "n-maxage" | d97517b7-c4d0-ce8c-94b1-807ed14ee6bd |

- prompt=login moved auth_time by 7s and asked for the password: true; its nonce is the request's: true; its sid is the first login's: true.
- The refresh-token grant's auth_time is the last authentication's: true (0s after it); its nonce: ""; its sid unchanged: true.
- max_age=0 asked for the password: true, and moved auth_time by 6s.
- **Ruling 15 may close on this run:** true (the control held: true; prompt=login moved auth_time forward: true; the nonce was echoed: true).
- The ID token's preferred_username for a user created as "alice": "alice".

| claim | client-credentials token | person's access token |
|---|---|---|
| auth_time | absent | `1.791354118e+09` |
| sid | absent | `d97517b7-c4d0-ce8c-94b1-807ed14ee6bd` |
| nonce | absent | absent |
| scp | absent | absent |
| amr | absent | absent |
| idtyp | absent | absent |
| azp | `port49-svc` | `port49-cli` |
| client_id | absent | absent |
| sub | `5f3c2d1e-0000-4000-8000-000000000049` | `eff69d41-ee60-4529-a81e-70b771c1b812` |
| scope | `profile email` | `openid profile email` |
| session_state | absent | absent |
| aud | `api://port49-svc` | absent |

- Ruling 21's markers on the client-credentials token: [] (the ruling rests on none).
- The client-credentials token's sub is the service account's fixed id 5f3c2d1e-0000-4000-8000-000000000049: true.

