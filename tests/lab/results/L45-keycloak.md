# L45 — keycloak

- **Date measured:** 2026-10-07
- **Run:** commit `15f1699c7bd7bd0673d317cc0d6931b8091ffc3a`, `PORT49_LAB_PLATFORMS=`, `-run TestL45|TestL46`
- **Platform:** Keycloak, as a container on `tests/lab/oidc/compose.yaml` (no network device)
- **Image version:** Keycloak 26.4.7 JVM: 21.0.9 (Red Hat, Inc. OpenJDK 64-Bit Server VM 21.0.9+10-LTS) OS: Linux 7.0.0-31-generic amd64; image quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007
- **Capture:** `tests/lab/evidence/L45-keycloak.json`: one JSON line per request or token, with the JWS header and claims decoded and the signature dropped (the wire is TLS, so a pcap would be encrypted).
- **Credentials:** none here or in the evidence: the admin password is generated per run and never printed; the lab user's password and the service secret are the realm file's published lab values.

## Claim

The back-channel logout token Keycloak sends to port49's /v1/logout when (a) the person logs out at the end-session endpoint, (b) an administrator signs the user out of every session, and (c) an administrator ends one session: its JWS header (alg, kid, typ); which of iss, aud, azp, iat, exp, jti, sub, sid and events it carries, and that nonce is absent; whether its sid and its sub are the ID token's; one token per session or per user; the request's content type; and what Keycloak does, and what its end-session endpoint answers, when the answer is 503, 400, or the connection is refused (policy engine spec §15 L45; §13 decision 39 rulings 12 and 13).

## Observation

| way | requests | content type | header | claims present | nonce | sid = ID token's | sub = ID token's | exp − iat |
|---|---|---|---|---|---|---|---|---|
| (a) end-session endpoint | 1 | `application/x-www-form-urlencoded` | alg RS256 kid true typ logout+jwt | aud, events, exp, iat, iss, jti, sid, sub, typ | false | true | true | 120s |
| (b) admin: sign out user (2 sessions) | 1 | `application/x-www-form-urlencoded` | alg RS256 kid true typ logout+jwt | aud, events, exp, iat, iss, jti, sid, sub, typ | false | false | true | 120s |

(b) sent 1 token(s) for 2 sessions; sids 6be722d5-4797-2595-055c-4ddb91fb80ec and 2b19c711-4efd-e081-9df7-c3dbb4e3a19d.

| (c) admin: end one session | 1 | `application/x-www-form-urlencoded` | alg RS256 kid true typ logout+jwt | aud, events, exp, iat, iss, jti, sid, sub, typ | false | true | true | 120s |
- answered 503: 1 request(s) in 2 minutes; the end-session endpoint answered 302 (<nil>).
- answered 400: 1 request(s) in 2 minutes; the end-session endpoint answered 302 (<nil>).
- answered nothing (connection refused): 0 request(s) in 2 minutes; the end-session endpoint answered 302 (<nil>).
- Keycloak's log: `keycloak-1 | 2026-10-07 06:19:35,097 WARN [org.keycloak.services] (executor-thread-1) KC-SERVICES0057: Logout for client 'port49-cli' failed: org.apache.http.conn.HttpHostConnectException: Connect to host.port49.lab:18750 [host.port49.lab/1...`

