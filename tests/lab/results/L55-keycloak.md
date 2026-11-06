# L55 — keycloak

- **Date measured:** 2026-11-06
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=`, `-run ^TestL55PublicClient$`
- **Platform:** Keycloak, as a container on `tests/lab/oidc/compose.yaml` (no network device)
- **Image version:** Keycloak 26.4.7 JVM: 21.0.9 (Red Hat, Inc. OpenJDK 64-Bit Server VM 21.0.9+10-LTS) OS: Linux 7.0.0-38-generic amd64; image quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007
- **Capture:** `tests/lab/evidence/L55-keycloak.json`: one JSON line per observed step, {step, value}: a token's value is its JWS header and claims decoded with the signature dropped, any other value is the observation's text (the wire is TLS, so a pcap would be encrypted).
- **Credentials:** none here or in the evidence: the admin password is generated per run and never printed; the lab user's password and the service secret are the realm file's published lab values.

## Claim

Keycloak as port49's public client meets it (plan 9b): which redirect registration admits an authorization request naming http://127.0.0.1:<port>/callback, for the registered port and an ephemeral one (RFC 8252 §7.3), against a matcher seen to accept the realm's own redirect and refuse another host's; whether a code is exchanged with the right S256 verifier, a wrong one and none, for port49-cli as the realm file sets its PKCE method, and whether code_challenge_method=plain is accepted; discovery's code_challenge_methods_supported and authorization_response_iss_parameter_supported, and whether the authorization response carries iss (RFC 9207); whether a 43-character base64url nonce, port49's key binding, comes back in the ID token byte for byte, and whether a prompt=login sign-in's auth_time is within 10s of it, and over a live SSO session whether prompt=login shows the form and moves auth_time on, against the same session with no prompt (policy engine spec §15 L55; §13 decision 43 rulings 1, 3, 4 and 8).

## Observation

port49-cli's `pkce.code.challenge.method` attribute is "S256" (`tests/lab/oidc/keycloak/realm.json`), so step 3 measures a client Keycloak is told requires that method; what it does for a client set to require none, which decision 43 ruling 1's provider listing no methods resembles, is not measured here.

| step | observed |
|---|---|
| 1a. discovery code_challenge_methods_supported | `[plain S256]` |
| 1b. discovery authorization_response_iss_parameter_supported | `true` |
| 1c. the authorization response's iss | `present true, the issuer true` |
| 2. control: the realm's own redirect, and http://evil.example/callback | `accepted; refused` |
| 2. registration http://127.0.0.1:18749/callback | `port 18749 accepted; port 45087 refused` |
| 2. registration http://127.0.0.1/callback | `port 18749 accepted; port 45087 accepted` |
| 2. registration http://127.0.0.1/* | `port 18749 accepted; port 45087 accepted` |
| 2. registration http://127.0.0.1:*/callback | `port 18749 refused; port 45087 refused` |
| 3. port49-cli's pkce.code.challenge.method attribute | `S256` |
| 3. the exchange with the right verifier | `200 with id_token, refresh_token` |
| 3. the exchange with a wrong verifier | `400 invalid_grant` |
| 3. the exchange with no verifier | `400 invalid_grant` |
| 3d. code_challenge_method=plain | `refused` |
| 4. a 43-character nonce, and auth_time | `nonce echoed byte for byte true; auth_time +0s from the sign-in` |
| 4b. control: the same SSO session 15s later, no prompt | `form shown false; auth_time +0s after the first sign-in's` |
| 4b. prompt=login over that SSO session | `form shown true; auth_time +15s after the first sign-in's (expected 15s or more)` |

