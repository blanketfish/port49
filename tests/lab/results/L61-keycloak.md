# L61 — keycloak

- **Date measured:** 2026-10-12
- **Run:** commit `1562789af8c9b62c10c91644a2dcb3464f7f8da0`, `PORT49_LAB_PLATFORMS=`, `-run TestL61`
- **Platform:** Keycloak, as a container on `tests/lab/oidc/compose.yaml` (no network device)
- **Image version:** Keycloak 26.4.7 JVM: 21.0.9 (Red Hat, Inc. OpenJDK 64-Bit Server VM 21.0.9+10-LTS) OS: Linux 7.0.0-31-generic amd64; image quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007
- **Capture:** `tests/lab/evidence/L61-keycloak.json`: one JSON line per observed step, {step, value}: a token's value is its JWS header and claims decoded with the signature dropped, any other value is the observation's text (the wire is TLS, so a pcap would be encrypted).
- **Credentials:** none here or in the evidence: the admin password is generated per run and never printed; the lab user's password and the service secret are the realm file's published lab values.

## Claim

Keycloak's `amr` and `acr` in an ID token for `idp_mfa`. With a realm flow of password and OTP, a `prompt=login` sign-in with both: whether the ID token carries `amr`, and which values, with Keycloak's AMR protocol mapper and with none; the control, a password-only sign-in, and its `amr`; whether `acr_values` changes either (policy engine spec §15 L61; §13 decision 45 ruling 13, the default `amr: [mfa]`).

## Observation

The realm flow `p49-otp` (made through the admin API at run time) is a required sub-flow of Keycloak's username-password form and its OTP form, bound to `port49-cli` as its browser flow; `alice-otp` holds a password and a TOTP credential whose seed is made per run and never written. Each sign-in is `prompt=login` in a fresh browser. The AMR mapper is Keycloak's `oidc-amr-mapper`, added to the client; the reference values are the executions' `default.reference.value` (cell config). Cell e is the remedy cell b points to when the gate fails.

| cell | observed |
|---|---|
| a. password and OTP, no AMR mapper | `amr absent; acr "1"` |
| config. reference value set on the execution | `auth-username-password-form -> pwd: 201` |
| config. reference value set on the execution | `auth-otp-form -> otp: 201` |
| config. reference value set on the execution | `sub-flow -> mfa: 201` |
| b. password and OTP, the AMR mapper, references pwd, otp and mfa | `amr [pwd otp]; acr "1"` |
| c. control: password only (alice, the default flow), the AMR mapper | `amr []; acr "1"` |
| d. (b) with acr_values=gold asked | `amr [pwd otp]; acr "1"` |
| e. (b) with the OTP execution's reference value set to mfa | `amr [pwd mfa]; acr "1"` |
| Gate M1. (b) carries one of [mfa] and (c) does not | `false (b carries: false; c carries: false)` |

