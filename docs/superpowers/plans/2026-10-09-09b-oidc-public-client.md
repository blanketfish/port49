# Plan 9b: port49-issued user certificates over an OIDC sign-in — Implementation Plan

> **Supersedes** the plan of the same name at `daebc7c` (written 2026-10-09, with its pre-flight
> fixes). That plan made the agent an OIDC client that held the ID token and the provider's refresh
> token in memory and renewed them silently. On 2026-10-10 Ryan directed instead that port49 issue
> short-lived client certificates from the start (design §7's "the broker MAY issue", made v1), so
> that a company with neither a PKI nor a hardware key can still use port49, and so that every
> session after a sign-in runs on the certificate path unchanged. Everything still valid is kept:
> the sign-in (PKCE S256, loopback, `state`, `nonce`, `iss`, `prompt=login`, the pasted address,
> `ErrNoWayBack`), C1's `hardenAgent`, I4's printing of the principal, and the lab lessons of
> I5 and I6. What issuance makes moot is dropped: tokens in the agent, silent renewal, the 401
> renew-and-resend, the browser refresh, and `id_token_not_renewed`. Pre-flight D1 dissolves
> (decision 43 ruling 11).
>
> **Amended the same day** for Ryan's later rulings: the client's config moves to `~/.port49`, under
> a root-owned `/etc/port49/config.yaml` the install ships, and no step per user may remain that
> cannot be done at scale (decision 43 ruling 24, R8, and a new Task 11; the lab and roadmap tasks
> become 12 and 13). The broker sends its CA bundle and each agent keeps it, so a rotation of the
> broker's TLS CA asks nothing of users either (ruling 25, R10; Tasks 8 and 11).
>
> **Amended after pre-flight 2** (`.superpowers/sdd/2026-10-09-09b-oidc-public-client/preflight2-review.md`).
> - On a broker that issues, a logout record stands as long as a certificate issued before it
>   can be presented (C1; ruling 16, Task 7).
> - A broker that sends no CA bundle clears what agents kept, and ruling 25 states what a taken
>   server key can plant (I1; Task 11).
> - L55 measures `prompt=login` over a live SSO session (I2), and L56 checks each run against the
>   key it wrote (I4).
> - A broker-CA rotation ships `broker_ca` through config management, so no user steps in (I3).
> - Freshness is judged on two clocks (m3), and `rotate-issuer` has guards (m4).
> - The gap m5 leaves until 9d is carried explicitly.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `port49 login --oidc` signs a person in at the identity provider the broker lists, and the
broker issues them a short-lived client certificate for a key generated on their host. The agent
then holds the session exactly as on the certificate path, so every mint, refresh and session
extension after the sign-in is a key signature.

**Plan 9 is split five ways** (roadmap, "Plan 9"). This is 9b.
- **9a** (merged, PR #44): sweeps by scope, the per-user config file, `port49 ssh`.
- **9c:** hardware-backed client keys (which hold 9b's issued keys too), `per_login_mfa` for the
  devices a policy level marks, and the broker certificate's CRL check.
- **9d:** host keys carried by inventory, and the Python and Ansible clients.
- **9e:** a directory-password sign-in, issuing the same certificate (added 2026-10-10).

What 9b builds:

- **The sign-in (decision 43 rulings 1–6).** The authorization-code flow with PKCE, S256 only, over
  a loopback redirect on `127.0.0.1` and an ephemeral port (RFC 8252), with no client secret, in
  `port49 login`'s own process.
  - Every sign-in asks `prompt=login`: it is a fresh authentication.
  - `state`, the `nonce` and RFC 9207's `iss` are checked. The `nonce` is the new key's hash, so
    the ID token names the one key it may be exchanged for.
  - On a host with no display no browser is launched. The address is always printed, and on a
    terminal the address the browser ended on can be pasted back. With no terminal either, and no
    fixed port to forward, that is said at once.
  - The device authorization grant is ruled out.
- **The key and the certificate (rulings 7–10).**
  - `port49 login` generates an ECDSA P-256 key and writes it 0600 through
    `userconfig.WritePrivate`. 9c puts it in a TPM, the Secure Enclave or a token, behind the same
    `crypto.Signer`.
  - `POST /v1/certificate` takes the sign-in's ID token as its bearer and a CSR for the key. The
    broker checks the token as any person's (decision 39), its `auth_time` within 5 minutes, and
    its `nonce` naming the CSR's key. It takes each token once.
  - It issues from its own issuing CA: CN the principal, one URI SAN carrying the sign-in (`iss`,
    `sub`, `sid`, `auth_time`, `amr`, `acr`), `clientAuth`, valid `certificate_lifetime`
    (default 12h, 1h–24h).
  - The broker trusts that CA for people alone. A chain ending there is never mapped through the
    directory and never checked against `certificate_status`.
- **The session (rulings 11 and 12).**
  - The agent opens the existing mTLS path with the issued certificate, unchanged.
  - `port49 refresh` and a new agent's extension of earlier device sessions are key signatures,
    with no browser.
  - `port49 login` reuses a held certificate while more than a quarter of its life is left, and
    signs in otherwise. `--sign-in` forces a sign-in.
- **One path for people (ruling 13).** A broker that issues takes a person's ID token at
  `/v1/certificate` and nowhere else.
- **The issuing CA (ruling 14).**
  - Its files are kept in the broker's state directory, written by `init-issuer`, rotated with
    overlap by `rotate-issuer`.
  - A broker whose CA key is missing or unreadable still starts and serves everything else. Its
    `/v1/certificate` answers 503 `issuance_unavailable`, and its start says what to run.
- **Revocation and logout (rulings 15 and 16).**
  - Revocation is by principal or by certificate serial, as today. The short lifetime is the main
    control.
  - The certificate carries its sign-in's `sid`. A back-channel logout refuses the certificate at
    its next request and refresh, and reaches its device sessions through the `sid` index.
- **The provider down at 3am (ruling 17).** People holding a certificate keep working all day,
  through a new agent too. Only a sign-in fails, and it says so.
- **The client's config (ruling 24; Task 11).** Ryan's standing rule of 2026-10-10: no step per
  user that cannot be done at scale.
  - `~/.port49/` holds `config.yaml` and the issued key and certificate, as `~/.ssh` does, made
    0700. `$PORT49_CONFIG` and `--config` name another file.
  - A root-owned `/etc/port49/config.yaml`, shipped by the install, is read under the user's file
    key by key, so a new user's first login is `port49 login` and the sign-in.
  - A config file at plan 9a's `~/.config/port49/` is refused in one line naming the move.
  - The broker sends its CA bundle (`broker.tls_ca_bundle_file`) on `/v1/config`; each agent keeps
    it per broker, and a login trusts it beside `broker_ca`, so the broker's TLS CA rotates with no
    step by a user (ruling 25).
- **Lab (ruling 23).**
  - **L55:** Keycloak as the client meets it: the redirect registrations, PKCE, the `iss`
    parameter, the key-binding `nonce` echoed, and `prompt=login` over a live SSO session.
  - **L56:** the real CLI end to end on Keycloak and vEOS: the CA missing and then made; sign-in,
    issue, mint, refresh with no browser, a new agent with no sign-in, a pasted sign-in, a logout,
    and the provider stopped.

**Architecture:**
- **`internal/oidc`:** `client.go` (new), `ReadIDToken` and `ReadDiscovery`, the client's reading
  of an ID token and a discovery document. `config.go` gains `Issuance`. The broker's verifier is
  untouched.
- **`internal/oidc/oidctest`:** `AuthServer`, an authorization server on the test issuer
  (`/authorize`, `/token` with PKCE), and `Browser` and `Redirected`.
- **`internal/oidcclient` (new):** `Discover`, `Login`, `AuthorizationURL`, `Skew`; `Provider`,
  `Endpoints`, `Tokens`; `UnreachableError`, `ProviderError`, `ErrNoWayBack`.
- **`internal/issuer` (new):** the issuing CA. `New`, `Load`, `Ephemeral`, `Mem`, `CA.Issue`,
  `CA.Ends`, `CA.PEM`, `SignIn`, `ReadSignIn`.
- **`internal/broker/api`:** `IssuanceNonce`, `IssueRequest`, `IssueResponse`, `Issuance`, and
  `Config.Issuance`.
- **`internal/broker`:**
  - `issued.go`: `issuedCaller`, `issuedLoggedOut`, `personBearerText`.
  - `issue.go`: `POST /v1/certificate`.
  - Edits for the trust: `Broker.Issuer`, `Broker.CertificateLifetime`, `CertCaller.Issued`,
    `CertCallerOf`, `Server`, `authenticate`, `callerOf`, `refresh`, `certRefusal`, the
    listener's `mapped`, and `config`.
- **`internal/decision`:** `EventIssue`, `CertificateIssued`, `Record.Certificate`.
- **`internal/daemon/metrics`:** `port49_certificates_issued_total{outcome}` and
  `port49_issuing_ca_not_after_timestamp_seconds`.
- **`internal/config`:** `broker.identity.issuance.certificate_lifetime`.
- **`internal/port49d`:** `issuer.go` (`openIssuer`, `issuerFiles`, `initIssuer`,
  `rotateIssuer`, `issuerCmd`). The subcommands `port49d init-issuer|rotate-issuer` and
  `port49-broker init-issuer|rotate-issuer`.
- **`internal/agent`:** `CertificateEnd`, which `agentMain` exits at when it comes before the
  session's deadline.
- **`internal/userconfig`:** `method`, `oidc_issuer`, `oidc_ca`, `oidc_redirect_port`;
  `WithoutOIDCCA`; `IssuedPaths`, `IssuedPathsIn` (Task 10). `Dir` moves to `~/.port49`, under
  which a root-owned `/etc/port49/config.yaml` is read key by key: `LoadAll`, `SystemPath`,
  `SystemOwner`, `EnvConfig` (`PORT49_CONFIG`), `LegacyDir` (Task 11).
- **`internal/hostkeys`:** `Path` stays in plan 9a's directory, through `userconfig.LegacyDir`,
  until 9d (Task 11).
- **The broker's CA bundle (ruling 25):** `internal/broker/api/cabundle.go` (`ParseCABundle`,
  `EncodeCABundle`, `CAFingerprints`), `api.Config.BrokerCABundle` and `BrokerCABundleRefused`,
  `Broker.CABundle` and `CABundleRefused`,
  `broker.tls_ca_bundle_file`, and port49d's `loadCABundle` (Task 8); `agent.BrokerRoot`,
  `agent.RotatedCAHint`, `userconfig.CABundlePath`, and `cmd/port49`'s `keepCABundle`,
  `forgetBundle` and `withKeptBundle` (Task 11).
- **`cmd/port49`:**
  - `issue.go`: `loginIssued`, `issueCertificate`, `requestCertificate`, `heldCertificate`,
    `startIssued`, `signIn`, `pickProvider`, `browserCommand`, `fetchBrokerConfig`, `warnSkew`;
  - `harden_linux.go`, `harden_darwin.go`, `harden_other.go`, and `hardenAgent` in `main.go`;
  - `sessionFlags`' new flags, `brokerPool` and `oidcRoots`, and `startAgent` factored out of
    `login`.
- **`tests/lab`:** `l55_test.go`, `l56_test.go`, `l55_l56_unit_test.go`. `make lab-oidc-l55` runs
  L55, and `make lab-oidc-agent` runs L56.

**Tech Stack:**
- Go 1.26, module `github.com/rhwendt/port49`, **no cgo**, and **no new module in the build graph**.
  - The standard library does the HTTP, the PKCE hash, the loopback listener, the key, the CSR and
    the certificates.
  - `golang.org/x/term` (direct since 9a) reads the paste with echo off.
  - `golang.org/x/sys/unix` (direct) gives `Prctl`, and `PtraceDenyAttach` on macOS.
- Keycloak 26.4, digest-pinned in `tests/lab/oidc/compose.yaml` and `tests/lab/compose/oidc.yaml`
  (plan 7h).

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2 (the principal table);
  - §5.1.4 (credential identity);
  - §5.6 (session lifetime);
  - §5.7 (the `issue` event, `certificate_issued`);
  - §12 (`port49 login`, `port49 refresh`);
  - §13: decision 17, decision 39 (rulings 9, 11, 13, 15, 16), decision 42 ruling 6, and decision
    43, rewritten;
  - §14 (the required assertions);
  - §15: L45, L46, L47, and L55 and L56, reworded.
- `docs/design/2026-08-21-port49-design.md`:
  - §7 ("The paths differ in what the agent holds", "relying party, not a certificate
    authority");
  - §8 (the two-credentials table);
  - §17 (Surface, Errors, Client libraries);
  - §19 (step 9).
- The roadmap `docs/superpowers/plans/README.md`: "Plan 9" (9b, 9c, 9e), "Plan 7h — As built",
  "Plan 9a — As built".
- The superseded draft and its pre-flight review:
  `.superpowers/sdd/2026-10-09-09b-oidc-public-client/preflight-review.md`.
- House style: plan 9a (`2026-10-09-09a-sweeps-and-ssh.md`). This plan is written against `main`
  at `2beaa35`.

**Prerequisite:** plan 9a merged (`main` at `39e6004` or later).

## Questions, ruled

Three, each ruled as recommended on 2026-10-10 by the controller under Ryan's standing grant, and
written into decision 43. The tasks build each ruling; each alternative is a small change, said
beside it.

- **Q1. When does plan 7h's bearer path for people retire?** (ruling 13)
  - **Recommendation:** gate it now, retire it at the pre-beta review. A broker that issues refuses
    a person's ID token everywhere but `POST /v1/certificate`, so on such a broker there is one path.
    A broker with a human OIDC verifier and no `issuance` block keeps 7h's path as built, which no
    port49 client drives after 9b.
  - **Why not now:** 7h's broker tests, `oidcrefresh.go`, and the L45/L46 harness (`make
    lab-oidc`) run on the bearer path. Retiring it means rebuilding about 1,400 lines of tests
    and the closed rows' harness on issuance. L56 measures the issuance path end to end, so
    nothing is unmeasured meanwhile.
  - **Alternative:** require `issuance` whenever a human OIDC verifier is listed (one config check
    in Task 8), and delete the bearer path's human branches in a follow-up before beta.
- **Q2. Where is the certificate lifetime set?** (ruling 9)
  - **Recommendation:** `broker.identity.issuance.certificate_lifetime`, default 12h, bounds
    1h–24h. 12h matches `session.max_session_age_default`, so one sign-in covers one working day.
  - **Alternative:** a per-role `certificate_lifetime` in the policy file, composed as the minimum,
    as `max_session_age` is. That is a policy-language change for a value nothing yet varies by
    role. 9c's `per_login_mfa` is where per-device strength arrives.
- **Q3. Is a held key file reused across agents?** (rulings 7 and 12)
  - **Recommendation:** yes, while more than a quarter of the certificate's life is left. A
    reboot, an agent crash or an OS update then costs no sign-in, and with the identity provider
    down a person keeps working through all of them. That is what makes ruling 17's "all day"
    true.
  - **The cost:** whoever copies `issued/<broker>.key` and its certificate, a home-directory backup
    included, holds the person's session until the certificate ends, at most
    `certificate_lifetime` (12h). That is today's
    file-key certificate path, with the key at most 12h old rather than a year. 9c moves the key
    into hardware.
  - **Alternative:** sign in at every new agent: delete the reuse branch in `loginIssued` (Task
    10). Then D1 does not dissolve: a reboot costs a password, and with the provider down a reboot
    ends the person's day.

## Rulings where the brief is open

Each is the stricter of the options, or the one the spec's own text already chose.

- **R1. The certificate carries its sign-in, signed by the CA.**
  - One URI SAN, `port49-sign-in:v1?iss=…&sub=…&sid=…&auth_time=…&iat=…&amr=…&acr=…`, and the
    principal as the subject's CN.
  - The broker reads it at every request with no store read. That keeps the handshake off the
    store at 3am, and keeps the certificate meaningful across a broker restart.
  - Ryan asked that the sid be recorded against the serial. The certificate binds the two under
    the CA's signature, and the `issue` record names both.
  - A private X.509 extension would need an OID. port49 holds no enterprise arc, and a `2.25`
    UUID arc does not fit `encoding/asn1`'s `[]int`. A URI SAN needs neither, and a chain ending
    at port49's own CA is read by no one else.
- **R2. The key binding is the nonce.**
  - `nonce = base64url(SHA-256("port49 issue v1\0" ‖ PKIX(key)))`.
  - An ID token taken in flight, or replayed within its 5-minute life, certifies no key but the one
    whose hash it names. The broker also takes each token once.
  - No challenge round trip is needed, and no unauthenticated store write. A challenge endpoint
    any caller could hit would be one.
- **R3. Freshness, on two clocks.** 5 minutes (plus `clock_skew`) is the sign-in's own wait
  (`oidcclient.SignInWait`). Each refusal is `401 sign_in_not_fresh`, and its words name the cause:
  - `iat − auth_time` over it, on the provider's own clock: a `prompt=login` the provider ignored.
    That is how one is caught.
  - `now − iat` over it, the broker's clock against the provider's: a sign-in that took too long, or
    two clocks apart. That is never blamed on `prompt=login` (pre-flight 2 m3).
  - `auth_time` after `iat` plus `clock_skew`: no sign-in. (The verifier already refuses an
    `auth_time` ahead of the broker's now.)
- **R4. Never refuse the start over the CA.** port49d answers device AAA in the same process.
  - A missing or unreadable key stops issuance alone.
  - A missing CA certificate also stops trust in the certificates it issued, and is said as loudly.
  - This is the server certificate's rule (`buildBrokerAnchor`: "refusing would take device AAA
    down with the broker"), not the revocations file's. A lost revocation would undo a revocation;
    a lost CA key undoes nothing.
- **R5. The previous CA stays trusted until its file is removed.**
  - Its key is deleted at promotion, so nothing new is signed by it. Trusting it once its
    certificates have expired admits nothing.
  - The start says to remove it after `certificate_lifetime` past the promotion.
- **R6. A held certificate the broker refuses is removed.**
  - When the new agent's first refresh is answered `credential_revoked` (a logout, or a mark on the
    certificate), `port49 login` deletes the issued key and certificate, says why, and the next
    login signs in.
  - A logout's record stands on a broker that issues as long as a certificate issued before it can
    be presented (ruling 16; pre-flight 2 C1), so a held certificate is still refused, and removed,
    hours after the logout, not only within `max_token_age`.
  - Kept, the files would start an agent that every request refuses.
- **R7. The issued key is generated in `port49 login`, not the agent,** and handed to the agent
  as today's `--cert` and `--key` are. The agent stays the certificate path's, unchanged but for
  the session end at the certificate's end.
- **R8. The toil check** (Ryan's standing rule, 2026-10-10). The cases weighed: 1,000 devices, 50
  operators, a new hire, a laptop rebuilt, and each CA rotated.
  - **A new user's first login:** `port49 login` and the sign-in. The broker URL, its CA and the
    method come from `/etc/port49/config.yaml`, shipped with the install. No file is written, no
    CA fetched, no directory made or `chmod`ed by the user (Task 11). Before this plan it was four
    keys, a CA file, and `chmod go-w ~/.config` on Ubuntu, per user and per host.
  - **A laptop rebuilt:** the same as a new user. The issued key is not backed up, and need not be:
    a sign-in makes a new one.
  - **The issuing CA rotated:** nothing for users; no client holds it (ruling 14).
  - **The broker's TLS CA rotated:** nothing for users either (ruling 25). The broker sends its CA
    bundle on `/v1/config`; each agent keeps it, and the next login trusts it beside `broker_ca`.
    Config management ships the next CA in `broker_ca` at the rotation's start, so a host away
    through the whole overlap has it on its return; an unmanaged one is told the fix in one line.
  - **A certificate expired or late:** the next `port49 login` signs in and writes over the key and
    certificate; a refused one is removed (R6). No file is handled by hand.
  - **50 operators on 4 jump hosts:** one system file per host, not 200 copies of five values.
- **R9. What the system file holds, and what it does not.**
  - **It holds** what only the install knows: `broker`, `broker_ca`, `method`, and where needed
    `oidc_issuer` and `oidc_ca`.
  - **It does not hold** the client id or the certificate's lifetime, which the brief listed. The
    broker already says both at each sign-in (`/v1/config`'s `oidc` and `issuance`), so a copy on
    every host could only drift from them. That is a toil the rule removes.
  - **Plan 9a's file moves alone.** The refusal says `mv <old>/config.yaml ~/.port49/config.yaml`,
    not `mv ~/.config/port49 ~/.port49` as the brief had it. The pins file stays in 9a's directory
    until 9d, and moving the whole directory would leave `port49 ssh` with no pins.
  - **Root alone** may own the system file: it names the broker for every user on the host. A
    directory above it is held to ruling 6's walk, as every config file is.
- **R10. The CA bundle is kept per broker** (ruling 25), in `~/.port49/broker_ca/<host>_<port>.pem`
  rather than one `~/.port49/broker_ca.pem` as the brief had it: a person who uses two brokers
  would otherwise trust each broker's CAs for the other.

## What carries over from the superseded draft

- **Kept:** the oidctest authorization server (trimmed), `oidc.ReadIDToken`, `oidc.ReadDiscovery`,
  `oidcclient.Discover`, the code exchange, `AuthorizationURL`, `Login` with its listener, paste
  and `ErrNoWayBack` (P5), `browserCommand`, `pickProvider`, `fetchBrokerConfig`, `warnSkew`, the
  config keys, `hardenAgent` with `TestMain`'s no-op (C1), the principal printed at login (I4),
  L55's redirect, PKCE and `iss` cells with their control (P10), and L56's raw-output leak check,
  its printed-by-design allow list, and a control beside every assertion (I5, I6).
- **Dropped:** the agent's OIDC session (`internal/agent/oidc.go`, `oidcrefresh.go`), the ID token
  as bearer, the refresh-token grant (`Renew`, `RefusedError`, `ErrSessionEnded`), the 401
  renew-and-resend, `max_token_age_seconds`, the browser refresh, the socket's
  `/oidc/challenge` and `/oidc/refresh`, and the codes `id_token_not_renewed`, `browser_required`
  and `not_oidc`. L55's refresh-token and session-limit cells go too: no refresh token is used.
- **Changed:** `harden` now fails open with a line on every agent. The key is a file the user
  reads already, so a dumpable agent exposes nothing new; non-dumpable keeps it out of core files
  and crash reporters.

## What this plan does not do

- **One new reason code, `certificate_issued`, and one new event, `issue`.** Task 1 writes them
  into §5.7 before any code reads them. Every refusal reuses an existing reason:
  `trust_domain_unresolved`, `identity_unmapped`, `credential_revoked`, `store_unavailable`.
- **New API codes:** `404 not_issuing`, `503 issuance_unavailable`, `401 sign_in_not_fresh`,
  `401 sign_in_not_bound`, `401 sign_in_spent`. Task 1 adds them to design §17.
- **One new endpoint,** `POST /v1/certificate`. `/v1/config` gains `issuance`.
- **No hardware key** (9c), **no `per_login_mfa`** (9c), **no password sign-in** (9e), **no device
  authorization grant**, and **no ID or refresh token held by the agent or written to disk.**
- **No CRL or OCSP for issued certificates.** The broker trusts its own CA, no device sees the
  certificate, and the short lifetime and the marks are the revocation.
- **No cross-replica check that brokers on one store share the issuing CA.** Each start prints its
  CA's fingerprint, and a mismatched replica refuses the others' certificates at the handshake.
  The check is carried to plan 12 (deployment).
- **No hosted provider.** L47 stays open and unassigned. The operator notes say "measured on
  Keycloak".
- **No claim about Keycloak before L55 closes:** which redirect registration admits an ephemeral
  port, and whether it enforces PKCE.
- **No fix for `port49 ssh` on a group-writable `~/.config`** (pre-flight 2 m5; carried to 9d). The
  pins file stays in 9a's `~/.config/port49/known_hosts` until 9d (R9), read through ruling 6's
  walk, and a refusal no longer names a `chmod` on a directory (ruling 24). So where `~/.config` is
  group-writable, Ubuntu's default 0775, `port49 ssh` and `port49 devices trust` are refused with
  no fix to run. Both rules stand; 9d removes the pins file, which ends it, and nothing ships
  between 9b and 9d. The PR body lists it under known limitations.

## What the operator sees

Every line below is printed by a task in this plan, and the tests named pin it.

- **`port49 login --oidc` on a desktop** (Task 10, `TestLoginOIDCIssuesACertificateAndMints`):

  ```
  port49: sign in at https://kc.example.com/realms/corp in the browser that opened; if none did, open this address:
    https://kc.example.com/realms/corp/protocol/openid-connect/auth?client_id=port49-cli&code_challenge=…&prompt=login&…
  port49: signed in at https://kc.example.com/realms/corp as user:alice@example.com; your certificate from https://port49-broker.example.com:8443 is valid until 2026-10-10T21:00:00Z
  port49: logged in to https://port49-broker.example.com:8443; the session ends at 2026-10-10T21:00:00Z (agent pid 4242, log /run/user/1000/port49/agent.log)
  refreshed at 2026-10-10T09:00:04Z; this login lasts until 2026-10-10T21:00:00Z
    leaf1 (alice)  extended to 2026-10-10T21:00:04Z
  ```

  The principal is the check a person makes (I4): a sign-in finished with someone else's answer
  names someone else. The refresh after the start is D1's answer: a key signature, no second
  password.
- **A login over a held certificate** (Task 10, `TestALoginOverAHeldCertificateSignsInNoMore`):

  ```
  port49: using your certificate for user:alice@example.com (signed in at https://kc.example.com/realms/corp at 2026-10-10T09:00:00Z), valid until 2026-10-10T21:00:00Z; `port49 login --sign-in` signs in again
  port49: logged in to https://port49-broker.example.com:8443; the session ends at 2026-10-10T21:00:00Z (agent pid 5150, log /run/user/1000/port49/agent.log)
  refreshed at 2026-10-10T13:12:40Z; this login lasts until 2026-10-10T21:00:00Z
    leaf1 (alice)  extended to 2026-10-11T01:12:40Z
  ```
- **On a jump host with no display** (Task 10, `TestLoginOIDCWithAPastedAddress`):

  ```
  port49: open this address in a browser and sign in at https://kc.example.com/realms/corp:
    https://kc.example.com/realms/corp/protocol/openid-connect/auth?…
  port49: waiting up to 5m0s. If the browser ends on a page that cannot be reached (it runs on another host), copy that page's address and paste it here (it is not shown), then press Enter:
  ```
- **No browser and no terminal** (Task 10, `TestLoginOIDCWithNoWayBackSaysSoAtOnce`), exit 1 at once:

  ```
  port49 login: no browser opened on this host and stdin is not a terminal to paste the address into, so the sign-in's answer has no way back to port49; run the command in a terminal (ssh -t), or log in with --redirect-port N and forward that port to this host (ssh -L N:127.0.0.1:N)
  ```
- **The provider down, a held certificate late but valid** (Task 10,
  `TestAProviderOutageUsesAHeldCertificate`), exit 0:

  ```
  port49 login: your identity provider at https://kc.example.com/realms/corp did not answer: Get "https://kc.example.com/realms/corp/.well-known/openid-configuration": dial tcp 10.0.0.5:443: connect: connection refused; port49 cannot sign you in until it answers (anyone already logged in keeps working: a certificate port49 issued needs no identity provider)
  port49 login: using your certificate for user:alice@example.com, valid until 2026-10-10T21:00:00Z, until your identity provider answers
  ```
- **The provider down, no certificate** (Task 10, `TestAProviderOutageWithNoCertificateSaysSo`):
  the first line above, and exit 1.
- **The broker's CA key missing** (Task 8, `TestABrokerWithNoIssuingCAStartsAndSaysSo`), on the
  broker's start:

  ```
  port49-broker: issuance: issuing-ca.pem is missing, so no certificate is issued and none it issued is trusted: on a first install run init-issuer once, as the broker's user; on each further broker on this store, copy issuing-ca.pem and issuing-ca.key from the first into its broker.state_dir
  port49-broker: issuance: certificates of 12h0m0s over an OIDC sign-in, from the issuing CA in /var/lib/port49-broker
  ```

  and at a sign-in (Task 7, `TestIssuanceUnavailableSaysSo`):

  ```
  port49 login: the broker did not issue your certificate: this broker cannot issue certificates now: its issuing CA is not usable; tell its operator (the broker's log says why) (issuance_unavailable)
  ```
- **A back-channel logout** (Tasks 6 and 10). On the next mint, the broker's words (plan 7h):

  ```
  port49 token: the session is over: your identity provider ended this session at 2026-10-10T15:00:00Z (back-channel logout); log in again
  ```

  and a login over that certificate (`TestARevokedHeldCertificateIsRemoved`), exit 1:

  ```
  port49 login: the broker refused your certificate: your identity provider ended this session at 2026-10-10T15:00:00Z (back-channel logout); log in again; it is removed, so `port49 login` signs you in again
  ```
- **The certificate's end** (Tasks 9 and 10: the session's end, and `agentMain`'s line), in the
  agent's log:

  ```
  port49 agent: your certificate ended at 2026-10-10T21:00:00Z, and the session with it; exiting - run `port49 login` (for a certificate port49 issued, it signs you in again)
  ```
- **A person's ID token sent to a broker that issues** (Task 6), 401:

  ```
  trust_domain_unresolved: this broker takes a person's ID token at POST /v1/certificate alone, which exchanges it for a short-lived certificate; run `port49 login` (spec §13 decision 43 ruling 13)
  ```
- **A new user on a host the install set up** (Task 11, `TestTheSystemFileAloneIsAFirstLogin`):
  `port49 login`, with no flag and no file of their own, prints the desktop sign-in above.
- **A config file left at plan 9a's place** (Task 11, `TestAConfigFileAtPlan9asPlaceIsRefused`),
  exit 2:

  ```
  port49 login: /home/alice/.config/port49/config.yaml is where plan 9a kept port49's config file; port49 reads /home/alice/.port49/config.yaml now: mkdir -m 700 -p /home/alice/.port49 && mv /home/alice/.config/port49/config.yaml /home/alice/.port49/config.yaml
  ```
- **A system file that is not root's** (Task 11, `TestASystemFileNotRootsIsRefused`), exit 2:

  ```
  port49 login: /etc/port49/config.yaml is not owned by root; the system port49 config file names the broker for every user on this host, so it is root's alone: chown root /etc/port49/config.yaml
  ```
- **A host away through a whole rotation of the broker's CA** (Task 11,
  `TestTheAgentSaysWhyTheBrokerDoesNotVerify`), in the agent's log the login prints, exit 1:

  ```
  port49 agent: the broker's certificate at https://port49-broker.example.com:8443 does not verify (x509: certificate signed by unknown authority); check that the trust anchor (--broker-ca) is the CA that issued it, and that the broker URL is a name the certificate carries; if the broker's operator rotated its CA while this host was away, get the broker's CA from them and run `port49 login --broker-ca FILE` once; port49 keeps it current from then on
  ```
- **The agent keeping a new CA bundle** (Task 11, `TestTheAgentKeepsTheBrokersCABundle`), in its
  log:

  ```
  port49 agent: kept the broker's CA bundle in /home/alice/.port49/broker_ca/port49-broker.example.com_8443.pem: sha256:3f…, sha256:9c… (was sha256:3f…)
  ```
- **A broker that sends no CA bundle** (Task 11, `TestABrokerWithNoBundleClearsTheKeptOne`), in the
  agent's log, where the kept file held a CA beside the one the connection was verified to:

  ```
  port49 agent: the broker sends no CA bundle; /home/alice/.port49/broker_ca/port49-broker.example.com_8443.pem now holds only the CA this connection was verified to: sha256:9c… (was sha256:3f…, sha256:9c…)
  ```

  and, where it did not hold that CA: `port49 agent: the broker sends no CA bundle; removed … (it
  held …)`. A broker that refused its own bundle at start leaves the kept file as it was:

  ```
  port49 agent: the broker refused its own tls_ca_bundle_file at start (its log says why), so it sends no CA bundle; /home/alice/.port49/broker_ca/port49-broker.example.com_8443.pem is left as it was
  ```
- **The broker's start with a bundle** (Task 8, `TestLoadCABundle`):

  ```
  port49-broker: broker: tls_ca_bundle_file /etc/port49-broker/ca-bundle.pem, sent to every client: sha256:3f…, sha256:9c…
  ```

  and with one that does not hold the server certificate's CA:

  ```
  port49-broker: broker: tls_ca_bundle_file /etc/port49-broker/ca-bundle.pem: it does not hold the CA of the server certificate in tls_cert_file (x509: certificate signed by unknown authority); no CA bundle is sent, so clients keep the CAs they hold
  ```
- **A directory above a config file that others can write** (Task 11), exit 2, with no `chmod`
  suggested for a directory that may be shared:

  ```
  port49 login: /srv/shared is writable by others (mode -rwxrwxr-x); whoever can write the directory holding the port49 config file chooses what port49 trusts, so port49 needs it writable by its owner alone (mode 0755 or 0700)
  ```

## Operator notes

These are for the PR body and plan 13's operator guide. Plan 13 owns the guide. Every line is
pinned by a test or a lab row. A line in *italics* rests on an open lab row and is restated when it
closes.

- **Turn issuance on** with `broker.identity.issuance: {}` (default `certificate_lifetime: 12h`;
  1h to 24h). It needs a human `oidc` verifier: a certificate is issued over a sign-in at it.
- **Make the issuing CA once per install:** `port49d init-issuer` (or `port49-broker init-issuer`),
  run as the broker's user. It writes `issuing-ca.pem` and `issuing-ca.key` (0600) into the
  broker's state directory. On every further broker on the same store, copy both files into its
  `broker.state_dir`, then restart. Each start prints the CA's fingerprint: compare them across
  brokers. A broker with another CA refuses the others' certificates at the handshake.
- **If the key is missing or unreadable,** the broker starts and serves everything else; only
  sign-ins fail (503 `issuance_unavailable`), and its start line says what to run. Alert on
  `port49_certificates_issued_total{outcome="unavailable"}` and on
  `port49_issuing_ca_not_after_timestamp_seconds` (0, or within 90 days).
- **Rotate with overlap,** running `rotate-issuer` on one broker throughout:
  1. `rotate-issuer` stages `issuing-ca-next.pem` and its key. Copy `issuing-ca-next.pem` alone to
     every other broker, and restart every broker: each now trusts it. The key stays where it was
     made.
  2. `rotate-issuer` again, on the same broker, promotes it. The old CA becomes
     `issuing-ca-previous.pem` and its key is overwritten. Copy `issuing-ca.pem`, `issuing-ca.key`
     and `issuing-ca-previous.pem` to every other broker, remove the `issuing-ca-next.pem` staged
     there, and restart every broker: each now issues with the new CA and still trusts the old.
  3. After `certificate_lifetime`, every certificate the old CA issued has expired. Remove
     `issuing-ca-previous.pem` and restart. The next rotation's promotion is refused until it is
     gone.
- **Register port49 at your provider as a public client:** no secret, the authorization-code flow,
  PKCE with S256 required. Its client id is the broker verifier's `client_id`.
  - *Its redirect URI: port49 listens on `http://127.0.0.1:<port>/callback`, on a free port each
    time (RFC 8252). Which registration admits that on Keycloak is L55's; until it closes,
    register `http://127.0.0.1:<fixed>/callback` and set `oidc_redirect_port: <fixed>`.*
  - Ask for the claim the broker maps (`email`, say) in the verifier's `scopes`: port49 asks for
    exactly those.
- **Ship `/etc/port49/config.yaml` with the client** (a package, config management or MDM), owned
  by root and writable by root alone, with the broker CA beside it:

  ```yaml
  broker: https://port49-broker.example.com:8443
  broker_ca: broker-ca.pem        # /etc/port49/broker-ca.pem; relative paths are this file's directory's
  method: oidc
  # oidc_issuer: https://kc.example.com/realms/corp   # only when the broker lists several providers
  # oidc_ca: idp-ca.pem                                # only when a private CA issued the provider's TLS
  ```

  A new user then runs `port49 login` and signs in; that is all. Each user's `~/.port49/config.yaml`
  (or the file `$PORT49_CONFIG` names) overrides it key by key, and a flag overrides both. The
  client id, scopes and lifetime come from the broker, and so do the CAs the broker's certificate
  will come from (below), so the system file's `broker_ca` only has to be right at install.
- **`port49 login --oidc`** (or `method: oidc` in a config file) signs in at the provider the broker
  lists, and asks your password and MFA every time (`prompt=login`).
  - It needs `broker` and `broker_ca`, as a certificate login does; the system file gives both.
  - With several providers, name one with `--issuer` or `oidc_issuer`. A provider whose TLS
    certificate a private CA issued needs `oidc_ca` or `--oidc-ca`.
  - The key and certificate are kept in `~/.port49/issued/<broker host>_<port>.key` and
    `.pem`, 0600. The key is your session until the certificate ends: a reboot or a new agent uses
    it with no sign-in, and whoever copies it holds your session until then, so never copy it off
    the host, and exclude `~/.port49/issued/` from home-directory backups (Time Machine, rsync and
    the like): a restore within the certificate's life holds the session. (9c moves it into a TPM,
    the OS keystore or a hardware key where there is one.)
- **Check whom you signed in as.** The login prints `signed in at … as <you>`. The address port49
  prints is not a password, but keep it to yourself: whoever has it can finish your sign-in with
  their own account. On a shared host a browser port49 launches shows that address to other users
  in its command line; there, use `--no-browser`.
- **On a host with no browser,** open the printed address on your laptop, sign in, and paste the
  `127.0.0.1` address the browser fails to load at port49's prompt (it is not shown). With no
  terminal either, use `ssh -t`, or `--redirect-port N` with `ssh -L N:127.0.0.1:N`.
- **After the sign-in, no browser.** `port49 refresh`, `port49 login` with the agent running, and a
  new agent after a reboot all use the key. A new sign-in comes when the certificate has under a
  quarter of its life left, or with `port49 login --sign-in`.
- **When your provider is down,** everyone holding a certificate keeps working until it ends:
  mints, refreshes, and new agents. Only a sign-in fails, and it says so, naming your certificate's
  end when you have one.
- **A back-channel logout** refuses your certificate at its next use, in the broker's words, and
  ends your device sessions as before. Your next `port49 login` removes the certificate and signs
  you in. On a broker that issues, a logout's record is kept `max(max_token_age, 24h) +
  2×clock_skew` (24h being the longest `certificate_lifetime` allowed), so it refuses the
  certificate for as long as the certificate lives, whatever lifetime it was issued with.
- **Configure `issuance` alike on every broker on one store.** A broker without it keeps a
  logout's record for `max_token_age` alone, so a logout it receives stops reaching an issued
  certificate after that.
- **Revoke a person's certificates** with `port49 revoke --principal user:…` (every certificate,
  issued or not), or one with `--cert-issuer DN --cert-serial HEX` from its `issue` record.
- **A person's ID token is refused at a broker that issues,** except at `POST /v1/certificate`. A
  machine's token is unaffected.
- **Rotate the broker's TLS CA with no user action** (decision 43 ruling 25). Set
  `broker.tls_ca_bundle_file` to a PEM file of the CAs clients are to trust for the broker's
  certificate (1 to 4 CAs, at most 64 KiB); every agent keeps it at its start, per broker, in
  `~/.port49/broker_ca/`.
  1. Add the next CA to the bundle and restart every broker. Each start names the bundle's
     fingerprints; a bundle without the CA of the certificate in use, or one that cannot be read,
     is not sent, the start says so, and agents keep the CAs they hold until it is fixed. In the
     same change, ship the current and the next CA together in
     `/etc/port49/broker-ca.pem` through the install's config management (package, config
     management or MDM), so a host away has both on its return.
  2. Wait while people log in: every agent that starts keeps the new bundle (its log says
     `kept the broker's CA bundle`). A day covers everyone who works daily; wait longer for
     people away.
  3. Switch `tls_cert_file` to a certificate the next CA issued, and restart.
  4. Drop the old CA from the bundle and from `/etc/port49/broker-ca.pem`, through config
     management again.
  - **Rotating because the old CA is compromised:** push the new `/etc/port49/broker-ca.pem`
    through config management at once. The bundle adds trust and never removes it, so the old CA
    stays trusted wherever `broker_ca` still holds it.
  - **Removing `tls_ca_bundle_file`** once a rotation is done is safe: each agent's next start,
    told no bundle, cuts what it kept to the CA its connection was verified to, or removes it.
    That is also the remedy if the broker's server key was ever taken: a bundle the taker sent is
    gone at each agent's next start against the real broker.
  - **An unmanaged host away for the whole overlap** gets one line naming the fix: get the broker's
    current CA and run `port49 login --broker-ca FILE` once; port49 keeps it current from then on.

## Global Constraints

- Go 1.26+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, **no cgo**, **no new
  module in the build graph**: `go.mod` and `go.sum` are unchanged.
- snake_case everywhere it is data: `certificate_lifetime`, `issuance`,
  `certificate_lifetime_seconds`, `csr`, `certificate`, `principal`, `serial`, `not_after`,
  `fingerprint`, `method`, `oidc_issuer`, `oidc_ca`, `oidc_redirect_port`, and the metrics
  `port49_certificates_issued_total{outcome}` and
  `port49_issuing_ca_not_after_timestamp_seconds`.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). **This plan adds
  `certificate_issued` only, after Task 1 writes it into §5.7.**
- **No ID token, code, verifier, private key or CSR signature is logged or printed.**
  - The authorization URL is printed on the operator's terminal and passed to the browser
    launcher. It carries `state`, the `nonce` (the key's hash) and the `code_challenge`, which the
    browser must carry to the provider. It is not a credential, but its `state` must not leave this
    user (I4). So the login prints the principal it was issued for.
  - The ID token goes to the broker in an `Authorization` header over TLS, never in a URL, argv or
    the environment, and is never written.
  - The key is written once, 0600, through `userconfig.WritePrivate`, and read through
    `keyfile.LoadX509KeyPair`.
  - The broker's refusals and log lines name the provider, the principal and the reason, never a
    token or a body.
  - Every test that runs a sign-in asserts that stdout, stderr and the agent's log hold none of
    `AuthServer.Issued()`, no `code_verifier` of `AuthServer.Grants()`, and none of the key's PEM.
- No device identity and no principal in a metric label.
- **Fail closed, never widen.** Each of these is a refusal:
  - a callback whose `iss` names another issuer, or with no `iss` from a provider that promised
    one;
  - a provider that offers PKCE methods without S256;
  - an ID token whose `nonce`, `iss`, `aud` or `azp` is not this sign-in's;
  - at issuance: a token whose `nonce` does not name the CSR's key, an `auth_time` over 5 minutes
    old, a token used twice, a CSR whose signature is not its key's, a key that is not ECDSA
    P-256/P-384, Ed25519 or RSA 2048–8192;
  - a certificate whose chains end at the issuing CA and at another anchor;
  - an issued certificate whose sign-in names an issuer or a principal domain no human verifier
    takes now;
  - an issued certificate whose sign-in a logout ended.
- **Never refuse a start over the issuing CA** (R4): issuance stops, and the start says why.
- **The lab register rules** (CLAUDE.md 1–4). Task 1 rewords L55 and L56, and Task 12 measures
  them. Until L55 closes, no doc says which redirect registration Keycloak accepts or that it
  enforces PKCE.
- Verify with `make test && make vet`, and `make test-race` on every touched package, and report
  the real output.
- Conventional Commits, on branch `feature/oidc-public-client`. Commit messages end with:

  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```
- Implementers never run `git checkout`, `restore`, `reset`, `stash` or `clean`.

## Review Focus

The five inputs or conditions most likely to bite a person, and the test that pins each:

1. **The identity provider is down at 3am.**
   - **Expected:** an agent running keeps minting and refreshing; a new agent over a held
     certificate starts with no sign-in; `port49 login` with a late held certificate uses it and
     says so; only a sign-in with nothing held fails, at once, saying the provider did not answer
     and that people already logged in are unaffected.
   - **Pinned by** Task 10's `TestAProviderOutageUsesAHeldCertificate` and
     `TestAProviderOutageWithNoCertificateSaysSo`, and L56 cell 6.
2. **The broker's issuing CA is missing or unreadable at start.**
   - **Expected:** the broker starts and serves mints, refreshes and logouts; a sign-in's exchange
     is 503 `issuance_unavailable` with no record; the start line names the file and the command.
     A missing CA certificate refuses issued certificates at the handshake, said at start too.
   - **Pinned by** Task 5's `TestLoadSaysWhatIsMissing`, Task 7's `TestIssuanceUnavailableSaysSo`,
     Task 8's `TestABrokerWithNoIssuingCAStartsAndSaysSo`, and L56 cell 0.
3. **A back-channel logout after the certificate was issued.**
   - **Expected:** the next mint and the next refresh on that certificate are refused
     `credential_revoked` in the broker's logout words; its device sessions are revoked through
     the `sid` index; the agent ends; the next `port49 login` removes the certificate and the one
     after signs in.
   - **Expected, past `max_token_age`:** the logout still refuses the certificate, for as long as the
     certificate lives; its record stands `max(max_token_age, 24h) + 2×clock_skew`, 24h being
     `issuer.MaxLifetime`, so a `certificate_lifetime` lowered since changes nothing.
   - **Pinned by** Task 6's `TestALogoutRefusesAnIssuedCertificate` and
     `TestALogoutReachesAnIssuedCertificatesContexts`, Task 7's
     `TestALogoutOutlivesMaxTokenAgeForAnIssuedCertificate`, Task 10's
     `TestARevokedHeldCertificateIsRemoved`, and L56 cell 5.
4. **A stolen ID token, a replay, or a leaked authorization URL.**
   - **Expected:** a token whose `nonce` names another key is refused `sign_in_not_bound`; a token
     used twice is refused `sign_in_spent`; one whose `auth_time` is stale is refused
     `sign_in_not_fresh`; a sign-in someone else finished from a leaked URL cannot be told apart
     here, so the login names the principal.
   - **Pinned by** Task 7's `TestATokenForAnotherKeyIsRefused`, `TestASignInIsExchangedOnce` and
     `TestAStaleSignInIsRefused`, and Task 10's `TestLoginOIDCIssuesACertificateAndMints`.
5. **Time: a certificate ending, or a laptop clock off the broker's.**
   - **Expected:** the agent exits at the certificate's end when that is sooner, saying to log in,
     and a request past it is refused as an expired certificate's; a held certificate the broker
     refuses at the handshake (its clock past the end) says to run `port49 login --sign-in`; a host
     clock more than 5 minutes off the provider's is warned, never refused.
   - **Pinned by** Task 9's `TestCertificateEndIsTheCertificatesNotAfter` (and the agent's
     existing `TestAHangUpWithAnExpiredCertificateEndsTheSession`), Task 10's
     `TestABrokerThatRefusesAHeldCertificateSaysToSignIn` and
     `TestASkewedClockIsWarnedNotRefused`.

## Conflict scan: where tasks share a file or an interface

- **`internal/oidc`:** Task 3 adds `client.go`; Task 8 edits `config.go` (`Issuance`).
  **`internal/oidc/oidctest`:** Task 2 adds `authserver.go` and edits `issuer.go`.
- **`internal/oidcclient`:** Task 3 creates it (`oidcclient.go`, `request.go`); Task 4 adds
  `login.go`.
- **`internal/issuer` and `internal/broker/api/issue.go`:** Task 5 alone.
- **`internal/broker`:** Task 6 edits `broker.go`, `workload.go`, `server.go`, `listen.go`,
  `certcheck.go` and `sessionrefresh.go`, and creates `issued.go` and `issued_test.go` (whose
  fixture helpers Task 7's tests use). Task 7 creates `issue.go` and `issue_test.go`, and edits
  `broker.go` again (`Handler`, `config`, the `CertificateLifetime` field). Task 7 starts after
  Task 6 is committed.
- **`internal/decision` and `internal/daemon/metrics`:** Task 7 alone.
- **`internal/config`, `internal/port49d`:** Task 8 alone. Task 8 also edits
  `internal/broker/api/api.go` and `internal/broker/broker.go` (the CA bundle) after Task 7.
- **`internal/agent`:** Task 9, then Task 11 (`BrokerRoot`, the rotation's hint).
- **`internal/userconfig`, `cmd/port49`:** Task 10, then Task 11 (`~/.port49`, the system file),
  which edits the same `Load`, `fill` and `TestMain` after Task 10 is committed. Task 11 also edits
  `internal/hostkeys/hostkeys.go` (`Path`), `cmd/port49/trust_hint_test.go`, `login_linux_test.go`
  and `issue.go`, and creates `cmd/port49/cabundle.go`.
- **The spec and the design:** Task 1 writes them. Task 12 closes L55 and L56 and fixes any text
  their results contradict.
- **`tests/lab/`, `Makefile`, `tests/lab/README.md`:** Task 12 alone.

Task 2 needs Task 1. Tasks 3 and 4 run in order after 2. Task 5 needs 1. Task 6 needs 5. Task 7
needs 6. Task 8 needs 7. Task 9 needs 1. Task 10 needs 4, 7 and 9. Task 11 needs 10. Task 12
needs 1–11. Task 13 is last.

## File Structure

**Create:**
- `internal/oidc/client.go`, `client_test.go`.
- `internal/oidc/oidctest/authserver.go`, `authserver_test.go`.
- `internal/oidcclient/oidcclient.go`, `request.go`, `oidcclient_test.go`, `login.go`,
  `login_test.go`.
- `internal/issuer/issuer.go`, `signin.go`, `issuer_test.go`.
- `internal/broker/api/issue.go`, `issue_test.go`.
- `internal/broker/issued.go`, `issued_test.go`, `issue.go`, `issue_test.go`.
- `internal/port49d/issuer.go`, `issuer_test.go`.
- `internal/broker/api/cabundle.go`, `cabundle_test.go`; `internal/broker/cabundle_test.go`;
  `internal/port49d/cabundle.go`, `cabundle_test.go` (Task 8).
- `cmd/port49/cabundle.go`, `cabundle_test.go` (Task 11).
- `cmd/port49/issue.go`, `issue_test.go`, `issue_login_linux_test.go`, `harden_linux.go`,
  `harden_darwin.go`, `harden_other.go`.
- `tests/lab/l55_test.go`, `l56_test.go`, `l55_l56_unit_test.go`.
- `tests/lab/results/L55-keycloak.md` and `tests/lab/results/L56-arista_eos.md`, written by the run,
  with their evidence.

**Modify:**
- `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md` (Task
  1; Task 12 closes L55 and L56).
- `internal/oidc/oidctest/issuer.go` (Task 2); `internal/oidc/config.go` (Task 8).
- `internal/broker/api/api.go` (Task 5).
- `internal/broker/broker.go`, `workload.go`, `server.go`, `listen.go`, `certcheck.go`,
  `sessionrefresh.go` (Tasks 6 and 7).
- `internal/decision/log.go`, `reasons.go`, `reasons_test.go`; `internal/daemon/metrics/metrics.go`
  (Task 7).
- `internal/config/identity.go`, `identity_test.go`; `internal/port49d/main.go`, `brokerd.go`
  (Task 8).
- `internal/agent/agent.go`, `agent_test.go` (Task 9).
- `internal/userconfig/userconfig.go`, `userconfig_test.go`; `cmd/port49/main.go`, `main_test.go`,
  `config_test.go` (Task 10; Task 11 again, with `issue_login_linux_test.go` and
  `trust_hint_test.go`).
- `internal/hostkeys/hostkeys.go` (Task 11).
- `internal/broker/api/api.go`, `internal/broker/broker.go`, `internal/config/config.go` (Task 8, the
  CA bundle); `internal/agent/agent.go`, `cmd/port49/issue.go`, `login_linux_test.go` (Task 11).
- `Makefile` (`lab-oidc-l55`, `lab-oidc-agent`), `tests/lab/README.md` (Task 12).
- `docs/superpowers/plans/README.md` (Task 13).

---

### Task 1: The spec says what plan 9b builds: decision 43, §2, §5.1.4, §5.6, §5.7, §12, §14, L55 and L56

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2 (the principal table);
  - §5.1.4 (after "Certificate `notAfter` and the OIDC `exp` are deliberately absent");
  - §5.6 (after the OIDC refresh as built);
  - §5.7 (the events table and count, the reason table);
  - §12 (`port49 refresh`, `port49 login`);
  - §13: decision 39 rulings 15 and 16, decision 42 ruling 6, and decision 43 (new);
  - §14 (a new bullet);
  - §15 (L55, L56).
- Modify: `docs/design/2026-08-21-port49-design.md`: §7, §8, §17 (Surface, Errors, Client
  libraries), §19.

**Interfaces:**
- Consumes: the rulings R1–R7 and Q1–Q3 above.
- Produces: decision 43, rulings 1–25, which every later task cites; the `issue` event and the
  `certificate_issued` reason, which Task 7 builds; L55 and L56, which Task 12 measures.

This task is docs only. Each step is an edit with the exact text. Where a step says "replace", the
old text is quoted and appears once; check with `grep -n` before editing.

- [ ] **Step 1: Decision 43, after decision 42**

Find the end of decision 42 with `grep -n "address for the one connection (Task 7)\.$"
docs/design/2026-08-23-policy-engine-spec.md`. That line ends decision 42; a blank line and `---`
follow it. Between that line and the blank line, insert a blank line and:

```markdown
**43. The agent in full, second part: port49-issued user certificates over an OIDC sign-in.**
*Plan 9b, 2026-10-10, on Ryan's direction of that day: design §7's "the broker MAY issue a
short-lived client certificate", made v1.* Rulings rest on reasoning unless they say data. Rulings
4 and 8 are provisional on L55 (Keycloak) and L47 (hosted providers, open). Q1–Q3 (rulings 13, 9 and
12) were ruled as recommended on 2026-10-10 by the controller under Ryan's standing grant: a
person's bearer outside `/v1/certificate` retires at the pre-beta review, not now; the lifetime is
broker config, 12h, 1h–24h, per role later if asked; a new agent reuses the held key and
certificate while the certificate is valid.

- **1. The flow** (data: RFC 6749 §4.1, RFC 7636, RFC 8252, OIDC Core §3.1).
  - **What it is.** The authorization-code flow with PKCE, `S256` only, as a public client with no
    client secret.
  - **Where it runs.** `port49 login` runs it in its own process, never in the agent, which never
    listens on a TCP port and never holds an ID token.
  - **The provider's PKCE.** A provider whose discovery lists `code_challenge_methods_supported`
    without `S256` is refused. One that lists none is used, with `S256` sent; whether Keycloak
    enforces it is L55's.
- **2. The provider** (data: OIDC Discovery §4).
  - **Which one.** The one `/v1/config`'s `oidc` lists, or the one `--issuer` or `oidc_issuer`
    names exactly. None listed is "this broker takes no OIDC login". Several and none named is a
    refusal that lists them.
  - **Its discovery document.** `issuer` must equal the configured issuer. `authorization_endpoint`
    and `token_endpoint` must be `https` URLs with a host and no credentials. Each member is read
    by its exact name.
  - **Reaching it.** No redirect is followed. `HTTPS_PROXY` is honoured, as the broker's key fetch
    honours it (decision 39 ruling 4). TLS is against `oidc_ca`, else the system's roots. The
    broker is never reached through a proxy.
- **3. The request.** It carries:
  - `response_type=code`, `client_id`, and `redirect_uri`;
  - `scope`: the verifier's scopes, `openid` first;
  - `state`: 32 random bytes;
  - `nonce`: the key binding, `base64url(SHA-256("port49 issue v1\0" ‖ PKIX(the new key)))`
    (`api.IssuanceNonce`), so the ID token names the one key it may be exchanged for;
  - `code_challenge`: S256 of a 32-byte verifier;
  - `prompt=login`: a sign-in is a fresh authentication.
- **4. The redirect** (data: RFC 8252 §7.3, RFC 9207; provisional on L55).
  - **The listener.** `http://127.0.0.1:<port>/callback`, on a listener bound to `127.0.0.1`
    alone. The port is ephemeral, or `oidc_redirect_port` for a provider that registers one. It
    answers `GET /callback` and nothing else.
  - **Another `state`.** An answer that does not carry this sign-in's `state` is answered 400 and
    waited past: anyone on the host can reach the port.
  - **This sign-in's answer.** The first answer carrying the `state` ends the wait. Its `iss`, when
    present, must be the issuer, and is required when discovery says the provider sends it. An
    `error` ends the sign-in with the provider's code.
  - **The page.** It holds no token, with `Cache-Control: no-store` and `Referrer-Policy:
    no-referrer`.
  - **The wait.** 5 minutes.
- **5. No browser.**
  - **When one is launched.** `$BROWSER` when set. On Linux, `xdg-open` only with `DISPLAY` or
    `WAYLAND_DISPLAY` set. On macOS, `open` outside an SSH session. `--no-browser` launches none.
    The authorization URL is always printed on stderr.
  - **The paste.** When stdin is a terminal, the address the browser ended on may be pasted back,
    and is not echoed.
  - **No way back.** With no browser opened, no terminal, and an ephemeral port, that is said at
    once, naming `ssh -t`, or a fixed port forwarded with `ssh -L`. With a fixed port the sign-in
    waits, and says how to forward it.
  - **No device grant.** The device authorization grant (RFC 8628) is not built: the paste covers
    the browser-less host with every property of the loopback flow; its user code is a phishing
    route (RFC 8628 §5.4); and a provider must enable it per client.
- **6. The exchange and the ID token, as the client reads it** (data: OIDC Core §3.1.3.7).
  - **The exchange.** The token endpoint, form-encoded, with `code_verifier` and no secret. A
    refresh token in the answer is dropped unread.
  - **What the client reads:** a compact JWS whose `alg` decision 39 ruling 3 accepts; `iss` exact;
    `aud` naming `client_id` and `azp` as decision 39 ruling 2 reads it; `nonce` equal to the
    request's; `sub`, `iat`, `exp` and `auth_time` present, `iat` no later than `exp`; every claim
    by its exact name.
  - **No signature check here, and no clock.** It came from the token endpoint over TLS (item 6),
    and the broker verifies it. A skew over 5 minutes between `iat` and this host's clock is
    warned, never refused.
- **7. The key.** `port49 login` generates an ECDSA P-256 key for each sign-in. Plan 9b keeps it
  in a file, `~/.port49/issued/<broker host>_<port>.key`, written 0600 through
  `userconfig.WritePrivate`, beside the certificate (`.pem`). Plan 9c generates it in a TPM, the
  Secure Enclave or a token behind the same `crypto.Signer`. It never leaves the host; the broker
  sees its public key, in a CSR whose signature proves it.
- **8. The exchange for a certificate:** `POST /v1/certificate`, the ID token as the bearer, `{csr}`
  base64url DER as the body, no client certificate. The broker refuses, recording each refusal as an
  `issue` deny:
  - a token any of decision 39 rulings 2–6 refuses, a marked principal, or a logged-out session,
    as a mint is refused;
  - a machine's token (400);
  - a sign-in that is not fresh, `401 sign_in_not_fresh`, `trust_domain_unresolved`, judged on two
    clocks: an `auth_time` more than 5 minutes (plus `clock_skew`) before the token's `iat`, the
    provider's own clock, which catches a provider that ignored `prompt=login` (provisional on
    L55); an `iat` more than that before the broker's now, a slow sign-in or two clocks apart, said
    as such; or an `auth_time` after the `iat` plus `clock_skew`. 5 minutes is the sign-in's own
    wait;
  - a CSR that does not parse, whose signature is not its key's, or whose key is not ECDSA
    P-256/P-384, Ed25519 or RSA 2048–8192 (400);
  - a `nonce` that is not `api.IssuanceNonce` of the CSR's key: `401 sign_in_not_bound`;
  - a token exchanged already (the store keeps its SHA-256 for `max_token_age`): `401
    sign_in_spent`.

  Then it writes the owner record (decision 39 ruling 11), issues, and records an `issue` permit
  `certificate_issued` with the certificate's serial, issuer, fingerprint and end. A broker whose
  CA cannot issue answers `503 issuance_unavailable`, Retry-After 60, with no record: the fault is
  the broker's, and its start and its process log say which. A broker with no `issuance` answers
  `404 not_issuing`.
- **9. The certificate** (Q2).
  - Signed by the broker's issuing CA; serial 128 random bits; valid from a minute before issue for
    `broker.identity.issuance.certificate_lifetime` (default 12h, 1h–24h), never past the CA's end.
  - Subject CN the principal the human verifier gave; one URI SAN,
    `port49-sign-in:v1?iss=…&sub=…&sid=…&auth_time=…&iat=…&amr=…&acr=…`, carrying the sign-in, so
    the `sid` is bound to the serial under the CA's signature (R1); `clientAuth`; no email or DNS
    SAN.
  - A per-role lifetime is not built: no policy value varies by role yet, and plan 9c's
    `per_login_mfa` is where per-device strength arrives.
- **10. The broker trusts its own certificates, for people alone.**
  - Its issuing CAs (current, next, previous) join the handshake's pool. A chain ending at one of
    them is the `humans` domain; one ending there and at another anchor is refused.
  - The principal is the certificate's CN, never mapped through the directory (membership is still
    read at mint, as for an OIDC principal). The sign-in must still name an issuer whose human
    verifier's `principal_domains` hold the principal, or it is refused `trust_domain_unresolved`:
    a provider removed from the configuration takes its people's certificates with it.
  - `certificate_status` is not asked: the broker's marks are such a certificate's status.
  - The credential is `{method: cert, fingerprint, issuer, serial, subject, iss, sub, sid, amr,
    acr}`: a mint indexes its contexts under the certificate and the `sid`, and its records carry
    `auth.oidc`.
- **11. `auth_time`, `session_expires`, and the fresh authentication event** (decision 17;
  dissolves plan 9b's pre-flight D1).
  - The session is the held connection, as on every certificate path: `auth_time` is when the
    broker accepted the handshake, or verified a refresh's signature, and `session_expires =
    auth_time + max_session_age` (§5.6).
  - The provider's `auth_time` bounds issuance alone (ruling 8), and is recorded as
    `auth.oidc.auth_time` on every record the certificate makes.
  - A key signature on a port49-issued certificate is a fresh authentication event exactly as one
    on any certificate is, while the certificate is valid. Against today's file-key certificate
    path it is the same proof, possession of a key in a 0600 file, with a key at most
    `certificate_lifetime` old, generated at a sign-in that was itself a fresh authentication. Plan
    9c's hardware key adds presence, and its `per_login_mfa` adds a proof per login to the devices
    a policy level marks.
  - `notAfter` bounds the mint and the refresh, never a device session (§5.1.4). So one sign-in
    gives at most `certificate_lifetime` of mints and refreshes, and the device sessions a last
    refresh extended run to their own ceilings.
  - So a new agent refreshes once at login, as on the certificate path, and `port49 refresh` is a
    key signature with no browser.
- **12. `port49 login` on the OIDC path** (Q3).
  - **A held certificate** for this broker, valid, readable through `keyfile`, carrying a sign-in,
    and with more than a quarter of its life left (`api.LateRenewal`), is used with no sign-in and
    said. `--sign-in` forces a sign-in.
  - **Otherwise** it signs in, generates a key, asks `/v1/certificate`, writes the key and then the
    certificate, and prints whom it signed in as and the certificate's end.
  - **The provider unreachable:** a held certificate still valid, late or not, is used, saying so.
    With none, the login says the provider did not answer and that people already logged in are
    unaffected, and exits 1.
  - **An agent running** for this broker with the held certificate is refreshed (a key signature).
    One with another certificate or another broker exits 1 naming it, as today. `--sign-in` with an
    agent running exits 1: stop the agent first.
  - **A held certificate refused:** when the new agent's first refresh is answered
    `credential_revoked`, the login removes the key and certificate, says the broker's words, and
    exits 1; the next login signs in. When the agent cannot connect with a held certificate, the
    login says to run `port49 login --sign-in`.
- **13. One path for people** (Q1). A broker with `issuance` takes a person's ID token at `POST
  /v1/certificate` alone, and refuses it on every other endpoint, `401 trust_domain_unresolved`,
  recorded. A machine's token is unaffected. A broker with a human `oidc` verifier and no
  `issuance` keeps plan 7h's bearer path (decision 39 rulings 8 and 15) as built, which no port49
  client drives after plan 9b; retiring it is carried to the pre-beta review.
- **14. The issuing CA.**
  - **Custody.** `issuing-ca.pem` and `issuing-ca.key` (PKCS #8, 0600, `keyfile`'s owner-only rule)
    in the broker's state directory (`broker.state_dir`, or the directory of
    `broker.revocations_file`). The broker signs through a `crypto.Signer`, so a KMS or an HSM is
    a later swap of its source.
  - **Made once.** `port49d init-issuer` or `port49-broker init-issuer`, as the broker's user: a
    P-256 key and a self-signed CA certificate valid 5 years. On every further broker on one
    store, the operator copies both files. Each start prints the CA's fingerprint; a cross-replica
    check is carried to plan 12.
  - **Rotation with overlap** (R5). `rotate-issuer`, on one broker, stages `issuing-ca-next.pem`
    and `.key`. Only the certificate is copied to the other brokers, which trust it from their next
    start; the key stays on the broker that staged it until the promotion. Run again there, it
    promotes: the current certificate becomes `issuing-ca-previous.pem`, its key is overwritten,
    and the next becomes current; the operator copies the three files to the other brokers. A
    broker trusts every one of the three present and signs with the current. The previous is
    removed by hand after `certificate_lifetime`; trusting it longer admits nothing, since its key
    is gone.
  - **The promotion's guards** (pre-flight 2 m4). It is idempotent, so an interrupted one is
    finished by running it again. It is refused while an earlier rotation's
    `issuing-ca-previous.pem` is still there, whose certificates may still be valid, and on a
    broker that holds the staged certificate without its key. A staged file that is already the
    current CA, left by a finished promotion or copied from the promoting broker, is removed, and
    nothing is promoted or said to be.
  - **At 3am** (R4). A start never fails over these files. A missing or unusable key stops
    issuance alone: `503 issuance_unavailable`, and the certificates already issued are trusted. A
    missing or unusable CA certificate also stops their trust. Each is said at start, naming the
    file and `init-issuer`. `port49_issuing_ca_not_after_timestamp_seconds` is the CA's end, 0
    when none is loaded.
- **15. Revocation.** By principal (every certificate the person holds, issued or not) or by
  certificate (`--cert-issuer` the CA's DN, `--cert-serial` from the `issue` record), as decision
  32 built it. The short lifetime is the main control. No CRL is published: no device sees the
  certificate, and the broker trusts its own CA.
- **16. Back-channel logout** (decision 39 ruling 13). The certificate carries its sign-in's `sid`
  and `sub`; the owner record is written at issuance and at each mint. A logout by `sid`, or by
  `sub` for a sign-in whose `iat` is at or before the logout plus `clock_skew`, refuses the
  certificate's next request and refresh `credential_revoked` in the broker's logout words, and a
  refresh's own reading after its writes marks what it extended. The `sid` index reaches its device
  sessions. A logout leaves no mark: a sign-in after it is taken. The certificate carries no mark of
  its own, so the logout record is what refuses it: on a broker that issues, a logout record stands
  `max(max_token_age, 24h) + 2×clock_skew` (24h is the longest `certificate_lifetime` allowed, so a
  lifetime lowered since leaves no certificate unreached), not decision 39's `max_token_age +
  2×clock_skew`, and the recovery's lift time follows it. Every broker on one store configures
  `issuance` alike: one without it keeps the shorter record. A recovery for a logout the store
  could not write names the shorter path: revoke the sign-in's certificates by serial, from their
  `issue` records, and lift the principal's mark after `max_token_age`.
- **17. The provider down at 3am.** People holding a certificate keep working until it ends: mints,
  refreshes, and new agents (ruling 12). Only a sign-in fails, and says so.
- **18. `/v1/config`.** A broker with `issuance` adds `issuance: {certificate_lifetime_seconds}`.
  Decision 39 ruling 16's `oidc` list is unchanged. A broker with `tls_ca_bundle_file` adds
  `broker_ca_bundle` (ruling 25).
- **19. The config file and the flags** (amends decision 42 ruling 6).
  - **The file.** `config.yaml` gains `method` (`x509`, the default, or `oidc`), `oidc_issuer`,
    `oidc_ca` (held to ruling 6's ownership rule as `broker_ca` is, and read once) and
    `oidc_redirect_port`.
  - **The flags.** `port49 login` takes `--oidc`, `--issuer`, `--oidc-ca`, `--redirect-port`,
    `--no-browser` and `--sign-in`. `--cert` or `--key` beside `--oidc` is a usage error, and so
    are the OIDC flags without it. `broker_ca` stays required: it is the broker's TLS, on either
    path.
- **20. What is never logged or printed:** the ID token, the code, the verifier, the key, and a
  token response's body. The authorization URL is printed on the operator's terminal and handed to
  the browser: it carries `state`, the `nonce` (a public key's hash) and the `code_challenge`. It is
  not a credential, but its `state` must not leave this user, since whoever holds it can complete
  this sign-in with their own account (a login CSRF; RFC 6749 §10.12). So the login prints the
  principal it was issued for.
- **21. The agent.** Unchanged but in two points. Its process exits at the certificate's end when
  that comes before `max_session_age`, saying so; a request past it meets the broker's refusal of
  an expired certificate, as on every certificate path. It makes itself non-dumpable on Linux and
  denies a debugger on macOS, so no core file or crash report holds the key; one that cannot runs
  on and says so, since the key is a file this user reads already.
- **22. The record and the metrics.** The `issue` event (§5.7): a permit `certificate_issued`
  carries `certificate: {serial, issuer, fingerprint, not_after}` and `auth.oidc`; a deny carries
  the refusal's reason. `port49_certificates_issued_total{outcome}` (`issued`, `refused`,
  `unavailable`) and `port49_issuing_ca_not_after_timestamp_seconds`; no principal and no device.
- **23. The lab.** L55: Keycloak as this client meets it. L56: issued certificates end to end on
  Keycloak and vEOS. L47 (hosted providers) stays open. Until L55 closes, no doc says which redirect
  registration admits an ephemeral port on Keycloak, or that it enforces PKCE.
- **24. The client's config, with no step per user** (Ryan, 2026-10-10, and the toil audit's H4;
  amends decision 42 ruling 6).
  - **The rule** (Ryan's, standing). A step too hard for a user or an operator to do at scale is
    not in the design, and what can be automated away from the user is. The cases weighed: 1,000
    devices, 50 operators, a new hire, a laptop rebuilt, and each CA rotated.
  - **Where.** `~/.port49/`, as `~/.ssh/` is, made 0700 when it is missing. It holds `config.yaml`
    and `issued/`, and no host-key pins: those stay in plan 9a's
    `$XDG_CONFIG_HOME/port49/known_hosts` until plan 9d takes them out of the user's flow.
    `$PORT49_CONFIG`, and over it `--config FILE`, name another personal file, which must exist.
  - **The system file.** `/etc/port49/config.yaml`, shipped by the install (a package, config
    management or MDM), takes the same keys, under the personal file key by key. A key the personal
    file sets wins, and a flag wins over both. The system file must be root's, and neither its group
    nor others may write it; the walk above it is ruling 6's. It holds what the install knows:
    `broker`, `broker_ca` (the CA beside it, as `/etc/port49/broker-ca.pem`), `method: oidc`, and
    where needed `oidc_issuer` and `oidc_ca`. The client id, the scopes and the certificate's
    lifetime come from the broker's `/v1/config` at each sign-in (decision 39 ruling 16; ruling 18),
    so no file holds a copy that can drift.
  - **A new user's first login** is `port49 login` and the sign-in at the provider. Nothing is per
    user: no file to write, no CA to fetch, no directory to make or `chmod`. Under plan 9a it was a
    config file of four keys, a CA file fetched, and on Ubuntu `chmod go-w ~/.config`, per user and
    per host; the OIDC path would have added up to four more keys.
  - **Each CA rotated, with no step by a user.** The issuing CA (ruling 14) is the broker's alone;
    no client holds it. The broker's TLS CA rotates through the bundle each agent keeps (ruling 25),
    and the install's config management ships the old and the new CA in `broker_ca`, one file per
    host, at the rotation's start, and the new alone at its end. A host config management reaches
    needs nothing of its user; the by-hand fix is for an unmanaged host alone.
  - **An expired or late certificate** is replaced by the next `port49 login`, which signs in and
    writes over the key and the certificate (ruling 12); a refused one is removed. No file is moved
    or deleted by hand.
  - **Plan 9a's file.** A `config.yaml` at `$XDG_CONFIG_HOME/port49/` (else `~/.config/port49/`),
    with none at `~/.port49/`, is refused in one line naming the move; it is never read, and never
    silently passed over.
  - **What a refusal says.** It names the exact path and the owner or mode it needs. It never
    suggests a `chmod` on a directory, which may be shared, as a group-writable `~/.config` is.
- **25. The broker's TLS CA rotates with no step by a user** (Ryan, 2026-10-10; completes ruling
  24).
  - **The bundle.** `broker.tls_ca_bundle_file` names the CAs clients are to trust for the
    broker's server certificate: the CA in use and, through a rotation, the next. The broker reads
    it at start and sends it on `GET /v1/config` as `broker_ca_bundle` (PEM). A bundle that cannot
    be read, holds anything but 1 to 4 CA certificates in at most 64 KiB, or does not verify the
    server certificate in use is not sent, said in one line, and the start goes on (R4's rule).
  - **The client.** The agent fetches `/v1/config` on the connection it has just verified, at every
    start, and keeps the bundle 0600 in `~/.port49/broker_ca/<host>_<port>.pem`, one per broker so
    no broker's bundle is trusted for another. A login trusts its `broker_ca` and the kept bundle
    together, and hands both to the agent it starts.
  - **Refused, and the file left as it was:** a bundle out of those bounds, or one that does not
    hold the CA this connection was verified to. A change is logged by fingerprint, old and new.
    A kept file that cannot be used is refused at login, naming it.
  - **A broker that sends no bundle clears it.** On a verified `/v1/config` with no
    `broker_ca_bundle`, a kept file that does not hold the CA this connection was verified to is
    removed, and one that does is cut to that CA alone, each said in one line. So the next login
    still verifies the broker, and any other CA the file held is gone.
  - **A broker that refused its own bundle is not one that sends none.** When
    `tls_ca_bundle_file` is configured and refused at start (unreadable, out of bounds, or without
    the server certificate's CA), `/v1/config` carries `broker_ca_bundle_refused: true`, and each
    agent leaves its kept file as it was, saying so in one line. So a typo in the bundle
    mid-rotation drops no CA a client holds, as the broker's own start line says.
  - **A rotation.** The operator adds the next CA to the bundle, and the install's config
    management adds it to every host's `broker_ca` at once (ruling 24); restarts the brokers; waits
    while people log in (every agent that starts keeps the new bundle: a day covers everyone who
    works daily, longer covers people away); then switches the server certificate to one the next
    CA issued; and later drops the old CA from the bundle and from `broker_ca`. No user does
    anything.
  - **A host away through the whole overlap** that config management reaches has the new
    `broker_ca` on its return. An unmanaged one meets a certificate no CA it trusts issued, and the
    refusal says on the same line: get the broker's CA from its operator and run `port49 login
    --broker-ca FILE` once; port49 keeps it current from then on. That is the last resort, not the
    rotation's path.
  - **What it does not do.** The bundle only adds trust beside `broker_ca`; it never removes the
    configured CA, which config management updates. So a rotation because the old CA is
    compromised also pushes the new `broker_ca` to every host at once: until then the old CA stays
    trusted there.
  - **What it costs** (pre-flight 2 I1). It carries trust only for the broker that sent it, over a
    connection verified to a CA the host already trusts, so a plain MITM pins nothing. But whoever
    holds the broker's server key, even briefly, can send a bundle that adds a CA of their own, and
    each agent that starts meanwhile trusts it for that broker. That outlives the compromise on a
    host that does not reconnect to the real broker, since a bundle is replaced only by a later
    one. The remedy is the real broker's next answer, a bundle or none, which every agent applies
    at its next start.
```

- [ ] **Step 2: Decision 39 rulings 13, 15 and 16, decision 42 ruling 6, §5.6's logout record and §12's config file point at decision 43**

Replace

```markdown
  old, before the extension; a logout read after the writes marks every context extended.
  Task 11.
- **16. `/v1/config`** lists `methods` and, per human OIDC verifier, `{issuer, client_id,
  scopes}`. Task 10.
```

with

```markdown
  old, before the extension; a logout read after the writes marks every context extended.
  Task 11. A broker that issues certificates takes a person's ID token at `POST /v1/certificate`
  alone (decision 43 ruling 13), so there a person refreshes by a key signature.
- **16. `/v1/config`** lists `methods` and, per human OIDC verifier, `{issuer, client_id,
  scopes}`. Task 10. Plan 9b adds `issuance` (decision 43 ruling 18).
```

In decision 42 ruling 6, replace

```markdown
  - **Where and what.** `$XDG_CONFIG_HOME/port49/config.yaml`, else
    `~/.config/port49/config.yaml`, holding `broker`, `broker_ca`, `cert` and `key`.
```

with

```markdown
  - **Where and what.** `~/.port49/config.yaml`, over the system-wide `/etc/port49/config.yaml`
    key by key (decision 43 ruling 24; plan 9a's `$XDG_CONFIG_HOME/port49/config.yaml` is refused,
    naming the move), holding `broker`, `broker_ca`, `cert` and `key`. Plan 9b adds `method`,
    `oidc_issuer`, `oidc_ca` and `oidc_redirect_port` (decision 43 ruling 19).
```

In §12, replace

```markdown
**`port49 login`** takes `--broker`, `--broker-ca`, `--cert` and `--key` from the per-user config
file, `$XDG_CONFIG_HOME/port49/config.yaml`, for each one its flags leave out. It reads the file
only when nobody but the operator or root can write it or any directory above it (§13 decision
42 ruling 6).
```

with

```markdown
**`port49 login`** takes `--broker`, `--broker-ca`, `--cert` and `--key` from the per-user config
file, `~/.port49/config.yaml` (or the file `$PORT49_CONFIG` names), for each one its flags leave
out, and from the system-wide `/etc/port49/config.yaml` the install ships for each one both leave
out. It reads a file only when nobody but the operator or root can write it or any directory above
it, and the system file only when it is root's (§13 decision 42 ruling 6, decision 43 ruling 24).
```

In decision 39 ruling 13 (pre-flight 2 re-review N5), replace

```markdown
  `sub`: every token issued at or before the logout's `iat` + `clock_skew`; kept `max_token_age` +
  2 × `clock_skew`); then each owner principal's own unspent tokens, only principals in the
```

with

```markdown
  `sub`: every token issued at or before the logout's `iat` + `clock_skew`; kept `max_token_age` +
  2 × `clock_skew`, and on a broker that issues certificates `max(max_token_age, 24h)` + 2 ×
  `clock_skew`, decision 43 ruling 16); then each owner principal's own unspent tokens, only
  principals in the
```

In §5.6, replace

```markdown
- **A logout record**, written first, kept `max_token_age` plus twice `clock_skew`. By `sid`, it
```

with

```markdown
- **A logout record**, written first, kept `max_token_age` plus twice `clock_skew` (on a broker
  that issues certificates, `max(max_token_age, 24h)` plus twice `clock_skew`, 24h being the
  longest certificate it may issue; §13 decision 43 ruling 16). By `sid`, it
```

- [ ] **Step 3: §2, the issued certificate's principal**

Before the row that begins `| Kubernetes |` (`grep -n "^| Kubernetes |"`), insert:

```markdown
| port49-issued certificate | the principal the human OIDC verifier gave at the sign-in it was issued on, from the certificate's subject CN, never mapped again; the sign-in's issuer must still be a human verifier's whose `principal_domains` hold it (§13 decision 43 ruling 10) |
```

- [ ] **Step 4: §5.1.4, a certificate port49 issued**

Before the paragraph that begins `**Consequence for the store.**` (`grep -n "^\*\*Consequence for
the store\.\*\*"`), insert:

```markdown
**A certificate port49 issued** (plan 9b; §13 decision 43) carries both halves: `method: cert`
with its fingerprint, issuer (the broker's issuing CA), serial and subject, and the `iss`, `sub`,
`sid`, `amr` and `acr` of the OIDC sign-in it was issued on, read from its one URI SAN. So a
back-channel logout naming that `sid` reaches the certificate's sessions, and a revocation by its
serial reaches them too. Its `notAfter` bounds the mint and the refresh, as any certificate's does,
and never a session.

```

- [ ] **Step 5: §5.6, the issued certificate's session**

After the line ``auth_time`) and L47 (hosted providers, open).`` (`grep -n "(hosted providers,
open)\.$"`), insert a blank line and:

```markdown
**A certificate port49 issued, as built (plan 9b; §13 decision 43 ruling 11).** After the sign-in
the agent holds the session on the certificate path, unchanged:

- **The clock.** `auth_time` is the broker's acceptance of the handshake or its verification of a
  refresh's signature; the provider's `auth_time` bounds issuance alone (5 minutes) and is recorded
  as `auth.oidc.auth_time`.
- **The fresh authentication event.** A refresh's key signature on the issued certificate is one,
  as on any certificate, while the certificate is valid. So `port49 refresh` and a new agent's
  refresh at login need no browser, and one sign-in gives at most `certificate_lifetime` of mints
  and refreshes.
- **The certificate's end** bounds the mint and the refresh, not a device session: what a last
  refresh extended runs to its own ceiling.
- **A back-channel logout** refuses the certificate through its `sid` for as long as it lives: on a
  broker that issues, a logout record stands `max(max_token_age, 24h) + 2×clock_skew`, 24h being
  the longest `certificate_lifetime` allowed (§13 decision 43 ruling 16).
```

- [ ] **Step 6: §5.7, the `issue` event and `certificate_issued`**

Make these five replacements, in this order, each of one ordinal word (each old text appears
once):

```
A fourteenth, `directory_forget`, is a report too           ->  A fifteenth, `directory_forget`, is a report too
A thirteenth, `inventory_change`, is a report too           ->  A fourteenth, `inventory_change`, is a report too
A twelfth, `account_gap`, is a report too                   ->  A thirteenth, `account_gap`, is a report too
shares this envelope as the eleventh event, `account`       ->  shares this envelope as the twelfth event, `account`
One envelope. Nine decision events, one at each point       ->  One envelope. Ten decision events, one at each point
```

After the row that begins `` | `explain` | broker | `` in the events table, insert:

```markdown
| `issue` | broker | whether a person's OIDC sign-in is exchanged for a port49-issued certificate (`POST /v1/certificate`; §13 decision 43 ruling 8): `permit certificate_issued`, carrying `certificate: {serial, issuer, fingerprint, not_after}` and `auth.oidc`, or a deny with the refusal's reason. A broker that cannot issue (`issuance_unavailable`) records nothing |
```

After the row that begins `` | `api_right_missing` | `` in the reason table, insert:

```markdown
| `certificate_issued` | `issue`: the broker issued a short-lived client certificate for the key the sign-in's `nonce` names (§13 decision 43 ruling 8) |
```

- [ ] **Step 7: §12, `port49 refresh` and `port49 login` with an issued certificate**

Replace

```markdown
otherwise; it also refreshes once after a new session connects. `port49 token` warns on stderr when
```

with

```markdown
otherwise; it also refreshes once after a new session connects. On a certificate port49 issued
(§13 decision 43 ruling 11) the refresh is the same key signature, with no browser.
`port49 token` warns on stderr when
```

After the line that ends the `port49 login` paragraph Step 2 wrote (`grep -n "^it, and the
system file only when it is root's"`), insert a blank line and:

```markdown
**`port49 login --oidc [--issuer URL] [--oidc-ca FILE] [--redirect-port N] [--no-browser]
[--sign-in]`**, or `method: oidc` in the config file, gets the person a certificate the broker
issues (§13 decision 43).
- **The sign-in.** At the identity provider `/v1/config` lists, by the authorization-code flow
  with PKCE and `prompt=login`, in a browser, or by pasting back the address it ended on.
- **The certificate.** For a key generated on this host (`~/.port49/issued/`, 0600),
  valid `certificate_lifetime`. The agent then holds the session as on the certificate path.
- **No sign-in** while a held certificate has more than a quarter of its life left, or while the
  provider does not answer and it is still valid; `--sign-in` forces one.
```

- [ ] **Step 8: §14, the required assertions for issued certificates**

Before the line that begins `- **Staleness ceiling**: with the broker unreachable` (`grep -n
"^- \*\*Staleness ceiling\*\*"`), insert:

```markdown
- **Port49-issued certificates** (§13 decision 43): a sign-in's ID token whose `nonce` names the
  CSR's key, `auth_time` within 5 minutes, is issued a certificate once, and a second exchange of
  the token is refused; a token whose `nonce` names another key, or a stale `auth_time`, is
  refused and recorded; the certificate mints as the sign-in's principal with `auth.oidc` on its
  records, never mapped through the directory; a chain ending at the issuing CA and another anchor
  is refused; a sign-in whose issuer no human verifier takes now is refused; a back-channel logout
  of its `sid` refuses its next mint and refresh `credential_revoked`, for as long as the certificate
  lives, and revokes its device sessions; a key signature refreshes it with no sign-in; a person's ID token at any other endpoint
  of a broker that issues is refused, and a machine's is not; a broker with no issuing CA key
  starts, answers a sign-in `issuance_unavailable`, and says so.
```

- [ ] **Step 9: §15, L55 and L56 after L54**

After the row that begins `| **L54** |` (`grep -n "^| \*\*L54\*\*"`), insert:

```markdown
| **L55** | Keycloak as port49's public client meets it (plan 9b). **The redirect:** for port49-cli registered with `http://127.0.0.1:18749/callback`, `http://127.0.0.1/callback`, `http://127.0.0.1/*` and `http://127.0.0.1:*/callback` in turn, whether the admin API takes the registration and whether an authorization request naming `http://127.0.0.1:<port>/callback` is accepted (the login form shown) for the registered port and an ephemeral one (RFC 8252 §7.3), against a matcher seen to accept the realm's own redirect and refuse another host's. **PKCE:** with `S256`, on port49-cli as the realm file sets its `pkce.code.challenge.method` (recorded), whether a code exchanged with the right verifier, a wrong one and none is answered, and with which `error`; whether `code_challenge_method=plain` is accepted. **Discovery and the answer:** `code_challenge_methods_supported`, `authorization_response_iss_parameter_supported`, and whether the authorization response carries `iss` (RFC 9207). **The key binding:** whether a 43-character base64url `nonce` comes back in the ID token byte for byte, and whether a `prompt=login` sign-in's `auth_time` is within 10s of the sign-in. **`prompt=login` over a live SSO session:** in one browser, a sign-in with no `prompt`, then 15s later, the control, the same session with no `prompt` (whether the form is shown, and `auth_time` against the first), then a `prompt=login` sign-in (whether the form is shown, and whether `auth_time` moves on by 15s or more). | §13 decision 43 rulings 1, 3, 4 and 8; the operator notes' redirect registration (plan 13) | Keycloak (26.x) | open — added 2026-10-09, reworded 2026-10-10 |
| **L56** | Port49-issued certificates end to end on Keycloak and one device (plan 9b), with the real `port49` CLI. Whether: a broker started with `broker.identity.issuance` and no issuing CA answers a sign-in's exchange 503 `issuance_unavailable` and its log names `init-issuer`, and after `port49-broker init-issuer` and a restart issues; `port49 login --oidc --no-browser` signs in through a scripted browser, asks the password, writes a 0600 key and its certificate, names the principal, starts the agent and refreshes once; `port49 token` mints and the device takes the token over SSH; `port49 refresh` extends the device session with no sign-in; `port49 login` after the agent stopped starts a new one with no sign-in and extends the device session; `port49 login --sign-in` at a terminal, the address pasted, issues a new certificate; an administrator's sign-out refuses the certificate's next mint in the broker's logout words and ends the agent, a `port49 login` over that certificate removes it, and a sign-in from the time the broker names works; with Keycloak stopped, `port49 token`, `port49 refresh` and a new agent over the held certificate work, and `port49 login --sign-in` says the provider did not answer and when the held certificate ends. No compact JWS, code or private key in the CLI's raw output or the agent's log (the PKCE verifier, which port49 draws and the lab never sees, is checked by the unit tests' `credentialsNowhere`). Each cell's assertion has a control that shows it can fail. | §13 decision 43 rulings 5, 8, 11, 12, 14, 16, 17 and 20; the operator notes (plan 13) | Keycloak (26.x); EOS | open — added 2026-10-09, reworded 2026-10-10 |
```

- [ ] **Step 10: Design §7, the issued certificate as built**

Replace

```markdown
stops trusting `jwks_max_age` (24h) after the last successful fetch. The agent's public client is
plan 9's.
```

with

```markdown
stops trusting `jwks_max_age` (24h) after the last successful fetch. The agent's public client is
plan 9b's, and exchanges the ID token for a certificate port49 issues (below).
```

Replace

```markdown
On the OIDC path the session is the identity provider's refresh token, held by the agent as a
public client with PKCE. It is a bearer on disk, usable by anyone who copies the file. The gap
is closable — after OIDC authentication the broker MAY issue a short-lived client certificate
whose key is generated locally in a TPM or OS keystore, giving hardware-backed session
protection without the organization running a CA. That is identified as the path for PKI-less
adoption and is **not required for v1**.

On both paths, extending a session at the ceiling requires a **fresh authentication event**
and takes `auth_time` from the new assertion (policy engine spec, §5.6).

**port49 is a relying party, not a certificate authority.** It validates certificates; it
does not issue, enroll, renew, or revoke them. Organizations using the certificate path
supply their own CA. The short-lived issuance described above would be the single, narrowly
scoped exception, and only for port49's own trust domain.
```

with

```markdown
On the OIDC path the agent holds no token. After the OIDC authentication the broker issues a
short-lived client certificate (12h by default) for a key generated on the person's host, and the
session is then the certificate path's held connection, unchanged. That is the path for a company
with no PKI, and it is v1 (plan 9b; policy engine spec §13 decision 43):
- **The sign-in.** `port49 login --oidc` signs in by the authorization-code flow with PKCE (S256),
  in its own process, over a loopback redirect, with `prompt=login`. On a host with no browser the
  address is printed, and the one the browser ends on is pasted back. The device authorization
  grant is not built.
- **The binding.** The sign-in's `nonce` is the new key's hash, so the ID token certifies that key
  alone, once, within 5 minutes of the authentication.
- **The key.** A file, 0600, until plan 9c generates it in a TPM, the Secure Enclave or a token.
  Whoever copies it holds the session until the certificate ends; that bound is the certificate's
  lifetime, not the provider's session.
- **After the sign-in,** every refresh and every new agent's extension is a key signature. With the
  provider down, people holding a certificate keep working until it ends.

On every path, extending a session at the ceiling requires a **fresh authentication event** and
takes `auth_time` from the new assertion (policy engine spec, §5.6). On the certificate path, a
port49-issued certificate's included, the assertion is the key's signature and `auth_time` the
broker's verification time (§13 decision 43 ruling 11).

**port49 is a relying party, not a certificate authority, except for its own short-lived user
certificates.** It validates the certificates organizations supply; it does not enroll, renew or
revoke them. The one exception is the certificate it issues a person over an OIDC sign-in: port49's
own trust domain's, read by the broker that issued it and no one else, seen by no device, its CA
kept in the broker's state directory and rotated with overlap (§13 decision 43 ruling 14).
```

- [ ] **Step 11: Design §8, §17 and §19**

In §8's table, replace

```markdown
| **Session** | 8–16h | agent: a held mTLS connection (certificate) or an IdP refresh token (OIDC); never on the wire | one authentication per day, plus one per reconnect |
```

with

```markdown
| **Session** | 8–16h | agent: a held mTLS connection, with the person's certificate or one port49 issued at an OIDC sign-in; never on the wire | one authentication per day, plus one per reconnect on a hardware key |
```

In §17's Surface block, after the line that begins `POST  /v1/logout`, insert:

```
POST  /v1/certificate     a person's OIDC sign-in, its ID token the bearer, exchanged for a short-lived client certificate for the key its nonce names (plan 9b)
```

In §17's Errors block, after the line that begins `503  revocation_running`, insert:

```
404  not_issuing                      /v1/certificate on a broker with no broker.identity.issuance (plan 9b)
503  issuance_unavailable             /v1/certificate: the broker's issuing CA is not usable; nothing was issued; no record; Retry-After: 60 (plan 9b)
401  sign_in_not_fresh                /v1/certificate: the ID token's auth_time is over 5 minutes old: the provider did not ask the person to sign in again (plan 9b)
401  sign_in_not_bound                /v1/certificate: the ID token's nonce does not name the CSR's key (plan 9b)
401  sign_in_spent                    /v1/certificate: the ID token was exchanged for a certificate already (plan 9b)
```

In §17's Client libraries, replace

```markdown
Only interactive human use requires session management and SSH integration.
```

with

```markdown
Only interactive human use requires session management and SSH integration. As built (plan 9b):
`port49 login --oidc` signs a person in at their identity provider and holds the certificate the
broker issues, so the rest is the certificate path's.
```

In §19, replace

```markdown
9. Agent in full: SSH integration with host-key verification, the OIDC public client.
```

with

```markdown
9. Agent in full: SSH integration with host-key verification, the OIDC public client and the
   short-lived user certificate the broker issues over it (§7), hardware-backed keys, and a
   directory-password sign-in.
```

- [ ] **Step 12: Check and commit**

Run: `grep -c "decision 43" docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md`
Expected: at least 10 in the spec and 3 in the design.

Run:

```bash
grep -nE '^\| \*\*L5[56]\*\*|^\| .issue. \||^\| .certificate_issued. \||Ten decision events|A fifteenth, .directory_forget.' \
  docs/design/2026-08-23-policy-engine-spec.md
```

Expected: six lines.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs(spec): decision 43, port49-issued user certificates over an OIDC sign-in; L55 and L56 reworded"
```

---

### Task 2: The provider the client talks to: an authorization server on the test issuer

**Files:**
- Create: `internal/oidc/oidctest/authserver.go`, `internal/oidc/oidctest/authserver_test.go`
- Modify: `internal/oidc/oidctest/issuer.go` (`Issuer.auth`, two routes, discovery members)

**Interfaces:**
- Consumes: `oidctest.Issuer` (`URL`, `Token`, `Roots`, `mu`, the discovery handler).
- Produces, for Tasks 3–12:
  - `func (i *Issuer) AuthServer(t testing.TB, clientID, sub string, claims map[string]any) *AuthServer`
  - `type AuthServer struct { ClientID, Sub string; Claims map[string]any; Now func() time.Time; … }`
  - `func (a *AuthServer) SetAuthTime(at time.Time)`, `NoIssParameter()`, `Deny(code string)`
  - `func (a *AuthServer) Authorizations() []url.Values`, `Grants() []url.Values`, `Issued() []string`
  - `func (i *Issuer) Browser() func(string) error`, `func (i *Issuer) Redirected(u string) (string, error)`

- [ ] **Step 1: Write the failing tests**

Create `internal/oidc/oidctest/authserver_test.go`:

```go
package oidctest

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// claimsOf is a JWS's claims, decoded without verification: the test reads
// what the server signed.
func claimsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d parts", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// authorize asks i's /authorize for a code with verifier's S256 challenge,
// redirecting to a loopback port nothing listens on, and returns the
// redirect's query without following it.
func authorize(t *testing.T, i *Issuer, verifier, nonce string) (url.Values, string) {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	redirect := "http://127.0.0.1:1/callback"
	q := url.Values{"response_type": {"code"}, "client_id": {"port49-cli"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"st"}, "nonce": {nonce}, "prompt": {"login"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	loc, err := i.Redirected(i.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query(), redirect
}

// token posts form to i's /token and returns the status and the answer.
func token(t *testing.T, i *Issuer, form url.Values) (int, map[string]any) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	resp, err := c.PostForm(i.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestTheCodeFlowIssuesAnIDTokenForTheVerifier(t *testing.T) {
	i := NewIssuer(t)
	a := i.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})
	q, redirect := authorize(t, i, "verifier-0123456789-0123456789-0123456789", "n-1")
	if q.Get("state") != "st" || q.Get("iss") != i.URL || q.Get("code") == "" {
		t.Fatalf("the answer: state %q iss %q code present %v", q.Get("state"), q.Get("iss"), q.Get("code") != "")
	}
	code, out := token(t, i, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"redirect_uri": {redirect}, "client_id": {"port49-cli"},
		"code_verifier": {"verifier-0123456789-0123456789-0123456789"}})
	// A provider's answer carries a refresh token too; port49 drops it.
	if code != 200 || out["refresh_token"] == nil {
		t.Fatalf("exchange: %d, refresh token present %v", code, out["refresh_token"] != nil)
	}
	if c := claimsOf(t, out["id_token"].(string)); c["sub"] != "sub-alice" || c["nonce"] != "n-1" ||
		c["aud"] != "port49-cli" || c["iss"] != i.URL || c["sid"] != "s-sub-alice" {
		t.Fatalf("the ID token's claims: sub %v nonce %v aud %v iss %v sid %v", c["sub"], c["nonce"], c["aud"],
			c["iss"], c["sid"])
	}
	if got := a.Authorizations(); len(got) != 1 || got[0].Get("prompt") != "login" {
		t.Fatalf("authorizations recorded: %d", len(got))
	}
	if n := len(a.Issued()); n != 3 {
		t.Fatalf("issued %d values (code, ID token, refresh token)", n)
	}
}

// A code is exchanged once, with the verifier its challenge was made from
// (RFC 7636 §4.6): a wrong verifier and a second use are invalid_grant.
func TestTheTokenEndpointRefusesAWrongVerifier(t *testing.T) {
	i := NewIssuer(t)
	i.AuthServer(t, "port49-cli", "sub-alice", nil)
	right := "verifier-0123456789-0123456789-0123456789"
	q, redirect := authorize(t, i, right, "n")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {redirect},
		"client_id": {"port49-cli"}, "code_verifier": {right + "x"}}
	if code, out := token(t, i, form); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a wrong verifier: %d %v", code, out["error"])
	}
	form.Set("code_verifier", right)
	if code, out := token(t, i, form); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a code tried once already: %d %v", code, out["error"])
	}
	form.Set("grant_type", "refresh_token")
	if code, out := token(t, i, form); code != 400 || out["error"] != "unsupported_grant_type" {
		t.Fatalf("the refresh grant, which port49 never sends: %d %v", code, out["error"])
	}
}

// SetAuthTime is a provider that reused an old authentication: a
// prompt=login it ignored.
func TestSetAuthTimeIsAReusedAuthentication(t *testing.T) {
	i := NewIssuer(t)
	a := i.AuthServer(t, "port49-cli", "sub-alice", nil)
	at := time.Now().Add(-time.Hour).Truncate(time.Second)
	a.SetAuthTime(at)
	q, redirect := authorize(t, i, "verifier-0123456789-0123456789-0123456789", "n")
	_, out := token(t, i, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"redirect_uri": {redirect}, "client_id": {"port49-cli"},
		"code_verifier": {"verifier-0123456789-0123456789-0123456789"}})
	if c := claimsOf(t, out["id_token"].(string)); c["auth_time"] != float64(at.Unix()) {
		t.Fatalf("auth_time %v, want %d", c["auth_time"], at.Unix())
	}
}

// Discovery names the endpoints once an authorization server exists, and
// Browser follows the provider's redirect to a loopback listener.
func TestDiscoveryAndTheBrowser(t *testing.T) {
	i := NewIssuer(t)
	i.AuthServer(t, "port49-cli", "sub-alice", nil)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	resp, err := c.Get(i.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc["authorization_endpoint"] != i.URL+"/authorize" || doc["token_endpoint"] != i.URL+"/token" ||
		doc["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("discovery: %v", doc)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan url.Values, 1)
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.URL.Query() }))
	}()
	defer ln.Close()
	q := url.Values{"response_type": {"code"}, "client_id": {"port49-cli"}, "state": {"s"},
		"redirect_uri": {"http://" + ln.Addr().String() + "/callback"}, "code_challenge": {"c"},
		"code_challenge_method": {"S256"}}
	if err := i.Browser()(i.URL + "/authorize?" + q.Encode()); err != nil {
		t.Fatal(err)
	}
	if v := <-got; v.Get("code") == "" || !strings.HasPrefix(v.Get("iss"), "https://") {
		t.Fatalf("the callback: code present %v, iss %q", v.Get("code") != "", v.Get("iss"))
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/oidc/oidctest/ -run 'TestTheCodeFlow|TestTheTokenEndpoint|TestSetAuthTime|TestDiscoveryAndTheBrowser' -count=1`
Expected: FAIL to build: `i.AuthServer undefined`.

- [ ] **Step 3: The authorization server**

Create `internal/oidc/oidctest/authserver.go`:

```go
package oidctest

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// AuthServer is the issuer's authorization server for one public client
// (plan 9b): GET /authorize answers at once, as a provider holding a live
// session does, by redirecting to the request's loopback redirect_uri with
// a code for Sub; POST /token takes that code with its PKCE verifier. Its
// answer carries an ID token and a refresh token, as a provider's does;
// port49 exchanges the ID token for a certificate and drops the refresh
// token. Discovery then names both endpoints, S256 and the iss parameter
// (RFC 9207).
type AuthServer struct {
	ClientID string
	Sub      string
	// Claims go into every ID token beside iss, aud, sub, iat, exp,
	// auth_time, sid, jti and the request's nonce.
	Claims map[string]any
	// Now is the provider's clock; nil is time.Now.
	Now func() time.Time

	t        testing.TB
	i        *Issuer
	mu       sync.Mutex
	authTime time.Time
	noIss    bool
	deny     string
	codes    map[string]grant
	asked    []url.Values
	grants   []url.Values
	issued   []string
}

// grant is what a code stands for.
type grant struct {
	redirect, challenge, nonce string
	authTime, expires          time.Time
}

// AuthServer makes i an authorization server for clientID, signing in sub
// with claims. ID tokens live five minutes, and each sign-in is an
// authentication at Now.
func (i *Issuer) AuthServer(t testing.TB, clientID, sub string, claims map[string]any) *AuthServer {
	a := &AuthServer{ClientID: clientID, Sub: sub, Claims: claims, t: t, i: i, codes: map[string]grant{}}
	i.mu.Lock()
	i.auth = a
	i.mu.Unlock()
	return a
}

func (a *AuthServer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// SetAuthTime makes every later sign-in reuse an authentication at at, as a
// provider ignoring prompt=login does; the zero time makes each one an
// authentication at Now again.
func (a *AuthServer) SetAuthTime(at time.Time) { a.mu.Lock(); a.authTime = at; a.mu.Unlock() }

// NoIssParameter drops iss from the authorization response and from
// discovery.
func (a *AuthServer) NoIssParameter() { a.mu.Lock(); a.noIss = true; a.mu.Unlock() }

// Deny answers every later authorization with error=code.
func (a *AuthServer) Deny(code string) { a.mu.Lock(); a.deny = code; a.mu.Unlock() }

// Authorizations is every /authorize query, in order.
func (a *AuthServer) Authorizations() []url.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]url.Values(nil), a.asked...)
}

// Grants is every /token form, in order.
func (a *AuthServer) Grants() []url.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]url.Values(nil), a.grants...)
}

// Issued is every code, ID token and refresh token given out: the values no
// output may hold.
func (a *AuthServer) Issued() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.issued...)
}

// signInTime is a new sign-in's auth_time. Called with a.mu held.
func (a *AuthServer) signInTime() time.Time {
	if !a.authTime.IsZero() {
		return a.authTime
	}
	return a.now()
}

func (a *AuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, q)
	redirect := q.Get("redirect_uri")
	u, err := url.Parse(redirect)
	if q.Get("client_id") != a.ClientID || err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" ||
		u.Path != "/callback" {
		http.Error(w, "oidctest: an unknown client or a redirect_uri that is not loopback", http.StatusBadRequest)
		return
	}
	back := u.Query()
	back.Set("state", q.Get("state"))
	if !a.noIss {
		back.Set("iss", a.i.URL)
	}
	switch {
	case a.deny != "":
		back.Set("error", a.deny)
		back.Set("error_description", "oidctest: denied")
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		back.Set("error", "invalid_request")
	default:
		code := opaque()
		a.codes[code] = grant{redirect: redirect, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
			authTime: a.signInTime(), expires: a.now().Add(time.Minute)}
		a.issued = append(a.issued, code)
		back.Set("code", code)
	}
	u.RawQuery = back.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *AuthServer) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	f := r.PostForm
	a.mu.Lock()
	defer a.mu.Unlock()
	a.grants = append(a.grants, f)
	fail := func(status int, code string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "oidctest: " + code})
	}
	if f.Get("client_id") != a.ClientID || f.Has("client_secret") {
		fail(http.StatusUnauthorized, "invalid_client")
		return
	}
	if f.Get("grant_type") != "authorization_code" {
		fail(http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	g, ok := a.codes[f.Get("code")]
	delete(a.codes, f.Get("code"))
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if !ok || a.now().After(g.expires) || f.Get("redirect_uri") != g.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		fail(http.StatusBadRequest, "invalid_grant")
		return
	}
	now := a.now()
	// A random jti: RS256 is deterministic, and two sign-ins in one second
	// must not give one JWS.
	c := map[string]any{"iss": a.i.URL, "aud": a.ClientID, "sub": a.Sub, "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "auth_time": g.authTime.Unix(), "sid": "s-" + a.Sub, "jti": opaque()}
	if g.nonce != "" {
		c["nonce"] = g.nonce
	}
	for k, v := range a.Claims {
		c[k] = v
	}
	id, rt := a.i.Token(a.t, "k1", c), opaque()
	a.issued = append(a.issued, id, rt)
	_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": opaque(),
		"expires_in": 300, "id_token": id, "refresh_token": rt})
}

// opaque is 32 random bytes, base64url.
func opaque() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Browser is a browser that trusts the issuer: it opens a URL and follows
// the provider's redirect to the loopback callback, as a person's browser
// does once they have signed in. It errs unless the last answer is 200.
func (i *Issuer) Browser() func(string) error {
	c := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}}}
	return func(u string) error {
		resp, err := c.Get(u)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("oidctest browser: %s", resp.Status)
		}
		return nil
	}
}

// Redirected opens u and returns where the provider redirected it, without
// following: what a person on a remote shell copies from the address bar.
func (i *Issuer) Redirected(u string) (string, error) {
	c := &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.Roots()}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("oidctest: /authorize answered %s", resp.Status)
	}
	return resp.Header.Get("Location"), nil
}
```

In `internal/oidc/oidctest/issuer.go`:

- Add a field to `Issuer`, after `fetches   atomic.Int64`:

  ```go
  	auth      *AuthServer // nil: /authorize and /token answer 404
  ```

- In `NewIssuer`'s discovery handler, replace

  ```go
  		i.mu.Lock()
  		status, hook := i.status, i.discovery
  		i.mu.Unlock()
  ```

  with

  ```go
  		i.mu.Lock()
  		status, hook, auth := i.status, i.discovery, i.auth
  		i.mu.Unlock()
  ```

  and replace

  ```go
  		if hook != nil {
  			hook(doc)
  		}
  ```

  with

  ```go
  		if auth != nil {
  			auth.mu.Lock()
  			doc["authorization_endpoint"] = i.URL + "/authorize"
  			doc["token_endpoint"] = i.URL + "/token"
  			doc["code_challenge_methods_supported"] = []string{"S256"}
  			doc["authorization_response_iss_parameter_supported"] = !auth.noIss
  			auth.mu.Unlock()
  		}
  		if hook != nil {
  			hook(doc)
  		}
  ```

- After the `GET /moved` route, add:

  ```go
  	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
  		i.mu.Lock()
  		a := i.auth
  		i.mu.Unlock()
  		if a == nil {
  			http.NotFound(w, r)
  			return
  		}
  		a.authorize(w, r)
  	})
  	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
  		i.mu.Lock()
  		a := i.auth
  		i.mu.Unlock()
  		if a == nil {
  			http.NotFound(w, r)
  			return
  		}
  		a.token(w, r)
  	})
  ```

`a.i.Token` takes `i.mu` while `a.mu` is held. Nothing takes the two the other way round (the
discovery handler releases `i.mu` before it takes `auth.mu`), so there is no lock-order cycle.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/oidc/... -count=1 && go test -race ./internal/oidc/oidctest/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oidc/oidctest/authserver.go internal/oidc/oidctest/authserver_test.go internal/oidc/oidctest/issuer.go
git commit -m "test(oidc): a test authorization server with PKCE for the public client"
```

---

### Task 3: Reading an ID token as a client, discovery, and the code exchange

**Files:**
- Create: `internal/oidc/client.go`, `internal/oidc/client_test.go`
- Create: `internal/oidcclient/oidcclient.go`, `internal/oidcclient/request.go`,
  `internal/oidcclient/oidcclient_test.go`

**Interfaces:**
- Consumes: `oidc.ParseCompact`, `known`, `payload`, `exact`, `claims`, `claimNames`, `audiences`,
  `humanAudience`, `numericDate`, `printableID`, `exactObject`, `discoveryMember` (all in
  `internal/oidc`); `oidc.NewClient`; `printsafe.Line`; Task 2's `AuthServer`.
- Produces, for Tasks 4 and 10:
  - `type oidc.IDToken struct { Issuer, Subject, Sid, Nonce string; AuthTime, IssuedAt, Expires time.Time }`
  - `func oidc.ReadIDToken(raw, issuer, clientID, nonce string) (oidc.IDToken, error)`
  - `type oidc.Discovery struct { AuthorizationEndpoint, TokenEndpoint string; CodeChallengeMethods []string; IssParameter bool }`
  - `func oidc.ReadDiscovery(raw []byte, issuer string) (oidc.Discovery, error)`
  - `type oidcclient.Provider struct { Issuer, ClientID string; Scopes []string; Roots *x509.CertPool }`
  - `type oidcclient.Endpoints struct { Authorization, Token string; IssParameter bool }`
  - `type oidcclient.Tokens struct { ID oidc.IDToken; IDRaw string; Received time.Time }`
  - `func oidcclient.Discover(ctx context.Context, p Provider) (Endpoints, error)`
  - `func oidcclient.Skew(t Tokens) time.Duration`
  - `func exchange(ctx context.Context, p Provider, e Endpoints, code, redirect, verifier, nonce string, now func() time.Time) (Tokens, error)` (unexported, for Task 4)
  - `func oidcclient.AuthorizationURL(p Provider, e Endpoints, redirect, state, nonce, challenge string) (string, error)`;
    `challengeOf`, `opaque`, `scopeOf` (unexported, for Task 4)
  - `type oidcclient.UnreachableError struct{ Issuer string; Err error }`;
    `type oidcclient.ProviderError struct{ Issuer string; Status int; Code, Description string }`

- [ ] **Step 1: Write the failing tests**

Create `internal/oidc/client_test.go`:

```go
package oidc_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

// ReadIDToken checks what a public client checks (decision 43 ruling 6), and
// never a date against a clock.
func TestReadIDTokenChecksWhatAClientChecks(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	now := time.Now()
	good := map[string]any{"iss": iss.URL, "aud": "port49-cli", "sub": "sub-alice", "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(), "nonce": "n-1", "sid": "s-1"}
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for kk, vv := range good {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	id, err := oidc.ReadIDToken(iss.Token(t, "k1", good), iss.URL, "port49-cli", "n-1")
	if err != nil || id.Subject != "sub-alice" || id.Sid != "s-1" || id.Nonce != "n-1" ||
		id.AuthTime.Unix() != now.Unix() {
		t.Fatalf("a good token: %v %v", id, err)
	}
	// An expired token is read: the client judges no date by its clock.
	old := with("exp", now.Add(-time.Hour).Unix())
	old["iat"] = now.Add(-2 * time.Hour).Unix()
	if _, err := oidc.ReadIDToken(iss.Token(t, "k1", old), iss.URL, "port49-cli", ""); err != nil {
		t.Fatalf("an expired token is the broker's to refuse: %v", err)
	}
	for name, c := range map[string]struct {
		claims map[string]any
		nonce  string
		want   string
	}{
		"another issuer":               {with("iss", "https://evil.example"), "", "was not issued by"},
		"another audience":             {with("aud", "other"), "", "aud does not name"},
		"several audiences and no azp": {with("aud", []string{"port49-cli", "other"}), "", "no azp"},
		"another azp":                  {with("azp", "other"), "", "azp is not"},
		"no sub":                       {with("sub", nil), "", "no usable sub"},
		"no auth_time":                 {with("auth_time", nil), "", "no auth_time"},
		"a date as a string":           {with("iat", "1700000000"), "", "NumericDate"},
		"exp before iat":               {with("exp", now.Add(-time.Minute).Unix()), "", "expires before"},
		"another nonce":                {good, "n-2", "nonce is not"},
		"no nonce when one was sent":   {with("nonce", nil), "n-1", "nonce is not"},
		"a claim named twice in cases": {with("SUB", "x"), "", "twice"},
	} {
		_, err := oidc.ReadIDToken(iss.Token(t, "k1", c.claims), iss.URL, "port49-cli", c.nonce)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// alg none and an HMAC are refused before any claim is read.
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`))
	for _, alg := range []string{"none", "HS256"} {
		head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `"}`))
		if _, err := oidc.ReadIDToken(head+"."+body+".c2ln", iss.URL, "port49-cli", ""); !errors.Is(err, oidc.ErrAlgorithm) {
			t.Errorf("alg %s: %v", alg, err)
		}
	}
	// String withholds the nonce.
	if s := id.String() + id.GoString(); strings.Contains(s, "n-1") {
		t.Fatalf("String holds the nonce: %s", s)
	}
}

func TestReadDiscovery(t *testing.T) {
	ok := `{"issuer":"https://kc.example/r","authorization_endpoint":"https://kc.example/r/auth",` +
		`"token_endpoint":"https://kc.example/r/token","code_challenge_methods_supported":["plain","S256"],` +
		`"authorization_response_iss_parameter_supported":true}`
	d, err := oidc.ReadDiscovery([]byte(ok), "https://kc.example/r")
	if err != nil || d.AuthorizationEndpoint != "https://kc.example/r/auth" || d.TokenEndpoint != "https://kc.example/r/token" ||
		len(d.CodeChallengeMethods) != 2 || !d.IssParameter {
		t.Fatalf("%+v %v", d, err)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"another issuer":         {strings.Replace(ok, `"issuer":"https://kc.example/r"`, `"issuer":"https://kc.example/x"`, 1), "another issuer"},
		"an http token endpoint": {strings.Replace(ok, `"https://kc.example/r/token"`, `"http://kc.example/r/token"`, 1), "token_endpoint"},
		"credentials in a URL":   {strings.Replace(ok, `"https://kc.example/r/auth"`, `"https://u:p@kc.example/r/auth"`, 1), "authorization_endpoint"},
		"a member twice":         {strings.Replace(ok, `{"issuer"`, `{"token_endpoint":"https://x/t","issuer"`, 1), "distinct members"},
		"methods not a list":     {strings.Replace(ok, `["plain","S256"]`, `"S256"`, 1), "code_challenge_methods_supported"},
	} {
		if _, err := oidc.ReadDiscovery([]byte(c.doc), "https://kc.example/r"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
```

Create `internal/oidcclient/oidcclient_test.go`:

```go
package oidcclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
)

// provider is iss as port49-cli's provider, with an authorization server
// signing in sub-alice.
func provider(t *testing.T) (*oidctest.Issuer, *oidctest.AuthServer, Provider) {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	as := iss.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})
	return iss, as, Provider{Issuer: iss.URL, ClientID: "port49-cli", Scopes: []string{"openid"}, Roots: iss.Roots()}
}

func TestDiscoverReadsTheEndpoints(t *testing.T) {
	iss, _, p := provider(t)
	e, err := Discover(context.Background(), p)
	if err != nil || e.Authorization != iss.URL+"/authorize" || e.Token != iss.URL+"/token" || !e.IssParameter {
		t.Fatalf("%+v %v", e, err)
	}
}

// A provider offering PKCE methods without S256 is refused; one listing none
// is used (decision 43 ruling 1).
func TestAProviderWithoutS256IsRefused(t *testing.T) {
	iss, _, p := provider(t)
	iss.Discovery(func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} })
	if _, err := Discover(context.Background(), p); err == nil || !strings.Contains(err.Error(), "S256") {
		t.Fatalf("plain only: %v", err)
	}
	iss.Discovery(func(d map[string]any) { delete(d, "code_challenge_methods_supported") })
	if _, err := Discover(context.Background(), p); err != nil {
		t.Fatalf("none listed: %v", err)
	}
}

func TestAProviderThatDoesNotAnswerIsUnreachable(t *testing.T) {
	iss, _, p := provider(t)
	iss.Close()
	var u *UnreachableError
	if _, err := Discover(context.Background(), p); !errors.As(err, &u) || u.Issuer != iss.URL {
		t.Fatalf("%v", err)
	}
}

// codeFor signs in at iss with nonce and returns the code, redirected to a
// loopback port nothing listens on.
func codeFor(t *testing.T, iss *oidctest.Issuer, p Provider, e Endpoints, verifier, nonce string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	u, err := AuthorizationURL(p, e, "http://127.0.0.1:1/callback", "st", nonce, base64.RawURLEncoding.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	loc, err := iss.Redirected(u)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := url.Parse(loc)
	return v.Query().Get("code")
}

// The code is exchanged with its verifier and no secret, and the ID token's
// nonce must be the request's.
func TestTheExchangeChecksTheNonce(t *testing.T) {
	iss, as, p := provider(t)
	e, err := Discover(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-0123456789-0123456789-0123456789"
	got, err := exchange(context.Background(), p, e, codeFor(t, iss, p, e, verifier, "n-1"),
		"http://127.0.0.1:1/callback", verifier, "n-1", time.Now)
	if err != nil || got.ID.Subject != "sub-alice" || got.IDRaw == "" || got.Received.IsZero() {
		t.Fatalf("%v %v", got, err)
	}
	if g := as.Grants(); g[0].Get("code_verifier") != verifier || g[0].Has("client_secret") {
		t.Fatalf("the exchange sent a secret or no verifier")
	}
	if _, err := exchange(context.Background(), p, e, codeFor(t, iss, p, e, verifier, "n-1"),
		"http://127.0.0.1:1/callback", verifier, "n-2", time.Now); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("another nonce: %v", err)
	}
}

// A refusal at the token endpoint is the provider's code, never its body;
// the answer's refresh token is never kept.
func TestAnExchangeRefusalSaysTheProvidersCode(t *testing.T) {
	iss, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	verifier := "verifier-0123456789-0123456789-0123456789"
	_, err := exchange(context.Background(), p, e, codeFor(t, iss, p, e, verifier, "n"), "http://127.0.0.1:1/callback",
		verifier+"x", "n", time.Now)
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.Code != "invalid_grant" || pe.Status != 400 {
		t.Fatalf("%v", err)
	}
}

// Every request asks for openid, whatever the verifier's scopes leave out
// (OIDC Core §3.1.2.1).
func TestTheScopeAlwaysAsksForOpenID(t *testing.T) {
	_, _, p := provider(t)
	p.Scopes = []string{"email"}
	u, err := AuthorizationURL(p, Endpoints{Authorization: "https://kc.example/r/auth?kc_idp_hint=x"}, "http://127.0.0.1:1/callback",
		"st", "n", "c")
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(u)
	if q.Query().Get("scope") != "openid email" || q.Query().Get("kc_idp_hint") != "x" || q.Query().Get("prompt") != "login" {
		t.Fatalf("%s", u)
	}
}

// Tokens never prints its token.
func TestTokensWithholdThemselves(t *testing.T) {
	h := Tokens{ID: oidc.IDToken{Subject: "sub-alice"}, IDRaw: "eyJ-the-id-token", Received: time.Now()}
	if s := h.String() + h.GoString(); strings.Contains(s, "eyJ-the-id-token") {
		t.Fatalf("%s", s)
	}
}

func TestSkew(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	if s := Skew(Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(7 * time.Minute)}); s != 7*time.Minute {
		t.Fatalf("%v", s)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/oidc/ ./internal/oidcclient/ -count=1`
Expected: FAIL to build: `oidc.ReadIDToken undefined`, `oidc.ReadDiscovery undefined`, `no Go
files in internal/oidcclient` (or `undefined: Discover`).

- [ ] **Step 3: `internal/oidc/client.go`**

```go
package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"
)

// IDToken is an ID token as port49's public client reads it (plan 9b; spec
// §13 decision 43 ruling 6): the claims it checks, from a token it does not
// verify by signature. The token came from the provider's token endpoint
// over TLS, which OIDC Core §3.1.3.7 item 6 allows in place of the
// signature, and the broker verifies it when it is exchanged for a
// certificate. Nothing here authorizes anything.
type IDToken struct {
	Issuer   string
	Subject  string
	Sid      string
	Nonce    string
	AuthTime time.Time
	IssuedAt time.Time
	Expires  time.Time
}

// String withholds the nonce.
func (t IDToken) String() string {
	return fmt.Sprintf("IDToken{issuer %s sub %s sid %s auth_time %s iat %s exp %s}", t.Issuer, t.Subject, t.Sid,
		t.AuthTime.UTC().Format(time.RFC3339), t.IssuedAt.UTC().Format(time.RFC3339), t.Expires.UTC().Format(time.RFC3339))
}

// GoString is String.
func (t IDToken) GoString() string { return t.String() }

// ReadIDToken reads raw as an ID token issued to clientID by issuer: a
// compact JWS whose alg is one Ruling 3 accepts (none and the HMACs are
// ErrAlgorithm); iss exactly issuer; aud naming clientID, and azp as
// humanAudience reads it; sub, iat, exp and auth_time present and iat no
// later than exp; every claim by its exact name; and, when nonce is not "",
// a nonce claim equal to it. It compares no date with a clock: the broker's
// clock judges the token (decision 43 ruling 6).
func ReadIDToken(raw, issuer, clientID, nonce string) (IDToken, error) {
	j, err := ParseCompact(raw)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}
	if !slices.Contains(known, j.Header.Alg) {
		return IDToken{}, fmt.Errorf("the ID token's alg: %w", ErrAlgorithm)
	}
	all, err := payload(j.Payload)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}
	var c claims
	if err := exact(all, &c, claimNames); err != nil {
		return IDToken{}, errors.New("the ID token: a claim is not of its type")
	}
	auds, ok := audiences(c.Aud)
	switch {
	case c.Iss != issuer:
		return IDToken{}, fmt.Errorf("the ID token was not issued by %s", issuer)
	case !ok:
		return IDToken{}, errors.New("the ID token has no aud")
	}
	if r := humanAudience(auds, c.Azp, clientID); r != nil {
		return IDToken{}, fmt.Errorf("the ID token: %s", r.why)
	}
	iat, okIat := numericDate(c.Iat)
	exp, okExp := numericDate(c.Exp)
	at, okAt := numericDate(c.AuthTime)
	switch {
	case !printableID(c.Sub):
		return IDToken{}, errors.New("the ID token has no usable sub")
	case !okIat || !okExp:
		return IDToken{}, errors.New("the ID token's iat or exp is not a NumericDate")
	case len(c.AuthTime) == 0:
		return IDToken{}, errors.New("the ID token has no auth_time")
	case !okAt:
		return IDToken{}, errors.New("the ID token's auth_time is not a NumericDate")
	case exp.Before(iat):
		return IDToken{}, errors.New("the ID token expires before it was issued")
	case nonce != "" && c.Nonce != nonce:
		return IDToken{}, errors.New("the ID token's nonce is not the one port49 sent")
	case c.Sid != "" && !printableID(c.Sid):
		return IDToken{}, errors.New("the ID token's sid is not printable")
	}
	return IDToken{Issuer: c.Iss, Subject: c.Sub, Sid: c.Sid, Nonce: c.Nonce, AuthTime: at, IssuedAt: iat,
		Expires: exp}, nil
}

// Discovery is what port49's public client reads of a provider's discovery
// document (OIDC Discovery §3; RFC 8414 §2; RFC 9207 §3), each member by its
// exact name and none repeated, as the key fetch reads issuer and jwks_uri.
type Discovery struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	// CodeChallengeMethods is code_challenge_methods_supported; nil when the
	// document does not list it.
	CodeChallengeMethods []string
	// IssParameter is authorization_response_iss_parameter_supported.
	IssParameter bool
}

// ReadDiscovery reads raw as issuer's discovery document: its issuer must be
// issuer exactly (OIDC Discovery §4.3), and the two endpoints https URLs with
// a host and no credentials.
func ReadDiscovery(raw []byte, issuer string) (Discovery, error) {
	doc, err := exactObject(raw)
	if err != nil {
		return Discovery{}, errors.New("the discovery document is not a JSON object of distinct members")
	}
	if iss, _ := discoveryMember(doc, "issuer"); iss != issuer {
		return Discovery{}, errors.New("the discovery document names another issuer (OpenID Connect Discovery §4.3)")
	}
	var d Discovery
	d.AuthorizationEndpoint, _ = discoveryMember(doc, "authorization_endpoint")
	d.TokenEndpoint, _ = discoveryMember(doc, "token_endpoint")
	for _, m := range []struct{ name, u string }{{"authorization_endpoint", d.AuthorizationEndpoint},
		{"token_endpoint", d.TokenEndpoint}} {
		u, err := url.Parse(m.u)
		if m.u == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return Discovery{}, fmt.Errorf("the discovery document's %s is not an https URL without credentials", m.name)
		}
	}
	if v, ok := doc["code_challenge_methods_supported"]; ok && json.Unmarshal(v, &d.CodeChallengeMethods) != nil {
		return Discovery{}, errors.New("the discovery document's code_challenge_methods_supported is not a list of strings")
	}
	if v, ok := doc["authorization_response_iss_parameter_supported"]; ok && json.Unmarshal(v, &d.IssParameter) != nil {
		return Discovery{}, errors.New("the discovery document's authorization_response_iss_parameter_supported is not a boolean")
	}
	return d, nil
}
```

`known` is `jws.go`'s list of the five algorithms; `claims`, `claimNames`, `payload`, `exact`,
`audiences`, `numericDate`, `printableID` and `humanAudience` are `verify.go`'s; `exactObject` is
`jws.go`'s and `discoveryMember` `keyset.go`'s. None changes.

- [ ] **Step 4: `internal/oidcclient/oidcclient.go` and `request.go`**

Create `internal/oidcclient/oidcclient.go`:

```go
// Package oidcclient is port49's OpenID Connect public client (plan 9b; spec
// §13 decision 43): the authorization-code flow with PKCE (S256) over a
// loopback redirect (RFC 8252), which `port49 login --oidc` runs in its own
// process to get an ID token it exchanges for a certificate. There is no
// client secret, and no refresh token is kept. The ID token, the code and
// the verifier go nowhere but the token endpoint and the broker; an error
// names the provider and its OAuth error code, never a token or a body.
package oidcclient

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
)

// maxBody bounds a discovery document and a token response.
const maxBody = 1 << 20

// Provider is one identity provider as the broker's /v1/config names it, and
// the anchor port49 reaches it with.
type Provider struct {
	Issuer   string
	ClientID string
	Scopes   []string
	// Roots is the provider's TLS anchor (oidc_ca); nil is the system's roots.
	Roots *x509.CertPool
}

// Endpoints is what discovery gives the client (decision 43 ruling 2).
type Endpoints struct {
	Authorization string
	Token         string
	// IssParameter is whether the provider puts iss in its authorization
	// response (RFC 9207), which the callback then requires.
	IssParameter bool
}

// Tokens is a sign-in's answer: the ID token, read, and its raw form, and
// when it arrived on this host's wall clock. A refresh token in the answer
// is dropped unread (decision 43 ruling 6).
type Tokens struct {
	ID       oidc.IDToken
	IDRaw    string
	Received time.Time
}

// String withholds the ID token.
func (t Tokens) String() string {
	return fmt.Sprintf("Tokens{%v received %s}", t.ID, t.Received.UTC().Format(time.RFC3339))
}

// GoString is String.
func (t Tokens) GoString() string { return t.String() }

// Skew is how far this host's clock was from the provider's when t arrived:
// positive when this host is ahead (decision 43 ruling 6).
func Skew(t Tokens) time.Duration { return t.Received.Sub(t.ID.IssuedAt) }

// UnreachableError is a provider that did not answer: a transport fault, a
// timeout, or a 5xx. A held certificate outlives it (decision 43 ruling 17).
type UnreachableError struct {
	Issuer string
	Err    error
}

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("your identity provider at %s did not answer: %v", e.Issuer, e.Err)
}

func (e *UnreachableError) Unwrap() error { return e.Err }

// ProviderError is the token endpoint refusing (RFC 6749 §5.2): its status,
// error code and description, made printable.
type ProviderError struct {
	Issuer      string
	Status      int
	Code        string
	Description string
}

func (e *ProviderError) Error() string {
	s := fmt.Sprintf("your identity provider at %s refused: %s (HTTP %d)", e.Issuer, e.Code, e.Status)
	if e.Description != "" {
		s += ": " + e.Description
	}
	return s
}

// Discover reads p's discovery document (oidc.ReadDiscovery) and refuses a
// provider that offers PKCE methods without S256; one that lists none is
// used, S256 sent (decision 43 ruling 1).
func Discover(ctx context.Context, p Provider) (Endpoints, error) {
	raw, err := get(ctx, p, strings.TrimSuffix(p.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return Endpoints{}, err
	}
	d, err := oidc.ReadDiscovery(raw, p.Issuer)
	if err != nil {
		return Endpoints{}, fmt.Errorf("%s: %w", p.Issuer, err)
	}
	if d.CodeChallengeMethods != nil && !slices.Contains(d.CodeChallengeMethods, "S256") {
		return Endpoints{}, fmt.Errorf("%s does not offer PKCE with S256 (it lists %s); port49 signs in with S256 only",
			p.Issuer, printsafe.Line(strings.Join(d.CodeChallengeMethods, ", "), 100))
	}
	return Endpoints{Authorization: d.AuthorizationEndpoint, Token: d.TokenEndpoint, IssParameter: d.IssParameter}, nil
}

// get is one GET of u at p: oidc.NewClient's TLS, timeout, proxy and no
// redirect; 200 and 1 MiB at most.
func get(ctx context.Context, p Provider, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := oidc.NewClient(p.Roots).Do(req)
	if err != nil {
		return nil, &UnreachableError{Issuer: p.Issuer, Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case err != nil:
		return nil, &UnreachableError{Issuer: p.Issuer, Err: err}
	case resp.StatusCode >= 500:
		return nil, &UnreachableError{Issuer: p.Issuer, Err: fmt.Errorf("GET %s answered %s", u, resp.Status)}
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: GET %s answered %s", p.Issuer, u, resp.Status)
	case len(body) > maxBody:
		return nil, fmt.Errorf("%s: GET %s: over %d bytes", p.Issuer, u, maxBody)
	}
	return body, nil
}

// errNoIDToken is a token response with no id_token.
var errNoIDToken = errors.New("the token endpoint's answer carries no id_token")

// exchange is the code's exchange (RFC 6749 §4.1.3, RFC 7636 §4.5): the
// verifier, no secret, and an ID token whose nonce is the request's. A
// transport fault or a 5xx is an *UnreachableError, any other refusal a
// *ProviderError; neither holds the form or the body.
func exchange(ctx context.Context, p Provider, e Endpoints, code, redirect, verifier, nonce string,
	now func() time.Time) (Tokens, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {p.ClientID}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := oidc.NewClient(p.Roots).Do(req)
	if err != nil {
		return Tokens{}, &UnreachableError{Issuer: p.Issuer, Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case err != nil:
		return Tokens{}, &UnreachableError{Issuer: p.Issuer, Err: err}
	case len(body) > maxBody:
		return Tokens{}, &UnreachableError{Issuer: p.Issuer, Err: errors.New("the token endpoint's answer is over 1 MiB")}
	case resp.StatusCode >= 500:
		return Tokens{}, &UnreachableError{Issuer: p.Issuer, Err: fmt.Errorf("the token endpoint answered %s", resp.Status)}
	case resp.StatusCode != http.StatusOK:
		var oe struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oe)
		return Tokens{}, &ProviderError{Issuer: p.Issuer, Status: resp.StatusCode,
			Code: printsafe.Line(oe.Error, 64), Description: printsafe.Line(oe.Description, 200)}
	}
	// Only id_token is read: a refresh token in the answer is not kept
	// (decision 43 ruling 6).
	var t struct {
		IDToken string `json:"id_token"`
	}
	if json.Unmarshal(body, &t) != nil {
		return Tokens{}, fmt.Errorf("%s: the token endpoint's answer is not a JSON object", p.Issuer)
	}
	if t.IDToken == "" {
		return Tokens{}, fmt.Errorf("%s: %w", p.Issuer, errNoIDToken)
	}
	id, err := oidc.ReadIDToken(t.IDToken, p.Issuer, p.ClientID, nonce)
	if err != nil {
		return Tokens{}, fmt.Errorf("%s: %w", p.Issuer, err)
	}
	return Tokens{ID: id, IDRaw: t.IDToken, Received: now().Round(0)}, nil
}
```

Create `internal/oidcclient/request.go`:

```go
package oidcclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// AuthorizationURL is the sign-in's request (decision 43 ruling 3) on e's
// authorization endpoint, keeping any query it already has: the code flow,
// the verifier's S256 challenge, state, nonce, the verifier's scopes with
// openid first, and prompt=login.
func AuthorizationURL(p Provider, e Endpoints, redirect, state, nonce, challenge string) (string, error) {
	u, err := url.Parse(e.Authorization)
	if err != nil {
		return "", fmt.Errorf("%s's authorization_endpoint: %w", p.Issuer, err)
	}
	q := u.Query()
	for k, v := range map[string]string{"response_type": "code", "client_id": p.ClientID, "redirect_uri": redirect,
		"scope": scopeOf(p), "state": state, "nonce": nonce, "code_challenge": challenge,
		"code_challenge_method": "S256", "prompt": "login"} {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// scopeOf is the scope a sign-in sends: the verifier's scopes, openid first
// when they leave it out (OIDC Core §3.1.2.1).
func scopeOf(p Provider) string {
	scopes := p.Scopes
	if !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	return strings.Join(scopes, " ")
}

// challengeOf is verifier's S256 code challenge (RFC 7636 §4.2).
func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// opaque is 32 random bytes, base64url: a verifier, a state or a nonce of
// 43 characters (RFC 7636 §4.1).
func opaque() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/oidc/... ./internal/oidcclient/ -count=1 && go test -race ./internal/oidcclient/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/oidc/client.go internal/oidc/client_test.go internal/oidcclient/
git commit -m "feat(oidcclient): read an ID token as a client, discovery and the code exchange"
```

---

### Task 4: The sign-in: the request, the loopback listener, and the pasted address

**Files:**
- Create: `internal/oidcclient/login.go`, `internal/oidcclient/login_test.go`

**Interfaces:**
- Consumes: Task 3's `Provider`, `Endpoints`, `Tokens`, `exchange`, `AuthorizationURL`,
  `challengeOf`, `opaque`; Task 2's `AuthServer`, `Issuer.Browser`, `Issuer.Redirected`;
  `printsafe.Line`.
- Produces, for Task 10:
  - `const SignInWait = 5 * time.Minute`; `var ErrNoWayBack error`
  - `type LoginOptions struct { Nonce string; Port int; Browser func(url string) error; Paste func() (string, error); Out io.Writer; Now func() time.Time }`
  - `func Login(ctx context.Context, p Provider, e Endpoints, o LoginOptions) (Tokens, error)`

- [ ] **Step 1: Write the failing tests**

Create `internal/oidcclient/login_test.go`:

```go
package oidcclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// credentialsNowhere fails if text holds any value the provider issued.
func credentialsNowhere(t *testing.T, text string, issued []string) {
	t.Helper()
	for _, v := range issued {
		if strings.Contains(text, v) {
			t.Fatalf("a code or token was printed")
		}
	}
}

// redirectOf is the redirect_uri an authorization URL names.
func redirectOf(t *testing.T, authURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	r, err := url.Parse(u.Query().Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The request is decision 43 ruling 3's, the redirect a loopback port, and
// the ID token the provider's; nothing printed holds a credential.
func TestASignInReturnsTheIDTokenForTheVerifier(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	var out bytes.Buffer
	got, err := Login(context.Background(), p, e, LoginOptions{Browser: iss.Browser(), Out: &out})
	if err != nil || got.ID.Subject != "sub-alice" || got.IDRaw == "" {
		t.Fatalf("%v %v\n%s", got, err, out.String())
	}
	q := as.Authorizations()[0]
	r, _ := url.Parse(q.Get("redirect_uri"))
	for k, want := range map[string]string{"response_type": "code", "client_id": "port49-cli", "scope": "openid",
		"code_challenge_method": "S256", "prompt": "login"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("code_challenge")) != 43 || len(q.Get("state")) != 43 || len(q.Get("nonce")) != 43 ||
		r.Scheme != "http" || r.Hostname() != "127.0.0.1" || r.Port() == "0" || r.Path != "/callback" {
		t.Fatalf("the request: challenge %d state %d nonce %d redirect %s", len(q.Get("code_challenge")),
			len(q.Get("state")), len(q.Get("nonce")), r)
	}
	if !strings.Contains(out.String(), "in the browser that opened") {
		t.Fatalf("%s", out.String())
	}
	credentialsNowhere(t, out.String(), as.Issued())
	// The listener is gone once Login returns.
	if c, err := net.DialTimeout("tcp", r.Host, time.Second); err == nil {
		c.Close()
		t.Fatalf("%s still listens", r.Host)
	}
}

// A nonce the caller gives (the key binding, decision 43 ruling 3) is the
// request's, and the ID token must echo it.
func TestTheGivenNonceIsSent(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	got, err := Login(context.Background(), p, e, LoginOptions{Nonce: "key-binding-n", Browser: iss.Browser()})
	if err != nil || got.ID.Nonce != "key-binding-n" || as.Authorizations()[0].Get("nonce") != "key-binding-n" {
		t.Fatalf("%v %v", got, err)
	}
}

// An answer with another state is refused and waited past: anyone on the
// host can reach the port (ruling 4).
func TestACallbackWithAnotherStateIsIgnored(t *testing.T) {
	iss, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	var status int
	browse := func(u string) error {
		r := redirectOf(t, u)
		resp, err := http.Get("http://" + r.Host + "/callback?state=forged&code=x")
		if err != nil {
			return err
		}
		resp.Body.Close()
		status = resp.StatusCode
		return iss.Browser()(u)
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: browse}); err != nil || status != 400 {
		t.Fatalf("forged answer %d, then %v", status, err)
	}
}

// An answer with this sign-in's state naming another issuer ends it (RFC
// 9207: a mix-up), and so does one with no iss from a provider that sends it.
func TestAnIssParameterNamingAnotherIssuerIsRefused(t *testing.T) {
	_, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	answer := func(extra string) func(string) error {
		return func(u string) error {
			v, _ := url.Parse(u)
			go func() {
				resp, err := http.Get(fmt.Sprintf("http://%s/callback?state=%s&code=x%s", redirectOf(t, u).Host,
					url.QueryEscape(v.Query().Get("state")), extra))
				if err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		}
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: answer("&iss=https%3A%2F%2Fevil.example")}); err == nil ||
		!strings.Contains(err.Error(), "RFC 9207") {
		t.Fatalf("another iss: %v", err)
	}
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: answer("")}); err == nil ||
		!strings.Contains(err.Error(), "carries no iss") {
		t.Fatalf("no iss from a provider that sends it: %v", err)
	}
}

// A provider's refusal is said by its code.
func TestADeniedSignInSaysTheProvidersCode(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	as.Deny("access_denied")
	// The browser opened: the 400 it ends on is port49's own page saying the
	// sign-in failed.
	browse := func(u string) error { _ = iss.Browser()(u); return nil }
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: browse}); err == nil ||
		!strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("%v", err)
	}
}

// With no browser the address is printed and a pasted one completes the
// sign-in; a paste that is not this sign-in's answer is refused, saying
// why, and asked again (ruling 5).
func TestAPastedAddressCompletesTheSignIn(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	authURL := make(chan string, 1)
	var mu sync.Mutex
	var out bytes.Buffer
	pastes := 0
	paste := func() (string, error) {
		mu.Lock()
		pastes++
		n := pastes
		mu.Unlock()
		u := <-authURL
		authURL <- u
		if n == 1 {
			return "http://example.com/elsewhere", nil
		}
		return iss.Redirected(u)
	}
	got, err := Login(context.Background(), p, e, LoginOptions{
		Browser: func(u string) error { authURL <- u; return errors.New("no display") },
		Paste:   paste, Out: &lockedWriter{mu: &mu, w: &out}})
	mu.Lock()
	text := out.String()
	mu.Unlock()
	if err != nil || got.ID.Subject != "sub-alice" {
		t.Fatalf("%v %v\n%s", got, err, text)
	}
	for _, want := range []string{"open this address in a browser", "paste it here (it is not shown)",
		"that is not the address the sign-in was sent back to", "paste the address again"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in %s", want, text)
		}
	}
	credentialsNowhere(t, text, as.Issued())
}

// A fixed port is the one the redirect names (oidc_redirect_port).
func TestAFixedPortIsUsed(t *testing.T) {
	iss, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, err := Login(context.Background(), p, e, LoginOptions{Port: port, Browser: iss.Browser()}); err != nil {
		t.Fatal(err)
	}
	if r, _ := url.Parse(as.Authorizations()[0].Get("redirect_uri")); r.Port() != fmt.Sprint(port) {
		t.Fatalf("redirect %s, want port %d", r, port)
	}
}

// A cancelled sign-in stops listening and says so.
func TestACancelledSignInStops(t *testing.T) {
	_, _, p := provider(t)
	e, _ := Discover(context.Background(), p)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Login(ctx, p, e, LoginOptions{Browser: func(string) error { return nil }}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

// No browser, no terminal and an ephemeral port is said at once; with a
// fixed port, which ssh -L can forward, the sign-in waits and says how
// (ruling 5).
func TestNoBrowserAndNoTerminalIsSaidAtOnce(t *testing.T) {
	_, as, p := provider(t)
	e, _ := Discover(context.Background(), p)
	none := func(string) error { return errors.New("no display") }
	start := time.Now()
	var out bytes.Buffer
	if _, err := Login(context.Background(), p, e, LoginOptions{Browser: none, Out: &out}); !errors.Is(err, ErrNoWayBack) ||
		time.Since(start) > 5*time.Second || out.Len() != 0 {
		t.Fatalf("%v after %s, printed %q", err, time.Since(start), out.String())
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Login(ctx, p, e, LoginOptions{Browser: none, Port: port, Out: &out}); !errors.Is(err, context.DeadlineExceeded) ||
		!strings.Contains(out.String(), fmt.Sprintf("ssh -L %d:127.0.0.1:%d", port, port)) {
		t.Fatalf("a fixed port: %v\n%s", err, out.String())
	}
	if n := len(as.Authorizations()); n != 0 {
		t.Fatalf("%d authorizations with no browser", n)
	}
}

// lockedWriter serializes writes from Login and its paste reader.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/oidcclient/ -run 'TestASignIn|TestTheGivenNonce|TestACallback|TestAnIssParameter|TestADenied|TestAPasted|TestAFixedPort|TestACancelled|TestNoBrowserAndNoTerminal' -count=1`
Expected: FAIL to build: `undefined: Login`, `undefined: LoginOptions`, `undefined: ErrNoWayBack`.

- [ ] **Step 3: `internal/oidcclient/login.go`**

```go
package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/printsafe"
)

// SignInWait is how long a sign-in waits for the browser, and how old a
// sign-in's authentication may be when the broker exchanges it for a
// certificate (spec §13 decision 43 ruling 8).
const SignInWait = 5 * time.Minute

// ErrNoWayBack is a sign-in that cannot complete: no browser opened on this
// host, stdin is no terminal to paste the address into, and the port is an
// ephemeral one no ssh -L could have forwarded (decision 43 ruling 5). It is
// said at once, not after SignInWait.
var ErrNoWayBack = errors.New("no browser opened on this host and stdin is not a terminal to paste the address " +
	"into, so the sign-in's answer has no way back to port49")

// LoginOptions is one sign-in.
type LoginOptions struct {
	// Nonce is the request's nonce: the key binding a login sends
	// (api.IssuanceNonce; decision 43 ruling 3), or "" for one drawn here.
	Nonce string
	// Port is the loopback listener's; 0 is an ephemeral one (RFC 8252 §7.3).
	Port int
	// Browser opens the authorization URL; nil, or an error, means no
	// browser opened.
	Browser func(url string) error
	// Paste, when not nil, reads one address the browser ended on, from a
	// terminal and not echoed (decision 43 ruling 5).
	Paste func() (string, error)
	// Out is where the address and the waiting line go: stderr.
	Out io.Writer
	Now func() time.Time
}

// Login runs one sign-in (decision 43 rulings 1, 3–5): the authorization
// request with PKCE (S256) and prompt=login, its answer taken at a
// 127.0.0.1 listener or pasted, and the code exchanged. The authorization
// URL is printed to o.Out: it carries state, the nonce and the
// code_challenge, none a credential, since the code is bound to the
// verifier this call holds; but whoever holds its state can complete this
// sign-in with their own account, so the caller says whom it signed in as
// (ruling 20). With no way for the answer to come back, it is ErrNoWayBack
// at once.
func Login(ctx context.Context, p Provider, e Endpoints, o LoginOptions) (Tokens, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	verifier, state, nonce := opaque(), opaque(), o.Nonce
	if nonce == "" {
		nonce = opaque()
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port)))
	if err != nil {
		return Tokens{}, fmt.Errorf("listening on 127.0.0.1:%d for the sign-in's answer: %w", o.Port, err)
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	authURL, err := AuthorizationURL(p, e, redirect, state, nonce, challengeOf(verifier))
	if err != nil {
		ln.Close()
		return Tokens{}, err
	}
	w := &waiter{state: state, issuer: p.Issuer, requireIss: e.IssParameter, redirect: redirect,
		done: make(chan answer, 1)}
	srv := &http.Server{Handler: w, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	opened := o.Browser != nil && o.Browser(authURL) == nil
	switch {
	case opened:
		fmt.Fprintf(o.Out, "port49: sign in at %s in the browser that opened; if none did, open this address:\n  %s\n",
			p.Issuer, authURL)
	case o.Paste == nil && o.Port == 0:
		// No browser here, no terminal to paste into, and a port no ssh -L
		// can name in advance: nothing can bring the answer back.
		return Tokens{}, ErrNoWayBack
	default:
		fmt.Fprintf(o.Out, "port49: open this address in a browser and sign in at %s:\n  %s\n", p.Issuer, authURL)
	}
	switch {
	case o.Paste != nil:
		fmt.Fprintf(o.Out, "port49: waiting up to %s. If the browser ends on a page that cannot be reached (it runs on "+
			"another host), copy that page's address and paste it here (it is not shown), then press Enter:\n", SignInWait)
		go w.readPastes(o.Paste, o.Out)
	case !opened:
		fmt.Fprintf(o.Out, "port49: waiting up to %s for the browser to come back to %s; from another host, forward "+
			"that port first (ssh -L %d:127.0.0.1:%d)\n", SignInWait, redirect, o.Port, o.Port)
	}
	wait, cancel := context.WithTimeout(ctx, SignInWait)
	defer cancel()
	var a answer
	select {
	case a = <-w.done:
	case <-wait.Done():
		if ctx.Err() != nil {
			return Tokens{}, ctx.Err()
		}
		return Tokens{}, fmt.Errorf("no sign-in answer reached port49 within %s; run the command again", SignInWait)
	}
	if a.err != nil {
		return Tokens{}, a.err
	}
	return exchange(ctx, p, e, a.code, redirect, verifier, nonce, o.Now)
}

// answer is a sign-in's outcome: a code, or why there is none.
type answer struct {
	code string
	err  error
}

// waiter takes the provider's answer at /callback, or pasted. The first
// answer carrying this sign-in's state ends the wait; one carrying another
// state is refused and waited past, since anyone on the host can reach the
// port (decision 43 ruling 4).
type waiter struct {
	state, issuer, redirect string
	requireIss              bool
	once                    sync.Once
	done                    chan answer
}

func (w *waiter) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method != http.MethodGet || r.URL.Path != "/callback" {
		http.NotFound(rw, r)
		return
	}
	a, ours := w.judge(r.URL.Query())
	if !ours {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(rw, "port49: this is not the sign-in port49 is waiting for; nothing was done.")
		return
	}
	w.deliver(a)
	if a.err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(rw, "port49: the sign-in failed; your terminal says why.")
		return
	}
	fmt.Fprintln(rw, "port49: signed in. You can close this tab and go back to your terminal.")
}

// deliver hands the first answer to Login; later ones are dropped.
func (w *waiter) deliver(a answer) { w.once.Do(func() { w.done <- a }) }

// judge reads one answer's query (RFC 6749 §4.1.2, RFC 9207 §2.4). ours is
// whether it carries this sign-in's state, and only then is it judged.
func (w *waiter) judge(q url.Values) (answer, bool) {
	if len(q["state"]) != 1 || q.Get("state") != w.state {
		return answer{}, false
	}
	switch iss, has := q.Get("iss"), q.Has("iss"); {
	case has && iss != w.issuer:
		return answer{err: fmt.Errorf("the sign-in's answer names the issuer %q, not %s: it came from another "+
			"provider (RFC 9207), so it is refused", printsafe.Line(iss, 200), w.issuer)}, true
	case !has && w.requireIss:
		return answer{err: fmt.Errorf("the sign-in's answer carries no iss, which %s says it always sends (RFC 9207), "+
			"so it is refused", w.issuer)}, true
	}
	if e := q.Get("error"); e != "" {
		msg := fmt.Sprintf("%s refused the sign-in: %s", w.issuer, printsafe.Line(e, 64))
		if d := q.Get("error_description"); d != "" {
			msg += ": " + printsafe.Line(d, 200)
		}
		return answer{err: errors.New(msg)}, true
	}
	if len(q["code"]) != 1 || q.Get("code") == "" {
		return answer{err: errors.New("the sign-in's answer carries no code")}, true
	}
	return answer{code: q.Get("code")}, true
}

// readPastes reads pasted addresses until one is this sign-in's answer, or
// paste fails (the terminal closed). Nothing pasted is printed.
func (w *waiter) readPastes(paste func() (string, error), out io.Writer) {
	for {
		s, err := paste()
		if err != nil {
			return
		}
		a, why := w.pasted(s)
		if why != "" {
			fmt.Fprintf(out, "port49: %s; paste the address again:\n", why)
			continue
		}
		w.deliver(a)
		return
	}
}

// pasted is one pasted address as an answer, or why it is not one.
func (w *waiter) pasted(s string) (answer, string) {
	u, err := url.Parse(strings.TrimSpace(s))
	want, _ := url.Parse(w.redirect)
	if err != nil || u.Scheme != want.Scheme || u.Host != want.Host || u.Path != want.Path {
		return answer{}, "that is not the address the sign-in was sent back to (" + w.redirect + "?…)"
	}
	a, ours := w.judge(u.Query())
	if !ours {
		return answer{}, "that address answers another sign-in (its state is not this one's)"
	}
	return a, ""
}
```

`AuthorizationURL`, `challengeOf` and `opaque` are Task 3's, in `request.go`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/oidcclient/ -count=1 && go test -race ./internal/oidcclient/ -count=1 && go vet ./internal/oidcclient/`
Expected: PASS, and vet silent.

- [ ] **Step 5: Commit**

```bash
git add internal/oidcclient/login.go internal/oidcclient/login_test.go
git commit -m "feat(oidcclient): the sign-in over a loopback redirect with PKCE, state, nonce and iss, and a pasted address"
```

---

### Task 5: The issuing CA, the sign-in a certificate carries, and the wire types

**Files:**
- Create: `internal/issuer/issuer.go`, `internal/issuer/signin.go`, `internal/issuer/issuer_test.go`
- Create: `internal/broker/api/issue.go`, `internal/broker/api/issue_test.go`
- Modify: `internal/broker/api/api.go` (`Config.Issuance`)

**Interfaces:**
- Consumes: the standard library alone.
- Produces, for Tasks 6–12:
  - `const issuer.CertFile, KeyFile, NextCertFile, NextKeyFile, PreviousCertFile`;
    `issuer.DefaultLifetime`, `MinLifetime`, `MaxLifetime`
  - `func issuer.New(now time.Time) (certPEM, keyPEM []byte, err error)`
  - `type issuer.Files struct { Cert, Key func(name string) ([]byte, error) }`; `func issuer.Mem(m map[string][]byte) Files`
  - `type issuer.CA struct { Cert *x509.Certificate; Trusted []*x509.Certificate; Unavailable error; … }`
  - `func issuer.Load(f Files, now time.Time) (*CA, []string)`; `func issuer.Ephemeral(now time.Time) (*CA, error)`
  - `func (c *CA) Issue(pub crypto.PublicKey, s SignIn, now time.Time, lifetime time.Duration) (*x509.Certificate, error)`
  - `func (c *CA) Ends(chains [][]*x509.Certificate) (issued, mixed bool)` (nil-safe)
  - `func (c *CA) PEM(cert *x509.Certificate) []byte`; `func issuer.Fingerprint(c *x509.Certificate) string`
  - `type issuer.SignIn struct { Principal, Issuer, Subject, Sid string; AMR []string; ACR string; AuthTime, IssuedAt time.Time }`;
    `func (s SignIn) URI() *url.URL`; `func issuer.ReadSignIn(leaf *x509.Certificate) (SignIn, error)`
  - `func api.IssuanceNonce(pub crypto.PublicKey) (string, error)`
  - `type api.IssueRequest struct { CSR string }`; `type api.IssueResponse struct { Certificate, Principal, Serial, NotAfter string }`
  - `type api.Issuance struct { CertificateLifetimeSeconds int }`; `api.Config.Issuance *Issuance`

- [ ] **Step 1: Write the failing tests**

Create `internal/issuer/issuer_test.go`:

```go
package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// files is a new CA's two files.
func files(t *testing.T, now time.Time) map[string][]byte {
	t.Helper()
	c, k, err := New(now)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{CertFile: c, KeyFile: k}
}

// alice is a sign-in whose sid needs escaping in a URI.
func alice(now time.Time) SignIn {
	return SignIn{Principal: "user:alice@example.com", Issuer: "https://kc.example/realms/corp", Subject: "sub-alice",
		Sid: "s&1=2", AMR: []string{"pwd", "otp"}, ACR: "1", AuthTime: now.Add(-time.Minute), IssuedAt: now}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A new CA loads, issues a client certificate that verifies against it, and
// the certificate carries its sign-in (decision 43 ruling 9).
func TestNewLoadAndIssue(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	c, lines := Load(Mem(files(t, now)), now)
	if c.Unavailable != nil || len(c.Trusted) != 1 || len(lines) != 1 || !strings.HasPrefix(lines[0], "issuing as ") {
		t.Fatalf("%v %q", c.Unavailable, lines)
	}
	s := alice(now)
	cert, err := c.Issue(newKey(t).Public(), s, now, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cert.Subject.CommonName != s.Principal || !cert.NotAfter.Equal(now.Add(12*time.Hour)) ||
		!cert.NotBefore.Equal(now.Add(-time.Minute)) || len(cert.EmailAddresses) != 0 || cert.SerialNumber.Sign() <= 0 {
		t.Fatalf("CN %q, %s to %s, emails %v, serial %v", cert.Subject.CommonName, cert.NotBefore, cert.NotAfter,
			cert.EmailAddresses, cert.SerialNumber)
	}
	got, err := ReadSignIn(cert)
	if err != nil || got.Principal != s.Principal || got.Issuer != s.Issuer || got.Subject != s.Subject ||
		got.Sid != s.Sid || got.ACR != s.ACR || !reflect.DeepEqual(got.AMR, s.AMR) ||
		!got.AuthTime.Equal(s.AuthTime) || !got.IssuedAt.Equal(s.IssuedAt) {
		t.Fatalf("%+v %v", got, err)
	}
	if issued, mixed := c.Ends([][]*x509.Certificate{{cert, c.Cert}}); !issued || mixed {
		t.Fatalf("issued %v mixed %v", issued, mixed)
	}
	if p := string(c.PEM(cert)); strings.Count(p, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("the chain: %s", p)
	}
}

// A certificate never outlives the CA that issued it.
func TestACertificateNeverOutlivesItsCA(t *testing.T) {
	now := time.Now()
	c, err := Ephemeral(now)
	if err != nil {
		t.Fatal(err)
	}
	late := c.Cert.NotAfter.Add(-time.Hour)
	cert, err := c.Issue(newKey(t).Public(), alice(late), late, 12*time.Hour)
	if err != nil || !cert.NotAfter.Equal(c.Cert.NotAfter) {
		t.Fatalf("%v %v", cert.NotAfter, err)
	}
}

// What is missing or unusable is said, and a start goes on: a missing key
// stops issuance and keeps trust; a missing CA stops both (ruling 14).
func TestLoadSaysWhatIsMissing(t *testing.T) {
	now := time.Now()
	c, lines := Load(Mem(nil), now)
	if c.Unavailable == nil || len(c.Trusted) != 0 || !strings.Contains(strings.Join(lines, "\n"), "run init-issuer once") {
		t.Fatalf("no files: %v %q", c.Unavailable, lines)
	}
	if _, err := c.Issue(newKey(t).Public(), alice(now), now, time.Hour); err == nil {
		t.Fatal("a CA with no files issued")
	}
	m := files(t, now)
	delete(m, KeyFile)
	c, lines = Load(Mem(m), now)
	if c.Unavailable == nil || len(c.Trusted) != 1 ||
		!strings.Contains(strings.Join(lines, "\n"), "the certificates already issued are trusted") {
		t.Fatalf("no key: %v %q", c.Unavailable, lines)
	}
	m[KeyFile] = files(t, now)[KeyFile]
	if c, _ = Load(Mem(m), now); c.Unavailable == nil || !strings.Contains(c.Unavailable.Error(), "not the key of") {
		t.Fatalf("another CA's key: %v", c.Unavailable)
	}
	if c, _ = Load(Mem(files(t, now)), now.Add(6*365*24*time.Hour)); c.Unavailable == nil ||
		!strings.Contains(c.Unavailable.Error(), "expired") || len(c.Trusted) != 0 {
		t.Fatalf("an expired CA: %v %d", c.Unavailable, len(c.Trusted))
	}
	f := Mem(files(t, now))
	f.Key = func(string) ([]byte, error) { return nil, errors.New("permission denied") }
	if c, _ = Load(f, now); c.Unavailable == nil || !strings.Contains(c.Unavailable.Error(), "permission denied") {
		t.Fatalf("an unreadable key: %v", c.Unavailable)
	}
}

// The staged next CA and the previous one are trusted, and only the current
// signs (ruling 14).
func TestTheNextAndPreviousAreTrustedNotSigning(t *testing.T) {
	now := time.Now()
	m := files(t, now)
	next, prev := files(t, now), files(t, now)
	m[NextCertFile], m[NextKeyFile], m[PreviousCertFile] = next[CertFile], next[KeyFile], prev[CertFile]
	c, lines := Load(Mem(m), now)
	if c.Unavailable != nil || len(c.Trusted) != 3 || !strings.Contains(strings.Join(lines, "\n"), "remove "+PreviousCertFile) {
		t.Fatalf("%v %d %q", c.Unavailable, len(c.Trusted), lines)
	}
	cert, err := c.Issue(newKey(t).Public(), alice(now), now, time.Hour)
	if err != nil || cert.CheckSignatureFrom(c.Cert) != nil || cert.CheckSignatureFrom(c.Trusted[1]) == nil {
		t.Fatalf("signed by the current alone: %v", err)
	}
}

// A connection whose chains end at the CA and at another anchor is mixed,
// which the broker refuses; a nil CA issued nothing.
func TestEndsRefusesAMixedChain(t *testing.T) {
	now := time.Now()
	c, _ := Ephemeral(now)
	o, _ := Ephemeral(now)
	leaf := &x509.Certificate{}
	if issued, mixed := c.Ends([][]*x509.Certificate{{leaf, c.Cert}, {leaf, o.Cert}}); issued || !mixed {
		t.Fatalf("both: issued %v mixed %v", issued, mixed)
	}
	if issued, mixed := c.Ends([][]*x509.Certificate{{leaf, o.Cert}}); issued || mixed {
		t.Fatalf("another's: issued %v mixed %v", issued, mixed)
	}
	var none *CA
	if issued, mixed := none.Ends([][]*x509.Certificate{{leaf, c.Cert}}); issued || mixed {
		t.Fatalf("no CA: issued %v mixed %v", issued, mixed)
	}
}

// ReadSignIn reads only what this CA issues.
func TestReadSignInRefusesWhatItDidNotIssue(t *testing.T) {
	now := time.Now()
	good := alice(now).URI()
	with := func(edit func(url.Values)) *url.URL {
		u := *good
		q := u.Query()
		edit(q)
		u.RawQuery = q.Encode()
		return &u
	}
	mk := func(cn string, uris []*url.URL, emails []string) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: cn}, URIs: uris, EmailAddresses: emails}
	}
	const p = "user:alice@example.com"
	for name, c := range map[string]struct {
		cert *x509.Certificate
		want string
	}{
		"an email SAN":           {mk(p, []*url.URL{good}, []string{"alice@example.com"}), "email"},
		"no URI":                 {mk(p, nil, nil), "no port49-sign-in"},
		"two URIs":               {mk(p, []*url.URL{good, good}, nil), "more than one"},
		"another scheme":         {mk(p, []*url.URL{{Scheme: "spiffe", Host: "x", Path: "/y"}}, nil), "no port49-sign-in"},
		"an unknown member":      {mk(p, []*url.URL{with(func(q url.Values) { q.Set("role", "admin") })}, nil), "unknown member"},
		"sub twice":              {mk(p, []*url.URL{with(func(q url.Values) { q.Add("sub", "b") })}, nil), "twice"},
		"no sub":                 {mk(p, []*url.URL{with(func(q url.Values) { q.Del("sub") })}, nil), "sub"},
		"a CN that is no user":   {mk("alice@example.com", []*url.URL{good}, nil), "principal"},
		"an http issuer":         {mk(p, []*url.URL{with(func(q url.Values) { q.Set("iss", "http://kc") })}, nil), "iss"},
		"auth_time not a number": {mk(p, []*url.URL{with(func(q url.Values) { q.Set("auth_time", "x") })}, nil), "auth_time"},
	} {
		if _, err := ReadSignIn(c.cert); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
```

Create `internal/broker/api/issue_test.go`:

```go
package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// The nonce names one key: 43 base64url characters, the same for the same
// key, another for another (decision 43 ruling 3).
func TestIssuanceNonceNamesTheKey(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	na, err := IssuanceNonce(a.Public())
	nb, _ := IssuanceNonce(b.Public())
	na2, _ := IssuanceNonce(a.Public())
	if err != nil || len(na) != 43 || na == nb || na != na2 {
		t.Fatalf("%q %q %q %v", na, nb, na2, err)
	}
	if _, err := IssuanceNonce("not a key"); err == nil {
		t.Fatal("a value that is no key named one")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/issuer/ ./internal/broker/api/ -count=1`
Expected: FAIL to build: `no Go files in internal/issuer` (or `undefined: Load`), `undefined:
IssuanceNonce`.

- [ ] **Step 3: `internal/issuer/issuer.go`**

```go
// Package issuer is the broker's issuing CA (plan 9b; spec §13 decision
// 43): the short-lived client certificates it issues a person over an OIDC
// sign-in, and the files the CA is kept in. port49 is a relying party, not a
// certificate authority, but for these: they are port49's own trust
// domain's, no device sees one, and only the broker trusts them.
package issuer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// The files, in the broker's state directory (decision 43 ruling 14).
const (
	CertFile         = "issuing-ca.pem"
	KeyFile          = "issuing-ca.key"
	NextCertFile     = "issuing-ca-next.pem"
	NextKeyFile      = "issuing-ca-next.key"
	PreviousCertFile = "issuing-ca-previous.pem"
)

// broker.identity.issuance.certificate_lifetime's default and bounds
// (decision 43 ruling 9).
const (
	DefaultLifetime = 12 * time.Hour
	MinLifetime     = time.Hour
	MaxLifetime     = 24 * time.Hour
)

// caLife is a new issuing CA's validity; a rotation replaces it long before.
const caLife = 5 * 365 * 24 * time.Hour

// New is a new issuing CA: a P-256 key, and a certificate it signs itself,
// valid caLife from now, named "port49 issuing CA" and 8 random hex digits,
// both PEM (the key PKCS #8).
func New(now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var tag [4]byte
	if _, err := rand.Read(tag[:]); err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{Organization: []string{"port49"}, CommonName: "port49 issuing CA " + hex.EncodeToString(tag[:])},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(caLife),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), nil
}

// newSerial is 128 random bits, never zero.
func newSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// Files reads the CA's files by name, from wherever the broker keeps them:
// (nil, nil) for a file that is not there.
type Files struct {
	Cert func(name string) ([]byte, error)
	Key  func(name string) ([]byte, error)
}

// Mem is Files over m, for tests and Ephemeral: a name m lacks is no file.
func Mem(m map[string][]byte) Files {
	get := func(name string) ([]byte, error) { return m[name], nil }
	return Files{Cert: get, Key: get}
}

// CA is the issuing CA as a broker holds it.
type CA struct {
	// Cert is the CA that signs, from CertFile; nil when there is none
	// usable.
	Cert *x509.Certificate
	// Trusted is every CA a chain may end at: Cert, the staged next and the
	// previous, those present (decision 43 ruling 14).
	Trusted []*x509.Certificate
	// Unavailable is why Issue refuses: nil when it issues.
	Unavailable error

	signer crypto.Signer
}

// Fingerprint is "sha256:" and the hex SHA-256 of c's DER, as the broker's
// records name a certificate.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Load reads the CA's files (decision 43 ruling 14). It never fails: a
// broker that cannot issue still starts and serves everything else, since
// port49d answers device AAA in the same process, and Unavailable says why
// nothing is issued. lines are what the start says, one fact each.
func Load(f Files, now time.Time) (*CA, []string) {
	c := &CA{}
	var lines []string
	cert, err := readCA(f, CertFile)
	switch {
	case err != nil:
		c.Unavailable = fmt.Errorf("%s is not usable: %v", CertFile, err)
		lines = append(lines, fmt.Sprintf("%s is not usable (%v), so no certificate is issued and none it issued is "+
			"trusted; fix it and restart", CertFile, err))
	case cert == nil:
		c.Unavailable = fmt.Errorf("%s is missing", CertFile)
		lines = append(lines, CertFile+" is missing, so no certificate is issued and none it issued is trusted: on a "+
			"first install run init-issuer once, as the broker's user; on each further broker on this store, copy "+
			CertFile+" and "+KeyFile+" from the first into its broker.state_dir")
	case !now.Before(cert.NotAfter):
		c.Unavailable = fmt.Errorf("%s expired at %s", CertFile, rfc(cert.NotAfter))
		lines = append(lines, fmt.Sprintf("%s expired at %s, so no certificate is issued and none it issued is "+
			"trusted: run rotate-issuer twice, restarting every broker after each, to make and promote another",
			CertFile, rfc(cert.NotAfter)))
	default:
		c.Cert = cert
		c.Trusted = append(c.Trusted, cert)
		if c.signer, err = readKey(f, KeyFile, cert); err != nil {
			c.Unavailable = fmt.Errorf("%s is not usable: %v", KeyFile, err)
			lines = append(lines, fmt.Sprintf("%s is not usable (%v), so no certificate is issued; the certificates "+
				"already issued are trusted; restore it beside %s (0600, the broker's user's) and restart",
				KeyFile, err, CertFile))
		}
	}
	for _, o := range []struct{ name, what string }{{NextCertFile, "the staged next CA"},
		{PreviousCertFile, "the previous CA"}} {
		cert, err := readCA(f, o.name)
		switch {
		case err != nil:
			lines = append(lines, fmt.Sprintf("%s is not usable (%v), so %s is not trusted", o.name, err, o.what))
		case cert != nil:
			c.Trusted = append(c.Trusted, cert)
			line := fmt.Sprintf("trusting %s too, %s (%s), valid until %s", o.what, cert.Subject, Fingerprint(cert),
				rfc(cert.NotAfter))
			if o.name == PreviousCertFile {
				line += "; remove " + PreviousCertFile + " once every certificate it issued has expired " +
					"(certificate_lifetime after the promotion), and restart"
			}
			lines = append(lines, line)
		}
	}
	if c.Unavailable == nil {
		lines = append([]string{fmt.Sprintf("issuing as %s (%s), valid until %s", c.Cert.Subject,
			Fingerprint(c.Cert), rfc(c.Cert.NotAfter))}, lines...)
	}
	return c, lines
}

// readCA is the one CA certificate in the PEM file name; nil for no file.
func readCA(f Files, name string) (*x509.Certificate, error) {
	raw, err := f.Cert(name)
	if err != nil || raw == nil {
		return nil, err
	}
	blk, rest := pem.Decode(raw)
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not one PEM certificate")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	if !c.BasicConstraintsValid || !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("not a CA certificate")
	}
	return c, nil
}

// readKey is the PKCS #8 key in name, which must be cert's.
func readKey(f Files, name string, cert *x509.Certificate) (crypto.Signer, error) {
	raw, err := f.Key(name)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("missing")
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PEM PKCS #8 private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	pub, okPub := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !okPub || !pub.Equal(s.Public()) {
		return nil, fmt.Errorf("it is not the key of %s", CertFile)
	}
	return s, nil
}

// Ephemeral is a new CA held in memory alone (New, then Load over Mem): for
// tests.
func Ephemeral(now time.Time) (*CA, error) {
	certPEM, keyPEM, err := New(now)
	if err != nil {
		return nil, err
	}
	c, _ := Load(Mem(map[string][]byte{CertFile: certPEM, KeyFile: keyPEM}), now)
	return c, c.Unavailable
}

// Issue signs a client certificate for pub over s (decision 43 ruling 9):
// CN the principal, one URI SAN carrying the sign-in (SignIn.URI),
// clientAuth, valid from a minute before now for lifetime, and never past
// the CA's own end.
func (c *CA) Issue(pub crypto.PublicKey, s SignIn, now time.Time, lifetime time.Duration) (*x509.Certificate, error) {
	switch {
	case c == nil:
		return nil, errors.New("issuer: no issuing CA")
	case c.Unavailable != nil:
		return nil, c.Unavailable
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(c.Cert.NotAfter) {
		notAfter = c.Cert.NotAfter
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: s.Principal},
		URIs: []*url.URL{s.URI()}, NotBefore: now.Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Ends reports whether chains, a connection's verified chains, end at a CA
// c trusts: issued when every one does, mixed when some do and some do not,
// which the broker refuses (decision 43 ruling 10). A nil c issued nothing.
func (c *CA) Ends(chains [][]*x509.Certificate) (issued, mixed bool) {
	if c == nil || len(c.Trusted) == 0 {
		return false, false
	}
	var ours, other bool
	for _, ch := range chains {
		if len(ch) == 0 {
			continue
		}
		if c.trusts(ch[len(ch)-1]) {
			ours = true
		} else {
			other = true
		}
	}
	return ours && !other, ours && other
}

func (c *CA) trusts(cert *x509.Certificate) bool {
	for _, t := range c.Trusted {
		if bytes.Equal(t.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

// PEM is cert, then the CA that signs, as POST /v1/certificate answers it.
func (c *CA) PEM(cert *x509.Certificate) []byte {
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})...)
}
```

- [ ] **Step 4: `internal/issuer/signin.go`**

```go
package issuer

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SignIn is the OIDC sign-in a certificate was issued on (decision 43
// rulings 9 and 16): whom the provider authenticated, when, and the
// provider's session, which a back-channel logout names.
type SignIn struct {
	Principal string
	Issuer    string
	Subject   string
	Sid       string
	AMR       []string
	ACR       string
	AuthTime  time.Time
	IssuedAt  time.Time
}

// signInScheme is the URI SAN's scheme. The URI is port49's own, read by the
// broker that issued it and by nothing else.
const signInScheme = "port49-sign-in"

// signInMembers are the URI's query members; amr alone may repeat.
var signInMembers = []string{"iss", "sub", "sid", "auth_time", "iat", "amr", "acr"}

// URI is s as the certificate's one URI SAN (spec §13 decision 43 ruling 9,
// R1): port49-sign-in:v1?iss=…&sub=…&auth_time=…&iat=…, with sid, acr and
// each amr when present. The principal is the subject's CN.
func (s SignIn) URI() *url.URL {
	q := url.Values{"iss": {s.Issuer}, "sub": {s.Subject}, "auth_time": {strconv.FormatInt(s.AuthTime.Unix(), 10)},
		"iat": {strconv.FormatInt(s.IssuedAt.Unix(), 10)}}
	if s.Sid != "" {
		q.Set("sid", s.Sid)
	}
	if s.ACR != "" {
		q.Set("acr", s.ACR)
	}
	for _, m := range s.AMR {
		q.Add("amr", m)
	}
	return &url.URL{Scheme: signInScheme, Opaque: "v1", RawQuery: q.Encode()}
}

// ReadSignIn reads the sign-in leaf was issued on: its subject's CN the
// principal, and its one URI SAN, port49-sign-in:v1, each member by its
// exact name and once (amr may repeat). Anything else is refused: this CA
// issues nothing else, so a leaf that differs is not one of its.
func ReadSignIn(leaf *x509.Certificate) (SignIn, error) {
	switch {
	case len(leaf.EmailAddresses) != 0 || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0:
		return SignIn{}, errors.New("it carries an email, DNS or IP SAN, which port49 never issues")
	case len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != signInScheme || leaf.URIs[0].Opaque != "v1":
		return SignIn{}, errors.New("it carries no port49-sign-in:v1 URI, or more than one URI")
	}
	q, err := url.ParseQuery(leaf.URIs[0].RawQuery)
	if err != nil {
		return SignIn{}, fmt.Errorf("its sign-in URI does not parse: %v", err)
	}
	for k, v := range q {
		switch {
		case !slices.Contains(signInMembers, k):
			return SignIn{}, fmt.Errorf("its sign-in URI has an unknown member %q", k)
		case k != "amr" && len(v) != 1:
			return SignIn{}, fmt.Errorf("its sign-in URI names %s twice", k)
		}
	}
	s := SignIn{Principal: leaf.Subject.CommonName, Issuer: q.Get("iss"), Subject: q.Get("sub"), Sid: q.Get("sid"),
		ACR: q.Get("acr"), AMR: q["amr"]}
	at, errAt := strconv.ParseInt(q.Get("auth_time"), 10, 64)
	iat, errIat := strconv.ParseInt(q.Get("iat"), 10, 64)
	switch {
	case !printable(s.Principal) || !strings.HasPrefix(s.Principal, "user:") || !strings.Contains(s.Principal, "@"):
		return SignIn{}, errors.New("its subject CN is not a principal (user: and an address)")
	case !printable(s.Issuer) || !strings.HasPrefix(s.Issuer, "https://"):
		return SignIn{}, errors.New("its sign-in's iss is not an https URL")
	case !printable(s.Subject):
		return SignIn{}, errors.New("its sign-in has no usable sub")
	case errAt != nil || errIat != nil:
		return SignIn{}, errors.New("its sign-in's auth_time or iat is not a number")
	case s.Sid != "" && !printable(s.Sid), s.ACR != "" && !printable(s.ACR),
		slices.ContainsFunc(s.AMR, func(m string) bool { return !printable(m) }):
		return SignIn{}, errors.New("its sign-in's sid, amr or acr is not printable")
	}
	s.AuthTime, s.IssuedAt = time.Unix(at, 0), time.Unix(iat, 0)
	return s, nil
}

// printable is 1 to 1024 bytes of printable ASCII, no space.
func printable(s string) bool {
	return s != "" && len(s) <= 1024 && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}
```

- [ ] **Step 5: `internal/broker/api/issue.go` and `Config.Issuance`**

Create `internal/broker/api/issue.go`:

```go
package api

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// issuanceNonceLabel prefixes the key a sign-in's nonce names, so the hash
// is one no other use of the key's bytes makes.
const issuanceNonceLabel = "port49 issue v1\x00"

// IssuanceNonce is the nonce a sign-in for a port49-issued certificate sends
// (spec §13 decision 43 ruling 3): the base64url SHA-256 of a label and the
// key's PKIX DER. The broker issues a certificate only for the key the ID
// token's nonce names, so a token taken in flight certifies no other key.
func IssuanceNonce(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(issuanceNonceLabel))
	h.Write(der)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// IssueRequest is POST /v1/certificate's body: the key's PKCS #10 request,
// base64url DER. Its subject is not read; its signature proves the key.
type IssueRequest struct {
	CSR string `json:"csr"`
}

// IssueResponse is POST /v1/certificate's answer (decision 43 ruling 8).
type IssueResponse struct {
	// Certificate is PEM: the certificate, then the issuing CA's.
	Certificate string `json:"certificate"`
	Principal   string `json:"principal"`
	// Serial is as `port49 revoke --cert-serial` takes it.
	Serial   string `json:"serial"`
	NotAfter string `json:"not_after"`
}

// Issuance is /v1/config's word that the broker issues certificates over an
// OIDC sign-in (decision 43 ruling 18).
type Issuance struct {
	CertificateLifetimeSeconds int `json:"certificate_lifetime_seconds"`
}
```

In `internal/broker/api/api.go`, in `Config`, after the `OIDC []OIDCProvider` field, add:

```go
	// Issuance is set when the broker issues a person a certificate over an
	// OIDC sign-in (plan 9b; spec §13 decision 43 ruling 18).
	Issuance *Issuance `json:"issuance,omitempty"`
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/issuer/ ./internal/broker/api/ -count=1 && go test -race ./internal/issuer/ -count=1 && go vet ./internal/issuer/`
Expected: PASS, and vet silent.

- [ ] **Step 7: Commit**

```bash
git add internal/issuer/ internal/broker/api/issue.go internal/broker/api/issue_test.go internal/broker/api/api.go
git commit -m "feat(issuer): the broker's issuing CA, the sign-in its certificates carry, and the issuance wire types"
```

---

### Task 6: The broker trusts the certificates it issues, for people alone

**Files:**
- Create: `internal/broker/issued.go`, `internal/broker/issued_test.go`
- Modify: `internal/broker/broker.go` (`Broker.Issuer`, `authenticate`, `callerOf`)
- Modify: `internal/broker/workload.go` (`CertCaller.Issued`, `CertCallerOf`)
- Modify: `internal/broker/server.go` (`Server`), `internal/broker/listen.go` (`mapped`),
  `internal/broker/certcheck.go` (`certRefusal`), `internal/broker/sessionrefresh.go`
  (`refreshChallenge`, `refresh`)

**Interfaces:**
- Consumes: Task 5's `issuer.CA` (`Ends`, `Trusted`, `Cert`, `Issue`), `issuer.ReadSignIn`,
  `issuer.SignIn`, `issuer.Ephemeral`; `oidc.Assertion`, `Assertion.Credential`, `oidc.DomainOf`,
  `Set.HumanDomains`; the broker's `CertIdentity`, `loggedOut`, `answerLoggedOut`, `markExtended`,
  `oidcAuth`, `caller`, `emit`, `writeError`; the tests' `newFixture`, `newFixtureWithPolicy`,
  `machinePolicy`, `withOIDC`, `idToken`, `bearer`, `postAt`, `state`, `client`, `liveContextAt`,
  `context`, `serveThroughWith`, `held`, `postOn`, `refreshOn`, `decodeMint`, `shown`, `records`,
  `eventsOf`, `certKey`, `alicePrincipal`, `mintLeaf1`.
- Produces, for Tasks 7–10:
  - `Broker.Issuer *issuer.CA`; `CertCaller.Issued *oidc.Assertion`
  - `func (b *Broker) issuedCaller(cs *tls.ConnectionState, now time.Time) (CertCaller, error)`
  - `func (b *Broker) issuedLoggedOut(w http.ResponseWriter, r *http.Request, event, nothing string, now time.Time, c caller) bool`
  - `callerOf` now returns `(principal, legacy string, cred store.Credential, issued *oidc.Assertion, err error)`
  - `const personBearerText`
  - test helpers: `(f *fixture) withIssuance(t) *oidctest.Issuer`, `aliceSignIn(iss) issuer.SignIn`,
    `issued(t, s) tls.Certificate`, `issuedState(c) *tls.ConnectionState`
- Not here: the logout record's life on an issuing broker (ruling 16) is Task 7 Step 5's, in
  `logout.go`; it reads `issuer.MaxLifetime` beside `certificateLifetime`, which Task 7 creates.
  Until then the record keeps decision 39's `max_token_age + 2×clock_skew`, and Task 6's logout
  tests act seconds after the logout.

- [ ] **Step 1: Write the failing tests**

Create `internal/broker/issued_test.go`:

```go
package broker

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

// withIssuance gives f's broker an issuing CA (plan 9b) beside withOIDC's
// provider, whose human verifier takes example.com.
func (f *fixture) withIssuance(t *testing.T) *oidctest.Issuer {
	t.Helper()
	iss := f.withOIDC(t)
	ca, err := issuer.Ephemeral(f.b.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.b.Issuer = ca
	return iss
}

// aliceSignIn is alice's sign-in at iss as withOIDC's tokens name it: sub
// sub-alice, sid s-sub-alice, at f's now.
func (f *fixture) aliceSignIn(iss *oidctest.Issuer) issuer.SignIn {
	return issuer.SignIn{Principal: alicePrincipal, Issuer: iss.URL, Subject: "sub-alice", Sid: "s-sub-alice",
		AMR: []string{"pwd", "otp"}, ACR: "1", AuthTime: f.b.Now(), IssuedAt: f.b.Now()}
}

// issued is a certificate f's issuing CA issues on s, for a fresh key, as
// crypto/tls holds it.
func (f *fixture) issued(t *testing.T, s issuer.SignIn) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.b.Issuer.Issue(key.Public(), s, f.b.Now(), 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
}

// issuedState is a handshake's state with c: one chain, ending at the
// issuing CA.
func (f *fixture) issuedState(c tls.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, f.b.Issuer.Cert}}}
}

// An issued certificate mints as its sign-in's principal; its records carry
// the sign-in, its token the sid and its serial, and the mint writes the
// owner record a logout finds the principal by (decision 43 rulings 10, 16).
func TestAnIssuedCertificateMintsAsItsSignIn(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	c := f.issued(t, f.aliceSignIn(iss))
	w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now)
	if r := decodeMint(t, w); r.Principal != alicePrincipal || r.Results[0].Verdict != "permit" {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	auth, _ := recs[len(recs)-1]["auth"].(map[string]any)
	o, _ := auth["oidc"].(map[string]any)
	if auth["method"] != "cert" || o["sid"] != "s-sub-alice" || o["issuer"] != iss.URL {
		t.Fatalf("the mint record's auth: %v", auth)
	}
	toks, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if err != nil || len(toks) == 0 || toks[0].Credential.Sid != store.SidKey(iss.URL, "s-sub-alice") ||
		toks[0].Credential.Serial != c.Leaf.SerialNumber.Text(16) {
		t.Fatalf("the token's credential: %d tokens, %v", len(toks), err)
	}
	own, err := f.st.OIDCOwner(context.Background(), store.SidKey(iss.URL, "s-sub-alice"))
	if _, ok := own.Entry(alicePrincipal); err != nil || !ok {
		t.Fatalf("no owner record for the sid: %v", err)
	}
}

// A back-channel logout of the sign-in reaches the contexts the
// certificate's tokens made, through the sid index (decision 43 ruling 16).
func TestALogoutReachesAnIssuedCertificatesContexts(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	if w := f.postAt(context.Background(), f.issuedState(f.issued(t, f.aliceSignIn(iss))), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	ctx := context.Background()
	toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"})
	tok := toks[len(toks)-1]
	// The daemon's redemption, as fixture.login writes it, with the
	// token's credential and its indexes.
	ref := store.ContextRef{NAS: "leaf1", Username: "alice"}
	if err := f.st.PutContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}, store.Context{CtxID: "ctx-leaf1",
		Principal: alicePrincipal, Username: "alice", PrivLvl: 15, BlobHash: tok.BlobHash, AuthTime: f.now,
		CreatedAt: f.now, RefreshedAt: f.now, SessionExpires: f.now.Add(time.Hour), Credential: tok.Credential},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, alicePrincipal, tok.Credential.Sid,
		store.CertKey(tok.Credential.Issuer, tok.Credential.Serial), ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Logout(ctx, oidc.LogoutToken{Issuer: iss.URL, Sid: "s-sub-alice", IssuedAt: f.b.Now(),
		Domains: []string{"example.com"}}, "backchannel_logout "+iss.URL); err != nil {
		t.Fatal(err)
	}
	if got := f.context(t, "leaf1", "alice"); got.RevokedAt.IsZero() {
		t.Fatal("the logout did not reach the issued certificate's context")
	}
}

// Through the listener: an issued certificate binds, mints, and refreshes by
// a key signature on its held connection, with no sign-in; after a logout of
// its sign-in, its next mint and its next refresh are refused in the
// broker's logout words (decision 43 rulings 11 and 16).
func TestALogoutRefusesAnIssuedCertificate(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	addr, _ := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) { f.b.Wire(l) })
	c := f.issued(t, f.aliceSignIn(iss))
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(c), f.now, f.now.Add(8*time.Hour))
	conn, br := held(t, f, addr, c)
	if a := postOn(t, conn, br, "/v1/tokens", mintLeaf1); a.status != 200 {
		t.Fatalf("a mint on the held connection: %d %s", a.status, a.body)
	}
	if status, resp := refreshOn(t, conn, br, c); status != 200 || len(resp.Sessions) != 1 ||
		resp.Sessions[0].Outcome != "extended" {
		t.Fatalf("a refresh by the issued key: %d %+v", status, resp)
	}
	if _, err := f.b.Logout(context.Background(), oidc.LogoutToken{Issuer: iss.URL, Sid: "s-sub-alice",
		IssuedAt: f.b.Now(), Domains: []string{"example.com"}}, "backchannel_logout "+iss.URL); err != nil {
		t.Fatal(err)
	}
	if a := postOn(t, conn, br, "/v1/tokens", mintLeaf1); a.status != 401 ||
		!strings.Contains(a.body, "credential_revoked") || !strings.Contains(a.body, "back-channel logout") {
		t.Fatalf("a mint after the logout: %d %s", a.status, a.body)
	}
	conn2, br2 := held(t, f, addr, c)
	if status, _ := refreshOn(t, conn2, br2, c); status != 401 {
		t.Fatalf("a refresh after the logout: %d", status)
	}
	recs := eventsOf(f.records(t), decision.EventRefresh)
	if r := recs[len(recs)-1]; r["verdict"] != "deny" || r["reason"] != "credential_revoked" {
		t.Fatalf("the refresh's record: %v", r)
	}
}

// An issued certificate is never mapped through the directory: the
// listener's Map is not asked for it. It is for a certificate an
// organization's CA issued: the control.
func TestAnIssuedCertificateIsNeverMapped(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	var maps atomic.Int32
	addr, _ := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) {
		f.b.Wire(l)
		l.Map = func(context.Context, tls.ConnectionState, store.Credential) (directory.Answer, *BindRefusal) {
			maps.Add(1)
			return directory.Answer{}, directoryRefusal(directory.ErrUnavailable)
		}
	})
	conn, br := held(t, f, addr, f.issued(t, f.aliceSignIn(iss)))
	if a := postOn(t, conn, br, "/v1/tokens", mintLeaf1); a.status != 200 || maps.Load() != 0 {
		t.Fatalf("the issued certificate: %d %s, mapped %d times", a.status, a.body, maps.Load())
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if a := postOn(t, c, bufio.NewReader(c), "/v1/tokens", mintLeaf1); a.status != 503 || maps.Load() != 1 {
		t.Fatalf("the control: %d %s, mapped %d times", a.status, a.body, maps.Load())
	}
}

// A chain ending at the issuing CA and at another anchor is no one's; a
// sign-in no human verifier takes now, by its issuer or its principal's
// domain, is refused (decision 43 ruling 10).
func TestAnIssuedCertificateTheBrokerCannotPlaceIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	c := f.issued(t, f.aliceSignIn(iss))
	both := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, f.b.Issuer.Cert}, {c.Leaf, f.ca.Cert}}}
	if w := f.postAt(context.Background(), both, mintLeaf1, "", f.now); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "issuing CA and to another trust anchor") {
		t.Fatalf("both anchors: %s", shown(w))
	}
	s := f.aliceSignIn(iss)
	s.Issuer = "https://elsewhere.example/realms/corp"
	if w := f.postAt(context.Background(), f.issuedState(f.issued(t, s)), mintLeaf1, "", f.now); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "port49 login --sign-in") {
		t.Fatalf("a provider no longer configured: %s", shown(w))
	}
	s = f.aliceSignIn(iss)
	s.Principal = "user:alice@elsewhere.example"
	if w := f.postAt(context.Background(), f.issuedState(f.issued(t, s)), mintLeaf1, "", f.now); w.Code != 401 {
		t.Fatalf("a domain the verifier does not hold: %s", shown(w))
	}
}

// everyChainUnknown answers every chain Unknown, as a CA no source covers.
type everyChainUnknown struct{}

func (everyChainUnknown) Check(context.Context, []*x509.Certificate) certstatus.Result {
	return certstatus.Result{Verdict: certstatus.Unknown, Detail: api.UncoveredStatus + " (test)"}
}

// An issued certificate is never put to certificate_status: the broker's
// marks are its status (decision 43 ruling 10). An organization's
// certificate is, the control.
func TestAnIssuedCertificateIsNotAskedItsStatus(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	f.b.CertStatus, f.b.OnUnavailable = everyChainUnknown{}, "refuse"
	if w := f.postAt(context.Background(), f.issuedState(f.issued(t, f.aliceSignIn(iss))), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("the issued certificate: %s", shown(w))
	}
	if w := f.postAt(context.Background(), f.state(f.alice), mintLeaf1, "", f.now); w.Code != 503 {
		t.Fatalf("the control: %s", shown(w))
	}
}

// An OIDC-only broker that issues asks for a certificate, against its own
// CAs, and takes its issued certificates on a held connection.
func TestAnOIDCOnlyBrokerThatIssuesTakesItsCertificates(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	f.b.NoX509 = true
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, nil)
	if err != nil || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven || srv.TLSConfig.ClientCAs == nil {
		t.Fatalf("%v: client auth %v", err, srv.TLSConfig.ClientAuth)
	}
	addr, _ := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) { f.b.Wire(l) })
	conn, br := held(t, f, addr, f.issued(t, f.aliceSignIn(iss)))
	if a := postOn(t, conn, br, "/v1/tokens", mintLeaf1); a.status != 200 {
		t.Fatalf("%d %s", a.status, a.body)
	}
}

// One path for people (decision 43 ruling 13): a broker that issues refuses
// a person's ID token on every endpoint but /v1/certificate; a machine's is
// unaffected; with no issuance a person's mints as plan 7h built.
func TestAPersonsBearerIsRefusedWhereTheBrokerIssues(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withIssuance(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	var e api.Error
	if w.Code != 401 || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error != "trust_domain_unresolved" ||
		!strings.Contains(e.Detail, "POST /v1/certificate") {
		t.Fatalf("a person's bearer: %s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if r := recs[len(recs)-1]; r["verdict"] != "deny" || r["principal"] != alicePrincipal {
		t.Fatalf("the refusal's record: %v", r)
	}
	now := f.b.Now()
	machine := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, machine); w.Code != 200 {
		t.Fatalf("a machine's bearer: %s", shown(w))
	}
	f.b.Issuer = nil
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil)); w.Code != 200 {
		t.Fatalf("a person's bearer with no issuance: %s", shown(w))
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/broker/ -run 'Issued|PersonsBearer|OIDCOnlyBrokerThatIssues' -count=1`
Expected: FAIL to build: `f.b.Issuer undefined (type *Broker has no field or method Issuer)`.

- [ ] **Step 3: `internal/broker/issued.go`**

```go
package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
)

// personBearerText answers a person's ID token at a broker that issues
// certificates, anywhere but POST /v1/certificate (decision 43 ruling 13).
const personBearerText = "this broker takes a person's ID token at POST /v1/certificate alone, which exchanges it " +
	"for a short-lived certificate; run `port49 login` (spec §13 decision 43 ruling 13)"

// issuedCaller is CertCallerOf for a chain ending at the broker's own
// issuing CA (plan 9b; spec §13 decision 43 ruling 10): the certificate's
// validity and clientAuth as any certificate's (CertIdentity), then the
// sign-in it carries. The principal is the sign-in's, never mapped through
// the directory. The sign-in's issuer must still be one of this broker's
// human OIDC verifiers, for the principal's domain, so a provider removed
// from the configuration takes its people's certificates with it. The
// credential is the certificate's and the sign-in's both, so a mint indexes
// its contexts under the sid a logout names.
func (b *Broker) issuedCaller(cs *tls.ConnectionState, now time.Time) (CertCaller, error) {
	cred, leaf, err := CertIdentity(cs, now)
	cc := CertCaller{Domain: DomainHumans, Cred: cred, Leaf: leaf}
	if err != nil {
		return cc, err
	}
	s, err := issuer.ReadSignIn(leaf)
	if err != nil {
		return cc, fmt.Errorf("%w: a certificate this broker's issuing CA signed does not read as one it issues: %v",
			ErrUntrusted, err)
	}
	if b.Identity == nil || !slices.Contains(b.Identity.HumanDomains(s.Issuer), oidc.DomainOf(s.Principal)) {
		return cc, fmt.Errorf("%w: the sign-in this certificate was issued on (%s, for %s) is not one this broker's "+
			"human OIDC verifiers take now; run `port49 login --sign-in`", ErrUntrusted, printsafe.Line(s.Issuer, 200),
			printsafe.Line(s.Principal, 200))
	}
	a := oidc.Assertion{Domain: oidc.Humans, Principal: s.Principal, Issuer: s.Issuer, Subject: s.Subject, Sid: s.Sid,
		AMR: s.AMR, ACR: s.ACR, AuthTime: s.AuthTime, IssuedAt: s.IssuedAt}
	oc := a.Credential()
	cc.Cred.Iss, cc.Cred.Sub, cc.Cred.Sid, cc.Cred.AMR, cc.Cred.ACR = oc.Iss, oc.Sub, oc.Sid, oc.AMR, oc.ACR
	cc.Principal, cc.Issued = s.Principal, &a
	return cc, nil
}

// issuedLoggedOut answers a request made with a certificate this broker
// issued whose sign-in the provider has since ended (decision 43 ruling 16):
// the logout records decision 39 ruling 13 keeps, read as a bearer's are,
// the sign-in's iat the token's. It reports whether it answered. A logout
// closes the connection. nothing completes the logouts-unreadable answer.
func (b *Broker) issuedLoggedOut(w http.ResponseWriter, r *http.Request, event, nothing string, now time.Time,
	c caller) bool {
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	l, out, err := b.loggedOut(ctx, *c.oidc)
	cancel()
	switch {
	case err != nil:
		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: c.principal, Auth: c.auth()})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not read the logouts in force, so it "+nothing+"; try again")
		return true
	case out:
		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
			Reason: decision.CredentialRevoked, Principal: c.principal, Auth: c.auth()})
		w.Header().Set("Connection", "close")
		b.answerLoggedOut(w, l)
		return true
	}
	return false
}
```

- [ ] **Step 4: The caller, the handshake and the listener**

In `internal/broker/broker.go`:

- Add `"github.com/rhwendt/port49/internal/issuer"` to the imports, and in `Broker`, before the
  comment that begins `// Workload is the workload certificate verifier`, add:

  ```go
  	// Issuer is the broker's issuing CA (plan 9b; spec §13 decision 43): nil
  	// issues nothing and trusts no port49-issued certificate. Its CAs join
  	// the handshake's pool, for people alone (Server, CertCallerOf).
  	Issuer *issuer.CA
  ```

- In `authenticate`, replace

  ```go
  	case hasBearer:
  		return b.bearerCaller(w, r, event, nothing, raw)
  	case b.NoX509 && !(hasCert && b.Workload != nil):
  ```

  with

  ```go
  	case hasBearer:
  		c, ok := b.bearerCaller(w, r, event, nothing, raw)
  		if ok && b.Issuer != nil && c.oidc.Domain == oidc.Humans {
  			// One path for people (decision 43 ruling 13): this broker
  			// exchanges a person's ID token for a certificate, and takes it
  			// nowhere else.
  			b.emit(decision.Record{TS: b.Now(), Event: event, Verdict: decision.VerdictDeny,
  				Reason: decision.TrustDomainUnresolved, Principal: c.principal, Auth: c.auth()})
  			writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), personBearerText)
  			return caller{}, false
  		}
  		return c, ok
  	case b.NoX509 && !(hasCert && (b.Workload != nil || b.Issuer != nil)):
  ```

  and in that case's body, replace

  ```go
  		if b.Workload != nil {
  ```

  with

  ```go
  		switch {
  		case b.Issuer != nil:
  			detail = "this broker takes the certificate it issues at `port49 login`, or a workload's where " +
  				"broker.identity.machines names one; run `port49 login`"
  		case b.Workload != nil:
  ```

  (the `if` block's closing brace now closes the `switch`).

- In `authenticate`, replace

  ```go
  	if b.Directory != nil && cc.Domain == DomainHumans {
  		if h := heldOf(r); h != nil && h.answer != nil {
  ```

  with

  ```go
  	if b.Directory != nil && cc.Domain == DomainHumans && cc.Issued == nil {
  		if h := heldOf(r); h != nil && h.answer != nil {
  ```

  and replace

  ```go
  	// Without a directory, and for a workload, which never reaches one (decision 40 ruling 5):
  	// the principal is the certificate's own.
  	if b.Directory == nil || cc.Domain == DomainMachines {
  		if marked(principal) || status() {
  			return caller{}, false
  		}
  		// Only a certificate that is served is counted late.
  		b.noteRenewal(cc, now)
  		return caller{principal: principal, cred: cred, authTime: authTime}, true
  	}
  ```

  with

  ```go
  	// Without a directory, for a workload, which never reaches one (decision 40 ruling 5), and for
  	// a certificate this broker issued, whose principal its sign-in gave (decision 43 ruling 10):
  	// the principal is the certificate's own.
  	if b.Directory == nil || cc.Domain == DomainMachines || cc.Issued != nil {
  		if marked(principal) || status() {
  			return caller{}, false
  		}
  		c := caller{principal: principal, cred: cred, authTime: authTime, oidc: cc.Issued}
  		// A certificate this broker issued answers to its sign-in's
  		// logouts (decision 43 ruling 16).
  		if cc.Issued != nil && b.issuedLoggedOut(w, r, event, nothing, now, c) {
  			return caller{}, false
  		}
  		// Only a certificate that is served is counted late.
  		b.noteRenewal(cc, now)
  		return c, true
  	}
  ```

- Replace `callerOf` with:

  ```go
  // callerOf is the caller of a request that does not map: the principal and
  // credential of the connection's verified certificate, legacy, the
  // principal its email SAN gave before a directory ("" without one), and
  // issued, the sign-in a certificate this broker issued carries (nil for
  // any other; decision 43 ruling 10). Under a directory the principal is
  // the one pinned to the held connection at bind (Ruling 4), never the
  // email SAN's; a connection with no pin is refused (errNoPin). An issued
  // certificate is never mapped.
  func (b *Broker) callerOf(r *http.Request, now time.Time) (principal, legacy string, cred store.Credential,
  	issued *oidc.Assertion, err error) {
  	cc, err := b.CertCallerOf(r.TLS, now)
  	if err != nil || b.Directory == nil || cc.Domain == DomainMachines || cc.Issued != nil {
  		return cc.Principal, cc.Legacy, cc.Cred, cc.Issued, err
  	}
  	if h := heldOf(r); h != nil && h.answer != nil {
  		return h.answer.Principal, cc.Legacy, cc.Cred, nil, nil
  	}
  	b.logf("broker: a held connection has no directory principal pinned (the listener has no Map); refusing it")
  	return "", cc.Legacy, cc.Cred, nil, errNoPin
  }
  ```

In `internal/broker/workload.go`:

- Add `"github.com/rhwendt/port49/internal/oidc"` to the imports, and in `CertCaller`, after
  `Leaf   *x509.Certificate`, add:

  ```go
  	// Issued is the sign-in a certificate this broker issued carries, as an
  	// assertion (plan 9b; decision 43 ruling 10); nil for any other
  	// certificate.
  	Issued *oidc.Assertion
  ```

- In `CertCallerOf`, replace

  ```go
  func (b *Broker) CertCallerOf(cs *tls.ConnectionState, now time.Time) (CertCaller, error) {
  	machine, chainErr := b.machineChain(cs)
  ```

  with

  ```go
  func (b *Broker) CertCallerOf(cs *tls.ConnectionState, now time.Time) (CertCaller, error) {
  	// A chain ending at the broker's own issuing CA is a person's, read from
  	// the sign-in it carries (decision 43 ruling 10); one ending there and at
  	// another anchor is no one's.
  	if cs != nil {
  		switch issued, mixed := b.Issuer.Ends(cs.VerifiedChains); {
  		case mixed:
  			cred, leaf, _ := CertIdentity(cs, now)
  			return CertCaller{Cred: cred, Leaf: leaf}, fmt.Errorf("%w: the certificate chains to this broker's "+
  				"issuing CA and to another trust anchor, so neither may take it", ErrUntrusted)
  		case issued:
  			return b.issuedCaller(cs, now)
  		}
  	}
  	machine, chainErr := b.machineChain(cs)
  ```

  and add to `CertCallerOf`'s comment, after its first sentence: `A chain ending at the broker's
  own issuing CA is read first (issuedCaller).`

In `internal/broker/server.go`'s `Server`:

- Replace

  ```go
  	case anchor == nil && b.NoX509 && b.Identity != nil:
  		// An OIDC-only broker (Ruling 1): no certificate is requested, and
  		// every caller authenticates by bearer.
  		clientAuth = tls.NoClientCert
  ```

  with

  ```go
  	case anchor == nil && b.NoX509 && b.Identity != nil && b.Issuer != nil:
  		// An OIDC-only broker that issues (plan 9b; decision 43 ruling 10):
  		// its one anchor is its own issuing CA's, added below.
  		pool = x509.NewCertPool()
  	case anchor == nil && b.NoX509 && b.Identity != nil:
  		// An OIDC-only broker (Ruling 1): no certificate is requested, and
  		// every caller authenticates by bearer.
  		clientAuth = tls.NoClientCert
  ```

- Replace

  ```go
  	if b.Workload != nil {
  		pool.AddCert(b.Workload.Anchor)
  	}
  ```

  with

  ```go
  	if b.Workload != nil {
  		pool.AddCert(b.Workload.Anchor)
  	}
  	// A broker that issues trusts its own CAs, for people alone (decision 43
  	// ruling 10): the chain's anchor says which it is (CertCallerOf).
  	if b.Issuer != nil && pool != nil {
  		for _, c := range b.Issuer.Trusted {
  			pool.AddCert(c)
  		}
  	}
  ```

- In its comment, replace `// An OIDC-only broker (NoX509, plan 7h) with no workload verifier is served
  // with a nil anchor and requests no certificate.` with `// An OIDC-only broker (NoX509, plan 7h)
  // with no workload verifier is served with a nil anchor and requests no certificate, unless it
  // issues certificates (plan 9b), when it requests one against its own issuing CAs.`

In `internal/broker/listen.go`, replace

```go
		// A workload is never mapped: its principal is its SPIFFE ID
		// (decision 40 ruling 5).
		mapped := l.Map != nil && cc.Domain != DomainMachines
```

with

```go
		// A workload is never mapped: its principal is its SPIFFE ID
		// (decision 40 ruling 5). Nor is a certificate the broker issued:
		// its principal is its sign-in's (decision 43 ruling 10).
		mapped := l.Map != nil && cc.Domain != DomainMachines && cc.Issued == nil
```

In `internal/broker/certcheck.go`'s `certRefusal`, after

```go
	if b.CertStatus == nil || cs == nil || len(cs.VerifiedChains) == 0 {
		return nil
	}
```

add

```go
	// A certificate this broker issued has no status but the broker's own
	// marks (decision 43 ruling 15).
	if issued, _ := b.Issuer.Ends(cs.VerifiedChains); issued {
		return nil
	}
```

- [ ] **Step 5: The refresh on an issued certificate**

In `internal/broker/sessionrefresh.go`:

- In `refreshChallenge`, replace `principal, _, cred, err := b.callerOf(r, now)` with
  `principal, _, cred, _, err := b.callerOf(r, now)`.
- In `refresh`, replace `principal, legacy, cred, err := b.callerOf(r, now)` with
  `principal, legacy, cred, issued, err := b.callerOf(r, now)`.
- In `refresh`, replace

  ```go
  	case revoked:
  		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
  		b.refuseRevokedAs(w, decision.EventRefresh, now, principal, cred, rv)
  		return
  	}
  	// The certificate's status, beside the marks (spec §5.1.4): a revoked one
  ```

  with

  ```go
  	case revoked:
  		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
  		b.refuseRevokedAs(w, decision.EventRefresh, now, principal, cred, rv)
  		return
  	}
  	// A certificate this broker issued answers to its sign-in's logouts, and
  	// its refresh records carry that sign-in (decision 43 rulings 11, 16).
  	var via *decision.OIDC
  	if issued != nil {
  		if b.issuedLoggedOut(w, r, decision.EventRefresh, "extended nothing", now,
  			caller{principal: principal, cred: cred, oidc: issued}) {
  			b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
  			return
  		}
  		via = oidcAuth(*issued)
  	}
  	// The certificate's status, beside the marks (spec §5.1.4): a revoked one
  ```

- Replace `rep, err := b.RefreshSession(ctx, m, answer, cred, at, nil)` with
  `rep, err := b.RefreshSession(ctx, m, answer, cred, at, via)`.
- Replace

  ```go
  		b.refuseRevokedAs(w, decision.EventRefresh, b.Now(), principal, cred, rv)
  		return
  	}
  	writeJSON(w, http.StatusOK, rep.response(b.MaxSessionAge))
  }
  ```

  with

  ```go
  		b.refuseRevokedAs(w, decision.EventRefresh, b.Now(), principal, cred, rv)
  		return
  	}
  	// The logouts again, after the extension's writes, as on the OIDC path:
  	// what a logout that landed meanwhile would have missed is marked.
  	if issued != nil {
  		switch l, out, err := b.loggedOut(ctx, *issued); {
  		case err != nil:
  			b.refreshStoreError(w, at, principal, cred, via, refreshEvery, partialRefreshText)
  			return
  		case out:
  			b.markExtended(ctx, caller{principal: principal, cred: cred, oidc: issued}, rep)
  			b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
  			b.answerLoggedOut(w, l)
  			return
  		}
  	}
  	writeJSON(w, http.StatusOK, rep.response(b.MaxSessionAge))
  }
  ```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `gofmt -l internal/broker/ && go test ./internal/broker/ -count=1`
Expected: `gofmt` lists nothing; PASS, every earlier broker test unchanged (7h's bearer tests run on
a broker with no `Issuer`).

Run: `go test -race ./internal/broker/ -run 'Issued|PersonsBearer|OIDCOnly|Refresh|Logout' -count=1 && go vet ./internal/broker/`
Expected: PASS, and vet silent.

- [ ] **Step 7: Commit**

```bash
git add internal/broker/
git commit -m "feat(broker): trust the certificates the broker issues, for people alone, with their sign-in's logouts"
```

---

### Task 7: `POST /v1/certificate`, the `issue` record, and its metrics

**Files:**
- Create: `internal/broker/issue.go`, `internal/broker/issue_test.go`
- Modify: `internal/broker/broker.go` (`Broker.CertificateLifetime`, `Handler`, `config`)
- Modify: `internal/broker/logout.go` (`logoutRecordTTL`, `logoutUnapplied`, `revokeIssuedSooner`)
- Modify: `internal/decision/reasons.go` (`CertificateIssued`, `EventIssue`), `internal/decision/log.go`
  (`Record.Certificate`, `Certificate`), `internal/decision/reasons_test.go`
- Modify: `internal/daemon/metrics/metrics.go` (`CertificatesIssued`, `IssuingCANotAfter`)

**Interfaces:**
- Consumes: Task 5's `issuer.CA.Issue`, `PEM`, `Unavailable`, `issuer.Fingerprint`,
  `issuer.DefaultLifetime`, `api.IssuanceNonce`, `api.IssueRequest`, `api.IssueResponse`,
  `api.Issuance`; Task 6's `withIssuance`, `issued`, `issuedState`, `aliceSignIn`; the broker's
  `bearerOf`, `bearerCaller`, `noteOwner`, `sayOnce`, `say`, `sayEvery`, `holdTimeout`,
  `logoutRecordTTL`, `logoutUnapplied`, `Logout`, `AdminSocket`; Task 5's `issuer.MaxLifetime`; the
  tests' `advance`.
- Produces, for Tasks 8, 10 and 12:
  - `POST /v1/certificate`; `Broker.CertificateLifetime time.Duration`;
    `func (b *Broker) certificateLifetime() time.Duration`
  - `decision.EventIssue`, `decision.CertificateIssued`, `decision.Certificate{Serial, Issuer, Fingerprint, NotAfter}`,
    `Record.Certificate`
  - `metrics.Metrics.CertificatesIssued *prometheus.CounterVec`, `IssuingCANotAfter prometheus.Gauge`

- [ ] **Step 1: Write the failing tests**

Create `internal/broker/issue_test.go`:

```go
package broker

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
)

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// csrBody is POST /v1/certificate's body for key.
func csrBody(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(api.IssueRequest{CSR: base64.RawURLEncoding.EncodeToString(der)})
	return string(b)
}

// signInFor is alice's ID token from iss whose nonce names key, with extra
// claims over withOIDC's.
func (f *fixture) signInFor(t *testing.T, iss *oidctest.Issuer, key crypto.Signer, extra map[string]any) string {
	t.Helper()
	nonce, err := api.IssuanceNonce(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]any{"nonce": nonce}
	for k, v := range extra {
		c[k] = v
	}
	return f.idToken(t, iss, c)
}

// apiError is w's API error, "" when it is none.
func apiError(w *httptest.ResponseRecorder) string {
	var e api.Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	return e.Error
}

// A fresh sign-in whose nonce names the CSR's key is issued a certificate for
// that key, carrying the sign-in, valid certificate_lifetime; the issue
// record names its serial; and the certificate mints (decision 43 rulings
// 8–10, 22).
func TestASignInIsIssuedACertificate(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key := newECKey(t)
	w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil))
	var resp api.IssueResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil || resp.Principal != alicePrincipal {
		t.Fatalf("%s", shown(w))
	}
	blk, rest := pem.Decode([]byte(resp.Certificate))
	if ca, _ := pem.Decode(rest); blk == nil || ca == nil {
		t.Fatalf("the chain: %q", resp.Certificate)
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	s, err := issuer.ReadSignIn(leaf)
	if err != nil || s.Sid != "s-sub-alice" || s.Subject != "sub-alice" || !key.PublicKey.Equal(leaf.PublicKey) ||
		!leaf.NotAfter.Equal(f.b.Now().Add(issuer.DefaultLifetime)) || resp.Serial != leaf.SerialNumber.Text(16) {
		t.Fatalf("%+v %v, not after %s", s, err, leaf.NotAfter)
	}
	recs := eventsOf(f.records(t), decision.EventIssue)
	if len(recs) != 1 || recs[0]["verdict"] != "permit" || recs[0]["reason"] != "certificate_issued" {
		t.Fatalf("%v", recs)
	}
	if cert, _ := recs[0]["certificate"].(map[string]any); cert["serial"] != resp.Serial ||
		cert["fingerprint"] != issuer.Fingerprint(leaf) {
		t.Fatalf("the record's certificate: %v", cert)
	}
	if n := testutil.ToFloat64(f.b.Metrics.CertificatesIssued.WithLabelValues("issued")); n != 1 {
		t.Fatalf("issued %v", n)
	}
	c := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("the issued certificate's mint: %s", shown(w))
	}
}

// A token whose nonce names another key, or none, is refused and recorded: a
// token taken in flight certifies no key but its own (decision 43 ruling 8;
// R2).
func TestATokenForAnotherKeyIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key, other := newECKey(t), newECKey(t)
	for name, tok := range map[string]string{
		"another key's nonce": f.signInFor(t, iss, other, nil),
		"no nonce":            f.idToken(t, iss, nil),
	} {
		if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 401 ||
			apiError(w) != "sign_in_not_bound" {
			t.Errorf("%s: %s", name, shown(w))
		}
	}
	recs := eventsOf(f.records(t), decision.EventIssue)
	if len(recs) != 2 || recs[0]["verdict"] != "deny" || recs[0]["principal"] != alicePrincipal ||
		recs[0]["reason"] != "trust_domain_unresolved" {
		t.Fatalf("%v", recs)
	}
}

// A sign-in is exchanged once (decision 43 ruling 8).
func TestASignInIsExchangedOnce(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key := newECKey(t)
	tok := f.signInFor(t, iss, key, nil)
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 200 {
		t.Fatalf("the first: %s", shown(w))
	}
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 401 ||
		apiError(w) != "sign_in_spent" {
		t.Fatalf("the second: %s", shown(w))
	}
}

// An auth_time over 5 minutes before the token's iat is a prompt=login the
// provider ignored, judged on the provider's own clock; a token issued over 5
// minutes before the broker's now is a slow sign-in or two clocks apart, and
// never blamed on prompt=login; an auth_time after the iat (the verifier
// refuses one ahead of the broker's now) is no sign-in.
// Each is refused and recorded (decision 43 ruling 8; R3). An auth_time and
// iat 4 minutes old, the control, is issued.
func TestAStaleSignInIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	now := f.b.Now()
	for name, c := range map[string]struct {
		claims       map[string]any
		want, unwant string
	}{
		"prompt=login ignored": {map[string]any{"auth_time": now.Add(-10 * time.Minute).Unix()},
			"prompt=login was not honoured", "clocks"},
		"the clocks apart": {map[string]any{"auth_time": now.Add(-10 * time.Minute).Unix(),
			"iat": now.Add(-10 * time.Minute).Unix()}, "clock and the broker's differ", "prompt=login"},
		"auth_time after iat": {map[string]any{"auth_time": now.Unix(), "iat": now.Add(-4 * time.Minute).Unix()},
			"after it issued the token", "prompt=login"},
	} {
		key := newECKey(t)
		w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, c.claims))
		if w.Code != 401 || apiError(w) != "sign_in_not_fresh" || !strings.Contains(w.Body.String(), c.want) ||
			strings.Contains(w.Body.String(), c.unwant) {
			t.Errorf("%s: %s", name, shown(w))
		}
	}
	if recs := eventsOf(f.records(t), decision.EventIssue); len(recs) != 3 || recs[0]["verdict"] != "deny" {
		t.Fatalf("%v", recs)
	}
	key := newECKey(t)
	tok := f.signInFor(t, iss, key, map[string]any{"auth_time": now.Add(-4 * time.Minute).Unix(),
		"iat": now.Add(-4 * time.Minute).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 200 {
		t.Fatalf("the control, 4 minutes old: %s", shown(w))
	}
}

// A logged-out person is issued nothing, as a mint is refused.
func TestALoggedOutPersonIsIssuedNothing(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	if err := f.st.PutLogout(context.Background(), store.Logout{Key: store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"),
		At: f.b.Now(), Origin: "backchannel_logout " + iss.URL}, time.Hour); err != nil {
		t.Fatal(err)
	}
	key := newECKey(t)
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil)); w.Code != 401 ||
		apiError(w) != "credential_revoked" {
		t.Fatalf("%s", shown(w))
	}
	if recs := eventsOf(f.records(t), decision.EventIssue); len(recs) != 1 || recs[0]["reason"] != "credential_revoked" {
		t.Fatalf("%v", recs)
	}
}

// A CSR whose signature is not its key's, or whose key is too weak, is
// refused.
func TestABadCSRIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key := newECKey(t)
	var req api.IssueRequest
	_ = json.Unmarshal([]byte(csrBody(t, key)), &req)
	der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
	der[len(der)-1] ^= 0xff // the signature's last byte
	bad, _ := json.Marshal(api.IssueRequest{CSR: base64.RawURLEncoding.EncodeToString(der)})
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", string(bad), f.signInFor(t, iss, key, nil)); w.Code != 400 {
		t.Fatalf("a bad signature: %s", shown(w))
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, weak), f.signInFor(t, iss, weak, nil)); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "2048") {
		t.Fatalf("a 1024-bit key: %s", shown(w))
	}
}

// A machine is issued nothing.
func TestAMachineIsIssuedNothing(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withIssuance(t)
	now := f.b.Now()
	machine := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, newECKey(t)), machine); w.Code != 400 {
		t.Fatalf("%s", shown(w))
	}
}

// A broker whose CA cannot issue says so, without the file's name, records
// nothing, and counts it; one with no issuance answers 404 (decision 43
// rulings 8 and 14).
func TestIssuanceUnavailableSaysSo(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	f.b.Issuer.Unavailable = errors.New("issuing-ca.key is not usable: missing")
	key := newECKey(t)
	w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil))
	if w.Code != 503 || w.Header().Get("Retry-After") != "60" || apiError(w) != "issuance_unavailable" ||
		strings.Contains(w.Body.String(), "issuing-ca.key") {
		t.Fatalf("%s", shown(w))
	}
	if n := len(eventsOf(f.records(t), decision.EventIssue)); n != 0 {
		t.Fatalf("%d issue records for the broker's own fault", n)
	}
	if n := testutil.ToFloat64(f.b.Metrics.CertificatesIssued.WithLabelValues("unavailable")); n != 1 {
		t.Fatalf("unavailable %v", n)
	}
	f.b.Issuer = nil
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil)); w.Code != 404 ||
		apiError(w) != "not_issuing" {
		t.Fatalf("no issuance: %s", shown(w))
	}
}

// /v1/config says the broker issues, and for how long (decision 43 ruling
// 18).
func TestConfigSaysTheBrokerIssues(t *testing.T) {
	f := newFixture(t, 8)
	f.withIssuance(t)
	f.b.CertificateLifetime = 8 * time.Hour
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	var c api.Config
	if json.Unmarshal(w.Body.Bytes(), &c) != nil || c.Issuance == nil || c.Issuance.CertificateLifetimeSeconds != 8*3600 {
		t.Fatalf("%s", w.Body)
	}
	f.b.Issuer = nil
	w = httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	if strings.Contains(w.Body.String(), "issuance") {
		t.Fatalf("a broker that does not issue says it does: %s", w.Body)
	}
}

// A logout's record stands on a broker that issues while a certificate
// issued on a sign-in before it may still be presented: the certificate
// carries no mark of its own, so past max_token_age its next mint is refused
// still (decision 43 ruling 16). The record stands the longest lifetime any
// broker may issue, so a lifetime lowered since keeps it; a broker that
// issued nothing when the logout landed keeps the record max_token_age
// alone, the control that shows the mint would otherwise pass. A recovery
// for a logout the store could not write names the shorter path, revoking
// the sign-in's certificates by serial, on a broker that issues alone.
func TestALogoutOutlivesMaxTokenAgeForAnIssuedCertificate(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	tm := f.b.Identity.Timing
	if got, want := f.b.logoutRecordTTL(), issuer.MaxLifetime+2*tm.ClockSkew; got != want {
		t.Fatalf("an issuing broker's logout record stands %s, want %s", got, want)
	}
	f.b.CertificateLifetime = time.Hour
	if got, want := f.b.logoutRecordTTL(), issuer.MaxLifetime+2*tm.ClockSkew; got != want {
		t.Fatalf("with the lifetime lowered to 1h the record stands %s, want %s", got, want)
	}
	f.b.CertificateLifetime = 0
	f.b.AdminSocket = "/run/port49/admin.sock"
	if got := f.b.logoutUnapplied(alicePrincipal, f.b.Now().Add(f.b.logoutRecordTTL())); !strings.Contains(got,
		"`port49 revoke --cert-issuer DN --cert-serial HEX`") ||
		!strings.Contains(got, f.b.Now().Add(tm.MaxTokenAge+2*tm.ClockSkew).UTC().Format(time.RFC3339)) {
		t.Fatalf("the recovery names no shorter path: %s", got)
	}
	past := tm.MaxTokenAge + 2*tm.ClockSkew + time.Minute
	logout := func(f *fixture, iss *oidctest.Issuer) {
		t.Helper()
		if _, err := f.b.Logout(context.Background(), oidc.LogoutToken{Issuer: iss.URL, Sid: "s-sub-alice",
			IssuedAt: f.b.Now(), Domains: []string{"example.com"}}, "backchannel_logout "+iss.URL); err != nil {
			t.Fatal(err)
		}
	}
	c := f.issued(t, f.aliceSignIn(iss))
	logout(f, iss)
	f.advance(past)
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.b.Now()); w.Code != 401 ||
		apiError(w) != "credential_revoked" || !strings.Contains(w.Body.String(), "back-channel logout") {
		t.Fatalf("a mint %s after the logout: %s", past, shown(w))
	}

	g := newFixture(t, 8)
	giss := g.withIssuance(t)
	gc := g.issued(t, g.aliceSignIn(giss))
	ca := g.b.Issuer
	g.b.Issuer = nil
	g.b.AdminSocket = "/run/port49/admin.sock"
	if got := g.b.logoutUnapplied(alicePrincipal, g.b.Now()); strings.Contains(got, "--cert-serial") {
		t.Fatalf("a broker that issues nothing names revoking by serial: %s", got)
	}
	logout(g, giss)
	g.b.Issuer = ca
	g.advance(past)
	if w := g.postAt(context.Background(), g.issuedState(gc), mintLeaf1, "", g.b.Now()); w.Code != 200 {
		t.Fatalf("the control, a record kept max_token_age alone: %s", shown(w))
	}
}
```

In `internal/decision/reasons_test.go`, add:

```go
// certificate_issued is in §5.7's vocabulary (plan 9b), so a policy test may
// name it, and the issue event is spelled as §5.7 spells it.
func TestCertificateIssuedIsKnown(t *testing.T) {
	if !Known(CertificateIssued) || CertificateIssued != "certificate_issued" || EventIssue != "issue" {
		t.Fatal("certificate_issued or issue is not §5.7's")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/broker/ ./internal/decision/ -run 'Certificate|SignIn|TokenForAnotherKey|BadCSR|MachineIsIssued|IssuanceUnavailable|LoggedOutPerson|CertificateIssued' -count=1`
Expected: FAIL to build: `f.b.Metrics.CertificatesIssued undefined`, `undefined: decision.EventIssue`,
`undefined: CertificateIssued`.

- [ ] **Step 3: The record, the reason and the metrics**

In `internal/decision/reasons.go`:

- Before the closing `)` of the reason `const` block (after `ProjectionFailClosed Reason =
  "projection_fail_closed"`), add:

  ```go

  	// CertificateIssued: the broker issued a short-lived client certificate
  	// for the key a person's sign-in names (spec §5.7; §13 decision 43
  	// ruling 8). A permit on the issue event.
  	CertificateIssued Reason = "certificate_issued"
  ```

- After `const EventExplain = "explain"`, add:

  ```go

  // EventIssue is POST /v1/certificate: whether a person's OIDC sign-in is
  // exchanged for a certificate the broker issues (spec §5.7; §13 decision
  // 43): permit certificate_issued, or a deny with the refusal's reason.
  const EventIssue = "issue"
  ```

- In `reasons`, replace `APIRightMissing,` with `APIRightMissing, CertificateIssued,`.

In `internal/decision/log.go`:

- In `Record`, after the `Explain *Explain` field, add:

  ```go
  	// Certificate is an issue record's certificate (spec §5.7; §13 decision
  	// 43 ruling 22).
  	Certificate *Certificate `json:"certificate,omitempty"`
  ```

- After the `Record` type, add:

  ```go
  // Certificate is the certificate an issue record names: its serial, as
  // `port49 revoke --cert-serial` takes it, the issuing CA's DN, its
  // fingerprint and its end. Identity, not a secret (spec §5.1.4).
  type Certificate struct {
  	Serial      string `json:"serial"`
  	Issuer      string `json:"issuer"`
  	Fingerprint string `json:"fingerprint"`
  	NotAfter    string `json:"not_after"`
  }
  ```

In `internal/daemon/metrics/metrics.go`:

- In `Metrics`, after `WorkloadRenewalLate prometheus.Counter`, add:

  ```go
  	// port49_certificates_issued_total{outcome}: POST /v1/certificate by
  	// outcome: issued, refused, unavailable (the issuing CA not usable)
  	// (plan 9b; spec §13 decision 43 ruling 22). No principal.
  	CertificatesIssued *prometheus.CounterVec
  	// port49_issuing_ca_not_after_timestamp_seconds: the Unix time the
  	// issuing CA in use expires; 0 when none is loaded. Where issuance is
  	// configured, alert on 0, and on it within 90 days.
  	IssuingCANotAfter prometheus.Gauge
  ```

- In `New`, after the `WorkloadRenewalLate:` entry, add:

  ```go
  		CertificatesIssued: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_certificates_issued_total",
  			Help: "Sign-ins exchanged for a port49-issued certificate, by outcome: issued, refused, unavailable."},
  			[]string{"outcome"}),
  		IssuingCANotAfter: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_issuing_ca_not_after_timestamp_seconds",
  			Help: "The Unix time the issuing CA in use expires; 0 when none is loaded."}),
  ```

- In the `reg.MustRegister(…)` call, replace `m.InventoryMirrorUnreadable, m.InventoryFetches,
  m.WorkloadRenewalLate)` with `m.InventoryMirrorUnreadable, m.InventoryFetches, m.WorkloadRenewalLate,
  m.CertificatesIssued, m.IssuingCANotAfter)`.
- After `m.PolicyBundleMatchesRunner.Set(1)`, add:

  ```go
  	// Every issuance outcome exists at 0 from the first scrape.
  	for _, o := range []string{"issued", "refused", "unavailable"} {
  		m.CertificatesIssued.WithLabelValues(o)
  	}
  ```

- [ ] **Step 4: `internal/broker/issue.go`**

```go
package broker

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
)

// issueFresh is how long after the provider authenticated the person a
// sign-in may be exchanged for a certificate: the sign-in's own wait
// (oidcclient.SignInWait), so a login is a fresh authentication (decision 43
// ruling 8; R3).
const issueFresh = 5 * time.Minute

// issueKey is a sign-in's once-only key: its ID token's SHA-256, so the
// store never holds a token.
func issueKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "issue_token " + hex.EncodeToString(sum[:])
}

// certificateLifetime is broker.identity.issuance.certificate_lifetime,
// issuer.DefaultLifetime when unset.
func (b *Broker) certificateLifetime() time.Duration {
	if b.CertificateLifetime > 0 {
		return b.CertificateLifetime
	}
	return issuer.DefaultLifetime
}

// issue is POST /v1/certificate (plan 9b; spec §13 decision 43 rulings
// 8–10): a person's sign-in, its ID token the bearer, exchanged for a
// short-lived client certificate for the key the request's CSR proves and
// the token's nonce names. Each refusal is one issue deny record. A broker
// whose CA cannot issue says so and records nothing: the fault is its own,
// and its start said which.
func (b *Broker) issue(w http.ResponseWriter, r *http.Request) {
	if b.Issuer == nil {
		writeError(w, http.StatusNotFound, "not_issuing", "this broker issues no certificates "+
			"(broker.identity.issuance is not configured); log in with a certificate")
		return
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "a sign-in is exchanged with no client certificate: its "+
			"ID token is the one credential")
		return
	}
	raw, has, berr := bearerOf(r)
	if !has || berr != nil {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: b.Now(), Event: decision.EventIssue, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "oidc"}})
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved),
			"a certificate is issued for a sign-in: send its ID token as the bearer (Authorization: Bearer)")
		return
	}
	// The token as any person's (decision 39 rulings 2–6), the marks and the
	// logouts; each refusal is recorded under issue.
	c, ok := b.bearerCaller(w, r, decision.EventIssue, "issued nothing", raw)
	if !ok {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		return
	}
	now := b.Now()
	refuse := func(status int, code, detail string) {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventIssue, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Principal: c.principal, Auth: c.auth()})
		writeError(w, status, code, detail)
	}
	if c.oidc.Domain != oidc.Humans {
		refuse(http.StatusBadRequest, "bad_request", "a machine is issued nothing: a workload presents its own "+
			"certificate or token")
		return
	}
	// Freshness on two clocks (R3): iat − auth_time is the provider's own, so
	// only it can say prompt=login was not honoured; now − iat is the
	// broker's against the provider's, a sign-in that took too long or two
	// clocks that differ, never blamed on the provider's prompt.
	skew, at := b.Identity.Timing.ClockSkew, c.oidc.AuthTime.UTC().Format(time.RFC3339)
	iat := c.oidc.IssuedAt.UTC().Format(time.RFC3339)
	switch {
	case c.oidc.AuthTime.After(c.oidc.IssuedAt.Add(skew)):
		refuse(http.StatusUnauthorized, "sign_in_not_fresh", fmt.Sprintf("your identity provider's token says you "+
			"authenticated at %s, after it issued the token at %s; such a token is no sign-in; run `port49 login` "+
			"again, and if it recurs tell the provider's operator", at, iat))
		return
	case c.oidc.IssuedAt.Sub(c.oidc.AuthTime) > issueFresh+skew:
		refuse(http.StatusUnauthorized, "sign_in_not_fresh", fmt.Sprintf("your identity provider last authenticated "+
			"you at %s, over %s before it issued this sign-in's token at %s: it did not ask you to sign in again "+
			"(prompt=login was not honoured); run `port49 login` again", at, issueFresh, iat))
		return
	case now.Sub(c.oidc.IssuedAt) > issueFresh+skew:
		refuse(http.StatusUnauthorized, "sign_in_not_fresh", fmt.Sprintf("your identity provider issued this "+
			"sign-in's token at %s, over %s before the broker's now (%s): the sign-in took too long, or the "+
			"provider's clock and the broker's differ by more than that; run `port49 login` again, and if it "+
			"recurs tell the broker's operator to check both clocks", iat, issueFresh, now.UTC().Format(time.RFC3339)))
		return
	}
	var req api.IssueRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil {
		refuse(http.StatusBadRequest, "bad_request", `the body is not a certificate request: {"csr": base64url DER}`)
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	var csr *x509.CertificateRequest
	if err == nil {
		csr, err = x509.ParseCertificateRequest(der)
	}
	if err == nil {
		err = csr.CheckSignature()
	}
	if err != nil {
		refuse(http.StatusBadRequest, "bad_request", "the CSR does not parse, or its signature is not its key's")
		return
	}
	if why := issuableKey(csr.PublicKey); why != "" {
		refuse(http.StatusBadRequest, "bad_request", why)
		return
	}
	if want, err := api.IssuanceNonce(csr.PublicKey); err != nil || c.oidc.Nonce != want {
		refuse(http.StatusUnauthorized, "sign_in_not_bound", "the sign-in's nonce does not name this request's key: "+
			"sign in again with the key you send (`port49 login`)")
		return
	}
	if err := b.Issuer.Unavailable; err != nil {
		b.Metrics.CertificatesIssued.WithLabelValues("unavailable").Inc()
		b.sayOnce("issuance_unavailable", sayEvery, "issuance: a sign-in of %s was not issued a certificate: %s",
			printsafe.Line(c.principal, 300), printsafe.Line(err.Error(), 300))
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "issuance_unavailable", "this broker cannot issue certificates "+
			"now: its issuing CA is not usable; tell its operator (the broker's log says why)")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	storeError := func() {
		b.Metrics.CertificatesIssued.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventIssue, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: c.principal, Auth: c.auth()})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not record your sign-in, so it issued nothing; run `port49 login` again")
	}
	switch first, err := b.Store.PutOnce(ctx, issueKey(raw), nil, b.Identity.Timing.MaxTokenAge); {
	case err != nil:
		storeError()
		return
	case !first:
		refuse(http.StatusUnauthorized, "sign_in_spent", "this sign-in was exchanged for a certificate already; run "+
			"`port49 login` to sign in again")
		return
	}
	// The owner record first, as a mint writes it (decision 39 ruling 11): a
	// logout that lands before the certificate's first mint finds the
	// principal by it.
	if err := b.noteOwner(ctx, *c.oidc); err != nil {
		storeError()
		return
	}
	cert, err := b.Issuer.Issue(csr.PublicKey, issuer.SignIn{Principal: c.principal, Issuer: c.oidc.Issuer,
		Subject: c.oidc.Subject, Sid: c.oidc.Sid, AMR: c.oidc.AMR, ACR: c.oidc.ACR, AuthTime: c.oidc.AuthTime,
		IssuedAt: c.oidc.IssuedAt}, now, b.certificateLifetime())
	if err != nil {
		b.Metrics.CertificatesIssued.WithLabelValues("unavailable").Inc()
		b.say("issuance: a certificate for %s could not be signed: %s", printsafe.Line(c.principal, 300),
			printsafe.Line(err.Error(), 300))
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "issuance_unavailable", "this broker could not sign your "+
			"certificate; tell its operator (the broker's log says why)")
		return
	}
	serial, notAfter := cert.SerialNumber.Text(16), cert.NotAfter.UTC().Format(time.RFC3339)
	b.Metrics.CertificatesIssued.WithLabelValues("issued").Inc()
	b.emit(decision.Record{TS: now, Event: decision.EventIssue, Verdict: decision.VerdictPermit,
		Reason: decision.CertificateIssued, Principal: c.principal, Auth: c.auth(),
		Certificate: &decision.Certificate{Serial: serial, Issuer: cert.Issuer.String(),
			Fingerprint: issuer.Fingerprint(cert), NotAfter: notAfter}})
	writeJSON(w, http.StatusOK, api.IssueResponse{Certificate: string(b.Issuer.PEM(cert)), Principal: c.principal,
		Serial: serial, NotAfter: notAfter})
}

// issuableKey is why pub cannot be issued a certificate, "" when it can: a
// key a refresh signature is made with (api.RefreshAlgorithm), at a strength
// the broker takes.
func issuableKey(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return ""
		}
	case ed25519.PublicKey:
		return ""
	case *rsa.PublicKey:
		if n := k.N.BitLen(); n >= 2048 && n <= 8192 {
			return ""
		}
	}
	return "the key must be ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 8192 bits"
}
```

- [ ] **Step 5: The route, the lifetime, `/v1/config`, and the logout record's life**

In `internal/broker/broker.go`:

- In `Broker`, after the `Issuer *issuer.CA` field Task 6 added, add:

  ```go
  	// CertificateLifetime is broker.identity.issuance.certificate_lifetime
  	// (decision 43 ruling 9); zero is issuer.DefaultLifetime.
  	CertificateLifetime time.Duration
  ```

- In `Handler`, after `mux.HandleFunc("POST /v1/refresh", b.refresh)`, add
  `mux.HandleFunc("POST /v1/certificate", b.issue)`.
- In `config`, before `writeJSON(w, http.StatusOK, c)`, add:

  ```go
  	if b.Issuer != nil {
  		c.Issuance = &api.Issuance{CertificateLifetimeSeconds: int(b.certificateLifetime() / time.Second)}
  	}
  ```

In `internal/broker/logout.go` (decision 43 ruling 16; pre-flight 2 C1, and its re-review's N4
and N7): a certificate the broker issued carries no mark of its own, so on a broker that issues the
logout record must stand while a certificate issued on a sign-in before it may be presented. That
is `max(max_token_age, issuer.MaxLifetime) + 2×clock_skew`, 24h2m: the longest lifetime any broker
may issue, not this broker's `certificate_lifetime`, so a lifetime lowered since still leaves no
certificate unreached. (A replica on the same store with no `issuance` writes the short record;
the operator notes say every broker on one store configures `issuance` alike.)
`logoutUnapplied`'s lift time is `now + logoutRecordTTL()` already, so it follows; its words name
the certificate too, and on a broker that issues it names the shorter path: revoke the sign-in's
certificates by serial, then lift after `max_token_age`.

- Add `"github.com/rhwendt/port49/internal/issuer"` to the imports, after
  `"github.com/rhwendt/port49/internal/decision"`.
- Replace

  ```go
  // logoutRecordTTL is how long a logout record stands: while a token issued
  // before it could still be presented. The recovery's lift time is the same
  // quantity.
  func (b *Broker) logoutRecordTTL() time.Duration {
  	t := b.Identity.Timing
  	return t.MaxTokenAge + 2*t.ClockSkew
  }
  ```

  with

  ```go
  // logoutRecordTTL is how long a logout record stands: while a token issued
  // before it could still be presented, and on a broker that issues
  // certificates while one issued on a sign-in before it could (decision 43
  // ruling 16): such a certificate carries no mark of its own, so the record
  // is what refuses it. That is the longest lifetime any broker may issue,
  // issuer.MaxLifetime, not this one's certificate_lifetime: a lifetime
  // lowered since, or a replica configured otherwise, leaves certificates
  // issued for longer. The recovery's lift time is the same quantity.
  func (b *Broker) logoutRecordTTL() time.Duration {
  	t := b.Identity.Timing
  	held := t.MaxTokenAge
  	if b.Issuer != nil {
  		held = max(held, issuer.MaxLifetime)
  	}
  	return held + 2*t.ClockSkew
  }
  ```

- Replace

  ```go
  // logoutUnapplied is the recovery for a logout nothing of which was written:
  // no logout record refuses the session's held ID token, so the contexts are
  // ended and the mark is lifted only after lift, when that token has expired.
  func (b *Broker) logoutUnapplied(principal string, lift time.Time) string {
  	at := lift.UTC().Format(time.RFC3339)
  	if b.AdminSocket == "" {
  		return b.proc() + " has no admin_socket configured, so end " + principal + "'s contexts: remove " + principal +
  			"'s grants from broker.policy_file (live within two watch intervals), and restore them only after " + at +
  			", when no ID token the logout would have refused can still mint; or configure admin_socket and revoke there"
  	}
  	where := b.proc() + "'s admin socket (" + b.AdminSocket + ")"
  	return "end " + principal + "'s contexts with `port49 revoke --principal " + principal + "` on " + where +
  		", and lift it with `port49 revoke --principal " + principal + " --lift` there only after " + at +
  		": no logout record refuses the session's held ID token until then; last check that `port49 revoke --list` " +
  		"there shows no mark for " + principal
  }
  ```

  with

  ```go
  // logoutUnapplied is the recovery for a logout nothing of which was written:
  // no logout record refuses the session's held ID token, or the certificate
  // issued on its sign-in, so the contexts are ended and the mark is lifted
  // only after lift, when that token or certificate has expired. On a broker
  // that issues, lift is a day off (issuer.MaxLifetime), so it also names the
  // shorter path: each certificate the sign-in got revoked by serial, from its
  // issue record, and the mark lifted once no ID token from before the logout
  // can still be presented.
  func (b *Broker) logoutUnapplied(principal string, lift time.Time) string {
  	at := lift.UTC().Format(time.RFC3339)
  	if b.AdminSocket == "" {
  		return b.proc() + " has no admin_socket configured, so end " + principal + "'s contexts: remove " + principal +
  			"'s grants from broker.policy_file (live within two watch intervals), and restore them only after " + at +
  			", when no ID token or issued certificate the logout would have refused can still mint; or configure " +
  			"admin_socket and revoke there"
  	}
  	where := b.proc() + "'s admin socket (" + b.AdminSocket + ")"
  	return "end " + principal + "'s contexts with `port49 revoke --principal " + principal + "` on " + where +
  		", and lift it with `port49 revoke --principal " + principal + " --lift` there only after " + at +
  		": no logout record refuses the session's held ID token or issued certificate until then; last check that " +
  		"`port49 revoke --list` there shows no mark for " + principal + b.revokeIssuedSooner(principal, where)
  }

  // revokeIssuedSooner is logoutUnapplied's shorter path on a broker that
  // issues (decision 43 ruling 16), "" on one that does not.
  func (b *Broker) revokeIssuedSooner(principal, where string) string {
  	if b.Issuer == nil {
  		return ""
  	}
  	t := b.Identity.Timing
  	sooner := b.Now().Add(t.MaxTokenAge + 2*t.ClockSkew).UTC().Format(time.RFC3339)
  	return "; or, sooner: revoke each certificate this broker issued " + principal + " on that sign-in with " +
  		"`port49 revoke --cert-issuer DN --cert-serial HEX` on " + where + ", the DN and serial from the decision " +
  		"log's issue records for " + principal + ", and lift the principal's mark after " + sooner + " instead, " +
  		"when no ID token from before the logout can still be presented"
  }
  ```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `gofmt -l internal/ && go test ./internal/broker/ ./internal/decision/ ./internal/daemon/metrics/ -count=1`
Expected: `gofmt` lists nothing; PASS.

Run: `go test -race ./internal/broker/ -run 'Certificate|SignIn|Issued|Issuance' -count=1 && go vet ./internal/...`
Expected: PASS, and vet silent.

- [ ] **Step 7: Commit**

```bash
git add internal/broker/ internal/decision/ internal/daemon/metrics/
git commit -m "feat(broker): POST /v1/certificate exchanges a fresh, key-bound sign-in for a short-lived certificate"
```

---

### Task 8: `broker.identity.issuance`, the CA at start, `init-issuer` and `rotate-issuer`, and the broker's CA bundle

**Files:**
- Modify: `internal/oidc/config.go` (`Config.Issuance`, `Issuance`)
- Modify: `internal/config/identity.go` (`identityYAML.Issuance`, `issuanceYAML`, `checkIssuance`),
  `internal/config/identity_test.go`
- Create: `internal/port49d/issuer.go`, `internal/port49d/issuer_test.go`
- Modify: `internal/port49d/main.go` (`Main`'s subcommands, `buildBrokerAnchor`),
  `internal/port49d/brokerd.go` (`BrokerMain`'s subcommands)
- The broker's CA bundle (ruling 25): Create `internal/broker/api/cabundle.go`,
  `internal/broker/api/cabundle_test.go`, `internal/broker/cabundle_test.go`,
  `internal/port49d/cabundle.go`, `internal/port49d/cabundle_test.go`; Modify
  `internal/broker/api/api.go` (`Config.BrokerCABundle`, `BrokerCABundleRefused`),
  `internal/broker/broker.go` (`Broker.CABundle`, `CABundleRefused`, `config`), `internal/config/config.go` (`BrokerConfig.TLSCABundleFile`)

**Interfaces:**
- Consumes: Task 5's `issuer.Load`, `issuer.New`, `issuer.Files`, the file names and lifetimes;
  Task 7's `Broker.CertificateLifetime`, `Metrics.IssuingCANotAfter`; port49d's `brokerStateDir`,
  `readOwnerOnly`, `writeOwnerOnly`, `procOf`, `stderr`; the tests' `brokerConfig`, `oidcOnly`,
  `captureStderr`, `seedMinter`, `minimalPolicy`, `loadWith`, `brokerWithIdentity`, `twoLists`.
- Produces, for Tasks 10 and 12:
  - `oidc.Config.Issuance *oidc.Issuance`; `type oidc.Issuance struct { CertificateLifetime time.Duration }`
  - `func issuerFiles(dir string) issuer.Files`; `func openIssuer(cfg config.Config, m *metrics.Metrics, say func(string, ...any)) *issuer.CA`
  - `func initIssuer(dir string, now time.Time) (created bool, line string, err error)`;
    `func rotateIssuer(dir string, now time.Time) (string, error)`
  - `func issuerCmd(proc, op, defaultConfig string, load func(string) (config.Config, error), args []string, stdout, stderr io.Writer) int`
  - the subcommands `port49d init-issuer|rotate-issuer [--config FILE]` and
    `port49-broker init-issuer|rotate-issuer [--config FILE]`
  - for Task 11: `api.ParseCABundle(raw []byte) ([]*x509.Certificate, error)`,
    `api.EncodeCABundle`, `api.CAFingerprints`, `api.MaxCABundleBytes`, `api.MaxCABundleCerts`,
    `api.Config.BrokerCABundle`, `Broker.CABundle`; `broker.tls_ca_bundle_file`;
    `func loadCABundle(path string, cert tls.Certificate, say func(string, ...any)) (bundle []byte, refused bool)`;
    `api.Config.BrokerCABundleRefused`, `Broker.CABundleRefused`

- [ ] **Step 1: Write the failing tests**

In `internal/config/identity_test.go`, add:

```go
// broker.identity.issuance: {} is 12h; certificate_lifetime sets it
// (decision 43 ruling 9). With none, the broker issues nothing.
func TestIssuanceLoads(t *testing.T) {
	for block, want := range map[string]time.Duration{
		"    issuance: {}\n":                         12 * time.Hour,
		"    issuance: {certificate_lifetime: 8h}\n": 8 * time.Hour,
	} {
		c, err := loadWith(t, brokerWithIdentity(twoLists+block))
		if err != nil || c.Broker.Identity.Issuance == nil || c.Broker.Identity.Issuance.CertificateLifetime != want {
			t.Fatalf("%q: %+v %v", block, c.Broker.Identity, err)
		}
	}
	if c, err := loadWith(t, brokerWithIdentity(twoLists)); err != nil || c.Broker.Identity.Issuance != nil {
		t.Fatalf("no issuance: %v", err)
	}
}

func TestIssuanceRefusals(t *testing.T) {
	machinesOnly := `  identity:
    machines:
      - type: oidc
        issuer: https://sso.corp.example.com/realms/corp
        audience: "api://port49-svc"
        clients: [{client_id: oxidized, sub: 5f3c2d1e-0000-4000-8000-000000000049}]
    issuance: {}
`
	for body, want := range map[string]string{
		brokerWithIdentity(machinesOnly):                                             "list a human oidc verifier",
		brokerWithIdentity(twoLists + "    issuance: {certificate_lifetime: 30m}\n"): "between 1h0m0s and 24h0m0s",
		brokerWithIdentity(twoLists + "    issuance: {certificate_lifetime: 48h}\n"): "between 1h0m0s and 24h0m0s",
		brokerWithIdentity(twoLists + "    issuance: {lifetime: 8h}\n"):              "unknown field",
	} {
		if _, err := loadWith(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v, want %q", err, want)
		}
	}
}
```

Create `internal/port49d/issuer_test.go`:

```go
package port49d

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store/memory"
)

// stateDir is a broker state directory as port49 keeps one: 0700, whatever
// the umask leaves a t.TempDir.
func stateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// init-issuer makes the CA once, 0600; run again it writes nothing; half a
// CA is refused. rotate-issuer stages and then promotes, the old CA kept
// trusted and its key gone (decision 43 ruling 14).
func TestInitAndRotateIssuer(t *testing.T) {
	dir, now := stateDir(t), time.Now()
	created, line, err := initIssuer(dir, now)
	if err != nil || !created || !strings.Contains(line, "created the issuing CA") {
		t.Fatalf("%v %q %v", created, line, err)
	}
	for _, name := range []string{issuer.CertFile, issuer.KeyFile} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	if created, line, err = initIssuer(dir, now); err != nil || created || !strings.Contains(line, "already there") {
		t.Fatalf("a second init: %v %q %v", created, line, err)
	}
	first, _ := issuer.Load(issuerFiles(dir), now)
	if line, err = rotateIssuer(dir, now); err != nil || !strings.Contains(line, "staged") {
		t.Fatalf("the stage: %q %v", line, err)
	}
	staged, _ := issuer.Load(issuerFiles(dir), now)
	if staged.Unavailable != nil || len(staged.Trusted) != 2 || !bytes.Equal(staged.Cert.Raw, first.Cert.Raw) {
		t.Fatalf("staged: %v %d", staged.Unavailable, len(staged.Trusted))
	}
	if line, err = rotateIssuer(dir, now); err != nil || !strings.Contains(line, "promoted the staged CA") {
		t.Fatalf("the promotion: %q %v", line, err)
	}
	after, _ := issuer.Load(issuerFiles(dir), now)
	if after.Unavailable != nil || len(after.Trusted) != 2 || bytes.Equal(after.Cert.Raw, first.Cert.Raw) ||
		!bytes.Equal(after.Trusted[1].Raw, first.Cert.Raw) {
		t.Fatalf("promoted: %v %d", after.Unavailable, len(after.Trusted))
	}
	for _, name := range []string{issuer.NextCertFile, issuer.NextKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s is still there: %v", name, err)
		}
	}
	if err := os.Remove(filepath.Join(dir, issuer.KeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := initIssuer(dir, now); err == nil || !strings.Contains(err.Error(), "without the other") {
		t.Fatalf("half a CA: %v", err)
	}
}

// A promotion interrupted after the certificate and before the key is
// finished by running it again (decision 43 ruling 14).
func TestAnInterruptedPromotionFinishes(t *testing.T) {
	dir, now := stateDir(t), time.Now()
	if _, _, err := initIssuer(dir, now); err != nil {
		t.Fatal(err)
	}
	if _, err := rotateIssuer(dir, now); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(filepath.Join(dir, issuer.CertFile))
	next, _ := os.ReadFile(filepath.Join(dir, issuer.NextCertFile))
	for name, body := range map[string][]byte{issuer.PreviousCertFile: cur, issuer.CertFile: next} {
		if err := writeOwnerOnly(filepath.Join(dir, name), body); err != nil {
			t.Fatal(err)
		}
	}
	if ca, _ := issuer.Load(issuerFiles(dir), now); ca.Unavailable == nil {
		t.Fatal("a certificate with the old key loaded as usable")
	}
	if _, err := rotateIssuer(dir, now); err != nil {
		t.Fatal(err)
	}
	if ca, _ := issuer.Load(issuerFiles(dir), now); ca.Unavailable != nil || len(ca.Trusted) != 2 ||
		!bytes.Equal(ca.Cert.Raw, mustCert(t, next)) {
		t.Fatalf("after the rerun: %v", ca.Unavailable)
	}
}

// The edges of a rotation (decision 43 ruling 14): another broker holds the
// staged certificate alone, trusts it, and cannot promote it; a staged file
// left there once the promotion is copied over is the current CA already,
// and is removed with nothing promoted; and a promotion is refused while an
// earlier rotation's previous CA is still there, until it is removed.
func TestRotateIssuerEdges(t *testing.T) {
	a, b, now := stateDir(t), stateDir(t), time.Now()
	if _, _, err := initIssuer(a, now); err != nil {
		t.Fatal(err)
	}
	copyToB := func(names ...string) {
		t.Helper()
		for _, n := range names {
			raw, err := os.ReadFile(filepath.Join(a, n))
			if err != nil {
				t.Fatal(err)
			}
			if err := writeOwnerOnly(filepath.Join(b, n), raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	copyToB(issuer.CertFile, issuer.KeyFile)
	if line, err := rotateIssuer(a, now); err != nil || !strings.Contains(line, "copy "+issuer.NextCertFile+" alone") {
		t.Fatalf("the stage: %q %v", line, err)
	}
	copyToB(issuer.NextCertFile)
	if ca, _ := issuer.Load(issuerFiles(b), now); ca.Unavailable != nil || len(ca.Trusted) != 2 {
		t.Fatalf("the other broker, the staged certificate alone: %v, %d trusted", ca.Unavailable, len(ca.Trusted))
	}
	if _, err := rotateIssuer(b, now); err == nil || !strings.Contains(err.Error(), "the broker that staged it") {
		t.Fatalf("a promotion with no staged key: %v", err)
	}
	if line, err := rotateIssuer(a, now); err != nil || !strings.Contains(line, "promoted the staged CA") {
		t.Fatalf("the promotion: %q %v", line, err)
	}
	copyToB(issuer.CertFile, issuer.KeyFile, issuer.PreviousCertFile)
	before, _ := os.ReadFile(filepath.Join(b, issuer.CertFile))
	if line, err := rotateIssuer(b, now); err != nil || !strings.Contains(line, "nothing was promoted") ||
		!strings.Contains(line, "if this broker promoted it, copy") {
		t.Fatalf("a staged file left from the promotion: %q %v", line, err)
	}
	after, _ := os.ReadFile(filepath.Join(b, issuer.CertFile))
	if _, err := os.Stat(filepath.Join(b, issuer.NextCertFile)); !errors.Is(err, fs.ErrNotExist) ||
		!bytes.Equal(before, after) {
		t.Fatalf("the leftover is still there (%v), or the current CA changed", err)
	}
	if _, err := rotateIssuer(a, now); err != nil {
		t.Fatal(err)
	}
	if _, err := rotateIssuer(a, now); err == nil ||
		!strings.Contains(err.Error(), issuer.PreviousCertFile+" from an earlier rotation") {
		t.Fatalf("a promotion over the previous CA: %v", err)
	}
	if err := os.Remove(filepath.Join(a, issuer.PreviousCertFile)); err != nil {
		t.Fatal(err)
	}
	if line, err := rotateIssuer(a, now); err != nil || !strings.Contains(line, "promoted the staged CA") {
		t.Fatalf("the promotion once it is removed: %q %v", line, err)
	}
}

// mustCert is the DER of the one PEM certificate in b.
func mustCert(t *testing.T, b []byte) []byte {
	t.Helper()
	c, _ := issuer.Load(issuer.Mem(map[string][]byte{issuer.CertFile: b}), time.Now())
	if c.Cert == nil {
		t.Fatal("no certificate")
	}
	return c.Cert.Raw
}

// A broker configured to issue with no CA starts, says what to run, and sets
// its gauge to 0; once the CA is made, the next start issues (decision 43
// ruling 14; R4).
func TestABrokerWithNoIssuingCAStartsAndSaysSo(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Broker.ClientCAFile = ""
	cfg.Broker.StateDir = stateDir(t)
	cfg.Broker.Identity = oidcOnly(t, iss, t.TempDir())
	cfg.Broker.Identity.Issuance = &oidc.Issuance{CertificateLifetime: 8 * time.Hour}
	out := captureStderr(t)
	m := metrics.New(prometheus.NewRegistry())
	srv, b, err := buildBroker(cfg, "inventory_file x", memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), m)
	if err != nil || srv == nil || b.Issuer == nil || b.Issuer.Unavailable == nil || b.CertificateLifetime != 8*time.Hour {
		t.Fatalf("%v, issuer %+v", err, b)
	}
	if !strings.Contains(out.String(), "issuance: issuing-ca.pem is missing") || !strings.Contains(out.String(), "init-issuer") {
		t.Fatalf("the start lines:\n%s", out.String())
	}
	if v := testutil.ToFloat64(m.IssuingCANotAfter); v != 0 {
		t.Fatalf("the gauge with no CA: %v", v)
	}
	if _, _, err := initIssuer(cfg.Broker.StateDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	out = captureStderr(t)
	m = metrics.New(prometheus.NewRegistry())
	if _, b, err = buildBroker(cfg, "inventory_file x", memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), m); err != nil || b.Issuer.Unavailable != nil ||
		!strings.Contains(out.String(), "issuance: issuing as ") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if v := testutil.ToFloat64(m.IssuingCANotAfter); v != float64(b.Issuer.Cert.NotAfter.Unix()) {
		t.Fatalf("the gauge: %v", v)
	}
}

// The subcommand takes one flag, and says so.
func TestIssuerCmdUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := issuerCmd("port49d", "init-issuer", "/etc/port49/port49d.yaml", nil, []string{"extra"}, &out,
		&errb); code != 2 || !strings.Contains(errb.String(), "usage: port49d init-issuer [--config FILE]") {
		t.Fatalf("%d %q", code, errb.String())
	}
}
```

The broker's CA bundle (ruling 25). Create `internal/broker/api/cabundle_test.go`:

```go
package api

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// A bundle is CAs alone, at most MaxCABundleCerts of them in at most
// MaxCABundleBytes; anything else is refused whole (decision 43 ruling 25).
func TestParseCABundle(t *testing.T) {
	now := time.Now()
	ca := func() []byte {
		c, err := testpki.NewCA("port49 test CA", now.Add(-time.Hour), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return c.PEM()
	}
	cur, next := ca(), ca()
	certs, err := ParseCABundle(append(append([]byte{}, cur...), next...))
	if err != nil || len(certs) != 2 || !bytes.Equal(EncodeCABundle(certs), append(append([]byte{}, cur...), next...)) ||
		strings.Count(CAFingerprints(certs), "sha256:") != 2 {
		t.Fatalf("%d %v", len(certs), err)
	}
	issuer, err := testpki.NewCA("port49 test CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := issuer.Issue(testpki.Leaf{CommonName: "broker", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, _, err := testpki.PEMs(leaf)
	if err != nil {
		t.Fatal(err)
	}
	five := bytes.Repeat(cur, 5)
	for name, c := range map[string]struct {
		raw  []byte
		want string
	}{
		"empty":       {nil, "no certificate"},
		"a leaf":      {leafPEM, "is not a CA"},
		"five":        {five, "over 4 certificates"},
		"too large":   {bytes.Repeat([]byte(" "), MaxCABundleBytes+1), "over 65536"},
		"a key":       {[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), "PRIVATE KEY block"},
		"trailing":    {append(append([]byte{}, cur...), "junk"...), "other than PEM"},
		"not parsing": {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), "certificate 1"},
	} {
		if _, err := ParseCABundle(c.raw); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
```

Create `internal/broker/cabundle_test.go`:

```go
package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
)

// GET /v1/config carries the CA bundle the broker was given, no field at all
// with none, and broker_ca_bundle_refused for one it refused (decision 43
// ruling 25).
func TestConfigCarriesTheCABundle(t *testing.T) {
	b := &Broker{MaxSessionAge: time.Hour, CABundle: []byte("-----BEGIN CERTIFICATE-----\n")}
	rec := httptest.NewRecorder()
	b.config(rec, httptest.NewRequest(http.MethodGet, "/v1/config", nil))
	var c api.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || c.BrokerCABundle != "-----BEGIN CERTIFICATE-----\n" {
		t.Fatalf("%v %q", err, rec.Body.String())
	}
	b.CABundle = nil
	rec = httptest.NewRecorder()
	b.config(rec, httptest.NewRequest(http.MethodGet, "/v1/config", nil))
	if strings.Contains(rec.Body.String(), "broker_ca_bundle") {
		t.Fatalf("%q", rec.Body.String())
	}
	// A bundle configured and refused at start is said, so clients keep what
	// they hold.
	b.CABundleRefused = true
	rec = httptest.NewRecorder()
	b.config(rec, httptest.NewRequest(http.MethodGet, "/v1/config", nil))
	c = api.Config{}
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || !c.BrokerCABundleRefused || c.BrokerCABundle != "" {
		t.Fatalf("%v %q", err, rec.Body.String())
	}
}
```

Create `internal/port49d/cabundle_test.go`:

```go
package port49d

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// The bundle GET /v1/config sends: sent when it holds the server
// certificate's CA, said by fingerprint; not sent, said, and marked refused
// when it does not, or cannot be read. The start goes on either way
// (decision 43 ruling 25).
func TestLoadCABundle(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, testpki.LabServerCert), filepath.Join(dir, testpki.LabServerKey))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile(filepath.Join(dir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	next, err := testpki.NewCA("port49 next CA", time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var said []string
	say := func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) }

	both := write("both.pem", append(append([]byte{}, cur...), next.PEM()...))
	got, refused := loadCABundle(both, cert, say)
	certs, err := api.ParseCABundle(got)
	if err != nil || refused || len(certs) != 2 || !certs[1].Equal(next.Cert) || len(said) != 1 ||
		!strings.Contains(said[0], "sent to every client: "+api.CAFingerprints(certs)) {
		t.Fatalf("%v %v", err, said)
	}
	for name, c := range map[string]struct{ path, want string }{
		"the next CA alone": {write("next.pem", next.PEM()), "does not hold the CA of the server certificate"},
		"missing":           {filepath.Join(dir, "none.pem"), "no such file"},
		"a leaf":            {write("leaf.pem", mustRead(t, filepath.Join(dir, testpki.LabServerCert))), "is not a CA"},
	} {
		said = nil
		if got, refused := loadCABundle(c.path, cert, say); got != nil || !refused || len(said) != 1 ||
			!strings.Contains(said[0], c.want) ||
			!strings.Contains(said[0], "no CA bundle is sent, so clients keep the CAs they hold") {
			t.Errorf("%s: %q %v", name, got, said)
		}
	}
	if got, refused := loadCABundle("", cert, say); got != nil || refused {
		t.Fatal("no file named sends nothing, and refuses nothing")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/config/ ./internal/port49d/ -run 'Issuance|Issuer|InterruptedPromotion|NoIssuingCA' -count=1`
Expected: FAIL to build: `unknown field Issuance in struct literal`, `undefined: initIssuer`.

Run: `go test ./internal/broker/... ./internal/port49d/ -run CABundle -count=1`
Expected: FAIL to build: `undefined: ParseCABundle`, `unknown field CABundle`, `undefined: loadCABundle`.

- [ ] **Step 3: The config**

In `internal/oidc/config.go`, in `Config`, after `Timing      Timing`, add:

```go
	// Issuance is broker.identity.issuance (plan 9b; spec §13 decision 43
	// rulings 9 and 14): nil when the broker issues no certificate.
	Issuance *Issuance
```

and after the `Config` type:

```go
// Issuance is broker.identity.issuance resolved.
type Issuance struct {
	// CertificateLifetime is certificate_lifetime: 12h by default, 1h to 24h.
	CertificateLifetime time.Duration
}
```

In `internal/config/identity.go`:

- Add `"github.com/rhwendt/port49/internal/issuer"` to the imports.
- In `identityYAML`, replace

  ```go
  	JWKSMaxAge          *time.Duration         `yaml:"jwks_max_age"`
  }
  ```

  with (aligned as `gofmt` leaves it)

  ```go
  	JWKSMaxAge          *time.Duration         `yaml:"jwks_max_age"`
  	Issuance            *issuanceYAML          `yaml:"issuance"`
  }
  ```

  and after the type add:

  ```go
  // issuanceYAML is broker.identity.issuance (plan 9b; spec §13 decision 43).
  // `issuance: {}` turns it on with its defaults.
  type issuanceYAML struct {
  	CertificateLifetime *time.Duration `yaml:"certificate_lifetime"`
  }
  ```

- In `checkIdentity`, replace

  ```go
  	if out.X509AnchorFile == "" && out.X509Machine == nil && len(out.OIDC) == 0 {
  ```

  with

  ```go
  	if y.Issuance != nil {
  		if out.Issuance, err = checkIssuance(*y.Issuance, out.OIDC); err != nil {
  			return nil, err
  		}
  	}
  	if out.X509AnchorFile == "" && out.X509Machine == nil && len(out.OIDC) == 0 {
  ```

- After `checkIdentity`, add:

  ```go
  // checkIssuance resolves broker.identity.issuance (plan 9b; spec §13
  // decision 43 rulings 9 and 14): a certificate is issued over a sign-in, so
  // a human oidc verifier must be listed; certificate_lifetime is 12h by
  // default, 1h to 24h.
  func checkIssuance(y issuanceYAML, vs []oidc.VerifierConfig) (*oidc.Issuance, error) {
  	if !slices.ContainsFunc(vs, func(v oidc.VerifierConfig) bool { return v.Domain == oidc.Humans }) {
  		return nil, errors.New("config: broker.identity.issuance: a certificate is issued over an OIDC sign-in, so " +
  			"list a human oidc verifier under broker.identity.humans")
  	}
  	life := issuer.DefaultLifetime
  	if y.CertificateLifetime != nil {
  		life = *y.CertificateLifetime
  	}
  	if life < issuer.MinLifetime || life > issuer.MaxLifetime {
  		return nil, fmt.Errorf("config: broker.identity.issuance.certificate_lifetime must be between %s and %s; got %s",
  			issuer.MinLifetime, issuer.MaxLifetime, life)
  	}
  	return &oidc.Issuance{CertificateLifetime: life}, nil
  }
  ```

- [ ] **Step 4: `internal/port49d/issuer.go`**

```go
package port49d

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/keyfile"
)

// issuerFiles reads the issuing CA's files in dir (spec §13 decision 43
// ruling 14): the certificates as the broker reads its own kept state
// (readOwnerOnly), the keys through keyfile's owner-only rule. A file that
// is not there is none.
func issuerFiles(dir string) issuer.Files {
	return issuer.Files{
		Cert: func(name string) ([]byte, error) { return readOwnerOnly(filepath.Join(dir, name)) },
		Key: func(name string) ([]byte, error) {
			path := filepath.Join(dir, name)
			if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			return keyfile.ReadSecret(path)
		},
	}
}

// openIssuer loads the issuing CA when broker.identity.issuance is set
// (decision 43 ruling 14), says what it holds, one line per fact, and sets
// the CA's end on its gauge (0 for none). It never refuses the start (R4):
// port49d answers device AAA in the same process.
func openIssuer(cfg config.Config, m *metrics.Metrics, say func(string, ...any)) *issuer.CA {
	dir := brokerStateDir(cfg)
	ca, lines := issuer.Load(issuerFiles(dir), time.Now())
	for _, l := range lines {
		say("issuance: %s", l)
	}
	say("issuance: certificates of %s over an OIDC sign-in, from the issuing CA in %s",
		cfg.Broker.Identity.Issuance.CertificateLifetime, dir)
	if ca.Cert != nil {
		m.IssuingCANotAfter.Set(float64(ca.Cert.NotAfter.Unix()))
	}
	return ca
}

// fingerprintOf is the fingerprint of the one certificate in certPEM, for a
// line that names a CA just written.
func fingerprintOf(certPEM []byte) string {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return "?"
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "?"
	}
	return issuer.Fingerprint(c)
}

// initIssuer is init-issuer (decision 43 ruling 14): the issuing CA made in
// dir, once, the key first. A CA already there and whole writes nothing, so
// a provisioning step may run it twice; half of one is refused.
func initIssuer(dir string, now time.Time) (created bool, line string, err error) {
	f := issuerFiles(dir)
	certPEM, errCert := f.Cert(issuer.CertFile)
	keyPEM, errKey := f.Key(issuer.KeyFile)
	switch {
	case errCert != nil || errKey != nil:
		return false, "", errors.Join(errCert, errKey)
	case certPEM != nil && keyPEM != nil:
		ca, _ := issuer.Load(f, now)
		if ca.Unavailable != nil {
			return false, "", fmt.Errorf("the issuing CA in %s is there and not usable (%v); init never replaces it",
				dir, ca.Unavailable)
		}
		return false, fmt.Sprintf("the issuing CA in %s is already there (%s); nothing written", dir,
			issuer.Fingerprint(ca.Cert)), nil
	case certPEM != nil || keyPEM != nil:
		return false, "", fmt.Errorf("one of %s and %s is in %s without the other; restore it, or remove it on purpose",
			issuer.CertFile, issuer.KeyFile, dir)
	}
	if certPEM, keyPEM, err = issuer.New(now); err != nil {
		return false, "", err
	}
	if err := writeOwnerOnly(filepath.Join(dir, issuer.KeyFile), keyPEM); err != nil {
		return false, "", err
	}
	if err := writeOwnerOnly(filepath.Join(dir, issuer.CertFile), certPEM); err != nil {
		return false, "", err
	}
	return true, fmt.Sprintf("created the issuing CA in %s: %s (%s) and %s, written by uid %d, which the broker must "+
		"run as; on every further broker on this store, copy both into its broker.state_dir; then restart each broker",
		dir, issuer.CertFile, fingerprintOf(certPEM), issuer.KeyFile, os.Geteuid()), nil
}

// rotateIssuer is rotate-issuer (decision 43 ruling 14; R5), run on one
// broker. With no staged CA it stages one: its certificate alone goes to the
// other brokers, which trust it from their next start, and its key stays
// here. With one it promotes it: the current certificate becomes the
// previous, its key is overwritten by the staged key, and the staged becomes
// current. A promotion is refused while an earlier rotation's previous CA is
// still here, since certificates it issued may still be valid, and on a
// broker that holds the staged certificate without its key. Each step is a
// whole-file write, so a promotion interrupted is finished by running it
// again; a staged file that is already the current CA, left by a promotion
// that finished or kept by another broker, is removed and nothing promoted.
func rotateIssuer(dir string, now time.Time) (string, error) {
	f := issuerFiles(dir)
	var cur, curKey, prev, nextCert, nextKey []byte
	for _, r := range []struct {
		dst  *[]byte
		name string
		read func(string) ([]byte, error)
	}{{&cur, issuer.CertFile, f.Cert}, {&curKey, issuer.KeyFile, f.Key}, {&prev, issuer.PreviousCertFile, f.Cert},
		{&nextCert, issuer.NextCertFile, f.Cert}, {&nextKey, issuer.NextKeyFile, f.Key}} {
		raw, err := r.read(r.name)
		if err != nil {
			return "", err
		}
		*r.dst = raw
	}
	join := func(name string) string { return filepath.Join(dir, name) }
	removeNext := func() error {
		for _, name := range []string{issuer.NextKeyFile, issuer.NextCertFile} {
			if err := os.Remove(join(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	switch {
	case cur == nil:
		return "", fmt.Errorf("there is no %s in %s to rotate from; run init-issuer first", issuer.CertFile, dir)
	case nextCert == nil && nextKey == nil:
		certPEM, keyPEM, err := issuer.New(now)
		if err != nil {
			return "", err
		}
		if err := writeOwnerOnly(join(issuer.NextKeyFile), keyPEM); err != nil {
			return "", err
		}
		if err := writeOwnerOnly(join(issuer.NextCertFile), certPEM); err != nil {
			return "", err
		}
		return fmt.Sprintf("staged the next issuing CA in %s (%s): copy %s alone to every other broker on this store "+
			"(its key, %s, stays here) and restart each, so each trusts it; then run rotate-issuer again here to issue "+
			"with it", dir, fingerprintOf(certPEM), issuer.NextCertFile, issuer.NextKeyFile), nil
	case nextCert != nil && bytes.Equal(cur, nextCert) && (nextKey == nil || bytes.Equal(curKey, nextKey)):
		if err := removeNext(); err != nil {
			return "", err
		}
		return fmt.Sprintf("the staged CA in %s is the current one already (%s), so nothing was promoted; removed "+
			"the staged files left from its promotion; if this broker promoted it, copy %s, %s and %s to every "+
			"other broker on this store, and restart each", dir, fingerprintOf(cur), issuer.CertFile, issuer.KeyFile,
			issuer.PreviousCertFile), nil
	case nextKey == nil:
		return "", fmt.Errorf("%s is in %s without %s: this broker trusts the staged CA but cannot promote it; run "+
			"rotate-issuer on the broker that staged it, which holds the key, then copy the files it names here",
			issuer.NextCertFile, dir, issuer.NextKeyFile)
	case nextCert == nil:
		return "", fmt.Errorf("%s is in %s without %s; restore it, or remove it on purpose", issuer.NextKeyFile, dir,
			issuer.NextCertFile)
	case prev != nil && !bytes.Equal(prev, cur) && !bytes.Equal(cur, nextCert):
		return "", fmt.Errorf("%s from an earlier rotation is still in %s, and a promotion would overwrite it while "+
			"certificates it issued may still be valid: remove it once certificate_lifetime has passed since that "+
			"promotion, restart each broker, and run rotate-issuer again", issuer.PreviousCertFile, dir)
	}
	if !bytes.Equal(cur, nextCert) {
		if err := writeOwnerOnly(join(issuer.PreviousCertFile), cur); err != nil {
			return "", err
		}
		if err := writeOwnerOnly(join(issuer.CertFile), nextCert); err != nil {
			return "", err
		}
	}
	if err := writeOwnerOnly(join(issuer.KeyFile), nextKey); err != nil {
		return "", err
	}
	if err := removeNext(); err != nil {
		return "", err
	}
	return fmt.Sprintf("promoted the staged CA in %s (%s): copy %s, %s and %s to every other broker on this store, "+
		"remove the %s staged there, and restart each; each then issues with it and still trusts the previous; after "+
		"certificate_lifetime, remove %s and restart again", dir, fingerprintOf(nextCert), issuer.CertFile,
		issuer.KeyFile, issuer.PreviousCertFile, issuer.NextCertFile, issuer.PreviousCertFile), nil
}

// issuerCmd runs `<proc> init-issuer|rotate-issuer [--config FILE]`
// (decision 43 ruling 14): it reads the config the process starts from and
// acts in its broker's state directory. It is run as the broker's user. It
// exits 0 having done it or found it done, 1 when it would not, and 2 on
// usage.
func issuerCmd(proc, op, defaultConfig string, load func(string) (config.Config, error), args []string,
	stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(proc+" "+op, flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfgPath := flags.String("config", defaultConfig, "path to "+filepath.Base(defaultConfig))
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "usage: %s %s [--config FILE]\n", proc, op)
		return 2
	}
	cfg, err := load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", proc, op, err)
		return 1
	}
	if cfg.Broker == nil || cfg.Broker.Identity == nil || cfg.Broker.Identity.Issuance == nil {
		fmt.Fprintf(stderr, "%s %s: %s configures no broker.identity.issuance; add `issuance: {}` under "+
			"broker.identity first\n", proc, op, *cfgPath)
		return 1
	}
	dir := brokerStateDir(cfg)
	var line string
	if op == "init-issuer" {
		_, line, err = initIssuer(dir, time.Now())
	} else {
		line, err = rotateIssuer(dir, time.Now())
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", proc, op, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: %s\n", proc, line)
	return 0
}
```

- [ ] **Step 5: The start and the subcommands**

In `internal/port49d/main.go`:

- In `Main`, after the `store-roles` dispatch, add:

  ```go
  	if len(args) > 0 && (args[0] == "init-issuer" || args[0] == "rotate-issuer") {
  		return issuerCmd("port49d", args[0], "/etc/port49/port49d.yaml", config.Load, args[1:], os.Stdout, os.Stderr)
  	}
  ```

  and replace the usage line's text `"usage: port49d [--config FILE], port49d init-revocations [--config FILE], "+`
  with `"usage: port49d [--config FILE], port49d init-revocations|init-issuer|rotate-issuer [--config FILE], "+`.
- In `buildBrokerAnchor`, replace

  ```go
  	b.NoX509 = cfg.Broker.ClientCAFile == ""
  	b.Workload = workload
  	announceIdentity(stderr, proc, cfg, b.Identity)
  ```

  with

  ```go
  	b.NoX509 = cfg.Broker.ClientCAFile == ""
  	b.Workload = workload
  	announceIdentity(stderr, proc, cfg, b.Identity)
  	// The issuing CA (plan 9b; decision 43 ruling 14), before the server's
  	// pool is built from it. It never refuses the start.
  	if id := cfg.Broker.Identity; id != nil && id.Issuance != nil {
  		b.Issuer = openIssuer(cfg, m, func(format string, args ...any) {
  			fmt.Fprintf(stderr, proc+": "+format+"\n", args...)
  		})
  		b.CertificateLifetime = id.Issuance.CertificateLifetime
  	}
  ```

In `internal/port49d/brokerd.go`'s `BrokerMain`, after the `revoke` dispatch, add:

```go
	if len(args) > 0 && (args[0] == "init-issuer" || args[0] == "rotate-issuer") {
		return issuerCmd("port49-broker", args[0], "/etc/port49/port49-broker.yaml", config.LoadBroker, args[1:],
			os.Stdout, os.Stderr)
	}
```

and replace its usage line `"usage: port49-broker [--config FILE]"` with `"usage: port49-broker [--config
FILE], or port49-broker revoke|init-issuer|rotate-issuer …"`.

- [ ] **Step 6: The broker's CA bundle (decision 43 ruling 25)**

`GET /v1/config` sends every client the CAs it is to trust for the broker's server certificate,
from `broker.tls_ca_bundle_file`: the CA in use and, through a rotation, the next. Read at start;
a bundle that cannot be read, is out of bounds, or does not verify the server certificate in use is
not sent, said in one line, and the start goes on (R4's rule). Clients keep what they hold.

Create `internal/broker/api/cabundle.go`, whose bounds and parse both ends use:

```go
package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// The bounds on GET /v1/config's broker_ca_bundle (spec §13 decision 43
// ruling 25): the CA in use and the next one through a rotation, with room
// to spare, and never a file of the system's roots.
const (
	MaxCABundleBytes = 64 << 10
	MaxCABundleCerts = 4
)

// ParseCABundle reads a broker CA bundle: 1 to MaxCABundleCerts PEM
// certificates, each a CA, in at most MaxCABundleBytes, holding nothing
// else. Both ends read it so: the broker the file it sends, the client what
// it is sent.
func ParseCABundle(raw []byte) ([]*x509.Certificate, error) {
	if len(raw) > MaxCABundleBytes {
		return nil, fmt.Errorf("the CA bundle is %d bytes, over %d", len(raw), MaxCABundleBytes)
	}
	var out []*x509.Certificate
	rest := raw
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the CA bundle holds a %s block; it holds certificates alone", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the CA bundle's certificate %d: %w", len(out)+1, err)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, fmt.Errorf("the CA bundle's certificate %d (%s) is not a CA", len(out)+1, c.Subject)
		}
		if out = append(out, c); len(out) > MaxCABundleCerts {
			return nil, fmt.Errorf("the CA bundle holds over %d certificates", MaxCABundleCerts)
		}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the CA bundle holds something other than PEM certificates")
	}
	if len(out) == 0 {
		return nil, errors.New("the CA bundle holds no certificate")
	}
	return out, nil
}

// EncodeCABundle is certs as PEM, nothing else.
func EncodeCABundle(certs []*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

// CAFingerprints names certs as a log line does: "sha256:" and the hex
// SHA-256 of each one's DER, comma-separated.
func CAFingerprints(certs []*x509.Certificate) string {
	fps := make([]string, len(certs))
	for i, c := range certs {
		sum := sha256.Sum256(c.Raw)
		fps[i] = "sha256:" + hex.EncodeToString(sum[:])
	}
	return strings.Join(fps, ", ")
}
```

In `internal/broker/api/api.go`, replace

```go
	// Issuance is set when the broker issues a person a certificate over an
	// OIDC sign-in (plan 9b; spec §13 decision 43 ruling 18).
	Issuance *Issuance `json:"issuance,omitempty"`
}
```

with

```go
	// Issuance is set when the broker issues a person a certificate over an
	// OIDC sign-in (plan 9b; spec §13 decision 43 ruling 18).
	Issuance *Issuance `json:"issuance,omitempty"`
	// BrokerCABundle is the CAs a client trusts for this broker's server
	// certificate, PEM: the one in use and, through a rotation, the next
	// (decision 43 ruling 25). Empty when broker.tls_ca_bundle_file is not
	// set.
	BrokerCABundle string `json:"broker_ca_bundle,omitempty"`
	// BrokerCABundleRefused is set when broker.tls_ca_bundle_file is
	// configured and the broker refused it at start (its log says why): a
	// client keeps the CAs it holds, and does not read the missing bundle as
	// the broker sending none.
	BrokerCABundleRefused bool `json:"broker_ca_bundle_refused,omitempty"`
}
```

In `internal/broker/broker.go`, replace

```go
	// CertificateLifetime is broker.identity.issuance.certificate_lifetime
	// (decision 43 ruling 9); zero is issuer.DefaultLifetime.
	CertificateLifetime time.Duration
```

with

```go
	// CertificateLifetime is broker.identity.issuance.certificate_lifetime
	// (decision 43 ruling 9); zero is issuer.DefaultLifetime.
	CertificateLifetime time.Duration
	// CABundle is broker.tls_ca_bundle_file's CAs, PEM, which GET /v1/config
	// sends every client (decision 43 ruling 25); nil sends none.
	CABundle []byte
	// CABundleRefused is a tls_ca_bundle_file configured and refused at
	// start: GET /v1/config says so, and clients keep what they hold.
	CABundleRefused bool
```

In `internal/broker/broker.go`, replace

```go
		c.Issuance = &api.Issuance{CertificateLifetimeSeconds: int(b.certificateLifetime() / time.Second)}
	}
	writeJSON(w, http.StatusOK, c)
```

with

```go
		c.Issuance = &api.Issuance{CertificateLifetimeSeconds: int(b.certificateLifetime() / time.Second)}
	}
	c.BrokerCABundle, c.BrokerCABundleRefused = string(b.CABundle), b.CABundleRefused
	writeJSON(w, http.StatusOK, c)
```

In `internal/config/config.go`, replace

```go
type BrokerConfig struct {
	Listen      string `yaml:"listen"`
	TLSCertFile string `yaml:"tls_cert_file"`
```

with

```go
type BrokerConfig struct {
	Listen      string `yaml:"listen"`
	TLSCertFile string `yaml:"tls_cert_file"`
	// TLSCABundleFile is the CAs clients are to trust for the server
	// certificate, sent on GET /v1/config: the CA in use and, through a
	// rotation, the next (spec §13 decision 43 ruling 25). Optional; read at
	// start, and a bundle that does not verify tls_cert_file is not sent.
	TLSCABundleFile string `yaml:"tls_ca_bundle_file"`
```

In `internal/port49d/main.go`, replace

```go
	var anchors []namedAnchor
	human := namedAnchor{key: "broker.client_ca_file", cert: anchorCert}
```

with

```go
	caBundle, caBundleRefused := loadCABundle(cfg.Broker.TLSCABundleFile, cert, func(format string, args ...any) {
		fmt.Fprintf(stderr, procOf(cfg)+": "+format+"\n", args...)
	})
	var anchors []namedAnchor
	human := namedAnchor{key: "broker.client_ca_file", cert: anchorCert}
```

In `internal/port49d/main.go`, replace

```go
		b.CertificateLifetime = id.Issuance.CertificateLifetime
	}
```

with

```go
		b.CertificateLifetime = id.Issuance.CertificateLifetime
	}
	b.CABundle, b.CABundleRefused = caBundle, caBundleRefused
```

Create `internal/port49d/cabundle.go`:

```go
package port49d

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/rhwendt/port49/internal/broker/api"
)

// loadCABundle is broker.tls_ca_bundle_file's CAs, PEM, which GET
// /v1/config sends every client (spec §13 decision 43 ruling 25), or nil.
// A bundle that cannot be read, is out of api.ParseCABundle's bounds, or
// does not verify the server certificate being served is not sent, and is
// said in one line; the start goes on. refused is then true, and GET
// /v1/config says so (broker_ca_bundle_refused), so clients keep the CAs
// they hold rather than read the broker as one that sends none.
func loadCABundle(path string, cert tls.Certificate, say func(string, ...any)) (bundle []byte, refused bool) {
	if path == "" {
		return nil, false
	}
	certs, err := readCABundle(path)
	if err == nil {
		err = verifiesServer(certs, cert)
	}
	if err != nil {
		say("broker: tls_ca_bundle_file %s: %v; no CA bundle is sent, so clients keep the CAs they hold", path, err)
		return nil, true
	}
	say("broker: tls_ca_bundle_file %s, sent to every client: %s", path, api.CAFingerprints(certs))
	return api.EncodeCABundle(certs), false
}

func readCABundle(path string) ([]*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, api.MaxCABundleBytes+1))
	if err != nil {
		return nil, err
	}
	return api.ParseCABundle(raw)
}

// verifiesServer refuses a bundle that does not hold the CA of the server
// certificate in use: a client would refuse it, and no rotation can start
// from it.
func verifiesServer(certs []*x509.Certificate, cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return errors.New("no server certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range certs {
		roots.AddCert(c)
	}
	for _, der := range cert.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	// Judged inside the leaf's own validity: an expired server certificate
	// is said on its own line, and is not this bundle's fault.
	at := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("it does not hold the CA of the server certificate in tls_cert_file (%v)", err)
	}
	return nil
}
```

The bundle is read beside the server certificate and set on the broker with the issuing CA: the
first `internal/port49d/main.go` edit above goes after the server certificate's validity lines,
the second after `b.CertificateLifetime` is set.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `gofmt -l internal/ && go test ./internal/oidc/ ./internal/config/ ./internal/broker/... ./internal/port49d/ -count=1`
Expected: `gofmt` lists nothing; PASS, every earlier test unchanged.

Run: `go test -race ./internal/port49d/ -run 'Issuer|InterruptedPromotion|NoIssuingCA|CABundle' -count=1 && go vet ./internal/...`
Expected: PASS, and vet silent.

- [ ] **Step 8: Commit**

```bash
git add internal/oidc/config.go internal/config/ internal/port49d/ internal/broker/api/cabundle.go \
  internal/broker/api/cabundle_test.go internal/broker/api/api.go internal/broker/broker.go \
  internal/broker/cabundle_test.go
git commit -m "feat(port49d): broker.identity.issuance, the issuing CA at start, init-issuer and rotate-issuer; the broker's CA bundle"
```

---

### Task 9: The agent says when its certificate ends

The session's deadline stays the broker's: a request past the certificate's end already meets the
broker's refusal, which the agent turns into "your certificate expired at …" and ends the session
(`refusal`, `hangUpError`; `TestAHangUpWithAnExpiredCertificateEndsTheSession` pins it). What the
agent lacks is the end itself, so that `agentMain` (Task 10) exits there and says why, rather than
running on to `max_session_age` with a certificate no broker takes.

**Files:**
- Modify: `internal/agent/agent.go` (`CertificateEnd`)
- Modify: `internal/agent/agent_test.go` (`rigOpts.notAfter`, a test)

**Interfaces:**
- Consumes: the agent's `leaf`; the test rig's `newRigWith`, `rigOpts`.
- Produces, for Task 10: `func (a *Agent) CertificateEnd() time.Time`.

- [ ] **Step 1: Write the failing test**

In `internal/agent/agent_test.go`:

- Replace `type rigOpts struct{ foreign, expired, wrongAnchor bool }` with:

  ```go
  type rigOpts struct {
  	foreign, expired, wrongAnchor bool
  	// notAfter, when set, is the client certificate's end; the session
  	// connects.
  	notAfter time.Time
  }
  ```

- In `newRigWith`, after the `if o.expired {` block, add:

  ```go
  	if !o.notAfter.IsZero() {
  		if cli, err = ca.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
  			NotBefore: now.Add(-time.Hour), NotAfter: o.notAfter}); err != nil {
  			t.Fatal(err)
  		}
  	}
  ```

- Add:

  ```go
  // CertificateEnd is the session certificate's notAfter, which agentMain
  // exits at when it comes before the session's deadline (decision 43 ruling
  // 21). The deadline itself is the broker's, unchanged.
  func TestCertificateEndIsTheCertificatesNotAfter(t *testing.T) {
  	end := time.Now().Add(30 * time.Second).Truncate(time.Second)
  	r := newRigWith(t, rigOpts{notAfter: end})
  	if !r.a.CertificateEnd().Equal(end) || !r.a.SessionEndsAt().After(end) {
  		t.Fatalf("CertificateEnd %s, SessionEndsAt %s, the certificate's end %s", r.a.CertificateEnd(),
  			r.a.SessionEndsAt(), end)
  	}
  	if !(&Agent{}).CertificateEnd().IsZero() {
  		t.Fatal("an agent with no certificate has an end")
  	}
  }
  ```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/agent/ -run TestCertificateEndIsTheCertificatesNotAfter -count=1`
Expected: FAIL to build: `r.a.CertificateEnd undefined`.

- [ ] **Step 3: The end**

In `internal/agent/agent.go`, after `leaf`, add:

```go
// CertificateEnd is the session certificate's notAfter, zero for none (plan
// 9b; spec §13 decision 43 ruling 21). Past it the broker refuses every
// request on the connection (Identity), so the agent process exits there
// (agentMain); a device session a refresh extended runs to its own ceiling
// (spec §5.1.4).
func (a *Agent) CertificateEnd() time.Time {
	if leaf := a.leaf(); leaf != nil {
		return leaf.NotAfter
	}
	return time.Time{}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/agent/ -count=1 && go test -race ./internal/agent/ -count=1`
Expected: PASS, every earlier agent test unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/
git commit -m "feat(agent): CertificateEnd, the end agentMain exits at"
```

---

### Task 10: `port49 login --oidc`: sign in, hold the issued certificate, start the agent

**Files:**
- Modify: `internal/userconfig/userconfig.go` (the four keys, `WithoutOIDCCA`, `IssuedPaths`,
  `IssuedPathsIn`), `internal/userconfig/userconfig_test.go`
- Create: `cmd/port49/issue.go`, `cmd/port49/issue_test.go`, `cmd/port49/issue_login_linux_test.go`,
  `cmd/port49/harden_linux.go`, `cmd/port49/harden_darwin.go`, `cmd/port49/harden_other.go`
- Modify: `cmd/port49/main.go` (usage, `sessionFlags`, `hardenAgent`, `register`, `fill`,
  `complete`, `brokerPool`, `config`, `login`, `startAgent` (new, from `login`), `agentMain`),
  `cmd/port49/main_test.go` (`TestMain`, `newLabBrokerWith`), `cmd/port49/config_test.go`

**Interfaces:**
- Consumes: Task 3's `oidcclient.Provider`, `Discover`, `Skew`, `Tokens`, `UnreachableError`;
  Task 4's `oidcclient.Login`, `LoginOptions`, `ErrNoWayBack`; Task 5's `issuer.ReadSignIn`,
  `issuer.SignIn`, `issuer.Ephemeral`, `api.IssuanceNonce`, `api.IssueRequest`, `api.IssueResponse`;
  Task 7's `POST /v1/certificate` and `api.Config.Issuance`; Task 9's `agent.CertificateEnd`;
  `api.LateRenewal`; `keyfile.LoadX509KeyPair`; `userconfig.ReadPrivate`, `WritePrivate`; the
  tests' `privateSocket`, `privateDir`, `stopAgentAt`, `labConfig`, `runningAgent`,
  `configBroker`, `runCLIEnv`, `labBroker`.
- Produces (the end of the chain):
  - `userconfig.File.Method`, `OIDCIssuer`, `OIDCCA`, `OIDCRedirectPort`, `OIDCCAPEM`;
    `userconfig.WithoutOIDCCA()`; `userconfig.IssuedPaths(broker string) (cert, key string, err error)`;
    `userconfig.IssuedPathsIn(dir, broker string) (cert, key string, err error)`
  - `loginIssued`, `issueCertificate`, `requestCertificate`, `heldCertificate`, `startIssued`,
    `startAgent`, `signIn`, `browserCommand`, `launchBrowser`, `pickProvider`,
    `fetchBrokerConfig`, `warnSkew`, `harden`, `hardenAgent`, `brokerPool`, `oidcRoots`
  - `newLabBrokerWith(t, maxAge, iss, issue)` (tests)

- [ ] **Step 1: Write the failing tests**

In `internal/userconfig/userconfig_test.go`, add:

```go
// The OIDC keys (decision 43 ruling 19): oidc_ca is resolved and read once
// through the walk, as broker_ca is.
func TestTheOIDCKeysAreRead(t *testing.T) {
	p := private(t, "config.yaml", "method: oidc\noidc_issuer: https://kc.example/r\noidc_ca: idp.pem\n"+
		"oidc_redirect_port: 18749\n")
	ca := filepath.Join(filepath.Dir(p), "idp.pem")
	if err := os.WriteFile(ca, []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok, err := Load(p)
	if err != nil || !ok || f.Method != "oidc" || f.OIDCIssuer != "https://kc.example/r" || f.OIDCCA != ca ||
		string(f.OIDCCAPEM) != "PEM" || f.OIDCRedirectPort != 18749 {
		t.Fatalf("%+v %v %v", f, ok, err)
	}
	if f, _, err := Load(p, WithoutOIDCCA()); err != nil || f.OIDCCAPEM != nil {
		t.Fatalf("WithoutOIDCCA: %q %v", f.OIDCCAPEM, err)
	}
}

func TestAnOIDCCAOthersCanWriteIsRefused(t *testing.T) {
	p := private(t, "config.yaml", "oidc_ca: idp.pem\n")
	ca := filepath.Join(filepath.Dir(p), "idp.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ca, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), ca+" is writable by others") ||
		!strings.Contains(err.Error(), "oidc_ca in") {
		t.Fatalf("%v", err)
	}
}

func TestAnUnknownMethodOrABadPortIsRefused(t *testing.T) {
	for body, want := range map[string]string{
		"method: saml\n":              `method "saml"`,
		"oidc_redirect_port: 70000\n": "is not a port",
		"oidc_redirect_port: -1\n":    "is not a port",
	} {
		if _, _, err := Load(private(t, "config.yaml", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
}

// An issued certificate is kept per broker, by its host and port, and a
// broker URL that would not make a plain file name is refused (decision 43
// ruling 7).
func TestIssuedPaths(t *testing.T) {
	for broker, want := range map[string]string{
		"https://Broker.Example:8443":  "broker.example_8443",
		"https://broker.example":       "broker.example_443",
		"https://[2001:db8::1]:8443/x": "2001-db8--1_8443",
	} {
		c, k, err := IssuedPathsIn("/d", broker)
		if err != nil || c != "/d/issued/"+want+".pem" || k != "/d/issued/"+want+".key" {
			t.Errorf("%s: %s %s %v", broker, c, k, err)
		}
	}
	for _, bad := range []string{"http://broker.example", "https://", "https://u:p@broker.example", "broker.example:8443"} {
		if _, _, err := IssuedPathsIn("/d", bad); err == nil {
			t.Errorf("%q made a path", bad)
		}
	}
}
```

Create `cmd/port49/issue_test.go`:

```go
package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidcclient"
	"github.com/rhwendt/port49/internal/testpki"
)

// A browser is launched only where one can be seen (decision 43 ruling 5).
func TestBrowserCommand(t *testing.T) {
	for _, c := range []struct {
		goos string
		env  map[string]string
		want string
	}{
		{"linux", map[string]string{"DISPLAY": ":0"}, "xdg-open U"},
		{"linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, "xdg-open U"},
		{"linux", map[string]string{"SSH_CONNECTION": "10.0.0.1 22 10.0.0.2 22"}, ""},
		{"linux", nil, ""},
		{"darwin", nil, "open U"},
		{"darwin", map[string]string{"SSH_TTY": "/dev/ttys001"}, ""},
		{"linux", map[string]string{"BROWSER": "firefox"}, "firefox U"},
		{"darwin", map[string]string{"BROWSER": "firefox", "SSH_TTY": "/dev/ttys001"}, "firefox U"},
	} {
		got := strings.Join(browserCommand(c.goos, func(k string) string { return c.env[k] }, "U"), " ")
		if got != c.want {
			t.Errorf("%s %v: %q, want %q", c.goos, c.env, got, c.want)
		}
	}
}

func TestPickProvider(t *testing.T) {
	one := api.Config{Methods: []string{"x509", "oidc"}, OIDC: []api.OIDCProvider{{Issuer: "https://a"}}}
	two := api.Config{Methods: []string{"oidc"}, OIDC: []api.OIDCProvider{{Issuer: "https://a"}, {Issuer: "https://b"}}}
	if p, err := pickProvider(one, ""); err != nil || p.Issuer != "https://a" {
		t.Fatalf("one: %v %v", p, err)
	}
	if p, err := pickProvider(two, "https://b"); err != nil || p.Issuer != "https://b" {
		t.Fatalf("named: %v %v", p, err)
	}
	for name, c := range map[string]struct {
		conf   api.Config
		issuer string
		want   string
	}{
		"none listed":  {api.Config{Methods: []string{"x509"}}, "", "takes no OIDC login"},
		"two unnamed":  {two, "", "name one with --issuer or oidc_issuer"},
		"not listed":   {two, "https://c", "does not list https://c"},
		"by its slash": {one, "https://a/", "does not list"},
	} {
		if _, err := pickProvider(c.conf, c.issuer); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// A skew over 5 minutes is said, never refused (ruling 6).
func TestASkewedClockIsWarnedNotRefused(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	var b bytes.Buffer
	warnSkew(&b, "port49 login", oidcclient.Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(2 * time.Minute)})
	if b.Len() != 0 {
		t.Fatalf("2m: %q", b.String())
	}
	warnSkew(&b, "port49 login", oidcclient.Tokens{ID: oidc.IDToken{IssuedAt: at}, Received: at.Add(-7 * time.Minute)})
	if !strings.Contains(b.String(), "this host's clock is 7m0s behind your identity provider's") {
		t.Fatalf("%q", b.String())
	}
}

// --cert or --key beside --oidc is a usage error, and so are the OIDC flags
// without it (ruling 19).
func TestTheLoginFlagsAreOneMethodsOrTheOthers(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--oidc", "--cert", "c.pem"}, "--cert and --key are a certificate login's"},
		{[]string{"--sign-in"}, "--sign-in is --oidc's"},
		{[]string{"--issuer", "https://a"}, "--issuer is --oidc's"},
	} {
		// An empty config file of its own: the test's default path may hold
		// another test's, and a missing --config is its own refusal.
		cfg := filepath.Join(privateDir(t), "config.yaml")
		if err := os.WriteFile(cfg, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		args := append(append([]string{"login"}, c.args...), "--broker", configBroker, "--broker-ca", "ca.pem",
			"--config", cfg)
		if code := run(args, &out, &errb); code != 2 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%v: code %d %q", c.args, code, errb.String())
		}
	}
}

// A held certificate is one port49 issued: missing files are ErrNotExist,
// and a certificate an organization's CA issued is not one.
func TestHeldCertificateReadsOnlyWhatTheBrokerIssued(t *testing.T) {
	dir := privateDir(t)
	if _, _, err := heldCertificate(filepath.Join(dir, "x.pem"), filepath.Join(dir, "x.key")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no files: %v", err)
	}
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := heldCertificate(filepath.Join(dir, testpki.LabClientCert), filepath.Join(dir, testpki.LabClientKey)); err == nil ||
		!strings.Contains(err.Error(), "not a certificate port49 issued") {
		t.Fatalf("the lab's certificate: %v", err)
	}
}

// An agent that cannot make itself non-dumpable says so and runs on: the
// key is a file this user reads already (ruling 21).
func TestAnAgentThatCannotHardenRunsOn(t *testing.T) {
	saved := hardenAgent
	hardenAgent = func() error { return errors.New("prctl: operation not permitted") }
	t.Cleanup(func() { hardenAgent = saved })
	var out, errb bytes.Buffer
	if code := run([]string{"agent", "--broker-ca", "ca.pem", "--config", filepath.Join(t.TempDir(), "none.yaml")},
		&out, &errb); code != 2 || !strings.Contains(errb.String(), "could not make the agent non-dumpable") ||
		!strings.Contains(errb.String(), "it runs on") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}
```

In `cmd/port49/config_test.go`, add:

```go
// method: oidc in the file makes a plain login an OIDC one: against a
// running agent holding another certificate it is refused, naming it.
func TestTheConfigFileCanChooseOIDC(t *testing.T) {
	dir := privateDir(t)
	cfg := labConfig(t, dir, configBroker)
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("method: oidc\n")
	f.Close()
	sock, refreshes := runningAgent(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"login", "--config", cfg, "--socket", sock}, &out, &errb)
	if code != 1 || refreshes() != 0 || !strings.Contains(errb.String(), "with another certificate") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}
```

Create `cmd/port49/issue_login_linux_test.go`:

```go
//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

// oidcLab is a real OIDC-only broker (newLabBrokerWith), issuing when
// newOIDCLab is told to, trusting an issuer whose authorization server
// signs alice in.
type oidcLab struct {
	*labBroker
	iss   *oidctest.Issuer
	as    *oidctest.AuthServer
	idpCA string
}

func newOIDCLab(t *testing.T, issue bool) *oidcLab {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	l := newLabBrokerWith(t, 12*time.Hour, iss, issue)
	o := &oidcLab{labBroker: l, iss: iss,
		as: iss.AuthServer(t, "port49-cli", "sub-alice", map[string]any{"preferred_username": "alice@example.com"})}
	o.as.Now = l.now
	o.idpCA = filepath.Join(privateDir(t), "idp-ca.pem")
	if err := os.WriteFile(o.idpCA, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return o
}

func (o *oidcLab) flags(socket string, extra ...string) []string {
	return append([]string{"--oidc", "--broker", o.url, "--broker-ca", filepath.Join(o.dir, testpki.LabCA),
		"--oidc-ca", o.idpCA, "--socket", socket}, extra...)
}

// issuedPaths is where the login keeps this broker's certificate and key.
func (o *oidcLab) issuedPaths(t *testing.T) (string, string) {
	t.Helper()
	c, k, err := userconfig.IssuedPaths(o.url)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// holdCertificate writes a certificate the broker issued at at, for
// lifetime, and its key, where the login keeps them, as a login at that
// time would have.
func (o *oidcLab) holdCertificate(t *testing.T, at time.Time, lifetime time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.b.Issuer.Issue(key.Public(), issuer.SignIn{Principal: "user:alice@example.com", Issuer: o.iss.URL,
		Subject: "sub-alice", Sid: "s-sub-alice", AuthTime: at, IssuedAt: at}, at, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := o.issuedPaths(t)
	if err := userconfig.WritePrivate(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"test key"); err != nil {
		t.Fatal(err)
	}
	if err := userconfig.WritePrivate(certPath, o.b.Issuer.PEM(c), "test certificate"); err != nil {
		t.Fatal(err)
	}
}

// driveBrowser makes the sign-in's browser the issuer's: it follows the
// provider's redirect to the loopback listener, as a person's does.
func driveBrowser(t *testing.T, iss *oidctest.Issuer) {
	t.Helper()
	saved, savedTerm := openBrowser, stdinIsTerminal
	openBrowser = func(u string) error {
		go func() { _ = iss.Browser()(u) }()
		return nil
	}
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { openBrowser, stdinIsTerminal = saved, savedTerm })
}

// agentLog is the log of the agent listening on sock.
func agentLog(sock string) string {
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(sock), "agent.log"))
	return string(b)
}

// credentialsNowhere fails if any text holds a value the provider issued,
// a PKCE verifier the login sent it, or the first line of the issued key's
// PEM.
func (o *oidcLab) credentialsNowhere(t *testing.T, texts ...string) {
	t.Helper()
	secrets := o.as.Issued()
	for _, g := range o.as.Grants() {
		if v := g.Get("code_verifier"); v != "" {
			secrets = append(secrets, v)
		}
	}
	_, keyPath := o.issuedPaths(t)
	if raw, err := os.ReadFile(keyPath); err == nil {
		if blk, _ := pem.Decode(raw); blk != nil {
			secrets = append(secrets, base64.StdEncoding.EncodeToString(blk.Bytes)[:40])
		}
	}
	for _, text := range texts {
		for _, v := range secrets {
			if strings.Contains(text, v) {
				t.Fatal("a code, a token, a verifier or the key reached the terminal or the agent's log")
			}
		}
	}
}

// peerPid is the pid of the process listening on sock.
func peerPid(t *testing.T, sock string) int {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var cred *syscall.Ucred
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) { cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
	if cred == nil {
		t.Fatal("no peer credentials")
	}
	return int(cred.Pid)
}

// The real path: login signs in with the key's hash as the nonce, the broker
// issues, the key and certificate are kept 0600, the agent starts on them
// and refreshes once (D1: a key signature, no second sign-in), and `port49
// token` mints; the agent is non-dumpable; nothing the provider issued, nor
// the key, reaches the terminal or the log.
func TestLoginOIDCIssuesACertificateAndMints(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: signed in at "+o.iss.URL+" as user:alice@example.com; your "+
			"certificate from "+o.url+" is valid until ") ||
		!strings.Contains(out.String(), "port49: logged in to "+o.url) ||
		!strings.Contains(out.String(), "\nrefreshed at ") || !strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	certPath, keyPath := o.issuedPaths(t)
	held, s, err := heldCertificate(certPath, keyPath)
	if err != nil || s.Principal != "user:alice@example.com" || s.Sid != "s-sub-alice" {
		t.Fatalf("the held certificate: %+v %v", s, err)
	}
	want, _ := api.IssuanceNonce(held.PrivateKey.(crypto.Signer).Public())
	if q := o.as.Authorizations(); len(q) != 1 || q[0].Get("prompt") != "login" || q[0].Get("nonce") != want {
		t.Fatalf("%d sign-ins, the nonce the key's hash: %v", len(q), len(q) == 1 && q[0].Get("nonce") == want)
	}
	for _, p := range []string{certPath, keyPath} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	var tok, terr bytes.Buffer
	if code := run([]string{"token", "--socket", sock, "leaf1"}, &tok, &terr); code != 0 || strings.TrimSpace(tok.String()) == "" {
		t.Fatalf("token: code %d stderr %q", code, terr.String())
	}
	if os.Getuid() != 0 {
		// A non-dumpable process's /proc/<pid> files are root's (proc(5)),
		// which a user namespace with root unmapped shows as the overflow
		// uid: either way, not this user's.
		fi, err := os.Stat(fmt.Sprintf("/proc/%d/environ", peerPid(t, sock)))
		if err != nil {
			t.Fatal(err)
		}
		if uid := fi.Sys().(*syscall.Stat_t).Uid; uid == uint32(os.Getuid()) {
			t.Fatalf("the agent is dumpable: its /proc/<pid>/environ is this user's (uid %d)", uid)
		}
	}
	o.credentialsNowhere(t, out.String(), errb.String(), terr.String(), agentLog(sock))
}

// After the sign-in, no browser: a login with the agent running refreshes by
// the key; a new agent over the held certificate (a reboot) signs in no more
// and extends the device sessions an earlier login left (D1); `port49
// refresh` is a key signature; --sign-in with the agent running is refused.
func TestALoginOverAHeldCertificateSignsInNoMore(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %q", code, errb.String())
	}
	o.step(11 * time.Second) // past the connection's refresh pacing
	out.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "port49: already logged in to "+o.url+" as user:alice@example.com; refreshing\n") ||
		!strings.Contains(out.String(), "extended to") {
		t.Fatalf("with the agent running: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	stopAgentAt(sock)
	out.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "port49: using your certificate for user:alice@example.com (signed in at "+o.iss.URL) ||
		!strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("a new agent: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	o.step(11 * time.Second)
	out.Reset()
	if code := run([]string{"refresh", "--socket", sock}, &out, &errb); code != 0 || !strings.Contains(out.String(), "extended to") {
		t.Fatalf("refresh: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	errb.Reset()
	if code := run(append([]string{"login"}, o.flags(sock, "--sign-in")...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "stop that agent first") {
		t.Fatalf("--sign-in with the agent running: code %d stderr %q", code, errb.String())
	}
	if n := len(o.as.Authorizations()); n != 1 {
		t.Fatalf("%d sign-ins; one was due", n)
	}
	o.credentialsNowhere(t, out.String(), errb.String(), agentLog(sock))
}

// A held certificate with under a quarter of its life left is replaced by a
// sign-in (ruling 12).
func TestALateCertificateSignsInAgain(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	o.holdCertificate(t, time.Now().Add(-11*time.Hour), 12*time.Hour)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: signed in at ") || len(o.as.Authorizations()) != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// The provider down at 3am, a late certificate still valid: the login says
// the provider did not answer, uses the certificate, and the agent mints
// (rulings 12 and 17).
func TestAProviderOutageUsesAHeldCertificate(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	o.holdCertificate(t, time.Now().Add(-11*time.Hour), 12*time.Hour)
	o.iss.Close()
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), "did not answer") || !strings.Contains(errb.String(), "needs no identity provider") ||
		!strings.Contains(errb.String(), "until your identity provider answers") ||
		!strings.Contains(out.String(), "port49: logged in to "+o.url) {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	var tok, terr bytes.Buffer
	if code := run([]string{"token", "--socket", sock, "leaf1"}, &tok, &terr); code != 0 {
		t.Fatalf("token: code %d stderr %q", code, terr.String())
	}
}

// The provider down, nothing held: said at once, exit 1, no agent started.
func TestAProviderOutageWithNoCertificateSaysSo(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	o.iss.Close()
	sock := privateSocket(t)
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "did not answer") || !strings.Contains(errb.String(), "cannot sign you in until it answers") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("an agent started")
	}
}

// A held certificate whose sign-in a logout ended: the new agent's refresh
// is refused in the broker's words, the login removes the certificate and
// its key, and says the next login signs in (ruling 12; R6).
func TestARevokedHeldCertificateIsRemoved(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %q", code, errb.String())
	}
	stopAgentAt(sock)
	if _, err := o.b.Logout(context.Background(), oidc.LogoutToken{Issuer: o.iss.URL, Sid: "s-sub-alice",
		IssuedAt: o.now(), Domains: []string{"example.com"}}, "backchannel_logout "+o.iss.URL); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "the broker refused your certificate") ||
		!strings.Contains(errb.String(), "back-channel logout") || !strings.Contains(errb.String(), "it is removed") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	certPath, keyPath := o.issuedPaths(t)
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s is still there: %v", p, err)
		}
	}
}

// A held certificate the broker refuses at the handshake (its clock past the
// certificate's end, this host's not): the login says to sign in again.
func TestABrokerThatRefusesAHeldCertificateSaysToSignIn(t *testing.T) {
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("login: %d %q", code, errb.String())
	}
	stopAgentAt(sock)
	o.step(13 * time.Hour)
	errb.Reset()
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "`port49 login --sign-in` signs you in again") || len(o.as.Authorizations()) != 1 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// With no browser, the address is printed and a pasted one completes the
// sign-in (ruling 5).
func TestLoginOIDCWithAPastedAddress(t *testing.T) {
	o := newOIDCLab(t, true)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	urls := make(chan string, 1)
	saved := [3]any{openBrowser, stdinIsTerminal, readPaste}
	openBrowser = func(u string) error { urls <- u; return fmt.Errorf("no display") }
	stdinIsTerminal = func() bool { return true }
	readPaste = func() (string, error) { return o.iss.Redirected(<-urls) }
	t.Cleanup(func() {
		openBrowser = saved[0].(func(string) error)
		stdinIsTerminal = saved[1].(func() bool)
		readPaste = saved[2].(func() (string, error))
	})
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), "open this address in a browser") ||
		!strings.Contains(errb.String(), "paste it here (it is not shown)") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	o.credentialsNowhere(t, out.String(), errb.String())
}

// No browser and no terminal, with an ephemeral port: said at once, naming
// the two ways that work (ruling 5).
func TestLoginOIDCWithNoWayBackSaysSoAtOnce(t *testing.T) {
	o := newOIDCLab(t, true)
	saved, savedTerm := openBrowser, stdinIsTerminal
	openBrowser = func(string) error { return fmt.Errorf("no display") }
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { openBrowser, stdinIsTerminal = saved, savedTerm })
	var out, errb bytes.Buffer
	start := time.Now()
	if code := run(append([]string{"login"}, o.flags(privateSocket(t))...), &out, &errb); code != 1 ||
		time.Since(start) > 10*time.Second || !strings.Contains(errb.String(), "ssh -t") ||
		!strings.Contains(errb.String(), "--redirect-port") || strings.Contains(errb.String(), "https://") {
		t.Fatalf("code %d after %s, stderr %q", code, time.Since(start), errb.String())
	}
}

// A provider that answers and is refused is not an outage: waiting changes
// nothing, so the login does not say to wait for it.
func TestADiscoveryRefusalIsNotAnOutage(t *testing.T) {
	o := newOIDCLab(t, true)
	o.iss.Discovery(func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} })
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(privateSocket(t))...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "S256") || strings.Contains(errb.String(), "until it answers") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// A broker that issues nothing is said, before any sign-in.
func TestABrokerThatIssuesNothingIsSaid(t *testing.T) {
	o := newOIDCLab(t, false)
	driveBrowser(t, o.iss)
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(privateSocket(t))...), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "issues no certificates") || len(o.as.Authorizations()) != 0 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/userconfig/ ./cmd/port49/ -run 'OIDC|Issued|BrowserCommand|PickProvider|Skewed|UnknownMethod|ChooseOIDC|LoginFlags|HeldCertificate|CannotHarden|ProviderOutage|LateCertificate|RevokedHeld|RefusesAHeld|DiscoveryRefusal|IssuesNothing|NoWayBack|PastedAddress' -count=1`
Expected: FAIL to build: `unknown field Method`, `undefined: browserCommand`, `undefined:
newLabBrokerWith`, `undefined: hardenAgent`, `undefined: heldCertificate`.

- [ ] **Step 3: The config file's keys and the issued paths**

In `internal/userconfig/userconfig.go`:

- In the package comment, replace ``config.yaml,
  // which gives `port49 login` its broker, broker CA, certificate and key;`` with ``config.yaml,
  // which gives `port49 login` its broker, broker CA, certificate and key, or its
  // identity provider (spec §13 decision 43 ruling 19), and the certificate the
  // broker issued it (IssuedPaths);``.
- Add `"net/url"` to the imports.
- Replace `File` with:

  ```go
  // File is config.yaml. Every key is optional; `port49 login` takes each one
  // its flags leave out. Paths are resolved by Load: relative to the file's
  // directory, and ~/ the home directory.
  type File struct {
  	Broker   string `yaml:"broker"`
  	BrokerCA string `yaml:"broker_ca"`
  	Cert     string `yaml:"cert"`
  	Key      string `yaml:"key"`
  	// Method is how `port49 login` authenticates: x509, the default, or
  	// oidc, a sign-in the broker issues a certificate for (decision 43
  	// ruling 19).
  	Method string `yaml:"method"`
  	// OIDCIssuer names the provider to sign in at when the broker lists
  	// several.
  	OIDCIssuer string `yaml:"oidc_issuer"`
  	// OIDCCA is the CA that issued the provider's TLS certificate; none is
  	// the system's roots.
  	OIDCCA string `yaml:"oidc_ca"`
  	// OIDCRedirectPort is the loopback port a sign-in returns to; 0 picks a
  	// free one.
  	OIDCRedirectPort int `yaml:"oidc_redirect_port"`

  	// BrokerCAPEM is the bytes of the file BrokerCA names, read once by Load
  	// through the same ownership walk; nil under WithoutCA or with no CA named.
  	BrokerCAPEM []byte `yaml:"-"`
  	// OIDCCAPEM is OIDCCA's bytes, read as BrokerCAPEM is; nil under
  	// WithoutOIDCCA or with none named.
  	OIDCCAPEM []byte `yaml:"-"`
  }
  ```

- Replace `type loadOptions struct{ skipCA bool }` with:

  ```go
  type loadOptions struct{ skipCA, skipOIDCCA bool }

  // WithoutOIDCCA is WithoutCA for oidc_ca, which --oidc-ca overrides.
  func WithoutOIDCCA() Option { return func(o *loadOptions) { o.skipOIDCCA = true } }
  ```

- In `Load`, replace `for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key} {` with:

  ```go
  	switch f.Method {
  	case "", "x509", "oidc":
  	default:
  		return File{}, false, fmt.Errorf("%s: method %q: port49 logs in by x509 or oidc", path, f.Method)
  	}
  	if f.OIDCRedirectPort < 0 || f.OIDCRedirectPort > 65535 {
  		return File{}, false, fmt.Errorf("%s: oidc_redirect_port %d is not a port", path, f.OIDCRedirectPort)
  	}
  	for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key, &f.OIDCCA} {
  ```

  and before `return f, true, nil` add:

  ```go
  	// The provider's CA decides whose sign-in port49 trusts, as the broker
  	// CA decides the broker: held to the same line, read once.
  	if f.OIDCCA != "" && !o.skipOIDCCA {
  		if f.OIDCCAPEM, err = ReadPrivate(f.OIDCCA, maxCA, "identity provider CA"); err != nil {
  			return File{}, false, fmt.Errorf("oidc_ca in %s: %w", path, err)
  		}
  	}
  ```

- After `Path`, add:

  ```go
  // IssuedPathsIn is where, under dir, `port49 login` keeps the certificate a
  // broker issued it and its key (spec §13 decision 43 ruling 7):
  // dir/issued/<host>_<port>.pem and .key, one pair per broker. A broker URL
  // that is not https with a host, or whose host is not a plain name or
  // address, is refused rather than made a file name.
  func IssuedPathsIn(dir, broker string) (cert, key string, err error) {
  	u, err := url.Parse(broker)
  	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
  		return "", "", fmt.Errorf("broker %q is not an https URL with a host", broker)
  	}
  	port := u.Port()
  	if port == "" {
  		port = "443"
  	}
  	host := strings.ToLower(strings.ReplaceAll(u.Hostname(), ":", "-"))
  	if strings.HasPrefix(host, ".") || strings.IndexFunc(host, func(r rune) bool {
  		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-')
  	}) >= 0 {
  		return "", "", fmt.Errorf("broker %q: its host is not a plain name or address", broker)
  	}
  	base := filepath.Join(dir, "issued", host+"_"+port)
  	return base + ".pem", base + ".key", nil
  }

  // IssuedPaths is IssuedPathsIn the config directory (Dir).
  func IssuedPaths(broker string) (cert, key string, err error) { return IssuedPathsIn(Dir(), broker) }
  ```

- [ ] **Step 4: `harden_linux.go`, `harden_darwin.go` and `harden_other.go`**

```go
//go:build linux

package main

import "golang.org/x/sys/unix"

// harden makes the agent process non-dumpable (spec §13 decision 43 ruling
// 21): no core file or crash report holds the session's key, and no process
// of this user can ptrace it. /proc/<pid> becomes root's.
func harden() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
```

```go
//go:build darwin

package main

import "golang.org/x/sys/unix"

// harden denies the agent process to a debugger (spec §13 decision 43 ruling
// 21): ptrace(PT_DENY_ATTACH), harden_linux.go's PR_SET_DUMPABLE on macOS,
// with no cgo.
func harden() error { return unix.PtraceDenyAttach() }
```

```go
//go:build !linux && !darwin

package main

// harden is Linux's and macOS's alone (harden_linux.go, harden_darwin.go);
// elsewhere the OS's own protection of a process's memory is all there is.
func harden() error { return nil }
```

Check the macOS build: `CGO_ENABLED=0 GOOS=darwin go vet ./cmd/port49/` is silent.

- [ ] **Step 5: `cmd/port49/issue.go`**

```go
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/oidcclient"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/userconfig"
)

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// loginIssued is `port49 login` on the OIDC path (spec §13 decision 43
// rulings 7, 8, 11, 12 and 17): a certificate the broker issues over a
// sign-in at the provider it lists. A held one with more than a quarter of
// its life left is used with no sign-in; otherwise this process signs in,
// generates a key, and asks the broker for a certificate for it. The agent
// then holds the session as on the certificate path, so a refresh, and a
// new agent's extension of the device sessions an earlier login left, are
// key signatures (ruling 11). With the provider down, a held certificate
// still valid is used, late or not.
func loginIssued(sf *sessionFlags, stdout, stderr io.Writer) int {
	ctx := context.Background()
	if sf.broker == "" {
		fmt.Fprintf(stderr, "port49 login: --broker and --broker-ca are required, as flags or in %s\n", sf.configFile)
		return 2
	}
	pool, err := sf.brokerPool()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	certPath, keyPath, err := userconfig.IssuedPaths(sf.broker)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	held, s, heldErr := heldCertificate(certPath, keyPath)
	if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
		// As on the certificate path: only the session this certificate
		// holds is refreshed; another's is someone else's identity.
		var other string
		switch {
		case strings.TrimRight(sf.broker, "/") != st.Broker:
			other = fmt.Sprintf("an agent logged in to %s", st.Broker)
		case heldErr != nil || agent.CertFingerprint(held) != st.CertFingerprint:
			other = fmt.Sprintf("an agent for %s with another certificate", st.Broker)
		}
		if other != "" {
			fmt.Fprintf(stderr, "port49 login: %s already holds %s; run 'port49 refresh' to extend that session, "+
				"stop that agent first, or use --socket\n", other, sf.socket)
			return 1
		}
		if sf.signIn {
			fmt.Fprintf(stderr, "port49 login: an agent already holds your session at %s, with your certificate for %s "+
				"valid until %s; `port49 refresh` extends it; to sign in again, stop that agent first\n", st.Broker,
				s.Principal, rfc3339(held.Leaf.NotAfter))
			return 1
		}
		fmt.Fprintf(stdout, "port49: already logged in to %s as %s; refreshing\n", st.Broker, s.Principal)
		out, err := agent.NewClient(sf.socket).Refresh(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "port49 login: refreshing the running agent's session:", unprefixed(err))
			return 1
		}
		printRefresh(stdout, out)
		return 0
	}
	now := time.Now()
	if heldErr != nil && !errors.Is(heldErr, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "port49 login: your held certificate is not used: %v\n", heldErr)
	}
	usable := heldErr == nil && now.Before(held.Leaf.NotAfter)
	if usable && !sf.signIn && !api.LateRenewal(held.Leaf, now) {
		fmt.Fprintf(stdout, "port49: using your certificate for %s (signed in at %s at %s), valid until %s; "+
			"`port49 login --sign-in` signs in again\n", s.Principal, s.Issuer, rfc3339(s.AuthTime),
			rfc3339(held.Leaf.NotAfter))
		return startIssued(sf, certPath, keyPath, true, stdout, stderr)
	}
	code, down := issueCertificate(ctx, sf, pool, certPath, keyPath, stdout, stderr)
	switch {
	case code == 0:
		return startIssued(sf, certPath, keyPath, false, stdout, stderr)
	case down && usable && !sf.signIn:
		fmt.Fprintf(stderr, "port49 login: using your certificate for %s, valid until %s, until your identity "+
			"provider answers\n", s.Principal, rfc3339(held.Leaf.NotAfter))
		return startIssued(sf, certPath, keyPath, true, stdout, stderr)
	case down && usable:
		fmt.Fprintf(stderr, "port49 login: your certificate for %s is valid until %s: `port49 login` without "+
			"--sign-in uses it\n", s.Principal, rfc3339(held.Leaf.NotAfter))
	}
	return code
}

// startIssued starts the agent on the issued certificate and its key, as
// --cert and --key would (ruling 7). A held one the agent could not connect
// with, still there, is said: the broker's clock may be past its end.
func startIssued(sf *sessionFlags, certPath, keyPath string, held bool, stdout, stderr io.Writer) int {
	sf.cert, sf.key = certPath, keyPath
	code := startAgent(sf, true, stdout, stderr)
	if _, err := os.Stat(certPath); code != 0 && held && err == nil {
		fmt.Fprintln(stderr, "port49 login: if the broker refused your held certificate, `port49 login --sign-in` "+
			"signs you in again")
	}
	return code
}

// heldCertificate is the certificate a broker issued this user and its key,
// from certPath and keyPath, with the sign-in it carries. A file not there
// is fs.ErrNotExist.
func heldCertificate(certPath, keyPath string) (tls.Certificate, issuer.SignIn, error) {
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Lstat(p); err != nil {
			return tls.Certificate{}, issuer.SignIn{}, err
		}
	}
	// Refused if the key is a symlink or readable by anyone but its owner
	// (keyfile; pre-flight F14).
	c, err := keyfile.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, issuer.SignIn{}, err
	}
	if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
		return tls.Certificate{}, issuer.SignIn{}, err
	}
	s, err := issuer.ReadSignIn(c.Leaf)
	if err != nil {
		return tls.Certificate{}, issuer.SignIn{}, fmt.Errorf("%s is not a certificate port49 issued: %v", certPath, err)
	}
	return c, s, nil
}

// issueCertificate signs in at the provider the broker lists and asks the
// broker for a certificate for a key generated here (decision 43 rulings 2,
// 3, 7 and 8), and keeps the key and then the certificate. down is whether
// the provider did not answer, which a held certificate outlives.
func issueCertificate(ctx context.Context, sf *sessionFlags, pool *x509.CertPool, certPath, keyPath string,
	stdout, stderr io.Writer) (code int, down bool) {
	conf, err := fetchBrokerConfig(ctx, sf.broker, pool)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1, false
	}
	if conf.Issuance == nil {
		fmt.Fprintf(stderr, "port49 login: the broker at %s issues no certificates (its broker.identity has no "+
			"issuance), so --oidc cannot log in there; log in with a certificate (--cert and --key)\n", sf.broker)
		return 1, false
	}
	prov, err := pickProvider(conf, sf.issuer)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1, false
	}
	roots, err := sf.oidcRoots()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2, false
	}
	p := oidcclient.Provider{Issuer: prov.Issuer, ClientID: prov.ClientID, Scopes: prov.Scopes, Roots: roots}
	failed := func(err error) (int, bool) {
		var u *oidcclient.UnreachableError
		if errors.As(err, &u) {
			fmt.Fprintf(stderr, "port49 login: %v; port49 cannot sign you in until it answers (anyone already logged "+
				"in keeps working: a certificate port49 issued needs no identity provider)\n", err)
			return 1, true
		}
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1, false
	}
	e, err := oidcclient.Discover(ctx, p)
	if err != nil {
		return failed(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return failed(err)
	}
	nonce, err := api.IssuanceNonce(key.Public())
	if err != nil {
		return failed(err)
	}
	tokens, err := signIn(ctx, p, e, nonce, sf.redirectPort, sf.noBrowser, stderr)
	if err != nil {
		return failed(err)
	}
	warnSkew(stderr, "port49 login", tokens)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return failed(err)
	}
	resp, err := requestCertificate(ctx, sf.broker, pool, tokens.IDRaw, csr)
	if err != nil {
		return failed(err)
	}
	blk, _ := pem.Decode([]byte(resp.Certificate))
	var leaf *x509.Certificate
	if blk != nil {
		leaf, err = x509.ParseCertificate(blk.Bytes)
	}
	if blk == nil || err != nil || !key.PublicKey.Equal(leaf.PublicKey) {
		return failed(errors.New("the broker's answer is not a certificate for the key this login sent"))
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return failed(err)
	}
	// The key first: a certificate written without it is one no login
	// loads, and the next login signs in.
	if err := userconfig.WritePrivate(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"port49-issued key"); err != nil {
		return failed(err)
	}
	if err := userconfig.WritePrivate(certPath, []byte(resp.Certificate), "port49-issued certificate"); err != nil {
		return failed(err)
	}
	fmt.Fprintf(stdout, "port49: signed in at %s as %s; your certificate from %s is valid until %s\n", p.Issuer,
		resp.Principal, sf.broker, resp.NotAfter)
	return 0, false
}

// requestCertificate is POST /v1/certificate, the sign-in's ID token the
// bearer, over TLS 1.3 to the broker's CA alone and never through a proxy.
// The token is in a header, never a URL, and is not kept.
func requestCertificate(ctx context.Context, broker string, pool *x509.CertPool, idToken string,
	csr []byte) (api.IssueResponse, error) {
	body, err := json.Marshal(api.IssueRequest{CSR: base64.RawURLEncoding.EncodeToString(csr)})
	if err != nil {
		return api.IssueResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(broker, "/")+"/v1/certificate",
		bytes.NewReader(body))
	if err != nil {
		return api.IssueResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}}
	resp, err := c.Do(req)
	if err != nil {
		return api.IssueResponse{}, fmt.Errorf("the broker at %s is unreachable: %w", broker, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return api.IssueResponse{}, fmt.Errorf("the broker at %s: %w", broker, err)
	}
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		_ = json.Unmarshal(raw, &e)
		return api.IssueResponse{}, fmt.Errorf("the broker did not issue your certificate: %s (%s)",
			printsafe.Line(e.Detail, 400), printsafe.Line(cmp.Or(e.Error, resp.Status), 64))
	}
	var out api.IssueResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return api.IssueResponse{}, fmt.Errorf("the broker's answer to the certificate request: %w", err)
	}
	return out, nil
}

// The sign-in's browser and terminal, vars so a test drives them.
var (
	// openBrowser opens a URL in this host's browser (launchBrowser).
	openBrowser = launchBrowser
	// stdinIsTerminal is whether a pasted address can be read.
	stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	// readPaste reads one pasted address with echo off.
	readPaste = func() (string, error) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		return strings.TrimSpace(string(b)), err
	}
)

// signIn runs one sign-in in this process (rulings 3–5): a browser when
// this host has one, the address on stderr always, and on a terminal a
// pasted address, not echoed. The terminal is restored however the sign-in
// ends.
func signIn(ctx context.Context, p oidcclient.Provider, e oidcclient.Endpoints, nonce string, port int,
	noBrowser bool, stderr io.Writer) (oidcclient.Tokens, error) {
	o := oidcclient.LoginOptions{Nonce: nonce, Port: port, Out: stderr, Now: time.Now}
	if !noBrowser {
		o.Browser = openBrowser
	}
	if stdinIsTerminal() {
		fd := int(os.Stdin.Fd())
		if saved, err := term.GetState(fd); err == nil {
			defer func() { _ = term.Restore(fd, saved) }()
		}
		o.Paste = readPaste
	}
	t, err := oidcclient.Login(ctx, p, e, o)
	if errors.Is(err, oidcclient.ErrNoWayBack) {
		return t, fmt.Errorf("%w; run the command in a terminal (ssh -t), or log in with --redirect-port N and "+
			"forward that port to this host (ssh -L N:127.0.0.1:N)", err)
	}
	return t, err
}

// browserCommand is the command that opens url here, or nil for none (ruling
// 5): $BROWSER when set; on Linux and the BSDs xdg-open, only with a display,
// since on a remote shell it falls back to a text browser on the operator's
// own terminal; on macOS open, outside an SSH session.
func browserCommand(goos string, env func(string) string, url string) []string {
	if b := env("BROWSER"); b != "" {
		return []string{b, url}
	}
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd":
		if env("DISPLAY") != "" || env("WAYLAND_DISPLAY") != "" {
			return []string{"xdg-open", url}
		}
	case "darwin":
		if env("SSH_CONNECTION") == "" && env("SSH_TTY") == "" {
			return []string{"open", url}
		}
	}
	return nil
}

// launchBrowser runs browserCommand detached, with no terminal: a browser
// that falls back to text must not take the operator's.
func launchBrowser(url string) error {
	argv := browserCommand(runtime.GOOS, os.Getenv, url)
	if argv == nil {
		return errors.New("no browser on this host")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// pickProvider is the provider a login signs in at (ruling 2): the one the
// broker lists, or the one issuer names exactly.
func pickProvider(c api.Config, issuer string) (api.OIDCProvider, error) {
	var listed []string
	for _, p := range c.OIDC {
		listed = append(listed, p.Issuer)
	}
	switch {
	case len(c.OIDC) == 0:
		return api.OIDCProvider{}, fmt.Errorf("the broker takes no OIDC login: it lists no identity provider "+
			"(its methods: %s)", strings.Join(c.Methods, ", "))
	case issuer != "":
		for _, p := range c.OIDC {
			if p.Issuer == issuer {
				return p, nil
			}
		}
		return api.OIDCProvider{}, fmt.Errorf("the broker does not list %s; it lists %s", issuer, strings.Join(listed, ", "))
	case len(c.OIDC) > 1:
		return api.OIDCProvider{}, fmt.Errorf("the broker lists %d identity providers (%s); name one with --issuer or "+
			"oidc_issuer", len(c.OIDC), strings.Join(listed, ", "))
	}
	return c.OIDC[0], nil
}

// fetchBrokerConfig is the broker's GET /v1/config, which needs no
// credential (design §17), over TLS 1.3 to the broker's CA alone and never
// through a proxy: the broker is the operator's own.
func fetchBrokerConfig(ctx context.Context, broker string, pool *x509.CertPool) (api.Config, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(broker, "/")+"/v1/config", nil)
	if err != nil {
		return api.Config{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		var verify *tls.CertificateVerificationError
		if errors.As(err, &verify) {
			return api.Config{}, fmt.Errorf("the broker's certificate at %s does not verify (%v); check that the broker "+
				"CA (--broker-ca) is the CA that issued it", broker, verify.Err)
		}
		return api.Config{}, fmt.Errorf("the broker at %s is unreachable: %w", broker, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return api.Config{}, fmt.Errorf("%s/v1/config answered %s", broker, resp.Status)
	}
	var conf api.Config
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&conf); err != nil {
		return api.Config{}, fmt.Errorf("%s/v1/config: %w", broker, err)
	}
	return conf, nil
}

// warnSkew says when this host's clock is more than 5 minutes from the
// provider's (ruling 6): never a refusal, since the broker judges every
// token by its own clock.
func warnSkew(stderr io.Writer, what string, t oidcclient.Tokens) {
	skew, dir := oidcclient.Skew(t), "ahead of"
	if skew < 0 {
		skew, dir = -skew, "behind"
	}
	if skew <= 5*time.Minute {
		return
	}
	fmt.Fprintf(stderr, "%s: this host's clock is %s %s your identity provider's; the broker judges every token by "+
		"its own clock, so set this host's clock if the broker refuses yours\n", what, skew.Round(time.Second), dir)
}

// oidcRoots is the provider's TLS anchor (ruling 19): the config file's
// oidc_ca, read through its walk; --oidc-ca's file; or nil, the system's
// roots.
func (s *sessionFlags) oidcRoots() (*x509.CertPool, error) {
	caPEM := s.oidcCAPEM
	if caPEM == nil && s.oidcCA != "" {
		var err error
		if caPEM, err = os.ReadFile(s.oidcCA); err != nil {
			return nil, err
		}
	}
	if caPEM == nil {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s holds no PEM certificate", s.oidcCA)
	}
	return pool, nil
}
```

- [ ] **Step 6: `cmd/port49/main.go`**

- In `usage`, replace

  ```
    port49 login [--config FILE] [--broker URL] [--cert FILE] [--key FILE] [--broker-ca FILE] [--socket PATH]
                 (each flag overrides its key in the config file, $XDG_CONFIG_HOME/port49/config.yaml)
  ```

  with

  ```
    port49 login [--config FILE] [--broker URL] [--broker-ca FILE] [--socket PATH] [--cert FILE --key FILE |
                 --oidc [--issuer URL] [--oidc-ca FILE] [--redirect-port N] [--no-browser] [--sign-in]]
                 (each flag overrides its key in the config file, $XDG_CONFIG_HOME/port49/config.yaml; --oidc
                 signs in at your identity provider and holds the certificate the broker issues, signing in
                 again when it has under a quarter of its life left, or with --sign-in)
  ```

- In `sessionFlags`, after `brokerCAFD int`, add:

  ```go
  	// The OIDC path (plan 9b; spec §13 decision 43 ruling 19).
  	oidc, noBrowser, signIn bool
  	issuer, oidcCA          string
  	redirectPort            int
  	// oidcCAPEM is oidc_ca's bytes, read by userconfig.Load through its walk.
  	oidcCAPEM []byte
  ```

- After the `sessionFlags` type, add (C1):

  ```go
  // hardenAgent is harden, a var so TestMain makes it a no-op: the tests that
  // run the agent in-process would make the whole test binary non-dumpable,
  // and the ssh tests exec /proc/<pid>/exe as the askpass. An agent the login
  // starts is its own process and hardens for real.
  var hardenAgent = harden
  ```

- In `register`, before the `--config` flag, add:

  ```go
  	fs.BoolVar(&s.oidc, "oidc", false, "sign in at the identity provider the broker lists, and hold the certificate "+
  		"the broker issues, in place of your own")
  	fs.StringVar(&s.issuer, "issuer", "", "with --oidc: which provider, when the broker lists several")
  	fs.StringVar(&s.oidcCA, "oidc-ca", "", "with --oidc: the CA that issued your identity provider's certificate "+
  		"(PEM); the system's roots otherwise")
  	fs.IntVar(&s.redirectPort, "redirect-port", 0, "with --oidc: the loopback port the sign-in returns to; 0 picks a free one")
  	fs.BoolVar(&s.noBrowser, "no-browser", false, "with --oidc: open no browser; print the address to sign in at")
  	fs.BoolVar(&s.signIn, "sign-in", false, "with --oidc: sign in again even while your certificate has life left")
  ```

- Replace `fill` with:

  ```go
  // fill takes from the config file each value the command line left out
  // (decision 42 ruling 6; decision 43 ruling 19). A missing file at the
  // default path is no file; one --config names must be there, and is read
  // and checked even when every flag is given. A flag wins: --oidc, or
  // --cert or --key, which make a certificate login, over the file's method.
  func (s *sessionFlags) fill(fs *flag.FlagSet) error {
  	set := map[string]bool{}
  	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
  	if !set["config"] && s.complete() {
  		return nil
  	}
  	var opts []userconfig.Option
  	if s.brokerCA != "" {
  		opts = append(opts, userconfig.WithoutCA()) // --broker-ca wins; the file's is unused
  	}
  	if s.oidcCA != "" {
  		opts = append(opts, userconfig.WithoutOIDCCA())
  	}
  	f, ok, err := userconfig.Load(s.configFile, opts...)
  	switch {
  	case err != nil:
  		return err
  	case !ok && set["config"]:
  		return fmt.Errorf("%s: no such file", s.configFile)
  	case !ok:
  		return nil
  	}
  	if s.brokerCA == "" {
  		s.brokerCA, s.brokerCAPEM = f.BrokerCA, f.BrokerCAPEM
  	}
  	if s.oidcCA == "" {
  		s.oidcCA, s.oidcCAPEM = f.OIDCCA, f.OIDCCAPEM
  	}
  	s.broker = cmp.Or(s.broker, f.Broker)
  	s.cert, s.key = cmp.Or(s.cert, f.Cert), cmp.Or(s.key, f.Key)
  	if !set["oidc"] && !set["cert"] && !set["key"] {
  		s.oidc = f.Method == "oidc"
  	}
  	s.issuer = cmp.Or(s.issuer, f.OIDCIssuer)
  	if !set["redirect-port"] {
  		s.redirectPort = f.OIDCRedirectPort
  	}
  	return nil
  }

  // complete is whether the command line names all this command needs, so
  // the config file is not read: the agent child is handed all of it, and a
  // certificate login with all four flags reads no file, as before.
  func (s *sessionFlags) complete() bool {
  	return !s.oidc && s.broker != "" && s.cert != "" && s.key != "" && s.brokerCA != ""
  }
  ```

- Replace `config` with `brokerPool` and a shorter `config`:

  ```go
  // brokerPool is the broker CA's pool, from the bytes the config file's walk
  // read, the login's descriptor, or --broker-ca's path, in that order. It
  // keeps the bytes in brokerCAPEM for the agent the login starts. Required,
  // not defaulted: with no pool the agent would trust every public CA for a
  // broker whose certificate a private CA issued.
  func (s *sessionFlags) brokerPool() (*x509.CertPool, error) {
  	if s.brokerCA == "" {
  		return nil, errors.New("--broker-ca is required: the CA that issued the broker's certificate; the system's " +
  			"roots are not trusted for the broker")
  	}
  	caPEM := s.brokerCAPEM
  	// source is where the bytes came from, for the message when they hold no
  	// certificate: the path is only read in the default case.
  	source := s.brokerCA
  	var err error
  	switch {
  	case caPEM != nil:
  		source = "the broker CA read for " + s.configFile + " (" + s.brokerCA + ")"
  	case s.brokerCAFD != 0:
  		source = "the broker CA the login passed (from " + s.brokerCA + ")"
  		// The login read the CA once and passed the bytes; the path is not
  		// read again.
  		in := os.NewFile(uintptr(s.brokerCAFD), "broker-ca")
  		if in == nil {
  			return nil, fmt.Errorf("--broker-ca-fd %d is not an open descriptor", s.brokerCAFD)
  		}
  		defer in.Close()
  		if caPEM, err = io.ReadAll(io.LimitReader(in, maxBrokerCA+1)); err != nil {
  			return nil, fmt.Errorf("reading the broker CA from the login: %w", err)
  		}
  		if len(caPEM) > maxBrokerCA {
  			return nil, fmt.Errorf("the broker CA is over %d bytes", maxBrokerCA)
  		}
  	default:
  		// Named by --broker-ca: the operator's own choice of path.
  		if caPEM, err = os.ReadFile(s.brokerCA); err != nil {
  			return nil, err
  		}
  	}
  	s.brokerCAPEM = caPEM
  	pool := x509.NewCertPool()
  	if !pool.AppendCertsFromPEM(caPEM) {
  		return nil, fmt.Errorf("%s holds no PEM certificate", source)
  	}
  	return pool, nil
  }

  func (s *sessionFlags) config(log io.Writer) (agent.Config, error) {
  	if s.broker == "" || s.cert == "" || s.key == "" {
  		return agent.Config{}, fmt.Errorf("--broker, --cert, --key and --broker-ca are all required, as flags "+
  			"or in %s", s.configFile)
  	}
  	if s.brokerCA == "" {
  		return agent.Config{}, errors.New("--broker-ca is required: the CA that issued the broker's certificate; " +
  			"the system's roots are not trusted for the broker")
  	}
  	// Refused if the key is a symlink or readable by anyone but its owner
  	// (keyfile; pre-flight F14).
  	cert, err := keyfile.LoadX509KeyPair(s.cert, s.key)
  	if err != nil {
  		return agent.Config{}, fmt.Errorf("loading the client certificate: %w", err)
  	}
  	pool, err := s.brokerPool()
  	if err != nil {
  		return agent.Config{}, err
  	}
  	return agent.Config{BrokerURL: s.broker, Cert: cert, BrokerCA: pool, Now: time.Now, Log: log}, nil
  }
  ```

- In `login`, replace

  ```go
  	if err := fs.Parse(args); err != nil {
  		return 2
  	}
  	if err := sf.fill(fs); err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 2
  	}
  	cfg, err := sf.config(stderr)
  ```

  with

  ```go
  	if err := fs.Parse(args); err != nil {
  		return 2
  	}
  	set := map[string]bool{}
  	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
  	if sf.oidc && (set["cert"] || set["key"]) {
  		fmt.Fprintln(stderr, "port49 login: --cert and --key are a certificate login's; --oidc signs in at your "+
  			"identity provider instead")
  		return 2
  	}
  	if err := sf.fill(fs); err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 2
  	}
  	if sf.oidc {
  		return loginIssued(&sf, stdout, stderr)
  	}
  	for _, name := range []string{"issuer", "oidc-ca", "redirect-port", "no-browser", "sign-in"} {
  		if set[name] {
  			fmt.Fprintf(stderr, "port49 login: --%s is --oidc's (or method: oidc in %s)\n", name, sf.configFile)
  			return 2
  		}
  	}
  	cfg, err := sf.config(stderr)
  ```

- Delete the rest of `login`, from `dir := filepath.Dir(sf.socket)` to its end, and end `login`
  with `return startAgent(&sf, false, stdout, stderr)`. Update `login`'s comment's last sentence to
  `With an agent already running it refreshes that agent's session instead (spec §5.6; decision
  33); otherwise it starts one (startAgent).` Then add the deleted code as its own function, with
  the refresh after the start changed for a certificate the broker issued:

  ```go
  // startAgent starts the agent in its own session, detached, and waits until
  // its socket answers. The handshake happens in the agent, so an untrusted
  // certificate fails here (plan 3, Decided 3) and the agent's log says why.
  // The broker CA's bytes go to it on descriptor 3, so it reads the path no
  // second time. It then refreshes once, a key signature, so the device
  // sessions an earlier login left are extended (decision 43 ruling 11). A
  // certificate the broker issued (issued) that the refresh is refused
  // credential_revoked is no use again: it and its key are removed, and the
  // next login signs in (ruling 12; R6).
  func startAgent(sf *sessionFlags, issued bool, stdout, stderr io.Writer) int {
  	ctx := context.Background()
  	dir := filepath.Dir(sf.socket)
  	if err := agent.PrivateDir(dir); err != nil {
  		fmt.Fprintln(stderr, "port49 login:", unprefixed(err))
  		return 1
  	}
  	logPath := filepath.Join(dir, "agent.log")
  	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 1
  	}
  	defer logf.Close()
  	self, err := os.Executable()
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 1
  	}
  	// The CA this login read goes to the agent on a pipe (descriptor 3, the
  	// first of ExtraFiles), so the agent trusts these bytes and does not read
  	// the path a second time.
  	caR, caW, err := os.Pipe()
  	if err != nil {
  		fmt.Fprintln(stderr, "port49 login:", err)
  		return 1
  	}
  	defer caR.Close()
  	defer caW.Close()
  	cmd := exec.Command(self, append(append([]string{"agent"}, sf.args()...), "--broker-ca-fd", "3")...)
  	cmd.Stdout, cmd.Stderr = logf, logf
  	cmd.ExtraFiles = []*os.File{caR}
  	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
  	if err := cmd.Start(); err != nil {
  		fmt.Fprintln(stderr, "port49 login: starting the agent:", err)
  		return 1
  	}
  	caR.Close()
  	// A goroutine: the pipe holds 64 KiB and the CA may be larger. An agent
  	// that dies leaves the write failing, which ends it.
  	go func() {
  		_, _ = caW.Write(sf.brokerCAPEM)
  		caW.Close()
  	}()
  	exited := make(chan error, 1)
  	go func() { exited <- cmd.Wait() }()
  	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
  		select {
  		case err := <-exited:
  			tail, _ := os.ReadFile(logPath)
  			fmt.Fprintf(stderr, "port49 login: the agent exited (%v); the end of %s:\n%s", err, logPath, lastLines(string(tail), 10))
  			return 1
  		case <-time.After(100 * time.Millisecond):
  		}
  		if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
  			fmt.Fprintf(stdout, "port49: logged in to %s; the session ends at %s (agent pid %d, log %s)\n",
  				st.Broker, st.SessionEndsAt, cmd.Process.Pid, logPath)
  			// The session is up whatever the refresh does: a failure is
  			// said, and the login still succeeds, unless the broker refused
  			// a certificate it issued.
  			out, err := agent.NewClient(sf.socket).Refresh(ctx)
  			var revoked *agent.RevokedError
  			switch {
  			case issued && errors.As(err, &revoked):
  				_ = os.Remove(sf.key)
  				_ = os.Remove(sf.cert)
  				fmt.Fprintf(stderr, "port49 login: the broker refused your certificate: %s; it is removed, so "+
  					"`port49 login` signs you in again\n", revoked.Detail)
  				return 1
  			case err != nil:
  				fmt.Fprintln(stderr, "port49 login: logged in, but the refresh of your live device sessions failed:",
  					unprefixed(err))
  			default:
  				printRefresh(stdout, out)
  			}
  			return 0
  		}
  	}
  	_ = cmd.Process.Kill()
  	fmt.Fprintf(stderr, "port49 login: the agent did not answer within 15s; see %s\n", logPath)
  	return 1
  }
  ```

  `main.go` already imports everything it uses.

- In `agentMain`, after

  ```go
  	if err := fs.Parse(args); err != nil {
  		return 2
  	}
  ```

  and before `if err := sf.fill(fs); err != nil {`, add (C1; ruling 21):

  ```go
  	// Before any key is read: no core file or crash report holds it. It runs
  	// on without: the key is a file this user reads already, until plan 9c
  	// puts it in hardware.
  	if err := hardenAgent(); err != nil {
  		fmt.Fprintf(stderr, "port49 agent: could not make the agent non-dumpable (%v); it runs on\n", err)
  	}
  ```

  and replace

  ```go
  		timer := time.NewTimer(time.Until(a.SessionEndsAt()))
  ```

  with

  ```go
  		// The certificate's end, when it comes first, ends the agent: past it
  		// the broker takes no request (decision 43 ruling 21).
  		ends, certEnds := a.SessionEndsAt(), false
  		if end := a.CertificateEnd(); !end.IsZero() && end.Before(ends) {
  			ends, certEnds = end, true
  		}
  		timer := time.NewTimer(time.Until(ends))
  ```

  and

  ```go
  		case <-timer.C:
  			fmt.Fprintln(stderr, "port49 agent: the session reached max_session_age; exiting - run `port49 login` to start another")
  ```

  with

  ```go
  		case <-timer.C:
  			if certEnds {
  				fmt.Fprintf(stderr, "port49 agent: your certificate ended at %s, and the session with it; exiting - run "+
  					"`port49 login` (for a certificate port49 issued, it signs you in again)\n", ends.UTC().Format(time.RFC3339))
  				break
  			}
  			fmt.Fprintln(stderr, "port49 agent: the session reached max_session_age; exiting - run `port49 login` to start another")
  ```

  The `break` leaves the `select`; the loop's own `break` after it still runs, as for the other
  cases.

- [ ] **Step 7: `TestMain` and `newLabBrokerWith` in `cmd/port49/main_test.go`**

In `TestMain`, after the `runCLIEnv` branch

```go
	if os.Getenv(runCLIEnv) == "1" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
```

add (C1):

```go
	// The tests that run the agent in-process (run([]string{"agent", …}))
	// would make this whole binary non-dumpable, and every later ssh test
	// would then fail to exec /proc/<pid>/exe as its askpass. A child agent
	// the login starts takes the branch above, and hardens for real.
	hardenAgent = func() error { return nil }
```

Rename `newLabBroker` to `newLabBrokerWith(t *testing.T, maxAge time.Duration, iss *oidctest.Issuer,
issue bool) *labBroker`, add

```go
func newLabBroker(t *testing.T, maxAge time.Duration) *labBroker {
	return newLabBrokerWith(t, maxAge, nil, false)
}
```

and add `"github.com/rhwendt/port49/internal/issuer"`,
`"github.com/rhwendt/port49/internal/oidc"` and `"github.com/rhwendt/port49/internal/oidc/oidctest"`
to the imports. In the renamed body, with `iss` not nil the broker is OIDC-only on iss (decision 39),
issuing with `issue` (decision 43), the seeded context is indexed by principal alone, and the
listener is wired as port49d wires it:

- After the `l.b = &broker.Broker{…}` statement, add:

  ```go
  	if iss != nil {
  		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
  			MaxAge: 24 * time.Hour, Now: l.now, M: l.b.Metrics})
  		l.b.NoX509 = true
  		l.b.Identity = &oidc.Set{Timing: oidc.DefaultTiming, Now: l.now, M: l.b.Metrics,
  			Verifiers: []*oidc.Verifier{{VerifierConfig: oidc.VerifierConfig{Domain: oidc.Humans, Issuer: iss.URL,
  				ClientID: "port49-cli", PrincipalClaim: oidc.ClaimPreferredUsername,
  				PrincipalDomains: []string{"example.com"}, Scopes: []string{"openid"},
  				Algorithms: []oidc.Alg{oidc.RS256}}, Keys: ks}}}
  		if issue {
  			ca, err := issuer.Ephemeral(l.now())
  			if err != nil {
  				t.Fatal(err)
  			}
  			l.b.Issuer = ca
  		}
  	}
  ```

- Replace

  ```go
  	if err := l.st.IndexContext(ctx, "user:alice@example.com", "",
  		store.CertKey(leaf.Issuer.String(), leaf.SerialNumber.Text(16)),
  		store.ContextRef{NAS: "leaf1", Username: "alice"}, 24*time.Hour); err != nil {
  		t.Fatal(err)
  	}

  	srv, err := l.b.Server("127.0.0.1:0", srvCert, pool)
  ```

  with

  ```go
  	certKey, anchor := store.CertKey(leaf.Issuer.String(), leaf.SerialNumber.Text(16)), pool
  	if iss != nil {
  		// A context before an OIDC login names no certificate; an OIDC-only
  		// broker takes no anchor.
  		certKey, anchor = "", nil
  	}
  	if err := l.st.IndexContext(ctx, "user:alice@example.com", "", certKey,
  		store.ContextRef{NAS: "leaf1", Username: "alice"}, 24*time.Hour); err != nil {
  		t.Fatal(err)
  	}

  	srv, err := l.b.Server("127.0.0.1:0", srvCert, anchor)
  ```

- Replace `bl.Refused = l.b.RefusedAtBind` with:

  ```go
  	bl.Refused = l.b.RefusedAtBind
  	if iss != nil {
  		// As port49d wires it: Caller reads a certificate the broker issued.
  		l.b.Wire(bl)
  	}
  ```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go test ./internal/userconfig/ ./cmd/port49/ -count=1`
Expected: PASS, every earlier `cmd/port49` and `userconfig` test unchanged. The ssh tests
(`TestPortSSHLogsInWithTheTokenAndRunsTheCommand` and the rest) pass in the full run, not only
alone: if they fail with `ssh_askpass: exec(/proc/<pid>/exe): Permission denied`, `TestMain` is not
making `hardenAgent` a no-op. Never weaken `harden` to fix it.

Run: `go vet ./... && CGO_ENABLED=0 GOOS=darwin go vet ./cmd/port49/ && go test -race ./internal/userconfig/ ./cmd/port49/ -count=1`
Expected: PASS, and vet silent.

- [ ] **Step 9: Commit**

```bash
git add internal/userconfig/ cmd/port49/
git commit -m "feat(port49): login --oidc signs in, holds the certificate the broker issues, and starts the agent on it"
```

---

### Task 11: The client's config home: `~/.port49`, the system file, `PORT49_CONFIG`, and the broker's CA bundle kept

Ryan's rulings of 2026-10-10 and the toil audit's H4 (decision 43 ruling 24). The per-user
directory moves to `~/.port49`, as `~/.ssh` is, and leaves `$XDG_CONFIG_HOME/port49`: on Ubuntu
`~/.config` is group-writable (0775), and the walk refused every file below it. A root-owned
`/etc/port49/config.yaml`, which the install ships, is read under the user's file, key by key, so a
new user's first login is `port49 login` and the sign-in. The pinned host keys stay where 9a put
them until 9d takes them out of the user's flow. The agent keeps the CA bundle the broker sends
(Task 8), and a login trusts it beside `broker_ca`, so a rotation of the broker's CA asks nothing of
the user (decision 43 ruling 25).

**Files:**
- Modify: `internal/userconfig/userconfig.go` (the package comment, `Dir`, `EnvConfig`, `Path`,
  `SystemPath`, `SystemOwner`, `LegacyDir`, `Load` split into `parse` and `readCAs`, `LoadAll`,
  `overlay`, `noLegacy`, `options`, `readPrivate`, `ownedAlone`'s directory refusal),
  `internal/userconfig/userconfig_test.go`
- Modify: `internal/hostkeys/hostkeys.go` (`Path`)
- Modify: `cmd/port49/main.go` (usage, the `--config` help, `fill`), `cmd/port49/main_test.go`
  (`TestMain`, `testSystemConfig`), `cmd/port49/config_test.go`,
  `cmd/port49/issue_login_linux_test.go`, `cmd/port49/trust_hint_test.go`
- The kept CA bundle (ruling 25): Create `cmd/port49/cabundle.go`, `cmd/port49/cabundle_test.go`;
  Modify `internal/agent/agent.go` (`Agent.brokerRoot`, `BrokerRoot`, `RotatedCAHint`,
  `rotatedCA`, `refusal`), `internal/userconfig/userconfig.go` (`CABundlePathIn`,
  `CABundlePath`), `cmd/port49/main.go` (`brokerPool`, `agentMain`), `cmd/port49/issue.go`
  (`fetchBrokerConfig`), `cmd/port49/login_linux_test.go`

**Interfaces:**
- Consumes: Task 10's `userconfig.File` with its eight keys, `Load`, `WithoutCA`, `WithoutOIDCCA`,
  `IssuedPaths`, `IssuedPathsIn`, and `sessionFlags.fill`; Task 8's `api.ParseCABundle`,
  `api.EncodeCABundle`, `api.CAFingerprints`, `api.MaxCABundleBytes`, `api.Config.BrokerCABundle`,
  `BrokerCABundleRefused` and `Broker.CABundle`; the tests' `newOIDCLab`, `driveBrowser`, `privateSocket`, `stopAgentAt`,
  `labConfig`, `runningAgent`, `configBroker`, `runCLIEnv`, `newLabBroker`.
- Produces:
  - `userconfig.Dir() string` (now `~/.port49`), `userconfig.EnvConfig` (`"PORT49_CONFIG"`),
    `userconfig.Path() string`, `userconfig.SystemPath`, `userconfig.SystemOwner`,
    `userconfig.LegacyDir() string`;
  - `userconfig.LoadAll(path string, named bool, opts ...Option) (File, bool, error)`;
  - `hostkeys.Path()` at `LegacyDir`;
  - the tests' `systemConfig(t, path)` and `testSystemConfig`;
  - `userconfig.CABundlePathIn(dir, broker string) (string, error)`, `userconfig.CABundlePath`;
    `func (a *agent.Agent) BrokerRoot() *x509.Certificate`, `agent.RotatedCAHint`;
    `keepCABundle(broker, bundle string, refused bool, root *x509.Certificate, log io.Writer)`,
    `forgetBundle(path string, root *x509.Certificate, log io.Writer)`,
    `withKeptBundle(broker string, caPEM []byte) ([]byte, error)`.

- [ ] **Step 1: Write the failing tests**

In `internal/userconfig/userconfig_test.go`, in `TestADirectoryAboveOthersCanWriteIsRefused`:

Replace

```go
	// The refusal tells the operator what to run.
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), top+" is writable by others") ||
		!strings.Contains(err.Error(), "chmod go-w "+top) {
```

with

```go
	// The refusal says what the directory needs, and no chmod: it may be
	// shared, as a group-writable ~/.config is.
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), top+" is writable by others") ||
		!strings.Contains(err.Error(), "writable by its owner alone (mode 0755 or 0700)") ||
		strings.Contains(err.Error(), "chmod") {
```

At the end of `internal/userconfig/userconfig_test.go`, add:

```go
// asSystem stands path in for /etc/port49/config.yaml for the rest of the
// test, owned by owner in root's place.
func asSystem(t *testing.T, path string, owner uint32) {
	t.Helper()
	oldPath, oldOwner := SystemPath, SystemOwner
	SystemPath, SystemOwner = path, owner
	t.Cleanup(func() { SystemPath, SystemOwner = oldPath, oldOwner })
}

// ~/.port49 is the directory, $PORT49_CONFIG names another file, and plan
// 9a's directory is kept for the pins alone (decision 43 ruling 24).
func TestTheDirectories(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(EnvConfig, "")
	if Dir() != "/home/alice/.port49" || Path() != "/home/alice/.port49/config.yaml" ||
		LegacyDir() != "/home/alice/.config/port49" {
		t.Fatalf("%s %s %s", Dir(), Path(), LegacyDir())
	}
	t.Setenv(EnvConfig, "/srv/p49.yaml")
	t.Setenv("XDG_CONFIG_HOME", "/x")
	if Path() != "/srv/p49.yaml" || Dir() != "/home/alice/.port49" || LegacyDir() != "/x/port49" {
		t.Fatalf("%s %s %s", Dir(), Path(), LegacyDir())
	}
}

// The personal file is over the system file, key by key; each file's
// relative paths are its own directory's, and the CA is read from the file
// whose key won. The system file alone is a config.
func TestLoadAllLayersYoursOverTheSystemFile(t *testing.T) {
	sys := private(t, "config.yaml", "broker: https://sys.example:8443\nbroker_ca: ca.pem\nmethod: oidc\n"+
		"oidc_issuer: https://idp.example\noidc_redirect_port: 18000\n")
	if err := os.WriteFile(filepath.Join(filepath.Dir(sys), "ca.pem"), []byte("SYSTEM CA"), 0o644); err != nil {
		t.Fatal(err)
	}
	asSystem(t, sys, uint32(os.Getuid()))
	t.Setenv("XDG_CONFIG_HOME", privateDir(t))
	mine := private(t, "config.yaml", "broker: https://mine.example:8443\noidc_redirect_port: 18001\n")
	f, ok, err := LoadAll(mine, false)
	if err != nil || !ok || f.Broker != "https://mine.example:8443" || f.OIDCRedirectPort != 18001 ||
		f.Method != "oidc" || f.OIDCIssuer != "https://idp.example" ||
		f.BrokerCA != filepath.Join(filepath.Dir(sys), "ca.pem") || string(f.BrokerCAPEM) != "SYSTEM CA" {
		t.Fatalf("%+v %v %v", f, ok, err)
	}
	f, ok, err = LoadAll(filepath.Join(privateDir(t), "config.yaml"), false)
	if err != nil || !ok || f.Broker != "https://sys.example:8443" || string(f.BrokerCAPEM) != "SYSTEM CA" {
		t.Fatalf("the system file alone: %+v %v %v", f, ok, err)
	}
	// A CA the system file names is refused in the system file's name.
	if err := os.Chmod(filepath.Join(filepath.Dir(sys), "ca.pem"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAll(mine, false); err == nil || !strings.Contains(err.Error(), "broker_ca in "+sys) {
		t.Fatalf("a CA others can write: %v", err)
	}
}

// Neither file is no config; a named file must be there.
func TestLoadAllWithNeitherFile(t *testing.T) {
	asSystem(t, filepath.Join(t.TempDir(), "none.yaml"), uint32(os.Getuid()))
	t.Setenv("XDG_CONFIG_HOME", privateDir(t))
	p := filepath.Join(privateDir(t), "config.yaml")
	if _, ok, err := LoadAll(p, false); ok || err != nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if _, _, err := LoadAll(p, true); err == nil || err.Error() != p+": no such file" {
		t.Fatalf("named: %v", err)
	}
}

// The system file names the broker for every user on the host, so it is
// root's alone; this user's own is refused, naming the owner it needs.
func TestASystemFileNotRootsIsRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run as root, this user's file is root's")
	}
	sys := private(t, "config.yaml", "broker: https://sys.example:8443\n")
	asSystem(t, sys, 0)
	if _, _, err := LoadAll(filepath.Join(privateDir(t), "config.yaml"), false); err == nil ||
		!strings.Contains(err.Error(), sys+" is not owned by root") || !strings.Contains(err.Error(), "chown root "+sys) {
		t.Fatalf("%v", err)
	}
	// Writable by others, it is refused as any config file is.
	asSystem(t, sys, uint32(os.Getuid()))
	if err := os.Chmod(sys, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAll(filepath.Join(privateDir(t), "config.yaml"), false); err == nil ||
		!strings.Contains(err.Error(), sys+" is writable by others") {
		t.Fatalf("%v", err)
	}
}

// A config file at plan 9a's place, with none at the default path, is
// refused naming the move; with one at the default path it is not read.
func TestAConfigAtPlan9asPlaceIsRefused(t *testing.T) {
	asSystem(t, filepath.Join(t.TempDir(), "none.yaml"), uint32(os.Getuid()))
	xdg := privateDir(t)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	old := filepath.Join(xdg, "port49", "config.yaml")
	if err := WritePrivate(old, []byte("broker: https://old.example:8443\n"), "port49 config file"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(privateDir(t), "config.yaml")
	if _, _, err := LoadAll(p, false); err == nil ||
		err.Error() != old+" is where plan 9a kept port49's config file; port49 reads "+p+" now: mkdir -m 700 -p "+
			filepath.Dir(p)+" && mv "+old+" "+p {
		t.Fatalf("%v", err)
	}
	if err := os.WriteFile(p, []byte("broker: https://new.example:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, ok, err := LoadAll(p, false); err != nil || !ok || f.Broker != "https://new.example:8443" {
		t.Fatalf("%+v %v %v", f, ok, err)
	}
}
```

In `cmd/port49/config_test.go`, add `"github.com/rhwendt/port49/internal/userconfig"` to the
imports, after `internal/testpki`. Then replace `TestLoginTakesWhatItLacksFromTheConfigFile` whole,
from its comment to its closing brace:

```go
// login takes what its flags leave out from the config file, at the default
// path and at --config (decision 42 ruling 6).
func TestLoginTakesWhatItLacksFromTheConfigFile(t *testing.T) {
	xdg := privateDir(t)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dir := filepath.Join(xdg, "port49")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := labConfig(t, dir, configBroker)
	for name, args := range map[string][]string{
		"the default path": nil,
		"--config":         {"--config", cfg},
	} {
		sock, refreshes := runningAgent(t, dir)
		var out, errb bytes.Buffer
		code := run(append(append([]string{"login"}, args...), "--socket", sock), &out, &errb)
		if code != 0 || refreshes() != 1 ||
			!strings.HasPrefix(out.String(), "port49: already logged in to "+configBroker+"; refreshing\n") {
			t.Errorf("%s: code %d stdout %q stderr %q", name, code, out.String(), errb.String())
		}
	}
}

```

with

```go
// login takes what its flags leave out from the config file, at the default
// path, ~/.port49/config.yaml, at $PORT49_CONFIG and at --config (decision 42
// ruling 6; decision 43 ruling 24).
func TestLoginTakesWhatItLacksFromTheConfigFile(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".port49")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	labConfig(t, dir, configBroker)
	other := privateDir(t)
	named := labConfig(t, other, configBroker)
	for _, c := range []struct {
		name, dir, env string
		args           []string
	}{
		{"the default path", dir, "", nil},
		{"$PORT49_CONFIG", other, named, nil},
		{"--config", other, "", []string{"--config", named}},
	} {
		// Each file names its own lab certificate, so only the file the
		// login should read matches the running agent's.
		t.Setenv(userconfig.EnvConfig, c.env)
		sock, refreshes := runningAgent(t, c.dir)
		var out, errb bytes.Buffer
		code := run(append(append([]string{"login"}, c.args...), "--socket", sock), &out, &errb)
		if code != 0 || refreshes() != 1 ||
			!strings.HasPrefix(out.String(), "port49: already logged in to "+configBroker+"; refreshing\n") {
			t.Errorf("%s: code %d stdout %q stderr %q", c.name, code, out.String(), errb.String())
		}
	}
}

// systemConfig stands path in for /etc/port49/config.yaml, and this user in
// for root, for the rest of the test.
func systemConfig(t *testing.T, path string) {
	t.Helper()
	oldPath, oldOwner := userconfig.SystemPath, userconfig.SystemOwner
	userconfig.SystemPath, userconfig.SystemOwner = path, uint32(os.Getuid())
	t.Cleanup(func() { userconfig.SystemPath, userconfig.SystemOwner = oldPath, oldOwner })
}

// The install's file is under the user's, key by key: a user who sets only
// broker keeps the system file's CA, certificate and key (decision 43
// ruling 24).
func TestTheSystemFileIsUnderYoursKeyByKey(t *testing.T) {
	sys := privateDir(t)
	systemConfig(t, labConfig(t, sys, "https://elsewhere.example:8443"))
	home := privateDir(t)
	t.Setenv("HOME", home)
	if err := userconfig.WritePrivate(filepath.Join(home, ".port49", "config.yaml"),
		[]byte("broker: "+configBroker+"\n"), "port49 config file"); err != nil {
		t.Fatal(err)
	}
	sock, refreshes := runningAgent(t, sys)
	var out, errb bytes.Buffer
	if code := run([]string{"login", "--socket", sock}, &out, &errb); code != 0 || refreshes() != 1 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// A config file at plan 9a's place, with none at ~/.port49, is refused in
// one line naming the move, exit 2, and nothing is asked of the agent.
func TestAConfigFileAtPlan9asPlaceIsRefused(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	labConfig(t, filepath.Join(home, ".config", "port49"), configBroker)
	sock, refreshes := runningAgent(t, filepath.Join(home, ".config", "port49"))
	var out, errb bytes.Buffer
	code := run([]string{"login", "--socket", sock}, &out, &errb)
	old, now := filepath.Join(home, ".config", "port49", "config.yaml"), filepath.Join(home, ".port49", "config.yaml")
	if code != 2 || refreshes() != 0 || strings.Count(errb.String(), "\n") != 1 ||
		!strings.Contains(errb.String(), "mkdir -m 700 -p "+filepath.Join(home, ".port49")+" && mv "+old+" "+now) {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

```

In `cmd/port49/issue_login_linux_test.go`, before `// After the sign-in, no browser: a login with
the agent running refreshes by`, add:

```go
// A new user with nothing but the install's /etc/port49/config.yaml runs
// `port49 login` and signs in, and that is all: no file of their own, no
// flag (the socket is the test's), and ~/.port49 and its issued directory
// made 0700 (decision 43 ruling 24).
func TestTheSystemFileAloneIsAFirstLogin(t *testing.T) {
	o := newOIDCLab(t, true)
	sys := filepath.Join(privateDir(t), "config.yaml")
	if err := os.WriteFile(sys, []byte("broker: "+o.url+"\nbroker_ca: "+filepath.Join(o.dir, testpki.LabCA)+
		"\nmethod: oidc\noidc_ca: "+o.idpCA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	systemConfig(t, sys)
	home := privateDir(t)
	t.Setenv("HOME", home)
	driveBrowser(t, o.iss)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run([]string{"login", "--socket", sock}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: signed in at "+o.iss.URL+" as user:alice@example.com") ||
		!strings.Contains(out.String(), "port49: logged in to "+o.url) {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	certPath, _ := o.issuedPaths(t)
	for _, d := range []string{filepath.Join(home, ".port49"), filepath.Dir(certPath)} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 || !strings.HasPrefix(certPath, d) {
			t.Fatalf("%s: %v %v", d, fi, err)
		}
	}
}
```

In `cmd/port49/trust_hint_test.go`, in `TestTrustRefusesAPinsDirectoryBeforeItMints`, a pins
directory is refused with what it needs, no longer a `chmod`:

Replace

```go
scans.Load() != 0 || !strings.Contains(errb.String(), "chmod go-w") {
```

with

```go
scans.Load() != 0 || !strings.Contains(errb.String(), "writable by its owner alone") {
```

The kept CA bundle (ruling 25). Create `cmd/port49/cabundle_test.go`:

```go
package main

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

const bundleBroker = "https://broker.example:8443"

func testCA(t *testing.T) *testpki.CA {
	t.Helper()
	ca, err := testpki.NewCA("port49 test CA", time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// The agent keeps a bundle that holds the CA its connection was verified
// to, 0600, and says so by fingerprint, once; one that drops that CA, or is
// out of bounds, is refused and the kept file left as it was (decision 43
// ruling 25).
func TestKeepCABundle(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	cur, next, other := testCA(t), testCA(t), testCA(t)
	path, err := userconfig.CABundlePath(bundleBroker)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	keepCABundle(bundleBroker, string(cur.PEM())+string(next.PEM()), false, cur.Cert, &log)
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, append(cur.PEM(), next.PEM()...)) ||
		!strings.Contains(log.String(), "kept the broker's CA bundle in "+path) || !strings.Contains(log.String(), "(was none)") {
		t.Fatalf("%v %q", err, log.String())
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	// The same bundle again is no change, and no line.
	log.Reset()
	keepCABundle(bundleBroker, string(cur.PEM())+string(next.PEM()), false, cur.Cert, &log)
	if log.Len() != 0 {
		t.Fatalf("%q", log.String())
	}
	for name, c := range map[string]struct {
		bundle, want string
	}{
		"the CA in use dropped": {string(next.PEM()) + string(other.PEM()), "does not hold the CA this connection was verified to"},
		"five CAs":              {strings.Repeat(string(cur.PEM()), 5), "over 4 certificates"},
		"junk":                  {string(cur.PEM()) + "junk", "other than PEM"},
	} {
		log.Reset()
		keepCABundle(bundleBroker, c.bundle, false, cur.Cert, &log)
		if got, _ := os.ReadFile(path); !bytes.Equal(got, raw) || !strings.Contains(log.String(), c.want) ||
			!strings.Contains(log.String(), "is left as it was") {
			t.Errorf("%s: %q", name, log.String())
		}
	}
	// The rotation's end: the old CA leaves the bundle once the server's
	// certificate is the next CA's, and the change is said.
	log.Reset()
	keepCABundle(bundleBroker, string(next.PEM()), false, next.Cert, &log)
	if !strings.Contains(log.String(), "(was "+api.CAFingerprints([]*x509.Certificate{cur.Cert, next.Cert})+")") {
		t.Fatalf("%q", log.String())
	}
}

// A broker that sends no bundle, on a verified connection, clears what the
// agent kept: a kept bundle holding a CA beside the one verified to (one a
// broker key held briefly by another could have planted) is cut to that CA,
// and one that does not hold it is removed, each said; with nothing kept
// nothing is said (decision 43 ruling 25).
func TestABrokerWithNoBundleClearsTheKeptOne(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	cur, planted, other := testCA(t), testCA(t), testCA(t)
	path, err := userconfig.CABundlePath(bundleBroker)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	keepCABundle(bundleBroker, "", false, cur.Cert, &log)
	if _, err := os.Stat(path); !os.IsNotExist(err) || log.Len() != 0 {
		t.Fatalf("nothing kept: %v %q", err, log.String())
	}
	keepCABundle(bundleBroker, string(cur.PEM())+string(planted.PEM()), false, cur.Cert, &bytes.Buffer{})
	log.Reset()
	keepCABundle(bundleBroker, "", false, cur.Cert, &log)
	if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, cur.PEM()) ||
		!strings.Contains(log.String(), "now holds only the CA this connection was verified to") {
		t.Fatalf("the CA verified to, kept alone: %v %q", err, log.String())
	}
	// A broker that refused its own bundle at start leaves the kept file as it
	// was: a typo in tls_ca_bundle_file mid-rotation drops no CA a client holds.
	log.Reset()
	keepCABundle(bundleBroker, "", true, cur.Cert, &log)
	if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, cur.PEM()) ||
		!strings.Contains(log.String(), "refused its own tls_ca_bundle_file") ||
		!strings.Contains(log.String(), path+" is left as it was") {
		t.Fatalf("a refused bundle: %v %q", err, log.String())
	}
	keepCABundle(bundleBroker, string(other.PEM())+string(planted.PEM()), false, other.Cert, &bytes.Buffer{})
	log.Reset()
	keepCABundle(bundleBroker, "", false, cur.Cert, &log)
	if _, err := os.Stat(path); !os.IsNotExist(err) || !strings.Contains(log.String(), "removed "+path) {
		t.Fatalf("a bundle the connection did not need: %v %q", err, log.String())
	}
}

// A login trusts its broker_ca and the bundle the agent kept for that
// broker, and no other broker's; a kept file that cannot be used is refused
// naming it.
func TestALoginTrustsTheKeptBundleBesideItsCA(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	cur, next := testCA(t), testCA(t)
	keepCABundle(bundleBroker, string(next.PEM()), false, next.Cert, &bytes.Buffer{})
	caFile := filepath.Join(privateDir(t), "ca.pem")
	if err := os.WriteFile(caFile, cur.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := next.Issue(testpki.Leaf{CommonName: "broker", DNSNames: []string{"broker.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(srv.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for broker, verifies := range map[string]bool{bundleBroker: true, "https://other.example:8443": false} {
		sf := sessionFlags{broker: broker, brokerCA: caFile}
		pool, err := sf.brokerPool()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "broker.example"}); (err == nil) != verifies {
			t.Errorf("%s: %v", broker, err)
		}
	}
	path, _ := userconfig.CABundlePath(bundleBroker)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	sf := sessionFlags{broker: bundleBroker, brokerCA: caFile}
	if _, err := sf.brokerPool(); err == nil || !strings.Contains(err.Error(), path+", the broker's CA bundle the agent kept") {
		t.Fatalf("%v", err)
	}
}
```

In `cmd/port49/main_test.go`, replace

```go
	if code != 1 || !strings.Contains(errb.String(), "does not verify") || !strings.Contains(errb.String(), "--broker-ca") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
```

with

```go
	// A CA this host does not trust is what a host away through a whole
	// rotation meets: the line names the fix (decision 43 ruling 25).
	if code != 1 || !strings.Contains(errb.String(), "does not verify") ||
		!strings.Contains(errb.String(), "; "+agent.RotatedCAHint) {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
```

In `cmd/port49/login_linux_test.go`, replace

```go
// The real path: port49 login starts the agent, which logs in to a real
```

with

```go
// A broker that sends a CA bundle: the agent the login starts keeps it in
// ~/.port49/broker_ca/, 0600, and logs it by fingerprint. A later login
// whose broker_ca is only the next CA still reaches the broker, through the
// kept bundle: the rotation's first half, with nothing asked of the user
// (decision 43 ruling 25).
func TestTheAgentKeepsTheBrokersCABundle(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	next, err := testpki.NewCA("port49 lab next CA", time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile(filepath.Join(l.dir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	l.b.CABundle = append(append([]byte{}, cur...), next.PEM()...)
	t.Setenv("HOME", privateDir(t))
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, l.flags(sock)...), &out, &errb); code != 0 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	path, err := userconfig.CABundlePath(l.url)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, l.b.CABundle) {
		t.Fatalf("%v %q", err, raw)
	}
	certs, _ := api.ParseCABundle(raw)
	if log, _ := os.ReadFile(filepath.Join(filepath.Dir(sock), "agent.log")); !strings.Contains(string(log),
		"kept the broker's CA bundle in "+path+": "+api.CAFingerprints(certs)) {
		t.Fatalf("the agent's log: %q", log)
	}
	stopAgentAt(sock)
	nextOnly := filepath.Join(privateDir(t), "next.pem")
	if err := os.WriteFile(nextOnly, next.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := l.flags(sock)
	for i := range flags {
		if flags[i] == "--broker-ca" {
			flags[i+1] = nextOnly
		}
	}
	out.Reset()
	if code := run(append([]string{"login"}, flags...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: logged in to "+l.url) {
		t.Fatalf("a login on the next CA alone: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// The real path: port49 login starts the agent, which logs in to a real
```

In `cmd/port49/login_linux_test.go`, replace

```go
import (
	"bytes"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)
```

with

```go
import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/userconfig ./cmd/port49`
Expected: FAIL to build: `undefined: SystemPath`, `SystemOwner`, `LoadAll`, `LegacyDir`,
`EnvConfig`, and `undefined: userconfig.SystemPath`, `keepCABundle`, `agent.RotatedCAHint` in
`cmd/port49`.

- [ ] **Step 3: `internal/userconfig/userconfig.go`**

Add `"cmp"` to the imports, after `"bytes"`.

Replace the package comment, as Task 10 Step 3 left it,

```go
// Package userconfig is the operator's own files under
// $XDG_CONFIG_HOME/port49 (spec §13 decision 42, ruling 6): config.yaml,
// which gives `port49 login` its broker, broker CA, certificate and key, or its
// identity provider (spec §13 decision 43 ruling 19), and the certificate the
// broker issued it (IssuedPaths); and
// the private-file reading and writing it shares with the pinned host keys
// (internal/hostkeys). Whoever can write these files chooses which broker the
// operator trusts and which device keys `port49 ssh` accepts, so a file, or a
// directory holding one, that anyone else can write is refused, never read.
// It is keyfile's rule for a private key, for writing rather than reading,
// and unlike internal/fence it holds on macOS too.
```

with

```go
// Package userconfig is the operator's own files under ~/.port49 (spec §13
// decision 43 ruling 24, amending decision 42 ruling 6): config.yaml, over the
// system-wide /etc/port49/config.yaml the install ships, which gives `port49
// login` its broker, broker CA, certificate and key, or its identity provider
// (decision 43 ruling 19); the certificate the broker issued it
// (IssuedPaths); and the private-file reading and writing it shares with the
// pinned host keys (internal/hostkeys). Whoever can write these files chooses
// which broker the operator trusts and which device keys `port49 ssh`
// accepts, so a file, or a directory holding one, that anyone else can write
// is refused, never read. It is keyfile's rule for a private key, for writing
// rather than reading, and unlike internal/fence it holds on macOS too.
```

Replace `Dir` and `Path`

```go
// Dir is $XDG_CONFIG_HOME/port49, else ~/.config/port49.
func Dir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "port49")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "port49")
	}
	return filepath.Join(".config", "port49")
}

// Path is the config file's default path.
func Path() string { return filepath.Join(Dir(), "config.yaml") }
```

with

```go
// Dir is ~/.port49, the operator's own port49 directory, as ~/.ssh is
// OpenSSH's (decision 43 ruling 24): config.yaml, and the certificates
// brokers issued (IssuedPaths). WritePrivate makes it 0700 when it is
// missing. It sits in the home directory, so its walk never meets a shared
// parent such as a group-writable ~/.config.
func Dir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".port49")
	}
	return ".port49"
}

// EnvConfig names a config file in place of ~/.port49/config.yaml; --config
// overrides it.
const EnvConfig = "PORT49_CONFIG"

// Path is the personal config file: $PORT49_CONFIG, else
// ~/.port49/config.yaml.
func Path() string {
	if p := os.Getenv(EnvConfig); p != "" {
		return p
	}
	return filepath.Join(Dir(), "config.yaml")
}

// SystemPath is the system-wide config file the install ships, under every
// user's own (LoadAll). Only the tests change it.
var SystemPath = "/etc/port49/config.yaml"

// SystemOwner is the uid that must own SystemPath: 0, root, as /etc is. Only
// the tests change it, standing their own uid in for root's, which no test
// can give a file.
var SystemOwner uint32

// LegacyDir is plan 9a's directory, $XDG_CONFIG_HOME/port49, else
// ~/.config/port49. The pinned host keys stay there until plan 9d takes
// them out of the user's flow; a config.yaml there is refused, naming the
// move (LoadAll).
func LegacyDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "port49")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "port49")
	}
	return filepath.Join(".config", "port49")
}
```

Replace `// IssuedPaths is IssuedPathsIn the config directory (Dir).` with `// IssuedPaths is
IssuedPathsIn ~/.port49 (Dir).`

`Load` becomes `parse`, which reads one file and no CA, and `readCAs`; `Load` and the new `LoadAll`
are built on them. Replace the head of `Load`, from its comment to its `ReadPrivate` line,

```go
// Load reads config.yaml at path. ok is false, with no error, when there is
// no file; a file that is there and cannot be used is an error, never a file
// ignored.
func Load(path string, opts ...Option) (f File, ok bool, err error) {
	var o loadOptions
	for _, opt := range opts {
		opt(&o)
	}
	raw, err := ReadPrivate(path, maxFile, "port49 config file")
```

with

```go
// Load reads config.yaml at path. ok is false, with no error, when there is
// no file; a file that is there and cannot be used is an error, never a file
// ignored.
func Load(path string, opts ...Option) (File, bool, error) {
	f, ok, err := parse(path, "port49 config file", false)
	if err != nil || !ok {
		return File{}, false, err
	}
	if err := f.readCAs(options(opts), path, path); err != nil {
		return File{}, false, err
	}
	return f, true, nil
}

// LoadAll is Load over two files, key by key (decision 43 ruling 24): the
// system-wide file at SystemPath, then path's, every key of which that is
// set wins. path is the personal file, ~/.port49/config.yaml, or one that
// --config or $PORT49_CONFIG names (named), which must then be there. ok is
// false, with no error, when neither file is. The system file must be
// root's: it names the broker for every user on the host. Each file's
// relative paths are its own directory's, and each CA is read once, from
// the file whose key won.
func LoadAll(path string, named bool, opts ...Option) (File, bool, error) {
	sys, sysOK, err := parse(SystemPath, "system port49 config file", true)
	if err != nil {
		return File{}, false, err
	}
	f, ok, err := parse(path, "port49 config file", false)
	switch {
	case err != nil:
		return File{}, false, err
	case !ok && named:
		return File{}, false, fmt.Errorf("%s: no such file", path)
	case !ok:
		if err := noLegacy(path); err != nil {
			return File{}, false, err
		}
		if !sysOK {
			return File{}, false, nil
		}
	}
	brokerFrom, oidcFrom := path, path
	if f.BrokerCA == "" {
		brokerFrom = SystemPath
	}
	if f.OIDCCA == "" {
		oidcFrom = SystemPath
	}
	f = overlay(sys, f)
	if err := f.readCAs(options(opts), brokerFrom, oidcFrom); err != nil {
		return File{}, false, err
	}
	return f, true, nil
}

// overlay is base with every key over sets in its place.
func overlay(base, over File) File {
	base.Broker = cmp.Or(over.Broker, base.Broker)
	base.BrokerCA = cmp.Or(over.BrokerCA, base.BrokerCA)
	base.Cert = cmp.Or(over.Cert, base.Cert)
	base.Key = cmp.Or(over.Key, base.Key)
	base.Method = cmp.Or(over.Method, base.Method)
	base.OIDCIssuer = cmp.Or(over.OIDCIssuer, base.OIDCIssuer)
	base.OIDCCA = cmp.Or(over.OIDCCA, base.OIDCCA)
	base.OIDCRedirectPort = cmp.Or(over.OIDCRedirectPort, base.OIDCRedirectPort)
	return base
}

// noLegacy refuses a config.yaml at plan 9a's place when path, the default,
// holds none, and names the move: unread, it would leave the operator logged
// in to whatever the system file names, or to nothing, with no word why.
func noLegacy(path string) error {
	old := filepath.Join(LegacyDir(), "config.yaml")
	if _, err := os.Lstat(old); err != nil {
		return nil
	}
	return fmt.Errorf("%s is where plan 9a kept port49's config file; port49 reads %s now: "+
		"mkdir -m 700 -p %s && mv %s %s", old, path, filepath.Dir(path), old, path)
}

// options is what opts make of Load's defaults.
func options(opts []Option) loadOptions {
	var o loadOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// parse reads and checks one config file, resolving its paths, and reads no
// CA. With rootOnly the file must be root's (SystemOwner).
func parse(path, what string, rootOnly bool) (f File, ok bool, err error) {
	raw, err := readPrivate(path, maxFile, what, rootOnly)
```

and replace the tail of the old `Load`, now `parse`'s, from the path loop to its closing brace,

```go
	for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key, &f.OIDCCA} {
		if *p, err = resolve(base, *p); err != nil {
			return File{}, false, fmt.Errorf("%s: %w", path, err)
		}
	}
	// The CA this file names pins the broker as the file does, so it is held
	// to the same line, ReadPrivate's: owned by you or root, nobody else can
	// write it or the directories above it. It is read here, once, and its
	// bytes carried, so nothing can be swapped in between a check and a read.
	if f.BrokerCA != "" && !o.skipCA {
		if f.BrokerCAPEM, err = ReadPrivate(f.BrokerCA, maxCA, "broker CA"); err != nil {
			return File{}, false, fmt.Errorf("broker_ca in %s: %w", path, err)
		}
	}
	// The provider's CA decides whose sign-in port49 trusts, as the broker
	// CA decides the broker: held to the same line, read once.
	if f.OIDCCA != "" && !o.skipOIDCCA {
		if f.OIDCCAPEM, err = ReadPrivate(f.OIDCCA, maxCA, "identity provider CA"); err != nil {
			return File{}, false, fmt.Errorf("oidc_ca in %s: %w", path, err)
		}
	}
	return f, true, nil
}
```

with

```go
	for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key, &f.OIDCCA} {
		if *p, err = resolve(base, *p); err != nil {
			return File{}, false, fmt.Errorf("%s: %w", path, err)
		}
	}
	return f, true, nil
}

// readCAs reads the CAs f names; brokerFrom and oidcFrom are the files that
// named them, for a refusal.
func (f *File) readCAs(o loadOptions, brokerFrom, oidcFrom string) error {
	var err error
	// The CA a config file names pins the broker as the file does, so it is
	// held to the same line, ReadPrivate's: owned by you or root, nobody
	// else can write it or the directories above it. It is read here, once,
	// and its bytes carried, so nothing can be swapped in between a check and
	// a read.
	if f.BrokerCA != "" && !o.skipCA {
		if f.BrokerCAPEM, err = ReadPrivate(f.BrokerCA, maxCA, "broker CA"); err != nil {
			return fmt.Errorf("broker_ca in %s: %w", brokerFrom, err)
		}
	}
	// The provider's CA decides whose sign-in port49 trusts, as the broker
	// CA decides the broker: held to the same line, read once.
	if f.OIDCCA != "" && !o.skipOIDCCA {
		if f.OIDCCAPEM, err = ReadPrivate(f.OIDCCA, maxCA, "identity provider CA"); err != nil {
			return fmt.Errorf("oidc_ca in %s: %w", oidcFrom, err)
		}
	}
	return nil
}
```

`parse`'s body between them is the old `Load`'s unchanged (the decoder, the second document, the
method and port checks); its named results `f`, `ok` and `err` are what that body assigns.

`readPrivate` gains the root-only check. Replace

```go
func ReadPrivate(path string, max int64, what string) ([]byte, error) {
	dir, base, err := splitPath(path)
```

with

```go
func ReadPrivate(path string, max int64, what string) ([]byte, error) {
	return readPrivate(path, max, what, false)
}

// readPrivate is ReadPrivate; with rootOnly the file must be root's
// (SystemOwner), not this user's.
func readPrivate(path string, max int64, what string, rootOnly bool) ([]byte, error) {
	dir, base, err := splitPath(path)
```

and, in `readPrivate`, replace `ownedAlone`'s check

```go
	if err := ownedAlone(file, li, what); err != nil {
		return nil, err
	}
```

with

```go
	if err := ownedAlone(file, li, what); err != nil {
		return nil, err
	}
	if st, ok := li.Sys().(*syscall.Stat_t); rootOnly && (!ok || st.Uid != SystemOwner) {
		return nil, fmt.Errorf("%s is not owned by root; the %s names the broker for every user on this host, "+
			"so it is root's alone: chown root %s", path, what, path)
	}
```

In `ownedAlone`, a directory's refusal says what it needs and names no command: the directory may be
shared, and a `chmod` would change it for everyone else (Ryan, 2026-10-10). Replace

```go
	if fi.Mode().Perm()&0o022 != 0 && !(fi.IsDir() && fi.Mode()&fs.ModeSticky != 0) {
		return fmt.Errorf("%s is writable by others (mode %v); whoever can write the %s chooses what port49 "+
			"trusts: chmod go-w %s", path, fi.Mode().Perm(), what, path)
	}
```

with

```go
	if fi.Mode().Perm()&0o022 != 0 && fi.IsDir() && fi.Mode()&fs.ModeSticky == 0 {
		// A directory may be shared, as a group-writable ~/.config is, so
		// the refusal says what it needs, never a chmod that would change it
		// for everyone else.
		return fmt.Errorf("%s is writable by others (mode %v); whoever can write the %s chooses what port49 "+
			"trusts, so port49 needs it writable by its owner alone (mode 0755 or 0700)", path, fi.Mode().Perm(), what)
	}
	if fi.Mode().Perm()&0o022 != 0 && !fi.IsDir() {
		return fmt.Errorf("%s is writable by others (mode %v); whoever can write the %s chooses what port49 "+
			"trusts: chmod go-w %s", path, fi.Mode().Perm(), what, path)
	}
```

- [ ] **Step 4: `internal/hostkeys/hostkeys.go`**

The pins stay in 9a's directory until 9d takes them out of the user's flow; `~/.port49` holds no
pins file (Ryan, 2026-10-10). Replace

```go
func Path() string { return filepath.Join(userconfig.Dir(), "known_hosts") }
```

with

```go
// It stays in plan 9a's directory (userconfig.LegacyDir), not ~/.port49,
// until plan 9d takes the pins out of the user's flow.
func Path() string { return filepath.Join(userconfig.LegacyDir(), "known_hosts") }
```

- [ ] **Step 5: `cmd/port49/main.go` and `TestMain`**

In the usage, replace

```
               (each flag overrides its key in the config file, $XDG_CONFIG_HOME/port49/config.yaml; --oidc
               signs in at your identity provider and holds the certificate the broker issues, signing in
               again when it has under a quarter of its life left, or with --sign-in)
```

with

```
               (each flag overrides its key in ~/.port49/config.yaml, or the file $PORT49_CONFIG names,
               each of whose keys overrides /etc/port49/config.yaml's; --oidc signs in at your identity
               provider and holds the certificate the broker issues, signing in again when it has under a
               quarter of its life left, or with --sign-in)
```

Replace `--config`'s help, `"your port49 config file: broker, broker_ca, cert and "+ "key, each
overridden by its flag"`, with `"your port49 config file, over /etc/port49/config.yaml "+ "key by
key; each flag overrides its key"`.

Replace `fill`'s comment's head

```go
// fill takes from the config file each value the command line left out
// (decision 42 ruling 6; decision 43 ruling 19). A missing file at the
// default path is no file; one --config names must be there, and is read
// and checked even when every flag is given.
```

with

```go
// fill takes from the config files each value the command line left out
// (decision 42 ruling 6; decision 43 rulings 19 and 24): the personal one
// over the system-wide one, key by key. A missing file at the default path
// is no file; one --config or $PORT49_CONFIG names must be there, and
// --config's is read and checked even when every flag is given.
```

and, in `fill`, replace

```go
	f, ok, err := userconfig.Load(s.configFile, opts...)
	switch {
	case err != nil:
		return err
	case !ok && set["config"]:
		return fmt.Errorf("%s: no such file", s.configFile)
	case !ok:
		return nil
	}
```

with

```go
	named := set["config"] || os.Getenv(userconfig.EnvConfig) != ""
	f, ok, err := userconfig.LoadAll(s.configFile, named, opts...)
	if err != nil || !ok {
		return err
	}
```

In `cmd/port49/main_test.go`, add `"github.com/rhwendt/port49/internal/userconfig"` to the imports,
after `internal/token`. After `const runCLIEnv = "PORT49_TEST_RUN_CLI"`, add:

```go
// testSystemConfig carries TestMain's stand-in for /etc/port49/config.yaml
// to the test binary run as port49.
const testSystemConfig = "PORT49_TEST_SYSTEM_CONFIG"
```

At the top of `TestMain`, before the subreaper hook, add:

```go
	// A child the tests start reads the system file the parent named.
	if p := os.Getenv(testSystemConfig); p != "" {
		userconfig.SystemPath = p
	}
```

and replace

```go
	// No test reads the developer's own ~/.config/port49 (plan 9a): every
	// default path under it lands in a directory of the test's.
	dir, err := os.MkdirTemp("", "p49cfg")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CONFIG_HOME", dir)
```

with

```go
	// No test reads the developer's own ~/.port49, ~/.config/port49 or
	// /etc/port49 (plans 9a and 9b): every default path lands in a
	// directory of the test's, 0700 as a home directory is.
	dir, err := os.MkdirTemp("", "p49cfg")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", dir)
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	os.Unsetenv(userconfig.EnvConfig)
	userconfig.SystemPath = filepath.Join(dir, "etc", "port49", "config.yaml")
	os.Setenv(testSystemConfig, userconfig.SystemPath)
```

- [ ] **Step 6: The kept CA bundle (decision 43 ruling 25)**

The agent fetches `/v1/config` on the connection it has just verified (`Connect`, unchanged), and
keeps the bundle in `~/.port49/broker_ca/<host>_<port>.pem`, 0600, one per broker so no broker's
bundle is trusted for another. A bundle out of `api.ParseCABundle`'s bounds, or one that drops the
CA the connection was verified to, is refused and the file left as it was; a change is logged by
fingerprint. A login trusts its `broker_ca` and the kept bundle together, and hands both to the
agent it starts. A certificate no CA this host trusts issued, which is what a host away through a
whole rotation meets, is said with the fix on the same line.

In `internal/agent/agent.go`, replace

```go
	handshakes   atomic.Int64
	// fingerprint is the certificate's, as CertFingerprint gives it.
```

with

```go
	handshakes   atomic.Int64
	// brokerRoot is the CA the last handshake verified the broker's
	// certificate to (BrokerRoot).
	brokerRoot atomic.Pointer[x509.Certificate]
	// fingerprint is the certificate's, as CertFingerprint gives it.
```

In `internal/agent/agent.go`, replace

```go
			if n := a.handshakes.Add(1); n > 1 {
```

with

```go
			if tc, ok := conn.(*tls.Conn); ok {
				if chains := tc.ConnectionState().VerifiedChains; len(chains) > 0 {
					a.brokerRoot.Store(chains[0][len(chains[0])-1])
				}
			}
			if n := a.handshakes.Add(1); n > 1 {
```

In `internal/agent/agent.go`, replace

```go
// SessionEndsAt is when this session ends; zero before Connect.
```

with

```go
// BrokerRoot is the CA the last handshake verified the broker's certificate
// to; nil before one. A CA bundle the broker sends must hold it (decision 43
// ruling 25).
func (a *Agent) BrokerRoot() *x509.Certificate { return a.brokerRoot.Load() }

// RotatedCAHint is the fix for a broker certificate no CA this host trusts
// issued, said on the same line: a host away through a whole CA rotation
// (decision 43 ruling 25).
const RotatedCAHint = "if the broker's operator rotated its CA while this host was away, get the broker's CA from " +
	"them and run `port49 login --broker-ca FILE` once; port49 keeps it current from then on"

// SessionEndsAt is when this session ends; zero before Connect.
```

In `internal/agent/agent.go`, replace

```go
	if errors.As(err, &verify) {
		return fmt.Errorf("agent: the broker's certificate at %s does not verify (%v); check that the trust anchor "+
			"(--broker-ca) is the CA that issued it, and that the broker URL is a name the certificate carries",
			a.broker, verify.Err)
	}
```

with

```go
	if errors.As(err, &verify) {
		return fmt.Errorf("agent: the broker's certificate at %s does not verify (%v); check that the trust anchor "+
			"(--broker-ca) is the CA that issued it, and that the broker URL is a name the certificate carries%s",
			a.broker, verify.Err, rotatedCA(verify.Err))
	}
```

In `internal/agent/agent.go`, replace

```go
// certificateAlerts are the alerts a broker sends about the certificate it
```

with

```go
// rotatedCA is RotatedCAHint after "; " for a certificate no CA this host
// trusts issued, and "" for any other failure.
func rotatedCA(err error) string {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "; " + RotatedCAHint
	}
	return ""
}

// certificateAlerts are the alerts a broker sends about the certificate it
```

In `internal/userconfig/userconfig.go`, replace

```go
// IssuedPaths is IssuedPathsIn ~/.port49 (Dir).
```

with

```go
// CABundlePathIn is where, under dir, the agent keeps the CA bundle a broker
// sent it (spec §13 decision 43 ruling 25): dir/broker_ca/<host>_<port>.pem,
// one per broker, so no broker's bundle is trusted for another.
func CABundlePathIn(dir, broker string) (string, error) {
	cert, _, err := IssuedPathsIn(dir, broker)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "broker_ca", filepath.Base(cert)), nil
}

// CABundlePath is CABundlePathIn ~/.port49 (Dir).
func CABundlePath(broker string) (string, error) { return CABundlePathIn(Dir(), broker) }

// IssuedPaths is IssuedPathsIn ~/.port49 (Dir).
```

In `cmd/port49/main.go`, replace

```go
	s.brokerCAPEM = caPEM
	pool := x509.NewCertPool()
```

with

```go
	// The bundle the agent kept for this broker joins the CA named here
	// (decision 43 ruling 25); the agent the login starts is handed both.
	if s.brokerCAFD == 0 {
		if caPEM, err = withKeptBundle(s.broker, caPEM); err != nil {
			return nil, err
		}
	}
	s.brokerCAPEM = caPEM
	pool := x509.NewCertPool()
```

In `cmd/port49/main.go`, replace

```go
	ln, err := agent.Listen(sf.socket)
```

with

```go
	keepCABundle(sf.broker, conf.BrokerCABundle, conf.BrokerCABundleRefused, a.BrokerRoot(), stderr)
	ln, err := agent.Listen(sf.socket)
```

In `cmd/port49/issue.go`, replace

```go
		if errors.As(err, &verify) {
			return api.Config{}, fmt.Errorf("the broker's certificate at %s does not verify (%v); check that the broker "+
				"CA (--broker-ca) is the CA that issued it", broker, verify.Err)
		}
```

with

```go
		if errors.As(err, &verify) {
			hint := ""
			var unknown x509.UnknownAuthorityError
			if errors.As(verify.Err, &unknown) {
				hint = "; " + agent.RotatedCAHint
			}
			return api.Config{}, fmt.Errorf("the broker's certificate at %s does not verify (%v); check that the broker "+
				"CA (--broker-ca) is the CA that issued it%s", broker, verify.Err, hint)
		}
```

Create `cmd/port49/cabundle.go`:

```go
package main

import (
	"cmp"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/userconfig"
)

// keepCABundle keeps the CA bundle the broker sent on the connection the
// agent verified, in ~/.port49/broker_ca/<host>_<port>.pem, 0600, for the
// next login to trust beside its broker_ca (spec §13 decision 43 ruling 25).
// So a rotation of the broker's CA asks nothing of the user. A bundle out of
// bounds, or one that drops the CA this connection was verified to, is
// refused and the file left as it was; a change is logged by fingerprint.
// A broker that sends no bundle clears what was kept (forgetBundle), so a
// CA planted by whoever held the broker's key once is gone at the real
// broker's next answer; one that refused its own bundle at start (refused)
// leaves the kept file as it was, since it sends none by fault, not by
// choice. Nothing here ends the session.
func keepCABundle(broker, bundle string, refused bool, root *x509.Certificate, log io.Writer) {
	path, err := userconfig.CABundlePath(broker)
	if err != nil {
		fmt.Fprintf(log, "port49 agent: the broker's CA bundle is not kept: %v\n", err)
		return
	}
	if refused {
		fmt.Fprintf(log, "port49 agent: the broker refused its own tls_ca_bundle_file at start (its log says why), "+
			"so it sends no CA bundle; %s is left as it was\n", path)
		return
	}
	if bundle == "" {
		forgetBundle(path, root, log)
		return
	}
	certs, err := api.ParseCABundle([]byte(bundle))
	if err == nil && (root == nil || !slices.ContainsFunc(certs, root.Equal)) {
		err = errors.New("it does not hold the CA this connection was verified to")
	}
	if err != nil {
		fmt.Fprintf(log, "port49 agent: the broker's CA bundle is refused: %v; %s is left as it was\n", err, path)
		return
	}
	was := "none"
	if old, err := userconfig.ReadPrivate(path, api.MaxCABundleBytes, "broker CA bundle"); err == nil {
		if held, err := api.ParseCABundle(old); err == nil {
			if slices.EqualFunc(held, certs, (*x509.Certificate).Equal) {
				return
			}
			was = api.CAFingerprints(held)
		}
	}
	if err := userconfig.WritePrivate(path, api.EncodeCABundle(certs), "broker CA bundle"); err != nil {
		fmt.Fprintf(log, "port49 agent: the broker's CA bundle is not kept: %v\n", err)
		return
	}
	fmt.Fprintf(log, "port49 agent: kept the broker's CA bundle in %s: %s (was %s)\n", path, api.CAFingerprints(certs), was)
}

// forgetBundle clears the bundle kept at path when the broker, on a verified
// connection, sends none (decision 43 ruling 25). A kept file that does not
// hold the CA this connection was verified to is not needed for it, and is
// removed; one that does is cut to that CA alone, so the next login still
// verifies the broker while any other CA it held is dropped.
func forgetBundle(path string, root *x509.Certificate, log io.Writer) {
	old, err := userconfig.ReadPrivate(path, api.MaxCABundleBytes, "broker CA bundle")
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	held, perr := api.ParseCABundle(old)
	if err == nil && perr != nil {
		err = perr
	}
	if err != nil || root == nil {
		fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle, and %s is left as it was: %v\n", path,
			cmp.Or(err, errors.New("no CA was verified")))
		return
	}
	if !slices.ContainsFunc(held, root.Equal) {
		if err := os.Remove(path); err != nil {
			fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle, and %s is not removed: %v\n", path, err)
			return
		}
		fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle; removed %s (it held %s)\n", path,
			api.CAFingerprints(held))
		return
	}
	if len(held) == 1 {
		return
	}
	only := []*x509.Certificate{root}
	if err := userconfig.WritePrivate(path, api.EncodeCABundle(only), "broker CA bundle"); err != nil {
		fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle, and %s is not changed: %v\n", path, err)
		return
	}
	fmt.Fprintf(log, "port49 agent: the broker sends no CA bundle; %s now holds only the CA this connection was "+
		"verified to: %s (was %s)\n", path, api.CAFingerprints(only), api.CAFingerprints(held))
}

// withKeptBundle is caPEM and the bundle the agent kept for broker, which a
// login trusts together (decision 43 ruling 25). A kept file that cannot be
// used is refused, naming it: it is the agent's to rewrite, and deleting it
// loses nothing but what the broker sends again.
func withKeptBundle(broker string, caPEM []byte) ([]byte, error) {
	if broker == "" {
		return caPEM, nil
	}
	path, err := userconfig.CABundlePath(broker)
	if err != nil {
		return caPEM, nil // the broker URL is refused where it is used
	}
	raw, err := userconfig.ReadPrivate(path, api.MaxCABundleBytes, "broker CA bundle")
	if errors.Is(err, fs.ErrNotExist) {
		return caPEM, nil
	}
	if err == nil {
		_, err = api.ParseCABundle(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("%s, the broker's CA bundle the agent kept: %w; remove it, and the next agent keeps "+
			"the broker's again", path, err)
	}
	return append(append(slices.Clip(caPEM), '\n'), raw...), nil
}
```

`agentMain`'s `keepCABundle` goes after a successful `Connect`, before the socket listens; its
lines go to the agent's log. `issue.go` already imports `crypto/x509` and `internal/agent`.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test -race ./internal/userconfig ./internal/hostkeys ./internal/agent ./cmd/port49`, then
`make test && make vet`, `CGO_ENABLED=0 GOOS=darwin go vet ./internal/userconfig ./internal/agent
./cmd/port49`, and `go vet -tags lab ./tests/lab/`.
Expected: PASS, with `TestTheDirectories`, `TestLoadAllLayersYoursOverTheSystemFile`,
`TestLoadAllWithNeitherFile`, `TestASystemFileNotRootsIsRefused`,
`TestAConfigAtPlan9asPlaceIsRefused`, `TestTheSystemFileIsUnderYoursKeyByKey`,
`TestAConfigFileAtPlan9asPlaceIsRefused`, `TestTheSystemFileAloneIsAFirstLogin`,
`TestKeepCABundle`, `TestALoginTrustsTheKeptBundleBesideItsCA` and
`TestTheAgentKeepsTheBrokersCABundle` among them. Every earlier test passes unchanged but the two
whose message changed (Step 1); `internal/agent`'s `TestARefusedHandshakeNamesTheLikelyCauses`
still finds "trust anchor", now followed by the rotation's hint.

- [ ] **Step 8: Commit**

```bash
git add internal/userconfig internal/hostkeys/hostkeys.go internal/agent/agent.go cmd/port49/main.go \
  cmd/port49/main_test.go cmd/port49/config_test.go cmd/port49/issue.go cmd/port49/cabundle.go \
  cmd/port49/cabundle_test.go cmd/port49/issue_login_linux_test.go cmd/port49/login_linux_test.go \
  cmd/port49/trust_hint_test.go
git commit -m "feat(userconfig): the client's config in ~/.port49, over a system-wide /etc/port49/config.yaml; the broker's CA bundle kept"
```

---

### Task 12: Lab L55 (Keycloak as the client meets it) and L56 (issued certificates end to end on vEOS)

**Files:**
- Create: `tests/lab/l55_test.go`, `tests/lab/l56_test.go`, `tests/lab/l55_l56_unit_test.go` (each
  `//go:build lab`)
- Create, by the run: `tests/lab/results/L55-keycloak.md`, `tests/lab/results/L56-arista_eos.md`, and
  `tests/lab/evidence/L55-keycloak.json`; the L56 capture through `make evidence`
- Modify: `Makefile` (`lab-oidc-l55`, `lab-oidc-agent`), `tests/lab/README.md` (an "OIDC sign-in and
  issued certificates" section), `docs/design/2026-08-23-policy-engine-spec.md` §15 (L55, L56
  statuses), decision 43, and any text the results contradict

**Interfaces:**
- Consumes: `bin/port49` (`make build`); `userconfig.IssuedPathsIn`; from the lab harness:
  `startKeycloak`, `keycloakClient`, `waitDiscovery`, `formAction`, `claimsOf`, `oidcEvidence`,
  `writeOIDCResult`, `leakIn`, `scrubbed`, `randomSecret`, `wideCell`, `oneLineMax`, `errCause`,
  `locShape`, `kcHost`, `kcPort`, `kcRealm`, `kcClient`, `kcRedirect`, `oidcAlice`,
  `oidcAlicePassword`, `oidcBrokerLogout`, `oidcE2EFiles`, `oidcE2EPKI`, `oidcBroker`
  (`mintRetry`), `brokerClient`, `sliceBrokerURL`, `slicePKIDir`, `root`, `platformSelection`,
  `labFor`, `l.startComposeWith`, `composeOptions`, `c.run`, `c.local`, `l.capture`, `l.shell`,
  `l.runPermitted`, `l.result`, `(k *keycloak) adminFromEnv`, `Admin`, `adminDo`, `UserID`,
  `LogoutUser`, `SetLogoutURL`, `ServiceToken`, `know`, `known`, `oidcNoteLeak`, `loginAgainAt`,
  `e2eAlice`, `labSecrets`.
- Produces: the two rows' notes. Until they close, decision 43's rulings 4 and 8 stay provisional,
  and no doc says which redirect registration Keycloak accepts.

The lab runs on the SER8 (memory: lab runs allowed; lab stays single-occupant). L55 needs Docker
alone. L56 needs the compose stack, containerlab and the EOS image.

- [ ] **Step 1: The pure helpers and their unit test**

Create `tests/lab/l55_l56_unit_test.go`:

```go
//go:build lab

package lab

import (
	"strings"
	"testing"
	"time"
)

func TestL56AuthURLReadsPort49sLine(t *testing.T) {
	for line, want := range map[string]string{
		"  https://keycloak.port49.lab:18443/realms/port49-lab/protocol/openid-connect/auth?client_id=port49-cli&state=x": "https://keycloak.port49.lab:18443/realms/port49-lab/protocol/openid-connect/auth?client_id=port49-cli&state=x",
		"port49: open this address in a browser and sign in at https://keycloak.port49.lab:18443/realms/port49-lab:":      "",
		"  http://127.0.0.1:18749/callback": "",
	} {
		if got, ok := l56AuthURL(line); got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", line, got, ok)
		}
	}
}

func TestL56LoginFromReadsTheBrokersTime(t *testing.T) {
	at, ok := l56LoginFrom("port49 token: the session is over: your identity provider ended your sessions at " +
		"2026-10-10T03:00:00Z (back-channel logout); log in again from 2026-10-10T03:01:01Z\n")
	if !ok || !at.Equal(time.Date(2026, 10, 10, 3, 1, 1, 0, time.UTC)) {
		t.Fatalf("%v %v", at, ok)
	}
	if _, ok := l56LoginFrom("port49 token: no agent"); ok {
		t.Fatal("read a time from nothing")
	}
}

func TestL55AcceptedIsTheLoginForm(t *testing.T) {
	form := []byte(`<form id="kc-form-login" class="x" action="https://k/login-actions/authenticate?x=1" method="post">`)
	if !l55Accepted(200, form) || l55Accepted(400, []byte("Invalid parameter: redirect_uri")) || l55Accepted(200, []byte("<html/>")) {
		t.Fatal("misread")
	}
}

// The end to end's broker asks for the email scope its principal claim needs,
// and issues certificates.
func TestL56FilesAskForTheEmailScopeAndIssue(t *testing.T) {
	files := map[string]string{
		"port49-broker.yaml": "broker:\n  client_ca_file: /etc/port49/ca.pem\n  listen: x\n",
		"policy.yaml":        "subjects:\ngrants:\n",
	}
	if err := l56Files(files); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"        principal_claim: email\n        scopes: [openid, email]\n",
		"  identity:\n    issuance: {}\n"} {
		if !strings.Contains(files["port49-broker.yaml"], want) {
			t.Fatalf("no %q in %s", want, files["port49-broker.yaml"])
		}
	}
}

// The leak check exempts what port49 prints by design and nothing else.
func TestL56LeakExemptsOnlyWhatPort49Prints(t *testing.T) {
	kc := &keycloak{}
	kc.know("state-0123456789", "verifier-0123456789")
	c := &l56CLI{printed: []string{"state-0123456789"}}
	if err := c.leak(kc, "  https://k/auth?state=state-0123456789"); err != nil {
		t.Fatalf("the printed state: %v", err)
	}
	for _, text := range []string{"verifier-0123456789", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"} {
		if c.leak(kc, "port49: "+text) == nil {
			t.Errorf("%q not seen", text)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test -tags lab ./tests/lab/ -run 'TestL56AuthURL|TestL56LoginFrom|TestL55Accepted|TestL56Files|TestL56Leak' -count=1`
Expected: FAIL to build: `undefined: l56AuthURL`. (Never `-run TestL56` alone: it matches
`TestL56IssuedEndToEnd`, the lab run itself.)

- [ ] **Step 3: L55**

Create `tests/lab/l55_test.go`:

```go
//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const l55Claim = "Keycloak as port49's public client meets it (plan 9b): which redirect registration admits an " +
	"authorization request naming http://127.0.0.1:<port>/callback, for the registered port and an ephemeral one " +
	"(RFC 8252 §7.3), against a matcher seen to accept the realm's own redirect and refuse another host's; whether a " +
	"code is exchanged with the right S256 verifier, a wrong one and none, for port49-cli as the realm file sets its " +
	"PKCE method, and whether code_challenge_method=plain is accepted; discovery's code_challenge_methods_supported " +
	"and authorization_response_iss_parameter_supported, and whether the authorization response carries iss (RFC " +
	"9207); whether a 43-character base64url nonce, port49's key binding, comes back in the ID token byte for byte, " +
	"and whether a prompt=login sign-in's auth_time is within 10s of it, and over a live SSO session whether " +
	"prompt=login shows the form and moves auth_time on, against the same session with no prompt (policy engine " +
	"spec §15 L55; §13 decision 43 rulings 1, 3, 4 and 8)."

// l55Accepted is whether Keycloak took an authorization request: it showed
// the login form, rather than its "Invalid parameter" page.
func l55Accepted(status int, body []byte) bool {
	return status == http.StatusOK && formAction.Match(body)
}

// l55Word is an authorization request's outcome as a cell says it.
func l55Word(accepted bool) string {
	if accepted {
		return "accepted"
	}
	return "refused"
}

// l55Browser is a browser of its own: a fresh cookie jar, so no SSO session.
func (k *keycloak) l55Browser() *http.Client {
	c := keycloakClient(k.ca)
	c.Jar, _ = cookiejar.New(nil)
	return c
}

// l55Authorize is an authorization request for port49-cli naming redirect,
// with an S256 challenge for verifier, a fresh state, and extra; a parameter
// extra sets to "" is left out.
func (k *keycloak) l55Authorize(t *testing.T, redirect, verifier string, extra url.Values) string {
	t.Helper()
	state := randomSecret(t)
	k.know(verifier, state)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {kcClient}, "redirect_uri": {redirect},
		"scope": {"openid email"}, "state": {state}, "prompt": {"login"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for key, v := range extra {
		q[key] = v
		if len(v) == 1 && v[0] == "" {
			delete(q, key)
		}
	}
	return k.URL + "/protocol/openid-connect/auth?" + q.Encode()
}

// authorizeAccepted asks with a fresh browser and reports whether Keycloak
// showed the login form.
func (k *keycloak) authorizeAccepted(t *testing.T, redirect string, extra url.Values) bool {
	t.Helper()
	resp, err := k.l55Browser().Get(k.l55Authorize(t, redirect, randomSecret(t)+randomSecret(t), extra))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return l55Accepted(resp.StatusCode, body)
}

// l55SignIn signs alice in with browser and returns the code, its verifier,
// and the authorization response's query (the code registered as secret).
func (k *keycloak) l55SignIn(t *testing.T, browser *http.Client, extra url.Values) (string, string, url.Values) {
	t.Helper()
	code, verifier, q, _ := k.l55SignInForm(t, browser, extra)
	return code, verifier, q
}

// l55SignInForm is l55SignIn, and whether Keycloak showed the login form
// (false: an SSO session in browser answered with no password).
func (k *keycloak) l55SignInForm(t *testing.T, browser *http.Client, extra url.Values) (string, string, url.Values,
	bool) {
	t.Helper()
	verifier, form := randomSecret(t)+randomSecret(t), false
	resp, err := browser.Get(k.l55Authorize(t, kcRedirect, verifier, extra))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			t.Fatalf("INVALID: authorize answered %s with no login form; no note is written", resp.Status)
		}
		form = true
		if resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {oidcAlice},
			"password": {oidcAlicePassword}, "credentialId": {""}}); err != nil {
			t.Fatalf("login: %s", errCause(err))
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("INVALID: no code (%s, redirect %s); no note is written", resp.Status, locShape(loc))
	}
	k.know(loc.Query().Get("code"))
	return loc.Query().Get("code"), verifier, loc.Query(), form
}

// l55Exchange is the code's exchange with verifierSent ("" sends none); it
// registers every token in the answer as secret, and never fails the test.
func (k *keycloak) l55Exchange(t *testing.T, code, verifierSent string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {kcRedirect},
		"client_id": {kcClient}}
	if verifierSent != "" {
		form.Set("code_verifier", verifierSent)
	}
	resp, err := k.HTTP.PostForm(k.URL+"/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("token endpoint: %s", errCause(err))
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	for _, key := range []string{"id_token", "access_token", "refresh_token"} {
		if v, ok := out[key].(string); ok {
			k.know(v)
		}
	}
	return resp.StatusCode, out
}

// l55IDClaims is the claims of the ID token the code's exchange answers; a
// cell with no id_token is INVALID, and no note is written.
func (k *keycloak) l55IDClaims(t *testing.T, code, verifier, cell string) map[string]any {
	t.Helper()
	status, out := k.l55Exchange(t, code, verifier)
	id, ok := out["id_token"].(string)
	if !ok {
		t.Fatalf("INVALID: cell %s's exchange gave no id_token (%s); no note is written", cell, l55Said(status, out))
	}
	_, claims := claimsOf(id)
	return claims
}

// l55Said is a token answer as a cell: its status, and its error or what it
// carried.
func l55Said(status int, out map[string]any) string {
	if e, ok := out["error"]; ok {
		return fmt.Sprintf("%d %v", status, e)
	}
	var has []string
	for _, key := range []string{"id_token", "refresh_token"} {
		if _, ok := out[key]; ok {
			has = append(has, key)
		}
	}
	return fmt.Sprintf("%d with %s", status, strings.Join(has, ", "))
}

// redirects and setRedirects read and replace port49-cli's redirect URIs;
// setRedirects reports whether Keycloak took them, read back.
func (k *keycloak) redirects(t *testing.T) (map[string]any, []string) {
	t.Helper()
	var clients []map[string]any
	k.adminDo(t, "GET", "/clients?clientId="+kcClient, nil, &clients)
	if len(clients) != 1 {
		t.Fatalf("%d clients named %s", len(clients), kcClient)
	}
	var uris []string
	for _, u := range clients[0]["redirectUris"].([]any) {
		uris = append(uris, u.(string))
	}
	return clients[0], uris
}

func (k *keycloak) setRedirects(t *testing.T, uris []string) bool {
	t.Helper()
	c, _ := k.redirects(t)
	c["redirectUris"] = uris
	b, _ := json.Marshal(c)
	req, _ := http.NewRequest("PUT", "https://"+kcHost+":"+kcPort+"/admin/realms/"+kcRealm+"/clients/"+c["id"].(string),
		strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer "+k.Admin(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		t.Fatalf("PUT the client: %s", errCause(err))
	}
	resp.Body.Close()
	_, got := k.redirects(t)
	return resp.StatusCode/100 == 2 && slices.Equal(got, uris)
}

func l55FreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestL55PublicClient(t *testing.T) {
	k := startKeycloak(t)
	ev, evPath := oidcEvidence(t, k, "L55-keycloak")
	var obs strings.Builder
	obs.WriteString("| step | observed |\n|---|---|\n")
	cell := func(step, what string) {
		fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what))
		ev(step, what)
	}

	// 1. Discovery and the answer's iss.
	var disc map[string]any
	resp, err := k.HTTP.Get(k.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %s", errCause(err))
	}
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	cell("1a. discovery code_challenge_methods_supported", fmt.Sprint(disc["code_challenge_methods_supported"]))
	cell("1b. discovery authorization_response_iss_parameter_supported",
		fmt.Sprint(disc["authorization_response_iss_parameter_supported"]))
	_, _, q := k.l55SignIn(t, k.l55Browser(), nil)
	cell("1c. the authorization response's iss", fmt.Sprintf("present %v, the issuer %v", q.Has("iss"), q.Get("iss") == k.URL))

	// 2. The redirect registrations, each against the registered port and an
	// ephemeral one. Controls: with the realm's own registration, its own
	// redirect is accepted and another host's refused, so "accepted" rests on
	// a matcher seen to say both.
	if !k.authorizeAccepted(t, kcRedirect, nil) || k.authorizeAccepted(t, "http://evil.example/callback", nil) {
		t.Fatal("INVALID: the realm's own redirect was not accepted, or another host's was; l55Accepted cannot tell")
	}
	cell("2. control: the realm's own redirect, and http://evil.example/callback", "accepted; refused")
	_, orig := k.redirects(t)
	defer k.setRedirects(t, orig)
	ephemeral := l55FreePort(t)
	for _, reg := range []string{kcRedirect, "http://127.0.0.1/callback", "http://127.0.0.1/*", "http://127.0.0.1:*/callback"} {
		if !k.setRedirects(t, []string{reg}) {
			cell("2. registration "+reg, "not taken by the admin API")
			continue
		}
		var parts []string
		for _, port := range []int{18749, ephemeral} {
			parts = append(parts, fmt.Sprintf("port %d %s", port,
				l55Word(k.authorizeAccepted(t, fmt.Sprintf("http://127.0.0.1:%d/callback", port), nil))))
		}
		cell("2. registration "+reg, strings.Join(parts, "; "))
	}
	if !k.setRedirects(t, []string{kcRedirect}) {
		t.Fatal("INVALID: the realm's own redirect could not be put back; no note is written")
	}

	// 3. PKCE, on port49-cli as the realm file configures it.
	client, _ := k.redirects(t)
	attrs, _ := client["attributes"].(map[string]any)
	pkce := fmt.Sprint(attrs["pkce.code.challenge.method"])
	preface := fmt.Sprintf("port49-cli's `pkce.code.challenge.method` attribute is %q (`tests/lab/oidc/keycloak/"+
		"realm.json`), so step 3 measures a client Keycloak is told requires that method; what it does for a client "+
		"set to require none, which decision 43 ruling 1's provider listing no methods resembles, is not measured "+
		"here.\n\n", pkce)
	cell("3. port49-cli's pkce.code.challenge.method attribute", pkce)
	for _, c := range []struct{ name, how string }{{"the right verifier", "right"}, {"a wrong verifier", "wrong"},
		{"no verifier", "none"}} {
		code, verifier, _ := k.l55SignIn(t, k.l55Browser(), nil)
		sent := map[string]string{"right": verifier, "wrong": verifier + "x", "none": ""}[c.how]
		cell("3. the exchange with "+c.name, l55Said(k.l55Exchange(t, code, sent)))
	}
	cell("3d. code_challenge_method=plain", l55Word(k.authorizeAccepted(t, kcRedirect,
		url.Values{"code_challenge_method": {"plain"}, "code_challenge": {randomSecret(t) + randomSecret(t)}})))

	// 4. The key binding: a nonce shaped as api.IssuanceNonce's comes back
	// byte for byte, and a prompt=login sign-in's auth_time is the sign-in's.
	sum := sha256.Sum256([]byte(randomSecret(t)))
	nonce := base64.RawURLEncoding.EncodeToString(sum[:])
	signedAt := time.Now()
	code, verifier, _ := k.l55SignIn(t, k.l55Browser(), url.Values{"nonce": {nonce}})
	claims := k.l55IDClaims(t, code, verifier, "4")
	at, _ := claims["auth_time"].(float64)
	cell("4. a 43-character nonce, and auth_time", fmt.Sprintf("nonce echoed byte for byte %v; auth_time %+.0fs "+
		"from the sign-in", claims["nonce"] == nonce, at-float64(signedAt.Unix())))

	// 4b. prompt=login over a live SSO session, which cell 4's fresh browser
	// cannot show: decision 43 ruling 8's freshness check rests on it. One
	// browser signs in with no prompt, and its fresh jar must be shown the
	// form; 15s later, the control: the same session with no prompt shows no
	// form and keeps the first auth_time, or there is no SSO session for
	// prompt=login to be measured over, and the cell is INVALID; then
	// prompt=login, which must show the form and move auth_time on.
	sso, noPrompt := k.l55Browser(), url.Values{"prompt": {""}}
	code, verifier, _, formFirst := k.l55SignInForm(t, sso, noPrompt)
	if !formFirst {
		t.Fatal("INVALID: cell 4b's first sign-in, in a fresh browser, was not shown the login form; no note is written")
	}
	first, _ := k.l55IDClaims(t, code, verifier, "4b")["auth_time"].(float64)
	time.Sleep(15 * time.Second)
	code, verifier, _, formNone := k.l55SignInForm(t, sso, noPrompt)
	again, _ := k.l55IDClaims(t, code, verifier, "4b")["auth_time"].(float64)
	if formNone || again != first {
		t.Fatalf("INVALID: cell 4b's control: no SSO session held (form %v, auth_time %+.0fs); no note is written",
			formNone, again-first)
	}
	code, verifier, _, formLogin := k.l55SignInForm(t, sso, nil)
	login, _ := k.l55IDClaims(t, code, verifier, "4b")["auth_time"].(float64)
	cell("4b. control: the same SSO session 15s later, no prompt", fmt.Sprintf("form shown %v; auth_time %+.0fs "+
		"after the first sign-in's", formNone, again-first))
	cell("4b. prompt=login over that SSO session", fmt.Sprintf("form shown %v; auth_time %+.0fs after the first "+
		"sign-in's (expected 15s or more)", formLogin, login-first))
	writeOIDCResult(t, k, "L55", l55Claim, preface+obs.String(), evPath)
}
```

`locShape` is `oidcflow_test.go`'s. `k.adminDo(t, "PUT", "", …)` is not used: L55 changes only
the client's redirect URIs, and puts them back.

- [ ] **Step 4: L56**

Create `tests/lab/l56_test.go`:

```go
//go:build lab

package lab

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

const l56Claim = "Port49-issued certificates end to end on Keycloak and one device (plan 9b), with the real port49 " +
	"CLI: a broker started with broker.identity.issuance and no issuing CA answers a sign-in's exchange 503 " +
	"issuance_unavailable and its log names init-issuer, and after port49-broker init-issuer and a restart issues; " +
	"port49 login --oidc --no-browser signs in through a scripted browser, asks the password, writes a 0600 key and " +
	"its certificate, names the principal, starts the agent and refreshes once; port49 token mints and the device " +
	"takes the token over SSH; port49 refresh extends the device session with no sign-in; port49 login after the " +
	"agent stopped starts a new one with no sign-in and extends the device session; port49 login --sign-in at a " +
	"terminal, the address pasted, issues a new certificate; an administrator's sign-out refuses the certificate's " +
	"next mint in the broker's logout words and ends the agent, a port49 login over that certificate removes it, and " +
	"a sign-in from the time the broker names works; with Keycloak stopped, port49 token, port49 refresh and a new " +
	"agent over the held certificate work, and port49 login --sign-in says the provider did not answer and when the " +
	"held certificate ends; no compact JWS, code or private key in the CLI's raw output or the agent's log " +
	"(policy engine spec §15 L56; §13 decision 43)."

// l56AuthURL is the authorization URL port49 prints on its own line,
// indented two spaces.
func l56AuthURL(line string) (string, bool) {
	if !strings.HasPrefix(line, "  https://") || strings.ContainsAny(strings.TrimSpace(line), " \t") {
		return "", false
	}
	return strings.TrimSpace(line), true
}

var loginFrom = regexp.MustCompile(`log in again from (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)`)

// l56LoginFrom is the time the broker's logout words say a login is taken from.
func l56LoginFrom(text string) (time.Time, bool) {
	m := loginFrom.FindStringSubmatch(text)
	if m == nil {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, m[1])
	return at, err == nil
}

// l56Files is the end to end's files: the human verifier asking for the
// email scope its principal claim needs, and the broker issuing.
func l56Files(files map[string]string) error {
	if err := oidcE2EFiles(files); err != nil {
		return err
	}
	const at = "        principal_claim: email\n"
	b := files["port49-broker.yaml"]
	if !strings.Contains(b, at) || !strings.Contains(b, "  identity:\n") {
		return fmt.Errorf("port49-broker.yaml has no human verifier's principal_claim, or no identity, to follow")
	}
	b = strings.Replace(b, at, at+"        scopes: [openid, email]\n", 1)
	files["port49-broker.yaml"] = strings.Replace(b, "  identity:\n", "  identity:\n    issuance: {}\n", 1)
	return nil
}

// l56Proxy is a CONNECT proxy on loopback that takes the CLI to Keycloak by
// its issuer's name, which this host does not resolve. It tunnels to that
// one name alone. It is lab plumbing, and the note says so.
func l56Proxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != kcHost+":"+kcPort {
			http.Error(w, "l56 proxy: "+kcHost+" alone", http.StatusForbidden)
			return
		}
		up, err := net.DialTimeout("tcp", "127.0.0.1:"+kcPort, 10*time.Second)
		if err != nil {
			http.Error(w, "l56 proxy: "+err.Error(), http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, conn); up.Close() }()
		_, _ = io.Copy(conn, up)
		conn.Close()
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// l56Pty is a pseudo-terminal: the master the test types on, and the slave
// port49 takes for its stdin, so it offers the paste.
func l56Pty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("INVALID: no pty: %v", err)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Fatalf("INVALID: no pty: TIOCSPTLCK: %v", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Fatalf("INVALID: no pty: TIOCGPTN: %v", e)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("INVALID: no pty: %v", err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

// l56CLI is bin/port49 as an operator runs it: its own config directory
// (where the issued key and certificate are kept) and agent socket, the
// broker's CA, Keycloak's CA, and the proxy.
type l56CLI struct {
	bin, sock, home string
	env             []string
	flags           []string
	// printed is what port49 prints by design among the values the run
	// registered as secret: each authorization URL's state, nonce and
	// code_challenge (decision 43 ruling 20), and each device token on
	// `port49 token`'s stdout. leak exempts these and nothing else.
	printed []string
}

func newL56CLI(t *testing.T, proxy, idpCA string) *l56CLI {
	t.Helper()
	bin := filepath.Join(root, "bin", "port49")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("bin/port49 is not built (`make build`): %v", err)
	}
	home, err := os.MkdirTemp("", "p49l56")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	c := &l56CLI{bin: bin, home: home, sock: filepath.Join(home, "run", "agent.sock"),
		env: append(os.Environ(), "HOME="+home, "HTTPS_PROXY=http://"+proxy, "NO_PROXY=127.0.0.1",
			"BROWSER=", "DISPLAY=", "WAYLAND_DISPLAY=")}
	c.flags = []string{"--oidc", "--no-browser", "--redirect-port", "18749", "--broker", sliceBrokerURL,
		"--broker-ca", filepath.Join(root, slicePKIDir, testpki.LabCA), "--oidc-ca", idpCA, "--socket", c.sock}
	t.Cleanup(c.stopAgent)
	return c
}

// issued is where the CLI keeps the broker's certificate and its key.
func (c *l56CLI) issued(t *testing.T) (string, string) {
	t.Helper()
	cert, key, err := userconfig.IssuedPathsIn(filepath.Join(c.home, ".port49"), sliceBrokerURL)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// keyNow registers the issued key there now, its PEM's first line, as a value
// no output may hold. finish calls it once the command has ended, so the run
// that wrote a key is checked against that key.
func (c *l56CLI) keyNow(kc *keycloak) {
	_, keyPath, err := userconfig.IssuedPathsIn(filepath.Join(c.home, ".port49"), sliceBrokerURL)
	if err != nil {
		return
	}
	if raw, err := os.ReadFile(keyPath); err == nil {
		if blk, _ := pem.Decode(raw); blk != nil {
			kc.know(base64.StdEncoding.EncodeToString(blk.Bytes)[:64])
		}
	}
}

// knowKey is keyNow, and the certificate's SHA-256, "" for none.
func (c *l56CLI) knowKey(t *testing.T, kc *keycloak) string {
	t.Helper()
	c.keyNow(kc)
	certPath, _ := c.issued(t)
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// agentLog is the agent's log, as the login started it.
func (c *l56CLI) agentLog() string {
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(c.sock), "agent.log"))
	return string(b)
}

// l56Run is one command's outcome. Its raw output is checked for a leaked
// credential first (leak), then scrubbed of every registered secret for the
// note.
type l56Run struct {
	code           int
	stdout, stderr string
	form           bool  // the scripted browser was shown the password form
	leak           error // the raw output held a credential (l56CLI.leak)
}

func (r l56Run) cell() string {
	return fmt.Sprintf("exit %d; stdout %q; stderr %q", r.code, oneLineMax(r.stdout, 300), oneLineMax(r.stderr, 400))
}

// leak is leakIn on raw CLI output, before any scrubbing: a compact JWS, or
// a value the run registered as secret (a code, the key, the admin password)
// that port49 does not print by design. The PKCE verifier port49 draws is
// never seen here; the unit tests' credentialsNowhere checks it.
func (c *l56CLI) leak(kc *keycloak, raw string) error {
	var secrets []string
	for _, v := range kc.known() {
		if !slices.Contains(c.printed, v) {
			secrets = append(secrets, v)
		}
	}
	return leakIn(raw, secrets)
}

// finish is r with its raw output checked for a leak, then scrubbed. The key
// the command may have written is registered first.
func (c *l56CLI) finish(kc *keycloak, r l56Run) l56Run {
	c.keyNow(kc)
	r.leak = c.leak(kc, r.stdout+"\n"+r.stderr)
	r.stdout, r.stderr = scrubbed(r.stdout, kc.known()), scrubbed(r.stderr, kc.known())
	return r
}

// l56Cmd is one port49 command running, its stderr read line by line for the
// authorization URL it prints.
type l56Cmd struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	urls           chan string
	done           chan struct{}
}

// start runs port49 with args, stdin from stdin (nil: none).
func (c *l56CLI) start(t *testing.T, stdin *os.File, args ...string) *l56Cmd {
	t.Helper()
	p := &l56Cmd{cmd: exec.Command(c.bin, args...), urls: make(chan string, 1), done: make(chan struct{})}
	p.cmd.Env = c.env
	p.cmd.Stdout = &p.stdout
	if stdin != nil {
		p.cmd.Stdin = stdin
	}
	errR, err := p.cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.done)
		sc := bufio.NewScanner(errR)
		sc.Buffer(make([]byte, 64<<10), 64<<10)
		for sc.Scan() {
			p.stderr.WriteString(sc.Text() + "\n")
			if u, ok := l56AuthURL(sc.Text()); ok {
				select {
				case p.urls <- u:
				default:
				}
			}
		}
	}()
	return p
}

// authURL is the address the command printed, its state, nonce and
// code_challenge registered as secret and as printed by design; "" when none
// came within 30s, the command killed.
func (p *l56Cmd) authURL(c *l56CLI, kc *keycloak) string {
	select {
	case u := <-p.urls:
		if q, err := url.Parse(u); err == nil {
			v := []string{q.Query().Get("state"), q.Query().Get("nonce"), q.Query().Get("code_challenge")}
			kc.know(v...)
			c.printed = append(c.printed, v...)
		}
		return u
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		return ""
	}
}

// wait waits up to 60s for the command to end, and is its outcome.
func (p *l56Cmd) wait(c *l56CLI, kc *keycloak, form bool) l56Run {
	waited := make(chan error, 1)
	go func() { <-p.done; waited <- p.cmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(60 * time.Second):
		_ = p.cmd.Process.Kill()
		<-waited
	}
	return c.finish(kc, l56Run{code: p.cmd.ProcessState.ExitCode(), stdout: p.stdout.String(),
		stderr: p.stderr.String(), form: form})
}

// signIn runs port49 with args, reads the address from its stderr, signs in
// as alice in the scripted browser, and lets Keycloak's redirect reach
// port49's listener on 127.0.0.1:18749.
func (c *l56CLI) signIn(t *testing.T, kc *keycloak, browser *http.Client, args ...string) l56Run {
	t.Helper()
	p := c.start(t, nil, args...)
	form := false
	if u := p.authURL(c, kc); u != "" {
		loc, shown := kc.answer(t, browser, u, oidcAlice, oidcAlicePassword)
		form = shown
		cb, err := (&http.Client{Timeout: 10 * time.Second}).Get(loc.String())
		if err != nil {
			t.Fatalf("the callback: %s", errCause(err))
		}
		cb.Body.Close()
	}
	return p.wait(c, kc, form)
}

// signInPasting is signIn at a terminal, the jump host's path (decision 43
// ruling 5): port49's stdin is a pty, and the address Keycloak sent the
// browser to is typed at port49's prompt, never sent to its listener. It
// also says whether that address carried iss and session_state.
func (c *l56CLI) signInPasting(t *testing.T, kc *keycloak, browser *http.Client, args ...string) (l56Run, string) {
	t.Helper()
	m, s := l56Pty(t)
	go func() { _, _ = io.Copy(io.Discard, m) }()
	p := c.start(t, s, args...)
	form, carried := false, "no address"
	if u := p.authURL(c, kc); u != "" {
		loc, shown := kc.answer(t, browser, u, oidcAlice, oidcAlicePassword)
		form = shown
		carried = fmt.Sprintf("the address pasted carries iss %v, session_state %v", loc.Query().Has("iss"),
			loc.Query().Has("session_state"))
		if _, err := io.WriteString(m, loc.String()+"\n"); err != nil {
			t.Fatalf("typing the address: %v", err)
		}
	}
	return p.wait(c, kc, form), carried
}

// answer is a person's browser on an address port49 printed: it signs in
// when Keycloak shows the form, and returns where Keycloak then sends the
// browser, port49's loopback address, unfollowed. It reports whether the
// form was shown.
func (k *keycloak) answer(t *testing.T, browser *http.Client, authURL, user, pass string) (*url.URL, bool) {
	t.Helper()
	resp, err := browser.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form := false
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			t.Fatalf("INVALID: the address port49 printed answered %s with no login form", resp.Status)
		}
		form = true
		if resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {user},
			"password": {pass}, "credentialId": {""}}); err != nil {
			t.Fatalf("login: %s", errCause(err))
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), "http://127.0.0.1:18749/callback") {
		t.Fatalf("INVALID: Keycloak did not send the browser to port49's listener (%s, %s)", resp.Status, locShape(loc))
	}
	k.know(loc.Query().Get("code"))
	return loc, form
}

// formWithoutPrompt is the control for "the password was asked": an
// authorization request in browser with no prompt=login, which Keycloak
// answers from the browser's SSO session, with no form. It reports whether
// the form was shown.
func (k *keycloak) formWithoutPrompt(t *testing.T, browser *http.Client) bool {
	t.Helper()
	resp, err := browser.Get(k.l55Authorize(t, kcRedirect, randomSecret(t)+randomSecret(t), url.Values{"prompt": nil}))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if loc, err := url.Parse(resp.Header.Get("Location")); err == nil {
		k.know(loc.Query().Get("code"))
	}
	return l55Accepted(resp.StatusCode, body)
}

// run runs port49 with args and no stdin, bounded at 60s: a command that
// tried to sign in here would wait for a browser no one drives.
func (c *l56CLI) run(t *testing.T, kc *keycloak, args ...string) l56Run {
	t.Helper()
	return c.start(t, nil, args...).wait(c, kc, false)
}

// token mints device and returns the token, registered as secret and as
// printed by design. That token is all the leak check exempts: anything
// else on stdout, and all of stderr, is checked as any output is.
func (c *l56CLI) token(kc *keycloak, device string) (string, l56Run) {
	cmd := exec.Command(c.bin, "token", "--socket", c.sock, device)
	cmd.Env = c.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	r := l56Run{code: cmd.ProcessState.ExitCode(), stdout: "[the token]"}
	tok := strings.TrimSpace(stdout.String())
	if r.code != 0 {
		tok, r.stdout = "", scrubbed(stdout.String(), kc.known())
	} else {
		kc.know(tok)
		c.printed = append(c.printed, tok)
	}
	r.leak = c.leak(kc, stdout.String()+"\n"+stderr.String())
	r.stderr = scrubbed(stderr.String(), kc.known())
	return tok, r
}

// stopAgent ends the agent listening on the socket, by its peer credentials.
func (c *l56CLI) stopAgent() {
	conn, err := net.Dial("unix", c.sock)
	if err != nil {
		return
	}
	var cred *syscall.Ucred
	if raw, err := conn.(*net.UnixConn).SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
	}
	conn.Close()
	if cred != nil && cred.Pid > 0 && int(cred.Pid) != os.Getpid() {
		_ = syscall.Kill(int(cred.Pid), syscall.SIGTERM)
	}
}

// stopAgentAndWait is stopAgent, then up to 5s for the socket to go: a
// reboot, as the next login meets it.
func (c *l56CLI) stopAgentAndWait(t *testing.T) {
	t.Helper()
	c.stopAgent()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(c.sock); errors.Is(err, fs.ErrNotExist) {
			return
		}
	}
	t.Fatal("INVALID: the agent did not stop within 5s")
}

func TestL56IssuedEndToEnd(t *testing.T) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sel {
		if p.name != "arista_eos" {
			continue
		}
		p := p
		t.Run(p.name, func(t *testing.T) { l56(t, labFor(t, p)) })
		return
	}
	t.Skip("PORT49_LAB_PLATFORMS does not select arista_eos")
}

// l56 is the claim measured on one device. A fault in the setup, or a
// control that does not hold, is INVALID and stops before the note, as the
// 7h end to end's (oidcEndToEnd). Every cell asserts what the claim says of
// it, through fail, and each assertion has a control that shows it can
// fail, noted beside the cell (I5, I6).
func l56(t *testing.T, l *lab) {
	var failed []string
	fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
	var obs strings.Builder
	cell := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }
	// ran is a CLI cell: its outcome, and a failure if its output leaked.
	ran := func(step string, r l56Run, extra string) {
		cell(step, r.cell()+extra)
		if r.leak != nil {
			fail("%s: the CLI's output: %v", step, r.leak)
		}
	}
	complete := false
	var kc *keycloak

	now := time.Now()
	idpCA, err := testpki.NewCA("port49 lab oidc l56 CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c := l.startComposeWith(t, composeOptions{Overlay: "oidc.yaml", Files: l56Files, Prepare: func(c *composeStack) error {
		brokerCA, err := os.ReadFile(filepath.Join(root, slicePKIDir, testpki.LabCA))
		if err != nil {
			return err
		}
		return oidcE2EPKI(filepath.Join(c.local, "oidc"), idpCA, brokerCA, time.Now())
	}})
	stop := l.capture(t, "L56")
	defer stop()
	var cli *l56CLI
	defer func() {
		if !complete {
			if len(failed) > 0 {
				t.Errorf("L56, before it stopped: %s", strings.Join(failed, "; "))
			}
			return
		}
		note := "The CLI reaches Keycloak through a CONNECT proxy in the test (`l56Proxy`), since this host does " +
			"not resolve keycloak.port49.lab; that is lab plumbing, not part of the claim. The CLI's raw output " +
			"is checked for a compact JWS or any value the run registered as secret (the issued key's included) " +
			"before it is scrubbed for this note; the authorization URL's state, nonce and code_challenge, and " +
			"each device token on `port49 token`'s stdout, are exempt, being printed by design.\n\n" +
			"| step | observed |\n|---|---|\n" + obs.String()
		cli.knowKey(t, kc)
		if err := leakIn(cli.agentLog(), kc.known()); err != nil {
			failed = append(failed, "the agent's log: "+err.Error())
		}
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		if err := oidcNoteLeak(note, kc.known()); err != nil {
			t.Errorf("the L56 note is not written: %v", err)
			return
		}
		l.result(t, "L56", l56Claim, note)
		if len(failed) > 0 {
			t.Errorf("L56: %s", strings.Join(failed, "; "))
		}
	}()

	kc = &keycloak{URL: "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm, ca: idpCA, HTTP: keycloakClient(idpCA)}
	kc.know(labSecrets...)
	kc.adminFromEnv(t, filepath.Join(c.local, "oidc", "admin.env"))
	kc.know(kc.admin)
	waitDiscovery(t, kc, 3*time.Minute)
	kc.SetLogoutURL(t, oidcBrokerLogout)
	br := oidcBroker{c: brokerClient(t), kc: kc, base: sliceBrokerURL}
	// The broker takes Keycloak's tokens once its key fetch and start gate
	// allow. A machine's token shows it: issuance leaves the machine path as
	// it was (decision 43 ruling 13). A fault here is setup, not the claim.
	svc := kc.ServiceToken(t)
	kc.know(svc)
	ready := func(what string) {
		if tok, said := br.mintRetry(t, svc, l.p.node, 3*time.Minute); tok == "" {
			t.Fatalf("INVALID: the broker never took a Keycloak token %s: %s", what, said)
		}
	}
	ready("at the start")
	cli = newL56CLI(t, l56Proxy(t), filepath.Join(c.local, "oidc", "idp-ca.pem"))
	browser := keycloakClient(idpCA)
	browser.Jar, _ = cookiejar.New(nil)
	login := append([]string{"login"}, cli.flags...)

	// 0. No issuing CA yet: the broker started, says what to run, and answers
	// a sign-in's exchange 503. Control: 1, the same login once the CA is made.
	r := cli.signIn(t, kc, browser, login...)
	ran("0a. port49 login --oidc, the broker with no issuing CA", r, "")
	if r.code != 1 || !strings.Contains(r.stderr, "issuance_unavailable") {
		fail("with no issuing CA: %s", r.cell())
	}
	logs, _ := c.run("logs", "port49-broker")
	said := strings.Contains(logs, "issuing-ca.pem is missing") && strings.Contains(logs, "init-issuer")
	cell("0b. the broker's start names the missing CA and init-issuer", fmt.Sprint(said))
	if !said {
		fail("the broker's start did not say the CA is missing and to run init-issuer")
	}
	out, err := c.run("run", "--rm", "--no-deps", "port49-broker", "init-issuer")
	if err != nil || !strings.Contains(out, "created the issuing CA") {
		t.Fatalf("INVALID: port49-broker init-issuer: %v: %s", err, oneLineMax(out, 400))
	}
	cell("0c. port49-broker init-issuer", oneLineMax(out, 300))
	if _, err := c.run("restart", "port49-broker"); err != nil {
		t.Fatalf("INVALID: restarting the broker: %v", err)
	}
	ready("after the restart")

	// 1. Login. Control for "password asked": with the SSO session it
	// leaves, a request with no prompt=login is answered with no form.
	r = cli.signIn(t, kc, browser, login...)
	before := cli.knowKey(t, kc)
	ran("1. port49 login --oidc --no-browser, a scripted browser", r, fmt.Sprintf("; password asked %v", r.form))
	if r.code != 0 {
		t.Fatalf("INVALID: the login failed: %s", r.cell())
	}
	if !r.form || !strings.Contains(r.stdout, " as "+e2eAlice+"; your certificate from ") ||
		!strings.Contains(r.stdout, "refreshed at") || !strings.Contains(r.stderr, "  https://") {
		fail("the login: password asked %v; %s", r.form, r.cell())
	}
	certPath, keyPath := cli.issued(t)
	for _, p := range []string{certPath, keyPath} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			fail("%s is not 0600: %v %v", p, fi, err)
		}
	}
	if kc.formWithoutPrompt(t, browser) {
		t.Fatal("INVALID: Keycloak showed the form to a request with no prompt=login inside the SSO session, so " +
			"\"password asked\" cannot tell prompt=login was honoured")
	}
	cell("1c. control: no prompt=login in the same browser", "no form shown")

	// 2. A token, and the device takes it. Control for the leak check: the
	// token's own stdout holds a registered value, and leakIn says so.
	// Control for "permitted": a token port49 did not mint is refused.
	tok, tr := cli.token(kc, l.p.node)
	ran("2a. port49 token", tr, "")
	if tok == "" {
		t.Fatalf("INVALID: the first token: %s", tr.cell())
	}
	if leakIn(tok+"\n", kc.known()) == nil {
		t.Fatal("INVALID: the leak check does not see a value the run registered")
	}
	sh, err := l.shell(oidcAlice, tok)
	if err != nil {
		t.Fatalf("INVALID: SSH with the token: %v", err)
	}
	res := l.runPermitted(sh, "show version", 20*time.Second)
	sh.Close()
	cell("2b. SSH as alice with it, `show version`", res.cell)
	if !res.permitted {
		fail("the device did not run `show version` with the minted token: %s", res.cell)
	}
	if bad, err := l.shell(oidcAlice, (randomSecret(t) + randomSecret(t))[:30]); err == nil {
		bad.Close()
		t.Fatal("INVALID: the device took a token port49 never minted, so 2b cannot tell")
	}
	cell("2c. control: SSH as alice with a token port49 never minted", "refused")

	// 3. A refresh by the key: no browser, no address printed. Control: 1,
	// whose sign-in printed the address.
	time.Sleep(11 * time.Second) // past the connection's refresh pacing
	r = cli.run(t, kc, "refresh", "--socket", cli.sock)
	ran("3. port49 refresh, no browser", r, "")
	if r.code != 0 || !strings.Contains(r.stdout, "extended to") || strings.Contains(r.stderr, "https://") {
		fail("the refresh: %s", r.cell())
	}

	// 4. A reboot: the agent stopped, a login over the held certificate signs
	// in no more and extends the device session (D1); then a --sign-in at a
	// terminal, the address pasted, issues a new certificate.
	cli.stopAgentAndWait(t)
	r = cli.run(t, kc, login...)
	ran("4a. port49 login after the agent stopped", r, "")
	if r.code != 0 || !strings.Contains(r.stdout, "using your certificate for "+e2eAlice) ||
		!strings.Contains(r.stdout, "extended to") || strings.Contains(r.stderr, "https://") {
		fail("a new agent over the held certificate: %s", r.cell())
	}
	cli.stopAgentAndWait(t)
	r, carried := cli.signInPasting(t, kc, browser, append([]string{"login", "--sign-in"}, cli.flags...)...)
	after := cli.knowKey(t, kc)
	ran("4b. port49 login --sign-in at a terminal, the address pasted", r, fmt.Sprintf("; password asked %v; %s; "+
		"a new certificate %v", r.form, carried, after != before))
	if r.code != 0 || !r.form || !strings.Contains(r.stderr, "paste it here (it is not shown)") || after == before {
		fail("the pasted sign-in: %s, password asked %v", r.cell(), r.form)
	}

	// 5. An administrator's sign-out: the certificate's next mint is refused
	// in the broker's logout words (its sid recorded against it), the agent
	// ends, a login over the certificate removes it, and a sign-in from the
	// time the broker names works. Control for 5a: 2a, a mint on the same
	// certificate before.
	signedOut := time.Now()
	kc.LogoutUser(t, kc.UserID(t, oidcAlice))
	ended := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if _, tr = cli.token(kc, l.p.node); tr.code != 0 {
			ended = strings.Contains(tr.stderr, "back-channel logout")
			break
		}
	}
	ran("5a. port49 token after an administrator's sign-out, polled up to 10s", tr, "")
	if !ended {
		fail("after the sign-out, no refusal in the broker's logout words: %s", tr.cell())
	}
	var gone l56Run
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if gone = cli.run(t, kc, "identity", "--socket", cli.sock); strings.Contains(gone.stderr, "no agent") {
			break
		}
	}
	ran("5b. the agent after it", gone, "")
	if gone.code == 0 || !strings.Contains(gone.stderr, "no agent") {
		fail("the agent still answers after the sign-out: %s", gone.cell())
	}
	r = cli.run(t, kc, login...)
	ran("5c. port49 login over the logged-out certificate", r, "")
	if _, err := os.Stat(certPath); r.code != 1 || !strings.Contains(r.stderr, "it is removed") ||
		!errors.Is(err, fs.ErrNotExist) {
		fail("a login over the logged-out certificate: %s; the certificate still there %v", r.cell(), err == nil)
	}
	from, named := l56LoginFrom(tr.stderr)
	waited := "the time the broker named"
	if !named {
		from, waited = loginAgainAt(signedOut), "clock_skew after the sign-out"
	}
	time.Sleep(time.Until(from) + time.Second)
	browser.Jar, _ = cookiejar.New(nil) // the sign-out ended the browser's SSO session too
	r = cli.signIn(t, kc, browser, login...)
	cli.knowKey(t, kc)
	ran("5d. port49 login again, from "+waited, r, "")
	if r.code != 0 {
		t.Fatalf("INVALID: the sign-in after the sign-out failed, so step 6 has no session: %s", r.cell())
	}

	// 6. Keycloak stopped: everyone holding a certificate keeps working.
	if _, err := c.run("stop", "keycloak"); err != nil {
		t.Fatalf("INVALID: stopping Keycloak: %v", err)
	}
	tok, tr = cli.token(kc, l.p.node)
	ran("6a. port49 token, Keycloak stopped", tr, "")
	if tok == "" {
		fail("a mint with Keycloak stopped: %s", tr.cell())
	}
	time.Sleep(11 * time.Second)
	r = cli.run(t, kc, "refresh", "--socket", cli.sock)
	ran("6b. port49 refresh, Keycloak stopped", r, "")
	if r.code != 0 || !strings.Contains(r.stdout, "extended to") {
		fail("a refresh with Keycloak stopped: %s", r.cell())
	}
	cli.stopAgentAndWait(t)
	r = cli.run(t, kc, login...)
	ran("6c. port49 login after the agent stopped, Keycloak stopped", r, "")
	if tok, tr = cli.token(kc, l.p.node); r.code != 0 || tok == "" {
		fail("a new agent with Keycloak stopped: %s; then %s", r.cell(), tr.cell())
	}
	cli.stopAgentAndWait(t)
	r = cli.run(t, kc, append([]string{"login", "--sign-in"}, cli.flags...)...)
	ran("6d. port49 login --sign-in, Keycloak stopped", r, "")
	if r.code != 1 || !strings.Contains(r.stderr, "did not answer") ||
		!strings.Contains(r.stderr, "without --sign-in uses it") {
		fail("a sign-in with Keycloak stopped: %s", r.cell())
	}
	if _, err := c.run("start", "keycloak"); err != nil {
		t.Fatalf("INVALID: starting Keycloak: %v", err)
	}
	waitDiscovery(t, kc, 3*time.Minute)
	complete = true
}
```

`l.shell`, `l.runPermitted` and `res.cell` (and `res.permitted`) are the harness's
(`l29_shell_test.go`, `directory_e2e_test.go`), as is `e2eAlice` (`user:alice@corp.example.com`, the
e2e broker's principal for alice). `loginAgainAt` is `oidc_e2e_test.go`'s; `l55Authorize` and
`l55Accepted` are L55's, in the same package. `c.run` is the compose stack's `docker compose` with
its overlays, so `logs port49-broker`, `run --rm --no-deps port49-broker init-issuer` (the image's
entrypoint is `port49-broker`, its user the broker's, its state volume the broker's), `restart
port49-broker`, and `stop|start keycloak` act on the stack's own services.

- [ ] **Step 5: The unit tests pass**

Run: `go test -tags lab ./tests/lab/ -run 'TestL56AuthURL|TestL56LoginFrom|TestL55Accepted|TestL56Files|TestL56Leak' -count=1 && make lab-unit`
Expected: PASS.

- [ ] **Step 6: The targets and the README**

In `Makefile`, add `lab-oidc-l55 lab-oidc-agent` to `.PHONY`, and after `lab-oidc`:

```make
# L55 (plan 9b): Keycloak as port49's OIDC public client meets it. Needs
# Docker with Compose v2.24.4+; a few minutes. lab-oidc re-measures the closed
# L45 and L46; this runs L55 alone.
lab-oidc-l55:
	go test -tags lab ./tests/lab/ -run 'TestL55' -count=1 -v -timeout 30m

# L56 (plan 9b): port49-issued certificates end to end, bin/port49 against
# the compose stack's Keycloak, broker and vEOS. Needs the compose stack,
# containerlab, the EOS image and `make build`.
lab-oidc-agent:
	PORT49_LAB_PLATFORMS=arista_eos go test -tags lab ./tests/lab/ -run 'TestL56' -count=1 -v -timeout 60m
```

In `tests/lab/README.md`, after the identity-provider section, add a section "OIDC sign-in and
issued certificates (plan 9b): L55 and L56" saying, in the README's style:
- `make lab-oidc-l55` measures L55 on the standalone Keycloak. It changes `port49-cli`'s redirect
  URIs for the run and puts them back. Cell 4b keeps one browser's SSO session across three
  sign-ins, 15s apart, to see whether `prompt=login` authenticates again.
- `make build && make lab-oidc-agent` measures L56: `bin/port49 login --oidc --no-browser` on the
  compose stack, a scripted browser signing in from the address port49 prints.
- L56 starts the broker with `broker.identity.issuance` and no issuing CA, checks what it says, then
  runs `docker compose run --rm --no-deps port49-broker init-issuer` and restarts the broker.
- The CLI reaches `keycloak.port49.lab` through a CONNECT proxy the test runs on loopback
  (`HTTPS_PROXY`), since the host does not resolve that name. port49 never sends the broker through
  a proxy.
- L56 step 4b runs `port49 login --sign-in` with a pty for stdin and types the address Keycloak sent
  the browser to, as a person on a jump host pastes it.
- Every CLI command's raw output is checked for a compact JWS or a registered secret (the issued
  key's PEM included, read once the command has ended, so a run is checked against the key it
  wrote) before it is scrubbed for the note, and a leak fails the run. Only what port49 prints by
  design is exempt. The PKCE verifier port49 draws is never seen by the lab; the unit tests check
  it.
- Each L56 cell asserts, and each assertion has a control that shows it can fail. A control that
  does not hold is INVALID, and no note is written.
- Keycloak is stopped and started by `docker compose stop|start keycloak`.

- [ ] **Step 7: Run L55, then L56**

Run: `make build && make lab-oidc-l55`
Expected: PASS; `tests/lab/results/L55-keycloak.md` and `tests/lab/evidence/L55-keycloak.json`
written. Read the note. If a step shows a setup fault (INVALID), fix the harness and run again;
never record it.

Run: `make lab-oidc-agent` (with the SER8's lab up, as `make lab-oidc`'s end to end needs). Run a
background stall watchdog while it runs (memory: lab run watchdog).
Expected: PASS; `tests/lab/results/L56-arista_eos.md` written; `make evidence` writes the
redacted capture.

- [ ] **Step 8: Close the rows, and fix what the results contradict**

For each row, follow CLAUDE.md's rule 3. The row's Status becomes `closed — measured <date>;
tests/lab/results/L55-keycloak.md` (L56: `tests/lab/results/L56-arista_eos.md`), with the
observation in one paragraph as L45's and L46's rows carry it. A cell the claim's code got wrong is
not closed over: fix the code on this branch first, re-run, and close on the run that passed.

Then rule 4: if a result contradicts a doc, the doc is wrong.
- **Decision 43's preamble and rulings 4 and 8.** Replace "provisional on L55 (Keycloak) and L47"
  with "measured on Keycloak, L55 closed; provisional on L47".
- **Ruling 4.** State which redirect registration Keycloak admitted for an ephemeral port. If none
  did, say Keycloak needs a fixed port and `oidc_redirect_port`; the client's ephemeral default
  stands, from RFC 8252.
- **Ruling 8.** If L55 cell 4 shows Keycloak does not echo the nonce byte for byte, or its
  `auth_time` is not the sign-in's under `prompt=login`, or cell 4b shows a `prompt=login` over a
  live SSO session that does not move `auth_time` on (its controls hold, or the run is INVALID:
  the fresh browser was shown the form, and the session with no `prompt` was not and kept the
  first `auth_time`), the key binding or the freshness check does not hold there: stop, and
  take it to Ryan before closing anything. A cell 4 or 4b exchange with no `id_token` is INVALID,
  never recorded.
- **This plan's operator notes**, which Task 13 copies: replace each italic line with what was
  measured.

Commit the harness and the notes first, and make the spec edits after that commit, so the second
commit holds them alone, as CLAUDE.md asks:

```bash
git add tests/lab/ Makefile
git commit -m "test(lab): L55 and L56, the OIDC sign-in and port49-issued certificates on Keycloak and vEOS"
# now edit §15's two Status cells and decision 43 as above
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L55 and L56"
```

A code fix the run called for is its own `fix(...)` commit before the first, with its test.

---

### Task 13: The roadmap's as-built entry

**Files:**
- Modify: `docs/superpowers/plans/README.md` ("Plan 9" and the status paragraph)

- [ ] **Step 1: Write the as-built entry**

Under `## Plan 9 — Agent in full (§19 step 9)`, after `### Plan 9a — As built` and its body, add
`### Plan 9b — As built`. Its body is three short bullet lists, as 9a's is:
- **Built:** the commits, the test count from `make test`, and L55's and L56's status.
- **Carried:** to 9c, 9e, plan 12, plan 13 or the pre-beta review, each with its reason. At least
  these:
  - **9c:** the issued key into the TPM, the Secure Enclave or a token, behind the same
    `crypto.Signer`; `per_login_mfa`.
  - **9d:** the pins file leaves `userconfig.LegacyDir` with `port49 devices trust`; `LegacyDir`
    then serves the refusal of plan 9a's config file alone.
  - **9d:** `port49 ssh` and `devices trust` are refused with no fix on a host whose `~/.config` is
    group-writable (pre-flight 2 m5): 9d must fix it, which removing the pins file does. The
    roadmap's 9d entry carries it already; the PR body lists it under known limitations.
  - **Plan 12:** each deployment shape's client package ships `/etc/port49/config.yaml` and the
    broker CA beside it, root-owned (decision 43 ruling 24).
  - **Plan 12:** a check that every broker on one store holds the same issuing CA (each start prints
    its fingerprint today); the issuing CA's files in each deployment shape's state volume, and
    `init-issuer` in each shape's setup.
  - **Plan 12: the issuing CA's custody at broker scale** (pre-flight 2 m7). `init-issuer` and
    `rotate-issuer` mean copying CA files to each broker by hand, three restart rounds per
    rotation: fine for 2–5 brokers once in five years. A Kubernetes Secret mounted read-only makes
    `rotate-issuer`'s writes fail, so that shape needs its own rotation (a new Secret per round).
    Keeping the CA in the shared store, sealed by `internal/store/crypt`, is the option that
    removes the copying: plan 12 weighs it against the key leaving the broker's disk for the
    store.
  - **Pre-beta review:** retiring plan 7h's bearer path for people (Q1), and its harness
    (`make lab-oidc`) rebuilt on issuance.
  - **Plan 13:** this plan's operator notes as the lab corrected them.
  - **L47:** stays unassigned.
- **Operator-facing notes:** this plan's "Operator notes" section, corrected to what L55 and L56
  measured, with no line left in italics.

In the status paragraph, after the sentence that says 9b is written, add the date 9b executed, its
branch (`feature/oidc-public-client`) and its base.

- [ ] **Step 2: Verify the branch and commit**

Run: `make test && make vet`
Expected: PASS, and `gofmt -l .` lists nothing.

Run: `make test-race`
Expected: PASS.

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: roadmap, plan 9b as built"
```
