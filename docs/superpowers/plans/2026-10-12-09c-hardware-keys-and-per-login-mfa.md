# Plan 9c: Hardware-Backed Client Keys, `per_login_mfa`, and the Broker Certificate's CRL Check — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The operator's key moves into hardware (a PKCS#11 token such as a YubiKey's PIV applet,
a TPM 2.0, and the macOS Secure Enclave if its spike allows) behind the one `crypto.Signer` the
agent already holds; the key `port49 login --oidc` generates goes there too. A policy can ask for
a second factor at each login to the devices it marks (`per_login_mfa`), proved by a touch on an
attested always-touch slot or by a fresh identity-provider sign-in with MFA. The agent checks the
broker certificate against the CRL it names. The key unplugged mid-session never ends the session.

**Branch:** `feature/hardware-keys-and-per-login-mfa`. Base: `main` at `d80795e` (plan 9b1 merged).

**What changes, in one screen:**
- **Keys** (`internal/hwkey`). `key:` (and `--key`) takes a path, as today, or a key reference:
  `pkcs11:` (RFC 7512), `tpm:` (a TSS2 key file or a persistent handle), `secure-enclave:` (gated on
  Task 2). `hwkey.Open` returns a `hwkey.Key`, a `crypto.Signer` with `State`, `Unlock` and `Close`,
  which goes into `agent.Config.Cert.PrivateKey` unchanged; `api.SignRefresh` takes it unchanged.
  PKCS#11 through `github.com/ebitengine/purego` v0.11.1, TPM through `github.com/google/go-tpm`
  v0.9.8, no cgo. A PIN is asked once by `port49 login` on the terminal and handed to the agent on a
  descriptor; it is never in argv, the environment or a log.
- **Issued keys** (`port49 login --oidc`). `issued_key_store: auto` (the default) generates the key
  in the TPM on Linux, the Secure Enclave on macOS (if Task 14 lands), else the 0600 file, and says
  which. `tpm`, `secure_enclave`, `pkcs11` and `file` name one; a named store that cannot be used
  refuses before the browser opens.
- **The 3am unplug.** The held connection keeps minting. `port49 refresh` and a reconnect say
  "insert your key", never end the session; `port49 login` with the agent running asks the PIN and
  unlocks it.
- **`per_login_mfa`** (spec §5.1.5, new; decision 45). Four levels: `defaults:`, a role, a scope
  that selects by an attribute (a device class or tag), and a scope that selects by `name` (one
  device). The strictest wins: the intersection of `accept`, the least `reuse_for`. Machines are
  exempt unless a level says `applies_to_machines: true`. An empty intersection refuses the policy
  at load, naming both levels.
- **The proof.** A mint item under an unmet requirement is answered `deny per_login_mfa_required`
  with a challenge. The proof goes to `POST /v1/mfa`: a touch-slot signature over the challenge and
  the held connection's exporter value, with the token's PIV attestation, or an ID token from a
  fresh sign-in whose `nonce` binds the challenge and whose `amr` shows MFA. The retried mint names
  the challenge. One proof covers further logins under the same requirement for `reuse_for`, bound
  to the principal, the certificate and the agent's session.
- **Held sessions.** A requirement gates logins and the session refresh, never a live session: a
  reload that adds one revokes nothing. A refresh extends a context under a requirement only with a
  proof that covers it; otherwise that context is answered `per_login_mfa_required` and runs to the
  ceiling it holds. `port49 refresh` gathers one proof and refreshes again.
- **The broker certificate's CRL check** (`internal/brokercrl`, over `internal/certstatus`).
  `broker_crl: check` (default): a revoked broker certificate is refused; a list that cannot be had
  is said once and the login goes on. `require` refuses that too; `off` checks nothing.
- **CI:** SoftHSM2 and swtpm under `make test-hw` and a new workflow `hwkeys`, built with
  `CGO_ENABLED=0`.
- **Lab:** L60 (YubiKey on the SER8; Ryan present), L61 (Keycloak's `amr` for `idp_mfa`), L62 (the
  SER8's own TPM), L63 (the Secure Enclave from an unsigned binary; Task 2).

**Architecture:**
- `internal/hwkey`: `Key`, `State`, `Open`, `IsRef`, `LoadPair`, errors. Subpackages
  `pkcs11` (purego binding, RFC 7512 URI, signer, generation), `tpm` (go-tpm signer, TSS2 key
  file, generation), `secureenclave` (darwin, gated).
- `internal/pivattest`: YubiKey PIV attestation, verified against the operator's roots.
- `internal/brokercrl`: the client's check of the broker chain, over `certstatus.Checker`.
- `internal/policy`: `PerLoginMFA`, `MFARequirement`, `Resolution.PerLoginMFA`, `defaults:`,
  `roles[].per_login_mfa`, `scopes[].per_login_mfa`; explain, `policy test`, `policy diff`.
- `internal/store`: `Credential.MFAMethod`, `Credential.MFAAt`; `MFAProof`, `PutMFAProof`,
  `GetMFAProof` in every backend.
- `internal/broker`: `mfa.go` (challenge, cover, `POST /v1/mfa`), the mint and the session refresh
  under a requirement; `internal/config` reads `broker.identity.per_login_mfa`.
- `internal/agent`: the agent session header, `ProveTouch`, `Unlock`, `KeyAbsentError`, socket
  `POST /mfa/touch` and `POST /unlock`, `Status.KeyState`.
- `cmd/port49`: key references and PINs in `login` and the agent child, `mfa.go` (prompting and
  proving for `token`, `ssh`, `refresh`), `--broker-crl`, `issued_key_store`.

**Tech Stack:** Go 1.26, module `github.com/rhwendt/port49`, `CGO_ENABLED=0`. New modules:
`github.com/ebitengine/purego` v0.11.1 and `github.com/google/go-tpm` v0.9.8 (both in the module
cache, checked 2026-10-09 by decision 42 ruling 13 and again 2026-10-12 while writing this plan:
go-tpm's `tpm2/transport/tcp` and `tpm2/transport/linuxtpm` import no cgo; purego lists Linux and
macOS amd64/arm64 as Tier 1 without cgo). CI: SoftHSM2 2.6 and swtpm 0.8 from Ubuntu 24.04.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`: §5.1.4 (the credential block), a new §5.1.5
  (per-login MFA), §5.7 (an event, four reasons, the mint and refresh rows), §12 (explain, `policy
  test`, `policy diff`), §13 (new decision 45; decision 43 ruling 13 amended), §14, §15 (L60–L63).
- `docs/design/2026-08-21-port49-design.md` §7 ("The paths differ in what the agent holds"; the
  PIV touch policy is the operator's) and §19 step 9.
- The roadmap `docs/superpowers/plans/README.md`, "Plan 9", the 9c entry; "Plan 9b — As built" and
  "Plan 9b1 — As built". House style: plan 9b1. Written against `main` at `d80795e`.

**Prerequisite:** plan 9b1 merged (`main` at `d80795e`).

## Owner's rulings this plan carries

1. **Hardware-backed client keys** (plan 3, owner's rulings 2026-09-24): YubiKey through its PIV
   applet over PKCS#11, and platform keystores (TPM, macOS Secure Enclave), with touch and PIN
   policy. FIDO2 alone cannot sign a TLS handshake. Plan 3's PEM file stays as the fallback.
2. **The broker certificate's CRL check** (plan 3, 2026-09-24): optional, when the certificate names
   a distribution point; defence in depth, since the CA is the operator's.
3. **Routes without cgo** (decision 42 ruling 13, pre-flight Q2 of plan 9a): PKCS#11 through
   purego, TPM through go-tpm, CI against SoftHSM2 and swtpm over the MS-simulator protocol, the
   Secure Enclave behind a spike on a macOS host. A route the spike or the measurement rules out is
   dropped only by Ryan.
4. **`per_login_mfa`** (Ryan, 2026-10-10, roadmap 9c entry): a proof at each login to a matching
   device, never called `mfa: required`; `accept` an explicit list of self-describing methods
   (`hardware_key_touch`, `idp_mfa`) with no booleans and no `none`; `reuse_for` default 15m, `0m`
   a proof at every login; bound to the principal and the agent's session; four levels; the
   strictest wins as an intersection; a lower level never weakens a higher; an empty intersection
   is a load error naming both levels; machines exempt unless `applies_to_machines: true`; a refusal
   or prompt names the device, the level and the methods; `port49 explain` and the policy tooling
   print the effective requirement and where each part came from.
5. **The 3am unplug** (roadmap): the held connection still mints; `port49 refresh` and a reconnect
   say "insert your key" and never end the session.
6. **Standing rules:** follow the spec; no feature cut; no per-user toil at fleet scale; security
   first; data is snake_case.

## Rulings this plan makes (recorded as decision 45 in Task 1)

Under the standing grant (security first, keep moving), each on reasoning unless it says data.

- **R1. One signer.** Every backend returns a `hwkey.Key`: `crypto.Signer` plus `State() State`,
  `Unlock(pin []byte) error` and `Close() error`. It is `agent.Config.Cert.PrivateKey`;
  `api.SignRefresh`, the TLS handshake and the per-login proof take it as a `crypto.Signer`. The
  file key stays `keyfile`'s, wrapped in nothing.
- **R2. Key references.** `key:` (`--key`) is a path, or a reference: `pkcs11:` in RFC 7512's form
  (path attributes `token`, `manufacturer`, `serial`, `model`, `object`, `type`, `id`, `slot-id`;
  query attributes `module-path` and `pin-source`), `tpm:file=PATH` (a TSS2 key file) or
  `tpm:handle=0x81xxxxxx` (a persistent handle), `secure-enclave:label=NAME` (Task 14). `pin-value`
  is refused: a PIN does not live in a config file. `pin-source=file:///path` is read through
  `keyfile.ReadSecret` (owner-only). A `pkcs11:` key with no `cert:` takes the certificate object
  with the key's `CKA_ID`, so a fleet's system file names `key: "pkcs11:id=%01?module-path=…"` once
  and no user writes anything. A reference that matches objects on two tokens is refused, naming
  both, never resolved to the first.
- **R3. The module.** The `module-path` must be absolute, a regular file, and owned by root or the
  user, with it and every directory above it not writable by group or others (userconfig's
  ownership walk): it is code the agent runs. One module per process, `C_Initialize` with
  `CKF_OS_LOCKING_OK` and no mutex callbacks, so the module never calls into Go. Memory the module
  sees is heap-allocated and pinned with `runtime.Pinner` for the call.
- **R4. The PIN.** Asked by `port49 login` on the terminal only when the token says
  `CKF_LOGIN_REQUIRED`, with echo off; handed to the agent on descriptor 4 (`--pin-fd 4`), as the
  broker CA is on 3; dropped (zeroed) after `C_Login`. One `C_Login` per PIN given: a refused PIN
  is never retried by port49, and the refusal says when the token reports
  `CKF_USER_PIN_COUNT_LOW` or `CKF_USER_PIN_FINAL_TRY` ("one try left before the key locks"). No
  terminal and no `pin-source`: the login refuses, naming `pin-source`.
- **R5. TPM 2.0.** `/dev/tpmrm0` (the kernel's resource manager), never `/dev/tpm0`. Keys are ECC
  P-256 signing keys under the TCG reference ECC SRK (`tpm2.ECCSRKTemplate`, created in the owner
  hierarchy at each open, so no persistent handle is needed), with empty auth, kept as a TSS2
  `PRIVATE KEY` PEM file (the "ASN.1 Specification for TPM 2.0 Key Files" form the OpenSSL tpm2
  provider and tpm2-tools write), 0600. The file is useless on another machine. Linux only; a
  user outside the `tss` group is told so in one line naming the group.
- **R6. The Secure Enclave** is built only if Task 2's spike shows an unsigned `port49` can create
  and find again a Secure Enclave key (gate SE1). Otherwise macOS is served through PKCS#11 (a
  YubiKey) and the choice goes back to Ryan (decision 42 ruling 13); L63 stays open.
- **R7. Issued keys in hardware.** `issued_key_store` in `config.yaml`: `auto` (the default), `tpm`,
  `secure_enclave`, `pkcs11` (with `issued_key: "pkcs11:…;id=…"` naming the object) or `file`.
  `auto` is the TPM on Linux where a key can be created there, the Secure Enclave on macOS once
  Task 14 lands, else the file; the login says which in one line. A named store that cannot be
  used refuses before any browser opens, as decision 43 ruling 18 refuses an issuance it cannot
  make. A `pkcs11` store never overwrites an object whose certificate port49 did not issue. The
  TPM key is `~/.port49/issued/<host>_<port>.tpmkey` beside the `.pem`; a held pair is found by
  either key file.
- **R8. The key unplugged.** A signing error the backend reads as the key gone (PKCS#11
  `CKR_DEVICE_REMOVED`, `CKR_TOKEN_NOT_PRESENT`, `CKR_SESSION_HANDLE_INVALID`, `CKR_DEVICE_ERROR`;
  a TPM transport error) is `hwkey.ErrKeyAbsent` and the key's state `Absent`. The agent never
  ends a session on it. `crypto/tls` flattens a signer's error into text
  (`handshake_client_tls13.go:797`, Go 1.26), so the agent reads the key's state after a failed
  dial, not the error. `port49 refresh` and `port49 token` on a dropped connection say "insert your
  key …; your session goes on until <end>". At the next use the backend re-opens the token; one that
  needs its PIN is `Locked`, and `port49 login` with the agent running asks the PIN and unlocks it
  over the agent's socket (`POST /unlock`), then refreshes.
- **R9. The broker certificate's CRL.** `broker_crl` in `config.yaml` (`--broker-crl`): `check`
  (the default), `require`, `off`. Each certificate of the verified chain but the root is checked
  against the lists its `http`/`https` distribution points name, through `certstatus.Checker`
  (verified against the issuer, the IDP scope rules, kept in `~/.port49/crl/`). A list naming a
  serial refuses the connection under `check` and `require` before any request, a bearer ID token
  included. A list that cannot be had: under `check` it is said once per process and the login goes
  on; under `require` it is refused. A certificate naming no usable distribution point is not
  checked and nothing is said. Login's own TLS connections (`/v1/config`, `/v1/certificate`,
  `/v1/mfa`), the agent's and `port49 workload`'s all check.
- **R10. Schema.** `per_login_mfa: {accept: [...], reuse_for: 15m, applies_to_machines: false}`
  under `defaults:` (new top-level key), a role, or a scope. `accept` is required, non-empty, each
  of `hardware_key_touch` and `idp_mfa` at most once. `reuse_for` 0s to 8h, default 15m.
  `applies_to_machines` default false, spelled out to be true. Unknown keys refused. The roadmap's
  "device class or tag" and "one device" levels are scopes: one matching attributes, one matching
  `name`. The policy has one way to select devices, and a second would be a second place to look at
  3am. A requirement never lives in the inventory record: a source-of-truth editor could remove it.
- **R11. The strictest wins.** The levels that apply on a device: `defaults`, each role that
  composes there (granted or attached), each scope that selects the device. For a machine, only
  those with `applies_to_machines: true`. Effective `accept` is their intersection, `reuse_for`
  their minimum, each part naming its level. Every subject on every device is checked at load, as
  the joint check is (§10). An empty intersection refuses the policy: "per_login_mfa: scope core
  accepts [hardware_key_touch] and role netadmin accepts [idp_mfa] on core-sw01; no method meets
  both". A machine-applying level whose accept leaves only `idp_mfa` for a machine is refused too
  (a machine has no sign-in). A scope with a match key that carries `per_login_mfa` must declare
  `on_missing` (a restriction, read as a deny is, spec §5.5) and `security_log: true` (whoever edits
  the attribute lifts the requirement, and the log must say so).
- **R12. `hardware_key_touch`** is a signature by the touch key over the challenge and the held
  connection's TLS exporter value (`EXPORTER-port49-per-login-mfa`), with that key's YubiKey PIV
  attestation, the token's attestation certificate (slot f9), and the session key's attestation.
  The broker verifies: the f9 certificate to `broker.identity.per_login_mfa.hardware_key_touch.
  attestation_roots_file`; each slot attestation's signature by f9 (checked directly, since some
  f9 certificates carry no basic constraints: go-piv v2.6.0 `piv/key.go:241-247` documents and
  works around it); the touch attestation's key is the signing key and its touch policy byte is
  `0x02` (always; OID 1.3.6.1.4.1.41482.3.8); the session attestation's key is the connection's
  client certificate key. So the touch is on the token that holds the session key, and an attacker
  holding a copied session key cannot prove with a token of their own. A TPM, Secure Enclave,
  file or imported key cannot satisfy it: none carries an attested presence. `touch_key:` in
  `config.yaml` names the touch slot (`pkcs11:id=%02?module-path=…`), one line in the system file.
- **R13. `idp_mfa`** is an ID token from a sign-in run by the CLI as `port49 login --oidc` runs it
  (PKCE, `prompt=login`, the loopback redirect, the pasted address), with `nonce` =
  `base64url(SHA-256("port49 per-login v1\0" ‖ challenge))` and the configured `acr_values` when
  set. The broker verifies it as decision 39 verifies a human ID token, and then: the principal it
  maps to is the challenge's; `auth_time` within 5 minutes plus `clock_skew` of its `iat` and of
  now; `amr` holds one of `broker.identity.per_login_mfa.idp_mfa.amr` (default `[mfa]`, RFC 8176);
  the token unspent (its SHA-256 kept `max_token_age`). Provisional on L61 for Keycloak's `amr`.
- **R14. How the proof rides the mint.** The mint answers each item under an unmet requirement
  `deny per_login_mfa_required`, with `per_login_mfa: {device, challenge, expires_at, accept,
  methods, reuse_for_seconds, levels}`; one challenge per request, 32 random bytes, kept 5 minutes
  (`PutOnce`), bound to the principal, the certificate and the agent session. The proof is posted
  to `POST /v1/mfa`: on the held connection for a touch, with a bearer ID token over a fresh
  connection for `idp_mfa` (the agent never holds an ID token, decision 43 ruling 1). The retried
  mint carries `per_login_mfa_challenge`, and the proof made for that challenge covers that
  request's items whose `accept` holds its method, whatever `reuse_for` says, once. So `reuse_for:
  0m` is a proof at every login. One endpoint serves the mint, the refresh and both methods.
- **R15. Reuse.** A proof is kept as `(SHA-256(principal ‖ 0 ‖ certificate fingerprint ‖ 0 ‖
  agent session), method) → proved_at` (`PutMFAProof`, the later kept, 8h). It covers a later
  login to a device whose effective `accept` holds the method and whose `reuse_for` has not passed
  since. The agent session is 32 random bytes the agent draws at start and sends as
  `Port49-Agent-Session` on every request; never logged. Another agent, or the same person on
  another machine, proves again. The store holds it, so a reconnect to another broker replica keeps
  it.
- **R16. Held sessions.** A requirement gates logins and refreshes. A policy reload that adds or
  tightens one revokes nothing, on any platform: on a platform that never asks about a command
  (decision 21) port49 could not end the session anyway, and on a per-command platform ending it
  would make a policy edit a fleet-wide logout at 3am. A session refresh extends a context under a
  requirement only when a proof covers it now; otherwise that context is answered
  `per_login_mfa_required` (deny, recorded), keeps the ceiling it holds, and the response carries a
  challenge. On a platform that never asks about a command the record carries `session.unreached:
  true`, and `port49 refresh` says the device's own session runs until the device closes it. So a
  session opened before a requirement cannot be extended past it without a proof.
- **R17. What people see.** A prompt: `core-sw01 asks for a second factor at each login: scope core
  accepts hardware_key_touch; role netadmin accepts hardware_key_touch, idp_mfa (reuse 15m, from
  defaults)`, then `touch your key now` or the sign-in. A refusal names the same and the cause.
  `port49 explain` prints `per_login_mfa accept hardware_key_touch (defaults ∩ role netadmin ∩
  scope core); reuse_for 5m (scope core); applies to humans`, or `per_login_mfa none`: the default
  is never invisible.
- **R18. Unavailable, and 3am.** A requirement whose `accept` holds no method this broker can
  verify now (no attestation roots for a touch-only device, no human OIDC verifier for an
  `idp_mfa`-only one) is `deny per_login_mfa_unavailable` for that device alone, said at the
  broker's start once per policy. The broker never refuses a start over it (decision 43 R4's rule).
  With the IdP down, touch still works where accepted; with no token at hand, idp works where
  accepted: the operator notes say to accept both where they can. Break-glass is unaffected.
- **R19. Records.** One new event, `per_login_mfa`: a proof posted, `permit per_login_mfa_proved`
  or `deny per_login_mfa_refused`, carrying `per_login_mfa: {method, challenge_sha256}`. A mint or
  refresh record under a requirement carries `per_login_mfa: {accept, reuse_for_seconds, levels,
  method, proved_at, reused}`. Reasons (§5.7 first): `per_login_mfa_required`,
  `per_login_mfa_proved`, `per_login_mfa_refused`, `per_login_mfa_unavailable`. Metric
  `port49_per_login_mfa_total{method,outcome}`; no principal, no device. A token's credential
  carries `mfa_method` and `mfa_at` into the context.
- **R20. Decision 43 ruling 13 amended.** A broker with `issuance` takes a person's ID token at
  `POST /v1/certificate` and at `POST /v1/mfa` (as an `idp_mfa` proof, never as a caller's
  credential), and refuses it everywhere else, as before.
- **R21. Workloads.** A machine meets a requirement only under `applies_to_machines: true`, and only
  by `hardware_key_touch` (`port49 workload token --touch-key REF`, stderr saying "touch the key").
  A workload's key may be a reference too (`--key pkcs11:…`).

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, `CGO_ENABLED=0` for every binary; the only new modules are
  `github.com/ebitengine/purego` v0.11.1 and `github.com/google/go-tpm` v0.9.8.
- snake_case for all data: `per_login_mfa`, `accept`, `reuse_for`, `applies_to_machines`,
  `hardware_key_touch`, `idp_mfa`, `issued_key_store`, `issued_key`, `touch_key`, `broker_crl`,
  `attestation_roots_file`, `amr`, `acr_values`, `per_login_mfa_challenge`, `mfa_method`, `mfa_at`,
  `port49_per_login_mfa_total`.
- Reason codes are §5.7's: Task 1 adds the four before any code emits them
  (`internal/decision/reasons.go` follows in Task 11).
- The log and every printed line never carry a token, an ID token, a PIN, a challenge, a signature,
  the agent session or a private key. A challenge is recorded as `challenge_sha256`.
- No device identity in metric labels.
- No per-user step at fleet scale: every new key (`key`, `touch_key`, `issued_key_store`,
  `broker_crl`) is settable once in the root-owned `/etc/port49/config.yaml`.
- A start never fails over a hardware or attestation file (decision 43 R4's rule); the start line
  says what is unavailable.
- Lab: positive controls enforced, a failed control is `INVALID` before any note is written;
  results notes per CLAUDE.md; captures redacted into `tests/lab/evidence/`. The YubiKey row (L60)
  needs Ryan present and is run late; no code task waits on it.
- Commit trailer, every commit: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
  and nothing else (no `Claude-Session:` line, no claude.ai link: owner's rule).
- Verify before done: `make test && make vet`, and `make test-hw` where a task names it; real
  output reported.

## Review Focus

1. **The key unplugged while the agent reconnects.** The handshake's signature fails inside
   `crypto/tls`, whose error carries only text. The session must not end, and the operator must
   read "insert your key", not "the broker refused this certificate". Test in Task 6
   (`TestAKeyUnpluggedNeverEndsTheSession`, the reconnect case).
2. **A wrong PIN.** port49 must never send a PIN twice, or the YubiKey's three tries go in one
   command. Test in Task 3 (`TestAWrongPINIsTriedOnce`) and Task 5
   (`TestLoginAsksThePINOnceAndSaysTriesLeft`).
3. **One subject on one device under a role and a scope that accept disjoint methods.** The policy
   must be refused at load, naming both levels, never loaded to fail every login there. Test in
   Task 9 (`TestDisjointLevelsRefuseTheLoad`), with the machine case.
4. **A touch from a token that does not hold the session key.** A copied session key and the
   attacker's own YubiKey must not satisfy `hardware_key_touch`. Test in Task 11
   (`TestATouchFromAnotherTokenIsRefused`), with Task 10's attestation cases.
5. **A touch proof replayed.** A signature taken on one connection and posted on another, or a
   challenge used twice, must be refused. Test in Task 11 (`TestATouchProofIsBoundToItsConnection`,
   `TestAChallengeIsUsedOnce`).
6. **The CRL's server down at 3am.** Under `check` every login goes on, said once; a list naming the
   broker refuses before any bearer token is sent. Test in Task 8 (`TestBrokerCRLModes`).
7. **A reload adds a requirement under a live Junos session.** Nothing is revoked; the next
   refresh does not extend it without a proof and says its session is out of reach. Test in Task 12
   (`TestARequirementAddedRevokesNothing`, `TestRefreshUnderARequirementNeedsAProof`).

---

## Task 1: Spec — §5.1.5 per-login MFA, decision 45, §5.1.4, §5.7, §12, §14, §15 L60–L63

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.1.4's credential block ~919–935; new
  §5.1.5 before `### 5.2 Session authorization (daemon)` ~1178; §5.7's events table ~2150–2162,
  the paragraph after it ~2164–2194, the reason table ~2306–2349; §12; §13 after decision 44's
  last ruling, before the `---` above `## 14.`; decision 43 ruling 13; §14; §15 table after L59's
  row and the detail bullets after L59's)

**Interfaces:** Produces the names every later task uses: `per_login_mfa`, `accept`, `reuse_for`,
`applies_to_machines`, `hardware_key_touch`, `idp_mfa`, event `per_login_mfa`, reasons
`per_login_mfa_required`, `per_login_mfa_proved`, `per_login_mfa_refused`,
`per_login_mfa_unavailable`, `POST /v1/mfa`, header `Port49-Agent-Session`, exporter label
`EXPORTER-port49-per-login-mfa`, `per_login_mfa_challenge`, `issued_key_store`, `touch_key`,
`broker_crl`, rows L60–L63.

- [ ] **Step 1: §5.1.4's credential block.** After the `acr` line inside the fenced block, add:

```
  # per-login MFA (plan 9c; §5.1.5)
  mfa_method   hardware_key_touch | idp_mfa   the proof the login's mint was covered by
  mfa_at       2026-10-12T02:11:07Z            when that proof was made
```

  and after the paragraph beginning `**`amr` and `acr` are recorded**` add: "**`mfa_method` and
  `mfa_at`** are the per-login proof the minting login was covered by (§5.1.5): what an incident
  responder asks of a session on a core device, and what a session refresh reads (decision 45
  ruling 16)."

- [ ] **Step 2: Add §5.1.5** before `### 5.2 Session authorization (daemon)`:

````markdown
### 5.1.5 Per-login MFA

A policy may ask for a second factor at each login to the devices it marks: `per_login_mfa`. It is
a proof at the login to a matching device, not the daily sign-in, which may already include MFA,
and it is never spelled `mfa: required` (§13 decision 45).

```yaml
defaults:
  per_login_mfa:
    accept: [hardware_key_touch, idp_mfa]
    reuse_for: 15m
roles:
  - name: netadmin
    per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}
scopes:
  - name: core
    match: {tier: core}
    on_missing: include
    security_log: true
    per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}
  - name: core-sw01
    match: {name: core-sw01}
    per_login_mfa: {accept: [hardware_key_touch], reuse_for: 0m}
```

**The keys.** `accept` is an explicit list, one or both of the methods below, each once; leaving
`per_login_mfa` out is no requirement, and there is no `none`. `reuse_for` is how long one proof
covers further logins under a requirement that proof satisfies: 15m when left out, `0m` a proof at
every login, at most 8h. `applies_to_machines` is false unless spelled out.

**The methods.**
- `hardware_key_touch`: a touch on an always-touch slot of the token that holds the session key,
  signing a broker challenge bound to the held connection. The broker verifies the token's PIV
  attestation (decision 45 ruling 12). Instant.
- `idp_mfa`: a fresh sign-in at the identity provider whose `amr` shows a second factor, its
  `nonce` binding the challenge (ruling 13). A browser round trip at each such login.

**Four levels, the strictest wins.** `defaults:` (every device), a role (where it composes, granted
or attached), a scope selecting by an attribute (a device class or tag), and a scope selecting by
`name` (one device). On a device the requirement is the intersection of the `accept` lists of every
level that applies and the least `reuse_for`; a lower level never weakens a higher. An empty
intersection refuses the policy at load, naming both levels. A machine principal is exempt but from
levels that set `applies_to_machines: true`, and a machine proves by `hardware_key_touch` alone. A
scope with a match key that sets `per_login_mfa` must declare `on_missing` and `security_log:
true`.

**The proof** (ruling 14). A mint item under an unmet requirement is answered `deny
per_login_mfa_required` with a challenge. The client proves at `POST /v1/mfa` and mints again
naming the challenge; that proof covers that request's items whose requirement accepts its
method, and, for `reuse_for`, later logins by the same principal, certificate and agent session
under a requirement it satisfies.

**A live session** (ruling 16). A requirement gates logins and session refreshes, never a live
session: a reload that adds one revokes nothing. A refresh extends a context under a requirement
only when a proof covers it; otherwise it is answered `per_login_mfa_required` and keeps the
ceiling it holds. On a platform that never asks about a command (decision 21) that ceiling does
not reach the device, and the record says so (`session.unreached`).

**Unavailable** (ruling 18). A requirement no method this broker can verify satisfies is `deny
per_login_mfa_unavailable` for that device alone.
````

- [ ] **Step 3: §5.7.**
  - In the events table, add a row after `issue`:
    `| `per_login_mfa` | broker | whether a per-login proof posted to `POST /v1/mfa` is accepted (§5.1.5; §13 decision 45): `permit per_login_mfa_proved` or `deny per_login_mfa_refused`, carrying `per_login_mfa: {method, challenge_sha256}`. A proof the broker cannot judge (`store_unavailable`) records that |`
  - In the `mint` row append: "A record of a device under a per-login requirement carries `per_login_mfa: {accept, reuse_for_seconds, levels, method, proved_at, reused}` (§5.1.5)".
  - In the `refresh` row append: "On a session refresh, a context under a requirement no proof covers is `deny per_login_mfa_required`, not extended (§5.1.5)".
  - "One envelope. Ten decision events" becomes "Eleven decision events"; "the twelfth event,
    `account`" becomes "the thirteenth"; "A thirteenth, `account_gap`" becomes "A fourteenth";
    "A fourteenth, `inventory_change`" becomes "A fifteenth"; "A fifteenth, `directory_forget`"
    becomes "A sixteenth".
  - In the reason table, after `certificate_issued`, add:

```markdown
| `per_login_mfa_required` | `mint`: the device's per-login requirement (§5.1.5) applies and no proof covers it; the item carries a challenge, and nothing is minted for it. `refresh`: a context under a requirement no proof covers is not extended and keeps its ceiling |
| `per_login_mfa_proved` | `per_login_mfa`: a proof posted to `POST /v1/mfa` verified (§13 decision 45 rulings 12 and 13) |
| `per_login_mfa_refused` | `per_login_mfa`: a proof did not verify: a challenge unknown, spent, expired or another caller's; a touch signature not over this connection's exporter value; an attestation that does not chain to the configured roots, is not always-touch, or is not the session key's token's; an ID token decision 39 refuses, for another principal, not fresh, without an accepted `amr`, not binding the challenge, or spent. The API answers 401 with the cause |
| `per_login_mfa_unavailable` | `mint`, `refresh`: the device's requirement accepts no method this broker can verify now (no `hardware_key_touch.attestation_roots_file` loaded, no human OIDC verifier). That device alone; alertable: a configuration fault, not a person's |
```

  - After the paragraph beginning "Every event has a success reason", add the sentence:
    "`per_login_mfa_refused` MUST be alertable on its own: a run of them is someone trying another
    token or another person's sign-in."

- [ ] **Step 4: §12.** In `port49 explain`'s output description add the `per_login_mfa` line
  (ruling 17's form). Under "Policy tests", add the key `per_login_mfa:` to a session test's
  assertions: `{accept: [...], reuse_for: 15m}` or `none`. Under `policy diff`, add: "a change to a
  subject's effective per-login requirement on a device is printed as `per_login_mfa:` with the
  before and after, and a weakening (a method added to `accept`, a longer `reuse_for`, a
  requirement removed) is printed as `warning:`."

- [ ] **Step 5: Amend decision 43 ruling 13.** Replace "takes a person's ID token at `POST
  /v1/certificate` alone" with "takes a person's ID token at `POST /v1/certificate`, and at `POST
  /v1/mfa` as an `idp_mfa` proof (decision 45 ruling 20)".

- [ ] **Step 6: Add decision 45** after decision 44's last ruling:

```markdown
**45. The agent in full, third part: hardware-backed client keys, `per_login_mfa`, and the broker
certificate's CRL check.** *Plan 9c, 2026-10-12, on plan 3's rulings of 2026-09-24, decision 42
ruling 13, and Ryan's direction of 2026-10-10.* Rulings rest on reasoning unless they say data.
Ruling 6 is gated on L63; rulings 3, 4, 8 and 12's PKCS#11 and attestation claims are
*provisional on L60*; ruling 13's `amr` on Keycloak is *provisional on L61*; ruling 5 on real
hardware is *provisional on L62*.
```

  Then rulings 1–22, each one paragraph, from this plan's R1–R21 in order (R1 → 1 … R21 → 21), with
  ruling 22 "**The lab.** L60 (a YubiKey on the SER8; Ryan present), L61 (Keycloak's `amr`), L62 (the
  SER8's TPM), L63 (the Secure Enclave from an unsigned binary)." Copy each R's text; replace "this
  plan" with "plan 9c" and "Task N" with the plan's task name.

- [ ] **Step 7: §14.** Add a group **Hardware keys and per-login MFA** with these bullets:
  - "**One signer**: a PKCS#11, TPM and file key each sign a TLS 1.3 handshake and a refresh
    through `crypto.Signer`; CI runs the first two against SoftHSM2 and swtpm with `CGO_ENABLED=0`."
  - "**The PIN once**: a refused PIN is never sent again by port49."
  - "**The key unplugged**: the held connection mints; a refresh and a reconnect say to insert the
    key and end no session; a re-inserted key is unlocked by `port49 login`."
  - "**Strictest wins**: the intersection and the least `reuse_for`; disjoint levels refuse the
    load naming both; machines exempt unless `applies_to_machines`."
  - "**The touch is the session token's**: an attestation from another token, or not always-touch,
    is refused; a touch signature over another connection's exporter value is refused."
  - "**A challenge once**: a challenge proved twice, or by another caller, is refused."
  - "**`reuse_for: 0m`**: a proof covers its own request and no other."
  - "**No revocation on reload**: a requirement added under a live session revokes nothing; the
    refresh does not extend it without a proof."
  - "**The broker CRL**: revoked refuses before any request; unavailable goes on under `check`, is
    refused under `require`."

- [ ] **Step 8: §15 rows.** After L59's row add:

```markdown
| **L60** | A YubiKey's PIV applet through `libykcs11` under purego, on the SER8 (needs Ryan present, with a YubiKey 5). Whether: `C_Initialize` with `CKF_OS_LOCKING_OK` and no callbacks, and `C_Finalize`, run clean with the token present, `libykcs11`'s threads included; a slot 9a key (PIN policy once, touch never, a lab CA's certificate) signs a TLS 1.3 handshake and a refresh with `port49 login` asking the PIN once; the attestation certificates (slot f9 and each slot's) are reachable as certificate objects, chain to Yubico's PIV root, and carry the touch policy (1.3.6.1.4.1.41482.3.8) and serial (…3.7) port49 reads; a slot 9c key with touch policy always proves `hardware_key_touch` with a touch, and with no touch within the token's timeout is refused in port49's words; the token unplugged mid-session: `port49 token` mints on the held connection, `port49 refresh` says to insert the key, the session survives, and after re-insertion `port49 login` asks the PIN and the refresh works; a wrong PIN is sent once and the message says the tries left; a key generated on the token for `issued_key_store: pkcs11` is issued a certificate. Each cell against a control. | §13 decision 45 rulings 3, 4, 8 and 12; the operator notes (plan 13) | YubiKey 5 (firmware recorded), libykcs11 (version recorded), SER8 | open — added by plan 9c 2026-10-12; needs Ryan present |
| **L61** | Keycloak's `amr` and `acr` in an ID token for `idp_mfa`. With a realm flow of password and OTP, a `prompt=login` sign-in with both: whether the ID token carries `amr`, and which values, with Keycloak's AMR protocol mapper and with none; the control, a password-only sign-in, and its `amr`; whether `acr_values` changes either. | §13 decision 45 ruling 13 (the default `amr: [mfa]`); the operator notes' provider setup | Keycloak (26.x) | open — added by plan 9c 2026-10-12 |
| **L62** | A real TPM 2.0 through `/dev/tpmrm0` on the SER8 for a non-root user in `tss`: whether `issued_key_store: tpm` creates a key under the ECC SRK, signs a TLS 1.3 handshake and a refresh, survives an agent restart and a reboot, and is refused (cannot load) on another machine given the same key file; the control, a user outside `tss`, is refused naming the group. | §13 decision 45 rulings 5 and 7 | SER8 (TPM vendor and firmware recorded) | open — added by plan 9c 2026-10-12 |
| **L63** | The macOS Secure Enclave through Security.framework under purego, from an unsigned `port49` built with `CGO_ENABLED=0`: whether `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` and `kSecAttrIsPermanent` creates a key, whether a second process finds it by label and signs with it, and what a refusal returns (`errSecMissingEntitlement`, -34018, or another). The control: the same calls for a software key. | §13 decision 45 ruling 6 (gate SE1) | macOS (version and hardware recorded) | open — added by plan 9c 2026-10-12; needs a macOS host |
```

  and after L59's detail bullet, one bullet each: "**L60**–**L63** — added by plan 9c. Why each is
  a row:" followed, per row, by the claim's dependency in one sentence (L60: decision 45's PKCS#11,
  PIN and touch claims are reasoning from the PKCS#11 and PIV specifications until a real token
  answers; L61: `idp_mfa`'s `amr` default is provider data; L62: swtpm is not a TPM's firmware;
  L63: the entitlement question decides whether the Secure Enclave is built).

- [ ] **Step 9: Check and commit.** `grep -n "per_login_mfa" docs/design/2026-08-23-policy-engine-spec.md | wc -l` is above 20; `grep -c "^| \*\*L6[0-3]\*\*" …` prints 4.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: spec decision 45, per-login MFA, hardware keys, broker CRL; L60-L63

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: The Secure Enclave spike (L63; gate SE1) — on a macOS host, else back to Ryan

**Files:**
- Create: `tests/spike/secureenclave/main.go` (`//go:build darwin`)
- Create: `tests/lab/results/L63-macos.md` (only when run)

**Interfaces:** Produces gate SE1 for Task 14. Nothing else depends on it.

- [ ] **Step 0: Find a macOS host.** None is known to this project: the development host is WSL2 and
  the lab machine (SER8) is Linux. If there is none, write the open question "the Secure Enclave
  spike needs a macOS host (decision 42 ruling 13); run `tests/spike/secureenclave` there, or drop
  the Secure Enclave and serve macOS through a YubiKey" to the plan's report, leave L63 open, mark
  Task 14 waiting, and go on to Task 3. Steps 1–4 are written so Ryan, or a later run, can run them.

- [ ] **Step 1: Write the spike.** One program, purego only, no cgo:

```go
//go:build darwin

// Command secureenclave is plan 9c's spike for L63: can an unsigned port49
// create a Secure Enclave key, find it again from a second process, and sign
// with it? It prints one line per cell and the OSStatus of each failure.
package main

import (
	"fmt"
	"os"

	"github.com/ebitengine/purego"
)

func main() {
	sec, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_LAZY)
	if err != nil {
		fmt.Println("dlopen Security:", err)
		os.Exit(1)
	}
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY)
	if err != nil {
		fmt.Println("dlopen CoreFoundation:", err)
		os.Exit(1)
	}
	// Each cell below is one function in cells.go (same package): createPermanent,
	// createEphemeral, findByLabel, sign, createSoftwareControl. Each prints
	// "cell <name>: ok" or "cell <name>: OSStatus <n> <CFErrorCopyDescription>".
	run(sec, cf, os.Args[1:])
}
```

  `cells.go` (same build tag) registers with `purego.RegisterLibFunc`: `CFDictionaryCreateMutable`,
  `CFDictionarySetValue`, `CFStringCreateWithCString`, `CFNumberCreate`, `CFRelease`,
  `CFErrorGetCode`, `CFErrorCopyDescription`, `CFStringGetCString`, `SecKeyCreateRandomKey`,
  `SecItemCopyMatching`, `SecKeyCreateSignature`, `SecKeyCopyPublicKey`,
  `SecAccessControlCreateWithFlags`; and reads the constants `kSecAttrTokenIDSecureEnclave`,
  `kSecAttrTokenID`, `kSecAttrKeyType`, `kSecAttrKeyTypeECSECPrimeRandom`, `kSecAttrKeySizeInBits`,
  `kSecAttrIsPermanent`, `kSecAttrLabel`, `kSecPrivateKeyAttrs`, `kSecAttrAccessControl`,
  `kSecClass`, `kSecClassKey`, `kSecReturnRef`, `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`,
  `kCFBooleanTrue`, `kCFBooleanFalse` with `purego.Dlsym` (each is a pointer to a `CFTypeRef`).
  Cells: `create-permanent LABEL`, `find LABEL` (run as a second process), `sign LABEL`,
  `create-ephemeral` (non-permanent, signs in the same process), `control` (the same calls with no
  `kSecAttrTokenID`, a software key).

- [ ] **Step 2: Run on the macOS host**, unsigned, `CGO_ENABLED=0 go build -o /tmp/se ./tests/spike/secureenclave`:
  `/tmp/se control`, `/tmp/se create-permanent p49-l63`, `/tmp/se find p49-l63`, `/tmp/se sign
  p49-l63`, `/tmp/se create-ephemeral`. The control must print `ok` for its create and sign, else
  the run is INVALID.

- [ ] **Step 3: Read gate SE1.** SE1 passes when `create-permanent`, `find` (second process) and
  `sign` all print `ok`. Write `tests/lab/results/L63-macos.md`: macOS version, hardware, the build
  line, each cell's output verbatim, and SE1's reading. If SE1 passes, close L63 per CLAUDE.md rule
  3 and Task 14 runs. If it fails with `-34018` (`errSecMissingEntitlement`) or anything else, L63
  closes with that observation, and the choice goes back to Ryan: macOS through a YubiKey alone, or
  `create-ephemeral`'s per-agent key (the agent child generates the key and the login signs in for
  it; a reboot or agent restart signs in again). Task 14 waits for that ruling.

- [ ] **Step 4: Commit** (when run):

```bash
git add tests/spike/secureenclave tests/lab/results/L63-macos.md docs/design/2026-08-23-policy-engine-spec.md
git commit -m "test: the Secure Enclave spike (L63, gate SE1)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: PKCS#11 through purego, and SoftHSM2 in CI

**Files:**
- Create: `internal/hwkey/hwkey.go`, `internal/hwkey/hwkey_test.go`
- Create: `internal/hwkey/pkcs11/consts.go`, `module.go`, `uri.go`, `signer.go`, `ecdsa.go`
- Create: `internal/hwkey/pkcs11/uri_test.go`, `ecdsa_test.go`, `consts_test.go`
- Create: `internal/hwkey/pkcs11/softhsm_test.go` (`//go:build hwkey`)
- Create: `internal/hwkey/hwtest/hwtest.go` (`//go:build hwkey`: starts SoftHSM2 and swtpm for tests)
- Create: `.github/workflows/hwkeys.yml`
- Modify: `Makefile` (target `test-hw`), `go.mod`, `go.sum`
- Modify: `internal/userconfig/userconfig.go` (export `CheckOwned(path string) error`, the
  ownership walk `resolveOwned` already does, for R3's module check), with a test in
  `internal/userconfig/userconfig_test.go` (`TestCheckOwnedRefusesAGroupWritableDirectory`)

**Interfaces:**
- Produces (`internal/hwkey`):

```go
type State int

const (
	Present State = iota // the key signs
	Absent               // the token or TPM is gone; insert it
	Locked               // the token is back and needs its PIN (Unlock)
)

func (s State) String() string // "present", "absent", "locked"

// Key is every hardware key: a crypto.Signer that says whether it can sign
// now, takes a PIN, and lets go of its token.
type Key interface {
	crypto.Signer
	State() State
	Unlock(pin []byte) error
	Close() error
}

var (
	ErrKeyAbsent = errors.New("hwkey: the key is not present")
	ErrLocked    = errors.New("hwkey: the key needs its PIN")
)

// PINError is a PIN the token refused. Low and Final are the token's own
// flags (CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY).
type PINError struct{ Low, Final bool }

func (e *PINError) Error() string
```

- Produces (`internal/hwkey/pkcs11`):

```go
type URI struct {
	Token, Manufacturer, Serial, Model, Object, Type string
	ID                                               []byte
	SlotID                                           *uint
	ModulePath, PINSource                            string
}

func ParseURI(s string) (URI, error)
func (u URI) String() string // canonical, for messages; never a PIN

type Module struct{ /* dlopen handle, function list, path */ }

func Load(path string) (*Module, error) // checks R3's ownership, dlopens, C_GetFunctionList, C_Initialize

// Signer is one private key object on one token; it implements hwkey.Key.
type Signer struct{ /* module, uri, slot, session, handle, public key */ }

func Open(u URI, pin []byte) (*Signer, error) // pin nil: Locked when the token needs login
func (s *Signer) Certificate() (*x509.Certificate, error) // CKO_CERTIFICATE with the key's CKA_ID
func (s *Signer) Certificates() ([]*x509.Certificate, error) // every certificate object on its token
func Generate(u URI, pin []byte) (*Signer, error) // CKM_EC_KEY_PAIR_GEN, P-256, CKA_ID u.ID
```

- [ ] **Step 1: Write the failing unit tests.** `internal/hwkey/pkcs11/uri_test.go`:

```go
package pkcs11

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseURI(t *testing.T) {
	u, err := ParseURI("pkcs11:token=YubiKey%20PIV;id=%01;type=private?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so&pin-source=file:///etc/port49/pin")
	if err != nil {
		t.Fatal(err)
	}
	if u.Token != "YubiKey PIV" || !bytes.Equal(u.ID, []byte{1}) || u.Type != "private" ||
		u.ModulePath != "/usr/lib/x86_64-linux-gnu/libykcs11.so" || u.PINSource != "file:///etc/port49/pin" {
		t.Fatalf("parsed %+v", u)
	}
	for _, bad := range []struct{ uri, says string }{
		{"pkcs11:id=%01?pin-value=123456", "pin-value"},
		{"pkcs11:id=%01", "module-path"},
		{"pkcs11:id=%01?module-path=libykcs11.so", "absolute"},
		{"pkcs11:id=%zz?module-path=/x.so", "percent"},
		{"pkcs11:colour=red;id=%01?module-path=/x.so", "colour"},
		{"pkcs11:id=%01;id=%02?module-path=/x.so", "twice"},
		{"pkcs11:?module-path=/x.so", "id or object"},
		{"file:/x", "pkcs11:"},
	} {
		if _, err := ParseURI(bad.uri); err == nil || !strings.Contains(err.Error(), bad.says) {
			t.Errorf("ParseURI(%q) = %v, want an error naming %q", bad.uri, err, bad.says)
		}
	}
}
```

  `internal/hwkey/pkcs11/ecdsa_test.go` (the raw `r‖s` a token returns becomes the DER Go's
  `ecdsa.VerifyASN1` reads, and a short `r` is padded, never misread):

```go
package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestRawECDSAToDER(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sum := sha256.Sum256([]byte("port49"))
	for i := 0; i < 64; i++ {
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		der, err := rawECDSAToDER(raw, 32)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, sum[:], der) {
			t.Fatalf("round %d: the DER form does not verify", i)
		}
	}
	if _, err := rawECDSAToDER(make([]byte, 63), 32); err == nil {
		t.Fatal("an odd-length signature was taken")
	}
}
```

  `internal/hwkey/pkcs11/consts_test.go` pins the function-list indexes against the PKCS#11 v2.40
  header order (`C_Initialize` 0, `C_Finalize` 1, `C_GetSlotList` 4, `C_GetTokenInfo` 6,
  `C_OpenSession` 12, `C_CloseSession` 13, `C_Login` 18, `C_Logout` 19, `C_GetAttributeValue` 24,
  `C_FindObjectsInit` 26, `C_FindObjects` 27, `C_FindObjectsFinal` 28, `C_SignInit` 42, `C_Sign`
  43, `C_GenerateKeyPair` 59): a table test over the `fn*` constants.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/hwkey/pkcs11/ -run 'TestParseURI|TestRawECDSAToDER|TestFunctionIndexes' -count=1`
Expected: FAIL (`undefined: ParseURI`, `rawECDSAToDER`).

- [ ] **Step 3: Implement.**
  - `go get github.com/ebitengine/purego@v0.11.1` (and, for Task 4, `github.com/google/go-tpm@v0.9.8`).
  - `consts.go`: the `CKR_*`, `CKA_*`, `CKO_*`, `CKK_*`, `CKM_*`, `CKF_*`, `CKU_USER` values the
    package uses (from PKCS#11 v2.40 §3), and `fnInitialize = 0` … `fnGenerateKeyPair = 59`.
  - `userconfig.go`: `CheckOwned(path string) error` is `resolveOwned(path, false, "PKCS#11 module")`
    with its error, exported.
  - `module.go`: `Load` checks `path` with `userconfig.CheckOwned(path)`, then
    `purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)`,
    `purego.Dlsym(h, "C_GetFunctionList")`, calls it with a pinned `*uintptr`, and reads the list:

```go
// ckFunctionList is CK_FUNCTION_LIST on LP64 Linux and macOS: a CK_VERSION
// (two bytes, padded to the pointer's alignment), then the functions in the
// header's order. Windows packs it to one byte and is not a port49 client.
type ckFunctionList struct {
	version [2]byte
	_       [6]byte
	fns     [68]uintptr
}

// call runs one PKCS#11 function and returns its CK_RV. Every pointer
// argument points at heap memory pinned by the caller for the call.
func (m *Module) call(fn int, args ...uintptr) uint {
	r, _, _ := purego.SyscallN(m.list.fns[fn], args...)
	return uint(r)
}
```

    `C_Initialize` gets a pinned `CK_C_INITIALIZE_ARGS` with every mutex callback nil and `flags =
    CKF_OS_LOCKING_OK`; `CKR_CRYPTOKI_ALREADY_INITIALIZED` is success. One `Module` per path per
    process (a package map under a mutex).
  - `uri.go`: `ParseURI` per RFC 7512 §2.3: `pkcs11:` then `;`-separated path attributes, `?` then
    `&`-separated query attributes, values percent-decoded, `id` as bytes. Refused, each with its own
    message: a scheme other than `pkcs11:`, an unknown attribute (named), one given twice,
    `pin-value` ("a PIN does not belong in a config file; use pin-source=file:///path or let
    `port49 login` ask it"), no `module-path` or a relative one, neither `id` nor `object`.
  - `signer.go`: `Open` loads the module, lists slots with a token, keeps the tokens whose info
    matches `Token`/`Manufacturer`/`Serial`/`Model` (blank-padded fields trimmed) and `SlotID`,
    finds the private key (`CKO_PRIVATE_KEY`, `CKA_ID`/`CKA_LABEL`) on each, and refuses two
    matches naming both tokens. It opens a session (`CKF_SERIAL_SESSION`), and reads the public key
    from the `CKO_PUBLIC_KEY` with the same `CKA_ID` (EC: `CKA_EC_PARAMS` and `CKA_EC_POINT`; RSA:
    `CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`), falling back to the certificate's. With
    `CKF_LOGIN_REQUIRED` and no PIN the state is `Locked`; with a PIN it calls `C_Login` once
    (`Unlock`), maps `CKR_PIN_INCORRECT` to `*hwkey.PINError` with the token's flags read after,
    and zeroes the PIN slice it was handed. `Sign`:

```go
// Sign signs digest with the token's key: ECDSA (CKM_ECDSA, the raw r‖s
// turned into DER), RSA-PSS with SHA-256 (CKM_RSA_PKCS_PSS), or Ed25519
// (CKM_EDDSA over the message). A token gone is hwkey.ErrKeyAbsent, and the
// key's state Absent until a later Sign finds it again (reopen).
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
```

    The PSS parameters are `CK_RSA_PKCS_PSS_PARAMS{hashAlg: CKM_SHA256, mgf: CKG_MGF1_SHA256,
    sLen: 32}` for `rsa.PSSSaltLengthEqualsHash` and `PSSSaltLengthAuto` alike; any other hash or
    PKCS#1 v1.5 is refused (TLS 1.3 and `api.SignRefresh` use neither). `reopen`: on `Absent`,
    `C_CloseSession` is ignored, the slot is found again by the URI, a session opened; `Locked` if
    it needs login, else `Present`.
  - `ecdsa.go`: `rawECDSAToDER(raw []byte, size int) ([]byte, error)` with `cryptobyte`.
  - `internal/hwkey/hwkey.go`: the types above and `IsRef(s string) bool` (prefix `pkcs11:`,
    `tpm:`, `secure-enclave:`). `Open` and `LoadPair` come in Task 5.

- [ ] **Step 4: Run the unit tests**

Run: `go test ./internal/hwkey/... -count=1`
Expected: PASS.

- [ ] **Step 5: The SoftHSM2 harness.** `internal/hwkey/hwtest/hwtest.go` (`//go:build hwkey`):

```go
// SoftHSM starts a fresh SoftHSM2 token for one test: its own
// SOFTHSM2_CONF and token directory under t.TempDir(), a token labelled
// "port49-test" with user PIN 123456 and SO PIN 12345678, and the module
// path from $PORT49_TEST_PKCS11_MODULE (default
// /usr/lib/softhsm/libsofthsm2.so). With $PORT49_TEST_HW_REQUIRED set, a
// missing softhsm2-util or module fails the test instead of skipping it,
// so CI cannot go green by skipping.
func SoftHSM(t *testing.T) (module string)
```

  It runs `softhsm2-util --init-token --free --label port49-test --pin 123456 --so-pin 12345678`
  with `SOFTHSM2_CONF` set via `t.Setenv`, and generates a P-256 key with `CKA_ID` `01` through
  `pkcs11.Generate`.

- [ ] **Step 6: Write the integration tests.** `internal/hwkey/pkcs11/softhsm_test.go`
  (`//go:build hwkey`):

```go
func TestASoftHSMKeySignsATLSHandshakeAndARefresh(t *testing.T) {
	module := hwtest.SoftHSM(t)
	u, _ := ParseURI("pkcs11:token=port49-test;id=%01?module-path=" + module)
	s, err := Open(u, []byte("123456"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// A refresh signature verifies with the public key, as the broker
	// verifies it (api.RefreshAlgorithm).
	msg := api.RefreshMessage(make([]byte, api.RefreshNonceLen), make([]byte, 32))
	sig, err := api.SignRefresh(s, msg)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), sum[:], sig) {
		t.Fatal("the refresh signature does not verify")
	}
	// A TLS 1.3 mutual handshake with the key behind tls.Certificate.
	assertMutualTLS(t, s)
}

func TestAWrongPINIsTriedOnce(t *testing.T) {
	module := hwtest.SoftHSM(t)
	u, _ := ParseURI("pkcs11:token=port49-test;id=%01?module-path=" + module)
	s, err := Open(u, nil)
	if err != nil || s.State() != hwkey.Locked {
		t.Fatalf("Open with no PIN = %v, %v; want Locked", s.State(), err)
	}
	var pe *hwkey.PINError
	if err := s.Unlock([]byte("000000")); !errors.As(err, &pe) {
		t.Fatalf("Unlock(wrong) = %v, want a *PINError", err)
	}
	if got := hwtest.SoftHSMLoginAttempts(t); got != 1 {
		t.Fatalf("the module saw %d logins, want 1", got)
	}
	if err := s.Unlock([]byte("123456")); err != nil || s.State() != hwkey.Present {
		t.Fatalf("Unlock(right) = %v, state %v", err, s.State())
	}
}

func TestTwoTokensHoldingTheIDAreRefused(t *testing.T) { /* two tokens, id %01 on both, no token= in the URI: the error names both labels */ }

func TestTheCertificateComesFromTheToken(t *testing.T) { /* a certificate object with CKA_ID 01 written by the harness; Certificate() returns it and its key equals Public() */ }
```

  `hwtest.SoftHSMLoginAttempts(t) int` returns `pkcs11.LoginCalls()`, a counter the package
  bumps on each `C_Login` (an unexported `loginCalls atomic.Int64`, read through an exported
  function in `export_hwkey_test.go`, `//go:build hwkey`), not SoftHSM's logs. `assertMutualTLS` runs an `httptest` TLS 1.3
  server requiring a client certificate signed by a test CA for `s.Public()`.

- [ ] **Step 7: `make test-hw` and the workflow.** In the `Makefile`, add to `.PHONY` and:

```make
# Hardware-key tests against SoftHSM2 and swtpm (plan 9c; decision 42 ruling
# 13), built with CGO_ENABLED=0 so purego runs as the shipped binary does.
# Needs softhsm2 and swtpm on PATH; PORT49_TEST_HW_REQUIRED makes a missing
# one a failure, not a skip.
test-hw:
	CGO_ENABLED=0 PORT49_TEST_HW_REQUIRED=1 go test -tags hwkey ./internal/hwkey/... ./internal/agent/... ./cmd/port49/... -run 'HW|SoftHSM|TPM|Unplug|Wrong|Tokens|Certificate' -count=1 -timeout 20m
	CGO_ENABLED=0 go build -o /dev/null ./cmd/port49
```

  `.github/workflows/hwkeys.yml`:

```yaml
# Hardware-key tests (plan 9c): SoftHSM2 and swtpm, no lab captures needed,
# so they run here as well as on the lab machine.
name: hwkeys
on:
  push: {branches: [main]}
  pull_request:
permissions: {contents: read}
jobs:
  hw:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version-file: go.mod}
      - run: sudo apt-get update && sudo apt-get install -y softhsm2 swtpm swtpm-tools
      - run: make test-hw
```

- [ ] **Step 8: Run**

Run: `make test-hw` (on a host with softhsm2; install with `sudo apt-get install -y softhsm2 swtpm swtpm-tools`), then `make test && make vet`.
Expected: PASS; paste the summary lines. Mutation check: change `fnSign` to 44 and see
`TestASoftHSMKeySignsATLSHandshakeAndARefresh` fail; restore.

- [ ] **Step 9: Commit**

```bash
git add internal/hwkey Makefile .github/workflows/hwkeys.yml go.mod go.sum
git commit -m "feat: PKCS#11 keys through purego, tested on SoftHSM2

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: TPM 2.0 through go-tpm, and swtpm in CI

**Files:**
- Create: `internal/hwkey/tpm/tpm.go`, `tss2.go`, `tss2_test.go`
- Create: `internal/hwkey/tpm/swtpm_test.go` (`//go:build hwkey`)
- Modify: `internal/hwkey/hwtest/hwtest.go` (add `SWTPM`)

**Interfaces:**
- Produces:

```go
// Dial opens the TPM: /dev/tpmrm0. A var so the hwkey tests dial swtpm.
var Dial = func() (transport.TPMCloser, error) { return linuxtpm.Open("/dev/tpmrm0") }

type Signer struct{ /* path, public, private blobs, ecdsa public key, state */ }

func Generate(path string) (*Signer, error)     // a P-256 sign key under the ECC SRK, written as a TSS2 file 0600
func Open(path string) (*Signer, error)         // a TSS2 file
func OpenHandle(handle uint32) (*Signer, error) // a persistent key, 0x81000000–0x81FFFFFF

func EncodeTSS2(pub tpm2.TPM2BPublic, priv tpm2.TPM2BPrivate) ([]byte, error)
func DecodeTSS2(pemBytes []byte) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, error)
```

- [ ] **Step 1: Write the failing tests.** `internal/hwkey/tpm/tss2_test.go`: a `TPM2BPublic` and
  `TPM2BPrivate` built with `tpm2.New2B` round-trip through `EncodeTSS2`/`DecodeTSS2`; the PEM type
  is `TSS2 PRIVATE KEY`; the OID is `2.23.133.10.1.3` (loadable key); `emptyAuth` is true; parent
  `0x40000001`; a file with another OID, a `policy` or `secret` element, or another parent is
  refused, each naming it.

  `internal/hwkey/tpm/swtpm_test.go` (`//go:build hwkey`):

```go
func TestATPMKeySignsAndSurvivesAReopen(t *testing.T) {
	hwtest.SWTPM(t) // sets Dial to swtpm over TCP for this test
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	s, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	msg := api.RefreshMessage(make([]byte, api.RefreshNonceLen), make([]byte, 32))
	sig, err := api.SignRefresh(s, msg)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), sum[:], sig) {
		t.Fatal("the signature does not verify")
	}
	s.Close()
	again, err := Open(path)
	if err != nil || !again.Public().(*ecdsa.PublicKey).Equal(s.Public()) {
		t.Fatalf("reopen: %v", err)
	}
}

func TestATPMKeyFromAnotherTPMDoesNotLoad(t *testing.T) {
	hwtest.SWTPM(t)
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	if _, err := Generate(path); err != nil {
		t.Fatal(err)
	}
	hwtest.SWTPMFresh(t) // a second swtpm with its own state: another machine
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "this machine's TPM") {
		t.Fatalf("Open on another TPM = %v, want refused naming this machine's TPM", err)
	}
}

func TestATPMGoneIsAbsent(t *testing.T) {
	stop := hwtest.SWTPM(t)
	s, _ := Generate(filepath.Join(t.TempDir(), "k.tpmkey"))
	stop()
	if _, err := s.Sign(nil, make([]byte, 32), crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) || s.State() != hwkey.Absent {
		t.Fatalf("Sign with swtpm stopped = %v, state %v", err, s.State())
	}
}
```

  `hwtest.SWTPM(t)` starts `swtpm socket --tpm2 --server type=tcp,port=P --ctrl type=tcp,port=P+1
  --tpmstate dir=D --flags not-need-init,startup-clear` on two free ports, sets `tpm.Dial` to
  `tcp.Open(tcp.Config{CommandAddress: …, PlatformAddress: …})` after `PowerOn`, and returns a stop
  function (also registered with `t.Cleanup`). `hwtest.SWTPMFresh(t)` stops the first and starts a
  second swtpm with a new state directory, so its SRK differs: another machine's TPM. The same
  `$PORT49_TEST_HW_REQUIRED` rule as SoftHSM.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/hwkey/tpm/ -count=1` and `CGO_ENABLED=0 go test -tags hwkey ./internal/hwkey/tpm/ -count=1`
Expected: FAIL (undefined).

- [ ] **Step 3: Implement.** `tpm.go`: each operation dials, creates the SRK
  (`tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}`),
  loads the key (`tpm2.Load`), signs (`tpm2.Sign` with `InScheme` ECDSA SHA-256 and a null
  `TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull}`), flushes both handles and
  closes: no handle outlives a call, so a TPM reset or a resource-manager restart costs nothing
  held. The key template: `TPMAlgECC`, `NameAlg` SHA-256, `FixedTPM`, `FixedParent`,
  `SensitiveDataOrigin`, `UserWithAuth`, `SignEncrypt`, curve `TPMECCNistP256`, scheme ECDSA
  SHA-256. The signature `r` and `s` become DER (`cryptobyte`). A dial or transport error is
  `hwkey.ErrKeyAbsent` and `Absent`; `EACCES` on `/dev/tpmrm0` is "port49 cannot open the TPM
  (/dev/tpmrm0): add this user to the tss group, then log in again". A `Load` failing with
  `TPM_RC_INTEGRITY` or `TPM_RC_BAD_AUTH` on a parent is "this key file was made by another
  machine's TPM, not this machine's TPM". `Unlock` is a no-op (empty auth); `State` is `Present`
  until a call fails as absent. `tss2.go`: `encoding/asn1` over the key-file structure, PEM type
  `TSS2 PRIVATE KEY`.

- [ ] **Step 4: Run**

Run: `go test ./internal/hwkey/... -count=1` and `make test-hw`
Expected: PASS. Mutation check: drop `FixedTPM` from the template and see nothing fail; then add a
unit test asserting the template's attributes (`TestTheKeyIsFixedToTheTPM`) and see it fail; restore.

- [ ] **Step 5: Commit**

```bash
git add internal/hwkey/tpm internal/hwkey/hwtest go.mod go.sum
git commit -m "feat: TPM 2.0 keys through go-tpm, tested on swtpm

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Key references in login and the agent; the PIN; `Unlock` and the key's state

**Files:**
- Modify: `internal/hwkey/hwkey.go` (`Open`, `LoadPair`)
- Modify: `internal/userconfig/userconfig.go` (fields `TouchKey`, `IssuedKeyStore`, `IssuedKey`,
  `BrokerCRL`; references not resolved as paths; `CheckOwned` exported)
- Modify: `cmd/port49/main.go` (`sessionFlags`: `--touch-key`, `--pin-fd`; `config` loads through
  `hwkey.LoadPair`; `startAgentDown` passes the PIN on descriptor 4; `login` asks the PIN, unlocks a
  running agent)
- Modify: `internal/agent/agent.go` (`Config.TouchKey`; `Status.KeyState`; `POST /unlock`; the
  agent session), `internal/agent/socket.go` (`Client.Unlock`)
- Test: `internal/hwkey/hwkey_test.go`, `internal/userconfig/userconfig_test.go`,
  `cmd/port49/login_hw_test.go` (`//go:build hwkey`), `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: Task 3's `pkcs11.Open`, `Signer.Certificate`; Task 4's `tpm.Open`, `tpm.OpenHandle`.
- Produces:

```go
// Open opens the key a reference names; pin may be nil (the key is then
// Locked where the token needs one).
func Open(ref string, pin []byte) (Key, error)

// LoadPair is keyfile.LoadX509KeyPair for a key that may be a reference:
// a path goes to keyfile unchanged; a reference is opened, and certPath ""
// takes the token's certificate for a pkcs11 key. The certificate's public
// key must be the key's.
func LoadPair(certPath, keyRef string, pin []byte) (tls.Certificate, error)

// agent
type Config struct {
	// … as today, and:
	// TouchKey is the touch_key slot, nil when none is configured.
	TouchKey hwkey.Key
}

type Status struct {
	// … as today, and:
	KeyState string `json:"key_state"` // present | absent | locked; "present" for a file key
	TouchKey bool   `json:"touch_key"`
}

func (c *Client) Unlock(ctx context.Context, pin []byte) error // POST /unlock {"pin": "…"}
```

- [ ] **Step 1: Write the failing tests.**
  - `internal/userconfig/userconfig_test.go`, `TestKeyReferencesAreNotPaths`: a config with
    `key: "pkcs11:id=%01?module-path=/usr/lib/libykcs11.so"`, `touch_key:` the same with `%02`,
    `issued_key_store: tpm`, `broker_crl: require` loads with the references byte for byte (not
    joined to the file's directory); `issued_key_store: floppy` and `broker_crl: maybe` are refused,
    naming the allowed words; the system file's `touch_key` is overridden by the personal file's.
  - `internal/hwkey/hwkey_test.go`, `TestLoadPairRefusesAMismatchedCertificate` (a file key under
    a certificate for another key is refused, as `keyfile` does today) and
    `TestOpenRefusesAnUnknownScheme`.
  - `internal/agent/agent_test.go`, `TestStatusSaysTheKeyState` with a fake `hwkey.Key` (a
    `fakeKey` in the test file: an ECDSA key with a settable state and an `Unlock` that records the
    PIN it got): `GET /status` says `locked`; `Client.Unlock` with `123456` makes it `present`; the
    PIN reached the key once and the agent's log holds no `123456`.
  - `cmd/port49/login_hw_test.go` (`//go:build hwkey`), `TestLoginAsksThePINOnceAndSaysTriesLeft`:
    against SoftHSM2 and the in-process broker the existing login tests use, `port49 login --key
    pkcs11:…` with the PIN piped to a pty: asks once, starts the agent, refreshes; with a wrong PIN:
    exits 1, says "the token refused the PIN", sends no second `C_Login`, never prints the PIN.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/userconfig/ ./internal/hwkey/ ./internal/agent/ -run 'KeyReferences|LoadPair|OpenRefuses|StatusSaysTheKeyState' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `userconfig.File` gains `TouchKey string yaml:"touch_key"`, `IssuedKeyStore string
    yaml:"issued_key_store"` (`auto`, `file`, `tpm`, `secure_enclave`, `pkcs11`), `IssuedKey string
    yaml:"issued_key"`, `BrokerCRL string yaml:"broker_crl"` (`check`, `require`, `off`); `overlay`
    takes each; `parse` resolves `Cert` and `Key` as paths only when `!hwkey.IsRef`, and `TouchKey`
    and `IssuedKey` must be references.
  - `sessionFlags` gains `touchKey`, `pinFD`, `brokerCRL`, `issuedKeyStore`, `issuedKey` with flags
    `--touch-key`, `--pin-fd` (internal), `--broker-crl`; `args()` passes `--touch-key` and
    `--broker-crl`.
  - `sessionFlags.config` loads with `hwkey.LoadPair(s.cert, s.key, pin)`, where `pin` is read from
    `--pin-fd` (at most 64 bytes, the descriptor closed after) in the agent child, and nil in the
    login. `hwkey.LoadPair` and `hwkey.Open` dispatch on the scheme: `pkcs11:` →
    `pkcs11.ParseURI`, then `pin-source` read through `keyfile.ReadSecret` when set; `tpm:file=` →
    `tpm.Open`; `tpm:handle=` → `tpm.OpenHandle`; `secure-enclave:` → an error naming Task 14's gate
    until that task lands.
  - `login`: after loading, a key whose `State()` is `Locked` asks the PIN with
    `term.ReadPassword` on the controlling terminal ("PIN for <token label>: "), or refuses with no
    terminal and no `pin-source` ("this key needs its PIN and there is no terminal to ask it on;
    set pin-source=file:///path in the key's URI"). `Unlock` is called once; a `*hwkey.PINError`
    exits 1 with "the token refused the PIN" and, by its flags, "fewer tries are left" or "one try
    is left before the key locks: unlock it with your token's own tool if it locks". The PIN goes
    to the agent child on a pipe as descriptor 4 (`ExtraFiles` gains it after the CA's), then the
    slice is zeroed.
  - A running agent whose `Status.KeyState` is `locked` (the key was unplugged and is back): `login`
    asks the PIN and calls `Client.Unlock`, then refreshes as today. `absent`: "insert your key and
    run `port49 login` again; your session goes on until <session_ends_at>", exit 1.
  - The agent: `Config.TouchKey` is opened by the agent child from `--touch-key` with the same PIN
    when it is on the same token (same module and token serial), else `Locked` until unlocked.
    `POST /unlock` decodes `{"pin": string}` (at most 64 bytes), calls `Unlock` on the session key
    and the touch key, zeroes the bytes, answers 200 or 401 `pin_refused` with the flags' words.
    The agent draws `agentSession` (32 random bytes) in `New` and sets
    `api.AgentSessionHeader` (`Port49-Agent-Session`, base64url) on every broker request in `doOn`.
  - `hardenAgent` stays first in `agentMain`: no core file holds a PIN either.

- [ ] **Step 4: Run**

Run: `go test ./internal/userconfig/ ./internal/hwkey/... ./internal/agent/ ./cmd/port49/ -count=1`, then `make test-hw`, then `make test && make vet`.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/hwkey internal/userconfig internal/agent cmd/port49
git commit -m "feat: hardware key references in login and the agent, with the PIN asked once

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: The 3am unplug — the key gone never ends the session

**Files:**
- Modify: `internal/agent/agent.go` (`KeyAbsentError`; `refusedReconnect`, `Refresh`, `post`)
- Modify: `cmd/port49/refresh.go`, `cmd/port49/main.go` (`mintFailed`)
- Test: `internal/agent/unplug_test.go`, `internal/agent/unplug_hw_test.go` (`//go:build hwkey`)

**Interfaces:**
- Consumes: `hwkey.Key.State`, `hwkey.ErrKeyAbsent`.
- Produces:

```go
// KeyAbsentError is a request that needed the key while it was gone: a
// refresh, or a reconnect's handshake. It ends nothing.
type KeyAbsentError struct {
	State       hwkey.State // Absent or Locked
	SessionEnds time.Time
}

func (e *KeyAbsentError) Error() string
// Absent: "insert your key; your session goes on until <t> (tokens are
// still minted on the held connection while it stays up)"
// Locked: "your key is back and needs its PIN: run `port49 login`; your
// session goes on until <t>"
```

- [ ] **Step 1: Write the failing tests.** `internal/agent/unplug_test.go`, against the in-process
  broker the agent tests use and a `fakeKey` whose state the test flips:

```go
func TestAKeyUnpluggedNeverEndsTheSession(t *testing.T) {
	b, key := startBrokerWithFakeKey(t)
	a := New(b.agentConfig(key))
	if _, err := a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	key.unplug() // Sign now returns hwkey.ErrKeyAbsent, State Absent

	// The held connection mints: the key was used at the handshake.
	if _, err := a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatalf("mint on the held connection with the key out: %v", err)
	}
	// A refresh needs the key: it says so and ends nothing.
	_, err := a.Refresh(context.Background())
	var absent *KeyAbsentError
	if !errors.As(err, &absent) || !strings.Contains(err.Error(), "insert your key") {
		t.Fatalf("refresh with the key out = %v", err)
	}
	// A reconnect needs the key at the handshake: the broker drops the
	// connection, the next mint dials, and the handshake's signature fails
	// inside crypto/tls as text alone.
	b.closeHeldConnections()
	_, err = a.Mint(context.Background(), "leaf1", false, 0)
	if !errors.As(err, &absent) {
		t.Fatalf("mint needing a reconnect with the key out = %v, want *KeyAbsentError", err)
	}
	select {
	case <-a.Done():
		t.Fatal("the session ended on an unplugged key")
	default:
	}
	// Re-inserted and unlocked, everything works again.
	key.plug()
	if _, err := a.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh after the key came back: %v", err)
	}
}
```

  Also `TestARefusedCertificateStillEndsTheSession`: with the key present and the broker refusing
  the certificate at a reconnect, `a.Done()` closes as today (the change must not swallow a real
  refusal). `internal/agent/unplug_hw_test.go` (`//go:build hwkey`): the same scenario on swtpm,
  `hwtest.SWTPM`'s stop function as the unplug and a restart with the same state directory as the
  re-insertion.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/agent/ -run 'Unplugged|RefusedCertificateStill' -count=1`
Expected: FAIL (the session ends, or the error is a refusal).

- [ ] **Step 3: Implement.** In `Refresh`, before `refreshOnce`, and in `refusedReconnect`, first:

```go
// keyState is the session key's state; a file key is always present.
func (a *Agent) keyState() hwkey.State {
	if k, ok := a.cert.PrivateKey.(hwkey.Key); ok {
		return k.State()
	}
	return hwkey.Present
}
```

  `refusedReconnect(err)` returns `&KeyAbsentError{State: s, SessionEnds: a.SessionEndsAt()}` and
  ends nothing when `keyState()` is not `Present` (crypto/tls's "tls: failed to sign handshake"
  carries no wrapped error, so the state is what is read); otherwise it behaves as today.
  `refreshOnce`'s `api.SignRefresh` error that `errors.Is(err, hwkey.ErrKeyAbsent)` or
  `hwkey.ErrLocked` becomes the same `KeyAbsentError`. The socket answers it `503 key_absent` with
  the error's text; `Client.Token` and `Client.Refresh` rebuild it. `mintFailed` and `refreshCmd`
  print it as is, exit 1.

- [ ] **Step 4: Run**

Run: `go test ./internal/agent/ ./cmd/port49/ -count=1`, `make test-hw`, then `make test && make vet`.
Expected: PASS. Mutation check: make `refusedReconnect` ignore the key state and see
`TestAKeyUnpluggedNeverEndsTheSession` fail at "the session ended"; restore.

- [ ] **Step 5: Commit**

```bash
git add internal/agent cmd/port49
git commit -m "feat: an unplugged key asks to be inserted and ends no session

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Issued keys in hardware — `port49 login --oidc` generates its key in the TPM or a token

**Files:**
- Modify: `cmd/port49/issue.go` (`issueCertificate`, `heldCertificate`, `startIssued`)
- Create: `cmd/port49/issuedkey.go`
- Modify: `internal/userconfig/userconfig.go` (`IssuedPathsIn` returns the TPM key path too)
- Test: `cmd/port49/issuedkey_test.go`, `cmd/port49/issuedkey_hw_test.go` (`//go:build hwkey`)

**Interfaces:**
- Consumes: `tpm.Generate`, `tpm.Open`, `pkcs11.Generate`, `pkcs11.Open`, `hwkey.LoadPair`.
- Produces:

```go
// issuedKeyStore is the store a sign-in's key goes into (decision 45 ruling
// 7), chosen before the sign-in so a store that cannot be used costs no
// password: "file", "tpm", "secure_enclave" or "pkcs11".
func chooseIssuedStore(sf *sessionFlags, stderr io.Writer) (store string, err error)

// newIssuedKey generates the sign-in's key in store: for "file" an ECDSA
// P-256 key in memory, written with the certificate as today; for "tpm" a
// key in tpmPath; for "pkcs11" the object sf.issuedKey names.
func newIssuedKey(store string, sf *sessionFlags, tpmPath string) (crypto.Signer, func() ([]byte, error), error)

// userconfig
func IssuedPathsIn(dir, broker string) (cert, key, tpmKey string, err error)
```

- [ ] **Step 1: Write the failing tests.** `cmd/port49/issuedkey_test.go`:
  `TestChooseIssuedStore` — `auto` on Linux with `tpm.Dial` failing picks `file` and says "no TPM
  this user can use (…); the key is a file"; `tpm` named with the dial failing refuses before any
  sign-in (the test's fake provider records no authorization request); `pkcs11` without
  `issued_key` refuses naming `issued_key`; `secure_enclave` on Linux refuses. `TestAHeldTPMPairIsFound`:
  with `<host>_<port>.tpmkey` and `.pem` present and no `.key`, `heldCertificate` loads through
  `hwkey.LoadPair`. `issuedkey_hw_test.go`: on swtpm, `port49 login --oidc` with the test
  authorization server (plan 9b's) writes `.tpmkey` (0600), no `.key`, the certificate's key is the
  TPM's, and the agent refreshes; on SoftHSM2 with `issued_key_store: pkcs11` and `issued_key:
  "pkcs11:token=port49-test;id=%10?module-path=…"` the key is generated on the token; an object
  `%10` already holding a certificate port49 did not issue (no sign-in URI SAN) is refused, the
  token untouched.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ -run 'ChooseIssuedStore|HeldTPMPair' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.** `issueCertificate` calls `chooseIssuedStore` after `fetchBrokerConfig`
  and before `oidcclient.Discover`; `ecdsa.GenerateKey` becomes `newIssuedKey`; `api.IssuanceNonce`
  takes the signer's `Public()`; `x509.CreateCertificateRequest` takes the signer; the check
  `key.PublicKey.Equal(leaf.PublicKey)` becomes `signer.Public().(interface{ Equal(crypto.PublicKey)
  bool }).Equal(leaf.PublicKey)`. Writing: for `file` as today; for `tpm` the `.tpmkey` was written
  by `tpm.Generate` (to a staged name, renamed with the certificate through `WritePrivateAll`'s
  order: key first, certificate last) and any old `.key` removed; for `pkcs11` the certificate alone.
  `startIssued` passes `--key` as the path or reference. `heldCertificate` looks for `.key`, then
  `.tpmkey` (`tpm:file=…`), then, with `issued_key_store: pkcs11`, the reference; a held pair whose
  key is absent says "your key (<store>) is not present: insert it, or `port49 login --sign-in`
  signs in for a new one".

- [ ] **Step 4: Run**

Run: `go test ./cmd/port49/ ./internal/userconfig/ -count=1`, `make test-hw`, `make test && make vet`.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49 internal/userconfig
git commit -m "feat: port49 login --oidc generates its key in the TPM or a token

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: The broker certificate's CRL check

**Files:**
- Create: `internal/brokercrl/brokercrl.go`, `internal/brokercrl/brokercrl_test.go`
- Modify: `internal/agent/agent.go` (`Config.VerifyBroker` into the dialer's `tls.Config`)
- Modify: `cmd/port49/issue.go` (`requestCertificate`, `fetchBrokerConfig`), `cmd/port49/main.go`
  (`sessionFlags.config`), `internal/workload/client.go` (`Config.VerifyBroker`),
  `cmd/port49/workload.go` (`--broker-crl`)

**Interfaces:**
- Consumes: `certstatus.New`, `certstatus.Config`, `certstatus.CRLSource`, `Checker.LoadPersisted`,
  `Checker.LoadAll`, `Checker.Check`; `metrics.New`.
- Produces:

```go
type Mode string

const (
	ModeCheck   Mode = "check"   // revoked refuses; unavailable is said and goes on
	ModeRequire Mode = "require" // revoked and unavailable both refuse
	ModeOff     Mode = "off"
)

// Checker checks the broker's verified chain against the CRLs its
// certificates name, keeping the last good list of each in dir.
type Checker struct{ /* … */ }

func New(dir string, mode Mode, now func() time.Time, warn func(string)) *Checker

// VerifyConnection is a tls.Config.VerifyConnection: it runs after the
// chain verified and before any request is written.
func (c *Checker) VerifyConnection(cs tls.ConnectionState) error

// RevokedError is a broker certificate a list names.
type RevokedError struct{ Subject, Serial, List string }

func (e *RevokedError) Error() string
// "the broker's certificate <subject> (serial <hex>) is revoked by <list>;
// nothing was sent to it; tell the broker's operator"
```

- [ ] **Step 1: Write the failing test.** `internal/brokercrl/brokercrl_test.go`, with a
  `testpki.NewCA`, a broker leaf naming `http://<httptest>/ca.crl` as its distribution point, and
  a `httptest` server serving a CRL the test signs:

```go
func TestBrokerCRLModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    Mode
		serve   string // "good" | "revoked" | "down" | "forged"
		noDP    bool
		refused bool
		said    string
	}{
		{"good list", ModeCheck, "good", false, false, ""},
		{"revoked under check", ModeCheck, "revoked", false, true, ""},
		{"revoked under require", ModeRequire, "revoked", false, true, ""},
		{"down under check goes on, said once", ModeCheck, "down", false, false, "could not check the broker certificate's revocation"},
		{"down under require refuses", ModeRequire, "down", false, true, ""},
		{"a list another key signed is not a list", ModeCheck, "forged", false, false, "could not check"},
		{"no distribution point: nothing checked, nothing said", ModeRequire, "down", true, false, ""},
		{"off checks nothing", ModeOff, "revoked", false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, srv := brokerChain(t, tc.serve, tc.noDP)
			var said []string
			c := New(t.TempDir(), tc.mode, time.Now, func(s string) { said = append(said, s) })
			err := c.VerifyConnection(cs)
			if (err != nil) != tc.refused {
				t.Fatalf("VerifyConnection = %v, refused want %v", err, tc.refused)
			}
			if tc.serve == "revoked" && tc.refused {
				var re *RevokedError
				if !errors.As(err, &re) {
					t.Fatalf("want *RevokedError, got %T", err)
				}
			}
			_ = c.VerifyConnection(cs) // a second connection says nothing new
			if tc.said == "" && len(said) != 0 || tc.said != "" && (len(said) != 1 || !strings.Contains(said[0], tc.said)) {
				t.Fatalf("said %q", said)
			}
			_ = srv
		})
	}
}

func TestTheLastGoodListOutlivesTheServerUntilItsNextUpdate(t *testing.T) { /* fetched once, server stopped, a new Checker on the same dir is answered from the kept list until NextUpdate, then says it could not check */ }

func TestNoBearerTokenReachesARevokedBroker(t *testing.T) { /* requestCertificate against an httptest TLS server with a revoked leaf under check: the server's handler is never called */ }
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/brokercrl/ -count=1`
Expected: FAIL (`undefined: New`).

- [ ] **Step 3: Implement.** For each certificate `chain[i]` of `cs.VerifiedChains[0]` but the
  root, each `CRLDistributionPoints` URL with scheme `http` or `https` is a `certstatus.CRLSource{
  Name: <host>-<first 8 hex of SHA-256(url)>, URL: url, Issuer: chain[i+1]}`; none at all and the
  check returns nil. `certstatus.New(certstatus.Config{CRLs: srcs, StateDir: dir}, now,
  metrics.New(prometheus.NewRegistry()), logf)` is built once per distinct source set and kept;
  `LoadPersisted`, then `LoadAll` with a 5s context when no kept list is fresh. `Check(ctx,
  chain)`: `Revoked` → `*RevokedError` (both modes); `Unknown` → under `check` `warn(...)` once per
  `Checker` and nil, under `require` an error naming the list and "broker_crl: require". `dir` is
  `~/.port49/crl/`, made 0700 through `userconfig.PrivateDir`. `sessionFlags.config`,
  `fetchBrokerConfig`, `requestCertificate` and the `/v1/mfa` client (Task 13) set
  `VerifyConnection`; the agent's `tls.Dialer.Config` gets it from `Config.VerifyBroker`; the
  workload client from its own `Config.VerifyBroker`. The warning goes to the agent's log and, in
  `login`, to stderr.

- [ ] **Step 4: Run**

Run: `go test ./internal/brokercrl/ ./internal/agent/ ./internal/workload/ ./cmd/port49/ -count=1`, then `make test && make vet`.
Expected: PASS. Mutation check: return nil for `Revoked` under `check` and see the two revoked cases
fail; restore.

- [ ] **Step 5: Commit**

```bash
git add internal/brokercrl internal/agent internal/workload cmd/port49
git commit -m "feat: the agent checks the broker certificate against its CRL

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: `per_login_mfa` in the policy — four levels, the strictest wins, explain, test and diff

**Files:**
- Create: `internal/policy/mfa.go`, `internal/policy/mfa_test.go`
- Modify: `internal/policy/file.go` (`file.Defaults`, `fileRole.PerLoginMFA`,
  `fileScope.PerLoginMFA`, `fileTest.PerLoginMFA`), `internal/policy/load.go` (parse, the joint
  check), `internal/policy/scope.go` (`composition.scopes`), `internal/policy/resolve.go`
  (`Resolution.PerLoginMFA`), `internal/policy/explain.go` (render), `internal/policy/tests.go`
  (the assertion), `internal/policy/diff.go` (the change and the weakening warning)

**Interfaces:**
- Produces:

```go
type MFAMethod string

const (
	HardwareKeyTouch MFAMethod = "hardware_key_touch"
	IdPMFA           MFAMethod = "idp_mfa"
)

// PerLoginMFA is one level's per_login_mfa as written.
type PerLoginMFA struct {
	Accept            []MFAMethod
	ReuseFor          time.Duration
	AppliesToMachines bool
}

// MFALevel is one level that applies on a device: "defaults", "role
// <name>" or "scope <name>", and what it accepts.
type MFALevel struct {
	Level    string
	Accept   []MFAMethod
	ReuseFor time.Duration
}

// MFARequirement is a device's effective requirement for one subject:
// Accept the intersection, ReuseFor the least, ReuseFrom the level that
// set it, and every level that applied. Levels is empty when there is none.
type MFARequirement struct {
	Accept    []MFAMethod
	ReuseFor  time.Duration
	ReuseFrom string
	Levels    []MFALevel
}

func (r MFARequirement) Required() bool { return len(r.Levels) > 0 }
func (r MFARequirement) Accepts(m MFAMethod) bool

// ErrMFADisjoint is two levels on one device whose accept lists share no
// method.
var ErrMFADisjoint = errors.New("policy: per_login_mfa levels accept no common method")

// in Resolution:
//	PerLoginMFA MFARequirement
```

- [ ] **Step 1: Write the failing tests** in `internal/policy/mfa_test.go`. A policy builder
  `mfaPolicy(t, yaml string)` loads YAML through the package's existing test loader with an
  inventory of `core-sw01` (`tier: core`, `arista_eos`), `edge-sw01` (`tier: edge`) and a subject
  `alice` (`user:alice@example.com`) granted role `netadmin` on `all_devices`, and a machine subject
  `oxidized` (`spiffe://example.com/oxidized`) granted `backup` on `all_devices`:

```go
// strictestPolicy is three levels on core-sw01 and two on edge-sw01.
const strictestPolicy = `
defaults:
  per_login_mfa: {accept: [hardware_key_touch, idp_mfa]}
roles:
  - name: netadmin
    permit: ["**"]
    per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 30m}
scopes:
  - name: core
    match: {tier: core}
    on_missing: include
    security_log: true
    per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}
`

func TestTheStrictestLevelWins(t *testing.T) {
	p := mfaPolicy(t, strictestPolicy)
	res := resolve(t, p, "alice", "core-sw01")
	want := MFARequirement{Accept: []MFAMethod{HardwareKeyTouch}, ReuseFor: 5 * time.Minute, ReuseFrom: "scope core",
		Levels: []MFALevel{
			{Level: "defaults", Accept: []MFAMethod{HardwareKeyTouch, IdPMFA}, ReuseFor: 15 * time.Minute},
			{Level: "role netadmin", Accept: []MFAMethod{HardwareKeyTouch, IdPMFA}, ReuseFor: 30 * time.Minute},
			{Level: "scope core", Accept: []MFAMethod{HardwareKeyTouch}, ReuseFor: 5 * time.Minute},
		}}
	if !reflect.DeepEqual(res.PerLoginMFA, want) {
		t.Fatalf("core-sw01: %+v\nwant %+v", res.PerLoginMFA, want)
	}
	edge := resolve(t, p, "alice", "edge-sw01")
	if edge.PerLoginMFA.ReuseFor != 15*time.Minute || len(edge.PerLoginMFA.Accept) != 2 {
		t.Fatalf("edge-sw01: %+v", edge.PerLoginMFA)
	}
}

func TestOneDeviceIsAScopeByName(t *testing.T) {
	p := mfaPolicy(t, `
scopes:
  - name: core-sw01
    match: {name: core-sw01}
    per_login_mfa: {accept: [hardware_key_touch], reuse_for: 0m}
`)
	if r := resolve(t, p, "alice", "core-sw01").PerLoginMFA; !r.Required() || r.ReuseFor != 0 {
		t.Fatalf("core-sw01: %+v", r)
	}
	if r := resolve(t, p, "alice", "edge-sw01").PerLoginMFA; r.Required() {
		t.Fatalf("edge-sw01 has a requirement: %+v", r)
	}
}

func TestDisjointLevelsRefuseTheLoad(t *testing.T) {
	_, err := loadMFA(`
roles:
  - name: netadmin
    permit: ["**"]
    per_login_mfa: {accept: [idp_mfa]}
scopes:
  - name: core
    match: {tier: core}
    on_missing: include
    security_log: true
    per_login_mfa: {accept: [hardware_key_touch]}
`)
	if !errors.Is(err, ErrMFADisjoint) || !strings.Contains(err.Error(), "role netadmin") ||
		!strings.Contains(err.Error(), "scope core") || !strings.Contains(err.Error(), "core-sw01") {
		t.Fatalf("load = %v, want ErrMFADisjoint naming both levels and the device", err)
	}
	// A machine-applying level that leaves a machine only idp_mfa: a machine
	// has no sign-in.
	_, err = loadMFA(`
defaults:
  per_login_mfa: {accept: [idp_mfa], applies_to_machines: true}
`)
	if err == nil || !strings.Contains(err.Error(), "machine") || !strings.Contains(err.Error(), "hardware_key_touch") {
		t.Fatalf("load = %v, want a refusal saying a machine proves by hardware_key_touch", err)
	}
}

func TestMachinesAreExemptUnlessALevelSaysSo(t *testing.T) {
	p := mfaPolicy(t, `
defaults:
  per_login_mfa: {accept: [hardware_key_touch]}
`)
	if r := resolve(t, p, "oxidized", "core-sw01").PerLoginMFA; r.Required() {
		t.Fatalf("a machine under defaults alone has a requirement: %+v", r)
	}
	p = mfaPolicy(t, `
defaults:
  per_login_mfa: {accept: [hardware_key_touch], applies_to_machines: true}
`)
	if r := resolve(t, p, "oxidized", "core-sw01").PerLoginMFA; !r.Required() {
		t.Fatal("applies_to_machines: true did not apply")
	}
}

func TestPerLoginMFASchemaRefusals(t *testing.T) {
	for _, bad := range []struct{ yaml, says string }{
		{`defaults: {per_login_mfa: {accept: []}}`, "accept"},
		{`defaults: {per_login_mfa: {}}`, "accept"},
		{`defaults: {per_login_mfa: {accept: [none]}}`, "none"},
		{`defaults: {per_login_mfa: {accept: [true]}}`, "hardware_key_touch or idp_mfa"},
		{`defaults: {per_login_mfa: {accept: [idp_mfa, idp_mfa]}}`, "twice"},
		{`defaults: {per_login_mfa: {accept: [idp_mfa], reuse_for: 9h}}`, "8h"},
		{`defaults: {per_login_mfa: {accept: [idp_mfa], reuse_for: -1m}}`, "reuse_for"},
		{`defaults: {per_login_mfa: {accept: [idp_mfa], required: true}}`, "required"},
		{`defaults: {mfa: required}`, "mfa"},
		{"scopes:\n  - name: core\n    match: {tier: core}\n    security_log: true\n    per_login_mfa: {accept: [idp_mfa]}", "on_missing"},
		{"scopes:\n  - name: core\n    match: {tier: core}\n    on_missing: include\n    per_login_mfa: {accept: [idp_mfa]}", "security_log"},
	} {
		if _, err := loadMFA(bad.yaml); err == nil || !strings.Contains(err.Error(), bad.says) {
			t.Errorf("load %q = %v, want an error naming %q", bad.yaml, err, bad.says)
		}
	}
}

func TestExplainPrintsTheEffectiveRequirement(t *testing.T) {
	p := mfaPolicy(t, strictestPolicy) // TestTheStrictestLevelWins's YAML, as a package const
	for device, want := range map[string]string{
		"core-sw01": "  per_login_mfa accept hardware_key_touch (defaults ∩ role netadmin ∩ scope core); " +
			"reuse_for 5m (scope core); applies to humans\n",
		"edge-sw01": "  per_login_mfa accept hardware_key_touch, idp_mfa (defaults ∩ role netadmin); " +
			"reuse_for 15m (defaults); applies to humans\n",
	} {
		e, err := p.Explain("alice", "", device, "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		e.RenderWithoutAttributes(&b)
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s: explain says\n%s\nwant the line %q", device, b.String(), want)
		}
	}
	none := mfaPolicy(t, "")
	e, _ := none.Explain("alice", "", "core-sw01", "", time.Now())
	var b strings.Builder
	e.RenderWithoutAttributes(&b)
	if !strings.Contains(b.String(), "  per_login_mfa none\n") {
		t.Errorf("no requirement: explain says\n%s", b.String())
	}
}

func TestPolicyTestAssertsTheRequirement(t *testing.T) { /* a session test with per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m} passes; with reuse_for: 15m fails naming both */ }

func TestPolicyDiffWarnsOnAWeakening(t *testing.T) { /* scope core's accept gains idp_mfa: the diff prints "per_login_mfa:" for alice on core-sw01 and a "warning:" line; a tightening prints the change and no warning */ }
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ -run 'StrictestLevel|OneDeviceIsAScope|DisjointLevels|MachinesAreExempt|PerLoginMFASchema|ExplainPrintsTheEffective|PolicyTestAssertsTheRequirement|PolicyDiffWarnsOnAWeakening' -count=1`
Expected: FAIL (undefined).

- [ ] **Step 3: Implement.**
  - `file.go`: `Defaults *fileDefaults yaml:"defaults"` with `PerLoginMFA *fileMFA
    yaml:"per_login_mfa"`; `fileMFA{Accept []string yaml:"accept"; ReuseFor *string
    yaml:"reuse_for"; AppliesToMachines bool yaml:"applies_to_machines"}`; `PerLoginMFA *fileMFA
    yaml:"per_login_mfa"` on `fileRole` and `fileScope`; `PerLoginMFA *fileTestMFA
    yaml:"per_login_mfa"` on `fileTest` (`none` as a scalar, or `{accept, reuse_for}`).
  - `mfa.go`: `parseMFA(at string, f *fileMFA) (*PerLoginMFA, error)` with ruling 10's checks; the
    levels in a fixed order (`defaults`, roles in `c.roles` order, scopes sorted); and:

```go
// mfaFor is the requirement on d for c (decision 45 ruling 11): every
// level that applies, the intersection of their accept lists, the least
// reuse_for. A machine's composition reads only the levels that apply to
// machines.
func (p *Policy) mfaFor(c composition) (MFARequirement, error) {
	machine := c.subject.Domain == DomainMachines
	var levels []MFALevel
	add := func(name string, m *PerLoginMFA) {
		if m == nil || machine && !m.AppliesToMachines {
			return
		}
		levels = append(levels, MFALevel{Level: name, Accept: m.Accept, ReuseFor: m.ReuseFor})
	}
	add("defaults", p.defaults.PerLoginMFA)
	for _, r := range c.roles {
		add("role "+r, p.roles[r].PerLoginMFA)
	}
	for _, s := range c.scopes {
		add("scope "+s, p.scopes[s].PerLoginMFA)
	}
	if len(levels) == 0 {
		return MFARequirement{}, nil
	}
	req := MFARequirement{Accept: slices.Clone(levels[0].Accept), ReuseFor: levels[0].ReuseFor,
		ReuseFrom: levels[0].Level, Levels: levels}
	for _, l := range levels[1:] {
		next := slices.DeleteFunc(slices.Clone(req.Accept), func(m MFAMethod) bool { return !slices.Contains(l.Accept, m) })
		if len(next) == 0 {
			first := levels[slices.IndexFunc(levels, func(o MFALevel) bool {
				return !slices.ContainsFunc(o.Accept, func(m MFAMethod) bool { return slices.Contains(l.Accept, m) })
			})]
			return MFARequirement{}, fmt.Errorf("%w: %s accepts %v and %s accepts %v", ErrMFADisjoint,
				first.Level, first.Accept, l.Level, l.Accept)
		}
		req.Accept = next
		if l.ReuseFor < req.ReuseFor {
			req.ReuseFor, req.ReuseFrom = l.ReuseFor, l.Level
		}
	}
	if machine && !req.Accepts(HardwareKeyTouch) {
		return MFARequirement{}, fmt.Errorf("policy: per_login_mfa: a machine principal proves by hardware_key_touch "+
			"alone, and %s leave it %v", levelNames(levels), req.Accept)
	}
	return req, nil
}
```

  - `levelNames(levels []MFALevel) string` joins the levels' names with ", " (in `mfa.go`). With
    two methods, an empty intersection always has an earlier level disjoint from the one that
    emptied it, so the `IndexFunc` above finds one; a third method added to the vocabulary must
    revisit this (a comment says so).
  - `load.go`'s `Policy` gains `defaults struct{ PerLoginMFA *PerLoginMFA }`, filled from
    `file.Defaults`; `Role.PerLoginMFA` and `Scope.PerLoginMFA` are `*PerLoginMFA`.
  - `scope.go`: `composeAll` appends every scope that selects `d` (the loop that attaches roles
    already visits them) to `c.scopes`, sorted.
  - `resolve.go`: `resolved` sets `res.PerLoginMFA, err = p.mfaFor(c)` and returns the error.
  - `load.go`: the joint check that compiles every subject on every device reports an
    `ErrMFADisjoint` (or the machine refusal) as a load error with the subject and device, never a
    quarantine: it is the policy's fault, not the device's. A scope with a match key and
    `per_login_mfa` must have `onMissingDeclared` and `SecurityLog`.
  - `explain.go`: after the `session` line, ruling 17's `per_login_mfa` line ("applies to humans",
    or "applies to machines too" when a level sets it, for a machine principal "applies to this
    machine").
  - `tests.go`: the assertion compares `Accept` as a set and `ReuseFor`.
  - `diff.go`: per subject and device, the requirement before and after; printed when it differs;
    a `warning:` when after's `Accept` is not a subset of before's, after's `ReuseFor` is longer, or
    after is not `Required()` and before was.

- [ ] **Step 4: Run**

Run: `go test ./internal/policy/ -count=1`, then `make test && make vet`.
Expected: PASS. Mutation checks, each restored: make `mfaFor` take the union (see
`TestTheStrictestLevelWins` and `TestDisjointLevelsRefuseTheLoad` fail); drop the machine filter
(see `TestMachinesAreExemptUnlessALevelSaysSo` fail).

- [ ] **Step 5: Commit**

```bash
git add internal/policy
git commit -m "feat: per_login_mfa in the policy, the strictest level wins

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: The PIV attestation verifier

**Files:**
- Create: `internal/pivattest/pivattest.go`, `internal/pivattest/pivattest_test.go`

**Interfaces:**
- Produces:

```go
const (
	TouchNever  = 0x01
	TouchAlways = 0x02
	TouchCached = 0x03
)

// Attestation is what a YubiKey's attestation certificate for one slot
// says (Yubico's PIV attestation, the extensions under 1.3.6.1.4.1.41482.3).
type Attestation struct {
	Key         crypto.PublicKey
	Serial      uint32
	PINPolicy   byte
	TouchPolicy byte
	Device      *x509.Certificate // the f9 certificate it is signed by
}

// Verify checks slot against device and device against roots at now, and
// reads slot's policy. device's signature over slot is checked directly:
// some f9 certificates carry no basic constraints, which x509.Verify
// refuses for an intermediate (go-piv v2.6.0 piv/key.go:241-247).
func Verify(roots *x509.CertPool, device, slot *x509.Certificate, now time.Time) (Attestation, error)
```

- [ ] **Step 1: Write the failing test** `internal/pivattest/pivattest_test.go`, with a test root
  (`testpki.NewCA`), a device certificate it signs with no basic constraints (as some f9s have), and
  slot certificates the device signs carrying the extensions:

```go
func TestVerify(t *testing.T) {
	root, device, deviceKey := yubicoLike(t) // device: v3, BasicConstraintsValid false
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	now := time.Now()
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 12345678, pin: 0x02, touch: TouchAlways})
	a, err := Verify(roots, device, slot, now)
	if err != nil || a.Serial != 12345678 || a.TouchPolicy != TouchAlways || a.PINPolicy != 0x02 {
		t.Fatalf("Verify = %+v, %v", a, err)
	}
	for _, bad := range []struct {
		name  string
		slot  *x509.Certificate
		roots *x509.CertPool
	}{
		{"another root", slot, x509.NewCertPool()},
		{"a slot another device signed", slotCert(t, otherDevice(t, root), nil, slotOpts{serial: 1, pin: 2, touch: TouchAlways}), roots},
		{"a key policy of three bytes", slotCert(t, device, deviceKey, slotOpts{rawPolicy: []byte{2, 2, 2}}), roots},
		{"no key policy", slotCert(t, device, deviceKey, slotOpts{noPolicy: true}), roots},
		{"a negative serial", slotCert(t, device, deviceKey, slotOpts{serial: -1, pin: 2, touch: 2}), roots},
	} {
		if _, err := Verify(bad.roots, device, bad.slot, now); err == nil {
			t.Errorf("%s: verified", bad.name)
		}
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/pivattest/ -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.** `device.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
  KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})`; then
  `device.CheckSignature(slot.SignatureAlgorithm, slot.RawTBSCertificate, slot.Signature)`; then
  `slot`'s validity at `now`; then the extensions: serial (1.3.6.1.4.1.41482.3.7, an ASN.1
  INTEGER, 0 to 2³²−1), policy (…3.8, exactly two bytes, each a known value), both required. The
  slot's own key is `slot.PublicKey`.

- [ ] **Step 4: Run**

Run: `go test ./internal/pivattest/ -count=1`
Expected: PASS. Mutation check: skip the `CheckSignature` step and see "a slot another device signed"
fail; restore.

- [ ] **Step 5: Commit**

```bash
git add internal/pivattest
git commit -m "feat: verify YubiKey PIV attestations against the operator's roots

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: The broker — challenges, proofs, `POST /v1/mfa`, the mint under a requirement

**Files:**
- Modify: `internal/decision/reasons.go` (event, four reasons), `internal/decision/log.go`
  (`Record.PerLoginMFA`, `decision.PerLoginMFA`)
- Modify: `internal/daemon/metrics/metrics.go` (`PerLoginMFA` counter)
- Modify: `internal/store/store.go` (`Credential.MFAMethod`, `Credential.MFAAt`, `MFAProof`,
  `PutMFAProof`, `GetMFAProof`), `internal/store/memory/memory.go`, `internal/store/etcd/oidc.go`
  (and `keys.go` for `k.mfaProof`), `internal/store/etcd/records.go` (`credRec` gains the two
  fields in the same order), `internal/store/crypt/crypt.go`, `internal/store/guard/guard.go`,
  `internal/store/storetest/oidc.go` (conformance)
- Modify: `internal/token/minter.go` (`Subject.Credential` carries the MFA fields through;
  `Request.PerLoginMFA *decision.PerLoginMFA`, copied into the permit record it writes)
- Modify: `internal/broker/api/api.go` (types below), `internal/broker/broker.go` (`Broker.PerLoginMFA`,
  route, `tokens`, `mintOne`, `config`)
- Create: `internal/broker/mfa.go`, `internal/broker/mfa_test.go`
- Modify: `internal/config/identity.go` (`broker.identity.per_login_mfa`), `internal/oidc/config.go`
  (`PerLoginMFA` config), `internal/port49d/brokerd.go` and `internal/port49d/main.go` (wire it)
- Modify: `internal/broker/issue.go` (decision 43 ruling 13's exception for `/v1/mfa`)

**Interfaces:**
- Consumes: Task 9's `Resolution.PerLoginMFA`, `MFARequirement.Accepts`; Task 10's
  `pivattest.Verify`; `oidc.Set`'s human verification (as `issue.go` calls it).
- Produces (`internal/broker/api`):

```go
// AgentSessionHeader carries the agent's session: 32 random bytes,
// base64url, drawn at the agent's start (decision 45 ruling 15).
const AgentSessionHeader = "Port49-Agent-Session"

// MFAExporterLabel is the TLS exporter label a touch proof covers.
const MFAExporterLabel = "EXPORTER-port49-per-login-mfa"

// MFAChallengeLen is a challenge's length in bytes.
const MFAChallengeLen = 32

// MFAMessage is what the touch key signs: a fixed context, the challenge,
// and the held connection's exporter value.
func MFAMessage(challenge, ekm []byte) []byte

// MFANonce is the nonce an idp_mfa sign-in carries:
// base64url(SHA-256("port49 per-login v1\0" ‖ challenge)).
func MFANonce(challenge []byte) string

// MFALevel is one level of a requirement, as the API and the record say it.
type MFALevel struct {
	Level           string   `json:"level"`
	Accept          []string `json:"accept"`
	ReuseForSeconds int      `json:"reuse_for_seconds"`
}

// PerLoginMFA is a requirement an item or a refresh answers with: the
// device, the challenge to prove, the policy's accept, the methods this
// broker verifies of them, and where each part came from.
type PerLoginMFA struct {
	Device          string     `json:"device,omitempty"`
	Challenge       string     `json:"challenge"`
	ExpiresAt       string     `json:"expires_at"`
	Accept          []string   `json:"accept"`
	Methods         []string   `json:"methods"`
	ReuseForSeconds int        `json:"reuse_for_seconds"`
	ReuseFrom       string     `json:"reuse_from"`
	Levels          []MFALevel `json:"levels"`
}

// in MintRequest:
//	PerLoginMFAChallenge string `json:"per_login_mfa_challenge,omitempty"`
// in MintItem:
//	PerLoginMFA *PerLoginMFA `json:"per_login_mfa,omitempty"`
// in RefreshResponse (Task 12):
//	PerLoginMFA *PerLoginMFA `json:"per_login_mfa,omitempty"`
// in Config:
//	PerLoginMFA *MFAConfig `json:"per_login_mfa,omitempty"`

type MFAConfig struct {
	Methods   []string `json:"methods"`              // what this broker verifies now
	ACRValues string   `json:"acr_values,omitempty"` // sent with an idp_mfa sign-in
}

// MFAProofRequest is POST /v1/mfa's body.
type MFAProofRequest struct {
	Challenge   string   `json:"challenge"`
	Method      string   `json:"method"`                // hardware_key_touch | idp_mfa
	Signature   string   `json:"signature,omitempty"`   // touch: base64url over MFAMessage
	Attestation []string `json:"attestation,omitempty"` // touch: base64url DER: [touch slot, f9 device, session slot]
}

type MFAProofResponse struct {
	Method   string `json:"method"`
	ProvedAt string `json:"proved_at"`
}
```

- Produces (`internal/store`):

```go
type MFAProof struct {
	Key    string // hex SHA-256 of principal, fingerprint and agent session, then "/" and the method
	Method string
	At     time.Time
}

// PutMFAProof keeps p for ttl, the later At kept, as PutLogout keeps the
// later logout.
PutMFAProof(ctx context.Context, p MFAProof, ttl time.Duration) error
// GetMFAProof is the live proof under key, or ErrNotFound.
GetMFAProof(ctx context.Context, key string) (MFAProof, error)

// in Credential (sealed with it):
//	MFAMethod string
//	MFAAt     time.Time
```

- Produces (`internal/broker`):

```go
// MFAVerifiers is broker.identity.per_login_mfa resolved: nil Roots means
// hardware_key_touch is unavailable here; idp_mfa is available while a
// human OIDC verifier is configured.
type MFAVerifiers struct {
	Roots     *x509.CertPool
	AMR       []string // default ["mfa"]
	ACRValues string
}

// in Broker:
//	PerLoginMFA *MFAVerifiers

// mfaCovers says whether a proof covers req for this caller now: the
// challenge's own proof named by the mint (once, whatever reuse_for), else
// a kept proof whose method req accepts, made within req.ReuseFor.
func (b *Broker) mfaCovers(ctx context.Context, c caller, agent string, req policy.MFARequirement,
	proved *provedChallenge, now time.Time) (method string, at time.Time, reused bool, err error)
```

- [ ] **Step 1: Write the failing tests.**
  - `internal/store/storetest/oidc.go`: `MFAProofKeepsTheLaterAndExpires` (as
    `LogoutKeepsTheLaterAndExpires`), added to `Run`'s table; it runs on memory and etcd.
  - `internal/broker/mfa_test.go`, against the broker fixture the mint tests use, with a policy
    whose scope `core` requires `[hardware_key_touch, idp_mfa]` with `reuse_for: 15m` on `core-sw01`,
    a test PIV root, and a client whose "token" is two ECDSA keys with attestations from one test
    device certificate:

```go
func TestAMintUnderARequirementAsksForAProof(t *testing.T) {
	f := newMFAFixture(t)
	resp := f.mint(t, f.alice, "core-sw01", "")
	it := resp.Results[0]
	if it.Verdict != "deny" || it.Reason != "per_login_mfa_required" || it.PerLoginMFA == nil {
		t.Fatalf("item = %+v", it)
	}
	m := it.PerLoginMFA
	if m.Device != "core-sw01" || len(m.Challenge) == 0 || !slices.Equal(m.Methods, []string{"hardware_key_touch", "idp_mfa"}) ||
		m.ReuseForSeconds != 900 || m.Levels[0].Level != "scope core" {
		t.Fatalf("requirement = %+v", m)
	}
	f.assertRecord(t, "mint", "deny", "per_login_mfa_required")
	// Nothing was minted.
	f.assertNoToken(t, "core-sw01")
}

func TestATouchProofCoversTheRetriedMintAndThenReuses(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("POST /v1/mfa = %d", code)
	}
	f.assertRecord(t, "per_login_mfa", "permit", "per_login_mfa_proved")
	it := f.mint(t, f.alice, "core-sw01", ch).Results[0]
	if it.Verdict != "permit" {
		t.Fatalf("retried mint = %+v", it)
	}
	f.assertMintRecordMFA(t, "hardware_key_touch", false)
	// A second login within reuse_for, no challenge named: reused.
	f.clock.Advance(10 * time.Minute)
	if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint within reuse_for = %+v", it)
	}
	f.assertMintRecordMFA(t, "hardware_key_touch", true)
	// Past reuse_for: asked again.
	f.clock.Advance(6 * time.Minute)
	if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("mint past reuse_for = %+v", it)
	}
	// Another agent session of the same person is asked.
	if it := f.mintAs(t, f.alice, f.otherAgent, "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("another agent = %+v", it)
	}
}

func TestReuseForZeroCoversOnlyItsOwnRequest(t *testing.T) { /* scope with reuse_for: 0m: the retried mint naming the challenge is a permit; a second mint a second later is asked again; the challenge named twice is refused the second time */ }

func TestATouchFromAnotherTokenIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
	// The touch slot's attestation comes from another device certificate
	// than the session key's: an attacker's own YubiKey beside a copied
	// session key.
	if code := f.proveTouchWith(t, f.alice, ch, f.otherTokenTouchKey, f.otherTokenAttestations); code != 401 {
		t.Fatalf("POST /v1/mfa = %d, want 401", code)
	}
	f.assertRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
}

func TestATouchSlotNotAlwaysIsRefused(t *testing.T) { /* attestation touch policy cached: 401, the detail says "touch policy always" */ }

func TestATouchProofIsBoundToItsConnection(t *testing.T) { /* the signature over another connection's exporter value: 401 */ }

func TestAChallengeIsUsedOnce(t *testing.T) { /* proved twice: the second 401; proved by bob's connection: 401 and alice's challenge still unspent */ }

func TestAnIdPProofCoversTheMint(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
	tok := f.idToken(t, idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"pwd", "mfa"}, authTime: f.clock.Now()})
	if code := f.proveIdP(t, tok, ch); code != 200 {
		t.Fatalf("POST /v1/mfa (idp) = %d", code)
	}
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
		t.Fatalf("retried mint = %+v", it)
	}
	for _, bad := range []struct {
		name string
		opts func(ch string) idTokenOpts
	}{
		{"another person", func(ch string) idTokenOpts {
			return idTokenOpts{principal: "bob@example.com", nonceFor: ch, amr: []string{"mfa"}, authTime: f.clock.Now()}
		}},
		{"another challenge", func(string) idTokenOpts {
			return idTokenOpts{principal: "alice@example.com", nonceFor: "another challenge", amr: []string{"mfa"}, authTime: f.clock.Now()}
		}},
		{"no second factor", func(ch string) idTokenOpts {
			return idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"pwd"}, authTime: f.clock.Now()}
		}},
		{"auth_time six minutes old", func(ch string) idTokenOpts {
			return idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"mfa"}, authTime: f.clock.Now().Add(-6 * time.Minute)}
		}},
	} {
		ch := f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
		if code := f.proveIdP(t, f.idToken(t, bad.opts(ch)), ch); code != 401 {
			t.Errorf("%s: %d, want 401", bad.name, code)
		}
	}
	// The first token, spent above, is refused a second time.
	ch = f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
	if code := f.proveIdP(t, tok, ch); code != 401 {
		t.Errorf("a spent ID token: %d, want 401", code)
	}
}

func TestUnavailableMethodsAreSaidPerDevice(t *testing.T) { /* no attestation roots and a touch-only scope: deny per_login_mfa_unavailable on core-sw01, edge-sw01 minted as before */ }

func TestTheCredentialCarriesTheProofIntoTheToken(t *testing.T) { /* the minted token's Credential.MFAMethod and MFAAt are the proof's */ }

func TestMachinesAreNotAsked(t *testing.T) { /* the workload subject mints core-sw01 with no proof under a level without applies_to_machines */ }
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'MintUnderARequirement|TouchProof|ReuseForZero|TouchFromAnother|TouchSlotNotAlways|BoundToItsConnection|ChallengeIsUsedOnce|IdPProof|UnavailableMethods|CredentialCarriesTheProof|MachinesAreNotAsked' -count=1` and `go test ./internal/store/... -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `reasons.go`: `PerLoginMFARequired`, `PerLoginMFAProved`, `PerLoginMFARefused`,
    `PerLoginMFAUnavailable` in the `const` block and in `reasons`; `const EventPerLoginMFA =
    "per_login_mfa"`.
  - `log.go`: `PerLoginMFA *PerLoginMFA json:"per_login_mfa,omitempty"` on `Record`;
    `type PerLoginMFA struct { Accept []string json:"accept,omitempty"; ReuseForSeconds *int
    json:"reuse_for_seconds,omitempty"; Levels []string json:"levels,omitempty"; Method string
    json:"method,omitempty"; ProvedAt string json:"proved_at,omitempty"; Reused bool
    json:"reused,omitempty"; ChallengeSHA256 string json:"challenge_sha256,omitempty" }`.
  - `metrics.go`: `port49_per_login_mfa_total{method,outcome}`; outcomes `required`, `proved`,
    `refused`, `reused`, `unavailable`; `method` is `hardware_key_touch`, `idp_mfa` or `none`.
  - store: the type, the two methods in the interface, memory (a map like `logout`), etcd
    (`k.mfaProof(key)` under the token prefix, `casAs` keeping the later `At` and the later
    expiry), crypt and guard as pass-throughs (the key is a hash and the value a clock: no
    identity); `credRec` gains `MFAMethod string json:"mfa_method,omitempty"` and `MFAAt
    time.Time json:"mfa_at,omitempty"` in the same position as `store.Credential`'s new fields
    (last).
  - `internal/config/identity.go`: `identityYAML.PerLoginMFA *perLoginMFAYAML
    yaml:"per_login_mfa"` with `HardwareKeyTouch *struct{ AttestationRootsFile string
    yaml:"attestation_roots_file" } yaml:"hardware_key_touch"` and `IdPMFA *struct{ AMR []string
    yaml:"amr"; ACRValues string yaml:"acr_values" } yaml:"idp_mfa"`; `oidc.Config.PerLoginMFA`.
    port49d and port49-broker read the roots file at start: unreadable or no PEM certificate →
    the start goes on, `hardware_key_touch` unavailable, one line naming the file.
  - `mfa.go`:
    - `agentKey(r *http.Request) string`: the header's 32 bytes, or `""` (a caller without one
      — a workload, a 7h bearer — keeps no reusable proof: each request proves).
    - `proofKey(principal, fingerprint, agent string, m policy.MFAMethod) string`.
    - `issueChallenge(ctx, c caller, agent string) (api challenge bytes, expires, error)`:
      `PutOnce("plm-challenge/"+hex(SHA-256(ch)), json{principal, fingerprint, agent}, 5m)`.
    - `POST /v1/mfa` → `b.mfaProve`: decodes `api.MFAProofRequest` (strict, 64 KiB); `TakeOnce`
      the challenge; for `hardware_key_touch` the caller must be the held connection's and match
      the challenge's principal, fingerprint and agent; the exporter value from `r.TLS`
      (`ExportKeyingMaterial(api.MFAExporterLabel, nil, 32)`); `pivattest.Verify` on the touch
      slot and on the session slot, both against the same device certificate (`bytes.Equal` of
      their `Device.Raw`), touch policy `TouchAlways`, session slot key equal to
      `r.TLS.PeerCertificates[0].PublicKey`, the signature by the touch slot key
      (`api.RefreshAlgorithm` for its type) over `api.MFAMessage`. For `idp_mfa`: the bearer
      verified as `issue.go` verifies one (`b.Identity`, humans only), its principal the
      challenge's, `nonce` equal to `api.MFANonce(ch)`, `auth_time` fresh (5 minutes plus
      `clock_skew`, against `iat` and now), `amr` holding one of `MFAVerifiers.AMR`, the token's
      SHA-256 `PutOnce` for `max_token_age` (a second use 401). On success: `PutOnce
      ("plm-proved/"+hex(SHA-256(ch)), json{method, at, principal, fingerprint, agent}, 5m)`,
      `PutMFAProof(MFAProof{Key: proofKey(...), Method, At: now}, 8h)` when `agent != ""`, the
      record `permit per_login_mfa_proved`, 200 `MFAProofResponse`. Any refusal: 401
      `per_login_mfa_refused` with the cause in `detail`, the record `deny per_login_mfa_refused`
      carrying `challenge_sha256`; a store error 503 `store_unavailable`, recorded.
    - `mfaCovers` as in Interfaces; the named challenge's proved record is `TakeOnce`d once per
      request in `tokens` (before the loop) and held as `*provedChallenge` for every item.
  - `broker.go`: `tokens` reads `api.AgentSessionHeader` and `req.PerLoginMFAChallenge`; issues at
    most one challenge per request, lazily, for the first item that needs one. `mintOne`, after the
    session-ceiling check and before `engine.Encode`: when `res.PerLoginMFA.Required()`:
    available methods = `Accept` ∩ what `b.PerLoginMFA` verifies (touch needs `Roots`, idp needs a
    human OIDC verifier); none → `deny per_login_mfa_unavailable` (record carries the
    requirement); `mfaCovers` → covered: the token's `Credential.MFAMethod`/`MFAAt` set, the
    minter's permit record gets `PerLoginMFA{Method, ProvedAt, Reused, Accept, ReuseForSeconds,
    Levels}` (through `token.Request.PerLoginMFA`, a new field the minter copies into its record);
    not covered → `deny per_login_mfa_required` with `item.PerLoginMFA` filled and its detail
    ruling 17's sentence. `config` adds `PerLoginMFA` when either method is available.
  - `issue.go`: the "person's ID token anywhere but `/v1/certificate`" refusal lets
    `/v1/mfa` through (its handler verifies the token as a proof, never as the caller's credential).

- [ ] **Step 4: Run**

Run: `go test ./internal/broker/... ./internal/store/... ./internal/decision/ ./internal/config/ ./internal/port49d/ -count=1`, then `make test && make vet`.
Expected: PASS. Mutation checks, each restored: drop the same-device check (see
`TestATouchFromAnotherTokenIsRefused` fail); drop the `TakeOnce` of the challenge (see
`TestAChallengeIsUsedOnce` fail); skip the exporter value (see `TestATouchProofIsBoundToItsConnection`
fail); make `mfaCovers` ignore `ReuseFor` (see `TestATouchProofCoversTheRetriedMintAndThenReuses`
fail).

- [ ] **Step 5: Commit**

```bash
git add internal/decision internal/daemon/metrics internal/store internal/token internal/broker internal/config internal/oidc internal/port49d
git commit -m "feat: the broker asks for and verifies a per-login proof

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Held sessions and the session refresh under a requirement

**Files:**
- Modify: `internal/broker/sessionrefresh.go` (`RefreshSession` takes the agent session;
  `extend` checks the requirement), `internal/broker/oidcrefresh.go` (passes `""`),
  `internal/broker/api/refresh.go` (`RefreshResponse.PerLoginMFA`)
- Test: `internal/broker/mfa_refresh_test.go`

**Interfaces:**
- Consumes: Task 11's `mfaCovers`, `issueChallenge`.
- Produces: `func (b *Broker) RefreshSession(ctx context.Context, m policy.Member, answer
  *directory.Answer, cred store.Credential, at time.Time, via *decision.OIDC, agent string)
  (SessionRefreshReport, error)`; outcome `per_login_mfa_required` beside `extended`, `revoked`,
  `past_grace`, `not_judged`; `SessionRefreshReport.Challenge` set when any context needed a proof.

- [ ] **Step 1: Write the failing tests.**

```go
func TestARequirementAddedRevokesNothing(t *testing.T) {
	f := newMFAFixture(t) // as Task 11's, with core-sw01 on juniper_junos (never asks about a command)
	f.loadPolicy(t, policyWithoutRequirement)
	f.loginOnDevice(t, f.alice, "core-sw01") // a live context, minted with no proof
	f.loadPolicy(t, policyWithRequirementOnCore) // the reload adds one
	ctx := f.context(t, "core-sw01", "alice")
	if !ctx.RevokedAt.IsZero() {
		t.Fatal("a reload that added per_login_mfa revoked a live context")
	}
}

func TestRefreshUnderARequirementNeedsAProof(t *testing.T) {
	f := newMFAFixture(t)
	f.loadPolicy(t, policyWithoutRequirement)
	f.loginOnDevice(t, f.alice, "core-sw01")
	before := f.context(t, "core-sw01", "alice").SessionExpires
	f.loadPolicy(t, policyWithRequirementOnCore)
	f.clock.Advance(time.Hour)
	out := f.refresh(t, f.alice)
	s := out.find("core-sw01")
	if s.Outcome != "per_login_mfa_required" || !s.Unreached || out.PerLoginMFA == nil {
		t.Fatalf("refresh = %+v", out)
	}
	if got := f.context(t, "core-sw01", "alice").SessionExpires; !got.Equal(before) {
		t.Fatalf("the ceiling moved to %v without a proof", got)
	}
	f.assertRecordWith(t, "refresh", "deny", "per_login_mfa_required", func(r decision.Record) bool { return r.Session.Unreached })
	// One touch, and the refresh extends it.
	f.proveTouch(t, f.alice, out.PerLoginMFA.Challenge)
	if s := f.refresh(t, f.alice).find("core-sw01"); s.Outcome != "extended" {
		t.Fatalf("refresh after a proof = %+v", s)
	}
}

func TestRefreshWithinReuseNeedsNoNewProof(t *testing.T) { /* a proof 5m ago in this agent session: extended at once */ }
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'RequirementAddedRevokesNothing|RefreshUnderARequirement|RefreshWithinReuse' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.** `refresh` (the handler) passes `agentKey(r)`; `extend` resolves as
  today, and when `res.PerLoginMFA.Required()` and `mfaCovers` says no, it writes `deny
  per_login_mfa_required` (with `Session.Unreached` as the context's platform says) and returns
  `"per_login_mfa_required"` without touching the context; `RefreshSession` issues one challenge
  when any context returned it and `response` puts it in `RefreshResponse.PerLoginMFA` (its
  `Device` empty, its requirement the strictest of those contexts', its `Levels` theirs). The
  policy-refresh pass after a reload (`refreshContext` without a session) is unchanged: it never
  reads the requirement, so a reload revokes nothing over it.

- [ ] **Step 4: Run**

Run: `go test ./internal/broker/ -count=1`, then `make test && make vet`.
Expected: PASS. Mutation check: let `extend` extend without the check and see
`TestRefreshUnderARequirementNeedsAProof` fail at "the ceiling moved"; restore.

- [ ] **Step 5: Commit**

```bash
git add internal/broker
git commit -m "feat: a session refresh under a requirement needs a proof, and a reload revokes nothing

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: The clients — the agent proves a touch; `token`, `ssh` and `refresh` prompt; `idp_mfa`; workloads

**Files:**
- Modify: `internal/agent/agent.go` (`Mint` takes the challenge; `MFARequiredError`; `ProveTouch`;
  socket `POST /mfa/touch`), `internal/agent/socket.go` (`Client.ProveTouch`, `TokenRequest`)
- Create: `cmd/port49/mfa.go`, `cmd/port49/mfa_test.go`
- Modify: `cmd/port49/main.go` (`tokenCmd`), `cmd/port49/ssh.go` (its mint at ~669),
  `cmd/port49/trust.go` (~179), `cmd/port49/refresh.go`
- Modify: `internal/workload/client.go` (`Config.TouchKey`, the item loop), `cmd/port49/workload.go`
  (`--touch-key`)

**Interfaces:**
- Consumes: Task 11's API types, Task 5's `Config.TouchKey`, plan 9b's `signIn`,
  `oidcclient.Discover`, `pickProvider`.
- Produces:

```go
// agent
type TokenRequest struct {
	Device               string `json:"device"`
	Enable               bool   `json:"enable"`
	TTLSeconds           int    `json:"ttl_seconds"`
	PerLoginMFAChallenge string `json:"per_login_mfa_challenge,omitempty"`
}

// MFARequiredError is an item answered per_login_mfa_required: what to
// prove, and how.
type MFARequiredError struct{ Requirement api.PerLoginMFA }

func (a *Agent) Mint(ctx context.Context, device string, enable bool, ttl time.Duration, challenge string) (api.MintItem, error)

// ProveTouch signs challenge with the touch key over the held connection's
// exporter value and posts it with the attestations to POST /v1/mfa.
func (a *Agent) ProveTouch(ctx context.Context, challenge string) error

func (c *Client) ProveTouch(ctx context.Context, challenge string) error

// cmd/port49
// prove gets one proof for req: a touch when it is accepted here and the
// agent has a touch key, else an idp_mfa sign-in when accepted, saying
// ruling 17's sentence first. It never runs without a terminal for idp_mfa.
func prove(ctx context.Context, socket string, sf *sessionFlags, req api.PerLoginMFA, stderr io.Writer) error

// describeMFA is ruling 17's sentence for req.
func describeMFA(req api.PerLoginMFA) string
```

- [ ] **Step 1: Write the failing tests.** `cmd/port49/mfa_test.go`:
  - `TestDescribeMFA`: for Task 11's requirement the sentence is `core-sw01 asks for a second
    factor at each login: scope core accepts hardware_key_touch, idp_mfa (reuse 15m, from scope
    core)`.
  - `TestTokenProvesATouchAndMintsAgain`: against the in-process broker and agent with a
    `fakeKey` touch key whose attestation the test PIV root signs, `port49 token core-sw01` prints
    the sentence and `touch your key now` on stderr, the token on stdout, exit 0; the broker saw one
    `/v1/mfa`. With the touch key's `Sign` returning an error after 15s (no touch): exit 1 and
    "no touch within the key's timeout; run the command again".
  - `TestTokenFallsBackToTheSignInWhenNoTouchKey`: no touch key, `idp_mfa` accepted: the sign-in
    runs against the test authorization server with `nonce` = `api.MFANonce(challenge)`; no
    terminal → exit 1 "this device asks for a sign-in at your identity provider and there is no
    terminal; run it at a terminal".
  - `TestRefreshProvesOnceAndRefreshesAgain`: `port49 refresh` with a context answered
    `per_login_mfa_required` proves once and prints the second refresh's answer, the device
    `extended`.
  - `TestNothingSecretIsPrinted`: across the tests above, stderr and stdout hold no challenge, no
    signature, no ID token and no agent session (the test greps for each value).
  - `internal/workload/client_test.go`, `TestAWorkloadProvesWithItsTouchKey`.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ ./internal/workload/ -run 'DescribeMFA|ProvesATouch|FallsBackToTheSignIn|ProvesOnceAndRefreshes|NothingSecretIsPrinted|WorkloadProves' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `Agent.Mint` puts the challenge in `api.MintRequest.PerLoginMFAChallenge`; an item with reason
    `per_login_mfa_required` returns `&MFARequiredError{*item.PerLoginMFA}`; the socket answers it
    `428` with the requirement as the body, and `Client.Token` rebuilds it. Every existing caller
    of `Mint` passes `""`.
  - `ProveTouch`: refuses with "no touch_key is configured" when `TouchKey` is nil; reads the
    touch key's attestation chain (`pkcs11.Signer.Certificates()`: the slot attestation whose key
    is the touch key's, the device certificate that signs it, and the slot attestation whose key
    is the session key's; any missing → "your token does not show its attestation certificates";
    provisional on L60) once and keeps it; takes the wire, gets the connection's exporter value as
    `refreshOnce` does, signs `api.MFAMessage`, posts `/v1/mfa`. A 401 is returned with the
    broker's detail; `hwkey.ErrKeyAbsent` as Task 6's `KeyAbsentError`.
  - `prove`: prints `describeMFA(req)`; if `hardware_key_touch` is in `req.Methods` and the agent's
    status says `touch_key`, prints "touch your key now" and calls `Client.ProveTouch`; else if
    `idp_mfa` is in `req.Methods`: needs a terminal on stdin; fetches `/v1/config` (with the CRL
    check), picks the provider as `issueCertificate` does, runs `signIn` with
    `api.MFANonce(challenge)` and, when the config says so, `acr_values`; posts the ID token as
    `Authorization: Bearer` to `/v1/mfa` with `{challenge, method: "idp_mfa"}` over TLS to the
    broker CA (never through a proxy), and drops the token. Neither available: "this device needs a
    proof you cannot give here: <sentence>; …" naming what is missing (`touch_key`, a terminal).
  - `tokenCmd`, `ssh` and `trust`: on `*agent.MFARequiredError`, `prove`, then mint once more naming
    the challenge; a second `per_login_mfa_required` is printed and exits 1 (never a loop).
  - `refreshCmd`: a response with `PerLoginMFA` → `prove`, then one more refresh; print both.
  - `workload.Client`: an item `per_login_mfa_required` with `Config.TouchKey` set proves through a
    `/v1/mfa` on its own connection (its own exporter value), stderr "touch the key for <device>",
    and retries that page once; without a touch key, the item fails with the sentence and the run
    exits as for any refused item.

- [ ] **Step 4: Run**

Run: `go test ./internal/agent/ ./internal/workload/ ./cmd/port49/ -count=1`, `make test-hw`, then `make test && make vet`.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agent internal/workload cmd/port49
git commit -m "feat: token, ssh, refresh and workloads give a per-login proof when asked

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: The Secure Enclave backend (only if Task 2's gate SE1 passed, or Ryan has ruled)

**Files:**
- Create: `internal/hwkey/secureenclave/secureenclave_darwin.go`, `secureenclave_other.go`,
  `secureenclave_darwin_test.go`
- Modify: `internal/hwkey/hwkey.go` (`secure-enclave:` dispatch), `cmd/port49/issuedkey.go`
  (`secure_enclave` and `auto` on macOS)

**Interfaces:**
- Consumes: Task 2's cells (the same purego registrations, moved into the package).
- Produces: `func Open(label string) (*Signer, error)`, `func Generate(label string) (*Signer,
  error)`; `Signer` implements `hwkey.Key` (`Unlock` a no-op; `State` `Absent` on
  `errSecItemNotFound` after a create).

- [ ] **Step 0: Read the gate.** If L63's note says SE1 passed, go on. If Ryan ruled the per-agent
  ephemeral key, replace `Generate`'s `kSecAttrIsPermanent` with false, generate in the agent child,
  and have the login sign in for the key the child reports on its socket before it connects (one
  extra socket call, `GET /issued-key`); write that in the plan text first. If neither, skip this
  task and record it in the roadmap as waiting on Ryan.
- [ ] **Step 1: Write the failing test** (`//go:build darwin`, runs on a macOS CI runner or by
  hand): generate under a random label, sign a refresh message, verify, open again from a second
  `exec` of the test binary, delete.
- [ ] **Step 2: Run it to see it fail** (`go test ./internal/hwkey/secureenclave/` on macOS).
- [ ] **Step 3: Implement** from Task 2's cells; `secureenclave_other.go` returns "the Secure
  Enclave is macOS's" everywhere else.
- [ ] **Step 4: Run** on macOS, and `make test && make vet` on Linux.
- [ ] **Step 5: Commit** `feat: Secure Enclave keys on macOS through purego`.

---

## Task 15: Lab — L61 (Keycloak's `amr`) and L62 (the SER8's TPM)

**Files:**
- Create: `tests/lab/mfa_keycloak_test.go`, `tests/lab/mfa_keycloak_unit_test.go`,
  `tests/lab/tpm_ser8_test.go`
- Create: `tests/lab/results/L61-keycloak.md`, `tests/lab/results/L62-ser8.md`
- Modify: `Makefile` (`lab-mfa-idp`, `lab-tpm`), `docs/design/2026-08-23-policy-engine-spec.md`
  (L61, L62 status; decision 45 ruling 13's default if L61 says so)

**Interfaces:** Consumes the compose Keycloak (plan 9b's `lab-oidc-l55` harness) and `bin/port49`.

- [ ] **Step 1: L61's harness.** The realm file gains a flow `p49-otp` (username-password form,
  then OTP form, required) bound to `port49-cli`, and a user `alice-otp` with a TOTP credential
  whose seed the harness holds; the scripted browser (L55's) types the password and a TOTP code it
  computes. Cells, each its own sign-in with `prompt=login`: (a) password and OTP, the AMR mapper
  absent; (b) the same with Keycloak's "Authentication Method Reference (AMR)" protocol mapper
  added to the client and each authenticator's reference value set to the RFC 8176 words (`pwd`,
  `otp`), plus `mfa` on the flow; (c) the control, password only (`alice`, the realm's default
  flow), with the mapper; (d) (b) with `acr_values=gold` asked. Each cell records the ID token's
  `amr` and `acr` (never the token; the unit test reads the claims from a redacted fixture).
  The control must sign in, else INVALID. Gate M1: (b) carries one of decision 45 ruling 13's
  default `amr` words and (c) does not.
- [ ] **Step 2: Run** `make lab-mfa-idp` (target: `go test -tags lab ./tests/lab/ -run 'TestL61'
  -count=1 -v -timeout 30m`); the unit test `TestL61ReadsTheClaims` runs under `make lab-unit`.
- [ ] **Step 3: Write and read `L61-keycloak.md`.** If M1 passes, close L61. If (b) carries `otp`
  and not `mfa`, the default `amr` stays `[mfa]` (the RFC's word) and the operator notes say to add
  `otp` (or set Keycloak's mapper to emit `mfa`) — rule 4 of CLAUDE.md: the doc changes to what was
  measured, cited.
- [ ] **Step 4: L62 on the SER8** (lab runs need no one present). As a non-root lab user in
  `tss`: `port49 login --oidc` with `issued_key_store: tpm` against the compose broker; `port49
  token` taken by vEOS; `port49 refresh`; the agent stopped and started; the SER8 rebooted and
  `port49 login` again (no sign-in, the held `.tpmkey` used); the `.tpmkey` copied to the WSL
  host's swtpm-less environment and `port49 login` there (refused naming "this machine's TPM");
  the control: a user outside `tss` (refused naming the group). Record the TPM's vendor and
  firmware (`/sys/class/tpm/tpm0/tpm_version_major`, `device/description`). Run under the lab
  watchdog (lab rule: a background stall watchdog, re-armed on wake).
- [ ] **Step 5: Close L62** if every cell read as claimed; otherwise fix the doc to the reading.
- [ ] **Step 6: Commit**

```bash
git add tests/lab Makefile docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L61 and L62

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: Lab — L60, a YubiKey on the SER8 (needs Ryan present)

> **Needs Ryan present, with a YubiKey 5.** Placed last of the code-and-lab tasks so nothing waits
> on it. If no YubiKey is to hand, the branch merges with L60 open; every claim cited to it stays
> *provisional on L60* and the PR says so.

**Files:**
- Create: `tests/lab/yubikey_test.go` (`//go:build lab`, behind `PORT49_LAB_YUBIKEY=1`),
  `tests/lab/results/L60-yubikey.md`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (L60 status)

- [ ] **Step 1: Ryan provisions the token** (on the SER8, `ykman` 5.x; the PIV PIN and management
  key are Ryan's, never typed into this session or written to a file the harness reads):
  `ykman piv keys generate --pin-policy once --touch-policy never 9a /tmp/9a.pub`, a lab CA
  certificate for it (`ykman piv certificates generate` is self-signed; the harness signs a CSR
  with the lab CA instead: `ykman piv certificates request 9a /tmp/9a.pub /tmp/9a.csr`, the harness
  signs it, `ykman piv certificates import 9a`); `ykman piv keys generate --pin-policy once
  --touch-policy always 9c /tmp/9c.pub`; the Yubico PIV root
  (`https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem`) saved as the broker's
  `attestation_roots_file`. Record the firmware (`ykman info`) and `libykcs11`'s version.
- [ ] **Step 2: The cells** (the harness drives `bin/port49` against the compose broker and vEOS;
  Ryan types the PIN and touches when the harness says):
  - (a) `C_Initialize`/`C_Finalize` five times in one process and across `CGO_ENABLED=0` builds, no
    crash, threads listed before and after (`/proc/self/task`);
  - (b) `port49 login --key "pkcs11:id=%01?module-path=…/libykcs11.so"`: the PIN asked once, the
    agent connects, refreshes; control: the same login with the lab's file key;
  - (c) the attestation objects: which certificate objects `Certificates()` returns, that the 9a
    and 9c attestations verify against the f9 certificate and the f9 against Yubico's root through
    `pivattest.Verify`, and their touch policies (9a never, 9c always);
  - (d) `port49 token` on a device under `hardware_key_touch`: the prompt, Ryan touches, the token
    is taken by vEOS; again with no touch: the timeout and port49's words; control: the same device
    with no requirement;
  - (e) the unplug: `port49 token` with the YubiKey out (minted on the held connection),
    `port49 refresh` ("insert your key"), the agent still running; re-inserted, `port49 login`
    asks the PIN, the refresh works;
  - (f) one wrong PIN: the message, the tries the token reports (`ykman piv info` before and
    after: one fewer), never a second attempt; then the right PIN;
  - (g) `issued_key_store: pkcs11` with `issued_key: "pkcs11:id=%04?module-path=…"` (slot 9e): the
    key generated on the token, the certificate issued, the agent connects.
- [ ] **Step 3: Write `L60-yubikey.md`**, close L60 if every cell read as claimed (CLAUDE.md rule
  3), else fix the doc to the reading and say so in the commit. If (c) shows `libykcs11` exposes no
  attestation objects, `hardware_key_touch` cannot be given through PKCS#11: that goes back to Ryan
  (read the attestation over PC/SC through purego, or accept the attestation once at enrolment),
  and `touch_key` is documented as not yet usable.
- [ ] **Step 4: Commit** `docs: close lab register entry L60` (or `test: L60 measured, …` if it
  stays open).

---

## Task 17: Roadmap as built, the design doc, and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line; the 9c entry; a new `### Plan 9c —
  As built` after `### Plan 9b1 — As built`)
- Modify: `docs/design/2026-08-21-port49-design.md` (§7: "The key. A file, 0600, until plan 9c…"
  becomes what was built; "The PIV touch policy is the operator's choice" gains `per_login_mfa`;
  §17's surface lists `POST /v1/mfa`)

- [ ] **Step 1: Write "Plan 9c — As built"**: branch and base, each task's commits, the gates read
  (SE1, M1), rows closed and opened, and carried at least:
  - L60 if open: every claim *provisional on L60* listed;
  - the Secure Enclave if Task 2 did not run: the question to Ryan;
  - the 7h bearer path's session refresh passes no agent session, so a person refreshing through it
    proves at every refresh under a requirement (it retires at the pre-beta review);
  - plan 12: ship `attestation_roots_file` and the `touch_key`/`key`/`issued_key_store`/`broker_crl`
    lines in each shape's `/etc/port49/config.yaml`; add the lab user to `tss` in the client
    packages that use the TPM;
  - plan 13: these operator notes.
  Paste the Operator notes below, edited to what was built.
- [ ] **Step 2: Verify** — `make test && make vet` and `make test-hw`; paste the summary lines into
  the PR body.
- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/README.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: roadmap, plan 9c as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Operator notes (for the pull request body)

- **Your key can live in hardware.** In `/etc/port49/config.yaml` (once, for the fleet) or your own
  `~/.port49/config.yaml`, set `key:` to a reference instead of a path:
  - a YubiKey or smartcard: `key: "pkcs11:id=%01?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so"`
    (slot 9a is `id=%01`; on macOS the module is where Homebrew put `libykcs11.dylib`). Leave
    `cert:` out and port49 reads the certificate from the token. The module must be owned by root
    or you and writable by no one else.
  - a TPM key file: `key: "tpm:file=/home/alice/.port49/my.tpmkey"`, or a persistent handle
    `tpm:handle=0x81000001`. You must be in the `tss` group.
  `port49 login` asks the token's PIN once, on the terminal; it is never on the command line, in
  the environment or in a log. A wrong PIN is sent once: port49 never retries it, and tells you
  when the token says few tries are left. For a host with no terminal, put the PIN in a file only
  you can read and add `pin-source=file:///path` to the URI; `pin-value` is refused.
- **Touch and PIN policy are yours.** For the session key, PIN once and touch never or cached is
  the sane default: the key is used once per session, at the handshake and at each refresh, never
  per device.
- **`port49 login --oidc` keeps its key in hardware by default.** `issued_key_store: auto` uses the
  TPM on Linux when you can (it says so), else the 0600 file as before. `tpm`, `pkcs11` (with
  `issued_key: "pkcs11:…;id=%04"`) or `file` name one; a named one that cannot be used stops before
  your browser opens. A TPM key file is useless on any other machine.
- **The key unplugged at 3am.** Your open device sessions and the agent's held connection keep
  working: `port49 token` still mints. `port49 refresh` and anything that needs a new connection say
  "insert your key"; nothing ends. Put the key back and run `port49 login`: it asks the PIN and
  carries on.
- **The broker's certificate is checked against its CRL** when it names a distribution point.
  `broker_crl: check` (default): a revoked broker certificate is refused before anything is sent to
  it; a CRL server that does not answer is said once and the login goes on. `require` refuses that
  too; `off` checks nothing. Lists are kept in `~/.port49/crl/`.
- **`per_login_mfa`: a second factor at each login to the devices you mark.** Under `defaults:`, a
  role, or a scope (`match: {tier: core}` for a class, `match: {name: core-sw01}` for one device):

  ```yaml
  per_login_mfa:
    accept: [hardware_key_touch, idp_mfa]   # one or both
    reuse_for: 15m                          # 0m: a proof at every login; at most 8h
  ```

  The strictest level wins: the methods every level accepts, the shortest `reuse_for`. Two levels
  that share no method refuse the policy at load, naming both. A scope that sets it needs
  `on_missing` and `security_log: true`. Machines are exempt unless a level says
  `applies_to_machines: true`, and then prove by a touch. `port49 explain` prints the effective
  requirement and where each part came from; `policy diff` warns on a weakening.
- **The two methods.**
  - `hardware_key_touch`: a touch on your token's always-touch slot. Set `touch_key:
    "pkcs11:id=%02?module-path=…"` (slot 9c, made with `ykman piv keys generate --touch-policy
    always 9c`), and on the broker `broker.identity.per_login_mfa.hardware_key_touch.
    attestation_roots_file:` Yubico's PIV attestation root. The broker checks that the touch slot
    is on the same token as your session key; a TPM, a file key or an imported key cannot give it.
  - `idp_mfa`: a fresh sign-in at your identity provider whose `amr` shows a second factor (`mfa` by
    default; `broker.identity.per_login_mfa.idp_mfa.amr` widens it, as L61 measured for Keycloak).
    A browser round trip each time, and it needs a terminal.
  Accept both where you can: with the IdP down, the touch still works, and with no token to hand,
  the sign-in does.
- **What you see.** `port49 token core-sw01` prints `core-sw01 asks for a second factor at each
  login: scope core accepts hardware_key_touch (reuse 15m, from scope core)` then `touch your key
  now`. One proof covers your further logins under that requirement for `reuse_for`, in this agent
  only: another agent, or another machine, proves again.
- **Live sessions are never cut by a policy edit.** Adding a requirement revokes nothing. Your next
  `port49 refresh` asks one proof before it extends those sessions; without it they keep their
  current end. On Junos (which never asks port49 about a command) the device's own session runs
  until it is closed, and `port49 refresh` says so.
- **New in the decision log:** event `per_login_mfa` (`per_login_mfa_proved`,
  `per_login_mfa_refused`); `per_login_mfa_required` and `per_login_mfa_unavailable` on `mint` and
  `refresh`; a mint record says which method covered it and whether it was reused. Alert on
  `per_login_mfa_refused` (someone trying another token or another person's sign-in) and on
  `per_login_mfa_unavailable` (a broker that cannot verify a method a policy demands). Metric:
  `port49_per_login_mfa_total{method,outcome}`.
- **Hardware tests:** `make test-hw` (needs `softhsm2`, `swtpm`, `swtpm-tools`), and the `hwkeys`
  workflow on every pull request.
