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
  Task 2). `clientkey.Open` returns a `hwkey.Key`, a `crypto.Signer` with `State`, `Unlock` and `Close`,
  which goes into `agent.Config.Cert.PrivateKey` unchanged; `api.SignRefresh` takes it unchanged.
  PKCS#11 through `github.com/ebitengine/purego` v0.11.1, TPM through `github.com/google/go-tpm`
  v0.9.8, no cgo. purego links the binary against the system's dynamic loader, so the purego
  backends (PKCS#11, the Secure Enclave) are built only under the build tag `hwkey_dlopen`: the
  client build carries them, the static build and the image do not and say so when asked for one
  (ruling 22). TPM and file keys are in every build. A PIN is asked once by `port49 login` on the
  terminal and handed to the agent on a descriptor; it is never in argv, the environment or a log.
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
  `CGO_ENABLED=0 -tags hwkey_dlopen`; `make check-static` fails the workflow if the build without
  the tag (the image's) is not statically linked.
- **Lab:** L60 (YubiKey on the SER8; Ryan present), L61 (Keycloak's `amr` for `idp_mfa`), L62 (the
  SER8's own TPM), L63 (the Secure Enclave from an unsigned binary; Task 2).

**Architecture:**
- `internal/hwkey`: `Key`, `State`, `IsRef`, errors; a leaf that imports no backend (re-review R3).
  Subpackages `pkcs11` (RFC 7512 URI and the DER conversion in every build; the purego binding,
  signer and the test harness's generation under `hwkey_dlopen`), `tpm` (go-tpm signer, TSS2 key
  file, generation; every build), `secureenclave` (darwin, `hwkey_dlopen`, gated); each imports
  `hwkey`, never the reverse.
- `internal/clientkey`: `Open`, `LoadPair`, `HasPKCS11`: a client key from a path or a
  reference, dispatched to the backends; `open_dlopen.go` and `open_static.go` are its build
  split. It imports `hwkey`, `pkcs11`, `tpm` and `keyfile`; `cmd/port49` and `internal/workload`
  import it (re-review R3).
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
macOS amd64/arm64 as Tier 1 without cgo). "No cgo" is not "static": a `CGO_ENABLED=0` binary that
imports purego is `dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2` (measured at
pre-flight, C1), because purego's fakecgo uses `//go:cgo_import_dynamic`; hence ruling 22's build
tag. CI: SoftHSM2 2.6 and the swtpm Ubuntu 24.04 ships (0.7.x; the workflow logs the version),
plus `ykcs11` and `pcscd` for Task 3's thread check.

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
2. **The broker certificate's CRL check** (plan 3, 2026-09-24): optional (`check` checks every link
   that names a distribution point, `require` refuses one that names none); defence in depth, since the CA is the operator's.
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
  both, never resolved to the first. The scheme is `secure-enclave:` while the config word is
  `secure_enclave`: RFC 3986 allows no `_` in a scheme, and data stays snake_case everywhere else.
- **R3. The module.** The `module-path` must be absolute, a regular file, and owned by root or the
  user, with it and every directory above it not writable by group or others: it is code the agent
  runs. `userconfig.CheckOwned(path)` walks the directory with `resolveOwned(filepath.Dir(path),
  false, what)` (which judges directories only, and refuses a non-directory as "not a
  directory"), then follows the base name's symbolic links (`libykcs11.so` is usually a chain),
  each link owned by root or the user, and judges the final regular file by `ownedBy` and a mode
  with no group or other write bit (pre-flight I1). One module per process, `C_Initialize` with
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
  `secure_enclave`, `pkcs11` (with `issued_key: "pkcs11:…;id=…"` naming the key) or `file`.
  `auto` is a token when `touch_key` and `issued_key` are both set (so the session key sits on the
  token a touch proves from, ruling 12), else the TPM on Linux where a key can be created there,
  the Secure Enclave on macOS once Task 14 lands, else the file; the login says which in one line.
  `auto` passes over a store this build lacks and says so in that line: in the static build
  (ruling 22) a fleet's `touch_key` and `issued_key` do not make `auto` pick `pkcs11` and refuse;
  it says "this port49 was built without PKCS#11 support, so issued_key is not used; use the
  client release for it" and goes on to the TPM or the file (re-review R10). A named store that cannot be used refuses before any browser opens, as decision 43 ruling 18
  refuses an issuance it cannot make. **For `pkcs11`, port49 never generates a key or writes an
  object on the token**: on a YubiKey both need the PIV management key (`CKU_SO`), and asking every
  user for it at each sign-in is fleet toil and a secret port49 should never hold. `issued_key`
  names a key the user made once (`ykman piv keys generate`); port49 signs the CSR with it and
  keeps the issued certificate as `~/.port49/issued/<host>_<port>.pem` (pre-flight I11). A TPM
  pair is `~/.port49/issued/<host>_<port>.<machine>.tpmkey` and `.<machine>.pem`, where
  `<machine>` is the first 8 hex digits of SHA-256 of `/etc/machine-id`: on a bastion pool whose
  home directories are shared, each host keeps its own pair, another host's reads as no held pair
  (a sign-in), never as an error, and is never overwritten (pre-flight I12). A held pair is found
  by either key file.
- **R8. The key unplugged.** A signing error the backend reads as the key gone (PKCS#11
  `CKR_DEVICE_REMOVED`, `CKR_TOKEN_NOT_PRESENT`, `CKR_SESSION_HANDLE_INVALID`, `CKR_DEVICE_ERROR`;
  a TPM transport error) is `hwkey.ErrKeyAbsent` and the key's state `Absent`. The agent never
  ends a session on it. `crypto/tls` flattens a signer's error into text
  (`handshake_client_tls13.go:797`, Go 1.26), so the agent reads the key's state after a failed
  dial, not the error. `port49 refresh` and `port49 token` on a dropped connection say "insert your
  key …; your session goes on until <end>". **`State()` re-probes while the cached state is
  `Absent`**, cheaply and without a PIN (PKCS#11: `C_GetSlotList(tokenPresent)` and
  `C_GetTokenInfo` matched by the URI, then a session reopened; TPM: a dial and a
  `GetCapability`), so a re-inserted key is seen by the next `GET /status` or `port49 refresh`
  with nothing signing in between; `Refresh` never refuses on a cached `Absent` without that probe
  (pre-flight C2). A key that is back and needs its PIN is `Locked` (PKCS#11
  `CKR_USER_NOT_LOGGED_IN` too), and `port49 login` with the agent running asks the PIN and unlocks
  it over the agent's socket (`POST /unlock`), then refreshes. With a reference key, `login`
  asks the running agent's `Status` first and, when it holds this broker with the same certificate
  fingerprint and is `absent` or `locked`, goes to the insert-or-unlock path without opening the
  token in the login process (pre-flight I15): an unplugged key never turns into "loading the
  client certificate: no token matches", and a second process never opens the token under the
  agent (whether that would drop the agent's PIV login is L60's to measure).
- **R9. The broker certificate's CRL.** `broker_crl` in `config.yaml` (`--broker-crl`): `check`
  (the default), `require`, `off`. Each certificate of the verified chain but the root is checked
  against the lists its `http`/`https` distribution points name, through `certstatus.Checker`
  (verified against the issuer, the IDP scope rules, kept in `~/.port49/crl/`). A list naming a
  serial refuses the connection under `check` and `require` before any request, a bearer ID token
  included. A list that cannot be had: under `check` it is said once per process and the login goes
  on; under `require` it is refused. A certificate naming no fetchable (`http`/`https`)
  distribution point is judged link by link: under `check` it is not checked and nothing is said,
  and an intermediate with none (common under step-ca and private PKI) is passed over while the
  leaf it issued is still checked (pre-flight I10); under `require` it is refused, leaf or
  intermediate (only the trust anchor is exempt), with "broker certificate <subject> names no
  http(s) CRL distribution point; broker_crl: require refuses it ... add an HTTP CDP to the CA, or
  set broker_crl: check" (Ryan, 2026-10-12). A revoked link is reported as revoked first. Runbook:
  rotate by issuing and loading the new broker certificate before publishing the revocation;
  revoke the leaf, not the CA; under `require`, a revoked broker certificate with no replacement
  stops new logins while held sessions continue. A fetch that failed is remembered for a minute,
  so a CRL server that is down costs one 5s wait, not one per connection. Login's own TLS connections (`/v1/config`, `/v1/certificate`, `/v1/mfa`), the
  agent's and `port49 workload`'s all check.
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
  the joint check is (§10), at the load's present and at each later grant expiry, as
  `checkDevices` checks. An empty intersection is a load error naming both levels: "per_login_mfa:
  scope core accepts [hardware_key_touch] and role netadmin accepts [idp_mfa] on core-sw01; no
  method meets both". A machine-applying level whose accept leaves only `idp_mfa` for a machine is
  the same error (a machine has no sign-in). **Where it is a load error, and where a quarantine**
  (pre-flight I4; re-review R5): a policy edit is refused only for the MFA entries it
  *introduces*, entries absent from the in-force policy's `MFADisjoint()` evaluated over the same
  inventory. A reload of an edited policy file that introduces one is refused with it (the bundle
  in force keeps serving, as for any refused policy edit); a policy and inventory loaded together
  (`loadBoth`) are judged by the same rule, against the in-force policy over the new inventory
  (the `base` `loadBoth` already builds for the admission bound). An entry already in force stays
  quarantined and does not block an unrelated edit: a grant revocation at 3am loads while
  core-sw01 is quarantined over MFA. `port49 policy diff` fails on an entry the new version
  introduces (its existing "quarantined for a new cause" rule), and `port49 policy test` fails on
  every quarantine, this one included, as it does today for every cause (there is no `policy
  check` command; `policy test` is the CI gate). When the policy did not change, at a start, on an
  inventory reload (a
  source-of-truth sync adding `tier: core`) or at a grant's expiry, the device is quarantined with
  that cause, as `checkDevice` quarantines a composition that will not compile: refused at mint,
  closed by the daemon, the rest of the fleet and every later inventory edit still served.
  Refusing the inventory edit instead would freeze inventory fleet-wide until someone edits the
  policy (decision 20, spec §10). A principal matching two subjects is composed only at mint
  (`resolveAll`); an empty intersection found there is wrapped as `ErrCompositionRefused`, so the
  item is `deny composition_refused`, recorded, never a `broker_error` fault (pre-flight I3). A
  scope with a match key other than `name` that carries `per_login_mfa` must declare `on_missing`
  (a restriction, read as a deny is, spec §5.5) and `security_log: true` (whoever edits the
  attribute lifts the requirement, and the log must say so). A scope whose only match key is
  `name` needs neither: `name` is always present (scope.go), so `on_missing` is moot, and no
  attribute edit lifts a name pin (pre-flight I2). `on_missing: exclude` on a `per_login_mfa` scope
  is a lint warning: a sync that drops the attribute lifts the requirement, which `security_log`
  records (pre-flight minor 14).
- **R12. `hardware_key_touch`** is a signature by the touch key over the challenge and the held
  connection's TLS exporter value (`EXPORTER-port49-per-login-mfa`), with that key's YubiKey PIV
  attestation, the token's attestation certificate (slot f9), and the session key's attestation.
  The broker verifies: the f9 certificate to `broker.identity.per_login_mfa.hardware_key_touch.
  attestation_roots_file`, whose self-signed certificates are the roots and whose others are
  intermediates (`VerifyOptions.Intermediates`), so a firmware whose attestation hierarchy has an
  intermediate under a newer Yubico root verifies once the operator lists both (pre-flight I14;
  the chain depth per firmware is *provisional on L60*); each slot attestation's signature by f9 (checked directly, since some
  f9 certificates carry no basic constraints: go-piv v2.6.0 `piv/key.go:241-247` documents and
  works around it); the touch attestation's key is the signing key and its touch policy byte is
  `0x02` (always; OID 1.3.6.1.4.1.41482.3.8); the session attestation's key is the connection's
  client certificate key. So the touch is on the token that holds the session key, and an attacker
  holding a copied session key cannot prove with a token of their own. A TPM, Secure Enclave,
  file or imported key cannot satisfy it: none carries an attested presence. `touch_key:` in
  `config.yaml` names the touch slot (`pkcs11:id=%02?module-path=…`), one line in the system file.
  **A fleet `touch_key` meets users whose session key is elsewhere** (pre-flight I6): the agent
  reports `touch_key: true` only when the touch key opened and sits on the same token (module and
  token serial) as a `pkcs11:` session key; otherwise it reports `touch_key_unusable: "<why>"`
  ("your session key is in the TPM; a touch proves only from the token that holds it", "no token
  matches touch_key") and starts anyway. The CLI then never tries a touch that must fail, so no
  `per_login_mfa_refused` (the alert meant for someone trying another token) fires at an ordinary
  login; it says why and goes to `idp_mfa` where accepted. A device that accepts only
  `hardware_key_touch` locks out a user whose session key is not on a token; the operator notes
  say so.
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
  (`PutOnce`), bound to the principal, the certificate and the agent session. **Each record is
  keyed by its binding** (re-review R1), so a wrong caller's take misses with `ErrNotFound` and
  spends nothing (`TakeOnce` removes the record whoever asks): the challenge under
  `plm-challenge/` + hex SHA-256(challenge ‖ 0 ‖ principal), the principal alone because an
  `idp_mfa` post has no client certificate; the proved record under `plm-proved/` + hex
  SHA-256(challenge ‖ 0 ‖ principal ‖ 0 ‖ fingerprint ‖ 0 ‖ agent_sha256). Each path computes the
  key from its own caller: bob posting alice's challenge, or minting with it, finds nothing. A
  touch post from alice's other certificate takes her challenge and is then refused on the
  fingerprint, spending it; that is the same person, never another's denial. The proof is posted
  to `POST /v1/mfa`: on the held connection for a touch, with a bearer ID token over a fresh
  connection for `idp_mfa` (the agent never holds an ID token, decision 43 ruling 1). The retried
  mint carries `per_login_mfa_challenge`, and the proof made for that challenge covers that
  request's items whose `accept` holds its method, whatever `reuse_for` says, once. So `reuse_for:
  0m` is a proof at every login. One endpoint serves the mint, the refresh and both methods.
  At the mint, the proved record is taken (`TakeOnce`) only after the request's idempotency key is reserved,
  so a store error or an in-progress answer before that leaves the proof for the retry. A store
  error while judging a requirement (`mfaCovers`, `issueChallenge`) is `deny store_unavailable`
  for that item, never "not covered": a challenge that was never stored would make the proof fail
  as `per_login_mfa_refused` and fire the alert during a store outage (pre-flight minor 1). A
  replay of a completed request (the same `Idempotency-Key`, its response lost) is answered from
  the reservation before the requirement is read, so a spent proof never turns a minted token into
  `per_login_mfa_required` (minor 2). The touch does not hold the wire: the agent reads the
  exporter value with the wire, releases it for the touch (up to the token's touch timeout, about
  15s, provisional on L60), and takes it again to post. Having taken it back, the agent reads the exporter value again
  and compares it with the one it signed over; if the connection changed meanwhile it does not
  post and says "the connection changed during the touch; run it again" (re-review R6). Posting it
  would be refused at the broker (another exporter value) as `per_login_mfa_refused`, the alert
  §5.7 reserves for someone trying another token, and would spend the challenge. So `port49
  revoke` never waits behind a touch (minor 4), and a reconnect during one fires no alert.
- **R15. Reuse.** A proof is kept as `(SHA-256(principal ‖ 0 ‖ certificate fingerprint ‖ 0 ‖
  agent_sha256), method) → proved_at` (`PutMFAProof`, the later kept, 8h), where `agent_sha256` is
  the hex SHA-256 of the agent session. The challenge and
  proved records (`PutOnce`, which crypt passes through unsealed) keep `agent_sha256`,
  never the value (pre-flight minor 16). `POST /v1/mfa` takes the binding (principal, fingerprint,
  `agent_sha256`) from the challenge record for both methods, never from its own request: an
  `idp_mfa` proof comes from the CLI over a fresh connection with no `Port49-Agent-Session`, and
  is kept for reuse all the same. A proof is not kept for reuse only when the challenge record's
  `agent_sha256` is empty (a workload, a 7h bearer) (re-review R2). It covers a later
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
  session opened before a requirement cannot be extended past it without a proof. The refresh
  after a proof names the proved challenge (`per_login_mfa_challenge` on `POST
  /v1/refresh/challenge` and on the refresh), so `reuse_for: 0m` works there as at the mint, and a
  challenge request naming a challenge proved by this caller is exempt from the connection's
  10s refresh pacing once: the request takes the single-use proved record, under the key its own
  caller computes (ruling 14), for the refresh that
  follows, so the pacing still bounds refreshes to one per proof. Without it, the refresh right after a touch would be
  answered 429 `refresh_too_soon` (pre-flight I5).
- **R17. What people see.** A prompt: `core-sw01 asks for a second factor at each login: scope core
  accepts hardware_key_touch; role netadmin accepts hardware_key_touch, idp_mfa (reuse 15m, from
  defaults)`, then `touch your key now` or the sign-in. A refusal names the same and the cause.
  `port49 explain` prints `per_login_mfa accept hardware_key_touch (defaults ∩ role netadmin ∩
  scope core); reuse_for 5m (scope core); applies to humans`, or `per_login_mfa none`: the default
  is never invisible.
- **R18. Unavailable, and 3am.** A requirement whose `accept` holds no method this broker can
  verify now (no attestation roots for a touch-only device, no human OIDC verifier for an
  `idp_mfa`-only one) is `deny per_login_mfa_unavailable` for that device alone, said at the
  broker's start once per policy. The broker never refuses a start over it (decision 43 ruling 14's rule).
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
  A workload's key may be a reference too (`--key pkcs11:…`): `workload.LoadCertificate` goes
  through `clientkey.LoadPair`, the PIN from `pin-source` alone (a workload has no terminal). Since a
  touch proves only from the token holding the connection key (ruling 12), an
  `applies_to_machines: true` level is met only by a workload whose `--key` and `--touch-key` are on
  one token; `policy test` and explain say "applies to this machine: provable only with a pkcs11
  key and touch key on one token", and `applies_to_machines: true` is a lint warning saying the
  same (pre-flight I7).
- **R22. Two builds** (pre-flight C1). purego makes a `CGO_ENABLED=0` binary dynamically linked
  (its fakecgo imports the system loader), and the image's base, `distroless/static`, has no
  loader: a `port49` that imports purego would not exec there, nor on Alpine/musl. So the purego
  backends (`internal/hwkey/pkcs11`'s binding and `secureenclave`) build only under the tag
  `hwkey_dlopen`. Without it, `clientkey.Open` refuses `pkcs11:` and `secure-enclave:` naming the
  build: "this port49 was built without PKCS#11 support (the static build, as in the container
  image); use the client release". The static build (`make build`, the image) is built with
  `CGO_ENABLED=0` and no tag (`make build` sets `CGO_ENABLED=0` from this plan on; before it, it
  inherited the environment's; re-review R9) and stays one of "the four static binaries" (spec
  §13, the image ruling at line ~7499) and the design's "single static binary" (§ at line ~1958);
  `make check-static` fails when it is not `statically linked`. The client build (`make
  build-client`, writing `bin/port49-client` so it never overwrites `make build`'s `bin/port49`,
  and plan 12's desktop and client release artifacts, the ones people run `port49 login` from)
  adds `-tags hwkey_dlopen` and is dynamically linked against the loader every desktop Linux and
  macOS has. TPM (go-tpm, pure Go) and file keys are in both. No
  route keeps one static binary and PKCS#11: a static binary cannot `dlopen`, and a PKCS#11 module
  is a shared library; a helper binary or p11-kit's RPC would add a process boundary for no gain
  over a second artifact. Which artifact each deployment shape ships is plan 12's (deployment is
  not prescriptive); this plan's PR and operator notes say which carries hardware keys.

## Pre-flight rulings (2026-10-12)

The pre-flight review (NO-GO: 2 Critical, 15 Important, 17 Minor) was ruled as below, each checked
against the code at `f6d8ae6`. Every ruling is folded into the R it amends, so decision 45 carries
it (Task 1 Step 6). None cuts a spec feature or weakens a check.

- **C1** purego links dynamically → R22: the `hwkey_dlopen` tag, two builds, `make
  check-static` in CI (Task 3), the operator note on which artifact has hardware keys (Task 17).
- **C2** stuck at "insert your key" → R8: `State()` re-probes from `Absent`; Tasks 3, 4, 6 test it
  with nothing signing between (`TestAReinsertedKeyIsSeenWithoutASignature`); Review Focus 8.
- **I1** `CheckOwned` on a file → R3: directories by `resolveOwned`, then links, then the file;
  Task 3 tests a group-writable file, a group-writable directory and a symlink chain.
- **I2** name-pinned scope vs R11 → R11: a scope pinned by `name` alone needs neither key; Task 9.
- **I3** multi-subject disjoint as `broker_error` → R11: wrapped as `ErrCompositionRefused` in
  `resolveAll`; Task 9 test.
- **I4** inventory sync freezing inventory → R11: a load error for policy edits and the tooling, a
  device quarantine at a start, an inventory reload or an expiry; Task 9 with a reload test.
- **I5** refresh paced after a proof → R16 (option a): the refresh names the proved challenge, which
  exempts one request from pacing; Tasks 12 and 13.
- **I6** fleet `touch_key` vs TPM/file session keys → R12 and R7: `touch_key` reported only on the
  session key's token, `touch_key_unusable` otherwise and never tried, `auto` picks the token when
  `touch_key` and `issued_key` are set, the lockout in the operator notes; Tasks 5, 7, 13.
- **I7** workloads cannot meet `applies_to_machines` → R21: workload `--key` a reference, PIN from
  `pin-source`; explain, `policy test` and lint say what proves it; Tasks 9, 13.
- **I8** `AgentSessionHeader` used before defined → defined in Task 5's interface block.
- **I9** `make test-hw`'s `-run` missed tests → no `-run`; the tags select.
- **I10** CRL check of DP-less intermediates → R9: link by link; Task 8 three-level test.
- **I11** `pkcs11` issued store needs the management key → R7: port49 never generates or writes on
  a token; `issued_key` is the user's own key; Task 7, L60 (g).
- **I12** shared homes and `.tpmkey` → R7: TPM pairs named for the machine; another machine's is no
  held pair; Task 7 test, L62 cell.
- **I13** libykcs11 under purego measured last → Task 3's `TestLibykcs11InitFinalizeUnderPurego`
  (no token, in CI) gates Tasks 5–7; L60 (a) keeps the token-present run.
- **I14** two-level attestation chain → R12: non-self-signed anchors are intermediates
  (`pivattest.Anchors`); chain depth *provisional on L60*; Task 10 three-level test.
- **I15** login opens the token before asking the agent → R8: a reference-key login asks the
  agent's status first and never opens the token when the agent holds it; `CKR_USER_NOT_LOGGED_IN`
  is `Locked`; Task 5 test; L60 (e2).
- **Minor 1** store errors and the challenge's take → R14 and Task 11: `store_unavailable`, take
  after the reservation.
- **Minor 2** replay under `reuse_for: 0m` → R14 and Task 11: replay before the requirement.
- **Minor 3** workload retry → Task 13: only the asked-for items, a new key.
- **Minor 4** a touch holding the wire → R14 and Task 13: the wire released across the touch.
- **Minor 5** the PIN as a Go string → Task 5: bytes, decoded by hand, zeroed.
- **Minor 6** test fakes and the guard table → Task 11's file list.
- **Minor 7** signature-change callers → Tasks 12 and 13 list them.
- **Minor 8** wrong mutation claim → Task 6's mutation now expects the `errors.As` failure.
- **Minor 9** wrong files → Task 11 names `broker.go`'s `authenticate`; Task 13 names `agent.go`'s
  `TokenRequest`.
- **Minor 10** stale spec texts → Task 1 Step 5.
- **Minor 11** comment-body tests → Review Focus 5's tests, the cross-binding case, the machine,
  unavailable, policy-test, diff, CRL bearer and refresh-reuse tests written out.
- **Minor 12** test defects → `s` checked before use, `[touch]` for the vocabulary and `[true]` for
  the decode, `TestTheKeyIsFixedToTheTPM` in Step 1.
- **Minor 13** SoftHSM per process → one `SOFTHSM2_CONF` per test binary (`TestMain`), a token per
  test.
- **Minor 14** `on_missing: exclude` → R11: a lint warning (refusing it would cut a legitimate
  scope shape; `security_log` records the lift).
- **Minor 15** diff exit and access review → Task 9: a weakening is gated like a privilege raise
  (controller's Task 1 review ruling 2026-10-12, decision 45 ruling 24; it was a warning with exit
  0); review rows show the levels each grant row carries.
- **Minor 16** `omitzero`, unsealed agent session → Task 11: `omitzero`; `agent_sha256` in
  `PutOnce` records.
- **Minor 17** swtpm version, AppArmor, CRL retry cost, upgrade order → Tech Stack, the workflow's
  swtpm smoke step, R9's one-minute failed-fetch memory, the operator notes' "Upgrade first".

## Re-review rulings (2026-10-12)

The re-review of the pre-flight fixes (GO on one condition: re-review R1–R5 in before the tasks
they touch) was ruled as below, each checked against the code at `7917f78`. As with the
pre-flight rulings, each is folded into the plan ruling it amends, so decision 45 carries it. The
re-review's numbers (re-review R1–R10) are not the plan's rulings R1–R22.

- **Re-review R1** `TakeOnce` spends another caller's record → R14, R16: the challenge keyed by
  SHA-256(challenge ‖ 0 ‖ principal), the proved record by SHA-256(challenge ‖ 0 ‖ principal ‖ 0
  ‖ fingerprint ‖ 0 ‖ agent_sha256); a wrong caller's take misses. Tasks 11, 12.
- **Re-review R2** an `idp_mfa` proof never kept → R15: `proofKey` over `agent_sha256`, the
  binding from the challenge record for both methods; Task 11's idp test gains a reuse step.
- **Re-review R3** import cycles (the controller's ruling: `hwkey` stays a leaf; the opener in a new
  package) → `internal/clientkey` holds `Open`, `LoadPair`, `HasPKCS11` and the build split, beside
  `keyfile`; `keyref` was not taken because `key_ref` already names a device's key in port49d.yaml.
  Tasks 3, 5, 7, 13, 14.
- **Re-review R4** test import cycles, counters in `_test.go` files → the counters' readers,
  `Finalize` and `ResetModules` in `pkcs11/testhooks.go` (`hwkey && hwkey_dlopen`, a non-test
  file); the SoftHSM tests are `package pkcs11_test`, and the swtpm tests `package tpm_test` for
  the same cycle through `hwtest.SWTPM`. Tasks 3, 4, 5, 7.
- **Re-review R5** I4's reload rule freezing policy edits → R11: refuse only entries a policy edit
  introduces, `loadBoth` by the same rule, `policy diff` on new entries, `policy test` on every
  quarantine as today. Task 9.
- **Re-review R6** a reconnect during a touch firing the alert → R14: the agent compares the
  exporter value after taking the wire back and does not post. Task 13.
- **Re-review R7** wrong `Resolve` arity → Task 9's test calls `Resolve(principal, d, now)`
  (resolve.go:102).
- **Re-review R8** `IssuedPathsIn`'s callers → its signature stays; the TPM pair's paths are a new
  `IssuedTPMPathsIn`, so `IssuedPaths`, `CABundlePathIn`, `userconfig_test.go` and
  `tests/lab/l56_test.go:189,200` are untouched. Task 7.
- **Re-review R9** (the controller's ruling) → R22: `make build` sets `CGO_ENABLED=0`; `make build-client`
  writes `bin/port49-client`. Tasks 3, 16, operator notes.
- **Re-review R10** `auto` picking a store the build lacks → R7: `auto` passes over it and says
  so; `TestChooseIssuedStore` gains the case. Task 7.

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, `CGO_ENABLED=0` for every binary; the only new modules are
  `github.com/ebitengine/purego` v0.11.1 and `github.com/google/go-tpm` v0.9.8.
- Static stays static (ruling 22): nothing outside a `//go:build hwkey_dlopen` file imports
  purego, directly or through a package; `make check-static` proves it for all four
  `STATIC_CMDS` (`port49d port49 port49-inventory port49-broker`), built as `bin/static/<cmd>`
  with `CGO_ENABLED=0` and no tag (re-review R9). `make vet` vets both tag sets.
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
- A start never fails over a hardware or attestation file (decision 43 ruling 14's rule); the start line
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
8. **The key re-inserted with nothing signing.** The held connection never drops, so no handshake
   signs; `State()` must re-probe from `Absent`, or the operator is stuck at "insert your key".
   Test in Task 6 (`TestAReinsertedKeyIsSeenWithoutASignature`) and Task 4's swtpm restart.
9. **The static build stays static.** `make check-static` in the `hwkeys` workflow (Task 3).

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
intersection is a load error naming both levels: `policy test` fails on it, `policy diff` fails
on one the new version introduces, and a reload of an edited policy that introduces one is
refused, while one already in force blocks no unrelated edit; where the policy did not change (a
start, an inventory reload, a grant's expiry) the device is quarantined with that cause (§10), so
an inventory sync never freezes the fleet's inventory. A machine principal is exempt except from levels
that set `applies_to_machines: true`, and a machine proves by `hardware_key_touch` alone, from a
key and touch slot on one token. A scope with a match key other than `name` that sets
`per_login_mfa` must declare `on_missing` and `security_log: true`; one pinned by `name` alone
needs neither.

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
  before and after, and a weakening (a method added to `accept`, a longer `reuse_for`, a level
  removed, `applies_to_machines` turned off, a requirement removed) fails the gate like a
  privilege raise: it fails unless a passing session test in the new version, on a device it is
  reported on, asserts the new `per_login_mfa:`. A tightening is printed and never fails. An empty
  intersection the new version introduces fails too, as a newly quarantined device does." Under
  "Policy tests", also: "A session test is what acknowledges a privilege raise, and a
  `per_login_mfa` weakening, to the gate." Add decision 45 ruling 24 (the controller's Task 1
  review ruling: a weakening is gated like a raise)."

- [ ] **Step 5: Amend decision 43 ruling 13.** Replace "takes a person's ID token at `POST
  /v1/certificate` alone" with "takes a person's ID token at `POST /v1/certificate`, and at `POST
  /v1/mfa` as an `idp_mfa` proof (decision 45 ruling 20)". Then the texts that ruling 13 and this
  plan leave stale (pre-flight minor 10), each found by its words, not its line number:
  - §5.7 (~2249) and decision 13 (~6368), where `amr` is "consulted by nothing": add "the session
    credential's; a per-login proof reads its own ID token's (decision 45 ruling 13)".
  - ~8934's "ten decision events" becomes "eleven".
  - ~7846's restatement of "alone (decision 43 ruling 13)" gains "as amended by decision 45 ruling
    20".

- [ ] **Step 6: Add decision 45** after decision 44's last ruling:

```markdown
**45. The agent in full, third part: hardware-backed client keys, `per_login_mfa`, and the broker
certificate's CRL check.** *Plan 9c, 2026-10-12, on plan 3's rulings of 2026-09-24, decision 42
ruling 13, and Ryan's direction of 2026-10-10.* Rulings rest on reasoning unless they say data.
Ruling 6 is gated on L63; rulings 3, 4, 8 and 12's PKCS#11 and attestation claims are
*provisional on L60*; ruling 13's `amr` on Keycloak is *provisional on L61*; ruling 5 on real
hardware and ruling 7's shared-home naming are *provisional on L62*. Ruling 22 rests on data:
a `CGO_ENABLED=0` build importing purego measured dynamically linked (plan 9c pre-flight C1).
```

  Then rulings 1–23, each one paragraph, from this plan's R1–R22 in order (R1 → 1 … R22 → 22), with
  ruling 23 "**The lab.** L60 (a YubiKey on the SER8; Ryan present), L61 (Keycloak's `amr`), L62 (the
  SER8's TPM), L63 (the Secure Enclave from an unsigned binary)." Copy each R's text as amended by
  the plan's pre-flight and re-review rulings; drop the "(pre-flight X)" and "(re-review RN)" tags; replace "this plan" with "plan 9c"
  and "Task N" with the plan's task name.

- [ ] **Step 7: §14.** Add a group **Hardware keys and per-login MFA** with these bullets:
  - "**One signer**: a PKCS#11, TPM and file key each sign a TLS 1.3 handshake and a refresh
    through `crypto.Signer`; CI runs the first two against SoftHSM2 and swtpm with `CGO_ENABLED=0`."
  - "**The PIN once**: a refused PIN is never sent again by port49."
  - "**The key unplugged**: the held connection mints; a refresh and a reconnect say to insert the
    key and end no session; a re-inserted key is seen by the next status or refresh with nothing
    signing between, and unlocked by `port49 login`."
  - "**Static stays static**: the build without `hwkey_dlopen` is statically linked."
  - "**Strictest wins**: the intersection and the least `reuse_for`; disjoint levels refuse the
    load naming both, and quarantine the device when only the inventory moved; machines exempt
    unless `applies_to_machines`."
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
| **L60** | A YubiKey's PIV applet through `libykcs11` under purego, on the SER8 (needs Ryan present, with a YubiKey 5). Whether: `C_Initialize` with `CKF_OS_LOCKING_OK` and no callbacks, and `C_Finalize`, run clean with the token present, `libykcs11`'s threads included; a slot 9a key (PIN policy once, touch never, a lab CA's certificate) signs a TLS 1.3 handshake and a refresh with `port49 login` asking the PIN once; the attestation certificates (slot f9 and each slot's) are reachable as certificate objects, chain to Yubico's PIV roots (the chain's depth for this firmware recorded: whether an intermediate sits under the root), and carry the touch policy (1.3.6.1.4.1.41482.3.8) and serial (…3.7) port49 reads; a slot 9c key with touch policy always proves `hardware_key_touch` with a touch, and with no touch within the token's timeout is refused in port49's words, and the timeout is recorded (decision 45 ruling 14 says about 15s); the token unplugged mid-session: `port49 token` mints on the held connection, `port49 refresh` says to insert the key, the session survives, and after re-insertion, with nothing minted between, the agent's `GET /status` says `locked`, `port49 login` asks the PIN and the refresh works; a `port49 login` or `port49 token` in another terminal does not de-authenticate the agent's PIV login; a wrong PIN is sent once and the message says the tries left; a key the user generated with `ykman` and named by `issued_key` (`issued_key_store: pkcs11`) is issued a certificate with port49 writing nothing to the token. Each cell against a control. | §13 decision 45 rulings 3, 4, 8 and 12; the operator notes (plan 13) | YubiKey 5 (firmware recorded), libykcs11 (version recorded), SER8 | open — added by plan 9c 2026-10-12; needs Ryan present |
| **L61** | Keycloak's `amr` and `acr` in an ID token for `idp_mfa`. With a realm flow of password and OTP, a `prompt=login` sign-in with both: whether the ID token carries `amr`, and which values, with Keycloak's AMR protocol mapper and with none; the control, a password-only sign-in, and its `amr`; whether `acr_values` changes either. | §13 decision 45 ruling 13 (the default `amr: [mfa]`); the operator notes' provider setup | Keycloak (26.x) | open — added by plan 9c 2026-10-12 |
| **L62** | A real TPM 2.0 through `/dev/tpmrm0` on the SER8 for a non-root user in `tss`: whether `issued_key_store: tpm` creates a key under the ECC SRK, signs a TLS 1.3 handshake and a refresh, survives an agent restart and a reboot, and is refused (cannot load) on another machine given the same key file; with a home directory another host shares (an NFS export, or the same directory mounted on the WSL host), each host's `port49 login --oidc` keeps its own `<host>_<port>.<machine>.tpmkey`, reads the other's as no held pair, and overwrites neither; the control, a user outside `tss`, is refused naming the group. | §13 decision 45 rulings 5 and 7 | SER8 (TPM vendor and firmware recorded) | open — added by plan 9c 2026-10-12 |
| **L63** | The macOS Secure Enclave through Security.framework under purego, from an unsigned `port49` built with `CGO_ENABLED=0`: whether `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` and `kSecAttrIsPermanent` creates a key, whether a second process finds it by label and signs with it, and what a refusal returns (`errSecMissingEntitlement`, -34018, or another). The control: the same calls for a software key. | §13 decision 45 ruling 6 (gate SE1) | macOS (version and hardware recorded) | open — added by plan 9c 2026-10-12; needs a macOS host |
```

  and after L59's detail bullet, one bullet each: "**L60**–**L63** — added by plan 9c. Why each is
  a row:" followed, per row, by the claim's dependency in one sentence (L60: decision 45's PKCS#11,
  PIN and touch claims are reasoning from the PKCS#11 and PIV specifications until a real token
  answers, and Yubico's attestation chain depth on current firmware is recollection, not
  measurement; L61: `idp_mfa`'s `amr` default is provider data; L62: swtpm is not a TPM's firmware;
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
- Create, every build: `internal/hwkey/pkcs11/consts.go`, `uri.go`, `ecdsa.go`, and their tests
  `uri_test.go`, `ecdsa_test.go`, `consts_test.go` (none imports purego, so `make test` runs them)
- Create, `//go:build hwkey_dlopen` (ruling 22): `internal/hwkey/pkcs11/module.go`, `signer.go`,
  `generate.go`
- Create, `//go:build hwkey && hwkey_dlopen`, a non-test file so `hwtest` and `cmd/port49`'s
  tests see it (re-review R4): `internal/hwkey/pkcs11/testhooks.go` (the call counters' readers,
  `Finalize`, `ResetModules`). The `hwkey` tag is set only by `make test-hw`, so no release build
  carries it.
- Create: `internal/hwkey/pkcs11/softhsm_test.go`, `ykcs11_test.go`, `main_hwkey_test.go` (each
  `//go:build hwkey && hwkey_dlopen`, each `package pkcs11_test`: they import `hwtest`, which
  imports `pkcs11`, and an in-package test would be an import cycle; re-review R4)
- Create: `internal/hwkey/hwtest/hwtest.go` (`//go:build hwkey`: swtpm for tests) and
  `hwtest_pkcs11.go` (`//go:build hwkey && hwkey_dlopen`: SoftHSM2)
- Create: `.github/workflows/hwkeys.yml`
- Modify: `Makefile` (`build` sets `CGO_ENABLED=0`; targets `test-hw`, `build-client`,
  `check-static`; `vet` gains the tags), `go.mod`, `go.sum`
- Modify: `internal/userconfig/userconfig.go` (export `CheckOwned(path string) error` for R3's
  module check: the directory walk, the links, the file), with tests in
  `internal/userconfig/userconfig_test.go` (`TestCheckOwnedJudgesTheModuleAndItsDirectories`)

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

// IsRef reports whether s is a key reference (pkcs11:, tpm:, secure-enclave:)
// rather than a path.
func IsRef(s string) bool
```

  `hwkey` imports no backend: `pkcs11`, `tpm` and `secureenclave` import it for `State`, the
  errors and `PINError`, and the opener that dispatches to them is Task 5's `internal/clientkey`
  (re-review R3).

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
func (s *Signer) TokenSerial() string // the token's CK_TOKEN_INFO serial, trimmed (ruling 12's same-token check)

// Generate makes a P-256 key pair (CKM_EC_KEY_PAIR_GEN, CKA_ID u.ID). Only
// the SoftHSM2 harness calls it: port49 never generates a key or writes an
// object on a token (decision 45 ruling 7).
func Generate(u URI, pin []byte) (*Signer, error)

// testhooks.go (//go:build hwkey && hwkey_dlopen; re-review R4). The
// counters are unexported atomic.Int64s in module.go, bumped at each call
// site in every hwkey_dlopen build; these read them.
func LoginCalls() int64           // C_Login
func OpenCalls() int64            // Open
func GenerateKeyPairCalls() int64 // C_GenerateKeyPair
func CreateObjectCalls() int64    // C_CreateObject
func Finalize(m *Module) uint     // C_Finalize, returning its CK_RV
func ResetModules()               // empties the one-Module-per-path cache
```

  Every `pkcs11` function above but `ParseURI` and `URI.String` lives in a `hwkey_dlopen` file.

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

  `internal/userconfig/userconfig_test.go`, `TestCheckOwnedJudgesTheModuleAndItsDirectories`
  (pre-flight I1): a 0755 module file in a 0700 directory passes; a group-writable module file is
  refused naming the file; a module in a group-writable directory is refused naming the directory;
  a symlink owned by the user pointing at a regular file the user owns passes (the libykcs11.so
  chain); a symlink to a directory is refused as "not a regular file".

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/hwkey/pkcs11/ -run 'TestParseURI|TestRawECDSAToDER|TestFunctionIndexes' -count=1` and `go test ./internal/userconfig/ -run CheckOwned -count=1`
Expected: FAIL (`undefined: ParseURI`, `rawECDSAToDER`, `CheckOwned`).

- [ ] **Step 3: Implement.**
  - `go get github.com/ebitengine/purego@v0.11.1` (and, for Task 4, `github.com/google/go-tpm@v0.9.8`).
  - `consts.go`: the `CKR_*`, `CKA_*`, `CKO_*`, `CKK_*`, `CKM_*`, `CKF_*`, `CKU_USER` values the
    package uses (from PKCS#11 v2.40 §3), and `fnInitialize = 0` … `fnGenerateKeyPair = 59`.
  - `userconfig.go`: `CheckOwned(path string) error` per ruling 3: `resolveOwned(filepath.Dir(path),
    false, "PKCS#11 module")` for the directories (it refuses a non-directory component, so it is
    never handed the file); then the base name `Lstat`ed, each symbolic link judged by `ownedBy`
    and followed (a relative target against the resolved directory, the target's own directory
    walked again by `resolveOwned`, at most `maxLinks`); the final component must be a regular
    file, owned by root or the user (`ownedBy`), with `mode&0o022 == 0`.
  - `module.go` (`hwkey_dlopen`): `Load` checks `path` with `userconfig.CheckOwned(path)`, then
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
    and zeroes the PIN slice it was handed. `CKR_USER_NOT_LOGGED_IN` from `C_Sign` is `Locked`
    and `hwkey.ErrLocked`. `Sign` and `State`:

```go
// Sign signs digest with the token's key: ECDSA (CKM_ECDSA, the raw r‖s
// turned into DER), RSA-PSS with SHA-256 (CKM_RSA_PKCS_PSS), or Ed25519
// (CKM_EDDSA over the message). A token gone is hwkey.ErrKeyAbsent, and the
// key's state Absent until State or Sign finds it again (reopen).
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)

// State is the key's state. While the cached state is Absent it re-probes,
// with no PIN: C_GetSlotList(tokenPresent) and C_GetTokenInfo matched by the
// URI, then reopen. So a re-inserted key is seen with nothing signing first
// (decision 45 ruling 8): the held connection never needs a handshake.
func (s *Signer) State() hwkey.State
```

    The PSS parameters are `CK_RSA_PKCS_PSS_PARAMS{hashAlg: CKM_SHA256, mgf: CKG_MGF1_SHA256,
    sLen: 32}` for `rsa.PSSSaltLengthEqualsHash` and `PSSSaltLengthAuto` alike; any other hash or
    PKCS#1 v1.5 is refused (TLS 1.3 and `api.SignRefresh` use neither). `reopen`: on `Absent`,
    `C_CloseSession` is ignored, the slot is found again by the URI, a session opened; `Locked` if
    it needs login, else `Present`.
  - `ecdsa.go`: `rawECDSAToDER(raw []byte, size int) ([]byte, error)` with `cryptobyte`.
  - `internal/hwkey/hwkey.go`: the types above and `IsRef(s string) bool` (prefix `pkcs11:`,
    `tpm:`, `secure-enclave:`), importing nothing of port49's. `Open` and `LoadPair` come in Task
    5, in `internal/clientkey` (re-review R3).
  - `module.go` keeps unexported `atomic.Int64` counters bumped at `C_Login`, `Open`,
    `C_GenerateKeyPair` and `C_CreateObject`; `testhooks.go` reads them and exposes `Finalize`
    and `ResetModules` for the libykcs11 test (re-review R4).
  - `Makefile`: `build` gains `CGO_ENABLED=0` on each line (no tag, the static build; re-review
    R9); `build-client` builds `bin/port49-client` with `CGO_ENABLED=0 go build -tags hwkey_dlopen`,
    never `bin/port49`, so the two builds never overwrite each other; `check-static` builds
    each of `STATIC_CMDS` as `bin/static/<cmd>` with `CGO_ENABLED=0` and no tag and fails
    unless `readelf -l` shows no program interpreter. It fails closed: a missing `readelf` is an
    error, and `readelf`'s own status is read (`out=$(readelf -l ...)` under `set -e`; a pipe
    would give grep's status); `vet` adds `go vet -tags hwkey_dlopen ./...` and `go vet
    -tags hwkey,hwkey_dlopen ./internal/hwkey/... ./internal/clientkey/... ./internal/agent/...
    ./internal/workload/... ./cmd/port49/...`.

- [ ] **Step 4: Run the unit tests**

Run: `go test ./internal/hwkey/... -count=1`
Expected: PASS.

- [ ] **Step 5: The SoftHSM2 harness.** `internal/hwkey/hwtest/hwtest_pkcs11.go`
  (`//go:build hwkey && hwkey_dlopen`). A module is initialized once per process and `Load` keeps
  one `Module` per path (ruling 3), so SoftHSM2 reads `SOFTHSM2_CONF` once: one configuration and
  token directory per test binary, set in `TestMain` before any `Load`, and a token per test
  (pre-flight minor 13):

```go
// SoftHSMMain is called from TestMain in each package that uses SoftHSM:
// it makes one SOFTHSM2_CONF and token directory for the test binary and
// sets the variable before any module loads, then runs m and removes the
// directory.
func SoftHSMMain(m *testing.M) int

// SoftHSM initializes a fresh token for one test, labelled
// "port49-test-<n>" (returned) with user PIN 123456 and SO PIN 12345678,
// in SoftHSMMain's directory, and returns the module path from
// $PORT49_TEST_PKCS11_MODULE (default /usr/lib/softhsm/libsofthsm2.so).
// With $PORT49_TEST_HW_REQUIRED set, a missing softhsm2-util or module
// fails the test instead of skipping it, so CI cannot go green by skipping.
func SoftHSM(t *testing.T) (module, label string)
```

  `SoftHSM` runs `softhsm2-util --init-token --free --label port49-test-<n> --pin 123456 --so-pin
  12345678`, generates a P-256 key with `CKA_ID` `01` through `pkcs11.Generate`, and registers a
  `t.Cleanup` that deletes the token (`softhsm2-util --delete-token --token <label>`). URIs in
  tests name the returned label.

- [ ] **Step 6: Write the integration tests**, each file `package pkcs11_test` (re-review R4).
  `internal/hwkey/pkcs11/main_hwkey_test.go` is
  `func TestMain(m *testing.M) { os.Exit(hwtest.SoftHSMMain(m)) }`.
  `internal/hwkey/pkcs11/softhsm_test.go` (`//go:build hwkey && hwkey_dlopen`):

```go
package pkcs11_test

func TestASoftHSMKeySignsATLSHandshakeAndARefresh(t *testing.T) {
	module, label := hwtest.SoftHSM(t)
	u, _ := pkcs11.ParseURI("pkcs11:token=" + label + ";id=%01?module-path=" + module)
	s, err := pkcs11.Open(u, []byte("123456"))
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
	module, label := hwtest.SoftHSM(t)
	u, _ := pkcs11.ParseURI("pkcs11:token=" + label + ";id=%01?module-path=" + module)
	s, err := pkcs11.Open(u, nil)
	if err != nil {
		t.Fatalf("Open with no PIN: %v", err)
	}
	defer s.Close()
	if s.State() != hwkey.Locked {
		t.Fatalf("Open with no PIN: state %v, want Locked", s.State())
	}
	before := hwtest.SoftHSMLoginAttempts(t)
	var pe *hwkey.PINError
	if err := s.Unlock([]byte("000000")); !errors.As(err, &pe) {
		t.Fatalf("Unlock(wrong) = %v, want a *PINError", err)
	}
	if got := hwtest.SoftHSMLoginAttempts(t) - before; got != 1 {
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
  bumps on each `C_Login` (an unexported `loginCalls atomic.Int64` in `module.go`, read through
  `testhooks.go`'s exported `LoginCalls`, a non-test file under `hwkey && hwkey_dlopen`, so
  `hwtest` can call it; a `_test.go` file would be seen by `pkcs11`'s own tests alone; re-review
  R4), not SoftHSM's logs; the counter is per process, so each test reads it before and after. `assertMutualTLS` runs an
  `httptest` TLS 1.3 server requiring a client certificate signed by a test CA for `s.Public()`.

  `TestAReinsertedTokenIsSeenByState`: open, then delete the token's slot directory under the
  harness's token directory (SoftHSM2's "unplug": `C_Sign` then answers a slot or session error,
  read as `Absent`), sign (`ErrKeyAbsent`, `Absent`), re-run `--init-token` with the same label and
  import the same key (`softhsm2-util --import` of a PKCS#8 the test kept), and assert `State()`
  answers `Locked` with no `Sign` between (pre-flight C2). If SoftHSM2 holds the token in memory
  so the delete never reads as gone, drop this test and say so in the task report: the re-probe is
  still covered by Task 4's swtpm restart and Task 6's fake.

  `internal/hwkey/pkcs11/ykcs11_test.go` (`//go:build hwkey && hwkey_dlopen`),
  `TestLibykcs11InitFinalizeUnderPurego` (decision 42 ruling 13's "9c's first task measures it";
  pre-flight I13): needs no token. With `pcscd` running and no card, five rounds of `Load` on
  `$PORT49_TEST_YKCS11_MODULE` (default the first match of
  `/usr/lib/*/libykcs11.so*`), `C_GetSlotList`, and `C_Finalize` (`pkcs11.Finalize`, from
  `testhooks.go`), each in a fresh `Module` (the per-path cache emptied by `pkcs11.ResetModules`);
  `/proc/self/task` counted before the first and after the last: no crash, no error but
  `CKR_OK`, and the thread count no higher after than after the first round. The same
  `$PORT49_TEST_HW_REQUIRED` rule. Tasks 5–7 build on purego only after this passes; if it fails,
  stop and take the reading to Ryan (decision 42 ruling 13: a route the measurement rules out is
  dropped only by Ryan).

- [ ] **Step 7: `make test-hw` and the workflow.** In the `Makefile`, add to `.PHONY` and:

```make
# Hardware-key tests against SoftHSM2, swtpm and libykcs11 (plan 9c; decision
# 42 ruling 13), built with CGO_ENABLED=0 and the client build's tag so
# purego runs as the client binary does. Needs softhsm2, swtpm, ykcs11 and a
# running pcscd; PORT49_TEST_HW_REQUIRED makes a missing one a failure, not a
# skip. No -run: the hwkey tag already selects the hardware tests, and a
# pattern would silently leave a new one out.
test-hw: check-static
	CGO_ENABLED=0 PORT49_TEST_HW_REQUIRED=1 go test -tags hwkey,hwkey_dlopen ./internal/hwkey/... ./internal/clientkey/... ./internal/agent/... ./internal/workload/... ./cmd/port49/... -count=1 -timeout 20m

# The static build (the image's, decision 45 ruling 22) must stay static: a
# purego import outside a hwkey_dlopen file would make it need a loader that
# distroless/static does not have.
check-static:
	@set -e; \
	command -v readelf >/dev/null || { echo "check-static needs readelf (binutils); without it nothing is checked"; exit 1; }; \
	mkdir -p bin/static; \
	for c in $(STATIC_CMDS); do \
	  CGO_ENABLED=0 go build -o bin/static/$$c ./cmd/$$c; \
	  out=$$(readelf -l bin/static/$$c); \
	  if printf '%s\n' "$$out" | grep -q 'program interpreter'; then \
	    echo "bin/static/$$c is dynamically linked; the image cannot run it"; exit 1; fi; \
	done
```

  `.PHONY` gains `test-hw build-client check-static`.

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
      - run: sudo apt-get update && sudo apt-get install -y softhsm2 swtpm swtpm-tools ykcs11 pcscd
      - run: sudo systemctl start pcscd.socket
      # Fails fast if swtpm cannot run here (an AppArmor profile refusing its
      # state directory, say), before twenty minutes of tests say it slowly.
      - run: swtpm --version && d=$(mktemp -d) && timeout 5 swtpm socket --tpm2 --tpmstate dir=$d --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init --daemon && pkill swtpm
      - run: make test-hw
```

- [ ] **Step 8: Run**

Run: `make test-hw` (on a host with them; install with `sudo apt-get install -y softhsm2 swtpm swtpm-tools ykcs11 pcscd`), then `make test && make vet`.
Expected: PASS; paste the summary lines, `TestLibykcs11InitFinalizeUnderPurego`'s thread counts
included. Mutation checks, each restored: change `fnSign` to 44 and see
`TestASoftHSMKeySignsATLSHandshakeAndARefresh` fail; import `pkcs11`'s binding from a file without
the tag (add a blank import of `internal/hwkey/pkcs11` to `cmd/port49` with `module.go`'s tag
dropped) and see `make check-static` fail.

- [ ] **Step 9: Commit**

```bash
git add internal/hwkey internal/userconfig Makefile .github/workflows/hwkeys.yml go.mod go.sum
git commit -m "feat: PKCS#11 keys through purego, tested on SoftHSM2

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: TPM 2.0 through go-tpm, and swtpm in CI

**Files:**
- Create: `internal/hwkey/tpm/tpm.go`, `tss2.go`, `tss2_test.go`
- Create: `internal/hwkey/tpm/swtpm_test.go` (`//go:build hwkey`, `package tpm_test`:
  `hwtest.SWTPM` sets `tpm.Dial`, so `hwtest` imports `tpm`, and an in-package test importing
  `hwtest` would be an import cycle; re-review R4)
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
package tpm_test

func TestATPMKeySignsAndSurvivesAReopen(t *testing.T) {
	hwtest.SWTPM(t) // sets tpm.Dial to swtpm over TCP for this test
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	s, err := tpm.Generate(path)
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
	again, err := tpm.Open(path)
	if err != nil || !again.Public().(*ecdsa.PublicKey).Equal(s.Public()) {
		t.Fatalf("reopen: %v", err)
	}
}

func TestATPMKeyFromAnotherTPMDoesNotLoad(t *testing.T) {
	hwtest.SWTPM(t)
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	if _, err := tpm.Generate(path); err != nil {
		t.Fatal(err)
	}
	hwtest.SWTPMFresh(t) // a second swtpm with its own state: another machine
	if _, err := tpm.Open(path); err == nil || !strings.Contains(err.Error(), "this machine's TPM") {
		t.Fatalf("Open on another TPM = %v, want refused naming this machine's TPM", err)
	}
}

func TestATPMGoneIsAbsentAndBackIsPresentWithoutASignature(t *testing.T) {
	sim := hwtest.SWTPM(t)
	s, err := tpm.Generate(filepath.Join(t.TempDir(), "k.tpmkey"))
	if err != nil {
		t.Fatal(err)
	}
	sim.Stop()
	if _, err := s.Sign(nil, make([]byte, 32), crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) || s.State() != hwkey.Absent {
		t.Fatalf("Sign with swtpm stopped = %v, state %v", err, s.State())
	}
	// Re-inserted: the same state directory. State re-probes from Absent with
	// no Sign in between (decision 45 ruling 8; pre-flight C2).
	sim.Restart()
	if got := s.State(); got != hwkey.Present {
		t.Fatalf("State after swtpm restarted = %v, want Present with no Sign between", got)
	}
}

// TestTheKeyIsFixedToTheTPM pins the template's attributes: a key that could
// leave the TPM is not a hardware key.
func TestTheKeyIsFixedToTheTPM(t *testing.T) {
	a := keyTemplate().ObjectAttributes
	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.UserWithAuth || !a.SignEncrypt || a.Decrypt {
		t.Fatalf("template attributes %+v", a)
	}
}
```

  (`TestTheKeyIsFixedToTheTPM` needs no TPM and reads the unexported `keyTemplate()`, so it
  lives in `tss2_test.go`, `package tpm`, with no tag and no `hwtest` import.)

  `hwtest.SWTPM(t)` starts `swtpm socket --tpm2 --server type=tcp,port=P --ctrl type=tcp,port=P+1
  --tpmstate dir=D --flags not-need-init,startup-clear` on two free ports, sets `tpm.Dial` to
  `tcp.Open(tcp.Config{CommandAddress: …, PlatformAddress: …})` after `PowerOn`, and returns a
  `*hwtest.TPM` with `Stop()` (the unplug) and `Restart()` (the re-insertion: the same state
  directory and ports, so the same SRK), the stop also registered with `t.Cleanup`; Task 6's
  `unplug_hw_test` uses both. `hwtest.SWTPMFresh(t)` stops the first and starts a
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
  until a call fails as absent, and while `Absent` it re-probes: a dial and a
  `GetCapability(TPM_CAP_TPM_PROPERTIES)`, `Present` when both answer (ruling 8). The template is
  `keyTemplate()`, so the test reads the one the code uses. `tss2.go`: `encoding/asn1` over the
  key-file structure, PEM type `TSS2 PRIVATE KEY`. Nothing here imports purego: this package is in
  every build (ruling 22).

- [ ] **Step 4: Run**

Run: `go test ./internal/hwkey/... -count=1` and `make test-hw`
Expected: PASS. Mutation checks, each restored: drop `FixedTPM` from `keyTemplate()` and see
`TestTheKeyIsFixedToTheTPM` fail; make `State` return the cached `Absent` without probing and see
`TestATPMGoneIsAbsentAndBackIsPresentWithoutASignature` fail.

- [ ] **Step 5: Commit**

```bash
git add internal/hwkey/tpm internal/hwkey/hwtest go.mod go.sum
git commit -m "feat: TPM 2.0 keys through go-tpm, tested on swtpm

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Key references in login and the agent; the PIN; `Unlock` and the key's state

**Files:**
- Create: `internal/clientkey/clientkey.go` (`Open`, `LoadPair`: a path to `keyfile`, `tpm:` to
  `tpm`), `internal/clientkey/open_dlopen.go` (`//go:build hwkey_dlopen`: `pkcs11:` and
  `secure-enclave:` dispatch, `HasPKCS11 = true`) and `internal/clientkey/open_static.go`
  (`//go:build !hwkey_dlopen`: the refusal naming the build, ruling 22; `HasPKCS11 = false`). A
  package of its own, not `hwkey`: the backends import `hwkey`, so an opener in `hwkey` importing
  them is an import cycle (re-review R3)
- Modify: `internal/userconfig/userconfig.go` (fields `TouchKey`, `IssuedKeyStore`, `IssuedKey`,
  `BrokerCRL`; references not resolved as paths; `CheckOwned` is Task 3's)
- Modify: `internal/broker/api/api.go` (`AgentSessionHeader`, defined here, used by Task 11;
  pre-flight I8)
- Modify: `cmd/port49/main.go` (`sessionFlags`: `--touch-key`, `--pin-fd`; `config` loads through
  `clientkey.LoadPair`; `startAgentDown` passes the PIN on descriptor 4; `login` asks the PIN, unlocks a
  running agent)
- Modify: `internal/agent/agent.go` (`Config.TouchKey`; `Status.KeyState`; `POST /unlock`; the
  agent session), `internal/agent/socket.go` (`Client.Unlock`)
- Test: `internal/clientkey/clientkey_test.go`, `internal/clientkey/open_static_test.go`
  (`//go:build !hwkey_dlopen`), `internal/userconfig/userconfig_test.go`,
  `cmd/port49/login_hw_test.go` and `cmd/port49/main_hwkey_test.go` (`//go:build hwkey &&
  hwkey_dlopen`), `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: Task 3's `pkcs11.Open`, `Signer.Certificate`, `Signer.TokenSerial`; Task 4's
  `tpm.Open`, `tpm.OpenHandle`.
- Produces:

```go
// internal/broker/api
// AgentSessionHeader carries the agent's session: 32 random bytes,
// base64url, drawn at the agent's start (decision 45 ruling 15).
const AgentSessionHeader = "Port49-Agent-Session"

// internal/clientkey (re-review R3; imports hwkey, pkcs11, tpm, keyfile)
// Open opens the key a reference names; pin may be nil (the key is then
// Locked where the token needs one).
func Open(ref string, pin []byte) (hwkey.Key, error)

// LoadPair is keyfile.LoadX509KeyPair for a key that may be a reference:
// a path goes to keyfile unchanged; a reference is opened, and certPath ""
// takes the token's certificate for a pkcs11 key. The certificate's public
// key must be the key's.
func LoadPair(certPath, keyRef string, pin []byte) (tls.Certificate, error)

// HasPKCS11 is whether this build carries the purego backends (the
// hwkey_dlopen tag, ruling 22): true in open_dlopen.go, false in
// open_static.go. Task 7's auto reads it (re-review R10).
const HasPKCS11 bool

// agent
type Config struct {
	// … as today, and:
	// TouchKey is the touch_key slot, nil when none is configured.
	TouchKey hwkey.Key
}

type Status struct {
	// … as today, and:
	KeyState string `json:"key_state"` // present | absent | locked; "present" for a file key
	// TouchKey is true only when the touch key opened and sits on the same
	// token (module and token serial) as a pkcs11 session key (ruling 12);
	// TouchKeyUnusable says why not when touch_key is configured.
	TouchKey         bool   `json:"touch_key"`
	TouchKeyUnusable string `json:"touch_key_unusable,omitempty"`
	// KeyRef is the session key's reference in canonical form (never a PIN),
	// "" for a file key: what login compares before it opens a token.
	KeyRef string `json:"key_ref,omitempty"`
}

func (c *Client) Unlock(ctx context.Context, pin []byte) error // POST /unlock {"pin": "…"}
```

- [ ] **Step 1: Write the failing tests.**
  - `internal/userconfig/userconfig_test.go`, `TestKeyReferencesAreNotPaths`: a config with
    `key: "pkcs11:id=%01?module-path=/usr/lib/libykcs11.so"`, `touch_key:` the same with `%02`,
    `issued_key_store: tpm`, `broker_crl: require` loads with the references byte for byte (not
    joined to the file's directory); `issued_key_store: floppy` and `broker_crl: maybe` are refused,
    naming the allowed words; the system file's `touch_key` is overridden by the personal file's.
  - `internal/clientkey/clientkey_test.go`, `TestLoadPairRefusesAMismatchedCertificate` (a file key under
    a certificate for another key is refused, as `keyfile` does today) and
    `TestOpenRefusesAnUnknownScheme`. `internal/clientkey/open_static_test.go` (`!hwkey_dlopen`),
    `TestTheStaticBuildSaysItHasNoPKCS11`: `Open("pkcs11:id=%01?module-path=/x.so", nil)` and
    `Open("secure-enclave:label=x", nil)` refuse with "built without PKCS#11 support" and "client
    release" in the text; `tpm:file=` reaches `tpm.Open` (a missing file's error, not the build's).
  - `internal/agent/agent_test.go`, `TestStatusSaysTheKeyState` with a fake `hwkey.Key` (a
    `fakeKey` in the test file: an ECDSA key whose device presence the test sets, a cached state
    that only `State()`'s probe or a `Sign` moves, as the backends do, and an `Unlock` that records
    the PIN it got): `GET /status` says `locked`; `Client.Unlock` with `123456` makes it `present`;
    the PIN reached the key once and the agent's log holds no `123456`. `TestTouchKeyIsReportedOnlyOnTheSessionToken`:
    a touch key on the session key's token (same module and serial) reports `touch_key: true`; a
    touch key with a TPM session key, or on another token, reports `touch_key: false` and
    `touch_key_unusable` naming why, and the agent starts in every case (pre-flight I6).
  - `cmd/port49/login_hw_test.go` (`//go:build hwkey && hwkey_dlopen`, with `main_hwkey_test.go`'s
    `TestMain` calling `hwtest.SoftHSMMain`), `TestLoginAsksThePINOnceAndSaysTriesLeft`:
    against SoftHSM2 and the in-process broker the existing login tests use, `port49 login --key
    pkcs11:…` with the PIN piped to a pty: asks once, starts the agent, refreshes; with a wrong PIN:
    exits 1, says "the token refused the PIN", sends no second `C_Login`, never prints the PIN.
    `TestLoginWithTheKeyOutReachesTheAgent` (pre-flight I15): with the agent running and its key
    reported `absent`, `port49 login` (same broker, same `key_ref`) never calls
    `pkcs11.Open` (`pkcs11.OpenCalls()` and `pkcs11.LoginCalls()` unchanged, read through Task 3's
    `testhooks.go`; re-review R4) and prints "insert your key and run
    `port49 login` again; your session goes on until …", exit 1; reported `locked`, it asks the PIN
    and calls `Client.Unlock`.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/userconfig/ ./internal/clientkey/ ./internal/agent/ -run 'KeyReferences|LoadPair|OpenRefuses|StaticBuildSays|StatusSaysTheKeyState|TouchKeyIsReported' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `userconfig.File` gains `TouchKey string yaml:"touch_key"`, `IssuedKeyStore string
    yaml:"issued_key_store"` (`auto`, `file`, `tpm`, `secure_enclave`, `pkcs11`), `IssuedKey string
    yaml:"issued_key"`; `BrokerCRL string yaml:"broker_crl"` (`check`, `require`, `off`) is already
    present (Task 8), as are `sessionFlags.brokerCRL`, `--broker-crl` and its place in `args()`:
    do not add them again. `overlay` takes each; `parse` resolves `Cert` and `Key` as paths only when `!hwkey.IsRef`, and `TouchKey`
    and `IssuedKey` must be references. (`userconfig` → `hwkey` is acyclic only because `hwkey`
    is a leaf: `pkcs11` imports `userconfig` for `CheckOwned`; re-review R3.)
  - `sessionFlags` gains `touchKey`, `pinFD`, `issuedKeyStore`, `issuedKey` with flags
    `--touch-key`, `--pin-fd` (internal); `args()` passes `--touch-key`. (`brokerCRL`,
    `--broker-crl` and its `args()` entry are already present from Task 8.)
  - `sessionFlags.config` loads with `clientkey.LoadPair(s.cert, s.key, pin)`, where `pin` is read from
    `--pin-fd` (at most 64 bytes, the descriptor closed after) in the agent child, and nil in the
    login. `clientkey.LoadPair` and `clientkey.Open` dispatch on the scheme: `pkcs11:` →
    `pkcs11.ParseURI`, then `pin-source` read through `keyfile.ReadSecret` when set; `tpm:file=` →
    `tpm.Open`; `tpm:handle=` → `tpm.OpenHandle`; `secure-enclave:` → an error naming Task 14's gate
    until that task lands. The `pkcs11:` and `secure-enclave:` arms live in `open_dlopen.go`;
    `open_static.go` answers both "this port49 was built without PKCS#11 support (the static
    build, as in the container image); use the client release" (ruling 22).
  - `login` with a reference key asks the running agent first (pre-flight I15): before
    `sf.config`, when `agent.NewClient(socket).Status` answers for this broker, `login` checks
    that the agent holds this login's key without opening the token: with a `cert:` file, its
    fingerprint equals `Status.CertFingerprint`; with the certificate on the token, the canonical
    reference (`URI.String()`, never a PIN) equals a new `Status.KeyRef`. When it does: `absent` →
    "insert your key and run `port49 login` again; your session goes on until
    <session_ends_at>", exit 1; `locked` → the PIN asked and `Client.Unlock`, then the refresh as
    today; `present` → as today. Only otherwise does `login` open the token.
  - `login`, starting an agent: after loading, a key whose `State()` is `Locked` asks the PIN with
    `term.ReadPassword` on the controlling terminal ("PIN for <token label>: "), or refuses with no
    terminal and no `pin-source` ("this key needs its PIN and there is no terminal to ask it on;
    set pin-source=file:///path in the key's URI"). `Unlock` is called once; a `*hwkey.PINError`
    exits 1 with "the token refused the PIN" and, by its flags, "fewer tries are left" or "one try
    is left before the key locks: unlock it with your token's own tool if it locks". The PIN goes
    to the agent child on a pipe as descriptor 4 (`ExtraFiles` gains it after the CA's), then the
    slice is zeroed.
  - The agent: `Config.TouchKey` is opened by the agent child from `--touch-key` with the same PIN
    when it is on the same token (same module and `TokenSerial`) as a `pkcs11:` session key, and
    `Status.TouchKey` is true only then. Otherwise (a TPM, file or Secure Enclave session key,
    another token, no token matching) the agent starts anyway, `Status.TouchKey` is false and
    `TouchKeyUnusable` says why (ruling 12; pre-flight I6). An open failure of the touch key is
    never a start failure.
  - `POST /unlock` reads the body as bytes (at most 64 bytes of PIN inside a 256-byte body) and
    decodes the `pin` field by hand from a `json.RawMessage` into a `[]byte` (a Go string cannot be
    zeroed; pre-flight minor 5), calls `Unlock` on the session key and the touch key, zeroes the
    body and the PIN, and answers 200 or 401 `pin_refused` with the flags' words. `Client.Unlock`
    builds the body in a `[]byte` it zeroes after the write.
  - The agent draws `agentSession` (32 random bytes) in `New` and sets `api.AgentSessionHeader`
    (base64url) on every broker request in `doOn`. The broker ignores the header until Task 11.
  - `hardenAgent` stays first in `agentMain`: no core file holds a PIN either.

- [ ] **Step 4: Run**

Run: `go test ./internal/userconfig/ ./internal/hwkey/... ./internal/clientkey/ ./internal/agent/ ./cmd/port49/ -count=1`, then `make test-hw`, then `make test && make vet`.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/hwkey internal/clientkey internal/userconfig internal/agent internal/broker/api cmd/port49
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
  broker the agent tests use and Task 5's `fakeKey`, which models the backends (pre-flight C2):
  `unplug()` and `plug()` set only whether the device is there; the cached state moves only when
  `Sign` fails (to `Absent`) or `State()` probes from `Absent` (to `Present`, or `Locked` when the
  test set `needsPIN`). `probes()` counts `State()`'s probes and `signs()` counts `Sign` calls.

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
	// Re-inserted: Refresh asks State, which re-probes from Absent; nothing
	// signed in between.
	key.plug()
	if _, err := a.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh after the key came back: %v", err)
	}
}

// TestAReinsertedKeyIsSeenWithoutASignature is the 3am trace: the held
// connection never drops, so no handshake signs after the key comes back.
// The key must still be seen (decision 45 ruling 8; pre-flight C2).
func TestAReinsertedKeyIsSeenWithoutASignature(t *testing.T) {
	b, key := startBrokerWithFakeKey(t)
	a := New(b.agentConfig(key))
	if _, err := a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := serveSocket(t, a) // the agent's socket, as login reaches it
	key.unplug()
	if _, err := a.Refresh(context.Background()); err == nil {
		t.Fatal("refresh with the key out succeeded")
	}
	if got := srv.status(t).KeyState; got != "absent" {
		t.Fatalf("status with the key out = %q, want absent", got)
	}
	// Back, and needing its PIN. No mint, no refresh, no handshake.
	key.needsPIN = true
	key.plug()
	signs := key.signs()
	if got := srv.status(t).KeyState; got != "locked" {
		t.Fatalf("status after re-insertion = %q, want locked (State must re-probe from Absent)", got)
	}
	if key.signs() != signs || key.probes() == 0 {
		t.Fatalf("seen by %d signs and %d probes; want a probe and no sign", key.signs()-signs, key.probes())
	}
	// Absent then Present on the next probe, no PIN needed: present at once.
	key.unplug()
	_, _ = a.Refresh(context.Background())
	key.needsPIN = false
	key.plug()
	if got := srv.status(t).KeyState; got != "present" {
		t.Fatalf("status after re-insertion = %q, want present", got)
	}
}
```

  Also `TestARefusedCertificateStillEndsTheSession`: with the key present and the broker refusing
  the certificate at a reconnect, `a.Done()` closes as today (the change must not swallow a real
  refusal). `internal/agent/unplug_hw_test.go` (`//go:build hwkey`): the same scenario on swtpm,
  `hwtest.SWTPM`'s `Stop()` as the unplug and `Restart()` (the same state directory) as the
  re-insertion, then `a.Refresh` with no mint and no reconnect in between: it succeeds.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/agent/ -run 'Unplugged|ReinsertedKey|RefusedCertificateStill' -count=1`
Expected: FAIL (the session ends, the error is a refusal, or the status stays `absent`).

- [ ] **Step 3: Implement.** In `Refresh`, before `refreshOnce`, and in `refusedReconnect`, first:

```go
// keyState is the session key's state; a file key is always present. A
// hardware key's State re-probes while it is Absent (decision 45 ruling 8),
// so this is never a cached Absent.
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
  print it as is, exit 1. `GET /status`'s `key_state` is `keyState()`, so it probes too. A
  `Refresh` whose `keyState()` is `Absent` after the probe returns the `KeyAbsentError` without
  signing; it never refuses on a cached state.

  **Built differently (task 5):** the socket answers 409 `key_absent` on `/unlock`, and 502 with
  `touch_timeout`, `key_locked` or `key_absent` on mint, refresh and `/identity`, not `503 key_absent`. A 503
  would land in the `StatusServiceUnavailable` arms of `Client.Token` and `Client.Refresh`, which
  know only `revocation_running` and would lose the `*KeyError`; 503 also means "retry later",
  which a key failure is not. The client rebuilds the error from the code. Ledgered deviation.

- [ ] **Step 4: Run**

Run: `go test ./internal/agent/ ./cmd/port49/ -count=1`, `make test-hw`, then `make test && make vet`.
Expected: PASS. Mutation checks, each restored: make `refusedReconnect` ignore the key state and
see `TestAKeyUnpluggedNeverEndsTheSession` fail at the reconnect's `errors.As(err, &absent)` (a
handshake that fails to sign is not a `refusal()` today, so the session does not end; the error is
simply not a `KeyAbsentError`; pre-flight minor 8); have `GET /status` and `Refresh` read a state
the agent kept from its last `KeyAbsentError` instead of calling `keyState()`, and see
`TestAReinsertedKeyIsSeenWithoutASignature` fail at "want locked". (The backends' own probe is
mutated in Task 4.)

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
- Modify: `internal/userconfig/userconfig.go` (a new `IssuedTPMPathsIn` and `IssuedTPMPaths`
  for the TPM pair, named for this machine; `IssuedPathsIn` keeps its signature, so its callers
  are untouched: `IssuedPaths` and `CABundlePathIn` in `userconfig.go`, `TestIssuedPaths` in
  `userconfig_test.go:606–618`, `tests/lab/l56_test.go:189,200` (built by `make test` through
  `lab-unit`), and through `IssuedPaths` `cmd/port49/issue.go:63` and
  `cmd/port49/issue_login_linux_test.go:67`; re-review R8), with tests in `userconfig_test.go`
- Test: `cmd/port49/issuedkey_test.go`, `cmd/port49/issuedkey_hw_test.go` (`//go:build hwkey`:
  swtpm) and `cmd/port49/issuedkey_pkcs11_hw_test.go` (`//go:build hwkey && hwkey_dlopen`:
  SoftHSM2)

**Interfaces:**
- Consumes: `tpm.Generate`, `tpm.Open`, `clientkey.Open` (a `pkcs11:` `issued_key`, opened, never
  generated: ruling 7), `clientkey.LoadPair`, `clientkey.HasPKCS11`; under `hwkey &&
  hwkey_dlopen`, `pkcs11.GenerateKeyPairCalls` and `pkcs11.CreateObjectCalls` (Task 3's
  `testhooks.go`; re-review R4).
- Produces:

```go
// issuedKeyStore is the store a sign-in's key goes into (decision 45 ruling
// 7), chosen before the sign-in so a store that cannot be used costs no
// password: "file", "tpm", "secure_enclave" or "pkcs11".
func chooseIssuedStore(sf *sessionFlags, stderr io.Writer) (store string, err error)

// newIssuedKey is the sign-in's key in store: for "file" an ECDSA P-256 key
// generated in memory, written with the certificate as today; for "tpm" a
// key generated in tpmPath; for "pkcs11" the key sf.issuedKey names, which
// the user made once on the token and port49 only opens and signs with.
func newIssuedKey(store string, sf *sessionFlags, tpmPath string) (crypto.Signer, func() ([]byte, error), error)

// userconfig
// IssuedTPMPathsIn is where, under dir, this machine keeps a TPM-held pair:
// tpmKey <host>_<port>.<machine>.tpmkey and tpmCert <host>_<port>.<machine>.pem
// beside IssuedPathsIn's pair, <machine> the first 8 hex digits of SHA-256 of
// /etc/machine-id (ruling 7), so hosts sharing a home directory keep a pair
// each. The broker URL is judged as IssuedPathsIn judges it. IssuedPathsIn
// is unchanged (re-review R8).
func IssuedTPMPathsIn(dir, broker string) (tpmCert, tpmKey string, err error)

// IssuedTPMPaths is IssuedTPMPathsIn ~/.port49 (Dir).
func IssuedTPMPaths(broker string) (tpmCert, tpmKey string, err error)

// MachineID is that 8-hex-digit name; an exported var so cmd/port49's tests
// set it.
var MachineID = func() (string, error)
```

- [ ] **Step 1: Write the failing tests.** `cmd/port49/issuedkey_test.go`:
  `TestChooseIssuedStore` — `auto` on Linux with `tpm.Dial` failing picks `file` and says "no TPM
  this user can use (…); the key is a file"; `auto` with `touch_key` and `issued_key` both set
  picks `pkcs11` and says so (pre-flight I6) when `clientkey.HasPKCS11`; in the static build
  (`!clientkey.HasPKCS11`, as `make test` builds it) the same `auto` passes over `pkcs11`, says
  "built without PKCS#11 support, so issued_key is not used", and picks the TPM or the file,
  never refusing (re-review R10); `tpm` named with the dial failing refuses before any
  sign-in (the test's fake provider records no authorization request); `pkcs11` without
  `issued_key` refuses naming `issued_key`; `pkcs11` named in the static build refuses naming the
  client release (ruling 22); `secure_enclave` on Linux refuses. Each case that depends on the
  build reads `clientkey.HasPKCS11`, so the test holds under `make test` and `make test-hw`
  alike. `TestIssuedTPMPaths` (`userconfig_test.go`): the pair is named for `MachineID`, and a
  broker URL `IssuedPathsIn` refuses is refused. `TestAHeldTPMPairIsFound`:
  with `<host>_<port>.<machine>.tpmkey` and `.pem` present and no `.key`, `heldCertificate` loads
  through `clientkey.LoadPair`. `TestAnotherMachinesTPMKeyIsNoHeldPair` (pre-flight I12): with
  `userconfig.MachineID` set to `aaaaaaaa` and only `<host>_<port>.bbbbbbbb.{tpmkey,pem}` present,
  `heldCertificate` reports no held pair (a sign-in, never an error), and the sign-in that follows
  writes `….aaaaaaaa.{tpmkey,pem}` and leaves both `bbbbbbbb` files byte for byte. `issuedkey_hw_test.go`: on
  swtpm, `port49 login --oidc` with the test authorization server (plan 9b's) writes
  `.<machine>.tpmkey` (0600), no `.key`, the certificate's key is the TPM's, and the agent
  refreshes. `issuedkey_pkcs11_hw_test.go`: on SoftHSM2, the harness makes a key `%10` (the user's
  one-time `ykman piv keys generate`), and with `issued_key_store: pkcs11` and `issued_key:
  "pkcs11:token=<label>;id=%10?module-path=…"` the login signs the CSR with it, writes the
  certificate to `<host>_<port>.pem` and nothing to the token (the token's object list is the same
  before and after, and `pkcs11.GenerateKeyPairCalls()` and `pkcs11.CreateObjectCalls()` read the
  same after the harness made `%10` and after the login); an `issued_key` naming no key refuses before the browser, saying to make one with
  the token's own tool (pre-flight I11).

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ -run 'ChooseIssuedStore|HeldTPMPair|AnotherMachinesTPMKey' -count=1` and `go test ./internal/userconfig/ -run IssuedTPMPaths -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.** `issueCertificate` calls `chooseIssuedStore` after `fetchBrokerConfig`
  and before `oidcclient.Discover`; `chooseIssuedStore`'s `auto` tries `pkcs11` only when
  `clientkey.HasPKCS11`, and otherwise says why it passed over a configured `issued_key` in the
  one line that names the store (re-review R10); the TPM pair's paths come from
  `userconfig.IssuedTPMPaths`, the file pair's from `IssuedPaths` as today (re-review R8); `ecdsa.GenerateKey` becomes `newIssuedKey`; `api.IssuanceNonce`
  takes the signer's `Public()`; `x509.CreateCertificateRequest` takes the signer; the check
  `key.PublicKey.Equal(leaf.PublicKey)` becomes `signer.Public().(interface{ Equal(crypto.PublicKey)
  bool }).Equal(leaf.PublicKey)`. Writing: for `file` as today; for `tpm` the `.<machine>.tpmkey`
  was written by `tpm.Generate` (to a staged name, renamed with the certificate through
  `WritePrivateAll`'s order: key first, certificate last) and any old `.key` removed; for `pkcs11`
  the certificate alone, to `.pem` (port49 writes nothing to the token). `startIssued` passes
  `--key` as the path or reference. `heldCertificate` looks for `.key`, then this machine's
  `.<machine>.tpmkey` (`tpm:file=…`), then, with `issued_key_store: pkcs11`, the reference; another
  machine's `.tpmkey` is not looked at, so it reads as no held pair and is never removed or
  overwritten. A held pair whose key is absent says "your key (<store>) is not present: insert it,
  or `port49 login --sign-in` signs in for a new one". A TPM pair's certificate is named for the
  machine too (`<host>_<port>.<machine>.pem`), so one host's sign-in never replaces the
  certificate another host's key needs: no ping-pong.

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
		{"no distribution point under check: nothing checked, nothing said", ModeCheck, "down", true, false, ""},
		{"no distribution point under require refuses", ModeRequire, "good", true, true, ""},
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

// An intermediate naming no distribution point (step-ca's default) is passed
// over under check, and the leaf it issued is still checked (decision 45
// ruling 9; pre-flight I10). Under require it is refused: it is a link with no
// fetchable list (Ryan, 2026-10-12).
func TestAnIntermediateWithNoDistributionPoint(t *testing.T) {
	for _, tc := range []struct {
		serve   string
		mode    Mode
		refused bool
	}{
		{"good", ModeCheck, false},
		{"revoked", ModeCheck, true}, // the leaf's own list still refuses
		{"good", ModeRequire, true},  // the intermediate names none
	} {
		cs, _ := threeLevelChain(t, tc.serve) // root → intermediate (no DP) → leaf (DP, list by the intermediate)
		var said []string
		c := New(privateDir(t), tc.mode, time.Now, func(s string) { said = append(said, s) })
		err := c.VerifyConnection(cs)
		if (err != nil) != tc.refused || len(said) != 0 {
			t.Fatalf("%s under %s: %v, said %q", tc.serve, tc.mode, err, said)
		}
		var ne *NoDistributionPointError
		if tc.mode == ModeRequire && (!errors.As(err, &ne) || !strings.Contains(err.Error(), "broker intermediate")) {
			t.Fatalf("require with a DP-less intermediate: %v, want *NoDistributionPointError naming it", err)
		}
	}
}

// A revoked leaf is reported as revoked, not as the missing distribution point
// of an intermediate above it.
func TestRevokedBeatsAMissingDistributionPointUnderRequire(t *testing.T) { /* threeLevelChain "revoked", ModeRequire: errors.As *RevokedError */ }

// A one-certificate chain is the trust anchor itself: nothing above it can
// list it, so require passes it (you revoke it by removing it from the trust file).
func TestASelfSignedAnchorPassesUnderRequire(t *testing.T) { /* VerifiedChains {{root.Cert}}, ModeRequire: nil */ }

// A down CRL server costs one wait, not one per connection.
func TestAFailedFetchIsRememberedForAMinute(t *testing.T) { /* serve "down" counting requests: three VerifyConnection calls within a minute make one fetch; after the fixture clock passes a minute, a fourth fetches again */ }

func TestNoBearerTokenReachesARevokedBroker(t *testing.T) {
	cs, srv := brokerChain(t, "revoked", false)
	called := false
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	broker.TLS = tlsServerFor(t, cs) // the revoked leaf and its chain
	broker.StartTLS()
	defer broker.Close()
	c := New(t.TempDir(), ModeCheck, time.Now, func(string) {})
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: poolOf(cs), VerifyConnection: c.VerifyConnection}}}
	req, _ := http.NewRequest("POST", broker.URL+"/v1/certificate", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer an-id-token")
	if _, err := client.Do(req); err == nil {
		t.Fatal("a request to a revoked broker succeeded")
	}
	if called {
		t.Fatal("the revoked broker's handler saw the request, bearer token and all")
	}
	_ = srv
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/brokercrl/ -count=1`
Expected: FAIL (`undefined: New`).

- [ ] **Step 3: Implement.** For each certificate `chain[i]` of `cs.VerifiedChains[0]` but the
  root, each `CRLDistributionPoints` URL with scheme `http` or `https` is a `certstatus.CRLSource{
  Name: <host>-<first 8 hex of SHA-256(url)>, URL: url, Issuer: chain[i+1]}`; none at all and
  nothing is fetched (under `check` the check returns nil; under `require` it refuses, below).
  `certstatus.New(certstatus.Config{CRLs: srcs, StateDir: dir}, now,
  metrics.New(prometheus.NewRegistry()), logf)` is built once per distinct source set and kept;
  `LoadPersisted`, then `LoadAll` with a 5s context when no kept list is fresh; a `LoadAll` that
  failed is not tried again for a minute (the `Checker` keeps when it failed), so a CRL server that
  is down costs login's three connections one wait, not three. The check is link by link
  (pre-flight I10): for each `i` whose `chain[i]` names an http(s) distribution point,
  `Check(ctx, []*x509.Certificate{chain[i], chain[i+1]})`, never `Check(ctx, chain)`, which would
  read an intermediate with no distribution point as `Unknown`. A link with no http(s)
  distribution point is recorded, not checked: under `check` it is passed over and nothing is
  said; under `require` the first such link is refused with `*NoDistributionPointError` ("add an
  HTTP CDP to the CA, or set broker_crl: check"), but only after the other links have been
  checked, so a revoked link is reported as `*RevokedError` first. The trust anchor is never a
  link, so a one-certificate chain passes. Each result: `Revoked` → `*RevokedError` (both modes); `Unknown` → under `check`
  `warn(...)` once per `Checker` and nil, under `require` an error naming the list and
  "broker_crl: require". `dir` is
  `~/.port49/crl/`, made 0700 through `userconfig.PrivateDir`. `sessionFlags.config`,
  `fetchBrokerConfig`, `requestCertificate` and the `/v1/mfa` client (Task 13) set
  `VerifyConnection`; the agent's `tls.Dialer.Config` gets it from `Config.VerifyBroker`; the
  workload client from its own `Config.VerifyBroker`. The warning goes to the agent's log and, in
  `login`, to stderr.

- [ ] **Step 4: Run**

Run: `go test ./internal/brokercrl/ ./internal/agent/ ./internal/workload/ ./cmd/port49/ -count=1`, then `make test && make vet`.
Expected: PASS. Mutation checks, each restored: return nil for `Revoked` under `check` and see the
two revoked cases fail; pass the whole chain to `Check` and see
`TestAnIntermediateWithNoDistributionPoint` fail.

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
  (`Resolution.PerLoginMFA`; `checkDevices`'s quarantine cause), `internal/policy/member.go`
  (`resolveAll` wraps a disjoint composition as `ErrCompositionRefused`),
  `internal/policy/explain.go` (render), `internal/policy/tests.go` (the assertion),
  `internal/policy/diff.go` (the change and the weakening gate), `internal/policy/lint.go`
  (two warnings), `internal/policy/review.go` (each row's levels)
- Modify: `internal/port49d/reload.go` (`load` and `loadBoth` refuse a bundle with an
  MFA-disjoint entry the in-force policy over the same inventory does not have; an inventory
  reload does not; re-review R5), `cmd/port49/policy.go` (`policy diff` fails on an unacknowledged weakening, `d.UnacknowledgedMFA() > 0`, and on an entry the new
  version introduces; `policy test` already fails on every quarantine)
- Test: `internal/policy/mfa_test.go`, `internal/policy/member_test.go`,
  `internal/port49d/reload_test.go`

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

// MFADisjoint lists the quarantined devices with an entry whose cause is
// ErrMFADisjoint (or the machine refusal), only those entries kept: what a
// start or an inventory reload quarantines (ruling 11).
func (p *Policy) MFADisjoint() []Quarantine

// NewMFADisjoint is the entries of after.MFADisjoint() that base's lack,
// matched by device, subject and cause: what a policy edit introduces, and
// all a policy-file reload, loadBoth and `policy diff` refuse. base is the
// in-force policy over the same inventory; nil base is every entry
// (re-review R5).
func NewMFADisjoint(base, after *Policy) []Quarantine

// in QuarantineEntry:
//	MFA bool // the cause is per_login_mfa's (ruling 11)
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

// disjointPolicy's role and scope share no method on core-sw01 alone.
const disjointPolicy = `
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
`

func TestDisjointLevelsRefuseTheLoad(t *testing.T) {
	_, err := loadMFA(disjointPolicy)
	if !errors.Is(err, ErrMFADisjoint) || !strings.Contains(err.Error(), "role netadmin") ||
		!strings.Contains(err.Error(), "scope core") || !strings.Contains(err.Error(), "core-sw01") {
		t.Fatalf("load = %v, want ErrMFADisjoint naming both levels and the device", err)
	}
	// loadMFA is `policy test`'s reading: a load error. The bundle itself,
	// loaded as a start or an inventory reload loads it, quarantines core-sw01
	// alone with the same cause, and edge-sw01 resolves (ruling 11; pre-flight
	// I4).
	p := mfaBundle(t, disjointPolicy)
	if q := p.MFADisjoint(); len(q) != 1 || q[0].Device != "core-sw01" || !strings.Contains(q[0].Entries[0].Cause, "scope core") {
		t.Fatalf("MFADisjoint = %+v, want core-sw01 alone", q)
	}
	// Resolve(principal, d, now): resolve.go:102 (re-review R7).
	if _, err := p.Resolve("user:alice@example.com", device(t, p, "edge-sw01"), time.Now()); err != nil {
		t.Fatalf("edge-sw01 under a disjoint core-sw01: %v", err)
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
		{`defaults: {per_login_mfa: {accept: [touch]}}`, "hardware_key_touch or idp_mfa"},
		// A boolean fails yaml.v3's strict decode before the vocabulary
		// check reads it (pre-flight minor 12): refused all the same.
		{`defaults: {per_login_mfa: {accept: [true]}}`, "true"},
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
	// A scope pinned by name alone needs neither on_missing nor security_log:
	// name is always present and no attribute edit lifts it (ruling 11;
	// pre-flight I2).
	if _, err := loadMFA("scopes:\n  - name: core-sw01\n    match: {name: core-sw01}\n    per_login_mfa: {accept: [idp_mfa]}"); err != nil {
		t.Errorf("a name-pinned scope: %v", err)
	}
	// name with another key is an attribute scope: both still required.
	if _, err := loadMFA("scopes:\n  - name: c\n    match: {name: core-sw01, tier: core}\n    per_login_mfa: {accept: [idp_mfa]}"); err == nil {
		t.Error("a scope matching name and tier loaded without on_missing")
	}
}

// Two subjects of one principal compose only at mint: a disjoint pair there
// is composition_refused, never a broker fault (ruling 11; pre-flight I3).
func TestADisjointCompositionIsRefusedNotAFault(t *testing.T) {
	p := mfaPolicy(t, `
roles:
  - name: netadmin
    permit: ["**"]
    per_login_mfa: {accept: [idp_mfa]}
  - name: core-ops
    permit: ["show **"]
    per_login_mfa: {accept: [hardware_key_touch]}
scopes:
  - name: core
    match: {tier: core}
    on_missing: include
grants:
  - {subject: alice-group, scope: all_devices, roles: [netadmin]}
  - {subject: alice-core, scope: core, roles: [core-ops]}
`) // grants and subjects in the policy file's own form; alice-group and
	// alice-core are two subjects one principal matches. Each alone loads;
	// only their composition on core-sw01 is disjoint.
	_, err := p.ResolveSubjects([]string{"alice-group", "alice-core"}, "", device(t, p, "core-sw01"), time.Now())
	if !errors.Is(err, ErrCompositionRefused) || !strings.Contains(err.Error(), "per_login_mfa") {
		t.Fatalf("ResolveSubjects = %v, want ErrCompositionRefused naming per_login_mfa", err)
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

func TestPolicyTestAssertsTheRequirement(t *testing.T) {
	p := mfaPolicy(t, strictestPolicy)
	pass := runSessionTest(t, p, `{subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}`)
	if !pass.OK {
		t.Fatalf("the matching assertion failed: %s", pass.Message)
	}
	fail := runSessionTest(t, p, `{subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 15m}}`)
	if fail.OK || !strings.Contains(fail.Message, "15m") || !strings.Contains(fail.Message, "5m") {
		t.Fatalf("a wrong reuse_for: %+v, want a failure naming both", fail)
	}
	none := runSessionTest(t, p, `{subject: alice, device: core-sw01, per_login_mfa: none}`)
	if none.OK {
		t.Fatal("per_login_mfa: none passed on a device with a requirement")
	}
}

func TestPolicyDiffGatesAWeakening(t *testing.T) {
	weaker := strings.Replace(strictestPolicy, "accept: [hardware_key_touch], reuse_for: 5m",
		"accept: [hardware_key_touch, idp_mfa], reuse_for: 5m", 1)
	out, code := diffRun(t, strictestPolicy, weaker)
	if !strings.Contains(out, "per_login_mfa:") || !strings.Contains(out, "core-sw01") ||
		!strings.Contains(out, "per_login_mfa_weakened:") || code == 0 {
		t.Fatalf("an unacknowledged weakening must print and fail (exit %d):\n%s", code, out)
	}
	// A session test asserting the new requirement acknowledges it, as for a privilege raise.
	acked := weaker + `
tests:
  - {subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 5m}}
`
	if out, code := diffRun(t, strictestPolicy, acked); code != 0 {
		t.Fatalf("an acknowledged weakening failed (exit %d):\n%s", code, out)
	}
	// A test asserting the old requirement does not acknowledge the new one.
	stale := weaker + `
tests:
  - {subject: alice, device: core-sw01, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}}
`
	if _, code := diffRun(t, strictestPolicy, stale); code == 0 {
		t.Fatal("a test asserting the old requirement acknowledged the weakening")
	}
	// A longer reuse_for is a weakening too.
	longer := strings.Replace(strictestPolicy, "reuse_for: 5m", "reuse_for: 30m", 1)
	if _, code := diffRun(t, strictestPolicy, longer); code == 0 {
		t.Fatal("a longer reuse_for passed the gate")
	}
	tighter := strings.Replace(strictestPolicy, "reuse_for: 5m", "reuse_for: 1m", 1)
	if out, code := diffRun(t, strictestPolicy, tighter); !strings.Contains(out, "per_login_mfa:") || code != 0 {
		t.Fatalf("a tightening must print and pass (exit %d):\n%s", code, out)
	}
}
```

  (`runSessionTest` and `diffRun` are thin helpers over the package's existing test-runner and
  diff entry points; `diffRun` returns the printed diff and the exit code `cmd/port49`'s `policy
  diff` would give, so Task 9's `cmd/port49/policy_test.go` also runs one weakening through the
  command.)

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ -run 'StrictestLevel|OneDeviceIsAScope|DisjointLevels|DisjointComposition|MachinesAreExempt|PerLoginMFASchema|ExplainPrintsTheEffective|PolicyTestAssertsTheRequirement|PolicyDiffGatesAWeakening' -count=1`
Expected: FAIL (undefined).

  Also `internal/port49d/reload_test.go`, `TestAnMFADisjointInventoryEditQuarantinesAndAPolicyEditIsRefused`
  (pre-flight I4): with `disjointPolicy`'s levels and core-sw01 at `tier: edge`, an inventory
  reload moving it to `tier: core` is applied (the new inventory in force, a second new device in
  the same edit served) and core-sw01 is quarantined with the per_login_mfa cause; a policy-file
  edit that makes edge-sw01 disjoint is refused, the bundle in force unchanged,
  `port49_policy_file_refused` at 1. Then, with core-sw01 still quarantined over MFA, a policy
  edit that revokes an unrelated grant (and introduces no MFA entry) is applied,
  `port49_policy_file_refused` at 0, core-sw01 still quarantined: an entry already in force
  freezes no edit (re-review R5). And a policy and inventory changed together (`loadBoth`), the
  inventory moving core-sw01 to `tier: core` and the policy revoking that grant: applied, judged
  against the in-force policy over the new inventory, which has the core-sw01 entry already.
  `cmd/port49`'s `policy test` on `disjointPolicy` exits 1 naming both levels and the device;
  `policy diff --old strictestPolicy --new disjointPolicy` exits 1 on the core-sw01 entry, and a
  diff whose both sides hold it exits 0 for it.

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
    `checkDeviceAt` reports an `ErrMFADisjoint` (or the machine refusal) as its cause, with the
    subject and device, and `checkDevice` marks the entry `MFA: true`; so it is checked at the
    load's present and at each later expiry, as every composition is.
  - `member.go`: `resolveAll` with `check` wraps an `ErrMFADisjoint` from `resolved` as
    `fmt.Errorf("%w: subjects %s on %s: %v", ErrCompositionRefused, …, err)`, so `mintOne`'s
    existing `ErrCompositionRefused` arm records `deny composition_refused` (pre-flight I3).
  - Load error versus quarantine (ruling 11; pre-flight I4; re-review R5): `policy.Load` keeps MFA
    entries in the quarantine like any other, and `MFADisjoint()` lists them. `policy test`
    refuses a policy with any, as it refuses every quarantine today, naming both levels and the
    device. `policy diff` refuses `NewMFADisjoint(before, after)`, through its existing "a device
    the new version quarantines for a new cause" rule. `port49d/reload.go`: `load` refuses a
    bundle when `NewMFADisjoint(old, pol)` is non-empty (`old` is over the same inventory there);
    `loadBoth` when `NewMFADisjoint(base, pol)` is, `base` being the in-force policy over the new
    inventory that it already builds for `CheckAdmissionOver` (a `base` that does not parse is
    nil, so every entry counts). Each refusal is the existing refusal line,
    `port49_policy_file_refused`, the bundle in force kept. An entry already in force refuses
    nothing. A start, an inventory reload and an expiry keep the quarantine, said on the existing
    quarantine line and counted in `port49_devices_quarantined`. A scope with a match key other than `name` and
    `per_login_mfa` must have `onMissingDeclared` and `SecurityLog`; one whose only key is `name`
    needs neither (pre-flight I2).
  - `lint.go`: a warning for `on_missing: exclude` on a `per_login_mfa` scope ("a sync that drops
    <key> lifts this requirement; security_log records it"; pre-flight minor 14), and one for
    `applies_to_machines: true` ("a workload proves only with a pkcs11 key and touch key on one
    token"; ruling 21).
  - `explain.go`: after the `session` line, ruling 17's `per_login_mfa` line ("applies to humans",
    or "applies to machines too" when a level sets it; for a machine principal "applies to this
    machine: provable only with a pkcs11 key and touch key on one token").
  - `tests.go`: the assertion compares `Accept` as a set and `ReuseFor`; `none` passes only when
    `!Required()`.
  - `diff.go`: per subject and device, the requirement before and after; printed when it differs.
    A new `Diff.MFA []MFAChange` (`Subject`, `Devices`, `At`, `Old`, `New MFARequirement`,
    `Weakened, Acknowledged bool`), built like `LevelChange`: `Weakened` when after's `Accept` is
    not a subset of before's, after's `ReuseFor` is longer, a level is gone (after has fewer
    levels), `applies_to_machines` went off, or after is not `Required()` and before was.
    `Acknowledged` is a passing session test in the new version, at `At`, on one of `Devices`,
    asserting the new `per_login_mfa:`. `func (d Diff) UnacknowledgedMFA() int` counts
    `Weakened && !Acknowledged`, as `UnacknowledgedLevels` counts `Raise && !Acknowledged`;
    `cmd/port49/policy.go` adds it to the summary line ("%d unacknowledged per_login_mfa
    weakenings") and to the `return 1` condition beside `d.UnacknowledgedLevels() > 0`. A
    weakening is printed `per_login_mfa_weakened:` (not `warning:`). A tightening is printed and
    never fails. (Controller's Task 1 review ruling 2026-10-12, decision 45 ruling 24, replacing
    pre-flight minor 15's warning.)
  - `review.go`: `ReviewRow` gains `PerLoginMFA []MFALevel`, the levels its scope and roles carry
    (and `defaults`), so the access review shows where requirements are written; the effective
    requirement is per device, and explain is where it is read (the roadmap's "policy tooling
    prints the effective requirement" is met by explain, `policy test` and `policy diff`).

- [ ] **Step 4: Run**

Run: `go test ./internal/policy/ ./internal/port49d/ ./cmd/port49/ -count=1`, then `make test && make vet`.
Expected: PASS. Mutation checks, each restored: make `mfaFor` take the union (see
`TestTheStrictestLevelWins` and `TestDisjointLevelsRefuseTheLoad` fail); drop the machine filter
(see `TestMachinesAreExemptUnlessALevelSaysSo` fail); drop `resolveAll`'s wrap (see
`TestADisjointCompositionIsRefusedNotAFault` fail); make the reloader refuse an inventory edit with
an MFA entry (see the reload test fail at "applied"); make `load` refuse on `MFADisjoint()` rather
than `NewMFADisjoint` (see the reload test fail at the unrelated grant revocation).

- [ ] **Step 5: Commit**

```bash
git add internal/policy internal/port49d cmd/port49
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

// Anchors is attestation_roots_file read: its self-signed certificates are
// Roots and the rest Intermediates, so a hierarchy with an intermediate
// under a newer Yubico root verifies (pre-flight I14).
type Anchors struct{ Roots, Intermediates *x509.CertPool }

// ParseAnchors reads every PEM certificate in b; none is an error.
func ParseAnchors(b []byte) (Anchors, error)

// Verify checks slot against device and device against the anchors at now,
// and reads slot's policy. device's signature over slot is checked directly:
// some f9 certificates carry no basic constraints, which x509.Verify
// refuses for an intermediate (go-piv v2.6.0 piv/key.go:241-247).
func Verify(a Anchors, device, slot *x509.Certificate, now time.Time) (Attestation, error)
```

- [ ] **Step 1: Write the failing test** `internal/pivattest/pivattest_test.go`, with a test root
  (`testpki.NewCA`), a device certificate it signs with no basic constraints (as some f9s have), and
  slot certificates the device signs carrying the extensions:

```go
func TestVerify(t *testing.T) {
	root, device, deviceKey := yubicoLike(t) // device: v3, BasicConstraintsValid false
	roots := Anchors{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	roots.Roots.AddCert(root.Cert)
	now := time.Now()
	slot := slotCert(t, device, deviceKey, slotOpts{serial: 12345678, pin: 0x02, touch: TouchAlways})
	a, err := Verify(roots, device, slot, now)
	if err != nil || a.Serial != 12345678 || a.TouchPolicy != TouchAlways || a.PINPolicy != 0x02 {
		t.Fatalf("Verify = %+v, %v", a, err)
	}
	// A three-level hierarchy (root → intermediate → f9), the anchors file
	// holding both: verifies; holding the root alone: refused.
	both, device3, deviceKey3 := yubicoLikeWithIntermediate(t) // PEM of root and intermediate
	anchors, err := ParseAnchors(both)
	if err != nil {
		t.Fatal(err)
	}
	slot3 := slotCert(t, device3, deviceKey3, slotOpts{serial: 7, pin: 2, touch: TouchAlways})
	if _, err := Verify(anchors, device3, slot3, now); err != nil {
		t.Fatalf("three levels with the intermediate listed: %v", err)
	}
	if _, err := Verify(Anchors{Roots: anchors.Roots}, device3, slot3, now); err == nil {
		t.Fatal("three levels verified with the intermediate missing")
	}
	for _, bad := range []struct {
		name  string
		slot  *x509.Certificate
		roots Anchors
	}{
		{"another root", slot, Anchors{Roots: x509.NewCertPool()}},
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

- [ ] **Step 3: Implement.** `ParseAnchors`: each PEM `CERTIFICATE`, self-signed (subject equals
  issuer and `CheckSignatureFrom(itself)` holds) into `Roots`, else into `Intermediates`; no root is
  an error. `device.Verify(x509.VerifyOptions{Roots: a.Roots, Intermediates: a.Intermediates,
  CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})`; then
  `device.CheckSignature(slot.SignatureAlgorithm, slot.RawTBSCertificate, slot.Signature)`; then
  `slot`'s validity at `now`; then the extensions: serial (1.3.6.1.4.1.41482.3.7, an ASN.1
  INTEGER, 0 to 2³²−1), policy (…3.8, exactly two bytes, each a known value), both required. The
  slot's own key is `slot.PublicKey`.

- [ ] **Step 4: Run**

Run: `go test ./internal/pivattest/ -count=1`
Expected: PASS. Mutation checks, each restored: skip the `CheckSignature` step and see "a slot
another device signed" fail; drop `Intermediates` from the options and see the three-level case
fail.

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
  fields in the same order), `internal/store/crypt/crypt.go`, `internal/store/guard/guard.go`
  (`PutMFAProof` and `GetMFAProof` rows in the pool table, `Token`: the table has no default and
  `TestEveryMethodIsRoutedToItsPool` fails without them), `internal/store/storetest/oidc.go`
  (conformance), and every test fake that implements `store.Store` outright, found by
  `grep -rn "var _ store.Store" --include='*_test.go'` (at least
  `internal/daemon/authen/authen_test.go`'s `noStore`, which panics on every call; pre-flight
  minor 6)
- Modify: `internal/token/minter.go` (`Subject.Credential` carries the MFA fields through;
  `Request.PerLoginMFA *decision.PerLoginMFA`, copied into the permit record it writes)
- Modify: `internal/broker/api/api.go` (types below), `internal/broker/broker.go` (`Broker.PerLoginMFA`,
  route, `tokens`, `mintOne`, `config`)
- Create: `internal/broker/mfa.go`, `internal/broker/mfa_test.go`
- Modify: `internal/config/identity.go` (`broker.identity.per_login_mfa`), `internal/oidc/config.go`
  (`PerLoginMFA` config), `internal/port49d/brokerd.go` and `internal/port49d/main.go` (wire it)
- Modify: `internal/broker/broker.go`'s `authenticate` (~624–633, the "one path for people"
  refusal: decision 43 ruling 13's exception for `/v1/mfa`; pre-flight minor 9)

**Interfaces:**
- Consumes: Task 9's `Resolution.PerLoginMFA`, `MFARequirement.Accepts`; Task 10's
  `pivattest.Verify`; `oidc.Set`'s human verification (as `issue.go` calls it).
- Produces (`internal/broker/api`):

```go
// (AgentSessionHeader is Task 5's.)

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
	Key    string // hex SHA-256 of principal, fingerprint and agent_sha256, then "/" and the method
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

  (`credRec`'s mirror of `MFAAt` is `time.Time json:"mfa_at,omitzero"`: `omitempty` never omits a
  zero `time.Time`; pre-flight minor 16.)

- Produces (`internal/broker`):

```go
// MFAVerifiers is broker.identity.per_login_mfa resolved: nil Anchors means
// hardware_key_touch is unavailable here; idp_mfa is available while a
// human OIDC verifier is configured.
type MFAVerifiers struct {
	Anchors   *pivattest.Anchors
	AMR       []string // default ["mfa"]
	ACRValues string
}

// in Broker:
//	PerLoginMFA *MFAVerifiers

// mfaCovers says whether a proof covers req for this caller now: the
// challenge's own proof named by the mint (once, whatever reuse_for), else
// a kept proof whose method req accepts, made within req.ReuseFor.
// agentSHA256 is the hex SHA-256 of the caller's agent session, "" for none.
func (b *Broker) mfaCovers(ctx context.Context, c caller, agentSHA256 string, req policy.MFARequirement,
	proved *provedChallenge, now time.Time) (method string, at time.Time, reused bool, err error)

// challengeKey and provedKey are the store keys of a challenge and its
// proved record, each over its binding, so a caller computing another's
// key finds nothing and spends nothing (re-review R1):
// "plm-challenge/" + hex SHA-256(ch ‖ 0 ‖ principal) and
// "plm-proved/" + hex SHA-256(ch ‖ 0 ‖ principal ‖ 0 ‖ fingerprint ‖ 0 ‖ agentSHA256).
func challengeKey(ch []byte, principal string) string
func provedKey(ch []byte, principal, fingerprint, agentSHA256 string) string

// proofKey is the reuse key, over agent_sha256, never the raw session
// (re-review R2).
func proofKey(principal, fingerprint, agentSHA256 string, m policy.MFAMethod) string
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

func TestATouchProofIsBoundToItsConnection(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
	// Signed over the exporter value of alice's other connection (a second
	// held connection of the same agent), posted on this one.
	other := f.dial(t, f.alice)
	sig := f.touchSign(t, ch, other.exporter(t))
	if code := f.postTouch(t, f.alice.conn, ch, sig, f.attestations); code != 401 {
		t.Fatalf("a signature over another connection's exporter value: %d, want 401", code)
	}
	f.assertRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
	// The same signature posted on the connection it was made for verifies:
	// the refusal was the binding, not the signature.
	ch2 := f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
	if code := f.postTouch(t, other, ch2, f.touchSign(t, ch2, other.exporter(t)), f.attestations); code != 200 {
		t.Fatalf("the control: %d, want 200", code)
	}
}

func TestAChallengeIsUsedOnce(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
	// bob proves alice's challenge on his own connection: refused, and the
	// challenge is not spent by it.
	if code := f.proveTouch(t, f.bob, ch); code != 401 {
		t.Fatalf("bob proving alice's challenge: %d, want 401", code)
	}
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("alice after bob's attempt: %d, want 200 (bob must not spend it)", code)
	}
	if code := f.proveTouch(t, f.alice, ch); code != 401 {
		t.Fatalf("the same challenge proved twice: %d, want 401", code)
	}
	// A proved challenge named by another caller's mint covers nothing:
	// bob's mint, and alice's under another certificate (pre-flight minor 11).
	if it := f.mint(t, f.bob, "core-sw01", ch).Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("bob's mint naming alice's proved challenge = %+v", it)
	}
	if it := f.mint(t, f.aliceOtherCert, "core-sw01", ch).Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("alice's mint under another certificate naming the challenge = %+v", it)
	}
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
		t.Fatalf("alice's own mint naming it = %+v (the other callers must not have spent it)", it)
	}
}

// A store that fails while a requirement is judged is store_unavailable for
// the item, never a challenge that was not stored (pre-flight minor 1).
func TestAStoreErrorIsNotARefusedProof(t *testing.T) {
	f := newMFAFixture(t)
	f.store.failOn("PutOnce", "GetMFAProof")
	it := f.mint(t, f.alice, "core-sw01", "").Results[0]
	if it.Verdict != "deny" || it.Reason != "store_unavailable" || it.PerLoginMFA != nil {
		t.Fatalf("mint with the store failing = %+v", it)
	}
	f.assertNoRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
}

// A retried request whose answer was lost replays the token it minted, even
// though the proof that covered it is spent (pre-flight minor 2).
func TestAReplayedMintUnderReuseZeroIsReplayed(t *testing.T) {
	f := newMFAFixture(t, withReuseFor(0))
	ch := f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge
	f.proveTouch(t, f.alice, ch)
	first := f.mintWithKey(t, f.alice, "core-sw01", ch, "idem-1")
	again := f.mintWithKey(t, f.alice, "core-sw01", ch, "idem-1")
	if first.Results[0].Verdict != "permit" || !reflect.DeepEqual(first, again) {
		t.Fatalf("replay = %+v, want the first answer %+v", again, first)
	}
}

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
	// The proof was posted with no Port49-Agent-Session (the CLI's fresh
	// connection), yet it is kept for this agent: a login within reuse_for
	// is covered without a second sign-in (re-review R2).
	f.clock.Advance(5 * time.Minute)
	if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint within reuse_for after an idp proof = %+v", it)
	}
	f.assertMintRecordMFA(t, "idp_mfa", true)
	f.clock.Advance(11 * time.Minute) // past reuse_for: each mint below is asked again
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

func TestUnavailableMethodsAreSaidPerDevice(t *testing.T) {
	f := newMFAFixture(t, withoutAttestationRoots(), withTouchOnlyCore())
	resp := f.mintMany(t, f.alice, "core-sw01", "edge-sw01")
	if it := resp.find("core-sw01"); it.Verdict != "deny" || it.Reason != "per_login_mfa_unavailable" {
		t.Fatalf("core-sw01 = %+v", it)
	}
	if it := resp.find("edge-sw01"); it.Verdict != "permit" {
		t.Fatalf("edge-sw01 = %+v, want minted as before", it)
	}
	f.assertRecord(t, "mint", "deny", "per_login_mfa_unavailable")
}

func TestTheCredentialCarriesTheProofIntoTheToken(t *testing.T) { /* the minted token's Credential.MFAMethod and MFAAt are the proof's */ }

func TestMachinesAreNotAsked(t *testing.T) {
	f := newMFAFixture(t) // core's level has no applies_to_machines
	if it := f.mint(t, f.oxidized, "core-sw01", "").Results[0]; it.Verdict != "permit" || it.PerLoginMFA != nil {
		t.Fatalf("a machine under a humans-only requirement = %+v", it)
	}
	f = newMFAFixture(t, withAppliesToMachines())
	if it := f.mint(t, f.oxidized, "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" ||
		!slices.Equal(it.PerLoginMFA.Methods, []string{"hardware_key_touch"}) {
		t.Fatalf("a machine under applies_to_machines = %+v, want asked for a touch alone", it)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'MintUnderARequirement|TouchProof|ReuseForZero|TouchFromAnother|TouchSlotNotAlways|BoundToItsConnection|ChallengeIsUsedOnce|StoreErrorIsNot|ReplayedMint|IdPProof|UnavailableMethods|CredentialCarriesTheProof|MachinesAreNotAsked' -count=1` and `go test ./internal/store/... -count=1`
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
    time.Time json:"mfa_at,omitzero"` in the same position as `store.Credential`'s new fields
    (last).
  - `internal/config/identity.go`: `identityYAML.PerLoginMFA *perLoginMFAYAML
    yaml:"per_login_mfa"` with `HardwareKeyTouch *struct{ AttestationRootsFile string
    yaml:"attestation_roots_file" } yaml:"hardware_key_touch"` and `IdPMFA *struct{ AMR []string
    yaml:"amr"; ACRValues string yaml:"acr_values" } yaml:"idp_mfa"`; `oidc.Config.PerLoginMFA`.
    port49d and port49-broker read the roots file at start with `pivattest.ParseAnchors`:
    unreadable, no PEM certificate or no self-signed root → the start goes on,
    `hardware_key_touch` unavailable, one line naming the file.
  - `mfa.go`:
    - `agentKey(r *http.Request) string`: the hex SHA-256 of the header's 32 bytes
      (`agent_sha256`), or `""` (a caller without one — a workload, a 7h bearer — keeps no
      reusable proof: each request proves). The raw session is never kept or compared.
    - `proofKey(principal, fingerprint, agentSHA256 string, m policy.MFAMethod) string`,
      `challengeKey`, `provedKey` as in Interfaces (re-review R1, R2).
    - `issueChallenge(ctx, c caller, agentSHA256 string) (api challenge bytes, expires, error)`:
      `PutOnce(challengeKey(ch, c.principal), json{principal, fingerprint, agent_sha256}, 5m)`,
      `agent_sha256` the hex SHA-256 of the agent session, never the value (`PutOnce` is not
      sealed; pre-flight minor 16).
    - `POST /v1/mfa` → `b.mfaProve`: decodes `api.MFAProofRequest` (strict, 64 KiB); finds the
      caller's principal first (for `hardware_key_touch` the held connection's; for `idp_mfa` the
      principal the verified ID token maps to), then `TakeOnce(challengeKey(ch, principal))`: a
      challenge issued to another principal is not found, so bob's post never spends alice's
      challenge (re-review R1), and is refused 401 as an unknown challenge. For
      `hardware_key_touch` the caller must be the held connection's and match the record's
      fingerprint and `agent_sha256`; the exporter value from `r.TLS`
      (`ExportKeyingMaterial(api.MFAExporterLabel, nil, 32)`); `pivattest.Verify` on the touch
      slot and on the session slot, both against the same device certificate (`bytes.Equal` of
      their `Device.Raw`), touch policy `TouchAlways`, session slot key equal to
      `r.TLS.PeerCertificates[0].PublicKey`, the signature by the touch slot key
      (`api.RefreshAlgorithm` for its type) over `api.MFAMessage`. For `idp_mfa`: the bearer
      verified as `issue.go` verifies one (`b.Identity`, humans only), its principal the
      challenge's, `nonce` equal to `api.MFANonce(ch)`, `auth_time` fresh (5 minutes plus
      `clock_skew`, against `iat` and now), `amr` holding one of `MFAVerifiers.AMR`, the token's
      SHA-256 `PutOnce` for `max_token_age` (a second use 401). On success, for both methods the
      binding is the challenge record's (principal, fingerprint, `agent_sha256`), never the
      request's (an `idp_mfa` post carries no client certificate and no agent session; re-review
      R2): `PutOnce(provedKey(ch, principal, fingerprint, agent_sha256), json{method, at}, 5m)`,
      `PutMFAProof(MFAProof{Key: proofKey(principal, fingerprint, agent_sha256, method), Method,
      At: now}, 8h)` skipped only when the record's `agent_sha256` is empty, the
      record `permit per_login_mfa_proved`, 200 `MFAProofResponse`. Any refusal: 401
      `per_login_mfa_refused` with the cause in `detail`, the record `deny per_login_mfa_refused`
      carrying `challenge_sha256`; a store error 503 `store_unavailable`, recorded.
    - `mfaCovers` as in Interfaces. On the named path the caller's own principal, fingerprint and
      `agent_sha256` compute `provedKey`, so bob's mint naming alice's proved challenge, or
      alice's with another certificate, finds no record, is not covered, and spends nothing
      (pre-flight minor 11; re-review R1); alice's own mint then finds it. The named challenge's
      proved record is `TakeOnce`d once per request in `tokens`,
      **after** `ReserveIdempotency` succeeds (a store error or an in-progress answer before that
      leaves the proof for the retry), and held as `*provedChallenge` for every item. A store
      error from `mfaCovers` or `issueChallenge` is `deny store_unavailable` for that item, never
      "not covered" (pre-flight minor 1). A reservation that returns a completed response is
      replayed before any requirement is read (pre-flight minor 2).
  - `broker.go`: `tokens` reads `api.AgentSessionHeader` and `req.PerLoginMFAChallenge`; issues at
    most one challenge per request, lazily, for the first item that needs one. `mintOne`, after the
    session-ceiling check and before `engine.Encode`: when `res.PerLoginMFA.Required()`:
    available methods = `Accept` ∩ what `b.PerLoginMFA` verifies (touch needs `Anchors`, idp needs a
    human OIDC verifier); none → `deny per_login_mfa_unavailable` (record carries the
    requirement); `mfaCovers` → covered: the token's `Credential.MFAMethod`/`MFAAt` set, the
    minter's permit record gets `PerLoginMFA{Method, ProvedAt, Reused, Accept, ReuseForSeconds,
    Levels}` (through `token.Request.PerLoginMFA`, a new field the minter copies into its record);
    not covered → `deny per_login_mfa_required` with `item.PerLoginMFA` filled and its detail
    ruling 17's sentence. `config` adds `PerLoginMFA` when either method is available.
  - `broker.go`'s `authenticate`: the "one path for people" refusal of a person's ID token lets
    `/v1/mfa` through (its handler verifies the token as a proof, never as the caller's credential).

- [ ] **Step 4: Run**

Run: `go test ./internal/broker/... ./internal/store/... ./internal/decision/ ./internal/config/ ./internal/port49d/ -count=1`, then `make test && make vet`.
Expected: PASS. Mutation checks, each restored: drop the same-device check (see
`TestATouchFromAnotherTokenIsRefused` fail); drop the `TakeOnce` of the challenge (see
`TestAChallengeIsUsedOnce` fail); skip the exporter value (see `TestATouchProofIsBoundToItsConnection`
fail); make `mfaCovers` ignore `ReuseFor` (see `TestATouchProofCoversTheRetriedMintAndThenReuses`
fail); key the challenge by the challenge alone, without the principal (see
`TestAChallengeIsUsedOnce` fail at "alice after bob's attempt"); key the proved record without the
caller's binding (see it fail at bob's mint, or at alice's own mint after it); key the reuse proof
by the request's agent session instead of the challenge record's (see
`TestAnIdPProofCoversTheMint` fail at "within reuse_for"); read the requirement before replaying a completed reservation (see
`TestAReplayedMintUnderReuseZeroIsReplayed` fail); treat a store error in `mfaCovers` as "not
covered" (see `TestAStoreErrorIsNotARefusedProof` fail).

- [ ] **Step 5: Commit**

```bash
git add internal/decision internal/daemon internal/store internal/token internal/broker internal/config internal/oidc internal/port49d
git commit -m "feat: the broker asks for and verifies a per-login proof

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Held sessions and the session refresh under a requirement

**Files:**
- Modify: `internal/broker/sessionrefresh.go` (`RefreshSession` takes the agent session and the
  named challenge; `extend` checks the requirement; `refreshChallenge`'s pacing exemption),
  `internal/broker/oidcrefresh.go` (passes `""`, `nil`), `internal/broker/api/refresh.go`
  (`RefreshResponse.PerLoginMFA`, `RefreshRequest.PerLoginMFAChallenge`,
  `RefreshChallengeRequest`)
- Modify, the test callers of `RefreshSession` (pre-flight minor 7; `grep -rl "RefreshSession("
  internal`): `internal/broker/broker_test.go`, `identity_api_test.go`, `member_test.go`,
  `reindex_test.go`, `workload_directory_test.go`, each passing `"", nil`
- Test: `internal/broker/mfa_refresh_test.go`

**Interfaces:**
- Consumes: Task 11's `mfaCovers`, `issueChallenge`.
- Produces: `func (b *Broker) RefreshSession(ctx context.Context, m policy.Member, answer
  *directory.Answer, cred store.Credential, at time.Time, via *decision.OIDC, agentSHA256 string,
  proved *provedChallenge) (SessionRefreshReport, error)` (`agentSHA256` is Task 11's
  `agentKey(r)`, the hex SHA-256 of the agent session) (the held connection's state gains
  `proved *provedChallenge`); outcome `per_login_mfa_required` beside
  `extended`, `revoked`, `past_grace`, `not_judged`; `SessionRefreshReport.Challenge` set when any
  context needed a proof.

```go
// RefreshChallengeRequest is POST /v1/refresh/challenge's optional body. A
// challenge proved by this caller exempts this one request from the
// connection's refresh pacing (decision 45 ruling 16): the request takes the
// proved record for the refresh that follows, so it exempts once.
type RefreshChallengeRequest struct {
	PerLoginMFAChallenge string `json:"per_login_mfa_challenge,omitempty"`
}

// in RefreshRequest:
//	PerLoginMFAChallenge string `json:"per_login_mfa_challenge,omitempty"`
```

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
	// One touch, and the refresh right after it, on the same held connection
	// and within the 10s pacing (no clock advance), names the challenge and
	// extends it (pre-flight I5).
	ch := out.PerLoginMFA.Challenge
	f.proveTouch(t, f.alice, ch)
	if s := f.refreshNaming(t, f.alice, ch).find("core-sw01"); s.Outcome != "extended" {
		t.Fatalf("refresh after a proof = %+v", s)
	}
	// The exemption is spent with the proof: a third refresh at once is paced.
	if code := f.refreshChallengeNaming(t, f.alice, ch); code != http.StatusTooManyRequests {
		t.Fatalf("a second exemption from the same proof: %d, want 429", code)
	}
	// Another caller naming alice's proved challenge finds nothing and spends
	// nothing: alice's exemption survives bob's request (re-review R1).
	f.clock.Advance(16 * time.Minute) // past the pacing and reuse_for: asked again
	ch2 := f.refresh(t, f.alice).PerLoginMFA.Challenge
	f.proveTouch(t, f.alice, ch2)
	_ = f.refreshChallengeNaming(t, f.bob, ch2)
	if s := f.refreshNaming(t, f.alice, ch2).find("core-sw01"); s.Outcome != "extended" {
		t.Fatalf("alice's refresh after bob named her challenge = %+v", s)
	}
}

func TestRefreshWithinReuseNeedsNoNewProof(t *testing.T) {
	f := newMFAFixture(t) // reuse_for 15m on core
	f.loadPolicy(t, policyWithoutRequirement)
	f.loginOnDevice(t, f.alice, "core-sw01")
	f.loadPolicy(t, policyWithRequirementOnCore)
	f.proveTouch(t, f.alice, f.mint(t, f.alice, "core-sw01", "").Results[0].PerLoginMFA.Challenge)
	f.clock.Advance(5 * time.Minute)
	out := f.refresh(t, f.alice)
	if s := out.find("core-sw01"); s.Outcome != "extended" || out.PerLoginMFA != nil {
		t.Fatalf("refresh within reuse_for = %+v", out)
	}
	// Another agent session of alice's is not covered by it.
	if s := f.refreshAs(t, f.alice, f.otherAgent).find("core-sw01"); s.Outcome != "per_login_mfa_required" {
		t.Fatalf("another agent's refresh = %+v", s)
	}
}
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
  `refreshChallenge` decodes the optional `RefreshChallengeRequest` (strict, 4 KiB, an empty body
  as today). When it names a challenge, it `TakeOnce`s `provedKey(ch, principal, fingerprint,
  agentKey(r))` computed from this caller, as `tokens` does: another caller's take misses with
  `ErrNotFound`, spends nothing, and is paced as any request (re-review R1). A record found is
  this caller's by its key; it is kept on the held
  connection beside the nonce (`h.proved`, expiring with it); a record taken this way skips the
  pacing check for this one request. `refresh` passes `h.proved` (or, with
  `RefreshRequest.PerLoginMFAChallenge` named and no `h.proved`, the record it takes itself) to
  `RefreshSession` and clears it, so one proof exempts once and a second request naming it is
  paced again (pre-flight I5). The store has no read-without-take for `PutOnce` records, and needs
  none. A store error is paced as today, never an exemption.

- [ ] **Step 4: Run**

Run: `go test ./internal/broker/ -count=1`, then `make test && make vet`.
Expected: PASS. Mutation checks, each restored: let `extend` extend without the check and see
`TestRefreshUnderARequirementNeedsAProof` fail at "the ceiling moved"; drop the pacing exemption
and see it fail at "refresh after a proof" (429); key the proved record by the challenge alone in
`refreshChallenge` and see it fail at "after bob named her challenge".

- [ ] **Step 5: Commit**

```bash
git add internal/broker
git commit -m "feat: a session refresh under a requirement needs a proof, and a reload revokes nothing

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: The clients — the agent proves a touch; `token`, `ssh` and `refresh` prompt; `idp_mfa`; workloads

**Files:**
- Modify: `internal/agent/agent.go` (`Mint` takes the challenge; `Refresh` takes one too;
  `MFARequiredError`; `ProveTouch`; socket `POST /mfa/touch`; `TokenRequest` and the socket's
  refresh body, which live here at ~1184; pre-flight minor 9), `internal/agent/socket.go`
  (`Client.ProveTouch`, `Client.Refresh`'s challenge)
- Modify, every caller of `Agent.Mint` and `Agent.Refresh` (~29 test call sites for `Mint`, Task
  6's `unplug_test.go` among them; `grep -rn "\.Mint(\|\.Refresh(ctx\|\.Refresh(context" internal
  cmd`), each passing `""` (pre-flight minor 7)
- Create: `cmd/port49/mfa.go`, `cmd/port49/mfa_test.go`
- Modify: `cmd/port49/main.go` (`tokenCmd`), `cmd/port49/ssh.go` (its mint at ~669),
  `cmd/port49/trust.go` (~179), `cmd/port49/refresh.go`
- Modify: `internal/workload/client.go` (`Config.TouchKey`, the item loop; `LoadCertificate`
  through `clientkey.LoadPair`, so `workload` imports `internal/clientkey`; re-review R3),
  `cmd/port49/workload.go` (`--touch-key`; `--key` a reference)
- Test: `internal/agent/mfa_touch_test.go` (`TestAConnectionChangedDuringTheTouchIsNotPosted`;
  re-review R6), `internal/workload/client_test.go`, and `internal/workload/client_hw_test.go`
  (`//go:build hwkey && hwkey_dlopen`, with a `TestMain` calling `hwtest.SoftHSMMain`)

**Interfaces:**
- Consumes: Task 11's API types, Task 5's `Config.TouchKey` and `clientkey.LoadPair`, plan 9b's `signIn`,
  `oidcclient.Discover`, `pickProvider`.
- Task 8's CRL check applies here: the `/v1/mfa` client (the IdP-MFA post and the touch post alike)
  builds its `tls.Config` with `VerifyConnection: sf.verifyBroker(...)`, as `fetchBrokerConfig` and
  `requestCertificate` do, and returns the `*agent.BrokerRefusedError` / `*brokercrl.RevokedError`
  unwrapped, never as "unreachable" and never retried (Task 8 fix: the agent's mint, call and
  refresh paths already do). A test connects, flips the check to refuse, and asks `ProveTouch`.
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

// Refresh names challenge ("" for none) on the refresh challenge request and
// on the refresh (decision 45 ruling 16).
func (a *Agent) Refresh(ctx context.Context, challenge string) (api.RefreshResponse, error)

// ProveTouch signs challenge with the touch key over the held connection's
// exporter value and posts it with the attestations to POST /v1/mfa. It
// holds the wire to read the exporter value and to post, never across the
// touch (ruling 14). Taking the wire back, it reads the exporter value again
// and posts nothing if it changed: ErrConnectionChanged (re-review R6).
func (a *Agent) ProveTouch(ctx context.Context, challenge string) error

// ErrConnectionChanged is a touch made over a connection that was replaced
// before the post: "the connection changed during the touch; run it again".
var ErrConnectionChanged = errors.New("agent: the connection changed during the touch; run it again")

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
    `extended`, with no clock advance between them and no `refresh_too_soon` (pre-flight I5).
  - `TestATouchKeyThatCannotProveIsNotTried` (pre-flight I6): with the agent's status saying
    `touch_key: false` and `touch_key_unusable: "your session key is in the TPM; …"`, a device
    accepting both methods goes straight to the sign-in after printing that reason, and the broker
    saw no `/v1/mfa` touch post (so no `per_login_mfa_refused`); a touch-only device exits 1 with
    the reason and "this device accepts only hardware_key_touch".
  - `TestRevokeIsNotHeldBehindATouch` (pre-flight minor 4): with the touch key's `Sign` blocking
    until the test releases it, `port49 revoke` in another goroutine completes before the release.
  - `internal/agent/mfa_touch_test.go`, `TestAConnectionChangedDuringTheTouchIsNotPosted`
    (re-review R6): with the touch key's `Sign` blocking, the test drops the held connection
    (`b.closeHeldConnections()`) and lets the agent redial, then releases the touch:
    `ProveTouch` returns `ErrConnectionChanged`, the broker saw no `/v1/mfa` post, no `deny
    per_login_mfa_refused` is recorded, and the challenge is unspent (a second `ProveTouch` on the
    new connection, touched at once, is 200). The CLI prints the error's text, exit 1.
  - `TestNothingSecretIsPrinted`: across the tests above, stderr and stdout hold no challenge, no
    signature, no ID token and no agent session (the test greps for each value).
  - `internal/workload/client_test.go`, `TestAWorkloadProvesWithItsTouchKey`: a page of two
    devices, one under `applies_to_machines: true`: the run mints the other at once, proves the
    touch, and retries only the asked-for item under a new `Idempotency-Key` (pre-flight minor 3:
    the same key with a changed body is a 409, and a retried whole page would mint the other device
    twice); `TestAWorkloadKeyMayBeAReference` (in `client_hw_test.go`, behind `hwkey &&
    hwkey_dlopen`, which `make test-hw` runs over `./internal/workload/...`): `LoadCertificate`
    with a `pkcs11:` key on SoftHSM2 takes its PIN from `pin-source` and refuses without one,
    naming `pin-source` (pre-flight I7).

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ ./internal/workload/ ./internal/agent/ -run 'DescribeMFA|ProvesATouch|FallsBackToTheSignIn|ProvesOnceAndRefreshes|TouchKeyThatCannotProve|RevokeIsNotHeld|NothingSecretIsPrinted|WorkloadProves|ConnectionChangedDuringTheTouch' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `Agent.Mint` puts the challenge in `api.MintRequest.PerLoginMFAChallenge`; an item with reason
    `per_login_mfa_required` returns `&MFARequiredError{*item.PerLoginMFA}`; the socket answers it
    `428` with the requirement as the body, and `Client.Token` rebuilds it. Every existing caller
    of `Mint` passes `""`. `Agent.Refresh(ctx, challenge)` sends a non-empty challenge as
    `RefreshChallengeRequest` on `/v1/refresh/challenge` and in `RefreshRequest`; the socket's
    refresh body gains `per_login_mfa_challenge`.
  - `ProveTouch`: refuses with "no touch_key is configured" when `TouchKey` is nil; reads the
    touch key's attestation chain (`pkcs11.Signer.Certificates()`: the slot attestation whose key
    is the touch key's, the device certificate that signs it, and the slot attestation whose key
    is the session key's; any missing → "your token does not show its attestation certificates";
    provisional on L60) once and keeps it; takes the wire, gets the connection's exporter value as
    `refreshOnce` does, and gives the wire back; signs `api.MFAMessage` (the touch, up to the
    token's timeout) holding no wire; takes the wire again, reads the exporter value again, and
    compares it with the one it signed over (`bytes.Equal`). Changed (a reconnect during the
    touch): it posts nothing and returns `ErrConnectionChanged`, so no `per_login_mfa_refused`
    fires and the challenge stays unspent (pre-flight minor 4; re-review R6). Unchanged: it posts
    `/v1/mfa` on the held connection. A 401 is returned with the broker's detail; `hwkey.ErrKeyAbsent` as Task
    6's `KeyAbsentError`.
  - `prove`: prints `describeMFA(req)`; if `hardware_key_touch` is in `req.Methods` and the agent's
    status says `touch_key: true`, prints "touch your key now" and calls `Client.ProveTouch`; when
    it says `touch_key_unusable`, prints that reason and never tries the touch (pre-flight I6); else if
    `idp_mfa` is in `req.Methods`: needs a terminal on stdin; fetches `/v1/config` (with the CRL
    check), picks the provider as `issueCertificate` does, runs `signIn` with
    `api.MFANonce(challenge)` and, when the config says so, `acr_values`; posts the ID token as
    `Authorization: Bearer` to `/v1/mfa` with `{challenge, method: "idp_mfa"}` over TLS to the
    broker CA (never through a proxy), and drops the token. Neither available: "this device needs a
    proof you cannot give here: <sentence>; …" naming what is missing (`touch_key`, a terminal).
  - `tokenCmd`, `ssh` and `trust`: on `*agent.MFARequiredError`, `prove`, then mint once more naming
    the challenge; a second `per_login_mfa_required` is printed and exits 1 (never a loop).
  - `refreshCmd`: a response with `PerLoginMFA` → `prove`, then one more refresh naming the
    challenge (`Client.Refresh(ctx, challenge)`; the broker exempts it from pacing once, Task 12);
    print both.
  - `workload.Client`: an item `per_login_mfa_required` with `Config.TouchKey` set proves through a
    `/v1/mfa` on its own connection (its own exporter value), stderr "touch the key for <device>",
    and retries only the items that asked for a proof, once, in a new request under a new
    `Idempotency-Key` naming the challenge (pre-flight minor 3); without a touch key, the item fails
    with the sentence and the run exits as for any refused item. `LoadCertificate(certFile,
    keyRef, …)` goes through `clientkey.LoadPair`; for a reference, the PIN comes from the URI's
    `pin-source` alone, and a key that needs one without it is refused naming `pin-source`
    (ruling 21; pre-flight I7). `cmd/port49/workload.go`'s `--key` help says a reference is taken.

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
- Modify: `internal/clientkey/open_dlopen.go` (`secure-enclave:` dispatch; `secureenclave`
  imports `hwkey`, so the dispatch lives in `clientkey`, re-review R3), `cmd/port49/issuedkey.go`
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
- [ ] **Step 2: Run it to see it fail** (`go test -tags hwkey_dlopen ./internal/hwkey/secureenclave/` on macOS).
- [ ] **Step 3: Implement** from Task 2's cells, in `secureenclave_darwin.go` (`//go:build darwin
  && hwkey_dlopen`, ruling 22); `secureenclave_other.go` (`//go:build !darwin || !hwkey_dlopen`)
  returns "the Secure Enclave is macOS's" off macOS and the build's refusal on a static build.
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
  the shared home (pre-flight I12): the lab user's `~/.port49/issued/` on an NFS export (or a
  directory both hosts mount) used from the SER8 and from a second host with its own TPM or
  swtpm: each `port49 login --oidc` keeps its own `.<machine>.{tpmkey,pem}`, the second host's
  first login signs in (no error), and a later login on each uses its own pair, neither
  overwritten; the control: a user outside `tss` (refused naming the group). Record the TPM's vendor and
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
  --touch-policy always 9c /tmp/9c.pub`; `ykman piv keys generate --pin-policy once 9e
  /tmp/9e.pub` (the user's one-time key for cell (g): port49 never generates on the token);
  Yubico's PIV attestation roots, every one Yubico publishes for current firmware (the original
  `https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem` and any newer root and
  intermediate Yubico lists), saved as the broker's `attestation_roots_file`. Record the firmware
  (`ykman info`) and `libykcs11`'s version.
- [ ] **Step 2: The cells** (the harness drives `bin/port49-client` from `make build-client`, the
  `hwkey_dlopen` build, against the compose broker and vEOS;
  Ryan types the PIN and touches when the harness says):
  - (a) `C_Initialize`/`C_Finalize` five times in one process with the token present (Task 3's
    `TestLibykcs11InitFinalizeUnderPurego` already ran it with no token, in CI), no crash, threads
    listed before and after (`/proc/self/task`);
  - (b) `port49 login --key "pkcs11:id=%01?module-path=…/libykcs11.so"`: the PIN asked once, the
    agent connects, refreshes; control: the same login with the lab's file key;
  - (c) the attestation objects: which certificate objects `Certificates()` returns, that the 9a
    and 9c attestations verify against the f9 certificate and the f9 against Yubico's roots through
    `pivattest.Verify`, the f9's chain depth (an intermediate or not, by firmware), and their touch
    policies (9a never, 9c always);
  - (d) `port49 token` on a device under `hardware_key_touch`: the prompt, Ryan touches, the token
    is taken by vEOS; again with no touch: the timeout and port49's words; control: the same device
    with no requirement;
  - (e) the unplug: `port49 token` with the YubiKey out (minted on the held connection),
    `port49 refresh` ("insert your key"), the agent still running; re-inserted, with nothing
    minted, the agent's `GET /status` says `locked` (ruling 8's re-probe), `port49 login` asks the
    PIN without failing to open the token first, the refresh works;
  - (e2) a `port49 login` and a `port49 token` in a second terminal while the agent holds the
    unlocked token: the agent's next refresh still signs with no PIN asked (the second process did
    not de-authenticate the agent's PIV login; pre-flight I15);
  - (f) one wrong PIN: the message, the tries the token reports (`ykman piv info` before and
    after: one fewer), never a second attempt; then the right PIN;
  - (g) `issued_key_store: pkcs11` with `issued_key: "pkcs11:id=%04?module-path=…"` (slot 9e,
    the key Step 1 made): the CSR signed by it, the certificate issued and kept as `.pem`, the
    token's objects the same before and after (`ykman piv info`), the agent connects; no
    management key asked (pre-flight I11).
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
    packages that use the TPM; **two `port49` artifacts** (decision 45 ruling 22): the static one
    in the image and server packages (no PKCS#11, no Secure Enclave), and the client release
    (`-tags hwkey_dlopen`, dynamically linked) in the desktop and jump-host packages people run
    `port49 login` from; name them so an operator can tell which is which, and keep
    `make check-static` in the release pipeline;
  - the `hwkeys` workflow is the first CI to run Go tests; plan 12 decides whether `make test`
    joins it;
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

- **Which `port49` has hardware keys.** There are two builds. The client build (`make
  build-client`, written as `bin/port49-client`; plan 12's desktop and jump-host release) has
  PKCS#11 (YubiKeys, smartcards), the TPM and, on macOS, the Secure Enclave; it needs the system's
  dynamic loader, which every desktop Linux and macOS has. The static build (`make build`, written
  as `bin/port49` with `CGO_ENABLED=0`, and the container image) has the TPM and
  file keys only; given a `pkcs11:` or `secure-enclave:` key it says "this port49 was built
  without PKCS#11 support (the static build, as in the container image); use the client release",
  and nothing else changes. Its `issued_key_store: auto` passes over a configured `issued_key`
  and says so, rather than refusing. Run `port49 login` from the client build.
- **Your key can live in hardware.** In `/etc/port49/config.yaml` (once, for the fleet) or your own
  `~/.port49/config.yaml`, set `key:` to a reference instead of a path:
  - a YubiKey or smartcard: `key: "pkcs11:id=%01?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so"`
    (slot 9a is `id=%01`; on macOS the module is where Homebrew put `libykcs11.dylib`). Leave
    `cert:` out and port49 reads the certificate from the token. The module, any symbolic link to
    it, and every directory above it must be owned by root or you and writable by no one else.
  - a TPM key file: `key: "tpm:file=/home/alice/.port49/my.tpmkey"`, or a persistent handle
    `tpm:handle=0x81000001`. You must be in the `tss` group.
  `port49 login` asks the token's PIN once, on the terminal; it is never on the command line, in
  the environment or in a log. A wrong PIN is sent once: port49 never retries it, and tells you
  when the token says few tries are left. For a host with no terminal, put the PIN in a file only
  you can read and add `pin-source=file:///path` to the URI; `pin-value` is refused.
- **Touch and PIN policy are yours.** For the session key, PIN once and touch never or cached is
  the sane default: the key is used once per session, at the handshake and at each refresh, never
  per device.
- **`port49 login --oidc` keeps its key in hardware by default.** `issued_key_store: auto` uses a
  token when `touch_key` and `issued_key` are both set, else the TPM on Linux when you can (it says
  so), else the 0600 file as before. `tpm`, `pkcs11` (with `issued_key: "pkcs11:…;id=%04"`) or
  `file` name one; a named one that cannot be used stops before your browser opens. For `pkcs11`,
  make the key once yourself (`ykman piv keys generate 9e …`): port49 signs with it and never
  writes to your token, so it never needs your management key. A TPM key file is useless on any
  other machine, and is named for the machine (`<host>_<port>.<machine>.tpmkey` and `.pem`), so
  jump hosts that share your home directory each keep their own and never overwrite each other's.
- **The key unplugged at 3am.** Your open device sessions and the agent's held connection keep
  working: `port49 token` still mints. `port49 refresh` and anything that needs a new connection say
  "insert your key"; nothing ends. Put the key back and run `port49 login`: it sees the key without
  touching the token first, asks the PIN and carries on.
- **The broker's certificate is checked against its CRL**, link by link, for every link that names a
  distribution point.
  `broker_crl: check` (default): a revoked broker certificate is refused before anything is sent to
  it; a CRL server that does not answer is said once and the login goes on (tried again after a
  minute, not at every connection); a link with no distribution point is not checked. `require`
  refuses that too, and refuses any certificate in the chain (the root aside) that names no
  `http`/`https` distribution point: add an HTTP CDP to the CA, or use `check`. `off` checks
  nothing. `require` therefore refuses a stock step-ca broker certificate, and the intermediates of
  many private PKIs, until the CA adds an HTTP CRL distribution point. To see whether yours has one:
  `openssl x509 -noout -ext crlDistributionPoints -in broker.pem` (and the same for each
  intermediate); no output means none. To rotate a broker certificate, issue and load the new one
  before publishing the revocation; revoke the leaf, not the CA. Under `require`, a revoked certificate with no replacement stops new logins while
  held sessions continue. Lists are kept in `~/.port49/crl/`.
- **`per_login_mfa`: a second factor at each login to the devices you mark.** Under `defaults:`, a
  role, or a scope (`match: {tier: core}` for a class, `match: {name: core-sw01}` for one device):

  ```yaml
  per_login_mfa:
    accept: [hardware_key_touch, idp_mfa]   # one or both
    reuse_for: 15m                          # 0m: a proof at every login; at most 8h
  ```

  The strictest level wins: the methods every level accepts, the shortest `reuse_for`. Two levels
  that share no method are a policy error naming both: `port49 policy test` fails, `policy diff`
  fails when your edit introduces it, and a reload of an edited policy that introduces it is
  refused (the old one keeps serving). If an inventory change makes them meet (a sync adds `tier:
  core`), that device alone is quarantined with the cause, and the rest of the inventory change
  applies; watch `port49_devices_quarantined`. While it stays quarantined, policy edits that do
  not add a new conflict still load: fixing a grant at 3am never waits on it. A scope that matches by an
  attribute needs `on_missing` and `security_log: true` (one matching `name` alone needs neither);
  `on_missing: exclude` there is a lint warning. Machines are exempt unless a level says
  `applies_to_machines: true`, and then prove by a touch from a key and touch slot on one token
  (`port49 workload token --key pkcs11:… --touch-key pkcs11:…`). `port49 explain` prints the
  effective requirement and where each part came from; `policy diff` fails on a weakening (a
  method added to `accept`, a longer `reuse_for`, a level removed, `applies_to_machines` turned
  off, a requirement removed) unless a session test asserts the new `per_login_mfa:`, as it does for a privilege raise;
  a tightening only prints.
- **Upgrade first.** Upgrade every broker and daemon before adding `per_login_mfa` to a policy: a
  replica that does not know the key refuses the policy and keeps serving the old one, with no
  requirement; `port49_policy_file_refused` is 1 there and `port49_policy_bundle_matches_runner`
  0 until it is upgraded.
- **The two methods.**
  - `hardware_key_touch`: a touch on your token's always-touch slot. Set `touch_key:
    "pkcs11:id=%02?module-path=…"` (slot 9c, made with `ykman piv keys generate --touch-policy
    always 9c`), and on the broker `broker.identity.per_login_mfa.hardware_key_touch.
    attestation_roots_file:` Yubico's PIV attestation roots, every one Yubico publishes (newer
    firmware chains through an intermediate under a newer root: list the root and the
    intermediate; L60 records which). The broker checks that the touch slot is on the same token
    as your session key; a TPM, a file key or an imported key cannot give it. **So a device that
    accepts only `hardware_key_touch` locks out anyone whose session key is not on their token**,
    including `--oidc` users whose key went to the TPM under `auto`: give them `issued_key` on the
    token, or accept `idp_mfa` too. port49 says this at the prompt ("your session key is in the
    TPM; a touch proves only from the token that holds it") instead of trying a touch that must
    fail.
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
- **Hardware tests:** `make test-hw` (needs `softhsm2`, `swtpm`, `swtpm-tools`, `ykcs11` and a
  running `pcscd`), and the `hwkeys` workflow on every pull request, which also fails if the
  static build stops being static (`make check-static`).
