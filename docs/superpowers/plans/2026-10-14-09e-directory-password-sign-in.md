# Plan 9e: A Directory-Password Sign-In — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A company with neither an identity provider nor a PKI signs its people in with the
directory password they already have, plus a second factor: `port49 login --directory` sends the
password and a TOTP code to the broker over its TLS, the broker checks the code and then the
password by a bind as the person's entry over LDAPS or StartTLS, and it issues the same short-lived
certificate plan 9b issues. Everything after the sign-in is 9b's.

**Branch:** `feature/directory-password-sign-in`. Base: `main` at `221bf0ff` (plan 9d merged).

**What changes, in one screen:**
- **A new human verifier, `type: directory_password`,** under `broker.identity.humans`, beside
  `broker.directory` (7g) and `broker.identity.issuance` (9b). It names its `principal_domains`, its
  `second_factor` (`totp`, the one value), its enrollment windows and its rate limits.
- **`POST /v1/sign-in`** takes `{name, password, code, csr}`, with no client certificate. In order:
  the source's attempt limit, the entry the name names (a search as the broker's own bind), the
  principal's attempt limit, the TOTP code, then the password, as a simple bind as the entry's DN
  on a connection of its own, closed at once. Then the certificate. For a person with no second
  factor and enrollment open for them, it answers `202` with an enrollment (an `otpauth://` URI and
  a handle) instead, and **`POST /v1/sign-in/confirm`** `{handle, code, csr}` takes the first code and
  issues.
- **The password** is read at the terminal with echo off, sent once in the request body over TLS
  1.3 to the broker's CA alone, bound once to the directory over the pool's TLS, and never stored,
  logged, hashed, put in argv, the environment or a file, or in `credential_sha256`.
- **TOTP** (RFC 6238; SHA-1, 6 digits, 30 s): the broker makes the secret, keeps it sealed in the
  enrollment store (`broker.directory.enrollment_store`, default the shape of `store:`; on memory a
  sealed file, D7, D12) bound to the principal and the entry, accepts one step either side, takes
  each step once, before the password is tried, and says a phone's clock is off when a code
  matches a step up to 5 minutes away.
- **The enrollment store fails closed.** `port49 directory init-enrollments` creates it once per
  install (its creation mark); port49d never creates it. A store with no mark, or one that will not
  unseal, refuses password sign-in `503 enrollment_store_lost` and nothing else.
  `port49 directory export`/`import` back it up and restore it; `reset-second-factor --all`
  replaces a lost one.
- **Attempt limits,** counted in `store:` (regional) before anything is judged, fail closed: 5
  failures per principal and 50 per source address (an IPv6 /64) per 15 minutes by default.
  `port49 directory unlock <principal>` clears a principal's; `port49 directory reset-second-factor
  <principal>` reopens enrollment for a lost phone.
- **The certificate** carries `method=directory_password` and `amr=pwd&amr=otp` in its
  `port49-sign-in:v1` URI. Records name it as `auth.directory_password: {amr, auth_time,
  entry_sha256}`.
- **New §5.7 reasons** `sign_in_refused`, `sign_in_throttled`, `enrollment_closed`,
  `enrollment_store_lost`, `second_factor_enrolled`; a new decision event `enroll`; three report
  events, `second_factor_reset`, `sign_in_unlock` and `enrollments_import`. Metrics
  `port49_sign_ins_total{outcome}` and `port49_directory_enrollment_store_ok`.
- **Design §7's "port49 has no password path at all"** and **§10's "it never binds as the user"**
  are amended: a person's password reaches the broker once per sign-in and is never a device
  credential; a service account still has no password path.
- **Lab:** a new row, **L67**, on OpenLDAP and Samba AD (the 7g harness) and Windows Server AD on
  the SER8 (this host, beehive).

**Architecture:**
- `internal/totp` (new): `NewSecret`, `URI`, `DecodeSecret`, `Code`, `Check`, over
  `github.com/pquerna/otp`'s code generation (decision D9).
- `internal/directory/signin.go` (new): `Resolver.SignInEntry`, `Resolver.CheckPassword`,
  `PasswordRefusal`, `dialPerson`.
- `internal/issuer/signin.go`: `SignIn.Method`, `MethodDirectoryPassword`; the URI and its reader.
- `internal/store`: three attempt methods on `Store` (regional; memory, etcd family `sa/`, crypt
  pass-through, the guard); a new `store.Enrollments` handle (D12) for second factors and the
  creation mark, in memory, `internal/store/enrollfile` (the sealed file, D7), etcd (family `sf/`
  and `meta/enrollments`, the broker's alone), crypt (`WrapEnrollments`: the secret sealed, bound
  to the principal) and the guard; `storetest` properties.
- `internal/broker/signin.go` (new): the two endpoints and the enrollment store's check;
  `signin_admin.go` (new): reset (one and `--all`), unlock, init, export, import and the re-seal
  pass; `issue.go`'s tail factored into `issueTo`; `issued.go`, `workload.go`,
  `broker.go`, `listen.go`, `server.go`, `oidc.go`: a certificate from a directory sign-in is read
  as 9b's are.
- `internal/config/identity.go`: the verifier; `internal/oidc/config.go`: `PasswordSignIn`.
- `cmd/port49/signin.go` (new): `port49 login --directory`; `cmd/port49/qr.go` (new): the
  enrollment's QR code on the terminal; `cmd/port49/directory.go`: `reset-second-factor`,
  `unlock`, `init-enrollments`, `export`, `import`.
- `tests/lab/l67_test.go` (new) and the 7g harness's seeds; `Makefile`: `lab-l67`,
  `lab-l67-windows`.

**Tech Stack:** Go 1.26, module `github.com/rhwendt/port49`, `CGO_ENABLED=0`. New direct
dependency: `github.com/pquerna/otp v1.5.0`, and through it `github.com/boombuler/barcode` (the QR
code), both pure Go (decision D9). `github.com/go-ldap/ldap/v3 v3.4.14` (in `go.mod` since 7g) for
the bind. Lab: the 7g harness (OpenLDAP 2.5 with the `ppolicy` overlay added, Samba AD 4.17), the
L44 harness's Windows Server 2025 DC on the SER8.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`: §5.7 (events, reasons, the credentials rule),
  §12 (`port49 login --directory`, `port49 directory reset-second-factor`, `unlock`,
  `init-enrollments`, `export`, `import`), §13 (new decision 47; decision 38's binds, decision 43 rulings 9, 10 and 13 amended),
  §14 (a "**Directory sign-in**" block), §15 (new **L67**).
- `docs/design/2026-08-21-port49-design.md`: §7 (human identity, a third path; the service-account
  paragraph), §10 (directory authentication), §12 (the failure table's directory row), §17 (the
  surface and errors).
- The roadmap `docs/superpowers/plans/README.md`: "Plan 9", the 9e entry; "Plan 7g — As built"
  (the directory, the pool, the bind hold-off), "Plan 9b — As built" (issuance), "Plan 9c — As
  built" (`per_login_mfa`, `auth.amr`), "Plan 9d — As built". House style: plan 9d.

**Prerequisite:** plan 9d merged (`main` at `221bf0ff`).

---

## Decisions for the controller

Each is a proposed ruling, with the alternatives in one line. **⚑ Ryan** marks a decision that
weakens security somewhere or that Ryan must make themselves; the controller rules on the rest. The
plan's text assumes each recommendation; a different ruling changes the tasks it names.

- **D1. The second factor: TOTP held by port49.** The broker makes a 20-byte secret, shows it once
  as an `otpauth://` URI (a QR code on the person's terminal), keeps it sealed in the enrollment
  store (D7, D12) bound to the principal and the entry's immutable id, and checks RFC 6238 codes (SHA-1, 6 digits,
  30 s; what every authenticator app reads). *Why:* Windows AD and Samba AD have no second factor
  of their own; a TOTP kept in the directory would need the broker to write there (design §10
  says read-only) and a schema change. *Alternatives:* the directory's own OTP (FreeIPA, OpenLDAP
  `slapo-otp`: password and code in one bind, which port49 cannot see was checked, and which AD
  lacks); a secret in a directory attribute; 9c's `hardware_key_touch` (needs a token per person
  and enrolling its serial); WebAuthn (no browser in this path). Tasks 1, 2, 4, 9.
- **D2. ⚑ Ryan — enrollment is trust on first use inside windows, with no admin per user.** A
  person with no second factor enrolls at a sign-in whose password is right when one of these is
  open for them: the rollout window (`enrollment.open_until`, one line for the whole fleet); their
  first `enrollment.new_entries_for` (14 days) after their entry's creation (`whenCreated` /
  `createTimestamp`), so a new hire needs no one; or `enrollment.reopen_for` (24h) after an operator
  ran `port49 directory reset-second-factor` (a lost phone). Outside them, `enrollment_closed`.
  Every enrollment is an `enroll` record, alertable. *The weakening:* inside a window a stolen
  password enrolls the thief's authenticator first, and the real person then finds a second factor
  they never set up; it is the first-contact window Ryan accepted for host keys (decision 46), and
  it is bounded per person. *Alternatives:* enrollment always open (weaker, no toil); an operator
  per user issues an enrollment code (toil the standing rule refuses); enrollment only with an
  existing port49 credential (a company on this path has none). Tasks 1, 5, 6, 9.
- **D3. The password's path.** Terminal (echo off) → the request body of `POST /v1/sign-in` over TLS
  1.3, verified to `broker_ca` and the broker CRL check (9c), never through a proxy → a simple bind
  as the entry's DN, the DN from the broker's own search (never the typed name), over the server's
  LDAPS or StartTLS with `broker.directory.ca_file`, on a fresh connection that presents no client
  certificate, closed after the one bind. An empty password is refused before any dial (RFC 4513
  §5.1.2's unauthenticated bind succeeds as anonymous). Never stored, logged, hashed (no
  `credential_sha256` for a sign-in), in argv, the environment or a file; no `--password` flag and
  no `password_env`. *Alternatives:* the client binding to the directory itself (self-asserted,
  design §10, and clients do not reach DCs); a Kerberos AS exchange at the broker (AD only); a
  client-side hash (it becomes the password). Tasks 1, 6, 9, 11.
- **D4. ⚑ Ryan — the order: the code before the password.** Source limit → the entry (a search as
  the broker) → principal limit → TOTP → the password bind. *Gain:* for an enrolled person a spray
  never reaches the directory, so port49 can never lock an AD account, and the password is never
  tested for someone without the code. *Cost:* port49 never sees "password right, code wrong", the
  signal that a password is stolen; it sees "code right, password wrong" instead. The person sees
  one refusal for any of the three. *Alternative:* password first, keeping that signal, with every
  spray reaching the directory's lockout. Tasks 1, 9.
- **D5. Lockout and rate limits.** Two fixed windows in the store: 5 failures per principal and 50
  per source per 15 minutes (`rate_limits.failures_per_principal`, `failures_per_source`,
  `window`). Each attempt is counted before it is judged, so parallel attempts cannot pass the
  limit; a success clears the principal's count and takes its own attempt back from the source's
  (a 202 that starts an enrollment gives back its source attempt only: the confirm clears the
  principal's). A broker fault (`503 directory_unavailable`, `store_unavailable`,
  `issuance_unavailable`, or a lost enrollment store found mid-request) gives back every count the
  attempt took, since nothing about the person was judged.
  The source is the TCP peer, an IPv4 /32 or an IPv6 /64. A store error is `503 store_unavailable`
  and nothing is checked (fail closed). Over the limit: `429 sign_in_throttled`, `Retry-After`,
  naming the time. `port49 directory unlock <principal>` clears a principal's count at 3am. 5 is
  under the common directory lockout threshold (AD's default on Server 2025 is 10 in 10 minutes;
  L67 cell (d) measures the interaction). A fixed window lets at most `2 × failures_per_principal −
  1` failures through in any one window length (four at the end of one window, five at the start
  of the next: nine against AD's ten, a margin of one); keep that under the directory's lockout
  threshold. *Accepted:* the per-principal 429 tells a caller that a typed name is a person's;
  port49 does not hide which names exist (a directory's lockout does the same), and the 429 never
  names the principal. *Alternatives:* a sliding window (more store traffic,
  same bound); per (principal, source) pairs (a distributed spray gets N×5); no per-source limit
  (one host sprays every name). Behind an L4 load balancer or NAT that hides sources, the
  per-source count is everyone's: the operator notes say to raise it or set 0 (off). Tasks 1, 4, 5, 9, 10.
- **D6. What `auth.amr` records.** `["pwd", "otp"]` (RFC 8176), in a new record block
  `auth.directory_password: {amr, auth_time, entry_sha256}` on the `issue` and `enroll` permits and
  on every record a directory sign-in's certificate makes, as `auth.oidc` is for 9b's. The
  certificate's URI carries `method=directory_password`, `sub` the entry's id hashed, `amr=pwd&amr=otp`,
  `auth_time` and `iat`, and no `iss`, `sid` or `acr`. *Alternatives:* add `mfa` (a reader derives
  it; port49 records what it checked); reuse `auth.oidc` with a pseudo-issuer (a record would claim
  a provider that does not exist). Tasks 1, 3, 7, 8.
- **D7. Ryan, 2026-10-14: a sealed file on the memory store.** On a memory enrollment store
  (D12; the default when `store.backend: memory`), enrollments, the TOTP used-step record and the
  creation mark live in a sealed file, `<broker state dir>/enrollments.json`, as revocations do
  (Task 4's `internal/store/enrollfile`). On etcd they live in etcd. Attempt counts live in `store:`
  (D12), on memory in memory: lost at a restart, they fail open by at most 5 guesses per principal,
  which is accepted. **A lost store fails closed (Ryan's question, 2026-10-14):** losing the
  enrollments must never reopen D2's window for everyone. The store keeps a creation mark (the
  file's body; the etcd key `meta/enrollments`). **port49d and the broker never create the store
  at start** (controller ruling on pre-flight I15, as decision 32 and `init-revocations` rule for
  revocations): `port49 directory init-enrollments`, on the broker's admin socket, is its one
  creator. It writes the mark, refuses when a store or a mark is already there, and writes one
  `second_factor_reset` report with `"created": true`. A store with no mark (a missing file or
  key, a new install not yet initialised included) or a file that will not unseal (a lost or
  rotated seal key, tampering) refuses password sign-in with `enrollment_store_lost`, before
  anything is counted or read. The log carries one error naming what to run, the metric
  `port49_directory_enrollment_store_ok` reads 0, and every other path serves: certificates
  already issued, tokens, and IdP sign-in. The operator restores the file or the etcd snapshot
  (`port49 directory import`), or runs `port49 directory reset-second-factor --all`, which
  replaces a lost store (an unreadable file renamed aside, never deleted), writes one record and
  opens the 24h reopen window for every entry with no active second factor; it is alertable, like
  `enroll`. Tasks 1, 4, 5, 9, 10, 12, 13, 15.
- **D8. ⚑ Ryan — no domain both an IdP and the directory password sign in.** A
  `directory_password` verifier's `principal_domains` may not overlap a human `oidc` verifier's.
  *Why:* a password and TOTP beside an IdP that enforces phishing-resistant MFA is a downgrade an
  attacker picks. *Alternative:* allow the overlap as an IdP-down fallback (people sign in with the
  password when the provider is down at 3am; 9b already keeps certificate holders working). Tasks 1, 5.
- **D9. The dependency: `github.com/pquerna/otp v1.5.0`.** It generates RFC 6238 codes (Vault's and
  Gitea's TOTP use it) and brings `github.com/boombuler/barcode` for the enrollment's QR code. port49
  keeps the policy around it: the window, the step taken once, constant-time comparison, the skew
  report. Ryan's rule is never to reimplement well-tested tooling; the repo has neither a TOTP nor
  a QR library today. *Alternatives:* RFC 6238 in-house on `crypto/hmac` (about 40 lines, RFC
  vectors) with `rsc.io/qr` for the QR code; no QR code (the secret typed by hand, error-prone at
  scale). Task 2.
- **D10. `totp` is not a `per_login_mfa` method in 9e.** A directory sign-in's person meets a
  `per_login_mfa` device by `hardware_key_touch` alone (with a token); `idp_mfa` needs a provider.
  Adding `totp` to 9c's methods changes the policy schema and its diff gate, and no roadmap entry
  asks for it; it is carried to a follow-up, not cut. The operator notes say so. *Alternative:* add
  it here (a Task between 9 and 10: the method, `POST /v1/mfa` taking a code, the diff gate).
  Tasks 1, 15.
- **D11. The vocabulary.** New §5.7 reasons: `sign_in_refused` (the name, password or code not
  accepted, deliberately one reason to the caller; the record's `sign_in.failed` says which),
  `sign_in_throttled`, `enrollment_closed`, `enrollment_store_lost` (D7), `second_factor_enrolled`.
  New decision event `enroll`;
  report events `second_factor_reset` (also written by `--all` and by `init-enrollments`, with
  `"all"` or `"created"`), `sign_in_unlock`, `enrollments_import`. Reused: `directory_unavailable`,
  `store_unavailable`, `identity_ambiguous`, `certificate_issued`. Tasks 1, 3.
- **D12. Ryan, 2026-10-14: enrollments have their own store handle.** `directory.enrollment_store`
  names the enrollment store separately from `store:` (the same shapes: `memory` with the sealed
  file of D7, or `etcd` with its own endpoints, TLS and keyspace). It defaults to `store:`. A
  multi-region deployment points it at a global etcd, one member per region, while tokens and
  contexts stay regional. The TOTP used-step record lives with the enrollments, so one code
  cannot be replayed in another region; attempt counts stay in `store:` (regional). Plan 11a
  builds the rest of the split (revocations, policy, the regional cache). Tasks 4, 5, 10.
- **D13. Ryan, 2026-10-14: `port49 directory export` and `import`.** `export` writes the
  enrollments, still sealed, to stdout, so a cron job can pipe it to any backup target. `import`
  checks the seal and the creation mark, refuses to overwrite a newer store unless given
  `--replace`, and writes one record (`enrollments_import`). Neither ever prints a secret. Tasks 1,
  3, 4, 10.

---

## Pre-flight 2026-10-14

A pre-flight review against `main` at `221bf0ff` found 5 Critical, 15 Important and 14 Minor
findings. Each is applied in the tasks below, as follows. Where a controller ruling differs from
the review, the ruling is what the tasks build.

- **C1** (D7 built nowhere): R1, Task 1 (row, report, commands, D7 header, rulings 18 and 19, §14,
  errors, design §12 row, L67 (g)), Task 4 rewritten (the `Enrollments` handle,
  `internal/store/enrollfile`), Task 5 (`enrollment_store`, no etcd requirement), Tasks 9, 10, 12,
  13, 15 and the operator notes.
- **C2** (D12, D13 had no task; counts): **Controller ruling:** D12 wins. Attempt counts live in
  `store:` (regional); enrollments, the TOTP used-step record and the creation mark live in
  `broker.directory.enrollment_store`. D7's text says so. Task 4 splits the interfaces that way;
  Task 5 adds the handle; Task 10 adds export and import.
- **C3** (`CanIssue` after the spend): Task 9 Step 3 rewritten; `CanIssue` stays in each caller
  before anything is spent; `issueTo` drops its `principal` parameter.
- **C4** (`dialTLS(..., nil)` panics): Task 6 gains `PersonConn`, `Resolver.PersonDial`,
  `dialPerson` and `personTLS`, dialling with `&Credentials{}`, never nil.
- **C5** (a right-password oracle outside every window): **Controller ruling:** the window is
  decided before the password; outside every window `403 enrollment_closed` with no bind.
  `enrollment_closed` reveals that a name exists and is unenrolled; this is accepted. R7, Task 1's
  row, Task 9 and its tests say so.
- **I1** (the step after the bind): **Controller ruling:** the TOTP step is taken before the bind.
  R5 and Task 9's handler; `TestTwoSignInsWithOneCodeIssueOnce` asserts one bind.
- **I2** (a swap's store error answered 401): Task 9's handler; `ErrConflict` is
  `sign_in_refused`, any other error `503 store_unavailable`.
- **I3** (the 429 names the principal): R7 and Task 9; the principal is never named to the caller;
  D5 records the name-enumeration exposure as accepted.
- **I4** (`changeAfterReset` on a successful bind): Task 6's `CheckPassword` reads the ppolicy
  control on a success too; a test row.
- **I5** (five reasons, the gauge, "twelve", the 503): Task 1 (row, §14 "twelve", errors row),
  Task 3 (`EnrollmentStoreLost`, `DirectoryEnrollmentStoreOK`, nine outcomes), operator notes.
- **I6** (crypt test constructors): Task 4 Step 8 written with `memory.NewEnrollments`,
  `WrapEnrollments` and `crypt_test.go`'s `keys()`.
- **I7** (`ldap.ParseGeneralizedTime`): Task 6 uses `ber.ParseGeneralizedTime`.
- **I8** (an empty mapping attribute): Task 5 Step 3 (`checkSearchShape`, `announceDirectory`)
  and Task 6 (`entryAttrs` appends the mapping only when set; a test).
- **I9** (Task 5's tests cannot load): Task 5's tests rewritten over `passwordBroker`, indented
  under `  identity:`, the empty row replaced by real bounds rows.
- **I10** (`csrBody` is a JSON body): Task 9 uses `csrOf` (Appendix B's bodies, now in Task 9).
- **I11** (2×limit−1 through a fixed window): D5, L67 (d) and the operator notes.
- **I12** (the entry-id refusal speaks first): R12 and Task 9; the generic sentence to the caller,
  the hourly log line names `reset-second-factor`.
- **I13** (`SignInEntry`'s error text): Task 9 Step 4; `entry` logs the class alone; the test's
  fake carries the typed name in its error.
- **I14** (no admin op for `--all`, export, import): Task 10's Interfaces; the import body
  follows the request line, bounded at 64 MiB.
- **I15** (a lost volume re-created silently): **Controller ruling:** the stronger alternative.
  port49d and the broker never create the enrollment store at start. `port49 directory
  init-enrollments` is its one creator: it writes the mark, refuses when a store or a mark is
  already there, writes one `second_factor_reset` report with `"created": true` (no new event), and
  is carried by the admin op `enrollments_init`; it follows decision 32 and `init-revocations`. A
  missing store or mark always means `enrollment_store_lost` (password sign-in refused 503; every
  other path serves). `reset-second-factor --all` stays the recovery path, renaming an unreadable
  file aside and never deleting it. D7, R13, Task 1, Task 4 (`CreateEnrollmentMark`), Task 9
  (`CheckEnrollmentStore`), Task 10, Task 12, Task 13 (g), Task 15 and the operator notes.
- **M1** (`metrics.New(reg)`): Task 3's test.
- **M2** (CLI names): Task 11 uses `user.Current()`; Task 12 runs `run` under
  `t.Setenv(runCLIEnv, "1")` (`runCLIEnv` is the env var's name, a constant, not a helper).
- **M3** (`readSecret` must not trim): Task 11.
- **M4** (`directory_password` under `machines`): Task 5, a case and a test row.
- **M5** (collision lists): Task 5 (`ownRevocationsFile`, the port49-broker list) and Task 10
  (`ownStateDir`'s names).
- **M6** (`failures_per_source: 0`): Task 9; no source count is written when it is off.
- **M7** (the empty password recorded `failed: name`): Task 9; `failed: password`, no principal.
- **M8** (`Cache-Control: no-store` on the 202): R4 and Task 9.
- **M9** (`totp.Code`): Task 2 gains `Code` and `DecodeSecret`, with tests.
- **M10** (a throttled confirm took the handle): Task 9; the handle is put back before the 429.
- **M11** (`TestTwoStepsAwayIsSaidAsSkew` tests three): Task 2 renames it
  `TestThreeStepsAwayIsSaidAsSkew`.
- **M12** (a bearer at a password-only broker): Task 8 gains `TestABearerAtAPasswordOnlyBroker`.
- **M13** (the 202 records nothing): R4 and R9 say so.
- **M14** (one instant for the confirm-by): R4 and Task 9; `until` computed once.
- **Found while applying:** the spec's report events are numbered across all events, so adding
  `enroll` (a decision event) renumbers `inventory_change` and `directory_forget` to sixteenth and
  seventeenth; Task 1 Step 2 says so. The unknown-op line lists nine ops (I14's five new ones with
  `enrollments_init`).

---

## Owner's rulings this plan carries

1. **9e exists** (Ryan, 2026-10-10): the route for a company with neither an IdP nor a PKI.
   `port49 login` signs the person in by an LDAP bind against `broker.directory`, plus a second
   factor, and the broker issues the same short-lived certificate 9b issues.
2. **Its spec task decides** the second factor, the password's path, lockout and rate limits per
   principal and per source, and what `auth.amr` records.
3. **Design §7's "port49 has no password path at all"** is amended: a person's password reaches the
   broker once per sign-in and is never a device credential.
4. **The 3am case is a test:** the directory down, holders of a certificate keep working; only a
   sign-in fails, and says so.
5. **Lab:** a new row on OpenLDAP and Samba AD (the 7g harness), and Windows AD on the SER8.
6. **Standing rules:** operational failure modes first; no user toil at scale; follow the spec; security
   first (the password never in a log, argv, env or `credential_sha256`; limits fail closed; the
   second factor cannot be skipped; an unvalidated body is never logged); deployment is not
   prescriptive; data is snake_case; reason codes from §5.7 alone; never reimplement well-tested
   tooling.

## Rulings this plan makes (recorded as decision 47 in Task 1)

D1–D13 above, as the controller and Ryan ruled them (with the pre-flight's rulings), and these,
each on reasoning unless it says data:

- **R1. Where it fits.** `type: directory_password` is a human verifier. It requires
  `broker.directory` and `broker.identity.issuance`, each refused at load when missing, naming it.
  It runs on either store shape: its enrollments live in `broker.directory.enrollment_store`
  (D12; default the shape of `store:`), on memory in a sealed file (D7). A broker may list it alone
  (no x509 anchor, no OIDC verifier): its client certificate pool is then its issuing CA's, as a 9b
  OIDC-only broker's is.
- **R2. `broker.directory.certificate_mapping` is required only beside a human x509 verifier.** Without
  one no certificate is ever mapped (an issued certificate's principal is its own, decision 43 ruling
  10), and a company with no PKI should not write a mapping. A mapping set with no x509 verifier is
  still checked.
- **R3. The name a person types** is matched against `broker.directory.username_attribute` under
  `user_filter` and the verifier's `filter` (ANDed; an LDAP filter, optional, for keeping service
  accounts out), escaped (RFC 4515). It must be 1–256 bytes of printable ASCII, else refused before
  any search (counted against the source). The entry must give a principal and a username as 7g's
  `identityOf` does, be one entry's alone (`principalUnique`, `usernameUnique`), not be a workload's
  (`notWorkload`), and its principal's domain must be in `principal_domains`. The search runs as the
  broker's own bind through the pool (`Pool.Do`), so the pool's breakers, hold-off and site order
  apply, and the server that answered is the one the password is bound against.
- **R4. The enrollment.** Two calls. `POST /v1/sign-in` for a person with no second factor, with a
  window open and then the password right, writes a pending record (the secret sealed, confirm by
  now + 10 minutes, the one instant the handle's lifetime ends too) and a once-record of the handle
  (32 random bytes; the store keeps its SHA-256 → principal, until that instant), and answers `202
  {enroll: {handle, otpauth_uri, confirm_by}}` with `Cache-Control: no-store`. Nothing is issued,
  and the 202 records nothing (the `enroll` record is the confirm's); `enrollment_started` counts
  it. `POST /v1/sign-in/confirm {handle, code, csr}` takes the handle, checks the code against the
  pending secret, makes the record active (`enrolled_at`, `enrolled_from` the source), records
  `enroll permit second_factor_enrolled`, and issues. A wrong code puts the handle back for the time
  it had left; the principal's limit bounds the tries. A pending record past its time is no
  enrollment, and a later sign-in starts again. Over a `reopened` record the enrollment keeps the
  record `reopened` with its own end (so a lapse leaves the operator's window in place) and holds
  the new secret in it; that secret is accepted only under a live confirm handle, whose once-record
  carries the principal and the enrollment's end, and never as an active factor. Two enrollments at
  once for one principal: the second loses the compare-and-swap and is refused.
- **R5. The code.** 6 digits; a step either side of the broker's now (RFC 6238 §5.2); a step taken
  once per principal, kept as `last_step` by compare-and-swap, so a replayed code and two replicas
  racing one code are both refused. A code matching a step 2 to 10 steps away is refused and said:
  "your authenticator's clock is about N minutes off; set it to the network's time and try again"
  (it counts as a failure, and only the holder of the secret can produce one). The comparison is
  constant-time. The step is taken when the code matches, before the password is tried: a code is
  one attempt at the password whatever its answer, two sign-ins racing one code reach the
  directory once, and a person who mistypes the password waits for the next code (at most 30 s).
- **R6. The directory's answer to the password.** Result 49 is a refusal. AD's (and Samba's) data
  code in the diagnostic message is read and kept only when it is one of `52e` (wrong password),
  `525` (no such user), `530`, `531` (logon hours or workstation), `532` (password expired), `533`
  (disabled), `701` (account expired), `773` (must change), `775` (locked); the rest of the message
  is dropped, as 7g drops it. OpenLDAP's `ppolicy` response control (requested on the bind) is read
  for `passwordExpired`, `accountLocked` and `changeAfterReset`. Results 51 (busy) and 52
  (unavailable) are `directory_unavailable`, as a connection that fails: the server did not serve
  the bind (RFC 4511 §A.2). 53 (unwilling to perform) is a refusal of the account's state (389-DS
  and eDirectory give it for an inactivated or locked account), so its `State()` is true with no
  data code. Any other result code is a refusal carrying its code; a connection that fails is `directory_unavailable`. A refusal at the bind is
  never a pool fault and never moves the pool's breakers or hold-off.
- **R7. What the person is told.** One sentence for a wrong name, password or code
  ("the broker did not accept that name, password and code; check each and run `port49 login`
  again"), so the API tells no one which was wrong. Past the code, the directory's own state is said
  ("your directory password has expired: change it, then sign in"; "must be changed before first
  use"; "is disabled"; "is locked: ask your directory administrator"), since only the holder of a
  right code gets that far; for a person enrolling, only one inside an enrollment window, which is
  decided before the password is checked: outside every window the answer is `403
  enrollment_closed` and nothing is bound (C5). `enrollment_closed` says a name exists and has no
  second factor, without a bind; it is the operator's signal at 3am and accepted as such.
  Throttled: the window's end; for the principal's limit, "an operator can clear it with `port49
  directory unlock` for your account". The principal is never named to the caller.
  The directory down: "the directory did not answer, so no one can sign in with a password now;
  anyone already signed in keeps working until their certificate ends".
- **R8. What is never logged or printed** but at the person's own terminal: the password, the code,
  the secret, the `otpauth://` URI, the handle, and a typed name that maps to no entry (people type
  passwords into name prompts). A record names the principal once one is known, and the source
  prefix. The broker reads the body with `DisallowUnknownFields` into a fixed struct and never echoes
  it; a body that does not parse is answered with no part of it.
- **R9. The records.** `issue` gains the directory sign-in: `permit certificate_issued` with
  `auth.directory_password` and `sign_in: {source}`, a deny with `sign_in: {source, failed,
  skew_seconds, directory_result, directory_data}`, `failed` one of `name`, `second_factor`,
  `second_factor_skew`, `password`, `directory_state`, `enrollment`, `principal_limit`,
  `source_limit`. An unknown name is recorded `deny sign_in_refused` with no principal; two entries
  for one name `deny identity_ambiguous` (alertable, as everywhere). `enroll`: `permit
  second_factor_enrolled` or a deny with the same reasons. The 202 that starts an enrollment
  records nothing. `second_factor_reset` and `sign_in_unlock` name the principal and `origin:
  admin_socket uid N`; `second_factor_reset` with `"all": true` (`--all`) or `"created": true`
  (`init-enrollments`) names none. `enrollments_import` names the records imported and the
  export's time. A lost enrollment store is recorded `issue deny enrollment_store_lost`.
- **R10. The certificate a directory sign-in gets** is 9b's (decision 43 ruling 9) but for its URI
  (D6). The broker reads it as 9b's (ruling 10): the principal is its CN, never mapped; it is
  trusted while a `directory_password` verifier is configured whose `principal_domains` hold the
  principal's domain, so removing the verifier takes its people's certificates with it. No logout
  reaches it (there is no provider), so revocation is by principal or serial and the short lifetime.
  Membership is read at mint through 7g's `Resolver`, within grace, as for any issued certificate.
- **R11. Seal-key rotation.** A second-factor record lives until it is reset, longer than
  `encryption.previous` usually stays. The crypt layer marks a record it opened under the previous
  key `Stale`, and each scheduled directory pass (`RefreshDirectory`, every `refresh_interval`)
  seals stale records again under the current key. A record that opens under neither key is never
  "not enrolled": the sign-in is `503 store_unavailable`, and the broker's line names
  `port49 directory reset-second-factor`.
- **R12. A second factor is the entry's, not just the principal's.** The record keeps the entry's id.
  A sign-in whose entry has another id (a re-created entry, after 7g's `port49 directory forget`) is
  refused `failed: second_factor` with the one sentence of ruling 7 (the caller is told nothing
  more), and the broker's log says once an hour which entries differ and names
  `port49 directory reset-second-factor <principal>`.
- **R13. Operator commands,** on the broker's admin socket, as `port49 directory forget` is:
  `port49 directory reset-second-factor <principal>` makes the record `reopened` for `reopen_for`
  (the secret dropped; an enrollment begun inside the window may later hold a pending secret in
  the reopened record, R4) and prints what it removed (`enrolled_at`, `enrolled_from`); with `--all`
  it drops nothing, lets every entry with no active second factor enroll for `reopen_for`, and
  replaces a lost enrollment store (an unreadable file renamed aside, never deleted).
  `port49 directory unlock <principal>` clears the principal's attempt count.
  `port49 directory init-enrollments` creates the enrollment store once per install (D7; refused
  when a store or a mark is there). `port49 directory export` writes the store, still sealed, to
  stdout; `port49 directory import [--replace]` fills it from an export (D13). None needs the
  directory, and none prints a secret.
- **R14. `/v1/config`** adds `"directory_password"` to `methods` and `sign_in: {second_factor:
  "totp"}`; its `issuance.available` already says when nothing can be issued, so the client says so
  before asking for a password.
- **R15. `port49 login --directory`**, or `method: directory`: the name from `--name`, else
  `sign_in_name` in the config file, else the login user's name, offered at the prompt; the password
  and code read from the terminal with echo off; no terminal is a refusal naming it. A held
  certificate is reused while it has a quarter of its life left, and through a broker or directory
  outage while it is valid, exactly as decision 43 rulings 12 and 17 say for `--oidc`. The
  enrollment is shown only on a terminal: the QR code, the key in groups of four for typing, and the
  time to confirm by.
- **R16. Service accounts** still never authenticate with a directory password (design §7): a
  workload's entry is refused (`notWorkload`), and the verifier's `filter` is how an operator keeps a
  person-shaped service account out; the operator notes say to set it.
- **R17. The 3am cases, each a test:** the directory down (a held certificate mints from grace, a
  sign-in is `503 directory_unavailable` and says so); the store down (a sign-in is `503
  store_unavailable`, nothing checked); a phone's clock off (refused, the skew said); a person locked
  out by someone spraying their name (`429` with the time and the unlock command; the held
  certificate still works); a lost phone (`reset-second-factor`, then a sign-in enrolls); the seal
  key rotated (R11); the enrollment store lost (`503 enrollment_store_lost`, nothing counted, a held
  certificate mints; `reset-second-factor --all` or `import` restores sign-in).

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, `CGO_ENABLED=0`; static stays static (`make check-static`).
  One new module, `github.com/pquerna/otp v1.5.0` (and the `github.com/boombuler/barcode` version its
  `go.mod` requires), recorded in Task 2's commit message with its licence (Apache-2.0; MIT).
- snake_case for all data: `directory_password`, `second_factor`, `principal_domains`,
  `open_until`, `new_entries_for`, `reopen_for`, `failures_per_principal`, `failures_per_source`,
  `window`, `totp_label`, `sign_in_name`, `otpauth_uri`, `confirm_by`, `entry_sha256`,
  `skew_seconds`, `directory_result`, `directory_data`.
- Reason codes come from §5.7 alone; Task 1 adds the five new ones to the table before any code
  uses them.
- Never in a log, a record, an error, a metric label, a test failure's output, argv, the
  environment or a file: the password, the TOTP code, the secret, the `otpauth://` URI, the
  enrollment handle, or a typed name that maps to no entry. No `credential_sha256` for a sign-in.
- No device identity and no principal in metric labels.
- Every limit and every store read on the sign-in path fails closed.
- No per-user step by an administrator at fleet scale: a new hire enrolls inside their window, the
  install's `/etc/port49/config.yaml` carries `method: directory`. The one operator step is per
  install, not per user: `port49 directory init-enrollments` (D7).
- The enrollment store is never created on a start path, and a store with no mark is never read as
  "no one is enrolled" (D7).
- Lab: positive controls enforced, a failed control is `INVALID` before any note is written; results
  notes per CLAUDE.md; captures redacted into `tests/lab/evidence/` (a bind is inside TLS, and the
  harness writes no TLS key log, so no capture holds a lab password); the lab watchdog runs during
  every lab run.
- Commit trailer, every commit: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
  and nothing else (no `Claude-Session:` line, no claude.ai link).
- Verify before done: `make test && make vet`, real output reported.

## Review Focus

1. **An empty or whitespace password.** RFC 4513 §5.1.2: a simple bind with a DN and an empty
   password is an unauthenticated bind, and many servers answer success. It must be refused before
   any dial, and the client must refuse to send one. Tests: Task 6
   (`TestAnEmptyPasswordIsNeverSent`), Task 9 (`TestAnEmptyPasswordIsRefusedAndCounted`); L67 cell
   (b) measures what each directory would have answered.
2. **A password typed into the name prompt.** A name that maps to no entry must never reach a
   record, an error, a line or the store, in any form, hashed included. Tests: Task 9
   (`TestAnUnknownNameIsNeverLogged`), Task 4 (no key derived from a name: the attempt keys are the
   principal's and the source's).
3. **Parallel attempts past the limit.** Fifty concurrent wrong codes for one principal must
   produce at most `failures_per_principal` judged attempts. Tests: Task 4
   (`SignInAttemptsCountEveryRacer`), Task 9 (`TestParallelAttemptsCannotPassThePrincipalLimit`).
4. **A second-factor record that will not open.** Under a retired seal key, or corrupt, it must
   never read as "not enrolled", which would reopen enrollment to anyone with the password. Tests:
   Task 4 (`TestASecondFactorUnderAnUnknownKeyIsAnError`, crypt), Task 9
   (`TestAnUnreadableSecondFactorRefusesTheSignIn`).
5. **The code replayed, or raced across replicas.** A code accepted once must be refused the
   second time, including when two sign-ins with the same code reach two brokers at once. Tests:
   Task 2 (`TestAStepIsTakenOnce`), Task 9 (`TestTwoSignInsWithOneCodeIssueOnce`).
6. **The directory refusing the password is not a down directory.** A 49 must not open a breaker,
   start the hold-off or move the pool, so one person's typo never darkens the pool for everyone.
   Test: Task 6 (`TestARefusedPasswordLeavesThePoolAlone`).
7. **A lost enrollment store.** A missing file or key, an unreadable file, or a store with no
   mark must refuse password sign-in and never be created or read as "no one is enrolled", which
   would reopen enrollment to anyone with a password. Tests: Task 4
   (`TestATamperedFileIsLostNeverEmpty`, `EnrollmentMarkIsCreatedOnce`), Task 9
   (`TestTheMarkAtStart`, `TestALostEnrollmentStoreRefusesOnlyTheSignIn`), Task 10
   (`TestInitEnrollmentsCreatesTheStoreOnce`, `TestPort49dWiresThePasswordSignIn`).

---

## Task 1: Spec and design — decision 47, §5.7, §12, §14, §15 (L67), design §7, §10, §12, §17

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §5.7's events intro (~2230–2231) and the
  `issue` row (~2244), a new `enroll` row after the `per_login_mfa` row (~2245), a new paragraph
  after "A sixteenth, `directory_forget`" (~2278–2284), with "A fifteenth"/"A sixteenth" (~2267,
  ~2278) renumbered; five rows after `per_login_mfa_unavailable` (~2432); the paragraph after the table (~2436–2452), one sentence; "Credentials never appear"
  (~2460–2466), one paragraph; §12 a new paragraph after the `port49 login --oidc` paragraph
  (~6279–6288) and after `port49 directory forget` where §12 lists it; §13 decision 38's binds item
  (search "**8.**" inside decision 38, ~7720), decision 43 rulings 9, 10 and 13 (~8640–8690), a
  new decision 47 after decision 46's last ruling, before the `---` above `## 14.` (~9448); §14 a
  "**Directory sign-in (decision 47)**" block after the "**Host keys (decision 46)**" block
  (~10081–10094), and "the eleven decision events" in "**One record per evaluation**" (~9583); §15
  a row after L66 (~10195).
- Modify: `docs/design/2026-08-21-port49-design.md`: §7 "Two supported paths" (~297–298) and a new
  paragraph after the OIDC path's bullets (~368); the service-account paragraph (~473–479); §10
  "Directory authentication" (~1076–1078); §12's "Directory unavailable" row (~1304) and a new
  "Enrollment store lost" row after it; §17's surface (~1994–2007) and errors (~2009–2031).

**Interfaces:** Produces every name later tasks use: decision 47 and its rulings, the five reasons,
the `enroll`, `second_factor_reset`, `sign_in_unlock` and `enrollments_import` events, the record
blocks `auth.directory_password` and `sign_in`, the config keys (`enrollment_store` included), the
endpoints, the commands (`init-enrollments`, `export`, `import` included), the gauge
`port49_directory_enrollment_store_ok`, and L67.

- [ ] **Step 1: §5.7, the events.** In the intro, "Eleven decision events" becomes "Twelve decision
  events" and the report list gains `second_factor_reset`, `sign_in_unlock` and
  `enrollments_import` ("plus eight report events"). In §14, "at each of the eleven decision
  events" (~9583) becomes "twelve". Replace the `issue` row's text with:

```markdown
| `issue` | broker | whether a person's sign-in is exchanged for a port49-issued certificate: an OIDC sign-in at `POST /v1/certificate` (§13 decision 43 ruling 8), or a directory-password sign-in at `POST /v1/sign-in` or `/v1/sign-in/confirm` (§13 decision 47): `permit certificate_issued`, carrying `certificate: {serial, issuer, fingerprint, not_after}` and `auth.oidc` or `auth.directory_password: {amr, auth_time, entry_sha256}`, or a deny with the refusal's reason. A directory sign-in's record carries `sign_in: {source}`, and on a deny `failed` (`name`, `second_factor`, `second_factor_skew`, `password`, `directory_state`, `enrollment`, `principal_limit`, `source_limit`) with `skew_seconds`, `directory_result` and `directory_data` where they apply. It never carries the name typed, the password, the code or the secret. A broker that cannot issue (`issuance_unavailable`) records nothing |
```

  After the `per_login_mfa` row add:

```markdown
| `enroll` | broker | whether a person's TOTP second factor is enrolled (`POST /v1/sign-in/confirm`; §13 decision 47 ruling 4): `permit second_factor_enrolled`, carrying `auth.directory_password` and `sign_in: {source}`, or a deny with the sign-in's reasons. Every enrollment is alertable: inside an enrollment window a stolen password enrolls the thief's authenticator |
```

- [ ] **Step 2: §5.7, the three report events.** The events are numbered across decision and
  report events alike, so with `enroll` the twelfth decision event, "A fifteenth,
  `inventory_change`" becomes "A sixteenth" and "A sixteenth, `directory_forget`" becomes "A
  seventeenth". After the `directory_forget` paragraph add:

```markdown
An eighteenth, `second_factor_reset`, is a report too: an operator ran `port49 directory
reset-second-factor <principal>` on the broker's admin socket (§13 decision 47 ruling 13) —
`{"principal": ..., "second_factor_reset": {"enrolled_at": ..., "enrolled_from": ..., "reopen_until":
..., "origin": "admin_socket uid N"}}`. The principal may enroll again until `reopen_until`. With
`--all` it names no principal and carries `"all": true`: every entry with no active second factor
may enroll until `reopen_until`, and a lost enrollment store (decision 47 D7) is replaced, the
unreadable file kept beside it. `port49 directory init-enrollments` writes one too, naming no
principal and carrying `"created": true` and no `reopen_until`: the enrollment store was created
(D7). Alert on it as on `enroll`, and on `created` at any time but an install. A nineteenth,
`sign_in_unlock`, is a report: an operator cleared a principal's failed-attempt count (`port49
directory unlock`), `{"principal": ..., "sign_in_unlock": {"failures": N, "origin": ...}}`. A
twentieth, `enrollments_import`, is a report: `port49 directory import` replaced or filled the
enrollment store (D13), `{"enrollments_import": {"records": N, "exported_at": ..., "replaced":
true|absent, "origin": ...}}`.
```

- [ ] **Step 3: §5.7, the reasons.** After the `per_login_mfa_unavailable` row add:

```markdown
| `sign_in_refused` | `issue`, `enroll`: a directory-password sign-in whose name maps to no entry under the verifier's filters or outside its `principal_domains`, whose code is wrong, replayed or from a clock too far off, whose password the directory refused, whose entry's state the directory refuses (expired, disabled, locked, must change), or whose second factor is another entry's (§13 decision 47). One reason to the caller on purpose, so the API never says which of the three was wrong; the record's `sign_in.failed` does. The API answers 401. Counted against the principal and the source |
| `sign_in_throttled` | `issue`, `enroll`: the sign-in's principal or source has had `failures_per_principal` or `failures_per_source` failed attempts in the window; nothing was checked (§13 decision 47 D5). The API answers 429 with `Retry-After`. Alert on a rise: someone is spraying |
| `enrollment_closed` | `issue`: a person with no second factor, and no enrollment window open for them; the password is not checked (§13 decision 47 D2, ruling 4). It says a name exists and has no second factor, without a bind, which is accepted (ruling 7). An operator's `port49 directory reset-second-factor` opens one. The API answers 403 |
| `enrollment_store_lost` | `issue`, `enroll`: the broker's enrollment store is lost — it has no creation mark (its file or key is missing, a new install not yet initialised by `port49 directory init-enrollments` included), or its file will not unseal (a lost or rotated seal key, tampering) (§13 decision 47 D7). Password sign-in is refused for everyone, before anything is counted or read; certificates already issued, tokens and IdP sign-in serve. The API answers 503. On a new install the operator runs `port49 directory init-enrollments`; otherwise restores the file or the etcd snapshot (`port49 directory import`), or runs `port49 directory reset-second-factor --all`. Alertable: `port49_directory_enrollment_store_ok` reads 0 |
| `second_factor_enrolled` | `enroll`: a person's TOTP second factor was confirmed with its first code (§13 decision 47 ruling 4). A permit; alertable |
```

  In the paragraph after the table add, after the `per_login_mfa_refused` sentence:
  "`sign_in_throttled`, `enrollment_store_lost` and `second_factor_enrolled` MUST be alertable on
  their own: a run of the first is a spray, the second is every password sign-in refused, and the
  third outside a rollout is someone enrolling."

- [ ] **Step 4: §5.7, credentials.** After "The credential is identified by `credential_sha256` only…"
  paragraph add:

```markdown
A directory-password sign-in (§13 decision 47) carries a password and a code to the broker. Neither
is a device credential, neither is hashed into `credential_sha256` or any other field, and the
record of a sign-in names its principal once one is known, never the name as typed: a name that maps
to no entry may be a password typed at the wrong prompt. The TOTP secret, its `otpauth://` URI and
an enrollment's handle are never logged either.
```

- [ ] **Step 5: §12, the commands.** After the `port49 login --oidc` paragraph add:

```markdown
**`port49 login --directory [--name NAME] [--sign-in]`**, or `method: directory` in the config file,
gets the person a certificate the broker issues over their directory password and a TOTP code (§13
decision 47).
- **The sign-in.** The name (`--name`, else `sign_in_name` in the config file, else the login
  user's) is offered at a prompt; the password and the code are read at the terminal with echo off,
  and never from a flag, the environment or a file. With no terminal it refuses, naming it.
- **The first sign-in** of a person with no second factor, inside an enrollment window, shows a QR
  code and the key in groups of four on the terminal, then asks the authenticator's first code.
- **The certificate** is 9b's: a key on this host, `certificate_lifetime`, the agent on the
  certificate path. A held certificate is reused as `--oidc` reuses it (decision 43 rulings 12, 17).

**`port49 directory reset-second-factor <principal>|--all [--socket PATH]`** drops the principal's
TOTP second factor and lets them enroll again for `enrollment.reopen_for` (§13 decision 47 ruling
13), printing when and from where the dropped one was enrolled. `--all` drops nothing: every entry
with no active second factor may enroll for `reopen_for`, and a lost enrollment store is replaced
(D7), its unreadable file kept beside it. **`port49 directory unlock <principal> [--socket
PATH]`** clears the principal's failed sign-in count. **`port49 directory init-enrollments
[--socket PATH]`** creates the enrollment store once per install (D7): it writes the creation
mark, refuses when a store or a mark is already there, and records `second_factor_reset` with
`"created": true`; port49d never creates the store itself, and until this runs password sign-in is
refused `enrollment_store_lost`. **`port49 directory export [--socket PATH]`** writes the
enrollment store, still sealed, to stdout (never a terminal); **`port49 directory import
[--replace] [--socket PATH] < FILE`** checks the seal and the creation mark and fills the store
from it, refusing to replace one holding a later enrollment or reset unless given `--replace`
(D13). All run on the broker's admin socket, as the broker's user or root, need no directory, and
never print a secret.
```

- [ ] **Step 6: Decision 38, 43 amendments.** In decision 38's binds item, after the sentence that
  the broker binds as itself, add: "Plan 9e (decision 47) binds as a person once per
  directory-password sign-in, to check the password, on a connection of its own that it closes
  after the one bind; groups are still read as the broker." In decision 43: ruling 9's URI bullet
  gains "A directory-password sign-in's URI carries `method=directory_password` (decision 47 D6)";
  ruling 10's issuer bullet gains "For a directory-password sign-in, a `directory_password` verifier
  whose `principal_domains` hold the principal (decision 47 ruling 10)"; ruling 13 gains "A
  directory-password sign-in takes no ID token (decision 47)".

- [ ] **Step 7: Decision 47.** Add after decision 46's last ruling, before the `---`:

```markdown
**47. The agent in full, fifth part: a directory-password sign-in.** *Plan 9e, 2026-10-14, on
Ryan's direction of 2026-10-10: the route for a company with neither an identity provider nor a
PKI.* Rulings rest on reasoning unless they say data. The directories' answers to a person's bind
(rulings 6 and 7, D5's lockout interaction, D2's creation attribute) are *provisional on L67*.
Decisions D1–D13 were ruled by the controller on <date>; D2, D4, D7, D8, D12 and D13 by Ryan on
<date>; the pre-flight's rulings (D7's no-create-at-start, C5, I1) by the controller on <date>.

- **D1. TOTP held by port49.** <the ruling as made, from the plan's D1>
- **D2. Enrollment inside windows.** <as made>
- **D3. The password's path.** <as made>
- **D4. The code before the password.** <as made>
- **D5. Limits.** <as made>
- **D6. `auth.amr`.** <as made>
- **D7. A sealed file on memory; a lost store fails closed; never created at start.** <as made>
- **D8. No overlap with an IdP.** <as made>
- **D9. pquerna/otp.** <as made>
- **D10. `totp` and `per_login_mfa`.** <as made>
- **D11. The vocabulary.** <as made>
- **D12. The enrollment store's own handle.** <as made>
- **D13. Export and import.** <as made>
- **1. Where it fits.** <R1>
- **2. `certificate_mapping` beside x509 alone.** <R2>
- **3. The name.** <R3>
- **4. The enrollment.** <R4>
- **5. The code.** <R5>
- **6. The directory's answer.** <R6>
- **7. What the person is told.** <R7>
- **8. Never logged.** <R8>
- **9. The records.** <R9>
- **10. The certificate.** <R10>
- **11. Seal-key rotation.** <R11>
- **12. The entry's own.** <R12>
- **13. Operator commands.** <R13>
- **14. `/v1/config`.** <R14>
- **15. `port49 login --directory`.** <R15>
- **16. Service accounts.** <R16>
- **17. The 3am cases.** <R17>
- **18. The config.** `broker.identity.humans[]`, `type: directory_password`: `principal_domains`
  (required, as an `oidc` verifier's); `second_factor: totp` (required; the one value); `filter`
  (optional LDAP filter); `enrollment: {open_until (RFC 3339, optional), new_entries_for (default
  336h; 0s off), reopen_for (default 24h, 1h–168h)}`; `rate_limits: {failures_per_principal
  (default 5, 1–100), failures_per_source (default 50, 0 off, at most 10000), window (default 15m,
  1m–24h)}`; `totp_label` (the authenticator's label, default `port49 (<broker host>)`, printable
  ASCII without `:`). At most one such verifier, and only under `humans`. Unknown keys refused.
  `broker.directory.enrollment_store` (D12): `{backend: memory}` (the sealed file
  `<state dir>/enrollments.json`) or `{backend: etcd, etcd: {endpoints, ca_file, prefix, identity:
  {cert_file, key_file}, call_timeout}}`; absent, the shape of `store:` (on etcd the same cluster
  and the broker's identity, under `<prefix>v1/sf/` and `meta/enrollments`). Set without a
  `directory_password` verifier, it is refused.
- **19. Metrics.** `port49_sign_ins_total{outcome}`: `issued`, `refused`, `throttled`,
  `enrollment_started`, `enrolled`, `enrollment_closed`, `enrollment_store_lost`,
  `directory_unavailable`, `store_unavailable`; every outcome at 0 from the first scrape.
  `port49_directory_enrollment_store_ok`: 1 when the enrollment store opened with its mark, 0 when
  it is lost (D7), absent without a `directory_password` verifier. No principal, no source.
- **20. The lab.** L67.
```

  Write each `<…>` as the ruling's full text from this plan's "Decisions for the controller" and
  "Rulings this plan makes", as the controller and Ryan ruled them (the "Pre-flight 2026-10-14"
  section's controller rulings already folded into them), with the alternatives dropped; the dates
  are those rulings'.

- [ ] **Step 8: §14.** After the "**Host keys (decision 46)**" block add:

```markdown
**Directory sign-in (decision 47)**

- **The code before the password**: a wrong code never reaches the directory; a right code and a
  wrong password are one refusal to the caller.
- **Never the empty password**: refused before any dial, by the client and the broker.
- **A step once**: a code accepted is refused again, on this replica or another; the step is taken
  before the password is tried.
- **Counted before judged**: parallel attempts never pass the limit; a store error refuses.
- **Never "not enrolled" by mistake**: a second-factor record that will not open refuses the
  sign-in; a record of another entry refuses it.
- **A lost store never reopens enrollment**: an enrollment store with no creation mark (its file
  or key missing, a new install not yet initialised included), or that will not unseal, refuses
  every password sign-in, 503 `enrollment_store_lost`, until `init-enrollments` (a new install),
  `import`, or `reset-second-factor --all` runs; nothing creates it at start; every other path
  serves.
- **No password outside a window**: a person with no second factor and no window open is refused
  `enrollment_closed` before any bind.
- **The directory down**: a sign-in says so, 503; a held certificate mints within grace.
- **A refused password is not a fault**: it moves no breaker and no hold-off.
- **Never logged**: no record, line or error holds the password, the code, the secret, the URI, the
  handle or an unmapped name.
```

- [ ] **Step 9: §15, L67.** After L66's row add:

```markdown
| **L67** | A person's simple bind from port49-broker, per directory, over LDAPS and over StartTLS (`start_tls: true`): (a) the right password accepted, a wrong one refused with which result code and, on AD, which `data` code; (b) a DN with an empty password sent by a raw client (not port49): whether the server answers success (an unauthenticated bind, RFC 4513 §5.1.2), and the control: `port49 login --directory` with an empty password sends no bind (capture); (c) with the right password, an expired password, a must-change password, a disabled account and a locked account (AD `pwdLastSet`, `userAccountControl`, a lockout; OpenLDAP's `ppolicy`), the result and data code or `ppolicy` error each gives, and whether a wrong password gives the same; (d) with the directory's lockout at 10 failures in 10 minutes, six wrong sign-ins by port49's defaults: the account's failed count after them (`badPwdCount`; `pwdFailureTime`), and the sixth refused by port49 with no bind on the wire; and nine wrong passwords straddling a window boundary (four before it ends, five after): the account's failed count, and whether it locked; (e) a wrong code: no bind for the person on the wire; (f) whether the broker's own bind reads the entry's creation time (`whenCreated`; `createTimestamp`); (g) end to end, once on the compose stack's broker on etcd and once on port49d on the memory store (the sealed file): before `port49 directory init-enrollments` a sign-in is refused `enrollment_store_lost`; after it `bin/port49 login --directory` enrolls, confirms, gets a certificate and mints for a device of the loopback inventory; with the directory stopped, the held certificate mints and a sign-in says the directory did not answer. | §13 decision 47 rulings 6, 7, D2, D5 | OpenLDAP (slapd 2.5, `ppolicy`), Samba AD (4.17), Windows Server AD (Windows Server 2025, the SER8) | open — added by plan 9e 2026-10-14 |
```

- [ ] **Step 10: Design §7.** "Two supported paths, both first class." becomes "Three supported paths,
  all first class." After the OIDC path's bullets (the paragraph ending "people holding a
  certificate keep working until it ends.") add:

```markdown
**A directory password and a second factor** (plan 9e; policy engine spec §13 decision 47), for a
company with neither a PKI nor an identity provider. `port49 login --directory` sends the person's
directory password and a TOTP code to the broker over its TLS; the broker checks the code, then the
password by one bind as the person's entry over LDAPS or StartTLS, and issues the same certificate
as the OIDC path, so the session is the certificate path's from there. The TOTP secret is enrolled
at the person's first sign-in inside a window (a rollout date, the first 14 days of a new entry, or
an operator's reset), and kept sealed in the broker's enrollment store (a sealed file on the
memory store, or etcd), which an operator creates once per install and which, lost, refuses
password sign-in rather than reopen enrollment. Attempts are limited per person and per source
address, counted before they are judged.
```

  Replace "Service accounts therefore never authenticate with a directory password; port49 has no
  password path at all." with "Service accounts therefore never authenticate with a directory
  password. port49's one password path is a person's directory-password sign-in (plan 9e): the
  password reaches the broker once per sign-in, is bound once to check it, and is never stored,
  logged or a device credential; a workload's entry is refused there, and the verifier's `filter`
  keeps a person-shaped service account out."

- [ ] **Step 11: Design §10.** After "It never binds as the user — … a self-asserted claim." add: "The
  one exception is a person's directory-password sign-in (plan 9e): the broker binds once as the
  person's entry, on a connection of its own, to check the password, and closes it. Groups are still
  read as the broker. A password the directory refuses is not a server fault: it opens no breaker
  and starts no hold-off."

- [ ] **Step 12: Design §12 and §17.** In the "Directory unavailable" row's "New session" cell add:
  "A directory-password sign-in is refused 503 `directory_unavailable` at once, with no grace (a
  password is never kept); a certificate already issued keeps working." After that row add one:
  "**Enrollment store lost** (plan 9e) | password sign-in refused 503 `enrollment_store_lost`,
  `port49_directory_enrollment_store_ok` 0 | held certificates, tokens, IdP sign-in serve | on a
  new install `port49 directory init-enrollments`; otherwise restore the file or snapshot
  (`port49 directory import`), or `port49 directory reset-second-factor --all`". In §17's surface
  add:

```
POST  /v1/sign-in         a person's directory name, password, TOTP code and CSR, no client certificate: a certificate, or an enrollment (plan 9e)
POST  /v1/sign-in/confirm an enrollment's handle, its first TOTP code and a CSR: a certificate (plan 9e)
```

  and in the errors:

```
404  not_signing_in                   /v1/sign-in: this broker has no directory_password verifier (plan 9e)
401  sign_in_refused                  /v1/sign-in: the name, password or code was not accepted; one code for the three (plan 9e)
429  sign_in_throttled                /v1/sign-in: too many failed attempts for the principal or the source in the window; Retry-After (plan 9e)
403  enrollment_closed                /v1/sign-in: no second factor, and no enrollment window open for this person; the password was not checked (plan 9e)
503  directory_unavailable            /v1/sign-in: no directory server answered; nothing is cached for a password (plan 9e)
503  enrollment_store_lost            /v1/sign-in: the enrollment store is lost or not yet initialised; nothing was checked (plan 9e)
```

- [ ] **Step 13: Check and commit.**

Run: `grep -n 'decision 47' docs/design/2026-08-23-policy-engine-spec.md | head; grep -n '<as made>\|<R[0-9]*>\|<date>\|<the ruling' docs/design/2026-08-23-policy-engine-spec.md`
Expected: decision 47 present in §5.7, §12, §13, §14, §15; the second grep prints nothing.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: decision 47, a directory-password sign-in, and L67

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: TOTP over pquerna/otp, and the QR code on a terminal

**Files:**
- Create: `internal/totp/totp.go`, `internal/totp/totp_test.go`
- Create: `cmd/port49/qr.go`, `cmd/port49/qr_test.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Produces:

```go
package totp

const (
	Digits     = 6
	Period     = 30 * time.Second
	SecretSize = 20 // bytes; RFC 4226 §4 recommends 160 bits
	Window     = 1  // steps either side accepted (RFC 6238 §5.2)
	SkewReach  = 10 // steps either side a code is looked for, to say a clock is off
)

var (
	ErrWrongCode = errors.New("totp: the code is not accepted")
	ErrReplayed  = errors.New("totp: the code's time step was taken already")
)

// Skewed is a code that matched a step outside Window but within
// SkewReach: refused, and By says how far the authenticator's clock is.
type Skewed struct{ By time.Duration }

func (s *Skewed) Error() string

func NewSecret() ([]byte, error)
func URI(secret []byte, label, account string) string
// DecodeSecret is the secret a URI's secret parameter carries (RFC 4648
// base32, upper case, no padding).
func DecodeSecret(s string) ([]byte, error)
// Code is secret's code at at (one GenerateCodeCustom call); for tests,
// the CLI test and the lab, which play the authenticator.
func Code(secret []byte, at time.Time) (string, error)
func Check(secret []byte, code string, now time.Time, lastStep int64) (int64, error)
```

```go
// cmd/port49/qr.go
func qrText(s string) (string, error)
```

- [ ] **Step 1: Add the module.**

Run: `go get github.com/pquerna/otp@v1.5.0 && go mod tidy && grep -n 'pquerna\|boombuler' go.mod`
Expected: `github.com/pquerna/otp v1.5.0` and `github.com/boombuler/barcode v…` in `go.mod`.
Record both versions for the commit message.

- [ ] **Step 2: Write the failing tests** in `internal/totp/totp_test.go`:

```go
package totp

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA-1, the last 6 of each 8-digit value.
var rfcSecret = []byte("12345678901234567890")

func TestRFC6238Vectors(t *testing.T) {
	for _, v := range []struct {
		at   int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"},
		{2000000000, "279037"}, {20000000000, "353130"}} {
		step, err := Check(rfcSecret, v.code, time.Unix(v.at, 0), 0)
		if err != nil || step != v.at/30 {
			t.Errorf("at %d: step %d, %v", v.at, step, err)
		}
	}
}

func TestOneStepEitherSideIsAccepted(t *testing.T) {
	at := time.Unix(1111111111, 0)
	for _, d := range []time.Duration{-Period, Period} {
		if _, err := Check(rfcSecret, "050471", at.Add(d), 0); err != nil {
			t.Errorf("%s away: %v", d, err)
		}
	}
}

func TestThreeStepsAwayIsSaidAsSkew(t *testing.T) {
	_, err := Check(rfcSecret, "050471", time.Unix(1111111111, 0).Add(3*Period), 0)
	var s *Skewed
	if !errors.As(err, &s) || s.By != -3*Period {
		t.Fatalf("%v", err)
	}
}

func TestAStepIsTakenOnce(t *testing.T) {
	at := time.Unix(1111111111, 0)
	step, err := Check(rfcSecret, "050471", at, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(rfcSecret, "050471", at, step); !errors.Is(err, ErrReplayed) {
		t.Fatalf("a step taken twice: %v", err)
	}
	// An earlier step than the last taken is refused too.
	if _, err := Check(rfcSecret, "081804", time.Unix(1111111109, 0), step); !errors.Is(err, ErrReplayed) {
		t.Fatalf("an earlier step: %v", err)
	}
}

func TestMalformedCodesAreWrong(t *testing.T) {
	for _, c := range []string{"", "05047", "0504710", "05047a", " 050471", "０５０４７１"} {
		if _, err := Check(rfcSecret, c, time.Unix(1111111111, 0), 0); !errors.Is(err, ErrWrongCode) {
			t.Errorf("%q: %v", c, err)
		}
	}
}

func TestNewSecretIsRandomAndSized(t *testing.T) {
	a, _ := NewSecret()
	b, _ := NewSecret()
	if len(a) != SecretSize || string(a) == string(b) {
		t.Fatal("not 20 random bytes")
	}
}

func TestTheURIIsWhatAuthenticatorsRead(t *testing.T) {
	u, err := url.Parse(URI(rfcSecret, "port49 (broker.example.com)", "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || !strings.HasPrefix(u.Path, "/port49 (broker.example.com):alice@example.com") ||
		q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || q.Get("issuer") != "port49 (broker.example.com)" ||
		q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Fatalf("%s", u)
	}
	if s, err := DecodeSecret(q.Get("secret")); err != nil || string(s) != string(rfcSecret) {
		t.Fatalf("the URI's secret does not decode back: %v", err)
	}
}

// Code is what an authenticator shows: the RFC's vector, and what Check takes.
func TestCodeIsTheAuthenticators(t *testing.T) {
	at := time.Unix(1111111111, 0)
	c, err := Code(rfcSecret, at)
	if err != nil || c != "050471" {
		t.Fatalf("%q %v", c, err)
	}
	if _, err := Check(rfcSecret, c, at, 0); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail.**

Run: `go test ./internal/totp/`
Expected: FAIL (`undefined: Check`).

- [ ] **Step 4: Implement** `internal/totp/totp.go`:

```go
// Package totp is a person's second factor at a directory-password sign-in
// (spec §13 decision 47): RFC 6238 codes as every authenticator app reads an
// otpauth URI, generated by github.com/pquerna/otp. The policy around them
// is port49's: the window, a step taken once, a constant-time comparison,
// and a clock said to be off.
package totp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	Digits     = 6
	Period     = 30 * time.Second
	SecretSize = 20
	Window     = 1
	SkewReach  = 10
)

var (
	ErrWrongCode = errors.New("totp: the code is not accepted")
	ErrReplayed  = errors.New("totp: the code's time step was taken already")
)

// Skewed is a code that matched a step outside Window but within SkewReach.
type Skewed struct{ By time.Duration }

func (s *Skewed) Error() string {
	return fmt.Sprintf("totp: the code is for a time %s from now", s.By)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var opts = totp.ValidateOpts{Period: uint(Period / time.Second), Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// NewSecret is SecretSize random bytes.
func NewSecret() ([]byte, error) {
	s := make([]byte, SecretSize)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// URI is the Key URI Format otpauth://totp/LABEL:ACCOUNT?… that
// authenticator apps scan.
func URI(secret []byte, label, account string) string {
	q := url.Values{"secret": {b32.EncodeToString(secret)}, "issuer": {label}, "algorithm": {"SHA1"},
		"digits": {strconv.Itoa(Digits)}, "period": {strconv.Itoa(int(Period / time.Second))}}
	return (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + label + ":" + account, RawQuery: q.Encode()}).String()
}

// DecodeSecret is the secret a URI's secret parameter carries.
func DecodeSecret(s string) ([]byte, error) { return b32.DecodeString(s) }

// Code is secret's code at at, as an authenticator shows it.
func Code(secret []byte, at time.Time) (string, error) {
	return totp.GenerateCodeCustom(b32.EncodeToString(secret), at, opts)
}

// Check is the step code matches at now: within Window of now, after
// lastStep (0: none taken). A code matching only further away, up to
// SkewReach, is *Skewed; none, ErrWrongCode; a step at or before lastStep,
// ErrReplayed.
func Check(secret []byte, code string, now time.Time, lastStep int64) (int64, error) {
	if len(code) != Digits {
		return 0, ErrWrongCode
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return 0, ErrWrongCode
		}
	}
	key := b32.EncodeToString(secret)
	period := int64(Period / time.Second)
	at := now.Unix() / period
	var found bool
	var step, off int64
	for d := int64(-SkewReach); d <= SkewReach; d++ {
		want, err := totp.GenerateCodeCustom(key, time.Unix((at+d)*period, 0), opts)
		if err != nil {
			return 0, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && (!found || abs(d) < abs(off)) {
			found, step, off = true, at+d, d
		}
	}
	switch {
	case !found:
		return 0, ErrWrongCode
	case off < -Window || off > Window:
		return 0, &Skewed{By: time.Duration(off) * Period}
	case step <= lastStep:
		return 0, ErrReplayed
	}
	return step, nil
}

func abs(d int64) int64 {
	if d < 0 {
		return -d
	}
	return d
}
```

  `Skewed.By` is the authenticator's clock against the broker's, negative when it is behind: a code
  that matches step `at+d` was generated by a clock `d` periods off, so `By = d × Period`. The test
  above checks a broker 3 periods after the code's time (the authenticator 3 periods behind):
  `By == -3 × Period`. Give `Skewed`'s doc comment that sentence.

- [ ] **Step 5: Run the tests to verify they pass.**

Run: `go test ./internal/totp/ -v`
Expected: PASS, every vector.

- [ ] **Step 6: Write the failing QR test** in `cmd/port49/qr_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

// The code is drawn two modules a character, with a four-module quiet zone,
// and the same input draws the same lines.
func TestQRTextIsSquareWithAQuietZone(t *testing.T) {
	uri := "otpauth://totp/port49:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	a, err := qrText(uri)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := qrText(uri)
	lines := strings.Split(strings.TrimRight(a, "\n"), "\n")
	w := len([]rune(lines[0]))
	if a != b || w < 29 || len(lines) != (w+1)/2 {
		t.Fatalf("width %d, %d lines", w, len(lines))
	}
	for _, l := range lines {
		if len([]rune(l)) != w {
			t.Fatal("ragged")
		}
	}
	// The quiet zone: the first two lines are light (spaces) in full.
	if strings.TrimSpace(lines[0]) != "" || strings.TrimSpace(lines[1]) != "" {
		t.Fatal("no quiet zone")
	}
}
```

- [ ] **Step 7: Implement** `cmd/port49/qr.go`:

```go
package main

import (
	"strings"

	"github.com/boombuler/barcode/qr"
)

// qrText draws s as a QR code for a terminal: two modules a character
// (the upper and lower half blocks), dark modules as blocks on the
// terminal's own background, with a quiet zone of four modules (ISO/IEC
// 18004). It is printed on the person's terminal alone (decision 47 ruling 15).
func qrText(s string) (string, error) {
	code, err := qr.Encode(s, qr.M, qr.Auto)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := code.Bounds().Dx()
	size := n + 2*quiet
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		if x < 0 || y < 0 || x >= n || y >= n {
			return false
		}
		r, _, _, _ := code.At(x, y).RGBA()
		return r == 0
	}
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		for x := 0; x < size; x++ {
			switch top, bottom := dark(x, y), dark(x, y+1); {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
```

  A terminal with a dark background inverts it, and authenticator apps read inverted codes (iOS and
  Android both do; L67 cell (g) has a person scan it on a phone and records which app read it).

- [ ] **Step 8: Run and verify.**

Run: `go test ./internal/totp/ ./cmd/port49/ -run 'TestRFC|TestOne|TestThree|TestAStep|TestMalformed|TestNewSecret|TestTheURI|TestCode|TestQRText' -v && make check-static`
Expected: PASS; the static build still static.

- [ ] **Step 9: Commit.**

```bash
git add go.mod go.sum internal/totp cmd/port49/qr.go cmd/port49/qr_test.go
git commit -m "feat: TOTP codes over pquerna/otp, and the enrollment's QR code

New modules: github.com/pquerna/otp v1.5.0 (Apache-2.0) and
github.com/boombuler/barcode <version> (MIT), pure Go (decision 47 D9).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Reasons, events, record blocks and the metric

**Files:**
- Modify: `internal/decision/reasons.go`, `internal/decision/log.go`,
  `internal/daemon/metrics/metrics.go`
- Test: `internal/decision/reasons_test.go`, `internal/decision/log_test.go`,
  `internal/daemon/metrics/metrics_test.go`

**Interfaces:**
- Produces:

```go
// reasons.go
SignInRefused        Reason = "sign_in_refused"
SignInThrottled      Reason = "sign_in_throttled"
EnrollmentClosed     Reason = "enrollment_closed"
EnrollmentStoreLost  Reason = "enrollment_store_lost"
SecondFactorEnrolled Reason = "second_factor_enrolled"

const EventEnroll = "enroll"
// report events
EventSecondFactorReset = "second_factor_reset"
EventSignInUnlock      = "sign_in_unlock"
EventEnrollmentsImport = "enrollments_import"

// log.go
type DirectoryPassword struct {
	AMR         []string `json:"amr"`
	AuthTime    string   `json:"auth_time"`
	EntrySHA256 string   `json:"entry_sha256"`
}
// Auth gains: DirectoryPassword *DirectoryPassword `json:"directory_password,omitempty"`
type SignIn struct {
	Source          string `json:"source"`
	Failed          string `json:"failed,omitempty"`
	SkewSeconds     int    `json:"skew_seconds,omitempty"`
	DirectoryResult int    `json:"directory_result,omitempty"`
	DirectoryData   string `json:"directory_data,omitempty"`
}
type SecondFactorReset struct {
	EnrolledAt   string `json:"enrolled_at,omitempty"`
	EnrolledFrom string `json:"enrolled_from,omitempty"`
	ReopenUntil  string `json:"reopen_until,omitempty"` // absent on created
	All          bool   `json:"all,omitempty"`          // reset-second-factor --all
	Created      bool   `json:"created,omitempty"`      // init-enrollments (D7)
	Origin       string `json:"origin"`
}
type SignInUnlock struct {
	Failures int    `json:"failures"`
	Origin   string `json:"origin"`
}
type EnrollmentsImport struct {
	Records    int    `json:"records"`
	ExportedAt string `json:"exported_at"`
	Replaced   bool   `json:"replaced,omitempty"`
	Origin     string `json:"origin"`
}
// Record gains: SignIn *SignIn `json:"sign_in,omitempty"`,
//   SecondFactorReset *SecondFactorReset `json:"second_factor_reset,omitempty"`,
//   SignInUnlock *SignInUnlock `json:"sign_in_unlock,omitempty"`,
//   EnrollmentsImport *EnrollmentsImport `json:"enrollments_import,omitempty"`

// metrics.go
SignIns *prometheus.CounterVec // port49_sign_ins_total{outcome}
// DirectoryEnrollmentStoreOK is port49_directory_enrollment_store_ok, a
// vector with no labels so that it is absent until the broker checks the
// store (WithLabelValues().Set(1 or 0)); testutil.ToFloat64 reads it then.
DirectoryEnrollmentStoreOK *prometheus.GaugeVec
```

- [ ] **Step 1: Write the failing tests.** In `internal/decision/reasons_test.go` add:

```go
func TestTheSignInReasonsAreKnown(t *testing.T) {
	for _, r := range []Reason{SignInRefused, SignInThrottled, EnrollmentClosed, EnrollmentStoreLost, SecondFactorEnrolled} {
		if !Known(r) {
			t.Errorf("%s is not in the vocabulary", r)
		}
	}
}
```

  In `internal/decision/log_test.go` add a test that marshals a `Record{Event: EventIssue, Auth:
  &Auth{Method: "cert", DirectoryPassword: &DirectoryPassword{AMR: []string{"pwd", "otp"}, AuthTime:
  "2026-10-14T00:00:00Z", EntrySHA256: "ab"}}, SignIn: &SignIn{Source: "192.0.2.0/32", Failed:
  "second_factor_skew", SkewSeconds: -90}}` and checks the JSON holds
  `"directory_password":{"amr":["pwd","otp"],"auth_time":"2026-10-14T00:00:00Z","entry_sha256":"ab"}`
  and `"sign_in":{"source":"192.0.2.0/32","failed":"second_factor_skew","skew_seconds":-90}`, and that
  a `SignIn` with only `Source` marshals to `{"source":"192.0.2.0/32"}`. In the same test, a
  `SecondFactorReset{Created: true, Origin: "admin_socket uid 0"}` marshals to
  `{"created":true,"origin":"admin_socket uid 0"}` (no `reopen_until`, no `all`).

  In `internal/daemon/metrics/metrics_test.go` add:

```go
func TestEverySignInOutcomeExistsAtZero(t *testing.T) {
	m := New(prometheus.NewRegistry())
	for _, o := range []string{"issued", "refused", "throttled", "enrollment_started", "enrolled",
		"enrollment_closed", "enrollment_store_lost", "directory_unavailable", "store_unavailable"} {
		if v := testutil.ToFloat64(m.SignIns.WithLabelValues(o)); v != 0 {
			t.Errorf("%s: %v", o, v)
		}
	}
	if n := testutil.CollectAndCount(m.SignIns); n != 9 {
		t.Fatalf("%d series; every outcome from the first scrape", n)
	}
}

// The gauge is not set at construction: it is absent without a
// directory_password verifier, and port49d sets it once the store is checked.
func TestTheEnrollmentStoreGaugeIsNotSetAtConstruction(t *testing.T) {
	reg := prometheus.NewRegistry()
	_ = New(reg)
	if n, err := testutil.GatherAndCount(reg, "port49_directory_enrollment_store_ok"); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
}
```

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./internal/decision/ ./internal/daemon/metrics/`
Expected: FAIL (`undefined: SignInRefused`, `m.SignIns undefined`).

- [ ] **Step 3: Implement.** In `reasons.go`, after `PerLoginMFAUnavailable`:

```go
	// The directory-password sign-in (spec §5.7; §13 decision 47).
	// SignInRefused: the name, password or code was not accepted, one reason
	// to the caller for the three. SignInThrottled: the principal's or the
	// source's failed attempts reached the limit, nothing checked.
	// EnrollmentClosed: no second factor and no window open. A permit on the
	// enroll event, SecondFactorEnrolled.
	SignInRefused        Reason = "sign_in_refused"
	SignInThrottled      Reason = "sign_in_throttled"
	EnrollmentClosed     Reason = "enrollment_closed"
	// EnrollmentStoreLost: the enrollment store has no creation mark or
	// will not unseal (decision 47 D7); password sign-in alone is refused.
	EnrollmentStoreLost  Reason = "enrollment_store_lost"
	SecondFactorEnrolled Reason = "second_factor_enrolled"
```

  Add the five to `reasons`. Add `EventEnroll` with a comment as `EventPerLoginMFA` has, and
  `EventSecondFactorReset`, `EventSignInUnlock`, `EventEnrollmentsImport` beside
  `EventDirectoryForget` ("not a decision: …").
  In `log.go`, add the types above with doc comments (the `SignIn` comment: "never the name typed,
  the password, the code or the secret") and the fields on `Auth` and `Record`. In `metrics.go` add
  `SignIns` beside `CertificatesIssued`:

```go
		SignIns: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_sign_ins_total",
			Help: "Directory-password sign-ins by outcome: issued, refused, throttled, enrollment_started, " +
				"enrolled, enrollment_closed, enrollment_store_lost, directory_unavailable, store_unavailable; " +
				"alert on a rise of throttled, on any enrollment_store_lost, and on enrolled outside a rollout."},
			[]string{"outcome"}),
		DirectoryEnrollmentStoreOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "port49_directory_enrollment_store_ok",
			Help: "1 when the broker's enrollment store opened with its creation mark, 0 when it is lost " +
				"or not yet initialised and password sign-in is refused (decision 47 D7); absent without a " +
				"directory_password verifier. Alert on 0."}, nil),
```

  register both in the `MustRegister` list after `m.CertificatesIssued`, and pre-create every
  `SignIns` outcome as `CertificatesIssued`'s are. The gauge is not set here.

- [ ] **Step 4: Run to verify they pass.**

Run: `go test ./internal/decision/ ./internal/daemon/metrics/ -v -run 'SignIn|Vocabulary|Reasons|EnrollmentStore'`
Expected: PASS, and the existing completeness test of `reasons` still passes.

- [ ] **Step 5: Commit.**

```bash
git add internal/decision internal/daemon/metrics
git commit -m "feat: the sign-in reasons, the enroll event and port49_sign_ins_total

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: The stores — attempt counts (regional) and the enrollment store (D7, D12, D13)

**Files:**
- Modify: `internal/store/store.go` (the three attempt methods on `Store`; the `Enrollments`
  interface and its types; `ErrEnrollmentStoreLost`)
- Modify: `internal/store/memory/memory.go` (attempts; `NewEnrollments`, an in-memory
  `Enrollments` for tests)
- Create: `internal/store/enrollfile/enrollfile.go`, `internal/store/enrollfile/enrollfile_test.go`
  (the sealed file, D7)
- Create: `internal/store/etcd/signin.go` (attempts and `Enrollments` on etcd); modify
  `internal/store/etcd/keys.go` (`sf/`, `sa/`, `meta/enrollments`), `internal/store/etcd/roles.go`
  (`daemonNever`, the probes)
- Modify: `internal/store/crypt/crypt.go` (`WrapEnrollments`: the secret, entry id and source
  sealed, bound to the principal; `Stale`; the attempt methods passed through `Wrap`)
- Modify: `internal/store/guard/guard.go` (the attempt methods in `Token`; `guard.WrapEnrollments`)
- Create: `internal/store/storetest/signin.go`, `internal/store/storetest/enrollments.go`; modify
  `internal/store/storetest/storetest.go` (register the attempt properties; `RunEnrollments`)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore` gains the three attempt methods)
- Test: `internal/store/crypt/crypt_test.go`, `internal/store/etcd/roles_test.go`,
  `internal/store/enrollfile/enrollfile_test.go`

**Interfaces:**
- Produces:

```go
// internal/store/store.go

// On Store (regional; plan 9e, D12): a sign-in's attempt counts.
// NoteSignInAttempt counts one attempt under key in a fixed window that
// starts at the first, and returns the count with it and the window's end.
NoteSignInAttempt(ctx context.Context, key string, window time.Duration) (int, time.Time, error)
// UndoSignInAttempt takes one back (never below 0); ClearSignInAttempts
// drops the count and returns what it held.
UndoSignInAttempt(ctx context.Context, key string) error
ClearSignInAttempts(ctx context.Context, key string) (int, error)

// SecondFactor is a person's TOTP second factor (plan 9e; spec §13 decision
// 47 rulings 4, 11, 12). Secret, EntryID and EnrolledFrom are sealed.
// LastStep is the used-step record (D12): it lives with the enrollment.
type SecondFactor struct {
	Principal    string
	State        string // SecondFactorPending | SecondFactorActive | SecondFactorReopened
	EntryID      string
	Secret       []byte
	EnrolledAt   time.Time
	EnrolledFrom string
	LastStep     int64
	Until        time.Time // a pending record's confirm-by, or a reopened record's end
	Rev          uint64    // set by GetSecondFactor, compared by SwapSecondFactor
	Sealed       []byte
	Stale        bool // opened under the previous encryption key: the scheduled pass seals it again
}

const (
	SecondFactorPending  = "pending"
	SecondFactorActive   = "active"
	SecondFactorReopened = "reopened"
)

// EnrollmentMark is the enrollment store's creation mark (D7): its absence
// is a lost store, never "no one is enrolled". ReopenAllUntil is
// reset-second-factor --all's window.
type EnrollmentMark struct {
	CreatedAt      time.Time
	ReopenAllUntil time.Time
}

// ErrEnrollmentStoreLost is an enrollment store that will not open (D7): a
// file that does not unseal or does not load. Every method answers it,
// wrapped with why, until PutEnrollmentMark replaces the store.
var ErrEnrollmentStoreLost = errors.New("store: the enrollment store is lost")

// Enrollments is the enrollment store (plan 9e, D7, D12): its own handle,
// opened from broker.directory.enrollment_store. Nothing creates it at a
// start; CreateEnrollmentMark (init-enrollments), PutEnrollmentMark
// (reset-second-factor --all) and Import are the only writers of the mark.
type Enrollments interface {
	GetSecondFactor(ctx context.Context, principal string) (SecondFactor, error) // ErrNotFound
	// SwapSecondFactor writes f if the record is still at rev (0: none
	// there); ErrConflict otherwise, and nothing is written. No lease.
	SwapSecondFactor(ctx context.Context, f SecondFactor, rev uint64) error
	SecondFactorPrincipals(ctx context.Context) ([]string, error)
	GetEnrollmentMark(ctx context.Context) (EnrollmentMark, error) // ErrNotFound when none
	// CreateEnrollmentMark writes m only where the store has no mark, no
	// record and (the file) no file, lost or not; ErrConflict otherwise,
	// and nothing is written (init-enrollments, D7).
	CreateEnrollmentMark(ctx context.Context, m EnrollmentMark) error
	// PutEnrollmentMark writes m, creating the store when it has none, and
	// replacing a lost one (the unreadable file renamed aside, never deleted).
	PutEnrollmentMark(ctx context.Context, m EnrollmentMark) error
	// Export is every record and the mark, sealed (D13), stamped with the
	// time it was taken; Import checks the seal and the mark and writes
	// them, refusing a store holding a record enrolled or reset after the
	// export unless replace (ErrConflict), and returns how many records it
	// wrote and the export's time.
	Export(ctx context.Context) ([]byte, error)
	Import(ctx context.Context, sealed []byte, replace bool) (int, time.Time, error)
}
```

```go
// internal/store/enrollfile
// Open reads path (D7). A missing file is an empty store with no mark
// (which the broker reads as lost until init-enrollments); a file that does
// not open is a lost store (every method: store.ErrEnrollmentStoreLost). It
// refuses a directory others can write (fence.CheckDir) and a link at path
// (fence.ReadNoLink). It never creates the file.
func Open(path string, keys crypt.Keys, now func() time.Time) (*File, error)
// File is store.Enrollments; Lost is why it is lost, "" when it is not.
func (f *File) Lost() string
```

```go
// internal/store/memory
func NewEnrollments(now func() time.Time) store.Enrollments

// internal/store/crypt
func WrapEnrollments(inner store.Enrollments, k Keys, openFailures *prometheus.CounterVec, opts ...Option) store.Enrollments

// internal/store/guard
func WrapEnrollments(inner store.Enrollments, c Config) store.Enrollments
```

- [ ] **Step 1: Write the failing properties.** The attempt counts, in
  `internal/store/storetest/signin.go`:

```go
package storetest

import (
	"context"
	"sync"
	"testing"
	"time"
)
```

  with `SignInAttemptsCountInAFixedWindow` and `SignInAttemptsCountEveryRacer` as written at the
  end of this step, registered in `Run` beside `MFAProofKeepsTheLaterAndExpires`.
  The enrollment store, in `internal/store/storetest/enrollments.go`:

```go
package storetest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// EnrollmentsBackend is a store.Enrollments implementation the enrollment
// properties run against; New returns a fresh, empty one. Sealed says its
// Export is sealed (the crypt layer over it), so the clear-text check runs.
type EnrollmentsBackend struct {
	New    func(t *testing.T, clock func() time.Time) store.Enrollments
	Sealed bool
}

// RunEnrollments runs every enrollment property against b.
func RunEnrollments(t *testing.T, b EnrollmentsBackend) {
	for _, p := range []struct {
		name string
		f    func(*testing.T, EnrollmentsBackend)
	}{
		{"SecondFactorSwapsByRevision", SecondFactorSwapsByRevision},
		{"EnrollmentMarkIsKept", EnrollmentMarkIsKept},
		{"EnrollmentMarkIsCreatedOnce", EnrollmentMarkIsCreatedOnce},
		{"ExportImportRoundTrips", ExportImportRoundTrips},
	} {
		t.Run(p.name, func(t *testing.T) { p.f(t, b) })
	}
}

// EnrollmentMarkIsKept: none is ErrNotFound; a put reads back; a second
// put replaces it whole.
func EnrollmentMarkIsKept(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	e := b.New(t, func() time.Time { return t0 })
	if _, err := e.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a new store has a mark: %v", err)
	}
	m := store.EnrollmentMark{CreatedAt: t0}
	if err := e.PutEnrollmentMark(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got, err := e.GetEnrollmentMark(ctx); err != nil || !got.CreatedAt.Equal(t0) || !got.ReopenAllUntil.IsZero() {
		t.Fatalf("%+v %v", got, err)
	}
	m.ReopenAllUntil = t0.Add(24 * time.Hour)
	if err := e.PutEnrollmentMark(ctx, m); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.GetEnrollmentMark(ctx); !got.ReopenAllUntil.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("not replaced: %+v", got)
	}
}

// EnrollmentMarkIsCreatedOnce: CreateEnrollmentMark writes on an empty
// store alone; a second is ErrConflict and changes nothing; a store holding
// a record and no mark is ErrConflict too (init-enrollments never papers
// over a store that lost its mark, D7).
func EnrollmentMarkIsCreatedOnce(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	e := b.New(t, func() time.Time { return t0 })
	if err := e.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0.Add(time.Hour)}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second create: %v", err)
	}
	if got, _ := e.GetEnrollmentMark(ctx); !got.CreatedAt.Equal(t0) {
		t.Fatalf("the refused create wrote: %+v", got)
	}
	r := b.New(t, func() time.Time { return t0 })
	if err := r.SwapSecondFactor(ctx, store.SecondFactor{Principal: "user:alice@example.com",
		State: store.SecondFactorActive, EntryID: "uuid:1", Secret: []byte("01234567890123456789")}, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a create over records with no mark: %v", err)
	}
}

// ExportImportRoundTrips: an export imports into an empty store whole; into
// a store holding a later enrollment it is ErrConflict and writes nothing,
// unless replace (D13).
func ExportImportRoundTrips(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	src := b.New(t, clock)
	_ = src.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0})
	f := store.SecondFactor{Principal: "user:alice@example.com", State: store.SecondFactorActive, EntryID: "uuid:1",
		Secret: []byte("01234567890123456789"), EnrolledAt: t0, EnrolledFrom: "192.0.2.0/32", LastStep: 7}
	if err := src.SwapSecondFactor(ctx, f, 0); err != nil {
		t.Fatal(err)
	}
	exp, err := src.Export(ctx)
	if err != nil || b.Sealed && (strings.Contains(string(exp), "01234567890123456789") || strings.Contains(string(exp), "uuid:1")) {
		t.Fatalf("an export in the clear, or %v", err)
	}
	dst := b.New(t, clock)
	if n, at, err := dst.Import(ctx, exp, false); err != nil || n != 1 || !at.Equal(t0) {
		t.Fatalf("%d %s %v", n, at, err)
	}
	if got, err := dst.GetSecondFactor(ctx, f.Principal); err != nil || string(got.Secret) != string(f.Secret) ||
		got.LastStep != 7 {
		t.Fatalf("%+v %v", got, err)
	}
	mu.Lock()
	now = t0.Add(time.Hour)
	mu.Unlock()
	later := f
	later.Principal, later.EnrolledAt = "user:bob@example.com", t0.Add(time.Hour)
	if err := dst.SwapSecondFactor(ctx, later, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dst.Import(ctx, exp, false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("an older export over a later enrollment: %v", err)
	}
	if _, err := dst.GetSecondFactor(ctx, later.Principal); err != nil {
		t.Fatalf("the refused import wrote: %v", err)
	}
	if _, _, err := dst.Import(ctx, exp, true); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.GetSecondFactor(ctx, later.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("--replace kept a record the export does not hold: %v", err)
	}
}

// SecondFactorSwapsByRevision: a record is written only where none is, then
// only at the revision read; a stale revision writes nothing (plan 9e, Task 4).
func SecondFactorSwapsByRevision(t *testing.T, b EnrollmentsBackend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	const p = "user:alice@example.com"
	if _, err := s.GetSecondFactor(ctx, p); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("none written: %v", err)
	}
	f := store.SecondFactor{Principal: p, State: store.SecondFactorPending, EntryID: "uuid:1",
		Secret: []byte("01234567890123456789"), Until: t0.Add(10 * time.Minute)}
	if err := s.SwapSecondFactor(ctx, f, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapSecondFactor(ctx, f, 0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second first write: %v", err)
	}
	got, err := s.GetSecondFactor(ctx, p)
	if err != nil || got.State != store.SecondFactorPending || string(got.Secret) != string(f.Secret) ||
		got.EntryID != "uuid:1" || got.Rev == 0 {
		t.Fatalf("%+v %v", got, err)
	}
	active := got
	active.State, active.LastStep = store.SecondFactorActive, 42
	if err := s.SwapSecondFactor(ctx, active, got.Rev); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapSecondFactor(ctx, active, got.Rev); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a stale revision: %v", err)
	}
	if ps, err := s.SecondFactorPrincipals(ctx); err != nil || len(ps) != 1 || ps[0] != p {
		t.Fatalf("%v %v", ps, err)
	}
}
```

  The attempt properties, in `signin.go` after its imports:

```go
// SignInAttemptsCountInAFixedWindow: the window starts at the first attempt,
// a later attempt does not move its end, and past the end the count starts
// again; undo never goes below zero; clear returns what it held.
func SignInAttemptsCountInAFixedWindow(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	const k = "principal:user:alice@example.com"
	for i := 1; i <= 3; i++ {
		n, end, err := s.NoteSignInAttempt(ctx, k, 15*time.Minute)
		if err != nil || n != i || !end.Equal(t0.Add(15*time.Minute)) {
			t.Fatalf("attempt %d: %d %s %v", i, n, end, err)
		}
		mu.Lock()
		now = now.Add(time.Minute)
		mu.Unlock()
	}
	if err := s.UndoSignInAttempt(ctx, k); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ClearSignInAttempts(ctx, k); err != nil || n != 2 {
		t.Fatalf("cleared %d %v", n, err)
	}
	if err := s.UndoSignInAttempt(ctx, k); err != nil {
		t.Fatalf("undo with none: %v", err)
	}
	if n, _, _ := s.NoteSignInAttempt(ctx, k, 15*time.Minute); n != 1 {
		t.Fatalf("after clear: %d", n)
	}
	mu.Lock()
	now = now.Add(16 * time.Minute)
	mu.Unlock()
	if n, end, _ := s.NoteSignInAttempt(ctx, k, 15*time.Minute); n != 1 || !end.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("a new window: %d %s", n, end)
	}
}

// SignInAttemptsCountEveryRacer: fifty attempts at once are fifty counts,
// each racer told a distinct count (Review Focus 3).
func SignInAttemptsCountEveryRacer(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	const k = "source:192.0.2.0/32"
	var wg sync.WaitGroup
	seen := make(chan int, 50)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, _, err := s.NoteSignInAttempt(ctx, k, time.Minute)
			if err != nil {
				t.Error(err)
			}
			seen <- n
		}()
	}
	wg.Wait()
	close(seen)
	got := map[int]bool{}
	for n := range seen {
		if got[n] {
			t.Fatalf("two racers told %d", n)
		}
		got[n] = true
	}
	if len(got) != 50 || !got[50] {
		t.Fatalf("%d distinct counts", len(got))
	}
}
```

  Register `RunEnrollments` against: `memory.NewEnrollments` (`Sealed: false`);
  `crypt.WrapEnrollments(memory.NewEnrollments(...), keys, nil)` (`Sealed: true`); the file,
  `crypt.WrapEnrollments(enrollfile.Open(filepath.Join(t.TempDir(), "enrollments.json"), keys,
  clock), keys, nil)` (`Sealed: true`); and etcd and crypt-over-etcd beside the existing etcd
  backends (`Sealed` as the crypt layer is there or not).

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./internal/store/...`
Expected: FAIL to compile (`undefined: store.Enrollments`, `s.NoteSignInAttempt undefined`).

- [ ] **Step 3: The interface and memory.** Add the attempt methods to `store.Store`, and the
  types, `ErrEnrollmentStoreLost` and `Enrollments` to `store.go` (doc comments as above). In
  `memory.go`: `attempts map[string]memAttempts{n int; end time.Time}` under the store's mutex
  (`NoteSignInAttempt` starts a new window when none is live, `!now.Before(end)`); and
  `memory.NewEnrollments(now) store.Enrollments` (records and the mark in maps under one mutex,
  revisions from a counter, `SecondFactorPrincipals` sorted; `CreateEnrollmentMark` refuses with a
  mark or any record; `Export`/`Import` as JSON of the body below, unsealed, stamped `exported_at`
  from `now` — the sealing layer seals). `noStore` in `internal/daemon/authen/authen_test.go`
  gains the three attempt methods (panic, as its others).

- [ ] **Step 4: The sealed file (D7).** `internal/store/enrollfile/enrollfile.go`:

```go
// fileVersion is the envelope's port49_enrollments member.
const fileVersion = 1

// fileBound is the additional data the file's body is sealed under, so a
// sealed record of another kind is never read as this file.
var fileBound = []byte("enrollments_file")

type envelope struct {
	Version int    `json:"port49_enrollments"`
	KeyID   string `json:"key_id"`
	Sealed  []byte `json:"sealed"` // base64 in JSON
}

type body struct {
	CreatedAt      time.Time            `json:"created_at"`
	ReopenAllUntil time.Time            `json:"reopen_all_until,omitzero"`
	ExportedAt     time.Time            `json:"exported_at,omitzero"` // set in an export alone
	SecondFactors  map[string]recordOut `json:"second_factors"`
}

// recordOut is a SecondFactor as the file keeps it: the crypt layer's
// sealed part as it came, the rest in the clear inside the file's seal.
type recordOut struct {
	State      string    `json:"state"`
	EnrolledAt time.Time `json:"enrolled_at,omitzero"`
	LastStep   int64     `json:"last_step,omitempty"`
	Until      time.Time `json:"until,omitzero"`
	Rev        uint64    `json:"rev"`
	Sealed     []byte    `json:"sealed"`
}
```

  `Open`: `fence.CheckDir(filepath.Dir(path), "enrollments file")`; `fence.ReadNoLink(path,
  64<<20, "enrollments file")`; not there → empty, no mark (the broker reads that as lost, D7;
  `Open` never creates the file); does not decode, wrong version, or `keys.OpenBound` fails → lost,
  `Lost()` naming why (`crypt.SealedKeyID` of the sealed bytes when the key is unknown: "sealed
  under key id %q, which this broker does not hold: set encryption.previous to it, restore the
  file, or run `port49 directory reset-second-factor --all`"). Each write: marshal, `SealBound`
  under the current key, `inventory.WriteAtomic(dir, base, envelope, 0o600)`; on error nothing in
  memory changes and the error is returned (fail closed). A file holding records and no mark is
  still a store with no mark: the broker reads it as lost, and `CreateEnrollmentMark` refuses it
  (the broker never writes a record while the store is lost, since its sign-in path checks that
  first). A file opened under the previous key is written again under the current one at its
  next write. `CreateEnrollmentMark` refuses (`store.ErrConflict`) when a file is at `path`,
  readable or not, or a mark or record is held; otherwise writes a file holding only the mark.
  `PutEnrollmentMark` on a lost store renames the file to `enrollments.json.unreadable-<now UTC
  20060102T150405Z>` (`os.Rename`, never a delete), then writes a fresh file holding only the
  mark; on a store with no file it writes one. `Export` is the envelope of the body with
  `exported_at` set, sealed as the file is; `Import` opens an envelope under the held keys,
  refuses (`store.ErrConflict`) when not `replace` and any record here has `EnrolledAt`, or a
  reopened `Until − reopen`, later than the export's `exported_at`, and otherwise writes the
  imported body whole (replacing a lost file as `PutEnrollmentMark` does).
  `internal/store/enrollfile/enrollfile_test.go`, each a test:
  - `TestAMissingFileIsAnEmptyStoreWithNoMark` (and `Open` wrote nothing at `path`)
  - `TestTheFileReopensWithItsRecords` (create a mark, two records, `Open` again, both read back)
  - `TestATamperedFileIsLostNeverEmpty` (flip one byte of `sealed`: `Lost() != ""`, every method
    `errors.Is(err, store.ErrEnrollmentStoreLost)`, never `store.ErrNotFound`)
  - `TestAFileUnderAnUnknownKeyIsLost` (written under v2, opened with only a v0 key: lost, the line
    names `v2`)
  - `TestAFileUnderThePreviousKeyIsRewrittenUnderTheCurrent` (written under v1, opened with
    `keys()`'s `{Current: v2, Previous: v1}`: opens; after one write, `key_id` is `v2`)
  - `TestResetAllKeepsTheUnreadableFileAside` (a tampered file; `PutEnrollmentMark`: an
    `enrollments.json.unreadable-*` file exists holding the old bytes, and the new file opens)
  - `TestCreateRefusesAnyFileThere` (a tampered file: `CreateEnrollmentMark` is `ErrConflict`, and
    the file's bytes are unchanged; a missing file: created)
  - `TestAFailedWriteChangesNothing` (the directory made 0500 after open: a swap errors, and
    `GetSecondFactor` still answers the record before it)
  - `TestTheFileIsOwnerOnlyAndHoldsNoSecretInTheClear` (mode 0600; the bytes hold neither the
    secret nor the entry id)
  - `TestAGroupWritableDirectoryIsRefused` (`fence.CheckDir`'s refusal at `Open`)

  The test keys are `crypt_test.go`'s `keys()` shape, copied into this package's test file.

- [ ] **Step 5: etcd.** In `keys.go` add `famSecondFactor = "sf/" // sf/<principal>: a person's
  second factor (plan 9e), the broker's alone` and `famSignInAttempts = "sa/" // sa/<key>: a
  sign-in attempt count, the broker's alone`, with `secondFactor(principal)` and
  `signInAttempts(key)`; the mark is `k.meta("enrollments")` (not in `daemonMetaReads`, so the
  daemon is never granted it). In `roles.go` add both families to `daemonNever` and four probes
  (read and write each), as `famMFAProof`'s. In `signin.go`: the attempt methods as a `casAs` loop
  on `{n, end}` under a lease of the window (as `PutMFAProof`'s), starting a new window when the
  stored end has passed; `GetSecondFactor` reads the JSON record and sets `Rev` from
  `ModRevision`; `SwapSecondFactor` a transaction comparing `ModRevision` to `rev`
  (`CreateRevision == 0` for `rev == 0`), no lease; `SecondFactorPrincipals` a keys-only prefix
  read; `Get/PutEnrollmentMark` on `meta/enrollments`; `CreateEnrollmentMark` one transaction
  comparing `CreateRevision == 0` on the mark key and on the `sf/` prefix (`clientv3.Compare(...)
  .WithPrefix()`; confirm the range compare in the module cache, else read the prefix keys-only
  in the same revision and compare the mark's `CreateRevision` with `WithRev`); `Export` reads
  `sf/` and the mark in one revision (`clientv3.WithRev`) into the same body shape as the file's,
  unsealed, `exported_at` from the clock; `Import` deletes `sf/` and writes the body in
  transactions of at most `maxTxnOps`, the mark last. `*etcd.Store` satisfies both `store.Store`
  and `store.Enrollments`: the enrollment handle is a second `*etcd.Store` opened on the
  enrollment store's endpoints and prefix (D12), or the same one when it shares `store.etcd`.

- [ ] **Step 6: crypt.** `crypt.WrapEnrollments(inner store.Enrollments, k Keys, openFailures
  *prometheus.CounterVec, opts ...Option) store.Enrollments`:

```go
// secondFactorSecret is a second factor's sealed part, bound to its
// principal: the secret, the entry it was enrolled for, and where from.
type secondFactorSecret struct {
	Secret       []byte `json:"secret"`
	EntryID      string `json:"entry_id"`
	EnrolledFrom string `json:"enrolled_from"`
}

func secondFactorAAD(principal string) []byte { return []byte("second_factor\x00" + principal) }
```

  `SwapSecondFactor` seals those three with `k.SealBound(…, secondFactorAAD(f.Principal))` and
  passes the record on with them zeroed and `Sealed` set; `GetSecondFactor` opens with the
  principal asked for (a record copied under another principal fails), sets `Stale` when
  `SealedKeyID(f.Sealed)` is `k.Previous.ID` (with `k.Previous != nil`), and returns
  `w.openErr("second factor", f.Sealed, err)` — never `store.ErrNotFound` — for a record that will
  not open. `Export` seals the inner export with `k.SealBound(b, []byte("enrollments_export"))`
  into the envelope shape above; `Import` opens it (an export under a key this broker does not
  hold is refused naming its key id) and passes the body in. The mark methods and
  `SecondFactorPrincipals` pass through. `crypt.Wrap`'s store passes the three attempt methods
  through (their keys are a principal and a source prefix, their values counts).

- [ ] **Step 7: The guard.** The three attempt methods in the `Token` pool (map entries
  `"NoteSignInAttempt": Token, "UndoSignInAttempt": Token, "ClearSignInAttempts": Token`).
  `guard.WrapEnrollments(inner, c)` on the etcd enrollment handle: every method in `Token` but
  `SecondFactorPrincipals`, `Export` and `Import` in `Bulk`.

- [ ] **Step 8: Crypt's own tests** in `crypt_test.go`, with the file's `keys()` (v2 current, v1
  previous):

```go
// A second factor's secret, entry and source are sealed bound to the
// principal; under the previous key it opens Stale; under a key held by
// neither it is an error, never "not enrolled" (Review Focus 4).
func TestASecondFactorUnderAnUnknownKeyIsAnError(t *testing.T) {
	inner := memory.NewEnrollments(time.Now)
	k := keys() // Current v2, Previous v1
	old := Keys{Current: *k.Previous}
	ctx := context.Background()
	f := store.SecondFactor{Principal: "user:alice@example.com", State: store.SecondFactorActive,
		Secret: []byte("01234567890123456789"), EntryID: "uuid:1", EnrolledFrom: "192.0.2.0/32"}
	if err := WrapEnrollments(inner, old, nil).SwapSecondFactor(ctx, f, 0); err != nil {
		t.Fatal(err)
	}
	raw, _ := inner.GetSecondFactor(ctx, f.Principal)
	if len(raw.Secret) != 0 || raw.EntryID != "" || raw.EnrolledFrom != "" || len(raw.Sealed) == 0 {
		t.Fatalf("the backend holds the secret in the clear: %+v", raw)
	}
	got, err := WrapEnrollments(inner, k, nil).GetSecondFactor(ctx, f.Principal)
	if err != nil || !got.Stale || string(got.Secret) != string(f.Secret) || got.EntryID != "uuid:1" {
		t.Fatalf("under the previous key: %+v %v", got, err)
	}
	var c [32]byte
	copy(c[:], "cccccccccccccccccccccccccccccccc")
	failures := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "t"}, []string{"record"})
	_, err = WrapEnrollments(inner, Keys{Current: Key{ID: "v0", Bytes: c}}, failures).GetSecondFactor(ctx, f.Principal)
	if err == nil || errors.Is(err, store.ErrNotFound) || !errors.Is(err, ErrUnknownKey) ||
		testutil.ToFloat64(failures.WithLabelValues("second factor")) != 1 {
		t.Fatalf("a record under no held key read as %v", err)
	}
}

// A record sealed for one principal and copied by the backend under
// another does not open as that other.
func TestASecondFactorCopiedToAnotherPrincipalDoesNotOpen(t *testing.T) {
	inner := memory.NewEnrollments(time.Now)
	ctx := context.Background()
	w := WrapEnrollments(inner, keys(), nil)
	f := store.SecondFactor{Principal: "user:alice@example.com", State: store.SecondFactorActive,
		Secret: []byte("01234567890123456789"), EntryID: "uuid:1"}
	if err := w.SwapSecondFactor(ctx, f, 0); err != nil {
		t.Fatal(err)
	}
	raw, _ := inner.GetSecondFactor(ctx, f.Principal)
	raw.Principal = "user:mallory@example.com"
	if err := inner.SwapSecondFactor(ctx, raw, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := w.GetSecondFactor(ctx, "user:mallory@example.com"); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("alice's record opened as mallory's: %v", err)
	}
}
```

  (`openErr` counts under the record name it is given, `"second factor"`, as the existing tests'
  `failures` vectors read it.)

- [ ] **Step 9: Run every backend.**

Run: `go test ./internal/store/... ./internal/daemon/authen/ -race`
Expected: PASS for memory, crypt, the file, etcd (the embedded etcd test server),
crypt-over-etcd, and the roles test, which now probes `sf/` and `sa/`.

- [ ] **Step 10: Commit.**

```bash
git add internal/store internal/daemon/authen/authen_test.go
git commit -m "feat: sign-in attempt counts, and the enrollment store sealed on file or etcd

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Config — the `directory_password` verifier

**Files:**
- Modify: `internal/oidc/config.go` (`PasswordSignIn`, `Config.PasswordSignIn`)
- Modify: `internal/config/identity.go` (`identityVerifierYAML` fields, the `directory_password`
  case, `checkPasswordSignIn`, `checkIssuance`, the "accepts no one" check, the domain overlap)
- Modify: `internal/config/config.go` (the cross-checks: `broker.directory`; `enrollment_store`
  resolved; the enrollments file in the collision lists, M5)
- Modify: `internal/config/directory.go` (`certificate_mapping` optional without an x509 human
  verifier; `checkSearchShape` skips an empty mapping attribute; `enrollment_store`)
- Modify: `internal/directory/config.go` (`Config.EnrollmentStore` and the types below);
  `internal/port49d/directory.go` (`announceDirectory` with no mapping)
- Test: `internal/config/identity_test.go`, `internal/config/directory_test.go`

**Interfaces:**
- Produces:

```go
// internal/oidc/config.go
// PasswordSignIn is a type: directory_password human verifier resolved
// (plan 9e; spec §13 decision 47 ruling 18).
type PasswordSignIn struct {
	PrincipalDomains     []string
	Filter               string
	OpenUntil            time.Time     // zero: no rollout window
	NewEntriesFor        time.Duration // 0: off
	ReopenFor            time.Duration
	FailuresPerPrincipal int
	FailuresPerSource    int // 0: off
	Window               time.Duration
	TOTPLabel            string // "" is "port49 (<broker host>)", filled at start
}

const (
	DefaultNewEntriesFor        = 14 * 24 * time.Hour
	DefaultReopenFor            = 24 * time.Hour
	DefaultFailuresPerPrincipal = 5
	DefaultFailuresPerSource    = 50
	DefaultSignInWindow         = 15 * time.Minute
)
// Config gains: PasswordSignIn *PasswordSignIn
```

```go
// internal/directory/config.go
// Config gains: EnrollmentStore EnrollmentStore (zero without a
// directory_password verifier; config fills it, Task 5 Step 3).

// EnrollmentStore is broker.directory.enrollment_store resolved (plan 9e,
// D12): Backend "memory" (the sealed file in the broker's state dir) or
// "etcd" with its own endpoints, CA, prefix and identity.
type EnrollmentStore struct {
	Backend string
	Etcd    *EnrollmentEtcd // nil on memory, and when it shares store.etcd
	File    string          // memory: <BrokerStateDir>/enrollments.json
}

type EnrollmentEtcd struct {
	Endpoints   []string
	CAFile      string
	Prefix      string
	CertFile    string
	KeyFile     string
	CallTimeout time.Duration
}
```

  YAML (snake_case):

```yaml
broker:
  directory:
    enrollment_store:            # optional; absent is the shape of store:
      backend: etcd
      etcd:
        endpoints: [https://etcd-global-1:2379, https://etcd-global-2:2379]
        ca_file: /etc/port49/etcd-global-ca.pem
        prefix: /port49-enrollments/
        identity: {cert_file: /etc/port49/broker-global.pem, key_file: /etc/port49/broker-global-key.pem}
        call_timeout: 500ms
```

- [ ] **Step 1: Write the failing tests** in `internal/config/identity_test.go`, table-driven over
  complete `  identity:` blocks (two spaces under `broker:`), loaded through `loadWith` and the
  helper below:

```go
// passwordBroker is brokerBlock with identity in place of client_ca_file and
// no certificate_status (no x509 verifier is configured, and checkBroker
// refuses one then); with dir, a broker.directory with no
// certificate_mapping (R2).
func passwordBroker(t *testing.T, identity string, dir bool) string {
	t.Helper()
	cfg := brokerWithIdentity(identity)
	if dir {
		cfg = withDirectoryBlock(t, cfg)
		cfg = strings.Replace(cfg, "    certificate_mapping: {kind: issuer_serial}\n", "", 1)
	}
	return strings.Replace(cfg, "  certificate_status: {disabled: true}\n", "", 1)
}

// withDirectoryBlock adds TestALoadedBrokerResolvesItsDirectory's
// broker.directory block (its CA written with writeTemp(testCAPEM), its
// password_env set) after cfg's certificate_status line.
func withDirectoryBlock(t *testing.T, cfg string) string

const passwordBase = `  identity:
    humans:
      - type: directory_password
        principal_domains: [example.com]
        second_factor: totp
    issuance: {}
`

func TestTheDirectoryPasswordVerifier(t *testing.T) {
	const base = passwordBase
	with := func(line string) string {
		return strings.Replace(base, "second_factor: totp\n", "second_factor: totp\n        "+line+"\n", 1)
	}
	for _, tc := range []struct {
		name, yaml, want string // want "" is accepted
	}{
		{"defaults", base, ""},
		{"no second factor", strings.Replace(base, "        second_factor: totp\n", "", 1), "second_factor is required"},
		{"another second factor", strings.Replace(base, "totp", "sms", 1), `second_factor "sms": totp`},
		{"no domains", strings.Replace(base, "        principal_domains: [example.com]\n", "", 1), "principal_domains"},
		{"no issuance", strings.Replace(base, "    issuance: {}\n", "", 1), "broker.identity.issuance"},
		{"two", strings.Replace(base, "    issuance: {}\n", `      - type: directory_password
        principal_domains: [other.com]
        second_factor: totp
    issuance: {}
`, 1), "at most one directory_password"},
		{"window too long", with("rate_limits: {window: 25h}"), "window"},
		{"reopen too short", with("enrollment: {reopen_for: 30m}"), "reopen_for"},
		{"open_until not RFC 3339", with("enrollment: {open_until: tomorrow}"), "open_until"},
		{"a filter that does not parse", with(`filter: "(memberOf="`), "filter"},
		{"an unknown key", with("otp: x"), "otp"},
		{"limits", with("rate_limits: {failures_per_principal: 0}"), "failures_per_principal"},
		{"label with a colon", with(`totp_label: "a:b"`), "totp_label"},
		{"under machines", strings.Replace(base, "humans:", "machines:", 1), "directory_password is a human verifier"},
		{"an OIDC verifier of the same domain", strings.Replace(base, "    humans:\n", `    humans:
      - type: oidc
        issuer: https://idp.example.com
        client_id: port49-cli
        principal_claim: email
        principal_domains: [example.com]
`, 1), "example.com is also"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadWith(t, passwordBroker(t, tc.yaml, true))
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// The verifier runs on either store shape (D7): on memory its enrollments
// are the sealed file in the broker's state directory; with no
// enrollment_store it takes store:'s shape. It still needs a directory.
func TestTheDirectoryPasswordVerifierNeedsADirectoryOnly(t *testing.T) {
	if _, err := loadWith(t, passwordBroker(t, passwordBase, false)); err == nil || !strings.Contains(err.Error(), "broker.directory") {
		t.Fatalf("no directory: %v", err)
	}
	c, err := loadWith(t, passwordBroker(t, passwordBase, true))
	if err != nil {
		t.Fatalf("the memory store: %v", err)
	}
	es := c.Broker.Directory.EnrollmentStore
	if es.Backend != "memory" || es.Etcd != nil || es.File != filepath.Join(BrokerStateDir(c.Broker), "enrollments.json") {
		t.Fatalf("%+v", es)
	}
}

// enrollment_store's own etcd is checked as store.etcd is: https
// endpoints, a CA, an identity; an unknown backend or key is refused; a
// valid block loads with its fields; set without a directory_password
// verifier, it is refused.
func TestTheEnrollmentStoreHandle(t *testing.T)
```

  Write `TestTheEnrollmentStoreHandle` as a table over the Interfaces' YAML above, inserted under
  `  directory:`: `backend: etcd` with an `http://` endpoint refused naming
  `enrollment_store.etcd.endpoints`; no `identity` refused naming it; `backend: sql` refused
  naming "memory or etcd"; an unknown key refused; the valid block loads with `Backend "etcd"`
  and every `EnrollmentEtcd` field; and the valid block on a broker with only an x509 verifier
  refused ("nothing is enrolled without one; remove it"). In `directory_test.go` add: a broker
  with no human x509 verifier loads without `certificate_mapping`, and its `Mapping` is zero; with
  one, a missing mapping is refused as today.

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./internal/config/ -run 'DirectoryPassword|CertificateMapping|EnrollmentStore'`
Expected: FAIL (`type "directory_password": one of x509 or oidc`).

- [ ] **Step 3: Implement.** In `identityVerifierYAML` add:

```go
	SecondFactor string             `yaml:"second_factor"`
	Filter       string             `yaml:"filter"`
	Enrollment   *enrollmentYAML    `yaml:"enrollment"`
	RateLimits   *rateLimitsYAML    `yaml:"rate_limits"`
	TOTPLabel    string             `yaml:"totp_label"`
```

```go
// enrollmentYAML is a directory_password verifier's enrollment windows
// (decision 47 D2).
type enrollmentYAML struct {
	OpenUntil     string         `yaml:"open_until"`
	NewEntriesFor *time.Duration `yaml:"new_entries_for"`
	ReopenFor     *time.Duration `yaml:"reopen_for"`
}

// rateLimitsYAML is its attempt limits (decision 47 D5).
type rateLimitsYAML struct {
	FailuresPerPrincipal *int           `yaml:"failures_per_principal"`
	FailuresPerSource    *int           `yaml:"failures_per_source"`
	Window               *time.Duration `yaml:"window"`
}
```

  In `checkIdentity`'s switch, a `case v.Type == "directory_password" && list.domain == oidc.Humans:`
  that refuses a second one, refuses the x509 and oidc keys (`trust_anchor_file`, `issuer`,
  `client_id`, `audience`, `principal_claim`, `clients`, `scopes`, `algorithms`, `ca_file`,
  `spiffe_trust_domains`, `directory`), and calls `checkPasswordSignIn(at, v)`; the oidc and x509
  cases refuse the new keys. `checkPasswordSignIn` applies ruling 18's bounds: `second_factor`
  required and `totp`; `principal_domains` non-empty, each a lower-case DNS name; `filter`, when set,
  parsed by `ldap.CompileFilter`; `open_until` RFC 3339; `new_entries_for` 0 to 90 days;
  `reopen_for` 1h to 168h; `failures_per_principal` 1–100; `failures_per_source` 0–10000; `window`
  1m–24h; `totp_label` printable ASCII without `:`, at most 64 bytes. `checkIssuance` accepts a human
  `oidc` verifier or `out.PasswordSignIn`, and its message names both. The "accepts no one" check
  counts `out.PasswordSignIn`. In `distinctVerifiers`' caller, after it: a `principal_domains` entry
  of the password verifier that a human `oidc` verifier also lists is refused, "…: example.com is
  also broker.identity.humans[0]'s: a password beside an identity provider is a downgrade an
  attacker picks (decision 47 D8)". A `directory_password` verifier under `machines` gets its own
  case before the default: "`%s`: directory_password is a human verifier; list it under humans"
  (M4). In `config.go`, where `b.Identity` and `b.Directory` are both known (~1233–1340):
  `PasswordSignIn` without `b.Directory` is refused naming `broker.directory`. `enrollment_store`
  resolves into `b.Directory.EnrollmentStore`: absent, the shape of `store:` (memory: `Backend
  "memory"`, the file `filepath.Join(BrokerStateDir(&b), "enrollments.json")`; etcd: `Backend
  "etcd"`, `Etcd` nil, meaning `store.etcd` and the broker's identity); present, checked as
  `store.etcd` is (https endpoints, `ca_file`, `identity`, `prefix`, `call_timeout`; unknown keys
  refused). `enrollment_store` without a `directory_password` verifier is refused ("nothing is
  enrolled without one; remove it"). Add the enrollments file to `ownRevocationsFile`'s `others`
  (~1696) and to the port49-broker collision list beside the kept OIDC keys (~1826) (M5). In
  `directory.go`, `checkDirectory` takes whether a human x509 verifier is configured and checks
  `certificate_mapping` only then, or when it is set. With no mapping, `Mapping` stays zero:
  `checkSearchShape` (~385) skips `certificate_mapping.attribute` when it is empty; `entryAttrs`
  appends the mapping attribute only when it is set (Task 6 owns that line and its test);
  `announceDirectory` (`internal/port49d/directory.go:76`) says "no certificate mapping (no x509
  verifier)" in place of the kind; `Mapping.KeysOf` already returns nothing for a zero mapping
  (I8).

- [ ] **Step 4: Run to verify they pass.**

Run: `go test ./internal/config/ -v -run 'DirectoryPassword|CertificateMapping|EnrollmentStore' && go test ./internal/config/ ./internal/port49d/`
Expected: PASS, the whole package.

- [ ] **Step 5: Commit.**

```bash
git add internal/oidc/config.go internal/config internal/directory/config.go internal/port49d/directory.go
git commit -m "feat: the directory_password verifier in broker.identity, and its enrollment store

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: The directory — the entry a name names, and a person's bind

**Files:**
- Create: `internal/directory/signin.go`, `internal/directory/signin_test.go`
- Modify: `internal/directory/conn.go` (factor the dial and StartTLS out of `NewDialer` into
  `dialTLS`, used by both), `internal/directory/resolver.go` (`Resolver.PersonDial`),
  `internal/directory/entry.go` (`entryAttrs` appends the mapping attribute only when set, I8)
- Test: `internal/directory/entry_test.go` (no `""` among the attributes with a zero mapping)

**Interfaces:**
- Consumes: `Pool.Do`, `Config.oneEntry`, `identityOf`, `principalUnique`, `usernameUnique`,
  `notWorkload`, `tlsConfig`, `ErrUnavailable`, `ErrUnmapped`, `ErrAmbiguous`.
- Produces:

```go
// SignInEntry is the entry a name typed at a directory sign-in names (plan
// 9e; decision 47 ruling 3), and the server that answered.
type SignInEntry struct {
	Identity
	Server    Server
	CreatedAt time.Time // whenCreated or createTimestamp; zero when neither was read
}

// ErrPasswordRefused is a person's bind the directory refused.
var ErrPasswordRefused = errors.New("directory: the password was refused")

// ErrEmptyPassword is a password refused before any dial (RFC 4513 §5.1.2).
var ErrEmptyPassword = errors.New("directory: an empty password is never sent")

// PasswordRefusal is how the directory refused a person's bind: its LDAP
// result, and AD's data code or OpenLDAP's ppolicy error when it gave one
// (ruling 6). It never holds the server's message.
type PasswordRefusal struct {
	Result int
	Data   string // "52e", "532", …, or "password_expired", "account_locked", "change_after_reset"
}

func (p *PasswordRefusal) Error() string
func (p *PasswordRefusal) Unwrap() error // ErrPasswordRefused
// State is whether the refusal names the account's state rather than a
// wrong password (ruling 7): every Data but "", "52e" and "525".
func (p *PasswordRefusal) State() bool

func (r *Resolver) SignInEntry(ctx context.Context, name, filter string) (SignInEntry, error)
func (r *Resolver) CheckPassword(ctx context.Context, s Server, dn, password string) error

// PersonConn is the one connection a person's bind is made on.
// *ldap.Conn is one.
type PersonConn interface {
	SimpleBind(*ldap.SimpleBindRequest) (*ldap.SimpleBindResult, error)
	Close() error
}

// Resolver gains:
//   PersonDial func(ctx context.Context, s Server) (PersonConn, error) // nil: dialPerson

// dialPerson dials s, secures it (LDAPS, or StartTLS), and returns the
// connection unbound. It presents no client certificate whatever the
// broker's bind mechanism (plan 9e, D3).
func dialPerson(ctx context.Context, cfg Config, s Server) (PersonConn, error)

// personTLS is the TLS a person's connection uses: tlsConfig(cfg, s,
// &Credentials{}), never a client certificate.
func personTLS(cfg Config, s Server) (*tls.Config, error)
```

- [ ] **Step 1: Write the failing tests** in `internal/directory/signin_test.go`. They use
  `newWorld` (`resolver_test.go`), whose principal is `user:alice@corp.example.com`, the package's
  fake searcher (`fake_test.go`) for `SignInEntry`, and a `personServer` seam (`PersonDial`) for
  `CheckPassword`:

```go
package directory

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const aliceDN = "CN=Alice,OU=Staff,DC=corp"

// signInWorld is newWorld with alice findable by sAMAccountName under the
// verifier's filter, created at 2026-10-01T12:00:00Z.
func signInWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	a := entry(aliceDN, map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}, "whenCreated": {"20261001120000.0Z"}})
	w.dir.on("(&(objectClass=person)(memberOf=cn=people)(sAMAccountName=alice))", a)
	return w
}

// The name is matched on username_attribute under both filters, escaped;
// the entry gives its principal and username; its creation time is read.
func TestSignInEntryFindsTheOneEntry(t *testing.T) {
	w := signInWorld(t)
	e, err := w.r.SignInEntry(context.Background(), "alice", "(memberOf=cn=people)")
	if err != nil {
		t.Fatal(err)
	}
	if e.Principal != "user:alice@corp.example.com" || e.Username != "alice" || e.DN != aliceDN ||
		!e.CreatedAt.Equal(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)) || e.Server.URI != dc01 {
		t.Fatalf("%+v", e)
	}
	var first *ldap.SearchRequest
	for _, c := range w.dir.calls {
		if strings.Contains(c.Filter, "memberOf") {
			first = c
		}
	}
	if first == nil || first.Filter != "(&(objectClass=person)(memberOf=cn=people)(sAMAccountName=alice))" ||
		!slicesContain(first.Attributes, "whenCreated") || !slicesContain(first.Attributes, "createTimestamp") ||
		slicesContain(first.Attributes, "") {
		t.Fatalf("the search: %+v", first)
	}
}

func slicesContain(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// A name holding filter metacharacters is escaped, never parsed.
func TestSignInEntryEscapesTheName(t *testing.T) {
	w := signInWorld(t)
	_, err := w.r.SignInEntry(context.Background(), "a*)(uid=*", "")
	if !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
	last := w.dir.calls[len(w.dir.calls)-1]
	if last.Filter != `(&(objectClass=person)(sAMAccountName=a\2a\29\28uid=\2a))` {
		t.Fatalf("filter %q", last.Filter)
	}
}

// Two entries for one name are ErrAmbiguous; none is ErrUnmapped; a
// workload's entry is ErrUnmapped; a stopped server is ErrUnavailable,
// never ErrUnmapped.
func TestSignInEntryRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("two", func(t *testing.T) {
		w := signInWorld(t)
		w.dir.on("(&(objectClass=person)(sAMAccountName=bob))", entry("CN=Bob,OU=A,DC=corp", nil),
			entry("CN=Bob,OU=B,DC=corp", nil))
		if _, err := w.r.SignInEntry(ctx, "bob", ""); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("none", func(t *testing.T) {
		w := signInWorld(t)
		if _, err := w.r.SignInEntry(ctx, "nobody", ""); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a workload's", func(t *testing.T) {
		w := signInWorld(t)
		w.r.Cfg.Workload = &WorkloadMapping{Attribute: "uid"}
		w.dir.on("(&(objectClass=person)(sAMAccountName=svc))", entry("CN=svc,OU=Svc,DC=corp", map[string][]string{
			"userPrincipalName": {"svc@corp.example.com"}, "sAMAccountName": {"svc"},
			"uid": {"spiffe://corp.example.com/svc"}}))
		if _, err := w.r.SignInEntry(ctx, "svc", ""); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("stopped", func(t *testing.T) {
		w := signInWorld(t)
		w.down()
		_, err := w.r.SignInEntry(ctx, "alice", "(memberOf=cn=people)")
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrUnmapped) {
			t.Fatalf("%v", err)
		}
	})
}

// personServer is PersonDial over a pipe: each dial is answered with one
// bind response carrying code and diag, and, when ppolicy >= 0, a Behera
// password-policy control with that error. It counts dials and closes,
// and down refuses the dial; hang never answers.
type personServer struct {
	mu            sync.Mutex
	code          int64
	diag          string
	ppolicy       int
	down, hang    bool
	dials, closed int
}

func newPersonServer(code int64, diag string) *personServer {
	return &personServer{code: code, diag: diag, ppolicy: -1}
}

type countedConn struct {
	*ldap.Conn
	p    *personServer
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.p.mu.Lock(); c.p.closed++; c.p.mu.Unlock() })
	return c.Conn.Close()
}

func (p *personServer) dial(ctx context.Context, s Server) (PersonConn, error) {
	p.mu.Lock()
	p.dials++
	code, diag, pp, down, hang := p.code, p.diag, p.ppolicy, p.down, p.hang
	p.mu.Unlock()
	if down {
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("dial tcp: connection refused"))
	}
	cc, sc := net.Pipe()
	go func() {
		defer sc.Close()
		pk, err := ber.ReadPacket(sc)
		if err != nil || hang {
			_, _ = io.Copy(io.Discard, sc)
			return
		}
		env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, pk.Children[0].Value, "MessageID"))
		resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind Response")
		resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
		env.AppendChild(resp)
		if pp >= 0 {
			env.AppendChild(beheraResponse(pp))
		}
		_, _ = sc.Write(env.Bytes())
		_, _ = io.Copy(io.Discard, sc)
	}()
	conn := ldap.NewConn(cc, false)
	conn.Start()
	return &countedConn{Conn: conn, p: p}, nil
}

// beheraResponse is a response's controls, [0], holding one Behera
// password-policy control whose value carries error e
// (draft-behera-ldap-password-policy-10 §6.2).
func beheraResponse(e int) *ber.Packet {
	controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	c := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	c.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		ldap.ControlTypeBeheraPasswordPolicy, "Control Type"))
	v := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PasswordPolicyResponseValue")
	v.AppendChild(ber.NewInteger(ber.ClassContext, ber.TypePrimitive, 1, int64(e), "error"))
	c.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v.Bytes()), "Control Value"))
	controls.AppendChild(c)
	return controls
}

// personResolver is a Resolver with no pool at all: CheckPassword must
// never need one (Review Focus 6).
func personResolver(p *personServer) *Resolver {
	return &Resolver{Cfg: adCfg(), PersonDial: p.dial}
}

var dc = Server{URI: "ldaps://dc-01"}

// An empty password is never sent: no dial is made (Review Focus 1).
func TestAnEmptyPasswordIsNeverSent(t *testing.T) {
	p := newPersonServer(0, "")
	for _, pw := range []string{"", " ", "\t"} {
		if err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, pw); !errors.Is(err, ErrEmptyPassword) {
			t.Fatalf("%q: %v", pw, err)
		}
	}
	if p.dials != 0 {
		t.Fatal("an empty password dialled the directory")
	}
}

// AD's data code is kept from the message, the rest dropped; a wrong
// password and a locked account read apart (ruling 6).
func TestARefusedPasswordKeepsADsDataCode(t *testing.T) {
	for _, tc := range []struct {
		msg, data string
		state     bool
	}{
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4f7c", "52e", false},
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4f7c", "775", true},
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 773, v4f7c", "773", true},
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 999, v4f7c", "", false},
		{"Invalid credentials", "", false},
	} {
		p := newPersonServer(ldap.LDAPResultInvalidCredentials, tc.msg)
		err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "x")
		var r *PasswordRefusal
		if !errors.As(err, &r) || r.Result != 49 || r.Data != tc.data || r.State() != tc.state ||
			!errors.Is(err, ErrPasswordRefused) || strings.Contains(err.Error(), "DSID") ||
			strings.Contains(err.Error(), "AcceptSecurityContext") {
			t.Errorf("%q: %v", tc.msg, err)
		}
	}
}

// OpenLDAP's ppolicy control is read on a refusal and on a success
// (I4): expired and locked on a 49, change-after-reset on a 0.
func TestThePasswordPolicyControlIsRead(t *testing.T) {
	for _, tc := range []struct {
		code   int64
		pp     int
		data   string
		result int
	}{
		{49, 0, "password_expired", 49},
		{49, 1, "account_locked", 49},
		{0, 2, "change_after_reset", 0},
	} {
		p := newPersonServer(tc.code, "")
		p.ppolicy = tc.pp
		err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "x")
		var r *PasswordRefusal
		if !errors.As(err, &r) || r.Data != tc.data || r.Result != tc.result || !r.State() {
			t.Errorf("code %d ppolicy %d: %v", tc.code, tc.pp, err)
		}
	}
	if err := personResolver(newPersonServer(0, "")).CheckPassword(context.Background(), dc, aliceDN, "x"); err != nil {
		t.Fatalf("a plain success: %v", err)
	}
}

// A refused password moves no breaker and starts no hold-off (Review
// Focus 6): CheckPassword runs with no pool at all, and on a world's
// resolver ten refusals leave its selection and its dials as they were.
func TestARefusedPasswordLeavesThePoolAlone(t *testing.T) {
	ctx := context.Background()
	p := newPersonServer(ldap.LDAPResultInvalidCredentials, "data 52e")
	for range 10 {
		if err := personResolver(p).CheckPassword(ctx, dc, aliceDN, "wrong"); !errors.Is(err, ErrPasswordRefused) {
			t.Fatal(err)
		}
	}
	w := signInWorld(t)
	w.r.PersonDial = p.dial
	if _, err := w.r.SignInEntry(ctx, "alice", "(memberOf=cn=people)"); err != nil {
		t.Fatal(err)
	}
	before, _ := w.r.Pool.Selected()
	dials := w.srv.dials[dc01]
	for range 10 {
		_ = w.r.CheckPassword(ctx, before, aliceDN, "wrong")
	}
	after, ok := w.r.Pool.Selected()
	if !ok || after.URI != before.URI || w.srv.dials[dc01] != dials || w.say.has("hold-off") {
		t.Fatalf("the pool moved: %v -> %v, dials %d -> %d", before, after, dials, w.srv.dials[dc01])
	}
}

// The person's bind is on a connection of its own, closed after the one
// bind, and the real dial presents no client certificate even when the
// broker binds by EXTERNAL.
func TestThePersonsBindIsItsOwnConnection(t *testing.T) {
	p := newPersonServer(0, "")
	if err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "right"); err != nil {
		t.Fatal(err)
	}
	if p.dials != 1 || p.closed != 1 {
		t.Fatalf("%d dials, %d closed", p.dials, p.closed)
	}
	cfg := adCfg()
	cfg.CAFile = writeCA(t)
	cfg.Bind.Mechanism = "external"
	tc, err := personTLS(cfg, dc)
	if err != nil || len(tc.Certificates) != 0 || tc.GetClientCertificate != nil {
		t.Fatalf("the person's TLS presents a certificate: %v", err)
	}
}

// A server that does not answer is ErrUnavailable, never a refusal; a
// bind that hangs ends at the caller's deadline.
func TestAStoppedServerIsUnavailable(t *testing.T) {
	p := newPersonServer(0, "")
	p.down = true
	err := personResolver(p).CheckPassword(context.Background(), dc, aliceDN, "x")
	var r *PasswordRefusal
	if !errors.Is(err, ErrUnavailable) || errors.As(err, &r) {
		t.Fatalf("%v", err)
	}
	p = newPersonServer(0, "")
	p.hang = true
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := personResolver(p).CheckPassword(ctx, dc, aliceDN, "x"); !errors.Is(err, ErrUnavailable) ||
		time.Since(start) > time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
}
```

  `writeCA(t) string` is new in this file: a `testpki.NewCA` written as PEM into `t.TempDir()`, as
  `conn_test.go`'s `TestTLSConfigVerifiesTheServerName` makes its CA. In `entry_test.go` add
  `TestAZeroMappingAsksForNoEmptyAttribute`: `adCfg()` with `Mapping` zeroed; `entryAttrs()` holds
  no `""`.

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./internal/directory/ -run 'SignIn|Password|PersonsBind|StoppedServer|ZeroMapping'`
Expected: FAIL (`undefined: SignInEntry`).

- [ ] **Step 3: Implement** `signin.go`. The core:

```go
// adData is AD's data code in a bind's diagnostic message, kept only when it
// is one ruling 6 names; the message itself is never kept.
var adData = regexp.MustCompile(`\bdata ([0-9a-f]{3,4})\b`)

var knownData = map[string]bool{"52e": true, "525": true, "530": true, "531": true, "532": true,
	"533": true, "701": true, "773": true, "775": true}

func (r *Resolver) CheckPassword(ctx context.Context, s Server, dn, password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrEmptyPassword
	}
	dial := r.PersonDial
	if dial == nil {
		dial = func(ctx context.Context, s Server) (PersonConn, error) { return dialPerson(ctx, r.Cfg, s) }
	}
	conn, err := dial(ctx, s) // never r.Pool: a person's bind is not the pool's
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, s.Label(), err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	var res *ldap.SimpleBindResult
	go func() {
		var err error
		res, err = conn.SimpleBind(&ldap.SimpleBindRequest{Username: dn, Password: password,
			Controls: []ldap.Control{ldap.NewControlBeheraPasswordPolicy()}})
		done <- err
	}()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = conn.Close()
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, s.Label(), ctx.Err())
	}
	var p *PasswordRefusal
	if err != nil {
		var le *ldap.Error
		if !errors.As(err, &le) || le.ResultCode >= 200 {
			return fmt.Errorf("%w: %s: the bind did not complete", ErrUnavailable, s.Label())
		}
		p = &PasswordRefusal{Result: int(le.ResultCode)}
		if m := adData.FindStringSubmatch(le.Err.Error()); m != nil && knownData[m[1]] {
			p.Data = m[1]
		}
	}
	if res != nil {
		if d := ppolicyData(res.Controls); d != "" {
			if p == nil { // a bind the server accepted, with a password it says must change (I4)
				p = &PasswordRefusal{Result: 0}
			}
			p.Data = d
		}
	}
	if p == nil {
		return nil
	}
	return p
}
```

  A success carrying `graceAuthNsRemaining` (an expired password with grace logins left) is a
  success: `ppolicyData` reads only the `Error` member. `changeAfterReset` on a success is a
  refusal with `Result: 0`, whose `State()` is true; L67 (c) records which directories send it.

  `ppolicyData` finds the `*ldap.ControlBeheraPasswordPolicy` among the result's controls and maps
  its `Error` as draft-behera-ldap-password-policy-10 §6.2 numbers them: `0` (passwordExpired) →
  `password_expired`, `1` (accountLocked) → `account_locked`, `2` (changeAfterReset) →
  `change_after_reset`; any other value, or no control, is "". go-ldap v3.4.14's `SimpleBind`
  returns its result, controls included, beside the error (`bind.go:64–95`), and decodes the
  Behera control (`control.go:657`); `NewControlBeheraPasswordPolicy()` is sent non-critical (AD
  ignores it).
  `SignInEntry` runs one `r.Pool.Do` whose function does `r.Cfg.oneEntry` with the filter
  `fmt.Sprintf("(&%s%s(%s=%s))", r.Cfg.UserFilter, filter, r.Cfg.UsernameAttribute,
  ldap.EscapeFilter(name))` and the attributes `entryAttrs()` plus `whenCreated` and
  `createTimestamp`, then `notWorkload`, `identityOf`, `principalUnique`, `usernameUnique`, and returns
  the `Server` `Do` reports. `CreatedAt` parses either attribute with
  `ber.ParseGeneralizedTime([]byte(v))` (`github.com/go-asn1-ber/asn1-ber`, a direct dependency
  already; it takes AD's `20261001120000.0Z`); an error is zero. `dialTLS(ctx, cfg, s, cr)` is
  `NewDialer`'s dial and StartTLS moved out; `NewDialer` calls it with its credentials and binds as
  before; `dialPerson` calls it with `&Credentials{}` (no certificate), never nil, since
  `tlsConfig` reads `cr.cert` unguarded; `personTLS` is `tlsConfig(cfg, s, &Credentials{})`.
  `entryAttrs` (`entry.go:24`) appends `c.Mapping.Attribute` only when it is non-empty (I8).
  `CheckPassword` uses `r.PersonDial` when set, else `dialPerson`; it never touches `r.Pool`.

- [ ] **Step 4: Run to verify they pass.**

Run: `go test ./internal/directory/ -race -v -run 'SignIn|Password|PersonsBind|StoppedServer|ZeroMapping' && go test ./internal/directory/`
Expected: PASS, the whole package (the 7g classification tests included: `dialTLS` changed nothing).

- [ ] **Step 5: Commit.**

```bash
git add internal/directory
git commit -m "feat: the directory finds a sign-in's entry and checks a person's password

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: The issuer — a directory sign-in in the certificate

**Files:**
- Modify: `internal/issuer/signin.go`
- Test: `internal/issuer/issuer_test.go`

**Interfaces:**
- Produces:

```go
// SignIn gains:
//   Method string // "" is MethodOIDC
const (
	MethodOIDC              = "oidc"
	MethodDirectoryPassword = "directory_password"
)
// EntrySubject is a directory sign-in's sub: the entry's id hashed, so a
// DN-form id fits the URI (decision 47 D6).
func EntrySubject(entryID string) string // "entry-sha256:" + hex SHA-256
```

- [ ] **Step 1: Write the failing tests:**

```go
// A directory sign-in's certificate carries method, sub, auth_time, iat and
// amr, and no iss; it reads back as it was issued (decision 47 D6).
func TestADirectorySignInRoundTrips(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ca, err := Ephemeral(now)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := SignIn{Method: MethodDirectoryPassword, Principal: "user:alice@example.com",
		Subject: EntrySubject("dn:cn=alice smith,ou=staff"), AMR: []string{"pwd", "otp"}, AuthTime: now, IssuedAt: now}
	c, err := ca.Issue(key.Public(), s, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadSignIn(c)
	if err != nil || got.Method != MethodDirectoryPassword || got.Issuer != "" || got.Subject != s.Subject ||
		!slices.Equal(got.AMR, []string{"pwd", "otp"}) {
		t.Fatalf("%+v %v", got, err)
	}
	if q := c.URIs[0].Query(); q.Get("method") != "directory_password" || q.Has("iss") {
		t.Fatalf("%s", c.URIs[0])
	}
}

// Each method's rules: an OIDC sign-in needs its https iss; a directory one
// takes none, and no sid; an unknown method is refused.
func TestEachMethodIsHeldToItsRules(t *testing.T) { /* table over validate(): OIDC with no iss
	refused; directory with an iss refused; directory with a sid refused; method "saml" refused;
	a 9b certificate with no method member still reads as MethodOIDC */ }
```

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./internal/issuer/ -run 'DirectorySignIn|EachMethod'`
Expected: FAIL (`unknown field Method`).

- [ ] **Step 3: Implement.** Add `Method` to `SignIn`; `URI` sets `method` only for
  `MethodDirectoryPassword` and omits an empty `iss`; `signInMembers` gains `"method"`;
  `ReadSignIn` reads it (absent is `MethodOIDC`); `validate` switches on it: `MethodOIDC` as today;
  `MethodDirectoryPassword` requires `Issuer == ""`, `Sid == ""`, a printable `Subject` with the
  `entry-sha256:` prefix and 64 hex digits, `AMR` non-empty; anything else is refused ("its sign-in
  names a method port49 does not issue"). `EntrySubject` as declared.

- [ ] **Step 4: Run to verify they pass.**

Run: `go test ./internal/issuer/ -v`
Expected: PASS, the 9b tests unchanged.

- [ ] **Step 5: Commit.**

```bash
git add internal/issuer
git commit -m "feat: an issued certificate can carry a directory-password sign-in

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: The broker reads a directory sign-in's certificate

**Files:**
- Modify: `internal/broker/workload.go` (`CertCaller.SignIn`), `internal/broker/issued.go`
  (`issuedCaller` by method), `internal/broker/broker.go` (`authenticate` ~675–760, `callerOf`
  ~797–800; the `Broker` fields), `internal/broker/listen.go` (~351), `internal/broker/oidc.go`
  (`caller.signIn`, `caller.auth`), `internal/broker/server.go` (~89, the password-only broker's
  pool)
- Test: `internal/broker/signin_cert_test.go` (new)

**Interfaces:**
- Consumes: `issuer.SignIn.Method`, `oidc.PasswordSignIn`, `decision.DirectoryPassword`.
- Produces:

```go
// Broker gains:
//   PasswordSignIn *oidc.PasswordSignIn // broker.identity's directory_password verifier; nil without one
// CertCaller gains:
//   SignIn *issuer.SignIn // the sign-in a certificate this broker issued carries, either method; nil for any other
// caller gains:
//   signIn *issuer.SignIn
func directoryPasswordAuth(s issuer.SignIn) *decision.DirectoryPassword
```

- [ ] **Step 1: Write the failing tests** in `signin_cert_test.go`:

```go
// A certificate issued over a directory sign-in mints as its principal,
// never mapped; its records carry auth.directory_password and no auth.oidc
// (decision 47 ruling 10, D6).
func TestADirectorySignInCertificateMints(t *testing.T) {
	f := newFixture(t, 8)
	f.withPasswordSignIn(t) // an issuing CA, PasswordSignIn{PrincipalDomains: ["example.com"]}, no OIDC
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now)
	if r := decodeMint(t, w); r.Principal != alicePrincipal || r.Results[0].Verdict != "permit" {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	auth, _ := recs[0]["auth"].(map[string]any)
	dp, _ := auth["directory_password"].(map[string]any)
	if dp == nil || auth["oidc"] != nil || dp["entry_sha256"] == "" {
		t.Fatalf("%v", auth)
	}
}

// With the verifier gone, or the principal's domain no longer its, the
// certificate is refused: removing the verifier takes its people's
// certificates with it.
func TestADirectorySignInCertificateNeedsItsVerifier(t *testing.T) { /* PasswordSignIn = nil →
	401 trust_domain_unresolved naming "directory_password verifier"; PrincipalDomains [other.com] → same */ }

// An OIDC sign-in's certificate is not taken as a directory one, nor the reverse.
func TestTheMethodsDoNotCross(t *testing.T) { /* a 9b certificate on a broker with PasswordSignIn and
	no OIDC verifier is refused; a directory certificate never reaches issuedLoggedOut */ }

// A broker with a directory_password verifier alone builds its pool from
// its issuing CA, as a 9b OIDC-only broker does.
func TestAPasswordOnlyBrokerServes(t *testing.T) { /* b.NoX509, b.Identity nil, b.PasswordSignIn and
	b.Issuer set: Server returns a server whose ClientCAs hold the issuing CA */ }

// A bearer token at a password-only broker (b.Identity nil): POST /v1/tokens
// with Authorization: Bearer is refused 401 and nothing panics
// (bearerCaller with no Identity).
func TestABearerAtAPasswordOnlyBroker(t *testing.T)
```

  Add to the fixture (in this file): `withPasswordSignIn`, which sets an `issuer.Ephemeral` CA,
  `f.b.NoX509 = true`, and `f.b.PasswordSignIn = &oidc.PasswordSignIn{PrincipalDomains:
  []string{"example.com"}, …}` with every default set explicitly (`NewEntriesFor`, `ReopenFor`,
  `FailuresPerPrincipal`, `FailuresPerSource`, `Window`, `TOTPLabel: "port49 (broker.test)"`);
  and `issuedDirectory`, which issues a certificate for a new key over `issuer.SignIn{Method:
  issuer.MethodDirectoryPassword, Principal: p, Subject: issuer.EntrySubject(entry), AMR:
  []string{"pwd", "otp"}, AuthTime: f.now, IssuedAt: f.now}` and returns it as a `tls.Certificate`
  (as `issued` does for 9b).

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./internal/broker/ -run 'DirectorySignInCertificate|MethodsDoNotCross|PasswordOnlyBroker'`
Expected: FAIL. (`TestABearerAtAPasswordOnlyBroker` may pass already; it guards Step 3.)

- [ ] **Step 3: Implement.**
  - `issuedCaller`: after `ReadSignIn`, `switch s.Method`. For `MethodDirectoryPassword`: refuse
    (`ErrUntrusted`) unless `b.PasswordSignIn != nil` and its `PrincipalDomains` hold
    `oidc.DomainOf(s.Principal)`, "the sign-in this certificate was issued on (a directory password,
    for %s) is not one this broker's directory_password verifier takes now; run `port49 login
    --sign-in`"; set `cc.Principal`, `cc.Cred.Sub = s.Subject`, `cc.Cred.AMR = s.AMR`, `cc.SignIn =
    &s`, and leave `cc.Issued` nil. For `MethodOIDC`: as today, plus `cc.SignIn = &s`.
  - Every `cc.Issued != nil` that means "a certificate this broker issued" becomes `cc.SignIn !=
    nil`: `broker.go` ~675, ~749, ~798 (`callerOf`), `listen.go` ~351. Those that mean "an OIDC
    sign-in" stay `cc.Issued`: `oidcAuth(*cc.Issued)` (~700) and `issuedLoggedOut` (~756).
  - `via` in `authenticate` becomes two values, `viaOIDC` and `viaDir`
    (`directoryPasswordAuth(*cc.SignIn)` for the directory method), and every `&decision.Auth{Method:
    cred.Method, OIDC: via}` there gains `DirectoryPassword: viaDir`.
  - `caller` gains `signIn`; `caller.auth()` sets `DirectoryPassword` from it for the directory method.
  - `directoryPasswordAuth` returns `{AMR: s.AMR, AuthTime: decision.FormatTime(s.AuthTime),
    EntrySHA256: strings.TrimPrefix(s.Subject, "entry-sha256:")}`.
  - `server.go`: a case `anchor == nil && b.NoX509 && (b.Identity != nil || b.PasswordSignIn != nil)
    && b.Issuer != nil` replaces ~89's, and the error at ~97 names "an OIDC or directory_password
    verifier".
  - `bearerCaller` with `b.Identity == nil` answers 401 (no verifier takes a bearer token here),
    never dereferences it (M12).

- [ ] **Step 4: Run to verify they pass.**

Run: `go test ./internal/broker/ -race`
Expected: PASS, every 9b issued-certificate test unchanged.

- [ ] **Step 5: Commit.**

```bash
git add internal/broker
git commit -m "feat: the broker reads a certificate issued over a directory sign-in

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: The broker — `POST /v1/sign-in` and `/v1/sign-in/confirm`

**Files:**
- Create: `internal/broker/api/signin.go`, `internal/broker/signin.go`,
  `internal/broker/signin_test.go`
- Modify: `internal/broker/issue.go` (factor the tail into `issueTo`), `internal/broker/broker.go`
  (routes, `config`, the `SignInDirectory` and `Enrollments` fields, the lost state)

**Interfaces:**
- Consumes: `totp.Check`, `totp.NewSecret`, `totp.URI`, `totp.Code` and `totp.DecodeSecret`
  (tests), `store.Enrollments`, `store.SecondFactor`, `store.EnrollmentMark`,
  `store.ErrEnrollmentStoreLost`, the attempt methods on `store.Store`, `memory.NewEnrollments`
  (tests), `directory.SignInEntry`, `directory.PasswordRefusal`, `issuer.EntrySubject`,
  `decision.SignIn`, `decision.EnrollmentStoreLost`, `Metrics.SignIns`,
  `Metrics.DirectoryEnrollmentStoreOK`.
- Produces:

```go
// api/signin.go
type SignInRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
	CSR      string `json:"csr"`
}
type Enrollment struct {
	Handle    string `json:"handle"`
	URI       string `json:"otpauth_uri"`
	ConfirmBy string `json:"confirm_by"`
}
type EnrollResponse struct {
	Enroll Enrollment `json:"enroll"`
}
type ConfirmRequest struct {
	Handle string `json:"handle"`
	Code   string `json:"code"`
	CSR    string `json:"csr"`
}
type SignInConfig struct {
	SecondFactor string `json:"second_factor"`
}
// Config gains: SignIn *SignInConfig `json:"sign_in,omitempty"`

// broker
// SignInDirectory is what a directory sign-in asks the directory;
// *directory.Resolver is one.
type SignInDirectory interface {
	SignInEntry(ctx context.Context, name, filter string) (directory.SignInEntry, error)
	CheckPassword(ctx context.Context, s directory.Server, dn, password string) error
}
// Broker gains:
//   SignInDirectory SignInDirectory
//   Enrollments     store.Enrollments // the enrollment store's handle (D12); b.Store keeps the attempts

// CheckEnrollmentStore is the start's and each scheduled pass's look at the
// enrollment store (D7): its mark present is well (gauge 1, lost cleared);
// no mark (ErrNotFound, a new install included) or a store that will not
// open (ErrEnrollmentStoreLost) is lost (gauge 0, one error line naming
// init-enrollments, import and reset-second-factor --all). It never
// creates the mark. A store that does not answer is not lost: the state and
// the gauge stay as they were, and the next pass looks again; its error is
// returned.
func (b *Broker) CheckEnrollmentStore(ctx context.Context) error
// EnrollmentStoreLost is why password sign-in is refused, "" when it is not.
func (b *Broker) EnrollmentStoreLost() string

// issueTo signs pub a certificate over sign, records the issue permit with
// auth and extra, and answers it; on the CA's signing fault it answers 503
// issuance_unavailable, unrecorded. The caller has called CanIssue.
func (b *Broker) issueTo(w http.ResponseWriter, now time.Time, pub crypto.PublicKey, sign issuer.SignIn,
	auth *decision.Auth, extra *decision.SignIn) bool

// sourcePrefix is r's peer as the per-source limit counts it: an IPv4
// address /32, an IPv6 address /64.
func sourcePrefix(remoteAddr string) string
```

- [ ] **Step 1: Write the failing tests** in `internal/broker/signin_test.go`, in full. The
  fixture is `withPasswordSignIn` and `issuedDirectory` (Task 8), an in-memory enrollment store with
  its mark, and a fake `SignInDirectory`. A body is `csrOf`'s base64url DER (the existing
  `csrBody` returns a whole JSON body, not a CSR).

```go
package broker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/totp"
)

// fakeDir is a directory of people by name: their entry and password.
// down makes every call ErrUnavailable, carrying the name typed in its
// text (as a server's diagnostic may: I13); state is a refusal every right
// password gets. It counts searches and binds.
type fakeDir struct {
	mu       sync.Mutex
	people   map[string]fakePerson
	down     bool
	state    string
	searches int
	binds    int
}

type fakePerson struct {
	entry    directory.SignInEntry
	password string
}

func (d *fakeDir) SignInEntry(_ context.Context, name, _ string) (directory.SignInEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.searches++
	if d.down {
		return directory.SignInEntry{}, fmt.Errorf("%w (the last: dc-01: filter (sAMAccountName=%s): busy)",
			directory.ErrUnavailable, name)
	}
	p, ok := d.people[name]
	if !ok {
		return directory.SignInEntry{}, fmt.Errorf("%w: no entry", directory.ErrUnmapped)
	}
	return p.entry, nil
}

func (d *fakeDir) CheckPassword(_ context.Context, _ directory.Server, dn, password string) error {
	if strings.TrimSpace(password) == "" {
		return directory.ErrEmptyPassword
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.down {
		return fmt.Errorf("%w: dc-01", directory.ErrUnavailable)
	}
	d.binds++
	for _, p := range d.people {
		switch {
		case p.entry.DN != dn:
		case p.password != password:
			return &directory.PasswordRefusal{Result: 49, Data: "52e"}
		case d.state != "":
			return &directory.PasswordRefusal{Result: 49, Data: d.state}
		default:
			return nil
		}
	}
	return &directory.PasswordRefusal{Result: 49, Data: "525"}
}

func (d *fakeDir) bindCount() int   { d.mu.Lock(); defer d.mu.Unlock(); return d.binds }
func (d *fakeDir) searchCount() int { d.mu.Lock(); defer d.mu.Unlock(); return d.searches }
func (d *fakeDir) setDown(v bool)   { d.mu.Lock(); d.down = v; d.mu.Unlock() }

// newSignInFixture is a password-only broker (withPasswordSignIn, Task 8)
// over the memory store and an in-memory enrollment store with its mark,
// with alice in the directory: entry uuid:alice, password "right", created
// a year ago (no new-entry window), and no other window open.
func newSignInFixture(t *testing.T) (*fixture, *fakeDir) {
	t.Helper()
	f := newFixture(t, 8)
	f.withPasswordSignIn(t)
	f.b.Enrollments = memory.NewEnrollments(f.b.Now)
	if err := f.b.Enrollments.CreateEnrollmentMark(context.Background(), store.EnrollmentMark{CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := f.b.CheckEnrollmentStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := &fakeDir{people: map[string]fakePerson{"alice": {password: "right", entry: directory.SignInEntry{
		Identity: directory.Identity{DN: "uid=alice,ou=Staff,dc=example,dc=com", EntryID: "uuid:alice",
			Principal: alicePrincipal, Username: "alice"},
		Server:    directory.Server{URI: "ldaps://dc-01.example.com"},
		CreatedAt: f.now.Add(-365 * 24 * time.Hour)}}}}
	f.b.SignInDirectory = dir
	return f, dir
}

// csrOf is a CSR for key as a sign-in body carries it: base64url DER (I10).
func csrOf(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// signIn posts req to /v1/sign-in with no client certificate, from
// httptest's 192.0.2.1:1234.
func (f *fixture) signIn(t *testing.T, req api.SignInRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	return f.call(context.Background(), nil, "POST", "/v1/sign-in", string(body))
}

func (f *fixture) confirm(t *testing.T, req api.ConfirmRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	return f.call(context.Background(), nil, "POST", "/v1/sign-in/confirm", string(body))
}

// enrolled writes an active second factor for principal on entry, with a
// fresh secret, and returns the secret.
func (f *fixture) enrolled(t *testing.T, principal, entry string) []byte {
	t.Helper()
	secret, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.b.Enrollments.SwapSecondFactor(context.Background(), store.SecondFactor{Principal: principal,
		State: store.SecondFactorActive, EntryID: entry, Secret: secret, EnrolledAt: f.now.Add(-time.Hour),
		EnrolledFrom: "192.0.2.0/32"}, 0); err != nil {
		t.Fatal(err)
	}
	return secret
}

// codeAt is secret's code at at (M9).
func codeAt(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	c, err := totp.Code(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// wrongCode is a six-digit code that is not secret's at at.
func wrongCode(t *testing.T, secret []byte, at time.Time) string {
	if codeAt(t, secret, at) == "000000" {
		return "000001"
	}
	return "000000"
}

func (f *fixture) lastIssue(t *testing.T) map[string]any {
	t.Helper()
	recs := eventsOf(f.records(t), decision.EventIssue)
	if len(recs) == 0 {
		t.Fatal("no issue record")
	}
	return recs[len(recs)-1]
}

func signInOf(rec map[string]any) map[string]any { m, _ := rec["sign_in"].(map[string]any); return m }

func (f *fixture) outcome(o string) float64 { return testutil.ToFloat64(f.b.Metrics.SignIns.WithLabelValues(o)) }

// counted is the attempts held under key, cleared as it is read.
func (f *fixture) counted(t *testing.T, key string) int {
	t.Helper()
	n, err := f.b.Store.ClearSignInAttempts(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

const aliceSource = "source:192.0.2.1/32"

// The whole path: the code, then the password, then 9b's certificate,
// recorded with auth.directory_password; the principal's count cleared,
// the source's attempt taken back, the step taken.
func TestASignInIsIssuedACertificate(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now),
		CSR: csrOf(t, newECKey(t))})
	if w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	var resp api.IssueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(resp.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	s, err := issuer.ReadSignIn(cert)
	if err != nil || s.Method != issuer.MethodDirectoryPassword || s.Principal != alicePrincipal ||
		s.Subject != issuer.EntrySubject("uuid:alice") || !slices.Equal(s.AMR, []string{"pwd", "otp"}) || s.Issuer != "" {
		t.Fatalf("%+v %v", s, err)
	}
	if dir.bindCount() != 1 || resp.Principal != alicePrincipal {
		t.Fatalf("%d binds, principal %s", dir.bindCount(), resp.Principal)
	}
	rec := f.lastIssue(t)
	auth, _ := rec["auth"].(map[string]any)
	dp, _ := auth["directory_password"].(map[string]any)
	if rec["verdict"] != "permit" || rec["reason"] != "certificate_issued" || dp == nil || auth["oidc"] != nil ||
		dp["entry_sha256"] != strings.TrimPrefix(issuer.EntrySubject("uuid:alice"), "entry-sha256:") ||
		signInOf(rec)["source"] != "192.0.2.1/32" || signInOf(rec)["failed"] != nil {
		t.Fatalf("%v", rec)
	}
	if n := f.counted(t, "principal:"+alicePrincipal); n != 0 {
		t.Fatalf("the principal's count holds %d", n)
	}
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("the source's count holds %d", n)
	}
	got, _ := f.b.Enrollments.GetSecondFactor(context.Background(), alicePrincipal)
	if got.LastStep != f.now.Unix()/30 || f.outcome("issued") != 1 {
		t.Fatalf("step %d, issued %v", got.LastStep, f.outcome("issued"))
	}
}

// The code before the password (D4): a wrong code never reaches the directory.
func TestAWrongCodeNeverReachesTheDirectory(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: wrongCode(t, secret, f.now),
		CSR: csrOf(t, newECKey(t))})
	if w.Code != 401 || apiError(w) != "sign_in_refused" || dir.bindCount() != 0 ||
		signInOf(f.lastIssue(t))["failed"] != "second_factor" || f.outcome("refused") != 1 {
		t.Fatalf("%s, %d binds", shown(w), dir.bindCount())
	}
}

// One answer for a wrong name, password or code (ruling 7); the record
// says which, and names no principal for an unknown name.
func TestOneRefusalForTheThree(t *testing.T) {
	var bodies []string
	for _, tc := range []struct {
		name, password string
		rightCode      bool
		failed         string
		principal      any
	}{
		{"nobody", "right", true, "name", nil},
		{"alice", "wrong", true, "password", alicePrincipal},
		{"alice", "right", false, "second_factor", alicePrincipal},
	} {
		f, _ := newSignInFixture(t)
		secret := f.enrolled(t, alicePrincipal, "uuid:alice")
		code := codeAt(t, secret, f.now)
		if !tc.rightCode {
			code = wrongCode(t, secret, f.now)
		}
		w := f.signIn(t, api.SignInRequest{Name: tc.name, Password: tc.password, Code: code, CSR: csrOf(t, newECKey(t))})
		rec := f.lastIssue(t)
		if w.Code != 401 || apiError(w) != "sign_in_refused" || rec["reason"] != "sign_in_refused" ||
			signInOf(rec)["failed"] != tc.failed || rec["principal"] != tc.principal {
			t.Fatalf("%s: %s %v", tc.failed, shown(w), rec)
		}
		bodies = append(bodies, w.Body.String())
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("the three answers differ:\n%s", strings.Join(bodies, "\n"))
	}
}

// A name that maps to no entry never reaches an answer, a line, a record or
// the store, hashed included, even when the directory's error carries it
// (Review Focus 2; I13).
func TestAnUnknownNameIsNeverLogged(t *testing.T) {
	const typed = "hunter2-typed-at-the-name-prompt"
	sum := sha256.Sum256([]byte(typed))
	for _, down := range []bool{false, true} {
		f, dir := newSignInFixture(t)
		dir.setDown(down)
		w := f.signIn(t, api.SignInRequest{Name: typed, Password: "x", Code: "123456", CSR: csrOf(t, newECKey(t))})
		if w.Code == 200 || strings.Contains(w.Body.String(), typed) || strings.Contains(f.log.String(), typed) ||
			strings.Contains(f.log.String(), fmt.Sprintf("%x", sum)) {
			t.Fatalf("down %v: the name typed reached the answer or the log", down)
		}
		if ps, _ := f.b.Enrollments.SecondFactorPrincipals(context.Background()); len(ps) != 0 {
			t.Fatal("a record was written for it")
		}
	}
}

// Nothing secret reaches a record, an answer other than the person's own
// 202, or a line: the password, the code, the secret, the URI, the handle.
func TestNoSecretIsLogged(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	const password = "correct-horse-battery-staple"
	f.b.SignInDirectory.(*fakeDir).people["alice"] = fakePerson{password: password,
		entry: f.b.SignInDirectory.(*fakeDir).people["alice"].entry}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: password, CSR: csrOf(t, newECKey(t))})
	var er api.EnrollResponse
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &er) != nil || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s", shown(w))
	}
	u, _ := url.Parse(er.Enroll.URI)
	b32 := u.Query().Get("secret")
	secret, _ := totp.DecodeSecret(b32)
	code := codeAt(t, secret, f.now)
	if w := f.confirm(t, api.ConfirmRequest{Handle: er.Enroll.Handle, Code: code, CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	f.advance(time.Minute)
	w = f.signIn(t, api.SignInRequest{Name: "alice", Password: password, Code: "999999", CSR: csrOf(t, newECKey(t))})
	for _, s := range []string{password, code, b32, er.Enroll.URI, er.Enroll.Handle, "otpauth"} {
		if strings.Contains(f.log.String(), s) || strings.Contains(w.Body.String(), s) {
			t.Fatalf("%q reached the log or a later answer", s)
		}
	}
}

// An empty password is refused before the directory, and counted against
// the source (Review Focus 1; M7).
func TestAnEmptyPasswordIsRefusedAndCounted(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "   ", Code: "123456", CSR: csrOf(t, newECKey(t))})
	rec := f.lastIssue(t)
	if w.Code != 401 || apiError(w) != "sign_in_refused" || dir.bindCount() != 0 || dir.searchCount() != 0 ||
		signInOf(rec)["failed"] != "password" || rec["principal"] != nil {
		t.Fatalf("%s %v", shown(w), rec)
	}
	if n := f.counted(t, aliceSource); n != 1 {
		t.Fatalf("the source counted %d", n)
	}
}

// Throttled: the sixth failure for a principal is 429 with Retry-After and
// the unlock command, names no principal, checks nothing, and the held
// certificate still mints (I3).
func TestThePrincipalLimit(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	bad := wrongCode(t, secret, f.now)
	for i := range 5 {
		if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: bad, CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
			t.Fatalf("attempt %d: %s", i+1, shown(w))
		}
	}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 429 || apiError(w) != "sign_in_throttled" || w.Header().Get("Retry-After") == "" ||
		!strings.Contains(shown(w), "port49 directory unlock") || strings.Contains(w.Body.String(), "alice@example.com") ||
		signInOf(f.lastIssue(t))["failed"] != "principal_limit" || dir.bindCount() != 0 || f.outcome("throttled") != 1 {
		t.Fatalf("%s", shown(w))
	}
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("a holder's mint: %s", shown(w))
	}
}

// The source limit, before any directory call; 0 turns it off and writes
// no count (M6).
func TestTheSourceLimit(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.PasswordSignIn.FailuresPerSource = 3
	for i := range 3 {
		if w := f.signIn(t, api.SignInRequest{Name: fmt.Sprintf("nobody%d", i), Password: "x", Code: "123456",
			CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
			t.Fatalf("%s", shown(w))
		}
	}
	searches := dir.searchCount()
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 429 || signInOf(f.lastIssue(t))["failed"] != "source_limit" || dir.searchCount() != searches {
		t.Fatalf("%s", shown(w))
	}
	f, dir = newSignInFixture(t)
	f.b.PasswordSignIn.FailuresPerSource = 0
	for i := range 10 {
		if w := f.signIn(t, api.SignInRequest{Name: fmt.Sprintf("nobody%d", i), Password: "x", Code: "123456",
			CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
			t.Fatalf("off, attempt %d: %s", i+1, shown(w))
		}
	}
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("off, yet counted %d (M6)", n)
	}
}

// Fifty parallel wrong codes judge at most five (Review Focus 3).
func TestParallelAttemptsCannotPassThePrincipalLimit(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.PasswordSignIn.FailuresPerSource = 0
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	bad := wrongCode(t, secret, f.now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: bad, CSR: csrOf(t, newECKey(t))})
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[401] > 5 || codes[401]+codes[429] != 50 || dir.bindCount() != 0 {
		t.Fatalf("%v, %d binds", codes, dir.bindCount())
	}
}

// signInStoreDown fails every attempt count.
type signInStoreDown struct{ store.Store }

func (signInStoreDown) NoteSignInAttempt(context.Context, string, time.Duration) (int, time.Time, error) {
	return 0, time.Time{}, store.ErrUnavailable
}

// A store that does not answer refuses, 503 store_unavailable, nothing checked.
func TestAStoreErrorRefusesTheSignIn(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.Store = signInStoreDown{f.b.Store}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "store_unavailable" || dir.searchCount() != 0 || dir.bindCount() != 0 ||
		f.outcome("store_unavailable") != 1 {
		t.Fatalf("%s", shown(w))
	}
}

// The 3am case (owner's ruling 4): the directory down, a sign-in is 503
// directory_unavailable saying anyone signed in keeps working, and a held
// directory-sign-in certificate mints.
func TestTheDirectoryDownSignInSaysSoAndHoldersMint(t *testing.T) {
	f, dir := newSignInFixture(t)
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	dir.setDown(true)
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "directory_unavailable" || !strings.Contains(shown(w), "keeps working") ||
		w.Header().Get("Retry-After") == "" || f.outcome("directory_unavailable") != 1 {
		t.Fatalf("%s", shown(w))
	}
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("a holder's mint: %s", shown(w))
	}
}

// A phone's clock off by 90s: refused, the skew said, counted, nothing
// bound; by 30s: accepted.
func TestAClockOffIsSaid(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now.Add(-90*time.Second)),
		CSR: csrOf(t, newECKey(t))})
	rec := f.lastIssue(t)
	if w.Code != 401 || !strings.Contains(shown(w), "about 2 minutes off") || dir.bindCount() != 0 ||
		signInOf(rec)["failed"] != "second_factor_skew" || signInOf(rec)["skew_seconds"] != float64(-90) {
		t.Fatalf("%s %v", shown(w), rec)
	}
	f.advance(30 * time.Second)
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now.Add(-30*time.Second)),
		CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("30s off: %s", shown(w))
	}
}

// A code taken once; two sign-ins racing one code issue once and reach the
// directory once (Review Focus 5; I1).
func TestTwoSignInsWithOneCodeIssueOnce(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:alice")
	code := codeAt(t, secret, f.now)
	var wg sync.WaitGroup
	got := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got <- f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: code, CSR: csrOf(t, newECKey(t))}).Code
		}()
	}
	wg.Wait()
	close(got)
	var codes []int
	for c := range got {
		codes = append(codes, c)
	}
	slices.Sort(codes)
	if !slices.Equal(codes, []int{200, 401}) || dir.bindCount() != 1 {
		t.Fatalf("%v, %d binds", codes, dir.bindCount())
	}
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: code, CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
		t.Fatalf("a replay: %s", shown(w))
	}
}

// unreadableEnrollments answers GetSecondFactor as a record under a key
// no one holds does, and records any write.
type unreadableEnrollments struct {
	store.Enrollments
	wrote bool
}

func (u *unreadableEnrollments) GetSecondFactor(context.Context, string) (store.SecondFactor, error) {
	return store.SecondFactor{}, errors.New("crypt: opening second factor: crypt: sealed under an unknown key")
}

func (u *unreadableEnrollments) SwapSecondFactor(context.Context, store.SecondFactor, uint64) error {
	u.wrote = true
	return nil
}

// A record that will not open refuses, 503, naming reset-second-factor,
// and never reads as "not enrolled" (Review Focus 4).
func TestAnUnreadableSecondFactorRefusesTheSignIn(t *testing.T) {
	f, dir := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour) // a window is open: "not enrolled" would enroll
	u := &unreadableEnrollments{Enrollments: f.b.Enrollments}
	f.b.Enrollments = u
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "store_unavailable" || !strings.Contains(shown(w), "reset-second-factor") ||
		dir.bindCount() != 0 || u.wrote {
		t.Fatalf("%s, %d binds, wrote %v", shown(w), dir.bindCount(), u.wrote)
	}
}

// A second factor of another entry refuses with the one sentence, and the
// broker's log names reset-second-factor (ruling 12; I12).
func TestASecondFactorOfAnotherEntryRefuses(t *testing.T) {
	f, dir := newSignInFixture(t)
	secret := f.enrolled(t, alicePrincipal, "uuid:old")
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 401 || apiError(w) != "sign_in_refused" || strings.Contains(w.Body.String(), "another directory entry") ||
		!strings.Contains(f.log.String(), "reset-second-factor") || dir.bindCount() != 0 ||
		signInOf(f.lastIssue(t))["failed"] != "second_factor" {
		t.Fatalf("%s", shown(w))
	}
}

// The directory's state, past the code, is said (ruling 7); with a wrong
// code it is never reached.
func TestTheDirectoryStateIsSaidPastTheCode(t *testing.T) {
	for data, words := range map[string]string{"532": "expired", "773": "must be changed", "533": "disabled",
		"775": "locked"} {
		f, dir := newSignInFixture(t)
		secret := f.enrolled(t, alicePrincipal, "uuid:alice")
		dir.state = data
		w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
		rec := signInOf(f.lastIssue(t))
		if w.Code != 401 || !strings.Contains(shown(w), words) || rec["failed"] != "directory_state" ||
			rec["directory_result"] != float64(49) || rec["directory_data"] != data {
			t.Fatalf("%s: %s %v", data, shown(w), rec)
		}
		f.advance(time.Minute)
		w = f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: wrongCode(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
		if strings.Contains(shown(w), words) {
			t.Fatalf("%s said without the code", data)
		}
	}
}

// enrollAlice is a 202 for alice with the right password, and the secret
// its URI carries.
func enrollAlice(t *testing.T, f *fixture) (api.Enrollment, []byte) {
	t.Helper()
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))})
	var er api.EnrollResponse
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &er) != nil {
		t.Fatalf("%s", shown(w))
	}
	u, err := url.Parse(er.Enroll.URI)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("%q", er.Enroll.URI)
	}
	secret, err := totp.DecodeSecret(u.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return er.Enroll, secret
}

// Enrollment: inside the new-entry window, the right password answers 202
// with a URI and a handle, nothing issued or recorded; confirm with the
// first code issues, records enroll permit second_factor_enrolled, and the
// record is active with enrolled_from the source.
func TestANewEntryEnrolls(t *testing.T) {
	f, dir := newSignInFixture(t)
	p := dir.people["alice"]
	p.entry.CreatedAt = f.now.Add(-time.Hour)
	dir.people["alice"] = p
	e, secret := enrollAlice(t, f)
	if e.Handle == "" || e.ConfirmBy != decision.FormatTime(f.now.Add(10*time.Minute)) ||
		len(eventsOf(f.records(t), decision.EventIssue)) != 0 || f.outcome("enrollment_started") != 1 {
		t.Fatalf("%+v", e)
	}
	w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))})
	if w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	enr := eventsOf(f.records(t), decision.EventEnroll)
	if len(enr) != 1 || enr[0]["verdict"] != "permit" || enr[0]["reason"] != "second_factor_enrolled" ||
		signInOf(enr[0])["source"] != "192.0.2.1/32" || f.lastIssue(t)["reason"] != "certificate_issued" {
		t.Fatalf("%v", enr)
	}
	got, err := f.b.Enrollments.GetSecondFactor(context.Background(), alicePrincipal)
	if err != nil || got.State != store.SecondFactorActive || got.EnrolledFrom != "192.0.2.1/32" ||
		got.EntryID != "uuid:alice" || got.LastStep != f.now.Unix()/30 || f.outcome("enrolled") != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

// The rollout window, a reopened record, and reset --all's window each open
// enrollment; outside every window any password is 403 enrollment_closed
// and nothing is bound (C5).
func TestEnrollmentWindows(t *testing.T) {
	ctx := context.Background()
	for name, open := range map[string]func(f *fixture){
		"rollout": func(f *fixture) { f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour) },
		"reopened": func(f *fixture) {
			_ = f.b.Enrollments.SwapSecondFactor(ctx, store.SecondFactor{Principal: alicePrincipal,
				State: store.SecondFactorReopened, Until: f.now.Add(time.Hour)}, 0)
		},
		"reset --all": func(f *fixture) {
			_ = f.b.Enrollments.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: f.now, ReopenAllUntil: f.now.Add(time.Hour)})
		},
	} {
		f, _ := newSignInFixture(t)
		open(f)
		if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))}); w.Code != 202 {
			t.Fatalf("%s: %s", name, shown(w))
		}
	}
	for _, pw := range []string{"right", "wrong"} {
		f, dir := newSignInFixture(t)
		w := f.signIn(t, api.SignInRequest{Name: "alice", Password: pw, CSR: csrOf(t, newECKey(t))})
		if w.Code != 403 || apiError(w) != "enrollment_closed" || dir.bindCount() != 0 ||
			signInOf(f.lastIssue(t))["failed"] != "enrollment" {
			t.Fatalf("closed, %s password: %s, %d binds", pw, shown(w), dir.bindCount())
		}
	}
}

// A wrong first code puts the handle back; a handle confirms once; an
// expired handle is refused.
func TestTheHandle(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret := enrollAlice(t, f)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: wrongCode(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
		t.Fatalf("a wrong code: %s", shown(w))
	}
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("the handle was not put back: %s", shown(w))
	}
	f.advance(30 * time.Second)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 401 ||
		!strings.Contains(shown(w), "port49 login") {
		t.Fatalf("a handle confirmed twice: %s", shown(w))
	}
	f, _ = newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret = enrollAlice(t, f)
	f.advance(11 * time.Minute)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 401 {
		t.Fatalf("an expired handle: %s", shown(w))
	}
}

// A confirm throttled by the principal's limit keeps its handle (M10):
// after an unlock, the same handle confirms.
func TestAThrottledConfirmKeepsTheHandle(t *testing.T) {
	ctx := context.Background()
	f, _ := newSignInFixture(t)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
	e, secret := enrollAlice(t, f)
	for range 5 {
		if _, _, err := f.b.Store.NoteSignInAttempt(ctx, "principal:"+alicePrincipal, f.b.PasswordSignIn.Window); err != nil {
			t.Fatal(err)
		}
	}
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 429 {
		t.Fatalf("over the limit: %s", shown(w))
	}
	f.counted(t, "principal:"+alicePrincipal)
	if w := f.confirm(t, api.ConfirmRequest{Handle: e.Handle, Code: codeAt(t, secret, f.now), CSR: csrOf(t, newECKey(t))}); w.Code != 200 {
		t.Fatalf("the throttled confirm spent the handle: %s", shown(w))
	}
}

// Two enrollments at once for one principal: whatever each answers, at
// most one handle ever confirms.
func TestTwoEnrollmentsAtOnce(t *testing.T) {
	for range 20 {
		f, _ := newSignInFixture(t)
		f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour)
		f.b.PasswordSignIn.FailuresPerSource = 0
		type got struct {
			e      api.Enrollment
			secret []byte
		}
		var wg sync.WaitGroup
		res := make(chan got, 2)
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))})
				var er api.EnrollResponse
				if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &er) != nil {
					return
				}
				u, _ := url.Parse(er.Enroll.URI)
				s, _ := totp.DecodeSecret(u.Query().Get("secret"))
				res <- got{er.Enroll, s}
			}()
		}
		wg.Wait()
		close(res)
		ok := 0
		for g := range res {
			if f.confirm(t, api.ConfirmRequest{Handle: g.e.Handle, Code: codeAt(t, g.secret, f.now), CSR: csrOf(t, newECKey(t))}).Code == 200 {
				ok++
			}
		}
		if ok > 1 {
			t.Fatalf("%d enrollments confirmed for one principal", ok)
		}
	}
}

// /v1/config says the broker signs in by directory password, with totp.
func TestConfigSaysDirectoryPassword(t *testing.T) {
	f, _ := newSignInFixture(t)
	w := f.call(context.Background(), nil, "GET", "/v1/config", "")
	var c api.Config
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Methods, []string{"directory_password"}) || c.SignIn == nil || c.SignIn.SecondFactor != "totp" ||
		c.Issuance == nil {
		t.Fatalf("%+v", c)
	}
}

// A client certificate at /v1/sign-in is refused; a broker with no verifier
// is 404 not_signing_in; a body with an unknown field is 400 and echoes
// none of it.
func TestSignInRefusesWhatIsNotASignIn(t *testing.T) {
	f, dir := newSignInFixture(t)
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	body, _ := json.Marshal(api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.Leaf}}
	if w := f.call(context.Background(), cs, "POST", "/v1/sign-in", string(body)); w.Code != 400 || dir.searchCount() != 0 {
		t.Fatalf("a client certificate: %s", shown(w))
	}
	f.b.PasswordSignIn = nil
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))}); w.Code != 404 ||
		apiError(w) != "not_signing_in" {
		t.Fatalf("no verifier: %s", shown(w))
	}
	f, _ = newSignInFixture(t)
	w := f.call(context.Background(), nil, "POST", "/v1/sign-in", `{"name":"alice","password":"hunter2-in-a-body","x":1}`)
	if w.Code != 400 || strings.Contains(w.Body.String(), "hunter2") || strings.Contains(f.log.String(), "hunter2") {
		t.Fatalf("an unknown field: %s", shown(w))
	}
}

// D7: a lost enrollment store refuses every password sign-in before
// anything is counted, 503 enrollment_store_lost; a held certificate mints.
func TestALostEnrollmentStoreRefusesOnlyTheSignIn(t *testing.T) {
	f, dir := newSignInFixture(t)
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	f.b.Enrollments = lostEnrollments{}
	if err := f.b.CheckEnrollmentStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", Code: "123456", CSR: csrOf(t, newECKey(t))})
	if w.Code != 503 || apiError(w) != "enrollment_store_lost" || dir.searchCount() != 0 || dir.bindCount() != 0 ||
		f.outcome("enrollment_store_lost") != 1 || f.lastIssue(t)["reason"] != "enrollment_store_lost" {
		t.Fatalf("%s", shown(w))
	}
	if n := f.counted(t, aliceSource); n != 0 {
		t.Fatalf("counted %d", n)
	}
	if testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 0 {
		t.Fatal("the gauge says ok")
	}
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("a holder's mint: %s", shown(w))
	}
}

// lostEnrollments answers the mark ErrEnrollmentStoreLost; nothing else of
// it may be called.
type lostEnrollments struct{ store.Enrollments }

func (lostEnrollments) GetEnrollmentMark(context.Context) (store.EnrollmentMark, error) {
	return store.EnrollmentMark{}, fmt.Errorf("%w: test", store.ErrEnrollmentStoreLost)
}

// D7 and pre-flight I15: no mark is lost whatever the rollout window says,
// and the check never creates one; a mark, once created, clears it.
func TestTheMarkAtStart(t *testing.T) {
	ctx := context.Background()
	f, dir := newSignInFixture(t)
	f.b.Enrollments = memory.NewEnrollments(f.b.Now)
	f.b.PasswordSignIn.OpenUntil = f.now.Add(time.Hour) // the rollout window open: still lost
	if err := f.b.CheckEnrollmentStore(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Enrollments.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the check created a mark: %v", err)
	}
	if f.b.EnrollmentStoreLost() == "" || testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 0 ||
		!strings.Contains(f.log.String(), "init-enrollments") || !strings.Contains(f.log.String(), "reset-second-factor --all") {
		t.Fatalf("no mark read as well: %q", f.b.EnrollmentStoreLost())
	}
	if w := f.signIn(t, api.SignInRequest{Name: "alice", Password: "right", CSR: csrOf(t, newECKey(t))}); w.Code != 503 ||
		apiError(w) != "enrollment_store_lost" || dir.bindCount() != 0 {
		t.Fatalf("%s", shown(w))
	}
	if err := f.b.Enrollments.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := f.b.CheckEnrollmentStore(ctx); err != nil || f.b.EnrollmentStoreLost() != "" ||
		testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 1 {
		t.Fatalf("a mark, still lost: %v %q", err, f.b.EnrollmentStoreLost())
	}
}

// downEnrollments does not answer.
type downEnrollments struct{ store.Enrollments }

func (downEnrollments) GetEnrollmentMark(context.Context) (store.EnrollmentMark, error) {
	return store.EnrollmentMark{}, store.ErrUnavailable
}

// A store that does not answer is not lost: the check returns its error,
// and the state and the gauge stay as they were (the next pass looks again).
func TestAnEnrollmentStoreThatDoesNotAnswerIsNotLost(t *testing.T) {
	f, _ := newSignInFixture(t)
	f.b.Enrollments = downEnrollments{}
	if err := f.b.CheckEnrollmentStore(context.Background()); !errors.Is(err, store.ErrUnavailable) ||
		f.b.EnrollmentStoreLost() != "" || testutil.ToFloat64(f.b.Metrics.DirectoryEnrollmentStoreOK) != 1 {
		t.Fatalf("%v %q", err, f.b.EnrollmentStoreLost())
	}
}
```

  Every refusal test checks the record's `reason` and `sign_in.failed` and the outcome where it
  names one.

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./internal/broker/ -run 'SignIn|Enroll|Handle|Limit|Clock|OneCode|Unreadable|AnotherEntry|DirectoryState|DirectoryDown|Config|Refusal|Logged|EmptyPassword|StoreError|Lost|Mark|DoesNotAnswer'`
Expected: FAIL (`undefined: api.SignInRequest`).

- [ ] **Step 3: Factor `issueTo` out of `issue`.** `issueTo` is `issue`'s tail from
  `b.Issuer.Issue(…)` through the response: the CA's signing fault (503 `issuance_unavailable`,
  unrecorded) and the permit. `CanIssue` stays in each caller, before anything is spent: `issue`
  keeps it where it is (`issue.go` ~160, before `PutOnce` ~178, so a CA fault leaves the ID token
  unspent, as 9b rules); the directory sign-in calls it once the entry is known (it needs the
  principal) and before the TOTP step is taken (I1). `issue` calls `issueTo` with `sign`, `c.auth()`
  and nil `extra` after its own `PutOnce` and `noteOwner`. The principal is `sign.Principal`; there
  is no separate parameter. Run `go test ./internal/broker/ -run Issue` before going on: unchanged.

- [ ] **Step 4: Implement `signin.go`.** The handler, in the order the rulings fix:

```go
// signIn is POST /v1/sign-in (plan 9e; spec §13 decision 47): a person's
// directory name, password and TOTP code, exchanged for 9b's certificate,
// or, for a person with no second factor inside a window, an enrollment.
// The order is ruling D4's: the source's limit, the entry, the principal's
// limit, the code (its step taken), the password. A lost enrollment store
// refuses before anything is counted or read (D7). Nothing in the body is
// ever echoed or logged.
func (b *Broker) signIn(w http.ResponseWriter, r *http.Request) {
	cfg := b.PasswordSignIn
	if cfg == nil || b.Issuer == nil || b.SignInDirectory == nil {
		writeError(w, http.StatusNotFound, "not_signing_in", "this broker takes no directory password "+
			"(broker.identity has no directory_password verifier)")
		return
	}
	now, src := b.Now(), sourcePrefix(r.RemoteAddr)
	s := &signInAttempt{b: b, w: w, now: now, src: src}
	if why := b.EnrollmentStoreLost(); why != "" {
		s.storeLost() // 503 enrollment_store_lost, recorded and counted; nothing read or counted (D7)
		return
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "a sign-in carries no client certificate")
		return
	}
	var req api.SignInRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `the body is not a sign-in: {"name", "password", "code", "csr"}`)
		return
	}
	pub, ok := s.csrKey(req.CSR) // 400 on a bad CSR, before anything is counted
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	if !s.underSourceLimit(ctx, cfg) {
		return
	}
	if !printableName(req.Name) {
		s.refuse("name", nil)
		return
	}
	if strings.TrimSpace(req.Password) == "" { // never sent (Review Focus 1); no principal is known yet (M7)
		s.refuse("password", nil)
		return
	}
	e, ok := s.entry(ctx, req.Name, cfg)
	if !ok {
		return
	}
	if !s.underPrincipalLimit(ctx, cfg, e.Principal) {
		return
	}
	f, err := b.Enrollments.GetSecondFactor(ctx, e.Principal)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && f.State != store.SecondFactorActive:
		s.enrollOrRefuse(ctx, cfg, e, f, err == nil, req.Password, pub)
		return
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		s.storeLost()
		return
	case err != nil:
		s.storeUnavailable(e.Principal, "second factor", "the broker could not read your second factor; "+
			"if this recurs, an operator runs `port49 directory reset-second-factor` for your account")
		return
	case f.EntryID != e.EntryID:
		// The one sentence to the caller (ruling 7); the broker's line, once an
		// hour, names the entries and reset-second-factor (ruling 12, I12).
		s.entryMoved(e, f.EntryID)
		return
	}
	if !s.issuable(e) { // CanIssue with the principal, before the step is taken (C3)
		return
	}
	step, err := totp.Check(f.Secret, req.Code, now, f.LastStep)
	var skew *totp.Skewed
	switch {
	case errors.As(err, &skew):
		s.refuseSkew(e, skew.By)
		return
	case err != nil:
		s.refuseAs(e, "second_factor", "")
		return
	}
	// The step is taken before the password is tried (decision 47 ruling 5):
	// a code is one attempt at the password, whatever its answer, and two
	// sign-ins racing one code reach the directory once.
	f.LastStep = step
	switch err := b.Enrollments.SwapSecondFactor(ctx, f, f.Rev); {
	case errors.Is(err, store.ErrConflict):
		s.refuseAs(e, "second_factor", "")
		return
	case err != nil:
		s.storeUnavailable(e.Principal, "second factor", "") // 503 store_unavailable (I2)
		return
	}
	if !s.password(ctx, e, req.Password) {
		return
	}
	s.succeeded(ctx, e.Principal)
	s.issue(pub, e)
}
```

  `signInAttempt` holds the request's state and every answer; each refusal emits one record
  (`issue` deny, `Auth: &decision.Auth{Method: "directory_password"}`, `Principal` when known,
  `SignIn: &decision.SignIn{Source: src, Failed: …}`), counts `SignIns`, and writes the API error
  with ruling 7's words. `storeLost` (D7) is C1's answer: the `issue deny enrollment_store_lost`
  record (`Auth: &decision.Auth{Method: "directory_password"}`, `SignIn: {Source}`),
  `enrollment_store_lost` counted, `Retry-After: 300`, and `503 enrollment_store_lost`: "the
  broker's store of second factors is missing or unreadable, so no one can sign in with a
  password until an operator creates or restores it (the broker's log says which); anyone
  already signed in keeps working until their certificate ends".
  `underSourceLimit`, with `cfg.FailuresPerSource > 0` (0 is off: no count is written, and
  `succeeded` undoes none, M6), calls `NoteSignInAttempt("source:"+src, cfg.Window)` and, with the
  count above the limit, answers `429 sign_in_throttled`, `Retry-After` the seconds to the window's
  end, "too many failed sign-ins from this address; try again after <end, RFC 3339>"; a store error
  is `503 store_unavailable`. `underPrincipalLimit` the same on `"principal:"+principal`, the words
  "too many failed sign-ins for this account; try again after <end>, or an operator can clear it
  with `port49 directory unlock` for your account" — the principal is never named to the caller
  (I3). `entry` maps `directory.ErrUnavailable` to `503 directory_unavailable` (ruling 7's words,
  `Retry-After: 30`), `ErrAmbiguous` to a record `identity_ambiguous` and the answer
  `sign_in_refused`, anything else and a principal outside `cfg.PrincipalDomains` to `failed:
  name` with **no principal and no name** in the record. `entry` never puts `err.Error()` from
  `SignInEntry` in a line, a record or an answer: `Pool.Do` wraps the server's diagnostic, which
  may echo the filter and so the typed name (R8). It logs the class alone (`directory_unavailable`,
  `identity_ambiguous`, `name`); for `ErrAmbiguous` the DNs come from entries, not the name (I13).
  `entryMoved` records `failed: second_factor` with the principal, answers the one
  `sign_in_refused` sentence, and says once an hour (`sayOnce`): "broker: sign-in: %s's second
  factor was enrolled for entry %s, and the directory now gives %s: an operator runs `port49
  directory reset-second-factor %s`" (entry ids, never secrets; I12). `issuable(e)` builds the
  sign-in `issue` will (below) and calls `b.Issuer.CanIssue`, answering as `issue.go` does
  (`ErrNotCertifiable` 401 `sign_in_not_certifiable`, recorded; otherwise 503
  `issuance_unavailable`, unrecorded). `password` calls `CheckPassword(ctx, e.Server, e.DN,
  password)`: `ErrUnavailable` is 503; a `PasswordRefusal` with `State()` is `failed:
  directory_state`, `directory_result` and `directory_data` recorded, the answer naming the state;
  any other refusal `failed: password`. `succeeded` calls `ClearSignInAttempts` on the principal's
  key and, with the source limit on, `UndoSignInAttempt` on the source's (a store error there is
  logged, never a refusal: the person is signed in). `issue` builds `issuer.SignIn{Method:
  issuer.MethodDirectoryPassword, Principal: e.Principal, Subject: issuer.EntrySubject(e.EntryID),
  AMR: []string{"pwd", "otp"}, AuthTime: now, IssuedAt: now}` and calls `issueTo` with
  `auth.directory_password` and `sign_in: {source}`.

  `enrollOrRefuse` decides whether a window is open first (C5): `cfg.OpenUntil.After(now)`;
  `cfg.NewEntriesFor > 0 && !e.CreatedAt.IsZero() && now.Before(e.CreatedAt.Add(cfg.NewEntriesFor))`;
  the record `reopened` with `Until` after now; or, those closed, the mark's `ReopenAllUntil` after
  now (one `GetEnrollmentMark`, on this path alone; `ErrEnrollmentStoreLost` is `storeLost`, any
  other error 503 `store_unavailable`). None: `403 enrollment_closed` with **no bind** ("you have
  no second factor, and enrollment is closed for you: ask an operator to run `port49 directory
  reset-second-factor` for your account"), recorded `failed: enrollment`, counted as a failure (it
  was counted before it was judged; it is not taken back). Open: the password is checked (an
  enrolling person has only it), then `issuable(e)`, then: `until := now.Add(10 * time.Minute)`,
  computed once (M14); a new secret; the record `pending` with `Until: until`, `EntryID`, swapped
  at the revision read (0 when none; a conflict is `sign_in_refused`); a handle of 32 random bytes
  put with `PutOnce("enroll_handle "+hex(sha256(handle)), []byte(principal), until.Sub(now))`; and
  `202 {enroll: {handle, otpauth_uri: totp.URI(secret, label, principal without "user:"),
  confirm_by: decision.FormatTime(until)}}` with `Cache-Control: no-store` (M8), counted
  `enrollment_started`, recording nothing (M13). The label is `cfg.TOTPLabel`.

  `signInConfirm` (`POST /v1/sign-in/confirm`): the same lost-store check, body rules, CSR check
  and source limit; `TakeOnce` of the handle's key (missing: `sign_in_refused`, "this enrollment
  ended or was confirmed; run `port49 login` again"); `GetSecondFactor` for the principal it held;
  the record must be `pending` and before `Until`; the principal's limit — over it, the handle is
  put back with `PutOnce` for `f.Until − now` before the 429 (M10); `issuable` for the record's
  entry — a CA fault puts the handle back the same way; `totp.Check(f.Secret, code, now, 0)`: a
  wrong code puts the handle back the same way and refuses; right, the record becomes `active`
  (`LastStep`, `EnrolledAt: now`, `EnrolledFrom: src`) by compare-and-swap (`ErrConflict`
  `sign_in_refused`, another error 503 `store_unavailable`), `enroll permit
  second_factor_enrolled` is recorded with `auth.directory_password`, `enrolled` counted, the
  principal's count cleared, and the certificate issued as `signIn` issues it. The entry for the
  certificate's `sub` is the record's `EntryID`.

  `sourcePrefix`: `netip.ParseAddrPort(remoteAddr)`; IPv4 (or 4-in-6 unmapped) `/32`, IPv6
  `netip.PrefixFrom(addr, 64).Masked()`; unparseable is `"unknown"`.

  `CheckEnrollmentStore` (in `signin.go`): `GetEnrollmentMark`; ok → lost cleared, gauge
  `WithLabelValues().Set(1)`; `ErrNotFound` or `ErrEnrollmentStoreLost` → lost set to the why,
  gauge 0, one error line (said once per state change): "broker: the enrollment store <where> is
  lost (<why>): password sign-in is refused until an operator acts. On a new install run `port49
  directory init-enrollments` once; if this broker has enrolled people, restore the store (`port49
  directory import`, or the etcd snapshot) or run `port49 directory reset-second-factor --all`";
  any other error → returned, nothing changed. It never writes the store. The lost state is under
  a mutex (`EnrollmentStoreLost` is read on every sign-in).

  In `broker.go`: the routes `mux.HandleFunc("POST /v1/sign-in", b.signIn)` and `mux.HandleFunc("POST
  /v1/sign-in/confirm", b.signInConfirm)`; in `config`, with `b.PasswordSignIn != nil`, `c.Methods =
  append(c.Methods, "directory_password")` and `c.SignIn = &api.SignInConfig{SecondFactor: "totp"}`.

- [ ] **Step 5: Run to verify they pass.**

Run: `go test ./internal/broker/ -race -v -run 'SignIn|Enroll|Handle|Limit|Clock|OneCode|Unreadable|AnotherEntry|DirectoryState|DirectoryDown|Config|Refusal|Logged|EmptyPassword|StoreError|Lost|Mark|DoesNotAnswer' && go test ./internal/broker/`
Expected: PASS, the whole package.

- [ ] **Step 6: Mutations.** Swap the code check and the password check; take the step after the
  password (I1: `TestTwoSignInsWithOneCodeIssueOnce` sees two binds); check the password before the
  window in `enrollOrRefuse` (C5: `TestEnrollmentWindows`); drop the principal limit's
  `NoteSignInAttempt` (judge before counting); make a `GetSecondFactor` error read as not found;
  skip the lost-store check; log `req.Name` in `refuse`, and `err.Error()` in `entry`. Each must
  turn a named test red. Record which in the report, then restore.

- [ ] **Step 7: Commit.**

```bash
git add internal/broker
git commit -m "feat: POST /v1/sign-in and /v1/sign-in/confirm, the directory-password sign-in

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Re-seal, reset, unlock, init, export and import; port49d's wiring

**Files:**
- Create: `internal/broker/signin_admin.go`, `internal/broker/signin_admin_test.go`
- Modify: `internal/broker/scheduled.go` (`RefreshDirectory` calls `CheckEnrollmentStore` and the
  re-seal pass)
- Modify: `internal/daemon/admin/admin.go` (ops `second_factor_reset`, `sign_in_unlock`,
  `enrollments_init`, `enrollments_export`, `enrollments_import`; `Request`, `Response` and
  `Server` fields; the import body after the request line), `internal/port49d/revocations.go`
  (`adminSecondFactorReset`, `adminSignInUnlock`, `adminEnrollmentsInit`,
  `adminEnrollmentsExport`, `adminEnrollmentsImport`), `internal/port49d/brokerd.go` (~568) and
  `internal/port49d/main.go` (~353–390, ~1276: the broker's `PasswordSignIn`, `SignInDirectory`,
  `Enrollments`, the label's default, the start line), `internal/port49d/statedir_linux.go`
  (`ownStateDir`'s names gain `enrollments.json`, M5)
- Modify: `cmd/port49/directory.go` (`reset-second-factor [--all]`, `unlock`, `init-enrollments`,
  `export`, `import [--replace]`)
- Test: `internal/daemon/admin/admin_test.go`, `cmd/port49/directory_linux_test.go`,
  `internal/port49d/brokerd_test.go`

**Interfaces:**
- Produces:

```go
func (b *Broker) ResealSecondFactors(ctx context.Context) (int, error)
// ResetSecondFactor with all (principal "") is --all: it drops no active
// factor, puts the mark {CreatedAt: kept or now, ReopenAllUntil: now +
// ReopenFor} (replacing a lost store, its unreadable file renamed aside),
// clears lost, and records second_factor_reset {"all": true}.
func (b *Broker) ResetSecondFactor(ctx context.Context, principal string, all bool, origin string) (string, error)
func (b *Broker) UnlockSignIn(ctx context.Context, principal, origin string) (string, error)
// InitEnrollments is init-enrollments (D7): CreateEnrollmentMark{CreatedAt:
// now}; ErrConflict is refused ("the enrollment store is already there:
// ..."); it records second_factor_reset {"created": true}, then
// CheckEnrollmentStore.
func (b *Broker) InitEnrollments(ctx context.Context, origin string) (string, error)
func (b *Broker) ExportEnrollments(ctx context.Context) ([]byte, error)
// ImportEnrollments records enrollments_import and runs CheckEnrollmentStore.
func (b *Broker) ImportEnrollments(ctx context.Context, sealed []byte, replace bool, origin string) (string, error)

// admin.Request gains:
//   All     bool `json:"all,omitempty"`     // second_factor_reset for every entry (D7)
//   Replace bool `json:"replace,omitempty"` // enrollments_import over a later store (D13)
// admin.Response gains:
//   Sealed []byte `json:"sealed,omitempty"` // enrollments_export's body, base64 in JSON
// enrollments_import's request line is followed on the connection by the
// sealed body, at most 64 MiB (maxImport); every other op stays within
// maxRequest (4096). enrollments_export's response is bounded the same.
// admin.Server gains:
//   SecondFactorReset func(ctx context.Context, principal string, all bool, uid uint32) (string, error)
//   SignInUnlock      func(ctx context.Context, principal string, uid uint32) (string, error)
//   EnrollmentsInit   func(ctx context.Context, uid uint32) (string, error)
//   EnrollmentsExport func(ctx context.Context, uid uint32) ([]byte, error)
//   EnrollmentsImport func(ctx context.Context, sealed []byte, replace bool, uid uint32) (string, error)
```

- [ ] **Step 1: Write the failing tests.** In `signin_admin_test.go`, over Task 9's
  `newSignInFixture`:

```go
// The re-seal pass rewrites a record that opened under the previous key,
// and leaves a current one (ruling 11).
func TestTheReSealPassSealsStaleRecords(t *testing.T) /* an Enrollments wrapper whose
	GetSecondFactor marks one record Stale; after ResealSecondFactors, that one was swapped (its
	Rev moved) and the other untouched; a record that will not open is counted and said once,
	never deleted */

// Reset makes the record reopened for reopen_for with no secret, prints
// what it removed, and records second_factor_reset with the origin; a
// sign-in then enrolls (the lost phone at 3am).
func TestResetReopensEnrollment(t *testing.T)

// D7: lost → reset --all → the unreadable file sits beside the new one,
// the gauge reads 1, an enroll for an old entry answers 202, an active
// factor is untouched, and second_factor_reset {"all": true} is recorded.
// Over an enrollfile in t.TempDir() with a tampered body.
func TestResetAllReplacesALostStoreAndOpensTheWindow(t *testing.T)

// D7, I15: init-enrollments on an empty store creates the mark, clears
// lost, sets the gauge 1, records second_factor_reset {"created": true}
// with no principal; a second run is refused and writes nothing; on a
// tampered file, or a store holding records with no mark, it is refused
// naming import and reset-second-factor --all.
func TestInitEnrollmentsCreatesTheStoreOnce(t *testing.T)

// D13: an export holds no secret or entry id in the clear; import into an
// empty store restores sign-in; import without replace over a later
// enrollment is refused naming --replace; with replace it replaces;
// enrollments_import is recorded.
func TestExportImport(t *testing.T)

// Unlock clears the principal's count and records sign_in_unlock with the
// count it held; the next sign-in is judged.
func TestUnlockClearsTheCount(t *testing.T)

// The admin socket's ops: a process with no broker says where they run;
// an empty principal is refused for second_factor_reset without all and
// for sign_in_unlock; an import body over maxImport is refused; the
// unknown-op line lists all nine ops.
func TestTheSignInAdminOps(t *testing.T) // admin_test.go

// `port49 directory reset-second-factor [--all]`, `unlock`,
// `init-enrollments`, `export` and `import [--replace]` over the socket:
// no secret on stdout's text; export to a terminal is refused ("redirect
// it to a file"); import without --replace over a later enrollment exits 1
// naming --replace.
func TestDirectorySignInCommands(t *testing.T) // cmd/port49, linux

// port49d with a directory_password verifier: the broker serves /v1/sign-in;
// it opens the enrollment store by its shape and never creates it (a new
// state dir: no enrollments.json after start, sign-in 503
// enrollment_store_lost, the gauge 0, the line names init-enrollments);
// its start line names the verifier; the label defaults to "port49
// (<host>)"; the scheduled pass runs the check and the re-seal; a global
// etcd that does not answer at start never stops port49d.
func TestPort49dWiresThePasswordSignIn(t *testing.T) // internal/port49d
```

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./internal/broker/ ./internal/daemon/admin/ ./cmd/port49/ ./internal/port49d/ -run 'ReSeal|Reset|Unlock|InitEnrollments|ExportImport|SignInAdmin|DirectorySignInCommands|PasswordSignIn'`
Expected: FAIL.

- [ ] **Step 3: Implement.** `ResealSecondFactors` lists `SecondFactorPrincipals`, reads each, and
  for `Stale` swaps it back unchanged at its `Rev` (the crypt layer seals under the current key); an
  error opening one is said once per principal per hour (`sayOnce`) naming `reset-second-factor`.
  `RefreshDirectory` calls `CheckEnrollmentStore` and then, the store not lost, the re-seal at its
  end when `b.PasswordSignIn != nil`; neither error fails the pass. `ResetSecondFactor` for one
  principal reads the record (none: `reopened` all the same), swaps `{State: reopened, Until: now
  + ReopenFor}` with no secret, emits `second_factor_reset`, and returns "reset <principal>'s
  second factor (enrolled <at> from <from>); they may enroll until <until>"; with `all` as its
  Interfaces comment says, returning "every entry with no active second factor may enroll until
  <until>" and, when it replaced a lost store, "the unreadable store was kept at <path>".
  `InitEnrollments`, `ExportEnrollments`, `ImportEnrollments` as their comments say; import
  returns "imported <n> second factors exported at <at>". `UnlockSignIn` calls
  `ClearSignInAttempts("principal:"+principal)`, emits `sign_in_unlock`, and returns "cleared <n>
  failed sign-ins for <principal>". All normalise the principal as `Forget` does. The admin ops
  mirror `directory_forget` (~295–310); `enrollments_import` reads its body after the request
  line through `io.LimitReader(c, maxImport+1)` and refuses one over `maxImport`.
  `cmd/port49/directory.go` takes `forget`, `reset-second-factor`, `unlock`, `init-enrollments`,
  `export` and `import`, each with `--socket`, and the usage line lists all six; `export` writes
  `Sealed` to stdout raw and refuses a terminal stdout ("redirect it to a file"); `import` reads
  stdin to EOF (bounded) and sends it. In port49d and port49-broker, beside `b.Issuer`:
  `b.PasswordSignIn = id.PasswordSignIn` with `TOTPLabel` defaulted to `"port49 (" + host of
  broker.listen's server name + ")"`, and `b.SignInDirectory = b.Directory`; the enrollment store
  opened by its shape, **never created** (D7): memory, `enrollfile.Open(es.File, keys, time.Now)`
  wrapped `crypt.WrapEnrollments`; etcd, the same `*etcd.Store` as `store:` when `es.Etcd == nil`,
  else `etcdstore.Open` on its own endpoints, CA, prefix and identity; wrapped
  `guard.WrapEnrollments(crypt.WrapEnrollments(...), guardConfig)`; `b.Enrollments` set; then
  `b.CheckEnrollmentStore(ctx)` before the listener opens, one line either way. A failure to dial
  the enrollment etcd at start never stops port49d: password sign-in answers `store_unavailable`
  until a pass reaches it. One start line: "broker: directory-password sign-in on (second factor
  totp; principal domains …; enrollments in <file | etcd endpoints>; enrollment open until …, new
  entries for 336h; limits 5 per principal, 50 per source, per 15m)". `ownStateDir` checks
  `enrollments.json` beside `stateMarksFile` and `stateWitnessFile` (M5).

- [ ] **Step 4: Run to verify they pass.**

Run: `go test ./internal/broker/ ./internal/daemon/admin/ ./cmd/port49/ ./internal/port49d/ -race`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add internal/broker internal/daemon/admin internal/port49d cmd/port49/directory.go cmd/port49/directory_linux_test.go
git commit -m "feat: reset, unlock, init, export and import of second factors; port49d serves the sign-in

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: The client — `port49 login --directory`

**Files:**
- Create: `cmd/port49/signin.go`, `cmd/port49/signin_test.go`
- Modify: `cmd/port49/issue.go` (`issueCertificate` takes the sign-in by method; the "signed in"
  line), `cmd/port49/main.go` (`sessionFlags.directory`, `signInName`; `--directory`, `--name`;
  `fill`; `login`'s dispatch and its usage), `internal/userconfig/userconfig.go` (`method: directory`,
  `sign_in_name`)
- Test: `internal/userconfig/userconfig_test.go`

**Interfaces:**
- Consumes: `api.SignInRequest`, `api.EnrollResponse`, `api.ConfirmRequest`, `api.SignInConfig`,
  `qrText`, `requestCertificate`'s transport (TLS 1.3 to the pool, no proxy, the CRL check).
- Produces:

```go
// The prompts, vars so a test drives them.
var (
	readSecret = func(prompt string, stderr io.Writer) (string, error) // echo off, stdin a terminal
	readLine   = func(prompt string, stderr io.Writer) (string, error)
	stdoutIsTerminal = func() bool
)

// directorySignIn is the sign-in half of issueCertificate for --directory:
// name, password and code to POST /v1/sign-in, the enrollment when the
// broker answers 202, and the certificate.
func directorySignIn(ctx context.Context, sf *sessionFlags, pool *x509.CertPool, verify func(tls.ConnectionState) error,
	csr []byte, conf api.Config, stdout, stderr io.Writer) (api.IssueResponse, error)
```

- [ ] **Step 1: Write the failing tests.** In `signin_test.go`, against an `httptest` TLS server
  standing in for the broker (as `issue_test.go` in `cmd/port49` does for `/v1/certificate`):

```go
// The password and the code go in the body, once, over TLS; never in argv,
// the URL or a header; the name offered is --name, else sign_in_name, else
// the login user's.
func TestTheSignInSendsTheBodyOnce(t *testing.T)
// No terminal: refused before anything is sent, naming it.
func TestNoTerminalIsRefused(t *testing.T)
// An empty password is refused at the prompt, nothing sent (Review Focus 1);
// a password ending in a space is sent as typed (M3).
func TestAnEmptyPasswordIsNotSent(t *testing.T)
// 202: the QR code and the key in groups of four on the terminal, the
// confirm-by time; the first code goes to /v1/sign-in/confirm with the
// handle; no secret on stdout when stdout is not a terminal (refused).
func TestEnrollmentIsShownAndConfirmed(t *testing.T)
// Each refusal in the broker's words: sign_in_refused, sign_in_throttled
// with its time and the typed name, enrollment_closed naming the
// operator's command, directory_unavailable and enrollment_store_lost
// saying holders keep working.
func TestTheBrokersRefusalsAreSaid(t *testing.T)
// A broker with no directory_password says so before a password is asked.
func TestABrokerWithoutTheVerifierIsSaidFirst(t *testing.T)
// --directory beside --oidc, --cert or --key is a usage error; method: directory in the file selects it.
func TestTheDirectoryFlags(t *testing.T)
```

  In `userconfig_test.go`: `method: directory` and `sign_in_name: alice` load; `method: password` is
  refused naming the three methods.

- [ ] **Step 2: Run to verify they fail.**

Run: `go test ./cmd/port49/ ./internal/userconfig/ -run 'SignIn|Enrollment|Terminal|EmptyPassword|Refusals|Verifier|DirectoryFlags|Method'`
Expected: FAIL.

- [ ] **Step 3: Implement.** `issueCertificate` keeps its prelude (broker config, issuance and its
  `available`, the store, the key) and branches on `sf.directory`: the OIDC branch as today; the
  directory branch refuses a `conf.SignIn == nil` before any prompt ("the broker at … takes no
  directory password; log in with --oidc or a certificate"), makes the CSR, and calls
  `directorySignIn`. `directorySignIn`:

```go
	if !loginStdinIsTerminal() {
		return api.IssueResponse{}, errors.New("a directory sign-in reads your password at a terminal, and stdin " +
			"is not one; run `port49 login --directory` at a terminal (use `ssh -t` on a remote host)")
	}
	name := sf.signInName
	if u, err := user.Current(); name == "" && err == nil { // as ssh.go reads the login user
		name = u.Username
	}
	if typed, err := readLine(fmt.Sprintf("directory name [%s]: ", name), stderr); err != nil {
		return api.IssueResponse{}, err
	} else if typed != "" {
		name = typed
	}
	password, err := readSecret("password: ", stderr)
	if err != nil {
		return api.IssueResponse{}, err
	}
	if strings.TrimSpace(password) == "" {
		return api.IssueResponse{}, errors.New("an empty password is never sent")
	}
	code, err := readSecret("code from your authenticator (empty if you have none yet): ", stderr)
	…
	resp, enroll, err := postSignIn(ctx, sf.broker, pool, verify, api.SignInRequest{Name: name,
		Password: password, Code: code, CSR: base64.RawURLEncoding.EncodeToString(csr)})
	if err != nil || enroll == nil {
		return resp, err
	}
	return confirmEnrollment(ctx, sf, pool, verify, *enroll, csr, stderr)
```

  `postSignIn` and `postConfirm` reuse `requestCertificate`'s client (TLS 1.3, `RootCAs: pool`,
  `VerifyConnection: verify`, `Proxy: nil`, no redirect) with the JSON body; an HTTP error answers
  with the broker's `detail` as the error; a transport error is `*brokerDownError`; 401
  `credential_revoked` is `*refusedError`, as for `/v1/certificate`. `confirmEnrollment` refuses when
  `!stdoutIsTerminal()` ("enrolling shows your second factor's secret; run `port49 login` at a
  terminal"), prints to the terminal "Enroll your second factor: scan this with your authenticator
  app, or type the key", `qrText(enroll.URI)`, the key from the URI's `secret` in groups of four,
  "confirm by <confirm_by>", asks the first code, and posts the confirm. The "signed in" line becomes
  "port49: signed in with your directory password as <principal>; your certificate from <broker> is
  valid until <end>" for the directory method (from `issuer.ReadSignIn`), and the held-certificate
  line in `loginIssued` says "(signed in with your directory password at <auth_time>)" for one.
  `loginIssued` is the path for both methods; `login` dispatches `sf.oidc || sf.directory` to it.
  `readSecret` is `term.ReadPassword` on stdin under `guardedPaste`'s signal handling, as the PIN is
  read; it returns the bytes as typed, never trimmed (a password may end in a space; `readPaste`
  trims, so it is not reused); only the emptiness test trims (M3). The string is dropped as soon as
  the request is built. On a 429 for the principal's limit, the client names the account by the
  name the person typed (it knows it; the broker never names the principal, I3): "too many failed
  sign-ins for <name>; …".

- [ ] **Step 4: Run to verify they pass.**

Run: `go test ./cmd/port49/ ./internal/userconfig/ -race -v -run 'SignIn|Enrollment|Terminal|EmptyPassword|Refusals|Verifier|DirectoryFlags|Method' && go test ./cmd/port49/`
Expected: PASS, the OIDC login tests unchanged.

- [ ] **Step 5: Commit.**

```bash
git add cmd/port49 internal/userconfig
git commit -m "feat: port49 login --directory, with the enrollment's QR code

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: The 3am cases end to end, through the real CLI

**Files:**
- Create: `cmd/port49/signin_login_linux_test.go`
- Modify: `cmd/port49/main_test.go` (`labOpts.signIn`, a fake `SignInDirectory` on the lab broker)

**Interfaces:**
- Consumes: `newLabBrokerOpts`, `labOpts`, `privateSocket`, `stopAgentAt`, `run` (under
  `t.Setenv(runCLIEnv, "1")`, as `login_linux_test.go` runs it: `runCLIEnv` is the env var's name,
  a constant in `main_test.go`), `totp.Code`, `enrollfile.Open`, `crypt.WrapEnrollments`; Task 9's
  fake directory (moved to a test helper both packages can build from, or a copy here).

- [ ] **Step 1: Write the tests.** `newDirectoryLab(t)` is `newLabBrokerOpts(t, labOpts{maxAge:
  12*time.Hour, signIn: dir})`, where the lab broker then sets `PasswordSignIn`, `SignInDirectory`,
  an issuing CA, `NoX509`, the memory store, and the enrollment store an `enrollfile` in
  `t.TempDir()` under test keys, wrapped `crypt.WrapEnrollments` (the shape port49d runs on
  memory, D7), initialised as `port49 directory init-enrollments` does (the lab's admin socket
  runs it, so the test exercises the command). The prompts are driven by `readSecret`, `readLine`
  and `stdoutIsTerminal` set per test; codes come from `totp.Code`.

```go
// A first login enrolls (QR, first code), gets a certificate, starts the
// agent, and `port49 token` mints; no password, code, secret or URI reaches
// the terminal's non-prompt output or the agent's log.
func TestLoginDirectoryEnrollsIssuesAndMints(t *testing.T)

// Owner's ruling 4, the 3am case: the directory down. A person holding a
// certificate logs in on it and mints; a person with none is told the
// directory did not answer and that anyone signed in keeps working; exit 1,
// no agent.
func TestTheDirectoryDownAtThreeAM(t *testing.T)

// A phone's clock off by two minutes: refused, saying the clock is about 2
// minutes off; with it fixed, the next login is issued.
func TestAClockOffAtThreeAM(t *testing.T)

// Locked out by a spray of the person's name: their login says the time and
// `port49 directory unlock`; their held certificate keeps them working; the
// operator's unlock lets the next login through.
func TestLockedOutAtThreeAM(t *testing.T)

// A lost phone: reset-second-factor, then the login enrolls again.
func TestALostPhoneAtThreeAM(t *testing.T)

// The broker down with a held certificate: said, try again; the same as --oidc.
func TestTheBrokerDownWithAHeldCertificate(t *testing.T)

// D7 at 3am: the enrollments file lost after the rollout. Password login
// says the store is lost and that holders keep working; a held certificate
// mints; the operator's reset-second-factor --all lets the next login
// enroll, and the unreadable file is kept beside the new one.
func TestALostEnrollmentStoreAtThreeAM(t *testing.T)

// D7, I15: a new install. Before `port49 directory init-enrollments` a
// login is refused, saying the store is not initialised; after it the
// first login enrolls. A second init-enrollments exits 1, writing nothing.
func TestAFreshInstallNeedsInitEnrollments(t *testing.T)
```

- [ ] **Step 2: Run them.** They exercise Tasks 9–11 together; a failure here is a defect in those
  tasks, fixed there.

Run: `go test ./cmd/port49/ -race -v -run 'LoginDirectory|AtThreeAM|BrokerDownWithAHeld|FreshInstall'`
Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add cmd/port49/signin_login_linux_test.go cmd/port49/main_test.go
git commit -m "test: the directory sign-in's 3am cases through the real CLI

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: Lab harness — L67 on OpenLDAP, Samba AD and Windows Server AD

**Files:**
- Modify: `tests/lab/directory/openldap/config.ldif` (load the `ppolicy` module and overlay, a
  default policy: `pwdMaxFailure 10`, `pwdFailureCountInterval 600`, `pwdLockout TRUE`,
  `pwdMustChange TRUE`), `tests/lab/directory/openldap/seed.ldif` (people's `userPassword` hashed at
  start, as the broker's is; `whenCreated` is not OpenLDAP's: `createTimestamp` is operational),
  `tests/lab/directory/openldap/entrypoint.sh`
- Modify: `tests/lab/directory/samba/seed.sh` (known per-run passwords for alice, carol, dave;
  `samba-tool domain passwordsettings set --account-lockout-threshold=10
  --account-lockout-duration=10 --reset-account-lockout-after=10`; an `expired`, a `disabled` and a
  `mustchange` user)
- Create: `tests/lab/directory/windows/scripts/l67.ps1` (the same users and lockout policy on the
  DC; reading `badPwdCount`)
- Create: `tests/lab/l67_test.go` (build tag `lab`), `tests/lab/l67_unit_test.go` (`make lab-unit`)
- Modify: `Makefile` (`lab-l67`, `lab-l67-windows`), `tests/lab/README.md` ("Directories": L67)

**Interfaces:**
- Consumes: the 7g harness (`newDirectories`, `startDirectories`, `labDir`, `dirPKI`,
  `resolverWith`, `evidenceLog`), the L44 harness's DC bring-up, `bin/port49` from `make build`.

- [ ] **Step 1: The seeds.** Every per-run password is generated by the harness (`crypto/rand`, 24
  base64 characters), passed to the containers in the environment the compose file already uses
  for `LAB_PORT49_PASSWORD`, held in memory by the test, and never printed: the evidence log writes
  `<alice's password>`. The OpenLDAP seed hashes each with `slappasswd` in the entrypoint, as it
  hashes the broker's.

- [ ] **Step 2: The cells**, one subtest each per directory, each with its positive control first:
  - **(a)** `CheckPassword` with the right password over LDAPS and over StartTLS: nil. Control: the
    broker's own bind succeeds on the same server. Then a wrong one: the `PasswordRefusal`, its
    result and data recorded.
  - **(b)** A raw go-ldap client sends `UnauthenticatedBind(aliceDN)` (empty password): the result
    recorded (success is the danger RFC 4513 §5.1.2 names). Then `CheckPassword(…, "")` returns
    `ErrEmptyPassword` and the server's connection count is unchanged (OpenLDAP's `stats` log, Samba's
    `ldb` log level 3, the DC's event 2889 / `netstat`).
  - **(c)** With the right password: the expired, must-change, disabled and locked users; each
    refusal's result, data or `ppolicy` error; then the same users with a wrong password, to record
    whether the state shows without the password.
  - **(d)** Six sign-ins with a wrong password for carol (enrolled, right code) through a broker with
    port49's defaults: the directory's failed count after them (`badPwdCount` on Samba and the DC,
    `pwdFailureTime` values on OpenLDAP), and the sixth answered `sign_in_throttled` with no bind:
    the count after six is five. Control: the account is not locked (a right-password bind succeeds
    after the window). Then, the window shortened to 2m for the cell (`rate_limits.window`), nine
    wrong passwords straddling a window boundary, four before it ends and five after (I11): the
    directory's failed count after them, and whether the account locked (AD's threshold of 10 is
    one above; the cell records the margin).
  - **(e)** A wrong code for carol: `sign_in_refused`, and the directory's failed count unchanged
    (no bind).
  - **(f)** `SignInEntry("alice")` as the broker's bind: `CreatedAt` non-zero and within a minute of
    the seed's time.
  - **(g)** End to end, twice: once on the compose stack's broker on etcd, and once on port49d on
    the memory store (the sealed `enrollments.json` in its state directory, D7). Control first: a
    sign-in before `port49 directory init-enrollments` is refused `enrollment_store_lost`, and no
    `enrollments.json` exists (memory). Then `port49 directory init-enrollments` on the broker's
    admin socket; `bin/port49 login --directory` under a pty (the harness's pty helper from L56)
    enrolls alice (the QR printed to the pty, the secret read back from the `otpauth://` line the
    harness parses on its side of the pty, the first code computed by `totp.Code`), confirms, and
    `bin/port49 token leaf1` mints against the loopback inventory. Then the directory container
    stopped: `bin/port49 token` still mints from grace, and `bin/port49 login --directory
    --sign-in` exits 1 saying the directory did not answer. A person scanning the QR with a phone
    is a manual note, not a cell.

- [ ] **Step 3: The unit test** (`l67_unit_test.go`): the evidence log never holds a generated
  password (feed one through `evidenceLog` and grep the file), and the cell table names every L67
  cell.

Run: `make lab-unit`
Expected: PASS.

- [ ] **Step 4: Make targets.**

```make
# L67 (plan 9e): a person's bind and the directory-password sign-in, on
# OpenLDAP and Samba AD as containers. Needs Docker with Compose v2.24.4+
# and `make build`; see tests/lab/README.md, "Directories".
lab-l67:
	go test -tags lab ./tests/lab/ -run '^TestL67$$' -count=1 -v -timeout 45m

# L67 on the Windows Server DC (the L44 harness, on the SER8). Needs KVM, the
# cached evaluation ISO and PORT49_LAB_L67_WINDOWS=1.
lab-l67-windows:
	PORT49_LAB_L67_WINDOWS=1 go test -tags lab ./tests/lab/ -run '^TestL67Windows$$' -count=1 -v -timeout 240m
```

  Add both to the `.PHONY` line.

- [ ] **Step 5: Build-check and commit.**

Run: `go vet -tags lab ./tests/lab/ && make lab-unit`
Expected: clean.

```bash
git add tests/lab Makefile
git commit -m "test(lab): the L67 harness on OpenLDAP, Samba AD and the Windows DC

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: Lab run — L67

**Files:**
- Create: `tests/lab/results/L67-openldap.md`, `tests/lab/results/L67-samba_ad.md`,
  `tests/lab/results/L67-windows_ad.md`; evidence under `tests/lab/evidence/`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L67's status; decision 47's provisional
  tags; any ruling a result contradicts, under register rule 4)

- [ ] **Step 1: Arm the watchdog,** per the lab-run rule, before each run.

- [ ] **Step 2: Run the containers.**

Run: `make build && make lab-l67`
Expected: every cell PASS on OpenLDAP and Samba AD, or a cell's reading that differs from a ruling,
recorded as such (not a test failure to paper over).

- [ ] **Step 3: Run Windows on the SER8.** The DC from the L44 harness, fresh.

Run: `make lab-l67-windows`
Expected: as Step 2. If the DC cannot be brought up in this session, L67 stays open with Windows
unmeasured (register rule 5), and the results note says so.

- [ ] **Step 4: Results notes,** one per directory: platform, image version (slapd and its
  `ppolicy`; Samba; Windows build), each cell's observation, the capture pointer. Every password is
  `<redacted>` in the notes and the evidence.

- [ ] **Step 5: Correct the docs under rule 4.** Each reading a ruling assumed and the lab
  contradicts (likeliest: ruling 6's data codes on Samba; (c)'s state leaking without the password,
  which changes ruling 7's words; (f)'s `createTimestamp`, which D2's new-entry window needs)
  changes the ruling and the code in this branch, citing the note. If (b) shows a directory accepting
  an empty-password bind, the operator notes say so and why port49 refuses it.

- [ ] **Step 6: Close or keep open.** With all three measured, L67's status is `closed — measured
  <date>; tests/lab/results/L67-openldap.md, L67-samba_ad.md, L67-windows_ad.md`; decision 47's
  "provisional on L67" goes. With one open, the row stays open naming it.

- [ ] **Step 7: Commit.**

```bash
git add tests/lab/results tests/lab/evidence docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entry L67 (directory-password sign-in)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

  (If L67 stays open: "docs: L67 measured on OpenLDAP and Samba AD; Windows open".)

---

## Task 15: Roadmap as built, and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status paragraph; "Plan 9", the 9e entry; a new
  "### Plan 9e — As built" after "### Plan 9d — As built")

- [ ] **Step 1: The status paragraph:** "9e written 2026-10-14 (… fifteen tasks …), executed …, L67
  …".
- [ ] **Step 2: Plan 9e — As built:** built (by task, with commits), the rulings as made (D1–D13
  with who ruled each, and the pre-flight's controller rulings), rows (L67), what is carried: D10's
  `totp` as a `per_login_mfa` method; plan 12's shipping of `method: directory` in
  `/etc/port49/config.yaml`, where each shape keeps `enrollments.json` (a persistent volume on k8s;
  `StateDirectory=` under systemd) and backs it up (`port49 directory export` from a cron job), and
  `port49 directory init-enrollments` as an install step (a one-off job, never a start path);
  plan 11a's rest of the D12 split; plan 13's guide; the pre-beta review's look at the enrollment
  windows. Then the operator notes below, corrected by the lab.
- [ ] **Step 3: Commit.**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: plan 9e as built, and its operator notes

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Operator notes (for the pull request body)

- **New: sign in with the directory password and a second factor.** For a company with no PKI and
  no identity provider. Either store shape works. On the memory store the second factors are kept
  sealed in `enrollments.json` in the broker's state directory: **back it up**
  (`port49 directory export > enrollments.sealed` from cron; restore with `port49 directory
  import`). On etcd they live in etcd, or, with `broker.directory.enrollment_store`, in an etcd of
  their own (one cluster across regions, so a code used in one region is used everywhere). On the
  broker:

  ```yaml
  broker:
    directory: { … }                  # plan 7g's; certificate_mapping is now optional without an x509 verifier
    identity:
      humans:
        - type: directory_password
          principal_domains: [corp.example.com]
          second_factor: totp
          filter: "(memberOf=CN=port49-people,OU=Groups,DC=corp,DC=example,DC=com)"   # keeps service accounts out
          enrollment:
            open_until: 2026-11-30T00:00:00Z   # the rollout
            new_entries_for: 336h               # a new hire's first 14 days; 0s off
            reopen_for: 24h                     # after reset-second-factor
          rate_limits: { failures_per_principal: 5, failures_per_source: 50, window: 15m }
      issuance: {}
  ```

  **Once per install, run `port49 directory init-enrollments`** on the broker's admin socket (as
  the broker's user or root): it creates the enrollment store. port49d never creates it itself, so
  a lost or unmounted volume is never mistaken for a new install; until it runs, password sign-in
  is refused `enrollment_store_lost` and `port49_directory_enrollment_store_ok` reads 0. It refuses
  to run over a store that is already there. On each host, `/etc/port49/config.yaml` with `method:
  directory`. A person runs `port49 login`, types their directory password and their
  authenticator's code, and holds a 12h certificate; after that everything is the certificate path
  (9b).
- **First sign-in.** Inside a window, the right password shows a QR code: scan it with any
  authenticator app (or type the key), then type the first code. Every enrollment is an `enroll`
  record and `port49_sign_ins_total{outcome="enrolled"}`: **alert on enrollments outside your
  rollout.** Inside a window a stolen password enrolls the thief's phone first; the real person
  then finds a second factor they never set up, and that is the signal.
- **Why the code comes first.** port49 checks the code, and uses it up, before it sends the
  password to the directory. A spray without the codes never reaches your DCs, so port49 cannot
  lock an AD account. The person sees one refusal for a wrong name, password or code; one who
  mistypes the password waits for the next code. Outside every enrollment window a person with no
  second factor is told enrollment is closed, and the password is not tried at all; that answer
  says the name exists and has not enrolled, which port49 accepts.
- **Limits.** 5 failures per person and 50 per source address (an IPv6 /64) in 15 minutes, counted
  before they are judged, in `store:` (regional); a store error refuses. **Behind a load balancer
  or NAT that hides client addresses, every sign-in shares one source:** raise
  `failures_per_source` or set it to 0. **Keep `2 × failures_per_principal` under your directory's
  lockout threshold:** a fixed window lets up to `2 × 5 − 1 = 9` failures through around a window
  boundary, one under AD's default of 10 (L67 (d) measured it). The 429 for a person's limit says
  an operator can unlock the account; it never names the principal.
- **At 3am.**
  - The directory down: sign-ins fail at once, 503, saying so; everyone holding a certificate keeps
    working, new agents included, within `directory.grace`.
  - Someone locked out by a spray of their name: `port49 directory unlock <principal>` on the
    broker's admin socket. Their held certificate works meanwhile.
  - A lost phone: `port49 directory reset-second-factor <principal>`; they enroll at their next
    sign-in within `reopen_for`.
  - A phone's clock off: the refusal says by how much.
  - "your second factor could not be read": the store's encryption key in use is not the one it was
    sealed under, and the previous is gone; reset the person's second factor. Keep
    `encryption.previous` until a scheduled pass has run after a rotation (it re-seals them).
  - "the broker's store of second factors is missing or unreadable" (`enrollment_store_lost`,
    `port49_directory_enrollment_store_ok` 0): the file or etcd key is gone, or will not unseal
    (the seal key changed), or this is a new install not yet initialised. Password sign-in alone
    is refused; held certificates, tokens and IdP sign-in serve. On a new install run `port49
    directory init-enrollments`. Otherwise restore it (`port49 directory import < backup`, or the
    etcd snapshot). If there is no backup, `port49 directory reset-second-factor --all` lets
    everyone enroll again for `reopen_for` (24h): **alert on it**, as a stolen password enrolls
    first in that window. The unreadable file is kept beside the new one.
  - After an etcd restore, a `reset-second-factor` run since the snapshot is undone (the lost
    phone's factor is back): run it again.
  - A person's entry re-created in the directory (after `port49 directory forget`): their sign-in
    is refused with the usual sentence, and the broker's log names `reset-second-factor` for them.
- **Alert on** `second_factor_reset` records with `"all"` or `"created"` (outside an install), on
  `port49_directory_enrollment_store_ok` 0, on `enrollment_store_lost`, and on
  `enrollments_import`.
- **What is never logged:** the password, the code, the secret, the QR code's URI, the enrollment
  handle, and a name that matches no entry (people type passwords at name prompts).
- **`per_login_mfa`.** A directory-password person meets a device's requirement only by
  `hardware_key_touch` (a YubiKey); `idp_mfa` needs a provider. A TOTP method there is carried to a
  later plan.
- **New reason codes:** `sign_in_refused`, `sign_in_throttled` (alert), `enrollment_closed`,
  `enrollment_store_lost` (alert), `second_factor_enrolled` (alert); new events `enroll`,
  `second_factor_reset`, `sign_in_unlock`, `enrollments_import`; metrics
  `port49_sign_ins_total{outcome}` and `port49_directory_enrollment_store_ok`; commands `port49
  directory reset-second-factor [--all]`, `unlock`, `init-enrollments`, `export`, `import
  [--replace]`.
- **Lab:** L67 (OpenLDAP, Samba AD, Windows Server 2025 AD): the readings the PR closes on.
