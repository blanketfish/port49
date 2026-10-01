# Plan 7b: Session Lifetime and Certificate Status — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build spec §5.6's session lifetime and §5.1.4's certificate status on the certificate
path.
- **Per-role ceiling.** A role declares `max_session_age` (a duration, or `never`), and a principal's
  ceiling on a device is the least of its roles'.
- **Warning.** An operator approaching the ceiling is warned in the `server_msg` of the
  authorization replies port49 permits.
- **Refresh.** `port49 refresh` (and `port49 login` while a session is held) re-authenticates by a
  signed nonce over the held connection and extends every live context the policy in force still
  grants, with no reconnect.
- **Grace.** Past the ceiling a context is denied and kept through the grace window, so a late
  refresh resumes it; past the window it is deleted.
- **Certificate status.** The broker checks every client certificate against the CRLs and OCSP
  responders the operator names, and a certificate they revoke is refused as it binds and at every
  mint and refresh. One that holds a session, a context or a token is revoked through 7a's marks,
  so everything it reaches is reached.
- **Lab.** A lab run measures what the warning rests on: whether a device shows `server_msg` on a
  permit, which opens L34, and L2's truncation length on five images.

**Architecture:**
- **Policy.** A role's `max_session_age` composes into `policy.Resolution.SessionAge`, which the
  broker turns into the token's `MaxSessionAge` with port49d's default. The policy refresh carries
  it into live contexts through `store.ContextPolicy`, shortening a ceiling and never lengthening
  one.
- **Daemon.** The authorizer adds the warning to a permit's reply within `session.ceiling_warning`,
  and deletes a context past `session_expires + grace_window` (teardown row 3).
- **Refresh.** The broker gains `POST /v1/refresh/challenge` and `POST /v1/refresh`: a 32-byte
  nonce, single use, held on the connection's session state. It is signed by the certificate's key
  over a TLS exporter value, so it cannot be answered on another connection. On success the
  connection's `auth_time` moves to the verification time and `Broker.RefreshSession` carries the
  policy in force into each of the principal's contexts before extending them through
  `store.RefreshContext`, which refuses one past its grace window.
- **Certificate status.** A new package, `internal/certstatus`, loads CRLs (file or URL, polled),
  verifies each against the issuer that verified the leaf, and asks OCSP with a cache. Its verdict
  is read by the listener at bind, by the mint and by the refresh. When a CRL adds an entry, the
  broker revokes that certificate through `Broker.Revoke` if anything still holds it.

**Tech Stack:**
- Go 1.22 (the module's `go` line).
- The standard library: `crypto/x509` (`ParseRevocationList`, `CheckSignature`,
  `CheckSignatureFrom`), `crypto/tls` (`ExportKeyingMaterial`), `crypto/rand`.
- `golang.org/x/crypto/ocsp`: part of `golang.org/x/crypto`, already a module dependency, so **no
  new module**.
- `prometheus/client_golang`.
- containerlab on beehive for Task 12.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §5.1.4: credential identity and revocation, "a certificate appearing on a CRL or OCSP response".
  - §5.6: session lifetime; the teardown table's rows 2, 3 and 3a; "Where these controls do not
    reach".
  - §5.7: the `refresh` event, the reason codes.
  - §12: tooling.
  - §13 decisions 12, 15, 17, 21, 32 and the new 33.
  - §15 L2, and the new L34.
- Design `docs/design/2026-08-21-port49-design.md`:
  - §7: the certificate path's refresh, "validates the chain, expiry, revocation".
  - §12: the failure matrix.
  - §17: the surface, `/v1/refresh`.
- Roadmap `docs/superpowers/plans/README.md`:
  - "Plan 7": the split, and 7b's bullet.
  - "Plan 7a — As built": its carried items for 7b, and its rulings as made.
  - "Plan 4b": "Hands to plan 7".
- The merged plan 7a (`2026-10-01-07a-revocation-and-broker-limits.md`).

**Prerequisite:** plan 7a merged (PR #20, `bf96a46`; `main` at `872402f`). Branch
`feature/session-lifetime-and-cert-status` off `main` at the commit that adds this file.

## What this plan does not do

- **No OIDC refresh.** `prompt=login`, `auth_time` from an assertion, and `sid` re-indexing are
  plan 7h's. This plan builds the certificate path's refresh, which is the one the spec gives the
  broker's own clock (§5.6).
- **No hardware key.** The agent signs the nonce with the key it holds, plan 3's PEM file. A YubiKey
  or a platform keystore, and with it the touch that makes a refresh a human event, is plan 9's
  (roadmap, "Plan 9"). Until then a refresh proves possession of the key file. The operator notes
  say so, and Ruling 6 keeps the agent from refreshing on its own.
- **No scheduled directory refresh, and no `staleness_ceiling` default.** Plan 7g brings them
  together (roadmap). A session refresh stamps `refreshed_at`, but the staleness check stays off by
  default.
- **No HTTP API rights.** `/v1/refresh` acts on the caller's own contexts alone, which is design
  §17's self-only default; 7c's `api:` rights add nothing to it.
- **No delta CRLs, and no CRL distribution points read from certificates.** The operator names each
  CRL source. A CRL carrying the delta-CRL indicator is refused (Ruling 9).

## Rulings where the spec is silent

Each takes the option that denies more, is written into the tasks named, and is recorded in spec
§13 as decision 33 by Task 1. Decision D-7b-1, under "Decisions for Ryan", names the one default the
owner should confirm; both of its options are built, so no task waits on it. The rulings below are
as revised after the pre-flight review (the next section lists each change).

1. **A role's `max_session_age` is a duration of at least 1m, or `never`.**
   - **Composition.** A principal's ceiling on a device is the least across the roles that compose
     there. A role that names none takes `session.max_session_age_default`. The result is `never`
     only when every role says so.
   - **The default.** It stays a finite duration, so a forgotten key never becomes `never`.
   - **The held connection.** It keeps its own ceiling at the default (decision 17), so a role longer
     than the default still re-authenticates the connection at the default, by refresh or reconnect.
   - **Visibility.** `port49 explain` prints the composed ceiling.

   Tasks 2, 3.
2. **A device whose ceiling has already passed is refused per item.** A mint whose connection
   authenticated longer ago than the device's ceiling is refused for that device, `session_expired`
   (a §5.7 meaning added by Task 1). The item's detail and `port49 token`'s line say `run 'port49
   refresh'`. Tasks 3, 8.
3. **A policy edit may shorten a live context's ceiling, never lengthen it; a refresh sets the
   ceiling the policy in force gives.**
   - **A policy edit.** It writes `session_expires = auth_time + the policy's ceiling` only when that
     is earlier, or when the context had none.
   - **A refresh.** It is a fresh authentication event, so it sets `session_expires = the new
     auth_time + the ceiling the policy in force composes on that device`. A lengthened ceiling, or
     `never` (which clears it), therefore takes effect at the operator's next refresh or login, as
     spec §5.6's example writes `T2+8h` (pre-flight I5).

   Tasks 4, 5, 7.
4. **The warning rides on permits within `session.ceiling_warning`, to platforms known to show it.**
   - **The window.** The default is 30m: the spec asks for "long enough to complete a change", and
     the example's 10m is not. `0s` turns it off.
   - **What carries it.** The `server_msg` of every permitted session and command authorization reply
     while `session_expires` is that close, in plain ASCII: `port49: session ends in 9m - run 'port49
     refresh'`.
   - **Which platforms.** Only those on an allow-list (`platform.CeilingWarning`), which is empty
     until L34's notes name the platforms that show it and still permit (Task 13; pre-flight M10).
     An operator may add an unmeasured platform with `session.ceiling_warning_platforms`; the lab
     run does that for all five images to measure them.
   - **The second warning.** Every platform gets `port49 token`'s stderr warning, from the item's
     `session_expires_at`, `--json` included.

   Tasks 6, 8, 13.
5. **Past the ceiling and inside the grace window, a context is denied and kept; past the grace
   window it is deleted at its next authorization.**
   - **A refresh.** One inside the window resumes the context. One past it never does: the store
     refuses that extension, `store.ErrPastGrace`.
   - **No wrong record.** The delete, and the refresh's write, are compare-and-sets on the revision
     read (`DeleteContextIf`, `ContextRefresh.ExpectRev`), so a context another principal's login
     replaced in between is neither deleted nor extended (pre-flight M4).
   - **The messages.** The default window stays 10m. Inside it the refusal names `port49 refresh`
     and `port49 login`; after it, `port49 token` and a new login.

   Tasks 4, 6, 7.
6. **A refresh is a signed nonce over the held connection, bound to that connection.**
   - **The exchange.** `POST /v1/refresh/challenge` issues 32 random bytes, good for 60s, once, and
     only on the connection that asked; a new challenge replaces the old.
   - **What is signed.** `"port49 session refresh v1\x00" ‖ nonce ‖ EKM`, where EKM is 32 bytes of
     the TLS exporter (`EXPORTER-port49-refresh`), so a nonce relayed to another connection cannot be
     answered.
   - **The algorithm.** It is fixed by the key: ECDSA with SHA-256, RSA-PSS with SHA-256, or Ed25519.
   - **Before verifying.** The certificate is checked again (`Identity`), with the marks and the
     certificate's status.
   - **The clock.** `auth_time` is the broker's verification time (spec §5.6), and the connection's
     own session clock moves to it.
   - **The rate.** One refresh per connection per 10s: a refresh compiles every context under the
     policy hold (pre-flight M17).
   - **A missing challenge.** It has its own API error, `refresh_challenge_missing`, which the agent
     retries once; the agent does not read detail text.
   - **Who triggers it.** The agent refreshes when asked, by `port49 refresh` or by `port49 login`
     (which refreshes once after connecting, and while a session is held), and never on its own: the
     ceiling measures time since a person authenticated (§5.6). With today's key files a refresh
     proves possession of the file, not presence (plan 9's hardware key does), and a scripted loop
     can keep a session alive. The operator notes say so.

   Tasks 7, 8.
7. **A refresh extends only what the policy in force has just judged and kept.**
   - **Judging.** Each of the principal's live contexts is re-resolved and written as a policy
     refresh writes it, and `refreshContext` returns its outcome.
   - **What is extended.** Only a context whose outcome is `unchanged`, or `updated` with the write
     landed. A context the pass revoked, left (quarantined device, no blob, another principal's) or
     could not write (`ErrConflict` after every attempt) is not extended, and is listed (`revoked`,
     `not_judged`) (pre-flight I4).
   - **The records.** Each extension is a `refresh` record carrying `session.auth_time` and
     `session.session_expires`. Every refresh record names `session.unreached` for a session-only
     platform (decision 21, carried from 7a).

   Tasks 5, 7.
8. **Certificate status is required configuration, and every CRL source names its signer.**
   - **Required.** With a `broker:` block, `broker.certificate_status` names at least one CRL or an
     OCSP responder, or says `disabled: true`, which is accepted and said at every start: design §7
     has the broker validate "revocation", and an operator must choose not to (D-7b-1).
   - **Each CRL source's signer.** It names `issuer_file`, the CA certificate that signs it. At
     config load that certificate must be the broker's anchor, or be signed by it (pre-flight C1).

   Tasks 10, 11.
9. **A CRL is verified before anything uses it, and only a complete one is taken.**
   - **At load.** A fetched or persisted list must verify against its source's `issuer_file`
     certificate. One that does not is refused (`refused`): it never replaces the last good list,
     never moves the CRL-number floor, and never reaches the new-entry callback. A list whose
     `CRLNumber` or `ThisUpdate` is below the last good one's is refused too, which stops a rollback.
   - **Scope.** A list is refused when it is a delta CRL, carries a critical extension other than
     Authority Key Identifier, CRL Number and an Issuing Distribution Point that says only
     `onlyContainsUserCerts`, or has an entry with a critical extension (pre-flight I3). A list scoped
     to user certificates covers leaves only, never an intermediate.
   - **Which list applies.** A list applies to a certificate when its source's issuer certificate is
     byte-for-byte the certificate that verified it.
   - **Every certificate in the chain.** Every one but the anchor is checked against its own issuer
     (`chain[i+1]`). A revoked intermediate refuses every leaf under it `credential_revoked`, and
     writes no mark on the leaf (pre-flight I2).
   - **Freshness.** A list is fresh until its `NextUpdate` (one with none, for `refresh_interval`).
   - **`certificateHold`.** An entry with reason `certificateHold` refuses its certificate while it
     is listed and writes no standing mark, since a hold is lifted by the CA (pre-flight M13).
   - **Where from.** A list is read from a file or fetched over `http` or `https`: no redirect, a
     16 MiB cap, 30s. The signature, not the transport, is the trust.
   - **OCSP.**
     - **The question.** It asks `ocsp.responder`, or with `use_aia` the certificate's own responder,
       within `ocsp.timeout` (2s), its CertID hashed with `ocsp.hash` (`sha256`, or `sha1` for a
       responder that knows no other; M14).
     - **What is accepted.** An answer is taken only when all of these hold (pre-flight C2):
       - it verifies for the issuer;
       - its signer is the issuer itself, or a delegate the issuer signed that carries
         `id-kp-OCSPSigning` and is inside its validity;
       - its serial is the certificate's;
       - its `ThisUpdate` is no later than now+5m;
       - its `NextUpdate`, when set, is later than now (when unset, `ThisUpdate` is within
         `refresh_interval`).
     - **The cache.** An answer is cached until the earlier of its `NextUpdate` and an hour, and an
       already-expired one never. A failure is cached for 30s, and concurrent questions about one
       certificate share one request (M15).
   - **Precedence.** A verified list that names the serial is final. Otherwise a fresh verified list
     that does not name it is good, and an OCSP answer decides where none covers the issuer.

   Task 9.
10. **A status that cannot be established is refused (`on_unavailable: refuse`, the default), as
    unavailable, not as a final verdict.**
    - **What counts.** A stale list, an unreachable responder, an issuer no source covers.
    - **The answer.** At bind, mint and refresh it is `503` with the API error
      `certificate_status_unavailable` and `Retry-After: 60`, and the decision record's reason
      `trust_domain_unresolved` (a §5.7 meaning added by Task 1; no new reason code). The agent keeps
      its session on a 503, so a publisher outage refuses new work and ends nobody's session
      (pre-flight I7); `401` stays for a certificate that is revoked or untrusted.
    - **`allow`.** It admits the certificate, counts it, and says it once per source per 10m (M1).
    - **Live sessions.** Untouched either way (the daemon never reads certificate status, decision
      13), up to their ceiling, past which no refresh is possible while the status is unknown.

    D-7b-1. Tasks 9, 10.
11. **A certificate the CRL or OCSP revokes is refused as 7a refuses a mark, before it binds.**
    - **At bind.** The status check runs before `bind`, while the connection is still charged to its
      source, so a revoked certificate never evicts its owner's connections and never holds a slot.
      It is answered `401 credential_revoked` and closed (pre-flight I1).
    - **At mint and refresh.** It is refused `credential_revoked`.
    - **A new CRL entry.**
      - **When it is marked.** It is revoked with 7a's `Broker.Revoke` (origin `crl <name>`), from a
        bounded queue rather than the loader's goroutine, wherever the certificate is still present:
        a held connection, a live context, an unspent token.
      - **A store error.** One reading those indexes puts the entry on a pending set retried at the
        next poll. It is never read as "present", so a store hiccup never marks a whole CRL (the CRL
        refuses the certificate at every use meanwhile) (pre-flight I9).
      - **Size.** A load that queues more than 100 revocations is said and counted.
    - **What is not marked.** An entry nothing holds is not marked, nor is a hold or a revoked
      intermediate. An OCSP `revoked` answer at bind, mint or refresh writes the leaf's mark the same
      way.

    Tasks 10, 11.
12. **The last good CRL outlives a restart, a failed load is retried soon, and the first fetch never
    delays device AAA.**
    - **Persistence.** Each verified list is written, 0600 and atomically, to the directory holding
      `broker.revocations_file` (`crl-<name>.der`). It is read behind the fence and verified again at
      start.
    - **Retries.** A source whose load failed is retried with backoff from 30s, doubling to
      `refresh_interval`.
    - **The first network load.** It runs after the TACACS+ and broker listeners bind. Until a list
      loads, `on_unavailable` governs as for any unknown status (pre-flight I8).

    Tasks 9, 11.

**One event meaning and three reason meanings are added** by Task 1, before any code (spec §5.7):
- `refresh` also records a session refresh, and `grants_matched` on it means the context was
  extended;
- `session_expired` gains its per-item `mint` and its `refresh` meanings;
- `trust_domain_unresolved` gains "status could not be established" (answered `503`) and "the
  refresh signature did not verify";
- `credential_revoked` gains "a CRL or OCSP response names it, or an intermediate above it".

No reason code is added.

## Decisions for Ryan

- **D-7b-1: is a certificate whose revocation status cannot be established refused or allowed, and
  is certificate status mandatory?** Spec §5.1.4 and design §7 say the broker checks revocation, and
  say nothing about a CRL publisher that is down at 3am. This plan rules **refuse** (Ruling 10), with
  **required** configuration that may say `disabled: true` (Ruling 8). Both choices are `on_unavailable:
  refuse | allow` and one required key, so changing the default is a one-line constant and a doc line,
  and no task depends on it. What each costs on a bad day, with the pre-flight fixes in:
  - **refuse (recommended):** a persisted, verified CRL keeps serving until its `NextUpdate` across
    restarts and short blips (Ruling 12). Past it, or with the OCSP responder down, new mints, logins
    and refreshes for the issuers covered are answered `503`, retried, with agents kept alive.
    - **What keeps working.** Live sessions keep working to their ceiling, and break-glass is
      untouched.
    - **The alarm.** `port49_crl_next_update_timestamp_seconds` alarms before it bites (CAs overlap
      their CRLs).
    - **What it buys.** Nobody holding a revoked certificate gets in while the publisher is down.
  - **allow:** logins continue through a publisher outage, alarmed. A certificate revoked during the
    outage keeps minting until the CRL returns, or until an operator runs `port49 revoke --cert`.
  This choice is separate from Ruling 10's shape: under either, an unavailable status never ends an
  agent's session.

## Revised after the pre-flight review (2026-10-01)

The pre-flight review (`.superpowers/sdd/2026-10-01-07b-session-lifetime-and-cert-status/preflight-review.md`)
found two critical, thirteen important and twenty-two minor problems. Every one is fixed with the
review's fix unless the line says otherwise; parts of one minor are rebutted. The rulings above and the
task text carry the fixes, and decision 33's text (Task 1) is amended to match.

- **C1** (a CRL acted on before it was verified): Rulings 8, 9. A required `issuer_file` per source,
  checked against the anchor at config load. Verification happens at load, before a list may replace
  the last good one, move the number floor, or report an entry. `ThisUpdate` rollback is refused, and
  sources are matched by issuer certificate. Task 9's tests: a forged list is refused and inert, and a
  forged high number does not move the floor.
- **C2** (OCSP without RFC 6960's checks): Ruling 9's OCSP clause, Task 9. The responder is the issuer
  or an in-validity delegate with the OCSP-signing EKU; the serial matches; `ThisUpdate` skew ≤ 5m;
  `NextUpdate` is in the future; an expired answer is never cached. Tests for each.
- **I1** (status checked after bind): Ruling 11, Task 10. Before bind, with a five-connection test.
- **I2** (intermediates unchecked): Ruling 9, Tasks 9 and 10. Every non-anchor certificate is
  checked; a revoked intermediate refuses the leaf, with no mark on it.
- **I3** (scoping extensions ignored): Ruling 9, Task 9, with a test per refusal.
- **I4** (unjudged contexts extended): Ruling 7, Tasks 5 and 7. `refreshContext` returns its
  outcome; only `unchanged` and landed `updated` are extended; the rest is `not_judged`.
- **I5** (a refresh kept the old window): Ruling 3, Tasks 4 and 7. `ContextRefresh.MaxSessionAge`
  sets the policy's ceiling from the new auth_time; `-1` keeps the window for the old callers.
- **I6** (the agent exited at its first deadline): Task 8. `agentMain` re-arms on a deadline change,
  with a test.
- **I7** (an unavailable status ended sessions): Ruling 10, Tasks 1, 8 and 10. `503
  certificate_status_unavailable` with `Retry-After`, the record still `trust_domain_unresolved`; the
  agent keeps its session. D-7b-1's choice is untouched.
- **I8** (restart and blip): Ruling 12, Tasks 9 and 11.
- **I9** (store errors marked every entry): Ruling 11, Task 10. A pending set, a bounded queue, and a
  threshold line, with a test.
- **I10** (refresh tests that measured nothing): Task 7. Every case signs correctly, so the property
  under test is the only defect; replay, 59s/61s and cross-connection exporter cases are added; the
  signature is checked absent from the log.
- **I11** (the helper could not carry the tests): Task 7 specifies `liveContextAt`: a 24h TTL, the
  policy's blob, and both indexes.
- **I12** (L2 on Junos measured nothing): Tasks 6 and 12. A lab switch fails the session
  authorization with the padded message on Junos, with break-glass ready (owner's prior: over 255
  bytes locked a user out); otherwise the note says not measurable and L2's Junos clause stays open.
- **I13** (nil dereference): Task 5 sets `Unreached` only where `rec.Session` exists.
- **Minors:**
  - M1 (rate-limited allow line) Task 10;
  - M2 (a refresh record for a revoked refresh) Task 7;
  - M3 (`grants_matched` on refresh) Task 1;
  - M4 (compare-and-set delete and extend) Tasks 4, 6, 7;
  - M5 (fixed 503 text) Task 7;
  - M6 (one line per device, aligned text) Task 8 and "What the operator sees";
  - M7 (`port49_crl_next_update_timestamp_seconds`, set at every load) Tasks 9, 11 and the operator
    notes;
  - M8 (names) throughout, in part rebutted below;
  - M9 (no duplicate `session:`; a 6m ceiling) Task 12;
  - M10 (allow-list) Ruling 4, Tasks 6, 13;
  - M11 (Junos `idle-timeout` from a per-role ceiling, and `policy diff` showing ceilings) carried to
    plan 12 by Task 13, with `explain` printing the ceiling in Task 2;
  - M12 (the hint and `--json`) Task 8;
  - M13 (`certificateHold`) Ruling 9;
  - M14 (`ocsp.hash`) Tasks 9, 11;
  - M15 (negative cache, shared request) Task 9;
  - M16 (`printsafe.Line` on peer text) Task 9;
  - M17 (rate limit) Ruling 6, Task 7;
  - M18 (a scripted refresh loop) Ruling 6 and the operator notes;
  - M19 (`!shortens` in the `sameSource` shortcut) Task 5;
  - M20 (the lab's broker-block rewrites, and the grace window's config comment) Tasks 6, 11;
  - M21 (the matrix row) Task 1;
  - M22 (refresh outcomes counted per context) Task 7.
- **M8 in part rebutted:** two of its names are right as the plan had them. `l.shell` exists
  (`func (l *lab) shell(user, password string) (*labShell, error)`, `tests/lab/l29_shell_test.go:20`).
  "Register rule 5" is spec §15's own rule 5 ("An entry may close differently per platform. A row
  with one platform measured and three open is still open."), which CLAUDE.md's four rules do not
  replace. The rest of M8 is fixed:
  - `RevokeTimeout`, through 7a's `detach`, not `revokeTimeout()`;
  - 7a's `revokeAgent` stop, which treats ESRCH as done, not `stopSliceAgentIfRunning`;
  - `(*lab).result`;
  - `SessionRefreshReport.Err` dropped from the interface list;
  - the listener's 10s line.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **Normal day.** port49d says at start `port49d: broker: certificate status from 1 CRL (corp_issuing,
  next update 2026-10-02T06:00:00Z) and OCSP (http://ocsp.example.com); a status that cannot be
  established is refused`. An operator works all day.
- **The warning.**
  - At 11h31m their next command prints `port49: session ends in 29m - run 'port49 refresh'`, on
    the platforms L34 finds show it (and any the operator lists in `session.ceiling_warning_platforms`).
  - `port49 token` also says on stderr `port49: your session on leaf-01 ends at 21:00:00Z (in 29m);
    run 'port49 refresh'`.
- **The refresh.** They run `port49 refresh`, which prints one line per device:

  ```
  refreshed at 2026-10-01T21:01:00Z; this login lasts until 2026-10-02T09:01:00Z
    leaf-01 (alice)    extended to 2026-10-02T09:01:00Z
    core-sw01 (alice)  extended to 2026-10-02T05:01:00Z
    edge-mx01 (alice)  extended to 2026-10-02T09:01:00Z, not reached: the device keeps its own session
  ```

  The next command is permitted with no message, and the candidate configuration is intact.
- **Missing the ceiling.** The next command is refused: `port49: session expired - run 'port49
  refresh' (or 'port49 login') within 10m to resume`. They run `port49 refresh` within the grace
  window and carry on.
- **Missing the grace window.** The command is refused `port49: session ended - get a new token
  ('port49 token') and log in again`. `port49 refresh` prints `  leaf-01 (alice)    past the grace
  window, not resumed: log in again there`.
- **A role tightened at 14:00** (`max_session_age: 1h` for `net-admin`). Every live context whose
  ceiling is later than auth_time+1h is shortened by the policy refresh. Each is one `refresh`
  record, and warnings start at the new time. A role loosened, or set to `never`, takes effect at
  each operator's next refresh or login.
- **3am, the CA's CRL publisher is down.** Nothing changes until the CRL port49d holds (persisted,
  so a restart keeps it) passes its `NextUpdate`; port49d retries the publisher from 30s with backoff
  and says each failure once. After `NextUpdate`:
  - every new `port49 login`, `port49 token` and `port49 refresh` for that issuer is answered `503`:
    `the broker cannot establish this certificate's revocation status (CRL corp_issuing is past its
    next update, 2026-10-02T06:00:00Z); try again`;
  - agents stay up and retry when told to; operators already on devices keep working to their
    ceiling, and break-glass is unaffected;
  - `time() - port49_crl_next_update_timestamp_seconds{crl="corp_issuing"} > 0` fired (alert well
    before, at `> -3600`) and `port49_cert_status_unavailable_total` climbs;
  - fix the publisher, or set `on_unavailable: allow` and restart port49d if you decide to accept the
    risk (D-7b-1).
- **Someone on the path serves a forged CRL or OCSP answer:** the list does not verify against
  `issuer_file`, is refused (`port49_crl_loads_total{outcome="refused"}`), and the last good list stays;
  a forged OCSP answer is `Unknown`. Nothing is revoked on its word.
- **A certificate is revoked at the CA.** At the next CRL poll (`refresh_interval`, default 10m),
  port49d says `port49d: broker: CRL corp_issuing names a certificate in use (issuer="CN=Corp
  Issuing CA", serial=3f9a01); revoking it`. That is a 7a revocation, origin `crl corp_issuing`: the
  held connection is closed, contexts marked, tokens deleted, and the `revoke` record names what was
  not reached. `port49 revoke --list` shows the mark.
- **A refresh from a stolen nonce, or on another connection:** `refresh deny trust_domain_unresolved`
  with `the refresh challenge was not answered by this connection's key`; nothing is extended.
- **An issuing CA is revoked by its root:** every leaf it issued is refused `credential_revoked` at
  its next login or mint (`this certificate's issuer, CN=…, was revoked at its CA`); no standing mark
  is written on the leaves.
- **Clocks.** CRL and OCSP freshness follow port49d's clock: an NTP step forward can make a fresh
  list stale. The `port49 token` warning follows the laptop's clock.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.22+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–7a, and still binding:

- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row.** A claim
  cited to an open row is unmeasured; do not "fix" a doc to assert it (lab register rules 1–4). The
  warning's display is L34's; L2's truncation length is L2's.
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.
- **Narrow setters only for live contexts** (`RefreshContext`, `SetContextPolicy`, `SetRevokedAt`,
  `DeleteContext`). `RefreshContext` still never lifts a revocation.
- **7a's ordering holds:** a revocation writes its mark first, through `Broker.Revoke`. Nothing here
  revokes another way.
- **A peer's text is printed only through `printsafe.Line`**, cut at 300 bytes. That covers a CRL's
  and an OCSP responder's text, and a certificate's names.

New in this plan:

- **The nonce, the signature and the exporter value are credentials of the moment.** They never
  reach a log, a record, an error or a metric. A refresh refused for its signature says why and
  never what.
- **No metric label names a principal, a certificate or a device.** The new labels are closed sets
  (`outcome`, `result`, `source` ∈ `crl`, `ocsp`, `none`) and `crl`, a source's configured name.
- **The code blocks are written against `872402f`.** Where the compiler or a test says a block is
  wrong about the tree, fix the block minimally, keep the behaviour the step's test asserts, and say
  so in the task's report and commit. Never weaken a test to make a block pass.
- **Every commit is preceded by `gofmt -w` on the Go files the task touched, then `make build &&
  make test && make vet`.** Report their real output.
- Branch `feature/session-lifetime-and-cert-status`; never commit code to `main`. Name every path in
  `git add`; never `git commit -a` (7a's 9e257ae).
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

## Running the lab (Task 12)

The lab host is beehive. The owner has given standing consent for lab runs; the lab is
single-occupant.

**Every run is made from a detached worktree pinned to a commit:** `git worktree add --detach
../port49-lab-7b <sha>`, then `make build` there. One platform at a time:
`PORT49_LAB_PLATFORMS=eos`, then `nxos`, `iosxe`, `vjunos`, `vsrx`.

**A stall watchdog runs for the whole run.** Its signals are the test log, capture growth and
results files, with a 25-minute stall threshold. Match the test binary exactly: `pgrep -f
"^/tmp/go-build[^ ]*/lab\.test"`. The run is long by design: each platform waits out one ceiling
and one grace window, about 20 minutes.

**After every platform,** confirm that no `port49d` holds `172.100.100.1:49`, that no agent is
running, and that the topology is destroyed.

**Before removing the worktree,** copy the raw captures to the main checkout's
`tests/lab/captures/`, then run `make evidence` there.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md   MOD  §5.1.4, §5.6, §5.7, §12, §13 d33, §15 L2 L34 (Task 1)
docs/design/2026-08-21-port49-design.md        MOD  §7, §12, §17 (Task 1)
internal/policy/file.go, load.go, resolve.go   MOD  role max_session_age; Resolution.SessionAge (Task 2)
internal/broker/broker.go, api/api.go          MOD  per-item ceiling; session_expires_at; ceiling_warning_seconds (Task 3)
internal/broker/refresh.go                     MOD  mintedBy's age; decideRefresh carries the ceiling; unreached (Tasks 3, 5)
internal/store/store.go, memory, crypt, storetest  MOD  ContextPolicy.MaxSessionAge; ContextRefresh.GraceCutoff;
                                                    ErrPastGrace (Task 4)
internal/decision/log.go                       MOD  Session.AuthTime, SessionExpires, Unreached (Task 5)
internal/platform/warning.go                   NEW  CeilingWarning (Task 6)
internal/daemon/author/author.go, lab.go       MOD  the warning; the grace sweep; the lab's padded message (Task 6)
internal/config/config.go                      MOD  session.ceiling_warning; lab.deny_message_length (Task 6);
                                                    broker.certificate_status (Task 11)
internal/broker/sessionrefresh.go              NEW  the challenge, the refresh, RefreshSession (Task 7)
internal/agent/agent.go, socket.go             MOD  Refresh; POST /refresh; warn from session_expires_at (Task 8)
cmd/port49/main.go, refresh.go                 MOD/NEW  port49 refresh; login refreshes (Task 8)
internal/certstatus/*.go                       NEW  CRL sources, OCSP, Checker (Task 9)
internal/broker/listen.go, certcheck.go        MOD/NEW  status at bind, mint, refresh; CRL entries revoked (Task 10)
internal/daemon/metrics/metrics.go             MOD  refresh, warning, certificate status metrics (Tasks 6, 7, 9)
cmd/port49d/main.go                            MOD  the checker's lifecycle, the broker's new fields (Task 11)
tests/lab/session_test.go, l2_test.go          NEW  L34, the refresh and grace end to end; L2 truncation (Task 12)
tests/lab/slice/session-policy.yaml            NEW  the slice policy with a 4m role (Task 12)
tests/lab/results/L34-*.md, L2-*.md, session-*.md  NEW  written by the run (Task 12)
docs/superpowers/plans/README.md               MOD  plan 7b as built (Task 13)
```

Thirteen tasks:
- **Task 1** is docs, and comes first: every later task cites the text it writes.
- **Tasks 2–11** are code, and every one leaves `make test` green:
  - 2 and 3: the per-role ceiling;
  - 4 and 5: the store and the policy refresh;
  - 6: the daemon's warning and grace;
  - 7 and 8: the refresh, broker and agent;
  - 9 to 11: certificate status.
- **Task 12** is the lab: L34 opened and measured, L2's remaining clauses, and the refresh and grace
  window end to end on five images. It gates the merge.
- **Task 13** is lab closure and docs.

---

### Task 1: The spec and the design say what plan 7b builds, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

No code. Each edit names a phrase to find (the files wrap their lines, so search for a phrase rather
than a whole sentence) and the text to put after it or in its place. Nothing here asserts device
behaviour: the warning's display is cited to L34, opened here.

- [ ] **Step 1: §5.1.4, certificate status as built.** After the last paragraph of the block that
  begins "**Revocation by principal or by certificate, as built (plan 7a", add:

  ```markdown
  **Certificate status, as built (plan 7b; §13, decision 33).** The broker checks every client
  certificate, and every certificate above it in its verified chain but the anchor, against the
  sources `broker.certificate_status` names.

  - **CRLs.** Each is read from a file or fetched over HTTP(S), polled every `refresh_interval`, and
    retried with backoff from 30s when a load fails. Each source names the CA certificate that signs
    it (`issuer_file`), which must be the trust anchor or signed by it.
  - **Verified before use.** A list is verified against that certificate before anything uses it: an
    unverified list never replaces the last good one, never moves its CRL number, and is never acted
    on.
  - **What is refused.** A list older than the last good one (by number or by `ThisUpdate`); a delta
    list; one carrying a critical extension other than its authority key identifier, its number, or
    an issuing distribution point that says only `onlyContainsUserCerts`; one with an entry carrying a
    critical extension.
  - **Which list applies.** It applies to a certificate when its issuer certificate is the one that
    verified it, and only until its `NextUpdate`.
  - **Persistence.** The last good list of each source is kept beside `broker.revocations_file`, so a
    restart keeps it.
  - **OCSP.** An answer is taken only when it verifies for the issuer, and its signer is the issuer or
    a delegate the issuer signed carrying `id-kp-OCSPSigning` inside its validity. Its serial must be
    the certificate's, its `ThisUpdate` no more than five minutes ahead, and its `NextUpdate`, when
    set, still to come. It is cached until the earlier of its `NextUpdate` and an hour.
  - **Precedence.** A list that names the serial is final; otherwise a fresh list covering the issuer
    decides, and then OCSP.

  A certificate a source revokes is answered `credential_revoked` before its connection binds, as a
  marked one is, and refused at every mint and refresh; so is every certificate under a revoked
  intermediate.

  When a list newly names a certificate something still holds (a held connection, a live context
  indexed under it, an unspent token), the broker revokes it as `port49 revoke --cert` does, its
  origin `crl <name>`. Everything it reaches is reached, and the mark outlives a list that later goes
  stale. A `certificateHold` entry, a revoked intermediate, and an entry nothing holds write no mark:
  each is refused at every use.

  A status that cannot be established (a stale list, a responder that does not answer, an issuer no
  source covers) is refused unless `on_unavailable: allow`. The refusal is answered as unavailable
  (HTTP 503, retried), never as a final verdict, so it ends no agent's session. Live sessions are
  never affected: the daemon never reads certificate status (decision 13). The configuration is
  required with a broker, and `disabled: true` is the explicit choice not to check.
  ```

- [ ] **Step 2: §5.6, session lifetime as built.** After the bullet list under "#### Session
  lifetime" (it ends with the bullet "**Refresh MUST be a fresh authentication event…** …a time at
  which possession was just proven."), add:

  ```markdown
  **As built (plan 7b; §13, decision 33).**

  - **The ceiling.** A role's `max_session_age` is a duration of at least 1m or `never`. The ceiling
    on a device is the least across the roles composing there, a role naming none taking
    `session.max_session_age_default`, and `never` only when every role says so. A device whose
    ceiling has passed since the connection authenticated is refused per item at mint,
    `session_expired`.
  - **A policy edit.** It shortens a live context's ceiling and never lengthens it.
  - **A refresh.** It sets the ceiling the policy in force gives, from the new `auth_time`, so a
    lengthened ceiling or `never` takes effect at the next refresh or login.
  - **The warning.**
    - It rides on the `server_msg` of permitted session and command authorization replies, within
      `session.ceiling_warning` (default 30m) of `session_expires`, to the platforms §15 L34 finds
      show it and still permit, and to any an operator lists.
    - It also goes on `port49 token`'s stderr, from the mint's `session_expires_at`, on every
      platform.
  - **Past the ceiling.** A context is denied `session_expired` and kept until the grace window
    (`session.grace_window`, default 10m) passes. Then it is deleted at its next authorization
    (teardown row 3), and no refresh resumes it. The delete and the refresh are compare-and-sets on
    the context's revision.
  - **The refresh on the certificate path.** It is `POST /v1/refresh/challenge` and `POST
    /v1/refresh`:
    - **The nonce.** 32 random bytes, good for 60s, once, on the connection that asked, signed by the
      certificate's key over the connection's TLS exporter value, so it cannot be answered on another
      connection. A connection may refresh once per 10s.
    - **The clock.** `auth_time` is the broker's verification time, and the held connection's session
      clock moves with it.
    - **What it extends.** Each of the principal's live contexts first takes the policy in force: a
      withdrawn grant is revoked, and only a context the policy has just judged and kept is extended,
      inside its grace window, each a `refresh` record.
    - **Who triggers it.** `port49 refresh` and `port49 login` run it; the agent never runs it on its
      own.
  ```

- [ ] **Step 3: §5.6, teardown row 3.** In the row `| 3 | **Session ceiling** — \`session_expires\`
  reached and the grace window elapsed | local, needs no external signal |`, replace "local, needs no
  external signal" with "local, needs no external signal: the daemon deletes the context at its first
  authorization past the window, and a refresh past it extends nothing (plan 7b)".

- [ ] **Step 4: §5.7, the `refresh` event.** In the events table's `refresh` row, replace "whether a
  live context takes the policy now in force, or is revoked (§5.1.3)" with:

  "whether a live context takes the policy now in force, or is revoked (§5.1.3); or, on a session
  refresh (`/v1/refresh`), whether it is extended, with `session.auth_time` and
  `session.session_expires` (§5.6). A context on a platform that never asks about a command carries
  `session.unreached: true` (decision 21)".

- [ ] **Step 5: §5.7, the reason codes.**
  - **`grants_matched`.** After "`refresh`: the policy in force was written into the live context",
    add "; or, on a session refresh, the context was extended".
  - **`session_expired`.** After its row's last sentence, add: "Per item on `mint`: the device's
    ceiling (the least `max_session_age` of its roles, §5.6) has passed since the connection
    authenticated; run `port49 refresh`. On `refresh`: the context is past its grace window and is not
    extended."
  - **`trust_domain_unresolved`.** After "`mint`: no configured verifier accepted the credential
    (design document §7)", add: "; or the revocation status of the certificate or one above it could
    not be established (a stale CRL, an OCSP responder that did not answer, an issuer no configured
    source covers) and `broker.certificate_status.on_unavailable` is `refuse` (§5.1.4). The API then
    answers 503 `certificate_status_unavailable`, to be retried, never a final 401. On `refresh`, also
    a refresh challenge not answered by the connection's key".
  - **`credential_revoked`.** In its row, after "on `mint`, a revocation by principal or by this
    certificate stands (§5.1.4)", add "or a CRL or OCSP response names the certificate or an
    intermediate above it".

- [ ] **Step 6: §12, the tooling.** After the `port49 revoke` paragraph (it begins "**`port49 revoke
  (--principal"), add:

  ```markdown
  **`port49 refresh`** re-authenticates the session the agent holds and extends every live context the
  policy in force still grants (§5.6). The agent signs the broker's nonce with the certificate's key
  over the held connection, and prints one line per device: extended to when, revoked by the policy,
  past its grace window, not judged, or on a platform the extension cannot reach. `port49 login` does
  the same while a session is held, and once after a new one connects. `port49 token` warns on stderr
  when the device's session ends within `session.ceiling_warning`. `port49 explain` prints a subject's
  ceiling on a device.
  ```

- [ ] **Step 7: §13, decision 33.** After decision 32's paragraph and before "### Deferred, with
  reasons", add:

  ```markdown
  **33. A session ends where its roles say, warns before, refreshes by a signed nonce, and every
  certificate's revocation status is checked at every use.** *Plan 7b, 2026-10-01, rulings where the
  spec was silent, each the option that denies more; revised after its pre-flight review.*

  - **The ceiling.** A role's `max_session_age` is a duration of at least 1m or `never`, the least
    across a device's roles governing, the default staying finite. A device whose ceiling has passed
    is refused per item at mint. A policy edit shortens a live ceiling and never lengthens one; a
    refresh sets the ceiling the policy in force gives.
  - **The warning.** It rides on permits within `session.ceiling_warning` (30m), to the platforms L34
    finds show it (an allow-list) and any an operator lists, and on `port49 token`'s stderr
    everywhere.
  - **Past the ceiling.** A context is kept through the grace window and deleted at its first
    authorization after it, by compare-and-set, and the store refuses to extend one past it.
  - **The refresh.** On the certificate path it is a single-use 60s nonce, signed by the certificate's
    key over the connection's TLS exporter value, at most one per connection per 10s, with `auth_time`
    the broker's verification time. It extends only contexts the policy in force has just judged and
    kept, and only an operator's `port49 refresh` or `port49 login` triggers it.
  - **Certificate status.**
    - **Configuration.** Required with a broker (`disabled: true` an explicit choice), every CRL
      source naming its signing CA (`issuer_file`), which the anchor must vouch for.
    - **CRLs.** A list is verified at load, before it may replace the last good one, move its number,
      or be acted on. A rollback, a delta, an unknown critical extension and a partitioned scope are
      refused. A list applies to a certificate whose verifying issuer is that source's issuer
      certificate, until its next update. It is persisted, and retried with backoff.
    - **The chain.** Every certificate but the anchor is checked.
    - **OCSP.** It is taken only from the issuer or an in-validity delegate with the OCSP-signing
      usage, for the right serial, fresh within five minutes' skew, and cached to its next update, at
      most an hour.
    - **Unknown.** A status that cannot be established is refused as unavailable (503, retried, no
      session ended) unless `on_unavailable: allow` (the owner to confirm, plan 7b D-7b-1).
    - **Revoked.** A revoked certificate is refused before it binds, at mint and at refresh. One a CRL
      newly names is revoked through decision 32's marks wherever it is still present, from a bounded
      queue, a store error deferring rather than marking.

  (§5.1.4, §5.6, §5.7, §12; design document §7, §12, §17)
  ```

- [ ] **Step 8: §15, L2 and L34.** In L2's Status, after "truncation length and IOS-XE unmeasured",
  add: "; plan 7b's lab run measures truncation on every image through `lab.deny_message_length`. That
  is a per-command denial on EOS, NX-OS and IOS-XE, and a session-authorization denial on Junos
  (`lab.deny_session`)". After the L33 row, add:

  ```markdown
  | **L34** | Whether a device shows the `server_msg` port49 puts on a **permitted** authorization reply — the session reply at login, and a per-command reply — and still treats the reply as a permit: the command's output appears and the session goes on. | The session-ceiling warning (§5.6, plan 7b; decision 33): sent only to the platforms this row finds show it and still permit (`platform.CeilingWarning`, an allow-list), or that an operator lists | EOS, NX-OS, IOS-XE, Junos | open — added 2026-10-01 by plan 7b; measured by its Task 12 |
  ```

- [ ] **Step 9: Design §7.** In the paragraph that begins "**X.509 client certificate** presented over
  mutual TLS", after "A refresh on the held connection is an application-level signed nonce", add ",
  bound to the connection by its TLS exporter value (plan 7b)".

- [ ] **Step 10: Design §17, the surface.** In the code block under "### Surface", after the `POST
  /v1/refresh` line, add:

  ```
  POST  /v1/refresh/challenge  certificate path: a single-use nonce the agent signs for /v1/refresh
  ```

- [ ] **Step 11: Design §12, the failure matrix.** After the row that begins `| **Revocations file
  missing or refused**`, add:

  ```markdown
  | **Certificate status unavailable** (a CRL past its next update, an OCSP responder down; policy engine spec §5.1.4) | ✗ for the issuers it covers, with `on_unavailable: refuse` (the default), answered 503 and retried, no agent session ended; ✓ alarmed with `allow`. A verified CRL persisted before the outage serves until its next update, across restarts | ✗ (no new token), as the column before | ✓ until its ceiling; no refresh while the status is unknown. The daemon never reads certificate status | ✗ new mints; tokens already minted still redeem |
  ```

- [ ] **Step 12: Check and commit.** `make test && make vet`.

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: session lifetime, the signed-nonce refresh, certificate status, L34 (plan 7b)

  Spec §5.1.4, §5.6, §5.7 (refresh records a session refresh; grants_matched, session_expired,
  trust_domain_unresolved and credential_revoked gain meanings; no reason added), §12,
  §13 decision 33, §15 L2 and the new L34; design §7, §12, §17.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 2: A role declares `max_session_age`, and a device's ceiling is the least of its roles'

**Files:**
- Modify: `internal/policy/file.go` (`fileRole`), `internal/policy/load.go` (`Role`; `buildRoles`;
  the refusal of plan 4 removed), `internal/policy/resolve.go` (`Resolution.SessionAge`, `resolved`),
  `internal/policy/explain.go` (the ceiling line, pre-flight M11)
- Test: `internal/policy/load_test.go`, `internal/policy/resolve_test.go`, `internal/policy/explain_test.go`

**Interfaces:**
- Produces:
  - `policy.Role.MaxSessionAge *time.Duration` (nil: the role names none; 0: `never`)
  - `type policy.SessionAge struct { Least time.Duration; Unset bool }` and
    `func (a SessionAge) Of(def time.Duration) time.Duration` (0 is `never`)
  - `policy.Resolution.SessionAge SessionAge`

The policy does not know port49d's `session.max_session_age_default`: `Of` takes it, so the
offline tools and the broker compose the same way and no `policy.Env` changes.

- [ ] **Step 1: The tests.** In `load_test.go`:

  ```go
  // A role's max_session_age is a duration of at least a minute, or never;
  // anything else refuses the policy, naming the role (spec §5.6; decision 33).
  func TestARolesMaxSessionAgeIsADurationOrNever(t *testing.T) {
  	base := "scopes: [{name: all_devices, match: {}}]\n" +
  		"subjects: [{name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}]\n" +
  		"grants: [{subject: s, scope: all_devices, roles: [r]}]\n"
  	for value, ok := range map[string]bool{"8h": true, "never": true, "1m": true, "30s": false, "soon": false,
  		"\"\"": false, "-1h": false} {
  		_, err := loadString(t, base+"roles: [{name: r, privilege: admin, permit: [\"**\"], max_session_age: "+value+"}]\n")
  		if ok != (err == nil) {
  			t.Errorf("max_session_age %s: %v", value, err)
  		}
  		if err != nil && !strings.Contains(err.Error(), `role "r"`) {
  			t.Errorf("%s: the refusal names no role: %v", value, err)
  		}
  	}
  }
  ```

  (`loadString` is the helper `load_test.go` uses to load a policy from text against a one-device
  inventory; if it has another name there, use that. The plan-4 test that expected "max_session_age
  per role is plan 7's" is deleted.) In `resolve_test.go`:

  ```go
  // The ceiling is the least across the roles that compose on the device; a
  // role naming none takes port49d's default; never only when every role
  // says never (spec §5.6).
  func TestTheSessionAgeIsTheLeastOfTheRoles(t *testing.T) {
  	for _, tc := range []struct {
  		ages []string // one role per entry; "" names none
  		def  time.Duration
  		want time.Duration
  	}{
  		{[]string{"8h", "2h"}, 12 * time.Hour, 2 * time.Hour},
  		{[]string{"8h", ""}, 12 * time.Hour, 8 * time.Hour},
  		{[]string{"8h", ""}, 4 * time.Hour, 4 * time.Hour},
  		{[]string{"never", "never"}, 12 * time.Hour, 0},
  		{[]string{"never", ""}, 12 * time.Hour, 12 * time.Hour},
  		{[]string{"never", "3h"}, 12 * time.Hour, 3 * time.Hour},
  		{[]string{""}, 12 * time.Hour, 12 * time.Hour},
  	} {
  		var roles, names []string
  		for i, a := range tc.ages {
  			name := fmt.Sprintf("r%d", i)
  			line := fmt.Sprintf("  - {name: %s, privilege: admin, permit: [\"**\"]", name)
  			if a != "" {
  				line += ", max_session_age: " + a
  			}
  			roles, names = append(roles, line+"}"), append(names, name)
  		}
  		p := mustLoadString(t, "scopes: [{name: all_devices, match: {}}]\nroles:\n"+strings.Join(roles, "\n")+"\n"+
  			"subjects: [{name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}]\n"+
  			"grants: [{subject: s, scope: all_devices, roles: ["+strings.Join(names, ", ")+"]}]\n")
  		res, err := p.Resolve("user:a@example.com", oneDevice(), time.Now())
  		if err != nil {
  			t.Fatal(err)
  		}
  		if got := res.SessionAge.Of(tc.def); got != tc.want {
  			t.Errorf("%v with default %s: %s, want %s", tc.ages, tc.def, got, tc.want)
  		}
  	}
  }
  ```

  (`mustLoadString` and `oneDevice` stand for the file's existing load-and-device helpers; use
  theirs.)

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/policy/ -run 'MaxSessionAge|SessionAge' -count=1`
  Expected: FAIL (plan 4's refusal; `SessionAge` undefined).

- [ ] **Step 3: The file and the role.** In `file.go`'s `fileRole`, add
  `MaxSessionAge *string `yaml:"max_session_age"``: a pointer, so an absent key (nil) is told from an
  explicit empty one, which is refused. (A `null` value decodes as nil too; the loose-decode pass
  already refuses a null in a `platforms:` block, so refuse a null `max_session_age` there in the same
  way, naming the role.) In `load.go`'s `Role`, add:

  ```go
  	// MaxSessionAge is how long a session may run on one authentication
  	// event under this role (spec §5.6): nil names none, and the role takes
  	// session.max_session_age_default; zero is `never`.
  	MaxSessionAge *time.Duration
  ```

  Replace the loop in the loose-decode check that refuses `max_session_age` on a role ("per role is
  plan 7's") with one that refuses only a null value (`if v, ok := r["max_session_age"]; ok && v ==
  nil`, naming the role as the old loop did). In `buildRoles`, after `role := &Role{...}`:

  ```go
  		if r.MaxSessionAge != nil {
  			age, err := parseSessionAge(*r.MaxSessionAge)
  			if err != nil {
  				return fmt.Errorf("role %q: max_session_age: %w", r.Name, err)
  			}
  			role.MaxSessionAge = &age
  		}
  ```

  Add:

  ```go
  // parseSessionAge reads a role's max_session_age: `never` (zero), or a
  // duration of at least a minute (spec §5.6; decision 33). A shorter one
  // would expire a session between two commands.
  func parseSessionAge(s string) (time.Duration, error) {
  	if s == "never" {
  		return 0, nil
  	}
  	d, err := time.ParseDuration(s)
  	if err != nil || d < time.Minute {
  		return 0, fmt.Errorf("must be a duration of at least 1m, or never; got %q", s)
  	}
  	return d, nil
  }
  ```

- [ ] **Step 4: The composition.** In `resolve.go`, beside `Resolution`:

  ```go
  // SessionAge is the max_session_age the roles composing on a device declare
  // (spec §5.6): Least is the least finite one, zero when none declares a
  // finite one; Unset is whether some role declares none and takes the
  // default.
  type SessionAge struct {
  	Least time.Duration
  	Unset bool
  }

  // Of is the ceiling given port49d's default: the least across the roles, a
  // role declaring none taking def; zero, never, only when every role says
  // never.
  func (a SessionAge) Of(def time.Duration) time.Duration {
  	age := a.Least
  	if a.Unset && (age == 0 || def < age) {
  		age = def
  	}
  	return age
  }
  ```

  add `SessionAge SessionAge` to `Resolution` (with a comment: "the roles' max_session_age, which
  the broker reads with port49d's default (SessionAge.Of)"), and in `resolved`, after `res` is
  built:

  ```go
  	for _, name := range c.roles {
  		switch age := p.roles[name].MaxSessionAge; {
  		case age == nil:
  			res.SessionAge.Unset = true
  		case *age > 0 && (res.SessionAge.Least == 0 || *age < res.SessionAge.Least):
  			res.SessionAge.Least = *age
  		}
  	}
  ```

- [ ] **Step 5: `explain` says the ceiling.** In `explain.go`, after the `level` line:

  ```go
  	switch a := r.SessionAge; {
  	case a.Least == 0 && !a.Unset:
  		fmt.Fprintf(w, "  session     max_session_age never (every role says never)\n")
  	case a.Least == 0:
  		fmt.Fprintf(w, "  session     max_session_age session.max_session_age_default (no role names one)\n")
  	case a.Unset:
  		fmt.Fprintf(w, "  session     max_session_age the lesser of %s and session.max_session_age_default\n", a.Least)
  	default:
  		fmt.Fprintf(w, "  session     max_session_age %s (the least of its roles')\n", a.Least)
  	}
  ```

  with an `explain_test.go` case for a role at `2h` beside one naming none. (`policy diff` reporting
  a changed ceiling is carried to plan 12 with the Junos `idle-timeout` classes; Task 13.)

- [ ] **Step 6: Run them.** `go test ./internal/policy/ -count=1 -race` → PASS. Then `gofmt -w`,
  `make build && make test && make vet`.

- [ ] **Step 7: Commit.**

  ```bash
  git add internal/policy
  git commit -m "feat(policy): max_session_age per role, the least of a device's roles

  A role declares a duration of at least 1m or never; Resolution.SessionAge composes them and
  Of applies port49d's default to a role that names none. Plan 4's refusal of the key is gone.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 3: The mint carries each device's ceiling, and refuses a device whose ceiling has passed

**Files:**
- Modify: `internal/broker/broker.go` (`Broker.CeilingWarning`; `config`; `mintOne`; `putBlob`)
- Modify: `internal/broker/api/api.go` (`Config.CeilingWarningSeconds`, `MintItem.SessionExpiresAt`)
- Modify: `internal/broker/refresh.go` (`minted.age`, `mintedBy`'s default, `keeps`)
- Test: `internal/broker/broker_test.go`, `internal/broker/refresh_test.go`

**Interfaces:**
- Consumes: Task 2's `SessionAge.Of`.
- Produces:
  - `Broker.CeilingWarning time.Duration` (port49d's `session.ceiling_warning`), sent as
    `api.Config.CeilingWarningSeconds` (`ceiling_warning_seconds`).
  - `api.MintItem.SessionExpiresAt string` (`session_expires_at`, RFC 3339; empty for `never`).
  - `func mintedBy(p *policy.Policy, principal string, d admission.Device, at time.Time, def time.Duration) (minted, bool)`;
    `mintedFor` keeps that signature.
  - `func (b *Broker) putBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error`

- [ ] **Step 1: The tests.** In `broker_test.go`, using a fixture policy whose `network_admin` role
  carries `max_session_age: 1h` (add a `newFixtureWithPolicy(t, cap, policyText)` helper beside
  `newFixture` if the file has none):

  ```go
  // A device's ceiling is its roles', on the token and on the item; a device
  // whose ceiling has passed since the connection authenticated is refused
  // per item, session_expired, and another device on the same connection is
  // not (spec §5.6; decision 33).
  func TestTheMintCarriesEachDevicesCeiling(t *testing.T) {
  	f := newFixtureWithPolicy(t, 8, strings.Replace(testPolicy,
  		"{name: network_admin, privilege: admin, permit: [\"**\"]}",
  		"{name: network_admin, privilege: admin, permit: [\"**\"], max_session_age: 1h}", 1))
  	ctx := context.Background()
  	auth := f.now
  	r := decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
  	if r.Results[0].SessionExpiresAt != auth.Add(time.Hour).UTC().Format(time.RFC3339) {
  		t.Fatalf("session_expires_at: %+v", r.Results[0])
  	}
  	toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"})
  	if len(toks) != 1 || toks[0].MaxSessionAge != time.Hour {
  		t.Fatalf("the token's max_session_age: %+v", toks)
  	}
  	// An hour on, on a connection that authenticated at auth: refused per item.
  	f.advance(time.Hour)
  	r = decodeMint(t, f.postAt(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, "", auth))
  	if r.Results[0].Verdict != "deny" || r.Results[0].Reason != "session_expired" ||
  		!strings.Contains(r.Results[0].Detail, "port49 refresh") {
  		t.Fatalf("a device past its ceiling: %+v", r.Results[0])
  	}
  }

  // A role whose ceiling was shortened supersedes the tokens minted under the
  // longer one; a lengthened one does not (decision 33's shorten-only rule,
  // carried to tokens as token_ttl's is).
  func TestAShortenedCeilingSupersedesTokens(t *testing.T) {
  	long := minted{username: "a", ttl: time.Minute, age: 8 * time.Hour}
  	short := long
  	short.age = time.Hour
  	never := long
  	never.age = 0
  	if long.keeps(short) || !short.keeps(long) || never.keeps(long) || !long.keeps(never) {
  		t.Fatal("keeps must refuse a token whose ceiling is longer than the policy in force allows")
  	}
  }
  ```

  (`postAt` posts with a held-connection state authenticated at the given time: `withHeldConn(ctx,
  at)` on the request's context, as `Server`'s `ConnContext` does. Add it beside `post`.)

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/broker/ -run 'Ceiling' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 3: The wire.** In `api.go`, add to `Config`
  `CeilingWarningSeconds int `json:"ceiling_warning_seconds,omitempty"``, and to `MintItem`:

  ```go
  	// SessionExpiresAt is when a login with this token stops being
  	// authorized: the connection's authentication plus the device's
  	// max_session_age (spec §5.6). Empty when the roles say never.
  	SessionExpiresAt string `json:"session_expires_at,omitempty"`
  ```

- [ ] **Step 4: The broker.** Add `CeilingWarning time.Duration` to `Broker` (comment:
  "session.ceiling_warning, told to the agent by /v1/config so `port49 token` warns too (plan
  7b)"); `config` sets `CeilingWarningSeconds: int(b.CeilingWarning / time.Second)`. In `mintOne`,
  after the `MintCheck` switch and before the blob is encoded:

  ```go
  	// The device's ceiling is the least of its roles' (spec §5.6). One that
  	// has passed since this connection authenticated would mint a token for a
  	// context born expired: refused for this device alone, and `port49
  	// refresh` resumes it (decision 33).
  	age := res.SessionAge.Of(b.MaxSessionAge)
  	if age > 0 && !b.Now().Before(authTime.Add(age)) {
  		item := deny(decision.SessionExpired, dev.Platform)
  		item.Detail = "this device's session ceiling has passed since you authenticated; run 'port49 refresh'"
  		return item, nil
  	}
  ```

  pass `MaxSessionAge: age` in the token's `Subject` (in place of `b.MaxSessionAge`), call
  `b.putBlob(ctx, hash, body, blobTTL(age, b.MaxSessionAge))`, and on the permit item set
  `SessionExpiresAt: authTime.Add(age).UTC().Format(time.RFC3339)` when `age > 0`. Add:

  ```go
  // blobTTL is how long a minted blob is kept: as long as the longest context
  // it can back at mint (decision 19). A `never` context keeps it alive by
  // the daemon's bump on activity (plan 7b, Task 6).
  func blobTTL(age, def time.Duration) time.Duration {
  	return max(age, def)
  }
  ```

  and give `putBlob` a `ttl` parameter in place of `b.MaxSessionAge`; the refresh's call passes
  `b.MaxSessionAge` (its contexts are bumped by the daemon).

- [ ] **Step 5: The token supersede.** In `refresh.go`, add `age time.Duration` to `minted`; give
  `mintedBy` a `def time.Duration` parameter and set `age: res.SessionAge.Of(def)`; update
  `mintedFor` and its callers to pass `b.MaxSessionAge`; and make `keeps`:

  ```go
  func (m minted) keeps(o minted) bool {
  	return m.username == o.username && bytes.Equal(m.blob, o.blob) && m.ceiling == o.ceiling &&
  		m.enable == o.enable && m.ttl <= o.ttl && !longerAge(m.age, o.age)
  }

  // longerAge reports whether a ceiling of a outlasts one of b, zero being
  // never: a token minted under a longer ceiling than the policy in force
  // allows is superseded, as a longer token_ttl is (decision 33).
  func longerAge(a, b time.Duration) bool {
  	return b != 0 && (a == 0 || a > b)
  }
  ```

  Update the doc comment on `keeps` to name the ceiling beside `token_ttl`.

- [ ] **Step 6: Run them.** `go test ./internal/broker/ -count=1 -race` → PASS. Then `gofmt -w`,
  `make build && make test && make vet`.

- [ ] **Step 7: Commit.**

  ```bash
  git add internal/broker
  git commit -m "feat(broker): mint each device's ceiling, refusing one already past

  The token's max_session_age is the least of the device's roles' with port49d's default; the
  item says session_expires_at; a device whose ceiling has passed since the connection
  authenticated is refused session_expired per item. A shortened ceiling supersedes tokens.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 4: The store shortens a ceiling on a policy write, sets one on a refresh, refuses to extend past the grace window, and binds the extend and the delete to the revision read

**Files:**
- Modify: `internal/store/store.go`:
  - `ContextPolicy.MaxSessionAge`;
  - `ContextRefresh.SessionAge`, `ContextRefresh.GraceCutoff`, `ContextRefresh.ExpectRev`;
  - `ErrPastGrace`;
  - `DeleteContextIf`;
  - the comments on `SetContextPolicy` and `RefreshContext`.
- Modify: `internal/store/memory/memory.go` (`SetContextPolicy`, `RefreshContext`, `DeleteContextIf`)
- Modify: `internal/store/crypt/crypt.go` (`DeleteContextIf` passes through)
- Modify: `internal/store/storetest/storetest.go` (`CeilingShortensOnly`, `RefreshSetsTheCeiling`,
  `RefreshStopsAtGrace`, `WritesBindToTheRevision`)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore.DeleteContextIf`)
- Test: `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go`

**Interfaces:**
- Produces:
  - `store.ContextPolicy.MaxSessionAge time.Duration`: the policy's ceiling (0 never). A policy write
    sets `SessionExpires = AuthTime + MaxSessionAge` only when that is earlier than the context's, or
    the context has none; zero changes nothing.
  - `store.ContextRefresh.SessionAge *time.Duration`:
    - nil keeps the window, as before (`session.Manager.Refresh`'s callers);
    - zero clears the ceiling (`never`);
    - otherwise `SessionExpires = AuthTime + *SessionAge` (pre-flight I5).
  - `store.ContextRefresh.GraceCutoff time.Time`: when non-zero, a context with a ceiling earlier than
    it is not refreshed (`ErrPastGrace`) and nothing is written.
  - `store.ContextRefresh.ExpectRev uint64`: when non-zero, the refresh writes only while the
    context's `Rev` is this, else `ErrConflict` (pre-flight M4).
  - `var store.ErrPastGrace`
  - `DeleteContextIf(ctx context.Context, k ContextKey, rev uint64) error`: deletes only while the
    context's `Rev` is `rev`; `ErrConflict` otherwise, `ErrNotFound` when absent.
  - the four `storetest` properties above.

The sealing layer passes everything through: `SessionExpires`, `AuthTime` and `Rev` are plaintext
bookkeeping, as `RevokedAt` is.

- [ ] **Step 1: The properties.** In `storetest.go`:

  ```go
  // CeilingShortensOnly is decision 33's rule for a policy edit: a policy
  // write shortens a context's ceiling, gives one to a context with none, and
  // never lengthens or removes one.
  func CeilingShortensOnly(t *testing.T, newStore func() store.Store, now time.Time) {
  	t.Helper()
  	ctx := context.Background()
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	auth := now.Add(-time.Hour)
  	for _, tc := range []struct {
  		name    string
  		expires time.Time // zero: no ceiling
  		age     time.Duration
  		want    time.Time
  	}{
  		{"shortened", auth.Add(8 * time.Hour), 2 * time.Hour, auth.Add(2 * time.Hour)},
  		{"never lengthened", auth.Add(2 * time.Hour), 8 * time.Hour, auth.Add(2 * time.Hour)},
  		{"given one", time.Time{}, 2 * time.Hour, auth.Add(2 * time.Hour)},
  		{"never removed", auth.Add(2 * time.Hour), 0, auth.Add(2 * time.Hour)},
  	} {
  		s := newStore()
  		if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b1",
  			AuthTime: auth, SessionExpires: tc.expires, RefreshedAt: auth}, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  		c, _ := s.GetContext(ctx, k)
  		if err := s.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "b2", MaxSessionAge: tc.age}); err != nil {
  			t.Fatal(err)
  		}
  		if c, _ := s.GetContext(ctx, k); !c.SessionExpires.Equal(tc.want) {
  			t.Errorf("%s: session_expires %v, want %v", tc.name, c.SessionExpires, tc.want)
  		}
  	}
  }

  // RefreshSetsTheCeiling: a refresh is a fresh authentication event, so it
  // sets the ceiling it is given from the new auth_time, lengthening, or
  // clearing it for never; one given none keeps the window (spec §5.6).
  func RefreshSetsTheCeiling(t *testing.T, newStore func() store.Store, now time.Time) {
  	t.Helper()
  	ctx := context.Background()
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	auth := now.Add(-time.Hour)
  	eight, never := 8*time.Hour, time.Duration(0)
  	for _, tc := range []struct {
  		name string
  		age  *time.Duration
  		want time.Time
  	}{
  		{"set", &eight, now.Add(8 * time.Hour)},
  		{"never", &never, time.Time{}},
  		{"window kept", nil, now.Add(2 * time.Hour)},
  	} {
  		s := newStore()
  		if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b",
  			AuthTime: auth, SessionExpires: auth.Add(2 * time.Hour), RefreshedAt: auth}, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  		if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now, SessionAge: tc.age},
  			time.Hour); err != nil {
  			t.Fatal(err)
  		}
  		if c, _ := s.GetContext(ctx, k); !c.SessionExpires.Equal(tc.want) {
  			t.Errorf("%s: session_expires %v, want %v", tc.name, c.SessionExpires, tc.want)
  		}
  	}
  }

  // RefreshStopsAtGrace: a refresh whose GraceCutoff is after the context's
  // ceiling writes nothing and says so (spec §5.6, teardown row 3); one inside
  // the window resumes the context.
  func RefreshStopsAtGrace(t *testing.T, newStore func() store.Store, now time.Time) {
  	t.Helper()
  	ctx := context.Background()
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	s := newStore()
  	auth := now.Add(-3 * time.Hour)
  	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b",
  		AuthTime: auth, SessionExpires: auth.Add(2 * time.Hour), RefreshedAt: auth}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now,
  		GraceCutoff: now.Add(-10 * time.Minute)}, time.Hour)
  	if !errors.Is(err, store.ErrPastGrace) {
  		t.Fatalf("a context an hour past its ceiling with a 10m window: %v", err)
  	}
  	if c, _ := s.GetContext(ctx, k); !c.AuthTime.Equal(auth) {
  		t.Fatal("a refused refresh wrote")
  	}
  	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now,
  		GraceCutoff: now.Add(-2 * time.Hour)}, time.Hour); err != nil {
  		t.Fatalf("inside the window: %v", err)
  	}
  }

  // WritesBindToTheRevision: a refresh with ExpectRev, and DeleteContextIf,
  // act only on the record read; a write landing in between makes each
  // ErrConflict and leaves the record (pre-flight M4).
  func WritesBindToTheRevision(t *testing.T, newStore func() store.Store, now time.Time) {
  	t.Helper()
  	ctx := context.Background()
  	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
  	s := newStore()
  	if err := s.PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:a", Username: "alice", BlobHash: "b",
  		AuthTime: now, SessionExpires: now.Add(time.Hour), RefreshedAt: now}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	read, _ := s.GetContext(ctx, k)
  	if err := s.SetPrivilege(ctx, k, 15); err != nil { // another writer lands
  		t.Fatal(err)
  	}
  	if err := s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now, ExpectRev: read.Rev},
  		time.Hour); !errors.Is(err, store.ErrConflict) {
  		t.Fatalf("a refresh against a stale revision: %v", err)
  	}
  	if err := s.DeleteContextIf(ctx, k, read.Rev); !errors.Is(err, store.ErrConflict) {
  		t.Fatalf("a delete against a stale revision: %v", err)
  	}
  	cur, _ := s.GetContext(ctx, k)
  	if err := s.DeleteContextIf(ctx, k, cur.Rev); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
  		t.Fatal("the delete at the current revision did not delete")
  	}
  }
  ```

  Call all four from `memory_test.go` and, through `Wrap(memory.New(...), keys(), nil)`, from
  `crypt_test.go`, as the file's other properties are called.

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/store/... -run 'Ceiling|Grace|Revision' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 3: The interface.** In `store.go`:

  ```go
  // ErrPastGrace is RefreshContext refusing a context whose ceiling is
  // earlier than the refresh's GraceCutoff: past the grace window, a session
  // is over and no refresh resumes it (spec §5.6, teardown row 3). Nothing
  // was written.
  var ErrPastGrace = errors.New("store: context is past its grace window")
  ```

  Add to `ContextRefresh`:

  ```go
  	// SessionAge, when set, is the ceiling the policy in force gives this
  	// context: SessionExpires becomes AuthTime plus it, and zero clears it
  	// (never). A refresh is a fresh authentication event, so it may lengthen
  	// a ceiling (spec §5.6; decision 33). Nil keeps the window the record's
  	// own pair described, as before.
  	SessionAge *time.Duration
  	// GraceCutoff, when non-zero, is the earliest ceiling a refresh may
  	// extend: the refresh time less the grace window. A context with a
  	// ceiling before it is ErrPastGrace and is not written. It is checked
  	// under the store's lock, so a refresh racing the window's end cannot
  	// resume a session the window closed.
  	GraceCutoff time.Time
  	// ExpectRev, when non-zero, is the revision the caller read: the write
  	// lands only on that record, else ErrConflict, so a context another
  	// principal's login replaced in between is not extended.
  	ExpectRev uint64
  ```

  and to `ContextPolicy`:

  ```go
  	// MaxSessionAge is the policy's ceiling for this principal on this
  	// device, zero for never (spec §5.6). SessionExpires becomes AuthTime
  	// plus it only when that is earlier, or the context has none: a policy
  	// edit shortens a session, and only a fresh authentication event
  	// lengthens one (decision 33). Zero changes nothing.
  	MaxSessionAge time.Duration
  ```

  and to `Store`, after `DeleteContext`:

  ```go
  	// DeleteContextIf deletes the context only while its Rev is rev, the
  	// revision the caller read: ErrConflict otherwise, ErrNotFound when it is
  	// absent. The grace window's sweep uses it, so it never deletes a context
  	// a login wrote since it was read.
  	DeleteContextIf(ctx context.Context, k ContextKey, rev uint64) error
  ```

- [ ] **Step 4: The memory store.** In `RefreshContext`, after the found check:

  ```go
  	if r.ExpectRev != 0 && e.rev != r.ExpectRev {
  		return store.ErrConflict
  	}
  	if !r.GraceCutoff.IsZero() && e.c.HasCeiling() && e.c.SessionExpires.Before(r.GraceCutoff) {
  		return store.ErrPastGrace
  	}
  ```

  and replace the window recompute with:

  ```go
  	switch {
  	case r.SessionAge != nil && *r.SessionAge == 0:
  		e.c.SessionExpires = time.Time{}
  	case r.SessionAge != nil:
  		e.c.SessionExpires = r.AuthTime.Add(*r.SessionAge)
  	case e.c.HasCeiling():
  		e.c.SessionExpires = r.AuthTime.Add(e.c.SessionExpires.Sub(e.c.AuthTime))
  	}
  ```

  In `SetContextPolicy`'s non-revoking branch, after the privilege clamp:

  ```go
  		if p.MaxSessionAge > 0 && !e.c.AuthTime.IsZero() {
  			if cap := e.c.AuthTime.Add(p.MaxSessionAge); e.c.SessionExpires.IsZero() || cap.Before(e.c.SessionExpires) {
  				e.c.SessionExpires = cap
  			}
  		}
  ```

  (A context with a zero `AuthTime` is the lab's instrument's and has no ceiling to measure from.)
  Add:

  ```go
  func (s *Store) DeleteContextIf(_ context.Context, k store.ContextKey, rev uint64) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	e, ok := s.contexts[k]
  	if !ok || !e.exp.After(s.now()) {
  		delete(s.contexts, k)
  		return store.ErrNotFound
  	}
  	if e.rev != rev {
  		return store.ErrConflict
  	}
  	delete(s.contexts, k)
  	return nil
  }
  ```

  In `crypt.go`, `DeleteContextIf` passes through; in `authen_test.go`'s `noStore`, it panics.

- [ ] **Step 5: Run them.** `go test ./internal/store/... ./internal/daemon/authen/ -count=1 -race` →
  PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 6: Commit.**

  ```bash
  git add internal/store internal/daemon/authen/authen_test.go
  git commit -m "feat(store): ceilings shortened by policy and set by refresh; grace; revision-bound writes

  ContextPolicy.MaxSessionAge shortens session_expires or gives a context one; a refresh's
  SessionAge sets it from the new auth_time (never clears it); GraceCutoff refuses to extend
  past the window (ErrPastGrace); ExpectRev and DeleteContextIf act only on the record read.
  Each is a storetest property every backend must pass.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 5: The policy refresh carries the ceiling, and its records name what they cannot reach

**Files:**
- Modify: `internal/broker/refresh.go` (`decideRefresh`, `refreshContext`)
- Modify: `internal/decision/log.go` (`Session.AuthTime`, `SessionExpires`, `Unreached`)
- Test: `internal/broker/refresh_test.go`

**Interfaces:**
- Consumes: Task 4's `ContextPolicy.MaxSessionAge`; Task 2's `SessionAge`.
- Produces: `decision.Session` gains `AuthTime string` (`auth_time`), `SessionExpires string`
  (`session_expires`), `Unreached bool` (`unreached`), each `omitempty`, rendered as `ts` is
  (`FormatTime`).

- [ ] **Step 1: The tests.** In `refresh_test.go`, using its fixture, add the two tests below and a
  third, `TestAnUnchangedContextDoesNotPanic`, which runs a refresh over a context the policy in force
  leaves unchanged (it fails today's draft with a nil dereference; pre-flight I13):

  ```go
  // A role shortened in the policy shortens every live context's ceiling at
  // the next refresh, and says so on the record; one lengthened does not
  // (decision 33).
  func TestAPolicyRefreshShortensALiveCeiling(t *testing.T) {
  	f := newRefreshFixture(t) // the file's fixture: one live context for alice on leaf1, 12h ceiling
  	f.load(t, strings.Replace(f.policyText, `permit: ["**"]}`, `permit: ["**"], max_session_age: 1h}`, 1))
  	rep, err := f.b.Refresh(context.Background(), nil)
  	if err != nil || rep.Updated != 1 {
  		t.Fatalf("%+v %v", rep, err)
  	}
  	c := f.context(t, "leaf1", "alice")
  	if !c.SessionExpires.Equal(c.AuthTime.Add(time.Hour)) {
  		t.Fatalf("session_expires %v, auth_time %v", c.SessionExpires, c.AuthTime)
  	}
  	rec := lastRecord(t, f, "refresh")
  	if rec["session"].(map[string]any)["session_expires"] == nil {
  		t.Fatalf("the record does not say the ceiling moved: %v", rec)
  	}
  }

  // A refresh record for a context on a platform that never asks about a
  // command says unreached (decision 21; carried from plan 7a).
  func TestARefreshRecordNamesAnUnreachedContext(t *testing.T) {
  	f := newRefreshFixture(t)
  	f.liveContextOn(t, "bare", "alice") // no platform: assumed out of reach, as the revocation assumes
  	f.load(t, strings.Replace(f.policyText, `permit: ["**"]`, `permit: ["show **"]`, 1))
  	if _, err := f.b.Refresh(context.Background(), nil); err != nil {
  		t.Fatal(err)
  	}
  	for _, rec := range recordsOf(t, f, "refresh") {
  		s := rec["session"].(map[string]any)
  		if (rec["device"].(map[string]any)["name"] == "bare") != (s["unreached"] == true) {
  			t.Fatalf("unreached on the wrong record: %v", rec)
  		}
  	}
  }
  ```

  (The fixture, `load`, `context`, `liveContextOn`, `lastRecord` and `recordsOf` stand for
  `refresh_test.go`'s existing helpers; where one is missing, add it beside the others, as small as
  it can be.)

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/broker/ -run 'Shortens|Unreached' -count=1`
  Expected: FAIL.

- [ ] **Step 3: The record.** In `log.go`'s `Session`, add:

  ```go
  	// AuthTime and SessionExpires are on a refresh record that moved them:
  	// a session refresh's new authentication and ceiling, or a policy
  	// refresh's shortened ceiling (spec §5.6, §5.7). Rendered as ts is.
  	AuthTime       string `json:"auth_time,omitempty"`
  	SessionExpires string `json:"session_expires,omitempty"`
  	// Unreached is a refresh record's context on a platform that never asks
  	// about a command, or on a device the inventory gives no platform: the
  	// live session keeps what it had (spec §13, decision 21).
  	Unreached bool `json:"unreached,omitempty"`
  ```

- [ ] **Step 4: The refresh.** In `decideRefresh`, after `clamp` is computed:

  ```go
  	age := res.SessionAge.Of(b.MaxSessionAge)
  	shortens := age > 0 && !c.AuthTime.IsZero() &&
  		(c.SessionExpires.IsZero() || c.AuthTime.Add(age).Before(c.SessionExpires))
  ```

  add `&& !shortens` to the `unchanged` condition, set `rec.Session.SessionExpires =
  decision.FormatTime(c.AuthTime.Add(age))` when `shortens`, and pass `MaxSessionAge: age` in the
  `store.ContextPolicy` it returns. Return `age` on the step too (`refreshStep.age`), for Task 7.

  In `refreshContext`:
  - **`Unreached`.** Right after `step.sessionOnly = …`, set `Unreached` only where a record exists:

    ```go
    	if step.rec.Session != nil { // an unchanged step carries no record (pre-flight I13)
    		step.rec.Session.Unreached = step.sessionOnly
    	}
    ```

    In the unreadable-context branch, set the record's `Session.Unreached` from the same
    `sessionOnly(known, plat)`.
  - **The `sameSource` shortcut.** Add `&& !shortens` to its condition (`step.shortens`, set by
    `decideRefresh`), so an inventory-only swap that changed which roles compose on a device still
    writes a shortened ceiling (pre-flight M19).
  - **The outcome.** Change the signature to return the step's outcome beside the error,
    `(outcome string, err error)`: `"updated"`, `"unchanged"`, `"revoked"`, `"quarantined"`,
    `"failed"`, or `"skipped"` for a context it leaves without judging (gone, another principal's,
    no blob, already revoked). Task 7 reads it (pre-flight I4), and `refreshContexts` ignores it.

- [ ] **Step 5: Run them.** `go test ./internal/broker/ ./internal/decision/ -count=1 -race` → PASS.
  Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 6: Commit.**

  ```bash
  git add internal/broker internal/decision
  git commit -m "feat(broker): the policy refresh shortens live ceilings and names unreached contexts

  A role's shortened max_session_age reaches every live context at the next refresh; a
  lengthened one waits for a fresh authentication. Refresh records carry session_expires when
  it moved, and unreached for a context on a session-only platform (decision 21).

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 6: The daemon warns before the ceiling, keeps a context through the grace window, and deletes it after

**Files:**
- Create: `internal/platform/warning.go`
- Modify: `internal/daemon/author/author.go` (`Handler.ceilingWarning`, `WithCeilingWarning`; the
  ceiling branch; the permit's `server_msg`; the blob bump beside `TouchContext`)
- Modify: `internal/daemon/author/lab.go` (`Lab.DenyMessageLength`)
- Modify: `internal/config/config.go` (`session.ceiling_warning`, `lab.deny_message_length`)
- Modify: `internal/daemon/metrics/metrics.go` (`CeilingWarnings`)
- Modify: `cmd/port49d/main.go` (`WithCeilingWarning`; the lab field)
- Test: `internal/daemon/author/author_test.go`, `internal/config/config_test.go`,
  `internal/platform/warning_test.go`

**Interfaces:**
- Produces:
  - `func platform.CeilingWarning(name string) bool`: an allow-list, empty until L34's notes name
    the platforms that show the warning and still permit (Task 13; pre-flight M10).
  - `config.SessionConfig.CeilingWarningPlatforms []string` (`session.ceiling_warning_platforms`):
    platforms an operator adds to the allow-list, unmeasured. The lab sets all five to measure them.
  - `config.LabConfig.DenySession bool` (`lab.deny_session`): the lab instrument fails the session
    authorization itself with its (padded) deny message, so L2's truncation is measurable on Junos,
    which never authorizes a command (pre-flight I12).
  - `func (h *Handler) WithCeilingWarning(d time.Duration) *Handler`
  - `config.SessionConfig.CeilingWarning time.Duration` (`session.ceiling_warning`, default 30m,
    `0s` off, at most 24h); `config.LabConfig.DenyMessageLength int` (`lab.deny_message_length`, 0
    or 16–4096)
  - metric `port49_ceiling_warnings_total` (no labels): permits that carried the warning.
  - The texts:
    - the warning, `port49: session ends in <n>m - run 'port49 refresh'`, with n rounded up and at
      least 1;
    - inside the grace window, `port49: session expired - run 'port49 refresh' within <n>m to
      resume`;
    - past it, `port49: session ended - get a new token ('port49 token') and log in again`.

- [ ] **Step 1: The tests.** In `author_test.go` (its fixture writes a context and authorizes against
  it; use its helpers):

  ```go
  // Inside ceiling_warning, a permitted reply carries the warning in
  // server_msg, and the record says so; outside it, nothing (spec §5.6;
  // decision 33, provisional on L34).
  func TestAPermitNearTheCeilingWarns(t *testing.T) {
  	for _, tc := range []struct {
  		left time.Duration
  		want string
  	}{{29*time.Minute + time.Second, "port49: session ends in 30m - run 'port49 refresh'"}, {31 * time.Minute, ""},
  		{10 * time.Second, "port49: session ends in 1m - run 'port49 refresh'"}} {
  		h, ctxStore, now := newAuthorFixture(t) // its context is on arista_eos
  		h.WithCeilingWarning(30*time.Minute, []string{"arista_eos"})
  		putContext(t, ctxStore, now.Add(-time.Hour), now.Add(tc.left)) // auth_time, session_expires
  		resp, rec := authorizeCommand(t, h, "show version")
  		if resp.Status != wire.AuthorStatusPassAdd || string(resp.ServerMsg) != tc.want || rec["server_msg"] != nilIfEmpty(tc.want) {
  			t.Errorf("%s left: %v %q %v", tc.left, resp.Status, resp.ServerMsg, rec["server_msg"])
  		}
  	}
  }

  // Past the ceiling and inside the grace window: denied, the context kept,
  // the message naming port49 refresh. Past the window: denied, the context
  // deleted (teardown row 3).
  func TestTheGraceWindowKeepsThenDeletes(t *testing.T) {
  	h, ctxStore, now := newAuthorFixture(t) // grace window 10m
  	putContext(t, ctxStore, now.Add(-2*time.Hour), now.Add(-5*time.Minute))
  	resp, _ := authorizeCommand(t, h, "show version")
  	if resp.Status != wire.AuthorStatusFail || !strings.Contains(string(resp.ServerMsg), "within 5m to resume") ||
  		!strings.Contains(string(resp.ServerMsg), "port49 login") {
  		t.Fatalf("inside the window: %v %q", resp.Status, resp.ServerMsg)
  	}
  	if _, err := ctxStore.GetContext(context.Background(), aliceKey); err != nil {
  		t.Fatal("the context was not kept inside the window")
  	}
  	putContext(t, ctxStore, now.Add(-2*time.Hour), now.Add(-11*time.Minute))
  	resp, rec := authorizeCommand(t, h, "show version")
  	if resp.Status != wire.AuthorStatusFail || !strings.Contains(string(resp.ServerMsg), "log in again") ||
  		rec["reason"] != "session_expired" {
  		t.Fatalf("past the window: %v %q %v", resp.Status, resp.ServerMsg, rec)
  	}
  	if _, err := ctxStore.GetContext(context.Background(), aliceKey); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("the context outlived its grace window: %v", err)
  	}
  }

  // A permit that extends a context's idle TTL bumps its blob too, so a
  // `never` session's blob outlives the TTL it was minted with (decision 19).
  func TestATouchBumpsTheBlob(t *testing.T) {
  	h, ctxStore, now := newAuthorFixture(t)
  	putContextTouched(t, ctxStore, now.Add(-13*time.Hour)) // LastTouchedAt older than half the idle TTL
  	authorizeCommand(t, h, "show version")
  	if !blobExpiresAfter(t, ctxStore, now.Add(11*time.Hour)) {
  		t.Fatal("the blob was not bumped with the context")
  	}
  }

  // A platform neither L34 nor the operator lists gets no server_msg on a
  // permit, however close the ceiling (pre-flight M10).
  func TestAnUnlistedPlatformGetsNoWarning(t *testing.T) {
  	h, ctxStore, now := newAuthorFixture(t)
  	h.WithCeilingWarning(30*time.Minute, nil)
  	putContext(t, ctxStore, now.Add(-time.Hour), now.Add(time.Minute))
  	if resp, _ := authorizeCommand(t, h, "show version"); len(resp.ServerMsg) != 0 {
  		t.Fatalf("%q", resp.ServerMsg)
  	}
  }

  // With lab.deny_session the lab instrument fails the session authorization
  // with its padded message: L2's truncation on a platform that never
  // authorizes a command (pre-flight I12).
  func TestTheLabCanDenyTheSession(t *testing.T) {
  	lab := &Lab{DenySession: true, DenyMessageLength: 64}
  	d := lab.Session(context.Background(), Request{})
  	if d.Permit || len(d.ServerMsg) != 64 {
  		t.Fatalf("%+v", d)
  	}
  }

  // The lab's deny message is padded to deny_message_length with a counting
  // pattern, so the device's cut is readable (L2's truncation length).
  func TestTheLabDenyMessageIsPadded(t *testing.T) {
  	msg := padLabMessage("port49: denied by lab_deny (show clock)", 64)
  	if len(msg) != 64 || !strings.HasPrefix(msg, "port49: denied by lab_deny (show clock) ") ||
  		strings.IndexFunc(msg, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
  		t.Fatalf("%q (%d)", msg, len(msg))
  	}
  }
  ```

  (`newAuthorFixture`, `putContext`, `putContextTouched`, `authorizeCommand`, `blobExpiresAfter`,
  `aliceKey` and `nilIfEmpty` stand for `author_test.go`'s helpers or small new ones beside them:
  the fixture builds a `Handler` over a memory store with a policy authorizer that permits `show **`
  and a blob in the store.) In `config_test.go`: `session.ceiling_warning` defaults to 30m, `0s` is
  off, `25h` is refused naming the key; `lab.deny_message_length: 8` and `5000` are refused.

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/daemon/author/ ./internal/config/ ./internal/platform/ -count=1`
  Expected: FAIL to compile.

- [ ] **Step 3: The platform table.** Create `internal/platform/warning.go`:

  ```go
  package platform

  // ceilingWarningOn names the platforms sent the session ceiling warning in
  // a permit's server_msg (spec §5.6; decision 33): those spec §15 L34 found
  // show it and still treat the reply as a permit, each entry citing its
  // note. It is empty until L34 is measured (plan 7b, Task 13); an operator
  // adds an unmeasured platform with session.ceiling_warning_platforms. A table
  // in code, not in a platform set: a released set is never edited.
  var ceilingWarningOn = map[string]bool{}

  // CeilingWarning reports whether name's permits carry the warning, given
  // the platforms the operator added.
  func CeilingWarning(name string, added []string) bool {
  	return ceilingWarningOn[name] || slices.Contains(added, name)
  }
  ```

  with a test that it is false for `arista_eos` alone and true when added.

- [ ] **Step 4: The authorizer.** In `author.go`: add `ceilingWarning time.Duration` and `warnPlatforms []string` to `Handler`
  (comment: "how long before session_expires a permit's reply carries the warning in server_msg;
  zero is none (spec §5.6; decision 33)"), and

  ```go
  // WithCeilingWarning sets session.ceiling_warning and the platforms the
  // operator added to the warning's allow-list.
  func (h *Handler) WithCeilingWarning(d time.Duration, added []string) *Handler {
  	h.ceilingWarning, h.warnPlatforms = d, added
  	return h
  }
  ```

  Replace the ceiling branch with:

  ```go
  	if !c.SessionExpires.IsZero() && now.After(c.SessionExpires) {
  		// Denial at the ceiling is FAIL, not ERROR. Inside the grace window
  		// the context is kept, so `port49 refresh` resumes it; past the window
  		// it is deleted (teardown row 3), and only a new login answers.
  		left := c.SessionExpires.Add(h.graceWindow).Sub(now)
  		if left > 0 {
  			return h.deny(rec, decision.SessionExpired, fmt.Sprintf(
  				"port49: session expired - run 'port49 refresh' (or 'port49 login') within %dm to resume", ceilMinutes(left)))
  		}
  		// Bound to the revision read: a login that replaced this context
  		// since is not deleted (pre-flight M4).
  		err := h.store.DeleteContextIf(ctx, store.ContextKey{NAS: peer.NAS, Username: user}, c.Rev)
  		h.metrics.StoreOps.WithLabelValues("delete_context", storeOutcome(err)).Inc()
  		return h.deny(rec, decision.SessionExpired,
  			"port49: session ended - get a new token ('port49 token') and log in again")
  	}
  ```

  On the permit path, before `h.emit(rec)`:

  ```go
  	// The warning rides on a permit within ceiling_warning of the ceiling
  	// (spec §5.6; decision 33). Whether the device shows it is L34's; the
  	// record says it was sent.
  	var warning string
  	if h.ceilingWarning > 0 && c.HasCeiling() && platform.CeilingWarning(peer.Platform, h.warnPlatforms) {
  		if left := c.SessionExpires.Sub(now); left <= h.ceilingWarning {
  			warning = fmt.Sprintf("port49: session ends in %dm - run 'port49 refresh'", ceilMinutes(left))
  			rec.ServerMsg = warning
  			h.metrics.CeilingWarnings.Inc()
  		}
  	}
  ```

  and set `resp.ServerMsg = []byte(warning)` on the PASS_ADD response when it is non-empty. Beside
  the `TouchContext` call, inside the same `if`:

  ```go
  		// The context's blob lives as long as the context (decision 19): a
  		// session with no ceiling outlives the TTL it was minted with.
  		if c.BlobHash != "" {
  			err := h.store.BumpBlob(ctx, c.BlobHash, h.contextIdleTTL)
  			h.metrics.StoreOps.WithLabelValues("bump_blob", storeOutcome(err)).Inc()
  		}
  ```

  and add:

  ```go
  // ceilMinutes is d in whole minutes, rounded up, at least one: an operator
  // told "0m" reads it as already over.
  func ceilMinutes(d time.Duration) int {
  	return max(1, int((d+time.Minute-1)/time.Minute))
  }
  ```

  Update `graceWindow`'s field comment: the authorizer now reads it.

- [ ] **Step 5: The lab's padded message.** In `lab.go`:
  - add `DenyMessageLength int` to `Lab` (comment: "pads the lab's deny server_msg to this many bytes
    with a counting pattern, for L2's truncation length; zero leaves it"), and apply it where the lab
    builds its deny message;
  - add `DenySession bool` (comment: "fails every session authorization with the deny message: L2 on
    Junos, which never authorizes a command, plan 7b"), which makes `Session` return a denial
    carrying the padded message;
  - add:

  ```go
  // padLabMessage pads msg with a space and then "0123456789" repeated, to
  // exactly n bytes, so the last digit a device prints says where it cut.
  func padLabMessage(msg string, n int) string {
  	if n <= len(msg)+1 {
  		return msg
  	}
  	var b strings.Builder
  	b.WriteString(msg + " ")
  	for i := 0; b.Len() < n; i++ {
  		b.WriteByte('0' + byte(i%10))
  	}
  	return b.String()
  }
  ```

- [ ] **Step 6: The config.** In `SessionConfig`, add:

  ```go
  	// CeilingWarning is how long before session_expires a permitted reply
  	// carries the warning in server_msg (spec §5.6; decision 33). Default
  	// 30m, long enough to finish a change; 0s turns it off; at most 24h.
  	CeilingWarning time.Duration `yaml:"ceiling_warning"`
  ```

  read through a `*time.Duration` in the YAML struct so an explicit `0s` is told from absent (as
  `limitsYAML` does for its windows), defaulting to 30m and refusing above 24h or below zero, naming
  `session.ceiling_warning`.

  Also:
  - **`CeilingWarningPlatforms`.** Add it, `[]string`, `yaml:"ceiling_warning_platforms"`, each entry
    a platform-name shape, unchecked against the set: an operator may name a variant.
  - **`LabConfig`.** Add `DenyMessageLength int `yaml:"deny_message_length"`` (refusing a value other
    than 0 or 16–4096) and `DenySession bool `yaml:"deny_session"``.
  - **`GraceWindow`'s comment.** Its "nothing reads it today" becomes "the authorizer denies through
    it and then deletes the context (plan 7b); the broker's refresh resumes inside it" (pre-flight
    M20). Add the metric (`port49_ceiling_warnings_total`, "Permitted
  authorization replies that carried the session ceiling warning.") and touch it in
  `metrics_test.go`.

- [ ] **Step 7: port49d.** In `main.go`, chain `.WithCeilingWarning(cfg.Session.CeilingWarning,
  cfg.Session.CeilingWarningPlatforms)` onto `author.New(...)`, and pass `DenyMessageLength:
  cfg.Lab.DenyMessageLength, DenySession: cfg.Lab.DenySession` into the `author.Lab` literal.

- [ ] **Step 8: Run them.** `go test ./internal/daemon/... ./internal/config/ ./internal/platform/ ./cmd/port49d/ -count=1 -race`
  → PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 9: Commit.**

  ```bash
  git add internal/platform/warning.go internal/platform/warning_test.go internal/daemon internal/config cmd/port49d
  git commit -m "feat(daemon): warn before the ceiling, keep the context through grace, delete it after

  A permit within session.ceiling_warning (30m) carries the warning in server_msg, on the
  platforms L34 finds show it (an allow-list, empty until then) or the operator lists. Past
  the ceiling a context is kept through the grace window and named in the denial; past it the
  context is deleted by compare-and-set. A touch bumps the context's blob.
  lab.deny_message_length and lab.deny_session serve L2.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 7: `/v1/refresh`: a signed nonce over the held connection extends every live session the policy has just judged and kept

**Files:**
- Create: `internal/broker/api/refresh.go` (the message, the exporter label, the algorithm, the
  signer, the wire types)
- Create: `internal/broker/sessionrefresh.go` (the two handlers, `RefreshSession`)
- Modify: `internal/broker/broker.go`:
  - `heldConn` gains a lock, the nonce, a movable `at` and the last refresh;
  - `Handler`'s routes;
  - `Broker.ContextIdleTTL`, `Broker.GraceWindow`;
  - a `refresh` variant of 7a's revoked refusal.
- Modify: `internal/daemon/metrics/metrics.go` (`SessionRefreshes`)
- Modify: `cmd/port49d/main.go` (the broker's new fields)
- Test: `internal/broker/api/refresh_test.go`, `internal/broker/sessionrefresh_test.go`,
  `internal/broker/fixture_test.go` (`liveContextAt`, `postOn`, `loadPolicy`)

**Interfaces:**
- Consumes:
  - 7a's `Identity`, `revocation`, `revokedError`, `emit`;
  - 4b's `refreshContext`, which Task 5 made return its outcome;
  - Task 4's `SessionAge`, `GraceCutoff`, `ExpectRev`, `ErrPastGrace` and `DeleteContextIf`;
  - Task 5's `decision.Session` fields.
- Produces:
  - **The message.**
    - `api.RefreshExporterLabel = "EXPORTER-port49-refresh"`, `api.RefreshNonceLen = 32`
    - `func api.RefreshMessage(nonce, ekm []byte) []byte`, which is `"port49 session refresh v1\x00" ‖
      nonce ‖ ekm`
    - `func api.RefreshAlgorithm(pub crypto.PublicKey) (x509.SignatureAlgorithm, bool)`
    - `func api.SignRefresh(signer crypto.Signer, msg []byte) ([]byte, error)`
  - **The wire types** (JSON names in parentheses; the nonce and signature are base64url without
    padding):
    - `type api.RefreshChallenge struct { Nonce, ExpiresAt string }` (`nonce`, `expires_at`)
    - `type api.RefreshRequest struct { Nonce, Signature string }` (`nonce`, `signature`)
    - `type api.RefreshResponse struct { AuthTime, SessionEndsAt string; Sessions []api.RefreshedSession }`
      (`auth_time`, `session_ends_at`, `sessions`)
    - `type api.RefreshedSession struct { Device, Username, Outcome, SessionExpires string; Unreached bool }`
      (`device`, `username`, `outcome`, `session_expires`, `unreached`); `Outcome` is one of
      `extended`, `revoked`, `past_grace`, `not_judged`.
  - **The broker.**
    - `func (b *Broker) RefreshSession(ctx context.Context, principal string, cred store.Credential, at time.Time) (SessionRefreshReport, error)`
    - `type SessionRefreshReport struct { At time.Time; Sessions []RefreshedContext }`, with
      `RefreshedContext{Ref store.ContextRef; Outcome string; SessionExpires time.Time; Unreached bool}`
  - **The metric.** `port49_session_refreshes_total{outcome}`, with `outcome` one of `extended`,
    `revoked`, `past_grace`, `not_judged` (counted per context), and `refused`, `store_error`,
    `too_soon` (counted per refresh) (pre-flight M22).
  - **The answers.**
    - A refusal is `401 trust_domain_unresolved` or `401 credential_revoked` (§5.7).
    - The API's own codes: `refresh_challenge_missing` (401, no live challenge on this connection,
      which the agent retries once), `refresh_too_soon` (429, `Retry-After`), `503 store_unavailable`
      with fixed text, and `400 bad_request` on no held connection.
    - Certificate status adds its 503 in Task 10.

- [ ] **Step 1: The message's tests.** Create `internal/broker/api/refresh_test.go`:
  - for an ECDSA P-256, an RSA 2048 and an Ed25519 key, `SignRefresh` followed by
    `x509.Certificate.CheckSignature(alg, msg, sig)` (with `RefreshAlgorithm`'s `alg`) verifies, and a
    one-byte change to the message does not;
  - `RefreshMessage` is the context string, the nonce and the exporter value concatenated, 26 + 32 +
    32 bytes;
  - `RefreshAlgorithm` of an unknown key type is false.

  Build each certificate with `x509.CreateCertificate`, self-signed: `testpki` issues ECDSA only.

- [ ] **Step 2: The fixture's helpers** (pre-flight I11). In `fixture_test.go`, add:

  ```go
  // liveContextAt writes a live context for principal on device under
  // username, authenticated at auth with the given ceiling (zero: none), as a
  // redemption of a token the policy in force minted would: its blob is that
  // policy's compiled blob for principal on device, written through putBlob;
  // its store TTL is a day, so a test may advance the clock by hours; it is
  // indexed by principal and by certificate.
  func (f *fixture) liveContextAt(t *testing.T, device, username, principal, certKey string, auth, expires time.Time) {
  	t.Helper()
  	ctx := context.Background()
  	pol := f.b.Policy.Load()
  	dev, ok := pol.Device(device)
  	if !ok {
  		t.Fatalf("no device %s", device)
  	}
  	var hash string
  	if res, err := pol.Resolve(principal, dev, f.b.Now()); err == nil {
  		body, h, err := engine.Encode(res.Blob)
  		if err != nil {
  			t.Fatal(err)
  		}
  		if err := f.b.putBlob(ctx, h, body, 24*time.Hour); err != nil {
  			t.Fatal(err)
  		}
  		hash = h
  	} else {
  		hash = "sha256:" + strings.Repeat("0", 64) // a device with no platform: no blob compiles
  	}
  	k := store.ContextKey{NAS: device, Username: username}
  	if err := f.st.PutContext(ctx, k, store.Context{CtxID: "ctx_" + device, Principal: principal, Username: username,
  		PrivLvl: 1, BlobHash: hash, AuthTime: auth, SessionExpires: expires, RefreshedAt: auth,
  		LastTouchedAt: auth}, 24*time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if err := f.st.IndexContext(ctx, principal, "", certKey, store.ContextRef{NAS: device, Username: username},
  		24*time.Hour); err != nil {
  		t.Fatal(err)
  	}
  }
  ```

  Also add `postOn(t, c, br, path, body) struct{ status int; body string }`, which writes one request
  on a held connection and reads its whole response, and `loadPolicy(t, text)`, which swaps
  `f.b.Policy` to a policy loaded from `text` over `f.devices`. Each sits beside its neighbours.

- [ ] **Step 3: The handlers' tests.** Create `internal/broker/sessionrefresh_test.go`. Each case
  signs correctly, so that the property under test is the only defect (pre-flight I10).

  ```go
  // challengeOn asks for a challenge on c and returns its nonce bytes and
  // its text.
  func challengeOn(t *testing.T, c *tls.Conn, br *bufio.Reader) ([]byte, string) {
  	t.Helper()
  	r := postOn(t, c, br, "/v1/refresh/challenge", "")
  	var ch api.RefreshChallenge
  	if err := json.Unmarshal([]byte(r.body), &ch); err != nil || r.status != 200 {
  		t.Fatalf("challenge: %d %s", r.status, r.body)
  	}
  	nonce, _ := base64.RawURLEncoding.DecodeString(ch.Nonce)
  	return nonce, ch.Nonce
  }

  // answer signs nonce with cert's key over over's exporter value, and sends
  // it on c.
  func answer(t *testing.T, c *tls.Conn, br *bufio.Reader, over *tls.Conn, cert tls.Certificate, nonce []byte,
  	nonceText string) (int, string) {
  	t.Helper()
  	cs := over.ConnectionState()
  	ekm, err := cs.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
  	if err != nil {
  		t.Fatal(err)
  	}
  	sig, err := api.SignRefresh(cert.PrivateKey.(crypto.Signer), api.RefreshMessage(nonce, ekm))
  	if err != nil {
  		t.Fatal(err)
  	}
  	body, _ := json.Marshal(api.RefreshRequest{Nonce: nonceText, Signature: base64.RawURLEncoding.EncodeToString(sig)})
  	r := postOn(t, c, br, "/v1/refresh", string(body))
  	return r.status, r.body
  }

  // refreshOn is a correct refresh on c.
  func refreshOn(t *testing.T, c *tls.Conn, br *bufio.Reader, cert tls.Certificate) (int, api.RefreshResponse) {
  	t.Helper()
  	nonce, text := challengeOn(t, c, br)
  	status, body := answer(t, c, br, c, cert, nonce, text)
  	var resp api.RefreshResponse
  	_ = json.Unmarshal([]byte(body), &resp)
  	return status, resp
  }

  // A refresh extends a live context the policy in force grants, from the
  // broker's verification time, to the ceiling that policy gives (here the
  // default, 12h, where the context had 8h); the connection's session clock
  // moves with it, so a mint past the handshake's ceiling goes through (spec
  // §5.6; decision 33; pre-flight I5).
  func TestARefreshExtendsToThePolicysCeiling(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	auth := f.now
  	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(8*time.Hour))
  	f.advance(7*time.Hour + 50*time.Minute)
  	status, resp := refreshOn(t, c, br, f.alice)
  	if status != 200 || len(resp.Sessions) != 1 || resp.Sessions[0].Outcome != "extended" {
  		t.Fatalf("%d %+v", status, resp)
  	}
  	got, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
  	if !got.AuthTime.Equal(f.b.Now()) || !got.SessionExpires.Equal(f.b.Now().Add(f.b.MaxSessionAge)) {
  		t.Fatalf("auth_time %v, session_expires %v", got.AuthTime, got.SessionExpires)
  	}
  	recs := eventsOf(f.records(t), "refresh")
  	if last := recs[len(recs)-1]; last["verdict"] != "permit" || last["reason"] != "grants_matched" ||
  		last["session"].(map[string]any)["auth_time"] == nil {
  		t.Fatalf("the refresh record: %v", last)
  	}
  	f.advance(4*time.Hour + 20*time.Minute)
  	if r := postOn(t, c, br, "/v1/tokens", `{"devices":["leaf1"]}`); r.status != 200 {
  		t.Fatalf("a mint after the refresh, past the handshake's ceiling: %d %s", r.status, r.body)
  	}
  }

  // What the policy did not just judge and keep is not extended: a context
  // past its grace window is deleted and named; one on a quarantined device,
  // and one whose policy write lost every race, are not judged; a withdrawn
  // grant is revoked; one on a device with no platform is extended and named
  // unreached (pre-flight I4).
  func TestARefreshExtendsOnlyWhatThePolicyKept(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	auth := f.now
  	f.b.GraceWindow = 10 * time.Minute
  	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(time.Hour))   // inside grace
  	f.liveContextAt(t, "nx1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(30*time.Minute)) // past grace
  	f.liveContextAt(t, "bare", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(8*time.Hour))   // unreached
  	f.advance(time.Hour + 5*time.Minute)
  	status, resp := refreshOn(t, c, br, f.alice)
  	by := map[string]api.RefreshedSession{}
  	for _, s := range resp.Sessions {
  		by[s.Device] = s
  	}
  	if status != 200 || by["leaf1"].Outcome != "extended" || by["nx1"].Outcome != "past_grace" ||
  		by["bare"].Outcome != "extended" || !by["bare"].Unreached {
  		t.Fatalf("%d %+v", status, resp)
  	}
  	if _, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "nx1", Username: "alice"}); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("a context past its grace window was kept: %v", err)
  	}
  	// A store whose policy writes always conflict: refreshContext gives up,
  	// and the context is not judged, so not extended.
  	f.advance(11 * time.Second)
  	f.loadPolicy(t, strings.Replace(testPolicy, `permit: ["**"]`, `permit: ["show **"]`, 1)) // leaf1's answer changes
  	f.b.Store = conflictingPolicyStore{f.st}
  	status, resp = refreshOn(t, c, br, f.alice)
  	for _, s := range resp.Sessions {
  		if s.Device == "leaf1" && s.Outcome != "not_judged" {
  			t.Fatalf("a context whose policy write lost every race was %s", s.Outcome)
  		}
  	}
  	// The grant withdrawn: revoked, never extended.
  	f.b.Store = f.st
  	f.advance(11 * time.Second)
  	f.loadPolicy(t, strings.Replace(testPolicy, "grants:\n  - {subject: netops", "grants:\n  - {subject: idle", 1))
  	status, resp = refreshOn(t, c, br, f.alice)
  	for _, s := range resp.Sessions {
  		if s.Outcome == "extended" {
  			t.Fatalf("after the grant was withdrawn, %s was extended", s.Device)
  		}
  	}
  }

  // conflictingPolicyStore refuses every SetContextPolicy with ErrConflict.
  type conflictingPolicyStore struct{ store.Store }

  func (conflictingPolicyStore) SetContextPolicy(context.Context, store.ContextKey, uint64, store.ContextPolicy) error {
  	return store.ErrConflict
  }

  // The nonce is bound to its connection and to its key, single use, and
  // good for 60s; each refusal is a refresh deny record with neither the
  // nonce nor the signature in the log (pre-flight I10).
  func TestARefreshIsBoundToItsConnectionAndItsKey(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	other, obr := held(t, f, addr, f.alice)

  	// Signed over another connection's exporter value: refused; over its
  	// own: accepted.
  	nonce, text := challengeOn(t, other, obr)
  	if s, _ := answer(t, other, obr, c, f.alice, nonce, text); s != 401 {
  		t.Fatalf("other's nonce signed over c's exporter, sent on other: %d", s)
  	}
  	f.advance(11 * time.Second)
  	nonce, text = challengeOn(t, other, obr)
  	if s, body := answer(t, other, obr, other, f.alice, nonce, text); s != 200 {
  		t.Fatalf("the same answer over other's own exporter: %d %s", s, body)
  	}

  	// Replay: a correct answer sent twice; the second is refused.
  	f.advance(11 * time.Second)
  	nonce, text = challengeOn(t, c, br)
  	if s, _ := answer(t, c, br, c, f.alice, nonce, text); s != 200 {
  		t.Fatalf("the first answer: %d", s)
  	}
  	f.advance(11 * time.Second)
  	if s, body := answer(t, c, br, c, f.alice, nonce, text); s != 401 || !strings.Contains(body, "refresh_challenge_missing") {
  		t.Fatalf("a replayed answer: %d %s", s, body)
  	}

  	// 59s: accepted; 61s: refused.
  	nonce, text = challengeOn(t, c, br)
  	f.advance(59 * time.Second)
  	if s, _ := answer(t, c, br, c, f.alice, nonce, text); s != 200 {
  		t.Fatalf("an answer at 59s: %d", s)
  	}
  	nonce, text = challengeOn(t, c, br)
  	f.advance(61 * time.Second)
  	if s, _ := answer(t, c, br, c, f.alice, nonce, text); s != 401 {
  		t.Fatalf("an answer at 61s: %d", s)
  	}

  	// Another key, the same principal: refused.
  	nonce, text = challengeOn(t, c, br)
  	renewed := f.client(t, "alice@example.com", f.now.Add(time.Hour))
  	if s, _ := answer(t, c, br, c, renewed, nonce, text); s != 401 {
  		t.Fatalf("a signature by another key: %d", s)
  	}
  	if strings.Contains(f.log.String(), text) {
  		t.Fatal("a nonce reached the log")
  	}
  	for _, r := range eventsOf(f.records(t), "refresh") {
  		raw, _ := json.Marshal(r)
  		if strings.Contains(string(raw), "signature") {
  			t.Fatalf("a refresh record carries a signature: %s", raw)
  		}
  	}
  }

  // A connection refreshes once per 10s (pre-flight M17).
  func TestARefreshIsRateLimited(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	if s, _ := refreshOn(t, c, br, f.alice); s != 200 {
  		t.Fatal(s)
  	}
  	if r := postOn(t, c, br, "/v1/refresh/challenge", ""); r.status != 429 || !strings.Contains(r.body, "refresh_too_soon") {
  		t.Fatalf("a second refresh inside 10s: %d %s", r.status, r.body)
  	}
  }

  // A revoked principal cannot refresh: credential_revoked, recorded as a
  // refresh, nothing extended (pre-flight M2).
  func TestARevokedCallerCannotRefresh(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	f.revoke(t, store.RevocationPrincipal, alicePrincipal)
  	nonce, text := challengeOn(t, c, br)
  	if s, body := answer(t, c, br, c, f.alice, nonce, text); s != 401 || !strings.Contains(body, "credential_revoked") {
  		t.Fatalf("%d %s", s, body)
  	}
  	recs := eventsOf(f.records(t), "refresh")
  	if last := recs[len(recs)-1]; last["reason"] != "credential_revoked" {
  		t.Fatalf("%v", last)
  	}
  }
  ```

  (`held`, `serveThrough`, `certKey`, `alicePrincipal` and `f.revoke` are 7a's. The listener answers
  a principal marked before the handshake at bind; this test marks after it, so the refresh's own
  check is what refuses.)

- [ ] **Step 4: Run them to see them fail.** `go test ./internal/broker/... -run 'Refresh' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 5: The message.** Create `internal/broker/api/refresh.go`:

  ```go
  package api

  import (
  	"crypto"
  	"crypto/ecdsa"
  	"crypto/ed25519"
  	"crypto/rand"
  	"crypto/rsa"
  	"crypto/sha256"
  	"crypto/x509"
  	"errors"
  )

  // RefreshExporterLabel is the TLS exporter label a refresh signature covers
  // (RFC 8446 §7.5): the exporter value is the connection's own, so a nonce
  // answered on another connection does not verify (spec §5.6; decision 33).
  const RefreshExporterLabel = "EXPORTER-port49-refresh"

  // RefreshNonceLen is the challenge's length in bytes.
  const RefreshNonceLen = 32

  const refreshContext = "port49 session refresh v1\x00"

  // RefreshMessage is what the agent signs and the broker verifies: a fixed
  // context string, so the key's signature means this and nothing else, then
  // the nonce, then the connection's exporter value.
  func RefreshMessage(nonce, ekm []byte) []byte {
  	m := make([]byte, 0, len(refreshContext)+len(nonce)+len(ekm))
  	return append(append(append(m, refreshContext...), nonce...), ekm...)
  }

  // RefreshAlgorithm is the one signature algorithm a key of this type signs
  // a refresh with: ECDSA with SHA-256, RSA-PSS with SHA-256, Ed25519.
  func RefreshAlgorithm(pub crypto.PublicKey) (x509.SignatureAlgorithm, bool) {
  	switch pub.(type) {
  	case *ecdsa.PublicKey:
  		return x509.ECDSAWithSHA256, true
  	case *rsa.PublicKey:
  		return x509.SHA256WithRSAPSS, true
  	case ed25519.PublicKey:
  		return x509.PureEd25519, true
  	}
  	return 0, false
  }

  // SignRefresh signs msg with signer as RefreshAlgorithm says for its key.
  func SignRefresh(signer crypto.Signer, msg []byte) ([]byte, error) {
  	switch signer.Public().(type) {
  	case *ecdsa.PublicKey:
  		sum := sha256.Sum256(msg)
  		return signer.Sign(rand.Reader, sum[:], crypto.SHA256)
  	case *rsa.PublicKey:
  		sum := sha256.Sum256(msg)
  		return signer.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
  	case ed25519.PublicKey:
  		return signer.Sign(rand.Reader, msg, crypto.Hash(0))
  	}
  	return nil, errors.New("api: a refresh is signed by an ECDSA, RSA or Ed25519 key")
  }

  // RefreshChallenge is POST /v1/refresh/challenge's answer.
  type RefreshChallenge struct {
  	Nonce     string `json:"nonce"`
  	ExpiresAt string `json:"expires_at"`
  }

  // RefreshRequest is POST /v1/refresh: the nonce and the signature over
  // RefreshMessage, both base64url without padding.
  type RefreshRequest struct {
  	Nonce     string `json:"nonce"`
  	Signature string `json:"signature"`
  }

  // RefreshedSession is one live context a refresh visited: its outcome
  // (extended, revoked, past_grace, not_judged), its ceiling when extended,
  // and whether the device's own session is out of the extension's reach.
  type RefreshedSession struct {
  	Device         string `json:"device"`
  	Username       string `json:"username"`
  	Outcome        string `json:"outcome"`
  	SessionExpires string `json:"session_expires,omitempty"`
  	Unreached      bool   `json:"unreached,omitempty"`
  }

  // RefreshResponse is POST /v1/refresh's 200.
  type RefreshResponse struct {
  	AuthTime      string             `json:"auth_time"`
  	SessionEndsAt string             `json:"session_ends_at"`
  	Sessions      []RefreshedSession `json:"sessions"`
  }
  ```

- [ ] **Step 6: The held connection.** In `broker.go`, replace `heldConn` with:

  ```go
  // heldConn is one connection's session state (design §7: on the certificate
  // path the agent's session IS the connection). at is when it authenticated:
  // stamped at accept, before the handshake (plan 3, Decided 2), and moved
  // only by a refresh that verified (spec §5.6; decision 33). nonce is the
  // refresh challenge outstanding on it, single use; lastRefresh paces
  // refreshes to one per refreshEvery.
  type heldConn struct {
  	mu          sync.Mutex
  	at          time.Time
  	nonce       []byte
  	nonceExp    time.Time
  	lastRefresh time.Time
  }

  func (h *heldConn) authAt() time.Time {
  	h.mu.Lock()
  	defer h.mu.Unlock()
  	return h.at
  }
  ```

  Then:
  - have `authTime` read `h.authAt()`;
  - add `func heldOf(r *http.Request) *heldConn`, nil without the state;
  - route `POST /v1/refresh/challenge` and `POST /v1/refresh` in `Handler`;
  - add the fields below to `Broker`.

  ```go
  	// ContextIdleTTL is the idle lifetime a refreshed context is extended to,
  	// and GraceWindow how long past its ceiling a refresh may still resume
  	// one (spec §5.6): port49d's context_idle_ttl and session.grace_window.
  	ContextIdleTTL time.Duration
  	GraceWindow    time.Duration
  ```

  Split 7a's `refuseRevoked` so the record's event is a parameter (pre-flight M2):
  - add `func (b *Broker) refuseRevokedAs(w http.ResponseWriter, event string, now time.Time, principal
    string, cred store.Credential, rv store.Revocation)` with its body;
  - `refuseRevoked` becomes `b.refuseRevokedAs(w, decision.EventMint, now, principal, cred, rv)`, so
    the mint path is unchanged;
  - the refresh passes `decision.EventRefresh`.

- [ ] **Step 7: The handlers and `RefreshSession`.** Create `internal/broker/sessionrefresh.go`:

  ```go
  package broker

  // refreshNonceTTL is how long a challenge may be answered; refreshEvery
  // paces one connection's refreshes (pre-flight M17).
  const (
  	refreshNonceTTL = 60 * time.Second
  	refreshEvery    = 10 * time.Second
  )

  // refreshChallenge issues the nonce a refresh signs (spec §5.6; decision
  // 33). It is held on this connection alone; a new one replaces it. A
  // connection that refreshed within refreshEvery is told to wait.
  func (b *Broker) refreshChallenge(w http.ResponseWriter, r *http.Request) {
  	now := b.Now()
  	principal, cred, err := Identity(r.TLS, now)
  	if err != nil {
  		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, string(decision.TrustDomainUnresolved), err.Error())
  		return
  	}
  	h := heldOf(r)
  	if h == nil {
  		writeError(w, http.StatusBadRequest, "bad_request", "a refresh is made on the held connection")
  		return
  	}
  	nonce := make([]byte, api.RefreshNonceLen)
  	if _, err := rand.Read(nonce); err != nil {
  		writeError(w, http.StatusInternalServerError, "broker_error", "no randomness for a challenge")
  		return
  	}
  	h.mu.Lock()
  	wait := h.lastRefresh.Add(refreshEvery).Sub(now)
  	if wait <= 0 {
  		h.nonce, h.nonceExp = nonce, now.Add(refreshNonceTTL)
  	}
  	h.mu.Unlock()
  	if wait > 0 {
  		b.Metrics.SessionRefreshes.WithLabelValues("too_soon").Inc()
  		w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
  		writeError(w, http.StatusTooManyRequests, "refresh_too_soon", "this connection refreshed moments ago; wait and retry")
  		return
  	}
  	writeJSON(w, http.StatusOK, api.RefreshChallenge{Nonce: base64.RawURLEncoding.EncodeToString(nonce),
  		ExpiresAt: now.Add(refreshNonceTTL).UTC().Format(time.RFC3339)})
  }

  // refresh verifies the signed challenge and extends the caller's live
  // sessions (spec §5.6). The nonce is taken whatever the outcome: single use.
  func (b *Broker) refresh(w http.ResponseWriter, r *http.Request) {
  	now := b.Now()
  	principal, cred, err := Identity(r.TLS, now)
  	if err != nil {
  		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, string(decision.TrustDomainUnresolved), err.Error())
  		return
  	}
  	h := heldOf(r)
  	if h == nil {
  		writeError(w, http.StatusBadRequest, "bad_request", "a refresh is made on the held connection")
  		return
  	}
  	var req api.RefreshRequest
  	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
  	dec.DisallowUnknownFields()
  	if err := dec.Decode(&req); err != nil {
  		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a refresh request")
  		return
  	}
  	h.mu.Lock()
  	nonce, exp := h.nonce, h.nonceExp
  	h.nonce = nil
  	h.mu.Unlock()
  	got, _ := base64.RawURLEncoding.DecodeString(req.Nonce)
  	sig, _ := base64.RawURLEncoding.DecodeString(req.Signature)
  	if nonce == nil || !now.Before(exp) || subtle.ConstantTimeCompare(nonce, got) != 1 {
  		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, "refresh_challenge_missing",
  			"no live refresh challenge on this connection; ask for one and answer it within 60s")
  		return
  	}
  	leaf := r.TLS.VerifiedChains[0][0] // Identity verified there is one
  	ekm, err := r.TLS.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
  	alg, ok := api.RefreshAlgorithm(leaf.PublicKey)
  	if err != nil || !ok || leaf.CheckSignature(alg, api.RefreshMessage(nonce, ekm), sig) != nil {
  		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, string(decision.TrustDomainUnresolved),
  			"the refresh challenge was not answered by this connection's key")
  		return
  	}
  	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
  	defer cancel()
  	rv, revoked, err := b.revocation(ctx, principal, cred)
  	switch {
  	case err != nil:
  		b.Metrics.SessionRefreshes.WithLabelValues("store_error").Inc()
  		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
  			"the broker could not read the revocations in force, so it extended nothing; try again")
  		return
  	case revoked:
  		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
  		b.refuseRevokedAs(w, decision.EventRefresh, now, principal, cred, rv)
  		return
  	}
  	// Certificate status (Task 10) is checked here, beside the marks.
  	at := b.Now() // the broker's verification time: the one clock §5.6 gives it
  	h.mu.Lock()
  	h.at, h.lastRefresh = at, at
  	h.mu.Unlock()
  	rep, err := b.RefreshSession(ctx, principal, cred, at)
  	if err != nil {
  		b.Metrics.SessionRefreshes.WithLabelValues("store_error").Inc()
  		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
  			"the broker could not read your live sessions, so it extended nothing; try again") // fixed text (M5)
  		return
  	}
  	writeJSON(w, http.StatusOK, rep.response(b.MaxSessionAge))
  }

  // refuseRefresh answers a refresh that proved nothing, and records it
  // without the nonce or the signature.
  func (b *Broker) refuseRefresh(w http.ResponseWriter, now time.Time, principal string, cred store.Credential,
  	reason decision.Reason, code, detail string) {
  	b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
  	b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: reason,
  		Principal: principal, Auth: &decision.Auth{Method: "cert", Fingerprint: cred.Fingerprint}})
  	writeError(w, http.StatusUnauthorized, code, detail)
  }

  // RefreshedContext is one context a session refresh visited.
  type RefreshedContext struct {
  	Ref            store.ContextRef
  	Outcome        string // extended | revoked | past_grace | not_judged
  	SessionExpires time.Time
  	Unreached      bool
  }

  // SessionRefreshReport is what RefreshSession did.
  type SessionRefreshReport struct {
  	At       time.Time
  	Sessions []RefreshedContext
  }

  // RefreshSession carries a fresh authentication at at into every live
  // context of principal (spec §5.6; decision 33). It holds the policy in
  // force, as a mint does, and first judges each context exactly as a policy
  // refresh would (refreshContext): a withdrawn grant is revoked there. Only
  // a context that judgment kept (unchanged, or updated with its write
  // landed) is extended, through store.RefreshContext bound to the revision
  // just read, to the ceiling the policy gives from at; a context past its
  // grace window is deleted, bound the same way (teardown row 3). Everything
  // else is named, not extended (pre-flight I4).
  func (b *Broker) RefreshSession(ctx context.Context, principal string, cred store.Credential, at time.Time) (SessionRefreshReport, error) {
  	pol, hold := b.Policy.Hold()
  	defer hold()
  	rep := SessionRefreshReport{At: at}
  	refs, err := b.Store.ContextsByPrincipal(ctx, principal)
  	if err != nil {
  		return rep, err
  	}
  	var pass RefreshReport
  	quarantined := map[string]bool{}
  	for _, ref := range refs {
  		k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
  		dev, known := pol.Device(ref.NAS)
  		unreached := !known || dev.Platform == "" || sessionOnly(pol, dev.Platform)
  		visit := RefreshedContext{Ref: ref, Unreached: unreached}
  		outcome, err := b.refreshContext(ctx, pol, nil, at, principal, ref, &pass, quarantined, false)
  		switch {
  		case err != nil && !errors.Is(err, store.ErrConflict):
  			return rep, err
  		case outcome == "revoked":
  			visit.Outcome = "revoked"
  		case err != nil || (outcome != "unchanged" && outcome != "updated"):
  			if outcome == "skipped" && !b.livePrincipalContext(ctx, k, principal) {
  				continue // gone, or another principal's now: not this caller's to report
  			}
  			visit.Outcome = "not_judged"
  		}
  		if visit.Outcome == "" {
  			visit.Outcome, visit.SessionExpires, err = b.extend(ctx, pol, principal, cred, ref, dev, at, unreached)
  			if err != nil {
  				return rep, err
  			}
  			if visit.Outcome == "" {
  				continue
  			}
  		}
  		b.Metrics.SessionRefreshes.WithLabelValues(visit.Outcome).Inc()
  		rep.Sessions = append(rep.Sessions, visit)
  	}
  	return rep, nil
  }

  // extend reads the context the judgment kept and extends it, or deletes
  // it past its grace window, both bound to the revision read. It returns ""
  // for a context gone or no longer the caller's.
  func (b *Broker) extend(ctx context.Context, pol *policy.Policy, principal string, cred store.Credential,
  	ref store.ContextRef, dev admission.Device, at time.Time, unreached bool) (string, time.Time, error) {
  	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
  	c, err := b.Store.GetContext(ctx, k)
  	switch {
  	case errors.Is(err, store.ErrNotFound):
  		return "", time.Time{}, nil
  	case err != nil:
  		return "", time.Time{}, err
  	case c.Principal != principal:
  		return "", time.Time{}, nil
  	case !c.RevokedAt.IsZero():
  		return "revoked", time.Time{}, nil
  	}
  	rec := decision.Record{TS: at, Event: decision.EventRefresh, Principal: principal,
  		Auth:    &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint},
  		Device:  &decision.Device{Name: ref.NAS, Platform: dev.Platform},
  		Session: &decision.Session{CtxID: c.CtxID, Username: c.Username, Unreached: unreached}}
  	if c.HasCeiling() && !at.Before(c.SessionExpires.Add(b.GraceWindow)) {
  		switch err := b.Store.DeleteContextIf(ctx, k, c.Rev); {
  		case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
  			return "not_judged", time.Time{}, nil
  		case err != nil:
  			return "", time.Time{}, err
  		}
  		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.SessionExpired
  		b.emit(rec)
  		return "past_grace", time.Time{}, nil
  	}
  	age := time.Duration(0)
  	if res, err := pol.Resolve(principal, dev, at); err == nil {
  		age = res.SessionAge.Of(b.MaxSessionAge)
  	} else {
  		age = b.MaxSessionAge // a device with no platform: the default, as its mint would have
  	}
  	switch err := b.Store.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: at, RefreshedAt: at,
  		SessionAge: &age, GraceCutoff: at.Add(-b.GraceWindow), ExpectRev: c.Rev}, b.ContextIdleTTL); {
  	case errors.Is(err, store.ErrPastGrace):
  		return "past_grace", time.Time{}, nil
  	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
  		return "not_judged", time.Time{}, nil
  	case err != nil:
  		return "", time.Time{}, err
  	}
  	var expires time.Time
  	if age > 0 {
  		expires = at.Add(age)
  		rec.Session.SessionExpires = decision.FormatTime(expires)
  	}
  	if c.BlobHash != "" {
  		_ = b.Store.BumpBlob(ctx, c.BlobHash, max(b.ContextIdleTTL, age))
  	}
  	rec.Session.AuthTime = decision.FormatTime(at)
  	rec.Verdict, rec.Reason = decision.VerdictPermit, decision.GrantsMatched
  	b.emit(rec)
  	return "extended", expires, nil
  }

  // livePrincipalContext reports whether k still holds a live context of
  // principal: a context refreshContext skipped for no blob is the caller's
  // and is reported not judged; one gone or another's is not reported.
  func (b *Broker) livePrincipalContext(ctx context.Context, k store.ContextKey, principal string) bool {
  	c, err := b.Store.GetContext(ctx, k)
  	return err == nil && c.Principal == principal && c.RevokedAt.IsZero()
  }

  // response is the wire form of rep; the connection's own session now ends
  // connAge after rep.At.
  func (rep SessionRefreshReport) response(connAge time.Duration) api.RefreshResponse {
  	out := api.RefreshResponse{AuthTime: rep.At.UTC().Format(time.RFC3339),
  		SessionEndsAt: rep.At.Add(connAge).UTC().Format(time.RFC3339), Sessions: []api.RefreshedSession{}}
  	for _, v := range rep.Sessions {
  		s := api.RefreshedSession{Device: v.Ref.NAS, Username: v.Ref.Username, Outcome: v.Outcome, Unreached: v.Unreached}
  		if !v.SessionExpires.IsZero() {
  			s.SessionExpires = v.SessionExpires.UTC().Format(time.RFC3339)
  		}
  		out.Sessions = append(out.Sessions, s)
  	}
  	return out
  }
  ```

  (imports as used: `context`, `crypto/rand`, `crypto/subtle`, `encoding/base64`, `encoding/json`,
  `errors`, `io`, `net/http`, `strconv`, `time`, `internal/admission`, `internal/broker/api`,
  `internal/decision`, `internal/policy`, `internal/store`.) `refreshContext` emits its own
  `refresh` record when it writes or revokes, as a policy refresh does; the extension's record follows
  it. A context `refreshContext` left `quarantined` is reported `not_judged`: a quarantined device
  is answered nothing by the daemon, and its context keeps what it had.

- [ ] **Step 8: The metric and port49d.** Add `SessionRefreshes` (`port49_session_refreshes_total`,
  label `outcome`, "Session refreshes: per context extended, revoked, past_grace or not_judged; per
  refresh refused, store_error or too_soon.") to `metrics.go` and its test. In `cmd/port49d/main.go`,
  after `buildBroker`, set:

  ```go
  	brk.ContextIdleTTL, brk.GraceWindow, brk.CeilingWarning = cfg.ContextIdleTTL, cfg.Session.GraceWindow,
  		cfg.Session.CeilingWarning
  ```

- [ ] **Step 9: Run them.** `go test ./internal/broker/... ./internal/daemon/metrics/ ./cmd/port49d/ -count=1 -race`
  → PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 10: Commit.**

  ```bash
  git add internal/broker internal/daemon/metrics cmd/port49d
  git commit -m "feat(broker): /v1/refresh, a signed nonce bound to the held connection

  POST /v1/refresh/challenge issues a single-use 60s nonce, one refresh per connection per 10s;
  POST /v1/refresh verifies the certificate's signature over it and the connection's TLS
  exporter value, checks the marks, moves the connection's auth_time to the verification time,
  and extends only contexts the policy in force has just judged and kept, to the ceiling it
  gives, bound to the revision read. A context past its grace window is deleted.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 8: `port49 refresh`, `port49 login` refreshes, and `port49 token` warns

**Files:**
- Modify: `internal/agent/agent.go` (`Refresh`; the deadline it moves; `ceilingWarning` from
  `/v1/config`; `Status.CeilingWarningSeconds`; `Handler`'s `POST /refresh`)
- Modify: `internal/agent/socket.go` (`Client.Refresh`)
- Create: `cmd/port49/refresh.go`
- Modify: `cmd/port49/main.go` (`run`'s switch; `usage`; `login` refreshes; `tokenCmd` warns;
  `agentMain` re-arms its deadline)
- Modify: `internal/agent/agent.go`'s `sessionOver` and the mint's status handling: a `503` is
  transient and never ends the session (pre-flight I7)
- Test: `internal/agent/agent_test.go`, `cmd/port49/main_test.go`

**Interfaces:**
- Consumes: Task 7's API.
- Produces:
  - `func (a *Agent) Refresh(ctx context.Context) (api.RefreshResponse, error)`: the challenge and the
    refresh on the held connection, signed with the session's key.
    - The API error `refresh_challenge_missing` is retried once with a new challenge. The agent reads
      the code, never the detail text.
    - `credential_revoked` ends the session, as a mint's does.
    - `refresh_too_soon` (429) and a `503` are returned as errors and end nothing.
  - `func (a *Agent) DeadlineChanged() <-chan struct{}`: signalled (non-blocking, buffered 1) when a
    refresh moves the deadline, so `agentMain` re-arms (pre-flight I6).
  - `func (c *Client) Refresh(ctx context.Context) (api.RefreshResponse, error)`
  - `func refreshCmd(args []string, stdout, stderr io.Writer) int`, and `func printRefresh(w io.Writer, r api.RefreshResponse)`
  - `agent.Status.CeilingWarningSeconds int` (`ceiling_warning_seconds`)

- [ ] **Step 1: The agent's tests.** In `agent_test.go`, against a real broker (the file's
  broker-backed fixture, or 7a's pattern of a `Broker` behind a `Listener` in-package where the
  agent tests already stand one up):
  - `Refresh` returns the broker's response, and `SessionEndsAt()` becomes its `session_ends_at`.
  - `Refresh` after the broker answered `credential_revoked` ends the session (`Done()` closed).
  - The connection used for the challenge is the one used for the refresh: the stub (a handler
    that records `r.RemoteAddr` per path) sees one remote address for both.
  - A `401 refresh_challenge_missing` is retried once; a `503 certificate_status_unavailable` at a
    mint, at a refresh and at `Connect` returns an error and leaves `Done()` open (pre-flight I7).
  - A refresh before the deadline signals `DeadlineChanged()`.

- [ ] **Step 2: The CLI's tests.** In `cmd/port49/main_test.go`, beside the `login`/`token` tests
  that stand up a broker and run `run([]string{"login", …})`:
  - `run([]string{"refresh", "--socket", sock})` prints `refreshed at …; this login lasts until …`
    and one line per device (`leaf1 (alice)  extended to …`) for a broker with one live context;
  - an agent refreshed shortly before its original deadline still answers `/status` after that
    deadline (pre-flight I6);
  - with no agent it exits 1 saying `run 'port49 login'`;
  - `port49 login` with an agent already running prints the refresh's line (not "already logged
    in");
  - `port49 token` for a device whose item's `session_expires_at` is within the agent's
    `ceiling_warning_seconds` prints the token on stdout and `port49: your session on leaf1 ends at …
    (in 29m); run 'port49 refresh'` on stderr, under `--json` too, and nothing on stderr when it is
    not;
  - `port49 token` for a device refused `session_expired` prints `port49 token: leaf1: deny
    session_expired: … run 'port49 refresh'` (the item's detail; pre-flight M12).

- [ ] **Step 3: Run them to see them fail.** `go test ./internal/agent/ ./cmd/port49/ -run 'Refresh|Warn' -count=1`
  Expected: FAIL.

- [ ] **Step 4: The agent.** In `agent.go`:

  ```go
  // Refresh re-authenticates the session on the held connection (spec §5.6;
  // decision 33): it asks the broker for a challenge, signs it with the
  // session's key over the connection's TLS exporter value, and sends the
  // signature. It is run by `port49 refresh` and `port49 login` alone, never
  // on the agent's own initiative: the ceiling measures time since a person
  // authenticated. A refusal that names the challenge, a connection dropped
  // between the two requests, is tried once more.
  func (a *Agent) Refresh(ctx context.Context) (api.RefreshResponse, error) {
  	signer, ok := a.cert.PrivateKey.(crypto.Signer)
  	if !ok {
  		return api.RefreshResponse{}, errors.New("agent: the session's key cannot sign a refresh")
  	}
  	for attempt := 1; ; attempt++ {
  		out, retry, err := a.refreshOnce(ctx, signer)
  		if err == nil || !retry || attempt == 2 {
  			return out, err
  		}
  	}
  }

  func (a *Agent) refreshOnce(ctx context.Context, signer crypto.Signer) (api.RefreshResponse, bool, error) {
  	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.broker+"/v1/refresh/challenge", http.NoBody)
  	resp, err := a.do(req)
  	if err != nil {
  		return api.RefreshResponse{}, false, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
  	}
  	var ch api.RefreshChallenge
  	derr := json.NewDecoder(resp.Body).Decode(&ch)
  	drain(resp.Body)
  	if resp.StatusCode != http.StatusOK || derr != nil || resp.TLS == nil {
  		return api.RefreshResponse{}, false, fmt.Errorf("agent: the broker refused a refresh challenge: %s", resp.Status)
  	}
  	nonce, err := base64.RawURLEncoding.DecodeString(ch.Nonce)
  	if err != nil || len(nonce) != api.RefreshNonceLen {
  		return api.RefreshResponse{}, false, errors.New("agent: the broker's challenge is malformed")
  	}
  	ekm, err := resp.TLS.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
  	if err != nil {
  		return api.RefreshResponse{}, false, err
  	}
  	sig, err := api.SignRefresh(signer, api.RefreshMessage(nonce, ekm))
  	if err != nil {
  		return api.RefreshResponse{}, false, err
  	}
  	body, _ := json.Marshal(api.RefreshRequest{Nonce: ch.Nonce, Signature: base64.RawURLEncoding.EncodeToString(sig)})
  	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, a.broker+"/v1/refresh", bytes.NewReader(body))
  	req.Header.Set("Content-Type", "application/json")
  	resp, err = a.do(req)
  	if err != nil {
  		return api.RefreshResponse{}, true, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
  	}
  	defer drain(resp.Body)
  	if resp.StatusCode != http.StatusOK {
  		var e api.Error
  		_ = json.NewDecoder(resp.Body).Decode(&e)
  		if over := sessionOver(resp.StatusCode, e); over != nil && e.Error == "credential_revoked" {
  			a.end(over)
  			return api.RefreshResponse{}, false, over
  		}
  		return api.RefreshResponse{}, e.Error == "refresh_challenge_missing",
  			fmt.Errorf("agent: the broker refused the refresh: %s %s", e.Error, e.Detail)
  	}
  	var out api.RefreshResponse
  	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
  		return api.RefreshResponse{}, false, err
  	}
  	if ends, err := time.Parse(time.RFC3339, out.SessionEndsAt); err == nil {
  		a.mu.Lock()
  		a.deadline = ends
  		a.mu.Unlock()
  		select {
  		case a.deadlineChanged <- struct{}{}:
  		default:
  		}
  	}
  	return out, false, nil
  }
  ```

  with `deadlineChanged chan struct{}` (buffered 1) made in `New`, and `DeadlineChanged` returning
  it.

  In `sessionOver` and the mint's status handling, a `503` never ends the session: `Mint`, `Connect`
  and `Refresh` return `fmt.Errorf("agent: the broker cannot establish your certificate's revocation
  status just now (%s); try again", e.Detail)` for `certificate_status_unavailable`, and a plain
  error for any other 503 (pre-flight I7).

  In `cmd/port49/main.go`'s `agentMain`, replace the one-shot timer with a loop (pre-flight I6):

  ```go
  	for {
  		timer := time.NewTimer(time.Until(a.SessionEndsAt()))
  		select {
  		case <-ctx.Done():
  			timer.Stop()
  			fmt.Fprintln(stderr, "port49 agent: signal received; exiting")
  		case <-a.DeadlineChanged():
  			timer.Stop()
  			fmt.Fprintf(stderr, "port49 agent: refreshed; the session now ends at %s\n",
  				a.SessionEndsAt().UTC().Format(time.RFC3339))
  			continue
  		case <-timer.C:
  			fmt.Fprintln(stderr, "port49 agent: the session reached max_session_age; exiting - run `port49 login` to start another")
  		case <-a.Done():
  			timer.Stop()
  			fmt.Fprintln(stderr, "port49 agent: exiting - run `port49 login` to start another session")
  		}
  		break
  	}
  ```

  In `Connect`, keep `c.CeilingWarningSeconds` (a new `ceilingWarning time.Duration` field under
  `a.mu`) and report it in `Status`. In `Handler`, add:

  ```go
  	mux.HandleFunc("POST /refresh", func(w http.ResponseWriter, r *http.Request) {
  		out, err := a.Refresh(r.Context())
  		var revoked *RevokedError
  		switch {
  		case errors.As(err, &revoked):
  			writeJSON(w, http.StatusGone, api.Error{Error: "credential_revoked", Detail: revoked.Detail})
  		case err != nil:
  			writeJSON(w, http.StatusBadGateway, api.Error{Error: "refresh_failed", Detail: err.Error()})
  		default:
  			writeJSON(w, http.StatusOK, out)
  		}
  	})
  ```

  In `socket.go`, add `Client.Refresh`, shaped as `Token` (POST `http://agent/refresh`, 200 decodes
  an `api.RefreshResponse`, 410 `credential_revoked` is a `*RevokedError`, anything else an error
  carrying the detail).

- [ ] **Step 5: The CLI.** Create `cmd/port49/refresh.go`:

  ```go
  package main

  // refreshCmd is `port49 refresh` (spec §12): it asks the agent to
  // re-authenticate the session it holds and extend every live session the
  // policy in force still grants.
  func refreshCmd(args []string, stdout, stderr io.Writer) int {
  	fs := flag.NewFlagSet("port49 refresh", flag.ContinueOnError)
  	fs.SetOutput(stderr)
  	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
  	if err := fs.Parse(args); err != nil {
  		return 2
  	}
  	if fs.NArg() != 0 {
  		fmt.Fprint(stderr, usage)
  		return 2
  	}
  	out, err := agent.NewClient(*socket).Refresh(context.Background())
  	switch {
  	case errors.Is(err, agent.ErrNoAgent):
  		fmt.Fprintf(stderr, "port49 refresh: no agent at %s; run 'port49 login'\n", *socket)
  		return 1
  	case err != nil:
  		fmt.Fprintln(stderr, "port49 refresh:", unprefixed(err))
  		return 1
  	}
  	printRefresh(stdout, out)
  	return 0
  }

  // printRefresh says what a refresh did, one line per device (pre-flight M6):
  // extended to when, revoked by the policy, past the grace window (log in
  // again there), not judged (try again), and whether the device's own
  // session is out of reach.
  func printRefresh(w io.Writer, r api.RefreshResponse) {
  	fmt.Fprintf(w, "refreshed at %s; this login lasts until %s\n", r.AuthTime, r.SessionEndsAt)
  	if len(r.Sessions) == 0 {
  		fmt.Fprintln(w, "  no live device session to extend")
  	}
  	width := 0
  	for _, s := range r.Sessions {
  		width = max(width, len(s.Device)+len(s.Username)+3)
  	}
  	for _, s := range r.Sessions {
  		var what string
  		switch s.Outcome {
  		case "extended":
  			what = "extended with no ceiling"
  			if s.SessionExpires != "" {
  				what = "extended to " + s.SessionExpires
  			}
  		case "revoked":
  			what = "revoked by the policy in force, not extended"
  		case "past_grace":
  			what = "past the grace window, not resumed: log in again there"
  		default:
  			what = "not extended this time (the policy could not be applied to it): run 'port49 refresh' again"
  		}
  		if s.Unreached {
  			what += ", not reached: the device keeps its own session"
  		}
  		fmt.Fprintf(w, "  %-*s  %s\n", width, fmt.Sprintf("%s (%s)", s.Device, s.Username), what)
  	}
  }
  ```

  (imports: `context`, `errors`, `flag`, `fmt`, `io`, `strings`, `internal/agent`,
  `internal/broker/api`.) In `main.go`: add `case "refresh": return refreshCmd(args[1:], stdout,
  stderr)` and the usage line `port49 refresh [--socket PATH]`. In `login`, where an agent is already
  running, call `agent.NewClient(sf.socket).Refresh(ctx)` and `printRefresh` instead of "already
  logged in" (a failure there prints the error and exits 1); after a new agent answers its status,
  call `Refresh` likewise and print its line after "logged in", where a refresh failure is said and
  the login still exits 0 (the session is up). In `tokenCmd`, where a non-permit item is printed,
  append the item's `Detail` when it has one (`port49 token: leaf1: deny session_expired: …`); and
  before the token is printed (plain or `--json`):

  ```go
  	// The device's own ceiling, said where the operator is looking, for a
  	// platform that does not show the server_msg warning (decision 33). On
  	// stderr, so --json's stdout stays one object (pre-flight M12). Placed
  	// before the --json and plain prints, so both get it.
  	if exp, err := time.Parse(time.RFC3339, item.SessionExpiresAt); err == nil {
  		if st, err := agent.NewClient(*socket).Status(context.Background()); err == nil && st.CeilingWarningSeconds > 0 {
  			if left := time.Until(exp); left <= time.Duration(st.CeilingWarningSeconds)*time.Second {
  				fmt.Fprintf(stderr, "port49: your session on %s ends at %s (in %s); run 'port49 refresh'\n",
  					device, item.SessionExpiresAt, left.Round(time.Minute))
  			}
  		}
  	}
  ```

- [ ] **Step 6: Run them.** `go test ./internal/agent/ ./cmd/port49/ -count=1 -race` → PASS. Then
  `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 7: Commit.**

  ```bash
  git add internal/agent cmd/port49
  git commit -m "feat(agent): port49 refresh; port49 login refreshes; port49 token warns

  The agent signs the broker's challenge on the held connection and moves its own deadline; it
  never refreshes on its own. port49 login refreshes a held session (and a new one once). port49
  token warns on stderr when the device's session ends within ceiling_warning.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 9: `internal/certstatus`: CRLs verified before use and kept across restarts, OCSP held to RFC 6960, every certificate in the chain

**Files:**
- Create: `internal/certstatus/certstatus.go` (`Checker`, `Check`, `Verdict`, `Result`, `Config`)
- Create: `internal/certstatus/crl.go` (verify at load, scope, persistence, polling with backoff, the
  new-entry callback)
- Create: `internal/certstatus/ocsp.go` (the query, RFC 6960's checks, the caches)
- Modify: `internal/daemon/metrics/metrics.go` (`CertStatusChecks`, `CRLLoads`, `CRLNextUpdate`,
  `CertStatusUnavailable`)
- Test: `internal/certstatus/crl_test.go`, `internal/certstatus/ocsp_test.go`,
  `internal/certstatus/chain_test.go`

**Interfaces:**
- Consumes:
  - `golang.org/x/crypto/ocsp`, in the `golang.org/x/crypto` module already required: run `go mod
    tidy` and confirm `go.mod` gains no module;
  - `printsafe.Line`;
  - `fence.ReadNoLink` and `inventory.WriteAtomic` for the persisted lists.
- Produces:
  - `type Verdict int`, with `Good`, `Revoked` and `Unknown`.
  - `type Result struct { Verdict Verdict; Source string; Name string; RevokedAt time.Time; Depth int; Subject string; Hold bool; Detail string }`:
    - `Source` is one of `"crl"`, `"ocsp"`, `"none"`;
    - `Depth` is the position in the chain of the certificate that decided: 0 for the leaf;
    - `Subject` is that certificate's subject, for a `Depth > 0`;
    - `Hold` marks a `certificateHold` entry.
  - `type CRLSource struct { Name, File, URL string; Issuer *x509.Certificate }`. `Issuer` is the
    CA certificate from `issuer_file`, which port49d's config has already checked against the anchor.
  - `type OCSPConfig struct { Responder string; UseAIA bool; Timeout time.Duration; Hash crypto.Hash }`
  - `type Config struct { CRLs []CRLSource; OCSP *OCSPConfig; RefreshInterval time.Duration; StateDir string }`
  - `func New(cfg Config, now func() time.Time, m *metrics.Metrics, logf func(string, ...any)) *Checker`
  - `func (c *Checker) OnNewEntry(f func(issuer, serial, source string))`. It is called only for a
    verified list's serials that are new over that source's last good list, never for a
    `certificateHold` entry, and never for a list refused or unverified.
  - `func (c *Checker) LoadPersisted() []error`: at start, from `StateDir`; local, fast.
  - `func (c *Checker) LoadAll(ctx context.Context) []error`
  - `func (c *Checker) Run(ctx context.Context)`: the first network load, then each source on its own
    schedule. A failed source is retried from 30s, doubling to `RefreshInterval`.
  - `func (c *Checker) Check(ctx context.Context, chain []*x509.Certificate) Result`
  - `func (c *Checker) Describe() string`
  - **Metrics** (`crl` is a source's configured name, a closed set from configuration):
    - `port49_cert_status_checks_total{source,result}`
    - `port49_crl_loads_total{crl,outcome}`, with `outcome` one of `loaded`, `unchanged`, `failed`,
      `refused`
    - `port49_crl_next_update_timestamp_seconds{crl}`, a gauge set after every load (pre-flight M7)
    - `port49_cert_status_unavailable_total`

- [ ] **Step 1: The CRL tests.** Create `internal/certstatus/crl_test.go`.
  - **Building the lists.** Build them with `x509.CreateRevocationList` over a `testpki.CA`, and add
    extensions with `RevocationList.ExtraExtensions` and entry extensions with
    `RevocationListEntry.ExtraExtensions`.
  - **Sources.** Serve them from an `httptest.Server` whose body a test can swap, or write them to a
    temp file. Give each source a `StateDir` under `t.TempDir()` (0700).

  Each case is a `t.Run`:
  1. **A fresh verified list** not naming the leaf: `Good`, source `crl`. Naming it: `Revoked`, with
     its time.
  2. **Signed by another key.** A list under the same issuer name, signed by another key (pre-flight
     C1):
     - it is refused at load (`CRLLoads{outcome="refused"}`);
     - the last good list stays in force, so a leaf it names stays `Revoked`;
     - `OnNewEntry` fires for none of its serials;
     - nothing is written to `StateDir`.
  3. **A forged list with a huge `CRLNumber`**, signed by another key: refused, and the next genuine
     list, numbered one above the last good one, loads.
  4. **A genuine list with a lower `CRLNumber`**, or the same number and an earlier `ThisUpdate`:
     refused (a rollback).
  5. **Past `NextUpdate`.** A list past it is `Unknown`, its detail naming the source and "past its
     next update". The same stale list naming the leaf is still `Revoked`.
  6. **Refused shapes** (pre-flight I3). Each of these is refused at load and counted `refused`:
     - a delta CRL (indicator 2.5.29.27);
     - an unknown critical extension;
     - a critical Issuing Distribution Point with `onlySomeReasons`, `indirectCRL`, a
       `distributionPoint`, `onlyContainsCACerts` or `onlyContainsAttributeCerts`;
     - an entry with a critical extension.

     An IDP with `onlyContainsUserCerts` alone loads and covers leaves only.
  7. **The chain.** An intermediate-issued leaf, chain `[leaf, intermediate, root]`, against the
     intermediate's list and the root's list (pre-flight I2):
     - the leaf is `Good`;
     - the root's list naming the intermediate makes the leaf `Revoked` with `Depth: 1` and `Subject`
       the intermediate's;
     - an `onlyContainsUserCerts` root list does not cover the intermediate, so the intermediate is
       `Unknown`, and so is the leaf.
  8. **`OnNewEntry`.**
     - It is called for each serial a second verified load adds, and only those, with the issuer as
       `pkix.Name.String()` prints it and the serial as `big.Int.Text(16)`.
     - It is never called for a `certificateHold` entry, whose leaf is `Revoked` with `Hold: true`
       (pre-flight M13).
  9. **Fetching.** A URL source that redirects, or serves over 16 MiB, is refused. A source that
     fails keeps the last good list and says it once.
  10. **Persistence** (pre-flight I8):
      - a verified list is written to `StateDir/crl-<name>.der`, 0600;
      - a new `Checker` with the server down loads it with `LoadPersisted` and answers `Good`;
      - a persisted file that does not verify is refused;
      - a persisted file in a directory others can write is refused.
  11. **Backoff.** With an injected clock and a source failing, `Run` retries at 30s, 60s and 120s,
      capped at `RefreshInterval`, and returns to `RefreshInterval` after a success.

- [ ] **Step 2: The OCSP tests** (pre-flight C2). Create `internal/certstatus/ocsp_test.go`.
  - **The responder.** An `httptest.Server` OCSP responder signs with `ocsp.CreateResponse`. A test
    picks its signer, the issuer or a delegate with or without `id-kp-OCSPSigning` and in or out of
    validity, and its `ThisUpdate`, `NextUpdate`, serial and status. It counts calls and can hang.
  - **`Unknown`, and never cached:**
    - a delegate without the OCSP-signing usage;
    - a delegate past its `NotAfter`;
    - a `NextUpdate` in the past;
    - a `ThisUpdate` 6m in the future;
    - a `ThisUpdate` older than `RefreshInterval` with no `NextUpdate`;
    - an answer for another serial;
    - an unsigned body;
    - a hang past `Timeout`.
  - **Accepted:**
    - the issuer signing `good` is `Good`, cached to `min(NextUpdate, 1h)`, so a second `Check`
      makes no call;
    - an in-validity delegate with the OCSP-signing usage is accepted;
    - `revoked` is `Revoked`.
  - **A failure** is cached 30s: a second `Check` within 30s makes no call, and one after makes one
    (M15).
  - **Twenty concurrent `Check`s** of one certificate make one call (M15).
  - **`use_aia`** reads the certificate's `OCSPServer`.
  - **`Hash: crypto.SHA1`** sends a SHA-1 CertID, and the responder's answer for it is taken (M14).
  - **A fresh list covering the issuer** means no OCSP call at all.
  - **Peer text.** A responder's status line in the detail is made printable: a test responder
    answering `500` with a control character in its reason phrase leaves none in `Result.Detail`
    (M16).

- [ ] **Step 3: Run them to see them fail.** `go test ./internal/certstatus/ -count=1`
  Expected: FAIL to compile.

- [ ] **Step 4: The checker.** Create `internal/certstatus/certstatus.go`:

  ```go
  // Package certstatus answers whether a client certificate, or any
  // certificate above it in its verified chain but the anchor, is revoked,
  // from the CRLs and OCSP responder port49d's broker.certificate_status names
  // (spec §5.1.4; decision 33). A CRL is verified against its source's
  // issuer certificate before anything uses it; an OCSP answer is held to RFC
  // 6960's responder and freshness rules. It decides nothing about policy:
  // the broker reads its Result.
  package certstatus

  // Verdict is a certificate's status.
  type Verdict int

  const (
  	Good Verdict = iota
  	Revoked
  	Unknown
  )

  func (v Verdict) String() string { return [...]string{"good", "revoked", "unknown"}[v] }

  // Result is one Check: the chain's verdict, the source that gave it and
  // its name, the depth and subject of the certificate that decided (0, the
  // leaf), when it was revoked, whether that is a hold, and for Unknown why.
  type Result struct {
  	Verdict   Verdict
  	Source    string // "crl", "ocsp", or "none"
  	Name      string
  	Depth     int
  	Subject   string
  	RevokedAt time.Time
  	Hold      bool
  	Detail    string
  }

  type CRLSource struct {
  	Name, File, URL string
  	Issuer          *x509.Certificate // the CA that signs the list (issuer_file)
  }

  type OCSPConfig struct {
  	Responder string
  	UseAIA    bool
  	Timeout   time.Duration
  	Hash      crypto.Hash // crypto.SHA256, or crypto.SHA1 (ocsp.hash)
  }

  type Config struct {
  	CRLs            []CRLSource
  	OCSP            *OCSPConfig
  	RefreshInterval time.Duration
  	StateDir        string // where each verified list is kept, crl-<name>.der
  }

  // Check is the chain's status (pre-flight I2). chain is a verified chain,
  // leaf first and the anchor last. Each certificate but the anchor is
  // checked against the one above it: the first Revoked decides, with its
  // depth; otherwise the first Unknown decides; otherwise Good.
  func (c *Checker) Check(ctx context.Context, chain []*x509.Certificate) Result {
  	var res Result
  	unknown := -1
  	var unknownRes Result
  	last := len(chain) - 1
  	if last == 0 {
  		last = 1 // a lone self-issued leaf is checked against itself
  	}
  	for i := 0; i < last; i++ {
  		cert, issuer := chain[i], chain[min(i+1, len(chain)-1)]
  		r := c.checkOne(ctx, cert, issuer, i)
  		r.Depth = i
  		if i > 0 {
  			r.Subject = printsafe.Line(cert.Subject.String(), 200)
  		}
  		if r.Verdict == Revoked {
  			res = r
  			break
  		}
  		if r.Verdict == Unknown && unknown < 0 {
  			unknown, unknownRes = i, r
  		}
  		if i == 0 {
  			res = r
  		}
  	}
  	if res.Verdict != Revoked && unknown >= 0 {
  		res = unknownRes
  	}
  	c.m.CertStatusChecks.WithLabelValues(res.Source, res.Verdict.String()).Inc()
  	if res.Verdict == Unknown {
  		c.m.CertStatusUnavailable.Inc()
  	}
  	return res
  }

  // checkOne is one certificate's status against its issuer: a verified list
  // that names it is final; a fresh one that does not is Good; then OCSP.
  func (c *Checker) checkOne(ctx context.Context, cert, issuer *x509.Certificate, depth int) Result {
  	res := c.checkCRLs(cert, issuer, depth)
  	if res.Verdict == Unknown && c.cfg.OCSP != nil {
  		if o := c.checkOCSP(ctx, cert, issuer); o.Verdict != Unknown {
  			return o
  		} else {
  			res.Detail = strings.TrimSpace(res.Detail + "; " + o.Detail)
  		}
  	}
  	return res
  }
  ```

  `New` builds `http` as `&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
  return errors.New("a status source does not redirect") }}` and the maps. `Describe` lists each
  source with its loaded list's `NextUpdate` ("not loaded yet" before the first) and the responder.
  `say` is the checker's own once-per-key-per-10m line limiter.

- [ ] **Step 5: The CRLs.** Create `internal/certstatus/crl.go`:

  ```go
  // loadedCRL is one source's last good list: verified, and in scope.
  type loadedCRL struct {
  	name      string
  	issuer    *x509.Certificate
  	list      *x509.RevocationList
  	revoked   map[string]revokedEntry // serial as big.Int.Text(16)
  	userOnly  bool                    // IDP onlyContainsUserCerts: covers leaves alone
  	loadedAt  time.Time
  }

  type revokedEntry struct {
  	at   time.Time
  	hold bool
  }

  const (
  	crlMax       = 16 << 20
  	crlFetchTime = 30 * time.Second
  	retryFirst   = 30 * time.Second
  )

  var (
  	oidAuthorityKeyID  = asn1.ObjectIdentifier{2, 5, 29, 35}
  	oidCRLNumber       = asn1.ObjectIdentifier{2, 5, 29, 20}
  	oidDeltaCRL        = asn1.ObjectIdentifier{2, 5, 29, 27}
  	oidIssuingDistPt   = asn1.ObjectIdentifier{2, 5, 29, 28}
  	oidReasonCode      = asn1.ObjectIdentifier{2, 5, 29, 21}
  	reasonCertificateHold = 6
  )

  // accept verifies raw as src's list and checks its scope, returning the
  // list ready to use or why it is refused (pre-flight C1, I3). Nothing about
  // a list is read for any purpose before this returns it.
  func (c *Checker) accept(src CRLSource, raw []byte) (*loadedCRL, error) {
  	if blk, _ := pem.Decode(raw); blk != nil && blk.Type == "X509 CRL" {
  		raw = blk.Bytes
  	}
  	list, err := x509.ParseRevocationList(raw)
  	if err != nil {
  		return nil, fmt.Errorf("does not parse as a CRL: %w", err)
  	}
  	if err := list.CheckSignatureFrom(src.Issuer); err != nil {
  		return nil, fmt.Errorf("is not signed by issuer_file's certificate (%v)", err)
  	}
  	l := &loadedCRL{name: src.Name, issuer: src.Issuer, list: list, revoked: map[string]revokedEntry{},
  		loadedAt: c.now()}
  	for _, ext := range list.Extensions {
  		switch {
  		case ext.Id.Equal(oidDeltaCRL):
  			return nil, errors.New("is a delta CRL; name the full CRL")
  		case ext.Id.Equal(oidIssuingDistPt):
  			userOnly, err := userCertsOnly(ext.Value)
  			if err != nil {
  				return nil, fmt.Errorf("is scoped by its issuing distribution point (%v); name a CRL covering every serial, or one scoped to user certificates alone", err)
  			}
  			l.userOnly = userOnly
  		case ext.Critical && !ext.Id.Equal(oidAuthorityKeyID) && !ext.Id.Equal(oidCRLNumber):
  			return nil, fmt.Errorf("carries a critical extension port49 does not understand (%s)", ext.Id)
  		}
  	}
  	for _, e := range list.RevokedCertificateEntries {
  		for _, ext := range e.Extensions {
  			if ext.Critical {
  				return nil, fmt.Errorf("has an entry with a critical extension (%s), such as an indirect CRL's issuer", ext.Id)
  			}
  		}
  		l.revoked[e.SerialNumber.Text(16)] = revokedEntry{at: e.RevocationTime, hold: e.ReasonCode == reasonCertificateHold}
  	}
  	return l, nil
  }

  // userCertsOnly reads an Issuing Distribution Point and accepts it only
  // when it says nothing but onlyContainsUserCerts (true) or nothing at all:
  // a distribution point, a reason subset, an indirect CRL or an attribute or
  // CA scope partitions the issuer's serials (pre-flight I3).
  func userCertsOnly(der []byte) (bool, error) {
  	var idp struct {
  		DistributionPoint          asn1.RawValue  `asn1:"optional,tag:0"`
  		OnlyContainsUserCerts      bool           `asn1:"optional,tag:1"`
  		OnlyContainsCACerts        bool           `asn1:"optional,tag:2"`
  		OnlySomeReasons            asn1.BitString `asn1:"optional,tag:3"`
  		IndirectCRL                bool           `asn1:"optional,tag:4"`
  		OnlyContainsAttributeCerts bool           `asn1:"optional,tag:5"`
  	}
  	if rest, err := asn1.Unmarshal(der, &idp); err != nil || len(rest) != 0 {
  		return false, errors.New("an issuing distribution point that does not parse")
  	}
  	if len(idp.DistributionPoint.FullBytes) > 0 || idp.OnlyContainsCACerts || idp.OnlySomeReasons.BitLength > 0 ||
  		idp.IndirectCRL || idp.OnlyContainsAttributeCerts {
  		return false, errors.New("a partitioned scope")
  	}
  	return idp.OnlyContainsUserCerts, nil
  }

  // install puts a verified list in force for its source when it is not
  // older than the last good one, persists it, and reports its new entries.
  // It is the one place a list is put in force.
  func (c *Checker) install(src CRLSource, l *loadedCRL, raw []byte, persist bool) error {
  	c.mu.Lock()
  	prev := c.crls[src.Name]
  	if prev != nil {
  		older := l.list.ThisUpdate.Before(prev.list.ThisUpdate)
  		if prev.list.Number != nil && l.list.Number != nil {
  			older = l.list.Number.Cmp(prev.list.Number) < 0 ||
  				(l.list.Number.Cmp(prev.list.Number) == 0 && older)
  		}
  		if older {
  			c.mu.Unlock()
  			return fmt.Errorf("is older than the list in force (number %v, this update %s); an older list is not taken",
  				l.list.Number, l.list.ThisUpdate.UTC().Format(time.RFC3339))
  		}
  	}
  	c.crls[src.Name] = l
  	onNew := c.onNew
  	c.mu.Unlock()
  	c.gaugeOne(l)
  	if persist && c.cfg.StateDir != "" {
  		if err := inventory.WriteAtomic(c.cfg.StateDir, "crl-"+src.Name+".der", l.list.Raw, 0o600); err != nil {
  			c.say("persist "+src.Name, "port49d: broker: certificate status: CRL %s could not be kept in %s (%v); "+
  				"a restart will fetch it again", src.Name, c.cfg.StateDir, err)
  		}
  	}
  	if onNew != nil {
  		for serial, e := range l.revoked {
  			if e.hold {
  				continue // a hold is lifted by the CA: refused while listed, never marked (M13)
  			}
  			if prev != nil {
  				if _, had := prev.revoked[serial]; had {
  					continue
  				}
  			}
  			onNew(l.list.Issuer.String(), serial, src.Name)
  		}
  	}
  	return nil
  }

  // load fetches, verifies and installs one source.
  func (c *Checker) load(ctx context.Context, src CRLSource) error {
  	raw, err := c.fetch(ctx, src)
  	if err != nil {
  		c.m.CRLLoads.WithLabelValues(src.Name, "failed").Inc()
  		return err
  	}
  	l, err := c.accept(src, raw)
  	if err == nil {
  		c.mu.Lock()
  		prev := c.crls[src.Name]
  		c.mu.Unlock()
  		if prev != nil && bytes.Equal(prev.list.Raw, l.list.Raw) {
  			c.m.CRLLoads.WithLabelValues(src.Name, "unchanged").Inc()
  			return nil
  		}
  		err = c.install(src, l, raw, true)
  	}
  	if err != nil {
  		c.m.CRLLoads.WithLabelValues(src.Name, "refused").Inc()
  		return err
  	}
  	c.m.CRLLoads.WithLabelValues(src.Name, "loaded").Inc()
  	return nil
  }

  // LoadPersisted puts each source's kept list in force at start, read
  // behind the fence and verified again, so a restart during a publisher
  // outage keeps a list still fresh (pre-flight I8).
  func (c *Checker) LoadPersisted() []error {
  	var errs []error
  	for _, src := range c.cfg.CRLs {
  		path := filepath.Join(c.cfg.StateDir, "crl-"+src.Name+".der")
  		raw, err := fence.ReadNoLink(path, crlMax, "kept CRL")
  		if errors.Is(err, fs.ErrNotExist) {
  			continue
  		}
  		if err == nil {
  			var l *loadedCRL
  			if l, err = c.accept(src, raw); err == nil {
  				err = c.install(src, l, raw, false)
  			}
  		}
  		if err != nil {
  			errs = append(errs, fmt.Errorf("kept CRL %s: %w", src.Name, err))
  		}
  	}
  	return errs
  }

  // Run fetches every source now, then each on its own schedule: every
  // RefreshInterval after a success, and from 30s doubling to
  // RefreshInterval after a failure (pre-flight I8). It returns when ctx ends.
  func (c *Checker) Run(ctx context.Context) {
  	type next struct {
  		at    time.Time
  		delay time.Duration
  	}
  	due := map[string]*next{}
  	for _, src := range c.cfg.CRLs {
  		due[src.Name] = &next{at: c.now()}
  	}
  	for {
  		soonest := c.now().Add(c.cfg.RefreshInterval)
  		for _, src := range c.cfg.CRLs {
  			n := due[src.Name]
  			if c.now().Before(n.at) {
  				soonest = minTime(soonest, n.at)
  				continue
  			}
  			if err := c.load(ctx, src); err != nil {
  				c.say("load "+src.Name, "port49d: broker: certificate status: CRL %s: %s; the list in force stays "+
  					"until its next update", src.Name, printsafe.Line(err.Error(), 300))
  				n.delay = min(max(2*n.delay, retryFirst), c.cfg.RefreshInterval)
  			} else {
  				n.delay = c.cfg.RefreshInterval
  			}
  			n.at = c.now().Add(n.delay)
  			soonest = minTime(soonest, n.at)
  		}
  		select {
  		case <-ctx.Done():
  			return
  		case <-c.after(soonest.Sub(c.now())):
  		}
  	}
  }
  ```

  The helpers:
  - `minTime` is the earlier of two times;
  - `c.after` is `time.After`, swapped in tests with the injected clock;
  - `fetch` is as before (a regular file within `crlMax`, or a URL with no redirect within
    `crlFetchTime` and `crlMax`);
  - `gaugeOne` sets `CRLNextUpdate{crl}` to the list's `NextUpdate` as a Unix time, or `loadedAt +
    RefreshInterval` when it has none.

  `checkCRLs` matches a list by issuer certificate:

  ```go
  // checkCRLs reads every list in force whose issuer certificate is,
  // byte for byte, the certificate that verified cert (pre-flight C1); a
  // list scoped to user certificates covers depth 0 alone.
  func (c *Checker) checkCRLs(cert, issuer *x509.Certificate, depth int) Result {
  	now := c.now()
  	c.mu.Lock()
  	defer c.mu.Unlock()
  	serial := cert.SerialNumber.Text(16)
  	var fresh *loadedCRL
  	var stale []string
  	for _, l := range c.crls {
  		if !bytes.Equal(l.issuer.Raw, issuer.Raw) || (l.userOnly && depth > 0) {
  			continue
  		}
  		if e, revoked := l.revoked[serial]; revoked {
  			return Result{Verdict: Revoked, Source: "crl", Name: l.name, RevokedAt: e.at, Hold: e.hold}
  		}
  		next := l.list.NextUpdate
  		if next.IsZero() {
  			next = l.loadedAt.Add(c.cfg.RefreshInterval)
  		}
  		if now.Before(next) {
  			fresh = l
  		} else {
  			stale = append(stale, fmt.Sprintf("CRL %s is past its next update, %s", l.name, next.UTC().Format(time.RFC3339)))
  		}
  	}
  	if fresh != nil {
  		return Result{Verdict: Good, Source: "crl", Name: fresh.name}
  	}
  	detail := fmt.Sprintf("no fresh CRL or OCSP answer covers %q", printsafe.Line(issuer.Subject.String(), 200))
  	if len(stale) > 0 {
  		detail = strings.Join(stale, "; ")
  	}
  	return Result{Verdict: Unknown, Source: "none", Detail: detail}
  }
  ```

- [ ] **Step 6: OCSP.** Create `internal/certstatus/ocsp.go`:

  ```go
  type ocspEntry struct {
  	res     Result
  	expires time.Time
  }

  const (
  	ocspMaxCache    = time.Hour        // a revocation reaches the broker within it
  	ocspFailCache   = 30 * time.Second // a responder down is asked once per 30s (M15)
  	ocspFutureSkew  = 5 * time.Minute
  )

  // checkOCSP asks the responder about cert, held to RFC 6960 (pre-flight
  // C2): the answer verifies for issuer, and its signer is issuer itself or
  // a delegate issuer signed that carries id-kp-OCSPSigning and is inside its
  // validity; its serial is cert's; its ThisUpdate is at most five minutes
  // ahead; its NextUpdate, when set, is still to come, and when unset its
  // ThisUpdate is within RefreshInterval. A good or revoked answer is cached
  // to the earlier of its NextUpdate and an hour, never once expired; a
  // failure for 30s. Concurrent questions about one certificate share one
  // request (M15).
  func (c *Checker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate) Result {
  	key := ocspKey(cert, issuer)
  	for {
  		c.mu.Lock()
  		if e, ok := c.ocsp[key]; ok && c.now().Before(e.expires) {
  			c.mu.Unlock()
  			return e.res
  		}
  		if wait, busy := c.ocspInflight[key]; busy {
  			c.mu.Unlock()
  			select {
  			case <-wait:
  				continue
  			case <-ctx.Done():
  				return Result{Verdict: Unknown, Source: "none", Detail: "OCSP: the question was abandoned"}
  			}
  		}
  		done := make(chan struct{})
  		c.ocspInflight[key] = done
  		c.mu.Unlock()
  		res, ttl := c.askOCSP(ctx, cert, issuer)
  		c.mu.Lock()
  		if ttl > 0 {
  			c.ocsp[key] = ocspEntry{res: res, expires: c.now().Add(ttl)}
  		}
  		delete(c.ocspInflight, key)
  		close(done)
  		c.mu.Unlock()
  		return res
  	}
  }

  // askOCSP is one question, and how long its answer may be reused.
  func (c *Checker) askOCSP(ctx context.Context, cert, issuer *x509.Certificate) (Result, time.Duration) {
  	now := c.now()
  	url := c.cfg.OCSP.Responder
  	if url == "" && c.cfg.OCSP.UseAIA && len(cert.OCSPServer) > 0 {
  		url = cert.OCSPServer[0]
  	}
  	unknown := func(why string) (Result, time.Duration) {
  		return Result{Verdict: Unknown, Source: "none",
  			Detail: "OCSP " + printsafe.Line(url, 120) + ": " + printsafe.Line(why, 200)}, ocspFailCache
  	}
  	if url == "" {
  		return unknown("no responder for this certificate")
  	}
  	reqBody, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: c.cfg.OCSP.Hash})
  	if err != nil {
  		return unknown(err.Error())
  	}
  	qctx, cancel := context.WithTimeout(ctx, c.cfg.OCSP.Timeout)
  	defer cancel()
  	req, err := http.NewRequestWithContext(qctx, http.MethodPost, url, bytes.NewReader(reqBody))
  	if err != nil {
  		return unknown(err.Error())
  	}
  	req.Header.Set("Content-Type", "application/ocsp-request")
  	resp, err := c.http.Do(req)
  	if err != nil {
  		return unknown("did not answer")
  	}
  	defer resp.Body.Close()
  	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
  	if err != nil || resp.StatusCode != http.StatusOK {
  		return unknown("answered " + resp.Status)
  	}
  	r, err := ocsp.ParseResponseForCert(raw, cert, issuer)
  	switch {
  	case err != nil:
  		return unknown("its answer does not verify for this issuer")
  	case r.Certificate != nil && !delegateOK(r.Certificate, now):
  		return unknown("its answer is signed by a delegate without the OCSP-signing usage, or out of validity")
  	case r.SerialNumber == nil || r.SerialNumber.Cmp(cert.SerialNumber) != 0:
  		return unknown("its answer is for another serial")
  	case r.ThisUpdate.After(now.Add(ocspFutureSkew)):
  		return unknown("its answer is dated in the future")
  	case !r.NextUpdate.IsZero() && !now.Before(r.NextUpdate):
  		return unknown("its answer is past its next update")
  	case r.NextUpdate.IsZero() && r.ThisUpdate.Before(now.Add(-c.cfg.RefreshInterval)):
  		return unknown("its answer is older than refresh_interval and names no next update")
  	}
  	res := Result{Source: "ocsp", Name: url}
  	switch r.Status {
  	case ocsp.Good:
  		res.Verdict = Good
  	case ocsp.Revoked:
  		res.Verdict, res.RevokedAt = Revoked, r.RevokedAt
  		res.Hold = r.RevocationReason == ocsp.CertificateHold
  	default:
  		return unknown("answered unknown")
  	}
  	ttl := ocspMaxCache
  	if !r.NextUpdate.IsZero() {
  		ttl = min(ttl, r.NextUpdate.Sub(now))
  	}
  	return res, ttl
  }

  // delegateOK is RFC 6960 §4.2.2.2's delegated responder: issued by the
  // issuer (ParseResponseForCert checked the signature), carrying
  // id-kp-OCSPSigning, and inside its validity.
  func delegateOK(d *x509.Certificate, now time.Time) bool {
  	if now.Before(d.NotBefore) || now.After(d.NotAfter) {
  		return false
  	}
  	for _, u := range d.ExtKeyUsage {
  		if u == x509.ExtKeyUsageOCSPSigning {
  			return true
  		}
  	}
  	return false
  }

  func ocspKey(cert, issuer *x509.Certificate) string {
  	sum := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
  	return hex.EncodeToString(sum[:]) + "|" + cert.SerialNumber.Text(16)
  }
  ```

  A revoked answer is cached like a good one; a certificate once revoked stays so. `New` makes
  `ocspInflight map[string]chan struct{}`.

- [ ] **Step 7: The metrics.** Add the four metrics with the names and labels above to `metrics.go` and
  its test.

- [ ] **Step 8: Run them.** `go test ./internal/certstatus/ ./internal/daemon/metrics/ -count=1 -race` →
  PASS. `go mod tidy` leaves `go.mod`'s `require` lines unchanged. Then `gofmt -w`,
  `make build && make test && make vet`.

- [ ] **Step 9: Commit.**

  ```bash
  git add internal/certstatus internal/daemon/metrics go.mod go.sum
  git commit -m "feat(certstatus): CRLs verified before use and kept; OCSP held to RFC 6960; the whole chain

  A CRL is verified against its source's issuer_file certificate before it may replace the last
  good list, move its number or report an entry; a rollback, a delta, an unknown critical
  extension and a partitioned scope are refused; verified lists are kept across restarts and a
  failed source is retried from 30s. OCSP answers come from the issuer or an in-validity
  delegate with the OCSP-signing usage, for the right serial, fresh within 5m of skew; failures
  are cached 30s and questions shared. Every certificate but the anchor is checked.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 10: The broker refuses a revoked or unestablished certificate before it binds, at mint and at refresh, and revokes what a CRL newly names from a bounded queue

**Files:**
- Create: `internal/broker/certcheck.go` (`StatusChecker`, `certRefusal`, `BindStatus`,
  `OnCRLEntry`, the revocation queue)
- Modify: `internal/broker/broker.go` (`Broker.CertStatus`, `Broker.OnUnavailable`; the check in
  `tokens`)
- Modify: `internal/broker/sessionrefresh.go` (the check in `refresh`)
- Modify: `internal/broker/listen.go`:
  - `Listener.Status`, called before `bind`;
  - `ConnCloser.HoldsCert`;
  - `answerRevoked` generalised to a refusal's status and code;
  - `Refused`, which now takes the reason.
- Test: `internal/broker/certcheck_test.go`, `internal/broker/listen_test.go`

**Interfaces:**
- Consumes:
  - Task 9's `Checker.Check` and `Result`, with its `Depth` and `Hold`;
  - 7a's `Revoke`, `detach`/`RevokeTimeout`, `refuseRevokedAs`, `answerRevoked` and `Refused`.
- Produces:
  - `type StatusChecker interface { Check(ctx context.Context, chain []*x509.Certificate) certstatus.Result }`
  - `Broker.CertStatus StatusChecker`; nil means no checking (port49d's `disabled: true`).
  - `Broker.OnUnavailable string`: `"refuse"` | `"allow"`.
  - `type BindRefusal struct { Status int; Reason decision.Reason; Error, Detail string; RetryAfter int }`:
    - a revoked certificate is `Status: 401`, `Error: "credential_revoked"`;
    - an unestablished one is `Status: 503`, `Error: "certificate_status_unavailable"`, `Reason:
      trust_domain_unresolved`, `RetryAfter: 60` (pre-flight I7).
  - `func (b *Broker) BindStatus(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal`,
    which port49d sets as `Listener.Status`.
  - `func (b *Broker) OnCRLEntry(issuer, serial, source string)`, which port49d sets with
    `Checker.OnNewEntry`. It only enqueues.
  - `func (b *Broker) RunRevocationQueue(ctx context.Context)`, which drains the queue one revocation
    at a time and retries the pending set at each call of `RetryPending`.
  - `func (b *Broker) RetryPending()`, which port49d calls after each CRL poll.
  - `ConnCloser` gains `HoldsCert(certKey string) bool`.
  - `Listener.Refused func(principal string, cred store.Credential, reason decision.Reason)`: 7a's
    callback with the reason added (`credential_revoked` for a mark, as before).

- [ ] **Step 1: The tests.** Create `internal/broker/certcheck_test.go` with a `fakeStatus` whose
  `Check` returns a set `certstatus.Result` per leaf serial and counts calls. Each case:
  - **A revoked leaf** (`Depth: 0`):
    - through `serveThrough` with `Listener.Status` set, it is answered `401 credential_revoked` and
      recorded `mint deny credential_revoked`;
    - with `MaxPerPrincipal: 4` and the owner's renewed certificate holding four connections, ten
      binds of the revoked certificate leave all four open and the held gauge at 4 (pre-flight I1);
    - a mint and a refresh with it are refused `credential_revoked`;
    - a `Broker.Revoke` with origin `crl …` or `ocsp …` follows; wait for its mark with `eventually`.
  - **A revoked intermediate** (`Depth: 1`): the leaf is refused `credential_revoked` with a detail
    naming the intermediate, and no mark is written on the leaf (pre-flight I2). **A hold** (`Hold:
    true`): refused, and no mark.
  - **An unknown status:**
    - with `OnUnavailable: "refuse"`, the mint is answered `503 certificate_status_unavailable` with
      `Retry-After: 60`, its record `mint deny trust_domain_unresolved`;
    - so is the bind, and the refresh (pre-flight I7);
    - with `"allow"`, the mint goes through, and two checks within 10m say the line once (M1).
  - **`OnCRLEntry`** for:
    - a certificate with a held connection: the queued revocation runs, the connection is closed, and
      the mark's origin is `crl corp`;
    - one with a live context or an unspent token: it runs;
    - one with none: no mark;
    - a store whose `ContextsByCert` errors: no mark, the entry is pending, and after the store
      recovers `RetryPending` revokes it if the certificate is present (pre-flight I9);
    - 150 entries enqueued at once: the threshold line is said once, and an operator's `Revoke` made
      meanwhile completes without waiting for all 150 (the queue yields between revocations).
  - **No checker:** with `CertStatus` nil, `fakeStatus` is never called.

  In `listen_test.go`, update 7a's tests for `Refused`'s new parameter.

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/broker/ -run 'Status|CRL' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 3: The broker's check.** Create `internal/broker/certcheck.go`:

  ```go
  // StatusChecker is certstatus.Checker as the broker sees it.
  type StatusChecker interface {
  	Check(ctx context.Context, chain []*x509.Certificate) certstatus.Result
  }

  // BindRefusal is why a certificate is refused, and how it is answered:
  // 401 for a verdict (revoked), 503 with Retry-After for a status that
  // cannot be established, which ends no session (pre-flight I7).
  type BindRefusal struct {
  	Status        int
  	Reason        decision.Reason
  	Error, Detail string
  	RetryAfter    int
  }

  // certRefusal is the chain's status as a refusal, or nil to go on (spec
  // §5.1.4; decision 33). A revoked leaf is refused and revoked through
  // Revoke, queued, so every path reaches it and the mark outlives a source
  // that goes stale; a revoked intermediate or a hold refuses without a mark.
  // Unknown is refused as unavailable unless OnUnavailable is "allow".
  func (b *Broker) certRefusal(ctx context.Context, cs *tls.ConnectionState, cred store.Credential) *BindRefusal {
  	if b.CertStatus == nil || cs == nil || len(cs.VerifiedChains) == 0 {
  		return nil
  	}
  	res := b.CertStatus.Check(ctx, cs.VerifiedChains[0])
  	switch res.Verdict {
  	case certstatus.Revoked:
  		what := "this certificate"
  		if res.Depth > 0 {
  			what = fmt.Sprintf("this certificate's issuer, %s,", res.Subject)
  		} else if !res.Hold {
  			b.enqueueRevoke(cred.Issuer, cred.Serial, res.Source+" "+res.Name)
  		}
  		return &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.CredentialRevoked,
  			Error: string(decision.CredentialRevoked), Detail: fmt.Sprintf(
  				"%s was revoked at its CA (%s %s, %s); nothing is minted for it", what, res.Source,
  				printsafe.Line(res.Name, 120), res.RevokedAt.UTC().Format(time.RFC3339))}
  	case certstatus.Unknown:
  		if b.OnUnavailable == "allow" {
  			b.sayOnce("allow "+res.Name, 10*time.Minute, "broker: admitting a certificate whose revocation "+
  				"status cannot be established (%s); broker.certificate_status.on_unavailable is allow", res.Detail)
  			return nil
  		}
  		return &BindRefusal{Status: http.StatusServiceUnavailable, Reason: decision.TrustDomainUnresolved,
  			Error: "certificate_status_unavailable", RetryAfter: 60,
  			Detail: "the broker cannot establish this certificate's revocation status (" + res.Detail + "); try again"}
  	}
  	return nil
  }

  // BindStatus is Listener.Status: the check before a connection binds.
  func (b *Broker) BindStatus(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal {
  	ctx, cancel := context.WithTimeout(context.Background(), holdTimeout)
  	defer cancel()
  	return b.certRefusal(ctx, &cs, cred)
  }

  // revokeQueueLen bounds the CRL revocations waiting; queueWarn is the
  // count past which a load is said (pre-flight I9).
  const (
  	revokeQueueLen = 4096
  	queueWarn      = 100
  )

  type queuedRevoke struct{ issuer, serial, origin string }

  // OnCRLEntry queues a certificate a CRL newly names; RunRevocationQueue
  // revokes it if it is still present. It never blocks the loader.
  func (b *Broker) OnCRLEntry(issuer, serial, source string) {
  	b.enqueueRevoke(issuer, serial, "crl "+source)
  }

  func (b *Broker) enqueueRevoke(issuer, serial, origin string) {
  	b.queueOnce.Do(func() { b.revokeQueue = make(chan queuedRevoke, revokeQueueLen) })
  	select {
  	case b.revokeQueue <- queuedRevoke{issuer, serial, origin}:
  		if n := len(b.revokeQueue); n == queueWarn {
  			b.logf("broker: %d CRL revocations are queued; each is revoked in turn, and each certificate "+
  				"is refused at every use meanwhile", n)
  		}
  	default:
  		b.pend(queuedRevoke{issuer, serial, origin}) // full: kept for the next retry
  	}
  }

  // RunRevocationQueue revokes queued certificates one at a time, each only
  // if it is still present: a held connection, a live context, an unspent
  // token. A store error reading those puts it on the pending set rather than
  // marking it (pre-flight I9). Each Revoke takes 7a's semaphore in turn, so
  // an operator's port49 revoke is served between two queued ones.
  func (b *Broker) RunRevocationQueue(ctx context.Context) {
  	b.queueOnce.Do(func() { b.revokeQueue = make(chan queuedRevoke, revokeQueueLen) })
  	for {
  		select {
  		case <-ctx.Done():
  			return
  		case q := <-b.revokeQueue:
  			b.revokeIfPresent(ctx, q)
  		}
  	}
  }

  func (b *Broker) revokeIfPresent(ctx context.Context, q queuedRevoke) {
  	key := store.CertKey(q.issuer, q.serial)
  	present := b.Conns != nil && b.Conns.HoldsCert(key)
  	if !present {
  		rctx, cancel := context.WithTimeout(ctx, holdTimeout)
  		refs, err := b.Store.ContextsByCert(rctx, key)
  		toks, err2 := b.Store.TokensByCert(rctx, key)
  		cancel()
  		if err != nil || err2 != nil {
  			b.pend(q)
  			return
  		}
  		present = len(refs) > 0 || len(toks) > 0
  	}
  	if !present {
  		return
  	}
  	b.logf("broker: %s names a certificate in use (issuer=%q, serial=%s); revoking it", q.origin, q.issuer, q.serial)
  	if _, err := b.Revoke(ctx, RevokeRequest{Issuer: q.issuer, Serial: q.serial, Origin: q.origin}); err != nil {
  		b.logf("broker: revoking a certificate its CA revoked (%s): %v; it is refused at every use anyway", q.origin, err)
  		b.pend(q)
  	}
  }

  // pend keeps q for RetryPending; RetryPending requeues every pending entry
  // (port49d calls it after each CRL poll).
  func (b *Broker) pend(q queuedRevoke)
  func (b *Broker) RetryPending()
  ```

  (`pend` and `RetryPending` hold a map under `b.mu`, keyed by issuer and serial. `sayOnce` is a
  per-key, per-window line limiter under `b.mu`. `queueOnce sync.Once` and `revokeQueue chan
  queuedRevoke` are new unexported `Broker` fields.)

  Add to `Broker`:

  ```go
  	// CertStatus answers a certificate chain's revocation status (spec
  	// §5.1.4; decision 33): nil checks nothing, port49d's `disabled: true`.
  	// OnUnavailable is "refuse" or "allow", for a status it cannot establish.
  	CertStatus    StatusChecker
  	OnUnavailable string
  ```

  In `tokens`, after the mark check and before the body is read:

  ```go
  	statusCtx, cancelStatus := context.WithTimeout(r.Context(), holdTimeout)
  	ref := b.certRefusal(statusCtx, r.TLS, cred)
  	cancelStatus()
  	if ref != nil {
  		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: ref.Reason,
  			Principal: principal, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
  		writeRefusal(w, ref)
  		return
  	}
  ```

  with

  ```go
  // writeRefusal answers a status refusal: a verdict closes the connection;
  // an unavailable status keeps it, says when to retry, and ends nothing.
  func writeRefusal(w http.ResponseWriter, ref *BindRefusal) {
  	if ref.RetryAfter > 0 {
  		w.Header().Set("Retry-After", strconv.Itoa(ref.RetryAfter))
  	} else {
  		w.Header().Set("Connection", "close")
  	}
  	writeError(w, ref.Status, ref.Error, ref.Detail)
  }
  ```

  Do the same in `refresh`, where Task 7 left the comment: record `refresh deny`, count
  `SessionRefreshes{outcome="refused"}`, and answer with `writeRefusal`.

- [ ] **Step 4: The listener, before bind** (pre-flight I1). In `listen.go`, add to `Listener`:

  ```go
  	// Status answers a certificate chain's revocation status before the
  	// connection binds (spec §5.1.4): a refusal is answered, recorded
  	// (Refused) and closed while the connection is still charged to its
  	// source, so a revoked certificate never holds a slot or evicts its
  	// owner's connections. port49d sets it to Broker.BindStatus; nil checks
  	// nothing.
  	Status func(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal
  ```

  In `handshake`, after `Identity` and **before** `l.bind`, add:

  ```go
  		if l.Status != nil {
  			if ref := l.Status(cs, principal, cred); ref != nil {
  				l.m.BrokerConnectionEvents.WithLabelValues("revoked_refused").Inc()
  				l.answerRefused(tc, ref.Status, api.Error{Error: ref.Error, Detail: ref.Detail}, ref.RetryAfter,
  					principal, cred, ref.Reason)
  				return
  			}
  		}
  ```

  Then:
  - **Generalise.** Turn 7a's `answerRevoked(tc, rv, principal, cred)` into `answerRefused(tc, status
    int, body api.Error, retryAfter int, principal string, cred store.Credential, reason
    decision.Reason)`, setting `Retry-After` when non-zero. The mark path in `bind` passes `401`,
    `revokedError(rv)`, `0` and `decision.CredentialRevoked`.
  - **`Refused`.** It takes the reason; update port49d's setter (`Broker.RefusedAtBind`) to record it.
  - **`HoldsCert`.** Add it:

  ```go
  // HoldsCert reports whether a held connection was made with certKey.
  func (l *Listener) HoldsCert(certKey string) bool {
  	l.mu.Lock()
  	defer l.mu.Unlock()
  	for _, conns := range l.held {
  		for _, c := range conns {
  			if c.certKey == certKey {
  				return true
  			}
  		}
  	}
  	return false
  }
  ```

  Add `HoldsCert(certKey string) bool` to `ConnCloser`, and to 7a's `fakeConns`.

- [ ] **Step 5: The agent.** Task 8 already keeps the session on a `503`. Add an agent test that a
  `503 certificate_status_unavailable` at `Connect` (a `port49 login` during an outage) reports "try
  again", and that the next `Connect` after the status returns succeeds.

- [ ] **Step 6: Run them.** `go test ./internal/broker/... ./internal/agent/ -count=1 -race` → PASS.
  Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 7: Commit.**

  ```bash
  git add internal/broker internal/agent
  git commit -m "feat(broker): refuse a revoked or unestablished certificate before it binds, at mint and refresh

  The chain's status is checked before bind, so a revoked certificate never holds a slot or
  evicts its owner. A revoked leaf is answered credential_revoked and revoked through Revoke
  from a bounded queue; a revoked intermediate or a hold refuses without a mark. A status that
  cannot be established is 503 certificate_status_unavailable with Retry-After (the record
  trust_domain_unresolved), ending no session, unless on_unavailable is allow. A store error
  defers a CRL entry rather than marking it.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 11: port49d configures certificate status, required with a broker

**Files:**
- Modify: `internal/config/config.go` (`BrokerConfig.CertificateStatus`, `CertificateStatusConfig`;
  `Load`'s checks)
- Modify: `cmd/port49d/main.go` (the checker: built, loaded, run, wired; the start line)
- Modify: `cmd/port49d/broker_test.go` (`brokerConfig`, `writeRunConfig`),
  `internal/config/broker_test.go`, `internal/config/config_test.go` (its inline broker blocks),
  `tests/lab/slice/broker.yaml`, `tests/lab/quarantine/broker.yaml`, `tests/lab/inventory_test.go`
  (its broker blocks): `certificate_status: {disabled: true}`
- Test: `internal/config/broker_test.go`, `cmd/port49d/certstatus_test.go` (new)

**Interfaces:**
- Produces:
  - `config.CertificateStatusConfig`:
    ```yaml
    certificate_status:
      disabled: false                # true: no checking, said at every start
      crls: [{name: corp_issuing, url: http://pki.example.com/corp.crl,     # or file: /path
              issuer_file: /etc/port49/corp-issuing-ca.pem}]                  # required: the CRL's signer
      ocsp: {responder: http://ocsp.example.com, use_aia: false, timeout: 2s, hash: sha256}   # hash: sha256 | sha1
      refresh_interval: 10m          # 1m..24h
      on_unavailable: refuse         # refuse | allow
    ```
  - `func (c CertificateStatusConfig) Checker(anchor *x509.Certificate, stateDir string) (certstatus.Config, error)`:
    reads each `issuer_file` (one PEM certificate) and refuses one that is neither the anchor nor
    signed by it (`CheckSignatureFrom(anchor)`), naming the source (pre-flight C1). The kept lists
    go in `stateDir`, the directory holding `broker.revocations_file` (pre-flight I8).

- [ ] **Step 1: The config's tests.** In `internal/config/broker_test.go`, add
  `  certificate_status: {disabled: true}` to `brokerBlock`, and test the following, each refusal
  naming its key:
  - the block absent refuses (`broker.certificate_status`);
  - `disabled: true` beside a source refuses;
  - a block with neither a CRL nor OCSP refuses;
  - a CRL with both or neither of `file` and `url` refuses;
  - a CRL without `issuer_file` refuses;
  - `ocsp.hash: md5` refuses (`sha256` default, `sha1` allowed);
  - a `url` that is not `http` or `https` refuses;
  - a name off `^[a-z][a-z0-9_]{0,63}$`, or a duplicate name, refuses;
  - `refresh_interval: 30s` and `25h` refuse;
  - `ocsp.timeout: 50ms` and `11s` refuse;
  - an OCSP block with neither `responder` nor `use_aia` refuses;
  - `on_unavailable: maybe` refuses;
  - a well-formed block loads, with defaults `refresh_interval` 10m, `ocsp.timeout` 2s and
    `on_unavailable` `refuse`.

- [ ] **Step 2: port49d's tests.** Create `cmd/port49d/certstatus_test.go`. Besides the cases below:
  - `Checker(anchor, dir)` refuses an `issuer_file` that another CA signed;
  - a run whose CRL URL hangs prints its TACACS+ listening line before the first fetch returns
    (pre-flight I8);
  - a second run, with the URL down, serves from the kept list.
  - **A file CRL.** With a `testpki` CA as the broker's anchor and a CRL file naming the lab
    client, start `run` (as 7a's `TestRunRestoresRevocationsBeforeTheBrokerServes` does) and check
    that:
    - the start line names the CRL and its next update;
    - a TLS connection with that client is answered `401 credential_revoked`.
  - **`disabled: true`.** The start line says certificate status is disabled.
  - **A stale CRL.** With `on_unavailable: refuse`, a mint is answered `401 trust_domain_unresolved`.

- [ ] **Step 3: Run them to see them fail.** `go test ./internal/config/ ./cmd/port49d/ -run 'Certificate|CertStatus' -count=1`
  Expected: FAIL.

- [ ] **Step 4: The config.** In `config.go`:

  ```go
  // CertificateStatusConfig is broker.certificate_status (spec §5.1.4;
  // decision 33): where the broker learns a client certificate's revocation.
  // Required with a broker: Disabled is the explicit choice not to check.
  type CertificateStatusConfig struct {
  	Disabled bool `yaml:"disabled"`
  	CRLs     []struct {
  		Name string `yaml:"name"`
  		File string `yaml:"file"`
  		URL  string `yaml:"url"`
  	} `yaml:"crls"`
  	OCSP *struct {
  		Responder string        `yaml:"responder"`
  		UseAIA    bool          `yaml:"use_aia"`
  		Timeout   time.Duration `yaml:"timeout"`
  	} `yaml:"ocsp"`
  	RefreshInterval time.Duration `yaml:"refresh_interval"`
  	OnUnavailable   string        `yaml:"on_unavailable"`
  }
  ```

  Then:
  - add `IssuerFile string `yaml:"issuer_file"`` to the CRL entry and `Hash string `yaml:"hash"`` to
    the OCSP block;
  - add `CertificateStatus *CertificateStatusConfig `yaml:"certificate_status"`` to `BrokerConfig`
    (comment: "required (plan 7b); see CertificateStatusConfig");
  - validate it in `Load`'s broker block as Step 1 tests, applying the defaults in place;
  - add `Checker(anchor, stateDir)`, mapping it onto `certstatus.Config` (`OCSP` nil when absent;
    `Hash` `crypto.SHA256` or `crypto.SHA1`).

- [ ] **Step 5: The wiring** (pre-flight I8). In `cmd/port49d/main.go`, after `buildBroker` and the
  revocations restore, before any listener binds, build the checker and put the kept lists in force.
  That is local and fast, so it never delays device AAA:

  ```go
  	var checker *certstatus.Checker
  	if brk != nil {
  		cs := cfg.Broker.CertificateStatus
  		if cs.Disabled {
  			fmt.Fprintln(stderr, "port49d: broker: certificate status checking is disabled "+
  				"(broker.certificate_status.disabled): a certificate revoked at its CA keeps minting until "+
  				"`port49 revoke --cert`")
  		} else {
  			ccfg, err := cs.Checker(anchorCert, filepath.Dir(cfg.Broker.RevocationsFile))
  			if err != nil {
  				stopSpool()
  				<-spoolDone
  				return fmt.Errorf("broker.certificate_status: %w", err)
  			}
  			checker = certstatus.New(ccfg, time.Now, m,
  				func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) })
  			checker.OnNewEntry(brk.OnCRLEntry)
  			for _, err := range checker.LoadPersisted() {
  				fmt.Fprintf(stderr, "port49d: broker: certificate status: %s\n", printsafe.Line(err.Error(), 300))
  			}
  			brk.CertStatus, brk.OnUnavailable = checker, cs.OnUnavailable
  		}
  	}
  ```

  (`anchorCert` is the one certificate `broker.LoadTLS` read from `client_ca_file`; give
  `buildBroker`'s caller access to it.) After the listeners bind and "listening" is said, start the
  network side and the revocation queue, joined at shutdown as the fetcher is (plan 6b, F8):

  ```go
  	if checker != nil {
  		go brk.RunRevocationQueue(ctx)
  		go checker.Run(ctx) // the first fetch happens now, never before device AAA is up
  		go func() { // pending CRL revocations, retried each interval (pre-flight I9)
  			t := time.NewTicker(cfg.Broker.CertificateStatus.RefreshInterval)
  			defer t.Stop()
  			for {
  				select {
  				case <-ctx.Done():
  					return
  				case <-t.C:
  					brk.RetryPending()
  				}
  			}
  		}()
  		fmt.Fprintf(stderr, "port49d: broker: certificate status from %s; a status that cannot be established is %s\n",
  			checker.Describe(), map[string]string{"refuse": "refused (503, retried)", "allow": "allowed, alarmed"}[
  				cfg.Broker.CertificateStatus.OnUnavailable])
  	}
  ```

  Where the listener is built, set `bl.Status = brk.BindStatus` beside `bl.Refused`.

- [ ] **Step 6: The fixtures.**
  - **Where the key goes.** Add `CertificateStatus: &config.CertificateStatusConfig{Disabled: true}`
    to `brokerConfig`, and `  certificate_status: {disabled: true}` to `writeRunConfig`'s broker block,
    the two lab broker YAMLs, `inventory_test.go`'s broker blocks and `config_test.go`'s inline broker
    blocks.
  - **The lab's rewrites** (pre-flight M20). `tests/lab/harness_test.go`'s `privatePolicy` and
    `tests/lab/private_policy_unit_test.go` rewrite only `policy_file`, `inventory_file` and
    `revocations_file` lines. Confirm the slice block they copy carries `certificate_status` from the
    YAML, and add it to the unit test's literal broker block.
  - **Task 12.** The lab's slice and revoke runs check no certificate status, and Task 12 does not
    need it.

- [ ] **Step 7: Run them.** `go test ./internal/config/ ./cmd/port49d/ -count=1 -race`, `go vet -tags lab ./tests/lab/`
  → PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 8: Commit.**

  ```bash
  git add internal/config cmd/port49d tests/lab/slice/broker.yaml tests/lab/quarantine/broker.yaml tests/lab/inventory_test.go
  git commit -m "feat(port49d): broker.certificate_status, required with a broker

  CRLs by file or URL and an OCSP responder, polled every refresh_interval; on_unavailable
  refuse (default) or allow; disabled: true the explicit choice not to check, said at every
  start. A source that fails at start never stops the daemon.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 12: (lab, on beehive) L34 and L2 on five images, and the refresh and grace window end to end

**Files:**
- Create: `tests/lab/slice/session-policy.yaml`: the slice policy with `max_session_age: 6m` on
  `network_admin`
- Create: `tests/lab/session_test.go` (`//go:build lab`): `TestSessionLifetime`
- Create: `tests/lab/l2_test.go` (`//go:build lab`): `TestL2Truncation`
- Create (by the run): `tests/lab/results/L34-<platform>.md`, `session-<platform>.md`,
  `L2-<platform>.md` (rewritten); redacted captures under `tests/lab/evidence/`

**Interfaces:**
- Consumes: the lab harness (`eachPlatform`, `derivedConfig`, `startDaemonWith`, `(*lab).shell`,
  `labShell.runOrEnd`, `(*lab).loginWithin`, `(*lab).waitForRecords`, `(*lab).result`); 7a's
  `revokeAgent` (whose stop treats an exited agent, ESRCH, as done) and `agentEnded`; the slice's PKI
  and broker block; `bin/port49 refresh` (Task 8).

**L34 is new; L2 stays open until every image in its row is measured.** L34's claim is the warning's
premise, opened by Task 1. L2's clauses still open are the truncation length, IOS-XE and the N9Kv.

- [ ] **Step 1: The policy.** `tests/lab/slice/session-policy.yaml` is `tests/lab/slice/policy.yaml`
  with `max_session_age: 6m` added to the `network_admin` role and its header comment saying so
  ("plan 7b's session run: a ceiling short enough to wait out, with room either side of a 2m
  warning"; pre-flight M9).

- [ ] **Step 2: `TestSessionLifetime`.** For each platform it:
  1. **Starts port49d** with the slice's broker block (`policy_file` pointed at `session-policy.yaml`)
     and a session block of `ceiling_warning: 2m`, `grace_window: 2m` and
     `ceiling_warning_platforms: [arista_eos, cisco_nxos, cisco_iosxe, juniper_junos]`.
     - The platform list puts the unmeasured platforms on the allow-list for the measurement (Ruling
       4).
     - The session block is merged into the derived config's `session:` key if it has one, never
       appended as a second (pre-flight M9).
  2. **Runs `port49 login`, then waits 4m10s.** The 6m ceiling is now under 2m away, from the
     connection's handshake.
  3. **Login inside the warning.** It mints, then logs in over SSH with the token and records:
     - the device's text before the first prompt (the session reply's `server_msg`, L34's session
       clause);
     - the `authorize_session` record's `server_msg`.
  4. **A command inside the warning.** It runs `show version` and records the device's text around
     the command output (the per-command clause), and whether the output appeared.
  5. **The refresh.** It runs `port49 refresh`, then `show version` again within the next 3m, and
     records that no warning is sent and the output appears. The refresh's output names one extended
     session (on Junos, also "not reached").
  6. **Past the ceiling.** It waits until 6m after the refresh, plus 10 s, and runs `show version`
     on a per-command platform: denied `session_expired`, the device's text recorded (L2's FAIL
     display).
  7. **Resumed in the grace window.** Within the 2m window, `port49 refresh`, then `show version`:
     permitted.
  8. **Past the grace window.** It waits out the ceiling and the window, plus 10 s, and runs `show
     version`: denied, the record `session_expired`, the context gone (`refresh` names it past
     grace).
  9. **The notes.** It writes `L34-<platform>.md` for steps 3–5 (claim: the L34 row's), and
     `session-<platform>.md` for the whole run (claim: decision 33's session clause). A step whose
     device text is not found is written as "not observed", never as a pass.

  On Junos, steps 4 and 6–8 measure only what the records say: the session reply at login is the one
  `server_msg` the device is ever sent (decision 21), and the note says so. Stop every agent with 7a's
  `revokeAgent` stop.

- [ ] **Step 3: `TestL2Truncation`.** For each platform it:
  - restarts port49d on the standing lab config, with `  deny_message_length: N` inserted under
    `lab:`, for N in 64, 128, 200, 255, 256, 512 and 1000;
  - on EOS, NX-OS and IOS-XE, logs in with a seeded token and runs a command the lab denies (its
    `deny_prefixes`);
  - on vJunos-router and vSRX, which never authorize a command (decision 21), adds `  deny_session:
    true` under `lab:` so the session authorization itself fails with the padded message, and records
    what the login prints (pre-flight I12);
  - records what the device printed and the longest prefix of the padded message it shows, read off
    the counting pattern.

  **Junos past 255 bytes.** On Junos the owner's production prior is that a reply over 255 bytes
  locked the user out. Before N=256, 512 and 1000 there, the run proves break-glass logs in (the
  harness's break-glass login), and it stops at the first N that leaves the device refusing
  break-glass, recording that as the finding. If the session denial cannot be made to carry the
  message at all, the note says "not measurable: session-only (decision 21)", and L2's Junos clause
  stays open (spec §15 rule 3).

  It then rewrites `L2-<platform>.md` with the display clause (displayed, or not, with the device's
  text) and the truncation length, keeping the earlier note's output-modifier observation.

- [ ] **Step 4: Pin, build, arm the watchdog, run.** As "Running the lab" says, one platform at a
  time:
  ```
  PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run 'TestSessionLifetime|TestL2Truncation' -count=1 -timeout 90m -v
  ```
  then `nxos`, `iosxe`, `vjunos` and `vsrx`. Read every note. A device that turns a permit carrying
  `server_msg` into anything but a permit is a finding for Task 13, not a test failure to retry.

- [ ] **Step 5: Evidence.** Copy the raw captures to the main checkout, run `make evidence`, confirm
  the labpcap audit, and remove the worktree.

- [ ] **Step 6: Commit.**

  ```bash
  git add tests/lab/slice/session-policy.yaml tests/lab/session_test.go tests/lab/l2_test.go \
    tests/lab/results/L34-*.md tests/lab/results/session-*.md tests/lab/results/L2-*.md tests/lab/evidence/
  git commit -m "test(lab): L34 and L2 on five images; the refresh and grace window end to end

  <what the notes say, per image: whether a permit's server_msg is shown and still permits;
  the truncation length; the warning, the refresh, the ceiling, the grace window>. Run at <sha>.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

  (Write the message from the notes.)

---

### Task 13: Close what the lab measured, and write plan 7b as built

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L2 and L34 Status; §5.6's warning
  sentence; decision 33 where the lab changes it)
- Modify: `internal/platform/warning.go` only if L34 finds a platform whose permit carrying
  `server_msg` is not a permit (with its test and a citation of the note)
- Modify: `docs/superpowers/plans/README.md` (status line; "Plan 7b — As built")

- [ ] **Step 1: L34, and the allow-list.**
  - **The allow-list.** For each platform whose note shows the warning displayed and the reply still
    a permit, add it to `ceilingWarningOn` in `internal/platform/warning.go`, with a comment citing
    the note, test it, and commit that as `feat(platform): the ceiling warning on <platforms> (L34)`
    before the docs. A platform that does not show it, or does not treat the reply as a permit, stays
    off the list; §5.6's text says its operators are warned only through `port49 token`, citing the
    note.
  - **The row.** If every platform in the row was measured, set its Status to `closed — measured
    <date>; tests/lab/results/L34-<platform>.md, …`, with one line per platform: shown or not shown,
    still a permit.
- [ ] **Step 2: L2.** With every image measured, Junos included (Task 12's session-denial path), set
  L2's Status to closed with the display and the truncation length per platform. Otherwise list what
  is measured and leave it open (spec §15 rule 5: a row with one platform measured and others open
  stays open).
- [ ] **Step 3: The as-built section.** Under "Plan 7", after "Plan 7a — As built", add "### Plan 7b —
  As built". It records:
  - the branch and the ledger;
  - what differs from this plan's text, task by task;
  - the final review and its fix wave;
  - the rulings as made (decision 33);
  - D-7b-1's answer if the owner gave one;
  - Task 12's outcome per image;
  - the operator notes, as amended;
  - "Carried, for later plans": to 7c, the HTTP revocation and API rights over `RefreshSession`'s
    self-only rule; to 7g, the `staleness_ceiling` default and the scheduled refresh; to 7h, the
    OIDC refresh (`prompt=login`, `auth_time` from the assertion, `sid` re-indexing); to 9, the
    hardware key's touch on refresh (and a PKCS#1 v1.5 mapping for tokens without PSS); to 12, the
    Junos `idle-timeout` classes rendered from a per-role ceiling rather than the default, and `port49
    policy diff` reporting a changed ceiling (pre-flight M11).
- [ ] **Step 4: The status line.** "7b written 2026-10-01 … executed <date> … merged …", as 7a's reads.
- [ ] **Step 5: Check and commit.** `make test && make vet`.

  ```bash
  git add docs/design docs/superpowers/plans/README.md
  git commit -m "docs: close L34 (and L2) as measured; plan 7b as built

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

## Operator-facing notes (for the pull request body)

- **New: `max_session_age` per role.**
  - It is a duration (at least `1m`) or `never`. A principal's session on a device ends at the
    least of its roles' (a role naming none takes `session.max_session_age_default`). `port49
    explain` shows it.
  - Shortening a role reaches live sessions at the next policy refresh. Lengthening it, or
    `never`, takes effect at each operator's next `port49 refresh` or login.
- **New: `port49 refresh`.**
  - It re-authenticates on your held broker connection and extends every live device session your
    policy still grants: no reconnect, and the candidate configuration stays intact. `port49 login`
    does the same when you are already logged in.
  - It prints one line per device: extended to when, revoked by the policy, past the grace window
    (log in again there), not extended this time (run it again), or on a platform it cannot reach
    (Junos keeps its own session).
  - One refresh per connection per 10s.
  - With today's PEM key files a refresh proves you hold the key file, not that you are at the
    keyboard, and a script that runs `port49 refresh` in a loop keeps sessions alive indefinitely: the
    ceiling then measures nothing. Keep key files where only their owner can read them; a hardware
    key (plan 9) adds the touch.
- **The warning.**
  - Within `session.ceiling_warning` (default 30m) of the end, permitted commands carry `port49:
    session ends in Nm - run 'port49 refresh'`. This happens only on the platforms the L34 lab run
    found show it and still permit, plus any you add with `session.ceiling_warning_platforms` (at your
    own risk, unmeasured).
  - `port49 token` prints the same on stderr for every platform, `--json` included.
  - `0s` turns the server_msg warning off.
- **Past the end.**
  - Commands are refused `session expired - run 'port49 refresh' (or 'port49 login') within Nm to
    resume` for `session.grace_window` (default 10m), and a refresh in that window resumes them.
  - After it the session is deleted: `session ended - get a new token and log in again`.
- **New required key: `broker.certificate_status`.**
  - **What to name.** Your CA's CRLs (`file:` or `url:`), each with `issuer_file:`, the CA
    certificate that signs it. That certificate must be your `client_ca_file` anchor or signed by
    it. Add an OCSP `responder` (or `use_aia: true`) if you have one, with `hash: sha1` for a
    responder that knows no SHA-256 CertID. Or write `disabled: true` to choose not to check (said at
    every start).
  - **What is refused.** A certificate a CRL or OCSP revokes, or one under a revoked issuing CA, is
    refused at login and at every mint.
  - **What is marked.** If the certificate holds anything (a connection, a device session, an unspent
    token), port49d revokes it as `port49 revoke --cert` would: see `port49 revoke --list`, origin
    `crl …`. A `certificateHold` entry is refused while listed and never marked.
  - **What is never trusted.** A CRL that does not verify against its `issuer_file` is never used,
    and nor is one that is scoped (partitioned, delta, unknown critical extension); check
    `port49_crl_loads_total{outcome="refused"}`.
  - **Persistence.** Verified CRLs are kept beside `revocations_file` (`crl-<name>.der`), so a restart
    during a publisher outage keeps serving them until their next update. Back them up with the rest.
- **`on_unavailable: refuse` (the default).**
  - **What happens.** A CRL past its next update, or an OCSP responder down, answers new logins,
    mints and refreshes for that issuer `503`, telling the agent to try again. No agent session ends,
    live device sessions continue to their ceiling, and break-glass is unaffected.
  - **Retries.** port49d retries a failed CRL from 30s with backoff.
  - **Alerts.** `time() - port49_crl_next_update_timestamp_seconds > -3600` (an hour of warning), and
    `port49_cert_status_unavailable_total`.
  - **`allow`.** It keeps logins working through an outage, and lets a certificate revoked during it
    in until the CRL returns (owner decision D-7b-1).
- **Clocks.** CRL and OCSP freshness follow port49d's clock, so an NTP step forward can make a fresh
  list stale. The `port49 token` warning follows the laptop's clock.
- **New metrics:**
  - `port49_session_refreshes_total{outcome}`, with `outcome` per context `extended`, `revoked`,
    `past_grace`, `not_judged`, and per refresh `refused`, `store_error`, `too_soon`;
  - `port49_ceiling_warnings_total`;
  - `port49_cert_status_checks_total{source,result}`;
  - `port49_crl_loads_total{crl,outcome}`;
  - `port49_crl_next_update_timestamp_seconds{crl}`;
  - `port49_cert_status_unavailable_total`.
- **New records:**
  - `refresh permit grants_matched` for each session a refresh extended, with `auth_time` and
    `session_expires`;
  - `refresh deny session_expired` for one past its grace window;
  - `refresh deny trust_domain_unresolved` for a refresh signature that did not verify, or a status
    that cannot be established;
  - `refresh deny credential_revoked` for a revoked caller;
  - `mint deny session_expired` per device whose session is already over;
  - `mint deny trust_domain_unresolved` when a certificate's status cannot be established;
  - `unreached: true` on refresh records for session-only platforms.
- **API:**
  - `POST /v1/refresh/challenge` and `POST /v1/refresh`, on the held connection only, with the
    errors `refresh_challenge_missing` (401) and `refresh_too_soon` (429).
  - `503 certificate_status_unavailable` with `Retry-After` when status cannot be established.
  - `GET /v1/config` gains `ceiling_warning_seconds`.
  - Mint items gain `session_expires_at`, and a `session_expired` item carries a detail.

## Self-review against the spec

- **§5.6 session lifetime:**
  - per-role and minimum composition: Tasks 2, 3;
  - "`never` MUST be expressible": Task 2;
  - the warning, configurable and long enough: Task 6, with the agent's warning in Task 8;
  - grace: Tasks 4, 6, 7;
  - "Refresh MUST NOT extend a session whose principal has lost the grant": Task 7. It extends only
    what `refreshContext` judged and kept, and names everything else.
  - "a fresh authentication event … the broker's verification time": Task 7;
  - "re-authentication does not require reconnecting": Task 7 moves the connection's clock;
  - teardown row 3: Task 6.
- **§5.1.4.** CRL or OCSP by issuer and serial: Tasks 9–11, feeding decision 32's marks (Task 10).
  - **CRLs.** They are verified against a configured issuer before any use. The whole chain is
    checked (pre-flight C1, I2, I3).
  - **OCSP.** It is held to RFC 6960 (C2).
  - **`unreached`.** The `refresh` records' field, carried from 7a: Task 5.
- **§5.7.** No reason code added. `session_expired`, `trust_domain_unresolved` and
  `credential_revoked` gain their meanings in Task 1, before the code (Tasks 3, 7, 10).
- **§15.** L34 is opened before the warning is built (Task 1) and measured (Task 12).
  - **The warning's allow-list.** It is empty until Task 13 fills it from L34's notes; the lab run
    measures through the operator's list.
  - **L2.** Its open clauses are measured in Task 12, Junos through a session denial. If they cannot
    be measured, the clause stays open.
  - **Assertions.** No doc asserts what L34 has not measured.
- **Design §7** (revocation validated by the broker): Ruling 8 makes it the default and an explicit
  opt-out. **§12** (failure matrix): Task 1. **§17** (the surface): Task 1, Task 7.
- **Carried:**
  - from 7a: the refresh records' `unreached` (Task 5) and CRL/OCSP feeding the certificate marks
    (Task 10);
  - from 4b: plan 7's refresh scheduling stays 7g's, as the roadmap says;
  - from plan 4's "Hands to plan 7": `max_session_age` per role (Task 2).
- **Hard rules:**
  - every key and label is snake_case;
  - no metric names a device, principal or certificate (`crl` is a configured source name);
  - the nonce, the signature and the exporter value never reach a log (Task 7's test checks the
    nonce);
  - a peer's text goes through `printsafe.Line`.
- **Placeholder scan.** Task 7's test helpers (`postOn`, `liveContextAt`, `loadPolicy`) and Tasks
  2, 5 and 6's fixtures name the existing helpers to follow or say exactly what to add. Task 12's
  steps name each measurement and what the note records.
- **Type consistency:**
  - `SessionAge.Of` (Task 2), used in Tasks 3 and 5;
  - from Task 4: `ContextPolicy.MaxSessionAge`, `ContextRefresh.SessionAge`, `GraceCutoff`,
    `ExpectRev`, `ErrPastGrace` and `DeleteContextIf`. Tasks 5, 6 and 7 use them;
  - from Task 5: `refreshContext`'s outcome. Task 7 uses it;
  - from Task 7: `api.Refresh*` (`Sessions` with `Outcome`), and the codes `refresh_challenge_missing`
    and `refresh_too_soon`. Task 8 uses them;
  - from Task 9: `certstatus.Result` (`Depth`, `Hold`), `Checker` (`LoadPersisted`, `Run`) and
    `CRLSource.Issuer`. Tasks 10 and 11 use them;
  - from Task 10: `BindRefusal` (`Status`, `RetryAfter`), `HoldsCert`, `Refused`'s reason,
    `RunRevocationQueue` and `RetryPending`. Task 11 uses them;
  - from Task 11: `CertificateStatusConfig.Checker(anchor, stateDir)`. Task 11's wiring uses it.
