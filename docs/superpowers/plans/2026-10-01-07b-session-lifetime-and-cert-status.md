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
§13 as decision 33 by Task 1. Decision D-7b-1, under "Decisions for Ryan", names the one default
the owner should confirm. Both of its options are built, so no task waits on it.

1. **A role's `max_session_age` is a duration of at least 1m, or `never`.** A principal's ceiling
   on a device is the least across the roles that compose there. A role that names none takes
   `session.max_session_age_default`. The result is `never` only when every role says so. The
   default stays a finite duration: a forgotten key never becomes `never`. The broker's held
   connection keeps its own ceiling at the default (decision 17), so a role longer than the default
   still re-authenticates the connection at the default, by refresh or reconnect. Tasks 2, 3.
2. **A device whose ceiling has already passed is refused per item.** A mint whose connection
   authenticated longer ago than the device's ceiling is refused for that device, `session_expired`
   (a §5.7 meaning added by Task 1). A token for a context born expired would only be a login
   refused at its first command. The answer tells the operator to run `port49 refresh`. Task 3.
3. **A policy edit may shorten a live context's ceiling, never lengthen it.** The policy refresh
   writes `session_expires = auth_time + the policy's ceiling` only when that is earlier, or when
   the context had none. A longer ceiling, or `never`, applies from the next login or refresh,
   because only a fresh authentication event moves a session's clock (§5.6, decision 17). Tasks 4,
   5.
4. **The warning rides on permits, within `session.ceiling_warning`.** The default is 30m: the spec
   asks for "long enough to complete a change", and the example's 10m is not. `0s` turns it off.
   - **What carries it.** The `server_msg` of every permitted session and command authorization
     reply, while `session_expires` is that close. The text is plain ASCII: `port49: session ends
     in 9m - run 'port49 refresh'`.
   - **Provisional on L34.** Whether a device shows `server_msg` on a permit, and still permits, is
     L34 (opened by Task 1). A platform L34 finds treating it as anything but a permit is switched
     off in `platform.CeilingWarning` by Task 13.
   - **A second warning.** `port49 token` warns on stderr from the item's `session_expires_at`, so
     an operator on a device that does not show the message is warned anyway.

   Tasks 6, 8.
5. **Past the ceiling and inside the grace window, a context is denied and kept; past the grace
   window it is deleted at its next authorization.** A refresh inside the window resumes it. A
   refresh past it never does: the store refuses that extension, `store.ErrPastGrace`. The default
   window stays 10m, and the refusal's message names `port49 refresh` inside it and `port49 token`
   and a new login after it. Tasks 4, 6, 7.
6. **A refresh is a signed nonce over the held connection, bound to that connection.**
   - **The exchange.** `POST /v1/refresh/challenge` issues 32 random bytes, good for 60s, once, and
     only on the connection that asked. A new challenge replaces the old.
   - **What is signed.** `"port49 session refresh v1\x00" ‖ nonce ‖ EKM`, where EKM is 32 bytes of
     the TLS exporter (`EXPORTER-port49-refresh`). A nonce relayed to another connection cannot be
     answered.
   - **The algorithm.** It is fixed by the key: ECDSA with SHA-256, RSA-PSS with SHA-256, Ed25519.
   - **Before verifying.** The broker checks the certificate again (`Identity`), the marks, and the
     certificate's status.
   - **On success.** `auth_time` is the broker's verification time (spec §5.6: "the one place the
     broker's clock is the source"), and the connection's own session clock moves to it.
   - **When it runs.** The agent refreshes when asked, by `port49 refresh` or by `port49 login`
     while it holds a session (the spec's t+7h55 example), and once right after a new `port49 login`
     connects. It never refreshes on its own: the ceiling measures time since a person authenticated
     (§5.6).

   Tasks 7, 8.
7. **A refresh carries the policy in force first.** Each of the principal's live contexts is
   re-resolved and written as a policy refresh writes it. A withdrawn grant is revoked, never
   extended (§5.6: "Refresh MUST NOT extend a session whose principal has lost the grant"). Only
   what is left is extended. A context on a session-only platform is extended in the store and
   named unreached (decision 21). Each extension is a `refresh` record carrying `session.auth_time`
   and `session.session_expires`. The same records name `session.unreached`, the field 7a carried to
   7b for the policy refresh too. Tasks 5, 7.
8. **Certificate status is required configuration.** With a `broker:` block,
   `broker.certificate_status` names at least one CRL or an OCSP responder, or says `disabled: true`.
   `disabled` is accepted and said at every start, because design §7 has the broker validate
   "revocation", and an operator must choose not to. D-7b-1 asks the owner to confirm. Tasks 10, 11.
9. **A CRL is trusted by its signature alone.**
   - **Where from.** It is read from a file or fetched over `http` or `https` (no redirects, 16 MiB
     cap, 30s).
   - **Which issuer.** It is used for a leaf only when its issuer name is the leaf's issuer's and it
     verifies against the certificate that verified the leaf: `chain[1]`, the anchor itself for a
     one-level chain.
   - **Freshness.** It is fresh until its `NextUpdate`; one with none is fresh for
     `refresh_interval`. A delta CRL is refused.
   - **OCSP.** It asks `ocsp.responder`, or, with `ocsp.use_aia: true`, the leaf's own responder,
     within `ocsp.timeout` (2s). The answer must be signed for the leaf's issuer
     (`ocsp.ParseResponseForCert`). Each answer is cached until its `NextUpdate`, at most an hour.
   - **Precedence.** A CRL that names the serial is final. Otherwise a fresh CRL that does not name
     it is good, and an OCSP answer decides where no fresh CRL covers the issuer.

   Task 9.
10. **A status that cannot be established is refused (`on_unavailable: refuse`, the default).** This
    covers a stale CRL, an unreachable responder, and an issuer no source covers. It is refused at
    bind, at mint and at refresh, `trust_domain_unresolved`, with a detail naming the source (a
    §5.7 meaning added by Task 1). `allow` admits the certificate, counts it and says it once per
    source per 10m. Live sessions are untouched either way: the daemon never reads certificate
    status (decision 13). D-7b-1. Tasks 9, 10.
11. **A certificate the CRL or OCSP revokes is refused as 7a refuses a mark.**
    - **At bind.** It is answered `401 credential_revoked` and closed, never held.
    - **At mint and refresh.** It is refused `credential_revoked`.
    - **Reaching what it holds.** When a CRL load adds an entry, the broker revokes that certificate
      with 7a's `Broker.Revoke` (origin `crl <name>`) wherever it is still present: a held
      connection, a live context indexed under it, or an unspent token. Its contexts, tokens and
      connections are reached, and the mark keeps it refused if the CRL later goes stale.
    - **What is not marked.** An entry nothing holds is not marked: the CRL refuses it at its next
      handshake, and marking every entry of a large CRL would grow the revocations file without
      bound. An OCSP `revoked` answer at bind, mint or refresh writes the mark the same way.

    Tasks 10, 11.

**One event meaning and three reason meanings are added** by Task 1, before any code (spec §5.7).
`refresh` also records a session refresh. `session_expired` gains its per-item `mint` and its
`refresh` meanings; `trust_domain_unresolved` gains "status could not be established" and "the
refresh signature did not verify"; `credential_revoked` gains "a CRL or OCSP response names it".
No reason code is added.

## Decisions for Ryan

- **D-7b-1: a certificate whose revocation status cannot be established is refused or allowed, and
  is certificate status mandatory?** Spec §5.1.4 and design §7 say the broker checks revocation, and
  say nothing about a CRL publisher that is down at 3am. This plan rules **refuse** (Ruling 10),
  with **required** configuration that may say `disabled: true` (Ruling 8). Both choices are
  `on_unavailable: refuse | allow` and one required key, so changing the default is a one-line
  constant and a doc line, and no task depends on it. What each costs on a bad day:
  - **refuse (recommended):** a CRL past its `NextUpdate`, or an OCSP responder down, stops every
    new mint and login for the issuers it covers. Live sessions keep working (the daemon never
    reads status), break-glass is untouched, and `port49_cert_status_unavailable_total` and
    `port49_crl_next_update_seconds < 0` alarm before it bites, since CAs overlap their CRLs.
    Nobody holding a revoked certificate gets in while the publisher is down.
  - **allow:** logins continue through a publisher outage, alarmed. A certificate revoked during the
    outage keeps minting until the CRL returns, or until an operator runs `port49 revoke --cert`.

## Revised after the pre-flight review

(Empty until the pre-flight review runs.)

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **Normal day.** port49d says at start `port49d: broker: certificate status from 1 CRL (corp_issuing,
  next update 2026-10-02T06:00:00Z) and OCSP (http://ocsp.example.com); a status that cannot be
  established is refused`. An operator works all day.
- **The warning.**
  - At 11h31m their next command prints `port49: session ends in 29m - run 'port49 refresh'`, on
    the platforms L34 finds show it.
  - `port49 token` also says on stderr `port49: your session on leaf-01 ends at 21:00:00Z (in 29m);
    run 'port49 refresh'`.
- **The refresh.** They run `port49 refresh`, which prints `refreshed: 4 session(s) extended to
  2026-10-02T09:01:00Z; not reached, on a platform that never asks port49 about a command:
  edge-mx01 (alice)`. The next command is permitted with no message, and the candidate configuration
  is intact.
- **Missing the ceiling.** The next command is refused: `port49: session expired - run 'port49
  refresh' within 10m to resume`. They run `port49 refresh` within the grace window and carry on.
- **Missing the grace window.** The command is refused `port49: session ended - get a new token
  ('port49 token') and log in again`. `port49 refresh` says `1 session past its grace window, not
  resumed: leaf-01 (alice); log in again there`.
- **A role tightened at 14:00** (`max_session_age: 1h` for `net-admin`). Every live context whose
  ceiling is later than auth_time+1h is shortened by the policy refresh. Each is one `refresh`
  record, and warnings start at the new time. A role loosened waits for each operator's next
  refresh.
- **3am, the CA's CRL publisher is down and the CRL passes `NextUpdate`.**
  - Every new `port49 login` and `port49 token` for that issuer is refused: `the broker cannot
    establish this certificate's revocation status (CRL corp_issuing is past its next update,
    2026-10-02T06:00:00Z); it mints nothing until it can`.
  - Operators already on devices keep working, and break-glass is unaffected.
  - `port49_crl_next_update_seconds{crl="corp_issuing"}` went negative and
    `port49_cert_status_unavailable_total` climbs.
  - Fix the publisher, or set `on_unavailable: allow` and restart port49d if you decide to accept
    the risk (D-7b-1).
- **A certificate is revoked at the CA.** At the next CRL poll (`refresh_interval`, default 10m),
  port49d says `port49d: broker: CRL corp_issuing names a certificate in use (issuer="CN=Corp
  Issuing CA", serial=3f9a01); revoking it`. That is a 7a revocation, origin `crl corp_issuing`: the
  held connection is closed, contexts marked, tokens deleted, and the `revoke` record names what was
  not reached. `port49 revoke --list` shows the mark.
- **A refresh from a stolen nonce, or on another connection:** `refresh deny trust_domain_unresolved`
  with `the refresh challenge was not answered by this connection's key`; nothing is extended.

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

- [ ] **Step 1: §5.1.4, certificate status as built.** After the paragraph that begins
  "**Revocation by principal or by certificate, as built (plan 7a",
  add:

  ```markdown
  **Certificate status, as built (plan 7b; §13, decision 33).** The broker checks every client
  certificate against the sources `broker.certificate_status` names: CRLs, read from a file or
  fetched over HTTP(S) and polled every `refresh_interval`, and an OCSP responder. A CRL is trusted
  by its signature alone: it is used for a leaf only when its issuer name is the leaf's issuer's and
  it verifies against the certificate that verified the leaf, and only until its `NextUpdate`. A
  delta CRL is refused. An OCSP answer is signed for the leaf's issuer and cached until its
  `NextUpdate`, at most an hour. A CRL that names the serial is final; otherwise a fresh CRL
  covering the issuer, or an OCSP answer, decides.

  A certificate a source revokes is answered `credential_revoked` as its connection binds, as a
  marked one is, and refused at every mint and refresh. When a CRL newly names a certificate
  something still holds (a held connection, a live context indexed under it, an unspent token), the
  broker revokes it as `port49 revoke --cert` does, its origin `crl <name>`, so everything it
  reaches is reached and the mark outlives a CRL that later goes stale. A status that cannot be
  established (a CRL past its next update, a responder that does not answer, an issuer no source
  covers) is refused, `trust_domain_unresolved`, unless `on_unavailable: allow`. Live sessions are
  never affected: the daemon never reads certificate status (decision 13). The configuration is
  required with a broker, and `disabled: true` is the explicit choice not to check.
  ```

- [ ] **Step 2: §5.6, session lifetime as built.** After the bullet list under "#### Session
  lifetime" (it ends with the bullet "**Refresh MUST be a fresh authentication event…** …a time at
  which possession was just proven."), add:

  ```markdown
  **As built (plan 7b; §13, decision 33).**

  - **The ceiling.** A role's `max_session_age` is a duration of at least 1m or `never`. The
    ceiling on a device is the least across the roles composing there, a role naming none taking
    `session.max_session_age_default`, and `never` only when every role says so. A device whose
    ceiling has passed since the connection authenticated is refused per item at mint,
    `session_expired`.
  - **A policy edit.** It shortens a live context's ceiling and never lengthens it: a longer ceiling
    applies from the next login or refresh.
  - **The warning.** It rides on the `server_msg` of permitted session and command authorization
    replies within `session.ceiling_warning` (default 30m) of `session_expires`, whether a device
    shows it being §15 L34's question, and on `port49 token`'s stderr from the mint's
    `session_expires_at`.
  - **Past the ceiling.** A context is denied `session_expired` and kept until the grace window
    (`session.grace_window`, default 10m) passes; then it is deleted at its next authorization
    (teardown row 3), and no refresh resumes it.
  - **The refresh.** On the certificate path it is `POST /v1/refresh/challenge` and `POST
    /v1/refresh`:
    - **The nonce.** 32 random bytes, good for 60s, once, on the connection that asked, signed by
      the certificate's key over the connection's TLS exporter value, so it cannot be answered on
      another connection.
    - **The clock.** `auth_time` is the broker's verification time, and the held connection's
      session clock moves with it.
    - **What it extends.** Each of the principal's live contexts first takes the policy in force: a
      withdrawn grant is revoked and never extended. What remains is extended inside its grace
      window, each a `refresh` record.
    - **Who triggers it.** `port49 refresh`, and `port49 login`, run it; the agent never runs it on
      its own.
  ```

- [ ] **Step 3: §5.6, teardown row 3.** In the row `| 3 | **Session ceiling** — \`session_expires\`
  reached and the grace window elapsed | local, needs no external signal |`, replace "local, needs
  no external signal" with "local, needs no external signal: the daemon deletes the context at its
  first authorization past the window, and a refresh past it extends nothing (plan 7b)".

- [ ] **Step 4: §5.7, the `refresh` event.** In the events table's `refresh` row, replace "whether a
  live context takes the policy now in force, or is revoked (§5.1.3)" with "whether a live context
  takes the policy now in force, or is revoked (§5.1.3); or, on a session refresh (`/v1/refresh`),
  whether it is extended, with `session.auth_time` and `session.session_expires` (§5.6). A context on
  a platform that never asks about a command carries `session.unreached: true` (decision 21)".

- [ ] **Step 5: §5.7, the reason codes.**
  - **`session_expired`.** After its row's last sentence, add: "Per item on `mint`: the device's
    ceiling (the least `max_session_age` of its roles, §5.6) has passed since the connection
    authenticated; run `port49 refresh`. On `refresh`: the context is past its grace window and is
    not extended."
  - **`trust_domain_unresolved`.** After "`mint`: no configured verifier accepted the credential
    (design document §7)", add "; or the certificate's revocation status could not be established
    (a CRL past its next update, an OCSP responder that did not answer, an issuer no configured
    source covers) and `broker.certificate_status.on_unavailable` is `refuse` (§5.1.4); on `refresh`,
    also a refresh challenge not answered by the connection's key".
  - **`credential_revoked`.** In its row, after "on `mint`, a revocation by principal or by this
    certificate stands (§5.1.4)", add "or a CRL or OCSP response names the certificate".

- [ ] **Step 6: §12, the tooling.** After the `port49 revoke` paragraph (it begins "**`port49 revoke
  (--principal"), add:

  ```markdown
  **`port49 refresh`** re-authenticates the session the agent holds and extends every live context
  the policy in force still grants (§5.6): the agent signs the broker's nonce with the certificate's
  key over the held connection, and prints how many sessions were extended to when, which were
  revoked by the policy, which are past their grace window, and which are on a platform the
  extension cannot reach. `port49 login` does the same while a session is held, and once after a new
  one connects. `port49 token` warns on stderr when the device's session ends within
  `session.ceiling_warning`.
  ```

- [ ] **Step 7: §13, decision 33.** After decision 32's paragraph and before "### Deferred, with
  reasons", add:

  ```markdown
  **33. A session ends where its roles say, warns before, refreshes by a signed nonce, and a
  certificate's revocation status is checked at every use.** *Plan 7b, 2026-10-01, rulings where
  the spec was silent, each the option that denies more.*

  - **The ceiling and the warning.** A role's `max_session_age` is a duration of at least 1m or
    `never`, the least across a device's roles governing, the default staying finite. A device whose
    ceiling has passed is refused per item at mint. A policy edit shortens a live ceiling and never
    lengthens one. The ceiling warning rides on permits within `session.ceiling_warning` (30m),
    provisional on §15 L34.
  - **Past the ceiling.** A context is kept through the grace window and deleted at its first
    authorization after it, and the store refuses to extend one past it.
  - **The refresh.** On the certificate path it is a single-use 60s nonce, signed by the
    certificate's key over the connection's TLS exporter value, with `auth_time` the broker's
    verification time. It carries the policy in force into each context before extending any, and
    only an operator's `port49 refresh` or `port49 login` triggers it.
  - **Certificate status.** It is required with a broker (`disabled: true` an explicit choice). A
    CRL is trusted by its signature against the leaf's verifying issuer and only until its next
    update; deltas are refused. OCSP is cached to its next update, at most an hour. A status that
    cannot be established is refused unless `on_unavailable: allow` (the owner to confirm, plan 7b
    D-7b-1). A revoked certificate is refused at bind, mint and refresh, and one a CRL newly names
    is revoked through decision 32's marks wherever it is still present.

  (§5.1.4, §5.6, §5.7, §12; design document §7, §12, §17)
  ```

- [ ] **Step 8: §15, L2 and L34.** In L2's Status, after "truncation length and IOS-XE unmeasured",
  add "; plan 7b's lab run measures truncation on every image, and IOS-XE and the N9Kv, through
  `lab.deny_message_length`". After the L33 row, add:

  ```markdown
  | **L34** | Whether a device shows the `server_msg` port49 puts on a **permitted** authorization reply — the session reply at login, and a per-command reply — and still treats the reply as a permit: the command's output appears and the session goes on. | The session-ceiling warning (§5.6, plan 7b; decision 33): built and on by default, provisional on this row, and switched off per platform (`platform.CeilingWarning`) where a permit carrying `server_msg` is not a permit | EOS, NX-OS, IOS-XE, Junos | open — added 2026-10-01 by plan 7b; measured by its Task 12 |
  ```

- [ ] **Step 9: Design §7.** In the paragraph that begins "**X.509 client certificate** presented
  over mutual TLS", after "A refresh on the held connection is an application-level signed nonce",
  add ", bound to the connection by its TLS exporter value (plan 7b)".

- [ ] **Step 10: Design §17, the surface.** In the code block under "### Surface", after the `POST
  /v1/refresh` line, add:

  ```
  POST  /v1/refresh/challenge  certificate path: a single-use nonce the agent signs for /v1/refresh
  ```

- [ ] **Step 11: Design §12, the failure matrix.** After the row that begins `| **Revocations file
  missing or refused**`, add:

  ```markdown
  | **Certificate status unavailable** (a CRL past its next update, an OCSP responder down; policy engine spec §5.1.4) | ✗ for the issuers it covers, with `on_unavailable: refuse` (the default); ✓ alarmed with `allow` | ✗ (no new token), as the column before | ✓ the daemon never reads certificate status | ✗ new mints; tokens already minted still redeem |
  ```

- [ ] **Step 12: Check and commit.** `make test && make vet`.

  ```bash
  git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
  git commit -m "docs: session lifetime, the signed-nonce refresh, certificate status, L34 (plan 7b)

  Spec §5.1.4, §5.6, §5.7 (refresh records a session refresh; session_expired,
  trust_domain_unresolved and credential_revoked gain meanings; no reason added), §12,
  §13 decision 33, §15 L2 and the new L34; design §7, §12, §17.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 2: A role declares `max_session_age`, and a device's ceiling is the least of its roles'

**Files:**
- Modify: `internal/policy/file.go` (`fileRole`), `internal/policy/load.go` (`Role`; `buildRoles`;
  the refusal of plan 4 removed), `internal/policy/resolve.go` (`Resolution.SessionAge`, `resolved`)
- Test: `internal/policy/load_test.go`, `internal/policy/resolve_test.go`

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

- [ ] **Step 5: Run them.** `go test ./internal/policy/ -count=1 -race` → PASS. Then `gofmt -w`,
  `make build && make test && make vet`.

- [ ] **Step 6: Commit.**

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
  	if r.Results[0].Verdict != "deny" || r.Results[0].Reason != "session_expired" {
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
  		return deny(decision.SessionExpired, dev.Platform), nil
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

### Task 4: The store shortens a ceiling on a policy write, and refuses to extend past the grace window

**Files:**
- Modify: `internal/store/store.go` (`ContextPolicy.MaxSessionAge`, `ContextRefresh.GraceCutoff`,
  `ErrPastGrace`; the comments on `SetContextPolicy` and `RefreshContext`)
- Modify: `internal/store/memory/memory.go` (`SetContextPolicy`, `RefreshContext`)
- Modify: `internal/store/storetest/storetest.go` (`CeilingShortensOnly`, `RefreshStopsAtGrace`)
- Test: `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go`

**Interfaces:**
- Produces:
  - `store.ContextPolicy.MaxSessionAge time.Duration`: the policy's ceiling (0 never). The write
    sets `SessionExpires = AuthTime + MaxSessionAge` only when that is earlier than the context's,
    or the context has none; zero changes nothing.
  - `store.ContextRefresh.GraceCutoff time.Time`: non-zero, a context with a ceiling earlier than it
    is not refreshed, `ErrPastGrace`, nothing written.
  - `var store.ErrPastGrace`
  - `storetest.CeilingShortensOnly(t, newStore, now)`, `storetest.RefreshStopsAtGrace(t, newStore, now)`

The sealing layer passes both through unchanged: `SessionExpires` and `AuthTime` are plaintext
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

  // RefreshStopsAtGrace: a refresh whose GraceCutoff is after the context's
  // ceiling writes nothing and says so (spec §5.6, teardown row 3); one inside
  // the window resumes the context, keeping its window.
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
  	if c, _ := s.GetContext(ctx, k); !c.SessionExpires.Equal(now.Add(2 * time.Hour)) {
  		t.Fatalf("the window was not kept: %v", c.SessionExpires)
  	}
  }
  ```

  Call both from `memory_test.go` and, through `Wrap(memory.New(...), keys(), nil)`, from
  `crypt_test.go`, as the file's other properties are called.

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/store/... -run 'Shortens|Grace' -count=1`
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
  	// GraceCutoff, when non-zero, is the earliest ceiling a refresh may
  	// extend: the refresh time less the grace window. A context with a
  	// ceiling before it is ErrPastGrace and is not written. It is checked
  	// under the store's lock, so a refresh racing the window's end cannot
  	// resume a session the window closed (plan 7b).
  	GraceCutoff time.Time
  ```

  and to `ContextPolicy`:

  ```go
  	// MaxSessionAge is the policy's ceiling for this principal on this device,
  	// zero for never (spec §5.6). SessionExpires becomes AuthTime plus it only
  	// when that is earlier, or the context has none: a policy edit shortens a
  	// session, and only a fresh authentication event lengthens one (decision
  	// 33). Zero changes nothing.
  	MaxSessionAge time.Duration
  ```

- [ ] **Step 4: The memory store.** In `RefreshContext`, after the found check:

  ```go
  	if !r.GraceCutoff.IsZero() && e.c.HasCeiling() && e.c.SessionExpires.Before(r.GraceCutoff) {
  		return store.ErrPastGrace
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

- [ ] **Step 5: Run them.** `go test ./internal/store/... -count=1 -race` → PASS. Then `gofmt -w`,
  `make build && make test && make vet`.

- [ ] **Step 6: Commit.**

  ```bash
  git add internal/store
  git commit -m "feat(store): a policy write shortens a ceiling; a refresh stops at the grace window

  ContextPolicy.MaxSessionAge shortens session_expires or gives a context one, never lengthens;
  ContextRefresh.GraceCutoff refuses to extend a context past its grace window (ErrPastGrace).
  Both are storetest properties every backend must pass.

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

- [ ] **Step 1: The tests.** In `refresh_test.go`, using its fixture:

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
  `store.ContextPolicy` it returns. In `refreshContext`, right after `step.sessionOnly = …`, add
  `step.rec.Session.Unreached = step.sessionOnly`; and in the unreadable-context branch, set the
  record's `Session.Unreached` from the same `sessionOnly(known, plat)`.

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
  - `func platform.CeilingWarning(name string) bool`: true for every platform until L34 says
    otherwise (Task 13).
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
  		h, ctxStore, now := newAuthorFixture(t)
  		h.WithCeilingWarning(30 * time.Minute)
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
  	if resp.Status != wire.AuthorStatusFail || !strings.Contains(string(resp.ServerMsg), "within 5m to resume") {
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

  // ceilingWarningOff names the platforms that are not sent the session
  // ceiling warning in a permit's server_msg (spec §5.6; decision 33). Whether
  // a device shows server_msg on a permit, and still permits, is spec §15 L34:
  // until it closes every platform is sent the warning, and a platform L34
  // finds treating such a permit as anything else is added here, citing its
  // note. A table in code, not in a platform set: a released set is never
  // edited.
  var ceilingWarningOff = map[string]bool{}

  // CeilingWarning reports whether name's permits carry the warning.
  func CeilingWarning(name string) bool { return !ceilingWarningOff[name] }
  ```

  with a one-line test that it is true for `arista_eos` and the table is empty.

- [ ] **Step 4: The authorizer.** In `author.go`: add `ceilingWarning time.Duration` to `Handler`
  (comment: "how long before session_expires a permit's reply carries the warning in server_msg;
  zero is none (spec §5.6; decision 33)"), and

  ```go
  // WithCeilingWarning sets session.ceiling_warning.
  func (h *Handler) WithCeilingWarning(d time.Duration) *Handler {
  	h.ceilingWarning = d
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
  				"port49: session expired - run 'port49 refresh' within %dm to resume", ceilMinutes(left)))
  		}
  		err := h.store.DeleteContext(ctx, store.ContextKey{NAS: peer.NAS, Username: user})
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
  	if h.ceilingWarning > 0 && c.HasCeiling() && platform.CeilingWarning(peer.Platform) {
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

- [ ] **Step 5: The lab's padded message.** In `lab.go`, add `DenyMessageLength int` to `Lab` (comment:
  "pads the lab's deny server_msg to this many bytes with a counting pattern, for L2's truncation
  length; zero leaves it"), apply it where the lab builds its deny message, and add:

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
  `session.ceiling_warning`. Add `DenyMessageLength int `yaml:"deny_message_length"`` to `LabConfig`,
  refusing a value other than 0 or 16–4096. Add the metric (`port49_ceiling_warnings_total`, "Permitted
  authorization replies that carried the session ceiling warning.") and touch it in
  `metrics_test.go`.

- [ ] **Step 7: port49d.** In `main.go`, chain `.WithCeilingWarning(cfg.Session.CeilingWarning)` onto
  `author.New(...)`, and pass `DenyMessageLength: cfg.Lab.DenyMessageLength` into the `author.Lab`
  literal.

- [ ] **Step 8: Run them.** `go test ./internal/daemon/... ./internal/config/ ./internal/platform/ ./cmd/port49d/ -count=1 -race`
  → PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 9: Commit.**

  ```bash
  git add internal/platform/warning.go internal/platform/warning_test.go internal/daemon internal/config cmd/port49d
  git commit -m "feat(daemon): warn before the ceiling, keep the context through grace, delete it after

  A permit within session.ceiling_warning (30m) carries the warning in server_msg (provisional
  on L34; platform.CeilingWarning switches it off per platform). Past the ceiling a context is
  kept through the grace window and named in the denial; past the window it is deleted.
  A touch bumps the context's blob. lab.deny_message_length pads the lab's denial for L2.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 7: `/v1/refresh`: a signed nonce over the held connection extends every live session the policy still grants

**Files:**
- Create: `internal/broker/api/refresh.go` (the message, the exporter label, the algorithm, the
  signer, the wire types)
- Create: `internal/broker/sessionrefresh.go` (the two handlers, `RefreshSession`)
- Modify: `internal/broker/broker.go` (`heldConn` gains a lock, the nonce and a movable `at`;
  `Handler` routes; `Broker.ContextIdleTTL`, `Broker.GraceWindow`)
- Modify: `internal/daemon/metrics/metrics.go` (`SessionRefreshes`)
- Modify: `cmd/port49d/main.go` (the broker's two new fields)
- Test: `internal/broker/api/refresh_test.go`, `internal/broker/sessionrefresh_test.go`

**Interfaces:**
- Consumes: 7a's `Identity`, `revocation`, `refuseRevoked`, `emit`, `supersede`; 4b's
  `refreshContext`; Task 4's `GraceCutoff`/`ErrPastGrace`; Task 5's `decision.Session` fields.
- Produces:
  - `api.RefreshExporterLabel = "EXPORTER-port49-refresh"`, `api.RefreshNonceLen = 32`
  - `func api.RefreshMessage(nonce, ekm []byte) []byte` (`"port49 session refresh v1\x00" ‖ nonce ‖ ekm`)
  - `func api.RefreshAlgorithm(pub crypto.PublicKey) (x509.SignatureAlgorithm, bool)`
  - `func api.SignRefresh(signer crypto.Signer, msg []byte) ([]byte, error)`
  - `type api.RefreshChallenge struct { Nonce string `json:"nonce"`; ExpiresAt string `json:"expires_at"` }`
  - `type api.RefreshRequest struct { Nonce string `json:"nonce"`; Signature string `json:"signature"` }` (base64url, no padding)
  - `type api.RefreshResponse struct { AuthTime, SessionEndsAt string; Extended []api.RefreshedSession; Revoked, PastGrace, Unreached []string }`
    with `RefreshedSession{Device, Username, SessionExpires string}` (JSON `auth_time`,
    `session_ends_at`, `extended`, `revoked`, `past_grace`, `unreached`, `device`, `username`,
    `session_expires`)
  - `func (b *Broker) RefreshSession(ctx context.Context, principal string, cred store.Credential, at time.Time) (SessionRefreshReport, error)`
  - `type SessionRefreshReport struct { At time.Time; Extended []ExtendedContext; Revoked, PastGrace, Unreached []store.ContextRef; Err error }`,
    `ExtendedContext{Ref store.ContextRef; SessionExpires time.Time}`
  - metric `port49_session_refreshes_total{outcome}`: `extended`, `refused`, `revoked`,
    `store_error`.
  - API error codes: `refresh_refused` is never used. A refusal is `401 trust_domain_unresolved`
    (§5.7), `401 credential_revoked`, or `503 store_unavailable`; a request on no held connection
    is `400 bad_request`.

- [ ] **Step 1: The message's tests.** Create `internal/broker/api/refresh_test.go`: for an ECDSA
  P-256, an RSA 2048 and an Ed25519 key, `SignRefresh` then `x509.Certificate.CheckSignature(alg,
  msg, sig)` with `RefreshAlgorithm`'s `alg` verifies, and a one-byte change to the message does
  not; `RefreshMessage` is the context string, the nonce and the exporter value concatenated, 32 +
  32 + 26 bytes; `RefreshAlgorithm` of a DSA or unknown key is false. (Build each certificate with
  `x509.CreateCertificate` self-signed; `testpki` issues ECDSA only.)

- [ ] **Step 2: The handlers' tests.** Create `internal/broker/sessionrefresh_test.go`, serving
  through 7a's `serveThrough`, and driving the exchange on one TLS connection (`tls.Dial`, then
  two requests on it, as 7a's `held`/`ask` do), signing with the client's key:

  ```go
  // refreshOn runs the challenge and the refresh on one connection, signing
  // with cert's key over that connection's exporter value; it returns the
  // refresh's status and body.
  func refreshOn(t *testing.T, c *tls.Conn, br *bufio.Reader, cert tls.Certificate, tamper func([]byte) []byte) (int, string) {
  	t.Helper()
  	ch := postOn(t, c, br, "/v1/refresh/challenge", "")
  	var challenge api.RefreshChallenge
  	if err := json.Unmarshal([]byte(ch.body), &challenge); err != nil || ch.status != 200 {
  		t.Fatalf("challenge: %d %s", ch.status, ch.body)
  	}
  	nonce, _ := base64.RawURLEncoding.DecodeString(challenge.Nonce)
  	cs := c.ConnectionState()
  	ekm, err := cs.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
  	if err != nil {
  		t.Fatal(err)
  	}
  	msg := api.RefreshMessage(nonce, ekm)
  	if tamper != nil {
  		msg = tamper(msg)
  	}
  	sig, err := api.SignRefresh(cert.PrivateKey.(crypto.Signer), msg)
  	if err != nil {
  		t.Fatal(err)
  	}
  	body, _ := json.Marshal(api.RefreshRequest{Nonce: challenge.Nonce, Signature: base64.RawURLEncoding.EncodeToString(sig)})
  	r := postOn(t, c, br, "/v1/refresh", string(body))
  	return r.status, r.body
  }

  // A refresh extends every live context the policy in force grants, from
  // the broker's verification time, keeping each context's window; the
  // connection's session clock moves with it, so a mint past the old ceiling
  // goes through (spec §5.6; decision 33).
  func TestARefreshExtendsLiveSessions(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	auth := f.now
  	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(8*time.Hour))
  	f.advance(7*time.Hour + 50*time.Minute)
  	status, body := refreshOn(t, c, br, f.alice, nil)
  	if status != 200 {
  		t.Fatalf("%d %s", status, body)
  	}
  	ctx, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
  	if !ctx.AuthTime.Equal(f.b.Now()) || !ctx.SessionExpires.Equal(f.b.Now().Add(8*time.Hour)) {
  		t.Fatalf("auth_time %v, session_expires %v", ctx.AuthTime, ctx.SessionExpires)
  	}
  	var resp api.RefreshResponse
  	if err := json.Unmarshal([]byte(body), &resp); err != nil || len(resp.Extended) != 1 {
  		t.Fatalf("%s %v", body, err)
  	}
  	rec := eventsOf(f.records(t), "refresh")
  	if last := rec[len(rec)-1]; last["verdict"] != "permit" || last["session"].(map[string]any)["auth_time"] == nil {
  		t.Fatalf("the refresh record: %v", last)
  	}
  	// Twelve hours after the handshake, on the same connection: still minting.
  	f.advance(4*time.Hour + 20*time.Minute)
  	if r := postOn(t, c, br, "/v1/tokens", `{"devices":["leaf1"]}`); r.status != 200 {
  		t.Fatalf("a mint after the refresh, past the handshake's ceiling: %d %s", r.status, r.body)
  	}
  }

  // A context whose grant the policy in force withdrew is revoked, not
  // extended; one past its grace window is not resumed and is deleted; one
  // on a session-only platform is extended and named unreached.
  func TestARefreshExtendsOnlyWhatThePolicyStillGrants(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	auth := f.now
  	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(time.Hour))   // past, inside grace
  	f.liveContextAt(t, "nx1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(30*time.Minute)) // past grace
  	f.liveContextAt(t, "bare", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(8*time.Hour))   // unreached
  	f.b.GraceWindow = 10 * time.Minute
  	f.advance(time.Hour + 5*time.Minute)
  	status, body := refreshOn(t, c, br, f.alice, nil)
  	var resp api.RefreshResponse
  	_ = json.Unmarshal([]byte(body), &resp)
  	if status != 200 || len(resp.PastGrace) != 1 || resp.PastGrace[0] != "nx1 (alice)" || len(resp.Unreached) != 1 {
  		t.Fatalf("%d %s", status, body)
  	}
  	if _, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "nx1", Username: "alice"}); !errors.Is(err, store.ErrNotFound) {
  		t.Fatalf("a context past its grace window was kept: %v", err)
  	}
  	// The grant withdrawn: the next refresh revokes, and extends nothing.
  	f.loadPolicy(t, strings.Replace(testPolicy, "grants:\n  - {subject: netops", "grants:\n  - {subject: idle", 1))
  	status, body = refreshOn(t, c, br, f.alice, nil)
  	_ = json.Unmarshal([]byte(body), &resp)
  	if status != 200 || len(resp.Extended) != 0 || len(resp.Revoked) == 0 {
  		t.Fatalf("after the grant was withdrawn: %d %s", status, body)
  	}
  }

  // The nonce is single use, 60s, and answered only by this connection's
  // key over this connection's exporter value: a stale, replayed or tampered
  // answer refreshes nothing, and is one refresh deny trust_domain_unresolved
  // record that never carries the nonce or the signature.
  func TestARefreshIsBoundToItsConnectionAndItsKey(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	if s, _ := refreshOn(t, c, br, f.alice, func(m []byte) []byte { m[len(m)-1] ^= 1; return m }); s != 401 {
  		t.Fatalf("a signature over another exporter value: %d", s)
  	}
  	// A nonce answered on another connection.
  	ch := postOn(t, c, br, "/v1/refresh/challenge", "")
  	var challenge api.RefreshChallenge
  	_ = json.Unmarshal([]byte(ch.body), &challenge)
  	other, obr := held(t, f, addr, f.alice)
  	body, _ := json.Marshal(api.RefreshRequest{Nonce: challenge.Nonce, Signature: "AAAA"})
  	if r := postOn(t, other, obr, "/v1/refresh", string(body)); r.status != 401 {
  		t.Fatalf("a nonce from another connection: %d", r.status)
  	}
  	// Stale.
  	ch = postOn(t, c, br, "/v1/refresh/challenge", "")
  	f.advance(61 * time.Second)
  	_ = json.Unmarshal([]byte(ch.body), &challenge)
  	body, _ = json.Marshal(api.RefreshRequest{Nonce: challenge.Nonce, Signature: "AAAA"})
  	if r := postOn(t, c, br, "/v1/refresh", string(body)); r.status != 401 {
  		t.Fatalf("a nonce past 60s: %d", r.status)
  	}
  	// Another key, the same principal: a certificate's key answers for itself.
  	renewed := f.client(t, "alice@example.com", f.now.Add(time.Hour))
  	if s, _ := refreshOn(t, c, br, renewed, nil); s != 401 {
  		t.Fatalf("a signature by another key: %d", s)
  	}
  	log := f.log.String()
  	if strings.Contains(log, challenge.Nonce) {
  		t.Fatal("the nonce reached the log")
  	}
  	if n := len(eventsOf(f.records(t), "refresh")); n < 4 {
  		t.Fatalf("%d refresh records for four refusals", n)
  	}
  }

  // A revoked principal cannot refresh: credential_revoked, nothing extended.
  func TestARevokedCallerCannotRefresh(t *testing.T) {
  	f := newFixture(t, 8)
  	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
  	c, br := held(t, f, addr, f.alice)
  	f.revoke(t, store.RevocationPrincipal, alicePrincipal)
  	if s, body := refreshOn(t, c, br, f.alice, nil); s != 401 || !strings.Contains(body, "credential_revoked") {
  		t.Fatalf("%d %s", s, body)
  	}
  }
  ```

  (`postOn(t, c, br, path, body)` writes one request on the connection and reads its response,
  returning `{status, body}`; `liveContextAt` is 7a's `liveContext` with the auth time and ceiling
  given; `loadPolicy` swaps `f.b.Policy` to a policy loaded from text over the fixture's devices.
  Add each beside its neighbours. The challenge in the third test is answered on `c` after it was
  answered on `other`; a nonce is single use, so `c`'s later challenge is a new one.)

- [ ] **Step 3: Run them to see them fail.** `go test ./internal/broker/... -run 'Refresh' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 4: The message.** Create `internal/broker/api/refresh.go`:

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
  // a refresh with: ECDSA with SHA-256, RSA-PSS with SHA-256, Ed25519. Fixing
  // it per key type leaves the caller nothing to choose.
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

  // RefreshedSession is one context a refresh extended.
  type RefreshedSession struct {
  	Device         string `json:"device"`
  	Username       string `json:"username"`
  	SessionExpires string `json:"session_expires,omitempty"`
  }

  // RefreshResponse is POST /v1/refresh's 200: what was extended, what the
  // policy in force revoked instead, what was past its grace window, and what
  // the extension cannot reach on the device ("device (username)").
  type RefreshResponse struct {
  	AuthTime      string             `json:"auth_time"`
  	SessionEndsAt string             `json:"session_ends_at"`
  	Extended      []RefreshedSession `json:"extended"`
  	Revoked       []string           `json:"revoked,omitempty"`
  	PastGrace     []string           `json:"past_grace,omitempty"`
  	Unreached     []string           `json:"unreached,omitempty"`
  }
  ```

- [ ] **Step 5: The held connection.** In `broker.go`, replace `heldConn` with:

  ```go
  // heldConn is one connection's session state (design §7: on the certificate
  // path the agent's session IS the connection). at is when it authenticated:
  // stamped at accept, before the handshake (plan 3, Decided 2), and moved
  // only by a refresh that verified (spec §5.6; decision 33). nonce is the
  // refresh challenge outstanding on it, single use.
  type heldConn struct {
  	mu       sync.Mutex
  	at       time.Time
  	nonce    []byte
  	nonceExp time.Time
  }

  func (h *heldConn) authAt() time.Time {
  	h.mu.Lock()
  	defer h.mu.Unlock()
  	return h.at
  }
  ```

  have `authTime` read `h.authAt()`, add `func heldOf(r *http.Request) *heldConn` (nil without the
  state), and route `POST /v1/refresh/challenge` and `POST /v1/refresh` in `Handler`. Add to `Broker`:

  ```go
  	// ContextIdleTTL is the idle lifetime a refreshed context is extended to,
  	// and GraceWindow how long past its ceiling a refresh may still resume
  	// one (spec §5.6): port49d's context_idle_ttl and session.grace_window.
  	ContextIdleTTL time.Duration
  	GraceWindow    time.Duration
  ```

- [ ] **Step 6: The handlers and `RefreshSession`.** Create `internal/broker/sessionrefresh.go`:

  ```go
  package broker

  import (
  	"bytes"
  	"context"
  	"crypto/rand"
  	"crypto/subtle"
  	"encoding/base64"
  	"encoding/json"
  	"errors"
  	"fmt"
  	"io"
  	"net/http"
  	"time"

  	"github.com/rhwendt/port49/internal/broker/api"
  	"github.com/rhwendt/port49/internal/decision"
  	"github.com/rhwendt/port49/internal/store"
  )

  // refreshNonceTTL is how long a challenge may be answered.
  const refreshNonceTTL = 60 * time.Second

  // refreshChallenge issues the nonce a refresh signs (spec §5.6; decision
  // 33). It is held on this connection alone; a new one replaces it.
  func (b *Broker) refreshChallenge(w http.ResponseWriter, r *http.Request) {
  	now := b.Now()
  	principal, cred, err := Identity(r.TLS, now)
  	if err != nil {
  		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, err.Error())
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
  	h.nonce, h.nonceExp = nonce, now.Add(refreshNonceTTL)
  	h.mu.Unlock()
  	writeJSON(w, http.StatusOK, api.RefreshChallenge{Nonce: base64.RawURLEncoding.EncodeToString(nonce),
  		ExpiresAt: now.Add(refreshNonceTTL).UTC().Format(time.RFC3339)})
  }

  // refresh verifies the signed challenge and extends the caller's live
  // sessions (spec §5.6). The nonce is taken whatever the outcome: single use.
  func (b *Broker) refresh(w http.ResponseWriter, r *http.Request) {
  	now := b.Now()
  	principal, cred, err := Identity(r.TLS, now)
  	if err != nil {
  		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved, err.Error())
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
  		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved,
  			"no live refresh challenge on this connection; ask for one and answer it within 60s")
  		return
  	}
  	leaf := r.TLS.VerifiedChains[0][0] // Identity verified there is one
  	ekm, err := r.TLS.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
  	alg, ok := api.RefreshAlgorithm(leaf.PublicKey)
  	if err != nil || !ok || leaf.CheckSignature(alg, api.RefreshMessage(nonce, ekm), sig) != nil {
  		b.refuseRefresh(w, now, principal, cred, decision.TrustDomainUnresolved,
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
  		b.Metrics.SessionRefreshes.WithLabelValues("revoked").Inc()
  		b.refuseRevoked(w, now, principal, cred, rv)
  		return
  	}
  	// Certificate status (Task 10) is checked here, beside the marks.
  	at := b.Now() // the broker's verification time: the one clock §5.6 gives it
  	h.mu.Lock()
  	h.at = at
  	h.mu.Unlock()
  	rep, err := b.RefreshSession(ctx, principal, cred, at)
  	if err != nil {
  		b.Metrics.SessionRefreshes.WithLabelValues("store_error").Inc()
  		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
  			"the broker could not read your live sessions; try again: "+err.Error())
  		return
  	}
  	b.Metrics.SessionRefreshes.WithLabelValues("extended").Inc()
  	writeJSON(w, http.StatusOK, rep.response(b.MaxSessionAge))
  }

  // refuseRefresh answers a refresh that proved nothing, and records it
  // without the nonce or the signature.
  func (b *Broker) refuseRefresh(w http.ResponseWriter, now time.Time, principal string, cred store.Credential,
  	reason decision.Reason, detail string) {
  	b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
  	b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: reason,
  		Principal: principal, Auth: &decision.Auth{Method: "cert", Fingerprint: cred.Fingerprint}})
  	writeError(w, http.StatusUnauthorized, string(reason), detail)
  }

  // ExtendedContext is one context a session refresh extended, with its new
  // ceiling (zero: none).
  type ExtendedContext struct {
  	Ref            store.ContextRef
  	SessionExpires time.Time
  }

  // SessionRefreshReport is what RefreshSession did.
  type SessionRefreshReport struct {
  	At                          time.Time
  	Extended                    []ExtendedContext
  	Revoked, PastGrace, Unreached []store.ContextRef
  }

  // RefreshSession carries a fresh authentication at at into every live
  // context of principal (spec §5.6; decision 33). It holds the policy in
  // force, as a mint does, and first writes the policy's answer into each
  // context exactly as a policy refresh would (refreshContext): a withdrawn
  // grant is revoked there and never extended. Then each context still live,
  // unrevoked, and inside its grace window is extended through
  // store.RefreshContext, keeping its window; one past the window is deleted
  // (teardown row 3) and named. Each extension is a refresh record.
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
  		if err := b.refreshContext(ctx, pol, nil, at, principal, ref, &pass, quarantined, false); err != nil &&
  			!errors.Is(err, store.ErrConflict) {
  			return rep, err
  		}
  		c, err := b.Store.GetContext(ctx, k)
  		switch {
  		case errors.Is(err, store.ErrNotFound):
  			continue
  		case err != nil:
  			return rep, err
  		case c.Principal != principal:
  			continue
  		}
  		dev, known := pol.Device(ref.NAS)
  		unreached := !known || dev.Platform == "" || sessionOnly(pol, dev.Platform)
  		rec := decision.Record{TS: at, Event: decision.EventRefresh, Principal: principal,
  			Auth:    &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint},
  			Device:  &decision.Device{Name: ref.NAS, Platform: dev.Platform},
  			Session: &decision.Session{CtxID: c.CtxID, Username: c.Username, Unreached: unreached}}
  		switch {
  		case !c.RevokedAt.IsZero():
  			rep.Revoked = append(rep.Revoked, ref)
  			continue
  		case c.HasCeiling() && !at.Before(c.SessionExpires.Add(b.GraceWindow)):
  			rep.PastGrace = append(rep.PastGrace, ref)
  			_ = b.Store.DeleteContext(ctx, k)
  			rec.Verdict, rec.Reason = decision.VerdictDeny, decision.SessionExpired
  			b.emit(rec)
  			continue
  		}
  		err = b.Store.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: at, RefreshedAt: at,
  			GraceCutoff: at.Add(-b.GraceWindow)}, b.ContextIdleTTL)
  		switch {
  		case errors.Is(err, store.ErrPastGrace):
  			rep.PastGrace = append(rep.PastGrace, ref)
  			continue
  		case errors.Is(err, store.ErrNotFound):
  			continue
  		case err != nil:
  			return rep, err
  		}
  		var expires time.Time
  		if c.HasCeiling() {
  			expires = at.Add(c.SessionExpires.Sub(c.AuthTime))
  			rec.Session.SessionExpires = decision.FormatTime(expires)
  		}
  		if c.BlobHash != "" {
  			_ = b.Store.BumpBlob(ctx, c.BlobHash, max(b.ContextIdleTTL, expires.Sub(at)))
  		}
  		rec.Session.AuthTime = decision.FormatTime(at)
  		rec.Verdict, rec.Reason = decision.VerdictPermit, decision.GrantsMatched
  		b.emit(rec)
  		rep.Extended = append(rep.Extended, ExtendedContext{Ref: ref, SessionExpires: expires})
  		if unreached {
  			rep.Unreached = append(rep.Unreached, ref)
  		}
  	}
  	return rep, nil
  }

  // response is the wire form of rep; the connection's own session now ends
  // connAge after rep.At.
  func (rep SessionRefreshReport) response(connAge time.Duration) api.RefreshResponse {
  	name := func(ref store.ContextRef) string { return fmt.Sprintf("%s (%s)", ref.NAS, ref.Username) }
  	out := api.RefreshResponse{AuthTime: rep.At.UTC().Format(time.RFC3339),
  		SessionEndsAt: rep.At.Add(connAge).UTC().Format(time.RFC3339), Extended: []api.RefreshedSession{}}
  	for _, e := range rep.Extended {
  		s := api.RefreshedSession{Device: e.Ref.NAS, Username: e.Ref.Username}
  		if !e.SessionExpires.IsZero() {
  			s.SessionExpires = e.SessionExpires.UTC().Format(time.RFC3339)
  		}
  		out.Extended = append(out.Extended, s)
  	}
  	for _, list := range []struct {
  		in  []store.ContextRef
  		out *[]string
  	}{{rep.Revoked, &out.Revoked}, {rep.PastGrace, &out.PastGrace}, {rep.Unreached, &out.Unreached}} {
  		for _, ref := range list.in {
  			*list.out = append(*list.out, name(ref))
  		}
  	}
  	return out
  }
  ```

  (`bytes` is unused if the compiler says so; drop it. `refreshContext` emits its own `refresh`
  record when it writes or revokes, as a policy refresh does; the extension's record follows it.)

- [ ] **Step 7: The metric and port49d.** Add `SessionRefreshes` (`port49_session_refreshes_total`,
  label `outcome`, "Session refreshes by outcome: extended, refused, revoked, store_error.") to
  `metrics.go` and its test. In `cmd/port49d/main.go`, after `buildBroker`, set
  `brk.ContextIdleTTL, brk.GraceWindow, brk.CeilingWarning = cfg.ContextIdleTTL,
  cfg.Session.GraceWindow, cfg.Session.CeilingWarning`.

- [ ] **Step 8: Run them.** `go test ./internal/broker/... ./internal/daemon/metrics/ ./cmd/port49d/ -count=1 -race`
  → PASS. Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 9: Commit.**

  ```bash
  git add internal/broker internal/daemon/metrics cmd/port49d
  git commit -m "feat(broker): /v1/refresh, a signed nonce bound to the held connection

  POST /v1/refresh/challenge issues a single-use 60s nonce; POST /v1/refresh verifies the
  certificate's signature over it and the connection's TLS exporter value, checks the marks,
  moves the connection's auth_time to the verification time, and carries the policy in force
  into each live context before extending what is still granted and inside its grace window.

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
- Modify: `cmd/port49/main.go` (`run`'s switch; `usage`; `login` refreshes; `tokenCmd` warns)
- Test: `internal/agent/agent_test.go`, `cmd/port49/main_test.go`

**Interfaces:**
- Consumes: Task 7's API.
- Produces:
  - `func (a *Agent) Refresh(ctx context.Context) (api.RefreshResponse, error)`: the challenge and the
    refresh on the held connection, signed with the session's key. A refusal naming the challenge
    ("no live refresh challenge") is retried once with a new challenge; `credential_revoked` ends the
    session, as a mint's does.
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

- [ ] **Step 2: The CLI's tests.** In `cmd/port49/main_test.go`, beside the `login`/`token` tests
  that stand up a broker and run `run([]string{"login", …})`:
  - `run([]string{"refresh", "--socket", sock})` prints `refreshed: 1 session(s) extended to …` for
    a broker with one live context;
  - with no agent it exits 1 saying `run 'port49 login'`;
  - `port49 login` with an agent already running prints the refresh's line (not "already logged
    in");
  - `port49 token` for a device whose item's `session_expires_at` is within the agent's
    `ceiling_warning_seconds` prints the token on stdout and `port49: your session on leaf1 ends at …
    (in 29m); run 'port49 refresh'` on stderr, and nothing on stderr when it is not.

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
  		return api.RefreshResponse{}, strings.Contains(e.Detail, "no live refresh challenge"),
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
  	}
  	return out, false, nil
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

  // printRefresh says what a refresh did, in the order an operator acts on
  // it: what was extended, what the policy revoked, what must be logged into
  // again, and what the extension cannot reach on the device.
  func printRefresh(w io.Writer, r api.RefreshResponse) {
  	until := "with no ceiling"
  	for _, s := range r.Extended {
  		if s.SessionExpires != "" {
  			until = "to " + s.SessionExpires
  			break
  		}
  	}
  	fmt.Fprintf(w, "refreshed: %d session(s) extended %s; this login lasts until %s\n", len(r.Extended), until,
  		r.SessionEndsAt)
  	if len(r.Revoked) > 0 {
  		fmt.Fprintf(w, "revoked by the policy in force, not extended: %s\n", strings.Join(r.Revoked, ", "))
  	}
  	if len(r.PastGrace) > 0 {
  		fmt.Fprintf(w, "%d session(s) past the grace window, not resumed: %s; log in again there\n",
  			len(r.PastGrace), strings.Join(r.PastGrace, ", "))
  	}
  	if len(r.Unreached) > 0 {
  		fmt.Fprintf(w, "not reached, on a platform that never asks port49 about a command: %s\n",
  			strings.Join(r.Unreached, ", "))
  	}
  }
  ```

  (imports: `context`, `errors`, `flag`, `fmt`, `io`, `strings`, `internal/agent`,
  `internal/broker/api`.) In `main.go`: add `case "refresh": return refreshCmd(args[1:], stdout,
  stderr)` and the usage line `port49 refresh [--socket PATH]`. In `login`, where an agent is already
  running, call `agent.NewClient(sf.socket).Refresh(ctx)` and `printRefresh` instead of "already
  logged in" (a failure there prints the error and exits 1); after a new agent answers its status,
  call `Refresh` likewise and print its line after "logged in", where a refresh failure is said and
  the login still exits 0 (the session is up). In `tokenCmd`, after printing the token:

  ```go
  	// The device's own ceiling, said where the operator is looking, for a
  	// platform that does not show the server_msg warning (decision 33).
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

### Task 9: `internal/certstatus`: CRLs trusted by their signature, OCSP with a cache

**Files:**
- Create: `internal/certstatus/certstatus.go` (`Checker`, `Check`, `Verdict`, `Result`, `Config`)
- Create: `internal/certstatus/crl.go` (loading, polling, the new-entry callback)
- Create: `internal/certstatus/ocsp.go` (the query and its cache)
- Modify: `internal/daemon/metrics/metrics.go` (`CertStatusChecks`, `CRLLoads`, `CRLNextUpdate`,
  `CertStatusUnavailable`)
- Test: `internal/certstatus/certstatus_test.go`, `internal/certstatus/ocsp_test.go`

**Interfaces:**
- Consumes: `golang.org/x/crypto/ocsp` (in the `golang.org/x/crypto` module already required; run
  `go mod tidy` and confirm `go.mod` gains no module), `printsafe.Line`.
- Produces:
  - `type Verdict int` with `Good`, `Revoked`, `Unknown`
  - `type Result struct { Verdict Verdict; Source string /* "crl" | "ocsp" | "none" */; Name string; RevokedAt time.Time; Detail string }`
  - `type CRLSource struct { Name, File, URL string }`, `type OCSPConfig struct { Responder string; UseAIA bool; Timeout time.Duration }`,
    `type Config struct { CRLs []CRLSource; OCSP *OCSPConfig; RefreshInterval time.Duration }`
  - `func New(cfg Config, now func() time.Time, m *metrics.Metrics, logf func(string, ...any)) *Checker`
  - `func (c *Checker) OnNewEntry(f func(issuer, serial, source string))`: called for every serial
    a CRL load adds over the last good load of that source, the first load's every serial included
  - `func (c *Checker) LoadAll(ctx context.Context) []error`, `func (c *Checker) Run(ctx context.Context)`
  - `func (c *Checker) Check(ctx context.Context, chain []*x509.Certificate) Result`
  - `func (c *Checker) Describe() string`: the start line's sources, each CRL's next update
  - metrics:
    - `port49_cert_status_checks_total{source,result}` (`result` ∈ `good`, `revoked`, `unknown`);
    - `port49_crl_loads_total{crl,outcome}` (`loaded`, `unchanged`, `failed`, `refused`);
    - `port49_crl_next_update_seconds{crl}` (a gauge: seconds to the loaded CRL's next update,
      negative once passed);
    - `port49_cert_status_unavailable_total`.

    `crl` is a source's configured name.

- [ ] **Step 1: The tests.** Create `internal/certstatus/certstatus_test.go`. Build CRLs with
  `x509.CreateRevocationList` over a `testpki.CA`'s certificate and key, served from an
  `httptest.Server` or written to a temp file; build an intermediate with `ca.Issue(testpki.Leaf{…,
  CA: true})` if `testpki.Leaf` has a CA field (otherwise `x509.CreateCertificate` with `IsCA`
  directly). The cases, each a `t.Run`:
  1. a fresh CRL that does not name the leaf: `Good`, source `crl`;
  2. one that names it: `Revoked`, with its revocation time;
  3. one past its `NextUpdate`: `Unknown`, its detail naming the source and "past its next
     update"; and the same stale CRL naming the leaf is still `Revoked`;
  4. a CRL signed by another CA under the same issuer name: does not apply, so the leaf is
     `Unknown` ("no fresh CRL or OCSP answer covers issuer …");
  5. an intermediate-issued leaf, chain `[leaf, intermediate, root]`, against the intermediate's
     CRL: applies (it verifies against `chain[1]`); the root's CRL does not;
  6. a CRL carrying the delta-CRL indicator extension (OID 2.5.29.27): refused at load,
     `CRLLoads{outcome="refused"}`, the last good kept;
  7. `OnNewEntry` is called for each serial a second load adds, and only those, with the issuer as
     `pkix.Name.String()` prints it and the serial as `big.Int.Text(16)`;
  8. a URL source that redirects is refused, and one over 16 MiB is refused;
  9. a source that fails to load keeps the last good list, says it once, and counts `failed`.

  Create `internal/certstatus/ocsp_test.go`. Run an `httptest.Server` OCSP responder that signs
  with the issuing CA via `ocsp.CreateResponse`. It answers `good`, `revoked` and an unsigned
  garbage body by query; it counts calls; and it can hang past the timeout. The cases:
  - `good` caches until its `NextUpdate`: a second `Check` makes no call;
  - `revoked` is `Revoked`;
  - garbage and a hang are `Unknown` within `Timeout`;
  - `use_aia` reads the leaf's `OCSPServer`;
  - a fresh CRL covering the issuer means no OCSP call at all.

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/certstatus/ -count=1`
  Expected: FAIL to compile.

- [ ] **Step 3: The checker.** Create `internal/certstatus/certstatus.go`:

  ```go
  // Package certstatus answers whether a client certificate is revoked, from
  // the CRLs and OCSP responder port49d's broker.certificate_status names
  // (spec §5.1.4; decision 33). A CRL is trusted by its signature alone,
  // against the certificate that verified the leaf; an OCSP answer by its
  // signature for the leaf's issuer. It decides nothing about policy: the
  // broker reads its Result.
  package certstatus

  // Verdict is a certificate's status.
  type Verdict int

  const (
  	Good Verdict = iota
  	Revoked
  	Unknown
  )

  func (v Verdict) String() string { return [...]string{"good", "revoked", "unknown"}[v] }

  // Result is one Check: the verdict, which kind of source gave it and its
  // name, when a revoked certificate was revoked, and for Unknown why.
  type Result struct {
  	Verdict   Verdict
  	Source    string // "crl", "ocsp", or "none"
  	Name      string
  	RevokedAt time.Time
  	Detail    string
  }

  type CRLSource struct{ Name, File, URL string }

  type OCSPConfig struct {
  	Responder string
  	UseAIA    bool
  	Timeout   time.Duration
  }

  type Config struct {
  	CRLs            []CRLSource
  	OCSP            *OCSPConfig
  	RefreshInterval time.Duration
  }

  // Checker holds the loaded CRLs and the OCSP cache.
  type Checker struct {
  	cfg  Config
  	now  func() time.Time
  	m    *metrics.Metrics
  	logf func(string, ...any)
  	http *http.Client

  	mu       sync.Mutex
  	crls     map[string]*loadedCRL // by source name; the last good load
  	verified map[[2]string]bool    // (source, issuer cert sha256) whose signature verified
  	ocsp     map[string]ocspEntry  // by issuer key hash ‖ serial
  	onNew    func(issuer, serial, source string)
  	said     map[string]time.Time  // a line once per key per 10m
  }

  // Check is chain's status: chain[0] the leaf, chain[1] the certificate that
  // verified it (the leaf itself for a one-certificate chain). A CRL that
  // names the serial is final, stale or not. Otherwise a fresh CRL covering
  // the issuer is Good. Otherwise OCSP, when configured, decides. Otherwise
  // Unknown, saying why.
  func (c *Checker) Check(ctx context.Context, chain []*x509.Certificate) Result {
  	leaf, issuer := chain[0], chain[0]
  	if len(chain) > 1 {
  		issuer = chain[1]
  	}
  	res := c.checkCRLs(leaf, issuer)
  	if res.Verdict == Unknown && c.cfg.OCSP != nil {
  		if o := c.checkOCSP(ctx, leaf, issuer); o.Verdict != Unknown {
  			res = o
  		} else {
  			res.Detail = strings.TrimSpace(res.Detail + "; " + o.Detail)
  		}
  	}
  	c.m.CertStatusChecks.WithLabelValues(res.Source, res.Verdict.String()).Inc()
  	if res.Verdict == Unknown {
  		c.m.CertStatusUnavailable.Inc()
  	}
  	return res
  }
  ```

  (imports as used; `Describe` lists each CRL source with its loaded list's `NextUpdate`, or "not
  loaded", and the OCSP responder, for the start line.)

- [ ] **Step 4: The CRLs.** Create `internal/certstatus/crl.go`:

  ```go
  // loadedCRL is one source's last good list.
  type loadedCRL struct {
  	name     string
  	list     *x509.RevocationList
  	revoked  map[string]time.Time // serial as big.Int.Text(16) → revocation time
  	loadedAt time.Time
  }

  const (
  	crlMax       = 16 << 20
  	crlFetchTime = 30 * time.Second
  )

  // oidDeltaCRLIndicator marks a delta CRL, which is refused: a delta read as
  // a full list would leave every serial it does not repeat unrevoked.
  var oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}

  // LoadAll loads every source once, keeping each source's last good list
  // when a load fails, and returns the failures.
  func (c *Checker) LoadAll(ctx context.Context) []error {
  	var errs []error
  	for _, src := range c.cfg.CRLs {
  		if err := c.load(ctx, src); err != nil {
  			errs = append(errs, fmt.Errorf("CRL %s: %w", src.Name, err))
  		}
  	}
  	return errs
  }

  // Run reloads every source each RefreshInterval until ctx ends.
  func (c *Checker) Run(ctx context.Context) {
  	t := time.NewTicker(c.cfg.RefreshInterval)
  	defer t.Stop()
  	for {
  		select {
  		case <-ctx.Done():
  			return
  		case <-t.C:
  			for _, err := range c.LoadAll(ctx) {
  				c.say(err.Error(), "port49d: broker: certificate status: %s; the last good list stays in force until its next update",
  					printsafe.Line(err.Error(), 300))
  			}
  			c.gauge()
  		}
  	}
  }

  func (c *Checker) load(ctx context.Context, src CRLSource) error {
  	raw, err := c.fetch(ctx, src)
  	if err != nil {
  		c.m.CRLLoads.WithLabelValues(src.Name, "failed").Inc()
  		return err
  	}
  	if blk, _ := pem.Decode(raw); blk != nil && blk.Type == "X509 CRL" {
  		raw = blk.Bytes
  	}
  	list, err := x509.ParseRevocationList(raw)
  	if err != nil {
  		c.m.CRLLoads.WithLabelValues(src.Name, "failed").Inc()
  		return fmt.Errorf("does not parse as a CRL: %w", err)
  	}
  	for _, ext := range list.Extensions {
  		if ext.Id.Equal(oidDeltaCRLIndicator) {
  			c.m.CRLLoads.WithLabelValues(src.Name, "refused").Inc()
  			return errors.New("is a delta CRL; name the full CRL")
  		}
  	}
  	l := &loadedCRL{name: src.Name, list: list, revoked: map[string]time.Time{}, loadedAt: c.now()}
  	for _, e := range list.RevokedCertificateEntries {
  		l.revoked[e.SerialNumber.Text(16)] = e.RevocationTime
  	}
  	c.mu.Lock()
  	prev := c.crls[src.Name]
  	if prev != nil && prev.list.Number != nil && list.Number != nil && list.Number.Cmp(prev.list.Number) < 0 {
  		c.mu.Unlock()
  		c.m.CRLLoads.WithLabelValues(src.Name, "refused").Inc()
  		return fmt.Errorf("its CRL number %s is below the loaded one's %s; an older list is not taken", list.Number, prev.list.Number)
  	}
  	c.crls[src.Name] = l
  	for k := range c.verified {
  		if k[0] == src.Name {
  			delete(c.verified, k) // a new list's signature is checked again
  		}
  	}
  	onNew := c.onNew
  	c.mu.Unlock()
  	outcome := "loaded"
  	if prev != nil && bytes.Equal(prev.list.Raw, list.Raw) {
  		outcome = "unchanged"
  	}
  	c.m.CRLLoads.WithLabelValues(src.Name, outcome).Inc()
  	if onNew != nil {
  		for serial := range l.revoked {
  			if prev == nil {
  				onNew(list.Issuer.String(), serial, src.Name)
  			} else if _, had := prev.revoked[serial]; !had {
  				onNew(list.Issuer.String(), serial, src.Name)
  			}
  		}
  	}
  	return nil
  }

  // fetch reads a source: a regular file, or a URL over HTTP(S) with no
  // redirect, within crlFetchTime, at most crlMax bytes. Transport trust
  // adds nothing: the list is trusted by its signature (decision 33).
  func (c *Checker) fetch(ctx context.Context, src CRLSource) ([]byte, error) {
  	if src.File != "" {
  		f, err := os.Open(src.File)
  		if err != nil {
  			return nil, err
  		}
  		defer f.Close()
  		raw, err := io.ReadAll(io.LimitReader(f, crlMax+1))
  		if err == nil && len(raw) > crlMax {
  			err = fmt.Errorf("is larger than %d bytes", crlMax)
  		}
  		return raw, err
  	}
  	ctx, cancel := context.WithTimeout(ctx, crlFetchTime)
  	defer cancel()
  	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
  	if err != nil {
  		return nil, err
  	}
  	resp, err := c.http.Do(req)
  	if err != nil {
  		return nil, err
  	}
  	defer resp.Body.Close()
  	if resp.StatusCode != http.StatusOK {
  		return nil, fmt.Errorf("answered %s", resp.Status)
  	}
  	raw, err := io.ReadAll(io.LimitReader(resp.Body, crlMax+1))
  	if err == nil && len(raw) > crlMax {
  		err = fmt.Errorf("is larger than %d bytes", crlMax)
  	}
  	return raw, err
  }

  // checkCRLs reads every loaded list whose issuer is the leaf's issuer and
  // whose signature verifies against issuer.
  func (c *Checker) checkCRLs(leaf, issuer *x509.Certificate) Result {
  	now := c.now()
  	c.mu.Lock()
  	defer c.mu.Unlock()
  	serial := leaf.SerialNumber.Text(16)
  	sum := sha256.Sum256(issuer.Raw)
  	var fresh *loadedCRL
  	var stale []string
  	for _, l := range c.crls {
  		if !bytes.Equal(l.list.RawIssuer, leaf.RawIssuer) {
  			continue
  		}
  		key := [2]string{l.name, hex.EncodeToString(sum[:])}
  		ok, seen := c.verified[key]
  		if !seen {
  			ok = l.list.CheckSignatureFrom(issuer) == nil
  			c.verified[key] = ok
  		}
  		if !ok {
  			continue
  		}
  		if at, revoked := l.revoked[serial]; revoked {
  			return Result{Verdict: Revoked, Source: "crl", Name: l.name, RevokedAt: at}
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
  	detail := fmt.Sprintf("no fresh CRL or OCSP answer covers issuer %q", printsafe.Line(leaf.Issuer.String(), 200))
  	if len(stale) > 0 {
  		detail = strings.Join(stale, "; ")
  	}
  	return Result{Verdict: Unknown, Source: "none", Detail: detail}
  }
  ```

  `New` builds `http` as `&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
  return errors.New("a CRL source does not redirect") }}`, and `gauge` sets
  `CRLNextUpdate{crl}` to the seconds from now to each loaded list's next update. `say` is the 7a
  listener's once-per-key-per-10m line.

- [ ] **Step 5: OCSP.** Create `internal/certstatus/ocsp.go`:

  ```go
  type ocspEntry struct {
  	res     Result
  	expires time.Time
  }

  // ocspMaxCache bounds how long an answer is reused: a revocation reaches
  // the broker within it even from a responder that sets a far NextUpdate.
  const ocspMaxCache = time.Hour

  // checkOCSP asks the responder for leaf, reusing a cached answer until its
  // NextUpdate (at most ocspMaxCache). The answer must be signed for issuer
  // (ocsp.ParseResponseForCert). Unreachable, unsigned or malformed is
  // Unknown, not cached.
  func (c *Checker) checkOCSP(ctx context.Context, leaf, issuer *x509.Certificate) Result {
  	now := c.now()
  	key := ocspKey(leaf, issuer)
  	c.mu.Lock()
  	if e, ok := c.ocsp[key]; ok && now.Before(e.expires) {
  		c.mu.Unlock()
  		return e.res
  	}
  	c.mu.Unlock()
  	url := c.cfg.OCSP.Responder
  	if url == "" && c.cfg.OCSP.UseAIA && len(leaf.OCSPServer) > 0 {
  		url = leaf.OCSPServer[0]
  	}
  	if url == "" {
  		return Result{Verdict: Unknown, Source: "none", Detail: "no OCSP responder for this certificate"}
  	}
  	unknown := func(why string) Result {
  		return Result{Verdict: Unknown, Source: "none", Detail: "OCSP " + printsafe.Line(url, 120) + ": " + why}
  	}
  	reqBody, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
  	if err != nil {
  		return unknown(err.Error())
  	}
  	ctx, cancel := context.WithTimeout(ctx, c.cfg.OCSP.Timeout)
  	defer cancel()
  	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
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
  	r, err := ocsp.ParseResponseForCert(raw, leaf, issuer)
  	if err != nil {
  		return unknown("its answer does not verify for this issuer")
  	}
  	res := Result{Verdict: Unknown, Source: "ocsp", Name: url}
  	switch r.Status {
  	case ocsp.Good:
  		res.Verdict = Good
  	case ocsp.Revoked:
  		res.Verdict, res.RevokedAt = Revoked, r.RevokedAt
  	default:
  		return unknown("answered unknown")
  	}
  	exp := now.Add(ocspMaxCache)
  	if !r.NextUpdate.IsZero() && r.NextUpdate.Before(exp) {
  		exp = r.NextUpdate
  	}
  	c.mu.Lock()
  	c.ocsp[key] = ocspEntry{res: res, expires: exp}
  	c.mu.Unlock()
  	return res
  }

  func ocspKey(leaf, issuer *x509.Certificate) string {
  	sum := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
  	return hex.EncodeToString(sum[:]) + "|" + leaf.SerialNumber.Text(16)
  }
  ```

  A revoked answer is cached too: a certificate once revoked stays so.

- [ ] **Step 6: The metrics.** Add the four metrics with the names and labels above to `metrics.go`
  and its test.

- [ ] **Step 7: Run them.** `go test ./internal/certstatus/ ./internal/daemon/metrics/ -count=1 -race`
  → PASS. `go mod tidy` leaves `go.mod`'s `require` lines unchanged. Then `gofmt -w`,
  `make build && make test && make vet`.

- [ ] **Step 8: Commit.**

  ```bash
  git add internal/certstatus internal/daemon/metrics go.mod go.sum
  git commit -m "feat(certstatus): CRLs trusted by their signature, OCSP with a bounded cache

  A CRL applies to a leaf when its issuer name is the leaf's and it verifies against the
  certificate that verified the leaf, until its next update; a delta CRL and an older CRL
  number are refused; a failed load keeps the last good. OCSP answers must verify for the
  issuer and are cached to NextUpdate, at most an hour. New CRL entries are reported.

  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
  ```

---

### Task 10: The broker refuses a revoked or unestablished certificate at bind, mint and refresh, and revokes what a CRL newly names

**Files:**
- Create: `internal/broker/certcheck.go` (`StatusChecker`, `certRefusal`, `BindStatus`,
  `OnCRLEntry`)
- Modify: `internal/broker/broker.go` (`Broker.CertStatus`, `Broker.OnUnavailable`; the check in
  `tokens`)
- Modify: `internal/broker/sessionrefresh.go` (the check in `refresh`)
- Modify: `internal/broker/listen.go` (`Listener.Status`; `ConnCloser.HoldsCert`;
  `answerRevoked` generalised to a refusal's code; `Refused` takes the reason)
- Test: `internal/broker/certcheck_test.go`, `internal/broker/listen_test.go`

**Interfaces:**
- Consumes: Task 9's `Checker.Check`, `Result`; 7a's `Revoke`, `refuseRevoked`, `answerRevoked`,
  `Refused`.
- Produces:
  - `type StatusChecker interface { Check(ctx context.Context, chain []*x509.Certificate) certstatus.Result }`
  - `Broker.CertStatus StatusChecker` (nil: no checking, port49d's `disabled: true`),
    `Broker.OnUnavailable string` (`"refuse"` | `"allow"`)
  - `type BindRefusal struct { Reason decision.Reason; Error, Detail string }` and
    `func (b *Broker) BindStatus(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal`,
    which port49d sets as `Listener.Status`
  - `func (b *Broker) OnCRLEntry(issuer, serial, source string)`, which port49d sets with
    `Checker.OnNewEntry`
  - `ConnCloser` gains `HoldsCert(certKey string) bool`
  - `Listener.Refused func(principal string, cred store.Credential, reason decision.Reason)` (7a's
    callback, with the reason added: `credential_revoked` for a mark, as before)

- [ ] **Step 1: The tests.** Create `internal/broker/certcheck_test.go` with a `fakeStatus` whose
  `Check` returns a set `certstatus.Result` per serial:
  - **A `Revoked` certificate.**
    - It is answered `401 credential_revoked` at bind, through `serveThrough` with `Listener.Status`
      set, and recorded `mint deny credential_revoked`.
    - Posting with that certificate is refused `credential_revoked` at mint and at refresh.
    - Each refusal starts a `Broker.Revoke` with origin `ocsp …` or `crl …`; wait for the mark with
      `eventually`.
  - **An `Unknown` status.**
    - With `OnUnavailable: "refuse"`, a mint is answered `401 trust_domain_unresolved`, its detail
      naming the result's `Detail`.
    - With `"allow"`, the mint goes through and the line is said once.
  - **`OnCRLEntry`** for:
    - a certificate with a held connection: `Revoke` runs, the connection is closed, the mark's origin
      is `crl corp`;
    - a certificate with a live context or an unspent token: `Revoke` runs;
    - a certificate with none of the three: no mark is written.
  - **No checker.** With `CertStatus` nil, nothing is checked (`fakeStatus` is never called).

  In `listen_test.go`, update 7a's tests for `Refused`'s new parameter.

- [ ] **Step 2: Run them to see them fail.** `go test ./internal/broker/ -run 'Status|CRL' -count=1`
  Expected: FAIL to compile.

- [ ] **Step 3: The broker's check.** Create `internal/broker/certcheck.go`:

  ```go
  // StatusChecker is certstatus.Checker as the broker sees it.
  type StatusChecker interface {
  	Check(ctx context.Context, chain []*x509.Certificate) certstatus.Result
  }

  // BindRefusal is why a connection is answered and closed as it binds.
  type BindRefusal struct {
  	Reason        decision.Reason
  	Error, Detail string
  }

  // certRefusal is the certificate's status as a refusal, or nil to go on
  // (spec §5.1.4; decision 33). A revoked certificate is refused and revoked
  // through Revoke, detached, so every path reaches it and the mark outlives
  // a source that later goes stale. Unknown is refused unless OnUnavailable
  // is "allow".
  func (b *Broker) certRefusal(ctx context.Context, cs *tls.ConnectionState, cred store.Credential) *BindRefusal {
  	if b.CertStatus == nil || cs == nil || len(cs.VerifiedChains) == 0 {
  		return nil
  	}
  	res := b.CertStatus.Check(ctx, cs.VerifiedChains[0])
  	switch res.Verdict {
  	case certstatus.Revoked:
  		go b.revokeFromStatus(cred, res)
  		return &BindRefusal{Reason: decision.CredentialRevoked, Error: string(decision.CredentialRevoked),
  			Detail: fmt.Sprintf("this certificate was revoked at its CA (%s %s, revoked %s); nothing is minted for it",
  				res.Source, printsafe.Line(res.Name, 120), res.RevokedAt.UTC().Format(time.RFC3339))}
  	case certstatus.Unknown:
  		if b.OnUnavailable == "allow" {
  			b.logf("broker: admitting a certificate whose revocation status cannot be established (%s); "+
  				"broker.certificate_status.on_unavailable is allow", res.Detail)
  			return nil
  		}
  		return &BindRefusal{Reason: decision.TrustDomainUnresolved, Error: string(decision.TrustDomainUnresolved),
  			Detail: "the broker cannot establish this certificate's revocation status (" + res.Detail +
  				"); it mints nothing until it can"}
  	}
  	return nil
  }

  // revokeFromStatus revokes a certificate its CA revoked, as `port49 revoke
  // --cert` does (Revoke's semaphore serialises it with the rest).
  func (b *Broker) revokeFromStatus(cred store.Credential, res certstatus.Result) {
  	ctx, cancel := context.WithTimeout(context.Background(), b.revokeTimeout())
  	defer cancel()
  	origin := res.Source + " " + res.Name
  	if _, err := b.Revoke(ctx, RevokeRequest{Issuer: cred.Issuer, Serial: cred.Serial, Origin: origin}); err != nil {
  		b.logf("broker: revoking a certificate its CA revoked (%s): %v; it is refused at every use anyway", origin, err)
  	}
  }

  // BindStatus is Listener.Status: the check at bind, before a connection is
  // held.
  func (b *Broker) BindStatus(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal {
  	ctx, cancel := context.WithTimeout(context.Background(), holdTimeout)
  	defer cancel()
  	return b.certRefusal(ctx, &cs, cred)
  }

  // OnCRLEntry revokes a certificate a CRL newly names wherever it is still
  // present: a held connection, a live context, an unspent token (decision
  // 33). One present nowhere is not marked: the CRL refuses it at its next
  // use, and a mark per entry of a large CRL would grow the revocations file
  // without bound.
  func (b *Broker) OnCRLEntry(issuer, serial, source string) {
  	key := store.CertKey(issuer, serial)
  	ctx, cancel := context.WithTimeout(context.Background(), holdTimeout)
  	defer cancel()
  	present := b.Conns != nil && b.Conns.HoldsCert(key)
  	if !present {
  		refs, err := b.Store.ContextsByCert(ctx, key)
  		toks, err2 := b.Store.TokensByCert(ctx, key)
  		present = len(refs) > 0 || len(toks) > 0 || err != nil || err2 != nil // a store error errs toward revoking
  	}
  	if !present {
  		return
  	}
  	b.logf("broker: CRL %s names a certificate in use (issuer=%q, serial=%s); revoking it", source, issuer, serial)
  	b.revokeFromStatus(store.Credential{Issuer: issuer, Serial: serial},
  		certstatus.Result{Verdict: certstatus.Revoked, Source: "crl", Name: source})
  }
  ```

  (`b.revokeTimeout()` is 7a's accessor for `RevokeTimeout` or its default; use what the tree
  names.) Add to `Broker`:

  ```go
  	// CertStatus answers a client certificate's revocation status (spec
  	// §5.1.4; decision 33): nil checks nothing, port49d's `disabled: true`.
  	// OnUnavailable is "refuse" or "allow", for a status it cannot establish.
  	CertStatus    StatusChecker
  	OnUnavailable string
  ```

  In `tokens`, after the mark check and before the body is read:

  ```go
  	if ref := b.certRefusal(checkCtx2, r.TLS, cred); ref != nil {
  		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: ref.Reason,
  			Principal: principal, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
  		w.Header().Set("Connection", "close")
  		writeError(w, http.StatusUnauthorized, ref.Error, ref.Detail)
  		return
  	}
  ```

  (with its own `holdTimeout` context), and the same in `refresh` where Task 7 left the comment,
  recording `refresh deny` and counting `SessionRefreshes{outcome="revoked"}` for a revocation or
  `"refused"` for unknown.

- [ ] **Step 4: The listener.** In `listen.go`: add to `Listener`

  ```go
  	// Status answers a certificate's revocation status as it binds (spec
  	// §5.1.4): a refusal is answered, recorded (Refused) and closed, as a
  	// mark is. port49d sets it to Broker.BindStatus; nil checks nothing.
  	Status func(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal
  ```

  In `handshake`, after `bind` returns no mark and before the connection is handed over, call
  `l.Status` when set. On a refusal, unbind the connection (it was just bound: give back the
  principal's slot as `forget` would, by closing it after answering) and answer it as
  `answerRevoked` does, with the refusal's code and detail.

  Generalise `answerRevoked(tc, rv, …)` to `answerRefused(tc, api.Error, principal, cred,
  reason)`. The mark path passes `revokedError(rv)` and `decision.CredentialRevoked`; the status
  path passes the refusal's. Give `Refused` the reason, and update port49d's setter
  (`Broker.RefusedAtBind`) to record it. Add `HoldsCert`:

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

  and add `HoldsCert(certKey string) bool` to `ConnCloser`, updating 7a's `fakeConns`.

- [ ] **Step 5: The agent.** A `401 trust_domain_unresolved` at `Connect` or at a mint already ends
  the session with the broker's detail (`sessionOver`). Add an agent test that its error text carries
  "cannot establish this certificate's revocation status".

- [ ] **Step 6: Run them.** `go test ./internal/broker/... ./internal/agent/ -count=1 -race` → PASS.
  Then `gofmt -w`, `make build && make test && make vet`.

- [ ] **Step 7: Commit.**

  ```bash
  git add internal/broker internal/agent
  git commit -m "feat(broker): refuse a revoked or unestablished certificate at bind, mint and refresh

  A certificate a CRL or OCSP revokes is answered credential_revoked as it binds and refused at
  every mint and refresh, and is revoked through Revoke (origin crl or ocsp) so everything it
  holds is reached. A status that cannot be established is refused trust_domain_unresolved
  unless on_unavailable is allow. A CRL's new entry is revoked wherever it is still present.

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
      crls: [{name: corp_issuing, url: http://pki.example.com/corp.crl}]   # or file: /path
      ocsp: {responder: http://ocsp.example.com, use_aia: false, timeout: 2s}
      refresh_interval: 10m          # 1m..24h
      on_unavailable: refuse         # refuse | allow
    ```
  - `func (c CertificateStatusConfig) Checker() certstatus.Config`

- [ ] **Step 1: The config's tests.** In `internal/config/broker_test.go`, add
  `  certificate_status: {disabled: true}` to `brokerBlock`, and test the following, each refusal
  naming its key:
  - the block absent refuses (`broker.certificate_status`);
  - `disabled: true` beside a source refuses;
  - a block with neither a CRL nor OCSP refuses;
  - a CRL with both or neither of `file` and `url` refuses;
  - a `url` that is not `http` or `https` refuses;
  - a name off `^[a-z][a-z0-9_]{0,63}$`, or a duplicate name, refuses;
  - `refresh_interval: 30s` and `25h` refuse;
  - `ocsp.timeout: 50ms` and `11s` refuse;
  - an OCSP block with neither `responder` nor `use_aia` refuses;
  - `on_unavailable: maybe` refuses;
  - a well-formed block loads, with defaults `refresh_interval` 10m, `ocsp.timeout` 2s and
    `on_unavailable` `refuse`.

- [ ] **Step 2: port49d's tests.** Create `cmd/port49d/certstatus_test.go`:
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

  add `CertificateStatus *CertificateStatusConfig `yaml:"certificate_status"`` to `BrokerConfig`
  (comment: "required (plan 7b); see CertificateStatusConfig"), validate it in `Load`'s broker block
  as Step 1 tests (applying the defaults in place), and add `Checker()` mapping it onto
  `certstatus.Config` (`OCSP` nil when absent).

- [ ] **Step 5: The wiring.** In `cmd/port49d/main.go`, after `buildBroker` and the revocations restore:

  ```go
  	if brk != nil {
  		cs := cfg.Broker.CertificateStatus
  		if cs.Disabled {
  			fmt.Fprintln(stderr, "port49d: broker: certificate status checking is disabled "+
  				"(broker.certificate_status.disabled): a certificate revoked at its CA keeps minting until "+
  				"`port49 revoke --cert`")
  		} else {
  			checker := certstatus.New(cs.Checker(), time.Now, m,
  				func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) })
  			checker.OnNewEntry(brk.OnCRLEntry)
  			loadCtx, cancelLoad := context.WithTimeout(ctx, 60*time.Second)
  			// A source that does not load at start does not stop the start: the
  			// daemon serves device AAA whatever the CA's publisher does, and the
  			// broker refuses what it cannot establish (on_unavailable).
  			for _, err := range checker.LoadAll(loadCtx) {
  				fmt.Fprintf(stderr, "port49d: broker: certificate status: %s\n", printsafe.Line(err.Error(), 300))
  			}
  			cancelLoad()
  			brk.CertStatus, brk.OnUnavailable = checker, cs.OnUnavailable
  			go checker.Run(ctx)
  			fmt.Fprintf(stderr, "port49d: broker: certificate status from %s; a status that cannot be established is %s\n",
  				checker.Describe(), map[string]string{"refuse": "refused", "allow": "allowed, alarmed"}[cs.OnUnavailable])
  		}
  	}
  ```

  and where the listener is built, set `bl.Status = brk.BindStatus` beside `bl.Refused`.
  `checker.Run`'s goroutine ends with `ctx`, which `run` cancels at shutdown: join it as the fetcher
  is joined (plan 6b, F8).

- [ ] **Step 6: The fixtures.** Add `CertificateStatus: &config.CertificateStatusConfig{Disabled: true}` to
  `brokerConfig`, `  certificate_status: {disabled: true}` to `writeRunConfig`'s broker block, the
  two lab broker YAMLs and `inventory_test.go`'s broker blocks, and to `config_test.go`'s inline
  broker blocks. (The lab's slice and revoke runs check no certificate status; Task 12 does not
  need it.)

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
- Create: `tests/lab/slice/session-policy.yaml`: the slice policy with `max_session_age: 4m` on
  `network_admin`
- Create: `tests/lab/session_test.go` (`//go:build lab`): `TestSessionLifetime`
- Create: `tests/lab/l2_test.go` (`//go:build lab`): `TestL2Truncation`
- Create (by the run): `tests/lab/results/L34-<platform>.md`, `session-<platform>.md`,
  `L2-<platform>.md` (rewritten); redacted captures under `tests/lab/evidence/`

**Interfaces:**
- Consumes: the lab harness (`eachPlatform`, `derivedConfig`, `startDaemonWith`, `shell`,
  `labShell.runOrEnd`, `loginWithin`, `waitForRecords`, `result`); 7a's `revokeAgent`, `agentEnded`;
  the slice's PKI and broker block; `bin/port49 refresh` (Task 8).

**L34 is new; L2 stays open until every image in its row is measured.** L34's claim is the warning's
premise, opened by Task 1. L2's clauses still open are the truncation length, IOS-XE and the N9Kv.

- [ ] **Step 1: The policy.** `tests/lab/slice/session-policy.yaml` is `tests/lab/slice/policy.yaml`
  with `max_session_age: 4m` added to the `network_admin` role and its header comment saying so
  ("plan 7b's session run: a ceiling short enough to wait out").

- [ ] **Step 2: `TestSessionLifetime`.** For each platform it:
  1. Starts port49d with the slice's broker block (`policy_file` pointed at `session-policy.yaml`) and
     `session: {ceiling_warning: 3m, grace_window: 2m}` appended.
  2. Runs `port49 login`, then waits 70 s. The 4m ceiling is now under 3m away, from the
     connection's handshake.
  3. **Login inside the warning.** It mints, then logs in over SSH with the token and records:
     - the device's text before the first prompt (the session reply's `server_msg`, L34's session
       clause);
     - the `authorize_session` record's `server_msg`.
  4. **A command inside the warning.** It runs `show version` and records the device's text around
     the command output (the per-command clause), and whether the output appeared.
  5. **The refresh.** It runs `port49 refresh`, then `show version` again, and records that no
     warning is sent and the output appears. The refresh's output names one extended session (on
     Junos, also "not reached").
  6. **Past the ceiling.** It waits until 4m after the refresh, plus 10 s, and runs `show version`
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
  `stopSliceAgentIfRunning` pattern.

- [ ] **Step 3: `TestL2Truncation`.** For each platform it:
  - restarts port49d on the standing lab config, with `  deny_message_length: N` inserted under
    `lab:`, for N in 64, 128, 200, 255, 256, 512 and 1000;
  - logs in with a seeded token and runs a command the lab denies (its `deny_prefixes`);
  - records what the device printed and the longest prefix of the padded message it shows, read off
    the counting pattern.

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

- [ ] **Step 1: L34.** If every platform in the row was measured, set its Status to `closed —
  measured <date>; tests/lab/results/L34-<platform>.md, …`, with one line per platform: shown or not
  shown, still a permit. Where a platform does not show it, §5.6's text says the warning reaches that
  platform's operators only through `port49 token`, citing the note. Where a platform does not treat
  it as a permit, add the platform to `ceilingWarningOff` with a comment citing the note, test it,
  and commit that as `fix(platform): no ceiling warning on <platform> (L34)` before the docs.
- [ ] **Step 2: L2.** With every image measured, set L2's Status to closed with the display and the
  truncation length per platform. Otherwise list what is measured and leave it open (register rule
  5).
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
    hardware key's touch on refresh.
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
    least of its roles' (a role naming none takes `session.max_session_age_default`).
  - Shortening a role reaches live sessions at the next policy refresh. Lengthening one applies
    from each operator's next `port49 refresh` or login.
- **New: `port49 refresh`.**
  - It re-authenticates on your held broker connection and extends every live device session your
    policy still grants: no reconnect, and the candidate configuration stays intact.
  - `port49 login` does the same when you are already logged in.
  - It prints what was extended, what the policy revoked, what is past the grace window (log in
    again there), and what is on a platform it cannot reach (Junos keeps its own session).
  - With today's PEM key file it proves you hold the key, not that you are at the keyboard; a
    hardware key (plan 9) adds the touch.
- **The warning.**
  - Within `session.ceiling_warning` (default 30m) of the end, permitted commands carry `port49:
    session ends in Nm - run 'port49 refresh'`, on devices that show it (see the L34 notes).
  - `port49 token` prints the same on stderr for the device it mints for.
  - `0s` turns the server_msg warning off.
- **Past the end.**
  - Commands are refused `session expired - run 'port49 refresh' within Nm to resume` for
    `session.grace_window` (default 10m); `port49 refresh` in that window resumes the session.
  - After it the session is deleted: `session ended - get a new token and log in again`.
- **New required key: `broker.certificate_status`.**
  - Name your CA's CRLs (`file:` or `url:`) and/or an OCSP responder, or write `disabled: true` to
    choose not to check (said at every start).
  - A certificate a CRL or OCSP revokes is refused at login and at every mint. If it holds anything
    (a connection, a device session, an unspent token), port49d revokes it as `port49 revoke --cert`
    would: see `port49 revoke --list` (origin `crl …`).
- **`on_unavailable: refuse` (the default).** A CRL past its next update or an OCSP responder that is
  down refuses new logins and mints for that issuer. Live device sessions and break-glass are
  unaffected. Alert on `port49_crl_next_update_seconds < 3600` and on
  `port49_cert_status_unavailable_total`. `allow` keeps logins working through an outage, and lets
  a certificate revoked during it in until the CRL returns (owner decision D-7b-1).
- **New metrics:**
  - `port49_session_refreshes_total{outcome}`
  - `port49_ceiling_warnings_total`
  - `port49_cert_status_checks_total{source,result}`
  - `port49_crl_loads_total{crl,outcome}`
  - `port49_crl_next_update_seconds{crl}`
  - `port49_cert_status_unavailable_total`
- **New records:**
  - **`refresh permit grants_matched`** for each session a refresh extended, with `auth_time` and
    `session_expires`.
  - **`refresh deny session_expired`** for one past its grace window.
  - **`refresh deny trust_domain_unresolved`** for a refresh signature that did not verify.
  - **`mint deny session_expired`** per device whose session is already over.
  - **`mint deny trust_domain_unresolved`** when a certificate's status cannot be established.
  - **`unreached: true`** on refresh records for session-only platforms.
- **API:**
  - `POST /v1/refresh/challenge` and `POST /v1/refresh`, on the held connection only.
  - `GET /v1/config` gains `ceiling_warning_seconds`.
  - Mint items gain `session_expires_at`.

## Self-review against the spec

- **§5.6 session lifetime:**
  - per-role and minimum composition: Tasks 2, 3;
  - "`never` MUST be expressible": Task 2;
  - the warning, configurable and long enough: Task 6, with the agent's warning in Task 8;
  - grace: Tasks 4, 6, 7;
  - "Refresh MUST NOT extend a session whose principal has lost the grant": Task 7, via
    `refreshContext`;
  - "a fresh authentication event … the broker's verification time": Task 7;
  - "re-authentication does not require reconnecting": Task 7 moves the connection's clock;
  - teardown row 3: Task 6.
- **§5.1.4.** CRL or OCSP by issuer and serial: Tasks 9–11, feeding decision 32's marks (Task 10).
  The `refresh` records' `unreached` field, carried from 7a: Task 5.
- **§5.7.** No reason code added. `session_expired`, `trust_domain_unresolved` and
  `credential_revoked` gain their meanings in Task 1, before the code (Tasks 3, 7, 10).
- **§15.** L34 is opened before the warning is built (Task 1) and measured (Task 12). The warning
  is provisional on it, with a code switch (Task 6) that Task 13 sets from the notes. L2's open
  clauses are measured in Task 12. No doc asserts what L34 has not measured.
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
  - `ContextPolicy.MaxSessionAge`, `ContextRefresh.GraceCutoff` and `ErrPastGrace` (Task 4), used in
    Tasks 5 and 7;
  - `api.Refresh*` (Task 7), used in Task 8;
  - `certstatus.Result`/`Checker` (Task 9), used in Tasks 10 and 11;
  - `BindRefusal`, `HoldsCert` and `Refused`'s reason (Task 10), used in Task 11.
