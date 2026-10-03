# Plan roadmap

One plan per design §19 step group, written one at a time (see `CLAUDE.md`). This file is
the standing brief for each plan: what it builds, which spec sections it implements, what
earlier plans hand it, what it must leave for later, and which lab register entries close in
it. When writing plan N, start here, then read the cited sections, then the previous plan.

**Every plan's PR body carries an "Operator-facing notes" section**: a short list of what an
operator will see change — new commands, config keys, reason codes, metrics, device behaviour.
Plan 13 builds the user and admin documentation from these.

Status: **1 merged 2026-09-21** (PR #2); **2 merged 2026-09-22** (PR #4;
fifteen tasks, reviewed per task and whole-branch); **3 merged 2026-09-23** (PR #8, below);
**lab 2026-09-24 merged** (PR #9); **4 merged 2026-09-24** (PR #10;
`2026-09-23-04-policy-engine.md`, twenty-three tasks plus a lab fold, reviewed per task and
whole-branch; the five calls in PR #10's "Questions for Ryan" were decided 2026-09-24 and
built on `feature/gate-rulings`: `operator` renders as level 15 on EOS and NX-OS, a level or
ceiling raise and a regex-constrained widening fail `port49 policy diff`, a refused mint always
does, a policy with no tests is reported `no_tests`, and a `lab:` block announces itself at
start; PR #11); **4b merged 2026-09-24** (PR #12;
`2026-09-24-04b-live-policy.md`, eight tasks: one docs, six code, one docs; reviewed per task
and whole-branch;
its three "Questions for Ryan" were decided security-first: delete unspent tokens whose answer
changed, rewrite every live context on every reload, leave a quarantined device's contexts);
**5a merged 2026-09-24** (PR #13; `2026-09-24-05a-platform-adapters.md`, eighteen tasks: one
docs, fifteen code, one lab, one lab-and-docs; reviewed per task, then a final whole-branch
review, one fix wave and two scoped re-reviews; L22 closed, and the EOS, NX-OS and IOS-XE
adapters `verified: containerlab`); plan 5 is split at the seam below. **5b written 2026-09-24,
revised 2026-09-25** after its pre-flight review and the owner's ruling of that day (decision 26)
(`2026-09-24-05b-projection-capabilities.md`, twenty tasks: one docs, three lab, fourteen code,
one lab, one lab-and-docs), **executed 2026-09-25, and Task 19**, the differential lab test, **on 2026-09-29**, and amended in flight with decision 27 and four lab tasks (3b,
L26b, L26c, the L26 rerun); reviewed per task and whole-branch; **merged 2026-09-29** (PR #14). It closed L23, L24, L26 and L26b;
Task 19, run 2026-09-29, closed L9, L10 and L12; L25 and the new L26c stay open (Plan 5b — As
built, below). **6a written 2026-09-30, revised the same day** after its pre-flight review
(`2026-09-30-06a-bundle-in-process.md`, twenty-two tasks: one docs, one lab, eighteen code, one
lab, one lab-and-docs; plan 6 is split at the seam below, and three owner decisions are listed at
its top), and **executed 2026-09-30** on `feature/bundle-in-process`, reviewed per task and
whole-branch, with a final fix wave. It closed L27 and L28 and opened L29 and L30 (Plan 6a — As
built, below); **merged 2026-09-30 (PR #15)**. **6b written 2026-09-30, revised the same day** after
its pre-flight review (`2026-09-30-06b-inventory-service.md`, twenty-two tasks: one docs, one lab,
seventeen code, two lab, one lab-and-docs); it splits again at the source, leaving the NetBox and
Nautobot connectors and the webhook trigger to plan 6c, and three owner decisions are listed at its
top. **Executed 2026-09-30** on `feature/inventory-service`, reviewed per task and whole-branch,
with a fix wave; Task 20's midnight nights were dropped by the owner's ruling. It closed L29 and
L30, and spec §14's quarantine through a sync passed on four images; it opened L31, slow Cisco
break-glass with single-connection on (Plan 6b — As built, below); **merged 2026-09-30 (PR #17)**. Next,
`fix/breakglass-reset`, which closes L31: **written 2026-09-30** (`2026-09-30-06b1-breakglass-reset.md`, seven tasks: one docs, three code, one lab harness, one lab run, one lab-and-docs; no owner decisions); **executed 2026-09-30** on `fix/breakglass-reset`, closing L31 (Fix `fix/breakglass-reset` — As built, below); **merged 2026-09-30 (PR #18)**. **6c written 2026-10-01** (`2026-10-01-06c-inventory-connectors.md`, seventeen tasks after its pre-flight review the same day: one docs, thirteen code, two lab, one lab-and-docs; no owner decisions, fourteen rulings where spec §10 was silent, recorded as decision 31; it opens L32 and L33); **executed 2026-10-01** on `feature/inventory-connectors`, reviewed per task and whole-branch (MERGE, 0/0/8), with a fix wave, closing L32 and L33 (Plan 6c — As built, below); **merged 2026-10-01 (PR #19)**. Plan 7 is **split into 7a–7h** (below, with one owner decision,
D1, the shared store's backend, which 7a–7c do not need); **7a written 2026-10-01**
(`2026-10-01-07a-revocation-and-broker-limits.md`, thirteen tasks: one docs, ten code, one lab,
one docs; no owner decision, ten rulings recorded as decision 32; revised the same day after its
pre-flight review: one critical, seven important and twenty-two minor fixed, one minor rebutted);
**executed 2026-10-01** on `feature/revocation-and-broker-limits`, reviewed per task and
whole-branch (FIX FIRST 0/1/9, then a fix wave and a MERGE re-review), with a lab-driven fix: the first lab run found the
agent surviving a revocation, and the listener now answers a revoked caller `credential_revoked`
(Plan 7a — As built, below); **merged 2026-10-01 (PR #20)**. **7b written 2026-10-01**
(`2026-10-01-07b-session-lifetime-and-cert-status.md`, thirteen tasks: one docs, ten code, one lab,
one lab-and-docs; twelve rulings recorded as decision 33; one owner decision, D-7b-1, whether a
certificate whose revocation status cannot be established is refused (ruled refuse) and whether
certificate status is required (ruled required, with an explicit `disabled`); it opens L34; revised the same day after its pre-flight review: two critical, thirteen important and
twenty-two minor fixed, one minor rebutted in part; its re-check's three important and five minor
fixed the same day); **executed 2026-10-01** on `feature/session-lifetime-and-cert-status`,
reviewed per task, closing L34 with `cisco_iosxe` the one platform that shows the ceiling warning,
and measuring L2 on five images (open: Junos cannot show it) (Plan 7b — As built, below); final
review done 2026-10-02 (one important: a token outlived its ceiling, fixed in the fix wave);
**merged 2026-10-02 (PR #21)**. **7c written 2026-10-02**
(`2026-10-02-07c-api-and-authorization.md`, fourteen tasks: one docs, eleven code, one lab, one
docs; no owner decision, ten rulings recorded as decision 34, decision 32 amended first by the
owner's answer on the revocations volume; no register row); **executed 2026-10-02** on
`feature/api-and-authorization`, reviewed per task and as a whole branch, the HTTP revocation's
shapes measured on vEOS, the N9Kv, the C8000V and vJunos-router (Plan 7c — As built, below);
final review: one important fixed (a slow revocation resent and reported as not done), re-review
clean; **merged 2026-10-02 (PR #22, merge c485e03)**, and `make test` (with the labpcap audit)
passes on main. **7d written 2026-10-02** (`2026-10-02-07d-shared-store.md`, sixteen tasks in two merges: 7d-1, Tasks 1–8, the etcd backend passing every `storetest` property, the login's one step and the lifted suite; 7d-2, Tasks 9–16, the guard, the config, the identities and roles, port49d on etcd, the crypt alarm, the agent's one connection, the lab and the docs; one owner decision, OD-1, the Go floor to 1.26, recommended accept; sixteen rulings recorded as decision 35; it opens and closes L35). **7d-1 merged 2026-10-02** (PR #24, merge fe23595): Tasks 1–8 plus 4b, 6b and 7b. It delivers:
- the etcd backend;
- the crypt sealing layer, with the Logins witness and the revision-ordered Ledger, including the snapshot-restore regression witness;
- the re-index and sweep;
- `storetest` across memory, crypt, etcd and crypt-over-etcd.

The final review found two important issues, both fixed:
- An unparseable lookup key stopped the refresh fleet-wide.
- A wrong encryption key would have revoked every session; a context under an unknown key is now never revoked.

The re-review also fixed r-m1: a refresh that skips anything keeps `port49_policy_refresh_pending` set. The flake fixes merged first, as PR #23.

Carried to Task 12: `ledger.Seal()` needs a test, and must be called only after the start's re-index. Carried to 7d-2: a `{}` answer on the admin socket to `port49 revoke` still exits 0.

**7d-2 executed and merged 2026-10-03 as PR #25** (merge 9282085; base 06d0821;
Tasks 8b–16 plus a new Task 13b, each reviewed). It delivers:
- the guard: a hard timeout on every store call, three pools with a circuit each, and going
  dark;
- `store:` in `port49d.yaml`, and every packet's store deadline;
- an etcd identity and role per component, checked at every start, and `port49d store-roles`;
- port49d on etcd: one per keyspace behind a fenced hold, every standing mark applied at the
  start, live sessions kept across a restart, and going dark in-process when the store is gone;
- the crypt alarm;
- a ledger keyed on each write, so an earlier version of a context put back while port49d
  runs is denied (Task 13b, Ruling T12-g);
- the agent's one connection.

L35 is measured and closed on five images. The lab's snapshot restore found a ledger bug, fixed
in 79812ef (Plan 7d — As built, below). **7e written 2026-10-03** (`2026-10-03-07e-broker-process.md`, eighteen tasks in two merges: 7e-1, Tasks 1–10, the store a fleet of processes shares (a sealed write sequence and a high-water ledger per key, the context and marks feeds, the ledger record the daemon cannot write, `superseded` in the store, the decision-log emits under the hold, two carried fixes); 7e-2, Tasks 11–18, `port49-broker`, port49d on etcd with no broker inside, one runner per keyspace, the revocations file retired on etcd, and the lab; sixteen rulings recorded as decision 36; one question for Ryan, OR-1, `port49 revoke`'s default socket, recommended unchanged; it opens L37 and L38 and measures them with L36); **7e-1 executed 2026-10-03** on `feature/broker-process`, each task reviewed (Plan 7e — As built, below). 7f–7h and 8–13 not yet.
**2b merged 2026-09-23** (PR #7; `2026-09-23-02b-context-join.md`, nine tasks, reviewed
per task and whole-branch): a second login by the same principal joins the live context
instead of replacing it, stored privilege is raise-only, and accounting attribution gets a
metric. PR #7's body lists three fail-closed follow-ups (one uniform "login into a revoked
result" check after `JoinContext`) for plan 3 to pick up.
**3 merged 2026-09-23** (PR #8; `2026-09-23-03-vertical-slice.md`, eighteen tasks:
thirteen code, three lab, two docs; reviewed per task and whole-branch; first real
certificate-to-device login measured on vEOS). It closes PR #7's first two follow-ups and carries the third to plan 7; its
"Questions for Ryan" section has three open calls.

---

## Plan 1 — Protocol core (§19 step 1) — `2026-09-06-01-protocol-core.md`

RFC 8907 wire, key trial, admission from a file inventory, per-source limits, in-memory
store, authentication/authorization/accounting handlers, decision log, config, `port49d`
binary, containerlab harness. Closes L1 (SSH transport only), L2, L5, L6, L8, L10.

## Plan 2 — Token model (§19 step 2) — `2026-09-22-02-token-model.md`

**Rewritten 2026-09-22 and executed on `feature/token-model`.** The 2026-09-06 draft assumed the `(nas, port)`
login-context key, which the lab showed breaks every measured vendor; the key is now
`(nas, username)` (spec §13 decision 15). The rewrite is against the real tree on
`feature/lab-l4-fallthrough` and carries every ruling in
`2026-09-20-plan-2-revision-notes.md`, the owner's 2026-09-21 ones included
(`contexts_by_principal` stays unencrypted, and why). **Fix round 1 applied 2026-09-22** after
review: **fifteen TDD tasks, sixteen commits**. The spec §5.8 edit for `system` attribution is
committed before the code that reads it, and now also carries §13 decision 15's record that the
`(nas, rem_addr)` enable index is deferred while `enable_username: enab` is refused at load.

**Builds:** the full token semantics on top of plan 1's store interface and handlers.

- Token format with the **device tag**: `tag ‖ secret`, `tag = base62(HMAC(k, device_id))[:6]`,
  24 random characters; daemon compares its own tag before any store access; `device_mismatch`
  under PAP/ASCII/HTTP, `token_not_found` under CHAP. Design §8 "Device binding".
- **Encryption at rest** for tokens, receipts, login context, and the idempotency record,
  with a key shared by broker and daemon and a two-key rotation window. Design §8.
- **Sliding receipt, not a `reusable` flag** (owner, 2026-09-21: "Bob shouldn't need to
  know"). Each re-presentation of the same `(nas, username, credential_sha256)` extends the
  receipt by `receipt_idle_ttl`, up to an absolute `receipt_max_age` from first redemption;
  a presentation past either is FAIL on the wire and `token_spent` in the log (the §5.7 row
  landed with decision 15's rewrite on 2026-09-22; the plan adds only the Go constant);
  revocation deletes the principal's receipts, so receipts are indexed by principal.
  **Defaults ruled 2026-09-22: 15 min idle, 2 h absolute** (Ansible linear strategy over a
  large fleet is the sizing case, L15). Decision 15's text is already replaced.
- **Device-generated accounting under another user** (Junos root RPC in production, NX-OS
  `admin` with `task_id=vsh.bin.$port`) must not trip `foreign_session`: a per-platform rule
  attributing them `system`, which needed a spec §5.8 sentence. **Ruling R1 (Task 11) reversed
  the "ships empty" plan on measured evidence, and spec §5.8 now carries the packet dump behind
  it**: `juniper_junos` ships **`root`** (`internal/platform/platform.go:213-216`).
  `tests/lab/evidence/L1-juniper_vsrx.pcap`, the committed capture behind
  `tests/lab/results/L1-juniper_vsrx.md`, holds three accounting records under `user=root`,
  `port=non-tty`, carrying their own `session_pid`, with no authentication and no authorization
  exchange for root anywhere in the file — vSRX's own alarm machinery writing accounting for a
  session port49 was never asked to authenticate. Without the row a stock vSRX with nothing
  wrong reports sessions port49 did not authenticate. **Every other platform ships empty**,
  including `juniper_vjunos-router` (the same decode of its capture finds no root records, so
  the behaviour is image-specific) and `cisco_nxos` (the `vsh.bin` observation is
  production-only and still has no note). Plan 5 fills the rest, from notes.
- **Refuse at mint any username canonicalization would change**: `Canonical` folds U+0130 onto
  `i`, so two directory names could share one `(nas, username)` context — and it also strips
  `DOMAIN\` and truncates at `@`, which an ASCII-only guard would let through, minting a token
  under a key no redemption can address. `Canonical` moves to `internal/username` so the minter
  can enforce it without importing the daemon that imports the minter.
- **Enable tokens**: mint pair with `kind`. No measured platform sends `$enab{level}$` (L3
  closed): vEOS and IOS-XE send the operator's own username with `service=enable`, NX-OS 10.x
  has no enable. The lookup is therefore the ordinary `(nas, username)` context; an enable
  START must update `privilege` in place and keep `ctx_id` (plan 1 replaces it, measured);
  candidate set filtered to `kind: enable`; `token_kind_mismatch`;
  `enable: none | auto | token`; `rem_addr` binding on enable. `$enab{level}$` becomes an
  explicit `platforms.<name>.enable_username: enab` option **refused at load** until a
  `tests/lab/results/` note shows a device sending it, which is also what keeps
  `enable: auto` inside §5.6's restriction. No `(nas, rem_addr)` index is built, so no new
  reason code is minted for it. Spec §7, §5.6.
- **Candidate-set cap** (order of eight) refusing the mint, never the redemption. Design §8.
- **Full store record set**: `blob`, `contexts_by_principal`, `contexts_by_sid`,
  `contexts_by_cert`, `active_principals`, idempotency record, failure counters; atomic
  remove-and-write-receipt; the race loser reads the receipt and answers PASS. Design §12.
- **Login context in full**: the §5.1.1 shape (`refreshed_at`, `revoked_at`, `auth_time`,
  `session_expires`, `session_discriminator`, `accounting_state`), the teardown rows that
  still have content — 1, 2, 3, 3a, 6, 7; **row 5 is withdrawn and row 4 has no path without
  the `(nas, rem_addr)` index** — and the checks in the §5.3 pseudocode (username, revoked,
  expired, stale, privilege). Accounting annotation binds the **platform's own** session
  discriminator (`session_pid` on Junos, `task_id` elsewhere — `task_id` restarts at 1 per
  session on Junos, L1), sets `closing`, and flags `foreign`. Spec §5.1.1, §5.3, §5.6, §5.8.
- A **mint function** callable in-process (no broker yet) that plan 3's minimal broker wraps.
- **`context_idle_ttl` is absolute, not idle.** Plan 1 sets it at `PutContext` and never
  extends it; `GetContext` does not touch it. Spec §5.6 says activity SHOULD extend it.
  **Ruled in the rewrite: it becomes a true idle TTL and keeps its name** — a key named
  `context_idle_ttl` that measures absolute age lies in its own name, and `session_expires` is
  already the absolute clock. The extension goes through a new TTL-only store method,
  `TouchContext(ctx, key, ttl)`, which writes the expiry and nothing else: re-`PutContext`ing the
  record read at the top of the request would discard a concurrent revocation permanently, on the
  daemon's highest-frequency path. It runs only when the remaining life is below half the TTL, so
  the common command costs no store write, and nothing is deferred to plan 7 for it.

**Hands to plan 3** (as executed, not as planned — each of these is built and tested with no
caller, so plan 3's broker is a transport over an existing core rather than new mechanism):

- **`session.Manager` is built and wired in `cmd/port49d/main.go:215` and nothing calls it.**
  `Refresh`, `RevokeByPrincipal`, `RevokeBySid` and `RevokeByCert` are complete and tested, so
  `/v1/refresh`, `/v1/logout` and `/v1/tokens/revoke` are HTTP over them.
- **`(*token.Minter).Mint(ctx, token.Request) (token.Result, error)`** — the in-process mint
  `POST /v1/tokens` wraps. `reusable` is gone, the kind is chosen by `WithEnable` plus the
  subject's mechanism, and **idempotency is keyed `(principal, device, key)`**, not on the
  header key alone (Task 12 C1: design §17 sends one key for a device *list*, and unscoped,
  device two is handed device one's token, tagged for the wrong device and refused on every
  attempt).
- **Encryption at rest and its two-key read window**, with the
  `port49_crypt_open_failures_total{record}` counter (`token`, `receipt`, `context`,
  `idempotency`) already emitted.
- **`session.staleness_ceiling` defaults to 0, so the `context_stale` check is dead in the
  shipping binary** until something calls `Refresh` on a schedule (spec §5.1.3). **Plan 3 did not
  wire it** (plan 3, Decided 14): the slice reads its policy once and its store dies with the
  process, so a refresh has nothing to carry. Plan 7 wires the schedule and sets the default in the
  same change — a ceiling with no refresher denies every context the moment it is set.

**Leaves for later:** the broker API and its authorization (plan 7); blobs' compiled content
(plan 4, the engine produces them; plan 2 stores opaque bytes by hash).

**Owed by plan 3 or plan 7 — each is documented in the code and now on the roadmap, because a
package comment is not where the next plan looks:**

- **Revocation does not delete the principal's unredeemed tokens** (`internal/session/session.go:14-21`;
  design §1182 assigns it to the broker). A token minted before a revocation still redeems into
  a fresh context with no `revoked_at` on it, by §5.6 row 1's unconditional overwrite. The
  operator sees a revocation that marked every context and deleted every receipt, then a PERMIT
  on a device they thought they had closed, with no log line joining the two. **This is the
  largest remaining hole in revocation.** Plan 7.
- **`crypt_open_failures_total{record="token"}` must become a key-rotation alarm before the
  first rotation.** `Candidates` drops a token it cannot open with a nil error, so the metric is
  the only witness that a rotation retired a key too early
  (`internal/store/crypt/crypt.go:216-231`). Plan 7 with the rest of the alarms, or plan 6 with
  key rotation reporting, whichever lands first.
- **`foreign` has a metric** since plan 2b (`port49_accounting_attributions_total{attribution}`,
  ruled with no rate limit). Nothing further is owed here.
- **Deferred from Task 13 and Task 9, all three settled and none of them work for plan 2:**
  an `ErrPartial` sentinel and the `Refresh`/`mark` `firstErr` asymmetry — `mark` returns the
  refs it touched *and* the first error, `Refresh` returns a count and an error, and plan 7
  owns the broker's error contract, which is where the shape should be decided once
  (`internal/session/session.go:176-220`). And **no compare-and-set on `PutContext` is
  needed**: the lost-update window that asked for one was on `escalate`, and the final review's
  C1 closed it with the narrow setters instead — `SetPrivilege` and `TouchContext`. Every
  writer of a live context now writes through a setter that names its fields.
**Lab:** none close here; L8 (password length) may need re-checking with the 30-character
tagged token. Plan 2 does move the harness off written secrets — `lab.seed_tokens` loses
`secret:`/`kind:`, the daemon mints the pairs and writes them to a `0600` `lab.seed_token_file`,
and `tests/lab/labcreds` reads that file — so the next lab deploy is the first on minted tokens.

## Plan 3 — Vertical slice (§19 step 3) — `2026-09-23-03-vertical-slice.md`

**Builds:** the first real identity reaching a real device with no shared password.

- A **minimal broker**: x509 client-certificate validation against one trust anchor over a
  **held mTLS connection**, literal-identity subjects, a file-backed policy with roles and
  grants and no scopes beyond `all_devices`, mint via plan 2, `/v1/tokens` and `/v1/config`
  only. Design §7 (certificate path), §17 "Minting", spec §13 decision 17.
- The **agent** `port49 login` and `port49 token` commands over that connection. Design §8
  "Two credentials, two lifetimes".
- **Borrowed ahead in simplest form** (say so in the plan): a hand-written admission snapshot
  and key group (plan 6), one blob written and read (plan 4), one platform's session
  attributes (plan 5).
- **eAPI / NX-API per-request authentication** measured in the lab with reusable tokens.
  Images for this are on hand (plan 1 Task 15 lists them with their vrnetlab kinds): Nexus
  9300v 10.4(2)F for NX-API and the L7 question; Catalyst 9000v 17.12 and C8000v 17.13 for
  IOS-XE, where the `$enab15$` enable path (L3) lives; vEOS for eAPI (image tagged 4.32.2F,
  running 4.31.2F).

**Inherits from the 2026-09-20/22 lab stretch (PR #3):** L3 is closed (no platform sends
`$enab{level}$`; NX-OS 10.x has no enable) and the `$enab15$` enable path is gone. L4 is
measured over SSH on all five images and stays open on `deadtime`, the other transports and
authorization fall-through; L7 is measured per request on eAPI and NX-API and stays open on its
cookie clause. So the lab list above is mostly done. What this plan still
owns: the first end-to-end run with a real credential. The sliding receipt is no longer an
open question — plan 2 shipped it as `receipt_idle_ttl` (15m) and `receipt_max_age` (2h), and
`receipt_ttl` is refused by name at config load — but **the agent's reconnect behaviour is
still part of this plan's design**: an agent minting a fresh token on each reconnect removes
most of the idle-gap problem the client matrix showed (L15), and the bounds are the fallback
rather than the answer. **Lab:** the API-transport half of L1 and the eAPI `/login` flow by
hand.

**Lab, as run:** the slice end to end on vEOS (`tests/lab/results/slice-arista_eos.md`); L7's eAPI
`/login` clause measured on vEOS (`L7-login-arista_eos.md`); L7 was left open on NX-API's
`nxapi_auth` cookie and closed 2026-09-24 when that was measured by hand
(`L7-nxapi-cookie-cisco_nxos.md`), so decision 15 no longer waits on L7 — what it still names as
unmeasured is HTTP keep-alive and an idle-gap playbook run (spec §13); L1's RESTCONF
clause measured on IOS-XE (`L1-restconf-cisco_iosxe.md`), and L1 open on the console.

## Plan 4 — Policy engine (§19 step 4) — `2026-09-23-04-policy-engine.md`

Spec §3 (normalization), §4 (grammar, pipeline stages), §5.1–§5.5 (mint resolution, blob
compilation, refresh, credential identity, scopes and `attached_roles`, version comparison),
§5.4 (dominance), §5.7 (decision log in full, replay), §6 (privilege levels, attribute
layering, substitution at session authorization), §11 (the complete example as a test
corpus), §12 (`explain`, policy tests, access review, `grants remove --subject`), §14
"Matching and precedence" and "Decision log" assertions. Replaces plan 1's `author.Lab`
with the real `Authorizer`. Produces the compiled blob plan 2 stores.

**The accounting spool needs a sink that can fail.** Plan 1's at-least-once guarantee ends at
`decision.Emitter.Emit`, which returns nothing: the spool deletes its `.draining` file whether
or not the sink took the records. With stdout as the sink that is academic. Whichever plan
first gives the decision log a real sink — this one owns the log in full, but it travels with
the sink if it lands later — must give the spool a sink interface that returns an error, and
the spool must not advance `drainOffset` past a refusal. Without both, the durability contract
is enforced up to the last hop and not across it.

**Carried from the 2026-09-24 lab branch:** `author.Decision.Error`, which makes
`Handler.Handle` answer a refusal ERROR, exists only for the lab's fault switch
(`lab.fault_file`, `author.LabFault`). When this plan replaces `author.Lab`, the real `Authorizer`
must never set it — a store outage stays FAIL `store_unavailable`, because an ERROR at command
authorization permits everything under IOS-XE `if-authenticated` and falls through to local RBAC
on the N9Kv (`tests/lab/results/L4-error-*.md`). Remove the field with `author.Lab`, or keep it and
the fault switch lab-only and say so.

**Carried from plan 3:**

- **Compare the blob's `Platform` with the device's platform at authorization.** Unreachable
  while the broker and the daemon share one inventory, so the slice does not check it; it
  becomes reachable when they stop sharing one.
- **A `GetBlob` store error answers `store_unavailable`** once the store is remote.

**As built:** the executor is `internal/engine` (the blob format and the one evaluator the
daemon, `port49 policy replay` and `port49 explain` all run) and the authoring side is
`internal/policy`; plan 3's `internal/blob`, `author.Blob` and `internal/broker/policy` are gone.
`author.Engine` is the daemon's authorizer. `author.Lab` survives only as the lab's instrument
for seeded contexts, behind an optional `lab:` block (plan 4, Decided 12). The accounting spool
drains to a `decision.Sink` and stops at a refused record. Authorization answers
`store_unavailable` FAIL, as plans 1–3 did, until L4 measures authorization fall-through (plan 4,
Question 3, owner's ruling 2026-09-24). A device that fails a joint policy-and-inventory check is
quarantined, not the policy refused: named at start, refused at mint `device_quarantined`, and
closed at once without a reply by the daemon, never held silent, because the lab measured a
silent server at about 5 s a command (spec §10, decision 20). Quarantine is time-scoped: a
device is quarantined only while its check fails, so a grant's expiry schedules an entry from
that instant (warned at start), and the daemon asks per connection and per packet with the
current time. `port49 policy test` carries the
shadowed-deny report and `port49 policy diff` the effective-permission diff and the
privilege-expansion gate (spec §12), and replay re-derives a session's attributes.

**Hands to plan 5:**

- `internal/platform/dialect.go` is borrowed ahead and is plan 5's to replace with the layered
  adapters: `pipe_authorized` is false on EOS, NX-OS and IOS-XE (measured,
  `tests/lab/results/L2-*.md`); `expands_abbreviations` is true on EOS, NX-OS and IOS-XE, set
  from L21 (closed 2026-09-24, interactive SSH; other transports unmeasured), and false on Junos
  and the generic adapter; entity classes are names from spec §8 and the lab configs, unverified against a device;
  only `arista_eos` renders levels. `operator` renders as `priv-lvl=15` there and carries ceiling
  number 15 on `cisco_nxos` (decided 2026-09-24, spec §6 and decision 23; the role-ceiling results
  below); IOS-XE's `operator` is still unrendered and is this plan's.
- **The owner's level definitions (2026-09-24), binding on the adapters:** `readonly` is show and
  info only; `operator` is non-disruptive state changes and no configuration (`clear counters`
  yes, `clear bgp *` no); `admin` is everything. The device role is the ceiling, and port49's
  command rules draw the line inside it.
- **Three lab runs, added to spec §15 L4's *To measure* by plan 4 (owner's rulings 2026-09-24),
  measured 2026-09-24 in the lab run merged as PR #9:** authentication `ERROR` does not give
  break-glass anywhere measured, and an authorization `ERROR` is dangerous (NX-OS falls to its
  local role checks and runs the command; IOS-XE `if-authenticated` runs everything), so FAIL
  stands (`tests/lab/results/L4-error-*.md`); only an unreachable port49 gives break-glass,
  which is plan 6's go-dark below.
- **Role ceiling, measured 2026-09-24** (`tests/lab/results/ceiling-*.md`): on IOS-XE levels 1
  and 7 refuse `clear counters`, `clear ip bgp *` and `configure` in the parser, and level 7 with
  `privilege exec level 7 clear counters` is the `operator` rung, so the device can enforce it; on
  EOS level 1 refuses all three and `network-operator` at 15 runs all three (L16 found the role binds only
  under local authorization); on NX-OS every role runs all three. **On EOS and NX-OS the
  `operator` rung is port49's per-command policy alone.** *Decided 2026-09-24:* `operator` renders
  as level 15 on both, with port49's rules the only fence, and a device method list must not fall
  back to `none` or `if-authenticated` (spec §6, §8, decision 23). IOS-XE level 7 with `privilege
  exec level 7 ...` in the reference config is this plan's adapter work.
- **L21**, added by plan 4, closed 2026-09-24 (`tests/lab/results/L21-*.md`): all three
  per-command platforms send resolved words over SSH; other transports are unmeasured.
- The dead-rule and fallback-exposure intersection checks of spec §12 are this plan's; plan 4
  built the shadowed-deny report, the effective-permission diff and the privilege-expansion gate,
  because it is the plan that switched to dominance (plan 4, Question 4, owner's rulings
  2026-09-24; listed in its section).
- Opening the pull request `port49 grants remove` prepares: plan 4 edits the file (printed, or
  `--write`), and plan 5 opens the review (owner's ruling 2026-09-24).
- The offline tools (`port49 explain`, `policy test`, `access review`, `grants remove`) load a
  policy without config's resolved `EnableUsernames`, so CI cannot see a `platforms:`
  enable-username override the daemon applies. Harmless while `config.Load` refuses such an
  override; plan 5's to close when its adapters bring the overrides (plan 4 pre-flight, N5).
- **When adapters become editable (review M8, 2026-09-24):** the policy diff reads which reply
  attributes bear privilege (`Dialect.PrivilegeAttributes`, `InertAttributes`) from the new
  version's dialect today, which is sound only while the table is built in. Once an operator can
  edit an adapter, judge `BearsPrivilege` under the stricter of the before and after dialects, so
  listing an attribute inert in the same change cannot hide its own edit, and gate any edit to an
  adapter's privilege-bearing or inert lists as a privilege change in its own right.
- Operator-supplied entity-class patterns, when adapters bring them, must be checked for `(?-i)`
  where a deny uses them: plan 4 refuses a deny regex that turns case-insensitivity off, because
  a case-sensitive deny can be walked past by case (spec §4), and permits keep the opt-in.
- **Decided 2026-09-24** (spec §12): a privilege raise — the device privilege the session reply
  gives, the ceiling, the level under either order, or `enable` switched on — fails `port49 policy
  diff` unless a session test (`level:`, `max_privilege:`, `priv_lvl:`, `enable:`) in the new
  policy asserts it; a regex-constrained widening fails unless a permit test shows it or an
  `acknowledge:` entry names the removed deny with a reason; a newly refused mint always fails.
  The reserved levels keep their order, and a ceiling caps the level on every platform. A policy
  with no tests passes `policy test` with `report: no_tests`, and `port49d` prints a `LAB MODE`
  line at start when its config has a `lab:` block (design §13).

**Hands to plan 6:** quarantine is applied by `port49d` when it loads the policy
(`policy.checkDevices`); plan 6 publishes it in the bundle, `admission: quarantined`, from the
inventory service (spec §10, decision 20). `security_log` is accepted and emits nothing until a
sync can change a scope's membership. `bundle` on every blob and record is the policy file's
`sha256:` until versioned bundles replace it. The remote store brings continuing active logins
from a replica's warm context cache through a store outage (design §12).

**Go-dark on a store outage (owner's ruling 2026-09-24; plan 6 or 7, whichever brings the
remote store):** `port49d` health-checks the store, closes its TACACS+ listener after N
consecutive failures and reopens it after M successes, with that hysteresis. The lab showed that
only an unreachable port49 gives break-glass: an authentication `ERROR` does not, and an
authorization `FAIL` refuses break-glass's commands (`tests/lab/results/L4-error-*.md`). The
listener must be closed, so a device sees connection refused and moves on at once, never held
silent, which costs about 5 s a command on IOS-XE, EOS and NX-OS. A per-username break-glass list
was rejected (every site's break-glass account differs). Operator note: NX-OS with `deadtime 1`
refuses token logins for about a minute after port49 returns.

**Hands to plan 7:** group subjects load, and are evaluated by name in the offline tools, but mint
for no one until the directory resolves membership; `api:` rights are validated and reported, not
enforced; `max_session_age` per role is refused at load by name; `/v1/explain` over the API (the
offline `port49 explain` exists). Policy reload is plan 4b's.

## Plan 4b — Live policy (spec §5.1.3)

The owner's core goal (2026-09-24): **a policy change reaches every live session without anyone
logging out.** Today a policy edit needs a `port49d` restart, and a restart ends every live login
context and every unspent token (plan 3, Question 3).

- **Reload trigger:** a watch on `broker.policy_file` and `SIGHUP`, both.
- **Validate or keep the old:** the new file is loaded against the current inventory exactly as
  at start. A file that does not load leaves the running policy in force, logged with the error
  and counted (`port49_policy_reloads_total{outcome}`); nothing half-applies.
- **Atomic swap:** the broker's policy and the daemon's quarantine list change in one step, so
  no mint sees one version's policy and another's quarantine.
- **The joint check re-runs on every reload:** the new policy's quarantine schedule (the
  time-scoped entries, grant expiries included) replaces the old one whole, so a fix releases a
  device and a new failure quarantines one without a restart, and its connections close as plan
  4's do.
- **Refresh of live contexts (spec §5.1.3):** each principal with a live context is re-resolved
  against the new policy, a new blob is written where the result differs, and `blob_hash` is
  updated in each of that principal's live contexts; a principal left with no grant has its
  contexts revoked (`revoked_at`). A policy-removed grant therefore reaches an
  active session on its next command, **with no logout**. Blobs are immutable, so a replica's
  cached copy of the old one is never wrong, only no longer referenced.
- Carried here from plan 7: `(*broker.Broker).Server` returns an error instead of panicking, now
  that a reload path exists.

Plan 7 keeps the scheduled refresh through `active_principals` for directory changes, and the
`staleness_ceiling` default that goes with it.

**As built** (`2026-09-24-04b-live-policy.md`): `policy.Live` holds the policy in force; the
broker mints from it and the daemon asks it about quarantine at every packet, so one swap changes
both. `port49d` reads `broker.policy_file` every `broker.policy_watch_interval` (default 5s) and
loads the bytes two agreeing reads saw, and loads at once on `SIGHUP`. The file is checked on the
descriptor it was read from: a file that does not load, or that anyone but `port49d`'s user or
root could have written — the file, or the directory holding it, group- or world-writable or owned
by anyone else — is refused whole (at start `port49d` does not start), said once per distinct
content, counted (`port49_policy_reloads_total{outcome}`) and alarmed
(`port49_policy_file_refused`). A mint holds the policy from its first resolution to its last
token write, and not while its response is written. A hold is never nested, and its store calls
are bounded by `holdTimeout` (10s; past it the rest of the batch is refused `store_unavailable`),
so a store that stops answering cannot hold a reload, and every mint queued behind it.

`(*broker.Broker).Refresh` carries the policy in force into every live context through
`store.SetContextPolicy`, the fifth narrow setter and the first that is a compare-and-set. It
compares `PolicyRev`, a revision only policy-relevant writes bump (join, revoke, privilege,
ceiling, enable, blob), so accounting traffic on a busy session cannot starve it. A principal with
no grant left on the device has the context revoked through `SetRevokedAt`, which writes the mark
alone and keeps the later of two, so no racing write can hold a withdrawn grant in force. A
context the policy in force cannot be resolved or compiled for is revoked too (`refresh deny
blob_unavailable`, the process log naming the `ctx_id`), and so is one that cannot be opened
(sealed under a key past the two-key window): its record names the device and the key's
username and no principal, since the owner is sealed and the index may be stale. A context on a
device quarantined now is left as it is, with one `refresh deny device_quarantined` record per
context per bundle, not one per pass. Every change is a `refresh` decision record (spec §5.7).
The refresh also deletes the unspent tokens a superseded policy minted that the policy in force
would not mint identically; a superseded policy's tokens are judged at the start of its span and
at every grant expiry inside it. A pass judges everything at one instant (`RefreshReport.At`) and
goes round again at once if a grant expired while it ran.

`port49d` runs the refresh at every reload and every grant expiry (scheduled from
`RefreshReport.At`), a settle pass 30s after each for a login in flight across the swap or the
expiry, and every 30s after a store error until one completes. `port49_policy_refresh_pending`
is 1 from a swap or an expiry until its settle pass completes, and while any retry is owed. A
context still changing after every compare-and-set attempt is left for the retry and the pass
goes on; a revocation never waits on it. The inventory is not reloaded: a reload after an
inventory edit says so (plan 6). `run` takes a context, so a test can stop it, and the end-to-end
test of `port49d` with no `lab:` block that plan 4 carried here drives a live edit through a real
login. `SIGHUP` no longer ends `port49d`.

**Hands to plan 6:** the snapshot refresh (spec §10) swaps an inventory under a live policy. It
must re-run the joint checks against the new inventory and call `Refresh` exactly as a policy
reload does, since a device leaving a scope is a narrowing like any other; `Refresh` already
revokes a context on a device inventory no longer names. Reloading the inventory itself is plan
6's: today a reload after an inventory edit only says a restart is needed. The token supersede
walks principals × devices × superseded policies × expiry instants, compiling each answer (plan
12 measures it at fleet size). With the remote store:
- **Unindexed contexts are invisible to the refresh** (4b pre-flight N4). An `IndexContext` can
  fail, and a login whose index write failed is invisible to the policy refresh as it is to
  revocation (`authen`, the `index_error` record). Close it, or at least extend the
  `index_error` wording to name the policy refresh too.
- **The refresh's store calls are bounded only by the caller's context** (4b Task 5, M4). A
  local store answers at once; a remote one can hang a pass, and with it every later reload,
  since `port49d` runs one pass at a time. Give each store call its own deadline.
- **Decision-log emits under a hold are not context-bounded** (4b Task 4). A mint writes its
  records while it holds the policy, so a stalled log sink stalls a swap. Harmless with a local
  file; bound it before the log can be remote.
- **The settle pass assumes redeem-to-write is under 30s** (4b final review m3). A login that
  spent a token before the supersede and writes its context after the settle pass keeps the
  superseded answer until the next reload or expiry, and the pending gauge reads 0. With the
  memory store this is immediate. The daemon's per-packet store calls use the connection's
  context with no deadline. Give them one that is well under `settleAfterReload`.
- **What the broker remembers grows with the policy's history** (4b final review m10). A file
  rewritten on a schedule, such as a templater stamping the time, reloads on that schedule.
  Every load writes one `refresh` record per live context and a new blob, held in the store for
  `max_session_age` and in `b.blobsSeen` for good. `b.superseded` holds one instant per
  (device, username) ever superseded. Both are bounded by memory today; bound them before the
  store is shared.

**Hands to plan 7:** the scheduled directory refresh is `Refresh`'s context pass with group
membership re-read; a policy refresh does not stamp `refreshed_at`, because nothing about the
directory was re-verified, so the staleness ceiling still waits on plan 7's scheduler. Revoking
by principal, `sid` or certificate should also delete tokens (roadmap, plan 3's hole), as the
policy refresh already does for a withdrawn grant. **A candidate reload guard** (4b Task 6, M3):
a reload that fails the joint check for most devices applies anyway and quarantines them live,
as spec §10 and decision 20 require; the CI gate (`port49 policy diff` fails on a newly
quarantined device) is today's only guard. An optional guard that refuses a reload quarantining
more than a configured share of the fleet is plan 7's to weigh. **Revocation records must name the
contexts they could not reach** (decision 21; 4b final review I1). The policy refresh
already counts contexts on session-only platforms (`RefreshReport.Unreached`), says so on its
summary line, and names each `ctx_id` in the process log. Revocation by identity adds the
record field, a §5.7 edit first, and the refresh should use it too.

**Hands to plan 12:** the policy file check covers the file, the directory holding it, and the
directory holding every symlink on the path. It does not cover ACLs or other ancestor
directories. The deployment docs must say that the path to the policy file is the deployment's
to protect, since whoever can write it decides every operator's access within seconds. The mode
of a directory holding a link, never the file's own directory, is excused on a read-only mount
(`fstatfs`). That is how a ConfigMap or Secret mount passes: its 0777 root is mounted read-only
(`tests/lab/results/configmap-mounts.md`). The excuse trusts whoever writes the mount's source,
so the deployment docs must say: do not mount the policy from FUSE, or from a host path others
can write (re-review n1). They must also say to use `fsGroup` or `defaultMode: 0444` for a
non-root `port49d`, and that an edit takes about 55 s to reach the pod. **`inventory_file`'s path
is the deployment's to protect exactly as `broker.policy_file`'s is** (plan 6a, pre-flight C2):
since plan 6a it is read behind the same fence, with a broker, and it decides scope membership,
capture addresses and key pins within seconds.
**The refresh's cost** (4b final review I3): one `mintedBy` compile measured 17.8 µs on the
fixture's three-role policy. The token scan runs principals × devices × instants for each
superseded policy, so 500 principals by 5,000 devices is about 45 s per instant per prior, and
a real policy compiles slower. The context pass now runs first, both loops stop when cancelled,
and a settle pass or retry no longer compares the policy in force with itself. Measure the
rest at fleet size here.

## Plan 5 — Platform adapters (§19 step 5)

**Split into 5a and 5b (2026-09-24),** because the brief below and every plan-4 hand-off is more
than 25 tasks. The seam is the kind of platform:

- **Plan 5a — `2026-09-24-05a-platform-adapters.md`. As built (merged 2026-09-24, PR
  #13):** The
  adapters as data and every platform that authorizes per command: the built-in adapters as files
  in a pinned set (`platforms/1.0.0/`; a policy that pins none renders with 1.0.0 forever),
  operator overrides in the policy file's `platforms:` block (merge per key, `replace`,
  `based_on`), EOS, NX-OS and IOS-XE rendering under a new decision 25 (a level is a device level
  and a device role; `operator` gets admin's level and readonly's role on EOS and NX-OS, and
  `priv-lvl=7` on IOS-XE with its reference configuration), IOS-XE's closed attribute list
  (anything else quarantines), redaction (built in, unpinned, before the spool), N5, the
  adapter-edit gate and the stricter `BearsPrivilege`, the `(?-i)` check on operator classes,
  `port49 platform list/show/export/upgrade`, the dead-rule and fallback-exposure reports, `port49
  devices check-config` (plan 2b's owed check), `grants remove --pr`, and a lab task that
  measures each adapter's reply level by level (new register row L22) and three candidate inert
  attributes.

  Where it differs from the plan's Decided list: L22 (`tests/lab/results/L22-*.md`, closed
  2026-09-24) measured every level on every platform as rendered and operator's configuration
  change refused at fallback on all three, so the EOS, NX-OS and IOS-XE adapters ship `verified:
  containerlab`, and any `platforms:` block over one of them clears it (`platform list` prints
  `—`, `policy diff` reports the change, `platform export <name>` leaves the key out so the
  block pastes back). Inert as measured: `home-directory`, `idletime` and `timeout` on EOS and
  NX-OS. IOS-XE lists nothing inert: it refused the session for `home-directory`, and a refused
  session there locks out SSH, so `idletime` and `timeout`, measured inert and now accepted
  (`accepted_attributes: [priv-lvl, idletime, timeout]`, not Decided 6's `priv-lvl` alone), are
  held bearing. Both are numbers everywhere: a placeholder in either is refused at load, and a
  value that is not a plain decimal 0 to 65535 quarantines the device, and so on IOS-XE does
  either attribute sent in the mandatory `=` form (`idletime=30`): only the optional `*` form,
  `idletime*30` and `timeout*480`, was measured there. `fallback`
  entries say what L22 measured: EOS operator names the commands that still ran, NX-OS operator
  and IOS-XE have none (IOS-XE refused a token session every command at 7 and 15). Beyond the
  plan: an operator's fallback text is kept apart as `fallback_note`, a block's `unreachable`
  rules are kept apart from the set's as the operator's (`unreachable_note`), a change to the generic adapter is gated (`platform: generic`), an
  `acknowledge:` entry names the sha256 of the value it covers and a stale one is reported, a
  load error quotes no rule text, and `grants remove --pr` targets the repository the push URL
  names. Carried: Junos's inert list and every Junos spelling to 5b (L10, L12, both open); L22's
  inert candidates (`home-directory`, `idletime`, `timeout`) re-measured beside readonly's reply
  (`priv-lvl=1`, network-operator) on EOS and NX-OS to 5b, since beside admin's a raise is
  invisible (5a final review M3); a replay-verifiable blob whose rules redaction hides, and a
  `based_on:` variant's wire facts, to plan 6 (below), which lifts the load's refusal of
  `based_on: juniper_junos` once port49d reads a variant's session service, exec-record commands
  and system users (5a final review M8).
- **Plan 5b — the session-only half and capability inference; written after 5a merges.** Junos's
  projection under decision 22 (`bits`, `bit_delivery`, `command_projection`, `local-user-name`
  templates, the generator constraints and the refused shape), gated on L12 and L9, with its own
  containerlab differential tests and `platform export` of the reference classes; decision 21's
  class `idle-timeout` from `max_session_age`; spec §9's capability inference (`port49 devices
  capabilities`, the supports-versus-observed matrix, accounting reconciliation); and an NX-OS
  `vsh.bin` system user if a note measures it. 5a leaves Junos rendering nothing, as today, so 5b
  reworks nothing 5a builds.

  **Written 2026-09-24** as `2026-09-24-05b-projection-capabilities.md`. The lab measures L9, L12,
  L23, L24 and L25 first (Tasks 2–4), and the new platform set 1.1.0 takes its values from those
  notes (Task 14, with a fail-closed branch for every outcome). The projection ships in 1.1.0, so
  an unpinned policy still gets nothing on Junos. Each reply is proven not to let the device run
  what port49 denies before it is sent, against a model in which the bits are a union and only
  measured carve-outs subtract. **Revised 2026-09-25:** a composition that cannot be proven gets
  that subject alone a fail-closed reply (`deny-commands=^.*$` and only the proven allows),
  recorded `projection_fail_closed`, and `policy test` and `policy diff` fail on it (decision 26,
  the owner's ruling, replacing the device quarantine). `policy test` also fails on any
  quarantine; a projected reply is gated by what the device can do under it; `remote` and `p49-*`
  are reserved usernames. Bits reach the device as `user-permissions` over the bitless
  `p49-remote` template, which L12 measured applied on both images (branch C); `local_user_name`
  stays an adapter choice. `port49 platform export --classes` renders
  the reference classes as a replace with decision 21's `idle-timeout`, and `devices check-config
  --config` holds a device to them. `port49 devices capabilities` reads the decision log,
  qualified by a new `account_gap` record. Task 19 is the differential test.

### Plan 5b — As built

Executed 2026-09-25 on `feature/session-projection`, every task but Task 19, which ran on
2026-09-29 (`feature/projection-differential`, merged into it). The plan was amended
in flight: decision 27 (Junos matches keywords only) and the lab tasks it needed, 3b (the keyword
tree, L26; keyword abbreviations, L9; NETCONF, L12), L26b (keyword proof by deny enforcement),
L26c (RPC reach from a projected CLI) and a rerun of L26. Task 15 did not run (L25 not
reproduced). Task 19 passed on both images after two review rounds added shapes the plan
missed (the capability reply with one and two keyword denies, bits short of `all`) and a
commit-checker step (`L12-projection-juniper_*.md`).

- **Set 1.1.0 is frozen and the default.** It is 1.0.0's EOS, NX-OS and IOS-XE files unchanged
  (branch K: L23 found all three candidates inert) and `juniper_junos` projected. `DefaultSet` is
  1.1.0 and `UnpinnedSet` stays 1.0.0, so an unpinned policy renders Junos as before.
  `TestEveryReleasedSetIsFrozen` holds 1.1.0 value for value, and
  `TestReleasedKeywordTreesAreFrozen` holds its keyword tree by sha256
  (`platforms/keywords/1.1.0/juniper_junos.yaml`, `aa144089…0168`). **The Junos adapter is
  `verified: containerlab`**: Task 19's differential passed on both images before the merge, so
  it was set on 1.1.0 and the `released` entry changed with it, as 5a did for 1.0.0.
- **Task 14's branches, as the notes read:**
  - B: `DenyMatchesExpanded` true (`L9-abbreviations-juniper_*.md`: no abbreviation of a
    keyword deny ran on either image).
  - B2: the rendered deny shape ` *… *(\|.*)?` is enforced, so `ere.go` is unchanged.
  - C: `bit_delivery: user_permissions`. L12 measured it applied over a bitless template, both
    bits of a two-bit value, per session. So there are no level templates: every session lands
    in `p49-remote`, and `user-permissions` carries the bits.
  - D: `bits` is the measured reach, the same on both images.
  - E: `carve_outs` is `view-configuration`'s `show configuration **` out of `view`. `show log
    **`, `show firewall **` and `show policer **` join it on completion evidence only. None
    leaves a deny off the wire in 1.1.0: over RPC even `show configuration **` is provisional on
    L26c, so its deny is sent and fails closed beneath `view` (final review I-3).
  - F, G: a template user commits with no uid, and one with no authentication refuses a local
    login, so nothing is locked.
  - H: L24's class `idle-timeout` closed idle sessions on both images, so the export's
    `idle-timeout` from `session.max_session_age_default` stands.
  - I: a malformed deny opened the session and refused `show version`.
  - J: `deny-commands` never reaches configuration mode, so a configuration-statement deny fails
    closed (`configuration_deny`).
  - L: every request carried `priv_lvl` 1, so the levels stay `{readonly: 1, operator: 15, admin:
    15}`.
  - M: `rpcServicesOff` is on (below).
  - Not A: Junos is projected.
- **`JunosFacts` is `{CaseSensitive: false, DenyMatchesExpanded: true, DenyBindsRPCs: false}`.**
  Case is not measurable, because the CLI refuses upper case itself. `DenyBindsRPCs: false` and
  option C are **provisional on L26c** (open), the conservative reading. L26c measured, with
  `netconf ssh` still configured, that `xml-mode netconf` opens NETCONF inside a projected CLI
  session; that a native RPC the probed deny did not name (`<get-software-information/>`) ran
  there; that the deny did bind a `<command>` RPC; and that RPC reach is bounded above by the
  bits. It did not observe a native RPC passing a deny that named what it reached, and whether
  the services allowlist is sufficient is unmeasured. So under option C (the owner's ruling until
  their device results) port49 assumes a deny beneath a sent bit or the baseline is not a
  boundary. The composition falls to the narrow shape, whose `deny-commands .*` refuses both entry points, or
  gets the fail-closed reply (`refused_shape`, naming RPC reach). **The realistic readonly still
  fails closed** on 1.1.0, now for three reasons: its baseline denies overflow 255 bytes, `save`
  cannot be proven a keyword, and port49 treats the denies beneath `view` as guarding the CLI only
  (option C). What does project:
  `permit: [show **]` alone as the narrow shape, a narrow grant of a few show commands, and an
  admin `permit: [**]` with a deny no bit but `all` reaches (decision 26).
- **Decision 27's keyword tree.** L26 walked `show` on both images (136 nodes and 755 keywords on
  vJunos-router, 118 and 668 on vSRX, no bound hit), and then again. vJunos-router's rerun
  reproduced its tree byte for byte. The vSRX rerun, under the hardened classifier, dropped one
  false keyword (`show rsvp interface`, the classifier's doing) and gained two its first run left
  out (`show interfaces terse extensive`, `show system processes detail`), which shows the walk is
  not reproducible there. So `tests/lab/cmd/junos-keywords` intersects every committed run (three
  trees) and refuses a merge missing one: 528 keywords. L26b's overlays add the seven proven by deny enforcement (`show cli`,
  `host`, `ingress-replication`, `policy`, `task`, `set cli`, `exit`), for 535. What it proves
  for the spec's denies:
  - `deny show configuration **` and `deny show chassis hardware **` are keyword denies, though
    either beneath a sent `view` still fails closed until L26c closes (option C);
  - §11's `deny show chassis cluster **` is not (vJunos-router has no `cluster`), nor is `deny
    show route summary`;
  - no `show configuration` hierarchy is a keyword, and a hierarchy deny is not enforced (L26b).
- **Reference classes and rollout.** `port49 platform export --policy <candidate> --inventory
  <file> --classes --config port49d.yaml juniper_junos` prints `device_config`, then each
  template class and user as a `delete` and its `set` lines. A redacted `device_config` line is
  printed as a `#` comment, with a count on stderr, so loading the export never overwrites the
  TACACS+ secret. `port49 devices check-config --policy <candidate> --inventory <file> --device
  <name> --config port49d.yaml <capture>` holds a device to the set the policy pins, so it runs
  against the candidate policy that pins 1.1.0. The capture must be `show configuration |
  display set | display inheritance | except "^set groups "`, and any other input is refused.
  It fails on a missing reference line, on any line under a template class or user that the
  reference does not write, on a management service outside the allowlist, and on any capture
  holding a group definition or an `apply-groups` line. The order is: load the classes on every
  device, check each against the candidate policy, then deploy the policy that moves the pin.
- **Decision 26's fail-closed reply.** A composition the projection cannot carry gets that
  subject alone `deny-commands=^.*$` and only the allows port49 proved, recorded
  `authorize_session` permit `projection_fail_closed`, with the blob's `fail_closed` giving why.
  `policy test` fails on it (`projection_refused`, `projection_overflow`) and on any quarantine,
  now or at a later expiry. `policy diff` fails on it, and on a projected reply that lets the
  device do more without a `reply:` test. `remote` and `p49-*` are reserved usernames.
- **`port49 devices capabilities`** reads the decision log offline and prints the
  supports-versus-observed matrix and any unauthorized tier. It exits 1 on a contradiction;
  "never seen" is a note. A window in which the spool dropped records (`account_gap`, per stage)
  reads "possibly", and does not page. `policy test` reports `unenforced_rules` for rules a
  platform neither asks about nor renders.
- **NX-OS system task: not landed.** L25's note found no sudo prompt on the N9Kv, so there was
  nothing to cancel and no `admin` record, and Task 15 did not run.
- **Lab register.**
  - Closed: L23; L24 (both Junos images); L26, and L26b, a new row; and, by Task 19 on
    2026-09-29, L9, L10 and L12, so decision 22 is no longer provisional.
  - Open: L25 (not reproduced); and L26c, a new row (RPC reach; a rerun is owed; the owner's SRX
    hardware results are in `L26c-operator-juniper_srx.md`, without a capture).

**Operator-facing notes (for the pull request body).**
- **Upgrade every daemon before pinning set 1.1.0.** A daemon that does not ship 1.1.0 refuses
  a policy that pins it, so a mixed fleet of daemons splits on the pin.
- **Before deploying a policy that pins 1.1.0**, with that candidate policy in hand
  (`port49 platform upgrade --policy policy.yaml --inventory inventory.yaml --to 1.1.0 --write`
  writes it; do not deploy it yet):
  1. Print the classes from the candidate: `port49 platform export --policy policy.yaml
     --inventory inventory.yaml --classes --config /etc/port49/port49d.yaml juniper_junos >
     classes.set`, and load them on every Junos device with `load set terminal` and `commit`.
  2. On each device, save the output of `show configuration | display set | display
     inheritance | except "^set groups "`, and nothing else, to a file, say `srx-fw-04.set`.
  3. Check it against the candidate: `port49 devices check-config --policy policy.yaml
     --inventory inventory.yaml --device srx-fw-04 --config /etc/port49/port49d.yaml
     srx-fw-04.set`. Without `--config` it exits 2, saying the platform is projected and to pass
     `--config`. With `--config` against a policy that does not pin 1.1.0 it exits 2 and prints
     the usage block: check against the candidate that pins 1.1.0.
  4. Only when every device passes, deploy the policy.

  **A class replace does not prove a template; `check-config` does.** It fails on a missing
  reference line and on anything extra under a template, such as a class `allow-commands` or a
  template password. **A device whose configuration uses groups is refused outright**: the check
  refuses any capture holding a group definition or an `apply-groups` line, since it cannot tell
  whether a group's statements were expanded (whether `display inheritance` drops them is
  unmeasured; Task 19).
- **Management services: only the CLI's.** A projected Junos device passes `check-config` only
  where nothing under `system services` is on but `ssh` and `telnet`. Under `ssh` only its
  transport options are allowed (ciphers, limits, `port`, `root-login`, `no-tcp-forwarding`, and
  the like), and under `telnet` only `authentication-order`, `connection-limit` and
  `rate-limit`; `sftp-server`, `tcp-forwarding` and any unknown statement fail. `rest`,
  `web-management` and `extension-service` fail wherever they appear. So NETCONF, the XML API,
  REST, J-Web, JET/gRPC/gNMI and `outbound-ssh` are off, because over NETCONF a native RPC ran
  past every wire deny (`L12-netconf-juniper_*.md`). Whether that is enough is unmeasured (L26c).
- **On 1.1.0 a Junos capability reply needs `xml-mode` permitted, so most broad grants fail
  closed and only narrow grants project** (option C, provisional on L26c, and borne out on SRX
  hardware). A capability reply
  (bits, and no `deny-commands .*`) leaves `xml-mode` and `op` runnable. In the lab (L26c,
  still open), `xml-mode netconf` opened NETCONF inside a projected CLI session, and a native
  RPC the session's deny did not name ran there, within the bits' reach. Whether such an RPC
  passes a deny that names what it reads is not yet measured in the lab, so port49 assumes it
  does; on SRX hardware (23.4R2-S8.7, operator-reported, `L26c-operator-juniper_srx.md`)
  `<get-configuration/>` did, and no deny naming `xml-mode` refused it. It
  sends a capability reply only where the grant permits everything its bits reach, `xml-mode`
  included, and does not treat a deny beneath a permitted bit as a boundary. Such a subject
  gets the narrow shape or the fail-closed reply, and `policy test` names it. A measurement can
  only relax this.
- **You cannot deny a single `show configuration` hierarchy on Junos.** A deny naming one (`show
  configuration system`) is not enforced by the device (L26b), so port49 refuses it as an
  argument deny. Deny all of `show configuration`, or none of it; and on 1.1.0 denying all of it
  under `view` still fails closed until L26c closes, since no carve-out leaves the deny off the
  wire and a deny beneath a sent bit is not a boundary (option C).
- **`deny-commands` cannot keep the configuration from a user who holds `view-configuration`.**
  From any CLI session such a user can run `xml-mode netconf` and send `<get-configuration/>`,
  which returns the whole configuration (secrets masked) past a deny of `show configuration`
  (SRX hardware, operator-reported). To withhold the configuration, withhold the bit. port49
  never relies on such a deny: that composition fails closed.
- **`port49 devices capabilities` output goes to cron mail, and its redaction is best effort.**
  A password typed as a command may appear in an example line.
- **The Junos adapter is `verified: containerlab`.** Task 19's differential ran every shape set
  1.1.0 renders on vJunos-router and vSRX, none wider than port49 permits.
- The notes already in the plan's "Operator-facing notes" stand where they do not contradict the
  ones above: a new set; per-subject fail-closed with `projection_fail_closed`; `policy test` fails
  on a quarantine; reserved usernames; the new adapter keys and reports; `policy diff`'s
  `projection:` lines; `explain`; `account_gap`. One is superseded: the deny beneath a permit no
  longer fails closed for want of L9, which measured it. It fails closed for assumed RPC reach,
  as above.

**Carried, for later plans.**
- **A `junoscript` deny may lift option C.** On SRX hardware (operator-reported,
  `L26c-operator-juniper_srx.md`), `deny-commands "junoscript"`, sent by TACACS+ or set on the
  class, refused `xml-mode netconf` while other commands ran, and refused that user's NETCONF
  sessions on port 830 too (`unknown command: xml-mode`). **port49 will not send it by default.**
  The owner ruled on 2026-09-30 that humans run Ansible over NETCONF under their own accounts, so
  a `junoscript` deny on human classes would break that automation. Option C stays. At most, the
  deny could be an explicit per-grant opt-in for grants whose holders never use NETCONF. The lab
  confirmation on both images (branch `lab/junoscript-deny`) records the behavior that ruling
  rests on.
- **Revisit `check-config`'s NETCONF-off requirement.** On SRX hardware `xml-mode` opens NETCONF
  with the service off (`L26c-operator-juniper_srx.md`), so turning the service off doesn't close
  RPC reach. Under option C a capability reply goes out only where the grant permits everything
  the bits reach, so RPC reach over the NETCONF service may already be bounded the same way.
  Fleets that automate over NETCONF can't pass the check today. Settle it in the lab before
  relaxing anything.
- **Carried from Task 19** (it ran and closed L9, L10 and L12; these were never its test's):
  - `DenyMatchesExpanded` re-measured;
  - the uid range and the class `idle-timeout` upper bound;
  - whether `set version` and `apply-groups` lines survive `display inheritance | except`;
  - ssh TCP forwarding's default;
  - whether a deny binds `scp` and the SSH exec channel.
- **The owner's device measurements:**
  - answered on SRX hardware, without a capture (`L26c-operator-juniper_srx.md`): a deny naming
    `xml-mode` does not bind, a `junoscript` deny does (see the carried item above), and
    `<get-configuration/>` reaches past a deny beneath `view-configuration`; `op` is unmeasured;
  - the L26c rerun (review I-1, I-4), with only the allowlist's services on, which closes
    whether the allowlist is sufficient and so option C's provisional marker;
  - the bitless (baseline) session's RPC reach, which Task 14 counts as a carve-out;
  - the L26d probes (the short `*`-form deny and allow, and whether wire and class lists merge),
    which safety checks stopped.
- **The device-class deny-list design** (the owner's production approach). Exported `p49-*`
  classes would carry the level's class-level deny list, which no 255-byte limit binds. The
  exported classes would carry denies only, never a broad allow, since a class allow beats every
  deny. The generator's proof would count the class list beside the wire's.
- **Wire measurements:**
  - `deny-configuration` (and `-regexps`) over the wire, which would let a configuration
    statement be denied in configuration mode and lift decided item 6;
  - the `-regexps` family's rendering, since its deny precedence is measured (L12);
  - where branch M disabled NETCONF, whether an RPC-level deny (deny-commands on RPC names, or a
    class setting) can bind NETCONF, so it can be enabled again.
- **The keyword capture:**
  - grow its seed list where a fleet's denies fail as unproven;
  - capture the tree per fleet release and hardware family (A-M5);
  - prove keywords outside `show` with a mechanism that runs nothing, so a deny under `request`,
    `clear` or `monitor` can be sent;
  - make `junos-keywords` refuse a committed image left off the command line (kw-merge M4).
- A way to declare a deny class-resident, the deny overflow's workaround in policy.
- A bit's reach per child word, not the literal `W **` upper bound, once a lab proves a path has
  no hidden subcommands (Task 3 ruling (a)).
- Task 3b's deferred minors: the harness does not wait on `^U` (M2), and the notes' capture
  counts run below their pcaps (M6).
- **Scale, for plan 12:**
  - `engine.Contains`, `MayMeet` and the rest compile both rules per call, and only the
    per-composition cache bounds the load; measure it at 10k devices;
  - `devices capabilities` reads a whole log into memory;
  - an `account_gap` count held in memory is lost on a restart.
- vJunosEvolved is unmeasured. L25 is still open.
- **Before the branch is pushed:** strip the credential values commit a4c4738's L26c notes
  carried from history (redacted in ba4f7c8). The rest is done in the final fix wave:
  `labcreds.NoteLeaks` and `TestResultsNotesCarryNoCredentials` fail on a Junos
  `encrypted-password`/`plain-text-password-value` value, a `$1$`/`$5$`/`$6$`/`$8$`/`$9$` hash or a
  lab default password in any results note, naming file and line only, and every notes writer
  passes what it writes through `labcreds.RedactNote`.
- **Parked for the final wave** (per-task review minors), done there unless named here: the
  flaky `TestPAPLoginThenAuthorizeThenAccount` did not reproduce (`-count=200 -race`, final
  review); the `-race` load test near its bound, Task 12's M2–M6 and 12b's M-F2 (the backstop's
  mixed-case non-ASCII gap) stay open.

Spec §8 in full: built-in adapters, entity classes, user overrides and layering, pinned
platform set, `redact` patterns (accounting redaction was deferred from plan 1 and MUST land
here), `capability`/`bits`/`bit_delivery`, the **Junos projection** under decision 22
(bits first, regexes second, refused shape), differential testing in containerlab,
`port49 platform export`. Spec §9 capability inference. **Lab:** L9, L11 and L12, all closed
(L9 and L12 by plan 5b's Task 19, 2026-09-29).

**Inherits from the lab (PR #3), per platform — a wrong or extra reply attribute is fatal,
not ignored:**
- **NX-OS**: send `shell:roles`, never `priv-lvl`. The role wins over `priv-lvl` in both
  directions, the role alone suffices, and `priv-lvl` with no role silently picks a role by a
  per-release mapping (0/1/6 → `vdc-operator`, 15 → `network-admin`). An unknown role name
  silently becomes `network-operator`; two roles are a union; a misnamed attribute is
  rejected outright. Custom roles by name work (L16). `network-operator` cannot run bare
  `show interface` (prompts for sudo; `show interface *` works) and the cancelled sudo writes
  an accounting record under `admin` with `task_id=vsh.bin.$port`. **Nothing port49 sends ends
  a session here**: an attribute this device does not understand is ignored under EITHER flag,
  mandatory included, so a wrong attribute is invisible rather than fatal and the RFC 8907 §8.2
  flag buys an adapter no signal at all. Two more entries in the privilege-to-role table, both
  reached with no role in the reply: no attributes at all gives `vdc-operator`, and an
  out-of-range `priv-lvl=99` gives `network-operator` (L18).
- **vEOS**: send the **bare** `roles=<name>` **and** `priv-lvl=N` together — one role name, no
  quotes. The bare attribute is applied under either flag; `shell:roles*` is ignored and a
  mandatory `shell:roles=` or an optional `cisco-av-pair*` **refuses the session**. A role with
  no `priv-lvl` beside it lands the operator at level 1, where they cannot even read their own
  role — the opposite of the NX-OS rule, so the two platforms need different replies. The value
  is taken literally: quotes are kept as part of the name, and an unknown role is echoed back
  rather than degraded. An OPTIONAL `priv-lvl*N` **is** applied on 4.31.2F. Under
  `aaa authorization commands ... local` the delivered role is real privilege (`network-operator`
  is refused `configure`, `network-admin` is not, an unknown name is refused), so port49's
  per-command answer is the only control **while port49 is in the command path** and the role is
  the control when it is not (L16). **On the §8.2 question vEOS is the conformant one**: an
  OPTIONAL attribute it does not read is ignored and a MANDATORY one ends the session, whatever
  the name — an invented attribute does both — so the flag is a working switch here and
  `cisco-av-pair*` is an exception to that rule rather than the rule. A `priv-lvl` value the
  device cannot use is DROPPED rather than clamped: `priv-lvl=99` lands the operator at level 1,
  the same as sending nothing (L18).
- **IOS-XE**: kills the session on any unrecognised attribute, optional included; `priv-lvl`
  only (L3/L16 notes). L18 extends that to a second foreign spelling, an invented attribute and
  an out-of-range `priv-lvl=99` — seven of ten variants refused, all `% Authorization failed.`
  **And the cost is the device, not the session:** after a run of refused authorizations this
  image stops answering SSH for about a minute, refusing connections at the authentication
  layer **without sending port49 a packet**, so nothing in the decision log says it happened and
  break-glass is refused with everyone else. An adapter for this platform must send exactly what
  the device reads and nothing else; there is no cheap mistake here.
- **Junos**: `platforms.juniper_junos.session_services` (default `[junos-exec]`; production
  fleets use `tacplus-options service-name`, e.g. `junos-exec-fw`; the name never selects
  policy). The emitted reference config MUST include `tacplus-options strict-authorization`:
  without it a port49 denial is advisory (login completes, class from the `remote` template);
  with it the denial refuses SSH and NETCONF while break-glass still gets in with port49 down
  (L17). `authorization-time-interval` (min 15 min) re-authorizes but a denial does not end
  the session: revocation cannot reach a live Junos session. `enhanced-accounting` adds the
  client source `Port` to the login record. Accounting `service` stays `shell` whatever the
  session service is; `session_pid` is the per-session discriminator. **Attributes, measured on
  both images and agreeing cell for cell (L18):** `local-user-name=<template>` **is applied**
  under either flag — the session leaves the `remote` template for the class the reply names —
  and `user-permissions` did nothing over a template whose class carried bits, mandatory,
  optional, or sent beside `local-user-name`. L12 later measured it applied over a bitless
  template, both bits of a two-bit value, per session, so set 1.1.0 sends it over `p49-remote`
  (`tests/lab/results/L12-juniper_*.md`; branch C); L12 stays open for the differential. A template name the device does not have degrades silently
  to the default `remote` template. Everything Junos does not understand is ignored under either
  flag, so nothing port49 sends can end a Junos session by attribute. No variant produced a
  per-command authorization request, on either image, in any of 26 sessions — decision 21's
  shape, confirmed.
- **From the 2026-09-24 lab (`tests/lab/results/ceiling-*.md`, `L4-error-*.md`, `L21-*.md`):**
  the device enforces a ceiling only through the privilege level. IOS-XE and vEOS at level 1
  refuse `clear counters`, `clear ip bgp *` and `configure` in the parser without asking port49;
  IOS-XE level 7 is level 1 until the reference config assigns it commands (`privilege exec
  level 7 clear counters` gives exactly the operator rung); vEOS `network-operator` at 15 ran
  `clear counters`, had `clear ip bgp *` authorized (`% BGP inactive`: no BGP on that image) and
  entered `configure`, and every NX-OS role, `network-operator` included, ran all three — with
  `network-operator` also changing configuration (not typed under the other roles, nor on vEOS) —
  while command authorization points at port49. So the operator rung is port49's per-command
  policy there, not the role. The reference configs must be written for a store outage, which is not
  the break-glass case (only an unreachable port49 is), and the N9Kv `deadtime` trades the 5s
  silent-server penalty for a minute of refused token logins. All three per-command platforms
  send resolved words (L21, closed): `expands_abbreviations: true` for them over SSH, and
  interface arguments differ (IOS-XE `GigabitEthernet`, `1`; EOS/NX-OS one word).
- Device-generated accounting under another user (Junos root RPC in production, NX-OS
  `admin`/`vsh.bin`) is real and must not be treated as a foreign session (plan 2 rule).

**Inherits from plan 1:** a Junos session authorization is **permitted and carries no
attributes**. Plan 1 answered every one of them `service_unsupported` until 2026-09-21,
because `author.Handle` required `service=shell` while L10 measured Junos sending
`service=junos-exec`; it now reads the platform's `session_services` list (spec §5.2, §8),
which defaults to `[junos-exec]` for `juniper_junos` and is settable for a fleet that has run
`set system tacplus-options service-name`. So the envelope is recognised and the decision log
shows `permit context_matched` for Junos. **The attributes are this plan's whole remaining
job there**: the session-only projection — class, `local-user-name`, `user-permissions`, the
`allow-commands` / `deny-commands` regexes — is decision 22, gated on L12, and plan 1 sends
none of it.

**Owed from plan 2b (context join):** a configuration check that **warns when a port49-served
username exists as a device-local account** on the device (spec §5.6, "Local account names MUST
NOT collide"). Such an account's commands arrive under the same username and match the port49
context at its highest granted level; `foreign` attribution is the only detection until this check
exists.

**Owed from plan 4 (owner's rulings 2026-09-24):** spec §12's dead-rule and fallback-exposure
intersection checks, which need the level and role data this plan's adapters bring. Plan 4 built
the shadowed-deny report, the effective-permission diff and the privilege-expansion gate, because
it is the plan that replaced deny-overrides with dominance. Also: opening the pull request `port49
grants remove` prepares (plan 4 delivers the file edit). The rest of what plan 4 hands this
plan — the borrowed dialect table, the role-ceiling results and the `operator` rendering on EOS
and NX-OS decided 2026-09-24, the owner's level definitions, the `(?-i)` check on entity classes — is under plan
4's "Hands to plan 5".

**Possible later, not planned:** per-window contexts on the platforms that give a window its own
stable identifier — EOS `vty<n>`, bound at session authorization
(`tests/lab/results/L1-arista_eos.md`; again 2026-09-22), and IOS-XE `tty<n>`
(`tests/lab/results/L1-cisco_iosxe.md`). The `(nas, username)` join is the design of record; this
would refine it per platform and needs its own ruling first.

## Plan 6 — Inventory service (§19 step 6)

Spec §10: file inventory in full, NetBox and Nautobot connectors, the versioned bundle,
`bundle/diff`, bounded-change safety, **quarantine** (silence, not FAIL — decision 20),
admission snapshot refresh in the daemon, key rotation reporting (`keys status`,
`keys diagnose`, unvalidated-source report), device records, address-added-as-security-event.
Design §10 "Device inventory".

**Owed from plan 5a (owner's ruling 2026-09-24):** a blob whose rule text carries a value the
redaction patterns hide is logged with that text redacted and `"redacted": true` (spec §5.8), so
`port49 policy replay` reports every record naming it `unverifiable`. Verification comes back
when replay can take the verbatim blob from outside the log: from the versioned bundle this plan
publishes, from the store, or from `--policy <file>`, checked against the hash the log carries.
Also owed: a `based_on:` variant's wire facts. port49d keys `session_services`, the exec records'
commands and the system users by platform name, so 5a refuses `based_on: juniper_junos` at load
(spec §8; 5a final review M8). This plan carries those facts to a variant and lifts the refusal.

**Split into 6a and 6b (2026-09-30).** The seam is the bundle's source:

- **Plan 6a — `2026-09-30-06a-bundle-in-process.md`. Written 2026-09-30; executed 2026-09-30
  (as built, below); merged 2026-09-30 (PR #15).**
  Everything that
  consumes a bundle, with the bundle built in port49d from `inventory_file` and
  `broker.policy_file`: `bundle.ID` (a content hash) and `bundle.Parse`; the loaded policy as the
  one pointer that carries admission, devices, quarantine and policy (new decision 28); key groups
  moved into the policy file; a device no group admits refused on its own, never the daemon
  (`admission_refused`); the inventory file watched and reloaded, bounded
  (`inventory.max_removed_percent`), with the refresh after it and an inventory-only swap leaving
  unchanged contexts alone; `inventory_change` records for addresses added and `security_log` scope
  changes; scopes pinned by `name`; `retire_after`, `device.key_ref`/`key_version` on every
  validated record, `port49 keys status`, `keys show` and `keys diagnose` (over a 0600 admin
  socket); `policy test --config`; `port49 inventory diff`; `based_on:` variants read, and
  redacted, as their base; `policy replay --policy --inventory` for a redacted blob. Two lab rows,
  both new: L27 (what NetBox and Nautobot return, recorded as fixtures for 6b) and L28 (what a
  device does on a key miss, and a rotation end to end). Owner decisions at the plan's top: a
  device-level key-group tie refuses the device; `keys diagnose` over a local socket; and, for 6b,
  whether port49d takes the policy from the service. Revised after its pre-flight review: the
  inventory file is read behind the policy file's write fence; the key-group move is safe in every
  order; `SIGHUP` re-reads the bound; the broker refuses to mint for a refused device
  (`device_unknown`); a test on an absent device fails CI and never a reload; a policy reload is held to
  the same bound as an inventory reload, and `policy diff` fails on a newly refused device.
- **Plan 6b — `2026-09-30-06b-inventory-service.md`. Written 2026-09-30; executed 2026-09-30
  (as built, below); merged 2026-09-30 (PR #18).**
  `cmd/port49-inventory` with the §10 API over mutual TLS (read and sync rights), the file connector,
  three of the four sync triggers (10-minute schedule, `port49 inventory sync`, startup), bounded
  change per source in the service, the signed bundle document and its sequence number, port49d's
  30 s pull with ETag, the persisted last good bundle, the shared mirror (a mounted directory), and
  cold-start readiness; owner decision 3's mismatch alarm; `SIGHUP` and a refused load trying both
  sources together (6a m7); the write fence moved to `internal/fence`. Lab: L29 (the reload case
  through syncs, and the midnight case as four scheduled runs), spec §14's quarantine through a sync,
  and L30 recorded as fixtures for 6c. Owner decisions at its top: every copy of the bundle signed
  (ed25519) and verified; the mirror a directory, not an object-store API; nothing the service sends
  assigns a key, and the pin tier moves into the reviewed policy as a key group matching a device name
  (revised after the pre-flight review: a `/32` group is tier 3 and is not a pin).
- **Fix `fix/breakglass-reset` — `2026-09-30-06b1-breakglass-reset.md`. Written 2026-09-30.** Right after 6b merges, before 6c. Closes **L31** (spec §15;
  `tests/lab/results/L31-breakglass-cisco-singleconnection.md`). With single-connection on,
  IOS-XE and NX-OS wait out their 5 s timeout after a reset that follows their request, so
  break-glass costs 16–21 s on a refused or quarantined device and 30–41 s on a removed one. Give
  the unadmitted, refused and quarantined paths (`internal/daemon/server/conn.go:233-238`,
  `:261-262`) L28's shape: record the first connection, reset it at once, and refuse the source's
  next connections at Accept for a short window. The unadmitted path takes a `keyMiss`-style close
  in place of `backoff`. Refused and quarantined, which take no strike by spec, get a strike-free
  window checked beside `Holding` (`server.go:119`) and cleared at every reload, so a fix or
  re-admission takes effect at once. Retries inside the window are counted, not recorded, so spec
  §10's "one record per connection" for the quarantine close and the `conn.go` comment change with
  it. Lab: IOS-XE and NX-OS with single-connection on, removed, refused and quarantined, against
  port49d stopped; the run closes L31. **Executed 2026-09-30**, closing L31 (As built, below). What
  shipped differs from this text in three places: the window is not cleared at a reload but
  re-checked at every Accept against the admission and policy in force, which covers a quarantine
  that ends without a reload too; the lab bar is the rekeyed control (a key miss) plus 1.5 s, with
  port49d stopped measured beside it; and vEOS ran as a no-regression check.
- **Plan 6c — `2026-10-01-06c-inventory-connectors.md`. Written 2026-10-01; executed 2026-10-01
  (as built, below).** Written after 6b and
  `fix/breakglass-reset` merged, against L27's and L30's fixtures; the rulings it made where spec §10
  is silent are at its top and become spec §13 decision 31, and it opens L32 (the connectors as
  built, through two kinds of TLS proxy) and L33 (webhooks to port49-inventory over TLS, and a NetBox
  and a Nautobot synced to vEOS). Version detection by `/api/status/`, GraphQL first, the REST fallback (`?depth=1` on
  Nautobot 2.x, following `next` as L30 finds it), the slug alias table, filters and maps, source
  credentials by `secret_env`, and the authenticated webhook trigger (HMAC-SHA512 of the body; a delivery
  only triggers a sync, so its order orders nothing and its `timestamp` is read for freshness alone,
  plan 6c ruling 2); every `Fetch` returning within
  `sync_timeout`; and `port49 inventory export --service … [--from N]`, so the offline tools keep an
  `--inventory` when no source is a file. Split from 6b because the connectors
  are the contributable surface and hold the only source-of-truth credentials, and two of their facts
  (L30) were unmeasured when 6b was written. **From L30, as measured** (spec §15; `L30-netbox.md`,
  `L30-nautobot.md`): follow `next` only when its scheme, host and port are the configured base's
  (every product builds `next` from the host the request arrived under), or rebuild it from the
  base; read GraphQL's `errors` before `data` even on HTTP 200 (NetBox 4.7.1 answers an unknown
  argument that way, with no names); take the status spelling per product and version (`"ACTIVE"`
  on NetBox 3.7, `"active"` on 4.x, `{"name": "Active"}` on Nautobot); page GraphQL by
  `pagination: {offset, limit}` on NetBox 4.x and `limit`/`offset` on Nautobot, and not at all on
  NetBox 3.7; and expect no `cluster` or `software_image_files` on a Nautobot 3.2.6 device, which
  otherwise answered as 2.4.43 did, so no separate 3.x profile is indicated. Its lab run syncs a
  NetBox and a Nautobot to a device end to end.

**Go-dark on a store outage is plan 7's**, with the remote store (plan 4's "Hands to plan 6": "plan
6 or 7, whichever brings the remote store"; plan 6 builds none), and so are the warm context
cache, plan 4b's remote-store items, and the `crypt_open_failures_total{record="token"}` alarm.

### Plan 6a — As built

Executed 2026-09-30 on `feature/bundle-in-process`, twenty-two tasks, each reviewed; the ledger is
`.superpowers/sdd/2026-09-30-06a-bundle-in-process/progress.md`. What differs from the plan's
text, task by task:

- **Task 3.** A device whose `transport` is `tls`, or neither `tcp` nor `tls`, refuses that device
  alone (`refused_transport`), not the inventory file; spec §10 was edited to say so.
  `admission.Resolve` decides one device (transport, then key group), and the admit step adds
  only the unknown-key check.
- **Task 4.** A refused entry never carries a `KeyRef`: the daemon and the config read a non-empty
  `KeyRef` as admitted, so a refusal names the undefined key in its text instead.
- **Tasks 7, 10, 12.** A bundle that admits none of a non-empty inventory is refused at start
  **and at both reloads**, the inventory's and the policy's, whatever
  `inventory.max_removed_percent` says, in the same words, naming `stop port49d` as the deliberate
  path. A quarantined device counts as admitted for the bound.
- **Task 11a** (added by the pre-flight review) fenced the inventory file at start; Task 12 fenced
  it at every reload, keeping the last good inventory and raising `port49_inventory_file_refused`.
- **Task 12.** The key-group move done in the wrong order (deleted from the inventory first) and
  followed by a restart refuses the start, naming the fix: a device sees the same fallback whether
  port49d is down or admits nothing, and the refusal is louder.
- **Task 14.** A key version ends at `retire_after` **even on an open connection**: each packet is
  judged at its own time, and the first past the date is refused. The plan had the version last
  the connection's life; a busy single-connect connection never idles out, so that had no bound.
  Spec §10 and Decided 7 were amended. `port49_key_version_devices` counts only since start (spec
  §10 says so, with an uptime-gated alert example), and the process collector is exported for it.
- **Task 15.** `key_ref` is constrained to `^[a-z][a-z0-9_]{0,63}$` wherever one is written,
  since every report prints it; YAML decode errors in port49d.yaml and the inventory print the
  line and a category only (`internal/yamlfault`); a missing environment variable is named by its
  key, not its variable; the clock is injected. Three fix rounds, each closing a path by which a
  pasted secret could reach output.
- **Task 16.** The other-uid refusal test (`TestAnotherUIDIsRefused`) needs root; the controller
  ran it with `sudo -n` and it passed. Non-root CI skips it.
- **Task 17.** A scope pinning a name the inventory lacks is a **warning** in `policy test`, not a
  failure: onboarding a device before it is in inventory is legitimate.
- **Task 18.** An unknown field is reported by line. Without `--config`, `inventory diff` warns
  that key_refs are unchecked and does not fail on it, and its admit-none check uses `policy
  test`'s. Under `--new-policy`, security marks are per step, and a two-file change that stops
  half-applied in one order exits 1.
- **Task 19** fixed a leak in the plan's code: when a record's `redacted` mark has been edited out
  of the log, a divergence printed the verbatim blob's rule text, secret included. Against a blob
  from the files, replay now prints only the log's side, and its output goes through the loaded
  policy's redaction.
- **Task 20** took **branch H** (below). A packet past `retire_after` on an open connection is
  closed as a first-packet miss is, with a strike and a reset.
- **Final review and fix wave** (`final-review.md`, `fixwave-report.md` beside the ledger).
  - **I1: a reload ends an open connection whose admission it withdrew.** Every packet looks its
    source up again in the admission in force, beside the quarantine and `retire_after` checks.
    A device refused, removed, renamed, moved to another `key_ref`, or given another platform or
    `based_on:` base (re-review R1) is reset at its next packet, with no reply and no strike, and one `unvalidated` record, reason `device_unknown`, diagnosis
    `admission_refused`, `unadmitted_source` or the new `admission_withdrawn`
    (`port49_connection_events_total{event="admission_closed"}`). Spec §10's "in-flight
    connections complete against the snapshot they began with" was amended as Task 14 amended
    Decided 7: a busy single-connect connection has no end, and a device moved off a compromised
    key kept speaking it. How a device takes the reset is L29's, which gained the reload case.
  - port49d.yaml, at start and at `SIGHUP`, and the inventory at start with no broker, are read as
    regular files only, non-blocking and bounded (`config.ReadRegular`): a named pipe at either
    path hung the start, or blocked the reloader and with it shutdown.
  - The admin socket is stale only when its dial is refused (`ECONNREFUSED`); any other dial
    error, such as another uid's socket (`EACCES`), refuses the start and removes nothing.
  - A swap forgets the `port49_key_version_devices` marks, and the packets held for
    `keys diagnose`, of devices the new bundle no longer admits under the `key_ref` they were seen
    on (a re-keyed device's held packet is kept).
  - An inventory fault names the file once.
  - Tests added: reverting to the inventory in force clears `port49_inventory_file_refused`; the
    refused device's start line, admitted count and gauge; both session-side replay guards (each
    fails with its guard removed); `policy diff`'s 20-line cap; a key group's bad `cidr` printed
    by position. `TestProjectionLoadTime` skips under `-race`, as the engine's timed tests do.

**Owner decisions, as ruled** (the anti-escalation defaults; Ryan may override): 1, a key-group tie
that exists only against the inventory refuses that device alone; 2, `keys diagnose` over a 0600
`SO_PEERCRED` Unix socket, off by default; 3, for 6b, port49d keeps its own policy file and takes
only the inventory from the service. **Key groups:** where both files carry them, the policy's win
and a notice names the inventory's as ignored.

**L28 took branch H.** The hold stalled break-glass on all four images (`L28-held-*.md`: three
commands 25–28 s on EOS, NX-OS and IOS-XE, 5.9 s on vJunos-router). port49d now strikes a key
miss and resets it at once, and refuses a source inside its backoff at Accept with a reset
(`key_miss_closed`, `held_refused`). A FIN was tried first and still cost the C8000V its own 5 s
timeout (`L28-fin-cisco_iosxe.md`), so the close is a reset. Break-glass is now at port49d-stopped
times on all four (`L28-*.md`). One record per strike; attempts refused inside a backoff leave
only the `held_refused` count. Accepted in review: a strike from a device's address resets that
address's connections for up to 5 s (denial of service, not escalation; spec §10 says so).

**Rows:** L27 and L28 closed 2026-09-30. L29 opened: what a device does when port49d resets an open
connection, at its key version's `retire_after` (a run across midnight UTC) or after a reload
withdrew its admission (a `SIGHUP` between two commands); split from L28, which measured first
packets only. L30 opened in the fix wave for L27's unmeasured parts: a non-null pagination `next`,
and Nautobot 3.x. Both are plan 6b's.

**Carried, for later plans:**

- **Plan 6b:** the object-store mirror, the persisted last good bundle and cold-start readiness;
  the bundle document and its integer sequence; owner decision 3's policy-hash mismatch notice and
  alarm; `SIGHUP` trying the combined bundle when both files changed, so a whole-fleet re-address
  does not deadlock and an intermediate bundle revokes nothing the final one admits (final review
  m7; until then the operator notes give the make-before-break order); **L29** (6b is the next
  plan with a device lab run, spec §14's quarantine through a sync, and its syncs make the reload
  case routine), and with it why the C8000V's liveness probe reached port49d only at its second or
  third attempt in L28 (Task 21 review m4); **L30**, L27's gaps: a non-null pagination `next` and
  Nautobot 3.x (Docker Hub has a 3.2 line); and L27's findings: Nautobot 1.6's `Api-Version` is `1.2`, so detect by `/api/status/`; Nautobot
  2.x REST at default depth names no related object, so read `?depth=1` or GraphQL; Nautobot
  delivers webhooks out of change order, so order by the body's `timestamp`.
- **Plan 7:** go-dark on a store outage, the warm context cache, and plan 4b's remote-store items.
  The `crypt_open_failures_total{record="token"}` alarm, which plan 2 handed to "plan 6 with key
  rotation reporting, or plan 7", goes to plan 7: it guards the encryption-at-rest rotation, not
  the device keys 6a reports on (M11).
- **Plan 12:** `secret_ref:` resolvers, and the key sets moving into the policy repository with
  them; `key_ref` as a device label in per-device-pin deployments (unchanged, and now on
  `port49_key_version_devices` and `port49_key_retirement_seconds` too); the write fence's
  unchecked ancestor directories and ACLs, now for `inventory_file` as well as the policy file;
  running `TestAnotherUIDIsRefused` in CI with root; measuring, at fleet size, the inventory-only
  refresh's blob comparison (one blob read and two decodes per live context, which a per-pass cache
  would cut; Task 11, M2).
- **Later, unassigned:** seeding `port49_key_version_devices` from the decision log at start, so a
  restart does not blank it (spec §10). The offline tools (`port49 policy test`, `policy diff`,
  `inventory diff`) still read the inventory with a plain read: a named pipe there hangs the tool, not
  port49d.
- **Where the final review's carries went:** Task 12 m1 (an open connection kept its admission),
  fixed as I1; Task 12 m2 (the revert test), Task 10 (the gauge and start lines), Task 19 (two
  replay guards) and Task 17 (the cap), tested; Task 12 m3 (`SIGHUP`'s unfenced read) and Task
  11a (`config.Load`'s pre-fence read), fixed; Task 16's stale detection, fixed; Task 16's
  non-root CI, plan 12 (above); final review m6, m9 and m10, fixed; m7, plan 6b (above); m8, L30.

### Plan 6b — As built

Executed 2026-09-30 on `feature/inventory-service`, each task reviewed, then a whole-branch review,
a fix wave and a scoped re-review; the ledger is
`.superpowers/sdd/2026-09-30-06b-inventory-service/progress.md`, with `final-review.md` and
`fixwave-report.md` beside it. A conflict scan before Task 1 ruled twenty mismatches between tasks
(F1–F20) and patched the plan on `main`, so each brief carried its fix. What differs from the plan's
text, task by task:

- **Conflict scan.** A cold start takes the copy published later (`published_at`), not the higher
  sequence (F1). The fetcher is joined at shutdown and says nothing when its context ends (F8). A
  cold-start copy that does not open sets `port49_inventory_bundle_refused` (F19). Lab tasks run
  `make test && make vet` before committing (F17).
- **Task 4.** `bundle.Open` refuses a document whose `sources` lists name a device that fails the
  inventory's name check, without echoing it, so the one choke point closes log injection; the
  syncer lists only names that pass.
- **Task 5.** port49-inventory.yaml refuses a second YAML document. port49d.yaml's loader does not;
  that is carried to plan 12.
- **Task 8.** The service reads its state behind the fence, a link in a file's own name refused
  (`fence.ReadNoLink`), because `state_dir` is the sequence's trust anchor: a planted older signed
  document could otherwise roll it back. The mirror is trusted by signature alone
  (`fence.ReadSigned`: no link in its name, a regular file, capped), so a ConfigMap-link mirror
  mount is refused, which fails closed. The rollback floor includes `published.json`.
- **Task 9.** `Restore` refuses a start rather than publish below a copy: a `state_dir` copy it
  cannot open, and, with `state_dir` empty, a mirror copy it cannot open. Beside a good `state_dir`
  a bad mirror is said and shows as `port49_inventory_mirror_behind`. `WriteMirror` never lowers the
  mirror's sequence, and the service rewrites a mirror that differs from its sealed bundle at start
  and at every pass, not only at a publish. The per-source `interval` was kept, as spec §10 has it,
  reversing pre-flight Minor 2.
- **Task 10.** Review found a URI SAN beginning `user:` impersonating an email identity: it is
  refused. A nil trust anchor is refused rather than falling back to the system roots, and
  `inventory.Server` returns an error. `readers` and `syncers` match exactly, `*` is not a wildcard,
  and a `user:` entry with an upper-case letter refuses the config, since callers' emails are
  matched lower-cased.
- **Task 12.** The client dials with a fresh, fully verified TLS config per connection, so a CA
  rotation needs no signal; text from a peer's certificate in a TLS error is sanitized before it is
  printed; the diff URL is built with `RawQuery`. `port49 inventory sync` waits as long as a sync
  may take (`sync_timeout`); every ask port49d makes has its 30 s deadline (F16).
- **Task 13.** Every path under `inventory.service` is absolute, `state_dir` and `mirror_dir` may
  not overlap either way, and the URL is strict `https`.
- **Task 14.** A copy published more than 5 minutes ahead of port49d's clock is refused, and judged
  again as the clock advances. The persisted copy is read through `fence.Read`, the mirror's through
  `OpenSignedFile`.
- **Task 15.** Review found that a `SIGHUP` could apply a held document signed by a key it had just
  removed: every apply now opens the document under the verify keys in force at that moment, through
  one `openDocument`. Documents are ordered by (`published_at`, `sequence`), so an older document
  replayed from before a service reset is refused.
- **Task 17.** The combined check runs in `reload` after the verify keys are re-read, through
  `openDocument`. A policy that fails to parse while an inventory is settled is said with it, and the
  inventory is tried again once a policy loads.
- **Task 19.** A phase counts only when port49d's `device_unknown` record and the capture both show
  a connection open across the change. The capture is read against the instant port49d applied the
  reload, not the sync's start, and an idle connection open before it counts. NX-OS's
  single-connection line is typed as its `?` offers (`key 0 <key> single-connection`). A mid-run
  `make build` in the shared worktree invalidated one vJunos run, so every device run since builds
  in a pinned, detached worktree.
- **Task 20** was built and reviewed, and its four overnight runs were dropped (owner decisions,
  below). `TestL29Midnight` stays in `tests/lab/`, gated by `PORT49_L29_MIDNIGHT`, and unused.
- **Final review** (FIX FIRST: no critical, three important, nine minor; all seven security
  invariants held) **and fix wave**, re-reviewed MERGE:
  - **I1: a correctly followed signing-key rotation left the old key's signature in force** on a
    stable fleet, so dropping the old key took TACACS+ down at the next port49d restart. The
    service now re-seals a bundle another key signed as the next sequence, at start and after every
    sync that does not publish, and says when the old key can go (decision 30's rotation order).
  - **I2: cold start persisted the newer copy before the policy accepted it,** so a restart during
    a re-address crash-looped. port49d now takes the newest copy its policy loads, bounds the
    mirror's copy against the persisted one by its own `max_removed_percent`, falls back to the
    other copy with a line, and persists only after the broker is built.
  - **I3: a hung mirror mount hung the service silently.** Mirror reads and writes run under a
    10 s deadline outside the sync lock, `mirror_behind` is 1 before the read, and the metrics
    listener, `/healthz` and `/readyz` (503) bind before `Restore`.
  - Minors: the service's `policy_file` behind the fence; the next sequence is above both the
    history and the last publication, so a Save that failed halfway no longer wedges the service;
    a clock stepped back publishes 1 s after the last publication, said; a refused document counts
    `port49_inventory_fetches_total{outcome="refused"}`, not `unchanged`, and a `SIGHUP` counts it
    once; two pre-6b server tests wait out their own teardown; the operator notes say to protect
    `ca_file`; the plan-12 carry below. Folded in after the re-review: two overlapping mirror calls
    no longer read a slow mirror as hung (N1).

**Owner decisions, as ruled:** 1, every copy of the bundle signed (ed25519) and verified, the
service's own state and mirror against its own `verify_key_files`; 2, the mirror a mounted
directory, not an object-store API; 3, nothing the service sends assigns a key, and a pin is a
policy key group matching the device's name, at tier 1 (a `/32` group is tier 3). **Ryan,
2026-09-30:** Task 20's midnight nights are dropped. The device sees the same TCP reset from
`retire_after` as from a reload, which Task 19 measured, and port49d's reset at the date is tested
in code with an injected clock (`internal/daemon/server/server_test.go`). L29 was reworded to say
so.

**Rows:** **L29 closed** 2026-09-30 on all four images (`L29-reload-*.md`). The session survives
the reset everywhere. Where port49d no longer serves the device, break-glass logs in: in up to
2.1 s on vEOS and vJunos-router, and up to 30 s on the C8000V and 41 s on the N9Kv. Where it still
serves the device under a new name or platform, its FAIL is final on EOS, NX-OS and IOS-XE.
vJunos-router held a connection open across some changes only: its committed note (the run at
6fcce47) measures removed and refused; earlier runs, observed in the lab log and not register
evidence, varied in which phases held one open. **L30 closed** 2026-09-30 (`L30-netbox.md`,
`L30-nautobot.md`), with which of `Host` and `X-Forwarded-Host` a product reads, and a proxied
`next` followed, named as unmeasured outside its question. **Spec §14's quarantine through a sync
passed** on all four (`quarantine-sync-*.md`). **L31 opened** (closed since by `fix/breakglass-reset`, as built below): with single-connection on, break-glass on
IOS-XE and NX-OS costs 16–41 s after a de-admitted device's reset (`L31-breakglass-cisco-singleconnection.md`). The C8000V's
liveness probe again reached port49 only at its second or third attempt before two of six phases
(30 s, 54 s); why is still not established.

**Carried, for later plans:**

- **Plan 6c:** the connectors, the webhook trigger, `Fetch` within `sync_timeout`, and `port49
  inventory export` (Plan 6c, above), written against L27 and L30 as measured: `next` followed only
  to the configured base's scheme, host and port; GraphQL `errors` read even on HTTP 200; the status
  spelling per product; Nautobot 3.2.6 dropping `cluster` and `software_image_files`.
- **Plan 12:** port49d.yaml's loader, and `config.InventoryServiceOf`, ignore a second YAML
  document (Plan 12, above).
- **`fix/breakglass-reset` (above), L31:** break-glass on the N9Kv and the C8000V took 17–41 s
  after a reload removed or refused the device, and 16.7 s and 20.3 s through a quarantine sync.
  The cause is analysed in `L31-breakglass-cisco-singleconnection.md`: with single-connection on,
  a reset after the request is waited out, and those paths never refuse the retries at Accept.
  Done: closed 2026-09-30 (below).
- **Later, unassigned:** the C8000V's slow liveness probe (above).

### Fix `fix/breakglass-reset` — As built

Executed 2026-09-30 on `fix/breakglass-reset`, each task reviewed; the ledger is
`.superpowers/sdd/2026-09-30-06b1-breakglass-reset/progress.md`. A pre-flight review revised the
plan first (8ee966f). The window is cleared by re-asking admission and the policy at Accept, not
at a reload, which covers a quarantine that ends without one, and it counts as its own event,
`declined_refused`, not `held_refused`.

- **Task 1 (docs):** spec §10's "A declined source is refused at Accept, and takes no strike", the
  refused-device, quarantine and reload paragraphs, a §14 bullet, and design §11 (e2d9765,
  26d666d; review minors 4573df8).
- **Task 2 (limits):** `Decline`, `Declined` and `Undecline`, a decline window on the strike's
  schedule and settings that is never a strike (6729c45, 9fd5c7e).
- **Task 3 (server):** an unadmitted source closes as a key miss does: record, strike, reset at
  once, never held; its retries are refused at Accept as `held_refused` (2db70ee).
- **Task 4 (server):** refused, quarantined, and reload-refused or removed connections record,
  reset at once and open a decline window; Accept re-asks admission and the policy inside it, and
  counts refusals as `declined_refused` (9e19e94). A quarantine landing between Accept's re-ask and
  `Undecline` fails closed (34b770a).
- **Task 5 (lab harness):** `TestL31BreakGlass` (dfec85f). Its review found the premises counted
  from the token login, not the break-glass interval, and a refused break-glass scored as a pass;
  both were fixed against the brief (b998ae9), and the runs were pinned there.
- **Task 6 (lab):** L31 on the N9Kv, the C8000V and vEOS with single-connection on (cfd34fd).
  Break-glass removed, refused and quarantined took 2.62, 2.58 and 2.61 s on the N9Kv against the
  control's 2.61 s, 1.28, 1.78 and 1.78 s on the C8000V against 1.28 s, and 0.33, 0.32 and 0.32 s
  on vEOS against 0.34 s; every declined phase's retries were refused at Accept.
- **Task 7 (docs):** **L31 closed** (spec §15), with the §10 sentences, the L29 and L31 notes and
  the `conn.go` quarantine comment giving the measured times; this section.

**Carried:** the C8000V's slow liveness probe (Plan 6b, above), still unassigned. vJunos-router did
not run L31: it was unaffected before the fix, and the fix only adds refusals at Accept.

**Follow-up, unassigned (final review M4):** the per-NAS cap's refusal at Accept
(`internal/daemon/server/server.go`, `refused_cap`) closes with a FIN, not a reset. This predates
this branch and is not a regression. A FIN that comes before the device writes is unmeasured on
IOS-XE and NX-OS with single-connection on, and L28 found the C8000V waits out a FIN that follows
its request. The default cap of 32 makes it unlikely for one device. Either reset before the close
at the cap, or add a lab register row and measure it first.

### Plan 6c — As built

Executed 2026-10-01 on `feature/inventory-connectors`, seventeen tasks, each reviewed; merged 2026-10-01 (PR #19,
merge 888b1d5) after a whole-branch review (MERGE, 0/0/8), its fix wave, and one last fix (943f225, final
re-review N1: a source is given the bundle's names only after a cut-short fetch returns); the ledger is
`.superpowers/sdd/2026-10-01-06c-inventory-connectors/progress.md`, with each task's brief, report
and review beside it. A pre-flight review revised the plan first (three important, seventeen minor;
the plan's "Revised after the pre-flight review"). What differs from the plan's text, task by task:

- **Task 1 (docs; e8ec237, 81c5b65).** Interface addresses are added to the primary addresses, never
  used in place of them, and `addresses.primary` defaults to true (review I1; ruling 10, spec §10
  and decision 31 amended). Design §17 names the webhook as the one inbound call without a workload
  identity, and says the secret is never sent with a delivery.
- **Task 2 (`internal/sot` client; d0bedc0, d9fe335).** The client refuses any request whose scheme
  or host is not the base's, so the token reaches `url` alone; a transport error keeps its cause and
  never prints the query; idle connections expire at 90 s.
- **Task 3 (profiles; 167127f, 0c2e60e).** Under a `profile:` override a release reads as measured
  only when the override is the profile detection would pick, and the said line names the override.
- **Task 4 (`sottest.Server`; 68664e9, 4d37cb9, b9c18eb, b1407e5).** The replay answers only the
  fields a query selects, each stack's ids in its own form (Nautobot UUIDs, NetBox numbers), L30's
  refusal texts word for word, and the recorded `name` filters over GraphQL and REST `?name=`; every
  shape no run recorded is marked so.
- **Task 5 (GraphQL; 1337890, ef45646).** A status error names the request under the `url`'s path
  prefix; `page_size` below 1 is refused; a page that begins with the device the page before began
  with fails as "ignored the offset", and a repeat fails at the page that holds it.
- **Task 6 (REST; fcd48cd, bd89f94).** `next` is always rebuilt on the base, its path and query kept,
  and said only when its origin differed; a `next` on another path is refused; a `next` dropping
  `depth=1` where the profile needs it is refused; the loop check compares the path and the sorted
  query.
- **Task 7 (mapping; db11f8e, e92fc6f).** `addrOf` drops no address for its prefix length (a
  `10.255.0.0/16` loopback is a real device's address); it refuses only a zone, and unmaps
  IPv4-mapped IPv6.
- **Task 8 (`sot.Source`; 94c1a17, 2b9582a).** Every removal is confirmed (ruling on Task 5's I-1):
  at most 256 names gone from a source's last read are each asked for by REST `?name=`, and one
  still there and in scope makes the read inconsistent; past 256, the list is read once more, whole,
  and taken only when both reads list the same names, else the sync fails ("the list changed between
  two reads"), and a failure keeps the last read. A `?name=` answer naming another device fails the
  read (an ignored filter cannot confirm anything). The detect note names a `profile:` override.
- **Task 9 (config; 42ed46f, 6d334b8).** `platform_aliases` refuses two keys equal in lower case, and
  `filter: {status: []}` is refused; `sot.ProfilesOf` lists the profiles a product takes.
- **Task 10 (`Fetch` within `sync_timeout`; 6642ce7, 631258a, ea40177).** A fetch is abandoned 5 s
  past `sync_timeout`; `port49_inventory_source_hung` clears when the abandoned call returns, not at
  the next sync; a caller's cancel (shutdown) is not a hang and waits for nothing; a complete answer
  inside the 5 s grace is used, as spec §10 allows. `port49_inventory_generic_platform_devices`
  counts the bundle in force.
- **Task 10a (bounds; 29eab03, c3dad62).** Both removal bounds, the service's and port49d's, count a
  device left with no address only if the old inventory admitted it, and a test holds the two to the
  same count.
- **Task 11 (the webhook handler; ea9c93a, 9b23238, 79d59cf).** A known and an unknown source name
  are answered alike up to the HMAC compare, the unknown one checked against a random decoy key, so
  neither the answer nor the bytes read tell them apart; a declared length over 1 MiB gets
  413 before any read; a replay entry lives until its timestamp plus 5 minutes, in wall time; a
  refusal line is re-armed by an accepted delivery at most once per 5-minute window, with an owed
  re-arm so a refusal after a deferred re-arm is still said once.
- **Task 12 (the listener; 0e0364d, 89eed09).** The webhook listener is capped at 64 connections, a
  bind error names `webhook_listen`, and a request in flight at shutdown is waited for. A delivery
  that arrives as shutdown begins is accepted and triggers nothing, and after that the connection is
  refused; the `503 {"error":"shutting_down"}` the handler holds is never sent (final review M1, which
  corrected this line, L33's notes and spec §15).
- **Task 13 (`inventory export`; a238518, afe4b5e).** It verifies before it writes; `?sequence=`
  takes canonical decimal only; `State.At` refuses a history file holding another sequence; a
  failed write to standard output exits 1; a symlinked `--out` is said as one; the header names the
  service's scheme and host only. `--from 0` is a usage error.
- **Task 14 (lab, L32; a50c993, 0f7cd70, e8bbe15, eb862a4, f2c43b6).** A third proxy,
  `proxy_plain` (a bare `proxy_pass`), was added in review, since neither planned proxy made any
  release name another origin; through it every release named its internal `http://<svc>:8080`, and
  the connector rebuilt `next` on `url` and said so. L32 found GraphQL's `id` selectable, a string,
  on all five releases, so the GraphQL list is keyed by `id` (e8bbe15), as REST's is, and the run was
  repeated; the name-based offset-ignored check is kept.
- **Task 15 (lab, L33; c8a63d8, 76de80e, 1c0b8d1, 6f96ab2, 0b4886f).** Beside the 401, a delivery
  answered 503 by a stand-in listener (port49-inventory itself never answers a delivery 503) was
  measured, and each release's retry setting read from its source. `run.sh`'s e2e mode selected no platform and both device runs wrote one capture name; both
  were fixed and the device runs repeated.
- **Task 16 (docs; e60f6a3, 101ce68).** L32 and L33 closed; spec §10's three "§15 L32's/L33's"
  sentences replaced by the measured answers; this section.
- **Final review** (MERGE: 0 critical, 0 important, 8 minor) **and fix wave**:
  - **M1:** port49-inventory never answers a delivery 503 at shutdown (above, Task 12); the as-built,
    spec §10 and §15 and L33's notes said it did, and were corrected (lab rule 4).
  - **M2:** a source confirms a removal against the names the bundle in force holds for it, given by
    the syncer before each fetch (`inventory.Confirmer`), not its own last read: a refused or
    abandoned read is no baseline, and a restart confirms against the restored bundle (71969a5).
  - **M3:** notes of single devices are bounded apart from the source's own, so they cannot silence
    a rebuilt `next` or a fallback; **M4:** the hung gauge's comment says it falls when a running
    sync ends (71969a5).
  - **M5:** `Webhooks.Secrets` holds `sot.Secret`, redacted however printed (89068bb).
  - **M6:** the L33 runs check the service's log for the API token as well as the webhook secret
    (d16d501).
  - **M7:** `internal/printsafe.Line` replaces the two printable-line copies, and `bundle.names`
    builds on `nameList` (8fa9637).
  - **M8:** the raw L33 captures are copied to the main checkout before the worktree is removed
    (the controller's step).

**Rulings, as made** (spec §13, decision 31; the plan's "Rulings where the spec is silent"): all
fourteen stand, with these amendments, each the option that denies more. Ruling 6: a list must
equal REST's `count` before and after it (pre-flight I1), and every removal is confirmed or read
twice (Task 8). Ruling 7: `next` is always built on the base (Task 6). Ruling 3: every 401 has one
body and a known source name is not told from an unknown one (pre-flight M9, Task 11). Ruling 10:
interface addresses are additive (Task 1). Ruling 12: the generic-platform line is said at each
publication that changes the set (pre-flight M6). Ruling 13: a complete answer inside the grace is
used (Task 10).

**Rows:** **L32 closed** 2026-10-01 (`L32-netbox.md`, `L32-nautobot.md`): every release builds `next`
from `X-Forwarded-Host` when sent, from `Host` otherwise, and takes `https` only from
`X-Forwarded-Proto`; the connector as built read all 120 devices through three proxies over GraphQL
and REST on all five releases, rebuilding `next` on `url` where a bare proxy left it naming the
upstream. **L33 closed** 2026-10-01 (`L33-netbox.md`, `L33-nautobot.md`,
`L33-e2e-netbox-arista_eos.md`, `L33-e2e-nautobot-arista_eos.md`): every release delivered over TLS
under a private CA; a change published in 2.4–2.7 s from NetBox and 3.6–4.1 s from Nautobot, and
reached port49d's reload on vEOS in 2.5–5.0 s and 4.5–7.0 s; no release sends a delivery refused 401,
or answered 503 by a stand-in listener, again by default.

**Operator notes** (for plan 13's docs, beside the plan's "Operator-facing notes"):

- `HTTPS_PROXY` is ignored by design: the service dials each source directly, so a source reachable
  only through an egress proxy is unsupported until plan 12.
- A webhook refused is not sent again by any measured release at its defaults (NetBox
  `RQ_RETRY_MAX` 0; Nautobot none). The source's `interval` sync is the backstop: size it to how long
  a change may wait.
- A webhook that arrives as port49-inventory shuts down is accepted and triggers nothing, or is
  refused at connect; it is never answered 503. By the same retry settings it is not sent again
  (the restart case follows from those settings; no run measured it). The startup sync, which reads
  every source, covers it.
- `port49 inventory export` without `--from` accepts an older genuine bundle; the header names its
  sequence.

**Carried, for later plans:**

- **Plan 12:** `token_secret_ref:` and `webhook_secret_ref:` with the `secret_ref:` resolvers; the
  service honouring an outbound HTTP proxy for its sources (it dials each source directly).
- **Later, unassigned:** tags as an attribute, once the spec gives a multi-valued attribute a shape;
  server-side GraphQL filters, once a lab run records each release's filter arguments; a GraphQL list
  above a server cap and a list changing between pages, which the count check turns into a failed
  sync rather than a silent loss but no run measured; further connectors (Infrahub, Ansible
  inventory), which take the same `inventory.Source`.

**Follow-ups, unassigned (not blocking):** plain HTTP on `webhook_listen` is refused (400) but
counted on no metric (Task 12 review M3); a `SIGTERM` during the 5 s fetch grace of a sync already
past its deadline waits it out, at most 5 s (Task 10 N1); L32's record could hold whether `next`'s
host resolves, so the note quotes it rather than the controller's reading (Task 14 M-R1).

## Plan 7 — Broker in full (§19 step 7)

Design §7 (OIDC public client with PKCE, certificate-to-directory mapping, directory
integration, trust domain by verifier lists), §10 (server pool, pre-warm, grace, replication
lag), §17 (the whole API surface, idempotency, batch mint, **`api:` rights** default
self-only, `/v1/refresh` with `prompt=login` and the cert-path signed-nonce refresh,
`/v1/logout` back-channel), spec §5.1.3 (scheduled refresh through `active_principals`),
§5.1.4 (revocation by `sid`, `sub`, CRL/OCSP), §5.6 session lifetime (ceiling warning,
grace window, `max_session_age` minimum across roles), the staleness ceiling end to end.

**Carried from plan 3:** a store two processes can reach, before the broker leaves `port49d`
(design §19 step 2); the scheduled refresh and the `staleness_ceiling` default, together; PR #7's
third follow-up — a join racing another principal's replace under one username can lose its sid or
certificate index entry (revocation by principal still reaches it); the certificate-to-directory
mapping replacing the slice's declared `username:`; go-dark on a store outage, if plan 6 has not
built it (plan 4's "Hands to plan 6"). Also owed by plan 3's reviews:

- An **atomic put-if-absent idempotency reservation**. Two concurrent requests under one key
  with different bodies can both pass the pre-check today, and the minter's read, mint and
  `PutIdempotency` are three steps, not one.
- **Per-source limits or admission on the broker listener.** One client reconnecting every 30s
  can keep all of `broker.MaxConns` (256) slots full.
- A **counter for broker TLS handshake failures**.
- A **per-principal cap on held broker connections**, beside the per-source one. Any
  certificate the anchor signs can open all 256 slots and hold them for `max_session_age`,
  locking every other operator out of `port49 login`.
- **A revocation must reach the held connection.** Plan 4b makes a policy edit live: removing
  a subject's grant revokes that principal's contexts with no restart and no logout. Revocation
  by principal or by certificate (spec §5.1.4) is this plan's, and it must also
  refuse mints on, or close, that principal's held broker connections; otherwise a token
  minted after the revocation lifts it (decision 15).

**Carried from plan 6a:** go-dark on a store outage, the warm context cache, plan 4b's
remote-store items, and the `crypt_open_failures_total{record="token"}` alarm (Plan 6a — As
built, "Carried").

**Split into 7a–7h (2026-10-01).** Plan 7 is the largest step group, and one platform-critical
choice in it is not made by the design: which shared store backs the broker once it leaves
`port49d` (design §12 lists Redis, Valkey, DynamoDB, etcd and an RDBMS as pluggable and picks none).
That is **Decision D1** below, for Ryan. The split is ordered by dependency first and security value
second, so that the three sub-plans that do not touch the store's backend come first and D1 has
until 7c merges to be made. Every sub-plan is separately mergeable and leaves `make test` green.

- **Plan 7a — `2026-10-01-07a-revocation-and-broker-limits.md`. Written 2026-10-01.** The carried
  security debts that need no backend: an **atomic idempotency reservation** (put-if-absent per
  device, the whole batch reserved before its first mint, a concurrent duplicate answered `409
  idempotency_in_progress`); a **broker listener that does its own TLS handshakes**, so every
  failure is counted by reason (`port49_broker_tls_handshake_failures_total{reason}`), with a
  **per-source cap on connections not yet authenticated** (reset at accept) and a **per-principal
  cap on held connections** (the oldest closed for the newest, so a laptop's dead connections never
  lock its owner out); and **revocation that reaches everything**: a standing mark by principal or
  by certificate (issuer, serial) checked at every mint, before and after its token writes, that
  closes the held connections it names (and, from the listener's in-memory copy, refuses them as
  they bind), deletes the unspent tokens through a new token index (plan 2's "largest remaining
  hole in revocation"), marks the live contexts twice and deletes the receipts, names the contexts
  it cannot reach, and is one `revoke` record (a new §5.7 event). An operator revokes
  and lifts with `port49 revoke` over the admin socket; the marks are kept in
  `broker.revocations_file` (its directory fenced, created at the first start beside a marker, a
  missing or unreadable file refusing every later start), so a restart forgets none. The store interface gains the reservation,
  the token index and the marks, each with a `storetest` property every backend must pass; no
  backend is built. Lab: revocation end to end on vEOS, the N9Kv, the C8000V and vJunos-router.
- **Plan 7b — session lifetime and certificate status.** `/v1/refresh` on the certificate path
  (the signed-nonce challenge over the held connection, `auth_time` the broker's verification time,
  decision 17); `max_session_age` per role, composed as the minimum (lifting plan 4's load
  refusal); the ceiling warning in `server_msg` and the grace window's sweep; CRL (and OCSP)
  checking of client certificates at mint, feeding 7a's certificate marks (spec §5.1.4); the
  refresh's per-context records naming unreached contexts as 7a's revoke record does (decision 21).
  Lab: L2's open truncation length and IOS-XE, which the warning rests on.
- **Plan 7c — `2026-10-02-07c-api-and-authorization.md`. Written 2026-10-02.** `api:` rights
  enforced (`revoke_others`, `explain_others`; `sync`, `keys_show` and `replay` ruled reserved, no
  broker endpoint guarding them; no right widens a mint or `RefreshSession`; self-only by default,
  design §17); `POST /v1/tokens/revoke`: `mine` (the caller's own tokens deleted by ID and its own
  contexts marked by compare-and-set, no standing mark), another principal under `revoke_others`
  through 7a's `Revoke` (origin `api <caller>`), or a (device, username); `GET /v1/identity`;
  `POST /v1/explain` (an unknown device answered as one with no grant); `/healthz` and `/readyz` on
  the broker, readiness never the store's; plan 4b's candidate reload guard ruled on (a policy
  reload newly quarantining or refusing more than `inventory.max_removed_percent` of the devices in
  service is refused); `port49d init-revocations`, a start never creating the file (decision 32
  amended); `port49 identity`, `port49 explain` and `port49 revoke --mine`/`--via-agent` over the
  agent; a new `store.DeleteToken` with a `storetest` property. Lab: the HTTP revocation's shapes on
  the four images 7a measured. **As built:** "Plan 7c — As built", below.
- **Plan 7d — `2026-10-02-07d-shared-store.md`. Written 2026-10-02.** The shared store (D1 = etcd). The backend D1 chooses, implementing every store method
  with its atomicity and passing every `storetest` property, 7a's included; store-native mutual-TLS
  authentication per component (design §17); a hard timeout and a circuit breaker on every store
  call, and pool separation between token and context operations (design §12); plan 4b's
  remote-store items (a deadline on each refresh and per-packet store call; the settle pass's
  redeem-to-write assumption; unindexed contexts invisible to the refresh); PR #7's third follow-up,
  a replace, its unindex and its index made one atomic operation; the
  `crypt_open_failures_total{record="token"}` alarm. **As built:** "Plan 7d — As built", below.
- **Plan 7e — `2026-10-03-07e-broker-process.md`. Written 2026-10-03.** The broker as its own process. `cmd/port49-broker`, and `port49d` serving
  TACACS+ with no broker inside; `b.superseded` and `b.blobsSeen` moved into the store and bounded
  (4b final review m10); decision-log emits under the policy hold bounded (4b Task 4); one refresh
  runner across broker replicas; `broker.revocations_file` retired if D1's backend persists. Lab:
  the slice on the split deployment.
- **Plan 7f — go-dark and the warm context cache.** The owner's ruling of 2026-09-24: `port49d`
  health-checks the store and closes its TACACS+ listener after N failed checks, reopening after M;
  the per-replica read-through cache of contexts and blobs, TTL in seconds, served past its TTL
  through an outage and alarmed (design §12). Lab: a new register row, what each image does when
  port49d closes its listener mid-session, beside port49d stopped.
- **Plan 7g — the directory.** LDAP and Active Directory group resolution with design §10's server
  pool (priority, sticky selection, circuit breaker, failback hysteresis, site awareness), nested
  groups by configuration, SASL EXTERNAL, GSSAPI or simple bind; the certificate-to-directory mapping
  replacing the slice's declared `username:` (strong, or issuer-pinned weak, ambiguity failing
  closed); group subjects minting; pre-warm and grace; the scheduled refresh through
  `active_principals` stamping `refreshed_at`, and the `staleness_ceiling` default, in one change.
  Lab: a new register row for nested-group resolution on OpenLDAP and Samba AD.
- **Plan 7h — OIDC and trust domains.** The verifier lists `identity.humans` and
  `identity.machines` (decision 16); OIDC ID and access tokens validated against the provider's
  JWKS; `/v1/config`'s issuer and client id; `prompt=login` refresh with `auth_time` from the
  assertion; `POST /v1/logout` back-channel by `sid` or `sub`, as 7a's marks by `sid`; `amr` and `acr`
  recorded. The agent's OIDC public client stays plan 9's. Lab: a new register row for the logout
  token a provider sends.

Order: 7a–7c do not depend on D1, and are the ones a stolen laptop or an abusive caller needs
first. 7d–7f need D1's backend. 7g and 7h integrate external identity systems, are the largest,
and each brings its own lab row. If D1 is still open when 7c merges, 7g may move ahead of 7d; it
needs no store change.

**Decision D1, for Ryan: which shared store does 7d build?** The design requires atomic
match-and-delete with TTL, an atomic remove-and-write, compare-and-set on contexts, and
reachability from every daemon (§12), and leaves the product open. The options, against what
port49 needs most (a redeemed token never comes back, and a revocation mark is never lost):

1. **etcd (recommended).** Raft: every acknowledged write survives a leader failover, so a
   redemption, a reservation and a revocation mark never roll back. Transactions give every
   compare-and-set the store needs, leases give TTL, and client authentication is mutual TLS with
   per-component roles (design §17's internal interfaces). Throughput is thousands of writes a
   second, above the §5 target of ~170 authentications a second. Costs: a lease per expiry
   bucket to keep lease churn down, an 8 GiB soft size limit (port49's records are small), and
   every write crosses to the leader.
2. **Valkey or Redis.** The fastest, and Lua scripts make each operation atomic. Replication is
   asynchronous: a failover can lose an acknowledged write, so a redeemed token can be redeemed
   again and a revocation mark can vanish. `WAIT` narrows that and does not close it. Acceptable
   only with the replay window documented, which is what design §13 already says of regional
   replication.
3. **PostgreSQL.** Serializable transactions and row locks; widely operated. TTL becomes a sweeper's
   job, and connection counts need a pooler at fleet scale.
4. **DynamoDB.** Conditional writes and transactions fit well, but it is one cloud's, and most network
   teams run port49 on premises.

Recommendation: etcd first, the interface kept pluggable, and a Valkey backend later only with its
replay window stated. 7a builds nothing that depends on this: its store methods are added to the
interface and the memory store, with `storetest` properties the chosen backend must pass.

### Plan 7a — As built

Executed 2026-10-01 on `feature/revocation-and-broker-limits`, thirteen tasks and one lab-driven
fix (fixA), each reviewed; merged 2026-10-01 (PR #20, merge bf96a46) after the fix wave's re-review
said MERGE. Two non-blocking follow-ups from that re-review: R1, `storetest` should say when it skips
the holderless-record case for a store that is not a `storetest.Planter` (7d's backend test must
implement Planter); R2, `Agent.Mint` after Done returns a bare `ErrSessionOver` rather than the
recorded reason; the ledger is
`.superpowers/sdd/2026-10-01-07a-revocation-and-broker-limits/progress.md`, with each task's brief,
report and review beside it. A pre-flight review revised the plan first (one critical, seven
important, twenty-two minor fixed at 1ac1665; M8 rebutted: a retransmission with no live context
answers `token_spent` and never replays a receipt, spec §5.6). What differs from the plan's text,
task by task:

- **Task 1 (docs; d0aedba, 9cb67bc).** The report events are renumbered around `revoke`; a
  retransmission whose receipt a revocation deleted is answered `token_not_found` (§5.1.4, §5.6, the
  `token_not_found` row); `revocation_lifted` is worded by decision 15 (a certificate's mark does not
  keep a context revoked); decision 32 names the fallback for an unwritable mark; decision 21 gives
  the `revoke` record's `unreached` to 7a and a refresh's to 7b.
- **Task 2 (idempotency reservation; 9d6e56f, 2038c3c, 2e6a662).** A reservation or completion with
  no holder is refused, and a completion expecting the empty holder conflicts, so a holderless record
  is never taken over; a pending record reads back through the sealing layer without opening; the
  lease's expiry is a `storetest` property of its own (`IdempotencyLeaseExpires`), since
  `IdempotencyReservesOnce` runs on a fixed clock.
- **Task 3 (the batch reserves; aabd43c, 4a8d154).** Controller ruling: each device's hold is renewed
  by a compare-and-set on its holder before its mint (one minute per device, not per batch), so a
  batch longer than the lease never lets a retry mint the same device; a lapsed or taken hold
  answers the whole request `409 idempotency_in_progress`, and the same CAS takes over an abandoned
  replay. A refused reservation is given back on its own context; the agent honours `Retry-After`
  up to 5 s. A completed record from before 7a (no holder) that is abandoned is answered 409 until
  it expires (bounded, fails safe).
- **Task 4 (token index; 8d4685a, 0576543).** A blank certificate key (no issuer, no serial, no
  `|`) is never indexed; a mint with no principal is refused (`ErrNoPrincipal`); the index outlives
  its token by a minute so a skewed clock cannot drop it first. Controller ruling: fix round 1
  (tests and a one-line guard, each mutation-checked by the implementer) was accepted on the
  report without a reviewer re-review; cost if wrong, a gap the final review would catch.
- **Task 5 (marks; 333548d, 2120e54).** `PutRevocation` refuses a malformed mark (an unknown kind,
  an empty key, a certificate key missing its issuer or serial), a deviation accepted in review and
  a `storetest` property; a well-formed mark that nothing names is still written, with Ruling 4's
  warning. A list's order within a kind is pinned. Controller ruling: the minors were accepted on
  the implementer's report (tests only, and one shared blank-key helper); cost if wrong, a test
  that measures less than it says.
- **Task 6 (the listener; b6a9b33, df8c834, 3381730).** The accept loop starts at the first `Accept`,
  so marks fed before `Serve` are in place before any connection binds; a mark that lands
  mid-handshake is refused at bind; the per-source isolation is a committed test (a second loopback
  address).
- **Task 7 (mint checks; 83f5e5c, 2efadc0, 0b53496).** The after-write check runs on both exits
  that follow writes (the 200 and a mid-batch `409`); a mint refused after its writes records `deny
  credential_revoked` for each device it minted, with `index_error` when the delete failed (spec §5.7,
  2efadc0), and `capability` does not count those tokens; a replay is refused to a revoked caller;
  when the second mark read fails, each written key is superseded (amending ruling 6).
- **Task 8 (`Revoke`, `Lift`; 2dd8723, a9727f0, 21185e9).** `normal()` refuses `user:` alone and a
  serial empty after `0x`/`-`; an all-digit serial is flagged (it may be openssl's decimal); an
  issuer with a control or format character is refused. The listener is told and held connections
  closed before the file is saved; Revoke and Lift are serialised by a one-slot semaphore that gives
  up at the caller's deadline, so a hung store cannot block every later revocation. A key is counted
  only if it held tokens; a certificate revocation says the principal's other certificates lost
  their tokens on those devices too. A context on a device the policy in force no longer lists is
  counted unreached.
- **Task 9 (port49d; 8cac758, d545bfb, 1da0f2d).** A save runs under a 5 s deadline in a one-slot
  writer that catches the file up after a hung write and lowers `port49_revocations_file_failed` only
  when every mark in force is written; a file laid down by hand gets its `.created` marker at the
  next start (else a later loss read as a first install). Marks are restored into, and saved from,
  `brk.Store`. With a listener in front, a principal marked across a restart was closed at bind (the
  test asserted that until fixA, below).
- **Task 10 (admin socket; 7209348, d579122, 19e1cff).** Controller ruling: a caller's hang-up
  cancels only the wait for the revocation slot; once a revocation or lift holds it, every step runs
  detached under `Broker.RevokeTimeout` (= `admin.OpTimeout`, 60 s), so a dropped SSH session never
  leaves a revocation half done. Unknown request keys are refused; a failed list names what failed.
  Controller ruling: the review's five minors were accepted on the implementer's report (#4
  mutation-checked); cost if wrong, a fix that does less than its report says.
- **Task 11 (`port49 revoke`; 021d408, eaa735c, 616bb5c).** Controller ruling: the client waits
  `RevokeWait + 5s` (140 s) for a revoke or lift, longer than the plan's 70 s, so the operator sees
  the report of a revocation still running. A failure after the request was sent prints "port49d did
  not answer … the revocation may be in force — check `port49 revoke --list`". `--cert` takes one
  certificate, PEM or DER, refuses a file holding a private key or more than one certificate, caps
  the read at 1 MiB, and prints the subject and issuer quoted. The client never half-closes.
- **Task 12 (lab; 2957904, 9e257ae, a85c58e, 5ccd2ef, ebb10d4, e4326e6, 64a9996).** The first runs at
  2957904 found that on vEOS, the N9Kv and the C8000V **the agent survived the revocation**: the
  listener closed the reconnect at bind without answering, and the agent read the hang-up as one that
  does not end a session. That contradicted spec §5.1.4 and the pre-flight's I4 (those first notes
  were overwritten before commit; the finding is recorded here and in bfd482a's message). Ruling (a)
  fixed it (fixA, below), and all four images were rerun. On IOS-XE the refusal prints only the
  `server_msg`; the test was taught that (9e257ae). The review's tightenings (each report names one
  held connection closed, and on Junos the session not reached; the `show version` line quoted; a
  revoked operator's `port49 login` refused) were measured in a full rerun at e4326e6 (64a9996).
  Controller ruling: the rerun was not re-reviewed, since the harness was reviewed and approved and
  the rerun only produced the evidence its tightened checks gate; cost if wrong, a note that says
  more than its run showed, which the final review re-read.
- **fixA (bfd482a, fe556d3, 504cb53, 1b46f56; most of its broker code in 9e257ae).** The listener
  completes the handshake of a marked certificate or principal, reads one bounded request (4 KiB of
  headers, the body drained, 5 s), answers `401 credential_revoked` with the mint path's body and the
  mark's own time, records it as `mint deny credential_revoked` (principal and fingerprint), and
  closes; it never reaches a handler or the store, and is never held or charged to the principal's
  cap. The agent's `Connect` reads the reason, so `port49 login` prints "… was revoked at …". Spec
  §5.1.4 and design §17 say so (1b46f56). **9e257ae is mislabelled:** "test(lab): read IOS-XE's FAIL
  text…" also carries most of fixA's broker code, swept in by a `git commit -am` in the shared
  worktree; history is left as is by ruling, and lab commits since name their paths. Found and fixed
  in passing: a cold-start clock race in port49d, where a clock step between two copies' readings
  could take the older bundle (504cb53; one clock reading per pass).
- **Task 13 (docs; this section).** Spec §5.6's retransmission sentence names the deleted-receipt
  exception; decision 32 amended (below); `tests/lab/README.md`'s `chmod go-w` covers
  `tests/lab/logs`, the lab's `revocations_file` directory, which the fence refuses group-writable;
  the plan's operator notes no longer say a revoked operator's login succeeds.
- **Final review and fix wave.** The whole-branch review of 1ac1665..6279776 ran: FIX FIRST, 0
  Critical, 1 Important, 9 Minor (`final-review.md` in the ledger's directory). It found no path by
  which a revoked principal or certificate keeps access beyond the residuals the spec names. The
  fix wave:
  - **I1 (8776e1b).** `port49 revoke --cert` sent the serial as bare hex, so a certificate whose hex
    serial is all digits (sequential CAs issue 10, 11, …) was flagged as a decimal copied by hand,
    and the report told the operator to lift a correct revocation. `--cert` now sends `0x<hex>`
    (a minus sign kept in front), and the hint for a hand-typed all-digit serial says to revoke
    again with `--cert FILE` first and only then lift, so no gap is left without a mark.
  - **fixA N1 (abee45d).** `refuse` says (or holds back) the line before it counts the failure.
  - **Task 3 M7 (8f19fa3).** A test that `Mint` waits by the broker's `Retry-After`.
  - **Task 7 N1 and N2 (c0b914c).** A replay the after-write check refuses writes no device deny:
    `token.Result.Replayed` (never stored) marks it, and `unmint` deletes and supersedes its key
    without one; §5.7 says so. A test pins `capability`'s re-permit after a double deny.
  - **M9 (e75c462, cbed56a, df086a7).** A revoked session's error no longer says to run `port49
    login` ("the session is over: this principal was revoked at …; … (port49 revoke --lift)",
    through the agent socket too; the lab notes, run at e4326e6, show the old text, and the lab
    test's match, "the session is over" and " was revoked at ", holds for both). `PutIdempotency` and `GetIdempotency` leave `store.Store`:
    tests read a record with `storetest.Peek` and write one by reserving and completing it, and
    the holderless-record case runs on a store that is a `storetest.Planter` (the memory store's
    test is one). The `Broker` comment names every optional field.
  - **M5–M8 and the rest of M9 (docs).** "Task 10 N1" is struck from this entry (a controller
    error; there was no such item); Ruling 4 is restated below; the omitted controller rulings are
    added above; §5.7 says a `revoke` record is written per revocation or lift that takes force
    and a failed or refused one writes none (rewording, as the review recommends); the plan's
    Ruling 10, its "What the operator sees" and its §5.1.4 text say a revoked login is refused,
    marked revised.

  Accepted, not to be fixed: Task 8/9 M2 (a hung disk keeps minted tokens redeemable up to 5 s
  longer, behind the save deadline). Left for Ryan: Task 9 M1 and decision 15's cost on a
  certificate's mark (below).

**Rulings, as made** (spec §13, decision 32; the plan's ten rulings): all stand, with these
amendments, each the option that denies more. Ruling 5 and ruling 10: a marked connection is
answered `credential_revoked` as it binds, recorded, and closed, not closed unanswered; a revoked
operator's `port49 login` is refused at its first request, not admitted until its first mint (lab,
fixA; decision 32 amended in this task, citing `tests/lab/results/revoke-*.md`). Ruling 6: when the
second mark read fails, the written keys are superseded (Task 7). Ruling 8: a hand-laid file is
given its marker; a save runs under a deadline and catches up (Task 9). Ruling 9: a hang-up cancels
only the wait for the slot (Task 10). Ruling 4 stands as written: a well-formed mark that no
subject names is still written, with a warning to check the spelling; the store refuses only a
malformed one (an unknown kind, an empty key, a certificate key missing its issuer or serial;
Task 5).

**Lab (Task 12).** No register row: the device behaviours rest on the slice, L4 and L17 notes.
Revocation end to end at e4326e6, all four PASS (`tests/lab/results/revoke-<platform>.md`, captures
`tests/lab/evidence/revoke-<platform>.pcap`): **vEOS 4.31.2F** (`revoke-arista_eos.md`): the next
command refused "% Authorization denied … this session was revoked"; **N9Kv 10.4(2)F**
(`revoke-cisco_nxos.md`): refused "Error: AAA authorization failed"; **C8000V 17.13.01a**
(`revoke-cisco_iosxe.md`): refused, the device printing only the `server_msg`; **vJunos-router
23.4R2-S2.1** (`revoke-juniper_vjunos-router.md`): the session kept what it had at login, and both
reports named `srx1 (slice01)` not reached. On every image an unspent token was refused
`token_not_found`, both agents ended on `401 credential_revoked` with one `mint deny` each, a revoked
`port49 login` was refused "revoked at", and a login after the lift worked.

**Operator notes** (for plan 13's docs, beside the plan's "Operator-facing notes", which are amended
for the revoked login):

- After revoking a stolen certificate, also close that user's sessions on the devices: under
  decision 15 the context is shared per (principal, device), so the owner's next login re-admits a
  still-open device shell; Junos keeps what it had at login anyway, and the report names the
  sessions it did not reach.
- `port49_revocations_file_failed` at 1: run the revoke again; do not restart port49d while it is
  raised, or the restart forgets the unsaved mark.
- A revocations file laid down by hand on a read-only volume refuses the start (port49d cannot write
  its marker).
- `port49 revoke --cert FILE` takes the leaf alone (it refuses a bundle), PEM or DER, and refuses a
  file holding a private key. Prefer it to `--cert-serial`: an all-digit `--cert-serial` is read as
  hex and the report warns that it may be a decimal copied from `openssl x509 -text`; if so, revoke
  again with `--cert FILE`, then lift the first. `--cert` never draws that warning.
- A revoked operator sees "the session is over: this principal was revoked at …" from `port49
  login` and `port49 token`; logging in again does not help until an operator lifts it.
- Exit codes: 0 done, 1 refused or unreachable, 2 usage, 3 in force but incomplete or unsaved. "port49d
  did not answer — the revocation may be in force" means check `port49 revoke --list` before
  retrying.
- A revoked caller's broker connection is answered `credential_revoked`; port49d says it on stderr
  (rate-limited), counts it (`revoked_refused`, `port49_decisions`) and writes a `mint deny` record.

**Decisions for Ryan (answered 2026-10-02, all as recommended):**

- **D1**, the shared store's backend: **etcd** (7d).
- **Task 9 review M1:** an unmounted or empty revocations volume that passes the fence looks like a
  first install, so port49d creates an empty file and starts with no marks, saying so in one stderr
  line. **Ruled: require an explicit one-time init instead of creating the file.** This changes
  decision 32 (and pre-flight C1); carried to plan 7c.
- **Decision 15's cost on a certificate's mark:** the owner's next login re-admits the stolen
  certificate's still-open device shell (operator notes, above). **Accepted**, as decision 15
  already does; the operator notes tell the responder to close the device session.

**Carried, for later plans:**

- **7b:** the refresh records' `unreached` field (decision 21); CRL and OCSP feeding the certificate
  marks.
- **7c:** the HTTP revocation over `Broker.Revoke`; self-revocation's shape (a principal revoking its
  own tokens without a standing mark).
- **7d:** `storetest.IdempotencyReservesOnce` (and `IdempotencyLeaseExpires`), `TokenIndex` and
  `RevocationMarks` for the chosen backend; whether `broker.revocations_file` stays once the store
  persists; the revocation's residual window (a redemption that removed its token before the delete
  and writes its context after the second pass), closed atomically in the store.
- **7e:** the listener and the marks in the separate broker process.

### Plan 7b — As built

Executed 2026-10-01 on `feature/session-lifetime-and-cert-status` (base 0fc2761), thirteen tasks,
each reviewed per task; the ledger is
`.superpowers/sdd/2026-10-01-07b-session-lifetime-and-cert-status/progress.md`, with each task's
brief, report and review beside it. A pre-flight review revised the plan first (two critical,
thirteen important and twenty-two minor fixed at 196aba0, M8 rebutted in part; its re-check's three
important and five minor fixed at 0fc2761). What differs from the plan's text, task by task:

- **Task 1 (docs; 52c5ac0, aa407ee).** §17 had no error-code list, so the new codes got an Errors
  paragraph. The review added an OCSP `revoked` answer as a marking origin (`ocsp <responder>`), the
  `refresh` meanings of `trust_domain_unresolved` and `credential_revoked` in §5.7, and the held
  connection's own ceiling at `session.max_session_age_default` in §5.6 and decision 33.
- **Task 2 (`max_session_age`; 0ba650f, 0b1c50e).** `SessionAge` gains `Never`: a zero
  `SessionAge` takes the default, never `never`, so a value nobody set fails closed. `port49
  explain` says `session.max_session_age_default (no role names a finite one)`.
- **Task 3 (the mint's ceiling; f3faa9e, d8fcd1e).** An idempotent replay keeps its tokens' original
  `session_expires_at`, and a record whose tokens are past their ceiling is minted again, not
  replayed (`token.Result.SessionExpiresAt`). The per-device test was rebuilt so one device's
  ceiling differs from the other's. Controller ruling: the connection keeps the default ceiling, so
  a role longer than the default still re-authenticates the connection at the default (Ruling 1, as
  intended).
- **Task 4 (the store; 7ca5b26, 5c5605c).** A context with no `auth_time` given a finite ceiling by
  policy gets one in the distant past, so it is denied `session_expired` (fail closed; a `storetest`
  property). The grace check uses the authorizer's predicate. A refresh of a `never` context past
  any cutoff is pinned to succeed.
- **Task 5 (the policy refresh; 691008e, 17b780d, 8dae9e3).** A context with no `auth_time` is
  written at every policy refresh, and so fails closed. A quarantined record on a session-only
  platform also carries `unreached`. §5.1.3 and §5.7 say the refresh moves `session_expires` only
  earlier.
- **Task 6 (warning, grace; dadd556, 87836c5).** The blob's TTL is bumped on permits, not only on a
  touch (the Task 3 review's carry), throttled to once per half idle TTL per hash on each replica
  (50 permits, one write). `main.go` sets `Broker.CeilingWarning`, which nothing set before, so
  `ceiling_warning_seconds` was always 0. A delete that loses its compare-and-set counts as
  `conflict`, not as a store error. The warning matches the peer's own platform name, so an
  inventory variant is warned only if listed by its own name.
- **Task 7 (`/v1/refresh`; 4443480, 2334ece, ff2405d).** A refresh's store errors are recorded
  `refresh deny store_unavailable` and counted `store_error`. The marks are read again after the
  extension, and a mark found then is answered `credential_revoked`. A 503 after the connection was
  renewed sends `Retry-After: 10` and says some sessions may have been extended. Controller ruling:
  every consumed nonce is paced, except an expired one, so an agent retrying after a stale nonce is
  not made to wait. A context `refreshContext` revoked for a fault is reported `revoked`, not
  `not_judged`.
- **Task 8 (the agent; 915dbd6, 495d74b).** Controller ruling: `port49 login` refreshes a running
  agent only when its broker and its certificate's fingerprint match the flags. Otherwise it exits 1
  naming the running agent's broker. The agent never moves its own deadline on a 503. A refresh
  whose connection drops or is swapped is tried once on a new connection.
- **Task 9 (`certstatus`; 8a9a11d, 6521fd2, df78f0b).** Retries back off from 30s again after a
  recovery (the plan's code waited a full `refresh_interval`). OCSP signatures are verified by hand,
  so an intermediate's own embedded certificate works. A list with no `NextUpdate` is fresh for
  `refresh_interval` from its `ThisUpdate`, not from its load. An empty chain is Unknown. From the
  review: the whole OCSP CertID is matched (name hash, key hash and serial); SHA-1 signatures on
  CRLs and OCSP are refused (controller ruling; SHA-1 stays allowed as the CertID hash); a caller
  hanging up never poisons the shared OCSP answer; a CRL must name `issuer_file`'s subject byte for
  byte, and says so when the names differ only in encoding; a CRL dated more than 5m ahead is
  refused.
- **Task 10 (refusals and marks; a726c33, 152aab3).** The queued revocation runs after the 401 is
  written, so the client reads its answer before the connection closes. A standing mark makes a
  replayed CRL entry a no-op. A refusal while queued is queued once. The status check and the mark
  check are decided under `bind`'s one lock (a mark wins over a 503). The `allow` line is limited
  per class of failure, so no responder text keys it. The agent's 503 message no longer repeats
  itself.
- **Task 11 (port49d; 56839bb, 4cf1945, 68d86e3).** The `Checker` is built in `cmd/port49d`, not
  on `config.CertificateStatusConfig`: config → certstatus → inventory (`WriteAtomic`) → config is
  an import cycle. The start line prints before the first fetch, and a list coming into force says
  `CRL <name> loaded (next update …)`. `disabled: true` beside any other key is refused. An
  `issuer_file` must be a CA; an OCSP `responder` must be http(s).
- **Task 12 (lab; e13250d, 4bd3100, 6dece62, 1330674, ec50053, 52a81e7, d73ca51, 6791b73).** The
  vSRX prompt is `srx1`, its configured host-name, not its node name; the harness waited for the
  wrong one (ec50053). NX-OS ran at 4bd3100 and vJunos-router's session run at 6dece62, the rest at
  ec50053; the commits between change only how the test reads and writes notes. The step 7 and 8
  refresh quotes in the session notes are rebuilt from the recorded cells and marked so; the
  harness now keeps the raw refresh output (`tests/lab/evidence/session-refresh-<platform>.txt`).
- **Task 13 (38c43fd, caffec6, 0b09d54, and this section).** `cisco_iosxe` alone joins
  `ceilingWarningOn`. L34 closes; L2 stays open, its N9Kv clause corrected (rule 4). §5.6 and
  decision 33 say what L34 found.
- **Final review and fix wave.** The final review (`final-review.md`) found one important issue: a
  login token outlived its session ceiling, so a token minted just before the ceiling opened a Junos
  shell just after it, which ran until logout (decision 21). The fix wave clamps a token's expiry to
  its ceiling at mint and refuses a token past its ceiling at redeem, FAIL `session_expired` (§5.6,
  §5.7, decision 33). From its minors: no test failure message prints a token (`api.MintItem`,
  `token.Result` and `store.Token` print with their tokens withheld); a session refresh no longer
  moves `port49_context_refreshes_total`, and its "still changing" line says to run `port49
  refresh` again; a policy refresh keeps its blob as long as the context; `port49 refresh` says
  `revoked, not extended (see 'port49 revoke --list' and the refresh record)`; a CRL's first load
  is told in bulk, and the queue line reads "N CRL entries are being checked against what is in
  use"; `session.Manager.Refresh` takes a grace cutoff and never resumes a context past it. Handed
  to it and done: `Mint` refuses a finite ceiling with a zero `AuthTime` (Task 3 M-3), the stale
  comment on `TestARefreshIsRateLimited`, and the over-long lines and §17 wording from Task 13's
  re-review. The re-review said MERGE with nothing open; merged 2026-10-02 (PR #21, merge
  513e4bd). The ten raw captures were copied into main's `tests/lab/captures/` after the merge,
  and `make test` (with the labpcap audit) passes on main.

**Rulings, as made** (spec §13, decision 33; the plan's twelve rulings): all stand. Ruling 4's
allow-list holds `cisco_iosxe` alone, from L34. Ruling 6 is amended by Task 7 (an expired nonce is
not paced) and Task 8 (`port49 login` refreshes only its own agent). Ruling 9 is amended by Task 9:
SHA-1 signatures are never trusted, the whole CertID is matched, and a CRL's issuer name must equal
`issuer_file`'s subject byte for byte.

**D-7b-1** (refuse or allow when status cannot be established; certificate status required):
**answered 2026-10-02, as ruled**: `refuse` by default, `allow` available, the key required with
`disabled: true` as the opt-out.

**Lab (Task 12)**, all five images on beehive, 2026-10-01 (`tests/lab/results/L34-*.md`, `L2-*.md`,
`session-*.md`; captures `tests/lab/evidence/session-<platform>.pcap`):

- **IOS-XE 17.13.01a.** L34: the warning shown before the prompt at login and with `show version`'s
  output, inside a 2m warning window; still a permit. L2: a denial shown in full, 64–1000 bytes.
  Session: the ceiling denial, the grace-window refresh that resumed, and "session ended" after it,
  each printed as port49 wrote it.
- **vEOS-lab 4.31.2F (image tagged 4.32.2F).** L34: not shown; still a permit. L2: shown in full,
  64–1000 bytes. Session: as IOS-XE, each message after the device's `% Authorization denied for
  command …:`.
- **NX-OS 10.4(2)F.** L34: not shown; still a permit. L2: never shown. Session: the ceiling and
  the end were enforced, and the device printed only `Error: AAA authorization failed
  AAA_AUTHOR_STATUS_METHOD=16(0x10)`.
- **vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15.** L34: not shown at login; no command reply exists.
  L2: not measurable; a session denial shows nothing and does not stop the login. Session: `show
  version` ran past the ceiling and past the grace window (decision 21); the refresh said "not
  reached: the device keeps its own session", and past the window "past the grace window, not
  resumed".
- Every image: `port49 token` printed its stderr warning inside the window.

**Operator notes** (for the pull request body and plan 13's docs; the plan's "Operator-facing
notes", amended):

- **Breaking: `broker.certificate_status` is required** whenever a broker is configured. To choose
  not to check, write `disabled: true` and nothing else beside it; any other key next to it is
  refused. port49d says it is disabled at every start.
- **What to name.** Your CA's CRLs (`file:` or `url:`), each with `issuer_file:`, the CA
  certificate that signs it, which must be your `client_ca_file` anchor or signed by it. Add an
  OCSP `responder` (or `use_aia: true`) if you have one, with `hash: sha1` for a responder that
  knows no SHA-256 CertID.
  - `issuer_file` must be the CA certificate itself, the one your clients chain to. A re-issued copy
    of it (same key, another certificate) does not match: every certificate under it has an
    unknown status, refused `503` under the default `on_unavailable: refuse`.
  - The CRL's issuer name must be byte for byte your CA certificate's subject. A CRL whose issuer
    is the same name encoded differently (UTF8String for PrintableString) is refused, and the
    message says so; the CA must encode its CRL issuer as its certificate's subject.
  - An intermediate CA: also name the root's CRL (`issuer_file` = your `client_ca_file`), or an
    OCSP responder the root signs for. port49d checks each CA in the chain and says at start when
    nothing covers one.
  - Keep `client_ca_file` and each `issuer_file` root-owned and not group- or other-writable.
    port49d does not check this yet.
- **What is never trusted.** A CRL that does not verify against its `issuer_file`, or one that is
  scoped (partitioned, delta, an unknown critical extension), is never used; watch
  `port49_crl_loads_total{outcome="refused"}`. A CRL or OCSP answer signed with SHA-1 is not
  trusted: the status is unknown ("signed with … SHA1, which port49 does not trust"), with no
  override. SHA-1 is accepted only as the OCSP CertID hash.
- **What is refused and what is marked.** A certificate a CRL or OCSP revokes, or one under a
  revoked issuing CA, is refused at login, mint and refresh. If it still holds something (a
  connection, a device session, an unspent token), port49d revokes it as `port49 revoke --cert`
  would: `port49 revoke --list` shows origin `crl <name>`. A `certificateHold` entry is refused
  while listed and never marked. Lift a CRL-origin mark only after the CA delists the certificate:
  while it is listed, the mark comes back at the next restart or the certificate's next use.
- **`on_unavailable: refuse` (the default; D-7b-1, confirmed).** A CRL past its next update, or an OCSP
  responder down, answers new logins, mints and refreshes for that issuer `503
  certificate_status_unavailable` with `Retry-After: 60`, recorded `<event> deny
  trust_domain_unresolved`. No agent session ends, live device sessions run to their ceiling, and
  break-glass is unaffected. `allow` keeps logins working through an outage and lets a certificate
  revoked during it in until the CRL returns.
- **Loading.** At first start a `url:` source says `CRL <name> (not loaded yet)` until its first
  fetch; that is normal. A list coming into force, or recovering, says `CRL <name> loaded (next
  update …)`. A failed load is retried from 30s with backoff. Verified lists are kept beside
  `revocations_file` (`crl-<name>.der`) and serve across a restart until their next update; back
  them up with it. Alert on `time() - port49_crl_next_update_timestamp_seconds > -3600` and on
  `port49_cert_status_unavailable_total`.
- **New: `max_session_age` per role.** A duration (at least `1m`) or `never`. A session on a device
  ends at the least of its roles' (a role naming none takes `session.max_session_age_default`), and
  `port49 explain` shows it. Shortening a role reaches live sessions at the next policy refresh;
  lengthening it, or `never`, at each operator's next `port49 refresh` or login.
- **New: `port49 refresh`.** It re-authenticates on your held broker connection and extends every
  live device session your policy still grants: no reconnect, and the candidate configuration stays
  intact. It prints one line per device: extended to when, revoked (`revoked, not extended (see
  'port49 revoke --list' and the refresh record)`: the policy, a revocation mark or a broker fault),
  past the grace window (log in again there), not extended this time (run it again), or not reached
  (Junos keeps its own session). One refresh per connection per 10s.
  - `port49 login` with an agent already running for the same broker and certificate says
    `port49: already logged in to <broker>; refreshing` and refreshes. With another broker or
    certificate it exits 1 naming the running agent's broker.
  - With today's PEM key files a refresh proves you hold the key file, not that you are at the
    keyboard; a script running `port49 refresh` in a loop keeps sessions alive indefinitely. Keep
    key files readable only by their owner; a hardware key (plan 9) adds the touch.
- **The warning.** Within `session.ceiling_warning` (default 30m) of the end:
  - On IOS-XE port49 adds `port49: session ends in Nm - run 'port49 refresh'` to every permitted
    reply in that window. The lab (a 2m window) saw IOS-XE print it before the prompt at login and
    with `show version`'s output, so a script that reads command output on IOS-XE should expect
    that line near a session's end.
  - EOS, NX-OS and Junos show nothing (L34). There, `port49 token` is the warning: `port49: your
    session on <device> ends at <time> (in Nm); run 'port49 refresh'` on stderr, `--json` included.
    It does so on every platform.
  - `session.ceiling_warning_platforms` adds a platform at your own risk (unmeasured). A platform
    variant is listed by its own name. `0s` turns the server_msg warning off.
- **Past the end.** Commands are refused `session expired - run 'port49 refresh' (or 'port49
  login') within Nm to resume` for `session.grace_window` (default 10m), and a refresh in that
  window resumes them. After it the session is deleted: `session ended - get a new token ('port49
  token') and log in again`. NX-OS prints only its own `Error: AAA authorization failed`, with no
  hint to refresh. Junos keeps its session past the ceiling and the grace window (decision 21):
  close it on the device.
- **A token ends at the ceiling.** A token expires at `token_ttl` or at the device's session
  ceiling, whichever is first; `port49 token --json`'s `expires_at` shows which. A login with a
  token past its ceiling fails on every platform (`redeem deny session_expired`), Junos included:
  run `port49 refresh`, then `port49 token` again.
- **Clocks.** CRL and OCSP freshness follow port49d's clock, so an NTP step forward can make a fresh
  list stale. `port49 token`'s warning follows the laptop's clock.
- **New metrics.** `port49_broker_connection_events_total{event}` gains `status_unavailable_refused`
  (`revoked_refused` stays for revoked certificates and principals, so a CA outage does not read as
  revocations); `port49_session_refreshes_total{outcome}` (`extended`, `revoked`, `past_grace`,
  `not_judged`, `refused`, `store_error`, `too_soon`); `port49_ceiling_warnings_total`;
  `port49_cert_status_checks_total{source,result}`; `port49_crl_loads_total{crl,outcome}`;
  `port49_crl_next_update_timestamp_seconds{crl}`; `port49_cert_status_unavailable_total`.
- **New records.** `refresh permit grants_matched` per extended session, with `auth_time` and
  `session_expires`; `refresh deny session_expired` past the grace window; `refresh deny
  trust_domain_unresolved` for a signature that did not verify or a status not established; `refresh
  deny credential_revoked`; `refresh deny store_unavailable`; `mint deny session_expired` per device
  already past its ceiling; `mint deny trust_domain_unresolved`; `redeem deny session_expired`, with
  `session.session_expires`, for a login with a token past its ceiling; `unreached: true` on refresh
  records for session-only platforms.
- **API.** `POST /v1/refresh/challenge` and `POST /v1/refresh`, on the held connection only, with
  `refresh_challenge_missing` (401) and `refresh_too_soon` (429); `503
  certificate_status_unavailable` with `Retry-After`; `GET /v1/config` gains
  `ceiling_warning_seconds`; mint items gain `session_expires_at`, and a `session_expired` item
  carries a detail.

**Unassigned follow-ups:**

- Fence `client_ca_file` and every `issuer_file` together (owner, no group or other write), as
  `policy_file` is fenced. Fencing `issuer_file` alone buys nothing: a swapped file fails closed.
- `Checker` lives in `cmd/port49d` because of the import cycle above; moving `inventory.WriteAtomic`
  to a leaf package would let it return to `config`.

**After the merge:** copy the ten raw captures from the feature worktree's `tests/lab/captures/`
(archived at `/mnt/images/port49-captures-7b-t12-2026-10-01/`) into main's, or main's labpcap
audit fails.

**Carried, for later plans:**

- **7c:** the HTTP revocation, and `api:` rights over `RefreshSession`'s self-only rule. Also from 7a (Ryan, 2026-10-02): an empty or missing revocations volume requires an explicit one-time init (`port49d init-revocations` or similar) instead of being created at start (amends decision 32).
- **7g:** the `staleness_ceiling` default and the scheduled refresh.
- **7h:** the OIDC refresh: `prompt=login`, `auth_time` from the assertion, `sid` re-indexing.
  `session.Manager.Refresh` now takes a grace cutoff (the refresh time less
  `session.grace_window`) and refuses a zero one.
- **9:** the hardware key's touch on refresh, and a PKCS#1 v1.5 mapping for tokens without PSS.
- **12:** the Junos `idle-timeout` classes rendered from a per-role ceiling rather than the default,
  and `port49 policy diff` reporting a changed ceiling (pre-flight M11).

### Plan 7c — As built

Executed 2026-10-02 on `feature/api-and-authorization` (base 7c0ce7c), fourteen tasks, each
reviewed per task; the ledger is
`.superpowers/sdd/2026-10-02-07c-api-and-authorization/progress.md`, with each task's brief,
report and review beside it. A pre-flight review revised the plan first
(nine important and twenty minor, fixed at 7c0ce7c); one further ruling came out of the conflict
scan (M14's side effect, below). What differs from the plan's text, task by task:

- **Task 1 (docs; a65aedd, 28c3832, 6c89938).** The conflict scan's ruling went into decision 34
  and §5.1.3 both: the net exemption counts only devices the inventory held before the reload, so
  padding the inventory cannot pass the guard. From the review: §12's admin-socket `port49 revoke`
  states its exit codes (0 done; 1 not in force, or no answer; 3 in force but unfinished or
  unsaved; 2 usage), and the HTTP forms spell out the same four; §10's policy-reload bound counts
  new refusals and new quarantines together; §5.1.4 says a retransmission after a
  self-revocation is answered `token_not_found` (the plan says `token_spent` at its lines 177,
  681 and 3264; the code, the spec and the tests say `token_not_found`, ruling I3-carry); §14 says
  nine decision events, and its replay agreement checks only a principal or certificate `revoke`.
- **Task 2 (init-revocations; bc0e90f, e413948, 65c817a, 6bd75ba, ca4c215, 088fc57).** Three
  drifts from the plan's text, each in spec §12 and decision 32 (088fc57):
  - **File before marker.** Init writes the empty file, then its marker (the plan says the marker
    first). A crash between the two leaves a file with no marker, which the next start loads and
    marks; the reverse order would leave a false "revocations were lost".
  - **A relative path is refused**, exit 1 (the plan says it warns): it would resolve against the
    shell's directory, not port49d's. A start still takes a relative path, as before.
  - **A raced init says so**: a file that appears while init runs is refused, exit 1, "another
    init-revocations is running or has just run; nothing written".
  - A directory root owns, asked by anyone else, gets "if a volume should be mounted there, it is
    not; mount it", never a `sudo -u root` line (e413948). The lab harness writes
    `{"revocations": []}` only when no file is there, so it never truncates one a running port49d
    holds (ca4c215).
- **Task 3 (vocabulary; 5010a3f, ed06f3d).** As planned. `HasRight`'s test pins a misspelt right,
  an empty one, an unknown one and a group subject, each refused.
- **Task 4 (`/v1/identity`; e9a9c73, d524ecd).** `refuseRevoked`, left with no caller, was folded
  into `refuseRevokedAs`. A test pins that identity lists only unexpired grants.
- **Task 5 (`/healthz`, `/readyz`; 7252a2c, 3a43135).** The test mints on a store that fails and
  sees `503 store_unavailable` while `/readyz` stays `200 serving`, and runs both probes over a nil
  store. `TestRunAnswersDrainingBeforeTheBrokerCloses` pins `503 draining` on the broker listener
  before shutdown. The probes are HTTPS on `broker.listen` with no client certificate, separate
  from the TACACS+ `/readyz` on the metrics listener (review note, operator notes below).
- **Task 6 (`store.DeleteToken`; dcfc675, 477217a, d3daca6, 7c88ca6).** Controller ruling: it keeps
  7a's token index entries. The index maps a principal to a `(device, username)` key, not to a
  token, so pruning could hide a second live token under the same key from a revocation; a stale
  entry costs one `DeleteTokens` on that key. A new property, `DeleteTokenRacesRedeem`, races it
  against a redeem and a put, 200 rounds, with no resurrection.
- **Task 7 (`RevokeOwn`, `RevokeKey`; 72972e6, 44fb23e).** `RevokeKey` deletes the receipts of every
  owner it read across its two passes, not only the last (kept by the review). A key where nothing
  was found says so. `RevokeOwn`'s comment says `token_not_found`, as above.
- **Task 8 (`POST /v1/tokens/revoke`; 4409fc2, 9f22972, 6753049).** Controller ruling (from Task 7
  M4): one self or key revocation in flight per caller principal (`holdOwnRevoke`); a second is
  `503 revocation_busy` at once, with `Retry-After: 5`, nothing revoked and no record (spec
  §5.1.4, design §17, 9f22972). Trailing bytes after the body are 400. A mark that cannot be
  written is `503 store_unavailable` with `Retry-After: 10`, and its text says what to do with no
  `admin_socket` (remove the grants from `broker.policy_file`) or with one (the socket's path).
- **Task 9 (`POST /v1/explain`; c810410, 384aabe, d701522).** The review found a timing oracle: the
  hidden values were worked out before the no-grant check, 1.14 ms against 28 ns, so an unknown
  device could be told from a known one with no grant. They are now worked out after it and
  memoized per policy; the remaining gap (380 ns against 27 ns) cannot be told apart over HTTP.
  Beyond the brief: `RenderWithoutAttributes`, so a session explain never returns attributes; a
  revoked target is answered from the mark, without reading the policy; a policy fault writes the
  `explain` record with `mint_error: broker_error`; a body over 16 KiB is 400.
- **Task 10 (the reload guard; 604eade, 83ea48e, d0b0cbb, 82099cd, 6b91cd8).** Four rulings from
  two review rounds, each in §5.1.3, §10 and decision 34:
  - **A combined reload is judged on its policy's effect** (I1): against the policy in force over
    the new inventory, so an inventory change's own quarantines stay decision 20's; a policy in
    force that does not parse over the new inventory counts every device (fail closed).
  - **The numerator counts only devices in service under the policy in force** (I2).
  - **A release never offsets a refusal** (M1): newly refused devices over the bound are refused
    whatever the reload releases, since a refusal deletes tokens a revert does not bring back.
  - **That refusal bound is plan 6a's**, over the devices admitted, quarantined ones included
    (R1), so a policy that refuses quarantined devices is still bounded.
  - Shares print rounded up, so 1 of 3 prints 34% (M2, R2, `CheckFrom` too). The restart warning
    is added only to a bound's refusal, not to the admit-none one, which a start also refuses.
  - The L31 harness edit (`max_removed_percent: 100` in its quarantined phase) was only checked by
    `go vet -tags lab`, not run in the lab; the next L31 run confirms it.
- **Task 11 (the agent; b7560c6, d6f9070).** Every coded 503 (`revocation_busy`,
  `store_unavailable`, `certificate_status_unavailable`) becomes an `agent.APIError` carrying its
  code, detail and `RetryAfter`, and reaches the CLI as `…; retry in Ns`; the plan's
  `unavailable` path would have turned `revocation_busy` into a 502. A broker 410 relayed through
  the socket is clamped to 502, since 410 is the agent's own session end. A broker 404 with no API
  code is `not_supported`, naming the broker as older. The socket refuses trailing data. Mint and
  refresh are unchanged.
- **Task 12 (the CLI; 7c6368d, 5c2025e).** Controller rulings: a terminal is detected by the
  `TCGETS` ioctl on Linux (`golang.org/x/sys` becomes a direct dependency), not by
  `ModeCharDevice`, under which `/dev/null` counts as a terminal and a cron job would be asked
  `[y/N]`, read EOF and revoke nothing; other systems keep the mode check. The question names the
  principal; the subject is printed on the `target:` line after the broker answers, since it is
  not known before. `--yes` outside `--via-agent --principal`, and `--socket` in an agent form, are
  usage errors (exit 2).
- **Task 13 (lab; 0529b92, 1af6f72, 9bfb710, 4a6a769).** All four images pass, run at 9bfb710.
  From the review: a row for the re-login session's next command after the key revocation, the
  Junos rows worded as measured, and the reach of the key and principal reports checked both ways.
- **Task 14 (this section).** No lab note contradicts §5.1.4's "Over HTTP, as built" or decision 34,
  so no doc is corrected under lab rule 4. Spec §10's reload-bound paragraphs, over-wide since
  d0b0cbb, are rewrapped.
- **Final review (b5e0317, 8ea6131, 5590f4b, and the docs after them).** I1: the agent waited 30 s
  on a revocation and resent it on any transport failure, so a slow store turned a mark that
  stood into `revocation_busy`, "nothing was revoked". It now waits past the broker's worst case
  (`api.RevokeSlotWait` + `admin.OpTimeout` + `admin.PersistTimeout` + 10 s), never resends a
  revocation once its writing began, and says an unanswered one may be in force. M1: `--mine`
  with a key reads only the caller's own indexes, so its time says nothing of another's session.
  M2: naming your own principal says first that no mark was made. M4: `/readyz`'s `503
  starting` is not seen in practice (below). M5: design §17 lists explain's `500 broker_error`.
  M3 is carried: spec §5.7 says a mark that could not be written writes no `revoke` record, and a
  record for it is a spec change, not a fix.

**Rulings, as made** (spec §13, decision 34; the plan's ten rulings): Rulings 1, 5 and 7 stand as
written. Ruling 2 stands, its retransmission answered `token_not_found` (I3-carry). Ruling 3 gains
the per-caller bound on self and key revocations (Task 8). Ruling 4 stands, with one exception
made in Task 8: neither busy answer writes a record. Ruling 6 gains: session attributes are never
returned, and a no-grant answer works out nothing a granted one does (Task 9). Ruling 8 is
amended by the conflict scan (padding never offsets) and by Task 10's I1, I2, M1 and R1 above.
Ruling 9 is amended by Task 2: the file before the marker, a relative path refused, a raced init
refused. Ruling 10 stands: no register row opens or closes.

**Lab (Task 13)**, four images on beehive, 2026-10-02, run at 9bfb710
(`tests/lab/results/api-revoke-*.md`; captures `tests/lab/evidence/api-revoke-<platform>.pcap`,
the redacted copies passing the labpcap audit on the branch). On every image: carol, with no right,
was refused 403 by principal and by key, and alice's next command ran; `--mine`'s unspent token
was refused `token_not_found`, the agent kept running, and a token minted after it logged in at
once; bob's key revocation ended alice's re-login, and she logged in again at once; bob's
principal revocation was listed `api user:bob@slice.port49.test`, ended alice's agent on `401
credential_revoked`, and a lift on the admin socket let her back; all six `revoke` records (by
`self`, `key`, `principal` × reason) were written.

- **vEOS-lab 4.31.2F (image tagged 4.32.2F)** (`api-revoke-arista_eos.md`). `--mine` and the key
  revocation each refused the next command: `% Authorization denied for command 'show version':
  port49: this session was revoked - log in again`. Pre-flight I1, measured: the session `--mine`
  refused ran `show version` again after alice's re-login (decision 15's join).
- **N9Kv 10.4(2)F** (`api-revoke-cisco_nxos.md`). As vEOS; the device printed only `Error: AAA
  authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)`. I1 re-admission measured.
- **C8000V 17.13.01a** (`api-revoke-cisco_iosxe.md`). As vEOS; the device printed `port49: this
  session was revoked - log in again`. I1 re-admission measured.
- **vJunos-router 23.4R2-S2.1** (`api-revoke-juniper_vjunos-router.md`). Not reached per command,
  as 7a found: every open session ran `show version` throughout, and the `--mine`, key and
  principal reports each named `srx1 (slice01)` not reached. The re-admission is not observable
  there. The capture is 1768 packets against the first run's 568: the device and SSH client
  retried TACACS+ around the refused old-token login (task 13 review M5); no claim rests on the
  count.

**Operator notes** (for the pull request body and plan 13's docs; the plan's "Operator-facing
notes", amended by what was built):

- **Breaking: port49d no longer creates `broker.revocations_file`.**
  - **First install.** Run, once, as the user port49d runs as (the owner of the file's directory):

    ```
    sudo -u port49 port49d init-revocations --config /etc/port49/port49d.yaml
    ```

    The subcommand comes first (`port49d --config X init-revocations` is a usage error, exit 2).
    It reads only `broker.revocations_file` from the config, so no secret needs to be in the
    environment, and it refuses a path that is another file port49d uses. It prints `port49d:
    created broker.revocations_file <path> with no revocations, and its marker <path>; …` and
    exits 0.
  - **What its exit 1 means.**
    - `… belongs to <user>, and this runs as uid N: … run as <user>, e.g. sudo -u <user> port49d
      init-revocations --config <cfg>`: run it as that user. Root is refused too: a root-written
      0600 file is one port49d cannot read. It never chowns.
    - `… belongs to root, and this runs as uid N: if a volume should be mounted there, it is not;
      mount it`: the volume did not mount, or the directory must be given to port49d's user.
    - `broker.revocations_file "<p>" is relative: it must be absolute`: give an absolute path in
      `port49d.yaml`. A start still accepts a relative one, resolved against port49d's working
      directory (`/` under systemd unless `WorkingDirectory=` is set).
    - `… exists and does not load (…); init never replaces it`: restore it, or fix it by hand.
    - `… is missing, and its marker <path> says port49d held revocations here: init never
      re-creates a lost file`: restore it from backup (below).
    - `… appeared while this ran: another init-revocations is running or has just run; nothing
      written`: run it once more to see `already initialized`.
  - **Once, at install, never on a start path.** By hand or as a one-off job. Never in an init
    container or an `ExecStartPre=`: wrapped to tolerate its refusal there, it would re-create the
    file on the next empty volume, the hazard this change removes. Run again, it prints `…is
    already initialized; nothing written` and exits 0, so an idempotent provisioning step needs no
    `|| true`.
  - **What a start does.** A missing file refuses every start: `broker.revocations_file <path>:
    does not exist: if port49d has run here before, the volume holding it is missing or empty:
    mount it or restore the file; only on a first install, run 'port49d init-revocations' once,
    as port49d's user, with the same --config`.
    So an unmounted or empty volume never starts port49d with no revocations.
  - **Upgrading.** An install that already has the file changes nothing; a start writes the marker
    beside it if it has none.
  - **After a loss.** Restore the file from backup. With its marker there, a start says `is
    missing, and its marker says port49d held revocations here`. Writing `{"revocations": []}` by
    hand (0600, port49d's user) is the deliberate way to start empty.
- **Upgrade: agents and brokers older than this release.** An agent lives for `max_session_age`,
  and one started by the old `port49` has no `identity`, `explain` or `revoke` route; the new CLI
  says ``your agent (started before this port49) does not carry this command; run `port49
  login` again``. A new CLI against an old port49d gets `not_supported: the broker at <url> does
  not serve /v1/…: it runs a port49d older than this port49`.
- **New: `port49 identity [--json] [--socket PATH]`.** It prints whom the broker resolves you to:
  principal, subject, groups, unexpired grants by scope, `api:` rights, and until when this
  connection lasts (`connection_ends_at`, from `max_session_age` at authentication); a device's
  own session ceiling may end a session sooner. `--json` prints the broker's answer. Exit 0, or 1
  with `no agent at <socket>; run 'port49 login'` or the broker's refusal. Each call writes an
  `identity` record, so do not put it in a shell prompt.
- **New: `port49 explain --device D [--command "LINE"] [--principal P]`**, with no
  `--policy`/`--inventory`.
  - **What it does.** It asks the broker through your agent, from the policy in force, and prints
    what the offline form prints, redacted, with no session attributes. For a denied command it
    names every role in the policy whose permits would match (what to ask for), never who holds
    one. A device the inventory lacks is answered exactly as one with no grant.
  - **Another principal.** `--principal` naming someone else needs `api: [explain_others]`;
    without it: `refused: explaining another principal needs the api: explain_others right`, exit
    1.
  - **Offline only.** `--subject` and `--show-attributes` are usage errors (exit 2) over the
    broker.
  - **Dashboards.** `explain` records carry hypothetical verdicts: a panel of denials, or of
    `port49_decisions_total{verdict="deny"}`, should filter `event!="explain"`.
- **New: `port49 revoke --mine [--device D --username U]`.**
  - **What it does.** It ends your own live sessions and deletes your unspent tokens (one device
    with `--device` and `--username`), and your receipts everywhere, so a client retransmitting a
    spent token anywhere is refused `token_not_found`.
  - **No lock.** It leaves no mark and closes no agent: `port49 token` and a login work at once
    after it (measured on four images). Use it when a token leaked.
  - **Close a stranger's session first.** Your next login on a device re-admits every session open
    there under your username, a stranger's on your leaked token included (measured on vEOS, the
    N9Kv and the C8000V). If anyone else used your token, close their session on the device, or
    ask an operator to revoke your principal, before you log in there again. The report says so.
  - **Junos sessions** keep what they had at login and are named `not reached` in the report;
    close them on the device.
- **New: `port49 revoke --via-agent --principal P [--yes]`** (needs `api: [revoke_others]`).
  - **What it does.** The admin socket's standing mark, from your laptop, through your agent. On a
    terminal it asks `revoke P everywhere? It is a standing mark: … [y/N]` first; anything but `y`
    or `yes`, EOF included, exits 1 with `nothing was revoked`. `--yes` skips the question, and is
    a usage error with any other form. Off a terminal (cron, `</dev/null`) it does not ask. It then
    prints `target: P (subject S)`, or `(no subject in the policy in force names it)`, so a typo of
    a real colleague's address is seen at once.
  - **Your own principal makes no mark.** Named as P, it is `--mine`: your sessions end, and
    nothing stands against you. The report's first line says `this is your own principal: no mark
    was made; to lock it, ask an operator to use port49d's admin socket (<path>)`. If your own
    certificate leaked, that is the step: an operator runs `port49 revoke --principal P` there.
  - **The record.** `port49 revoke --list` and the `revoke` record name you as `origin: api <you>`.
  - **Lifting** stays the admin socket's, as does `--cert`; the report names the socket. With no
    `admin_socket` configured, the mark is still made, and the report and port49d's start line
    (`port49d: broker: no admin_socket: …`) say lifting it needs port49d stopped, the entry
    removed from `broker.revocations_file`, and a start.
  - **Watch for a burst.** Alert on
    `rate(port49_revocations_total{by="principal",outcome=~"applied|partial"}[5m])` above your
    normal: a compromised `revoke_others` certificate can mark every human. Revoke that
    certificate on the admin socket, then lift the marks it made during the burst, and only those:
    a mark the same principal made before the compromise (a departed employee, a leaked
    principal) is legitimate and must stay. Until a bulk lift exists:
    - Read `port49 revoke --list` first, and find when the burst began, from the alert or the
      `revoke` records (`origin: api user:oncall@example.com`).
    - Set `t` to just before it, in UTC as `--list` prints it. The filter keeps only marks at or
      after `t` (`$4` is the `since` time; RFC 3339 in UTC compares as text).
    - Run it on port49d's host, as port49d's user or root: `--list` and `--lift` are the admin
      socket's.

    ```
    port49 revoke --list | awk -v t=2026-10-02T03:00:00Z \
      '$1 == "principal" && $4 >= t && /\(api user:oncall@example\.com\)$/ {print $2}' |
      while read -r p; do port49 revoke --lift --principal "$p"; done
    ```
- **New: `port49 revoke --via-agent --device D --username U`** (needs `api: [revoke_others]`).
  - **What it does.** It ends whatever holds that key, with no mark, so the owner can log in again;
    revoke the principal to stop that. It prints `target:` with the owner it found. The owner's
    next login there re-admits any session still open on it: close it on the device. A key where
    nothing was found says `nothing was found under D (U)`.
  - **Without the right** it is refused 403, never narrowed to your own sessions there: `refused:
    ending a (device, username) whoever holds it needs the api: revoke_others right, …; for your
    own session there, use --mine --device D --username U`, exit 1.
  - **Not in `--list`.** A self or key revocation leaves no mark; `--list` says so on stderr, and
    the decision log's `revoke` records (`revocation.by` `self` or `key`) name each.
- **What the agent forms exit with, and what each error means.** 0 done; 1 refused, unreachable
  (nothing revoked) or unanswered (it may be in force, below); 3 in force but incomplete, or a
  standing mark not saved; 2 usage. Over the
  agent `--agent-socket` names your agent; `--socket` (port49d's admin socket) is a usage error
  there.
  - `refused: revoking another principal needs the api: revoke_others right`: your subject does
    not declare it. Ask for it, or ask an operator to use the admin socket.
  - ``the broker at <url> did not answer the revocation (…); it may be in force — check `port49
    revoke --list` (on port49d's host) and port49d's log before retrying``: the request was sent
    and no answer came within the broker's worst case (85 s: the 10 s wait for the slot, the 60 s
    run, the 5 s save, a margin), or the connection dropped after it was sent. The agent never
    sends a revocation twice. For `--mine` or a key it says `it may have run — check port49d's
    decision log (event revoke)`, since neither leaves a mark for `--list`. `your agent at
    <socket> did not answer …` is the same for an agent that dropped the request. Look before you
    run it again: a second run behind a slow first one is `revocation_busy`.
  - `the broker is unavailable just now: revocation_busy: …; retry in 5s`: another revocation or
    lift held the slot for 10 s, or your own `--mine` or key revocation is still running. This
    request revoked nothing. If an earlier run of yours went unanswered, it may be the one
    running: check as above before you run it again.
  - `the broker is unavailable just now: store_unavailable: the revocation could not be recorded,
    so nothing was revoked; …; retry in 10s`: the store refused the mark. Retry; the text names
    the admin socket, or, with none configured, says to remove the principal's grants from
    `broker.policy_file` meanwhile.
  - `no agent at <socket>; run 'port49 login'`, and the session-over lines, as for `port49 token`.
- **`api:` rights now mean something.**
  - **What they unlock.** `revoke_others` and `explain_others` act on other people. `sync`,
    `keys_show` and `replay` are reserved and grant nothing yet.
  - **What no right does.** No right lets anyone mint or refresh for another principal.
  - **The gate.** A right gained fails `port49 policy diff` unless a test asserts the subject's
    whole `api:` list, as before. Every subject with `api:` is in the CI report.
- **New: the policy reload guard.**
  - **What is refused.** A policy edit that would take more than `inventory.max_removed_percent`
    (default 10) of the devices in service out of service, by refusing admission or by
    quarantining, is refused. So is one that newly refuses admission to more than that share of the
    devices admitted, whatever it releases elsewhere. `port49_policy_file_refused` goes to 1, and
    the policy in force keeps serving. The line names each device and cause, redacted, with the
    share rounded up (`the new policy takes 5 of 20 devices in service out of it (25%), more than
    inventory.max_removed_percent (10%): …`).
  - **The refused file is still on disk.** The line ends `the refused file is still on disk and is
    NOT what is serving: a restart of port49d would load it with no such bound, so revert or fix
    it now`. A pod rescheduled, a crash or the next deploy loads it and takes those devices out of
    service. Revert or fix it at once.
  - **A combined policy-and-inventory reload** is judged on the policy's effect alone: devices the
    inventory change moves into a quarantined scope are the inventory's, as before. When the guard
    fires on the policy, the line begins `broker.policy_file <path>:`; with both read from files,
    it ends `the refused files are still on disk …`.
  - **Small fleets.** One quarantined device of three is 34%. Raise the bound and send `SIGHUP`
    for a deliberate change, then lower it again: the same bound holds inventory syncs.
  - **A refused edit keeps any grant it withdrew.** `port49 revoke` cuts a principal off whatever
    the file says.
  - **What is never refused** on the combined count: a reload after which at least as many of the
    devices the inventory already held are in service as before, such as an incident fix that
    releases many and quarantines a few. Devices the same reload adds never count toward that.
- **New broker endpoints.**
  - `GET /v1/identity`, `POST /v1/explain` and `POST /v1/tokens/revoke`, each authenticated as
    `/v1/tokens` is.
  - `GET /healthz` (`200 ok`) and `GET /readyz` (`200 serving`; `503 draining: port49d is
    shutting down` from the signal on), with no certificate and no record. Before the broker
    serves there is no answer: the connection is refused until port49d binds `broker.listen`, and
    waits in the moment between the bind and serving. The code's `503 starting` is not seen in
    practice. `/readyz` stays 200 through a store outage, by design (design §12); watch the alarms
    instead.
  - **Probe them over HTTPS with no client certificate** on `broker.listen` (kubelet `scheme:
    HTTPS`). A plain-HTTP or TCP probe fails the TLS handshake and logs a `handshake_*` line and
    counts `port49_broker_tls_handshake_failures_total` every period. They are not the TACACS+
    `/readyz` on the metrics listener.
  - **New API errors:** `403 api_right_missing`; `503 revocation_busy` (`Retry-After: 5`); `400
    bad_request` for a `sid` (until plan 7h), trailing bytes, or an explain body over 16 KiB.
- **New records.**
  - `identity permit grants_matched` and `identity deny no_grants_matched`.
  - `explain <the answer>`, with `explain.asked_by` and `explain.asked_by_fingerprint`, the
    `policy.bundle` that answered, `explain.command: true` when one was asked and never the
    command; on a broker fault, `explain.mint_error: broker_error` with no verdict.
  - `revoke deny api_right_missing`, naming the target (or the key) and the caller in `origin`.
  - `revoke` with `by: self` or `by: key`, `device` and `username`, and `origin: api <principal>`;
    `saved` only on a standing mark.
  - A record about someone other than the caller carries no `auth`: `auth` and `principal` always
    describe one credential, so a join of fingerprint to principal stays true.
  - A call refused before it is read, or as its connection binds, is recorded under its own
    event, with the mint's reasons. A busy answer writes no record.
- **Metrics.** `port49_revocations_total{by}` gains `self` and `key`.
  `port49_decisions_total{event}` counts `identity` and `explain`.

**Unassigned follow-ups:**

- A bulk lift, `port49 revoke --lift --origin "api <principal>"`, so recovery from a mass
  revocation by a compromised `revoke_others` certificate is one command, not one lift per victim
  (pre-flight M19; the shell loop above until then). It takes a `--since` as well, so a lift
  never reaches a mark the same origin made before the compromise (task 14 review I1).
- `internal/agent`'s `TestAnExpiredHangUpDuringARefreshEndsTheSession` (7b code) failed once in a
  Task 10 mutation run across `./...`; 200 plain runs and 15 package runs under `-race` did not
  reproduce it. Task 11's first `make test` also reported one failure it could not attribute,
  not seen in five reruns. Watch for it.
- The next L31 run confirms the quarantined phase's reload applies under
  `max_removed_percent: 100` (Task 10's harness edit, vet-checked only).

**After the merge:** main's `tests/lab/labpcap` test fails until this branch merges: the raw
captures are already in main's `tests/lab/captures/`, and their redacted evidence arrives with the
merge. Run `make test` on main after the merge to see it pass.

**Carried, for later plans:**

- **7d:** `storetest.DeleteTokenRemovesOne` and `DeleteTokenRacesRedeem` on the etcd backend. Its
  M-2 case puts a token already expired; etcd may refuse that put, in which case use a
  clock-advancing constructor. `DeleteToken` keeps 7a's index entries (Task 6 ruling); the
  property does not assert whether a deleted token's stale entry stays, so a backend may prune it
  only where that cannot hide a second live token under the key. The self-revocation's
  compare-and-set on the backend's `SetContextPolicy`. The agent's single held connection (final
  review): a `port49 token` started behind a slow revocation (up to 85 s) still gives up at 30 s
  and says the broker is unreachable; a second connection for revocations is a design change. It
  fails safe and predates 7c, but a remote store makes it likely.
- **Spec, unassigned:** a `revoke` record for a mark that could not be written (final review M3).
  Spec §5.7 says such a mark writes none today, so only port49d's stderr shows it during a store
  outage.
- **7e:** `/healthz` and `/readyz` on the broker's own process. The revocations file's init in the
  broker's deployment, run once at install and never on a start path. A reload guard at start,
  against the last bundle in force, so a restart cannot load a file the guard refused (pre-flight
  I4). The per-caller self/key bound (`holdOwnRevoke`) and the revocation slot are per process;
  with replicas, a caller holds one per replica.
- **7g:** rights held through a group subject (`HasRight` refuses one today, pinned by ed06f3d).
- **7h:** `/v1/tokens/revoke` by `sid` (400 today); `/v1/logout`.
- **12:** the deployment's `port49d init-revocations` step: once, at install, by hand or as a
  one-off job, as port49d's user, and never in an init container or `ExecStartPre=` (a tolerated
  failure there re-creates the file on the next empty volume, the hazard decision 32's amendment
  removes); the small-fleet note on the reload guard; the guard at start, as for 7e; the broker's
  readiness probe as HTTPS with no client certificate.

### Plan 7d — As built

Executed in two merges from `2026-10-02-07d-shared-store.md`, each task reviewed. The ledger is
`.superpowers/sdd/2026-10-02-07d-shared-store/progress.md`, with each task's brief, report and
review beside it. `7d2-carries.md` records what each task handed a later one. A pre-flight review
and two re-checks revised the plan before Task 1 (ef549e4). Tasks 4b, 6b, 7b and 13b were added
during execution. 7d-1's Task 8 Step 6 section was not written at its merge, so 7d-1 is recorded
here from the ledger. What differs from the plan's text, task by task:

**7d-1** (`feature/shared-store`, base ef549e4; merged 2026-10-02, PR #24, merge fe23595):

- **Task 1 (docs; 2f37031, f371f37).** Two clauses moved to Task 8b, because only 7d-2 builds
  them: the once-per-process ledger, and "cannot lift a revocation by principal or certificate"
  holding only under the daemon's role.
- **Task 2 (the lifted suite; feed70c).** 44 subtests on memory and crypt.
- **Task 3 (`SwapLogin`, `PurgeTokens`; a7d3d89, 7eb5054).** A racing property pins the mark
  check to the write inside `SwapLogin` (review I1).
- **Task 4 (the login's one step; 8022d26, 300a222, 8f656a8, 2062739, c9d40c3).** A join that
  errors wrote a `FailReceipt`, as an interim fail-closed step. Two known-gap tests pinned a
  revoked certificate replaying PASS. 300a222's spec amendment was reverted (2062739) by
  ruling I4: the spec was right, and 4b restores it.
- **Task 4b (the seal, the ledger, the marks; 60e0ec4, b0dafc9, 909c42a, ef31e69, 5f6aa9d,
  19277e9, 98c7d9d).** Beyond the plan, a sealed `Logins` witness: the last 8
  `credential_sha256` prefixes. It is the commit proof a replay needs, which a store writer
  cannot fake. An unwitnessed replay is `token_spent`. Both known-gap tests flipped. Task 5
  found a ledger defect: under concurrent writes, "last" could be recorded out of commit
  order. It was fixed on `fix/ledger-order` and cherry-picked (0c304ad, 19a47c4).
- **Task 5 (the etcd foundation; 2fef779, 6432b92, be47fc8, 78cc867, eec9c57).**
  - `Backend.RaceRounds` per backend, and `make test-race`.
  - Race properties for `IndexToken` and `ExtendReceipt` (review I1).
  - prometheus, x/crypto and x/sys bumped.
- **Task 6 (contexts on etcd; 355c506, 78275f2, c3ba62a).** Sealed writes return their commit
  revision (c3ba62a), ahead of Task 6b.
- **Task 7 (the indexes on etcd; c78380e, 98b6999, 3f7a0d9, 749af0c, 12f9315, 98c06fe).** An
  `x/` record that does not decode no longer stops anything (review I-1, overriding the plan's
  `TestAnUndecodableIndexRecordIsAnError`):
  - a revocation over-reaches it;
  - `ActivePrincipals` and the sweep skip it and count it
    (`port49_store_index_records_undecodable_total`);
  - the sweep never deletes what it cannot decode.
- **Task 6b (new: the ledger by revision; 17fcab3, 38856a8, f2c0aee, 4bc961c).**
  - The ledger orders writes by commit revision, so two first logins on an empty key are not
    denied.
  - A regression witness stops a snapshot restore under a running port49d from admitting a
    stale record over a new session (review C1).
- **Task 7b (the re-index; ff5c3fb, d2f4a56, 4d4c531, c375955, 858f7f0, b76b703, 0fa66d9,
  2ade09f).**
  - One garbled `c/` no longer aborts the refresh: it is deleted at the revision read.
  - A rotated sid is written into the sealed record (`ContextRefresh.Sid`), so the re-index
    compares sids exactly.
  - Deleted `ip/` and `is/` lookup entries are found too.
- **Task 8 (idempotency on etcd, every property; 79dcd46, f978801, 57ef6fe, c73f05b,
  2ec6ca5).** 57 subtests each on memory, etcd and crypt-over-etcd.
- **Flakes.** Five were fixed first and merged as PR #23. One was a production fix: the refresh
  challenge retries a reset on a held connection.
- **Final review (ecec515, a9cf678, 2e3901b, bd4ae7f; docs 42ceb9a–81b9c98).**
  - F-1: an unparseable lookup entry is said, counted, skipped and swept.
  - F-2: a context under a key port49d does not hold is never revoked.
  - r-m1: a refresh that skips anything keeps `port49_policy_refresh_pending` at 1.

**7d-2** (`feature/shared-store-daemon`, base 06d0821; merged as PR #25, 9282085):

- **Task 8b (docs; ee4ff27, then 910b213, 8a49560, 41fd152, 6e43436, 707e828, 82deff5,
  f63df64, 37dbd0e, e4eb512, 1218c9a, 952d6ed, 0931755, 413f63a, 1d928e3, 90e4775,
  1751e4e).** The docs follow 7d-1's code over the plan's text. A context under a key not held
  is denied, never revoked (a9cf678), so decision 35 and the operator note say the start leaves
  it, not that it "ends" it. Four review rounds reshaped the hold:
  - `hold_ttl` is 10s to 60s, refused below 10s. clientv3's keepalive loop ticks every 500ms,
    so a healthy lease of 5–8s can report under half its TTL.
  - The fence loses an answered read only when it reports under half of `hold_ttl`, judged at
    its send. The judgement is a pure `judge`, tested by table.
  - The round trip a hold survives, to the etcd leader, is the least of three bounds:
    `call_timeout` binds at the defaults.
  - `etcdutl snapshot restore --bump-revision 1000000000 --mark-compacted` was confirmed in
    v3.6.15's source and recommended.

  Rulings T12-a, c and d came out of this review (below).
- **Task 9 (the guard; c03cc30, 3628986, 4753190, 2644adb).**
  - A caller's deadline while it waits for a slot is `saturated`, not `canceled`, so a full
    pool never reads as devices going away.
  - A caller already past its deadline is `deadline`, counts toward the circuit, and never
    reaches the store (review I1).
  - The circuit gauge is set from the pool's state under its lock.
  - An open circuit and a refused run are each told once (review M1).
  - `TestRefusalsGoDark` uses four refusals, so the gap check is pinned.
  - The etcdtest hung proxy and the cluster retry are exercised (7d-1's Task 5 review M3).
- **Task 10 (the config; c7d67c8, 74b79b9).**
  - `hold_ttl`'s floor is 10s, per Task 8b; the brief's 5s was stale.
  - An endpoint with user information, a path, a query or a fragment is refused at load,
    naming only its index. The first cut echoed the endpoint, password included (review I1).
  - Store file paths must be absolute.
  - `start_timeout: 0` decodes bare (`StartTimeoutSet` is `*zeroDuration`, not the plan's
    `*time.Duration`).
  - Every refusal carries `config: `.
- **Task 11 (identities and roles; 6377394, 38bb2ab, 86adb77, 2df619b).**
  - `CheckIdentity` also reads the daemon's own grants (`UserGet`, `RoleGet`). It refuses any
    grant on `id/`, `tp/` or `tc/`, and any write outside the nine families. The probes alone
    passed a daemon grant widened onto `rv/`, `meta/hold` or `id/` (review I1).
  - Ruling T11-a: a certificate CN of `root` is refused, at load and by `CheckIdentity`, as is
    a user holding etcd's root role.
  - An identity whose etcd user cannot be named is refused.
  - `ErrNotSeparated` reads "a store identity reaches past its role".
  - `store-roles` prints the residual, and says to check an existing role with `etcdctl role
    get` first.
- **Task 12 (port49d on etcd; 1d8cd0b, db6c12b, 5739e76, 01da5d1, 5abcd36, c1d2f65, ab106b1,
  5b459a8, c47be85, 4c37a54, 0f75e02, fb28ba4, ace3fd9, d8f8f5c, 6c3a3ff, 793df0a, 709e579,
  f054682).**
  - **Signatures the plan does not list:**
    - `guard.WrapRev`: `crypt.Wrap` takes a `store.RevStore`, so the plan's
      `crypt.Wrap(guard.Wrap(…))` did not compile;
    - `broker.ErrLeftUnderUnheldKey` and `ErrPrincipalUnvisited`, exported;
    - the process's one ledger, passed to `openStores`, `runOnce` and
      `startOnPersistentStore`, which returns `(refreshOwed, error)`;
    - the start's hold-or-open decision, the pure `startLeftBy`;
    - `reloader.startLeft`.
  - `refreshContexts` returns what it left by precedence: an unvisited principal, then a busy
    context, then an unheld key.
  - `session.mark` returns an outage over an earlier unreadable context (M-B9).
  - The plan's end-to-end tests lacked the exec session authorization; `loginSession` adds it.
  - `TestAStartSealsTheLedgerOnceItHasReadTheStore` pins where `Seal` is called (7d-1 m-7).
  - Ruling T12-e: `Hold` waits a third of `hold_ttl` after the lock.
  - From the review: `Hold` grants its lease under the caller's ctx, capped at a third of
    `hold_ttl`, and bounds its TryLock and holder write the same way. It lets go with a 1s
    bound, and says when it leaves the lease to expire.
- **Task 13 (the crypt alarm; bbf39d5, f0082bb, cf4d0b2, e95edfa, 2df6bb2).**
  - The start's warning says the sessions are denied until a start holds the key, not that
    the start ends them.
  - A key id outside `[A-Za-z0-9._-]{1,64}` prints as `?` (`crypt.LineKeyID`). Config still
    accepts such an id (spec follow-up, below).
  - Ruling T13-a: an undecodable `meta/seal_keys` is said, gauged 1 and overwritten, and the
    start goes on.
  - The check is bounded at four times `call_timeout`.
  - Ruling T13-b: the alarm is per process. It is kept across a store-gone re-entry and gauged
    while that run waits.
  - An empty key id is called corrupt.
  - One sayer serves every sealing layer, pinned by a test.
  - bbf39d5 pins 7d-1's untested change: the session refresh reports a context under an
    unheld key `not_judged`.
- **Task 13b (new, Ruling T12-g; 87c4d21, c043526, e4e32ac, f46ee39).**
  - Every context seal carries a fresh random `write_id` (form 3), and the ledger is keyed on
    it, so an earlier version of the same context put back while port49d runs is denied.
  - A form-2 record does not open: it is denied, then revoked by the refresh as tampered.
  - Ruling T13b-a: the refresh still revokes a context the ledger denies, after a restore too.
  - Review I-1: a read that raced a write of the same context is read again, up to twice
    (`Ledger.stale`), and `revokeUnopened` reads once more before it revokes. A re-index pass
    that meets the race leaves that context for the next pass.
- **Task 14 (the agent; 05cfecb, 8a9b75a, 98505fc, 92161a7).**
  - 05cfecb takes the unassigned carry: an admin-socket answer naming nothing exits 1 as
    unanswered. `admin.Response` has no `by`, so "naming nothing" is no `error` and no `text`.
  - 8a9b75a is a WIP commit, kept, from redoing `agent.go` edits that a `git checkout` lost.
  - 92161a7: a revocation behind a running one says it was not sent.
- **Task 15 (the lab; b3ce65d, b193375, 79812ef, a6ebda6, 4f62284, 0eee340, 2a340f6;
  3159dbc from 79812ef's review).**
  - **Harness fixes:**
    - replies are matched on the device port, session and sequence;
    - a redeem answered ERROR is recorded `deny store_unavailable`;
    - IB1's dark check is re-run after the settle;
    - an INVALID cell is re-measured (Ruling T15-a); none was.
  - **A code bug, fixed with a unit test in 79812ef.** After a `--bump-revision` restore, a
    login's write compared on the restored record's low revision and committed above the
    ledger's last, and the ledger dropped it. So the first login after the restore was denied
    on its own context. Design §12 was right and the code wrong (CLAUDE.md lab rule 4).
    The fix's own review hardened it in 3159dbc: such a write becomes the last only if it was
    sent after the last write ended. That closes a write whose reply came late, across two
    restores, being placed over a later write the store holds.
  - **Docs corrected by the notes (2a340f6).** The listeners close when the hold is lost, not
    after `hold_ttl`. IOS-XE refuses an open session's command once port49d is dark.
- **Task 16 (this section; the docs).** Spec §15's Junos `authorization-time-interval` note
  is now the memory store's. On etcd the store keeps the contexts across a restart, and the
  note says L35 did not measure the re-authorization. 13b's two nits are fixed: the
  `reindex.go` comment names `errReadAgain`, and a design §8 line is rewrapped. Every other
  drift a task report names was fixed in that task's own docs commits.

**Rulings, as made** (spec §13, decision 35; the plan's rulings 1–18 and OD-1):
- **Stand as written:** 1–7, 9, 13, 15, 16 and 18, and OD-1 (Go 1.26).
- **Ruling 8 (the guard)** gains Task 9's two deadline outcomes.
- **Ruling 10 (identities)** gains the grant read and the `root` refusal (T11-a).
- **Ruling 11 (the hold)** is amended:
  - by Task 8b: `hold_ttl` is 10s to 60s, and an answered read is lost under half, judged
    at its send;
  - by T12-b: one ledger per process, kept across a store gone;
  - by T12-e: a new holder waits a third of `hold_ttl` before it serves.
- **Ruling 12 (the start)** tells three outcomes apart:
  - T12-a: a context under an unheld key opens the start, and the pending gauge stays 1;
  - T12-c: a principal whose lookup failed holds the start, as an outage does;
  - T12-d: a busy context opens the start, and is retried at once.
- **Ruling 14 (the crypt alarm)** is amended:
  - the warning says denied, never ended;
  - T13-a: an undecodable seal-key record never refuses a start;
  - T13-b: the alarm is per process.
- **Ruling 17 (the seal and the ledger)** is amended:
  - T12-g: the ledger is keyed on a sealed write ID, so a runtime put-back of the same
    context is denied (Task 13b). This had been proposed for 7e; Ryan ruled to fix it now,
    2026-10-03.
  - T13b-a: a denied context is still revoked by the refresh.
  - 79812ef and 3159dbc: a write sent after the last ended, which commits above it after a
    revision bump, is the last.

The controller's rulings in 7d-1 are each in the ledger:
- C1: every mark applied at the start;
- I12 and CA1: the whole-context seal, and the token's trusted fields sealed;
- IA1, with I1's `Seal`: the ledger;
- the `Logins` witness (4b review I1);
- the exact-revision ledger and its restore witness (6b);
- an undecodable index record over-reached, never fatal (Task 7 I-1);
- the rotated sid sealed (7b);
- F-1 and F-2.

**Lab (Task 15)**, five images on beehive, 2026-10-03, run at 0eee340 from a pinned worktree with
`hold_ttl` 60s (`tests/lab/results/L35-*.md`; captures `tests/lab/evidence/L35-*.pcap`). Every
step-3 cell was valid on its first hang. With the store hung, every reply came in 500–502ms in
the capture (`call_timeout`), so `packet_deadline`'s 2s default stands.

| image | store hung: command / login | break-glass, store hung | dark after | dark: open session / break-glass | listening again; the session |
|---|---|---|---|---|---|
| vEOS-lab 4.31.2F (tagged 4.32.2F) | FAIL, port49's text / ERROR, refused | logs in; its command FAIL | 12s | runs / logs in | 56s; same `ctx_id`, permit |
| N9Kv 10.4(2)F | FAIL, AAA error / ERROR twice, refused | logs in; its command FAIL | 25s | runs / logs in | 38s; same `ctx_id`, permit |
| C8000V 17.13.01a | FAIL, prints nothing / ERROR, refused | refused (ERROR is final) | 20s | **refused `% Authorization failed.`** / logs in | 1m27s; same `ctx_id`, permit |
| vJunos-router 23.4R2-S2.1 | session runs on / ERROR, refused | logs in (`password`) | 17s | runs / logs in | 55s; runs |
| vSRX3 21.4R3.15 | session runs on / ERROR, refused | logs in (`password`) | 14s | runs / logs in | 53s; runs |

On every image a restart on the same store kept the open session, and refused a token minted
before it `token_not_found`. Listening again waits for the lost hold's lease (60s) to expire,
then a third of `hold_ttl`.

The IOS-XE dark row contradicts `quarantine-cisco_iosxe.md`, where an open session's `show
privilege` ran with port49d stopped. The two runs differ in the command and in what came before
(a hung store's FAIL). Design §12 now states what was measured, and a run to settle the
difference is carried to 7e.

**The restore** (`L35-restore-*.md`), on vEOS, the N9Kv and the C8000V, with etcd 3.6.15:
- `store-roles`' 21 lines run as printed under etcdctl, and port49d starts under the roles
  they make.
- `--bump-revision 1000000000 --mark-compacted` reused no revision.
- port49d said nothing through the 8.1s restore and stayed listening.
- The session written since the snapshot was denied `store_unavailable`. The next refresh pass
  revoked it (counted failed), and the device still showed `store_unavailable` after that.
- A new login after the restore was admitted, after 79812ef.

**Operator notes** (for the pull request bodies and plan 13's docs; the plan's "Operator-facing
notes", amended by what was built).

7d-1's, as PR #24 carried them, still hold, with one change from Task 13b. port49d remembers the
write it last made at each device and username, not only the `ctx_id`. So an earlier version of
the same session, written back, is denied too: `store_unavailable`, counted as
`port49_crypt_open_failures_total{record="context"}`, until the next login.

7d-2's:

- **New: `store:` in `port49d.yaml`.** `backend: memory` stays the default.
  - **Turning on etcd.** Set `backend: etcd` with `store.etcd`:
    - **endpoints:** `https` only, with `ca_file`. An endpoint with a user, a password, a path
      or a query is refused at load, and the error names only its index.
    - **a client certificate each for `daemon` and `broker`.** The CN is the etcd user, and
      neither may be `root`. The key files are owned by port49d's user, mode 0600, not
      symlinks, and every path is absolute.

    `admin_socket` must be set too. Run `port49d store-roles --config …` and apply its output
    once, as etcd's root. Its 21 lines run as printed under etcdctl 3.6.15.
  - **Knobs and defaults:**
    - `call_timeout` 500ms, `bulk_timeout` 30s;
    - `packet_deadline` 2s, at most 2s: Junos times out at about 3s (L13). Measured with a
      hung store, every reply came in about 500ms (L35);
    - `breaker`: 5 failures and 5s open;
    - `max_in_flight`: 64 token, 128 context, 4 bulk;
    - `lease_grace` 5m;
    - `start_timeout` 30s. A bare `0` waits forever;
    - `hold_ttl` 15s, from 10s to 60s. A shorter hold can drop on a healthy etcd, so it is
      refused;
    - `sweep_interval` 10m.
- **etcd itself.** Run three or five members in the devices' region, with:
  - client-certificate auth and auth enabled;
  - `--auto-compaction-mode=periodic --auto-compaction-retention=1h`, and defragmentation;
  - a quota above the live records;
  - **every call answered well under `call_timeout` (500ms).** That is the binding bound at
    the defaults. The hold itself survives a round trip to the etcd leader of about 0.83s at
    `hold_ttl` 10s and 1.25s at 15s. Past any of them port49d closes every listener: dark,
    never two port49d on one keyspace. A cross-site etcd raises `call_timeout`,
    `packet_deadline` and `hold_ttl` together.
- **The roles.**
  - **etcd replaces a grant on the same range; it does not add to it.** Re-running an older
    `store-roles` output, or granting by hand, can silently change a role.
  - port49d's start reads the daemon's grants and refuses one that reaches past its role ("a
    store identity reaches past its role").
  - Check an existing role with `etcdctl role get` before you apply anything.
- **Who may write etcd.** The daemon's client certificate can write tokens, receipts, contexts
  and the index. With it alone, a thief can replay records port49 sealed, never forge them.
  - **While port49d runs**, a session record put back is denied, an earlier version of the
    same session included. A `revoke --mine` or key revocation that answers `incomplete`
    holds while port49d runs, but may not be sealed into the record yet: run it again.
  - **Across a port49d restart**, a record put back while port49d was stopped is taken:
    - another login's, which is impersonation until that session's ceiling or its device's
      next login;
    - or an earlier version of the session's own, which undoes a `revoke --mine`.

  Protect the daemon's key like the encryption key. After a suspected theft, have etcd stop
  trusting that certificate before port49d next restarts: a new CN, granted the daemon's role,
  and the old user deleted.
- **Backups.**
  - **Back etcd up** as you would the revocations file.
  - **Protect every snapshot as the store itself.** It holds who is logged into which device
    (the plaintext index; design §8).
  - **Restore with port49d stopped.** Use `etcdutl snapshot restore --bump-revision 1000000000
    --mark-compacted`, which reused no revision when measured (L35).
    - A restore rolls the marks back too: a revocation added since the snapshot is gone from
      etcd, and one lifted since is back.
    - The start puts the revocations file's marks back into etcd, and applies every mark to the
      restored sessions. It purges every unspent token, so a token redeemed since the snapshot
      cannot be redeemed again.
    - Then run `port49 revoke --lift` again for any revocation lifted since the snapshot.
  - **What a restored snapshot brings back.** It brings back the contexts it held.
    - One ended by a principal or certificate revocation is denied again at once, by the
      marks.
    - One ended by `port49 revoke --mine`, or by `(device, username)`, is live again until its
      idle TTL. Revoke it again after a restore.
  - **Restored under a running port49d,** port49d sees the rollback as records put back.
    - Every session written since the snapshot is denied `store_unavailable`, and the next
      refresh pass revokes it.
    - **The device still shows `store_unavailable` after that pass, not a revocation** (L35).
      The user logs in again, and that login is admitted.
    - A port49d restart before the pass admits those sessions again.
- **One port49d per keyspace until plan 7e.**
  - A second one waits, is not ready, and names the holder every 30s.
  - On Kubernetes use `strategy: Recreate`.
  - Never delete `meta/hold` by hand: stop the port49d that holds it. A port49d that takes the
    keyspace waits a third of `hold_ttl` before it serves, so a deleted key never serves two
    while etcd answers both.
- **What a restart does now.**
  - Live sessions survive. Every standing revocation is applied to them first, so a mark added
    to the file with port49d stopped takes effect before it serves. Each is then carried onto
    the policy in force, and the next command is answered from the kept context. Measured on
    all five images (L35).
  - Unspent tokens are purged (`port49d: store: purged N unspent token(s) …`), so run `port49
    token` again. A retried `port49 token` with the same idempotency key mints afresh.
    - **The replay's caveat.** That relies on this port49d's clock. If port49d moves to a host
      whose clock is behind the old one's, a replay inside the skew can still be answered from
      before.
    - **A pending reservation.** One a stopped port49d left blocks its key for up to a minute.
  - **Editing `broker.revocations_file` with port49d stopped no longer lifts a mark on etcd:**
    the store's copy comes back. Lift with `port49 revoke --lift` on the admin socket.
  - **Junos re-authorization on etcd is unmeasured.** On the memory store a restart denied
    every live Junos session's next re-authorization (`authorization-time-interval`). On etcd
    the contexts survive, but L35 did not measure a re-authorization (§15 L36, open).
- **What an etcd outage does.**
  - **At start:** nothing listens, and `/readyz` says `waiting for the store`. Devices use their
    local method, and break-glass works. port49d waits up to `start_timeout`, then exits 1. With
    `0` it waits for as long as it takes.
  - **While running:**
    - Commands are refused `store_unavailable` within `packet_deadline`, and at once after the
      circuit opens (`port49_store_circuit_open` 1). Break-glass logs in where the device falls
      through on ERROR: on vEOS and the N9Kv its commands are then refused, and Junos
      authorizes no command with port49. IOS-XE refuses break-glass outright (L4, L35).
    - **The listeners close.** They close when port49d loses its hold (12–25s into a hang at
      `hold_ttl` 60s, measured), or when a pool's circuit stays open for `hold_ttl`.
      - port49d resets every held TACACS+ connection and says why.
      - `/readyz` is 503 meanwhile. port49d does not exit.
      - Devices fall to local, and break-glass logs in on all five images.
    - **On IOS-XE, dark means break-glass.** An open session's commands are refused (`%
      Authorization failed.`) until port49d listens again. vEOS, the N9Kv and Junos run them
      under local authorization.
    - **Listening again.** port49d waits for etcd itself, then serves again, and sessions resume
      on their contexts. That takes the lost hold's lease to expire, plus a third of `hold_ttl`:
      38s to 1m27s at 60s, measured. Meanwhile it says `keyspace … is still held by this
      port49d's last run (its hold was lost when the store stopped answering); waiting up to
      hold_ttl (…) for its lease to expire`: that is port49d waiting on itself, so do not stop
      it. If that start fails for another reason (a policy file caught half-written), it says
      so and tries again every 5s; it does not exit.
    - **Keep `Restart=on-failure` anyway.** It still restarts port49d after a crash, or after a
      cold start that exits 1 (a configuration fault, or `start_timeout`).
    - **Metrics between runs.** `/healthz`, `/readyz` and `/metrics` are unbound for the drain
      and the next config load (seconds), and the counters restart. Give a Kubernetes liveness
      probe a failure window over 30s.
  - **A store slow but up** does the same once its token or context calls keep missing their
    deadlines. So does etcd refusing every such call (a role removed): a steady run of
    refusals, not two an hour apart.
  - **Slow scans** (the refresh's, a large purge) open only the bulk pool's circuit
    (`port49_store_circuit_open{pool="bulk"}` 1, and a line saying logins and commands are
    unaffected). port49d keeps serving. Alert on it, and size `bulk_timeout`.
  - **A wrong token's FAIL** arrives at the failure delay even with a slow store. The store's
    time is inside the delay, so it is at most 2s at the defaults.
- **Certificates.**
  - Each start prints each client certificate's expiry, and
    `port49_store_client_cert_expiry_timestamp_seconds{component}` carries it.
  - An expired or untrusted certificate is named, never reported as etcd not answering.
  - A certificate that does not parse is refused, naming both of its files.
  - After an outage, a renewed certificate file is picked up without a restart.
- **New metrics:**
  - `port49_store_calls_total{component,pool,outcome}`, `port49_store_call_seconds{component,pool}`
    and `port49_store_circuit_open{component,pool}`. The pools are `token`, `context` and
    `bulk`; the outcomes include `deadline`, `saturated` and `refused`;
  - `port49_store_keyspace_held`, `port49_store_client_cert_expiry_timestamp_seconds{component}`
    and `port49_crypt_store_key_unknown`;
  - port49d now reports 7d-1's `port49_contexts_reindexed_total`,
    `port49_contexts_reindex_failures_total` and
    `port49_store_index_records_undecodable_total`.

  Alert on any of:
  - a circuit open;
  - any increase of `port49_contexts_reindexed_total`: an index record was deleted in etcd, and
    the context it hid has been re-indexed (each sweep, `sweep_interval`);
  - any increase of `port49_crypt_open_failures_total{record="context"}` with the key held: a
    record altered in etcd, or another login's, or an earlier version of a session, written
    back;
  - `port49_store_keyspace_held` 0 while port49d runs;
  - a client certificate within 30 days of expiry;
  - `port49_crypt_store_key_unknown` 1;
  - any `increase(port49_crypt_open_failures_total{record="token"}[10m])`.
- **Key rotation across a restart.** Keep `encryption.previous` until the old key's records
  expire.
  - **The warning.** A start that finds the store last written under a key it does not hold
    says so. It names the key id, printed as `?` if it is outside `[A-Za-z0-9._-]{1,64}`, and
    sets `port49_crypt_store_key_unknown` to 1.
  - **The alarm lasts only for that process.** The next start records its own keys, so the
    warning and the gauge clear even if sessions sealed under the lost key are still live.
    From then on `port49_crypt_open_failures_total` and the unopenable-record lines are the
    only witnesses.
  - **The unopenable-record lines.** A record that will not open is named by its key id on
    stderr, once per 10 minutes.
  - **An unreadable `meta/seal_keys`** is said, raises the alarm, and is overwritten. The start
    goes on.
- **A wrong `PORT49_ENC_V1` never revokes.** Sessions sealed under a key port49d does not hold
  are denied `store_unavailable`.
  - The re-index and the refresh say each one by device and username, count it
    (`port49_contexts_reindex_failures_total`, the refresh's `failed`), and leave it.
    `port49_policy_refresh_pending` stays 1.
  - Fix the key and restart, and those sessions answer again.
  - A record that fails authentication is tampered and is still revoked. So is another login's
    record or an earlier version of the session written back.
- **A session record that does not decode** (a `c/` value garbled in etcd) is unreadable, as
  one that will not open is.
  - The next login on that device and username replaces it.
  - The refresh and the re-index delete it at the revision they read, since nothing can revoke
    or use it.
  - It is said by its key alone, never its value.
- **A `port49 token`, refresh, identity or explain behind a slow `port49 revoke`** now says
  `your revocation sent at … is still running on the broker; nothing was minted; run port49
  token again once port49 revoke reports` (exit 1). It no longer says `the broker … is
  unreachable`.
- **A revocation behind another running one** says `an earlier revocation still held the
  connection; this one was not sent` (exit 1). Nothing was sent, so run it again.
- **`port49 revoke` on the admin socket now exits 1 on an answer that names nothing.** It says
  ``port49 revoke: port49d did not answer (its answer named no revocation); the revocation may
  be in force — check `port49 revoke --list` and port49d's log before retrying`` (`lift` for a
  lift), as the agent forms already did. port49d never sends one.
- **New command: `port49d store-roles [--config FILE]`.**

**Unassigned follow-ups:**

- 7c's M3, unchanged: a `revoke` record for a mark that could not be written.
- The bulk lift (7c), unchanged.
- **New: Ruling 17's residual, as Task 13b left it.** With a stolen daemon store credential:
  - **Across a restart, impersonation.** Another login's context put back while port49d was
    stopped is taken as that key's at the start. It holds until its sealed ceiling, if it has
    one, or the key's next login.
  - **Across a restart, rollback.** An earlier version of a key's own context put back while
    port49d was stopped undoes a revocation that leaves no mark (self or key). The start's
    refresh judges its policy.
  - **While port49d runs** (narrowed by Task 13b from any earlier version): the write before
    one in flight or of unknown outcome, put back, is admitted until a later write lands at
    the key. A self or key revocation whose seal failed after its plaintext mark landed is
    held by the ledger's revocation floor (final review I-1); across a restart it is that
    mark alone, so its `incomplete` answer says to run it again.
  - A deleted token put back for a holder of its secret, until its sealed expiry.
  - A receipt's sliding bound stretched to its sealed cap.
  - A context kept alive past its idle TTL: to its sealed ceiling if it has one, and
    indefinitely under `max_session_age: never`.
  - A context hidden from the index until the next sweep re-indexes it. Meanwhile a revocation
    by sid does not reach it.

  Closing it needs two things. One is a revocation record the daemon's role cannot write, for
  every kind: a spec change to decision 34. The other is a sealed freshness check that holds
  across restarts: Task 13b's write ID holds only within one process's ledger, so this needs a
  write sequence the broker's role keeps per key, which 7e's shared ledger could become.
- **Spec follow-up (7e or later):** config refuses an encryption key id outside the seal-key
  charset. Today such an id prints as `?` (Task 13).
- `TestStartClusterRetriesAPortTaken` (etcdtest) failed once under load: its one retry hit a
  taken port again (the pick-then-bind race). A retry until a deadline would settle it.
- Lab hygiene: beehive's root filesystem filled during Task 15 and killed port49d at setup
  (ENOSPC). Check free space before a lab run.

**After the merge:** the raw L35 captures are only in the 7d-2 worktree's `tests/lab/captures/`.
Copy `tests/lab/captures/L35-*` to the main checkout before removing the worktree, or the
labpcap audit fails.

**Carried, for later plans:**

- **7e:**
  - `b.superseded`, `b.blobsSeen` and `quarantineRecorded` move into the store, with m10's
    bound on `b.superseded`.
  - More than one port49d per keyspace: the hold becomes per broker process, and the daemons
    hold none.
  - The listener's marks and the daemon's (`store.Marks`) are shared across replicas, through
    a watch on the marks family.
  - The ledger (`crypt.Ledger`) is shared across replicas or replaced, since per process it
    would deny another replica's logins (re-check IA1). Since Task 13b it is keyed on write
    IDs.
  - `broker.revocations_file` is retired.
  - One refresh runner.
  - The decision-log emits under a policy hold are bounded (4b Task 4).
  - A lab run to settle why IOS-XE refused an open session's command once port49d went dark
    (`L35-cisco_iosxe.md`), when `quarantine-cisco_iosxe.md` ran one with port49d stopped.
- **Lab, unassigned:** §15 L36 (open), whether a live Junos session's re-authorization
  (`authorization-time-interval`) after a port49d restart on etcd is answered from the kept
  context, and whether a denial then ends it. L35 did not measure it.
- **7f:**
  - Go-dark proper: the N-failures/M-passes listener control replaces Ruling 11's coarse
    close-and-wait.
  - The warm context cache.
- **12:**
  - The etcd deployment artifacts: the members, compaction, the quota, and the roles applied
    from `port49d store-roles`.
  - `call_timeout`, `bulk_timeout` and `packet_deadline` sized against load.
  - The store alarms, a client certificate's expiry among them.

### Plan 7e — As built

Executed from `2026-10-03-07e-broker-process.md`, each task reviewed. The ledger is
`.superpowers/sdd/2026-10-03-07e-broker-process/progress.md`, with each task's brief, report
and review beside it. A pre-flight review, a re-check and a final check revised the plan before
Task 1 (716b857). Task 8a was added by the pre-flight (the feed fence). What differs from the
plan's text, task by task:

**7e-1** (`feature/broker-process`, base `b508ba0`):

- **Task 1 (docs, decision 36; 11ac5e2).** As planned. Design §15's exports list gains the four
  7e gauges in Task 11 (review m-1).
- **Task 2 (etcdtest; c21f04f, c92827d).** `StartCluster` retries a taken port until a
  deadline, and a failed attempt stops at once (Ruling T2-a).
- **Task 3 (config; a85c22e).** An encryption key id outside the seal-key charset is refused at
  load. Task 13 routes the broker's keys through the same check.
- **Task 4 (records after the policy; a316fd0, b329bd4, 6bfc362, d7c0662, a4e5215).** A mint's
  records, and a session refresh's (Ruling T4-a), are written once it lets go of the policy.
  One blob record per hash per request (review I1).
- **Task 5 (`superseded` in the store; ca282ba, 6130540, 3e692eb).** The local copy is pruned
  once a minute; the daemon is probed against writing `sp/`. Carried to 7e-2's docs: broker
  replicas need NTP-synced clocks; an undecodable `meta/superseded_all` is deleted, and the next
  start rewrites it.
- **Task 6 (`Seen`, `Ping`; 5f1d17d, f98cd2f, 83ff587).** Every context-client response feeds
  `Seen` (`sawKV`), deletes, indexes and meta included (Ruling T6-a).
- **Task 7 (the sealed sequence and the ledger; f8b057f, dc320bd, bcde669, 3f66a33).** The
  revocation floor is `revoked(k, at, seen)`, held through `max(hw, seen-1)`, in place of the
  plan's pending floor, which revoked every user's next login after the upgrade (Ruling T7-a).
  The unopenable sayer is keyed by (record, key id, kind), so the upgrade's line never silences
  a put-back's.
- **Task 8 (the context feed; 972fefe, 864531a).** `Ledger` gains `SetBase`, `Seed`,
  `ObserveFollowed`, `Dirty`/`Redirty`; a rescan's seed is `seedFollowed`, which makes no entry
  below the base. A floor-only entry counts as no mark. Watch events feed `Seen`.
- **Task 8a (new: the feed fence; 3bd92b7, 08b095f, b2260b1, 618bff3).** `crypt.Fence`,
  `crypt.Fenced` and `ErrFeedBehind`: a context read waits, within `call_timeout`, for the feed
  to pass the record's revision. A waiting read's progress request is made again for each new
  watch. Parked (R-1): `askAgain` may reach etcd before the new watch registers; that read then
  waits out `call_timeout`, failing closed. Task 17 revisits it if L37 sees it.
- **Task 9 (the marks feed; 3677a78, 30e0554, 04a2c71, 88f03c3, a3464a3, 7f98f81, 49fc71d,
  1147a0e).** `WatchRevocations`' callback is `fn(r, lifted, rev)`, and `FollowMarks` advances
  per event (Ruling T9-a). A reload never lifts a mark whose store write has not landed
  (`Marks.Pend`, `Unrecorded`; T9-b); such a mark closes no held connection (spec §5.1.4, T9-d)
  and reaches this listener once the store has it. `port49_revocations_in_force` follows the
  feed (T9-c). An undecodable mark stands by its key on a load as on a watch (T9-e).
- **Flake fix (f6e5a26).** A product bug: on `credential_revoked` the agent's close cut the 410
  answer, so the client said "no agent". It shuts down within 5s after stopping.
- **Task 10 (the ledger record; 267f73a, 782f2d5).**
  - `store.LedgerMark` gains `FloorSeq`, the sequence the floor holds through: `Dirty` writes it,
    and `Seed` takes the floor where the key's mark is at or below it (review C1). `lw/` keeps it
    as `floor_seq`, and a mark above it clears the floor there, as in the ledger.
  - The plan's put-back test needed a second subject sharing alice's username, which spec §2
    refuses. bob is a second identity of alice's subject instead: same username, other
    principal.
  - `KeepLedger` writes what it still owes once when it stops, within 2s, so a graceful stop
    leaves its last round in the record.
  - `TestAStartSealsTheLedgerOnceItHasReadTheStore` deletes `lw/` with the context, so the base
    still judges the put-back alone.
  - Review fix round 1:
    - A floor-only mark (`seq` 0) seeds its floor and no mark, so the key's next login gives it a
      lease again (I-1).
    - A seeded key the ledger holds as the record does is owed nothing, and
      `store.LedgerSink.PutLedgerMarks` returns how many marks landed, so a failed write owes
      only the rest (I-2).
    - A stop that cannot write says how many marks it leaves (M-1).
    - An undecodable `lw/` key names its remedy (M-4).

**Interfaces 7e-1 changed, for 7e-2's tasks:**
- `store.MarkFeed.WatchRevocations(ctx, after, fn func(r Revocation, lifted bool, rev uint64),
  progress func(rev uint64))`. Both etcd watches ask for progress notifications, and
  `FollowMarks` and `crypt.FollowContexts` resume a re-watch from the last progress as well as
  the last change, so a reconnect within the compaction retention never reloads (final review
  I-1).
- `store.LedgerMark{Key, Seq, RevokedAt, FloorSeq, Until}`.
- `crypt.KeepLedger(ctx, l, sink, every, report, logf)`, with the stop's last write.
- `store.LedgerSink.PutLedgerMarks(ctx, ms) (int, error)`: how many of `ms`, from the first,
  landed before an error.
- `crypt.Ledger`: `SetBase`, `Base`, `Seed`, `ObserveFollowed`, `Dirty`, `Redirty`, `Pending`,
  `Fence`.
- `crypt.Fence` (`Attach`, `Followed`, `SetUp`, `Up`, `At`, `Asks`, `Wait`), `crypt.Fenced`,
  `crypt.ErrFeedBehind`.
- `store.Marks.Pend` and `Unrecorded`.
- port49d's `stores.keep`, run and joined by `runOnce` beside `stores.follow`.

**7e-1's operator notes, as built:**
- **Re-apply `port49d store-roles` before upgrading.** It prints one more grant: the daemon's
  read on `lw/`. Without it the start stops with `the daemon's role cannot read lw/, the ledger
  record: apply port49d store-roles (plan 7e)`. The start check also refuses a daemon role that
  can write `lw/`, or read or write `sp/`.
- **Upgrading from 7d on etcd ends every live session once.** A context 7d sealed does not open
  under 7e: it is denied `store_unavailable`, replaced at the user's next login, and revoked by
  the next refresh. Each node says it once per 10 minutes as the upgrade. Rolling back to 7d
  ends sessions again.
- **A context put back in etcd while port49d was stopped is denied after the restart** at every
  key the ledger record (`lw/`) holds a later write for. A revocation's floor is kept there too,
  through every sequence it held. The record trails by at most a second, and a graceful stop
  writes what is owed. A stop that cannot write says `stopping with N ledger mark(s) not
  written to the ledger record`.
  - A revocation at a key with no mark (each form-3 context at the upgrade) leaves an `lw/` key
    with no lease. It gets one at the key's next login. One that never sees a login again stays,
    at most one per (device, username).
  - An `lw/` key that does not decode stops the start, naming the key. Delete that key as etcd's
    root to start without its mark, accepting a put-back at that one key.
- **A context read waits for port49d's watch on the store** (the feed fence): milliseconds
  normally. With the watch stopped and etcd answering, new sessions are denied
  `store_unavailable`, `port49_store_feed_up{feed="contexts"}` is 0, and the line says `the
  context feed stopped`. **Run etcd 3.5.8 or later** (3.4.24 on 3.4; etcd #15220).
- **After an etcd restore under a running port49d,** the next login is admitted, and a session
  written since the snapshot is denied until its next login, as 7d measured.
- **A stalled decision-log sink no longer holds a policy reload**, nor the mints behind it.
- **New config refusal:** an `encryption` key `id` outside `A-Z a-z 0-9 . _ -` (1 to 64).
- **New metrics:** `port49_store_feed_up{feed}` (0 for longer than `hold_ttl` is an alarm),
  `port49_store_feed_rescans_total{feed}` (alert on any increase), `port49_ledger_pending`
  (above 0 for a minute is an alarm: the record cannot be written), `port49_ledger_behind` (1 is
  an alarm: the keeper's context feed is down). Both ledger gauges read 0 once the keeper stops.

## Plan 8 — Workload certificates (§19 step 8)

Design §7 "Machine identity" option 2: enrollment, self-renewal, multi-identity subjects,
`username` declared on machine subjects, cross-domain username collision at mint. Unattended
config backup (Oxidized) as the day-one consumer.

## Plan 9 — Agent in full (§19 step 9)

`port49 ssh` with host-key verification and `port49 devices trust`, the OIDC public client,
the in-session re-auth flow, integration examples (design §17 "Integration examples").

**Owed from plan 3 (owner's rulings 2026-09-24):**
- **A per-user config file** (e.g. `~/.config/port49/config.yaml`: `broker`, `broker_ca`,
  `cert`, `key`) so `port49 login` needs no flags. `broker_ca` stays **required** — the file
  supplies it, it never falls back to the system roots — and it pins the **CA**, not the
  broker's leaf, so a broker certificate renewal does not break every client. Flags override
  the file.
- **Hardware-backed client keys**: YubiKey through its **PIV** applet (PKCS#11), and platform
  keystores (TPM, macOS Secure Enclave), with touch/PIN policy. FIDO2 alone cannot sign a TLS
  handshake; it belongs to the OIDC path. Plan 3's PEM file stays as the fallback.
- **Optional CRL check of the broker's certificate** when it names a distribution point (the
  CA is the operator's own, so this is defence in depth; revocation of *client* certificates
  at the broker is plan 7's, spec §5.1.4).

## Plan 10 — Kubernetes path (§19 step 10)

Projected ServiceAccount token validation against the cluster JWKS; identity
`system:serviceaccount:<ns>:<name>`; the `k8s` verifier type. Design §7.

## Plan 11 — RFC 9887 TLS listener (§19 step 11)

Separate listener on 300, mutual TLS replacing the shared key, device records expressing
both. Design §11.

## Plan 12 — Deployment (§19 step 12)

Deployment artifacts, the **reference device AAA configuration per platform** (the thing that
disables fall-through on FAIL, design §12), load validation at the §5 target rate, the
failure-matrix tests of design §12 and §14, observability alarms with a metric behind each
(design §15).

Carried here from plan 1's review:

- **A global connection cap.** Today the only one is `EMFILE`, which is the worst possible
  cap: it fails `Accept` for admitted devices too, and it fails the spool's own `OpenFile`, so
  accounting starts answering ERROR. Plan 1 pulled forward the two cheap parts — the
  `accept_error` counter and log, and a 5s header deadline for a source that is not admitted.
  The cap itself, its sizing, and its alarm are this plan's.
- **Accounting throughput is bounded by one disk's fsync latency.** `Offer` holds one mutex
  across a `stat`, an open, a write, an fsync and a close, per record, for the whole fleet.
  The fix is a group commit — batch concurrent offers into one fsync — and it needs this
  plan's load numbers to size. Do not change it before there are numbers.
- **`key_validations_total{key_ref}` is a device-identity label in one deployment shape.** Key
  groups make `key_ref` a fleet-wide label with a handful of values, which is what the
  cardinality rule assumes. A deployment that pins a key per device (the tier-1 pin) turns it
  into one series per device — both a cardinality problem and, against design §15's "device
  identity never appears in metric labels", a correctness one. Say which it is and bound it
  when the alarms are written.

**Carried from plan 6a** (Plan 6a — As built, "Carried"): `secret_ref:` resolvers, with the key
sets moving into the policy repository; `key_ref` on `port49_key_version_devices` and
`port49_key_retirement_seconds` as well as above; the write fence's ancestor directories and
ACLs, for `inventory_file` as for the policy file; `TestAnotherUIDIsRefused` run in CI as root;
the inventory-only refresh's cost at fleet size.

**Carried from plan 6b** (final review Minor 7): port49d's config loader
(internal/config/config.go) ignores a second YAML document; refuse it as port49-inventory does.
`config.InventoryServiceOf`, which `SIGHUP` reads, ignores one too.

## Plan 13 — User and admin documentation

**Builds:** a published documentation site — MkDocs Material on GitHub Pages, deployed by a
GitHub Action — written when the repository goes public. Four sections:

- **Concepts:** the token, the receipt and the login context; revocation; trust domains.
- **Operator guide:** install, the broker and the agent, `port49 login`, and troubleshooting
  organized by what the operator sees.
- **Admin guide:** policy, roles and grants, key rotation, revocation, and one device-configuration
  page per platform built from `tests/lab/results/`, including the traps the lab measured.
- **Reference:** config keys, reason codes, metrics and the decision-log schema, generated from the
  code so it cannot drift.

**Inherits:** from every earlier plan, the "Operator-facing notes" section of its PR body (top of
this file).

**Leaves for later:** nothing. **Lab:** none.

---

Plans 8–11 are small and may be merged into a neighbour when written. Renumber nothing;
leave a gap and say why in this file.
