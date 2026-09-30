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
top. Its Task 19 gates the merge; its Task 20 (L29 at midnight) runs first and may land after it.
6c and 7–13 not yet.
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
- **Plan 6b — `2026-09-30-06b-inventory-service.md`. Written 2026-09-30.**
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
- **Plan 6c — the NetBox and Nautobot connectors; written after 6b merges, against L27's and L30's
  fixtures.** Version detection by `/api/status/`, GraphQL first, the REST fallback (`?depth=1` on
  Nautobot 2.x, following `next` as L30 finds it), the slug alias table, filters and maps, source
  credentials by `secret_env`, and the authenticated webhook trigger (HMAC-SHA512 of the body, ordered
  by the body's `timestamp`, a delivery only triggering a sync); every `Fetch` returning within
  `sync_timeout`; and `port49 inventory export --service … [--from N]`, so the offline tools keep an
  `--inventory` when no source is a file. Split from 6b because the connectors
  are the contributable surface and hold the only source-of-truth credentials, and two of their facts
  (L30) were unmeasured when 6b was written.

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
