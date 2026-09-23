# Plan 2b: Context Join Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A second login by the same principal on the same device joins the live login context
instead of replacing it, the stored privilege becomes raise-only, and accounting attribution gets a
metric — so an operator's second window no longer takes away the first window's enable, turns its
accounting STOP into a `foreign` alert, or lifts a revocation.

**Architecture:** The store gains a revision on every context record and one compare-and-set write,
`SwapContext`. A pure function in `internal/store` (`JoinContext`) reads the live context, merges a
login into it by the field rules of decision D1 below, and swaps on the revision it read, retrying on
conflict — so it holds for the memory store and for the sealing layer alike, and never erases a
concurrent `SetRevokedAt`. The login path in `internal/daemon/authen` calls it in place of
`PutContext`. `SetPrivilege` becomes raise-only. Accounting counts every record by attribution.

**Tech Stack:** Go 1.22, standard library, the plan-1 and plan-2 packages. No new dependencies.
Nothing here needs containerlab.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §5.1.1, §5.3, §5.6, §5.8, §13 decision 15,
§15 L1; `docs/design/2026-09-20-login-context-key-options.md`. Roadmap:
`docs/superpowers/plans/README.md`, "Plan 5".
**Prerequisite:** plan 2 merged (PR #4). Branch `feature/context-join` off `main` at `e15aa5c`.

## Why this plan exists

The login context is keyed `(nas, username)` because authorization packets carry no per-window
identifier on every platform: NX-OS sends `port` empty on every command authorization, and Junos
never authorizes commands at all (spec §15, L1, L18). The context is therefore "this principal's
authorization on this device", not one connection. But today a second login by the same user on the
same device **replaces** the whole context (`internal/daemon/authen/authen.go`, the `PutContext` at
the end of `redeem`), which:

- resets the stored privilege — window A, enabled to 15, is then denied `privilege_exceeded`;
- empties `SessionDiscriminators` — window A's accounting STOP becomes `foreign`;
- wipes `RevokedAt` — a token minted before a revocation re-admits the user
  (`internal/session/session.go`, the package comment).

And a session authorization in a new window calls `SetPrivilege` with that window's granted level
(`internal/daemon/author/author.go`, the `cmd == ""` block), lowering the level window A holds.

## Decisions this plan implements (Ryan, 2026-09-23)

These are settled. The plan argues from them and does not revisit them.

**D1. A second login joins the live context instead of replacing it.** Field rules on a join
(existing live context, same principal):

| field | rule |
|---|---|
| `CtxID` | kept (each redeem record still carries its own `credential_sha256`) |
| `PrivLvl` | kept; the new login's level only raises it, clamped to the new ceiling (D2) |
| `SessionDiscriminators`, `AccountingState` | kept |
| `BlobHash`, `MaxPrivilege`, `Enable` | from the newest login (latest broker decision wins) |
| `AuthTime`, `SessionExpires` | the later of the two |
| `RevokedAt` | kept, UNLESS the new token was minted after `RevokedAt` (needs a mint time on `store.Token`) |
| `Credential` | newest; every login is still indexed (`IndexContext`) so revocation by either sid/cert reaches it |
| `Port`, `RemAddr` | newest (informational) |
| `RefreshedAt`, `LastTouchedAt` | now |
| principal differs | NOT a join: fresh context, and the record names the replaced ctx_id |

An expired context (idle TTL gone) is absent → fresh context. A context past `SessionExpires` is
replaced fresh, not joined. Mechanism: a store operation that performs read-merge-write atomically
by compare-and-set with a bounded retry, for both the memory store and the crypt wrapper, never
clobbering a concurrent `SetRevokedAt`.

**D2. Stored privilege is raise-only.** `SetPrivilege` stores max(current, level), clamped to
`store.Context.PrivilegeCeiling()` (zero `MaxPrivilege` = no ceiling). The session authorization
reply still comes from policy, never from the stored level.

**D3. `foreign` gets a metric.** A counter by attribution (`resolved | unattributed | system |
foreign`), snake_case, no device identity in labels. No rate limit.

**D4. Junos console `root` stays `system`.** The `system` record carries the port; the limitation is
documented in spec §5.8.

**D5. Documentation.** Spec §5.6 gets the join table; §13 decision 15 a sentence; §5.3 raise-only.
The key-options memo is wrong about vEOS (two concurrent sessions did not both report `vty4`) and is
corrected against the log. Spec guidance on device-local accounts and local enable fallback. Roadmap:
plan 5 owes a local-account config check; per-window contexts on EOS/IOS-XE are a possible later
addition, not planned.

**Tests that must exist:** (1) second window keeps enable; (2) first window's STOP after a second
login is `resolved`; (3) a token minted before a revocation stays revoked, minted after is admitted;
(4) concurrent joins racing each other and `SetRevokedAt` lose nothing, on memory AND crypt;
(5) another principal under the same username gets a fresh context with the replaced ctx_id
recorded. Task 8 has 1, 2, 3 and 5; Task 5 has 4.

## Decided in this plan

Where the decisions leave a shape open, this plan chooses, and says why here once:

1. **The compare-and-set is a revision, not a field comparison.** `store.Context` gains `Rev uint64`,
   set by `GetContext` and compared by a new `SwapContext(ctx, k, rev, c, ttl)`; zero means "only if
   absent". Every write to a context moves it — `PutContext`, `SwapContext` and all five narrow
   setters — from one store-wide counter, so a record deleted and rewritten never repeats a revision.
   A revision is plaintext bookkeeping, so the sealing layer passes it through: the merge happens in
   `crypt` with the sealed fields open and the precondition is enforced by the inner store under its
   own lock. A callback-under-lock design would not survive a networked backend; a revision does.
2. **The loop lives in `internal/store` (`JoinContext`), not in `authen`**, so the race test runs
   against the exact code the daemon uses, on every store, through one conformance helper
   (`internal/store/storetest`). `MaxJoinAttempts = 8`: a swap is refused only when another write
   landed, so the bound is on concurrent writers to one operator's context, not on time.
3. **The login reads the live context BEFORE spending the token.** The receipt carries the ctx_id
   and is written atomically with the redemption, so the ctx_id has to be known first: the join's
   id if the live context is joinable, a fresh one otherwise. The same read makes an unreadable
   context (store down, or sealed under a retired key) fail the login ERROR `store_unavailable`
   **with the token unspent** — a context port49 cannot read cannot be merged, and replacing it
   blind could erase a revocation. This is a behaviour change: today such a context is silently
   overwritten. It is bounded by the idle TTL, the authorizer already fails every command on that
   context, and `crypt_open_failures_total{record="context"}` names it.
4. **A kept level above a lowered ceiling is clamped** — the join computes
   min(max(held, new), new ceiling), which is `SetPrivilege`'s D2 rule applied to the merge. A
   stored level above the context's own ceiling is a state no other path can produce.
5. **A replace of the SAME principal's context past its ceiling carries `RevokedAt` by D1's rule.**
   D1 says such a context is "replaced fresh"; without this, a revoked operator whose context had
   also passed its ceiling could lift the revocation with a token minted before it — the exact bug
   D1 closes for the join. A different principal's replace starts clean.
6. **Zero `SessionExpires` is later than any time** (it means "no ceiling"), so a join never gives a
   context a ceiling neither login's policy would impose. `CreatedAt` is kept on a join.
7. **The memory store's reverse index remembers every sid and cert a ref was indexed under**, not
   only the last. D1 promises revocation by either login's sid or cert reaches the joined context,
   and today a second `IndexContext` overwrites the first login's sid in the reverse record, so every
   later extension re-stamps only the newest and the first login's entries age out at `index_ttl`
   under a context still authorizing.
8. **The attribution counter increments after the spool accepts the record**, so a refused record —
   answered ERROR and resent by the device — is not counted twice. Name:
   `port49_accounting_attributions_total{attribution}`. No attribution metric existed to reuse.
9. **`PutContext` stays in the interface** with no production caller; tests and seeding use it.

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

Carried from plan 2, and still binding:

- **Every context write outside login goes through a narrow setter**, never a re-put of a record read
  earlier in the request. This plan adds the one whole-record write that is safe — `SwapContext`
  behind `JoinContext` — and nothing else may write a whole context.
- **Every claim about device behaviour cites a `tests/lab/results/` note or a decision log by name.**
  A claim with neither is marked *unmeasured* and the code must not depend on it.
- **No new reason code.** A join is `token_redeemed`; a replace is `token_redeemed` with
  `session.replaced_ctx_id`; an unreadable context is `store_unavailable`.
- Branch `feature/context-join`; never commit code to `main`.
- Every verification runs `make test && make vet` and `go test -race ./internal/...`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

---

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md       MOD  §5.1.1, §5.3, §5.6, §5.8, §13 d15, §15 L1, tests list
docs/design/2026-09-20-login-context-key-options.md MOD  the vEOS concurrent-port correction
docs/superpowers/plans/README.md                    MOD  plan 5 owes the local-account check
internal/store/store.go                MOD  ErrConflict; Context.Rev; Token.MintedAt; SwapContext; docs
internal/store/join.go                 NEW  Joinable, Join, JoinContext, MaxJoinAttempts, JoinResult
internal/store/join_test.go            NEW  the field rules, replace cases, retry bound, memory race
internal/store/storetest/storetest.go  NEW  JoinRacesRevocation: the conformance race, per store
internal/store/memory/memory.go        MOD  revisions; SwapContext; raise-only SetPrivilege; multi-key reverse index
internal/store/memory/memory_test.go   MOD  CAS, revision, reverse-index and raise-only tests
internal/store/crypt/crypt.go          MOD  sealContext; SwapContext
internal/store/crypt/crypt_test.go     MOD  SwapContext seals; race through the sealing layer; SetPrivilege raise
internal/token/minter.go               MOD  MintedAt on every token
internal/token/minter_test.go          MOD  MintedAt test
internal/daemon/authen/authen.go       MOD  pre-read; JoinContext in place of PutContext; loginContext
internal/daemon/authen/authen_test.go  MOD  noStore.SwapContext; join, revocation, replace, unreadable tests
internal/daemon/authen/key_test.go     MOD  the second-login test now joins
internal/daemon/author/author.go       MOD  comment: raise-only
internal/daemon/author/author_test.go  MOD  the lowering test inverted
internal/daemon/author/join_test.go    NEW  test 1, through both handlers
internal/daemon/acct/acct.go           MOD  the attribution counter
internal/daemon/acct/acct_test.go      MOD  counter and system-port tests
internal/daemon/acct/join_test.go      NEW  test 2, through both handlers
internal/daemon/metrics/metrics.go     MOD  port49_accounting_attributions_total{attribution}
internal/daemon/metrics/metrics_test.go MOD registered
internal/session/session.go            MOD  package comment: what the join now contains
```

Nine tasks, nine commits. Tasks 1 and 2 are documentation and come first, as plan 2's spec commit
did: Task 5 lifts a revocation on one path, and `store.Store`'s `RefreshContext` comment says the
§13 decision table has to say so first.

---

### Task 1: The spec — the join, raise-only privilege, the attribution metric, console `root`

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`

**Interfaces:** none; documentation. Every later task cites the sections this one writes.

- [ ] **Step 1: §5.1.1 — the token carries `minted_at`**

Replace:

```
token:(nas, username)    { handle, kind, blob_hash, principal, username,
                           max_session_age, expires, ... }
```

with:

```
token:(nas, username)    { handle, kind, blob_hash, principal, username,
                           max_session_age, minted_at, expires, ... }
```

and after the paragraph that begins "`max_session_age` rides in the token record", add:

```
`minted_at` is when the broker cut the token, on the broker's clock — the clock revocation stamps
`revoked_at` with. It is what decides whether a login may lift a revocation on the context it joins
(§5.6): `auth_time` cannot, because it is when the human authenticated at the IdP, which can be
hours before the mint.
```

In the `ctx:(nas, username)` block, replace the line

```
  privilege         15
```

with

```
  privilege         15                   the HIGHEST level granted on this device (5.3); raise-only
```

- [ ] **Step 2: §5.3 — `ctx.privilege` is raise-only**

In the §5.3 pseudocode, replace the parenthetical under `→ if request level > ctx.privilege`:

```
       (ctx.privilege is the level port49 last GRANTED: the login START's level, then
        the `priv-lvl` a permitted session authorization carried, then an escalation;
        the session-authorization permit records its granted level in place, same
        ctx_id — measured on vEOS the session authorization arrives at priv_lvl 1,
        port49 grants 15, and every later command arrives at 15;
        tests/lab/results/L1-arista_eos.md, L3-arista_eos.md)
```

with:

```
       (ctx.privilege is the HIGHEST level port49 has granted this user on this device:
        the login START's level, raised by the `priv-lvl` a permitted session
        authorization carried and by an escalation, and never lowered — the context
        covers every window of one operator (§5.6), so a second window granted less must
        not take the first window's enable away. It is clamped to the context's ceiling
        (`max_privilege`; zero is none), and it is still a bound: the device cannot
        exceed it without port49 having said yes somewhere. The session-authorization
        permit raises it in place, same ctx_id — measured on vEOS the session
        authorization arrives at priv_lvl 1, port49 grants 15, and every later command
        arrives at 15; tests/lab/results/L1-arista_eos.md, L3-arista_eos.md. The level a
        session authorization REPLIES is policy's answer and never this field.
        Ruled 2026-09-23.)
```

- [ ] **Step 3: §5.6 — the join replaces the overwrite**

Replace the whole paragraph that begins `**One operator, one device, one context.** The accepted cost
of this key` and ends `and can join the older shell's records to the newer ones.` with:

```
**One operator, one device, one context — and a second login joins it.** The context is "this
principal's authorization on this device", not one connection: no wire field on authorization
tells two of one operator's windows apart on every platform — NX-OS sends `port` empty on every
command authorization and Junos never authorizes a command (§15, L1, L18). So a second login by the
same principal under the same username on the same device **joins** the live context rather than
replacing it (ruled 2026-09-23):

| field | on a join |
|---|---|
| `ctx_id` | kept — each `redeem` record still carries its own `credential_sha256` |
| `privilege` | kept; the new login's level only raises it, clamped to the new ceiling (§5.3) |
| `session_discriminators`, `accounting_state` | kept |
| `blob_hash`, `max_privilege`, `enable` | from the newest login — the latest broker decision wins |
| `auth_time`, `session_expires` | the later of the two; no ceiling is later than any time |
| `revoked_at` | kept, unless the new token was minted after it (§5.1.1 `minted_at`; §13, decision 15) |
| credential | the newest; every login is still indexed, so revocation by either login's `sid` or certificate reaches the context |
| `port`, `rem_addr` | the newest (informational) |
| `refreshed_at`, `last_touched_at` | now |

A login is **not** a join, and writes a fresh context whose `redeem` record carries
`session.replaced_ctx_id`, in two cases: the live context belongs to **another principal** under
the same username, or it is **past `session_expires`**. A ceiling ending is not a credential
verified again, so the same principal's `revoked_at` carries across that replace by the rule in the
table. A context the idle TTL has reclaimed is absent, and the login writes a fresh one with nothing
to name. The join is a compare-and-set on the context's revision, so a revocation, an accounting
annotation, a privilege raise or a refresh that lands mid-login is merged rather than erased, and
two simultaneous logins both land. A context port49 cannot read — the store is down, or the record
is sealed under a retired key — cannot be joined: the login is `store_unavailable`, and it is
refused before the token is spent.

What remains of the old cost: both windows log one `ctx_id`, so a log reader tells them apart by
`port`, `rem_addr` and each `redeem` record's `credential_sha256`, not by `ctx_id`.
```

In the teardown table, replace row 1's Authority cell text

```
port49 performed it — overwrites unconditionally, and logs the overwrite (above).
```

with

```
port49 performed it — joins the same principal's live context and replaces another principal's, logging the replace (above).
```

leaving the rest of that cell as it is.

At the end of the paragraph that begins "`session.replaced_ctx_id` is what surfaced it", after
"is **plan 2's work**.", add:

```
The converse — a second login writing `priv_lvl=1` over an enabled context — is closed by the join
above and by raise-only privilege (§5.3), 2026-09-23.
```

- [ ] **Step 4: §5.6 — local accounts and local enable secrets**

Replace the paragraph that begins `**Local account names MUST NOT collide with device-facing
usernames.**` and ends `knows.` with:

```
**Local account names MUST NOT collide with device-facing usernames, and `enable` MUST NOT fall
back to a local secret.** A device-local `bob` that is not the port49 username `bob` matches on
username and inherits the context — and the context holds the highest level port49 has granted
`bob` on that device (§5.3). Every command such a session sends arrives under the same username and
is authorized at that level; so does every command of a port49 `bob` session that reached `enable`
through a local enable secret rather than through port49. The reference AAA configuration MUST
require disjoint namespaces for break-glass and local accounts and MUST NOT put a local fallback on
the enable method list, and port49 SHOULD warn when it observes a local fallback succeed for a
username it knows. The detection that exists is accounting: such a session's exec records carry a
discriminator port49 never saw begin and are attributed `foreign` (§5.8), counted in
`port49_accounting_attributions_total{attribution="foreign"}`. Plan 5's adapters owe a
configuration check that warns when a port49-served username exists as a device-local account.
```

- [ ] **Step 5: §5.8 — the attribution metric, and console `root`**

After the paragraph that ends `or a device-local account shares a principal's name.`, add:

```
Every accounting record the spool accepts is counted in
`port49_accounting_attributions_total{attribution}`, and `foreign` is the series to alert on. The
label is the attribution alone — no device and no user; the decision record carries both. It is not
rate-limited: a burst of `foreign` is itself the signal. A record the spool refused is not counted,
because the device was answered ERROR and will send it again.
```

After the paragraph that ends `and `unattributed` partition every accounting record.`, add:

```
**A console login as `root` on Junos is attributed `system`, and that is a known limitation.**
`root` is on `juniper_junos`'s list because the device's own machinery writes accounting under it
(above), and a person at the console logging in as `root` writes accounting under the same name.
port49 cannot tell the two apart from the record, so both are `system` and neither is `foreign`.
The record keeps the `port` the device sent, which is what lets a log reader see where the session
was. What `port` a Junos console session presents is unmeasured in this lab. Ruled 2026-09-23.
```

- [ ] **Step 6: §13 decision 15 — the accepted cost is now a join**

Replace the paragraph that begins `*The accepted cost, stated plainly.*` and ends `§5.6 requires the
overwrite to be logged so it is at least visible.` with:

```
*The accepted cost, stated plainly.* One user's concurrent sessions on one device share a context.
**Since 2026-09-23 a second login by the same principal joins it** (§5.6, the join table): the
`ctx_id`, the privilege already granted, the bound session discriminators and a revocation the new
token predates are kept, and the newest broker decision supplies the policy blob, the ceiling and
the enable mechanism. The overwrite this paragraph used to accept reset the stored privilege
(window A, enabled to 15, was then denied `privilege_exceeded`), emptied the discriminator set
(window A's STOP became `foreign`), and wiped `revoked_at` (a token minted before a revocation
re-admitted the user). **A join lifts `revoked_at` only when the broker minted the new token after
the revocation** — the credential verified again, which is the one thing that may; a refresh never
does (§5.1.3). Another principal under the same username, or a context past `session_expires`, is
still replaced, and §5.6 requires the replace to be logged. A log reader still cannot tell two
shells apart by `ctx_id`; no wire field distinguishes them on every platform, so this is not fixable
by a better key.
```

- [ ] **Step 7: the test-requirements list**

Replace `- **Context teardown**: a redemption overwrites;` with
`- **Context teardown**: a redemption by the same principal joins the live context and one by
another principal replaces it (§5.6);`, leaving the rest of that bullet as it is.

- [ ] **Step 8: Check nothing else in the spec still says a second login overwrites**

Run: `grep -n "overwrites the first\|overwrite unconditionally\|overwrites unconditionally\|records its granted level" docs/design/2026-08-23-policy-engine-spec.md`
Expected: no output. Any hit is a sentence Steps 2–7 missed; fix it the same way.

- [ ] **Step 9: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: a second login joins the live context; privilege is raise-only

Spec §5.6 replaces the overwrite with the join table, §5.3 makes
ctx.privilege the highest level granted, §5.1.1 adds minted_at, §5.8
adds port49_accounting_attributions_total and documents console root
as a system-attribution limitation, and §13 decision 15 records that
a join lifts revoked_at only for a token minted after it.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: Correct the vEOS concurrent-port claim; the roadmap

**Files:**
- Modify: `docs/design/2026-09-20-login-context-key-options.md`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/superpowers/plans/README.md`

**The claim, and the evidence against it.** The memo and the spec say two concurrent vEOS sessions
both reported `vty4` at authorization. The 2026-09-22 vEOS run's decision log,
`tests/lab/logs/decisions-arista_eos.jsonl`, shows the opposite: `alice02` and `alice03` concurrent
from 15:57:48 to 15:57:55, each on its own vty from `authorize_session` onward, and both on `ssh` at
authentication:

```
15:57:48.801  redeem             alice02  port=ssh   ctx=3RX73MAJFOPPVVK4
15:57:49.002  authorize_session  alice02  port=vty4  ctx=3RX73MAJFOPPVVK4
15:57:53.817  redeem             alice03  port=ssh   ctx=J7AJZEQAQH2V6ARV
15:57:54.020  authorize_session  alice03  port=vty6  ctx=J7AJZEQAQH2V6ARV
15:57:54.988  escalate           alice03  port=vty6
15:57:54.988  escalate           alice02  port=vty4
15:57:55.751  account            alice02  port=vty4
```

`tests/lab/logs/` is git-ignored, so the correction quotes these records inline rather than only
citing the path. The N9Kv half of the claim — `port` `0` at login and at session authorization,
**empty on every command authorization** — stands, and so does the conclusion: no field present at
the authentication START separates two sessions on every platform. Per `CLAUDE.md`'s lab rule 4, the
doc is wrong, it is fixed, and the commit message says so.

**Interfaces:** none; documentation.

- [ ] **Step 1: The memo — a correction note at the top**

In `docs/design/2026-09-20-login-context-key-options.md`, directly after the `**Date:**` paragraph,
add:

```
> **Corrected 2026-09-23.** This memo said two concurrent vEOS sessions both reported `vty4` at
> authorization. The 2026-09-22 vEOS run shows two concurrent sessions on **different** vtys from
> session authorization onward — `alice02` on `vty4`, `alice03` on `vty6`, 15:57:48–15:57:55 — and
> both on `ssh` at authentication (`tests/lab/logs/decisions-arista_eos.jsonl`, git-ignored; the
> records are quoted in §1). The conclusion stands: `ssh` at the authentication START is what the
> context would have to be keyed on, and it separates nothing. The N9Kv observations are unchanged.
```

- [ ] **Step 2: The memo — the EOS table row and the paragraph under it**

Replace the table row

```
| `port` | `ssh` | `ssh` **or** `vty4` | `ssh` | `ssh` or `vty4` | **no** — both concurrent sessions reported `ssh`, then both reported `vty4` |
```

with

```
| `port` | `ssh` | `ssh` **or** `vty<n>` | `ssh` | `ssh` or `vty<n>` | **not at authentication** — both concurrent sessions reported `ssh` there; from session authorization onward each has its own vty (`vty4`, `vty6`; corrected 2026-09-23) |
```

In item 1 under "Two things in that table", replace

```
   and the first exec accounting START, and becomes `vty4` once a vty is allocated. Measured:
   `alice02`, `alice03` and `alice06` each show `ssh` at `redeem` and `vty4` at
   `authorize_session`.
```

with

```
   and the first exec accounting START, and becomes `vty<n>` once a vty is allocated. Measured:
   `alice02`, `alice03` and `alice06` each show `ssh` at `redeem` and a vty at
   `authorize_session`. Two *concurrent* sessions get **different** vtys, stable from
   `authorize_session` onward — the 2026-09-22 run, `tests/lab/logs/decisions-arista_eos.jsonl`:

   | time | event | user | port |
   |---|---|---|---|
   | 15:57:48.801 | redeem | alice02 | `ssh` |
   | 15:57:49.002 | authorize_session | alice02 | `vty4` |
   | 15:57:53.817 | redeem | alice03 | `ssh` |
   | 15:57:54.020 | authorize_session | alice03 | `vty6` |
   | 15:57:54.988 | escalate | alice03 / alice02 | `vty6` / `vty4` |
```

- [ ] **Step 3: The memo — the §1 summary and the worked example**

In "The one-line summary of section 1", replace

```
> empty.** Every session discriminator that exists — Junos `port`/`session_pid`, EOS
> `task_id` — lives only in accounting, which §5.6 row 7 already demotes to advisory and
> which arrives 1.8–4.4 s late on Junos (measured, L6).
```

with

```
> empty.** Every session discriminator that exists — Junos `port`/`session_pid`, EOS
> `task_id` — lives only in accounting, which §5.6 row 7 already demotes to advisory and
> which arrives 1.8–4.4 s late on Junos (measured, L6). EOS's `vty<n>` separates concurrent
> sessions from session authorization onward but is `ssh` at the authentication START that
> would have to write the context (corrected 2026-09-23).
```

In the worked-example table, replace row 7's first cell `bob does the same on leaf1, also `vty4``
with `bob does the same on leaf1, on `vty6` (corrected 2026-09-23; the 2026-09-22 log)`.

- [ ] **Step 4: The spec — §13 decision 15 and §15 L1**

In §13 decision 15, replace

```
the key needed from it: two concurrent vEOS sessions both reported `vty4`, two concurrent
N9Kv sessions both reported `0`, so two operators on one device collided and locked each
other out.
```

with

```
the key needed from it: two concurrent N9Kv sessions both reported `0`, so two operators on one
device collided and locked each other out; and vEOS, which does give two concurrent sessions
different vtys (`vty4`, `vty6`) from session authorization onward, says `ssh` for both at the
authentication START that writes the context. (Corrected 2026-09-23: this sentence said both vEOS
sessions reported `vty4`; `tests/lab/logs/decisions-arista_eos.jsonl`, 2026-09-22 run,
15:57:48–15:57:55.)
```

In §15's L1 entry, replace

```
  Concurrency did not rescue it either. Two overlapping vEOS sessions both reported `vty4` at authorization,
  and two overlapping N9Kv sessions both reported `0` — one denied `username_mismatch`, the other
  `context_missing`.
```

with

```
  Concurrency did not rescue it either. Two overlapping N9Kv sessions both reported `0` — one denied
  `username_mismatch`, the other `context_missing`. (This paragraph also said two overlapping vEOS
  sessions both reported `vty4` at authorization. Corrected 2026-09-23: the 2026-09-22 run shows two
  concurrent vEOS sessions on `vty4` and `vty6`, below.)
```

and replace

```
  still says `ssh` at authentication and `vty<n>` at authorization, and two concurrent sessions still cannot
  be told apart by it — and the outcome is now the opposite.
```

with

```
  still says `ssh` at authentication and `vty<n>` at authorization, so two concurrent sessions cannot be
  told apart by it where the context is written — and the outcome is now the opposite.
```

- [ ] **Step 5: Check nothing else repeats the claim**

Run: `grep -rn "both reported \`vty4\`\|also \`vty4\`\|then both reported" docs/design/`
Expected: no output other than inside the "Corrected 2026-09-23" sentences Steps 1–4 wrote.

- [ ] **Step 6: The roadmap — what plan 5 owes, and what is not planned**

In `docs/superpowers/plans/README.md`, at the end of the "Plan 5 — Platform adapters" section (after
the paragraph that ends `and plan 1 sends none of it.`), add:

```
**Owed from plan 2b (context join):** a configuration check that **warns when a port49-served
username exists as a device-local account** on the device (spec §5.6, "Local account names MUST
NOT collide"). Such an account's commands arrive under the same username and match the port49
context at its highest granted level; `foreign` attribution is the only detection until this check
exists.

**Possible later, not planned:** per-window contexts on the platforms that give a window its own
stable identifier — EOS `vty<n>`, bound at session authorization (the 2026-09-22 vEOS run), and
IOS-XE `tty<n>` (`tests/lab/results/L1-cisco_iosxe.md`). The `(nas, username)` join is the design of
record; this would refine it per platform and needs its own ruling first.
```

- [ ] **Step 7: Commit**

```bash
git add docs/design/2026-09-20-login-context-key-options.md docs/design/2026-08-23-policy-engine-spec.md docs/superpowers/plans/README.md
git commit -m "docs: correct the vEOS concurrent-port claim; roadmap for plan 5

The key-options memo and spec §13 decision 15 / §15 L1 said two
concurrent vEOS sessions both reported vty4. The lab log contradicts
it: tests/lab/logs/decisions-arista_eos.jsonl (2026-09-22 run) has
alice02 on vty4 and alice03 on vty6 concurrently, 15:57:48-55, each
stable from authorize_session on, both ssh at authentication. The
docs were wrong and are fixed; the records are quoted inline because
the log is git-ignored. The N9Kv claim (port 0, empty on command
authz) stands.

The roadmap records the local-account config check plan 5 owes, and
per-window contexts on EOS/IOS-XE as possible later work.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: Every token carries its mint time

**Files:**
- Modify: `internal/store/store.go` (the `Token` struct)
- Modify: `internal/token/minter.go` (`Mint`)
- Test: `internal/token/minter_test.go`

**Interfaces:**
- Produces: `store.Token.MintedAt time.Time`, set by `token.Minter.Mint` to its clock's `now()` on
  every token of a mint (both of a pair). Zero on tokens not cut by the minter, which D1 reads as
  "minted before any revocation". Task 5's `JoinContext` takes it as `mintedAt`; Task 8 passes
  `winner.MintedAt`.

`MintedAt` is plaintext: `crypt`'s `sealToken` seals `Secret`, `Principal`, `Username` and
`Credential` only, so a new field passes through with no change there.

- [ ] **Step 1: Write the failing test**

Append to `internal/token/minter_test.go`:

```go
// Every token carries the moment it was cut, on the minter's clock. A second
// login joining a revoked context keeps the revocation unless the token was
// minted after it (spec §5.6), and AuthTime cannot answer that: it is when the
// human authenticated at the IdP, and a mint an hour later carries the same
// one. Both tokens of a pair carry the same instant.
func TestEveryTokenCarriesItsMintTime(t *testing.T) {
	at := time.Unix(1_757_041_495, 0)
	st := memory.New(func() time.Time { return at })
	m := NewMinter(st, decision.NewJSONLines(&bytes.Buffer{}), rand.Reader, TagKey([]byte("k")), func() time.Time { return at }, 3)
	s := subject()
	s.AuthTime = at.Add(-time.Hour)
	if _, err := m.Mint(context.Background(), Request{Subject: s, Device: "leaf-01", WithEnable: true, TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	c, _ := st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"})
	if len(c) != 2 {
		t.Fatalf("want the pair, got %d", len(c))
	}
	for _, tok := range c {
		if !tok.MintedAt.Equal(at) {
			t.Fatalf("%s token: minted_at %v, want %v (auth_time is %v and must not stand in for it)",
				tok.Kind, tok.MintedAt, at, tok.AuthTime)
		}
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/token/ -run TestEveryTokenCarriesItsMintTime -count=1`
Expected: FAIL to build — `tok.MintedAt undefined (type store.Token has no field or method MintedAt)`.

- [ ] **Step 3: Add the field**

In `internal/store/store.go`, in `type Token struct`, between `AuthTime      time.Time` and the
blank line before `Sealed`, add:

```go
	// MintedAt is when the broker cut this token, on the broker's clock — the
	// clock revocation stamps RevokedAt with. AuthTime cannot stand in for it:
	// that is when the human authenticated at the IdP, which can be hours
	// before a mint, so a token minted after a revocation can carry an
	// AuthTime from before it. JoinContext compares this to a live context's
	// RevokedAt (spec §5.6). Zero reads as "minted before any revocation",
	// which keeps the mark.
	MintedAt time.Time
```

- [ ] **Step 4: Set it in the minter**

In `internal/token/minter.go`, replace

```go
	expires := m.now().Add(ttl)
	res := Result{ExpiresAt: expires, Username: r.Subject.Username}
```

with

```go
	mintedAt := m.now()
	expires := mintedAt.Add(ttl)
	res := Result{ExpiresAt: expires, Username: r.Subject.Username}
```

and in the `store.Token{...}` literal inside `mint`, replace

```go
			Credential: r.Subject.Credential, AuthTime: r.Subject.AuthTime,
```

with

```go
			Credential: r.Subject.Credential, AuthTime: r.Subject.AuthTime, MintedAt: mintedAt,
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/token/ ./internal/store/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/store.go internal/token/minter.go internal/token/minter_test.go
git commit -m "feat: every minted token records when it was minted

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: A context revision, and `SwapContext`

**Files:**
- Modify: `internal/store/store.go`
- Modify: `internal/store/memory/memory.go`
- Modify: `internal/store/crypt/crypt.go`
- Modify: `internal/daemon/authen/authen_test.go` (`noStore` gains the method)
- Test: `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go`

**Interfaces:**
- Produces:
  - `store.ErrConflict` — `errors.New("store: context changed since it was read")`.
  - `store.Context.Rev uint64` — set by `GetContext`; ignored by every writer except as
    `SwapContext`'s comparison.
  - `store.Store.SwapContext(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration) error`
    — writes only if the live record carries `rev` (zero: only if no live record); otherwise
    `ErrConflict` and nothing written. On success, as `PutContext`: expiry now+ttl, `LastTouchedAt`
    stamped, index entries extended.
  - Memory: every write to a context (`PutContext`, `SwapContext`, `TouchContext`, `SetPrivilege`,
    `AnnotateContext`, `RefreshContext`, `SetRevokedAt`) takes a new revision from one store-wide
    counter.
  - Crypt: `SwapContext` seals as `PutContext` does and passes `rev` through.

- [ ] **Step 1: Write the failing memory tests**

Append to `internal/store/memory/memory_test.go`:

```go
// SwapContext is a compare-and-set, and each of its refusals is a state a
// read-merge-write can meet: someone wrote since the read, the record expired
// under it, or a record appeared where the read found none. Every refusal
// writes nothing.
func TestSwapContextIsACompareAndSet(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}

	// Absent: only rev 0 writes.
	if err := s.SwapContext(ctx, k, 7, store.Context{CtxID: "x", Username: "u"}, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a revision for a record that does not exist must conflict: %v", err)
	}
	if err := s.SwapContext(ctx, k, 0, store.Context{CtxID: "a", Username: "u"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	a, _ := s.GetContext(ctx, k)
	if a.CtxID != "a" || a.Rev == 0 {
		t.Fatalf("a written record must carry a revision: %+v", a)
	}

	// Present: rev 0 and a stale revision both conflict, and write nothing.
	if err := s.SwapContext(ctx, k, 0, store.Context{CtxID: "b", Username: "u"}, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rev 0 over a live record must conflict: %v", err)
	}
	if err := s.SwapContext(ctx, k, a.Rev+1, store.Context{CtxID: "b", Username: "u"}, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a revision the record does not carry must conflict: %v", err)
	}
	if got, _ := s.GetContext(ctx, k); got.CtxID != "a" || got.Rev != a.Rev {
		t.Fatalf("a refused swap wrote: %+v", got)
	}

	// The revision it was read at writes, stamps like PutContext, and moves it.
	now = now.Add(30 * time.Second)
	if err := s.SwapContext(ctx, k, a.Rev, store.Context{CtxID: "b", Username: "u", Rev: 12345}, time.Minute); err != nil {
		t.Fatal(err)
	}
	b, _ := s.GetContext(ctx, k)
	if b.CtxID != "b" || b.Rev == a.Rev || b.Rev == 12345 || !b.LastTouchedAt.Equal(now) {
		t.Fatalf("the swap must write, stamp LastTouchedAt, and take a fresh revision whatever the caller passed: %+v", b)
	}

	// Expired: the old revision conflicts; rev 0 writes.
	now = now.Add(2 * time.Minute)
	if err := s.SwapContext(ctx, k, b.Rev, store.Context{CtxID: "c", Username: "u"}, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a revision of an expired record must conflict, not resurrect it: %v", err)
	}
	if err := s.SwapContext(ctx, k, 0, store.Context{CtxID: "c", Username: "u"}, time.Minute); err != nil {
		t.Fatalf("an expired record is absent: %v", err)
	}
	if c, _ := s.GetContext(ctx, k); c.CtxID != "c" || c.Rev <= b.Rev {
		t.Fatalf("a record written again must never repeat a revision: %+v (previous %d)", c, b.Rev)
	}
}

// Every writer moves the revision, the narrow setters included. A setter that
// did not would be a write a read-merge-write cannot see, and SetRevokedAt is
// the one that matters: a join that read before the revocation and swapped
// after it would put back a RevokedAt of zero (store.Context.Rev).
func TestEveryContextWriteMovesTheRevision(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", PrivLvl: 1,
		AuthTime: now, SessionExpires: now.Add(time.Hour)}, time.Hour)
	for _, w := range []struct {
		name  string
		write func() error
	}{
		{"PutContext", func() error { return s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u"}, time.Hour) }},
		{"TouchContext", func() error { return s.TouchContext(ctx, k, time.Hour) }},
		{"SetPrivilege", func() error { return s.SetPrivilege(ctx, k, 15) }},
		{"AnnotateContext", func() error { return s.AnnotateContext(ctx, k, "h", store.AccountingStateOpen) }},
		{"RefreshContext", func() error {
			return s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Hour)
		}},
		{"SetRevokedAt", func() error { return s.SetRevokedAt(ctx, k, now) }},
	} {
		before, _ := s.GetContext(ctx, k)
		if err := w.write(); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		if err := s.SwapContext(ctx, k, before.Rev, before, time.Hour); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("%s did not move the revision: a copy read before it swapped over it (%v)", w.name, err)
		}
	}
}
```

- [ ] **Step 2: Write the failing crypt test**

Append to `internal/store/crypt/crypt_test.go`:

```go
// SwapContext seals exactly what PutContext seals and hands the revision
// through: Rev is plaintext, so the inner store can hold the precondition on a
// record it cannot read, and a revision read through this layer is the one the
// inner store compares.
func TestSwapContextSealsAndKeepsTheRevision(t *testing.T) {
	inner := memory.New(time.Now)
	s := Wrap(inner, keys(), nil)
	ctx := context.Background()
	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	c := store.Context{CtxID: "ctx1", Principal: "user:alice@example.com", Username: "alice",
		Port: "ssh", RemAddr: "198.51.100.4", PrivLvl: 15}
	if err := s.SwapContext(ctx, ck, 0, c, time.Hour); err != nil {
		t.Fatal(err)
	}
	if raw, _ := inner.GetContext(ctx, ck); raw.Principal != "" || raw.RemAddr != "" || raw.CtxID != "" || raw.Sealed == nil {
		t.Fatalf("SwapContext wrote plaintext: %+v", raw)
	}
	got, err := s.GetContext(ctx, ck)
	if err != nil || got.Principal != "user:alice@example.com" || got.Rev == 0 {
		t.Fatalf("%+v %v", got, err)
	}
	// A narrow setter lands between the read and the swap, through this layer.
	if err := s.SetRevokedAt(ctx, ck, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapContext(ctx, ck, got.Rev, got, time.Hour); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a revision read through the sealing layer must be the one the inner store compares: %v", err)
	}
	if after, _ := s.GetContext(ctx, ck); after.RevokedAt.IsZero() {
		t.Fatalf("the refused swap erased the revocation: %+v", after)
	}
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./internal/store/... -count=1`
Expected: FAIL to build — `s.SwapContext undefined`, `store.ErrConflict undefined`, `a.Rev undefined`.

- [ ] **Step 4: The interface — `ErrConflict`, `Rev`, `SwapContext`**

In `internal/store/store.go`, after `var ErrNotFound = errors.New("store: not found")`, add:

```go

// ErrConflict is SwapContext refusing a write because the context is no longer
// the one the caller read: another writer landed in between, or the record
// expired, or one appeared where none was. Nothing was written. The caller
// reads again and decides again; JoinContext is the loop that does.
var ErrConflict = errors.New("store: context changed since it was read")
```

In `type Context struct`, between `CreatedAt    time.Time` and the blank line before `Sealed []byte`,
add:

```go

	// Rev is the store's revision of this record. GetContext sets it and
	// SwapContext compares it; every other writer ignores what the caller
	// passes, and every write to the record — each narrow setter included —
	// moves it. That last part is the point: a read-merge-write that lost a
	// race to SetRevokedAt finds the revision moved and reads again, rather
	// than putting back a copy whose RevokedAt is zero. It is plaintext
	// bookkeeping, like the expiry.
	Rev uint64
```

In `type Store interface`, replace

```go
	PutContext(ctx context.Context, k ContextKey, c Context, ttl time.Duration) error
	GetContext(ctx context.Context, k ContextKey) (Context, error)
```

with

```go
	// PutContext writes c unconditionally. No production path calls it: the
	// login path joins through SwapContext (JoinContext), and every other
	// writer has a narrow setter. It stays for seeding and tests.
	PutContext(ctx context.Context, k ContextKey, c Context, ttl time.Duration) error
	GetContext(ctx context.Context, k ContextKey) (Context, error)
	// SwapContext is PutContext with a precondition: it writes c only if the
	// record at k is still the one the caller read. rev is the Rev GetContext
	// returned; zero means "only if there is no live record". Anything else —
	// a revision that moved, a record that expired, a record that appeared —
	// is ErrConflict, and nothing is written.
	//
	// It is how a whole-record write is made safe against the narrow setters.
	// The login path has to write most of a context (spec §5.6, the join
	// table), and the sealing layer cannot merge fields it cannot read under
	// the inner store's lock, so it reads, merges, and swaps; a revocation,
	// annotation, privilege raise or refresh that landed in between moves the
	// revision and the swap refuses. See JoinContext.
	//
	// On success it behaves as PutContext does: the expiry is now+ttl,
	// LastTouchedAt is stamped, and the context's index entries are extended.
	SwapContext(ctx context.Context, k ContextKey, rev uint64, c Context, ttl time.Duration) error
```

- [ ] **Step 5: Memory — the revision counter and the shared write**

In `internal/store/memory/memory.go`, replace

```go
	writes int // incremented on every write; triggers sweep at sweepEvery
}

type ctxEntry struct {
	c   store.Context
	exp time.Time
}
```

with

```go
	writes int // incremented on every write; triggers sweep at sweepEvery
	// revs is the last context revision handed out. It is store-wide rather
	// than per key so a context that is deleted and written again never
	// repeats a revision an earlier reader holds.
	revs uint64
}

type ctxEntry struct {
	c   store.Context
	exp time.Time
	rev uint64 // store.Context.Rev; see nextRevLocked
}

// nextRevLocked returns a revision no context has held. Every write to a
// context takes one, which is what makes SwapContext's comparison mean "no one
// wrote this record since you read it" (store.Context.Rev).
func (s *Store) nextRevLocked() uint64 {
	s.revs++
	return s.revs
}
```

In `PutContext`, replace everything from `c.LastTouchedAt = now` to the end of the function with:

```go
	s.writeContextLocked(k, c, now, ttl)
	return nil
}

// writeContextLocked is the whole-record write PutContext and SwapContext
// share once SwapContext's precondition has held.
func (s *Store) writeContextLocked(k store.ContextKey, c store.Context, now time.Time, ttl time.Duration) {
	c.LastTouchedAt = now
	c.Rev = 0 // the entry holds the revision; the record's copy is GetContext's to fill
	exp := now.Add(ttl)
	s.contexts[k] = ctxEntry{c: c, exp: exp, rev: s.nextRevLocked()}
	// A re-put is an extension too, so the index entries come with it
	// (design §12). At a first login this is a no-op — the context is written
	// before it is indexed — and it matters when a second login joins or
	// replaces a live context.
	s.extendIndexesLocked(store.ContextRef{NAS: k.NAS, Username: k.Username}, exp)
	s.writes++
	if s.writes%sweepEvery == 0 {
		s.sweepLocked()
	}
}
```

(`PutContext`'s leading comment about stamping `LastTouchedAt` stays where it is, above the call.)

- [ ] **Step 6: Memory — `GetContext` returns the revision; `SwapContext`**

Replace `GetContext`'s final `return e.c, nil` with:

```go
	c := e.c
	c.Rev = e.rev
	return c, nil
}

// SwapContext writes c only if the record at k still carries revision rev, or,
// for rev zero, only if there is no live record (store.Store). The comparison
// and the write are one critical section, which is the whole of what makes it
// a compare-and-set.
func (s *Store) SwapContext(_ context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e, ok := s.contexts[k]
	live := ok && e.exp.After(now)
	if live && e.rev != rev || !live && rev != 0 {
		return store.ErrConflict
	}
	s.writeContextLocked(k, c, now, ttl)
	return nil
```

(the closing `}` of `GetContext` now closes `SwapContext`).

- [ ] **Step 7: Memory — every narrow setter moves the revision**

In each of `TouchContext`, `SetPrivilege`, `AnnotateContext`, `RefreshContext` and `SetRevokedAt`,
insert

```go
	e.rev = s.nextRevLocked()
```

on the line immediately before that function's `s.contexts[k] = e`.

- [ ] **Step 8: Crypt — `sealContext` and `SwapContext`**

In `internal/store/crypt/crypt.go`, replace the whole `PutContext` method with:

```go
func (w *wrapped) sealContext(c store.Context) (store.Context, error) {
	s, err := w.sealJSON(contextSecret{CtxID: c.CtxID, Principal: c.Principal, Username: c.Username,
		Port: c.Port, RemAddr: c.RemAddr, Credential: c.Credential})
	if err != nil {
		return store.Context{}, err
	}
	c.CtxID, c.Principal, c.Username, c.Port, c.RemAddr, c.Credential, c.Sealed =
		"", "", "", "", "", store.Credential{}, s
	return c, nil
}

func (w *wrapped) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	sc, err := w.sealContext(c)
	if err != nil {
		return err
	}
	return w.inner.PutContext(ctx, k, sc, ttl)
}

// SwapContext seals as PutContext does and hands the revision through
// untouched. Rev is plaintext, and that is what lets this layer take part in a
// compare-and-set at all: the inner store compares a revision it can read on a
// record it cannot, so the merge happens up here with the fields open and the
// precondition is enforced down there under its own lock (store.Store).
func (w *wrapped) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
	sc, err := w.sealContext(c)
	if err != nil {
		return err
	}
	return w.inner.SwapContext(ctx, k, rev, sc, ttl)
}
```

`GetContext` needs no change: it copies the inner record, including `Rev`, and replaces only the
sealed fields.

- [ ] **Step 9: The authen test stub**

In `internal/daemon/authen/authen_test.go`, directly after `noStore`'s `PutContext` method, add:

```go
func (noStore) SwapContext(context.Context, store.ContextKey, uint64, store.Context, time.Duration) error {
	panic("store called")
}
```

- [ ] **Step 10: Run the tests**

Run: `go build ./... && go test ./internal/... -count=1 && go vet ./... && go vet -tags lab ./tests/lab/...`
Expected: PASS, and vet clean.

- [ ] **Step 11: Commit**

```bash
git add internal/store/store.go internal/store/memory/memory.go internal/store/memory/memory_test.go \
  internal/store/crypt/crypt.go internal/store/crypt/crypt_test.go internal/daemon/authen/authen_test.go
git commit -m "feat: context revisions and a compare-and-set SwapContext

Every write to a context, the narrow setters included, moves a
store-wide revision; SwapContext writes only at the revision the caller
read. The sealing layer passes the plaintext revision through, so the
merge can happen above it and the precondition below it.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: `JoinContext` — the field rules and the compare-and-set loop

**Files:**
- Create: `internal/store/join.go`
- Create: `internal/store/storetest/storetest.go`
- Test: `internal/store/join_test.go` (new), `internal/store/crypt/crypt_test.go`

**Interfaces:**
- Consumes: `store.Store.SwapContext`, `store.ErrConflict`, `store.Context.Rev` (Task 4).
- Produces:
  - `const store.MaxJoinAttempts = 8`
  - `type store.JoinResult struct { Context Context; Joined bool; Replaced string }`
  - `func store.Joinable(live, login Context, now time.Time) bool` — same principal and not past
    `SessionExpires`.
  - `func store.Join(live, login Context, mintedAt time.Time) Context` — D1's field rules; pure.
  - `func store.JoinContext(ctx context.Context, s Store, k ContextKey, login Context, mintedAt, now time.Time, ttl time.Duration) (JoinResult, error)`
    — read, decide, swap on the revision read; retry on `ErrConflict` up to `MaxJoinAttempts`, then
    return an error wrapping `ErrConflict`. Any other read or swap error is returned as it is.
  - `func storetest.JoinRacesRevocation(t *testing.T, newStore func() store.Store, now time.Time)` —
    decision test 4, for any store.

- [ ] **Step 1: Write the conformance race**

Create `internal/store/storetest/storetest.go`:

```go
// Package storetest holds store.Store properties every implementation must
// have, written once and run against each: the memory store and the sealing
// layer over it today, a networked backend later. It is imported only by
// tests.
package storetest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// JoinRacesRevocation runs logins joining one live context concurrently with a
// revocation of it, many rounds over, and checks that nothing is lost: the
// revocation stands, because every token was minted before it; every login
// landed, because the kept privilege and auth_time are the highest any of them
// carried; and the ctx_id is the one the context was created with.
//
// newStore returns a fresh store per round. now is the fixed time the store's
// clock must return.
//
// joiners is MaxJoinAttempts-2, and that is not arbitrary: a swap is refused
// only when another writer's write landed, each of the other joiners and the
// revoker writes exactly once, so no join here can be refused MaxJoinAttempts
// times. A failure is therefore a lost write, never a starved loop.
func JoinRacesRevocation(t *testing.T, newStore func() store.Store, now time.Time) {
	t.Helper()
	const rounds = 200
	const joiners = store.MaxJoinAttempts - 2
	const principal = "user:alice@example.com"
	k := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	mintedAt := now.Add(-time.Minute)
	for round := 0; round < rounds; round++ {
		s := newStore()
		ctx := context.Background()
		if err := s.PutContext(ctx, k, store.Context{CtxID: "ctx_first", Principal: principal, Username: "alice",
			PrivLvl: 1, AuthTime: now.Add(-time.Hour), RefreshedAt: now.Add(-time.Hour)}, time.Hour); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, joiners+1)
		var wg sync.WaitGroup
		for i := 1; i <= joiners; i++ {
			login := store.Context{CtxID: fmt.Sprintf("ctx_login_%d", i), Principal: principal, Username: "alice",
				PrivLvl: uint8(i), AuthTime: now.Add(time.Duration(i) * time.Second), RefreshedAt: now}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := store.JoinContext(ctx, s, k, login, mintedAt, now, time.Hour)
				errs <- err
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.SetRevokedAt(ctx, k, now)
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		got, err := s.GetContext(ctx, k)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if !got.RevokedAt.Equal(now) {
			t.Fatalf("round %d: a join erased the revocation: %+v", round, got)
		}
		if got.PrivLvl != joiners || !got.AuthTime.Equal(now.Add(joiners*time.Second)) {
			t.Fatalf("round %d: a login was lost — privilege %d, auth_time %v, want %d and %v",
				round, got.PrivLvl, got.AuthTime, joiners, now.Add(joiners*time.Second))
		}
		if got.CtxID != "ctx_first" {
			t.Fatalf("round %d: a join replaced the ctx_id: %+v", round, got)
		}
	}
}
```

- [ ] **Step 2: Write the failing unit tests**

Create `internal/store/join_test.go`:

```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/store/storetest"
)

var t0 = time.Unix(1_757_041_495, 0)

// live is window A's context as it stands when window B logs in: enabled to
// 15, one session bound by accounting, and an older broker decision.
func live() store.Context {
	return store.Context{CtxID: "ctxA", Principal: "user:alice@example.com", Username: "alice",
		Port: "ssh", RemAddr: "198.51.100.4", PrivLvl: 15, BlobHash: "sha256:old",
		Credential: store.Credential{Method: "oidc", Sid: "sid-A"},
		AuthTime:   t0.Add(-2 * time.Hour), SessionExpires: t0.Add(6 * time.Hour),
		RefreshedAt: t0.Add(-time.Hour), LastTouchedAt: t0.Add(-time.Minute),
		SessionDiscriminators: []string{store.HashDiscriminator("42")}, AccountingState: store.AccountingStateOpen,
		Enable: "token", MaxPrivilege: 15, CreatedAt: t0.Add(-2 * time.Hour), Rev: 9}
}

// login is window B's context as the login path builds it on its own.
func login() store.Context {
	return store.Context{CtxID: "ctxB", Principal: "user:alice@example.com", Username: "alice",
		Port: "vty6", RemAddr: "198.51.100.9", PrivLvl: 1, BlobHash: "sha256:new",
		Credential: store.Credential{Method: "oidc", Sid: "sid-B"},
		AuthTime:   t0.Add(-10 * time.Minute), SessionExpires: t0.Add(7*time.Hour + 50*time.Minute),
		RefreshedAt: t0, LastTouchedAt: t0, Enable: "auto", MaxPrivilege: 15, CreatedAt: t0}
}

// The join table of spec §5.6, one row per field.
func TestJoinFieldRules(t *testing.T) {
	got := store.Join(live(), login(), t0)
	for _, c := range []struct {
		field string
		ok    bool
	}{
		{"ctx_id kept", got.CtxID == "ctxA"},
		{"principal and username kept", got.Principal == "user:alice@example.com" && got.Username == "alice"},
		{"privilege kept: the login's 1 does not lower window A's 15", got.PrivLvl == 15},
		{"session discriminators kept", len(got.SessionDiscriminators) == 1 && got.SessionDiscriminators[0] == store.HashDiscriminator("42")},
		{"accounting state kept", got.AccountingState == store.AccountingStateOpen},
		{"created_at kept", got.CreatedAt.Equal(t0.Add(-2 * time.Hour))},
		{"blob hash from the newest login", got.BlobHash == "sha256:new"},
		{"enable from the newest login", got.Enable == "auto"},
		{"credential from the newest login", got.Credential.Sid == "sid-B"},
		{"port and rem_addr from the newest login", got.Port == "vty6" && got.RemAddr == "198.51.100.9"},
		{"auth_time is the later", got.AuthTime.Equal(t0.Add(-10 * time.Minute))},
		{"session_expires is the later", got.SessionExpires.Equal(t0.Add(7*time.Hour + 50*time.Minute))},
		{"refreshed_at and last_touched_at are now", got.RefreshedAt.Equal(t0) && got.LastTouchedAt.Equal(t0)},
		{"no revocation to carry", got.RevokedAt.IsZero()},
		{"the revision is the store's, not the merge's", got.Rev == 0},
	} {
		if !c.ok {
			t.Errorf("%s: %+v", c.field, got)
		}
	}
}

// The login's level raises, and the result is bounded by the newest ceiling —
// SetPrivilege's rule (spec §5.3). Zero MaxPrivilege is no ceiling.
func TestJoinPrivilegeIsRaiseOnlyAndClamped(t *testing.T) {
	for _, tt := range []struct {
		name            string
		held, in, limit uint8
		want            uint8
	}{
		{"a lower login keeps the held level", 15, 1, 15, 15},
		{"a higher login raises it", 1, 15, 15, 15},
		{"a lowered ceiling bounds what is kept", 15, 1, 7, 7},
		{"no ceiling bounds nothing", 15, 1, 0, 15},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l, n := live(), login()
			l.PrivLvl, n.PrivLvl, n.MaxPrivilege = tt.held, tt.in, tt.limit
			if got := store.Join(l, n, t0).PrivLvl; got != tt.want {
				t.Fatalf("privilege %d, want %d", got, tt.want)
			}
		})
	}
}

// Zero session_expires is "no ceiling", which is later than any time.
func TestJoinNeverAddsACeiling(t *testing.T) {
	l, n := live(), login()
	n.SessionExpires = time.Time{}
	if got := store.Join(l, n, t0); !got.SessionExpires.IsZero() {
		t.Fatalf("a login with no ceiling must leave none: %v", got.SessionExpires)
	}
	l, n = live(), login()
	l.SessionExpires = time.Time{}
	if got := store.Join(l, n, t0); !got.SessionExpires.IsZero() {
		t.Fatalf("a context with no ceiling must not gain one: %v", got.SessionExpires)
	}
}

// A token minted before the revocation is what the revocation was meant to
// stop; one minted after it is the broker having verified the credential again
// (spec §13, decision 15). A zero MintedAt reads as before.
func TestJoinKeepsARevocationUnlessMintedAfterIt(t *testing.T) {
	revokedAt := t0.Add(-5 * time.Minute)
	for _, tt := range []struct {
		name     string
		mintedAt time.Time
		kept     bool
	}{
		{"minted before", revokedAt.Add(-time.Minute), true},
		{"minted at the same instant", revokedAt, true},
		{"no mint time recorded", time.Time{}, true},
		{"minted after", revokedAt.Add(time.Minute), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l := live()
			l.RevokedAt = revokedAt
			got := store.Join(l, login(), tt.mintedAt)
			if kept := !got.RevokedAt.IsZero(); kept != tt.kept {
				t.Fatalf("revoked_at %v, kept %v, want kept %v", got.RevokedAt, kept, tt.kept)
			}
		})
	}
}

func TestJoinable(t *testing.T) {
	other := login()
	other.Principal = "user:alice@corp.example"
	past := live()
	past.SessionExpires = t0.Add(-time.Second)
	never := live()
	never.SessionExpires = time.Time{}
	for _, tt := range []struct {
		name     string
		live, in store.Context
		joinable bool
	}{
		{"same principal, inside the ceiling", live(), login(), true},
		{"same principal, no ceiling", never, login(), true},
		{"another principal under the same username", live(), other, false},
		{"past session_expires", past, login(), false},
	} {
		if got := store.Joinable(tt.live, tt.in, t0); got != tt.joinable {
			t.Errorf("%s: joinable %v, want %v", tt.name, got, tt.joinable)
		}
	}
}

func newMemory() *memory.Store { return memory.New(func() time.Time { return t0 }) }

var ck = store.ContextKey{NAS: "leaf-01", Username: "alice"}

func TestJoinContextOnAnEmptyKeyWritesTheLogin(t *testing.T) {
	s := newMemory()
	res, err := store.JoinContext(context.Background(), s, ck, login(), t0, t0, time.Hour)
	if err != nil || res.Joined || res.Replaced != "" || res.Context.CtxID != "ctxB" {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := s.GetContext(context.Background(), ck); got.CtxID != "ctxB" || got.PrivLvl != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestJoinContextJoinsTheSamePrincipal(t *testing.T) {
	s := newMemory()
	s.PutContext(context.Background(), ck, live(), time.Hour)
	res, err := store.JoinContext(context.Background(), s, ck, login(), t0, t0, time.Hour)
	if err != nil || !res.Joined || res.Replaced != "" || res.Context.CtxID != "ctxA" {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := s.GetContext(context.Background(), ck); got.CtxID != "ctxA" || got.PrivLvl != 15 || got.BlobHash != "sha256:new" {
		t.Fatalf("%+v", got)
	}
}

// Another principal under the same username is not this operator's second
// window: it replaces, and names what it replaced.
func TestJoinContextReplacesAnotherPrincipal(t *testing.T) {
	s := newMemory()
	l := live()
	l.RevokedAt = t0.Add(-time.Minute)
	s.PutContext(context.Background(), ck, l, time.Hour)
	n := login()
	n.Principal = "user:alice@corp.example"
	res, err := store.JoinContext(context.Background(), s, ck, n, time.Time{}, t0, time.Hour)
	if err != nil || res.Joined || res.Replaced != "ctxA" {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := s.GetContext(context.Background(), ck)
	if got.CtxID != "ctxB" || got.Principal != "user:alice@corp.example" || got.PrivLvl != 1 ||
		len(got.SessionDiscriminators) != 0 || !got.RevokedAt.IsZero() {
		t.Fatalf("another principal's login must start clean: %+v", got)
	}
}

// Past its ceiling the context is replaced, not joined — but a ceiling ending
// is not a credential verified again, so the same principal's revocation
// carries by the join's own rule.
func TestJoinContextReplacesPastTheCeilingAndCarriesTheRevocation(t *testing.T) {
	s := newMemory()
	l := live()
	l.SessionExpires = t0.Add(-time.Second)
	l.RevokedAt = t0.Add(-time.Minute)
	s.PutContext(context.Background(), ck, l, time.Hour)
	res, err := store.JoinContext(context.Background(), s, ck, login(), t0.Add(-2*time.Minute), t0, time.Hour)
	if err != nil || res.Joined || res.Replaced != "ctxA" {
		t.Fatalf("%+v %v", res, err)
	}
	got, _ := s.GetContext(context.Background(), ck)
	if got.CtxID != "ctxB" || got.PrivLvl != 1 || !got.RevokedAt.Equal(t0.Add(-time.Minute)) {
		t.Fatalf("%+v", got)
	}
}

// alwaysConflicts refuses every swap, which is what a context written to
// faster than a login can merge looks like from inside JoinContext.
type alwaysConflicts struct {
	*memory.Store
	swaps int
}

func (a *alwaysConflicts) SwapContext(context.Context, store.ContextKey, uint64, store.Context, time.Duration) error {
	a.swaps++
	return store.ErrConflict
}

func TestJoinContextGivesUpAfterMaxJoinAttempts(t *testing.T) {
	s := &alwaysConflicts{Store: newMemory()}
	_, err := store.JoinContext(context.Background(), s, ck, login(), t0, t0, time.Hour)
	if !errors.Is(err, store.ErrConflict) || s.swaps != store.MaxJoinAttempts {
		t.Fatalf("want ErrConflict after %d swaps, got %v after %d", store.MaxJoinAttempts, err, s.swaps)
	}
}

// storeFails answers the read with an error that is not ErrNotFound — a store
// that is down, or a record the sealing layer cannot open.
type storeFails struct{ *memory.Store }

func (storeFails) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	return store.Context{}, errors.New("store down")
}

func TestJoinContextDoesNotWriteBlindOverAReadError(t *testing.T) {
	s := storeFails{newMemory()}
	s.Store.PutContext(context.Background(), ck, live(), time.Hour)
	if _, err := store.JoinContext(context.Background(), s, ck, login(), t0, t0, time.Hour); err == nil {
		t.Fatal("a context that cannot be read must not be replaced")
	}
	if got, _ := s.Store.GetContext(context.Background(), ck); got.CtxID != "ctxA" {
		t.Fatalf("%+v", got)
	}
}

func TestJoinRacesRevocationOnTheMemoryStore(t *testing.T) {
	storetest.JoinRacesRevocation(t, func() store.Store { return newMemory() }, t0)
}
```

Append to `internal/store/crypt/crypt_test.go`, and add
`"github.com/rhwendt/port49/internal/store/storetest"` to its imports:

```go
// The join's merge happens up here, with the sealed fields open, and the
// precondition is held down in the inner store: the property has to survive
// that split, so it is run against the wrapped store as well as the bare one.
func TestJoinRacesRevocationThroughTheSealingLayer(t *testing.T) {
	now := time.Unix(1_757_041_495, 0)
	storetest.JoinRacesRevocation(t, func() store.Store {
		return Wrap(memory.New(func() time.Time { return now }), keys(), nil)
	}, now)
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./internal/store/... -count=1`
Expected: FAIL to build — `undefined: store.Join`, `store.JoinContext`, `store.MaxJoinAttempts`.

- [ ] **Step 4: Implement**

Create `internal/store/join.go`:

```go
package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// MaxJoinAttempts bounds JoinContext's read-merge-swap loop. A swap is refused
// only when another write to the same context landed between the read and the
// swap, so the bound is on concurrent writers to one operator's context on one
// device — a login racing a touch, an annotation, a privilege raise, a refresh,
// a revocation, or another login — not on time. Eight is several times what a
// human operator produces; running out is ERROR on the login, never a guess.
const MaxJoinAttempts = 8

// JoinResult is what JoinContext wrote, and why.
type JoinResult struct {
	// Context is the record as written (the store stamps LastTouchedAt on its
	// own copy). Its CtxID is the one to log: the live context's on a join,
	// the login's own otherwise.
	Context Context
	// Joined is true when the login merged into a live context of the same
	// principal.
	Joined bool
	// Replaced is the ctx_id of a live context this login overwrote rather
	// than joined — another principal's, or one past its session ceiling.
	// Empty on a join and on a first login. It is what the redeem record
	// carries as session.replaced_ctx_id (spec §5.6).
	Replaced string
}

// Joinable reports whether a login may join the live context rather than
// replace it (spec §5.6): the same principal, and a context not past its
// session ceiling. A context past session_expires is over, whatever else it
// holds, and a login does not extend it; it starts a new one.
func Joinable(live, login Context, now time.Time) bool {
	if live.Principal != login.Principal {
		return false
	}
	return live.SessionExpires.IsZero() || !now.After(live.SessionExpires)
}

// Join merges a login into the live context it may join, by the field rules of
// spec §5.6. The context is "this principal's authorization on this device",
// not one connection, so a second window adds to it and takes nothing away
// from the first: the ctx_id, the privilege already granted, the session
// discriminators and the accounting state are kept. What the newest broker
// decision says — the policy blob, the ceiling, the enable mechanism, the
// credential — comes from the login. The clock fields take the later of the
// two. mintedAt is the login token's store.Token.MintedAt.
func Join(live, login Context, mintedAt time.Time) Context {
	out := live
	out.Port, out.RemAddr = login.Port, login.RemAddr
	out.BlobHash, out.MaxPrivilege, out.Enable = login.BlobHash, login.MaxPrivilege, login.Enable
	out.Credential = login.Credential
	out.AuthTime = later(live.AuthTime, login.AuthTime)
	out.SessionExpires = laterCeiling(live.SessionExpires, login.SessionExpires)
	out.RefreshedAt = login.RefreshedAt
	out.LastTouchedAt = login.LastTouchedAt
	// The login's level only ever raises what is held, and the result is
	// bounded by the ceiling the newest login carries — the same rule
	// SetPrivilege applies (spec §5.3).
	if login.PrivLvl > out.PrivLvl {
		out.PrivLvl = login.PrivLvl
	}
	if ceiling, ok := out.PrivilegeCeiling(); ok && out.PrivLvl > ceiling {
		out.PrivLvl = ceiling
	}
	out.RevokedAt = carryRevocation(live.RevokedAt, mintedAt)
	out.SessionDiscriminators = append([]string(nil), live.SessionDiscriminators...)
	out.Rev = 0
	return out
}

// carryRevocation keeps a revocation unless the token being redeemed was
// minted after it. A token cut before the revocation is exactly what the
// revocation was meant to stop, so it must not lift the mark; a token cut after
// it is the broker having verified the credential again, which is the one thing
// that may (spec §13, decision 15).
func carryRevocation(revokedAt, mintedAt time.Time) time.Time {
	if revokedAt.IsZero() || mintedAt.After(revokedAt) {
		return time.Time{}
	}
	return revokedAt
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// laterCeiling is later for session_expires, where zero is "no ceiling" and so
// is later than any time: a join never gives a context a ceiling that neither
// login's policy would impose on its own.
func laterCeiling(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	return later(a, b)
}

// JoinContext writes a login's context at k: a join into the live context when
// Joinable says it may, the login itself otherwise (spec §5.6). It reads,
// decides, and swaps on the revision it read, retrying from the read when the
// swap is refused, so a write that lands in between — SetRevokedAt above all —
// is merged rather than erased, and two concurrent logins both land in one
// context instead of one overwriting the other.
//
// login is the context this login would create on its own, CtxID included.
// A replace of the same principal's context past its ceiling carries the
// revocation by the same rule a join does: a session ceiling ending is not a
// credential being verified again.
//
// A store error other than a refused swap is returned as it is, and a record
// the sealing layer cannot open is one of those: a context port49 cannot read
// cannot be merged, and replacing it blind could erase a revocation.
func JoinContext(ctx context.Context, s Store, k ContextKey, login Context, mintedAt, now time.Time, ttl time.Duration) (JoinResult, error) {
	for attempt := 0; attempt < MaxJoinAttempts; attempt++ {
		live, err := s.GetContext(ctx, k)
		var res JoinResult
		var rev uint64
		switch {
		case errors.Is(err, ErrNotFound):
			res.Context = login
		case err != nil:
			return JoinResult{}, err
		case Joinable(live, login, now):
			res = JoinResult{Context: Join(live, login, mintedAt), Joined: true}
			rev = live.Rev
		default:
			res = JoinResult{Context: login, Replaced: live.CtxID}
			if live.Principal == login.Principal {
				res.Context.RevokedAt = carryRevocation(live.RevokedAt, mintedAt)
			}
			rev = live.Rev
		}
		switch err := s.SwapContext(ctx, k, rev, res.Context, ttl); {
		case err == nil:
			return res, nil
		case !errors.Is(err, ErrConflict):
			return JoinResult{}, err
		}
	}
	return JoinResult{}, fmt.Errorf("store: context still changing after %d attempts: %w", MaxJoinAttempts, ErrConflict)
}
```

- [ ] **Step 5: Run the tests, with the race detector**

Run: `go test -race ./internal/store/... -count=1`
Expected: PASS for `internal/store`, `internal/store/crypt`, `internal/store/memory`.

- [ ] **Step 6: Prove the race test can fail**

The race test is only worth having if it catches the bug it exists for. Temporarily replace, in
`internal/store/join.go`,

```go
		switch err := s.SwapContext(ctx, k, rev, res.Context, ttl); {
```

with

```go
		_ = rev
		switch err := s.PutContext(ctx, k, res.Context, ttl); {
```

Run: `go test ./internal/store/ -run TestJoinRacesRevocationOnTheMemoryStore -count=1`
Expected: FAIL — `a login was lost` or `a join erased the revocation` within the 200 rounds.
Undo the two lines by hand (the file is new and untracked, so `git checkout` cannot restore it) and
re-run Step 5. Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/store/join.go internal/store/join_test.go internal/store/storetest/storetest.go internal/store/crypt/crypt_test.go
git commit -m "feat: JoinContext merges a login into the live context by compare-and-set

The field rules of spec §5.6's join table, and a read-merge-swap loop
bounded at MaxJoinAttempts. storetest.JoinRacesRevocation runs joins
against each other and against SetRevokedAt on the memory store and
through the sealing layer: no lost revocation, no lost login.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: The memory store's reverse index keeps every login's sid and cert

**Files:**
- Modify: `internal/store/memory/memory.go` (`indexKeys`, `sweepLocked`, `extendIndexesLocked`,
  `IndexContext`, `UnindexContext`, `ReindexSid`)
- Test: `internal/store/memory/memory_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature change. Behaviour: a ref indexed under several sids or certs is extended
  under all of them; `UnindexContext` and `ReindexSid` remove only the key they name.

D1 promises that revocation by either login's sid or certificate reaches a joined context. The
indexes themselves already hold both entries — `IndexContext` adds to `bySid` and `byCert` — but the
reverse record `indexedAs` holds one sid and one cert, so the second login's `IndexContext`
overwrites the first's there, and from then on every extension re-stamps only the newest. The first
login's entries expire at `index_ttl` under a context that is still authorizing, and a back-channel
logout for that sid reports zero contexts touched — design §12's dangerous direction.

- [ ] **Step 1: Write the failing test**

Append to `internal/store/memory/memory_test.go`:

```go
// A context a second login joined is indexed under both logins' credentials,
// and revocation by either has to reach it for as long as it lives (spec §5.6).
// The reverse record used to hold one sid and one cert, so the second
// IndexContext overwrote the first login's and every extension after it
// re-stamped only the newest: the first login's entries aged out at index_ttl
// under a context still authorizing, and a back-channel logout for that sid
// reported zero contexts.
func TestExtendingCarriesEveryJoinedLoginsSidAndCert(t *testing.T) {
	now := time.Unix(1000, 0)
	s := New(func() time.Time { return now })
	ctx := context.Background()
	k := store.ContextKey{NAS: "n", Username: "u"}
	ref := store.ContextRef{NAS: "n", Username: "u"}
	certA, certB := store.CertKey("ca", "01"), store.CertKey("ca", "02")
	s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u"}, time.Minute)
	if err := s.IndexContext(ctx, "user:alice", "sA", certA, ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:alice", "sB", certB, ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		now = now.Add(30 * time.Second)
		if err := s.TouchContext(ctx, k, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		get  func() ([]store.ContextRef, error)
	}{
		{"first login's sid", func() ([]store.ContextRef, error) { return s.ContextsBySid(ctx, "sA") }},
		{"second login's sid", func() ([]store.ContextRef, error) { return s.ContextsBySid(ctx, "sB") }},
		{"first login's cert", func() ([]store.ContextRef, error) { return s.ContextsByCert(ctx, certA) }},
		{"second login's cert", func() ([]store.ContextRef, error) { return s.ContextsByCert(ctx, certB) }},
	} {
		if refs, err := tc.get(); err != nil || len(refs) != 1 {
			t.Fatalf("%s aged out under a live context: %v %v", tc.name, refs, err)
		}
	}

	// Unindexing one login's keys leaves the other's reaching the context.
	if err := s.UnindexContext(ctx, "", "sA", certA, ref); err != nil {
		t.Fatal(err)
	}
	now = now.Add(45 * time.Second)
	if err := s.TouchContext(ctx, k, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	if refs, _ := s.ContextsBySid(ctx, "sA"); len(refs) != 0 {
		t.Fatalf("an extension resurrected an unindexed sid: %v", refs)
	}
	if refs, _ := s.ContextsBySid(ctx, "sB"); len(refs) != 1 {
		t.Fatalf("unindexing one login's sid lost the other's: %v", refs)
	}
	if refs, _ := s.ContextsByCert(ctx, certB); len(refs) != 1 {
		t.Fatalf("unindexing one login's cert lost the other's: %v", refs)
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/store/memory/ -run TestExtendingCarriesEveryJoinedLoginsSidAndCert -count=1`
Expected: FAIL — `first login's sid aged out under a live context: [] <nil>`.

- [ ] **Step 3: `indexKeys` holds lists**

In `internal/store/memory/memory.go`, replace the `indexKeys` type and its comment with:

```go
// indexKeys is the set of index keys one ref was written under. An empty
// principal means that index was never written for this ref — the same "" that
// IndexContext reads as "skip this index".
//
// sids and certKeys are lists, not single values, because a context is
// joined: a second login by the same principal on the same device merges into
// the live context (spec §5.6), and each login is indexed under its own sid
// and certificate. Revocation by either has to keep reaching the context for
// as long as it lives, so an extension re-stamps every one of them. They are
// short — one entry per distinct credential that logged in — and the sweep
// drops an entry once its index entry is gone.
type indexKeys struct {
	principal string
	sids      []string
	certKeys  []string
}

func (r indexKeys) empty() bool { return r.principal == "" && len(r.sids) == 0 && len(r.certKeys) == 0 }

// withKey appends key if it is non-empty and not already present. It copies,
// for the reason addDiscriminator does.
func withKey(keys []string, key string) []string {
	if key == "" {
		return keys
	}
	for _, k := range keys {
		if k == key {
			return keys
		}
	}
	return append(append([]string(nil), keys...), key)
}

// withoutKey drops key, copying.
func withoutKey(keys []string, key string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != key {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
```

- [ ] **Step 4: The sweep prunes per key**

In `sweepLocked`, replace the final loop

```go
	for ref, rec := range s.indexedAs {
		if !indexed(s.byPrincipal, rec.principal, ref) &&
			!indexed(s.bySid, rec.sid, ref) &&
			!indexed(s.byCert, rec.certKey, ref) {
			delete(s.indexedAs, ref)
		}
	}
}
```

with

```go
	for ref, rec := range s.indexedAs {
		if !indexed(s.byPrincipal, rec.principal, ref) {
			rec.principal = ""
		}
		rec.sids = stillIndexed(s.bySid, rec.sids, ref)
		rec.certKeys = stillIndexed(s.byCert, rec.certKeys, ref)
		if rec.empty() {
			delete(s.indexedAs, ref)
		} else {
			s.indexedAs[ref] = rec
		}
	}
}

// stillIndexed keeps the keys under which idx still holds ref.
func stillIndexed(idx map[string]map[store.ContextRef]time.Time, keys []string, ref store.ContextRef) []string {
	var out []string
	for _, k := range keys {
		if indexed(idx, k, ref) {
			out = append(out, k)
		}
	}
	return out
}
```

- [ ] **Step 5: Extension, indexing, unindexing, and rotation**

In `extendIndexesLocked`, replace

```go
	restamp(s.bySid, rec.sid, ref, exp)
	restamp(s.byCert, rec.certKey, ref, exp)
```

with

```go
	for _, sid := range rec.sids {
		restamp(s.bySid, sid, ref, exp)
	}
	for _, certKey := range rec.certKeys {
		restamp(s.byCert, certKey, ref, exp)
	}
```

In `IndexContext`, replace the comment and block from `// Record where this ref now answers from`
through `s.indexedAs[ref] = rec` with:

```go
	// Record where this ref now answers from, so an extension of its context
	// can carry these entries with it (extendIndexesLocked). A sid or cert is
	// added to what was recorded, never swapped for it: a joined context
	// answers under every login's credential (indexKeys). An empty key leaves
	// the record alone, matching the "" this method already reads as "skip
	// this index".
	rec := s.indexedAs[ref]
	if principal != "" {
		rec.principal = principal
	}
	rec.sids = withKey(rec.sids, sid)
	rec.certKeys = withKey(rec.certKeys, certKey)
	s.indexedAs[ref] = rec
```

In `UnindexContext`, replace

```go
		if rec.sid == sid {
			rec.sid = ""
		}
		if rec.certKey == certKey {
			rec.certKey = ""
		}
		if rec == (indexKeys{}) {
```

with

```go
		rec.sids = withoutKey(rec.sids, sid)
		rec.certKeys = withoutKey(rec.certKeys, certKey)
		if rec.empty() {
```

In `ReindexSid`, replace

```go
	if newSid != "" {
		rec := s.indexedAs[ref]
		rec.sid = newSid
		s.indexedAs[ref] = rec
	}
```

with

```go
	if rec, ok := s.indexedAs[ref]; ok || newSid != "" {
		rec.sids = withKey(withoutKey(rec.sids, oldSid), newSid)
		if rec.empty() {
			delete(s.indexedAs, ref)
		} else {
			s.indexedAs[ref] = rec
		}
	}
```

- [ ] **Step 6: Run the tests**

Run: `go test -race ./internal/store/... ./internal/session/ -count=1 && go vet ./internal/store/...`
Expected: PASS — including the existing `TestExtendingAContextCarriesItsIndexEntries`,
`TestExtendingNeverShortensOrCreatesAnIndexEntry` and `TestExtendingFollowsARotatedSid`.

- [ ] **Step 7: Commit**

```bash
git add internal/store/memory/memory.go internal/store/memory/memory_test.go
git commit -m "fix: extending a context carries every login's sid and cert index entries

A joined context is indexed under each login's credential; the reverse
record held only the last, so the first login's entries aged out under
a live context and revocation by that sid found nothing.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: Stored privilege is raise-only

**Files:**
- Modify: `internal/store/store.go` (`SetPrivilege`'s comment)
- Modify: `internal/store/memory/memory.go` (`SetPrivilege`)
- Modify: `internal/daemon/author/author.go` (comment only)
- Test: `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go`,
  `internal/daemon/author/author_test.go`

**Interfaces:**
- Consumes: `store.Context.PrivilegeCeiling()` (plan 2).
- Produces: no signature change. `SetPrivilege(ctx, k, level)` stores
  min(max(current, level), ceiling) — the ceiling read under the lock, so a join that lowered it
  since the caller's read is honoured. `crypt.SetPrivilege` stays a pass-through.

`author.Handle` keeps its own clamp before the call (it reads the same helper, so the two cannot
drift); the store's clamp is the one that sees the ceiling as it is now.

- [ ] **Step 1: Write the failing store test**

Append to `internal/store/memory/memory_test.go`:

```go
// The stored level is the highest port49 has granted this user on this device,
// bounded by the ceiling (spec §5.3). A second window's session authorization
// granting a lower level must not take window A's enable away, and zero
// MaxPrivilege is no ceiling (store.Context.PrivilegeCeiling).
func TestSetPrivilegeIsRaiseOnlyAndClamped(t *testing.T) {
	for _, tt := range []struct {
		name             string
		held, max, level uint8
		want             uint8
	}{
		{"a raise is recorded", 1, 15, 15, 15},
		{"a lower grant keeps the held level", 15, 15, 1, 15},
		{"a raise past the ceiling stops at it", 1, 7, 15, 7},
		{"no ceiling bounds nothing", 1, 0, 15, 15},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New(time.Now)
			ctx := context.Background()
			k := store.ContextKey{NAS: "n", Username: "u"}
			s.PutContext(ctx, k, store.Context{CtxID: "c", Username: "u", PrivLvl: tt.held, MaxPrivilege: tt.max}, time.Minute)
			if err := s.SetPrivilege(ctx, k, tt.level); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.GetContext(ctx, k); got.PrivLvl != tt.want {
				t.Fatalf("level %d, want %d", got.PrivLvl, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Invert the author test that asserted lowering, and add the second-window case**

In `internal/daemon/author/author_test.go`, replace the whole of
`TestACommandAboveTheGrantedLevelIsStillDenied` and the comment above it (from
`// The inverse, and the half of the rule that still denies:` up to, not including,
`// A DENIED session authorization grants nothing`) with:

```go
// The half of the rule that still denies: what is recorded is what port49
// GRANTED, not what the device asks for. A session authorized at priv-lvl=1
// that is followed by a command claiming 15 is a device asserting a level
// port49 never gave it.
func TestACommandAboveTheGrantedLevelIsStillDenied(t *testing.T) {
	st := memory.New(time.Now)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 1, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)
	log := &bytes.Buffer{}
	h := New(st, &Lab{SessionAttributes: []string{"priv-lvl=1"}}, decision.NewJSONLines(log),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

	sess := req("alice", "vty4", "service=shell", "cmd=")
	sess.PrivLvl = 1
	if resp := h.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("%+v", resp)
	}
	r := req("alice", "vty4", "service=shell", "cmd=configure", "cmd-arg=<cr>")
	r.PrivLvl = 15
	resp := h.Handle(context.Background(), peer, r)
	if resp.Status != wire.AuthorStatusFail || lastRecord(t, log)["reason"] != "privilege_exceeded" {
		t.Fatalf("%+v %v", resp, lastRecord(t, log))
	}
}

// A lower grant does not lower the context (spec §5.3). The context is keyed
// (nas, username) and covers every window of one operator: window B's session
// authorization answered priv-lvl=1 must not take away the 15 window A was
// granted, or A's next command is `privilege_exceeded` for no reason A can see.
// The REPLY still says 1 — that is policy's answer, and the stored level never
// feeds it.
func TestALowerGrantKeepsTheHeldLevel(t *testing.T) {
	st := memory.New(time.Now)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	st.PutContext(context.Background(), key,
		store.Context{CtxID: "c", Username: "alice", PrivLvl: 15, MaxPrivilege: 15, RefreshedAt: time.Now()}, time.Hour)
	h := New(st, &Lab{SessionAttributes: []string{"priv-lvl=1"}}, decision.NewJSONLines(&bytes.Buffer{}),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

	sess := req("alice", "vty6", "service=shell", "cmd=")
	sess.PrivLvl = 1
	resp := h.Handle(context.Background(), peer, sess)
	if resp.Status != wire.AuthorStatusPassAdd || len(resp.Args) != 1 || string(resp.Args[0]) != "priv-lvl=1" {
		t.Fatalf("the reply is policy's answer and must still say 1: %+v", resp)
	}
	if c, _ := st.GetContext(context.Background(), key); c.PrivLvl != 15 {
		t.Fatalf("a lower grant must not lower the held level: %+v", c)
	}
	r := req("alice", "vty4", "service=shell", "cmd=configure", "cmd-arg=<cr>")
	r.PrivLvl = 15
	if resp := h.Handle(context.Background(), peer, r); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("window A's command at the level it was granted must still be permitted: %+v", resp)
	}
}

```

- [ ] **Step 3: The crypt pass-through test raises instead of lowering**

In `internal/store/crypt/crypt_test.go`'s `TestWrappedStoreHoldsNoPlaintext`, the context is seeded at
15 and `SetPrivilege(ctx, ck, 1)` is asserted to land 1 — a lowering D2 forbids. Make it a raise:

- in the `s.PutContext(ctx, ck, store.Context{...PrivLvl: 15}, ...)` call, change `PrivLvl: 15` to
  `PrivLvl: 1`, and in the check right after it change `c.PrivLvl != 15` to `c.PrivLvl != 1`;
- change `s.SetPrivilege(ctx, ck, 1)` to `s.SetPrivilege(ctx, ck, 15)`;
- in `if c, _ := inner.GetContext(ctx, ck); c.PrivLvl != 1 {` (the "must reach the inner store in the
  clear" check) change `1` to `15`;
- in `if c, _ := s.GetContext(ctx, ck); c.PrivLvl != 1 || c.Principal != ...` (the "narrow write
  must leave the sealed fields readable" check) change `1` to `15`.

- [ ] **Step 4: Run them to see them fail**

Run: `go test ./internal/store/... ./internal/daemon/author/ -count=1`
Expected: FAIL — `TestSetPrivilegeIsRaiseOnlyAndClamped` (`level 1, want 15`; `level 15, want 7`) and
`TestALowerGrantKeepsTheHeldLevel` (`a lower grant must not lower the held level`). The crypt test
passes either way (a raise lands under both rules); it is changed so it stops asserting the old one.

- [ ] **Step 5: Implement**

In `internal/store/memory/memory.go`'s `SetPrivilege`, replace `e.c.PrivLvl = level` with:

```go
	//
	// Raise-only, then clamped, both under this lock: the ceiling read is the
	// one on the record now, which a join may have moved since the caller read
	// it (spec §5.3).
	if level > e.c.PrivLvl {
		e.c.PrivLvl = level
	}
	if ceiling, ok := e.c.PrivilegeCeiling(); ok && e.c.PrivLvl > ceiling {
		e.c.PrivLvl = ceiling
	}
```

(the `//` line continues the comment block directly above it).

In `internal/store/store.go`, replace the first paragraph of `SetPrivilege`'s comment

```go
	// SetPrivilege records the level port49 last granted this context, in
	// place and under the store's own lock. It writes exactly one field,
	// PrivLvl, and is TouchContext's sibling for the same reason: the
	// authorization path must not write back a record it read at the top of
	// the request, because the writer it would race is revocation.
	//
```

with

```go
	// SetPrivilege raises the level this context records to level, in place
	// and under the store's own lock. It writes exactly one field, PrivLvl, and
	// is TouchContext's sibling for the same reason: the authorization path
	// must not write back a record it read at the top of the request, because
	// the writer it would race is revocation.
	//
	// Raise-only: the stored value is max(current, level), clamped to the
	// context's ceiling (Context.PrivilegeCeiling; zero MaxPrivilege is none).
	// PrivLvl means "the highest level port49 has granted this user on this
	// device", not "the level of the latest window" — the context is keyed
	// (nas, username) and covers every window of one operator, so a second
	// window's session authorization granting less must not take the first
	// window's enable away (spec §5.3). It is still a bound: the device cannot
	// exceed it without port49 having said yes somewhere. What a session
	// authorization REPLIES is policy's answer and never this field.
	//
```

In `internal/daemon/author/author.go`, replace

```go
	// `ctx.privilege` is the level port49 last GRANTED, so a permitted session
	// authorization whose reply carries `priv-lvl` records it (spec §5.3, §7).
```

with

```go
	// `ctx.privilege` is the highest level port49 has GRANTED this user on this
	// device, so a permitted session authorization whose reply carries
	// `priv-lvl` raises it to that level and never lowers it: the context covers
	// every window of one operator, and a second window granted less must not
	// take the first window's enable away (spec §5.3, §7; SetPrivilege is
	// raise-only in the store).
```

- [ ] **Step 6: Run the tests**

Run: `go test -race ./internal/... -count=1 && go vet ./...`
Expected: PASS. In particular `TestTheDevicePrivLvlRaisedByOurOwnSessionReply`,
`TestTheGrantedLevelIsClampedToMaxPrivilege`, `TestEnableCeilingRefusesOnlyWhatWasMinted` and
`TestSetPrivilegeWritesTheLevelAndNothingElse` still pass: every one of them raises.

- [ ] **Step 7: Commit**

```bash
git add internal/store/store.go internal/store/memory/memory.go internal/store/memory/memory_test.go \
  internal/store/crypt/crypt_test.go internal/daemon/author/author.go internal/daemon/author/author_test.go
git commit -m "fix: stored privilege is raise-only, clamped to the ceiling

A second window's session authorization granted a lower level and
SetPrivilege wrote it over the first window's enable. The stored level
is now the highest granted on the device; the reply is still policy's.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: The login joins the live context

**Files:**
- Modify: `internal/daemon/authen/authen.go` (`redeem`; new `loginContext`)
- Modify: `internal/session/session.go` (package comment)
- Modify: `internal/store/store.go` (`RefreshContext`'s comment)
- Test: `internal/daemon/authen/authen_test.go`, `internal/daemon/authen/key_test.go`,
  `internal/daemon/author/join_test.go` (new), `internal/daemon/acct/join_test.go` (new)

**Interfaces:**
- Consumes: `store.Joinable`, `store.JoinContext`, `store.JoinResult` (Task 5); `store.Token.MintedAt`
  (Task 3); raise-only `SetPrivilege` (Task 7).
- Produces:
  - `func (s *Session) loginContext(winner *store.Token, username, port, remAddr string) store.Context`
    in package authen — the context a login would create on its own, `CtxID` unset.
  - On the login path, `redeem` reads the context **before** `RedeemAndReceipt`: joinable → the
    receipt and the record carry the live `CtxID`; absent or not joinable → `newCtxID()`; any other
    read error → ERROR `store_unavailable` with the token unspent. After the redemption it calls
    `store.JoinContext(ctx, s.h.store, ck, login, winner.MintedAt, s.h.now(), s.h.contextTTL)` in place
    of `PutContext`, sets `session.replaced_ctx_id` from `JoinResult.Replaced`, and logs
    `JoinResult.Context.CtxID`. The `store_ops` label for the write is `join_context` (was
    `put_context`).
  - The enable path is unchanged.

- [ ] **Step 1: Test 1 of the decisions — through authentication and authorization**

Create `internal/daemon/author/join_test.go`:

```go
package author

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/token"
)

// joinTagKey is this file's device-tag key. Every secret is the device's tag
// followed by filler, as in package authen's tests.
var joinTagKey = token.TagKey([]byte("labkey"))

// realAuthen is the authentication handler over the same store the authorizer
// reads, so a test here drives a login the way the daemon does rather than
// seeding the context it would have written.
func realAuthen(st store.Store) *authen.Handler {
	ids := 0
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond,
		AuthFailureWindow: time.Minute}, time.Now)
	return authen.New(st, decision.NewJSONLines(&bytes.Buffer{}), l, metrics.New(prometheus.NewRegistry()), time.Now,
		func() string { ids++; return fmt.Sprintf("ctx%d", ids) },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(joinTagKey))
}

func papLogin(t *testing.T, h *authen.Handler, secret string) {
	t.Helper()
	reply, _ := h.NewSession(peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
	if reply.Status != wire.AuthenStatusPass {
		t.Fatalf("login: %+v", reply)
	}
}

// Test 1 of the decisions, end to end through both handlers: window A enables
// to 15; window B logs in and its session authorization is granted less; window
// A's next command at 15 is still permitted. Before the join, B's login wrote a
// fresh context at level 1 over A's, and A was denied `privilege_exceeded` on a
// session port49 had just escalated.
func TestASecondWindowDoesNotTakeTheFirstWindowsEnable(t *testing.T) {
	st := memory.New(time.Now)
	tag := token.Tag(joinTagKey, "leaf-01")
	windowA, windowB := tag+"tokatokatokatokatokatoka", tag+"tokbtokbtokbtokbtokbtokb"
	for id, secret := range map[string]string{"a": windowA, "b": windowB} {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: id, Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
				Principal: "user:alice@example.com", Enable: "auto", MaxPrivilege: 15,
				ExpiresAt: time.Now().Add(15 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	an := realAuthen(st)
	log := &bytes.Buffer{}
	az := New(st, &Lab{SessionAttributes: []string{"priv-lvl=1"}}, decision.NewJSONLines(log),
		metrics.New(prometheus.NewRegistry()), time.Now, platform.Defaults(), time.Hour, time.Minute, time.Hour)

	// Window A: login, session authorization, enable to 15.
	papLogin(t, an, windowA)
	sess := req("alice", "vty4", "service=shell", "cmd=")
	sess.PrivLvl = 1
	if resp := az.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("window A session: %+v", resp)
	}
	en := an.NewSession(peer)
	en.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 15,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceEnable, User: []byte("alice"),
		Port: []byte("vty4"), RemAddr: []byte("198.51.100.4")})
	if reply, _ := en.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")}); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("window A enable: %+v", reply)
	}

	// Window B: login, and a session authorization granted 1.
	papLogin(t, an, windowB)
	sess = req("alice", "vty6", "service=shell", "cmd=")
	sess.PrivLvl = 1
	if resp := az.Handle(context.Background(), peer, sess); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("window B session: %+v", resp)
	}

	// Window A, still enabled.
	cmd := req("alice", "vty4", "service=shell", "cmd=configure", "cmd-arg=<cr>")
	cmd.PrivLvl = 15
	if resp := az.Handle(context.Background(), peer, cmd); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("window A lost its enable to window B's login: %+v %v", resp, lastRecord(t, log))
	}
	if c, _ := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); c.CtxID != "ctx1" {
		t.Fatalf("both windows must share the first login's ctx_id: %+v", c)
	}
}
```

- [ ] **Step 2: Test 2 of the decisions — through authentication and accounting**

Create `internal/daemon/acct/join_test.go`:

```go
package acct

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/token"
)

// Test 2 of the decisions, end to end through the authentication and
// accounting handlers: window A logs in and accounting binds its session;
// window B logs in and accounting binds its own; window A's exec STOP is then
// `resolved`. Before the join, B's login wrote a fresh context with an empty
// discriminator set, B's START put only B's discriminator in it, and A's STOP —
// a session port49 had authenticated — paged as `foreign`.
func TestTheFirstWindowsStopAfterASecondLoginIsResolved(t *testing.T) {
	tagKey := token.TagKey([]byte("labkey"))
	tag := token.Tag(tagKey, "leaf-01")
	st := memory.New(time.Now)
	windowA, windowB := tag+"tokatokatokatokatokatoka", tag+"tokbtokbtokbtokbtokbtokb"
	for id, secret := range map[string]string{"a": windowA, "b": windowB} {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: id, Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
				Principal: "user:alice@example.com", ExpiresAt: time.Now().Add(15 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	ids := 0
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond,
		AuthFailureWindow: time.Minute}, time.Now)
	an := authen.New(st, decision.NewJSONLines(&bytes.Buffer{}), l, metrics.New(prometheus.NewRegistry()), time.Now,
		func() string { ids++; return fmt.Sprintf("ctx%d", ids) },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, token.NewTagWindow(tagKey))
	login := func(secret string) {
		t.Helper()
		reply, _ := an.NewSession(peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
			PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
			Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
		if reply.Status != wire.AuthenStatusPass {
			t.Fatalf("login: %+v", reply)
		}
	}

	out := &bytes.Buffer{}
	sp, err := NewSpool(16, filepath.Join(t.TempDir(), "o.jsonl"), decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sp.Run(ctx); close(done) }()
	h := New(st, sp, metrics.New(prometheus.NewRegistry()), time.Now, nil)

	login(windowA)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty4", "task_id=42", "service=shell", "cmd="))
	login(windowB)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty6", "task_id=43", "service=shell", "cmd="))
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty4", "task_id=42", "service=shell", "cmd=", "elapsed_time=60"))
	cancel()
	<-done

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 records, got %d: %s", len(lines), out.String())
	}
	if !strings.Contains(lines[2], `"attribution":"resolved"`) {
		t.Fatalf("window A's STOP must resolve, not page: %s", lines[2])
	}
	c, _ := st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if !hasDisc(c, "42") || !hasDisc(c, "43") || c.CtxID != "ctx1" {
		t.Fatalf("both windows' sessions must be bound to the one context: %v %+v", discs(t, c, "42", "43"), c)
	}
}
```

- [ ] **Step 3: Tests 3 and 5, the kept ctx_id on the receipt, and the unreadable context**

Append to `internal/daemon/authen/authen_test.go`:

```go
// joinFixture seeds window A's live context and hands back window B's login
// START. Window A is enabled to 15 and accounting has bound one session to it,
// which is exactly the state a replace used to erase.
func (f *fixture) joinFixture(t *testing.T, adjust func(*store.Context)) wire.AuthenStart {
	t.Helper()
	f.seedLoginWith(t, "token", 15, func(c *store.Context) {
		c.PrivLvl = 15
		c.SessionDiscriminators = []string{store.HashDiscriminator("42")}
		if adjust != nil {
			adjust(c)
		}
	})
	return wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("ssh"),
		RemAddr: []byte("198.51.100.4"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
}

// Window B's login joins window A's context: the ctx_id, A's privilege and A's
// bound session all survive, and the record names the kept context and
// displaces nothing (spec §5.6).
func TestASecondLoginJoinsAndKeepsTheFirstWindowsState(t *testing.T) {
	f := setup(t)
	start := f.joinFixture(t, nil)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctxL" || c.PrivLvl != 15 || len(c.SessionDiscriminators) != 1 {
		t.Fatalf("the join must keep window A's ctx_id, privilege and bound session: %+v", c)
	}
	s := f.records(t)[0]["session"].(map[string]any)
	if s["ctx_id"] != "ctxL" || s["replaced_ctx_id"] != nil {
		t.Fatalf("%v", s)
	}
}

// The receipt carries the ctx_id the login will be written under, and for a
// join that is the live context's: a retransmission of window B's login
// replays naming ctxL, not an id minted for a context that was never written.
func TestAJoinedLoginsReceiptNamesTheKeptContext(t *testing.T) {
	f := setup(t)
	start := f.joinFixture(t, nil)
	f.h.NewSession(f.peer).Start(context.Background(), start)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	last := f.records(t)[len(f.records(t))-1]
	if reply.Status != wire.AuthenStatusPass || last["reason"] != "receipt_replayed" ||
		last["session"].(map[string]any)["ctx_id"] != "ctxL" {
		t.Fatalf("%+v %v", reply, last)
	}
}

// Test 3 of the decisions. A token minted before a revocation is what the
// revocation was meant to stop, and redeeming it on a device where the revoked
// context is still live must not lift the mark. A token minted after it is the
// broker having verified the credential again, and admits (spec §13,
// decision 15).
func TestARevocationSurvivesATokenMintedBeforeIt(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	for _, tt := range []struct {
		name     string
		mintedAt time.Time
		revoked  bool
	}{
		{"minted before the revocation", revokedAt.Add(-time.Minute), true},
		{"minted after the revocation", revokedAt.Add(time.Second), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t)
			start := f.joinFixture(t, func(c *store.Context) { c.RevokedAt = revokedAt })
			secret := f.tag() + "mintmintmintmintmint0123"
			if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
				store.Token{ID: "m", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
					Principal: "user:alice@example.com", Enable: "token", MaxPrivilege: 15,
					MintedAt: tt.mintedAt, ExpiresAt: f.now.Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			start.Data = []byte(secret)
			f.h.NewSession(f.peer).Start(context.Background(), start)
			c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
			if got := !c.RevokedAt.IsZero(); got != tt.revoked || c.CtxID != "ctxL" {
				t.Fatalf("revoked %v, want %v: %+v", got, tt.revoked, c)
			}
		})
	}
}

// Test 5 of the decisions. The same device-facing username under another
// principal is not this operator's second window: it replaces, starts at its
// own login level with nothing bound, and the record names what it displaced.
func TestAnotherPrincipalUnderTheSameUsernameReplaces(t *testing.T) {
	f := setup(t)
	start := f.joinFixture(t, nil)
	secret := f.tag() + "othrothrothrothrothrothr"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "o", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@corp.example", ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	start.Data = []byte(secret)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctx1" || c.Principal != "user:alice@corp.example" || c.PrivLvl != 1 || len(c.SessionDiscriminators) != 0 {
		t.Fatalf("another principal must get a fresh context: %+v", c)
	}
	s := f.records(t)[0]["session"].(map[string]any)
	if s["ctx_id"] != "ctx1" || s["replaced_ctx_id"] != "ctxL" {
		t.Fatalf("the replace must name what it displaced: %v", s)
	}
}

// unreadableContext answers GetContext the way the sealing layer answers a
// record sealed under a retired key: an error that is not ErrNotFound.
type unreadableContext struct{ *memory.Store }

func (unreadableContext) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	return store.Context{}, errors.New("crypt: opening context: sealed under an unknown key")
}

// A context port49 cannot read cannot be joined, and replacing it blind could
// erase a revocation. The login is ERROR — and it is ERROR before the token is
// spent, so the operator's token still works once the record is readable or
// reclaimed, and the device's retry is not a replay of a PASS nothing backs.
func TestAnUnreadableContextFailsTheLoginBeforeTheTokenIsSpent(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return unreadableContext{st} })
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1"))
	if reply.Status != wire.AuthenStatusError || f.records(t)[0]["reason"] != "store_unavailable" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
	if cands, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(cands) != 1 {
		t.Fatalf("the token must not be spent on a login that cannot be written: %d left", len(cands))
	}
}
```

- [ ] **Step 4: The existing tests that asserted the overwrite**

In `internal/daemon/authen/key_test.go`, replace `TestSecondLoginReplacesContextAndLogsIt` and its
comment (from `// TestSecondLoginReplacesContextAndLogsIt is requirement (c)` up to, not including,
`// TestReceiptIsScopedToNASUsernameAndCredential is requirement (d).`) with:

```go
// TestSecondLoginJoinsTheLiveContext is requirement (c) as spec §5.6 now
// states it: one user's concurrent sessions on one device share a context, and
// a second login by the same principal joins it rather than replacing it. The
// ctx_id is kept, so both shells' later records join on one id, and the second
// login's record displaces nothing.
func TestSecondLoginJoinsTheLiveContext(t *testing.T) {
	f := setup(t)
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "t2", Secret: []byte(f.tag() + "tok2tok2tok2tok2tok2tok2"), Kind: store.KindLogin, Principal: "user:alice@example.com", ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", f.tag()+"tok1tok1tok1tok1tok1tok1")); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("first login: %+v", reply)
	}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", f.tag()+"tok2tok2tok2tok2tok2tok2")); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("second login: %+v", reply)
	}
	r := f.records(t)
	if len(r) != 2 {
		t.Fatalf("records: %v", r)
	}
	for i, rec := range r {
		s := rec["session"].(map[string]any)
		if s["ctx_id"] != "ctx1" || s["replaced_ctx_id"] != nil {
			t.Fatalf("login %d must name the one context and displace nothing: %v", i+1, s)
		}
	}
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if err != nil || c.CtxID != "ctx1" || c.Username != "alice" {
		t.Fatalf("%+v %v", c, err)
	}
}

```

In `internal/daemon/authen/authen_test.go`, `capturingStore` intercepted `PutContext`, which the login
path no longer calls. Replace

```go
// capturingStore keeps the Context the handler handed to PutContext, before
// any store stamped anything on it.
type capturingStore struct {
	*memory.Store
	got store.Context
}

func (c *capturingStore) PutContext(ctx context.Context, k store.ContextKey, v store.Context, ttl time.Duration) error {
	c.got = v
	return c.Store.PutContext(ctx, k, v, ttl)
}

// memory.PutContext stamps LastTouchedAt itself
```

with

```go
// capturingStore keeps the Context the handler handed to SwapContext, before
// any store stamped anything on it.
type capturingStore struct {
	*memory.Store
	got store.Context
}

func (c *capturingStore) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, v store.Context, ttl time.Duration) error {
	c.got = v
	return c.Store.SwapContext(ctx, k, rev, v, ttl)
}

// memory.SwapContext stamps LastTouchedAt itself
```

`TestReplayedEnableNamesTheLiveContext` relied on a same-principal relogin replacing `ctxL`. Under
the join that relogin keeps `ctxL`, and the only replace left inside a receipt's window is another
principal's login. Replace its comment

```go
// And when the context was replaced between the escalation and the
// retransmission, the replay must name the context that exists now. The receipt
// froze ctxL; alice's second shell replaced it with ctx1 (spec §15, L1: the key
// cannot tell two of her shells apart).
```

with

```go
// And when the context was replaced between the escalation and the
// retransmission, the replay must name the context that exists now. The receipt
// froze ctxL; a login under the same username by another principal replaced it
// with ctx1 (spec §5.6: only a different principal, or a context past its
// ceiling, is replaced rather than joined).
```

and replace its relogin block

```go
	// A second login on the same (nas, username): ctxL is replaced by ctx1, at
	// login privilege.
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"),
		Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("relogin: %+v", reply)
	}
```

with

```go
	// A login under the same username by ANOTHER principal: ctxL is replaced
	// by ctx1, at login privilege. It is the one way left for the context to
	// change identity inside a receipt's window — the same principal's second
	// login joins ctxL and keeps its id (spec §5.6).
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "other", Secret: []byte(f.tag() + "othrothrothrothrothrothr"), Kind: store.KindLogin,
			Username: "alice", Principal: "user:alice@corp.example", Enable: "token", MaxPrivilege: 15,
			ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"),
		Data: []byte(f.tag() + "othrothrothrothrothrothr")}); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("relogin: %+v", reply)
	}
```

- [ ] **Step 5: Run them to see them fail**

Run: `go test ./internal/daemon/... -count=1 2>&1 | grep -E '^(--- FAIL|ok|FAIL)'`
Expected FAIL: `TestTheHandlerStampsTheContextClocksItself` (nothing calls `SwapContext` yet),
`TestSecondLoginJoinsTheLiveContext`, `TestASecondLoginJoinsAndKeepsTheFirstWindowsState`,
`TestAJoinedLoginsReceiptNamesTheKeptContext`, `TestARevocationSurvivesATokenMintedBeforeIt`,
`TestAnUnreadableContextFailsTheLoginBeforeTheTokenIsSpent`,
`TestASecondWindowDoesNotTakeTheFirstWindowsEnable` (`privilege_exceeded`), and
`TestTheFirstWindowsStopAfterASecondLoginIsResolved` (`"attribution":"foreign"`).
Expected PASS already: `TestAnotherPrincipalUnderTheSameUsernameReplaces` and
`TestReplayedEnableNamesTheLiveContext` — the replace they describe is today's behaviour for every
login, and must stay the behaviour for another principal's.

- [ ] **Step 6: Decide the ctx_id before the redemption**

In `internal/daemon/authen/authen.go`'s `redeem`, replace

```go
	// 3. Atomic redemption; the loser of a race adopts the winner's receipt.
	//
	// An escalation keeps the context's id (spec §5.6 row 1, §7), and the
	// receipt has to carry that id rather than a fresh one: the receipt is what
	// answers a retransmitted enable, and a ctx_id minted here and stored
	// nowhere would be replayed into the log naming a context that does not
	// exist. `enable` is false on every login path, where this is plan 1's
	// behaviour unchanged.
	ctxID := incumbent.CtxID
	if !enable {
		ctxID = s.h.newCtxID()
	}
```

with

```go
	// 3. Atomic redemption; the loser of a race adopts the winner's receipt.
	//
	// The receipt carries the ctx_id this redemption lands on, so that id is
	// settled before the redemption rather than after it: the receipt is what
	// answers a retransmission, and a ctx_id minted here and stored nowhere
	// would be replayed into the log naming a context that does not exist.
	// An escalation keeps the context's id (spec §5.6 row 1, §7). A login
	// joins the live context when it may (spec §5.6), and then it is that
	// context's id too; otherwise it is a fresh one.
	//
	// The login's read is here, before the token is spent, for a second
	// reason: a context that cannot be read — the store is down, or the record
	// is sealed under a retired key — cannot be joined, and JoinContext below
	// would refuse it anyway. Refusing now leaves the token unspent, so the
	// operator's retry works once the record is readable or reclaimed, instead
	// of replaying a PASS that nothing backs.
	//
	// The read and JoinContext's own are not one operation. If the context
	// changes identity between them — reclaimed, or replaced by another
	// principal's login — the receipt names the id predicted here and the
	// redeem record names the one written. That costs a retransmission's
	// replay record its ctx_id, and needs a login under the same username on
	// the same device inside a few milliseconds.
	ctxID := incumbent.CtxID
	var login store.Context
	if !enable {
		login = s.loginContext(winner, username, port, remAddr)
		prev, perr := s.h.store.GetContext(ctx, ck)
		s.h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(perr)).Inc()
		switch {
		case perr == nil && store.Joinable(prev, login, s.h.now()):
			ctxID = prev.CtxID
		case perr == nil || errors.Is(perr, store.ErrNotFound):
			ctxID = s.h.newCtxID()
		default:
			return s.storeError(rec)
		}
		login.CtxID = ctxID
	}
```

- [ ] **Step 7: Join in place of the overwrite**

Still in `redeem`, replace everything from the comment `// A context already under this key is this
operator's own earlier login on` down to and including

```go
	err = s.h.store.PutContext(ctx, ck, newCtx, s.h.contextTTL)
	s.h.metrics.StoreOps.WithLabelValues("put_context", storeOutcome(err)).Inc()
	if err != nil {
		// The token is already redeemed, but without a context a later authorization
		// request has nothing to check against: ERROR, not a PASS we can't back up.
		return s.storeError(rec)
	}
```

with

```go
	// Join, or write fresh (spec §5.6). A live context of the same principal
	// is this operator's other window on this device, and the login merges
	// into it: the ctx_id, the privilege already granted, the bound sessions
	// and a revocation the token predates are all kept, so window A loses
	// nothing to window B. Another principal under the same username, or a
	// context past its ceiling, is replaced, and the record names the ctx_id
	// it displaced. JoinContext reads, merges and swaps on the revision it
	// read, so a revocation or annotation landing mid-login is merged rather
	// than erased, and two simultaneous logins both land.
	out, err := store.JoinContext(ctx, s.h.store, ck, login, winner.MintedAt, s.h.now(), s.h.contextTTL)
	s.h.metrics.StoreOps.WithLabelValues("join_context", storeOutcome(err)).Inc()
	if err != nil {
		// The token is already redeemed, but without a context a later authorization
		// request has nothing to check against: ERROR, not a PASS we can't back up.
		return s.storeError(rec)
	}
	rec.Session.ReplacedCtxID = out.Replaced
	// Indexed under this login's credential even on a join, and added to what
	// the context was indexed under rather than replacing it: revocation by
	// either login's sid or certificate has to reach the joined context.
```

(the `IndexContext` call that follows is unchanged). At the end of `redeem`, replace

```go
	rec.Session.CtxID = ctxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
}
```

with

```go
	rec.Session.CtxID = out.Context.CtxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
}

// loginContext is the context this login would create on its own, in its
// §5.1.1 shape: everything a later authorization has to answer from without
// reaching the broker again. Its CtxID is left for the caller. JoinContext
// writes it as it is on a first login and merges it into the live context on
// a second.
func (s *Session) loginContext(winner *store.Token, username, port, remAddr string) store.Context {
	now := s.h.now()
	c := store.Context{Principal: winner.Principal, Username: username,
		Port: port, RemAddr: remAddr, PrivLvl: s.start.PrivLvl, BlobHash: winner.BlobHash,
		Credential: winner.Credential, AuthTime: winner.AuthTime, RefreshedAt: now,
		LastTouchedAt: now, Enable: winner.Enable, MaxPrivilege: winner.MaxPrivilege, CreatedAt: now}
	// A zero MaxSessionAge is `max_session_age: never` and must stay
	// expressible (spec §5.6): it leaves SessionExpires zero, which Task 10
	// reads as no ceiling rather than as expired at the epoch.
	//
	// Nothing else is guarded here, and a token carrying a ceiling with no
	// AuthTime to anchor it is deliberately left to compute a SessionExpires
	// in the distant past. That denies, loudly and visibly, where dropping the
	// ceiling instead would hand out an unbounded session that looks exactly
	// like a legitimate `never` and that nothing logs.
	if winner.MaxSessionAge > 0 {
		c.SessionExpires = winner.AuthTime.Add(winner.MaxSessionAge)
	}
	return c
}
```

- [ ] **Step 8: The comments that described the old behaviour**

In `internal/session/session.go`'s package comment, replace

```go
// it, a revoked principal's unredeemed token still redeems, writing a fresh
// context by spec §5.6 row 1's unconditional overwrite with no revoked_at on
// it. The operator sees a revocation that marked every context and deleted
// every receipt, and then a PERMIT on a device they thought they had closed,
// with no log line connecting the two. Plan 7 owns closing this.
```

with

```go
// it, a revoked principal's unredeemed token still redeems. On a device where
// the revoked context is still live the damage is contained: the login joins
// that context and keeps its revoked_at, because the token was minted before
// the revocation (store.JoinContext; spec §5.6). On a device with no live
// context there is nothing to join, and the redemption writes a fresh context
// with no revoked_at on it. The operator sees a revocation that marked every
// context and deleted every receipt, and then a PERMIT on a device they
// thought they had closed, with no log line connecting the two. Plan 7 owns
// closing this.
```

In `internal/store/store.go`'s `RefreshContext` comment, replace

```go
	// two. If a lift is ever genuinely wanted it belongs behind a separate
	// setter that only a path which re-verified the credential may call, and
	// the spec's §13 decision table has to say so first.
```

with

```go
	// two. The one path that may lift a mark is a login whose token the broker
	// minted after the revocation — the credential verified again — and it
	// does so through JoinContext, never here (spec §13, decision 15).
```

- [ ] **Step 9: Run everything**

Run: `make test && make vet && go test -race ./internal/... -count=1 && go vet -tags lab ./tests/lab/...`
Expected: every package `ok`, `gofmt` silent, vet clean. `internal/daemon/server`'s end-to-end test
still passes: its two users are different usernames and never join.

- [ ] **Step 10: Commit**

```bash
git add internal/daemon/authen/authen.go internal/daemon/authen/authen_test.go internal/daemon/authen/key_test.go \
  internal/daemon/author/join_test.go internal/daemon/acct/join_test.go internal/session/session.go internal/store/store.go
git commit -m "fix: a second login joins the live context instead of replacing it

A second login by the same principal on the same device replaced the
whole context: window A's enable was reset, its bound sessions were
emptied so its STOP paged foreign, and revoked_at was wiped so a token
minted before a revocation re-admitted the user. The login now reads
the context before spending the token, carries the joined ctx_id on the
receipt, and writes through JoinContext. Another principal, or a
context past its ceiling, is still replaced and logged.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: Count accounting records by attribution; a `system` record keeps its port

**Files:**
- Modify: `internal/daemon/metrics/metrics.go`, `internal/daemon/metrics/metrics_test.go`
- Modify: `internal/daemon/acct/acct.go`
- Test: `internal/daemon/acct/acct_test.go`

**Interfaces:**
- Produces: `metrics.Metrics.Attributions *prometheus.CounterVec` —
  `port49_accounting_attributions_total{attribution}`, registered by `metrics.New`; incremented by
  `acct.Handle` once per record the spool accepted, with the record's attribution.

D4 needs no code: `acct.Handle` already puts the request's `port` on every record
(`decision.Session.Port` has no `omitempty`). Its test pins that for a `system` record and is
expected to pass on its first run.

- [ ] **Step 1: Write the failing tests**

Append to `internal/daemon/acct/acct_test.go`:

```go
// Every record the spool accepted is counted by its attribution, and `foreign`
// is the one to alert on (spec §5.8): a session port49 did not authenticate,
// under a name it does. The label is the attribution and nothing else — no
// device and no user, which CLAUDE.md forbids in a metric label.
func TestEveryAttributionIsCounted(t *testing.T) {
	h, st, _, stop := setup(t)
	sys := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "test_system_users"}
	putCtx(t, st, store.Context{CtxID: "ctx1", Principal: "user:alice@example.com",
		SessionDiscriminators: []string{store.HashDiscriminator("42")}})
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStart, "alice", "vty0", "task_id=42", "service=shell", "cmd="))
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=99", "service=shell", "cmd="))
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "mallory", "vty0", "task_id=7", "service=shell", "cmd="))
	h.Handle(context.Background(), sys, acct(wire.AcctFlagStop, "root", "non-tty", "task_id=3", "service=shell", "cmd="))
	stop()
	for _, a := range []string{"resolved", "foreign", "unattributed", "system"} {
		if got := testutil.ToFloat64(h.metrics.Attributions.WithLabelValues(a)); got != 1 {
			t.Errorf("port49_accounting_attributions_total{attribution=%q} = %v, want 1", a, got)
		}
	}
}

// A record the spool refused is not counted: the device was answered ERROR and
// will send it again, and counting both would double it.
func TestARefusedRecordIsNotCounted(t *testing.T) {
	st := memory.New(time.Now)
	m := metrics.New(prometheus.NewRegistry())
	h := New(st, brokenSpool(filepath.Join(t.TempDir(), "absent", "o.jsonl"), m), m, time.Now, nil)
	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "mallory", "vty0", "task_id=1", "service=shell", "cmd="))
	if got := testutil.ToFloat64(m.Attributions.WithLabelValues("unattributed")); got != 0 {
		t.Fatalf("a refused record was counted: %v", got)
	}
}

// A console login as a system user stays `system` (spec §5.8): `root` on
// juniper_junos is the device's own machinery in the capture, and port49
// cannot tell that from a person at the console under the same name. What it
// can do is keep the port on the record, so a log reader sees where the
// session was. The port value here is illustrative: what a Junos console
// presents in `port` is unmeasured in this lab.
func TestASystemRecordCarriesItsPort(t *testing.T) {
	h, _, out, stop := setup(t)
	sys := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "test_system_users"}
	h.Handle(context.Background(), sys, acct(wire.AcctFlagStart, "root", "ttyd0", "task_id=1", "service=shell", "cmd="))
	stop()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &m); err != nil {
		t.Fatal(err)
	}
	if m["attribution"] != "system" || m["session"].(map[string]any)["port"] != "ttyd0" {
		t.Fatalf("a system record must stay system and carry the port it arrived on: %v", m)
	}
}
```

In `internal/daemon/metrics/metrics_test.go`'s `TestNewRegistersEveryMetric`, add
`m.Attributions.WithLabelValues("foreign").Inc()` after the `CryptOpenFailures` line, and
`"port49_accounting_attributions_total":     false,` to `expectedMetrics`.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/acct/ ./internal/daemon/metrics/ -count=1`
Expected: FAIL to build — `h.metrics.Attributions undefined`, `m.Attributions undefined`.

- [ ] **Step 3: The counter**

In `internal/daemon/metrics/metrics.go`, add to `type Metrics struct`, after `CryptOpenFailures`:

```go
	// port49_accounting_attributions_total{attribution}: every accounting
	// record the spool accepted, by the attribution it was given — "resolved",
	// "unattributed", "system", "foreign" (spec §5.8). `foreign` is the one to
	// alert on: an exec record for a session port49 did not authenticate,
	// under a name it does, which is a local fallback, a console, or a
	// device-local account sharing a port49 username. The label is the
	// attribution only; the device and the user are on the log record.
	Attributions *prometheus.CounterVec
```

In `New`, after the `CryptOpenFailures:` entry of the literal, add:

```go
		Attributions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_accounting_attributions_total",
			Help: "Accounting records accepted, by attribution."}, []string{"attribution"}),
```

and add `m.Attributions` as the last argument of `reg.MustRegister(...)`.

- [ ] **Step 4: Count it**

In `internal/daemon/acct/acct.go`'s `Handle`, replace

```go
	h.metrics.Requests.WithLabelValues("acct", "success").Inc()
```

with

```go
	h.metrics.Requests.WithLabelValues("acct", "success").Inc()
	// Counted once the record is durable, not before: a refused record is
	// answered ERROR and the device sends it again.
	h.metrics.Attributions.WithLabelValues(attribution).Inc()
```

- [ ] **Step 5: Run everything**

Run: `make test && make vet && go test -race ./internal/... -count=1 && go vet -tags lab ./tests/lab/...`
Expected: every package `ok`; `TestASystemRecordCarriesItsPort` passes as it did before Step 3.

- [ ] **Step 6: Commit**

```bash
git add internal/daemon/metrics/metrics.go internal/daemon/metrics/metrics_test.go \
  internal/daemon/acct/acct.go internal/daemon/acct/acct_test.go
git commit -m "feat: count accounting records by attribution

port49_accounting_attributions_total{attribution} counts every record
the spool accepts; foreign is the series to alert on. A system record
keeps the port it arrived on, which the test now pins.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

## Self-review

**Decision coverage**

| Decision | Task |
|---|---|
| D1 join field rules, each row | 5 (`Join`, `TestJoinFieldRules`), 8 (the login path) |
| D1 `RevokedAt` kept unless minted after; `MintedAt` on the token | 3, 5, 8 (test 3) |
| D1 every login indexed; revocation by either sid/cert reaches the context | 6, 8 (`IndexContext` on every login) |
| D1 different principal → fresh, replaced ctx_id recorded | 5, 8 (test 5) |
| D1 idle-expired → fresh; past `SessionExpires` → replaced, not joined | 4 (expired swap), 5 |
| D1 atomic read-merge-write, CAS with bounded retry, memory AND crypt, never clobbers `SetRevokedAt` | 4, 5 (test 4, both stores) |
| D2 raise-only, clamped, zero = no ceiling; reply still from policy | 7 |
| D3 counter by attribution, snake_case, no device label, no rate limit | 9 |
| D4 console `root` stays `system`, record carries port, §5.8 documents it | 1, 9 |
| D5 §5.6 join table, §13 d15 sentence, §5.3 raise-only | 1 |
| D5 memo and spec vEOS correction, cited to the log | 2 |
| D5 local-account and local-enable guidance; `foreign` is the detection | 1 |
| D5 roadmap: plan 5 config check; per-window contexts not planned | 2 |
| Tests 1, 2, 3, 5 | 8 |
| Test 4 | 5 |

**Placeholder scan:** none. Every code step carries the code or the exact edit.

**Type consistency, checked:** `store.Context.Rev uint64` is set only by `memory.GetContext` and
compared only by `memory.SwapContext`; `SwapContext(ctx, k, rev uint64, c, ttl)` has the same
signature in `store.Store`, memory, crypt, `noStore`, `capturingStore` and `alwaysConflicts`;
`store.JoinContext(ctx, s, k, login, mintedAt, now, ttl) (JoinResult, error)` is called by
`storetest.JoinRacesRevocation`, `join_test.go` and `authen.redeem` with the same argument order;
`JoinResult.Replaced` feeds `decision.Session.ReplacedCtxID` and nothing else;
`store.Token.MintedAt` is set by the minter and read by `authen.redeem` only;
`metrics.Metrics.Attributions` is written by `acct.Handle` only; `authen.New`, `author.New` and
`acct.New` keep their plan-2 signatures.

**Things an implementer must not miss.** Task 4 adds a method to `store.Store`, so `noStore` in
`authen_test.go` has to gain it in the same commit or the authen tests stop compiling. Task 7 must
land before Task 8: test 1 needs raise-only `SetPrivilege` as well as the join. Task 5 Step 6 is a
deliberate mutation — undo it before committing. Task 8 moves the login's context read in front of
`RedeemAndReceipt`; the enable path's read above it is unchanged and must stay where it is.

**Unmeasured, and not relied on:** what `port` a Junos console session presents (Task 9's test value
is labelled illustrative); whether any device reuses a session discriminator across a join (the
existing §5.8 measurement says not across a logout, which is all the join relies on).

---

## Execution

Runs on Go 1.22 with no new dependencies, on branch `feature/context-join`. Nine tasks, nine commits.
Nothing here needs containerlab. The final gate is `make test && make vet`,
`go test -race ./internal/...`, and `go vet -tags lab ./tests/lab/...`, reported with their real
output.
