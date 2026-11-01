# Plan 4b: Live Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A policy edit takes effect live and nobody is logged out: `port49d` notices a changed
policy file, refuses one that does not load and keeps serving the old, swaps in one that does in
one step, re-runs the joint checks, and carries the new policy into every live login context —
a narrowing or a widening from the next command, a withdrawn grant as a revoked context.

**Architecture:** The policy in force becomes one swappable pointer, `policy.Live`, which the
broker mints from and the daemon asks about quarantine at every packet, so one swap changes both.
A reloader goroutine in `port49d` reads the file on a timer and on `SIGHUP` and swaps a policy
that loads. After every swap, at every grant expiry, and again after a short settle, the broker's
new `Refresh` re-resolves each live context's principal on its device against the policy in force
and writes the answer through `store.SetContextPolicy`, a narrow setter that is also a
compare-and-set on the revision it read; a principal with no grant left has the context revoked.
`Refresh` also deletes the unspent tokens a superseded policy minted and the policy in force would
not mint identically, because a redemption would otherwise write the superseded answer back.

**Tech Stack:** Go 1.22, standard library, the plan 1–4 packages. No new dependencies: the file
watch is a content-hash poll, not inotify.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §5.1.3 (refreshing live context; this
plan adds "Policy reload"), §5.6 teardown row 2 (revocation), §5.7 (the `refresh` event; the
`grants_matched`, `no_grants_matched`, `device_quarantined` and `credential_revoked` rows), §10
(quarantine), §13 decision 20 and the new decision 24, §14 "Session lifetime and revocation".
Design `docs/design/2026-08-21-port49-design.md` §9 (refresh), §12 (the failure matrix). Roadmap
`docs/superpowers/plans/README.md`, "Plan 4b", and the plan 4 section's carries (the end-to-end
test of `run` with no `lab:` block).
**Prerequisite:** plan 4 merged (PR #10) and the gate rulings merged (PR #11). Branch
`feature/live-policy` off `main` at `e10ab29`.

## Why this plan exists

The owner's intent, 2026-09-24: "one of my intended goals of this entire project" — a policy
change reaches every live session without anyone logging out. Today `broker.policy_file` is read
once, at start (`cmd/port49d/main.go`, `buildBroker`), and the store is in memory, so an edit
needs a restart and a restart ends every live login context and every unspent token (plan 3,
Question 3). The one edit that most needs to reach a live session — a grant withdrawn — is the
one that cannot, short of logging everyone out.

What the roadmap owes, and nothing past it:

- a reload trigger — a watch on `broker.policy_file` and `SIGHUP`, both;
- validate or keep the old: a file that does not load leaves the policy in force serving,
  logged, counted, and alarmed, and nothing half-applies;
- an atomic swap of the broker's policy and the daemon's quarantine, so no mint sees one
  version's grants and another's quarantine, and in-flight requests finish on the one they
  started with;
- the joint checks and the time-scoped quarantine schedule re-run for the new policy;
- the refresh of every live context (spec §5.1.3): re-resolved, the new blob written by
  compare-and-set, revoked where no grant is left, with no logout;
- the carries: `(*broker.Broker).Server` returns an error instead of panicking (from plan 7), and
  an end-to-end test that runs `port49d`'s `run` with no `lab:` block (from plan 4), which needs a
  way to stop `run` from a test.

## Decided in this plan

1. **The policy in force is one pointer, `policy.Live`.** A loaded `*policy.Policy` is never
   edited, so a reader holds one version throughout; the swap is the only thing that changes the
   version. The daemon's per-packet quarantine question and the quarantine gauge `Load` it with no
   lock. A mint `Hold`s it — a read lock from its first resolution to its last token write — so
   that once `Swap` returns no mint is still writing a token resolved against the policy it
   replaced. The token supersede (Decided 7) depends on that. A batch is one version: a request
   never mints device 1 from one policy and device 2 from the next. The hold is released before
   the response is written (pre-flight S1): a client that stops reading, or a peer that vanishes
   mid-response, would otherwise hold a reload — and, behind it, every mint and every refresh —
   until TCP gave up, with nothing said. A deferred release still covers a panic, which net/http
   recovers.
2. **The watch is a content-hash poll, and a change is loaded when two reads in a row agree.**
   `broker.policy_watch_interval` (default 5s, 1s to 5m) reads the file and compares its sha256
   — which is also the bundle the file loads as (plan 4, Decided 3) — with the policy in force. A
   poll sees an in-place write, an editor's rename-and-replace and a Kubernetes ConfigMap's
   symlink swap alike, where inotify would need a new dependency and per-editor care. Two
   agreeing reads mean a file caught half-written is neither loaded nor refused: without them an
   editor's in-place save would log a spurious refusal and page someone. What is loaded is the
   bytes the two reads agreed on, never a third read (pre-flight S2): a list cut short can load
   *wider* than the one intended — a block-style `deny:` list cut after its first item loses the
   rest. `SIGHUP` loads at once, with no second read, because the operator asked. Neither guards a
   writer stalled part-way for two intervals, or a `SIGHUP` sent mid-write, so the file is to be
   written atomically (a temporary file renamed over it); the config comment, the spec and the
   operator notes say so. `SIGHUP` is caught with no `broker:` block too, and said to do nothing:
   its default action ends the process, and a reload habit must never take device AAA down. It is
   caught first thing in `run` (pre-flight N5), so a HUP sent during start does not end it either.
3. **A file that does not load is refused whole, with the start's own words.** One loader serves
   the start and every reload, so the error an operator reads after an edit is the one a restart
   would have printed. The refusal is said once per distinct content (a SIGHUP always answers),
   counted in `port49_policy_reloads_total{outcome}` (`applied`, `unchanged`, `refused`), and held
   in `port49_policy_file_refused`, 1 while the file on disk is not the policy serving — the alert
   for an edit someone believes is live and is not. Putting the old file back clears it. The
   refusal is one line: a YAML error's own lines are joined into it (pre-flight N7). It echoes
   values from the file quoted, exactly as the start does; the policy holds no credential.
   **A file anyone but `port49d`'s user or root could have written is refused the same way**
   (pre-flight N6, the owner's security-first ruling): the file group- or world-writable, its
   directory group- or world-writable, or either owned by another uid. At start `port49d` does not
   start; at a reload the policy in force serves, the refusal is said once and counted `refused`.
   With a live reload, whoever can write the file decides every operator's access within
   seconds. It is `internal/keyfile`'s rule for a private key, for writing rather than reading;
   unlike keyfile a symlink is followed — a Kubernetes ConfigMap mounts the policy as a chain of
   them — and what is checked is the final target, opened with `O_NOFOLLOW`, and the directory
   holding it. The lab harness gives `port49d` a private copy of its policy, since a checkout
   under a umask of 002 is group-writable.
4. **The refresh writes through a new narrow setter, `SetContextPolicy`, and it is a
   compare-and-set.** It writes a closed list — the blob hash, the ceiling (lowering a held level
   above a lowered ceiling, the join's rule, spec §5.3) and the `enable` mechanism; or, to revoke,
   `revoked_at` alone — only if the record still carries the revision the refresher read. The
   other setters write a value that is right whoever the record belongs to; this one writes a
   value computed from who it belongs to, and the principal is sealed, so the inner store cannot
   check it. A login that replaced the record with another principal's, or joined it with a token
   minted under the previous policy, moves the revision, and the refresher reads again and decides
   again. `RefreshContext` is not reused: it moves `auth_time`, `session_expires` and the idle TTL,
   and a policy edit is neither a re-authentication nor activity — reused, every reload would keep
   every idle context alive. `SwapContext` is not reused either: it writes the whole record and
   extends the TTL for the same reason. The setter never raises the held level: a widened level
   reaches the device only at the next session authorization or `enable`, which is where levels
   are granted (spec §5.3). It does not stamp `refreshed_at`: nothing about the directory was
   re-verified, and the staleness clock is plan 7's.
5. **Every reload rewrites every live context** (Question 2). Every edit changes the bundle, so
   every blob's hash changes, and a record decided after the reload should name the policy that
   was in force when it was decided. A second pass with nothing new finds every context
   `unchanged` and writes nothing.
6. **One new event, `refresh`, and no new reason.** A refresh re-resolves a principal on a device
   and acts on the answer, which is a decision, so it is one record (spec §5.7: "every evaluation
   emits exactly one record"), naming the context's `ctx_id`, the bundle, the subject and grants,
   and the blob written. It reuses three reasons already in the table, each row amended in Task 1:
   `grants_matched` (permit: the policy written into the context), `no_grants_matched` (deny: the
   context revoked), `device_quarantined` (deny: the context left as it was). A resolution that
   fails on a device the load did not quarantine is a broker defect, as it is at mint: the context
   is revoked — it is serving a policy no longer in force, and fail closed says it stops — and the
   process log says why, naming the `ctx_id` so the `credential_revoked` after it can be joined,
   with no decision record, as a mint item error has none. An unchanged context writes nothing and
   logs nothing. Both are carve-outs from §5.7's "every evaluation emits exactly one record", and
   Task 1 writes them into §5.7 beside that sentence (pre-flight S6). The process-log lines go
   through `log.Printf`, as the broker's other process-log lines do, not port49d's swappable
   `stderr`: the same stream in production, and not asserted by a test (pre-flight N8, accepted as
   is).
7. **Unspent tokens whose answer changed are deleted** (Question 1). A token carries the blob,
   ceiling and `enable` of the policy that minted it, and a redemption writes them into the
   context it creates or joins. Without the delete a grant withdrawn at 10:00 comes back at 10:05
   on a device where the operator had no context, from a token minted at 09:58 — exactly the edit
   this plan exists for. Design §8 already puts deleting tokens on revoke by `(device, username)`
   on the broker. A token the policy in force would mint identically, the bundle aside, is kept.
   A superseded policy is judged across its whole span, not at one instant (pre-flight S5): a
   token carries the answer at the moment of its mint, and the answer changes at each grant expiry
   in the span, so the answers are read at the span's start and at every expiry inside it
   (`broker.Prior`'s `At` and `Until`). Read only at the start, a pass the store stopped at an
   expiry would leave a token minted after it that a withdrawing edit ought to clear.
8. **A context on a quarantined device is left as it is** (Question 3). The daemon answers nothing
   from that device while it is quarantined, and the refresh at the reload or expiry that lifts
   the quarantine brings the context forward.
9. **The refresh runs at every reload, again 30s after it, at every grant expiry, and every 30s
   after a store error until it finishes.** The second pass after a reload catches a login in
   flight across the swap: it spent its token before the supersede and wrote its context after
   the first pass had visited it, finishing on the policy it started with, as the owner asked, and
   is brought forward 30s later. A grant's expiry changes a resolution with no edit (spec §5.1), so
   it is a scheduled refresh (`policy.NextChange`); without it a live context keeps an expired
   grant's rules until the next edit. The reloader remembers every policy in force since the last
   complete pass (`broker.Prior`), so a pass the store stopped compares against all of them when
   it runs again. **A busy context does not stop a pass** (pre-flight S3): every accounting
   record moves a context's revision, so a session busy enough can make every compare-and-set
   stale. After `store.MaxJoinAttempts` a revocation is written anyway through `SetRevokedAt`,
   the setter that writes the mark alone — fail closed, at worst revoking a login another
   principal made a moment ago, whose owner logs in again — and any other answer is counted
   `failed` and left for the retry; the pass goes on to the next context and returns the
   conflict at the end, so the reloader retries in 30s.
10. **The inventory is not reloaded, and a reload after an inventory edit says so.** Reading the
    inventory file again is cheap; applying it is not: admission's trie, the key ring, the
    per-source limits and the broker's device table are built from it once, and spec §10's
    snapshot refresh (plan 6) is the design for swapping them — build fully, validate, refuse a
    shrink past the bounded-change limit, then swap. A reload here checks the new policy against
    the inventory loaded at start, and when the inventory file has changed since, one line says it
    was not applied and a restart is needed. So a policy edit alone behaves exactly as described;
    an inventory edit needs a restart until plan 6.
11. **The store down during a reload does not stop the swap.** The new policy is in force for
    every mint at once — and every mint fails `store_unavailable` until the store answers, as it
    would have anyway. The refresh stops at its first store error, says how far it got, and is run
    again every 30s; a context not reached keeps its previous policy until then. Nothing is
    half-written to any one context: each is one compare-and-set. `port49_policy_refresh_pending`
    is 1 from the swap, or a stopped pass, until a pass completes (pre-flight S4) — the alert for
    a policy that loaded and has not yet reached every live session, a withdrawn grant included —
    and the pass that completes after a stop always says so in one line (pre-flight N9).
12. **`run` takes a context.** `main` makes it from `SIGINT` and `SIGTERM`, a test from its own;
    `stdout` is swappable like `stderr`, and the listening lines print the bound addresses, so a
    test can start `port49d` on port 0 and find it.
13. **What a refresh leaves alone:** a context with no blob (the lab's instrument answers it, plan
    4, Decided 12), a context already revoked (a refresh never lifts a mark, spec §5.6), and one
    another principal's login has taken since the index was read (its own principal's pass
    reaches it). Receipts are not deleted on a revoke: a retransmission answered while the context
    it names is revoked is already refused `credential_revoked` (spec §5.6).
14. **No lab task.** Nothing a device sees changes: the daemon's answers — a narrowed command's
    denial, `credential_revoked`, a quarantined device closed without a reply — are the ones
    plans 2–4 built and measured. No register row opens or closes.

## Pre-flight rulings folded in

The pre-flight (`.superpowers/sdd/2026-09-24-04b-live-policy/preflight-report.md`) found no
blocking item. Every ruling below was accepted and is in the tasks as written, and all were
dry-run together. Every code ruling but N5 (where `SIGHUP` is caught) has a test; the tests for
S1, S3 and S5 were run against the code without their fix and failed, which is how S5 went from
suspected to shown.

| Ruling | Where |
|---|---|
| S1 the mint's hold ends before its response is written | Decided 1; Task 4 (`broker.go`; `TestASwapDoesNotWaitForAResponseWrite`) |
| S2 the watch loads the bytes its two reads agreed on; write atomically | Decided 2; Task 6 (`poll`, `load`; `TestTheWatchLoadsTheBytesItsReadsAgreedOn`); `BrokerConfig`; spec §5.1.3; operator notes |
| S3 a busy context is revoked anyway or left for the retry, and the pass goes on | Decided 9; Task 5 (`refreshContext`, `refreshContexts`; `TestABusyContextDoesNotStopTheRefresh`, `TestABusyContextIsRevokedAnyway`); spec §5.1.3 and §14 |
| S4 `port49_policy_refresh_pending` | Decided 11; Task 6; design §12; spec §5.1.3; operator notes |
| S5 a superseded policy is judged at every expiry in its span | Decided 7; Task 5 (`Prior.Until`, `instants`; `TestASupersededPolicyIsJudgedAtEveryExpiryItSpanned`); Task 6 (the reloader closes a span at the swap); spec §5.1.3 and §14 |
| S6 §5.7's two `refresh` carve-outs; the fault line names the `ctx_id` | Decided 6; Task 1; Task 5 |
| N1, N2 the `SetContextPolicy` comment; `crypt.go`'s hunk keeps `DeleteContext`'s doc | Task 2 |
| N4 a login whose index write failed is invisible to the refresh | Task 8, handed to plan 6 |
| N5 `SIGHUP` is caught first thing in `run` | Decided 2; Task 6 |
| N6 a policy file someone else could have written is refused, at start and at a reload | Decided 3; Task 1 (spec §5.1.3, §14; design §12, §13); Task 4 (`readPolicyFile`, the lab harness); Task 6 (`policyVersion`); operator notes |
| N7 a refusal is one line | Decided 3; Task 6 (`oneLine`; `TestARefusalIsOneLine`) |
| N8 the refresh's process-log lines stay on `log.Printf` | Decided 6 (accepted as is) |
| N9 the pass after a stop says it finished | Decided 11; Task 6 |
| N10 the whole §14 clamp assertion, end to end | Task 7 (a lowered `max_privilege`, then `privilege_exceeded` at 15 and a permit at 1) |
| N11 `credential_revoked` from a routine edit | What the operator sees; operator notes |
| D5 design §12 rows for a refused file and an incomplete refresh | Task 1 |

## Questions for Ryan

None blocks a task; each has a recommendation the plan implements as written.

1. **Should a reload delete unspent tokens whose answer changed?** The cost: an operator who ran
   `port49 token` before an edit that changed their answer on a device gets `token_not_found` at
   the next login there, and runs it again. The alternative keeps every token and accepts that a
   withdrawn grant comes back for up to `token_ttl` (at most 900s) on any device where the
   operator had no live context — a PERMIT after the edit, from a token minted before it.
   *Recommendation:* delete (Decided 7). Only keys whose answer changed are cleared, so an edit to
   one subject costs no one else a re-mint.
2. **Should every reload rewrite every live context, or only those whose decision changed?** Every
   edit changes the bundle, so every blob hash changes. Rewriting all of them costs one store
   write and one `refresh` record per live context per reload; rewriting only changed decisions
   leaves every later command record naming a bundle that is no longer in force, which an auditor
   reads as "decided by a policy that had been replaced". *Recommendation:* rewrite all (Decided
   5); the log volume is one line per operator per edit.
3. **Should a context on a device the new policy quarantines be revoked, or left?** Left, the
   device's connections are closed without a reply until the fix lands, and the refresh that lifts
   the quarantine brings the context forward with no new login. Revoked, every operator on the
   device must log in again once it is fixed — a logout the goal rules out, for a fault that is
   the policy's. *Recommendation:* leave it (Decided 8).

## What the operator sees

The owner's rule: trace a mechanism on a bad day first. `port49d`'s lines go to stderr, the
decision log to stdout.

- **An edit that loads:** `port49d: policy reloaded (file changed): sha256:<new> replaces
  sha256:<old>; 0 device(s) quarantined now, 0 before`, the quarantine and rule lines a start
  prints, then `port49d: policy refresh: 12 live context(s) updated, 1 revoked, 0 unchanged, 0
  left on quarantined devices, 0 failed; unspent tokens superseded on 2 (device, username)
  key(s)`. The decision log has one `refresh` record per context changed.
- **An edit that does not load:** `port49d: policy reload (file changed) refused; still serving
  sha256:<old>: broker.policy_file /etc/port49/policy.yaml: roles: "root" is not a privilege
  level…` — once, however long the file stays broken. `port49_policy_file_refused` is 1; alert on
  it. Fix the file or put it back: `port49d: policy: broker.policy_file … is the policy in force
  again`, and the gauge returns to 0.
- **A policy file someone else could have written:** at start, `port49d: broker.policy_file
  /etc/port49/policy.yaml: the file /etc/port49/policy.yaml is mode -rw-rw-rw-, writable by others
  than its owner; whoever can write the policy decides every operator's access - chmod go-w it`,
  and `port49d` does not start. At a reload the same words follow `refused; still serving
  sha256:<old>:`, once, with `port49_policy_file_refused` at 1; `chmod go-w` is a change the watch
  sees, and the file then loads.
- **The store down during a reload, or failing half-way through a refresh:** `port49d: policy
  refresh stopped (3 live context(s) updated, … so far): refreshing live contexts: <error>; the
  contexts not reached keep their previous policy; trying again in 30s`, and
  `port49_policy_refresh_pending` is 1 — alert on it. The new policy is in force for every mint;
  the retry finishes the job once the store answers, says `port49d: policy refresh finished: …`,
  and the gauge returns to 0.
- **An operator whose grant was withdrawn, at their next command:** `% port49: this session was
  revoked - log in again` on the device; in the log, `authorize_command deny credential_revoked`
  naming their `ctx_id`, and before it `refresh deny no_grants_matched` naming the same `ctx_id`
  and the bundle that withdrew it. `port49 token` for that device answers `no_grants_matched`.
  `credential_revoked` is alertable as an incident signal (spec §5.7), and a routine edit now
  produces it too: the `refresh deny no_grants_matched` record naming the same `ctx_id` is what
  tells a withdrawn grant from a revoked credential, so an alert rule can leave those out.
- **A narrowed or lowered operator:** the next command outside the new rules is denied as any
  denial is; a lowered `max_privilege` shows as `privilege_exceeded`, and the `refresh` record
  before it carries `session.privilege_clamped` from and to.
- **A withdrawn or narrowed operator on Junos (final-review I1):** Junos never asks port49 about
  a command (spec §13 decision 21), so the live shell keeps the access it had at login until
  logout. The context is still revoked or rewritten, for the next login, and the refresh line
  says so: `… 1 revoked, …; 1 of them on platforms that do not authorize commands keep their
  live session until logout (spec §13 decision 21); …`, with a `broker: refresh:` line naming the
  device and `ctx_id`. Close that session on the device itself.
- **An inventory edit followed by `SIGHUP`:** `port49d: inventory_file … has changed since start
  and is not reloaded (plan 6); … restart port49d to apply it`.

## Written against `main` after the gate rulings

This plan was first written against `11f02c0` and rebased when PR #11 (`feature/gate-rulings`)
merged as `e10ab29`; every block below is written against `e10ab29` and applies with no
hand-resolution. What the rebase changed, so a reader of the first version is not surprised:

- **Spec §13.** PR #11 took decision 23 (`operator` renders as `admin`'s level on EOS and NX-OS),
  so this plan's decision is **24**.
- **`cmd/port49d/broker_test.go` (Task 4).** PR #11 moved the two port49d quarantine tests from
  `operator` to a declared `unmapped` level (`unmappedLevel`); Task 4 applies only its renames to
  them (`pol` to `b`, `pol.Quarantined` to `b.Policy.Quarantined`).
- **`cmd/port49d/main.go` (Tasks 6 and 7).** PR #11 added `"strings"` and the `LAB MODE` line
  (`labWarning`, printed first in `run`). Task 6 drops only `"slices"`; Task 7 keeps
  `labWarning` and its print in the new `run(parent context.Context, …)`. `writeRunConfig` has
  no `lab:` block, so the end-to-end test never prints the `LAB MODE` line.
- **No test here depends on how `operator` renders.** The one refresh test that needs a
  quarantine lands a subject at a declared level no built-in platform renders
  (`TestARefreshLeavesAQuarantinedDevicesContextAlone`), the mechanism PR #11's own tests use.

Nothing in this plan touches the policy tests' grammar (`level:`, `report:`), `policy diff`, or
the dialect table.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.22+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–4, and still binding:

- **Every context write outside login goes through a narrow setter.** This plan adds the fifth,
  `SetContextPolicy`, and nothing re-puts a context it read.
- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row.**
- **A blob fails closed; one decision has one hash; no metric label names a device; nothing logs a
  token** (plan 3's hardening, kept).

New in this plan:

- **No new reason code.** One new event, `refresh`, added to spec §5.7 in Task 1 before any code
  emits it (Task 5).
- **Code is applied as written.** Whole new files are given whole; a change to an existing file is a
  unified diff, applied with `git apply` from the repository root (save the block to a file, or
  pipe it). A hunk that does not apply means the tree is not where this plan expects: stop and say
  so rather than editing by hand.
- **No new dependencies.**
- Branch `feature/live-policy`; never commit code to `main`.
- Every verification runs `make test && make vet`, `go test -race ./internal/... ./cmd/...`,
  `go vet -tags lab ./tests/lab/...`, and `make build`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

---

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md    MOD  §5.1.3 "Policy reload"; §5.6 row 2; §5.7 refresh event, carve-outs + four rows; §13 decision 24; §14 (Task 1)
docs/design/2026-08-21-port49-design.md         MOD  §12 two failure rows; §13 the policy file is a privilege (Task 1)
internal/store/store.go                         MOD  ContextPolicy; Store.SetContextPolicy (Task 2)
internal/store/memory/memory.go                 MOD  SetContextPolicy
internal/store/memory/memory_test.go            MOD
internal/store/crypt/crypt.go                   MOD  SetContextPolicy passes through
internal/store/crypt/crypt_test.go              MOD
internal/daemon/authen/authen_test.go           MOD  noStore gains the method
internal/policy/live.go                         NEW  Live; Policy.NextChange, Principals, UsernameOf (Task 3)
internal/policy/live_test.go                    NEW
internal/broker/broker.go                       MOD  Broker.Policy is a *policy.Live; a request holds one version (Task 4)
internal/broker/server.go                       MOD  Server returns its refusal
internal/broker/{engine,fixture,server}_test.go MOD
cmd/port49d/main.go                             MOD  buildBroker returns the broker; loadPolicy, parsePolicy, sayPolicy (Task 4); SIGHUP, the reloader (Task 6); run(ctx), stdout, bound addresses (Task 7)
cmd/port49d/broker_test.go                      MOD  (Tasks 4, 7)
cmd/port49d/policyfile.go                       NEW  readPolicyFile: refuse a policy file others could write (Task 4)
cmd/port49d/policyfile_test.go                  NEW
tests/lab/harness_test.go                       MOD  port49d gets a private copy of its policy file (Task 4)
tests/lab/README.md                             MOD  the by-hand run makes the policy file safe (Task 4)
internal/decision/reasons.go                    MOD  EventRefresh (Task 5)
internal/daemon/metrics/metrics.go              MOD  ContextRefreshes, TokensSuperseded (Task 5); PolicyReloads, PolicyFileRefused, PolicyRefreshPending (Task 6)
internal/daemon/metrics/metrics_test.go         MOD
internal/broker/refresh.go                      NEW  Prior (At, Until), RefreshReport, Refresh (Task 5)
internal/broker/refresh_test.go                 NEW
internal/config/config.go                       MOD  broker.policy_watch_interval (Task 6)
internal/config/broker_test.go                  MOD
cmd/port49d/reload.go                           NEW  reloader (Task 6)
cmd/port49d/reload_test.go                      NEW
cmd/port49d/run_test.go                         NEW  port49d with no lab: block, end to end through a live edit (Task 7)
docs/superpowers/plans/README.md                MOD  plan 4b as built; hands to 6, 7 (Task 8)
```

Eight tasks: **one docs task first** (Task 1: the spec says what the code will do), **six code
tasks** (2–7), and **one docs task last** (Task 8: the roadmap). Tasks 2 and 3 add mechanism with
no caller; Task 4 puts the broker on `policy.Live` with nothing swapping it yet; Task 5 adds the
refresh with nothing calling it; **Task 6 is the switch**, after which an edit to the file reaches
live sessions; Task 7 proves it end to end through `run`. Every task leaves `make test` green.

---
### Task 1: The spec says what a live reload does, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.1.3, §5.6 teardown row 2, §5.7 events,
  the two `refresh` carve-outs from "every evaluation emits exactly one record" and four reason
  rows, §13 decision 24, §14 "Session lifetime and revocation")
- Modify: `docs/design/2026-08-21-port49-design.md` (§12 "Policy file refused" and "Policy refresh
  incomplete" rows; §13 "The policy file is a privilege")

**Interfaces:**
- Produces: the §5.7 `refresh` event Task 5 emits, and the reason rows it emits under; §5.1.3's
  "Policy reload", which every later task implements a paragraph of — including the agreed-bytes
  rule and atomic writes (Task 6), the policy file's permissions (Tasks 4 and 6), the busy
  context and the span a superseded policy is judged over (Task 5), and
  `port49_policy_refresh_pending` (Task 6); decision 24; the §14 assertions Tasks 2–7 test.

Why first: a new event is added to the spec table before any code names it (`CLAUDE.md`, and plan
4's practice for `blob_platform_mismatch`), and §5.1.3 as written describes only plan 7's
directory refresh.

- [ ] **Step 1: Apply the spec and design edits**

<!-- patch: docs/design/2026-08-23-policy-engine-spec.md -->
```diff
diff --git a/docs/design/2026-08-23-policy-engine-spec.md b/docs/design/2026-08-23-policy-engine-spec.md
index d604973..503d60a 100644
--- a/docs/design/2026-08-23-policy-engine-spec.md
+++ b/docs/design/2026-08-23-policy-engine-spec.md
@@ -587,6 +587,86 @@ This also makes **policy-driven revocation reach active sessions**, not only dir
 revocation. A policy change that removes a grant produces a different blob, and live contexts
 pick it up on the next refresh.
 
+#### Policy reload
+
+A policy edit reaches every live session **without anyone logging out** (plan 4b). The file is
+read on a timer and on `SIGHUP`, and a change is handled in four steps:
+
+1. **Validate or keep the old.** The new file is loaded against the inventory exactly as at
+   start. A file that does not load is refused: the policy in force keeps serving, the refusal
+   is logged once with the reason and the bundle still serving, and
+   `port49_policy_file_refused` holds at 1 until a file loads or the old one is put back. A typo
+   never takes the fleet down. Nothing is half-applied. A change the timer finds is loaded once
+   two reads in a row agree, and what is loaded is the bytes those two reads agreed on; a
+   `SIGHUP` loads what is on disk at once. Either way a file must be written atomically (a
+   temporary file renamed over it): a writer stalled part-way for two intervals, or a `SIGHUP`
+   sent mid-write, loads what is there, and a list cut short can load wider than the one
+   intended.
+
+   **Whoever can write the policy decides every operator's access,** so a policy file anyone
+   else could have written is refused like one that does not load, at start as at a reload: a
+   file that is group- or world-writable, or whose directory is, or that is owned by neither
+   the user `port49d` runs as nor root. At start `port49d` does not start; at a reload the
+   policy in force keeps serving. The check follows symlinks — it is the file actually read,
+   and the directory holding it, that must be safe — so a Kubernetes ConfigMap mount, whose
+   files and the directory holding them are root's and not group- or world-writable, passes.
+2. **Swap.** The loaded policy replaces the one in force in one step, so no mint sees one
+   version's grants and another's quarantine. A mint in flight finishes on the policy it
+   started with, and the swap waits for it.
+3. **Re-run the joint checks.** The new policy's quarantine schedule, grant expiries included,
+   replaces the old one whole (§10): a fix releases a device and a new failure quarantines one,
+   with no restart, and the daemon closes a newly quarantined device's connections without a
+   reply as it does at start.
+4. **Refresh.** Every live context is re-resolved against the new policy for its principal on
+   its device, and the answer is written into it by compare-and-set on the revision that was
+   read: the blob hash, the privilege ceiling (a held level above a lowered ceiling comes down
+   to it, as at a join, §5.3) and the `enable` mechanism. A principal left with no grant on
+   the device has that context **revoked** instead (§5.6 row 2), and its next command is
+   denied `credential_revoked`. A context on a device quarantined now is left as it is until
+   the refresh that lifts the quarantine. A narrowed rule denies the next command and a widened
+   one permits it; a widened *level* reaches the device only at the next session authorization
+   or `enable`, where levels are granted. `auth_time`, `session_expires`, `refreshed_at` and the
+   idle TTL are not touched: nothing about the operator's authentication or the directory was
+   re-verified, and a reload is not activity.
+
+Every edit changes the bundle (§5.7), so every live context takes a new blob at a reload and
+the records decided after it name the policy that was in force. A change the refresh makes is a
+`refresh` decision record (§5.7) naming the context's `ctx_id`, so the record before a
+command's changed answer says why.
+
+**Unspent tokens are the other half.** A token carries the blob, ceiling and `enable`
+mechanism of the policy that minted it, and a redemption writes them into the context it
+creates or joins. So the refresh also deletes, per `(device, username)`, the unspent tokens a
+superseded policy minted and the policy in force would not mint identically — otherwise a grant
+removed at 10:00 returns at 10:05 on a device where the operator had no context yet, from a
+token minted at 09:58. A token whose answer is unchanged, the bundle aside, is kept: a reload is
+not a reason to make everyone mint again. A login in flight across the swap may still write the
+superseded answer after the refresh has passed its context, so the refresh runs again a short
+settle interval after every reload.
+
+**A grant's expiry is a scheduled edit.** A resolution changes with no edit to the file when a
+grant expires (§5.1), so the refresh also runs at every expiry instant; otherwise a live context
+would keep an expired grant's rules until the next edit.
+
+**The store down during a reload** does not stop the swap: the new policy is in force for every
+mint at once (and every mint fails `store_unavailable` until the store answers). The refresh
+stops at its first store error, says how far it got, and runs again until it finishes; a
+context not yet reached keeps its previous policy until then, and
+`port49_policy_refresh_pending` holds at 1 from the swap until a pass completes — the alert for
+a policy in force that has not yet reached every live session. The directory-driven scheduled
+refresh through `active_principals` is plan 7's.
+
+**A context that keeps changing does not stop the pass.** A write landing between the
+refresh's read and its compare-and-set sends it back to read again, a bounded number of times.
+A context still changing after that is left for the retry and the pass goes on to the next,
+so one busy session cannot hold every session after it on the superseded policy. A
+revocation is not left: it is written unconditionally (`revoked_at` alone), failing closed.
+
+**A superseded policy's tokens are judged across the whole time it was in force.** A token
+it minted carries the answer at the instant of the mint, and that answer changes at each grant
+expiry inside the span, so the comparison is made at the start of the span and at every expiry
+within it; a key is cleared if any of those answers differs from the policy in force.
+
 ### 5.1.4 Credential identity and revocation
 
 Login context records which credential authorized it. Not to re-verify — **the daemon never
@@ -1185,7 +1265,7 @@ did not generate and cannot verify MUST NOT delete state.
 | | Trigger | Authority |
 |---|---|---|
 | 1 | **Login redemption** on the same `(nas, username)` | port49 performed it — joins the same principal's live context and replaces another principal's, logging the replace (above). An `enable` redemption is not this: it updates `privilege` in place and keeps `ctx_id` (§7). **That is a requirement on plan 2's escalate path, not a description of the tree** — see below |
-| 2 | **Revocation** — OIDC back-channel logout by `sid` or `sub`; a certificate appearing on a CRL or OCSP response by issuer and serial; a policy change withdrawing every grant | authoritative, from the identity layer (§5.1.4). Sets `revoked_at` rather than deleting, so the next command is denied `credential_revoked` with a `server_msg` saying so — distinguishable from a session port49 never saw. Row 6 reclaims the state |
+| 2 | **Revocation** — OIDC back-channel logout by `sid` or `sub`; a certificate appearing on a CRL or OCSP response by issuer and serial; a policy change withdrawing every grant on the device (§5.1.3, "Policy reload") | authoritative, from the identity layer (§5.1.4). Sets `revoked_at` rather than deleting, so the next command is denied `credential_revoked` with a `server_msg` saying so — distinguishable from a session port49 never saw. Row 6 reclaims the state |
 | 3 | **Session ceiling** — `session_expires` reached and the grace window elapsed | local, needs no external signal |
 | 3a | **Staleness ceiling** — `now - refreshed_at` beyond `staleness_ceiling` because the broker has been unreachable that long (design document §9) | local; denies `context_stale` with a `server_msg` naming the broker outage, retains the context so recovery resumes it |
 | 4 | **Username mismatch** on an enable exchange resolved through `(nas, rem_addr)` | a genuine conflict — denies and invalidates. On the command path this cannot arise: the username is the key |
@@ -1393,6 +1473,12 @@ component that made the decision, and it is distinct from the accounting records
 sends — those report what a device *did*, after the fact, only for the tiers it was
 configured to report. The decision log records what port49 *decided*, for whom, and against
 which rule. It is complete by construction, because every decision passes through us.
+Two carve-outs, both on the `refresh` event (§5.1.3): a refresh that finds a context already
+on the answer the policy in force gives writes nothing and records nothing — at every reload
+that is one record per live session saved, and there is nothing to explain — and a refresh
+that revokes a context because the broker could not resolve or compile its policy is a fault,
+not a decision: the process log names the context's `ctx_id` and the fault, and it is counted
+`failed`, as a mint item error is.
 
 > **A decision record must be replayable.**
 
@@ -1462,7 +1548,7 @@ of the product, not a problem to optimize away.
 
 #### Events
 
-One envelope. Five decision events, one at each point a decision is made, plus two report
+One envelope. Six decision events, one at each point a decision is made, plus two report
 events (`account`, `blob`) that share the envelope and carry no verdict:
 
 | `event` | Emitted by | Decides |
@@ -1472,6 +1558,7 @@ events (`account`, `blob`) that share the envelope and carry no verdict:
 | `authorize_session` | daemon | the session and its returned attributes (§6) |
 | `authorize_command` | daemon | one command vector |
 | `escalate` | daemon | an `enable` exchange, attributed to the principal (§7) |
+| `refresh` | broker | whether a live context takes the policy now in force, or is revoked (§5.1.3) |
 | `blob` | broker | not a decision: the full compiled blob, emitted once per hash so replay depends on the log alone (§5.1.1) |
 
 Device accounting shares this envelope as the seventh event, `account`, and is specified in
@@ -1519,8 +1606,8 @@ not an unvalidated body. A connection with no verified chain names no one.
 
 | `reason` | Meaning |
 |---|---|
-| `grants_matched` | `mint`: at least one declared grant selected the device; blob written |
-| `no_grants_matched` | `mint`: no declared grant for this principal selects the device |
+| `grants_matched` | `mint`: at least one declared grant selected the device; blob written. `refresh`: the policy in force was written into the live context |
+| `no_grants_matched` | `mint`: no declared grant for this principal selects the device. `refresh`: none does any more, and the live context is revoked |
 | `username_collision` | `mint`: the derived username is already held by a subject in another trust domain (§2) |
 | `trust_domain_unresolved` | `mint`: no configured verifier accepted the credential (design document §7) |
 | `candidate_cap_reached` | `mint`: `token.candidate_cap` unspent tokens already stand for this `(device, username)`; the mint is refused, never a redemption, and every token already issued stays usable (design document §8) |
@@ -1547,12 +1634,12 @@ not an unvalidated body. A connection with no verified chain names no one.
 | `privilege_exceeded` | the request is above the session's granted level |
 | `session_expired` | the session ceiling was reached; context retained through the grace window (§5.6). On `mint`: the held connection's authentication is older than `max_session_age`, and the caller must authenticate again (§13, decision 17) |
 | `context_stale` | the broker has been unreachable past `staleness_ceiling`; context retained, denies until refreshed (§5.1.1, design document §9) |
-| `credential_revoked` | the context's `revoked_at` is set — CRL, OCSP, back-channel logout, or every grant withdrawn (§5.6); on `redeem`, a login whose resulting context is revoked because its token was not minted after the revocation, or a retransmission answered while the context it names is revoked (§5.6) |
+| `credential_revoked` | the context's `revoked_at` is set — CRL, OCSP, back-channel logout, or every grant on the device withdrawn (§5.1.3, §5.6); on `redeem`, a login whose resulting context is revoked because its token was not minted after the revocation, or a retransmission answered while the context it names is revoked (§5.6) |
 | `device_unknown` | the source address is not in the admission trie (§10) |
 | `platform_unknown` | the device's platform has no adapter; generic fallback applied |
 | `blob_unavailable` | the referenced blob could not be resolved from the store or any cache — a store fault, alarmed (§5.1.1) — or the context no longer fits the blob: a session attribute filled from it exceeds 255 bytes, or a filled-in value carries a separator (`=`, `*`) or a control character, either of which the broker refused at mint (§6), or the reply would send a `priv-lvl` above the context's `max_privilege`, a composition the load quarantines (§7) |
 | `blob_platform_mismatch` | the context's blob was compiled for a platform other than the one inventory gives the device — inventory changed since the mint, or the broker and the daemon read different inventories. Its dialect and attributes are another platform's, so it is never answered from; operational, alertable beside `blob_unavailable` |
-| `device_quarantined` | the device is in inventory but failed joint validation against policy (§10); the connection is closed without a reply, as for `device_unknown`, until fixed |
+| `device_quarantined` | the device is in inventory but failed joint validation against policy (§10); the connection is closed without a reply, as for `device_unknown`, until fixed. On `refresh`, the live context is left as it was until the quarantine lifts |
 
 Every event has a success reason and at least one failure reason in this table, so
 "decisions by event, verdict, and reason" (design document §15) is a complete metric. A
@@ -4091,6 +4178,15 @@ policy landed there. `operator` gets level 15 on both, port49's per-command rule
 fence, and the device's method list must not fall back to `none` or `if-authenticated`.
 IOS-XE, whose level 7 can carry the rung, is left to plan 5's adapters. (§6, §8)
 
+**24. A policy edit reaches live sessions without a logout.** A restart ends every live
+context and every unspent token, so without a live reload the only way to narrow an operator's
+access was to log everyone out — and the edit most in need of reaching a live session, a grant
+withdrawn, was the one that could not. The file is reloaded in place, refused whole if it does
+not load, and carried into every live context by compare-and-set: a narrowing or a widening
+applies from the next command, and a principal with no grant left on a device has that context
+revoked. Unspent tokens whose answer changed are deleted, because a redemption would otherwise
+write the superseded answer into a fresh context. (§5.1.3)
+
 ### Deferred, with reasons
 
 Neither of these is an open question about the design. Both are closed for v1 on the
@@ -4313,6 +4409,29 @@ Beyond those already listed in the design document's §14:
   without a reconnect, and the next command authorizes.
 - **Refresh re-resolves policy**: a principal whose grant was withdrawn cannot extend a
   session into continued access.
+- **Policy reload reaches a live session with no logout**: an edit narrowing a role denies the
+  next command in the same context, `ctx_id` unchanged; one widening it permits the next
+  command; one withdrawing the principal's grant on the device marks the context revoked and
+  the next command is denied `credential_revoked`; a lowered `max_privilege` lowers the held
+  level, and the next command above it is denied `privilege_exceeded`.
+- **A policy that does not load is refused whole**: the policy in force keeps serving, the
+  refusal is logged once and counted, and `port49_policy_file_refused` is 1 until a file loads
+  or the old one is put back.
+- **Superseded tokens are deleted and unchanged ones kept**: after an edit, an unspent token
+  whose answer changed no longer redeems, and one whose answer did not still does.
+- **A refresh loses a race safely**: a write landing on a context between the refresh's read
+  and its write is kept, and the refresh reads again and writes the new policy beside it.
+- **A grant's expiry reaches a live context** at the expiry instant, with no edit.
+- **A policy file someone else could have written is refused**: group- or world-writable, a
+  group- or world-writable directory, or an owner other than `port49d`'s user or root refuses
+  the start, and at a reload keeps the policy in force serving, logged once and counted
+  `refused`; the check follows a symlink to the file it reads.
+- **A superseded token is judged at every instant it could have been minted**: a token minted
+  after a grant's expiry under the policy since replaced is deleted when its answer differs,
+  though the answer before the expiry did not.
+- **A busy context does not stop a refresh**: a context whose every compare-and-set conflicts
+  is counted failed, or revoked unconditionally where the answer is a revocation, and every
+  context after it is still refreshed.
 - **Grace window**: a command past the ceiling is denied with `session_expired` while context
   is retained; a re-auth inside the grace window resumes the same session; past it, context is
   gone and the reason becomes `context_missing`.
```

<!-- patch: docs/design/2026-08-21-port49-design.md -->
```diff
diff --git a/docs/design/2026-08-21-port49-design.md b/docs/design/2026-08-21-port49-design.md
index 8c68a8e..03e6673 100644
--- a/docs/design/2026-08-21-port49-design.md
+++ b/docs/design/2026-08-21-port49-design.md
@@ -1108,6 +1108,8 @@ silently engages is indistinguishable from a bug.
 | **Operator credential lost** | ✗ | ✗ | ✓ existing logins persist | ✗ |
 | **Inventory service unavailable** | ✓ | ✓ last good snapshot | ✓ | ✓ |
 | **Device presents a retired or wrong key** | ✗ that device only | ✗ → device-local break-glass | ✗ | ✗ |
+| **Policy file refused** (does not load, or someone else could have written it; policy engine spec §5.1.3) | ✓ | ✓ on the policy in force | ✓ on the policy in force | ✓ on the policy in force. The edit is not live: `port49_policy_file_refused` is 1 and one line says why |
+| **Policy refresh incomplete** (the store failed part-way through carrying a reload into live sessions) | ✓ | ✓ on the new policy, once the store answers | ⚠ a context not yet reached keeps its previous policy — a withdrawn grant included — until the refresh, retried every 30s, reaches it; `port49_policy_refresh_pending` is 1 | ✓ on the new policy |
 
 ### Consequences
 
@@ -1266,6 +1268,12 @@ than per login; and contexts are small, so caching them is cheap. But a cold rep
 the first command of a login will see the round trip, and the target should be understood as
 holding in steady state rather than at every instant.
 
+**The policy file is a privilege.** `port49d` reloads `broker.policy_file` live, so whoever can
+write it decides every operator's access within seconds. The file and the directory holding it
+MUST be writable by `port49d`'s user or root alone; `port49d` refuses one that is not, at start
+and at every reload (policy engine spec §5.1.3). Write it atomically, by renaming a complete
+file over it.
+
 **Independently upgradeable server groups.** Deployments SHOULD present two server groups
 that are independently deployed and independently upgraded, with devices configured to use
 both. Network-layer failover cannot detect a build that passes health checks but fails
```

- [ ] **Step 2: Check it landed**

Run: `grep -n '^#### Policy reload\|^| .refresh. | broker\|^\*\*24\. \|Policy reload reaches a live session\|^Two carve-outs, both on\|Whoever can write the policy decides' docs/design/2026-08-23-policy-engine-spec.md`
Expected: six lines — the §5.1.3 heading, the permissions paragraph, the §5.7 carve-outs, the
§5.7 event row, decision 24, the §14 assertion.

Run: `grep -n '^| \*\*Policy file refused\*\*\|^| \*\*Policy refresh incomplete\*\*\|^\*\*The policy file is a privilege\.\*\*' docs/design/2026-08-21-port49-design.md`
Expected: three lines — the two §12 rows and the §13 requirement.

- [ ] **Step 3: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: the spec says what a live policy reload does, before the code does

Spec §5.1.3 gains 'Policy reload': validate or keep the old, swap, re-run
the joint checks, refresh every live context by compare-and-set, revoke
where no grant is left, and delete unspent tokens whose answer changed.
A change is loaded from the bytes two reads agreed on, and the file must
be written atomically; a policy file anyone but port49d's user or root
could have written is refused, at start and at a reload. A busy context
does not stop a pass, and a superseded policy is judged across its span.
§5.7 gains the refresh event, its two carve-outs from 'every evaluation
emits exactly one record', and four reason rows say what they mean on it.
§5.6 row 2, §13 decision 24 and §14's assertions follow. Design §12
gains the refused-file and incomplete-refresh rows; §13 says the policy
file is a privilege.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 2: `SetContextPolicy`, the refresher's compare-and-set setter

**Files:**
- Modify: `internal/store/store.go`, `internal/store/memory/memory.go`, `internal/store/crypt/crypt.go`
- Test: modify `internal/store/memory/memory_test.go`, `internal/store/crypt/crypt_test.go`,
  `internal/daemon/authen/authen_test.go`

**Interfaces:**
- Produces:
  - `type ContextPolicy struct { RevokedAt time.Time; BlobHash string; MaxPrivilege uint8; Enable string }`
    in package `store`.
  - `Store.SetContextPolicy(ctx context.Context, k ContextKey, rev uint64, p ContextPolicy) error` —
    `ErrConflict` if the revision moved, `ErrNotFound` if absent or expired; with `RevokedAt` set it
    writes that alone, otherwise the other three fields, lowering `PrivLvl` to a new ceiling; it
    moves the revision and never the expiry, `LastTouchedAt`, `AuthTime`, `SessionExpires` or
    `RefreshedAt`.
  - `crypt`'s wrapper passes it through: every field it reads or writes is plaintext.

Every writer of a live context outside login is a narrow setter (plan 2b), so the refresh gets
one of its own; Decided 4 says why it is also a compare-and-set, and why `RefreshContext` and
`SwapContext` are not reused.

- [ ] **Step 1: Write the failing tests**

The memory store's test is the contract: it seeds a field of every other writer's, lands a write
between the read and the refresh, and checks the closed list, the clamp, the revocation and the
expiry. The sealing layer's test runs the compare-and-set through `crypt`. `authen`'s `noStore`
implements every method by hand, so it gains this one.

<!-- patch: internal/store/memory/memory_test.go -->
```diff
diff --git a/internal/store/memory/memory_test.go b/internal/store/memory/memory_test.go
index f588d3b..5b21a5a 100644
--- a/internal/store/memory/memory_test.go
+++ b/internal/store/memory/memory_test.go
@@ -1064,6 +1064,10 @@ func TestEveryContextWriteMovesTheRevision(t *testing.T) {
 			return s.RefreshContext(ctx, k, store.ContextRefresh{AuthTime: now, RefreshedAt: now}, time.Hour)
 		}},
 		{"SetRevokedAt", func() error { return s.SetRevokedAt(ctx, k, now) }},
+		{"SetContextPolicy", func() error {
+			c, _ := s.GetContext(ctx, k)
+			return s.SetContextPolicy(ctx, k, c.Rev, store.ContextPolicy{BlobHash: "sha256:b", Enable: "none"})
+		}},
 	} {
 		before, _ := s.GetContext(ctx, k)
 		if err := w.write(); err != nil {
@@ -1254,3 +1258,79 @@ func TestUnindexRefClearsEveryKeyRecordedForTheRef(t *testing.T) {
 		t.Fatalf("another ref under the same sid must be left alone: %v", r)
 	}
 }
+
+// SetContextPolicy is the refresher's setter (spec §5.1.3): a compare-and-set
+// on the revision the refresher read, writing its closed list and nothing
+// else. The seed carries a field of every other writer's — the annotation,
+// the discriminators, the clocks — so a write that strayed shows.
+func TestSetContextPolicyWritesItsListOnlyIfTheRecordIsTheOneRead(t *testing.T) {
+	now := time.Unix(1000, 0)
+	s := New(func() time.Time { return now })
+	ctx := context.Background()
+	k := store.ContextKey{NAS: "n", Username: "u"}
+	seed := store.Context{CtxID: "c", Principal: "p", Username: "u", PrivLvl: 15, MaxPrivilege: 15,
+		Enable: "token", BlobHash: "sha256:old", AuthTime: now.Add(-time.Hour),
+		SessionExpires: now.Add(7 * time.Hour), RefreshedAt: now.Add(-time.Hour),
+		SessionDiscriminators: []string{"h"}, AccountingState: store.AccountingStateOpen}
+	s.PutContext(ctx, k, seed, time.Minute)
+	read, _ := s.GetContext(ctx, k)
+
+	// A write that lands between the read and the refresh moves the revision,
+	// and the refresh is refused with nothing written.
+	if err := s.AnnotateContext(ctx, k, "", store.AccountingStateClosing); err != nil {
+		t.Fatal(err)
+	}
+	if err := s.SetContextPolicy(ctx, k, read.Rev, store.ContextPolicy{BlobHash: "sha256:new", Enable: "none"}); !errors.Is(err, store.ErrConflict) {
+		t.Fatalf("a revision that moved must conflict: %v", err)
+	}
+	if got, _ := s.GetContext(ctx, k); got.BlobHash != "sha256:old" {
+		t.Fatalf("a refused refresh wrote: %+v", got)
+	}
+
+	// Read again, write again: the three fields land, and a held level above
+	// the new ceiling comes down to it.
+	stamped := now
+	now = now.Add(30 * time.Second)
+	read, _ = s.GetContext(ctx, k)
+	if err := s.SetContextPolicy(ctx, k, read.Rev, store.ContextPolicy{BlobHash: "sha256:new", MaxPrivilege: 7, Enable: "none"}); err != nil {
+		t.Fatal(err)
+	}
+	got, err := s.GetContext(ctx, k)
+	if err != nil {
+		t.Fatal(err)
+	}
+	if got.BlobHash != "sha256:new" || got.MaxPrivilege != 7 || got.Enable != "none" || got.PrivLvl != 7 {
+		t.Fatalf("the refresh did not land, or did not clamp: %+v", got)
+	}
+	if got.CtxID != "c" || got.Principal != "p" || !got.AuthTime.Equal(seed.AuthTime) ||
+		!got.SessionExpires.Equal(seed.SessionExpires) || !got.RefreshedAt.Equal(seed.RefreshedAt) ||
+		!got.RevokedAt.IsZero() || len(got.SessionDiscriminators) != 1 || got.AccountingState != store.AccountingStateClosing {
+		t.Fatalf("SetContextPolicy wrote a field that is not its own: %+v", got)
+	}
+	// Not activity: the expiry and its stamp stay where they were.
+	if !got.LastTouchedAt.Equal(stamped) {
+		t.Fatalf("SetContextPolicy must not stamp LastTouchedAt: %+v", got)
+	}
+
+	// A ceiling lifted does not raise the held level: a level is granted at a
+	// session authorization or an enable, never by a refresh.
+	if err := s.SetContextPolicy(ctx, k, got.Rev, store.ContextPolicy{BlobHash: "sha256:wide", Enable: "token"}); err != nil {
+		t.Fatal(err)
+	}
+	if got, _ = s.GetContext(ctx, k); got.PrivLvl != 7 || got.MaxPrivilege != 0 {
+		t.Fatalf("a lifted ceiling must leave the level alone: %+v", got)
+	}
+
+	// A revocation writes RevokedAt and nothing else.
+	if err := s.SetContextPolicy(ctx, k, got.Rev, store.ContextPolicy{RevokedAt: now, BlobHash: "sha256:ignored"}); err != nil {
+		t.Fatal(err)
+	}
+	if got, _ = s.GetContext(ctx, k); !got.RevokedAt.Equal(now) || got.BlobHash != "sha256:wide" {
+		t.Fatalf("a revoking refresh must write the mark and only the mark: %+v", got)
+	}
+
+	now = now.Add(31 * time.Second) // past the original expiry: nothing extended it
+	if err := s.SetContextPolicy(ctx, k, got.Rev, store.ContextPolicy{BlobHash: "sha256:x"}); !errors.Is(err, store.ErrNotFound) {
+		t.Fatalf("an expired context must be ErrNotFound, not resurrected: %v", err)
+	}
+}
```

<!-- patch: internal/store/crypt/crypt_test.go -->
```diff
diff --git a/internal/store/crypt/crypt_test.go b/internal/store/crypt/crypt_test.go
index 81355dd..576ed69 100644
--- a/internal/store/crypt/crypt_test.go
+++ b/internal/store/crypt/crypt_test.go
@@ -384,3 +384,37 @@ func TestUnindexRefPassesThrough(t *testing.T) {
 		t.Fatalf("UnindexRef did not reach the inner store: %v", r)
 	}
 }
+
+// SetContextPolicy's compare-and-set survives the sealing layer: the
+// revision read through GetContext, with the principal opened, is the one the
+// inner store compares, and the fields it writes are plaintext, so the sealed
+// ones are untouched.
+func TestSetContextPolicyThroughTheSealingLayer(t *testing.T) {
+	inner := memory.New(time.Now)
+	s := Wrap(inner, keys(), nil)
+	ctx := context.Background()
+	ck := store.ContextKey{NAS: "leaf-01", Username: "alice"}
+	if err := s.PutContext(ctx, ck, store.Context{CtxID: "ctx1", Principal: "user:alice@example.com",
+		Username: "alice", PrivLvl: 15, BlobHash: "sha256:old"}, time.Hour); err != nil {
+		t.Fatal(err)
+	}
+	got, err := s.GetContext(ctx, ck)
+	if err != nil {
+		t.Fatal(err)
+	}
+	if err := s.SetRevokedAt(ctx, ck, time.Now()); err != nil {
+		t.Fatal(err)
+	}
+	if err := s.SetContextPolicy(ctx, ck, got.Rev, store.ContextPolicy{BlobHash: "sha256:new"}); !errors.Is(err, store.ErrConflict) {
+		t.Fatalf("the revision read through the sealing layer must be the one compared: %v", err)
+	}
+	got, _ = s.GetContext(ctx, ck)
+	if err := s.SetContextPolicy(ctx, ck, got.Rev, store.ContextPolicy{BlobHash: "sha256:new", MaxPrivilege: 1}); err != nil {
+		t.Fatal(err)
+	}
+	after, err := s.GetContext(ctx, ck)
+	if err != nil || after.Principal != "user:alice@example.com" || after.CtxID != "ctx1" ||
+		after.BlobHash != "sha256:new" || after.PrivLvl != 1 {
+		t.Fatalf("%+v %v", after, err)
+	}
+}
```

<!-- patch: internal/daemon/authen/authen_test.go -->
```diff
diff --git a/internal/daemon/authen/authen_test.go b/internal/daemon/authen/authen_test.go
index 1480e30..4b85e73 100644
--- a/internal/daemon/authen/authen_test.go
+++ b/internal/daemon/authen/authen_test.go
@@ -460,6 +460,10 @@ func (noStore) SetRevokedAt(context.Context, store.ContextKey, time.Time) error
 	panic("store called")
 }
 
+func (noStore) SetContextPolicy(context.Context, store.ContextKey, uint64, store.ContextPolicy) error {
+	panic("store called")
+}
+
 var _ store.Store = noStore{}
 
 func TestEmptyCanonicalUsernameFailsWithoutStoreLookup(t *testing.T) {
```

- [ ] **Step 2: Run them to see them fail**

Run: `go vet ./internal/store/... ./internal/daemon/authen/`
Expected: FAIL to build — `undefined: store.ContextPolicy`, `s.SetContextPolicy undefined`.

- [ ] **Step 3: Add the setter to the interface and both stores**

<!-- patch: internal/store/store.go -->
```diff
diff --git a/internal/store/store.go b/internal/store/store.go
index bc8486a..92e0950 100644
--- a/internal/store/store.go
+++ b/internal/store/store.go
@@ -306,6 +306,28 @@ type ContextRefresh struct {
 	BlobHash string
 }
 
+// ContextPolicy is what a policy refresh writes into a live context (spec
+// §5.1.3): the policy's answer for this principal on this device, re-resolved
+// against the policy now in force. It is a struct for the reason
+// ContextRefresh is: what SetContextPolicy may write is a closed list, and
+// naming that list in one type is what keeps it closed.
+type ContextPolicy struct {
+	// RevokedAt, when non-zero, is the whole write: the principal has no grant
+	// on this device any more, and the context is marked revoked at this
+	// instant. The fields below are then ignored — a revoked context's policy
+	// is never read again (spec §5.3).
+	RevokedAt time.Time
+	// BlobHash replaces the context's policy blob hash. It is never empty on
+	// a write that does not revoke.
+	BlobHash string
+	// MaxPrivilege replaces the context's privilege ceiling; zero is none,
+	// as on the token (Context.PrivilegeCeiling). A held level above a new
+	// ceiling is lowered to it.
+	MaxPrivilege uint8
+	// Enable replaces the enable mechanism: none | auto | token (spec §7).
+	Enable string
+}
+
 // ContextRef is what the indexes hold: the context key, nothing more.
 type ContextRef struct {
 	NAS      string
@@ -476,6 +498,36 @@ type Store interface {
 	//
 	// ErrNotFound if the key is absent or already expired.
 	SetRevokedAt(ctx context.Context, k ContextKey, at time.Time) error
+	// SetContextPolicy writes a policy refresh's answer into this context, in
+	// place and under the store's own lock, and only if the record is still
+	// the one the caller read: rev is the Rev GetContext returned, and a
+	// revision that moved is ErrConflict with nothing written (spec §5.1.3).
+	//
+	// It is the fifth narrow setter, and the only one that is also a
+	// compare-and-set. The others write a value that is right whoever the
+	// record belongs to; this one writes a value computed from who it belongs
+	// to. The refresher reads the context's principal — sealed, so the inner
+	// store cannot check it — resolves that principal on this device, and
+	// writes the answer. A login that replaced the record with another
+	// principal's in between, or joined it with a token minted under the
+	// previous policy, would otherwise be handed the wrong principal's policy
+	// or keep the superseded one. Conflict, read again, decide again.
+	//
+	// It writes a closed list: with RevokedAt set, RevokedAt alone; otherwise
+	// BlobHash, MaxPrivilege and Enable, and PrivLvl lowered to the new
+	// ceiling when it is above it — the join's rule (spec §5.3), so a lowered
+	// max_privilege reaches the next command as privilege_exceeded. It never
+	// raises PrivLvl: a widened level reaches the device only through the next
+	// session authorization or enable, which is where a level is granted.
+	//
+	// It does not extend the expiry or stamp LastTouchedAt: a policy edit is
+	// not activity, or every reload would keep every idle context alive. It
+	// does not touch AuthTime, SessionExpires or RefreshedAt: nothing about
+	// the operator's authentication or the directory was re-verified. And it
+	// never clears RevokedAt, for the reason RefreshContext never does.
+	//
+	// ErrNotFound if the key is absent or already expired.
+	SetContextPolicy(ctx context.Context, k ContextKey, rev uint64, p ContextPolicy) error
 	// DeleteContext has no production caller today: the caller it had was
 	// author's `username_mismatch` branch, which under the old `(nas, port)`
 	// key could delete a live operator's context on an uncredentialed request.
```

<!-- patch: internal/store/memory/memory.go -->
```diff
diff --git a/internal/store/memory/memory.go b/internal/store/memory/memory.go
index ff41935..215ea75 100644
--- a/internal/store/memory/memory.go
+++ b/internal/store/memory/memory.go
@@ -661,6 +661,33 @@ func (s *Store) SetRevokedAt(_ context.Context, k store.ContextKey, at time.Time
 	return nil
 }
 
+// SetContextPolicy is the refresher's setter: the compare, the write and the
+// clamp are one critical section (store.Store). It moves the revision and
+// nothing about the expiry: a policy edit is not activity.
+func (s *Store) SetContextPolicy(_ context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
+	s.mu.Lock()
+	defer s.mu.Unlock()
+	e, ok := s.contexts[k]
+	if !ok || !e.exp.After(s.now()) {
+		delete(s.contexts, k)
+		return store.ErrNotFound
+	}
+	if e.rev != rev {
+		return store.ErrConflict
+	}
+	if !p.RevokedAt.IsZero() {
+		e.c.RevokedAt = p.RevokedAt
+	} else {
+		e.c.BlobHash, e.c.MaxPrivilege, e.c.Enable = p.BlobHash, p.MaxPrivilege, p.Enable
+		if ceiling, ok := e.c.PrivilegeCeiling(); ok && e.c.PrivLvl > ceiling {
+			e.c.PrivLvl = ceiling
+		}
+	}
+	e.rev = s.nextRevLocked()
+	s.contexts[k] = e
+	return nil
+}
+
 func (s *Store) DeleteContext(_ context.Context, k store.ContextKey) error {
 	s.mu.Lock()
 	defer s.mu.Unlock()
```

<!-- patch: internal/store/crypt/crypt.go -->
```diff
diff --git a/internal/store/crypt/crypt.go b/internal/store/crypt/crypt.go
index e50b0d1..7f435d2 100644
--- a/internal/store/crypt/crypt.go
+++ b/internal/store/crypt/crypt.go
@@ -378,6 +378,17 @@ func (w *wrapped) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.
 	return w.inner.SetRevokedAt(ctx, k, at)
 }
 
+// SetContextPolicy passes through: every field it writes or compares is
+// plaintext — a revision, a timestamp, a blob hash, a ceiling, an enable
+// mechanism and the level it clamps — so the inner store can hold the
+// compare-and-set on a record whose sealed fields it cannot read, exactly as
+// SwapContext's revision does. The principal the value was computed from is
+// read up here, through GetContext, and the revision is what binds the write
+// to that read.
+func (w *wrapped) SetContextPolicy(ctx context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
+	return w.inner.SetContextPolicy(ctx, k, rev, p)
+}
+
 // DeleteContext is addressed by key alone.
 func (w *wrapped) DeleteContext(ctx context.Context, k store.ContextKey) error {
 	return w.inner.DeleteContext(ctx, k)
```

- [ ] **Step 4: Run the store and authen packages**

Run: `go test -race ./internal/store/... ./internal/daemon/authen/ && make vet`
Expected: PASS, including `TestSetContextPolicyWritesItsListOnlyIfTheRecordIsTheOneRead`,
`TestEveryContextWriteMovesTheRevision` (now with a `SetContextPolicy` row) and
`TestSetContextPolicyThroughTheSealingLayer`.

- [ ] **Step 5: Commit**

```bash
git add internal/store internal/daemon/authen/authen_test.go
git commit -m "feat: SetContextPolicy, the refresher's compare-and-set setter

The fifth narrow setter writes a policy refresh's answer into a live
context -- blob hash, ceiling (clamping the held level), enable, or the
revocation alone -- only if the revision is still the one read. It moves
nothing about the session's clocks or its idle TTL: a policy edit is not
a re-authentication and not activity.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 3: `policy.Live`, the policy in force, swapped whole

**Files:**
- Create: `internal/policy/live.go`
- Test: `internal/policy/live_test.go`

**Interfaces:**
- Produces:
  - `type Live struct` with `func NewLive(p *Policy) *Live`, `func (l *Live) Load() *Policy`,
    `func (l *Live) Hold() (p *Policy, release func())`, `func (l *Live) Swap(p *Policy) *Policy`
    (returns the policy replaced; waits for every `Hold`), and
    `func (l *Live) Quarantined(device string, now time.Time) (string, bool)`.
  - `func (p *Policy) NextChange(t time.Time) (at time.Time, ok bool)` — the first grant expiry
    after `t`.
  - `func (p *Policy) Principals() []string` — every identity a subject lists, sorted.
  - `func (p *Policy) UsernameOf(principal string) (string, bool)`.

Decided 1 is the argument for the read lock: the token supersede in Task 5 must see every token
the replaced policy minted.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/policy/live_test.go -->
```go
package policy

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

// A mint holds the policy it resolved against until its token is written; a
// swap waits for it, and every hold after the swap sees the new policy. The
// quarantine question takes no lock and answers from whichever is in force.
func TestLiveSwapWaitsForAHoldAndThenAnswersFromTheNewPolicy(t *testing.T) {
	old := mustParse(t, good)
	next := mustParse(t, good+"\n# an edit\n")
	l := NewLive(old)
	held, release := l.Hold()
	if held != old {
		t.Fatal("Hold returns the policy in force")
	}
	swapped := make(chan *Policy)
	go func() { swapped <- l.Swap(next) }()
	select {
	case <-swapped:
		t.Fatal("Swap returned while a mint still held the old policy")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if got := <-swapped; got != old {
		t.Fatalf("Swap returns what it replaced: %p, want %p", got, old)
	}
	if p, release := l.Hold(); p != next {
		t.Fatal("a hold after the swap sees the new policy")
	} else {
		release()
	}
	if l.Load() != next {
		t.Fatal("Load sees the new policy")
	}
	if _, ok := l.Quarantined("leaf-01", noon); ok {
		t.Fatal("the quarantine question is asked of the policy in force")
	}
}

// Reads race a stream of swaps without a data race (go test -race).
func TestLiveIsSafeForConcurrentUse(t *testing.T) {
	a, b := mustParse(t, good), mustParse(t, good+"\n# b\n")
	l := NewLive(a)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				p, release := l.Hold()
				_ = p.Bundle
				release()
				l.Quarantined("leaf-01", noon)
			}
		}()
	}
	for j := 0; j < 200; j++ {
		if j%2 == 0 {
			l.Swap(b)
		} else {
			l.Swap(a)
		}
	}
	wg.Wait()
}

// good's one expiring grant is alice's, on 2026-12-01 (Decided 22 of plan 4:
// a date-only expiry is the start of that day, UTC).
func TestNextChangeIsTheNextGrantExpiry(t *testing.T) {
	p := mustParse(t, good)
	lapse := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if at, ok := p.NextChange(noon); !ok || !at.Equal(lapse) {
		t.Fatalf("NextChange(noon) = %v %v, want %v", at, ok, lapse)
	}
	if _, ok := p.NextChange(lapse); ok {
		t.Fatal("no grant expires after the last expiry")
	}
}

func TestPrincipalsAndUsernameOf(t *testing.T) {
	p := mustParse(t, good)
	want := []string{"spiffe://port49/host/oxidized-01", "system:serviceaccount:netops:oxidized", "user:alice@example.com"}
	if got := p.Principals(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Principals() = %v, want %v (a group subject lists none)", got, want)
	}
	if u, ok := p.UsernameOf("system:serviceaccount:netops:oxidized"); !ok || u != "svc-config-backup" {
		t.Fatalf("UsernameOf = %q %v", u, ok)
	}
	if _, ok := p.UsernameOf("user:mallory@example.com"); ok {
		t.Fatal("a principal no subject lists has no username")
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go vet ./internal/policy/`
Expected: FAIL to build — `undefined: NewLive`.

- [ ] **Step 3: Write `live.go`**

<!-- write: internal/policy/live.go -->
```go
package policy

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Live is the policy in force: one pointer, replaced whole when port49d
// reloads the file (plan 4b). A loaded Policy is never edited, so everything
// that holds one reads a single version throughout; the swap is what changes
// the version, and it changes the broker's answers and the daemon's quarantine
// in one step, because both read this pointer.
//
// Two kinds of reader. The daemon's per-packet quarantine question and the
// quarantine gauge Load the pointer and take no lock: they are one lookup. A
// mint Holds it — a read lock across the resolution and the token write — so
// that once Swap returns, no mint is still writing a token resolved against
// the policy it replaced. The refresh that follows a swap relies on that: it
// deletes the tokens the old policy minted and the new one would not have,
// and a mint still in flight on the old policy would write one after it.
type Live struct {
	mu sync.RWMutex
	p  atomic.Pointer[Policy]
}

// NewLive returns a Live holding p.
func NewLive(p *Policy) *Live {
	l := &Live{}
	l.p.Store(p)
	return l
}

// Load is the policy in force now.
func (l *Live) Load() *Policy { return l.p.Load() }

// Hold is Load for a mint: the policy in force, which stays in force until
// release is called. release must be called exactly once.
func (l *Live) Hold() (p *Policy, release func()) {
	l.mu.RLock()
	return l.p.Load(), l.mu.RUnlock
}

// Swap puts p in force and returns the policy it replaced. It waits for every
// Hold on the old policy to be released, and a Hold after it returns sees p.
func (l *Live) Swap(p *Policy) *Policy {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.p.Swap(p)
}

// Quarantined is (*Policy).Quarantined on the policy in force: the daemon's
// question at every packet (spec §10), answered by whichever version is in
// force when the packet arrives.
func (l *Live) Quarantined(device string, now time.Time) (string, bool) {
	return l.Load().Quarantined(device, now)
}

// NextChange is the first instant after t at which a grant expires, and so at
// which a resolution may change with no edit to the file (spec §5.1). A
// policy-driven refresh runs then as well as at a reload, or a live context
// would keep an expired grant's rules until the next edit. ok is false when no
// grant expires after t.
func (p *Policy) NextChange(t time.Time) (at time.Time, ok bool) {
	for _, g := range p.grants {
		if g.Expires.After(t) && (!ok || g.Expires.Before(at)) {
			at, ok = g.Expires, true
		}
	}
	return at, ok
}

// Principals is every identity a subject lists, sorted: every principal this
// policy can mint for. A group subject lists none; it mints for no one until
// plan 7's directory resolves membership.
func (p *Policy) Principals() []string {
	out := make([]string, 0, len(p.byID))
	for id := range p.byID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// UsernameOf is the device-facing username a principal mints under: its
// subject's (spec §2). A token and a login context are keyed by it.
func (p *Policy) UsernameOf(principal string) (string, bool) {
	name, ok := p.byID[principal]
	if !ok {
		return "", false
	}
	return p.subs[name].Username, true
}
```

- [ ] **Step 4: Run the package, with the race detector**

Run: `go test -race ./internal/policy/ && make vet`
Expected: PASS; `TestLiveIsSafeForConcurrentUse` reports no race.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/live.go internal/policy/live_test.go
git commit -m "feat: policy.Live, the policy in force, swapped whole

One pointer the broker mints from and the daemon asks about quarantine,
so one swap changes both. A mint holds a read lock across its request, so
a swap waits for every mint on the policy it replaces. NextChange,
Principals and UsernameOf are what the refresh reads.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 4: The broker mints from the policy in force; `Server` returns its refusal

**Files:**
- Create: `cmd/port49d/policyfile.go`
- Modify: `internal/broker/broker.go`, `internal/broker/server.go`, `cmd/port49d/main.go`,
  `tests/lab/harness_test.go`, `tests/lab/README.md`
- Test: create `cmd/port49d/policyfile_test.go`; modify `internal/broker/engine_test.go`,
  `internal/broker/fixture_test.go`, `internal/broker/server_test.go`, `cmd/port49d/broker_test.go`

**Interfaces:**
- Consumes: `policy.Live`, `NewLive`, `Hold`, `Swap`, `Load`, `Quarantined` (Task 3).
- Produces:
  - `broker.Broker.Policy` is a `*policy.Live`. `tokens` holds one version from its first
    resolution to its last token write, releases it before writing the response (Decided 1), and
    passes it to `mintOne`, whose signature gains `pol *policy.Policy` after `ctx`.
  - `func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool) (*http.Server, error)`
    — a nil or empty anchor pool is an error, not a panic (carried from plan 7).
  - In `cmd/port49d`: `buildBroker(...) (*http.Server, *broker.Broker, error)`;
    `loadPolicy(cfg config.Config) (*policy.Policy, error)` and
    `parsePolicy(cfg config.Config, raw []byte) (*policy.Policy, error)` — the one load, at start and
    at every reload (Decided 3); `readPolicyFile(path string) ([]byte, error)`, which refuses a file
    anyone but port49d's user or root could have written, and its test seam `geteuid`
    (Decided 3); `sayPolicy(pol *policy.Policy, now time.Time)` — the quarantine and rule lines, at
    start and after every reload;
    `watchQuarantine(live *policy.Live, m *metrics.Metrics, now func() time.Time)`, which asks the
    `Live` at the moment of asking.
  - In `tests/lab`: `privatePolicy(cfg, dir string) (string, error)`, which `derivedConfigCmd`
    runs so the daemon a lab run starts reads a policy only this user can write.

Nothing swaps the policy yet; this task makes every reader read the pointer, so Task 6's swap is
seen everywhere at once. `watchQuarantine`'s count moves into `quarantinedAt` in Task 6, where the
reload's line uses it too; here it is written inline as before.

- [ ] **Step 1: Move the tests to the new types, and write the failing one**

`TestTheNextMintAnswersFromASwappedPolicy` swaps a policy that withdraws alice's grant and expects
the very next mint to be refused `no_grants_matched`, naming the new bundle.
`TestServerRefusesAMissingAnchor` expects an error where it recovered a panic.
`TestASwapDoesNotWaitForAResponseWrite` stalls a mint's response write and expects a swap to
return regardless (Decided 1). `policyfile_test.go` refuses a group- or world-writable file or
directory, a file another uid owns, and a symlink to an unsafe file, and refuses the start with
one (Decided 3).

<!-- patch: internal/broker/engine_test.go -->
```diff
diff --git a/internal/broker/engine_test.go b/internal/broker/engine_test.go
index 1213337..c5a8f56 100644
--- a/internal/broker/engine_test.go
+++ b/internal/broker/engine_test.go
@@ -3,6 +3,8 @@ package broker
 import (
 	"context"
 	"errors"
+	"net/http"
+	"net/http/httptest"
 	"os"
 	"path/filepath"
 	"strings"
@@ -56,7 +58,7 @@ func TestAMintRecordNamesItsBundle(t *testing.T) {
 	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
 	mints := eventsOf(f.records(t), "mint")
 	pol, _ := mints[len(mints)-1]["policy"].(map[string]any)
-	if pol["bundle"] != f.b.Policy.Bundle || !strings.HasPrefix(f.b.Policy.Bundle, "sha256:") {
+	if pol["bundle"] != f.b.Policy.Load().Bundle || !strings.HasPrefix(f.b.Policy.Load().Bundle, "sha256:") {
 		t.Fatalf("mint record policy: %v", pol)
 	}
 }
@@ -85,7 +87,7 @@ grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: nx, r
 	if err != nil {
 		t.Fatal(err)
 	}
-	f.b.Policy = pol
+	f.b.Policy.Swap(pol)
 	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
 	byDevice := map[string]string{}
 	for _, it := range resp.Results {
@@ -129,7 +131,7 @@ grants: [{subject: s, scope: all_devices, roles: [r]}]
 	if err != nil {
 		t.Fatal(err)
 	}
-	f.b.Policy = pol
+	f.b.Policy.Swap(pol)
 	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
 	if it := resp.Results[0]; it.Error != "attribute_too_long" || it.Login != "" {
 		t.Fatalf("%+v", it)
@@ -158,7 +160,7 @@ grants: [{subject: s, scope: all_devices, roles: [r]}]
 	if err != nil {
 		t.Fatal(err)
 	}
-	f.b.Policy = pol
+	f.b.Policy.Swap(pol)
 	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["sw=1"]}`, ""))
 	if it := resp.Results[0]; it.Error != "attribute_unsafe" || it.Login != "" {
 		t.Fatalf("%+v", it)
@@ -177,3 +179,67 @@ func (f *fixture) assertItemErrorOnly(t *testing.T, code string) {
 		t.Errorf("an item error wrote a decision record: %v", mints)
 	}
 }
+
+// The next mint answers from a swapped policy, and names its bundle: a
+// broker keeps nothing of the policy it was built with (plan 4b). Removing
+// netops's one grant leaves alice no_grants_matched on the very next request.
+func TestTheNextMintAnswersFromASwappedPolicy(t *testing.T) {
+	f := newFixture(t, 8)
+	if it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]; it.Verdict != "permit" {
+		t.Fatalf("before the swap: %+v", it)
+	}
+	body := strings.Replace(testPolicy, "  - {subject: netops, scope: all_devices, roles: [network_admin, no_reload], max_privilege: admin}\n",
+		"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n", 1)
+	pol, err := policy.Parse([]byte(body), policy.Env{Devices: []admission.Device{f.b.Devices["leaf1"]}})
+	if err != nil {
+		t.Fatal(err)
+	}
+	f.b.Policy.Swap(pol)
+	f.log.Reset()
+	if it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]; it.Verdict != "deny" || it.Reason != "no_grants_matched" {
+		t.Fatalf("after the swap: %+v", it)
+	}
+	carol := f.client(t, "carol@example.com", f.now.Add(24*time.Hour))
+	decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["leaf1"]}`, ""))
+	mints := eventsOf(f.records(t), "mint")
+	if pol0, _ := mints[len(mints)-1]["policy"].(map[string]any); pol0["bundle"] != pol.Bundle {
+		t.Fatalf("the mint after the swap names the new bundle: %v", mints[len(mints)-1])
+	}
+}
+
+// stalledWriter is a response writer whose Write blocks until released: a
+// client that stopped reading, or a peer that vanished mid-response.
+type stalledWriter struct {
+	header  http.Header
+	writing chan struct{}
+	release chan struct{}
+}
+
+func (w *stalledWriter) Header() http.Header { return w.header }
+func (w *stalledWriter) WriteHeader(int)     {}
+func (w *stalledWriter) Write(p []byte) (int, error) {
+	close(w.writing)
+	<-w.release
+	return len(p), nil
+}
+
+// A mint holds the policy until its last token is written, not until its
+// response is: a response the client never reads must not hold a reload, or
+// every mint queued behind the reload, and every refresh after it (pre-flight
+// S1).
+func TestASwapDoesNotWaitForAResponseWrite(t *testing.T) {
+	f := newFixture(t, 8)
+	w := &stalledWriter{header: http.Header{}, writing: make(chan struct{}), release: make(chan struct{})}
+	defer close(w.release)
+	r := httptest.NewRequest("POST", "/v1/tokens", strings.NewReader(`{"devices":["leaf1"]}`))
+	r.TLS = f.state(f.alice)
+	go f.b.Handler().ServeHTTP(w, r)
+	<-w.writing
+	swapped := make(chan struct{})
+	go func() { f.b.Policy.Swap(f.b.Policy.Load()); close(swapped) }()
+	select {
+	case <-swapped:
+	case <-time.After(2 * time.Second):
+		t.Fatal("a swap waited for a response write")
+	}
+}
```

<!-- patch: internal/broker/fixture_test.go -->
```diff
diff --git a/internal/broker/fixture_test.go b/internal/broker/fixture_test.go
index 6354f8d..3a3813b 100644
--- a/internal/broker/fixture_test.go
+++ b/internal/broker/fixture_test.go
@@ -81,7 +81,7 @@ func newFixture(t *testing.T, candidateCap int) *fixture {
 	}
 	f.alice = f.client(t, "alice@example.com", f.now.Add(24*time.Hour))
 	log := decision.NewJSONLines(f.log)
-	f.b = &Broker{Policy: pol, Devices: devices,
+	f.b = &Broker{Policy: policy.NewLive(pol), Devices: devices,
 		Minter: token.NewMinter(f.st, log, rand.Reader, token.TagKey([]byte("k")), clock, candidateCap),
 		Store:  f.st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: clock,
 		MaxSessionAge: 12 * time.Hour, BatchMax: 4}
```

<!-- patch: internal/broker/server_test.go -->
```diff
diff --git a/internal/broker/server_test.go b/internal/broker/server_test.go
index 24cbb8d..274cff1 100644
--- a/internal/broker/server_test.go
+++ b/internal/broker/server_test.go
@@ -38,7 +38,10 @@ func startServerLogging(t *testing.T, f *fixture, errLog *log.Logger) string {
 	if err != nil {
 		t.Fatal(err)
 	}
-	srv := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
+	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
+	if err != nil {
+		t.Fatal(err)
+	}
 	srv.ErrorLog = errLog
 	ln, err := net.Listen("tcp", "127.0.0.1:0")
 	if err != nil {
@@ -287,7 +290,10 @@ func TestShutdownReturnsWithEverySlotHeld(t *testing.T) {
 	if err != nil {
 		t.Fatal(err)
 	}
-	srv := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
+	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
+	if err != nil {
+		t.Fatal(err)
+	}
 	raw, err := net.Listen("tcp", "127.0.0.1:0")
 	if err != nil {
 		t.Fatal(err)
@@ -555,17 +561,13 @@ func TestAStalledRequestWithoutACertificateIsClosed(t *testing.T) {
 }
 
 // A nil pool would mean the system roots — every public CA an anchor for the
-// email mapping — and an empty one trusts nobody: Server refuses both.
+// email mapping — and an empty one trusts nobody: Server refuses both, with
+// an error rather than a panic.
 func TestServerRefusesAMissingAnchor(t *testing.T) {
 	f := newFixture(t, 8)
 	for name, pool := range map[string]*x509.CertPool{"nil": nil, "empty": x509.NewCertPool()} {
-		func() {
-			defer func() {
-				if recover() == nil {
-					t.Errorf("a %s anchor pool must be refused", name)
-				}
-			}()
-			f.b.Server("127.0.0.1:0", f.alice, pool)
-		}()
+		if srv, err := f.b.Server("127.0.0.1:0", f.alice, pool); err == nil || srv != nil {
+			t.Errorf("a %s anchor pool must be refused: %v %v", name, srv, err)
+		}
 	}
 }
```

<!-- patch: cmd/port49d/broker_test.go -->
```diff
diff --git a/cmd/port49d/broker_test.go b/cmd/port49d/broker_test.go
index 6a895ca..f43e08a 100644
--- a/cmd/port49d/broker_test.go
+++ b/cmd/port49d/broker_test.go
@@ -62,9 +62,9 @@ func buildWith(cfg config.Config) error {
 }
 
 func TestNoBrokerBlockBuildsNoBroker(t *testing.T) {
-	srv, pol, err := buildBroker(config.Config{}, nil, nil, nil, nil)
-	if srv != nil || pol != nil || err != nil {
-		t.Fatalf("%v %v %v", srv, pol, err)
+	srv, b, err := buildBroker(config.Config{}, nil, nil, nil, nil)
+	if srv != nil || b != nil || err != nil {
+		t.Fatalf("%v %v %v", srv, b, err)
 	}
 }
 
@@ -108,12 +108,12 @@ func TestAQuarantinedDeviceDoesNotStopTheStart(t *testing.T) {
 	var out bytes.Buffer
 	defer func(w io.Writer) { stderr = w }(stderr)
 	stderr = &out
-	_, pol, err := buildBroker(brokerConfig(t, unmappedLevel+strings.Replace(minimalPolicy, "privilege: admin", "privilege: unmapped", 1)),
+	_, b, err := buildBroker(brokerConfig(t, unmappedLevel+strings.Replace(minimalPolicy, "privilege: admin", "privilege: unmapped", 1)),
 		memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
 	if err != nil {
 		t.Fatalf("a quarantined device must not stop the start: %v", err)
 	}
-	if _, ok := pol.Quarantined("leaf1", time.Now()); !ok {
+	if _, ok := b.Policy.Quarantined("leaf1", time.Now()); !ok {
 		t.Fatal("the daemon is handed the policy that quarantines leaf1")
 	}
 	if !strings.Contains(out.String(), "device leaf1 (arista_eos) is quarantined") ||
@@ -131,12 +131,12 @@ func TestAWidenedDenyIsSaidAtStart(t *testing.T) {
 	stderr = &out
 	cfg := brokerConfig(t, strings.Replace(minimalPolicy, `permit: ["**"]}`, `permit: ["**"], deny: ["* * /tftp/"]}`, 1))
 	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "ntp1", Platform: "meinberg_lantime"})
-	_, pol, err := buildBroker(cfg, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
+	_, b, err := buildBroker(cfg, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
 		metrics.New(prometheus.NewRegistry()))
 	if err != nil {
 		t.Fatal(err)
 	}
-	if _, ok := pol.Quarantined("ntp1", time.Now()); ok {
+	if _, ok := b.Policy.Quarantined("ntp1", time.Now()); ok {
 		t.Fatal("a widened deny quarantines nothing")
 	}
 	if !strings.Contains(out.String(), `port49d: broker: role "r": deny "* * /tftp/" on meinberg_lantime: /tftp/:`) ||
@@ -171,7 +171,7 @@ func TestTheDaemonsQuarantineFollowsTheClock(t *testing.T) {
 	stderr = &out
 	now := time.Now()
 	lapse := now.Add(48 * time.Hour).Truncate(time.Second)
-	_, pol, err := buildBroker(brokerConfig(t, unmappedLevel+`
+	_, b, err := buildBroker(brokerConfig(t, unmappedLevel+`
 scopes: [{name: all_devices, match: {}}]
 roles:
   - {name: op, privilege: unmapped, permit: [show **]}
@@ -191,7 +191,7 @@ grants:
 	}
 	m := metrics.New(prometheus.NewRegistry())
 	clock := now
-	quarantined := watchQuarantine(pol, m, func() time.Time { return clock })
+	quarantined := watchQuarantine(b.Policy, m, func() time.Time { return clock })
 	if _, ok := quarantined("leaf1", now); ok || testutil.ToFloat64(m.DevicesQuarantined) != 0 {
 		t.Fatal("before the expiry leaf1 is neither refused nor counted")
 	}
```

<!-- write: cmd/port49d/policyfile_test.go -->
```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policyAt writes a policy file with mode perm in a fresh directory of mode
// dirPerm, and returns its path.
func policyAt(t *testing.T, perm, dirPerm os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod, not the create mode: the umask would narrow that.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		t.Fatal(err)
	}
	return path
}

// Whoever can write the policy decides every operator's access (spec
// §5.1.3), so a file or a directory anyone but port49d's user could write is
// refused, naming what to fix.
func TestAPolicyFileOthersCouldWriteIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		perm, dirPerm os.FileMode
		want          string
	}{
		"group-writable file":      {0o620, 0o755, "the file"},
		"world-writable file":      {0o602, 0o755, "the file"},
		"group-writable directory": {0o644, 0o775, "the directory"},
		"world-writable directory": {0o644, 0o1777, "the directory"},
	} {
		path := policyAt(t, c.perm, c.dirPerm)
		if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if raw, err := readPolicyFile(policyAt(t, 0o644, 0o755)); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("a file only its owner can write is read: %v", err)
	}
}

// A file owned by neither port49d's user nor root is refused.
func TestAPolicyFileAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file is owned by an accepted uid")
	}
	defer func(f func() int) { geteuid = f }(geteuid)
	geteuid = func() int { return os.Geteuid() + 1 }
	if _, err := readPolicyFile(policyAt(t, 0o600, 0o700)); err == nil || !strings.Contains(err.Error(), "chown it") {
		t.Fatalf("%v", err)
	}
}

// A symlink is followed, and the target and its directory are what is
// checked: a ConfigMap's chain of links to a safe file passes, and a link to
// a file others could write does not.
func TestAPolicySymlinkIsJudgedByItsTarget(t *testing.T) {
	link := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.Symlink(policyAt(t, 0o644, 0o755), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(link); err != nil {
		t.Fatalf("a link to a safe file is read: %v", err)
	}
	unsafe := filepath.Join(t.TempDir(), "policy.yaml")
	target := policyAt(t, 0o666, 0o755)
	if err := os.Symlink(target, unsafe); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(unsafe); err == nil || !strings.Contains(err.Error(), target) {
		t.Fatalf("a link to a world-writable file names the target: %v", err)
	}
}

// At start an unsafe policy file refuses the start, as a policy that does not
// load does, naming the config key and the file.
func TestAnUnsafePolicyFileRefusesTheStart(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	if err := os.Chmod(cfg.Broker.PolicyFile, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), "broker.policy_file "+cfg.Broker.PolicyFile) ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("%v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go vet ./internal/broker/ ./cmd/port49d/`
Expected: FAIL to build — `f.b.Policy.Load undefined (type *policy.Policy has no field or method Load)`
in the broker, and `b.Policy undefined (type *policy.Policy has no field or method Policy)` in
`cmd/port49d` (vet stops at the first error in each package).

- [ ] **Step 3: Put the broker and port49d on `policy.Live`**

<!-- patch: internal/broker/broker.go -->
```diff
diff --git a/internal/broker/broker.go b/internal/broker/broker.go
index cd9a44f..05929a2 100644
--- a/internal/broker/broker.go
+++ b/internal/broker/broker.go
@@ -50,7 +50,10 @@ const (
 
 // Broker is the slice's broker. Every field is required.
 type Broker struct {
-	Policy *policy.Policy
+	// Policy is the policy in force. port49d swaps it when the file changes
+	// (plan 4b), and a request resolves against the one version it held from
+	// its first mint to its last, never half of each.
+	Policy *policy.Live
 	// Devices is the inventory by name: the admission snapshot the daemon
 	// admits from (plan 3, Decided 15). A target is named, never addressed,
 	// and a name inventory does not know is refused (design §17).
@@ -189,25 +192,43 @@ func (b *Broker) tokens(w http.ResponseWriter, r *http.Request) {
 			return
 		}
 	}
+	// Held from the first resolution to the last token write, so a reload's
+	// swap waits for this request's mints and the refresh after it sees every
+	// token the old policy minted (policy.Live). Released before the response
+	// is written: a client that stops reading, or a peer that vanishes
+	// mid-response, must not hold a reload — and, behind it, every mint and
+	// every refresh — until TCP gives up. The deferred call is for a panic,
+	// which net/http recovers: a hold it leaked would stop every reload.
+	pol, hold := b.Policy.Hold()
+	held := true
+	release := func() {
+		if held {
+			held = false
+			hold()
+		}
+	}
+	defer release()
 	resp := api.MintResponse{Principal: principal}
-	resp.Subject, _ = b.Policy.SubjectOf(principal)
+	resp.Subject, _ = pol.SubjectOf(principal)
 	for _, name := range req.Devices {
-		item, err := b.mintOne(r.Context(), principal, cred, authTime, name, req, key, bodyHash)
+		item, err := b.mintOne(r.Context(), pol, principal, cred, authTime, name, req, key, bodyHash)
 		if errors.Is(err, token.ErrIdempotencyConflict) {
 			// Only a concurrent request on the same key, between the check
 			// above and this mint, reaches here.
+			release()
 			writeConflict(w)
 			return
 		}
 		resp.Results = append(resp.Results, item)
 	}
+	release()
 	writeJSON(w, http.StatusOK, resp)
 }
 
 // mintOne answers one device. The only error it returns is an idempotency
 // conflict, which is the whole request's; every other refusal is an item.
-func (b *Broker) mintOne(ctx context.Context, principal string, cred store.Credential, authTime time.Time,
-	name string, req api.MintRequest, key, bodyHash string) (api.MintItem, error) {
+func (b *Broker) mintOne(ctx context.Context, pol *policy.Policy, principal string, cred store.Credential,
+	authTime time.Time, name string, req api.MintRequest, key, bodyHash string) (api.MintItem, error) {
 	deny := func(reason decision.Reason, platform string) api.MintItem {
 		b.emit(decision.Record{TS: b.Now(), Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: reason,
 			Principal: principal, Auth: &decision.Auth{Method: cred.Method},
@@ -221,7 +242,7 @@ func (b *Broker) mintOne(ctx context.Context, principal string, cred store.Crede
 		// device and no platform, which is what tells an operator which.
 		return deny(decision.NoGrantsMatched, ""), nil
 	}
-	res, err := b.Policy.Resolve(principal, dev, b.Now())
+	res, err := pol.Resolve(principal, dev, b.Now())
 	switch {
 	case errors.Is(err, policy.ErrNoGrants):
 		return deny(decision.NoGrantsMatched, dev.Platform), nil
@@ -290,7 +311,7 @@ func (b *Broker) mintOne(ctx context.Context, principal string, cred store.Crede
 		Device: name, Platform: dev.Platform, BlobHash: hash, WithEnable: req.Enable,
 		TTL:            time.Duration(req.TTLSeconds) * time.Second,
 		IdempotencyKey: key, BodyHash: bodyHash,
-		Policy: &decision.Policy{Bundle: b.Policy.Bundle, Subject: res.Subject, Grants: res.Grants}})
+		Policy: &decision.Policy{Bundle: pol.Bundle, Subject: res.Subject, Grants: res.Grants}})
 	var capped *token.ErrTooManyOutstanding
 	switch {
 	case errors.Is(err, token.ErrIdempotencyConflict):
```

<!-- patch: internal/broker/server.go -->
```diff
diff --git a/internal/broker/server.go b/internal/broker/server.go
index 8ef99a2..1aadf3e 100644
--- a/internal/broker/server.go
+++ b/internal/broker/server.go
@@ -5,6 +5,7 @@ import (
 	"crypto/tls"
 	"crypto/x509"
 	"encoding/pem"
+	"errors"
 	"fmt"
 	"net"
 	"net/http"
@@ -56,13 +57,16 @@ const MaxConns = 256
 // that never comes would hold a slot of the cap for good (pre-flight F1). The
 // time between requests is IdleTimeout's, so a held connection is unaffected.
 //
-// anchor must hold the one trust anchor. Server panics on a nil pool, which
+// anchor must hold the one trust anchor. Server refuses a nil pool, which
 // crypto/tls would take as the system roots — every public CA an anchor for
-// the email mapping — and on an empty one, which trusts no one.
-func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool) *http.Server {
+// the email mapping — and an empty one, which trusts no one. It returns the
+// refusal rather than panicking (plan 4b): port49d now runs code after start
+// that swaps policy under a live daemon, and nothing on a path that can run
+// with device AAA already serving may end the process.
+func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool) (*http.Server, error) {
 	if anchor == nil || anchor.Equal(x509.NewCertPool()) {
-		panic("broker: the broker trusts exactly one anchor; a nil pool would mean the system roots, " +
-			"and an empty one trusts no one")
+		return nil, errors.New("broker: the broker trusts exactly one anchor; a nil pool would mean the system " +
+			"roots, and an empty one trusts no one")
 	}
 	return &http.Server{
 		Addr:    addr,
@@ -89,7 +93,7 @@ func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool
 		ReadHeaderTimeout: 10 * time.Second,
 		ReadTimeout:       readTimeout,
 		IdleTimeout:       b.MaxSessionAge,
-	}
+	}, nil
 }
 
 // closeIdleWithoutCertificate closes a connection that presented no client
```

<!-- patch: cmd/port49d/main.go -->
```diff
diff --git a/cmd/port49d/main.go b/cmd/port49d/main.go
index ced655a..e20defa 100644
--- a/cmd/port49d/main.go
+++ b/cmd/port49d/main.go
@@ -172,52 +172,23 @@ func labWarning(lab *config.LabConfig) string {
 var stderr io.Writer = os.Stderr
 
 // buildBroker loads what the broker needs and returns its server and the
-// policy it loaded, or nils when no broker: block is configured. The daemon
-// asks the policy about quarantine, and nothing else (spec §10). It runs
+// broker, or nils when no broker: block is configured. The daemon asks the
+// broker's policy about quarantine, and nothing else (spec §10). It runs
 // before any listener opens, so a policy typo or an unreadable certificate
 // ends the start with one line rather than surfacing at the first mint. Each
 // error names the config key and the file, so that line says what to go and
 // fix.
 func buildBroker(cfg config.Config, st store.Store, minter *token.Minter, log decision.Emitter,
-	m *metrics.Metrics) (*http.Server, *policy.Policy, error) {
+	m *metrics.Metrics) (*http.Server, *broker.Broker, error) {
 	if cfg.Broker == nil {
 		return nil, nil, nil
 	}
-	// The policy is checked against the inventory the daemon admits from: a
-	// class a platform in it does not define, or a level it cannot render, is
-	// found here rather than at the first mint for that device (spec §4, §6).
-	pol, err := policy.Load(cfg.Broker.PolicyFile, policy.Env{Devices: cfg.Inventory.Devices,
-		EnableUsernames: cfg.EnableUsernames})
+	pol, err := loadPolicy(cfg)
 	if err != nil {
-		return nil, nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, err)
-	}
-	// A device a joint check failed on is quarantined rather than the policy
-	// refused: its mints are refused device_quarantined and the rest of the
-	// fleet loads (spec §10; §13 decision 20). Each is said here, with its
-	// cause, so the line at start names what to fix. Quarantine is
-	// time-scoped: one a grant's expiry will bring on is said now too, with
-	// when, while the device still mints.
-	now := time.Now()
-	for _, q := range pol.Quarantines(now) {
-		for _, e := range q.Entries {
-			msg := e.Message(now)
-			if e.Current(now) {
-				msg = "is " + msg
-			}
-			fmt.Fprintf(stderr, "port49d: broker: device %s (%s) %s\n", q.Device, q.Platform, msg)
-		}
-	}
-	// A deny term that matches any argument, because its platform may send
-	// what was typed and its abbreviations cannot be read, over-denies
-	// rather than refusing the device (spec §3 rule 4); say which.
-	for _, f := range pol.WidenedDenies() {
-		fmt.Fprintf(stderr, "port49d: broker: %s\n", f.Message)
-	}
-	// A permit naming an interface joined never matches where the platform
-	// sends the name and the index apart (spec §3 rule 5); say which.
-	for _, f := range pol.JoinedNamePermits() {
-		fmt.Fprintf(stderr, "port49d: broker: %s\n", f.Message)
+		return nil, nil, err
 	}
+	now := time.Now()
+	sayPolicy(pol, now)
 	cert, anchor, err := broker.LoadTLS(cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile)
 	if err != nil {
 		return nil, nil, fmt.Errorf("broker TLS files (tls_cert_file %s, tls_key_file %s, client_ca_file %s): %w",
@@ -250,41 +221,99 @@ func buildBroker(cfg config.Config, st store.Store, minter *token.Minter, log de
 		}
 		devices[d.Name] = d
 	}
-	b := &broker.Broker{Policy: pol, Devices: devices, Minter: minter, Store: st, Log: log, Metrics: m,
+	b := &broker.Broker{Policy: policy.NewLive(pol), Devices: devices, Minter: minter, Store: st, Log: log, Metrics: m,
 		Now: time.Now, MaxSessionAge: cfg.Session.MaxSessionAgeDefault, BatchMax: cfg.Broker.BatchMax}
-	// Startup only. Server panics on a nil or empty anchor pool; LoadTLS has
-	// just returned a pool of exactly one, so it cannot here, and buildBroker
-	// runs before the TACACS+ listener opens — a panic would end a start, never
-	// a running daemon's device AAA. A live reload (plan 4b) must not call
-	// Server until it returns an error instead.
-	srv := b.Server(cfg.Broker.Listen, cert, anchor)
+	srv, err := b.Server(cfg.Broker.Listen, cert, anchor)
+	if err != nil {
+		return nil, nil, fmt.Errorf("broker.client_ca_file %s: %w", cfg.Broker.ClientCAFile, err)
+	}
 	// net/http logs what no handler sees — a handshake refused for an expired
 	// or untrusted certificate — through ErrorLog. Left nil it goes to the
 	// standard library's default logger; routed here it lands beside
 	// port49d's other lines, where an operator is already looking.
 	srv.ErrorLog = stdlog.New(stderr, "port49d: broker: ", 0)
-	return srv, pol, nil
+	return srv, b, nil
+}
+
+// loadPolicy reads broker.policy_file and checks it against the inventory the
+// daemon admits from: a class a platform in it does not define, or a level it
+// cannot render, is found here rather than at the first mint for that device
+// (spec §4, §6). It is the one load, at start and at every reload, so a file
+// the start would refuse is a file a reload refuses, with the same words. A
+// file anyone but port49d's user or root could have written is one of them
+// (readPolicyFile).
+func loadPolicy(cfg config.Config) (*policy.Policy, error) {
+	raw, err := readPolicyFile(cfg.Broker.PolicyFile)
+	if err != nil {
+		return nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, err)
+	}
+	return parsePolicy(cfg, raw)
+}
+
+// parsePolicy is loadPolicy for bytes already read: a reload loads exactly the
+// bytes it hashed, so the version it remembers refusing is the version it
+// refused, and the version the watch saw agree twice is the version loaded.
+func parsePolicy(cfg config.Config, raw []byte) (*policy.Policy, error) {
+	pol, err := policy.Parse(raw, policy.Env{Devices: cfg.Inventory.Devices, EnableUsernames: cfg.EnableUsernames})
+	if err != nil {
+		return nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, err)
+	}
+	return pol, nil
+}
+
+// sayPolicy writes what a loaded policy does to the fleet short of refusing
+// it, at start and after every reload, so the lines an operator reads after
+// an edit are the lines they would read after a restart.
+//
+// A device a joint check failed on is quarantined rather than the policy
+// refused: its mints are refused device_quarantined and the rest of the
+// fleet loads (spec §10; §13 decision 20). Each is said, with its cause, so
+// the line names what to fix. Quarantine is time-scoped: one a grant's
+// expiry will bring on is said too, with when, while the device still mints.
+func sayPolicy(pol *policy.Policy, now time.Time) {
+	for _, q := range pol.Quarantines(now) {
+		for _, e := range q.Entries {
+			msg := e.Message(now)
+			if e.Current(now) {
+				msg = "is " + msg
+			}
+			fmt.Fprintf(stderr, "port49d: broker: device %s (%s) %s\n", q.Device, q.Platform, msg)
+		}
+	}
+	// A deny term that matches any argument, because its platform may send
+	// what was typed and its abbreviations cannot be read, over-denies
+	// rather than refusing the device (spec §3 rule 4); say which.
+	for _, f := range pol.WidenedDenies() {
+		fmt.Fprintf(stderr, "port49d: broker: %s\n", f.Message)
+	}
+	// A permit naming an interface joined never matches where the platform
+	// sends the name and the index apart (spec §3 rule 5); say which.
+	for _, f := range pol.JoinedNamePermits() {
+		fmt.Fprintf(stderr, "port49d: broker: %s\n", f.Message)
+	}
 }
 
 // watchQuarantine is what the daemon asks of the policy: whether a device is
 // quarantined at the time of a packet (spec §10; §13 decision 20), and at each
 // scrape how many are, for port49_devices_quarantined. Quarantine is
-// time-scoped, so neither is captured at start. nil with no policy.
-func watchQuarantine(pol *policy.Policy, m *metrics.Metrics,
+// time-scoped, and the policy in force changes at a reload, so neither is
+// captured at start: both ask the Live at the moment of asking. nil with no
+// policy.
+func watchQuarantine(live *policy.Live, m *metrics.Metrics,
 	now func() time.Time) func(device string, at time.Time) (string, bool) {
-	if pol == nil {
+	if live == nil {
 		return nil
 	}
 	m.CountQuarantined(func() int {
 		at, n := now(), 0
-		for _, q := range pol.Quarantines(at) {
+		for _, q := range live.Load().Quarantines(at) {
 			if slices.ContainsFunc(q.Entries, func(e policy.QuarantineEntry) bool { return e.Current(at) }) {
 				n++
 			}
 		}
 		return n
 	})
-	return pol.Quarantined
+	return live.Quarantined
 }
 
 func run(cfgPath string) error {
@@ -380,7 +409,7 @@ func run(cfgPath string) error {
 	sessions := session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
 	_ = sessions
 
-	brokerSrv, pol, err := buildBroker(cfg, st, minter, log, m)
+	brokerSrv, brk, err := buildBroker(cfg, st, minter, log, m)
 	if err != nil {
 		stopSpool()
 		<-spoolDone
@@ -412,7 +441,11 @@ func run(cfgPath string) error {
 	// A quarantined device is closed without a reply, as for an unknown
 	// source, so it falls to its local method exactly as in an outage.
 	// buildBroker has already named each one and its cause.
-	deps := server.Deps{Admission: cfg.Admission, Quarantined: watchQuarantine(pol, m, time.Now), Keys: cfg.Keyring(),
+	var live *policy.Live
+	if brk != nil {
+		live = brk.Policy
+	}
+	deps := server.Deps{Admission: cfg.Admission, Quarantined: watchQuarantine(live, m, time.Now), Keys: cfg.Keyring(),
 		// The context indexes are given the context's own idle TTL: they exist
 		// to let revocation reach a live context, so they need to outlast
 		// nothing the context does not.
```

<!-- write: cmd/port49d/policyfile.go -->
```go
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// geteuid is os.Geteuid, swapped in tests: CI has no second uid to own a file.
var geteuid = os.Geteuid

// readPolicyFile reads broker.policy_file, refusing a file anyone but the user
// port49d runs as, or root, could have written (spec §5.1.3). port49d reloads
// the file live (plan 4b), so whoever can write it decides every operator's
// access within seconds: the file must not be group- or world-writable, nor
// its directory, and the file must be owned by port49d's user or by root. It
// is keyfile's rule for a private key, for writing rather than reading.
//
// A symlink is followed, unlike keyfile's: a Kubernetes ConfigMap mounts the
// policy as a chain of them. What is checked is what is read — the final
// target, opened without following a link planted after the path was
// resolved, and the directory holding it, which is what decides who could
// replace it. The directories above that are not walked; keep the policy
// where only root can rename its directory.
//
// It is opened non-blocking, so a named pipe is refused rather than hanging a
// start or a reload until something writes to it.
func readPolicyFile(path string) ([]byte, error) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(target, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", target)
	}
	if err := writableByUsAlone("the file "+target, fi); err != nil {
		return nil, err
	}
	dir := filepath.Dir(target)
	di, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if err := writableByUsAlone("the directory "+dir, di); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// writableByUsAlone refuses what port49d's user or root is not the only one
// able to write.
func writableByUsAlone(what string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", what)
	}
	if euid := geteuid(); st.Uid != uint32(euid) && st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d; whoever can write the policy decides every operator's access, "+
			"so it must belong to the user port49d runs as (uid %d) or to root - chown it", what, st.Uid, euid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is mode %v, writable by others than its owner; whoever can write the policy "+
			"decides every operator's access - chmod go-w it", what, perm)
	}
	return nil
}
```

The lab harness starts `port49d` from a checkout, whose policy files and directories a umask of
002 leaves group-writable; `port49d` would now refuse them. The harness gives it a private copy,
and the by-hand run in the lab README makes the checkout's file safe.

<!-- patch: tests/lab/harness_test.go -->
```diff
diff --git a/tests/lab/harness_test.go b/tests/lab/harness_test.go
index 8fb816c..4b6183d 100644
--- a/tests/lab/harness_test.go
+++ b/tests/lab/harness_test.go
@@ -836,6 +836,10 @@ func (l *lab) derivedConfigCmd(suffix, attrs, cmdAttrs, extra string) (string, e
 	if suffix != "" {
 		name += "-" + suffix
 	}
+	out, err = privatePolicy(out, filepath.Join(dir, name+"-policy"))
+	if err != nil {
+		return "", err
+	}
 	path := filepath.Join(dir, name+".yaml")
 	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
 		return "", err
@@ -843,6 +847,46 @@ func (l *lab) derivedConfigCmd(suffix, attrs, cmdAttrs, extra string) (string, e
 	return path, nil
 }
 
+// privatePolicy copies the file a `policy_file:` line names into dir, a
+// directory only this user can write, and points the line at the copy.
+// port49d refuses a policy file anyone else could have written, or one in a
+// directory they could (spec §5.1.3), and a checkout under a umask of 002 —
+// the usual one on a desktop distribution — leaves the repository's policy
+// files and their directories group-writable.
+func privatePolicy(cfg, dir string) (string, error) {
+	const anchor = "  policy_file: "
+	i := strings.Index(cfg, anchor)
+	if i < 0 {
+		return cfg, nil
+	}
+	j := strings.Index(cfg[i:], "\n")
+	if j < 0 {
+		j = len(cfg) - i
+	}
+	src := strings.TrimSpace(cfg[i+len(anchor) : i+j])
+	if !filepath.IsAbs(src) {
+		src = filepath.Join(root, src)
+	}
+	raw, err := os.ReadFile(src)
+	if err != nil {
+		return "", err
+	}
+	if err := os.MkdirAll(dir, 0o700); err != nil {
+		return "", err
+	}
+	if err := os.Chmod(dir, 0o700); err != nil {
+		return "", err
+	}
+	dst := filepath.Join(dir, "policy.yaml")
+	if err := os.WriteFile(dst, raw, 0o600); err != nil {
+		return "", err
+	}
+	if err := os.Chmod(dst, 0o600); err != nil {
+		return "", err
+	}
+	return cfg[:i] + anchor + dst + cfg[i+j:], nil
+}
+
 // startDaemonWith starts port49d against cfgPath. resume appends to this
 // platform's log files instead of truncating them, which is what a test that
 // stops and restarts the daemon mid-run needs: a truncated decision log would
```

<!-- patch: tests/lab/README.md -->
```diff
diff --git a/tests/lab/README.md b/tests/lab/README.md
index b27d599..96b15aa 100644
--- a/tests/lab/README.md
+++ b/tests/lab/README.md
@@ -217,6 +217,9 @@ do sleep 10; done
 # any device configuration the run needs (plan 3 Task 17's RESTCONF AAA) goes here, as breakglass
 # the daemon config: the lab file, plus the broker block where the run needs a broker
 cat tests/lab/port49d-lab.yaml tests/lab/slice/broker.yaml > tests/lab/logs/port49d-byhand.yaml
+# a broker run only: port49d refuses a policy file, or a directory holding one, that others could
+# write (spec §5.1.3), and a checkout under a umask of 002 is group-writable
+chmod go-w tests/lab/slice tests/lab/slice/policy.yaml
 # a broker run only: its certificates, written before the daemon that loads them at start
 go run ./tests/lab/cmd/slice-pki
 PORT49_LAB_KEY=labsecret PORT49_LAB_ENC_KEY=port49-lab-encryption-key-32byte \
```

- [ ] **Step 4: Run the broker and port49d**

Run: `go test -race ./internal/broker/ ./cmd/port49d/ && make test && make vet && go vet -tags lab ./tests/lab/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/broker cmd/port49d tests/lab/harness_test.go tests/lab/README.md
git commit -m "feat: the broker mints from the policy in force; Server returns its refusal

Broker.Policy is a policy.Live, and a mint request holds one version from
its first device to its last token write, released before the response
is written. The daemon's quarantine question and gauge ask the Live at
the moment of asking. Server returns an error for a nil or empty anchor
pool instead of panicking (carried from plan 7). buildBroker's load and
start-up lines become loadPolicy, parsePolicy and sayPolicy, which a
reload will call. A policy file anyone but port49d's user or root could
have written is refused, and the lab harness gives port49d a private
copy of its policy.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 5: A refresh carries the policy in force into live contexts

**Files:**
- Create: `internal/broker/refresh.go`
- Modify: `internal/decision/reasons.go`, `internal/daemon/metrics/metrics.go`
- Test: `internal/broker/refresh_test.go`; modify `internal/daemon/metrics/metrics_test.go`

**Interfaces:**
- Consumes: `store.SetContextPolicy`, `store.ContextPolicy` (Task 2); `Policy.Principals`,
  `Live.Load` (Task 3); `Broker.Policy` as a `*policy.Live` (Task 4); `policy.MintCheck`,
  `Policy.Resolve`, `Policy.SubjectOf`, `engine.Encode` (plan 4); the broker's own `putBlob` and
  `emit`.
- Produces:
  - `type Prior struct { Policy *policy.Policy; At, Until time.Time }` — a policy in force since
    the last complete refresh, over the span it minted in: from `At` to `Until` (zero for the policy
    still in force); its answers are read at `At` and at every grant expiry in the span
    (`Prior.instants`, Decided 7).
  - `type RefreshReport struct { TokenKeys, Updated, Unchanged, Revoked, Quarantined, Failed int }`.
  - `func (b *Broker) Refresh(ctx context.Context, priors []Prior) (RefreshReport, error)` — the
    token supersede, then every live context; a store error ends the pass and is returned with the
    report so far; a context still changing after every attempt is revoked anyway where that is
    the answer, left for the retry otherwise, and the pass goes on and returns `store.ErrConflict`
    at the end (Decided 9).
  - `decision.EventRefresh = "refresh"`.
  - `metrics.Metrics.ContextRefreshes` — `port49_context_refreshes_total{outcome}`: `updated`,
    `unchanged`, `revoked`, `quarantined`, `failed`; `metrics.Metrics.TokensSuperseded` —
    `port49_tokens_superseded_total`.

Spec §5.1.3's refresh, with Decided 4 through 8 and 13. The context pass reads the indexes the
daemon keeps for exactly this — `active_principals`, then `contexts_by_principal` — and never
scans the keyspace. Each context is read, decided with no store access (`decideRefresh`), its
blob put and emitted before any context names it, and written by compare-and-set; a conflict reads
again, up to `store.MaxJoinAttempts`.

Three tests pin the pre-flight rulings: `TestASupersededPolicyIsJudgedAtEveryExpiryItSpanned` (a
token minted after an expiry the old policy spanned is superseded, though the answer at the span's
start matched), `TestABusyContextDoesNotStopTheRefresh` and `TestABusyContextIsRevokedAnyway`.
Each fails against the refresh without its ruling.

- [ ] **Step 1: Write the failing tests**

`login` in the test file mints through the broker and redeems as the daemon does — the context
takes the token's blob, ceiling and `enable`, and is indexed under the principal — so each test
starts from a context the broker really compiled. `decides` compiles the blob a context names,
from the store, and answers a command the way the daemon's authorizer does.

<!-- write: internal/broker/refresh_test.go -->
```go
package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
)

const alice = "user:alice@example.com"

// reload parses body against the fixture's inventory and swaps it in, as
// port49d does, returning what the refresh compares against: the policy it
// replaced, read at the instant of the swap.
func (f *fixture) reload(t *testing.T, body string) []Prior {
	t.Helper()
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: []admission.Device{f.b.Devices["leaf1"],
		f.b.Devices["nx1"], f.b.Devices["bare"]}, Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
}

// edit is testPolicy with each old string replaced by its new one, in order.
func edit(t *testing.T, pairs ...string) string {
	t.Helper()
	body := testPolicy
	for i := 0; i < len(pairs); i += 2 {
		if !strings.Contains(body, pairs[i]) {
			t.Fatalf("testPolicy has no %q", pairs[i])
		}
		body = strings.Replace(body, pairs[i], pairs[i+1], 1)
	}
	return body
}

// Edits to testPolicy: alice's one grant, the role list's last line, and that
// line with a read_only role after it.
const (
	aliceGrant = "roles: [network_admin, no_reload], max_privilege: admin"
	roleList   = "  - {name: no_reload, deny: [\"reload **\"]}\n"
	readOnly   = roleList + "  - {name: read_only, privilege: readonly, permit: [show **]}\n"
)

// login mints principal a token for device through the broker and redeems it
// as the daemon does (package authen): the context takes the token's blob,
// ceiling and enable mechanism, at priv-lvl 15, and is indexed under the
// principal. It returns the context as written.
func (f *fixture) login(t *testing.T, principal, device, username string) store.Context {
	t.Helper()
	cert := f.alice
	if principal != alice {
		cert = f.client(t, strings.TrimPrefix(principal, "user:"), f.now.Add(24*time.Hour))
	}
	if it := decodeMint(t, f.post(context.Background(), f.state(cert), `{"devices":["`+device+`"]}`, "")).Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint for %s on %s: %+v", principal, device, it)
	}
	ctx := context.Background()
	tk := store.TokenKey{NAS: device, Username: username}
	toks, err := f.st.Candidates(ctx, tk)
	if err != nil || len(toks) == 0 {
		t.Fatalf("no token to redeem: %v", err)
	}
	tok := toks[len(toks)-1]
	if err := f.st.DeleteTokens(ctx, tk); err != nil {
		t.Fatal(err)
	}
	k := store.ContextKey{NAS: device, Username: username}
	c := store.Context{CtxID: "ctx-" + device + "-" + username, Principal: principal, Username: username, PrivLvl: 15,
		BlobHash: tok.BlobHash, MaxPrivilege: tok.MaxPrivilege, Enable: tok.Enable, AuthTime: f.now,
		CreatedAt: f.now, RefreshedAt: f.now}
	if err := f.st.PutContext(ctx, k, c, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, principal, "", "", store.ContextRef{NAS: device, Username: username}, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.GetContext(ctx, k)
	return got
}

func (f *fixture) context(t *testing.T, device, username string) store.Context {
	t.Helper()
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: device, Username: username})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// decides compiles the blob a context names, from the store, and answers one
// command with it, as the daemon's authorizer does.
func (f *fixture) decides(t *testing.T, c store.Context, cmd ...string) bool {
	t.Helper()
	body, err := f.st.GetBlob(context.Background(), c.BlobHash)
	if err != nil {
		t.Fatalf("the context names a blob the store does not hold: %v", err)
	}
	b, err := engine.Decode(c.BlobHash, body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := engine.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	raw := []string{"service=shell", "cmd=" + cmd[0]}
	for _, a := range cmd[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return p.Command(append(raw, "cmd-arg=<cr>")).Permit
}

// The owner's goal (2026-09-24): a policy edit reaches a live session, and
// nobody is logged out. alice loses network_admin for read_only; her context
// keeps its ctx_id and its session, takes the new blob, and her next
// `configure` is denied while `show version` is still permitted.
func TestARefreshNarrowsALiveContextWithNoLogout(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	if !f.decides(t, before, "configure") {
		t.Fatal("before the edit alice may configure")
	}
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if after.CtxID != before.CtxID || !after.RevokedAt.IsZero() || after.BlobHash == before.BlobHash {
		t.Fatalf("the context must keep its ctx_id and take the new blob, unrevoked: %+v", after)
	}
	if f.decides(t, after, "configure") || !f.decides(t, after, "show", "version") {
		t.Fatal("after the edit alice's next configure is denied and show is permitted")
	}
	if rep.Updated != 1 || rep.Revoked != 0 {
		t.Fatalf("report: %+v", rep)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["verdict"] != "permit" || recs[0]["reason"] != "grants_matched" ||
		recs[0]["principal"] != alice {
		t.Fatalf("one refresh record, permit grants_matched: %v", recs)
	}
	if s, _ := recs[0]["session"].(map[string]any); s["ctx_id"] != before.CtxID {
		t.Fatalf("the record names the context's ctx_id: %v", recs[0])
	}
	if p, _ := recs[0]["policy"].(map[string]any); p["blob"] != after.BlobHash || p["bundle"] != f.b.Policy.Load().Bundle {
		t.Fatalf("the record names the blob and bundle written: %v", recs[0])
	}
	if n := testutil.ToFloat64(f.b.Metrics.ContextRefreshes.WithLabelValues("updated")); n != 1 {
		t.Fatalf("port49_context_refreshes_total{outcome=updated} = %v", n)
	}
	// The blob a context names is in the log, so a command decided against it
	// replays (spec §5.7).
	found := false
	for _, b := range f.blobRecords(t) {
		found = found || b.Hash == after.BlobHash
	}
	if !found {
		t.Fatal("the refreshed blob was never emitted")
	}
}

// A principal left with no grant on a device has that context revoked, not
// deleted: the next command is denied credential_revoked, distinguishable from
// a session port49 never saw (spec §5.6 row 2). The same edit supersedes her
// unspent token on nx1, which a redemption would otherwise turn into a fresh
// context carrying the grant the edit removed.
func TestARefreshRevokesAContextWhoseGrantIsGone(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["nx1"]}`, ""))
	priors := f.reload(t, edit(t, "  - {subject: netops, scope: all_devices, "+aliceGrant+"}\n",
		"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n"))
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if !after.RevokedAt.Equal(f.now) || after.BlobHash != before.BlobHash || after.CtxID != before.CtxID {
		t.Fatalf("the context is marked revoked at the refresh, and nothing else changes: %+v", after)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("alice's unspent nx1 token must be deleted: %d left", len(toks))
	}
	if rep.Revoked != 1 || rep.TokenKeys != 1 {
		t.Fatalf("report: %+v", rep)
	}
	recs := eventsOf(f.records(t), "refresh")
	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "no_grants_matched" {
		t.Fatalf("one refresh record, deny no_grants_matched: %v", recs)
	}
	if n := testutil.ToFloat64(f.b.Metrics.TokensSuperseded); n != 1 {
		t.Fatalf("port49_tokens_superseded_total = %v", n)
	}
}

// A lowered max_privilege reaches the next command: the held level comes down
// to the new ceiling (the join's rule, spec §5.3), and the record says from
// what to what, which is what explains the privilege_exceeded that follows.
func TestALoweredCeilingClampsTheHeldLevel(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: readonly"))
	f.log.Reset()
	if _, err := f.b.Refresh(context.Background(), priors); err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if after.PrivLvl != 1 || after.MaxPrivilege != 1 {
		t.Fatalf("the held level must come down to readonly's priv-lvl 1: %+v", after)
	}
	recs := eventsOf(f.records(t), "refresh")
	s, _ := recs[0]["session"].(map[string]any)
	clamp, _ := s["privilege_clamped"].(map[string]any)
	if clamp["from"] != 15.0 || clamp["to"] != 1.0 || s["privilege"] != 1.0 {
		t.Fatalf("the record says the level was clamped from 15 to 1: %v", recs[0])
	}
}

// A context on a device the new policy quarantines is left as it is: the
// daemon answers nothing from that device now, and the refresh that lifts the
// quarantine reaches it. The record says so. The edit lands alice at a level
// the policy declares and no built-in platform renders, which quarantines
// every device she reaches (spec §10), whatever the dialect table renders
// for the reserved levels.
func TestARefreshLeavesAQuarantinedDevicesContextAlone(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	priors := f.reload(t, "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n"+
		edit(t, "{name: network_admin, privilege: admin,", "{name: network_admin, privilege: unmapped,"))
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	if after := f.context(t, "leaf1", "alice"); after.BlobHash != before.BlobHash || !after.RevokedAt.IsZero() {
		t.Fatalf("a quarantined device's context is left as it was: %+v", after)
	}
	recs := eventsOf(f.records(t), "refresh")
	if rep.Quarantined != 1 || len(recs) != 1 || recs[0]["reason"] != "device_quarantined" {
		t.Fatalf("report %+v, records %v", rep, recs)
	}
}

// An edit that changes no one's answer — here a comment — deletes no token: a
// reload is not a reason to make everyone mint again. Every live context still
// takes the new bundle's blob, so the records after the reload name the policy
// that was in force when they were decided. A second pass finds nothing to do.
func TestAnEditThatChangesNoAnswerKeepsEveryToken(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["nx1"]}`, ""))
	priors := f.reload(t, testPolicy+"# reviewed 2026-09-24\n")
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
		t.Fatalf("an unchanged answer keeps its token: %d left", len(toks))
	}
	after := f.context(t, "leaf1", "alice")
	if rep.TokenKeys != 0 || rep.Updated != 1 || after.BlobHash == before.BlobHash {
		t.Fatalf("report %+v; the context takes the new bundle's blob: %+v", rep, after)
	}
	rep, err = f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: f.now}})
	if err != nil || rep.Unchanged != 1 || rep.Updated != 0 {
		t.Fatalf("a second pass: %+v %v", rep, err)
	}
}

// What a refresh does not touch: a context the lab's instrument answers (no
// blob), one already revoked (a refresh never lifts a mark), and one that
// another principal's login has taken since the index was read.
func TestARefreshSkipsWhatIsNotItsToChange(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	f.login(t, alice, "leaf1", "alice")
	lab := store.ContextKey{NAS: "nx1", Username: "alice"}
	f.st.PutContext(ctx, lab, store.Context{CtxID: "lab", Principal: alice, Username: "alice", PrivLvl: 15}, time.Hour)
	f.st.IndexContext(ctx, alice, "", "", store.ContextRef{NAS: "nx1", Username: "alice"}, time.Hour)
	f.st.SetRevokedAt(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}, f.now.Add(-time.Minute))
	taken := store.ContextKey{NAS: "leaf1", Username: "al"}
	f.st.PutContext(ctx, taken, store.Context{CtxID: "carol", Principal: "user:carol@example.com", Username: "al",
		BlobHash: "sha256:carol"}, time.Hour)
	f.st.IndexContext(ctx, alice, "", "", store.ContextRef{NAS: "leaf1", Username: "al"}, time.Hour)
	priors := f.reload(t, edit(t, aliceGrant, "roles: [no_reload], max_privilege: admin"))
	rep, err := f.b.Refresh(ctx, priors)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Updated+rep.Revoked+rep.Unchanged+rep.Quarantined+rep.Failed != 0 {
		t.Fatalf("nothing here is the refresh's to change: %+v", rep)
	}
	if c := f.context(t, "nx1", "alice"); c.BlobHash != "" || !c.RevokedAt.IsZero() {
		t.Fatalf("the lab's context was touched: %+v", c)
	}
	if c := f.context(t, "leaf1", "alice"); !c.RevokedAt.Equal(f.now.Add(-time.Minute)) {
		t.Fatalf("a revoked context was touched: %+v", c)
	}
	if c := f.context(t, "leaf1", "al"); c.BlobHash != "sha256:carol" || !c.RevokedAt.IsZero() {
		t.Fatalf("another principal's context was given alice's answer: %+v", c)
	}
}

// racingStore lands a write on the context between the refresh's read and its
// compare-and-set, once — a login joining with a token minted under the
// previous policy, say — and counts the attempts.
type racingStore struct {
	store.Store
	raced    bool
	attempts int
}

func (r *racingStore) SetContextPolicy(ctx context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
	r.attempts++
	if !r.raced {
		r.raced = true
		if err := r.Store.AnnotateContext(ctx, k, "", store.AccountingStateOpen); err != nil {
			return err
		}
	}
	return r.Store.SetContextPolicy(ctx, k, rev, p)
}

// A write that lands between the read and the refresh's own is not
// overwritten: the compare-and-set refuses, the refresh reads again and
// decides again, and the write it raced survives beside the new policy.
func TestARefreshThatLosesARaceReadsAgain(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	racing := &racingStore{Store: f.st}
	f.b.Store = racing
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	after := f.context(t, "leaf1", "alice")
	if racing.attempts != 2 || rep.Updated != 1 || after.AccountingState != store.AccountingStateOpen ||
		f.decides(t, after, "configure") {
		t.Fatalf("attempts %d, report %+v, context %+v", racing.attempts, rep, after)
	}
}

// failingStore fails the index read a refresh starts from.
type failingStore struct{ store.Store }

func (failingStore) ActivePrincipals(context.Context) ([]string, error) {
	return nil, errors.New("store: connection refused")
}

// A store that fails mid-refresh ends the pass with the error and what was
// done so far; the policy is already in force for every mint, and port49d
// runs the pass again (plan 4b). Nothing is half-written to any context.
func TestARefreshReturnsAStoreErrorForTheCallerToRetry(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.b.Store = failingStore{f.st}
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	if _, err := f.b.Refresh(context.Background(), priors); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("the store's error is returned: %v", err)
	}
	f.b.Store = f.st
	if rep, err := f.b.Refresh(context.Background(), priors); err != nil || rep.Updated != 1 {
		t.Fatalf("the pass run again finishes the job: %+v %v", rep, err)
	}
}

// A widening applies from the next command too: dropping no_reload lets
// alice's next `reload` through, in the session she already has.
func TestARefreshWidensALiveContext(t *testing.T) {
	f := newFixture(t, 8)
	before := f.login(t, alice, "leaf1", "alice")
	if f.decides(t, before, "reload") {
		t.Fatal("before the edit no_reload denies reload")
	}
	priors := f.reload(t, edit(t, aliceGrant, "roles: [network_admin], max_privilege: admin"))
	if _, err := f.b.Refresh(context.Background(), priors); err != nil {
		t.Fatal(err)
	}
	if after := f.context(t, "leaf1", "alice"); after.CtxID != before.CtxID || !f.decides(t, after, "reload") {
		t.Fatalf("after the edit the same context permits reload: %+v", after)
	}
}

// A grant's expiry changes a resolution with no edit to the file, and the
// refresh port49d runs at that instant (policy.NextChange) carries it into the
// live context: the policy's own schedule, applied like an edit (spec §5.1).
func TestAGrantsExpiryReachesALiveContext(t *testing.T) {
	f := newFixture(t, 8)
	lapse := f.now.Add(time.Hour)
	priors := f.reload(t, edit(t, aliceGrant, aliceGrant+", expires: "+lapse.UTC().Format(time.RFC3339)))
	f.login(t, alice, "leaf1", "alice")
	if _, err := f.b.Refresh(context.Background(), priors); err != nil {
		t.Fatal(err)
	}
	if c := f.context(t, "leaf1", "alice"); !c.RevokedAt.IsZero() {
		t.Fatalf("before the expiry the grant stands: %+v", c)
	}
	start := f.now
	f.advance(time.Hour)
	rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Load(), At: start}})
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("at the expiry the context is revoked: %+v %v", rep, err)
	}
}

// A superseded policy's tokens are judged at every instant it could have
// minted them, not only where its span began (spec §5.1.3). Here alice also
// holds read_only until a lapse, and the pass that would have run at the lapse
// never completed, so her prior's span starts before it. Her token minted
// after the lapse carries no read_only; the new policy gives read_only for
// good, which is what the old one said at the start of its span — and not
// what it minted.
func TestASupersededPolicyIsJudgedAtEveryExpiryItSpanned(t *testing.T) {
	f := newFixture(t, 8)
	start := f.now
	lapse := f.now.Add(time.Hour)
	extra := "  - {subject: netops, scope: all_devices, roles: [read_only]"
	f.reload(t, edit(t, roleList, readOnly)+extra+", expires: "+lapse.UTC().Format(time.RFC3339)+"}\n")
	f.advance(2 * time.Hour)
	if it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint after the lapse: %+v", it)
	}
	pol, err := policy.Parse([]byte(edit(t, roleList, readOnly)+extra+"}\n"), policy.Env{Devices: []admission.Device{
		f.b.Devices["leaf1"], f.b.Devices["nx1"], f.b.Devices["bare"]}, Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	priors := []Prior{{Policy: f.b.Policy.Swap(pol), At: start, Until: f.b.Now()}}
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil {
		t.Fatal(err)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 || rep.TokenKeys != 1 {
		t.Fatalf("the token minted after the lapse must be superseded: %d left, report %+v", len(toks), rep)
	}
}

// stuckStore conflicts every compare-and-set on one context: a session busy
// enough that every read the refresh makes is stale by its write.
type stuckStore struct {
	store.Store
	stuck store.ContextKey
}

func (s stuckStore) SetContextPolicy(ctx context.Context, k store.ContextKey, rev uint64, p store.ContextPolicy) error {
	if k == s.stuck {
		return store.ErrConflict
	}
	return s.Store.SetContextPolicy(ctx, k, rev, p)
}

// One busy context does not hold every context after it on the superseded
// policy: it is counted failed and left for the retry, the pass goes on, and
// the error it returns is the conflict, so port49d runs it again.
func TestABusyContextDoesNotStopTheRefresh(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.login(t, alice, "nx1", "alice")
	f.b.Store = stuckStore{Store: f.st, stuck: store.ContextKey{NAS: "leaf1", Username: "alice"}}
	priors := f.reload(t, edit(t, roleList, readOnly, aliceGrant, "roles: [read_only], max_privilege: admin"))
	rep, err := f.b.Refresh(context.Background(), priors)
	if !errors.Is(err, store.ErrConflict) || rep.Failed != 1 || rep.Updated != 1 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	if f.decides(t, f.context(t, "nx1", "alice"), "configure") {
		t.Fatal("the context after the busy one must still be refreshed")
	}
}

// A revocation is not left for the retry: where the answer is no grant, a
// context whose every compare-and-set conflicts is marked revoked anyway, by
// the setter that writes the mark alone (fail closed).
func TestABusyContextIsRevokedAnyway(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.b.Store = stuckStore{Store: f.st, stuck: store.ContextKey{NAS: "leaf1", Username: "alice"}}
	priors := f.reload(t, edit(t, "  - {subject: netops, scope: all_devices, "+aliceGrant+"}\n",
		"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n"))
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatalf("the busy context must be revoked: %+v", c)
	}
}
```

<!-- patch: internal/daemon/metrics/metrics_test.go -->
```diff
diff --git a/internal/daemon/metrics/metrics_test.go b/internal/daemon/metrics/metrics_test.go
index a8dad14..53c559b 100644
--- a/internal/daemon/metrics/metrics_test.go
+++ b/internal/daemon/metrics/metrics_test.go
@@ -31,6 +31,8 @@ func TestNewRegistersEveryMetric(t *testing.T) {
 	m.BrokerItemErrors.WithLabelValues("device_unconfigured").Inc()
 	m.BlobCache.WithLabelValues("hit").Inc()
 	m.CountQuarantined(func() int { return 1 })
+	m.ContextRefreshes.WithLabelValues("updated").Inc()
+	m.TokensSuperseded.Inc()
 
 	// Gather all metrics from registry.
 	families, err := reg.Gather()
@@ -57,6 +59,8 @@ func TestNewRegistersEveryMetric(t *testing.T) {
 		"port49_broker_item_errors_total":          false,
 		"port49_blob_cache_lookups_total":          false,
 		"port49_devices_quarantined":               false,
+		"port49_context_refreshes_total":           false,
+		"port49_tokens_superseded_total":           false,
 	}
 
 	// Check that all expected metrics are present and all gathered metrics are snake_case.
```

- [ ] **Step 2: Run them to see them fail**

Run: `go vet ./internal/broker/ ./internal/daemon/metrics/`
Expected: FAIL to build — `m.ContextRefreshes undefined` in metrics, `undefined: Prior` in the
broker.

- [ ] **Step 3: Add the event and the metrics, and write the refresh**

<!-- patch: internal/decision/reasons.go -->
```diff
diff --git a/internal/decision/reasons.go b/internal/decision/reasons.go
index 78d8863..e4aa1a1 100644
--- a/internal/decision/reasons.go
+++ b/internal/decision/reasons.go
@@ -71,6 +71,11 @@ const (
 	EventUnvalidated      = "unvalidated" // not a decision; header-only diagnosis record (spec §10)
 )
 
+// EventRefresh is the broker carrying the policy in force into a live login
+// context (spec §5.1.3): the policy written into it, or the context revoked.
+// It is a decision, so it has a verdict and a reason from the table above.
+const EventRefresh = "refresh"
+
 const (
 	VerdictPermit = "permit"
 	VerdictDeny   = "deny"
```

<!-- patch: internal/daemon/metrics/metrics.go -->
```diff
diff --git a/internal/daemon/metrics/metrics.go b/internal/daemon/metrics/metrics.go
index 0064a9e..9014b56 100644
--- a/internal/daemon/metrics/metrics.go
+++ b/internal/daemon/metrics/metrics.go
@@ -75,6 +75,21 @@ type Metrics struct {
 	// leave; the gauge is what an alert watches, and it names no device.
 	DevicesQuarantined prometheus.GaugeFunc
 	quarantined        atomic.Pointer[func() int]
+	// port49_context_refreshes_total{outcome}: live login contexts a policy
+	// refresh visited, by what it did to each (spec §5.1.3) — "updated" (the
+	// policy in force written into it), "unchanged", "revoked" (no grant left
+	// on that device), "quarantined" (the device is quarantined; the context
+	// is left as it was), or "failed" (a context that could not be read, a
+	// policy that could not be compiled for it, or a context still changing
+	// after every compare-and-set attempt; the process log says which).
+	// A context the refresh skipped — another principal's since, the lab's,
+	// already revoked — is not counted. The label is the outcome only.
+	ContextRefreshes *prometheus.CounterVec
+	// port49_tokens_superseded_total: (device, username) keys whose unspent
+	// tokens a policy change deleted, because the policy now in force would
+	// not mint what they carry. Each is one operator's `port49 token` to run
+	// again; none is a session ended.
+	TokensSuperseded prometheus.Counter
 }
 
 // CountQuarantined sets what port49_devices_quarantined reports at each scrape.
@@ -123,6 +138,10 @@ func New(reg prometheus.Registerer) *Metrics {
 			Help: "Mint items the broker could not decide, by API error code."}, []string{"error"}),
 		BlobCache: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_blob_cache_lookups_total",
 			Help: "Compiled-blob cache lookups by the authorizer, by outcome."}, []string{"outcome"}),
+		ContextRefreshes: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_context_refreshes_total",
+			Help: "Live login contexts a policy refresh visited, by outcome."}, []string{"outcome"}),
+		TokensSuperseded: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_tokens_superseded_total",
+			Help: "(device, username) keys whose unspent tokens a policy change deleted."}),
 	}
 	m.DevicesQuarantined = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_devices_quarantined",
 		Help: "Inventory devices the loaded policy quarantines now."}, func() float64 {
@@ -134,6 +153,6 @@ func New(reg prometheus.Registerer) *Metrics {
 	reg.MustRegister(m.Requests, m.Latency, m.Decisions, m.Unvalidated, m.KeyValidations,
 		m.Connections, m.ConnectionEvents, m.AuthFailures, m.SpoolDepth, m.SpoolDrops, m.SpoolQuarantines,
 		m.StoreOps, m.DecisionLogWriteFailures, m.CryptOpenFailures, m.Attributions, m.BrokerItemErrors, m.BlobCache,
-		m.DevicesQuarantined)
+		m.DevicesQuarantined, m.ContextRefreshes, m.TokensSuperseded)
 	return m
 }
```

<!-- write: internal/broker/refresh.go -->
```go
package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
)

// Prior is a policy that has been in force since the last complete refresh,
// and the span it minted in: from At — when the last complete refresh ran, or
// when it came into force if that was later — to Until, when it was replaced;
// zero for the policy still in force, whose span runs to the refresh. A token
// it minted carries its answer at the instant of the mint, and a resolution
// changes only at a grant's expiry, so its answers are read at At and at every
// expiry in the span (instants). The refresh that runs at each expiry would
// otherwise close the span there, but one the store stopped does not.
type Prior struct {
	Policy *policy.Policy
	At     time.Time
	Until  time.Time
}

// instants are the times at which pr's answers are read: At, and every grant
// expiry after it up to Until (now, for the policy still in force).
func (pr Prior) instants(now time.Time) []time.Time {
	until := pr.Until
	if until.IsZero() {
		until = now
	}
	out := []time.Time{pr.At}
	for t := pr.At; ; {
		next, ok := pr.Policy.NextChange(t)
		if !ok || next.After(until) {
			return out
		}
		out = append(out, next)
		t = next
	}
}

// RefreshReport counts what one refresh did, for the line port49d writes after
// it. The context counts are port49_context_refreshes_total's outcomes.
type RefreshReport struct {
	// TokenKeys is how many (device, username) keys had their unspent tokens
	// deleted as superseded.
	TokenKeys                                        int
	Updated, Unchanged, Revoked, Quarantined, Failed int
}

// Refresh carries the policy in force into everything the policies before it
// left behind (spec §5.1.3), and is what makes a policy edit reach a live
// session with no logout (plan 4b). It runs after every reload and at every
// grant expiry, and it can be run again: a pass that stopped part-way is
// finished by the next.
//
// First the tokens. A token carries its blob hash, ceiling and enable
// mechanism from the policy that minted it, and a redemption writes them into
// the context it creates or joins. So an unspent token minted under a prior
// policy whose answer the policy in force would not give is deleted, key by
// key; otherwise a grant removed at 10:00 comes back at 10:05 on a device where
// the operator had no context yet, from a token minted at 09:58. A token the
// policy in force would mint identically is left alone: a reload is not a
// reason to make everyone run `port49 token` again.
//
// Then the contexts: every live context of every active principal is
// re-resolved against the policy in force, for that principal on that device,
// and the answer is written into it by compare-and-set (store.SetContextPolicy)
// — the blob, the ceiling (a held level above a lowered one comes down to it)
// and the enable mechanism. A principal left with no grant on the device has
// the context revoked instead, so its next command is denied
// `credential_revoked` (spec §5.6 row 2). A context on a device quarantined now
// is left as it is: the daemon answers nothing from that device while it is
// quarantined, and the refresh at the reload or expiry that lifts the
// quarantine reaches it. Nobody is logged out: a narrowed rule denies the next
// command, a widened one permits it, and the session goes on.
//
// Every context the refresh changes, and every one it leaves for a quarantine,
// is one `refresh` decision record naming the context's ctx_id, so the record
// before a command's changed answer says why.
//
// A store error ends the pass and is returned with the report so far; nothing
// is half-written to any one context, and the caller runs it again. A context
// still changing after every attempt does not end it: it is revoked anyway
// where that is the answer, left for the retry otherwise, and the pass returns
// store.ErrConflict at the end so the caller runs it again.
func (b *Broker) Refresh(ctx context.Context, priors []Prior) (RefreshReport, error) {
	cur, now := b.Policy.Load(), b.Now()
	var rep RefreshReport
	if err := b.supersedeTokens(ctx, cur, now, priors, &rep); err != nil {
		return rep, fmt.Errorf("deleting superseded tokens: %w", err)
	}
	if err := b.refreshContexts(ctx, cur, now, &rep); err != nil {
		return rep, fmt.Errorf("refreshing live contexts: %w", err)
	}
	return rep, nil
}

// minted is what a token for one principal on one device carries of its
// policy, the bundle aside: every policy file has its own bundle, so comparing
// it would supersede every token at every edit.
type minted struct {
	username string
	blob     []byte
	ceiling  uint8
	enable   string
}

// mintedBy is what p would mint for principal on d at at, and false when it
// would mint nothing: no grant, a quarantine, or a refusal the broker makes as
// an item error (policy.MintCheck).
func mintedBy(p *policy.Policy, principal string, d admission.Device, at time.Time) (minted, bool) {
	res, err := p.Resolve(principal, d, at)
	if err != nil {
		return minted{}, false
	}
	if code, _ := policy.MintCheck(res, principal, d.Name); code != "" {
		return minted{}, false
	}
	blob := res.Blob
	blob.Bundle = "-" // Encode refuses an empty bundle; every real one is a sha256
	body, _, err := engine.Encode(blob)
	if err != nil {
		return minted{}, false
	}
	return minted{username: res.Username, blob: body, ceiling: res.MaxPrivilege, enable: res.Enable}, true
}

func (m minted) same(o minted) bool {
	return m.username == o.username && bytes.Equal(m.blob, o.blob) && m.ceiling == o.ceiling && m.enable == o.enable
}

// supersedeTokens deletes the unspent tokens of every (device, username) where
// a prior policy minted something, at any instant of its span, that the policy
// in force would not. A key is
// cleared whole: tokens are keyed by it, and every principal minting under one
// username is one subject, whose answer changed. That includes a token minted
// under the policy in force between the swap and this pass — the operator runs
// `port49 token` again, and the refresh runs straight after the swap to keep
// that window short.
func (b *Broker) supersedeTokens(ctx context.Context, cur *policy.Policy, now time.Time, priors []Prior,
	rep *RefreshReport) error {
	names := make([]string, 0, len(b.Devices))
	for name := range b.Devices {
		names = append(names, name)
	}
	sort.Strings(names)
	type answer struct {
		m  minted
		ok bool
	}
	current := map[[2]string]answer{} // the policy in force's, by (principal, device), computed once
	keys := map[store.TokenKey]bool{}
	for _, pr := range priors {
		instants := pr.instants(now)
		for _, principal := range pr.Policy.Principals() {
			for _, name := range names {
				d := b.Devices[name]
				for _, at := range instants {
					was, ok := mintedBy(pr.Policy, principal, d, at)
					if !ok {
						continue // nothing was minted then, so nothing is superseded
					}
					is, seen := current[[2]string{principal, name}]
					if !seen {
						is.m, is.ok = mintedBy(cur, principal, d, now)
						current[[2]string{principal, name}] = is
					}
					if is.ok && was.same(is.m) {
						continue
					}
					keys[store.TokenKey{NAS: name, Username: was.username}] = true
				}
			}
		}
	}
	ordered := make([]store.TokenKey, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].NAS != ordered[j].NAS {
			return ordered[i].NAS < ordered[j].NAS
		}
		return ordered[i].Username < ordered[j].Username
	})
	for _, k := range ordered {
		// Read first only to count: a key whose tokens are all spent or
		// expired supersedes nothing an operator would notice.
		toks, err := b.Store.Candidates(ctx, k)
		if err != nil {
			return err
		}
		if err := b.Store.DeleteTokens(ctx, k); err != nil {
			return err
		}
		if len(toks) > 0 {
			rep.TokenKeys++
			b.Metrics.TokensSuperseded.Inc()
		}
	}
	return nil
}

// refreshContexts visits every live context through the indexes the daemon
// keeps for exactly this (spec §5.1.3): active_principals, then each one's
// contexts_by_principal. A store error ends the pass. A context still changing
// after every attempt does not: it is left for the retry, the pass goes on,
// and the conflict is returned at the end so the caller runs it again — one
// busy session must not hold every session after it on the superseded policy.
func (b *Broker) refreshContexts(ctx context.Context, cur *policy.Policy, now time.Time, rep *RefreshReport) error {
	principals, err := b.Store.ActivePrincipals(ctx)
	if err != nil {
		return err
	}
	var busy error
	for _, principal := range principals {
		refs, err := b.Store.ContextsByPrincipal(ctx, principal)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			switch err := b.refreshContext(ctx, cur, now, principal, ref, rep); {
			case errors.Is(err, store.ErrConflict):
				if busy == nil {
					busy = err
				}
			case err != nil:
				return err
			}
		}
	}
	return busy
}

// refreshContext re-resolves one context and writes the answer, reading again
// and deciding again when a write landed between its read and its own, up to
// store.MaxJoinAttempts times.
func (b *Broker) refreshContext(ctx context.Context, cur *policy.Policy, now time.Time, principal string,
	ref store.ContextRef, rep *RefreshReport) error {
	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
	var step refreshStep
	for attempt := 0; attempt < store.MaxJoinAttempts; attempt++ {
		c, err := b.Store.GetContext(ctx, k)
		var unreadable *store.UnreadableContextError
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil // the index outlived the context; its own TTL reclaims it
		case errors.As(err, &unreadable):
			// Sealed under a key that has left the two-key window: whose it
			// is cannot be read, the authorizer cannot open it either and
			// answers it store_unavailable, and the next login replaces it.
			log.Printf("broker: refresh: the context for %q on %q will not open (%v); left as it is", ref.Username,
				ref.NAS, err)
			b.count(rep, "failed")
			return nil
		case err != nil:
			return err
		}
		// Another principal's since the index was read (its own pass reaches
		// it), the lab's instrument's (no blob; it answers from config), or
		// revoked already (a refresh never lifts a mark, store.Store).
		if c.Principal != principal || c.BlobHash == "" || !c.RevokedAt.IsZero() {
			return nil
		}
		step = b.decideRefresh(cur, now, principal, ref, c)
		if step.write == nil {
			if step.outcome != "unchanged" {
				b.emit(step.rec)
			}
			b.count(rep, step.outcome)
			return nil
		}
		// The blob is in the store, and in the log, before any context
		// names it: the daemon's next command reads it by that name.
		if step.body != nil {
			if err := b.putBlob(ctx, step.write.BlobHash, step.body); err != nil {
				return err
			}
		}
		switch err := b.Store.SetContextPolicy(ctx, k, c.Rev, *step.write); {
		case errors.Is(err, store.ErrConflict):
			continue
		case errors.Is(err, store.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		if step.rec.Event != "" { // a fault is logged, not recorded: no decision was made
			b.emit(step.rec)
		}
		b.count(rep, step.outcome)
		return nil
	}
	// Still changing after every attempt: a session busy enough that every
	// read was stale by its write. A revocation is not left for the retry. It
	// is the one answer that is safe without the read, so it lands now
	// through SetRevokedAt, which writes the mark alone: fail closed, at the
	// worst revoking a login another principal made a moment ago, whose owner
	// logs in again. Anything else is counted failed and left for the retry.
	if step.write != nil && !step.write.RevokedAt.IsZero() {
		switch err := b.Store.SetRevokedAt(ctx, k, step.write.RevokedAt); {
		case errors.Is(err, store.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		if step.rec.Event != "" {
			b.emit(step.rec)
		}
		b.count(rep, step.outcome)
		return nil
	}
	log.Printf("broker: refresh: the context for %q on %q was still changing after %d attempts; left for the retry",
		ref.Username, ref.NAS, store.MaxJoinAttempts)
	b.count(rep, "failed")
	return fmt.Errorf("the context for %q on %q was still changing after %d attempts: %w", ref.Username, ref.NAS,
		store.MaxJoinAttempts, store.ErrConflict)
}

// refreshStep is one context's answer: the write, when there is one (nil
// leaves the context as it is), the blob it names, the decision record, and
// the outcome it is counted under.
type refreshStep struct {
	write   *store.ContextPolicy
	body    []byte
	rec     decision.Record
	outcome string
}

// decideRefresh is what the policy in force says about principal on the
// context's device now. It reads no store.
func (b *Broker) decideRefresh(cur *policy.Policy, now time.Time, principal string, ref store.ContextRef,
	c store.Context) refreshStep {
	rec := decision.Record{TS: now, Event: decision.EventRefresh, Principal: principal,
		Device:  &decision.Device{Name: ref.NAS},
		Session: &decision.Session{CtxID: c.CtxID, Username: c.Username, Privilege: c.PrivLvl},
		Policy:  &decision.Policy{Bundle: cur.Bundle}}
	rec.Policy.Subject, _ = cur.SubjectOf(principal)
	revoke := func() refreshStep {
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.NoGrantsMatched
		return refreshStep{write: &store.ContextPolicy{RevokedAt: now}, rec: rec, outcome: "revoked"}
	}
	dev, ok := b.Devices[ref.NAS]
	if !ok {
		// Inventory is read once, at start, so a live context on a device it
		// does not name was written by a daemon reading another inventory.
		// Nothing can be minted for it here.
		return revoke()
	}
	rec.Device.Platform = dev.Platform
	res, err := cur.Resolve(principal, dev, now)
	if err == nil {
		rec.Policy.Grants = res.Grants
	}
	switch {
	case errors.Is(err, policy.ErrNoGrants):
		return revoke()
	case errors.Is(err, policy.ErrDeviceQuarantined):
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.DeviceQuarantined
		return refreshStep{rec: rec, outcome: "quarantined"}
	case err != nil:
		// The load's joint checks compile every subject on every device at
		// every expiry and quarantine the ones that fail, so this is a broker
		// defect, as it is at mint. The context is revoked rather than left
		// on a policy that is no longer in force; the process log says why,
		// and no decision record does, because no decision was made.
		log.Printf("broker: refresh: resolving %s on %q: %v; revoking the context (ctx_id %s)", principal, ref.NAS,
			err, c.CtxID)
		return refreshStep{write: &store.ContextPolicy{RevokedAt: now}, outcome: "failed"}
	case res.Username != c.Username:
		// The subject's username changed: the principal can no longer mint
		// under the name this context is keyed by.
		return revoke()
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		log.Printf("broker: refresh: the policy for %s on %q compiled to a blob the daemon would refuse: %v; "+
			"revoking the context (ctx_id %s)", principal, ref.NAS, err, c.CtxID)
		return refreshStep{write: &store.ContextPolicy{RevokedAt: now}, outcome: "failed"}
	}
	if code, detail := policy.MintCheck(res, principal, ref.NAS); code != "" {
		// The mint would refuse this principal a token here, as an item
		// error. The context still takes the new rules — its commands are
		// decided by the policy in force — and the daemon refuses the session
		// reply it cannot build, blob_unavailable, as it would have for a
		// token (spec §6).
		log.Printf("broker: refresh: the session reply for %s on %q will be refused (%s): %s", principal, ref.NAS,
			code, detail)
	}
	if hash == c.BlobHash && res.MaxPrivilege == c.MaxPrivilege && res.Enable == c.Enable {
		return refreshStep{outcome: "unchanged"}
	}
	rec.Verdict, rec.Reason, rec.Policy.Blob = decision.VerdictPermit, decision.GrantsMatched, hash
	if ceiling := res.MaxPrivilege; res.HasCeiling && c.PrivLvl > ceiling {
		rec.Session.PrivilegeClamped = &decision.PrivilegeClamp{From: c.PrivLvl, To: ceiling}
		rec.Session.Privilege = ceiling
	}
	return refreshStep{write: &store.ContextPolicy{BlobHash: hash, MaxPrivilege: res.MaxPrivilege, Enable: res.Enable},
		body: body, rec: rec, outcome: "updated"}
}

// count adds one context to the report and the metric.
func (b *Broker) count(rep *RefreshReport, outcome string) {
	switch outcome {
	case "updated":
		rep.Updated++
	case "unchanged":
		rep.Unchanged++
	case "revoked":
		rep.Revoked++
	case "quarantined":
		rep.Quarantined++
	case "failed":
		rep.Failed++
	}
	b.Metrics.ContextRefreshes.WithLabelValues(outcome).Inc()
}
```

- [ ] **Step 4: Run the broker, with the race detector**

Run: `go test -race ./internal/broker/ ./internal/daemon/metrics/ ./internal/decision/ && make test && make vet`
Expected: PASS — the narrowing, widening, revocation, clamp, quarantine, unchanged-edit, skip, race,
store-error, expiry, span and busy-context tests among them.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/refresh.go internal/broker/refresh_test.go internal/decision/reasons.go internal/daemon/metrics
git commit -m "feat: a policy refresh carries the policy in force into live contexts

Broker.Refresh re-resolves every live context's principal on its device
against the policy in force and writes the answer by compare-and-set:
the new blob, ceiling and enable, or a revocation where no grant is left.
A quarantined device's context is left for the refresh that lifts it.
Unspent tokens a superseded policy minted, whose answer changed, are
deleted. Each change is a refresh decision record naming the ctx_id.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 6: `port49d` watches the policy file and reloads it live

**Files:**
- Create: `cmd/port49d/reload.go`
- Modify: `cmd/port49d/main.go`, `internal/config/config.go`, `internal/daemon/metrics/metrics.go`
- Test: `cmd/port49d/reload_test.go`; modify `internal/config/broker_test.go`,
  `internal/daemon/metrics/metrics_test.go`

**Interfaces:**
- Consumes: `Broker.Refresh`, `Prior`, `RefreshReport` (Task 5); `Live.Swap`, `Live.Load`,
  `Policy.NextChange` (Task 3); `parsePolicy`, `sayPolicy` (Task 4).
- Produces:
  - `config.BrokerConfig.PolicyWatchInterval` — `broker.policy_watch_interval`, default 5s, refused
    outside 1s to 5m.
  - `metrics.Metrics.PolicyReloads` — `port49_policy_reloads_total{outcome}`: `applied`,
    `unchanged`, `refused`; `metrics.Metrics.PolicyFileRefused` — `port49_policy_file_refused`;
    `metrics.Metrics.PolicyRefreshPending` — `port49_policy_refresh_pending` (Decided 11).
  - In `cmd/port49d`: `type reloader struct`, `newReloader(cfg config.Config, b *broker.Broker,
    m *metrics.Metrics, now func() time.Time) *reloader`, and its methods `run(ctx, hup <-chan os.Signal)`,
    `poll(ctx)`, `reload(ctx, trigger string)` (SIGHUP's: one read, then `load`),
    `load(ctx, trigger string, raw []byte, v string, err error)` (puts what was read in force; the
    poll passes the bytes its two reads agreed on, Decided 2), `refresh(ctx)`;
    `fileVersion(path string) ([]byte, string, error)` (the inventory's);
    `policyVersion(path string) ([]byte, string, error)` (the policy's, through `readPolicyFile`, so
    an unsafe file is a version of its own and putting its mode right is a change);
    `oneLine(err error) string`; `quarantinedAt(p *policy.Policy, now time.Time) int`, which
    `watchQuarantine` now calls; constants `settleAfterReload` and `refreshRetry`, both 30s. A swap
    closes the replaced policy's span (`Prior.Until`).
  - `run` catches `SIGHUP` first thing, in every configuration: with a broker the reloader runs
    until `run`'s context ends, and `run` waits for it before shutting the broker down; with none,
    SIGHUP is said to do nothing.

**This is the switch.** Decided 2, 3, 9, 10 and 11 are this task. The reloader is one goroutine,
so a poll, a reload and a scheduled refresh never run at once, and its tests drive each method
directly on a clock they move. `loadPolicy` and `parsePolicy` are Task 4's already, so this task's
`main.go` change is the SIGHUP catch and the reloader's start. The pre-flight tests here:
`TestTheWatchLoadsTheBytesItsReadsAgreedOn`, `TestAPolicyFileOthersCouldWriteIsRefusedAtAReload`,
`TestARefusalIsOneLine`, and the pending gauge, the span's end and the "finished" line in
`TestARefreshTheStoreStopsIsRetried`.

- [ ] **Step 1: Write the failing tests**

<!-- write: cmd/port49d/reload_test.go -->
```go
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
)

// reloadRig is a broker built from its files as port49d builds it, with a
// reloader over it on a clock the test moves, and stderr captured.
type reloadRig struct {
	cfg config.Config
	b   *broker.Broker
	m   *metrics.Metrics
	st  *memory.Store
	r   *reloader
	out *syncBuffer
	now time.Time
}

func newReloadRig(t *testing.T, policyBody string) *reloadRig {
	t.Helper()
	rig := &reloadRig{out: &syncBuffer{}, now: time.Now().Truncate(time.Second)}
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = io.Discard
	rig.cfg = brokerConfig(t, policyBody)
	rig.cfg.Broker.PolicyWatchInterval = time.Second
	rig.cfg.InventoryFile = filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(rig.cfg.InventoryFile, []byte("devices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.st = memory.New(rig.clock)
	rig.m = metrics.New(prometheus.NewRegistry())
	_, b, err := buildBroker(rig.cfg, rig.st, seedMinter(), decision.NewJSONLines(io.Discard), rig.m)
	if err != nil {
		t.Fatal(err)
	}
	rig.b = b
	b.Now = rig.clock
	rig.r = newReloader(rig.cfg, b, rig.m, rig.clock)
	return rig
}

func (rig *reloadRig) clock() time.Time { return rig.now }

// write replaces the policy file's content.
func (rig *reloadRig) write(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(rig.cfg.Broker.PolicyFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// with runs fn with port49d's stderr captured in rig.out.
func (rig *reloadRig) with(fn func()) {
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = rig.out
	fn()
}

// A context alice holds on leaf1, as a redemption writes it, naming a blob the
// policy in force would not compile.
func (rig *reloadRig) aliceLoggedIn(t *testing.T) store.ContextKey {
	t.Helper()
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if err := rig.st.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:alice@example.com",
		Username: "alice", PrivLvl: 15, BlobHash: "sha256:before"}, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := rig.st.IndexContext(ctx, "user:alice@example.com", "", "", store.ContextRef{NAS: "leaf1", Username: "alice"},
		12*time.Hour); err != nil {
		t.Fatal(err)
	}
	return k
}

const showOnly = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

// An edit is loaded once two reads in a row agree on it, so a file an editor
// is still writing is never loaded half-way; then it is in force, said, and
// counted.
func TestAPolicyEditIsLoadedOnceTwoReadsAgree(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Bundle
	rig.write(t, showOnly)
	rig.with(func() { rig.r.poll(context.Background()) })
	if rig.b.Policy.Load().Bundle != before {
		t.Fatal("one read of a new file must not load it")
	}
	rig.with(func() { rig.r.poll(context.Background()) })
	if got := rig.b.Policy.Load().Bundle; got != engine.HashOf([]byte(showOnly)) {
		t.Fatalf("the second agreeing read loads it: bundle %s", got)
	}
	if n := testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("applied")); n != 1 {
		t.Fatalf("port49_policy_reloads_total{outcome=applied} = %v", n)
	}
	if want := "port49d: policy reloaded (file changed): " + engine.HashOf([]byte(showOnly)) + " replaces " + before; !strings.Contains(rig.out.String(), want) {
		t.Fatalf("stderr %q, want %q", rig.out.String(), want)
	}
}

// A typo never takes the fleet down: a file that does not load is refused, the
// policy in force keeps serving, the refusal is said once with the reason and
// the bundle still serving, and port49_policy_file_refused holds at 1 until
// the file is put back.
func TestAPolicyThatDoesNotLoadIsRefusedAndTheOldOneServes(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Bundle
	rig.write(t, strings.Replace(minimalPolicy, "privilege: admin", "privilege: root", 1))
	for i := 0; i < 5; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Bundle != before {
		t.Fatal("a refused file must leave the policy in force")
	}
	if n := testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("refused")); n != 1 {
		t.Fatalf("a refusal is counted once per content, got %v", n)
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatal("port49_policy_file_refused must be 1 while the file on disk is refused")
	}
	out := rig.out.String()
	if strings.Count(out, "refused") != 1 || !strings.Contains(out, "still serving "+before) ||
		!strings.Contains(out, `"root" is not a privilege level`) || !strings.Contains(out, rig.cfg.Broker.PolicyFile) {
		t.Fatalf("stderr: %q", out)
	}
	rig.write(t, minimalPolicy)
	rig.with(func() { rig.r.poll(context.Background()) })
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 || !strings.Contains(rig.out.String(), "is the policy in force again") {
		t.Fatalf("a file put back clears the alarm: %q", rig.out.String())
	}
}

// SIGHUP loads at once, with no second read, and says when nothing changed.
func TestSIGHUPLoadsAtOnce(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if n := testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("unchanged")); n != 1 ||
		!strings.Contains(rig.out.String(), "port49d: policy reload (SIGHUP): broker.policy_file unchanged") {
		t.Fatalf("unchanged %v, stderr %q", n, rig.out.String())
	}
	rig.write(t, showOnly)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if rig.b.Policy.Load().Bundle != engine.HashOf([]byte(showOnly)) {
		t.Fatal("SIGHUP puts the file in force at once")
	}
}

// A reload is carried into every live context at once, and again
// settleAfterReload later for a login that was in flight across the swap
// (plan 4b). The line after it says what the refresh did.
func TestAReloadRefreshesLiveContextsAndSchedulesTheSettlePass(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	k := rig.aliceLoggedIn(t)
	rig.write(t, showOnly)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	c, err := rig.st.GetContext(context.Background(), k)
	if err != nil || c.BlobHash == "sha256:before" || c.CtxID != "c1" || !c.RevokedAt.IsZero() || c.MaxPrivilege != 0 {
		t.Fatalf("alice's context takes the new policy in place: %+v %v", c, err)
	}
	if !rig.r.due.Equal(rig.now.Add(settleAfterReload)) {
		t.Fatalf("the settle pass is due at %v, got %v", rig.now.Add(settleAfterReload), rig.r.due)
	}
	if !strings.Contains(rig.out.String(), "port49d: policy refresh: 1 live context(s) updated, 0 revoked") {
		t.Fatalf("stderr: %q", rig.out.String())
	}
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 0 {
		t.Fatal("a pass that completed leaves nothing pending")
	}
}

// failingStore stops a refresh at its first index read.
type failingStore struct{ store.Store }

func (failingStore) ActivePrincipals(context.Context) ([]string, error) {
	return nil, errors.New("store: connection refused")
}

// The store down during a reload: the new policy is in force for every mint
// at once, the refresh says how far it got and when it tries again, and the
// retry finishes the job once the store is back.
func TestARefreshTheStoreStopsIsRetried(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	k := rig.aliceLoggedIn(t)
	rig.b.Store = failingStore{rig.st}
	rig.write(t, showOnly)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if rig.b.Policy.Load().Bundle != engine.HashOf([]byte(showOnly)) {
		t.Fatal("the policy is in force whether or not the refresh finished")
	}
	if !strings.Contains(rig.out.String(), "port49d: policy refresh stopped") ||
		!strings.Contains(rig.out.String(), "trying again in 30s") || !rig.r.due.Equal(rig.now.Add(refreshRetry)) {
		t.Fatalf("due %v, stderr %q", rig.r.due, rig.out.String())
	}
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 {
		t.Fatal("port49_policy_refresh_pending must be 1 while a context may hold the old policy")
	}
	// The policy it replaced was in force until the swap; the retry judges
	// its tokens over that span and no further (broker.Prior).
	if len(rig.r.priors) != 2 || !rig.r.priors[0].Until.Equal(rig.now) || !rig.r.priors[1].Until.IsZero() {
		t.Fatalf("priors: %+v", rig.r.priors)
	}
	rig.b.Store = rig.st
	rig.now = rig.now.Add(refreshRetry)
	rig.with(func() { rig.r.refresh(context.Background()) })
	if c, _ := rig.st.GetContext(context.Background(), k); c.BlobHash == "sha256:before" {
		t.Fatalf("the retry refreshes the context: %+v", c)
	}
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 0 ||
		!strings.Contains(rig.out.String(), "port49d: policy refresh finished: 1 live context(s) updated") {
		t.Fatalf("the pass that completes after a stop says so and clears the gauge: %q", rig.out.String())
	}
}

// The watch loads the bytes its two reads agreed on, not a third read: an
// editor that begins writing again between them must not have its half-written
// file loaded (pre-flight S2). Here the file on disk is already torn by the
// time the agreed version is loaded.
func TestTheWatchLoadsTheBytesItsReadsAgreedOn(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.write(t, showOnly[:len(showOnly)/2])
	rig.with(func() {
		rig.r.load(context.Background(), "file changed", []byte(showOnly), engine.HashOf([]byte(showOnly)), nil)
	})
	if got := rig.b.Policy.Load().Bundle; got != engine.HashOf([]byte(showOnly)) {
		t.Fatalf("bundle %s: the agreed bytes are what is loaded", got)
	}
}

// Whoever can write the policy decides every operator's access, so a file
// someone else could have written is refused at a reload as at start: the
// policy in force keeps serving, the refusal is said once and counted, and
// putting the mode right is a change the watch sees (spec §5.1.3).
func TestAPolicyFileOthersCouldWriteIsRefusedAtAReload(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Bundle
	rig.write(t, showOnly)
	if err := os.Chmod(rig.cfg.Broker.PolicyFile, 0o622); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Bundle != before || testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 ||
		testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("refused")) != 1 {
		t.Fatalf("an unsafe file is refused once and the policy in force serves: %q", rig.out.String())
	}
	if strings.Count(rig.out.String(), "writable by others") != 1 {
		t.Fatalf("stderr: %q", rig.out.String())
	}
	if err := os.Chmod(rig.cfg.Broker.PolicyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Bundle != engine.HashOf([]byte(showOnly)) || testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
		t.Fatalf("the file with its mode put right loads: %q", rig.out.String())
	}
}

// A refusal is one line, as every port49d line is: a YAML error's own lines
// are joined into it.
func TestARefusalIsOneLine(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.write(t, strings.Replace(minimalPolicy, "token_ttl: 60s", "token_ttl: nope", 1))
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	out := strings.TrimSuffix(rig.out.String(), "\n")
	if strings.Contains(out, "\n") || !strings.Contains(out, "refused;") || !strings.Contains(out, "cannot unmarshal") {
		t.Fatalf("stderr: %q", rig.out.String())
	}
}

// A grant's expiry is a scheduled refresh (policy.NextChange).
func TestTheRefreshIsScheduledAtTheNextGrantExpiry(t *testing.T) {
	lapse := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	rig := newReloadRig(t, strings.Replace(minimalPolicy, "roles: [r]}", "roles: [r], expires: "+
		lapse.UTC().Format(time.RFC3339)+"}", 1))
	if !rig.r.due.Equal(lapse) {
		t.Fatalf("due %v, want the expiry %v", rig.r.due, lapse)
	}
}

// The inventory is read once, at start, until plan 6: a reload after an
// inventory edit says so, once, rather than leaving an operator to believe
// SIGHUP applied it.
func TestAnInventoryEditIsSaidNotApplied(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	if err := os.WriteFile(rig.cfg.InventoryFile, []byte("devices: [{name: leaf2, platform: arista_eos}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if n := strings.Count(rig.out.String(), "has changed since start and is not reloaded"); n != 1 {
		t.Fatalf("said %d times: %q", n, rig.out.String())
	}
}

// run takes SIGHUP from its channel and returns when its context ends.
func TestTheReloaderRunsOnSIGHUPUntilCancelled(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = rig.out
	ctx, cancel := context.WithCancel(context.Background())
	hup := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() { rig.r.run(ctx, hup); close(done) }()
	hup <- syscall.SIGHUP
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(rig.out.String(), "(SIGHUP)") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return when its context ended")
	}
	if !strings.Contains(rig.out.String(), "port49d: policy reload (SIGHUP)") {
		t.Fatalf("stderr: %q", rig.out.String())
	}
}
```

<!-- patch: internal/config/broker_test.go -->
```diff
diff --git a/internal/config/broker_test.go b/internal/config/broker_test.go
index 72616cd..5c9602c 100644
--- a/internal/config/broker_test.go
+++ b/internal/config/broker_test.go
@@ -4,6 +4,7 @@ import (
 	"fmt"
 	"strings"
 	"testing"
+	"time"
 )
 
 const brokerBlock = `broker:
@@ -32,7 +33,8 @@ func TestABrokerBlockLoads(t *testing.T) {
 	if err != nil {
 		t.Fatal(err)
 	}
-	if b := c.Broker; b == nil || b.Listen != "127.0.0.1:8449" || b.PolicyFile != "/etc/port49/policy.yaml" || b.BatchMax != 100 {
+	if b := c.Broker; b == nil || b.Listen != "127.0.0.1:8449" || b.PolicyFile != "/etc/port49/policy.yaml" || b.BatchMax != 100 ||
+		b.PolicyWatchInterval != 5*time.Second {
 		t.Fatalf("broker: %+v", c.Broker)
 	}
 }
@@ -58,3 +60,19 @@ func TestBatchMaxIsBounded(t *testing.T) {
 		t.Fatalf("batch_max 5000: %v", err)
 	}
 }
+
+// The watch reads the policy file on a timer. Faster than a second is a disk
+// read loop, and slower than five minutes is an edit an operator thinks is
+// live and is not; both are refused rather than clamped.
+func TestPolicyWatchIntervalIsBounded(t *testing.T) {
+	for _, v := range []string{"500ms", "10m"} {
+		if _, err := loadWith(t, brokerBlock+"  policy_watch_interval: "+v+"\n"); err == nil ||
+			!strings.Contains(err.Error(), "broker.policy_watch_interval") {
+			t.Errorf("policy_watch_interval %s: %v", v, err)
+		}
+	}
+	c, err := loadWith(t, brokerBlock+"  policy_watch_interval: 30s\n")
+	if err != nil || c.Broker.PolicyWatchInterval != 30*time.Second {
+		t.Fatalf("30s: %+v %v", c.Broker, err)
+	}
+}
```

<!-- patch: internal/daemon/metrics/metrics_test.go -->
```diff
diff --git a/internal/daemon/metrics/metrics_test.go b/internal/daemon/metrics/metrics_test.go
index 53c559b..61d28aa 100644
--- a/internal/daemon/metrics/metrics_test.go
+++ b/internal/daemon/metrics/metrics_test.go
@@ -33,6 +33,9 @@ func TestNewRegistersEveryMetric(t *testing.T) {
 	m.CountQuarantined(func() int { return 1 })
 	m.ContextRefreshes.WithLabelValues("updated").Inc()
 	m.TokensSuperseded.Inc()
+	m.PolicyReloads.WithLabelValues("applied").Inc()
+	m.PolicyFileRefused.Set(0)
+	m.PolicyRefreshPending.Set(0)
 
 	// Gather all metrics from registry.
 	families, err := reg.Gather()
@@ -61,6 +64,9 @@ func TestNewRegistersEveryMetric(t *testing.T) {
 		"port49_devices_quarantined":               false,
 		"port49_context_refreshes_total":           false,
 		"port49_tokens_superseded_total":           false,
+		"port49_policy_reloads_total":              false,
+		"port49_policy_file_refused":               false,
+		"port49_policy_refresh_pending":            false,
 	}
 
 	// Check that all expected metrics are present and all gathered metrics are snake_case.
```

- [ ] **Step 2: Run them to see them fail**

Run: `go vet ./cmd/port49d/ ./internal/config/ ./internal/daemon/metrics/`
Expected: FAIL to build — `m.PolicyReloads undefined` in metrics, `b.PolicyWatchInterval
undefined` in config, `undefined: reloader` in `cmd/port49d`.

- [ ] **Step 3: Add the config key and the metrics, write the reloader, and start it**

<!-- patch: internal/config/config.go -->
```diff
diff --git a/internal/config/config.go b/internal/config/config.go
index ba412c7..8264a3f 100644
--- a/internal/config/config.go
+++ b/internal/config/config.go
@@ -124,15 +124,16 @@ type TokenConfig struct {
 // port49d on a second listener because the store is in-process (plan 3,
 // Decided 1). Absent, port49d runs no broker, as before.
 //
-// The policy file is read once, at start, and the store is in memory: a
-// policy edit needs a restart, and a restart ends every live login context
-// and every unspent token — every operator logs in again (plan 3,
-// Question 3). Live policy reload, which keeps every login, is plan 4b's
-// (roadmap).
+// The policy file is watched: port49d reads it every policy_watch_interval,
+// and on SIGHUP, and a file that loads is put in force and carried into every
+// live login context with no logout; one that does not is refused and the
+// policy in force keeps serving (plan 4b). The TLS files and the inventory are
+// read once, at start: a change to either needs a restart, and the store is in
+// memory, so a restart ends every live login context and every unspent token.
 //
-// The slice has no revocation lever. To cut someone off, remove their subject
-// from the policy (or re-issue the CA) and restart; certificate revocation is
-// plan 7.
+// To cut someone off, remove their grants from the policy: their live
+// contexts are revoked at the next reload, with no restart. Certificate
+// revocation is plan 7.
 //
 // A relative path resolves against port49d's working directory, not the
 // config file's, as inventory_file does.
@@ -152,6 +153,16 @@ type BrokerConfig struct {
 	// BatchMax caps the devices in one mint request; a larger sweep pages
 	// (design §17). Default 100.
 	BatchMax int `yaml:"batch_max"`
+	// PolicyWatchInterval is how often port49d reads policy_file for a
+	// change (plan 4b). A change is loaded once two reads in a row agree, and
+	// what is loaded is the bytes they agreed on, so an edit is in force
+	// within two intervals and a write in progress is not loaded part-way.
+	// Default 5s; 1s to 5m. SIGHUP loads what is on disk at once. Write the
+	// file atomically — a temporary file renamed over it: a writer stalled
+	// part-way for two intervals, or a SIGHUP sent mid-write, loads what is
+	// there. The file and its directory must be writable by port49d's user or
+	// root alone, or it is refused (spec §5.1.3).
+	PolicyWatchInterval time.Duration `yaml:"policy_watch_interval"`
 }
 
 // encKeyYAML names one encryption-at-rest key: the id that travels with every
@@ -403,6 +414,11 @@ func Load(path string) (Config, error) {
 		if b.BatchMax < 1 || b.BatchMax > 1000 {
 			return Config{}, fmt.Errorf("config: broker.batch_max must be between 1 and 1000; got %d", b.BatchMax)
 		}
+		b.PolicyWatchInterval = orD(b.PolicyWatchInterval, 5*time.Second)
+		if b.PolicyWatchInterval < time.Second || b.PolicyWatchInterval > 5*time.Minute {
+			return Config{}, fmt.Errorf("config: broker.policy_watch_interval must be between 1s and 5m; got %s",
+				b.PolicyWatchInterval)
+		}
 		c.Broker = &b
 	}
 
```

<!-- patch: internal/daemon/metrics/metrics.go -->
```diff
diff --git a/internal/daemon/metrics/metrics.go b/internal/daemon/metrics/metrics.go
index 9014b56..e8ded7f 100644
--- a/internal/daemon/metrics/metrics.go
+++ b/internal/daemon/metrics/metrics.go
@@ -90,6 +90,23 @@ type Metrics struct {
 	// not mint what they carry. Each is one operator's `port49 token` to run
 	// again; none is a session ended.
 	TokensSuperseded prometheus.Counter
+	// port49_policy_reloads_total{outcome}: attempts to put a changed policy
+	// file in force (plan 4b) — "applied", "unchanged" (a SIGHUP with nothing
+	// new), or "refused" (the file does not load; the policy in force keeps
+	// serving). The watch counts a refused file once per distinct content,
+	// however many times it reads it; each SIGHUP is an attempt of its own.
+	PolicyReloads *prometheus.CounterVec
+	// port49_policy_file_refused: 1 while the file on disk is one port49d
+	// refused, so the policy serving is not the one in the file; 0 once a
+	// file loads or the file is put back. It is the alert: an edit someone
+	// believes is live, and is not.
+	PolicyFileRefused prometheus.Gauge
+	// port49_policy_refresh_pending: 1 from a policy swap, or a refresh pass
+	// the store stopped, until a pass completes. While it is 1 a live login
+	// context may still hold a policy no longer in force — a withdrawn grant
+	// included. It is the alert beside port49_policy_file_refused: an edit that
+	// loaded, and has not yet reached every live session.
+	PolicyRefreshPending prometheus.Gauge
 }
 
 // CountQuarantined sets what port49_devices_quarantined reports at each scrape.
@@ -142,6 +159,12 @@ func New(reg prometheus.Registerer) *Metrics {
 			Help: "Live login contexts a policy refresh visited, by outcome."}, []string{"outcome"}),
 		TokensSuperseded: prometheus.NewCounter(prometheus.CounterOpts{Name: "port49_tokens_superseded_total",
 			Help: "(device, username) keys whose unspent tokens a policy change deleted."}),
+		PolicyReloads: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_policy_reloads_total",
+			Help: "Attempts to put a changed policy file in force, by outcome."}, []string{"outcome"}),
+		PolicyFileRefused: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_policy_file_refused",
+			Help: "1 while the policy file on disk is one port49d refused and an older policy is serving."}),
+		PolicyRefreshPending: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_policy_refresh_pending",
+			Help: "1 from a policy swap until a refresh pass has carried it into every live login context."}),
 	}
 	m.DevicesQuarantined = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_devices_quarantined",
 		Help: "Inventory devices the loaded policy quarantines now."}, func() float64 {
@@ -153,6 +176,7 @@ func New(reg prometheus.Registerer) *Metrics {
 	reg.MustRegister(m.Requests, m.Latency, m.Decisions, m.Unvalidated, m.KeyValidations,
 		m.Connections, m.ConnectionEvents, m.AuthFailures, m.SpoolDepth, m.SpoolDrops, m.SpoolQuarantines,
 		m.StoreOps, m.DecisionLogWriteFailures, m.CryptOpenFailures, m.Attributions, m.BrokerItemErrors, m.BlobCache,
-		m.DevicesQuarantined, m.ContextRefreshes, m.TokensSuperseded)
+		m.DevicesQuarantined, m.ContextRefreshes, m.TokensSuperseded, m.PolicyReloads, m.PolicyFileRefused,
+		m.PolicyRefreshPending)
 	return m
 }
```

<!-- write: cmd/port49d/reload.go -->
```go
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/policy"
)

// After a reload the refresh runs twice: at once, and again settleAfterReload
// later. The second pass catches a login that spent a token the first pass
// was about to supersede and wrote its context after the first pass had
// visited it — a login in flight across the swap finishes on the policy it
// started with (plan 4b), and this is how its context is brought forward.
// refreshRetry is how soon a pass the store stopped is run again.
const (
	settleAfterReload = 30 * time.Second
	refreshRetry      = 30 * time.Second
)

// reloader keeps the broker's policy the one in broker.policy_file (plan 4b).
// It is one goroutine, so a reload, a poll and a scheduled refresh never run
// at once: every field below is its own.
//
// What an operator sees. A file that loads: one line naming the bundle it
// replaced and the one now in force, the quarantine and rule lines a start
// would print, and one line saying what the refresh did to live contexts. A
// file that does not: one line saying it was refused, why, and which bundle
// is still serving, once per distinct content, with port49_policy_file_refused
// at 1 until the file loads or is put back. A file someone else could have
// written is refused the same way (readPolicyFile). A refresh the store
// stopped: one line with how far it got and when it will try again, and
// port49_policy_refresh_pending at 1 until a pass completes; the policy is in
// force for every mint regardless, and the contexts not yet reached keep their
// previous policy until then. The pass that completes after a stop always
// says so.
type reloader struct {
	cfg      config.Config
	broker   *broker.Broker
	metrics  *metrics.Metrics
	now      func() time.Time
	interval time.Duration

	// priors are the policies in force since the last complete refresh, which
	// the next refresh compares the policy in force against (broker.Prior).
	priors []broker.Prior
	// due is when the next refresh runs; zero is never.
	due time.Time
	// pending is a changed file's version seen by one poll, waiting for the
	// next to agree: an editor writing in place is not read half-way.
	pending string
	// refused is the version last refused, so a refusal is said once.
	refused string
	// inventory is the inventory file's version as loaded at start, and
	// inventorySaid the changed version last said.
	inventory, inventorySaid string
	// stopped is set while the last refresh pass did not complete, so the
	// one that does says so whatever it found.
	stopped bool
}

func newReloader(cfg config.Config, b *broker.Broker, m *metrics.Metrics, now func() time.Time) *reloader {
	start := now()
	r := &reloader{cfg: cfg, broker: b, metrics: m, now: now, interval: cfg.Broker.PolicyWatchInterval,
		priors: []broker.Prior{{Policy: b.Policy.Load(), At: start}}}
	_, r.inventory, _ = fileVersion(cfg.InventoryFile)
	r.schedule(start)
	return r
}

// fileVersion is a file's content and a string that changes when it does: its
// sha256, or why it could not be read.
func fileVersion(path string) ([]byte, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "unreadable: " + err.Error(), err
	}
	return raw, engine.HashOf(raw), nil
}

// policyVersion is fileVersion for the policy file, read as the start reads it
// (readPolicyFile): the version of a file that loads is the bundle it loads
// as, and a file someone else could have written is a version of its own —
// refused, and said once — so putting its mode right is a change the watch
// sees.
func policyVersion(path string) ([]byte, string, error) {
	raw, err := readPolicyFile(path)
	if err != nil {
		return nil, "unreadable: " + err.Error(), err
	}
	return raw, engine.HashOf(raw), nil
}

// run serves until ctx ends: a poll every interval, a reload at every SIGHUP,
// and the refresh schedule.
func (r *reloader) run(ctx context.Context, hup <-chan os.Signal) {
	tick := time.NewTicker(r.interval)
	defer tick.Stop()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		arm(timer, r.due, r.now())
		select {
		case <-ctx.Done():
			return
		case <-hup:
			r.reload(ctx, "SIGHUP")
		case <-tick.C:
			r.poll(ctx)
		case <-timer.C:
			r.refresh(ctx)
		}
	}
}

// arm sets timer to fire at due, or not at all for a zero due.
func arm(timer *time.Timer, due, now time.Time) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	if !due.IsZero() {
		timer.Reset(max(due.Sub(now), 0))
	}
}

// poll reads the policy file and loads it once two reads in a row agree on a
// version that is neither the one in force nor one already refused. What it
// loads is the second read's bytes, the ones the two reads agreed on: read
// again, a file an editor began writing in between would be loaded half-way.
func (r *reloader) poll(ctx context.Context) {
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	switch {
	case v == r.broker.Policy.Load().Bundle:
		r.pending = ""
		if r.refused != "" {
			r.refused = ""
			r.metrics.PolicyFileRefused.Set(0)
			fmt.Fprintf(stderr, "port49d: policy: broker.policy_file %s is the policy in force again (%s)\n",
				r.cfg.Broker.PolicyFile, v)
		}
	case v == r.refused:
	case v != r.pending:
		r.pending = v
	default:
		r.pending = ""
		r.load(ctx, "file changed", raw, v, err)
	}
}

// reload reads the policy file once and loads what it read: SIGHUP's path,
// with no second read, because the operator asked.
func (r *reloader) reload(ctx context.Context, trigger string) {
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	r.load(ctx, trigger, raw, v, err)
}

// load puts raw, the policy file's content read as version v, in force and
// refreshes, if it loads. A file that does not load, or could not be read
// (err), changes nothing.
func (r *reloader) load(ctx context.Context, trigger string, raw []byte, v string, err error) {
	r.checkInventory()
	old := r.broker.Policy.Load()
	var pol *policy.Policy
	if err == nil {
		pol, err = parsePolicy(r.cfg, raw)
	} else {
		err = fmt.Errorf("broker.policy_file %s: %w", r.cfg.Broker.PolicyFile, err)
	}
	if err != nil {
		r.metrics.PolicyReloads.WithLabelValues("refused").Inc()
		r.metrics.PolicyFileRefused.Set(1)
		r.refused = v
		fmt.Fprintf(stderr, "port49d: policy reload (%s) refused; still serving %s: %s\n", trigger, old.Bundle,
			oneLine(err))
		return
	}
	r.refused = ""
	r.metrics.PolicyFileRefused.Set(0)
	if pol.Bundle == old.Bundle {
		r.metrics.PolicyReloads.WithLabelValues("unchanged").Inc()
		fmt.Fprintf(stderr, "port49d: policy reload (%s): broker.policy_file unchanged, %s in force\n", trigger,
			pol.Bundle)
		return
	}
	now := r.now()
	r.broker.Policy.Swap(pol)
	// The last prior is the policy that was in force; its span ends here.
	r.priors[len(r.priors)-1].Until = now
	r.priors = append(r.priors, broker.Prior{Policy: pol, At: now})
	r.metrics.PolicyRefreshPending.Set(1)
	r.metrics.PolicyReloads.WithLabelValues("applied").Inc()
	fmt.Fprintf(stderr, "port49d: policy reloaded (%s): %s replaces %s; %d device(s) quarantined now, %d before\n",
		trigger, pol.Bundle, old.Bundle, quarantinedAt(pol, now), quarantinedAt(old, now))
	sayPolicy(pol, now)
	r.refresh(ctx)
	if settle := now.Add(settleAfterReload); r.due.IsZero() || settle.Before(r.due) {
		r.due = settle
	}
}

// refresh runs one refresh pass and schedules the next: at the next grant
// expiry when it finished, or refreshRetry from now when the store stopped it
// or a context was still changing. port49_policy_refresh_pending is 1 from a
// swap or a stopped pass until a pass completes: while it is, a live context
// may still hold a policy no longer in force — a withdrawn grant included.
func (r *reloader) refresh(ctx context.Context) {
	rep, err := r.broker.Refresh(ctx, r.priors)
	now := r.now()
	if err != nil {
		r.stopped = true
		r.metrics.PolicyRefreshPending.Set(1)
		fmt.Fprintf(stderr, "port49d: policy refresh stopped (%s so far): %v; the contexts not reached keep their "+
			"previous policy; trying again in %s\n", summary(rep), err, refreshRetry)
		r.due = now.Add(refreshRetry)
		return
	}
	r.priors = []broker.Prior{{Policy: r.broker.Policy.Load(), At: now}}
	r.metrics.PolicyRefreshPending.Set(0)
	switch {
	case r.stopped:
		r.stopped = false
		fmt.Fprintf(stderr, "port49d: policy refresh finished: %s\n", summary(rep))
	case rep.Updated+rep.Revoked+rep.Quarantined+rep.Failed+rep.TokenKeys > 0:
		fmt.Fprintf(stderr, "port49d: policy refresh: %s\n", summary(rep))
	}
	r.schedule(now)
}

// schedule sets the next refresh to the next instant a grant expires.
func (r *reloader) schedule(now time.Time) {
	r.due = time.Time{}
	if at, ok := r.broker.Policy.Load().NextChange(now); ok {
		r.due = at
	}
}

func summary(rep broker.RefreshReport) string {
	return fmt.Sprintf("%d live context(s) updated, %d revoked, %d unchanged, %d left on quarantined devices, "+
		"%d failed; unspent tokens superseded on %d (device, username) key(s)", rep.Updated, rep.Revoked,
		rep.Unchanged, rep.Quarantined, rep.Failed, rep.TokenKeys)
}

// oneLine is err's text on one line, the way port49d's other lines are: a YAML
// error lists what it found on lines of its own.
func oneLine(err error) string {
	lines := strings.Split(err.Error(), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return strings.ReplaceAll(strings.Join(lines, "; "), ":; ", ": ")
}

// quarantinedAt counts the devices p quarantines at now.
func quarantinedAt(p *policy.Policy, now time.Time) int {
	n := 0
	for _, q := range p.Quarantines(now) {
		for _, e := range q.Entries {
			if e.Current(now) {
				n++
				break
			}
		}
	}
	return n
}

// checkInventory says, once per change, that the inventory file on disk is
// not the one port49d loaded. The inventory is read at start and only then
// until plan 6's snapshot refresh (spec §10): admission, the key ring and the
// broker's device table are built from it once, and a reload checks the new
// policy against that same inventory. So an inventory edit is not applied by a
// reload, and an operator who sent SIGHUP after one is told so rather than
// left to believe it.
func (r *reloader) checkInventory() {
	_, v, _ := fileVersion(r.cfg.InventoryFile)
	if v == r.inventory || v == r.inventorySaid {
		return
	}
	r.inventorySaid = v
	fmt.Fprintf(stderr, "port49d: inventory_file %s has changed since start and is not reloaded (plan 6); the "+
		"policy is checked against the inventory loaded at start; restart port49d to apply it\n", r.cfg.InventoryFile)
}
```

<!-- patch: cmd/port49d/main.go -->
```diff
diff --git a/cmd/port49d/main.go b/cmd/port49d/main.go
index e20defa..3e9ebe6 100644
--- a/cmd/port49d/main.go
+++ b/cmd/port49d/main.go
@@ -21,7 +21,6 @@ import (
 	"net/http"
 	"os"
 	"os/signal"
-	"slices"
 	"strings"
 	"syscall"
 	"time"
@@ -304,19 +303,21 @@ func watchQuarantine(live *policy.Live, m *metrics.Metrics,
 	if live == nil {
 		return nil
 	}
-	m.CountQuarantined(func() int {
-		at, n := now(), 0
-		for _, q := range live.Load().Quarantines(at) {
-			if slices.ContainsFunc(q.Entries, func(e policy.QuarantineEntry) bool { return e.Current(at) }) {
-				n++
-			}
-		}
-		return n
-	})
+	m.CountQuarantined(func() int { return quarantinedAt(live.Load(), now()) })
 	return live.Quarantined
 }
 
 func run(cfgPath string) error {
+	// SIGHUP reloads the policy (plan 4b), and is taken with no broker too,
+	// where it is said to do nothing: its default action ends the process, and
+	// a reload habit must not take device AAA down. It is caught first, before
+	// anything else, so a HUP sent while port49d starts — by the tool that
+	// just wrote the file, say — does not end it either; one that arrives
+	// before the reloader runs waits in the channel.
+	hup := make(chan os.Signal, 1)
+	signal.Notify(hup, syscall.SIGHUP)
+	defer signal.Stop(hup)
+
 	cfg, err := config.Load(cfgPath)
 	if err != nil {
 		return err
@@ -509,6 +510,24 @@ func run(cfgPath string) error {
 		fmt.Fprintf(stderr, "port49d: broker listening on %s\n", brokerSrv.Addr)
 	}
 
+	// The policy file is watched and SIGHUP reloads it (plan 4b); hup was
+	// caught at the top of run.
+	reloadDone := make(chan struct{})
+	go func() {
+		defer close(reloadDone)
+		if brk == nil {
+			for {
+				select {
+				case <-ctx.Done():
+					return
+				case <-hup:
+					fmt.Fprintln(stderr, "port49d: SIGHUP: no broker: block, so there is no policy to reload")
+				}
+			}
+		}
+		newReloader(cfg, brk, m, time.Now).run(ctx, hup)
+	}()
+
 	serveErr := make(chan error, 1)
 	go func() { serveErr <- server.Serve(ctx, ln, deps) }()
 
@@ -530,6 +549,7 @@ func run(cfgPath string) error {
 		<-serveErr
 	}
 	cancel()
+	<-reloadDone
 	if brokerSrv != nil {
 		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
 		_ = brokerSrv.Shutdown(shutdownCtx)
```

- [ ] **Step 4: Run everything**

Run: `go test -race ./cmd/port49d/ ./internal/config/ ./internal/daemon/metrics/ && make test && make vet`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49d internal/config internal/daemon/metrics
git commit -m "feat: port49d watches the policy file and reloads it live

broker.policy_file is read every broker.policy_watch_interval (default
5s) and the bytes two agreeing reads saw are loaded; SIGHUP loads at
once, and is caught first thing in run. A file that does not load, or
that someone else could have written, is refused whole, said once on
one line, counted in port49_policy_reloads_total and held in
port49_policy_file_refused, and the policy in force keeps serving. One
that loads is swapped in and refreshed into every live context, again
30s later, at every grant expiry, and every 30s after a store error
until done, with port49_policy_refresh_pending at 1 until it is. An
inventory edit is said, not applied: that is plan 6's snapshot refresh.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 7: `port49d` with no `lab:` block carries a policy edit to a live session

**Files:**
- Modify: `cmd/port49d/main.go`
- Test: `cmd/port49d/run_test.go`; modify `cmd/port49d/broker_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `func run(parent context.Context, cfgPath string) error` — serves until `parent` ends; `main`
    passes a context ended by `SIGINT` or `SIGTERM`.
  - `var stdout io.Writer = os.Stdout` beside `stderr`: the decision log.
  - The listening lines name the bound addresses (`ln.Addr()`, `bln.Addr()`), not the configured
    ones.
  - `writeRunConfig` writes no `lab:` block and a 1s `policy_watch_interval`.

The end-to-end test plan 4 carried here, and the owner's goal as a test: `port49d` as it ships —
no `lab:` block, the broker in the process — started by `run`, a real mint over mutual TLS, a real
TACACS+ login and authorizations over TCP, and four edits to the policy file on disk: a narrowing
(`configure` denied in the same session), a lowered `max_privilege` (the held level comes down: a
command asked at 15 is denied `privilege_exceeded`, and at 1 permitted — spec §14's clamp
assertion whole, pre-flight N10), a typo (refused; nothing changes), and a withdrawn grant (the
context revoked; `credential_revoked` at the next command). One login, one `ctx_id` for every
record, and `run` returns when its context ends. `authorizeAt` and `permitsAt` ask a command at a
given level; `waitForCount` waits for a line's second appearance.

- [ ] **Step 1: Write the failing test, and drop the lab block from the run config**

<!-- write: cmd/port49d/run_test.go -->
```go
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/testpki"
)

// tacacsClient is the smallest TACACS+ client that can log in and ask for
// authorization: one exchange per connection, as the lab's devices use.
type tacacsClient struct {
	t    *testing.T
	addr string
	key  []byte
}

func (c tacacsClient) exchange(typ wire.Type, body []byte) []byte {
	c.t.Helper()
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		c.t.Fatal(err)
	}
	defer conn.Close()
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: 1, SessionID: 0x5eed, Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, c.key, body)...)); err != nil {
		c.t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		c.t.Fatal(err)
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		c.t.Fatal(err)
	}
	return wire.Obfuscate(rh, c.key, rb)
}

func (c tacacsClient) login(user, password string) uint8 {
	c.t.Helper()
	r, err := wire.DecodeAuthenReply(c.exchange(wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin,
		PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte(user),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(password)}.Encode()))
	if err != nil {
		c.t.Fatal(err)
	}
	return r.Status
}

// authorize asks for a session (no words) or a command. A session is asked at
// the login's priv-lvl 1 and a command at 15, as vEOS does once the session
// reply has granted 15 (tests/lab/results/L1-arista_eos.md).
func (c tacacsClient) authorize(user string, words ...string) wire.AuthorResponse {
	c.t.Helper()
	return c.authorizeAt(15, user, words...)
}

// authorizeAt is authorize with a command asked at priv.
func (c tacacsClient) authorizeAt(priv uint8, user string, words ...string) wire.AuthorResponse {
	c.t.Helper()
	args := [][]byte{[]byte("service=shell")}
	if len(words) == 0 {
		args = append(args, []byte("cmd="))
		priv = 1
	} else {
		args = append(args, []byte("cmd="+words[0]))
		for _, w := range words[1:] {
			args = append(args, []byte("cmd-arg="+w))
		}
		args = append(args, []byte("cmd-arg=<cr>"))
	}
	r, err := wire.DecodeAuthorResponse(c.exchange(wire.TypeAuthor, wire.AuthorRequest{
		AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: priv, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("vty1"), Args: args}.Encode()))
	if err != nil {
		c.t.Fatal(err)
	}
	return r
}

func (c tacacsClient) permits(user string, words ...string) bool {
	c.t.Helper()
	return c.permitsAt(15, user, words...)
}

func (c tacacsClient) permitsAt(priv uint8, user string, words ...string) bool {
	c.t.Helper()
	s := c.authorizeAt(priv, user, words...).Status
	return s == wire.AuthorStatusPassAdd || s == wire.AuthorStatusPassRepl
}

// mint asks the broker for alice's token on device, over mutual TLS with the
// lab client certificate testpki.WriteLab left beside the broker's.
func mint(t *testing.T, brokerAddr, pkiDir, device string) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, testpki.LabClientCert), filepath.Join(pkiDir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	resp, err := client.Post("https://"+brokerAddr+"/v1/tokens", "application/json",
		bytes.NewReader([]byte(`{"devices":["`+device+`"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out api.MintResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Login == "" {
		t.Fatalf("mint: %+v", out)
	}
	return out.Results[0].Login
}

// waitFor polls buf until it holds want, or fails the test.
func waitFor(t *testing.T, buf *syncBuffer, want string) {
	t.Helper()
	waitForCount(t, buf, want, 1)
}

// waitForCount polls buf until it holds want n times, or fails the test.
func waitForCount(t *testing.T, buf *syncBuffer, want string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(buf.String(), want) < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %q; have %q", want, buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// records are the decision log's records of one event, in order.
func records(t *testing.T, log *syncBuffer, event string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["event"] == event {
			out = append(out, m)
		}
	}
	return out
}

func ctxID(m map[string]any) any {
	s, _ := m["session"].(map[string]any)
	return s["ctx_id"]
}

// port49d as it ships — no lab: block, the broker in the process — end to end
// through a live policy change (plan 4b; the end-to-end test plan 4 carried
// here). alice mints and logs in once. Narrowing her role takes her next
// `configure` away in the session she has; lowering her max_privilege lowers
// the level she holds, and her next command above it is denied
// privilege_exceeded; a policy that does not load leaves her as she was;
// withdrawing her grant revokes the context, and her next command is denied
// credential_revoked. She never logs in again, and every command is decided in
// the one context her login created.
func TestRunServesAPolicyEditToALiveSessionWithNoLogout(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	pkiDir := filepath.Dir(b.TLSCertFile)
	cfgPath := writeRunConfig(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	// Cleanups run last-registered first: run has returned before stderr and
	// stdout are put back, whether the test passed or failed.
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})

	waitFor(t, &out, "port49d: broker listening on ")
	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(addrs) != 2 {
		t.Fatalf("stderr: %q", out.String())
	}
	dev := tacacsClient{t: t, addr: addrs[0][1], key: []byte("run-test-secret")}

	if st := dev.login("alice", mint(t, addrs[1][1], pkiDir, "leaf1")); st != wire.AuthenStatusPass {
		t.Fatalf("login: status %d; decision log %s", st, log.String())
	}
	if r := dev.authorize("alice"); r.Status != wire.AuthorStatusPassAdd || len(r.Args) != 1 || string(r.Args[0]) != "priv-lvl=15" {
		t.Fatalf("session authorization: %+v", r)
	}
	if !dev.permits("alice", "configure") {
		t.Fatal("before the edit alice may configure")
	}

	// Narrow: show only. The watch reads the file within two intervals.
	if err := os.WriteFile(b.PolicyFile, []byte(showOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "port49d: policy refresh: 1 live context(s) updated")
	if dev.permits("alice", "configure") || !dev.permits("alice", "show", "version") {
		t.Fatal("after the edit alice's configure is denied and show is permitted, in the same session")
	}

	// Lower the ceiling to readonly, priv-lvl 1 on EOS: the level alice holds
	// comes down to it, and a command asked at 15 is above it (spec §14).
	lowered := strings.Replace(showOnly, "roles: [r]}", "roles: [r], max_privilege: readonly}", 1)
	if err := os.WriteFile(b.PolicyFile, []byte(lowered), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, &out, "port49d: policy refresh: 1 live context(s) updated", 2)
	if dev.permits("alice", "show", "version") {
		t.Fatal("after the ceiling is lowered a command at 15 is above the level alice holds")
	}
	if cmds := records(t, &log, "authorize_command"); cmds[len(cmds)-1]["reason"] != "privilege_exceeded" {
		t.Fatalf("the command above the lowered level: %v", cmds[len(cmds)-1])
	}
	if !dev.permitsAt(1, "alice", "show", "version") {
		t.Fatal("at the lowered level alice's show is still permitted")
	}

	// A typo is refused and the policy in force keeps serving.
	if err := os.WriteFile(b.PolicyFile, []byte(strings.Replace(lowered, "privilege: readonly", "privilege: root", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "refused; still serving ")
	if !dev.permitsAt(1, "alice", "show", "version") {
		t.Fatal("a refused file changes nothing")
	}

	// Withdraw alice's grant, to carol: alice's context is revoked, not
	// deleted.
	withdrawn := strings.Replace(showOnly, "grants: [{subject: s,", "grants: [{subject: c,", 1)
	withdrawn = strings.Replace(withdrawn, "subjects: [", `subjects: [{name: c, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}, `, 1)
	if err := os.WriteFile(b.PolicyFile, []byte(withdrawn), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "1 revoked")
	r := dev.authorizeAt(1, "alice", "show", "version")
	if r.Status != wire.AuthorStatusFail || !strings.Contains(string(r.ServerMsg), "revoked") {
		t.Fatalf("after the grant is withdrawn: %+v", r)
	}

	// One login, one context: every command above was decided in it, and the
	// refresh records name it too.
	redeems := records(t, &log, "redeem")
	if len(redeems) != 1 {
		t.Fatalf("alice logged in %d times", len(redeems))
	}
	id := ctxID(redeems[0])
	for _, event := range []string{"authorize_command", "refresh"} {
		for _, rec := range records(t, &log, event) {
			if ctxID(rec) != id {
				t.Fatalf("a %s record names another context: %v", event, rec)
			}
		}
	}
	cmds := records(t, &log, "authorize_command")
	if last := cmds[len(cmds)-1]; last["reason"] != "credential_revoked" {
		t.Fatalf("the last command: %v", last)
	}

	cancel()
	select {
	case err := <-done:
		done <- err // for the cleanup
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return when its context ended")
	}
	if !strings.Contains(out.String(), "port49d: accounting spool drained, exiting") {
		t.Fatalf("stderr: %q", out.String())
	}
}
```

<!-- patch: cmd/port49d/broker_test.go -->
```diff
diff --git a/cmd/port49d/broker_test.go b/cmd/port49d/broker_test.go
index f43e08a..a7db974 100644
--- a/cmd/port49d/broker_test.go
+++ b/cmd/port49d/broker_test.go
@@ -2,6 +2,7 @@ package main
 
 import (
 	"bytes"
+	"context"
 	"crypto/tls"
 	"fmt"
 	"io"
@@ -336,7 +337,8 @@ func TestBrokerTLSErrorsReachPort49dsLog(t *testing.T) {
 }
 
 // writeRunConfig writes a complete port49d.yaml whose broker block uses b,
-// and returns its path.
+// and returns its path. It has no lab: block: it is the production shape, a
+// daemon answering only what the broker minted (plan 4, Decided 12).
 func writeRunConfig(t *testing.T, b *config.BrokerConfig) string {
 	t.Helper()
 	t.Setenv("T_RUN_SECRET", "run-test-secret")
@@ -362,14 +364,13 @@ keys:
 encryption:
   current: {id: v1, secret_env: T_RUN_ENC}
 accounting: {spool_path: %s}
-lab:
-  session_attributes: ["priv-lvl=15"]
 broker:
   listen: %q
   tls_cert_file: %s
   tls_key_file: %s
   client_ca_file: %s
   policy_file: %s
+  policy_watch_interval: 1s
 `, inv, filepath.Join(dir, "acct.jsonl"), b.Listen, b.TLSCertFile, b.TLSKeyFile, b.ClientCAFile,
 		b.PolicyFile)), 0o600); err != nil {
 		t.Fatal(err)
@@ -385,7 +386,7 @@ func runExpectingRefusal(t *testing.T, cfgPath string) (string, error) {
 	defer func(w io.Writer) { stderr = w }(stderr)
 	stderr = &out
 	done := make(chan error, 1)
-	go func() { done <- run(cfgPath) }()
+	go func() { done <- run(context.Background(), cfgPath) }()
 	select {
 	case err := <-done:
 		return out.String(), err
```

- [ ] **Step 2: Run it to see it fail**

Run: `go vet ./cmd/port49d/`
Expected: FAIL to build — `too many arguments in call to run` (`have (context.Context, string)`,
`want (string)`).

- [ ] **Step 3: Give `run` a context**

<!-- patch: cmd/port49d/main.go -->
```diff
diff --git a/cmd/port49d/main.go b/cmd/port49d/main.go
index 3e9ebe6..84e6988 100644
--- a/cmd/port49d/main.go
+++ b/cmd/port49d/main.go
@@ -51,7 +51,9 @@ import (
 func main() {
 	cfgPath := flag.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
 	flag.Parse()
-	if err := run(*cfgPath); err != nil {
+	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
+	defer stop()
+	if err := run(ctx, *cfgPath); err != nil {
 		fmt.Fprintln(os.Stderr, "port49d:", err)
 		os.Exit(1)
 	}
@@ -166,9 +168,12 @@ func labWarning(lab *config.LabConfig) string {
 		"never be in production\n", strings.Join(enables, "; "))
 }
 
-// stderr is where port49d's operational lines go — not the decision log,
-// which is stdout — swapped in tests.
-var stderr io.Writer = os.Stderr
+// stderr is where port49d's operational lines go, and stdout is the decision
+// log; both are swapped in tests.
+var (
+	stderr io.Writer = os.Stderr
+	stdout io.Writer = os.Stdout
+)
 
 // buildBroker loads what the broker needs and returns its server and the
 // broker, or nils when no broker: block is configured. The daemon asks the
@@ -307,7 +312,10 @@ func watchQuarantine(live *policy.Live, m *metrics.Metrics,
 	return live.Quarantined
 }
 
-func run(cfgPath string) error {
+// run is port49d from config load to exit. It serves until parent ends —
+// main's is SIGINT or SIGTERM, a test's is its own — and then shuts down in
+// the order the package comment gives, returning once the spool has drained.
+func run(parent context.Context, cfgPath string) error {
 	// SIGHUP reloads the policy (plan 4b), and is taken with no broker too,
 	// where it is said to do nothing: its default action ends the process, and
 	// a reload habit must not take device AAA down. It is caught first, before
@@ -324,14 +332,12 @@ func run(cfgPath string) error {
 	}
 	fmt.Fprint(stderr, labWarning(cfg.Lab))
 
-	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
-	defer stop()
-	ctx, cancel := context.WithCancel(signalCtx)
+	ctx, cancel := context.WithCancel(parent)
 	defer cancel()
 
 	reg := prometheus.NewRegistry()
 	m := metrics.New(reg)
-	log := decision.NewJSONLinesWithFailureHook(os.Stdout, m.DecisionLogWriteFailures.Inc)
+	log := decision.NewJSONLinesWithFailureHook(stdout, m.DecisionLogWriteFailures.Inc)
 	lim := limits.New(cfg.Limits, time.Now)
 
 	// Everything that holds a credential, a principal or a context is sealed
@@ -499,15 +505,17 @@ func run(cfgPath string) error {
 			return fmt.Errorf("broker listener on %s: %w", brokerSrv.Addr, err)
 		}
 	}
+	// The bound address, not the configured one: `:49` says nothing about
+	// which address answered, and `:0` says nothing about which port.
 	fmt.Fprintf(stderr, "port49d: listening on %s, metrics on %s, %d devices admitted\n",
-		cfg.Listen, cfg.MetricsListen, len(cfg.Inventory.Devices))
+		ln.Addr(), cfg.MetricsListen, len(cfg.Inventory.Devices))
 
 	brokerErr := make(chan error, 1)
 	if brokerSrv != nil {
 		// Capped, so connections to the broker cannot take the file
 		// descriptors the TACACS+ listener beside it needs (pre-flight F1).
 		go func() { brokerErr <- brokerSrv.ServeTLS(broker.Limit(bln, broker.MaxConns), "", "") }()
-		fmt.Fprintf(stderr, "port49d: broker listening on %s\n", brokerSrv.Addr)
+		fmt.Fprintf(stderr, "port49d: broker listening on %s\n", bln.Addr())
 	}
 
 	// The policy file is watched and SIGHUP reloads it (plan 4b); hup was
```

- [ ] **Step 4: Run the whole verification**

Run: `make test && make vet && go test -race ./internal/... ./cmd/... && go vet -tags lab ./tests/lab/... && make build`
Expected: PASS; `TestRunServesAPolicyEditToALiveSessionWithNoLogout` takes about eight seconds (four
edits, each read twice at a 1s interval).

- [ ] **Step 5: Commit**

```bash
git add cmd/port49d
git commit -m "test: port49d with no lab: block carries a policy edit to a live session

run takes a context, so a test can start and stop port49d; the decision
log is swappable like stderr, and the listening lines name the bound
addresses. The end-to-end test carried from plan 4 runs port49d with no
lab: block, mints and logs in once, and drives a narrowing, a lowered
ceiling, a refused typo and a withdrawn grant through the policy file,
all in one context.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 8: The roadmap says what plan 4b built and what plans 6 and 7 inherit

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the "Plan 4b" section)

**Interfaces:**
- Produces: plan 4b's "As built" paragraph; what plan 6's snapshot refresh and plan 7's scheduled
  refresh inherit from `Refresh`.

The status line is the merge's to change (`docs: plan 4b merged`), as it was for plan 4.

- [ ] **Step 1: Apply the roadmap edit**

<!-- patch: docs/superpowers/plans/README.md -->
```diff
diff --git a/docs/superpowers/plans/README.md b/docs/superpowers/plans/README.md
index 3d98a68..649ee10 100644
--- a/docs/superpowers/plans/README.md
+++ b/docs/superpowers/plans/README.md
@@ -368,6 +368,43 @@ context and every unspent token (plan 3, Question 3).
 Plan 7 keeps the scheduled refresh through `active_principals` for directory changes, and the
 `staleness_ceiling` default that goes with it.
 
+**As built** (`2026-09-24-04b-live-policy.md`): `policy.Live` holds the policy in force; the
+broker mints from it and the daemon asks it about quarantine at every packet, so one swap changes
+both. `port49d` reads `broker.policy_file` every `broker.policy_watch_interval` (default 5s) and
+loads the bytes two agreeing reads saw, and loads at once on `SIGHUP`; a file that does not load,
+or that anyone but `port49d`'s user or root could have written (the file or its directory), is
+refused whole — at start `port49d` does not start — said once, counted
+(`port49_policy_reloads_total{outcome}`) and alarmed (`port49_policy_file_refused`). A mint holds
+the policy from its first resolution to its last token write, and not while its response is
+written. `(*broker.Broker).Refresh` carries the policy in force into every
+live context through `store.SetContextPolicy`, the fifth narrow setter and the first that is a
+compare-and-set, and revokes a context whose principal has no grant left on its device; each
+change is a `refresh` decision record (spec §5.7). It also deletes the unspent tokens a
+superseded policy minted and the policy in force would not mint identically. It runs at every
+reload, again 30s after it for a login in flight across the swap, at every grant expiry, and
+every 30s after a store error until it finishes, with `port49_policy_refresh_pending` at 1 until
+it does; a context still changing after every compare-and-set attempt is revoked anyway where that
+is the answer and left for the retry otherwise, and the pass goes on. A superseded policy's tokens
+are judged at the start of its span and at every grant expiry inside it. The inventory is not reloaded: a reload after an
+inventory edit says so. `run` takes a context, so a test can stop it, and the end-to-end test of
+`port49d` with no `lab:` block that plan 4 carried here drives a live edit through a real login.
+
+**Hands to plan 6:** the snapshot refresh (spec §10) swaps an inventory under a live policy. It
+must re-run the joint checks against the new inventory and call `Refresh` exactly as a policy
+reload does, since a device leaving a scope is a narrowing like any other; `Refresh` already
+revokes a context on a device inventory no longer names. The token supersede walks principals ×
+devices × superseded policies × expiry instants, compiling each answer (plan 12 measures it at
+fleet size). With the remote store an `IndexContext` can fail, and a login whose index write
+failed is invisible to the policy refresh as it is to revocation (`authen`, the `index_error`
+record): plan 6 must close that, or at least extend the `index_error` wording to name the policy
+refresh too.
+
+**Hands to plan 7:** the scheduled directory refresh is `Refresh`'s context pass with group
+membership re-read; a policy refresh does not stamp `refreshed_at`, because nothing about the
+directory was re-verified, so the staleness ceiling still waits on plan 7's scheduler. Revoking
+by principal, `sid` or certificate should also delete tokens (roadmap, plan 3's hole), as the
+policy refresh already does for a withdrawn grant.
+
 ## Plan 5 — Platform adapters (§19 step 5)
 
 Spec §8 in full: built-in adapters, entity classes, user overrides and layering, pinned
```

- [ ] **Step 2: Check it landed**

Run: `grep -n '^\*\*As built\*\* (`2026-09-24-04b\|^\*\*Hands to plan 6:\*\* the snapshot\|^\*\*Hands to plan 7:\*\* the scheduled' docs/superpowers/plans/README.md`
Expected: three lines, all between `## Plan 4b` and `## Plan 5`.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: plan 4b as built, and what plans 6 and 7 inherit

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

## Operator-facing notes (for the PR body)

- **A policy edit is live without a restart.** `port49d` reads `broker.policy_file` every
  `broker.policy_watch_interval` (new key, default `5s`, `1s`–`5m`) and loads a change once two
  reads agree; `kill -HUP` loads at once. **Write the file atomically** — a temporary file renamed
  over it, as editors, config management and a Kubernetes ConfigMap do: a write stalled part-way
  for two intervals, or a `SIGHUP` sent mid-write, loads what is on disk. Nobody is logged out: a
  narrowed rule denies the next command, a widened one permits it, a lowered `max_privilege`
  lowers the held level, and a withdrawn grant revokes that operator's context on that device
  (`credential_revoked` at the next command).
- **Not on Junos.** Junos never asks port49 about a command (spec §13 decision 21), so a live
  Junos shell keeps the access it had at login until logout, whatever the edit. The context is
  still revoked or rewritten for the next login, and the refresh line says how many such
  sessions there are (`N of them on platforms that do not authorize commands keep their live
  session until logout`), with each `ctx_id` in the process log: close those sessions on the
  device.
- **A policy that does not load is refused** and the old one keeps serving; one stderr line says
  why. New metrics: `port49_policy_reloads_total{outcome}` (`applied`, `unchanged`, `refused`) and
  `port49_policy_file_refused` (alert on 1).
- **Breaking: a policy file someone else could have written is refused.** The file and the
  directory holding it must be writable by `port49d`'s user or root alone and owned by one of
  them; otherwise `port49d` does not start, and a reload keeps the policy in force serving. A
  symlink is followed, and the directory holding every link on the way is held to the same
  rule. The one exception is a directory holding a link, never the file's own directory: on a
  read-only mount it may have any mode. A Kubernetes ConfigMap or Secret mount passes: its
  0777 mount root is mounted read-only (`tests/lab/results/configmap-mounts.md`). The exception
  trusts whoever writes the mount's source, so do not mount the policy from FUSE, or from a host
  path others can write. With `defaultMode: 0400` or `0440` and no
  `fsGroup`, a non-root `port49d` cannot read the file. Use `fsGroup` or `defaultMode: 0444`.
  An edit to the ConfigMap reached the pod about 55 s later in the lab (the kubelet's sync).
  Files over 1 MiB are refused. Fix with `chmod go-w` (file and directory) or `chown`.
  With a live reload, whoever can write the policy decides every operator's access within
  seconds.
- **A reload that has not yet reached every live session** holds
  `port49_policy_refresh_pending` at 1 (alert on it staying 1): the store failed part-way, and a
  context not reached keeps its previous policy, a withdrawn grant included, until the 30s retry
  finishes and says `policy refresh finished`.
- **New decision event `refresh`**, one per live context a reload changes, naming its `ctx_id`:
  `permit grants_matched`, `deny no_grants_matched` (revoked), or `deny device_quarantined` (left as
  it was). New metrics: `port49_context_refreshes_total{outcome}` and
  `port49_tokens_superseded_total`.
- **An unspent token whose answer the edit changed is deleted**: its holder sees
  `token_not_found` and runs `port49 token` again. Tokens whose answer did not change are kept.
  An idempotent retry of a mint whose tokens were superseded is not replayed with the dead token.
  It mints afresh under the policy in force, and its `mint` record's `index_error` says why.
- **`credential_revoked` now also follows a routine edit** that withdraws a grant. The
  `refresh deny no_grants_matched` record naming the same `ctx_id` tells the two apart; an alert
  on `credential_revoked` as an incident signal should leave those out.
- **A policy file that changes on a schedule reloads on that schedule.** A templater that
  stamps the time into it every minute gives a reload every minute, and every reload writes one
  `refresh` record per live context. Stamp nothing that changes unless the policy does. A
  `SIGHUP` with no edit is answered `unchanged` without being compiled again.
- **The inventory is still read only at start.** A reload after an inventory edit says so; restart
  to apply it (plan 6).
- **`SIGHUP` no longer ends `port49d`**, with or without a `broker:` block.
- The listening lines name the bound address (`[::]:49`, not `:49`).

## Self-review

- **Spec coverage.** §5.1.3 "Policy reload": validate or keep (Task 6, `reload`), swap (Tasks 3,
  4, 6), joint checks re-run (the load itself, `sayPolicy`, and `Live.Quarantined` per packet),
  refresh by compare-and-set (Tasks 2, 5), revoke (Task 5), tokens (Task 5), settle and expiry
  passes (Task 6), store down (Tasks 5, 6), the pending gauge (Task 6), the busy context and the
  superseded policy's span (Task 5), the agreed bytes (Task 6), the policy file's permissions
  (Tasks 4, 6). §5.7's `refresh` event and its carve-outs (Tasks 1, 5). §14's eight new
  assertions: narrowing, widening, revocation and clamp (`refresh_test.go`, `run_test.go`, the
  clamp end to end to `privilege_exceeded`); refusal (`reload_test.go`, `run_test.go`); tokens
  (`TestARefreshRevokesAContextWhoseGrantIsGone`, `TestAnEditThatChangesNoAnswerKeepsEveryToken`,
  `TestASupersededPolicyIsJudgedAtEveryExpiryItSpanned`); the race
  (`TestARefreshThatLosesARaceReadsAgain`); expiry (`TestAGrantsExpiryReachesALiveContext`,
  `TestTheRefreshIsScheduledAtTheNextGrantExpiry`); the unsafe file (`policyfile_test.go`,
  `TestAPolicyFileOthersCouldWriteIsRefusedAtAReload`); the busy context
  (`TestABusyContextDoesNotStopTheRefresh`, `TestABusyContextIsRevokedAnyway`). The roadmap's
  carries: `Server` (Task 4), `run` with no `lab:` block (Task 7).
- **Written against the tree.** Every task's code was written and tested on a scratch branch off
  `e10ab29`, and each task's commit passed `go vet ./...`, `gofmt -l .` and `go test ./...
  -count=1`. The blocks in this file were then extracted and applied in order to a clean checkout
  of `main` plus this plan's commit, exactly as an executor applies them: every Step 2 failed with
  the build error it names, every Step 4 passed, and the result was byte-identical to the scratch
  branch and passed `go test -race ./internal/... ./cmd/...`, `make vet`,
  `go vet -tags lab ./tests/lab/...` and `make build`. The pre-flight rulings were then folded in
  the same way — written and tested task by task on a scratch branch off `e10ab29`, the blocks
  regenerated from it, and the whole plan dry-run again from a clean copy.
