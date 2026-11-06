# Plan 5a: Platform Adapters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The per-command platforms get their adapters in full: the built-in adapters become files
in a pinned platform set, an operator can override and add adapters in the policy file, each
reserved level renders the reply its device measurably applies, typed secrets never reach the log,
and the tooling of spec §8 and §12 — `platform list/show/export/upgrade`, the adapter-edit gate,
the dead-rule and fallback-exposure reports, the local-account check, the offboarding pull request
— reads them.

**Architecture:** `platform.Dialect` stays the one type everything reads; it is now parsed from
`platforms/<set>/<platform>.yaml`, embedded in both binaries and validated as an operator's block
is. A policy pins a set (`platform_set:`, 1.0.0 where it pins none) and lays its own `platforms:`
blocks over it, so the broker, the daemon's redaction and every offline tool read one merged
table from one file. Rendering follows decision 25: a level is a device level and a device role,
because the level fences a session while port49 answers and the role when the device falls back
to local. The policy diff learns to judge an adapter edit, and the daemon redacts every record
before it is written.

**Tech Stack:** Go 1.22, standard library, `gopkg.in/yaml.v3` (already a dependency), `git` and
`gh` on the operator's path for `grants remove --pr` only. No new module dependencies.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §8 (adapters in full but the
session-only projection), §6 (rendering, `accepted_attributes`, "Exact attribute spellings"),
§5.7 and §5.8 (redaction), §5.6 (local accounts), §12 (intersection checks, the adapter-edit gate,
`platform upgrade`, `grants remove`, `devices check-config`), §13 decisions 23 and 25, §15 L10,
L16, L18, L21 and the new L22. Roadmap `docs/superpowers/plans/README.md`, "Plan 5", and every
"hands to plan 5" item under plan 4. The lab notes are the source of truth for every value an
adapter ships (`CLAUDE.md`, "The lab register is the source of truth").
**Prerequisite:** plans 4 and 4b merged (PRs #10, #11, #12). Branch `feature/platform-adapters`
off `main` at `f759a55`.

## Why this plan exists, and why it is 5a

`internal/platform/dialect.go` is plan 4's borrowed table: EOS renders `priv-lvl` alone, NX-OS and
IOS-XE render nothing — every N9Kv session lands at `vdc-operator` and every IOS-XE session at
level 1, whatever the policy says (L18) — adapters cannot be edited, nothing pins them, and a
typed `username bob secret Hunter2` is written to the decision log and the accounting spool in the
clear (spec §5.8 says redaction MUST land here). The roadmap's Plan 5 section, plus everything plan
4 handed it, is more than 25 tasks. It splits cleanly along one seam:

- **5a (this plan): the adapters as data, and every platform that authorizes per command.** The
  files, the pin, operator overrides and their gate, EOS, NX-OS and IOS-XE rendering, redaction,
  the platform tooling, the intersection reports, the local-account check, `grants remove --pr`,
  N5, and the lab run that verifies the three adapters. Eighteen tasks.
- **5b: the session-only half, and capability inference.** Junos's projection under decision 22
  — `bits`, `bit_delivery`, `command_projection`, `local-user-name` templates, the generator
  constraints, the refused shape — gated on L12 and L9, with its own differential lab tests and
  `platform export` of the reference classes; decision 21's class `idle-timeout`; spec §9's
  capability inference (`devices capabilities`, the observed matrix, accounting reconciliation);
  and the NX-OS `vsh.bin` system user if a note ever measures it. Nothing 5a builds is reworked
  by 5b: Junos renders nothing in 5a, exactly as today.

## Decided in this plan

1. **The built-in adapters are files, and a set is immutable once released.**
   `platforms/1.0.0/<platform>.yaml` is embedded (`platforms.FS`) and parsed into
   `platform.Dialect` by `platform.LoadSets`, each file laid over the generic adapter and validated
   exactly as an operator's block is (`platform.Validate`). A bad embedded file panics at start and
   is caught by `TestEmbeddedSetsLoad` first. The citations that were comments on plan 4's Go
   literal move into the YAML beside each value. **1.0.0 is the first set and is final when this
   plan merges**; Tasks 3–5, 14, 15 and 18 still edit it, because it has not been released.
   `TestEveryReleasedSetIsFrozen` holds each released set value for value, keyed by version so a
   later default does not unpin 1.0.0, and `TestTheGenericAdapterIsFrozen` holds the generic
   adapter and plan 3's ceiling table every set is laid over: a change to either is a new set
   (pre-flight S3).
2. **A policy that pins no set renders with 1.0.0, forever** (`platform.UnpinnedSet`). Refusing an
   unpinned policy would break every policy file in service for no security gain, and defaulting to
   the newest set is exactly the unreviewed upgrade the pin exists to stop; the first set is the
   only default that never moves. A set the binary does not ship is refused at load, by name.
   `port49 policy test` prints `platform_set: <v>` first.
3. **An operator's adapters live in the policy file's `platforms:` block**, not in files beside it,
   so `port49 policy test`, `policy diff`, `explain` and the broker read one merged table from the
   file review already covers, and a block goes through the same reload (plan 4b) as a grant. A
   block merges per top-level key: a map (`privilege`, `ceiling_levels`, `entity_classes`,
   `unreachable`, `fallback`) per entry — spec §8's "adds one class, inherits everything else" —
   and a list or value whole. `redact` appends and never removes. `replace: true` starts from the
   generic adapter, `based_on:` names a platform in the pinned set under a new name, and a name the
   set does not ship starts from the generic adapter. A block may not claim `verified`, may not
   be named `all` or `default` (the names `attributes:` and the redaction table give every
   platform), and no adapter may list inert an attribute one of its levels renders, nor
   `priv-lvl`: what a level renders is the level (pre-flight S8, N7).
4. **The daemon's wire facts stay where they are.** `session_services` (settable in
   `port49d.yaml`), `session_discriminator`, `exec_commands` and `system_users` are read by a
   daemon with no policy at all, so they stay built in until plan 6's bundle carries adapters to
   the daemon. Redaction is the exception: port49d reads the policy in force's blocks at every
   record (Task 11), and the built-in patterns with no policy.
5. **A level renders as a device level and a device role (decision 25).** Measured: the level is
   what the device enforces below port49 (ceiling-*.md), and the role is what binds when the method
   list falls back to local (L16, command authorization LOCAL). So:

   | level | `arista_eos` | `cisco_nxos` | `cisco_iosxe` |
   |---|---|---|---|
   | readonly | `priv-lvl=1`, `roles=network-operator` | `shell:roles*network-operator` | `priv-lvl=1` |
   | operator | `priv-lvl=15`, `roles=network-operator` | `shell:roles*network-operator` | `priv-lvl=7` |
   | admin | `priv-lvl=15`, `roles=network-admin` | `shell:roles*network-admin` | `priv-lvl=15` |

   EOS reads the bare `roles=`, needs `priv-lvl` beside it, and applies it under either flag; the
   mandatory spelling is used because a device that cannot read it then refuses the session rather
   than landing it on a default role (L16-arista_eos.md, 2026-09-22). NX-OS is sent the role and
   never `priv-lvl`, optional because the flag changes nothing there and a device that does not
   read it must ignore it (L16-cisco_nxos.md, L18). NX-OS keeps its `ceiling_levels` for the
   token's number (decision 23); `Dialect.PrivLvl` reads them when the rendering sends no
   `priv-lvl`. IOS-XE's level 7 depends on device configuration, which the adapter carries as
   `device_config` and the lab config gains; without it level 7 is level 1, which fails closed.
6. **IOS-XE takes `priv-lvl` and nothing else, and anything else quarantines the device.** A reply
   IOS-XE does not recognise refuses the session and, repeated, stops the device answering SSH for
   a minute, break-glass included (L18). `accepted_attributes: [priv-lvl]` makes a composition
   whose reply carries anything else fail the joint check: the device is closed without a reply
   and falls to local at once, `policy test` names it, and `policy diff` fails on the new
   quarantine before it ships. An attribute under `all:` therefore quarantines the IOS-XE fleet;
   the operator keys it to the platforms that read it.
7. **The gate judges a level's own rendering by the level.** With EOS and NX-OS now sending a
   role, every level change changes the reply, and the reply gate cannot read direction — so a
   lowering from admin to readonly would have failed `policy diff`, contradicting spec §12's "a
   lowering is reported and does not fail". Where the platform's adapter is identical in both
   versions, the attributes the level renders are judged by `level` and `priv_lvl`, which do read
   direction; everything else in the reply, and every reply on a platform whose adapter changed, is
   judged as before, failing closed (Task 3).
8. **An adapter edit is gated in its own right, and privilege is read under the stricter adapter**
   (review M8, the roadmap's plan 4 hand-off). The diff compares, key by key through
   `platform.SpecOf`, the adapter of every platform either version has one for and every
   inventory platform — a block for a platform no device has yet included, because the inventory
   is not diffed and the day a device arrives is no review (pre-flight B2) — whether the edit is
   a block or a pin move. A key that changes what port49 decides, what the gate reads, or what the
   audit keeps (`redact`, pre-flight S1) is gated and acknowledged only in writing:
   `acknowledge: [{platform: arista_eos, field: entity_classes, reason: ...}]`; other keys are
   reported. `BearsPrivilege` is asked of both versions' adapters, the stricter winning, so
   listing `roles` inert cannot hide a change to `roles` in the same diff.
9. **Redaction is built in, unpinned, and applied before anything is written.**
   `platforms/redact.yaml` holds the built-in patterns (`{match, after}` or `{match, from}`): a
   `default` list every platform gets, and per platform a list that adds to it and never replaces
   it (pre-flight S2: Junos's list had dropped `key` and `password`). A policy block adds
   patterns, and an edit to them is gated (Decided 8). A pattern whose `match` is `*` and `**`
   alone may not use `from`: it would blank every record's arguments, the audit rather than a
   secret (pre-flight S1). Where a pattern removes words from a record's raw pairs and not its
   vector, or the other way round, the form it missed loses every argument (pre-flight N2). They
   apply to the accounting
   record before the spool, which is on disk, and to the `authorize_command` record before it is
   emitted, because a typed secret reaches both (spec §5.7). The decision is made on the command as
   sent. A redacted record carries `"redacted": true`, and `policy replay` reports it
   `unverifiable`. Where a platform may send what was typed, a pattern's word matches its
   abbreviations, removing more rather than less. Every pattern is vendor syntax, unmeasured, and
   the spec says redaction is best-effort.
10. **N5 closes by moving `enable_username` into the adapter.** The offline tools and the broker
    now read it from the same file. `port49d.yaml`'s `platforms.<name>.enable_username: principal`,
    the only value config.Load ever accepted, still loads, with a notice at start pointing at the
    policy file — refusing it would make the upgrade an outage for no gain (pre-flight S4); any
    other value is refused by name. `enab` is refused by `platform.Validate` with the words
    config.Load used. `policy.Env.EnableUsernames` is gone.
11. **The intersection checks report, they do not fail.** `dead_rule` and `fallback_exposure` read
    the adapter's `unreachable` and `fallback`, which list only what the ceiling notes and L16
    measured. §11's own `svc_oxidized` is now reported, exactly as spec §12's example shows.
12. **The local-account check reads a file; port49 never logs into a device.** `port49 devices
    check-config` takes the configuration a compliance tool fetched and exits 1 on a collision
    with a username port49 serves there, or on a line the adapter's `config_checks` name. Run on
    the lab's own configs it finds the enable fallbacks L3 needed and the Junos
    `authentication-order` L4 measured (Task 15's test). A configuration it could not read to the
    end — a line past the scanner's limit — is an error, never a clean pass (pre-flight S9).
13. **`grants remove --pr` works in a worktree of its own.** A branch off `--base` as `--remote`
    has it (fetched), carrying the edit and nothing else, pushed, and `gh pr create`; the
    operator's checkout is never touched. A policy file with uncommitted edits, or one that
    differs from the base's, is refused rather than silently carrying other commits or computing
    the removal from a file the pull request does not merge into (pre-flight S5). A `--remote` or
    `--base` starting with `-` is refused, and a credential in a URL git or gh prints is replaced
    before the error is shown (pre-flight N9).
14. **The lab verifies the replies, and `verified: containerlab` waits for it.** Task 17 delivers
    each adapter's exact reply through the lab authorizer, level by level, and measures what the
    device reports and which ceiling commands it sends port49; the slice runs end to end on all
    three platforms; three candidate inert attributes are measured beside admin's reply, and one
    counts inert only if the session opened with admin's identity and reach and still authorized
    a `show version` (pre-flight S6: L18 saw IOS-XE open a session and refuse every command in
    it). Then decision 25's fallback is measured, not inferred (pre-flight B1): operator's reply,
    one interactive session, port49d stopped under it, a configuration change typed, with
    admin's reply as the control. The notes are `tests/lab/results/L22-<platform>.md` (pre-flight
    S7). Task 18 flips `verified` only where the note agrees with the adapter, closes L22 only
    where the fallback was measured too, removes decision 25's provisional marker only for what
    was measured, and lists inert only what the note shows inert.
15. **No new reason code, no new metric, no new dependency.** One record field (`redacted`), three
    report kinds (`dead_rule`, `fallback_exposure`, `platform_override_redundant`), one acknowledge
    shape (`{platform, field, reason}`).

## What the operator sees

The owner's rule: trace a mechanism on a bad day first.

- **After the upgrade, with no edit:** an EOS admin session is told `priv-lvl=15`,
  `roles=network-admin`; an operator `priv-lvl=15`, `roles=network-operator`. An NX-OS session is
  told its role for the first time — admins land on `network-admin` where they used to land on
  `vdc-operator`. An IOS-XE admin lands at 15 where it used to land at 1, and an operator at 7,
  which runs `clear counters` only once the device carries the adapter's `device_config` (`port49
  platform show cisco_iosxe` prints it). `policy test` prints `platform_set: 1.0.0` first. This is
  the one rendering change a binary upgrade makes: 1.0.0 is the first set, and every later change
  waits for a pin.
- **port49 unreachable, a session already open, method list ending in `local`:** an EOS or NX-OS
  operator keeps `network-operator` — reads, no configuration — and an admin keeps
  `network-admin`. `policy test` says so ahead of time, per subject: `report: fallback_exposure:
  subject "svc_oxidized" at admin (priv-lvl=15, roles=network-admin) on arista_eos: port49's rules
  confine it to show **, …`.
- **A role attribute keyed `all:` with IOS-XE in the inventory:** `quarantine: xe-01
  (cisco_iosxe): subject "s": on cisco_iosxe its session reply sends idletime*30 (role ro), and
  cisco_iosxe takes no attribute but priv-lvl: …` in `policy test`; `QUARANTINES:` and exit 1 in
  `policy diff`; at start, the quarantine line, and the device falls to local. Never the minute of
  refused SSH that sending it would cost.
- **An adapter edit in review:** `ADAPTER: platforms.arista_eos.entity_classes {…} -> {…}: the key
  changes what port49 decides or what this gate reads, so the diff cannot vouch for it; add
  {platform: arista_eos, field: entity_classes, reason: "..."} under acknowledge:` and exit 1,
  until the entry is there; then `adapter (acknowledged: <reason>): …`.
- **A typed secret:** the device runs `username bob secret Hunter2` as it would have; the log's
  `request.raw` and `record.raw` say `cmd-arg=«redacted»` with `"redacted": true`, and `policy
  replay` says `unverifiable: the record was redacted before it was written`. Nothing reaches the
  spool file on disk in the clear.
- **`port49d.yaml` still carrying `platforms.<name>.enable_username: principal`:** `port49d`
  starts, and says at start: `port49d: platforms.cisco_iosxe.enable_username moved to the policy
  file in plan 5: write it under platforms: {cisco_iosxe: {enable_username: ...}} there, …;
  principal is the default, so delete the line`. Any other value does not start, with the same
  words.
- **A policy pinning a set the binary does not ship:** `port49d` does not start, and a reload is
  refused and keeps the policy in force: `platform_set: 1.4.0 is not a set this binary ships; it
  ships 1.0.0. …`.
- **Offboarding a machine subject:** `port49 grants remove --policy … --inventory … --subject
  svc_old --pr` prints the pull request's URL; the checkout is untouched. Run from a checkout
  whose policy file differs from `origin/main`'s, it refuses and says so.

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

Carried from plans 2–4b, and still binding:

- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row**, in
  the adapter file beside the value it justifies.
- **A blob fails closed; a quarantined device is closed without a reply; nothing logs a token.**
- **Every context write outside login goes through a narrow setter.** This plan writes no context.

New in this plan:

- **Code is applied as written.** Whole new files are given as diffs from `/dev/null`; a change to
  an existing file is a unified diff, applied with `git apply` from the repository root (save the
  block to a file, or pipe it). Every block was generated from a commit that went green against
  `f759a55` in order, and the red step of every task was run and fails as its Step 2 says. A hunk
  that does not apply means the tree is not where this plan expects: stop and say so rather than
  editing by hand.
- **A released platform set is never edited.** 1.0.0 is released when this plan merges.
- **No new dependencies.**
- Branch `feature/platform-adapters`; never commit code to `main`.
- Every verification runs `make test && make vet`, `go vet -tags lab ./tests/lab/...`, and
  `make build`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  ```

---

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md  MOD  §5.6, §5.7, §5.8, §6, §8, §12, §13 decision 25, §15 L22 (Task 1; L22 closed Task 18)
platforms/platforms.go                        NEW  embed: FS (Task 2), Redact (Task 10)
platforms/1.0.0/{arista_eos,cisco_nxos,cisco_iosxe,juniper_junos}.yaml  NEW  the built-in set (Task 2; Tasks 3-5, 14, 15, 18 fill it)
platforms/redact.yaml                         NEW  built-in redaction patterns, unpinned (Task 10)
internal/platform/adapter.go                  NEW  Spec, ParseSpecs, Over, Validate (Task 2); SpecOf, SpecKeys (Task 9)
internal/platform/set.go                      NEW  DefaultSet, UnpinnedSet, LoadSets, Sets, Set (Tasks 2, 6)
internal/platform/dialect.go                  MOD  the Go literal goes; new fields per task; PrivLvl reads CeilingLevels (Task 4)
internal/platform/redact.go                   NEW  Redaction, Redactions, Redact, RedactRaw (Task 10); Redactor, RedactRecord (Task 11)
internal/platform/config.go                   NEW  ReadConfig, LocalAccount, ConfigFinding (Task 15)
internal/platform/platform.go                 MOD  EnableUsernames and KnownEnableUsername go (Task 8)
internal/policy/load.go                       MOD  buildPlatforms, PlatformSet (Task 6); blocks (Task 7); acknowledge shapes (Task 9); PlatformNames/Source (Task 12); Env.Sets (Task 13)
internal/policy/file.go                       MOD  platform_set, platforms:, acknowledge platform/field
internal/policy/resolve.go                    MOD  accepted_attributes joint check (Task 5); enable_username from the adapter (Task 8)
internal/policy/diff.go                       MOD  a level's own rendering (Task 3); Adapters, stricter BearsPrivilege (Task 9); redact gated (Task 10)
internal/policy/lint.go                       MOD  platform_override_redundant (Task 7); ShadowedBuiltIns, Reach (Task 13); intersections (Task 14)
internal/policy/intersect.go                  NEW  dead_rule, fallback_exposure (Task 14)
internal/policy/edit.go                       MOD  SetPlatformSet (Task 13)
internal/policy/review.go                     MOD  ServedUsernames (Task 15)
internal/config/config.go                     MOD  enable_username: principal loads with a notice, others refused (Task 8)
internal/decision/log.go                      MOD  Request.Redacted, AcctRecord.Redacted (Task 11)
internal/daemon/author/author.go              MOD  WithRedactor; emit redacts (Task 11)
internal/daemon/acct/acct.go                  MOD  WithRedactor; redact before the spool (Task 11)
internal/replay/replay.go                     MOD  a redacted record is unverifiable (Task 11)
cmd/port49d/main.go                           MOD  Env without EnableUsernames (Task 8); redactorFor (Task 11)
cmd/port49/policy.go                          MOD  platform_set line (Task 6); offlineEnv (Task 8); ADAPTER lines (Task 9); grants remove --pr (Task 16)
cmd/port49/platform.go                        NEW  platform list/show/export (Task 12), upgrade (Task 13)
cmd/port49/devices.go                         NEW  devices check-config (Task 15)
cmd/port49/pr.go                              NEW  removalPR, withoutCredentials (Task 16)
cmd/port49/main.go                            MOD  usage and dispatch
tests/lab/configs/iosxe-startup.cfg           MOD  level 7's lines (Task 5)
tests/lab/adapters_test.go                    NEW  the differential lab test (Task 17)
tests/lab/slice_test.go, slice/policy.yaml    MOD  the slice on all three per-command platforms (Task 17)
tests/lab/results/L22-*.md, slice-*.md        NEW  written by the lab run (Task 17)
docs/superpowers/plans/README.md              MOD  plan 5a as built; 5b's brief (Task 18)
```

Eighteen tasks: **one docs task first** (Task 1), **fifteen code tasks** (2–16), **one lab task**
(17, on the lab host), and **one lab-and-docs task last** (18). Every code task leaves `make test`
green, and each was applied in order to `f759a55` and run.

---
### Task 1: The spec says what the adapters do, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.6, §5.7, §5.8, §6, §8, §10's bundle
  example, §11's example, §12, §13 decisions 23 and 25, §15 new row L22)

**Interfaces:** none; every later task cites a paragraph this one writes.

What changes, so a reviewer can check each against a task:

- §5.7 "Credentials never appear": a typed secret is redacted in `authorize_command` and `account`
  records; `redacted: true`; replay reports `unverifiable` (Tasks 10, 11).
- §5.8 "Redact secrets": the pattern grammar as built (`{match, after}` / `{match, from}`),
  `platforms/redact.yaml`, unpinned, additive, a platform's list on top of `default`; patterns
  lead with `**` (NX-OS's accounting `cmd`, L21); a wildcard-only `from` pattern refused; both
  forms of a record redacted together (Tasks 10, 11).
- §5.6: the owed configuration check is `port49 devices check-config` (Task 15).
- §6: operator blocks live in the policy file; IOS-XE `operator` is `priv-lvl=7` with its
  reference configuration; the device role and decision 25; "Exact attribute spellings" corrected
  from `shell:roles` to the bare `roles=` on EOS — **the lab contradicts the doc here**
  (`tests/lab/results/L16-arista_eos.md`, 2026-09-22), so the doc is fixed and the commit says so;
  `accepted_attributes` (Tasks 3–5).
- §8: the example adapter is the shipped one; the Fields table gains every key this plan adds;
  "User-editable, day one", "Knowing what is shipped" and the pin as built, the generic adapter
  frozen with the sets; a block may not list inert what a level renders, nor be named `all` or
  `default`; `port49d.yaml`'s `enable_username: principal` loads with a notice (Tasks 2, 6, 7, 8,
  12, 13).
- §12: the intersection checks as built (Task 14), `devices check-config` (15), the level's own
  rendering and the stricter adapter in the privilege gate (Tasks 3, 9), the adapter-edit gate on
  every platform either version has an adapter for, `redact` gated (9, 10), `grants remove --pr`
  cut from the remote's base (16).
- §13: decision 23 points at decision 25; decision 25 is new, provisional on L22, whose question
  includes the fallback it rests on.
- §15: L22, the role ceiling per level, the adapters' replies, and operator's reply with port49
  stopped under an open session, open (closed by Task 18).

- [ ] **Step 1: Apply the spec edits**

<!-- patch: docs/design/2026-08-23-policy-engine-spec.md -->
````diff
diff --git a/docs/design/2026-08-23-policy-engine-spec.md b/docs/design/2026-08-23-policy-engine-spec.md
index 4e70c81..8b26a32 100644
--- a/docs/design/2026-08-23-policy-engine-spec.md
+++ b/docs/design/2026-08-23-policy-engine-spec.md
@@ -1555,8 +1555,10 @@ require disjoint namespaces for break-glass and local accounts and MUST NOT put
 the enable method list, and port49 SHOULD warn when it observes a local fallback succeed for a
 username it knows. The detection that exists is accounting: such a session's exec records carry a
 discriminator port49 never saw begin and are attributed `foreign` (§5.8), counted in
-`port49_accounting_attributions_total{attribution="foreign"}`. Plan 5's adapters owe a
-configuration check that warns when a port49-served username exists as a device-local account.
+`port49_accounting_attributions_total{attribution="foreign"}`. The configuration check is
+`port49 devices check-config` (§12): it reads a device's configuration against its adapter and
+fails on a device-local account named as a username port49 serves there, and on an enable list
+that falls back to a local secret.
 
 #### Gated on the lab
 
@@ -1764,6 +1766,14 @@ which a credential can be recovered. The credential is identified by `credential
 only — the same hash the receipt binds (§5.1.1), which is what lets a retransmission be
 recognized in the log as one decision retried rather than two decisions made.
 
+A secret an operator types into a command — `username bob secret Hunter2` — reaches port49 on
+the command's authorization request as well as its accounting record, so both are redacted
+before they are written, by the platform's `redact` patterns (§5.8). The decision is made on
+the command as sent; only the record loses the secret. A redacted record carries
+`"redacted": true` in its `request` (an `authorize_command`) or its `record` (an `account`),
+and `port49 policy replay` reports it `unverifiable` rather than replaying the redacted words:
+the command it decided is not in the log, by design.
+
 #### Replay
 
 `port49 policy replay <record>` re-evaluates a record against the blob it names and reports
@@ -1907,21 +1917,46 @@ record keeps it.
 logs fill with plaintext passwords, and it is worse here than in a conventional deployment
 because port49's stream is designed to be shipped and retained.
 
-Platform adapters therefore declare redaction patterns, applied before emit:
+Platform adapters therefore declare redaction patterns, applied before the record reaches the
+spool — which is on disk — and before an authorization record is emitted (§5.7):
 
 ```yaml
-# platforms/arista_eos.yaml
-redact:
-  - {match: ['username', '*', 'secret', '**'],        from: 3}
-  - {match: ['username', '*', 'password', '**'],      from: 3}
-  - {match: ['enable', 'secret', '**'],               from: 2}
-  - {match: ['**', 'key', '*'],                       from: -1}
+# platforms/redact.yaml — the built-in patterns
+default:
+  - {match: ['**'], after: secret}
+  - {match: ['**'], after: password}
+  - {match: ['**'], after: key}
+juniper_junos:
+  - {match: ['**'], after: encrypted-password}
 ```
 
+A pattern's `match` is words, `*` for one word and `**` for any number, anchored at both ends
+as a rule is. A command it matches loses every word after the first word equal to `after`, or
+every word from position `from` on (0 is the command word and is never removed; a negative
+`from` counts from the end). A platform that may send what was typed (`expands_abbreviations:
+false`) has a pattern's word match its abbreviations too, which removes more rather than less.
+Junos sends a whole command line as one `cmd`, so each element is split into words first.
+The built-in patterns lead with `**`, because a secret sits anywhere in a line and NX-OS's
+accounting `cmd` is the configuration path joined with ` ; ` and a result — `configure
+terminal ; username bob password ... (SUCCESS)` (`tests/lab/results/L21-cisco_nxos.md`) — which
+a pattern anchored at the command word never matches. A pattern whose `match` is `*` and `**`
+alone matches every command, and with `from` it would remove the arguments of every record: it
+is refused, and a secret is named by the word it follows, with `after`. Where a pattern removes
+words from a record's `raw` pairs and not its vector, or the other way round, the form it
+missed loses every argument, so a secret is never left in one of the two.
+
 Redaction replaces argument *values* with `«redacted»` and preserves the vector's shape and
 length, so the reconciliation join still works on a redacted record. It applies to `raw` as
 well — a rule that redacted only the normalized form would defeat itself.
 
+**The built-in patterns are not part of a pinned platform set** (§8). Redaction changes what
+the log keeps and never what anyone may do, so a pattern a release adds applies at upgrade.
+They live in `platforms/redact.yaml` beside the sets: a `default` list every platform gets, and
+per platform a list that **adds** to it and never replaces it. A policy file's
+`platforms.<name>.redact` adds patterns too and never removes one, `replace: true` included;
+because a pattern changes what the audit keeps, an edit to it is gated (§12). `port49 platform
+show` prints both.
+
 Redaction is best-effort by nature and MUST NOT be presented otherwise: a pattern that misses
 leaks. It is strictly better than emitting verbatim, and the honest mitigation is that
 port49's own credentials are never typed at a device prompt in the first place.
@@ -2297,7 +2332,8 @@ defaults to the non-breaking choice.
 ### Where attributes are declared
 
 **Platform file**, for anything tied to a level. Operators may extend a shipped platform or
-define their own in the policy repository, with no upstream change required:
+define their own in the policy file's `platforms:` block, with no upstream change required
+(§8, "User-editable, day one"):
 
 ```yaml
 platforms:
@@ -2366,6 +2402,12 @@ port49 cannot check what an attribute means. It MUST check everything else:
   the failure is never truncation on the device (L11); it is a refusal at policy load, which
   is where this MUST be caught.
 - Mandatory versus optional, with a warning on any mandatory attribute not recognized.
+- **What the device takes.** An adapter MAY list `accepted_attributes`, every attribute name
+  the platform's session reply may carry. IOS-XE refuses the session for anything else under
+  either flag, and a run of refusals stops it answering SSH for about a minute, break-glass
+  included (`tests/lab/results/L18-cisco_iosxe.md`), so its adapter lists `priv-lvl` alone and
+  a composition whose reply carries another attribute fails the joint check and quarantines
+  the device (§10): closed without a reply, it falls to local at once.
 
 **Unknown attributes default to optional (`*`).** A mandatory attribute a device cannot
 parse causes it to reject the entire session, breaking every login on that platform.
@@ -2399,16 +2441,33 @@ the device configuration:
   `ceiling_indistinct`.
 
 IOS-XE is not in this rule: its level 7, given commands with `privilege exec level 7 ...`,
-is exactly the operator rung, so the device can enforce it (`ceiling-cisco_iosxe.md`). Its
-rendering is plan 5's adapter work.
+is exactly the operator rung, so the device can enforce it (`ceiling-cisco_iosxe.md`).
+`operator` renders `priv-lvl=7` there, and the adapter's reference configuration carries
+the lines level 7 depends on — a command method list for level 7, so the device asks port49
+about a level-7 command at all, and `privilege exec level 7 clear counters`, the one command
+the measured rung runs. Without them level 7 is level 1, which fails closed (decision 25).
+
+**The device role is the other half, and it is what binds when port49 cannot answer.** With
+command authorization pointed at port49 no EOS or NX-OS role narrows anything (above); with
+the method list fallen back to `local`, the role delivered at login is the policy — on vEOS
+`network-operator` is refused `configure` and `network-admin` is not, and on the N9Kv
+`network-operator` is refused a configuration command (`L16-arista_eos.md`,
+`L16-cisco_nxos.md`, command authorization LOCAL). So where `operator` gets admin's level, it
+gets readonly's role: `priv-lvl=15`, `roles=network-operator` on EOS and
+`shell:roles*network-operator` on NX-OS, and an outage never hands an operator configuration
+(decision 25). `admin` gets `network-admin`, `readonly` `network-operator` and, on EOS,
+`priv-lvl=1`.
 
 **Platforms that are not `priv-lvl`-native** (Junos maps to `local-user-name`) MUST declare
 a mapping for every level. A missing mapping is a **policy load error in CI**, not a broken
 login at 3am.
 
 **Exact attribute spellings are lab-verified, not asserted.** The shipped adapters use bare
-`priv-lvl` for the TACACS+ shell-service reply and `shell:roles` for EOS and NX-OS roles.
-Those spellings — and every other attribute name in a shipped platform file — MUST be
+`priv-lvl` for the TACACS+ shell-service reply, the bare `roles=` for EOS roles and
+`shell:roles*` for NX-OS roles, and nothing but `priv-lvl` on IOS-XE. This paragraph said
+`shell:roles` for EOS until plan 5: the lab shows vEOS ignores `shell:roles*` and refuses the
+session on `shell:roles=`, and reads the bare `roles=` (`tests/lab/results/L16-arista_eos.md`,
+2026-09-22). Those spellings — and every other attribute name in a shipped platform file — MUST be
 confirmed against a real image in the containerlab matrix before that adapter is marked
 `VERIFIED` (§8). A wrong attribute name fails silently as an ignored optional attribute, or
 loudly as a rejected session if declared mandatory, and neither outcome should be discovered
@@ -2566,13 +2625,14 @@ A platform adapter is a small declarative file. Adapters ship built in, are veri
 containerlab matrix where an image exists, and are both overridable and contributable.
 
 ```yaml
+# platforms/1.0.0/arista_eos.yaml, abridged
 platforms:
   arista_eos:
-    supports: [session, commands, config_commands]
+    supports: [session, commands]  # config_commands is unmeasured (§9)
     privilege:
-      readonly: ["priv-lvl=1",  "shell:roles*network-operator"]
-      operator: ["priv-lvl=15"]      # admin's level; port49's rules are the fence (§6)
-      admin:    ["priv-lvl=15", "shell:roles*network-admin"]
+      readonly: ["priv-lvl=1",  "roles=network-operator"]
+      operator: ["priv-lvl=15", "roles=network-operator"]  # admin's level, readonly's role (§6)
+      admin:    ["priv-lvl=15", "roles=network-admin"]
     entity_classes:
       management: ['^Management[0-9]+$']
       loopback:   ['^Loopback[0-9]+$']
@@ -2617,18 +2677,26 @@ attribute is complete in four lines:
 | `privilege` | level → attributes at session authorization | always |
 | `supports` | capability declaration (see §9) | always |
 | `entity_classes` | named sets of device entity names, referenced as `@class` in rules | if rules use classes |
-| `enable_username` | `principal`, or a template such as `$enab{level}$` | if enable is supported |
+| `enable_username` | `principal`, or a template such as `$enab{level}$` (refused at load until a lab note shows a device sending it, §7) | if enable is supported |
 | `expands_abbreviations` | whether the device sends resolved command words | if `commands` |
 | `splits_interface_names` | whether the device sends an interface name and its index as two arguments (§3 rule 5); `true` on `cisco_iosxe` only (L21) | optional |
 | `pipe_token` / `pipe_authorized` | modifier separator; whether it reaches us | if `commands` |
 | `command_projection` | how rules render for session-only platforms (below) | if `session`-only |
 | `bits` / `bit_delivery` | each permission bit's reach in rule form, and whether bits travel as `user-permissions` or a `local-user-name` template (below) | if `session`-only |
-| `redact` | patterns whose argument values are removed before an accounting record is emitted (§5.8) | if the platform sends command accounting — session-only platforms included |
+| `redact` | patterns whose argument values are removed before an accounting or authorization record is written (§5.7, §5.8); a block **adds** to the built-in patterns in `platforms/redact.yaml` and never removes one, and an edit to it is gated (§12) | if the platform sends command accounting — session-only platforms included |
 | `session_services` | the authorization `service` values this platform's sessions arrive with; a **list**, because the name is device-configurable on Junos | defaults per platform |
 | `session_discriminator` | the accounting AV pair whose value separates two sessions of one user on one device (§5.8) | defaults per platform |
 | `exec_commands` | the `cmd` values that mark an exec record rather than a per-command one; empty means "the exec record carries no `cmd` at all" (§5.8) | defaults per platform |
 | `system_users` | usernames this platform's own machinery writes accounting under, attributed `system` (§5.8); `juniper_junos` ships `root`, every other adapter ships empty | optional |
 | `port_pattern` | expected `port` shape, used only for drift detection | optional |
+| `ceiling_levels` | the priv-lvl number each level stands for where the rendering sends no `priv-lvl` (NX-OS is sent a role and no level, L16), for the token's ceiling | if `privilege` sends no `priv-lvl` |
+| `strip_cr` / `shows_server_msg` | whether commands end in `<cr>` (§3 rule 1); whether the device displays a denial's `server_msg` (L2) | defaults from the generic adapter |
+| `privilege_attributes` / `inert_attributes` | the attribute names that carry privilege on the platform, and those held to carry none: the only names a placeholder may go in (§6), and the only ones whose change the diff does not gate (§12) | defaults from the generic adapter |
+| `accepted_attributes` | where set, every attribute name the session reply may carry; any other quarantines the device (§6, "What the device takes") | optional |
+| `device_config` | the device configuration the adapter's renderings depend on, one line each, printed by `platform show` | optional |
+| `unreachable` / `fallback` | per level, the commands the device refuses in its own parser, and what it gives a session on its own when port49 cannot answer: the dead-rule and fallback-exposure reports read them (§12) | optional |
+| `local_accounts` / `config_checks` | patterns that find a device-local account in the device's configuration, and lines the configuration must not carry: `port49 devices check-config` reads them (§5.6) | optional |
+| `verified` | `containerlab` or `community`; a built-in adapter's own claim, refused in a policy file | optional |
 
 ### `session_services`
 
@@ -2902,19 +2970,24 @@ Operators MUST be able to define and override platforms without an upstream chan
 containing Supermicro BMCs, Meinberg time servers, and HPE gear cannot wait on releases —
 that is the ticket-queue bottleneck the design exists to remove.
 
-Built-ins ship embedded in the binary; user files live in the policy repository and merge
-over them, per top-level key:
+Built-ins ship embedded in the binary; an operator's blocks live in the policy file, under
+its `platforms:` key, and merge over them per top-level key. A key whose value is a map —
+`privilege`, `ceiling_levels`, `entity_classes`, `unreachable`, `fallback` — merges per entry,
+so a block that adds one class keeps the rest; a list or a value replaces the built-in's
+whole; `redact` adds and never removes (§5.8):
 
 ```yaml
-# platforms/arista_eos.yaml — adds one class, inherits everything else
+# in the policy file — adds one class, inherits everything else
 platforms:
   arista_eos:
     entity_classes:
       uplink: ['^Ethernet(49|50|51|52)$']
 ```
 
-`replace: true` on a platform block discards the built-in and starts clean. `based_on:`
-declares a variant, using the same vocabulary as `parent:` on privilege levels:
+`replace: true` on a platform block discards the built-in and starts from the generic adapter
+(below). `based_on:` declares a variant of a platform the pinned set ships, under a new name,
+using the same vocabulary as `parent:` on privilege levels; a name the set does not ship starts
+from the generic adapter:
 
 ```yaml
   whitebox_nos:
@@ -2923,8 +2996,24 @@ declares a variant, using the same vocabulary as `parent:` on privilege levels:
       management: ['^ma1$']
 ```
 
-User files receive identical structural validation to shipped ones: required fields,
-attribute syntax, the 255-byte limit, and entity-class patterns must compile under RE2.
+The blocks are in the policy file, not a file beside it, so `port49 policy test` and `policy
+diff` read exactly what the broker renders from, and a block goes through the same review.
+They receive identical structural validation to shipped ones: required fields, attribute
+syntax, the 255-byte limit, entity-class patterns compiling under RE2, a rendering the platform
+accepts (`accepted_attributes`), and `enable_username` (§7). A block may not claim `verified`,
+may not list inert an attribute one of its levels renders — that attribute is the level (§6)
+— and may not be named `all` or `default`, which name every platform in `attributes:` and in
+the redaction table.
+A class pattern a deny names may not turn case-insensitivity off (`(?-i)`), on any platform: a
+differently-cased interface name would walk past the deny (§4).
+
+Four adapter fields are the daemon's rather than the policy's — `session_services`,
+`session_discriminator`, `exec_commands` and `system_users` are read on the wire, including by
+a daemon with no policy — and stay built in, `session_services` settable in `port49d.yaml` as
+before, until plan 6's bundle carries adapters to the daemon. `enable_username` moved the other
+way in plan 5, to the policy file, where the offline tools see it: `port49d.yaml` still loads
+`principal`, the only value it ever took, with a notice saying where the key went, and
+refuses any other value by name.
 
 ### Knowing what is shipped
 
@@ -2936,19 +3025,29 @@ diffable across tags without running anything.
 **They are introspectable**, and honest about verification:
 
 ```
-$ port49 platform list
-PLATFORM           SOURCE     VERIFIED       SUPPORTS
-arista_eos         built-in   containerlab   session,commands,config_commands
-cisco_nxos         built-in   containerlab   session,commands,config_commands
-juniper_junos      built-in   containerlab   session
-f5_bigip           built-in   community      session
-meinberg_lantime   local      —              session
+$ port49 platform list --policy policy.yaml --inventory inventory.yaml
+PLATFORM           SOURCE       VERIFIED       SUPPORTS
+arista_eos         overridden   —              session,commands
+cisco_iosxe        built-in     containerlab   session,commands
+cisco_nxos         built-in     containerlab   session,commands
+juniper_junos      built-in     —              session
+```
+
+(`containerlab` where `tests/lab/results/L22-<platform>.md` shows the adapter's replies
+applied as it says; the 2026-09 lab run is plan 5a's Task 17.)
+
+```
+meinberg_lantime   local        —              session
+whitebox_nos       variant      —              session,commands
 ```
 
 A community-contributed adapter nobody has run against a real image MUST say so rather than
-appearing identical to one verified on every commit. `platform show <name>` prints a
-definition, `--effective` the merged result after overrides, and `platform export --all`
-writes them to disk.
+appearing identical to one verified on every commit, and so must a built-in adapter a block
+changed: SOURCE says `overridden`, `variant` or `local`, and VERIFIED `—`. `platform show
+<name>` prints a definition — the built-in, or with `--policy` the merged result — headed by
+where it came from and followed by the built-in redaction patterns; `platform export <name>`
+prints the file alone, and `platform export --all --dir DIR` writes one per platform, a
+directory `platforms/` would accept.
 
 **Published documentation is generated from the embedded files** at release time, so it
 cannot drift from the binary.
@@ -2958,27 +3057,30 @@ release, upgrading the binary silently changes what every EOS admin session rece
 **binary upgrade becomes an unreviewed policy change**. Policy therefore pins a version:
 
 ```yaml
-platform_set: 1.4.0
+platform_set: 1.0.0
 ```
 
-Upgrading the binary changes nothing about rendering. `port49 platform upgrade` moves the pin
-and reports exactly what changes:
+The sets are directories, `platforms/<version>/`, and a released one is never edited; nor is
+the generic adapter each set's files are laid over, which a `replace:` block and a platform no
+set ships start from — a change to either ships as a new set. **A
+policy that pins none renders with 1.0.0, the first set, on every binary** — so a policy
+written before pinning existed never changes on upgrade, and moves forward only by pinning a
+newer set. A set the binary does not ship is refused at load, by name. Upgrading the binary
+changes nothing about rendering. `port49 platform upgrade --to V` moves the pin (with
+`--write`, in the file, touching nothing else) and reports exactly what changes:
 
 ```
-platform_set 1.4.0 → 1.5.0
-
-  arista_eos.privilege.admin
-    + shell:roles*network-admin        (was absent)
-    affects 4,412 devices, 6 subjects
-
-  juniper_junos.supports
-    + config_commands                  ⚠ 2 roles have config rules
-                                         that were previously dead
+platform_set 1.0.0 -> 1.1.0
+  platforms.arista_eos.privilege
+    {"admin":["priv-lvl=15","roles=network-admin"],...} -> {...} (gated: the change that moves the pin acknowledges it, ...)
+    affects 4412 devices, 6 subjects
+  shadowed: platforms.arista_eos.entity_classes: set 1.1.0 changes the built-in value and the policy's block keeps its own; compare the two
 ```
 
-CI SHOULD also report override drift — an override that now matches the built-in and can be
-removed, or a built-in change an override shadows — so local platform files do not rot
-silently as upstream improves.
+`port49 policy diff` on the file before and after is the gate: a pin move is an adapter edit
+like any other (§12). CI also reports override drift — `platform_override_redundant`, a block
+key that says what the pinned set already says and can be removed; and at upgrade, a built-in
+change a block shadows — so local platform files do not rot silently as upstream improves.
 
 **`port49 platform export <name>`** emits a file suitable for an upstream pull request:
 written for one fleet on day one, contributed once proven.
@@ -3121,7 +3223,7 @@ They are therefore published as **one versioned bundle**:
 bundle v2291
   inventory      device records, addresses, platforms, attributes
   policy         compiled roles, scopes, subjects, grants
-  platform_set   1.4.0, as pinned by the policy repository
+  platform_set   1.0.0, as pinned by the policy repository
 ```
 
 **A sync can make a valid policy invalid, and the bundle builder quarantines rather than
@@ -3598,7 +3700,7 @@ Mitigations, designed in rather than documented afterward:
 ## 11. Complete policy example
 
 ```yaml
-platform_set: 1.4.0
+platform_set: 1.0.0
 
 privilege_levels:
   - {name: readonly}
@@ -3772,20 +3874,38 @@ the device offers and what port49 permits (§6), CI MUST report where the two di
 system, and both are ordinary review questions once surfaced:
 
 ```
-⚠ DEAD RULES — interface_tech permits commands its privilege cannot reach
-    privilege: readonly  →  arista_eos priv-lvl=1
-    unreachable: configure **, interface /^(ethernet|port-channel)/, shutdown
-    the device will never submit these for authorization
-
-⚠ FALLBACK EXPOSURE — svc_oxidized
-    port49 rules confine it to:  show **
-    device role on failure:      network-admin  (full administrative access)
-    if port49 is unreachable, this subject has more access than policy grants
+report: dead_rule: role "interface_tech": permit "configure terminal" cannot be reached at
+  readonly (priv-lvl=1, roles=network-operator) on arista_eos: the device refuses every command
+  it matches in its own parser and never asks port49 (unreachable: clear counters **, clear ip
+  bgp **, configure terminal **, show users detail **; tests/lab/results/ceiling-arista_eos.md)
+
+report: fallback_exposure: subject "svc_oxidized" at admin (priv-lvl=15, roles=network-admin)
+  on arista_eos: port49's rules confine it to show **, terminal length *, and if port49 cannot
+  answer and the device falls back to local it gets network-admin: every command, configuration
+  included: more than the policy grants (spec §6, §12)
 ```
 
+Both read the adapter (§8), and only what the lab measured. A **dead rule** is a permit every
+command of which is in the adapter's `unreachable` list for the level the session renders at:
+the commands the device refused in its parser at that level with port49 permitting everything
+(`tests/lab/results/ceiling-*.md`). A **fallback exposure** is a subject whose composed rules
+deny something, at a level whose adapter `fallback` says what the device gives a session on its
+own when the method list falls back to `local` — `network-admin` at admin on EOS and NX-OS,
+level 15 on IOS-XE. `operator` gets readonly's role for this reason (§6), so it is never
+exposed where its device role binds. Each is reported by `port49 policy test` and does not fail
+it: the answer is a review question, not a wrong policy.
+
 **Attribute shadowing.** Where a role or grant attribute overrides a platform attribute of
 the same name (§6), CI MUST name both so the override is deliberate.
 
+**`port49 devices check-config`** reads a device's configuration, as `show running-config`
+prints it, against the policy's adapter for its platform, and exits non-zero on a device-local
+account named as a username port49 serves on that device — the collision §5.6 forbids — or on a
+line the adapter's `config_checks` name: a command method list falling back to `none` or
+`if-authenticated` (§6), an enable list falling back to a local secret (§5.6), a Junos
+`authentication-order` with `password` in it (L4). port49 never logs into a device; this reads
+a file a compliance tool fetched.
+
 **`port49 devices capabilities`** reports the `supports`-versus-`observed` matrix from §9.
 
 **Shadowed-deny report.** Because a more specific permit can override a deny (§5.4), CI MUST
@@ -3834,6 +3954,13 @@ each instant. Any of these is a raise:
   ruling 2026-09-24, review C4). The gate cannot read the direction of such a change, so it fails
   closed.
 
+Where the platform's adapter is the same in both versions, the attributes the level itself
+renders move with the level, and `level` and `priv_lvl` judge the direction: a subject moved
+from admin to readonly on EOS is a lowering, although the role its rendering names changed from
+`network-admin` to `network-operator`. Which attributes bear privilege is read from both
+versions' adapters, the stricter winning, so an edit that lists an attribute inert cannot hide a
+change to it in the same diff.
+
 Each fails unless a passing session test in the new policy, at that instant, on a device of the
 group reported, asserts the new value of every dimension that rose: `priv_lvl:` for the device
 privilege, `max_privilege:` for the ceiling, `level:` for the level, `enable:` for the mechanism,
@@ -3901,6 +4028,18 @@ broker refuses to mint for (`attribute_too_long`, `attribute_unsafe`) is locked
 device the refusal covers; a test cannot make that intended, so the change must fix the attribute
 (owner's ruling 2026-09-24, confirming plan 4's behaviour).
 
+**An adapter edit fails the gate** (review M8, 2026-09-24). Once an operator can edit an
+adapter (§8), the diff compares each platform's adapter key by key, for every platform either
+version has an adapter for, whether or not the inventory has a device of it yet — the inventory
+is not diffed, so the day a device arrives is no review — and whether the change is a
+`platforms:` block or a moved `platform_set`. A key that changes what port49 decides, what the
+gate itself reads or what the audit keeps — `supports`, `privilege`, `ceiling_levels`,
+`entity_classes`, the normalization keys, `privilege_attributes`, `inert_attributes`,
+`accepted_attributes`, `enable_username`, `redact` — fails unless an `acknowledge:`
+entry names the platform and the key with a reason, `{platform: arista_eos, field:
+entity_classes, reason: ...}`: a diff cannot vouch for its own reading when the change is to
+the reading. Every other key is reported.
+
 **`port49 platform upgrade`** reports what a platform-set bump changes, so a binary upgrade
 is never an unreviewed policy change (§8).
 
@@ -3922,7 +4061,10 @@ since a group key is shared across the devices in its group.
 **Access review** is a rendering of the flat grant table, not an investigation:
 `port49 access review --subject <name>` lists every grant row the subject appears in, with
 scope size and expiry, and `port49 grants remove --subject <name>` produces the pull request
-that deletes them all — and, when no grant on the subject remains, the subject block itself,
+that deletes them all (`--pr` opens it: a branch off the base as the remote has it, carrying the
+edit and nothing else, pushed, and the review opened with `gh`, leaving the operator's checkout
+untouched; a policy file that differs from the base's is refused, since the removal would be
+computed from a file the pull request does not merge into) — and, when no grant on the subject remains, the subject block itself,
 so nothing is left behind to match. Directory-driven humans are offboarded by group removal;
 these two commands are the offboarding path for machine subjects and literal identities,
 which is the cost decision 2 accepted. A subject block with no grants is reported by CI.
@@ -4282,7 +4424,8 @@ pointed at port49, no role or level between readonly and admin narrows what port
 lower would only make it readonly on EOS, and refusing it quarantined every EOS device a
 policy landed there. `operator` gets level 15 on both, port49's per-command rules are the
 fence, and the device's method list must not fall back to `none` or `if-authenticated`.
-IOS-XE, whose level 7 can carry the rung, is left to plan 5's adapters. (§6, §8)
+IOS-XE, whose level 7 can carry the rung, is left to plan 5's adapters; decision 25 renders it
+there, and gives `operator` readonly's device role on EOS and NX-OS. (§6, §8)
 
 **24. A policy edit reaches live sessions without a logout.** A restart ends every live
 context and every unspent token, so without a live reload the only way to narrow an operator's
@@ -4293,6 +4436,23 @@ applies from the next command, and a principal with no grant left on a device ha
 revoked. Unspent tokens whose answer changed are deleted, because a redemption would otherwise
 write the superseded answer into a fresh context. (§5.1.3)
 
+**25. A level renders as a device level and a device role, and each fences a different
+failure.** *Plan 5, 2026-09.* While port49 answers, the device level is what the device
+enforces below port49: level 1 refuses the disruptive commands in the parser on EOS and
+IOS-XE, and nothing between 1 and 15 does on EOS or NX-OS (`tests/lab/results/ceiling-*.md`).
+When port49 cannot answer and the method list falls back to `local`, the device role is the
+policy (`L16-arista_eos.md`, `L16-cisco_nxos.md`, command authorization LOCAL). So `operator`
+gets admin's level where the device cannot draw the line (decision 23) and readonly's role
+everywhere a role binds — `roles=network-operator` beside `priv-lvl=15` on EOS,
+`shell:roles*network-operator` on NX-OS — and an outage never hands an operator
+configuration. On IOS-XE, whose level 7 is the operator rung once the device is told what 7
+runs, `operator` is `priv-lvl=7`, the adapter carries the reference configuration it depends
+on, and the device takes `priv-lvl` and nothing else, so any other attribute quarantines it
+(`L18-cisco_iosxe.md`). *Provisional on L22* until the adapters' own replies are measured,
+and operator's reply is measured with port49 stopped under an open session: L16 measured the
+role binding with the method list pointed at `local` alone, not a list falling back to it.
+(§6, §8)
+
 ### Deferred, with reasons
 
 Neither of these is an open question about the design. Both are closed for v1 on the
@@ -4755,6 +4915,7 @@ implemented against a guess. This section is the one place the distinction is ke
 | **L18** | How each platform treats a reply attribute it did not ask for: applied, ignored, or the session killed. Another vendor's attribute, an invented one, and a known attribute carrying a value the device cannot use, each in the OPTIONAL and the MANDATORY spelling. Per variant: whether the session opens and, when it does not, what the device says verbatim; what role or privilege the session ends up with; and whether the device still sends per-command authorization. | Whether an adapter may send one attribute list to a mixed fleet at all (§8). RFC 8907 §8.2 says an OPTIONAL argument a device does not understand SHOULD be ignored and a MANDATORY one MUST fail the authorization; `lab.session_attributes` in `tests/lab/port49d-lab.yaml` rested on the first half until IOS-XE disproved it (L10), and what an operator's typo costs (§6) rests on the same answer. Also decision 22's two Junos attributes (§13, gated on L12). | EOS, NX-OS, IOS-XE, Junos | open — added and measured 2026-09-22 on all five images, `tests/lab/l18_test.go`. **Three vendors answer three different ways, so §8 cannot have one rule.** vEOS follows §8.2 in both directions. The N9Kv and both Junos images honour neither half and ignore everything, mandatory included. IOS-XE refuses the session for anything it does not recognise under either flag — and a run of those refusals stops it answering SSH at all for about a minute, without sending port49 a packet. On Junos `local-user-name` is applied under either flag and **`user-permissions` does nothing**, which is decision 22's second attribute measured for the first time. **The per-command reply is measured too, 2026-09-22, and it does not follow the session reply:** the C8000V refuses EVERY command in the session — `Command authorization failed.` — for any of the three attributes under either flag, on authorizations port49 answered `permit`; vEOS ignores an optional unknown there and refuses every command on a MANDATORY one; the N9Kv ignores all of them. Junos has no per-command reply to ask it of (L10, L14; decision 21). Open: every non-SSH transport, and whether IOS-XE's SSH condition is the vty pool; see below |
 | **L19** | The maximum password length each platform accepts via PAP, on every login path where the device uses PAP. | The 30-character handle (design document §8): an authentication START carries a PAP password in `data`, whose length field is one byte, so PAP can bound the handle where the ASCII prompt does not — and NX-OS uses PAP for every SSH login by default | all | open — added 2026-09-23, split from L8. On the N9Kv an SSH login is carried as PAP and 127 characters arrive (`tests/lab/results/L8-cisco_nxos.md`); PAP on any other path, and on EOS, Junos and IOS-XE, which this lab does not configure for it, is unmeasured; see below |
 | **L20** | Whether a device answers a repeat API request without asking TACACS+; for how long; what it keys that answer on (the credential, the username, the client); whether a **wrong password** for the same user inside that window is also accepted; and whether a credential port49 would now refuse is re-checked inside it. | Whether a revocation in port49 reaches an API client at all (§5.1.4), and decision 15's bound on how long a spent token works — the receipt's `receipt_idle_ttl` and `receipt_max_age` act only on exchanges the device sends | IOS-XE; then every HTTP API transport | open — added 2026-09-23. IOS-XE RESTCONF answered a repeat of an already-spent token, 3s later, with `200 OK` and **zero** TACACS+ traffic (`tests/lab/results/L1-restconf-cisco_iosxe.md`), so a revocation in port49 cannot reach that repeat. **Measured 2026-09-24 on IOS-XE** (`tests/lab/results/L20-cisco_iosxe.md`): the cache is per credential (username and password), not per username or client address; a wrong password inside it goes to port49 and is refused; it lasts about 10s fixed from the authentication that filled it; and a cached credential is not re-checked, even with port49 answering every authentication ERROR. Open: every other HTTP API transport, so the row stays open; see below |
+| **L22** | What each per-command platform's device lets a session run at each level port49 renders — with port49 permitting every command, which of `clear counters`, `clear ip bgp *` and `configure terminal` it runs, refuses in its own parser, or sends port49 — and which level or role it reports, for the exact reply each built-in adapter sends; and, with port49 stopped under an open session on a command method list ending in `local`, whether operator's reply can change the configuration where admin's can. | Decision 25; the adapters' `privilege`, `unreachable` and `fallback` (§8); the dead-rule and fallback-exposure reports (§12) | EOS, NX-OS, IOS-XE | open — added by plan 5. Measured by hand 2026-09-24 with single attributes (`tests/lab/results/ceiling-arista_eos.md`, `ceiling-cisco_nxos.md`, `ceiling-cisco_iosxe.md`): level 1 refuses all three in the parser on vEOS and IOS-XE; IOS-XE level 7 with `privilege exec level 7 clear counters` runs `clear counters` alone; at 15 on vEOS and under every N9Kv role, all three reach port49. The adapters' exact replies and the fallback are plan 5a's Task 17 (`tests/lab/results/L22-*.md`) |
 | **L21** | Whether each platform sends the command words the operator typed (`sh run`) or the resolved ones (`show running-config`) on a per-command authorization request, and on the accounting record for it. | `expands_abbreviations` per platform (§3 rule 4, §8): where it is `false` a deny's word matches its own abbreviations, which over-denies, and where it is wrongly `true` an abbreviation slips past a deny | EOS, NX-OS, IOS-XE | closed — measured 2026-09-24; `tests/lab/results/L21-arista_eos.md`, `L21-cisco_nxos.md`, `L21-cisco_iosxe.md`. All three images send the **resolved** words, on the request and on the accounting record, over interactive SSH: `sh ver` arrives as `cmd=show cmd-arg=version`, and `sh clock` was denied by a `show clock` deny on all three. Interface names differ: IOS-XE splits `Gi1` into `GigabitEthernet`, `1`; vEOS and the N9Kv join it (`Ethernet1`, `Ethernet1/1`). Other transports and releases are outside what was measured; see below |
 
 **What has been measured so far, per row.** The measurements exist and the notes are in the
````

- [ ] **Step 2: Check it landed**

Run: `grep -c 'L22' docs/design/2026-08-23-policy-engine-spec.md && grep -n '^\*\*25\.' docs/design/2026-08-23-policy-engine-spec.md`
Expected: `3` (the new row, decision 25's "provisional on L22", and §8's `L22-<platform>.md`), then one line,
`**25. A level renders as a device level and a device role, …`.

- [ ] **Step 3: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: plan 5a's spec: adapters as files, redaction, decision 25, L22

The lab contradicts spec §6 on EOS roles: vEOS ignores shell:roles* and
refuses the session on shell:roles=, and applies the bare roles= under
either flag (tests/lab/results/L16-arista_eos.md, 2026-09-22). The
paragraph said shell:roles for EOS; it is corrected.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: The built-in adapters are files

**Files:**
- Create: `platforms/platforms.go`, `platforms/1.0.0/arista_eos.yaml`, `cisco_nxos.yaml`,
  `cisco_iosxe.yaml`, `juniper_junos.yaml`
- Create: `internal/platform/adapter.go`, `internal/platform/set.go`
- Modify: `internal/platform/dialect.go` (the Go literal and its citation comment go; `DialectFor`,
  `Dialects` and `PrivilegeAttributeNames` read the sets)
- Test: `internal/platform/adapter_test.go`

**Interfaces:**
- Produces:
  - package `platforms`: `var FS embed.FS` — `<version>/<platform>.yaml`.
  - `type Spec struct` — one pointer field per adapter key, yaml snake_case; nil is "not set".
  - `func ParseSpecs(raw []byte) (map[string]Spec, error)` — strict, one document, a `platforms:` key.
  - `func (s Spec) Over(base Dialect) Dialect` — every set field replaces base's; shares nothing.
  - `func Validate(name string, d Dialect) error` — errors name `platforms.<name>.<key>`; it
    refuses listing inert `priv-lvl` or an attribute one of the adapter's levels renders.
  - `const DefaultSet = "1.0.0"`; `func LoadSets(fsys fs.FS) (map[string]map[string]Dialect, error)`;
    `func Sets() []string`; `func Set(version string) (map[string]Dialect, bool)` (a copy).
  - Unchanged signatures: `DialectFor`, `Dialects`, `PrivilegeAttributeNames`, and every `Dialect`
    method.

Behaviour-preserving: the four files say exactly what plan 4's literal said, and
`TestTheDefaultSetIsTheTablePlan4Shipped` (renamed `TestTheDefaultSetValueForValue` in Task 3)
pins it value for value. Each file is laid over the generic adapter, so a minimal adapter — spec
§8's four-line time server — loads. `TestEveryReleasedSetIsFrozen` holds every released set
against its own table, keyed by version, so the day a later set becomes the default 1.0.0 is
still held; `TestTheGenericAdapterIsFrozen` holds the generic adapter and plan 3's ceiling table
under it (pre-flight S3). Task 8 adds `EnableUsername` to both.

- [ ] **Step 1: Write the failing test**

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
new file mode 100644
index 0000000..d8f7851
--- /dev/null
+++ b/internal/platform/adapter_test.go
@@ -0,0 +1,220 @@
+package platform
+
+import (
+	"reflect"
+	"strings"
+	"testing"
+	"testing/fstest"
+
+	"github.com/blanketfish/port49/platforms"
+)
+
+// shipped is the table plan 4 compiled into the binary, value for value.
+// Moving it into platforms/1.0.0/ must not change what any device is told.
+var shipped = map[string]Dialect{
+	"arista_eos": {
+		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
+		Supports: []string{"session", "commands"},
+		EntityClasses: map[string][]string{
+			"management": {`^Management[0-9]+$`},
+			"loopback":   {`^Loopback[0-9]+$`},
+			"physical":   {`^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$`},
+		},
+		Levels:              map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=15"}, "admin": {"priv-lvl=15"}},
+		PrivilegeAttributes: []string{"priv-lvl", "roles"},
+		InertAttributes:     []string{"home-directory"},
+	},
+	"cisco_nxos": {
+		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true,
+		Supports:            []string{"session", "commands"},
+		EntityClasses:       map[string][]string{"management": {`^mgmt[0-9]+$`}},
+		CeilingLevels:       map[string]uint8{"readonly": 1, "operator": 15, "admin": 15},
+		PrivilegeAttributes: []string{"priv-lvl", "shell:roles", "cisco-av-pair"},
+		InertAttributes:     []string{"home-directory"},
+	},
+	"cisco_iosxe": {
+		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true, SplitsInterfaceNames: true,
+		Supports:            []string{"session", "commands"},
+		PrivilegeAttributes: []string{"priv-lvl"},
+		InertAttributes:     []string{"home-directory"},
+	},
+	"juniper_junos": {
+		PipeToken: "|", StripCR: true,
+		Supports:      []string{"session"},
+		EntityClasses: map[string][]string{"management": {`^(fxp0|em0)$`}},
+		PrivilegeAttributes: []string{"local-user-name", "user-permissions", "allow-commands", "deny-commands",
+			"allow-configuration", "deny-configuration", "allow-commands-regexps", "deny-commands-regexps",
+			"allow-configuration-regexps", "deny-configuration-regexps"},
+		InertAttributes: []string{"home-directory"},
+	},
+}
+
+func TestTheDefaultSetIsTheTablePlan4Shipped(t *testing.T) {
+	got := Dialects()
+	if len(got) != len(shipped) {
+		t.Fatalf("%d platforms, want %d", len(got), len(shipped))
+	}
+	for name, want := range shipped {
+		if !reflect.DeepEqual(got[name], want) {
+			t.Errorf("%s:\n got %+v\nwant %+v", name, got[name], want)
+		}
+	}
+}
+
+// released is every released platform set, value for value. A released set is
+// never edited (spec §8, "the platform set is pinned"): when a later set
+// becomes the default, 1.0.0's entry stays here as it is and the new set is
+// added beside it, so a binary upgrade cannot change what a pinned policy
+// renders without this test failing.
+var released = map[string]map[string]Dialect{"1.0.0": shipped}
+
+func TestEveryReleasedSetIsFrozen(t *testing.T) {
+	for version, want := range released {
+		got, ok := Set(version)
+		if !ok || len(got) != len(want) {
+			t.Fatalf("set %s: %d platforms, want %d", version, len(got), len(want))
+		}
+		for name := range want {
+			if !reflect.DeepEqual(got[name], want[name]) {
+				t.Errorf("set %s, %s:\n got %+v\nwant %+v", version, name, got[name], want[name])
+			}
+		}
+	}
+}
+
+// The generic adapter is under every released set: each file is laid over it,
+// and a `replace:` block or a platform no set ships starts from it. So is
+// plan 3's ceiling table, for a platform that renders nothing. A change to
+// either would change a pinned policy's rendering; a change ships as a new
+// set instead (spec §8).
+func TestTheGenericAdapterIsFrozen(t *testing.T) {
+	want := Dialect{PipeToken: "|", StripCR: true, Supports: []string{"session"},
+		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"}}
+	if !reflect.DeepEqual(generic, want) {
+		t.Errorf("generic:\n got %+v\nwant %+v", generic, want)
+	}
+	if !reflect.DeepEqual(ceilingLevels, map[string]uint8{"readonly": 1, "admin": 15}) {
+		t.Errorf("ceilingLevels: %v", ceilingLevels)
+	}
+}
+
+// Every embedded set loads, and the default is one of them: the binary
+// panics at start otherwise, so this is where a bad file is caught.
+func TestEmbeddedSetsLoad(t *testing.T) {
+	all, err := LoadSets(platforms.FS)
+	if err != nil {
+		t.Fatal(err)
+	}
+	if _, ok := all[DefaultSet]; !ok {
+		t.Fatalf("no set %s in %v", DefaultSet, Sets())
+	}
+	if !reflect.DeepEqual(Sets(), []string{"1.0.0"}) {
+		t.Fatalf("sets: %v", Sets())
+	}
+	set, ok := Set(DefaultSet)
+	if !ok {
+		t.Fatal("Set(DefaultSet)")
+	}
+	set["arista_eos"].EntityClasses["management"][0] = "changed"
+	if again, _ := Set(DefaultSet); again["arista_eos"].EntityClasses["management"][0] == "changed" {
+		t.Fatal("Set must return a copy")
+	}
+	if _, ok := Set("0.9.0"); ok {
+		t.Fatal("no set 0.9.0 ships")
+	}
+}
+
+// A set is a directory named by its version, and each file defines the
+// platform it is named for and nothing else.
+func TestLoadSetsRefusesAMisfiledAdapter(t *testing.T) {
+	good := "platforms:\n  meinberg_lantime:\n    supports: [session]\n"
+	for name, fsys := range map[string]fstest.MapFS{
+		"a set not named by a version": {"latest/meinberg_lantime.yaml": {Data: []byte(good)}},
+		"a file named for another":     {"1.0.0/lantime.yaml": {Data: []byte(good)}},
+		"a file defining two": {"1.0.0/meinberg_lantime.yaml": {Data: []byte(good +
+			"  other:\n    supports: [session]\n")}},
+		"an invalid adapter": {"1.0.0/meinberg_lantime.yaml": {Data: []byte(
+			"platforms:\n  meinberg_lantime:\n    supports: [telnet]\n")}},
+	} {
+		if _, err := LoadSets(fsys); err == nil {
+			t.Errorf("%s: loaded", name)
+		}
+	}
+	all, err := LoadSets(fstest.MapFS{"1.0.0/meinberg_lantime.yaml": {Data: []byte(good)}})
+	if err != nil || !reflect.DeepEqual(all["1.0.0"]["meinberg_lantime"].Supports, []string{"session"}) {
+		t.Fatalf("%v %+v", err, all)
+	}
+}
+
+// The schema is closed: a key it does not know is refused, not ignored, and
+// a file is one document.
+func TestParseSpecsIsStrict(t *testing.T) {
+	for name, raw := range map[string]string{
+		"an unknown key":   "platforms:\n  x:\n    supports: [session]\n    privelege: {}\n",
+		"two documents":    "platforms:\n  x:\n    supports: [session]\n---\nplatforms: {}\n",
+		"no platforms key": "x:\n  supports: [session]\n",
+		"a level too high": "platforms:\n  x:\n    ceiling_levels: {admin: 300}\n",
+	} {
+		if _, err := ParseSpecs([]byte(raw)); err == nil {
+			t.Errorf("%s: parsed", name)
+		}
+	}
+}
+
+// Over replaces what a block sets, whole, and keeps the rest.
+func TestOverReplacesOnlyWhatIsSet(t *testing.T) {
+	specs, err := ParseSpecs([]byte("platforms:\n  arista_eos:\n    entity_classes:\n      uplink: ['^Ethernet49$']\n"))
+	if err != nil {
+		t.Fatal(err)
+	}
+	base, _ := DialectFor("arista_eos")
+	d := specs["arista_eos"].Over(base)
+	if !reflect.DeepEqual(d.EntityClasses, map[string][]string{"uplink": {`^Ethernet49$`}}) {
+		t.Fatalf("classes: %v", d.EntityClasses)
+	}
+	if !reflect.DeepEqual(d.Levels, base.Levels) || !d.ExpandsAbbreviations {
+		t.Fatalf("the rest is the base's: %+v", d)
+	}
+	d.Levels["admin"][0] = "changed"
+	if again, _ := DialectFor("arista_eos"); again.Levels["admin"][0] == "changed" {
+		t.Fatal("Over must not share the base's maps")
+	}
+}
+
+// Validate refuses what a device would get wrong silently or loudly.
+func TestValidateNamesTheField(t *testing.T) {
+	ok := Dialect{PipeToken: "|", Supports: []string{"session"}}
+	for field, d := range map[string]Dialect{
+		"supports":                  {PipeToken: "|"},
+		"supports: \"telnet\"":      {PipeToken: "|", Supports: []string{"telnet"}},
+		"must include session":      {PipeToken: "|", Supports: []string{"commands"}},
+		"privilege.admin":           with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"priv-lvl"}} }),
+		"takes no placeholder":      with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"x*{username}"}} }),
+		"is sent twice":             with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"a=1", "a*2"}} }),
+		"ceiling_levels.admin":      with(ok, func(d *Dialect) { d.CeilingLevels = map[string]uint8{"admin": 16} }),
+		"not a class name":          with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"Mgmt": {"x"}} }),
+		"matches nothing":           with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"mgmt": {}} }),
+		"does not compile":          with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"mgmt": {"("}} }),
+		"pipe_token":                with(ok, func(d *Dialect) { d.PipeToken = "" }),
+		"not an attribute name":     with(ok, func(d *Dialect) { d.InertAttributes = []string{"a=b"} }),
+		"also in privilege_attribu": with(ok, func(d *Dialect) { d.PrivilegeAttributes, d.InertAttributes = []string{"a"}, []string{"a"} }),
+		"a level renders it": with(ok, func(d *Dialect) {
+			d.Levels, d.InertAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"roles"}
+		}),
+		"inert_attributes: priv-lvl": with(ok, func(d *Dialect) { d.InertAttributes = []string{"priv-lvl"} }),
+	} {
+		err := Validate("x", d)
+		if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "platforms.x.") {
+			t.Errorf("%s: %v", field, err)
+		}
+	}
+	if err := Validate("x", ok); err != nil {
+		t.Fatal(err)
+	}
+}
+
+func with(d Dialect, edit func(*Dialect)) Dialect {
+	d = d.clone()
+	edit(&d)
+	return d
+}
````

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/platform/`
Expected: FAIL, `[setup failed]` — package `github.com/blanketfish/port49/platforms` does not exist,
and `LoadSets`, `ParseSpecs`, `Validate` are undefined.

- [ ] **Step 3: Write the files and the loader**

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
new file mode 100644
index 0000000..8767b09
--- /dev/null
+++ b/internal/platform/adapter.go
@@ -0,0 +1,208 @@
+package platform
+
+import (
+	"bytes"
+	"errors"
+	"fmt"
+	"io"
+	"regexp"
+	"slices"
+	"strings"
+
+	"gopkg.in/yaml.v3"
+
+	"github.com/blanketfish/port49/internal/engine"
+)
+
+// Spec is one platform block as a file writes it (spec §8): a built-in adapter
+// under platforms/<set>/. A nil field is one the block does not set, and Over
+// lays the set fields over a base, so a block that sets one key inherits every
+// other.
+type Spec struct {
+	Supports             *[]string            `yaml:"supports"`
+	Privilege            *map[string][]string `yaml:"privilege"`
+	CeilingLevels        *map[string]uint8    `yaml:"ceiling_levels"`
+	EntityClasses        *map[string][]string `yaml:"entity_classes"`
+	ExpandsAbbreviations *bool                `yaml:"expands_abbreviations"`
+	SplitsInterfaceNames *bool                `yaml:"splits_interface_names"`
+	PipeToken            *string              `yaml:"pipe_token"`
+	PipeAuthorized       *bool                `yaml:"pipe_authorized"`
+	StripCR              *bool                `yaml:"strip_cr"`
+	ShowsServerMsg       *bool                `yaml:"shows_server_msg"`
+	PrivilegeAttributes  *[]string            `yaml:"privilege_attributes"`
+	InertAttributes      *[]string            `yaml:"inert_attributes"`
+}
+
+// ParseSpecs reads an adapter file: one YAML document whose one key is
+// `platforms`, a map of platform name to Spec. A key the schema does not know
+// is refused, never ignored: an ignored key is an adapter that reads one way
+// and renders another.
+func ParseSpecs(raw []byte) (map[string]Spec, error) {
+	var f struct {
+		Platforms map[string]Spec `yaml:"platforms"`
+	}
+	dec := yaml.NewDecoder(bytes.NewReader(raw))
+	dec.KnownFields(true)
+	if err := dec.Decode(&f); err != nil && err != io.EOF {
+		return nil, err
+	}
+	if err := dec.Decode(&struct{}{}); err != io.EOF {
+		return nil, errors.New("an adapter file is one YAML document; remove the `---` separator and what follows it")
+	}
+	if len(f.Platforms) == 0 {
+		return nil, errors.New("an adapter file defines its platforms under a `platforms:` key, and this one defines none")
+	}
+	return f.Platforms, nil
+}
+
+// Over lays s over base: every field s sets replaces base's, whole, and every
+// field it leaves nil is base's. The result shares nothing with either.
+func (s Spec) Over(base Dialect) Dialect {
+	d := base.clone()
+	if s.Supports != nil {
+		d.Supports = slices.Clone(*s.Supports)
+	}
+	if s.Privilege != nil {
+		d.Levels = cloneLists(*s.Privilege)
+	}
+	if s.CeilingLevels != nil {
+		d.CeilingLevels = make(map[string]uint8, len(*s.CeilingLevels))
+		for k, v := range *s.CeilingLevels {
+			d.CeilingLevels[k] = v
+		}
+	}
+	if s.EntityClasses != nil {
+		d.EntityClasses = cloneLists(*s.EntityClasses)
+	}
+	if s.ExpandsAbbreviations != nil {
+		d.ExpandsAbbreviations = *s.ExpandsAbbreviations
+	}
+	if s.SplitsInterfaceNames != nil {
+		d.SplitsInterfaceNames = *s.SplitsInterfaceNames
+	}
+	if s.PipeToken != nil {
+		d.PipeToken = *s.PipeToken
+	}
+	if s.PipeAuthorized != nil {
+		d.PipeAuthorized = *s.PipeAuthorized
+	}
+	if s.StripCR != nil {
+		d.StripCR = *s.StripCR
+	}
+	if s.ShowsServerMsg != nil {
+		d.ShowsServerMsg = *s.ShowsServerMsg
+	}
+	if s.PrivilegeAttributes != nil {
+		d.PrivilegeAttributes = slices.Clone(*s.PrivilegeAttributes)
+	}
+	if s.InertAttributes != nil {
+		d.InertAttributes = slices.Clone(*s.InertAttributes)
+	}
+	return d
+}
+
+func cloneLists(m map[string][]string) map[string][]string {
+	out := make(map[string][]string, len(m))
+	for k, v := range m {
+		out[k] = slices.Clone(v)
+	}
+	return out
+}
+
+// capabilities is spec §9's vocabulary for `supports`.
+var capabilities = []string{"session", "commands", "config_commands"}
+
+// className is the shape of an entity class name, as a rule writes it after
+// `@` (engine.ParseRule).
+var className = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
+
+// Validate is the structural validation spec §8 requires of every adapter,
+// built-in or not: port49 cannot check what an attribute means, so it checks
+// everything else. Each error names the field.
+func Validate(name string, d Dialect) error {
+	field := func(f string) string { return "platforms." + name + "." + f }
+	if len(d.Supports) == 0 {
+		return fmt.Errorf("%s is required: which of %s the platform authorizes (spec §9)", field("supports"),
+			strings.Join(capabilities, ", "))
+	}
+	for _, c := range d.Supports {
+		if !slices.Contains(capabilities, c) {
+			return fmt.Errorf("%s: %q is not a capability; the capabilities are %s", field("supports"), c,
+				strings.Join(capabilities, ", "))
+		}
+	}
+	if !slices.Contains(d.Supports, "session") {
+		return fmt.Errorf("%s must include session: every platform port49 serves authorizes its sessions",
+			field("supports"))
+	}
+	for _, level := range sortedKeys(d.Levels) {
+		seen := map[string]bool{}
+		for _, a := range d.Levels[level] {
+			if err := engine.CheckAttribute(a); err != nil {
+				return fmt.Errorf("%s: %w", field("privilege."+level), err)
+			}
+			// A level's rendering is the level: a placeholder in it would let a
+			// principal's name decide what the device is told (spec §6).
+			if slices.ContainsFunc(engine.Placeholders, func(p string) bool { return strings.Contains(a, p) }) {
+				return fmt.Errorf("%s: %s: a level's rendering takes no placeholder (spec §6)", field("privilege."+level), a)
+			}
+			n := engine.AttributeName(a)
+			if seen[n] {
+				// A device keeps the first of two and drops the second, silently
+				// (spec §8, "Generator constraints").
+				return fmt.Errorf("%s: %s is sent twice; send it once", field("privilege."+level), n)
+			}
+			seen[n] = true
+		}
+	}
+	for _, level := range sortedKeys(d.CeilingLevels) {
+		if n := d.CeilingLevels[level]; n > 15 {
+			return fmt.Errorf("%s: %d is not a privilege level; they run 0 to 15", field("ceiling_levels."+level), n)
+		}
+	}
+	for _, class := range sortedKeys(d.EntityClasses) {
+		if !className.MatchString(class) {
+			return fmt.Errorf("%s: %q is not a class name: lower case, digits and _, starting with a letter",
+				field("entity_classes"), class)
+		}
+		if len(d.EntityClasses[class]) == 0 {
+			return fmt.Errorf("%s is empty, which matches nothing; remove the class instead", field("entity_classes."+class))
+		}
+		for _, p := range d.EntityClasses[class] {
+			if _, err := regexp.Compile(p); err != nil {
+				return fmt.Errorf("%s: %q does not compile under RE2: %w", field("entity_classes."+class), p, err)
+			}
+		}
+	}
+	if d.PipeToken == "" || strings.ContainsAny(d.PipeToken, " \t") {
+		return fmt.Errorf("%s is %q: one argument with no whitespace, e.g. \"|\"", field("pipe_token"), d.PipeToken)
+	}
+	for _, list := range []struct {
+		name  string
+		names []string
+	}{{"privilege_attributes", d.PrivilegeAttributes}, {"inert_attributes", d.InertAttributes}} {
+		for _, n := range list.names {
+			if n == "" || strings.ContainsAny(n, "=* \t") {
+				return fmt.Errorf("%s: %q is not an attribute name", field(list.name), n)
+			}
+		}
+	}
+	for _, n := range d.InertAttributes {
+		if slices.Contains(d.PrivilegeAttributes, n) {
+			return fmt.Errorf("%s: %s is also in privilege_attributes; an attribute carries privilege or it does not",
+				field("inert_attributes"), n)
+		}
+		// What a level renders is the level (spec §6): listed inert, every
+		// later change to it would pass the diff ungated.
+		rendered := n == "priv-lvl"
+		for _, level := range sortedKeys(d.Levels) {
+			rendered = rendered || slices.ContainsFunc(d.Levels[level], func(a string) bool {
+				return engine.AttributeName(a) == n
+			})
+		}
+		if rendered {
+			return fmt.Errorf("%s: %s: a level renders it, so it carries privilege", field("inert_attributes"), n)
+		}
+	}
+	return nil
+}
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index bba4bf5..6681064 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -14,10 +14,8 @@ import (
 // the broker compiles it into the blob, so a daemon and a broker cannot
 // disagree about a rule.
 //
-// BORROWED AHEAD from plan 5, which builds the adapters in full — user
-// overrides and layering, the pinned platform set, `redact`, projection — and
-// replaces this table. Every value here is either measured and cited, or
-// marked unmeasured and chosen in the direction that fails closed.
+// The built-in dialects are files, platforms/<set>/<platform>.yaml (spec §8,
+// "Knowing what is shipped"), parsed by LoadSets into this type.
 type Dialect struct {
 	// PipeToken is the argument that separates a command from its output
 	// modifiers (spec §3 rule 2). Only a whole argument equal to it splits.
@@ -76,111 +74,12 @@ type Dialect struct {
 	InertAttributes []string
 }
 
-// dialects are the built-in platforms. Each value is cited or marked
-// unmeasured:
-//
-//   - PipeAuthorized is false on every platform with a command path, and that
-//     is measured: typing `show clock | include AAAA…` sent port49 `show clock`
-//     alone on vEOS 4.31.2F, NX-OS 10.4(2)F and IOS-XE 17.13.01a
-//     (tests/lab/results/L2-arista_eos.md, L2-cisco_nxos.md,
-//     L2-cisco_iosxe.md). Whether any other modifier reaches port49 anywhere
-//     is unmeasured. Junos never authorizes a command.
-//   - ShowsServerMsg: a 61-character server_msg on a denied command was
-//     displayed in full on vEOS 4.31.2F and IOS-XE 17.13.01a and not at all on
-//     NX-OS 10.4(2)F, which printed its own error (tests/lab/results/
-//     L2-arista_eos.md, L2-cisco_iosxe.md, L2-cisco_nxos.md). Junos makes no
-//     command request to carry one and is unmeasured, so false.
-//   - StripCR: every command authorization measured ends `cmd-arg=<cr>`
-//     (L10-arista_eos.md, L10-cisco_nxos.md, L10-cisco_iosxe.md).
-//   - ExpandsAbbreviations is true on EOS, NX-OS and IOS-XE, set from L21:
-//     typed `sh ver`, `sho run` and `sh clock` arrived as the full keywords on
-//     the authorization request and the accounting record on vEOS 4.31.2F,
-//     NX-OS 10.4(2)F and IOS-XE 17.13.01a, and `sh clock` was denied by a
-//     `show clock` deny on all three (tests/lab/results/L21-arista_eos.md,
-//     L21-cisco_nxos.md, L21-cisco_iosxe.md). That was interactive SSH; eAPI,
-//     NX-API and NETCONF are unmeasured. Junos sends no command to expand and
-//     is unmeasured, so false, the direction that fails closed.
-//   - SplitsInterfaceNames is true on IOS-XE alone: a typed `int Gi1` arrived
-//     as `cmd-arg=GigabitEthernet cmd-arg=1` on IOS-XE 17.13.01a, while vEOS
-//     and the N9Kv sent one argument, `Ethernet1` and `Ethernet1/1`
-//     (tests/lab/results/L21-cisco_iosxe.md, L21-arista_eos.md,
-//     L21-cisco_nxos.md). Other interface types and subinterfaces are
-//     unmeasured; an index is read as digits and `/ . :`.
-//   - Supports: EOS, NX-OS and IOS-XE send per-command authorization (L1, L10);
-//     Junos sends none, in 26 sessions on two images (L18; decision 21).
-//     Config-command authorization is unmeasured, so no platform claims it.
-//   - EntityClasses: interface NAMES, not device behaviour. `management` is the
-//     interface the lab reaches each image on (fxp0 and mgmt0 in
-//     tests/lab/configs/vjunos-startup.conf and nxos-startup.cfg; Management1
-//     is spec §8's EOS example, and `em0` spec §8's Junos one, which no lab
-//     image uses); `loopback` and `physical` are spec §8's EOS example. IOS-XE defines none: its lab management interface is
-//     GigabitEthernet1, which is a physical port by name.
-//   - Levels: arista_eos renders `priv-lvl` for readonly and admin, applied by
-//     vEOS on every lab run since 2026-09-20 (L16-arista_eos.md). `operator`
-//     renders as admin does, on the owner's ruling of 2026-09-24 (spec §6,
-//     decision 23): at level 15 vEOS ran `clear counters`, `clear ip bgp *`
-//     and `configure` for a `network-operator` session, and at level 1 refused
-//     even `clear counters` (ceiling-arista_eos.md), so no level fences an
-//     operator there and port49's command rules are the fence. Every other
-//     platform renders nothing, as in plan 3; plan 5 fills them.
-//   - CeilingLevels: cisco_nxos numbers `operator` 15, admin's number, on the
-//     same ruling: every N9Kv role ran all three commands and
-//     `network-operator` changed configuration (ceiling-cisco_nxos.md).
-//     IOS-XE, whose level 7 can carry the operator rung (ceiling-cisco_iosxe.md),
-//     keeps plan 3's table until plan 5 renders it.
-//   - PrivilegeAttributes: `priv-lvl` sets the level on EOS, NX-OS and IOS-XE
-//     (L16, ceiling-*.md); EOS applies a bare `roles=<name>` and NX-OS
-//     `shell:roles`, bare or inside `cisco-av-pair` (L16-arista_eos.md,
-//     L16-cisco_nxos.md); Junos applies `local-user-name` and decision 22
-//     names `user-permissions`, measured inert on these releases but a
-//     permission carrier by design (L18-juniper_*.md), and its command and
-//     configuration regexes, `allow-commands`, `deny-commands`,
-//     `allow-configuration`, `deny-configuration` and their `-regexps` forms,
-//     vendor-documented and unmeasured (L18; decision 22). The generic
-//     adapter lists `priv-lvl`, what an unknown TACACS+ device most likely
-//     reads.
-//   - InertAttributes: `home-directory` everywhere, spec §6's motivating case
-//     for a placeholder; unmeasured on any lab image.
-var dialects = map[string]Dialect{
-	"arista_eos": {
-		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
-		Supports: []string{"session", "commands"},
-		EntityClasses: map[string][]string{
-			"management": {`^Management[0-9]+$`},
-			"loopback":   {`^Loopback[0-9]+$`},
-			"physical":   {`^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$`},
-		},
-		Levels:              map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=15"}, "admin": {"priv-lvl=15"}},
-		PrivilegeAttributes: []string{"priv-lvl", "roles"},
-		InertAttributes:     inert,
-	},
-	"cisco_nxos": {
-		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: false,
-		Supports:            []string{"session", "commands"},
-		EntityClasses:       map[string][]string{"management": {`^mgmt[0-9]+$`}},
-		CeilingLevels:       map[string]uint8{"readonly": 1, "operator": 15, "admin": 15},
-		PrivilegeAttributes: []string{"priv-lvl", "shell:roles", "cisco-av-pair"},
-		InertAttributes:     inert,
-	},
-	"cisco_iosxe": {
-		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
-		SplitsInterfaceNames: true,
-		Supports:             []string{"session", "commands"},
-		PrivilegeAttributes:  []string{"priv-lvl"},
-		InertAttributes:      inert,
-	},
-	"juniper_junos": {
-		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: false,
-		Supports:      []string{"session"},
-		EntityClasses: map[string][]string{"management": {`^(fxp0|em0)$`}},
-		PrivilegeAttributes: []string{"local-user-name", "user-permissions", "allow-commands", "deny-commands",
-			"allow-configuration", "deny-configuration", "allow-commands-regexps", "deny-commands-regexps",
-			"allow-configuration-regexps", "deny-configuration-regexps"},
-		InertAttributes: inert,
-	},
-}
+// builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
+// every value is cited to the lab note that measured it or marked unmeasured
+// and chosen in the direction that fails closed.
+func builtin() map[string]Dialect { return sets[DefaultSet] }
 
-// inert is every shipped adapter's InertAttributes.
+// inert is the generic adapter's InertAttributes, as every shipped adapter's.
 var inert = []string{"home-directory"}
 
 // generic is the dialect of a platform port49 ships no adapter for (spec §8,
@@ -202,7 +101,7 @@ var ceilingLevels = map[string]uint8{"readonly": 1, "admin": 15}
 // platform gets the generic dialect. The maps are copies: a caller cannot edit
 // the table through them.
 func DialectFor(name string) (Dialect, bool) {
-	d, ok := dialects[name]
+	d, ok := builtin()[name]
 	if !ok {
 		d = generic
 	}
@@ -211,8 +110,8 @@ func DialectFor(name string) (Dialect, bool) {
 
 // Dialects is the whole built-in table, copied.
 func Dialects() map[string]Dialect {
-	out := make(map[string]Dialect, len(dialects))
-	for name, d := range dialects {
+	out := make(map[string]Dialect, len(builtin()))
+	for name, d := range builtin() {
 		out[name] = d.clone()
 	}
 	return out
@@ -246,15 +145,17 @@ func (d Dialect) clone() Dialect {
 // this platform: every name but one measured inert (InertAttributes).
 func (d Dialect) BearsPrivilege(name string) bool { return !slices.Contains(d.InertAttributes, name) }
 
-// PrivilegeAttributeNames is every built-in platform's PrivilegeAttributes,
-// sorted: the names no attribute value may put a placeholder in, whatever
-// platform key it is written under (spec §6).
+// PrivilegeAttributeNames is the PrivilegeAttributes of every platform in
+// every built-in set, sorted: the names no attribute value may put a
+// placeholder in, whatever platform key it is written under (spec §6).
 func PrivilegeAttributeNames() []string {
 	out := slices.Clone(generic.PrivilegeAttributes)
-	for _, d := range dialects {
-		for _, n := range d.PrivilegeAttributes {
-			if !slices.Contains(out, n) {
-				out = append(out, n)
+	for _, set := range sets {
+		for _, d := range set {
+			for _, n := range d.PrivilegeAttributes {
+				if !slices.Contains(out, n) {
+					out = append(out, n)
+				}
 			}
 		}
 	}
````

<!-- patch: internal/platform/set.go -->
````diff
diff --git a/internal/platform/set.go b/internal/platform/set.go
new file mode 100644
index 0000000..2225ed2
--- /dev/null
+++ b/internal/platform/set.go
@@ -0,0 +1,137 @@
+package platform
+
+import (
+	"fmt"
+	"io/fs"
+	"path"
+	"slices"
+	"strconv"
+	"strings"
+
+	"github.com/blanketfish/port49/platforms"
+)
+
+// DefaultSet is the platform set this build renders with: the one a policy
+// that pins none gets (spec §8, "the platform set is pinned").
+const DefaultSet = "1.0.0"
+
+// sets is every built-in platform set, by version, parsed and validated once.
+// An embedded file that does not load is a build defect, never an operator's
+// error, so it panics at start rather than degrading; TestEmbeddedSetsLoad is
+// what keeps that from reaching a binary.
+var sets = mustLoadSets(platforms.FS)
+
+func mustLoadSets(fsys fs.FS) map[string]map[string]Dialect {
+	out, err := LoadSets(fsys)
+	if err != nil {
+		panic("platform: the built-in adapters do not load: " + err.Error())
+	}
+	if _, ok := out[DefaultSet]; !ok {
+		panic("platform: no built-in set " + DefaultSet)
+	}
+	return out
+}
+
+// LoadSets reads every set in fsys: a directory per version, a file per
+// platform named for it, each defining that platform alone. Each file is laid
+// over the generic adapter, so a key it leaves out is what an unmodeled device
+// gets (spec §8, "Unknown platforms"), and every adapter is validated as a
+// user's would be ("User-editable, day one").
+func LoadSets(fsys fs.FS) (map[string]map[string]Dialect, error) {
+	dirs, err := fs.ReadDir(fsys, ".")
+	if err != nil {
+		return nil, err
+	}
+	out := map[string]map[string]Dialect{}
+	for _, dir := range dirs {
+		if !dir.IsDir() {
+			continue
+		}
+		version := dir.Name()
+		if _, ok := parseVersion(version); !ok {
+			return nil, fmt.Errorf("platform set %q: a set is named by its version, e.g. 1.0.0", version)
+		}
+		files, err := fs.ReadDir(fsys, version)
+		if err != nil {
+			return nil, err
+		}
+		set := map[string]Dialect{}
+		for _, f := range files {
+			if f.IsDir() || path.Ext(f.Name()) != ".yaml" {
+				continue
+			}
+			raw, err := fs.ReadFile(fsys, path.Join(version, f.Name()))
+			if err != nil {
+				return nil, err
+			}
+			specs, err := ParseSpecs(raw)
+			if err != nil {
+				return nil, fmt.Errorf("%s/%s: %w", version, f.Name(), err)
+			}
+			want := strings.TrimSuffix(f.Name(), ".yaml")
+			if _, ok := specs[want]; !ok || len(specs) != 1 {
+				return nil, fmt.Errorf("%s/%s: the file defines %s and nothing else", version, f.Name(), want)
+			}
+			d := specs[want].Over(generic)
+			if err := Validate(want, d); err != nil {
+				return nil, fmt.Errorf("%s/%s: %w", version, f.Name(), err)
+			}
+			set[want] = d
+		}
+		out[version] = set
+	}
+	return out, nil
+}
+
+// Sets lists the built-in set versions, oldest first.
+func Sets() []string {
+	out := make([]string, 0, len(sets))
+	for v := range sets {
+		out = append(out, v)
+	}
+	slices.SortFunc(out, compareVersions)
+	return out
+}
+
+// Set returns a built-in set by version, copied, and whether it exists.
+func Set(version string) (map[string]Dialect, bool) {
+	set, ok := sets[version]
+	if !ok {
+		return nil, false
+	}
+	out := make(map[string]Dialect, len(set))
+	for name, d := range set {
+		out[name] = d.clone()
+	}
+	return out, true
+}
+
+// parseVersion reads a set version: dotted non-negative integers.
+func parseVersion(v string) ([]int, bool) {
+	var out []int
+	for _, part := range strings.Split(v, ".") {
+		n, err := strconv.Atoi(part)
+		if err != nil || n < 0 || strconv.Itoa(n) != part {
+			return nil, false
+		}
+		out = append(out, n)
+	}
+	return out, len(out) > 0
+}
+
+func compareVersions(a, b string) int {
+	x, _ := parseVersion(a)
+	y, _ := parseVersion(b)
+	return slices.Compare(x, y)
+}
+
+// sortedKeys is a map's keys in order, so a map with several faults reports
+// the same one on every load.
+func sortedKeys[V any](m map[string]V) []string {
+	keys := make([]string, 0, len(m))
+	for k := range m {
+		keys = append(keys, k)
+	}
+	slices.Sort(keys)
+	return keys
+}
````

<!-- patch: platforms/1.0.0/arista_eos.yaml -->
````diff
diff --git a/platforms/1.0.0/arista_eos.yaml b/platforms/1.0.0/arista_eos.yaml
new file mode 100644
index 0000000..c6a3752
--- /dev/null
+++ b/platforms/1.0.0/arista_eos.yaml
@@ -0,0 +1,39 @@
+# arista_eos — vEOS-lab 4.31.2F (image tagged 4.32.2F) in the port49 lab.
+# Every value is measured and cited, or marked unmeasured and chosen in the
+# direction that fails closed (spec §8, §15).
+platforms:
+  arista_eos:
+    # Session and per-command authorization (L1, L10). Config-command
+    # authorization is unmeasured, so it is not claimed.
+    supports: [session, commands]
+    # readonly and admin are applied by vEOS on every lab run since 2026-09-20
+    # (tests/lab/results/L16-arista_eos.md). operator renders as admin does
+    # (spec §6, decision 23): at 15 vEOS fenced nothing port49 permitted, and
+    # at 1 it refused even `clear counters` (ceiling-arista_eos.md).
+    privilege:
+      readonly: ["priv-lvl=1"]
+      operator: ["priv-lvl=15"]
+      admin: ["priv-lvl=15"]
+    # Interface names, not device behaviour: spec §8's example.
+    entity_classes:
+      management: ['^Management[0-9]+$']
+      loopback: ['^Loopback[0-9]+$']
+      physical: ['^Ethernet[0-9/.]+$', '^Port-Channel[0-9]+$']
+    # `sh ver` arrived as `show version` over SSH (L21-arista_eos.md); eAPI and
+    # NETCONF are unmeasured.
+    expands_abbreviations: true
+    # `int Et1` arrived as one argument, `Ethernet1` (L21-arista_eos.md).
+    splits_interface_names: false
+    # A typed `show clock | include ...` reached port49 as `show clock` alone
+    # (L2-arista_eos.md, "Truncation length").
+    pipe_token: "|"
+    pipe_authorized: false
+    # Every command authorization ends `cmd-arg=<cr>` (L10-arista_eos.md).
+    strip_cr: true
+    # A 61-character server_msg was displayed in full (L2-arista_eos.md).
+    shows_server_msg: true
+    # `priv-lvl` sets the level and a bare `roles=<name>` the role
+    # (L16-arista_eos.md). home-directory is spec §6's motivating case for a
+    # placeholder, unmeasured on any lab image.
+    privilege_attributes: [priv-lvl, roles]
+    inert_attributes: [home-directory]
````

<!-- patch: platforms/1.0.0/cisco_iosxe.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_iosxe.yaml b/platforms/1.0.0/cisco_iosxe.yaml
new file mode 100644
index 0000000..473dbb8
--- /dev/null
+++ b/platforms/1.0.0/cisco_iosxe.yaml
@@ -0,0 +1,28 @@
+# cisco_iosxe — Catalyst 8000V 17.13.01a in the port49 lab.
+# Every value is measured and cited, or marked unmeasured and chosen in the
+# direction that fails closed (spec §8, §15).
+platforms:
+  cisco_iosxe:
+    # Session and per-command authorization (L1, L10). Config-command
+    # authorization is unmeasured, so it is not claimed.
+    supports: [session, commands]
+    # No level is rendered yet, and no entity class is defined: the lab's
+    # management interface is GigabitEthernet1, a physical port by name.
+    #
+    # `sh ver` arrived as `show version` over SSH (L21-cisco_iosxe.md);
+    # RESTCONF and NETCONF are unmeasured.
+    expands_abbreviations: true
+    # `int Gi1` arrived as `cmd-arg=GigabitEthernet cmd-arg=1`
+    # (L21-cisco_iosxe.md). Other interface types are unmeasured.
+    splits_interface_names: true
+    # A typed `show clock | include ...` reached port49 as `show clock` alone
+    # (L2-cisco_iosxe.md, "Truncation length").
+    pipe_token: "|"
+    pipe_authorized: false
+    # Every command authorization ends `cmd-arg=<cr>` (L10-cisco_iosxe.md).
+    strip_cr: true
+    # A 61-character server_msg was displayed in full (L2-cisco_iosxe.md).
+    shows_server_msg: true
+    # `priv-lvl` sets the level (L16, ceiling-cisco_iosxe.md).
+    privilege_attributes: [priv-lvl]
+    inert_attributes: [home-directory]
````

<!-- patch: platforms/1.0.0/cisco_nxos.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_nxos.yaml b/platforms/1.0.0/cisco_nxos.yaml
new file mode 100644
index 0000000..92603fc
--- /dev/null
+++ b/platforms/1.0.0/cisco_nxos.yaml
@@ -0,0 +1,35 @@
+# cisco_nxos — Nexus 9300v 10.4(2)F in the port49 lab.
+# Every value is measured and cited, or marked unmeasured and chosen in the
+# direction that fails closed (spec §8, §15).
+platforms:
+  cisco_nxos:
+    # Session and per-command authorization (L1, L10). Config-command
+    # authorization is unmeasured, so it is not claimed.
+    supports: [session, commands]
+    # No level is rendered yet. The token's ceiling still needs a number:
+    # operator numbers 15, admin's, on the owner's ruling of 2026-09-24 —
+    # every N9Kv role ran all three disruptive commands and network-operator
+    # changed configuration (ceiling-cisco_nxos.md; spec §6, decision 23).
+    ceiling_levels: {readonly: 1, operator: 15, admin: 15}
+    # mgmt0 is the interface the lab reaches the device on
+    # (tests/lab/configs/nxos-startup.cfg).
+    entity_classes:
+      management: ['^mgmt[0-9]+$']
+    # `sh ver` arrived as `show version` over SSH (L21-cisco_nxos.md); NX-API
+    # and NETCONF are unmeasured.
+    expands_abbreviations: true
+    # `int e1/1` arrived as one argument, `Ethernet1/1` (L21-cisco_nxos.md).
+    splits_interface_names: false
+    # A typed `show clock | include ...` reached port49 as `show clock` alone
+    # (L2-cisco_nxos.md, "Truncation length").
+    pipe_token: "|"
+    pipe_authorized: false
+    # Every command authorization ends `cmd-arg=<cr>` (L10-cisco_nxos.md).
+    strip_cr: true
+    # NX-OS printed its own error and never port49's server_msg
+    # (L2-cisco_nxos.md).
+    shows_server_msg: false
+    # `priv-lvl` picks a role by a per-release table, and `shell:roles`, bare
+    # or inside `cisco-av-pair`, names one (L16-cisco_nxos.md).
+    privilege_attributes: [priv-lvl, shell:roles, cisco-av-pair]
+    inert_attributes: [home-directory]
````

<!-- patch: platforms/1.0.0/juniper_junos.yaml -->
````diff
diff --git a/platforms/1.0.0/juniper_junos.yaml b/platforms/1.0.0/juniper_junos.yaml
new file mode 100644
index 0000000..6ad4261
--- /dev/null
+++ b/platforms/1.0.0/juniper_junos.yaml
@@ -0,0 +1,32 @@
+# juniper_junos — vSRX 21.4R3.15 and vJunos-router 23.4R2-S2.1 in the port49 lab.
+# Every value is measured and cited, or marked unmeasured and chosen in the
+# direction that fails closed (spec §8, §15).
+platforms:
+  juniper_junos:
+    # Session authorization only: no per-command request in 26 sessions on two
+    # images (L18; decision 21). The projection that carries port49's rules
+    # onto the session reply is decision 22, provisional on L12 (plan 5b), so
+    # no level is rendered yet.
+    supports: [session]
+    # fxp0 is the interface the lab reaches both images on
+    # (tests/lab/configs/vjunos-startup.conf); em0 is spec §8's example and no
+    # lab image uses it.
+    entity_classes:
+      management: ['^(fxp0|em0)$']
+    # Junos sends no command to expand; unmeasured, so false, the direction
+    # that fails closed.
+    expands_abbreviations: false
+    splits_interface_names: false
+    pipe_token: "|"
+    pipe_authorized: false
+    strip_cr: true
+    # No command request to carry one; unmeasured, so false.
+    shows_server_msg: false
+    # local-user-name is applied (L18-juniper_*.md); user-permissions is
+    # measured inert on these releases and a permission carrier by design
+    # (decision 22); the command and configuration regexes are
+    # vendor-documented and unmeasured (L18).
+    privilege_attributes: [local-user-name, user-permissions, allow-commands, deny-commands, allow-configuration,
+      deny-configuration, allow-commands-regexps, deny-commands-regexps, allow-configuration-regexps,
+      deny-configuration-regexps]
+    inert_attributes: [home-directory]
````

<!-- patch: platforms/platforms.go -->
````diff
diff --git a/platforms/platforms.go b/platforms/platforms.go
new file mode 100644
index 0000000..6d4c9a8
--- /dev/null
+++ b/platforms/platforms.go
@@ -0,0 +1,18 @@
+// Package platforms holds the built-in platform adapters as the files they are
+// (spec §8, "Knowing what is shipped"): one directory per platform set, named
+// by its version, one YAML file per platform in it. They are embedded in both
+// binaries, and they are browsable and diffable across tags without running
+// anything. internal/platform parses them; nothing else reads this package.
+//
+// A set, once released, is never edited: a policy pins one (`platform_set:`),
+// and a binary upgrade must not change what a pinned policy renders (spec §8,
+// "the platform set is pinned"). A change to a shipped adapter is a new
+// directory.
+package platforms
+
+import "embed"
+
+// FS is every built-in set: `<version>/<platform>.yaml`.
+//
+//go:embed */*.yaml
+var FS embed.FS
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`; `gofmt -l .` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add platforms internal/platform
git commit -m "refactor: the built-in adapters are files, platforms/1.0.0

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: EOS is told the role beside the level; a level's own rendering moves with it

**Files:**
- Modify: `platforms/1.0.0/arista_eos.yaml` (`privilege`)
- Modify: `internal/policy/diff.go` (`levelChange`)
- Test: `internal/platform/adapter_test.go`, `internal/platform/dialect_test.go`,
  `internal/policy/{diff,resolve,tests}_test.go`, `cmd/port49/policy_test.go`,
  `cmd/port49d/run_test.go`, `internal/broker/broker_test.go`

**Interfaces:**
- Consumes: `(*Policy).render(dialect, level) ([]string, string, bool)` (existing).
- Produces: no new signature. `arista_eos` renders `readonly: [priv-lvl=1, roles=network-operator]`,
  `operator: [priv-lvl=15, roles=network-operator]`, `admin: [priv-lvl=15, roles=network-admin]`
  (Decided 5). `levelChange` skips an attribute the level itself renders where the platform's
  adapter is the same in both versions (Decided 7).

Every test that asserted an EOS reply of `["priv-lvl=…"]` alone moves to the new reply. Two
things are new: `TestEOSSendsTheLevelAndTheRole`, and the lowering half of
`TestPolicyDiffGatesALevelRaise`, which passes only with the `diff.go` change — without it the
role's change from `network-admin` to `network-operator` fails the gate on a lowering.

- [ ] **Step 1: Move the tests to the new reply, and add the new one**

<!-- patch: cmd/port49/policy_test.go -->
````diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index 2d8456d..510f990 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -543,7 +543,8 @@ func TestPolicyDiffGatesALevelRaise(t *testing.T) {
 	var out, errb bytes.Buffer
 	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
 		!strings.Contains(out.String(), "RAISES: noc on leaf-01: level readonly -> admin, max_privilege none -> none, "+
-			"priv_lvl 1 -> 15, enable none -> none, reply [\"priv-lvl=1\"] -> [\"priv-lvl=15\"]; no session test asserts it: add {subject: noc, device: leaf-01, "+
+			"priv_lvl 1 -> 15, enable none -> none, reply [\"priv-lvl=1\", \"roles=network-operator\"] -> "+
+			"[\"priv-lvl=15\", \"roles=network-admin\"]; no session test asserts it: add {subject: noc, device: leaf-01, "+
 			"priv_lvl: 15, level: admin}") ||
 		!strings.Contains(out.String(), "1 unacknowledged privilege raises") {
 		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
@@ -688,7 +689,7 @@ func TestPolicyDiffGatesAPrivilegeAttributeInTheReply(t *testing.T) {
 	}
 	var out, errb bytes.Buffer
 	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
-		!strings.Contains(out.String(), `reply ["priv-lvl=1"] -> ["priv-lvl=1", "roles=network-admin"]; no session test asserts it: `+
+		!strings.Contains(out.String(), `reply ["priv-lvl=1", "roles=network-operator"] -> ["priv-lvl=1", "roles=network-admin"]; no session test asserts it: `+
 			`add {subject: noc, device: leaf-01, reply: ["priv-lvl=1", "roles=network-admin"]}`) {
 		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
 	}
````

<!-- patch: cmd/port49d/run_test.go -->
````diff
diff --git a/cmd/port49d/run_test.go b/cmd/port49d/run_test.go
index e90cf01..611c943 100644
--- a/cmd/port49d/run_test.go
+++ b/cmd/port49d/run_test.go
@@ -230,7 +230,8 @@ func TestRunServesAPolicyEditToALiveSessionWithNoLogout(t *testing.T) {
 	if st := dev.login("alice", mint(t, addrs[1][1], pkiDir, "leaf1")); st != wire.AuthenStatusPass {
 		t.Fatalf("login: status %d; decision log %s", st, log.String())
 	}
-	if r := dev.authorize("alice"); r.Status != wire.AuthorStatusPassAdd || len(r.Args) != 1 || string(r.Args[0]) != "priv-lvl=15" {
+	if r := dev.authorize("alice"); r.Status != wire.AuthorStatusPassAdd || len(r.Args) != 2 || string(r.Args[0]) != "priv-lvl=15" ||
+		string(r.Args[1]) != "roles=network-admin" {
 		t.Fatalf("session authorization: %+v", r)
 	}
 	if !dev.permits("alice", "configure") {
````

<!-- patch: internal/broker/broker_test.go -->
````diff
diff --git a/internal/broker/broker_test.go b/internal/broker/broker_test.go
index 88cbe65..4f24a09 100644
--- a/internal/broker/broker_test.go
+++ b/internal/broker/broker_test.go
@@ -8,6 +8,7 @@ import (
 	"encoding/hex"
 	"encoding/json"
 	"net/http/httptest"
+	"slices"
 	"strings"
 	"sync"
 	"testing"
@@ -107,7 +108,7 @@ func TestTheBlobIsWrittenAndEmittedOncePerHash(t *testing.T) {
 			t.Fatal(err)
 		}
 		dev, _ := m["device"].(map[string]any)
-		if dev["name"] == "leaf1" && (len(b.Attributes) != 1 || b.Attributes[0] != "priv-lvl=15") {
+		if dev["name"] == "leaf1" && !slices.Equal(b.Attributes, []string{"priv-lvl=15", "roles=network-admin"}) {
 			t.Fatalf("leaf1's blob: %+v", b)
 		}
 	}
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index d8f7851..18e9d43 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -9,8 +9,8 @@ import (
 	"github.com/blanketfish/port49/platforms"
 )
 
-// shipped is the table plan 4 compiled into the binary, value for value.
-// Moving it into platforms/1.0.0/ must not change what any device is told.
+// shipped is the default set, value for value: the table plan 4 compiled
+// into the binary, and each change plan 5 made to it with the note behind it.
 var shipped = map[string]Dialect{
 	"arista_eos": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
@@ -20,7 +20,9 @@ var shipped = map[string]Dialect{
 			"loopback":   {`^Loopback[0-9]+$`},
 			"physical":   {`^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$`},
 		},
-		Levels:              map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=15"}, "admin": {"priv-lvl=15"}},
+		// L16-arista_eos.md, ceiling-arista_eos.md; decisions 23 and 25.
+		Levels: map[string][]string{"readonly": {"priv-lvl=1", "roles=network-operator"},
+			"operator": {"priv-lvl=15", "roles=network-operator"}, "admin": {"priv-lvl=15", "roles=network-admin"}},
 		PrivilegeAttributes: []string{"priv-lvl", "roles"},
 		InertAttributes:     []string{"home-directory"},
 	},
@@ -49,7 +51,7 @@ var shipped = map[string]Dialect{
 	},
 }
 
-func TestTheDefaultSetIsTheTablePlan4Shipped(t *testing.T) {
+func TestTheDefaultSetValueForValue(t *testing.T) {
 	got := Dialects()
 	if len(got) != len(shipped) {
 		t.Fatalf("%d platforms, want %d", len(got), len(shipped))
````

<!-- patch: internal/platform/dialect_test.go -->
````diff
diff --git a/internal/platform/dialect_test.go b/internal/platform/dialect_test.go
index 0564ae4..e3e5bad 100644
--- a/internal/platform/dialect_test.go
+++ b/internal/platform/dialect_test.go
@@ -88,12 +88,11 @@ func TestManagementIsDefinedPerPlatform(t *testing.T) {
 	}
 }
 
-// Levels render per platform. arista_eos is the one platform whose rendering is
-// measured (L16); every other platform renders nothing, which is not a mapping
-// error, and still has a number for the token's ceiling.
+// Levels render per platform, and a platform that renders no priv-lvl still
+// has a number for the token's ceiling.
 func TestLevelsRenderAndHaveANumber(t *testing.T) {
 	eos, _ := DialectFor("arista_eos")
-	if a, ok := eos.Render("admin"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15"}) {
+	if a, ok := eos.Render("admin"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15", "roles=network-admin"}) {
 		t.Fatalf("eos admin: %v %v", a, ok)
 	}
 	if n, ok := eos.PrivLvl("readonly"); !ok || n != 1 {
@@ -113,8 +112,8 @@ func TestLevelsRenderAndHaveANumber(t *testing.T) {
 // spec §6, decision 23), and nothing new on IOS-XE, which can (plan 5's).
 func TestOperatorIsAdminsLevelWhereTheDeviceCannotFenceIt(t *testing.T) {
 	eos, _ := DialectFor("arista_eos")
-	if a, ok := eos.Render("operator"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15"}) {
-		t.Fatalf("eos operator renders as admin does: %v %v", a, ok)
+	if a, ok := eos.Render("operator"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15", "roles=network-operator"}) {
+		t.Fatalf("eos operator gets admin's level and readonly's role: %v %v", a, ok)
 	}
 	if n, ok := eos.PrivLvl("operator"); !ok || n != 15 {
 		t.Fatalf("eos operator: %d %v", n, ok)
@@ -145,7 +144,7 @@ func TestUnknownPlatformsAreGenericAndTheTableIsCopied(t *testing.T) {
 	eos.EntityClasses["management"][0] = "changed"
 	eos.Levels["admin"] = nil
 	again, _ := DialectFor("arista_eos")
-	if again.EntityClasses["management"][0] == "changed" || len(again.Levels["admin"]) != 1 {
+	if again.EntityClasses["management"][0] == "changed" || len(again.Levels["admin"]) != 2 {
 		t.Fatal("DialectFor must return a copy")
 	}
 	if len(Dialects()) != len(Names()) {
@@ -191,3 +190,21 @@ func TestPrivilegeAttributesArePerPlatformAndFailClosed(t *testing.T) {
 		}
 	}
 }
+
+// EOS is told the level and the role together, because a role with no
+// priv-lvl beside it lands the session at 1 (L16-arista_eos.md). The level
+// fences a session while port49 answers and the role when the device falls
+// back to local, so operator gets admin's level and readonly's role
+// (ceiling-arista_eos.md; decisions 23 and 25).
+func TestEOSSendsTheLevelAndTheRole(t *testing.T) {
+	eos, _ := DialectFor("arista_eos")
+	for level, want := range map[string][]string{
+		"readonly": {"priv-lvl=1", "roles=network-operator"},
+		"operator": {"priv-lvl=15", "roles=network-operator"},
+		"admin":    {"priv-lvl=15", "roles=network-admin"},
+	} {
+		if got, ok := eos.Render(level); !ok || !reflect.DeepEqual(got, want) {
+			t.Errorf("%s: %v %v, want %v", level, got, ok, want)
+		}
+	}
+}
````

<!-- patch: internal/policy/diff_test.go -->
````diff
diff --git a/internal/policy/diff_test.go b/internal/policy/diff_test.go
index 2b696d9..af5e1e1 100644
--- a/internal/policy/diff_test.go
+++ b/internal/policy/diff_test.go
@@ -583,7 +583,7 @@ func TestTheGateFailsAPrivilegeAttributeInTheReply(t *testing.T) {
 		}
 		was := `[]`
 		if tt.device == "leaf-01" {
-			was = `["priv-lvl=1"]`
+			was = `["priv-lvl=1", "roles=network-operator"]`
 		}
 		back = Compare(mustParse(t, after), mustParse(t, diffBase+"tests:\n  - {subject: noc, device: "+tt.device+", reply: "+was+"}\n"), noon)
 		if back.UnacknowledgedLevels() != raised-1 {
````

<!-- patch: internal/policy/resolve_test.go -->
````diff
diff --git a/internal/policy/resolve_test.go b/internal/policy/resolve_test.go
index c15e60e..a01fa7f 100644
--- a/internal/policy/resolve_test.go
+++ b/internal/policy/resolve_test.go
@@ -33,7 +33,7 @@ func TestResolveComposesAndCompiles(t *testing.T) {
 	}
 	b := r.Blob
 	if b.Platform != "arista_eos" || b.Bundle != p.Bundle || b.Privilege != "readonly" ||
-		!reflect.DeepEqual(b.Attributes, []string{"priv-lvl=1"}) || !reflect.DeepEqual(b.Pipe, sortedCopy(DefaultPipe)) ||
+		!reflect.DeepEqual(b.Attributes, []string{"priv-lvl=1", "roles=network-operator"}) || !reflect.DeepEqual(b.Pipe, sortedCopy(DefaultPipe)) ||
 		b.Normalize.PipeToken != "|" || b.Normalize.PipeAuthorized || !b.Normalize.ExpandsAbbreviations {
 		t.Fatalf("blob: %+v", b)
 	}
@@ -130,7 +130,7 @@ grants:
 	}
 	// Order is first appearance — platform, then roles by name, then grants —
 	// with an override taking the place of what it shadows.
-	want := []string{"priv-lvl=2", "home-directory*/home/{username}", "idletime*30", "timeout*60"}
+	want := []string{"priv-lvl=2", "roles=network-operator", "home-directory*/home/{username}", "idletime*30", "timeout*60"}
 	if !reflect.DeepEqual(r.Blob.Attributes, want) {
 		t.Fatalf("attributes %q, want %q", r.Blob.Attributes, want)
 	}
````

<!-- patch: internal/policy/tests_test.go -->
````diff
diff --git a/internal/policy/tests_test.go b/internal/policy/tests_test.go
index 20f44ad..33e368c 100644
--- a/internal/policy/tests_test.go
+++ b/internal/policy/tests_test.go
@@ -225,9 +225,9 @@ roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {all: ["h
 subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
 grants: [{subject: s, scope: all_devices, roles: [ro]}]
 tests:
-  - {subject: s, device: leaf-01, reply: ["priv-lvl=1", "home-directory*/h/"]}
+  - {subject: s, device: leaf-01, reply: ["priv-lvl=1", "roles=network-operator", "home-directory*/h/"]}
   - {subject: s, device: nx-01, reply: ["home-directory*/h/"]}
-  - {subject: s, device: leaf-01, reply: ["home-directory*/h/", "priv-lvl=1"]}
+  - {subject: s, device: leaf-01, reply: ["home-directory*/h/", "priv-lvl=1", "roles=network-operator"]}
   - {subject: s, device: nx-01, reply: []}
 `)
 	want := []bool{true, true, false, false}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/ ./cmd/... ./internal/broker/`
Expected: FAIL — `TestEOSSendsTheLevelAndTheRole`, `TestPolicyDiffGatesALevelRaise`,
`TestPolicyDiffGatesAPrivilegeAttributeInTheReply`, `TestRunServesAPolicyEditToALiveSessionWithNoLogout`,
`TestTheBlobIsWrittenAndEmittedOncePerHash`, `TestEveryReleasedSetIsFrozen` (the frozen table
moved ahead of the file) and the policy tests asserting the reply.

- [ ] **Step 3: Render the role, and judge a level's rendering by the level**

<!-- patch: internal/policy/diff.go -->
````diff
diff --git a/internal/policy/diff.go b/internal/policy/diff.go
index 37fe6d3..8a41277 100644
--- a/internal/policy/diff.go
+++ b/internal/policy/diff.go
@@ -3,6 +3,7 @@ package policy
 import (
 	"errors"
 	"fmt"
+	"reflect"
 	"slices"
 	"sort"
 	"strconv"
@@ -777,14 +778,28 @@ func (c *comparison) levelChange(l LevelChange, was, is privilege) LevelChange {
 	// which priv_lvl judges, changes what the device lets the session do in a
 	// direction the gate cannot read, unless its adapter lists it inert: on a
 	// session-only platform losing deny-commands widens access (spec §12).
+	//
+	// Except the level's own rendering. Where the platform's adapter is the
+	// same in both versions, what a level renders there is what it rendered,
+	// so the attributes a level brings move with the level, and level and
+	// priv_lvl judge the direction: a subject moved from admin to readonly on
+	// EOS is lowered, although the role its rendering names changed from
+	// network-admin to network-operator. An adapter edit is judged whole here
+	// and gated in its own right.
 	dialect := c.after.dialect(is.platform)
-	moved := func(from, to []string) bool {
+	var oldRendered, newRendered []string
+	if reflect.DeepEqual(c.before.dialect(was.platform), dialect) {
+		oldRendered, _, _ = c.before.render(dialect, was.level)
+		newRendered, _, _ = c.after.render(dialect, is.level)
+	}
+	moved := func(from, to, rendered []string) bool {
 		return slices.ContainsFunc(from, func(a string) bool {
 			name := a[:strings.IndexAny(a, "=*")]
-			return name != "priv-lvl" && !slices.Contains(to, a) && dialect.BearsPrivilege(name)
+			return name != "priv-lvl" && !slices.Contains(to, a) && !slices.Contains(rendered, a) &&
+				dialect.BearsPrivilege(name)
 		})
 	}
-	if moved(l.NewReply, l.OldReply) || moved(l.OldReply, l.NewReply) {
+	if moved(l.NewReply, l.OldReply, newRendered) || moved(l.OldReply, l.NewReply, oldRendered) {
 		l.Raised = append(l.Raised, "reply")
 	}
 	l.Raise = len(l.Raised) > 0
````

<!-- patch: platforms/1.0.0/arista_eos.yaml -->
````diff
diff --git a/platforms/1.0.0/arista_eos.yaml b/platforms/1.0.0/arista_eos.yaml
index c6a3752..786f51b 100644
--- a/platforms/1.0.0/arista_eos.yaml
+++ b/platforms/1.0.0/arista_eos.yaml
@@ -6,14 +6,25 @@ platforms:
     # Session and per-command authorization (L1, L10). Config-command
     # authorization is unmeasured, so it is not claimed.
     supports: [session, commands]
-    # readonly and admin are applied by vEOS on every lab run since 2026-09-20
-    # (tests/lab/results/L16-arista_eos.md). operator renders as admin does
-    # (spec §6, decision 23): at 15 vEOS fenced nothing port49 permitted, and
-    # at 1 it refused even `clear counters` (ceiling-arista_eos.md).
+    # The level and the role travel together: EOS reads the bare `roles=`, and
+    # a role with no `priv-lvl` beside it lands the session at 1
+    # (tests/lab/results/L16-arista_eos.md, 2026-09-22).
+    #
+    # The level is what fences a session while port49 answers: at 1 the parser
+    # refuses `clear counters`, `clear ip bgp *` and `configure terminal`
+    # without asking port49, and at 15 it fences nothing port49 permits, a
+    # network-operator role included (ceiling-arista_eos.md). So operator gets
+    # admin's 15 and port49's rules are its fence (spec §6, decision 23).
+    #
+    # The role is what fences a session when port49 cannot answer and
+    # `aaa authorization commands ... local` takes over: network-operator is
+    # refused `configure`, network-admin is not (L16-arista_eos.md, command
+    # authorization LOCAL). So operator gets readonly's role, and the
+    # fallback never hands an operator configuration (decision 25).
     privilege:
-      readonly: ["priv-lvl=1"]
-      operator: ["priv-lvl=15"]
-      admin: ["priv-lvl=15"]
+      readonly: ["priv-lvl=1", "roles=network-operator"]
+      operator: ["priv-lvl=15", "roles=network-operator"]
+      admin: ["priv-lvl=15", "roles=network-admin"]
     # Interface names, not device behaviour: spec §8's example.
     entity_classes:
       management: ['^Management[0-9]+$']
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add platforms internal cmd
git commit -m "feat: EOS is told the role beside the level (decision 25)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: NX-OS is told its role, IOS-XE its level, and IOS-XE's operator is 7

**Files:**
- Modify: `platforms/1.0.0/cisco_nxos.yaml`, `platforms/1.0.0/cisco_iosxe.yaml` (`privilege`)
- Modify: `internal/platform/dialect.go` (`PrivLvl` reads `CeilingLevels` when the rendering sends
  no `priv-lvl`; the `CeilingLevels` comment)
- Test: `internal/platform/{adapter,dialect}_test.go`, `internal/policy/{diff,explain,lint,load,resolve,tests}_test.go`,
  `internal/broker/engine_test.go`

**Interfaces:**
- Produces: `Dialect.PrivLvl(level)` — the rendering's `priv-lvl`; else `CeilingLevels`; else,
  where the platform renders nothing and declares no table, plan 3's; else `false`.
  `cisco_nxos` renders `shell:roles*` alone; `cisco_iosxe` renders `priv-lvl=1/7/15`.

The tests' stand-in for "a level no platform renders", `unmappedLevel`, now quarantines NX-OS and
IOS-XE devices too; Junos renders nothing until 5b, so the tests' device that still mints moves
from `nx-01` to `srx-fw-04`. The broker's quarantine test moves to a class NX-OS does not define,
since its fixture has no Junos device.

- [ ] **Step 1: Move the tests, and add the new one**

<!-- patch: internal/broker/engine_test.go -->
````diff
diff --git a/internal/broker/engine_test.go b/internal/broker/engine_test.go
index 336cc1c..bd1b572 100644
--- a/internal/broker/engine_test.go
+++ b/internal/broker/engine_test.go
@@ -66,21 +66,18 @@ func TestAMintRecordNamesItsBundle(t *testing.T) {
 
 // A device a joint check failed on is quarantined at load, and a mint for it
 // is refused device_quarantined, by name, while every other device mints
-// (spec §10; §13 decision 20). leaf1 is arista_eos, which renders no custom level
-// `unmapped` (`operator` renders there since spec §13 decision 23).
+// (spec §10; §13 decision 20). nx1 is cisco_nxos, which defines no @loopback.
 func TestAQuarantinedDeviceIsRefusedAtMint(t *testing.T) {
 	f := newFixture(t, 8)
 	path := filepath.Join(t.TempDir(), "policy.yaml")
 	body := `
-privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]
-scopes: [{name: all_devices, match: {}}]
-roles: [{name: r, privilege: unmapped, permit: ["**"]}]
-subjects: [{name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}]
-grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: nx, roles: [r]}]
+scopes: [{name: all_devices, match: {}}, {name: eos, match: {platform: arista_eos}, on_missing: exclude}]
+roles: [{name: r, permit: ["**"], deny: [interface @loopback]}]
+subjects:
+  - {name: c, identity: "user:carol@example.com", username: carol, token_ttl: 60s}
+  - {name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}
+grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: eos, roles: [r]}]
 `
-	body = strings.Replace(body, "scopes: [{name: all_devices, match: {}}]",
-		"scopes: [{name: all_devices, match: {}}, {name: nx, match: {platform: cisco_nxos}}]", 1)
-	body = strings.Replace(body, "subjects: [", `subjects: [{name: c, identity: "user:carol@example.com", username: carol, token_ttl: 60s}, `, 1)
 	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
 		t.Fatal(err)
 	}
@@ -94,7 +91,7 @@ grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: nx, r
 	for _, it := range resp.Results {
 		byDevice[it.Device] = it.Verdict + " " + it.Reason
 	}
-	if byDevice["leaf1"] != "deny device_quarantined" || !strings.HasPrefix(byDevice["nx1"], "permit") {
+	if byDevice["nx1"] != "deny device_quarantined" || !strings.HasPrefix(byDevice["leaf1"], "permit") {
 		t.Fatalf("%+v", resp.Results)
 	}
 	// A principal with no grant on the quarantined device hears
@@ -102,7 +99,7 @@ grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: nx, r
 	// tell a caller which devices exist (design §17).
 	carol := f.client(t, "carol@example.com", f.now.Add(24*time.Hour))
 	f.log.Reset()
-	resp = decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["leaf1"]}`, ""))
+	resp = decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["nx1"]}`, ""))
 	if it := resp.Results[0]; it.Verdict != "deny" || it.Reason != "no_grants_matched" {
 		t.Fatalf("carol: %+v", it)
 	}
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index 18e9d43..4514c51 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -28,15 +28,20 @@ var shipped = map[string]Dialect{
 	},
 	"cisco_nxos": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true,
-		Supports:            []string{"session", "commands"},
-		EntityClasses:       map[string][]string{"management": {`^mgmt[0-9]+$`}},
+		Supports:      []string{"session", "commands"},
+		EntityClasses: map[string][]string{"management": {`^mgmt[0-9]+$`}},
+		// L16-cisco_nxos.md, ceiling-cisco_nxos.md; decisions 23 and 25.
+		Levels: map[string][]string{"readonly": {"shell:roles*network-operator"},
+			"operator": {"shell:roles*network-operator"}, "admin": {"shell:roles*network-admin"}},
 		CeilingLevels:       map[string]uint8{"readonly": 1, "operator": 15, "admin": 15},
 		PrivilegeAttributes: []string{"priv-lvl", "shell:roles", "cisco-av-pair"},
 		InertAttributes:     []string{"home-directory"},
 	},
 	"cisco_iosxe": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true, SplitsInterfaceNames: true,
-		Supports:            []string{"session", "commands"},
+		Supports: []string{"session", "commands"},
+		// L18-cisco_iosxe.md, ceiling-cisco_iosxe.md; decision 25.
+		Levels:              map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=7"}, "admin": {"priv-lvl=15"}},
 		PrivilegeAttributes: []string{"priv-lvl"},
 		InertAttributes:     []string{"home-directory"},
 	},
````

<!-- patch: internal/platform/dialect_test.go -->
````diff
diff --git a/internal/platform/dialect_test.go b/internal/platform/dialect_test.go
index e3e5bad..8b98074 100644
--- a/internal/platform/dialect_test.go
+++ b/internal/platform/dialect_test.go
@@ -99,17 +99,24 @@ func TestLevelsRenderAndHaveANumber(t *testing.T) {
 		t.Fatalf("eos readonly: %d %v", n, ok)
 	}
 	nx, _ := DialectFor("cisco_nxos")
-	if a, ok := nx.Render("operator"); !ok || len(a) != 0 {
-		t.Fatalf("nx-os renders nothing, for any level: %v %v", a, ok)
+	if a, ok := nx.Render("admin"); !ok || !reflect.DeepEqual(a, []string{"shell:roles*network-admin"}) {
+		t.Fatalf("nx-os admin: %v %v", a, ok)
 	}
 	if n, ok := nx.PrivLvl("admin"); !ok || n != 15 {
-		t.Fatalf("nx-os admin's ceiling number: %d %v", n, ok)
+		t.Fatalf("nx-os renders no priv-lvl, and admin's ceiling number is its table's: %d %v", n, ok)
+	}
+	junos, _ := DialectFor("juniper_junos")
+	if a, ok := junos.Render("admin"); !ok || len(a) != 0 {
+		t.Fatalf("junos renders nothing until plan 5b's projection: %v %v", a, ok)
+	}
+	if n, ok := junos.PrivLvl("admin"); !ok || n != 15 {
+		t.Fatalf("junos admin's ceiling number is plan 3's table's: %d %v", n, ok)
 	}
 }
 
 // operator gets admin's device privilege on arista_eos and cisco_nxos, where
 // the device cannot draw the operator line (tests/lab/results/ceiling-*.md;
-// spec §6, decision 23), and nothing new on IOS-XE, which can (plan 5's).
+// spec §6, decision 23), and level 7 on IOS-XE, where it can (decision 25).
 func TestOperatorIsAdminsLevelWhereTheDeviceCannotFenceIt(t *testing.T) {
 	eos, _ := DialectFor("arista_eos")
 	if a, ok := eos.Render("operator"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15", "roles=network-operator"}) {
@@ -125,7 +132,11 @@ func TestOperatorIsAdminsLevelWhereTheDeviceCannotFenceIt(t *testing.T) {
 	if n, ok := nx.PrivLvl("readonly"); !ok || n != 1 {
 		t.Fatalf("nx-os readonly: %d %v", n, ok)
 	}
-	for _, name := range []string{"cisco_iosxe", "juniper_junos", "no_such_platform"} {
+	xe, _ := DialectFor("cisco_iosxe")
+	if n, ok := xe.PrivLvl("operator"); !ok || n != 7 {
+		t.Fatalf("ios-xe operator: %d %v", n, ok)
+	}
+	for _, name := range []string{"juniper_junos", "no_such_platform"} {
 		d, _ := DialectFor(name)
 		if _, ok := d.PrivLvl("operator"); ok {
 			t.Fatalf("%s: operator has no number there yet", name)
@@ -208,3 +219,28 @@ func TestEOSSendsTheLevelAndTheRole(t *testing.T) {
 		}
 	}
 }
+
+// NX-OS is told the role and never priv-lvl: the role decides in both
+// directions and a priv-lvl beside it is inert (L16-cisco_nxos.md). IOS-XE is
+// told priv-lvl and nothing else, and its level 7 is the operator rung
+// (L18-cisco_iosxe.md, ceiling-cisco_iosxe.md).
+func TestNXOSSendsTheRoleAndIOSXETheLevel(t *testing.T) {
+	nx, _ := DialectFor("cisco_nxos")
+	xe, _ := DialectFor("cisco_iosxe")
+	for _, tt := range []struct {
+		d     Dialect
+		level string
+		want  []string
+	}{
+		{nx, "readonly", []string{"shell:roles*network-operator"}},
+		{nx, "operator", []string{"shell:roles*network-operator"}},
+		{nx, "admin", []string{"shell:roles*network-admin"}},
+		{xe, "readonly", []string{"priv-lvl=1"}},
+		{xe, "operator", []string{"priv-lvl=7"}},
+		{xe, "admin", []string{"priv-lvl=15"}},
+	} {
+		if got, ok := tt.d.Render(tt.level); !ok || !reflect.DeepEqual(got, tt.want) {
+			t.Errorf("%s: %v %v, want %v", tt.level, got, ok, tt.want)
+		}
+	}
+}
````

<!-- patch: internal/policy/diff_test.go -->
````diff
diff --git a/internal/policy/diff_test.go b/internal/policy/diff_test.go
index af5e1e1..cb79814 100644
--- a/internal/policy/diff_test.go
+++ b/internal/policy/diff_test.go
@@ -95,7 +95,7 @@ func TestTheDiffReportsWhatItCannotEnumerate(t *testing.T) {
 		t.Fatalf("access %+v", d.Access)
 	}
 	quarantining := mustParse(t, unmappedLevel+strings.Replace(diffBase, "privilege: readonly", "privilege: unmapped", 1))
-	if q := Compare(before, quarantining, noon).Quarantined; len(q) != 2 || q[0].Device != "campus-sw-7" {
+	if q := Compare(before, quarantining, noon).Quarantined; len(q) != 4 || q[0].Device != "campus-sw-7" {
 		t.Fatalf("newly quarantined %+v", q)
 	}
 }
@@ -197,22 +197,26 @@ func TestTheGateSeesAWidenedPipeAllowlist(t *testing.T) {
 func TestTheGateSeesAReleaseAndANewCause(t *testing.T) {
 	quarantining := unmappedLevel + strings.Replace(diffBase, "privilege: readonly", "privilege: unmapped", 1)
 	d := Compare(mustParse(t, quarantining), mustParse(t, diffBase), noon)
-	if len(d.Released) != 2 || d.Released[0].Device != "campus-sw-7" || d.Unacknowledged() == 0 {
+	if len(d.Released) != 4 || d.Released[0].Device != "campus-sw-7" || d.Unacknowledged() == 0 {
 		t.Fatalf("released %+v, %d unacknowledged", d.Released, d.Unacknowledged())
 	}
 	for _, c := range d.Changes {
-		if c.Old.Reason != decision.DeviceQuarantined || !c.Gated || !slices.Contains([]string{"leaf-01", "campus-sw-7"}, c.Devices[0]) {
+		if c.Old.Reason != decision.DeviceQuarantined || !c.Gated ||
+			!slices.Contains([]string{"leaf-01", "campus-sw-7", "nx-01", "xe-01"}, c.Devices[0]) {
 			t.Errorf("%+v", c)
 		}
 	}
-	acked := diffBase + "tests:\n  - {subject: noc, device: leaf-01, command: \"show version\", expect: permit}\n"
+	acked := diffBase + "tests:\n"
+	for _, device := range []string{"leaf-01", "nx-01", "xe-01"} {
+		acked += "  - {subject: noc, device: " + device + ", command: \"show version\", expect: permit}\n"
+	}
 	if d := Compare(mustParse(t, quarantining), mustParse(t, acked), noon); d.Unacknowledged() != 0 {
 		t.Fatalf("a test acknowledges it: %+v", d.Changes)
 	}
 	second := strings.Replace(quarantining, "grants:\n", "  - {name: ops, identity: \"user:ops@example.com\", username: ops, token_ttl: 60s}\ngrants:\n"+
 		"  - {subject: ops, scope: all_devices, roles: [read_only]}\n", 1)
 	q := Compare(mustParse(t, quarantining), mustParse(t, second), noon).Quarantined
-	if len(q) != 2 || len(q[0].Entries) != 1 || !strings.Contains(q[0].Entries[0].Cause, `"ops"`) {
+	if len(q) != 4 || len(q[0].Entries) != 1 || !strings.Contains(q[0].Entries[0].Cause, `"ops"`) {
 		t.Fatalf("newly quarantined %+v", q)
 	}
 }
@@ -556,7 +560,7 @@ func TestTheGateFailsAPrivilegeAttributeInTheReply(t *testing.T) {
 		{`{juniper_junos: [local-user-name=super-user]}`, "srx-lab-01", `["local-user-name=super-user"]`},
 		{`{cisco_nxos: ["shell:roles=network-admin"]}`, "nx-01", `["shell:roles=network-admin"]`},
 		{`{arista_eos: ["roles=network-admin"]}`, "leaf-01", `["priv-lvl=1", "roles=network-admin"]`},
-		{`{all: ["idletime*30"]}`, "xe-01", `["idletime*30"]`},
+		{`{all: ["idletime*30"]}`, "xe-01", `["priv-lvl=1", "idletime*30"]`},
 	} {
 		after := strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], attributes: "+tt.attrs+"}", 1)
 		d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
@@ -581,9 +585,10 @@ func TestTheGateFailsAPrivilegeAttributeInTheReply(t *testing.T) {
 		if back.UnacknowledgedLevels() != raised {
 			t.Fatalf("%s: removing it fails the gate: %+v", tt.attrs, back.Levels)
 		}
-		was := `[]`
-		if tt.device == "leaf-01" {
-			was = `["priv-lvl=1", "roles=network-operator"]`
+		was := map[string]string{"leaf-01": `["priv-lvl=1", "roles=network-operator"]`,
+			"nx-01": `["shell:roles*network-operator"]`, "xe-01": `["priv-lvl=1"]`}[tt.device]
+		if was == "" {
+			was = `[]`
 		}
 		back = Compare(mustParse(t, after), mustParse(t, diffBase+"tests:\n  - {subject: noc, device: "+tt.device+", reply: "+was+"}\n"), noon)
 		if back.UnacknowledgedLevels() != raised-1 {
````

<!-- patch: internal/policy/explain_test.go -->
````diff
diff --git a/internal/policy/explain_test.go b/internal/policy/explain_test.go
index 44bc671..69bebf6 100644
--- a/internal/policy/explain_test.go
+++ b/internal/policy/explain_test.go
@@ -104,7 +104,7 @@ grants: [{subject: s, scope: all_devices, roles: [op]}]`)
 	_, out := explained(t, p, "s", "", "leaf-01", "show version", false)
 	mustContain(t, out, "deny device_quarantined", "leaf-01 (arista_eos) fails a joint check now",
 		"level unmapped has no rendering on arista_eos")
-	_, out = explained(t, p, "s", "", "nx-01", "show version", false)
+	_, out = explained(t, p, "s", "", "srx-fw-04", "show version", false)
 	mustContain(t, out, "permit permit_dominates")
 }
 
````

<!-- patch: internal/policy/lint_test.go -->
````diff
diff --git a/internal/policy/lint_test.go b/internal/policy/lint_test.go
index ceccae8..cfd5908 100644
--- a/internal/policy/lint_test.go
+++ b/internal/policy/lint_test.go
@@ -17,7 +17,7 @@ subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s
 grants: [{subject: s, scope: all_devices, roles: [op]}]
 tests:
   - {subject: s, device: leaf-01, command: "show version", expect: deny, reason: device_quarantined}
-  - {subject: s, device: nx-01, command: "show version", expect: permit}
+  - {subject: s, device: srx-fw-04, command: "show version", expect: permit}
 `)
 	results := p.RunTests(noon)
 	if len(results) != 2 {
````

<!-- patch: internal/policy/load_test.go -->
````diff
diff --git a/internal/policy/load_test.go b/internal/policy/load_test.go
index c59b9d1..fbb1e71 100644
--- a/internal/policy/load_test.go
+++ b/internal/policy/load_test.go
@@ -46,10 +46,11 @@ func mustParse(t *testing.T, body string) *Policy {
 }
 
 // unmappedLevel declares a level, between operator and admin, that no
-// built-in platform renders or numbers: a role landing an arista_eos session
-// there quarantines the device, and a ceiling naming it loads nowhere. Since
-// the owner's ruling of 2026-09-24 `operator` renders on EOS (spec §6,
-// decision 23), so it is the tests' stand-in for a level with no mapping.
+// built-in platform renders or numbers: a role landing a session there
+// quarantines every device whose platform renders levels — arista_eos,
+// cisco_nxos and cisco_iosxe since plan 5 — and a ceiling naming it loads
+// nowhere. juniper_junos renders nothing until plan 5b's projection, so its
+// devices are the tests' devices that still mint.
 const unmappedLevel = "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n"
 
 // good is spec §11's shape, cut to what every platform in inventory() can
````

<!-- patch: internal/policy/resolve_test.go -->
````diff
diff --git a/internal/policy/resolve_test.go b/internal/policy/resolve_test.go
index a01fa7f..c29f8a9 100644
--- a/internal/policy/resolve_test.go
+++ b/internal/policy/resolve_test.go
@@ -58,20 +58,26 @@ func sortedCopy(s []string) []string {
 }
 
 // A platform that renders no level sends no attributes, and still numbers the
-// ceiling for the token (plan 3's table); a group subject resolves by name
-// only, since matching a person to a group is the directory's (plan 7).
+// ceiling for the token (plan 3's table), as one that renders a role and no
+// priv-lvl numbers it from its own; a group subject resolves by name only,
+// since matching a person to a group is the directory's (plan 7).
 func TestAPlatformThatRendersNothingStillHasACeiling(t *testing.T) {
 	p := mustParse(t, good)
-	if _, err := p.Resolve("CN=netops-admins,OU=Groups,DC=example,DC=com", deviceNamed(t, "nx-01"), noon); !errors.Is(err, ErrNoGrants) {
+	if _, err := p.Resolve("CN=netops-admins,OU=Groups,DC=example,DC=com", deviceNamed(t, "srx-fw-04"), noon); !errors.Is(err, ErrNoGrants) {
 		t.Fatalf("a group is never a principal: %v", err)
 	}
-	r, err := p.ResolveSubject("netops_admins", deviceNamed(t, "nx-01"), noon)
+	r, err := p.ResolveSubject("netops_admins", deviceNamed(t, "srx-fw-04"), noon)
 	if err != nil {
 		t.Fatal(err)
 	}
 	if r.MaxPrivilege != 15 || !r.HasCeiling || r.Level != "admin" || len(r.Blob.Attributes) != 0 ||
 		!reflect.DeepEqual(r.Blob.Pipe, []string{"**"}) {
-		t.Fatalf("netops_admins on NX-OS: %+v", r)
+		t.Fatalf("netops_admins on Junos: %+v", r)
+	}
+	r, err = p.ResolveSubject("netops_admins", deviceNamed(t, "nx-01"), noon)
+	if err != nil || r.MaxPrivilege != 15 || !r.HasCeiling ||
+		!reflect.DeepEqual(r.Blob.Attributes, []string{"shell:roles*network-admin"}) {
+		t.Fatalf("netops_admins on NX-OS: %+v %v", r, err)
 	}
 	if _, err := p.ResolveSubject("nobody", deviceNamed(t, "nx-01"), noon); err == nil {
 		t.Fatal("an undeclared subject is an error")
@@ -170,8 +176,8 @@ grants: [{subject: s, scope: all_devices, roles: [tech]}]`, `role "tech" names @
 scopes: [{name: all_devices, match: {}}]
 roles: [{name: op, privilege: unmapped, permit: [show **]}]
 subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
-grants: [{subject: s, scope: all_devices, roles: [op]}]`, "level unmapped has no rendering on arista_eos",
-			[]string{"campus-sw-7", "leaf-01"}},
+grants: [{subject: s, scope: all_devices, roles: [op]}]`, "level unmapped has no rendering on",
+			[]string{"campus-sw-7", "leaf-01", "nx-01", "xe-01"}},
 		{"a landing level above the ceiling", `
 scopes: [{name: all_devices, match: {}}]
 roles: [{name: adm, privilege: admin, permit: ["**"]}]
@@ -352,7 +358,7 @@ grants:
   - {subject: s, scope: all_devices, roles: [op], expires: 2026-11-01}
   - {subject: s, scope: dc, roles: [adm], expires: 2026-10-01}`, env())
 	leaf, campus := got["leaf-01"], got["campus-sw-7"]
-	if len(got) != 2 || len(leaf) != 1 || len(campus) != 1 ||
+	if len(got) != 4 || len(leaf) != 1 || len(campus) != 1 || len(got["nx-01"]) != 1 || len(got["xe-01"]) != 1 ||
 		!strings.HasPrefix(leaf[0], "will be quarantined from 2026-10-01T00:00:00.000Z, when grant dc [adm] expires: ") ||
 		!strings.Contains(leaf[0], "level unmapped has no rendering on arista_eos") ||
 		!strings.HasPrefix(campus[0], `quarantined: subject "s": level unmapped`) {
````

<!-- patch: internal/policy/tests_test.go -->
````diff
diff --git a/internal/policy/tests_test.go b/internal/policy/tests_test.go
index 33e368c..e38e32b 100644
--- a/internal/policy/tests_test.go
+++ b/internal/policy/tests_test.go
@@ -226,7 +226,7 @@ subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s
 grants: [{subject: s, scope: all_devices, roles: [ro]}]
 tests:
   - {subject: s, device: leaf-01, reply: ["priv-lvl=1", "roles=network-operator", "home-directory*/h/"]}
-  - {subject: s, device: nx-01, reply: ["home-directory*/h/"]}
+  - {subject: s, device: nx-01, reply: ["shell:roles*network-operator", "home-directory*/h/"]}
   - {subject: s, device: leaf-01, reply: ["home-directory*/h/", "priv-lvl=1", "roles=network-operator"]}
   - {subject: s, device: nx-01, reply: []}
 `)
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/ ./internal/broker/`
Expected: FAIL — `TestNXOSSendsTheRoleAndIOSXETheLevel`, `TestTheDefaultSetValueForValue`,
`TestLevelsRenderAndHaveANumber`, `TestOperatorIsAdminsLevelWhereTheDeviceCannotFenceIt`,
`TestTheDiffReportsWhatItCannotEnumerate`, `TestTheGateSeesAReleaseAndANewCause`,
`TestEveryReleasedSetIsFrozen` and the other moved tests.

- [ ] **Step 3: Render them**

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index 6681064..06f337c 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -59,9 +59,10 @@ type Dialect struct {
 	// Question 2) — and is not a load error; an entry missing from a non-nil
 	// map is, unless the level's parent chain reaches one.
 	Levels map[string][]string
-	// CeilingLevels is the priv-lvl number each level stands for on a
-	// platform that renders none (Levels nil), where the token's ceiling still
-	// needs one. nil is plan 3's table, ceilingLevels.
+	// CeilingLevels is the priv-lvl number each level stands for where the
+	// platform's rendering sends no priv-lvl — NX-OS is sent a role and no
+	// level (L16) — and the token's ceiling still needs one. nil on a platform
+	// with no Levels is plan 3's table, ceilingLevels.
 	CeilingLevels map[string]uint8
 	// PrivilegeAttributes are the attribute names measured to carry privilege
 	// on this platform (spec §6): none takes a placeholder, and the policy
@@ -186,18 +187,11 @@ func (d Dialect) Render(level string) (attrs []string, ok bool) {
 }
 
 // PrivLvl is the priv-lvl number this platform gives exactly this level: the
-// value of a `priv-lvl` attribute in its rendering, or, where the platform
-// renders none, its CeilingLevels or plan 3's table. ok is false where none
-// says.
+// value of a `priv-lvl` attribute in its rendering; where the rendering sends
+// none, its CeilingLevels (NX-OS renders a role and no level, L16); and where
+// the platform renders nothing at all and declares no table, plan 3's. ok is
+// false where none says.
 func (d Dialect) PrivLvl(level string) (uint8, bool) {
-	if d.Levels == nil {
-		table := d.CeilingLevels
-		if table == nil {
-			table = ceilingLevels
-		}
-		n, ok := table[level]
-		return n, ok
-	}
 	for _, a := range d.Levels[level] {
 		i := strings.IndexAny(a, "=*")
 		if i < 0 || a[:i] != "priv-lvl" {
@@ -207,5 +201,13 @@ func (d Dialect) PrivLvl(level string) (uint8, bool) {
 			return uint8(n), true
 		}
 	}
-	return 0, false
+	table := d.CeilingLevels
+	if table == nil {
+		if d.Levels != nil {
+			return 0, false
+		}
+		table = ceilingLevels
+	}
+	n, ok := table[level]
+	return n, ok
 }
````

<!-- patch: platforms/1.0.0/cisco_iosxe.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_iosxe.yaml b/platforms/1.0.0/cisco_iosxe.yaml
index 473dbb8..6f3a74d 100644
--- a/platforms/1.0.0/cisco_iosxe.yaml
+++ b/platforms/1.0.0/cisco_iosxe.yaml
@@ -6,8 +6,24 @@ platforms:
     # Session and per-command authorization (L1, L10). Config-command
     # authorization is unmeasured, so it is not claimed.
     supports: [session, commands]
-    # No level is rendered yet, and no entity class is defined: the lab's
-    # management interface is GigabitEthernet1, a physical port by name.
+    # priv-lvl alone: this image refuses the session for any attribute it does
+    # not recognise, under either flag, and a run of refusals stops it
+    # answering SSH for about a minute, break-glass included
+    # (tests/lab/results/L18-cisco_iosxe.md).
+    #
+    # The device draws its own ladder: level 1 refuses `clear counters`,
+    # `clear ip bgp *` and `configure terminal` in the parser without asking
+    # port49; level 7 does the same until the device is told what level 7
+    # may run, and `privilege exec level 7 clear counters` makes it exactly
+    # the operator rung (ceiling-cisco_iosxe.md). So operator is 7 here, not
+    # admin's 15 (decision 25), and the reference configuration carries the
+    # line that gives 7 its commands.
+    privilege:
+      readonly: ["priv-lvl=1"]
+      operator: ["priv-lvl=7"]
+      admin: ["priv-lvl=15"]
+    # No entity class is defined: the lab's management interface is
+    # GigabitEthernet1, a physical port by name.
     #
     # `sh ver` arrived as `show version` over SSH (L21-cisco_iosxe.md);
     # RESTCONF and NETCONF are unmeasured.
````

<!-- patch: platforms/1.0.0/cisco_nxos.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_nxos.yaml b/platforms/1.0.0/cisco_nxos.yaml
index 92603fc..ddb18b9 100644
--- a/platforms/1.0.0/cisco_nxos.yaml
+++ b/platforms/1.0.0/cisco_nxos.yaml
@@ -6,10 +6,27 @@ platforms:
     # Session and per-command authorization (L1, L10). Config-command
     # authorization is unmeasured, so it is not claimed.
     supports: [session, commands]
-    # No level is rendered yet. The token's ceiling still needs a number:
-    # operator numbers 15, admin's, on the owner's ruling of 2026-09-24 —
-    # every N9Kv role ran all three disruptive commands and network-operator
-    # changed configuration (ceiling-cisco_nxos.md; spec §6, decision 23).
+    # The role alone, never priv-lvl: `shell:roles` decides the role in both
+    # directions and a priv-lvl beside it is inert, the role alone suffices,
+    # and priv-lvl with no role picks one by a per-release table
+    # (tests/lab/results/L16-cisco_nxos.md, 2026-09-22). The flag changes
+    # nothing on this image (L16, L18), so the attribute is optional, the
+    # spelling a device that does not read it must ignore (spec §6).
+    #
+    # While command authorization points at port49 no role narrows anything:
+    # network-operator ran `clear counters`, `clear ip bgp *` and a
+    # configuration change (ceiling-cisco_nxos.md), so port49's rules are the
+    # fence for every level (decision 23). When the device falls back to
+    # local, the role binds: network-operator is refused a configuration
+    # command, network-admin is not (L16-cisco_nxos.md, command authorization
+    # LOCAL). So operator gets readonly's role (decision 25).
+    privilege:
+      readonly: ["shell:roles*network-operator"]
+      operator: ["shell:roles*network-operator"]
+      admin: ["shell:roles*network-admin"]
+    # No priv-lvl is rendered, so the token's ceiling takes its number here:
+    # operator numbers 15, admin's, on the owner's ruling of 2026-09-24
+    # (spec §6, decision 23).
     ceiling_levels: {readonly: 1, operator: 15, admin: 15}
     # mgmt0 is the interface the lab reaches the device on
     # (tests/lab/configs/nxos-startup.cfg).
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add platforms internal
git commit -m "feat: NX-OS is told its role, IOS-XE its level, operator at 7 (decision 25)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: IOS-XE takes `priv-lvl` alone, and the adapters carry their device configuration

**Files:**
- Modify: `internal/platform/dialect.go`, `internal/platform/adapter.go` (`AcceptedAttributes`,
  `DeviceConfig`: field, key, `Over`, `Validate`)
- Modify: `platforms/1.0.0/*.yaml` (IOS-XE `accepted_attributes`; `device_config` on the three)
- Modify: `internal/policy/resolve.go` (`checkDeviceAt`)
- Modify: `tests/lab/configs/iosxe-startup.cfg` (level 7's lines)
- Test: `internal/platform/adapter_test.go`, `internal/policy/{diff,resolve}_test.go`

**Interfaces:**
- Produces: `Dialect.AcceptedAttributes []string` (nil takes any name); `Dialect.DeviceConfig
  []string`; keys `accepted_attributes`, `device_config`. `Validate` refuses a rendering the
  platform does not accept, and a configuration line that is not one printable line.
- The joint check quarantines a composition whose reply carries a name not in
  `AcceptedAttributes`, naming the attribute and its source (Decided 6).

The diff test's `all: [idletime*30]` row moves from `xe-01`, now quarantined for it, to `nx-01`.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index 4514c51..c4dce17 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -25,6 +25,7 @@ var shipped = map[string]Dialect{
 			"operator": {"priv-lvl=15", "roles=network-operator"}, "admin": {"priv-lvl=15", "roles=network-admin"}},
 		PrivilegeAttributes: []string{"priv-lvl", "roles"},
 		InertAttributes:     []string{"home-directory"},
+		DeviceConfig:        []string{"aaa authorization commands all default group port49 local"},
 	},
 	"cisco_nxos": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true,
@@ -36,6 +37,8 @@ var shipped = map[string]Dialect{
 		CeilingLevels:       map[string]uint8{"readonly": 1, "operator": 15, "admin": 15},
 		PrivilegeAttributes: []string{"priv-lvl", "shell:roles", "cisco-av-pair"},
 		InertAttributes:     []string{"home-directory"},
+		DeviceConfig: []string{"aaa authorization commands default group port49 local",
+			"aaa authorization config-commands default group port49 local"},
 	},
 	"cisco_iosxe": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true, SplitsInterfaceNames: true,
@@ -44,6 +47,11 @@ var shipped = map[string]Dialect{
 		Levels:              map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=7"}, "admin": {"priv-lvl=15"}},
 		PrivilegeAttributes: []string{"priv-lvl"},
 		InertAttributes:     []string{"home-directory"},
+		AcceptedAttributes:  []string{"priv-lvl"},
+		DeviceConfig: []string{"aaa authorization commands 1 default group port49 local",
+			"aaa authorization commands 7 default group port49 local",
+			"aaa authorization commands 15 default group port49 local",
+			"aaa accounting commands 7 default start-stop group port49", "privilege exec level 7 clear counters"},
 	},
 	"juniper_junos": {
 		PipeToken: "|", StripCR: true,
@@ -209,6 +217,10 @@ func TestValidateNamesTheField(t *testing.T) {
 			d.Levels, d.InertAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"roles"}
 		}),
 		"inert_attributes: priv-lvl": with(ok, func(d *Dialect) { d.InertAttributes = []string{"priv-lvl"} }),
+		"not in accepted_attributes": with(ok, func(d *Dialect) {
+			d.Levels, d.AcceptedAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"priv-lvl"}
+		}),
+		"device_config[0]": with(ok, func(d *Dialect) { d.DeviceConfig = []string{"line one\nline two"} }),
 	} {
 		err := Validate("x", d)
 		if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "platforms.x.") {
````

<!-- patch: internal/policy/diff_test.go -->
````diff
diff --git a/internal/policy/diff_test.go b/internal/policy/diff_test.go
index cb79814..0c90e00 100644
--- a/internal/policy/diff_test.go
+++ b/internal/policy/diff_test.go
@@ -560,7 +560,7 @@ func TestTheGateFailsAPrivilegeAttributeInTheReply(t *testing.T) {
 		{`{juniper_junos: [local-user-name=super-user]}`, "srx-lab-01", `["local-user-name=super-user"]`},
 		{`{cisco_nxos: ["shell:roles=network-admin"]}`, "nx-01", `["shell:roles=network-admin"]`},
 		{`{arista_eos: ["roles=network-admin"]}`, "leaf-01", `["priv-lvl=1", "roles=network-admin"]`},
-		{`{all: ["idletime*30"]}`, "xe-01", `["priv-lvl=1", "idletime*30"]`},
+		{`{all: ["idletime*30"]}`, "nx-01", `["shell:roles*network-operator", "idletime*30"]`},
 	} {
 		after := strings.Replace(diffBase, "roles: [read_only, cve]}", "roles: [read_only, cve], attributes: "+tt.attrs+"}", 1)
 		d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
````

<!-- patch: internal/policy/resolve_test.go -->
````diff
diff --git a/internal/policy/resolve_test.go b/internal/policy/resolve_test.go
index c29f8a9..39b8d0e 100644
--- a/internal/policy/resolve_test.go
+++ b/internal/policy/resolve_test.go
@@ -553,3 +553,32 @@ grants: [{subject: s, scope: all_devices, roles: [adm], max_privilege: operator}
 		}
 	}
 }
+
+// IOS-XE refuses the whole session for an attribute it does not take, under
+// either flag, and a run of refusals stops it answering SSH, break-glass
+// included (tests/lab/results/L18-cisco_iosxe.md). A composition whose reply
+// would carry one quarantines the device, naming the attribute and where it
+// came from; one keyed to other platforms leaves IOS-XE alone.
+func TestAnAttributeIOSXEDoesNotTakeQuarantinesIt(t *testing.T) {
+	body := `
+scopes: [{name: all_devices, match: {}}]
+roles: [{name: ro, privilege: readonly, permit: [show **], attributes: {KEY: ["idletime*30"]}}]
+subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
+grants: [{subject: s, scope: all_devices, roles: [ro]}]`
+	p := mustParse(t, strings.Replace(body, "KEY", "all", 1))
+	q := p.Quarantines(noon)
+	if len(q) != 1 || q[0].Device != "xe-01" || !strings.Contains(causesOf(q[0])[0],
+		"its session reply sends idletime*30 (role ro), and cisco_iosxe takes no attribute but priv-lvl") {
+		t.Fatalf("quarantines: %+v", q)
+	}
+	for _, key := range []string{"arista_eos", "cisco_nxos"} {
+		if q := mustParse(t, strings.Replace(body, "KEY", key, 1)).Quarantines(noon); len(q) != 0 {
+			t.Errorf("%s: %+v", key, q)
+		}
+	}
+	// priv-lvl is what it takes, from the level or from a role.
+	ok := strings.Replace(strings.Replace(body, "KEY", "cisco_iosxe", 1), "idletime*30", "priv-lvl=1", 1)
+	if q := mustParse(t, ok).Quarantines(noon); len(q) != 0 {
+		t.Fatalf("%+v", q)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/`
Expected: FAIL — `d.AcceptedAttributes undefined`, `d.DeviceConfig undefined` (build failed), and
`TestAnAttributeIOSXEDoesNotTakeQuarantinesIt`.

- [ ] **Step 3: Add the keys, the check and the configuration**

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index 8767b09..39671fd 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -31,6 +31,8 @@ type Spec struct {
 	ShowsServerMsg       *bool                `yaml:"shows_server_msg"`
 	PrivilegeAttributes  *[]string            `yaml:"privilege_attributes"`
 	InertAttributes      *[]string            `yaml:"inert_attributes"`
+	AcceptedAttributes   *[]string            `yaml:"accepted_attributes"`
+	DeviceConfig         *[]string            `yaml:"device_config"`
 }
 
 // ParseSpecs reads an adapter file: one YAML document whose one key is
@@ -98,6 +100,12 @@ func (s Spec) Over(base Dialect) Dialect {
 	if s.InertAttributes != nil {
 		d.InertAttributes = slices.Clone(*s.InertAttributes)
 	}
+	if s.AcceptedAttributes != nil {
+		d.AcceptedAttributes = slices.Clone(*s.AcceptedAttributes)
+	}
+	if s.DeviceConfig != nil {
+		d.DeviceConfig = slices.Clone(*s.DeviceConfig)
+	}
 	return d
 }
 
@@ -180,7 +188,8 @@ func Validate(name string, d Dialect) error {
 	for _, list := range []struct {
 		name  string
 		names []string
-	}{{"privilege_attributes", d.PrivilegeAttributes}, {"inert_attributes", d.InertAttributes}} {
+	}{{"privilege_attributes", d.PrivilegeAttributes}, {"inert_attributes", d.InertAttributes},
+		{"accepted_attributes", d.AcceptedAttributes}} {
 		for _, n := range list.names {
 			if n == "" || strings.ContainsAny(n, "=* \t") {
 				return fmt.Errorf("%s: %q is not an attribute name", field(list.name), n)
@@ -204,5 +213,22 @@ func Validate(name string, d Dialect) error {
 			return fmt.Errorf("%s: %s: a level renders it, so it carries privilege", field("inert_attributes"), n)
 		}
 	}
+	if d.AcceptedAttributes != nil {
+		// The adapter's own rendering has to be something the device takes,
+		// or every session at that level is refused.
+		for _, level := range sortedKeys(d.Levels) {
+			for _, a := range d.Levels[level] {
+				if n := engine.AttributeName(a); !slices.Contains(d.AcceptedAttributes, n) {
+					return fmt.Errorf("%s: %s is not in accepted_attributes, so the device would refuse every session "+
+						"at %s", field("privilege."+level), n, level)
+				}
+			}
+		}
+	}
+	for i, line := range d.DeviceConfig {
+		if strings.TrimSpace(line) == "" || strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
+			return fmt.Errorf("%s[%d]: one printable ASCII configuration line", field("device_config"), i)
+		}
+	}
 	return nil
 }
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index 06f337c..e2735b7 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -73,6 +73,16 @@ type Dialect struct {
 	// diff does not gate. An attribute in neither list bears privilege: the
 	// gate and the load fail closed on what nobody listed.
 	InertAttributes []string
+	// AcceptedAttributes, where it is not nil, is every attribute name this
+	// platform's session reply may carry: the device refuses the whole session
+	// for any other (IOS-XE, L18), so a composition whose reply carries one
+	// fails the joint check and quarantines the device. nil takes any name.
+	AcceptedAttributes []string
+	// DeviceConfig is the device configuration this adapter's renderings
+	// depend on, one line each: `port49 platform show` prints it, and a device
+	// without it does not get what the level promises (IOS-XE's level 7 is
+	// level 1 until it is given commands, ceiling-cisco_iosxe.md).
+	DeviceConfig []string
 }
 
 // builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
@@ -122,6 +132,8 @@ func (d Dialect) clone() Dialect {
 	d.Supports = append([]string(nil), d.Supports...)
 	d.PrivilegeAttributes = slices.Clone(d.PrivilegeAttributes)
 	d.InertAttributes = slices.Clone(d.InertAttributes)
+	d.AcceptedAttributes = slices.Clone(d.AcceptedAttributes)
+	d.DeviceConfig = slices.Clone(d.DeviceConfig)
 	if d.EntityClasses != nil {
 		classes := make(map[string][]string, len(d.EntityClasses))
 		for k, v := range d.EntityClasses {
````

<!-- patch: internal/policy/resolve.go -->
````diff
diff --git a/internal/policy/resolve.go b/internal/policy/resolve.go
index e47027e..168beb3 100644
--- a/internal/policy/resolve.go
+++ b/internal/policy/resolve.go
@@ -465,6 +465,21 @@ func (p *Policy) checkDeviceAt(sub *Subject, d admission.Device, at time.Time) s
 				res.Attributes[at].Attribute, res.Attributes[at].Source, res.Ceiling, res.MaxPrivilege)
 		}
 	}
+	// A platform that refuses a session for any attribute it does not take
+	// is never sent one: the device would refuse every login, and on IOS-XE a
+	// run of refusals stops it answering SSH for about a minute, break-glass
+	// included (tests/lab/results/L18-cisco_iosxe.md). Quarantined, the
+	// device is closed without a reply and falls to local at once.
+	if accepted := p.dialect(d.Platform).AcceptedAttributes; accepted != nil {
+		for _, a := range res.Attributes {
+			if name := engine.AttributeName(a.Attribute); !slices.Contains(accepted, name) {
+				return fmt.Sprintf("on %s its session reply sends %s (%s), and %s takes no attribute but %s: the "+
+					"device refuses the whole session for any other, and a run of refusals stops it answering SSH, "+
+					"break-glass included (tests/lab/results/L18-cisco_iosxe.md); key the attribute to the platforms "+
+					"that read it", d.Platform, a.Attribute, a.Source, d.Platform, strings.Join(accepted, ", "))
+			}
+		}
+	}
 	if sub.Enable == "auto" {
 		if eu := p.env.EnableUsernames[d.Platform]; eu != "" && eu != platform.EnablePrincipal {
 			return fmt.Sprintf("enable: auto reaches this device, whose platform %s does not put the operator's "+
````

<!-- patch: platforms/1.0.0/arista_eos.yaml -->
````diff
diff --git a/platforms/1.0.0/arista_eos.yaml b/platforms/1.0.0/arista_eos.yaml
index 786f51b..63b3203 100644
--- a/platforms/1.0.0/arista_eos.yaml
+++ b/platforms/1.0.0/arista_eos.yaml
@@ -25,6 +25,11 @@ platforms:
       readonly: ["priv-lvl=1", "roles=network-operator"]
       operator: ["priv-lvl=15", "roles=network-operator"]
       admin: ["priv-lvl=15", "roles=network-admin"]
+    # The command method list must end in local, never none or
+    # if-authenticated: an operator session at 15 would run every command when
+    # port49 cannot answer (spec §6, decision 23). The group name is the lab's.
+    device_config:
+      - aaa authorization commands all default group port49 local
     # Interface names, not device behaviour: spec §8's example.
     entity_classes:
       management: ['^Management[0-9]+$']
````

<!-- patch: platforms/1.0.0/cisco_iosxe.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_iosxe.yaml b/platforms/1.0.0/cisco_iosxe.yaml
index 6f3a74d..84533e8 100644
--- a/platforms/1.0.0/cisco_iosxe.yaml
+++ b/platforms/1.0.0/cisco_iosxe.yaml
@@ -22,6 +22,21 @@ platforms:
       readonly: ["priv-lvl=1"]
       operator: ["priv-lvl=7"]
       admin: ["priv-lvl=15"]
+    # The only attribute this image takes: anything else refuses the session,
+    # and a policy whose reply would carry one quarantines the device instead
+    # (L18-cisco_iosxe.md; decision 25).
+    accepted_attributes: [priv-lvl]
+    # What level 7 needs from the device: a command list for each level
+    # port49 renders, so the device asks port49 about level-7 commands, and
+    # the one command the measured operator rung runs. The request carries the
+    # command's level, not the session's (ceiling-cisco_iosxe.md). The group
+    # name is the lab's.
+    device_config:
+      - aaa authorization commands 1 default group port49 local
+      - aaa authorization commands 7 default group port49 local
+      - aaa authorization commands 15 default group port49 local
+      - aaa accounting commands 7 default start-stop group port49
+      - privilege exec level 7 clear counters
     # No entity class is defined: the lab's management interface is
     # GigabitEthernet1, a physical port by name.
     #
````

<!-- patch: platforms/1.0.0/cisco_nxos.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_nxos.yaml b/platforms/1.0.0/cisco_nxos.yaml
index ddb18b9..3bc5ba2 100644
--- a/platforms/1.0.0/cisco_nxos.yaml
+++ b/platforms/1.0.0/cisco_nxos.yaml
@@ -24,6 +24,12 @@ platforms:
       readonly: ["shell:roles*network-operator"]
       operator: ["shell:roles*network-operator"]
       admin: ["shell:roles*network-admin"]
+    # The command method list must end in local, where the delivered role
+    # binds (L16-cisco_nxos.md, command authorization LOCAL; spec §6,
+    # decision 23). The group name is the lab's.
+    device_config:
+      - aaa authorization commands default group port49 local
+      - aaa authorization config-commands default group port49 local
     # No priv-lvl is rendered, so the token's ceiling takes its number here:
     # operator numbers 15, admin's, on the owner's ruling of 2026-09-24
     # (spec §6, decision 23).
````

<!-- patch: tests/lab/configs/iosxe-startup.cfg -->
````diff
diff --git a/tests/lab/configs/iosxe-startup.cfg b/tests/lab/configs/iosxe-startup.cfg
index 2747603..ccacaa7 100644
--- a/tests/lab/configs/iosxe-startup.cfg
+++ b/tests/lab/configs/iosxe-startup.cfg
@@ -103,14 +103,23 @@ aaa authorization exec default group port49 local
 ! no authorization request for anything an unprivileged session types -- which
 ! is the half of L2 and L10 that matters after a `disable`.
 aaa authorization commands 1 default group port49 local
+aaa authorization commands 7 default group port49 local
 aaa authorization commands 15 default group port49 local
 !
+! Level 7 is port49's `operator` on this platform (plan 5, decision 25), and
+! it is level 1 until the device is told what it may run: this line is the
+! operator rung measured in tests/lab/results/ceiling-cisco_iosxe.md --
+! `clear counters` yes, `clear ip bgp *` and `configure terminal` no. The
+! commands 7 list above is what sends a level-7 command to port49 at all.
+privilege exec level 7 clear counters
+!
 ! Without this, commands typed inside configuration mode are not authorized at
 ! all and L2's denial would never be reachable from `configure terminal`.
 aaa authorization config-commands
 !
 aaa accounting exec default start-stop group port49
 aaa accounting commands 1 default start-stop group port49
+aaa accounting commands 7 default start-stop group port49
 aaa accounting commands 15 default start-stop group port49
 !
 ! ---------------------------------------------------------------------------
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/...`
Expected: every package `ok`. `LC_ALL=C grep -n '[^ -~]' tests/lab/configs/iosxe-startup.cfg`
prints nothing (the harness refuses a non-ASCII startup config).

- [ ] **Step 5: Commit**

```bash
git add platforms internal tests/lab/configs/iosxe-startup.cfg
git commit -m "feat: IOS-XE takes priv-lvl alone; adapters carry their device configuration

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: A policy pins its platform set

**Files:**
- Modify: `internal/platform/set.go` (`UnpinnedSet`)
- Modify: `internal/policy/file.go` (`platform_set`), `internal/policy/load.go` (`buildPlatforms`,
  `PlatformSet`; `platforms()` and `dialect()` read the pinned set; the `platform_set` refusal goes)
- Modify: `cmd/port49/policy.go` (`policy test` prints the set first)
- Test: `internal/policy/load_test.go`, `internal/policy/testdata/spec11.yaml` (comment only, same
  line count, so `edit_test.go`'s line numbers hold), `cmd/port49/policy_test.go`

**Interfaces:**
- Produces: `const platform.UnpinnedSet = "1.0.0"`; `func (p *Policy) PlatformSet() string`.
  `policy.Env.Dialects` now lays over the pinned set rather than over the built-in table.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/policy_test.go -->
````diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index 510f990..4ac442f 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -105,11 +105,13 @@ func TestPolicyToolsExitTwoOnAUsageError(t *testing.T) {
 }
 
 // `port49 policy test` passes a policy whose tests pass, and fails one whose
-// test does not, naming it.
+// test does not, naming it. It says first which platform set the policy
+// renders with (spec §8).
 func TestPolicyTestIsACIGate(t *testing.T) {
 	pol, inv := policyFixture(t)
 	var out, errb bytes.Buffer
 	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
+		!strings.HasPrefix(out.String(), "platform_set: 1.0.0\n") ||
 		!strings.Contains(out.String(), "PASS noc on leaf-01: \"reload\" -> deny no_rule_matched") ||
 		!strings.Contains(out.String(), "2 tests, 0 failed; 0 shadowed denies, 0 unacknowledged") {
 		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
````

<!-- patch: internal/policy/load_test.go -->
````diff
diff --git a/internal/policy/load_test.go b/internal/policy/load_test.go
index fbb1e71..c27fad5 100644
--- a/internal/policy/load_test.go
+++ b/internal/policy/load_test.go
@@ -4,6 +4,7 @@ import (
 	"net/netip"
 	"os"
 	"path/filepath"
+	"reflect"
 	"strings"
 	"testing"
 
@@ -128,7 +129,7 @@ const grantOK = "grants:\n  - {subject: s, scope: all_devices, roles: [r]}\n"
 // plan lifts it.
 func TestLoadRefusesByName(t *testing.T) {
 	for _, tt := range []struct{ name, yaml, want string }{
-		{"platform_set", "platform_set: 1.4.0\n" + roleOK + subjOK, "plan 5"},
+		{"a platform set this binary does not ship", "platform_set: 1.4.0\n" + roleOK + subjOK, "it ships 1.0.0"},
 		{"key_groups", "key_groups: []\n" + roleOK + subjOK, "inventory file"},
 		{"platforms", "platforms: {arista_eos: {}}\n" + roleOK + subjOK, "plan 5"},
 		{"a role's max_session_age", "roles:\n  - {name: r, max_session_age: 8h}\n" + subjOK, "plan 7"},
@@ -440,3 +441,21 @@ func TestAPlaceholderGoesOnlyInAnInertAttribute(t *testing.T) {
 		}
 	}
 }
+
+// A policy pins the platform set it renders with (spec §8). One that pins none
+// renders with 1.0.0, the first set, on every binary; a set this binary does
+// not ship is refused by name (TestLoadRefusesByName).
+func TestAPolicyPinsItsPlatformSet(t *testing.T) {
+	body := scopeOK + roleOK + subjOK + grantOK
+	if p := mustParse(t, body); p.PlatformSet() != platform.UnpinnedSet || p.PlatformSet() != "1.0.0" {
+		t.Fatalf("unpinned: %q", p.PlatformSet())
+	}
+	p := mustParse(t, "platform_set: 1.0.0\n"+body)
+	if p.PlatformSet() != "1.0.0" {
+		t.Fatalf("pinned: %q", p.PlatformSet())
+	}
+	want, _ := platform.Set("1.0.0")
+	if got := p.Dialect("cisco_iosxe"); !reflect.DeepEqual(got, want["cisco_iosxe"]) {
+		t.Fatalf("the pinned set's adapter: %+v", got)
+	}
+}
````

<!-- patch: internal/policy/testdata/spec11.yaml -->
````diff
diff --git a/internal/policy/testdata/spec11.yaml b/internal/policy/testdata/spec11.yaml
index 997ab19..0a2ee32 100644
--- a/internal/policy/testdata/spec11.yaml
+++ b/internal/policy/testdata/spec11.yaml
@@ -2,8 +2,8 @@
 # are not here, and two values are, each corrected in the spec by the same
 # plan:
 #
-#   - `platform_set` is plan 5's and `key_groups` live in the inventory file
-#     until plan 6 (spec11-inventory.yaml carries §11's two groups).
+#   - `platform_set` is left to its default, 1.0.0, and `key_groups` live in the
+#     inventory file until plan 6 (spec11-inventory.yaml carries both groups).
 #   - svc_oxidized declares the username spec §2 gives it. A machine subject
 #     with no username fails at load (spec §14, "Username resolution"), and
 #     §11 as printed omitted it.
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/`
Expected: FAIL — `p.PlatformSet undefined`, `undefined: platform.UnpinnedSet` (build failed), and
`TestPolicyTestIsACIGate` (no `platform_set:` line).

- [ ] **Step 3: Pin it**

<!-- patch: cmd/port49/policy.go -->
````diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index f6f9f9e..6a2d61d 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -124,6 +124,9 @@ func policyTest(args []string, stdout, stderr io.Writer) int {
 		return 1
 	}
 	now := time.Now()
+	// The set the policy renders with, first: a reviewer reading a rendering
+	// change needs to know which adapters produced it (spec §8).
+	fmt.Fprintf(stdout, "platform_set: %s\n", p.PlatformSet())
 	// A quarantined device is reported, not a failure of its own: the policy
 	// loaded, and decision 20 exists so one device cannot block the rest. A
 	// test on it fails in the ordinary way, as device_quarantined. An entry an
````

<!-- patch: internal/platform/set.go -->
````diff
diff --git a/internal/platform/set.go b/internal/platform/set.go
index 2225ed2..001f47c 100644
--- a/internal/platform/set.go
+++ b/internal/platform/set.go
@@ -11,10 +11,16 @@ import (
 	"github.com/blanketfish/port49/platforms"
 )
 
-// DefaultSet is the platform set this build renders with: the one a policy
-// that pins none gets (spec §8, "the platform set is pinned").
+// DefaultSet is the newest set this build ships: what `port49 platform`
+// shows and exports unless asked for another.
 const DefaultSet = "1.0.0"
 
+// UnpinnedSet is the set a policy that pins none renders with, and it never
+// moves: 1.0.0 is the first set, so a policy written before pinning existed
+// renders the same on every later binary (spec §8, "the platform set is
+// pinned"). A policy moves forward only by pinning a newer set.
+const UnpinnedSet = "1.0.0"
+
 // sets is every built-in platform set, by version, parsed and validated once.
 // An embedded file that does not load is a build defect, never an operator's
 // error, so it panics at start rather than degrading; TestEmbeddedSetsLoad is
````

<!-- patch: internal/policy/file.go -->
````diff
diff --git a/internal/policy/file.go b/internal/policy/file.go
index a6a2ac6..c892df4 100644
--- a/internal/policy/file.go
+++ b/internal/policy/file.go
@@ -11,6 +11,7 @@ import (
 // declared: the decoder refuses one it does not know rather than ignoring it,
 // because an ignored key is a policy that reads one way and runs another.
 type file struct {
+	PlatformSet     string        `yaml:"platform_set"`
 	PrivilegeLevels []fileLevel   `yaml:"privilege_levels"`
 	Scopes          []fileScope   `yaml:"scopes"`
 	Roles           []fileRole    `yaml:"roles"`
````

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index 51e0652..deb3926 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -37,8 +37,8 @@ type Env struct {
 	// Devices is the inventory: the file inventory the daemon admits from,
 	// until plan 6's bundle.
 	Devices []admission.Device
-	// Dialects replaces the built-in platform table when non-nil. Tests use it;
-	// plan 5's layered adapters will too.
+	// Dialects replaces platforms of the pinned set when non-nil: tests use
+	// it to stand a platform up with other behaviour.
 	Dialects map[string]platform.Dialect
 	// EnableUsernames is config's resolved table (config.Config); a platform
 	// with no entry is `principal`.
@@ -54,6 +54,11 @@ type Policy struct {
 	// file's bytes, until plan 6 publishes versioned bundles (spec §5.7).
 	Bundle string
 
+	// set is the platform set the policy pins (spec §8), and adapters its
+	// platforms: the built-in set, Env.Dialects over it.
+	set      string
+	adapters map[string]platform.Dialect
+
 	levels  []string          // the declared ordering, lowest first
 	parents map[string]string // level → parent, for rendering
 	scopes  map[string]*Scope
@@ -196,7 +201,7 @@ func Parse(raw []byte, env Env) (*Policy, error) {
 			"everything after it, or merge it into the first document")
 	}
 	p := &Policy{Bundle: engine.HashOf(raw), env: env}
-	for _, step := range []func(file) error{p.buildLevels, p.buildRoles, p.buildScopes, p.buildSubjects,
+	for _, step := range []func(file) error{p.buildPlatforms, p.buildLevels, p.buildRoles, p.buildScopes, p.buildSubjects,
 		p.buildGrants, p.checkMinters, p.buildTests, p.buildAcknowledgments} {
 		if err := step(f); err != nil {
 			return nil, err
@@ -216,17 +221,14 @@ func Parse(raw []byte, env Env) (*Policy, error) {
 // carries two of them.
 func refusedKeys(raw []byte) error {
 	var loose struct {
-		PlatformSet any              `yaml:"platform_set"`
-		KeyGroups   any              `yaml:"key_groups"`
-		Platforms   any              `yaml:"platforms"`
-		Roles       []map[string]any `yaml:"roles"`
+		KeyGroups any              `yaml:"key_groups"`
+		Platforms any              `yaml:"platforms"`
+		Roles     []map[string]any `yaml:"roles"`
 	}
 	if err := yaml.Unmarshal(raw, &loose); err != nil {
 		return nil // the strict decode reports it, with a line number
 	}
 	switch {
-	case loose.PlatformSet != nil:
-		return errors.New("platform_set: pinning the platform set is plan 5's; remove the key until it lands")
 	case loose.KeyGroups != nil:
 		return errors.New("key_groups: key groups live in the inventory file (inventory_file) until plan 6 " +
 			"moves them to the policy repository; move the block there")
@@ -246,6 +248,29 @@ func refusedKeys(raw []byte) error {
 	return nil
 }
 
+// buildPlatforms resolves the platform set the policy pins, or UnpinnedSet
+// where it pins none (spec §8): a binary upgrade never changes what a policy
+// renders, and a set this binary does not ship is refused by name.
+func (p *Policy) buildPlatforms(f file) error {
+	p.set = f.PlatformSet
+	if p.set == "" {
+		p.set = platform.UnpinnedSet
+	}
+	set, ok := platform.Set(p.set)
+	if !ok {
+		return fmt.Errorf("platform_set: %s is not a set this binary ships; it ships %s. Pin one of those, or run "+
+			"a binary that ships %s (spec §8)", p.set, strings.Join(platform.Sets(), ", "), p.set)
+	}
+	for name, d := range p.env.Dialects {
+		set[name] = d
+	}
+	p.adapters = set
+	return nil
+}
+
+// PlatformSet is the platform set the policy renders with.
+func (p *Policy) PlatformSet() string { return p.set }
+
 func (p *Policy) buildLevels(f file) error {
 	p.parents = map[string]string{}
 	if len(f.PrivilegeLevels) == 0 {
@@ -855,15 +880,10 @@ func (p *Policy) device(name string) (admission.Device, bool) {
 	return admission.Device{}, false
 }
 
-// platforms is every dialect this policy can meet: the built-in table with
-// the environment's own table over it.
-func (p *Policy) platforms() map[string]platform.Dialect {
-	out := platform.Dialects()
-	for name, d := range p.env.Dialects {
-		out[name] = d
-	}
-	return out
-}
+// platforms is every dialect this policy can meet: its pinned set, the
+// environment's own table over it. The map is the policy's own; callers read
+// it and never write it.
+func (p *Policy) platforms() map[string]platform.Dialect { return p.adapters }
 
 // checkClasses refuses a rule naming a class no platform defines. That is
 // the policy's own error, a typo, rather than a device's: no inventory could
@@ -930,14 +950,13 @@ func (p *Policy) privLvl(dialect platform.Dialect, level string) (uint8, bool) {
 	return 0, false
 }
 
-// dialect is the platform's dialect under this policy's environment.
+// dialect is the platform's dialect in this policy's set, or the generic
+// adapter for a platform the set has none for (spec §8, "Unknown platforms").
 func (p *Policy) dialect(name string) platform.Dialect {
-	if p.env.Dialects != nil {
-		if d, ok := p.env.Dialects[name]; ok {
-			return d
-		}
+	if d, ok := p.adapters[name]; ok {
+		return d
 	}
-	d, _ := platform.DialectFor(name)
+	d, _ := platform.DialectFor("")
 	return d
 }
 
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal cmd
git commit -m "feat: a policy pins its platform set; unpinned is 1.0.0, forever

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: The policy file's `platforms:` block overrides and adds adapters

**Files:**
- Modify: `internal/platform/adapter.go` (`Over` merges a map per entry)
- Modify: `internal/policy/file.go` (`filePlatform`), `internal/policy/load.go` (blocks in
  `buildPlatforms`; `checkDenyClasses`; attributes keyed by an operator's platform; the
  `platforms:` refusal goes), `internal/policy/lint.go` (`platform_override_redundant`)
- Test: `internal/platform/adapter_test.go`, `internal/policy/load_test.go`,
  `internal/policy/platforms_test.go`

**Interfaces:**
- Produces: `FindingPlatformOverride = "platform_override_redundant"`. `Spec.Over` merges
  `privilege`, `ceiling_levels` and `entity_classes` per entry. A block's `replace: true` starts
  from the generic adapter; `based_on: <name>` from a platform the pinned set ships, under a new
  name only. A deny naming a class whose pattern on any platform turns case-insensitivity off is
  refused at load (the roadmap's `(?-i)` hand-off). A block named `all` or `default` is refused:
  `attributes.all` and the redaction table's `default` already name every platform (pre-flight
  N7).

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index c4dce17..f7f87b7 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -176,16 +176,21 @@ func TestParseSpecsIsStrict(t *testing.T) {
 	}
 }
 
-// Over replaces what a block sets, whole, and keeps the rest.
-func TestOverReplacesOnlyWhatIsSet(t *testing.T) {
-	specs, err := ParseSpecs([]byte("platforms:\n  arista_eos:\n    entity_classes:\n      uplink: ['^Ethernet49$']\n"))
+// Over merges a map a block sets per entry, replaces a list or a value
+// whole, and keeps what the block leaves out (spec §8's "adds one class,
+// inherits everything else").
+func TestOverMergesPerTopLevelKey(t *testing.T) {
+	specs, err := ParseSpecs([]byte("platforms:\n  arista_eos:\n    entity_classes:\n      uplink: ['^Ethernet49$']\n" +
+		"      management: ['^Management1$']\n    supports: [session]\n"))
 	if err != nil {
 		t.Fatal(err)
 	}
 	base, _ := DialectFor("arista_eos")
 	d := specs["arista_eos"].Over(base)
-	if !reflect.DeepEqual(d.EntityClasses, map[string][]string{"uplink": {`^Ethernet49$`}}) {
-		t.Fatalf("classes: %v", d.EntityClasses)
+	want := map[string][]string{"uplink": {`^Ethernet49$`}, "management": {`^Management1$`},
+		"loopback": base.EntityClasses["loopback"], "physical": base.EntityClasses["physical"]}
+	if !reflect.DeepEqual(d.EntityClasses, want) || !reflect.DeepEqual(d.Supports, []string{"session"}) {
+		t.Fatalf("classes: %v supports %v", d.EntityClasses, d.Supports)
 	}
 	if !reflect.DeepEqual(d.Levels, base.Levels) || !d.ExpandsAbbreviations {
 		t.Fatalf("the rest is the base's: %+v", d)
````

<!-- patch: internal/policy/load_test.go -->
````diff
diff --git a/internal/policy/load_test.go b/internal/policy/load_test.go
index c27fad5..0da7ceb 100644
--- a/internal/policy/load_test.go
+++ b/internal/policy/load_test.go
@@ -131,7 +131,6 @@ func TestLoadRefusesByName(t *testing.T) {
 	for _, tt := range []struct{ name, yaml, want string }{
 		{"a platform set this binary does not ship", "platform_set: 1.4.0\n" + roleOK + subjOK, "it ships 1.0.0"},
 		{"key_groups", "key_groups: []\n" + roleOK + subjOK, "inventory file"},
-		{"platforms", "platforms: {arista_eos: {}}\n" + roleOK + subjOK, "plan 5"},
 		{"a role's max_session_age", "roles:\n  - {name: r, max_session_age: 8h}\n" + subjOK, "plan 7"},
 		{"an unknown key", scopeOK + roleOK + subjOK + "gratns: []\n", "field gratns not found"},
 		{"a second document", scopeOK + roleOK + subjOK + grantOK + "---\nscopes: []\n", "one YAML document"},
````

<!-- patch: internal/policy/platforms_test.go -->
````diff
diff --git a/internal/policy/platforms_test.go b/internal/policy/platforms_test.go
new file mode 100644
index 0000000..ec8096a
--- /dev/null
+++ b/internal/policy/platforms_test.go
@@ -0,0 +1,168 @@
+package policy
+
+import (
+	"net/netip"
+	"reflect"
+	"strings"
+	"testing"
+
+	"github.com/blanketfish/port49/internal/admission"
+	"github.com/blanketfish/port49/internal/platform"
+)
+
+// withDevice is the test inventory with one more device, of a platform the
+// built-in set does not ship.
+func withDevice(name, platformName string) Env {
+	e := env()
+	e.Devices = append(e.Devices, admission.Device{Name: name, Platform: platformName,
+		Addresses: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})
+	return e
+}
+
+// A `platforms:` block merges over the pinned set per top-level key: a map
+// per entry, so a block adding one class keeps the rest; a list or value
+// whole (spec §8, "User-editable, day one").
+func TestAPlatformBlockMergesOverTheBuiltIn(t *testing.T) {
+	p := mustParse(t, `
+platforms:
+  arista_eos:
+    entity_classes:
+      uplink: ['^Ethernet(49|50)$']
+`+scopeOK+`roles:
+  - {name: r, privilege: admin, permit: ["**"], deny: [interface @uplink]}
+`+subjOK+grantOK)
+	eos := p.Dialect("arista_eos")
+	builtin, _ := platform.DialectFor("arista_eos")
+	if !reflect.DeepEqual(eos.EntityClasses["uplink"], []string{`^Ethernet(49|50)$`}) ||
+		!reflect.DeepEqual(eos.EntityClasses["management"], builtin.EntityClasses["management"]) ||
+		!reflect.DeepEqual(eos.Levels, builtin.Levels) {
+		t.Fatalf("arista_eos: %+v", eos)
+	}
+	d := deviceNamed(t, "leaf-01")
+	if _, o, err := p.Decide("s", "", d, "interface Ethernet49", noon); err != nil || o.Permit {
+		t.Fatalf("the operator's class binds on EOS: %+v %v", o, err)
+	}
+	// The class is EOS's alone, so every other platform in inventory fails the
+	// joint check and is quarantined, as with a built-in class (spec §10).
+	if q := p.Quarantines(noon); len(q) != 6 || q[0].Device != "nx-01" {
+		t.Fatalf("quarantines: %+v", q)
+	}
+}
+
+// based_on declares a variant under a new name; replace starts from nothing;
+// a platform the set does not ship starts from the generic adapter. Each is
+// validated as a built-in is.
+func TestAPlatformBlockDeclaresAVariantOrStartsClean(t *testing.T) {
+	body := `
+platforms:
+  whitebox_nos:
+    based_on: arista_eos
+    entity_classes:
+      management: ['^ma1$']
+  meinberg_lantime:
+    supports: [session]
+    privilege:
+      readonly: ["priv-lvl=1"]
+      operator: ["priv-lvl=7"]
+      admin: ["priv-lvl=15"]
+  cisco_iosxe:
+    replace: true
+    privilege:
+      readonly: ["priv-lvl=1"]
+      operator: ["priv-lvl=1"]
+      admin: ["priv-lvl=15"]
+` + scopeOK + roleOK + subjOK + grantOK
+	e := withDevice("wb-01", "whitebox_nos")
+	p, err := Parse([]byte(body), e)
+	if err != nil {
+		t.Fatal(err)
+	}
+	wb, eos := p.Dialect("whitebox_nos"), p.Dialect("arista_eos")
+	if !reflect.DeepEqual(wb.EntityClasses["management"], []string{"^ma1$"}) ||
+		!reflect.DeepEqual(wb.EntityClasses["loopback"], eos.EntityClasses["loopback"]) ||
+		!reflect.DeepEqual(wb.Levels, eos.Levels) || !wb.ExpandsAbbreviations {
+		t.Fatalf("whitebox_nos is EOS with its own management class: %+v", wb)
+	}
+	if d, ok := p.device("wb-01"); !ok {
+		t.Fatal("wb-01")
+	} else if r, err := p.Resolve("user:a@example.com", d, noon); err != nil ||
+		!reflect.DeepEqual(r.Blob.Attributes, []string{"priv-lvl=15", "roles=network-admin"}) {
+		t.Fatalf("wb-01 renders as EOS does: %+v %v", r.Blob.Attributes, err)
+	}
+	lantime := p.Dialect("meinberg_lantime")
+	if n, ok := lantime.PrivLvl("operator"); !ok || n != 7 || lantime.PipeToken != "|" {
+		t.Fatalf("meinberg_lantime starts from the generic adapter: %+v", lantime)
+	}
+	xe := p.Dialect("cisco_iosxe")
+	if xe.AcceptedAttributes != nil || xe.SplitsInterfaceNames || xe.DeviceConfig != nil ||
+		!reflect.DeepEqual(xe.Supports, []string{"session"}) {
+		t.Fatalf("replace discards the built-in: %+v", xe)
+	}
+}
+
+// Every refusal names the block.
+func TestAPlatformBlockIsRefusedByName(t *testing.T) {
+	rest := scopeOK + roleOK + subjOK + grantOK
+	for _, tt := range []struct{ name, block, want string }{
+		{"a name no inventory could write", "  Arista-EOS: {supports: [session]}\n", "platforms.Arista-EOS: a platform name"},
+		{"replace and based_on", "  x: {replace: true, based_on: arista_eos}\n", "platforms.x: replace starts from nothing"},
+		{"based_on a shipped name", "  cisco_nxos: {based_on: arista_eos}\n", "platforms.cisco_nxos: based_on declares a variant"},
+		{"based_on nothing shipped", "  x: {based_on: arista}\n", `platforms.x: based_on "arista" is not a platform in set 1.0.0`},
+		{"an invalid adapter", "  x: {entity_classes: {mgmt: ['(']}}\n", "platforms.x.entity_classes.mgmt"},
+		{"an unknown key", "  arista_eos: {entity_class: {}}\n", "field entity_class not found"},
+		{"the attributes key", "  all: {supports: [session]}\n", "platforms.all: all is reserved"},
+		{"the redaction default", "  default: {supports: [session]}\n", "platforms.default: default is reserved"},
+		{"a rendering the device refuses", "  cisco_iosxe: {privilege: {admin: [\"roles=x\"]}}\n",
+			"platforms.cisco_iosxe.privilege.admin: roles is not in accepted_attributes"},
+	} {
+		if _, err := Parse([]byte("platforms:\n"+tt.block+rest), env()); err == nil || !strings.Contains(err.Error(), tt.want) {
+			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
+		}
+	}
+}
+
+// A class pattern is matched case-insensitively, and one an operator writes
+// with (?-i) is refused where a deny names the class: a differently-cased
+// name would walk past it (spec §4). A permit may opt out, which only narrows
+// it (roadmap, plan 4's "Hands to plan 5").
+func TestACaseSensitiveClassIsRefusedInADeny(t *testing.T) {
+	block := "platforms:\n  arista_eos:\n    entity_classes:\n      uplink: ['(?-i)^Ethernet49$']\n"
+	deny := block + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [\"**\"], deny: [interface @uplink]}\n" +
+		subjOK + grantOK
+	if _, err := Parse([]byte(deny), env()); err == nil || !strings.Contains(err.Error(),
+		`role "r": deny "interface @uplink" names @uplink, whose pattern /(?-i)^Ethernet49$/ on arista_eos turns `+
+			`case-insensitivity off`) {
+		t.Fatalf("%v", err)
+	}
+	permit := block + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [interface @uplink]}\n" + subjOK + grantOK
+	if _, err := Parse([]byte(permit), env()); err != nil {
+		t.Fatalf("a permit may opt out: %v", err)
+	}
+}
+
+// Attributes may be keyed by a platform a block defines, and a placeholder
+// is refused in an attribute such a platform says carries privilege.
+func TestAttributesMayNameAnOperatorsPlatform(t *testing.T) {
+	block := "platforms:\n  f5_bigip:\n    privilege_attributes: [F5-LTM-User-Role]\n"
+	ok := block + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [\"**\"], attributes: {f5_bigip: [\"F5-LTM-User-Partition*all\"]}}\n" +
+		subjOK + grantOK
+	if _, err := Parse([]byte(ok), env()); err != nil {
+		t.Fatal(err)
+	}
+	bad := block + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [\"**\"], attributes: {f5_bigip: [\"F5-LTM-User-Role*{username}\"]}}\n" +
+		subjOK + grantOK
+	if _, err := Parse([]byte(bad), env()); err == nil || !strings.Contains(err.Error(), "carries privilege and takes no placeholder") {
+		t.Fatalf("%v", err)
+	}
+}
+
+// An override that says what the pinned set already says is reported, so
+// local platform files do not rot as upstream improves (spec §8).
+func TestARedundantOverrideIsReported(t *testing.T) {
+	p := mustParse(t, "platforms:\n  arista_eos:\n    expands_abbreviations: true\n    shows_server_msg: false\n"+
+		scopeOK+roleOK+subjOK+grantOK)
+	got := findings(p, FindingPlatformOverride)
+	if len(got) != 1 || !strings.Contains(got[0], "platforms.arista_eos.expands_abbreviations says what platform set 1.0.0") {
+		t.Fatalf("%q", got)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/`
Expected: FAIL — `undefined: FindingPlatformOverride` (build failed) and `TestOverMergesPerTopLevelKey`.

- [ ] **Step 3: Read the blocks**

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index 39671fd..1191720 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -57,24 +57,30 @@ func ParseSpecs(raw []byte) (map[string]Spec, error) {
 	return f.Platforms, nil
 }
 
-// Over lays s over base: every field s sets replaces base's, whole, and every
-// field it leaves nil is base's. The result shares nothing with either.
+// Over lays s over base, per top-level key (spec §8): a list or a value s
+// sets replaces base's whole, and a map s sets — privilege, ceiling_levels,
+// entity_classes — merges into base's per entry, so a block that adds one
+// class keeps the rest. Every field s leaves nil is base's. The result shares
+// nothing with either. Discarding an entry takes `replace: true`, which
+// starts from nothing.
 func (s Spec) Over(base Dialect) Dialect {
 	d := base.clone()
 	if s.Supports != nil {
 		d.Supports = slices.Clone(*s.Supports)
 	}
 	if s.Privilege != nil {
-		d.Levels = cloneLists(*s.Privilege)
+		d.Levels = mergeLists(d.Levels, *s.Privilege)
 	}
 	if s.CeilingLevels != nil {
-		d.CeilingLevels = make(map[string]uint8, len(*s.CeilingLevels))
+		if d.CeilingLevels == nil {
+			d.CeilingLevels = map[string]uint8{}
+		}
 		for k, v := range *s.CeilingLevels {
 			d.CeilingLevels[k] = v
 		}
 	}
 	if s.EntityClasses != nil {
-		d.EntityClasses = cloneLists(*s.EntityClasses)
+		d.EntityClasses = mergeLists(d.EntityClasses, *s.EntityClasses)
 	}
 	if s.ExpandsAbbreviations != nil {
 		d.ExpandsAbbreviations = *s.ExpandsAbbreviations
@@ -109,12 +115,16 @@ func (s Spec) Over(base Dialect) Dialect {
 	return d
 }
 
-func cloneLists(m map[string][]string) map[string][]string {
-	out := make(map[string][]string, len(m))
-	for k, v := range m {
-		out[k] = slices.Clone(v)
+// mergeLists sets every entry of over in base, a map Over already owns, and
+// returns it; a nil base becomes a new map.
+func mergeLists(base, over map[string][]string) map[string][]string {
+	if base == nil {
+		base = make(map[string][]string, len(over))
+	}
+	for k, v := range over {
+		base[k] = slices.Clone(v)
 	}
-	return out
+	return base
 }
 
 // capabilities is spec §9's vocabulary for `supports`.
````

<!-- patch: internal/policy/file.go -->
````diff
diff --git a/internal/policy/file.go b/internal/policy/file.go
index c892df4..f773363 100644
--- a/internal/policy/file.go
+++ b/internal/policy/file.go
@@ -5,20 +5,33 @@ import (
 	"time"
 
 	"gopkg.in/yaml.v3"
+
+	"github.com/blanketfish/port49/internal/platform"
 )
 
 // The policy file's schema (spec §11), snake_case throughout. Every key is
 // declared: the decoder refuses one it does not know rather than ignoring it,
 // because an ignored key is a policy that reads one way and runs another.
 type file struct {
-	PlatformSet     string        `yaml:"platform_set"`
-	PrivilegeLevels []fileLevel   `yaml:"privilege_levels"`
-	Scopes          []fileScope   `yaml:"scopes"`
-	Roles           []fileRole    `yaml:"roles"`
-	Subjects        []fileSubject `yaml:"subjects"`
-	Grants          []fileGrant   `yaml:"grants"`
-	Tests           []fileTest    `yaml:"tests"`
-	Acknowledge     []fileAck     `yaml:"acknowledge"`
+	PlatformSet     string                  `yaml:"platform_set"`
+	Platforms       map[string]filePlatform `yaml:"platforms"`
+	PrivilegeLevels []fileLevel             `yaml:"privilege_levels"`
+	Scopes          []fileScope             `yaml:"scopes"`
+	Roles           []fileRole              `yaml:"roles"`
+	Subjects        []fileSubject           `yaml:"subjects"`
+	Grants          []fileGrant             `yaml:"grants"`
+	Tests           []fileTest              `yaml:"tests"`
+	Acknowledge     []fileAck               `yaml:"acknowledge"`
+}
+
+// filePlatform is one block under `platforms:` (spec §8, "User-editable, day
+// one"): the adapter keys of platform.Spec, merged per key over the pinned
+// set's adapter of that name, or over another's with based_on, or over
+// nothing with replace.
+type filePlatform struct {
+	platform.Spec `yaml:",inline"`
+	Replace       bool   `yaml:"replace"`
+	BasedOn       string `yaml:"based_on"`
 }
 
 // fileAck is one acknowledge: entry (spec §12): the author's written word for
````

<!-- patch: internal/policy/lint.go -->
````diff
diff --git a/internal/policy/lint.go b/internal/policy/lint.go
index 5e9a33b..5fabadf 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -2,6 +2,7 @@ package policy
 
 import (
 	"fmt"
+	"reflect"
 	"slices"
 	"sort"
 	"strings"
@@ -9,6 +10,7 @@ import (
 
 	"github.com/blanketfish/port49/internal/admission"
 	"github.com/blanketfish/port49/internal/engine"
+	"github.com/blanketfish/port49/internal/platform"
 )
 
 // Finding is something CI reports about a policy that loads: not an error,
@@ -33,6 +35,7 @@ const (
 	FindingNoTests             = "no_tests"
 	FindingCeilingIndistinct   = "ceiling_indistinct"
 	FindingAcknowledgeStale    = "acknowledge_stale"
+	FindingPlatformOverride    = "platform_override_redundant"
 )
 
 // Lint computes the findings at now, ordered by kind and then message so two
@@ -132,6 +135,7 @@ func (p *Policy) Lint(now time.Time) []Finding {
 				"and acknowledges nothing; delete it (spec §12)", a.Role, a.Rule, a.Rule)
 		}
 	}
+	out = append(out, p.redundantOverrides()...)
 	if len(p.tests) == 0 {
 		add(FindingNoTests, "the policy has no tests: nothing in it acknowledges a shadowed deny, an expansion or "+
 			"a privilege raise, so the gates fail on the first one; add tests (spec §12, \"Policy tests\")")
@@ -269,3 +273,34 @@ func (p *Policy) indistinctCeilings() []string {
 	}
 	return out
 }
+
+// redundantOverrides names every key a `platforms:` block sets to what the
+// pinned set already says (spec §8, "Knowing what is shipped"): an override
+// that matches the built-in can be removed, and left in place it would
+// silently pin the old value when a later set improves it.
+func (p *Policy) redundantOverrides() []Finding {
+	var out []Finding
+	for _, name := range sortedKeys(p.overrides) {
+		b := p.overrides[name]
+		builtin, ok := platform.Set(p.set)
+		base, shipped := builtin[name]
+		if !ok || !shipped || b.Replace || b.BasedOn != "" {
+			continue
+		}
+		v := reflect.ValueOf(b.Spec)
+		for i := 0; i < v.NumField(); i++ {
+			if v.Field(i).IsNil() {
+				continue
+			}
+			var one platform.Spec
+			reflect.ValueOf(&one).Elem().Field(i).Set(v.Field(i))
+			if reflect.DeepEqual(one.Over(base), base) {
+				key := strings.Split(v.Type().Field(i).Tag.Get("yaml"), ",")[0]
+				out = append(out, Finding{Kind: FindingPlatformOverride, Message: fmt.Sprintf(
+					"platforms.%s.%s says what platform set %s already says; remove it, or it keeps this value when "+
+						"a later set changes it", name, key, p.set)})
+			}
+		}
+	}
+	return out
+}
````

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index deb3926..cd9ea38 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -55,9 +55,12 @@ type Policy struct {
 	Bundle string
 
 	// set is the platform set the policy pins (spec §8), and adapters its
-	// platforms: the built-in set, Env.Dialects over it.
-	set      string
-	adapters map[string]platform.Dialect
+	// platforms: the built-in set, the file's `platforms:` blocks over it,
+	// Env.Dialects over those. overrides are the blocks as written, for the
+	// drift report.
+	set       string
+	adapters  map[string]platform.Dialect
+	overrides map[string]filePlatform
 
 	levels  []string          // the declared ordering, lowest first
 	parents map[string]string // level → parent, for rendering
@@ -222,7 +225,6 @@ func Parse(raw []byte, env Env) (*Policy, error) {
 func refusedKeys(raw []byte) error {
 	var loose struct {
 		KeyGroups any              `yaml:"key_groups"`
-		Platforms any              `yaml:"platforms"`
 		Roles     []map[string]any `yaml:"roles"`
 	}
 	if err := yaml.Unmarshal(raw, &loose); err != nil {
@@ -232,8 +234,6 @@ func refusedKeys(raw []byte) error {
 	case loose.KeyGroups != nil:
 		return errors.New("key_groups: key groups live in the inventory file (inventory_file) until plan 6 " +
 			"moves them to the policy repository; move the block there")
-	case loose.Platforms != nil:
-		return errors.New("platforms: user platform definitions are plan 5's; the built-in adapters apply")
 	}
 	for i, r := range loose.Roles {
 		if _, ok := r["max_session_age"]; ok {
@@ -250,7 +250,10 @@ func refusedKeys(raw []byte) error {
 
 // buildPlatforms resolves the platform set the policy pins, or UnpinnedSet
 // where it pins none (spec §8): a binary upgrade never changes what a policy
-// renders, and a set this binary does not ship is refused by name.
+// renders, and a set this binary does not ship is refused by name. Each
+// `platforms:` block then merges over the set per top-level key, or starts
+// from another platform (`based_on:`) or from nothing (`replace: true`), and
+// is validated exactly as a built-in is.
 func (p *Policy) buildPlatforms(f file) error {
 	p.set = f.PlatformSet
 	if p.set == "" {
@@ -261,6 +264,49 @@ func (p *Policy) buildPlatforms(f file) error {
 		return fmt.Errorf("platform_set: %s is not a set this binary ships; it ships %s. Pin one of those, or run "+
 			"a binary that ships %s (spec §8)", p.set, strings.Join(platform.Sets(), ", "), p.set)
 	}
+	builtin, _ := platform.Set(p.set)
+	generic, _ := platform.DialectFor("")
+	p.overrides = f.Platforms
+	for _, name := range sortedKeys(f.Platforms) {
+		b := f.Platforms[name]
+		at := "platforms." + name
+		_, shipped := builtin[name]
+		var base platform.Dialect
+		switch {
+		case !platformNameShape.MatchString(name):
+			return fmt.Errorf("%s: a platform name is lower case, digits and _, starting with a letter, as an "+
+				"inventory's platform: field writes it", at)
+		case name == "all" || name == "default":
+			// `all` keys an attribute to every platform (§6) and `default` is
+			// the redaction list of every platform with none (§5.8): a platform
+			// of either name would be read as the other.
+			return fmt.Errorf("%s: %s is reserved: attributes.all names every platform and the built-in redaction "+
+				"table's default list every unlisted one; name the platform as the inventory does", at, name)
+		case b.Replace && b.BasedOn != "":
+			return fmt.Errorf("%s: replace starts from nothing and based_on from another platform; use one", at)
+		case b.BasedOn != "" && shipped:
+			return fmt.Errorf("%s: based_on declares a variant under a new name, and %s is a platform this set "+
+				"ships; set the keys to change on it directly, or name the variant", at, name)
+		case b.BasedOn != "":
+			d, ok := builtin[b.BasedOn]
+			if !ok {
+				return fmt.Errorf("%s: based_on %q is not a platform in set %s; it ships %s", at, b.BasedOn, p.set,
+					strings.Join(sortedKeys(builtin), ", "))
+			}
+			base = d
+		case b.Replace || !shipped:
+			// A new platform, or one discarded whole, starts from what an
+			// unmodeled device gets (spec §8, "Unknown platforms").
+			base = generic
+		default:
+			base = builtin[name]
+		}
+		d := b.Spec.Over(base)
+		if err := platform.Validate(name, d); err != nil {
+			return err
+		}
+		set[name] = d
+	}
 	for name, d := range p.env.Dialects {
 		set[name] = d
 	}
@@ -268,6 +314,9 @@ func (p *Policy) buildPlatforms(f file) error {
 	return nil
 }
 
+// platformNameShape is how an inventory writes a platform.
+var platformNameShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
+
 // PlatformSet is the platform set the policy renders with.
 func (p *Policy) PlatformSet() string { return p.set }
 
@@ -365,6 +414,11 @@ func (p *Policy) buildRoles(f file) error {
 				if err := p.checkClasses(rule); err != nil {
 					return fmt.Errorf("role %q: %w", r.Name, err)
 				}
+				if list.deny {
+					if err := p.checkDenyClasses(rule); err != nil {
+						return fmt.Errorf("role %q: %w", r.Name, err)
+					}
+				}
 				*list.out = append(*list.out, engine.CanonicalRule(rule))
 			}
 		}
@@ -420,7 +474,7 @@ func checkRule(rule string, deny bool) error {
 // valid (engine.CheckAttribute).
 func (p *Policy) checkAttributes(attrs map[string][]string) error {
 	for key, list := range attrs {
-		if key != "all" && !platform.Known(key) && !p.inInventory(key) {
+		if _, adapted := p.adapters[key]; key != "all" && !adapted && !p.inInventory(key) {
 			return fmt.Errorf("attributes: %q is neither `all` nor a platform port49 ships or the inventory names", key)
 		}
 		for _, a := range list {
@@ -445,7 +499,8 @@ func (p *Policy) checkPlaceholder(key, a string) error {
 		return nil
 	}
 	name := a[:strings.IndexAny(a, "=*")]
-	if slices.Contains(platform.PrivilegeAttributeNames(), name) {
+	if slices.Contains(platform.PrivilegeAttributeNames(), name) || slices.ContainsFunc(sortedKeys(p.adapters),
+		func(n string) bool { return slices.Contains(p.adapters[n].PrivilegeAttributes, name) }) {
 		return fmt.Errorf("attributes.%s: %s: %s carries privilege and takes no placeholder: the device would get "+
 			"whatever the mint fills in, which no review tool can see (spec §6)", key, a, name)
 	}
@@ -912,6 +967,36 @@ func (p *Policy) checkClasses(rule string) error {
 	return nil
 }
 
+// checkDenyClasses refuses a deny naming a class whose pattern turns
+// case-insensitivity off on any platform: a class pattern is compiled
+// case-insensitively (engine.compileTerm), and one that opts out lets a
+// differently-cased interface name walk past the deny (spec §3 rule 3, §4).
+// A deny's own regex term is checkRule's; a class's patterns are an
+// adapter's, the operator's since plan 5, so they are checked here where the
+// adapters are known. A permit may opt out, since that only narrows it.
+func (p *Policy) checkDenyClasses(rule string) error {
+	terms, err := engine.ParseRule(rule)
+	if err != nil {
+		return err
+	}
+	for _, t := range terms {
+		if t.Kind != engine.Class {
+			continue
+		}
+		for _, name := range sortedKeys(p.adapters) {
+			for _, pattern := range p.adapters[name].EntityClasses[t.Text] {
+				if caseSensitive(pattern) {
+					return fmt.Errorf("deny %q names @%s, whose pattern /%s/ on %s turns case-insensitivity off; "+
+						"port49 matches case-insensitively, and a differently-cased name would walk past the deny "+
+						"(spec §4); remove the (?-i) from platforms.%s.entity_classes.%s", rule, t.Text, pattern, name,
+						name, t.Text)
+				}
+			}
+		}
+	}
+	return nil
+}
+
 // normalizeFor is the part of a platform's dialect a blob carries (spec
 // §5.1.2). A platform port49 has a dialect for that declares no command
 // authorization is session-only (Junos: L18, decision 21), and no command
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal
git commit -m "feat: the policy file's platforms: block overrides and adds adapters

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: The enable username is an adapter fact the offline tools read (N5)

**Files:**
- Modify: `internal/platform/dialect.go`, `internal/platform/adapter.go` (`EnableUsername`; `enab`
  refused by `Validate`), `internal/platform/platform.go` (`EnableUsernames`,
  `KnownEnableUsername` go)
- Modify: `internal/policy/load.go` (`Env.EnableUsernames` goes), `internal/policy/resolve.go`
- Modify: `internal/config/config.go` (`moveEnableUsernames`, `Config.Notices`;
  `Config.EnableUsernames` goes)
- Modify: `cmd/port49/policy.go` (`offlineEnv`), `cmd/port49d/main.go`,
  `internal/daemon/authen/authen.go` (comment)
- Test: `internal/platform/{adapter,platform}_test.go`, `internal/policy/resolve_test.go`,
  `internal/config/config_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Produces: `Dialect.EnableUsername string`, key `enable_username`, `principal` on every built-in
  adapter and the generic one. Removed: `policy.Env.EnableUsernames`, `config.Config.EnableUsernames`,
  `platform.EnableUsernames`, `platform.KnownEnableUsername`. `platform.EnablePrincipal` and
  `EnableEnab` stay. `config.Config.Notices []string`: lines port49d prints at start about the
  file itself; `enable_username: principal` in `port49d.yaml` loads and adds one, and any other
  value is refused (pre-flight S4).

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/policy_test.go -->
````diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index 4ac442f..90485e7 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -4,13 +4,11 @@ import (
 	"bytes"
 	"os"
 	"path/filepath"
-	"reflect"
 	"strings"
 	"testing"
 
 	"github.com/blanketfish/port49/internal/decision"
 	"github.com/blanketfish/port49/internal/engine"
-	"github.com/blanketfish/port49/internal/platform"
 )
 
 // unmappedLevel declares a level no built-in platform renders: a role landing
@@ -460,11 +458,22 @@ func TestGrantsRemoveFailsWhenStdoutFails(t *testing.T) {
 	}
 }
 
-// The offline tools load a policy with the enable-username table port49d
-// resolves, so the `enable: auto` joint check answers the same offline.
-func TestOfflineToolsLoadWithTheEnableUsernameTable(t *testing.T) {
-	if got := offlineEnv(nil).EnableUsernames; !reflect.DeepEqual(got, platform.EnableUsernames()) {
-		t.Fatalf("%v", got)
+// The offline tools load a policy as port49d does: the inventory, and every
+// adapter fact from the policy file itself, so an enable-username the file
+// declares refuses the load in CI exactly as it refuses port49d's start.
+func TestOfflineToolsReadTheAdaptersFromThePolicyFile(t *testing.T) {
+	if e := offlineEnv(nil); e.Dialects != nil || !e.Now.IsZero() {
+		t.Fatalf("%+v", e)
+	}
+	pol, inv := policyFixture(t)
+	raw := readFile(t, pol)
+	if err := os.WriteFile(pol, append([]byte("platforms: {arista_eos: {enable_username: enab}}\n"), raw...), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
+		!strings.Contains(errb.String(), "platforms.arista_eos.enable_username") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
 	}
 }
 
````

<!-- patch: internal/config/config_test.go -->
````diff
diff --git a/internal/config/config_test.go b/internal/config/config_test.go
index 4614bd4..86f875a 100644
--- a/internal/config/config_test.go
+++ b/internal/config/config_test.go
@@ -8,8 +8,6 @@ import (
 	"strings"
 	"testing"
 	"time"
-
-	"github.com/blanketfish/port49/internal/platform"
 )
 
 // The sample config is assembled from three pieces rather than written twice,
@@ -448,28 +446,27 @@ platforms:
 	}
 }
 
-// TestEnableUsernameEnabIsRefusedUntilTheLabShowsIt: `$enab{level}$` is not a
-// username form any measured platform sends on the enable START (vEOS and
-// Catalyst 8000V both send the operator's own username; NX-OS 10.x has no
-// enable exchange at all — tests/lab/results/L3-arista_eos.md,
-// L3-cisco_iosxe.md, L3-nxos-cisco_nxos.md), so the option exists to be
-// refused, not to be used, until a lab note says otherwise.
-func TestEnableUsernameEnabIsRefusedUntilTheLabShowsIt(t *testing.T) {
+// TestEnableUsernameMovedToThePolicyFile: the enable username is an adapter
+// fact, and adapters live in the policy file since plan 5, where the offline
+// tools read it as port49d does (plan 4 pre-flight N5). `principal`, the only
+// value config.Load ever accepted, still starts, with a notice saying where
+// the key went: refusing it would turn the upgrade into an outage for no
+// gain. Any other value is refused and told the same.
+func TestEnableUsernameMovedToThePolicyFile(t *testing.T) {
 	setKeyEnv(t)
 	invPath := write(t, "inventory.yaml", inv)
-	body := fmt.Sprintf(sample, invPath) + "\nplatforms: {cisco_iosxe: {enable_username: enab}}\n"
-	_, err := Load(write(t, "c.yaml", body))
-	if err == nil || !strings.Contains(err.Error(), "tests/lab/results") {
-		t.Fatalf("enable_username: enab must be refused and say what would unlock it: %v", err)
-	}
-	body = fmt.Sprintf(sample, invPath) + "\nplatforms: {cisco_iosxe: {enable_username: principal}}\n"
-	c, err := Load(write(t, "d.yaml", body))
-	if err != nil || c.EnableUsernames["cisco_iosxe"] != platform.EnablePrincipal {
-		t.Fatalf("%v %v", c.EnableUsernames, err)
-	}
-	body = fmt.Sprintf(sample, invPath) + "\nplatforms: {cisco_iosxe: {enable_username: princpal}}\n"
-	if _, err := Load(write(t, "e.yaml", body)); err == nil {
-		t.Fatal("a mistyped enable_username must be a load error")
+	body := fmt.Sprintf(sample, invPath) + "\nplatforms: {cisco_iosxe: {enable_username: principal}}\n"
+	c, err := Load(write(t, "c.yaml", body))
+	if err != nil || len(c.Notices) != 1 ||
+		!strings.Contains(c.Notices[0], "platforms.cisco_iosxe.enable_username moved to the policy file") {
+		t.Fatalf("principal: %q %v", c.Notices, err)
+	}
+	for i, v := range []string{"enab", "princpal"} {
+		body := fmt.Sprintf(sample, invPath) + "\nplatforms: {cisco_iosxe: {enable_username: " + v + "}}\n"
+		_, err := Load(write(t, fmt.Sprintf("c%d.yaml", i), body))
+		if err == nil || !strings.Contains(err.Error(), "platforms.cisco_iosxe.enable_username moved to the policy file") {
+			t.Fatalf("%s: %v", v, err)
+		}
 	}
 }
 
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index f7f87b7..aa3ea15 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -25,6 +25,7 @@ var shipped = map[string]Dialect{
 			"operator": {"priv-lvl=15", "roles=network-operator"}, "admin": {"priv-lvl=15", "roles=network-admin"}},
 		PrivilegeAttributes: []string{"priv-lvl", "roles"},
 		InertAttributes:     []string{"home-directory"},
+		EnableUsername:      EnablePrincipal,
 		DeviceConfig:        []string{"aaa authorization commands all default group port49 local"},
 	},
 	"cisco_nxos": {
@@ -37,6 +38,7 @@ var shipped = map[string]Dialect{
 		CeilingLevels:       map[string]uint8{"readonly": 1, "operator": 15, "admin": 15},
 		PrivilegeAttributes: []string{"priv-lvl", "shell:roles", "cisco-av-pair"},
 		InertAttributes:     []string{"home-directory"},
+		EnableUsername:      EnablePrincipal,
 		DeviceConfig: []string{"aaa authorization commands default group port49 local",
 			"aaa authorization config-commands default group port49 local"},
 	},
@@ -47,6 +49,7 @@ var shipped = map[string]Dialect{
 		Levels:              map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=7"}, "admin": {"priv-lvl=15"}},
 		PrivilegeAttributes: []string{"priv-lvl"},
 		InertAttributes:     []string{"home-directory"},
+		EnableUsername:      EnablePrincipal,
 		AcceptedAttributes:  []string{"priv-lvl"},
 		DeviceConfig: []string{"aaa authorization commands 1 default group port49 local",
 			"aaa authorization commands 7 default group port49 local",
@@ -61,6 +64,7 @@ var shipped = map[string]Dialect{
 			"allow-configuration", "deny-configuration", "allow-commands-regexps", "deny-commands-regexps",
 			"allow-configuration-regexps", "deny-configuration-regexps"},
 		InertAttributes: []string{"home-directory"},
+		EnableUsername:  EnablePrincipal,
 	},
 }
 
@@ -104,7 +108,8 @@ func TestEveryReleasedSetIsFrozen(t *testing.T) {
 // set instead (spec §8).
 func TestTheGenericAdapterIsFrozen(t *testing.T) {
 	want := Dialect{PipeToken: "|", StripCR: true, Supports: []string{"session"},
-		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"}}
+		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"},
+		EnableUsername: EnablePrincipal}
 	if !reflect.DeepEqual(generic, want) {
 		t.Errorf("generic:\n got %+v\nwant %+v", generic, want)
 	}
@@ -203,7 +208,7 @@ func TestOverMergesPerTopLevelKey(t *testing.T) {
 
 // Validate refuses what a device would get wrong silently or loudly.
 func TestValidateNamesTheField(t *testing.T) {
-	ok := Dialect{PipeToken: "|", Supports: []string{"session"}}
+	ok := Dialect{PipeToken: "|", Supports: []string{"session"}, EnableUsername: EnablePrincipal}
 	for field, d := range map[string]Dialect{
 		"supports":                  {PipeToken: "|"},
 		"supports: \"telnet\"":      {PipeToken: "|", Supports: []string{"telnet"}},
````

<!-- patch: internal/platform/platform_test.go -->
````diff
diff --git a/internal/platform/platform_test.go b/internal/platform/platform_test.go
index 309f2a8..1883510 100644
--- a/internal/platform/platform_test.go
+++ b/internal/platform/platform_test.go
@@ -2,6 +2,7 @@ package platform
 
 import (
 	"reflect"
+	"strings"
 	"testing"
 )
 
@@ -54,20 +55,25 @@ func TestNamesIsSortedAndComplete(t *testing.T) {
 	}
 }
 
-// TestEnableUsernamesNamesEveryKnownPlatformAsPrincipal pins the built-in
-// enable-username table: every platform this package knows, mapped to
-// EnablePrincipal, because no platform in the lab has been measured sending
-// anything else (tests/lab/results/L3-arista_eos.md, L3-cisco_iosxe.md,
-// L3-nxos-cisco_nxos.md).
-func TestEnableUsernamesNamesEveryKnownPlatformAsPrincipal(t *testing.T) {
-	got := EnableUsernames()
-	for _, name := range Names() {
-		if got[name] != EnablePrincipal {
-			t.Errorf("%s: enable username is %q, want %q", name, got[name], EnablePrincipal)
+// TestEveryAdapterSaysTheEnableSTARTCarriesThePrincipal pins the built-in
+// adapters' enable username: every platform this package knows, and the
+// generic adapter, says EnablePrincipal, because no platform in the lab has
+// been measured sending anything else (tests/lab/results/L3-arista_eos.md,
+// L3-cisco_iosxe.md, L3-nxos-cisco_nxos.md). `enab` is refused wherever it is
+// written.
+func TestEveryAdapterSaysTheEnableSTARTCarriesThePrincipal(t *testing.T) {
+	for _, name := range append(Names(), "no_such_platform") {
+		if d, _ := DialectFor(name); d.EnableUsername != EnablePrincipal {
+			t.Errorf("%s: enable username is %q, want %q", name, d.EnableUsername, EnablePrincipal)
 		}
 	}
-	if len(got) != len(Names()) {
-		t.Fatalf("EnableUsernames() has %d entries, want %d", len(got), len(Names()))
+	d, _ := DialectFor("arista_eos")
+	for v, want := range map[string]string{EnableEnab: "tests/lab/results", "princpal": `it must be "principal"`} {
+		d.EnableUsername = v
+		if err := Validate("arista_eos", d); err == nil || !strings.Contains(err.Error(),
+			"platforms.arista_eos.enable_username") || !strings.Contains(err.Error(), want) {
+			t.Errorf("%s: %v", v, err)
+		}
 	}
 }
 
````

<!-- patch: internal/policy/resolve_test.go -->
````diff
diff --git a/internal/policy/resolve_test.go b/internal/policy/resolve_test.go
index 39b8d0e..c08d427 100644
--- a/internal/policy/resolve_test.go
+++ b/internal/policy/resolve_test.go
@@ -282,7 +282,11 @@ grants: [{subject: s, scope: all_devices, roles: [ro]}]`
 	if p, err := Parse([]byte(body), e); err != nil || len(p.Quarantines(noon)) != 0 {
 		t.Fatalf("every shipped platform carries the principal: %v", err)
 	}
-	e.EnableUsernames = map[string]string{"arista_eos": platform.EnableEnab}
+	// Validate refuses `enab` in any adapter a file writes, so only an
+	// environment's own table can stand one up.
+	eos, _ := platform.DialectFor("arista_eos")
+	eos.EnableUsername = platform.EnableEnab
+	e.Dialects = map[string]platform.Dialect{"arista_eos": eos}
 	p, err := Parse([]byte(body), e)
 	if err != nil {
 		t.Fatal(err)
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/ ./internal/config/ ./cmd/port49/`
Expected: FAIL — `d.EnableUsername undefined`, `c.Notices undefined` (build failed), and
`TestOfflineToolsReadTheAdaptersFromThePolicyFile` (`field enable_username not found`).

- [ ] **Step 3: Move it**

<!-- patch: cmd/port49/policy.go -->
````diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 6a2d61d..0da947f 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -15,7 +15,6 @@ import (
 
 	"github.com/blanketfish/port49/internal/admission"
 	"github.com/blanketfish/port49/internal/decision"
-	"github.com/blanketfish/port49/internal/platform"
 	"github.com/blanketfish/port49/internal/policy"
 	"github.com/blanketfish/port49/internal/replay"
 )
@@ -26,11 +25,12 @@ import (
 type policyFiles struct{ policy, inventory string }
 
 // offlineEnv is the environment the offline tools load a policy in: the
-// inventory, and the built-in enable-username table port49d resolves from
-// config, so a joint check port49d runs (`enable: auto`) runs here too.
-// Config accepts no override of it today (config.resolveEnableUsernames).
+// inventory, and nothing else. Every adapter fact a joint check reads — the
+// enable username that `enable: auto` needs included — is in the policy
+// file's platform set and `platforms:` blocks, which port49d loads the same
+// way, so CI answers what port49d answers (plan 4 pre-flight N5).
 func offlineEnv(devices []admission.Device) policy.Env {
-	return policy.Env{Devices: devices, EnableUsernames: platform.EnableUsernames()}
+	return policy.Env{Devices: devices}
 }
 
 func (f *policyFiles) register(fs *flag.FlagSet) {
````

<!-- patch: cmd/port49d/main.go -->
````diff
diff --git a/cmd/port49d/main.go b/cmd/port49d/main.go
index e92e6ea..bbbba2e 100644
--- a/cmd/port49d/main.go
+++ b/cmd/port49d/main.go
@@ -258,7 +258,7 @@ func loadPolicy(cfg config.Config) (*policy.Policy, error) {
 // bytes it hashed, so the version it remembers refusing is the version it
 // refused, and the version the watch saw agree twice is the version loaded.
 func parsePolicy(cfg config.Config, raw []byte) (*policy.Policy, error) {
-	pol, err := policy.Parse(raw, policy.Env{Devices: cfg.Inventory.Devices, EnableUsernames: cfg.EnableUsernames})
+	pol, err := policy.Parse(raw, policy.Env{Devices: cfg.Inventory.Devices})
 	if err != nil {
 		return nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, quotesCut{err})
 	}
@@ -376,6 +376,9 @@ func run(parent context.Context, cfgPath string) error {
 	// starts: an edit in between would otherwise never be said (checkInventory).
 	_, inventoryAtStart, _ := fileVersion(cfg.InventoryFile)
 	fmt.Fprint(stderr, labWarning(cfg.Lab))
+	for _, n := range cfg.Notices {
+		fmt.Fprintln(stderr, "port49d:", n)
+	}
 
 	ctx, cancel := context.WithCancel(parent)
 	defer cancel()
````

<!-- patch: internal/config/config.go -->
````diff
diff --git a/internal/config/config.go b/internal/config/config.go
index 9b94187..1d8bb55 100644
--- a/internal/config/config.go
+++ b/internal/config/config.go
@@ -196,9 +196,9 @@ type PlatformConfig struct {
 	// fleet part-way through a rename lists both names.
 	SessionServices []string `yaml:"session_services"`
 
-	// EnableUsername selects what username an enable START is expected to
-	// carry: `principal` (the default, and the only value config.Load
-	// accepts) or `enab`, which is refused — see resolveEnableUsernames.
+	// EnableUsername moved to the policy file's `platforms:` block in plan 5,
+	// where the offline tools see it as port49d does (plan 4 pre-flight N5).
+	// It is declared only so config.Load can say where it went.
 	EnableUsername string `yaml:"enable_username"`
 }
 
@@ -267,10 +267,9 @@ type Config struct {
 	// error rather than a platform silently on its default (spec §5.2, §8).
 	SessionServices map[string][]string
 
-	// EnableUsernames is the resolved enable-username table: every built-in
-	// platform mapped to platform.EnablePrincipal, the only value config.Load
-	// accepts today (see resolveEnableUsernames).
-	EnableUsernames map[string]string
+	// Notices are lines port49d prints at start about the file itself: a key
+	// that still loads but has moved, and where it went.
+	Notices []string
 
 	// Inventory and Admission are read and built once, here, so the daemon
 	// never re-reads the file and the two can never disagree.
@@ -383,7 +382,7 @@ func Load(path string) (Config, error) {
 	if err := resolveSessionServices(&c, f.Platforms); err != nil {
 		return Config{}, err
 	}
-	if err := resolveEnableUsernames(&c, f.Platforms); err != nil {
+	if err := moveEnableUsernames(&c, f.Platforms); err != nil {
 		return Config{}, err
 	}
 	// No lab: block is a production daemon: Lab stays nil, the policy engine
@@ -677,17 +676,13 @@ func resolveSessionServices(c *Config, overrides map[string]PlatformConfig) erro
 	return nil
 }
 
-// resolveEnableUsernames applies any platforms.<name>.enable_username override
-// to the built-in table, and refuses `enab`.
-//
-// The $enab{level}$ enable path is unbuilt on purpose: it would need a
-// (nas, rem_addr) secondary index, and rem_addr is measured identical for two
-// concurrent sessions behind one bastion, so that index would have to refuse
-// rather than guess — and its refusal needs a reason code spec §5.7 does not
-// carry. None of that is worth building for a username form no device in this
-// lab has ever sent.
-func resolveEnableUsernames(c *Config, overrides map[string]PlatformConfig) error {
-	c.EnableUsernames = platform.EnableUsernames()
+// moveEnableUsernames handles platforms.<name>.enable_username, which is an
+// adapter fact: since plan 5 adapters live in the policy file's `platforms:`
+// block, where `port49 policy test` reads it as port49d does, and a key here
+// would be one CI never sees (plan 4 pre-flight N5). `principal`, the default
+// and the only value config.Load ever accepted, still loads with a notice, so
+// the upgrade is not an outage; any other value is refused by name.
+func moveEnableUsernames(c *Config, overrides map[string]PlatformConfig) error {
 	names := make([]string, 0, len(overrides))
 	for name := range overrides {
 		names = append(names, name)
@@ -698,19 +693,13 @@ func resolveEnableUsernames(c *Config, overrides map[string]PlatformConfig) erro
 		if v == "" {
 			continue
 		}
-		if !platform.KnownEnableUsername(v) {
-			return fmt.Errorf("config: platforms.%s.enable_username is %q; it must be %q or %q",
-				name, v, platform.EnablePrincipal, platform.EnableEnab)
-		}
-		if v == platform.EnableEnab {
-			return fmt.Errorf("config: platforms.%s.enable_username: %q is refused: no platform in the lab has been "+
-				"measured sending that username form, and port49 does not ship an unexercised enable path for it. "+
-				"Every platform with an enable exchange sends the operator's own username "+
-				"(tests/lab/results/L3-arista_eos.md, L3-cisco_iosxe.md). To enable it, add a "+
-				"tests/lab/results/ note showing a device sending it and lift this refusal with the code that reads it",
-				name, platform.EnableEnab)
+		moved := fmt.Sprintf("platforms.%s.enable_username moved to the policy file in plan 5: write it under "+
+			"`platforms: {%s: {enable_username: ...}}` there, where `port49 policy test` reads it as port49d does",
+			name, name)
+		if v != platform.EnablePrincipal {
+			return fmt.Errorf("config: %s", moved)
 		}
-		c.EnableUsernames[name] = v
+		c.Notices = append(c.Notices, moved+"; principal is the default, so delete the line")
 	}
 	return nil
 }
````

<!-- patch: internal/daemon/authen/authen.go -->
````diff
diff --git a/internal/daemon/authen/authen.go b/internal/daemon/authen/authen.go
index f7d02a7..504c978 100644
--- a/internal/daemon/authen/authen.go
+++ b/internal/daemon/authen/authen.go
@@ -280,8 +280,8 @@ func (s *Session) redeem(ctx context.Context, method string, presented []byte, m
 		}
 		// `auto` PASSes on the context alone, any password accepted (spec §7).
 		// That is only safe because `enable_username: enab` cannot load
-		// (config.Load), so this context is always the operator's own and never
-		// a shared `$enab15$` pseudo-user's.
+		// (platform.Validate), so this context is always the operator's own and
+		// never a shared `$enab15$` pseudo-user's.
 		if c.Enable == "auto" {
 			return s.escalate(ctx, rec, ck, decision.EscalationGranted)
 		}
````

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index 1191720..1850a5b 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -33,6 +33,7 @@ type Spec struct {
 	InertAttributes      *[]string            `yaml:"inert_attributes"`
 	AcceptedAttributes   *[]string            `yaml:"accepted_attributes"`
 	DeviceConfig         *[]string            `yaml:"device_config"`
+	EnableUsername       *string              `yaml:"enable_username"`
 }
 
 // ParseSpecs reads an adapter file: one YAML document whose one key is
@@ -112,6 +113,9 @@ func (s Spec) Over(base Dialect) Dialect {
 	if s.DeviceConfig != nil {
 		d.DeviceConfig = slices.Clone(*s.DeviceConfig)
 	}
+	if s.EnableUsername != nil {
+		d.EnableUsername = *s.EnableUsername
+	}
 	return d
 }
 
@@ -235,6 +239,20 @@ func Validate(name string, d Dialect) error {
 			}
 		}
 	}
+	switch d.EnableUsername {
+	case EnablePrincipal:
+	case EnableEnab:
+		// The $enab{level}$ enable path is unbuilt on purpose: it would need a
+		// (nas, rem_addr) index that must refuse rather than guess, and no
+		// device in the lab has sent that username form (spec §7, L3).
+		return fmt.Errorf("%s: %q is refused: no platform in the lab has been measured sending that username "+
+			"form, and port49 does not ship an unexercised enable path for it. Every platform with an enable "+
+			"exchange sends the operator's own username (tests/lab/results/L3-arista_eos.md, L3-cisco_iosxe.md). "+
+			"To enable it, add a tests/lab/results/ note showing a device sending it and lift this refusal with "+
+			"the code that reads it", field("enable_username"), EnableEnab)
+	default:
+		return fmt.Errorf("%s is %q; it must be %q", field("enable_username"), d.EnableUsername, EnablePrincipal)
+	}
 	for i, line := range d.DeviceConfig {
 		if strings.TrimSpace(line) == "" || strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
 			return fmt.Errorf("%s[%d]: one printable ASCII configuration line", field("device_config"), i)
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index e2735b7..65bb981 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -83,6 +83,12 @@ type Dialect struct {
 	// without it does not get what the level promises (IOS-XE's level 7 is
 	// level 1 until it is given commands, ceiling-cisco_iosxe.md).
 	DeviceConfig []string
+	// EnableUsername is what the platform's enable START carries in `user`:
+	// EnablePrincipal, the operator's own username, on every platform
+	// measured. It lives in the adapter, where the offline tools read it as
+	// port49d does, so the `enable: auto` joint check answers the same in CI
+	// (spec §5.6, §7).
+	EnableUsername string
 }
 
 // builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
@@ -98,7 +104,7 @@ var inert = []string{"home-directory"}
 // no modifier is claimed to reach port49, and the device is assumed to send
 // abbreviations as typed.
 var generic = Dialect{PipeToken: "|", StripCR: true, Supports: []string{"session"},
-	PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert}
+	PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert, EnableUsername: EnablePrincipal}
 
 // ceilingLevels is the priv-lvl number a level stands for on a platform that
 // renders no level, where the number is still needed: the token's
````

<!-- patch: internal/platform/platform.go -->
````diff
diff --git a/internal/platform/platform.go b/internal/platform/platform.go
index b46d125..1ee9ac0 100644
--- a/internal/platform/platform.go
+++ b/internal/platform/platform.go
@@ -91,26 +91,13 @@ func Defaults() map[string][]string {
 // been observed sending $enab{level}$.
 //
 // EnableEnab exists so the shape has a name and a refusal rather than an
-// implementation nothing has ever exercised. config.Load refuses it.
+// implementation nothing has ever exercised. Validate refuses it, in a
+// built-in adapter and an operator's alike.
 const (
 	EnablePrincipal = "principal"
 	EnableEnab      = "enab"
 )
 
-// EnableUsernames is the built-in table: every known platform, principal.
-func EnableUsernames() map[string]string {
-	out := make(map[string]string, len(sessionServices))
-	for name := range sessionServices {
-		out[name] = EnablePrincipal
-	}
-	return out
-}
-
-// KnownEnableUsername reports whether v is a value config.Load will accept
-// for `platforms.<name>.enable_username` — either the shipping default or the
-// refused-but-named `enab` — as opposed to a typo, which is a different error.
-func KnownEnableUsername(v string) bool { return v == EnablePrincipal || v == EnableEnab }
-
 // sessionDiscriminators names the AV pair whose value separates two sessions of
 // one user on one device, per platform (spec §5.8). Every entry is measured:
 //
````

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index cd9ea38..ba63278 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -40,9 +40,6 @@ type Env struct {
 	// Dialects replaces platforms of the pinned set when non-nil: tests use
 	// it to stand a platform up with other behaviour.
 	Dialects map[string]platform.Dialect
-	// EnableUsernames is config's resolved table (config.Config); a platform
-	// with no entry is `principal`.
-	EnableUsernames map[string]string
 	// Now is the present the joint checks start from: a grant already expired
 	// by then is not checked. Zero is the clock at load; tests fix it.
 	Now time.Time
````

<!-- patch: internal/policy/resolve.go -->
````diff
diff --git a/internal/policy/resolve.go b/internal/policy/resolve.go
index 168beb3..a417df5 100644
--- a/internal/policy/resolve.go
+++ b/internal/policy/resolve.go
@@ -481,7 +481,7 @@ func (p *Policy) checkDeviceAt(sub *Subject, d admission.Device, at time.Time) s
 		}
 	}
 	if sub.Enable == "auto" {
-		if eu := p.env.EnableUsernames[d.Platform]; eu != "" && eu != platform.EnablePrincipal {
+		if p.dialect(d.Platform).EnableUsername != platform.EnablePrincipal {
 			return fmt.Sprintf("enable: auto reaches this device, whose platform %s does not put the operator's "+
 				"own username on the enable exchange; use token or none (spec §5.6, \"Why enable: auto is "+
 				"restricted\")", d.Platform)
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/...`
Expected: every package `ok`. `grep -rn enable_username tests/lab` prints nothing (no lab config
sets it).

- [ ] **Step 5: Commit**

```bash
git add internal cmd
git commit -m "fix: the enable username is an adapter fact the offline tools read (N5)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: The diff gates an adapter edit, and reads privilege under the stricter adapter

**Files:**
- Modify: `internal/platform/adapter.go` (`SpecOf`, `SpecKeys`)
- Modify: `internal/policy/diff.go` (`AdapterChange`, `Diff.Adapters`, `UnacknowledgedAdapters`,
  `comparison.adapters`; `levelChange` asks both adapters)
- Modify: `internal/policy/file.go`, `internal/policy/load.go` (acknowledge `{platform, field,
  reason}`), `internal/policy/lint.go` (stale check for rule entries only)
- Modify: `cmd/port49/policy.go` (`ADAPTER` lines, the summary count, `ackName`)
- Test: `internal/platform/adapter_test.go`, `internal/policy/{diff,load}_test.go`,
  `cmd/port49/policy_test.go`

**Interfaces:**
- Produces:
  - `func SpecOf(d Dialect) Spec` — `SpecOf(d).Over(Dialect{}) == d`; `func SpecKeys() []string`.
  - `type AdapterChange struct { Platform, Field, Old, New string; Gated, Acknowledged bool; AcknowledgedBy string }`;
    `Diff.Adapters []AdapterChange`; `func (d Diff) UnacknowledgedAdapters() int`.
  - `Acknowledgment` gains `Platform, Field` (order: `Role, Rule, Platform, Field, Reason`).
  - `policy diff`'s summary line ends `; N unacknowledged adapter edits`, and exits 1 on any.
  - `comparison.adapters` compares every platform either version has an adapter for, and every
    inventory platform: a block for a platform with no device yet is gated too (pre-flight B2).

The inert-listing test uses NX-OS's `cisco-av-pair`, which no level renders: Task 2's `Validate`
refuses listing inert an attribute a level renders, such as EOS's `roles`, so the M8 hole is shown
on the one kind of attribute a block may still list inert.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/policy_test.go -->
````diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index 90485e7..8f32574 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -768,3 +768,37 @@ func TestPolicyDiffGatesABrokerRightGained(t *testing.T) {
 		t.Fatalf("a right lost: code %d\n%s%s", code, out.String(), errb.String())
 	}
 }
+
+// An edit to a key of an adapter the gate reads fails `port49 policy diff`
+// until an acknowledge: entry names the platform and the key, and `policy
+// test` prints the entry beside the others (review M8; spec §12).
+func TestPolicyDiffGatesAnAdapterEdit(t *testing.T) {
+	oldPol, inv := policyFixture(t)
+	raw := string(readFile(t, oldPol))
+	newPol := filepath.Join(t.TempDir(), "policy.yaml")
+	edited := "platforms: {arista_eos: {entity_classes: {management: ['^Management1$']}}}\n" + raw
+	if err := os.WriteFile(newPol, []byte(edited), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
+		!strings.Contains(out.String(), `ADAPTER: platforms.arista_eos.entity_classes {"loopback":`) ||
+		!strings.Contains(out.String(), `add {platform: arista_eos, field: entity_classes, reason: "..."} under acknowledge:`) ||
+		!strings.Contains(out.String(), "; 1 unacknowledged adapter edits\n") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	acked := edited + "acknowledge:\n  - {platform: arista_eos, field: entity_classes, reason: only Management1 is out of band}\n"
+	if err := os.WriteFile(newPol, []byte(acked), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	out.Reset()
+	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
+		!strings.Contains(out.String(), "adapter (acknowledged: only Management1 is out of band): platforms.arista_eos.entity_classes") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	out.Reset()
+	if code := run([]string{"policy", "test", "--policy", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
+		!strings.Contains(out.String(), "acknowledge: platforms.arista_eos.entity_classes: only Management1 is out of band\n") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+}
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index aa3ea15..f10e966 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -2,6 +2,7 @@ package platform
 
 import (
 	"reflect"
+	"slices"
 	"strings"
 	"testing"
 	"testing/fstest"
@@ -247,3 +248,18 @@ func with(d Dialect, edit func(*Dialect)) Dialect {
 	edit(&d)
 	return d
 }
+
+// SpecOf is Over's inverse: every built-in adapter, written back out as a
+// block and laid over nothing, is itself again. Export and the policy diff
+// both rely on it.
+func TestSpecOfRoundTrips(t *testing.T) {
+	for name, d := range Dialects() {
+		if got := SpecOf(d).Over(Dialect{}); !reflect.DeepEqual(got, d) {
+			t.Errorf("%s:\n got %+v\nwant %+v", name, got, d)
+		}
+	}
+	keys := SpecKeys()
+	if len(keys) != reflect.TypeOf(Spec{}).NumField() || keys[0] != "supports" || !slices.Contains(keys, "enable_username") {
+		t.Fatalf("keys %v", keys)
+	}
+}
````

<!-- patch: internal/policy/diff_test.go -->
````diff
diff --git a/internal/policy/diff_test.go b/internal/policy/diff_test.go
index 0c90e00..f0bbfe7 100644
--- a/internal/policy/diff_test.go
+++ b/internal/policy/diff_test.go
@@ -753,3 +753,66 @@ func TestAnAPIOnlyTestDoesNotAcknowledgeAnIdentityMove(t *testing.T) {
 		t.Fatalf("an api:-only test acknowledged the move: %d unacknowledged", n)
 	}
 }
+
+// Which attributes bear privilege is read from the adapters, so an edit that
+// lists an attribute inert is judged under the stricter of the two versions:
+// it cannot hide a change to that attribute in the same diff. The list edit is
+// gated in its own right, and acknowledged only in writing (review M8).
+func TestAnInertListingCannotHideItsOwnEdit(t *testing.T) {
+	after := "platforms:\n  cisco_nxos:\n    privilege_attributes: [priv-lvl, shell:roles]\n" +
+		"    inert_attributes: [home-directory, cisco-av-pair]\n" + strings.Replace(diffBase,
+		"roles: [read_only, cve]}", `roles: [read_only, cve], attributes: {cisco_nxos: ["cisco-av-pair*shell:roles=network-admin"]}}`, 1)
+	d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
+	raised := false
+	for _, l := range d.Levels {
+		if slices.Contains(l.Devices, "nx-01") && slices.Contains(l.Raised, "reply") && !l.Acknowledged {
+			raised = true
+		}
+	}
+	if !raised {
+		t.Fatalf("cisco-av-pair changed on NX-OS, which the old adapter says bears privilege: %+v", d.Levels)
+	}
+	if len(d.Adapters) != 2 || d.Adapters[0] != (AdapterChange{Platform: "cisco_nxos", Field: "privilege_attributes",
+		Old: `["priv-lvl","shell:roles","cisco-av-pair"]`, New: `["priv-lvl","shell:roles"]`, Gated: true}) ||
+		d.Adapters[1] != (AdapterChange{Platform: "cisco_nxos", Field: "inert_attributes", Old: `["home-directory"]`,
+			New: `["home-directory","cisco-av-pair"]`, Gated: true}) || d.UnacknowledgedAdapters() != 2 {
+		t.Fatalf("adapters %+v", d.Adapters)
+	}
+	acked := after + "acknowledge:\n  - {platform: cisco_nxos, field: inert_attributes, reason: \"a label here\"}\n" +
+		"  - {platform: cisco_nxos, field: privilege_attributes, reason: \"a label here\"}\n"
+	d = Compare(mustParse(t, diffBase), mustParse(t, acked), noon)
+	if d.UnacknowledgedAdapters() != 0 || d.Adapters[1].AcknowledgedBy != "a label here" ||
+		len(d.StaleAcknowledgments) != 0 {
+		t.Fatalf("adapters %+v stale %+v", d.Adapters, d.StaleAcknowledgments)
+	}
+	if d.UnacknowledgedLevels() == 0 {
+		t.Fatal("the entry acknowledges the list edit, not the reply the edit would have hidden")
+	}
+	// The same entry against a diff with no such edit acknowledges nothing.
+	if d := Compare(mustParse(t, diffBase), mustParse(t, diffBase+"acknowledge:\n  - {platform: cisco_nxos, "+
+		"field: inert_attributes, reason: x}\n"), noon); len(d.StaleAcknowledgments) != 1 {
+		t.Fatalf("stale %+v", d.StaleAcknowledgments)
+	}
+}
+
+// A key of an adapter that changes what port49 decides is gated, on every
+// platform either version has an adapter for, a device or not; one that
+// changes only what explain says is reported (spec §8, §12). A block for a
+// platform no device has yet is gated too: the inventory is not diffed, so
+// the day a device of it arrives is not a review.
+func TestAnAdapterEditIsGatedOrReported(t *testing.T) {
+	after := "platforms:\n  cisco_iosxe:\n    privilege: {operator: [\"priv-lvl=15\"]}\n  cisco_nxos:\n" +
+		"    shows_server_msg: true\n  f5_bigip:\n    supports: [session]\n    privilege: {admin: [\"priv-lvl=15\"]}\n" +
+		diffBase
+	d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
+	if len(d.Adapters) != 3 || d.UnacknowledgedAdapters() != 2 {
+		t.Fatalf("adapters %+v", d.Adapters)
+	}
+	xe, nx, f5 := d.Adapters[0], d.Adapters[1], d.Adapters[2]
+	if xe.Platform != "cisco_iosxe" || xe.Field != "privilege" || !xe.Gated ||
+		!strings.Contains(xe.New, `"operator":["priv-lvl=15"]`) ||
+		nx.Platform != "cisco_nxos" || nx.Field != "shows_server_msg" || nx.Gated ||
+		f5.Platform != "f5_bigip" || f5.Field != "privilege" || !f5.Gated || f5.Old != "null" {
+		t.Fatalf("adapters %+v", d.Adapters)
+	}
+}
````

<!-- patch: internal/policy/load_test.go -->
````diff
diff --git a/internal/policy/load_test.go b/internal/policy/load_test.go
index 0da7ceb..a9e79d6 100644
--- a/internal/policy/load_test.go
+++ b/internal/policy/load_test.go
@@ -133,6 +133,10 @@ func TestLoadRefusesByName(t *testing.T) {
 		{"key_groups", "key_groups: []\n" + roleOK + subjOK, "inventory file"},
 		{"a role's max_session_age", "roles:\n  - {name: r, max_session_age: 8h}\n" + subjOK, "plan 7"},
 		{"an unknown key", scopeOK + roleOK + subjOK + "gratns: []\n", "field gratns not found"},
+		{"an acknowledgment of two shapes", scopeOK + roleOK + subjOK +
+			"acknowledge: [{role: r, rule: x, platform: arista_eos, field: supports, reason: y}]\n", "one of the two"},
+		{"an acknowledgment of no adapter key", scopeOK + roleOK + subjOK +
+			"acknowledge: [{platform: arista_eos, field: suports, reason: y}]\n", "field is one of an adapter's keys"},
 		{"a second document", scopeOK + roleOK + subjOK + grantOK + "---\nscopes: []\n", "one YAML document"},
 		{"an empty file", "", "declares no subjects"},
 		{"a duration with no unit", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60}\n", "need a unit"},
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/ ./cmd/port49/`
Expected: FAIL — `undefined: SpecOf`, `d.Adapters undefined`, `undefined: AdapterChange` (build
failed). With the rest of the change applied and `levelChange`'s `oldDialect.BearsPrivilege(name) ||`
removed, `TestAnInertListingCannotHideItsOwnEdit` fails: that is the M8 hole, shown.

- [ ] **Step 3: Compare the adapters**

<!-- patch: cmd/port49/policy.go -->
````diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 0da947f..69c3ff8 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -142,7 +142,7 @@ func policyTest(args []string, stdout, stderr io.Writer) int {
 	// An acknowledge: entry is the author's written word for a widening no
 	// test can show (spec §12); review reads each one.
 	for _, a := range p.Acknowledgments() {
-		fmt.Fprintf(stdout, "acknowledge: %s %q: %s\n", a.Role, a.Rule, a.Reason)
+		fmt.Fprintf(stdout, "acknowledge: %s: %s\n", ackName(a), a.Reason)
 	}
 	// The shadowed-deny report is what replaces the guarantee deny-overrides
 	// gave (spec §12): every deny a more specific permit beats, for whom, and
@@ -313,8 +313,21 @@ func policyDiff(args []string, stdout, stderr io.Writer) int {
 			"permits there is an expansion\n", r.Device, r.Platform, from(r.At))
 	}
 	for _, a := range d.StaleAcknowledgments {
-		fmt.Fprintf(stdout, "report: acknowledge_stale: %s %q (%s): no widening in this diff is the one it names, so "+
-			"it acknowledges nothing; delete it (spec §12)\n", a.Role, a.Rule, a.Reason)
+		fmt.Fprintf(stdout, "report: acknowledge_stale: %s (%s): no change in this diff is the one it names, so "+
+			"it acknowledges nothing; delete it (spec §12)\n", ackName(a), a.Reason)
+	}
+	for _, a := range d.Adapters {
+		change := fmt.Sprintf("platforms.%s.%s %s -> %s", a.Platform, a.Field, a.Old, a.New)
+		switch {
+		case !a.Gated:
+			fmt.Fprintf(stdout, "adapter: %s\n", change)
+		case a.Acknowledged:
+			fmt.Fprintf(stdout, "adapter (acknowledged: %s): %s\n", a.AcknowledgedBy, change)
+		default:
+			fmt.Fprintf(stdout, "ADAPTER: %s: the key changes what port49 decides or what this gate reads, so the "+
+				"diff cannot vouch for it; add {platform: %s, field: %s, reason: \"...\"} under acknowledge: (spec §12)\n",
+				change, a.Platform, a.Field)
+		}
 	}
 	for _, p := range d.Principals {
 		switch {
@@ -462,11 +475,12 @@ func policyDiff(args []string, stdout, stderr io.Writer) int {
 	fmt.Fprintf(stdout, "%d commands changed: %d widen, %d narrow; %d unacknowledged expansions past a deny; "+
 		"%d unacknowledged privilege raises; %d unacknowledged regex-constrained widenings; %d unacknowledged "+
 		"principal or username changes; %d devices newly quarantined, %d released; %d mints newly refused; "+
-		"%d unresolved\n", len(d.Changes), widen, narrow, d.Unacknowledged(), d.UnacknowledgedLevels(),
-		d.UnacknowledgedRegex(), d.UnacknowledgedPrincipals(), len(d.Quarantined), len(d.Released), len(d.Refused),
-		len(d.Unresolved))
+		"%d unresolved; %d unacknowledged adapter edits\n", len(d.Changes), widen, narrow, d.Unacknowledged(),
+		d.UnacknowledgedLevels(), d.UnacknowledgedRegex(), d.UnacknowledgedPrincipals(), len(d.Quarantined),
+		len(d.Released), len(d.Refused), len(d.Unresolved), d.UnacknowledgedAdapters())
 	if d.Unacknowledged() > 0 || d.UnacknowledgedLevels() > 0 || d.UnacknowledgedRegex() > 0 ||
-		d.UnacknowledgedPrincipals() > 0 || len(d.Quarantined) > 0 || len(d.Refused) > 0 || len(d.Unresolved) > 0 {
+		d.UnacknowledgedPrincipals() > 0 || len(d.Quarantined) > 0 || len(d.Refused) > 0 || len(d.Unresolved) > 0 ||
+		d.UnacknowledgedAdapters() > 0 {
 		return 1
 	}
 	return 0
@@ -482,6 +496,15 @@ func yamlList(items []string) string {
 	return "[" + strings.Join(quoted, ", ") + "]"
 }
 
+// ackName is an acknowledge: entry as review reads it: the deny by role and
+// rule, or the adapter key by platform and field.
+func ackName(a policy.Acknowledgment) string {
+	if a.Platform != "" {
+		return "platforms." + a.Platform + "." + a.Field
+	}
+	return fmt.Sprintf("%s %q", a.Role, a.Rule)
+}
+
 // quarantineLine is an entry after a label that already says quarantine:
 // the cause for one in force now, and when for one an expiry brings on.
 func quarantineLine(e policy.QuarantineEntry, now time.Time) string {
````

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index 1850a5b..d2ff68e 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -5,6 +5,7 @@ import (
 	"errors"
 	"fmt"
 	"io"
+	"reflect"
 	"regexp"
 	"slices"
 	"strings"
@@ -260,3 +261,52 @@ func Validate(name string, d Dialect) error {
 	}
 	return nil
 }
+
+// SpecOf is d as a block that sets every field d has: nil where d leaves a
+// map or a list nil, so that SpecOf(d).Over(Dialect{}) is d again. `port49
+// platform export` writes it, and the policy diff compares two adapters
+// through it, key by key.
+func SpecOf(d Dialect) Spec {
+	s := Spec{ExpandsAbbreviations: ptr(d.ExpandsAbbreviations), SplitsInterfaceNames: ptr(d.SplitsInterfaceNames),
+		PipeToken: ptr(d.PipeToken), PipeAuthorized: ptr(d.PipeAuthorized), StripCR: ptr(d.StripCR),
+		ShowsServerMsg: ptr(d.ShowsServerMsg), EnableUsername: ptr(d.EnableUsername)}
+	d = d.clone()
+	if d.Supports != nil {
+		s.Supports = &d.Supports
+	}
+	if d.Levels != nil {
+		s.Privilege = &d.Levels
+	}
+	if d.CeilingLevels != nil {
+		s.CeilingLevels = &d.CeilingLevels
+	}
+	if d.EntityClasses != nil {
+		s.EntityClasses = &d.EntityClasses
+	}
+	if d.PrivilegeAttributes != nil {
+		s.PrivilegeAttributes = &d.PrivilegeAttributes
+	}
+	if d.InertAttributes != nil {
+		s.InertAttributes = &d.InertAttributes
+	}
+	if d.AcceptedAttributes != nil {
+		s.AcceptedAttributes = &d.AcceptedAttributes
+	}
+	if d.DeviceConfig != nil {
+		s.DeviceConfig = &d.DeviceConfig
+	}
+	return s
+}
+
+func ptr[T any](v T) *T { return &v }
+
+// SpecKeys are the keys an adapter block may set, in the order Spec
+// declares them: what an acknowledge: entry may name as a field.
+func SpecKeys() []string {
+	t := reflect.TypeOf(Spec{})
+	out := make([]string, t.NumField())
+	for i := range out {
+		out[i] = strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
+	}
+	return out
+}
````

<!-- patch: internal/policy/diff.go -->
````diff
diff --git a/internal/policy/diff.go b/internal/policy/diff.go
index 8a41277..07a1968 100644
--- a/internal/policy/diff.go
+++ b/internal/policy/diff.go
@@ -1,6 +1,7 @@
 package policy
 
 import (
+	"encoding/json"
 	"errors"
 	"fmt"
 	"reflect"
@@ -13,6 +14,7 @@ import (
 	"github.com/blanketfish/port49/internal/admission"
 	"github.com/blanketfish/port49/internal/decision"
 	"github.com/blanketfish/port49/internal/engine"
+	"github.com/blanketfish/port49/internal/platform"
 )
 
 // Diff is the effective-permission diff between two versions of a policy
@@ -49,6 +51,44 @@ type Diff struct {
 	// widening in the diff is the one they name. They acknowledge nothing and
 	// are reported, acknowledge_stale (spec §12).
 	StaleAcknowledgments []Acknowledgment
+	// Adapters are the keys of a platform's adapter that differ between the
+	// versions, on every platform either version has an adapter for or the
+	// inventory has devices of: a platform_set moved, or a `platforms:` block
+	// edited (spec §8, §12).
+	Adapters []AdapterChange
+}
+
+// AdapterChange is one key of one platform's adapter that the two versions
+// say differently. A key that changes what port49 decides — a rendering, a
+// class, how a command is normalized — or what this gate reads — which
+// attributes bear privilege, which the device takes — is Gated: a diff cannot
+// vouch for its own reading when the change is to the reading, so it is
+// acknowledged only in writing, by an acknowledge: entry naming the platform
+// and the key (review M8, 2026-09-24). Old and New are the key's value as
+// JSON, `null` where the adapter leaves it unset.
+type AdapterChange struct {
+	Platform, Field     string
+	Old, New            string
+	Gated, Acknowledged bool
+	AcknowledgedBy      string
+}
+
+// gatedAdapterKeys are the adapter keys an edit to is gated; every other key
+// is reported. A key a later plan adds is reported until it is listed here.
+var gatedAdapterKeys = []string{"supports", "privilege", "ceiling_levels", "entity_classes", "expands_abbreviations",
+	"splits_interface_names", "pipe_token", "pipe_authorized", "strip_cr", "privilege_attributes", "inert_attributes",
+	"accepted_attributes", "enable_username"}
+
+// UnacknowledgedAdapters counts the gated adapter edits no acknowledge: entry
+// names.
+func (d Diff) UnacknowledgedAdapters() int {
+	n := 0
+	for _, a := range d.Adapters {
+		if a.Gated && !a.Acknowledged {
+			n++
+		}
+	}
+	return n
 }
 
 // PrincipalChange is a principal that resolves to another subject in the new
@@ -337,6 +377,7 @@ func Compare(before, after *Policy, now time.Time) Diff {
 		c.at(at)
 	}
 	c.principals(now)
+	c.adapters()
 	for _, a := range after.acked {
 		if !c.usedAcks[a] {
 			c.d.StaleAcknowledgments = append(c.d.StaleAcknowledgments, a)
@@ -786,9 +827,14 @@ func (c *comparison) levelChange(l LevelChange, was, is privilege) LevelChange {
 	// EOS is lowered, although the role its rendering names changed from
 	// network-admin to network-operator. An adapter edit is judged whole here
 	// and gated in its own right.
-	dialect := c.after.dialect(is.platform)
+	//
+	// Which attributes bear privilege is itself read from the adapters, so it
+	// is read from both, the stricter winning: an edit that lists an
+	// attribute inert cannot hide a change to that attribute in the same
+	// diff (review M8, 2026-09-24).
+	oldDialect, dialect := c.before.dialect(was.platform), c.after.dialect(is.platform)
 	var oldRendered, newRendered []string
-	if reflect.DeepEqual(c.before.dialect(was.platform), dialect) {
+	if reflect.DeepEqual(oldDialect, dialect) {
 		oldRendered, _, _ = c.before.render(dialect, was.level)
 		newRendered, _, _ = c.after.render(dialect, is.level)
 	}
@@ -796,7 +842,7 @@ func (c *comparison) levelChange(l LevelChange, was, is privilege) LevelChange {
 		return slices.ContainsFunc(from, func(a string) bool {
 			name := a[:strings.IndexAny(a, "=*")]
 			return name != "priv-lvl" && !slices.Contains(to, a) && !slices.Contains(rendered, a) &&
-				dialect.BearsPrivilege(name)
+				(oldDialect.BearsPrivilege(name) || dialect.BearsPrivilege(name))
 		})
 	}
 	if moved(l.NewReply, l.OldReply, newRendered) || moved(l.OldReply, l.NewReply, oldRendered) {
@@ -989,3 +1035,40 @@ func (p *Policy) expansionAcks(before *Policy, instants []time.Time) map[string]
 	}
 	return acks
 }
+
+// adapters compares each platform's adapter, key by key, for every platform
+// the inventory has devices of and every platform either version has an
+// adapter for. A block for a platform no device has yet is compared too: the
+// inventory is not diffed, so the day a device of it arrives is no review.
+func (c *comparison) adapters() {
+	platforms := map[string]bool{}
+	for _, d := range c.after.Devices() {
+		platforms[d.Platform] = true
+	}
+	for _, p := range []*Policy{c.before, c.after} {
+		for name := range p.adapters {
+			platforms[name] = true
+		}
+	}
+	keys := platform.SpecKeys()
+	for _, name := range sortedKeys(platforms) {
+		was := reflect.ValueOf(platform.SpecOf(c.before.dialect(name)))
+		is := reflect.ValueOf(platform.SpecOf(c.after.dialect(name)))
+		for i, key := range keys {
+			if reflect.DeepEqual(was.Field(i).Interface(), is.Field(i).Interface()) {
+				continue
+			}
+			old, _ := json.Marshal(was.Field(i).Interface())
+			now, _ := json.Marshal(is.Field(i).Interface())
+			a := AdapterChange{Platform: name, Field: key, Old: string(old), New: string(now),
+				Gated: slices.Contains(gatedAdapterKeys, key)}
+			for _, ack := range c.after.acked {
+				if a.Gated && ack.Platform == name && ack.Field == key {
+					a.Acknowledged, a.AcknowledgedBy = true, ack.Reason
+					c.usedAcks[ack] = true
+				}
+			}
+			c.d.Adapters = append(c.d.Adapters, a)
+		}
+	}
+}
````

<!-- patch: internal/policy/file.go -->
````diff
diff --git a/internal/policy/file.go b/internal/policy/file.go
index f773363..9e51262 100644
--- a/internal/policy/file.go
+++ b/internal/policy/file.go
@@ -35,11 +35,14 @@ type filePlatform struct {
 }
 
 // fileAck is one acknowledge: entry (spec §12): the author's written word for
-// a removed or rewritten deny no test can flip.
+// a removed or rewritten deny no test can flip, or for an edit to a
+// platform's adapter the gate reads (Diff.Adapters).
 type fileAck struct {
-	Role   string `yaml:"role"`
-	Rule   string `yaml:"rule"`
-	Reason string `yaml:"reason"`
+	Role     string `yaml:"role"`
+	Rule     string `yaml:"rule"`
+	Platform string `yaml:"platform"`
+	Field    string `yaml:"field"`
+	Reason   string `yaml:"reason"`
 }
 
 type fileLevel struct {
````

<!-- patch: internal/policy/lint.go -->
````diff
diff --git a/internal/policy/lint.go b/internal/policy/lint.go
index 5fabadf..9140a7e 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -130,7 +130,7 @@ func (p *Policy) Lint(now time.Time) []Finding {
 		add(FindingCeilingIndistinct, "%s", f)
 	}
 	for _, a := range p.acked {
-		if p.hasDeny(a.Rule) {
+		if a.Role != "" && p.hasDeny(a.Rule) {
 			add(FindingAcknowledgeStale, "acknowledge: %s %q: the policy still denies %q, so the entry removed nothing "+
 				"and acknowledges nothing; delete it (spec §12)", a.Role, a.Rule, a.Rule)
 		}
````

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index ba63278..5de23bf 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -141,10 +141,11 @@ type Test struct {
 }
 
 // Acknowledgment is one `acknowledge:` entry (spec §12): a removed or
-// rewritten deny, named by its role and exact rule text, that the author
+// rewritten deny, named by its role and exact rule text, or an edited key of a
+// platform's adapter, named by the platform and the key, that the author
 // acknowledges in writing, with why.
 type Acknowledgment struct {
-	Role, Rule, Reason string
+	Role, Rule, Platform, Field, Reason string
 }
 
 // NoCeiling is how a test asserts that the grants compose to no ceiling.
@@ -886,10 +887,17 @@ func (p *Policy) buildTests(f file) error {
 
 func (p *Policy) buildAcknowledgments(f file) error {
 	for i, a := range f.Acknowledge {
+		byRule, byAdapter := a.Role != "" || a.Rule != "", a.Platform != "" || a.Field != ""
 		switch {
-		case a.Role == "" || a.Rule == "":
+		case byRule == byAdapter:
+			return fmt.Errorf("acknowledge[%d]: name a deny by role and rule, or an adapter edit by platform and "+
+				"field, one of the two (spec §12)", i)
+		case byRule && (a.Role == "" || a.Rule == ""):
 			return fmt.Errorf("acknowledge[%d]: role and rule are required: the entry names the exact deny it "+
 				"acknowledges (spec §12)", i)
+		case byAdapter && (a.Platform == "" || !slices.Contains(platform.SpecKeys(), a.Field)):
+			return fmt.Errorf("acknowledge[%d]: platform and field are required, and field is one of an adapter's "+
+				"keys: %s (spec §8, §12)", i, strings.Join(platform.SpecKeys(), ", "))
 		case strings.TrimSpace(a.Reason) == "":
 			return fmt.Errorf("acknowledge[%d]: reason is required: review reads it beside the change it "+
 				"acknowledges (spec §12)", i)
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal cmd
git commit -m "feat: policy diff gates an adapter edit, reading privilege under the stricter adapter

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Redaction patterns, built in and unpinned

**Files:**
- Create: `platforms/redact.yaml`, `internal/platform/redact.go`
- Modify: `platforms/platforms.go` (`Redact`), `internal/platform/dialect.go`,
  `internal/platform/adapter.go` (`Redact`: field, key, `Over` appends, `Validate`, `SpecOf`)
- Modify: `internal/policy/diff.go` (`redact` is a gated key)
- Test: `internal/platform/redact_test.go`, `internal/policy/diff_test.go`

**Interfaces:**
- Produces:
  - `const Redacted = "«redacted»"`.
  - `type Redaction struct { Match []string; After string; From *int }` (yaml `match`, `after`, `from`).
  - `func LoadRedactions(raw []byte) (map[string][]Redaction, error)`; `func Redactions(platformName string) []Redaction`
    — the `default` list, then the platform's own: a platform's list adds and never replaces
    (pre-flight S2).
  - A pattern whose `match` is `*` and `**` alone is refused with `from`: it would blank every
    record (pre-flight S1). `redact` is a gated adapter key in `policy diff`.
  - `func Redact(rules []Redaction, abbrev bool, elements []string) ([]string, bool)` — the elements
    with every removed word replaced, and whether any was; an untouched element comes back as it was.
  - `func RedactRaw(rules []Redaction, abbrev bool, raw []string) ([]string, bool)` — over the
    values of `cmd` and `cmd-arg`, a trailing `<cr>` aside, each keeping its key and separator.
  - `Dialect.Redact []Redaction` — what a block adds; key `redact`.

- [ ] **Step 1: Write the failing test**

<!-- patch: internal/platform/redact_test.go -->
````diff
diff --git a/internal/platform/redact_test.go b/internal/platform/redact_test.go
new file mode 100644
index 0000000..8feafb7
--- /dev/null
+++ b/internal/platform/redact_test.go
@@ -0,0 +1,177 @@
+package platform
+
+import (
+	"reflect"
+	"strings"
+	"testing"
+
+	"github.com/blanketfish/port49/platforms"
+)
+
+// The built-in table loads, has a default list, and gives Junos its own on
+// top of it: a platform's list adds to the default and never replaces it, so
+// a word the default removes is removed everywhere.
+func TestBuiltInRedactionsLoad(t *testing.T) {
+	if _, err := LoadRedactions(platforms.Redact); err != nil {
+		t.Fatal(err)
+	}
+	if !reflect.DeepEqual(Redactions("arista_eos"), Redactions("meinberg_lantime")) || len(Redactions("")) == 0 {
+		t.Fatal("a platform with no list of its own takes the default")
+	}
+	junos, all := Redactions("juniper_junos"), Redactions("arista_eos")
+	if len(junos) <= len(all) || !reflect.DeepEqual(junos[:len(all)], all) {
+		t.Fatalf("junos has the default list and its own after it: %+v", junos)
+	}
+	list := Redactions("arista_eos")
+	list[0].After = "changed"
+	if Redactions("arista_eos")[0].After == "changed" {
+		t.Fatal("Redactions must return a copy")
+	}
+}
+
+// Spec §5.8's own case: `username bob secret Hunter2` is written with the
+// secret removed, in the vector and the raw pairs alike, and the vector keeps
+// its shape and length so the reconciliation join still lines up. The command
+// word is never removed.
+func TestASecretIsRemovedAndTheShapeKept(t *testing.T) {
+	rules := Redactions("cisco_iosxe")
+	for _, tt := range []struct{ in, want []string }{
+		{[]string{"username", "bob", "secret", "Hunter2"}, []string{"username", "bob", "secret", Redacted}},
+		{[]string{"username", "bob", "privilege", "15", "secret", "0", "Hunter2"},
+			[]string{"username", "bob", "privilege", "15", "secret", Redacted, Redacted}},
+		{[]string{"enable", "password", "x"}, []string{"enable", "password", Redacted}},
+		{[]string{"tacacs-server", "host", "10.0.0.1", "key", "7", "0822455D0A16"},
+			[]string{"tacacs-server", "host", "10.0.0.1", "key", Redacted, Redacted}},
+		{[]string{"snmp-server", "community", "s3cret", "RO"}, []string{"snmp-server", "community", Redacted, Redacted}},
+	} {
+		got, redacted := Redact(rules, false, tt.in)
+		if !redacted || !reflect.DeepEqual(got, tt.want) {
+			t.Errorf("%q: %q %v, want %q", tt.in, got, redacted, tt.want)
+		}
+	}
+	in := []string{"show", "running-config"}
+	if got, redacted := Redact(rules, false, in); redacted || !reflect.DeepEqual(got, in) {
+		t.Fatalf("a command with no secret is untouched: %q", got)
+	}
+	raw := []string{"task_id=43", "service=shell", "cmd=username", "cmd-arg=bob", "cmd-arg=secret", "cmd-arg=Hunter2",
+		"cmd-arg=<cr>"}
+	got, redacted := RedactRaw(rules, false, raw)
+	want := []string{"task_id=43", "service=shell", "cmd=username", "cmd-arg=bob", "cmd-arg=secret",
+		"cmd-arg=" + Redacted, "cmd-arg=<cr>"}
+	if !redacted || !reflect.DeepEqual(got, want) {
+		t.Fatalf("raw: %q", got)
+	}
+	if strings.Contains(strings.Join(got, " "), "Hunter2") || raw[5] != "cmd-arg=Hunter2" {
+		t.Fatal("the secret is gone from the copy, and the input is not edited")
+	}
+}
+
+// One real line per secret each vendor's syntax carries, on each platform's
+// built-in patterns: the secret is not in what is written. The NX-OS
+// accounting `cmd` is the configuration path joined with ` ; ` and a result
+// (tests/lab/results/L21-cisco_nxos.md), which is why the patterns lead with
+// `**`.
+func TestEachVendorsSecretsAreRedacted(t *testing.T) {
+	for _, tt := range []struct {
+		platform string
+		raw      []string
+	}{
+		{"arista_eos", []string{"cmd=snmp-server", "cmd-arg=user", "cmd-arg=u", "cmd-arg=g", "cmd-arg=v3",
+			"cmd-arg=auth", "cmd-arg=sha", "cmd-arg=SECRET1", "cmd-arg=priv", "cmd-arg=aes", "cmd-arg=SECRET2"}},
+		{"arista_eos", []string{"cmd=ip", "cmd-arg=ospf", "cmd-arg=message-digest-key", "cmd-arg=1", "cmd-arg=md5",
+			"cmd-arg=SECRET1"}},
+		{"cisco_iosxe", []string{"cmd=neighbor", "cmd-arg=10.0.0.1", "cmd-arg=password", "cmd-arg=7",
+			"cmd-arg=SECRET1"}},
+		{"cisco_iosxe", []string{"cmd=crypto", "cmd-arg=isakmp", "cmd-arg=key", "cmd-arg=SECRET1", "cmd-arg=address",
+			"cmd-arg=10.0.0.1"}},
+		{"cisco_iosxe", []string{"cmd=ntp", "cmd-arg=authentication-key", "cmd-arg=1", "cmd-arg=md5",
+			"cmd-arg=SECRET1"}},
+		{"cisco_nxos", []string{"cmd=configure terminal ; username bob password SECRET1 role network-admin (SUCCESS)"}},
+		{"cisco_nxos", []string{"cmd=configure terminal ; snmp-server user u network-admin auth sha SECRET1 priv " +
+			"aes-128 SECRET2 (SUCCESS)"}},
+		{"juniper_junos", []string{"cmd=set protocols ospf area 0 interface ge-0/0/0.0 authentication md5 1 key SECRET1"}},
+		{"juniper_junos", []string{"cmd=set snmp v3 usm local-engine user u authentication-sha authentication-password " +
+			"SECRET1"}},
+		{"juniper_junos", []string{"cmd=set snmp v3 usm local-engine user u privacy-aes128 privacy-password SECRET1"}},
+		{"juniper_junos", []string{"cmd=set system radius-server 10.0.0.1 secret SECRET1"}},
+		{"juniper_junos", []string{"cmd=set security ike policy p pre-shared-key ascii-text SECRET1"}},
+		{"juniper_junos", []string{"cmd=set system login user bob authentication plain-text-password-value SECRET1"}},
+	} {
+		d, _ := DialectFor(tt.platform)
+		got, redacted := RedactRaw(Redactions(tt.platform), !d.ExpandsAbbreviations, tt.raw)
+		if joined := strings.Join(got, " "); !redacted || strings.Contains(joined, "SECRET") {
+			t.Errorf("%s %q: %q", tt.platform, tt.raw, got)
+		}
+	}
+}
+
+// Junos sends a whole command line as one `cmd`, so each element is split
+// into words; and a platform that may send what was typed has a pattern's word
+// match its abbreviations too, which removes more rather than less.
+func TestJunosLinesAndAbbreviationsAreRedacted(t *testing.T) {
+	got, redacted := RedactRaw(Redactions("juniper_junos"), true,
+		[]string{"task_id=2", "cmd=set system root-authentication encrypted-password \"$6$abc\" <cr>"})
+	if !redacted || got[1] != "cmd=set system root-authentication encrypted-password "+Redacted+" "+Redacted {
+		t.Fatalf("%q", got)
+	}
+	if got, _ := Redact(Redactions(""), true, []string{"usern", "bob", "sec", "0", "Hunter2"}); got[4] != Redacted {
+		t.Fatalf("abbreviated: %q", got)
+	}
+	if got, redacted := Redact(Redactions(""), false, []string{"usern", "bob", "sec", "0", "Hunter2"}); redacted {
+		t.Fatalf("a platform that expands abbreviations sends `secret`, never `sec`: %q", got)
+	}
+}
+
+// A pattern's match is anchored at both ends, `from` counts positions and a
+// negative one counts from the end, and nothing removes the command word.
+func TestMatchAndFrom(t *testing.T) {
+	from := func(n int) *int { return &n }
+	rules := []Redaction{{Match: []string{"crypto", "key", "*", "**"}, From: from(3)},
+		{Match: []string{"**", "psk"}, From: from(-1)}}
+	for _, tt := range []struct{ in, want []string }{
+		{[]string{"crypto", "key", "a", "b", "c"}, []string{"crypto", "key", "a", Redacted, Redacted}},
+		{[]string{"crypto", "keys", "a", "b"}, []string{"crypto", "keys", "a", "b"}},
+		{[]string{"x", "psk"}, []string{"x", Redacted}},
+		{[]string{"psk"}, []string{"psk"}},
+	} {
+		if got, _ := Redact(rules, false, tt.in); !reflect.DeepEqual(got, tt.want) {
+			t.Errorf("%q: %q, want %q", tt.in, got, tt.want)
+		}
+	}
+}
+
+// A pattern that could not do what it says is refused where it is written.
+func TestARedactionIsValidated(t *testing.T) {
+	zero, one := 0, 1
+	for want, r := range map[string]Redaction{
+		"match is required":         {After: "x"},
+		"no regex or class":         {Match: []string{"/secret/"}, After: "x"},
+		"more than two **":          {Match: []string{"**", "a", "**", "b", "**"}, After: "x"},
+		"one of the two":            {Match: []string{"**"}, After: "x", From: &one},
+		"from: 0 is the command":    {Match: []string{"**"}, From: &zero},
+		"after \"a b\" is one word": {Match: []string{"**"}, After: "a b"},
+		"matches every command":     {Match: []string{"*", "**"}, From: &one},
+	} {
+		if err := r.check(); err == nil || !strings.Contains(err.Error(), want) {
+			t.Errorf("%q: %v", want, err)
+		}
+	}
+	d, _ := DialectFor("arista_eos")
+	d.Redact = []Redaction{{Match: []string{"**"}}}
+	if err := Validate("arista_eos", d); err == nil || !strings.Contains(err.Error(), "platforms.arista_eos.redact[0]") {
+		t.Fatalf("%v", err)
+	}
+}
+
+// A block's redact adds to what the adapter has; it never replaces a list.
+func TestABlockAddsRedactions(t *testing.T) {
+	specs, err := ParseSpecs([]byte("platforms:\n  x:\n    redact: [{match: ['**'], after: psk}]\n"))
+	if err != nil {
+		t.Fatal(err)
+	}
+	base := Dialect{Redact: []Redaction{{Match: []string{"**"}, After: "secret"}}}
+	d := specs["x"].Over(base)
+	if len(d.Redact) != 2 || d.Redact[0].After != "secret" || d.Redact[1].After != "psk" || len(base.Redact) != 1 {
+		t.Fatalf("%+v", d.Redact)
+	}
+}
````

<!-- patch: internal/policy/diff_test.go -->
````diff
diff --git a/internal/policy/diff_test.go b/internal/policy/diff_test.go
index f0bbfe7..a2d2638 100644
--- a/internal/policy/diff_test.go
+++ b/internal/policy/diff_test.go
@@ -816,3 +816,15 @@ func TestAnAdapterEditIsGatedOrReported(t *testing.T) {
 		t.Fatalf("adapters %+v", d.Adapters)
 	}
 }
+
+// A redaction pattern changes what the audit keeps, so a block that adds one
+// is gated like a rendering: a pattern written wide enough removes what every
+// command was typed with from the log and the spool (spec §5.8, §12).
+func TestARedactionEditIsGated(t *testing.T) {
+	after := "platforms:\n  arista_eos:\n    redact: [{match: ['**'], after: interface}]\n" + diffBase
+	d := Compare(mustParse(t, diffBase), mustParse(t, after), noon)
+	if len(d.Adapters) != 1 || d.Adapters[0].Field != "redact" || !d.Adapters[0].Gated ||
+		d.UnacknowledgedAdapters() != 1 {
+		t.Fatalf("adapters %+v", d.Adapters)
+	}
+}
````

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/platform/ ./internal/policy/`
Expected: FAIL — `undefined: LoadRedactions`, `undefined: platforms.Redact`, `undefined: Redacted`
(build failed), and `TestARedactionEditIsGated` (`field redact not found`).

- [ ] **Step 3: Write the patterns and the redactor**

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index d2ff68e..d8c30b5 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -35,6 +35,7 @@ type Spec struct {
 	AcceptedAttributes   *[]string            `yaml:"accepted_attributes"`
 	DeviceConfig         *[]string            `yaml:"device_config"`
 	EnableUsername       *string              `yaml:"enable_username"`
+	Redact               *[]Redaction         `yaml:"redact"`
 }
 
 // ParseSpecs reads an adapter file: one YAML document whose one key is
@@ -117,6 +118,10 @@ func (s Spec) Over(base Dialect) Dialect {
 	if s.EnableUsername != nil {
 		d.EnableUsername = *s.EnableUsername
 	}
+	if s.Redact != nil {
+		// Appended, never replaced: a block cannot take a redaction away.
+		d.Redact = append(d.Redact, *s.Redact...)
+	}
 	return d
 }
 
@@ -240,6 +245,11 @@ func Validate(name string, d Dialect) error {
 			}
 		}
 	}
+	for i, r := range d.Redact {
+		if err := r.check(); err != nil {
+			return fmt.Errorf("%s[%d]: %w", field("redact"), i, err)
+		}
+	}
 	switch d.EnableUsername {
 	case EnablePrincipal:
 	case EnableEnab:
@@ -295,6 +305,9 @@ func SpecOf(d Dialect) Spec {
 	if d.DeviceConfig != nil {
 		s.DeviceConfig = &d.DeviceConfig
 	}
+	if d.Redact != nil {
+		s.Redact = &d.Redact
+	}
 	return s
 }
 
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index 65bb981..b64e031 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -89,6 +89,10 @@ type Dialect struct {
 	// port49d does, so the `enable: auto` joint check answers the same in CI
 	// (spec §5.6, §7).
 	EnableUsername string
+	// Redact are the redaction patterns an operator's `platforms:` block adds
+	// to the platform's built-in ones (Redactions). A block adds; it never
+	// removes a built-in pattern (spec §5.8).
+	Redact []Redaction
 }
 
 // builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
@@ -140,6 +144,7 @@ func (d Dialect) clone() Dialect {
 	d.InertAttributes = slices.Clone(d.InertAttributes)
 	d.AcceptedAttributes = slices.Clone(d.AcceptedAttributes)
 	d.DeviceConfig = slices.Clone(d.DeviceConfig)
+	d.Redact = slices.Clone(d.Redact)
 	if d.EntityClasses != nil {
 		classes := make(map[string][]string, len(d.EntityClasses))
 		for k, v := range d.EntityClasses {
````

<!-- patch: internal/platform/redact.go -->
````diff
diff --git a/internal/platform/redact.go b/internal/platform/redact.go
new file mode 100644
index 0000000..c5fdc51
--- /dev/null
+++ b/internal/platform/redact.go
@@ -0,0 +1,230 @@
+package platform
+
+import (
+	"bytes"
+	"errors"
+	"fmt"
+	"slices"
+	"strings"
+
+	"gopkg.in/yaml.v3"
+
+	"github.com/blanketfish/port49/platforms"
+)
+
+// Redacted is what a removed word becomes (spec §5.8): the vector keeps its
+// shape and length, so the reconciliation join still lines up.
+const Redacted = "«redacted»"
+
+// Redaction is one `redact:` pattern (spec §5.8): a command it matches loses
+// every word after the first word equal to After, or every word from position
+// From on. Match is words, `*` for one word and `**` for any number, anchored
+// at both ends as a rule is.
+type Redaction struct {
+	Match []string `yaml:"match"`
+	After string   `yaml:"after,omitempty"`
+	From  *int     `yaml:"from,omitempty"`
+}
+
+// check refuses a pattern that could not do what it says, or could remove the
+// command word the join needs.
+func (r Redaction) check() error {
+	stars := 0
+	for _, w := range r.Match {
+		switch {
+		case w == "**":
+			stars++
+		case w == "*":
+		case w == "" || strings.ContainsAny(w, " \t/@"):
+			return fmt.Errorf("match word %q: a pattern is words, * and **, with no regex or class", w)
+		}
+	}
+	switch {
+	case len(r.Match) == 0:
+		return errors.New("match is required: the command the pattern applies to")
+	case stars > 2:
+		return errors.New("match has more than two **; split it into two patterns")
+	case (r.After == "") == (r.From == nil):
+		return errors.New("give after or from, one of the two")
+	case r.After != "" && strings.ContainsAny(r.After, " \t"):
+		return fmt.Errorf("after %q is one word", r.After)
+	case r.From != nil && *r.From == 0:
+		return errors.New("from: 0 is the command word, which the reconciliation join needs; the first argument is 1")
+	case r.From != nil && !slices.ContainsFunc(r.Match, func(w string) bool { return w != "*" && w != "**" }):
+		// A match of wildcards alone is every command, and `from` then
+		// blanks the arguments of every record: the audit trail, not a
+		// secret. Name the word the secret follows, with after.
+		return errors.New("a match of * and ** alone matches every command, and from would remove the arguments of " +
+			"every record; name the command's words, or use after with the word the secret follows")
+	}
+	return nil
+}
+
+// redactions is the built-in table, platforms/redact.yaml, parsed once. An
+// embedded file that does not load is a build defect: TestBuiltInRedactionsLoad
+// keeps it from reaching a binary.
+var redactions = mustLoadRedactions(platforms.Redact)
+
+func mustLoadRedactions(raw []byte) map[string][]Redaction {
+	out, err := LoadRedactions(raw)
+	if err != nil {
+		panic("platform: the built-in redactions do not load: " + err.Error())
+	}
+	return out
+}
+
+// LoadRedactions reads a redaction table: platform name, or `default`, to its
+// patterns.
+func LoadRedactions(raw []byte) (map[string][]Redaction, error) {
+	var out map[string][]Redaction
+	dec := yaml.NewDecoder(bytes.NewReader(raw))
+	dec.KnownFields(true)
+	if err := dec.Decode(&out); err != nil {
+		return nil, err
+	}
+	if len(out["default"]) == 0 {
+		return nil, errors.New("the redaction table has no default list")
+	}
+	for _, name := range sortedKeys(out) {
+		for i, r := range out[name] {
+			if err := r.check(); err != nil {
+				return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
+			}
+		}
+	}
+	return out, nil
+}
+
+// Redactions is a platform's built-in patterns, copied: the default list, and
+// the platform's own after it. A platform's list adds and never replaces, so
+// a word the default removes is removed on every platform.
+func Redactions(platformName string) []Redaction {
+	list := slices.Clone(redactions["default"])
+	if platformName != "default" {
+		list = append(list, redactions[platformName]...)
+	}
+	return list
+}
+
+// Redact applies rules to a command's elements — a vector, or the values of
+// a record's cmd and cmd-arg pairs — and returns them with every removed word
+// replaced by Redacted, and whether any was. Each element is split into words,
+// because Junos sends a whole command line as one `cmd`. Where abbrev is set,
+// the platform may send what was typed, so a pattern's word also matches any
+// abbreviation of it — `sec` for `secret` — which removes more rather than
+// less. An element no pattern touches comes back as it was.
+func Redact(rules []Redaction, abbrev bool, elements []string) ([]string, bool) {
+	var words []string
+	var owner []int
+	for i, e := range elements {
+		for _, w := range strings.Fields(e) {
+			words, owner = append(words, w), append(owner, i)
+		}
+	}
+	hide := make([]bool, len(words))
+	redacted := false
+	for _, r := range rules {
+		if !matchWords(r.Match, words, abbrev) {
+			continue
+		}
+		start := len(words)
+		switch {
+		case r.After != "":
+			for i := 1; i < len(words); i++ {
+				if sameWord(r.After, words[i], abbrev) {
+					start = i + 1
+					break
+				}
+			}
+		case *r.From > 0:
+			start = *r.From
+		default:
+			start = len(words) + *r.From
+		}
+		for i := max(start, 1); i < len(words); i++ {
+			hide[i], redacted = true, true
+		}
+	}
+	if !redacted {
+		return elements, false
+	}
+	out := slices.Clone(elements)
+	touched := map[int]bool{}
+	for i, h := range hide {
+		if h {
+			touched[owner[i]] = true
+		}
+	}
+	for e := range touched {
+		var rebuilt []string
+		for i, w := range words {
+			if owner[i] != e {
+				continue
+			}
+			if hide[i] {
+				w = Redacted
+			}
+			rebuilt = append(rebuilt, w)
+		}
+		out[e] = strings.Join(rebuilt, " ")
+	}
+	return out, true
+}
+
+// RedactRaw applies rules to a record's raw AV pairs: the values of its cmd
+// and cmd-arg pairs are the command's elements, a trailing `<cr>` aside, and
+// each keeps its own key and separator.
+func RedactRaw(rules []Redaction, abbrev bool, raw []string) ([]string, bool) {
+	var at []int
+	var elements []string
+	for i, a := range raw {
+		j := strings.IndexAny(a, "=*")
+		if j < 0 || (a[:j] != "cmd" && a[:j] != "cmd-arg") {
+			continue
+		}
+		at, elements = append(at, i), append(elements, a[j+1:])
+	}
+	if n := len(elements); n > 0 && elements[n-1] == "<cr>" {
+		at, elements = at[:n-1], elements[:n-1]
+	}
+	redactedElements, redacted := Redact(rules, abbrev, elements)
+	if !redacted {
+		return raw, false
+	}
+	out := slices.Clone(raw)
+	for k, i := range at {
+		j := strings.IndexAny(out[i], "=*")
+		out[i] = out[i][:j+1] + redactedElements[k]
+	}
+	return out, true
+}
+
+// matchWords reports whether pattern matches every word, anchored at both
+// ends: a word matches itself case-insensitively, `*` one word, `**` any
+// number.
+func matchWords(pattern, words []string, abbrev bool) bool {
+	if len(pattern) == 0 {
+		return len(words) == 0
+	}
+	switch pattern[0] {
+	case "**":
+		for i := 0; i <= len(words); i++ {
+			if matchWords(pattern[1:], words[i:], abbrev) {
+				return true
+			}
+		}
+		return false
+	case "*":
+		return len(words) > 0 && matchWords(pattern[1:], words[1:], abbrev)
+	}
+	return len(words) > 0 && sameWord(pattern[0], words[0], abbrev) && matchWords(pattern[1:], words[1:], abbrev)
+}
+
+// sameWord reports whether word, as a pattern writes it, is the word sent:
+// equal ignoring case, or where abbrev is set a shorter prefix of it.
+func sameWord(word, sent string, abbrev bool) bool {
+	if strings.EqualFold(word, sent) {
+		return true
+	}
+	return abbrev && sent != "" && len(sent) < len(word) && strings.EqualFold(word[:len(sent)], sent)
+}
````

<!-- patch: internal/policy/diff.go -->
````diff
diff --git a/internal/policy/diff.go b/internal/policy/diff.go
index 07a1968..e702a6b 100644
--- a/internal/policy/diff.go
+++ b/internal/policy/diff.go
@@ -75,9 +75,11 @@ type AdapterChange struct {
 
 // gatedAdapterKeys are the adapter keys an edit to is gated; every other key
 // is reported. A key a later plan adds is reported until it is listed here.
+// `redact` is gated because it changes what the audit keeps: a pattern wide
+// enough removes what every command was typed with from the log and the spool.
 var gatedAdapterKeys = []string{"supports", "privilege", "ceiling_levels", "entity_classes", "expands_abbreviations",
 	"splits_interface_names", "pipe_token", "pipe_authorized", "strip_cr", "privilege_attributes", "inert_attributes",
-	"accepted_attributes", "enable_username"}
+	"accepted_attributes", "enable_username", "redact"}
 
 // UnacknowledgedAdapters counts the gated adapter edits no acknowledge: entry
 // names.
````

<!-- patch: platforms/platforms.go -->
````diff
diff --git a/platforms/platforms.go b/platforms/platforms.go
index 6d4c9a8..a558a07 100644
--- a/platforms/platforms.go
+++ b/platforms/platforms.go
@@ -16,3 +16,9 @@ import "embed"
 //
 //go:embed */*.yaml
 var FS embed.FS
+
+// Redact is the built-in redaction table (spec §5.8), which is not pinned:
+// redaction changes what the log keeps, never what anyone may do.
+//
+//go:embed redact.yaml
+var Redact []byte
````

<!-- patch: platforms/redact.yaml -->
````diff
diff --git a/platforms/redact.yaml b/platforms/redact.yaml
new file mode 100644
index 0000000..fa9e90c
--- /dev/null
+++ b/platforms/redact.yaml
@@ -0,0 +1,41 @@
+# Redaction patterns (spec §5.8): the words of a command that are removed
+# before an accounting or authorization record is written, because a typed
+# secret — `username bob secret Hunter2` — arrives in full.
+#
+# These are NOT part of a pinned platform set. Redaction changes what the log
+# keeps and never what anyone may do, so a pattern a release adds applies at
+# upgrade, and a policy file's `platforms.<name>.redact` adds to these; it
+# never removes one.
+#
+# Best-effort, and said so: a pattern that misses leaks. Every pattern here is
+# vendor syntax, unmeasured in the lab. Each is `{match: [...], after: <word>}`
+# — a command the pattern matches loses every word after the first word equal
+# to <word> — or `{match: [...], from: N}`, every word from position N on (0 is
+# the command word and is never removed; a negative N counts from the end).
+# `*` is one word and `**` any number, as in a rule.
+#
+# `default` applies to every platform, an unmodeled one included; a
+# platform's own list adds to it and never replaces it.
+#
+# The patterns lead with `**` because a secret can sit anywhere in a line, and
+# NX-OS's accounting `cmd` is the configuration path joined with ` ; ` and a
+# result, `configure terminal ; username bob password ... (SUCCESS)`
+# (tests/lab/results/L21-cisco_nxos.md): a pattern anchored at the command
+# word would never match it.
+default:
+  - {match: ['**'], after: secret}
+  - {match: ['**'], after: password}
+  - {match: ['**'], after: key}
+  - {match: ['**'], after: key-string}
+  - {match: ['**'], after: authentication-key}
+  - {match: ['**'], after: message-digest-key}
+  - {match: ['**'], after: community}
+  # SNMPv3 passphrases: `snmp-server user u g v3 auth sha <pass> priv aes 128
+  # <pass>`. Scoped to the command, so `auth` elsewhere is left alone.
+  - {match: ['**', snmp-server, user, '**'], after: auth}
+juniper_junos:
+  - {match: ['**'], after: encrypted-password}
+  - {match: ['**'], after: plain-text-password-value}
+  - {match: ['**'], after: pre-shared-key}
+  - {match: ['**'], after: authentication-password}
+  - {match: ['**'], after: privacy-password}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add platforms internal/platform
git commit -m "feat: redaction patterns, built in and unpinned (spec §5.8)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: No record is written with a typed secret in it

**Files:**
- Modify: `internal/platform/redact.go` (`Redactor`, `BuiltInRedactor`, `RedactRecord`)
- Modify: `internal/decision/log.go` (`Request.Redacted`, `AcctRecord.Redacted`)
- Modify: `internal/daemon/author/author.go` (`WithRedactor`; `emit` redacts),
  `internal/daemon/acct/acct.go` (`WithRedactor`; redact before `Offer`)
- Modify: `internal/replay/replay.go` (a redacted record is `unverifiable`)
- Modify: `cmd/port49d/main.go` (`redactorFor`, wired into both handlers)
- Test: `internal/daemon/author/author_test.go`, `internal/daemon/acct/acct_test.go`,
  `internal/replay/replay_test.go`, `cmd/port49d/redact_test.go`, `internal/platform/redact_test.go`

**Interfaces:**
- Produces: `type platform.Redactor func(platformName string) (rules []Redaction, abbrev bool)`;
  `platform.BuiltInRedactor`; `func platform.RedactRecord(rules []Redaction, abbrev bool, raw,
  vector []string) ([]string, []string, bool)` — both forms of a record together, the form a
  pattern missed losing every argument where the other lost a word (pre-flight N2);
  `(*author.Handler).WithRedactor(platform.Redactor) *author.Handler`;
  `(*acct.Handler).WithRedactor(platform.Redactor) *acct.Handler`. A handler with none uses the
  built-in patterns, so no constructor changes and no test helper moves.
- JSON: `request.redacted`, `record.redacted`, `omitempty`.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49d/redact_test.go -->
````diff
diff --git a/cmd/port49d/redact_test.go b/cmd/port49d/redact_test.go
new file mode 100644
index 0000000..b239d2f
--- /dev/null
+++ b/cmd/port49d/redact_test.go
@@ -0,0 +1,39 @@
+package main
+
+import (
+	"reflect"
+	"testing"
+
+	"github.com/blanketfish/port49/internal/platform"
+	"github.com/blanketfish/port49/internal/policy"
+)
+
+// port49d redacts with the built-in patterns and, where a policy is in force,
+// the ones its `platforms:` blocks add, read at each record so a reload
+// reaches them (spec §5.8).
+func TestTheDaemonRedactsWithThePolicyInForce(t *testing.T) {
+	if rules, abbrev := redactorFor(nil)("arista_eos"); !reflect.DeepEqual(rules, platform.Redactions("arista_eos")) ||
+		abbrev {
+		t.Fatalf("no policy: %+v %v", rules, abbrev)
+	}
+	parse := func(body string) *policy.Policy {
+		p, err := policy.Parse([]byte(body+minimalPolicy), policy.Env{})
+		if err != nil {
+			t.Fatal(err)
+		}
+		return p
+	}
+	live := policy.NewLive(parse(""))
+	redact := redactorFor(live)
+	if rules, _ := redact("arista_eos"); len(rules) != len(platform.Redactions("arista_eos")) {
+		t.Fatalf("%+v", rules)
+	}
+	live.Swap(parse("platforms: {arista_eos: {redact: [{match: ['**'], after: psk}]}}\n"))
+	rules, abbrev := redact("arista_eos")
+	if len(rules) != len(platform.Redactions("arista_eos"))+1 || rules[len(rules)-1].After != "psk" || abbrev {
+		t.Fatalf("after the reload: %+v %v", rules, abbrev)
+	}
+	if _, abbrev := redact("juniper_junos"); !abbrev {
+		t.Fatal("junos may send what was typed")
+	}
+}
````

<!-- patch: internal/daemon/acct/acct_test.go -->
````diff
diff --git a/internal/daemon/acct/acct_test.go b/internal/daemon/acct/acct_test.go
index e39bf04..6c8d075 100644
--- a/internal/daemon/acct/acct_test.go
+++ b/internal/daemon/acct/acct_test.go
@@ -694,3 +694,31 @@ func TestASystemRecordCarriesItsPort(t *testing.T) {
 		t.Fatalf("a system record must stay system and carry the port it arrived on: %v", m)
 	}
 }
+
+// Command accounting carries typed text verbatim, so a secret is replaced
+// before the record reaches the spool, which is on disk (spec §5.8). The
+// record keeps its shape and says it was redacted, and the attribution was
+// read from the record as sent.
+func TestAccountingNeverWritesASecret(t *testing.T) {
+	h, _, out, stop := setup(t)
+	h.Handle(context.Background(), peer, acct(wire.AcctFlagStop, "alice", "vty0", "task_id=44", "service=shell",
+		"cmd=enable", "cmd-arg=secret", "cmd-arg=0", "cmd-arg=Hunter2", "cmd-arg=<cr>"))
+	junos := authen.Peer{NAS: "srx-01", NASAddr: "10.20.0.8", Platform: "juniper_junos"}
+	h.Handle(context.Background(), junos, acct(wire.AcctFlagStop, "alice", "0", "task_id=2", "service=shell",
+		"session_pid = 31050", `cmd=set system root-authentication encrypted-password "$6$abc" <cr>`))
+	stop()
+	if strings.Contains(out.String(), "Hunter2") || strings.Contains(out.String(), "$6$abc") {
+		t.Fatalf("a secret reached the sink: %s", out.String())
+	}
+	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
+	var m map[string]any
+	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
+		t.Fatal(err)
+	}
+	rec := m["record"].(map[string]any)
+	vec := rec["vector"].([]any)
+	if m["attribution"] != "resolved" || rec["redacted"] != true || len(vec) != 4 || vec[2] != platform.Redacted ||
+		vec[3] != platform.Redacted {
+		t.Fatalf("%v", m)
+	}
+}
````

<!-- patch: internal/daemon/author/author_test.go -->
````diff
diff --git a/internal/daemon/author/author_test.go b/internal/daemon/author/author_test.go
index c09baac..6377ce4 100644
--- a/internal/daemon/author/author_test.go
+++ b/internal/daemon/author/author_test.go
@@ -969,3 +969,38 @@ func (c *countingTouchStore) TouchContext(ctx context.Context, k store.ContextKe
 	c.touches++
 	return c.Store.TouchContext(ctx, k, ttl)
 }
+
+// A typed secret is authorized like any command and never written: the
+// record's raw pairs and vector carry «redacted» where it was, keep their
+// shape, and say they were redacted (spec §5.7, §5.8). A redactor the daemon
+// is given — the policy in force's — applies in place of the built-in one.
+func TestASecretIsDecidedButNeverWritten(t *testing.T) {
+	h, _, log := setup(t)
+	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=username",
+		"cmd-arg=bob", "cmd-arg=secret", "cmd-arg=Hunter2", "cmd-arg=<cr>"))
+	if resp.Status != wire.AuthorStatusPassAdd {
+		t.Fatalf("%+v", resp)
+	}
+	if strings.Contains(log.String(), "Hunter2") {
+		t.Fatalf("the secret reached the log: %s", log.String())
+	}
+	r := lastRecord(t, log)["request"].(map[string]any)
+	raw, vec := r["raw"].([]any), r["vector"].([]any)
+	if r["redacted"] != true || len(raw) != 6 || raw[4] != "cmd-arg="+platform.Redacted || raw[5] != "cmd-arg=<cr>" ||
+		len(vec) != 4 || vec[3] != platform.Redacted || vec[2] != "secret" {
+		t.Fatalf("%v", r)
+	}
+	// A command with nothing to redact says nothing about it.
+	h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show", "cmd-arg=version"))
+	if r := lastRecord(t, log)["request"].(map[string]any); r["redacted"] != nil {
+		t.Fatalf("%v", r)
+	}
+	h.WithRedactor(func(string) ([]platform.Redaction, bool) {
+		return []platform.Redaction{{Match: []string{"**"}, After: "psk"}}, false
+	})
+	h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=crypto", "cmd-arg=psk",
+		"cmd-arg=s3cret"))
+	if strings.Contains(log.String(), "s3cret") {
+		t.Fatalf("the redactor the daemon was given did not apply: %s", log.String())
+	}
+}
````

<!-- patch: internal/platform/redact_test.go -->
````diff
diff --git a/internal/platform/redact_test.go b/internal/platform/redact_test.go
index 8feafb7..97e2614 100644
--- a/internal/platform/redact_test.go
+++ b/internal/platform/redact_test.go
@@ -175,3 +175,22 @@ func TestABlockAddsRedactions(t *testing.T) {
 		t.Fatalf("%+v", d.Redact)
 	}
 }
+
+// A record's raw pairs and its vector are two spellings of one command. A
+// pattern anchored at both ends can match one and not the other — the raw
+// pairs lose their `<cr>`, the vector may keep it — so where either form loses
+// a word and the other matched nothing, the other loses every argument: the
+// secret is never left standing in the form the pattern missed.
+func TestARecordIsRedactedInBothForms(t *testing.T) {
+	rules := []Redaction{{Match: []string{"username", "*", "secret", "*"}, After: "secret"}}
+	raw := []string{"cmd=username", "cmd-arg=bob", "cmd-arg=secret", "cmd-arg=Hunter2", "cmd-arg=<cr>"}
+	vector := []string{"username", "bob", "secret", "Hunter2", "<cr>"}
+	gotRaw, gotVector, redacted := RedactRecord(rules, false, raw, vector)
+	if !redacted || strings.Contains(strings.Join(gotRaw, " ")+strings.Join(gotVector, " "), "Hunter2") ||
+		gotVector[0] != "username" || len(gotVector) != len(vector) {
+		t.Fatalf("raw %q vector %q", gotRaw, gotVector)
+	}
+	if r, v, redacted := RedactRecord(rules, false, raw[:2], vector[:2]); redacted || len(r) != 2 || len(v) != 2 {
+		t.Fatalf("nothing matched, nothing changed: %q %q", r, v)
+	}
+}
````

<!-- patch: internal/replay/replay_test.go -->
````diff
diff --git a/internal/replay/replay_test.go b/internal/replay/replay_test.go
index 7ce2b0a..8658f12 100644
--- a/internal/replay/replay_test.go
+++ b/internal/replay/replay_test.go
@@ -225,3 +225,22 @@ func TestALineThatIsNotARecordDivergesAndTheRestReplays(t *testing.T) {
 		t.Fatalf("--line on the torn line: %+v %v", one, err)
 	}
 }
+
+// A record redacted before it was written (spec §5.8) does not carry the
+// command it decided, so the replay says so rather than claim an agreement
+// over the redacted words.
+func TestARedactedRecordIsUnverifiable(t *testing.T) {
+	log, _ := daemonLog(t)
+	lines := strings.Split(strings.TrimSpace(log), "\n")
+	var rec map[string]any
+	if err := json.Unmarshal([]byte(lines[2]), &rec); err != nil {
+		t.Fatal(err)
+	}
+	rec["request"].(map[string]any)["redacted"] = true
+	edited, _ := json.Marshal(rec)
+	lines[2] = string(edited)
+	res := replayAll(t, strings.Join(lines, "\n"))
+	if r := res[1]; r.Status != Unverifiable || !strings.Contains(r.Detail, "redacted before it was written") {
+		t.Fatalf("%+v", r)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/... ./internal/replay/ ./cmd/port49d/ ./internal/platform/`
Expected: FAIL — `h.WithRedactor undefined`, `undefined: redactorFor`, `undefined: RedactRecord`
(build failed), and `TestAccountingNeverWritesASecret`, `TestARedactedRecordIsUnverifiable`.

- [ ] **Step 3: Redact before writing**

<!-- patch: cmd/port49d/main.go -->
````diff
diff --git a/cmd/port49d/main.go b/cmd/port49d/main.go
index bbbba2e..78bfeb9 100644
--- a/cmd/port49d/main.go
+++ b/cmd/port49d/main.go
@@ -339,6 +339,20 @@ func sayPolicy(pol *policy.Policy, now time.Time) {
 	}
 }
 
+// redactorFor is the redaction port49d applies before any record is written
+// (spec §5.8): the built-in patterns and, where a policy is in force, the
+// ones its `platforms:` blocks add, read at each record so a reload reaches
+// them. With no policy the built-in patterns apply alone.
+func redactorFor(live *policy.Live) platform.Redactor {
+	if live == nil {
+		return platform.BuiltInRedactor
+	}
+	return func(name string) ([]platform.Redaction, bool) {
+		d := live.Load().Dialect(name)
+		return append(platform.Redactions(name), d.Redact...), !d.ExpandsAbbreviations
+	}
+}
+
 // watchQuarantine is what the daemon asks of the policy: whether a device is
 // quarantined at the time of a packet (spec §10; §13 decision 20), and at each
 // scrape how many are, for port49_devices_quarantined. Quarantine is
@@ -516,13 +530,13 @@ func run(parent context.Context, cfgPath string) error {
 		// The grace window is carried for plan 7's sweep and read by nothing
 		// today.
 		Author: author.New(handlerStore, authz, log, m, time.Now, cfg.SessionServices,
-			cfg.Session.StalenessCeiling, cfg.Session.GraceWindow, cfg.ContextIdleTTL),
+			cfg.Session.StalenessCeiling, cfg.Session.GraceWindow, cfg.ContextIdleTTL).WithRedactor(redactorFor(live)),
 		// The system-user table is injected rather than looked up through a
 		// package global, so nothing can mutate a security rule at run time.
 		// It carries `root` for juniper_junos and nothing else
 		// (internal/platform). No idle TTL: accounting does not extend one
 		// (spec §5.8).
-		Acct:   acct.New(handlerStore, spool, m, time.Now, platform.SystemUsers()),
+		Acct:   acct.New(handlerStore, spool, m, time.Now, platform.SystemUsers()).WithRedactor(redactorFor(live)),
 		Limits: lim, Metrics: m, Log: log, Now: time.Now, IdleTimeout: cfg.Limits.IdleTimeout}
 
 	// A dead metrics listener is not a detail: without it nobody can see the
````

<!-- patch: internal/daemon/acct/acct.go -->
````diff
diff --git a/internal/daemon/acct/acct.go b/internal/daemon/acct/acct.go
index 7b92012..21c50b6 100644
--- a/internal/daemon/acct/acct.go
+++ b/internal/daemon/acct/acct.go
@@ -33,6 +33,17 @@ type Handler struct {
 	// production state in the production binary, and an unlocked map read by
 	// parallel requests.
 	systemUsers map[string][]string
+	// redact is the redaction every record passes through before it reaches
+	// the spool (spec §5.8); nil is the built-in patterns.
+	redact platform.Redactor
+}
+
+// WithRedactor sets the redaction applied to every record before it reaches
+// the spool: port49d passes the policy in force's. Without it the built-in
+// patterns apply.
+func (h *Handler) WithRedactor(r platform.Redactor) *Handler {
+	h.redact = r
+	return h
 }
 
 // New builds the accounting handler.
@@ -143,6 +154,17 @@ func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AcctReq
 		rec.Principal = c.Principal
 		rec.Session.CtxID = c.CtxID
 	}
+	// Before the spool, which is on disk: command accounting carries typed
+	// text verbatim, and a secret must not reach the disk any more than the
+	// sink (spec §5.8). The attribution above read the record as sent.
+	redact := h.redact
+	if redact == nil {
+		redact = platform.BuiltInRedactor
+	}
+	rules, abbrev := redact(peer.Platform)
+	if r, v, ok := platform.RedactRecord(rules, abbrev, raw, vector); ok {
+		rec.AcctRecord.Raw, rec.AcctRecord.Vector, rec.AcctRecord.Redacted = r, v, true
+	}
 
 	if err := h.spool.Offer(rec); err != nil {
 		h.metrics.Requests.WithLabelValues("acct", "error").Inc()
````

<!-- patch: internal/daemon/author/author.go -->
````diff
diff --git a/internal/daemon/author/author.go b/internal/daemon/author/author.go
index 8a92242..121315e 100644
--- a/internal/daemon/author/author.go
+++ b/internal/daemon/author/author.go
@@ -87,6 +87,17 @@ type Handler struct {
 	// context to. It is an idle clock, not a session clock — session_expires
 	// is the session clock — so activity slides it forward (spec §5.6).
 	contextIdleTTL time.Duration
+	// redact is the redaction every record passes through before it is
+	// written (spec §5.8); nil is the built-in patterns.
+	redact platform.Redactor
+}
+
+// WithRedactor sets the redaction applied to every record before it is
+// written: port49d passes the policy in force's, so a `platforms:` block's
+// patterns reach the log. Without it the built-in patterns apply.
+func (h *Handler) WithRedactor(r platform.Redactor) *Handler {
+	h.redact = r
+	return h
 }
 
 // New builds an authorization handler. stalenessCeiling, graceWindow and
@@ -349,6 +360,21 @@ func (h *Handler) deny(rec decision.Record, reason decision.Reason, msg string)
 }
 
 func (h *Handler) emit(rec decision.Record) {
+	// The decision was made on the command as sent; only the record loses
+	// its secret. A typed `username bob secret Hunter2` is authorized like
+	// any command and is never written (spec §5.7, §5.8).
+	if rec.Request != nil && rec.Device != nil {
+		redact := h.redact
+		if redact == nil {
+			redact = platform.BuiltInRedactor
+		}
+		rules, abbrev := redact(rec.Device.Platform)
+		if raw, vector, ok := platform.RedactRecord(rules, abbrev, rec.Request.Raw, rec.Request.Vector); ok {
+			req := *rec.Request
+			req.Raw, req.Vector, req.Redacted = raw, vector, true
+			rec.Request = &req
+		}
+	}
 	h.log.Emit(rec)
 	h.metrics.Decisions.WithLabelValues(rec.Event, rec.Verdict, string(rec.Reason)).Inc()
 }
````

<!-- patch: internal/decision/log.go -->
````diff
diff --git a/internal/decision/log.go b/internal/decision/log.go
index 586f7cb..bf07bf4 100644
--- a/internal/decision/log.go
+++ b/internal/decision/log.go
@@ -117,6 +117,10 @@ type Request struct {
 	Service string   `json:"service,omitempty"`
 	Raw     []string `json:"raw"`
 	Vector  []string `json:"vector"`
+	// Redacted says words of Raw and Vector were replaced with «redacted»
+	// before the record was written (spec §5.8): a typed secret is never
+	// logged, and a replay cannot see the command that was decided.
+	Redacted bool `json:"redacted,omitempty"`
 }
 
 // Reply is what a permitted authorization returned to the device, as sent: a
@@ -127,12 +131,15 @@ type Reply struct {
 }
 
 type AcctRecord struct {
-	Raw         []string `json:"raw"`
-	Vector      []string `json:"vector"`
-	PrivLvl     uint8    `json:"priv_lvl"`
-	StartTime   int64    `json:"start_time,omitempty"`
-	StopTime    int64    `json:"stop_time,omitempty"`
-	ElapsedTime int64    `json:"elapsed_time,omitempty"`
+	Raw    []string `json:"raw"`
+	Vector []string `json:"vector"`
+	// Redacted is Request.Redacted's twin: words were replaced before the
+	// record reached the spool, so no secret is ever on disk (spec §5.8).
+	Redacted    bool  `json:"redacted,omitempty"`
+	PrivLvl     uint8 `json:"priv_lvl"`
+	StartTime   int64 `json:"start_time,omitempty"`
+	StopTime    int64 `json:"stop_time,omitempty"`
+	ElapsedTime int64 `json:"elapsed_time,omitempty"`
 }
 
 // Mint is the audit trail for authority (spec §5.7): which tokens were issued,
````

<!-- patch: internal/platform/redact.go -->
````diff
diff --git a/internal/platform/redact.go b/internal/platform/redact.go
index c5fdc51..568b667 100644
--- a/internal/platform/redact.go
+++ b/internal/platform/redact.go
@@ -95,6 +95,18 @@ func LoadRedactions(raw []byte) (map[string][]Redaction, error) {
 	return out, nil
 }
 
+// Redactor says which patterns apply to a platform's records and whether the
+// platform may send what was typed. The daemon's handlers take one, so a
+// policy's `platforms:` blocks reach them (spec §5.8).
+type Redactor func(platformName string) (rules []Redaction, abbrev bool)
+
+// BuiltInRedactor is the Redactor with no policy in force: the built-in
+// patterns, and the built-in adapter's word on abbreviations.
+func BuiltInRedactor(platformName string) ([]Redaction, bool) {
+	d, _ := DialectFor(platformName)
+	return Redactions(platformName), !d.ExpandsAbbreviations
+}
+
 // Redactions is a platform's built-in patterns, copied: the default list, and
 // the platform's own after it. A platform's list adds and never replaces, so
 // a word the default removes is removed on every platform.
@@ -171,6 +183,32 @@ func Redact(rules []Redaction, abbrev bool, elements []string) ([]string, bool)
 	return out, true
 }
 
+// RedactRecord applies rules to a record's raw pairs and its vector, which are
+// two spellings of one command. A pattern anchored at both ends can match one
+// and miss the other — the raw pairs drop their `<cr>` — so where either form
+// loses a word and the other matched nothing, the other loses every argument:
+// removing more rather than leaving the secret in the form the pattern
+// missed (spec §5.8).
+func RedactRecord(rules []Redaction, abbrev bool, raw, vector []string) ([]string, []string, bool) {
+	r, inRaw := RedactRaw(rules, abbrev, raw)
+	v, inVector := Redact(rules, abbrev, vector)
+	if inRaw == inVector {
+		return r, v, inRaw
+	}
+	// Every argument: the rule check refuses this pattern in a file, where it
+	// would blank every record; here it applies to one record already found
+	// to carry a secret.
+	one := 1
+	everything := []Redaction{{Match: []string{"**"}, From: &one}}
+	if !inRaw {
+		r, _ = RedactRaw(everything, false, raw)
+	}
+	if !inVector {
+		v, _ = Redact(everything, false, vector)
+	}
+	return r, v, true
+}
+
 // RedactRaw applies rules to a record's raw AV pairs: the values of its cmd
 // and cmd-arg pairs are the command's elements, a trailing `<cr>` aside, and
 // each keeps its own key and separator.
````

<!-- patch: internal/replay/replay.go -->
````diff
diff --git a/internal/replay/replay.go b/internal/replay/replay.go
index 08d38a9..aa9f016 100644
--- a/internal/replay/replay.go
+++ b/internal/replay/replay.go
@@ -248,6 +248,12 @@ func one(rec decision.Record, p *program) (Status, string) {
 		if rec.Request == nil {
 			return Diverge, "the record has no request to replay"
 		}
+		if rec.Request.Redacted {
+			// The command it decided is not in the log, by design: replaying
+			// the redacted words would claim an agreement nobody can check.
+			return Unverifiable, "the record was redacted before it was written (spec §5.8), so the command it " +
+				"decided is not in the log"
+		}
 		o := prog.Command(rec.Request.Raw)
 		reason = o.Reason
 		if !o.Permit {
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal cmd
git commit -m "feat: no record is written with a typed secret in it (spec §5.7, §5.8)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: `port49 platform list`, `show` and `export`

**Files:**
- Create: `cmd/port49/platform.go`
- Modify: `cmd/port49/main.go` (usage, dispatch)
- Modify: `internal/platform/adapter.go` (`omitempty` on every key; `Verified`; `Validate`),
  `internal/platform/dialect.go` (`Verified`)
- Modify: `internal/policy/load.go` (a block may not set `verified`; `PlatformNames`,
  `PlatformSource`)
- Test: `cmd/port49/platform_test.go`, `internal/platform/adapter_test.go`,
  `internal/policy/platforms_test.go`

**Interfaces:**
- Produces: `Dialect.Verified string` (`""`, `containerlab`, `community`), key `verified`;
  `func (p *Policy) PlatformNames() []string`; `func (p *Policy) PlatformSource(name string) string`
  (`built-in`, `overridden`, `variant`, `local`). Commands:
  `port49 platform list [--set V | --policy F --inventory I]`,
  `port49 platform show [...] PLATFORM`, `port49 platform export [...] (PLATFORM | --all --dir DIR)`.
  An export read back with `ParseSpecs` and laid over nothing is the adapter again; `export --all`
  writes a directory `LoadSets` reads back as the set.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/platform_test.go -->
````diff
diff --git a/cmd/port49/platform_test.go b/cmd/port49/platform_test.go
new file mode 100644
index 0000000..5276533
--- /dev/null
+++ b/cmd/port49/platform_test.go
@@ -0,0 +1,121 @@
+package main
+
+import (
+	"bytes"
+	"os"
+	"path/filepath"
+	"reflect"
+	"strings"
+	"testing"
+
+	"github.com/blanketfish/port49/internal/platform"
+)
+
+// `port49 platform list` prints every platform with where its adapter comes
+// from, how it was verified and what it authorizes (spec §8); with a policy,
+// its blocks are named for what they are, and an adapter a block changed is
+// not the one anybody verified.
+func TestPlatformListSaysWhereEachAdapterComesFrom(t *testing.T) {
+	var out, errb bytes.Buffer
+	if code := run([]string{"platform", "list"}, &out, &errb); code != 0 ||
+		!strings.HasPrefix(out.String(), "PLATFORM") || strings.Count(out.String(), "built-in") != 4 ||
+		listRow(out.String(), "juniper_junos") != "juniper_junos built-in — session" {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	pol, inv := policyFixture(t)
+	raw := readFile(t, pol)
+	blocks := "platforms:\n  arista_eos: {entity_classes: {uplink: ['^Ethernet49$']}}\n" +
+		"  whitebox_nos: {based_on: arista_eos}\n  meinberg_lantime: {supports: [session]}\n"
+	if err := os.WriteFile(pol, append([]byte(blocks), raw...), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	out.Reset()
+	if code := run([]string{"platform", "list", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	for name, want := range map[string]string{"arista_eos": "overridden — session,commands",
+		"meinberg_lantime": "local — session", "whitebox_nos": "variant — session,commands"} {
+		if got := listRow(out.String(), name); got != name+" "+want {
+			t.Errorf("%s: %q in\n%s", name, got, out.String())
+		}
+	}
+	if code := run([]string{"platform", "list", "--set", "0.1.0"}, &out, &errb); code != 1 ||
+		!strings.Contains(errb.String(), "it ships 1.0.0") {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+}
+
+// `show` prints the adapter as a file writes it, headed by where it came from
+// and followed by the built-in redaction; `export` prints the file alone, and
+// what it prints is the adapter again when read back (spec §8).
+func TestPlatformShowAndExportPrintTheAdapter(t *testing.T) {
+	var out, errb bytes.Buffer
+	if code := run([]string{"platform", "show", "cisco_iosxe"}, &out, &errb); code != 0 {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+	for _, want := range []string{"# cisco_iosxe: built-in, platform set 1.0.0\n", "      operator:\n        - priv-lvl=7\n",
+		"    accepted_attributes:\n      - priv-lvl\n", "      - privilege exec level 7 clear counters\n",
+		"#   {match: ['**'], after: secret}\n"} {
+		if !strings.Contains(out.String(), want) {
+			t.Errorf("missing %q in\n%s", want, out.String())
+		}
+	}
+	for _, name := range platform.Names() {
+		out.Reset()
+		if code := run([]string{"platform", "export", name}, &out, &errb); code != 0 {
+			t.Fatalf("%s: code %d %s", name, code, errb.String())
+		}
+		specs, err := platform.ParseSpecs(out.Bytes())
+		if err != nil {
+			t.Fatalf("%s: %v\n%s", name, err, out.String())
+		}
+		want, _ := platform.DialectFor(name)
+		if got := specs[name].Over(platform.Dialect{}); !reflect.DeepEqual(got, want) {
+			t.Errorf("%s:\n got %+v\nwant %+v", name, got, want)
+		}
+	}
+	if code := run([]string{"platform", "show", "junos"}, &out, &errb); code != 1 ||
+		!strings.Contains(errb.String(), `"junos" has no adapter here; the platforms are arista_eos,`) {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+}
+
+// `export --all --dir` writes one file per platform, and the directory is a
+// platform set LoadSets reads back as the one it was written from: a file
+// fit for platforms/ in an upstream pull request.
+func TestPlatformExportAllWritesASet(t *testing.T) {
+	root := t.TempDir()
+	dir := filepath.Join(root, "1.0.0")
+	if err := os.Mkdir(dir, 0o755); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	if code := run([]string{"platform", "export", "--all", "--dir", dir}, &out, &errb); code != 0 {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+	sets, err := platform.LoadSets(os.DirFS(root))
+	if err != nil {
+		t.Fatal(err)
+	}
+	want, _ := platform.Set(platform.DefaultSet)
+	if !reflect.DeepEqual(sets["1.0.0"], want) {
+		t.Fatalf("the exported set reads back differently:\n%+v", sets["1.0.0"])
+	}
+	for _, args := range [][]string{{"platform", "show", "--all", "--dir", dir}, {"platform", "export", "--all"},
+		{"platform", "export"}, {"platform", "list", "extra"}, {"platform"}, {"platform", "upgrad"}} {
+		if code := run(args, &out, &errb); code != 2 {
+			t.Errorf("%q: code %d", args, code)
+		}
+	}
+}
+
+// listRow is the `platform list` line for name, its columns joined by one
+// space, so a test does not depend on how wide another row made them.
+func listRow(out, name string) string {
+	for _, line := range strings.Split(out, "\n") {
+		if f := strings.Fields(line); len(f) > 0 && f[0] == name {
+			return strings.Join(f, " ")
+		}
+	}
+	return ""
+}
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index f10e966..aa1d950 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -231,7 +231,8 @@ func TestValidateNamesTheField(t *testing.T) {
 		"not in accepted_attributes": with(ok, func(d *Dialect) {
 			d.Levels, d.AcceptedAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"priv-lvl"}
 		}),
-		"device_config[0]": with(ok, func(d *Dialect) { d.DeviceConfig = []string{"line one\nline two"} }),
+		"device_config[0]":    with(ok, func(d *Dialect) { d.DeviceConfig = []string{"line one\nline two"} }),
+		"verified is \"lab\"": with(ok, func(d *Dialect) { d.Verified = "lab" }),
 	} {
 		err := Validate("x", d)
 		if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "platforms.x.") {
````

<!-- patch: internal/policy/platforms_test.go -->
````diff
diff --git a/internal/policy/platforms_test.go b/internal/policy/platforms_test.go
index ec8096a..4db69a9 100644
--- a/internal/policy/platforms_test.go
+++ b/internal/policy/platforms_test.go
@@ -112,6 +112,7 @@ func TestAPlatformBlockIsRefusedByName(t *testing.T) {
 		{"an unknown key", "  arista_eos: {entity_class: {}}\n", "field entity_class not found"},
 		{"the attributes key", "  all: {supports: [session]}\n", "platforms.all: all is reserved"},
 		{"the redaction default", "  default: {supports: [session]}\n", "platforms.default: default is reserved"},
+		{"a verified claim", "  arista_eos: {verified: containerlab}\n", "platforms.arista_eos: verified is port49's own claim"},
 		{"a rendering the device refuses", "  cisco_iosxe: {privilege: {admin: [\"roles=x\"]}}\n",
 			"platforms.cisco_iosxe.privilege.admin: roles is not in accepted_attributes"},
 	} {
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/ ./cmd/port49/`
Expected: FAIL — `d.Verified undefined` (build failed), the three `TestPlatform…` tests, and
`TestAPlatformBlockIsRefusedByName` (a `verified` block loads).

- [ ] **Step 3: Write the commands**

<!-- patch: cmd/port49/main.go -->
````diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index f0019b2..815da69 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -39,6 +39,9 @@ const usage = `usage:
   port49 policy diff --old FILE --new FILE --inventory FILE
   port49 access review --policy FILE --inventory FILE --subject NAME
   port49 grants remove --policy FILE --inventory FILE --subject NAME [--write]
+  port49 platform list [--set VERSION | --policy FILE --inventory FILE]
+  port49 platform show [--set VERSION | --policy FILE --inventory FILE] PLATFORM
+  port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir DIR)
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
@@ -68,6 +71,8 @@ func run(args []string, stdout, stderr io.Writer) int {
 		if len(args) > 1 && args[1] == "remove" {
 			return grantsRemove(args[2:], stdout, stderr)
 		}
+	case "platform":
+		return platformCmd(args[1:], stdout, stderr)
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
````

<!-- patch: cmd/port49/platform.go -->
````diff
diff --git a/cmd/port49/platform.go b/cmd/port49/platform.go
new file mode 100644
index 0000000..f1b0a4e
--- /dev/null
+++ b/cmd/port49/platform.go
@@ -0,0 +1,218 @@
+package main
+
+import (
+	"bytes"
+	"flag"
+	"fmt"
+	"io"
+	"os"
+	"path/filepath"
+	"slices"
+	"strings"
+	"text/tabwriter"
+
+	"gopkg.in/yaml.v3"
+
+	"github.com/blanketfish/port49/internal/platform"
+	"github.com/blanketfish/port49/internal/policy"
+)
+
+// platformCmd runs `port49 platform SUBCOMMAND` (spec §8, "Knowing what is
+// shipped"): the built-in adapters are files, and these print them, with a
+// policy's `platforms:` blocks laid over them where one is named.
+func platformCmd(args []string, stdout, stderr io.Writer) int {
+	if len(args) == 0 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	switch args[0] {
+	case "list":
+		return platformList(args[1:], stdout, stderr)
+	case "show":
+		return platformShow(args[1:], stdout, stderr, false)
+	case "export":
+		return platformShow(args[1:], stdout, stderr, true)
+	}
+	fmt.Fprint(stderr, usage)
+	return 2
+}
+
+// adapters are the platforms a platform command reads: a built-in set, or,
+// with --policy and --inventory, the policy's set with its blocks over it.
+type adapters struct {
+	files policyFiles
+	set   string
+}
+
+func (a *adapters) register(fs *flag.FlagSet) {
+	a.files.register(fs)
+	fs.StringVar(&a.set, "set", platform.DefaultSet, "the built-in platform set, when no --policy is given")
+}
+
+// load returns the policy, nil without --policy, and a lookup for the
+// adapters in force.
+func (a *adapters) load() (*policy.Policy, map[string]platform.Dialect, error) {
+	if a.files.policy == "" && a.files.inventory == "" {
+		set, ok := platform.Set(a.set)
+		if !ok {
+			return nil, nil, fmt.Errorf("--set %s is not a set this binary ships; it ships %s", a.set,
+				strings.Join(platform.Sets(), ", "))
+		}
+		return nil, set, nil
+	}
+	if a.files.missing() {
+		return nil, nil, fmt.Errorf("--policy and --inventory go together")
+	}
+	p, err := a.files.load()
+	if err != nil {
+		return nil, nil, err
+	}
+	out := map[string]platform.Dialect{}
+	for _, name := range p.PlatformNames() {
+		out[name] = p.Dialect(name)
+	}
+	return p, out, nil
+}
+
+// platformList prints one line per platform: where its adapter comes from,
+// how it was verified, and what it authorizes. A built-in adapter an
+// operator's block changed is not the one the lab verified, so it prints `—`.
+func platformList(args []string, stdout, stderr io.Writer) int {
+	fs := flag.NewFlagSet("port49 platform list", flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	var a adapters
+	a.register(fs)
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	if fs.NArg() != 0 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	p, set, err := a.load()
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 platform list:", err)
+		return 1
+	}
+	tw := tabwriter.NewWriter(stdout, 0, 0, 3, ' ', 0)
+	fmt.Fprintln(tw, "PLATFORM\tSOURCE\tVERIFIED\tSUPPORTS")
+	for _, name := range sortedNames(set) {
+		d, source := set[name], "built-in"
+		if p != nil {
+			source = p.PlatformSource(name)
+		}
+		verified := d.Verified
+		if verified == "" || source != "built-in" {
+			verified = "—"
+		}
+		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, source, verified, strings.Join(d.Supports, ","))
+	}
+	tw.Flush()
+	return 0
+}
+
+// platformShow prints one platform's adapter as a file writes it. `show`
+// heads it with where it came from and follows it with the built-in
+// redaction patterns, which are not part of a set; `export` prints the file
+// alone, for an upstream pull request (spec §8), and with --all --dir writes
+// one file per platform.
+func platformShow(args []string, stdout, stderr io.Writer, export bool) int {
+	name := "port49 platform show"
+	if export {
+		name = "port49 platform export"
+	}
+	fs := flag.NewFlagSet(name, flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	var a adapters
+	a.register(fs)
+	all := fs.Bool("all", false, "every platform, one file each in --dir (export only)")
+	dir := fs.String("dir", "", "the directory --all writes to")
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	switch {
+	case *all && (!export || *dir == "" || fs.NArg() != 0), !*all && (*dir != "" || fs.NArg() != 1):
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	p, set, err := a.load()
+	if err != nil {
+		fmt.Fprintf(stderr, "%s: %v\n", name, err)
+		return 1
+	}
+	if *all {
+		for _, platformName := range sortedNames(set) {
+			body, err := adapterFile(platformName, set[platformName])
+			if err == nil {
+				err = os.WriteFile(filepath.Join(*dir, platformName+".yaml"), body, 0o644)
+			}
+			if err != nil {
+				fmt.Fprintf(stderr, "%s: %v\n", name, err)
+				return 1
+			}
+		}
+		return 0
+	}
+	platformName := fs.Arg(0)
+	d, ok := set[platformName]
+	if !ok {
+		fmt.Fprintf(stderr, "%s: %q has no adapter here; the platforms are %s\n", name, platformName,
+			strings.Join(sortedNames(set), ", "))
+		return 1
+	}
+	body, err := adapterFile(platformName, d)
+	if err != nil {
+		fmt.Fprintf(stderr, "%s: %v\n", name, err)
+		return 1
+	}
+	if !export {
+		source, setName := "built-in", a.set
+		if p != nil {
+			source, setName = p.PlatformSource(platformName), p.PlatformSet()
+		}
+		fmt.Fprintf(stdout, "# %s: %s, platform set %s\n", platformName, source, setName)
+	}
+	stdout.Write(body)
+	if !export {
+		fmt.Fprintln(stdout, "# built-in redaction, applied before any record is written and not part of a set (spec §5.8):")
+		for _, r := range platform.Redactions(platformName) {
+			fmt.Fprintf(stdout, "#   %s\n", redactionLine(r))
+		}
+	}
+	return 0
+}
+
+// adapterFile is d as an adapter file: `platforms: {name: ...}`.
+func adapterFile(name string, d platform.Dialect) ([]byte, error) {
+	var buf bytes.Buffer
+	enc := yaml.NewEncoder(&buf)
+	enc.SetIndent(2)
+	if err := enc.Encode(map[string]map[string]platform.Spec{"platforms": {name: platform.SpecOf(d)}}); err != nil {
+		return nil, err
+	}
+	if err := enc.Close(); err != nil {
+		return nil, err
+	}
+	return buf.Bytes(), nil
+}
+
+// redactionLine is a pattern as redact.yaml writes it.
+func redactionLine(r platform.Redaction) string {
+	words := make([]string, len(r.Match))
+	for i, w := range r.Match {
+		words[i] = "'" + w + "'"
+	}
+	if r.From != nil {
+		return fmt.Sprintf("{match: [%s], from: %d}", strings.Join(words, ", "), *r.From)
+	}
+	return fmt.Sprintf("{match: [%s], after: %s}", strings.Join(words, ", "), r.After)
+}
+
+func sortedNames(set map[string]platform.Dialect) []string {
+	out := make([]string, 0, len(set))
+	for name := range set {
+		out = append(out, name)
+	}
+	slices.Sort(out)
+	return out
+}
````

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index d8c30b5..b06afa1 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -18,24 +18,25 @@ import (
 // Spec is one platform block as a file writes it (spec §8): a built-in adapter
 // under platforms/<set>/. A nil field is one the block does not set, and Over
 // lays the set fields over a base, so a block that sets one key inherits every
-// other.
+// other. A nil field is also one `port49 platform export` leaves out.
 type Spec struct {
-	Supports             *[]string            `yaml:"supports"`
-	Privilege            *map[string][]string `yaml:"privilege"`
-	CeilingLevels        *map[string]uint8    `yaml:"ceiling_levels"`
-	EntityClasses        *map[string][]string `yaml:"entity_classes"`
-	ExpandsAbbreviations *bool                `yaml:"expands_abbreviations"`
-	SplitsInterfaceNames *bool                `yaml:"splits_interface_names"`
-	PipeToken            *string              `yaml:"pipe_token"`
-	PipeAuthorized       *bool                `yaml:"pipe_authorized"`
-	StripCR              *bool                `yaml:"strip_cr"`
-	ShowsServerMsg       *bool                `yaml:"shows_server_msg"`
-	PrivilegeAttributes  *[]string            `yaml:"privilege_attributes"`
-	InertAttributes      *[]string            `yaml:"inert_attributes"`
-	AcceptedAttributes   *[]string            `yaml:"accepted_attributes"`
-	DeviceConfig         *[]string            `yaml:"device_config"`
-	EnableUsername       *string              `yaml:"enable_username"`
-	Redact               *[]Redaction         `yaml:"redact"`
+	Supports             *[]string            `yaml:"supports,omitempty"`
+	Privilege            *map[string][]string `yaml:"privilege,omitempty"`
+	CeilingLevels        *map[string]uint8    `yaml:"ceiling_levels,omitempty"`
+	EntityClasses        *map[string][]string `yaml:"entity_classes,omitempty"`
+	ExpandsAbbreviations *bool                `yaml:"expands_abbreviations,omitempty"`
+	SplitsInterfaceNames *bool                `yaml:"splits_interface_names,omitempty"`
+	PipeToken            *string              `yaml:"pipe_token,omitempty"`
+	PipeAuthorized       *bool                `yaml:"pipe_authorized,omitempty"`
+	StripCR              *bool                `yaml:"strip_cr,omitempty"`
+	ShowsServerMsg       *bool                `yaml:"shows_server_msg,omitempty"`
+	PrivilegeAttributes  *[]string            `yaml:"privilege_attributes,omitempty"`
+	InertAttributes      *[]string            `yaml:"inert_attributes,omitempty"`
+	AcceptedAttributes   *[]string            `yaml:"accepted_attributes,omitempty"`
+	DeviceConfig         *[]string            `yaml:"device_config,omitempty"`
+	EnableUsername       *string              `yaml:"enable_username,omitempty"`
+	Redact               *[]Redaction         `yaml:"redact,omitempty"`
+	Verified             *string              `yaml:"verified,omitempty"`
 }
 
 // ParseSpecs reads an adapter file: one YAML document whose one key is
@@ -122,6 +123,9 @@ func (s Spec) Over(base Dialect) Dialect {
 		// Appended, never replaced: a block cannot take a redaction away.
 		d.Redact = append(d.Redact, *s.Redact...)
 	}
+	if s.Verified != nil {
+		d.Verified = *s.Verified
+	}
 	return d
 }
 
@@ -137,6 +141,12 @@ func mergeLists(base, over map[string][]string) map[string][]string {
 	return base
 }
 
+// verifications are what `verified` may say (spec §8, "Knowing what is
+// shipped"): unset, confirmed against a lab image on every change
+// (`containerlab`, with a tests/lab/results/ note), or contributed and run by
+// nobody here (`community`).
+var verifications = []string{"", "containerlab", "community"}
+
 // capabilities is spec §9's vocabulary for `supports`.
 var capabilities = []string{"session", "commands", "config_commands"}
 
@@ -250,6 +260,9 @@ func Validate(name string, d Dialect) error {
 			return fmt.Errorf("%s[%d]: %w", field("redact"), i, err)
 		}
 	}
+	if !slices.Contains(verifications, d.Verified) {
+		return fmt.Errorf("%s is %q; it is containerlab, community, or unset", field("verified"), d.Verified)
+	}
 	switch d.EnableUsername {
 	case EnablePrincipal:
 	case EnableEnab:
@@ -308,6 +321,9 @@ func SpecOf(d Dialect) Spec {
 	if d.Redact != nil {
 		s.Redact = &d.Redact
 	}
+	if d.Verified != "" {
+		s.Verified = &d.Verified
+	}
 	return s
 }
 
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index b64e031..9679b6e 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -93,6 +93,12 @@ type Dialect struct {
 	// to the platform's built-in ones (Redactions). A block adds; it never
 	// removes a built-in pattern (spec §5.8).
 	Redact []Redaction
+	// Verified is how the adapter's spellings were confirmed (spec §8):
+	// "containerlab" where a tests/lab/results/ note shows every attribute it
+	// sends applied by a lab image, "community" for a contributed adapter
+	// nobody here has run, and empty where neither is true. Only a built-in
+	// adapter may say it.
+	Verified string
 }
 
 // builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
````

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index 5de23bf..626ca92 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -280,6 +280,9 @@ func (p *Policy) buildPlatforms(f file) error {
 			// of either name would be read as the other.
 			return fmt.Errorf("%s: %s is reserved: attributes.all names every platform and the built-in redaction "+
 				"table's default list every unlisted one; name the platform as the inventory does", at, name)
+		case b.Verified != nil:
+			return fmt.Errorf("%s: verified is port49's own claim about its lab (spec §8); an adapter written "+
+				"here is unverified until it is contributed and measured, so remove the key", at)
 		case b.Replace && b.BasedOn != "":
 			return fmt.Errorf("%s: replace starts from nothing and based_on from another platform; use one", at)
 		case b.BasedOn != "" && shipped:
@@ -318,6 +321,29 @@ var platformNameShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
 // PlatformSet is the platform set the policy renders with.
 func (p *Policy) PlatformSet() string { return p.set }
 
+// PlatformNames is every platform the policy has an adapter for, sorted: its
+// set's and its `platforms:` blocks'.
+func (p *Policy) PlatformNames() []string { return sortedKeys(p.adapters) }
+
+// PlatformSource says where a platform's adapter comes from, as `port49
+// platform list` prints it: `built-in`, `overridden` (a block over a built-in,
+// or one that replaced it), `variant` (based_on), or `local` (a platform the
+// set does not ship).
+func (p *Policy) PlatformSource(name string) string {
+	b, written := p.overrides[name]
+	builtin, _ := platform.Set(p.set)
+	_, shipped := builtin[name]
+	switch {
+	case !written:
+		return "built-in"
+	case b.BasedOn != "":
+		return "variant"
+	case shipped:
+		return "overridden"
+	}
+	return "local"
+}
+
 func (p *Policy) buildLevels(f file) error {
 	p.parents = map[string]string{}
 	if len(f.PrivilegeLevels) == 0 {
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && make build && ./bin/port49 platform show cisco_iosxe`
Expected: every package `ok`; the adapter, headed `# cisco_iosxe: built-in, platform set 1.0.0`,
with its `device_config` and the redaction lines.

- [ ] **Step 5: Commit**

```bash
git add internal cmd
git commit -m "feat: port49 platform list, show and export

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: `port49 platform upgrade`

**Files:**
- Modify: `cmd/port49/platform.go` (`platformUpgrade`), `cmd/port49/main.go`
- Modify: `internal/policy/edit.go` (`SetPlatformSet`), `internal/policy/load.go` (`Env.Sets`,
  `builtinSet`), `internal/policy/lint.go` (`ShadowedBuiltIns`, `Reach`)
- Test: `internal/policy/platforms_test.go`, `cmd/port49/platform_test.go`

**Interfaces:**
- Produces: `func SetPlatformSet(raw []byte, version string) ([]byte, error)`;
  `policy.Env.Sets map[string]map[string]platform.Dialect` (tests: this build ships one set);
  `func (p *Policy) ShadowedBuiltIns(from string) []string`;
  `func (p *Policy) Reach(platformName string, now time.Time) (devices, subjects int)`.
  `port49 platform upgrade --policy F --inventory I --to V [--write]`: the report on stdout, the pin
  rewritten with `--write` and nothing else in the file; a set the policy does not load on writes
  nothing and exits 1.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/platform_test.go -->
````diff
diff --git a/cmd/port49/platform_test.go b/cmd/port49/platform_test.go
index 5276533..f485e2f 100644
--- a/cmd/port49/platform_test.go
+++ b/cmd/port49/platform_test.go
@@ -119,3 +119,26 @@ func listRow(out, name string) string {
 	}
 	return ""
 }
+
+// `port49 platform upgrade` reports what moving the pin changes and, with
+// --write, rewrites the pin alone. A set this binary does not ship is not a
+// pin the policy can load on, and nothing is written.
+func TestPlatformUpgradeMovesThePin(t *testing.T) {
+	pol, inv := policyFixture(t)
+	raw := readFile(t, pol)
+	var out, errb bytes.Buffer
+	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv, "--to", "1.0.0", "--write"},
+		&out, &errb); code != 0 || out.String() != "platform_set 1.0.0 -> 1.0.0\n  no adapter the inventory uses changes\n" {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	if got := readFile(t, pol); string(got) != "platform_set: 1.0.0\n"+string(raw) {
+		t.Fatalf("%s", got)
+	}
+	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv, "--to", "9.9.9", "--write"},
+		&out, &errb); code != 1 || !strings.Contains(errb.String(), "does not load on platform set 9.9.9, so nothing was written") {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv}, &out, &errb); code != 2 {
+		t.Fatalf("no --to: code %d", code)
+	}
+}
````

<!-- patch: internal/policy/platforms_test.go -->
````diff
diff --git a/internal/policy/platforms_test.go b/internal/policy/platforms_test.go
index 4db69a9..8a72a6f 100644
--- a/internal/policy/platforms_test.go
+++ b/internal/policy/platforms_test.go
@@ -167,3 +167,61 @@ func TestARedundantOverrideIsReported(t *testing.T) {
 		t.Fatalf("%q", got)
 	}
 }
+
+// Moving the pin is a policy change like any other (spec §8): the diff finds
+// every adapter key the move changes on a platform the inventory has, a block
+// that keeps its own value hides the built-in's change and is named for it,
+// and Reach says what a change touches. This build ships one set, so the
+// environment stands up a second.
+func TestAPinMoveIsReportedKeyByKey(t *testing.T) {
+	first, _ := platform.Set("1.0.0")
+	second, _ := platform.Set("1.0.0")
+	eos, xe := second["arista_eos"], second["cisco_iosxe"]
+	eos.EntityClasses = map[string][]string{"management": {"^Management1$"}, "loopback": eos.EntityClasses["loopback"],
+		"physical": eos.EntityClasses["physical"]}
+	xe.DeviceConfig = append(xe.DeviceConfig, "privilege exec level 7 show logging")
+	second["arista_eos"], second["cisco_iosxe"] = eos, xe
+	e := env()
+	e.Sets = map[string]map[string]platform.Dialect{"1.0.0": first, "1.1.0": second}
+	body := "platforms:\n  arista_eos:\n    entity_classes: {management: ['^Management[12]$']}\n" + scopeOK + roleOK +
+		subjOK + grantOK
+	before, err := Parse([]byte("platform_set: 1.0.0\n"+body), e)
+	if err != nil {
+		t.Fatal(err)
+	}
+	moved, err := SetPlatformSet([]byte("platform_set: 1.0.0\n"+body), "1.1.0")
+	if err != nil || !strings.HasPrefix(string(moved), "platform_set: 1.1.0\nplatforms:\n") {
+		t.Fatalf("%v\n%s", err, moved)
+	}
+	after, err := Parse(moved, e)
+	if err != nil {
+		t.Fatal(err)
+	}
+	d := Compare(before, after, noon)
+	if len(d.Adapters) != 1 || d.Adapters[0].Platform != "cisco_iosxe" || d.Adapters[0].Field != "device_config" ||
+		d.Adapters[0].Gated {
+		t.Fatalf("the block hides arista_eos's management change; iosxe's device_config is reported: %+v", d.Adapters)
+	}
+	if got := after.ShadowedBuiltIns("1.0.0"); !reflect.DeepEqual(got, []string{"platforms.arista_eos.entity_classes"}) {
+		t.Fatalf("shadowed: %q", got)
+	}
+	if devices, subjects := before.Reach("arista_eos", noon); devices != 2 || subjects != 1 {
+		t.Fatalf("reach: %d devices, %d subjects", devices, subjects)
+	}
+}
+
+// SetPlatformSet rewrites the pin and nothing else, or adds one where the
+// file pins none.
+func TestSetPlatformSetTouchesOnlyThePin(t *testing.T) {
+	raw := "# the policy\nscopes: []\nplatform_set: 1.0.0   # pinned 2026-09-24\nroles: []\n"
+	got, err := SetPlatformSet([]byte(raw), "1.1.0")
+	if err != nil || string(got) != "# the policy\nscopes: []\nplatform_set: 1.1.0\nroles: []\n" {
+		t.Fatalf("%v %q", err, got)
+	}
+	if got, _ := SetPlatformSet([]byte("roles: []\n"), "1.0.0"); string(got) != "platform_set: 1.0.0\nroles: []\n" {
+		t.Fatalf("%q", got)
+	}
+	if _, err := SetPlatformSet([]byte("platform_set:\n  - 1.0.0\n"), "1.1.0"); err == nil {
+		t.Fatal("a pin that is not one line is refused")
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/`
Expected: FAIL — `e.Sets undefined`, `undefined: SetPlatformSet`, `ShadowedBuiltIns undefined`
(build failed), and `TestPlatformUpgradeMovesThePin`.

- [ ] **Step 3: Write the upgrade**

<!-- patch: cmd/port49/main.go -->
````diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index 815da69..fc91e4c 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -42,6 +42,7 @@ const usage = `usage:
   port49 platform list [--set VERSION | --policy FILE --inventory FILE]
   port49 platform show [--set VERSION | --policy FILE --inventory FILE] PLATFORM
   port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir DIR)
+  port49 platform upgrade --policy FILE --inventory FILE --to VERSION [--write]
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
````

<!-- patch: cmd/port49/platform.go -->
````diff
diff --git a/cmd/port49/platform.go b/cmd/port49/platform.go
index f1b0a4e..c2429ad 100644
--- a/cmd/port49/platform.go
+++ b/cmd/port49/platform.go
@@ -10,9 +10,11 @@ import (
 	"slices"
 	"strings"
 	"text/tabwriter"
+	"time"
 
 	"gopkg.in/yaml.v3"
 
+	"github.com/blanketfish/port49/internal/admission"
 	"github.com/blanketfish/port49/internal/platform"
 	"github.com/blanketfish/port49/internal/policy"
 )
@@ -32,6 +34,8 @@ func platformCmd(args []string, stdout, stderr io.Writer) int {
 		return platformShow(args[1:], stdout, stderr, false)
 	case "export":
 		return platformShow(args[1:], stdout, stderr, true)
+	case "upgrade":
+		return platformUpgrade(args[1:], stdout, stderr)
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
@@ -182,6 +186,82 @@ func platformShow(args []string, stdout, stderr io.Writer, export bool) int {
 	return 0
 }
 
+// platformUpgrade moves a policy's platform_set pin and reports exactly what
+// the move changes (spec §8, §12): every adapter key that differs between the
+// two sets on a platform the inventory has, with the devices and subjects it
+// reaches, and every key a `platforms:` block keeps its own value for while
+// the built-in under it changes. The report is the output; --write also
+// rewrites the pin in the file, and nothing else in it. `port49 policy diff`
+// on the two files is the gate: this says what it will find.
+func platformUpgrade(args []string, stdout, stderr io.Writer) int {
+	fs := flag.NewFlagSet("port49 platform upgrade", flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	var files policyFiles
+	files.register(fs)
+	to := fs.String("to", "", "the platform set to pin")
+	write := fs.Bool("write", false, "rewrite the pin in the policy file")
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	if files.missing() || *to == "" || fs.NArg() != 0 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	inv, err := admission.LoadFile(files.inventory)
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
+		return 1
+	}
+	raw, err := os.ReadFile(files.policy)
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
+		return 1
+	}
+	before, err := policy.Parse(raw, offlineEnv(inv.Devices))
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
+		return 1
+	}
+	moved, err := policy.SetPlatformSet(raw, *to)
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 platform upgrade:", err)
+		return 1
+	}
+	after, err := policy.Parse(moved, offlineEnv(inv.Devices))
+	if err != nil {
+		fmt.Fprintf(stderr, "port49 platform upgrade: the policy does not load on platform set %s, so nothing was "+
+			"written: %v\n", *to, err)
+		return 1
+	}
+	now := time.Now()
+	fmt.Fprintf(stdout, "platform_set %s -> %s\n", before.PlatformSet(), after.PlatformSet())
+	d := policy.Compare(before, after, now)
+	for _, a := range d.Adapters {
+		gate := "reported"
+		if a.Gated {
+			gate = "gated: the change that moves the pin acknowledges it, {platform: " + a.Platform + ", field: " +
+				a.Field + ", reason: ...}"
+		}
+		devices, subjects := before.Reach(a.Platform, now)
+		fmt.Fprintf(stdout, "  platforms.%s.%s\n    %s -> %s (%s)\n    affects %d devices, %d subjects\n", a.Platform,
+			a.Field, a.Old, a.New, gate, devices, subjects)
+	}
+	for _, key := range after.ShadowedBuiltIns(before.PlatformSet()) {
+		fmt.Fprintf(stdout, "  shadowed: %s: set %s changes the built-in value and the policy's block keeps its "+
+			"own; compare the two\n", key, after.PlatformSet())
+	}
+	if len(d.Adapters) == 0 {
+		fmt.Fprintln(stdout, "  no adapter the inventory uses changes")
+	}
+	if *write {
+		if err := replaceFile(files.policy, moved); err != nil {
+			fmt.Fprintln(stderr, "port49 platform upgrade:", err)
+			return 1
+		}
+	}
+	return 0
+}
+
 // adapterFile is d as an adapter file: `platforms: {name: ...}`.
 func adapterFile(name string, d platform.Dialect) ([]byte, error) {
 	var buf bytes.Buffer
````

<!-- patch: internal/policy/edit.go -->
````diff
diff --git a/internal/policy/edit.go b/internal/policy/edit.go
index 8c42672..efa9adb 100644
--- a/internal/policy/edit.go
+++ b/internal/policy/edit.go
@@ -238,3 +238,32 @@ func field(m *yaml.Node, key string) string {
 	}
 	return ""
 }
+
+// SetPlatformSet is the policy file pinned to version, for `port49 platform
+// upgrade` (spec §8): the `platform_set:` line rewritten where the file has
+// one, or a line added at the top where it pins none. Every other byte is the
+// operator's, so the pull request shows only the pin.
+func SetPlatformSet(raw []byte, version string) ([]byte, error) {
+	var doc yaml.Node
+	if err := yaml.Unmarshal(raw, &doc); err != nil {
+		return nil, err
+	}
+	line := "platform_set: " + version + "\n"
+	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
+		return nil, errors.New("the policy file is not a YAML mapping")
+	}
+	top := doc.Content[0]
+	for i := 0; i+1 < len(top.Content); i += 2 {
+		key, value := top.Content[i], top.Content[i+1]
+		if key.Value != "platform_set" {
+			continue
+		}
+		if value.Kind != yaml.ScalarNode || value.Line != key.Line {
+			return nil, errors.New("platform_set is not a one-line value; write it as `platform_set: 1.0.0`")
+		}
+		lines := bytes.SplitAfter(raw, []byte("\n"))
+		lines[key.Line-1] = []byte(line)
+		return bytes.Join(lines, nil), nil
+	}
+	return append([]byte(line), raw...), nil
+}
````

<!-- patch: internal/policy/lint.go -->
````diff
diff --git a/internal/policy/lint.go b/internal/policy/lint.go
index 9140a7e..334f0c1 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -282,7 +282,7 @@ func (p *Policy) redundantOverrides() []Finding {
 	var out []Finding
 	for _, name := range sortedKeys(p.overrides) {
 		b := p.overrides[name]
-		builtin, ok := platform.Set(p.set)
+		builtin, ok := p.builtinSet(p.set)
 		base, shipped := builtin[name]
 		if !ok || !shipped || b.Replace || b.BasedOn != "" {
 			continue
@@ -304,3 +304,52 @@ func (p *Policy) redundantOverrides() []Finding {
 	}
 	return out
 }
+
+// ShadowedBuiltIns names every key a `platforms:` block sets over a built-in
+// whose built-in value differs between set from and the policy's own set:
+// what `port49 platform upgrade` must say, because the upgrade changes the
+// built-in and the block goes on hiding it (spec §8, override drift).
+func (p *Policy) ShadowedBuiltIns(from string) []string {
+	was, ok1 := p.builtinSet(from)
+	is, ok2 := p.builtinSet(p.set)
+	if !ok1 || !ok2 {
+		return nil
+	}
+	var out []string
+	keys := platform.SpecKeys()
+	for _, name := range sortedKeys(p.overrides) {
+		b := p.overrides[name]
+		a, inWas := was[name]
+		z, inIs := is[name]
+		if !inWas || !inIs || b.Replace || b.BasedOn != "" {
+			continue
+		}
+		set := reflect.ValueOf(b.Spec)
+		old, now := reflect.ValueOf(platform.SpecOf(a)), reflect.ValueOf(platform.SpecOf(z))
+		for i, key := range keys {
+			if !set.Field(i).IsNil() && !reflect.DeepEqual(old.Field(i).Interface(), now.Field(i).Interface()) {
+				out = append(out, "platforms."+name+"."+key)
+			}
+		}
+	}
+	return out
+}
+
+// Reach is how many devices of a platform the inventory has, and how many
+// subjects hold a grant on one of them at now: what a change to that
+// platform's adapter affects.
+func (p *Policy) Reach(platformName string, now time.Time) (devices, subjects int) {
+	holds := map[string]bool{}
+	for _, d := range p.env.Devices {
+		if d.Platform != platformName {
+			continue
+		}
+		devices++
+		for name, sub := range p.subs {
+			if len(p.compose(sub, d, now).grants) > 0 {
+				holds[name] = true
+			}
+		}
+	}
+	return devices, len(holds)
+}
````

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index 626ca92..e8a3a0b 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -40,6 +40,9 @@ type Env struct {
 	// Dialects replaces platforms of the pinned set when non-nil: tests use
 	// it to stand a platform up with other behaviour.
 	Dialects map[string]platform.Dialect
+	// Sets replaces the built-in platform sets when non-nil: tests use it to
+	// stand up a second set, since this build ships one.
+	Sets map[string]map[string]platform.Dialect
 	// Now is the present the joint checks start from: a grant already expired
 	// by then is not checked. Zero is the clock at load; tests fix it.
 	Now time.Time
@@ -257,12 +260,12 @@ func (p *Policy) buildPlatforms(f file) error {
 	if p.set == "" {
 		p.set = platform.UnpinnedSet
 	}
-	set, ok := platform.Set(p.set)
+	set, ok := p.builtinSet(p.set)
 	if !ok {
 		return fmt.Errorf("platform_set: %s is not a set this binary ships; it ships %s. Pin one of those, or run "+
 			"a binary that ships %s (spec §8)", p.set, strings.Join(platform.Sets(), ", "), p.set)
 	}
-	builtin, _ := platform.Set(p.set)
+	builtin, _ := p.builtinSet(p.set)
 	generic, _ := platform.DialectFor("")
 	p.overrides = f.Platforms
 	for _, name := range sortedKeys(f.Platforms) {
@@ -315,6 +318,23 @@ func (p *Policy) buildPlatforms(f file) error {
 	return nil
 }
 
+// builtinSet is a built-in platform set by version, copied: the environment's
+// where it gives sets, the binary's otherwise.
+func (p *Policy) builtinSet(version string) (map[string]platform.Dialect, bool) {
+	if p.env.Sets == nil {
+		return platform.Set(version)
+	}
+	set, ok := p.env.Sets[version]
+	if !ok {
+		return nil, false
+	}
+	out := make(map[string]platform.Dialect, len(set))
+	for name, d := range set {
+		out[name] = d
+	}
+	return out, true
+}
+
 // platformNameShape is how an inventory writes a platform.
 var platformNameShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
 
@@ -331,7 +351,7 @@ func (p *Policy) PlatformNames() []string { return sortedKeys(p.adapters) }
 // set does not ship).
 func (p *Policy) PlatformSource(name string) string {
 	b, written := p.overrides[name]
-	builtin, _ := platform.Set(p.set)
+	builtin, _ := p.builtinSet(p.set)
 	_, shipped := builtin[name]
 	switch {
 	case !written:
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal cmd
git commit -m "feat: port49 platform upgrade moves the pin and says what it changes

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: The dead-rule and fallback-exposure reports

**Files:**
- Create: `internal/policy/intersect.go`
- Modify: `internal/platform/dialect.go`, `internal/platform/adapter.go` (`Unreachable`,
  `Fallback`), `platforms/1.0.0/{arista_eos,cisco_nxos,cisco_iosxe}.yaml`
- Modify: `internal/policy/lint.go` (`Lint` appends `intersections`)
- Test: `internal/policy/intersect_test.go`, `internal/policy/spec11_test.go`,
  `internal/platform/adapter_test.go`

**Interfaces:**
- Produces: `Dialect.Unreachable map[string][]string`, `Dialect.Fallback map[string]string`, keys
  `unreachable`, `fallback`; `FindingDeadRule = "dead_rule"`,
  `FindingFallbackExposure = "fallback_exposure"`. Values are only what
  `tests/lab/results/ceiling-*.md` and L16's LOCAL phase measured (Decided 11). IOS-XE's admin
  fallback is unmeasured for a TACACS+ session and says so in the file: reporting an exposure that
  may not exist is the direction that fails closed.

§11's `svc_oxidized` is now reported: it is spec §12's own example.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index aa1d950..8aab240 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -28,6 +28,10 @@ var shipped = map[string]Dialect{
 		InertAttributes:     []string{"home-directory"},
 		EnableUsername:      EnablePrincipal,
 		DeviceConfig:        []string{"aaa authorization commands all default group port49 local"},
+		// ceiling-arista_eos.md; L16-arista_eos.md, command authorization LOCAL.
+		Unreachable: map[string][]string{"readonly": {"clear counters **", "clear ip bgp **", "configure terminal **",
+			"show users detail **"}},
+		Fallback: map[string]string{"admin": "network-admin: every command, configuration included"},
 	},
 	"cisco_nxos": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true,
@@ -42,6 +46,7 @@ var shipped = map[string]Dialect{
 		EnableUsername:      EnablePrincipal,
 		DeviceConfig: []string{"aaa authorization commands default group port49 local",
 			"aaa authorization config-commands default group port49 local"},
+		Fallback: map[string]string{"admin": "network-admin: every command, configuration included"},
 	},
 	"cisco_iosxe": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true, SplitsInterfaceNames: true,
@@ -56,6 +61,9 @@ var shipped = map[string]Dialect{
 			"aaa authorization commands 7 default group port49 local",
 			"aaa authorization commands 15 default group port49 local",
 			"aaa accounting commands 7 default start-stop group port49", "privilege exec level 7 clear counters"},
+		Unreachable: map[string][]string{"readonly": {"clear counters **", "clear ip bgp **", "configure terminal **"},
+			"operator": {"clear ip bgp **", "configure terminal **"}},
+		Fallback: map[string]string{"admin": "level 15: every command, configuration included"},
 	},
 	"juniper_junos": {
 		PipeToken: "|", StripCR: true,
@@ -231,8 +239,10 @@ func TestValidateNamesTheField(t *testing.T) {
 		"not in accepted_attributes": with(ok, func(d *Dialect) {
 			d.Levels, d.AcceptedAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"priv-lvl"}
 		}),
-		"device_config[0]":    with(ok, func(d *Dialect) { d.DeviceConfig = []string{"line one\nline two"} }),
-		"verified is \"lab\"": with(ok, func(d *Dialect) { d.Verified = "lab" }),
+		"device_config[0]":        with(ok, func(d *Dialect) { d.DeviceConfig = []string{"line one\nline two"} }),
+		"verified is \"lab\"":     with(ok, func(d *Dialect) { d.Verified = "lab" }),
+		"unreachable.readonly":    with(ok, func(d *Dialect) { d.Unreachable = map[string][]string{"readonly": {"/(/"}} }),
+		"fallback.admin is empty": with(ok, func(d *Dialect) { d.Fallback = map[string]string{"admin": " "} }),
 	} {
 		err := Validate("x", d)
 		if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "platforms.x.") {
````

<!-- patch: internal/policy/intersect_test.go -->
````diff
diff --git a/internal/policy/intersect_test.go b/internal/policy/intersect_test.go
new file mode 100644
index 0000000..7bed683
--- /dev/null
+++ b/internal/policy/intersect_test.go
@@ -0,0 +1,80 @@
+package policy
+
+import (
+	"strings"
+	"testing"
+)
+
+// A permit the device refuses in its own parser at the session's level is
+// dead: the device never asks port49 about it (spec §12, "Intersection
+// checks"). On EOS and IOS-XE at readonly `clear counters` is refused; on
+// IOS-XE at operator it is the one command level 7 runs, and `configure
+// terminal` is still refused (tests/lab/results/ceiling-*.md). NX-OS refuses
+// nothing, so nothing is dead there.
+func TestADeadRuleIsReported(t *testing.T) {
+	p := mustParse(t, `
+scopes: [{name: all_devices, match: {}}]
+roles:
+  - {name: noc, privilege: readonly, permit: [show **, clear counters]}
+  - {name: ops, privilege: operator, permit: [show **, clear counters, configure terminal]}
+subjects:
+  - {name: a, identity: "user:a@example.com", username: a, token_ttl: 60s}
+  - {name: b, identity: "user:b@example.com", username: b, token_ttl: 60s}
+grants:
+  - {subject: a, scope: all_devices, roles: [noc]}
+  - {subject: b, scope: all_devices, roles: [ops]}
+`)
+	got := findings(p, FindingDeadRule)
+	want := []string{
+		`role "noc": permit "clear counters" cannot be reached at readonly (priv-lvl=1) on cisco_iosxe`,
+		`role "noc": permit "clear counters" cannot be reached at readonly (priv-lvl=1, roles=network-operator) on arista_eos`,
+		`role "ops": permit "configure terminal" cannot be reached at operator (priv-lvl=7) on cisco_iosxe`,
+	}
+	if len(got) != len(want) {
+		t.Fatalf("%d findings, want %d: %q", len(got), len(want), got)
+	}
+	for i := range want {
+		if !strings.HasPrefix(got[i], want[i]) {
+			t.Errorf("finding %d: %q, want %q…", i, got[i], want[i])
+		}
+	}
+	if !strings.Contains(got[2], "tests/lab/results/ceiling-cisco_iosxe.md") {
+		t.Errorf("the finding cites the note: %q", got[2])
+	}
+}
+
+// A subject port49 confines at a level whose device role, on its own, is
+// every command is exposed when the device falls back to local (spec §6,
+// §12): it is named with what port49 permits it and what the fallback gives.
+// A subject port49 permits everything is not, and neither is a level the
+// fallback does not widen.
+func TestAFallbackExposureIsReported(t *testing.T) {
+	p := mustParse(t, `
+scopes: [{name: all_devices, match: {}}]
+roles:
+  - {name: backup, privilege: admin, permit: [show **]}
+  - {name: root, privilege: admin, permit: ["**"]}
+  - {name: noc, privilege: readonly, permit: [show **]}
+subjects:
+  - {name: svc_oxidized, identity: "app:oxidized", username: oxidized, token_ttl: 60s}
+  - {name: admins, identity: "user:a@example.com", username: a, token_ttl: 60s}
+  - {name: noc, identity: "user:n@example.com", username: n, token_ttl: 60s}
+grants:
+  - {subject: svc_oxidized, scope: all_devices, roles: [backup]}
+  - {subject: admins, scope: all_devices, roles: [root]}
+  - {subject: noc, scope: all_devices, roles: [noc]}
+`)
+	got := findings(p, FindingFallbackExposure)
+	if len(got) != 3 {
+		t.Fatalf("one per platform with a fallback, for svc_oxidized alone: %q", got)
+	}
+	for i, platformName := range []string{"cisco_iosxe", "arista_eos", "cisco_nxos"} {
+		if !strings.HasPrefix(got[i], `subject "svc_oxidized" at admin (`) || !strings.Contains(got[i], ") on "+platformName+
+			": port49's rules confine it to show **, and if port49 cannot answer") {
+			t.Errorf("%q", got[i])
+		}
+	}
+	if !strings.Contains(got[1], "it gets network-admin: every command, configuration included") {
+		t.Errorf("%q", got[1])
+	}
+}
````

<!-- patch: internal/policy/spec11_test.go -->
````diff
diff --git a/internal/policy/spec11_test.go b/internal/policy/spec11_test.go
index 5183a10..8ea6902 100644
--- a/internal/policy/spec11_test.go
+++ b/internal/policy/spec11_test.go
@@ -172,20 +172,31 @@ func checkClaim(t *testing.T, p *Policy, subject string, d admission.Device, lin
 	}
 }
 
-// What CI reports about §11: three group subjects nobody can mint for until
-// plan 7, and the SRX whose version the comparator could not order, included
-// in the mitigation and named (spec §5.5).
+// What CI reports about §11: svc_oxidized's fallback exposure, which is spec
+// §12's own example — port49 confines it to show commands, and elevated_session
+// lands it at admin, network-admin on the device when port49 cannot answer —
+// three group subjects nobody can mint for until plan 7, and the SRX whose
+// version the comparator could not order, included in the mitigation and
+// named (spec §5.5).
 func TestTheCompletePolicyExampleReportsWhatItShould(t *testing.T) {
 	p := spec11(t, spec11Raw(t))
 	var kinds []string
-	var incomparable string
+	var incomparable, exposure string
 	for _, f := range p.Lint(noon) {
 		kinds = append(kinds, f.Kind)
-		if f.Kind == FindingIncomparableVersion {
+		switch f.Kind {
+		case FindingIncomparableVersion:
 			incomparable = f.Message
+		case FindingFallbackExposure:
+			exposure = f.Message
 		}
 	}
-	want := []string{FindingGroupSubject, FindingGroupSubject, FindingGroupSubject, FindingIncomparableVersion}
+	if !strings.HasPrefix(exposure, `subject "svc_oxidized" at admin (priv-lvl=15, roles=network-admin) on arista_eos: `+
+		`port49's rules confine it to show **, terminal length *, and if port49 cannot answer`) {
+		t.Fatalf("the exposure: %s", exposure)
+	}
+	want := []string{FindingFallbackExposure, FindingGroupSubject, FindingGroupSubject, FindingGroupSubject,
+		FindingIncomparableVersion}
 	if !reflect.DeepEqual(kinds, want) {
 		t.Fatalf("findings %q, want %q", kinds, want)
 	}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/`
Expected: FAIL — `d.Unreachable undefined`, `undefined: FindingDeadRule` (build failed).

- [ ] **Step 3: Write the reports**

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index b06afa1..cc97f02 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -37,6 +37,8 @@ type Spec struct {
 	EnableUsername       *string              `yaml:"enable_username,omitempty"`
 	Redact               *[]Redaction         `yaml:"redact,omitempty"`
 	Verified             *string              `yaml:"verified,omitempty"`
+	Unreachable          *map[string][]string `yaml:"unreachable,omitempty"`
+	Fallback             *map[string]string   `yaml:"fallback,omitempty"`
 }
 
 // ParseSpecs reads an adapter file: one YAML document whose one key is
@@ -126,6 +128,17 @@ func (s Spec) Over(base Dialect) Dialect {
 	if s.Verified != nil {
 		d.Verified = *s.Verified
 	}
+	if s.Unreachable != nil {
+		d.Unreachable = mergeLists(d.Unreachable, *s.Unreachable)
+	}
+	if s.Fallback != nil {
+		if d.Fallback == nil {
+			d.Fallback = map[string]string{}
+		}
+		for k, v := range *s.Fallback {
+			d.Fallback[k] = v
+		}
+	}
 	return d
 }
 
@@ -260,6 +273,19 @@ func Validate(name string, d Dialect) error {
 			return fmt.Errorf("%s[%d]: %w", field("redact"), i, err)
 		}
 	}
+	for _, level := range sortedKeys(d.Unreachable) {
+		for _, rule := range d.Unreachable[level] {
+			if _, err := engine.ParseRule(rule); err != nil {
+				return fmt.Errorf("%s: %w", field("unreachable."+level), err)
+			}
+		}
+	}
+	for _, level := range sortedKeys(d.Fallback) {
+		if strings.TrimSpace(d.Fallback[level]) == "" {
+			return fmt.Errorf("%s is empty: say what the device gives a session at %s on its own", field("fallback."+level),
+				level)
+		}
+	}
 	if !slices.Contains(verifications, d.Verified) {
 		return fmt.Errorf("%s is %q; it is containerlab, community, or unset", field("verified"), d.Verified)
 	}
@@ -324,6 +350,12 @@ func SpecOf(d Dialect) Spec {
 	if d.Verified != "" {
 		s.Verified = &d.Verified
 	}
+	if d.Unreachable != nil {
+		s.Unreachable = &d.Unreachable
+	}
+	if d.Fallback != nil {
+		s.Fallback = &d.Fallback
+	}
 	return s
 }
 
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index 9679b6e..36c026d 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -99,6 +99,17 @@ type Dialect struct {
 	// nobody here has run, and empty where neither is true. Only a built-in
 	// adapter may say it.
 	Verified string
+	// Unreachable maps a level to the rules the device refuses at that level
+	// in its own parser, never asking port49 (tests/lab/results/ceiling-*.md):
+	// a permit every command of which is here is dead there (spec §12).
+	// Only measured commands are listed; a level with none lists nothing.
+	Unreachable map[string][]string
+	// Fallback maps a level to what the device gives a session at it on its
+	// own when port49 cannot answer and the command method list falls back to
+	// local, where that is more than a confined role: a subject port49
+	// confines at that level has more access in an outage than the policy
+	// grants (spec §6, §12, "Fallback exposure").
+	Fallback map[string]string
 }
 
 // builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
@@ -168,6 +179,16 @@ func (d Dialect) clone() Dialect {
 	if d.CeilingLevels != nil {
 		d.CeilingLevels = maps.Clone(d.CeilingLevels)
 	}
+	if d.Unreachable != nil {
+		unreachable := make(map[string][]string, len(d.Unreachable))
+		for k, v := range d.Unreachable {
+			unreachable[k] = slices.Clone(v)
+		}
+		d.Unreachable = unreachable
+	}
+	if d.Fallback != nil {
+		d.Fallback = maps.Clone(d.Fallback)
+	}
 	return d
 }
 
````

<!-- patch: internal/policy/intersect.go -->
````diff
diff --git a/internal/policy/intersect.go b/internal/policy/intersect.go
new file mode 100644
index 0000000..e0beafe
--- /dev/null
+++ b/internal/policy/intersect.go
@@ -0,0 +1,149 @@
+package policy
+
+import (
+	"fmt"
+	"slices"
+	"strings"
+	"time"
+
+	"github.com/blanketfish/port49/internal/engine"
+	"github.com/blanketfish/port49/internal/platform"
+)
+
+// The intersection checks of spec §12: the effective permission set is what
+// the device offers intersected with what port49 permits (§6), and CI names
+// where the two disagree. A dead rule is a permit the device never lets a
+// session reach; a fallback exposure is a session the device gives more than
+// port49 does once port49 cannot answer. Both read each subject's
+// composition on each device at now and at every later grant expiry, as the
+// shadowed-deny report does, and each is said once per role or subject,
+// platform and level.
+const (
+	FindingDeadRule         = "dead_rule"
+	FindingFallbackExposure = "fallback_exposure"
+)
+
+func (p *Policy) intersections(now time.Time) []Finding {
+	var out []Finding
+	seen := map[string]bool{}
+	add := func(kind, key, format string, args ...any) {
+		if !seen[kind+"\x00"+key] {
+			seen[kind+"\x00"+key] = true
+			out = append(out, Finding{Kind: kind, Message: fmt.Sprintf(format, args...)})
+		}
+	}
+	instants := p.expiryInstants(now)
+	for _, name := range sortedKeys(p.subs) {
+		for _, d := range p.env.Devices {
+			for _, at := range instants {
+				res, err := p.resolve(p.subs[name], d, at)
+				if err != nil || res.Level == "" {
+					continue
+				}
+				dialect := p.dialect(d.Platform)
+				attrs, level, ok := p.render(dialect, res.Level)
+				if !ok {
+					continue
+				}
+				on := fmt.Sprintf("%s (%s) on %s", level, strings.Join(attrs, ", "), d.Platform)
+				if unreachable := dialect.Unreachable[level]; len(unreachable) > 0 {
+					for _, role := range res.Roles {
+						for _, rule := range p.roles[role].Permit {
+							if p.dead(rule, unreachable, d.Platform, dialect) {
+								add(FindingDeadRule, role+"\x00"+rule+"\x00"+d.Platform+"\x00"+level,
+									"role %q: permit %q cannot be reached at %s: the device refuses every command it "+
+										"matches in its own parser and never asks port49 (unreachable: %s; "+
+										"tests/lab/results/ceiling-%s.md)", role, rule, on, strings.Join(unreachable, ", "),
+									d.Platform)
+							}
+						}
+					}
+				}
+				if fallback := dialect.Fallback[level]; fallback != "" && confined(res.Blob) {
+					add(FindingFallbackExposure, name+"\x00"+d.Platform+"\x00"+level,
+						"subject %q at %s: port49's rules confine it to %s, and if port49 cannot answer and the device "+
+							"falls back to local it gets %s: more than the policy grants (spec §6, §12)", name, on,
+						permitsOf(res.Blob), fallback)
+				}
+			}
+		}
+	}
+	return out
+}
+
+// dead reports whether every command permit matches is one of unreachable's:
+// the probes both rule sets tell apart, each decided as the device would send
+// it on the platform. A permit that matches nothing probed is not called dead.
+func (p *Policy) dead(permit string, unreachable []string, platformName string, dialect platform.Dialect) bool {
+	blob := func(rules []string) *engine.Program {
+		b := engine.Blob{Version: engine.Version, Bundle: "intersection", Platform: platformName,
+			Normalize: p.normalizeFor(platformName), Classes: dialect.EntityClasses}
+		for _, r := range rules {
+			b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Permit, Rule: r, Role: "r"})
+		}
+		prog, err := engine.Compile(b)
+		if err != nil {
+			return nil
+		}
+		return prog
+	}
+	mine, theirs := blob([]string{permit}), blob(unreachable)
+	if mine == nil || theirs == nil {
+		return false
+	}
+	matched := false
+	for _, v := range engine.Probes(mine, theirs) {
+		raw := probeRaw(v)
+		if !mine.Command(raw).Permit {
+			continue
+		}
+		if !theirs.Command(raw).Permit {
+			return false
+		}
+		matched = true
+	}
+	return matched
+}
+
+// confined reports whether a composition's rules deny any command: a session
+// they permit everything to has nothing a fallback could add. Without a `**`
+// permit some command matches no permit; with one, a deny binds on a command
+// the probes find.
+func confined(b engine.Blob) bool {
+	if !slices.ContainsFunc(b.Rules, func(r engine.Rule) bool { return r.Verdict == engine.Permit && r.Rule == "**" }) {
+		return true
+	}
+	prog, err := engine.Compile(b)
+	if err != nil {
+		return true
+	}
+	for _, v := range engine.Probes(prog) {
+		if !prog.Command(probeRaw(v)).Permit {
+			return true
+		}
+	}
+	return false
+}
+
+// permitsOf is a composition's permits as review reads them.
+func permitsOf(b engine.Blob) string {
+	var out []string
+	for _, r := range b.Rules {
+		if r.Verdict == engine.Permit && !slices.Contains(out, r.Rule) {
+			out = append(out, r.Rule)
+		}
+	}
+	if len(out) == 0 {
+		return "nothing"
+	}
+	return strings.Join(out, ", ")
+}
+
+// probeRaw is a probe vector as a device sends it.
+func probeRaw(v []string) []string {
+	raw := []string{"service=shell", "cmd=" + v[0]}
+	for _, a := range v[1:] {
+		raw = append(raw, "cmd-arg="+a)
+	}
+	return raw
+}
````

<!-- patch: internal/policy/lint.go -->
````diff
diff --git a/internal/policy/lint.go b/internal/policy/lint.go
index 334f0c1..a3a11fb 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -136,6 +136,7 @@ func (p *Policy) Lint(now time.Time) []Finding {
 		}
 	}
 	out = append(out, p.redundantOverrides()...)
+	out = append(out, p.intersections(now)...)
 	if len(p.tests) == 0 {
 		add(FindingNoTests, "the policy has no tests: nothing in it acknowledges a shadowed deny, an expansion or "+
 			"a privilege raise, so the gates fail on the first one; add tests (spec §12, \"Policy tests\")")
````

<!-- patch: platforms/1.0.0/arista_eos.yaml -->
````diff
diff --git a/platforms/1.0.0/arista_eos.yaml b/platforms/1.0.0/arista_eos.yaml
index 63b3203..d685103 100644
--- a/platforms/1.0.0/arista_eos.yaml
+++ b/platforms/1.0.0/arista_eos.yaml
@@ -30,6 +30,15 @@ platforms:
     # port49 cannot answer (spec §6, decision 23). The group name is the lab's.
     device_config:
       - aaa authorization commands all default group port49 local
+    # At 1 the parser refuses these without asking port49
+    # (ceiling-arista_eos.md): a permit for nothing else is dead there.
+    unreachable:
+      readonly: [clear counters **, clear ip bgp **, configure terminal **, show users detail **]
+    # Under `aaa authorization commands ... local`, network-admin configures
+    # and network-operator is refused (L16-arista_eos.md, command
+    # authorization LOCAL).
+    fallback:
+      admin: "network-admin: every command, configuration included"
     # Interface names, not device behaviour: spec §8's example.
     entity_classes:
       management: ['^Management[0-9]+$']
````

<!-- patch: platforms/1.0.0/cisco_iosxe.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_iosxe.yaml b/platforms/1.0.0/cisco_iosxe.yaml
index 84533e8..0f6671d 100644
--- a/platforms/1.0.0/cisco_iosxe.yaml
+++ b/platforms/1.0.0/cisco_iosxe.yaml
@@ -37,6 +37,17 @@ platforms:
       - aaa authorization commands 15 default group port49 local
       - aaa accounting commands 7 default start-stop group port49
       - privilege exec level 7 clear counters
+    # The parser refuses these without asking port49 (ceiling-cisco_iosxe.md),
+    # at 7 with the reference line above in place.
+    unreachable:
+      readonly: [clear counters **, clear ip bgp **, configure terminal **]
+      operator: [clear ip bgp **, configure terminal **]
+    # Local authorization runs a command at or below the session's level
+    # (the lab's break-glass account, tests/lab/configs/iosxe-startup.cfg); a
+    # token session at 15 falling back is unmeasured, and reported as the
+    # exposure it would be.
+    fallback:
+      admin: "level 15: every command, configuration included"
     # No entity class is defined: the lab's management interface is
     # GigabitEthernet1, a physical port by name.
     #
````

<!-- patch: platforms/1.0.0/cisco_nxos.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_nxos.yaml b/platforms/1.0.0/cisco_nxos.yaml
index 3bc5ba2..114079f 100644
--- a/platforms/1.0.0/cisco_nxos.yaml
+++ b/platforms/1.0.0/cisco_nxos.yaml
@@ -30,6 +30,11 @@ platforms:
     device_config:
       - aaa authorization commands default group port49 local
       - aaa authorization config-commands default group port49 local
+    # No role refuses a command while port49 answers (ceiling-cisco_nxos.md),
+    # so nothing is unreachable. Under local authorization network-admin
+    # changed configuration (L16-cisco_nxos.md, command authorization LOCAL).
+    fallback:
+      admin: "network-admin: every command, configuration included"
     # No priv-lvl is rendered, so the token's ceiling takes its number here:
     # operator numbers 15, admin's, on the owner's ruling of 2026-09-24
     # (spec §6, decision 23).
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add platforms internal
git commit -m "feat: dead-rule and fallback-exposure reports (spec §12)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: `port49 devices check-config`

**Files:**
- Create: `internal/platform/config.go`, `cmd/port49/devices.go`
- Modify: `internal/platform/dialect.go`, `internal/platform/adapter.go` (`LocalAccounts`,
  `ConfigChecks`, `ConfigCheck`), `platforms/1.0.0/*.yaml`
- Modify: `internal/policy/review.go` (`ServedUsernames`), `cmd/port49/main.go`
- Test: `internal/platform/config_test.go`, `internal/platform/adapter_test.go`,
  `internal/policy/review_test.go`, `cmd/port49/devices_test.go`

**Interfaces:**
- Produces: `Dialect.LocalAccounts []string` (RE2, one capture group), `Dialect.ConfigChecks
  []ConfigCheck`, `type ConfigCheck struct { Match, Says string }`, keys `local_accounts`,
  `config_checks`; `func (d Dialect) ReadConfig(config []byte) ([]LocalAccount, []ConfigFinding,
  error)` — the error where the text was not read to the end, which the command exits 1 on
  (pre-flight S9);
  `func (p *Policy) ServedUsernames(device string, now time.Time) (map[string]string, []string, error)`.
  `port49 devices check-config --policy F --inventory I --device NAME CONFIGFILE`, exit 1 on a
  finding. This is plan 2b's owed check (spec §5.6).

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/devices_test.go -->
````diff
diff --git a/cmd/port49/devices_test.go b/cmd/port49/devices_test.go
new file mode 100644
index 0000000..b9c4960
--- /dev/null
+++ b/cmd/port49/devices_test.go
@@ -0,0 +1,52 @@
+package main
+
+import (
+	"bytes"
+	"os"
+	"path/filepath"
+	"strings"
+	"testing"
+)
+
+// A device-local account named as a username port49 serves on the device is
+// the collision spec §5.6 forbids, and each line the adapter's checks name is
+// reported beside it; either fails the check (plan 2b's owed configuration
+// check). The break-glass account port49 does not serve is fine.
+func TestCheckConfigFindsACollisionAndAForbiddenLine(t *testing.T) {
+	pol, inv := policyFixture(t)
+	cfg := filepath.Join(t.TempDir(), "leaf-01.cfg")
+	if err := os.WriteFile(cfg, []byte("hostname leaf-01\n"+
+		"username breakglass privilege 15 role network-admin secret 0 x\n"+
+		"username noc privilege 1 secret 0 y\n"+
+		"aaa authorization commands all default group port49 none\n"), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
+	for _, want := range []string{
+		`COLLISION: ` + cfg + `:3: a device-local account "noc" is the username port49 serves subject noc on leaf-01`,
+		`CONFIG: ` + cfg + `:4: aaa authorization commands all default group port49 none: the command method list falls back`,
+		"2 local accounts, 2 usernames served on leaf-01 (arista_eos), 2 findings\n",
+	} {
+		if !strings.Contains(out.String(), want) {
+			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
+		}
+	}
+	if code != 1 || strings.Contains(out.String(), `"breakglass"`) {
+		t.Fatalf("code %d\n%s", code, out.String())
+	}
+	if err := os.WriteFile(cfg, []byte("username breakglass privilege 15 secret 0 x\n"), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	out.Reset()
+	if code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg},
+		&out, &errb); code != 0 {
+		t.Fatalf("code %d\n%s", code, out.String())
+	}
+	for _, args := range [][]string{{"devices", "check-config", "--policy", pol, "--inventory", inv, cfg},
+		{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01"}, {"devices"}} {
+		if code := run(args, &out, &errb); code != 2 {
+			t.Errorf("%q: code %d", args, code)
+		}
+	}
+}
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index 8aab240..fc778c9 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -31,7 +31,15 @@ var shipped = map[string]Dialect{
 		// ceiling-arista_eos.md; L16-arista_eos.md, command authorization LOCAL.
 		Unreachable: map[string][]string{"readonly": {"clear counters **", "clear ip bgp **", "configure terminal **",
 			"show users detail **"}},
-		Fallback: map[string]string{"admin": "network-admin: every command, configuration included"},
+		Fallback:      map[string]string{"admin": "network-admin: every command, configuration included"},
+		LocalAccounts: []string{`^username (\S+)`},
+		ConfigChecks: []ConfigCheck{
+			{Match: `^aaa authorization commands \S+ default .*\b(none|if-authenticated)\s*$`, Says: "the command method " +
+				"list falls back to none or if-authenticated: an operator session at 15 runs every command when port49 " +
+				"cannot answer; end it in local (spec §6, decision 23)"},
+			{Match: `^aaa authentication enable default .*\b(local|enable)\s*$`, Says: "enable falls back to a local " +
+				"secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)"},
+		},
 	},
 	"cisco_nxos": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true,
@@ -46,7 +54,13 @@ var shipped = map[string]Dialect{
 		EnableUsername:      EnablePrincipal,
 		DeviceConfig: []string{"aaa authorization commands default group port49 local",
 			"aaa authorization config-commands default group port49 local"},
-		Fallback: map[string]string{"admin": "network-admin: every command, configuration included"},
+		Fallback:      map[string]string{"admin": "network-admin: every command, configuration included"},
+		LocalAccounts: []string{`^username (\S+)`},
+		ConfigChecks: []ConfigCheck{
+			{Match: `^aaa authorization (config-)?commands default .*\b(none|if-authenticated)\s*$`, Says: "the command " +
+				"method list falls back to none or if-authenticated: an operator session runs every command when port49 " +
+				"cannot answer; end it in local (spec §6, decision 23)"},
+		},
 	},
 	"cisco_iosxe": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true, SplitsInterfaceNames: true,
@@ -63,7 +77,15 @@ var shipped = map[string]Dialect{
 			"aaa accounting commands 7 default start-stop group port49", "privilege exec level 7 clear counters"},
 		Unreachable: map[string][]string{"readonly": {"clear counters **", "clear ip bgp **", "configure terminal **"},
 			"operator": {"clear ip bgp **", "configure terminal **"}},
-		Fallback: map[string]string{"admin": "level 15: every command, configuration included"},
+		Fallback:      map[string]string{"admin": "level 15: every command, configuration included"},
+		LocalAccounts: []string{`^username (\S+)`},
+		ConfigChecks: []ConfigCheck{
+			{Match: `^aaa authorization commands \d+ default .*\b(none|if-authenticated)\s*$`, Says: "the command method " +
+				"list falls back to none or if-authenticated: an ERROR or an outage then permits every command at that " +
+				"level (tests/lab/results/L4-error-cisco_iosxe.md); end it in local"},
+			{Match: `^aaa authentication enable default .*\b(local|enable)\s*$`, Says: "enable falls back to a local " +
+				"secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)"},
+		},
 	},
 	"juniper_junos": {
 		PipeToken: "|", StripCR: true,
@@ -74,6 +96,10 @@ var shipped = map[string]Dialect{
 			"allow-configuration-regexps", "deny-configuration-regexps"},
 		InertAttributes: []string{"home-directory"},
 		EnableUsername:  EnablePrincipal,
+		LocalAccounts:   []string{`^set system login user (\S+)`, `^\s*user (\S+) \{`},
+		ConfigChecks: []ConfigCheck{{Match: `authentication-order .*\bpassword\b`, Says: "a FAIL from port49 falls " +
+			"through to the local password on this platform (tests/lab/results/L4-juniper_vsrx.md, " +
+			"L4-juniper_vjunos-router.md): a denied operator logs in locally"}},
 	},
 }
 
````

<!-- patch: internal/platform/config_test.go -->
````diff
diff --git a/internal/platform/config_test.go b/internal/platform/config_test.go
new file mode 100644
index 0000000..d897423
--- /dev/null
+++ b/internal/platform/config_test.go
@@ -0,0 +1,91 @@
+package platform
+
+import (
+	"os"
+	"reflect"
+	"strings"
+	"testing"
+)
+
+// The adapters read the lab's own device configurations the way the check
+// does: each names its break-glass account, and each line the spec forbids is
+// found where the lab carries it on purpose — the enable fallback L3 needs, and
+// the Junos authentication order L4 measured falling through on a FAIL.
+func TestTheAdaptersReadTheLabConfigs(t *testing.T) {
+	for _, tt := range []struct {
+		platform, file string
+		accounts       []LocalAccount
+		checks         []int
+		says           string
+	}{
+		{"arista_eos", "eos-startup.cfg", []LocalAccount{{"breakglass", 16}}, []int{24}, "enable falls back to a local secret"},
+		{"cisco_iosxe", "iosxe-startup.cfg", []LocalAccount{{"breakglass", 50}}, []int{91}, "enable falls back to a local secret"},
+		{"cisco_nxos", "nxos-startup.cfg", []LocalAccount{{"breakglass", 34}}, nil, ""},
+		{"juniper_junos", "vjunos-startup.conf", []LocalAccount{{"remote", 52}, {"breakglass", 56}}, []int{32},
+			"falls through to the local password"},
+	} {
+		raw, err := os.ReadFile("../../tests/lab/configs/" + tt.file)
+		if err != nil {
+			t.Fatal(err)
+		}
+		d, _ := DialectFor(tt.platform)
+		accounts, findings, err := d.ReadConfig(raw)
+		if err != nil || !reflect.DeepEqual(accounts, tt.accounts) {
+			t.Errorf("%s accounts: %+v %v", tt.platform, accounts, err)
+		}
+		var lines []int
+		for _, f := range findings {
+			lines = append(lines, f.Line)
+			if !strings.Contains(f.Says, tt.says) {
+				t.Errorf("%s line %d: %q", tt.platform, f.Line, f.Says)
+			}
+		}
+		if !reflect.DeepEqual(lines, tt.checks) {
+			t.Errorf("%s checks on lines %v, want %v", tt.platform, lines, tt.checks)
+		}
+	}
+}
+
+// A command method list that falls back to none or if-authenticated is named
+// on every per-command platform (spec §6, decision 23).
+func TestAMethodListThatFallsBackToNoneIsNamed(t *testing.T) {
+	for platformName, line := range map[string]string{
+		"arista_eos":  "aaa authorization commands all default group port49 none",
+		"cisco_iosxe": "aaa authorization commands 15 default group port49 if-authenticated",
+		"cisco_nxos":  "aaa authorization config-commands default group port49 none",
+	} {
+		d, _ := DialectFor(platformName)
+		if _, findings, _ := d.ReadConfig([]byte("hostname x\n" + line + "\n")); len(findings) != 1 ||
+			findings[0].Line != 2 || !strings.Contains(findings[0].Says, "none or if-authenticated") {
+			t.Errorf("%s: %+v", platformName, findings)
+		}
+	}
+	eos, _ := DialectFor("arista_eos")
+	if _, findings, _ := eos.ReadConfig([]byte("aaa authorization commands all default group port49 local\n")); len(findings) != 0 {
+		t.Errorf("a list ending in local is what the spec asks for: %+v", findings)
+	}
+}
+
+// A configuration the check could not read to the end is an error, never a
+// clean result: a line past the scanner's limit — a banner, a certificate
+// chain — would otherwise stop the read and pass whatever followed it.
+func TestAConfigReadShortIsAnError(t *testing.T) {
+	eos, _ := DialectFor("arista_eos")
+	raw := "banner motd " + strings.Repeat("x", 2<<20) + "\naaa authorization commands all default group port49 none\n"
+	if _, _, err := eos.ReadConfig([]byte(raw)); err == nil {
+		t.Fatal("a line past the limit must fail the read")
+	}
+}
+
+// A pattern with no capture group could not say which account it found.
+func TestALocalAccountPatternCapturesTheName(t *testing.T) {
+	d, _ := DialectFor("arista_eos")
+	d.LocalAccounts = []string{`^username \S+`}
+	if err := Validate("arista_eos", d); err == nil || !strings.Contains(err.Error(), "one capture group") {
+		t.Fatalf("%v", err)
+	}
+	d.LocalAccounts, d.ConfigChecks = nil, []ConfigCheck{{Match: "x"}}
+	if err := Validate("arista_eos", d); err == nil || !strings.Contains(err.Error(), "config_checks[0]") {
+		t.Fatalf("%v", err)
+	}
+}
````

<!-- patch: internal/policy/review_test.go -->
````diff
diff --git a/internal/policy/review_test.go b/internal/policy/review_test.go
index c6ae933..7771bdd 100644
--- a/internal/policy/review_test.go
+++ b/internal/policy/review_test.go
@@ -1,6 +1,7 @@
 package policy
 
 import (
+	"reflect"
 	"strings"
 	"testing"
 	"time"
@@ -32,3 +33,18 @@ func TestReviewListsEveryGrantRow(t *testing.T) {
 		t.Fatal("an undeclared subject is an error")
 	}
 }
+
+// ServedUsernames is every username a grant reaches the device with, by the
+// subject that claims it; a group subject's members are the directory's, so
+// the group is named instead (spec §5.6; plan 7).
+func TestServedUsernamesAreTheOnesAGrantReaches(t *testing.T) {
+	p := mustParse(t, good)
+	users, groups, err := p.ServedUsernames("leaf-01", noon)
+	if err != nil || !reflect.DeepEqual(users, map[string]string{"alice": "alice", "svc-config-backup": "svc_oxidized"}) ||
+		!reflect.DeepEqual(groups, []string{"netops_admins"}) {
+		t.Fatalf("%v %v %v", users, groups, err)
+	}
+	if _, _, err := p.ServedUsernames("nowhere", noon); err == nil {
+		t.Fatal("a device not in the inventory")
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/ ./cmd/port49/`
Expected: FAIL — `undefined: ConfigCheck`, `p.ServedUsernames undefined` (build failed), and
`TestCheckConfigFindsACollisionAndAForbiddenLine`.

- [ ] **Step 3: Write the check**

<!-- patch: cmd/port49/devices.go -->
````diff
diff --git a/cmd/port49/devices.go b/cmd/port49/devices.go
new file mode 100644
index 0000000..bb7db55
--- /dev/null
+++ b/cmd/port49/devices.go
@@ -0,0 +1,82 @@
+package main
+
+import (
+	"flag"
+	"fmt"
+	"io"
+	"os"
+	"strings"
+	"time"
+)
+
+// checkConfig is `port49 devices check-config` (spec §5.6, §6): a device's
+// configuration, as `show running-config` prints it, read against the
+// policy's adapter for its platform. A device-local account named as a
+// username port49 serves on that device is a collision the spec forbids —
+// such a session's commands arrive under the same username and are
+// authorized at the level port49 granted that username there — and each line
+// the adapter's checks name is one the spec says the device must not carry.
+// It exits 1 on either. port49 never logs into a device; this reads a file a
+// compliance tool fetched (spec §8, "Verification").
+func checkConfig(args []string, stdout, stderr io.Writer) int {
+	fs := flag.NewFlagSet("port49 devices check-config", flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	var files policyFiles
+	files.register(fs)
+	device := fs.String("device", "", "the device the configuration is from, by its inventory name")
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	if files.missing() || *device == "" || fs.NArg() != 1 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	p, err := files.load()
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 devices check-config:", err)
+		return 1
+	}
+	d, ok := p.Device(*device)
+	if !ok {
+		fmt.Fprintf(stderr, "port49 devices check-config: device %q is not in the inventory\n", *device)
+		return 1
+	}
+	config, err := os.ReadFile(fs.Arg(0))
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 devices check-config:", err)
+		return 1
+	}
+	served, groups, err := p.ServedUsernames(*device, time.Now())
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 devices check-config:", err)
+		return 1
+	}
+	accounts, findings, err := p.Dialect(d.Platform).ReadConfig(config)
+	if err != nil {
+		fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", fs.Arg(0), err)
+		return 1
+	}
+	failed := 0
+	for _, a := range accounts {
+		if subject, ok := served[a.Name]; ok {
+			failed++
+			fmt.Fprintf(stdout, "COLLISION: %s:%d: a device-local account %q is the username port49 serves subject %s "+
+				"on %s: a session under it inherits that context's level, and the spec forbids the collision (spec "+
+				"§5.6); rename the local account\n", fs.Arg(0), a.Line, a.Name, subject, *device)
+		}
+	}
+	for _, f := range findings {
+		failed++
+		fmt.Fprintf(stdout, "CONFIG: %s:%d: %s: %s\n", fs.Arg(0), f.Line, strings.TrimSpace(f.Text), f.Says)
+	}
+	for _, g := range groups {
+		fmt.Fprintf(stdout, "note: group subject %s reaches %s; its members' usernames come from the directory "+
+			"(plan 7), so they are not checked\n", g, *device)
+	}
+	fmt.Fprintf(stdout, "%d local accounts, %d usernames served on %s (%s), %d findings\n", len(accounts), len(served),
+		*device, d.Platform, failed)
+	if failed > 0 {
+		return 1
+	}
+	return 0
+}
````

<!-- patch: cmd/port49/main.go -->
````diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index fc91e4c..bf4648c 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -43,6 +43,7 @@ const usage = `usage:
   port49 platform show [--set VERSION | --policy FILE --inventory FILE] PLATFORM
   port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir DIR)
   port49 platform upgrade --policy FILE --inventory FILE --to VERSION [--write]
+  port49 devices check-config --policy FILE --inventory FILE --device NAME CONFIGFILE
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
@@ -74,6 +75,10 @@ func run(args []string, stdout, stderr io.Writer) int {
 		}
 	case "platform":
 		return platformCmd(args[1:], stdout, stderr)
+	case "devices":
+		if len(args) > 1 && args[1] == "check-config" {
+			return checkConfig(args[2:], stdout, stderr)
+		}
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
````

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index cc97f02..cde77ac 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -39,6 +39,8 @@ type Spec struct {
 	Verified             *string              `yaml:"verified,omitempty"`
 	Unreachable          *map[string][]string `yaml:"unreachable,omitempty"`
 	Fallback             *map[string]string   `yaml:"fallback,omitempty"`
+	LocalAccounts        *[]string            `yaml:"local_accounts,omitempty"`
+	ConfigChecks         *[]ConfigCheck       `yaml:"config_checks,omitempty"`
 }
 
 // ParseSpecs reads an adapter file: one YAML document whose one key is
@@ -139,6 +141,12 @@ func (s Spec) Over(base Dialect) Dialect {
 			d.Fallback[k] = v
 		}
 	}
+	if s.LocalAccounts != nil {
+		d.LocalAccounts = slices.Clone(*s.LocalAccounts)
+	}
+	if s.ConfigChecks != nil {
+		d.ConfigChecks = slices.Clone(*s.ConfigChecks)
+	}
 	return d
 }
 
@@ -286,6 +294,19 @@ func Validate(name string, d Dialect) error {
 				level)
 		}
 	}
+	for i, p := range d.LocalAccounts {
+		re, err := regexp.Compile(p)
+		if err != nil || re.NumSubexp() != 1 {
+			return fmt.Errorf("%s[%d]: %q is an RE2 pattern with one capture group, the account's name", field("local_accounts"),
+				i, p)
+		}
+	}
+	for i, c := range d.ConfigChecks {
+		if _, err := regexp.Compile(c.Match); err != nil || c.Match == "" || strings.TrimSpace(c.Says) == "" {
+			return fmt.Errorf("%s[%d]: match is an RE2 pattern over a configuration line, and says what the line costs",
+				field("config_checks"), i)
+		}
+	}
 	if !slices.Contains(verifications, d.Verified) {
 		return fmt.Errorf("%s is %q; it is containerlab, community, or unset", field("verified"), d.Verified)
 	}
@@ -356,6 +377,12 @@ func SpecOf(d Dialect) Spec {
 	if d.Fallback != nil {
 		s.Fallback = &d.Fallback
 	}
+	if d.LocalAccounts != nil {
+		s.LocalAccounts = &d.LocalAccounts
+	}
+	if d.ConfigChecks != nil {
+		s.ConfigChecks = &d.ConfigChecks
+	}
 	return s
 }
 
````

<!-- patch: internal/platform/config.go -->
````diff
diff --git a/internal/platform/config.go b/internal/platform/config.go
new file mode 100644
index 0000000..569c437
--- /dev/null
+++ b/internal/platform/config.go
@@ -0,0 +1,67 @@
+package platform
+
+import (
+	"bufio"
+	"bytes"
+	"fmt"
+	"regexp"
+)
+
+// LocalAccount is a device-local account a configuration declares, and the
+// line that declares it.
+type LocalAccount struct {
+	Name string
+	Line int
+}
+
+// ConfigFinding is a configuration line one of the adapter's checks names.
+type ConfigFinding struct {
+	Line int
+	Text string
+	Says string
+}
+
+// ReadConfig reads a device's configuration text, as `show running-config`
+// prints it, against the adapter: every local account its LocalAccounts
+// patterns name, every line a ConfigChecks entry matches, and an error where
+// the text could not be read to the end. It is a lab and CI instrument: port49
+// never logs into a device (spec §8, "Verification").
+func (d Dialect) ReadConfig(config []byte) ([]LocalAccount, []ConfigFinding, error) {
+	var accounts []LocalAccount
+	var findings []ConfigFinding
+	var accountRes, checkRes []*regexp.Regexp
+	// Validate compiled every pattern; one that does not compile here is
+	// skipped rather than trusted to panic.
+	for _, p := range d.LocalAccounts {
+		if re, err := regexp.Compile(p); err == nil && re.NumSubexp() == 1 {
+			accountRes = append(accountRes, re)
+		}
+	}
+	checks := make(map[*regexp.Regexp]string)
+	for _, c := range d.ConfigChecks {
+		if re, err := regexp.Compile(c.Match); err == nil {
+			checkRes, checks[re] = append(checkRes, re), c.Says
+		}
+	}
+	sc := bufio.NewScanner(bytes.NewReader(config))
+	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
+	for n := 1; sc.Scan(); n++ {
+		line := sc.Text()
+		for _, re := range accountRes {
+			if m := re.FindStringSubmatch(line); m != nil {
+				accounts = append(accounts, LocalAccount{Name: m[1], Line: n})
+			}
+		}
+		for _, re := range checkRes {
+			if re.MatchString(line) {
+				findings = append(findings, ConfigFinding{Line: n, Text: line, Says: checks[re]})
+			}
+		}
+	}
+	// A read that stopped short is not a clean configuration: whatever
+	// followed the line it stopped at was never checked.
+	if err := sc.Err(); err != nil {
+		return nil, nil, fmt.Errorf("the configuration was not read to the end: %w", err)
+	}
+	return accounts, findings, nil
+}
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index 36c026d..b686c4b 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -110,6 +110,22 @@ type Dialect struct {
 	// confines at that level has more access in an outage than the policy
 	// grants (spec §6, §12, "Fallback exposure").
 	Fallback map[string]string
+	// LocalAccounts are RE2 patterns, one capture group each, that find a
+	// device-local account's name in the device's configuration: `port49
+	// devices check-config` warns where one is a username port49 serves
+	// there, which the spec forbids (§5.6, "Local account names MUST NOT
+	// collide").
+	LocalAccounts []string
+	// ConfigChecks are configuration lines the spec says a device must not
+	// carry (§5.6, §6), each with what it costs: the same check names them.
+	ConfigChecks []ConfigCheck
+}
+
+// ConfigCheck is one line a device's configuration must not carry: an RE2
+// pattern over each line, and what the line costs, as the check says it.
+type ConfigCheck struct {
+	Match string `yaml:"match"`
+	Says  string `yaml:"says"`
 }
 
 // builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
@@ -189,6 +205,8 @@ func (d Dialect) clone() Dialect {
 	if d.Fallback != nil {
 		d.Fallback = maps.Clone(d.Fallback)
 	}
+	d.LocalAccounts = slices.Clone(d.LocalAccounts)
+	d.ConfigChecks = slices.Clone(d.ConfigChecks)
 	return d
 }
 
````

<!-- patch: internal/policy/review.go -->
````diff
diff --git a/internal/policy/review.go b/internal/policy/review.go
index 3136b32..57d6e9a 100644
--- a/internal/policy/review.go
+++ b/internal/policy/review.go
@@ -37,3 +37,28 @@ func (p *Policy) Review(subject string, now time.Time) ([]ReviewRow, error) {
 	}
 	return out, nil
 }
+
+// ServedUsernames is every username port49 would mint a token under for the
+// device at now, by the subject that claims it: each identity-list subject a
+// grant reaches the device with. A group subject's usernames come from the
+// directory one per member (plan 7), so groups names the group subjects that
+// reach it, whose members the check cannot list.
+func (p *Policy) ServedUsernames(device string, now time.Time) (usernames map[string]string, groups []string, err error) {
+	d, ok := p.device(device)
+	if !ok {
+		return nil, nil, fmt.Errorf("device %q is not in the inventory", device)
+	}
+	usernames = map[string]string{}
+	for _, name := range sortedKeys(p.subs) {
+		s := p.subs[name]
+		if len(p.compose(s, d, now).grants) == 0 {
+			continue
+		}
+		if s.Group != "" {
+			groups = append(groups, name)
+			continue
+		}
+		usernames[s.Username] = name
+	}
+	return usernames, groups, nil
+}
````

<!-- patch: platforms/1.0.0/arista_eos.yaml -->
````diff
diff --git a/platforms/1.0.0/arista_eos.yaml b/platforms/1.0.0/arista_eos.yaml
index d685103..42a2b8e 100644
--- a/platforms/1.0.0/arista_eos.yaml
+++ b/platforms/1.0.0/arista_eos.yaml
@@ -39,6 +39,15 @@ platforms:
     # authorization LOCAL).
     fallback:
       admin: "network-admin: every command, configuration included"
+    # `port49 devices check-config`: a local account named as a port49
+    # username inherits that username's context (spec §5.6), and two lines
+    # the spec forbids.
+    local_accounts: ['^username (\S+)']
+    config_checks:
+      - match: '^aaa authorization commands \S+ default .*\b(none|if-authenticated)\s*$'
+        says: "the command method list falls back to none or if-authenticated: an operator session at 15 runs every command when port49 cannot answer; end it in local (spec §6, decision 23)"
+      - match: '^aaa authentication enable default .*\b(local|enable)\s*$'
+        says: "enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)"
     # Interface names, not device behaviour: spec §8's example.
     entity_classes:
       management: ['^Management[0-9]+$']
````

<!-- patch: platforms/1.0.0/cisco_iosxe.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_iosxe.yaml b/platforms/1.0.0/cisco_iosxe.yaml
index 0f6671d..5477d53 100644
--- a/platforms/1.0.0/cisco_iosxe.yaml
+++ b/platforms/1.0.0/cisco_iosxe.yaml
@@ -48,6 +48,13 @@ platforms:
     # exposure it would be.
     fallback:
       admin: "level 15: every command, configuration included"
+    # `port49 devices check-config` (spec §5.6).
+    local_accounts: ['^username (\S+)']
+    config_checks:
+      - match: '^aaa authorization commands \d+ default .*\b(none|if-authenticated)\s*$'
+        says: "the command method list falls back to none or if-authenticated: an ERROR or an outage then permits every command at that level (tests/lab/results/L4-error-cisco_iosxe.md); end it in local"
+      - match: '^aaa authentication enable default .*\b(local|enable)\s*$'
+        says: "enable falls back to a local secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)"
     # No entity class is defined: the lab's management interface is
     # GigabitEthernet1, a physical port by name.
     #
````

<!-- patch: platforms/1.0.0/cisco_nxos.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_nxos.yaml b/platforms/1.0.0/cisco_nxos.yaml
index 114079f..ae58461 100644
--- a/platforms/1.0.0/cisco_nxos.yaml
+++ b/platforms/1.0.0/cisco_nxos.yaml
@@ -35,6 +35,12 @@ platforms:
     # changed configuration (L16-cisco_nxos.md, command authorization LOCAL).
     fallback:
       admin: "network-admin: every command, configuration included"
+    # `port49 devices check-config` (spec §5.6). NX-OS 10.x has no enable
+    # exchange (L3-nxos-cisco_nxos.md).
+    local_accounts: ['^username (\S+)']
+    config_checks:
+      - match: '^aaa authorization (config-)?commands default .*\b(none|if-authenticated)\s*$'
+        says: "the command method list falls back to none or if-authenticated: an operator session runs every command when port49 cannot answer; end it in local (spec §6, decision 23)"
     # No priv-lvl is rendered, so the token's ceiling takes its number here:
     # operator numbers 15, admin's, on the owner's ruling of 2026-09-24
     # (spec §6, decision 23).
````

<!-- patch: platforms/1.0.0/juniper_junos.yaml -->
````diff
diff --git a/platforms/1.0.0/juniper_junos.yaml b/platforms/1.0.0/juniper_junos.yaml
index 6ad4261..ae5a2ee 100644
--- a/platforms/1.0.0/juniper_junos.yaml
+++ b/platforms/1.0.0/juniper_junos.yaml
@@ -30,3 +30,8 @@ platforms:
       deny-configuration, allow-commands-regexps, deny-commands-regexps, allow-configuration-regexps,
       deny-configuration-regexps]
     inert_attributes: [home-directory]
+    # `port49 devices check-config` (spec §5.6), set or hierarchical form.
+    local_accounts: ['^set system login user (\S+)', '^\s*user (\S+) \{']
+    config_checks:
+      - match: 'authentication-order .*\bpassword\b'
+        says: "a FAIL from port49 falls through to the local password on this platform (tests/lab/results/L4-juniper_vsrx.md, L4-juniper_vjunos-router.md): a denied operator logs in locally"
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add platforms internal cmd
git commit -m "feat: port49 devices check-config finds a local account colliding with a served username

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: `grants remove --pr` opens the review

**Files:**
- Create: `cmd/port49/pr.go`
- Modify: `cmd/port49/policy.go` (`grantsRemove`: `--pr`, `--remote`, `--base`), `cmd/port49/main.go`
- Test: `cmd/port49/pr_test.go`

**Interfaces:**
- Produces: `var runGit func(dir string, args ...string) (string, error)`;
  `var openPR func(dir, branch, base, title, body string) (string, error)` (a test replaces it);
  `func removalPR(path, subject string, edited []byte, r policy.Removal, remote, base string) (string, error)`.
  Branch `port49/offboard-<subject>`, cut from `--base` as `--remote` has it after a fetch; a
  subject name outside `[A-Za-z0-9._-]` is refused for `--pr`, and so is a `--remote` or `--base`
  starting with `-`, or a policy file that differs from the base's (pre-flight S5).
  `func withoutCredentials(string) string` replaces a URL's credential in git's and gh's error
  text (pre-flight N9). `--pr` with `--write` is a usage error.

The test runs real `git` against a scratch repository and a bare remote, with identity and
signing set in the repository, and skips where `git` is not installed; `gh` is never run.

- [ ] **Step 1: Write the failing test**

<!-- patch: cmd/port49/pr_test.go -->
````diff
diff --git a/cmd/port49/pr_test.go b/cmd/port49/pr_test.go
new file mode 100644
index 0000000..4c6117d
--- /dev/null
+++ b/cmd/port49/pr_test.go
@@ -0,0 +1,146 @@
+package main
+
+import (
+	"bytes"
+	"os"
+	"os/exec"
+	"path/filepath"
+	"strings"
+	"testing"
+)
+
+// gitRepo is a scratch repository holding the policy fixture, committed on
+// main, with a bare repository as its origin. Identity and signing are set
+// in the repository, so the test does not depend on the machine's git config.
+func gitRepo(t *testing.T) (repo, remote, pol, inv string) {
+	t.Helper()
+	if _, err := exec.LookPath("git"); err != nil {
+		t.Skip("git is not installed")
+	}
+	root := t.TempDir()
+	repo, remote = filepath.Join(root, "policy"), filepath.Join(root, "remote.git")
+	fixturePol, fixtureInv := policyFixture(t)
+	for _, args := range [][]string{{"init", "--quiet", "--bare", remote}, {"init", "--quiet", "-b", "main", repo}} {
+		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
+			t.Fatalf("git %v: %v %s", args, err, out)
+		}
+	}
+	pol, inv = filepath.Join(repo, "policy.yaml"), filepath.Join(repo, "inventory.yaml")
+	for src, dst := range map[string]string{fixturePol: pol, fixtureInv: inv} {
+		if err := os.WriteFile(dst, readFile(t, src), 0o644); err != nil {
+			t.Fatal(err)
+		}
+	}
+	for _, args := range [][]string{{"config", "user.email", "ci@example.test"}, {"config", "user.name", "ci"},
+		{"config", "commit.gpgsign", "false"}, {"add", "."}, {"commit", "--quiet", "-m", "policy"},
+		{"remote", "add", "origin", remote}, {"push", "--quiet", "origin", "main"}} {
+		if _, err := runGit(repo, args...); err != nil {
+			t.Fatal(err)
+		}
+	}
+	return repo, remote, pol, inv
+}
+
+// `grants remove --pr` opens the pull request plan 4's edit prepares (spec
+// §12; owner's ruling 2026-09-24): a branch carrying the removal and nothing
+// else, pushed, and the review opened against main. The operator's checkout
+// is not touched, and a policy file with uncommitted edits is refused rather
+// than left out of the pull request.
+func TestGrantsRemoveOpensThePullRequest(t *testing.T) {
+	repo, remote, pol, inv := gitRepo(t)
+	before := readFile(t, pol)
+	var asked []string
+	orig := openPR
+	openPR = func(dir, branch, base, title, body string) (string, error) {
+		asked = []string{branch, base, title, body}
+		return "https://example.test/policy/pull/7", nil
+	}
+	t.Cleanup(func() { openPR = orig })
+	var out, errb bytes.Buffer
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
+		&errb); code != 0 || out.String() != "https://example.test/policy/pull/7\n" {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	if len(asked) != 4 || asked[0] != "port49/offboard-ops" || asked[1] != "main" ||
+		asked[2] != "chore(policy): offboard ops" || !strings.Contains(asked[3], "1 grant row(s), the subject block") {
+		t.Fatalf("the pull request: %q", asked)
+	}
+	if !bytes.Equal(readFile(t, pol), before) {
+		t.Fatal("the checkout's policy file changed")
+	}
+	pushed, err := runGit(remote, "show", "port49/offboard-ops:policy.yaml")
+	if err != nil || strings.Contains(pushed, "name: ops") || !strings.Contains(pushed, "name: noc") {
+		t.Fatalf("the pushed branch: %v\n%s", err, pushed)
+	}
+	if changed, _ := runGit(remote, "diff", "--name-only", "main", "port49/offboard-ops"); changed != "policy.yaml" {
+		t.Fatalf("the branch changes %q", changed)
+	}
+	if list, _ := runGit(repo, "worktree", "list"); strings.Count(list, "\n") != 0 {
+		t.Fatalf("the scratch worktree is left behind:\n%s", list)
+	}
+	if err := os.WriteFile(pol, append(before, []byte("# an edit in progress\n")...), 0o644); err != nil {
+		t.Fatal(err)
+	}
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--pr"}, &out,
+		&errb); code != 1 || !strings.Contains(errb.String(), "uncommitted changes") {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--pr",
+		"--write"}, &out, &errb); code != 2 {
+		t.Fatalf("--pr and --write: code %d", code)
+	}
+}
+
+// The branch is cut from the base on the remote, not from the checkout's
+// HEAD: an operator on a branch ahead of main gets a pull request carrying the
+// removal alone, and one whose policy file differs from the base's is refused,
+// because the removal was computed from a file the pull request would not
+// merge into (spec §12, "the edit and nothing else").
+func TestThePullRequestIsCutFromTheBase(t *testing.T) {
+	repo, remote, pol, inv := gitRepo(t)
+	orig := openPR
+	openPR = func(dir, branch, base, title, body string) (string, error) { return "https://example.test/pull/8", nil }
+	t.Cleanup(func() { openPR = orig })
+	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("unrelated\n"), 0o644); err != nil {
+		t.Fatal(err)
+	}
+	for _, args := range [][]string{{"checkout", "--quiet", "-b", "work"}, {"add", "notes.txt"},
+		{"commit", "--quiet", "-m", "unrelated"}} {
+		if _, err := runGit(repo, args...); err != nil {
+			t.Fatal(err)
+		}
+	}
+	var out, errb bytes.Buffer
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
+		&errb); code != 0 {
+		t.Fatalf("code %d\n%s", code, errb.String())
+	}
+	if log, _ := runGit(remote, "log", "--format=%s", "main..port49/offboard-ops"); log != "chore(policy): offboard ops" {
+		t.Fatalf("the branch carries more than the removal:\n%s", log)
+	}
+	if err := os.WriteFile(pol, append(readFile(t, pol), []byte("# committed here, not on main\n")...), 0o644); err != nil {
+		t.Fatal(err)
+	}
+	if _, err := runGit(repo, "commit", "--quiet", "-am", "a local policy edit"); err != nil {
+		t.Fatal(err)
+	}
+	errb.Reset()
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--pr"}, &out,
+		&errb); code != 1 || !strings.Contains(errb.String(), "differs from origin/main") {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+	errb.Reset()
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--pr",
+		"--remote", "--receive-pack=touch /tmp/x"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "not a remote") {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+}
+
+// git's own error text can carry a remote's URL, and a URL can carry a
+// credential: it is removed before the error is printed.
+func TestAGitErrorDoesNotPrintACredential(t *testing.T) {
+	got := withoutCredentials("fatal: unable to access 'https://ci:ghp_s3cret@github.com/o/p.git/': 403")
+	if strings.Contains(got, "ghp_s3cret") || !strings.Contains(got, "https://«redacted»@github.com/o/p.git/") {
+		t.Fatalf("%q", got)
+	}
+}
````

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./cmd/port49/`
Expected: FAIL — `undefined: runGit`, `undefined: openPR` (build failed).

- [ ] **Step 3: Open the pull request**

<!-- patch: cmd/port49/main.go -->
````diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index bf4648c..c267355 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -38,7 +38,7 @@ const usage = `usage:
   port49 policy replay [--line N] LOGFILE|-
   port49 policy diff --old FILE --new FILE --inventory FILE
   port49 access review --policy FILE --inventory FILE --subject NAME
-  port49 grants remove --policy FILE --inventory FILE --subject NAME [--write]
+  port49 grants remove --policy FILE --inventory FILE --subject NAME [--write | --pr [--remote R] [--base B]]
   port49 platform list [--set VERSION | --policy FILE --inventory FILE]
   port49 platform show [--set VERSION | --policy FILE --inventory FILE] PLATFORM
   port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir DIR)
````

<!-- patch: cmd/port49/policy.go -->
````diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 69c3ff8..70ce382 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -651,9 +651,9 @@ func accessReview(args []string, stdout, stderr io.Writer) int {
 // grantsRemove is the offboarding path for machine subjects and literal
 // identities (spec §12): the policy file with every grant row naming the
 // subject deleted, and the subject block with them. It prints the new file on
-// stdout for a pull request, or with --write replaces the file in place; the
-// result must load against the inventory before anything is written. What it
-// removed goes to stderr.
+// stdout, or with --write replaces the file in place, or with --pr opens the
+// pull request that carries it (removalPR); the result must load against the
+// inventory before anything is written. What it removed goes to stderr.
 func grantsRemove(args []string, stdout, stderr io.Writer) int {
 	fs := flag.NewFlagSet("port49 grants remove", flag.ContinueOnError)
 	fs.SetOutput(stderr)
@@ -661,10 +661,13 @@ func grantsRemove(args []string, stdout, stderr io.Writer) int {
 	files.register(fs)
 	subject := fs.String("subject", "", "the subject to offboard, by its name in the policy")
 	write := fs.Bool("write", false, "replace the policy file instead of printing the result")
+	pr := fs.Bool("pr", false, "open a pull request that carries the removal, leaving the checkout alone")
+	remote := fs.String("remote", "origin", "the remote --pr pushes its branch to")
+	base := fs.String("base", "main", "the branch --pr asks to merge into")
 	if err := fs.Parse(args); err != nil {
 		return 2
 	}
-	if *subject == "" || files.missing() || fs.NArg() != 0 {
+	if *subject == "" || files.missing() || fs.NArg() != 0 || (*write && *pr) {
 		fmt.Fprint(stderr, usage)
 		return 2
 	}
@@ -688,14 +691,24 @@ func grantsRemove(args []string, stdout, stderr io.Writer) int {
 			*subject, err)
 		return 1
 	}
-	if *write {
+	switch {
+	case *pr:
+		url, err := removalPR(files.policy, *subject, out, removed, *remote, *base)
+		if err != nil {
+			fmt.Fprintln(stderr, "port49 grants remove:", err)
+			return 1
+		}
+		fmt.Fprintln(stdout, url)
+	case *write:
 		if err := replaceFile(files.policy, out); err != nil {
 			fmt.Fprintln(stderr, "port49 grants remove:", err)
 			return 1
 		}
-	} else if _, err := stdout.Write(out); err != nil {
-		fmt.Fprintln(stderr, "port49 grants remove:", err)
-		return 1
+	default:
+		if _, err := stdout.Write(out); err != nil {
+			fmt.Fprintln(stderr, "port49 grants remove:", err)
+			return 1
+		}
 	}
 	fmt.Fprintf(stderr, "port49 grants remove: %s: %d grant row(s), the subject block, and %d test(s) removed\n",
 		*subject, removed.Grants, removed.Tests)
````

<!-- patch: cmd/port49/pr.go -->
````diff
diff --git a/cmd/port49/pr.go b/cmd/port49/pr.go
new file mode 100644
index 0000000..62d7f96
--- /dev/null
+++ b/cmd/port49/pr.go
@@ -0,0 +1,140 @@
+package main
+
+import (
+	"bytes"
+	"errors"
+	"fmt"
+	"os"
+	"os/exec"
+	"path/filepath"
+	"regexp"
+	"strings"
+
+	"github.com/blanketfish/port49/internal/policy"
+)
+
+// branchSafe is a subject name that can stand in a branch name as it is.
+var branchSafe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
+
+// runGit runs git in dir, with no shell, and returns what it printed. A test
+// replaces nothing here: it runs real git against a scratch repository.
+var runGit = func(dir string, args ...string) (string, error) {
+	cmd := exec.Command("git", args...)
+	cmd.Dir = dir
+	var out, errb bytes.Buffer
+	cmd.Stdout, cmd.Stderr = &out, &errb
+	if err := cmd.Run(); err != nil {
+		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err,
+			withoutCredentials(strings.TrimSpace(errb.String())))
+	}
+	return strings.TrimSpace(out.String()), nil
+}
+
+// credentialInURL is the user-information part of a URL, where a token
+// pasted into a remote's address sits.
+var credentialInURL = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)
+
+// withoutCredentials is git's or gh's error text with any credential in a URL
+// replaced: some git releases print the remote's address as configured.
+func withoutCredentials(s string) string {
+	return credentialInURL.ReplaceAllString(s, "${1}«redacted»@")
+}
+
+// openPR opens the pull request with the gh CLI, in dir, and returns its URL.
+// A test replaces it: nothing in a test reaches GitHub.
+var openPR = func(dir, branch, base, title, body string) (string, error) {
+	cmd := exec.Command("gh", "pr", "create", "--head", branch, "--base", base, "--title", title, "--body", body)
+	cmd.Dir = dir
+	var out, errb bytes.Buffer
+	cmd.Stdout, cmd.Stderr = &out, &errb
+	if err := cmd.Run(); err != nil {
+		return "", fmt.Errorf("gh pr create: %v: %s", err, withoutCredentials(strings.TrimSpace(errb.String())))
+	}
+	return strings.TrimSpace(out.String()), nil
+}
+
+// removalPR opens the pull request `grants remove` prepares (spec §12; plan 4
+// prepares the file, plan 5 opens the review): a branch off base as the
+// remote has it, with the policy file edited and nothing else, pushed to
+// remote, and a pull request against base. It works in a worktree of its own,
+// so the operator's checkout, and any edit in it, is never touched. It
+// refuses a policy file with uncommitted changes, which the pull request would
+// otherwise silently leave out, and one that differs from base's, since the
+// removal was computed from a file the pull request would not merge into. It
+// returns the pull request's URL.
+func removalPR(path, subject string, edited []byte, r policy.Removal, remote, base string) (string, error) {
+	if !branchSafe.MatchString(subject) {
+		return "", fmt.Errorf("subject %q cannot name a branch; offboard it with --write and open the review by hand",
+			subject)
+	}
+	// Both reach git's argument list; one starting with `-` would be read as
+	// an option (`--receive-pack=...` runs a command).
+	if remote == "" || strings.HasPrefix(remote, "-") {
+		return "", fmt.Errorf("--remote %q is not a remote's name", remote)
+	}
+	if base == "" || strings.HasPrefix(base, "-") {
+		return "", fmt.Errorf("--base %q is not a branch's name", base)
+	}
+	path, err := filepath.EvalSymlinks(path)
+	if err != nil {
+		return "", err
+	}
+	dir := filepath.Dir(path)
+	top, err := runGit(dir, "rev-parse", "--show-toplevel")
+	if err != nil {
+		return "", fmt.Errorf("the policy file is not in a git repository: %w", err)
+	}
+	rel, err := filepath.Rel(top, path)
+	if err != nil {
+		return "", err
+	}
+	if dirty, err := runGit(top, "status", "--porcelain", "--", rel); err != nil {
+		return "", err
+	} else if dirty != "" {
+		return "", errors.New("the policy file has uncommitted changes; commit or discard them first, so the pull " +
+			"request carries the removal and nothing else")
+	}
+	if _, err := runGit(top, "fetch", "--quiet", remote, base); err != nil {
+		return "", err
+	}
+	from, err := runGit(top, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
+	if err != nil {
+		return "", err
+	}
+	here, _ := runGit(top, "rev-parse", "HEAD:"+filepath.ToSlash(rel))
+	there, _ := runGit(top, "rev-parse", from+":"+filepath.ToSlash(rel))
+	if here == "" || here != there {
+		return "", fmt.Errorf("the policy file differs from %s/%s; the removal is computed from your checkout's "+
+			"copy, so bring it level with %s/%s first, and the pull request carries the removal and nothing else",
+			remote, base, remote, base)
+	}
+	branch := "port49/offboard-" + subject
+	scratch, err := os.MkdirTemp("", "port49-offboard-")
+	if err != nil {
+		return "", err
+	}
+	defer os.RemoveAll(scratch)
+	work := filepath.Join(scratch, "work")
+	if _, err := runGit(top, "worktree", "add", "-b", branch, work, from); err != nil {
+		return "", err
+	}
+	defer runGit(top, "worktree", "remove", "--force", work)
+	info, err := os.Stat(path)
+	if err != nil {
+		return "", err
+	}
+	if err := os.WriteFile(filepath.Join(work, rel), edited, info.Mode().Perm()); err != nil {
+		return "", err
+	}
+	title := "chore(policy): offboard " + subject
+	body := fmt.Sprintf("`port49 grants remove --subject %s` (spec §12): %d grant row(s), the subject block, and %d "+
+		"test(s) removed. The edited file loads against the inventory; run `port49 policy test` and `port49 policy "+
+		"diff` in CI as for any policy change.", subject, r.Grants, r.Tests)
+	if _, err := runGit(work, "commit", "--quiet", "-m", title, "-m", body, "--", rel); err != nil {
+		return "", err
+	}
+	if _, err := runGit(work, "push", "--quiet", "-u", remote, branch); err != nil {
+		return "", err
+	}
+	return openPR(work, branch, base, title, body)
+}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet`
Expected: every package `ok`.

- [ ] **Step 5: Commit**

```bash
git add cmd
git commit -m "feat: port49 grants remove --pr opens the offboarding review

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 17 (lab, on beehive): the adapters' replies, measured

**Files:**
- Create: `tests/lab/adapters_test.go`
- Modify: `tests/lab/slice_test.go`, `tests/lab/slice/policy.yaml` (the slice on all three
  per-command platforms)
- Results (written by the run): `tests/lab/results/L22-arista_eos.md`, `L22-cisco_nxos.md`,
  `L22-cisco_iosxe.md` — named for the register row they close (CLAUDE.md, "Closing an entry") —
  `slice-cisco_nxos.md`, `slice-cisco_iosxe.md`, a fresh `slice-arista_eos.md`; evidence under
  `tests/lab/evidence/` (`L22-*.pcap`, `slice-*.pcap`).

**Interfaces:**
- Consumes: `platform.DialectFor(name).Render(level)` — the binary under test's own rendering;
  the harness's `derivedConfig`, `startDaemonWith`, `stopDaemon`, `nextLogin`, `login`, `dial`,
  `drainRecords`, `capture`, `result`, `waitDeviceReady`.
- Produces: the notes Task 18 reads, and `adapterExpect`, the table the run is judged against —
  Decided 5's rendering and `tests/lab/results/ceiling-*.md`'s ladder.

This task runs on the lab host (the lab is single-occupant; the owner has standing consent for lab
runs). It needs no new image: vEOS 4.31.2F, the N9Kv 10.4(2)F and the C8000V 17.13.01a are on hand.
The IOS-XE startup config gained level 7's lines in Task 5, so the IOS-XE node must be redeployed
from it (`make lab` deploys; a hand run must `containerlab deploy --reconfigure`).

For each level the test delivers the adapter's exact reply through the lab authorizer
(`lab.session_attributes`), logs in with a fresh seeded token, and records the device's identity
line (`show privilege`, or `show user-account` on NX-OS), and whether `clear counters` and
`configure terminal` reached port49 at all, and whether a `show version` was permitted. On NX-OS
it records the bare `show interface` too, since production has seen `network-operator` prompted
for sudo there. Each command goes on its own SSH exec channel, as the harness's `login` sends it;
on IOS-XE `clear counters` then meets `[confirm]` with no one to answer, which does not matter,
because whether it reached port49 is read off the authorization record, which comes first.

Then it tries `home-directory*/home/port49`, `idletime*30` and `timeout*480` beside admin's reply;
on IOS-XE a refusal locks SSH for about a minute, and the test waits it out. A candidate is inert
only where its session opened with admin's identity, admin's reach for both ceiling commands, and
a permitted `show version`: L18 saw the C8000V open a session and refuse every command in it, so
an open session alone proves nothing (pre-flight S6).

Last, the fallback decision 25 rests on, which L16 measured only with the method list pointed at
`local` alone (pre-flight B1): operator's reply, one interactive pty session, port49d stopped
under it, then `configure terminal` and `hostname <node>` — the value the device already holds,
as L16 did — typed with the device's method list falling back to `local`. admin's reply is the
control; on EOS and NX-OS it must change the configuration, or the operator's refusal says nothing
about its role. On IOS-XE the control is recorded, not required: a token session at 15 falling
back is unmeasured, and operator's level 7 refuses `configure terminal` in the parser anyway.

It fails on any level whose measurement differs from the adapter's promise, and on an operator
who changes the configuration with port49 down — and CLAUDE.md rule 4 then applies: the adapter
(or decision 25) is wrong, not the device.

- [ ] **Step 1: Write the lab test and move the slice**

<!-- patch: tests/lab/adapters_test.go -->
````diff
diff --git a/tests/lab/adapters_test.go b/tests/lab/adapters_test.go
new file mode 100644
index 0000000..f5db9db
--- /dev/null
+++ b/tests/lab/adapters_test.go
@@ -0,0 +1,380 @@
+//go:build lab
+
+package lab
+
+import (
+	"bytes"
+	"encoding/json"
+	"fmt"
+	"io"
+	"slices"
+	"strings"
+	"sync"
+	"testing"
+	"time"
+
+	"golang.org/x/crypto/ssh"
+
+	adapter "github.com/blanketfish/port49/internal/platform"
+)
+
+// TestAdapterReplies is the differential test of the per-command adapters
+// (plan 5a, Task 17; spec §8, "Differential testing is required"): for each
+// reserved level, the exact reply the built-in adapter renders is delivered,
+// and what the device does with it is measured against what the adapter says
+// it will do — the privilege or role the device reports, and which of the
+// ceiling commands it sends port49 at all (tests/lab/results/ceiling-*.md).
+// Then each candidate inert attribute beside admin's reply: whether the
+// session still opens, the privilege is unchanged, the same ceiling commands
+// reach port49 and a `show version` is still authorized — L18 saw the C8000V
+// open a session and then refuse every command in it — which is what listing
+// it inert would claim (spec §6). On NX-OS the bare `show interface` is
+// recorded too: production has seen network-operator prompted for sudo there
+// (roadmap, plan 5), and readonly gets that role.
+//
+// Last, the fallback decision 25 rests on: operator's reply, one interactive
+// session, port49d stopped under it, and a configuration change typed — the
+// device's method list falls back to local, and the role it delivered at
+// login is the policy. admin's reply is the control: a refusal that happens
+// to every session says nothing about the role.
+//
+// The lab authorizer delivers the reply (`lab.session_attributes`), so every
+// variant is one daemon restart and one seeded login; the rendering itself is
+// the adapter's, read from the binary under test, so the note measures what
+// ships. The level and inert variants send each command on its own SSH exec
+// channel, as the harness's login does; the fallback holds one pty session,
+// because port49d stops in the middle of it. The note is L22's (spec §15).
+
+// adapterProbe is one level's expectation: the identity line the device must
+// print, and whether each ceiling command reaches port49.
+type adapterProbe struct {
+	identity                 string
+	clearReached, cfgReached bool
+}
+
+var adapterExpect = map[string]map[string]adapterProbe{
+	// ceiling-arista_eos.md: level 1 refuses both in the parser; 15 sends both.
+	"arista_eos": {
+		"readonly": {"Current privilege level is 1", false, false},
+		"operator": {"Current privilege level is 15", true, true},
+		"admin":    {"Current privilege level is 15", true, true},
+	},
+	// ceiling-cisco_nxos.md: every role sends both; the role is what differs.
+	"cisco_nxos": {
+		"readonly": {"roles:network-operator", true, true},
+		"operator": {"roles:network-operator", true, true},
+		"admin":    {"roles:network-admin", true, true},
+	},
+	// ceiling-cisco_iosxe.md, with tests/lab/configs/iosxe-startup.cfg's
+	// `privilege exec level 7 clear counters`.
+	"cisco_iosxe": {
+		"readonly": {"Current privilege level is 1", false, false},
+		"operator": {"Current privilege level is 7", true, false},
+		"admin":    {"Current privilege level is 15", true, true},
+	},
+}
+
+// inertCandidates are the attributes Task 18 lists inert where this run finds
+// the session unchanged — opened, admin's identity and reach, and a permitted
+// `show version` — spec §6's own case and two Cisco shell attributes an
+// operator is likeliest to add under `all`.
+var inertCandidates = []string{"home-directory*/home/port49", "idletime*30", "timeout*480"}
+
+func TestAdapterReplies(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		expect, ok := adapterExpect[l.p.name]
+		if !ok {
+			t.Skipf("%s renders no level until plan 5b's projection", l.p.name)
+		}
+		d, _ := adapter.DialectFor(l.p.name)
+		stop := l.capture(t, "L22")
+		defer stop()
+		defer func() {
+			std, err := l.configPath()
+			if err == nil {
+				err = l.restart(std)
+			}
+			if err != nil {
+				t.Fatalf("could not put port49d back on the lab config: %v", err)
+			}
+		}()
+		var obs strings.Builder
+		fmt.Fprintf(&obs, "| level | reply | session | identity | `clear counters` | `configure terminal` | bare `show interface` |\n"+
+			"|---|---|---|---|---|---|---|\n")
+		for _, level := range []string{"readonly", "operator", "admin"} {
+			attrs, _ := d.Render(level)
+			row := l.adapterVariant(t, level, attrs)
+			fmt.Fprintf(&obs, "| %s | `%s` | %s | %s | %s | %s | %s |\n", level, strings.Join(attrs, "`, `"), row.session,
+				row.identity, reached(row.clear), reached(row.cfg), row.showIf)
+			want := expect[level]
+			switch {
+			case row.err != nil:
+				t.Errorf("%s: the adapter's reply %q did not open a session: %v", level, attrs, row.err)
+			case !strings.Contains(row.identity, want.identity):
+				t.Errorf("%s: the device reports %q, the adapter promises %q", level, row.identity, want.identity)
+			case row.clear != want.clearReached || row.cfg != want.cfgReached:
+				t.Errorf("%s: clear counters reached port49 %v (want %v), configure terminal %v (want %v)", level,
+					row.clear, want.clearReached, row.cfg, want.cfgReached)
+			}
+		}
+		fmt.Fprintf(&obs, "\n### Inert candidates, each beside admin's reply\n\n"+
+			"| attribute | session | identity | `clear counters` | `configure terminal` | `show version` | inert |\n"+
+			"|---|---|---|---|---|---|---|\n")
+		admin, _ := d.Render("admin")
+		adminRow := l.adapterVariant(t, "admin-control", admin)
+		for _, a := range inertCandidates {
+			row := l.adapterVariant(t, "inert-"+strings.SplitN(a, "*", 2)[0], append(slices.Clone(admin), a))
+			// Inert only where nothing about the session moved: opened, admin's
+			// identity, admin's reach, and a command still authorized.
+			inert := row.err == nil && row.identity == adminRow.identity && row.clear == adminRow.clear &&
+				row.cfg == adminRow.cfg && row.showVersion
+			fmt.Fprintf(&obs, "| `%s` | %s | %s | %s | %s | %s | %s |\n", a, row.session, row.identity,
+				reached(row.clear), reached(row.cfg), permitted(row.showVersion), yesNo(inert))
+			if row.err != nil && l.p.name == "cisco_iosxe" {
+				// A refused session stops this image answering SSH for about a
+				// minute (L18); wait it out before the next variant.
+				if err := l.waitDeviceReady(3 * time.Minute); err != nil {
+					t.Fatalf("after %s: %v", a, err)
+				}
+			}
+		}
+		fmt.Fprintf(&obs, "\n### Fallback: port49d stopped under an open session\n\n"+
+			"| level | reply | `configure terminal`, then `hostname %s` | transcript after port49d stopped |\n"+
+			"|---|---|---|---|\n", l.p.node)
+		for _, level := range []string{"operator", "admin"} {
+			attrs, _ := d.Render(level)
+			fb := l.fallbackVariant(t, level, attrs)
+			fmt.Fprintf(&obs, "| %s | `%s` | %s | `%s` |\n", level, strings.Join(attrs, "`, `"), fb.outcome(),
+				strings.ReplaceAll(fb.transcript, "\n", " ⏎ "))
+			switch {
+			case fb.err != nil:
+				t.Errorf("fallback %s: %v", level, fb.err)
+			case level == "operator" && fb.changed:
+				t.Errorf("fallback: an operator changed the configuration with port49 down; decision 25 says the "+
+					"role it was given refuses it (L16, command authorization LOCAL):\n%s", fb.transcript)
+			case level == "admin" && !fb.changed && l.p.name != "cisco_iosxe":
+				// The control: network-admin configures under local
+				// authorization, or the operator's refusal measured nothing.
+				t.Errorf("fallback control: admin could not change the configuration either, so the operator's "+
+					"refusal says nothing about its role:\n%s", fb.transcript)
+			}
+		}
+		l.result(t, "L22", "Each built-in adapter's reply at readonly, operator and admin is applied by the "+
+			"device as the adapter says — the privilege or role the device reports, and which of `clear counters` "+
+			"and `configure terminal` it sends port49 at all; which candidate inert attributes leave admin's "+
+			"session unchanged; and, with port49d stopped under an open session, that operator's reply cannot "+
+			"change the configuration where admin's can (plan 5a, Task 17; spec §6, §8, §15 L22; decision 25).",
+			obs.String())
+	})
+}
+
+// adapterRow is one variant's measurement.
+type adapterRow struct {
+	err              error
+	session          string
+	identity         string
+	clear, cfg       bool
+	showVersion      bool // a `show version` authorize_command was permitted
+	clearOut, cfgOut string
+	// showIf is the first line of NX-OS's reply to a bare `show interface`,
+	// "—" elsewhere.
+	showIf string
+}
+
+func reached(b bool) string {
+	if b {
+		return "sent to port49"
+	}
+	return "refused by the device"
+}
+
+func permitted(b bool) string {
+	if b {
+		return "permitted by port49"
+	}
+	return "not permitted"
+}
+
+func yesNo(b bool) string {
+	if b {
+		return "yes"
+	}
+	return "no"
+}
+
+// adapterVariant restarts port49d delivering attrs, logs in with a fresh
+// seeded token, and runs the identity command and the two ceiling commands.
+func (l *lab) adapterVariant(t *testing.T, name string, attrs []string) adapterRow {
+	t.Helper()
+	quoted, _ := json.Marshal(attrs)
+	cfg, err := l.derivedConfig("adapter-"+name, string(quoted), "")
+	if err != nil {
+		t.Fatal(err)
+	}
+	if err := l.restart(cfg); err != nil {
+		t.Fatalf("%s: port49d would not start: %v", name, err)
+	}
+	user, secret := l.nextLogin(t)
+	identity := "show privilege"
+	if l.p.name == "cisco_nxos" {
+		identity = "show user-account " + user
+	}
+	commands := []string{identity, "clear counters", "configure terminal", "show version"}
+	if l.p.name == "cisco_nxos" {
+		commands = append(commands, "show interface")
+	}
+	off := l.mark()
+	outs, err := l.login(user, secret, commands...)
+	recs := l.drainRecords(off, 3*time.Second)
+	row := adapterRow{err: err, session: "opened", showIf: "—"}
+	if err != nil {
+		row.session = "refused: " + err.Error()
+		return row
+	}
+	if len(outs) == 5 {
+		row.showIf = "`" + strings.TrimSpace(strings.Split(strings.TrimSpace(outs[4])+"\n", "\n")[0]) + "`"
+	}
+	if len(outs) >= 3 {
+		row.identity = strings.TrimSpace(strings.Split(strings.TrimSpace(outs[0]), "\n")[0])
+		if l.p.name == "cisco_nxos" {
+			for _, line := range strings.Split(outs[0], "\n") {
+				if strings.Contains(line, "roles:") {
+					row.identity = strings.TrimSpace(line)
+				}
+			}
+		}
+		row.clearOut, row.cfgOut = outs[1], outs[2]
+	}
+	for _, r := range recs {
+		if str(r, "event") != "authorize_command" {
+			continue
+		}
+		v := strs(sub(r, "request"), "vector")
+		switch {
+		case len(v) >= 2 && v[0] == "clear" && v[1] == "counters":
+			row.clear = true
+		case len(v) >= 2 && v[0] == "configure" && v[1] == "terminal":
+			row.cfg = true
+		case len(v) >= 2 && v[0] == "show" && v[1] == "version" && str(r, "verdict") == "permit":
+			row.showVersion = true
+		}
+	}
+	return row
+}
+
+// restart runs port49d on cfg.
+func (l *lab) restart(cfg string) error {
+	if err := l.stopDaemon(); err != nil {
+		return err
+	}
+	return l.startDaemonWith(cfg, true)
+}
+
+// fallbackRow is one fallback variant: whether the configuration change
+// took, and what the device printed after port49d stopped.
+type fallbackRow struct {
+	err        error
+	changed    bool
+	transcript string
+}
+
+func (f fallbackRow) outcome() string {
+	switch {
+	case f.err != nil:
+		return "not measured: " + f.err.Error()
+	case f.changed:
+		return "**accepted**"
+	}
+	return "refused"
+}
+
+// fallbackVariant delivers attrs, opens one interactive session, stops
+// port49d under it, and types `configure terminal` and `hostname <node>` —
+// the value the device already holds, as L16 did, so an accepted change
+// changes nothing. The device's command method list ends in local
+// (tests/lab/configs/*-startup.cfg), so with port49d gone it authorizes on
+// its own. The change took where the device printed no `%` error after the
+// hostname line and left configuration mode on `end`.
+func (l *lab) fallbackVariant(t *testing.T, level string, attrs []string) fallbackRow {
+	t.Helper()
+	quoted, _ := json.Marshal(attrs)
+	cfg, err := l.derivedConfig("fallback-"+level, string(quoted), "")
+	if err != nil {
+		t.Fatal(err)
+	}
+	if err := l.restart(cfg); err != nil {
+		t.Fatalf("fallback %s: port49d would not start: %v", level, err)
+	}
+	user, secret := l.nextLogin(t)
+	c, err := l.dial(user, secret, 45*time.Second)
+	if err != nil {
+		return fallbackRow{err: err}
+	}
+	defer c.Close()
+	s, err := c.NewSession()
+	if err != nil {
+		return fallbackRow{err: err}
+	}
+	defer s.Close()
+	if err := s.RequestPty("vt100", 40, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
+		return fallbackRow{err: fmt.Errorf("request pty: %w", err)}
+	}
+	stdin, err := s.StdinPipe()
+	if err != nil {
+		return fallbackRow{err: err}
+	}
+	var buf syncBuffer
+	s.Stdout, s.Stderr = &buf, &buf
+	if err := s.Shell(); err != nil {
+		return fallbackRow{err: fmt.Errorf("start shell: %w", err)}
+	}
+	typeLine := func(line string, wait time.Duration) {
+		_, _ = io.WriteString(stdin, line+"\r")
+		time.Sleep(wait)
+	}
+	typeLine("", 3*time.Second)
+	if err := l.stopDaemon(); err != nil {
+		return fallbackRow{err: err}
+	}
+	mark := buf.Len()
+	// A down TACACS+ server is a refused connection, so the device moves to
+	// local at once; the waits are for the device's own prompt.
+	typeLine("configure terminal", 5*time.Second)
+	typeLine("hostname "+l.p.node, 5*time.Second)
+	afterHostname := buf.Len()
+	typeLine("end", 3*time.Second)
+	typeLine("exit", 2*time.Second)
+	stdin.Close()
+	out := buf.String()
+	hostnameOut := out[mark:afterHostname]
+	if i := strings.Index(hostnameOut, "hostname "+l.p.node); i >= 0 {
+		hostnameOut = hostnameOut[i:]
+	}
+	return fallbackRow{changed: strings.Contains(out[mark:afterHostname], "(config)#") &&
+		!strings.Contains(hostnameOut, "%"), transcript: strings.TrimSpace(out[mark:])}
+}
+
+// syncBuffer is a bytes.Buffer the SSH session writes from its own
+// goroutine while the test reads it.
+type syncBuffer struct {
+	mu sync.Mutex
+	b  bytes.Buffer
+}
+
+func (b *syncBuffer) Write(p []byte) (int, error) {
+	b.mu.Lock()
+	defer b.mu.Unlock()
+	return b.b.Write(p)
+}
+
+func (b *syncBuffer) Len() int {
+	b.mu.Lock()
+	defer b.mu.Unlock()
+	return b.b.Len()
+}
+
+func (b *syncBuffer) String() string {
+	b.mu.Lock()
+	defer b.mu.Unlock()
+	return b.b.String()
+}
````

<!-- patch: tests/lab/slice_test.go -->
````diff
diff --git a/tests/lab/slice_test.go b/tests/lab/slice_test.go
index 2cd0b8c..4a6fbcd 100644
--- a/tests/lab/slice_test.go
+++ b/tests/lab/slice_test.go
@@ -28,8 +28,9 @@ import (
 // authorization is answered from the blob the mint compiled. A second window
 // asks for a second token and gets a fresh one.
 //
-// vEOS only: the slice renders session attributes for arista_eos alone (plan 3,
-// Decided 6), and a login elsewhere would measure plan 5's missing adapter.
+// The per-command platforms: plan 5a's adapters render a level on vEOS, the
+// N9Kv and IOS-XE (tests/lab/results/L22-*.md). Junos renders nothing
+// until plan 5b's projection, so a login there would measure a missing adapter.
 
 const (
 	sliceUser      = "slice01"
@@ -37,9 +38,14 @@ const (
 	slicePrincipal = "user:" + sliceEmail
 	slicePKIDir    = "tests/lab/logs/slice-pki"
 	sliceBrokerURL = "https://127.0.0.1:8449"
-	sliceDenied    = "show hostname"
 )
 
+// sliceDenied is the command the slice's policy denies and nothing else does,
+// per platform: IOS-XE has no `show hostname`, and an unknown word there is
+// refused in the parser without asking port49 (ceiling-cisco_iosxe.md).
+var sliceDenied = map[string]string{"arista_eos": "show hostname", "cisco_nxos": "show hostname",
+	"cisco_iosxe": "show users"}
+
 const sliceClaim = "The vertical slice end to end: an operator's client certificate, validated by the broker " +
 	"against one trust anchor, mints a device token over a held mTLS connection (`port49 login`, `port49 token`); " +
 	"the token logs into the device; every authorization is answered from the compiled blob the mint wrote; and a " +
@@ -49,8 +55,9 @@ var agentPID = regexp.MustCompile(`agent pid (\d+)`)
 
 func TestSliceEndToEnd(t *testing.T) {
 	eachPlatform(t, func(t *testing.T, l *lab) {
-		if l.p.name != "arista_eos" {
-			t.Skipf("the slice renders session attributes for arista_eos only (plan 3, Decided 6); %s waits for plan 5", l.p.name)
+		denied, ok := sliceDenied[l.p.name]
+		if !ok {
+			t.Skipf("%s renders no level until plan 5b's projection", l.p.name)
 		}
 		port49 := filepath.Join(root, "bin", "port49")
 		if _, err := os.Stat(port49); err != nil {
@@ -106,14 +113,14 @@ func TestSliceEndToEnd(t *testing.T) {
 		}
 		defer stopSliceAgent(t, string(out))
 
-		tok1 := sliceToken(t, port49, sock)
-		outs, err := l.login(sliceUser, tok1, "show version", sliceDenied)
+		tok1 := sliceToken(t, port49, sock, l.p.node)
+		outs, err := l.login(sliceUser, tok1, "show version", denied)
 		if err != nil {
 			t.Fatalf("SSH login as %s with the broker-minted token failed: %v\nrecords:%s", sliceUser, err, summarize(l.recordsSince(off)))
 		}
 		// A second window is a second device connection, and it gets a fresh
 		// mint (plan 3, Decided 11).
-		tok2 := sliceToken(t, port49, sock)
+		tok2 := sliceToken(t, port49, sock, l.p.node)
 		if tok2 == tok1 {
 			t.Fatal("port49 token handed back a token it had already handed out")
 		}
@@ -135,7 +142,7 @@ func TestSliceEndToEnd(t *testing.T) {
 				t.Fatalf("a minted token is in %s", path)
 			}
 		}
-		obs, err := sliceObservation(recs, []string{tok1, tok2}, outs)
+		obs, err := sliceObservation(recs, []string{tok1, tok2}, outs, denied, l.p.node)
 		if err != nil {
 			t.Fatalf("%v\nrecords:%s", err, summarize(recs))
 		}
@@ -144,15 +151,15 @@ func TestSliceEndToEnd(t *testing.T) {
 	})
 }
 
-func sliceToken(t *testing.T, port49, sock string) string {
+func sliceToken(t *testing.T, port49, sock, device string) string {
 	t.Helper()
-	cmd := exec.Command(port49, "token", "--socket", sock, "leaf1")
+	cmd := exec.Command(port49, "token", "--socket", sock, device)
 	var stderr strings.Builder
 	cmd.Stderr = &stderr
 	out, err := cmd.Output()
 	tok := strings.TrimSpace(string(out))
 	if err != nil || len(tok) != labcreds.TokenLen {
-		t.Fatalf("port49 token leaf1: %v, %d characters on stdout; stderr: %s", err, len(tok), stderr.String())
+		t.Fatalf("port49 token %s: %v, %d characters on stdout; stderr: %s", device, err, len(tok), stderr.String())
 	}
 	return tok
 }
@@ -192,7 +199,7 @@ func sha(s string) string {
 // sliceObservation checks the chain the slice exists to show and renders it.
 // Every link is read off a record; a missing link fails the test, because a
 // run that did not produce it measured something else.
-func sliceObservation(recs []map[string]any, tokens []string, outs []string) (string, error) {
+func sliceObservation(recs []map[string]any, tokens []string, outs []string, sliceDenied, device string) (string, error) {
 	mints := sliceRecords(recs, "mint", "grants_matched")
 	if len(mints) < 2 {
 		return "", fmt.Errorf("want two permitted mints for %s, got %d", slicePrincipal, len(mints))
@@ -241,9 +248,9 @@ func sliceObservation(recs []map[string]any, tokens []string, outs []string) (st
 	}
 
 	var b strings.Builder
-	fmt.Fprintf(&b, "Two `port49 token leaf1` calls over one `port49 login` session minted two different tokens for "+
+	fmt.Fprintf(&b, "Two `port49 token %s` calls over one `port49 login` session minted two different tokens for "+
 		"principal `%s`, username `%s`, each on its own `mint` record naming blob `%s`. The `blob` event carried it:\n\n"+
-		"```json\n%s\n```\n\n", slicePrincipal, sliceUser, hash, blobBody)
+		"```json\n%s\n```\n\n", device, slicePrincipal, sliceUser, hash, blobBody)
 	b.WriteString("Every record for `slice01` in the run, in order (tokens appear as the hash the log carries):\n\n")
 	b.WriteString("| event | verdict | reason | ctx_id | port | credential_sha256 / vector |\n|---|---|---|---|---|---|\n")
 	for _, r := range recs {
````

<!-- patch: tests/lab/slice/policy.yaml -->
````diff
diff --git a/tests/lab/slice/policy.yaml b/tests/lab/slice/policy.yaml
index 41927c9..49e1a86 100644
--- a/tests/lab/slice/policy.yaml
+++ b/tests/lab/slice/policy.yaml
@@ -1,7 +1,8 @@
 # The vertical slice's lab policy (plan 3). One subject: the client certificate
 # `go run ./tests/lab/cmd/slice-pki` cuts. It may do everything on every device
 # except one command, so the end-to-end run can show a permit and a denial that
-# only the compiled blob could have made: `show hostname` is in no deny list in
+# only the compiled blob could have made: `show hostname` (and `show users`, the
+# IOS-XE stand-in, which has no `show hostname`) is in no deny list in
 # port49d-lab.yaml, so a denial of it cannot have come from the lab authorizer.
 #
 # `slice01` is a username no seed uses, so nothing but a broker-minted token can
@@ -12,7 +13,7 @@ scopes:
   - {name: all_devices, match: {}}
 roles:
   - {name: network_admin, privilege: admin, permit: ["**"]}
-  - {name: slice_denies, deny: ["show hostname"]}
+  - {name: slice_denies, deny: ["show hostname", "show users"]}
 subjects:
   - {name: slice_operator, identity: ["user:alice@slice.port49.test"], username: slice01,
      enable: token, token_ttl: 60s}
````

- [ ] **Step 2: Check it compiles, off the lab host**

Run: `go vet -tags lab ./tests/lab/... && make test`
Expected: clean; every package `ok`.

- [ ] **Step 3: Run it on the lab host**

Run:
```bash
make build
PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/... -count=1 -v -timeout 120m -run 'TestAdapterReplies|TestSliceEndToEnd'
PORT49_LAB_PLATFORMS=nxos go test -tags lab ./tests/lab/... -count=1 -v -timeout 120m -run 'TestAdapterReplies|TestSliceEndToEnd'
PORT49_LAB_PLATFORMS=iosxe go test -tags lab ./tests/lab/... -count=1 -v -timeout 120m -run 'TestAdapterReplies|TestSliceEndToEnd'
make evidence
```
Expected: `PASS` for both tests on each platform, and `tests/lab/results/L22-<platform>.md`
written for each, with a table whose rows are Decided 5's and `adapterExpect`'s, an "Inert
candidates" table with an `inert` column, and a "Fallback" table in which operator's change is
refused and, on EOS and NX-OS, admin's is accepted. Keep the raw
captures in `tests/lab/captures/` until the evidence is committed: the `labpcap` audit reads them,
so a lab run in a worktree copies its raw captures to the main checkout before the worktree is
removed.

If a level or the fallback fails, stop: do not edit `adapterExpect` or the fallback's judgement
to match. Bring the note to review; the adapter (or decision 25) changes, with the note cited,
before Task 18.

- [ ] **Step 4: Commit the test, the notes and the evidence**

```bash
git add tests/lab/adapters_test.go tests/lab/slice_test.go tests/lab/slice/policy.yaml \
  tests/lab/results/L22-*.md tests/lab/results/slice-*.md tests/lab/evidence/L22-*.pcap \
  tests/lab/evidence/slice-*.pcap
git commit -m "test: the per-command adapters' replies, measured in the lab (L22)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 18: Close L22, mark the adapters verified, list what the lab showed inert

**Files:**
- Modify: `platforms/1.0.0/{arista_eos,cisco_nxos,cisco_iosxe}.yaml` (`verified`; `inert_attributes`
  and, on IOS-XE, `accepted_attributes` as the notes show)
- Modify: `internal/platform/adapter_test.go` (`shipped`), `cmd/port49/platform_test.go`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L22 and L10; decision 25)
- Modify: `docs/superpowers/plans/README.md` (plan 5a as built)

**Interfaces:** none new. `port49 platform list` prints `containerlab` for each adapter the notes
verify.

This task is written for the outcome Task 17 is built to confirm — every level on every platform
as the adapter says, and the fallback refusing operator's configuration change. The code part below is that case, and was run green. For a platform whose
note disagrees, leave its `verified` unset (drop its hunk and its `shipped` line) and say which
row disagreed in the PR body.

- [ ] **Step 1: Mark the verified adapters, and the test that shows it**

<!-- patch: cmd/port49/platform_test.go -->
````diff
diff --git a/cmd/port49/platform_test.go b/cmd/port49/platform_test.go
index f485e2f..9273748 100644
--- a/cmd/port49/platform_test.go
+++ b/cmd/port49/platform_test.go
@@ -19,7 +19,8 @@ func TestPlatformListSaysWhereEachAdapterComesFrom(t *testing.T) {
 	var out, errb bytes.Buffer
 	if code := run([]string{"platform", "list"}, &out, &errb); code != 0 ||
 		!strings.HasPrefix(out.String(), "PLATFORM") || strings.Count(out.String(), "built-in") != 4 ||
-		listRow(out.String(), "juniper_junos") != "juniper_junos built-in — session" {
+		listRow(out.String(), "juniper_junos") != "juniper_junos built-in — session" ||
+		listRow(out.String(), "cisco_iosxe") != "cisco_iosxe built-in containerlab session,commands" {
 		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
 	}
 	pol, inv := policyFixture(t)
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index fc778c9..5e992d7 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -28,6 +28,7 @@ var shipped = map[string]Dialect{
 		InertAttributes:     []string{"home-directory"},
 		EnableUsername:      EnablePrincipal,
 		DeviceConfig:        []string{"aaa authorization commands all default group port49 local"},
+		Verified:            "containerlab", // tests/lab/results/L22-arista_eos.md
 		// ceiling-arista_eos.md; L16-arista_eos.md, command authorization LOCAL.
 		Unreachable: map[string][]string{"readonly": {"clear counters **", "clear ip bgp **", "configure terminal **",
 			"show users detail **"}},
@@ -54,6 +55,7 @@ var shipped = map[string]Dialect{
 		EnableUsername:      EnablePrincipal,
 		DeviceConfig: []string{"aaa authorization commands default group port49 local",
 			"aaa authorization config-commands default group port49 local"},
+		Verified:      "containerlab", // tests/lab/results/L22-cisco_nxos.md
 		Fallback:      map[string]string{"admin": "network-admin: every command, configuration included"},
 		LocalAccounts: []string{`^username (\S+)`},
 		ConfigChecks: []ConfigCheck{
@@ -75,6 +77,7 @@ var shipped = map[string]Dialect{
 			"aaa authorization commands 7 default group port49 local",
 			"aaa authorization commands 15 default group port49 local",
 			"aaa accounting commands 7 default start-stop group port49", "privilege exec level 7 clear counters"},
+		Verified: "containerlab", // tests/lab/results/L22-cisco_iosxe.md
 		Unreachable: map[string][]string{"readonly": {"clear counters **", "clear ip bgp **", "configure terminal **"},
 			"operator": {"clear ip bgp **", "configure terminal **"}},
 		Fallback:      map[string]string{"admin": "level 15: every command, configuration included"},
````

<!-- patch: platforms/1.0.0/arista_eos.yaml -->
````diff
diff --git a/platforms/1.0.0/arista_eos.yaml b/platforms/1.0.0/arista_eos.yaml
index 42a2b8e..2159842 100644
--- a/platforms/1.0.0/arista_eos.yaml
+++ b/platforms/1.0.0/arista_eos.yaml
@@ -3,6 +3,10 @@
 # direction that fails closed (spec §8, §15).
 platforms:
   arista_eos:
+    # Every reply this adapter renders was applied by the lab image as the
+    # adapter says, at readonly, operator and admin
+    # (tests/lab/results/L22-arista_eos.md; spec §15, L22).
+    verified: containerlab
     # Session and per-command authorization (L1, L10). Config-command
     # authorization is unmeasured, so it is not claimed.
     supports: [session, commands]
````

<!-- patch: platforms/1.0.0/cisco_iosxe.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_iosxe.yaml b/platforms/1.0.0/cisco_iosxe.yaml
index 5477d53..7794da8 100644
--- a/platforms/1.0.0/cisco_iosxe.yaml
+++ b/platforms/1.0.0/cisco_iosxe.yaml
@@ -3,6 +3,10 @@
 # direction that fails closed (spec §8, §15).
 platforms:
   cisco_iosxe:
+    # Every reply this adapter renders was applied by the lab image as the
+    # adapter says, at readonly, operator and admin
+    # (tests/lab/results/L22-cisco_iosxe.md; spec §15, L22).
+    verified: containerlab
     # Session and per-command authorization (L1, L10). Config-command
     # authorization is unmeasured, so it is not claimed.
     supports: [session, commands]
````

<!-- patch: platforms/1.0.0/cisco_nxos.yaml -->
````diff
diff --git a/platforms/1.0.0/cisco_nxos.yaml b/platforms/1.0.0/cisco_nxos.yaml
index ae58461..20a8530 100644
--- a/platforms/1.0.0/cisco_nxos.yaml
+++ b/platforms/1.0.0/cisco_nxos.yaml
@@ -3,6 +3,10 @@
 # direction that fails closed (spec §8, §15).
 platforms:
   cisco_nxos:
+    # Every reply this adapter renders was applied by the lab image as the
+    # adapter says, at readonly, operator and admin
+    # (tests/lab/results/L22-cisco_nxos.md; spec §15, L22).
+    verified: containerlab
     # Session and per-command authorization (L1, L10). Config-command
     # authorization is unmeasured, so it is not claimed.
     supports: [session, commands]
````

- [ ] **Step 2: List inert only what the notes show inert**

For each candidate in a note's "Inert candidates" table whose `inert` column says `yes` — the
session opened with admin's identity, both ceiling commands reached port49 as admin's did, and
`show version` was permitted — add the attribute's name to that platform's `inert_attributes`,
and on `cisco_iosxe` to `accepted_attributes` too, with the note cited on the line above — for
example, if `L22-arista_eos.md` shows `idletime*30` inert:

```yaml
    # home-directory: spec §6's case. idletime: admin's session unchanged beside its reply
    # (tests/lab/results/L22-arista_eos.md, "Inert candidates").
    inert_attributes: [home-directory, idletime]
```

and in `internal/platform/adapter_test.go`'s `shipped` the same list. A candidate whose `inert`
column says `no` — refused, a changed identity, a changed reach, or commands no longer authorized
— is not inert and is not listed; on IOS-XE it also stays out of `accepted_attributes`, since
there one attribute under `all:` would reach the whole fleet (pre-flight S6). `home-directory` stays listed on every platform whatever
its row shows (it is spec §6's seeded case and already inert); if IOS-XE refused it, add that
finding to the IOS-XE file's comment, since IOS-XE's closed list already quarantines a reply that
carries it.

- [ ] **Step 3: Close the row**

In spec §15, replace L22's status cell with (dates from the notes' **Date measured** lines):

```
closed — measured <date in the notes>; tests/lab/results/L22-arista_eos.md, L22-cisco_nxos.md, L22-cisco_iosxe.md. Each built-in adapter's reply at readonly, operator and admin was applied as the adapter says: on vEOS level 1 then 15 with network-operator, network-operator and network-admin; on the N9Kv network-operator, network-operator, network-admin, every ceiling command sent to port49; on IOS-XE 17.13.01a levels 1, 7 and 15, level 7 sending `clear counters` and refusing `configure terminal` in the parser. With port49d stopped under an open session and the method list falling back to local, operator's reply could not change the configuration on any of the three, and admin's could on vEOS and the N9Kv. By hand 2026-09-24: tests/lab/results/ceiling-*.md
```

Decision 25's provisional marker comes off only for what was measured. Where every level row and
the fallback agree, delete the sentence beginning `*Provisional on L22*` whole. Where the level
rows agree and the fallback disagreed or could not be measured, L22 stays open and says so, and
the sentence becomes `*Provisional on L22* for the outage half: operator's reply with port49
stopped under an open session is <not yet measured | measured changing the configuration on
<platform>, tests/lab/results/L22-<platform>.md>.` In L10's status cell, append: `The three
per-command adapters' spellings are measured by plan 5a (tests/lab/results/L22-*.md); Junos's wait
on L12 (plan 5b), so the row stays open.` If a platform's level rows disagreed, L22 stays open and
says which, and decision 25 stays provisional whole.

- [ ] **Step 4: Write the roadmap's as-built paragraph**

In `docs/superpowers/plans/README.md`, in the Plan 5 section's "Plan 5a" bullet, replace
"Written 2026-09-24; not yet executed." with "As built (PR #N):" and follow the bullet with one
paragraph naming what shipped where it differs from the plan's Decided list, the adapters marked
verified, the inert attributes listed, and anything a reviewer carried to 5b. In the status line,
replace "**5a written 2026-09-24** (… not yet executed)" with "**5a merged <date>** (PR #N; …)"
and say plan 5b is the next plan to write.

- [ ] **Step 5: Run everything, and commit twice**

Run: `make test && make vet && go vet -tags lab ./tests/lab/...`
Expected: every package `ok`.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entry L22; decision 25 no longer provisional

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
git add platforms internal cmd docs/superpowers/plans/README.md
git commit -m "feat: the per-command adapters are verified in containerlab

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Self-review against the spec and the roadmap

| Owed | Task |
|---|---|
| Built-in adapters, `platforms/*.yaml`, introspectable (§8) | 2, 12 |
| Exact measured reply shapes per platform (roadmap "Inherits from the lab") | 3, 4, 5; lab 17 |
| IOS-XE operator at 7 with `privilege exec level 7 …` in the reference config (plan 4 hand-off) | 4, 5 |
| Entity classes; user overrides and layering; `replace`, `based_on` (§8) | 2, 7 |
| `(?-i)` in an operator's class a deny names (plan 4 hand-off) | 7 |
| Pinned platform set; `platform upgrade`; override drift (§8, §12) | 6, 13, 7 |
| `redact` — MUST land here (§5.8) | 10, 11 |
| `port49 platform export` (§8) | 12 |
| Editable adapters: stricter `BearsPrivilege`; gate on privilege-bearing and inert lists (review M8) | 9 |
| N5: offline tools and the enable username (plan 4 pre-flight) | 8 |
| Local-account collision check (plan 2b owed; §5.6) | 15 |
| Dead-rule and fallback-exposure checks (§12; plan 4 owed) | 14 |
| Opening the pull request `grants remove` prepares (owner's ruling 2026-09-24) | 16 |
| Inert-attribute lists beyond `home-directory` | 17, 18 (measured, never assumed) |
| Differential testing in containerlab | 17 (per-command); the projection's is 5b |
| Capability inference §9; Junos projection, L9, L12; `bits`, `bit_delivery`, `command_projection` | **5b** |

## Pre-flight rulings folded in (2026-09-24)

The pre-flight report is `.superpowers/sdd/2026-09-24-05a-platform-adapters/preflight-report.md`;
every ruling below was accepted by the owner's lead and is in the tasks as written.

| Finding | Ruling | Where |
|---|---|---|
| B1 decision 25's outage half unmeasured | Task 17 measures it (fallback variant, admin control); L22's question includes it; Task 18 lifts the provisional marker only for what was measured | Tasks 1, 17, 18 |
| B2 adapter gate blind to platforms with no device | `comparison.adapters` covers every platform either version has an adapter for | Tasks 1, 9 |
| S1 `redact` only reported | `redact` is gated; a wildcard-only `match` with `from` is refused | Tasks 1, 10 |
| S2 redaction gaps | a platform's list adds to `default`; `message-digest-key`, SNMPv3 `auth`, Junos `authentication-password`, `privacy-password`; one real line per vendor tested | Tasks 1, 10 |
| S3 pin misses the generic adapter and later releases | `TestEveryReleasedSetIsFrozen` (keyed by version), `TestTheGenericAdapterIsFrozen` | Tasks 1, 2, 8 |
| S4 `enable_username: principal` stops port49d | loads with a start notice; other values refused | Tasks 1, 8 |
| S5 `--pr` branches off HEAD | cut from the fetched base; a file differing from the base's refused; `-`-leading `--remote`/`--base` refused | Tasks 1, 16 |
| S6 inert judged on "opened" alone | inert needs admin's identity and reach and a permitted `show version` | Tasks 17, 18 |
| S7 results not named for L22 | `L22-<platform>.md`, `L22-*.pcap` | Tasks 1, 17, 18 |
| S8 a rendered attribute listable inert | `Validate` refuses it, and `priv-lvl` | Tasks 1, 2, 9 (test moved to NX-OS `cisco-av-pair`) |
| S9 check-config passes a short read | `ReadConfig` returns the scanner's error; exit 1 | Task 15 |
| N2 raw and vector redacted apart | `RedactRecord`: the missed form loses every argument | Tasks 1, 11 |
| N3 NX-OS accounting `cmd` | the patterns lead with `**`, said in §5.8 and `redact.yaml`, tested | Tasks 1, 10 |
| N4 mandatory `roles=` on EOS | operator note below | — |
| N6 exec channel vs interactive | Task 17's prose and note name the transport | Task 17 |
| N7 `all` / `default` as platform names | refused | Tasks 1, 7 |
| N8 `redactorFor` split a doc comment | moved above it | Task 11 |
| N9 credential in git's error text | `withoutCredentials` | Task 16 |

Skipped, with the reason: **N1** (a minimum abbreviation length) removes *less* on the platforms
that send what was typed, so a typed `pa` for `password` would leak — the opposite of failing
closed. **N5** is already the first operator note. **N11** is a false positive in the closed
direction; making the gate look past a redact-only edit would loosen it. **N10** and **N12** asked
for nothing.

## Questions for Ryan

One call, with the recommendation the plan implements as written. Nothing else in 5a needed you:
every other choice is the security-first default, argued in "Decided".

1. **An operator's device role is readonly's (`network-operator`) on EOS and NX-OS.** While port49
   answers it changes nothing — the operator is at 15 and port49's rules are the fence (decision
   23). When port49 cannot answer and the method list falls back to `local`, it is the whole
   policy: the operator can read and cannot configure, and may not be able to run the
   non-disruptive state changes the `operator` rung exists for (whether `network-operator` runs
   `clear counters` under local authorization is unmeasured). The alternative, `network-admin`,
   keeps the operator working through an outage and hands them configuration while nothing checks
   it. *Recommendation:* `network-operator` (decision 25). An outage is when nothing else fences a
   session, and a custom role that carries exactly the rung is a device-configuration change an
   operator can make and override in a `platforms:` block today.

## Operator-facing notes (for the PR body)

- **Rendering changes once, at this upgrade, and never again without a pin.** EOS gains
  `roles=` beside `priv-lvl`; NX-OS is told `shell:roles*network-operator` or `network-admin`
  (sessions used to land on `vdc-operator`); IOS-XE is told `priv-lvl` 1, 7 or 15 (it used to be
  told nothing and land at 1). A policy with no `platform_set:` renders with 1.0.0 forever.
- **IOS-XE operators need device configuration:** `aaa authorization commands 7 default group
  <port49-group> local` and `privilege exec level 7 clear counters` (and any other level-7
  command). `port49 platform show cisco_iosxe` prints the lines. Without them an operator is level
  1.
- **IOS-XE takes `priv-lvl` and nothing else.** A role or grant attribute that reaches an IOS-XE
  device quarantines it; key such attributes to the platforms that read them.
- **Adapters are editable** in the policy file's `platforms:` block; `port49 platform list`, `show`,
  `export`, `upgrade`. An edit to a key the gate reads needs an `acknowledge: {platform, field,
  reason}` entry for `policy diff` to pass.
- **`port49d.yaml` `platforms.<name>.enable_username` has moved** to the policy file. `principal`
  still starts, with a notice at start; any other value does not. Delete the line.
- **Typed secrets are redacted** in authorization and accounting records (`"redacted": true`);
  `policy replay` reports such records `unverifiable`. Built-in patterns in
  `platforms/redact.yaml`; add more under `platforms.<name>.redact` — an edit there is gated in
  `policy diff` like a rendering, because it changes what the audit keeps.
- **EOS is sent `roles=` in its mandatory form.** An EOS release that cannot parse `roles` refuses
  every login on that platform, and no local fallback follows, because port49 answered; measured
  fine on vEOS 4.31.2F. Try one device of each EOS release before the fleet.
- **New reports in `policy test`:** `dead_rule`, `fallback_exposure`,
  `platform_override_redundant`. They report; they do not fail.
- **New commands:** `port49 devices check-config` (a device-local account colliding with a served
  username, forbidden method-list fallbacks), `port49 grants remove --pr` (cut from the remote's
  base, and refused where the checkout's policy file differs from it).
- **Lowering a level on EOS or NX-OS passes `policy diff`** as before, although the role in the
  reply changed with it.
- **Lab:** register row L22 (added, and closed by Task 18 if the run agrees); the three
  per-command adapters `verified: containerlab`.
