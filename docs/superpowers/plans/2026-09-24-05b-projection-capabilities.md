# Plan 5b: Session-Only Projection and Capability Inference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Junos session gets port49's rules for the first time. They are rendered into the session
reply as permission bits and command regexes, proven before sending not to let the device run
anything port49 denies, and measured on both Junos images. And port49 reads its own decision log to
say which devices ask it about commands at all.

**Architecture:** A new package, `internal/projection`, turns one composition's rules into a Junos
session reply under decision 22. Before returning the reply it proves it against a model of the
device built from the lab's measurements: engine programs over the rules and over each permission
bit's reach, read the way a login class reads them. `internal/policy` calls it from `compile` for
any platform whose adapter declares `command_projection`. The reply is then ordinary blob
attributes, so the daemon, `policy replay` and every offline tool carry it unchanged. The
projection ships in a new platform set, 1.1.0, so turning it on is a pin move that `port49 policy
diff` reviews. Another new package, `internal/capability`, reads the decision log to build spec
§9's supports-versus-observed matrix and its accounting reconciliation. A new `account_gap`
record, written by the accounting spool whenever it drops a record, qualifies both.

**Tech Stack:** Go 1.22+ (the module's own `go` line), the standard library, `gopkg.in/yaml.v3`
(already a dependency); containerlab on the lab host (beehive) for Tasks 2, 3, 4 and 18. No new
module dependencies.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §8 ("Projection for session-only
platforms" in full, the Fields table, "Knowing what is shipped"), §9 (capability inference), §5.6
("Where these controls do not reach", decision 21's lever), §5.7 (the event table), §5.8 (system
users), §12 (the gated adapter keys), §13 decisions 21 and 22, §15 L9, L10, L12 and the new L23,
L24 and L25. Roadmap `docs/superpowers/plans/README.md`, "Plan 5a — As built" and "Plan 5b".
The lab notes decide every value an adapter ships (`CLAUDE.md`, "The lab register is the source of
truth").

**Prerequisite:** plan 5a merged (PR #13). Branch `feature/session-projection` off `main` at
`444d7da`, or at the plan commit that adds this file.

## Questions for Ryan

None are open. Every place the design left a choice, this plan took the option that denies more,
and records it under Decided. Two of those decisions will be visible to anyone writing a Junos
policy, so they are listed here too:

- **A change to a Junos session reply fails `policy diff` until a `reply:` session test asserts
  the new reply.** This applies to a narrowing and to an edit that only changes rules. It is the
  owner's review C4 ruling ("the gate cannot read the direction of such a change, so it fails
  closed"), and now every rule edit that reaches a Junos composition changes the reply. The diff
  prints the test to add, the new reply included (Task 11). *Recommendation for later, not this
  plan:* judge a projected reply by its bits alone, a raise where a bit was added, and leave its
  regexes to the effective-permission diff. Soundness (Decided 3) makes that safe, but it is a
  change to a ruling and needs one.
- **One subject's refused composition quarantines the Junos device for every subject.** This is
  decision 20's rule for every joint check, and `policy diff` fails on the new quarantine before
  it ships. An admin role with any deny is one such composition (Decided 6).

## Why this plan exists, and what 5a left

Since plan 1 answered `junos-exec`, port49 has authorized Junos sessions without constraining
them: the session reply carries nothing, and each session lands in the device's own `remote`
template (`tests/lab/results/junos-session-service-juniper_vjunos-router.md`: "until it lands,
port49 does not constrain a Junos session at all"). Decision 22 says how rules become a reply.
L12 and L9 are the measurements it rests on, and both are open. Plan 5a split at this seam and
left Junos rendering nothing. It also carried three items here. The first is Junos's inert list
and spellings (L10, L12). The second is L22's inert candidates re-measured beside readonly's reply
on EOS and NX-OS (5a final review M3). The third is an NX-OS `vsh.bin` system user, if a note ever
measures one. The roadmap gives this plan decision 21's class `idle-timeout` and spec §9's
capability inference as well.

## Decided in this plan

1. **The projection ships in platform set 1.1.0; 1.0.0 is frozen.** A released set is never
   edited, and 1.0.0 was released when 5a merged. `platforms/1.1.0/` copies 1.0.0's EOS, NX-OS and
   IOS-XE files and gives `juniper_junos` the projection. `DefaultSet` becomes 1.1.0, so `platform
   show` and `export` default to it, and `UnpinnedSet` stays 1.0.0. A policy that pins no set
   therefore renders Junos exactly as today. `port49 platform upgrade --to 1.1.0` prints every
   key the move changes, all of them gated (Task 13's test), and 1.1.0 is frozen when this plan
   merges (Task 19). Every other outcome was worse. Shipping the projection unpinned would change
   every Junos session on a binary upgrade, which is the unreviewed policy change the pin exists
   to stop. Editing 1.0.0 would break its freeze.
2. **On a projected platform, `privilege:` is each level's ceiling in bits.** The field is
   `Dialect.CeilingBits`, and `Levels` stays nil, so no code path reads a bit name as an
   attribute. `Spec.Over` routes `privilege` by the merged `command_projection`, and `SpecOf`
   writes the bits back under `privilege`, so export, the diff and the round trip hold. Four keys
   are new: `command_projection` (`junos_regex` is the one value), `bits`, `bit_delivery` and
   `local_user_names`. Every one is gated in the diff automatically, because a key is gated until
   it is listed as reported. Over a set that projects, a block may not remove or change the
   projection. It may add a rule to a bit's reach, which only makes the generator trust the bit
   less, but never remove one or declare a bit the set does not (`keepsProjection`). An
   under-claimed reach is how a device would run what port49 denies.
3. **A reply is proven before it is sent.** The device model is L11's: a command runs where a
   matching allow beats every deny, or where the bits reach it and no deny matches. A bit's reach
   is read as a class reads it, so the most specific reach rule decides and `view-configuration`
   carves `show configuration **` out of `view`. The generator checks four obligations from the
   rules' terms (Task 5's `engine.Contains`, `MayMeet`, `AlwaysDominates`, `NeverDominates`):
   - a bit is sent only where every command it reaches is decided by one rule of the grant;
   - a permit is sent as an allow only where it dominates every deny it meets, and only within the
     level's ceiling bits, carve-outs counted;
   - a deny is left off the wire only where the bits already refuse everything it matches;
   - bits that enter configuration mode are sent only for a grant of every command (Decided 6).

   The same programs then decide one probe for each way the rules can be told apart
   (`engine.Probes`), and one the device would run and port49 would deny is a defect. Nothing is
   sent in that case. Where the device is narrower than port49, for example a permit beyond the
   level's bits, the result fails closed and is reported. A composition the checks cannot pass is
   a refusal: its device is quarantined through the existing joint check, and `policy test` and
   `policy diff` name why. This is spec §8's "Where equivalence cannot be established for a shape,
   CI MUST refuse the policy".
4. **The built-in adapter delivers bits by template (`local_user_name`) until L12 measures
   `user-permissions`.** The spec prefers `user_permissions`. L18, though, measured
   `user-permissions` changing nothing over a template whose class had bits
   (`tests/lab/results/L18-juniper_*.md`, variants 9 and 10), while `local-user-name` was applied
   under either flag. Task 13 switches the set to `user_permissions` only if Task 2's note shows
   it applied over a bitless template, both bits of a two-bit value applied, and per session. A
   reply naming a template the device lacks degrades to `remote` (L18, variant 7). The adapter's
   `device_config` therefore requires `remote` to use `p49-remote`, a class with no bits, and a
   `config_checks` entry flags that class carrying any. With both, a missing template runs
   nothing.
5. **The regex dialect is read in the direction that fails closed until L9 measures it**
   (`projection.JunosFacts`):
   - every regex has explicit `^` and `$`;
   - while the device matches case-sensitively, a deny's letters are written in both cases
     (`[sS][hH][oO][wW]`);
   - while a deny may be walked past by abbreviation (`sh conf`), no deny but `.*` is sent, so a
     capability shape that needs one goes narrow, and a grant the narrow shape cannot carry is
     refused;
   - words are printable ASCII with no `{`, `}`, `"` or `\`, and ERE operators are escaped;
   - regex and class patterns are carried only in the subset of RE2 that means the same in POSIX
     ERE.

   Task 2 measures each fact, and Task 13 sets `JunosFacts` from its note. Where the two images
   disagree, the fail-closed value is used. If explicit anchors are not taken, the projection
   does not ship at all (Task 13, Step 4).
6. **Bits that enter configuration mode go only to a grant of every command with no deny.** In
   configuration mode a statement is governed by the class's configuration permissions, and
   `deny-commands` does not reach it. `show` and `run` there are further paths around a command
   deny. So for any other composition, port49 could deny a statement the device then runs. An
   admin role with a deny on Junos is therefore refused, and its devices quarantined, until a
   later plan measures `deny-configuration` (carried). Task 2 measures whether `deny-commands`
   reaches a statement or `run`, so the note says whether this refusal is necessary or only
   cautious.
7. **A rule whose text carries a value redaction hides is never projected.** A Junos reply is
   the rules, and it is written whole to the `authorize_session` record and the blob event
   (§5.7). Such a composition is refused rather than having the secret logged. `rule_secret_literal`
   already reports those rules.
8. **No role or grant sets an attribute the projection renders.** The rule covers
   `local-user-name`, `user-permissions`, and the four command and four configuration regex
   families. It applies under a projected platform's key, and under `all` wherever a projected
   platform exists. It is a load error (spec §8, "Generator constraints" 1, 4 and the new 6).
9. **The reply gate is unchanged, and the diff also reports the projection.** Under the C4 ruling
   a reply change is judged whole (Questions). `policy diff` also prints a `projection:` line
   when a composition's shape, bits or template moved, as spec §8 asks ("any grant whose shape or
   bits changed").
10. **The ceiling is the projection's.** `exceeds` skips the projection's own attributes, since
    the generator renders them from the level's bits and never beyond them, so a `max_privilege`
    on Junos no longer quarantines. 1.1.0 numbers Junos's levels `{readonly: 1, operator: 15,
    admin: 15}`. Every Junos request carries priv_lvl 1
    (`junos-session-service-juniper_vjunos-router.md`), and operator is numbered as admin, as
    decision 23 does where the number fences nothing. Task 2 records the priv_lvl each variant's
    request carried.
11. **Operator's ceiling leaves out `reset`.** Spec §8's example gives operator `reset`, which
    restarts software processes. The owner's level definitions (2026-09-24) bind the adapters:
    operator is non-disruptive state changes and no configuration. 1.1.0's operator is `clear
    network trace view view-configuration`. Each bit's reach is a candidate that Task 3 verifies
    as an upper bound, and a failure widens it.
12. **Decision 21's idle-timeout is rendered by export, from `max_session_age`.** `port49
    platform export --classes --config port49d.yaml juniper_junos` prints the reference
    configuration: `device_config`, the bitless `remote` class, and each level's template and
    class. Every class carries `idle-timeout`, set to `session.max_session_age_default` in whole
    minutes rounded down. `config.MaxSessionAge` reads that key alone, with Load's default and its
    positivity rule, so no daemon secret is needed to run the export. L24 measures that the timer
    ends a session a reply landed in.
13. **Capability inference reads the decision log, and a gap in the accounting stream qualifies
    it.** `port49 devices capabilities` is offline, like `policy replay`. The spool now writes an
    `account_gap` record per stage for the records it drops, before the records that follow the
    drop (§5.7's ninth event, a report), so a reader of the log can tell "the device did not ask"
    from "we did not receive". A reconciliation finding in a window that has a gap is printed as
    possible and does not page. Spec §9's heuristics are fixed values: configuration entries
    followed by silence, over at least 5 entries and at least 80% of them. The join tests whether
    the accounting text holds the authorization's command. NX-OS's accounting `cmd` is a joined
    configuration path, so a shape the join does not expect reads as authorized, and the report
    under-reports rather than accuses. The CI half is the `unenforced_rules` finding.
14. **An NX-OS system user is keyed on its task_id, never on `admin` alone**, and it is added
    only if L25 reproduces the production record. Fleets name their break-glass account `admin`,
    so a name-only entry would attribute a person's local login `system` and hide it.
    `platform.SystemTasks` pairs the user with `^vsh\.bin\.[0-9]+$`. A `based_on:` variant does
    not get the pair, and reads such a record `unattributed`: an extra alarm, the safe direction.
15. **M3 is its own row.** L23 re-measures the inert candidates beside readonly's reply. If one
    moves the session, 1.1.0 lists it under that platform's `privilege_attributes`. Every shipped
    set's privilege attributes are unioned wherever the gate, the ceiling and the placeholder
    check ask (`platform.PrivilegeAttributeNames`), so a 1.0.0 pin is protected too, without
    editing 1.0.0.
16. **No new reason code and no new metric.** The new vocabulary is one event, `account_gap`,
    which is a report, three finding kinds (`projection`, `projection_overflow`,
    `unenforced_rules`), four adapter keys and one CLI command. Task 1 writes each into the spec
    first.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **After the upgrade, with no edit:** Junos sessions are unchanged, because an unpinned policy
  renders with 1.0.0. `policy test` newly prints `report: unenforced_rules: subject "noc" on
  juniper_junos (supports: session): its roles carry 3 command rules, and juniper_junos neither
  asks port49 about a command nor has them rendered into its session reply, so they decide
  nothing there (spec §9)`. That was true before this plan; now the report says so.
- **Turning the projection on, in this order.**
  1. Push the reference configuration to every Junos device: `port49 platform export --classes
     --config /etc/port49/port49d.yaml juniper_junos` prints the set lines.
  2. Check it: `port49 devices check-config` reports a device that lacks `tacplus-options
     strict-authorization` or `user remote class p49-remote` as MISSING.
  3. Move the pin: `port49 platform upgrade --to 1.1.0 --write`, then `policy diff`.

  The order matters. A device without the classes lands every session in its old `remote`
  template, whose bits the reply's regexes then decide over. A device without
  `strict-authorization` treats every port49 denial as advisory (L17).
- **A readonly role with a carve-out, before L9 has measured abbreviations:** `quarantine:
  srx-fw-04 (juniper_junos): subject "noc": on juniper_junos, permit "show **" (role "r") needs an
  allow-commands the device would let beat deny "show configuration **" (role "r"), which sits
  beneath it: Junos regex cannot write everything under a permit except a deny, ...` Under
  `user_permissions` the same carve-out renders as `user-permissions=view`, with the deny dropped
  because it aligns with the bit.
- **An admin with a deny on Junos:** `on juniper_junos the reply's bit all enters configuration
  mode, where a statement is governed by the class's configuration permissions and no command
  regex reaches it ... and the composition denies "request system reboot **" (role "admin"):
  port49 would deny what the device runs there`. The device is quarantined, and every login to it
  falls to its local accounts, exactly as in an outage.
- **`port49 explain` on a Junos command** notes what the device does under the reply: `under the
  session reply's projection (capability shape) the device refuses it; what it runs is its class ∩
  the wire, and the class half is the device's configuration, outside port49`.
- **`policy test`** prints each composition's projection (`report: projection: subject "noc" on
  juniper_junos: capability shape, template p49-readonly (bits view view-configuration); refused by
  the bits, sent as nothing: reload **`). A reply past 255 bytes prints `report:
  projection_overflow: ... set system login class p49-remote allow-commands "^(...)$"`, the
  workaround in the same report as the quarantine.
- **`policy diff` after a rule edit that reaches Junos:** `RAISES: s on srx-fw-04, ... reply
  [user-permissions=view view-configuration] -> [user-permissions=view]; no session test asserts
  it: add {subject: s, device: srx-fw-04, reply: [user-permissions=view]}`, and `projection: s on
  srx-fw-04, ...: capability (bits view view-configuration) -> capability (bits view)`.
- **At 3am, with a device that has no command authorization configured:** `port49 devices
  capabilities --policy policy.yaml --inventory inventory.yaml --since 24h
  /var/log/port49/decisions.jsonl` prints the matrix, then `⚠ UNAUTHORIZED TIER — leaf-04` with
  three example commands, and exits 1. If the spool dropped records in the window, the first line
  says so, the block reads `? POSSIBLY AN UNAUTHORIZED TIER`, and the command exits 0.
- **An NX-OS `admin` record with task_id `vsh.bin.28561`** (only if L25 reproduced it) is
  `attribution: system`. The same account logging in from a console or SSH carries
  `<addr>@pts/<n>` and stays `unattributed` or `foreign`.

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

Carried from plans 2–5a, and still binding:

- **Every claim about device behaviour cites a `tests/lab/results/` note or a register row**, in
  the adapter file beside the value it justifies. A claim cited to an open row is unmeasured; do not
  "fix" a doc to assert it (CLAUDE.md, lab register rules 1–4).
- **A released platform set is never edited.** 1.0.0 is released; 1.1.0 is released when this plan
  merges.
- **A blob fails closed; a quarantined device is closed without a reply; nothing logs a token.**
- **Every context write outside login goes through a narrow setter.** This plan writes no context.
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.

New in this plan:

- **Code is applied as written.** A whole new file is a diff from `/dev/null`, and a change to an
  existing file is a unified diff. Apply each with `git apply` from the repository root: save the
  block to a file, or pipe it. Every block was generated from a commit that went green against
  `444d7da`, in order, and the red step of every code task was run and fails as its Step 2 says. A
  hunk that does not apply means the tree is not where this plan expects: stop and say so, and do
  not edit by hand.
- **Every commit is preceded by `make test && make vet`**, and by `go vet -tags lab ./tests/lab/...`
  and `make build`. Report their real output.
- **Lab tasks follow "Running the lab" below:** a deadline on every SSH or pty read, where expiry
  is "not observed" and fails the test and is never a pass; the harness's boot budget per image;
  and a stall watchdog run by the controller for the whole run.
- **No new dependencies.** Branch `feature/session-projection`; never commit code to `main`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

## Running the lab (Tasks 2, 3, 4 and 18)

The lab is beehive's containerlab, and it holds one run at a time. The owner has given standing
consent for lab runs. Images on hand: vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15, Nexus 9300v
10.4(2)F and vEOS-lab 4.31.2F. A vJunosEvolved image is on the host but not in the harness, and
this plan does not measure it.

**One platform per `go test` run, one test per run.** The harness seeds 16 token logins per
platform per run (`tokenPoolSize`), and Task 2 spends exactly 16. The `make lab` loop is not used
here. Each run:

```bash
make build
PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^TestL12JunosWire$' -count=1 -v -timeout 90m \
  > tests/lab/logs/l12-wire-vjunos.log 2>&1 &
echo $! > tests/lab/logs/l12-wire-vjunos.pid
```

**Boot budgets are the harness's** (`platforms` in `tests/lab/harness_test.go`): vJunos-router
8 min, vSRX 6 min, N9Kv 15 min, vEOS 6 min, and then up to 8 min for the device to speak TACACS+
(`tacacsReadyBudget`). A device that misses its budget fails the run. Do not raise a budget to make
a run pass. The harness's own comment says the budgets are a property of the host: measure the boot
and change the number only if the host has changed.

**Every read has a deadline.** Every command these tests type has a deadline:
- `junosPer`, 45 s, on each Junos command and completion;
- `adapterVariant`'s 150 s per command on EOS and NX-OS;
- 60 s on each L25 prompt;
- 4 min on an idle-timeout hold (L24);
- 90 s on each login prompt.

An expiry is **not observed**. It fails the test, and its cell says "not observed". It is never a
refusal and never a pass, and a note is not committed from a run that has one: rerun it.

**The controller runs a stall watchdog for the whole run.** The controller is the agent that
started the run, not the test. A stall is a log that has not grown in 25 minutes, which is longer
than the slowest step (an 8-minute boot, an 8-minute TACACS+ readiness wait and a 180 s commit). On
a stall, stop the run and clean up, and report it with the log's last 40 lines. A stalled run is
never read as a result. With the Monitor tool, or in a shell:

```bash
LOG=tests/lab/logs/l12-wire-vjunos.log; PID=$(cat tests/lab/logs/l12-wire-vjunos.pid); TOPO=tests/lab/topologies/vjunos.clab.yml
last=-1; still=0
while kill -0 "$PID" 2>/dev/null; do
  size=$(stat -c %s "$LOG")
  if [ "$size" = "$last" ]; then still=$((still + 1)); else still=0; last=$size; fi
  if [ "$still" -ge 25 ]; then
    echo "STALL: $LOG has not grown in 25 minutes"; tail -40 "$LOG"
    kill -INT "$PID"; sleep 180                      # the harness's handler tears the lab down
    kill -KILL "$PID" 2>/dev/null
    sudo containerlab destroy -t "$TOPO" --cleanup
    pkill -f 'bin/port49d' || true
    sudo pkill -f 'tcpdump.*tests/lab/captures' || true
    exit 1
  fi
  sleep 60
done
```

Topologies: `vjunos` → `tests/lab/topologies/vjunos.clab.yml`, `vsrx` → `vsrx.clab.yml`, `nxos` →
`nxos.clab.yml`, `eos` → `eos.clab.yml`.

**Evidence.** Run `make evidence` after the run. It writes the redacted captures the notes cite
into `tests/lab/evidence/`; commit those, and never `tests/lab/captures/`. If the run happened in a
worktree, copy its raw captures into the main checkout's `tests/lab/captures/` before removing the
worktree, or the labpcap audit fails. After every run, confirm that no `port49d` still holds
`172.100.100.1:49` and that the topology is destroyed.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md  MOD  §5.6, §5.7, §6, §8, §9, §12, §13 d21/d22, §15 L9/L12/L23-L25 (Task 1); §5.8 (Task 14); closed rows (Task 19)
tests/lab/junos_wire_test.go                  NEW  L9 and L12 wire facts; shared Junos helpers: junosSession, junosProbe, junosRun, junosConfigureAdmin (Task 2)
tests/lab/junos_bits_test.go                  NEW  each bit's reach as an upper bound (L12), class idle-timeout (L24) (Task 3)
tests/lab/l23_test.go                         NEW  inert candidates beside readonly (L23), NX-OS vsh.bin (L25) (Task 4)
internal/engine/contain.go                    NEW  Contains, MayMeet, AlwaysDominates, NeverDominates (Task 5)
internal/platform/dialect.go                  MOD  CommandProjection, Bits, BitDelivery, LocalUserNames, CeilingBits; RemoteClass;
                                                   ProjectionAttributes, Projected, LevelBits, ExpandBits (Task 6); generics["1.1.0"] (Task 13)
internal/platform/adapter.go                  MOD  Spec keys, Over, SpecOf, validateProjection, MonotoneBits (Task 6)
internal/policy/load.go                       MOD  keepsProjection, checkBlockOrder (Task 6); checkProjected (Task 9)
internal/projection/ere.go                    NEW  Facts, ruleERE, patternERE, bracket (Task 7)
internal/projection/project.go                NEW  Input, Result, Refusal, Project, JunosFacts, FactsFor (Task 8)
internal/projection/model.go                  NEW  the device model, the witness, Result.Device, Result.Narrower (Task 8)
internal/policy/resolve.go                    MOD  Resolution.Projection, compile → project, layerAttributes, exceeds (Task 9)
internal/policy/tests.go, explain.go          MOD  Caveats on a projected platform, ProjectionCaveats (Task 10)
internal/policy/lint.go                       MOD  projection, projection_overflow (Task 10); unenforced_rules (Task 17)
internal/policy/diff.go, cmd/port49/policy.go MOD  Diff.Projections, ProjectionChange, projectionText (Task 11)
internal/platform/classes.go                  NEW  ReferenceClasses (Task 12)
internal/config/config.go                     MOD  DefaultMaxSessionAge, MaxSessionAge (Task 12)
cmd/port49/platform.go, main.go               MOD  platform export --classes --config (Task 12); devices capabilities (Task 17)
platforms/1.1.0/*.yaml                        NEW  the set: 1.0.0's three per-command files, juniper_junos projected (Task 13)
internal/platform/set.go                      MOD  DefaultSet 1.1.0 (Task 13)
internal/platform/platform.go                 MOD  SystemTask, SystemTasks (Task 14, if L25 measures it)
internal/daemon/acct/acct.go, cmd/port49d     MOD  WithSystemTasks, isSystemUser on task_id (Task 14)
internal/decision/log.go, reasons.go          MOD  Gap, EventAccountGap (Task 15)
internal/daemon/acct/spool.go                 MOD  drop, flushGaps (Task 15)
internal/capability/capability.go             NEW  Device, Options, Row, Report, Infer (Task 16)
cmd/port49/capabilities.go                    NEW  devicesCapabilities, readLogs (Task 17)
tests/lab/projection_test.go                  NEW  the differential test (Task 18)
tests/lab/results/L9-*, L12-*, L23-*, L24-*, L25-*, L12-bits-*, L12-projection-*   NEW  written by the lab runs
docs/superpowers/plans/README.md              MOD  plan 5b as built (Task 19)
```

Nineteen tasks:
- **Task 1** is docs.
- **Tasks 2, 3 and 4** are lab measurements, run early because the set's values come from them.
- **Tasks 5–17** are code. Every one leaves `make test` green.
- **Task 18** is the differential lab test.
- **Task 19** is lab closure and docs.

Task 14 runs only if Task 4's L25 note measured the record. Tasks 5–12 depend on no lab result,
and may proceed while the lab tasks run: the lab holds one run at a time, and the code does not
need it. Task 13 reads all three lab notes.

---

### Task 1: The spec says what plan 5b builds, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.6, §5.7, §6, §8, §9, §12, §13 decisions
  21 and 22, §15 L9, L12 and new rows L23, L24, L25)

**Interfaces:** none. Every later task cites a paragraph this one writes.

What changes, so a reviewer can check each against a task:

- §5.6: decision 21's lever is `platform export --classes` rendering `idle-timeout`, measured by
  L24 (Task 12).
- §5.7: `account_gap`, the ninth event: a report, one record per spool drop stage (Task 15).
- §6: a projected platform maps each level to ceiling bits and, under `local_user_name`, a template
  (Tasks 6, 9).
- §8, the Fields table: `command_projection`, `bits` / `bit_delivery` and `local_user_names` as
  built (Task 6). The `bit_delivery` paragraph says why 1.1.0 ships `local_user_name` (L18; Task
  13). "As built (plan 5b)" gives the device model, the four proof obligations, `JunosFacts`, the
  ERE subset and the reports (Tasks 7–11). Generator constraint 6 and the quarantine note are new.
  So is "The reference classes are exported" (Task 12).
- §9, "As built": `devices capabilities`, its heuristics, the join, `account_gap` qualification and
  `unenforced_rules` (Tasks 15–17).
- §12: `local_user_names` joins the gated rendering keys.
- §13: decision 21 names `export --classes`, and decision 22 records what was built.
- §15: L9 and L12 gain the clauses Task 2 measures, and L23, L24 and L25 are new and open. Task 19
  closes them.

The lab has not yet measured anything this task writes as fact. Each sentence here either cites a
closed note (L11, L17, L18, L21, L22) or says the value is read in the direction that fails
closed until its row closes.

- [ ] **Step 1: Apply the spec edits**

<!-- patch: docs/design/2026-08-23-policy-engine-spec.md -->
````diff
diff --git a/docs/design/2026-08-23-policy-engine-spec.md b/docs/design/2026-08-23-policy-engine-spec.md
index ebfde3c..a0bfab1 100644
--- a/docs/design/2026-08-23-policy-engine-spec.md
+++ b/docs/design/2026-08-23-policy-engine-spec.md
@@ -1442,7 +1442,10 @@ Post-login control there is bounded by the device's own session, and port49 can
 nor revoke. This MUST be stated rather than implied: `port49 explain` MUST say so when asked
 about revocation or a ceiling on such a platform, exactly as it must for `pipe_authorized:
 false`. Two levers exist and both are used. The adapter renders the class `idle-timeout` from
-`max_session_age`, which is an approximation but an enforced one. And every revocation record
+`max_session_age`, which is an approximation but an enforced one: `port49 platform export
+--classes` prints each class a projected platform's replies rest on with `idle-timeout` set to
+`session.max_session_age_default` in whole minutes, rounded down (§8), and L24 measures that it
+ends an idle session a reply landed in that class. And every revocation record
 names the live contexts it could **not** reach, so an incident responder knows which devices
 still need a manual disconnect.
 
@@ -1674,6 +1677,14 @@ events (`account`, `blob`) that share the envelope and carry no verdict:
 
 Device accounting shares this envelope as the eighth event, `account`, and is specified in
 §5.8. It is not a decision — it is a report — so it carries no `policy` block and no verdict.
+A ninth, `account_gap`, is a report too: accounting records port49 received and did not write,
+`{"gap": {"stage": ..., "records": N, "since": ...}}`, one record per spool drop stage —
+`offer_refused` (answered `ERROR`; the device may send the record again), `drain_unparseable`
+and `drain_set_aside` (answered `SUCCESS`, and not in the log) — written by the spool before
+the records after the drop. It is what lets a reader of the log know the accounting stream has
+a hole, which reconciliation must know before it says a device did not ask (§9). The count is
+held in memory, so a restart loses what was not yet written; `port49_spool_drops_total{stage}`
+is the alarm, and this record is the log's own witness.
 
 `escalate` exists as its own event because the device-facing username on those platforms is
 `$enab{level}$`, not a person. The record carries the principal resolved from login context,
@@ -2653,7 +2664,9 @@ gets readonly's role: `priv-lvl=15`, `roles=network-operator` on EOS and
 
 **Platforms that are not `priv-lvl`-native** (Junos maps to `local-user-name`) MUST declare
 a mapping for every level. A missing mapping is a **policy load error in CI**, not a broken
-login at 3am.
+login at 3am. On a projected platform (§8) the mapping is the level's ceiling in permission
+bits, and under `bit_delivery: local_user_name` a template user per level; a level with no
+bits on its parent chain quarantines the device it lands on.
 
 **Exact attribute spellings are lab-verified, not asserted.** The shipped adapters use bare
 `priv-lvl` for the TACACS+ shell-service reply, the bare `roles=` for EOS roles and
@@ -2900,8 +2913,9 @@ attribute is complete in four lines:
 | `expands_abbreviations` | whether the device sends resolved command words | if `commands` |
 | `splits_interface_names` | whether the device sends an interface name and its index as two arguments (§3 rule 5); `true` on `cisco_iosxe` only (L21) | optional |
 | `pipe_token` / `pipe_authorized` | modifier separator; whether it reaches us | if `commands` |
-| `command_projection` | how rules render for session-only platforms (below) | if `session`-only |
-| `bits` / `bit_delivery` | each permission bit's reach in rule form, and whether bits travel as `user-permissions` or a `local-user-name` template (below) | if `session`-only |
+| `command_projection` | how rules render for session-only platforms (below): `junos_regex`, the one this build renders. Where it is set, `privilege` is each level's ceiling in permission bits, never attributes, and `supports` is `[session]` | if `session`-only |
+| `bits` / `bit_delivery` | each permission bit's reach in rule form, an upper bound measured in the lab (L12), and whether bits travel as `user-permissions` or a `local-user-name` template (below). A block may add to a bit's reach and never take from it, and may not declare a bit the set does not | if `session`-only |
+| `local_user_names` | under `bit_delivery: local_user_name`, each level's template user on the device, whose class `port49 platform export --classes` renders with the level's bits | with `local_user_name` |
 | `redact` | patterns whose argument values are removed before an accounting or authorization record is written (§5.7, §5.8); a block **adds** to the built-in patterns in `platforms/redact.yaml` and never removes one, and an edit to it is gated (§12) | if the platform sends command accounting — session-only platforms included |
 | `session_services` | the authorization `service` values this platform's sessions arrive with; a **list**, because the name is device-configurable on Junos | defaults per platform |
 | `session_discriminator` | the accounting AV pair whose value separates two sessions of one user on one device (§5.8) | defaults per platform |
@@ -3055,9 +3069,15 @@ Bits reach the device one of two ways, both in use in real fleets and selected p
 | `user_permissions` | `user-permissions=<bits>` per session, chosen per grant | one template user (`remote` or named) whose class carries no bits of its own |
 | `local_user_name` | `local-user-name=<template>`, one template per level, bits in its class | one class per level, rendered by `port49 platform export` |
 
-`user_permissions` is the default: zero per-level provisioning, and the bit set follows the
-grant rather than the level. `local_user_name` is for deployments that already provision
-classes and want the ceiling in device config where their compliance tooling can see it.
+`user_permissions` is the design's preference: zero per-level provisioning, and the bit set
+follows the grant rather than the level. `local_user_name` is for deployments that already
+provision classes and want the ceiling in device config where their compliance tooling can see
+it. **The built-in adapter ships `local_user_name`** until L12 measures `user-permissions`
+applied over a bitless template, per session: over a template whose class carried bits, it
+changed nothing, mandatory or optional (`tests/lab/results/L18-juniper_*.md`, variants 9 and
+10), while `local-user-name` was applied under either flag. A reply naming a template the device
+lacks lands the session in `remote` (L18, variant 7), so the reference configuration gives
+`remote` a class with no bits, `p49-remote`, and a missing template runs nothing.
 
 **Regexes for what bits cannot separate.** After the bits are chosen:
 
@@ -3134,6 +3154,52 @@ but has no capture, and neither has the reach of each bit, the `.*` baseline on
 the `-regexps` family's precedence. The plan's containerlab step closes L12 before the
 generator is final.
 
+**As built (plan 5b).** The projection ships in platform set **1.1.0**; a policy that pins
+none renders with 1.0.0 and Junos gets nothing, as before, so turning it on is a pin move
+`port49 policy diff` gates like any adapter edit. `internal/projection` renders each
+composition, and proves the reply before it is sent: every command the device would run under
+it is one port49 permits. It reads the device as the lab measured it (L11): a command runs
+where a matching allow beats every deny, or where the bits reach it and no deny matches, a
+bit's reach read as the classes read it — the most specific reach rule decides, so
+`view-configuration`'s `show configuration **` carves out of `view`'s `show **`. The proof's
+obligations, each checked from the rules' terms (`engine.Contains`, `MayMeet`,
+`AlwaysDominates`, `NeverDominates`), with a probe of every way the rules can be told apart
+as its witness:
+
+- **A bit is sent only where every command it reaches is decided by one rule of the grant**:
+  held by a permit, or by a deny, which is then sent. Under `local_user_name` the template's
+  class carries every bit of the level, so each must be; otherwise the grant goes narrow.
+- **A permit goes out as an allow only where it dominates every deny it meets**, since on the
+  device the allow beats them all; one that does not is the refused shape, named with both
+  rules. And only within the level's ceiling bits, a carve-out counted: a permit beyond them is
+  not sent, so the device refuses what port49 would permit there — narrower, which fails
+  closed, and reported.
+- **A deny is left off the wire only where the bits already refuse every command it matches**:
+  a dropped bit's reach holds it, no sent bit's reach ever dominates that, and no allow meets
+  it.
+- **Bits that enter configuration mode** (a reach holding `configure`: `configure`, `all`)
+  **are sent only for a grant of every command with no deny.** A statement typed there is
+  governed by the class's configuration permissions, which no command regex reaches, so port49
+  could deny what the device runs; until L12 measures otherwise, such a composition is refused.
+- **A rule whose text carries a value redaction hides is never projected**: the reply is written
+  whole to the `authorize_session` record and the blob event (§5.7, §5.8).
+
+What the regexes rest on is the device's regex dialect, measured by L9 and read into
+`JunosFacts` in the direction that fails closed until measured: explicit `^` and `$` anchors
+on every regex; a deny's letters written in both cases (`[sS][hH][oO][wW]`) while the device
+is case-sensitive; and no deny but `.*` while a deny may be walked past by abbreviating it — a
+capability shape needing one goes narrow, and a narrow one that cannot carry the grant is
+refused. A word is ASCII, carries no `{`, `}`, `"` or `\`, and escapes ERE's operators; a
+regex or class pattern is carried only in the subset of RE2 that reads the same in POSIX ERE
+(literals, bracket expressions, `.`, grouping, alternation, `*`, `+`, `?`, a repeat of at most
+8 written out, anchors at its ends), and anything else is refused. Every attribute is sent
+mandatory, once, and within RFC 8907's 255 bytes including its name; past that the device is
+quarantined and `policy test` prints the class line that would carry the value instead
+(`projection_overflow`). A role or grant may not set an attribute the projection renders, on a
+projected platform or under `all` where one is. Each composition's shape, bits, what each regex
+carries, what the bits refuse and what is beyond them is reported (`projection`), and `policy
+diff` reports a composition whose shape or bits moved (§12).
+
 #### Generator constraints
 
 None of these are caught by the device. All MUST be enforced at policy load:
@@ -3147,6 +3213,15 @@ None of these are caught by the device. All MUST be enforced at policy load:
    voids the entire deny baseline beneath it.
 5. **Reject invalid or over-budget policy loudly at load time**, never silently at session
    time. A server that skips an attribute at session time produces a fail-open shape.
+6. **Never emit an attribute a role or grant also sets.** The projection renders the template,
+   the bits and the regexes; a hand-written one beside it is a second instance (1), and over it
+   a regex nothing proved (4). Refused at load (plan 5b).
+
+A refusal here is a joint check (§10): the device the composition lands on is quarantined —
+closed without a reply, so it falls to local at once — and `policy test` and `policy diff`
+name the cause. **Operator note:** one subject's refused composition quarantines the whole
+device for every subject, as every joint check does; `policy diff` fails on the new quarantine
+before it ships.
 
 **Blast radius.** An invalid projection locks out every user authenticating against that
 device simultaneously. Lockout is fail-closed, but deployments MUST have a break-glass path
@@ -3179,6 +3254,14 @@ instrument for the differential test, not a runtime one.
 `start.*` as unanchored would also match `request start …`, diverging from our semantics.
 That belongs in the adapter and is asserted in the lab, never assumed.
 
+**The reference classes are exported.** `port49 platform export --classes --config
+port49d.yaml PLATFORM` prints, as `set` lines, the configuration a projected platform's
+replies rest on: the adapter's `device_config` (on Junos `tacplus-options strict-authorization`
+and the `remote` template's bitless class), and under `local_user_name` each level's template
+user and class with the level's bits. Every class carries `idle-timeout` from
+`session.max_session_age_default`, in whole minutes rounded down (decision 21); the file is
+read for that key alone, so no key or secret is needed to run it.
+
 **Importing existing configuration.** Simple alternations of prefix patterns convert to
 token rules mechanically; arbitrary regex does not. A migration tool MUST convert what it can
 and **flag the remainder for human review rather than approximating**, because a
@@ -3459,6 +3542,33 @@ health over the same window: spool drops, `ERROR` replies, and unattributed-reco
 will eventually accuse a correctly configured device, and once that happens nobody reads the
 report again.
 
+**As built (plan 5b).** `port49 devices capabilities --policy FILE --inventory FILE [--since
+DURATION] LOGFILE...` reads the decision log a daemon wrote (`-` for stdin) and prints, per
+inventory device, its admission, what its adapter declares under `supports`, and what the log
+shows it asked: `session` for an `authorize_session` record, `commands` for an
+`authorize_command`, `config_commands` for an authorization request that followed a permitted
+configuration entry (`configure …`) in the same context. `--since` bounds the window by the
+newest record's time, never the wall clock. It warns — and exits 1, for a job to page on — on:
+
+- **never seen**: an admitted device with no record in the window;
+- **config-commands probably off**: on a `commands` platform, at least 5 permitted configuration
+  entries in the window and at least 80% of them followed by no authorization request in their
+  context before the session's exec STOP or the window's end. An entry followed only by exec
+  commands is read as followed, so the inference under-reports rather than accuses;
+- **an unauthorized tier**: on a `commands` platform, command accounting records of contexts
+  port49 authenticated (`attribution: resolved`) whose command text holds no authorized command
+  of the same context. Holding, not equality, is the join, because NX-OS's accounting `cmd` is
+  the configuration path joined with ` ; ` and a result (L21), so a shape the join does not
+  expect reads as authorized. Printed as spec §9's block, with the device's unattributed, foreign
+  and system counts beside it.
+
+A capability observed that the adapter does not declare is a note, never a warning: it is a lab
+measurement waiting to be made. The window's `account_gap` records (§5.7) qualify the whole
+report: with any, it says so on its first line, an unauthorized tier is printed as possible, not
+found, and does not set the exit code. CI's half is `report: unenforced_rules`: a subject whose
+roles carry command rules on a platform that neither authorizes commands nor projects them —
+Junos under set 1.0.0 — is told they decide nothing there.
+
 > **Principle.** Never require an operator to assert something the system can observe.
 > Anything declared by hand about device behavior will eventually be wrong, and it will be
 > wrong silently.
@@ -4407,7 +4517,7 @@ to that list. The gated keys therefore include:
 - The normalization keys, which change the vector rules match against: `expands_abbreviations`,
   `splits_interface_names`, `strip_cr`, `pipe_token` and `pipe_authorized`.
 - The rendering keys of session-only platforms, which decide what the device enforces:
-  `command_projection`, `bits` and `bit_delivery`.
+  `command_projection`, `bits`, `bit_delivery` and `local_user_names`.
 - The keys the gate reads: `privilege_attributes`, `inert_attributes` and
   `accepted_attributes`.
 - `enable_username`, `shows_server_msg`, and `redact`, which changes what the audit keeps.
@@ -4791,7 +4901,8 @@ ceiling, revocation, username binding, and the in-session warning all act at the
 authorization request, and Junos never makes one. Rather than claim reach that does not exist,
 `explain` states the limit, the adapter renders class `idle-timeout` from `max_session_age` as
 the enforced approximation, and revocation records name the contexts they could not reach.
-(§5.6)
+(§5.6) *Plan 5b:* `port49 platform export --classes` renders the idle-timeout (§8), measured by
+L24; revocation records naming contexts are plan 7's.
 
 **22. Session-only projection is bits first, regexes second, chosen per grant, with one
 shape refused.** *Provisional on L12.* The generator picks the smallest permission-bit set
@@ -4802,7 +4913,10 @@ as `deny .*` plus one allow alternation, since emitting nothing widens it to the
 travel as `user-permissions` per session by default, or as a `local-user-name` template
 where a deployment provisions classes. A permit narrower than the bits with a deny beneath
 it is refused at load; the `-regexps` family's documented deny-precedence may lift that once
-measured. The choice is made from the composed grant, never per role. (§8, §15)
+measured. The choice is made from the composed grant, never per role. (§8, §15) *As built in
+plan 5b* (§8, "As built"): a reply is proven before it is sent, bits that enter configuration
+mode are sent only for a grant of everything, the built-in adapter delivers bits by template
+until L12 measures `user-permissions`, and the projection ships in set 1.1.0.
 
 **23. Where the device cannot draw the operator line, `operator` renders as `admin`'s level.**
 *Owner's ruling 2026-09-24.* On `arista_eos` and `cisco_nxos`, with command authorization
@@ -5295,10 +5409,10 @@ implemented against a guess. This section is the one place the distinction is ke
 | **L6** | How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next. | The `task_id` binding tolerance (§5.8); what reconciliation may conclude from silence (§9); `ERROR` semantics | all | open — arrival and latency measured on EOS and Junos; retry unmeasured; see below |
 | **L7** | Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests. | Reusable tokens (§13, decision 15); capability inference (§9) | EOS, NX-OS | closed — measured 2026-09-24; `tests/lab/results/L7-arista_eos.md`, `L7-login-arista_eos.md`, `L7-cisco_nxos.md`, `L7-nxapi-cookie-cisco_nxos.md`. eAPI and NX-API both measured 2026-09-20: one authentication per HTTP request on both, with per-command authorization and per-command accounting. Both cookies measured: eAPI `/login` 2026-09-23 and NX-API `nxapi_auth` 2026-09-24 — a request carrying the cookie runs no authentication and no session authorization, only its command authorizations (NX-API: the command plus `end`; `configure terminal` too for `cli_conf`). The `nxapi_auth` cookie expires after 10 minutes idle (`NXAPI timeout 10`), ends on `POST /logout`, and wins over a wrong Basic password sent beside it; NAPALM `nxos` never uses it (21 authentications for a six-call job) while Ansible `httpapi` does (one); see below |
 | **L8** | The maximum password length each platform accepts at an interactive prompt. (PAP was split out to L19 on 2026-09-23.) | The 30-character handle (design document §8) | all | closed — measured 2026-09-23; `tests/lab/results/L8-cisco_nxos.md`, `L8-cisco_iosxe.md`; and 2026-09-20, `L8-arista_eos.md`, `L8-juniper_vjunos-router.md`, `L8-juniper_vsrx.md`. The 30-character handle logs in on all five images. Longest intact: **127 on the N9Kv**, which refuses 128 and above locally and never asks port49; at least 1024 on IOS-XE; at least 138 on vEOS and both Junos images, where nothing longer was tried; see below |
-| **L9** | Whether Junos anchors `allow-commands` / `deny-commands` regexes, and which RE2 constructs its regex dialect rejects. | Projection generator constraints (§8) | Junos | open |
+| **L9** | Whether Junos anchors `allow-commands` / `deny-commands` regexes, and which RE2 constructs its regex dialect rejects. Whether explicit `^` and `$` are taken; whether a deny regex reads a command in the case and the abbreviation typed (`SHOW VERSION`, `sh ver`) or as the CLI expands it; whether a value with spaces is taken raw. | Projection generator constraints (§8); `JunosFacts` in `internal/projection`, each fact read in the direction that fails closed until measured | Junos | open |
 | **L10** | Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter. | Adapter `VERIFIED` status (§8) | all shipped adapters | open — `shell` on EOS, `junos-exec` on Junos. **Reading 3's conclusion is corrected by L17 (2026-09-21):** a denied Junos session authorization is advisory under the configuration this lab deploys, not on this vendor — `tacplus-options strict-authorization` makes the same denial refuse the login; see below. The three per-command adapters' spellings are measured by plan 5a (tests/lab/results/L22-*.md); Junos's wait on L12 (plan 5b), so the row stays open |
 | **L11** | Junos precedence, repetition, and length behavior for wire and class rules. | The projection model (§8) | Junos (SRX) | **closed** — measured 2026-09-03; results in `port49-junos-lab-tests-results.md` |
-| **L12** | `user-permissions` over TACACS+: accepted with a bitless template, replaces rather than merges with the class, per-session. What each bit reaches, so `bits:` can be declared. Whether a wire `deny-commands .*` plus one allow alternation yields exactly the permits. Whether `deny-commands-regexps` beats `allow-commands-regexps` over the wire as documented, and whether numbered names (`allow-commands1`, `allow-commands2`) are distinct attributes. | The projection rule, its default shape, and its refused shape (§8; §13, decision 22) | Junos (vSRX / vJunos-router in containerlab) | open — `user-permissions` and class bits are in production use; no capture yet |
+| **L12** | `user-permissions` over TACACS+: accepted with a bitless template, replaces rather than merges with the class, per-session, and two bits in one value. What each bit reaches, so `bits:` can be declared, and that `view` alone does not show the configuration. Whether a wire `deny-commands .*` plus one allow alternation yields exactly the permits. Whether `deny-commands-regexps` beats `allow-commands-regexps` over the wire as documented, and whether numbered names (`allow-commands1`, `allow-commands2`) are distinct attributes. Whether `deny-commands` reaches a statement typed in configuration mode, and `run`. Whether a template user commits with no uid. | The projection rule, its default shape, and its refused shape (§8; §13, decision 22); the built-in `bit_delivery` and `bits` (set 1.1.0) | Junos (vSRX / vJunos-router in containerlab) | open — `user-permissions` and class bits are in production use; no capture yet |
 | **L13** | How long a device waits for a TACACS+ reply, and what it does when a FAIL arrives after that — reports an authentication failure, or treats the server as unreachable and falls through to the next method or the next server. | port49 delays a FAIL on purpose: `limits.auth_failure_delay_base` doubling to `limits.auth_failure_delay_max`, **default 500ms and 2s**, which is the "answered with increasing delay" of design document §11. The ceiling was 5s until this row measured device reply timeouts; **2026-09-21 it was lowered to 2s**, which is under every timeout measured here, so a FAIL is always delivered inside it (`tests/lab/results/L13-*.md`). A ceiling above a device's timeout turns a denial into silence, and silence is the fall-through condition of §5.6 and L4. | all | open — measured 2026-09-20 over SSH on vJunos-router, vSRX, vEOS, N9Kv and Catalyst 8000V: about 3s on both Junos images, 5.0s on vEOS, about 6s on the N9Kv, which also retransmits, and above 12s on IOS-XE, which this sweep does not bound from above; past that timeout every platform that reached it takes the fall-through branch; other transports and the next-server case unmeasured; see below |
 | **L14** | Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does; whether any authorization request is sent for the session or for an `<edit-config>`, and with what `service`, `cmd` and `cmd-arg`; what `port` and `rem_addr` contain; what accounting arrives for a NETCONF session and for a commit. | Adapter coverage for automation traffic (§8); the login context key (§5.1.1); what reconciliation may conclude from accounting (§9) | Junos, NX-OS, EOS | open — measured 2026-09-20 on vEOS, vJunos-router and vSRX; on the N9Kv the AAA half is measured and the RPC half is not, because the channel closes before any RPC is answered; IOS-XE and key-based SSH unmeasured. **2026-09-21 (L17):** a Junos NETCONF session on port 830 is refused outright when port49 denies its session authorization and `tacplus-options strict-authorization` is committed, so the statement reaches automation traffic and not only interactive logins; see below |
 | **L16** | Role delivery over TACACS+ and its interaction with command authorization. Whether a custom role named in a reply attribute takes effect — verified by a command it forbids being refused, never by the device echoing the name back; whether the device still sends a per-command authorization request for a command its own role forbids; which wins when the device's role and port49 disagree, **in both directions**; two roles at once (NX-OS documents a union with permit winning); a role name the device does not have; no role attribute at all; the accepted spellings (`shell:roles=` / `shell:roles*`, bare or inside `cisco-av-pair`); and the `priv-lvl=N` to `priv-N` mapping under `feature privilege`. | The session-attribute model (§6) and adapter `privilege` blocks (§8) — a custom role is the NX-OS and EOS analogue of a Junos login class, which is what decision 22 projects into. Also what the decision log means (§5.7, §9): if a device can refuse a command port49 permitted, the log records a permit for a command that never ran. | EOS, NX-OS | open — added 2026-09-21. vEOS measured 2026-09-21 (`shell:roles*<name>` **does not deliver a role** — the device reports the session's role as `<unknown>` — port49's per-command deny binds, and a `cisco-av-pair*` attribute sent as OPTIONAL is refused outright) and **2026-09-22, which corrects the reading drawn from it**: EOS reads the **bare** attribute `roles=<name>`, which the first run never sent, under either argument flag; sent by its own name the role is applied, and under `aaa authorization commands ... local` it is the operator's real privilege. `priv-lvl` must be sent too — a reply with a role and no `priv-lvl` lands the session at level 1 — and an OPTIONAL `priv-lvl*N` **is** applied on this image. NX-OS measured 2026-09-21 (delivery: all three spellings work, an unknown name degrades to `network-operator`, and a delivered role's own rules do not bind while `aaa authorization commands` points at TACACS+) and 2026-09-22 (precedence: **`shell:roles` decides the role and a `priv-lvl` beside it is inert, in both directions**, so an NX-OS adapter sends the role and never the privilege level; with command authorization pointed at `local` instead, the delivered role does bind). Open on EOS: the `cisco-av-pair` ambiguity, and whether a role that permits everything carries a read-only one delivered beside it (the pair was measured, the permissive role alone was not). **2026-09-24, the disruptive commands** (`tests/lab/results/ceiling-*.md`, no row of its own yet): with port49 permitting every command, an NX-OS `network-operator` session ran `clear counters`, `clear ip bgp *` and a configuration change, and a vEOS `network-operator` session at level 15 ran `clear counters`, had `clear ip bgp *` parsed and passed (BGP cannot run on that image) and entered `configure`; only the privilege level binds there (level 1 is refused all three by the parser, never asking port49); see below |
@@ -5309,6 +5423,9 @@ implemented against a guess. This section is the one place the distinction is ke
 | **L20** | Whether a device answers a repeat API request without asking TACACS+; for how long; what it keys that answer on (the credential, the username, the client); whether a **wrong password** for the same user inside that window is also accepted; and whether a credential port49 would now refuse is re-checked inside it. | Whether a revocation in port49 reaches an API client at all (§5.1.4), and decision 15's bound on how long a spent token works — the receipt's `receipt_idle_ttl` and `receipt_max_age` act only on exchanges the device sends | IOS-XE; then every HTTP API transport | open — added 2026-09-23. IOS-XE RESTCONF answered a repeat of an already-spent token, 3s later, with `200 OK` and **zero** TACACS+ traffic (`tests/lab/results/L1-restconf-cisco_iosxe.md`), so a revocation in port49 cannot reach that repeat. **Measured 2026-09-24 on IOS-XE** (`tests/lab/results/L20-cisco_iosxe.md`): the cache is per credential (username and password), not per username or client address; a wrong password inside it goes to port49 and is refused; it lasts about 10s fixed from the authentication that filled it; and a cached credential is not re-checked, even with port49 answering every authentication ERROR. Open: every other HTTP API transport, so the row stays open; see below |
 | **L21** | Whether each platform sends the command words the operator typed (`sh run`) or the resolved ones (`show running-config`) on a per-command authorization request, and on the accounting record for it. | `expands_abbreviations` per platform (§3 rule 4, §8): where it is `false` a deny's word matches its own abbreviations, which over-denies, and where it is wrongly `true` an abbreviation slips past a deny | EOS, NX-OS, IOS-XE | closed — measured 2026-09-24; `tests/lab/results/L21-arista_eos.md`, `L21-cisco_nxos.md`, `L21-cisco_iosxe.md`. All three images send the **resolved** words, on the request and on the accounting record, over interactive SSH: `sh ver` arrives as `cmd=show cmd-arg=version`, and `sh clock` was denied by a `show clock` deny on all three. Interface names differ: IOS-XE splits `Gi1` into `GigabitEthernet`, `1`; vEOS and the N9Kv join it (`Ethernet1`, `Ethernet1/1`). Other transports and releases are outside what was measured; see below |
 | **L22** | What each per-command platform's device lets a session run at each level port49 renders — with port49 permitting every command, which of `clear counters`, `clear ip bgp *` and `configure terminal` it runs, refuses in its own parser, or sends port49 — and which level or role it reports, for the exact reply each built-in adapter sends; and, with port49 stopped under an open session on a command method list ending in `local`, whether operator's reply can change the configuration where admin's can, and whether it runs `clear counters` and `clear ip bgp *`; and, on IOS-XE with `privilege exec level 7 clear counters` configured and no `aaa authorization commands 7` list, whether a level-7 session runs `clear counters` without asking port49. | Decision 25; the adapters' `privilege`, `unreachable` and `fallback` (§8); the dead-rule and fallback-exposure reports (§12) | EOS, NX-OS, IOS-XE | closed — measured 2026-09-24; tests/lab/results/L22-arista_eos.md, L22-cisco_nxos.md, L22-cisco_iosxe.md. Each built-in adapter's reply at readonly, operator and admin was applied as the adapter says: on vEOS level 1 then 15 with network-operator, network-operator and network-admin; on the N9Kv network-operator, network-operator, network-admin, `clear counters` and `configure terminal` both sent to port49 at every level; on IOS-XE 17.13.01a levels 1, 7 and 15, level 7 sending `clear counters` and refusing `configure terminal` in the parser. With port49d stopped under an open session and the method list falling back to local, operator's reply could not change the configuration on any of the three, and admin's could on vEOS and the N9Kv. Beside it (`L22-carried-*.md`): vEOS's network-operator still ran `clear counters` and passed `clear ip bgp *` through authorization, the N9Kv's was refused both, and IOS-XE refused a token session every command at 7 and at 15, admin's included; on IOS-XE with no `aaa authorization commands 7` list, operator's `clear counters` ran without asking port49. Inert beside admin's reply: `home-directory`, `idletime` and `timeout` on vEOS and the N9Kv; `idletime*30` and `timeout*480` on IOS-XE, where they are accepted but held bearing (§6), and which refused the session for `home-directory`. By hand 2026-09-24: tests/lab/results/ceiling-*.md |
+| **L23** | Whether `home-directory`, `idletime` and `timeout`, each beside readonly's reply, leave the session readonly's on EOS and NX-OS: the same identity, the same reach for `clear counters` and `configure terminal`, and a permitted `show version`. Beside admin's reply (L22) a raise is invisible (5a final review M3). | The inert lists of `arista_eos` and `cisco_nxos` (§6, §8) | EOS, NX-OS | open |
+| **L24** | Whether a Junos login class's `idle-timeout` ends an idle session a TACACS+ reply landed in that class, through `local-user-name` and through the `remote` template. | Decision 21's enforced approximation; `port49 platform export --classes` (§5.6, §8) | Junos | open |
+| **L25** | Whether the N9Kv writes an accounting record under `admin` with task_id `vsh.bin.<port>` when a network-operator cancels the sudo prompt of a bare `show interface`, and what distinguishes it from a person's `admin` session. | A `cisco_nxos` system user keyed on its task_id, never the username alone (§5.8) | NX-OS | open — a production observation with no note |
 
 **What has been measured so far, per row.** The measurements exist and the notes are in the
 repository. NX-OS was measured on 2026-09-20 and is no longer outstanding; **IOS-XE was
````

- [ ] **Step 2: Check it**

Run: `git diff --stat` and `make test && make vet`
Expected: the spec is the only file changed, and every package is `ok` (nothing else moved). Read
the new rows L23, L24 and L25 in §15's table, and check that each one's Status is `open`.

- [ ] **Step 3: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "$(cat <<'EOF'
docs: spec says what plan 5b builds before the code does

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 2: (lab, on beehive) The Junos wire facts decision 22 rests on: L9 and L12

**Files:**
- Create: `tests/lab/junos_wire_test.go`
- Results (written by the run): `tests/lab/results/L12-juniper_vjunos-router.md`,
  `L12-juniper_vsrx.md`, `L9-juniper_vjunos-router.md`, `L9-juniper_vsrx.md`; evidence
  `tests/lab/evidence/L12-juniper_*.pcap`

**Interfaces:**
- Consumes (harness): `eachPlatform`, `l.capture`, `l.derivedConfigCmd`, `l.restart`, `l.nextLogin`,
  `l.sshCLI`, `c.expect`, `c.sendExpect`, `c.expectFrom`, `junosPrepare`, `junosConfigure`,
  `l.withAdminCLI`, `l.junosCLI`, `l.drainRecords`, `l.result`, `l.configPath`, `precReply`,
  `l16TrimEcho`, `l16Slug`, `containsAny`, `oneLine`, `orEmpty`, `str`, `sub`.
- Produces, for Tasks 3 and 18: `junosPer` (45 s), `junosRefusal`,
  `type junosProbe struct{ cmd string; complete bool }`, `type junosRun`,
  `(junosRun).ran(cmd string) bool`, `(junosRun).completes(p junosProbe) bool`,
  `(junosRun).cell(p, control junosRun) string`,
  `(*lab).junosConfigureAdmin(t, lines []string) string`,
  `(*lab).junosSession(t, name, attrs string, probes []junosProbe) junosRun`,
  `(*lab).junosProbe(c *cliConn, p junosProbe) (string, error)`. And the notes Task 13 reads.

This runs before any code, because 1.1.0's values come from it. The lab authorizer delivers each
variant's reply (`lab.session_attributes`), and each variant costs one daemon restart and one
seeded token login. The run spends 16 logins, which is the whole pool: 14 variants and 2 for the
per-session check. The control is a template holding `all` and no regex. A command the control
does not run says nothing about a variant, and its cell reads "not comparable".

The test configures four template users without a uid (`p49-l12-none`, `-view`, `-cfg`, `-all`)
over the break-glass CLI with port49d stopped, and deletes them at the end. Committing without a
uid is itself a measurement: `platform export --classes` renders none. Every probe is harmless.
One interface's counters are cleared and the loopback is pinged. `request system reboot` and
`restart routing` are probed by `?` completion and never run. The configuration-mode variant sets
the host name the device already has, so nothing changes whether or not it is refused.

Every command has `junosPer`, 45 s. An expiry is `not observed`, fails the test, and stops that
session's probes, since the session's state is unknown past a missed prompt.

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/junos_wire_test.go -->
````diff
diff --git a/tests/lab/junos_wire_test.go b/tests/lab/junos_wire_test.go
new file mode 100644
index 0000000..c007c45
--- /dev/null
+++ b/tests/lab/junos_wire_test.go
@@ -0,0 +1,428 @@
+//go:build lab
+
+package lab
+
+import (
+	"fmt"
+	"slices"
+	"strings"
+	"testing"
+	"time"
+)
+
+// The Junos wire facts decision 22's generator rests on (spec §8, §13; §15
+// L9 and L12): what a reply's `user-permissions` does over a bitless
+// template, whether a wire `deny-commands .*` plus one allow alternation
+// yields exactly the permits, how a deny regex is anchored, whether it reads
+// a command in the case and the abbreviation typed, whether it reaches a
+// statement typed in configuration mode, the `-regexps` family's precedence,
+// and whether numbered names are distinct attributes. Each is a variant of
+// the lab authorizer's session reply (`lab.session_attributes`) and one
+// token login; the control is a template holding every bit and no regex, so
+// a command the control does not run says nothing about a variant.
+//
+// Every command typed has a deadline, junosPer: a prompt that does not come
+// back within it is "not observed", never a refusal, and fails the test.
+
+// junosPer is the deadline on every command a Junos lab test types.
+const junosPer = 45 * time.Second
+
+// junosRefusal are the words a Junos CLI answers a command it will not run
+// with. A cell is `refused` only where the control ran the command and the
+// variant's output holds one of these; every cell's output is in the note
+// verbatim, so a marker this list lacks shows up as `ran` beside the text
+// that says otherwise, and the reader sees it.
+var junosRefusal = []string{"permission denied", "unknown command", "syntax error", "not allowed", "error:"}
+
+// junosProbe is one command a variant types, or with complete, whose last
+// word it asks `?` completion for and never runs: `request system reboot` is
+// probed by whether `reboot` completes after `request system`. A complete
+// probe ending in `?` is a listing, `show ?`, kept whole.
+type junosProbe struct {
+	cmd      string
+	complete bool
+}
+
+// junosRun is one variant's session.
+type junosRun struct {
+	name, attrs, user string
+	loginErr          string
+	auth              string            // `show cli authorization`
+	outs              map[string]string // probe → the device's reply
+	unobserved        []string          // probes whose prompt never came back
+	privilege         string            // the authorize_session record's session.privilege
+}
+
+func (r junosRun) ran(cmd string) bool {
+	out, ok := r.outs[cmd]
+	return ok && !slices.Contains(r.unobserved, cmd) && !containsAny(strings.ToLower(out), junosRefusal)
+}
+
+func (r junosRun) completes(p junosProbe) bool {
+	words := strings.Fields(p.cmd)
+	out := r.outs[p.cmd]
+	return strings.Contains(out, "\n  "+words[len(words)-1]+" ") || strings.Contains(out, "\n"+words[len(words)-1]+" ")
+}
+
+// cell is a probe's outcome in a variant, read against the control.
+func (r junosRun) cell(p junosProbe, control junosRun) string {
+	switch {
+	case r.loginErr != "":
+		return "no session"
+	case slices.Contains(r.unobserved, p.cmd):
+		return "not observed"
+	case p.complete && r.completes(p):
+		return "completes"
+	case p.complete:
+		return "absent"
+	case !control.ran(p.cmd):
+		return "not comparable (the control did not run it)"
+	case r.ran(p.cmd):
+		return "ran"
+	}
+	return "refused"
+}
+
+// junosConfigureAdmin applies configuration lines over a break-glass CLI,
+// port49d stopped so the device takes the local password (L4 reading 3).
+func (l *lab) junosConfigureAdmin(t *testing.T, lines []string) string {
+	t.Helper()
+	var out string
+	l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
+		return l.junosCLI(breakglassUser, breakglassPassword)
+	}, func(c *cliConn) error {
+		o, err := junosConfigure(c, lines...)
+		out = o
+		if err != nil {
+			return fmt.Errorf("applying %v: %w\n%s", lines, err, o)
+		}
+		return nil
+	})
+	return out
+}
+
+// junosSession restarts port49d with attrs as the session reply, logs in
+// with the next seeded token, reads `show cli authorization`, and types each
+// probe with its deadline. A probe sequence that enters configuration mode
+// ends with `exit configuration-mode` itself (configurationProbes).
+func (l *lab) junosSession(t *testing.T, name, attrs string, probes []junosProbe) junosRun {
+	t.Helper()
+	r := junosRun{name: name, attrs: attrs, outs: map[string]string{}}
+	cfg, err := l.derivedConfigCmd("junos-"+l16Slug(name), attrs, "", "")
+	if err == nil {
+		err = l.restart(cfg)
+	}
+	if err != nil {
+		t.Fatalf("%s: port49d with %s: %v", name, attrs, err)
+	}
+	off := l.mark()
+	user, secret := l.nextLogin(t)
+	r.user = user
+	c, err := l.sshCLI(user, secret)
+	if err == nil {
+		if _, err = c.expect(90*time.Second, junosOpPrompt); err != nil {
+			c.Close()
+		}
+	}
+	if err != nil {
+		r.loginErr = oneLine(err.Error())
+		return r
+	}
+	defer c.Close()
+	if err := junosPrepare(c); err != nil {
+		r.unobserved = append(r.unobserved, "set cli screen-length 0")
+	}
+	if out, err := c.sendExpect("show cli authorization", junosPer, junosOpPrompt); err != nil {
+		r.unobserved = append(r.unobserved, "show cli authorization")
+	} else {
+		r.auth = precReply(l16TrimEcho(out, "show cli authorization"))
+	}
+	for _, p := range probes {
+		out, err := l.junosProbe(c, p)
+		r.outs[p.cmd] = out
+		if err != nil {
+			r.unobserved = append(r.unobserved, p.cmd)
+			t.Errorf("%s: %q not observed within %s: %v", name, p.cmd, junosPer, err)
+			break // the session's state is unknown past a missed prompt
+		}
+	}
+	for _, rec := range l.drainRecords(off, 10*time.Second) {
+		if str(rec, "event") == "authorize_session" && str(sub(rec, "session"), "username") == user {
+			r.privilege = fmt.Sprint(sub(rec, "session")["privilege"])
+		}
+	}
+	return r
+}
+
+// junosProbe types one probe. A completion probe writes the words and `?`
+// with no newline, waits for the prompt to be redrawn with them, and clears
+// the line with ^U, so the command is never run.
+func (l *lab) junosProbe(c *cliConn, p junosProbe) (string, error) {
+	if !p.complete {
+		out, err := c.sendExpect(p.cmd, junosPer, junosOpPrompt, junosCfgPrompt, "(yes)")
+		if err == nil && strings.Contains(out, "(yes)") {
+			var more string
+			more, err = c.sendExpect("yes", junosPer, junosOpPrompt)
+			out += more
+		}
+		return precReply(l16TrimEcho(out, p.cmd)), err
+	}
+	send := p.cmd
+	prefix := strings.TrimSuffix(p.cmd, "?")
+	if !strings.HasSuffix(p.cmd, "?") {
+		words := strings.Fields(p.cmd)
+		prefix = strings.Join(words[:len(words)-1], " ") + " "
+		send = prefix + "?"
+	}
+	from := len(c.out.String())
+	if _, err := fmt.Fprint(c.in, send); err != nil {
+		return "", err
+	}
+	out, err := c.expectFrom(from, junosPer, junosOpPrompt+prefix)
+	fmt.Fprint(c.in, "\x15")
+	return out, err
+}
+
+// junosWireClasses are the templates the wire variants name: one with no
+// bits, one with `view`, one that configures, one with every bit. None has a
+// uid, which is itself a measurement: a template the reference configuration
+// renders has none (platform export --classes).
+var junosWireClasses = []string{
+	"set system login class p49-l12-none idle-timeout 60",
+	"set system login user p49-l12-none class p49-l12-none",
+	"set system login class p49-l12-view permissions view",
+	"set system login user p49-l12-view class p49-l12-view",
+	"set system login class p49-l12-cfg permissions [ configure view view-configuration ]",
+	"set system login user p49-l12-cfg class p49-l12-cfg",
+	"set system login class p49-l12-all permissions all",
+	"set system login user p49-l12-all class p49-l12-all",
+}
+
+var junosWireDelete = []string{
+	"delete system login user p49-l12-none", "delete system login class p49-l12-none",
+	"delete system login user p49-l12-view", "delete system login class p49-l12-view",
+	"delete system login user p49-l12-cfg", "delete system login class p49-l12-cfg",
+	"delete system login user p49-l12-all", "delete system login class p49-l12-all",
+}
+
+// junosWireProbes are typed in every variant. None changes the device: a
+// clear of one interface's counters, a ping of the loopback, and the two
+// disruptive commands by completion only.
+var junosWireProbes = []junosProbe{
+	{cmd: "show version"}, {cmd: "show system uptime"}, {cmd: "show interfaces terse"},
+	{cmd: "show interfaces fxp0 terse"}, {cmd: "show configuration system host-name"},
+	{cmd: "clear interfaces statistics fxp0"}, {cmd: "ping 127.0.0.1 count 1 rapid"},
+	{cmd: "SHOW VERSION"}, {cmd: "show interfaces FXP0 terse"}, {cmd: "sh ver"}, {cmd: "sh int fxp0 terse"},
+	{cmd: "set cli screen-width 200"},
+	{cmd: "request system reboot", complete: true}, {cmd: "restart routing", complete: true},
+}
+
+type junosVariant struct{ name, attrs, why string }
+
+var junosWireVariants = []junosVariant{
+	{"control", `["local-user-name=p49-l12-all"]`, "every bit and no regex: what the device runs at all"},
+	{"bitless", `["local-user-name=p49-l12-none"]`, "a template with no bits: the baseline every session has"},
+	{"bitless + user-permissions", `["local-user-name=p49-l12-none", "user-permissions=view"]`,
+		"L12: is user-permissions applied over a bitless template"},
+	{"bitless + user-permissions optional", `["local-user-name=p49-l12-none", "user-permissions*view"]`,
+		"L12: the same, optional"},
+	{"bitless + two bits", `["local-user-name=p49-l12-none", "user-permissions=view clear"]`,
+		"L12: two bits in one value, space-separated, as the generator writes them"},
+	{"remote + user-permissions", `["user-permissions=view"]`,
+		"L12: over remote's view view-configuration, does it replace (view alone) or merge"},
+	{"narrow", `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^(show version|show interfaces( .*)?)$"]`,
+		"L12: deny .* and one allow alternation yield exactly the permits"},
+	{"deny unanchored word", `["local-user-name=p49-l12-all", "deny-commands=version"]`,
+		"L9: is a deny regex matched anywhere in the line"},
+	{"deny prefix", `["local-user-name=p49-l12-all", "deny-commands=show ver"]`, "L9: is it matched as a prefix"},
+	{"deny anchored", `["local-user-name=p49-l12-all", "deny-commands=^show version$"]`,
+		"L9: explicit anchors; and the case and abbreviation of `show version`"},
+	{"deny argument", `["local-user-name=p49-l12-all", "deny-commands=^show interfaces fxp0( .*)?$"]`,
+		"L9: an argument's case and an abbreviated command against a deny"},
+	{"configuration mode", `["local-user-name=p49-l12-cfg", "deny-commands=^(set system host-name.*|show version)$"]`,
+		"L12: does deny-commands reach a statement typed in configuration mode, and `run`"},
+	{"regexps family", `["local-user-name=p49-l12-view", "deny-commands-regexps=^show version$", "allow-commands-regexps=^show version$"]`,
+		"L12: does the -regexps family's deny beat its allow over the wire"},
+	{"numbered name", `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^show version$", "allow-commands2=^show system uptime$"]`,
+		"L12: is allow-commands2 an attribute of its own"},
+}
+
+// configurationProbes are typed in the configuration-mode variant after its
+// probes: the statement sets the host name the device already has, so
+// nothing changes whether it is refused or not.
+var configurationProbes = []junosProbe{{cmd: "configure"}, {cmd: "set system host-name srx1"}, {cmd: "run show version"},
+	{cmd: "run show system uptime"}, {cmd: "exit configuration-mode"}}
+
+func TestL12JunosWire(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
+			t.Skip("Junos only")
+		}
+		stop := l.capture(t, "L12")
+		defer stop()
+		commit := l.junosConfigureAdmin(t, junosWireClasses)
+		defer l.junosConfigureAdmin(t, junosWireDelete)
+		defer func() {
+			if std, err := l.configPath(); err == nil {
+				if err := l.restart(std); err != nil {
+					t.Errorf("could not put port49d back on the lab config: %v", err)
+				}
+			}
+		}()
+		runs := map[string]junosRun{}
+		for _, v := range junosWireVariants {
+			probes := junosWireProbes
+			if v.name == "configuration mode" {
+				probes = append(slices.Clone(probes), configurationProbes...)
+			}
+			runs[v.name] = l.junosSession(t, v.name, v.attrs, probes)
+			if runs[v.name].loginErr != "" {
+				t.Errorf("%s: the session did not open, so nothing was measured: %s", v.name, runs[v.name].loginErr)
+			}
+		}
+		perSession := l.junosPerSession(t)
+		control := runs["control"]
+		if !control.ran("show version") || !control.ran("show interfaces terse") {
+			t.Fatalf("the control ran neither `show version` nor `show interfaces terse`, so no cell compares: %+v", control)
+		}
+		facts := junosFacts(runs)
+		var b strings.Builder
+		fmt.Fprintf(&b, "The templates were committed without a uid (%s).\n\n", commitWord(commit))
+		fmt.Fprintf(&b, "| variant | reply | why | priv_lvl on the request |\n|---|---|---|---|\n")
+		for _, v := range junosWireVariants {
+			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", v.name, v.attrs, v.why, runs[v.name].privilege)
+		}
+		fmt.Fprintf(&b, "\n| probe |")
+		for _, v := range junosWireVariants {
+			fmt.Fprintf(&b, " %s |", v.name)
+		}
+		fmt.Fprintf(&b, "\n|---|%s\n", strings.Repeat("---|", len(junosWireVariants)))
+		for _, p := range append(slices.Clone(junosWireProbes), configurationProbes...) {
+			fmt.Fprintf(&b, "| `%s` |", p.cmd)
+			for _, v := range junosWireVariants {
+				r := runs[v.name]
+				cell := "—"
+				if _, ok := r.outs[p.cmd]; ok {
+					cell = r.cell(p, control)
+				}
+				fmt.Fprintf(&b, " %s |", cell)
+			}
+			b.WriteString("\n")
+		}
+		fmt.Fprintf(&b, "\n### Read off the table\n\n%s\n%s\n", facts, perSession)
+		for _, v := range junosWireVariants {
+			r := runs[v.name]
+			fmt.Fprintf(&b, "\n### %s\n\nReply `%s`. `show cli authorization`:\n\n```\n%s\n```\n", v.name, v.attrs, r.auth)
+			for _, p := range append(slices.Clone(junosWireProbes), configurationProbes...) {
+				if out, ok := r.outs[p.cmd]; ok {
+					fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", p.cmd, orEmpty([]string{out}, 0))
+				}
+			}
+		}
+		// One run, two rows: each note carries the whole table, so either
+		// reads on its own; the capture is the run's (L12-*.pcap).
+		l.result(t, "L12", "Over TACACS+ on `junos-exec`: whether `user-permissions` is applied over a bitless "+
+			"template, replacing or merging, per session, and two bits in one value; whether a wire "+
+			"`deny-commands .*` plus one allow alternation yields exactly the permits; whether deny-commands "+
+			"reaches a statement typed in configuration mode, and `run`; whether `deny-commands-regexps` beats "+
+			"`allow-commands-regexps`; whether `allow-commands2` is an attribute of its own; whether a template "+
+			"user commits with no uid (spec §8, §13 decision 22, §15 L12).", b.String())
+		l.result(t, "L9", "Over TACACS+ on `junos-exec`: whether a `deny-commands` regex is matched anywhere in "+
+			"the line, as a prefix, or only as anchored; whether explicit `^` and `$` are taken; whether it reads "+
+			"a command in the case typed (`SHOW VERSION`, an argument `FXP0`) and in the abbreviation typed "+
+			"(`sh ver`) or as the CLI expands it; and whether a value with spaces is taken raw (spec §8, §15 L9). "+
+			"The `JunosFacts` lines below are what internal/projection reads.", b.String())
+	})
+}
+
+// junosFacts reads the facts the generator's JunosFacts and bit_delivery
+// take off the table, each with the rule it was read by.
+func junosFacts(runs map[string]junosRun) string {
+	c := runs["control"]
+	var b strings.Builder
+	say := func(format string, args ...any) { fmt.Fprintf(&b, "- "+format+"\n", args...) }
+	anchored := runs["deny anchored"]
+	say("explicit anchors: `^show version$` refused `show version` (%v) and ran `show system uptime` (%v)",
+		!anchored.ran("show version"), anchored.ran("show system uptime"))
+	say("unanchored: `version` refused `show version` (%v); `show ver` refused `show version` (%v)",
+		!runs["deny unanchored word"].ran("show version"), !runs["deny prefix"].ran("show version"))
+	caseSafe := func(cmd string, deny junosRun) bool { return !c.ran(cmd) || !deny.ran(cmd) }
+	caseSensitive := !(caseSafe("SHOW VERSION", anchored) && caseSafe("show interfaces FXP0 terse", runs["deny argument"]))
+	say("JunosFacts.CaseSensitive = %v: false only where every other-case spelling was refused by the CLI in "+
+		"the control or by the deny", caseSensitive)
+	expanded := c.ran("sh ver") && !anchored.ran("sh ver") && c.ran("sh int fxp0 terse") &&
+		!runs["deny argument"].ran("sh int fxp0 terse")
+	say("JunosFacts.DenyMatchesExpanded = %v: true only where the control ran both abbreviations and each "+
+		"deny refused them", expanded)
+	n := runs["narrow"]
+	say("narrow shape exact: ran `show version` %v, `show interfaces terse` %v; refused `show system uptime` %v, "+
+		"`clear interfaces statistics fxp0` %v, `ping` %v", n.ran("show version"), n.ran("show interfaces terse"),
+		!n.ran("show system uptime"), !n.ran("clear interfaces statistics fxp0"), !n.ran("ping 127.0.0.1 count 1 rapid"))
+	up := strings.Contains(runs["bitless + user-permissions"].auth, "view") &&
+		!strings.Contains(runs["bitless"].auth, "view")
+	say("user-permissions over a bitless template applied: %v (bit_delivery: user_permissions only if true, and "+
+		"per session below)", up)
+	say("user-permissions over remote: `show cli authorization` lists view-configuration: %v (true: merged or "+
+		"ignored; false: replaced)", strings.Contains(runs["remote + user-permissions"].auth, "view-configuration"))
+	cfg := runs["configuration mode"]
+	say("a statement typed in configuration mode under a deny-commands naming it: %s; `run show version` "+
+		"under a deny naming `show version`: %s", cfg.cell(junosProbe{cmd: "set system host-name srx1"}, c),
+		cfg.cell(junosProbe{cmd: "run show version"}, c))
+	say("-regexps: `show version` refused with both deny and allow naming it: %v", !runs["regexps family"].ran("show version"))
+	say("allow-commands2 an attribute of its own: `show system uptime` ran: %v", runs["numbered name"].ran("show system uptime"))
+	return b.String()
+}
+
+// junosPerSession asks whether user-permissions is per session: session A
+// opens under `view`, port49d restarts under `clear`, session B opens, and A
+// is asked again. It spends two tokens.
+func (l *lab) junosPerSession(t *testing.T) string {
+	t.Helper()
+	cfgA, err := l.derivedConfigCmd("junos-per-a", `["local-user-name=p49-l12-none", "user-permissions=view"]`, "", "")
+	if err == nil {
+		err = l.restart(cfgA)
+	}
+	if err != nil {
+		t.Fatal(err)
+	}
+	user, secret := l.nextLogin(t)
+	a, err := l.sshCLI(user, secret)
+	if err == nil {
+		_, err = a.expect(90*time.Second, junosOpPrompt)
+	}
+	if err != nil {
+		return "- per session: session A did not open (" + oneLine(err.Error()) + "), not measured"
+	}
+	defer a.Close()
+	before, errA := a.sendExpect("show cli authorization", junosPer, junosOpPrompt)
+	cfgB, err := l.derivedConfigCmd("junos-per-b", `["local-user-name=p49-l12-none", "user-permissions=clear"]`, "", "")
+	if err == nil {
+		err = l.restart(cfgB)
+	}
+	if err != nil {
+		t.Fatal(err)
+	}
+	userB, secretB := l.nextLogin(t)
+	bConn, err := l.sshCLI(userB, secretB)
+	var bAuth string
+	if err == nil {
+		if _, err = bConn.expect(90*time.Second, junosOpPrompt); err == nil {
+			bAuth, err = bConn.sendExpect("show cli authorization", junosPer, junosOpPrompt)
+		}
+		bConn.Close()
+	}
+	after, errA2 := a.sendExpect("show cli authorization", junosPer, junosOpPrompt)
+	if errA != nil || errA2 != nil || err != nil {
+		t.Errorf("per session: not observed (%v %v %v)", errA, errA2, err)
+		return "- per session: not observed"
+	}
+	return fmt.Sprintf("- per session: A before `%s`, B `%s`, A after B `%s`", oneLine(before), oneLine(bAuth),
+		oneLine(after))
+}
+
+func commitWord(out string) string {
+	if strings.Contains(out, "commit complete") {
+		return "commit complete"
+	}
+	return "the commit output did not say complete: " + oneLine(out)
+}
````

- [ ] **Step 2: Compile it**

Run: `go vet -tags lab ./tests/lab/...`
Expected: no output. The package builds only with the `lab` tag, and nothing in `make test` runs it.

- [ ] **Step 3: Run it on vJunos-router**

```bash
make build
PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^TestL12JunosWire$' -count=1 -v -timeout 90m \
  > tests/lab/logs/l12-wire-vjunos.log 2>&1 &
echo $! > tests/lab/logs/l12-wire-vjunos.pid
```

Run it in the background as "Running the lab" shows, with the stall watchdog running for the whole run. Boot budget 8 min. Expected: `--- PASS: TestL12JunosWire/juniper_vjunos-router`,
and `wrote tests/lab/results/L12-juniper_vjunos-router.md` and `L9-...` in the log. A FAIL that
names `not observed`, or a variant whose session did not open, measured nothing for that cell:
rerun. A FAIL on the control means the lab is broken, not Junos: stop and report it.

- [ ] **Step 4: Run it on vSRX**

The same, with `PORT49_LAB_PLATFORMS=vsrx`, the log `l12-wire-vsrx.log`, and topology
`vsrx.clab.yml` for the watchdog. Boot budget 6 min. On vSRX `junosCLI` reaches the break-glass CLI
over the console as root (`results/juniper_vsrx-config-verified.md`), and the note says so.

- [ ] **Step 5: Read the notes, and record what Task 13 takes from them**

Each note ends with "Read off the table". Copy these lines into the task's report for Task 13:

- `explicit anchors: ... refused show version (true) and ran show system uptime (true)`. **If
  either is false on either image, report it to the controller before Task 13.** The projection
  writes `^...$` on every regex, and a device that does not take them cannot be sent one. Tasks
  5–12 still land. Task 13 then ships 1.1.0 without `command_projection` on Junos (Step 4, item
  1), and Task 18 is skipped.
- `JunosFacts.CaseSensitive = ...` and `JunosFacts.DenyMatchesExpanded = ...` on both images.
- `user-permissions over a bitless template applied: ...`, the two-bit variant's `show cli
  authorization` (both `view` and `clear` listed?) and the per-session line (A's permissions
  unchanged after B?).
- The configuration-mode line: the statement's cell, and `run show version`'s.
- `-regexps` and `allow-commands2`. These are informational: nothing in this plan sends either.
- The table's `priv_lvl on the request` column. The Junos adapter's ceiling numbers assume 1
  (Decided 10), so if it is not 1, say so in the report.

- [ ] **Step 6: Commit the test, the notes and the evidence**

```bash
make evidence
git add tests/lab/junos_wire_test.go tests/lab/results/L12-juniper_*.md tests/lab/results/L9-juniper_*.md \
  tests/lab/evidence/L12-juniper_*.pcap
git commit -m "$(cat <<'EOF'
test: measure the Junos wire facts decision 22 rests on (L9, L12)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

The rows stay open until Task 19. A note is a measurement, and closing a row is its own commit
(CLAUDE.md, rule 3).

---

### Task 3: (lab, on beehive) Each bit's reach, and the class idle-timeout: L12 and L24

**Files:**
- Create: `tests/lab/junos_bits_test.go`
- Results (written by the run): `tests/lab/results/L12-bits-juniper_vjunos-router.md`,
  `L12-bits-juniper_vsrx.md`, `L24-juniper_vjunos-router.md`, `L24-juniper_vsrx.md`; evidence
  `L12-bits-*.pcap`, `L24-*.pcap`

**Interfaces:**
- Consumes: Task 2's `junosSession`, `junosProbe`, `junosRun`, `junosConfigureAdmin`, `junosPer`;
  the harness's `l.dial`, `syncBuf`.
- Produces: `junosBitReach map[string][]string`, the candidate reach Task 13 ships under `bits:`.
  Also `(*lab).holdUntilClosed(user, password string, within time.Duration) (time.Duration, string,
  error)`. And the notes Task 13 reads.

`junosBitReach` is the candidate each bit's reach is verified against, as an upper bound. For each
bit a ceiling names (view, view-configuration, clear, network, trace), a template's class holds
that bit alone. A sixth class, `none`, holds none. The test reads the top-level `?` completion and
`show ?` completion under each. A word a bit's completion offers and `none`'s does not must be held
by the bit's candidate reach, or the test fails and names the rule to add. That is the direction
that fails closed: a reach that says more than the bit does only makes the projection trust the bit
less. The carve-out the model reads is asserted too. Under `view` alone, `show configuration system
host-name` must not show the host name, or `view-configuration` carves nothing out of `view` and
`view`'s reach must hold `show configuration **`.

L24 lands one session through `local-user-name` in a class with `idle-timeout 1`, and one through
the `remote` template, whose class gets `idle-timeout 1` for the run. It holds each idle. The
deadline is 4 minutes: a session still open then is not observed, and fails.

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/junos_bits_test.go -->
````diff
diff --git a/tests/lab/junos_bits_test.go b/tests/lab/junos_bits_test.go
new file mode 100644
index 0000000..fd19560
--- /dev/null
+++ b/tests/lab/junos_bits_test.go
@@ -0,0 +1,311 @@
+//go:build lab
+
+package lab
+
+import (
+	"fmt"
+	"io"
+	"regexp"
+	"slices"
+	"strings"
+	"testing"
+	"time"
+
+	"golang.org/x/crypto/ssh"
+)
+
+// junosBitReach is each permission bit's reach in rule form, the candidate
+// this test verifies as an upper bound and platforms/1.1.0/juniper_junos.yaml
+// ships under `bits:` (spec §8, §15 L12). A bit that reaches a command no rule
+// here holds fails the test: widen the rule, here and in the adapter, since
+// a reach that says more than the bit does only makes the projection trust
+// the bit less.
+var junosBitReach = map[string][]string{
+	"view":               {"show **"},
+	"view-configuration": {"show configuration **"},
+	"clear":              {"clear **"},
+	"network":            {"ping **", "traceroute **", "ssh **", "telnet **"},
+	"trace":              {"monitor **"},
+}
+
+// junosBitProbes are typed under each single-bit template. Top-level and
+// `show` completion are the reach; the executed probes are the evidence a
+// reader checks it against.
+var junosBitProbes = []junosProbe{
+	{cmd: "?", complete: true}, {cmd: "show ?", complete: true},
+	{cmd: "show version"}, {cmd: "show configuration system host-name"}, {cmd: "show system uptime"},
+	{cmd: "clear interfaces statistics fxp0"}, {cmd: "ping 127.0.0.1 count 1 rapid"},
+	{cmd: "traceroute 127.0.0.1 ttl 1 wait 1"}, {cmd: "file list /var/tmp"},
+	{cmd: "monitor interface", complete: true}, {cmd: "request system reboot", complete: true},
+	{cmd: "restart routing", complete: true}, {cmd: "configure"}, {cmd: "exit configuration-mode"},
+}
+
+// completionWords is the words a `?` listing offers, one per line, the
+// description after them dropped.
+var completionWord = regexp.MustCompile(`(?m)^  ?([a-z][a-z0-9-]*)\s`)
+
+func completionWords(out string) []string {
+	var words []string
+	for _, m := range completionWord.FindAllStringSubmatch(out, -1) {
+		if !slices.Contains(words, m[1]) {
+			words = append(words, m[1])
+		}
+	}
+	return words
+}
+
+func TestL12JunosBits(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
+			t.Skip("Junos only")
+		}
+		stop := l.capture(t, "L12-bits")
+		defer stop()
+		bits := append([]string{"none"}, sortedKeysOf(junosBitReach)...)
+		var define, remove []string
+		for _, b := range bits {
+			class := "p49-l12-b-" + b
+			if b == "none" {
+				define = append(define, "set system login class "+class+" idle-timeout 60")
+			} else {
+				define = append(define, "set system login class "+class+" permissions "+b)
+			}
+			define = append(define, "set system login user "+class+" class "+class)
+			remove = append(remove, "delete system login user "+class, "delete system login class "+class)
+		}
+		l.junosConfigureAdmin(t, define)
+		defer l.junosConfigureAdmin(t, remove)
+		defer func() {
+			if std, err := l.configPath(); err == nil {
+				if err := l.restart(std); err != nil {
+					t.Errorf("could not put port49d back on the lab config: %v", err)
+				}
+			}
+		}()
+		runs := map[string]junosRun{}
+		for _, b := range bits {
+			runs[b] = l.junosSession(t, "bit "+b, `["local-user-name=p49-l12-b-`+b+`"]`, junosBitProbes)
+			if runs[b].loginErr != "" {
+				t.Errorf("bit %s: the session did not open: %s", b, runs[b].loginErr)
+			}
+		}
+		base := runs["none"]
+		var b strings.Builder
+		fmt.Fprintf(&b, "Each row is a session whose template's class holds one bit and nothing else; `none` holds "+
+			"none. A word is the bit's where its completion lists it and `none`'s does not.\n\n"+
+			"| bit | top-level words beyond none | `show` words beyond none | candidate reach | held |\n|---|---|---|---|---|\n")
+		for _, bit := range bits[1:] {
+			r := runs[bit]
+			top := beyond(completionWords(r.outs["?"]), completionWords(base.outs["?"]))
+			show := beyond(completionWords(r.outs["show ?"]), completionWords(base.outs["show ?"]))
+			var unheld []string
+			for _, w := range top {
+				if !heldBy(junosBitReach[bit], w+" **") {
+					unheld = append(unheld, w+" **")
+				}
+			}
+			for _, w := range show {
+				if !heldBy(junosBitReach[bit], "show "+w+" **") {
+					unheld = append(unheld, "show "+w+" **")
+				}
+			}
+			fmt.Fprintf(&b, "| %s | %s | %s | `%s` | %s |\n", bit, strings.Join(top, " "), strings.Join(show, " "),
+				strings.Join(junosBitReach[bit], "`, `"), heldCell(unheld))
+			if len(unheld) > 0 {
+				t.Errorf("bit %s reaches %v, which its candidate reach does not hold: add each to junosBitReach[%q] "+
+					"and to platforms/1.1.0/juniper_junos.yaml's bits.%s (an upper bound only fails closed)", bit,
+					unheld, bit, bit)
+			}
+		}
+		// The carve-out the projection reads: under view alone, the
+		// configuration is not shown; view-configuration's reach is narrower
+		// than view's and holds it.
+		view := runs["view"].outs["show configuration system host-name"]
+		carved := !strings.Contains(view, "host-name "+l.p.node)
+		fmt.Fprintf(&b, "\nUnder `view` alone `show configuration system host-name` shows the host name: %v. "+
+			"The projection reads `view-configuration` as carving `show configuration **` out of `view` "+
+			"(the most specific reach decides), which holds only if this is false.\n", !carved)
+		if !carved {
+			t.Errorf("under view alone the configuration is shown, so view-configuration carves nothing out of "+
+				"view: add \"show configuration **\" to view's reach:\n%s", view)
+		}
+		fmt.Fprintf(&b, "\n| probe |")
+		for _, bit := range bits {
+			fmt.Fprintf(&b, " %s |", bit)
+		}
+		fmt.Fprintf(&b, "\n|---|%s\n", strings.Repeat("---|", len(bits)))
+		for _, p := range junosBitProbes {
+			if p.cmd == "?" || p.cmd == "show ?" {
+				continue
+			}
+			fmt.Fprintf(&b, "| `%s` |", p.cmd)
+			for _, bit := range bits {
+				fmt.Fprintf(&b, " %s |", runs[bit].cell(p, runs["none"]))
+			}
+			b.WriteString("\n")
+		}
+		fmt.Fprintf(&b, "\nThe reach as measured, ready for `bits:`:\n\n```yaml\n")
+		for _, bit := range sortedKeysOf(junosBitReach) {
+			fmt.Fprintf(&b, "      %s: [%s]\n", bit, quotedList(junosBitReach[bit]))
+		}
+		b.WriteString("      all: [\"**\"]\n```\n")
+		for _, bit := range bits {
+			r := runs[bit]
+			fmt.Fprintf(&b, "\n### %s\n\n`show cli authorization`:\n\n```\n%s\n```\n", bit, r.auth)
+			for _, p := range junosBitProbes {
+				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", p.cmd, orEmpty([]string{r.outs[p.cmd]}, 0))
+			}
+		}
+		l.result(t, "L12-bits", "What each permission bit a built-in level's ceiling names reaches, alone in a "+
+			"template's class, over TACACS+ `local-user-name`: every command word its completion offers that a "+
+			"class with no bits does not, held by the adapter's `bits:` reach as an upper bound; and that "+
+			"`view` alone does not show the configuration (spec §8, §15 L12).", b.String())
+	})
+}
+
+func sortedKeysOf(m map[string][]string) []string {
+	out := make([]string, 0, len(m))
+	for k := range m {
+		out = append(out, k)
+	}
+	slices.Sort(out)
+	return out
+}
+
+func beyond(words, base []string) []string {
+	var out []string
+	for _, w := range words {
+		if !slices.Contains(base, w) {
+			out = append(out, w)
+		}
+	}
+	return out
+}
+
+// heldBy reports whether some reach rule holds rule, both words then `**`:
+// the reach rule's words are a prefix of the rule's.
+func heldBy(reach []string, rule string) bool {
+	want := strings.Fields(rule)
+	return slices.ContainsFunc(reach, func(r string) bool {
+		f := strings.Fields(r)
+		if len(f) == 0 || f[len(f)-1] != "**" || len(f)-1 > len(want)-1 {
+			return false
+		}
+		return slices.Equal(f[:len(f)-1], want[:len(f)-1])
+	})
+}
+
+func heldCell(unheld []string) string {
+	if len(unheld) == 0 {
+		return "yes"
+	}
+	return "**no**: " + strings.Join(unheld, ", ")
+}
+
+func quotedList(rules []string) string {
+	q := make([]string, len(rules))
+	for i, r := range rules {
+		q[i] = fmt.Sprintf("%q", r)
+	}
+	return strings.Join(q, ", ")
+}
+
+// TestL24JunosIdleTimeout measures decision 21's approximation: a login
+// class's idle-timeout ends an idle session a TACACS+ reply landed in that
+// class, through `local-user-name` and through the `remote` template. Each
+// session is held idle with a deadline of four minutes on its closing; still
+// open then is not observed, and fails.
+func TestL24JunosIdleTimeout(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
+			t.Skip("Junos only")
+		}
+		stop := l.capture(t, "L24")
+		defer stop()
+		l.junosConfigureAdmin(t, []string{"set system login class p49-l24-idle permissions view",
+			"set system login class p49-l24-idle idle-timeout 1",
+			"set system login user p49-l24-idle class p49-l24-idle",
+			"set system login class p49-readonly idle-timeout 1"})
+		defer l.junosConfigureAdmin(t, []string{"delete system login user p49-l24-idle",
+			"delete system login class p49-l24-idle", "delete system login class p49-readonly idle-timeout"})
+		defer func() {
+			if std, err := l.configPath(); err == nil {
+				if err := l.restart(std); err != nil {
+					t.Errorf("could not put port49d back on the lab config: %v", err)
+				}
+			}
+		}()
+		var b strings.Builder
+		fmt.Fprintf(&b, "| path | reply | closed after | what the device said |\n|---|---|---|---|\n")
+		for _, v := range []struct{ name, attrs string }{
+			{"local-user-name", `["local-user-name=p49-l24-idle"]`},
+			{"remote template", `[]`},
+		} {
+			cfg, err := l.derivedConfigCmd("l24-"+l16Slug(v.name), v.attrs, "", "")
+			if err == nil {
+				err = l.restart(cfg)
+			}
+			if err != nil {
+				t.Fatal(err)
+			}
+			user, secret := l.nextLogin(t)
+			elapsed, said, err := l.holdUntilClosed(user, secret, 4*time.Minute)
+			cell := elapsed.Round(time.Second).String()
+			if err != nil {
+				cell = "not observed: " + oneLine(err.Error())
+				t.Errorf("%s: %v", v.name, err)
+			}
+			fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` |\n", v.name, v.attrs, cell, oneLine(said))
+		}
+		l.result(t, "L24", "A login class's `idle-timeout` ends an idle session a TACACS+ reply landed in "+
+			"that class, through `local-user-name` and through the `remote` template (spec §5.6; §13 decision 21).",
+			b.String())
+	})
+}
+
+// holdUntilClosed opens an interactive session and types nothing until the
+// device closes it, within the deadline. An error is a session that did not
+// open, or one still open at the deadline: not observed.
+func (l *lab) holdUntilClosed(user, password string, within time.Duration) (time.Duration, string, error) {
+	c, err := l.dial(user, password, 45*time.Second)
+	if err != nil {
+		return 0, "", err
+	}
+	defer c.Close()
+	s, err := c.NewSession()
+	if err != nil {
+		return 0, "", err
+	}
+	defer s.Close()
+	if err := s.RequestPty("vt100", 40, 120, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
+		return 0, "", err
+	}
+	var buf syncBuf
+	s.Stdout, s.Stderr = &buf, &buf
+	stdin, err := s.StdinPipe()
+	if err != nil {
+		return 0, "", err
+	}
+	defer stdin.Close()
+	if err := s.Shell(); err != nil {
+		return 0, "", err
+	}
+	start := time.Now()
+	done := make(chan error, 1)
+	go func() { done <- s.Wait() }()
+	select {
+	case <-done:
+		return time.Since(start), tail(buf.String()), nil
+	case <-time.After(within):
+		io.WriteString(stdin, "exit\n")
+		return 0, tail(buf.String()), fmt.Errorf("still open after %s", within)
+	}
+}
+
+func tail(s string) string {
+	lines := strings.Split(strings.TrimSpace(s), "\n")
+	if len(lines) > 3 {
+		lines = lines[len(lines)-3:]
+	}
+	return strings.Join(lines, " / ")
+}
````

- [ ] **Step 2: Compile it**

Run: `go vet -tags lab ./tests/lab/...`
Expected: no output.

- [ ] **Step 3: Run it on vJunos-router, then vSRX**

```bash
PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^(TestL12JunosBits|TestL24JunosIdleTimeout)$' \
  -count=1 -v -timeout 90m > tests/lab/logs/l12-bits-vjunos.log 2>&1 &
echo $! > tests/lab/logs/l12-bits-vjunos.pid
```

Run it in the background as "Running the lab" shows, with the stall watchdog running for the whole run. The run spends 8 of the 16 seeded logins. Then the same with
`PORT49_LAB_PLATFORMS=vsrx`.

Expected: both tests PASS on both images. If `TestL12JunosBits` fails with `bit X reaches [...],
which its candidate reach does not hold`, that is a measurement, not a defect. Add each named
rule to `junosBitReach[X]` in this file, rerun until it passes, and carry the final table to Task
13 (the note prints it, "ready for `bits:`"). If the carve-out assertion fails, add `"show
configuration **"` to `view`'s reach the same way.

- [ ] **Step 4: Commit the test, the notes and the evidence**

```bash
make evidence
git add tests/lab/junos_bits_test.go tests/lab/results/L12-bits-juniper_*.md tests/lab/results/L24-juniper_*.md \
  tests/lab/evidence/L12-bits-juniper_*.pcap tests/lab/evidence/L24-juniper_*.pcap
git commit -m "$(cat <<'EOF'
test: measure each Junos bit's reach and the class idle-timeout (L12, L24)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 4: (lab, on beehive) Inert beside readonly on EOS and NX-OS, and NX-OS's vsh.bin record: L23 and L25

**Files:**
- Create: `tests/lab/l23_test.go`
- Results (written by the run): `tests/lab/results/L23-arista_eos.md`, `L23-cisco_nxos.md`,
  `L25-cisco_nxos.md`; evidence `L23-*.pcap`, `L25-cisco_nxos.pcap`

**Interfaces:**
- Consumes: 5a's `adapterVariant`, `adapterRow` and its `reach`/`permit` helpers, and
  `inertCandidates` (`tests/lab/adapters_test.go`); `negativeFinding`; `platform.DialectFor(name).
  Render("readonly")`.
- Produces: the notes Task 13 (L23) and Task 14 (L25) read.

5a final review M3: beside admin's reply, a candidate that raised the session would look inert,
because admin already holds everything. Beside readonly's, a raise shows. The control is
readonly's own reply, and it must open with `show version` permitted, or nothing compares. A
candidate is inert only where the session opened with readonly's identity, the same reach for
`clear counters` and `configure terminal`, and a permitted `show version`. A candidate listed
inert that moved the session fails the test and names Task 13.

L25 opens one pty session as a network-operator (readonly's reply), types a bare `show interface`,
and cancels the sudo prompt with ^C if one appears. It then waits 30 s for an accounting record
under `admin`. Each prompt has a 60 s deadline. If no record comes, the note carries it as a
negative finding with the exact transcript (`negativeFinding`), and the row stays open.

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/l23_test.go -->
````diff
diff --git a/tests/lab/l23_test.go b/tests/lab/l23_test.go
new file mode 100644
index 0000000..b2c7304
--- /dev/null
+++ b/tests/lab/l23_test.go
@@ -0,0 +1,153 @@
+//go:build lab
+
+package lab
+
+import (
+	"fmt"
+	"slices"
+	"strings"
+	"testing"
+	"time"
+
+	adapter "github.com/rhwendt/port49/internal/platform"
+)
+
+// TestL23InertBesideReadonly re-measures L22's inert candidates beside
+// readonly's reply, where a raise shows: beside admin's, the session already
+// holds everything, so an attribute that raised it would look inert (5a final
+// review M3; spec §15 L23). A candidate is inert here only where the session
+// opened with readonly's identity, the same reach for both ceiling commands,
+// and a `show version` port49 permitted. Every command has adapterVariant's
+// deadline; one that did not finish is not observed and fails the test.
+func TestL23InertBesideReadonly(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "arista_eos" && l.p.name != "cisco_nxos" {
+			t.Skip("EOS and NX-OS: IOS-XE holds every candidate bearing (L22-cisco_iosxe.md)")
+		}
+		d, _ := adapter.DialectFor(l.p.name)
+		stop := l.capture(t, "L23")
+		defer stop()
+		defer func() {
+			if std, err := l.configPath(); err == nil {
+				if err := l.restart(std); err != nil {
+					t.Errorf("could not put port49d back on the lab config: %v", err)
+				}
+			}
+		}()
+		readonly, _ := d.Render("readonly")
+		control := l.adapterVariant(t, "l23-readonly", readonly)
+		if control.err != nil || len(control.unobserved) > 0 || !control.showVersion {
+			t.Fatalf("readonly's own reply did not give a session to compare against: %+v", control)
+		}
+		var b strings.Builder
+		fmt.Fprintf(&b, "Control, readonly's reply `%s`: identity `%s`, `clear counters` %s, `configure terminal` %s, "+
+			"`show version` %s.\n\n| attribute | session | identity | `clear counters` | `configure terminal` | "+
+			"`show version` | inert |\n|---|---|---|---|---|---|---|\n", strings.Join(readonly, "`, `"), control.identity,
+			control.reach("clear counters", control.clear), control.reach("configure terminal", control.cfg),
+			control.permit(control.showVersion))
+		for _, a := range inertCandidates {
+			name := strings.SplitN(a, "*", 2)[0]
+			row := l.adapterVariant(t, "l23-"+name, append(slices.Clone(readonly), a))
+			if len(row.unobserved) > 0 {
+				t.Errorf("%s: not observed: %v", a, row.unobserved)
+			}
+			inert := row.err == nil && len(row.unobserved) == 0 && row.identity == control.identity &&
+				row.clear == control.clear && row.cfg == control.cfg && row.showVersion
+			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s |\n", a, row.session, row.identity,
+				row.reach("clear counters", row.clear), row.reach("configure terminal", row.cfg),
+				row.permit(row.showVersion), yesNo(inert))
+			if !inert && slices.Contains(d.InertAttributes, name) {
+				t.Errorf("%s is listed inert on %s and moved readonly's session: set 1.1.0 lists it bearing "+
+					"(plan 5b, Task 13)", name, l.p.name)
+			}
+		}
+		l.result(t, "L23", "Whether home-directory, idletime and timeout, each beside readonly's reply, leave the "+
+			"session readonly's: the same identity, the same reach for `clear counters` and `configure terminal`, "+
+			"and a permitted `show version` (spec §6, §15 L23; 5a final review M3).", b.String())
+	})
+}
+
+// TestL25NXOSSystemUser measures the production observation plan 2 left
+// unentered: on the N9Kv, a network-operator's bare `show interface` prompts
+// for sudo, and cancelling it writes an accounting record under `admin` with
+// task_id `vsh.bin.<port>` (roadmap, plan 5). The session is one pty with a
+// deadline on every prompt; the records are read off the decision log.
+func TestL25NXOSSystemUser(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "cisco_nxos" {
+			t.Skip("NX-OS only")
+		}
+		d, _ := adapter.DialectFor(l.p.name)
+		stop := l.capture(t, "L25")
+		defer stop()
+		readonly, _ := d.Render("readonly")
+		quoted := `["` + strings.Join(readonly, `", "`) + `"]`
+		cfg, err := l.derivedConfig("l25", quoted, "")
+		if err == nil {
+			err = l.restart(cfg)
+		}
+		if err != nil {
+			t.Fatal(err)
+		}
+		defer func() {
+			if std, err := l.configPath(); err == nil {
+				if err := l.restart(std); err != nil {
+					t.Errorf("could not put port49d back on the lab config: %v", err)
+				}
+			}
+		}()
+		off := l.mark()
+		user, secret := l.nextLogin(t)
+		c, err := l.sshCLI(user, secret)
+		if err != nil {
+			t.Fatalf("the network-operator session did not open: %v", err)
+		}
+		defer c.Close()
+		prompt := l.p.node + "#"
+		if _, err := c.expect(90*time.Second, prompt); err != nil {
+			t.Fatalf("no prompt: %v", err)
+		}
+		const per = 60 * time.Second
+		out, err := c.sendExpect("show interface", per, prompt, "assword", "--More--")
+		switch {
+		case err != nil:
+			t.Fatalf("`show interface` not observed within %s: %v", per, err)
+		case strings.Contains(out, "--More--"):
+			_, err = c.sendExpect("q", per, prompt)
+		case strings.Contains(out, "assword"):
+			// Cancel the sudo prompt, as the production operator did.
+			from := len(c.out.String())
+			fmt.Fprint(c.in, "\x03")
+			var more string
+			more, err = c.expectFrom(from, per, prompt)
+			out += more
+		}
+		if err != nil {
+			t.Fatalf("the prompt did not come back within %s: %v", per, err)
+		}
+		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
+			return slices.ContainsFunc(rs, func(r map[string]any) bool {
+				return str(r, "event") == "account" && str(sub(r, "session"), "username") == "admin"
+			})
+		})
+		var admin []string
+		for _, r := range recs {
+			if str(r, "event") == "account" && str(sub(r, "session"), "username") == "admin" {
+				admin = append(admin, fmt.Sprintf("flags %s, task_id `%s`, attribution %s, cmd `%s`", str(r, "flags"),
+					str(r, "task_id"), str(r, "attribution"), strings.Join(strs(sub(r, "record"), "raw"), " ")))
+			}
+		}
+		var b strings.Builder
+		fmt.Fprintf(&b, "Reply `%s`; the session was %s. `show interface` answered:\n\n```\n%s\n```\n\n", quoted, user,
+			orEmpty([]string{out}, 0))
+		if len(admin) == 0 {
+			b.WriteString(negativeFinding{Claim: "no accounting record under `admin` followed the cancelled sudo in 30s",
+				Sent: "show interface, then ^C at the password prompt", Got: orEmpty([]string{out}, 0)}.render(t))
+		} else {
+			fmt.Fprintf(&b, "Accounting records under `admin` after it:\n\n- %s\n", strings.Join(admin, "\n- "))
+		}
+		l.result(t, "L25", "On the N9Kv, whether a network-operator's bare `show interface` prompts for sudo, and "+
+			"whether cancelling it writes an accounting record under `admin` with task_id `vsh.bin.<port>` "+
+			"(spec §5.8, §15 L25).", b.String())
+	})
+}
````

- [ ] **Step 2: Compile it**

Run: `go vet -tags lab ./tests/lab/...`
Expected: no output.

- [ ] **Step 3: Run L23 on vEOS, then L23 and L25 on the N9Kv**

```bash
PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run '^TestL23InertBesideReadonly$' -count=1 -v -timeout 90m \
  > tests/lab/logs/l23-eos.log 2>&1 &
echo $! > tests/lab/logs/l23-eos.pid
```

Then `PORT49_LAB_PLATFORMS=nxos` with `-run '^(TestL23InertBesideReadonly|TestL25NXOSSystemUser)$'` and
`-timeout 120m` (the N9Kv's boot budget is 15 min, and it takes about two minutes to finish `clear
counters` on an exec channel). Run it in the background as "Running the lab" shows, with the stall watchdog running for the whole run.

Expected: PASS, and one note per test per platform. A candidate that is not inert beside readonly
fails `TestL23InertBesideReadonly` with the name to move: that is a measurement, carried to Task 13.
`TestL25NXOSSystemUser` passes whether or not the record appears. What it measured is in the note:
an `admin` record with `task_id vsh.bin.<n>` means Task 14 runs, and a negative finding means Task
14 is skipped.

- [ ] **Step 4: Commit the test, the notes and the evidence**

```bash
make evidence
git add tests/lab/l23_test.go tests/lab/results/L23-*.md tests/lab/results/L25-cisco_nxos.md \
  tests/lab/evidence/L23-*.pcap tests/lab/evidence/L25-cisco_nxos.pcap
git commit -m "$(cat <<'EOF'
test: re-measure the inert candidates beside readonly, and NX-OS's vsh.bin record (L23, L25)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 5: Rule containment and dominance a projection can prove with

**Files:**
- Create: `internal/engine/contain.go`
- Test: `internal/engine/contain_test.go`

**Interfaces:**
- Consumes: the engine's own `compileRule`, `meets`, `overrides`, `fixedLen`, `anyMatch`, and
  `Normalize.abbreviated`.
- Produces, for Task 8:
  - `func Contains(outer, inner string, classes map[string][]string) (bool, error)`: every command
    `inner` matches, `outer` matches too, both read as permits. True is a proof, and false may be a
    containment it could not see.
  - `func MayMeet(permit, deny string, classes map[string][]string, n Normalize) (bool, error)`
  - `func AlwaysDominates(permit, deny string, classes map[string][]string, n Normalize) (bool, error)`
  - `func NeverDominates(permit, deny string, classes map[string][]string, n Normalize) (bool, error)`

The projection's proof needs four questions of two rules, answered from their terms. The engine
already answers one direction ("does some command match both, with the permit dominating?":
`overrides`, from the shadowed-deny report). These export it and three more. `Contains` answers
only what it can decide. A regex or class term holds another only where it is the same term, and
`*` is held only by `*` or `**`. So a `false` never licenses anything. Dominance is read off term
ranks, which are the same on every command both rules match (spec §5.4). `NeverDominates` therefore
does not turn on whether two patterns really share a string, and `AlwaysDominates` refuses wherever
they only possibly meet.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/engine/contain_test.go -->
````diff
diff --git a/internal/engine/contain_test.go b/internal/engine/contain_test.go
new file mode 100644
index 0000000..c715c86
--- /dev/null
+++ b/internal/engine/contain_test.go
@@ -0,0 +1,59 @@
+package engine
+
+import "testing"
+
+func TestContains(t *testing.T) {
+	classes := map[string][]string{"management": {"^(fxp0|em0)$"}}
+	for _, c := range []struct {
+		outer, inner string
+		want         bool
+	}{
+		{"show **", "show configuration **", true},
+		{"show **", "show", true},
+		{"show configuration **", "show **", false},
+		{"show *", "show version", true},
+		{"show *", "show version detail", false},
+		{"show version", "SHOW VERSION", true},
+		{"**", "request system reboot", true},
+		{"show interfaces @management", "show interfaces fxp0", true},
+		{"show interfaces @management", "show interfaces ge-0/0/0", false},
+		{"show interfaces @management", "show interfaces *", false},
+		{"show interfaces @management", "show interfaces @management", true},
+		{"show interfaces /^fxp/", "show interfaces /^fxp0$/", false},
+		{"show interfaces *", "show interfaces @management", true},
+		{"show version", "show version **", false},
+		{"show version **", "show version", true},
+	} {
+		got, err := Contains(c.outer, c.inner, classes)
+		if err != nil || got != c.want {
+			t.Errorf("Contains(%q, %q) = %v, %v; want %v", c.outer, c.inner, got, err, c.want)
+		}
+	}
+}
+
+func TestMayMeetAndAlwaysDominates(t *testing.T) {
+	junos := Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}
+	for _, c := range []struct {
+		permit, deny string
+		meet, dom    bool
+	}{
+		// The spec's capability shape: a permit beneath a deny wins there.
+		{"show configuration interfaces **", "show configuration **", true, true},
+		// The refused shape: a deny beneath the permit.
+		{"show interfaces **", "show interfaces terse", true, false},
+		{"show version", "request system reboot", false, true},
+		// Incomparable: neither is more specific at every position.
+		{"show * detail", "show interfaces *", true, false},
+		// Two patterns meeting at one position: possible, never definite.
+		{"show interfaces /^ge-/", "show interfaces /-0$/", true, false},
+	} {
+		meet, err := MayMeet(c.permit, c.deny, nil, junos)
+		if err != nil || meet != c.meet {
+			t.Errorf("MayMeet(%q, %q) = %v, %v; want %v", c.permit, c.deny, meet, err, c.meet)
+		}
+		dom, err := AlwaysDominates(c.permit, c.deny, nil, junos)
+		if err != nil || dom != c.dom {
+			t.Errorf("AlwaysDominates(%q, %q) = %v, %v; want %v", c.permit, c.deny, dom, err, c.dom)
+		}
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/engine/`
Expected: FAIL, build failed: `undefined: Contains`, `undefined: MayMeet`, `undefined: AlwaysDominates`.

- [ ] **Step 3: Add the four functions**

<!-- patch: internal/engine/contain.go -->
````diff
diff --git a/internal/engine/contain.go b/internal/engine/contain.go
new file mode 100644
index 0000000..1dc7c19
--- /dev/null
+++ b/internal/engine/contain.go
@@ -0,0 +1,134 @@
+package engine
+
+import "strings"
+
+// Contains reports whether every command inner matches is matched by outer
+// too, both read as a permit reads them: as received, never widened (spec §3,
+// §4). It answers what it can decide from the terms and says false otherwise:
+// a regex or class term holds another only where it is the same term, and a
+// `*` is held only by `*` or `**`. So true is a proof and false may be a
+// containment it could not see, the direction a session-only projection
+// needs — a bit's reach it cannot prove held by a rule is never taken to be
+// (spec §8, "The projection model").
+func Contains(outer, inner string, classes map[string][]string) (bool, error) {
+	o, err := compileRule(Permit, outer, "", classes, Normalize{PipeToken: "|"})
+	if err != nil {
+		return false, err
+	}
+	in, err := compileRule(Permit, inner, "", classes, Normalize{PipeToken: "|"})
+	if err != nil {
+		return false, err
+	}
+	return contains(o[0], in[0]), nil
+}
+
+func contains(outer, inner compiled) bool {
+	of, orest := fixedLen(outer.terms)
+	nf, nrest := fixedLen(inner.terms)
+	switch {
+	case nrest && !orest:
+		// inner matches vectors of every length past nf; outer does not.
+		return false
+	case !orest && nf != of:
+		return false
+	case nf < of:
+		// outer requires terms inner may leave out.
+		return false
+	}
+	for i := 0; i < of; i++ {
+		if !termHolds(outer.terms[i], inner.terms[i]) {
+			return false
+		}
+	}
+	return true
+}
+
+// termHolds reports whether every argument term n takes, outer term o takes
+// too, read as received.
+func termHolds(o, n cterm) bool {
+	switch o.kind {
+	case Any, Rest:
+		return true
+	case Word:
+		return n.kind == Word && strings.EqualFold(o.word, n.word)
+	}
+	// o is a regex or a class.
+	switch n.kind {
+	case Word:
+		return anyMatch(o.res, n.word)
+	case o.kind:
+		return o.word == n.word
+	}
+	return false
+}
+
+// MayMeet reports whether some command may match both permit and deny, the
+// deny read as the platform's dialect n widens it (compileRule): true where
+// two patterns meet at one position and nobody can say cheaply whether they
+// share a string.
+func MayMeet(permit, deny string, classes map[string][]string, n Normalize) (bool, error) {
+	pm, ds, err := compilePair(permit, deny, classes, n)
+	if err != nil {
+		return false, err
+	}
+	for _, d := range ds {
+		if meets(pm, d, n.abbreviated()) {
+			return true, nil
+		}
+	}
+	return false, nil
+}
+
+// AlwaysDominates reports whether permit dominates deny on every command both
+// match (spec §5.4): wherever they meet, the permit is at least as specific
+// at every position and more at one, and nothing about it turns on two
+// patterns meeting. Rules that never meet are dominated vacuously. A
+// session-only projection emits a permit as a device allow only where this
+// holds for every deny, since on the device a matching allow beats any
+// matching deny (spec §8, L11).
+func AlwaysDominates(permit, deny string, classes map[string][]string, n Normalize) (bool, error) {
+	pm, ds, err := compilePair(permit, deny, classes, n)
+	if err != nil {
+		return false, err
+	}
+	abbrev := n.abbreviated()
+	for _, d := range ds {
+		if !meets(pm, d, abbrev) {
+			continue
+		}
+		if ok, possible := overrides(pm, d, abbrev); !ok || possible {
+			return false, nil
+		}
+	}
+	return true, nil
+}
+
+func compilePair(permit, deny string, classes map[string][]string, n Normalize) (compiled, []compiled, error) {
+	pm, err := compileRule(Permit, permit, "", classes, n)
+	if err != nil {
+		return compiled{}, nil, err
+	}
+	ds, err := compileRule(Deny, deny, "", classes, n)
+	if err != nil {
+		return compiled{}, nil, err
+	}
+	return pm[0], ds, nil
+}
+
+// NeverDominates reports whether permit dominates deny on no command both
+// match: wherever they meet, the deny stands. Which of two rules dominates is
+// read off their terms' ranks, the same on every command both match (spec
+// §5.4), so it does not turn on whether two patterns really share a string.
+func NeverDominates(permit, deny string, classes map[string][]string, n Normalize) (bool, error) {
+	pm, ds, err := compilePair(permit, deny, classes, n)
+	if err != nil {
+		return false, err
+	}
+	abbrev := n.abbreviated()
+	for _, d := range ds {
+		if ok, _ := overrides(pm, d, abbrev); ok {
+			return false, nil
+		}
+	}
+	return true, nil
+}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/contain.go internal/engine/contain_test.go
git commit -m "$(cat <<'EOF'
feat: rule containment and dominance a projection can prove with

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 6: The adapter declares a session-only platform's projection, bits and templates

**Files:**
- Modify: `internal/platform/dialect.go` (the new fields, constants and methods)
- Modify: `internal/platform/adapter.go` (the Spec keys, `Over`, `SpecOf`, `validateProjection`,
  `MonotoneBits`)
- Modify: `internal/policy/load.go` (`keepsProjection`; `checkBlockOrder` reads `local_user_names`
  and `MonotoneBits`)
- Test: `internal/platform/projection_test.go` (new), `internal/platform/adapter_test.go`,
  `internal/policy/projection_test.go` (new; Tasks 9–11 and 17 append to it)

**Interfaces:**
- Consumes: `engine.ParseRule`, `engine.Class`, `engine.Regex`; 5a's `Spec.Over`, `SpecOf`,
  `Validate`, `keepsSetClaims`, `checkBlockOrder`.
- Produces:
  - `Dialect` fields `CommandProjection string`, `Bits map[string][]string`, `BitDelivery string`,
    `LocalUserNames map[string]string`, and `CeilingBits map[string][]string` (the `privilege` key
    of a projected adapter).
  - Spec keys `command_projection`, `bits`, `bit_delivery`, `local_user_names` (`*string`,
    `*map[string][]string`, `*string`, `*map[string]string`).
  - `const ProjectionJunosRegex = "junos_regex"`, `BitDeliveryUserPermissions = "user_permissions"`,
    `BitDeliveryLocalUserName = "local_user_name"`, `RemoteClass = "p49-remote"`.
  - `func ProjectionAttributes(projection string) []string`, `func (Dialect) Projected() bool`,
    `func (Dialect) LevelBits(level string) ([]string, bool)`, and `func (Dialect) ExpandBits(bits
    []string) []string`, which reads `all` as every declared bit.
  - `func MonotoneBits(name string, d Dialect, order []string) error`.
  - In `internal/policy`'s tests: `projectedSet = "9.0.0"`, `projectedEnv(delivery string) Env`,
    `parseProjected(t, delivery, body string) *Policy`, `readonlyCarveOut`.

The projection's inputs become adapter data, validated as every adapter is. On a projected
platform, `privilege` is each level's ceiling in bits (Decided 2). Over routes it by the merged
`command_projection`, and the one Dialect field with no Spec key of its own is `CeilingBits`: the
field-count test says so. Validate requires the following of a projected adapter:
- `supports: [session]`, and no attribute levels;
- no `accepted_attributes`;
- every projection-owned name in `privilege_attributes`;
- a bit's reach made of words, `*` and `**` only;
- a known `bit_delivery`;
- under `local_user_name`, a template per level, a login-name shape, and one class per template.

A projection key on a platform that projects nothing is refused: it would read as enforced. In the
policy, a block over a set that projects keeps the projection and every rule of each bit's reach
(`keepsProjection`), and a level's ceiling bits rise with `privilege_levels` (`MonotoneBits`).
Nothing renders yet. Task 9 wires the policy, and until Task 13 no built-in adapter projects.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index ca27484..a884283 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -543,8 +543,9 @@ func TestSpecOfRoundTrips(t *testing.T) {
 		}
 	}
 	// A Dialect field with no Spec key would be one no block sets and the
-	// diff never compares (task 9 review M1).
-	if n, m := reflect.TypeOf(Dialect{}).NumField(), reflect.TypeOf(Spec{}).NumField(); n != m {
+	// diff never compares (task 9 review M1). CeilingBits is the one field
+	// that shares a key: `privilege`, on a projected platform (spec §8).
+	if n, m := reflect.TypeOf(Dialect{}).NumField(), reflect.TypeOf(Spec{}).NumField(); n != m+1 {
 		t.Fatalf("Dialect has %d fields and Spec %d keys", n, m)
 	}
 	keys := SpecKeys()
````

<!-- patch: internal/platform/projection_test.go -->
````diff
diff --git a/internal/platform/projection_test.go b/internal/platform/projection_test.go
new file mode 100644
index 0000000..e1c589b
--- /dev/null
+++ b/internal/platform/projection_test.go
@@ -0,0 +1,121 @@
+package platform
+
+import (
+	"reflect"
+	"strings"
+	"testing"
+)
+
+// junosProjected is a projected Junos adapter as a test writes one: spec §8's
+// example bits, readonly and admin ceilings, one template per level.
+func junosProjected(delivery string) Dialect {
+	base, _ := Generic(UnpinnedSet)
+	d := Spec{
+		Supports:            &[]string{"session"},
+		CommandProjection:   ptr(ProjectionJunosRegex),
+		BitDelivery:         ptr(delivery),
+		PrivilegeAttributes: ptr(ProjectionAttributes(ProjectionJunosRegex)),
+		Bits: &map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
+			"clear": {"clear **"}, "all": {"**"}},
+		Privilege: &map[string][]string{"readonly": {"view", "view-configuration"}, "admin": {"all"}},
+	}.Over(base)
+	if delivery == BitDeliveryLocalUserName {
+		d.LocalUserNames = map[string]string{"readonly": "p49-readonly", "admin": "p49-admin"}
+	}
+	return d
+}
+
+// On a projected platform `privilege` is each level's ceiling in bits: Over
+// routes it to CeilingBits, renders no attribute for a level, and SpecOf
+// writes it back under `privilege`, so export and the diff read it there.
+func TestProjectedPrivilegeIsBits(t *testing.T) {
+	d := junosProjected(BitDeliveryUserPermissions)
+	if d.Levels != nil || !reflect.DeepEqual(d.CeilingBits["readonly"], []string{"view", "view-configuration"}) {
+		t.Fatalf("levels %v, ceiling bits %v", d.Levels, d.CeilingBits)
+	}
+	if attrs, ok := d.Render("admin"); !ok || attrs != nil {
+		t.Errorf("a projected level renders no attribute of its own: %v %v", attrs, ok)
+	}
+	if err := Validate("juniper_junos", d); err != nil {
+		t.Fatal(err)
+	}
+	if got := SpecOf(d).Over(Dialect{}); !reflect.DeepEqual(got, d) {
+		t.Errorf("round trip:\n got %+v\nwant %+v", got, d)
+	}
+	block := Spec{Privilege: &map[string][]string{"operator": {"view", "clear"}}}.Over(d)
+	if !reflect.DeepEqual(block.CeilingBits["operator"], []string{"view", "clear"}) || block.Levels != nil {
+		t.Errorf("a block over a projected platform sets bits: %v %v", block.CeilingBits, block.Levels)
+	}
+	if got := d.ExpandBits([]string{"all"}); !reflect.DeepEqual(got, []string{"all", "clear", "view", "view-configuration"}) {
+		t.Errorf("all is every bit: %v", got)
+	}
+}
+
+func TestValidateRefusesABadProjection(t *testing.T) {
+	for _, c := range []struct {
+		name string
+		edit func(*Dialect)
+		want string
+	}{
+		{"unknown projection", func(d *Dialect) { d.CommandProjection = "junos" }, "command_projection"},
+		{"per command too", func(d *Dialect) { d.Supports = []string{"session", "commands"} }, "supports"},
+		{"no bits", func(d *Dialect) { d.Bits = nil }, "bits is required"},
+		{"a bit with a class", func(d *Dialect) { d.Bits["view"] = []string{"show interfaces @management"} },
+			"bits.view[0]: term 3"},
+		{"a ceiling naming no bit", func(d *Dialect) { d.CeilingBits["readonly"] = []string{"view", "vew"} },
+			"privilege.readonly[1]: vew"},
+		{"no delivery", func(d *Dialect) { d.BitDelivery = "" }, "bit_delivery"},
+		{"a projection name not bearing privilege", func(d *Dialect) {
+			d.PrivilegeAttributes = []string{"local-user-name"}
+		}, "user-permissions is missing"},
+		{"accepted attributes", func(d *Dialect) { d.AcceptedAttributes = []string{"local-user-name"} },
+			"accepted_attributes"},
+		{"templates under user_permissions", func(d *Dialect) { d.LocalUserNames = map[string]string{"admin": "a"} },
+			"read only under bit_delivery"},
+	} {
+		d := with(junosProjected(BitDeliveryUserPermissions), c.edit)
+		if err := Validate("juniper_junos", d); err == nil || !strings.Contains(err.Error(), c.want) {
+			t.Errorf("%s: %v, want %q", c.name, err, c.want)
+		}
+	}
+	for _, c := range []struct {
+		name string
+		edit func(*Dialect)
+		want string
+	}{
+		{"a level with no template", func(d *Dialect) { delete(d.LocalUserNames, "admin") }, "admin has no template"},
+		{"a template that is no login name", func(d *Dialect) { d.LocalUserNames["admin"] = "P49 Admin" },
+			"local_user_names.admin is not a login name"},
+		{"two levels, one template, two classes", func(d *Dialect) { d.LocalUserNames["admin"] = "p49-readonly" },
+			"share template p49-readonly"},
+		{"a template for a level with no bits", func(d *Dialect) { d.LocalUserNames["operator"] = "p49-operator" },
+			"operator has no bits"},
+	} {
+		d := with(junosProjected(BitDeliveryLocalUserName), c.edit)
+		if err := Validate("juniper_junos", d); err == nil || !strings.Contains(err.Error(), c.want) {
+			t.Errorf("%s: %v, want %q", c.name, err, c.want)
+		}
+	}
+	if err := Validate("juniper_junos", junosProjected(BitDeliveryLocalUserName)); err != nil {
+		t.Errorf("local_user_name: %v", err)
+	}
+	// A projection key nothing reads reads as enforced.
+	eos, _ := DialectFor("arista_eos")
+	eos.BitDelivery = BitDeliveryLocalUserName
+	if err := Validate("arista_eos", eos); err == nil || !strings.Contains(err.Error(), "read only with command_projection") {
+		t.Errorf("bit_delivery with no projection: %v", err)
+	}
+}
+
+func TestMonotoneBits(t *testing.T) {
+	order := []string{"readonly", "operator", "admin"}
+	d := junosProjected(BitDeliveryUserPermissions)
+	if err := MonotoneBits("juniper_junos", d, order); err != nil {
+		t.Fatalf("admin's all holds every bit: %v", err)
+	}
+	d.CeilingBits["operator"] = []string{"view", "clear"}
+	if err := MonotoneBits("juniper_junos", d, order); err == nil || !strings.Contains(err.Error(),
+		"privilege.readonly: view-configuration is not in operator's bits") {
+		t.Errorf("readonly above operator: %v", err)
+	}
+}
````

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
new file mode 100644
index 0000000..32107a7
--- /dev/null
+++ b/internal/policy/projection_test.go
@@ -0,0 +1,66 @@
+package policy
+
+import (
+	"strings"
+	"testing"
+
+	"github.com/rhwendt/port49/internal/platform"
+)
+
+// projectedSet is the test's second platform set: 1.0.0 with juniper_junos
+// projected as spec §8 writes it, the bits the lab measures standing in for
+// the ones platforms/1.1.0 ships.
+const projectedSet = "9.0.0"
+
+func projectedEnv(delivery string) Env {
+	e := env()
+	first, _ := platform.Set(platform.UnpinnedSet)
+	second, _ := platform.Set(platform.UnpinnedSet)
+	p, d := platform.ProjectionJunosRegex, delivery
+	spec := platform.Spec{CommandProjection: &p, BitDelivery: &d,
+		Bits: &map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
+			"clear": {"clear **"}, "network": {"ping **", "traceroute **"}, "all": {"**"}},
+		Privilege: &map[string][]string{"readonly": {"view", "view-configuration"},
+			"operator": {"view", "view-configuration", "clear", "network"}, "admin": {"all"}},
+		CeilingLevels: &map[string]uint8{"readonly": 1, "operator": 15, "admin": 15}}
+	if delivery == platform.BitDeliveryLocalUserName {
+		spec.LocalUserNames = &map[string]string{"readonly": "p49-readonly", "operator": "p49-operator",
+			"admin": "p49-admin"}
+	}
+	second["juniper_junos"] = spec.Over(second["juniper_junos"])
+	e.Sets = map[string]map[string]platform.Dialect{platform.UnpinnedSet: first, projectedSet: second}
+	return e
+}
+
+func parseProjected(t *testing.T, delivery, body string) *Policy {
+	t.Helper()
+	p, err := Parse([]byte("platform_set: "+projectedSet+"\n"+body), projectedEnv(delivery))
+	if err != nil {
+		t.Fatal(err)
+	}
+	return p
+}
+
+const readonlyCarveOut = scopeOK + `roles:
+  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}
+` + subjOK + grantOK
+
+// A block keeps the set's projection and every rule of a bit's reach, and a
+// level's ceiling bits rise with the policy's level order.
+func TestABlockKeepsTheProjection(t *testing.T) {
+	for _, c := range []struct{ block, want string }{
+		{"bits: {view: [\"show version\"]}", "a block may add to a bit's reach, not take from it"},
+		{"bits: {maintenance: [\"request system **\"]}", "a block may not add a bit"},
+		{"privilege: {readonly: [all]}", "privilege.readonly: all is not in operator's bits"},
+		{"local_user_names: {operator: p49-operator}", "read only under bit_delivery"},
+	} {
+		_, err := Parse([]byte("platform_set: "+projectedSet+"\nplatforms:\n  juniper_junos:\n    "+c.block+"\n"+
+			readonlyCarveOut), projectedEnv(platform.BitDeliveryUserPermissions))
+		if err == nil || !strings.Contains(err.Error(), c.want) {
+			t.Errorf("%s: %v", c.block, err)
+		}
+	}
+	// Adding to a bit's reach loads: it only trusts the bit less.
+	parseProjected(t, platform.BitDeliveryUserPermissions, "platforms:\n  juniper_junos:\n"+
+		"    bits: {view: [\"show **\", \"monitor **\"]}\n"+readonlyCarveOut)
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/`
Expected: FAIL, build failed: `unknown field CommandProjection in struct literal of type Spec`,
`undefined: ProjectionJunosRegex`, `undefined: ProjectionAttributes`, `d.LocalUserNames undefined`.

- [ ] **Step 3: Add the keys, their validation and the block floors**

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index cf6b650..06e5780 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -45,6 +45,10 @@ type Spec struct {
 	FallbackNote         *map[string]string   `yaml:"fallback_note,omitempty"`
 	LocalAccounts        *[]string            `yaml:"local_accounts,omitempty"`
 	ConfigChecks         *[]ConfigCheck       `yaml:"config_checks,omitempty"`
+	CommandProjection    *string              `yaml:"command_projection,omitempty"`
+	Bits                 *map[string][]string `yaml:"bits,omitempty"`
+	BitDelivery          *string              `yaml:"bit_delivery,omitempty"`
+	LocalUserNames       *map[string]string   `yaml:"local_user_names,omitempty"`
 }
 
 // ParseSpecs reads an adapter file: one YAML document whose one key is
@@ -80,9 +84,30 @@ func (s Spec) Over(base Dialect) Dialect {
 	if s.Supports != nil {
 		d.Supports = slices.Clone(*s.Supports)
 	}
-	if s.Privilege != nil {
+	if s.CommandProjection != nil {
+		d.CommandProjection = *s.CommandProjection
+	}
+	// On a projected platform `privilege` is each level's ceiling in bits
+	// (spec §8), read by the projection and never sent as attributes.
+	if s.Privilege != nil && d.Projected() {
+		d.CeilingBits = mergeLists(d.CeilingBits, *s.Privilege)
+	} else if s.Privilege != nil {
 		d.Levels = mergeLists(d.Levels, *s.Privilege)
 	}
+	if s.Bits != nil {
+		d.Bits = mergeLists(d.Bits, *s.Bits)
+	}
+	if s.BitDelivery != nil {
+		d.BitDelivery = *s.BitDelivery
+	}
+	if s.LocalUserNames != nil {
+		if d.LocalUserNames == nil {
+			d.LocalUserNames = map[string]string{}
+		}
+		for k, v := range *s.LocalUserNames {
+			d.LocalUserNames[k] = v
+		}
+	}
 	if s.CeilingLevels != nil {
 		if d.CeilingLevels == nil {
 			d.CeilingLevels = map[string]uint8{}
@@ -455,6 +480,9 @@ func Validate(name string, d Dialect) error {
 				field("config_checks"), i)
 		}
 	}
+	if err := validateProjection(field, d); err != nil {
+		return err
+	}
 	if !slices.Contains(verifications, d.Verified) {
 		return fmt.Errorf("%s is not containerlab, community, or unset", field("verified"))
 	}
@@ -639,6 +667,22 @@ func SpecOf(d Dialect) Spec {
 	if d.Levels != nil {
 		s.Privilege = &d.Levels
 	}
+	if d.Projected() {
+		s.CommandProjection = &d.CommandProjection
+		s.Privilege = nil
+		if d.CeilingBits != nil {
+			s.Privilege = &d.CeilingBits
+		}
+	}
+	if d.Bits != nil {
+		s.Bits = &d.Bits
+	}
+	if d.BitDelivery != "" {
+		s.BitDelivery = &d.BitDelivery
+	}
+	if d.LocalUserNames != nil {
+		s.LocalUserNames = &d.LocalUserNames
+	}
 	if d.CeilingLevels != nil {
 		s.CeilingLevels = &d.CeilingLevels
 	}
@@ -699,3 +743,154 @@ func SpecKeys() []string {
 	}
 	return out
 }
+
+// bitName is the shape of a permission bit's name, as Junos spells them
+// (`view-configuration`).
+var bitName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
+
+// templateName is the shape of a template user this build renders: what
+// Junos takes as a login name, lower case so no two differ only by case.
+var templateName = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
+
+// validateProjection is Validate for the projection keys (spec §8): a
+// projection this build renders, a session-only platform, `privilege` as
+// ceiling bits the adapter declares, each bit's reach in rule form, a
+// delivery, and a template per level where the delivery needs one. Where
+// there is no projection, none of the keys is set: a key nothing reads reads
+// as enforced.
+func validateProjection(field func(string) string, d Dialect) error {
+	if !d.Projected() {
+		for _, k := range []struct {
+			key string
+			set bool
+		}{{"bits", d.Bits != nil}, {"bit_delivery", d.BitDelivery != ""}, {"local_user_names", d.LocalUserNames != nil}} {
+			if k.set {
+				return fmt.Errorf("%s is read only with command_projection; set that, or remove the key", field(k.key))
+			}
+		}
+		return nil
+	}
+	if d.CommandProjection != ProjectionJunosRegex {
+		return fmt.Errorf("%s is not a projection this build renders; the one it renders is %s",
+			field("command_projection"), ProjectionJunosRegex)
+	}
+	if !slices.Equal(d.Supports, []string{"session"}) {
+		return fmt.Errorf("%s: a projected platform authorizes its sessions and nothing else, so supports is "+
+			"[session]; a platform that asks port49 about commands is answered per command (spec §8)", field("supports"))
+	}
+	if d.Levels != nil {
+		// Unreachable through a file: Over routes `privilege` to CeilingBits
+		// on a projected platform. A Dialect built by hand could carry both.
+		return fmt.Errorf("%s names permission bits on a projected platform, never attributes", field("privilege"))
+	}
+	if d.AcceptedAttributes != nil {
+		return fmt.Errorf("%s: a projected platform's reply is the projection's own names; remove the key",
+			field("accepted_attributes"))
+	}
+	for _, n := range ProjectionAttributes(d.CommandProjection) {
+		if !slices.Contains(d.PrivilegeAttributes, n) {
+			return fmt.Errorf("%s: %s is missing: the projection sends it, and it carries privilege (spec §8)",
+				field("privilege_attributes"), n)
+		}
+	}
+	if len(d.Bits) == 0 {
+		return fmt.Errorf("%s is required with command_projection: each permission bit's reach in rule form "+
+			"(spec §8)", field("bits"))
+	}
+	for k, bit := range sortedKeys(d.Bits) {
+		if !bitName.MatchString(bit) {
+			return fmt.Errorf("%s: bit %d in name order is not a permission bit's name", field("bits"), k+1)
+		}
+		if len(d.Bits[bit]) == 0 {
+			return fmt.Errorf("%s is empty: a bit that reaches nothing is not declared", field("bits."+bit))
+		}
+		for i, rule := range d.Bits[bit] {
+			terms, err := engine.ParseRule(rule)
+			if err != nil {
+				return fmt.Errorf("%s[%d]: %w", field("bits."+bit), i, err)
+			}
+			// A bit's reach is the device's: a class is a policy's names and a
+			// regex no containment can read (engine.Contains).
+			for j, t := range terms {
+				if t.Kind == engine.Class || t.Kind == engine.Regex {
+					return fmt.Errorf("%s[%d]: term %d: a bit's reach is words, `*` and `**`", field("bits."+bit), i, j+1)
+				}
+			}
+		}
+	}
+	switch d.BitDelivery {
+	case BitDeliveryUserPermissions, BitDeliveryLocalUserName:
+	default:
+		return fmt.Errorf("%s is %s or %s (spec §8)", field("bit_delivery"), BitDeliveryUserPermissions,
+			BitDeliveryLocalUserName)
+	}
+	for _, level := range sortedKeys(d.CeilingBits) {
+		seen := map[string]bool{}
+		for i, bit := range d.CeilingBits[level] {
+			if _, ok := d.Bits[bit]; !ok {
+				return fmt.Errorf("%s[%d]: %s is not a bit under bits", field("privilege."+level), i, bit)
+			}
+			if seen[bit] {
+				return fmt.Errorf("%s: %s is listed twice", field("privilege."+level), bit)
+			}
+			seen[bit] = true
+		}
+	}
+	if d.BitDelivery != BitDeliveryLocalUserName {
+		if d.LocalUserNames != nil {
+			return fmt.Errorf("%s is read only under bit_delivery: %s", field("local_user_names"), BitDeliveryLocalUserName)
+		}
+		return nil
+	}
+	byName := map[string]string{}
+	for _, level := range sortedKeys(d.CeilingBits) {
+		name, ok := d.LocalUserNames[level]
+		if !ok {
+			return fmt.Errorf("%s: level %s has no template user; bit_delivery: %s sends one per level", field(
+				"local_user_names"), level, BitDeliveryLocalUserName)
+		}
+		if !templateName.MatchString(name) {
+			return fmt.Errorf("%s is not a login name: lower case letters, digits, `.`, `-` and `_`, starting with "+
+				"a letter, at most 64", field("local_user_names."+level))
+		}
+		// One template is one class: two levels sharing it get the same bits.
+		if other, ok := byName[name]; ok && !slices.Equal(d.ExpandBits(d.CeilingBits[other]),
+			d.ExpandBits(d.CeilingBits[level])) {
+			return fmt.Errorf("%s: levels %s and %s share template %s and have different bits; one template is one "+
+				"class", field("local_user_names"), other, level, name)
+		}
+		byName[name] = level
+	}
+	for _, level := range sortedKeys(d.LocalUserNames) {
+		if _, ok := d.CeilingBits[level]; !ok {
+			return fmt.Errorf("%s: level %s has no bits under privilege", field("local_user_names"), level)
+		}
+	}
+	return nil
+}
+
+// MonotoneBits refuses a projected adapter whose ceiling bits do not rise
+// with order, the policy's levels lowest first: every bit a lower level's
+// ceiling holds, `all` read as every bit, a higher level's holds too. It is
+// Monotone for a platform whose levels are bits (spec §8).
+func MonotoneBits(name string, d Dialect, order []string) error {
+	var levels []string
+	for _, l := range order {
+		if _, ok := d.CeilingBits[l]; ok {
+			levels = append(levels, l)
+		}
+	}
+	for i, lower := range levels {
+		low := d.ExpandBits(d.CeilingBits[lower])
+		for _, higher := range levels[i+1:] {
+			high := d.ExpandBits(d.CeilingBits[higher])
+			for _, bit := range low {
+				if !slices.Contains(high, bit) {
+					return fmt.Errorf("platforms.%s.privilege.%s: %s is not in %s's bits, above it; a level's ceiling "+
+						"holds no bit the levels above it lack", name, lower, bit, higher)
+				}
+			}
+		}
+	}
+	return nil
+}
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index d0a6256..2e0afc8 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -146,6 +146,88 @@ type Dialect struct {
 	// ConfigChecks are configuration lines the spec says a device must not
 	// carry (§5.6, §6), each with what it costs: the same check names them.
 	ConfigChecks []ConfigCheck
+	// CommandProjection names how a session-only platform's rules are
+	// rendered into its session reply (spec §8, "Projection for session-only
+	// platforms"): ProjectionJunosRegex, or empty for none. Where it is set,
+	// the adapter's `privilege` is each level's ceiling in permission bits
+	// (CeilingBits), not attributes, and Levels is nil.
+	CommandProjection string
+	// Bits maps each permission bit the platform's classes carry to its reach
+	// in rule form: every command the bit lets a session run, as rules, an
+	// upper bound measured in the lab (spec §15, L12). The projection trusts
+	// a bit only as far as this says, so a reach that says less than the bit
+	// does would let the device run what port49 denies; a block may add to a
+	// bit's reach and never take from it (spec §8).
+	Bits map[string][]string
+	// BitDelivery is how the chosen bits reach the device (spec §8):
+	// BitDeliveryUserPermissions, `user-permissions=<bits>` per session over a
+	// bitless template, or BitDeliveryLocalUserName, `local-user-name=` one
+	// template per level whose class carries the level's bits.
+	BitDelivery string
+	// LocalUserNames maps a level to the device's template user for it under
+	// BitDeliveryLocalUserName; `port49 platform export --classes` renders
+	// each with its class.
+	LocalUserNames map[string]string
+	// CeilingBits maps a level to the permission bits that are its ceiling on
+	// a projected platform: the `privilege` key of such an adapter.
+	CeilingBits map[string][]string
+}
+
+// The command projections port49 renders (spec §8).
+const ProjectionJunosRegex = "junos_regex"
+
+// The ways bits reach a projected device (spec §8, "bit_delivery").
+const (
+	BitDeliveryUserPermissions = "user_permissions"
+	BitDeliveryLocalUserName   = "local_user_name"
+)
+
+// RemoteClass is the login class the reference configuration gives the
+// device's `remote` template user: no bits, so a session whose reply names no
+// template, or names one the device does not have, runs nothing a bit
+// reaches (spec §8; tests/lab/results/L18-juniper_*.md: an unknown template
+// degrades to `remote`).
+const RemoteClass = "p49-remote"
+
+// projectionAttributes are the reply attributes a projection renders and
+// owns on its platform: every name Junos documents for a login class's
+// template, bits and command and configuration regexes (spec §8). No role or
+// grant may set one on a projected platform, or it would stand beside, or
+// over, what the generator proved (Policy.checkAttributes).
+var projectionAttributes = map[string][]string{
+	ProjectionJunosRegex: {"local-user-name", "user-permissions", "allow-commands", "deny-commands",
+		"allow-configuration", "deny-configuration", "allow-commands-regexps", "deny-commands-regexps",
+		"allow-configuration-regexps", "deny-configuration-regexps"},
+}
+
+// ProjectionAttributes is the attribute names projection owns, copied; none
+// for no projection.
+func ProjectionAttributes(projection string) []string {
+	return slices.Clone(projectionAttributes[projection])
+}
+
+// Projected reports whether the platform's rules are rendered into its
+// session reply.
+func (d Dialect) Projected() bool { return d.CommandProjection != "" }
+
+// LevelBits returns the permission bits that are exactly this level's
+// ceiling on a projected platform, without following a parent chain (the
+// policy's to follow), and whether the adapter names the level.
+func (d Dialect) LevelBits(level string) ([]string, bool) {
+	bits, ok := d.CeilingBits[level]
+	return slices.Clone(bits), ok
+}
+
+// ExpandBits is bits with every bit `all` implies: on Junos the `all`
+// permission is every permission (spec §8), so a set holding it holds every
+// bit the adapter declares. The result is sorted and has no duplicates.
+func (d Dialect) ExpandBits(bits []string) []string {
+	if slices.Contains(bits, "all") {
+		bits = sortedKeys(d.Bits)
+	}
+	out := slices.Clone(bits)
+	slices.Sort(out)
+	return slices.Compact(out)
 }
 
 // ConfigCheck is one line a device's configuration must not carry: an RE2
@@ -269,9 +351,26 @@ func (d Dialect) clone() Dialect {
 	}
 	d.LocalAccounts = slices.Clone(d.LocalAccounts)
 	d.ConfigChecks = slices.Clone(d.ConfigChecks)
+	d.Bits = cloneLists(d.Bits)
+	d.CeilingBits = cloneLists(d.CeilingBits)
+	if d.LocalUserNames != nil {
+		d.LocalUserNames = maps.Clone(d.LocalUserNames)
+	}
 	return d
 }
 
+// cloneLists is a map of lists copied deep; nil stays nil.
+func cloneLists(m map[string][]string) map[string][]string {
+	if m == nil {
+		return nil
+	}
+	out := make(map[string][]string, len(m))
+	for k, v := range m {
+		out[k] = slices.Clone(v)
+	}
+	return out
+}
+
 // BearsPrivilege reports whether an attribute name may carry privilege on
 // this platform: every name but one measured inert (InertAttributes).
 func (d Dialect) BearsPrivilege(name string) bool { return !slices.Contains(d.InertAttributes, name) }
````

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index 28c6729..799d7f9 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -497,6 +497,9 @@ func keepsSetClaims(at, shippedAs string, d, ref platform.Dialect, version strin
 				shippedAs)
 		}
 	}
+	if err := keepsProjection(at, shippedAs, d, ref, version); err != nil {
+		return err
+	}
 	for _, c := range d.Supports {
 		if !slices.Contains(ref.Supports, c) {
 			return fmt.Errorf("%s.supports: %s is not a capability platform set %s measured on %s; a rule would read "+
@@ -531,6 +534,38 @@ func keepsSetClaims(at, shippedAs string, d, ref platform.Dialect, version strin
 	return nil
 }
 
+// keepsProjection refuses a merged adapter that loosens what the set's
+// projection rests on (spec §8): a projected platform stays projected by the
+// set's projection, since without it the device's own template decides and
+// no rule reaches the session; and a bit's reach is a floor, since a reach
+// that says less than the bit does lets the device run what port49 denies.
+// A block may add to a bit's reach, which only makes the projection trust the
+// bit less, and may not declare a bit the set did not measure.
+func keepsProjection(at, shippedAs string, d, ref platform.Dialect, version string) error {
+	if !ref.Projected() {
+		return nil
+	}
+	if d.CommandProjection != ref.CommandProjection {
+		return fmt.Errorf("%s.command_projection: platform set %s projects %s's rules as %s, and without it no rule "+
+			"reaches a session there; a block may not remove or change it (spec §8)", at, version, shippedAs,
+			ref.CommandProjection)
+	}
+	for _, bit := range sortedKeys(d.Bits) {
+		reach, measured := ref.Bits[bit]
+		if !measured {
+			return fmt.Errorf("%s.bits.%s: platform set %s does not declare this bit on %s, so its reach is "+
+				"unmeasured; a block may not add a bit (spec §8, §15 L12)", at, bit, version, shippedAs)
+		}
+		for _, rule := range reach {
+			if !slices.Contains(d.Bits[bit], rule) {
+				return fmt.Errorf("%s.bits.%s: a rule platform set %s measured in this bit's reach is missing; a "+
+					"block may add to a bit's reach, not take from it (spec §8)", at, bit, version)
+			}
+		}
+	}
+	return nil
+}
+
 // keepsRoleOrder refuses a merged adapter that ranks two values of a role
 // attribute the other way round from the set's adapter it stands for: the
 // diff gate reads a move down role_order as a lowering (spec §12), so a
@@ -720,7 +755,8 @@ func (p *Policy) checkBlockOrder(file) error {
 			key    string
 			levels []string
 		}{{"privilege", mapKeys(b.Privilege)}, {"ceiling_levels", mapKeys(b.CeilingLevels)},
-			{"unreachable", mapKeys(b.Unreachable)}, {"fallback", mapKeys(b.Fallback)}} {
+			{"unreachable", mapKeys(b.Unreachable)}, {"fallback", mapKeys(b.Fallback)},
+			{"local_user_names", mapKeys(b.LocalUserNames)}} {
 			for _, l := range entries.levels {
 				if !slices.Contains(p.levels, l) {
 					return fmt.Errorf("platforms.%s.%s.%s: level %s is not declared; the levels are %s", name,
@@ -731,6 +767,9 @@ func (p *Policy) checkBlockOrder(file) error {
 		if err := platform.Monotone(name, p.adapters[name], p.levels); err != nil {
 			return err
 		}
+		if err := platform.MonotoneBits(name, p.adapters[name], p.levels); err != nil {
+			return err
+		}
 	}
 	return nil
 }
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/adapter.go internal/platform/adapter_test.go internal/platform/dialect.go internal/platform/projection_test.go internal/policy/load.go internal/policy/projection_test.go
git commit -m "$(cat <<'EOF'
feat: the adapter declares a session-only platform's projection, bits and templates

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 7: A rule written as the Junos regex that matches what it matches

**Files:**
- Create: `internal/projection/ere.go` (the package's doc comment, `Facts`, `ruleERE`,
  `patternERE`, `bracket`)
- Test: `internal/projection/ere_test.go`

**Interfaces:**
- Consumes: `engine.ParseRule` and its term kinds; `regexp/syntax`.
- Produces, for Task 8:
  - `type Facts struct{ CaseSensitive, DenyMatchesExpanded bool }`;
  - `func ruleERE(rule string, classes map[string][]string, deny bool, f Facts) (string, error)`, a
    rule as an unanchored extended regex over a whole command line;
  - `var errUnwritable`.

A rule becomes an ERE over the command line: words joined by one space, `*` as `[^ ]+`, and a
trailing `**` as `( .*)?`. A word is printable ASCII with ERE's operators escaped. A word holding
`{`, `}`, `"` or `\` is refused, since a brace pair reads as a spec §6 placeholder, and the wire's
handling of a quote or a backslash is unmeasured. Where the device is case-sensitive, a deny's
letters are written in both cases (`[sS]`). An allow is written in lower case: it matches only
less, which fails closed.

A regex or class pattern is read as the matcher reads it, case-insensitive and unanchored unless
it anchors. It is carried only in the subset that reads the same in POSIX ERE: literals, bracket
expressions (over printable ASCII less the space, POSIX's `]`-first, `-`-last rules, runs as
ranges), `.` as `[^ ]`, grouping, alternation, `*`, `+`, `?`, a repeat of at most 8 written out,
and anchors at its two ends. Anything else is refused. The test checks the deny ERE with Go's
regexp, which reads this subset the same way.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/projection/ere_test.go -->
````diff
diff --git a/internal/projection/ere_test.go b/internal/projection/ere_test.go
new file mode 100644
index 0000000..b5cdbd7
--- /dev/null
+++ b/internal/projection/ere_test.go
@@ -0,0 +1,65 @@
+package projection
+
+import (
+	"errors"
+	"regexp"
+	"testing"
+)
+
+func TestRuleERE(t *testing.T) {
+	classes := map[string][]string{"management": {"^(fxp0|em0)$"}, "uplink": {"^et-0/0/[0-3]$", "^ae1$"}}
+	folded := Facts{CaseSensitive: true}
+	for _, c := range []struct {
+		rule string
+		deny bool
+		want string
+	}{
+		{"show version", false, "show version"},
+		{"show version", true, "[sS][hH][oO][wW] [vV][eE][rR][sS][iI][oO][nN]"},
+		{"SHOW Version", false, "show version"},
+		{"show interfaces **", false, "show interfaces( .*)?"},
+		{"**", false, ".*"},
+		{"show route *", false, "show route [^ ]+"},
+		{"file show /var/log/messages", false, `file show /var/log/messages`},
+		{"ping 10.0.0.1", false, `ping 10\.0\.0\.1`},
+		{"show interfaces @management", false, "show interfaces ((fxp0|em0))"},
+		{"show interfaces @uplink **", false, "show interfaces ((et-0/0/[0-3])|(ae1))( .*)?"},
+		{"show interfaces /^ge-/", false, "show interfaces (ge-)[^ ]*"},
+	} {
+		got, err := ruleERE(c.rule, classes, c.deny, folded)
+		if err != nil || got != c.want {
+			t.Errorf("ruleERE(%q, deny=%v) = %q, %v; want %q", c.rule, c.deny, got, err, c.want)
+		}
+	}
+	for _, rule := range []string{"echo {username}", `show "x"`, "show /\\bword/", "show café"} {
+		if _, err := ruleERE(rule, classes, true, folded); err == nil {
+			t.Errorf("ruleERE(%q) wrote it", rule)
+		}
+	}
+	// A class's bracket expression is POSIX: `]` first, `-` last, ranges
+	// for runs.
+	got, err := ruleERE("show interfaces /^[a-c\\]-]x$/", nil, false, Facts{})
+	if err != nil || got != "show interfaces ([]A-Ca-c-]x)" {
+		t.Errorf("bracket: %q %v", got, err)
+	}
+}
+
+// The ERE a deny is written as matches every spelling of the rule's words
+// port49 matches, in either case, and nothing past the rule's own shape: a
+// check with Go's regexp, which reads this subset of ERE the same way.
+func TestADenyERECoversEveryCase(t *testing.T) {
+	e, err := ruleERE("show configuration **", nil, true, Facts{CaseSensitive: true})
+	if err != nil {
+		t.Fatal(err)
+	}
+	re := regexp.MustCompile("^" + e + "$")
+	for line, want := range map[string]bool{"show configuration": true, "SHOW Configuration system": true,
+		"show configurations": false, "request show configuration": false} {
+		if re.MatchString(line) != want {
+			t.Errorf("%q: %v", line, !want)
+		}
+	}
+	if _, err := ruleERE("show é", nil, true, Facts{}); !errors.Is(err, errUnwritable) {
+		t.Errorf("non-ASCII: %v", err)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/projection/`
Expected: FAIL, build failed: `undefined: Facts`, `undefined: ruleERE`, `undefined: errUnwritable`.

- [ ] **Step 3: Add the translation**

<!-- patch: internal/projection/ere.go -->
````diff
diff --git a/internal/projection/ere.go b/internal/projection/ere.go
new file mode 100644
index 0000000..d435db2
--- /dev/null
+++ b/internal/projection/ere.go
@@ -0,0 +1,314 @@
+// Package projection renders a composition's command rules into the session
+// reply of a platform that never asks port49 about a command (spec §8,
+// "Projection for session-only platforms"; §13 decision 22). Junos is the
+// case it is built for: its login classes carry permission bits and two
+// command regexes, and a matching allow beats a matching deny from any origin
+// (§15, L11). The reply is computed from the composed rules, never per role,
+// and it is proven not to let the device run a command port49 would deny
+// before it is sent; what cannot be proven is refused, and the policy with it
+// on that platform.
+package projection
+
+import (
+	"errors"
+	"fmt"
+	"regexp/syntax"
+	"strings"
+	"unicode"
+
+	"github.com/rhwendt/port49/internal/engine"
+)
+
+// Facts are what a projection's device was measured doing with a command
+// regex (spec §15, L9). Each is read in the direction that fails closed until
+// a lab note says otherwise.
+type Facts struct {
+	// CaseSensitive: the device matches a regex against the command in the
+	// case it was typed, so a deny spells each letter in both cases. A deny
+	// that matched only one case would let `SHOW CONFIGURATION` past a deny
+	// of `show configuration`, where port49 compares case-insensitively
+	// (spec §3 rule 3).
+	CaseSensitive bool
+	// DenyMatchesExpanded: the device matches a deny regex against the
+	// command with its words expanded, `sh conf` as `show configuration`.
+	// Where it does not, a deny of anything narrower than every command is
+	// walked past by abbreviating it, so no deny but `.*` is sent (spec §3
+	// rule 4).
+	DenyMatchesExpanded bool
+}
+
+// ereLiteral are the runes ERE reads as operators outside a bracket
+// expression, escaped with a backslash. `{`, `}`, `"` and `\` are refused
+// rather than escaped: a brace pair is read as a spec §6 placeholder by the
+// attribute check, and the wire's handling of a quote or a backslash in an
+// attribute value is unmeasured.
+const ereLiteral = `.[]()*+?|^$`
+
+// errUnwritable is a rule the device's regex cannot carry faithfully.
+var errUnwritable = errors.New("unwritable")
+
+// ruleERE is one rule as an extended regex over a whole command line, words
+// joined by one space, without anchors: `show interfaces **` is
+// `show interfaces( .*)?`. deny says which side of the reply it lands on: a
+// deny's literals match every case where the device matches case-sensitively,
+// and an allow's match only the lower case, which the device takes at least.
+func ruleERE(rule string, classes map[string][]string, deny bool, f Facts) (string, error) {
+	terms, err := engine.ParseRule(rule)
+	if err != nil {
+		return "", err
+	}
+	var b strings.Builder
+	for i, t := range terms {
+		if t.Kind == engine.Rest {
+			if i == 0 {
+				b.WriteString(".*")
+			} else {
+				b.WriteString("( .*)?")
+			}
+			break
+		}
+		if i > 0 {
+			b.WriteByte(' ')
+		}
+		switch t.Kind {
+		case engine.Any:
+			b.WriteString("[^ ]+")
+		case engine.Word:
+			w, err := wordERE(t.Text, deny, f)
+			if err != nil {
+				return "", fmt.Errorf("term %d: %w", i+1, err)
+			}
+			b.WriteString(w)
+		case engine.Regex, engine.Class:
+			patterns := []string{t.Text}
+			if t.Kind == engine.Class {
+				patterns = classes[t.Text]
+			}
+			if len(patterns) == 0 {
+				return "", fmt.Errorf("term %d: @%s has no pattern on this platform", i+1, t.Text)
+			}
+			var alts []string
+			for k, p := range patterns {
+				e, err := patternERE(p, deny, f)
+				if err != nil {
+					return "", fmt.Errorf("term %d, pattern %d: %w", i+1, k+1, err)
+				}
+				alts = append(alts, e)
+			}
+			if len(alts) == 1 {
+				b.WriteString(alts[0])
+			} else {
+				b.WriteString("(" + strings.Join(alts, "|") + ")")
+			}
+		}
+	}
+	return b.String(), nil
+}
+
+// wordERE is a literal word: printable ASCII only, since the device's
+// command line is, and no rune the wire or the attribute check reads.
+func wordERE(w string, deny bool, f Facts) (string, error) {
+	var b strings.Builder
+	for _, r := range w {
+		switch {
+		case r < 0x21 || r > 0x7e:
+			return "", fmt.Errorf("%w: a word holds a rune that is not printable ASCII", errUnwritable)
+		case strings.ContainsRune(`{}"\`, r):
+			return "", fmt.Errorf("%w: a word holds %q, which the reply cannot carry", errUnwritable, r)
+		case strings.ContainsRune(ereLiteral, r):
+			b.WriteByte('\\')
+			b.WriteRune(r)
+		default:
+			b.WriteString(letter(r, deny, f))
+		}
+	}
+	return b.String(), nil
+}
+
+// letter is one literal rune: a deny's letter in both cases where the device
+// is case-sensitive, anything else lower case.
+func letter(r rune, deny bool, f Facts) string {
+	lo, up := unicode.ToLower(r), unicode.ToUpper(r)
+	if deny && f.CaseSensitive && lo != up {
+		return "[" + string(lo) + string(up) + "]"
+	}
+	return string(lo)
+}
+
+// patternERE is an RE2 pattern from a regex term or an entity class, read
+// as the matcher reads it — case-insensitive, and matching the argument
+// anywhere unless it anchors (engine.compileTerm) — as an ERE over that one
+// argument: no space, since an argument has none. It takes literals, bracket
+// expressions, `.`, grouping, alternation, `*`, `+`, `?`, a bounded repeat
+// written out, and anchors at the pattern's two ends; anything else refuses
+// the pattern rather than guessing at the device's dialect (spec §8,
+// "Anchoring is a per-platform property"; §15 L9).
+func patternERE(pattern string, deny bool, f Facts) (string, error) {
+	re, err := syntax.Parse("(?i)"+pattern, syntax.Perl)
+	if err != nil {
+		return "", err
+	}
+	re = re.Simplify()
+	lead, trail := "[^ ]*", "[^ ]*"
+	if re.Op == syntax.OpConcat && len(re.Sub) > 0 {
+		subs := re.Sub
+		if subs[0].Op == syntax.OpBeginText {
+			lead, subs = "", subs[1:]
+		}
+		if n := len(subs); n > 0 && subs[n-1].Op == syntax.OpEndText {
+			trail, subs = "", subs[:n-1]
+		}
+		re = &syntax.Regexp{Op: syntax.OpConcat, Sub: subs, Flags: re.Flags}
+	}
+	body, err := ere(re, deny, f)
+	if err != nil {
+		return "", err
+	}
+	return lead + "(" + body + ")" + trail, nil
+}
+
+func ere(re *syntax.Regexp, deny bool, f Facts) (string, error) {
+	switch re.Op {
+	case syntax.OpEmptyMatch:
+		return "", nil
+	case syntax.OpLiteral:
+		var b strings.Builder
+		for _, r := range re.Rune {
+			s, err := wordERE(string(r), deny, f)
+			if err != nil {
+				return "", err
+			}
+			if re.Flags&syntax.FoldCase == 0 {
+				// A literal the pattern made case-sensitive: an allow may take
+				// it as written; a deny policy refuses a (?-i) (checkRule).
+				s = string(r)
+				if strings.ContainsRune(ereLiteral, r) {
+					s = `\` + s
+				}
+			}
+			b.WriteString(s)
+		}
+		return b.String(), nil
+	case syntax.OpCharClass:
+		return bracket(re.Rune, deny)
+	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
+		return "[^ ]", nil
+	case syntax.OpCapture:
+		s, err := ere(re.Sub[0], deny, f)
+		return "(" + s + ")", err
+	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
+		s, err := ere(re.Sub[0], deny, f)
+		op := map[syntax.Op]string{syntax.OpStar: "*", syntax.OpPlus: "+", syntax.OpQuest: "?"}[re.Op]
+		return "(" + s + ")" + op, err
+	case syntax.OpRepeat:
+		// A brace is read as a placeholder by the attribute check, so a
+		// bounded repeat is written out; an unbounded one is n copies and a star.
+		if re.Max > 8 || (re.Max < 0 && re.Min > 8) {
+			return "", fmt.Errorf("%w: a repeat above 8", errUnwritable)
+		}
+		s, err := ere(re.Sub[0], deny, f)
+		if err != nil {
+			return "", err
+		}
+		out := strings.Repeat("("+s+")", re.Min)
+		if re.Max < 0 {
+			return out + "(" + s + ")*", nil
+		}
+		return out + strings.Repeat("("+s+")?", re.Max-re.Min), nil
+	case syntax.OpConcat:
+		var b strings.Builder
+		for _, sub := range re.Sub {
+			s, err := ere(sub, deny, f)
+			if err != nil {
+				return "", err
+			}
+			b.WriteString(s)
+		}
+		return b.String(), nil
+	case syntax.OpAlternate:
+		alts := make([]string, len(re.Sub))
+		for i, sub := range re.Sub {
+			s, err := ere(sub, deny, f)
+			if err != nil {
+				return "", err
+			}
+			alts[i] = s
+		}
+		return strings.Join(alts, "|"), nil
+	}
+	return "", fmt.Errorf("%w: the pattern uses an operator the device's regex is not measured to take", errUnwritable)
+}
+
+// bracket is a character class as a POSIX bracket expression over printable
+// ASCII less the space, which no argument holds. A class that also admits a
+// rune past ASCII is `[^ ]` in a deny, which matches more, and loses that
+// rune in an allow, which matches less: each the side that fails closed.
+func bracket(ranges []rune, deny bool) (string, error) {
+	in := func(r rune) bool {
+		for i := 0; i+1 < len(ranges); i += 2 {
+			if ranges[i] <= r && r <= ranges[i+1] {
+				return true
+			}
+		}
+		return false
+	}
+	beyond := false
+	for i := 0; i+1 < len(ranges); i += 2 {
+		if ranges[i+1] > 0x7e {
+			beyond = true
+		}
+	}
+	if deny && beyond {
+		return "[^ ]", nil
+	}
+	var set []rune
+	for r := rune(0x21); r <= 0x7e; r++ {
+		if in(r) && !strings.ContainsRune(`{}"\`, r) {
+			set = append(set, r)
+		}
+	}
+	if len(set) == 0 {
+		return "", fmt.Errorf("%w: a character class with nothing printable in it", errUnwritable)
+	}
+	if len(set) == 1 {
+		return wordERE(string(set), false, Facts{})
+	}
+	// POSIX: `]` first, `-` last, `^` anywhere but first; runs of three or
+	// more of the rest as a range. A backslash is literal inside brackets,
+	// and none is ever in one (refused above).
+	special := func(r rune) bool { return r == ']' || r == '-' || r == '^' }
+	var head, body, tail string
+	for i := 0; i < len(set); {
+		r := set[i]
+		switch r {
+		case ']':
+			head = "]"
+			i++
+			continue
+		case '-':
+			tail = "-"
+			i++
+			continue
+		case '^':
+			tail = "^" + tail
+			i++
+			continue
+		}
+		j := i
+		for j+1 < len(set) && set[j+1] == set[j]+1 && !special(set[j+1]) {
+			j++
+		}
+		if j-i >= 2 {
+			body += string(r) + "-" + string(set[j])
+		} else {
+			body += string(set[i : j+1])
+		}
+		i = j + 1
+	}
+	if strings.HasPrefix(tail, "^") && head == "" && body == "" {
+		// `^` and `-` alone: `^` may not open the expression.
+		tail = strings.TrimPrefix(tail, "^") + "^"
+		return "[" + tail + "]", nil
+	}
+	return "[" + head + body + tail + "]", nil
+}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/projection/ere.go internal/projection/ere_test.go
git commit -m "$(cat <<'EOF'
feat: a rule written as the Junos regex that matches what it matches

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 8: The Junos projection, proven before it is sent (decision 22)

**Files:**
- Create: `internal/projection/project.go`, `internal/projection/model.go`
- Test: `internal/projection/project_test.go`

**Interfaces:**
- Consumes: Task 5's `engine.Contains`, `MayMeet`, `AlwaysDominates`, `NeverDominates`; Task 6's
  `Dialect.Bits`, `ExpandBits`, `BitDelivery`, `platform.RemoteClass`; Task 7's `ruleERE`, `Facts`;
  `engine.Compile`, `engine.Probes`, `engine.CheckAttribute`, `engine.MaxAttribute`.
- Produces, for Tasks 9–11 and 18:
  - `const ShapeCapability = "capability"`, `ShapeNarrow = "narrow"`;
  - `var JunosFacts = Facts{CaseSensitive: true, DenyMatchesExpanded: false}` and `func
    FactsFor(projection string) Facts`;
  - `type Input struct{ Platform string; Dialect platform.Dialect; Level string; Bits []string;
    Template string; Rules []engine.Rule; Classes map[string][]string; Normalize engine.Normalize;
    Secret func(rule string) bool; Facts Facts }`;
  - `type Result struct{ Shape string; Bits []string; Template string; Attributes []string; Denies,
    Allows, Omitted, Beyond []engine.Rule }`, with `(Result).Device(vector []string) bool` and
    `(Result).Narrower(max int) [][]string`;
  - `type Refusal struct{ Why, Attribute, Value, Class string }` (an error);
  - `func Project(in Input) (Result, error)`.

`Project` renders one composition and proves it (Decided 3).
- **Capability shape.**
  - Under `user_permissions`, the bits are the ceiling's usable bits, less those a deny aligns
    with; `all` is sent alone.
  - Under `local_user_name`, the template's class carries every ceiling bit, so each must be
    usable.
  - A permit is sent as an allow only where the bits do not carry it, or where it dominates a
    deny, and then only within the ceiling (`within`, carve-outs counted) and only where it
    dominates every deny it meets (`allowable`). Otherwise the composition is the refused shape,
    named with both rules.
  - A deny the bits already refuse is `Omitted`.
  - With a deny left to send and a device that may not expand abbreviations, the shape goes
    narrow.
- **Narrow shape.** `deny-commands=^.*$` and one allow alternation of the permits within the
  ceiling. Under `user_permissions` it takes the fewest ceiling bits that reach them (greedy);
  under `local_user_name`, the template's.
- **Guards.**
  - Bits that enter configuration mode go only to a grant of everything with no deny (Decided 6).
  - A rule redaction would hide is refused (Decided 7).
  - Every attribute is mandatory and within 255 bytes. Past that the result is a `Refusal`
    carrying the attribute, its value and the class that would hold it.
- **The witness.** The model decides every probe `engine.Probes` draws from the port49, allow,
  deny and bits programs. A vector the device would run and port49 would deny is a defect, and
  nothing is sent.

The tests are spec §8's own examples. The realistic readonly drops `view-configuration` and sends
`user-permissions=view` alone. `read_only_limited` is `deny .*` plus `(show version|show
interfaces( .*)?|show route( .*)?)`. The refused shape is `show interfaces **` over `show interfaces
terse`. The operator, with `network` unusable because nothing permits `traceroute`, sends `ping`
as an allow. With abbreviations unmeasured, the same operator is refused.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/projection/project_test.go -->
````diff
diff --git a/internal/projection/project_test.go b/internal/projection/project_test.go
new file mode 100644
index 0000000..13c9437
--- /dev/null
+++ b/internal/projection/project_test.go
@@ -0,0 +1,209 @@
+package projection
+
+import (
+	"errors"
+	"reflect"
+	"strings"
+	"testing"
+
+	"github.com/rhwendt/port49/internal/engine"
+	"github.com/rhwendt/port49/internal/platform"
+)
+
+// junos is a projected Junos adapter as the tests read one: spec §8's bits,
+// and the levels' ceilings.
+func junos(delivery string) platform.Dialect {
+	d := platform.Dialect{Supports: []string{"session"}, PipeToken: "|", StripCR: true,
+		CommandProjection: platform.ProjectionJunosRegex, BitDelivery: delivery,
+		Bits: map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
+			"clear": {"clear **"}, "network": {"ping **", "traceroute **"}, "configure": {"configure **"},
+			"all": {"**"}},
+		CeilingBits: map[string][]string{"readonly": {"view", "view-configuration"},
+			"operator": {"view", "view-configuration", "clear", "network"}, "admin": {"all"}}}
+	if delivery == platform.BitDeliveryLocalUserName {
+		d.LocalUserNames = map[string]string{"readonly": "p49-readonly", "operator": "p49-operator", "admin": "p49-admin"}
+	}
+	return d
+}
+
+var measured = Facts{CaseSensitive: true, DenyMatchesExpanded: true}
+
+func input(delivery, level string, f Facts, rules ...engine.Rule) Input {
+	d := junos(delivery)
+	return Input{Platform: "juniper_junos", Dialect: d, Level: level, Bits: d.CeilingBits[level],
+		Template: d.LocalUserNames[level], Rules: rules,
+		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}, Facts: f}
+}
+
+func permit(rule string) engine.Rule {
+	return engine.Rule{Verdict: engine.Permit, Rule: rule, Role: "r"}
+}
+func deny(rule string) engine.Rule { return engine.Rule{Verdict: engine.Deny, Rule: rule, Role: "d"} }
+
+// Spec §8's realistic readonly: a deny aligned with a bit drops the bit and
+// sends nothing for the deny.
+func TestADenyAlignedWithABitDropsIt(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
+		permit("show **"), deny("show configuration **")))
+	if err != nil {
+		t.Fatal(err)
+	}
+	if res.Shape != ShapeCapability || !reflect.DeepEqual(res.Attributes, []string{"user-permissions=view"}) ||
+		len(res.Omitted) != 1 {
+		t.Fatalf("%+v", res)
+	}
+	if res.Device([]string{"show", "configuration"}) || !res.Device([]string{"show", "version"}) {
+		t.Error("the device model disagrees with the reply")
+	}
+}
+
+// Under a template the class carries every bit of the level, so the deny
+// travels as a regex.
+func TestATemplateCarriesTheLevelsBits(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryLocalUserName, "readonly", measured,
+		permit("show **"), deny("show configuration **")))
+	if err != nil {
+		t.Fatal(err)
+	}
+	want := []string{"local-user-name=p49-readonly",
+		"deny-commands=^[sS][hH][oO][wW] [cC][oO][nN][fF][iI][gG][uU][rR][aA][tT][iI][oO][nN]( .*)?$"}
+	if !reflect.DeepEqual(res.Attributes, want) {
+		t.Fatalf("%q", res.Attributes)
+	}
+}
+
+// A permit beneath a deny dominates it in port49, so it travels as an allow,
+// which beats the deny on the device too (L11).
+func TestAPermitBeneathADenyIsAnAllow(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
+		permit("show **"), deny("show configuration **"), permit("show configuration interfaces **")))
+	if err != nil {
+		t.Fatal(err)
+	}
+	if len(res.Denies) != 1 || len(res.Allows) != 1 ||
+		res.Attributes[2] != "allow-commands=^show configuration interfaces( .*)?$" {
+		t.Fatalf("%q", res.Attributes)
+	}
+	if !res.Device([]string{"show", "configuration", "interfaces", "fxp0"}) ||
+		res.Device([]string{"show", "configuration", "system"}) {
+		t.Error("device model")
+	}
+}
+
+// Spec §8's read_only_limited: permits narrower than every bit render as
+// deny .* and one allow alternation, under the bits that reach them.
+func TestANarrowGrantIsDenyAllAndOneAllow(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
+		permit("show version"), permit("show interfaces **"), permit("show route **")))
+	if err != nil {
+		t.Fatal(err)
+	}
+	want := []string{"user-permissions=view", "deny-commands=^.*$",
+		"allow-commands=^(show version|show interfaces( .*)?|show route( .*)?)$"}
+	if res.Shape != ShapeNarrow || !reflect.DeepEqual(res.Attributes, want) {
+		t.Fatalf("%s %q", res.Shape, res.Attributes)
+	}
+}
+
+// The refused shape names the two rules and the platform.
+func TestTheRefusedShapeNamesBothRules(t *testing.T) {
+	_, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
+		permit("show interfaces **"), deny("show interfaces terse")))
+	var r *Refusal
+	if !errors.As(err, &r) || !strings.Contains(r.Why, `permit "show interfaces **"`) ||
+		!strings.Contains(r.Why, `deny "show interfaces terse"`) || !strings.Contains(r.Why, "juniper_junos") {
+		t.Fatalf("%v", err)
+	}
+}
+
+// A permit no ceiling bit reaches is never sent: the device refuses it where
+// port49 would permit it, which fails closed, and CI says so.
+func TestAPermitBeyondTheCeilingIsNotSent(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
+		permit("show **"), permit("clear counters")))
+	if err != nil {
+		t.Fatal(err)
+	}
+	if len(res.Beyond) != 1 || res.Beyond[0].Rule != "clear counters" || len(res.Allows) != 0 {
+		t.Fatalf("%+v", res)
+	}
+	if n := res.Narrower(5); len(n) != 1 || strings.Join(n[0], " ") != "clear counters" {
+		t.Errorf("narrower: %q", n)
+	}
+}
+
+func TestAdmin(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**")))
+	if err != nil || !reflect.DeepEqual(res.Attributes, []string{"user-permissions=all"}) {
+		t.Fatalf("%q %v", res.Attributes, err)
+	}
+	// A deny under bits that enter configuration mode cannot be carried: a
+	// statement there is no command the regexes reach.
+	_, err = Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**"),
+		deny("request system reboot **")))
+	var r *Refusal
+	if !errors.As(err, &r) || !strings.Contains(r.Why, "enters configuration mode") {
+		t.Fatalf("%v", err)
+	}
+}
+
+func TestOperator(t *testing.T) {
+	rules := []engine.Rule{permit("show **"), permit("clear **"), permit("ping **"), deny("clear bgp **")}
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "operator", measured, rules...))
+	if err != nil {
+		t.Fatal(err)
+	}
+	// network also reaches traceroute, which nothing permits: ping goes as an
+	// allow instead of the bit.
+	if !reflect.DeepEqual(res.Bits, []string{"clear", "view", "view-configuration"}) || len(res.Allows) != 1 ||
+		res.Allows[0].Rule != "ping **" || len(res.Denies) != 1 {
+		t.Fatalf("%+v", res)
+	}
+	// Where a deny can be walked past by abbreviating it, only .* is sent, and
+	// the operator's shape is refused: clear ** would beat clear bgp **.
+	_, err = Project(input(platform.BitDeliveryUserPermissions, "operator", Facts{CaseSensitive: true}, rules...))
+	if !errors.As(err, new(*Refusal)) {
+		t.Fatalf("%v", err)
+	}
+}
+
+func TestNoLevelIsDenyAll(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "", measured, permit("show **")))
+	if err != nil || !reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$"}) || len(res.Beyond) != 1 {
+		t.Fatalf("%q %v", res.Attributes, err)
+	}
+}
+
+func TestSecretsAndBudget(t *testing.T) {
+	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
+		deny("show snmp community hunter2"))
+	in.Secret = func(rule string) bool { return strings.Contains(rule, "hunter2") }
+	if _, err := Project(in); err == nil || !strings.Contains(err.Error(), "redaction hides") {
+		t.Fatalf("secret: %v", err)
+	}
+	var rules []engine.Rule
+	rules = append(rules, permit("show **"))
+	for _, w := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"} {
+		rules = append(rules, deny("show "+w+" **"))
+	}
+	_, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, rules...))
+	var r *Refusal
+	if !errors.As(err, &r) || r.Attribute != "deny-commands" || !strings.HasPrefix(r.Value, "^(") {
+		t.Fatalf("over budget: %v", err)
+	}
+}
+
+// A permit a bit outside the ceiling carves out of a bit inside it is beyond
+// the ceiling: an allow for it would run what the level's bits do not.
+func TestACarvedPermitIsBeyondTheCeiling(t *testing.T) {
+	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
+		deny("show configuration **"), permit("show configuration interfaces **"))
+	in.Bits = []string{"view"}
+	res, err := Project(in)
+	if err != nil {
+		t.Fatal(err)
+	}
+	if len(res.Allows) != 0 || len(res.Beyond) != 1 || res.Beyond[0].Rule != "show configuration interfaces **" {
+		t.Fatalf("%+v", res)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/projection/`
Expected: FAIL, build failed: `undefined: Input`, `undefined: Project`, `undefined: ShapeCapability`,
`undefined: Refusal`.

- [ ] **Step 3: Add the generator and the device model**

<!-- patch: internal/projection/model.go -->
````diff
diff --git a/internal/projection/model.go b/internal/projection/model.go
new file mode 100644
index 0000000..6ce2ccf
--- /dev/null
+++ b/internal/projection/model.go
@@ -0,0 +1,118 @@
+package projection
+
+import (
+	"slices"
+
+	"github.com/rhwendt/port49/internal/engine"
+)
+
+// model is the device's decision under a reply, as spec §8 measured it: a
+// command runs where a matching allow beats every deny, or where the bits
+// reach it and no deny matches (L11). Each part is an engine program over the
+// same rules the reply's regexes were written from, so the check below reads
+// the reply exactly as the translation promises the device reads it.
+type model struct {
+	port, allow, deny, bits *engine.Program
+}
+
+func (g generator) model(res Result) (*model, error) {
+	prog := func(rules []engine.Rule) (*engine.Program, error) {
+		return engine.Compile(engine.Blob{Version: engine.Version, Bundle: "projection", Platform: g.in.Platform,
+			Normalize: g.in.Normalize, Rules: rules, Classes: g.in.Classes, Pipe: []string{}})
+	}
+	var m model
+	var err error
+	if m.port, err = prog(g.in.Rules); err != nil {
+		return nil, err
+	}
+	allows := make([]engine.Rule, len(res.Allows))
+	for i, a := range res.Allows {
+		allows[i] = engine.Rule{Verdict: engine.Permit, Rule: a.Rule, Role: a.Role}
+	}
+	if m.allow, err = prog(allows); err != nil {
+		return nil, err
+	}
+	denies := slices.Clone(res.Denies)
+	if res.Shape == ShapeNarrow {
+		denies = []engine.Rule{{Verdict: engine.Deny, Rule: "**", Role: "projection"}}
+	}
+	if m.deny, err = prog(denies); err != nil {
+		return nil, err
+	}
+	// The bits: each reach rule of a bit held as a permit, of a bit not held
+	// as a deny, so the most specific decides, as it does in a class.
+	var bits []engine.Rule
+	held := g.in.Dialect.ExpandBits(res.Bits)
+	for _, b := range sortedKeys(g.in.Dialect.Bits) {
+		verdict := engine.Deny
+		if slices.Contains(held, b) {
+			verdict = engine.Permit
+		}
+		for _, r := range g.in.Dialect.Bits[b] {
+			bits = append(bits, engine.Rule{Verdict: verdict, Rule: r, Role: b})
+		}
+	}
+	if m.bits, err = prog(bits); err != nil {
+		return nil, err
+	}
+	return &m, nil
+}
+
+func raw(vector []string) []string {
+	out := []string{"cmd=" + vector[0]}
+	for _, a := range vector[1:] {
+		out = append(out, "cmd-arg="+a)
+	}
+	return out
+}
+
+// device is whether the device runs vector under the reply.
+func (m *model) device(vector []string) bool {
+	r := raw(vector)
+	if len(m.allow.Command(r).Permits) > 0 {
+		return true
+	}
+	return m.bits.Command(r).Permit && len(m.deny.Command(r).Denies) == 0
+}
+
+// unsound is a command the device would run and port49 would deny, among one
+// vector per way the rules can be told apart (engine.Probes).
+func (m *model) unsound() ([]string, bool) {
+	for _, v := range engine.Probes(m.port, m.allow, m.deny, m.bits) {
+		if len(v) == 0 {
+			continue
+		}
+		if m.device(v) && !m.port.Command(raw(v)).Permit {
+			return v, true
+		}
+	}
+	return nil, false
+}
+
+// Narrower lists up to max commands port49 permits and the device, under the
+// reply, does not: what CI reports as the reply's shortfall (spec §8).
+func (r Result) Narrower(max int) [][]string {
+	if r.model == nil {
+		return nil
+	}
+	var out [][]string
+	for _, v := range engine.Probes(r.model.port, r.model.allow, r.model.deny, r.model.bits) {
+		if len(v) == 0 || slices.Contains(v, engine.OtherArgument) {
+			continue
+		}
+		if r.model.port.Command(raw(v)).Permit && !r.model.device(v) {
+			out = append(out, v)
+			if len(out) == max {
+				break
+			}
+		}
+	}
+	return out
+}
+
+// Device reports whether the device runs vector under the reply: what
+// explain and a policy test say beside port49's own answer on a projected
+// platform (spec §8, "Verification").
+func (r Result) Device(vector []string) bool {
+	return r.model != nil && len(vector) > 0 && r.model.device(vector)
+}
````

<!-- patch: internal/projection/project.go -->
````diff
diff --git a/internal/projection/project.go b/internal/projection/project.go
new file mode 100644
index 0000000..a39095b
--- /dev/null
+++ b/internal/projection/project.go
@@ -0,0 +1,538 @@
+package projection
+
+import (
+	"errors"
+	"fmt"
+	"slices"
+	"strings"
+
+	"github.com/rhwendt/port49/internal/engine"
+	"github.com/rhwendt/port49/internal/platform"
+)
+
+// The shapes a reply takes (spec §8, "The projection model").
+const (
+	// ShapeCapability is bits for the broad reach, `deny-commands` for what
+	// the bits reach and the grant denies, `allow-commands` for a permit
+	// beneath such a deny: the common case.
+	ShapeCapability = "capability"
+	// ShapeNarrow is a grant narrower than every bit that reaches its
+	// permits: `deny-commands` `.*` and one allow alternation of the permits,
+	// under the smallest bits that reach them. It cannot carry a deny
+	// beneath a permit.
+	ShapeNarrow = "narrow"
+)
+
+// JunosFacts are what the Junos images were measured doing with a command
+// regex (spec §15, L9): tests/lab/results/L9-juniper_*.md.
+var JunosFacts = Facts{CaseSensitive: true, DenyMatchesExpanded: false}
+
+// FactsFor is what a projection's device was measured doing: the zero Facts,
+// which fail closed, for a projection with no measurement.
+func FactsFor(projection string) Facts {
+	if projection == platform.ProjectionJunosRegex {
+		return JunosFacts
+	}
+	return Facts{CaseSensitive: true}
+}
+
+// Input is one composition on one projected platform: the rules its roles
+// compose to (the blob's), and its level's ceiling in bits.
+type Input struct {
+	Platform string
+	Dialect  platform.Dialect
+	// Level is the level the bits and template are the ceiling of, its parent
+	// chain followed; empty where the composition has no level, which gets no
+	// bits and no template.
+	Level    string
+	Bits     []string
+	Template string
+	Rules    []engine.Rule
+	Classes  map[string][]string
+	// Normalize is the platform's normalization, as the blob carries it.
+	Normalize engine.Normalize
+	// Secret reports whether a rule's text carries a value the platform's
+	// redaction hides: the reply is logged whole, so such a rule is never
+	// sent (spec §5.8).
+	Secret func(rule string) bool
+	Facts  Facts
+}
+
+// Result is the reply a composition renders to, and what CI reports of it
+// (spec §8): the shape, the bits or template, the rules each regex carries,
+// and what the device is narrower than port49 in.
+type Result struct {
+	Shape    string
+	Bits     []string // sent as user-permissions, or carried by Template's class
+	Template string   // sent as local-user-name
+	// Attributes is the reply, in wire order: the bits or the template, then
+	// deny-commands, then allow-commands.
+	Attributes []string
+	Denies     []engine.Rule // sent in deny-commands; none for ShapeNarrow
+	Allows     []engine.Rule // sent in allow-commands
+	// Omitted are denies the bits already refuse, sent as nothing: a dropped
+	// bit where a deny aligns with it.
+	Omitted []engine.Rule
+	// Beyond are permits no bit of the level's ceiling reaches: never sent,
+	// so the device refuses what port49 would permit there, never the
+	// reverse (spec §8, "never exceeding the level's ceiling").
+	Beyond []engine.Rule
+	model  *model
+}
+
+// Refusal is a composition the platform cannot be told faithfully: the
+// joint check quarantines the device, and `port49 policy test` and `policy
+// diff` name it, rather than a nearer shape being sent (spec §8, "Refused
+// shape"; "Generator constraints" 5).
+type Refusal struct {
+	Why string
+	// Attribute and Value are the reply attribute past RFC 8907's length,
+	// where that is the refusal, and Class the login class that would carry
+	// the value on the device instead: the workaround the report prints
+	// beside it (spec §8, "CI MUST report when a grant crosses that line").
+	Attribute, Value, Class string
+}
+
+func (r *Refusal) Error() string { return r.Why }
+
+func refuse(format string, args ...any) error { return &Refusal{Why: fmt.Sprintf(format, args...)} }
+
+// Project renders one composition (spec §8; §13 decision 22). It proves the
+// reply sound before it returns it: every command the device would run under
+// it is one port49 permits.
+func Project(in Input) (Result, error) {
+	d := in.Dialect
+	var permits, denies []engine.Rule
+	for _, r := range in.Rules {
+		if in.Secret != nil && in.Secret(r.Rule) {
+			return Result{}, refuse("role %q has a rule whose text carries a value redaction hides, and %s's "+
+				"session reply is its rules, logged whole (spec §5.8): write the rule without it", r.Role, in.Platform)
+		}
+		if r.Verdict == engine.Permit {
+			permits = append(permits, r)
+		} else {
+			denies = append(denies, r)
+		}
+	}
+	g := generator{in: in, permits: permits, denies: denies, ceiling: d.ExpandBits(in.Bits)}
+	res, err := g.capability()
+	if errors.As(err, new(*narrowOnly)) {
+		res, err = g.narrow()
+	}
+	if err != nil {
+		return Result{}, err
+	}
+	if err := g.configuration(res); err != nil {
+		return Result{}, err
+	}
+	if err := g.attributes(&res); err != nil {
+		return Result{}, err
+	}
+	m, err := g.model(res)
+	if err != nil {
+		return Result{}, err
+	}
+	res.model = m
+	if v, ok := m.unsound(); ok {
+		// The checks above are a proof; this is its witness. A vector here is
+		// a generator defect, and nothing is sent.
+		return Result{}, refuse("on %s the reply would let the device run %q, which port49 denies; this is a "+
+			"projection defect, and nothing is sent", in.Platform, strings.Join(v, " "))
+	}
+	return res, nil
+}
+
+// narrowOnly is capability's answer where only the narrow shape can carry
+// the grant.
+type narrowOnly struct{ why string }
+
+func (n *narrowOnly) Error() string { return n.why }
+
+type generator struct {
+	in              Input
+	permits, denies []engine.Rule
+	ceiling         []string
+}
+
+func (g generator) contains(outer, inner string) bool {
+	ok, err := engine.Contains(outer, inner, g.in.Classes)
+	return err == nil && ok
+}
+
+func (g generator) mayMeet(permit, deny string) bool {
+	ok, err := engine.MayMeet(permit, deny, g.in.Classes, g.in.Normalize)
+	return err != nil || ok
+}
+
+func (g generator) dominates(permit, deny string) bool {
+	ok, err := engine.AlwaysDominates(permit, deny, g.in.Classes, g.in.Normalize)
+	return err == nil && ok
+}
+
+// declared is the level's ceiling bits as the adapter writes them, sorted:
+// what a template's class carries, `all` unexpanded.
+func (g generator) declared() []string {
+	out := slices.Clone(g.in.Bits)
+	slices.Sort(out)
+	return slices.Compact(out)
+}
+
+// reach is every reach rule of bits.
+func (g generator) reach(bits []string) []string {
+	var out []string
+	for _, b := range bits {
+		out = append(out, g.in.Dialect.Bits[b]...)
+	}
+	return out
+}
+
+// covered reports whether every command rule r matches is decided by a
+// rule of the grant: held by one permit or one deny. Under bits reaching r,
+// such a command is then permitted by port49, or refused on the device by
+// the deny sent for it.
+func (g generator) covered(r string) bool {
+	for _, q := range slices.Concat(g.permits, g.denies) {
+		if g.contains(q.Rule, r) {
+			return true
+		}
+	}
+	return false
+}
+
+// usable reports whether every command bit b reaches is covered.
+func (g generator) usable(b string) bool {
+	for _, r := range g.in.Dialect.Bits[b] {
+		if !g.covered(r) {
+			return false
+		}
+	}
+	return true
+}
+
+// aligned reports whether every command bit b reaches is denied: the bit
+// adds nothing, and is dropped rather than a deny sent against it.
+func (g generator) aligned(b string) bool {
+	for _, r := range g.in.Dialect.Bits[b] {
+		if !slices.ContainsFunc(g.denies, func(d engine.Rule) bool { return g.contains(d.Rule, r) }) {
+			return false
+		}
+	}
+	return true
+}
+
+// within reports whether the level's ceiling bits reach every command
+// permit p matches, a bit outside the ceiling carving nothing out of it: a
+// permit beyond them is never sent, since on the device an allow runs
+// whatever the bits say (spec §8, "never exceeding the level's ceiling").
+func (g generator) within(p string) bool { return g.reaches(p, g.ceiling, false) }
+
+// outside is every declared bit s does not hold, `all` read as every bit.
+func (g generator) outside(s []string) []string {
+	held := g.in.Dialect.ExpandBits(s)
+	var out []string
+	for _, b := range sortedKeys(g.in.Dialect.Bits) {
+		if !slices.Contains(held, b) {
+			out = append(out, b)
+		}
+	}
+	return out
+}
+
+// byBits reports whether the bits s reach every command of p that port49
+// does not deny outright. A bit's reach is read as the device's classes read
+// it (spec §8): the most specific reach rule decides, so a bit outside s whose
+// reach is narrower carves its commands out of a broader bit's —
+// `view-configuration` out of `view`. So some reach rule of s holds p, and
+// each reach rule outside s that meets p and is not beaten by it there is held
+// by a deny: what it carves out, port49 refuses too.
+func (g generator) byBits(p string, s []string) bool { return g.reaches(p, s, true) }
+
+// reaches reports whether some reach rule of the bits s holds p and beats,
+// on p, every reach rule outside s that meets it. With denied, a rule
+// outside s that a deny holds may carve p: port49 refuses what it carves too.
+func (g generator) reaches(p string, s []string, denied bool) bool {
+	carve := g.reach(g.outside(s))
+	return slices.ContainsFunc(g.reach(g.in.Dialect.ExpandBits(s)), func(r string) bool {
+		if !g.contains(r, p) {
+			return false
+		}
+		for _, o := range carve {
+			if g.mayMeet(p, o) && !g.dominates(r, o) &&
+				!(denied && slices.ContainsFunc(g.denies, func(d engine.Rule) bool { return g.contains(d.Rule, o) })) {
+				return false
+			}
+		}
+		return true
+	})
+}
+
+func (g generator) neverDominates(permit, deny string) bool {
+	ok, err := engine.NeverDominates(permit, deny, g.in.Classes, g.in.Normalize)
+	return err == nil && ok
+}
+
+// allowable is the deny sending p as an allow would void, if any: on the
+// device a matching allow beats every deny, so p goes out only where it
+// dominates each deny it meets (spec §5.4, §8).
+func (g generator) allowable(p string) (engine.Rule, bool) {
+	for _, d := range g.denies {
+		if g.mayMeet(p, d.Rule) && !g.dominates(p, d.Rule) {
+			return d, false
+		}
+	}
+	return engine.Rule{}, true
+}
+
+// refusedShape is spec §8's refused shape, naming the grant's two rules and
+// the platform.
+func (g generator) refusedShape(p, d engine.Rule) error {
+	return refuse("on %s, permit %q (role %q) needs an allow-commands the device would let beat deny %q (role %q), "+
+		"which sits beneath it: Junos regex cannot write everything under a permit except a deny, so the "+
+		"composition is refused rather than rendered nearer (spec §8, \"Refused shape\")", g.in.Platform, p.Rule,
+		p.Role, d.Rule, d.Role)
+}
+
+// capability is the capability shape, or narrowOnly where it cannot carry
+// the grant.
+func (g generator) capability() (Result, error) {
+	d := g.in.Dialect
+	var bits []string
+	if d.BitDelivery == platform.BitDeliveryLocalUserName {
+		// The template's class carries every bit of the level: each has to
+		// be covered, or the class lets the device run what port49 denies.
+		for _, b := range g.ceiling {
+			if !g.usable(b) {
+				return Result{}, &narrowOnly{fmt.Sprintf("the template's bit %s reaches commands no rule decides", b)}
+			}
+		}
+		bits = g.declared()
+	} else {
+		for _, b := range g.ceiling {
+			if g.usable(b) && !g.aligned(b) {
+				bits = append(bits, b)
+			}
+		}
+		// `all` holds every bit, so it is sent alone: the smallest set.
+		if slices.Contains(bits, "all") {
+			bits = []string{"all"}
+		}
+	}
+	if len(bits) == 0 {
+		// No bit's reach is decided by the grant whole and permitted in part:
+		// the permits are narrower than every bit (spec §8, "Narrow shape").
+		return Result{}, &narrowOnly{"no bit of the ceiling is the grant's whole"}
+	}
+	res := Result{Shape: ShapeCapability, Bits: bits, Template: g.in.Template}
+	for _, p := range g.permits {
+		// A permit the bits carry sends nothing; one that needs an allow is
+		// sent only within the level's ceiling.
+		covered := g.byBits(p.Rule, bits)
+		under := slices.ContainsFunc(g.denies, func(dn engine.Rule) bool {
+			return g.mayMeet(p.Rule, dn.Rule) && g.dominates(p.Rule, dn.Rule)
+		})
+		if covered && !under {
+			continue
+		}
+		if !g.within(p.Rule) {
+			res.Beyond = append(res.Beyond, p)
+			continue
+		}
+		if dn, ok := g.allowable(p.Rule); !ok {
+			return Result{}, g.refusedShape(p, dn)
+		}
+		res.Allows = append(res.Allows, p)
+	}
+	for _, dn := range g.denies {
+		if g.omittable(dn, bits, res.Allows) {
+			res.Omitted = append(res.Omitted, dn)
+			continue
+		}
+		res.Denies = append(res.Denies, dn)
+	}
+	if len(res.Denies) > 0 && !g.in.Facts.DenyMatchesExpanded {
+		return Result{}, &narrowOnly{"a deny narrower than every command is walked past by abbreviating it"}
+	}
+	return res, nil
+}
+
+// omittable reports whether the bits already refuse every command deny dn
+// matches, so nothing is sent for it (spec §8, "drops the bit instead of
+// emitting a regex"): a reach rule of a bit outside bits holds dn and no
+// reach rule of bits that meets dn ever dominates it, and no allow reaches
+// into it.
+func (g generator) omittable(dn engine.Rule, bits []string, allows []engine.Rule) bool {
+	for _, a := range allows {
+		if g.mayMeet(a.Rule, dn.Rule) {
+			return false
+		}
+	}
+	return slices.ContainsFunc(g.reach(g.outside(bits)), func(o string) bool {
+		if !g.contains(o, dn.Rule) {
+			return false
+		}
+		for _, r := range g.reach(g.in.Dialect.ExpandBits(bits)) {
+			if g.mayMeet(r, dn.Rule) && !g.neverDominates(r, o) {
+				return false
+			}
+		}
+		return true
+	})
+}
+
+// configurationBits is the first bit of bits that enters configuration mode:
+// whose reach holds `configure`.
+func (g generator) configurationBits(bits []string) string {
+	for _, b := range bits {
+		if slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.contains(r, "configure") }) {
+			return b
+		}
+	}
+	return ""
+}
+
+// configuration refuses a reply whose bits enter configuration mode for a
+// grant that is not everything: a statement typed there is governed by the
+// class's configuration permissions, which no deny-commands or
+// allow-commands reaches (spec §8; §15 L12), so port49 could deny a
+// statement the device then runs. Only a grant that permits every command
+// and denies none is carried faithfully there.
+func (g generator) configuration(res Result) error {
+	bit := g.configurationBits(res.Bits)
+	if bit == "" {
+		return nil
+	}
+	everything := slices.ContainsFunc(g.permits, func(p engine.Rule) bool { return g.contains(p.Rule, "**") })
+	if everything && len(g.denies) == 0 {
+		return nil
+	}
+	what := "permits less than every command"
+	if len(g.denies) > 0 {
+		what = fmt.Sprintf("denies %q (role %q)", g.denies[0].Rule, g.denies[0].Role)
+	}
+	return refuse("on %s the reply's bit %s enters configuration mode, where a statement is governed by the "+
+		"class's configuration permissions and no command regex reaches it (spec §8, §15 L12), and the composition "+
+		"%s: port49 would deny what the device runs there. Carry it only as a grant of every command with no deny, "+
+		"or lower the level", g.in.Platform, bit, what)
+}
+
+// narrow is the narrow shape: every permit the ceiling reaches as one allow
+// alternation over `deny-commands .*`, under the fewest ceiling bits that
+// reach them — the template's, where the delivery is one.
+func (g generator) narrow() (Result, error) {
+	res := Result{Shape: ShapeNarrow, Template: g.in.Template}
+	for _, p := range g.permits {
+		if !g.within(p.Rule) {
+			res.Beyond = append(res.Beyond, p)
+			continue
+		}
+		if dn, ok := g.allowable(p.Rule); !ok {
+			return Result{}, g.refusedShape(p, dn)
+		}
+		res.Allows = append(res.Allows, p)
+	}
+	if g.in.Dialect.BitDelivery == platform.BitDeliveryLocalUserName {
+		res.Bits = g.declared()
+		return res, nil
+	}
+	// Greedy cover: the bit reaching the most allows not yet reached, first
+	// in name order on a tie.
+	left := slices.Clone(res.Allows)
+	for len(left) > 0 {
+		best, n := "", 0
+		for _, b := range g.ceiling {
+			k := 0
+			for _, p := range left {
+				if slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.contains(r, p.Rule) }) {
+					k++
+				}
+			}
+			if k > n {
+				best, n = b, k
+			}
+		}
+		if n == 0 {
+			break // within() said some ceiling bit reaches each; unreachable
+		}
+		res.Bits = append(res.Bits, best)
+		left = slices.DeleteFunc(left, func(p engine.Rule) bool {
+			return slices.ContainsFunc(g.in.Dialect.Bits[best], func(r string) bool { return g.contains(r, p.Rule) })
+		})
+	}
+	slices.Sort(res.Bits)
+	return res, nil
+}
+
+// attributes renders res as the reply: each attribute once, mandatory, within
+// RFC 8907's 255 bytes (spec §8, "Generator constraints").
+func (g generator) attributes(res *Result) error {
+	d := g.in.Dialect
+	switch {
+	case d.BitDelivery == platform.BitDeliveryLocalUserName && res.Template != "":
+		res.Attributes = append(res.Attributes, "local-user-name="+res.Template)
+	case d.BitDelivery == platform.BitDeliveryUserPermissions && len(res.Bits) > 0:
+		res.Attributes = append(res.Attributes, "user-permissions="+strings.Join(res.Bits, " "))
+	}
+	deny, err := g.alternation(res.Denies, true)
+	if err != nil {
+		return err
+	}
+	if res.Shape == ShapeNarrow {
+		deny = ".*"
+	}
+	if deny != "" {
+		res.Attributes = append(res.Attributes, "deny-commands=^"+deny+"$")
+	}
+	allow, err := g.alternation(res.Allows, false)
+	if err != nil {
+		return err
+	}
+	if allow != "" {
+		res.Attributes = append(res.Attributes, "allow-commands=^"+allow+"$")
+	}
+	for _, a := range res.Attributes {
+		if err := engine.CheckAttribute(a); err != nil {
+			i := strings.IndexByte(a, '=')
+			class := res.Template
+			if class == "" {
+				class = platform.RemoteClass
+			}
+			return &Refusal{Attribute: a[:i], Value: a[i+1:], Class: class, Why: fmt.Sprintf("on %s the reply's %s is %d bytes, and RFC 8907 carries at most %d in one "+
+				"attribute; a device sent part of a deny is sent none of it (spec §8, \"Generator constraints\"): "+
+				"move the rules into the template's class on the device (port49 platform export --classes) and out of "+
+				"the grant, or narrow the grant", g.in.Platform, engine.AttributeName(a), len(a), engine.MaxAttribute)}
+		}
+	}
+	return nil
+}
+
+// alternation is rules as one group, `(a|b)`, or one rule bare; empty for
+// none.
+func (g generator) alternation(rules []engine.Rule, deny bool) (string, error) {
+	var alts []string
+	for _, r := range rules {
+		e, err := ruleERE(r.Rule, g.in.Classes, deny, g.in.Facts)
+		if err != nil {
+			return "", refuse("on %s, %s %q (role %q) cannot be written as the device's regex: %v (spec §8, §15 L9)",
+				g.in.Platform, r.Verdict, r.Rule, r.Role, err)
+		}
+		if !slices.Contains(alts, e) {
+			alts = append(alts, e)
+		}
+	}
+	switch len(alts) {
+	case 0:
+		return "", nil
+	case 1:
+		return alts[0], nil
+	}
+	return "(" + strings.Join(alts, "|") + ")", nil
+}
+
+func sortedKeys[V any](m map[string]V) []string {
+	out := make([]string, 0, len(m))
+	for k := range m {
+		out = append(out, k)
+	}
+	slices.Sort(out)
+	return out
+}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/projection/model.go internal/projection/project.go internal/projection/project_test.go
git commit -m "$(cat <<'EOF'
feat: the Junos projection, proven before it is sent (decision 22)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 9: A pinned 1.1.0 renders the Junos session reply from the rules, and refuses what it cannot

**Files:**
- Modify: `internal/policy/resolve.go` (`Resolution.Projection`; `compile` calls `project`;
  `layerAttributes` puts the projection at the platform layer; `exceeds` skips its names)
- Modify: `internal/policy/load.go` (`checkProjected`, called from `checkAttributes`)
- Test: `internal/policy/projection_test.go`

**Interfaces:**
- Consumes: Task 8's `projection.Project`, `Input`, `Result`, `FactsFor`; Task 6's `Projected`,
  `LevelBits`, `LocalUserNames`, `ProjectionAttributes`; `platform.Redactions`,
  `platform.RedactRule`.
- Produces:
  - `Resolution.Projection *projection.Result`, nil on a platform that projects nothing;
  - `compile` now returns `(engine.Blob, []AttributeSource, *projection.Result, error)`;
  - `(*Policy).project(c composition, b engine.Blob, dialect platform.Dialect)
    (projection.Result, error)`.

`compile` builds the blob's rules as before and, on a projected platform, hands them to
`projection.Project` with the level's ceiling bits and template, following the parent chain. The
projection's attributes go in at the platform layer: source `platform juniper_junos, projection
(<shape>)`. A level with no bits on its chain, and every projection refusal, is a compile error.
`checkDevices` already reads a compile error as a joint-check failure, so the device is
quarantined and the rest of the fleet loads. `exceeds` skips the projection's own names, since the
generator holds them to the level's ceiling bits, so a Junos grant with `max_privilege` loads.
`checkProjected` refuses a role or grant attribute the projection renders (Decided 8). Nothing
changes for a policy on 1.0.0; the test's projected set stands in until Task 13.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
index 32107a7..e0c7e71 100644
--- a/internal/policy/projection_test.go
+++ b/internal/policy/projection_test.go
@@ -1,6 +1,7 @@
 package policy
 
 import (
+	"reflect"
 	"strings"
 	"testing"
 
@@ -64,3 +65,70 @@ func TestABlockKeepsTheProjection(t *testing.T) {
 	parseProjected(t, platform.BitDeliveryUserPermissions, "platforms:\n  juniper_junos:\n"+
 		"    bits: {view: [\"show **\", \"monitor **\"]}\n"+readonlyCarveOut)
 }
+
+// A pinned set that projects Junos renders the composition's rules into the
+// session reply, at the platform layer, and every other platform as before.
+func TestAJunosSessionReplyIsTheProjection(t *testing.T) {
+	p := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)
+	res, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
+	if err != nil {
+		t.Fatal(err)
+	}
+	if !reflect.DeepEqual(res.Blob.Attributes, []string{"user-permissions=view"}) ||
+		res.Attributes[0].Source != "platform juniper_junos, projection (capability)" || res.Projection == nil {
+		t.Fatalf("%q %+v", res.Blob.Attributes, res.Attributes)
+	}
+	if q := p.Quarantines(noon); len(q) != 0 {
+		t.Fatalf("quarantines: %+v", q)
+	}
+	// The unpinned policy renders Junos with 1.0.0: nothing.
+	if res, _ := mustParse(t, readonlyCarveOut).ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon); len(res.Blob.Attributes) != 0 {
+		t.Errorf("1.0.0 projects nothing: %q", res.Blob.Attributes)
+	}
+}
+
+// The refused shape quarantines every device of the platform, naming the two
+// rules; the rest of the fleet loads (spec §8, §10). So does a bit whose
+// reach a block widened past what the grant decides.
+func TestTheRefusedShapeQuarantinesJunos(t *testing.T) {
+	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
+`+subjOK+grantOK)
+	q := p.Quarantines(noon)
+	if len(q) != 4 || q[0].Platform != "juniper_junos" ||
+		!strings.Contains(q[0].Entries[0].Cause, `permit "show interfaces **"`) {
+		t.Fatalf("%+v", q)
+	}
+	p = parseProjected(t, platform.BitDeliveryUserPermissions, "platforms:\n  juniper_junos:\n"+
+		"    bits: {view: [\"show **\", \"monitor **\"]}\n"+readonlyCarveOut)
+	if q := p.Quarantines(noon); len(q) != 4 {
+		t.Fatalf("view now reaches monitor, which nothing decides, so the carve-out goes narrow and is refused: %+v", q)
+	}
+}
+
+// No role or grant sets an attribute the projection renders.
+func TestARoleCannotSetAProjectedAttribute(t *testing.T) {
+	for _, key := range []string{"juniper_junos", "all"} {
+		_, err := Parse([]byte("platform_set: "+projectedSet+"\n"+scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show **"], attributes: {`+key+`: ["deny-commands=^request.*$"]}}
+`+subjOK+grantOK), projectedEnv(platform.BitDeliveryUserPermissions))
+		if err == nil || !strings.Contains(err.Error(), "rendered by juniper_junos's projection") {
+			t.Errorf("%s: %v", key, err)
+		}
+	}
+}
+
+// A ceiling is held by the projection: a readonly grant capped at readonly
+// loads, and its reply is the projection's, not a raise.
+func TestACeilingOnJunos(t *testing.T) {
+	p := parseProjected(t, platform.BitDeliveryLocalUserName, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show **"]}
+`+subjOK+"grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: readonly}\n")
+	if q := p.Quarantines(noon); len(q) != 0 {
+		t.Fatalf("%+v", q)
+	}
+	res, err := p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
+	if err != nil || res.Blob.Attributes[0] != "local-user-name=p49-readonly" || res.MaxPrivilege != 1 {
+		t.Fatalf("%q %d %v", res.Blob.Attributes, res.MaxPrivilege, err)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/`
Expected: FAIL, build failed: `res.Projection undefined (type Resolution has no field or method
Projection)`.

- [ ] **Step 3: Render the projection in compile**

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index 799d7f9..a0095f9 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -884,6 +884,9 @@ func (p *Policy) checkAttributes(attrs map[string][]string) error {
 			if err := engine.CheckAttribute(a); err != nil {
 				return fmt.Errorf("%s: %w", at, err)
 			}
+			if err := p.checkProjected(at, key, a); err != nil {
+				return err
+			}
 			if err := p.checkPlaceholder(at, key, a); err != nil {
 				return err
 			}
@@ -892,6 +895,24 @@ func (p *Policy) checkAttributes(attrs map[string][]string) error {
 	return nil
 }
 
+// checkProjected refuses an attribute a projection renders, under a
+// projected platform's key or under `all` where any platform is projected:
+// beside the projection it would be a second instance the device drops or
+// keeps first, and over it a regex nothing proved (spec §8, "Generator
+// constraints" 1 and 4). The projection renders the template, the bits and
+// the regexes from the rules; write rules.
+func (p *Policy) checkProjected(at, key, a string) error {
+	name := engine.AttributeName(a)
+	for _, plat := range sortedKeys(p.adapters) {
+		d := p.adapters[plat]
+		if (key == plat || key == "all") && platform.ContainsName(platform.ProjectionAttributes(d.CommandProjection), name) {
+			return fmt.Errorf("%s: %s is rendered by %s's projection from the rules (command_projection: %s), so no "+
+				"role or grant sets it there; write the rule instead (spec §8)", at, name, plat, d.CommandProjection)
+		}
+	}
+	return nil
+}
+
 // checkPlaceholder allows a placeholder only in an attribute listed inert on
 // its platform key, or under `all` on every platform port49 ships and the
 // inventory names (spec §6). Anywhere else the device would get whatever the
````

<!-- patch: internal/policy/resolve.go -->
````diff
diff --git a/internal/policy/resolve.go b/internal/policy/resolve.go
index f7b007b..db269ff 100644
--- a/internal/policy/resolve.go
+++ b/internal/policy/resolve.go
@@ -13,6 +13,7 @@ import (
 	"github.com/rhwendt/port49/internal/decision"
 	"github.com/rhwendt/port49/internal/engine"
 	"github.com/rhwendt/port49/internal/platform"
+	"github.com/rhwendt/port49/internal/projection"
 )
 
 // ErrNoGrants is no_grants_matched: no subject lists the principal, or no
@@ -45,6 +46,9 @@ type Resolution struct {
 	// attributes came from and what it shadowed (spec §6).
 	Blob       engine.Blob
 	Attributes []AttributeSource
+	// Projection is the session reply's projection of the rules on a
+	// projected platform (spec §8), and what it reports: nil elsewhere.
+	Projection *projection.Result
 }
 
 // AttributeSource is one attribute of the session reply and its provenance:
@@ -131,7 +135,7 @@ func (p *Policy) resolved(sub *Subject, d admission.Device, c composition) (Reso
 		res.MaxPrivilege, res.HasCeiling = n, true
 	}
 	var err error
-	res.Blob, res.Attributes, err = p.compile(c, d, dialect)
+	res.Blob, res.Attributes, res.Projection, err = p.compile(c, d, dialect)
 	return res, err
 }
 
@@ -139,7 +143,8 @@ func (p *Policy) resolved(sub *Subject, d admission.Device, c composition) (Reso
 // every role's rules, each carrying its role; the pipe allowlist of every
 // role that permits anything; the patterns behind every class a rule names,
 // as this platform defines them; and the session attributes, layered.
-func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dialect) (engine.Blob, []AttributeSource, error) {
+func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dialect) (engine.Blob, []AttributeSource,
+	*projection.Result, error) {
 	b := engine.Blob{Version: engine.Version, Bundle: p.Bundle, Platform: d.Platform, Privilege: c.level,
 		Normalize: p.normalizeFor(d.Platform), Classes: map[string][]string{}}
 	pipe := map[string]bool{}
@@ -173,7 +178,7 @@ func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dia
 					// A class the platform does not define would silently never
 					// match — a deny that does nothing — so it is an error, and
 					// at load, not at a mint (spec §4, §8).
-					return engine.Blob{}, nil, fmt.Errorf("role %q names @%s, which %s does not define", name,
+					return engine.Blob{}, nil, nil, fmt.Errorf("role %q names @%s, which %s does not define", name,
 						t.Text, platformName(d.Platform))
 				}
 				b.Classes[t.Text] = patterns
@@ -194,9 +199,17 @@ func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dia
 		return strings.Compare(x.Verdict+"\x00"+x.Rule+"\x00"+x.Role, y.Verdict+"\x00"+y.Rule+"\x00"+y.Role)
 	})
 	b.Rules = slices.Compact(b.Rules)
-	attrs, err := p.layerAttributes(c, d.Platform, dialect)
+	var proj *projection.Result
+	if dialect.Projected() {
+		r, err := p.project(c, b, dialect)
+		if err != nil {
+			return engine.Blob{}, nil, nil, err
+		}
+		proj = &r
+	}
+	attrs, err := p.layerAttributes(c, d.Platform, dialect, proj)
 	if err != nil {
-		return engine.Blob{}, nil, err
+		return engine.Blob{}, nil, nil, err
 	}
 	for _, a := range attrs {
 		b.Attributes = append(b.Attributes, a.Attribute)
@@ -208,7 +221,39 @@ func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dia
 		slices.Sort(b.AcceptedAttributes)
 		b.AcceptedAttributes = slices.Compact(b.AcceptedAttributes)
 	}
-	return b, attrs, nil
+	return b, attrs, proj, nil
+}
+
+// project renders the composition's rules into a projected platform's
+// session reply (spec §8; §13 decision 22): the level's ceiling bits and
+// template, its parent chain followed as a rendering's is, and the blob's
+// rules and classes. A composition the projection cannot carry faithfully is
+// an error, which quarantines the device (checkDevices) and fails `policy
+// test` and `policy diff` (spec §8, "Refused shape").
+func (p *Policy) project(c composition, b engine.Blob, dialect platform.Dialect) (projection.Result, error) {
+	in := projection.Input{Platform: b.Platform, Dialect: dialect, Rules: b.Rules, Classes: b.Classes,
+		Normalize: b.Normalize, Facts: projection.FactsFor(dialect.CommandProjection)}
+	if c.level != "" {
+		level, ok := "", false
+		for l := c.level; l != "" && !ok; l = p.parents[l] {
+			if in.Bits, ok = dialect.LevelBits(l); ok {
+				level = l
+			}
+		}
+		if !ok {
+			return projection.Result{}, fmt.Errorf("level %s has no ceiling bits on %s and no parent that has "+
+				"(spec §6, §8)", c.level, b.Platform)
+		}
+		in.Level, in.Template = level, dialect.LocalUserNames[level]
+	}
+	// The reply is logged whole, in the authorize_session record and the
+	// blob event, so a rule redaction would hide is never sent (spec §5.8).
+	patterns := append(platform.Redactions(b.Platform), dialect.Redact...)
+	in.Secret = func(rule string) bool {
+		_, hidden := platform.RedactRule(patterns, strings.Fields(rule))
+		return hidden
+	}
+	return projection.Project(in)
 }
 
 func platformName(name string) string {
@@ -222,7 +267,8 @@ func platformName(name string) string {
 // specific winning on a duplicate attribute name and every override recorded.
 // Within one layer, sources are taken in name order — roles by name, grants by
 // scope — so which one wins cannot depend on a file's layout.
-func (p *Policy) layerAttributes(c composition, platformName string, dialect platform.Dialect) ([]AttributeSource, error) {
+func (p *Policy) layerAttributes(c composition, platformName string, dialect platform.Dialect,
+	proj *projection.Result) ([]AttributeSource, error) {
 	var out []AttributeSource
 	index := map[string]int{}
 	put := func(a, source string) {
@@ -236,7 +282,13 @@ func (p *Policy) layerAttributes(c composition, platformName string, dialect pla
 		index[name] = len(out)
 		out = append(out, AttributeSource{Attribute: a, Source: source})
 	}
-	if c.level != "" {
+	if proj != nil {
+		// A projected platform's level is its bits, which the projection
+		// sends with the regexes: the platform layer (spec §6, §8).
+		for _, a := range proj.Attributes {
+			put(a, "platform "+platformName+", projection ("+proj.Shape+")")
+		}
+	} else if c.level != "" {
 		attrs, rendered, ok := p.render(dialect, c.level)
 		if !ok {
 			return nil, fmt.Errorf("level %s has no rendering on %s and no parent that has one (spec §6)",
@@ -459,8 +511,15 @@ func (p *Policy) exceeds(dialect platform.Dialect, bound, level string, reply []
 	ceiling, _, _ := p.render(dialect, bound)
 	rendered, _, _ := p.render(dialect, level)
 	held, sent := attributesByName(ceiling), attributesByName(reply)
+	owned := platform.ProjectionAttributes(dialect.CommandProjection)
 	for i, a := range reply {
 		name := engine.AttributeName(a)
+		// A projection's own attributes are held to the level's ceiling bits
+		// by the projection itself, which renders them from the level and
+		// never past it (spec §8).
+		if platform.ContainsName(owned, name) {
+			continue
+		}
 		if !strings.EqualFold(name, "priv-lvl") && raisesCeiling(name, dialect) &&
 			rose(held[name], sent[name], ceiling, rendered, dialect, dialect) {
 			return i, true
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/load.go internal/policy/projection_test.go internal/policy/resolve.go
git commit -m "$(cat <<'EOF'
feat: a pinned 1.1.0 renders Junos's session reply from the rules, and refuses what it cannot

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 10: policy test and explain say what the projection sends and what the device runs

**Files:**
- Modify: `internal/policy/tests.go` (`Caveats` on a projected platform; `ProjectionCaveats`;
  `RunTests` appends them)
- Modify: `internal/policy/explain.go` (session and command caveats)
- Modify: `internal/policy/lint.go` (`projection` and `projection_overflow` findings; `Projections`)
- Test: `internal/policy/projection_test.go`

**Interfaces:**
- Consumes: Task 9's `Resolution.Projection`; Task 8's `Result.Device`, `Result.Narrower`,
  `Refusal`; 5a's `redacted` (intersect.go); `p.expiryInstants`.
- Produces:
  - `func ProjectionCaveats(res Resolution, platformName string, o engine.Outcome) []string`;
  - `FindingProjection = "projection"` and `FindingProjectionOverflow = "projection_overflow"`;
  - `func (p *Policy) Projections(now time.Time) []Finding`.

Spec §8's reporting duties:
- CI names each composition's shape, its bits or template, what each regex carries, what the bits
  refuse, what is beyond the level's bits, and up to three commands where the device is narrower.
- A reply past the wire's length is reported with the class line that would carry it
  (`projection_overflow`).
- `explain` states that the effective set is class ∩ wire, and says what the device does with the
  command under the reply.

Every rule and vector the findings print is redacted, as the dead-rule report redacts its rules.
Rule text is policy, and a probe vector is made of rule words.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
index e0c7e71..615f64e 100644
--- a/internal/policy/projection_test.go
+++ b/internal/policy/projection_test.go
@@ -132,3 +132,63 @@ func TestACeilingOnJunos(t *testing.T) {
 		t.Fatalf("%q %d %v", res.Blob.Attributes, res.MaxPrivilege, err)
 	}
 }
+
+// explain says what the device does with a command under the projection, and
+// that the class half of what it runs is outside port49 (spec §8,
+// "Verification").
+func TestExplainSaysWhatTheDeviceDoes(t *testing.T) {
+	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show **", "clear counters"], deny: ["show configuration **"]}
+`+subjOK+grantOK)
+	for line, want := range map[string]string{
+		"show configuration system": "the device refuses it",
+		"show version":              "the device runs it",
+		"clear counters":            "the projection does not carry it to juniper_junos",
+	} {
+		e, err := p.Explain("s", "", "srx-fw-04", line, noon)
+		if err != nil || !strings.Contains(strings.Join(e.Caveats, "\n"), want) {
+			t.Errorf("%s: %q %v", line, e.Caveats, err)
+		}
+	}
+	e, err := p.Explain("s", "", "srx-fw-04", "", noon)
+	if err != nil || !strings.Contains(strings.Join(e.Caveats, "\n"), "the reply projects these rules as the capability shape") {
+		t.Errorf("session: %q %v", e.Caveats, err)
+	}
+}
+
+// policy test reports each composition's projection, and a reply past RFC
+// 8907's length with the class line that carries it instead.
+func TestProjectionFindings(t *testing.T) {
+	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show **", "clear counters"], deny: ["show configuration **"]}
+`+subjOK+grantOK)
+	var got []string
+	for _, f := range p.Lint(noon) {
+		if f.Kind == FindingProjection {
+			got = append(got, f.Message)
+		}
+	}
+	want := `subject "s" on juniper_junos: capability shape, bits view; refused by the bits, sent as nothing: ` +
+		`show configuration **; beyond the level's bits, not sent: clear counters; the device refuses what port49 ` +
+		`permits, e.g. clear counters`
+	if len(got) != 1 || got[0] != want {
+		t.Fatalf("%q", got)
+	}
+	// Sixteen permits narrower than view: the narrow shape's one allow
+	// alternation is past 255 bytes.
+	body := scopeOK + "roles:\n  - {name: r, privilege: readonly, permit: ["
+	for i, w := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
+		"juliett", "kilo", "lima", "mike", "november", "oscar", "papa"} {
+		if i > 0 {
+			body += ", "
+		}
+		body += `"show ` + w + ` **"`
+	}
+	p = parseProjected(t, platform.BitDeliveryUserPermissions, body+"]}\n"+subjOK+grantOK)
+	for _, f := range p.Lint(noon) {
+		if f.Kind == FindingProjectionOverflow && strings.Contains(f.Message, "set system login class p49-remote allow-commands") {
+			return
+		}
+	}
+	t.Fatalf("no overflow finding: %+v", p.Lint(noon))
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/`
Expected: FAIL, build failed: `undefined: FindingProjection`, `undefined: FindingProjectionOverflow`.

- [ ] **Step 3: Add the caveats and the findings**

<!-- patch: internal/policy/explain.go -->
````diff
diff --git a/internal/policy/explain.go b/internal/policy/explain.go
index 828245c..b18c661 100644
--- a/internal/policy/explain.go
+++ b/internal/policy/explain.go
@@ -133,10 +133,16 @@ func (p *Policy) Explain(subject, principal, device, line string, now time.Time)
 				"no command in this session is asked of port49, and a revocation or a session ceiling does not "+
 				"reach a live session there (spec §5.6)", d.Platform, strings.Join(dialect.Supports, ", ")))
 		}
+		if pr := res.Projection; pr != nil {
+			e.Caveats = append(e.Caveats, fmt.Sprintf("the reply projects these rules as the %s shape (spec §8): what "+
+				"the device runs is its class ∩ the wire, and the class half is the device's configuration, outside "+
+				"port49 (port49 platform export --classes prints the reference)", pr.Shape))
+		}
 		return e, nil
 	}
 	e.Outcome = o
 	e.Caveats = append(e.Caveats, Caveats(d.Platform, dialect, o)...)
+	e.Caveats = append(e.Caveats, ProjectionCaveats(res, d.Platform, o)...)
 	e.Caveats = append(e.Caveats, p.splitNotes(line, d.Platform)...)
 	// Spec §12: explain MUST say so where `supports` lacks config_commands. No
 	// built-in platform declares it (internal/platform), so a command typed in
````

<!-- patch: internal/policy/lint.go -->
````diff
diff --git a/internal/policy/lint.go b/internal/policy/lint.go
index 9a91683..cbaaa05 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -1,6 +1,7 @@
 package policy
 
 import (
+	"errors"
 	"fmt"
 	"reflect"
 	"slices"
@@ -11,6 +12,7 @@ import (
 	"github.com/rhwendt/port49/internal/admission"
 	"github.com/rhwendt/port49/internal/engine"
 	"github.com/rhwendt/port49/internal/platform"
+	"github.com/rhwendt/port49/internal/projection"
 )
 
 // Finding is something CI reports about a policy that loads: not an error,
@@ -40,6 +42,14 @@ const (
 	// FindingDeviceConfigSecretLiteral is a `platforms:` block's device_config
 	// line carrying a value redaction hides (spec §5.8).
 	FindingDeviceConfigSecretLiteral = "device_config_secret_literal"
+	// FindingProjection is how a composition's rules render on a projected
+	// platform: the shape, the bits, what each regex carries, and where the
+	// device is narrower than port49 (spec §8).
+	FindingProjection = "projection"
+	// FindingProjectionOverflow is a reply attribute past RFC 8907's length,
+	// which quarantines the device, with the class line that would carry it
+	// on the device instead (spec §8).
+	FindingProjectionOverflow = "projection_overflow"
 )
 
 // Lint computes the findings at now, ordered by kind and then message so two
@@ -140,6 +150,7 @@ func (p *Policy) Lint(now time.Time) []Finding {
 		}
 	}
 	out = append(out, p.redundantOverrides()...)
+	out = append(out, p.Projections(now)...)
 	out = append(out, p.intersections(now)...)
 	if len(p.tests) == 0 {
 		add(FindingNoTests, "the policy has no tests: nothing in it acknowledges a shadowed deny, an expansion or "+
@@ -517,3 +528,83 @@ func (p *Policy) onGeneric(name string) bool {
 	_, shipped := builtin[name]
 	return b.Replace || !shipped
 }
+
+// Projections reports each composition on a projected platform (spec §8,
+// "CI reports which shape each grant rendered under, the bit set it chose"):
+// once per subject, platform and reply, at now and at every later grant
+// expiry. A reply attribute past RFC 8907's length quarantines the device;
+// its finding prints the class line that would carry the value instead.
+func (p *Policy) Projections(now time.Time) []Finding {
+	var out []Finding
+	seen := map[string]bool{}
+	add := func(kind, msg string) {
+		if !seen[msg] {
+			seen[msg] = true
+			out = append(out, Finding{Kind: kind, Message: msg})
+		}
+	}
+	patterns := p.Redactions()
+	for _, name := range sortedKeys(p.subs) {
+		for _, d := range p.env.Devices {
+			if !p.dialect(d.Platform).Projected() {
+				continue
+			}
+			for _, at := range p.expiryInstants(now) {
+				res, err := p.resolve(p.subs[name], d, at)
+				var r *projection.Refusal
+				switch {
+				case errors.As(err, &r) && r.Attribute != "":
+					add(FindingProjectionOverflow, fmt.Sprintf("subject %q on %s: the reply's %s is %d bytes, past RFC "+
+						"8907's %d, so the device is quarantined; the class line that carries it on the device instead: "+
+						"set system login class %s %s %q", name, d.Platform, r.Attribute, len(r.Attribute)+1+len(r.Value),
+						engine.MaxAttribute, r.Class, r.Attribute, r.Value))
+				case err != nil || res.Projection == nil:
+				default:
+					add(FindingProjection, projectionMessage(name, d.Platform, *res.Projection, patterns))
+				}
+			}
+		}
+	}
+	return out
+}
+
+func projectionMessage(subject, platformName string, pr projection.Result, patterns []platform.Redaction) string {
+	rules := func(rs []engine.Rule) string {
+		var texts []string
+		for _, r := range rs {
+			texts = append(texts, r.Rule)
+		}
+		return strings.Join(redacted(patterns, texts), "; ")
+	}
+	carrier := "no bits"
+	switch {
+	case pr.Template != "":
+		carrier = "template " + pr.Template + " (bits " + strings.Join(pr.Bits, " ") + ")"
+	case len(pr.Bits) > 0:
+		carrier = "bits " + strings.Join(pr.Bits, " ")
+	}
+	msg := fmt.Sprintf("subject %q on %s: %s shape, %s", subject, platformName, pr.Shape, carrier)
+	if len(pr.Denies) > 0 {
+		msg += "; deny-commands: " + rules(pr.Denies)
+	}
+	if pr.Shape == projection.ShapeNarrow {
+		msg += "; deny-commands: everything"
+	}
+	if len(pr.Allows) > 0 {
+		msg += "; allow-commands: " + rules(pr.Allows)
+	}
+	if len(pr.Omitted) > 0 {
+		msg += "; refused by the bits, sent as nothing: " + rules(pr.Omitted)
+	}
+	if len(pr.Beyond) > 0 {
+		msg += "; beyond the level's bits, not sent: " + rules(pr.Beyond)
+	}
+	var narrower []string
+	for _, v := range pr.Narrower(3) {
+		narrower = append(narrower, strings.Join(v, " "))
+	}
+	if len(narrower) > 0 {
+		msg += "; the device refuses what port49 permits, e.g. " + strings.Join(redacted(patterns, narrower), "; ")
+	}
+	return msg
+}
````

<!-- patch: internal/policy/tests.go -->
````diff
diff --git a/internal/policy/tests.go b/internal/policy/tests.go
index da7e8a2..2ca812a 100644
--- a/internal/policy/tests.go
+++ b/internal/policy/tests.go
@@ -95,7 +95,12 @@ func (p *Policy) Decide(subject, principal string, d admission.Device, line stri
 // device will not honor.
 func Caveats(platformName string, dialect platform.Dialect, o engine.Outcome) []string {
 	var out []string
-	if !dialect.Authorizes("commands") {
+	if dialect.Projected() {
+		out = append(out, fmt.Sprintf("%s does not send per-command authorization (supports: %s): the device "+
+			"decides this command itself, from the session reply's projection of these rules (command_projection: %s), "+
+			"and a revocation or a session ceiling does not reach a live session there (spec §5.6, §8)", platformName,
+			strings.Join(dialect.Supports, ", "), dialect.CommandProjection))
+	} else if !dialect.Authorizes("commands") {
 		out = append(out, fmt.Sprintf("%s does not send per-command authorization (supports: %s): the device "+
 			"never asks port49 about this command, and a revocation or a session ceiling does not reach a live "+
 			"session there (spec §5.6)", platformName, strings.Join(dialect.Supports, ", ")))
@@ -108,6 +113,31 @@ func Caveats(platformName string, dialect platform.Dialect, o engine.Outcome) []
 	return out
 }
 
+// ProjectionCaveats say what the device does with a command under a
+// projected session reply (spec §8, "Verification"): whether it runs it, and
+// that its effective set is its class ∩ the wire, the class half outside
+// port49. Where port49 permits what the device refuses, the projection is
+// narrower there, which fails closed and is said.
+func ProjectionCaveats(res Resolution, platformName string, o engine.Outcome) []string {
+	pr := res.Projection
+	if pr == nil || len(o.Vector) == 0 {
+		return nil
+	}
+	runs := pr.Device(o.Vector)
+	verb := "refuses"
+	if runs {
+		verb = "runs"
+	}
+	out := []string{fmt.Sprintf("under the session reply's projection (%s shape) the device %s it; what it runs is "+
+		"its class ∩ the wire, and the class half is the device's configuration, outside port49 (spec §8, "+
+		"\"Verification\")", pr.Shape, verb)}
+	if o.Permit && !runs {
+		out = append(out, fmt.Sprintf("port49 permits this and the projection does not carry it to %s: the "+
+			"device refuses it, which fails closed (spec §8)", platformName))
+	}
+	return out
+}
+
 // TestResult is one `tests:` entry's run.
 type TestResult struct {
 	Test    Test
@@ -198,6 +228,7 @@ func (p *Policy) RunTests(now time.Time) []TestResult {
 			}
 			r.Permit, r.Reason, r.Outcome = o.Permit, o.Reason, o
 			r.Caveats = append(Caveats(d.Platform, p.dialect(d.Platform), o), p.splitNotes(t.Command, d.Platform)...)
+			r.Caveats = append(r.Caveats, ProjectionCaveats(res, d.Platform, o)...)
 		}
 		// API rights belong to the subject, not to a session on a device, so
 		// they are read whether or not the mint would be made (spec §12).
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/explain.go internal/policy/lint.go internal/policy/projection_test.go internal/policy/tests.go
git commit -m "$(cat <<'EOF'
feat: policy test and explain say what the projection sends and what the device runs

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 11: policy diff reports a Junos reply whose shape or bits moved

**Files:**
- Modify: `internal/policy/diff.go` (`Diff.Projections`, `ProjectionChange`, `projectionChange`,
  one check in `group`)
- Modify: `cmd/port49/policy.go` (the `projection:` line, `projectionText`)
- Test: `internal/policy/projection_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: Task 9's `Resolution.Projection`; the diff's `side`, `group`, `once`.
- Produces:
  - `Diff.Projections []ProjectionChange`;
  - `type ProjectionChange struct{ Subject string; Devices []string; At time.Time; OldShape, NewShape
    string; OldBits, NewBits []string; OldTemplate, NewTemplate string }`;
  - `projectionText(shape string, bits []string, template string) string` in cmd/port49.

The gate is unchanged (Decided 9). A reply that changes is judged whole, and the `RAISES` line
already prints the `reply:` test to paste. This adds the report spec §8 asks for, "any grant whose
shape or bits changed between two policy versions, since that is a change in what the wire says
even when no rule changed". The report is one line per composition group, and it moves nothing
past the gate. The test is the realistic readonly gaining its carve-out: `view view-configuration`
becomes `view`. The line is reported, and the reply change is still an unacknowledged raise.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/policy_test.go -->
````diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index ffaf454..6010b33 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -955,3 +955,17 @@ key_groups:
 		}
 	}
 }
+
+// policy diff prints a projection whose shape or bits moved (spec §8, §12).
+func TestPolicyDiffPrintsAProjectionChange(t *testing.T) {
+	if got := projectionText("", nil, ""); got != "none" {
+		t.Errorf("%q", got)
+	}
+	if got := projectionText("capability", []string{"view"}, ""); got != "capability (bits view)" {
+		t.Errorf("%q", got)
+	}
+	if got := projectionText("narrow", []string{"view", "view-configuration"}, "p49-readonly"); got !=
+		"narrow (template p49-readonly, bits view view-configuration)" {
+		t.Errorf("%q", got)
+	}
+}
````

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
index 615f64e..52b0336 100644
--- a/internal/policy/projection_test.go
+++ b/internal/policy/projection_test.go
@@ -192,3 +192,21 @@ func TestProjectionFindings(t *testing.T) {
 	}
 	t.Fatalf("no overflow finding: %+v", p.Lint(noon))
 }
+
+// The diff reports a reply whose shape or bits moved, and the reply gate
+// judges the reply itself: it cannot read the direction of a change to a
+// projected attribute, so it fails closed (spec §12, review C4).
+func TestTheDiffReportsAProjectionChange(t *testing.T) {
+	before := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show **"]}
+`+subjOK+grantOK)
+	after := parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)
+	d := Compare(before, after, noon)
+	if len(d.Projections) != 1 || !reflect.DeepEqual(d.Projections[0].OldBits, []string{"view", "view-configuration"}) ||
+		!reflect.DeepEqual(d.Projections[0].NewBits, []string{"view"}) || len(d.Projections[0].Devices) != 4 {
+		t.Fatalf("%+v", d.Projections)
+	}
+	if d.UnacknowledgedLevels() == 0 {
+		t.Error("a projected reply's change is a raise until a reply: test asserts it")
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/`
Expected: FAIL, build failed: `d.Projections undefined (type Diff has no field or method
Projections)` and `undefined: projectionText`.

- [ ] **Step 3: Report the projection change**

<!-- patch: cmd/port49/policy.go -->
````diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 9bc5239..952840c 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -438,6 +438,11 @@ func policyDiff(args []string, stdout, stderr io.Writer) int {
 			label, l.Subject, strings.Join(l.Devices, ", "), from(l.At), orNone(l.OldLevel), orNone(l.NewLevel),
 			orNone(l.OldCeiling), orNone(l.NewCeiling), l.OldPrivLvl, l.NewPrivLvl, l.OldEnable, l.NewEnable, reply, tail)
 	}
+	for _, pc := range d.Projections {
+		fmt.Fprintf(stdout, "projection: %s on %s%s: %s -> %s (spec §8; the reply gate above judges it)\n", pc.Subject,
+			strings.Join(pc.Devices, ", "), from(pc.At), projectionText(pc.OldShape, pc.OldBits, pc.OldTemplate),
+			projectionText(pc.NewShape, pc.NewBits, pc.NewTemplate))
+	}
 	widen, narrow := 0, 0
 	for _, c := range d.Changes {
 		on := c.Subject + " on " + strings.Join(c.Devices, ", ") + from(c.At)
@@ -848,3 +853,17 @@ func redactOutput(stdout, stderr io.Writer) (out, errOut *redacting, flush func(
 		}
 	}
 }
+
+// projectionText is one side of a projection change: its shape and what
+// carries the bits, or none.
+func projectionText(shape string, bits []string, template string) string {
+	switch {
+	case shape == "":
+		return "none"
+	case template != "":
+		return shape + " (template " + template + ", bits " + strings.Join(bits, " ") + ")"
+	case len(bits) == 0:
+		return shape + " (no bits)"
+	}
+	return shape + " (bits " + strings.Join(bits, " ") + ")"
+}
````

<!-- patch: internal/policy/diff.go -->
````diff
diff --git a/internal/policy/diff.go b/internal/policy/diff.go
index a4ce029..8e5a026 100644
--- a/internal/policy/diff.go
+++ b/internal/policy/diff.go
@@ -16,6 +16,7 @@ import (
 	"github.com/rhwendt/port49/internal/decision"
 	"github.com/rhwendt/port49/internal/engine"
 	"github.com/rhwendt/port49/internal/platform"
+	"github.com/rhwendt/port49/internal/projection"
 )
 
 // Diff is the effective-permission diff between two versions of a policy
@@ -57,6 +58,35 @@ type Diff struct {
 	// inventory has devices of: a platform_set moved, or a `platforms:` block
 	// edited (spec §8, §12).
 	Adapters []AdapterChange
+	// Projections are compositions on a projected platform whose reply
+	// changed shape, bits or template: a change in what the wire says even
+	// where no rule changed (spec §8). Reported; the reply gate is what fails
+	// on them (Levels, "reply").
+	Projections []ProjectionChange
+}
+
+// ProjectionChange is one composition's projection before and after, on the
+// devices that hold the same blobs. A side with no projection has Shape "".
+type ProjectionChange struct {
+	Subject                  string
+	Devices                  []string
+	At                       time.Time
+	OldShape, NewShape       string
+	OldBits, NewBits         []string
+	OldTemplate, NewTemplate string
+}
+
+// projectionChange compares two resolutions' projections, ok where the
+// shape, the bits or the template moved.
+func projectionChange(was, is *projection.Result) (ProjectionChange, bool) {
+	var pc ProjectionChange
+	if was != nil {
+		pc.OldShape, pc.OldBits, pc.OldTemplate = was.Shape, was.Bits, was.Template
+	}
+	if is != nil {
+		pc.NewShape, pc.NewBits, pc.NewTemplate = is.Shape, is.Bits, is.Template
+	}
+	return pc, pc.OldShape != pc.NewShape || !slices.Equal(pc.OldBits, pc.NewBits) || pc.OldTemplate != pc.NewTemplate
 }
 
 // AdapterChange is one key of one platform's adapter that the two versions
@@ -645,6 +675,11 @@ func (c *comparison) group(subject string, devices []string, was, is side, at ti
 			NewEnable: is.priv.enable, OldReply: splitReply(was.priv.reply), NewReply: splitReply(is.priv.reply)},
 			was.priv, is.priv))
 	}
+	if pc, ok := projectionChange(wr.Projection, ir.Projection); ok && c.once("projection", subject, on, pc.OldShape,
+		pc.NewShape, strings.Join(pc.OldBits, " "), strings.Join(pc.NewBits, " "), pc.OldTemplate, pc.NewTemplate) {
+		pc.Subject, pc.Devices, pc.At = subject, devices, at
+		c.d.Projections = append(c.d.Projections, pc)
+	}
 	if was.hash == is.hash {
 		return
 	}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/policy.go cmd/port49/policy_test.go internal/policy/diff.go internal/policy/projection_test.go
git commit -m "$(cat <<'EOF'
feat: policy diff reports a Junos reply whose shape or bits moved

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 12: platform export --classes prints the reference classes, idle-timeout from max_session_age (decision 21)

**Files:**
- Create: `internal/platform/classes.go` (`ReferenceClasses`)
- Modify: `internal/config/config.go` (`DefaultMaxSessionAge`, `MaxSessionAge`; Load uses the
  constant)
- Modify: `cmd/port49/platform.go` (`--classes`, `--config`, `exportClasses`), `cmd/port49/main.go`
  (usage)
- Test: `internal/platform/classes_test.go` (new), `internal/config/config_test.go`,
  `cmd/port49/platform_test.go`

**Interfaces:**
- Consumes: Task 6's `Projected`, `DeviceConfig`, `CeilingBits`, `LocalUserNames`, `BitDelivery`,
  `RemoteClass`; 5a's `platformShow`, `adapters.load`, `RedactAdapter`.
- Produces:
  - `func ReferenceClasses(d Dialect, maxSessionAge time.Duration) ([]string, error)`;
  - `const config.DefaultMaxSessionAge = 12 * time.Hour`;
  - `func config.MaxSessionAge(raw []byte) (time.Duration, error)`;
  - `port49 platform export --classes --config PORT49D_YAML PLATFORM`.

Decision 21's enforced approximation is `idle-timeout` in the class, from `max_session_age`. Spec §8
also requires the reference class per level to be published for compliance tools. `ReferenceClasses`
prints, as `set` lines:
- the adapter's `device_config`;
- `class p49-remote idle-timeout N` and `user remote class p49-remote`;
- under `local_user_name`, each template's class with its level's `permissions [ ... ]` and
  `idle-timeout N`, and its user.

N is whole minutes rounded down, at least 1, since rounding down is the stricter direction. No uid
is written, and Task 2 measured the commit taking none. `config.MaxSessionAge` reads
`session.max_session_age_default` alone. `config.Load` would demand every key's secret in the
environment, and an offline tool run in CI has none, so the export does not use it. The flag goes
with `export`, one platform and `--config`; any other combination is a usage error. On 1.0.0,
Junos projects nothing and the export says so. Task 13's test covers the success path.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/platform_test.go -->
````diff
diff --git a/cmd/port49/platform_test.go b/cmd/port49/platform_test.go
index 40ee75c..5aeb248 100644
--- a/cmd/port49/platform_test.go
+++ b/cmd/port49/platform_test.go
@@ -634,3 +634,29 @@ func TestAnOperatorsUnreachableRulesExportAsTheOperators(t *testing.T) {
 		t.Errorf("--all:\n%s", file)
 	}
 }
+
+// export --classes prints a projected platform's reference configuration;
+// a platform that projects nothing has none, and the flag goes with export
+// and a config alone.
+func TestPlatformExportClasses(t *testing.T) {
+	cfg := filepath.Join(t.TempDir(), "port49d.yaml")
+	if err := os.WriteFile(cfg, []byte("inventory_file: inventory.yaml\nsession: {max_session_age_default: 8h}\n"),
+		0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	if code := run([]string{"platform", "export", "--set", "1.0.0", "--classes", "--config", cfg, "juniper_junos"},
+		&out, &errb); code != 1 || !strings.Contains(errb.String(), "projects nothing") {
+		t.Fatalf("1.0.0: code %d\n%s%s", code, out.String(), errb.String())
+	}
+	for _, args := range [][]string{
+		{"platform", "show", "--classes", "--config", cfg, "juniper_junos"},
+		{"platform", "export", "--classes", "juniper_junos"},
+		{"platform", "export", "--config", cfg, "juniper_junos"},
+		{"platform", "export", "--classes", "--config", cfg, "--all", "--dir", t.TempDir()},
+	} {
+		if code := run(args, &out, &errb); code != 2 {
+			t.Errorf("%q: code %d", args, code)
+		}
+	}
+}
````

<!-- patch: internal/config/config_test.go -->
````diff
diff --git a/internal/config/config_test.go b/internal/config/config_test.go
index da4df0f..8262400 100644
--- a/internal/config/config_test.go
+++ b/internal/config/config_test.go
@@ -832,3 +832,16 @@ func TestLabFaultFileIsOptionalAndLabOnly(t *testing.T) {
 		t.Fatal("a top-level fault_file loaded; the switch belongs to the lab block only")
 	}
 }
+
+// MaxSessionAge reads the one key, with Load's default, and no secret.
+func TestMaxSessionAge(t *testing.T) {
+	for raw, want := range map[string]time.Duration{"": DefaultMaxSessionAge,
+		"session: {max_session_age_default: 8h}\n": 8 * time.Hour} {
+		if got, err := MaxSessionAge([]byte(raw)); err != nil || got != want {
+			t.Errorf("%q: %s %v", raw, got, err)
+		}
+	}
+	if _, err := MaxSessionAge([]byte("session: {max_session_age_default: -1h}\n")); err == nil {
+		t.Error("a negative age")
+	}
+}
````

<!-- patch: internal/platform/classes_test.go -->
````diff
diff --git a/internal/platform/classes_test.go b/internal/platform/classes_test.go
new file mode 100644
index 0000000..0f67a38
--- /dev/null
+++ b/internal/platform/classes_test.go
@@ -0,0 +1,41 @@
+package platform
+
+import (
+	"reflect"
+	"strings"
+	"testing"
+	"time"
+)
+
+// The reference classes carry the level's bits and an idle-timeout from
+// max_session_age (decision 21); the remote template has no bits.
+func TestReferenceClasses(t *testing.T) {
+	d := junosProjected(BitDeliveryLocalUserName)
+	d.DeviceConfig = []string{"set system tacplus-options strict-authorization"}
+	got, err := ReferenceClasses(d, 12*time.Hour+59*time.Second)
+	if err != nil {
+		t.Fatal(err)
+	}
+	want := []string{
+		"set system tacplus-options strict-authorization",
+		"set system login class p49-remote idle-timeout 720",
+		"set system login user remote class p49-remote",
+		"set system login class p49-admin permissions [ all ]",
+		"set system login class p49-admin idle-timeout 720",
+		"set system login user p49-admin class p49-admin",
+		"set system login class p49-readonly permissions [ view view-configuration ]",
+		"set system login class p49-readonly idle-timeout 720",
+		"set system login user p49-readonly class p49-readonly",
+	}
+	if !reflect.DeepEqual(got, want) {
+		t.Fatalf("%q", got)
+	}
+	up, _ := ReferenceClasses(junosProjected(BitDeliveryUserPermissions), 30*time.Second)
+	if len(up) != 2 || !strings.HasSuffix(up[0], "idle-timeout 1") {
+		t.Fatalf("user_permissions: %q", up)
+	}
+	eos, _ := DialectFor("arista_eos")
+	if _, err := ReferenceClasses(eos, time.Hour); err == nil {
+		t.Error("a platform that projects nothing has no classes")
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/config/ ./cmd/port49/`
Expected: FAIL, build failed: `undefined: ReferenceClasses`, `undefined: DefaultMaxSessionAge`,
`undefined: MaxSessionAge`; and `--- FAIL: TestPlatformExportClasses`.

- [ ] **Step 3: Add the export**

<!-- patch: cmd/port49/main.go -->
````diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index 0d7804f..30dcc08 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -41,7 +41,8 @@ const usage = `usage:
   port49 grants remove --policy FILE --inventory FILE --subject NAME [--write | --pr [--remote R] [--base B]]
   port49 platform list [--set VERSION | --policy FILE --inventory FILE]
   port49 platform show [--set VERSION | --policy FILE --inventory FILE] PLATFORM
-  port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir EMPTY_DIR)
+  port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir EMPTY_DIR |
+                         --classes --config PORT49D_YAML PLATFORM)
   port49 platform upgrade --policy FILE --inventory FILE --to VERSION [--write]
   port49 devices check-config --policy FILE --inventory FILE --device NAME CONFIGFILE
 `
````

<!-- patch: cmd/port49/platform.go -->
````diff
diff --git a/cmd/port49/platform.go b/cmd/port49/platform.go
index a607e68..74762a1 100644
--- a/cmd/port49/platform.go
+++ b/cmd/port49/platform.go
@@ -16,6 +16,7 @@ import (
 	"gopkg.in/yaml.v3"
 
 	"github.com/rhwendt/port49/internal/admission"
+	"github.com/rhwendt/port49/internal/config"
 	"github.com/rhwendt/port49/internal/platform"
 	"github.com/rhwendt/port49/internal/policy"
 )
@@ -142,12 +143,16 @@ func platformShow(args []string, stdout, stderr io.Writer, export bool) int {
 	a.register(fs)
 	all := fs.Bool("all", false, "every platform, one file each in --dir (export only)")
 	dir := fs.String("dir", "", "the directory --all writes to")
+	classes := fs.Bool("classes", false, "a projected platform's reference device configuration, as set lines "+
+		"(export only)")
+	cfgPath := fs.String("config", "", "port49d.yaml: its session.max_session_age_default is the classes' "+
+		"idle-timeout (with --classes)")
 	if err := fs.Parse(args); err != nil {
 		return 2
 	}
 	switch {
 	case *all && (!export || *dir == "" || fs.NArg() != 0), !*all && (*dir != "" || fs.NArg() != 1),
-		a.conflicting():
+		a.conflicting(), *classes && (!export || *all || *cfgPath == ""), !*classes && *cfgPath != "":
 		fmt.Fprint(stderr, usage)
 		return 2
 	}
@@ -195,6 +200,9 @@ func platformShow(args []string, stdout, stderr io.Writer, export bool) int {
 			strings.Join(sortedNames(set), ", "))
 		return 1
 	}
+	if *classes {
+		return exportClasses(stdout, stderr, name, platformName, d, *cfgPath, a, p)
+	}
 	mode := exportShow
 	if export {
 		mode = exportBlock
@@ -485,3 +493,39 @@ func sortedNames(set map[string]platform.Dialect) []string {
 	slices.Sort(out)
 	return out
 }
+
+// exportClasses prints a projected platform's reference device configuration
+// (spec §8): the configuration its replies rest on, the bitless `remote`
+// template, and each level's template and class where the adapter sends one,
+// every class carrying idle-timeout from port49d.yaml's
+// session.max_session_age_default (spec §5.6; §13 decision 21). A compliance
+// tool checks devices against it; port49 never logs into one.
+func exportClasses(stdout, stderr io.Writer, name, platformName string, d platform.Dialect, cfgPath string, a adapters,
+	p *policy.Policy) int {
+	raw, err := os.ReadFile(cfgPath)
+	if err != nil {
+		fmt.Fprintf(stderr, "%s: %v\n", name, err)
+		return 1
+	}
+	age, err := config.MaxSessionAge(raw)
+	if err != nil {
+		fmt.Fprintf(stderr, "%s: %s: %v\n", name, cfgPath, err)
+		return 1
+	}
+	lines, err := platform.ReferenceClasses(d, age)
+	if err != nil {
+		fmt.Fprintf(stderr, "%s: %s: %v\n", name, platformName, err)
+		return 1
+	}
+	setName := a.set
+	if p != nil {
+		setName = p.PlatformSet()
+	}
+	fmt.Fprintf(stdout, "# %s: reference configuration, platform set %s (spec §8). idle-timeout is "+
+		"session.max_session_age_default (%s) in whole minutes: a session-only device never asks port49 again after "+
+		"login, so this timer is what ends a session there (decision 21).\n", platformName, setName, age)
+	for _, line := range lines {
+		fmt.Fprintln(stdout, line)
+	}
+	return 0
+}
````

<!-- patch: internal/config/config.go -->
````diff
diff --git a/internal/config/config.go b/internal/config/config.go
index 502602c..221e449 100644
--- a/internal/config/config.go
+++ b/internal/config/config.go
@@ -287,6 +287,31 @@ type Config struct {
 
 const defaultWindow = 10 * time.Minute
 
+// DefaultMaxSessionAge is session.max_session_age_default where the file
+// sets none (spec §5.6: "The default is 12h").
+const DefaultMaxSessionAge = 12 * time.Hour
+
+// MaxSessionAge reads session.max_session_age_default from a port49d.yaml's
+// bytes and nothing else, with Load's default and its refusal of a value that
+// is not positive. It is what `port49 platform export --classes` renders a
+// session-only platform's idle-timeout from (spec §13, decision 21), and it
+// reads no secret, so a CI job holding no key can run it.
+func MaxSessionAge(raw []byte) (time.Duration, error) {
+	var f struct {
+		Session struct {
+			MaxSessionAgeDefault time.Duration `yaml:"max_session_age_default"`
+		} `yaml:"session"`
+	}
+	if err := yaml.Unmarshal(raw, &f); err != nil {
+		return 0, fmt.Errorf("config: %w", err)
+	}
+	d := orD(f.Session.MaxSessionAgeDefault, DefaultMaxSessionAge)
+	if d <= 0 {
+		return 0, fmt.Errorf("config: session.max_session_age_default must be greater than zero; got %s", d)
+	}
+	return d, nil
+}
+
 func Load(path string) (Config, error) {
 	raw, err := os.ReadFile(path)
 	if err != nil {
@@ -341,7 +366,7 @@ func Load(path string) (Config, error) {
 			StalenessCeiling:     f.Session.StalenessCeiling,
 			GraceWindow:          orD(f.Session.GraceWindow, 10*time.Minute),
 			IndexTTL:             orD(f.Session.IndexTTL, 12*time.Hour),
-			MaxSessionAgeDefault: orD(f.Session.MaxSessionAgeDefault, 12*time.Hour),
+			MaxSessionAgeDefault: orD(f.Session.MaxSessionAgeDefault, DefaultMaxSessionAge),
 		},
 		Token:       TokenConfig{CandidateCap: orI(f.Token.CandidateCap, 8)},
 		encCurrent:  f.Encryption.Current,
````

<!-- patch: internal/platform/classes.go -->
````diff
diff --git a/internal/platform/classes.go b/internal/platform/classes.go
new file mode 100644
index 0000000..a140548
--- /dev/null
+++ b/internal/platform/classes.go
@@ -0,0 +1,52 @@
+package platform
+
+import (
+	"errors"
+	"fmt"
+	"slices"
+	"strings"
+	"time"
+)
+
+// ReferenceClasses is the device configuration a projected platform's
+// replies rest on, as `set` lines (spec §8, "publish the reference class per
+// privilege level through port49 platform export"): the adapter's
+// device_config lines, the bitless `remote` template, and under
+// BitDeliveryLocalUserName each level's template user and class, carrying
+// the level's bits. Every class carries `idle-timeout` from maxSessionAge,
+// in whole minutes rounded down and at least one: a session-only device never
+// asks port49 again after login, so the class's own timer is the one limit
+// that ends a session there (spec §5.6; §13 decision 21).
+func ReferenceClasses(d Dialect, maxSessionAge time.Duration) ([]string, error) {
+	if !d.Projected() {
+		return nil, errors.New("the platform projects nothing, so it has no reference classes; its device_config " +
+			"is what `platform show` prints")
+	}
+	if maxSessionAge <= 0 {
+		return nil, errors.New("max_session_age must be positive: it is the classes' idle-timeout")
+	}
+	minutes := max(int64(maxSessionAge/time.Minute), 1)
+	out := slices.Clone(d.DeviceConfig)
+	class := func(name string, bits []string) {
+		if len(bits) > 0 {
+			out = append(out, fmt.Sprintf("set system login class %s permissions [ %s ]", name, strings.Join(bits, " ")))
+		}
+		out = append(out, fmt.Sprintf("set system login class %s idle-timeout %d", name, minutes))
+	}
+	class(RemoteClass, nil)
+	out = append(out, "set system login user remote class "+RemoteClass)
+	if d.BitDelivery != BitDeliveryLocalUserName {
+		return out, nil
+	}
+	seen := map[string]bool{}
+	for _, level := range sortedKeys(d.LocalUserNames) {
+		name := d.LocalUserNames[level]
+		if seen[name] {
+			continue
+		}
+		seen[name] = true
+		class(name, d.CeilingBits[level])
+		out = append(out, fmt.Sprintf("set system login user %s class %s", name, name))
+	}
+	return out, nil
+}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/main.go cmd/port49/platform.go cmd/port49/platform_test.go internal/config/config.go internal/config/config_test.go internal/platform/classes.go internal/platform/classes_test.go
git commit -m "$(cat <<'EOF'
feat: platform export --classes prints the reference classes, idle-timeout from max_session_age (decision 21)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 13: Platform set 1.1.0: Junos projected, from what L9, L12 and L23 measured

**Files:**
- Create: `platforms/1.1.0/arista_eos.yaml`, `cisco_iosxe.yaml`, `cisco_nxos.yaml` (copies of
  1.0.0's), `platforms/1.1.0/juniper_junos.yaml`
- Modify: `internal/platform/set.go` (`DefaultSet = "1.1.0"`), `internal/platform/dialect.go`
  (`generics["1.1.0"]`), `internal/projection/project.go` (`JunosFacts`, Step 4)
- Test: `internal/platform/adapter_test.go` (`shipped110`, `releasedGeneric`, the set list),
  `config_test.go`, `dialect_test.go`, `classes_test.go`, `cmd/port49/platform_test.go`

**Interfaces:**
- Consumes: the notes of Tasks 2, 3 and 4; Task 6's keys; Task 12's `ReferenceClasses`.
- Produces: set 1.1.0, `platform.DefaultSet == "1.1.0"`, and the test table `shipped110`, which
  Task 19 freezes.

The patches below are the set as this plan's candidates write it. The candidates are:
- `bit_delivery: local_user_name`, with templates `p49-readonly`, `p49-operator` and `p49-admin`;
- the bits and ceilings of Decided 11;
- `ceiling_levels {1, 15, 15}`;
- `device_config` requiring `strict-authorization` and `remote` on `p49-remote`;
- a `config_checks` entry for bits on `p49-remote`;
- the EOS, NX-OS and IOS-XE files unchanged from 1.0.0.

Step 4 then changes exactly what the lab notes measured differently, each edit named with its
consequence. Where a note and a candidate agree, the candidate stands. Where the two Junos images
disagree, the value that denies more stands.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/platform_test.go -->
````diff
diff --git a/cmd/port49/platform_test.go b/cmd/port49/platform_test.go
index 5aeb248..a8e7f49 100644
--- a/cmd/port49/platform_test.go
+++ b/cmd/port49/platform_test.go
@@ -97,7 +97,7 @@ func TestPlatformShowAndExportPrintTheAdapter(t *testing.T) {
 	if code := run([]string{"platform", "show", "cisco_iosxe"}, &out, &errb); code != 0 {
 		t.Fatalf("code %d %s", code, errb.String())
 	}
-	for _, want := range []string{"# cisco_iosxe: built-in, platform set 1.0.0\n", "      operator:\n        - priv-lvl=7\n",
+	for _, want := range []string{"# cisco_iosxe: built-in, platform set 1.1.0\n", "      operator:\n        - priv-lvl=7\n",
 		"    accepted_attributes:\n      - priv-lvl\n", "      - privilege exec level 7 clear counters\n",
 		"    verified: containerlab\n",
 		"#   {match: ['**'], after: secret}\n"} {
@@ -635,9 +635,9 @@ func TestAnOperatorsUnreachableRulesExportAsTheOperators(t *testing.T) {
 	}
 }
 
-// export --classes prints a projected platform's reference configuration;
-// a platform that projects nothing has none, and the flag goes with export
-// and a config alone.
+// export --classes prints a projected platform's reference configuration,
+// its idle-timeout from port49d.yaml; a platform that projects nothing has
+// none, and the flag goes with export and a config alone.
 func TestPlatformExportClasses(t *testing.T) {
 	cfg := filepath.Join(t.TempDir(), "port49d.yaml")
 	if err := os.WriteFile(cfg, []byte("inventory_file: inventory.yaml\nsession: {max_session_age_default: 8h}\n"),
@@ -649,6 +649,14 @@ func TestPlatformExportClasses(t *testing.T) {
 		&out, &errb); code != 1 || !strings.Contains(errb.String(), "projects nothing") {
 		t.Fatalf("1.0.0: code %d\n%s%s", code, out.String(), errb.String())
 	}
+	out.Reset()
+	if code := run([]string{"platform", "export", "--classes", "--config", cfg, "juniper_junos"}, &out, &errb); code != 0 ||
+		!strings.Contains(out.String(), "platform set 1.1.0") ||
+		!strings.Contains(out.String(), "set system login class p49-readonly permissions [ view view-configuration ]\n") ||
+		!strings.Contains(out.String(), "set system login class p49-readonly idle-timeout 480\n") ||
+		!strings.Contains(out.String(), "set system login user remote class p49-remote\n") {
+		t.Fatalf("1.1.0: code %d\n%s%s", code, out.String(), errb.String())
+	}
 	for _, args := range [][]string{
 		{"platform", "show", "--classes", "--config", cfg, "juniper_junos"},
 		{"platform", "export", "--classes", "juniper_junos"},
@@ -660,3 +668,22 @@ func TestPlatformExportClasses(t *testing.T) {
 		}
 	}
 }
+
+// Moving a policy from 1.0.0 to 1.1.0 turns the Junos projection on, and
+// every key that does so is gated: the move is reviewed like any adapter edit
+// (spec §8, §12).
+func TestUpgradingToTheProjectedSet(t *testing.T) {
+	pol, inv := policyFixture(t)
+	if err := os.WriteFile(inv, []byte(strings.Replace(string(readFile(t, inv)), "devices:\n",
+		"devices:\n  - {name: srx-01, platform: juniper_junos, addresses: [10.0.0.9]}\n", 1)), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv, "--to", "1.1.0"}, &out, &errb)
+	for _, key := range []string{"command_projection", "bits", "bit_delivery", "local_user_names", "privilege"} {
+		if !strings.Contains(out.String(), "platforms.juniper_junos."+key+"\n") ||
+			!strings.Contains(out.String(), "field: "+key+", sha256:") {
+			t.Errorf("%s is not reported gated:\n%s%s", key, out.String(), errb.String())
+		}
+	}
+}
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index a884283..9b682dc 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -12,8 +12,8 @@ import (
 	"github.com/rhwendt/port49/platforms"
 )
 
-// shipped is the default set, value for value: the table plan 4 compiled
-// into the binary, and each change plan 5 made to it with the note behind it.
+// shipped is set 1.0.0, value for value: the table plan 4 compiled into the
+// binary, and each change plan 5a made to it with the note behind it.
 var shipped = map[string]Dialect{
 	"arista_eos": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
@@ -126,12 +126,38 @@ var shipped = map[string]Dialect{
 	},
 }
 
+// shipped110 is set 1.1.0, value for value: 1.0.0 with juniper_junos
+// projected (plan 5b; spec §8, §13 decision 22).
+var shipped110 = func() map[string]Dialect {
+	out := map[string]Dialect{}
+	for name, d := range shipped {
+		out[name] = d.clone()
+	}
+	j := out["juniper_junos"]
+	j.CommandProjection, j.BitDelivery = ProjectionJunosRegex, BitDeliveryLocalUserName
+	j.LocalUserNames = map[string]string{"readonly": "p49-readonly", "operator": "p49-operator", "admin": "p49-admin"}
+	j.Bits = map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
+		"clear": {"clear **"}, "network": {"ping **", "traceroute **", "ssh **", "telnet **"}, "trace": {"monitor **"},
+		"all": {"**"}}
+	j.CeilingBits = map[string][]string{"readonly": {"view", "view-configuration"},
+		"operator": {"clear", "network", "trace", "view", "view-configuration"}, "admin": {"all"}}
+	j.CeilingLevels = map[string]uint8{"readonly": 1, "operator": 15, "admin": 15}
+	j.DeviceConfig = []string{"set system tacplus-options strict-authorization",
+		"set system login user remote class p49-remote"}
+	j.ConfigChecks = append(j.ConfigChecks, ConfigCheck{Match: `^set\s+system\s+login\s+class\s+p49-remote\s+permissions\b`,
+		Says: "the remote template's class carries bits: a session whose reply names a template the device lacks lands " +
+			"in remote (tests/lab/results/L18-juniper_vjunos-router.md, variant 7) and runs them, which port49 never " +
+			"granted; read this check against `show configuration | display set`"})
+	out["juniper_junos"] = j
+	return out
+}()
+
 func TestTheDefaultSetValueForValue(t *testing.T) {
 	got := Dialects()
-	if len(got) != len(shipped) {
-		t.Fatalf("%d platforms, want %d", len(got), len(shipped))
+	if len(got) != len(shipped110) {
+		t.Fatalf("%d platforms, want %d", len(got), len(shipped110))
 	}
-	for name, want := range shipped {
+	for name, want := range shipped110 {
 		if !reflect.DeepEqual(got[name], want) {
 			t.Errorf("%s:\n got %+v\nwant %+v", name, got[name], want)
 		}
@@ -168,6 +194,9 @@ var releasedGeneric = map[string]Dialect{
 	"1.0.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
 		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"},
 		EnableUsername: EnablePrincipal},
+	"1.1.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
+		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"},
+		EnableUsername: EnablePrincipal},
 }
 
 // Each released set's generic adapter is its own and frozen, and every set
@@ -203,7 +232,7 @@ func TestEmbeddedSetsLoad(t *testing.T) {
 	if _, ok := all[DefaultSet]; !ok {
 		t.Fatalf("no set %s in %v", DefaultSet, Sets())
 	}
-	if !reflect.DeepEqual(Sets(), []string{"1.0.0"}) {
+	if !reflect.DeepEqual(Sets(), []string{"1.0.0", "1.1.0"}) {
 		t.Fatalf("sets: %v", Sets())
 	}
 	set, ok := Set(DefaultSet)
````

<!-- patch: internal/platform/classes_test.go -->
````diff
diff --git a/internal/platform/classes_test.go b/internal/platform/classes_test.go
index 0f67a38..1aea23d 100644
--- a/internal/platform/classes_test.go
+++ b/internal/platform/classes_test.go
@@ -34,6 +34,16 @@ func TestReferenceClasses(t *testing.T) {
 	if len(up) != 2 || !strings.HasSuffix(up[0], "idle-timeout 1") {
 		t.Fatalf("user_permissions: %q", up)
 	}
+	// What export prints for the shipped Junos adapter carries every line
+	// check-config holds a Junos device to.
+	junos, _ := DialectFor("juniper_junos")
+	ref, err := ReferenceClasses(junos, 12*time.Hour)
+	if err != nil {
+		t.Fatal(err)
+	}
+	if missing, err := Missing([]byte(strings.Join(ref, "\n")), junos.DeviceConfig); err != nil || len(missing) != 0 {
+		t.Fatalf("%q %v", missing, err)
+	}
 	eos, _ := DialectFor("arista_eos")
 	if _, err := ReferenceClasses(eos, time.Hour); err == nil {
 		t.Error("a platform that projects nothing has no classes")
````

<!-- patch: internal/platform/config_test.go -->
````diff
diff --git a/internal/platform/config_test.go b/internal/platform/config_test.go
index 9e9f338..00dfc2f 100644
--- a/internal/platform/config_test.go
+++ b/internal/platform/config_test.go
@@ -95,8 +95,12 @@ func TestALocalAccountPatternCapturesTheName(t *testing.T) {
 // command method list a level-7 command is never asked about (spec §6). The
 // lab's configurations carry every line their adapter names.
 func TestARequiredLineThatIsAbsentIsMissing(t *testing.T) {
+	// The Junos startup config is hierarchical, and predates the projection:
+	// the Junos lab tests apply the reference configuration at run time
+	// (tests/lab/projection_test.go), and what `platform export --classes`
+	// prints carries every device_config line (TestReferenceClasses).
 	for platformName, file := range map[string]string{"arista_eos": "eos-startup.cfg", "cisco_iosxe": "iosxe-startup.cfg",
-		"cisco_nxos": "nxos-startup.cfg", "juniper_junos": "vjunos-startup.conf"} {
+		"cisco_nxos": "nxos-startup.cfg"} {
 		raw, err := os.ReadFile("../../tests/lab/configs/" + file)
 		if err != nil {
 			t.Fatal(err)
````

<!-- patch: internal/platform/dialect_test.go -->
````diff
diff --git a/internal/platform/dialect_test.go b/internal/platform/dialect_test.go
index 71f79a7..201ff9e 100644
--- a/internal/platform/dialect_test.go
+++ b/internal/platform/dialect_test.go
@@ -136,11 +136,13 @@ func TestOperatorIsAdminsLevelWhereTheDeviceCannotFenceIt(t *testing.T) {
 	if n, ok := xe.PrivLvl("operator"); !ok || n != 7 {
 		t.Fatalf("ios-xe operator: %d %v", n, ok)
 	}
-	for _, name := range []string{"juniper_junos", "no_such_platform"} {
-		d, _ := DialectFor(name)
-		if _, ok := d.PrivLvl("operator"); ok {
-			t.Fatalf("%s: operator has no number there yet", name)
-		}
+	// Junos renders no priv-lvl, and its bits are the fence (decision 22):
+	// operator numbers as admin for the token's ceiling, as on NX-OS.
+	if n, ok := func() (uint8, bool) { d, _ := DialectFor("juniper_junos"); return d.PrivLvl("operator") }(); !ok || n != 15 {
+		t.Fatalf("junos operator: %d %v", n, ok)
+	}
+	if d, _ := DialectFor("no_such_platform"); func() bool { _, ok := d.PrivLvl("operator"); return ok }() {
+		t.Fatal("no_such_platform: operator has no number there")
 	}
 }
 
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./cmd/port49/`
Expected: FAIL, among others: `TestEmbeddedSetsLoad: sets: [1.0.0]`, `TestTheGenericAdapterIsFrozen:
set 1.1.0 generic`, `TestTheDefaultSetValueForValue: juniper_junos`, and `TestReferenceClasses: the
platform projects nothing`.

- [ ] **Step 3: Add the set**

```bash
mkdir -p platforms/1.1.0
cp platforms/1.0.0/arista_eos.yaml platforms/1.0.0/cisco_iosxe.yaml platforms/1.0.0/cisco_nxos.yaml platforms/1.1.0/
```

Then apply:

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index 2e0afc8..efe5ac6 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -261,6 +261,9 @@ var inert = []string{"home-directory"}
 var generics = map[string]Dialect{
 	"1.0.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
 		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert, EnableUsername: EnablePrincipal},
+	// 1.1.0 changes no generic value: the Junos projection is juniper_junos's.
+	"1.1.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
+		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert, EnableUsername: EnablePrincipal},
 }
 
 // Generic returns set version's generic adapter, copied, and whether the
````

<!-- patch: internal/platform/set.go -->
````diff
diff --git a/internal/platform/set.go b/internal/platform/set.go
index b512b3a..c63826b 100644
--- a/internal/platform/set.go
+++ b/internal/platform/set.go
@@ -13,7 +13,7 @@ import (
 
 // DefaultSet is the newest set this build ships: what `port49 platform`
 // shows and exports unless asked for another.
-const DefaultSet = "1.0.0"
+const DefaultSet = "1.1.0"
 
 // UnpinnedSet is the set a policy that pins none renders with, and it never
 // moves: 1.0.0 is the first set, so a policy written before pinning existed
````

<!-- patch: platforms/1.1.0/juniper_junos.yaml -->
````diff
diff --git a/platforms/1.1.0/juniper_junos.yaml b/platforms/1.1.0/juniper_junos.yaml
new file mode 100644
index 0000000..4e42996
--- /dev/null
+++ b/platforms/1.1.0/juniper_junos.yaml
@@ -0,0 +1,92 @@
+# juniper_junos — vSRX 21.4R3.15 and vJunos-router 23.4R2-S2.1 in the port49 lab.
+# Every value is measured and cited, or marked unmeasured and chosen in the
+# direction that fails closed (spec §8, §15).
+platforms:
+  juniper_junos:
+    # Session authorization only: no per-command request in 26 sessions on two
+    # images (L18; decision 21). Its rules reach a session through the
+    # projection below (decision 22).
+    supports: [session]
+    # The composed rules render into the session reply as the Junos login
+    # class model reads it: permission bits, then deny-commands and
+    # allow-commands, a matching allow beating any deny (L11, closed;
+    # tests/lab/results/L12-juniper_*.md). What the regexes rest on — explicit
+    # anchors, case, abbreviations — is L9's (tests/lab/results/L9-juniper_*.md)
+    # and internal/projection's JunosFacts.
+    command_projection: junos_regex
+    # The template carries the level's bits: local-user-name is applied under
+    # either flag (L18-juniper_*.md, variants 1 and 2) and a template the
+    # device lacks degrades to `remote`, which device_config below makes
+    # bitless. user-permissions: tests/lab/results/L12-juniper_*.md.
+    bit_delivery: local_user_name
+    local_user_names: {readonly: p49-readonly, operator: p49-operator, admin: p49-admin}
+    # Each bit's reach in rule form: every command a class holding that bit
+    # alone ran or completed in the lab, as rules that hold them, an upper
+    # bound (tests/lab/results/L12-bits-juniper_*.md). The projection trusts a
+    # bit no further than this. `all` is every bit.
+    bits:
+      view: ["show **"]
+      view-configuration: ["show configuration **"]
+      clear: ["clear **"]
+      network: ["ping **", "traceroute **", "ssh **", "telnet **"]
+      trace: ["monitor **"]
+      all: ["**"]
+    # Each level's ceiling in bits. readonly is show and info, operator adds
+    # the non-disruptive state changes and no configuration, admin is
+    # everything (the owner's level definitions, 2026-09-24). Spec §8's
+    # example operator also holds `reset`, which restarts software processes:
+    # disruptive, so not here.
+    privilege:
+      readonly: [view, view-configuration]
+      operator: [clear, network, trace, view, view-configuration]
+      admin: [all]
+    # No priv-lvl is sent: the bits are the fence. The token's ceiling still
+    # needs a number; every Junos request carries priv_lvl 1
+    # (tests/lab/results/junos-session-service-juniper_vjunos-router.md), so
+    # readonly numbers 1, and operator numbers as admin, as decision 23 does
+    # where the device's number fences nothing.
+    ceiling_levels: {readonly: 1, operator: 15, admin: 15}
+    # What the replies depend on, in `show configuration | display set` form.
+    device_config:
+      # Required: without it a port49 denial is advisory and the session opens
+      # in the remote template (L17-juniper_*.md).
+      - set system tacplus-options strict-authorization
+      # Required: a reply naming a template the device lacks lands the
+      # session in `remote` (L18-juniper_*.md, variant 7), so remote's class
+      # carries no bits and a missing template runs nothing.
+      - set system login user remote class p49-remote
+    # fxp0 is the interface the lab reaches both images on
+    # (tests/lab/configs/vjunos-startup.conf); em0 is spec §8's example and no
+    # lab image uses it.
+    entity_classes:
+      management: ['^(fxp0|em0)$']
+    # Junos sends no command to expand; unmeasured, so false, the direction
+    # that fails closed.
+    expands_abbreviations: false
+    splits_interface_names: false
+    # Junos never authorizes a command (L18; decision 21), so no modifier
+    # reaches port49.
+    pipe_token: "|"
+    pipe_authorized: false
+    # Unmeasured for a command request, which Junos never sends; its
+    # accounting records end `<cr>` (tests/lab/results/L17-juniper_vjunos-router.md), and
+    # true is every measured platform's value.
+    strip_cr: true
+    # No command request to carry one; unmeasured, so false.
+    shows_server_msg: false
+    # Every name the projection sends, and the configuration regexes it never
+    # sends: all carry privilege (spec §8).
+    privilege_attributes: [local-user-name, user-permissions, allow-commands, deny-commands, allow-configuration,
+      deny-configuration, allow-commands-regexps, deny-commands-regexps, allow-configuration-regexps,
+      deny-configuration-regexps]
+    inert_attributes: [home-directory]
+    # `port49 devices check-config` (spec §5.6), set or hierarchical form: a
+    # name quoted or bare, and an account `show configuration` prints under a
+    # protect: or inactive: prefix, which is still an account (an inactive one
+    # is read too, failing closed: one `activate` brings it back).
+    local_accounts: ['^set\s+system\s+login\s+user\s+"?([^\s"]+)', '^\s*(?:(?:protect|inactive):\s+)*user\s+"?([^\s"{]+)"?\s*\{']
+    config_checks:
+      - match: 'authentication-order .*\bpassword\b'
+        says: "a FAIL from port49 falls through to the local password on this platform (tests/lab/results/L4-juniper_vsrx.md, L4-juniper_vjunos-router.md): a denied operator logs in locally"
+      - match: '^set\s+system\s+login\s+class\s+p49-remote\s+permissions\b'
+        says: "the remote template's class carries bits: a session whose reply names a template the device lacks lands in remote (tests/lab/results/L18-juniper_vjunos-router.md, variant 7) and runs them, which port49 never granted; read this check against `show configuration | display set`"
````

- [ ] **Step 4: Apply what the lab measured**

Read Tasks 2–4's notes and make exactly these edits. Each keeps the tests and the adapter in step.
Record in the commit message which notes each value came from.

1. **Anchors (L9).** If either Junos note says explicit anchors were not taken, the projection
   cannot ship. Make these edits, skip items 2–4 and Task 18, and say so in the PR. Otherwise
   continue with item 2.
   - In `platforms/1.1.0/juniper_junos.yaml`, delete `command_projection`, `bit_delivery`,
     `local_user_names` and `bits` (with its body).
   - Delete the whole `privilege:` block, which would otherwise be read as attributes.
   - Delete both `device_config` lines and the `p49-remote` config check.
   - In `shipped110`, keep only the `CeilingLevels` line.
   - Delete the Junos block of `TestReferenceClasses`, the success block of
     `TestPlatformExportClasses`, and `TestUpgradingToTheProjectedSet`.
2. **`JunosFacts` (L9).** In `internal/projection/project.go`, set `var JunosFacts =
   Facts{CaseSensitive: <A>, DenyMatchesExpanded: <B>}`. Here `<A>` is `false` only if both notes
   say `JunosFacts.CaseSensitive = false`, and `<B>` is `true` only if both say
   `JunosFacts.DenyMatchesExpanded = true`. Update the comment above it to cite both notes.
3. **`bit_delivery` (L12).** Switch to `user_permissions` only if both notes show all three:
   `user-permissions over a bitless template applied: true`, the two-bit variant's `show cli
   authorization` listing both `view` and `clear`, and the per-session line showing A's
   permissions unchanged after B. If so, make these edits:
   - In the adapter file: `bit_delivery: user_permissions`, delete the `local_user_names` line,
     and rewrite the comment above to cite `L12-juniper_*.md`.
   - In `shipped110`: `j.CommandProjection, j.BitDelivery = ProjectionJunosRegex,
     BitDeliveryUserPermissions`, and delete the `j.LocalUserNames = ...` line.
   - In `cmd/port49/platform_test.go`'s `TestPlatformExportClasses` success block: replace the
     two `p49-readonly` expectations with `!strings.Contains(out.String(), "p49-readonly")`, since
     the export then prints only the `remote` class.
   - In `TestUpgradingToTheProjectedSet`: drop `"local_user_names"` from the list.

   Otherwise leave `local_user_name`.
4. **Bits (L12-bits).** If Task 3 widened `junosBitReach`, write the same rules under `bits:` here
   and in `shipped110`'s `j.Bits`. The note prints the YAML ready to paste.
5. **Inert beside readonly (L23).** For each candidate the note shows not inert on `arista_eos` or
   `cisco_nxos`:
   - In that platform's 1.1.0 file, remove it from `inert_attributes` and add it to
     `privilege_attributes`, citing `L23-<platform>.md` in the comment.
   - Make the same edit to that platform's entry in `shipped110`, which becomes a copy with the
     two lists changed.
   - Note it for Task 19: a 1.0.0 pin is covered through `PrivilegeAttributeNames` (Decided 15).
6. **priv_lvl (Task 2's table).** If a Junos request carried a priv_lvl other than 1, set
   `ceiling_levels` so that readonly's number is at least that value, and say so in the commit.

Add every file these edits touch to the commit in Step 6, including `internal/projection/project.go`
when item 2 changed it.

- [ ] **Step 5: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

Also run `./bin/port49 platform upgrade --policy <a policy pinning nothing> --inventory
tests/lab/inventory-lab.yaml --to 1.1.0` and read the report. Every `platforms.juniper_junos.*` key
the move changes is listed with its `acknowledge:` entry.

- [ ] **Step 6: Commit**

```bash
git add cmd/port49/platform_test.go internal/platform/adapter_test.go internal/platform/classes_test.go internal/platform/config_test.go internal/platform/dialect.go internal/platform/dialect_test.go internal/platform/set.go platforms/1.1.0/arista_eos.yaml platforms/1.1.0/cisco_iosxe.yaml platforms/1.1.0/cisco_nxos.yaml platforms/1.1.0/juniper_junos.yaml
git commit -m "$(cat <<'EOF'
feat: platform set 1.1.0 projects Junos, from what L9, L12 and L23 measured

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 14: NX-OS's vsh.bin record under admin is system, on its task_id only (L25; only if measured)

**Files:**
- Modify: `internal/platform/platform.go` (`SystemTask`, `systemTasks`, `SystemTasks`)
- Modify: `internal/daemon/acct/acct.go` (`systemTasks`, `WithSystemTasks`, `isSystemUser` takes
  the task_id)
- Modify: `cmd/port49d/main.go` (wires `WithSystemTasks`)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.8, the Fields table, §14's system
  users)
- Test: `internal/daemon/acct/acct_test.go`

**Interfaces:**
- Consumes: `tests/lab/results/L25-cisco_nxos.md` (Task 4).
- Produces:
  - `type platform.SystemTask struct{ User string; TaskID *regexp.Regexp }`;
  - `func platform.SystemTasks() map[string][]platform.SystemTask`;
  - `func (h *Handler) WithSystemTasks(t map[string][]platform.SystemTask) *Handler`;
  - `isSystemUser(platformName, user, taskID string) bool`.

**Run this task only if L25's note shows an accounting record under `admin` with a task_id of the
form `vsh.bin.<digits>`.** Otherwise skip it: leave L25 open, and say so in the PR body under
"Carried". If the note's task_id has another exact shape, write the pattern that shape needs in
`systemTasks` and in the test, anchored at both ends, and change nothing else.

The pair is keyed on the user and the task_id (Decided 14). It is not among `WireFactsDiffer`'s
facts. A `based_on:` variant does not get it and reads such a record `unattributed`, the safe
direction, as a missing session discriminator does.

- [ ] **Step 1: Write the failing test**

<!-- patch: internal/daemon/acct/acct_test.go -->
````diff
diff --git a/internal/daemon/acct/acct_test.go b/internal/daemon/acct/acct_test.go
index c02ba58..9a5879b 100644
--- a/internal/daemon/acct/acct_test.go
+++ b/internal/daemon/acct/acct_test.go
@@ -752,3 +752,21 @@ func TestTheSpoolFileNeverHoldsASecret(t *testing.T) {
 		t.Fatalf("the spool file: %s", b)
 	}
 }
+
+// A platform's machinery writing under a username a person may hold is
+// system only on its own task_id: the N9Kv's cancelled-sudo record is, and
+// an `admin` session's is not (tests/lab/results/L25-cisco_nxos.md).
+func TestASystemTaskIsTheTaskNotTheUser(t *testing.T) {
+	h := &Handler{systemTasks: platform.SystemTasks()}
+	if !h.isSystemUser("cisco_nxos", "admin", "vsh.bin.28561") {
+		t.Error("the vsh.bin record")
+	}
+	for _, c := range []struct{ platform, user, task string }{
+		{"cisco_nxos", "admin", "172.100.100.1@pts/0"}, {"cisco_nxos", "alice", "vsh.bin.28561"},
+		{"arista_eos", "admin", "vsh.bin.28561"}, {"cisco_nxos", "admin", "vsh.bin.1 x"},
+	} {
+		if h.isSystemUser(c.platform, c.user, c.task) {
+			t.Errorf("%+v is system", c)
+		}
+	}
+}
````

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/daemon/acct/`
Expected: FAIL, build failed: `unknown field systemTasks in struct literal of type Handler`,
`undefined: platform.SystemTasks`, `too many arguments in call to h.isSystemUser`.

- [ ] **Step 3: Add the system task**

<!-- patch: cmd/port49d/main.go -->
````diff
diff --git a/cmd/port49d/main.go b/cmd/port49d/main.go
index 144280f..65af7bb 100644
--- a/cmd/port49d/main.go
+++ b/cmd/port49d/main.go
@@ -562,7 +562,8 @@ func run(parent context.Context, cfgPath string) error {
 		// It carries `root` for juniper_junos and nothing else
 		// (internal/platform). No idle TTL: accounting does not extend one
 		// (spec §5.8).
-		Acct:   acct.New(handlerStore, spool, m, time.Now, platform.SystemUsers()).WithRedactor(redactorFor(live)),
+		Acct: acct.New(handlerStore, spool, m, time.Now, platform.SystemUsers()).WithRedactor(redactorFor(live)).
+			WithSystemTasks(platform.SystemTasks()),
 		Limits: lim, Metrics: m, Log: log, Now: time.Now, IdleTimeout: cfg.Limits.IdleTimeout}
 
 	// A dead metrics listener is not a detail: without it nobody can see the
````

<!-- patch: docs/design/2026-08-23-policy-engine-spec.md -->
````diff
diff --git a/docs/design/2026-08-23-policy-engine-spec.md b/docs/design/2026-08-23-policy-engine-spec.md
index a0bfab1..353c0b4 100644
--- a/docs/design/2026-08-23-policy-engine-spec.md
+++ b/docs/design/2026-08-23-policy-engine-spec.md
@@ -2299,9 +2299,16 @@ for a session port49 was never asked to authenticate. Without the entry those th
 behaviour is image-specific and unmeasured there. L17's narrower negative stands as written — under
 *that* run's accounting event list, with `enhanced-accounting` committed, every record named the
 logged-in operator (§15, L17) — and does not contradict this: it measured a different
-configuration on a different day. One production observation remains **unmeasured in this lab**,
-an NX-OS `admin` record carrying `task_id=vsh.bin.$port` after a cancelled `sudo`, and a
-`tests/lab/results/` note reproducing it is what would add `cisco_nxos`.
+configuration on a different day.
+
+**`cisco_nxos` ships `admin`, on its own task_id only.** On the N9Kv a network-operator's bare
+`show interface` prompts for sudo, and cancelling it writes an accounting record under `admin`
+with `task_id=vsh.bin.<n>` (`tests/lab/results/L25-cisco_nxos.md`). `admin` is also the name a
+fleet gives its break-glass account, so a system user keyed on the name alone would attribute a
+person's local login `system` and hide it; the entry is keyed on the username **and** the
+record's task_id (`^vsh\.bin\.[0-9]+$`), and a person's session there carries
+`<addr>@pts/<n>` (L1). A `based_on:` variant does not get it and reads such a record
+`unattributed`: an alarm too many, the safe direction.
 
 `system` is reached only where `unattributed` would otherwise be — after `foreign` has already
 been decided, on a record that resolved to no context at all. A device acting on its own behalf
@@ -2920,7 +2927,7 @@ attribute is complete in four lines:
 | `session_services` | the authorization `service` values this platform's sessions arrive with; a **list**, because the name is device-configurable on Junos | defaults per platform |
 | `session_discriminator` | the accounting AV pair whose value separates two sessions of one user on one device (§5.8) | defaults per platform |
 | `exec_commands` | the `cmd` values that mark an exec record rather than a per-command one; empty means "the exec record carries no `cmd` at all" (§5.8) | defaults per platform |
-| `system_users` | usernames this platform's own machinery writes accounting under, attributed `system` (§5.8); `juniper_junos` ships `root`, every other adapter ships empty | optional |
+| `system_users` | usernames this platform's own machinery writes accounting under, attributed `system` (§5.8); `juniper_junos` ships `root`, and `cisco_nxos` `admin` on a task_id `vsh.bin.<n>` only (L25); every other adapter ships empty | optional |
 | `port_pattern` | expected `port` shape, used only for drift detection | optional |
 | `ceiling_levels` | the priv-lvl number each level stands for where the rendering sends no `priv-lvl` (NX-OS is sent a role and no level, L16), for the token's ceiling | if `privilege` sends no `priv-lvl` |
 | `strip_cr` / `shows_server_msg` | whether commands end in `<cr>` (§3 rule 1); whether the device displays a denial's `server_msg` (L2) | defaults from the generic adapter |
@@ -5168,8 +5175,8 @@ Beyond those already listed in the design document's §14:
   `accounting_state` and moves neither the expiry nor `last_touched_at`.
 - **System users**: a record naming a username the platform's adapter declares a system user is
   attributed `system`, never `foreign` and never `unattributed`. `juniper_junos` declares `root`
-  (§5.8, measured in `tests/lab/evidence/L1-juniper_vsrx.pcap`); every other adapter declares
-  none.
+  (§5.8, measured in `tests/lab/evidence/L1-juniper_vsrx.pcap`), and `cisco_nxos` `admin` only on
+  a task_id `vsh.bin.<n>` (L25); an `admin` record with any other task_id is not `system`.
 - **Unattributed records** are recorded rather than discarded, carry `ctx_id: null`, and are
   counted separately.
 
````

<!-- patch: internal/daemon/acct/acct.go -->
````diff
diff --git a/internal/daemon/acct/acct.go b/internal/daemon/acct/acct.go
index b5de160..c1bcb46 100644
--- a/internal/daemon/acct/acct.go
+++ b/internal/daemon/acct/acct.go
@@ -33,6 +33,9 @@ type Handler struct {
 	// production state in the production binary, and an unlocked map read by
 	// parallel requests.
 	systemUsers map[string][]string
+	// systemTasks is platform.SystemTasks(), handed in the same way
+	// (WithSystemTasks): a username attributed system only on a task_id.
+	systemTasks map[string][]platform.SystemTask
 	// redact is the redaction every record passes through before it reaches
 	// the spool (spec §5.8); nil is the built-in patterns.
 	redact platform.Redactor
@@ -46,6 +49,13 @@ func (h *Handler) WithRedactor(r platform.Redactor) *Handler {
 	return h
 }
 
+// WithSystemTasks sets the usernames a platform's machinery writes
+// accounting under on a task_id of its own (platform.SystemTasks).
+func (h *Handler) WithSystemTasks(t map[string][]platform.SystemTask) *Handler {
+	h.systemTasks = t
+	return h
+}
+
 // New builds the accounting handler.
 //
 // It takes no idle TTL, deliberately. An annotation writes through
@@ -133,7 +143,7 @@ func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AcctReq
 		attribution = "foreign"
 	case resolved:
 		attribution = "resolved"
-	case h.isSystemUser(peer.Platform, canonical):
+	case h.isSystemUser(peer.Platform, canonical, avOf(raw, "task_id")):
 		// The device acting on its own behalf, not a session port49 failed to
 		// authenticate (§5.8). Never foreign; countable on its own.
 		attribution = "system"
@@ -264,12 +274,17 @@ func contains(set []string, hash string) bool {
 // isSystemUser reports whether this platform's adapter declares user as one of
 // its own machinery's accounting identities (spec §5.8). Every shipped
 // platform's list is empty, so this returns false in the binary as it ships.
-func (h *Handler) isSystemUser(platformName, user string) bool {
+func (h *Handler) isSystemUser(platformName, user, taskID string) bool {
 	for _, u := range h.systemUsers[platformName] {
 		if u == user {
 			return true
 		}
 	}
+	for _, t := range h.systemTasks[platformName] {
+		if t.User == user && t.TaskID.MatchString(taskID) {
+			return true
+		}
+	}
 	return false
 }
 
````

<!-- patch: internal/platform/platform.go -->
````diff
diff --git a/internal/platform/platform.go b/internal/platform/platform.go
index e0b1616..24b7188 100644
--- a/internal/platform/platform.go
+++ b/internal/platform/platform.go
@@ -12,6 +12,7 @@ package platform
 
 import (
 	"fmt"
+	"regexp"
 	"sort"
 	"strings"
 )
@@ -200,9 +201,8 @@ func IsExecRecord(platformName, cmd string) bool {
 // operator (L17-juniper_vsrx.md, L17-juniper_vjunos-router.md). It measured a
 // different configuration and does not contradict the above.
 //
-// Still unmeasured, and therefore NOT entered: an NX-OS admin record with
-// task_id=vsh.bin.$port after a cancelled sudo. A tests/lab/results/ note is
-// what would add cisco_nxos.
+// NX-OS's `admin` is not entered here: a person's break-glass account is
+// named that too, so it is a SystemTask, keyed on its task_id (systemTasks).
 var systemUsers = map[string][]string{
 	"juniper_junos": {"root"},
 }
@@ -221,6 +221,38 @@ func SystemUsers() map[string][]string {
 	return out
 }
 
+// SystemTask is a platform's own machinery writing accounting under a
+// username a person may also hold, told apart by the record's task_id: only a
+// record whose task_id matches TaskID is attributed `system` (spec §5.8).
+// Keyed on the username alone, the break-glass account a fleet names `admin`
+// would never be seen as a session port49 did not authenticate.
+type SystemTask struct {
+	User   string
+	TaskID *regexp.Regexp
+}
+
+// systemTasks are the SystemTasks per platform. They are not among the wire
+// facts a `based_on:` variant is refused for (WireFactsDiffer): without one a
+// variant's such record is unattributed, an alarm too many rather than a
+// session hidden, the safe direction.
+//
+// cisco_nxos: after a network-operator's cancelled sudo prompt on a bare
+// `show interface`, the N9Kv writes an accounting record under `admin` with
+// task_id=vsh.bin.<port> (tests/lab/results/L25-cisco_nxos.md). A person's
+// session there carries task_id `<addr>@pts/<n>` (L1-cisco_nxos.md).
+var systemTasks = map[string][]SystemTask{
+	"cisco_nxos": {{User: "admin", TaskID: regexp.MustCompile(`^vsh\.bin\.[0-9]+$`)}},
+}
+
+// SystemTasks is the per-platform SystemTask table, copied.
+func SystemTasks() map[string][]SystemTask {
+	out := make(map[string][]SystemTask, len(systemTasks))
+	for name, tasks := range systemTasks {
+		out[name] = append([]SystemTask(nil), tasks...)
+	}
+	return out
+}
+
 // WireFactsDiffer names what the daemon reads off the wire for name that it
 // does not for a platform with no entry here: its session service, its exec
 // records' commands and its system users. A `based_on:` variant is keyed by
@@ -244,5 +276,6 @@ func WireFactsDiffer(name string) []string {
 	if users := systemUsers[name]; len(users) > 0 {
 		out = append(out, fmt.Sprintf("system users %s", strings.Join(users, " ")))
 	}
+
 	return out
 }
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49d/main.go docs/design/2026-08-23-policy-engine-spec.md internal/daemon/acct/acct.go internal/daemon/acct/acct_test.go internal/platform/platform.go
git commit -m "$(cat <<'EOF'
feat: NX-OS's vsh.bin record under admin is system, on its task_id only (L25)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 15: A dropped accounting record is an account_gap in the log

**Files:**
- Modify: `internal/decision/reasons.go` (`EventAccountGap`), `internal/decision/log.go` (`Gap`,
  `Record.Gap`)
- Modify: `internal/daemon/acct/spool.go` (`gapMu`, `gaps`, `gapSince`, `drop`, `flushGaps`;
  every drop goes through `drop`; `drainOnce` flushes first and last)
- Test: `internal/daemon/acct/spool_test.go`, `internal/daemon/acct/sink_test.go`

**Interfaces:**
- Consumes: the spool's existing drop points: `offerFailed`, the oversized-line and set-aside
  branches of `drainOnce`, and `deliverLine`'s unparseable line.
- Produces, for Tasks 16 and 17:
  - `decision.EventAccountGap = "account_gap"`;
  - `type decision.Gap struct{ Stage string; Records int; Since string }`, JSON keys `stage`,
    `records`, `since`;
  - `decision.Record.Gap *Gap`, JSON key `gap`, omitted when nil.

Spec §9 says reconciliation MUST be qualified by the accounting stream's health: spool drops,
`ERROR` replies and unattributed counts. Two of those were metrics only, and a reader of the log
could not see them. Now every drop is counted by stage, as before, and also held in memory. The
drain writes one `account_gap` record per stage before the next records it forwards, and again at
the end of the pass. A refused write keeps the count for the next pass. `offer_refused` is the
stage an `ERROR` reply comes from. Two existing tests now see the gap record after the records they
count, and are updated to expect it.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/daemon/acct/sink_test.go -->
````diff
diff --git a/internal/daemon/acct/sink_test.go b/internal/daemon/acct/sink_test.go
index a6323c6..0793875 100644
--- a/internal/daemon/acct/sink_test.go
+++ b/internal/daemon/acct/sink_test.go
@@ -238,8 +238,10 @@ func TestAnUnencodableRecordIsSetAside(t *testing.T) {
 	if ok, n := sp.drainOnce(); !ok || n != 3 {
 		t.Fatalf("ok=%v forwarded=%d", ok, n)
 	}
-	if len(sink.got) != 2 || sink.got[0] != "a" || sink.got[1] != "c" {
-		t.Fatalf("delivered %q, want a c", sink.got)
+	// The third is the account_gap record naming the one set aside, which
+	// carries no task_id (TestADropIsAGapInTheLog).
+	if len(sink.got) != 3 || sink.got[0] != "a" || sink.got[1] != "c" || sink.got[2] != "" {
+		t.Fatalf("delivered %q, want a c and the gap", sink.got)
 	}
 	aside, err := os.ReadFile(path + ".unencodable")
 	if err != nil || strings.Count(string(aside), "\n") != 1 || !strings.Contains(string(aside), `"task_id":"b"`) {
````

<!-- patch: internal/daemon/acct/spool_test.go -->
````diff
diff --git a/internal/daemon/acct/spool_test.go b/internal/daemon/acct/spool_test.go
index d126bba..d56b52a 100644
--- a/internal/daemon/acct/spool_test.go
+++ b/internal/daemon/acct/spool_test.go
@@ -433,10 +433,13 @@ func TestOversizedLineIsDroppedNotFatal(t *testing.T) {
 		sp.drainOnce()
 	}
 
-	want := []string{`"task_id":"1"`, `"task_id":"2"`, `"task_id":"4"`, `"task_id":"5"`}
+	// The drop is written as an account_gap record after the pass
+	// (TestADropIsAGapInTheLog).
+	want := []string{`"task_id":"1"`, `"task_id":"2"`, `"task_id":"4"`, `"task_id":"5"`, `"event":"account_gap"`}
 	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
 	if len(lines) != len(want) {
-		t.Fatalf("want %d records (1,2,4,5; 3 dropped as oversized), got %d: %q", len(want), len(lines), out.String())
+		t.Fatalf("want %d records (1,2,4,5; 3 dropped as oversized, and its gap), got %d: %q", len(want), len(lines),
+			out.String())
 	}
 	for _, w := range want {
 		if n := strings.Count(out.String(), w); n != 1 {
@@ -823,3 +826,34 @@ func TestTheDrainRedactsARecordSpooledBeforeTheUpgrade(t *testing.T) {
 		t.Fatalf("%s", out.String())
 	}
 }
+
+// A record the spool drops is written to the log as an account_gap record,
+// by stage, before the records after it: reconciliation reads the log, and
+// must know it has a hole before it says a device did not ask (spec §9).
+func TestADropIsAGapInTheLog(t *testing.T) {
+	path := filepath.Join(t.TempDir(), "overflow.jsonl")
+	good, err := (decision.Record{Event: decision.EventAccount, TaskID: "after"}).MarshalJSON()
+	if err != nil {
+		t.Fatal(err)
+	}
+	if err := os.WriteFile(path+".draining", append([]byte("{not json at all}\n"), append(good, '\n')...), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	out := &bytes.Buffer{}
+	sp, err := NewSpool(4, path, decision.NewJSONLines(out), metrics.New(prometheus.NewRegistry()))
+	if err != nil {
+		t.Fatal(err)
+	}
+	sp.drainOnce()
+	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
+	if len(lines) != 2 || !strings.Contains(lines[0], `"task_id":"after"`) ||
+		!strings.Contains(lines[1], `"event":"account_gap"`) || !strings.Contains(lines[1], `"stage":"drain_unparseable"`) ||
+		!strings.Contains(lines[1], `"records":1`) {
+		t.Fatalf("%q", out.String())
+	}
+	out.Reset()
+	sp.drainOnce()
+	if out.Len() != 0 {
+		t.Fatalf("a gap is reported once: %q", out.String())
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/acct/`
Expected: FAIL: `TestAnUnencodableRecordIsSetAside: delivered ["a" "c"], want a c and the gap`,
`TestOversizedLineIsDroppedNotFatal` (4 records, want 5), and `TestADropIsAGapInTheLog`.

- [ ] **Step 3: Write the gap**

<!-- patch: internal/daemon/acct/spool.go -->
````diff
diff --git a/internal/daemon/acct/spool.go b/internal/daemon/acct/spool.go
index d04e921..04fc2bc 100644
--- a/internal/daemon/acct/spool.go
+++ b/internal/daemon/acct/spool.go
@@ -132,6 +132,14 @@ type Spool struct {
 	mu    sync.Mutex
 	depth int // records durably written but not yet forwarded; shared with Offer, so mutex-protected
 
+	// gaps counts, by stage, records dropped and not yet reported to the sink
+	// as an account_gap record, and gapSince when the first was (flushGaps).
+	// Its own lock: a drop at Offer happens under mu, and one on the drain
+	// path does not.
+	gapMu    sync.Mutex
+	gaps     map[string]int
+	gapSince map[string]time.Time
+
 	// needNewline is set whenever the file may end mid-record: a write or sync
 	// that failed, or an existing file whose last byte is not "\n" at
 	// construction. The next Offer writes a leading newline so its record
@@ -387,7 +395,7 @@ func (s *Spool) Offer(r decision.Record) error {
 //
 // Called with mu held.
 func (s *Spool) offerFailed(stage string, err error) {
-	s.metrics.SpoolDrops.WithLabelValues(dropOfferRefused).Inc()
+	s.drop(dropOfferRefused)
 	s.logThrottled(&s.lastOfferLog,
 		"acct: spool %s failed on %s, accounting records are being refused: %v", stage, s.path, err)
 }
@@ -503,6 +511,13 @@ func (s *Spool) drainOnce() (ok bool, forwarded int) {
 	if s.forceFail { // test-only hook; see spool_test.go
 		return false, 0
 	}
+	// A hole reported before the records after it, so a reader of the log
+	// meets the gap where it happened (spec §5.7, §9).
+	if !s.flushGaps() {
+		s.sinkRefused = true
+		return false, 0
+	}
+	defer s.flushGaps()
 
 	draining := s.path + ".draining"
 	s.sinkRefused = false
@@ -572,7 +587,7 @@ func (s *Spool) drainOnce() (ok bool, forwarded int) {
 			switch {
 			case oversized:
 				log.Printf("acct: dropping oversized spool line (over %d bytes)", maxLineBytes)
-				s.metrics.SpoolDrops.WithLabelValues(dropDrainUnparseable).Inc()
+				s.drop(dropDrainUnparseable)
 			default:
 				err := s.deliverLine(bytes.TrimRight(line, "\n"))
 				if errors.Is(err, decision.ErrUnencodable) {
@@ -582,7 +597,7 @@ func (s *Spool) drainOnce() (ok bool, forwarded int) {
 					if err = s.setAside(line); err == nil {
 						log.Printf("acct: an accounting record the decision log cannot encode was set aside in %s",
 							s.path+".unencodable")
-						s.metrics.SpoolDrops.WithLabelValues(dropDrainSetAside).Inc()
+						s.drop(dropDrainSetAside)
 					}
 				}
 				if err != nil {
@@ -712,7 +727,7 @@ func (s *Spool) deliverLine(line []byte) error {
 	var r decision.Record
 	if err := r.UnmarshalJSON(line); err != nil {
 		log.Printf("acct: dropping spool line that failed to unmarshal: %v", err)
-		s.metrics.SpoolDrops.WithLabelValues(dropDrainUnparseable).Inc()
+		s.drop(dropDrainUnparseable)
 		return nil
 	}
 	// Offer took the record already redacted, but a spool file an earlier
@@ -794,3 +809,43 @@ func (f *failAfterReader) Read(p []byte) (int, error) {
 	f.n -= int64(n)
 	return n, err
 }
+
+// drop counts a record the spool will not write to the sink, by stage, and
+// holds it for the next account_gap record: the metric is the alarm, and the
+// record is what tells a reader of the log that the stream has a hole, which
+// reconciliation must know before it says a device did not ask (spec §9).
+func (s *Spool) drop(stage string) {
+	s.metrics.SpoolDrops.WithLabelValues(stage).Inc()
+	s.gapMu.Lock()
+	defer s.gapMu.Unlock()
+	if s.gaps == nil {
+		s.gaps, s.gapSince = map[string]int{}, map[string]time.Time{}
+	}
+	if s.gaps[stage] == 0 {
+		s.gapSince[stage] = time.Now()
+	}
+	s.gaps[stage]++
+}
+
+// flushGaps writes one account_gap record per stage with drops held, and
+// forgets each the sink took. It reports whether the sink took them all; a
+// refusal leaves the rest for the next pass. The count lives in memory, so a
+// restart loses what was not yet written; a restart is itself in port49d's
+// log.
+func (s *Spool) flushGaps() bool {
+	s.gapMu.Lock()
+	defer s.gapMu.Unlock()
+	for _, stage := range []string{dropOfferRefused, dropDrainUnparseable, dropDrainSetAside} {
+		n := s.gaps[stage]
+		if n == 0 {
+			continue
+		}
+		rec := decision.Record{TS: time.Now(), Event: decision.EventAccountGap,
+			Gap: &decision.Gap{Stage: stage, Records: n, Since: decision.FormatTime(s.gapSince[stage])}}
+		if err := s.sink.Write(rec); err != nil {
+			return false
+		}
+		delete(s.gaps, stage)
+	}
+	return true
+}
````

<!-- patch: internal/decision/log.go -->
````diff
diff --git a/internal/decision/log.go b/internal/decision/log.go
index 3ffadb4..3ef3da8 100644
--- a/internal/decision/log.go
+++ b/internal/decision/log.go
@@ -34,6 +34,7 @@ type Record struct {
 	Blob        *Blob        `json:"blob,omitempty"`
 	Unvalidated *Unvalidated `json:"unvalidated,omitempty"`
 	ServerMsg   string       `json:"server_msg,omitempty"`
+	Gap         *Gap         `json:"gap,omitempty"`
 	// IndexError names what a failed index write cost, on the record for the
 	// session that lost it. Revocation must report the contexts it could not
 	// reach (spec §5.6), and this is the only place that says which they are.
@@ -207,6 +208,19 @@ type Blob struct {
 	Redacted bool `json:"redacted,omitempty"`
 }
 
+// Gap is the `account_gap` record's body: how many accounting records port49
+// received and did not write to this log, at which stage, since when (spec
+// §5.7, §9). offer_refused was answered ERROR, and the device may send the
+// record again; drain_unparseable and drain_set_aside were answered SUCCESS
+// and are not in the log (a set-aside one is in the spool's .unencodable
+// file). Reconciliation reads it: a window with a gap cannot say a device
+// did not ask.
+type Gap struct {
+	Stage   string `json:"stage"`
+	Records int    `json:"records"`
+	Since   string `json:"since"`
+}
+
 // Unvalidated is what is recorded for a packet no key validated: cleartext header
 // fields, the source, and a hash of the body — never the body.
 type Unvalidated struct {
````

<!-- patch: internal/decision/reasons.go -->
````diff
diff --git a/internal/decision/reasons.go b/internal/decision/reasons.go
index e4aa1a1..33a8699 100644
--- a/internal/decision/reasons.go
+++ b/internal/decision/reasons.go
@@ -69,6 +69,10 @@ const (
 	EventBlob             = "blob"
 	EventAccount          = "account"
 	EventUnvalidated      = "unvalidated" // not a decision; header-only diagnosis record (spec §10)
+	// EventAccountGap is not a decision: accounting records port49 received
+	// and could not write, by stage, so a reader of the log knows the stream
+	// has a hole there (spec §5.7, §9).
+	EventAccountGap = "account_gap"
 )
 
 // EventRefresh is the broker carrying the policy in force into a live login
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/acct/sink_test.go internal/daemon/acct/spool.go internal/daemon/acct/spool_test.go internal/decision/log.go internal/decision/reasons.go
git commit -m "$(cat <<'EOF'
feat: a dropped accounting record is an account_gap in the log

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 16: Infer each device's configured capability from the decision log (spec §9)

**Files:**
- Create: `internal/capability/capability.go`
- Test: `internal/capability/capability_test.go`

**Interfaces:**
- Consumes: `decision.Record` and its events; Task 15's `EventAccountGap`, `Gap`;
  `platform.IsExecRecord`.
- Produces, for Task 17:
  - `const Session, Commands, ConfigCommands`;
  - `type Device struct{ Name, Platform string; Supports []string; Quarantine string }`;
  - `type Options struct{ From, To time.Time; ConfigEntries int; ConfigSilent float64 }`;
  - `type Row struct{ Device Device; Observed, Warnings, Notes []string; Unauthorized int; Examples
    []string; ConfigEntered, ConfigSilent int; Unattributed, Foreign, System int }`;
  - `type Report struct{ From, To time.Time; Rows []Row; Gaps []decision.Gap }` with
    `(Report).Qualified() bool`;
  - `func Infer(records []decision.Record, devices []Device, opt Options) Report`.

Spec §9's three observations, read off records in log order.
- **The matrix.** `session` and `commands` come from the authorization events.
  `config_commands` comes from an authorization request that followed a permitted `configure …`
  in the same context before its exec STOP.
- **Warnings.**
  - `never seen`: an admitted device with no record.
  - `config-commands probably off`: on a `commands` platform, at least `ConfigEntries` entries
    (default 5), at least `ConfigSilent` (0.8) of them followed by no request.
  - `N commands in accounting had no corresponding authorization request`: resolved command
    accounting whose text holds no authorized command of its context.
- **Notes.** A capability observed that the adapter does not declare. It is a lab measurement
  waiting to be made, never a fault.
- **Gaps.** The window's `account_gap` records.

The join is text containment, lower-cased with `<cr>` dropped (Decided 13), and it runs only on
platforms that declare `commands`. A session-only platform decides every command itself by design.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/capability/capability_test.go -->
````diff
diff --git a/internal/capability/capability_test.go b/internal/capability/capability_test.go
new file mode 100644
index 0000000..8fa34cb
--- /dev/null
+++ b/internal/capability/capability_test.go
@@ -0,0 +1,123 @@
+package capability
+
+import (
+	"reflect"
+	"strings"
+	"testing"
+	"time"
+
+	"github.com/rhwendt/port49/internal/decision"
+)
+
+var t0 = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
+
+type logb struct {
+	recs []decision.Record
+	at   time.Duration
+}
+
+func (l *logb) add(event, device, platformName, ctx string, edit func(*decision.Record)) {
+	l.at += time.Second
+	r := decision.Record{TS: t0.Add(l.at), Event: event, Device: &decision.Device{Name: device, Platform: platformName},
+		Session: &decision.Session{CtxID: ctx}}
+	if edit != nil {
+		edit(&r)
+	}
+	l.recs = append(l.recs, r)
+}
+
+func (l *logb) command(device, ctx, verdict string, words ...string) {
+	l.add(decision.EventAuthorizeCommand, device, "arista_eos", ctx, func(r *decision.Record) {
+		r.Verdict, r.Request = verdict, &decision.Request{Vector: append(words, "<cr>")}
+	})
+}
+
+func (l *logb) account(device, ctx, attribution string, words ...string) {
+	l.add(decision.EventAccount, device, "arista_eos", ctx, func(r *decision.Record) {
+		r.Flags, r.Attribution = "stop", attribution
+		raw := []string{"task_id=1"}
+		if len(words) > 0 {
+			raw = append(raw, "cmd="+strings.Join(words, " "))
+		}
+		r.AcctRecord = &decision.AcctRecord{Raw: raw, Vector: words}
+	})
+}
+
+var eos = []string{Session, Commands}
+
+func TestTheMatrix(t *testing.T) {
+	var l logb
+	// leaf-01: sessions and commands, and every command it accounted for
+	// was asked about.
+	l.add(decision.EventAuthorizeSession, "leaf-01", "arista_eos", "c1", nil)
+	l.command("leaf-01", "c1", decision.VerdictPermit, "show", "version")
+	l.account("leaf-01", "c1", "resolved", "show", "version", "<cr>")
+	// leaf-04: sessions, and commands in accounting nobody asked about.
+	l.add(decision.EventAuthorizeSession, "leaf-04", "arista_eos", "c4", nil)
+	for _, cmd := range []string{"show interfaces", "show version", "ping 10.0.0.1", "show version"} {
+		l.account("leaf-04", "c4", "resolved", strings.Fields(cmd)...)
+	}
+	l.account("leaf-04", "", "unattributed", "show", "clock")
+	devices := []Device{{Name: "leaf-01", Platform: "arista_eos", Supports: eos},
+		{Name: "leaf-04", Platform: "arista_eos", Supports: eos},
+		{Name: "ntp-01", Platform: "meinberg", Supports: []string{Session}},
+		{Name: "xr-edge-1", Platform: "cisco_ios_xr", Supports: eos, Quarantine: "@management undefined"}}
+	rep := Infer(l.recs, devices, Options{})
+	if !rep.Qualified() || len(rep.Rows) != 4 {
+		t.Fatalf("%+v", rep)
+	}
+	if r := rep.Rows[0]; !reflect.DeepEqual(r.Observed, eos) || len(r.Warnings) != 0 {
+		t.Errorf("leaf-01: %+v", r)
+	}
+	if r := rep.Rows[1]; r.Unauthorized != 3 || !reflect.DeepEqual(r.Examples, []string{"ping 10.0.0.1", "show interfaces",
+		"show version"}) || r.Unattributed != 1 || len(r.Warnings) != 1 {
+		t.Errorf("leaf-04: %+v", r)
+	}
+	if r := rep.Rows[2]; !reflect.DeepEqual(r.Warnings, []string{"never seen"}) {
+		t.Errorf("ntp-01: %+v", r)
+	}
+	if r := rep.Rows[3]; len(r.Warnings) != 0 {
+		t.Errorf("a quarantined device is not reported unseen: %+v", r)
+	}
+}
+
+// Configuration entries no authorization followed, over a window, say
+// config-commands is probably off; one session that left at once does not.
+func TestConfigCommandsProbablyOff(t *testing.T) {
+	var l logb
+	for i, ctx := range []string{"a", "b", "c", "d", "e"} {
+		l.command("leaf-04", ctx, decision.VerdictPermit, "configure", "terminal")
+		if i == 0 {
+			l.command("leaf-04", ctx, decision.VerdictPermit, "interface", "Ethernet1")
+		}
+		l.account("leaf-04", ctx, "resolved") // the exec STOP
+	}
+	devices := []Device{{Name: "leaf-04", Platform: "arista_eos", Supports: eos}}
+	r := Infer(l.recs, devices, Options{}).Rows[0]
+	if r.ConfigEntered != 5 || r.ConfigSilent != 4 || !strings.Contains(strings.Join(r.Warnings, ";"), "config-commands probably off") ||
+		!reflect.DeepEqual(r.Observed, []string{Commands, ConfigCommands}) {
+		t.Fatalf("%+v", r)
+	}
+	r = Infer(l.recs[:3], devices, Options{}).Rows[0]
+	if len(r.Warnings) != 0 {
+		t.Fatalf("one entry is not a window: %+v", r)
+	}
+}
+
+// A gap in the accounting stream qualifies the window; the window bounds
+// what is read; a session-only platform's commands are never reconciled.
+func TestGapsWindowsAndSessionOnly(t *testing.T) {
+	var l logb
+	l.account("srx-1", "s1", "resolved", "show", "version")
+	l.add(decision.EventAccountGap, "", "", "", func(r *decision.Record) {
+		r.Device, r.Session, r.Gap = nil, nil, &decision.Gap{Stage: "drain_unparseable", Records: 2}
+	})
+	devices := []Device{{Name: "srx-1", Platform: "juniper_junos", Supports: []string{Session}}}
+	rep := Infer(l.recs, devices, Options{})
+	if rep.Qualified() || rep.Rows[0].Unauthorized != 0 {
+		t.Fatalf("%+v", rep)
+	}
+	if rep := Infer(l.recs, devices, Options{From: t0.Add(90 * time.Minute)}); len(rep.Gaps) != 0 {
+		t.Fatalf("window: %+v", rep)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/capability/`
Expected: FAIL, build failed: `undefined: Session`, `undefined: Device`, `undefined: Infer`,
`undefined: Options`.

- [ ] **Step 3: Add the inference**

<!-- patch: internal/capability/capability.go -->
````diff
diff --git a/internal/capability/capability.go b/internal/capability/capability.go
new file mode 100644
index 0000000..a2df8a3
--- /dev/null
+++ b/internal/capability/capability.go
@@ -0,0 +1,264 @@
+// Package capability infers what each device is configured to authorize from
+// the decision log it already writes (spec §9): a device capable of command
+// authorization and not configured for it looks healthy while its commands
+// go unauthorized, and port49 must say so without asking an operator to
+// assert anything. It reads records only; it never contacts a device.
+package capability
+
+import (
+	"fmt"
+	"slices"
+	"sort"
+	"strings"
+	"time"
+
+	"github.com/rhwendt/port49/internal/decision"
+	"github.com/rhwendt/port49/internal/platform"
+)
+
+// The capabilities of spec §9's vocabulary, as `supports` names them.
+const (
+	Session        = "session"
+	Commands       = "commands"
+	ConfigCommands = "config_commands"
+)
+
+// Device is one inventory device as the report reads it: what its adapter
+// declares, and whether policy admits it now.
+type Device struct {
+	Name, Platform string
+	Supports       []string
+	// Quarantine is the first cause the device is quarantined for at the
+	// report's end, empty where it is admitted (spec §10).
+	Quarantine string
+}
+
+// Options bound the inference. The zero value takes every record and the
+// defaults below.
+type Options struct {
+	// From and To bound the window by record time; zero is unbounded.
+	From, To time.Time
+	// ConfigEntries is how many permitted configuration entries a device
+	// needs in the window before the config-commands inference speaks, and
+	// ConfigSilent the share of them that must see no authorization after
+	// them: spec §9's observation is evidence, not proof, and is read over a
+	// window, never per session. Defaults 5 and 0.8.
+	ConfigEntries int
+	ConfigSilent  float64
+}
+
+// Row is one device's line of the matrix, and its reconciliation.
+type Row struct {
+	Device   Device
+	Observed []string
+	Warnings []string
+	// Notes are what the matrix says that is no fault: a capability observed
+	// that the adapter does not declare is a lab measurement waiting to be
+	// made, never one to assert by hand (spec §9, "Principle").
+	Notes []string
+	// Unauthorized counts command accounting records, in contexts port49
+	// authenticated, that no authorization request of the same context
+	// accounts for; Examples are up to three of their commands.
+	Unauthorized int
+	Examples     []string
+	// ConfigEntered and ConfigSilent are the permitted configuration entries
+	// and those no authorization request followed in their context.
+	ConfigEntered, ConfigSilent int
+	// Unattributed, Foreign and System count the device's accounting records
+	// by attribution (spec §5.8): the stream's health for this device.
+	Unattributed, Foreign, System int
+}
+
+// Report is the inference over one window.
+type Report struct {
+	From, To time.Time
+	Rows     []Row
+	// Gaps are the account_gap records in the window: records port49
+	// received and did not write. Where there are any, a reconciliation
+	// finding says "possibly": the gap may be the authorization it did not
+	// find (spec §9, "What silence can and cannot mean").
+	Gaps []decision.Gap
+}
+
+// Qualified reports whether the window's accounting stream is whole, so a
+// reconciliation finding stands as a finding.
+func (r Report) Qualified() bool { return len(r.Gaps) == 0 }
+
+// Infer reads records, in log order, against devices (spec §9).
+func Infer(records []decision.Record, devices []Device, opt Options) Report {
+	if opt.ConfigEntries == 0 {
+		opt.ConfigEntries = 5
+	}
+	if opt.ConfigSilent == 0 {
+		opt.ConfigSilent = 0.8
+	}
+	var rep Report
+	type ctxKey struct{ device, ctx string }
+	byDevice := map[string][]decision.Record{}
+	authorized := map[ctxKey][]string{} // context → each authorized command, as text
+	for _, r := range records {
+		if (!opt.From.IsZero() && r.TS.Before(opt.From)) || (!opt.To.IsZero() && r.TS.After(opt.To)) {
+			continue
+		}
+		if rep.From.IsZero() || r.TS.Before(rep.From) {
+			rep.From = r.TS
+		}
+		if r.TS.After(rep.To) {
+			rep.To = r.TS
+		}
+		if r.Event == decision.EventAccountGap && r.Gap != nil {
+			rep.Gaps = append(rep.Gaps, *r.Gap)
+			continue
+		}
+		if r.Device == nil {
+			continue
+		}
+		byDevice[r.Device.Name] = append(byDevice[r.Device.Name], r)
+		if r.Event == decision.EventAuthorizeCommand && r.Session != nil && r.Request != nil {
+			k := ctxKey{r.Device.Name, r.Session.CtxID}
+			authorized[k] = append(authorized[k], text(r.Request.Vector))
+		}
+	}
+	for _, d := range devices {
+		row := Row{Device: d}
+		recs := byDevice[d.Name]
+		observed := map[string]bool{}
+		var entries []decision.Record // permitted configuration entries
+		unmatched := map[string]bool{}
+		for i, r := range recs {
+			switch r.Event {
+			case decision.EventAuthorizeSession:
+				observed[Session] = true
+			case decision.EventAuthorizeCommand:
+				observed[Commands] = true
+				if r.Verdict == decision.VerdictPermit && r.Request != nil && configEntry(r.Request.Vector) {
+					entries = append(entries, r)
+					if followed(recs[i+1:], r.Session) {
+						observed[ConfigCommands] = true
+					} else {
+						row.ConfigSilent++
+					}
+				}
+			case decision.EventAccount:
+				switch r.Attribution {
+				case "unattributed":
+					row.Unattributed++
+				case "foreign":
+					row.Foreign++
+				case "system":
+					row.System++
+				}
+				if !slices.Contains(d.Supports, Commands) || r.Attribution != "resolved" || r.Session == nil ||
+					r.AcctRecord == nil || isExec(d.Platform, r.AcctRecord.Raw) {
+					continue
+				}
+				cmd := text(r.AcctRecord.Vector)
+				if cmd == "" {
+					continue
+				}
+				if !slices.ContainsFunc(authorized[ctxKey{d.Name, r.Session.CtxID}], func(a string) bool {
+					return a != "" && strings.Contains(cmd, a)
+				}) {
+					unmatched[r.Session.CtxID+"\x00"+cmd] = true
+				}
+			}
+		}
+		row.ConfigEntered = len(entries)
+		for _, c := range []string{Session, Commands, ConfigCommands} {
+			if observed[c] {
+				row.Observed = append(row.Observed, c)
+			}
+		}
+		keys := make([]string, 0, len(unmatched))
+		for k := range unmatched {
+			keys = append(keys, k)
+		}
+		sort.Strings(keys)
+		row.Unauthorized = len(keys)
+		for _, k := range keys {
+			_, cmd, _ := strings.Cut(k, "\x00")
+			if len(row.Examples) < 3 && !slices.Contains(row.Examples, cmd) {
+				row.Examples = append(row.Examples, cmd)
+			}
+		}
+		row.Warnings = warnings(row, opt)
+		for _, c := range row.Observed {
+			if !slices.Contains(d.Supports, c) {
+				row.Notes = append(row.Notes, c+" observed, and the adapter does not declare it")
+			}
+		}
+		rep.Rows = append(rep.Rows, row)
+	}
+	return rep
+}
+
+func warnings(row Row, opt Options) []string {
+	var out []string
+	d := row.Device
+	if d.Quarantine == "" && len(row.Observed) == 0 {
+		out = append(out, "never seen")
+	}
+	if slices.Contains(d.Supports, Commands) && row.ConfigEntered >= opt.ConfigEntries &&
+		float64(row.ConfigSilent) >= opt.ConfigSilent*float64(row.ConfigEntered) {
+		out = append(out, fmt.Sprintf("config-commands probably off: %d of %d configuration entries saw no "+
+			"authorization request after them in their session", row.ConfigSilent, row.ConfigEntered))
+	}
+	if row.Unauthorized > 0 {
+		out = append(out, fmt.Sprintf("%d commands in accounting had no corresponding authorization request",
+			row.Unauthorized))
+	}
+	return out
+}
+
+// text is a command vector as one lower-case line with no trailing `<cr>`:
+// the form the join compares, where an accounting record's text holds the
+// authorization's (NX-OS's accounting `cmd` is the configuration path joined
+// with ` ; ` and a result, tests/lab/results/L21-cisco_nxos.md). Holding it
+// is the test, so an unexpected accounting shape reads as authorized, which
+// under-reports rather than accuses (spec §9).
+func text(vector []string) string {
+	for len(vector) > 0 && vector[len(vector)-1] == "<cr>" {
+		vector = vector[:len(vector)-1]
+	}
+	return strings.ToLower(strings.Join(vector, " "))
+}
+
+// configEntry is a command that enters configuration mode on the platforms
+// that authorize commands: `configure`, and what follows it.
+func configEntry(vector []string) bool {
+	return len(vector) > 0 && strings.EqualFold(vector[0], "configure")
+}
+
+// followed reports whether an authorization request of the same context
+// comes after a configuration entry, before the context's session ends:
+// spec §9's third observation reads silence up to the session's end.
+func followed(after []decision.Record, s *decision.Session) bool {
+	if s == nil {
+		return false
+	}
+	for _, r := range after {
+		if r.Session == nil || r.Session.CtxID != s.CtxID {
+			continue
+		}
+		switch {
+		case r.Event == decision.EventAuthorizeCommand:
+			return true
+		case r.Event == decision.EventAccount && r.Flags == "stop" && r.AcctRecord != nil &&
+			len(r.AcctRecord.Vector) == 0:
+			return false // the exec STOP: the session ended
+		}
+	}
+	return false
+}
+
+// isExec reports whether an accounting record is the session's own exec
+// record rather than a command's (spec §5.8).
+func isExec(platformName string, raw []string) bool {
+	cmd := ""
+	for _, a := range raw {
+		if strings.HasPrefix(a, "cmd=") || strings.HasPrefix(a, "cmd*") {
+			cmd = a[4:]
+		}
+	}
+	return platform.IsExecRecord(platformName, cmd)
+}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/capability/capability.go internal/capability/capability_test.go
git commit -m "$(cat <<'EOF'
feat: infer each device's configured capability from the decision log (spec §9)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 17: port49 devices capabilities, and CI names rules a platform never enforces (spec §9)

**Files:**
- Create: `cmd/port49/capabilities.go`
- Modify: `cmd/port49/main.go` (usage and dispatch)
- Modify: `internal/policy/lint.go` (`unenforced_rules`, `UnenforcedRules`)
- Test: `cmd/port49/capabilities_test.go` (new), `internal/policy/projection_test.go`,
  `internal/policy/spec11_test.go`

**Interfaces:**
- Consumes: Task 16's `capability.Infer` and its types; `policyFiles`, `redactOutput`;
  `(*Policy).Quarantined`, `Dialect`, `Devices`, `Redactions`.
- Produces:
  - `port49 devices capabilities --policy FILE --inventory FILE [--since DURATION] LOGFILE...|-`;
  - `devicesCapabilities(args []string, stdout, stderr io.Writer) int`;
  - `readLogs(names []string) ([]decision.Record, int, error)`;
  - `FindingUnenforcedRules = "unenforced_rules"` and `func (p *Policy) UnenforcedRules(now
    time.Time) []Finding`.

The command prints spec §9's matrix with a header line naming the window and the accounting
stream's health, then one `⚠ UNAUTHORIZED TIER — <device>` block per device with its examples and
its accounting health. With a gap in the window, the block reads `? POSSIBLY AN UNAUTHORIZED
TIER` and does not set the exit code. The command exits 1 on a finding a cron job should page on,
0 otherwise, and 2 on a usage error. A log line that does not parse is counted, never quoted, and
everything printed passes through the policy's redaction. `--since` is measured back from the
newest record, never from the wall clock, so a replayed log reports the same thing on any day.

CI's half: a subject whose roles carry command rules on a platform that neither authorizes
commands nor projects them is told the rules decide nothing there. That covers Junos under 1.0.0,
and spec §11's example pins no set, so its expected findings gain four.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/capabilities_test.go -->
````diff
diff --git a/cmd/port49/capabilities_test.go b/cmd/port49/capabilities_test.go
new file mode 100644
index 0000000..e5670c1
--- /dev/null
+++ b/cmd/port49/capabilities_test.go
@@ -0,0 +1,43 @@
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
+// `devices capabilities` reads the log a daemon wrote and prints the matrix
+// and the reconciliation, and exits 1 on a finding; a gap in the accounting
+// stream makes the reconciliation's finding a possibility.
+func TestDevicesCapabilities(t *testing.T) {
+	pol, inv := policyFixture(t)
+	log := filepath.Join(t.TempDir(), "decisions.jsonl")
+	lines := []string{
+		`{"ts":"2026-09-24T12:00:01.000Z","event":"authorize_session","verdict":"permit","reason":"context_matched","device":{"nas":"10.0.0.1","name":"leaf-01","platform":"arista_eos"},"session":{"ctx_id":"c1","port":"vty4","rem_addr":"","privilege":15}}`,
+		`{"ts":"2026-09-24T12:00:02.000Z","event":"account","flags":"stop","attribution":"resolved","device":{"nas":"10.0.0.1","name":"leaf-01","platform":"arista_eos"},"session":{"ctx_id":"c1","port":"vty4","rem_addr":"","privilege":15},"record":{"raw":["task_id=3","cmd=show interfaces <cr>"],"vector":["show","interfaces","<cr>"],"priv_lvl":15}}`,
+		`not a record`,
+	}
+	if err := os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	code := run([]string{"devices", "capabilities", "--policy", pol, "--inventory", inv, log}, &out, &errb)
+	if code != 1 || !strings.Contains(out.String(), "leaf-01  arista_eos  admitted   session,commands  session") ||
+		!strings.Contains(out.String(), "⚠ UNAUTHORIZED TIER — leaf-01") ||
+		!strings.Contains(out.String(), `example: "show interfaces"`) ||
+		!strings.Contains(out.String(), "1 log lines did not read as records") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+	gap := `{"ts":"2026-09-24T12:00:03.000Z","event":"account_gap","gap":{"stage":"drain_unparseable","records":2,"since":"2026-09-24T12:00:00.000Z"}}`
+	if err := os.WriteFile(log, []byte(strings.Join(append(lines[:2], gap), "\n")+"\n"), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	out.Reset()
+	code = run([]string{"devices", "capabilities", "--policy", pol, "--inventory", inv, log}, &out, &errb)
+	if code != 0 || !strings.Contains(out.String(), "? POSSIBLY AN UNAUTHORIZED TIER") ||
+		!strings.Contains(out.String(), "drain_unparseable 2") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+}
````

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
index 52b0336..fb53773 100644
--- a/internal/policy/projection_test.go
+++ b/internal/policy/projection_test.go
@@ -210,3 +210,23 @@ func TestTheDiffReportsAProjectionChange(t *testing.T) {
 		t.Error("a projected reply's change is a raise until a reply: test asserts it")
 	}
 }
+
+// Rules on a platform that neither asks port49 nor has them projected decide
+// nothing, and CI says so (spec §9); projected, they are the reply.
+func TestUnenforcedRules(t *testing.T) {
+	count := func(p *Policy) int {
+		n := 0
+		for _, f := range p.Lint(noon) {
+			if f.Kind == FindingUnenforcedRules {
+				n++
+			}
+		}
+		return n
+	}
+	if n := count(mustParse(t, readonlyCarveOut)); n != 1 {
+		t.Errorf("1.0.0: %d", n)
+	}
+	if n := count(parseProjected(t, platform.BitDeliveryUserPermissions, readonlyCarveOut)); n != 0 {
+		t.Errorf("projected: %d", n)
+	}
+}
````

<!-- patch: internal/policy/spec11_test.go -->
````diff
diff --git a/internal/policy/spec11_test.go b/internal/policy/spec11_test.go
index def0084..7df6123 100644
--- a/internal/policy/spec11_test.go
+++ b/internal/policy/spec11_test.go
@@ -198,8 +198,12 @@ func TestTheCompletePolicyExampleReportsWhatItShould(t *testing.T) {
 	// Two exposures on EOS: svc_oxidized at admin, and noc_tier1 at operator,
 	// whose network-operator still ran clear counters and clear ip bgp * with
 	// port49 down (tests/lab/results/L22-arista_eos.md).
+	// And the example pins no set, so it renders with 1.0.0, which projects
+	// nothing onto Junos: each subject granted there with rules is told its
+	// rules decide nothing on the SRXs (spec §9).
 	want := []string{FindingFallbackExposure, FindingFallbackExposure, FindingGroupSubject, FindingGroupSubject,
-		FindingGroupSubject, FindingIncomparableVersion}
+		FindingGroupSubject, FindingIncomparableVersion, FindingUnenforcedRules, FindingUnenforcedRules,
+		FindingUnenforcedRules, FindingUnenforcedRules}
 	if !reflect.DeepEqual(kinds, want) {
 		t.Fatalf("findings %q, want %q", kinds, want)
 	}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/`
Expected: FAIL, build failed: `undefined: FindingUnenforcedRules`; and `--- FAIL:
TestDevicesCapabilities: code 2` (usage: the command does not exist yet).

- [ ] **Step 3: Add the command and the finding**

<!-- patch: cmd/port49/capabilities.go -->
````diff
diff --git a/cmd/port49/capabilities.go b/cmd/port49/capabilities.go
new file mode 100644
index 0000000..7c5eab6
--- /dev/null
+++ b/cmd/port49/capabilities.go
@@ -0,0 +1,183 @@
+package main
+
+import (
+	"bufio"
+	"flag"
+	"fmt"
+	"io"
+	"os"
+	"sort"
+	"strings"
+	"text/tabwriter"
+	"time"
+
+	"github.com/rhwendt/port49/internal/capability"
+	"github.com/rhwendt/port49/internal/decision"
+)
+
+// devicesCapabilities is `port49 devices capabilities` (spec §9): what each
+// inventory device declares it authorizes beside what the decision log shows
+// it asked, and each device whose accounting holds commands no authorization
+// request accounts for. It reads the log a daemon wrote; it never contacts a
+// device, and nobody asserts anything by hand. It exits 1 on a finding a
+// cron job should page on: a device never seen, config-commands probably off,
+// or an unauthorized tier in a window whose accounting stream is whole.
+func devicesCapabilities(args []string, stdout, stderr io.Writer) int {
+	fs := flag.NewFlagSet("port49 devices capabilities", flag.ContinueOnError)
+	fs.SetOutput(stderr)
+	var files policyFiles
+	files.register(fs)
+	since := fs.Duration("since", 0, "read only the records within this long of the newest one (default: all)")
+	if err := fs.Parse(args); err != nil {
+		return 2
+	}
+	if files.missing() || fs.NArg() == 0 || *since < 0 {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
+	out, errOut, flush := redactOutput(stdout, stderr)
+	defer flush()
+	stdout, stderr = out, errOut
+	p, err := files.load()
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 devices capabilities:", err)
+		return 1
+	}
+	out.rules, errOut.rules = p.Redactions(), p.Redactions()
+	recs, unread, err := readLogs(fs.Args())
+	if err != nil {
+		fmt.Fprintln(stderr, "port49 devices capabilities:", err)
+		return 1
+	}
+	var opt capability.Options
+	if *since > 0 && len(recs) > 0 {
+		newest := recs[0].TS
+		for _, r := range recs {
+			if r.TS.After(newest) {
+				newest = r.TS
+			}
+		}
+		opt.From = newest.Add(-*since)
+	}
+	now := time.Now()
+	var devices []capability.Device
+	for _, d := range p.Devices() {
+		cd := capability.Device{Name: d.Name, Platform: d.Platform, Supports: p.Dialect(d.Platform).Supports}
+		cd.Quarantine, _ = p.Quarantined(d.Name, now)
+		devices = append(devices, cd)
+	}
+	sort.Slice(devices, func(i, j int) bool { return devices[i].Name < devices[j].Name })
+	rep := capability.Infer(recs, devices, opt)
+	fmt.Fprintf(stdout, "window: %s to %s; %s\n", decision.FormatTime(rep.From), decision.FormatTime(rep.To),
+		streamHealth(rep, unread))
+	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
+	fmt.Fprintln(tw, "DEVICE\tPLATFORM\tADMISSION\tSUPPORTS\tOBSERVED\t")
+	code := 0
+	for _, r := range rep.Rows {
+		admission, observed := "admitted", strings.Join(r.Observed, ",")
+		if observed == "" {
+			observed = "—"
+		}
+		var flags []string
+		if r.Device.Quarantine != "" {
+			admission = "quarantined"
+			flags = append(flags, "✗ "+r.Device.Quarantine)
+		}
+		for _, w := range r.Warnings {
+			if r.Unauthorized > 0 && strings.HasSuffix(w, "had no corresponding authorization request") {
+				continue // the reconciliation section says it, qualified
+			}
+			flags = append(flags, "⚠ "+w)
+			code = 1
+		}
+		for _, n := range r.Notes {
+			flags = append(flags, "note: "+n)
+		}
+		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Device.Name, r.Device.Platform, admission,
+			strings.Join(r.Device.Supports, ","), observed, strings.Join(flags, "; "))
+	}
+	tw.Flush()
+	for _, r := range rep.Rows {
+		if r.Unauthorized == 0 {
+			continue
+		}
+		head := "⚠ UNAUTHORIZED TIER"
+		if !rep.Qualified() {
+			head = "? POSSIBLY AN UNAUTHORIZED TIER (the accounting stream has a gap in this window)"
+		} else {
+			code = 1
+		}
+		quoted := make([]string, len(r.Examples))
+		for i, e := range r.Examples {
+			quoted[i] = fmt.Sprintf("%q", e)
+		}
+		fmt.Fprintf(stdout, "\n%s — %s\n    %d commands in accounting had no corresponding authorization request\n"+
+			"    example: %s\n    accounting on %s in the window: %d unattributed, %d foreign, %d system\n", head,
+			r.Device.Name, r.Unauthorized, strings.Join(quoted, ", "), r.Device.Name, r.Unattributed, r.Foreign, r.System)
+	}
+	return code
+}
+
+// streamHealth is the window's accounting stream as the report qualifies
+// its findings by it (spec §9, "What silence can and cannot mean").
+func streamHealth(rep capability.Report, unread int) string {
+	s := "accounting stream: no account_gap in the window"
+	if !rep.Qualified() {
+		by := map[string]int{}
+		for _, g := range rep.Gaps {
+			by[g.Stage] += g.Records
+		}
+		var parts []string
+		for _, stage := range []string{"offer_refused", "drain_unparseable", "drain_set_aside"} {
+			if by[stage] > 0 {
+				parts = append(parts, fmt.Sprintf("%s %d", stage, by[stage]))
+			}
+		}
+		s = "accounting stream: records dropped in the window (" + strings.Join(parts, ", ") +
+			"), so a reconciliation finding below is possible, not proven"
+	}
+	if unread > 0 {
+		s += fmt.Sprintf("; %d log lines did not read as records and were skipped", unread)
+	}
+	return s
+}
+
+// readLogs reads decision-log files, `-` for stdin, one JSON record a line.
+// A line that does not read as a record is counted, never quoted.
+func readLogs(names []string) (recs []decision.Record, unread int, err error) {
+	for _, name := range names {
+		if err := readLog(name, &recs, &unread); err != nil {
+			return nil, 0, err
+		}
+	}
+	return recs, unread, nil
+}
+
+func readLog(name string, recs *[]decision.Record, unread *int) error {
+	in := io.Reader(os.Stdin)
+	if name != "-" {
+		f, err := os.Open(name)
+		if err != nil {
+			return err
+		}
+		defer f.Close()
+		in = f
+	}
+	sc := bufio.NewScanner(in)
+	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
+	for sc.Scan() {
+		if strings.TrimSpace(sc.Text()) == "" {
+			continue
+		}
+		var r decision.Record
+		if r.UnmarshalJSON(sc.Bytes()) != nil {
+			*unread++
+			continue
+		}
+		*recs = append(*recs, r)
+	}
+	if err := sc.Err(); err != nil {
+		return fmt.Errorf("%s was not read to the end: %w", name, err)
+	}
+	return nil
+}
````

<!-- patch: cmd/port49/main.go -->
````diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index 30dcc08..aa00e0c 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -45,6 +45,7 @@ const usage = `usage:
                          --classes --config PORT49D_YAML PLATFORM)
   port49 platform upgrade --policy FILE --inventory FILE --to VERSION [--write]
   port49 devices check-config --policy FILE --inventory FILE --device NAME CONFIGFILE
+  port49 devices capabilities --policy FILE --inventory FILE [--since DURATION] LOGFILE...|-
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
@@ -80,6 +81,9 @@ func run(args []string, stdout, stderr io.Writer) int {
 		if len(args) > 1 && args[1] == "check-config" {
 			return checkConfig(args[2:], stdout, stderr)
 		}
+		if len(args) > 1 && args[1] == "capabilities" {
+			return devicesCapabilities(args[2:], stdout, stderr)
+		}
 	}
 	fmt.Fprint(stderr, usage)
 	return 2
````

<!-- patch: internal/policy/lint.go -->
````diff
diff --git a/internal/policy/lint.go b/internal/policy/lint.go
index cbaaa05..4ccd79d 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -50,6 +50,10 @@ const (
 	// which quarantines the device, with the class line that would carry it
 	// on the device instead (spec §8).
 	FindingProjectionOverflow = "projection_overflow"
+	// FindingUnenforcedRules is a subject's command rules on a platform that
+	// neither asks port49 about a command nor has them projected into its
+	// session reply: they decide nothing there (spec §9, "CI").
+	FindingUnenforcedRules = "unenforced_rules"
 )
 
 // Lint computes the findings at now, ordered by kind and then message so two
@@ -151,6 +155,7 @@ func (p *Policy) Lint(now time.Time) []Finding {
 	}
 	out = append(out, p.redundantOverrides()...)
 	out = append(out, p.Projections(now)...)
+	out = append(out, p.UnenforcedRules(now)...)
 	out = append(out, p.intersections(now)...)
 	if len(p.tests) == 0 {
 		add(FindingNoTests, "the policy has no tests: nothing in it acknowledges a shadowed deny, an expansion or "+
@@ -608,3 +613,35 @@ func projectionMessage(subject, platformName string, pr projection.Result, patte
 	}
 	return msg
 }
+
+// UnenforcedRules reports every subject whose roles carry command rules on
+// a platform that authorizes no command and projects none into its session
+// reply (spec §9, "CI: a granted role carries command rules that the
+// platform's supports cannot enforce"), once per subject and platform: the
+// device never asks, so the rules decide nothing there. On a pinned set that
+// projects the platform the rules are its reply, and nothing is reported.
+func (p *Policy) UnenforcedRules(now time.Time) []Finding {
+	var out []Finding
+	seen := map[string]bool{}
+	for _, name := range sortedKeys(p.subs) {
+		for _, d := range p.env.Devices {
+			dialect := p.dialect(d.Platform)
+			if dialect.Authorizes("commands") || dialect.Projected() || seen[name+"\x00"+d.Platform] {
+				continue
+			}
+			for _, at := range p.expiryInstants(now) {
+				res, err := p.resolve(p.subs[name], d, at)
+				if err != nil || len(res.Blob.Rules) == 0 {
+					continue
+				}
+				seen[name+"\x00"+d.Platform] = true
+				out = append(out, Finding{Kind: FindingUnenforcedRules, Message: fmt.Sprintf("subject %q on %s "+
+					"(supports: %s): its roles carry %d command rules, and %s neither asks port49 about a command nor "+
+					"has them rendered into its session reply, so they decide nothing there (spec §9)", name,
+					d.Platform, strings.Join(dialect.Supports, ", "), len(res.Blob.Rules), d.Platform)})
+				break
+			}
+		}
+	}
+	return out
+}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

Also run the new command against a real log. The lab daemon writes one: `./bin/port49 devices
capabilities --policy tests/lab/slice/policy.yaml --inventory tests/lab/inventory-lab.yaml
tests/lab/logs/*.jsonl`. Read the matrix. The Junos devices show `session` observed and never
`commands`.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/capabilities.go cmd/port49/capabilities_test.go cmd/port49/main.go internal/policy/lint.go internal/policy/projection_test.go internal/policy/spec11_test.go
git commit -m "$(cat <<'EOF'
feat: port49 devices capabilities, and CI names rules a platform never enforces (spec §9)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 18: (lab, on beehive) The projection's differential test

**Files:**
- Create: `tests/lab/projection_test.go`
- Results (written by the run): `tests/lab/results/L12-projection-juniper_vjunos-router.md`,
  `L12-projection-juniper_vsrx.md`; evidence `projection-juniper_*.pcap`

**Interfaces:**
- Consumes: Task 2's `junosProbe`, `junosRun`, `junosConfigureAdmin`, `junosPer`; Task 12's
  `platform.ReferenceClasses`; Task 13's set 1.1.0; Task 8's `projection.JunosFacts`,
  `Result.Device`; `policy.Load`, `Decide`, `ResolveSubject`, `Quarantined`; the slice's `sliceUser`,
  `slicePrincipal`, `sliceBrokerURL`, `slicePKIDir`, `sliceToken`, `stopSliceAgent`,
  `tests/lab/slice/broker.yaml`.
- Produces: the notes Task 19 closes L9, L10 (Junos) and L12 on, and sets `verified` by.

This is spec §8's "Differential testing is required". The test applies the reference
configuration `ReferenceClasses` renders for 1.1.0, with a 12h max_session_age, over the
break-glass CLI, and restores the lab's own afterwards: the `remote` user on `p49-readonly`, and
no `strict-authorization`. For each of nine rule shapes it writes a policy pinning 1.1.0 and
restarts port49d with the slice's broker on it. It then runs `port49 login` and `port49 token
<node>`, logs in with the token, reads `show cli authorization`, and types thirteen probes under
`junosPer`. Each probe's outcome is compared with `policy.Decide` on the command as the device
expands it:
- the device running a command port49 denies fails the test, as fail-open;
- the device refusing one port49 permits must be what `Result.Device` predicted (narrower by
  design), or it fails as a model mismatch.

A shape the generator refuses must be quarantined, and `port49 token` must be refused for the
device. Shapes that need a deny render only where `JunosFacts.DenyMatchesExpanded` is true, and
are expected refused otherwise. `SHOW VERSION` and `sh ver` are asked of port49 as `show version`.

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/projection_test.go -->
````diff
diff --git a/tests/lab/projection_test.go b/tests/lab/projection_test.go
new file mode 100644
index 0000000..aa78bb8
--- /dev/null
+++ b/tests/lab/projection_test.go
@@ -0,0 +1,278 @@
+//go:build lab
+
+package lab
+
+import (
+	"fmt"
+	"os"
+	"os/exec"
+	"path/filepath"
+	"strings"
+	"testing"
+	"time"
+
+	"github.com/rhwendt/port49/internal/admission"
+	adapter "github.com/rhwendt/port49/internal/platform"
+	"github.com/rhwendt/port49/internal/policy"
+	"github.com/rhwendt/port49/internal/projection"
+	"github.com/rhwendt/port49/internal/testpki"
+)
+
+// TestProjectionDifferential is spec §8's differential test of decision
+// 22's projection: the reference configuration `platform export --classes`
+// renders for set 1.1.0 is applied to the device, and for each rule shape the
+// generator produces, a policy pinning 1.1.0 is minted through the broker, the
+// token logs in, and every probe's outcome on the device is compared with
+// port49's own decision on the command as the device expands it. The device
+// running a command port49 denies fails the test; the device refusing one
+// port49 permits must be what the projection itself predicts (a permit beyond
+// the level's bits, say), or it fails too. A shape the generator refuses must
+// quarantine the device: the login is refused and nothing is sent.
+//
+// Every command typed has junosPer's deadline; a prompt that does not come
+// back is not observed, and fails.
+
+// projectionProbe is a command as typed and as the device expands it: port49
+// is asked about the second, since a session-only device decides on it.
+type projectionProbe struct {
+	junosProbe
+	canonical string
+}
+
+var projectionProbes = []projectionProbe{
+	{junosProbe{cmd: "show version"}, "show version"},
+	{junosProbe{cmd: "show system uptime"}, "show system uptime"},
+	{junosProbe{cmd: "show interfaces terse"}, "show interfaces terse"},
+	{junosProbe{cmd: "show interfaces fxp0 terse"}, "show interfaces fxp0 terse"},
+	{junosProbe{cmd: "show interfaces lo0 terse"}, "show interfaces lo0 terse"},
+	{junosProbe{cmd: "show configuration system host-name"}, "show configuration system host-name"},
+	{junosProbe{cmd: "show route summary"}, "show route summary"},
+	{junosProbe{cmd: "clear interfaces statistics fxp0"}, "clear interfaces statistics fxp0"},
+	{junosProbe{cmd: "ping 127.0.0.1 count 1 rapid"}, "ping 127.0.0.1 count 1 rapid"},
+	{junosProbe{cmd: "sh ver"}, "show version"},
+	{junosProbe{cmd: "SHOW VERSION"}, "show version"},
+	{junosProbe{cmd: "request system reboot", complete: true}, "request system reboot"},
+	{junosProbe{cmd: "restart routing", complete: true}, "restart routing"},
+}
+
+// projectionShapes are the rule shapes the generator produces, and the one
+// it refuses. Each is the roles block of a policy pinning set 1.1.0. A shape
+// that sends a deny beneath a bit renders only where JunosFacts says a deny
+// reads the expanded command (L9); elsewhere it is refused like the refused
+// shape, and quarantines the device.
+var projectionShapes = []struct {
+	name, roles        string
+	sendsDeny, refused bool
+}{
+	{"readonly", `  - {name: r, privilege: readonly, permit: ["show **"]}`, false, false},
+	{"readonly, a deny aligned with a bit", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}`, true, false},
+	{"a permit beneath a deny", `  - {name: r, privilege: readonly, permit: ["show **", "show configuration system host-name"], deny: ["show configuration **"]}`, true, false},
+	{"narrow", `  - {name: r, privilege: readonly, permit: ["show version", "show interfaces **"]}`, false, false},
+	{"a class term", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show interfaces @management **"]}`, true, false},
+	{"a permit beyond the bits", `  - {name: r, privilege: readonly, permit: ["show **", "clear interfaces statistics **"]}`, false, false},
+	{"operator", `  - {name: r, privilege: operator, permit: ["show **", "clear **", "ping **"]}`, false, false},
+	{"admin", `  - {name: r, privilege: admin, permit: ["**"]}`, false, false},
+	{"the refused shape", `  - {name: r, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}`, false, true},
+}
+
+func TestProjectionDifferential(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
+			t.Skip("Junos only")
+		}
+		port49 := filepath.Join(root, "bin", "port49")
+		if _, err := os.Stat(port49); err != nil {
+			t.Fatalf("%s is missing: run `make build` first (%v)", port49, err)
+		}
+		set, ok := adapter.Set("1.1.0")
+		if !ok || !set["juniper_junos"].Projected() {
+			t.Fatal("set 1.1.0 does not project juniper_junos (plan 5b, Task 13)")
+		}
+		reference, err := adapter.ReferenceClasses(set["juniper_junos"], 12*time.Hour)
+		if err != nil {
+			t.Fatal(err)
+		}
+		stop := l.capture(t, "projection")
+		defer stop()
+		l.junosConfigureAdmin(t, reference)
+		defer l.junosConfigureAdmin(t, projectionRestore(reference))
+		pki := filepath.Join(root, slicePKIDir)
+		if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
+			t.Fatal(err)
+		}
+		inv, err := admission.LoadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
+		if err != nil {
+			t.Fatal(err)
+		}
+		defer func() {
+			if std, err := l.configPath(); err == nil {
+				if err := l.restart(std); err != nil {
+					t.Errorf("could not put port49d back on the lab config: %v", err)
+				}
+			}
+		}()
+		var b strings.Builder
+		fmt.Fprintf(&b, "The reference configuration applied, as `port49 platform export --classes` prints it for set "+
+			"1.1.0 with a 12h max_session_age:\n\n```\n%s\n```\n", strings.Join(reference, "\n"))
+		fmt.Fprintf(&b, "\nThe binary's JunosFacts: %+v.\n", projection.JunosFacts)
+		for _, shape := range projectionShapes {
+			fmt.Fprintf(&b, "\n### %s\n\n", shape.name)
+			refused := shape.refused || (shape.sendsDeny && !projection.JunosFacts.DenyMatchesExpanded)
+			b.WriteString(l.projectionShape(t, port49, pki, inv.Devices, shape.name, shape.roles, refused))
+		}
+		l.result(t, "L12-projection", "Decision 22's projection, differentially: for each rule shape the generator "+
+			"produces, what the device runs under the reply port49 renders, compared with port49's own decision on "+
+			"the command as the device expands it — never more — and, for the refused shape, that the device is "+
+			"quarantined (spec §8, \"Verification\"; §13 decision 22; §15 L9, L12).", b.String())
+	})
+}
+
+// projectionShape runs one shape and renders its section of the note.
+func (l *lab) projectionShape(t *testing.T, port49, pki string, devices []admission.Device, name, roles string,
+	refused bool) string {
+	t.Helper()
+	body := "platform_set: 1.1.0\nscopes:\n  - {name: all_devices, match: {}}\nroles:\n" + roles + "\n" +
+		"subjects:\n  - {name: slice_operator, identity: [\"" + slicePrincipal + "\"], username: " + sliceUser +
+		", enable: none, token_ttl: 60s}\ngrants:\n  - {subject: slice_operator, scope: all_devices, roles: [r]}\n"
+	path := filepath.Join(root, "tests", "lab", "logs", "projection-"+l16Slug(name)+".yaml")
+	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	pol, err := policy.Load(path, policy.Env{Devices: devices})
+	if err != nil {
+		t.Fatalf("%s: the shape's policy does not load: %v", name, err)
+	}
+	device, _ := pol.Device(l.p.node)
+	_, quarantined := pol.Quarantined(device.Name, time.Now())
+	brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
+	if err != nil {
+		t.Fatal(err)
+	}
+	broker := strings.Replace(string(brokerYAML), "tests/lab/slice/policy.yaml", path, 1)
+	cfg, err := l.derivedConfig("projection-"+l16Slug(name), `[]`, broker)
+	if err == nil {
+		err = l.restart(cfg)
+	}
+	if err != nil {
+		t.Fatalf("%s: port49d: %v", name, err)
+	}
+	sockDir, err := os.MkdirTemp("", "p49proj")
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer os.RemoveAll(sockDir)
+	sock := filepath.Join(sockDir, "a", "agent.sock")
+	out, err := exec.Command(port49, "login", "--broker", sliceBrokerURL,
+		"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
+		"--broker-ca", filepath.Join(pki, testpki.LabCA), "--socket", sock).CombinedOutput()
+	if err != nil {
+		t.Fatalf("%s: port49 login: %v\n%s", name, err, out)
+	}
+	defer stopSliceAgent(t, string(out))
+	var b strings.Builder
+	if quarantined {
+		tok := exec.Command(port49, "token", "--socket", sock, l.p.node)
+		msg, err := tok.CombinedOutput()
+		fmt.Fprintf(&b, "port49 quarantines %s under this policy (policy test names why). `port49 token` said: `%s`\n",
+			l.p.node, oneLine(string(msg)))
+		if err == nil {
+			t.Errorf("%s: port49 minted a token for a quarantined device", name)
+		}
+		if !refused {
+			t.Errorf("%s: this shape was expected to render, and port49 quarantined the device", name)
+		}
+		return b.String()
+	}
+	if refused {
+		t.Errorf("%s: expected refused, and port49 rendered it", name)
+	}
+	res, err := pol.ResolveSubject("slice_operator", device, time.Now())
+	if err != nil {
+		t.Fatalf("%s: %v", name, err)
+	}
+	tok := sliceToken(t, port49, sock, l.p.node)
+	c, err := l.sshCLI(sliceUser, tok)
+	if err == nil {
+		if _, err = c.expect(90*time.Second, junosOpPrompt); err != nil {
+			c.Close()
+		}
+	}
+	if err != nil {
+		t.Errorf("%s: the session did not open: %v", name, err)
+		return "The session did not open: " + oneLine(err.Error()) + "\n"
+	}
+	defer c.Close()
+	if err := junosPrepare(c); err != nil {
+		t.Errorf("%s: set cli screen-length 0 not observed: %v", name, err)
+	}
+	auth, _ := c.sendExpect("show cli authorization", junosPer, junosOpPrompt)
+	fmt.Fprintf(&b, "Reply `%s` (%s shape). `show cli authorization`:\n\n```\n%s\n```\n\n", strings.Join(res.Blob.Attributes,
+		"`, `"), res.Projection.Shape, precReply(l16TrimEcho(auth, "show cli authorization")))
+	b.WriteString("| typed | port49 on | port49 | projection predicts | device | agrees |\n|---|---|---|---|---|---|\n")
+	for _, p := range projectionProbes {
+		devOut, err := l.junosProbe(c, p.junosProbe)
+		if err != nil {
+			t.Errorf("%s: %q not observed within %s: %v", name, p.cmd, junosPer, err)
+			fmt.Fprintf(&b, "| `%s` | | | | not observed | |\n", p.cmd)
+			break
+		}
+		r := junosRun{outs: map[string]string{p.cmd: devOut}}
+		ran := r.ran(p.cmd)
+		if p.complete {
+			ran = r.completes(p.junosProbe)
+		}
+		_, o, err := pol.Decide("slice_operator", "", device, p.canonical, time.Now())
+		if err != nil {
+			t.Fatalf("%s: %v", name, err)
+		}
+		predicts := res.Projection.Device(strings.Fields(p.canonical))
+		switch {
+		case ran && !o.Permit:
+			t.Errorf("%s: the device ran %q, which port49 denies (%s): the projection fails open", name, p.cmd, o.Reason)
+		case ran != predicts && !(ran && o.Permit):
+			t.Errorf("%s: the device %s %q, and the projection predicts it %s", name, verb(ran), p.cmd, verb(predicts))
+		}
+		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s | %s |\n", p.cmd, p.canonical, verdictWord(o.Permit),
+			verb(predicts), verb(ran), yesNo(ran == o.Permit))
+	}
+	return b.String()
+}
+
+func verb(ran bool) string {
+	if ran {
+		return "runs"
+	}
+	return "refuses"
+}
+
+func verdictWord(permit bool) string {
+	if permit {
+		return "permit"
+	}
+	return "deny"
+}
+
+// projectionRestore is what puts the lab's own configuration back after the
+// reference configuration: the startup config's remote template and its
+// p49-readonly class as they were, every other class and user the reference
+// added deleted, and strict-authorization removed.
+func projectionRestore(reference []string) []string {
+	out := []string{"delete system tacplus-options strict-authorization",
+		"set system login user remote class p49-readonly", "delete system login class p49-readonly idle-timeout"}
+	seen := map[string]bool{}
+	for _, line := range reference {
+		f := strings.Fields(line)
+		if len(f) < 5 || f[0] != "set" || f[1] != "system" || f[2] != "login" {
+			continue
+		}
+		// The startup config's own remote user and p49-readonly class stay,
+		// put back above; the p49-readonly template user is the reference's.
+		kind, name := f[3], f[4]
+		if (kind == "user" && name == "remote") || (kind == "class" && name == "p49-readonly") || seen[kind+name] {
+			continue
+		}
+		seen[kind+name] = true
+		out = append(out, "delete system login "+kind+" "+name)
+	}
+	return out
+}
````

- [ ] **Step 2: Compile it**

Run: `go vet -tags lab ./tests/lab/...` and `make build`
Expected: no output, and `bin/port49` built (the test runs it).

- [ ] **Step 3: Run it on vJunos-router, then vSRX**

```bash
PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^TestProjectionDifferential$' -count=1 -v \
  -timeout 90m > tests/lab/logs/projection-vjunos.log 2>&1 &
echo $! > tests/lab/logs/projection-vjunos.pid
```

Run it in the background as "Running the lab" shows, with the stall watchdog running for the whole run. Then the same with `PORT49_LAB_PLATFORMS=vsrx`. The test spends no seeded
token, because the broker mints each one.

Expected: PASS on both images. A `the projection fails open` failure is a defect in this plan, or
in a measurement a set value rests on. Stop, do not ship 1.1.0's projection, and report the probe,
the reply and `show cli authorization`. CLAUDE.md rule 4 applies: the device is right. A `the
projection predicts it runs` failure is a reach or fact the lab contradicts. Fix the set value
(Task 13, Step 4), rerun Tasks 5–13's tests, and rerun this test.

- [ ] **Step 4: Commit the test, the notes and the evidence**

```bash
make evidence
git add tests/lab/projection_test.go tests/lab/results/L12-projection-juniper_*.md \
  tests/lab/evidence/projection-juniper_*.pcap
git commit -m "$(cat <<'EOF'
test: the projection's differential lab test (L9, L12)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

---

### Task 19: Close what the lab measured, freeze set 1.1.0, and write plan 5b as built

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 statuses and per-row paragraphs; §13
  decision 22's provisional marker)
- Modify: `platforms/1.1.0/juniper_junos.yaml` (`verified: containerlab`), `internal/platform/adapter_test.go`
  (`released`, `shipped110`), `cmd/port49/platform_test.go` (the list row)
- Modify: `docs/superpowers/plans/README.md` (plan 5b as built, the carried items)

**Interfaces:**
- Consumes: every note Tasks 2, 3, 4 and 18 wrote.
- Produces: set 1.1.0, frozen (`TestEveryReleasedSetIsFrozen`), and the roadmap entry plan 6 reads.

A row closes only where its lab test passed, and only where `tests/lab/results/L<N>-<platform>.md`
exists with the platform, the image version, the observation and a capture pointer. The Status
then reads `closed — measured <date>; tests/lab/results/...` (CLAUDE.md rule 3). A row with a
platform still open stays open (rule 5).

- [ ] **Step 1: Close the rows the notes close**

In §15's table:
- **L9**: close it if both Junos notes read every fact, with no `not observed` cell. Cite
  `L9-juniper_vjunos-router.md` and `L9-juniper_vsrx.md`.
- **L12**: close it if `L12-*`, `L12-bits-*` and `L12-projection-*` all passed on both images.
  Leave it open, naming the clause, if any clause is unmeasured. The `-regexps` precedence and the
  numbered names are measured by Task 2 either way.
- **L10**: add "Junos's spellings (`local-user-name`, `user-permissions`, `deny-commands`,
  `allow-commands`) measured by plan 5b (`L12-projection-juniper_*.md`)". Close it: every shipped
  adapter's spellings are now measured.
- **L23**: close it on `L23-arista_eos.md` and `L23-cisco_nxos.md`.
- **L24**: close it on `L24-juniper_*.md`.
- **L25**: close it on `L25-cisco_nxos.md` only if the record was measured. Otherwise leave it open
  with "not reproduced in the lab (L25-cisco_nxos.md)".

Add one paragraph per closed row under "What has been measured so far", in the form the existing
rows use: what was measured, on which images, and the one-line answer. Remove decision 22's
"*Provisional on L12.*" only if L12 closed. If it did not, keep the marker and say which clause
holds it open. Where a note contradicts the spec, fix the spec and cite the note (CLAUDE.md rule 4).

- [ ] **Step 2: Mark the Junos adapter verified, and freeze 1.1.0**

If `TestProjectionDifferential` passed on both images, apply all three patches. If it did not,
1.1.0 is frozen without `verified`: apply only the `internal/platform/adapter_test.go` patch, then
delete its `j.Verified = "containerlab"` line, and skip the other two.

<!-- patch: platforms/1.1.0/juniper_junos.yaml -->
````diff
diff --git a/platforms/1.1.0/juniper_junos.yaml b/platforms/1.1.0/juniper_junos.yaml
index 4e42996..5366ade 100644
--- a/platforms/1.1.0/juniper_junos.yaml
+++ b/platforms/1.1.0/juniper_junos.yaml
@@ -3,6 +3,10 @@
 # direction that fails closed (spec §8, §15).
 platforms:
   juniper_junos:
+    # Every reply this adapter renders, at every shape the projection
+    # produces, ran on both lab images no more than port49 permits
+    # (tests/lab/results/L12-projection-juniper_*.md; spec §15, L12).
+    verified: containerlab
     # Session authorization only: no per-command request in 26 sessions on two
     # images (L18; decision 21). Its rules reach a session through the
     # projection below (decision 22).
````

<!-- patch: cmd/port49/platform_test.go -->
````diff
diff --git a/cmd/port49/platform_test.go b/cmd/port49/platform_test.go
index a8e7f49..e4f95fb 100644
--- a/cmd/port49/platform_test.go
+++ b/cmd/port49/platform_test.go
@@ -26,7 +26,7 @@ func TestPlatformListSaysWhereEachAdapterComesFrom(t *testing.T) {
 	var out, errb bytes.Buffer
 	if code := run([]string{"platform", "list"}, &out, &errb); code != 0 ||
 		!strings.HasPrefix(out.String(), "PLATFORM") || strings.Count(out.String(), "built-in") != 4 ||
-		listRow(out.String(), "juniper_junos") != "juniper_junos built-in — session" ||
+		listRow(out.String(), "juniper_junos") != "juniper_junos built-in containerlab session" ||
 		listRow(out.String(), "arista_eos") != "arista_eos built-in containerlab session,commands" ||
 		listRow(out.String(), "cisco_nxos") != "cisco_nxos built-in containerlab session,commands" ||
 		listRow(out.String(), "cisco_iosxe") != "cisco_iosxe built-in containerlab session,commands" {
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index 9b682dc..6ef6f10 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -135,6 +135,7 @@ var shipped110 = func() map[string]Dialect {
 	}
 	j := out["juniper_junos"]
 	j.CommandProjection, j.BitDelivery = ProjectionJunosRegex, BitDeliveryLocalUserName
+	j.Verified = "containerlab" // tests/lab/results/L12-projection-juniper_*.md
 	j.LocalUserNames = map[string]string{"readonly": "p49-readonly", "operator": "p49-operator", "admin": "p49-admin"}
 	j.Bits = map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
 		"clear": {"clear **"}, "network": {"ping **", "traceroute **", "ssh **", "telnet **"}, "trace": {"monitor **"},
@@ -169,7 +170,7 @@ func TestTheDefaultSetValueForValue(t *testing.T) {
 // becomes the default, 1.0.0's entry stays here as it is and the new set is
 // added beside it, so a binary upgrade cannot change what a pinned policy
 // renders without this test failing.
-var released = map[string]map[string]Dialect{"1.0.0": shipped}
+var released = map[string]map[string]Dialect{"1.0.0": shipped, "1.1.0": shipped110}
 
 func TestEveryReleasedSetIsFrozen(t *testing.T) {
 	for version, want := range released {
````

- [ ] **Step 3: Write plan 5b as built into the roadmap**

In `docs/superpowers/plans/README.md`:
- Update the status line: "**5b merged <date>** (PR #N; `2026-09-24-05b-projection-capabilities.md`,
  nineteen tasks: one docs, three lab, thirteen code, one lab, one lab-and-docs)". Name the rows
  it closed.
- Add "Plan 5b — As built" under Plan 5. It covers:
  - the set 1.1.0 pin and its values as measured, with every Step 4 edit that differed from the
    candidates;
  - which JunosFacts closed;
  - the `bit_delivery` outcome;
  - the reference-classes rollout order;
  - `devices capabilities` and `account_gap`;
  - whether the NX-OS system task landed.
- Add these carried items:
  - `deny-configuration` for statements typed in configuration mode, which would lift Decided 6;
  - the `-regexps` family if Task 2 measured its deny precedence, which would lift the refused
    shape;
  - a way to declare a deny class-resident, the overflow's workaround in policy;
  - the reply gate's C4 friction (Questions);
  - `engine.Contains`, `MayMeet` and the rest compile both rules per call, so plan 12 measures the
    projection at fleet size;
  - `devices capabilities` reads a whole log into memory (plan 12);
  - an `account_gap` count held in memory is lost on a restart;
  - vJunosEvolved is unmeasured;
  - L25, if still open.

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/superpowers/plans/README.md platforms/1.1.0/juniper_junos.yaml \
  internal/platform/adapter_test.go cmd/port49/platform_test.go
git commit -m "$(cat <<'EOF'
docs: close lab register entries L9, L10, L12, L23, L24, L25; freeze set 1.1.0; plan 5b as built

<name each row closed and each left open, with its note>

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
EOF
)"
```

Name only the rows actually closed in the subject line. Then open the pull request with the
"Operator-facing notes" below in its body (roadmap rule).

---

## Operator-facing notes (for the pull request body)

- **New platform set 1.1.0.** It projects Junos's rules into the session reply. An unpinned policy
  still renders with 1.0.0 and changes nothing. Pin it with `port49 platform upgrade --to 1.1.0
  --write`; `policy diff` gates every Junos key the move changes.
- **Before pinning,** push `port49 platform export --classes --config port49d.yaml juniper_junos`
  to every Junos device (`strict-authorization`, `remote` on the bitless `p49-remote`, one template
  and class per level), and check it with `port49 devices check-config`.
- **New adapter keys:** `command_projection`, `bits`, `bit_delivery`, `local_user_names`. All are
  gated in the diff. A block may add to a bit's reach, but may not remove a rule or add a bit.
- **Refused at load:** a role or grant attribute the projection renders, on a projected platform
  or under `all`.
- **Quarantined** (the device falls to local):
  - a Junos composition in the refused shape;
  - bits that enter configuration mode for anything but a grant of every command with no deny,
    which covers an admin role with a deny;
  - a rule carrying a redacted value;
  - a reply attribute past 255 bytes.
- **New `policy test` reports:** `projection`, `projection_overflow` (with the class line that
  carries the value instead), and `unenforced_rules`.
- **`policy diff`:** a changed Junos reply fails until a `reply:` test asserts it, and a
  `projection:` line reports each shape or bits change.
- **`port49 explain`** on a Junos command says whether the device runs it under the reply.
- **New command: `port49 devices capabilities`.** It gives the supports-versus-observed matrix and
  the unauthorized tier, read from the decision log. It exits 1 on a finding.
- **New log event: `account_gap`.** Accounting records the spool dropped, by stage.
- **NX-OS (if L25 measured it):** an `admin` accounting record with task_id `vsh.bin.<n>` is now
  `system`.
- **Lab register:** L9, L10, L12, L23, L24 and L25, each closed or left open as Task 19 records.

## Self-review against the spec

- **§8 "Projection for session-only platforms":**
  - bits first, regexes second, chosen per composition: Task 8;
  - the capability, narrow and refused shapes: Task 8;
  - `bit_delivery`, both ways: Tasks 6, 8 and 13;
  - `bits`, `privilege` as the ceiling, reference classes by export: Tasks 6 and 12;
  - CI reporting shape and bits: Task 10, and changes between versions: Task 11;
  - the class-crossing report with its snippet: Task 10 (`projection_overflow`);
  - generator constraints 1–5: Task 8's `attributes` and Task 9's `checkProjected` for 1, `CheckAttribute`
    for 2, 3 by construction (nothing emits `-regexps`), `allowable` and `within` for 4, and
    quarantine at load for 5;
  - differential testing: Task 18;
  - `explain` stating class ∩ wire: Task 10;
  - anchoring as a platform property: `JunosFacts` from L9 (Tasks 2 and 13).
- **Decision 21:** the class idle-timeout from `max_session_age` is Task 12, measured by Task 3
  (L24). `explain`'s statement already existed. Revocation records naming unreached contexts are
  plan 7's (roadmap), and stay there.
- **Decision 22:** Tasks 5–13 and 18. It stays provisional until L12 closes (Task 19).
- **§9:**
  - the three observations and the matrix: Task 16;
  - `devices capabilities`: Task 17;
  - reconciliation over the tiers `supports` declares: Task 16;
  - qualified by stream health (the spool's drops, ERROR replies and unattributed counts): Tasks
    15–17;
  - the CI check: Task 17.
- **Roadmap carries:**
  - Junos's inert list and spellings: Tasks 2, 13, 18 and 19;
  - M3 re-measured beside readonly: Tasks 4 and 13;
  - the NX-OS `vsh.bin` system user if measured: Tasks 4 and 14.
- **Lab rules:**
  - every read has a deadline, and expiry is not observed and fails;
  - boot budgets are the harness's, per image;
  - the controller runs the stall watchdog, per "Running the lab".
