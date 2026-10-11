# Plan 9b1: Junos Apply-Groups and Per-User `junoscript` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry Ryan's four rulings of 2026-10-11 for Junos. A subject whose safety rests on a
deny beneath a sent permission bit is projected with a `junoscript` deny, which makes the CLI deny
a real boundary and closes NETCONF for that person alone; a readonly with a deny under `show`
projects too. `port49 devices check-config` reads configuration groups instead of refusing them,
names a group that widens a template, and takes many captures in one run. The lab measures what
is still open and closes L26c and the new L57 and L58.

**Why the name `09b1`.** The roadmap names a fix slotted between two plans of a step by the
earlier plan's number and a digit: `06b1` (`fix/breakglass-reset`) went between 6b and 6c. This
goes between 9b (merged) and 9c (not written), so it is `09b1`, not `09c0`. Branch:
`feature/junos-groups-and-junoscript` (it adds a platform set and a CLI form, not only a fix).

**What changes, in one screen:**
- **Set 1.2.0** (a released set is never edited, spec §8 "the platform set is pinned"). It is 1.1.0
  plus one adapter key on `juniper_junos`: `rpc_entry_denies: ["junoscript **"]` (and `"op **"`
  if Task 3 finds an `op url` script reaching an RPC past the `junoscript` deny), and `save` in
  its Junos keyword tree (if L58 proves it). `DefaultSet` moves to 1.2.0. A policy pinned to
  1.1.0 renders byte for byte as before.
- **The projection** (`internal/projection`): where `JunosFacts.DenyBindsRPCs` is false and a deny
  is the only guard beneath a sent bit or the baseline, a dialect with `RPCEntryDenies` keeps the
  capability shape and appends those denies (role `rpc_entry`). Today that composition falls to
  the narrow shape or fails closed as `refused_shape`. An allow the reply must send that meets an
  entry deny still falls back, since an allow beats a deny (L11).
- **A readonly with a deny beneath `show **` projects** (owner's ruling 4; decision 44 ruling
  10). Under the entry deny, set 1.2.0 also: sends the baseline's `xml-mode **` as nothing, since
  the `junoscript` deny refuses it (L26c-junoscript; bare `xml-mode` measured in Task 3, L58);
  proves `save` a keyword (its tree adds it if L58 proves it on both images); renders a reply's
  `word **` denies as one alternative, ` *(help|quit|…)( .*)? *(\|.*)?` (89 bytes for the
  readonly's twelve and `junoscript`); and sends a permit the bits reach but for a carve-out as allows of those
  carve-outs. So a readonly granted `show **` less `show configuration **` gets `view`, 170 bytes
  of `deny-commands`, and allows of `show log`, `show firewall` and `show policer`, reported as
  sent beyond the bits; view-configuration stays unsent. A capability reply that would send an
  allow its bits do not reach yields to a narrow one that reaches every allow, so a readonly
  granted `show **` alone renders as under 1.1.0. Each of these renders only where the adapter
  carries `rpc_entry_denies`.
- **Two CI warnings** (`internal/policy`): `projection_netconf_closed` (this subject has no NETCONF
  on these devices) and `projection_deny_beneath_view_configuration` (Ryan: the class grants
  `view-configuration` and the policy denies `show configuration`; a warning, not a refusal).
  `policy test` prints them; `policy diff` prints the new ones as `warning:` lines and still exits 0
  on them.
- **check-config:** the capture becomes `show configuration | display set | display inheritance`
  (group definitions kept). Groups are no longer refused. A group statement that lands on a
  template class or user and adds a privilege statement fails, naming the group. Harmless
  statements pass. A capture that lacks a group's expansion where the configuration applies it is
  refused as not inherited, and so is one that applies a group to a template without carrying the
  group's definition. Under set 1.2.0 the services allowlist drops NETCONF, the XML API
  and `outbound-ssh`; `web-management` and `extension-service` (and `rest`, unless Task 3 shows
  the deny closes it) still fail. `--batch FILE...` checks many captures.
- **Lab:** Task 3 (before code) measures the other ways in under `deny junoscript`, the group
  inheritance, and `save` and bare `xml-mode` under the factored deny (new row L58, closed there);
  Task 9 (after code) runs the projection differential under set 1.2.0 and check-config on the
  captured groups, then closes L26c and L57.

**Architecture:**
- `internal/platform`: `Dialect.RPCEntryDenies`, `Spec.RPCEntryDenies` (`rpc_entry_denies`),
  `RPCEntryRole`; `NetconfForbidden`; `ConfigCapture` (renamed from `ServicesCapture`);
  `CheckServices` by set; `TemplateDrift` reading groups. Set 1.2.0 under `platforms/1.2.0/` and
  `platforms/keywords/1.2.0/`.
- `internal/policy`: the block rules for `rpc_entry_denies` (`load.go`), two finding kinds
  (`lint.go`), `Diff.ProjectionWarnings` (`diff.go`).
- `internal/projection`: `generator.entryDenies`, `Result.EntryDenied`, `Result.NetconfClosed`,
  `Result.ConfigurationBeneath`; `rpcEntries` gains `junoscript`; `rpcWhy` states only what is
  measured. Task 5b: `Result.Closed`, `generator.closesEntries`, `closedByEntry`,
  `carvedAllows`, `factored`, and `shape` keeping the narrow shape where the capability one sends
  an allow beyond its bits.
- `cmd/port49`: `checkConfig` split into a per-file `checkRun.one`, plus `--batch`; `policyDiff`
  prints warnings.
- `tests/lab`: `junos_entry_test.go`, `junos_entry_unit_test.go`, `junos_groups_test.go`,
  `junos_baseline_test.go`, `junos_baseline_unit_test.go`; `projection_test.go` runs under a
  named set.

**Tech Stack:** Go 1.26, module `github.com/rhwendt/port49`, no cgo, no new module. Containerlab
with vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15 (both images present on the lab host).

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`: §8 ("A wire deny does not bind a native NETCONF
  RPC" through "…is future work"; "Knowing what is shipped" is unchanged and binds Task 4), §12
  (`devices check-config`, the projection codes table), §13 (new decision 44, ten rulings), §14 (Platform and
  projection), §15 (L26c; new L57 and L58; their detail bullets).
- Results notes this plan argues from: `tests/lab/results/L26c-junoscript-juniper_vjunos-router.md`,
  `L26c-junoscript-juniper_vsrx.md` (2026-09-30, captures in `tests/lab/evidence/`),
  `L26c-juniper_*.md`, `L26c-operator-juniper_srx.md`, `L12-netconf-juniper_*.md`;
  `L26b-juniper_*.md` (the factored deny's shape, enforced; `save` proven on vJunos-router only)
  and `L12-bits-juniper_*.md` (view-configuration's carve-outs).
- The roadmap `docs/superpowers/plans/README.md`, "Plan 9". House style: plans 9a and 9b. Written
  against `main` at `22ada89`.

**Prerequisite:** plan 9b merged (`main` at `22ada89`).

## Owner's rulings this plan carries (Ryan, 2026-10-11)

1. **NETCONF per user.** A subject whose policy relies on a deny beneath a sent permission bit is
   projected with `deny-commands` including `junoscript`, so the CLI deny is a real boundary and
   NETCONF is closed for that person alone. Automation accounts without such denies keep NETCONF.
   The "class grants `view-configuration` + policy denies `show configuration`" case becomes a
   `policy diff` warning, not a refusal. `devices check-config` drops the services allowlist that
   requires NETCONF, the XML API, REST and the rest off. Spec first; L26c closes when the lab task
   passes.
2. **apply-groups.** check-config reads the inherited view and passes groups that do not change
   the template. It fails only where a group adds, to a template user or class, a permission, an
   `allow-`/`deny-commands`, an `allow-`/`deny-configuration` (and the `-regexps` forms), or
   authentication on a template user, naming the group. Harmless attributes (idle-timeout,
   login-alarms, login-tip) pass. Many captures in one run, for CI.
3. **Lab.** New cells: (a) NETCONF as an SSH subsystem on port 22 under `deny junoscript` vs a
   control; (b) `op` scripts and `op url` under it; (c) a port49-projected subject with a deny
   beneath a sent bit plus the added `junoscript` deny: CLI deny holds, NETCONF refused, a
   control's NETCONF works; (d) what `display inheritance` shows for wildcard groups,
   `apply-groups-except` and nested groups. Positive controls enforced; close L26c and the groups
   row.
4. **A readonly with a show deny works in 9b1** (after pre-flight, on finding 5). The remedy goes
   into set 1.2.0: (a) the baseline `xml-mode` deny is read as closed by the entry deny
   `junoscript` (L26c-junoscript: a deny of `xml-mode` does not bind; `junoscript` closes `xml-mode
   netconf` and port 830); (b) a lab cell in the pre-code lab task measures `save` into the
   keyword tree, with its control, and gates (b)'s render change; (c) one factored alternative for
   `word **` denies, with a budget test showing a readonly `show **` less `show configuration **`,
   and less `show security **`, rendering within 255 as the capability shape. view-configuration
   stays out of readonly: the spec's undecided reach stands. Spec text first, tests first.

## Controller rulings this plan carries (2026-10-11, pre-flight)

1. **`web-management`, `extension-service` and `rest` keep failing check-config under set 1.2.0**
   unless a lab cell measures the `junoscript` deny closing them: conservative until measured. No
   cell measures J-Web or JET, so those two always fail; REST is G2's (Task 3).
2. **The allowlist for statements under a template stands** (R4, decision 44 ruling 9): anything
   neither privilege nor known-harmless fails.
3. **Verifying the capture is inherited stands** (R5): a capture missing an applied group's
   expansion is refused.
4. **`op **` joins `rpc_entry_denies` only if cell (b) shows an `op url` script reaching an RPC
   past the `junoscript` deny** (G1 reads "reached" and nothing else; the op cell's control is
   canonical, so "not measured" ends the run INVALID instead of deciding the list).

## Rulings this plan makes (recorded as decision 44 in Task 1)

Under the standing grant (security first, keep moving), each on reasoning unless it says data.

- **R1 (data: `L26c-junoscript-juniper_*.md`).** The entry deny is adapter data, `rpc_entry_denies`,
  in a new set 1.2.0, not a change to `JunosFacts`: spec §8 forbids a binary upgrade changing what
  a pinned policy renders. A block may drop an entry deny (that platform then renders as 1.1.0)
  and never add one the set did not measure, the rule `carve_outs` already has.
- **R2.** Ryan's ruling names `junoscript`. Cell (b) decides `op`: if an `op url` script reaches an
  RPC past the `junoscript` deny, set 1.2.0's list is `["junoscript **", "op **"]`. Denying `op`
  to a subject port49 permits it is narrower, which is always allowed, and the report says so;
  failing the whole subject closed is what the ruling replaces.
- **R3 (security: hold for Ryan if he disagrees).** Ryan's ruling drops the services allowlist.
  This plan drops what the `junoscript` deny was measured to close: NETCONF (`netconf`, port 830),
  the XML API (`xnm-ssh`, `xnm-ssl`, `xnm-clear-text`, the same protocol), `outbound-ssh` (NETCONF
  dialled out under the same login), every non-RPC service (`dhcp-local-server`, `dns`, `ftp`, …),
  and the ssh option list. It keeps `web-management` and `extension-service` failing, since no
  measurement shows the deny closes J-Web or JET/gRPC, and `rest` unless cell (e) shows the deny
  closes it. Under set 1.1.0 the allowlist is unchanged. The controller ruled this conservative
  reading on 2026-10-11 (controller ruling 1); it is no longer an open question.
- **R4.** Template statements in three lists. The privilege list Ryan named fails, naming the
  group. The harmless list passes, on a template or from a group: a class's `idle-timeout`,
  `login-alarms` and `login-tip`, and a user's `full-name`. **Anything else under a template also
  fails**, as drift does today: `allow-hidden-commands`, `login-script`, `logical-system`,
  `tenant` and `security-role` change what a session runs, and an allowlist does not fail open on
  a statement nobody listed (plan 5b pre-flight C1). Ryan's "FAIL only when" is read as "these
  are the named failures"; a statement on neither list is an unlisted one, not a harmless one.
- **R5.** The capture is trusted where the device expanded it, and verified where that matters
  (cell d). A group statement that lands on a template, by an `apply-groups` naming its group at
  or above that level with no `apply-groups-except` between, must appear expanded there, unless
  the template writes a harmless leaf of its own there (a local leaf stands over a group's). If it
  does not appear, the capture lacks `display inheritance`, and check-config refuses it rather
  than passing a group it could not see applied. Where the template writes a privilege or unlisted
  statement of the same name itself (`permissions` on a `local_user_name` template), whether Junos
  adds the group's value beside it is unmeasured, so the group is named at its own line, a
  finding either way. An `apply-groups` at or above a template naming a group the capture does not
  define is refused too: a capture filtered with `| except "^set groups "` hides what it brings. An
  excepted or unapplied group is not a finding. In a group, a `<pattern>` word is read as every
  word it matches, in check-config's services check as in the template check.
- **R6.** `--batch FILE...` names each device by its file name as it is where the inventory has
  that name (Oxidized writes the name with no extension, and an FQDN has dots), else by the name
  less its last extension (`srx-01.conf` is `srx-01`). Every file is checked whatever
  one before it found. Exit 2 if any file's check was a usage or "nothing checked" outcome, else
  1 if any had a finding or could not be read, else 0.
- **R7.** `policy diff` prints only the warnings the change brings (present after, absent before):
  every unchanged warning on every diff is noise at 3am, and `policy test` prints them all.
- **R8.** `projection_netconf_closed` also fires for the narrow shape, whose `.*` refuses
  `junoscript` (measured: the fail-closed reply's `.*` refused `xml-mode`, `L26c-juniper_*.md`),
  and only on a platform whose pinned set carries `rpc_entry_denies`: under 1.1.0 check-config
  requires NETCONF off on the whole device, so a per-subject "no NETCONF" there is noise on every
  readonly. It is a report only, never a different reply. Its message names the entry denies the
  reply carries, so a subject denied `op` by G1 is told so (R2's "reported").
- **R9 (owner's ruling 4; data: `L26c-junoscript-juniper_*.md`, `L26b-juniper_*.md`, L58).** A
  readonly with a deny beneath `show **` projects under set 1.2.0. Pre-flight measured why it did
  not, against the shipped adapter and tree with Task 5 applied: its baseline denies carry `save
  **` and `xml-mode **`, which no proven keyword names, so `capability` returned `narrowOnly`;
  they render 333 bytes alone; and, found while building the remedy, view-configuration's other
  carve-outs (`show log`, `show firewall`, `show policer`) take `show **` out of `view`'s reach, so
  the capability shape had to send `show **` as an allow, which beats the deny beneath it
  (`refused_shape`). Five changes, each only where the adapter carries `rpc_entry_denies`, so set
  1.1.0, or a block that drops the entry deny, renders byte for byte as before (decision 44 ruling
  5):
  - (a) The baseline's `xml-mode **` is sent as nothing beside `junoscript **` (`Result.Closed`):
    Junos authorizes `xml-mode` as `junoscript`, and a deny naming `xml-mode` does not bind. The
    model reads it refused, so the reply is still proven sound. Bare `xml-mode` (the Junos XML
    protocol) was never typed under the deny; L58 types it, and gate G4 stops the plan if it runs.
  - (b) Set 1.2.0's keyword tree adds `save` at the root if L58 proves it on both images (G3).
    L26b proved it on vJunos-router only: vSRX's control took the hidden `save
    dhcp-security-snoop` and refused the file name after it, so nothing ran.
  - (c) A reply's `word **` denies render as one alternative, ` *(w1|w2|…)( .*)? *(\|.*)?`, at
    the first one's place: the shape L26b's deny sessions were enforced in on both images. The
    readonly's twelve words and `junoscript` are 89 bytes (the ruling's estimate was about 103).
  - (d) A permit the bits reach but for a carve-out of a ceiling bit the reply does not send,
    whose own allow would beat a deny beneath it, goes out as allows of those carve-outs, each
    within the ceiling, sendable, and meeting no deny (`carvedAllows`). Without it (a)–(c) still
    leave the readonly `refused_shape`. Whether an allow runs past the bits is unmeasured, so each
    is reported as sent beyond them (`Unreached`), and Task 9 records what the device does.
  - (e) A capability reply that sends an allow its bits do not reach yields to a narrow reply
    that carries the grant with every allow reached and leaves off no more. Without it (a) and
    (b) move every grant 1.1.0 sent to the narrow shape only for `save` and `xml-mode`, the
    readonly granted `show **` alone first, to `view` and an allow of `show **` beyond it, where
    Junos shows no configuration (`L12-bits-juniper_*.md`, carve-outs). With it that readonly
    keeps both bits and renders as under 1.1.0.
  The readonly granted `show **` less `show configuration **` then gets `view`, 170 bytes of
  `deny-commands` and allows of `show log`, `show firewall` and `show policer`. Less `show
  security **` it gets 165 bytes and also an allow of `show configuration` beyond `view`; under
  `view` alone Junos does not show the configuration, so in practice that subject reads none
  (reported). view-configuration stays out of readonly: such a grant decides none of its other
  reach (`monitor`, `request mpls` and the rest), the spec's undecided reach, which stands.
  Recorded as decision 44 ruling 10.

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, no cgo, no new module.
- snake_case for all data: the adapter key `rpc_entry_denies`, finding kinds
  `projection_netconf_closed` and `projection_deny_beneath_view_configuration`.
- Reason codes: none added. A fail-closed reply is still `projection_fail_closed`
  (`internal/decision/reasons.go`); the new codes are §12 CI finding kinds, added to §12's table
  before any code emits them (Task 1).
- A released platform set is never edited: `platforms/1.1.0/` and `platforms/keywords/1.1.0/` are
  not touched. A policy pinned to 1.1.0 renders byte-identical attributes.
- The log and every printed line never carry a token, password or hash: check-config's finding
  text (`Says`) names statement keywords and group names only; a configuration line it prints
  goes through `redact`.
- No device identity in metric labels (no metric is added).
- No per-device or per-user manual step (Ryan's no-toil rule): one capture command per device,
  which CI already runs; `--batch` takes a directory of them.
- Lab: positive controls enforced; a control that fails is `INVALID`, `t.Fatalf` before any note
  is written. Results notes per CLAUDE.md; captures redacted into `tests/lab/evidence/`.
- Commit trailer, every commit: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
  and nothing else (no `Claude-Session:` line, no claude.ai link: owner's rule).
- Verify before done: `make test && make vet`, real output reported.

## Review Focus

1. **The entry deny pushes `deny-commands` past 255 bytes.** The capability shape overflows and
   must never be sent truncated: the narrow shape where it carries the grant, else the
   fail-closed reply as an overflow. Test in Task 5 (`TestTheEntryDenyCountsTowardTheBudget`).
2. **An allow the reply must send meets an entry deny.** On the device the allow beats the deny
   (L11), so NETCONF would stay open: the composition must not get the capability shape. Test in
   Task 5 (`TestAnAllowMeetingTheEntryDenyKeepsTheFallback`).
3. **A capture taken with plain `display set` from a device whose group widens `p49-remote`.**
   The widening is invisible without inheritance: check-config must refuse the capture, never
   report the device clean. Test in Task 7 (`TestTemplateDriftReadsGroups`, "not inherited").
4. **A template class that writes its own `idle-timeout` under a group that sets another.** The
   device keeps the class's; check-config must not call the capture "not inherited". Test in
   Task 7 ("own leaf").
5. **The entry deny's reach on the shipped set.** Unit fixtures (`measuredJunos`) prove every
   baseline word a keyword and leave `xml-mode` out of the baseline; the shipped tree does not.
   `TestTheShippedSetsEntryDeny` and `TestAReadonlyWithAShowDenyFitsTheBudget` (Task 5b) pin what
   1.2.0 really does from the shipped adapter and tree, and that 1.1.0's renders did not move.
6. **What the readonly remedy sends as nothing or as an allow.** `xml-mode` is closed only beside
   `junoscript **` and only as the baseline's deny; a carved allow meets no deny and stays within
   the ceiling; a plain readonly keeps the narrow shape. A wrong step here is wider than port49:
   the model's witness must still refuse every reply that would run a denied command (Task 5b's
   mutation checks).
7. **One bad file in a CI batch.** A file naming no inventory device, or one that cannot be
   read, must be reported and must not stop the other files or turn the run green. Test in
   Task 8 (`TestCheckConfigBatch`).

---

## Task 1: Spec — decision 44, §8 rewritten, §12 check-config and codes, §14, §15 L26c, L57 and L58

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§8 lines ~3877–3922; §12 ~5687–5712;
  §13 after decision 43, before `## 14.`; §14 "Platform and projection"; §15 table rows L26c and
  after L56; the L26c detail bullet ~10838–10858)

**Interfaces:** Produces the names every later task uses: adapter key `rpc_entry_denies`, role
`rpc_entry`, finding kinds `projection_netconf_closed`,
`projection_deny_beneath_view_configuration`, capture
`show configuration | display set | display inheritance`, flag `--batch`, rows L57 and L58.

- [ ] **Step 1: Replace §8's RPC paragraphs.** Replace from the paragraph beginning `**A wire deny
  does not bind a native NETCONF RPC**` through the sentence ending `…since admins need `start
  shell` and the bits already refuse it.` with:

```markdown
**A wire deny does not bind a native NETCONF RPC** (`tests/lab/results/L12-netconf-juniper_*.md`,
both images). The token that opens the CLI opens NETCONF with the same reply, and there a native
RPC ran past every wire deny (`<get-configuration>` past `deny show configuration **`); only a
`<command>` RPC was refused. A CLI session reaches the same RPCs from inside itself:
`xml-mode netconf` opens NETCONF there, and a native RPC its deny did not name ran
(`L26c-juniper_*.md`). On SRX hardware `<get-configuration/>` through it returned the whole
configuration past a deny of `show configuration` beneath `view-configuration`
(`L26c-operator-juniper_srx.md`, operator-reported). **So `deny-commands` cannot keep the
configuration from a session that holds `view-configuration` and reaches an RPC.**

**A deny of `junoscript` closes the RPC entry points, per user** (`tests/lab/results/L26c-junoscript-juniper_*.md`,
both images, each refusal isolated against a control with the same bits and no deny). Junos
authorizes `xml-mode` as `junoscript`. `deny-commands "junoscript"`, sent by TACACS+ or set on the
class, refused `xml-mode netconf` and `junoscript netconf` from the CLI, and refused that user's
NETCONF on port 830 (`error: unknown command: xml-mode`). `show version` still ran, and the
control reached `<get-software-information/>` both ways. A deny naming `xml-mode` does not bind,
and a hidden command does not abbreviate. The deny closes NETCONF for the session whose reply
carries it and for no one else. *Provisional on L26c* for the other ways in: the NETCONF
subsystem on port 22, the SSH exec channel, an `op url` script, REST and `scp` (plan 9b1, Task 3),
and the projected reply end to end (Task 9).

**Set 1.2.0 sends it** (the adapter key `rpc_entry_denies`; decision 44). Take a composition whose
only guard beneath a sent bit, or beneath the baseline every session holds, is a wire deny. It
keeps the capability shape, and its `deny-commands` carries the adapter's entry denies beside its
own. The CLI deny is then the boundary. That subject has no NETCONF, `xml-mode` or XML API session
on the device. A subject whose reply carries no such deny keeps them: an automation account
granted everything its bits reach, say. Over NETCONF a native RPC is bounded by the bits alone, so
no subject has both a deny beneath its bits and NETCONF.

**A readonly with a deny beneath `show **`** (decision 44 ruling 10). A grant that leaves a
baseline command to a deny carries baseline denies, and a readonly's are fourteen. Set 1.2.0
carries them beside the entry deny. Each change below renders only where the adapter has
`rpc_entry_denies`, so a set without it, or a block that drops it, renders as set 1.1.0 does.

- The baseline's `xml-mode **`, which no keyword tree proves, is sent as nothing beside
  `junoscript **`. Junos authorizes `xml-mode` as `junoscript`, and a deny naming `xml-mode` does
  not bind (`tests/lab/results/L26c-junoscript-juniper_*.md`). Bare `xml-mode` under the deny is
  *provisional on L58*.
- Set 1.2.0's keyword tree proves `save`, *provisional on L58* (L26b proved it on vJunos-router
  only).
- A reply's `word **` denies render as one alternative, ` *(help|quit|…)( .*)? *(\|.*)?`, the
  shape L26b's deny sessions were enforced in (`L26b-juniper_*.md`).
- A permit the bits reach but for a carve-out of a ceiling bit the reply does not send, where
  an allow of the permit would beat a deny beneath it, goes out as allows of those carve-outs.
  Each is within the ceiling and meets no deny. Whether an allow runs a command past the bits is
  unmeasured, so CI reports each as sent beyond them.
- Where the capability shape would send an allow its bits do not reach, and the narrow shape
  carries the grant with every allow reached and leaves off no more, the narrow shape is sent.

So a readonly granted `show **` less `show configuration **` gets `view`, a `deny-commands` of
170 bytes (its twelve `word **` denies and `junoscript` in one alternative, `set cli` and its
own deny), and allows of `show log`, `show firewall` and `show policer`, view-configuration's
other carve-outs. view-configuration is not sent: the grant decides none of its other reach
(`monitor`, `request mpls` and the rest). A readonly granted `show **` alone keeps the narrow
shape and both bits, as under set 1.1.0.

Where the reply must send an allow that meets an entry deny, the allow would beat it (L11), so the
entry is not closed. The composition then falls to the narrow shape, whose `.*` refuses every
entry point, or to the fail-closed reply (`refused_shape`, its message naming RPC reach). A narrow
allow that would run `xml-mode`, `junoscript` or `op` is refused the same way, and the fail-closed
reply leaves it off.

CI reports two warnings. `projection_netconf_closed` names each subject a reply closes NETCONF
for. `projection_deny_beneath_view_configuration` names each sent deny that meets `show
configuration` beneath a held `view-configuration`: the CLI refuses it and NETCONF is closed, but
the bit is what grants the configuration, so withholding the bit is the real fence.

**Set 1.1.0 is unchanged**, since a released set is never edited. It sends no entry deny, so a
composition whose only guard beneath a sent bit is a wire deny gets the narrow shape or the
fail-closed reply there, as before (option C).

**Management services.** Under set 1.1.0 a projected Junos device runs no management service but
the CLI's, checked as an allowlist. `devices check-config` passes it only where nothing under
`system services` is on but `ssh` and `telnet`, an unknown service included, and `rest`,
`web-management` and `extension-service` appear nowhere. Under set 1.2.0 the entry deny closes
NETCONF, the XML API and device-initiated NETCONF per user, so the check no longer requires them
off. It still fails `web-management` and `extension-service`, and `rest` (*provisional on L26c*:
plan 9b1 Task 3 measures it). No measurement shows the entry deny closes their RPCs. Both sets
read the capture §12 names.

**No carve-out leaves a deny off the wire in either set**: `view-configuration`'s `show
configuration **` out of `view` is measured on the CLI only. `start` is never denied, since admins
need `start shell` and the bits already refuse it.
```

- [ ] **Step 1b: The adapter key in §8's Fields table.** Add a row after `local_user_names`:

```markdown
| `rpc_entry_denies` | on a projected platform, the denies a reply adds where a wire deny is the only guard beneath a sent bit or the baseline, closing the CLI's ways into a native RPC for that session (decision 44). Set 1.2.0's `juniper_junos` carries `["junoscript **"]`. Each is words and a trailing `**`. A block may drop one, and the platform then renders as set 1.1.0 does; it may never add one the set did not measure | optional |
```

  In the `command_projection` row's list of keys refused where the pinned set does not project
  the platform (`` `command_projection`, `bits`, `carve_outs`, `bit_delivery` or
  `local_user_names` ``), add `rpc_entry_denies`; likewise in the list of the same keys at spec line ~5906
  (`` `command_projection`, `bits`, `bit_delivery`, `carve_outs` and `local_user_names` ``).

- [ ] **Step 2: Replace §12's check-config paragraph's projected part.** In the paragraph beginning
  `**`port49 devices check-config`**`, replace from `On a projected platform it also reads the
  configuration,` through `the uid Junos assigns aside (§8).` with:

```markdown
On a projected platform it also reads the configuration, as `show configuration | display set |
display inheritance` prints it: groups' statements expanded where they apply, the group
definitions kept, one capture, refusing any other form (§8). It reads it against the reference
`platform export --classes` writes, and `--config port49d.yaml`, the classes' idle-timeout, is
required. A reference line the device lacks fails it. So does any line under a template class or
template user the reference does not write: a class `allow-commands`, a permission, a template
password. Exempt are the uid Junos assigns, a class's `idle-timeout`, `login-alarms` and
`login-tip`, and a user's `full-name`, which change nothing a session runs (decision 44).

**Configuration groups pass where they change no template.** A group whose statement lands under a
template class or user fails the check, the finding naming the group. "Lands" reads a wildcard
`<*>` or `<p49-*>` path as Junos does. It fails where it adds a permission, an `allow-` or
`deny-commands`, an `allow-` or `deny-configuration` (or a `-regexps` form), or a template user's
authentication or class: `group BASE adds `permissions` to class p49-remote: every port49 session
on this device gets it`. It fails too where it adds anything not known harmless.

The check trusts the inherited capture's expanded lines (L57) and verifies them where it matters.
Take a group the configuration applies to a template, by an `apply-groups` naming it at or above
that level with no `apply-groups-except` between. If the capture does not carry its statement
there, and the template does not write a harmless leaf of that name itself, the capture was taken
without `display inheritance`, and the check refuses it. Where the template writes a privilege or
unlisted statement of that name itself, the group is named at its own line. A capture that
applies a group at or above a template without carrying the group's definition, as one taken
with the earlier `| except "^set groups "` does where it prints `apply-groups`, is refused. In a
group's statement a `<pattern>` word is read as every word it matches, in the services check too.

`--batch FILE...` checks many captures in one run, the CI form (decision 44 ruling 8). Each file
is checked against the inventory device its file name names: the name as it is where the
inventory has it (Oxidized's files, an FQDN), else the name with its last extension removed
(`srx-01.conf` is `srx-01`). Every file is checked whatever one before it found. The run exits 1
when any file has a finding or cannot be read.
```

- [ ] **Step 3: Add the two codes to §12's projection codes table**, after the
  `projection_argument_allow` row:

```markdown
| `projection_netconf_closed` | on a platform whose pinned set carries `rpc_entry_denies`, a composition whose Junos reply refuses `junoscript`: the entry deny beneath a deny, or the narrow shape's `.*`. The subject has no NETCONF, `xml-mode` or XML API session on those devices (§8; decision 44) | no, a warning; `policy diff` prints the ones the change brings |
| `projection_deny_beneath_view_configuration` | a sent deny that meets `show configuration` beneath a held `view-configuration`: the CLI refuses it and NETCONF is closed, but the bit is what grants the configuration; withhold the bit instead (§8; decision 44) | no, a warning; `policy diff` prints the ones the change brings |
```

- [ ] **Step 4: Add decision 44** after decision 43's last paragraph and before the `---` that
  precedes `## 14.`:

```markdown
**44. Junos: a per-user `junoscript` deny, and check-config reads configuration groups.**
*Plan 9b1, 2026-10-11, on Ryan's rulings of that day.* Rulings rest on reasoning unless they say
data. Rulings 1, 2 and 6 are *provisional on L26c* until plan 9b1's Task 9 closes it; ruling 7 is
provisional on L57; ruling 10's `save` and bare `xml-mode` are *provisional on L58* until plan
9b1's Task 3 closes it.

- **1. The entry deny** (data: `tests/lab/results/L26c-junoscript-juniper_*.md`). Take a
  composition whose only guard beneath a sent bit or the baseline is a wire deny. Under a set
  whose adapter carries `rpc_entry_denies`, it is projected in the capability shape with those
  denies added to its `deny-commands`, role `rpc_entry`. This replaces option C's narrow-or-closed
  answer for that set. Set 1.2.0's `juniper_junos` carries `["junoscript **"]`; ruling 2 says
  when it carries `op **` too.
- **2. `op`.** If an `op url` script reaches an RPC past the `junoscript` deny (plan 9b1 Task 3,
  cell b), set 1.2.0's list is `["junoscript **", "op **"]`. Denying `op` to a subject port49
  permits it is narrower, which is reported, not refused.
- **3. Who keeps NETCONF.** A subject whose reply carries no deny beneath a sent bit or the
  baseline. An allow the reply must send that meets an entry deny would beat it (L11), so that
  composition keeps the narrow or fail-closed answer. `junoscript` joins `xml-mode` and `op` as
  an entry a narrow allow may not open.
- **4. Two warnings** (Ryan's ruling). `projection_netconf_closed` and
  `projection_deny_beneath_view_configuration` (§12). Neither fails `policy test` or `policy diff`.
  `policy diff` prints the ones a change brings, since every unchanged warning on every diff is
  noise.
- **5. The key is adapter data** (§8, "the platform set is pinned"). `rpc_entry_denies` is read
  only on a projected platform. A block may drop an entry deny, and that platform then renders
  as set 1.1.0 does: ruling 10's render changes hang on the key too. It may never add one the set
  did not measure, as with `carve_outs`. `DefaultSet` is 1.2.0. A policy pinned to 1.1.0 renders
  byte for byte as before.
- **6. Services** (Ryan's ruling, narrowed for security; data L26c). Under set 1.2.0
  check-config no longer fails NETCONF, the XML API, `outbound-ssh`, any non-RPC service, or an
  ssh option. It still fails `web-management` and `extension-service` anywhere in the hierarchy,
  and `rest` unless plan 9b1 Task 3 measures the `junoscript` deny closing it. Set 1.1.0's
  allowlist is unchanged.
- **7. Groups** (Ryan's ruling; data L57). check-config reads `show configuration | display set
  | display inheritance` and trusts the expanded lines. It names the group behind a template line
  it fails: a group statement whose path, wildcards read as Junos reads them, equals the line.
  Take a group the configuration applies to a template: an `apply-groups` naming it at or above
  the template's level, with no `apply-groups-except` naming it at or below that level. If the
  template does not write a harmless leaf of that name itself and the capture does not carry its
  statement there, the capture is refused as not inherited; where the template writes a privilege
  or unlisted statement of that name, the group is named at its own line. An `apply-groups`
  reaching a template whose group the capture does not define is refused. A group applied from
  inside another group's definition is read as applied at the top (conservative), unless L57
  shows Junos does not expand it. Neither `apply-groups` nor `apply-groups-except` is itself a
  finding. In a group a `<pattern>` word is read as every word it matches.
- **8. Batch.** `--batch FILE...`, the device named by the file name where the inventory has it,
  else by the name less its last extension. Every file is checked. Exit 2 if any file's outcome
  was a usage or "nothing checked" one, else 1 if any had a finding or could not be read.
- **9. Unlisted statements fail.** Under a template, a statement on neither ruling 7's privilege
  list nor its harmless list fails, from a group or written there. `allow-hidden-commands`,
  `login-script`, `logical-system`, `tenant` and `security-role` change what a session runs, and
  an allowlist does not fail open on a statement nobody listed (plan 5b pre-flight C1).
- **10. A readonly with a deny beneath `show **`** (Ryan's ruling of 2026-10-11, on plan 9b1's
  pre-flight; data: `L26c-junoscript-juniper_*.md`, `L26b-juniper_*.md`, `L58-juniper_*.md`).
  Without this ruling such a readonly fails closed under 1.2.0 as under 1.1.0: its baseline
  denies name `save` and `xml-mode`, which no proven keyword names, they render 333 bytes alone,
  and view-configuration's carve-outs take `show **` out of `view`'s reach, so `show **` would go
  out as an allow that beats the deny. Where the adapter carries `rpc_entry_denies`, and only
  there: the baseline's `xml-mode **` is sent as nothing beside `junoscript **`, which refuses it
  (Junos authorizes `xml-mode` as `junoscript`; the model reads it refused); set 1.2.0's tree
  proves `save`; `word **` denies render as one alternative; a permit the bits reach but for a
  carve-out of an unsent ceiling bit, whose allow would beat a deny beneath it, goes out as allows
  of those carve-outs, each within the ceiling and meeting no deny, reported as sent beyond the
  bits; and a capability reply sending an allow its bits do not reach yields to a narrow one
  that reaches every allow and leaves off no more. view-configuration is not sent to such a
  readonly, whose grant decides none of its other reach; ruling 4's warning stays an operator's
  and an admin's.
```

- [ ] **Step 5: Add two §14 bullets** under **Platform and projection**, after "Projection shape
  selection":

```markdown
- **The entry deny** (decision 44): under set 1.2.0 an operator granted `**` less `show
  configuration **` renders the capability shape with `junoscript` in `deny-commands`; the device
  refuses `show configuration`, `xml-mode netconf` and that user's NETCONF on port 830, while a
  subject with no deny beneath its bits opens NETCONF; under set 1.1.0 the same policy fails
  closed as before. Under set 1.2.0 a readonly granted `show **` less `show configuration **`
  renders `view`, its denies with `junoscript` in 170 bytes, and allows of `show log`, `show
  firewall` and `show policer`; the device refuses `show configuration`, `xml-mode` and
  `xml-mode netconf`. A readonly granted `show **` alone renders as under 1.1.0 (ruling 10).
- **check-config reads groups** (decision 44): a group adding `permissions` to `p49-remote` fails
  naming the group; a group adding `login-tip` passes; a capture without `display inheritance`
  from a device applying a group to a template is refused; `--batch` checks every file.
```

- [ ] **Step 6: Edit L26c's table row.** Replace its **Claim** cell's last sentence (`Beside it,
  unmeasured: … and `scp`.`) with:

```markdown
Beside it: whether a deny naming the entry points binds, with their abbreviations and through a class's own deny list; whether `deny-commands "junoscript"` also refuses NETCONF as an SSH subsystem on port 22 (with `netconf ssh` configured), NETCONF over the SSH exec channel (`ssh <device> xml-mode netconf need-trailer`), an `op url` script's `jcs:invoke` RPCs, REST (`/rpc/…`) and `scp` of `/config/juniper.conf.gz`, each against a control; whether a port49-projected reply under set 1.2.0 carrying the entry deny keeps the CLI deny, refuses NETCONF, and leaves a no-deny subject's NETCONF working.
```

  Replace its **What rests on it** cell with:

```markdown
`JunosFacts.DenyBindsRPCs` (false): a deny beneath a sent bit or the baseline guards the CLI only; set 1.1.0 fails closed on it (§8, option C), and set 1.2.0 adds `rpc_entry_denies` (`junoscript **`) instead (decision 44 rulings 1–3, 6); which management services check-config fails under each set (§8)
```

  Append to its **Status** cell, after `The rest of the row stays open`:
  `; plan 9b1 (2026-10-11) measures the rest in its Tasks 3 and 9`.

- [ ] **Step 7: Add L57's row** after L56's:

```markdown
| **L57** | What a Junos configuration capture carries for configuration groups that reach port49's template classes. Under `show configuration \| display set \| display inheritance`, and the other order (`\| display inheritance \| display set`), against plain `display set`: whether a group applied at the top by `apply-groups` is expanded under `system login class p49-remote` for a `<*>` and a `<p49-*>` path; whether `apply-groups-except` at the class keeps a group's statements off it; whether a group applied from inside another group's definition commits, and is expanded; whether the `apply-groups` and `set groups` lines still print in the inherited capture; whether a class's own leaf (`idle-timeout`) stands over a group's; whether a group's `permissions` is added beside a class's own (a leaf-list). And whether a TACACS+ session landing in `remote` holds what a group added (`show cli authorization`). | `port49 devices check-config`'s group reading (§12; decision 44 rulings 7 and 9): which lines it trusts as expanded, and when it refuses a capture as not inherited | Junos (vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15) | open — added by plan 9b1 |
```

- [ ] **Step 8: Add L57's detail bullet** after the L26c detail bullet (the one ending `…so a
  rerun is owed (L26c review I-1, I-4).`):

```markdown
- **L57** — added by plan 9b1 (`tests/lab/junos_groups_test.go`); open. Why it is a row:
  `devices check-config` used to refuse any capture carrying `apply-groups`, and the fleets port49
  serves template their logins through groups. Decision 44 trusts the device's own expansion,
  so what `display inheritance` prints in set form is a claim about the device, and is measured.
```

- [ ] **Step 8b: Add L58's row** after L57's, and its detail bullet after L57's:

```markdown
| **L58** | The two Junos baseline words a readonly's set 1.2.0 reply rests on, under the factored deny set 1.2.0 renders, one alternative naming both words (`^ *(save\|junoscript)( .*)?` and the pipe tail), each against a control with the same class (`permissions view`) and no deny. `save`: whether it is a keyword to deny-commands, a `save` command the control runs with `\| count`'s evidence refused under the deny with the caret under `save` (L26b proved it on vJunos-router; on vSRX its control took the hidden `save dhcp-security-snoop` and refused the file name after it, so nothing ran). `xml-mode`: whether bare `xml-mode` (the Junos XML protocol, greeting `<junoscript`) and `xml-mode netconf` are refused under it, where the control is greeted. | Set 1.2.0's keyword tree (`save`); decision 44 ruling 10's `xml-mode **` sent as nothing beside `junoscript **` | Junos (vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15) | open — added by plan 9b1 |
```

```markdown
- **L58** — added by plan 9b1 (`tests/lab/junos_baseline_test.go`); open. Why it is a row: a
  readonly's reply carries the baseline's denies, and decision 44 ruling 10 sends `save **` as a
  proven keyword and `xml-mode **` as nothing. L26b left `save` unproven on vSRX, and L26c typed
  only `xml-mode netconf` under a `junoscript` deny.
```

- [ ] **Step 9: Check and commit.**

```bash
grep -n 'rpc_entry_denies\|projection_netconf_closed\|L57\|L58' docs/design/2026-08-23-policy-engine-spec.md | head
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: spec for plan 9b1, a per-user junoscript deny and groups in check-config

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Lab harness — the entry cells (a, b, c0, e, scp), the groups cells (d), and L58

**Files:**
- Create: `tests/lab/junos_entry_test.go`
- Create: `tests/lab/junos_entry_unit_test.go`
- Create: `tests/lab/junos_groups_test.go`
- Create: `tests/lab/junos_baseline_test.go`, `tests/lab/junos_baseline_unit_test.go` (L58)

**Interfaces:**
- Consumes (existing, `tests/lab`): `eachPlatform`, `(*lab).capture`, `(*lab).junosConfigureAdmin`,
  `(*lab).junosLogin(t, name, attrs) (*cliConn, junosRun, int64)`, `(*lab).nextLogin`,
  `(*lab).netconfDialPort(user, secret, port) (*netconfConn, string, error)`,
  `(*netconfConn).rpc(id, body) (string, error)`, `(*lab).dialHostPort`, `(*lab).junosCLI`,
  `jsdEntry`-style typing via `l26cRun`, `newL26cRun`, `l26cEntryCell`, `l26cRPCCell`,
  `l26cSend`, `junosSettle`, `junosShow`, `isAuthRejection`, `sessionPermitted`, `(*lab).mark`,
  `(*lab).drainRecords`, `(*lab).result`, `firstLines`, `oneLine`, `tableCell`, `cellOr`,
  `commitWord`, `redactConfigCapture`, `labcreds.RedactNote`, `junosL26cClientHello`,
  `adapter.Set`, `adapter.ReferenceClasses`, `projectionRestore`; for L58, L26b's
  `(*lab).l26bSession`, `l26bUserKey`, `l26bCell`, `l26bDenyCell`, `l26bVerdict`,
  `junosL26cRefusal`, `keywordWalk`, `junosPrepare`, `containsAny`, `(*cliConn).send`,
  `(*cliConn).expectFrom`, `(*lab).configPath`, `(*lab).restart`.
- Produces: `TestL26cEntryNetconf`, `TestL26cEntryScripts`, `TestL57JunosGroups`,
  `TestL58JunosBaselineWords`;
  pure helpers `entryVerdict(runs map[string]l26cRun, deny []string, control string,
  canonical, probes []string) (readings map[string]string, unisolated []string)`,
  `opScriptCell(out string) string`, `scpCell(n int64, err error) string`,
  `l57Readings(capture string) l57Reading`, `l58EntryCell(out string) string`,
  `l58Save(control, deny, controlOuts map[string]string) (verdict, by string)`.
  Results entries `L26c-entries`, `L57` and `L58`; fixture files
  `internal/platform/testdata/l57-<platform>.set`.

The seeded login pool is 16 per platform per `go test` process (`tokenPoolSize`), so each test
runs in its own invocation (Task 3). `TestL26cEntryNetconf` uses 12 (four per class: the CLI
session, port 830, port 22, the exec channel). `TestL26cEntryScripts` uses 11 (W, V and C: the CLI
session, REST's request, scp; Vw: the login and scp); REST's tunnel and scp's harness control are
break-glass's. `TestL58JunosBaselineWords` uses 6 (control and deny: the CLI session, bare
`xml-mode`, `xml-mode netconf`, each entry in its own session since it turns the session into
XML).

- [ ] **Step 1: Write the failing unit tests** (`tests/lab/junos_entry_unit_test.go`):

```go
//go:build lab

package lab

import (
	"errors"
	"testing"
)

// These run without a device: the entry cells' isolation verdict, and the
// op script's and scp's cells.

func TestEntryVerdict(t *testing.T) {
	const p830, xml, p22 = "port 830", "entry: xml-mode netconf need-trailer", "port 22 subsystem"
	runs := map[string]l26cRun{
		"W": jsdRun(map[string]string{p830: "refused", xml: "refused", p22: "refused"}),
		"V": jsdRun(map[string]string{p830: "hello", xml: "hello", p22: "refused"}),
		"C": jsdRun(map[string]string{p830: "hello", xml: "hello", p22: "refused"}),
	}
	readings, unisolated := entryVerdict(runs, []string{"W"}, "C", []string{p830, xml}, []string{p830, xml, p22})
	if readings["W "+p830] != "deny" || readings["W "+xml] != "deny" {
		t.Errorf("W refused where C reached: %v", readings)
	}
	// Port 22 runs nowhere: C refused it too, so W's refusal is no deny, and
	// it is not canonical, so nothing fails.
	if readings["W "+p22] != "runs nowhere" || len(unisolated) != 0 {
		t.Errorf("port 22: %v %v", readings, unisolated)
	}
	// A canonical probe C did not reach fails the run.
	runs["C"] = jsdRun(map[string]string{p830: "refused", xml: "hello"})
	if _, unisolated = entryVerdict(runs, []string{"W"}, "C", []string{p830, xml}, []string{p830, xml}); len(unisolated) != 1 {
		t.Errorf("C refused port 830: %v", unisolated)
	}
	// W reaching is "reached", the deny's failure, whatever C did.
	runs["W"] = jsdRun(map[string]string{p830: "hello"})
	if r, _ := entryVerdict(runs, []string{"W"}, "C", nil, []string{p830}); r["W "+p830] != "reached" {
		t.Errorf("W reached: %v", r)
	}
	// A token the device refused, or a cell not observed, says nothing about
	// the deny: never "deny", even where C reached (G2 must not drop a
	// service on a spent token).
	runs["C"] = jsdRun(map[string]string{p830: "hello"})
	for _, cell := range []string{"login refused", "not observed"} {
		runs["W"] = jsdRun(map[string]string{p830: cell})
		if r, _ := entryVerdict(runs, []string{"W"}, "C", nil, []string{p830}); r["W "+p830] != "not observed" {
			t.Errorf("W %s: %v", cell, r)
		}
	}
}

func TestOpScriptCell(t *testing.T) {
	for _, c := range []struct{ out, want string }{
		{"P49OP-VERSION srx1\nP49OP-CONFIG 1\n", "version and configuration"},
		{"P49OP-VERSION srx1\nP49OP-CONFIG 0\n", "version only"},
		{"error: permission denied\n", "refused"},
		{"syntax error, expecting <command>\n", "refused"},
		{"", "not observed"},
	} {
		if got := opScriptCell(c.out); got != c.want {
			t.Errorf("%q: got %q, want %q", c.out, got, c.want)
		}
	}
}

func TestScpCell(t *testing.T) {
	for _, c := range []struct {
		n    int64
		err  error
		want string
	}{
		{4096, nil, "file read"},
		{0, errors.New("scp: permission denied"), "refused"},
		{0, nil, "refused"},
	} {
		if got := scpCell(c.n, c.err); got != c.want {
			t.Errorf("%d %v: got %q, want %q", c.n, c.err, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test -tags lab ./tests/lab/ -run 'TestEntryVerdict|TestOpScriptCell|TestScpCell' -count=1`
Expected: FAIL, `undefined: entryVerdict` (and the other two).

- [ ] **Step 3: Write `tests/lab/junos_entry_test.go`.** The classes, the replies and the two tests.
  Every probe a class can type gets a cell; `—` where not typed.

```go
//go:build lab

package lab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestL26cEntryNetconf and TestL26cEntryScripts measure the ways into an RPC
// that `deny-commands "junoscript"` was not yet measured against (spec §15
// L26c; plan 9b1 Task 3), each against a control with the same bits:
//   - W: view and view-configuration, and the rendered deny of `show
//     configuration` and `junoscript`, the reply set 1.2.0 sends;
//   - V: the same with no junoscript deny, set 1.1.0's capability shape: the
//     hole the operator saw on SRX hardware, reproduced (L26c-operator);
//   - C: the same bits and no deny, the positive control.
// Vw, view alone and no deny, reads `scp` only.

var junosEntryClass = []string{
	"set system login class p49-ent-vc permissions view",
	"set system login class p49-ent-vc permissions view-configuration",
	"set system login user p49-ent-vc class p49-ent-vc",
	"set system login class p49-ent-v permissions view",
	"set system login user p49-ent-v class p49-ent-v",
}

var junosEntryDelete = []string{
	"delete system login user p49-ent-vc", "delete system login class p49-ent-vc",
	"delete system login user p49-ent-v", "delete system login class p49-ent-v",
}

// entryDenyBoth is port49's rendering of deny `show configuration **` and deny
// `junoscript **` as one alternation (internal/projection ruleERE, denyLead and
// pipeTail).
const entryDenyBoth = `deny-commands=^( *show +configuration( .*)? *(\|.*)?| *junoscript( .*)? *(\|.*)?)$`

var junosEntryVariants = []junosVariant{
	{"W", `["local-user-name=p49-ent-vc", "` + jsonEscape(entryDenyBoth) + `"]`,
		"view view-configuration; deny show configuration and junoscript (set 1.2.0's reply)"},
	{"V", `["local-user-name=p49-ent-vc", "deny-commands=^ *show +configuration( .*)? *(\\|.*)?$"]`,
		"view view-configuration; deny show configuration only (the hole)"},
	{"C", `["local-user-name=p49-ent-vc"]`, "view view-configuration; no deny (the control)"},
}

// jsonEscape is s as a JSON string's body: the reply is a JSON list.
func jsonEscape(s string) string { return strings.ReplaceAll(s, `\`, `\\`) }

// entryVerdict reads each deny class's cell against the control: "deny"
// where the class was refused and the control reached the probe; "runs
// nowhere" where the control was refused too; "reached" where the class
// reached it; "not observed" where the class's token was refused or its cell
// was not observed, which says nothing about the deny. unisolated lists each
// canonical probe the control did not reach: the run cannot say the deny
// closed it, and the run fails.
func entryVerdict(runs map[string]l26cRun, deny []string, control string, canonical, probes []string) (
	map[string]string, []string) {
	readings := map[string]string{}
	var unisolated []string
	reached := func(c string) bool {
		return l26cReached(c) || c == "ran" || c == "file read" || strings.HasPrefix(c, "version")
	}
	for _, p := range probes {
		cc := runs[control].cells[p]
		if slices.Contains(canonical, p) && !reached(cc) {
			unisolated = append(unisolated, fmt.Sprintf("%s: the control %s", p, cellOr(runs[control], p)))
		}
		for _, cls := range deny {
			cell, ok := runs[cls].cells[p]
			if !ok {
				continue
			}
			switch {
			case reached(cell):
				readings[cls+" "+p] = "reached"
			case cell == "login refused" || cell == "not observed":
				readings[cls+" "+p] = "not observed"
			case reached(cc):
				readings[cls+" "+p] = "deny"
			default:
				readings[cls+" "+p] = "runs nowhere"
			}
		}
	}
	return readings, unisolated
}

// entryProbes are TestL26cEntryNetconf's cells, in table order.
var entryProbes = []string{"show configuration system host-name", "entry: xml-mode netconf need-trailer",
	"xml-mode netconf need-trailer: get-configuration", "port 830", "port 830: get-configuration",
	"port 22 subsystem", "port 22 subsystem: get-configuration", "exec channel", "exec channel: get-configuration"}

// entryCanonical are the probes the control must reach, or the run is INVALID:
// every way in the L26c claim names, so none closes the row unmeasured. If the
// exec channel cannot be made to reach under C after a harness fix, STOP and
// report: the claim is then narrowed, never closed past it.
var entryCanonical = []string{"show configuration system host-name", "entry: xml-mode netconf need-trailer",
	"port 830", "port 22 subsystem", "exec channel"}

const getConfigHost = "<get-configuration><configuration><system><host-name/></system></configuration></get-configuration>"

// entryNetconf dials NETCONF on port with the next token and asks for the
// host name from the configuration. A channel the device closes after
// port49d permitted the session is "refused".
func (l *lab) entryNetconf(t *testing.T, r l26cRun, key, port string) {
	t.Helper()
	off := l.mark()
	user, secret := l.nextLogin(t)
	n, hello, err := l.netconfDialPort(user, secret, port)
	if err != nil {
		cell := "not observed"
		switch {
		case isAuthRejection(err):
			cell = "login refused"
		case sessionPermitted(l.drainRecords(off, 10*time.Second)):
			cell = "refused"
		}
		r.cells[key], r.outs[key] = cell, oneLine(err.Error())
		return
	}
	defer n.Close()
	r.cells[key], r.outs[key] = "hello", firstLines(hello, 5)
	reply, err := n.rpc(1, getConfigHost)
	r.outs[key+": get-configuration"] = firstLines(reply, 10)
	r.cells[key+": get-configuration"] = l26cRPCCell(reply, "<host-name>")
	if err != nil {
		r.cells[key+": get-configuration"] = "not observed"
	}
}

// entryExec runs `xml-mode netconf need-trailer` as an SSH exec command with
// the next token, writes the client hello and the get-configuration RPC to
// its stdin, and reads what comes back within 60s.
func (l *lab) entryExec(t *testing.T, r l26cRun) {
	t.Helper()
	off := l.mark()
	user, secret := l.nextLogin(t)
	const key = "exec channel"
	c, err := l.dialHostPort(user, secret, l.p.addr+":22", 60*time.Second)
	if err != nil {
		r.cells[key], r.outs[key] = "login refused", oneLine(err.Error())
		return
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", oneLine(err.Error())
		return
	}
	defer s.Close()
	s.Stdin = strings.NewReader(junosL26cClientHello + "\n<rpc>" + getConfigHost + "</rpc>]]>]]>\n" +
		"<rpc><close-session/></rpc>]]>]]>\n")
	var out bytes.Buffer
	s.Stdout, s.Stderr = &out, &out
	done := make(chan error, 1)
	go func() { done <- s.Run("xml-mode netconf need-trailer") }()
	select {
	case err = <-done:
	case <-time.After(60 * time.Second):
		err = fmt.Errorf("no exit within 60s")
	}
	got := out.String()
	r.outs[key] = firstLines(got, 12)
	switch {
	case strings.Contains(got, "</hello>"):
		r.cells[key] = "hello"
		r.cells[key+": get-configuration"] = l26cRPCCell(got, "<host-name>")
	case sessionPermitted(l.drainRecords(off, 10*time.Second)) || strings.Contains(got, "unknown command"):
		r.cells[key] = "refused"
	default:
		r.cells[key] = "not observed"
	}
	if err != nil && r.cells[key] == "not observed" {
		r.outs[key] += "\n" + oneLine(err.Error())
	}
}

func TestL26cEntryNetconf(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26c-entries")
		defer stop()
		commit := l.junosConfigureAdmin(t, append(slices.Clone(junosEntryClass), "set system services netconf ssh"))
		defer l.junosConfigureAdmin(t, junosEntryDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		runs := map[string]l26cRun{}
		for _, v := range junosEntryVariants {
			r := newL26cRun()
			runs[v.name] = r
			// One CLI session: the deny on the CLI, then xml-mode, which ends it.
			c, run, _ := l.junosLogin(t, "entry "+v.name, v.attrs)
			if c == nil {
				t.Fatalf("INVALID: %s: the session did not open, so nothing was measured: %s", v.name, run.loginErr)
			}
			r.outs["show cli authorization"] = run.auth
			o, err := l26cSend(c, "show configuration system host-name")
			r.outs["show configuration system host-name"] = firstLines(o, 6)
			r.cells["show configuration system host-name"] = l26cCLICell(o, "host-name")
			if err != nil {
				r.cells["show configuration system host-name"] = "not observed"
			}
			entryXMLMode(c, r)
			c.Close()
			l.entryNetconf(t, r, "port 830", "830")
			l.entryNetconf(t, r, "port 22 subsystem", "22")
			l.entryExec(t, r)
		}
		for _, p := range entryProbes {
			for _, name := range []string{"W", "V", "C"} {
				if runs[name].cells[p] == "not observed" {
					t.Errorf("not observed: %s in %s", p, name)
				}
			}
		}
		readings, unisolated := entryVerdict(runs, []string{"W", "V"}, "C", entryCanonical, entryProbes)
		if len(unisolated) > 0 {
			t.Fatalf("INVALID: the control did not reach %s; no note is written", strings.Join(unisolated, "; "))
		}
		for _, p := range []string{"port 22 subsystem", "exec channel"} {
			if readings["W "+p] == "reached" {
				t.Errorf("STOP: under the junoscript deny W reached %s, which the deny does not close: report to "+
					"the controller before Task 4 (decision 44 ruling 1 rests on it)", p)
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "The classes were committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit),
			strings.Join(junosEntryClass, "\n"))
		entryTables(&b, runs, readings, junosEntryVariants, entryProbes)
		l.result(t, "L26c-entries", "Whether `deny-commands \"junoscript\"`, sent by TACACS+ beside a deny of `show "+
			"configuration` under `view view-configuration`, refuses NETCONF as an SSH subsystem on port 22 and "+
			"over the SSH exec channel (`xml-mode netconf need-trailer`), as it refuses `xml-mode` from the CLI and "+
			"port 830; with the same reply less the junoscript deny (the hole) and a control with the same bits and "+
			"no deny (spec §15 L26c; plan 9b1 Task 3, cell a).", b.String())
	})
}

// entryXMLMode types the CLI entry, and where a hello comes back sends the
// client hello and the get-configuration RPC.
func entryXMLMode(c *cliConn, r l26cRun) {
	const key = "entry: xml-mode netconf need-trailer"
	from := len(c.out.String())
	if err := c.send("xml-mode netconf need-trailer"); err != nil {
		r.cells[key] = "not observed"
		return
	}
	out, err := c.expectFrom(from, junosPer, "</hello>", junosOpPrompt)
	r.outs[key], r.cells[key] = out, l26cEntryCell(out)
	if err != nil {
		r.cells[key] = "not observed"
	}
	if r.cells[key] != "hello" {
		return
	}
	const k = "xml-mode netconf need-trailer: get-configuration"
	fmt.Fprint(c.in, junosL26cClientHello+"\n")
	from = len(c.out.String())
	fmt.Fprint(c.in, "<rpc>"+getConfigHost+"</rpc>]]>]]>\n")
	reply, err := c.expectFrom(from, 60*time.Second, "</rpc-reply>")
	r.outs[k], r.cells[k] = firstLines(reply, 12), l26cRPCCell(reply, "<host-name>")
	if err != nil {
		r.cells[k] = "not observed"
	}
}

// entryTables writes the cells, the verdicts, and each class's raw outputs.
func entryTables(b *strings.Builder, runs map[string]l26cRun, readings map[string]string, vs []junosVariant,
	probes []string) {
	b.WriteString("| class | reply | why |\n|---|---|---|\n")
	for _, v := range vs {
		fmt.Fprintf(b, "| %s | `%s` | %s |\n", v.name, tableCell(v.attrs), v.why)
	}
	names := make([]string, 0, len(vs))
	for _, v := range vs {
		names = append(names, v.name)
	}
	fmt.Fprintf(b, "\n| probe | %s |\n|---|%s\n", strings.Join(names, " | "), strings.Repeat("---|", len(names)))
	for _, p := range probes {
		cells := make([]string, len(names))
		for i, n := range names {
			cells[i] = cellOr(runs[n], p)
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(p), strings.Join(cells, " | "))
	}
	b.WriteString("\n### Verdict against the control\n\n| probe | W | V |\n|---|---|---|\n")
	for _, p := range probes {
		fmt.Fprintf(b, "| %s | %s | %s |\n", tableCell(p), jsdOrDash(readings["W "+p]), jsdOrDash(readings["V "+p]))
	}
	for _, n := range names {
		fmt.Fprintf(b, "\n### %s\n", n)
		keys := make([]string, 0, len(runs[n].outs))
		for k := range runs[n].outs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			fmt.Fprintf(b, "\n`%s`:\n\n```\n%s\n```\n", k, firstLines(runs[n].outs[k], 20))
		}
	}
}
```

  Then, in the same file, `TestL26cEntryScripts` (cells b, e and scp). The op script is written
  over break-glass with `start shell sh`; REST is reached through a break-glass SSH
  connection's `direct-tcpip` channel to `127.0.0.1:3000` inside the VM, so no port needs
  forwarding through vrnetlab.

```go
// junosEntryOpScript asks for the software information and the configuration's
// host name through jcs:invoke, and prints a marker for each that came back.
var junosEntryOpScript = []string{
	`version 1.0;`,
	`ns junos = "http://xml.juniper.net/junos/*/junos";`,
	`ns xnm = "http://xml.juniper.net/xnm/1.1/xnm";`,
	`ns jcs = "http://xml.juniper.net/junos/commit-scripts/1.0";`,
	`match / {`,
	`    <op-script-results> {`,
	`        var $v = jcs:invoke("get-software-information");`,
	`        <output> "P49OP-VERSION " _ $v//host-name;`,
	`        var $rpc = <get-configuration> { <configuration> { <system>; } }`,
	`        var $g = jcs:invoke($rpc);`,
	`        <output> "P49OP-CONFIG " _ count($g//host-name);`,
	`    }`,
	`}`,
}

const junosEntryOpPath = "/var/tmp/p49-entry-op.slax"

// opScriptCell reads what `op url` printed.
func opScriptCell(out string) string {
	switch {
	case strings.Contains(out, "P49OP-VERSION") && strings.Contains(out, "P49OP-CONFIG 1"):
		return "version and configuration"
	case strings.Contains(out, "P49OP-VERSION"):
		return "version only"
	case strings.TrimSpace(out) == "":
		return "not observed"
	}
	return "refused"
}

// scpCell is what an scp read of a file came to: bytes received, or why not.
func scpCell(n int64, err error) string {
	if err == nil && n > 0 {
		return "file read"
	}
	return "refused"
}

// entryScp reads path over the scp protocol (`scp -f`) with the next token.
func (l *lab) entryScp(t *testing.T, r l26cRun, path string) {
	t.Helper()
	const key = "scp /config/juniper.conf.gz"
	user, secret := l.nextLogin(t)
	c, err := l.dialHostPort(user, secret, l.p.addr+":22", 60*time.Second)
	if err != nil {
		r.cells[key], r.outs[key] = scpCell(0, err), oneLine(err.Error())
		return
	}
	defer c.Close()
	n, err := scpRead(c, path)
	r.cells[key] = scpCell(n, err)
	r.outs[key] = fmt.Sprintf("%d bytes; err %v", n, err)
}

// scpRead is the sink side of scp's protocol: ack, read the C line, ack, read
// the file, ack.
func scpRead(c *ssh.Client, path string) (int64, error) {
	s, err := c.NewSession()
	if err != nil {
		return 0, err
	}
	defer s.Close()
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	var stderr bytes.Buffer
	s.Stderr = &stderr
	if err := s.Start("scp -f " + path); err != nil {
		return 0, err
	}
	in.Write([]byte{0})
	var line []byte
	buf := make([]byte, 1)
	for {
		if _, err := out.Read(buf); err != nil {
			return 0, fmt.Errorf("scp: %v %s", err, oneLine(stderr.String()))
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	var mode string
	var size int64
	var name string
	if _, err := fmt.Sscanf(string(line), "C%s %d %s", &mode, &size, &name); err != nil {
		return 0, fmt.Errorf("scp: %q %s", line, oneLine(stderr.String()))
	}
	in.Write([]byte{0})
	n, err := io.CopyN(io.Discard, out, size)
	in.Write([]byte{0})
	return n, err
}

// entryREST asks the REST API for the configuration's host name, through an
// SSH connection's direct-tcpip channel to 127.0.0.1:3000 inside the VM (so no
// port needs forwarding through vrnetlab), with a token as basic auth. The
// tunnel is break-glass's: who carries the TCP stream says nothing about the
// request, and a token spent on it is one fewer for the cells. The request is
// the class's token, since REST authenticates each request (L15).
func (l *lab) entryREST(t *testing.T, r l26cRun) {
	t.Helper()
	const key = "rest: get-configuration"
	tunnel, err := l.dialHostPort(breakglassUser, breakglassPassword, l.p.addr+":22", 60*time.Second)
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", "the tunnel's login: "+oneLine(err.Error())
		return
	}
	defer tunnel.Close()
	user, secret := l.nextLogin(t)
	hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return tunnel.Dial("tcp", "127.0.0.1:3000")
		}}}
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:3000/rpc", strings.NewReader(getConfigHost))
	req.Header.Set("Content-Type", "application/xml")
	req.SetBasicAuth(user, secret)
	resp, err := hc.Do(req)
	if err != nil {
		r.cells[key], r.outs[key] = "not observed", oneLine(err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	r.outs[key] = fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, firstLines(string(body), 10))
	switch {
	case resp.StatusCode == http.StatusOK && strings.Contains(string(body), "<host-name>"):
		r.cells[key] = "result"
	case resp.StatusCode == http.StatusUnauthorized && isTokenRejected(string(body)):
		r.cells[key] = "login refused"
	default:
		r.cells[key] = "refused"
	}
}

// isTokenRejected reports a 401 whose body says the credential was refused,
// which says nothing about the deny.
func isTokenRejected(body string) bool {
	return strings.Contains(strings.ToLower(body), "authentication")
}

var scriptProbes = []string{"op url: script", "rest: get-configuration", "scp /config/juniper.conf.gz"}

func TestL26cEntryScripts(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26c-scripts")
		defer stop()
		commit := l.junosConfigureAdmin(t, junosEntryClass)
		defer l.junosConfigureAdmin(t, junosEntryDelete)
		// REST is its own commit: an image that refuses it leaves the rest measured.
		restCommit := l.junosConfigureAdmin(t, []string{"set system services rest http port 3000"})
		defer l.junosConfigureAdmin(t, []string{"delete system services rest"})
		restOn := strings.Contains(restCommit, "commit complete")
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		// The op script, over break-glass.
		bg, err := l.junosCLI(breakglassUser, breakglassPassword)
		if err != nil {
			t.Fatalf("INVALID: no break-glass CLI: %v", err)
		}
		if _, err := bg.sendExpect("start shell sh", junosPer, "$ ", "% "); err != nil {
			t.Fatalf("INVALID: start shell: %v", err)
		}
		quoted := make([]string, len(junosEntryOpScript))
		for i, ln := range junosEntryOpScript {
			quoted[i] = "'" + ln + "'"
		}
		bg.sendExpect("printf '%s\\n' "+strings.Join(quoted, " ")+" > "+junosEntryOpPath, junosPer, "$ ", "% ")
		bg.sendExpect("exit", junosPer, junosOpPrompt)
		bg.Close()
		// scp's harness control: break-glass reads the file, or a "refused"
		// in every class could be scpRead's own fault.
		if bgc, err := l.dialHostPort(breakglassUser, breakglassPassword, l.p.addr+":22", 60*time.Second); err != nil {
			t.Fatalf("INVALID: no break-glass SSH for scp's control: %v", err)
		} else {
			n, err := scpRead(bgc, "/config/juniper.conf.gz")
			bgc.Close()
			if scpCell(n, err) != "file read" {
				t.Fatalf("INVALID: break-glass could not scp /config/juniper.conf.gz (%d bytes, %v): the harness "+
					"cannot read a file, so no class's refusal says anything", n, err)
			}
		}

		runs := map[string]l26cRun{}
		classes := append(slices.Clone(junosEntryVariants),
			junosVariant{"Vw", `["local-user-name=p49-ent-v"]`, "view alone; no deny (scp only)"})
		for _, v := range classes {
			r := newL26cRun()
			runs[v.name] = r
			if v.name != "Vw" {
				c, run, _ := l.junosLogin(t, "scripts "+v.name, v.attrs)
				if c == nil {
					t.Fatalf("INVALID: %s: the session did not open: %s", v.name, run.loginErr)
				}
				o, err := l26cSend(c, "op url "+junosEntryOpPath)
				r.outs["op url: script"], r.cells["op url: script"] = firstLines(o, 12), opScriptCell(o)
				if err != nil {
					r.cells["op url: script"] = "not observed"
				}
				c.Close()
				if restOn {
					l.entryREST(t, r)
				} else {
					r.cells["rest: get-configuration"] = "not measured (the image refused `rest`)"
					r.outs["rest: get-configuration"] = restCommit
				}
			} else {
				// The login sets port49d's reply for the scp token after it.
				c, run, _ := l.junosLogin(t, "scripts Vw", v.attrs)
				if c == nil {
					t.Fatalf("INVALID: Vw: the session did not open: %s", run.loginErr)
				}
				c.Close()
			}
			l.entryScp(t, r, "/config/juniper.conf.gz")
		}
		canonical := []string{"op url: script"}
		if restOn {
			canonical = append(canonical, "rest: get-configuration")
		}
		readings, unisolated := entryVerdict(runs, []string{"W", "V", "Vw"}, "C", canonical, scriptProbes)
		if len(unisolated) > 0 {
			t.Fatalf("INVALID: the control did not reach %s; no note is written", strings.Join(unisolated, "; "))
		}
		// G1 is decided by data alone (controller ruling 4): W's op cell is a
		// deny or a reach, or nothing is written.
		if v := readings["W op url: script"]; v != "deny" && v != "reached" {
			t.Fatalf("INVALID: W's op url cell reads %q, so G1 is undecided; no note is written", v)
		}
		if runs["Vw"].cells["scp /config/juniper.conf.gz"] == "file read" {
			t.Errorf("STOP: a class with `view` alone read the configuration file over scp: report to the controller")
		}
		var b strings.Builder
		fmt.Fprintf(&b, "The classes were committed: %s. REST: %s.\n\nThe op script, at `%s`:\n\n```\n%s\n```\n\n",
			commitWord(commit), commitWord(restCommit), junosEntryOpPath, strings.Join(junosEntryOpScript, "\n"))
		entryTables(&b, runs, readings, classes, scriptProbes)
		fmt.Fprintf(&b, "\n### Gates (plan 9b1)\n\n- G1, `op`: under W the script printed %s: %s.\n- G2, `rest`: under "+
			"W %s: %s.\n", runs["W"].cells["op url: script"], gateWord(readings["W op url: script"], "op"),
			runs["W"].cells["rest: get-configuration"], gateWord(readings["W rest: get-configuration"], "rest"))
		l.result(t, "L26c-scripts", "Whether `deny-commands \"junoscript\"` beside a deny of `show configuration` "+
			"also refuses an `op url` script's `jcs:invoke` RPCs and REST's `/rpc`, and what `scp` of "+
			"`/config/juniper.conf.gz` reads under each class; against the same reply less the junoscript deny and a "+
			"control with the same bits and no deny (spec §15 L26c; plan 9b1 Task 3, cells b and e).", b.String())
	})
}

// gateWord is what a W verdict means for set 1.2.0's lists.
func gateWord(verdict, entry string) string {
	switch verdict {
	case "deny":
		return "closed by the junoscript deny; `" + entry + "` stays off set 1.2.0's list"
	case "reached":
		return "reached past the junoscript deny; `" + entry + "` goes on set 1.2.0's list"
	}
	return "not measured; `" + entry + "` is handled as reached (fails closed)"
}
```

- [ ] **Step 4: Write `tests/lab/junos_groups_test.go`** (cell d, L57). It applies the set 1.1.0
  reference (as `TestProjectionDifferential` does), the groups, captures four forms, logs a token
  in landing in `remote`, and writes the inherited capture as a fixture.

```go
//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adapter "github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// TestL57JunosGroups measures what a configuration capture carries for groups
// that reach port49's template classes (spec §15 L57; decision 44 ruling 7).
var junosGroupsLines = []string{
	"set groups p49g-tip system login class <*> login-tip",
	"set groups p49g-perm system login class <p49-*> permissions view-configuration",
	`set groups p49g-perm system login class <p49-*> allow-commands "^show version$"`,
	"set groups p49g-excepted system login class <*> permissions clear",
	"set groups p49g-unapplied system login class <*> permissions all",
	"set groups p49g-timeout system login class <*> idle-timeout 30",
	// A class that writes its own permissions, under p49g-perm's <p49-*>:
	// whether Junos adds a group's leaf-list value beside a local one, as a
	// local_user_name template would meet it (pre-flight, R5).
	"set system login class p49-l57own permissions view",
	"set apply-groups p49g-tip",
	"set apply-groups p49g-perm",
	"set apply-groups p49g-excepted",
	"set apply-groups p49g-timeout",
	"set system login class p49-remote apply-groups-except p49g-excepted",
}

// junosGroupsNested is committed apart: whether Junos takes a group applied
// from inside another's definition is itself a cell.
var junosGroupsNested = []string{
	"set groups p49g-inner system login class <p49-*> permissions network",
	"set groups p49g-outer apply-groups p49g-inner",
	"set apply-groups p49g-outer",
}

var junosGroupsDelete = []string{
	"delete apply-groups p49g-tip", "delete apply-groups p49g-perm", "delete apply-groups p49g-excepted",
	"delete apply-groups p49g-timeout", "delete apply-groups p49g-outer",
	"delete system login class p49-remote apply-groups-except",
	"delete groups p49g-tip", "delete groups p49g-perm", "delete groups p49g-excepted", "delete groups p49g-unapplied",
	"delete groups p49g-timeout", "delete groups p49g-outer", "delete groups p49g-inner",
	"delete system login class p49-l57own",
}

// l57Reading is what one capture says about p49-remote.
type l57Reading struct {
	remote                      []string // every set line under system login class p49-remote
	applyLines, groupLines      bool     // `set apply-groups` and `set groups` lines printed
	tip, perm, excepted, nested bool     // each group's statement expanded under p49-remote
	ownTimeout                  bool     // idle-timeout is the reference's 720, not the group's 30
	ownPerm                     bool     // p49g-perm's view-configuration beside p49-l57own's own view
}

func l57Readings(capture string) l57Reading {
	var r l57Reading
	for _, ln := range strings.Split(strings.ReplaceAll(capture, "\r", ""), "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "set apply-groups "):
			r.applyLines = true
		case strings.HasPrefix(ln, "set groups "):
			r.groupLines = true
		case strings.HasPrefix(ln, "set system login class p49-remote "):
			r.remote = append(r.remote, ln)
			rest := strings.TrimPrefix(ln, "set system login class p49-remote ")
			r.tip = r.tip || strings.HasPrefix(rest, "login-tip")
			r.perm = r.perm || rest == "permissions view-configuration"
			r.excepted = r.excepted || rest == "permissions clear"
			r.nested = r.nested || rest == "permissions network"
			r.ownTimeout = r.ownTimeout || rest == "idle-timeout 720"
		case ln == "set system login class p49-l57own permissions view-configuration":
			r.ownPerm = true
		}
	}
	return r
}

var l57Captures = []string{
	"show configuration | display set | display inheritance | no-more",
	"show configuration | display inheritance | display set | no-more",
	"show configuration | display set | no-more",
	"show configuration system login | display inheritance | no-more",
}

func TestL57JunosGroups(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		set, ok := adapter.Set("1.1.0")
		if !ok {
			t.Fatal("no set 1.1.0")
		}
		reference, err := adapter.ReferenceClasses(set["juniper_junos"], 12*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		stop := l.capture(t, "L57")
		defer stop()
		l.junosConfigureAdmin(t, reference)
		defer l.junosConfigureAdmin(t, projectionRestore(reference))
		commit := l.junosConfigureAdmin(t, junosGroupsLines)
		defer l.junosConfigureAdmin(t, junosGroupsDelete)
		nestedCommit := l.junosConfigureAdmin(t, junosGroupsNested)
		if !strings.Contains(nestedCommit, "commit complete") {
			l.junosConfigureAdmin(t, []string{"delete apply-groups p49g-outer", "delete groups p49g-outer",
				"delete groups p49g-inner"})
		}
		caps := map[string]string{}
		bg, err := l.junosCLI(breakglassUser, breakglassPassword)
		if err != nil {
			t.Fatalf("INVALID: no break-glass CLI: %v", err)
		}
		for _, cmd := range l57Captures {
			out, err := junosShow(bg, cmd)
			if err != nil {
				t.Fatalf("INVALID: %s: %v", cmd, err)
			}
			caps[cmd] = redactConfigCapture(labcreds.RedactNote(out))
		}
		bg.Close()
		// Positive control: p49g-tip has no wildcard but <*>, is applied at the
		// top, and nothing excepts it. If neither inherited capture carries it,
		// the groups did not apply, and nothing below says anything. The
		// fixture is the first inherited form that does: the one Task 7's
		// ConfigCapture becomes.
		inheritedForm := l57Captures[0]
		if !l57Readings(caps[inheritedForm]).tip {
			inheritedForm = l57Captures[1]
		}
		if !l57Readings(caps[inheritedForm]).tip {
			t.Fatalf("INVALID: neither inherited form shows p49g-tip's login-tip under p49-remote; no note is written")
		}
		// A session landing in remote: what a group added, the session holds.
		c, run, _ := l.junosLogin(t, "L57 remote", `[]`)
		if c != nil {
			c.Close()
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Reference (set 1.1.0, 12h) applied, then the groups: %s. Nested: %s.\n\n```\n%s\n%s\n```\n\n",
			commitWord(commit), commitWord(nestedCommit), strings.Join(junosGroupsLines, "\n"),
			strings.Join(junosGroupsNested, "\n"))
		b.WriteString("| capture | apply-groups lines | set groups lines | p49g-tip | p49g-perm | p49g-excepted | " +
			"nested | own idle-timeout 720 | group permission beside own |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, cmd := range l57Captures {
			r := l57Readings(caps[cmd])
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n", tableCell(cmd), yesNo(r.applyLines),
				yesNo(r.groupLines), yesNo(r.tip), yesNo(r.perm), yesNo(r.excepted), yesNo(r.nested), yesNo(r.ownTimeout),
				yesNo(r.ownPerm))
		}
		fmt.Fprintf(&b, "\nA token session with no reply attributes (lands in `remote`), `show cli authorization`:\n\n```\n%s\n```\n",
			strings.TrimSpace(run.auth))
		for _, cmd := range l57Captures {
			fmt.Fprintf(&b, "\n### `%s` (p49-remote and the group lines)\n\n```\n%s\n```\n", cmd, l57Excerpt(caps[cmd]))
		}
		fixture := filepath.Join(root, "internal", "platform", "testdata", "l57-"+l.p.name+".set")
		if err := os.MkdirAll(filepath.Dir(fixture), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture, []byte(caps[inheritedForm]), 0o644); err != nil {
			t.Fatal(err)
		}
		l.result(t, "L57", "What a Junos configuration capture carries for configuration groups that reach port49's "+
			"template class p49-remote: a `<*>` and a `<p49-*>` group applied at the top, one kept off the class by "+
			"`apply-groups-except`, one applied nowhere, one applied from inside another, and a group's idle-timeout "+
			"beside the class's own; in both inherited set forms, plain set form and the inherited curly form; and "+
			"what a session landing in `remote` holds (spec §15 L57; decision 44 ruling 7).", b.String())
	})
}

// l57Excerpt is a capture's lines naming p49g-, apply-groups or p49-remote.
func l57Excerpt(capture string) string {
	var out []string
	for _, ln := range strings.Split(capture, "\n") {
		if strings.Contains(ln, "p49g-") || strings.Contains(ln, "apply-groups") || strings.Contains(ln, "p49-remote") {
			out = append(out, strings.TrimRight(ln, "\r"))
		}
	}
	return strings.Join(out, "\n")
}
```

- [ ] **Step 4b: Write L58's cell** (owner's ruling 4: `save` and bare `xml-mode` under the
  factored deny, each against a control). First the unit tests,
  `tests/lab/junos_baseline_unit_test.go`:

```go
//go:build lab

package lab

import "testing"

// These run without a device: L58's entry cell and its `save` verdict.

func TestL58EntryCell(t *testing.T) {
	for _, c := range []struct{ out, want string }{
		{"<?xml version=\"1.0\"?>\n<junoscript xmlns=\"http://xml.juniper.net/xnm/1.1/xnm\">", "greeting"},
		{"<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"></hello>", "greeting"},
		{"xml-mode\n^\nunknown command.\nuser@srx1> ", "refused"},
		{"user@srx1> ", "not observed"},
	} {
		if got := l58EntryCell(c.out); got != c.want {
			t.Errorf("%q: %s, want %s", c.out, got, c.want)
		}
	}
}

// `save` is proven by any candidate the control ran and the deny refused;
// a control that refused every candidate leaves it unproven, never absent.
func TestL58Save(t *testing.T) {
	a, b := junosL58Saves[0], junosL58Saves[1]
	if v, by := l58Save(map[string]string{a: "refused", b: "ran"}, map[string]string{a: "refused", b: "refused"},
		nil); v != "proven" || by != b {
		t.Errorf("the second candidate: %s %q", v, by)
	}
	if v, _ := l58Save(map[string]string{a: "refused", b: "refused"}, map[string]string{a: "refused", b: "refused"},
		map[string]string{a: "unknown command", b: "unknown command"}); v != "unproven" {
		t.Errorf("the control ran none: %s", v)
	}
	if v, _ := l58Save(map[string]string{a: "ran", b: "ran"}, map[string]string{a: "ran", b: "not observed"},
		nil); v != "unproven" {
		t.Errorf("the deny refused none: %s", v)
	}
}
```

  Then `tests/lab/junos_baseline_test.go` (pre-flight: `go vet -tags lab` clean and the two unit
  tests pass against it):

```go
//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
)

// TestL58JunosBaselineWords measures the two baseline words set 1.2.0's
// readonly reply rests on (spec §15 L58; decision 44 ruling 10). `save`: L26b
// proved it a keyword on vJunos-router and left it unproven on vSRX, whose
// control took the hidden `save dhcp-security-snoop` and refused the file
// name after it; each candidate below is typed in both sessions, and the word
// is proven where the control ran one with `| count`'s evidence and the deny
// refused that one, its caret under `save` (l26bVerdict). `xml-mode`: L26c
// measured `xml-mode netconf` refused under a deny of `junoscript`; bare
// `xml-mode`, the Junos XML protocol, was not typed. Both are typed under the
// factored alternative set 1.2.0 renders, ` *(save|junoscript)( .*)? *(\|.*)?`,
// against a control with the same class and no deny.
//
// Positive controls are enforced: a session that does not open, `show
// version` not running in either CLI session, or the control not reaching
// the XML greeting for either entry is INVALID, before any note is written.
// `save` unproven, or an entry reached under the deny, is a result: the note
// records it and Task 3's gates stop the plan.

var junosL58Class = []string{
	"set system login class p49-l58-view permissions view",
	"set system login user p49-l58-view class p49-l58-view",
}

var junosL58Delete = []string{"delete system login user p49-l58-view", "delete system login class p49-l58-view"}

// junosL58Deny is the factored alternative naming both words, as set 1.2.0
// renders a reply's `word **` denies.
const junosL58Deny = `^ *(save|junoscript)( .*)? *(\|.*)?$`

// junosL58Saves are the `save` commands typed: vJunos-router's L26b probe,
// and the hidden command vSRX took, without the file name it refused.
var junosL58Saves = []string{
	"save dhcp-security-snoop /var/tmp/p49-l58.snoop | count",
	"save dhcp-security-snoop | count",
}

// junosL58Entries are the commands that turn a CLI session into an XML
// session: bare `xml-mode` greets with `<junoscript`, `xml-mode netconf` with
// a NETCONF `<hello>`.
var junosL58Entries = []string{"xml-mode", "xml-mode netconf need-trailer"}

// l58EntryCell is a CLI's answer to an entry: greeting (`<junoscript` or a
// NETCONF hello, and no refusal), refused, or not observed.
func l58EntryCell(out string) string {
	greeted := strings.Contains(out, "<junoscript") || strings.Contains(out, "</hello>")
	refused := containsAny(strings.ToLower(out), junosL26cRefusal)
	switch {
	case greeted && !refused:
		return "greeting"
	case refused && !greeted:
		return "refused"
	}
	return "not observed"
}

// l58Save is `save`'s verdict on one image from each candidate's control
// and deny cells: proven where some candidate is (l26bVerdict, offered:
// `save` is never absent here, since the image took it in L26b), and the
// candidate that proved it.
func l58Save(control, deny map[string]string, controlOuts map[string]string) (string, string) {
	for _, cmd := range junosL58Saves {
		if l26bVerdict(control[cmd], deny[cmd], true, controlOuts[cmd]) == "proven" {
			return "proven", cmd
		}
	}
	return "unproven", ""
}

// l58Entry types entry in a fresh session under attrs and reads the greeting
// or the refusal; the session is XML afterwards, so it is closed.
func (l *lab) l58Entry(t *testing.T, name, attrs, entry string) (string, string) {
	t.Helper()
	c, r, _ := l.junosLogin(t, name, attrs)
	if c == nil {
		t.Fatalf("INVALID: %s: the session did not open: %s", name, r.loginErr)
	}
	defer c.Close()
	from := len(c.out.String())
	if err := c.send(entry); err != nil {
		return "not observed", err.Error()
	}
	out, err := c.expectFrom(from, junosPer, "<junoscript", "</hello>", junosOpPrompt)
	if err == nil && !strings.Contains(out, "<junoscript") && !strings.Contains(out, "</hello>") {
		junosSettle(c)
		out = c.out.String()[from:]
	}
	if err != nil {
		return "not observed", out
	}
	return l58EntryCell(out), out
}

func TestL58JunosBaselineWords(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L58")
		defer stop()

		// The completions after each word, over break-glass, before any token.
		listings := map[string]string{}
		func() {
			c, err := l.junosCLI(breakglassUser, breakglassPassword)
			if err != nil {
				t.Fatalf("INVALID: no break-glass CLI: %v", err)
			}
			defer c.Close()
			if err := junosPrepare(c); err != nil {
				t.Fatalf("INVALID: set cli screen-length 0 not observed within %s: %v", junosPer, err)
			}
			w := &keywordWalk{c: c, logf: t.Logf, prompt: "@" + junosHost + "> "}
			for _, p := range []string{"save", "xml-mode"} {
				words, ph, err := w.completion(p)
				listings[p] = fmt.Sprintf("%s (placeholder %v, err %v)", strings.Join(words, " "), ph, err)
			}
		}()

		commit := l.junosConfigureAdmin(t, junosL58Class)
		defer l.junosConfigureAdmin(t, junosL58Delete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()

		const class = `"local-user-name=p49-l58-view"`
		quote := func(re string) string { return strings.ReplaceAll(re, `\`, `\\`) }
		control := "[" + class + "]"
		deny := "[" + class + `, "deny-commands=` + quote(junosL58Deny) + `"]`
		cmds := append([]string{"show version | count"}, junosL58Saves...)

		cells := map[string]map[string]string{"control": {}, "deny": {}}
		outs := map[string]map[string]string{}
		for _, s := range []struct{ name, attrs string }{{"control", control}, {"deny", deny}} {
			o, _, auth := l.l26bSession(t, s.name, s.attrs, cmds, false)
			// l26bSession says why with t.Errorf; nothing is written after it.
			if t.Failed() {
				t.Fatalf("INVALID: %s: the session did not open, or a command was not observed within %s", s.name, junosPer)
			}
			outs[s.name] = o
			outs[s.name]["auth"] = auth
			promptLen := len(o[l26bUserKey] + "@" + junosHost + "> ")
			cells[s.name]["show version | count"] = l26bCell(o["show version | count"], nil)
			for _, cmd := range junosL58Saves {
				if s.name == "control" {
					cells[s.name][cmd] = l26bCell(o[cmd], nil)
				} else {
					cells[s.name][cmd] = l26bDenyCell(o[cmd], "save", nil, promptLen)
				}
			}
			if cells[s.name]["show version | count"] != "ran" {
				t.Fatalf("INVALID: %s: `show version | count` %s, so the session measures nothing",
					s.name, cells[s.name]["show version | count"])
			}
		}
		save, by := l58Save(cells["control"], cells["deny"], outs["control"])

		entryOuts := map[string]string{}
		for _, e := range junosL58Entries {
			for _, s := range []struct{ name, attrs string }{{"control", control}, {"deny", deny}} {
				cell, out := l.l58Entry(t, s.name+" "+e, s.attrs, e)
				cells[s.name][e], entryOuts[s.name+" "+e] = cell, out
			}
			if cells["control"][e] != "greeting" {
				t.Fatalf("INVALID: the control's `%s` %s, so the deny's answer is not isolated", e, cells["control"][e])
			}
		}

		var b strings.Builder
		fmt.Fprintf(&b, "The class was committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit), strings.Join(junosL58Class, "\n"))
		fmt.Fprintf(&b, "Completion over break-glass: `save ?`: %s; `xml-mode ?`: %s.\n\n", listings["save"], listings["xml-mode"])
		fmt.Fprintf(&b, "| session | reply |\n|---|---|\n| control | `%s` |\n| deny | `%s` |\n\n", tableCell(control), tableCell(deny))
		b.WriteString("| probe | control | deny |\n|---|---|---|\n")
		for _, p := range append(cmds, junosL58Entries...) {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", tableCell(p), cells["control"][p], cells["deny"][p])
		}
		fmt.Fprintf(&b, "\n### Gates\n\n- **G3** `save`: **%s**", save)
		if by != "" {
			fmt.Fprintf(&b, " (by `%s`)", tableCell(by))
		}
		closed := cells["deny"]["xml-mode"] == "refused" && cells["deny"]["xml-mode netconf need-trailer"] == "refused"
		fmt.Fprintf(&b, ".\n- **G4** `xml-mode` under the `junoscript` deny: bare %s, `netconf` %s: **%s**.\n",
			cells["deny"]["xml-mode"], cells["deny"]["xml-mode netconf need-trailer"],
			map[bool]string{true: "closed", false: "not closed"}[closed])
		b.WriteString("\n### Outputs\n")
		for _, s := range []string{"control", "deny"} {
			fmt.Fprintf(&b, "\n#### %s, user `%s`\n\n```\n%s\n```\n", s, outs[s][l26bUserKey], outs[s]["auth"])
			for _, p := range cmds {
				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", tableCell(p), outs[s][p])
			}
			for _, e := range junosL58Entries {
				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", e, entryOuts[s+" "+e])
			}
		}
		l.result(t, "L58", "Whether `save` is a keyword to deny-commands, and whether bare `xml-mode` and `xml-mode "+
			"netconf` are refused, under set 1.2.0's factored deny naming `save` and `junoscript`, each against a "+
			"control with the same class and no deny (spec §15 L58; decision 44 ruling 10).", b.String())
	})
}
```

- [ ] **Step 5: Run the unit tests and vet the lab package**

Run: `go test -tags lab ./tests/lab/ -run 'TestEntryVerdict|TestOpScriptCell|TestScpCell|TestL58EntryCell|TestL58Save' -count=1 && go vet -tags lab ./tests/lab/ && make lab-unit`
Expected: PASS. (A helper this task names that does not exist under that name — `yesNo`,
`l26cCLICell`, `l26cReached`, `jsdRun` — is in `tests/lab` today; `grep -n 'func yesNo\|func
l26cCLICell\|func l26cReached\|func jsdRun' tests/lab/*.go` shows each.)

- [ ] **Step 6: Commit**

```bash
git add tests/lab/junos_entry_test.go tests/lab/junos_entry_unit_test.go tests/lab/junos_groups_test.go \
  tests/lab/junos_baseline_test.go tests/lab/junos_baseline_unit_test.go
git commit -m "test(lab): L26c entry cells, L57 groups and L58 baseline words harness

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Lab run — the entry cells, L57 and L58, before any code; the gates

**Files:**
- Create (by the run): `tests/lab/results/L26c-entries-juniper_vjunos-router.md`,
  `…-juniper_vsrx.md`; `L26c-scripts-juniper_*.md`; `L57-juniper_*.md`; `L58-juniper_*.md`;
  `tests/lab/evidence/L26c-entries-*.pcap`, `L26c-scripts-*.pcap`, `L57-*.pcap`, `L58-*.pcap`
  (redacted); `internal/platform/testdata/l57-juniper_vjunos-router.set`, `l57-juniper_vsrx.set`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (the gated words of decision 44 rulings
  2 and 6, and §8's "Management services"; L58's row, bullet and "provisional on L58")

**Interfaces:** Produces the gates later tasks read: **G1** (does `op` go on set 1.2.0's
`rpc_entry_denies`?) and **G2** (does `rest` stay a services finding under 1.2.0?), each in the
`L26c-scripts` note's "Gates" section; **G3** (is `save` a keyword on both images?) and **G4**
(is bare `xml-mode` and `xml-mode netconf` refused under the `junoscript` deny?) in the `L58`
notes' "Gates"; and the L57 fixtures Task 7's test reads.

Arm the stall watchdog before the run (lab-run watchdog rule). The lab is single-occupant. If the
run is in a worktree, copy `tests/lab/captures/*` to the main checkout before removing it.

- [ ] **Step 1: Run each test in its own invocation, per platform** (the seeded pool is 16 per
  process):

```bash
make build
for t in TestL26cEntryNetconf TestL26cEntryScripts TestL57JunosGroups TestL58JunosBaselineWords; do
  for p in juniper_vjunos-router juniper_vsrx; do
    PORT49_LAB_PLATFORMS=$p go test -tags lab ./tests/lab/ -run "^$t\$" -count=1 -v -timeout 90m || break 2
  done
done
make evidence
```

Expected: every run PASS, eight notes written, two fixtures written. An `INVALID:` failure writes
no note: fix the harness (a control that cannot reach is a harness or image fault) and rerun. A
`STOP:` failure: stop and report to the controller with the note's table; do not start Task 4.

- [ ] **Step 2: Read the gates** from `tests/lab/results/L26c-scripts-juniper_*.md`, "Gates":
  - **G1** (controller ruling 4): if either image says `op` "goes on set 1.2.0's list" (W
    reached an RPC through `op url`), Task 4's list is `["junoscript **", "op **"]`; otherwise
    `["junoscript **"]`. The run cannot end with the op cell undecided: that is INVALID.
  - **G2** (controller ruling 1): if both images say REST is "closed by the junoscript deny",
    Task 7 drops `rest` from `rpcPastEntryDeny`; otherwise, "not measured" included, it stays.
  - From `L57-juniper_*.md`: which inherited form shows `p49g-tip` (if only `| display
    inheritance | display set` does, Task 7's `ConfigCapture` is that order); whether nesting
    committed and was expanded (if it committed and `nested` is "no" in the inherited forms, Task
    7 sets `nestedApplies = false`); whether `p49g-excepted` is absent under p49-remote (if it
    is present, Junos ignores the except, and Task 7's `appliesAt` must not honour
    `apply-groups-except`; report that to the controller).
  - From the same notes: whether the inherited form prints `set apply-groups` lines. Task 7
    reads where a group applies from them. If the inherited form prints none, STOP and report to
    the controller before Task 7: naming the group behind an expanded line then needs another
    reading (the group statements whose path matches it), and an `apply-groups` line becomes
    itself the sign of a capture taken without `display inheritance`.
  - "group permission beside own": if `yes`, Junos adds a group's `permissions` beside a class's
    own, and Task 7's naming of such a group at its own line is what the device does; if `no`,
    the local leaf-list stands, and the finding is still kept (Ryan's ruling names a group that
    adds a permission to a template whether or not the template's own value wins today). Record
    which in the roadmap's as-built.
  - From `L58-juniper_*.md`, "Gates" (owner's ruling 4):
    - **G3** `save`: if both images say **proven**, Task 4 ships set 1.2.0's keyword tree with
      `save` at the root. If either says unproven, STOP and report to the controller with both
      notes' tables before Task 4: the readonly then still carries an unprovable `save **` and
      fails closed under 1.2.0, against the owner's ruling, and Task 5b's shipped tests would
      assert what the set cannot do.
    - **G4** `xml-mode`: if both images say **closed** (bare `xml-mode` and `xml-mode netconf`
      refused under the deny, the control greeted), Task 5b's `closedByEntry` stands. If either
      says not closed, STOP and report: sending the baseline's `xml-mode **` as nothing would let
      that form run, which is wider than port49.

- [ ] **Step 3: Write the gated words into the spec.** In decision 44 ruling 2 replace "If an
  `op url` script reaches … `["junoscript **", "op **"]`." with the measured sentence (e.g.
  "Measured 2026-10-1x (`L26c-scripts-juniper_*.md`): under the `junoscript` deny `op url` …; set
  1.2.0's list is `[…]`."). In ruling 6 and §8's "Management services", replace the `rest`
  clause the same way. Leave "*provisional on L26c*" in place: the row closes in Task 9.

- [ ] **Step 3b: Close L58** (CLAUDE.md rule 3), where G3 and G4 passed on both images: edit its
  Status to `closed — measured <date>; tests/lab/results/L58-juniper_vjunos-router.md,
  L58-juniper_vsrx.md`, then what each image showed (`save` proven by which candidate; bare
  `xml-mode` and `xml-mode netconf` refused under the deny, the control greeted). Rewrite its
  detail bullet to the observation. In decision 44's head remove "ruling 10's `save` and bare
  `xml-mode` are *provisional on L58* until plan 9b1's Task 3 closes it", and in §8's readonly
  paragraph replace each "*provisional on L58*" with the citation `L58-juniper_*.md`. If a result contradicts
  a sentence of §8 or decision 44, fix the sentence, cite the note, and say so in the commit
  (rule 4).

- [ ] **Step 4: Commit the notes, evidence, fixtures and spec words**

```bash
git add tests/lab/results/L26c-entries-juniper_*.md tests/lab/results/L26c-scripts-juniper_*.md \
  tests/lab/results/L57-juniper_*.md tests/lab/results/L58-juniper_*.md tests/lab/evidence/L26c-entries-* \
  tests/lab/evidence/L26c-scripts-* tests/lab/evidence/L57-* tests/lab/evidence/L58-* \
  internal/platform/testdata/l57-*.set
git commit -m "test(lab): L26c entry points, L57 groups and L58 baseline words on vJunos-router and vSRX

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L58; decision 44's gated words from Task 3

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Set 1.2.0 and the `rpc_entry_denies` adapter key

**Files:**
- Modify: `internal/platform/dialect.go` (the `Dialect` struct after `CeilingBits`; the
  `BaselineBit` const block; `clone` ~line 386; `generics` ~line 290)
- Modify: `internal/platform/adapter.go` (`Spec` struct after `LocalUserNames`, line 52; `Over`
  after the `LocalUserNames` merge, ~line 113; `SpecOf` after `LocalUserNames`, ~line 690;
  `validateProjection`, the not-projected key list ~line 806 and after the `carve_outs` loop
  ~line 880)
- Modify: `internal/platform/set.go:16` (`DefaultSet`)
- Modify: `internal/policy/load.go` (the not-projected key list ~line 484; `keepsProjection`
  after the `carve_outs` loop ~line 696)
- Create: `platforms/1.2.0/arista_eos.yaml`, `cisco_iosxe.yaml`, `cisco_nxos.yaml` (copies of
  1.1.0's), `platforms/1.2.0/juniper_junos.yaml` (1.1.0's, edited below),
  `platforms/keywords/1.2.0/juniper_junos.yaml` (1.1.0's with `save` at the root, G3)
- Test: `internal/platform/adapter_test.go`, `internal/platform/keywords_test.go`,
  `internal/policy/platforms_test.go`

**Interfaces:**
- Consumes: G1 and G3 from Task 3.
- Produces: `platform.Dialect.RPCEntryDenies []string`; `platform.Spec.RPCEntryDenies *[]string`
  (yaml `rpc_entry_denies`); `const platform.RPCEntryRole = "rpc_entry"`;
  `platform.DefaultSet == "1.2.0"`.

- [ ] **Step 1: Write the failing tests.** In `internal/platform/adapter_test.go`:

```go
// Set 1.2.0 is 1.1.0 and one key: juniper_junos's entry deny (decision 44
// ruling 5). Every other platform, and every other Junos key, is 1.1.0's, so
// the pin move changes one gated key and nothing else.
func TestSet120IsSet110AndTheEntryDeny(t *testing.T) {
	was, ok1 := Set("1.1.0")
	is, ok2 := Set("1.2.0")
	if !ok1 || !ok2 || DefaultSet != "1.2.0" {
		t.Fatalf("sets: %v %v, default %s", ok1, ok2, DefaultSet)
	}
	for name, d := range was {
		got := is[name]
		if name == "juniper_junos" {
			if len(got.RPCEntryDenies) == 0 || got.RPCEntryDenies[0] != "junoscript **" {
				t.Errorf("juniper_junos rpc_entry_denies: %q", got.RPCEntryDenies)
			}
			got.RPCEntryDenies = nil
		}
		if !reflect.DeepEqual(SpecOf(d), SpecOf(got)) {
			t.Errorf("%s differs between 1.1.0 and 1.2.0 beyond rpc_entry_denies", name)
		}
	}
	if len(was["juniper_junos"].RPCEntryDenies) != 0 {
		t.Error("set 1.1.0 was edited: it sends no entry deny")
	}
	if KeywordsFor("1.2.0", "juniper_junos") == nil {
		t.Error("set 1.2.0 ships no keyword tree")
	}
}

// rpc_entry_denies is a projected platform's, words and a trailing `**`.
func TestRPCEntryDeniesIsValidated(t *testing.T) {
	d := junosProjected(BitDeliveryUserPermissions)
	d.RPCEntryDenies = []string{"junoscript **"}
	if err := Validate("juniper_junos", d); err != nil {
		t.Fatalf("valid: %v", err)
	}
	d.RPCEntryDenies = []string{"/xml.*/ **"}
	if err := Validate("juniper_junos", d); err == nil || !strings.Contains(err.Error(), "rpc_entry_denies") {
		t.Errorf("a regex term: %v", err)
	}
	eos, _ := DialectFor("arista_eos")
	eos.RPCEntryDenies = []string{"junoscript **"}
	if err := Validate("arista_eos", eos); err == nil || !strings.Contains(err.Error(), "command_projection") {
		t.Errorf("not projected: %v", err)
	}
}
```

  In `internal/platform/keywords_test.go` (G3 passed; it fails until Step 5 edits the tree):

```go
// Set 1.2.0's Junos tree is 1.1.0's and `save` at the root, which L58 proved
// on both images (tests/lab/results/L58-juniper_*.md; decision 44 ruling 10):
// nothing else moves.
func TestTheSet120JunosTreeIsSet110AndSave(t *testing.T) {
	was, err1 := fs.ReadFile(platforms.Keywords, "keywords/1.1.0/juniper_junos.yaml")
	is, err2 := fs.ReadFile(platforms.Keywords, "keywords/1.2.0/juniper_junos.yaml")
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	want := strings.Replace(string(was), `"restart", "scp"`, `"restart", "save", "scp"`, 1)
	if want == string(was) || string(is) != want {
		t.Fatal("platforms/keywords/1.2.0/juniper_junos.yaml is not 1.1.0's with `save` at the root")
	}
	if !KeywordsFor("1.2.0", "juniper_junos").Keyword(nil, "save") || KeywordsFor("1.1.0", "juniper_junos").Keyword(nil, "save") {
		t.Error("save is a keyword in 1.2.0's tree only")
	}
}
```

  In `internal/policy/platforms_test.go`, the block rule (find a test there that loads a policy
  with a `platforms:` block over a pinned set and copy its env setup; the body below is the
  policy text):

```go
// A block may drop set 1.2.0's entry deny and never add one the set did not
// measure (decision 44 ruling 5).
func TestABlockMayDropTheEntryDenyNotAddOne(t *testing.T) {
	head := "platform_set: 1.2.0\nplatforms:\n  juniper_junos:\n"
	for _, c := range []struct {
		block string
		ok    bool
	}{
		{"    rpc_entry_denies: []\n", true},
		{"    rpc_entry_denies: [\"junoscript **\"]\n", true},
		{"    rpc_entry_denies: [\"junoscript **\", \"start **\"]\n", false},
	} {
		_, err := Parse([]byte(head+c.block+scopeOK+"roles:\n  - {name: r, privilege: readonly, permit: [\"show **\"]}\n"+
			subjOK+grantOK), env())
		if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), "rpc_entry_denies") {
			t.Errorf("%q: %v", c.block, err)
		}
	}
	_, err := Parse([]byte("platform_set: 1.1.0\nplatforms:\n  arista_eos:\n    rpc_entry_denies: [\"x **\"]\n"+
		scopeOK+"roles:\n  - {name: r, permit: [\"show **\"]}\n"+subjOK+grantOK), env())
	if err == nil || !strings.Contains(err.Error(), "rpc_entry_denies") {
		t.Errorf("a platform the set does not project: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/ -run 'Set120|RPCEntryDenies|EntryDenyNotAddOne' -count=1`
Expected: FAIL to compile (`RPCEntryDenies` undefined).

- [ ] **Step 3: The field, the key, the role.** In `internal/platform/dialect.go`, after
  `CeilingBits`:

```go
	// RPCEntryDenies are the denies a reply adds where a deny is the only
	// guard beneath a sent bit or the baseline: a wire deny binds no native
	// RPC (L12-netconf), and these close the CLI's ways into one, per user
	// (tests/lab/results/L26c-junoscript-juniper_*.md; decision 44). Set 1.2.0's
	// juniper_junos carries `junoscript **`; empty, the projection fails such a
	// composition closed (set 1.1.0, option C). A block may drop one and never
	// add one (spec §8).
	RPCEntryDenies []string
```

  Beside `BaselineBit`:

```go
// RPCEntryRole is the role of a deny the projection adds from RPCEntryDenies:
// none of the grant's, as BaselineBit's is none (decision 44).
const RPCEntryRole = "rpc_entry"
```

  In `clone`, after `d.CarveOuts = cloneLists(d.CarveOuts)`:
  `d.RPCEntryDenies = slices.Clone(d.RPCEntryDenies)`.
  In `generics`, after the `"1.1.0"` entry:

```go
	// 1.2.0 changes no generic value: the entry deny is juniper_junos's.
	"1.2.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert, EnableUsername: EnablePrincipal},
```

  In `internal/platform/adapter.go`, the `Spec` field after `LocalUserNames`:
  `RPCEntryDenies *[]string `yaml:"rpc_entry_denies,omitempty"``. In `Over`, after the
  `LocalUserNames` merge:

```go
	if s.RPCEntryDenies != nil {
		d.RPCEntryDenies = append([]string{}, *s.RPCEntryDenies...)
	}
```

  In `SpecOf`, after `LocalUserNames`:

```go
	if d.RPCEntryDenies != nil {
		s.RPCEntryDenies = &d.RPCEntryDenies
	}
```

  In `validateProjection`, add `{"rpc_entry_denies", d.RPCEntryDenies != nil}` to the
  not-projected list, and after the `carve_outs` loop:

```go
	for i, rule := range d.RPCEntryDenies {
		terms, err := engine.ParseRule(rule)
		if err != nil {
			return fmt.Errorf("%s[%d]: %w", field("rpc_entry_denies"), i, err)
		}
		for j, t := range terms {
			if t.Kind == engine.Class || t.Kind == engine.Regex {
				return fmt.Errorf("%s[%d]: term %d: an entry deny is words and `**`", field("rpc_entry_denies"), i, j+1)
			}
		}
	}
```

  In `internal/platform/set.go`: `const DefaultSet = "1.2.0"`.

- [ ] **Step 4: The block rules.** In `internal/policy/load.go`, add
  `{"rpc_entry_denies", b.Spec.RPCEntryDenies != nil}` to the list refused where the pinned set
  does not project the platform. In `keepsProjection`, after the `carve_outs` loop:

```go
	for i, rule := range d.RPCEntryDenies {
		if !slices.Contains(ref.RPCEntryDenies, rule) {
			return fmt.Errorf("%s.rpc_entry_denies[%d]: platform set %s does not measure this deny closing an RPC "+
				"entry point on %s; a block may drop one, not add one (spec §8, §15 L26c)", at, i, version, shippedAs)
		}
	}
```

- [ ] **Step 5: Ship set 1.2.0.**

```bash
mkdir -p platforms/1.2.0 platforms/keywords/1.2.0
cp platforms/1.1.0/arista_eos.yaml platforms/1.1.0/cisco_iosxe.yaml platforms/1.1.0/cisco_nxos.yaml \
   platforms/1.1.0/juniper_junos.yaml platforms/1.2.0/
cp platforms/keywords/1.1.0/juniper_junos.yaml platforms/keywords/1.2.0/
```

  In `platforms/1.2.0/juniper_junos.yaml`, change the first line's set wording if it names 1.1.0,
  and replace the comment paragraph beginning `# A wire deny binds the CLI and a `<command>` RPC`
  through `# beneath a sent bit is a deny.` with:

```yaml
    # A wire deny binds the CLI and a `<command>` RPC, never a native RPC
    # (tests/lab/results/L12-netconf-juniper_*.md, L26c-juniper_*.md), and a CLI
    # session reaches native RPCs through `xml-mode`. A deny of `junoscript`
    # closes that entry for the session whose reply carries it, and its NETCONF
    # on port 830, the control reaching both (L26c-junoscript-juniper_*.md; the
    # rest of L26c: L26c-entries-juniper_*.md, L26c-scripts-juniper_*.md). So
    # where a deny is the only guard beneath a sent bit or the baseline, the
    # reply adds rpc_entry_denies and keeps the capability shape; that subject
    # has no NETCONF. `port49 devices check-config` fails J-Web
    # (`web-management`) and JET/gRPC/gNMI (`extension-service`), which no
    # measurement shows the deny closes.
```

  And after `bit_delivery: user_permissions`, add (with G1's list):

```yaml
    # Set 1.2.0: what the reply denies beside a deny beneath its bits, to close
    # the RPC entry points per user (decision 44). A block may drop one, never
    # add one.
    rpc_entry_denies: ["junoscript **"]
```

  If G1 put `op` on the list, the value is `["junoscript **", "op **"]` and the comment names
  `L26c-scripts-juniper_*.md`'s op row.

  In `platforms/keywords/1.2.0/juniper_junos.yaml`, the root node's words gain `save` between
  `restart` and `scp` (G3; one edit, no other byte moves: `TestTheSet120JunosTreeIsSet110AndSave`
  holds it). The tree carries no comment; L58's notes and that test are its provenance, as
  `TestTheShippedJunosTreeIsTheLabs` is 1.1.0's.

- [ ] **Step 6: Run the new tests, then the whole suite**

Run: `go test ./internal/platform/ ./internal/policy/ -run 'Set120|RPCEntryDenies|EntryDenyNotAddOne' -count=1 && make test`
Expected: the three PASS. In `make test`, a test that read `DefaultSet` and asserted a value only
1.1.0 has now fails: pin it to `1.1.0` explicitly (`--set 1.1.0`, `platform.Set("1.1.0")`), never
loosen the assertion. Three in `internal/platform/adapter_test.go` are the frozen-set guards and
take an entry, not a pin: add `shipped120` (`shipped110` with `juniper_junos.RPCEntryDenies =
[]string{"junoscript **"}`, plus `op **` where G1 put it there, built as `shipped110` is) and put
it in `released` as `"1.2.0"`; add `"1.2.0"` to `releasedGeneric` (the same value as 1.1.0's);
point `TestTheDefaultSetValueForValue` at `shipped120`. `released["1.1.0"]` stays as it is: that
it still passes is the proof 1.1.0 was not edited. `TestSpecOfRoundTrips` counts Dialect fields
against Spec keys; both gain one. With `"1.2.0"` in `released`,
`TestReleasedKeywordTreesAreFrozen` needs the tree's entry in `releasedKeywords` (`keywords_test.go`):
`"1.2.0/juniper_junos": "2017ca9e10d5e3e7c53fb78cd65a5480aa91387212cef7a6924aa87110912688"`, the
sha256 of 1.1.0's tree with `save` added as Step 5 says (pre-flight computed it; `sha256sum
platforms/keywords/1.2.0/juniper_junos.yaml` must print it). `TestEmbeddedSetsLoad` lists the sets:
add `"1.2.0"`. In `cmd/port49/platform_test.go`, `TestPlatformShowAndExportPrintTheAdapter` and
`TestPlatformExportClasses` read the default set's label (`platform set 1.1.0`): the default is
what they test, so their wants become `1.2.0`. Pre-flight saw exactly these fail with this step's
code, and nothing else. Repeat until `make test` passes.

- [ ] **Step 7: Commit**

```bash
git add internal/platform internal/policy platforms
git commit -m "feat: platform set 1.2.0 with juniper_junos rpc_entry_denies

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: The projection closes the RPC entry where it can

**Files:**
- Modify: `internal/projection/project.go` (the `Result` struct and `Clone`; `capability`'s
  `!g.in.Facts.DenyBindsRPCs` block, lines ~639–651; `rpcEntries` line 684 and its comment;
  `rpcWhy` lines 693–698; `rpcCarves`'s comment; `JunosFacts`'s comment lines 52–66)
- Modify: `internal/projection/ere.go` (the `DenyBindsRPCs` field comment, lines 40–45)
- Test: `internal/projection/project_guard_test.go`

**Interfaces:**
- Consumes: `platform.Dialect.RPCEntryDenies`, `platform.RPCEntryRole` (Task 4).
- Produces: `func (r Result) EntryDenied() bool`; `func (r Result) NetconfClosed() bool`;
  `Result.ConfigurationBeneath []engine.Rule`.

- [ ] **Step 1: Write the failing tests** in `internal/projection/project_guard_test.go`:

```go
// entry is in with set 1.2.0's entry deny on its dialect.
func entry(in Input, denies ...string) Input {
	if len(denies) == 0 {
		denies = []string{"junoscript **"}
	}
	in.Dialect.RPCEntryDenies = denies
	return in
}

func entryDenied(res Result, rule string) bool {
	return slices.ContainsFunc(res.Denies, func(d engine.Rule) bool {
		return d.Rule == rule && d.Role == platform.RPCEntryRole
	})
}

// Where a deny is the only guard beneath a sent bit or the baseline, a dialect
// with RPCEntryDenies keeps the capability shape and adds them; the device
// then refuses junoscript, which is narrower than port49, never wider. With no
// entry deny the answer is set 1.1.0's, unchanged (decision 44 ruling 1).
func TestAnEntryDenyClosesRPCBeneathADeny(t *testing.T) {
	admin := []engine.Rule{permit("**"), deny("request security **")}
	res, err := Project(entry(measuredInput(platform.BitDeliveryUserPermissions, "admin", JunosFacts, admin...)))
	if err != nil || res.Shape != ShapeCapability || !entryDenied(res, "junoscript **") || !res.EntryDenied() ||
		!res.NetconfClosed() {
		t.Fatalf("admin: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	if !strings.Contains(res.Attributes[len(res.Attributes)-1], "junoscript( .*)?") {
		t.Errorf("the entry deny is on the wire: %q", res.Attributes)
	}
	if res.Device([]string{"junoscript", "netconf"}) || res.Device([]string{"request", "security", "pki"}) {
		t.Error("the device runs what the reply denies")
	}
	if res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "admin", JunosFacts, admin...)); err != nil ||
		res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape {
		t.Fatalf("set 1.1.0, unchanged: %s %+v %v", res.Shape, res.Refusal, err)
	}
	// The baseline's deny: operator, everything its bits and the baseline
	// reach but `start`.
	ops := []engine.Rule{permit("show **"), permit("clear **"), permit("request **"), permit("test **")}
	for _, w := range []string{"help", "quit", "exit", "set", "file", "load", "op", "save", "scp", "ping",
		"traceroute", "ssh", "telnet", "mtrace", "probe", "monitor"} {
		ops = append(ops, permit(w+" **"))
	}
	res, err = Project(entry(measuredInput(platform.BitDeliveryUserPermissions, "operator", JunosFacts, ops...)))
	if err != nil || res.Shape != ShapeCapability || !entryDenied(res, "junoscript **") ||
		!slices.ContainsFunc(res.Denies, func(d engine.Rule) bool { return d.Rule == "start **" }) {
		t.Fatalf("baseline: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	// No deny beneath a sent bit: no entry deny, NETCONF stays.
	res, err = Project(entry(measuredInput(platform.BitDeliveryUserPermissions, "operator", JunosFacts,
		append(ops, permit("start **"))...)))
	if err != nil || res.EntryDenied() || res.NetconfClosed() {
		t.Fatalf("no deny beneath: %s %q %v", res.Shape, res.Attributes, err)
	}
}

// An allow the reply must send that meets an entry deny beats it on the device
// (L11): the entry is not closed, and the answer is set 1.1.0's. The grant
// holds every baseline word but `op`, so its only baseline deny is `op **`
// and the reply fits; `op url **` beneath that deny goes out as an allow. With
// `op **` on the entry list the allow meets it and the composition falls back;
// with `junoscript **` alone it keeps the capability shape (pre-flight: the
// earlier form of this test passed with the allow check removed).
func TestAnAllowMeetingTheEntryDenyKeepsTheFallback(t *testing.T) {
	rules := []engine.Rule{permit("show **"), permit("clear **"), permit("request **"), permit("test **"),
		permit("op url **"), deny("show configuration **")}
	for _, w := range []string{"help", "quit", "exit", "set", "file", "load", "save", "scp", "ping", "traceroute", "ssh",
		"telnet", "mtrace", "probe", "monitor"} {
		rules = append(rules, permit(w+" **"))
	}
	in := func(denies ...string) Input {
		in := entry(measuredInput(platform.BitDeliveryUserPermissions, "operator", JunosFacts, rules...), denies...)
		in.Keywords = keywordTree(append(reachOf(in.Dialect), "op url **")...)
		return in
	}
	res, err := Project(in("junoscript **"))
	if err != nil || res.Shape != ShapeCapability || !res.EntryDenied() ||
		!slices.ContainsFunc(res.Allows, func(a engine.Rule) bool { return a.Rule == "op url **" }) {
		t.Fatalf("the control: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	res, err = Project(in("junoscript **", "op **"))
	if err != nil || res.EntryDenied() || res.Shape == ShapeCapability {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}

// The entry deny counts toward RFC 8907's 255 bytes: a capability shape it
// pushes over is never sent truncated. Eight keyword denies under `show **`
// render 251 bytes of deny-commands, and the entry deny's alternative 28
// more (measured in pre-flight; `measured`'s case classes would render 473);
// the narrow shape cannot carry a deny beneath `show **`, so the subject gets
// the fail-closed reply as an overflow (spec §8, "Generator constraints").
func TestTheEntryDenyCountsTowardTheBudget(t *testing.T) {
	rules := []engine.Rule{permit("show **")}
	for _, w := range strings.Fields("alpha bravo charlie delta echo foxtrot golf hotel") {
		rules = append(rules, deny("show "+w+" **"))
	}
	// JunosFacts with a binding deny: the same rendering (lower-case words),
	// and no entry deny, so the arithmetic compares like with like.
	binding := JunosFacts
	binding.DenyBindsRPCs = true
	fits, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", binding, rules...))
	if err != nil || fits.Shape != ShapeCapability {
		t.Fatalf("without the entry deny the reply fits: %s %+v %v", fits.Shape, fits.Refusal, err)
	}
	res, err := Project(entry(input(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, rules...)))
	if err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailOverflow {
		t.Fatalf("over: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	for _, a := range res.Attributes {
		if len(a) > engine.MaxAttribute {
			t.Errorf("%d bytes: %s", len(a), a)
		}
	}
	res, err = Project(entry(input(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, rules[:3]...)))
	if err != nil || res.Shape != ShapeCapability || !res.EntryDenied() {
		t.Fatalf("under: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}

// A deny meeting `show configuration` sent beneath a held view-configuration
// is what policy test warns of (decision 44 ruling 4).
func TestADenyBeneathViewConfigurationIsReported(t *testing.T) {
	in := entry(input(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show **"),
		deny("show configuration **")))
	in.Dialect.Bits["view-configuration"] = []string{"show configuration **", "show log **"}
	in.Keywords = keywordTree("show log **", "show configuration **")
	res, err := Project(in)
	if err != nil || !res.EntryDenied() || len(res.ConfigurationBeneath) != 1 ||
		res.ConfigurationBeneath[0].Rule != "show configuration **" {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Bits, res.ConfigurationBeneath, err)
	}
	c := res.Clone()
	c.ConfigurationBeneath[0].Rule = "x"
	if res.ConfigurationBeneath[0].Rule == "x" {
		t.Error("Clone shares ConfigurationBeneath")
	}
}

// shipped is a composition on set version's juniper_junos, its adapter and
// keyword tree as shipped.
func shipped(version, level string, rules ...engine.Rule) Input {
	set, _ := platform.Set(version)
	d := set["juniper_junos"]
	return Input{Platform: "juniper_junos", Dialect: d, Level: level, Bits: d.CeilingBits[level], Rules: rules,
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}, Facts: JunosFacts,
		Keywords: platform.KeywordsFor(version, "juniper_junos")}
}

// What set 1.2.0's entry deny changes, read from the shipped adapter and
// keyword tree, not a fixture (decision 44 ruling 1): an operator granted
// everything but `show configuration` gets the capability shape with the
// entry deny and the view-configuration warning's rule. Task 5b adds the
// readonly (ruling 10).
func TestTheShippedSetsEntryDeny(t *testing.T) {
	res, err := Project(shipped("1.2.0", "operator", permit("**"), deny("show configuration **")))
	if err != nil || res.Shape != ShapeCapability || !res.EntryDenied() || len(res.ConfigurationBeneath) != 1 {
		t.Fatalf("operator: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}

// junoscript is an RPC entry a narrow allow may not open (decision 44 ruling 3).
func TestJunoscriptIsAnRPCEntry(t *testing.T) {
	g := newGenerator(input(platform.BitDeliveryUserPermissions, "readonly", JunosFacts), nil)
	for _, r := range []string{"junoscript **", "xml-mode netconf", "op url **"} {
		if !g.opensRPC(r) {
			t.Errorf("%s opens no RPC entry", r)
		}
	}
}
```

  And update `TestTheRPCReachRefusalSaysItIsAnAssumption` (rename it
  `TestTheRPCReachRefusalSaysOnlyWhatIsMeasured`): its wants become

```go
	for _, want := range []string{
		"on juniper_junos a wire deny does not bind a native RPC",
		"tests/lab/results/L12-netconf-juniper_*.md",
		"rpc_entry_denies",
		"so port49 fails the composition closed",
	} {
```

  and its overclaim list stays as it is.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/projection/ -run 'EntryDeny|TheEntryDeny|BeneathViewConfiguration|JunoscriptIsAnRPCEntry|RPCReachRefusal|ShippedSets' -count=1`
Expected: FAIL (`EntryDenied` undefined).

- [ ] **Step 3: Implement.** In `Result`, after `Unsent`:

```go
	// ConfigurationBeneath are the grant's sent denies that meet `show
	// configuration` while the session holds view-configuration: the CLI
	// refuses them, but the bit is what grants the configuration, and policy
	// test warns (projection_deny_beneath_view_configuration; decision 44).
	ConfigurationBeneath []engine.Rule
```

  In `Clone`: `r.ConfigurationBeneath = slices.Clone(r.ConfigurationBeneath)`, and in
  `project_test.go`'s `TestCloneCopiesEverySlice` add `ConfigurationBeneath: []engine.Rule{r}` to
  `fresh()` (it fails on any slice field it does not set). After `Clone`:

```go
// EntryDenied reports whether the reply carries the adapter's RPC entry denies
// (decision 44): the subject has no NETCONF there.
func (r Result) EntryDenied() bool {
	return slices.ContainsFunc(r.Denies, func(d engine.Rule) bool { return d.Role == platform.RPCEntryRole })
}

// NetconfClosed reports whether the reply refuses `junoscript` short of the
// fail-closed reply: the entry deny, or the narrow shape's `.*`.
func (r Result) NetconfClosed() bool {
	return r.FailClosed == "" && (r.EntryDenied() || r.Shape == ShapeNarrow)
}
```

  Replace `capability`'s `!g.in.Facts.DenyBindsRPCs` block with:

```go
	if !g.in.Facts.DenyBindsRPCs {
		for _, dn := range res.Denies {
			if b, ok := g.beneath(dn.Rule, bits); ok {
				// The reply's own configuration refusal comes first where
				// render recovers from it by dropping those bits, which may
				// leave the deny beneath none.
				var cr *Refusal
				if err := g.configuration(res); errors.As(err, &cr) && g.recoverable(cr) {
					return Result{}, err
				}
				if more, ok := g.entryDenies(res); ok {
					res.Denies = append(res.Denies, more...)
					res.ConfigurationBeneath = g.configurationBeneath(res)
					return res, nil
				}
				return Result{}, &narrowOnly{why: "a deny beneath a sent bit guards the CLI alone",
					refusal: g.rpcReach(dn, b), beyond: res.Beyond}
			}
		}
	}
	res.ConfigurationBeneath = g.configurationBeneath(res)
	return res, nil
```

  and after `beneath`:

```go
// entryDenies are the adapter's RPC entry denies a reply adds where a deny is
// the only guard beneath a sent bit or the baseline (decision 44): each one
// res does not already send. None where the adapter has none (set 1.1.0), or
// where an allow res sends meets one, since on the device an allow beats a
// deny (L11) and the entry would stay open.
func (g generator) entryDenies(res Result) ([]engine.Rule, bool) {
	if len(g.in.Dialect.RPCEntryDenies) == 0 {
		return nil, false
	}
	var out []engine.Rule
	for _, rule := range g.in.Dialect.RPCEntryDenies {
		if slices.ContainsFunc(res.Allows, func(a engine.Rule) bool { return g.mayMeet(a.Rule, rule) }) {
			return nil, false
		}
		if !slices.ContainsFunc(res.Denies, func(d engine.Rule) bool { return d.Rule == rule }) {
			out = append(out, engine.Rule{Verdict: engine.Deny, Rule: rule, Role: platform.RPCEntryRole})
		}
	}
	return out, true
}

// viewConfiguration is the bit that grants the configuration, and
// configurationRead the command it reads it with.
const viewConfiguration, configurationRead = "view-configuration", "show configuration **"

// configurationBeneath is every grant deny res sends that meets `show
// configuration` while the session holds view-configuration.
func (g generator) configurationBeneath(res Result) []engine.Rule {
	if !slices.Contains(g.held(res.Bits), viewConfiguration) {
		return nil
	}
	var out []engine.Rule
	for _, dn := range res.Denies {
		if dn.Role != platform.BaselineBit && dn.Role != platform.RPCEntryRole && g.mayMeet(configurationRead, dn.Rule) {
			out = append(out, dn)
		}
	}
	return out
}
```

  `rpcEntries` becomes `[]string{"xml-mode", "junoscript", "op"}`, its comment adding that Junos
  authorizes `xml-mode` as `junoscript` (L26c-junoscript-juniper_*.md). This touches every set,
  and spec §8 says a binary upgrade changes no pinned render: under 1.1.0 no reply can carry an
  allow of `junoscript`, since only `all` reaches it and a reply with an allow never keeps `all`
  (it enters configuration mode, and render drops it), so nothing 1.1.0 renders moves; Task 4's
  frozen-set tests and every 1.1.0-pinned test passing unchanged is the check. `rpcWhy` becomes:

```go
// rpcWhy is why a wire deny is no boundary on a device it binds no RPC on,
// where the reply cannot close the entry points: only what is measured.
func (g generator) rpcWhy() string {
	if len(g.in.Dialect.RPCEntryDenies) > 0 {
		return fmt.Sprintf("on %s a wire deny does not bind a native RPC (tests/lab/results/L12-netconf-juniper_*.md), "+
			"and an allow the reply sends would beat its rpc_entry_denies (%s; L11), so port49 fails the composition "+
			"closed", g.in.Platform, strings.Join(g.in.Dialect.RPCEntryDenies, ", "))
	}
	return fmt.Sprintf("on %s a wire deny does not bind a native RPC a CLI session reaches through `xml-mode` "+
		"(tests/lab/results/L12-netconf-juniper_*.md, L26c-juniper_*.md), and this platform set sends no "+
		"rpc_entry_denies (set 1.2.0 does; spec §8), so port49 fails the composition closed", g.in.Platform)
}
```

  Rewrite `JunosFacts`'s comment last sentences and `ere.go`'s `DenyBindsRPCs` comment to say
  "measured (L12-netconf-juniper_*.md, L26c-juniper_*.md): a wire deny does not bind a native RPC;
  where the adapter has `RPCEntryDenies` the reply closes the entry points instead (decision 44)",
  removing "provisional on L26c" and "unmeasured". `rpcCarves`'s comment: replace "It is empty
  until L26c closes" with "It is empty: set 1.2.0 closes the entry instead (RPCEntryDenies), and no
  carve-out was measured over RPC".

- [ ] **Step 4: Run the package**

Run: `go test ./internal/projection/ -count=1`
Expected: PASS, the existing `TestACarveOutBeneathASentBitFailsClosed` and
`TestOnlyACarveOutMeasuredOverRPCOmitsADeny` unchanged (their adapters carry no entry deny).

- [ ] **Step 5: Commit**

```bash
git add internal/projection
git commit -m "feat: projection adds rpc_entry_denies beneath a deny instead of failing closed

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5b: A readonly with a deny beneath `show **` projects (decision 44 ruling 10)

Owner's ruling 4 and R9. Five changes, each only where the dialect carries `RPCEntryDenies`
(`closesEntries`), so set 1.1.0 and a block that drops the entry deny render as before. Built and
measured in pre-flight against the shipped adapter and tree (Tasks 4 and 5 applied, `save` added
to the 1.2.0 tree): every test below passed, and each fails with its change removed (the mutation
column of Step 5).

**Files:**
- Modify: `internal/projection/project.go` (`Result` after `ConfigurationBeneath`; `Clone`;
  `shape` after its `res, err = g.finish(res, err)`; `capability`'s permit loop, before its
  `DenyMatchesExpanded` check, and Task 5's `!g.in.Facts.DenyBindsRPCs` block; new functions after
  Task 5's `entryDenies`; `alternation`)
- Modify: `internal/projection/model.go` (`model`, the deny program)
- Modify: `internal/policy/lint.go` (`projectionMessage`, after the `Omitted` clause ~line 871)
- Test: `internal/projection/project_guard_test.go`, `internal/projection/project_test.go`
  (`TestCloneCopiesEverySlice`), `internal/policy/projection_test.go`

**Interfaces:**
- Consumes: Task 4's set 1.2.0 (its tree proves `save`, G3), Task 5's `entryDenies`, `entry`,
  `shipped`, `TestTheShippedSetsEntryDeny`; G4 from Task 3.
- Produces: `Result.Closed []engine.Rule`; `generator.closesEntries`, `closedByEntry`,
  `carvedAllows`, `factored`; `var authorizedAs`.

- [ ] **Step 1: Write the failing tests** in `internal/projection/project_guard_test.go`, and
  replace Task 5's `TestTheShippedSetsEntryDeny` with the one below:

```go
// Under the entry deny, the baseline's `xml-mode **`, which no keyword tree
// proves, is sent as nothing: Junos authorizes `xml-mode` as `junoscript`,
// which the entry deny refuses (decision 44 ruling 10). The model reads it
// refused; without the entry deny the composition fails closed as before.
func TestTheEntryDenyClosesTheBaselinesXMLMode(t *testing.T) {
	ops := []engine.Rule{permit("show **"), permit("clear **"), permit("request **"), permit("test **")}
	for _, w := range []string{"help", "quit", "exit", "set", "file", "load", "op", "save", "scp", "ping",
		"traceroute", "ssh", "telnet", "mtrace", "probe", "monitor"} {
		ops = append(ops, permit(w+" **"))
	}
	in := func(entries bool) Input {
		in := measuredInput(platform.BitDeliveryUserPermissions, "operator", JunosFacts, ops...)
		// The shipped baseline holds `xml-mode`; the tree measuredInput
		// proves was built before it, so `xml-mode` is no keyword, as shipped.
		in.Dialect.Bits[platform.BaselineBit] = append(in.Dialect.Bits[platform.BaselineBit], "xml-mode **")
		if entries {
			in = entry(in)
		}
		return in
	}
	res, err := Project(in(true))
	if err != nil || res.Shape != ShapeCapability || !res.EntryDenied() || len(res.Closed) != 1 ||
		res.Closed[0].Rule != "xml-mode **" || slices.ContainsFunc(res.Denies, func(d engine.Rule) bool {
		return d.Rule == "xml-mode **"
	}) {
		t.Fatalf("%s %q closed %v %+v %v", res.Shape, res.Attributes, res.Closed, res.Refusal, err)
	}
	if strings.Contains(strings.Join(res.Attributes, " "), "xml") {
		t.Errorf("xml-mode is on the wire: %q", res.Attributes)
	}
	for _, v := range [][]string{{"xml-mode", "netconf"}, {"xml-mode"}, {"junoscript", "netconf"}, {"start", "shell"}} {
		if res.Device(v) {
			t.Errorf("the device runs %q", v)
		}
	}
	if res, err = Project(in(false)); err != nil || res.Shape != ShapeFailClosed {
		t.Fatalf("without the entry deny: %s %+v %v", res.Shape, res.Refusal, err)
	}
}

// Under the entry deny, `word **` denies render as one alternative; without
// it each is its own, as set 1.1.0 renders (decision 44 ruling 10).
func TestWordDeniesRenderAsOneAlternative(t *testing.T) {
	rules := []engine.Rule{permit("**"), deny("start **"), deny("file **"), deny("show configuration **")}
	res, err := Project(entry(measuredInput(platform.BitDeliveryUserPermissions, "admin", JunosFacts, rules...)))
	want := `deny-commands=^( *(start|file|junoscript)( .*)? *(\|.*)?| *show +configuration( .*)? *(\|.*)?)$`
	if err != nil || res.Shape != ShapeCapability || !slices.Contains(res.Attributes, want) {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	for _, v := range [][]string{{"start", "shell"}, {"file", "list"}, {"junoscript"}, {"show", "configuration"}} {
		if res.Device(v) {
			t.Errorf("the device runs %q", v)
		}
	}
	binding := JunosFacts
	binding.DenyBindsRPCs = true
	res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "admin", binding, rules...))
	want = `deny-commands=^( *start( .*)? *(\|.*)?| *file( .*)? *(\|.*)?| *show +configuration( .*)? *(\|.*)?)$`
	if err != nil || !slices.Contains(res.Attributes, want) {
		t.Fatalf("no entry deny: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}

// Under the entry deny, a readonly's `show **` less a deny beneath `view`
// goes out as `view` and an allow of each of view-configuration's carve-outs
// it holds and no deny does: an allow of `show **` would beat the deny (L11).
// The allow runs beyond the bits, unmeasured, so it is reported (Unreached).
// Without the entry deny the answer is set 1.1.0's refused shape.
func TestACarvedPermitGoesOutAsItsCarveOuts(t *testing.T) {
	in := func(entries bool) Input {
		in := measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show **"),
			deny("show configuration **"))
		in.Dialect.Bits["view-configuration"] = append(in.Dialect.Bits["view-configuration"], "show log **")
		in.Dialect.CarveOuts = map[string][]string{"view-configuration": {"show configuration **", "show log **"}}
		if entries {
			in = entry(in)
		}
		return in
	}
	res, err := Project(in(true))
	if err != nil || res.Shape != ShapeCapability || !slices.Equal(res.Bits, []string{"view"}) || !res.EntryDenied() ||
		len(res.Allows) != 1 || res.Allows[0].Rule != "show log **" || len(res.Unreached) != 1 {
		t.Fatalf("%s %q allows %v unreached %v %+v %v", res.Shape, res.Attributes, res.Allows, res.Unreached,
			res.Refusal, err)
	}
	if res.Device([]string{"show", "configuration"}) || !res.Device([]string{"show", "version"}) ||
		!res.Device([]string{"show", "log", "messages"}) {
		t.Errorf("%q", res.Attributes)
	}
	if res, err = Project(in(false)); err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape {
		t.Fatalf("without the entry deny: %s %+v %v", res.Shape, res.Refusal, err)
	}
}

// Under the entry deny, a readonly granted `show **` and no deny keeps the
// narrow shape and both bits, as under set 1.1.0: the capability shape would
// send `view` and an allow of `show **` beyond it, and only the bits are
// measured to show the configuration (decision 44 ruling 10).
func TestAReadonlyKeepsTheNarrowShapeWhereItsBitsReachIt(t *testing.T) {
	was, err := Project(measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show **")))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Project(entry(measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show **"))))
	if err != nil || res.Shape != ShapeNarrow || !slices.Equal(res.Attributes, was.Attributes) || len(res.Unreached) != 0 {
		t.Fatalf("%s %q, was %s %q: %v", res.Shape, res.Attributes, was.Shape, was.Attributes, err)
	}
}

// What set 1.2.0 renders, read from the shipped adapter and keyword tree,
// not a fixture (decision 44 rulings 1 and 10), beside set 1.1.0's, which is
// unchanged: an operator granted everything but `show configuration` keeps
// the capability shape with the entry deny; a readonly granted `show **`
// keeps the narrow shape, byte for byte.
func TestTheShippedSetsEntryDeny(t *testing.T) {
	res, err := Project(shipped("1.2.0", "operator", permit("**"), deny("show configuration **")))
	if err != nil || res.Shape != ShapeCapability || !res.EntryDenied() || len(res.ConfigurationBeneath) != 1 {
		t.Fatalf("operator: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	was, err1 := Project(shipped("1.1.0", "readonly", permit("show **")))
	res, err = Project(shipped("1.2.0", "readonly", permit("show **")))
	if err != nil || err1 != nil || res.Shape != ShapeNarrow || !slices.Equal(res.Attributes, was.Attributes) {
		t.Fatalf("readonly: %s %q, under 1.1.0 %q: %v %v", res.Shape, res.Attributes, was.Attributes, err, err1)
	}
	for _, rules := range [][]engine.Rule{
		{permit("show **"), deny("show configuration **")},
		{permit("**"), deny("show configuration **")},
	} {
		level := map[bool]string{true: "readonly", false: "operator"}[rules[0].Rule == "show **"]
		res, err = Project(shipped("1.1.0", level, rules...))
		if err != nil || res.Shape != ShapeFailClosed || !slices.Equal(res.Attributes, []string{"deny-commands=^.*$"}) {
			t.Errorf("1.1.0 %s: %s %q %v", level, res.Shape, res.Attributes, err)
		}
	}
}

// RFC 8907's 255 bytes hold a readonly's deny beneath `show **` under set
// 1.2.0 (decision 44 ruling 10): fourteen baseline denies, `xml-mode` sent as
// nothing, the twelve `word **` ones in one alternative with the entry deny,
// `set cli` beside them, and the grant's. Measured in pre-flight: 170 and 165 bytes of deny-commands.
func TestAReadonlyWithAShowDenyFitsTheBudget(t *testing.T) {
	for _, c := range []struct {
		deny   string
		bytes  int
		allows []string
	}{
		{"show configuration **", 170, []string{"show log **", "show firewall **", "show policer **"}},
		{"show security **", 165, []string{"show configuration **", "show log **", "show firewall **", "show policer **"}},
	} {
		res, err := Project(shipped("1.2.0", "readonly", permit("show **"), deny(c.deny)))
		if err != nil || res.Shape != ShapeCapability || !slices.Equal(res.Bits, []string{"view"}) || !res.EntryDenied() ||
			len(res.Closed) != 1 || res.Closed[0].Rule != "xml-mode **" {
			t.Fatalf("%s: %s %q %+v %v", c.deny, res.Shape, res.Attributes, res.Refusal, err)
		}
		var allows []string
		for _, a := range res.Allows {
			allows = append(allows, a.Rule)
		}
		if !slices.Equal(allows, c.allows) || len(res.Unreached) != len(c.allows) {
			t.Errorf("%s: allows %v, unreached %v", c.deny, allows, res.Unreached)
		}
		i := slices.IndexFunc(res.Attributes, func(a string) bool { return strings.HasPrefix(a, "deny-commands=") })
		if i < 0 || len(res.Attributes[i]) != c.bytes {
			t.Errorf("%s: %q", c.deny, res.Attributes)
		}
		words := strings.Fields(c.deny)
		for _, v := range [][]string{words[:2], {"save", "x"}, {"xml-mode", "netconf"}, {"junoscript"}, {"start", "shell"},
			{"request", "system", "reboot"}} {
			if res.Device(v) {
				t.Errorf("%s: the device runs %q", c.deny, v)
			}
		}
		if !res.Device([]string{"show", "version"}) {
			t.Errorf("%s: show version does not run", c.deny)
		}
	}
}
```

  In `project_test.go`'s `TestCloneCopiesEverySlice`, add `Closed: []engine.Rule{r}` to `fresh()`.
  In `internal/policy/projection_test.go`:

```go
// A baseline deny the entry deny refuses is reported beside the reply, not
// sent (decision 44 ruling 10).
func TestTheProjectionMessageNamesWhatTheEntryDenyCloses(t *testing.T) {
	pr := projection.Result{Shape: projection.ShapeCapability, Bits: []string{"view"},
		Closed: []engine.Rule{{Verdict: engine.Deny, Rule: "xml-mode **", Role: platform.BaselineBit}}}
	if msg := projectionMessage(pr, nil, nil); !strings.Contains(msg, "; refused by the entry deny, sent as nothing: xml-mode **") {
		t.Errorf("%q", msg)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/projection/ ./internal/policy/ -run 'XMLMode|OneAlternative|CarvedPermit|KeepsTheNarrowShape|ShippedSets|FitsTheBudget|EntryDenyCloses|CloneCopies' -count=1`
Expected: FAIL to compile (`Closed` undefined).

- [ ] **Step 3: Implement.** In `Result`, after `ConfigurationBeneath`:

```go
	// Closed are baseline denies the reply's entry deny refuses on the
	// device, sent as nothing: Junos authorizes `xml-mode` as `junoscript`,
	// and a deny naming `xml-mode` does not bind
	// (tests/lab/results/L26c-junoscript-juniper_*.md; decision 44 ruling 10).
	Closed []engine.Rule
```

  In `Clone`: `r.Closed = slices.Clone(r.Closed)`. In `model.go`, the deny program reads closed
  denies as sent, since the device refuses them: `denies := slices.Concat(res.Denies, res.Closed)`
  in place of `denies := slices.Clone(res.Denies)`.

  In `capability`'s permit loop, replace

```go
		if dn, ok := g.allowable(p.Rule); !ok {
			return Result{}, g.refusedShape(p, dn)
		}
```

  with

```go
		if dn, ok := g.allowable(p.Rule); !ok {
			// Under the entry deny, a permit the bits reach but for a
			// carve-out goes out as those carve-outs (carvedAllows).
			carved, ok := g.carvedAllows(p, bits)
			if !ok {
				return Result{}, g.refusedShape(p, dn)
			}
			for _, c := range carved {
				if !slices.ContainsFunc(res.Allows, func(a engine.Rule) bool { return a.Rule == c.Rule }) {
					res.Allows = append(res.Allows, c)
				}
			}
			continue
		}
```

  Before `if len(res.Denies) > 0 && !g.in.Facts.DenyMatchesExpanded {`:

```go
	// A baseline deny the entry deny refuses is sent as nothing, where the
	// entry deny goes out (closedByEntry): it is beneath the baseline, so the
	// loop below adds the entry deny for it.
	var closed []engine.Rule
	if _, ok := g.entryDenies(res); ok && !g.in.Facts.DenyBindsRPCs {
		res.Denies = slices.DeleteFunc(res.Denies, func(dn engine.Rule) bool {
			if g.closedByEntry(dn) {
				closed = append(closed, dn)
				return true
			}
			return false
		})
	}
```

  In Task 5's `!g.in.Facts.DenyBindsRPCs` block, the loop reads `for _, dn := range
  slices.Concat(res.Denies, closed) {`, and after `res.Denies = append(res.Denies, more...)` add
  `res.Closed = closed`. After `entryDenies`:

```go
// closesEntries reports whether the dialect closes the RPC entry points
// (RPCEntryDenies): set 1.2.0. What the entry deny makes possible renders
// only there, so a set without it, or a block that drops it, renders as set
// 1.1.0 does (decision 44 ruling 5).
func (g generator) closesEntries() bool { return len(g.in.Dialect.RPCEntryDenies) > 0 }

// authorizedAs are the commands Junos authorizes as another: a deny of
// `junoscript` refused `xml-mode netconf` (`unknown command: xml-mode`), and a
// deny naming `xml-mode` did not bind (tests/lab/results/L26c-junoscript-juniper_*.md,
// both images; bare `xml-mode` in L58-juniper_*.md).
var authorizedAs = map[string]string{"xml-mode": "junoscript"}

// closedByEntry reports whether dn is a baseline deny an entry deny refuses
// on the device, its command read as Junos authorizes it: the baseline's
// `xml-mode **`, which no keyword tree proves, beside `junoscript **`.
func (g generator) closedByEntry(dn engine.Rule) bool {
	words := strings.Fields(dn.Rule)
	if dn.Role != platform.BaselineBit || len(words) == 0 {
		return false
	}
	as, ok := authorizedAs[words[0]]
	if !ok {
		return false
	}
	words[0] = as
	read := strings.Join(words, " ")
	return slices.ContainsFunc(g.in.Dialect.RPCEntryDenies, func(e string) bool { return g.contains(e, read) })
}

// carvedAllows are permit p sent as the carve-outs that keep it from the
// bits, where the bits reach the rest of it: an allow of p would beat a deny
// beneath it (L11), and an allow of each carve-out p holds meets none. A
// carve-out a deny holds needs nothing. Each is within the ceiling, sendable
// and allowable, or there are none (ok false). Only under the entry deny,
// which lets a deny beneath the bits stand (decision 44 ruling 10): a
// readonly's `show **` less `show configuration **` sends `view` and allows
// `show log`, `show firewall` and `show policer`, view-configuration's other
// carve-outs, whose run beyond the bits is reported (Unreached).
func (g generator) carvedAllows(p engine.Rule, bits []string) ([]engine.Rule, bool) {
	if !g.closesEntries() {
		return nil, false
	}
	held := g.held(bits)
	if !slices.ContainsFunc(g.reach(held), func(r string) bool { return g.contains(r, p.Rule) }) {
		return nil, false
	}
	var out []engine.Rule
	for _, c := range g.carves(held) {
		if !g.mayMeet(p.Rule, c) || slices.ContainsFunc(g.denies, func(d engine.Rule) bool { return g.contains(d.Rule, c) }) {
			continue
		}
		if !g.contains(p.Rule, c) || !g.within(c) || g.unsendableAllow(c) != "" {
			return nil, false
		}
		if _, ok := g.allowable(c); !ok {
			return nil, false
		}
		out = append(out, engine.Rule{Verdict: engine.Permit, Rule: c, Role: p.Role})
	}
	return out, true
}
```

  In `shape`, after `res, err = g.finish(res, err)`:

```go
	// Under the entry deny, a capability reply that sends an allow its bits
	// do not reach yields to a narrow one whose bits reach every allow and
	// that leaves off no more: the bits are measured, an allow beyond them is
	// not (decision 44 ruling 10).
	if err == nil && len(res.Unreached) > 0 && g.closesEntries() {
		n, nerr := g.finish(g.narrow())
		if nerr == nil && len(n.Unreached) == 0 && !slices.ContainsFunc(n.Beyond, func(p engine.Rule) bool {
			return !slices.Contains(res.Beyond, p)
		}) && len(n.Unsent) <= len(res.Unsent) {
			return n, nil
		}
	}
```

  `alternation` becomes:

```go
// alternation is rules as one group, `(a|b)`, or one rule bare; empty for
// none.
func (g generator) alternation(rules []engine.Rule, deny bool) (string, error) {
	var alts, words []string
	at := -1 // where the factored `word **` denies go: the first one's place
	for _, r := range rules {
		if w, ok := g.factored(r.Rule, deny); ok {
			if at < 0 {
				at = len(alts)
				alts = append(alts, "")
			}
			if !slices.Contains(words, w) {
				words = append(words, w)
			}
			continue
		}
		e, err := ruleERE(r.Rule, g.in.Classes, deny, g.in.Facts)
		if err != nil {
			return "", refuse(FailUnwritable, "on %s, %s %s (role %q) cannot be written as the device's regex: %v "+
				"(spec §8, §15 L9)", g.in.Platform, r.Verdict, g.quote(r.Rule), r.Role, err)
		}
		if !slices.Contains(alts, e) {
			alts = append(alts, e)
		}
	}
	if at >= 0 {
		group := words[0]
		if len(words) > 1 {
			group = "(" + strings.Join(words, "|") + ")"
		}
		alts[at] = denyLead + group + "( .*)?" + pipeTail
	}
	switch len(alts) {
	case 0:
		return "", nil
	case 1:
		return alts[0], nil
	}
	return "(" + strings.Join(alts, "|") + ")", nil
}

// factored is a `word **` deny's word as the deny side writes it, where the
// dialect closes the entry points: such denies render as one alternative,
// ` *(help|quit|…)( .*)? *(\|.*)?`, the shape L26b's deny sessions were
// enforced in (tests/lab/results/L26b-juniper_*.md), and a readonly's
// baseline denies fit the budget (decision 44 ruling 10).
func (g generator) factored(rule string, deny bool) (string, bool) {
	if !deny || !g.closesEntries() {
		return "", false
	}
	words, rest, other := keywordShape(rule)
	if len(words) != 1 || !rest || other != "" {
		return "", false
	}
	w, err := wordERE(words[0], true, g.in.Facts)
	return w, err == nil
}
```

  A single word renders as `ruleERE` renders it (` *w( .*)? *(\|.*)?`), so only its place in the
  alternation moves. `failClosed` and the allow side never factor.

- [ ] **Step 4: The report.** In `internal/policy/lint.go`'s `projectionMessage`, after the
  `Omitted` clause:

```go
	if len(pr.Closed) > 0 {
		msg += "; refused by the entry deny, sent as nothing: " + rules(pr.Closed)
	}
```

- [ ] **Step 5: Run, and check each change is what a test holds**

Run: `go test ./internal/projection/ ./internal/policy/ -count=1 && make test`
Expected: PASS. Every set-1.1.0-pinned test and Task 4's frozen-set tests pass unchanged. Then
remove each change in turn and see its tests fail (pre-flight saw exactly this):

| change removed | fails |
|---|---|
| `closedByEntry` returns false | `TestTheEntryDenyClosesTheBaselinesXMLMode`, `TestAReadonlyWithAShowDenyFitsTheBudget` |
| the model reads `res.Denies` only | the same two (the witness finds `xml-mode` running) |
| `factored` returns false | `TestWordDeniesRenderAsOneAlternative`, `TestACarvedPermitGoesOutAsItsCarveOuts`, `TestAReadonlyWithAShowDenyFitsTheBudget` |
| `carvedAllows` returns false | `TestACarvedPermitGoesOutAsItsCarveOuts`, `TestAReadonlyWithAShowDenyFitsTheBudget` |
| `shape`'s narrow preference | `TestAReadonlyKeepsTheNarrowShapeWhereItsBitsReachIt`, `TestTheShippedSetsEntryDeny` |

  Pre-flight also ran Task 6's code and `TestTheEntryDenyWarnings` (its fixture carries an entry
  deny) on top of this task's: it passes, so Task 6 needs no change for it.

- [ ] **Step 6: Commit**

```bash
git add internal/projection internal/policy/lint.go internal/policy/projection_test.go
git commit -m "feat: a readonly with a deny beneath show projects under set 1.2.0

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: The two warnings, in `policy test` and `policy diff`

**Files:**
- Modify: `internal/policy/lint.go` (constants after `FindingProjectionArgumentAllow`, line 632;
  `Projections`, the per-reply items ~line 684 and the `named` lines ~739–747; new message
  functions beside `unsentMessage`)
- Modify: `internal/policy/diff.go` (`Diff` after `ProjectionRefusals`, line 70; `Compare`
  ~line 446)
- Modify: `cmd/port49/policy.go` (`policyDiff`, after the `d.Projections` loop, line ~596)
- Test: `internal/policy/projection_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `projection.Result.NetconfClosed`, `EntryDenied`, `ConfigurationBeneath` (Task 5).
- Produces: `policy.FindingProjectionNetconfClosed = "projection_netconf_closed"`,
  `policy.FindingProjectionDenyBeneathViewConfiguration =
  "projection_deny_beneath_view_configuration"`, `Diff.ProjectionWarnings []Finding`.

- [ ] **Step 1: Write the failing test** in `internal/policy/projection_test.go`:

```go
// parseEntry is parseProjected under user_permissions with set 1.2.0's entry
// deny on the test set, and view-configuration reaching `show log` too, so a
// deny of `show configuration` is sent beneath the bit, not aligned with it.
func parseEntry(t *testing.T, body string) *Policy {
	t.Helper()
	e := projectedEnv(platform.BitDeliveryUserPermissions)
	d := e.Sets[projectedSet]["juniper_junos"]
	d.RPCEntryDenies = []string{"junoscript **"}
	d.Bits["view-configuration"] = []string{"show configuration **", "show log **"}
	e.Sets[projectedSet]["juniper_junos"] = d
	p, err := Parse([]byte("platform_set: "+projectedSet+"\n"+body), e)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The entry deny closes NETCONF for that subject, and a deny of `show
// configuration` beneath view-configuration is Ryan's operator error: each a
// warning, failing nothing; policy diff prints the ones a change brings
// (decision 44 ruling 4).
func TestTheEntryDenyWarnings(t *testing.T) {
	plain := parseEntry(t, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"]}
`+subjOK+grantOK)
	denies := parseEntry(t, scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}
`+subjOK+grantOK)
	kinds := func(fs []Finding) map[string][]string {
		out := map[string][]string{}
		for _, f := range fs {
			out[f.Kind] = append(out[f.Kind], f.Message)
		}
		return out
	}
	got := kinds(denies.Projections(noon))
	if n := got[FindingProjectionNetconfClosed]; len(n) != 1 || !strings.Contains(n[0], "no NETCONF") {
		t.Errorf("netconf closed: %q", n)
	}
	if v := got[FindingProjectionDenyBeneathViewConfiguration]; len(v) != 1 ||
		!strings.Contains(v[0], "show configuration **") || !strings.Contains(v[0], "withhold view-configuration") {
		t.Errorf("view-configuration: %q", v)
	}
	if ProjectionRefusals(denies.Projections(noon)) != 0 {
		t.Error("a warning fails policy test")
	}
	if p := kinds(plain.Projections(noon)); len(p[FindingProjectionNetconfClosed])+
		len(p[FindingProjectionDenyBeneathViewConfiguration]) != 0 {
		t.Errorf("no deny beneath, no warning: %v", p)
	}
	d := Compare(plain, denies, noon)
	if len(d.ProjectionWarnings) != 2 || len(d.ProjectionRefusals) != 0 {
		t.Errorf("the change brings two warnings: %+v", d.ProjectionWarnings)
	}
	if d := Compare(denies, denies, noon); len(d.ProjectionWarnings) != 0 {
		t.Errorf("an unchanged warning is not repeated: %+v", d.ProjectionWarnings)
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/policy/ -run TestTheEntryDenyWarnings -count=1`
Expected: FAIL to compile (`FindingProjectionNetconfClosed` undefined).

- [ ] **Step 3: Implement.** In `lint.go`, after `FindingProjectionArgumentAllow`:

```go
// FindingProjectionNetconfClosed is a composition whose Junos reply refuses
// `junoscript`: set 1.2.0's entry deny beneath a deny, or the narrow shape's
// `.*`. That subject has no NETCONF, `xml-mode` or XML API session on those
// devices (spec §8; decision 44). A warning: it fails neither policy test nor
// policy diff, which prints the ones a change brings.
const FindingProjectionNetconfClosed = "projection_netconf_closed"

// FindingProjectionDenyBeneathViewConfiguration is a sent deny that meets
// `show configuration` beneath a held view-configuration: the CLI refuses it
// and NETCONF is closed, but the bit grants the configuration (decision 44
// ruling 4). A warning.
const FindingProjectionDenyBeneathViewConfiguration = "projection_deny_beneath_view_configuration"

// projectionNote reports whether a projection finding is a report or warning
// written after its subject and platform with a colon, rather than a refusal.
func projectionNote(kind string) bool {
	return kind == FindingProjection || kind == FindingProjectionArgumentAllow ||
		kind == FindingProjectionNetconfClosed || kind == FindingProjectionDenyBeneathViewConfiguration
}
```

  In `Projections`, after the `for _, u := range pr.Unsent` loop:

```go
				// Only where the pinned set lets NETCONF stay on (R8): under
				// 1.1.0 check-config has it off on the whole device.
				if pr.NetconfClosed() && len(p.dialect(d.Platform).RPCEntryDenies) > 0 {
					reports[i] = append(reports[i], item{FindingProjectionNetconfClosed, netconfClosedMessage(*pr)})
				}
				if len(pr.ConfigurationBeneath) > 0 {
					reports[i] = append(reports[i], item{FindingProjectionDenyBeneathViewConfiguration,
						configurationBeneathMessage(*pr, patterns)})
				}
```

  Replace both `g.kind == FindingProjection || g.kind == FindingProjectionArgumentAllow`
  conditions with `projectionNote(g.kind)`. Beside `unsentMessage`:

```go
// netconfClosedMessage is a projection_netconf_closed warning after its
// subject and platform.
func netconfClosedMessage(pr projection.Result) string {
	var entry []string
	for _, d := range pr.Denies {
		if d.Role == platform.RPCEntryRole {
			entry = append(entry, "`"+d.Rule+"`")
		}
	}
	// Each entry deny is named, `op **` included where the set carries it:
	// a subject denied `op` that port49 permits is told so (R2).
	how := "the reply adds deny " + strings.Join(entry, " and ")
	if pr.Shape == projection.ShapeNarrow {
		how = "the narrow reply's `deny-commands .*` refuses `junoscript`"
	}
	return " " + how + ", so this subject has no NETCONF, `xml-mode` or XML API session there " +
		"(tests/lab/results/L26c-junoscript-juniper_*.md); an account that needs NETCONF needs a grant with no deny " +
		"beneath its bits (spec §8; decision 44 ruling 3)"
}

// configurationBeneathMessage is a projection_deny_beneath_view_configuration
// warning after its subject and platform, each rule redacted.
func configurationBeneathMessage(pr projection.Result, patterns []platform.Redaction) string {
	var rules []string
	for _, r := range pr.ConfigurationBeneath {
		rules = append(rules, r.Rule)
	}
	return " deny " + strings.Join(redacted(patterns, rules), "; ") + " is sent beneath view-configuration, " +
		"which the reply holds: the CLI refuses it and NETCONF is closed, but the bit is what grants the " +
		"configuration; withhold view-configuration instead (spec §8; decision 44 ruling 4)"
}
```

  In `diff.go`, `Diff` gains after `ProjectionRefusals`:

```go
	// ProjectionWarnings are the projection warnings the new version has and
	// the old did not (projection_netconf_closed,
	// projection_deny_beneath_view_configuration): reported, never failing the
	// diff (decision 44 ruling 4).
	ProjectionWarnings []Finding
```

  In `Compare`, replace the `after.Projections(now)` loop with:

```go
	warning := func(k string) bool {
		return k == FindingProjectionNetconfClosed || k == FindingProjectionDenyBeneathViewConfiguration
	}
	var had []Finding
	for _, f := range before.Projections(now) {
		if warning(f.Kind) {
			had = append(had, f)
		}
	}
	for _, f := range after.Projections(now) {
		switch {
		case f.Kind == FindingProjectionRefused || f.Kind == FindingProjectionOverflow:
			c.d.ProjectionRefusals = append(c.d.ProjectionRefusals, f)
		case warning(f.Kind) && !slices.Contains(had, f):
			c.d.ProjectionWarnings = append(c.d.ProjectionWarnings, f)
		}
	}
```

  In `cmd/port49/policy.go`'s `policyDiff`, after the `d.Projections` loop:

```go
	// A warning the change brings (decision 44 ruling 4): reported, and the
	// exit code is not touched by it.
	for _, f := range d.ProjectionWarnings {
		fmt.Fprintf(stdout, "warning: %s: %s\n", f.Kind, f.Message)
	}
```

  In `cmd/port49/policy_test.go`, beside the existing `policy diff` tests, add an assertion that
  a diff bringing an entry-deny warning prints a `warning: projection_netconf_closed:` line and
  still exits 0. The policy pins `1.2.0` (the shipped set, after Task 4) with an operator role
  granted `["**"]` less `["show configuration **"]` over a `juniper_junos` device, against the
  same file without the deny; copy the env setup of a `policyDiff` test there.

- [ ] **Step 4: Run**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy cmd/port49/policy.go cmd/port49/policy_test.go
git commit -m "feat: projection_netconf_closed and deny-beneath-view-configuration warnings

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: check-config reads groups; the services check by set

**Files:**
- Modify: `internal/platform/classes.go` (`TemplateDrift`, lines ~162–243, and its doc comment;
  new helpers below `hasPrefix`)
- Modify: `internal/platform/services.go` (`rpcServicesOff`'s comment; `RPCServicesChecked`;
  `ServicesCapture` → `ConfigCapture`; `CheckServices`; `servicesSays`; new `rpcPastEntryDeny`,
  `entrySays`, `NetconfForbidden`)
- Modify: every `ServicesCapture` reference (`grep -rn ServicesCapture --include='*.go' .`:
  `cmd/port49/devices.go`'s comment, `internal/platform/services_test.go`)
- Modify: `tests/lab/projection_test.go:355` (`netconfForbidden` calls
  `adapter.NetconfForbidden`)
- Test: `internal/platform/classes_test.go`, `internal/platform/services_test.go`

**Interfaces:**
- Consumes: `Dialect.RPCEntryDenies` (Task 4); G2 and the L57 gates and fixtures (Task 3).
- Produces: `platform.ConfigCapture` (string const); `platform.NetconfForbidden(d Dialect) bool`;
  `TemplateDrift` keeps its signature `(config []byte, d Dialect, maxSessionAge time.Duration)
  (missing []string, extra []ConfigFinding, err error)`.

- [ ] **Step 1: Write the failing tests.** In `internal/platform/classes_test.go`:

```go
// check-config trusts the inherited capture, names the group behind a
// template line it fails, passes the harmless statements, and refuses a
// capture that lacks a group's expansion where the configuration applies it
// (decision 44 rulings 7 and 9).
func TestTemplateDriftReadsGroups(t *testing.T) {
	d := junosProjected(BitDeliveryUserPermissions)
	const base = "set version 23.4R2-S2.1\nset system login class p49-remote idle-timeout 720\n" +
		"set system login user remote uid 2001\nset system login user remote class p49-remote\n"
	for _, c := range []struct {
		name, config string
		says         []string // each finding's Says holds its entry, in order
		err          string
	}{
		{"privilege, inherited", base + "set groups BASE system login class <*> permissions all\n" +
			"set apply-groups BASE\nset system login class p49-remote permissions all\n",
			[]string{"group BASE adds `permissions` to class p49-remote: every port49 session on this device gets it"}, ""},
		{"harmless, inherited", base + "set groups TIP system login class <*> login-tip\nset apply-groups TIP\n" +
			"set system login class p49-remote login-tip\n", nil, ""},
		{"harmless, written there", base + "set system login class p49-remote login-alarms\n" +
			"set system login user remote full-name \"port49 template\"\n", nil, ""},
		{"not inherited", base + "set groups BASE system login class <*> permissions all\nset apply-groups BASE\n",
			nil, "display inheritance"},
		{"excepted", base + "set groups BASE system login class <*> permissions all\nset apply-groups BASE\n" +
			"set system login class p49-remote apply-groups-except BASE\n", nil, ""},
		{"applied nowhere", base + "set groups BASE system login class <*> permissions all\n", nil, ""},
		{"own leaf", base + "set groups T system login class <*> idle-timeout 30\nset apply-groups T\n", nil, ""},
		{"not known harmless", base + "set groups H system login class <p49-*> allow-hidden-commands\n" +
			"set apply-groups H\nset system login class p49-remote allow-hidden-commands\n",
			[]string{"group H sets `allow-hidden-commands` on class p49-remote, which port49 does not know to be harmless"}, ""},
		{"authentication", base + "set groups A system login user <*> authentication encrypted-password \"$6$abc\"\n" +
			"set apply-groups A\nset system login user remote authentication encrypted-password \"$6$abc\"\n",
			[]string{"group A adds `authentication` to user remote"}, ""},
		{"nested", base + "set groups INNER system login class <p49-*> permissions view\n" +
			"set groups OUTER apply-groups INNER\nset apply-groups OUTER\n" +
			"set system login class p49-remote permissions view\n",
			[]string{"group INNER adds `permissions` to class p49-remote"}, ""},
		{"drift, no group", base + "set system login class p49-remote permissions view\n",
			[]string{templateDriftSays}, ""},
	} {
		missing, extra, err := TemplateDrift([]byte(c.config), d, 12*time.Hour)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) || !strings.Contains(err.Error(), ConfigCapture) {
				t.Errorf("%s: want an error naming %q: %v", c.name, c.err, err)
			}
			continue
		}
		if err != nil || len(missing) != 0 || len(extra) != len(c.says) {
			t.Errorf("%s: %v %q %+v", c.name, err, missing, extra)
			continue
		}
		for i, s := range c.says {
			if !strings.Contains(extra[i].Says, s) || strings.Contains(extra[i].Says, "$6$") {
				t.Errorf("%s: finding %d says %q, want %q", c.name, i, extra[i].Says, s)
			}
		}
	}
}

// The groups the lab committed (tests/lab/results/L57-juniper_*.md), read
// from each image's own inherited capture: p49g-perm is named on p49-remote
// for its permission and its allow-commands, p49g-inner too where the image
// committed and expanded the nesting, and the harmless, excepted, unapplied
// and timeout groups pass.
func TestTemplateDriftReadsTheL57Captures(t *testing.T) {
	files, _ := filepath.Glob("testdata/l57-*.set")
	if len(files) != 2 {
		t.Fatalf("want the two L57 captures, got %q", files)
	}
	d := junosProjected(BitDeliveryUserPermissions)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, extra, err := TemplateDrift(raw, d, 12*time.Hour)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		perm := 0
		for _, e := range extra {
			switch {
			case strings.Contains(e.Says, "group p49g-perm"):
				perm++
			case strings.Contains(e.Says, "group p49g-inner") && strings.Contains(string(raw), "p49g-outer apply-groups"):
			default:
				t.Errorf("%s:%d: %s: %s", f, e.Line, e.Text, e.Says)
			}
		}
		if perm != 2 {
			t.Errorf("%s: want p49g-perm's permissions and allow-commands on p49-remote, got %d: %+v", f, perm, extra)
		}
	}
}
```

  In `internal/platform/services_test.go`, rewrite `TestCheckServices`'s `bad` loop and add the
  set-1.2.0 case:

```go
	// A group is read, not refused: a service a group defines is a finding at
	// its line, and an apply-groups line is no error (decision 44 ruling 7).
	f, err := CheckServices(d, []byte(clean+"set groups g system services rest\nset apply-groups g\n"))
	if err != nil || len(f) != 1 || !strings.HasPrefix(f[0].Text, "set groups g") {
		t.Errorf("a group's service: %+v %v", f, err)
	}
	for _, bad := range []string{"system {\n    services {\n        rest;\n    }\n}\n", ""} {
		if _, err := CheckServices(d, []byte(bad)); err == nil || !strings.Contains(err.Error(), ConfigCapture) {
			t.Errorf("%.40q: %v", bad, err)
		}
	}
```

```go
// Under set 1.2.0's entry deny NETCONF, the XML API, outbound-ssh and every
// non-RPC service pass; the services no measurement shows the deny closes
// still fail (decision 44 ruling 6).
func TestCheckServicesUnderTheEntryDeny(t *testing.T) {
	d := junosProjected(BitDeliveryUserPermissions)
	d.RPCEntryDenies = []string{"junoscript **"}
	if NetconfForbidden(d) || !RPCServicesChecked(d) {
		t.Fatal("under the entry deny NETCONF is allowed and the check still runs")
	}
	clean := "set version 23.4R2-S2.1\nset system services ssh\nset system services netconf ssh\n" +
		"set system services xnm-ssl\nset system services outbound-ssh client c\n" +
		"set system services dhcp-local-server group g\nset system services ssh sftp-server\n"
	if f, err := CheckServices(d, []byte(clean)); len(f) != 0 || err != nil {
		t.Fatalf("clean: %+v %v", f, err)
	}
	for _, line := range append([]string{"set system services web-management https interface fxp0",
		"set system services extension-service request-response grpc"}, rpcPastEntryDenyExtra...) {
		f, err := CheckServices(d, []byte(clean+line+"\n"))
		if err != nil || len(f) != 1 || !strings.Contains(f[0].Says, "junoscript") {
			t.Errorf("%s: %+v %v", line, f, err)
		}
	}
}

// rpcPastEntryDenyExtra is `rest`'s line where Task 3's G2 kept it a finding;
// empty where the deny was measured closing it.
var rpcPastEntryDenyExtra = []string{"set system services rest http port 3000"}
```

  (If G2 dropped `rest`, `rpcPastEntryDenyExtra` is `nil` and the clean config gains
  `set system services rest http port 3000`.)

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ -run 'TemplateDriftReads|CheckServices' -count=1`
Expected: FAIL to compile (`ConfigCapture`, `NetconfForbidden` undefined).

- [ ] **Step 3: Implement the services side** in `services.go`:

```go
// ConfigCapture is the one form check-config reads a projected Junos device's
// configuration in: set form, groups' statements expanded where they apply,
// and the group definitions kept, so what a group brings is read where it
// lands and named by its group (decision 44 ruling 7; L57). A capture taken
// with the earlier `| except "^set groups "` still reads where it applies no
// group to a template; where it does, the definition is missing and
// TemplateDrift refuses it.
const ConfigCapture = `show configuration | display set | display inheritance`

// rpcPastEntryDeny are the services that run RPCs and that no measurement
// shows set 1.2.0's entry deny closing: J-Web and JET/gRPC/gNMI, and REST
// unless L26c-scripts measured it closed (decision 44 ruling 6).
var rpcPastEntryDeny = []string{"rest", "web-management", "extension-service"}

// NetconfForbidden reports whether check-config fails a device of d for
// serving NETCONF: a checked device whose set sends no entry deny (set 1.1.0).
func NetconfForbidden(d Dialect) bool { return RPCServicesChecked(d) && len(d.RPCEntryDenies) == 0 }

const entrySays = "a management service that runs RPCs is enabled, and the reply's `junoscript` deny was not measured " +
	"to close it (tests/lab/results/L26c-scripts-juniper_*.md; decision 44 ruling 6): a session walks around every " +
	"deny port49 sends. Disable it, or pin a set that does not project Junos"
```

  (G2: if both images measured REST closed, `rpcPastEntryDeny` is
  `[]string{"web-management", "extension-service"}`.)

  In `CheckServices`: delete the `groups` refusal and the `apply-groups` refusal. Strip a leading
  `groups NAME` with the logical systems, and read a group's `<pattern>` word as every word it
  matches (decision 44 ruling 7): a plain capture of `set groups g system <s*> netconf ssh`, or
  under 1.2.0 `set groups g system services <r*> http`, applied at the top, is otherwise read as
  nothing while the device runs the service (pre-flight, measured against this code). The reading
  is held to the levels a service sits at (`services X`, `system X`, `system services X`), so
  `set groups g interfaces <*> unit 0` stays clean:

```go
		inGroup := false
		for len(path) > 2 && (path[0].keyword("groups") || path[0].keyword("logical-systems") ||
			path[0].keyword("tenants")) {
			inGroup = inGroup || path[0].keyword("groups")
			path = path[2:]
		}
		// In a group a `<pattern>` word stands for every word it matches, as
		// Junos applies it (decision 44 ruling 7): the statement is a finding
		// where any reading of it is one, whether or not the capture expanded it.
		is := func(w word, k string) bool {
			return w.keyword(k) || inGroup && !w.value && strings.HasPrefix(w.text, "<") && groupWord(w.text, k)
		}
		entry := len(d.RPCEntryDenies) > 0
		offList := false
		if !entry && len(path) >= 3 && is(path[0], "system") && is(path[1], "services") {
			options, ok := cliServices[path[2].text]
			offList = path[2].value || !ok || len(path) >= 4 && (path[3].value || !slices.Contains(options, path[3].text))
		}
		anywhere, says := rpcAnywhere, servicesSays
		if entry {
			anywhere, says = rpcPastEntryDeny, entrySays
		}
		// wild is a group's wildcard at path[i] that could be one of anywhere.
		wild := func(i int) bool {
			return inGroup && len(path) > i && slices.ContainsFunc(anywhere, func(k string) bool {
				return !path[i].keyword(k) && is(path[i], k)
			})
		}
		rpcWord := slices.ContainsFunc(words, func(w word) bool { return slices.ContainsFunc(anywhere, w.keyword) }) ||
			wild(0) || len(path) > 1 && (is(path[0], "services") || is(path[0], "system")) && wild(1) ||
			len(path) > 2 && is(path[0], "system") && is(path[1], "services") && wild(2)
		if offList || rpcWord {
			findings = append(findings, ConfigFinding{Line: n, Text: joinWords(trimmed), Says: says})
		}
```

  (`groupWord` is `classes.go`'s, Step 4.) Add to `TestCheckServicesUnderTheEntryDeny`, or a new
  test beside it, the cases this was measured on: under set 1.1.0 `set groups g system <s*>
  netconf ssh`, `set groups g <*> services netconf ssh`, `set groups g system services <*> http`
  are each one finding; under the entry deny `set groups g system services <r*> http`, `set groups
  g services <*> control` and `set groups g system <e*> application file a.py` are each one; and
  `set groups g interfaces <*> unit 0` and `set groups g system login class <*> idle-timeout 5`
  are none under either.

  Rename `ServicesCapture` to `ConfigCapture` in every reference. Rewrite `rpcServicesOff`'s and
  `CheckServices`'s comments: set 1.1.0 keeps the allowlist; set 1.2.0 reads only
  `rpcPastEntryDeny`; a group is read where it is written and where it applies.

- [ ] **Step 4: Implement the groups side** in `classes.go`. Add, below `hasPrefix`:

```go
// harmlessTemplateStatements change nothing a session may run: a class's
// idle-timeout (the reference writes one; another value is a missing
// reference line), banner and alarms, and a user's full name. They pass under
// a template, written there or from a group (decision 44 ruling 7).
var harmlessTemplateStatements = map[string][]string{
	"class": {"idle-timeout", "login-alarms", "login-tip"},
	"user":  {"full-name"},
}

// privilegeTemplateStatements are the statements a group adding to a template
// is named for (Ryan's ruling, 2026-10-11): a class's bits and command or
// configuration regexes, and a template user's authentication or class. Any
// other statement not harmless fails too (ruling 9).
var privilegeTemplateStatements = map[string][]string{
	"class": {"permissions", "allow-commands", "deny-commands", "allow-configuration", "deny-configuration",
		"allow-commands-regexps", "deny-commands-regexps", "allow-configuration-regexps", "deny-configuration-regexps"},
	"user": {"authentication", "class"},
}

// nestedApplies is whether a group applied from inside another group's
// definition is read as applied at the top (L57; decision 44 ruling 7).
var nestedApplies = true

// groupStatement is one statement of a group's definition: the group, the
// path it adds at with `groups NAME` taken off and wildcards kept, its line.
type groupStatement struct {
	group string
	path  []string
	line  int
	text  string
}

// application is an apply-groups or apply-groups-except statement: the level
// it sits at and the group it names.
type application struct {
	level  []string
	group  string
	except bool
}

// unquoted is words with their quotes taken off.
func unquoted(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = strings.Trim(w, `"`)
	}
	return out
}

// applications reads an apply-groups or apply-groups-except statement's path
// (the words after `set`, logical systems taken off): one per group it names.
// inGroup is a statement inside a group's definition, applied at the top
// where nestedApplies holds, and not at all where it does not.
func applications(path []string, inGroup bool) []application {
	for k, w := range path {
		if w != "apply-groups" && w != "apply-groups-except" {
			continue
		}
		level := path[:k]
		if inGroup {
			if !nestedApplies {
				return nil
			}
			level = nil
		}
		var out []application
		for _, g := range path[k+1:] {
			if g = strings.Trim(g, "[]"); g != "" {
				out = append(out, application{level: slices.Clone(level), group: g, except: w == "apply-groups-except"})
			}
		}
		return out
	}
	return nil
}

// appliesAt reports whether group g's statements land at p: an apply-groups
// naming g at a level at or above p, and no apply-groups-except naming g at
// or below that level and at or above p.
func appliesAt(apps []application, g string, p []string) bool {
	at := -1
	for _, a := range apps {
		if !a.except && a.group == g && hasPrefix(p, a.level, false) && len(a.level) > at {
			at = len(a.level)
		}
	}
	if at < 0 {
		return false
	}
	return !slices.ContainsFunc(apps, func(a application) bool {
		return a.except && a.group == g && hasPrefix(p, a.level, false) && len(a.level) >= at
	})
}

// groupWord reports whether a group's path word matches word as Junos reads
// it: `<pattern>` a glob, anything else itself. A glob that does not compile
// matches, failing closed.
func groupWord(pattern, word string) bool {
	if len(pattern) > 1 && pattern[0] == '<' && pattern[len(pattern)-1] == '>' {
		ok, err := path.Match(pattern[1:len(pattern)-1], word)
		return ok || err != nil
	}
	return pattern == word
}

// groupAt reports whether a group statement's path lands under template
// path t, each word read as Junos reads a group's (groupWord): a wildcard may
// stand at any level, `system login <*> p49-readonly` included.
func groupAt(p, t []string) bool {
	if len(p) < len(t) {
		return false
	}
	for i, w := range t {
		if !groupWord(p[i], w) {
			return false
		}
	}
	return true
}

// groupSays is the finding for a template line group brings.
func groupSays(group string, t []string, stmt string) string {
	who := "every port49 session at that template on this device"
	if t[3] == RemoteClass || t[3] == remoteUser {
		who = "every port49 session on this device"
	}
	if slices.Contains(privilegeTemplateStatements[t[2]], stmt) {
		return fmt.Sprintf("group %s adds `%s` to %s %s: %s gets it; remove it from the group, or narrow the group's "+
			"wildcard past the p49- templates (spec §8; decision 44 ruling 7)", group, stmt, t[2], t[3], who)
	}
	return fmt.Sprintf("group %s sets `%s` on %s %s, which port49 does not know to be harmless there: %s gets it; "+
		"remove it from the group, or narrow the group's wildcard past the p49- templates (decision 44 ruling 9)",
		group, stmt, t[2], t[3], who)
}
```

  Then in `TemplateDrift`, keep the loop's form checks and the `deactivate`/`protect` branch, and
  change the `set` branch and the tail. The `set` branch becomes:

```go
		case "set":
			setForm = true
			carried[line] = true
			if len(words) == 3 && strings.EqualFold(strings.Trim(words[1], `"`), "version") {
				version = true
			}
			w := unquoted(words[1:])
			for len(w) > 2 && (w[0] == "logical-systems" || w[0] == "tenants") {
				w = w[2:]
			}
			inGroup := len(w) > 2 && w[0] == "groups"
			body := w
			if inGroup {
				// A group may write a logical system's or tenant's login
				// too: read under the templates as the expanded line is.
				body = w[2:]
				defined[w[1]] = true
				for len(body) > 2 && (body[0] == "logical-systems" || body[0] == "tenants") {
					body = body[2:]
				}
			}
			if a := applications(body, inGroup); a != nil || slices.Contains(body, "apply-groups") ||
				slices.Contains(body, "apply-groups-except") {
				apps = append(apps, a...)
				return
			}
			if inGroup {
				groups = append(groups, groupStatement{group: w[1], path: body, line: n, text: line})
				return
			}
			paths[strings.Join(w, " ")] = true
			if slices.Contains(want, line) || uidLine.MatchString(line) {
				return
			}
			for _, t := range tpaths {
				if !hasPrefix(w, t, false) {
					continue
				}
				if len(w) > len(t) && slices.Contains(harmlessTemplateStatements[t[2]], w[len(t)]) {
					return
				}
				extraAt[strings.Join(w, " ")] = append(extraAt[strings.Join(w, " ")], len(extra))
				extra = append(extra, ConfigFinding{Line: n, Text: line, Says: templateDriftSays})
				return
			}
```

  with, before the loop, `var groups []groupStatement; var apps []application; paths :=
  map[string]bool{}; defined := map[string]bool{}; extraAt := map[string][]int{}` and `tpaths`
  the templates' `paths()` (the existing `paths` slice renamed `tpaths`, the `deactivate` branch
  reading `tpaths` too). `extraAt` maps a path to the indexes of its findings in `extra`: the
  `deactivate` branch appends to `extra` as well, so a parallel slice of paths would misalign.
  After the form checks and before the `missing` loop:

```go
	// A group applied at or above a template whose definition the capture
	// lacks brings what nothing here shows: a capture filtered with `| except
	// "^set groups "` would pass it unread (pre-flight).
	for _, a := range apps {
		if a.except || defined[a.group] {
			continue
		}
		if slices.ContainsFunc(tpaths, func(t []string) bool { return hasPrefix(t, a.level, false) }) {
			return nil, nil, fmt.Errorf("group %s is applied where it reaches a port49 template, and the capture "+
				"does not carry its definition: capture the whole configuration with `%s`", a.group, ConfigCapture)
		}
	}
	// A group statement that lands on a template: named on the template's
	// line where the capture carries it, and the capture refused as not
	// inherited where it does not and the template writes no harmless leaf of
	// that name itself (decision 44 ruling 7).
	for _, gs := range groups {
		for _, t := range tpaths {
			if len(gs.path) <= len(t) || !groupAt(gs.path, t) {
				continue
			}
			at := append(slices.Clone(t), gs.path[len(t):]...)
			if !appliesAt(apps, gs.group, at) {
				continue
			}
			stmt := gs.path[len(t)]
			other := map[string]string{"class": "user", "user": "class"}[t[2]]
			if known := func(kind string) bool {
				return slices.Contains(privilegeTemplateStatements[kind], stmt) ||
					slices.Contains(harmlessTemplateStatements[kind], stmt)
			}; !known(t[2]) && known(other) {
				// A `<*>` over both containers: the statement is the other
				// kind's, and Junos expands it only where it is valid.
				continue
			}
			key := strings.Join(at, " ")
			own := strings.Join(append(slices.Clone(t), stmt), " ")
			switch {
			case paths[key]:
				for _, i := range extraAt[key] {
					extra[i].Says = groupSays(gs.group, t, stmt)
				}
			case slices.ContainsFunc(sortedKeys(paths), func(p string) bool { return p == own || strings.HasPrefix(p, own+" ") }):
				// The template writes the statement itself. A harmless leaf
				// of its own stands over the group's (L57). Anything else is
				// named at the group's line: whether Junos adds a group's
				// value beside the template's, as a leaf-list such as
				// permissions might, is L57's "group permission beside
				// own", and the group is one Ryan's ruling names either way.
				if !slices.Contains(harmlessTemplateStatements[t[2]], stmt) {
					extra = append(extra, ConfigFinding{Line: gs.line, Text: gs.text, Says: groupSays(gs.group, t, stmt)})
				}
			default:
				return nil, nil, fmt.Errorf("line %d: group %s applies to %s %s, and the capture does not carry what it "+
					"adds there: capture the whole configuration with `%s`", gs.line, gs.group, t[2], t[3], ConfigCapture)
			}
		}
	}
```

  Add `"path"` to the imports. Update `TemplateDrift`'s doc comment: the capture is
  `ConfigCapture`; a group is read where it lands and named; the harmless statements pass; a
  capture lacking an applied group's expansion is an error; its two old error texts name
  `ConfigCapture` in place of `show configuration | display set`.

  Apply the L57 gates from Task 3: `ConfigCapture`'s order; `nestedApplies`.

- [ ] **Step 5: Point the lab's NETCONF switch at the set.** In `tests/lab/projection_test.go`:
  `func netconfForbidden(d adapter.Dialect) bool { return adapter.NetconfForbidden(d) }`, its
  comment saying set 1.1.0 forbids NETCONF and set 1.2.0 does not.

- [ ] **Step 6: Run**

Run: `go test ./internal/platform/ ./cmd/port49/ -count=1 && go vet -tags lab ./tests/lab/`
Expected: PASS once these existing tests are moved to the rulings, each case still failing (a
finding or an error) unless a ruling says it passes. Measured in pre-flight against this task's
code, these are the ones that change:
  - `TestTemplateDriftFailsEveryWayToCarryMore`: "a group applied to the class" (`apply-groups
    wide`, no definition) now errors, naming `ConfigCapture`: move it to a loop that wants an
    error. "a group setting a template class", "a wildcard group" and "a wildcard group above"
    define a group nothing applies, which ruling 7 passes: add `set apply-groups wide` to each
    and move them to the error loop ("does not carry what it adds"; for "a wildcard group above",
    the class `p49-readonly` writes its own `permissions`, so it is a named finding at the group's
    line, `group wide adds `permissions``, not an error). The idle-timeout case now has no extra
    (`idle-timeout` is harmless; the reference's line is still missing): want `len(extra) == 0`.
  - `TestTemplateDriftReadsQuotedAndNestedPaths`: `set groups g logical-systems <*> system login
    class p49-readonly permissions all` gains `set apply-groups g` and is the same named finding.
  - `TestCheckServicesBypasses`: the group definitions (`set groups g system services netconf
    ssh`, the quoted, capitalized and logical-system forms) move to the findings list (one
    finding each); `set apply-groups g`, `set system apply-groups g`, `set logical-systems ls1
    apply-groups g` and `set logical-systems ls1 Apply-Groups g` pass (no finding, no error); `set
    system services apply-groups g` is one finding (an unknown word under `system services`).

- [ ] **Step 7: Commit**

```bash
git add internal/platform cmd/port49/devices.go tests/lab/projection_test.go
git commit -m "feat: check-config reads configuration groups and checks services by set

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: `port49 devices check-config --batch`

**Files:**
- Modify: `cmd/port49/devices.go` (`checkConfig` split; doc comment)
- Modify: `cmd/port49/main.go:84` (usage)
- Test: `cmd/port49/devices_test.go`

**Interfaces:**
- Consumes: `checkConfigFixture`, `policyFixture` (`cmd/port49/devices_test.go`).
- Produces: `--batch`; `type checkRun struct`; `func (c checkRun) one(device, file string) int`.

- [ ] **Step 1: Write the failing test** in `cmd/port49/devices_test.go`:

```go
// --batch checks every capture against the device its file name names, keeps
// going past one it cannot read or place, and exits 1 where any fails
// (decision 44 ruling 8).
func TestCheckConfigBatch(t *testing.T) {
	pol, inv := policyFixture(t)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	clean := write("leaf-01.cfg", "hostname leaf-01\nusername breakglass privilege 15 secret 0 x\n"+
		"aaa authorization exec default group port49 local\naaa authorization commands all default group port49 local\n")
	sub := filepath.Join(dir, "b")
	os.Mkdir(sub, 0o700)
	collides := filepath.Join(sub, "leaf-01")
	os.WriteFile(collides, []byte("hostname leaf-01\nusername noc privilege 1 secret 0 y\n"), 0o600)
	unknown := write("nosuch.cfg", "hostname nosuch\n")
	// A file that cannot be read, named for a device the inventory has, so
	// the read is what fails (the device is looked up first).
	missing := filepath.Join(dir, "c", "leaf-01.conf")

	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--batch",
		clean, collides, unknown, missing}, &out, &errb)
	all := out.String() + errb.String()
	for _, want := range []string{
		"on leaf-01 (arista_eos), 0 findings\n",
		`COLLISION: ` + collides + `:2: a device-local account "noc"`,
		`device "nosuch" is not in the inventory`,
		filepath.Join("c", "leaf-01.conf"),
		"batch: 4 configurations checked, 3 failed\n",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	if code != 1 {
		t.Errorf("code %d", code)
	}
	out.Reset()
	if code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--batch", clean},
		&out, &errb); code != 0 || !strings.Contains(out.String(), "batch: 1 configurations checked, 0 failed") {
		t.Errorf("clean batch: %d\n%s", code, out.String())
	}
	for _, args := range [][]string{
		{"devices", "check-config", "--policy", pol, "--inventory", inv, "--batch"},
		{"devices", "check-config", "--policy", pol, "--inventory", inv, "--batch", "--device", "leaf-01", clean},
	} {
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%q: code %d", args, code)
		}
	}
}
```

  Add one more case in the same test, with its own inventory (copy `policyFixture`'s and rename
  the device `leaf-01.example.net`): a file named `leaf-01.example.net`, no extension, as
  Oxidized writes an FQDN, is checked against that device, not `leaf-01.example`.

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./cmd/port49/ -run TestCheckConfigBatch -count=1`
Expected: FAIL (`flag provided but not defined: -batch`, code 2).

- [ ] **Step 3: Implement.** In `checkConfig`, add the flag and the usage rule, and split the
  per-device body out unchanged in its words except that `fs.Arg(0)` becomes `file` and
  `*device` becomes `device`:

```go
	batch := fs.Bool("batch", false, "check each CONFIGFILE against the inventory device its file name names, "+
		"as it is or less its last extension (srx-01.conf is srx-01): the CI form")
	...
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || *batch && (*device != "" || fs.NArg() == 0) || !*batch && (*device == "" || fs.NArg() != 1) {
		fmt.Fprint(stderr, usage)
		return 2
	}
	out, errOut, flush := redactOutput(stdout, stderr)
	defer flush()
	stdout, stderr = out, errOut
	p, err := files.load()
	if err != nil {
		fmt.Fprintln(stderr, "port49 devices check-config:", err)
		return 1
	}
	out.learn(p)
	errOut.learn(p)
	c := checkRun{p: p, files: files, cfgPath: *cfgPath, stdout: stdout, stderr: stderr}
	if !*batch {
		return c.one(*device, fs.Arg(0))
	}
	// Every file is checked whatever one before it found (decision 44
	// ruling 8): a CI run reports the fleet, not its first failure.
	worst, failed := 0, 0
	for _, file := range fs.Args() {
		// The name as it is where the inventory has it (Oxidized's files,
		// an FQDN), else less its last extension (decision 44 ruling 8).
		name := filepath.Base(file)
		if _, ok := p.Device(name); !ok {
			name = strings.TrimSuffix(name, filepath.Ext(name))
		}
		code := c.one(name, file)
		if code != 0 {
			failed++
		}
		worst = max(worst, code)
	}
	fmt.Fprintf(stdout, "batch: %d configurations checked, %d failed\n", fs.NArg(), failed)
	return worst
}

// checkRun is what every file of one check-config run is read against.
type checkRun struct {
	p              *policy.Policy
	files          policyFiles
	cfgPath        string
	stdout, stderr io.Writer
}

// one checks file as device's configuration and prints its findings: 0 clean,
// 1 a finding or a file it could not read, 2 a usage or nothing-checked
// outcome, as a single check-config exits.
func (c checkRun) one(device, file string) int {
	p, stdout, stderr := c.p, c.stdout, c.stderr
	rules := p.Redactions()
	redact := func(line string) string { return platform.RedactConfigLine(rules, line) }
	// … the body from `d, ok := p.Device(*device)` to the end of today's
	// checkConfig, with fs.Arg(0) → file, *device → device, *cfgPath →
	// c.cfgPath, and files → c.files …
}
```

  Add `"path/filepath"` and `"github.com/rhwendt/port49/internal/policy"` to the imports if not
  present. Update the doc comment (the `--batch` form; the capture is `platform.ConfigCapture`)
  and `main.go`'s usage line:

```
  port49 devices check-config --policy FILE --inventory FILE [--config PORT49D_YAML]
                              (--device NAME CONFIGFILE | --batch CONFIGFILE...)
```

- [ ] **Step 4: Run**

Run: `go test ./cmd/port49/ -run CheckConfig -count=1`
Expected: PASS, every existing `TestCheckConfig*` unchanged.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/devices.go cmd/port49/main.go cmd/port49/devices_test.go
git commit -m "feat: port49 devices check-config --batch

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Lab run — set 1.2.0 end to end (cell c), check-config on L57; close L26c and L57

**Files:**
- Modify: `tests/lab/projection_test.go` (`TestProjectionDifferential` runs per set;
  `projectionShape` takes the set; `projectionNetconf` expects NETCONF refused where the reply
  carries the entry deny; a 1.2.0 shape list)
- Create (by the run): `tests/lab/results/L26c-projected-juniper_*.md`, evidence
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L26c and L57 rows and bullets;
  decision 44's "provisional"; §8's "*Provisional on L26c*")

**Interfaces:** Consumes everything above; `make build` first, so `bin/port49` is this branch's.

- [ ] **Step 1: Run the differential under a named set.** Change `projectionShape`'s first line
  to take `set string` and write `"platform_set: " + set + "\n…"`, and `projectionNetconf`'s
  `off bool` to `want string` (`"disabled"`, `"refused"` or `"open"`):

```go
	n, hello, err := l.netconfDial(sliceUser, tok)
	switch want {
	case "disabled", "refused":
		if err == nil {
			n.Close()
			t.Errorf("%s: NETCONF opened, and the reply %s it", name, map[string]string{
				"disabled": "runs on a set that requires it disabled", "refused": "denies junoscript, which refuses"}[want])
			return "\nNETCONF opened, which the reply should have refused.\n"
		}
		return "\nNETCONF " + want + ", as the reply requires: `" + oneLine(err.Error()) + "`\n"
	}
	// "open": the existing RPC fail-open checks, unchanged.
```

  In `projectionShape`, pass `want` as `"disabled"` where `adapter.NetconfForbidden(set)`,
  `"refused"` where `res.Projection.NetconfClosed() || res.Projection.FailClosed != ""` (both
  refuse `junoscript`), else `"open"`. Also type `xml-mode netconf need-trailer` at the CLI after
  the probes, through `entryXMLMode` (Task 2), and fail the shape where it is `hello` under a reply
  that refuses `junoscript`. Add:

```go
// projectionShapes120 are cell (c): set 1.2.0's answer for a deny beneath a
// sent bit. The first two carry a deny of `show configuration` beneath their
// bits and every baseline word permitted, so the only deny beneath is the
// grant's and the reply fits: the capability shape with the entry deny, the
// CLI refusing `show configuration`, NETCONF refused. "operator, all it
// reaches" has no deny beneath and keeps NETCONF: the control. The readonly
// rows are decision 44 ruling 10: `view`, the baseline's denies in one
// alternative with `junoscript` (`xml-mode` sent as nothing, refused through
// it), and allows of view-configuration's carve-outs the deny does not hold,
// sent beyond the bits, whose runs the note records as the device's
// shortfall; "readonly" alone keeps 1.1.0's narrow reply.
var projectionShapes120 = []struct{ name, roles, want string }{
	{"operator, a deny of show configuration beneath its bits", `  - {name: r, privilege: operator, permit: ["show **", ` +
		`"clear **", "ping **", "traceroute **", "request **", "test **", "monitor **", "file **", "help **", "set **", ` +
		`"start **", "op **", "save **", "load **", "scp **", "ssh **", "telnet **", "mtrace **", "probe **", "quit **", ` +
		`"exit **", "junoscript **", "xml-mode **"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"admin keeping a keyword deny", `  - {name: r, privilege: admin, permit: ["**"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"operator, all it reaches", `  - {name: r, privilege: operator, permit: ["**"]}`, projection.ShapeCapability},
	{"readonly denying show configuration", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"readonly denying show security", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show security **"]}`, projection.ShapeCapability},
	{"readonly", `  - {name: r, privilege: readonly, permit: ["show **"]}`, projection.ShapeNarrow},
}
```

  Each readonly row also types `xml-mode` (bare) at the CLI beside `xml-mode netconf
  need-trailer`, and fails the shape where it greets under a reply that refuses `junoscript`
  (`l58EntryCell`, Task 2).

  Before the run, check each row's `want` with this branch's `bin/port49 policy test` on the
  shape's policy (`projectionShape` writes it to `tests/lab/logs/projection-<slug>.yaml`). A row
  whose reply differs gets the shape `policy test` reports, and the note says why, except that
  the first two must render the capability shape with the entry deny, the third with no deny,
  the two readonly-with-a-deny rows the capability shape with `user-permissions=view` and the
  entry deny (owner's ruling 4), and "readonly" the narrow shape. If they do not, STOP and
  report: cell (c), or ruling 10 on the device, would be unmeasured.

  `TestProjectionDifferential` loops over the sets `PORT49_LAB_PROJECTION_SETS` names
  (comma-separated, default `1.1.0,1.2.0`), with `projectionShapes` and `projectionShapes120`
  respectively. It writes `L12-projection` for 1.1.0 as today and `L26c-projected` for 1.2.0.
  Each set's run is its own function, so the NETCONF switch is per set: where
  `adapter.NetconfForbidden(set)` (1.1.0) the run deletes `netconf ssh` and its `defer` puts it
  back before the next set starts; under 1.2.0 `netconf ssh` stays configured, so a NETCONF
  refusal there is the reply's `junoscript` deny and the control's NETCONF opens. (One `defer` at
  the test's top would leave NETCONF deleted for 1.2.0, and the control would fail.) Task 9 runs
  1.2.0 only: L12 is closed and this plan changes nothing 1.1.0 renders (Task 4's frozen-set
  tests), so its note is not rewritten.

- [ ] **Step 2: check-config on the L57 captures with this branch's binary.** The lab policy
  pins no set, so write one that pins 1.2.0, and name each capture for its lab node
  (`tests/lab/inventory-lab.yaml`: `srx1` is vJunos-router, `vsrx1` is vSRX):

```bash
d=$(mktemp -d)
printf 'platform_set: 1.2.0\nscopes:\n  - {name: all_devices, match: {}}\nroles:\n  - {name: r, privilege: readonly, permit: ["show **"]}\nsubjects:\n  - {name: s, identity: ["user:a@example.com"], username: a, token_ttl: 60s}\ngrants:\n  - {subject: s, scope: all_devices, roles: [r]}\n' > $d/policy.yaml
cp internal/platform/testdata/l57-juniper_vjunos-router.set $d/srx1.set
cp internal/platform/testdata/l57-juniper_vsrx.set $d/vsrx1.set
./bin/port49 devices check-config --policy $d/policy.yaml --inventory tests/lab/inventory-lab.yaml \
  --config tests/lab/port49d-lab.yaml --batch $d/srx1.set $d/vsrx1.set
```

  Expected: exit 1; each file's findings name `group p49g-perm` on `p49-remote` (and
  `p49g-inner` where nesting expanded), and `MISSING` lists nothing but what the lab's config
  lacks of `device_config`. Nothing names p49g-tip, p49g-excepted, p49g-unapplied or
  p49g-timeout. Paste the output at the end of each `L26c-projected` note as "check-config on
  L57". If the policy does not load against the lab inventory (a key group, say), add what
  `policy test` asks for to `$d/policy.yaml`.

- [ ] **Step 3: Run per platform**

```bash
make build
for p in juniper_vjunos-router juniper_vsrx; do
  PORT49_LAB_PROJECTION_SETS=1.2.0 PORT49_LAB_PLATFORMS=$p \
    go test -tags lab ./tests/lab/ -run '^TestProjectionDifferential$' -count=1 -v -timeout 120m || break
done
make evidence
```

  Expected: PASS on both; `L26c-projected-juniper_*.md` written. Under 1.2.0 the CLI refuses
  `show configuration` for the operator, admin and "readonly denying show configuration" shapes
  (`show security` for its row) and runs everything else their bits reach; `xml-mode`, `xml-mode
  netconf` and port 830 are refused for every entry-deny shape and for the narrow readonly; and
  "operator, all it reaches" opens NETCONF with every RPC check passing (the control: a failure
  there is INVALID, not a pass). Where a readonly's allow beyond `view` (`show log`, `show
  firewall`, `show policer`, and `show configuration` under the `show security` deny) is refused
  or shows nothing, that is the device narrower than port49, reported, not a failure: record it
  in the note and in the roadmap's as-built, since it decides what such a readonly can read.

- [ ] **Step 4: Close the rows.** Per CLAUDE.md rule 3: edit L26c's Status to
  `closed — measured <date>; tests/lab/results/L26c-juniper_*.md, L26c-junoscript-juniper_*.md, L26c-entries-juniper_*.md, L26c-scripts-juniper_*.md, L26c-projected-juniper_*.md`,
  followed by one paragraph of what each measured (both images agreeing, or the difference). Edit
  L57's Status to `closed — measured <date>; tests/lab/results/L57-juniper_vjunos-router.md,
  L57-juniper_vsrx.md` and what the table showed. Rewrite both detail bullets to the
  observations. Remove "*provisional on L26c*" from §8 and decision 44, and "provisional on L57"
  from decision 44's head. The row closes only on what was measured: every way in its claim
  names reached the control and was read against it on both images. If any was not (an image
  that refused `rest`, say), move that part of the claim to a new open row before closing, and
  leave what rests on it as it is (G2's `rest` stays a finding). If a result contradicts a sentence of §8, decision 44 or the adapter
  comment, fix that sentence, cite the note, and say so in the commit message (CLAUDE.md rule 4).

- [ ] **Step 5: Commit**

```bash
git add tests/lab/projection_test.go tests/lab/results/L26c-projected-juniper_*.md tests/lab/evidence/L26c-projected-*
git commit -m "test(lab): set 1.2.0's projection end to end on vJunos-router and vSRX

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L26c and L57

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Roadmap as built, and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line; Plan 9's 9b1 entry; a new
  `### Plan 9b1 — As built` after `### Plan 9b — As built`)

- [ ] **Step 1: Write "Plan 9b1 — As built"**: the branch and base, each task's commit, what Task
  3's gates decided (G1, G2, G3, G4, the L57 gates, "group permission beside own"), the rows
  closed, anything carried. Say what Task 9 saw a readonly's allows beyond `view` do on each
  image (ran, refused, or ran and showed nothing): that is what a readonly with a show deny can
  read, and if they are refused it is carried as an open question for Ryan (sending
  view-configuration with its other reach denied is the alternative his ruling set aside). Paste
  the Operator notes below, edited to what was built, under it.

- [ ] **Step 2: Verify**

Run: `make test && make vet`
Expected: PASS; paste the real summary lines into the PR body.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: roadmap, plan 9b1 as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Operator notes (for the pull request body)

- **New platform set 1.2.0, and the default.** It is 1.1.0 plus one key on `juniper_junos`,
  `rpc_entry_denies: ["junoscript **"]`, and `save` in its keyword tree. A policy pinned to
  1.1.0 renders exactly as before.
  `port49 platform upgrade --policy … --to 1.2.0` shows the change; `policy diff` gates it until
  the `acknowledge:` entry for `platforms.juniper_junos.rpc_entry_denies` is added.
- **Junos subjects granted everything but a few denies now project.** Under 1.1.0 a grant like
  operator `**` less `show configuration **` got the fail-closed reply. Under 1.2.0 it gets its
  bits, its denies, and `junoscript` denied. The CLI deny then holds, and `xml-mode`,
  `junoscript netconf` and NETCONF on port 830 are refused **for that user only**. `policy diff`
  on the pin move lists each such subject's projection change.
- **A readonly with a show deny now projects.** Under 1.1.0 `show **` less `show configuration
  **` (or less `show security **`, or any deny under `show`) got the fail-closed reply. Under 1.2.0
  it gets `view`, its denies and the baseline's in one regex with `junoscript` (170 bytes for the
  common case), and allows of `show log`, `show firewall` and `show policer`. The CLI deny holds;
  `xml-mode` and NETCONF are refused for that user. `view-configuration` is not sent, so `show
  log`, `show firewall` and `show policer` (and, under a deny elsewhere in `show`, `show
  configuration`) run only through an allow beyond the bits: `policy test` lists them as allows
  the bits do not reach, and the as-built records what the lab images did with them. A readonly
  granted `show **` with no deny renders exactly as under 1.1.0.
- **Who has NETCONF.** A subject whose grant has no deny beneath its bits (an automation account
  granted everything its level reaches) keeps NETCONF. A subject with any such deny does not.
  `policy test` warns `projection_netconf_closed` for each. An Ansible or PyEZ account that needs
  NETCONF needs a grant with no deny beneath its bits.
- **New warning `projection_deny_beneath_view_configuration`.** A policy whose reply sends
  `view-configuration` and denies `show configuration` beneath it (an operator or admin granted
  `**` less that deny) gets a warning, not a refusal. A readonly with that deny gets no warning:
  its reply does not send the bit. The CLI refuses the command and NETCONF is closed, but the bit is what grants
  the configuration, so the real fix is a level without the bit. `policy diff` prints new
  warnings as `warning:` lines and still exits 0 on them.
- **`devices check-config` reads configuration groups.** Capture with
  `show configuration | display set | display inheritance` (the group definitions are now kept;
  the old `| except "^set groups "` capture still works, its groups unnamed). `apply-groups` no
  longer fails the check. A group that adds a permission, a command or configuration regex, or
  authentication to `p49-remote`, `remote` or another port49 template fails, naming the group:
  `group BASE adds `permissions` to class p49-remote: every port49 session on this device gets
  it`. `idle-timeout`, `login-tip`, `login-alarms` and `full-name` pass. Any other statement
  under a template still fails. A capture without `display inheritance` from a device that
  applies a group to a template is refused, with the capture command to use, and so is one that
  applies a group to a template without the group's definition (the old `| except "^set groups
  "` capture, where it prints `apply-groups`): change the CI capture command once, fleet-wide.
- **`devices check-config --batch FILE...`** checks a directory of captures in one run. Each file
  is checked against the device its file name names: the name as it is where the inventory has
  it (Oxidized's extensionless files, FQDNs included), else less its last extension
  (`srx-01.conf` is `srx-01`). It prints `batch: N configurations checked, M failed` and exits 1
  if any failed.
- **Management services under 1.2.0.** NETCONF, the XML API (`xnm-*`), `outbound-ssh` and every
  non-RPC service no longer fail check-config. J-Web (`web-management`) and JET/gRPC
  (`extension-service`) still do, and REST (`rest`) as Task 3 measured. Under 1.1.0 nothing
  changed.
- **No new reason code, metric or config key in `port49d.yaml`.** The decision log records the
  reply as before; the `junoscript` deny appears in it.
