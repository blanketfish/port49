# Plan 5b: Session-Only Projection and Capability Inference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Junos session gets port49's rules for the first time. They are rendered into the session
reply as permission bits and command regexes, proven before sending not to let the device run
anything port49 denies, and measured on both Junos images. A composition that cannot be told to
the device faithfully fails closed for that subject alone. And port49 reads its own decision log to
say which devices ask it about commands at all.

**Architecture:** A new package, `internal/projection`, turns one composition's rules into a Junos
session reply under decision 22. Before returning the reply it proves it against a model of the
device built from the lab's measurements: engine programs over the rules, over the union of the
held bits' reach, and over the measured carve-outs of the bits not held. A composition neither
shape can carry gets the **fail-closed reply** of decision 26, proven the same way. `internal/policy`
calls it from `compile` for any platform whose adapter declares `command_projection`, once per
composition. The reply is then ordinary blob attributes, so the daemon, `policy replay` and every
offline tool carry it unchanged; a fail-closed one is marked on the blob and recorded
`projection_fail_closed`. The projection ships in a new platform set, 1.1.0, so turning it on is a
pin move that `port49 policy diff` reviews. Another new package, `internal/capability`, reads the
decision log to build spec §9's supports-versus-observed matrix and its accounting reconciliation.
A new `account_gap` record, written by the accounting spool whenever it drops a record, qualifies
both.

**Tech Stack:** Go 1.22+ (the module's own `go` line), the standard library, `gopkg.in/yaml.v3`
(already a dependency); containerlab on the lab host (beehive) for Tasks 2, 3, 4 and 19. No new
module dependencies.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §2 (reserved usernames), §8 ("Projection
for session-only platforms" in full, the Fields table, "Knowing what is shipped"), §9 (capability
inference), §5.6 ("Where these controls do not reach", decision 21's lever), §5.7 (the event and
reason tables), §5.8 (system users), §12 (policy test, the diff's gates, check-config, the gated
adapter keys), §13 decisions 21, 22 and the new 26, §15 L9, L10, L12 and the new L23, L24 and
L25. Roadmap `docs/superpowers/plans/README.md`, "Plan 5a — As built" and "Plan 5b". The lab
notes decide every value an adapter ships (`CLAUDE.md`, "The lab register is the source of
truth").

**Prerequisite:** plan 5a merged (PR #13). Branch `feature/session-projection` off `main` at the
plan commit that adds this file.

## Questions for Ryan

None are open. Owner's ruling 2026-09-25 settled the one the pre-flight review raised (decision
26, below), and the controller ruled each finding that left a choice. Where the design still left
one, this plan took the option that denies more and records it under Decided.


Amendment 1's one question, how decision 27 reads a trailing `**`, is ruled (below): the plan's
reading stands.

## What changed after the pre-flight review

The pre-flight review of the first version (2 Critical, 15 Important, 8 Minor) is folded in. Each
finding, and where it is fixed:

- **C1**, the device model read every narrower reach of an unheld bit as a carve-out and dropped
  denies the device does not enforce: the bits are now a union, and only an explicit, measured
  `carve_outs` list subtracts. A block adding reach is a gated widening (Decided 3; Tasks 6, 8).
- **C2**, the overflow report told the operator to put one subject's allows into a shared class:
  a class line is printed for `deny-commands` only (Decided 9; Task 11).
- **I1**, numbered and case variants of the projection's names: `Dialect.ProjectionOwns` (Task 6).
- **I2**, a `$`-anchored deny against a piped line: every deny ends in a pipe tail, and Task 2
  probes `show version | no-more` (Decided 5; Tasks 2, 7).
- **I3, I4, I5, I15**, the lab probes: a no-bit control and an `all` control, the host name
  `srx1`, holds that wait for the prompt, and probes that abbreviate, upper-case and pipe the
  denied commands, run the baseline, and try configuration mode (Tasks 2, 3, 19).
- **I6, I7**, lab outcomes with no branch, and a hunk that depended on candidate values: Task 14's
  Step 4 names every outcome with its fail-closed edit, the tests it adds assert no candidate
  value, and Task 20 anchors on lines no branch moves.
- **I8, M8**, the additive export and the unchecked template classes: the export is a replace, and
  `check-config` holds the device to it (Task 13).
- **I9**, template users: `remote` and `p49-*` are refused as usernames at load and at the mint,
  and Task 2 measures whether a template user can log in locally (Decided 18; Tasks 2, 9, 13).
- **I10, M10**: `policy test` fails on any quarantine or fail-closed reply, and `platform upgrade`
  previews both (Tasks 11, 14).
- **I11**: the narrow shape takes the smallest covering bits (Task 8).
- **I12**: each composition is projected once per policy; 1,000 SRXs and 20 subjects load in about
  0.2 s, and a test holds the bound at 2 s (Task 9).
- **I13**: "never seen" is a note and exits 0 (Tasks 17, 18).
- **I14**: a projected reply is judged by what the device can do under it (Decided 9; Task 12).
- **M1, M2**: no empty group; a deny's `*` and pattern positions admit a space (Task 7). Task 2
  also sends a malformed deny.
- **M3, M5**: every missed prompt fails the test; the watchdog allows the N9Kv's bring-up and
  cleans up after a `go test` timeout ("Running the lab").
- **M6**: the `account_gap` text says what the code does (Tasks 1, 16).
- **M7**: L25 also asks whether an NX-API session as `admin` carries `vsh.bin` (Tasks 4, 15).
- **M9**: the overflow's value is redacted (Task 11).

## Amendment 1 (2026-09-25): Junos matches keywords only

**The finding.** Task 2 measured, on vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15 alike
(`tests/lab/results/L12-juniper_*.md`, `L9-juniper_*.md`, commit `2b8d131`; the lead's
`task-2-report.md`), that Junos matches `deny-commands` and `allow-commands` against a command's
**keywords** as the CLI expands them, never its arguments. `^show interfaces fxp0( .*)?$` did not
stop `show interfaces fxp0 terse` or `sh int fxp0 terse`. Keyword denies work: the anchors with the
pipe tail, the narrow shape, the baseline under `.*`, and `sh ver` refused. port49 has no Junos
grammar, so it cannot tell a keyword from an argument.

**The owner's ruling, 2026-09-25** (spec §13 decision 27, which this amendment's commit adds):
- A Junos deny whose every word is proven a keyword is sent as written. The proof is a keyword list
  captured in the lab and shipped in set 1.1.0.
- A deny naming any word not proven a keyword cannot be enforced on Junos: `policy test` and `policy
  diff` fail with "Junos can't deny by argument: `fxp0` in `deny show interfaces fxp0`; deny the whole
  command (`show interfaces`) or drop the rule", and at runtime that subject gets decision 26's
  fail-closed reply. port49 never widens the deny itself.
- An allow naming an argument never matches on Junos, so it fails closed: the user cannot run it,
  and `policy test` warns.
- Class, regex and `*` terms get the same treatment: anything port49 cannot prove keyword-only
  counts as naming an argument.

**Two more inputs, the same day.**
- **`deny-commands` does not reach configuration mode**, measured on both images
  (`tests/lab/results/L12-configuration-juniper_vjunos-router.md`, `L12-configuration-juniper_vsrx.md`):
  in a class holding `configure`, `system` and `system-control`, `set system host-name srx1` ran in
  configuration mode under `deny-commands=^set system host-name( .*)?$`, as in the control. The
  generator must never rely on deny-commands to stop a configuration statement. A deny naming one,
  or able to match one, fails like an argument deny: `policy test` fails with a clear message, and
  that subject gets the fail-closed reply. The lead's exception, a composition whose configuration
  bits are dropped entirely, is not taken (pre-flight B-M2): such a deny still fails closed,
  because port49 cannot prove its words are not an operational command the capture never saw, and
  the message says to drop the rule. `deny-configuration` support is not added here; it is carried.
- **Whether deny-commands binds a NETCONF RPC is unmeasured** (pre-flight B1). The token that opens
  the CLI opens `ssh -s netconf` with the same reply. If denies bind CLI lines only, every deny is
  walked around by the equivalent RPC (`<get-configuration>` past `deny show configuration **`).
  Task 3b measures it, because the answer can change set 1.1.0 (Task 14, branch M), and Task 19
  keeps a NETCONF check.
- **`DenyMatchesExpanded` stays false in set 1.1.0** (the lead's ruling) until more abbreviations are
  measured: Task 2's reading rests on one (`sh ver`). Task 3b adds a probe set, and Task 14's branch B
  sets it true only if every probe is refused on both images. Until then compositions that rely on
  it keep the fail-closed reply.

**How the plan reads it** (each the option that denies more, or the one the measurement proves):
1. **A rule is keyword-only** where its terms are words, optionally ending in `**` (the grammar
   allows `**` last only), and each word is a keyword the tree lists at its place. A trailing `**`
   is proven for a deny: the device refuses every command whose keywords begin with the deny's
   words, which is every command port49's deny matches, and more. That is the realistic readonly's
   `deny show configuration **`, spec §11's `show chassis cluster **` and every carve-out. It is
   ruled (below).
2. **The deny that matters is one that meets a permit.** One that meets none is port49's
   `no_rule_matched` either way and never needs the wire, so it does not fail anything. One that
   meets a permit and names an argument fails closed (`argument_deny`) with the ruling's message;
   the "whole command" it suggests is the deny's proven keyword prefix. A capability shape whose
   bits reach an unprovable deny that no permit meets goes narrow, where `.*` holds it.
3. **An allow is sent only where the device runs exactly what port49 permits under it**:
   keyword-only, and no argument may be typed before any of its words, or after its last where no
   `**` follows. `allow show interfaces terse` is not sent, since the device would also run `show
   interfaces fxp0 terse`, which port49 does not permit; it is warned about like an allow naming an
   argument. Unsent allows make the device narrower, never wider.
4. **The keyword tree** (`platform.Keywords`) records, per captured command path, the keywords
   proven there and whether an argument may be typed there. **A word is a keyword only on positive
   evidence** (the lead's ruling on this amendment's pre-flight A1): the CLI offers it by completion
   at that exact place, and its own RPC shows it a keyword — an element named as the word and no
   element holding it as text (`show interfaces terse` is `<terse/>`), an RPC with no text where the
   path alone still asked for a `<command>` (`show route`), or a path still asking for a
   `<command>` (`show chassis`). Absence of evidence is an argument: no RPC (`monitor traffic
   interface fxp0`, `help`, `set cli`), an error asking for anything but a command (`ping
   routing-instance mgmt_junos`, which still needs a host), RPC text that differs from the word, and
   a timeout. **The capture types nothing that acts or streams** (pre-flight A2): it first proves on
   `show system uptime` and `show version` that `| display xml rpc` shows the RPC and runs nothing,
   then walks only under `show`. Every other top-level word is proven a command name by the top-level
   listing, and nothing under it is proven, so `deny request system reboot **`, `deny clear bgp **`
   and `deny monitor traffic **` fail closed as argument denies; `deny clear **`, `deny request **`
   and `deny monitor **` go out. So, in set 1.1.0 as the lab's facts stand (re-pre-flight R-M2,
   R-M6): with `DenyMatchesExpanded` false no deny but `.*` reaches the wire, and **any Junos
   composition with a deny beneath a permit gets the fail-closed reply**; the device differential
   covers the narrow shape, the fail-closed reply and capability shapes with no deny. A path the
   capture did not reach proves nothing, a keyword on one image only is not proven (the merge
   keeps what every image proves, and an argument on any image), and the tree is the set's
   measurement: it lives outside the adapter, in `platforms/keywords/<set>/<platform>.yaml`, and no
   `platforms:` block can touch it. It is bounded: the capture walks its seeds' prefixes first and
   stops at 4,000 nodes and 20,000 commands per image, and a tree past 5,000 nodes or 1 MiB is
   refused at load. **Its scope is the two lab images** (vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15):
   on another release or hardware family a word it proves a keyword could take an argument, and a
   keyword deny would fail open there (pre-flight A-M5). The adapter comment and §8 say so, and
   "capture per fleet release" is carried. An argument completion never lists (a hidden one) is
   invisible to the capture, so an exact allow could run with one; the stake is a read command under
   `show`, and L26's note says so (A-M4).
5. **The proof and its witness need no argument matching.** Only keyword-only rules reach the wire,
   and for those the device matches at least what the model's deny program matches and exactly
   what its allow program matches, so the model remains an over-approximation of what the device
   runs. Task 7's handling of arguments inside a deny (spaces, `.+`) now decides nothing, since no
   such rule is sent; it stays, harmless.
6. **`DenyMatchesExpanded` is about keyword abbreviations only**, and stays `false` until Task 3b's
   abbreviation probes are all refused on both images. Task 2 read `sh ver` refused under the anchored
   deny, one sample; Task 3b's `TestL9JunosAbbreviations` types twenty-one: five denied commands of
   two and three keywords, each abbreviated at several lengths, two piped, and one ambiguous at the
   second level. Branch B sets the fact `true` only where both images' notes say `true`.
7. **Configuration mode never depends on `deny-commands`.** A reply that lets the session enter
   configuration mode — a bit whose reach holds `configure` or `edit`, its alias, or an allow meeting
   either (pre-flight B-M1) — carries no deny
   at all (Task 8's `configuration`; the grant must be every command with no deny), so nothing a
   deny names is ever left to deny-commands in configuration mode. The admin-with-deny path under
   `user_permissions` drops every bit that enters configuration mode and refuses an allow meeting
   `configure`, so the device refuses `configure` itself (Task 12a's test asserts it), and its safety
   rests on the bits, not on any regex. A deny that meets a permit, begins with a configuration verb
   (`set`, `delete`, `edit`, `activate`, …) and is not an operational command the keyword tree proves
   fails closed as `configuration_deny`, whose message says why: "`deny set system host-name **`
   names a configuration statement, and Junos never applies deny-commands in configuration mode …
   port49 cannot enforce it: drop the rule". One the tree proves an operational command is sent,
   since no reply that carries it can configure; 1.1.0's tree proves nothing under `set` (item 4),
   so the baseline's `set cli **` is not sent either, and a capability shape that would need it
   goes narrow, where `.*` holds it. `deny-configuration`
   and `-regexps` over the wire are carried to a later plan.
8. **A set update refreshes the tree** by rerunning Task 3b on the new set's images, merging with
   `junos-keywords`, and shipping it under the new set's directory. A released set's tree is frozen
   (Task 20). A pin move that changes the tree changes replies, which the diff's reply gate judges
   (Task 12).

**Ruled: a trailing `**`** (the lead, 2026-09-25; the `**` in the ruling's wording was the lead's,
not the owner's). A trailing `**` on a deny whose other words are all proven keywords is proven,
because the device refuses by keyword prefix and so refuses at least what port49 denies: `deny show
configuration **` and `deny show chassis hardware **` are keyword denies (`cluster` is not a keyword
on vJunos, so `deny show chassis cluster **` fails closed on the merged tree). A `**` or `*` anywhere else, or a
trailing `**` after an argument, counts as naming an argument. This is what `keywordShape` and
`argument` already do (Task 12a), and decision 27 says it. Task 19's "a deny aligned with a bit"
and "a class term" shapes exercise the trailing case on the device.

**Order of execution.** 1 → **1a** → 2 → 3 → **3b** → 4 → 5 … 12 → **12a** → **12b** → 13 → **13a** → 14
(amended) → 15 … 18 → 19 (amended) → 20 (amended). Tasks 1, 2 and 5 are done; Task 6 is in its fix
round. Every block below was generated from a commit that went green, and the whole order was
verified from the branch head `813b910`: each block applies in order, and `gofmt`, `go vet`, `go vet
-tags lab` and `go test ./...` pass after every task, Task 14 run with a stand-in capture in place of
Task 3b's. If Task 6's fix round moves a line these blocks touch, apply with `git apply -3`; none of
them edits `internal/platform/adapter.go`, `dialect.go` or `internal/policy/load.go`.

**Changes to existing tasks, in one place:**
- **Task 7**: unchanged; see item 5.
- **Task 8**: Task 12a adds the keyword checks to the generator it writes. Its test
  `TestATemplateCarriesTheLevelsBits` now expects the deny as Task 7's fix `eaf7975` renders it,
  `^ *[sS]…( .*)? *(\|.*)?$`, so the block applies and passes on the branch.
- **Task 11**: its `TestProjectionFindings` now expects the overflowing deny's class line to open
  `^( *[sS]`, the rendered shape since `eaf7975`. An `argument_deny` composition is a `projection_refused` finding with the
  ruling's message, and fails `policy test` as every fail-closed composition does. Task 12b adds the
  warning.
- **Task 12**: unchanged; `policy diff` fails on the same finding.
- **Task 13a**, new: the management-service allowlist `check-config` applies when branch M turns it
  on (`platform.CheckServices`), off by default.
- **Task 14**: new step, "Ship the keyword tree"; branch B keeps `DenyMatchesExpanded` false unless
  every Task 3b abbreviation probe is refused on both images; new branch B2 reverts the rendered deny
  shape if the device does not enforce it; new branch M acts on the NETCONF
  measurement; branch J records that deny-commands does not reach configuration mode; branch A lists nothing about arguments, which decision 27
  handles.
- **Task 19**: five more shapes and one more probe.
- **Task 20**: L26 closes, the tree is frozen, and the roadmap records decision 27.

### Task 1a: The spec records decision 27, before the code

**Done in the amendment's own commit** (docs only). It changed `docs/design/2026-08-23-policy-engine-spec.md`:
- §5.7: `projection_fail_closed`'s reasons gain `argument_deny` and `configuration_deny`.
- §8 "As built": a paragraph "Junos matches keywords only", the keyword tree, what is sent and
  what fails; `DenyMatchesExpanded` is about keyword abbreviations; Task 7's argument handling
  decides nothing now.
- §8 "Generator constraints": 8, "Never emit a regex that names an argument"; the fail-closed
  paragraph lists the argument deny.
- §12: a table of the projection report codes, `projection_argument_allow` new, and which fail
  `policy test` and `policy diff`.
- §13: decision 27, the owner's ruling of 2026-09-25, amending decision 22.
- §15: L9 and L12 gain the argument clause and Task 2's measurement, L12 the configuration-mode
  measurement, and L9 the abbreviation probes; L26, the keyword tree, is new and open.
- §8 and decision 27 also say that deny-commands never reaches configuration mode, that no reply able
  to configure carries a deny, and that `configuration_deny` fails closed.

Check: `git show --stat <this amendment's commit>` lists the spec and this plan and nothing else.

### Task 3b: (lab, on beehive) The Junos CLI keyword tree, and keyword abbreviations: L26 and L9

**Files:**
- Create: `tests/lab/junos_keywords_test.go`, `tests/lab/junos_abbrev_test.go`,
  `tests/lab/junos_netconf_test.go`
- Results (written by the run): `tests/lab/results/L26-juniper_vjunos-router.md`,
  `L26-juniper_vsrx.md`, the trees `L26-keywords-juniper_vjunos-router.yaml`,
  `L26-keywords-juniper_vsrx.yaml`, `L9-abbreviations-juniper_*.md` and `L12-netconf-juniper_*.md`;
  evidence `L26-juniper_*.pcap`, `L9-abbreviations-juniper_*.pcap`, `L12-netconf-juniper_*.pcap`

**Interfaces:**
- Consumes (harness): `eachPlatform`, `l.capture`, `l.junosCLI`, `junosPrepare`, `c.sendExpect`,
  `c.expectFrom`, `junosOpPrompt`, `junosPer`, `l.result`, `root`, `breakglassUser`,
  `breakglassPassword`; Task 2's `junosSession`, `junosConfigureAdmin`, `junosRun`, `tableCell`,
  `commitWord`, `l.configPath`, `l.restart`, `l.derivedConfigCmd`, `l.nextLogin`; the harness's
  `netconfDial`, `netconfConn.rpc`, `netconfPort`.
- Produces, for Task 19: `junosNetconfRPCs` and `netconfCell`.
- Produces: the two per-image trees Task 14 merges, in the form `platform.ParseKeywords` (Task 12a)
  reads.

Over the break-glass CLI, which holds every permission and so sees every command, the test first
proves the capture inert: `show system uptime | display xml rpc` and `show version | display xml
rpc` must show their RPCs (`get-system-uptime-information`, `get-software-information`) and none
of their output (`System booted`, `Junos:`), or the test fails before the walk (pre-flight A2). It
then walks only under `show`, which acts on nothing; every other top-level word is recorded as a
command name from the top-level listing, and nothing under it is typed, so a word under it is
unproven. At each path it types `<path> ?` and reads the words offered; an `<argument>`
placeholder among them means an argument may be typed there. Each offered word is proven a
keyword only on positive evidence from `<path> <word> | display xml rpc` (item 4 above); anything
else — no RPC, an error asking for anything but a `<command>`, the word as an element's text, text
that differs from it — is an argument and marks the path as taking one. A prompt that does not come
back within `junosPer` is interrupted with ^C and the word is an argument; one that does not come
back after that either is not observed and fails the test. Where the path's completion offered an
`<argument>` placeholder, only an RPC naming the word proves it: "expecting <command>" after an
argument could also mean a mandatory keyword follows the value (re-pre-flight R-M1).

Bounds: the prefixes of the seed list (spec §11's `show chassis cluster status`, the carve-out,
the lab's and the fleet's show commands) first, so the bounds never cut them off (A-M1); then every
path under `show` of up to 2 words, to 4 words; at most 4,000 nodes and 20,000 commands per image.
The note says whether the walk stopped at a bound, which words were offered and not proven, and
what the capture cannot see (hidden arguments; other releases). The test fails if `show`, `show
interfaces`, `show version`, `show interfaces terse`, `show system` or `show system uptime` is not
proven, since then it misread the device. It logs a progress line every 100 commands, well inside
the watchdog's bound (A-M2), and spends no token: the break-glass account is local.

`TestL9JunosAbbreviations` measures `DenyMatchesExpanded` for keywords. Over a class holding every
bit, a control session and a session under one deny naming five commands of two and three keywords
(with the pipe tail) each type twenty-one probes: every command in full, abbreviated at several
lengths (`sh ver`, `sho vers`, `show versi`; `sh int ter`, `sh interfaces te`), piped (`sh ver |
no-more`, `sh int ter | count`), and `sh i terse`, which is ambiguous after `show`. The control's
answer says which probe is ambiguous on the image; one it refused for any other reason measured
nothing and fails the test. The note's line `JunosFacts.DenyMatchesExpanded (keywords) = true`
holds only where the deny refused every probe and the control ran every unambiguous one. The deny
is written exactly as the generator renders one since Task 7's fix `eaf7975`: a leading ` *`,
words joined by ` +`, the tail ` *(\|.*)?` that takes trailing spaces and a pipeline, and one
alternation (` *show +version *(\|.*)?`, …; pre-flight B-M3). Before the abbreviations, the note
reads whether that shape is enforced at all: every one of the five commands in full, and `show
version | no-more`, run by the control and refused under the deny (Task 14's branch B2).
Four odd probes, from the Task 7 review, are recorded whatever the control does: `ſhow version`
(U+017F, which case-folds to `s`), and a denied command padded with leading and with trailing
spaces, no pipe. Where the control runs one, the deny must refuse it, or the fact stays false. It
spends two seeded tokens.

`TestL12JunosNetconf` measures whether a wire deny, and the fail-closed reply, bind a NETCONF RPC
(pre-flight B1). Four NETCONF sessions, each opened with a fresh token under its own reply, send four RPCs:
`<get-configuration/>`, a filtered `<get-configuration>` of `<system/>`, `<command>show
configuration</command>`, which runs CLI text over NETCONF (re-pre-flight R-M3), and
`<get-software-information/>`, the equivalents of `show configuration`, `show configuration
system` and `show version`: a control class holding view and view-configuration; the same class under a
deny naming both commands, as rendered; the fail-closed reply with no template (`remote`'s class);
and the fail-closed reply over a bitless template with `user-permissions=view view-configuration`.
The hello has 45 s and each RPC 60 s; a reply that is neither the output nor an `<rpc-error>` is
not observed and fails the test. The note's line `deny-commands and the fail-closed reply bind
NETCONF RPCs: true` holds only where the control ran every RPC and every other session refused
every one. It
spends four seeded tokens, six with the abbreviations, of the sixteen.

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/junos_keywords_test.go -->
````diff
diff --git a/tests/lab/junos_keywords_test.go b/tests/lab/junos_keywords_test.go
new file mode 100644
index 0000000..e3f2239
--- /dev/null
+++ b/tests/lab/junos_keywords_test.go
@@ -0,0 +1,423 @@
+//go:build lab
+
+package lab
+
+import (
+	"fmt"
+	"os"
+	"path/filepath"
+	"regexp"
+	"slices"
+	"strings"
+	"testing"
+)
+
+// TestL26JunosKeywords captures the Junos CLI keyword tree the projection
+// proves rules against (spec §13 decision 27; §15 L26). Junos matches a
+// deny-commands or allow-commands regex against a command's keywords only
+// (tests/lab/results/L12-juniper_*.md), and port49 has no Junos grammar, so a
+// rule reaches the wire only where this tree proves each of its words a
+// keyword.
+//
+// A word is a keyword only on positive evidence (the lead's ruling on the
+// amendment's pre-flight A1). The CLI must offer it by completion at that
+// exact place (`<path> ?`), which alone is not enough, since Junos offers an
+// argument's values there too (interface names, routing instances). And its
+// RPC must show it a keyword: `<path> <word> | display xml rpc` either shows
+// an RPC in which the word is an element's name and no element's text
+// (`show interfaces terse` is `<terse/>`), or an RPC with no text at all
+// where `<path>` alone was still asking for a `<command>` (`show route`), or
+// is itself still asking for a `<command>` (`show chassis`); the last two only
+// where `<path>`'s completion offered no `<argument>` placeholder, since after
+// an argument a mandatory keyword could also be "expecting <command>"
+// (re-pre-flight R-M1). Anything else is
+// an argument: an RPC holding the word as text (`<interface-name>fxp0`), text
+// that differs from the word, no RPC, an error naming anything but
+// `<command>`, and a prompt that did not come back. The two images' trees are
+// merged by intersection (Task 14), so a keyword must be proven on both.
+//
+// The walk runs no command that acts or streams (pre-flight A2). Before it
+// walks, it proves on harmless commands that `| display xml rpc` shows the
+// RPC without running the command: `show system uptime` and `show version`
+// return their RPCs and none of their output. It then descends only under
+// `show`: every other top-level word is a command name, proven by the
+// top-level listing, and nothing under it is typed, so a word under one is
+// unproven and counts as an argument. A prompt that does not come back within
+// junosPer is interrupted with ^C and the word is an argument; if the prompt
+// does not come back after that either, the session's state is unknown, and
+// the test fails as not observed.
+//
+// The walk is bounded: the prefixes of junosKeywordSeeds first, then every
+// path under `show` of up to junosKeywordBreadth words, to at most
+// junosKeywordDepth words, junosKeywordNodes nodes and junosKeywordCommands
+// commands. A path it did not reach proves nothing, so a rule under it fails
+// closed. It logs progress every 100 commands, for the watchdog.
+//
+// It writes tests/lab/results/L26-keywords-<image>.yaml, the tree in the
+// format platform.ParseKeywords reads, and the note. Task 14 merges the two
+// images' files into platforms/keywords/1.1.0/juniper_junos.yaml.
+
+const (
+	junosKeywordBreadth  = 2
+	junosKeywordDepth    = 4
+	junosKeywordNodes    = 4000
+	junosKeywordCommands = 20000
+)
+
+// junosKeywordWalked is the one top-level command the walk descends under:
+// it only shows, and its RPC is shown without running it.
+const junosKeywordWalked = "show"
+
+// junosKeywordSeeds are show commands a policy denies or allows below the
+// breadth: spec §11's example, the carve-out, and the operational commands
+// the lab and the owner's fleet name. Their prefixes are walked first, in
+// full, so the bounds never cut them off (pre-flight A-M1).
+var junosKeywordSeeds = []string{
+	"show chassis cluster status", "show chassis hardware", "show chassis routing-engine",
+	"show configuration system", "show interfaces terse", "show interfaces extensive",
+	"show route summary", "show system users", "show system uptime", "show system processes",
+	"show cli authorization", "show bgp summary", "show bgp neighbor", "show ospf neighbor",
+	"show security policies", "show security flow session", "show version",
+}
+
+// junosPlaceholder is an argument in a completion listing: `<name>`, but not
+// `<[Enter]>`, which says the command is complete there.
+var junosPlaceholder = regexp.MustCompile(`^<[^\[].*>$`)
+
+var (
+	junosRPCTag     = regexp.MustCompile(`<([A-Za-z][A-Za-z0-9_.-]*)[\s/>]`)
+	junosRPCText    = regexp.MustCompile(`>([^<>]+)<`)
+	junosRPCCommand = regexp.MustCompile(`expecting <command>`)
+)
+
+type keywordWalk struct {
+	c        *cliConn
+	logf     func(format string, args ...any)
+	prompt   string
+	nodes    map[string]*keywordNode
+	rpcs     map[string]rpcAnswer
+	commands int
+	values   []string // "<path> <word> (why)": offered, and not proven a keyword
+}
+
+type keywordNode struct {
+	words    []string
+	argument bool
+}
+
+// rpcAnswer is what `<cmd> | display xml rpc` showed.
+type rpcAnswer struct {
+	rpc          bool     // an RPC came back
+	tags, values []string // its element names and texts
+	command      bool     // the device is still asking for a <command>
+	stalled      bool     // no prompt within junosPer, interrupted
+}
+
+func (w *keywordWalk) tick() {
+	w.commands++
+	if w.commands%100 == 0 {
+		w.logf("keyword walk: %d commands, %d nodes", w.commands, len(w.nodes))
+	}
+}
+
+// completion lists what the CLI offers after path: the words, and whether an
+// argument placeholder is among them.
+func (w *keywordWalk) completion(path string) ([]string, bool, error) {
+	w.tick()
+	send := "?"
+	if path != "" {
+		send = path + " ?"
+	}
+	prefix := strings.TrimSuffix(send, "?")
+	from := len(w.c.out.String())
+	if _, err := fmt.Fprint(w.c.in, send); err != nil {
+		return nil, false, err
+	}
+	const none = "No valid completions"
+	out, err := w.c.expectFrom(from, junosPer, w.prompt+prefix, none)
+	if i := strings.Index(out, none); err == nil && i >= 0 && !strings.Contains(out, w.prompt+prefix) {
+		_, err = w.c.expectFrom(from+i+len(none), junosPer, w.prompt)
+		fmt.Fprint(w.c.in, "\x15")
+		return nil, false, err
+	}
+	fmt.Fprint(w.c.in, "\x15")
+	if err != nil {
+		return nil, false, err
+	}
+	var words []string
+	argument, listing := false, false
+	for _, line := range strings.Split(out, "\n") {
+		line = strings.TrimRight(line, "\r")
+		if strings.HasPrefix(line, "Possible completions:") {
+			listing = true
+			continue
+		}
+		if !listing || !strings.HasPrefix(line, " ") {
+			continue
+		}
+		f := strings.Fields(line)
+		if len(f) == 0 || f[0] == "|" || f[0] == "<[Enter]>" {
+			continue
+		}
+		if junosPlaceholder.MatchString(f[0]) {
+			argument = true
+			continue
+		}
+		words = append(words, strings.ToLower(f[0]))
+	}
+	slices.Sort(words)
+	return slices.Compact(words), argument, nil
+}
+
+// rpc is `<cmd> | display xml rpc`, remembered. A prompt that does not come
+// back is interrupted; one that still does not come back is an error.
+func (w *keywordWalk) rpc(cmd string) (rpcAnswer, error) {
+	if a, ok := w.rpcs[cmd]; ok {
+		return a, nil
+	}
+	w.tick()
+	out, err := w.c.sendExpect(cmd+" | display xml rpc", junosPer, w.prompt)
+	var a rpcAnswer
+	if err != nil {
+		fmt.Fprint(w.c.in, "\x03")
+		if _, err := w.c.expectFrom(len(w.c.out.String()), junosPer, w.prompt); err != nil {
+			return rpcAnswer{}, fmt.Errorf("%q did not return a prompt, even after ^C: %w", cmd, err)
+		}
+		a.stalled = true
+	} else if i := strings.Index(out, "<rpc>"); i >= 0 {
+		a.rpc = true
+		// The RPC alone: Junos follows it with a <cli> block whose tags are
+		// no part of the command.
+		body := out[i:]
+		if j := strings.Index(body, "</rpc>"); j >= 0 {
+			body = body[:j]
+		}
+		for _, m := range junosRPCTag.FindAllStringSubmatch(body, -1) {
+			a.tags = append(a.tags, strings.ToLower(m[1]))
+		}
+		for _, m := range junosRPCText.FindAllStringSubmatch(body, -1) {
+			if t := strings.TrimSpace(m[1]); t != "" {
+				a.values = append(a.values, strings.ToLower(t))
+			}
+		}
+	} else {
+		a.command = junosRPCCommand.MatchString(out)
+	}
+	w.rpcs[cmd] = a
+	return a, nil
+}
+
+// keyword reports whether word, offered after path, is proven a keyword
+// there, and if not, why. placeholder is whether path's completion offered an
+// `<argument>` placeholder, in which case only an RPC naming the word proves it.
+func (w *keywordWalk) keyword(path, word string, placeholder bool) (bool, string, error) {
+	a, err := w.rpc(path + " " + word)
+	if err != nil {
+		return false, "", err
+	}
+	switch {
+	case a.stalled:
+		return false, "no prompt within the deadline", nil
+	case a.rpc && slices.Contains(a.values, word):
+		return false, "the RPC holds it as text", nil
+	case a.rpc && slices.Contains(a.tags, word):
+		return true, "", nil
+	case placeholder:
+		return false, "an argument may be typed here, and no RPC names the word", nil
+	case a.rpc && len(a.values) == 0:
+		parent, err := w.rpc(path)
+		if err != nil {
+			return false, "", err
+		}
+		if parent.command {
+			return true, "", nil
+		}
+		return false, "an RPC names it nowhere, and the path was not asking for a command", nil
+	case a.rpc:
+		return false, "the RPC holds text other than the word", nil
+	case a.command:
+		return true, "", nil
+	}
+	return false, "no RPC, and no <command> asked for", nil
+}
+
+// seeded reports whether path is a prefix of a seed, word for word.
+func seeded(path []string) bool {
+	for _, s := range junosKeywordSeeds {
+		f := strings.Fields(s)
+		if len(f) >= len(path) && slices.Equal(f[:len(path)], path) {
+			return true
+		}
+	}
+	return false
+}
+
+// visit captures one node, and returns its keywords.
+func (w *keywordWalk) visit(path []string) ([]string, error) {
+	p := strings.Join(path, " ")
+	if n, ok := w.nodes[p]; ok {
+		return n.words, nil
+	}
+	words, argument, err := w.completion(p)
+	if err != nil {
+		return nil, fmt.Errorf("completion after %q: %w", p, err)
+	}
+	n := &keywordNode{argument: argument}
+	for _, word := range words {
+		if len(path) == 0 {
+			// The top-level listing holds command names only.
+			n.words = append(n.words, word)
+			continue
+		}
+		ok, why, err := w.keyword(p, word, argument)
+		if err != nil {
+			return nil, err
+		}
+		if ok {
+			n.words = append(n.words, word)
+			continue
+		}
+		n.argument = true
+		w.values = append(w.values, fmt.Sprintf("%s %s (%s)", p, word, why))
+	}
+	w.nodes[p] = n
+	return n.words, nil
+}
+
+func (w *keywordWalk) bounded() bool {
+	return len(w.nodes) >= junosKeywordNodes || w.commands >= junosKeywordCommands
+}
+
+// walk captures the root, then every seed's prefixes, then the breadth under
+// junosKeywordWalked, within the bounds.
+func (w *keywordWalk) walk() error {
+	if _, err := w.visit(nil); err != nil {
+		return err
+	}
+	for _, s := range junosKeywordSeeds {
+		f := strings.Fields(s)
+		for i := 1; i < len(f) && i < junosKeywordDepth && !w.bounded(); i++ {
+			words, err := w.visit(f[:i])
+			if err != nil {
+				return err
+			}
+			if !slices.Contains(words, f[i]) {
+				break // not proven here: nothing under it is walked
+			}
+		}
+	}
+	queue := [][]string{{junosKeywordWalked}}
+	for len(queue) > 0 && !w.bounded() {
+		path := queue[0]
+		queue = queue[1:]
+		words, err := w.visit(path)
+		if err != nil {
+			return err
+		}
+		for _, word := range words {
+			next := append(slices.Clone(path), word)
+			if len(next) < junosKeywordDepth && (len(next) <= junosKeywordBreadth || seeded(next)) {
+				queue = append(queue, next)
+			}
+		}
+	}
+	return nil
+}
+
+// proveInert shows that `| display xml rpc` returns a command's RPC and does
+// not run it, on two harmless commands, before anything else is typed.
+func (w *keywordWalk) proveInert() error {
+	for _, c := range []struct{ cmd, rpc, output string }{
+		{"show system uptime", "get-system-uptime-information", "System booted"},
+		{"show version", "get-software-information", "Junos:"},
+	} {
+		w.tick()
+		out, err := w.c.sendExpect(c.cmd+" | display xml rpc", junosPer, w.prompt)
+		if err != nil {
+			return fmt.Errorf("%s | display xml rpc: not observed: %w", c.cmd, err)
+		}
+		if !strings.Contains(out, "<rpc>") || !strings.Contains(out, c.rpc) || strings.Contains(out, c.output) {
+			return fmt.Errorf("%s | display xml rpc did not show the RPC alone, so the pipe may run the command "+
+				"and the walk does not start: %s", c.cmd, oneLine(out))
+		}
+	}
+	return nil
+}
+
+// yaml is the tree as platform.ParseKeywords reads it.
+func (w *keywordWalk) yaml(platformName string) string {
+	var b strings.Builder
+	fmt.Fprintf(&b, "platform: %s\nnodes:\n", platformName)
+	paths := make([]string, 0, len(w.nodes))
+	for p := range w.nodes {
+		paths = append(paths, p)
+	}
+	slices.Sort(paths)
+	for _, p := range paths {
+		n := w.nodes[p]
+		quoted := make([]string, len(n.words))
+		for i, word := range n.words {
+			quoted[i] = fmt.Sprintf("%q", word)
+		}
+		fmt.Fprintf(&b, "  %q: {words: [%s], argument: %v}\n", p, strings.Join(quoted, ", "), n.argument)
+	}
+	return b.String()
+}
+
+func TestL26JunosKeywords(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
+			t.Skip("Junos only")
+		}
+		stop := l.capture(t, "L26")
+		defer stop()
+		c, err := l.junosCLI(breakglassUser, breakglassPassword)
+		if err != nil {
+			t.Fatalf("no break-glass CLI: %v", err)
+		}
+		defer c.Close()
+		if err := junosPrepare(c); err != nil {
+			t.Fatalf("set cli screen-length 0 not observed within %s: %v", junosPer, err)
+		}
+		w := &keywordWalk{c: c, logf: t.Logf, prompt: "@" + junosHost + "> ", nodes: map[string]*keywordNode{},
+			rpcs: map[string]rpcAnswer{}}
+		if err := w.proveInert(); err != nil {
+			t.Fatal(err)
+		}
+		if err := w.walk(); err != nil {
+			t.Fatalf("not observed; the walk stopped: %v", err)
+		}
+		// Keywords every image has: a capture without them misread the device.
+		for _, want := range [][2]string{{"", "show"}, {"show", "interfaces"}, {"show", "version"},
+			{"show interfaces", "terse"}, {"show", "system"}, {"show system", "uptime"}} {
+			if n := w.nodes[want[0]]; n == nil || !slices.Contains(n.words, want[1]) {
+				t.Errorf("%q is not proven a keyword after %q", want[1], want[0])
+			}
+		}
+		file := filepath.Join(root, "tests", "lab", "results", "L26-keywords-"+l.p.name+".yaml")
+		if err := os.WriteFile(file, []byte(w.yaml("juniper_junos")), 0o644); err != nil {
+			t.Fatal(err)
+		}
+		bounded := "no"
+		if w.bounded() {
+			bounded = "yes: every path it did not reach proves nothing"
+		}
+		var b strings.Builder
+		fmt.Fprintf(&b, "`| display xml rpc` showed the RPCs of `show system uptime` and `show version` and none of "+
+			"their output, so it runs nothing. The walk then typed only under `show`: %d nodes, %d commands. "+
+			"Stopped at a bound: %s.\n\n", len(w.nodes), w.commands, bounded)
+		fmt.Fprintf(&b, "Bounds: the prefixes of %d seed commands first, then every path under `show` of up to %d "+
+			"words, to %d words; at most %d nodes and %d commands.\n\n", len(junosKeywordSeeds), junosKeywordBreadth,
+			junosKeywordDepth, junosKeywordNodes, junosKeywordCommands)
+		fmt.Fprintf(&b, "Words offered by completion and not proven keywords (%d), the first 60: `%s`\n\n",
+			len(w.values), strings.Join(w.values[:min(60, len(w.values))], "`, `"))
+		b.WriteString("What this does not show: an argument completion never lists, a hidden one, is invisible " +
+			"here, so an exact allow may run with one (the stake is a read command under `show`); and the tree " +
+			"holds for these two images only: another release or hardware family (MX, EX, QFX, SRX hardware) " +
+			"may take an argument where this tree proves a keyword.\n\n")
+		fmt.Fprintf(&b, "The tree: `tests/lab/results/L26-keywords-%s.yaml`.\n", l.p.name)
+		l.result(t, "L26", "The Junos operational CLI keyword tree under `show`, each keyword proven by completion "+
+			"and by its RPC, within the stated bounds: the keywords decision 27 proves a projected rule's words "+
+			"against (spec §8; §15 L26).", b.String())
+	})
+}
````

<!-- patch: tests/lab/junos_abbrev_test.go -->
````diff
diff --git a/tests/lab/junos_abbrev_test.go b/tests/lab/junos_abbrev_test.go
new file mode 100644
index 0000000..b8f4bef
--- /dev/null
+++ b/tests/lab/junos_abbrev_test.go
@@ -0,0 +1,160 @@
+//go:build lab
+
+package lab
+
+import (
+	"fmt"
+	"strings"
+	"testing"
+)
+
+// TestL9JunosAbbreviations first reads whether the rendered deny is enforced
+// at all: every command typed in full, plain and piped, refused under it. A
+// shape the device does not enforce is Task 14's branch B2, which reverts
+// the deny to the shape Task 2 measured or ships Junos unprojected. It then
+// measures JunosFacts.DenyMatchesExpanded for
+// keywords (spec §15 L9; decision 27; the lead's ruling of 2026-09-25): that a
+// keyword deny refuses the command however its keywords are abbreviated, at
+// several lengths and command depths, piped, and where an abbreviation is
+// ambiguous at one level. Task 2 measured one abbreviation, `sh ver`, which is
+// too little to trust a deny against every abbreviated form, so the fact stays
+// false in set 1.1.0 unless every probe here is refused under the deny on both
+// images, while the control, a class holding every bit and no regex, ran each
+// unambiguous one. An ambiguous abbreviation the CLI refuses in the control
+// is recorded, and must be refused under the deny too.
+//
+// Two sessions, two seeded tokens. Every command has junosPer; a missed
+// prompt is not observed and fails the test.
+
+var junosAbbrevClass = []string{
+	"set system login class p49-l9-all permissions all",
+	"set system login user p49-l9-all class p49-l9-all",
+}
+
+var junosAbbrevDelete = []string{"delete system login user p49-l9-all", "delete system login class p49-l9-all"}
+
+// junosAbbrevDeny names five commands of two and three keywords exactly as
+// the generator renders a deny (ruleERE, Task 7 as fixed in eaf7975;
+// pre-flight B-M3): a leading ` *`, words joined by ` +`, the tail ` *(\|.*)?`
+// taking trailing spaces and a pipeline, one alternation, anchored. Its
+// letters are lower case, as with CaseSensitive false; the bracketed form a
+// case-sensitive device gets matches everything this does and more, so a
+// probe this refuses, that refuses too.
+const junosAbbrevDeny = `^( *show +version *(\\|.*)?| *show +interfaces +terse *(\\|.*)?| *show +system +uptime *(\\|.*)?|` +
+	` *show +route +summary *(\\|.*)?| *show +chassis +hardware *(\\|.*)?)$`
+
+// junosAbbrevProbe is one abbreviation, and whether the CLI may find it
+// ambiguous, in which case the control need not run it. An odd probe is one
+// the CLI may refuse outright in the control, which is recorded, not failed:
+// where the control runs it, the deny must refuse it as any other.
+type junosAbbrevProbe struct {
+	cmd       string
+	ambiguous bool
+	odd       bool
+}
+
+var junosAbbrevProbes = []junosAbbrevProbe{
+	{cmd: "show version"}, {cmd: "show version | no-more"}, {cmd: "sh ver"}, {cmd: "sho vers"}, {cmd: "show versi"},
+	{cmd: "sh ver | no-more"},
+	{cmd: "show interfaces terse"}, {cmd: "sh int ter"}, {cmd: "sh interfaces te"}, {cmd: "show int terse"},
+	{cmd: "sh int ter | count"},
+	{cmd: "show system uptime"}, {cmd: "sh sys upt"}, {cmd: "sh system up"}, {cmd: "show sy uptime"},
+	{cmd: "show route summary"}, {cmd: "sh rou sum"}, {cmd: "sh route summ"},
+	{cmd: "show chassis hardware"}, {cmd: "sh chas hard"}, {cmd: "sh chassis hardw"},
+	// `i` is ambiguous after `show` (interfaces, igmp, ike, ...).
+	{cmd: "sh i terse", ambiguous: true},
+	// The Task 7 review's: a lookalike letter (U+017F, which case-folds to
+	// `s`), and a denied command padded with spaces, no pipe.
+	{cmd: "\u017fhow version", odd: true}, {cmd: "   show version", odd: true}, {cmd: "show version   ", odd: true},
+	{cmd: "   sh int ter   ", odd: true},
+}
+
+func TestL9JunosAbbreviations(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
+			t.Skip("Junos only")
+		}
+		stop := l.capture(t, "L9-abbreviations")
+		defer stop()
+		commit := l.junosConfigureAdmin(t, junosAbbrevClass)
+		defer l.junosConfigureAdmin(t, junosAbbrevDelete)
+		defer func() {
+			if std, err := l.configPath(); err == nil {
+				if err := l.restart(std); err != nil {
+					t.Errorf("could not put port49d back on the lab config: %v", err)
+				}
+			}
+		}()
+		probes := make([]junosProbe, len(junosAbbrevProbes))
+		for i, p := range junosAbbrevProbes {
+			probes[i] = junosProbe{cmd: p.cmd}
+		}
+		control := l.junosSession(t, "control", `["local-user-name=p49-l9-all"]`, probes)
+		deny := l.junosSession(t, "deny", `["local-user-name=p49-l9-all", "deny-commands=`+junosAbbrevDeny+`"]`, probes)
+		for _, r := range []junosRun{control, deny} {
+			if r.loginErr != "" {
+				t.Fatalf("%s: the session did not open, so nothing was measured: %s", r.name, r.loginErr)
+			}
+			if len(r.unobserved) > 0 {
+				t.Fatalf("%s: not observed: %v", r.name, r.unobserved)
+			}
+		}
+		ambiguous := func(r junosRun, cmd string) bool { return strings.Contains(r.outs[cmd], "ambiguous") }
+		// The rendered shape is enforced where every full form, plain and
+		// piped, is refused under the deny and run by the control.
+		full := []string{"show version", "show version | no-more", "show interfaces terse", "show system uptime",
+			"show route summary", "show chassis hardware"}
+		enforced := true
+		for _, cmd := range full {
+			enforced = enforced && control.ran(cmd) && !deny.ran(cmd)
+		}
+		expanded := enforced
+		var b strings.Builder
+		fmt.Fprintf(&b, "The class was committed: %s.\n\n```\n%s\n```\n\nThe deny: `deny-commands=%s`.\n\n",
+			commitWord(commit), strings.Join(junosAbbrevClass, "\n"), tableCell(junosAbbrevDeny))
+		b.WriteString("| probe | control | under the deny |\n|---|---|---|\n")
+		for _, p := range junosAbbrevProbes {
+			ranControl := control.ran(p.cmd) && !ambiguous(control, p.cmd)
+			ranDeny := deny.ran(p.cmd) && !ambiguous(deny, p.cmd)
+			// The control's own answer says which abbreviation is ambiguous on
+			// this image; one it refused for any other reason measures nothing.
+			if !ranControl && !ambiguous(control, p.cmd) && !p.odd {
+				t.Errorf("the control did not run %q, so the deny's cell measures nothing: %s", p.cmd,
+					oneLine(control.outs[p.cmd]))
+				expanded = false
+			}
+			if p.ambiguous && !ambiguous(control, p.cmd) {
+				t.Logf("%q was expected ambiguous and was not on this image", p.cmd)
+			}
+			if ranDeny {
+				expanded = false
+			}
+			fmt.Fprintf(&b, "| %s | %s | %s |\n", tableCell(fmt.Sprintf("%q", p.cmd)), ranWord(ranControl, ambiguous(control, p.cmd)),
+				ranWord(ranDeny, ambiguous(deny, p.cmd)))
+		}
+		fmt.Fprintf(&b, "\n### Read off the table\n\n- the rendered deny shape (` *... *(\\|.*)?`) enforced: %v: every "+
+			"full form, plain and piped, refused under it and run by the control\n", enforced)
+		fmt.Fprintf(&b, "- JunosFacts.DenyMatchesExpanded (keywords) = %v: true only where the shape is enforced, the "+
+			"deny refused every probe and the control ran every unambiguous one; set 1.1.0 takes true only where "+
+			"both images say true\n", expanded)
+		for _, r := range []junosRun{control, deny} {
+			fmt.Fprintf(&b, "\n### %s\n\nReply `%s`. `show cli authorization`:\n\n```\n%s\n```\n", r.name, r.attrs, r.auth)
+			for _, p := range junosAbbrevProbes {
+				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", p.cmd, orEmpty([]string{r.outs[p.cmd]}, 0))
+			}
+		}
+		l.result(t, "L9-abbreviations", "Whether a keyword deny-commands refuses its command however the keywords "+
+			"are abbreviated, at several lengths and depths, piped, and ambiguous at one level: "+
+			"JunosFacts.DenyMatchesExpanded for keywords (spec §15 L9; decision 27).", b.String())
+	})
+}
+
+func ranWord(ran, ambiguous bool) string {
+	switch {
+	case ambiguous:
+		return "ambiguous"
+	case ran:
+		return "ran"
+	}
+	return "refused"
+}
````

<!-- patch: tests/lab/junos_netconf_test.go -->
````diff
diff --git a/tests/lab/junos_netconf_test.go b/tests/lab/junos_netconf_test.go
new file mode 100644
index 0000000..7f79cd6
--- /dev/null
+++ b/tests/lab/junos_netconf_test.go
@@ -0,0 +1,176 @@
+//go:build lab
+
+package lab
+
+import (
+	"fmt"
+	"slices"
+	"strings"
+	"testing"
+)
+
+// TestL12JunosNetconf asks whether a wire deny-commands, and the fail-closed
+// reply, bind a NETCONF RPC (spec §15 L12; decision 27; plan 5b pre-flight
+// B1). The token that opens an SSH CLI also opens `ssh -s netconf`, and the
+// session gets the same reply (L14). If Junos applies deny-commands to CLI
+// command lines only, every deny port49 sends is walked around by the RPC
+// that does the same thing: `<get-configuration>` past `deny show
+// configuration **`. The answer can change set 1.1.0 (Task 14, branch M), so
+// it is measured here, before the code is final.
+//
+// Four sessions, each a NETCONF session opened with a fresh seeded token
+// under its own reply, each sending the RPCs of junosNetconfRPCs, the
+// equivalents of denied commands: `<get-configuration/>` whole and filtered
+// and `<command>show configuration</command>` (`show configuration`), and
+// `<get-software-information/>` (`show version`). The control's class holds
+// view and view-configuration and no regex, so every one runs. Then the same class
+// under a deny naming both commands, as the generator renders it; the
+// fail-closed reply under local_user_name (no template: the `remote` user's
+// class, which in the lab holds the same bits); and the fail-closed reply
+// under user_permissions, the same bits sent over a bitless template. Every
+// read has a deadline (the hello 45 s, each RPC 60 s); a reply that is
+// neither the RPC's output nor an `<rpc-error>` is not observed and fails the
+// test. Four seeded tokens.
+
+var junosNetconfClass = []string{
+	"set system login class p49-nc-ro permissions [ view view-configuration ]",
+	"set system login user p49-nc-ro class p49-nc-ro",
+	"set system login class p49-nc-none idle-timeout 60",
+	"set system login user p49-nc-none class p49-nc-none",
+}
+
+var junosNetconfDelete = []string{"delete system login user p49-nc-ro", "delete system login class p49-nc-ro",
+	"delete system login user p49-nc-none", "delete system login class p49-nc-none"}
+
+// junosNetconfDeny names `show configuration **` and `show version` as the
+// generator renders a deny (ruleERE, as fixed in eaf7975: a leading ` *`,
+// words joined by ` +`, the tail ` *(\|.*)?`).
+const junosNetconfDeny = `^( *show +configuration( .*)? *(\\|.*)?| *show +version *(\\|.*)?)$`
+
+var junosNetconfVariants = []junosVariant{
+	{"control", `["local-user-name=p49-nc-ro"]`, "view and view-configuration, no regex: every RPC runs"},
+	{"deny", `["local-user-name=p49-nc-ro", "deny-commands=` + junosNetconfDeny + `"]`,
+		"the same class under a deny naming both commands"},
+	{"fail-closed, local_user_name", `["deny-commands=^.*$"]`,
+		"decision 26's reply with no template: the session lands in remote's class"},
+	{"fail-closed, user_permissions", `["local-user-name=p49-nc-none", "user-permissions=view view-configuration", "deny-commands=^.*$"]`,
+		"decision 26's reply with bits over a bitless template"},
+}
+
+// junosNetconfRPCs are the RPCs sent in each session, each with what its
+// output holds and the CLI command it stands for: the configuration whole and
+// filtered, the CLI text itself over `<command>` (re-pre-flight R-M3), and the
+// software version. The configuration's evidence is the host name, which each
+// form prints.
+var junosNetconfRPCs = []struct{ rpc, evidence, command string }{
+	{"<get-configuration/>", "host-name", "show configuration"},
+	{"<get-configuration><configuration><system/></configuration></get-configuration>", "host-name",
+		"show configuration system"},
+	{"<command>show configuration</command>", "host-name", "show configuration"},
+	{"<get-software-information/>", "<software-information", "show version"},
+}
+
+// netconfCell is one RPC's outcome: ran, refused, or not observed.
+func netconfCell(reply, evidence string) string {
+	switch {
+	case strings.Contains(reply, "<rpc-error>"):
+		return "refused"
+	case strings.Contains(reply, evidence):
+		return "ran"
+	}
+	return "not observed"
+}
+
+func TestL12JunosNetconf(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
+			t.Skip("Junos only")
+		}
+		if netconfPort(l.p) == "" {
+			t.Fatalf("%s: this lab does not enable NETCONF, so nothing can be measured", l.p.name)
+		}
+		stop := l.capture(t, "L12-netconf")
+		defer stop()
+		commit := l.junosConfigureAdmin(t, junosNetconfClass)
+		defer l.junosConfigureAdmin(t, junosNetconfDelete)
+		defer func() {
+			if std, err := l.configPath(); err == nil {
+				if err := l.restart(std); err != nil {
+					t.Errorf("could not put port49d back on the lab config: %v", err)
+				}
+			}
+		}()
+		cells := make([][]string, len(junosNetconfVariants))
+		replies := make([][]string, len(junosNetconfVariants))
+		for i, v := range junosNetconfVariants {
+			cfg, err := l.derivedConfigCmd("junos-nc-"+l16Slug(v.name), v.attrs, "", "")
+			if err == nil {
+				err = l.restart(cfg)
+			}
+			if err != nil {
+				t.Fatalf("%s: port49d with %s: %v", v.name, v.attrs, err)
+			}
+			user, secret := l.nextLogin(t)
+			n, hello, err := l.netconfDial(user, secret)
+			if err != nil {
+				t.Fatalf("%s: the NETCONF session did not open, so nothing was measured: %v (%s)", v.name, err,
+					oneLine(hello))
+			}
+			for k, r := range junosNetconfRPCs {
+				reply, err := n.rpc(k+1, r.rpc)
+				cell := netconfCell(reply, r.evidence)
+				if err != nil || cell == "not observed" {
+					t.Errorf("%s: %s not observed: %v %s", v.name, r.rpc, err, oneLine(reply))
+					cell = "not observed"
+				}
+				cells[i] = append(cells[i], cell)
+				replies[i] = append(replies[i], reply)
+			}
+			n.Close()
+		}
+		ranControl := !slices.ContainsFunc(cells[0], func(c string) bool { return c != "ran" })
+		if !ranControl {
+			t.Errorf("the control did not run every RPC, so no deny is measured: %v", cells[0])
+		}
+		bound := ranControl
+		for _, row := range cells[1:] {
+			for _, c := range row {
+				bound = bound && c == "refused"
+			}
+		}
+		var b strings.Builder
+		fmt.Fprintf(&b, "The classes were committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit),
+			strings.Join(junosNetconfClass, "\n"))
+		b.WriteString("| session | reply | why |")
+		for _, r := range junosNetconfRPCs {
+			fmt.Fprintf(&b, " %s |", tableCell(r.rpc))
+		}
+		b.WriteString("\n|---|---|---|" + strings.Repeat("---|", len(junosNetconfRPCs)) + "\n")
+		for i, v := range junosNetconfVariants {
+			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", v.name, tableCell(v.attrs), v.why, strings.Join(cells[i], " | "))
+		}
+		fmt.Fprintf(&b, "\n### Read off the table\n\n- deny-commands and the fail-closed reply bind NETCONF RPCs: %v "+
+			"(true only where the control ran every RPC and every other session refused every one; set 1.1.0 "+
+			"takes it as bound only where both images say true)\n", bound)
+		for i, v := range junosNetconfVariants {
+			fmt.Fprintf(&b, "\n### %s\n", v.name)
+			for k, r := range junosNetconfRPCs {
+				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", r.rpc, orEmpty([]string{firstLines(replies[i][k], 30)}, 0))
+			}
+		}
+		l.result(t, "L12-netconf", "Over TACACS+ on `junos-exec`: whether a wire deny-commands, and decision 26's "+
+			"fail-closed reply, bind a NETCONF RPC opened with the same token and reply, "+
+			"`<get-configuration>` and `<get-software-information>` beside `show configuration` and `show version` "+
+			"(spec §15 L12; decision 27).", b.String())
+	})
+}
+
+// firstLines is at most n lines of s: an RPC's output is the configuration,
+// and the note needs only enough of it to show what ran.
+func firstLines(s string, n int) string {
+	lines := strings.Split(s, "\n")
+	if len(lines) <= n {
+		return s
+	}
+	return strings.Join(lines[:n], "\n") + fmt.Sprintf("\n… (%d more lines)", len(lines)-n)
+}
````

- [ ] **Step 2: Compile it**

Run: `go vet -tags lab ./tests/lab/...`
Expected: no output.

- [ ] **Step 3: Run it on vJunos-router, then vSRX**

```bash
PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^(TestL26JunosKeywords|TestL9JunosAbbreviations|TestL12JunosNetconf)$' \
  -count=1 -v -timeout 240m > tests/lab/logs/l26-keywords-vjunos.log 2>&1 &
echo $! > tests/lab/logs/l26-keywords-vjunos.pid
```

Run it as "Running the lab" shows, with the stall watchdog (`STALL=25`) for the whole run and its
cleanup after a `go test` timeout. The walk logs a progress line every 20 nodes, so the log grows
well inside the stall bound. Then the same with `PORT49_LAB_PLATFORMS=vsrx`. Nobody runs `make
build` during a run: the harness grants `bin/port49d` its capability once, at the start.

Expected: PASS on both images, `wrote tests/lab/results/L26-juniper_<image>.md` and
`L9-abbreviations-juniper_<image>.md` and `L12-netconf-juniper_<image>.md`, and the two
`L26-keywords-*.yaml` files. A `not observed`
failure measured nothing: rerun.

- [ ] **Step 4: Commit the test, the notes, the trees and the evidence**

```bash
make evidence
git add tests/lab/junos_keywords_test.go tests/lab/junos_abbrev_test.go tests/lab/junos_netconf_test.go \
  tests/lab/results/L26-juniper_*.md tests/lab/results/L26-keywords-juniper_*.yaml \
  tests/lab/results/L9-abbreviations-juniper_*.md tests/lab/results/L12-netconf-juniper_*.md \
  tests/lab/evidence/L26-juniper_*.pcap tests/lab/evidence/L9-abbreviations-juniper_*.pcap \
  tests/lab/evidence/L12-netconf-juniper_*.pcap
git commit -m "$(cat <<'EOF'
test: capture the Junos CLI keyword tree, keyword abbreviations and NETCONF (L26, L9, L12)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 12a: Junos matches keywords only: a rule reaches the wire only where the keyword tree proves it

**Files:**
- Create: `internal/platform/keywords.go` (`Keywords`, `KeywordNode`, `ParseKeywords`,
  `KeywordsFor`, `MergeKeywords`, `MarshalKeywords`, the bounds), `platforms/keywords/README.md`,
  `internal/projection/keywords.go` (`keywordShape`, `argument`, `denyProvable`, `unsendableAllow`,
  `configurationVerbs`, `denyRefusal`, `argumentDeny`), `internal/policy/keywords.go` (`setKeywords`)
- Modify: `platforms/platforms.go` (`Keywords embed.FS`), `internal/projection/project.go`
  (`Input.Keywords`, `Result.Unsent`, `Unsent`, `FailArgumentDeny`, `FailConfigurationDeny`; the checks in `render`,
  `capability`, `narrow`, `failClosed`), `internal/policy/resolve.go` (`projectOnce` passes the
  pinned set's tree)
- Test: `internal/platform/keywords_test.go`, `internal/projection/project_test.go`,
  `internal/policy/keywords_test.go` (new; the test set's tree)

**Interfaces:**
- Consumes: Task 8's generator; Task 9's `projectOnce`, `Policy.set`.
- Produces:
  - `type platform.Keywords` with `Keyword(path []string, word string) bool`, `TakesArgument(path
    []string) bool`, `Len() int`; `platform.ParseKeywords(raw []byte) (string, *Keywords, error)`,
    `platform.KeywordsFor(version, platform string) *Keywords`, `platform.MergeKeywords(...*Keywords)
    *Keywords`, `platform.MarshalKeywords(platform string, k *Keywords) []byte`,
    `MaxKeywordNodes = 5000`, `MaxKeywordBytes = 1 << 20`;
  - `platforms.Keywords embed.FS` (`keywords/<version>/<platform>.yaml`);
  - `projection.Input.Keywords *platform.Keywords`, `Result.Unsent []Unsent`, `type Unsent struct{
    Rule engine.Rule; Why string }`, `FailArgumentDeny = "argument_deny"`, `FailConfigurationDeny =
    "configuration_deny"`.

The tree lives outside the set directories, whose loader takes one adapter file per platform and
nothing else, so no `platforms:` block can reach it and Task 6's files are untouched. Nil proves
nothing: on a projected platform with no tree every live deny fails closed and no allow is sent.
`render` refuses, before any shape, a deny that meets a permit and is not keyword-only, with the
ruling's message and the proven keyword prefix as the whole command to deny instead; where the deny
begins with a configuration verb the refusal is `configuration_deny`, saying deny-commands never
reaches configuration mode (item 7 above). The configuration guard names `edit`, the operational
alias for `configure`, beside it (pre-flight B-M1), and the tests assert that no reply carrying a
deny lets the device run `configure`, `configure private`, `configure exclusive`, `configure
batch` or `edit`. `capability`
goes narrow where a deny it would send is not keyword-only (no permit meets it; `.*` holds it).
`capability`, `narrow` and `failClosed` leave an allow off where `unsendableAllow` says why, into
`Result.Unsent`. The policy passes the pinned set's tree (`setKeywords`, which the tests point at the
test set's own tree).

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/platform/keywords_test.go -->
````diff
diff --git a/internal/platform/keywords_test.go b/internal/platform/keywords_test.go
new file mode 100644
index 0000000..a234046
--- /dev/null
+++ b/internal/platform/keywords_test.go
@@ -0,0 +1,151 @@
+package platform
+
+import (
+	"fmt"
+	"io/fs"
+	"path"
+	"strings"
+	"testing"
+	"testing/fstest"
+
+	"github.com/blanketfish/port49/platforms"
+)
+
+const keywordFixture = `platform: juniper_junos
+nodes:
+  "": {words: [show], argument: false}
+  "show": {words: [interfaces, version], argument: false}
+  "show interfaces": {words: [terse], argument: true}
+`
+
+// A keyword tree answers only what the capture reached: a word is a keyword
+// where its path's node lists it, and an argument may be typed wherever the
+// node says so or no node was captured (spec §8; §15 L26).
+func TestKeywords(t *testing.T) {
+	name, k, err := ParseKeywords([]byte(keywordFixture))
+	if err != nil || name != "juniper_junos" || k.Len() != 3 {
+		t.Fatalf("%s %v %v", name, k, err)
+	}
+	for _, c := range []struct {
+		path []string
+		word string
+		want bool
+	}{
+		{nil, "show", true},
+		{nil, "SHOW", true},
+		{[]string{"show"}, "interfaces", true},
+		{[]string{"show", "interfaces"}, "terse", true},
+		{[]string{"show", "interfaces"}, "fxp0", false},
+		{[]string{"show", "version"}, "brief", false}, // not captured: proves nothing
+		{nil, "request", false},
+	} {
+		if got := k.Keyword(c.path, c.word); got != c.want {
+			t.Errorf("Keyword(%q, %q) = %v", c.path, c.word, got)
+		}
+	}
+	if k.TakesArgument([]string{"show"}) || !k.TakesArgument([]string{"show", "interfaces"}) ||
+		!k.TakesArgument([]string{"show", "version"}) {
+		t.Error("TakesArgument")
+	}
+	var none *Keywords
+	if none.Keyword(nil, "show") || !none.TakesArgument(nil) {
+		t.Error("a nil tree proves nothing")
+	}
+}
+
+// A file that could let the projection prove what the lab did not measure
+// is refused: an orphan node, an unsorted or upper-case word, an unknown key,
+// and one past the bounds.
+func TestParseKeywordsRefuses(t *testing.T) {
+	for _, bad := range []string{
+		"platform: juniper_junos\nnodes:\n  \"\": {words: [show]}\n  \"show interfaces\": {words: []}\n",
+		"platform: juniper_junos\nnodes:\n  \"\": {words: [version, show]}\n",
+		"platform: juniper_junos\nnodes:\n  \"\": {words: [Show]}\n",
+		"platform: juniper_junos\nnodes:\n  \"\": {words: [show], keyword: true}\n",
+		"platform: juniper_junos\nnodes:\n  \"show\": {words: []}\n",
+		"nodes:\n  \"\": {words: []}\n",
+		"platform: juniper_junos\nnodes:\n  \"\": {words: [x]}\n" + strings.Repeat("#", MaxKeywordBytes),
+	} {
+		if _, _, err := ParseKeywords([]byte(bad)); err == nil {
+			t.Errorf("parsed: %.80q", bad)
+		}
+	}
+	// MaxKeywordNodes children of the root and the root: one node too many.
+	var words, nodes []string
+	for i := range MaxKeywordNodes {
+		w := fmt.Sprintf("w%05d", i)
+		words = append(words, w)
+		nodes = append(nodes, fmt.Sprintf("  %q: {words: []}\n", w))
+	}
+	raw := "platform: p\nnodes:\n  \"\": {words: [" + strings.Join(words, ", ") + "]}\n" + strings.Join(nodes, "")
+	if _, _, err := ParseKeywords([]byte(raw)); err == nil || !strings.Contains(err.Error(), "past the bound") {
+		t.Errorf("past the node bound: %v", err)
+	}
+}
+
+// A set's tree is read from keywords/<version>/<platform>.yaml, absent is
+// nil, and a file for another platform is a build defect.
+func TestKeywordsFor(t *testing.T) {
+	fsys := fstest.MapFS{"keywords/9.9.9/juniper_junos.yaml": {Data: []byte(keywordFixture)},
+		"keywords/9.9.9/other.yaml": {Data: []byte(keywordFixture)}}
+	if k := keywordsIn(fsys, "9.9.9", "juniper_junos"); k.Len() != 3 {
+		t.Fatal("not read")
+	}
+	if keywordsIn(fsys, "9.9.8", "juniper_junos") != nil || KeywordsFor("1.0.0", "juniper_junos") != nil {
+		t.Fatal("a set with no tree has none")
+	}
+	defer func() {
+		if recover() == nil {
+			t.Error("a file naming another platform loaded")
+		}
+	}()
+	keywordsIn(fsys, "9.9.9", "other")
+}
+
+// Two images' captures merge to what both prove: a keyword on one image only
+// is not a keyword, an argument on either is one, and a node under a word the
+// merge dropped goes with it. The merge writes what ParseKeywords reads.
+func TestMergeKeywords(t *testing.T) {
+	_, a, _ := ParseKeywords([]byte(keywordFixture))
+	_, b, err := ParseKeywords([]byte(`platform: juniper_junos
+nodes:
+  "": {words: [request, show], argument: false}
+  "show": {words: [interfaces], argument: true}
+  "show interfaces": {words: [terse], argument: false}
+  "request": {words: [], argument: false}
+`))
+	if err != nil {
+		t.Fatal(err)
+	}
+	m := MergeKeywords(a, b)
+	if !m.Keyword(nil, "show") || m.Keyword(nil, "request") || m.Keyword([]string{"show"}, "version") ||
+		!m.Keyword([]string{"show", "interfaces"}, "terse") || !m.TakesArgument([]string{"show"}) || m.Len() != 3 {
+		t.Fatalf("%s", MarshalKeywords("juniper_junos", m))
+	}
+	name, back, err := ParseKeywords(MarshalKeywords("juniper_junos", m))
+	if err != nil || name != "juniper_junos" || back.Len() != 3 || !back.TakesArgument([]string{"show"}) {
+		t.Fatalf("round trip: %v", err)
+	}
+}
+
+// Every tree the binary ships loads, names its own platform and sits within
+// the bounds; a set's tree is frozen with its set (Task 20).
+func TestShippedKeywordTreesLoad(t *testing.T) {
+	err := fs.WalkDir(platforms.Keywords, "keywords", func(p string, d fs.DirEntry, err error) error {
+		if err != nil || d.IsDir() || path.Ext(p) != ".yaml" {
+			return err
+		}
+		parts := strings.Split(p, "/")
+		if len(parts) != 3 {
+			t.Errorf("%s: not keywords/<version>/<platform>.yaml", p)
+			return nil
+		}
+		if k := KeywordsFor(parts[1], strings.TrimSuffix(parts[2], ".yaml")); k.Len() == 0 {
+			t.Errorf("%s: no nodes", p)
+		}
+		return nil
+	})
+	if err != nil {
+		t.Fatal(err)
+	}
+}
````

<!-- patch: internal/policy/keywords_test.go -->
````diff
diff --git a/internal/policy/keywords_test.go b/internal/policy/keywords_test.go
new file mode 100644
index 0000000..beafd6c
--- /dev/null
+++ b/internal/policy/keywords_test.go
@@ -0,0 +1,34 @@
+package policy
+
+import "github.com/blanketfish/port49/internal/platform"
+
+// projectedKeywords is the test set's keyword tree: every word these tests
+// deny or allow on juniper_junos, as the lab's capture writes it. `show
+// interfaces` and `show route` take an argument, as on Junos.
+const projectedKeywords = `platform: juniper_junos
+nodes:
+  "": {words: ["clear", "configure", "help", "monitor", "ping", "quit", "request", "set", "show", "traceroute"], argument: false}
+  "show": {words: ["alpha", "bravo", "charlie", "configuration", "delta", "echo", "foxtrot", "golf", "hotel", "india", "interfaces", "juliett", "kilo", "lima", "log", "mike", "november", "oscar", "papa", "route", "system", "version"], argument: false}
+  "show configuration": {words: ["system"], argument: false}
+  "show interfaces": {words: ["terse"], argument: true}
+  "show route": {words: [], argument: true}
+  "show system": {words: ["users"], argument: false}
+  "show version": {words: [], argument: false}
+  "clear": {words: ["bgp", "counters"], argument: false}
+  "request": {words: ["system"], argument: false}
+  "request system": {words: ["reboot"], argument: false}
+`
+
+func init() {
+	_, k, err := platform.ParseKeywords([]byte(projectedKeywords))
+	if err != nil {
+		panic(err)
+	}
+	shipped := setKeywords
+	setKeywords = func(version, name string) *platform.Keywords {
+		if version == projectedSet && name == "juniper_junos" {
+			return k
+		}
+		return shipped(version, name)
+	}
+}
````

<!-- patch: internal/projection/project_test.go -->
````diff
diff --git a/internal/projection/project_test.go b/internal/projection/project_test.go
index defb11b..d6d9a2e 100644
--- a/internal/projection/project_test.go
+++ b/internal/projection/project_test.go
@@ -3,6 +3,7 @@ package projection
 import (
 	"fmt"
 	"reflect"
+	"slices"
 	"strings"
 	"testing"
 
@@ -33,9 +34,63 @@ func input(delivery, level string, f Facts, rules ...engine.Rule) Input {
 	d := junos(delivery)
 	return Input{Platform: "juniper_junos", Dialect: d, Level: level, Bits: d.CeilingBits[level],
 		Template: d.LocalUserNames[level], Rules: rules,
-		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}, Facts: f}
+		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}, Facts: f,
+		Keywords: testKeywords}
 }
 
+// testKeywords is a keyword tree in the shape the lab captures (Task 3b):
+// every word these tests deny or allow as a keyword, and an argument after
+// `show interfaces`, `show route`, `show log`, `ping` and the rest, as Junos
+// takes one there.
+var testKeywords = func() *platform.Keywords {
+	nodes := map[string]struct {
+		words string
+		arg   bool
+	}{
+		"":                              {"clear configure exit help monitor ping quit request set show traceroute", false},
+		"show":                          {"alpha bravo charlie chassis cli configuration delta echo foxtrot golf hotel india interfaces juliett kilo lima log mike november oscar papa route snmp system version", false},
+		"show interfaces":               {"extensive terse", true},
+		"show interfaces terse":         {"", true},
+		"show configuration":            {"interfaces system", false},
+		"show configuration interfaces": {"", true},
+		"show configuration system":     {"", false},
+		"show version":                  {"", false},
+		"show route":                    {"", true},
+		"show log":                      {"", true},
+		"show system":                   {"uptime", false},
+		"clear":                         {"bgp counters interfaces", false},
+		"clear bgp":                     {"neighbor", false},
+		"clear counters":                {"", false},
+		"request":                       {"system", false},
+		"request system":                {"reboot", false},
+		"ping":                          {"", true},
+		"traceroute":                    {"", true},
+		"monitor":                       {"", true},
+		"set":                           {"cli", false},
+		"set cli":                       {"", true},
+		"quit":                          {"", false},
+		"configure":                     {"", false},
+	}
+	for _, w := range strings.Fields("alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa") {
+		nodes["show "+w] = struct {
+			words string
+			arg   bool
+		}{"", false}
+	}
+	var b strings.Builder
+	b.WriteString("platform: juniper_junos\nnodes:\n")
+	for path, n := range nodes {
+		words := strings.Fields(n.words)
+		slices.Sort(words)
+		fmt.Fprintf(&b, "  %q: {words: [%s], argument: %v}\n", path, strings.Join(words, ", "), n.arg)
+	}
+	_, k, err := platform.ParseKeywords([]byte(b.String()))
+	if err != nil {
+		panic(err)
+	}
+	return k
+}()
+
 func permit(rule string) engine.Rule {
 	return engine.Rule{Verdict: engine.Permit, Rule: rule, Role: "r"}
 }
@@ -250,8 +305,8 @@ func TestSecretsAndBudget(t *testing.T) {
 	// An allow past the budget is never moved into a class, where it would
 	// run for every subject past their own denies (C2): no class line.
 	rules = nil
-	for i := range 16 {
-		rules = append(rules, permit(fmt.Sprintf("show interfaces ge-0/0/%d extensive", i)))
+	for _, w := range strings.Fields("alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa") {
+		rules = append(rules, permit("show "+w+" **"))
 	}
 	res, err = Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, rules...))
 	if r := res.Refusal; err != nil || res.FailClosed != FailOverflow || r.Attribute != "allow-commands" ||
@@ -352,3 +407,117 @@ func TestWidens(t *testing.T) {
 		t.Error("a widening by a command names it")
 	}
 }
+
+// Junos matches a deny against a command's keywords only (decision 27): a
+// deny that meets a permit and names an argument is one the device never
+// enforces, so the subject gets the fail-closed reply, and the refusal names
+// the word and the whole command to deny instead. Classes, regexes and `*`
+// stand for arguments; a deny no permit meets is no_rule_matched anyway.
+func TestADenyNamingAnArgumentFailsClosed(t *testing.T) {
+	for _, c := range []struct{ deny, word, instead string }{
+		{"show interfaces fxp0", "`fxp0` in `deny show interfaces fxp0`", "deny the whole command (`show interfaces`)"},
+		{"show interfaces fxp0 **", "`fxp0`", "deny the whole command (`show interfaces`)"},
+		{"show interfaces @management", "`@management`", "@management stands for an argument"},
+		{"show route *", "`*`", "deny the whole command (`show route`)"},
+		{"show /^int/ **", "`/^int/`", "deny the whole command (`show`)"},
+		{"show frobnicate", "`frobnicate`", "not a keyword the lab measured after \"show\""},
+	} {
+		in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"), deny(c.deny))
+		in.Classes = map[string][]string{"management": {"^fxp0$"}}
+		res, err := Project(in)
+		if err != nil || res.FailClosed != FailArgumentDeny || !strings.Contains(res.Refusal.Why, "Junos can't deny by argument") ||
+			!strings.Contains(res.Refusal.Why, c.word) || !strings.Contains(res.Refusal.Why, c.instead) {
+			t.Errorf("%s: %+v %v", c.deny, res.Refusal, err)
+		}
+		if res.Device([]string{"show", "interfaces", "fxp0", "terse"}) {
+			t.Errorf("%s: the fail-closed reply runs a command", c.deny)
+		}
+	}
+	// No permit meets it: port49 refuses those commands for want of a
+	// permit, and the reply needs no deny.
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show version"),
+		deny("clear interfaces fxp0")))
+	if err != nil || res.FailClosed != "" {
+		t.Fatalf("%+v %v", res, err)
+	}
+	// A deny of keywords, `**` or not, goes out.
+	res, err = Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
+		deny("show system **"), deny("show version")))
+	if err != nil || res.FailClosed != "" || len(res.Denies) != 2 {
+		t.Fatalf("%+v %v", res, err)
+	}
+	// With no keyword tree nothing is proven.
+	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"), deny("show version"))
+	in.Keywords = nil
+	if res, err := Project(in); err != nil || res.FailClosed != FailArgumentDeny {
+		t.Fatalf("no tree: %+v %v", res, err)
+	}
+}
+
+// An allow naming an argument never matches on Junos, and one with an
+// argument possible among its words would run more than port49 permits:
+// neither is sent, the device refuses what port49 permits there, and the
+// result says why (decision 27).
+func TestAnAllowNamingAnArgumentIsNotSent(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show version"),
+		permit("show interfaces fxp0 **"), permit("show interfaces terse"), permit("show route **")))
+	if err != nil || res.Shape != ShapeNarrow {
+		t.Fatalf("%+v %v", res, err)
+	}
+	want := []string{"user-permissions=view", "deny-commands=^.*$", "allow-commands=^(show version|show route( .*)?)$"}
+	if !reflect.DeepEqual(res.Attributes, want) || len(res.Unsent) != 2 ||
+		!strings.Contains(res.Unsent[0].Why, `"fxp0" is not a keyword the lab measured after "show interfaces"`) ||
+		!strings.Contains(res.Unsent[1].Why, `would also run "show interfaces <argument> terse"`) {
+		t.Fatalf("%q %+v", res.Attributes, res.Unsent)
+	}
+	if res.Device([]string{"show", "interfaces", "fxp0", "terse"}) || !res.Device([]string{"show", "route", "x"}) {
+		t.Error("device model")
+	}
+}
+
+// deny-commands never reaches configuration mode (decision 27;
+// L12-configuration-juniper_*.md). A reply that can enter it carries no deny,
+// so a deny of a configuration statement is enforced only as an operational
+// command: where the keyword tree does not prove it one, the subject gets the
+// fail-closed reply, saying why. The admin path that drops the configuration
+// bits relies on no deny in configuration mode: the device cannot enter it.
+func TestADenyOfAConfigurationStatementFailsClosed(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**"),
+		deny("set system host-name **")))
+	if err != nil || res.FailClosed != FailConfigurationDeny || !strings.Contains(res.Refusal.Why,
+		"names a configuration statement, and Junos never applies deny-commands in configuration mode") {
+		t.Fatalf("%+v %v", res.Refusal, err)
+	}
+	if res.Device([]string{"configure"}) {
+		t.Error("the fail-closed reply enters configuration mode")
+	}
+	// An operational command that begins with a configuration verb, which
+	// the tree proves, is sent, under bits that cannot configure.
+	res, err = Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**"), deny("set cli **")))
+	if err != nil || res.FailClosed != "" || !slices.Contains(res.ConfigurationDropped, "configure") ||
+		res.Device([]string{"configure"}) || res.Device([]string{"set", "cli", "screen-width", "80"}) {
+		t.Fatalf("%+v %v", res, err)
+	}
+	// No reply that carries a deny can enter configuration mode, by
+	// `configure`, its variants or `edit`, its alias (pre-flight B-M1).
+	entries := [][]string{{"configure"}, {"configure", "private"}, {"configure", "exclusive"},
+		{"configure", "batch"}, {"edit"}}
+	for _, rules := range [][]engine.Rule{{permit("**"), deny("request system reboot")},
+		{permit("show **"), permit("configure"), deny("show version")},
+		{permit("show **"), permit("edit **"), deny("show version")}} {
+		for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
+			res, err := Project(input(delivery, "admin", measured, rules...))
+			if err != nil {
+				t.Fatal(err)
+			}
+			if len(res.Denies) == 0 && res.Shape == ShapeCapability {
+				continue
+			}
+			for _, e := range entries {
+				if res.Device(e) {
+					t.Errorf("%s %v: a reply with a deny runs %q: %q", delivery, rules, e, res.Attributes)
+				}
+			}
+		}
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/projection/ ./internal/policy/`
Expected: FAIL, build failed: `unknown field Keywords in struct literal of type Input`, `undefined:
platform.Keywords`, `undefined: platform.ParseKeywords`, `undefined: FailArgumentDeny`.

- [ ] **Step 3: Add the tree, the checks and the wiring**

<!-- patch: internal/platform/keywords.go -->
````diff
diff --git a/internal/platform/keywords.go b/internal/platform/keywords.go
new file mode 100644
index 0000000..10d14ee
--- /dev/null
+++ b/internal/platform/keywords.go
@@ -0,0 +1,228 @@
+package platform
+
+import (
+	"bytes"
+	"errors"
+	"fmt"
+	"io/fs"
+	"path"
+	"slices"
+	"strings"
+
+	"gopkg.in/yaml.v3"
+
+	"github.com/blanketfish/port49/platforms"
+)
+
+// MaxKeywordNodes and MaxKeywordBytes bound a keyword tree: the lab's capture
+// stops at the node cap, and a file past either is refused, since the tree
+// is embedded in both binaries and read at every policy load.
+const (
+	MaxKeywordNodes = 5000
+	MaxKeywordBytes = 1 << 20
+)
+
+// Keywords is a projected platform's CLI keyword tree as the lab captured it
+// on every image a set measures (spec §8; §15 L26): for each command path
+// the capture reached, the words the CLI completes there that are keywords,
+// and whether an argument may be typed there. Junos matches a deny-commands
+// or allow-commands regex against a command's keywords only, never its
+// arguments (tests/lab/results/L12-juniper_*.md), so the projection sends a
+// rule only where this tree proves every word of it a keyword. A path the
+// capture did not reach proves nothing: a word under it is not a keyword,
+// and an argument may be typed there. It is the set's measurement, so no
+// `platforms:` block can change it.
+type Keywords struct {
+	nodes map[string]KeywordNode
+}
+
+// KeywordNode is one captured command path: Words are the keywords the CLI
+// completes after it, lower case and sorted, and Argument whether it takes an
+// argument there, on any image.
+type KeywordNode struct {
+	Words    []string `yaml:"words"`
+	Argument bool     `yaml:"argument"`
+}
+
+type keywordFile struct {
+	Platform string                 `yaml:"platform"`
+	Nodes    map[string]KeywordNode `yaml:"nodes"`
+}
+
+// ParseKeywords reads a keyword file: `platform:` and `nodes:`, keyed by
+// command path, the root as "". Every word is a lower-case run of printable
+// ASCII with no space, every node but the root is listed by its parent, and
+// the file is within MaxKeywordBytes and MaxKeywordNodes.
+func ParseKeywords(raw []byte) (string, *Keywords, error) {
+	if len(raw) > MaxKeywordBytes {
+		return "", nil, fmt.Errorf("keywords: %d bytes, past the bound of %d", len(raw), MaxKeywordBytes)
+	}
+	var f keywordFile
+	dec := yaml.NewDecoder(bytes.NewReader(raw))
+	dec.KnownFields(true)
+	if err := dec.Decode(&f); err != nil {
+		return "", nil, fmt.Errorf("keywords: %w", err)
+	}
+	if f.Platform == "" {
+		return "", nil, errors.New("keywords: no platform")
+	}
+	if len(f.Nodes) > MaxKeywordNodes {
+		return "", nil, fmt.Errorf("keywords: %d nodes, past the bound of %d", len(f.Nodes), MaxKeywordNodes)
+	}
+	if _, ok := f.Nodes[""]; !ok {
+		return "", nil, errors.New("keywords: no root node (\"\")")
+	}
+	for p, n := range f.Nodes {
+		for _, w := range n.Words {
+			if w == "" || w != strings.ToLower(w) || strings.IndexFunc(w, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0 {
+				return "", nil, fmt.Errorf("keywords: node %q: word %q is not a lower-case printable word", p, w)
+			}
+		}
+		if !slices.IsSorted(n.Words) {
+			return "", nil, fmt.Errorf("keywords: node %q: words are not sorted", p)
+		}
+		if p == "" {
+			continue
+		}
+		i := strings.LastIndexByte(p, ' ')
+		parent, last := "", p
+		if i >= 0 {
+			parent, last = p[:i], p[i+1:]
+		}
+		if pn, ok := f.Nodes[parent]; !ok || !slices.Contains(pn.Words, last) {
+			return "", nil, fmt.Errorf("keywords: node %q: its parent %q does not list %q", p, parent, last)
+		}
+	}
+	return f.Platform, &Keywords{nodes: f.Nodes}, nil
+}
+
+// Keyword reports whether word is a keyword after path: the capture reached
+// path and the CLI completes word there. Case is ignored, as port49 ignores
+// it in a rule's word.
+func (k *Keywords) Keyword(path []string, word string) bool {
+	if k == nil {
+		return false
+	}
+	n, ok := k.nodes[strings.ToLower(strings.Join(path, " "))]
+	if !ok {
+		return false
+	}
+	_, found := slices.BinarySearch(n.Words, strings.ToLower(word))
+	return found
+}
+
+// TakesArgument reports whether an argument may be typed after path: true
+// where the capture found one on any image, and true where it did not reach
+// path, which proves nothing.
+func (k *Keywords) TakesArgument(path []string) bool {
+	if k == nil {
+		return true
+	}
+	n, ok := k.nodes[strings.ToLower(strings.Join(path, " "))]
+	return !ok || n.Argument
+}
+
+// Len is the number of captured nodes.
+func (k *Keywords) Len() int {
+	if k == nil {
+		return 0
+	}
+	return len(k.nodes)
+}
+
+// KeywordsFor is set version's keyword tree for platform, from the embedded
+// `platforms/keywords/<version>/<platform>.yaml`, or nil where the set ships
+// none. A file that does not load is a build defect, and panics, as a set's
+// adapter file does.
+func KeywordsFor(version, platformName string) *Keywords {
+	return keywordsIn(platforms.Keywords, version, platformName)
+}
+
+func keywordsIn(fsys fs.FS, version, platformName string) *Keywords {
+	raw, err := fs.ReadFile(fsys, path.Join("keywords", version, platformName+".yaml"))
+	if err != nil {
+		return nil
+	}
+	name, k, err := ParseKeywords(raw)
+	if err == nil && name != platformName {
+		err = fmt.Errorf("keywords: the file names platform %q", name)
+	}
+	if err != nil {
+		panic(fmt.Sprintf("platforms/keywords/%s/%s.yaml: %v", version, platformName, err))
+	}
+	return k
+}
+
+// MergeKeywords is what every capture proves: a node captured on each image,
+// the keywords each completes there, and an argument where any image takes
+// one. A keyword only one image has is not proven, and fails closed; a node
+// whose last word is not a keyword of its merged parent is dropped with its
+// subtree. Nil is the empty tree.
+func MergeKeywords(trees ...*Keywords) *Keywords {
+	if len(trees) == 0 {
+		return &Keywords{nodes: map[string]KeywordNode{}}
+	}
+	merged := map[string]KeywordNode{}
+	for p, n := range trees[0].nodeMap() {
+		words, arg, ok := slices.Clone(n.Words), n.Argument, true
+		for _, other := range trees[1:] {
+			o, found := other.nodeMap()[p]
+			if !found {
+				ok = false
+				break
+			}
+			words = slices.DeleteFunc(words, func(w string) bool { return !slices.Contains(o.Words, w) })
+			arg = arg || o.Argument
+		}
+		if ok {
+			merged[p] = KeywordNode{Words: words, Argument: arg}
+		}
+	}
+	paths := make([]string, 0, len(merged))
+	for p := range merged {
+		paths = append(paths, p)
+	}
+	slices.SortFunc(paths, func(a, b string) int { return strings.Count(a, " ") - strings.Count(b, " ") })
+	for _, p := range paths {
+		if p == "" {
+			continue
+		}
+		i := strings.LastIndexByte(p, ' ')
+		parent, last := "", p
+		if i >= 0 {
+			parent, last = p[:i], p[i+1:]
+		}
+		if pn, ok := merged[parent]; !ok || !slices.Contains(pn.Words, last) {
+			delete(merged, p)
+		}
+	}
+	return &Keywords{nodes: merged}
+}
+
+func (k *Keywords) nodeMap() map[string]KeywordNode {
+	if k == nil {
+		return nil
+	}
+	return k.nodes
+}
+
+// MarshalKeywords writes k as ParseKeywords reads it, paths sorted, so a
+// capture diffs line by line against the last one.
+func MarshalKeywords(platformName string, k *Keywords) []byte {
+	var b strings.Builder
+	fmt.Fprintf(&b, "platform: %s\nnodes:\n", platformName)
+	paths := make([]string, 0, k.Len())
+	for p := range k.nodeMap() {
+		paths = append(paths, p)
+	}
+	slices.Sort(paths)
+	for _, p := range paths {
+		n := k.nodes[p]
+		quoted := make([]string, len(n.Words))
+		for i, w := range n.Words {
+			quoted[i] = fmt.Sprintf("%q", w)
+		}
+		fmt.Fprintf(&b, "  %q: {words: [%s], argument: %v}\n", p, strings.Join(quoted, ", "), n.Argument)
+	}
+	return []byte(b.String())
+}
````

<!-- patch: internal/policy/keywords.go -->
````diff
diff --git a/internal/policy/keywords.go b/internal/policy/keywords.go
new file mode 100644
index 0000000..12048e8
--- /dev/null
+++ b/internal/policy/keywords.go
@@ -0,0 +1,9 @@
+package policy
+
+import "github.com/blanketfish/port49/internal/platform"
+
+// setKeywords is a set's keyword tree for a platform (platform.KeywordsFor):
+// the projection sends a rule only where it proves the rule's words keywords
+// (spec §13 decision 27). It is the pinned set's measurement, never a
+// `platforms:` block's, and tests replace it to stand up a set of their own.
+var setKeywords = platform.KeywordsFor
````

<!-- patch: internal/policy/resolve.go -->
````diff
diff --git a/internal/policy/resolve.go b/internal/policy/resolve.go
index 89226ec..28dd332 100644
--- a/internal/policy/resolve.go
+++ b/internal/policy/resolve.go
@@ -260,7 +260,8 @@ func (p *Policy) project(c composition, b engine.Blob, dialect platform.Dialect)
 
 func (p *Policy) projectOnce(c composition, b engine.Blob, dialect platform.Dialect) (projection.Result, error) {
 	in := projection.Input{Platform: b.Platform, Dialect: dialect, Rules: b.Rules, Classes: b.Classes,
-		Normalize: b.Normalize, Facts: projection.FactsFor(dialect.CommandProjection)}
+		Normalize: b.Normalize, Facts: projection.FactsFor(dialect.CommandProjection),
+		Keywords: setKeywords(p.set, b.Platform)}
 	if c.level != "" {
 		level, ok := "", false
 		for l := c.level; l != "" && !ok; l = p.parents[l] {
````

<!-- patch: internal/projection/keywords.go -->
````diff
diff --git a/internal/projection/keywords.go b/internal/projection/keywords.go
new file mode 100644
index 0000000..146c797
--- /dev/null
+++ b/internal/projection/keywords.go
@@ -0,0 +1,154 @@
+package projection
+
+import (
+	"fmt"
+	"slices"
+	"strings"
+
+	"github.com/blanketfish/port49/internal/engine"
+)
+
+// Junos matches a deny-commands or allow-commands regex against a command's
+// keywords only, never its arguments: `^show interfaces fxp0( .*)?$` did not
+// refuse `show interfaces fxp0 terse` on either image, while a deny of
+// keywords refused them typed, abbreviated or piped
+// (tests/lab/results/L12-juniper_*.md, L9-juniper_*.md; spec §13 decision
+// 27). port49 has no Junos grammar, so a rule reaches the wire only where the
+// set's keyword tree proves each of its words a keyword (platform.Keywords).
+// What is proven is the one shape the device matches as port49 does: words,
+// optionally ending in `**`. A `*`, an entity class or a regex stands for an
+// argument, and so does a word the tree does not list at its place.
+
+// keywordShape is rule's words before any `**`, whether `**` ends it, and
+// the first term that is not a word, as its text, or "" where every term
+// before `**` is one.
+func keywordShape(rule string) (words []string, rest bool, other string) {
+	terms, err := engine.ParseRule(rule)
+	if err != nil {
+		return nil, false, rule
+	}
+	for _, t := range terms {
+		switch t.Kind {
+		case engine.Word:
+			words = append(words, t.Text)
+		case engine.Rest:
+			return words, true, ""
+		case engine.Any:
+			return words, false, "*"
+		case engine.Class:
+			return words, false, "@" + t.Text
+		default:
+			return words, false, "/" + t.Text + "/"
+		}
+	}
+	return words, false, ""
+}
+
+// argument is the first term of rule the keyword tree does not prove a
+// keyword, as the rule writes it, and the words before it, which are: ok
+// where every word is proven and none stands for an argument.
+func (g generator) argument(rule string) (term string, prefix []string, ok bool) {
+	words, _, other := keywordShape(rule)
+	for i, w := range words {
+		if !g.in.Keywords.Keyword(words[:i], w) {
+			return w, words[:i], false
+		}
+	}
+	if other != "" {
+		return other, words, false
+	}
+	return "", words, true
+}
+
+// denyProvable reports whether the device refuses every command a deny of
+// rule matches: each word is a keyword, so the command's keywords begin with
+// them, and a trailing `**` is the regex's own `( .*)?`. The device may
+// refuse more — `show interfaces` exactly also refuses `show interfaces
+// fxp0` — which is narrower, and fails closed.
+func (g generator) denyProvable(rule string) bool {
+	_, _, ok := g.argument(rule)
+	return ok
+}
+
+// unsendableAllow is why an allow of rule cannot go out, or "": on the
+// device an allow runs every command whose keywords its regex matches, so
+// it is sent only where those are the commands port49 permits under it. A
+// word that is not a keyword never matches, and an argument that may be typed
+// among the rule's words would be run too: `show interfaces terse` would also
+// run `show interfaces fxp0 terse`. Both are left off the wire, which is
+// narrower, and reported.
+func (g generator) unsendableAllow(rule string) string {
+	term, prefix, ok := g.argument(rule)
+	if !ok {
+		return argumentWhy(term, prefix) + ", so an allow of it never matches on the device"
+	}
+	// An argument typed before any of the rule's words, or after its last
+	// where no `**` permits one there, is one port49 does not permit.
+	words, rest, _ := keywordShape(rule)
+	places := len(words)
+	if !rest {
+		places++
+	}
+	for i := 0; i < places; i++ {
+		if g.in.Keywords.TakesArgument(words[:i]) {
+			at := strings.Join(words[:i], " ")
+			return fmt.Sprintf("an argument may be typed after %q, so an allow of it would also run %q with an "+
+				"argument there, which port49 does not permit", at, strings.TrimSpace(at+" <argument> "+
+				strings.Join(words[i:], " ")))
+		}
+	}
+	return ""
+}
+
+// argumentWhy says which term is not a proven keyword.
+func argumentWhy(term string, prefix []string) string {
+	if strings.HasPrefix(term, "@") || strings.HasPrefix(term, "/") || term == "*" {
+		return fmt.Sprintf("%s stands for an argument", term)
+	}
+	at := strings.Join(prefix, " ")
+	if at == "" {
+		return fmt.Sprintf("%q is not a keyword the lab measured at the start of a command", term)
+	}
+	return fmt.Sprintf("%q is not a keyword the lab measured after %q", term, at)
+}
+
+// configurationVerbs are the configuration-mode commands that change the
+// configuration. deny-commands never reaches a statement typed there: under a
+// deny naming `set system host-name`, the statement ran on both images
+// (tests/lab/results/L12-configuration-juniper_*.md). A reply that can enter
+// configuration mode carries no deny at all (configuration), so a deny
+// starting with one of these is enforced only as an operational command, where
+// the keyword tree proves it or it fails closed.
+var configurationVerbs = []string{"activate", "annotate", "commit", "copy", "deactivate", "delete", "edit",
+	"insert", "load", "protect", "rename", "replace", "rollback", "save", "set", "top", "unprotect", "up",
+	"wildcard"}
+
+// denyRefusal is the refusal of a deny that meets a permit and is not proven
+// keyword-only: configuration_deny where its first word is a configuration
+// verb, argument_deny otherwise.
+func (g generator) denyRefusal(d engine.Rule) error {
+	words, _, _ := keywordShape(d.Rule)
+	if len(words) == 0 || !slices.Contains(configurationVerbs, strings.ToLower(words[0])) {
+		return g.argumentDeny(d)
+	}
+	term, prefix, _ := g.argument(d.Rule)
+	return refuse(FailConfigurationDeny, "on %s, `deny %s` (role %q) names a configuration statement, and Junos "+
+		"never applies deny-commands in configuration mode: on both images a statement ran there under a "+
+		"deny-commands naming it (tests/lab/results/L12-configuration-juniper_*.md), and deny-configuration is not "+
+		"measured; as an operational command it is not proven either (%s). port49 cannot enforce it: drop the rule",
+		g.in.Platform, d.Rule, d.Role, argumentWhy(term, prefix))
+}
+
+// argumentDeny is decision 27's refusal of a deny port49 needs enforced and
+// the device cannot: the subject gets the fail-closed reply, and `policy
+// test` and `policy diff` name the word and the whole command to deny instead.
+func (g generator) argumentDeny(d engine.Rule) error {
+	term, prefix, _ := g.argument(d.Rule)
+	instead := "drop the rule"
+	if len(prefix) > 0 {
+		instead = fmt.Sprintf("deny the whole command (`%s`) or drop the rule", strings.Join(prefix, " "))
+	}
+	return refuse(FailArgumentDeny, "on %s, Junos can't deny by argument: `%s` in `deny %s` (role %q): %s, and "+
+		"Junos matches a deny against a command's keywords only (tests/lab/results/L12-juniper_*.md); %s",
+		g.in.Platform, term, d.Rule, d.Role, argumentWhy(term, prefix), instead)
+}
````

<!-- patch: internal/projection/project.go -->
````diff
diff --git a/internal/projection/project.go b/internal/projection/project.go
index 3beb309..321c77d 100644
--- a/internal/projection/project.go
+++ b/internal/projection/project.go
@@ -39,6 +39,15 @@ const (
 	FailUnwritable        = "unwritable"
 	FailSecretRule        = "secret_rule"
 	FailUnsound           = "unsound"
+	// FailArgumentDeny is a deny that meets a permit and names a word the
+	// keyword tree does not prove a keyword: Junos never matches it
+	// (decision 27).
+	FailArgumentDeny = "argument_deny"
+	// FailConfigurationDeny is a deny that meets a permit, names a
+	// configuration statement, and is no operational command the keyword
+	// tree proves: deny-commands never reaches configuration mode, and
+	// deny-configuration is not measured (decision 27).
+	FailConfigurationDeny = "configuration_deny"
 )
 
 // JunosFacts are what the Junos images were measured doing with a command
@@ -74,6 +83,10 @@ type Input struct {
 	// sent (spec §5.8).
 	Secret func(rule string) bool
 	Facts  Facts
+	// Keywords is the platform's keyword tree, from the policy's pinned set
+	// (platform.KeywordsFor): a rule reaches the wire only where it proves
+	// the rule's words keywords. Nil proves nothing.
+	Keywords *platform.Keywords
 }
 
 // Result is the reply a composition renders to, and what CI reports of it
@@ -103,6 +116,10 @@ type Result struct {
 	// mode, left out because the composition is not a grant of every command
 	// with no deny and the rest proved sound without them (decision 26).
 	ConfigurationDropped []string
+	// Unsent are permits whose allow the device would not match as port49
+	// does, left off the wire: the device refuses what port49 permits there,
+	// and `policy test` warns (projection_argument_allow; decision 27).
+	Unsent []Unsent
 	// FailClosed is why the reply is ShapeFailClosed, one of the Fail*
 	// constants; empty otherwise. Refusal says it for the report.
 	FailClosed string
@@ -129,6 +146,12 @@ type Refusal struct {
 
 func (r *Refusal) Error() string { return r.Why }
 
+// Unsent is a permit left off the wire, and why.
+type Unsent struct {
+	Rule engine.Rule
+	Why  string
+}
+
 func refuse(category, format string, args ...any) error {
 	return &Refusal{Category: category, Why: fmt.Sprintf(format, args...)}
 }
@@ -216,6 +239,17 @@ func (g generator) render() (Result, error) {
 				r.Role, g.in.Platform)
 		}
 	}
+	// A deny that meets a permit is one port49 needs the device to enforce,
+	// under an allow or under bits; one naming an argument never is (decision
+	// 27). A deny no permit meets is port49's no_rule_matched either way.
+	for _, d := range g.denies {
+		if d.Role == platform.BaselineBit || g.denyProvable(d.Rule) {
+			continue
+		}
+		if slices.ContainsFunc(g.permits, func(p engine.Rule) bool { return g.mayMeet(p.Rule, d.Rule) }) {
+			return Result{}, g.denyRefusal(d)
+		}
+	}
 	res, err := g.shape()
 	var r *Refusal
 	if !errors.As(err, &r) || r.Category != FailConfigurationMode ||
@@ -299,9 +333,23 @@ func (g generator) carves(held []string) []string {
 	return out
 }
 
-// entersConfiguration reports whether bit b's reach holds `configure`.
+// entersConfiguration reports whether bit b's reach holds a command that enters
+// configuration mode (configurationEntries).
 func (g generator) entersConfiguration(b string) bool {
-	return slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.contains(r, "configure") })
+	return slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool {
+		return slices.ContainsFunc(configurationEntries, func(e string) bool { return g.contains(r, e) })
+	})
+}
+
+// configurationEntries are the operational commands that enter configuration
+// mode: `configure` and its variants (`configure private`, `exclusive`,
+// `batch` begin with it), and `edit`, its alias (plan 5b pre-flight B-M1).
+var configurationEntries = []string{"configure", "edit"}
+
+// meetsConfiguration reports whether rule meets a command that enters
+// configuration mode.
+func (g generator) meetsConfiguration(rule string) bool {
+	return slices.ContainsFunc(configurationEntries, func(e string) bool { return g.mayMeet(rule, e+" **") })
 }
 
 // plain is bits without the ones that enter configuration mode.
@@ -440,6 +488,10 @@ func (g generator) capability() (Result, error) {
 		if dn, ok := g.allowable(p.Rule); !ok {
 			return Result{}, g.refusedShape(p, dn)
 		}
+		if why := g.unsendableAllow(p.Rule); why != "" {
+			res.Unsent = append(res.Unsent, Unsent{Rule: p, Why: why})
+			continue
+		}
 		res.Allows = append(res.Allows, p)
 	}
 	for _, dn := range g.denies {
@@ -452,6 +504,13 @@ func (g generator) capability() (Result, error) {
 	if len(res.Denies) > 0 && !g.in.Facts.DenyMatchesExpanded {
 		return Result{}, &narrowOnly{"a deny narrower than every command is walked past by abbreviating it"}
 	}
+	for _, dn := range res.Denies {
+		if !g.denyProvable(dn.Rule) {
+			// A deny the device would not enforce, of a command no permit
+			// meets: the narrow shape's `.*` holds it instead.
+			return Result{}, &narrowOnly{"a deny under the bits names an argument"}
+		}
+	}
 	return res, nil
 }
 
@@ -485,7 +544,7 @@ func (g generator) configuration(res Result) error {
 		}
 	}
 	for _, a := range res.Allows {
-		if what == "" && g.mayMeet(a.Rule, "configure **") {
+		if what == "" && g.meetsConfiguration(a.Rule) {
 			what = fmt.Sprintf("allow %q", a.Rule)
 		}
 	}
@@ -518,6 +577,10 @@ func (g generator) narrow() (Result, error) {
 		if dn, ok := g.allowable(p.Rule); !ok {
 			return Result{}, g.refusedShape(p, dn)
 		}
+		if why := g.unsendableAllow(p.Rule); why != "" {
+			res.Unsent = append(res.Unsent, Unsent{Rule: p, Why: why})
+			continue
+		}
 		res.Allows = append(res.Allows, p)
 	}
 	if g.in.Dialect.BitDelivery == platform.BitDeliveryLocalUserName {
@@ -662,10 +725,14 @@ func (g generator) failClosed(r *Refusal) (Result, error) {
 		_, ok := h.allowable(p.Rule)
 		secret := g.in.Secret != nil && g.in.Secret(p.Rule)
 		_, werr := ruleERE(p.Rule, g.in.Classes, false, g.in.Facts)
-		if secret || werr != nil || !ok || !h.within(p.Rule) || h.mayMeet(p.Rule, "configure **") {
+		if secret || werr != nil || !ok || !h.within(p.Rule) || h.meetsConfiguration(p.Rule) {
 			res.Beyond = append(res.Beyond, p)
 			continue
 		}
+		if why := h.unsendableAllow(p.Rule); why != "" {
+			res.Unsent = append(res.Unsent, Unsent{Rule: p, Why: why})
+			continue
+		}
 		res.Allows = append(res.Allows, p)
 	}
 	send := func() (Result, error) {
````

<!-- patch: platforms/keywords/README.md -->
````diff
diff --git a/platforms/keywords/README.md b/platforms/keywords/README.md
new file mode 100644
index 0000000..de7aa28
--- /dev/null
+++ b/platforms/keywords/README.md
@@ -0,0 +1,7 @@
+# Keyword trees
+
+`<set version>/<platform>.yaml` is a projected platform's CLI keyword tree, as the lab captured it
+on every image that set measures (spec §8; §15 L26). Junos matches `deny-commands` and
+`allow-commands` against a command's keywords only, so the projection sends a rule only where
+this tree proves each of its words a keyword. A released set's tree is never edited: a new
+capture ships in a new set.
````

<!-- patch: platforms/platforms.go -->
````diff
diff --git a/platforms/platforms.go b/platforms/platforms.go
index a558a07..bee82a9 100644
--- a/platforms/platforms.go
+++ b/platforms/platforms.go
@@ -22,3 +22,10 @@ var FS embed.FS
 //
 //go:embed redact.yaml
 var Redact []byte
+
+// Keywords is every set's CLI keyword trees: `keywords/<version>/<platform>.yaml`
+// (internal/platform.KeywordsFor). They sit outside the set directories, which
+// hold one adapter file per platform and nothing else.
+//
+//go:embed keywords
+var Keywords embed.FS
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/...`
Expected: every package `ok`, no `gofmt` output. Do not run `make build` while a lab run is in progress: the lab uses `bin/`.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/keywords.go internal/platform/keywords_test.go internal/policy/keywords.go internal/policy/keywords_test.go internal/policy/resolve.go internal/projection/keywords.go internal/projection/project.go internal/projection/project_test.go platforms/keywords/README.md platforms/platforms.go
git commit -m "$(cat <<'EOF'
feat: Junos matches keywords only; a rule reaches the wire only where the keyword tree proves it

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 12b: policy test warns about an allow Junos would not match as port49 does

**Files:**
- Modify: `internal/policy/lint.go` (`FindingProjectionArgumentAllow`; `Projections` reports each
  `Result.Unsent`)
- Test: `internal/policy/keywords_test.go`

**Interfaces:**
- Consumes: Task 12a's `Result.Unsent`.
- Produces: `FindingProjectionArgumentAllow = "projection_argument_allow"`, a warning: it is not
  counted by `ProjectionRefusals`, so it fails neither `policy test` nor `policy diff`.

The message names the subject, the platform, the rule, its role and why, and says what to do:
`subject "s" on juniper_junos: allow "show interfaces fxp0 **" (role "r") is not sent: "fxp0" is not
a keyword the lab measured after "show interfaces", so an allow of it never matches on the device;
the device refuses what port49 permits there. Permit the whole command with `**` after its keywords,
or drop the rule (spec §13 decision 27)`. The rule is redacted; the reason quotes only the rule's
own words, and a rule redaction would hide never reaches `Unsent` (its composition is refused as
`secret_rule` first). The constant sits beside `Projections`, not in the finding-kind block Task 18
edits.

- [ ] **Step 1: Write the failing test**

<!-- patch: internal/policy/keywords_test.go -->
````diff
diff --git a/internal/policy/keywords_test.go b/internal/policy/keywords_test.go
index beafd6c..a83d1e3 100644
--- a/internal/policy/keywords_test.go
+++ b/internal/policy/keywords_test.go
@@ -1,6 +1,11 @@
 package policy
 
-import "github.com/blanketfish/port49/internal/platform"
+import (
+	"strings"
+	"testing"
+
+	"github.com/blanketfish/port49/internal/platform"
+)
 
 // projectedKeywords is the test set's keyword tree: every word these tests
 // deny or allow on juniper_junos, as the lab's capture writes it. `show
@@ -32,3 +37,21 @@ func init() {
 		return shipped(version, name)
 	}
 }
+
+// An allow Junos would not match as port49 does is left off the reply, and
+// policy test warns, naming the rule and why, without failing (decision 27).
+func TestAnArgumentAllowIsAWarning(t *testing.T) {
+	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show version", "show interfaces fxp0 **", "show interfaces terse"]}
+`+subjOK+grantOK)
+	var got []string
+	for _, f := range p.Lint(noon) {
+		if f.Kind == FindingProjectionArgumentAllow {
+			got = append(got, f.Message)
+		}
+	}
+	if len(got) != 2 || !strings.Contains(got[0], `allow "show interfaces fxp0 **" (role "r") is not sent: "fxp0" is not a keyword`) ||
+		!strings.Contains(got[1], `would also run "show interfaces <argument> terse"`) || ProjectionRefusals(p.Lint(noon)) != 0 {
+		t.Fatalf("%q", got)
+	}
+}
````

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/policy/`
Expected: FAIL, build failed: `undefined: FindingProjectionArgumentAllow`.

- [ ] **Step 3: Add the warning**

<!-- patch: internal/policy/lint.go -->
````diff
diff --git a/internal/policy/lint.go b/internal/policy/lint.go
index ad27049..d157884 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -537,6 +537,14 @@ func (p *Policy) onGeneric(name string) bool {
 	return b.Replace || !shipped
 }
 
+// FindingProjectionArgumentAllow is a permit whose allow is left off a
+// Junos reply because the device would not match it as port49 does: it names
+// a word the keyword tree does not prove a keyword, or an argument may be
+// typed among its words (spec §13 decision 27). The device refuses what port49
+// permits there, which fails closed, so it is a warning and does not fail
+// `policy test`.
+const FindingProjectionArgumentAllow = "projection_argument_allow"
+
 // Projections reports each composition on a projected platform (spec §8,
 // "CI reports which shape each grant rendered under, the bit set it chose"):
 // once per subject, platform and reply, at now and at every later grant
@@ -571,6 +579,14 @@ func (p *Policy) Projections(now time.Time) []Finding {
 					continue // a quarantine or a refused mint, reported as one
 				}
 				pr := *res.Projection
+				// Why quotes only the rule's own words, and a rule redaction would
+				// hide is never among Unsent: its composition is refused first.
+				for _, u := range pr.Unsent {
+					add(FindingProjectionArgumentAllow, fmt.Sprintf("subject %q on %s: allow %q (role %q) is not sent: "+
+						"%s; the device refuses what port49 permits there. Permit the whole command with `**` after "+
+						"its keywords, or drop the rule (spec §13 decision 27)", name, d.Platform,
+						strings.Join(redacted(patterns, []string{u.Rule.Rule}), ""), u.Rule.Role, u.Why))
+				}
 				if pr.FailClosed == "" {
 					add(FindingProjection, projectionMessage(name, d.Platform, pr, patterns))
 					continue
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/...`
Expected: every package `ok`, no `gofmt` output. Do not run `make build` while a lab run is in progress: the lab uses `bin/`.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/keywords_test.go internal/policy/lint.go
git commit -m "$(cat <<'EOF'
feat: policy test warns about an allow Junos would not match as port49 does

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 13a: check-config's management-service allowlist, for Task 14's branch M

**Files:**
- Create: `internal/platform/services.go` (`rpcServicesOff`, `RPCServicesChecked`, `CheckServices`,
  `ServicesCapture`)
- Modify: `cmd/port49/devices.go` (`check-config` prints a `SERVICE:` line per finding)
- Test: `internal/platform/services_test.go`

**Interfaces:**
- Consumes: Task 13's projected block in `check-config`; `eachLine`, `ConfigFinding`.
- Produces: `var platform.rpcServicesOff = false`, the switch branch M flips; `func
  RPCServicesChecked(d Dialect) bool`; `func CheckServices(d Dialect, config []byte)
  ([]ConfigFinding, error)`; `const ServicesCapture`.

Re-pre-flight C1, ruled by the lead: where Task 3b finds that a deny does not bind an RPC, the
device must run no management service but the CLI's, checked as an **allowlist**. Only `system
services ssh` and `telnet` may be on; anything else under `system services`, an unknown name
included, fails, and so does `rest`, `web-management` or `extension-service` anywhere in the
hierarchy. The input must be `show configuration | display set | display inheritance | except
"^set groups "`: groups' statements expanded where they apply, their definitions left out. Any
other form, a `set groups` line included, is refused with that capture named, since a service
behind it could be missed. A `deactivate` line enables nothing. The code ships now and does
nothing until branch M sets `rpcServicesOff = true`, so no Task 14 edit depends on the lab's answer
beyond that one line. The test turns the switch on to exercise the check.

- [ ] **Step 1: Write the failing test**

<!-- patch: internal/platform/services_test.go -->
````diff
diff --git a/internal/platform/services_test.go b/internal/platform/services_test.go
new file mode 100644
index 0000000..88d8398
--- /dev/null
+++ b/internal/platform/services_test.go
@@ -0,0 +1,51 @@
+package platform
+
+import (
+	"strings"
+	"testing"
+)
+
+// With branch M's switch on, a projected Junos device passes only with no
+// management service but the CLI's: anything else under system services,
+// an unknown name included, and REST, J-Web or extension-service at any
+// hierarchy fail. Input not in the one form the check reads is refused, a
+// group definition included, since a service behind one could be missed
+// (plan 5b pre-flight C1).
+func TestCheckServices(t *testing.T) {
+	d := junosProjected(BitDeliveryLocalUserName)
+	if RPCServicesChecked(d) {
+		t.Fatal("the switch is branch M's; it is off until the lab says denies do not bind RPCs")
+	}
+	if f, err := CheckServices(d, []byte("set system services netconf ssh\n")); f != nil || err != nil {
+		t.Fatalf("off: %v %v", f, err)
+	}
+	rpcServicesOff = true
+	defer func() { rpcServicesOff = false }()
+	clean := "set system host-name srx1\nset system services ssh root-login deny\nset system services telnet\n" +
+		"set interfaces fxp0 description \"rest of the lab\"\ndeactivate system services netconf\n"
+	if f, err := CheckServices(d, []byte(clean)); len(f) != 0 || err != nil {
+		t.Fatalf("clean: %+v %v", f, err)
+	}
+	for _, line := range []string{"set system services netconf ssh", "set system services xnm-ssl",
+		"set system services rest http port 3000", "set system services web-management https interface fxp0",
+		"set system services extension-service request-response grpc", "set system services outbound-ssh client c",
+		"set system services frobnicate", "set services rest control", "set system services dhcp-local-server group g"} {
+		f, err := CheckServices(d, []byte(clean+line+"\n"))
+		if err != nil || len(f) != 1 || f[0].Text != line || !strings.Contains(f[0].Says, "only `system services ssh`") {
+			t.Errorf("%s: %+v %v", line, f, err)
+		}
+	}
+	for _, bad := range []string{
+		clean + "set groups g system services rest\n",
+		"system {\n    services {\n        rest;\n    }\n}\n",
+		"",
+	} {
+		if _, err := CheckServices(d, []byte(bad)); err == nil || !strings.Contains(err.Error(), "display inheritance") {
+			t.Errorf("%.40q: %v", bad, err)
+		}
+	}
+	eos, _ := DialectFor("arista_eos")
+	if RPCServicesChecked(eos) {
+		t.Error("the check is a projected Junos adapter's")
+	}
+}
````

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/platform/`
Expected: FAIL, build failed: `undefined: RPCServicesChecked`, `undefined: CheckServices`,
`undefined: rpcServicesOff`.

- [ ] **Step 3: Add the check**

<!-- patch: cmd/port49/devices.go -->
````diff
diff --git a/cmd/port49/devices.go b/cmd/port49/devices.go
index fe4847c..4e9e5e8 100644
--- a/cmd/port49/devices.go
+++ b/cmd/port49/devices.go
@@ -107,7 +107,7 @@ func checkConfig(args []string, stdout, stderr io.Writer) int {
 		return 1
 	}
 	var templateMissing []string
-	var drift []platform.ConfigFinding
+	var drift, services []platform.ConfigFinding
 	if dialect.Projected() {
 		if *cfgPath == "" {
 			fmt.Fprintf(stderr, "port49 devices check-config: %s projects the policy into its session reply, so its "+
@@ -129,6 +129,13 @@ func checkConfig(args []string, stdout, stderr io.Writer) int {
 			fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", fs.Arg(0), err)
 			return 1
 		}
+		// Where a deny does not bind the RPCs a management service serves,
+		// every such service but the CLI's fails the device (plan 5b
+		// Task 14, branch M).
+		if services, err = platform.CheckServices(dialect, config); err != nil {
+			fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", fs.Arg(0), err)
+			return 1
+		}
 	} else if *cfgPath != "" {
 		fmt.Fprint(stderr, usage)
 		return 2
@@ -144,6 +151,10 @@ func checkConfig(args []string, stdout, stderr io.Writer) int {
 		failed++
 		fmt.Fprintf(stdout, "TEMPLATE: %s:%d: %s: %s\n", fs.Arg(0), f.Line, redact(f.Text), f.Says)
 	}
+	for _, f := range services {
+		failed++
+		fmt.Fprintf(stdout, "SERVICE: %s:%d: %s: %s\n", fs.Arg(0), f.Line, redact(f.Text), f.Says)
+	}
 	for _, a := range accounts {
 		// The daemon looks a context up by the canonical form of the username
 		// the device sends (spec §2), so a local NOC, CORP\noc or noc@corp
````

<!-- patch: internal/platform/services.go -->
````diff
diff --git a/internal/platform/services.go b/internal/platform/services.go
new file mode 100644
index 0000000..96bb153
--- /dev/null
+++ b/internal/platform/services.go
@@ -0,0 +1,96 @@
+package platform
+
+import (
+	"errors"
+	"regexp"
+	"slices"
+	"strings"
+)
+
+// rpcServicesOff is whether a projected Junos device must run no management
+// service but the CLI's: true only where tests/lab/results/L12-netconf-juniper_*.md
+// found a wire deny-commands, or the fail-closed reply, not binding a NETCONF
+// RPC on either image (plan 5b Task 14, branch M). A service that runs RPCs
+// under the same TACACS+ login and reply would then walk around every deny
+// port49 sends: `<get-configuration>` past `deny show configuration **`.
+var rpcServicesOff = false
+
+// RPCServicesChecked reports whether `port49 devices check-config` holds a
+// device of d to the management-service allowlist (CheckServices).
+func RPCServicesChecked(d Dialect) bool {
+	return rpcServicesOff && d.CommandProjection == ProjectionJunosRegex
+}
+
+// cliServices are the only services under `system services` a checked
+// device may enable: the CLI's own transports. `ssh` serves NETCONF only
+// through `system services netconf ssh`, which is not on the list. Anything
+// else under `system services`, a name this list does not know included,
+// fails (plan 5b pre-flight C1: an allowlist, not a denylist).
+var cliServices = []string{"ssh", "telnet"}
+
+// rpcAnywhere are service names that run RPCs wherever in the hierarchy they
+// appear: the REST API, J-Web, and JET/gRPC/gNMI.
+var rpcAnywhere = []string{"rest", "web-management", "extension-service"}
+
+// ServicesCapture is the one form CheckServices reads: set form, groups'
+// statements expanded where they apply, and the group definitions left out,
+// so no statement is hidden behind a group the check cannot resolve.
+const ServicesCapture = `show configuration | display set | display inheritance | except "^set groups "`
+
+var quoted = regexp.MustCompile(`"[^"]*"`)
+
+// CheckServices reads a device's configuration, as ServicesCapture prints
+// it, where RPCServicesChecked(d): every management service but the CLI's is
+// a finding. It is an error where the input is not in that form — a line
+// that is not a set statement, or a `set groups` line whose statements the
+// check cannot resolve — since then a service could be missed. Where d is not
+// checked it reads nothing.
+func CheckServices(d Dialect, config []byte) ([]ConfigFinding, error) {
+	if !RPCServicesChecked(d) {
+		return nil, nil
+	}
+	var findings []ConfigFinding
+	var formErr error
+	statements := 0
+	err := eachLine(config, func(n int, line string) {
+		line = strings.Join(strings.Fields(line), " ")
+		if formErr != nil || line == "" {
+			return
+		}
+		switch {
+		case strings.HasPrefix(line, "set groups "):
+			formErr = errors.New("the configuration holds a group definition, whose statements the check cannot " +
+				"resolve: capture it with `" + ServicesCapture + "`")
+			return
+		case strings.HasPrefix(line, "deactivate "):
+			return // an inactive statement enables nothing
+		case !strings.HasPrefix(line, "set "):
+			formErr = errors.New("the configuration is not in set form: capture it with `" + ServicesCapture + "`")
+			return
+		}
+		statements++
+		words := strings.Fields(quoted.ReplaceAllString(line, `""`))
+		if len(words) >= 4 && words[1] == "system" && words[2] == "services" && !slices.Contains(cliServices, words[3]) {
+			findings = append(findings, ConfigFinding{Line: n, Text: line, Says: servicesSays})
+			return
+		}
+		if slices.ContainsFunc(words, func(w string) bool { return slices.Contains(rpcAnywhere, w) }) {
+			findings = append(findings, ConfigFinding{Line: n, Text: line, Says: servicesSays})
+		}
+	})
+	if err != nil {
+		return nil, err
+	}
+	if formErr != nil {
+		return nil, formErr
+	}
+	if statements == 0 {
+		return nil, errors.New("the configuration holds no set statement: capture it with `" + ServicesCapture + "`")
+	}
+	return findings, nil
+}
+
+const servicesSays = "a management service other than the CLI's is enabled, and a port49 deny does not bind the RPCs " +
+	"it serves (tests/lab/results/L12-netconf-juniper_*.md): a session walks around every deny port49 sends. On a " +
+	"projected Junos device only `system services ssh` and `telnet` may be on: disable this one, or pin a set that " +
+	"does not project Junos"
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/...`
Expected: every package `ok`, no `gofmt` output. Do not run `make build` while a lab run is in progress: the lab uses `bin/`.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/devices.go internal/platform/services.go internal/platform/services_test.go
git commit -m "$(cat <<'EOF'
feat: check-config's management-service allowlist, for a device whose RPCs no deny binds

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 14, amended: ship the keyword tree, and read `DenyMatchesExpanded` from the keyword cell

Insert this step after "Add the set", before "Apply what the lab measured":

- [ ] **Step 3a: Ship the keyword tree**

Apply the merge tool, then merge Task 3b's two trees into the set's:

<!-- patch: tests/lab/cmd/junos-keywords/main.go -->
````diff
diff --git a/tests/lab/cmd/junos-keywords/main.go b/tests/lab/cmd/junos-keywords/main.go
new file mode 100644
index 0000000..48ac082
--- /dev/null
+++ b/tests/lab/cmd/junos-keywords/main.go
@@ -0,0 +1,52 @@
+// Command junos-keywords merges the lab's per-image Junos keyword captures,
+// tests/lab/results/L26-keywords-<image>.yaml, into the tree a platform set
+// ships (spec §13 decision 27; §15 L26): what every image proves, a keyword
+// on one image only left out, an argument on any image kept. It writes the
+// tree to stdout, in the form platform.ParseKeywords reads.
+//
+//	go run ./tests/lab/cmd/junos-keywords tests/lab/results/L26-keywords-*.yaml \
+//	  > platforms/keywords/1.1.0/juniper_junos.yaml
+package main
+
+import (
+	"fmt"
+	"os"
+
+	"github.com/blanketfish/port49/internal/platform"
+)
+
+func main() {
+	if err := run(os.Args[1:]); err != nil {
+		fmt.Fprintln(os.Stderr, "junos-keywords:", err)
+		os.Exit(1)
+	}
+}
+
+func run(files []string) error {
+	if len(files) < 2 {
+		return fmt.Errorf("give every image's capture, at least two: a keyword one image lacks is not proven")
+	}
+	var trees []*platform.Keywords
+	name := ""
+	for _, f := range files {
+		raw, err := os.ReadFile(f)
+		if err != nil {
+			return err
+		}
+		n, k, err := platform.ParseKeywords(raw)
+		if err != nil {
+			return fmt.Errorf("%s: %w", f, err)
+		}
+		if name != "" && n != name {
+			return fmt.Errorf("%s names platform %q, and %s %q", f, n, files[0], name)
+		}
+		name = n
+		trees = append(trees, k)
+	}
+	out := platform.MarshalKeywords(name, platform.MergeKeywords(trees...))
+	if _, k, err := platform.ParseKeywords(out); err != nil || k.Len() == 0 {
+		return fmt.Errorf("the merged tree does not load (%v), or is empty", err)
+	}
+	_, err := os.Stdout.Write(out)
+	return err
+}
````

```bash
mkdir -p platforms/keywords/1.1.0
go run ./tests/lab/cmd/junos-keywords tests/lab/results/L26-keywords-juniper_vjunos-router.yaml \
  tests/lab/results/L26-keywords-juniper_vsrx.yaml > platforms/keywords/1.1.0/juniper_junos.yaml
go test ./internal/platform/ -run 'Keyword'
```

Expected: the file is written, and `TestShippedKeywordTreesLoad` passes, which holds it within 5,000
nodes and 1 MiB. The merge keeps what both images prove: a keyword on one image only is left out,
an argument on either is kept. Add `platforms/keywords/1.1.0/juniper_junos.yaml` and
`tests/lab/cmd/junos-keywords/main.go` to the task's commit.

If Task 3b produced no tree on either image (pre-flight A-M3), ship 1.1.0 with **no** keyword
tree: skip the merge, and write in the adapter comment and the commit message that no Junos rule
is proven. Every live Junos deny then fails closed and no allow is sent, so every Junos
composition that is not a pure bits grant gets the fail-closed reply, and `policy test` names each
one before anyone pins the set. Report it to the controller: it ships a projection that denies
nearly everything, which is closed and loud, rather than branch A's unprojected Junos. In the
adapter file, above `bits:`, write the tree's scope: "The keyword tree
(platforms/keywords/1.1.0/juniper_junos.yaml) is proven on vJunos-router 23.4R2-S2.1 and vSRX
21.4R3.15 only (tests/lab/results/L26-juniper_*.md); on another release or hardware family a word
it proves a keyword may take an argument (spec §8)."

In Step 4's branch table:
- **Branch A** loses nothing and gains nothing: a deny naming an argument is decision 27's, handled
  by Task 12a, and is never a reason to ship Junos unprojected.
- **Branch B**, replaced (the lead's ruling of 2026-09-25): `CaseSensitive` is `false` (Task 2: the
  CLI refuses an upper-case keyword itself). `DenyMatchesExpanded` stays **false** unless **both**
  `L9-abbreviations-juniper_*.md` notes (Task 3b) read `JunosFacts.DenyMatchesExpanded (keywords) =
  true`: every one of their twenty-one probes refused under the deny, and the control ran every
  unambiguous one. Task 2's single `sh ver` cell does not set it, and neither does its read-off
  line, which mixed in the argument deny. Write `var JunosFacts = Facts{CaseSensitive: false,
  DenyMatchesExpanded: <true only as above>}`, citing the notes and decision 27 in the comment above
  it. While it is false, a composition that needs a deny on the wire keeps the fail-closed reply.
- **Branch B2**, new (Task 7's fix `eaf7975` changed the rendered deny to ` *… *(\|.*)?`, which no
  lab has measured; Task 2 measured `( *\|.*)?`). Read `the rendered deny shape … enforced` in
  both `L9-abbreviations-juniper_*.md` notes. If both say true, change nothing. If either says
  false, the device does not enforce the rendered shape: revert to exactly the shape Task 2
  measured refusing `show version`, `show version | no-more` and `sh ver` on both images,
  `^show version( *\|.*)?$` (re-pre-flight R-M7). In `internal/projection/ere.go` set `denyLead =
  ""` and `pipeTail = `( *\|.*)?``, and in `ruleERE` write a deny's words joined by one space,
  as an allow's are (`pick(deny, " +", " ")` becomes `" "`), since Task 2 measured single spaces
  and ` +` is unmeasured. Update Task 7's and Task 8's expected strings to that shape, and say so in
  the commit message. If Task 2's shape is not enforced either, take
  branch A.
- **Branch M**, new (pre-flight B1, re-pre-flight C1): read `L12-netconf-juniper_*.md`. If both
  notes say deny-commands and the fail-closed reply bind NETCONF RPCs, record it in the commit
  message and change nothing. If either says not, or the images disagree, a deny port49 sends is
  walked around by any service that runs Junos RPCs under the same login and reply, so a projected
  Junos device must run none but the CLI's. In `internal/platform/services.go` (Task 13a) set `var
  rpcServicesOff = true` and rewrite its comment to cite both notes. That turns on Task 13a's
  **allowlist**: `devices check-config` passes a projected Junos device only where nothing under
  `system services` is on but `ssh` (whose NETCONF is the separate `netconf ssh`) and `telnet`,
  an unknown service name included, and where `rest`, `web-management` and `extension-service`
  appear nowhere in the hierarchy. It reads only `show configuration | display set | display
  inheritance | except "^set groups "`, so a service a group applies is expanded where it applies,
  and it refuses any other input, a leftover `set groups` line included, saying which capture to
  make. The services this rules out, to name in the adapter comment (above `bits:`) and the
  operator notes: NETCONF (`netconf ssh`), the XML API (`xnm-ssh`, `xnm-ssl`, `xnm-clear-text`),
  REST (`rest`), J-Web (`web-management`), JET/gRPC/gNMI (`extension-service`), device-initiated
  NETCONF (`outbound-ssh`) and anything this build does not know. Junos cannot turn them off per
  user, so they are off outright. Task 19 then disables NETCONF for its run and expects every
  NETCONF session refused (`netconfForbidden` reads the same switch). If an image serves RPCs with
  no `system services` statement the capture shows, the check cannot see it: take branch A.
- **Branch J**, rewritten: `deny-commands` does not reach configuration mode, measured on both
  images (`L12-configuration-juniper_*.md`). Nothing changes in code: no reply that can configure
  carries a deny, and a configuration-statement deny fails closed (Task 12a). Write it into the
  commit message, and carry "measure deny-configuration(-regexps) over the wire" (Task 20).

### Task 19, amended: an argument deny, an argument allow, an enumerated value

Apply this block after Task 19's own. It adds five shapes — a deny naming an argument, which must
get the fail-closed reply; an allow naming one, which is not sent, so the device refuses what port49
permits; a deny naming an enumerated value (`show route protocol static`), which reaches the wire
only if Task 3b's tree proved `static` a keyword; and, for pre-flight A1, `deny monitor traffic
interface fxp0 **` beside `permit monitor **` (a value under a command with no RPC) and `deny ping
routing-instance mgmt_junos **` beside `permit ping **` (a value under a command that still needs
a host), each of which must get the fail-closed reply, and so fail CI — and the probe `show route
protocol static`. No probe streams: under the fail-closed reply `monitor` and `ping` are refused
outright, and a reply that let them run would fail the test's fail-open check at the first probe.

It also adds a NETCONF check to every shape (pre-flight B1): with the shape's own token, which gets
the same reply, it sends `<get-configuration/>` and `<get-software-information/>` and fails the test
where the device runs one whose command (`show configuration`, `show version`) port49 denies. Where
Task 14's branch M made set 1.1.0 forbid NETCONF, the run disables it on the device, as an operator
must, puts `netconf ssh` back after, and expects every NETCONF session refused; `netconfForbidden`
reads Task 13a's switch. The check sends the same four RPCs as Task 3b. "Admin with a deny" now
expects the fail-closed reply: nothing under `request` is proven in 1.1.0 (re-pre-flight R-M2).

A new shape, "admin keeping a keyword deny" (`permit **`, `deny show configuration **`), exercises
the admin that keeps its deny with the configuration bits dropped. Its probes include the denied
command in full, abbreviated, in upper case, piped and padded with spaces, and `edit` beside
`configure`. For it the test asserts that the device never enters configuration mode by
`configure` or `edit`; that every form of the denied command is refused, on the CLI and over
NETCONF (the fail-open checks); and, where it renders rather than failing closed, that the device
runs every command the reply was proven to let run. Under 1.1.0's facts as shipped
(`DenyMatchesExpanded` false) it gets the fail-closed reply, where the refusals still hold; it
renders once Task 14's branches B and C allow, and the note says which. The
test's fail-open check is what catches a misclassified value: if the tree called it a keyword and
the device ignores the deny, the device runs a command port49 denies, and the test fails.

<!-- patch: tests/lab/projection_test.go -->
````diff
diff --git a/tests/lab/projection_test.go b/tests/lab/projection_test.go
index 70aacec..b5bc6d3 100644
--- a/tests/lab/projection_test.go
+++ b/tests/lab/projection_test.go
@@ -61,7 +61,12 @@ var projectionProbes = []projectionProbe{
 	{junosProbe{cmd: "SHOW CONFIGURATION SYSTEM HOST-NAME", evidence: hostEvidence}, "show configuration system host-name"},
 	{junosProbe{cmd: "show configuration system host-name | display set", evidence: hostEvidence},
 		"show configuration system host-name"},
+	{junosProbe{cmd: "   show configuration system host-name   ", evidence: hostEvidence},
+		"show configuration system host-name"},
 	{junosProbe{cmd: "show route summary"}, "show route summary"},
+	// An enumerated value: the keyword tree must not prove `static` a keyword
+	// unless Junos matches a deny against it (decision 27).
+	{junosProbe{cmd: "show route protocol static"}, "show route protocol static"},
 	{junosProbe{cmd: "clear interfaces statistics fxp0"}, "clear interfaces statistics fxp0"},
 	{junosProbe{cmd: "ping 127.0.0.1 count 1 rapid"}, "ping 127.0.0.1 count 1 rapid"},
 	{junosProbe{cmd: "sh ver"}, "show version"},
@@ -75,8 +80,12 @@ var projectionProbes = []projectionProbe{
 	// Configuration mode, typed last: a statement there is governed by the
 	// class's configuration permissions, which no command regex reaches.
 	{junosProbe{cmd: "configure"}, "configure"},
+	{junosProbe{cmd: "edit"}, "edit"},
 }
 
+// configEntry reports whether cmd enters configuration mode.
+func configEntry(cmd string) bool { return cmd == "configure" || cmd == "edit" }
+
 // projectionShapes are the rule shapes the generator produces, and the one
 // no measurement lets it carry. Each is the roles block of a policy pinning
 // set 1.1.0. Which shape a composition renders to is the generator's, from
@@ -96,8 +105,32 @@ var projectionShapes = []struct {
 	{"a permit beyond the bits", `  - {name: r, privilege: readonly, permit: ["show **", "clear interfaces statistics **"]}`, false},
 	{"operator", `  - {name: r, privilege: operator, permit: ["show **", "clear **", "ping **"]}`, false},
 	{"admin", `  - {name: r, privilege: admin, permit: ["**"]}`, false},
-	{"admin with a deny", `  - {name: r, privilege: admin, permit: ["**"], deny: ["request system reboot **"]}`, false},
+	// Under 1.1.0's keyword tree nothing under `request` is proven, so this
+	// deny fails closed (re-pre-flight R-M2), and no shape in this list
+	// exercises a capability shape carrying a deny on the device.
+	{"admin with a deny", `  - {name: r, privilege: admin, permit: ["**"], deny: ["request system reboot **"]}`, true},
+	// An admin keeping a keyword deny under `show` (re-pre-flight minor):
+	// with the bits that enter configuration mode dropped, the reply carries
+	// the deny, the device refuses the configuration in every form typed and
+	// over NETCONF, runs everything else the model says it runs, and never
+	// enters configure or edit. Under set 1.1.0's facts as shipped
+	// (DenyMatchesExpanded false) it is the fail-closed reply, where the
+	// same refusals hold; it renders once Task 14's branches B and C allow.
+	{"admin keeping a keyword deny", `  - {name: r, privilege: admin, permit: ["**"], deny: ["show configuration **"]}`, false},
 	{"the refused shape", `  - {name: r, privilege: readonly, permit: ["show interfaces **", "show version"], deny: ["show interfaces terse"]}`, true},
+	// Junos matches keywords only (decision 27): a deny naming an argument
+	// fails closed, an allow naming one is not sent, and a deny naming an
+	// enumerated value runs only if the keyword tree proved it a keyword, which
+	// the fail-open check then tests on the device.
+	{"a deny naming an argument", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show interfaces fxp0 **"]}`, true},
+	{"an allow naming an argument", `  - {name: r, privilege: readonly, permit: ["show version", "show interfaces fxp0 **"]}`, false},
+	{"a deny naming an enumerated value", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show route protocol static"]}`, false},
+	// A value under a command with no RPC, and one under a command that still
+	// needs another argument: neither is proven a keyword (pre-flight A1), so
+	// each deny fails closed and fails CI. Nothing here streams: the
+	// fail-closed reply refuses `monitor` and `ping` outright.
+	{"a deny of a value under a command with no RPC", `  - {name: r, privilege: operator, permit: ["show **", "monitor **"], deny: ["monitor traffic interface fxp0 **"]}`, true},
+	{"a deny of a value under an incomplete command", `  - {name: r, privilege: operator, permit: ["show **", "ping **"], deny: ["ping routing-instance mgmt_junos **"]}`, true},
 }
 
 func TestProjectionDifferential(t *testing.T) {
@@ -121,6 +154,14 @@ func TestProjectionDifferential(t *testing.T) {
 		defer stop()
 		l.junosConfigureAdmin(t, reference)
 		defer l.junosConfigureAdmin(t, projectionRestore(reference))
+		// Where set 1.1.0 requires NETCONF disabled (plan 5b Task 14, branch
+		// M), the run disables it as the operator must, and puts the lab's
+		// `netconf ssh` back after.
+		netconfOff := netconfForbidden(set["juniper_junos"])
+		if netconfOff {
+			l.junosConfigureAdmin(t, []string{"delete system services netconf"})
+			defer l.junosConfigureAdmin(t, []string{"set system services netconf ssh"})
+		}
 		pki := filepath.Join(root, slicePKIDir)
 		if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
 			t.Fatal(err)
@@ -142,7 +183,8 @@ func TestProjectionDifferential(t *testing.T) {
 		fmt.Fprintf(&b, "\nThe binary's JunosFacts: %+v.\n", projection.JunosFacts)
 		for _, shape := range projectionShapes {
 			fmt.Fprintf(&b, "\n### %s\n\n", shape.name)
-			b.WriteString(l.projectionShape(t, port49, pki, inv.Devices, shape.name, shape.roles, shape.failClosed))
+			b.WriteString(l.projectionShape(t, port49, pki, inv.Devices, shape.name, shape.roles, shape.failClosed,
+				netconfOff))
 		}
 		l.result(t, "L12-projection", "Decisions 22 and 26's projection, differentially: for each rule shape the "+
 			"generator produces, what the device runs under the reply port49 renders, typed as an operator might "+
@@ -155,7 +197,7 @@ func TestProjectionDifferential(t *testing.T) {
 
 // projectionShape runs one shape and renders its section of the note.
 func (l *lab) projectionShape(t *testing.T, port49, pki string, devices []admission.Device, name, roles string,
-	failClosed bool) string {
+	failClosed, netconfOff bool) string {
 	t.Helper()
 	body := "platform_set: 1.1.0\nscopes:\n  - {name: all_devices, match: {}}\nroles:\n" + roles + "\n" +
 		"subjects:\n  - {name: slice_operator, identity: [\"" + slicePrincipal + "\"], username: " + sliceUser +
@@ -248,7 +290,7 @@ func (l *lab) projectionShape(t *testing.T, port49, pki string, devices []admiss
 		if p.complete {
 			ran = r.completes(p.junosProbe)
 		}
-		if p.cmd == "configure" && strings.Contains(devOut, "configuration mode") {
+		if configEntry(p.cmd) && strings.Contains(devOut, "configuration mode") {
 			ran = true
 			if _, err := c.sendExpect("exit configuration-mode", junosPer, junosOpPrompt); err != nil {
 				t.Errorf("%s: leaving configuration mode not observed within %s: %v", name, junosPer, err)
@@ -263,7 +305,13 @@ func (l *lab) projectionShape(t *testing.T, port49, pki string, devices []admiss
 		// a command it runs and the model says it refuses is a model defect
 		// even where port49 permits it. The device refusing what the model
 		// says it runs is narrower, which fails closed, and is recorded.
+		keepsDeny := name == "admin keeping a keyword deny"
 		switch {
+		case keepsDeny && configEntry(p.cmd) && ran:
+			t.Errorf("%s: the device entered configuration mode by %q under a reply that carries a deny", name, p.cmd)
+		case keepsDeny && res.Projection.FailClosed == "" && predicts && o.Permit && !ran && !p.complete &&
+			!configEntry(p.cmd):
+			t.Errorf("%s: the device refused %q, which port49 permits and the reply was proven to let run", name, p.cmd)
 		case ran && !o.Permit:
 			t.Errorf("%s: the device ran %q, which port49 denies (%s): the projection fails open", name, p.cmd, o.Reason)
 		case ran && !predicts:
@@ -273,6 +321,58 @@ func (l *lab) projectionShape(t *testing.T, port49, pki string, devices []admiss
 		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s | %s |\n", p.cmd, p.canonical, verdictWord(o.Permit),
 			verb(predicts), verb(ran), yesNo(ran == o.Permit))
 	}
+	b.WriteString(l.projectionNetconf(t, name, pol, device, tok, netconfOff))
+	return b.String()
+}
+
+// netconfForbidden reports whether check-config holds a device of d to the
+// management-service allowlist, which fails one serving NETCONF (plan 5b
+// Task 14, branch M; platform.CheckServices).
+func netconfForbidden(d adapter.Dialect) bool { return adapter.RPCServicesChecked(d) }
+
+// projectionNetconf opens NETCONF with the shape's token, which gets the same
+// reply, and sends the RPC equivalents of `show configuration` and `show
+// version` (TestL12JunosNetconf's): an RPC the device runs where port49
+// denies its command fails the test, as the CLI's fail-open check does (plan
+// 5b pre-flight B1). Where the set requires NETCONF disabled, the session
+// must not open. Each RPC has its deadline; a reply that is neither output
+// nor an `<rpc-error>` is not observed.
+func (l *lab) projectionNetconf(t *testing.T, name string, pol *policy.Policy, device admission.Device, tok string,
+	off bool) string {
+	t.Helper()
+	n, hello, err := l.netconfDial(sliceUser, tok)
+	if off {
+		if err == nil {
+			n.Close()
+			t.Errorf("%s: NETCONF opened, and set 1.1.0 requires it disabled", name)
+			return "\nNETCONF opened, although set 1.1.0 requires it disabled.\n"
+		}
+		return "\nNETCONF is disabled, as set 1.1.0 requires: `" + oneLine(err.Error()) + "`\n"
+	}
+	if err != nil {
+		t.Errorf("%s: the NETCONF session did not open: %v (%s)", name, err, oneLine(hello))
+		return "\nNETCONF: not observed, `" + oneLine(err.Error()) + "`\n"
+	}
+	defer n.Close()
+	var b strings.Builder
+	b.WriteString("\n| NETCONF RPC | as the command | port49 | device |\n|---|---|---|---|\n")
+	for k, r := range junosNetconfRPCs {
+		reply, err := n.rpc(k+1, r.rpc)
+		cell := netconfCell(reply, r.evidence)
+		if err != nil || cell == "not observed" {
+			t.Errorf("%s: %s not observed: %v %s", name, r.rpc, err, oneLine(reply))
+			cell = "not observed"
+		}
+		_, o, err := pol.Decide("slice_operator", "", device, r.command, time.Now())
+		if err != nil {
+			t.Fatalf("%s: %v", name, err)
+		}
+		if cell == "ran" && !o.Permit {
+			t.Errorf("%s: over NETCONF the device ran %s, and port49 denies %q (%s): the projection fails open "+
+				"over RPC", name, r.rpc, r.command, o.Reason)
+		}
+		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", r.rpc, r.command, verdictWord(o.Permit), cell)
+	}
 	return b.String()
 }
 
````

The run's token count is unchanged (the broker mints each), and the shapes add about three
minutes per image.

### Task 20, amended: close L26, freeze the tree, record decision 27

Apply this block with Task 20's, then add 1.1.0's entry to `releasedKeywords`, using the file's
sha256 (`sha256sum platforms/keywords/1.1.0/juniper_junos.yaml`):
`var releasedKeywords = map[string]string{"1.1.0/juniper_junos": "<that sha256>"}`.

<!-- patch: internal/platform/keywords_test.go -->
````diff
diff --git a/internal/platform/keywords_test.go b/internal/platform/keywords_test.go
index a234046..25fc17f 100644
--- a/internal/platform/keywords_test.go
+++ b/internal/platform/keywords_test.go
@@ -1,6 +1,7 @@
 package platform
 
 import (
+	"crypto/sha256"
 	"fmt"
 	"io/fs"
 	"path"
@@ -149,3 +150,21 @@ func TestShippedKeywordTreesLoad(t *testing.T) {
 		t.Fatal(err)
 	}
 }
+
+// releasedKeywords is each released set's keyword tree by the sha256 of its
+// file: a released set's tree is never edited, and a new capture ships in a
+// new set (plan 5b Task 20 adds 1.1.0's entry when it freezes the set).
+var releasedKeywords = map[string]string{}
+
+func TestReleasedKeywordTreesAreFrozen(t *testing.T) {
+	for file, want := range releasedKeywords {
+		raw, err := fs.ReadFile(platforms.Keywords, "keywords/"+file+".yaml")
+		if err != nil {
+			t.Errorf("%s: %v", file, err)
+			continue
+		}
+		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
+			t.Errorf("%s: sha256 %s, released as %s: a released tree is never edited; ship a new set", file, got, want)
+		}
+	}
+}
````

In §15, close **L26** on `L26-juniper_vjunos-router.md` and `L26-juniper_vsrx.md` if both runs
passed. Its paragraph under "What has been measured so far" gives each tree's size and says whether
the walk stopped at a bound; a path it did not reach proves nothing, by design. Add `platforms/keywords/1.1.0/juniper_junos.yaml` to the
commit. In the roadmap's "Plan 5b — As built", record decision 27, the tree's size, and which
spec §11 denies it proves. Carry, for a later plan: "measure deny-configuration(-regexps) over the
wire", which would let a configuration statement be denied in configuration mode; where branch M
disabled NETCONF, "measure whether an RPC-level deny (deny-commands on RPC names, or a class
setting) can bind NETCONF, so it can be enabled again"; "grow the
keyword capture's seed list where a fleet's denies fail as unproven"; "capture the keyword tree per
fleet release and hardware family" (A-M5); and "prove keywords outside `show`" with a mechanism that
runs nothing, so a deny under `request`, `clear` or `monitor` can be sent. Close **L9** only if both
`L9-abbreviations-juniper_*.md` notes passed, citing them beside Task 2's.

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
   key the move changes, all of them gated, and previews what the move quarantines or fails
   closed (Task 14). 1.1.0 is frozen when this plan merges (Task 20). Shipping the projection
   unpinned would change every Junos session on a binary upgrade, which is the unreviewed policy
   change the pin exists to stop.
2. **On a projected platform, `privilege:` is each level's ceiling in bits.** The field is
   `Dialect.CeilingBits`, and `Levels` stays nil, so no code path reads a bit name as an
   attribute. `Spec.Over` routes `privilege` by the merged `command_projection`, and `SpecOf`
   writes the bits back under `privilege`. Five keys are new: `command_projection` (`junos_regex`
   is the one value), `bits`, `bit_delivery`, `local_user_names` and `carve_outs`. Every one is
   gated in the diff, because a key is gated until it is listed as reported.
3. **The device model is a union, and only measured carve-outs subtract** (pre-flight C1). A
   command runs where a matching allow beats every deny (L11), or where some held bit's reach
   holds it and no deny matches. Junos permission bits are a union: a command two bits reach runs
   if either is held. The one subtraction is `carve_outs`, a list of commands a bit alone makes
   available whatever other bit reaches them, each measured (`view-configuration`'s `show
   configuration **`, Task 3). A bit not held removes nothing else. The bit `baseline` is what a
   class with no bits runs, measured by Task 3, held by every session and never sent. The
   generator denies on the wire each baseline command no permit holds. Over a set that projects,
   a block may add a rule to a bit's reach, which the diff gates as a widening, and may drop a
   carve-out; it may never remove reach, add a bit or add a carve-out (`keepsProjection`). The
   bits' reach and carve-outs are applied by the device's parser, so the model matches them as
   port49 matches a deny, the widest reading.
4. **A reply is proven before it is sent.** The generator checks each obligation from the rules'
   terms (Task 5's `engine.Contains`, `MayMeet`, `AlwaysDominates`):
   - a bit is sent only where every command it reaches is decided by one rule of the grant;
   - a permit is sent as an allow only where it dominates every deny it meets, and only within the
     level's ceiling bits, carve-outs counted;
   - a deny is left off the wire only where a measured carve-out of a bit not sent holds it;
   - bits that enter configuration mode, and an allow meeting `configure`, are sent only for a
     grant of every command (Decided 6).

   The same programs then decide one probe for each way the rules can be told apart
   (`engine.Probes`). One the device would run and port49 would deny is a defect, and that
   subject gets the fail-closed reply. Where the device is narrower than port49, for example a
   permit beyond the level's bits, the result fails closed and is reported.
5. **The regex dialect is read in the direction that fails closed until L9 measures it**
   (`projection.JunosFacts`):
   - every regex has explicit `^` and `$`, and every deny ends in the pipe tail `( *\|.*)?`,
     since the engine strips a pipeline before matching (pre-flight I2). The tail only makes a
     deny match more, so it stays whatever L9 says;
   - while the device matches case-sensitively, a deny's letters are written in both cases;
   - while a deny may be walked past by abbreviation (`sh conf`), no deny but `.*` is sent, so a
     capability shape that needs one goes narrow;
   - a deny is as wide as its rule: runs of spaces between words, and an argument that may hold a
     space; an allow is as narrow;
   - words are printable ASCII with no `{`, `}`, `"` or `\`, ERE operators are escaped, patterns
     are carried only in the subset of RE2 that means the same in POSIX ERE, and never as an empty
     group or alternative.

   Task 2 measures each fact, and Task 14 sets `JunosFacts` from its note. Where the two images
   disagree, the fail-closed value is used.
6. **Bits that enter configuration mode go only to a grant of every command with no deny.** In
   configuration mode a statement is governed by the class's configuration permissions, and
   `deny-commands` does not reach it. For decided item 6 of decision 26, an admin composition
   with a deny: under `user_permissions` the reply is rendered again without the bits that enter
   configuration mode, and sent that way if it proves sound; the admin keeps every operational
   command, less the deny, and `configure` is beyond the reply. That needs the deny on the wire,
   so until L9 measures that a deny reads the expanded command it too is the fail-closed reply.
   Under `local_user_name` the template's class carries the level's bits whole, so the
   composition gets the fail-closed reply.
7. **A composition the projection cannot carry fails closed for that subject alone** (decision
   26, owner's ruling 2026-09-25). The **fail-closed reply** is `deny-commands=^.*$`, an allow for
   each permit that is within the level's ceiling bits that do not enter configuration mode,
   dominates every deny it meets, does not meet `configure` and can be written, and no other bit
   or template. Under `user_permissions` it carries the smallest of those bits that reach the
   allows; under `local_user_name` no `local-user-name`, so the session lands in the bitless
   `p49-remote`. If the allows cannot go out whole, none does. It is proven as any reply is. The
   session is recorded `authorize_session`, permit, reason `projection_fail_closed`, a code Task 1
   adds to §5.7 first, and the blob carries why (`fail_closed`: `refused_shape`,
   `configuration_mode`, `overflow`, `unwritable`, `secret_rule` or `unsound`). Every other
   subject on the device keeps its reply. Decision 20's quarantine stays for inventory drift and
   the other joint checks.
8. **No role or grant sets an attribute the projection renders.** The rule covers
   `local-user-name`, `user-permissions`, and the command and configuration regex families, in
   every case and numbered variant the device reads (`allow-commands2`, `User-Permissions`;
   pre-flight I1), and every name the adapter lists as bearing privilege. It applies under a
   projected platform's key, and under `all` wherever a projected platform exists, and it is a
   load error (spec §8, "Generator constraints" 1, 4 and the new 6).
9. **CI refuses what the device cannot be told** (spec §8, "CI MUST refuse the policy").
   `policy test` reports each fail-closed composition as `projection_refused`, or
   `projection_overflow` for an attribute past 255 bytes, naming the subject, every device and
   why, and exits non-zero on any of them and on any quarantine, now or at a later expiry
   (pre-flight I10). `policy diff` exits non-zero on every fail-closed composition in the new
   version. The overflow's class line is printed for `deny-commands` only, and says it binds every
   subject at that template; an allow is never moved into a class, where it would run for every
   subject past their own denies (pre-flight C2). **The reply gate judges a projected reply by
   what the device can do under it** (pre-flight I14): a bit it did not hold, or a command it did
   not run, is a raise; a pure narrowing is not, and needs no `reply:` test.
10. **The ceiling is the projection's.** `exceeds` skips the projection's own attributes, since
    the generator renders them from the level's bits and never beyond them. 1.1.0 numbers Junos's
    levels `{readonly: 1, operator: 15, admin: 15}`. Every Junos request carries priv_lvl 1
    (`junos-session-service-juniper_vjunos-router.md`), and operator is numbered as admin, as
    decision 23 does where the number fences nothing. Task 2 records the priv_lvl each request
    carried.
11. **Operator's ceiling leaves out `reset`.** Spec §8's example gives operator `reset`, which
    restarts software processes. The owner's level definitions (2026-09-24) bind the adapters:
    operator is non-disruptive state changes and no configuration. 1.1.0's operator is `clear
    network trace view view-configuration`. Each bit's reach is a candidate that Task 3 verifies
    as an upper bound, one level under each word, and a failure widens it.
12. **The built-in adapter delivers bits by template (`local_user_name`) until L12 measures
    `user-permissions`.** L18 measured `user-permissions` changing nothing over a template whose
    class had bits (`tests/lab/results/L18-juniper_*.md`, variants 9 and 10), while
    `local-user-name` was applied under either flag. Task 14 switches the set to
    `user_permissions` only if Task 2's note shows it applied over a bitless template, both bits of
    a two-bit value applied, and per session.
13. **The reference classes are a replace, and `check-config` holds a device to them**
    (pre-flight I8, M8). `port49 platform export --classes --config port49d.yaml juniper_junos`
    prints `device_config`, then each template class and user as a `delete` followed by its `set`
    lines: the bitless `remote` in `p49-remote`, and each level's template. Every class carries
    `idle-timeout` from `session.max_session_age_default`, in whole minutes rounded down (decision
    21; L24 measures it). `port49 devices check-config --config` reads a `display set`
    configuration and fails on any reference line missing and any line under a template class or
    user the reference does not write.
14. **Capability inference reads the decision log, and a gap in the accounting stream qualifies
    it.** `port49 devices capabilities` is offline, like `policy replay`. The spool writes an
    `account_gap` record per stage for the records it drops (§5.7), so a reader can tell "the
    device did not ask" from "we did not receive". A reconciliation finding in a window with a gap
    is printed as possible and does not page. "Never seen" is a note and exits 0 (pre-flight
    I13): only a contradiction between what a device declares and what it did pages.
15. **An NX-OS system user is keyed on its task_id, never on `admin` alone**, and only if L25
    reproduces the production record over SSH and finds no `vsh.bin` on an NX-API session as
    `admin` (pre-flight M7). `platform.SystemTasks` pairs the user with `^vsh\.bin\.[0-9]+$`. A
    `based_on:` variant does not get the pair, and reads such a record `unattributed`.
16. **M3 is its own row.** L23 re-measures the inert candidates beside readonly's reply. If one
    moves the session, 1.1.0 lists it under that platform's `privilege_attributes`. Every shipped
    set's privilege attributes are unioned wherever the gate, the ceiling and the placeholder check
    ask (`platform.PrivilegeAttributeNames`), so a 1.0.0 pin is protected too.
17. **One new reason code, and no new metric.** `projection_fail_closed` is added to §5.7 by Task
    1 before Task 10 uses it. The other new vocabulary is one event, `account_gap` (a report), four
    finding kinds (`projection`, `projection_refused`, `projection_overflow`, `unenforced_rules`),
    five adapter keys and one CLI command.
18. **`remote` and every `p49-*` name are reserved usernames** (pre-flight I9). A Junos session
    under a template user's name lands in that template's class whatever the reply says, so a
    subject told less than port49 permits would run the class's bits. Policy load refuses a
    subject that declares one, and the broker refuses to mint for one a directory derives. No
    template user can log in locally: Juniper documents a template user as one with no
    authentication; Task 2 measures that, and Task 14 locks them if it found otherwise.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **After the upgrade, with no edit:** Junos sessions are unchanged, because an unpinned policy
  renders with 1.0.0. `policy test` newly prints `report: unenforced_rules: subject "noc" on
  juniper_junos (supports: session): its roles carry 3 command rules, and juniper_junos neither
  asks port49 about a command nor has them rendered into its session reply, so they decide
  nothing there (spec §9)`. That was true before this plan; now the report says so. A policy test
  that passed with a quarantined device now fails: the quarantine was always there, and CI now
  refuses to ship it.
- **Turning the projection on, in this order.**
  1. Load the reference on every Junos device: `port49 platform export --classes --config
     /etc/port49/port49d.yaml juniper_junos` prints the lines; `load set terminal` takes them,
     and each template class and user is replaced whole.
  2. Check it: `port49 devices check-config --config /etc/port49/port49d.yaml --device srx-fw-04
     srx-fw-04.set` on `show configuration | display set` fails on a missing reference line
     (`TEMPLATE: ...`), on `set system login class p49-remote allow-commands "^configure"`, and
     on a template user's password.
  3. Move the pin: `port49 platform upgrade --to 1.1.0` prints the gated keys and every subject
     the move fails closed, then `--write`, then `policy diff`.

  The order matters. A device without the classes lands every session in its old `remote`
  template. A device without `strict-authorization` treats every port49 denial as advisory (L17).
- **Until L9 measures that a deny reads the expanded command:** no deny narrower than `.*` goes
  out, so under the shipped `local_user_name` a Junos composition with a deny beneath a permit —
  the realistic readonly with its `show configuration` deny included — gets the fail-closed reply:
  `report: projection_refused: subject "noc" on juniper_junos (srx-fw-04, srx-fw-05, srx-fw-22)
  gets the fail-closed reply (refused_shape): on juniper_junos, permit "show **" (role "r") needs
  an allow-commands the device would let beat deny "show configuration **" ...; it is told every
  command denied, and every other subject on those devices keeps its reply`. `policy test` exits
  1. The subject's session opens and every command is refused; everyone else on the device works.
- **An admin with a deny on Junos,** once L9 measures that a deny reads the expanded command and
  under `user_permissions`: `user-permissions=clear network trace view view-configuration` and the
  deny, with `configure` beyond the reply. Before that, or under `local_user_name`: the fail-closed
  reply, reported the same way.
- **The daemon's log at 3am:** `{"event":"authorize_session","verdict":"permit",
  "reason":"projection_fail_closed",...,"reply":{"attributes":["deny-commands=^.*$"]}}` names the
  one subject told less than port49 would permit, and the blob event says why.
- **A subject whose username is `p49-admin`:** `subject "s": username "p49-admin" is reserved:
  remote and every p49-* name are the device's template users ...` at load.
- **`port49 explain` on a Junos command** notes what the device does under the reply, and, for a
  fail-closed composition, `the composition cannot be told to juniper_junos faithfully
  (refused_shape): ...`.
- **`policy diff` after revoking a Junos permit:** a `projection:` line reports the shape or bits
  change; no `RAISES`, since the device can do less. Adding a permit back is a raise until a
  `reply:` test asserts it.
- **At 3am, with a device that has no command authorization configured:** `port49 devices
  capabilities --since 24h /var/log/port49/decisions.jsonl` prints the matrix, then `⚠
  UNAUTHORIZED TIER — leaf-04` with three example commands, and exits 1. A device nobody logged
  into reads `note: never seen` and does not page. If the spool dropped records in the window, the
  block reads `? POSSIBLY AN UNAUTHORIZED TIER`, and the command exits 0.
- **An NX-OS `admin` record with task_id `vsh.bin.28561`** (only if L25 reproduced it) is
  `attribution: system`. The same account logging in from SSH carries `<addr>@pts/<n>` and stays
  `unattributed` or `foreign`.

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
  `d1f1ba3` (plan text aside, the same tree as this plan's commit), in order, and the red step of
  every code task fails as its Step 2 says. A hunk that does not apply means the tree is not where
  this plan expects: stop and say so, and do not edit by hand. A branch of Task 14's Step 4 is the
  one hand edit, and each says exactly what to change.
- **Every commit is preceded by `make test && make vet`**, and by `go vet -tags lab ./tests/lab/...`
  and `make build`. Report their real output.
- **Lab tasks follow "Running the lab" below:** a deadline on every SSH or pty read, where expiry
  is "not observed" and fails the test and is never a pass; the harness's boot budget per image;
  and a stall watchdog run by the controller for the whole run.
- **No new dependencies.** Branch `feature/session-projection`; never commit code to `main`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  ```

## Running the lab (Tasks 2, 3, 4 and 19)

The lab is beehive's containerlab, and it holds one run at a time. The owner has given standing
consent for lab runs. Images on hand: vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15, Nexus 9300v
10.4(2)F and vEOS-lab 4.31.2F. A vJunosEvolved image is on the host but not in the harness, and
this plan does not measure it.

**One platform per `go test` run, one task's tests per run.** The harness seeds 16 token logins per
platform per run (`tokenPoolSize`). Task 2 spends exactly 16, Task 3 spends 9, Task 4 up to 5, and
Task 19 none, since the broker mints each token. The `make lab` loop is not used here. Each run:

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
- 60 s on each L25 prompt, and on the NX-API request;
- 90 s on each login prompt, and the prompt is waited for before any timer starts;
- 4 min on an idle-timeout hold (L24), which fails if the session closes in under 50 s.

An expiry is **not observed**. It fails the test, and its cell says "not observed". It is never a
refusal and never a pass, and a note is not committed from a run that has one: rerun it.

**The controller runs a stall watchdog for the whole run.** The controller is the agent that
started the run, not the test. A stall is a log that has not grown in `STALL` minutes: 25 on the
Junos images and vEOS, which is longer than their slowest silent step (an 8-minute boot, an
8-minute TACACS+ readiness wait and a 180 s commit), and **40 on the N9Kv**, whose deploy, 15-minute
boot and 8-minute TACACS+ wait log nothing in between (pre-flight M5). On a stall, stop the run
and clean up, and report it with the log's last 40 lines. A stalled run is never read as a result.
**A `go test -timeout` panic skips the harness's deferred teardown**, and can leave
`strict-authorization` and the reference classes on a device and `port49d` bound, so the watchdog
cleans up after one too. With the Monitor tool, or in a shell:

```bash
LOG=tests/lab/logs/l12-wire-vjunos.log; PID=$(cat tests/lab/logs/l12-wire-vjunos.pid)
TOPO=tests/lab/topologies/vjunos.clab.yml; STALL=25       # 40 for nxos
cleanup() {
  sudo containerlab destroy -t "$TOPO" --cleanup
  pkill -f 'bin/port49d' || true
  sudo pkill -f 'tcpdump.*tests/lab/captures' || true
}
last=-1; still=0
while kill -0 "$PID" 2>/dev/null; do
  size=$(stat -c %s "$LOG")
  if [ "$size" = "$last" ]; then still=$((still + 1)); else still=0; last=$size; fi
  if [ "$still" -ge "$STALL" ]; then
    echo "STALL: $LOG has not grown in $STALL minutes"; tail -40 "$LOG"
    kill -INT "$PID"; sleep 180                      # the harness's handler tears the lab down
    kill -KILL "$PID" 2>/dev/null
    cleanup; exit 1
  fi
  sleep 60
done
if grep -q 'panic: test timed out' "$LOG"; then
  echo "TIMEOUT: go test's -timeout expired, and the deferred teardown did not run"; tail -40 "$LOG"
  cleanup; exit 1
fi
```

Topologies: `vjunos` → `tests/lab/topologies/vjunos.clab.yml`, `vsrx` → `vsrx.clab.yml`, `nxos` →
`nxos.clab.yml`, `eos` → `eos.clab.yml`. Destroying the topology discards each device's
configuration, the reference classes included.

**Evidence.** Run `make evidence` after the run. It writes the redacted captures the notes cite
into `tests/lab/evidence/`; commit those, and never `tests/lab/captures/`. If the run happened in a
worktree, copy its raw captures into the main checkout's `tests/lab/captures/` before removing the
worktree, or the labpcap audit fails. After every run, confirm that no `port49d` still holds
`172.100.100.1:49` and that the topology is destroyed.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md  MOD  §2, §5.6, §5.7, §6, §8, §9, §12, §13 d21/d22/d26, §15 (Task 1); §5.8 (Task 15); closed rows (Task 20)
tests/lab/junos_wire_test.go                  NEW  L9 and L12 wire facts, template logins; shared Junos helpers (Task 2)
tests/lab/junos_bits_test.go                  NEW  each bit's reach, the baseline and the carve-out (L12); class idle-timeout (L24) (Task 3)
tests/lab/l23_test.go                         NEW  inert candidates beside readonly (L23), NX-OS vsh.bin over SSH and NX-API (L25) (Task 4)
internal/engine/contain.go                    NEW  Contains, MayMeet, AlwaysDominates (Task 5)
internal/platform/dialect.go                  MOD  CommandProjection, Bits, CarveOuts, BitDelivery, LocalUserNames, CeilingBits; BaselineBit,
                                                   RemoteClass; Projected, ProjectionOwns, LevelBits, ExpandBits (Task 6); generics["1.1.0"] (Task 14)
internal/platform/adapter.go                  MOD  Spec keys, Over, SpecOf, validateProjection, MonotoneBits (Task 6)
internal/policy/load.go                       MOD  keepsProjection, checkBlockOrder (Task 6); checkProjected, reserved usernames, the projection cache (Task 9)
internal/projection/ere.go                    NEW  Facts, ruleERE with the deny's pipe tail, patternERE, bracket (Task 7)
internal/projection/project.go                NEW  Input, Result, Refusal, Project, the fail-closed reply, JunosFacts, FactsFor (Task 8)
internal/projection/model.go                  NEW  the union device model, the witness, Device, Narrower (Task 8); Widens (Task 12)
internal/policy/resolve.go                    MOD  Resolution.Projection, compile → project (cached), layerAttributes, exceeds (Task 9)
internal/engine/blob.go                       MOD  Blob.FailClosed (Task 9); Blob.SessionReason (Task 10)
internal/token/minter.go                      MOD  ReservedUsername, ErrUsernameReserved (Task 9)
internal/decision/reasons.go                  MOD  projection_fail_closed (Task 10); EventAccountGap (Task 16)
internal/daemon/author/engine.go, replay      MOD  the session's reason from the blob (Task 10)
internal/policy/tests.go, explain.go          MOD  Caveats on a projected platform, ProjectionCaveats (Task 11)
internal/policy/lint.go                       MOD  projection, projection_refused, projection_overflow (Task 11); unenforced_rules (Task 18)
cmd/port49/policy.go                          MOD  policy test fails on a quarantine or a refusal (Task 11); the diff's projection lines (Task 12)
internal/policy/diff.go                       MOD  Diff.Projections, ProjectionRefusals, the projected reply gate (Task 12)
internal/platform/classes.go                  NEW  ReferenceClasses as a replace, TemplateDrift (Task 13)
internal/config/config.go                     MOD  DefaultMaxSessionAge, MaxSessionAge (Task 13)
cmd/port49/platform.go, devices.go, main.go   MOD  export --classes, check-config --config (Task 13); upgrade preview (Task 14); capabilities (Task 18)
platforms/1.1.0/*.yaml                        NEW  the set: 1.0.0's three per-command files, juniper_junos projected (Task 14)
internal/platform/set.go                      MOD  DefaultSet 1.1.0 (Task 14)
internal/platform/platform.go                 MOD  SystemTask, SystemTasks (Task 15, if L25 measures it)
internal/daemon/acct/acct.go, cmd/port49d     MOD  WithSystemTasks, isSystemUser on task_id (Task 15)
internal/decision/log.go                      MOD  Gap (Task 16)
internal/daemon/acct/spool.go                 MOD  drop, flushGaps (Task 16)
internal/capability/capability.go             NEW  Device, Options, Row, Report, Infer (Task 17)
cmd/port49/capabilities.go                    NEW  devicesCapabilities, readLogs (Task 18)
tests/lab/projection_test.go                  NEW  the differential test (Task 19)
tests/lab/results/L9-*, L12-*, L23-*, L24-*, L25-*, L12-bits-*, L12-projection-*   NEW  written by the lab runs
docs/superpowers/plans/README.md              MOD  plan 5b as built (Task 20)
```

Twenty tasks:
- **Task 1** is docs.
- **Tasks 2, 3 and 4** are lab measurements, run early because the set's values come from them.
- **Tasks 5–18** are code. Every one leaves `make test` green.
- **Task 19** is the differential lab test.
- **Task 20** is lab closure and docs.

Task 15 runs only if Task 4's L25 note measured the record and found none on NX-API. Tasks 5–13
depend on no lab result, and may proceed while the lab tasks run: the lab holds one run at a time,
and the code does not need it. Task 14 reads all three lab notes.

---

### Task 1: The spec says what plan 5b builds, decision 26 included, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§2, §5.6, §5.7, §6, §8, §9, §12, §13
  decisions 21 and 22 and the new 26, §15 L9, L12 and new rows L23, L24, L25)

**Interfaces:** none. Every later task cites a paragraph this one writes, and Task 10 uses the
reason code it adds.

What changes, so a reviewer can check each against a task:

- §2: `remote` and every `p49-*` name are reserved usernames (Task 9).
- §5.6: decision 21's lever is `platform export --classes` rendering `idle-timeout`, measured by
  L24 (Task 13).
- §5.7: `account_gap`, the ninth event, a report, with when each stage's record is written (Task
  16; pre-flight M6). The reason table gains `projection_fail_closed` (Task 10). CLAUDE.md: a
  reason code is added to the spec table first.
- §6: a projected platform maps each level to ceiling bits and, under `local_user_name`, a
  template (Tasks 6, 9).
- §8, the Fields table: `command_projection`, `bits` with the union and `baseline`, the new
  `carve_outs`, `bit_delivery` and `local_user_names` (Task 6). The `bit_delivery` paragraph says
  why 1.1.0 ships `local_user_name` (L18; Task 14). The refused shape: CI refuses it, and a daemon
  answers it fail-closed. "As built (plan 5b)" gives the union device model, the proof
  obligations, the pipe tail, the ERE subset, the reports and the measured load bound (Tasks
  7–12). Generator constraint 6 is new, and the paragraph after the constraints is decision 26's
  fail-closed reply with its operator note. So is "The reference classes are exported", as a
  replace (Task 13), and the blast radius.
- §9, "As built": `devices capabilities`, "never seen" as a note, its heuristics, the join,
  `account_gap` qualification and `unenforced_rules` (Tasks 16–18).
- §12: check-config's template check (Task 13); the diff and `policy test` fail on a fail-closed
  composition and on any quarantine (Tasks 11, 12); a projected reply is judged by what the device
  can do (Task 12); `carve_outs` and `local_user_names` join the gated rendering keys.
- §13: decision 21 names `export --classes`, decision 22 records what was built, and **decision 26
  is the owner's ruling of 2026-09-25**: a composition the projection cannot carry fails closed for
  that subject alone.
- §15: L9 and L12 gain the clauses Task 2 measures (the pipe tail, the malformed deny, template
  logins, the baseline under `.*`), L25 names NX-API, and L23, L24 and L25 are new and open. Task
  20 closes them.

The lab has not yet measured anything this task writes as fact. Each sentence here either cites a
closed note (L11, L17, L18, L21, L22) or says the value is read in the direction that fails
closed until its row closes.

- [ ] **Step 1: Apply the spec edits**

<!-- patch: docs/design/2026-08-23-policy-engine-spec.md -->
````diff
diff --git a/docs/design/2026-08-23-policy-engine-spec.md b/docs/design/2026-08-23-policy-engine-spec.md
index ebfde3c..b63fcfe 100644
--- a/docs/design/2026-08-23-policy-engine-spec.md
+++ b/docs/design/2026-08-23-policy-engine-spec.md
@@ -150,6 +150,12 @@ the `(nas, username)` store key and make the audit trail ambiguous; this is a po
 error. Collision with a device-local account name is the same hazard described in §5.6 and
 SHOULD be reported where port49 can observe it.
 
+**`remote` and every `p49-*` name are reserved.** They are a Junos device's template users: a
+session under one lands in that template's class whatever the reply says, so a subject the
+projection told less than port49 permits (§13, decision 26) would run what the template's
+class runs. A subject declaring one is a policy load error, and the broker refuses to mint for
+one a directory derives (plan 5b pre-flight I9).
+
 **The username is canonicalized before it is used as a key, not merely compared.** The
 device sends whatever the operator typed — `alice`, `DOMAIN\alice`, or
 `alice@corp.example.com`. The broker writes the token under the canonical form — lower-cased,
@@ -1442,7 +1448,10 @@ Post-login control there is bounded by the device's own session, and port49 can
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
 
@@ -1674,6 +1683,16 @@ events (`account`, `blob`) that share the envelope and carry no verdict:
 
 Device accounting shares this envelope as the eighth event, `account`, and is specified in
 §5.8. It is not a decision — it is a report — so it carries no `policy` block and no verdict.
+A ninth, `account_gap`, is a report too: accounting records port49 received and did not write,
+`{"gap": {"stage": ..., "records": N, "since": ...}}`, one record per spool drop stage —
+`offer_refused` (answered `ERROR`; the device may send the record again), `drain_unparseable`
+and `drain_set_aside` (answered `SUCCESS`, and not in the log). An `offer_refused` drop is written
+before the next drain pass's records; a drop during a pass is written when that pass ends,
+after the records it sat among, its `since` saying when it began. It is what lets a reader of
+the log know the accounting stream has a hole, which reconciliation must know before it says a
+device did not ask (§9). The count is
+held in memory, so a restart loses what was not yet written; `port49_accounting_spool_drops_total{stage}`
+is the alarm, and this record is the log's own witness.
 
 `escalate` exists as its own event because the device-facing username on those platforms is
 `$enab{level}$`, not a person. The record carries the principal resolved from login context,
@@ -1751,6 +1770,7 @@ not an unvalidated body. A connection with no verified chain names no one.
 | `blob_unavailable` | the referenced blob could not be resolved from the store or any cache — a store fault, alarmed (§5.1.1) — or the context no longer fits the blob: a session attribute filled from it exceeds 255 bytes, or a filled-in value carries a separator (`=`, `*`) or a control character, either of which the broker refused at mint (§6), or the reply would send a `priv-lvl` above the context's `max_privilege`, a `priv-lvl` that is not a level 0 to 15, or an attribute the blob's `accepted_attributes` does not take — compositions the load quarantines (§6, §7). On `refresh`: the policy in force could not be resolved or compiled for this context — an unexpected broker fault, since the reload's load (§5.1.3 step 1) compiled every subject on every device, and what failed quarantined its device or refused the policy under the joint check (§10) — so the context is revoked, failing closed; the process log names the `ctx_id` and the fault, and it is counted `failed`. Also on `refresh`: the context could not be opened — sealed under a key that has left the two-key window, or failing authentication — so it is revoked through the monotonic revocation mark, the record names the device and the username its key holds and no principal (the owner and `ctx_id` are sealed, and the index entry that led to it may be stale), and it is counted `failed` |
 | `blob_platform_mismatch` | the context's blob was compiled for a platform other than the one inventory gives the device — inventory changed since the mint, or the broker and the daemon read different inventories. Its dialect and attributes are another platform's, so it is never answered from; operational, alertable beside `blob_unavailable` |
 | `device_quarantined` | the device is in inventory but failed joint validation against policy (§10); the connection is closed without a reply, as for `device_unknown`, until fixed. On `refresh`, a deny recorded once per context per policy version (bundle): the live context is left as it was until the quarantine lifts |
+| `projection_fail_closed` | `authorize_session`, a permit: the session on a projected platform (§8) was answered with its composition's fail-closed reply — every command denied but what the projection proved — because the projection cannot tell the device that composition faithfully (§13, decision 26). The blob carries why (`fail_closed`: `refused_shape`, `configuration_mode`, `overflow`, `unwritable`, `secret_rule` or `unsound`). Every other subject on the device is answered as before; `policy test` and `policy diff` fail on the composition |
 
 Every event has a success reason and at least one failure reason in this table, so
 "decisions by event, verdict, and reason" (design document §15) is a complete metric. A
@@ -2653,7 +2673,10 @@ gets readonly's role: `priv-lvl=15`, `roles=network-operator` on EOS and
 
 **Platforms that are not `priv-lvl`-native** (Junos maps to `local-user-name`) MUST declare
 a mapping for every level. A missing mapping is a **policy load error in CI**, not a broken
-login at 3am.
+login at 3am. On a projected platform (§8) the mapping is the level's ceiling in permission
+bits, and under `bit_delivery: local_user_name` a template user per level; a level with no
+bits on its parent chain is a load error on the device it lands on, as any level with no
+mapping is.
 
 **Exact attribute spellings are lab-verified, not asserted.** The shipped adapters use bare
 `priv-lvl` for the TACACS+ shell-service reply, the bare `roles=` for EOS roles and
@@ -2900,8 +2923,10 @@ attribute is complete in four lines:
 | `expands_abbreviations` | whether the device sends resolved command words | if `commands` |
 | `splits_interface_names` | whether the device sends an interface name and its index as two arguments (§3 rule 5); `true` on `cisco_iosxe` only (L21) | optional |
 | `pipe_token` / `pipe_authorized` | modifier separator; whether it reaches us | if `commands` |
-| `command_projection` | how rules render for session-only platforms (below) | if `session`-only |
-| `bits` / `bit_delivery` | each permission bit's reach in rule form, and whether bits travel as `user-permissions` or a `local-user-name` template (below) | if `session`-only |
+| `command_projection` | how rules render for session-only platforms (below): `junos_regex`, the one this build renders. Where it is set, `privilege` is each level's ceiling in permission bits, never attributes, and `supports` is `[session]` | if `session`-only |
+| `bits` / `bit_delivery` | each permission bit's reach in rule form, an upper bound measured in the lab (L12), and whether bits travel as `user-permissions` or a `local-user-name` template (below). A session runs the union of its bits' reach. The bit `baseline` is what a class with no bits runs, held by every session and never sent or named in `privilege`. A block may add to a bit's reach, an edit the diff gates as widening (§12), and never take from it, and may not declare a bit the set does not | if `session`-only |
+| `carve_outs` | the commands a bit alone makes available, whatever other bit reaches them: each rule held by that bit's own reach, measured in the lab (L12). The only subtraction from the union: a bit not held removes no command another bit reaches except these. A block may drop one and never add one | optional, with `bits` |
+| `local_user_names` | under `bit_delivery: local_user_name`, each level's template user on the device, whose class `port49 platform export --classes` renders with the level's bits | with `local_user_name` |
 | `redact` | patterns whose argument values are removed before an accounting or authorization record is written (§5.7, §5.8); a block **adds** to the built-in patterns in `platforms/redact.yaml` and never removes one, and an edit to it is gated (§12) | if the platform sends command accounting — session-only platforms included |
 | `session_services` | the authorization `service` values this platform's sessions arrive with; a **list**, because the name is device-configurable on Junos | defaults per platform |
 | `session_discriminator` | the accounting AV pair whose value separates two sessions of one user on one device (§5.8) | defaults per platform |
@@ -3055,9 +3080,15 @@ Bits reach the device one of two ways, both in use in real fleets and selected p
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
 
@@ -3090,8 +3121,9 @@ cannot carry a deny beneath a permit.
 **Refused shape.** Permits narrower than the covering bits *and* a deny beneath one of them —
 `permit: [show interfaces **], deny: [show interfaces terse]` — fits neither. Junos regex
 has no lookahead, so "everything under X except Y" cannot be written as one allow. CI MUST
-refuse the policy at load, naming the grant, the two rules, and the platform, rather than
-rendering the nearest shape. Junos documents a second attribute family,
+refuse the policy, naming the grant, the two rules, and the platform, rather than rendering
+the nearest shape; a daemon that loads it anyway answers that subject with the fail-closed
+reply, never the nearest shape (decision 26). Junos documents a second attribute family,
 `allow-commands-regexps` / `deny-commands-regexps`, in which **deny takes precedence by
 default** and which is mutually exclusive with the plain family on the wire. If that
 precedence holds over TACACS+ (L12), the refused shape becomes expressible in that family
@@ -3134,6 +3166,72 @@ but has no capture, and neither has the reach of each bit, the `.*` baseline on
 the `-regexps` family's precedence. The plan's containerlab step closes L12 before the
 generator is final.
 
+**As built (plan 5b).** The projection ships in platform set **1.1.0**; a policy that pins
+none renders with 1.0.0 and Junos gets nothing, as before, so turning it on is a pin move
+`port49 policy diff` gates like any adapter edit. `internal/projection` renders each
+composition, and proves the reply before it is sent: every command the device would run under
+it is one port49 permits. It reads the device as the lab measured it (L11): a command runs
+where a matching allow beats every deny, or where the bits reach it and no deny matches. The
+bits are a **union**: a command runs where any held bit's reach holds it, `baseline` always
+held, unless a measured `carve_outs` entry of a bit not held takes it out —
+`view-configuration`'s `show configuration **` out of `view`'s `show **`. Nothing else
+subtracts: a bit not held never removes a command another bit reaches (plan 5b pre-flight C1).
+The bits' reach and carve-outs are applied by the device's command parser, which reads a
+command whatever its spacing, case or abbreviation, so both are matched as port49 matches a
+deny, the widest reading. The proof's obligations, each checked from the rules' terms
+(`engine.Contains`, `MayMeet`, `AlwaysDominates`), with a probe of every way the rules can be
+told apart as its witness:
+
+- **A bit is sent only where every command it reaches is decided by one rule of the grant**:
+  held by a permit, or by a deny, which is then sent. Under `local_user_name` the template's
+  class carries every bit of the level, so each must be; otherwise the grant goes narrow.
+  Every baseline command no permit holds is denied on the wire.
+- **A permit goes out as an allow only where it dominates every deny it meets**, since on the
+  device the allow beats them all; one that does not is the refused shape, named with both
+  rules. And only within the level's ceiling bits, a carve-out counted: a permit beyond them is
+  not sent, so the device refuses what port49 would permit there — narrower, which fails
+  closed, and reported.
+- **A deny is left off the wire only where a measured carve-out of a bit not sent holds every
+  command it matches**, and no allow meets it. No other bit boundary licenses it.
+- **Bits that enter configuration mode** (a reach holding `configure`: `configure`, `all`)
+  **are sent, and an allow meeting `configure` is sent, only for a grant of every command with
+  no deny.** A statement typed there is governed by the class's configuration permissions,
+  which no command regex reaches, so port49 could deny what the device runs. Under
+  `user_permissions` such a composition is rendered again without those bits, and sent that way
+  where the rest proves sound (decision 26, decided item 6); otherwise it gets the fail-closed
+  reply.
+- **The narrow shape's bits are the smallest set that reaches its allows**, preferring bits
+  that do not enter configuration mode, so a narrow admin grant is not refused for `all`.
+- **A rule whose text carries a value redaction hides is never projected**: the reply is written
+  whole to the `authorize_session` record and the blob event (§5.7, §5.8).
+
+What the regexes rest on is the device's regex dialect, measured by L9 and read into
+`JunosFacts` in the direction that fails closed until measured: explicit `^` and `$` anchors
+on every regex; a deny's letters written in both cases (`[sS][hH][oO][wW]`) while the device
+is case-sensitive; and no deny but `.*` while a deny may be walked past by abbreviating it — a
+capability shape needing one goes narrow, and a narrow one that cannot carry the grant gets the
+fail-closed reply. Every deny ends in a pipe tail, `( *\|.*)?`, since the engine strips a
+pipeline before matching and a deny anchored at its rule's last word would miss `clear bgp all
+| no-more`; it only makes a deny match more, so it stays whatever L9 measures. A deny is as
+wide as its rule — a run of spaces between words, an argument that may hold a space — and an
+allow as narrow. A word is ASCII, carries no `{`, `}`, `"` or `\`, and escapes ERE's
+operators; a regex or class pattern is carried only in the subset of RE2 that reads the same in
+POSIX ERE (literals, bracket expressions, `.`, grouping, alternation, `*`, `+`, `?`, a repeat
+of at most 8 written out, anchors at its ends), never as an empty group or alternative, and
+anything else is refused. Every attribute is sent mandatory, once, and within RFC 8907's 255
+bytes including its name; past that the subject gets the fail-closed reply, and for
+`deny-commands` `policy test` prints the class line that would carry the denies on the device
+instead, binding every subject at that template (`projection_overflow`). An allow is never
+moved into a class: a class `allow-commands` runs for every subject at that template, past
+their own denies (L11). A role or grant may not set an attribute the projection renders, in any
+case or numbered variant the device reads (`allow-commands2`, `User-Permissions`), on a
+projected platform or under `all` where one is. Each composition's shape, bits, what each regex
+carries, what the bits refuse and what is beyond them is reported (`projection`), a
+composition that gets the fail-closed reply is reported by subject, device and reason
+(`projection_refused`), and `policy diff` reports a composition whose shape or bits moved
+(§12). A composition is projected once per policy however many devices it lands on: 1,000
+SRXs and 20 subjects load in about 0.2 s (`TestProjectionLoadTime`, bound 2 s).
+
 #### Generator constraints
 
 None of these are caught by the device. All MUST be enforced at policy load:
@@ -3147,10 +3245,33 @@ None of these are caught by the device. All MUST be enforced at policy load:
    voids the entire deny baseline beneath it.
 5. **Reject invalid or over-budget policy loudly at load time**, never silently at session
    time. A server that skips an attribute at session time produces a fail-open shape.
-
-**Blast radius.** An invalid projection locks out every user authenticating against that
-device simultaneously. Lockout is fail-closed, but deployments MUST have a break-glass path
-independent of TACACS attributes — a local account or console access (design document §4).
+6. **Never emit an attribute a role or grant also sets.** The projection renders the template,
+   the bits and the regexes; a hand-written one beside it is a second instance (1), and over it
+   a regex nothing proved (4). Refused at load (plan 5b).
+
+A composition the projection cannot tell the device faithfully — the refused shape, bits that
+enter configuration mode where they cannot be dropped, an attribute past the budget, a rule it
+cannot write, a rule redaction hides, or a reply its witness finds unsound — is not a joint
+check (§13, decision 26). That subject alone gets the **fail-closed reply**: `deny-commands`
+`^.*$`, an allow for each permit that is within the level's ceiling bits that do not enter
+configuration mode, dominates every deny it meets, does not meet `configure` and can be
+written, and no other bit or template — under `user_permissions` the smallest of those bits
+that reach the allows, under `local_user_name` no `local-user-name`, so the session lands in
+the bitless `p49-remote`. Where the allows cannot go out whole none does. The reply is proven
+as any other. The session is recorded `projection_fail_closed` (§5.7), and `policy test` and
+`policy diff` exit non-zero on it, naming the subject, the device and why (§8, "CI MUST refuse
+the policy"). **Operator note:** until L9 measures that a deny reads the command as the CLI
+expands it, no deny narrower than `.*` goes out, so under the shipped `local_user_name` a
+composition with any deny beneath a permit — the realistic readonly with its
+`show configuration` deny included — gets the fail-closed reply on Junos; everyone else on the
+device keeps working, and CI names each such subject before it ships.
+
+**Blast radius.** A projection port49 cannot carry fails closed for the one subject it
+belongs to (decision 26). A device whose template classes drift from the reference, or that
+lacks them, can still lock out every user authenticating against it at once: a missing
+template lands every session in `remote`. Lockout is fail-closed, but deployments MUST have a
+break-glass path independent of TACACS attributes — a local account or console access (design
+document §4).
 
 #### Verification
 
@@ -3179,6 +3300,21 @@ instrument for the differential test, not a runtime one.
 `start.*` as unanchored would also match `request start …`, diverging from our semantics.
 That belongs in the adapter and is asserted in the lab, never assumed.
 
+**The reference classes are exported.** `port49 platform export --classes --config
+port49d.yaml PLATFORM` prints, as `set` lines, the configuration a projected platform's
+replies rest on: the adapter's `device_config` (on Junos `tacplus-options
+strict-authorization`), the `remote` template user in the bitless class `p49-remote`, and under
+`local_user_name` each level's template user and class with the level's bits, one per line as
+`show configuration | display set` prints them. Each template class and user is written as a
+replace — a `delete` before its `set` lines — so loading it leaves nothing a device carried
+under one: a class `allow-commands`, or a template user's local password. No template user is
+one that can log in locally: Juniper documents a template user as one with no authentication,
+and L12 measures that it refuses a local login; the reference adds a locked
+`authentication encrypted-password "*"` only if that measurement found otherwise. Every class
+carries `idle-timeout` from `session.max_session_age_default`, in whole minutes rounded down
+(decision 21); the file is read for that key alone, so no key or secret is needed to run it.
+`port49 devices check-config --config port49d.yaml` holds a device to it (§12).
+
 **Importing existing configuration.** Simple alternations of prefix patterns convert to
 token rules mechanically; arbitrary regex does not. A migration tool MUST convert what it can
 and **flag the remainder for human review rather than approximating**, because a
@@ -3459,6 +3595,35 @@ health over the same window: spool drops, `ERROR` replies, and unattributed-reco
 will eventually accuse a correctly configured device, and once that happens nobody reads the
 report again.
 
+**As built (plan 5b).** `port49 devices capabilities --policy FILE --inventory FILE [--since
+DURATION] LOGFILE...` reads the decision log a daemon wrote (`-` for stdin) and prints, per
+inventory device, its admission, what its adapter declares under `supports`, and what the log
+shows it asked: `session` for an `authorize_session` record, `commands` for an
+`authorize_command`, `config_commands` for an authorization request that followed a permitted
+configuration entry (`configure …`) in the same context. `--since` bounds the window by the
+newest record's time, never the wall clock. An admitted device with no record in the window
+is noted **never seen** and exits 0: in a day's window every device nobody logged into is one,
+and a job that pages on them is one nobody reads. It warns — and exits 1, for a job to page on
+— on a contradiction between what a device declares and what it did:
+
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
@@ -4229,7 +4394,12 @@ line the adapter's `config_checks` name: a command method list falling back to `
 `authentication-order` with `password` in it (L4) — or on a `device_config` line the
 configuration does not carry as a top-level line of its own, the absence no `config_checks`
 entry can see: IOS-XE's level-7 command method list, without which a level-7 command is never
-asked about (§6). A `platforms:` block adds to the set's `device_config`, `local_accounts` and
+asked about (§6). On a projected platform it also reads the configuration, as `show
+configuration | display set` prints it, against the reference `platform export --classes`
+writes, and `--config port49d.yaml`, the classes' idle-timeout, is required: a reference line
+the device lacks, and any line under a template class or template user the reference does not
+write — a class `allow-commands`, a permission, a template password — fails it, the uid Junos
+assigns aside (§8). A `platforms:` block adds to the set's `device_config`, `local_accounts` and
 `config_checks` and never takes one away, `replace: true` and `based_on:` included: a block
 that rewrites the set's line ending in `local` to end in `none` still has the set's line
 required and its own reported by the set's check. A device configuration is full of secrets,
@@ -4267,9 +4437,13 @@ rules distinguish — each word, `*`, `**`, and each deny word's abbreviations 
 command whose decision changed, each level or ceiling that changed (a privilege change, §6),
 and each device the new policy quarantines. It exits non-zero on a command a deny refused that
 the new policy permits, unless a policy test in the new policy exercises that permit over that
-deny, on a newly quarantined device, and on a subject whose mint the new policy's broker
-refuses (`attribute_too_long`, `attribute_unsafe`), since the diff, `policy test` and `explain`
-run the broker's mint checks and answer as it does.
+deny, on a newly quarantined device, on a subject whose mint the new policy's broker refuses
+(`attribute_too_long`, `attribute_unsafe`), since the diff, `policy test` and `explain` run the
+broker's mint checks and answer as it does, and on every composition the new policy gives a
+projection's fail-closed reply, new or not (§13, decision 26). `port49 policy test` exits
+non-zero on a device quarantined now or at a later expiry and on every fail-closed
+composition too: the daemon still serves the rest (decision 20), and CI ships neither (plan 5b
+pre-flight I10); `port49 platform upgrade` previews both.
 
 **A privilege raise fails the gate too** (owner's rulings 2026-09-24). The gate compares what
 the device gets and what port49 enforces, not level names, for each subject on each device at
@@ -4294,7 +4468,13 @@ each instant. Any of these is a raise:
   fence, so removing one widens access too: without `deny-commands` a Junos session loses its
   only refusal, and without `local-user-name` it falls back to the device's template user (owner's
   ruling 2026-09-24, review C4). The gate cannot read the direction of such a change, so it fails
-  closed.
+  closed. **On a projected platform the projection's own attributes are judged by what the
+  device can do under them** (plan 5b pre-flight I14): a reply under which the device holds a
+  bit it did not, or runs a command it did not, among one command per way either reply's rules
+  can be told apart, is a raise; one that only narrows — a revoked permit, an added deny — is
+  not, whatever its regexes say, and needs no `reply:` test. The proof that the device runs
+  nothing port49 denies (§8) is what makes the direction readable. A projection that went away
+  is a raise.
 
 One change's direction the gate can read: a level's own rendering moving down `role_order`
 (§8). Where an attribute is the old level's rendering in the old reply and the new level's in
@@ -4407,7 +4587,7 @@ to that list. The gated keys therefore include:
 - The normalization keys, which change the vector rules match against: `expands_abbreviations`,
   `splits_interface_names`, `strip_cr`, `pipe_token` and `pipe_authorized`.
 - The rendering keys of session-only platforms, which decide what the device enforces:
-  `command_projection`, `bits` and `bit_delivery`.
+  `command_projection`, `bits`, `bit_delivery`, `carve_outs` and `local_user_names`.
 - The keys the gate reads: `privilege_attributes`, `inert_attributes` and
   `accepted_attributes`.
 - `enable_username`, `shows_server_msg`, and `redact`, which changes what the audit keeps.
@@ -4791,7 +4971,8 @@ ceiling, revocation, username binding, and the in-session warning all act at the
 authorization request, and Junos never makes one. Rather than claim reach that does not exist,
 `explain` states the limit, the adapter renders class `idle-timeout` from `max_session_age` as
 the enforced approximation, and revocation records name the contexts they could not reach.
-(§5.6)
+(§5.6) *Plan 5b:* `port49 platform export --classes` renders the idle-timeout (§8), measured by
+L24; revocation records naming contexts are plan 7's.
 
 **22. Session-only projection is bits first, regexes second, chosen per grant, with one
 shape refused.** *Provisional on L12.* The generator picks the smallest permission-bit set
@@ -4802,7 +4983,13 @@ as `deny .*` plus one allow alternation, since emitting nothing widens it to the
 travel as `user-permissions` per session by default, or as a `local-user-name` template
 where a deployment provisions classes. A permit narrower than the bits with a deny beneath
 it is refused at load; the `-regexps` family's documented deny-precedence may lift that once
-measured. The choice is made from the composed grant, never per role. (§8, §15)
+measured. The choice is made from the composed grant, never per role. (§8, §15) *As built in
+plan 5b* (§8, "As built"): a reply is proven before it is sent, against a device model in which
+the bits are a union and only measured carve-outs subtract; bits that enter configuration mode
+are sent only for a grant of everything; the built-in adapter delivers bits by template until
+L12 measures `user-permissions`; the projection ships in set 1.1.0. "Refused at load" is
+amended by decision 26: the refused shape gets that subject the fail-closed reply, and CI
+refuses the policy.
 
 **23. Where the device cannot draw the operator line, `operator` renders as `admin`'s level.**
 *Owner's ruling 2026-09-24.* On `arista_eos` and `cisco_nxos`, with command authorization
@@ -4844,6 +5031,21 @@ role is what fenced operator. On IOS-XE admin's control was refused too — ever
 and at 15, since a token user has no local account (`L22-carried-cisco_iosxe.md`) — so there
 it shows that a token session gets nothing from local, not that local fences level 7. (§6, §8)
 
+**26. A composition the projection cannot carry fails closed for that subject alone.**
+*Owner's ruling 2026-09-25*, replacing decision 20's quarantine for projection refusals. Where
+the projection cannot safely tell a Junos device one subject's composition, only that subject
+gets a fail-closed reply: no template bits beyond what is proven, `deny-commands=^.*$`, and only
+the allows the generator can prove. Everyone else on the device keeps working. Decision 20's
+quarantine (§10) stays for inventory drift and the other joint checks; it no longer applies to
+projection refusals. `policy test` and `policy diff` exit non-zero on any such composition and
+name the subject, the device and the reason, so CI refuses it before it ships (§8, "CI MUST
+refuse the policy"). For decided item 6, an admin composition with a deny, the reply drops only
+the bits that enter configuration mode where the rest is provably sound, which it can be under
+`user_permissions`; otherwise it is the fail-closed reply. Every such session is recorded
+`projection_fail_closed` (§5.7). The pre-flight review of plan 5b measured the alternative: spec
+§11's own policy quarantined all three SRXs for every user, and `policy test` passed it. (§8,
+§10)
+
 ### Deferred, with reasons
 
 Neither of these is an open question about the design. Both are closed for v1 on the
@@ -5295,10 +5497,10 @@ implemented against a guess. This section is the one place the distinction is ke
 | **L6** | How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next. | The `task_id` binding tolerance (§5.8); what reconciliation may conclude from silence (§9); `ERROR` semantics | all | open — arrival and latency measured on EOS and Junos; retry unmeasured; see below |
 | **L7** | Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests. | Reusable tokens (§13, decision 15); capability inference (§9) | EOS, NX-OS | closed — measured 2026-09-24; `tests/lab/results/L7-arista_eos.md`, `L7-login-arista_eos.md`, `L7-cisco_nxos.md`, `L7-nxapi-cookie-cisco_nxos.md`. eAPI and NX-API both measured 2026-09-20: one authentication per HTTP request on both, with per-command authorization and per-command accounting. Both cookies measured: eAPI `/login` 2026-09-23 and NX-API `nxapi_auth` 2026-09-24 — a request carrying the cookie runs no authentication and no session authorization, only its command authorizations (NX-API: the command plus `end`; `configure terminal` too for `cli_conf`). The `nxapi_auth` cookie expires after 10 minutes idle (`NXAPI timeout 10`), ends on `POST /logout`, and wins over a wrong Basic password sent beside it; NAPALM `nxos` never uses it (21 authentications for a six-call job) while Ansible `httpapi` does (one); see below |
 | **L8** | The maximum password length each platform accepts at an interactive prompt. (PAP was split out to L19 on 2026-09-23.) | The 30-character handle (design document §8) | all | closed — measured 2026-09-23; `tests/lab/results/L8-cisco_nxos.md`, `L8-cisco_iosxe.md`; and 2026-09-20, `L8-arista_eos.md`, `L8-juniper_vjunos-router.md`, `L8-juniper_vsrx.md`. The 30-character handle logs in on all five images. Longest intact: **127 on the N9Kv**, which refuses 128 and above locally and never asks port49; at least 1024 on IOS-XE; at least 138 on vEOS and both Junos images, where nothing longer was tried; see below |
-| **L9** | Whether Junos anchors `allow-commands` / `deny-commands` regexes, and which RE2 constructs its regex dialect rejects. | Projection generator constraints (§8) | Junos | open |
+| **L9** | Whether Junos anchors `allow-commands` / `deny-commands` regexes, and which RE2 constructs its regex dialect rejects. Whether explicit `^` and `$` are taken, with the pipe tail `( *\|.*)?` refusing `show version | no-more`; whether a deny regex reads a command in the case and the abbreviation typed (`SHOW VERSION`, `sh ver`) or as the CLI expands it; whether a value with spaces is taken raw; whether a malformed wire regex (`^(show$`) is ignored, which fails open, or refuses the session. | Projection generator constraints (§8); `JunosFacts` in `internal/projection`, each fact read in the direction that fails closed until measured | Junos | open |
 | **L10** | Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter. | Adapter `VERIFIED` status (§8) | all shipped adapters | open — `shell` on EOS, `junos-exec` on Junos. **Reading 3's conclusion is corrected by L17 (2026-09-21):** a denied Junos session authorization is advisory under the configuration this lab deploys, not on this vendor — `tacplus-options strict-authorization` makes the same denial refuse the login; see below. The three per-command adapters' spellings are measured by plan 5a (tests/lab/results/L22-*.md); Junos's wait on L12 (plan 5b), so the row stays open |
 | **L11** | Junos precedence, repetition, and length behavior for wire and class rules. | The projection model (§8) | Junos (SRX) | **closed** — measured 2026-09-03; results in `port49-junos-lab-tests-results.md` |
-| **L12** | `user-permissions` over TACACS+: accepted with a bitless template, replaces rather than merges with the class, per-session. What each bit reaches, so `bits:` can be declared. Whether a wire `deny-commands .*` plus one allow alternation yields exactly the permits. Whether `deny-commands-regexps` beats `allow-commands-regexps` over the wire as documented, and whether numbered names (`allow-commands1`, `allow-commands2`) are distinct attributes. | The projection rule, its default shape, and its refused shape (§8; §13, decision 22) | Junos (vSRX / vJunos-router in containerlab) | open — `user-permissions` and class bits are in production use; no capture yet |
+| **L12** | `user-permissions` over TACACS+: accepted with a bitless template, replaces rather than merges with the class, per-session, and two bits in one value. What each bit reaches, so `bits:` can be declared, and that `view` alone does not show the configuration. Whether a wire `deny-commands .*` plus one allow alternation yields exactly the permits. Whether `deny-commands-regexps` beats `allow-commands-regexps` over the wire as documented, and whether numbered names (`allow-commands1`, `allow-commands2`) are distinct attributes. Whether `deny-commands` reaches a statement typed in configuration mode, and `run`. Whether a template user commits with no uid, and whether one with no authentication refuses a local login. What a class with no bits runs (`baseline`), and whether `deny-commands .*` refuses it. | The projection rule, its default shape, and its refused shape (§8; §13, decision 22); the built-in `bit_delivery` and `bits` (set 1.1.0) | Junos (vSRX / vJunos-router in containerlab) | open — `user-permissions` and class bits are in production use; no capture yet |
 | **L13** | How long a device waits for a TACACS+ reply, and what it does when a FAIL arrives after that — reports an authentication failure, or treats the server as unreachable and falls through to the next method or the next server. | port49 delays a FAIL on purpose: `limits.auth_failure_delay_base` doubling to `limits.auth_failure_delay_max`, **default 500ms and 2s**, which is the "answered with increasing delay" of design document §11. The ceiling was 5s until this row measured device reply timeouts; **2026-09-21 it was lowered to 2s**, which is under every timeout measured here, so a FAIL is always delivered inside it (`tests/lab/results/L13-*.md`). A ceiling above a device's timeout turns a denial into silence, and silence is the fall-through condition of §5.6 and L4. | all | open — measured 2026-09-20 over SSH on vJunos-router, vSRX, vEOS, N9Kv and Catalyst 8000V: about 3s on both Junos images, 5.0s on vEOS, about 6s on the N9Kv, which also retransmits, and above 12s on IOS-XE, which this sweep does not bound from above; past that timeout every platform that reached it takes the fall-through branch; other transports and the next-server case unmeasured; see below |
 | **L14** | Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does; whether any authorization request is sent for the session or for an `<edit-config>`, and with what `service`, `cmd` and `cmd-arg`; what `port` and `rem_addr` contain; what accounting arrives for a NETCONF session and for a commit. | Adapter coverage for automation traffic (§8); the login context key (§5.1.1); what reconciliation may conclude from accounting (§9) | Junos, NX-OS, EOS | open — measured 2026-09-20 on vEOS, vJunos-router and vSRX; on the N9Kv the AAA half is measured and the RPC half is not, because the channel closes before any RPC is answered; IOS-XE and key-based SSH unmeasured. **2026-09-21 (L17):** a Junos NETCONF session on port 830 is refused outright when port49 denies its session authorization and `tacplus-options strict-authorization` is committed, so the statement reaches automation traffic and not only interactive logins; see below |
 | **L16** | Role delivery over TACACS+ and its interaction with command authorization. Whether a custom role named in a reply attribute takes effect — verified by a command it forbids being refused, never by the device echoing the name back; whether the device still sends a per-command authorization request for a command its own role forbids; which wins when the device's role and port49 disagree, **in both directions**; two roles at once (NX-OS documents a union with permit winning); a role name the device does not have; no role attribute at all; the accepted spellings (`shell:roles=` / `shell:roles*`, bare or inside `cisco-av-pair`); and the `priv-lvl=N` to `priv-N` mapping under `feature privilege`. | The session-attribute model (§6) and adapter `privilege` blocks (§8) — a custom role is the NX-OS and EOS analogue of a Junos login class, which is what decision 22 projects into. Also what the decision log means (§5.7, §9): if a device can refuse a command port49 permitted, the log records a permit for a command that never ran. | EOS, NX-OS | open — added 2026-09-21. vEOS measured 2026-09-21 (`shell:roles*<name>` **does not deliver a role** — the device reports the session's role as `<unknown>` — port49's per-command deny binds, and a `cisco-av-pair*` attribute sent as OPTIONAL is refused outright) and **2026-09-22, which corrects the reading drawn from it**: EOS reads the **bare** attribute `roles=<name>`, which the first run never sent, under either argument flag; sent by its own name the role is applied, and under `aaa authorization commands ... local` it is the operator's real privilege. `priv-lvl` must be sent too — a reply with a role and no `priv-lvl` lands the session at level 1 — and an OPTIONAL `priv-lvl*N` **is** applied on this image. NX-OS measured 2026-09-21 (delivery: all three spellings work, an unknown name degrades to `network-operator`, and a delivered role's own rules do not bind while `aaa authorization commands` points at TACACS+) and 2026-09-22 (precedence: **`shell:roles` decides the role and a `priv-lvl` beside it is inert, in both directions**, so an NX-OS adapter sends the role and never the privilege level; with command authorization pointed at `local` instead, the delivered role does bind). Open on EOS: the `cisco-av-pair` ambiguity, and whether a role that permits everything carries a read-only one delivered beside it (the pair was measured, the permissive role alone was not). **2026-09-24, the disruptive commands** (`tests/lab/results/ceiling-*.md`, no row of its own yet): with port49 permitting every command, an NX-OS `network-operator` session ran `clear counters`, `clear ip bgp *` and a configuration change, and a vEOS `network-operator` session at level 15 ran `clear counters`, had `clear ip bgp *` parsed and passed (BGP cannot run on that image) and entered `configure`; only the privilege level binds there (level 1 is refused all three by the parser, never asking port49); see below |
@@ -5309,6 +5511,9 @@ implemented against a guess. This section is the one place the distinction is ke
 | **L20** | Whether a device answers a repeat API request without asking TACACS+; for how long; what it keys that answer on (the credential, the username, the client); whether a **wrong password** for the same user inside that window is also accepted; and whether a credential port49 would now refuse is re-checked inside it. | Whether a revocation in port49 reaches an API client at all (§5.1.4), and decision 15's bound on how long a spent token works — the receipt's `receipt_idle_ttl` and `receipt_max_age` act only on exchanges the device sends | IOS-XE; then every HTTP API transport | open — added 2026-09-23. IOS-XE RESTCONF answered a repeat of an already-spent token, 3s later, with `200 OK` and **zero** TACACS+ traffic (`tests/lab/results/L1-restconf-cisco_iosxe.md`), so a revocation in port49 cannot reach that repeat. **Measured 2026-09-24 on IOS-XE** (`tests/lab/results/L20-cisco_iosxe.md`): the cache is per credential (username and password), not per username or client address; a wrong password inside it goes to port49 and is refused; it lasts about 10s fixed from the authentication that filled it; and a cached credential is not re-checked, even with port49 answering every authentication ERROR. Open: every other HTTP API transport, so the row stays open; see below |
 | **L21** | Whether each platform sends the command words the operator typed (`sh run`) or the resolved ones (`show running-config`) on a per-command authorization request, and on the accounting record for it. | `expands_abbreviations` per platform (§3 rule 4, §8): where it is `false` a deny's word matches its own abbreviations, which over-denies, and where it is wrongly `true` an abbreviation slips past a deny | EOS, NX-OS, IOS-XE | closed — measured 2026-09-24; `tests/lab/results/L21-arista_eos.md`, `L21-cisco_nxos.md`, `L21-cisco_iosxe.md`. All three images send the **resolved** words, on the request and on the accounting record, over interactive SSH: `sh ver` arrives as `cmd=show cmd-arg=version`, and `sh clock` was denied by a `show clock` deny on all three. Interface names differ: IOS-XE splits `Gi1` into `GigabitEthernet`, `1`; vEOS and the N9Kv join it (`Ethernet1`, `Ethernet1/1`). Other transports and releases are outside what was measured; see below |
 | **L22** | What each per-command platform's device lets a session run at each level port49 renders — with port49 permitting every command, which of `clear counters`, `clear ip bgp *` and `configure terminal` it runs, refuses in its own parser, or sends port49 — and which level or role it reports, for the exact reply each built-in adapter sends; and, with port49 stopped under an open session on a command method list ending in `local`, whether operator's reply can change the configuration where admin's can, and whether it runs `clear counters` and `clear ip bgp *`; and, on IOS-XE with `privilege exec level 7 clear counters` configured and no `aaa authorization commands 7` list, whether a level-7 session runs `clear counters` without asking port49. | Decision 25; the adapters' `privilege`, `unreachable` and `fallback` (§8); the dead-rule and fallback-exposure reports (§12) | EOS, NX-OS, IOS-XE | closed — measured 2026-09-24; tests/lab/results/L22-arista_eos.md, L22-cisco_nxos.md, L22-cisco_iosxe.md. Each built-in adapter's reply at readonly, operator and admin was applied as the adapter says: on vEOS level 1 then 15 with network-operator, network-operator and network-admin; on the N9Kv network-operator, network-operator, network-admin, `clear counters` and `configure terminal` both sent to port49 at every level; on IOS-XE 17.13.01a levels 1, 7 and 15, level 7 sending `clear counters` and refusing `configure terminal` in the parser. With port49d stopped under an open session and the method list falling back to local, operator's reply could not change the configuration on any of the three, and admin's could on vEOS and the N9Kv. Beside it (`L22-carried-*.md`): vEOS's network-operator still ran `clear counters` and passed `clear ip bgp *` through authorization, the N9Kv's was refused both, and IOS-XE refused a token session every command at 7 and at 15, admin's included; on IOS-XE with no `aaa authorization commands 7` list, operator's `clear counters` ran without asking port49. Inert beside admin's reply: `home-directory`, `idletime` and `timeout` on vEOS and the N9Kv; `idletime*30` and `timeout*480` on IOS-XE, where they are accepted but held bearing (§6), and which refused the session for `home-directory`. By hand 2026-09-24: tests/lab/results/ceiling-*.md |
+| **L23** | Whether `home-directory`, `idletime` and `timeout`, each beside readonly's reply, leave the session readonly's on EOS and NX-OS: the same identity, the same reach for `clear counters` and `configure terminal`, and a permitted `show version`. Beside admin's reply (L22) a raise is invisible (5a final review M3). | The inert lists of `arista_eos` and `cisco_nxos` (§6, §8) | EOS, NX-OS | open |
+| **L24** | Whether a Junos login class's `idle-timeout` ends an idle session a TACACS+ reply landed in that class, through `local-user-name` and through the `remote` template. | Decision 21's enforced approximation; `port49 platform export --classes` (§5.6, §8) | Junos | open |
+| **L25** | Whether the N9Kv writes an accounting record under `admin` with task_id `vsh.bin.<port>` when a network-operator cancels the sudo prompt of a bare `show interface`, and what distinguishes it from a person's `admin` session, over SSH and over NX-API. | A `cisco_nxos` system user keyed on its task_id, never the username alone (§5.8) | NX-OS | open — a production observation with no note |
 
 **What has been measured so far, per row.** The measurements exist and the notes are in the
 repository. NX-OS was measured on 2026-09-20 and is no longer outstanding; **IOS-XE was
````

- [ ] **Step 2: Check it**

Run: `git diff --stat` and `make test && make vet`
Expected: the spec is the only file changed, and every package is `ok` (nothing else moved). Read
the new rows L23, L24 and L25 in §15's table, and check that each one's Status is `open`; read
decision 26 and the `projection_fail_closed` row.

- [ ] **Step 3: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "$(cat <<'EOF'
docs: spec for plan 5b, the Junos projection, capability inference and decision 26

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
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
- Consumes (harness): `eachPlatform`, `l.capture`, `l.derivedConfigCmd`, `l.restart`, `l.stopDaemon`,
  `l.nextLogin`, `l.sshCLI`, `l.dial`, `isAuthRejection`, `c.expect`, `c.sendExpect`, `c.expectFrom`,
  `junosPrepare`, `junosConfigure`, `l.withAdminCLI`, `l.junosCLI`, `l.drainRecords`, `l.result`,
  `l.configPath`, `precReply`, `l16TrimEcho`, `l16Slug`, `containsAny`, `oneLine`, `orEmpty`, `str`,
  `sub`; `breakglassUser`, `breakglassPassword`.
- Produces, for Tasks 3 and 19: `junosHost = "srx1"`, `junosPer` (45 s), `junosRefusal`,
  `type junosProbe struct{ cmd string; complete bool; evidence string }`, `type junosRun`,
  `(junosRun).runs(p junosProbe) bool`, `(junosRun).ran(cmd string) bool`,
  `(junosRun).completes(p junosProbe) bool`, `(junosRun).cell(p, control junosRun) string`,
  `(*lab).junosConfigureAdmin(t, lines []string) string`,
  `(*lab).junosLogin(t, name, attrs string) (*cliConn, junosRun, bool)`,
  `(*lab).junosSession(t, name, attrs string, probes []junosProbe) junosRun`,
  `(*lab).junosProbe(c *cliConn, p junosProbe) (string, error)`, `configurationProbes`, `orErr`. And
  the notes Task 14 reads.

This runs before any code, because 1.1.0's values come from it. The lab authorizer delivers each
variant's reply (`lab.session_attributes`), and each variant costs one daemon restart and one
seeded token login. The run spends 16 logins, which is the whole pool: 14 variants and 2 for the
per-session check. The control is a template holding `all` and no regex, and it is checked the
moment its session closes: a control that ran nothing stops the run before a token is wasted.
A command the control does not run says nothing about a variant, and its cell reads "not
comparable". A variant whose login is not prepared or whose `show cli authorization` is not
observed fails the test (pre-flight M3).

The variants measure what the generator writes: explicit anchors with the deny's pipe tail,
refusing `show version` and `show version | no-more` (pre-flight I2); case and abbreviation;
a malformed deny `^(show$`, which says whether a bad wire regex fails open or refuses the session
(pre-flight M1); the narrow shape; a no-bit template, to read the baseline under `deny .*`;
`user-permissions` over a bitless template, with two bits, and per session; configuration mode;
the `-regexps` family; and `allow-commands2`. The host-name probe carries evidence (`host-name
srx1`, the name both images' startup configuration sets), so a filtered empty output reads as
refused, never as run.

The test configures four template users without a uid (`p49-l12-none`, `-view`, `-cfg`, `-all`)
over the break-glass CLI with port49d stopped, and deletes them at the end. Committing without a
uid is itself a measurement. With port49d still stopped it dials a template user locally with an
empty password and with `x`, then commits a user whose password is `encrypted-password "*"` and
dials that: whether a template user can log in locally, and whether the lock refuses it
(pre-flight I9). Every probe is harmless. One interface's counters are cleared and the loopback is
pinged. `request system reboot` and `restart routing` are probed by `?` completion and never run.
The configuration-mode variant sets the host name the device already has.

Every command has `junosPer`, 45 s. An expiry is `not observed`, fails the test, and stops that
session's probes, since the session's state is unknown past a missed prompt.

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/junos_wire_test.go -->
````diff
diff --git a/tests/lab/junos_wire_test.go b/tests/lab/junos_wire_test.go
new file mode 100644
index 0000000..49305e7
--- /dev/null
+++ b/tests/lab/junos_wire_test.go
@@ -0,0 +1,556 @@
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
+// a command in the case, the abbreviation and the pipe typed, what a
+// malformed one does, whether it reaches a statement typed in configuration
+// mode, the `-regexps` family's precedence, whether numbered names are
+// distinct attributes, and whether a template user can be logged into
+// locally. Each is a variant of the lab authorizer's session reply
+// (`lab.session_attributes`) and one token login; the control is a template
+// holding every bit and no regex, so a command the control does not run says
+// nothing about a variant.
+//
+// Every command typed has a deadline, junosPer: a prompt that does not come
+// back within it is "not observed", never a refusal, and fails the test.
+
+// junosPer is the deadline on every command a Junos lab test types.
+const junosPer = 45 * time.Second
+
+// junosHost is the host name both Junos images carry
+// (tests/lab/configs/vjunos-startup.conf), whatever the lab node is named.
+const junosHost = "srx1"
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
+// probe ending in `?` is a listing, `show ?`, kept whole. A probe with
+// evidence ran only where its output holds it: `show configuration` that
+// prints nothing has not shown the configuration.
+type junosProbe struct {
+	cmd      string
+	complete bool
+	evidence string
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
+// runs reports whether the session ran the probe: observed, and its output
+// holds the probe's evidence, or no refusal where it has none.
+func (r junosRun) runs(p junosProbe) bool {
+	out, ok := r.outs[p.cmd]
+	if !ok || slices.Contains(r.unobserved, p.cmd) {
+		return false
+	}
+	if p.evidence != "" {
+		return strings.Contains(out, p.evidence)
+	}
+	return !containsAny(strings.ToLower(out), junosRefusal)
+}
+
+// ran is runs for a probe with no evidence.
+func (r junosRun) ran(cmd string) bool { return r.runs(junosProbe{cmd: cmd}) }
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
+	case !control.runs(p):
+		return "not comparable (the control did not run it)"
+	case r.runs(p):
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
+// junosLogin restarts port49d with attrs as the session reply and logs in
+// with the next seeded token, paging off. A session that did not open is a
+// run with loginErr set and no connection.
+func (l *lab) junosLogin(t *testing.T, name, attrs string) (*cliConn, junosRun, int64) {
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
+		return nil, r, off
+	}
+	if err := junosPrepare(c); err != nil {
+		r.unobserved = append(r.unobserved, "set cli screen-length 0")
+		t.Errorf("%s: `set cli screen-length 0` not observed within its deadline: %v", name, err)
+	}
+	if out, err := c.sendExpect("show cli authorization", junosPer, junosOpPrompt); err != nil {
+		r.unobserved = append(r.unobserved, "show cli authorization")
+		t.Errorf("%s: `show cli authorization` not observed within %s: %v", name, junosPer, err)
+	} else {
+		r.auth = precReply(l16TrimEcho(out, "show cli authorization"))
+	}
+	return c, r, off
+}
+
+// junosSession is junosLogin, then each probe with its deadline, then the
+// priv_lvl the device put on the session authorization. A probe sequence that
+// enters configuration mode ends with `exit configuration-mode` itself
+// (configurationProbes).
+func (l *lab) junosSession(t *testing.T, name, attrs string, probes []junosProbe) junosRun {
+	t.Helper()
+	c, r, off := l.junosLogin(t, name, attrs)
+	if c == nil {
+		return r
+	}
+	defer c.Close()
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
+		if str(rec, "event") == "authorize_session" && str(sub(rec, "session"), "username") == r.user {
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
+	{cmd: "show version"}, {cmd: "show version | no-more"}, {cmd: "show system uptime"},
+	{cmd: "show interfaces terse"}, {cmd: "show interfaces fxp0 terse"},
+	{cmd: "show configuration system host-name", evidence: "host-name " + junosHost},
+	{cmd: "clear interfaces statistics fxp0"}, {cmd: "ping 127.0.0.1 count 1 rapid"},
+	{cmd: "SHOW VERSION"}, {cmd: "show interfaces FXP0 terse"}, {cmd: "sh ver"}, {cmd: "sh int fxp0 terse"},
+	{cmd: "set cli screen-width 200"}, {cmd: "file list /var/tmp"},
+	{cmd: "request system reboot", complete: true}, {cmd: "restart routing", complete: true},
+}
+
+type junosVariant struct{ name, attrs, why string }
+
+// junosWireVariants are fourteen logins; the per-session check spends two
+// more, the harness's pool of sixteen.
+var junosWireVariants = []junosVariant{
+	{"control", `["local-user-name=p49-l12-all"]`, "every bit and no regex: what the device runs at all"},
+	{"bitless", `["local-user-name=p49-l12-none"]`, "a template with no bits: the baseline every session has"},
+	{"bitless + user-permissions", `["local-user-name=p49-l12-none", "user-permissions=view"]`,
+		"L12: is user-permissions applied over a bitless template"},
+	{"bitless + two bits", `["local-user-name=p49-l12-none", "user-permissions=view clear"]`,
+		"L12: two bits in one value, space-separated, as the generator writes them"},
+	{"remote + user-permissions", `["user-permissions=view"]`,
+		"L12: over remote's view view-configuration, does it replace (view alone) or merge"},
+	{"narrow", `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^(show version|show interfaces( .*)?)$"]`,
+		"L12: deny .* and one allow alternation yield exactly the permits, and what .* does to the baseline"},
+	{"deny unanchored word", `["local-user-name=p49-l12-all", "deny-commands=version"]`,
+		"L9: is a deny regex matched anywhere in the line"},
+	{"deny prefix", `["local-user-name=p49-l12-all", "deny-commands=show ver"]`, "L9: is it matched as a prefix"},
+	{"deny anchored", `["local-user-name=p49-l12-all", "deny-commands=^show version( *\\|.*)?$"]`,
+		"L9: explicit anchors with the pipe tail the generator writes; and the case and abbreviation of `show version`"},
+	{"deny argument", `["local-user-name=p49-l12-all", "deny-commands=^show interfaces fxp0( .*)?$"]`,
+		"L9: an argument's case and an abbreviated command against a deny"},
+	{"deny malformed", `["local-user-name=p49-l12-all", "deny-commands=^(show$"]`,
+		"L9: a regex the dialect rejects: refused session, ignored, or applied"},
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
+var configurationProbes = []junosProbe{{cmd: "configure"}, {cmd: "set system host-name " + junosHost},
+	{cmd: "run show version"}, {cmd: "run show system uptime"}, {cmd: "exit configuration-mode"}}
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
+			if runs[v.name].loginErr != "" && v.name != "deny malformed" {
+				t.Errorf("%s: the session did not open, so nothing was measured: %s", v.name, runs[v.name].loginErr)
+			}
+			// The control is checked before a token more is spent: without it
+			// no cell compares.
+			if c := runs["control"]; v.name == "control" && (!c.ran("show version") || !c.ran("show interfaces terse") ||
+				!c.runs(junosWireProbes[5])) {
+				t.Fatalf("the control did not run `show version`, `show interfaces terse` and show the configuration, "+
+					"so no cell compares: %+v", c)
+			}
+		}
+		perSession := l.junosPerSession(t)
+		locks := l.junosTemplateLogins(t)
+		control := runs["control"]
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
+				if _, ok := r.outs[p.cmd]; ok || r.loginErr != "" {
+					cell = r.cell(p, control)
+				}
+				fmt.Fprintf(&b, " %s |", cell)
+			}
+			b.WriteString("\n")
+		}
+		fmt.Fprintf(&b, "\n### Read off the table\n\n%s%s\n%s\n", facts, perSession, locks)
+		for _, v := range junosWireVariants {
+			r := runs[v.name]
+			fmt.Fprintf(&b, "\n### %s\n\nReply `%s`.", v.name, v.attrs)
+			if r.loginErr != "" {
+				fmt.Fprintf(&b, " The session did not open: `%s`.\n", r.loginErr)
+				continue
+			}
+			fmt.Fprintf(&b, " `show cli authorization`:\n\n```\n%s\n```\n", r.auth)
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
+			"`deny-commands .*` plus one allow alternation yields exactly the permits, and what it does to the "+
+			"commands a class with no bits runs; whether deny-commands reaches a statement typed in configuration "+
+			"mode, and `run`; whether `deny-commands-regexps` beats `allow-commands-regexps`; whether "+
+			"`allow-commands2` is an attribute of its own; whether a template user commits with no uid, and "+
+			"whether it can be logged into locally (spec §8, §13 decision 22, §15 L12).", b.String())
+		l.result(t, "L9", "Over TACACS+ on `junos-exec`: whether a `deny-commands` regex is matched anywhere in "+
+			"the line, as a prefix, or only as anchored; whether explicit `^` and `$` are taken with the pipe tail "+
+			"`( *\\|.*)?`; whether it reads a command in the case typed (`SHOW VERSION`, an argument `FXP0`), the "+
+			"abbreviation typed (`sh ver`) and the pipe typed (`| no-more`), or as the CLI expands it; what a "+
+			"malformed regex does; and whether a value with spaces is taken raw (spec §8, §15 L9). The "+
+			"`JunosFacts` lines below are what internal/projection reads.", b.String())
+	})
+}
+
+// junosFacts reads the facts the generator's JunosFacts, bit_delivery and
+// the set's fallbacks take off the table, each with the rule it was read by.
+func junosFacts(runs map[string]junosRun) string {
+	c := runs["control"]
+	var b strings.Builder
+	say := func(format string, args ...any) { fmt.Fprintf(&b, "- "+format+"\n", args...) }
+	anchored := runs["deny anchored"]
+	anchors := !anchored.ran("show version") && !anchored.ran("show version | no-more") &&
+		anchored.ran("show system uptime")
+	say("explicit anchors with the pipe tail: %v: `^show version( *\\|.*)?$` refused `show version` (%v) and "+
+		"`show version | no-more` (%v), and ran `show system uptime` (%v)", anchors, !anchored.ran("show version"),
+		!anchored.ran("show version | no-more"), anchored.ran("show system uptime"))
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
+	m := runs["deny malformed"]
+	say("a malformed deny `^(show$`: the session opened %v (%s); `show version` ran %v", m.loginErr == "",
+		orErr(m.loginErr), m.ran("show version"))
+	n := runs["narrow"]
+	exact := n.ran("show version") && n.ran("show interfaces terse") && !n.ran("show system uptime") &&
+		!n.ran("clear interfaces statistics fxp0") && !n.ran("ping 127.0.0.1 count 1 rapid") &&
+		!n.runs(junosWireProbes[5]) && n.loginErr == ""
+	say("narrow shape exact: %v: ran `show version` %v and `show interfaces terse` %v; refused `show system "+
+		"uptime` %v, `clear interfaces statistics fxp0` %v, `ping` %v, the configuration %v", exact,
+		n.ran("show version"), n.ran("show interfaces terse"), !n.ran("show system uptime"),
+		!n.ran("clear interfaces statistics fxp0"), !n.ran("ping 127.0.0.1 count 1 rapid"), !n.runs(junosWireProbes[5]))
+	bl := runs["bitless"]
+	say("under deny .*, the commands a class with no bits runs: `set cli screen-width 200` bitless %v, narrow %v; "+
+		"`file list /var/tmp` bitless %v, narrow %v", bl.ran("set cli screen-width 200"), n.ran("set cli screen-width 200"),
+		bl.ran("file list /var/tmp"), n.ran("file list /var/tmp"))
+	up := strings.Contains(runs["bitless + user-permissions"].auth, "view") &&
+		!strings.Contains(runs["bitless"].auth, "view")
+	two := runs["bitless + two bits"].auth
+	say("user-permissions over a bitless template applied: %v; both bits of a two-bit value applied: %v "+
+		"(bit_delivery: user_permissions only if both are true, and per session below)", up,
+		strings.Contains(two, "view") && strings.Contains(two, "clear"))
+	say("user-permissions over remote: `show cli authorization` lists view-configuration: %v (true: merged or "+
+		"ignored; false: replaced)", strings.Contains(runs["remote + user-permissions"].auth, "view-configuration"))
+	cfg := runs["configuration mode"]
+	say("a statement typed in configuration mode under a deny-commands naming it: %s; `run show version` "+
+		"under a deny naming `show version`: %s", cfg.cell(configurationProbes[1], c), cfg.cell(configurationProbes[2], c))
+	say("-regexps: `show version` refused with both deny and allow naming it: %v", !runs["regexps family"].ran("show version"))
+	say("allow-commands2 an attribute of its own: `show system uptime` ran: %v", runs["numbered name"].ran("show system uptime"))
+	return b.String()
+}
+
+func orErr(s string) string {
+	if s == "" {
+		return "no error"
+	}
+	return s
+}
+
+// junosPerSession asks whether user-permissions is per session: session A
+// opens under `view`, port49d restarts under `clear`, session B opens, and A
+// is asked again. It spends two tokens. Anything not observed fails the test.
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
+		t.Errorf("per session: session A did not open: %v", err)
+		return "- per session: not observed (session A did not open)\n"
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
+		return "- per session: not observed\n"
+	}
+	return fmt.Sprintf("- per session: A before `%s`, B `%s`, A after B `%s`\n", oneLine(before), oneLine(bAuth),
+		oneLine(after))
+}
+
+// junosTemplateLogins asks whether a template user can be logged into on
+// its own, with port49d stopped so the device takes the local password (L4):
+// the reference configuration's templates carry no authentication, and one
+// with class `all` that took an empty password would be a way in for anyone.
+// Then whether `authentication encrypted-password "*"` commits, and whether it
+// locks the account. Each dial has a 30 s deadline; a dial that neither
+// failed nor opened is not observed and fails the test.
+func (l *lab) junosTemplateLogins(t *testing.T) string {
+	t.Helper()
+	if err := l.stopDaemon(); err != nil {
+		t.Fatalf("could not stop port49d for the local logins: %v", err)
+	}
+	defer func() {
+		if std, err := l.configPath(); err == nil {
+			if err := l.restart(std); err != nil {
+				t.Errorf("could not put port49d back on the lab config: %v", err)
+			}
+		}
+	}()
+	var b strings.Builder
+	dial := func(user, password string) string {
+		c, err := l.dial(user, password, 30*time.Second)
+		if err == nil {
+			c.Close()
+			return "**logged in**"
+		}
+		if !isAuthRejection(err) {
+			t.Errorf("a local login as %s was not observed: %v", user, err)
+			return "not observed: " + oneLine(err.Error())
+		}
+		return "refused"
+	}
+	fmt.Fprintf(&b, "- a template user with no authentication, locally: empty password %s, `x` %s\n",
+		dial("p49-l12-none", ""), dial("p49-l12-none", "x"))
+	lock := []string{"set system login user p49-l12-lock class p49-l12-none",
+		`set system login user p49-l12-lock authentication encrypted-password "*"`}
+	c, err := l.junosCLI(breakglassUser, breakglassPassword)
+	if err != nil {
+		t.Fatalf("no admin CLI for the lock measurement: %v", err)
+	}
+	out, cerr := junosConfigure(c, lock...)
+	c.Close()
+	fmt.Fprintf(&b, "- `authentication encrypted-password \"*\"` commits: %v (%s)\n", cerr == nil, commitWord(out))
+	if cerr == nil {
+		fmt.Fprintf(&b, "- that template, locally: empty password %s, `*` %s\n", dial("p49-l12-lock", ""),
+			dial("p49-l12-lock", "*"))
+		if c, err := l.junosCLI(breakglassUser, breakglassPassword); err == nil {
+			if _, err := junosConfigure(c, "delete system login user p49-l12-lock"); err != nil {
+				t.Errorf("removing p49-l12-lock: %v", err)
+			}
+			c.Close()
+		}
+	}
+	return b.String()
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

Run it in the background as "Running the lab" shows, with the stall watchdog running for the whole run and cleaning up after a `go test` timeout. Boot budget 8 min; watchdog `STALL=25`. Expected: `--- PASS:
TestL12JunosWire/juniper_vjunos-router`, and `wrote tests/lab/results/L12-juniper_vjunos-router.md`
and `L9-...` in the log. A FAIL that names `not observed`, or a variant whose session did not open,
measured nothing for that cell: rerun. A FAIL on the control means the lab is broken, not Junos:
stop and report it.

- [ ] **Step 4: Run it on vSRX**

The same, with `PORT49_LAB_PLATFORMS=vsrx`, the log `l12-wire-vsrx.log`, and topology
`vsrx.clab.yml` for the watchdog. Boot budget 6 min. On vSRX `junosCLI` reaches the break-glass CLI
over the console as root (`results/juniper_vsrx-config-verified.md`), and the note says so.

- [ ] **Step 5: Read the notes, and record what Task 14 takes from them**

Each note ends with "Read off the table". Copy every line of it into the task's report for Task
14, which has a branch for each. In particular:

- `explicit anchors with the pipe tail: ...` on both images;
- `JunosFacts.CaseSensitive = ...` and `JunosFacts.DenyMatchesExpanded = ...` on both images;
- `narrow shape exact: ...`, with which of its probes ran;
- `under deny .*, the commands a class with no bits runs: ...` (the baseline under `.*`);
- the malformed deny line;
- `user-permissions over a bitless template applied: ...`, the two-bit line and the per-session
  line;
- the template-login lines and "The templates were committed without a uid";
- the configuration-mode line, `-regexps` and `allow-commands2`;
- the table's `priv_lvl on the request` column. The Junos adapter's ceiling numbers assume 1
  (Decided 10), so if it is not 1, say so in the report.

- [ ] **Step 6: Commit the test, the notes and the evidence**

```bash
make evidence
git add tests/lab/junos_wire_test.go tests/lab/results/L12-juniper_*.md tests/lab/results/L9-juniper_*.md \
  tests/lab/evidence/L12-juniper_*.pcap
git commit -m "$(cat <<'EOF'
test: measure the Junos wire facts decision 22 rests on (L9, L12)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

The rows stay open until Task 20. A note is a measurement, and closing a row is its own commit
(CLAUDE.md, rule 3).

---

### Task 3: (lab, on beehive) Each bit's reach, the baseline, the carve-out, and the class idle-timeout: L12 and L24

**Files:**
- Create: `tests/lab/junos_bits_test.go`
- Results (written by the run): `tests/lab/results/L12-bits-juniper_vjunos-router.md`,
  `L12-bits-juniper_vsrx.md`, `L24-juniper_vjunos-router.md`, `L24-juniper_vsrx.md`; evidence
  `L12-bits-*.pcap`, `L24-*.pcap`

**Interfaces:**
- Consumes: Task 2's `junosSession`, `junosProbe`, `junosRun`, `junosConfigureAdmin`, `junosPer`,
  `junosHost`; the harness's `l.dial`, `syncBuf`.
- Produces: `junosBitReach map[string][]string`, `baseline` included, and `junosCarveOuts
  map[string][]string`: the candidates Task 14 ships under `bits:` and `carve_outs:`. Also
  `(*lab).junosSurvey`, `(*lab).holdUntilClosed(user, password string, within time.Duration)
  (time.Duration, string, error)`. And the notes Task 14 reads.

`junosBitReach` is the candidate each bit's reach is verified against, as an upper bound. For each
bit a ceiling names (view, view-configuration, clear, network, trace), a template's class holds
that bit alone; a class `none` holds no bit, and a class `all` holds every bit (pre-flight I3).
Under each the test reads the top-level `?` completion and one level under each word it offers
(`junosSurvey`). A word a bit's completion offers and `none`'s does not must be held by the bit's
candidate reach, and every word `none` offers must be held by the candidate `baseline`, or the test
fails and names the rule to add. That is the direction that fails closed: a reach that says more
than the bit does makes the projection require more of the grant before it sends the bit, and a
larger baseline puts more denies on the wire.

The carve-out is asserted against the `all` control, and only where both probes were observed
(pre-flight I4): under `all`, `show configuration system host-name` shows `host-name srx1`; under
`view` alone it must not. If it does, `view-configuration` carves nothing, and the note says to
remove the carve-out. The executed-probe table reads each probe against `all`, never `none`.

L24 lands one session through `local-user-name` in a class with `idle-timeout 1`, and one through
the `remote` template, whose class gets `idle-timeout 1` for the run. It waits for the operational
prompt before starting the clock, then holds each idle (pre-flight I5). A session that closes in
under 50 s was not closed by an idle timer and fails; one still open after 4 minutes is not
observed, and fails.

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/junos_bits_test.go -->
````diff
diff --git a/tests/lab/junos_bits_test.go b/tests/lab/junos_bits_test.go
new file mode 100644
index 0000000..63bf7b1
--- /dev/null
+++ b/tests/lab/junos_bits_test.go
@@ -0,0 +1,392 @@
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
+// ships under `bits:` (spec §8, §15 L12). `baseline` is what a class with no
+// bits runs, held by every session. A bit that reaches a command no rule here
+// holds fails the test: widen the rule, here and in the adapter. Reach is a
+// union, so a wider reach only makes the projection send the bit for fewer
+// grants.
+var junosBitReach = map[string][]string{
+	"baseline":           {"help **", "quit **", "exit **", "set cli **", "show cli **"},
+	"view":               {"show **"},
+	"view-configuration": {"show configuration **"},
+	"clear":              {"clear **"},
+	"network":            {"ping **", "traceroute **", "ssh **", "telnet **"},
+	"trace":              {"monitor **"},
+}
+
+// junosCarveOuts are the commands a bit alone makes available, whatever other
+// bit reaches them: the adapter's `carve_outs:`. The one candidate is the one
+// the projection's realistic readonly rests on, and this test asserts it:
+// under `view` alone the configuration is not shown.
+var junosCarveOuts = map[string][]string{"view-configuration": {"show configuration **"}}
+
+// junosHostProbe shows the configuration only where it prints the host name.
+var junosHostProbe = junosProbe{cmd: "show configuration system host-name", evidence: "host-name " + junosHost}
+
+// junosBitProbes are typed under each single-bit template after the survey,
+// read against the `all` control.
+var junosBitProbes = []junosProbe{
+	{cmd: "show version"}, junosHostProbe, {cmd: "show system uptime"},
+	{cmd: "clear interfaces statistics fxp0"}, {cmd: "ping 127.0.0.1 count 1 rapid"},
+	{cmd: "traceroute 127.0.0.1 ttl 1 wait 1"}, {cmd: "file list /var/tmp"}, {cmd: "set cli screen-width 200"},
+	{cmd: "monitor interface", complete: true}, {cmd: "request system reboot", complete: true},
+	{cmd: "restart routing", complete: true}, {cmd: "configure"}, {cmd: "exit configuration-mode"},
+}
+
+// completionWord is a word a `?` listing offers, one per line, the
+// description after it dropped.
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
+// junosSurvey is one class's reach as its completion offers it: every word
+// at the top level, and every word one level under each (`show ?`,
+// `request ?`), keyed "word" and "word sub". Each listing has junosPer; a
+// listing not observed fails the test and ends the survey.
+func (l *lab) junosSurvey(t *testing.T, name string, c *cliConn, r *junosRun) []string {
+	t.Helper()
+	top, err := l.junosProbe(c, junosProbe{cmd: "?", complete: true})
+	if err != nil {
+		t.Errorf("%s: the top-level listing not observed within %s: %v", name, junosPer, err)
+		r.unobserved = append(r.unobserved, "?")
+		return nil
+	}
+	var reach []string
+	for _, w := range completionWords(top) {
+		reach = append(reach, w)
+		out, err := l.junosProbe(c, junosProbe{cmd: w + " ?", complete: true})
+		if err != nil {
+			t.Errorf("%s: `%s ?` not observed within %s: %v", name, w, junosPer, err)
+			r.unobserved = append(r.unobserved, w+" ?")
+			return reach
+		}
+		for _, x := range completionWords(out) {
+			reach = append(reach, w+" "+x)
+		}
+	}
+	return reach
+}
+
+func TestL12JunosBits(t *testing.T) {
+	eachPlatform(t, func(t *testing.T, l *lab) {
+		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
+			t.Skip("Junos only")
+		}
+		stop := l.capture(t, "L12-bits")
+		defer stop()
+		var bits []string
+		for b := range junosBitReach {
+			if b != "baseline" {
+				bits = append(bits, b)
+			}
+		}
+		slices.Sort(bits)
+		classes := append([]string{"none", "all"}, bits...)
+		var define, remove []string
+		for _, b := range classes {
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
+		runs, reach := map[string]junosRun{}, map[string][]string{}
+		for _, b := range classes {
+			c, r, _ := l.junosLogin(t, "bit "+b, `["local-user-name=p49-l12-b-`+b+`"]`)
+			if c == nil {
+				t.Errorf("bit %s: the session did not open: %s", b, r.loginErr)
+				runs[b] = r
+				continue
+			}
+			reach[b] = l.junosSurvey(t, b, c, &r)
+			for _, p := range junosBitProbes {
+				out, err := l.junosProbe(c, p)
+				r.outs[p.cmd] = out
+				if err != nil {
+					r.unobserved = append(r.unobserved, p.cmd)
+					t.Errorf("bit %s: %q not observed within %s: %v", b, p.cmd, junosPer, err)
+					break
+				}
+			}
+			c.Close()
+			runs[b] = r
+		}
+		all := runs["all"]
+		if !all.runs(junosHostProbe) || !all.ran("show version") {
+			t.Fatalf("the `all` control neither showed the configuration nor ran `show version`, so nothing "+
+				"compares: %+v", all)
+		}
+		var b strings.Builder
+		fmt.Fprintf(&b, "Each row is a session whose template's class holds one bit and nothing else; `none` "+
+			"holds none and `all` every bit. A command word, or a word and the word under it, is the bit's where "+
+			"its completion offers it and `none`'s does not; `none`'s own are the baseline.\n\n"+
+			"| bit | words beyond none | candidate reach | held |\n|---|---|---|---|\n")
+		check := func(bit string, words []string) {
+			var unheld []string
+			for _, w := range words {
+				if !heldBy(junosBitReach[bit], w+" **") {
+					unheld = append(unheld, w+" **")
+				}
+			}
+			fmt.Fprintf(&b, "| %s | %s | `%s` | %s |\n", bit, strings.Join(words, ", "),
+				strings.Join(junosBitReach[bit], "`, `"), heldCell(unheld))
+			if len(unheld) > 0 {
+				t.Errorf("%s reaches %v, which its candidate reach does not hold: add each to junosBitReach[%q] "+
+					"and to platforms/1.1.0/juniper_junos.yaml's bits.%s", bit, unheld, bit, bit)
+			}
+		}
+		check("baseline", reach["none"])
+		for _, bit := range bits {
+			check(bit, beyond(reach[bit], reach["none"]))
+		}
+		// The carve-out the projection reads: under `view` alone the
+		// configuration is not shown, observed, against a control that shows it.
+		view := runs["view"]
+		shown := view.runs(junosHostProbe)
+		_, typed := view.outs[junosHostProbe.cmd]
+		observed := typed && !slices.Contains(view.unobserved, junosHostProbe.cmd)
+		fmt.Fprintf(&b, "\nUnder `view` alone `show configuration system host-name` (observed: %v) shows `host-name "+
+			"%s`: %v; under `all` it does. Under `view-configuration` alone: %v. The adapter's carve-out "+
+			"`view-configuration: [show configuration **]` holds only if `view` alone does not show it.\n", observed,
+			junosHost, shown, runs["view-configuration"].runs(junosHostProbe))
+		if !observed || shown {
+			t.Errorf("the carve-out is not measured: under view alone the probe was observed %v and showed the "+
+				"configuration %v; remove it from junosCarveOuts and from the adapter's carve_outs, and add "+
+				"\"show configuration **\" to view's reach", observed, shown)
+		}
+		fmt.Fprintf(&b, "\n| probe |")
+		for _, c := range classes {
+			fmt.Fprintf(&b, " %s |", c)
+		}
+		fmt.Fprintf(&b, "\n|---|%s\n", strings.Repeat("---|", len(classes)))
+		for _, p := range junosBitProbes {
+			fmt.Fprintf(&b, "| `%s` |", p.cmd)
+			for _, c := range classes {
+				fmt.Fprintf(&b, " %s |", runs[c].cell(p, all))
+			}
+			b.WriteString("\n")
+		}
+		fmt.Fprintf(&b, "\nThe reach as measured, ready for `bits:` and `carve_outs:`:\n\n```yaml\n    bits:\n")
+		for _, bit := range sortedKeysOf(junosBitReach) {
+			fmt.Fprintf(&b, "      %s: [%s]\n", bit, quotedList(junosBitReach[bit]))
+		}
+		b.WriteString("      all: [\"**\"]\n    carve_outs:\n")
+		for _, bit := range sortedKeysOf(junosCarveOuts) {
+			fmt.Fprintf(&b, "      %s: [%s]\n", bit, quotedList(junosCarveOuts[bit]))
+		}
+		b.WriteString("```\n")
+		for _, c := range classes {
+			r := runs[c]
+			fmt.Fprintf(&b, "\n### %s\n\n`show cli authorization`:\n\n```\n%s\n```\n\nCompletion: %s\n", c, r.auth,
+				strings.Join(reach[c], ", "))
+			for _, p := range junosBitProbes {
+				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", p.cmd, orEmpty([]string{r.outs[p.cmd]}, 0))
+			}
+		}
+		l.result(t, "L12-bits", "What each permission bit a built-in level's ceiling names reaches, alone in a "+
+			"template's class, over TACACS+ `local-user-name`: every command word, and every word one level under "+
+			"it, its completion offers that a class with no bits does not, held by the adapter's `bits:` reach as "+
+			"an upper bound; what a class with no bits runs (`baseline`); and that `view` alone does not show the "+
+			"configuration, the one carve-out the adapter declares (spec §8, §15 L12).", b.String())
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
+// class, through `local-user-name` and through the `remote` template. The
+// clock starts at the prompt; a session closed in under 50 s did not idle out
+// (idle-timeout is 1 minute) and fails, and one still open after four minutes
+// is not observed, and fails.
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
+		fmt.Fprintf(&b, "| path | reply | closed after the prompt | what the device said |\n|---|---|---|---|\n")
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
+			switch {
+			case err != nil:
+				cell = "not observed: " + oneLine(err.Error())
+				t.Errorf("%s: %v", v.name, err)
+			case elapsed < 50*time.Second:
+				t.Errorf("%s: closed %s after the prompt, before a 1-minute idle-timeout could: not the timer", v.name,
+					elapsed)
+			}
+			fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` |\n", v.name, v.attrs, cell, oneLine(said))
+		}
+		l.result(t, "L24", "A login class's `idle-timeout` ends an idle session a TACACS+ reply landed in "+
+			"that class, through `local-user-name` and through the `remote` template (spec §5.6; §13 decision 21).",
+			b.String())
+	})
+}
+
+// holdUntilClosed opens an interactive session, waits for its prompt (90 s),
+// and types nothing until the device closes it, within the deadline. An error
+// is a session that did not reach a prompt, or one still open at the
+// deadline: not observed.
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
+	done := make(chan error, 1)
+	go func() { done <- s.Wait() }()
+	prompt := time.Now().Add(90 * time.Second)
+	for !strings.Contains(buf.String(), junosOpPrompt) {
+		select {
+		case <-done:
+			return 0, tail(buf.String()), fmt.Errorf("closed before a prompt")
+		case <-time.After(250 * time.Millisecond):
+		}
+		if time.Now().After(prompt) {
+			return 0, tail(buf.String()), fmt.Errorf("no prompt within 90s")
+		}
+	}
+	start := time.Now()
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

Run it in the background as "Running the lab" shows, with the stall watchdog running for the whole run and cleaning up after a `go test` timeout. The run spends 9 of the 16 seeded logins. Then the same with
`PORT49_LAB_PLATFORMS=vsrx`.

Expected: both tests PASS on both images. If `TestL12JunosBits` fails with `bit X reaches [...],
which its candidate reach does not hold` (or `baseline`), that is a measurement, not a defect. Add
each named rule to `junosBitReach[X]` in this file, rerun until it passes, and carry the final
table to Task 14 (the note prints `bits:` and `carve_outs:` ready to paste). If the carve-out
assertion fails, remove the entry from `junosCarveOuts` as the failure says, and carry that too.

- [ ] **Step 4: Commit the test, the notes and the evidence**

```bash
make evidence
git add tests/lab/junos_bits_test.go tests/lab/results/L12-bits-juniper_*.md tests/lab/results/L24-juniper_*.md \
  tests/lab/evidence/L12-bits-juniper_*.pcap tests/lab/evidence/L24-juniper_*.pcap
git commit -m "$(cat <<'EOF'
test: measure each Junos bit's reach and the class idle-timeout (L12, L24)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
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
  `inertCandidates` (`tests/lab/adapters_test.go`); `negativeFinding`; the NX-API helpers of
  `tests/lab/l7_test.go`; `platform.DialectFor(name).Render("readonly")`.
- Produces: the notes Task 14 (L23) and Task 15 (L25) read.

5a final review M3: beside admin's reply, a candidate that raised the session would look inert,
because admin already holds everything. Beside readonly's, a raise shows. The control is
readonly's own reply, and it must open with `show version` permitted, or nothing compares. A
candidate is inert only where the session opened with readonly's identity, the same reach for
`clear counters` and `configure terminal`, and a permitted `show version`. A candidate listed
inert that moved the session fails the test and names Task 14.

L25 opens one pty session as a network-operator (readonly's reply), types a bare `show interface`,
and cancels the sudo prompt with ^C if one appears. It then waits 30 s for an accounting record
under `admin`. Each prompt has a 60 s deadline. If no record comes, the note carries it as a
negative finding with the exact transcript (`negativeFinding`), and the row stays open. It then
sends one NX-API `cli_show` as the NX-API user and records the task_ids that session's accounting
carried (pre-flight M7): a person's API session whose record carries `vsh.bin.<n>` would make the
task_id no discriminator, and Task 15 then does not key a system user on it.

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/l23_test.go -->
````diff
diff --git a/tests/lab/l23_test.go b/tests/lab/l23_test.go
new file mode 100644
index 0000000..9a8e75f
--- /dev/null
+++ b/tests/lab/l23_test.go
@@ -0,0 +1,180 @@
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
+	adapter "github.com/blanketfish/port49/internal/platform"
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
+					"(plan 5b, Task 14)", name, l.p.name)
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
+		// Whether a person's session can carry a vsh.bin task_id: an NX-API
+		// request, the other path a person's `admin` could take, recorded by
+		// its task_id. A system task keyed on the task_id is sound only if no
+		// person's record carries one (plan 5b pre-flight M7).
+		read := nxapiRead.check(t, l)
+		off = l.mark()
+		body := nxapiBody("cli_show", "show version")
+		if _, err := apiPost("https://"+l.p.addr+"/ins", read.user, read.secret, "application/json", body,
+			60*time.Second); err != nil {
+			t.Errorf("the NX-API request was not observed: %v", err)
+		}
+		var tasks []string
+		for _, r := range l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
+			return slices.ContainsFunc(rs, func(r map[string]any) bool {
+				return str(r, "event") == "account" && str(sub(r, "session"), "username") == read.user
+			})
+		}) {
+			if str(r, "event") == "account" && str(sub(r, "session"), "username") == read.user {
+				tasks = append(tasks, "`"+str(r, "task_id")+"`")
+			}
+		}
+		if len(tasks) == 0 {
+			t.Errorf("no accounting record for the NX-API request in 30s: the task_id it carries is not observed")
+		}
+		vsh := slices.ContainsFunc(tasks, func(s string) bool { return strings.HasPrefix(s, "`vsh.bin.") })
+		fmt.Fprintf(&b, "\nA person's NX-API `cli_show` as %s wrote accounting with task_id %s: a `vsh.bin.` task_id "+
+			"on a person's record: %v.\n", read.user, strings.Join(tasks, ", "), vsh)
+		l.result(t, "L25", "On the N9Kv, whether a network-operator's bare `show interface` prompts for sudo, "+
+			"whether cancelling it writes an accounting record under `admin` with task_id `vsh.bin.<port>`, and "+
+			"whether a person's NX-API request can carry such a task_id (spec §5.8, §15 L25).", b.String())
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
counters` on an exec channel). Run it in the background as "Running the lab" shows, with the stall watchdog running for the whole run and cleaning up after a `go test` timeout. On the N9Kv the watchdog runs with `STALL=40`.

Expected: PASS, and one note per test per platform. A candidate that is not inert beside readonly
fails `TestL23InertBesideReadonly` with the name to move: that is a measurement, carried to Task 14.
`TestL25NXOSSystemUser` passes whether or not the record appears; a missed prompt or NX-API
request fails it. What it measured is in the note: an SSH `admin` record with `task_id vsh.bin.<n>`
and no `vsh.bin` task_id on the NX-API session means Task 15 runs; anything else means it does not.

- [ ] **Step 4: Commit the test, the notes and the evidence**

```bash
make evidence
git add tests/lab/l23_test.go tests/lab/results/L23-*.md tests/lab/results/L25-cisco_nxos.md \
  tests/lab/evidence/L23-*.pcap tests/lab/evidence/L25-cisco_nxos.pcap
git commit -m "$(cat <<'EOF'
test: re-measure the inert candidates beside readonly, and NX-OS's vsh.bin record (L23, L25)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
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

The projection's proof needs three questions of two rules, answered from their terms. The engine
already answers one direction ("does some command match both, with the permit dominating?":
`overrides`, from the shadowed-deny report). These export it and two more. `Contains` answers
only what it can decide. A regex or class term holds another only where it is the same term, and
`*` is held only by `*` or `**`. So a `false` never licenses anything. Dominance is read off term
ranks, which are the same on every command both rules match (spec §5.4), and `AlwaysDominates`
refuses wherever two patterns only possibly meet. The first version also exported
`NeverDominates`, which only the omitted-deny rule used; under the union model (Task 8) nothing
does, so it is not written.

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

- [ ] **Step 3: Add the three functions**

<!-- patch: internal/engine/contain.go -->
````diff
diff --git a/internal/engine/contain.go b/internal/engine/contain.go
new file mode 100644
index 0000000..313c888
--- /dev/null
+++ b/internal/engine/contain.go
@@ -0,0 +1,116 @@
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
EOF
)"
```

---

### Task 6: The adapter declares a session-only platform's projection, bits, carve-outs and templates

**Files:**
- Modify: `internal/platform/dialect.go` (the new fields, constants and methods)
- Modify: `internal/platform/adapter.go` (the Spec keys, `Over`, `SpecOf`, `validateProjection`,
  `MonotoneBits`)
- Modify: `internal/policy/load.go` (`keepsProjection`; `checkBlockOrder` reads `local_user_names`
  and `MonotoneBits`)
- Test: `internal/platform/projection_test.go` (new), `internal/platform/adapter_test.go`,
  `internal/policy/projection_test.go` (new; Tasks 9, 11, 12 and 18 append to it)

**Interfaces:**
- Consumes: `engine.ParseRule`, `engine.Class`, `engine.Regex`, Task 5's `engine.Contains`; 5a's
  `Spec.Over`, `SpecOf`, `Validate`, `keepsSetClaims`, `checkBlockOrder`.
- Produces:
  - `Dialect` fields `CommandProjection string`, `Bits map[string][]string`, `CarveOuts
    map[string][]string`, `BitDelivery string`, `LocalUserNames map[string]string`, and
    `CeilingBits map[string][]string` (the `privilege` key of a projected adapter).
  - Spec keys `command_projection`, `bits`, `carve_outs`, `bit_delivery`, `local_user_names`.
  - `const ProjectionJunosRegex = "junos_regex"`, `BitDeliveryUserPermissions = "user_permissions"`,
    `BitDeliveryLocalUserName = "local_user_name"`, `RemoteClass = "p49-remote"`,
    `BaselineBit = "baseline"`.
  - `func ProjectionAttributes(projection string) []string`, `func (Dialect) Projected() bool`,
    `func (Dialect) ProjectionOwns(name string) bool`, `func (Dialect) LevelBits(level string)
    ([]string, bool)`, and `func (Dialect) ExpandBits(bits []string) []string`, which reads `all`
    as every declared bit but `baseline`.
  - `func MonotoneBits(name string, d Dialect, order []string) error`.
  - In `internal/policy`'s tests: `projectedSet = "9.0.0"`, `projectedEnv(delivery string) Env`,
    `parseProjected(t, delivery, body string) *Policy`, `readonlyCarveOut`.

The projection's inputs become adapter data, validated as every adapter is. On a projected
platform, `privilege` is each level's ceiling in bits (Decided 2). Validate requires the following
of a projected adapter:
- `supports: [session]`, and no attribute levels;
- no `accepted_attributes`;
- every projection-owned name in `privilege_attributes`;
- a bit's reach made of words, `*` and `**` only;
- each carve-out named for a declared bit other than `baseline`, and held by that bit's own reach
  (`engine.Contains`): a carve-out outside the bit would subtract what the bit never reached;
- `baseline` never named in a level's ceiling, since every session holds it;
- a known `bit_delivery`;
- under `local_user_name`, a template per level, a login-name shape, and one class per template.

A projection key on a platform that projects nothing is refused: it would read as enforced.
`ProjectionOwns` answers for every name the projection renders, in any case and with any numeric
suffix (`allow-commands2`, `User-Permissions`; pre-flight I1), and every name the adapter lists as
bearing privilege; Task 9 refuses them as role and grant attributes. In the policy, a block over a
set that projects keeps the projection and every rule of each bit's reach, may add reach, which
the diff gates as a widening, and may drop a carve-out but never add one the set does not measure
(`keepsProjection`, pre-flight C1). A level's ceiling bits rise with `privilege_levels`
(`MonotoneBits`). Nothing renders yet. Task 9 wires the policy, and until Task 14 no built-in
adapter projects.

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
index 0000000..ca1d185
--- /dev/null
+++ b/internal/platform/projection_test.go
@@ -0,0 +1,153 @@
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
+			"clear": {"clear **"}, "all": {"**"}, BaselineBit: {"quit **", "set cli **"}},
+		CarveOuts: &map[string][]string{"view-configuration": {"show configuration **"}},
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
+		{"a carve-out of an undeclared bit", func(d *Dialect) { d.CarveOuts["trace"] = []string{"monitor **"} },
+			"carve_outs.trace"},
+		{"a carve-out the bit does not reach", func(d *Dialect) {
+			d.CarveOuts["view-configuration"] = []string{"show log **"}
+		}, "carve_outs.view-configuration[0]: the bit's own reach does not hold it"},
+		{"a carve-out of the baseline", func(d *Dialect) { d.CarveOuts[BaselineBit] = []string{"quit **"} },
+			"never to baseline"},
+		{"a level naming the baseline", func(d *Dialect) { d.CeilingBits["readonly"] = []string{"view", BaselineBit} },
+			"baseline is held by every session"},
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
+
+// A projected platform owns every name Junos reads as a class's template,
+// bits or regexes, numbered and in any case, and every name its adapter lists
+// as bearing privilege; a platform that projects nothing owns none.
+func TestProjectionOwns(t *testing.T) {
+	d := junosProjected(BitDeliveryUserPermissions)
+	for _, n := range []string{"allow-commands", "allow-commands2", "Deny-Commands1", "deny-configuration-regexps",
+		"user-permissions2", "LOCAL-USER-NAME", "allow-configuration"} {
+		if !d.ProjectionOwns(n) {
+			t.Errorf("%s is not owned", n)
+		}
+	}
+	for _, n := range []string{"home-directory", "allow-commandsx", "idletime"} {
+		if d.ProjectionOwns(n) {
+			t.Errorf("%s is owned", n)
+		}
+	}
+	eos, _ := DialectFor("arista_eos")
+	if eos.ProjectionOwns("allow-commands") {
+		t.Error("a platform that projects nothing owns nothing")
+	}
+}
````

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
new file mode 100644
index 0000000..5d206d1
--- /dev/null
+++ b/internal/policy/projection_test.go
@@ -0,0 +1,69 @@
+package policy
+
+import (
+	"strings"
+	"testing"
+
+	"github.com/blanketfish/port49/internal/platform"
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
+		CarveOuts: &map[string][]string{"view-configuration": {"show configuration **"}},
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
+		{"carve_outs: {view: [\"show log **\"]}", "a block may drop one, not add one"},
+	} {
+		_, err := Parse([]byte("platform_set: "+projectedSet+"\nplatforms:\n  juniper_junos:\n    "+c.block+"\n"+
+			readonlyCarveOut), projectedEnv(platform.BitDeliveryUserPermissions))
+		if err == nil || !strings.Contains(err.Error(), c.want) {
+			t.Errorf("%s: %v", c.block, err)
+		}
+	}
+	// Adding to a bit's reach loads, and so does dropping a carve-out: each
+	// claims the bits reach more. The diff gates both as adapter edits.
+	parseProjected(t, platform.BitDeliveryUserPermissions, "platforms:\n  juniper_junos:\n"+
+		"    bits: {view: [\"show **\", \"monitor **\"]}\n    carve_outs: {view-configuration: []}\n"+readonlyCarveOut)
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/`
Expected: FAIL, build failed: `unknown field CommandProjection in struct literal of type Spec`,
`undefined: ProjectionJunosRegex`, `undefined: ProjectionAttributes`, `undefined: BaselineBit`,
`unknown field CarveOuts in struct literal of type Spec`.

- [ ] **Step 3: Add the keys, their validation and the block floors**

<!-- patch: internal/platform/adapter.go -->
````diff
diff --git a/internal/platform/adapter.go b/internal/platform/adapter.go
index cf6b650..a074b72 100644
--- a/internal/platform/adapter.go
+++ b/internal/platform/adapter.go
@@ -45,6 +45,11 @@ type Spec struct {
 	FallbackNote         *map[string]string   `yaml:"fallback_note,omitempty"`
 	LocalAccounts        *[]string            `yaml:"local_accounts,omitempty"`
 	ConfigChecks         *[]ConfigCheck       `yaml:"config_checks,omitempty"`
+	CommandProjection    *string              `yaml:"command_projection,omitempty"`
+	Bits                 *map[string][]string `yaml:"bits,omitempty"`
+	CarveOuts            *map[string][]string `yaml:"carve_outs,omitempty"`
+	BitDelivery          *string              `yaml:"bit_delivery,omitempty"`
+	LocalUserNames       *map[string]string   `yaml:"local_user_names,omitempty"`
 }
 
 // ParseSpecs reads an adapter file: one YAML document whose one key is
@@ -80,9 +85,33 @@ func (s Spec) Over(base Dialect) Dialect {
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
+	if s.CarveOuts != nil {
+		d.CarveOuts = mergeLists(d.CarveOuts, *s.CarveOuts)
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
@@ -455,6 +484,9 @@ func Validate(name string, d Dialect) error {
 				field("config_checks"), i)
 		}
 	}
+	if err := validateProjection(field, d); err != nil {
+		return err
+	}
 	if !slices.Contains(verifications, d.Verified) {
 		return fmt.Errorf("%s is not containerlab, community, or unset", field("verified"))
 	}
@@ -639,6 +671,25 @@ func SpecOf(d Dialect) Spec {
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
+	if d.CarveOuts != nil {
+		s.CarveOuts = &d.CarveOuts
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
@@ -699,3 +750,175 @@ func SpecKeys() []string {
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
+		}{{"bits", d.Bits != nil}, {"carve_outs", d.CarveOuts != nil}, {"bit_delivery", d.BitDelivery != ""},
+			{"local_user_names", d.LocalUserNames != nil}} {
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
+	for _, bit := range sortedKeys(d.CarveOuts) {
+		if _, ok := d.Bits[bit]; !ok || bit == BaselineBit {
+			return fmt.Errorf("%s.%s: a carve-out belongs to a bit under bits, never to %s", field("carve_outs"), bit,
+				BaselineBit)
+		}
+		for i, rule := range d.CarveOuts[bit] {
+			// Only commands the bit itself reaches can be the bit's alone.
+			held := slices.ContainsFunc(d.Bits[bit], func(r string) bool {
+				ok, err := engine.Contains(r, rule, nil)
+				return err == nil && ok
+			})
+			if !held {
+				return fmt.Errorf("%s[%d]: the bit's own reach does not hold it", field("carve_outs."+bit), i)
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
+			if bit == BaselineBit {
+				return fmt.Errorf("%s[%d]: %s is held by every session, so no level names it", field("privilege."+level),
+					i, bit)
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
index d0a6256..dec8bec 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -2,6 +2,7 @@ package platform
 
 import (
 	"maps"
+	"regexp"
 	"slices"
 	"strings"
 
@@ -146,6 +147,115 @@ type Dialect struct {
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
+	// upper bound measured in the lab (spec §15, L12). A session's reach is
+	// the union of its bits' (Junos permissions are a union), save what
+	// CarveOuts removes. A reach that says less than the bit does would let
+	// the device run what port49 denies, so a block may add to a bit's reach,
+	// a gated edit, and never take from it (spec §8). The bit named
+	// BaselineBit is what a class with no bits runs: every session holds it.
+	Bits map[string][]string
+	// CarveOuts maps a bit to the commands that only it makes available,
+	// whatever other bit's reach holds them: `view-configuration`'s `show
+	// configuration **`, which `view` alone does not show (L12). Only a
+	// measured carve-out is listed; a block may drop one and never add one,
+	// since a carve-out says the held bits reach less (spec §8).
+	CarveOuts map[string][]string
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
+// BaselineBit names, in Bits, what a class with no bits runs: held by every
+// session on the platform, and never in a level's ceiling (spec §8).
+const BaselineBit = "baseline"
+
+// projectionOwned is every attribute a projection's platform reads as a
+// login class's template, bits or command or configuration regex, numbered
+// variants included (`allow-commands2`, `user-permissions1`), in any case:
+// what a role or grant may not set there (spec §8, "Generator constraints").
+var projectionOwned = regexp.MustCompile(
+	`(?i)^((allow|deny)-(commands|configuration)(-regexps)?|user-permissions|local-user-name)[0-9]*$`)
+
+// ProjectionOwns reports whether an attribute name is one a projected
+// platform reads as a class's template, bits or regexes, or one its adapter
+// lists as bearing privilege: no role or grant sets it there.
+func (d Dialect) ProjectionOwns(name string) bool {
+	return d.Projected() && (projectionOwned.MatchString(name) || ContainsName(d.PrivilegeAttributes, name))
+}
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
+		// The baseline is held by every session and never delivered.
+		bits = slices.DeleteFunc(sortedKeys(d.Bits), func(b string) bool { return b == BaselineBit })
+	}
+	out := slices.Clone(bits)
+	slices.Sort(out)
+	return slices.Compact(out)
 }
 
 // ConfigCheck is one line a device's configuration must not carry: an RE2
@@ -269,9 +379,27 @@ func (d Dialect) clone() Dialect {
 	}
 	d.LocalAccounts = slices.Clone(d.LocalAccounts)
 	d.ConfigChecks = slices.Clone(d.ConfigChecks)
+	d.Bits = cloneLists(d.Bits)
+	d.CarveOuts = cloneLists(d.CarveOuts)
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
index 28c6729..2c4faec 100644
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
@@ -531,6 +534,48 @@ func keepsSetClaims(at, shippedAs string, d, ref platform.Dialect, version strin
 	return nil
 }
 
+// keepsProjection refuses a merged adapter that loosens what the set's
+// projection rests on (spec §8): a projected platform stays projected by the
+// set's projection, since without it the device's own template decides and
+// no rule reaches the session; a bit's reach is a floor, since a reach that
+// says less than the bit does lets the device run what port49 denies; and a
+// carve-out is a ceiling, since one says the held bits reach less. A block may
+// add to a bit's reach, an edit the diff gates like any adapter edit, drop a
+// carve-out, and may not declare a bit the set did not measure.
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
+	for _, bit := range sortedKeys(d.CarveOuts) {
+		for _, rule := range d.CarveOuts[bit] {
+			if !slices.Contains(ref.CarveOuts[bit], rule) {
+				return fmt.Errorf("%s.carve_outs.%s: platform set %s does not measure this carve-out on %s; a carve-out "+
+					"says the held bits reach less, so a block may drop one, not add one (spec §8, §15 L12)", at, bit,
+					version, shippedAs)
+			}
+		}
+	}
+	return nil
+}
+
 // keepsRoleOrder refuses a merged adapter that ranks two values of a role
 // attribute the other way round from the set's adapter it stands for: the
 // diff gate reads a move down role_order as a lowering (spec §12), so a
@@ -720,7 +765,8 @@ func (p *Policy) checkBlockOrder(file) error {
 			key    string
 			levels []string
 		}{{"privilege", mapKeys(b.Privilege)}, {"ceiling_levels", mapKeys(b.CeilingLevels)},
-			{"unreachable", mapKeys(b.Unreachable)}, {"fallback", mapKeys(b.Fallback)}} {
+			{"unreachable", mapKeys(b.Unreachable)}, {"fallback", mapKeys(b.Fallback)},
+			{"local_user_names", mapKeys(b.LocalUserNames)}} {
 			for _, l := range entries.levels {
 				if !slices.Contains(p.levels, l) {
 					return fmt.Errorf("platforms.%s.%s.%s: level %s is not declared; the levels are %s", name,
@@ -731,6 +777,9 @@ func (p *Policy) checkBlockOrder(file) error {
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
EOF
)"
```

---

### Task 7: A rule written as the Junos regex that matches what it matches, a deny widest

**Files:**
- Create: `internal/projection/ere.go` (the package's doc comment, `Facts`, `pipeTail`, `ruleERE`,
  `patternERE`, `bracket`)
- Test: `internal/projection/ere_test.go`

**Interfaces:**
- Consumes: `engine.ParseRule` and its term kinds; `regexp/syntax`.
- Produces, for Task 8:
  - `type Facts struct{ CaseSensitive, DenyMatchesExpanded bool }`;
  - `func ruleERE(rule string, classes map[string][]string, deny bool, f Facts) (string, error)`, a
    rule as an unanchored extended regex over a whole command line, a deny ending in `pipeTail`;
  - `var errUnwritable`.

A rule becomes an ERE over the command line, and every choice is the one that fails closed on its
side. **An allow is as narrow as the rule:** lower case, one space between words, `*` as `[^ ]+`,
a pattern's position with no space. **A deny is as wide:** each letter in both cases where the
device is case-sensitive, ` +` between words, `*` as `.+` and a pattern's surrounding and `.` able
to hold a space, since a quoted argument does and the engine never splits it (pre-flight M2), and
the **pipe tail** `( *\|.*)?` after it (pre-flight I2). The engine strips a pipeline before
matching, so port49 denies `clear bgp all | no-more` under `deny clear bgp all`; a deny anchored at
its last word would miss that line on a device that matches the whole line. The tail only makes a
deny match more, so it is right whatever Task 2 measures. A trailing `**` is `( .*)?`.

A word is printable ASCII with ERE's operators escaped. A word holding `{`, `}`, `"` or `\` is
refused, since a brace pair reads as a spec §6 placeholder, and the wire's handling of a quote or a
backslash is unmeasured. A regex or class pattern is read as the matcher reads it,
case-insensitive and unanchored unless it anchors, and carried only in the subset that reads the
same in POSIX ERE: literals, bracket expressions (POSIX's `]`-first, `-`-last rules, runs as
ranges; a deny's class that also admits a space, a rune past ASCII or a rune the reply cannot
carry is `.`), grouping, alternation, `*`, `+`, `?`, a repeat of at most 8 written out, and
anchors at its two ends. An empty group or alternative, which POSIX leaves undefined, is refused
(pre-flight M1). The tests check the EREs with Go's regexp, which reads this subset the same way.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/projection/ere_test.go -->
````diff
diff --git a/internal/projection/ere_test.go b/internal/projection/ere_test.go
new file mode 100644
index 0000000..55883b0
--- /dev/null
+++ b/internal/projection/ere_test.go
@@ -0,0 +1,99 @@
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
+		{"show version", true, `[sS][hH][oO][wW] +[vV][eE][rR][sS][iI][oO][nN]( *\|.*)?`},
+		{"SHOW Version", false, "show version"},
+		{"show interfaces **", false, "show interfaces( .*)?"},
+		{"**", false, ".*"},
+		{"show route *", false, "show route [^ ]+"},
+		{"show route *", true, `[sS][hH][oO][wW] +[rR][oO][uU][tT][eE] +.+( *\|.*)?`},
+		{"file show /var/log/messages", false, `file show /var/log/messages`},
+		{"ping 10.0.0.1", false, `ping 10\.0\.0\.1`},
+		{"show interfaces @management", false, "show interfaces ((fxp0|em0))"},
+		{"show interfaces @uplink **", false, "show interfaces ((et-0/0/[0-3])|(ae1))( .*)?"},
+		{"show interfaces /^ge-/", false, "show interfaces (ge-)[^ ]*"},
+		{"show interfaces /ge-/", true, `[sS][hH][oO][wW] +[iI][nN][tT][eE][rR][fF][aA][cC][eE][sS] +.*([gG][eE]-).*( *\|.*)?`},
+	} {
+		got, err := ruleERE(c.rule, classes, c.deny, folded)
+		if err != nil || got != c.want {
+			t.Errorf("ruleERE(%q, deny=%v) = %q, %v; want %q", c.rule, c.deny, got, err, c.want)
+		}
+	}
+	for _, rule := range []string{"echo {username}", `show "x"`, "show /\\bword/", "show café",
+		"show /^(ge|)$/", "show /^()$/", "show /^$/"} {
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
+
+// A deny matches every line port49 denies under its rule, in every spelling
+// the device may be handed: a pipeline after it, a run of spaces between
+// words, and a quoted argument that holds a space. An allow matches only the
+// rule's own narrow shape.
+func TestADenyEREIsWideAndAnAllowNarrow(t *testing.T) {
+	for _, c := range []struct {
+		rule  string
+		deny  bool
+		lines map[string]bool
+	}{
+		{"clear bgp all", true, map[string]bool{"clear bgp all": true, "clear bgp all | no-more": true,
+			"clear bgp all|count": true, "clear  bgp all": true, "clear bgp all x": false}},
+		{"show route *", true, map[string]bool{`show route "a b"`: true, "show route": false}},
+		{"show interfaces @spaced", true, map[string]bool{"show interfaces ge 0": true}},
+		{"show interfaces /^[a-z{]+$/", true, map[string]bool{"show interfaces a{b": true}},
+		{"show route *", false, map[string]bool{"show route x": true, `show route "a b"`: false,
+			"show route x | no-more": false, "show  route x": false}},
+	} {
+		e, err := ruleERE(c.rule, map[string][]string{"spaced": {"^[a-z ]+$"}}, c.deny, Facts{CaseSensitive: true})
+		if err != nil {
+			t.Fatalf("%s: %v", c.rule, err)
+		}
+		re := regexp.MustCompile("^" + e + "$")
+		for line, want := range c.lines {
+			if re.MatchString(line) != want {
+				t.Errorf("%s (deny=%v) against %q: %v", c.rule, c.deny, line, !want)
+			}
+		}
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/projection/`
Expected: FAIL, build failed: `undefined: Facts`, `undefined: ruleERE`.

- [ ] **Step 3: Add the translation**

<!-- patch: internal/projection/ere.go -->
````diff
diff --git a/internal/projection/ere.go b/internal/projection/ere.go
new file mode 100644
index 0000000..71172ef
--- /dev/null
+++ b/internal/projection/ere.go
@@ -0,0 +1,343 @@
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
+	"github.com/blanketfish/port49/internal/engine"
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
+// pipeTail ends every deny: the engine matches a command with its pipeline
+// stripped, so port49 denies `clear bgp all | no-more` under a deny of
+// `clear bgp all`, and a deny anchored at the rule's last word would miss
+// that line on a device that matches the whole line. Whether Junos strips
+// the pipeline first is L9's pipe probe; the tail is right either way, since
+// it only makes a deny match more.
+const pipeTail = `( *\|.*)?`
+
+// ruleERE is one rule as an extended regex over a whole command line, without
+// anchors: `show interfaces **` is `show interfaces( .*)?`. deny says which
+// side of the reply it lands on, and every choice below is the one that fails
+// closed on that side. An allow is as narrow as the rule: lower case, one
+// space between words, and no space inside an argument. A deny is as wide:
+// every case where the device matches case-sensitively, any run of spaces
+// between words, an argument that may hold a space (a quoted one does, and
+// the engine never splits it), and the pipe tail.
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
+			b.WriteString(pick(deny, " +", " "))
+		}
+		switch t.Kind {
+		case engine.Any:
+			b.WriteString(pick(deny, ".+", "[^ ]+"))
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
+	if deny {
+		b.WriteString(pipeTail)
+	}
+	return b.String(), nil
+}
+
+func pick(deny bool, ifDeny, ifAllow string) string {
+	if deny {
+		return ifDeny
+	}
+	return ifAllow
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
+// argument. It takes literals, bracket
+// expressions, `.`, grouping, alternation, `*`, `+`, `?`, a bounded repeat
+// written out, and anchors at the pattern's two ends; anything else refuses
+// the pattern rather than guessing at the device's dialect (spec §8,
+// "Anchoring is a per-platform property"; §15 L9). So does anything that
+// would write an empty group, `()` or `(ge|)`, which POSIX leaves undefined.
+func patternERE(pattern string, deny bool, f Facts) (string, error) {
+	re, err := syntax.Parse("(?i)"+pattern, syntax.Perl)
+	if err != nil {
+		return "", err
+	}
+	re = re.Simplify()
+	lead, trail := pick(deny, ".*", "[^ ]*"), pick(deny, ".*", "[^ ]*")
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
+	if body == "" {
+		return "", fmt.Errorf("%w: the pattern matches only the empty argument", errUnwritable)
+	}
+	return lead + "(" + body + ")" + trail, nil
+}
+
+func ere(re *syntax.Regexp, deny bool, f Facts) (string, error) {
+	switch re.Op {
+	case syntax.OpEmptyMatch:
+		return "", fmt.Errorf("%w: an empty alternative or group", errUnwritable)
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
+		return pick(deny, ".", "[^ ]"), nil
+	case syntax.OpCapture:
+		s, err := ere(re.Sub[0], deny, f)
+		if err == nil && s == "" {
+			err = fmt.Errorf("%w: an empty group", errUnwritable)
+		}
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
+// ASCII less the space. A class that also admits a space, a rune past ASCII or
+// a rune the reply cannot carry is `.` in a deny, which matches more, and
+// loses that rune in an allow, which matches less: each the side that fails
+// closed.
+func bracket(ranges []rune, deny bool) (string, error) {
+	in := func(r rune) bool {
+		for i := 0; i+1 < len(ranges); i += 2 {
+			if ranges[i] <= r && r <= ranges[i+1] {
+				return true
+			}
+		}
+		return false
+	}
+	beyond := in(' ') || in('{') || in('}') || in('"') || in('\\')
+	for i := 0; i+1 < len(ranges); i += 2 {
+		if ranges[i+1] > 0x7e || ranges[i] < 0x21 {
+			beyond = true
+		}
+	}
+	if deny && beyond {
+		return ".", nil
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
feat: a composed rule as the extended regex a Junos class reads

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: The Junos projection, proven before it is sent, or the fail-closed reply (decisions 22 and 26)

**Files:**
- Create: `internal/projection/project.go`, `internal/projection/model.go`
- Test: `internal/projection/project_test.go`

**Interfaces:**
- Consumes: Task 5's `engine.Contains`, `MayMeet`, `AlwaysDominates`; Task 6's `Dialect.Bits`,
  `CarveOuts`, `ExpandBits`, `BitDelivery`, `platform.BaselineBit`, `platform.RemoteClass`; Task 7's
  `ruleERE`, `Facts`; `engine.Compile`, `engine.Probes`, `engine.CheckAttribute`,
  `engine.MaxAttribute`.
- Produces, for Tasks 9–12 and 19:
  - `const ShapeCapability = "capability"`, `ShapeNarrow = "narrow"`, `ShapeFailClosed =
    "fail_closed"`;
  - `const FailRefusedShape, FailConfigurationMode, FailOverflow, FailUnwritable, FailSecretRule,
    FailUnsound` (`refused_shape`, `configuration_mode`, `overflow`, `unwritable`, `secret_rule`,
    `unsound`);
  - `var JunosFacts = Facts{CaseSensitive: true, DenyMatchesExpanded: false}` and `func
    FactsFor(projection string) Facts`;
  - `type Input struct{ Platform string; Dialect platform.Dialect; Level string; Bits []string;
    Template string; Rules []engine.Rule; Classes map[string][]string; Normalize engine.Normalize;
    Secret func(rule string) bool; Facts Facts }`;
  - `type Result struct{ Shape string; Bits []string; Template string; Attributes []string; Denies,
    Allows, Omitted, Beyond []engine.Rule; ConfigurationDropped []string; FailClosed string;
    Refusal *Refusal }`, with `(Result).Device(vector []string) bool` and `(Result).Narrower(max
    int) [][]string`;
  - `type Refusal struct{ Category, Why, Attribute, Value, Class string }` (an error, never
    returned: it rides on `Result.Refusal`);
  - `func Project(in Input) (Result, error)`, whose error is a defect only (a program that does
    not compile).

`Project` renders one composition and proves it (Decided 3, 4 and 7).

- **The device model** (`model.go`) is the union of pre-flight C1's fix: a command runs where an
  allow matches; otherwise not where a deny matches; otherwise where some held bit's reach holds
  it, `baseline` included, and no carve-out of a bit not held does. The reach and carve-out
  programs match as port49 matches a deny, the widest reading, because the device's parser
  applies them to a command whatever its spacing, case or abbreviation. The witness skips a probe
  vector with a word the parser never sees (empty, or padded with a space), whose trimmed form is
  probed in its own right.
- **The baseline.** Each baseline reach rule no permit or deny holds becomes a deny of role
  `baseline`, so the wire refuses what every session could otherwise run.
- **Capability shape.**
  - Under `user_permissions`, the bits are the ceiling's usable bits, less those a deny aligns
    with; `all` is sent alone.
  - Under `local_user_name`, the template's class carries every ceiling bit, so each must be
    usable.
  - A permit is sent as an allow only where the bits do not carry it, or where it dominates a
    deny, and then only within the ceiling (`within`, carve-outs counted) and only where it
    dominates every deny it meets (`allowable`). Otherwise the composition is the refused shape.
  - A deny is `Omitted` only where a carve-out of a bit not sent holds it and no allow meets it.
  - With a deny left to send and a device that may not expand abbreviations, the shape goes
    narrow.
- **Narrow shape.** `deny-commands=^.*$` and one allow alternation of the permits within the
  ceiling. Under `user_permissions` it takes the smallest set of ceiling bits that reach them,
  preferring bits that do not enter configuration mode, then name order (`cover`, pre-flight
  I11); under `local_user_name`, the template's.
- **Guards.** Bits that enter configuration mode, or an allow meeting `configure`, go only to a
  grant of everything with no deny. Under `user_permissions` a composition refused for that is
  rendered again without those bits, and sent that way if it is sound (`ConfigurationDropped`;
  Decided 6). A rule redaction would hide refuses the composition. Every attribute is mandatory
  and within 255 bytes; past that the refusal carries the attribute, its value, and, for
  `deny-commands` only, the class that would hold it (pre-flight C2).
- **The fail-closed reply** (`failClosed`, decision 26) answers every refusal and every witness
  failure: `deny-commands=^.*$`, the allows the generator proves over the ceiling's bits that do
  not enter configuration mode, the smallest of those bits under `user_permissions`, and no
  template. Where the allows cannot go out whole, none does. It is proven with the same model.

The tests are spec §8's own examples and the review's reproductions: the realistic readonly
drops `view-configuration` and sends `user-permissions=view`; `read_only_limited` is `deny .*` plus
one alternation; the refused shape gets the fail-closed reply under both deliveries, keeping `show
version`; a bit outside the ceiling claiming `show log **` removes nothing (C1); the baseline is
denied; a narrow admin grant takes `network view`, not `all` (I11); an admin with a deny drops
`all` and `configure` under `user_permissions` and fails closed under `local_user_name`; and an
allow past the budget prints no class line (C2).

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/projection/project_test.go -->
````diff
diff --git a/internal/projection/project_test.go b/internal/projection/project_test.go
new file mode 100644
index 0000000..c482916
--- /dev/null
+++ b/internal/projection/project_test.go
@@ -0,0 +1,318 @@
+package projection
+
+import (
+	"fmt"
+	"reflect"
+	"strings"
+	"testing"
+
+	"github.com/blanketfish/port49/internal/engine"
+	"github.com/blanketfish/port49/internal/platform"
+)
+
+// junos is a projected Junos adapter as the tests read one: spec §8's bits,
+// view-configuration's measured carve-out, and the levels' ceilings.
+func junos(delivery string) platform.Dialect {
+	d := platform.Dialect{Supports: []string{"session"}, PipeToken: "|", StripCR: true,
+		CommandProjection: platform.ProjectionJunosRegex, BitDelivery: delivery,
+		Bits: map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
+			"clear": {"clear **"}, "network": {"ping **", "traceroute **"}, "configure": {"configure **"},
+			"all": {"**"}},
+		CarveOuts: map[string][]string{"view-configuration": {"show configuration **"}},
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
+		`deny-commands=^ *[sS][hH][oO][wW] +[cC][oO][nN][fF][iI][gG][uU][rR][aA][tT][iI][oO][nN]( .*)? *(\|.*)?$`}
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
+// The refused shape gets the fail-closed reply, which names the two rules
+// and the platform for CI: deny everything, and no allow, since the one
+// permit meets the deny beneath it (decision 26).
+func TestTheRefusedShapeFailsClosed(t *testing.T) {
+	for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
+		res, err := Project(input(delivery, "readonly", measured,
+			permit("show interfaces **"), deny("show interfaces terse"), permit("show version")))
+		if err != nil {
+			t.Fatal(err)
+		}
+		r := res.Refusal
+		if res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape || r == nil ||
+			!strings.Contains(r.Why, `permit "show interfaces **"`) ||
+			!strings.Contains(r.Why, `deny "show interfaces terse"`) || !strings.Contains(r.Why, "juniper_junos") {
+			t.Fatalf("%s: %+v", delivery, res)
+		}
+		// show version is proven and goes out; the template never does, so the
+		// session lands in the bitless p49-remote.
+		want := []string{"deny-commands=^.*$", "allow-commands=^show version$"}
+		if delivery == platform.BitDeliveryUserPermissions {
+			want = append([]string{"user-permissions=view"}, want...)
+		}
+		if !reflect.DeepEqual(res.Attributes, want) || len(res.Beyond) != 1 {
+			t.Errorf("%s: %q, beyond %v", delivery, res.Attributes, res.Beyond)
+		}
+		if res.Device([]string{"show", "interfaces", "terse"}) || res.Device([]string{"show", "interfaces", "em0"}) {
+			t.Errorf("%s: the fail-closed reply runs a command it did not prove", delivery)
+		}
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
+	// statement there is no command the regexes reach. Under user_permissions
+	// those bits are dropped and the rest is proven (decision 26): the admin
+	// keeps every operational command the other bits reach, less the deny.
+	res, err = Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**"),
+		deny("request system reboot **")))
+	if err != nil || res.Shape != ShapeCapability ||
+		!reflect.DeepEqual(res.ConfigurationDropped, []string{"all", "configure"}) ||
+		res.Attributes[0] != "user-permissions=clear network view view-configuration" {
+		t.Fatalf("%+v %v", res, err)
+	}
+	if res.Device([]string{"configure"}) || !res.Device([]string{"show", "configuration"}) {
+		t.Error("device model")
+	}
+	// Under local_user_name the template's class carries the level's bits
+	// whole, so there is nothing to drop: the fail-closed reply.
+	res, err = Project(input(platform.BitDeliveryLocalUserName, "admin", measured, permit("**"),
+		deny("request system reboot **")))
+	if err != nil || res.FailClosed != FailConfigurationMode ||
+		!reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$"}) ||
+		!strings.Contains(res.Refusal.Why, "enters configuration mode") {
+		t.Fatalf("%+v %v", res, err)
+	}
+}
+
+// A narrow admin grant takes the smallest bits that reach its permits, not
+// all, which would enter configuration mode and be refused (I11).
+func TestANarrowAdminTakesTheSmallestBits(t *testing.T) {
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("show version"),
+		permit("ping **")))
+	want := []string{"user-permissions=network view", "deny-commands=^.*$",
+		"allow-commands=^(show version|ping( .*)?)$"}
+	if err != nil || res.Shape != ShapeNarrow || !reflect.DeepEqual(res.Attributes, want) {
+		t.Fatalf("%s %q %v", res.Shape, res.Attributes, err)
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
+	// the operator's shape is refused: clear ** would beat clear bgp **. The
+	// subject keeps what is proven: show and ping, not clear.
+	res, err = Project(input(platform.BitDeliveryUserPermissions, "operator", Facts{CaseSensitive: true}, rules...))
+	want := []string{"user-permissions=network view", "deny-commands=^.*$", "allow-commands=^(show( .*)?|ping( .*)?)$"}
+	if err != nil || res.FailClosed != FailRefusedShape || !reflect.DeepEqual(res.Attributes, want) {
+		t.Fatalf("%q %v", res.Attributes, err)
+	}
+	if res.Device([]string{"clear", "bgp", "neighbor"}) || res.Device([]string{"clear", "arp"}) {
+		t.Error("the fail-closed reply runs clear")
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
+	if res, err := Project(in); err != nil || res.FailClosed != FailSecretRule ||
+		!strings.Contains(res.Refusal.Why, "redaction hides") ||
+		!reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$"}) {
+		t.Fatalf("secret: %+v %v", res, err)
+	}
+	var rules []engine.Rule
+	rules = append(rules, permit("show **"))
+	for _, w := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"} {
+		rules = append(rules, deny("show "+w+" **"))
+	}
+	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, rules...))
+	r := res.Refusal
+	if err != nil || res.FailClosed != FailOverflow || r.Attribute != "deny-commands" ||
+		!strings.HasPrefix(r.Value, "^(") || r.Class != platform.RemoteClass {
+		t.Fatalf("over budget: %+v %v", res, err)
+	}
+	// An allow past the budget is never moved into a class, where it would
+	// run for every subject past their own denies (C2): no class line.
+	rules = nil
+	for i := range 16 {
+		rules = append(rules, permit(fmt.Sprintf("show interfaces ge-0/0/%d extensive", i)))
+	}
+	res, err = Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, rules...))
+	if r := res.Refusal; err != nil || res.FailClosed != FailOverflow || r.Attribute != "allow-commands" ||
+		r.Class != "" || !strings.Contains(r.Why, "narrow the grant") {
+		t.Fatalf("allow over budget: %+v %v", res, err)
+	}
+	// The allows cannot go out whole, so none does.
+	if !reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$"}) || len(res.Beyond) != 16 {
+		t.Errorf("%q", res.Attributes)
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
+
+// A bit's reach is a union (C1): a bit not held never takes a command out of
+// one that is, so a deny under a held bit's reach is sent, whatever reach a
+// bit outside the ceiling claims. Only a measured carve-out licenses leaving
+// a deny off the wire.
+func TestAnUnheldBitRemovesNothing(t *testing.T) {
+	in := input(platform.BitDeliveryLocalUserName, "readonly", measured, permit("show **"), deny("show log **"))
+	in.Dialect.Bits["trace"] = []string{"monitor **", "show log **"}
+	res, err := Project(in)
+	if err != nil || len(res.Omitted) != 0 || len(res.Denies) != 1 || res.Denies[0].Rule != "show log **" {
+		t.Fatalf("%+v %v", res, err)
+	}
+	if res.Device([]string{"show", "log", "messages"}) {
+		t.Error("the device runs a command port49 denies")
+	}
+}
+
+// The baseline runs its commands for every session, so each no permit holds
+// is denied on the wire (I3), and a bit never drops it.
+func TestTheBaselineIsDenied(t *testing.T) {
+	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"))
+	in.Dialect.Bits[platform.BaselineBit] = []string{"quit **", "show cli **"}
+	res, err := Project(in)
+	if err != nil || res.Shape != ShapeCapability || len(res.Denies) != 1 ||
+		res.Denies[0].Rule != "quit **" || res.Denies[0].Role != platform.BaselineBit {
+		t.Fatalf("%+v %v", res, err)
+	}
+	if res.Device([]string{"quit"}) || !res.Device([]string{"show", "cli"}) {
+		t.Error("device model")
+	}
+	// Where a deny may be walked past, the baseline's deny sends the grant
+	// narrow, and .* holds it.
+	in.Facts = Facts{CaseSensitive: true}
+	res, err = Project(in)
+	if err != nil || res.Shape != ShapeNarrow || res.Device([]string{"quit"}) {
+		t.Fatalf("%+v %v", res, err)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/projection/`
Expected: FAIL, build failed: `undefined: Input`, `undefined: Project`, `undefined: ShapeCapability`,
`undefined: ShapeNarrow`.

- [ ] **Step 3: Add the generator and the device model**

<!-- patch: internal/projection/model.go -->
````diff
diff --git a/internal/projection/model.go b/internal/projection/model.go
new file mode 100644
index 0000000..d53e729
--- /dev/null
+++ b/internal/projection/model.go
@@ -0,0 +1,137 @@
+package projection
+
+import (
+	"slices"
+	"strings"
+
+	"github.com/blanketfish/port49/internal/engine"
+)
+
+// model is the device's decision under a reply, as spec §8 measured it: a
+// command runs where a matching allow beats every deny, or where the bits
+// reach it and no deny matches (L11). The bits are a union: a command runs
+// where any held bit's reach holds it, the baseline always held, unless a
+// measured carve-out of a bit not held takes it out (carve_outs). Nothing
+// else subtracts: a bit not held never removes a command another bit reaches.
+// Each part is an engine program over the same rules the reply's regexes were
+// written from, so the check below reads the reply exactly as the translation
+// promises the device reads it. The bits' reach and carve-outs are applied by
+// the device's command parser, which reads a command whatever its spacing,
+// case or abbreviation, so both are matched as port49 matches a deny: the
+// widest reading, which for the reach errs toward the device running more.
+type model struct {
+	port, allow, deny, reach, carve *engine.Program
+}
+
+func (g generator) model(res Result) (*model, error) {
+	prog := func(rules []engine.Rule) (*engine.Program, error) {
+		return engine.Compile(engine.Blob{Version: engine.Version, Bundle: "projection", Platform: g.in.Platform,
+			Normalize: g.in.Normalize, Rules: rules, Classes: g.in.Classes, Pipe: []string{}})
+	}
+	parsed := func(rules []string, role string) []engine.Rule {
+		out := make([]engine.Rule, len(rules))
+		for i, r := range rules {
+			out[i] = engine.Rule{Verdict: engine.Deny, Rule: r, Role: role}
+		}
+		return out
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
+	if res.Shape != ShapeCapability {
+		denies = []engine.Rule{{Verdict: engine.Deny, Rule: "**", Role: "projection"}}
+	}
+	if m.deny, err = prog(denies); err != nil {
+		return nil, err
+	}
+	held := g.held(res.Bits)
+	if m.reach, err = prog(parsed(g.reach(held), "reach")); err != nil {
+		return nil, err
+	}
+	if m.carve, err = prog(parsed(g.carves(held), "carve")); err != nil {
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
+	if len(m.deny.Command(r).Denies) > 0 {
+		return false
+	}
+	return len(m.reach.Command(r).Denies) > 0 && len(m.carve.Command(r).Denies) == 0
+}
+
+// probes is one vector per way the rules can be told apart (engine.Probes),
+// less those with a word the device's parser never sees: empty, or with a
+// space at either end. The parser splits a line on whitespace, so such a
+// vector is its trimmed form, which is probed in its own right.
+func (m *model) probes() [][]string {
+	return slices.DeleteFunc(engine.Probes(m.port, m.allow, m.deny, m.reach, m.carve), func(v []string) bool {
+		return slices.ContainsFunc(v, func(w string) bool { return w == "" || strings.TrimSpace(w) != w })
+	})
+}
+
+// unsound is a command the device would run and port49 would deny, among one
+// vector per way the rules can be told apart (engine.Probes).
+func (m *model) unsound() ([]string, bool) {
+	for _, v := range m.probes() {
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
+	for _, v := range r.model.probes() {
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
index 0000000..3beb309
--- /dev/null
+++ b/internal/projection/project.go
@@ -0,0 +1,795 @@
+package projection
+
+import (
+	"errors"
+	"fmt"
+	"math/bits"
+	"slices"
+	"strings"
+
+	"github.com/blanketfish/port49/internal/engine"
+	"github.com/blanketfish/port49/internal/platform"
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
+	// ShapeFailClosed is the reply a composition gets when neither shape can
+	// carry it faithfully (spec §13 decision 26): `deny-commands` `.*`, only
+	// the allows the generator proves, and no bit that enters configuration
+	// mode; no template. The subject is told less than port49 would permit,
+	// every other subject on the device is unaffected, and `policy test` and
+	// `policy diff` fail on it.
+	ShapeFailClosed = "fail_closed"
+)
+
+// Why a composition got the fail-closed reply: Result.FailClosed.
+const (
+	FailRefusedShape      = "refused_shape"
+	FailConfigurationMode = "configuration_mode"
+	FailOverflow          = "overflow"
+	FailUnwritable        = "unwritable"
+	FailSecretRule        = "secret_rule"
+	FailUnsound           = "unsound"
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
+	// Denies are sent in deny-commands; none outside ShapeCapability. One
+	// whose Role is platform.BaselineBit is not the grant's: it holds a
+	// command the baseline runs for every session and no permit holds.
+	Denies []engine.Rule
+	Allows []engine.Rule // sent in allow-commands
+	// Omitted are denies the bits already refuse, sent as nothing: a measured
+	// carve-out of a bit not sent holds each.
+	Omitted []engine.Rule
+	// Beyond are permits no reply sends: beyond the level's ceiling, or, in
+	// the fail-closed reply, not proven. The device refuses what port49 would
+	// permit there, never the reverse (spec §8, "never exceeding the level's
+	// ceiling").
+	Beyond []engine.Rule
+	// ConfigurationDropped are the level's bits that enter configuration
+	// mode, left out because the composition is not a grant of every command
+	// with no deny and the rest proved sound without them (decision 26).
+	ConfigurationDropped []string
+	// FailClosed is why the reply is ShapeFailClosed, one of the Fail*
+	// constants; empty otherwise. Refusal says it for the report.
+	FailClosed string
+	Refusal    *Refusal
+	model      *model
+}
+
+// Refusal is why a composition cannot be told faithfully, named for `policy
+// test` and `policy diff` (spec §8, "Refused shape"; "Generator constraints"
+// 5). It never leaves the generator as an error: the composition gets the
+// fail-closed reply (decision 26).
+type Refusal struct {
+	Category string
+	Why      string
+	// Attribute and Value are the reply attribute past RFC 8907's length,
+	// where that is the refusal. Class is the login class that would carry
+	// the value on the device instead, the workaround the report prints
+	// beside it (spec §8, "CI MUST report when a grant crosses that line"),
+	// and is set only for deny-commands: a class allow-commands runs for
+	// every session in the class, past each subject's own denies (L11), so
+	// an allow is never moved there.
+	Attribute, Value, Class string
+}
+
+func (r *Refusal) Error() string { return r.Why }
+
+func refuse(category, format string, args ...any) error {
+	return &Refusal{Category: category, Why: fmt.Sprintf(format, args...)}
+}
+
+// Project renders one composition (spec §8; §13 decisions 22 and 26). It
+// proves the reply sound before it returns it: every command the device would
+// run under it is one port49 permits. A composition neither shape carries
+// gets the fail-closed reply, which is proven the same way. The error is a
+// defect only: a program that does not compile.
+func Project(in Input) (Result, error) {
+	g := newGenerator(in, in.Bits)
+	res, err := g.render()
+	var r *Refusal
+	if err == nil {
+		m, merr := g.model(res)
+		if merr != nil {
+			return Result{}, merr
+		}
+		res.model = m
+		v, bad := m.unsound()
+		if !bad {
+			return res, nil
+		}
+		// The checks are a proof; this is its witness. A vector here is a
+		// generator defect, and the subject gets the fail-closed reply.
+		err = refuse(FailUnsound, "on %s the reply would let the device run %q, which port49 denies; this is a "+
+			"projection defect", in.Platform, strings.Join(v, " "))
+	}
+	if !errors.As(err, &r) {
+		return Result{}, err
+	}
+	return g.failClosed(r)
+}
+
+type generator struct {
+	in              Input
+	permits, denies []engine.Rule
+	ceiling         []string
+}
+
+// newGenerator splits the rules, and adds a deny for each baseline reach rule
+// no permit holds: the baseline runs it for every session, so without the
+// deny the device would run what port49 refuses.
+func newGenerator(in Input, ceiling []string) generator {
+	g := generator{in: in, ceiling: in.Dialect.ExpandBits(ceiling)}
+	for _, r := range in.Rules {
+		if r.Verdict == engine.Permit {
+			g.permits = append(g.permits, r)
+		} else {
+			g.denies = append(g.denies, r)
+		}
+	}
+	for _, b := range in.Dialect.Bits[platform.BaselineBit] {
+		held := func(q engine.Rule) bool { return g.contains(q.Rule, b) }
+		if !slices.ContainsFunc(g.permits, held) && !slices.ContainsFunc(g.denies, held) {
+			g.denies = append(g.denies, engine.Rule{Verdict: engine.Deny, Rule: b, Role: platform.BaselineBit})
+		}
+	}
+	return g
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
+// render is the capability or narrow shape, and, under user_permissions,
+// the same without the bits that enter configuration mode where those are
+// what refused it (decision 26, for spec §13's decided item 6).
+func (g generator) render() (Result, error) {
+	for _, r := range g.in.Rules {
+		if g.in.Secret != nil && g.in.Secret(r.Rule) {
+			return Result{}, refuse(FailSecretRule, "role %q has a rule whose text carries a value redaction "+
+				"hides, and %s's session reply is its rules, logged whole (spec §5.8): write the rule without it",
+				r.Role, g.in.Platform)
+		}
+	}
+	res, err := g.shape()
+	var r *Refusal
+	if !errors.As(err, &r) || r.Category != FailConfigurationMode ||
+		g.in.Dialect.BitDelivery != platform.BitDeliveryUserPermissions {
+		return res, err
+	}
+	lower := g.plain(g.ceiling)
+	if len(lower) == len(g.ceiling) {
+		return res, err
+	}
+	h := newGenerator(g.in, lower)
+	res2, err2 := h.shape()
+	if err2 != nil {
+		return res, err
+	}
+	res2.ConfigurationDropped = slices.DeleteFunc(slices.Clone(g.ceiling), func(b string) bool {
+		return slices.Contains(lower, b)
+	})
+	return res2, nil
+}
+
+func (g generator) shape() (Result, error) {
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
+	return res, nil
+}
+
+// narrowOnly is capability's answer where only the narrow shape can carry
+// the grant.
+type narrowOnly struct{ why string }
+
+func (n *narrowOnly) Error() string { return n.why }
+
+// declared is the level's ceiling bits as the adapter writes them, sorted:
+// what a template's class carries, `all` unexpanded.
+func (g generator) declared() []string {
+	out := slices.Clone(g.in.Bits)
+	slices.Sort(out)
+	return slices.Compact(out)
+}
+
+// held is the bits s, `all` read as every bit, and the baseline where the
+// adapter declares one: what a session sent s holds.
+func (g generator) held(s []string) []string {
+	out := g.in.Dialect.ExpandBits(s)
+	if _, ok := g.in.Dialect.Bits[platform.BaselineBit]; ok {
+		out = append(out, platform.BaselineBit)
+	}
+	return out
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
+// carves is every measured carve-out of a declared bit not in held: the
+// commands a session without that bit is refused whatever else it holds.
+func (g generator) carves(held []string) []string {
+	var out []string
+	for _, b := range sortedKeys(g.in.Dialect.CarveOuts) {
+		if !slices.Contains(held, b) {
+			out = append(out, g.in.Dialect.CarveOuts[b]...)
+		}
+	}
+	return out
+}
+
+// entersConfiguration reports whether bit b's reach holds `configure`.
+func (g generator) entersConfiguration(b string) bool {
+	return slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.contains(r, "configure") })
+}
+
+// plain is bits without the ones that enter configuration mode.
+func (g generator) plain(bits []string) []string {
+	return slices.DeleteFunc(slices.Clone(bits), g.entersConfiguration)
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
+// permit p matches, no carve-out of a bit outside the ceiling meeting it: a
+// permit beyond them is never sent, since on the device an allow runs
+// whatever the bits say (spec §8, "never exceeding the level's ceiling").
+func (g generator) within(p string) bool { return g.reaches(p, g.ceiling, false) }
+
+// byBits reports whether the bits s run every command of p that port49 does
+// not deny outright: some reach rule of s holds p, and each carve-out of a
+// bit outside s that meets p is held by a deny, so what it carves port49
+// refuses too.
+func (g generator) byBits(p string, s []string) bool { return g.reaches(p, s, true) }
+
+// reaches reports whether some reach rule of the bits s holds p and no
+// carve-out of a bit outside s meets it; with denied, a carve-out a deny
+// holds may.
+func (g generator) reaches(p string, s []string, denied bool) bool {
+	held := g.held(s)
+	if !slices.ContainsFunc(g.reach(held), func(r string) bool { return g.contains(r, p) }) {
+		return false
+	}
+	for _, c := range g.carves(held) {
+		if g.mayMeet(p, c) &&
+			!(denied && slices.ContainsFunc(g.denies, func(d engine.Rule) bool { return g.contains(d.Rule, c) })) {
+			return false
+		}
+	}
+	return true
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
+	return refuse(FailRefusedShape, "on %s, permit %q (role %q) needs an allow-commands the device would let "+
+		"beat deny %q (role %q), which sits beneath it: Junos regex cannot write everything under a permit except "+
+		"a deny (spec §8, \"Refused shape\")", g.in.Platform, p.Rule, p.Role, d.Rule, d.Role)
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
+// emitting a regex"): a measured carve-out of a bit not sent holds dn, and no
+// allow meets it. Only a carve-out licenses this: under the union, a bit not
+// sent refuses nothing another bit reaches.
+func (g generator) omittable(dn engine.Rule, bits []string, allows []engine.Rule) bool {
+	for _, a := range allows {
+		if g.mayMeet(a.Rule, dn.Rule) {
+			return false
+		}
+	}
+	return slices.ContainsFunc(g.carves(g.held(bits)), func(c string) bool { return g.contains(c, dn.Rule) })
+}
+
+// configuration refuses a reply that enters configuration mode for a grant
+// that is not everything — a bit whose reach holds `configure`, or an allow
+// that meets it: a statement typed there is governed by the class's
+// configuration permissions, which no deny-commands or allow-commands
+// reaches (spec §8; §15 L12), so port49 could deny a statement the device
+// then runs. Only a grant that permits every command and denies none is
+// carried faithfully there.
+func (g generator) configuration(res Result) error {
+	what := ""
+	for _, b := range g.held(res.Bits) {
+		if g.entersConfiguration(b) {
+			what = "bit " + b
+			break
+		}
+	}
+	for _, a := range res.Allows {
+		if what == "" && g.mayMeet(a.Rule, "configure **") {
+			what = fmt.Sprintf("allow %q", a.Rule)
+		}
+	}
+	if what == "" {
+		return nil
+	}
+	everything := slices.ContainsFunc(g.permits, func(p engine.Rule) bool { return g.contains(p.Rule, "**") })
+	if everything && len(g.denies) == 0 {
+		return nil
+	}
+	grant := "permits less than every command"
+	if len(g.denies) > 0 {
+		grant = fmt.Sprintf("denies %q (role %q)", g.denies[0].Rule, g.denies[0].Role)
+	}
+	return refuse(FailConfigurationMode, "on %s the reply's %s enters configuration mode, where a statement is "+
+		"governed by the class's configuration permissions and no command regex reaches it (spec §8, §15 L12), "+
+		"and the composition %s: port49 would deny what the device runs there", g.in.Platform, what, grant)
+}
+
+// narrow is the narrow shape: every permit the ceiling reaches as one allow
+// alternation over `deny-commands .*`, under the smallest set of ceiling bits
+// that reach them — the template's, where the delivery is one.
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
+	res.Bits = g.cover(g.ceiling, res.Allows)
+	return res, nil
+}
+
+// maxCover bounds cover's exact search, in candidate subsets; past it the
+// cover is greedy.
+const maxCover = 1 << 16
+
+// cover is the smallest set of the bits from that reach every allow: fewest
+// bits, then fewest that enter configuration mode, then first in name order
+// (I11: `all` reaches everything, and a narrow admin grant under it would
+// be refused for entering configuration mode). Bits reaching the same
+// allows are one candidate, the preferred of them.
+func (g generator) cover(from []string, allows []engine.Rule) []string {
+	if len(allows) == 0 {
+		return nil
+	}
+	if len(allows) > 63 {
+		allows = allows[:63] // more never fit in one attribute
+	}
+	type cand struct {
+		bit    string
+		mask   uint64
+		config bool
+	}
+	var cands []cand
+	full := uint64(1)<<len(allows) - 1
+	for _, b := range from {
+		var m uint64
+		for i, p := range allows {
+			if slices.ContainsFunc(g.in.Dialect.Bits[b], func(r string) bool { return g.contains(r, p.Rule) }) {
+				m |= 1 << i
+			}
+		}
+		if m == 0 {
+			continue
+		}
+		c := cand{b, m, g.entersConfiguration(b)}
+		if k := slices.IndexFunc(cands, func(o cand) bool { return o.mask == m }); k >= 0 {
+			if o := cands[k]; o.config && !c.config || o.config == c.config && c.bit < o.bit {
+				cands[k] = c
+			}
+			continue
+		}
+		cands = append(cands, c)
+	}
+	names := func(set uint64) []string {
+		var out []string
+		for i, c := range cands {
+			if set&(1<<i) != 0 {
+				out = append(out, c.bit)
+			}
+		}
+		slices.Sort(out)
+		return out
+	}
+	configs := func(set uint64) int {
+		n := 0
+		for i, c := range cands {
+			if set&(1<<i) != 0 && c.config {
+				n++
+			}
+		}
+		return n
+	}
+	better := func(a, b uint64) bool {
+		if na, nb := bits.OnesCount64(a), bits.OnesCount64(b); na != nb {
+			return na < nb
+		}
+		if ca, cb := configs(a), configs(b); ca != cb {
+			return ca < cb
+		}
+		return slices.Compare(names(a), names(b)) < 0
+	}
+	if len(cands) < 64 && uint64(1)<<len(cands) <= maxCover {
+		best, found := uint64(0), false
+		for set := uint64(1); set < uint64(1)<<len(cands); set++ {
+			var m uint64
+			for i, c := range cands {
+				if set&(1<<i) != 0 {
+					m |= c.mask
+				}
+			}
+			if m == full && (!found || better(set, best)) {
+				best, found = set, true
+			}
+		}
+		if found {
+			return names(best)
+		}
+		return nil // within() said some ceiling bit reaches each; unreachable
+	}
+	// Greedy: the candidate reaching the most allows not yet reached, one
+	// that does not enter configuration mode first, then name order.
+	var set, got uint64
+	for got != full {
+		pick := -1
+		for i, c := range cands {
+			if set&(1<<i) != 0 {
+				continue
+			}
+			n := bits.OnesCount64(c.mask &^ got)
+			if n == 0 {
+				continue
+			}
+			if pick < 0 {
+				pick = i
+				continue
+			}
+			p := cands[pick]
+			pn := bits.OnesCount64(p.mask &^ got)
+			if n > pn || n == pn && (p.config && !c.config || p.config == c.config && c.bit < p.bit) {
+				pick = i
+			}
+		}
+		if pick < 0 {
+			break
+		}
+		set |= 1 << pick
+		got |= cands[pick].mask
+	}
+	return names(set)
+}
+
+// failClosed is the reply for a composition neither shape carries (spec §13
+// decision 26): `deny-commands` `.*`, an allow for each permit that is
+// within the level's ceiling bits that do not enter configuration mode,
+// dominates every deny it meets, does not meet `configure`, and can be
+// written; under user_permissions the smallest of those bits that reach the
+// allows, and no template under local_user_name, so the session lands in the
+// bitless p49-remote. Where the allows cannot be sent whole, none is.
+func (g generator) failClosed(r *Refusal) (Result, error) {
+	res := Result{Shape: ShapeFailClosed, FailClosed: r.Category, Refusal: r}
+	h := newGenerator(g.in, g.plain(g.ceiling))
+	for _, p := range h.permits {
+		_, ok := h.allowable(p.Rule)
+		secret := g.in.Secret != nil && g.in.Secret(p.Rule)
+		_, werr := ruleERE(p.Rule, g.in.Classes, false, g.in.Facts)
+		if secret || werr != nil || !ok || !h.within(p.Rule) || h.mayMeet(p.Rule, "configure **") {
+			res.Beyond = append(res.Beyond, p)
+			continue
+		}
+		res.Allows = append(res.Allows, p)
+	}
+	send := func() (Result, error) {
+		out := res
+		out.Attributes = nil
+		if g.in.Dialect.BitDelivery == platform.BitDeliveryUserPermissions {
+			out.Bits = h.cover(h.ceiling, out.Allows)
+		}
+		if len(out.Bits) > 0 {
+			out.Attributes = append(out.Attributes, "user-permissions="+strings.Join(out.Bits, " "))
+		}
+		out.Attributes = append(out.Attributes, "deny-commands=^.*$")
+		allow, err := h.alternation(out.Allows, false)
+		if err != nil {
+			return out, err
+		}
+		if allow != "" {
+			out.Attributes = append(out.Attributes, "allow-commands=^"+allow+"$")
+		}
+		for _, a := range out.Attributes {
+			if err := engine.CheckAttribute(a); err != nil {
+				return out, err
+			}
+		}
+		m, err := h.model(out)
+		if err != nil {
+			return Result{}, err
+		}
+		out.model = m
+		if _, bad := m.unsound(); bad {
+			return out, errors.New("unsound")
+		}
+		return out, nil
+	}
+	out, err := send()
+	if err != nil && out.Shape != "" {
+		// The allows cannot go out whole: none does, and the reply is
+		// `deny-commands` `.*` alone.
+		res.Beyond = append(res.Beyond, res.Allows...)
+		res.Allows = nil
+		out, err = send()
+	}
+	return out, err
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
+			r := &Refusal{Category: FailOverflow, Attribute: a[:i], Value: a[i+1:],
+				Why: fmt.Sprintf("on %s the reply's %s is %d bytes, and RFC 8907 carries at most %d in one attribute; "+
+					"a device sent part of a deny is sent none of it (spec §8, \"Generator constraints\")",
+					g.in.Platform, engine.AttributeName(a), len(a), engine.MaxAttribute)}
+			if r.Attribute == "deny-commands" {
+				r.Class = res.Template
+				if r.Class == "" {
+					r.Class = platform.RemoteClass
+				}
+				r.Why += ": move the denies into the template's class on the device (port49 platform export " +
+					"--classes), where they bind every subject at that template, or narrow the grant"
+			} else {
+				r.Why += ": narrow the grant; an allow is never moved into a class, where it would run for every " +
+					"subject past their own denies"
+			}
+			return r
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
+			return "", refuse(FailUnwritable, "on %s, %s %q (role %q) cannot be written as the device's regex: %v "+
+				"(spec §8, §15 L9)", g.in.Platform, r.Verdict, r.Rule, r.Role, err)
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
feat: project a composition into a Junos reply, proven sound, or the fail-closed reply

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: A pinned projected set renders each subject's Junos reply, fail-closed where it must, once per composition

**Files:**
- Modify: `internal/policy/resolve.go` (`Resolution.Projection`; `compile` calls `project`, which
  caches; `layerAttributes` puts the projection at the platform layer; `exceeds` skips its names)
- Modify: `internal/policy/load.go` (`Policy.projected`; `checkProjected`, called from
  `checkAttributes`; the reserved-username refusal)
- Modify: `internal/engine/blob.go` (`Blob.FailClosed`, and `Encode` carries it)
- Modify: `internal/token/minter.go` (`ReservedUsername`, `ErrUsernameReserved`)
- Test: `internal/policy/projection_test.go`, `internal/token/minter_test.go`

**Interfaces:**
- Consumes: Task 8's `projection.Project`, `Input`, `Result`, `FactsFor`; Task 6's `Projected`,
  `ProjectionOwns`, `LevelBits`, `LocalUserNames`; `platform.Redactions`, `platform.RedactRule`.
- Produces:
  - `Resolution.Projection *projection.Result`, nil on a platform that projects nothing;
  - `compile` now returns `(engine.Blob, []AttributeSource, *projection.Result, error)`;
  - `(*Policy).project(c composition, b engine.Blob, dialect platform.Dialect)
    (projection.Result, error)`, memoized in `Policy.projected sync.Map`;
  - `engine.Blob.FailClosed string`, JSON `fail_closed`, omitted when empty;
  - `func token.ReservedUsername(u string) bool` and `var token.ErrUsernameReserved`.

`compile` builds the blob's rules as before and, on a projected platform, hands them to
`projection.Project` with the level's ceiling bits and template, following the parent chain. The
projection's attributes go in at the platform layer: source `platform juniper_junos, projection
(<shape>)`. A fail-closed result is not an error: its reply is the blob's attributes and its reason
is `Blob.FailClosed`, so **one subject's composition never quarantines the device** (decision 26).
A level with no bits on its chain is still a compile error, as a level with no rendering is.
`FailClosed` is written only when set, so every existing blob keeps its hash.

`project` is memoized per policy on the platform, the level and the blob's rules and classes: the
adapter, the normalization and the redactions are fixed by the platform within one policy, so
nothing else can change the result (pre-flight I12). `TestProjectionLoadTime` loads 1,000 SRXs
and 20 subjects over four compositions, one of them refused; it took 0.22 s on the build host, and
the test holds it under 2 s.

`exceeds` skips the projection's own names, since the generator holds them to the level's ceiling
bits. `checkProjected` refuses a role or grant attribute `ProjectionOwns` claims (Decided 8). A
subject declaring `remote` or a `p49-*` username is a load error, and the mint refuses one a
directory derives (Decided 18). Nothing changes for a policy on 1.0.0; the test's projected set
stands in until Task 14.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
index 5d206d1..f9fc9b1 100644
--- a/internal/policy/projection_test.go
+++ b/internal/policy/projection_test.go
@@ -1,8 +1,14 @@
 package policy
 
 import (
+	"fmt"
+	"net/netip"
+	"reflect"
 	"strings"
 	"testing"
+	"time"
+
+	"github.com/blanketfish/port49/internal/admission"
 
 	"github.com/blanketfish/port49/internal/platform"
 )
@@ -67,3 +73,138 @@ func TestABlockKeepsTheProjection(t *testing.T) {
 	parseProjected(t, platform.BitDeliveryUserPermissions, "platforms:\n  juniper_junos:\n"+
 		"    bits: {view: [\"show **\", \"monitor **\"]}\n    carve_outs: {view-configuration: []}\n"+readonlyCarveOut)
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
+	if !reflect.DeepEqual(res.Blob.Attributes, []string{"user-permissions=view"}) || res.Blob.FailClosed != "" ||
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
+// The refused shape gets that subject the fail-closed reply, and quarantines
+// nothing: every other subject on the device keeps its reply (decision 26).
+// So does a bit whose reach a block widened past what the grant decides.
+func TestTheRefusedShapeFailsClosedForThatSubjectOnly(t *testing.T) {
+	body := scopeOK + `roles:
+  - {name: r, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
+  - {name: ok, privilege: readonly, permit: ["show version"]}
+subjects:
+  - {name: s, identity: ["user:a@example.com"], username: a, token_ttl: 60s}
+  - {name: t, identity: ["user:b@example.com"], username: b, token_ttl: 60s}
+grants:
+  - {subject: s, scope: all_devices, roles: [r]}
+  - {subject: t, scope: all_devices, roles: [ok]}
+`
+	for _, block := range []string{"", "platforms:\n  juniper_junos:\n    bits: {view: [\"show **\", \"monitor **\"]}\n"} {
+		p := parseProjected(t, platform.BitDeliveryUserPermissions, block+body)
+		if q := p.Quarantines(noon); len(q) != 0 {
+			t.Fatalf("a projection refusal quarantines nothing: %+v", q)
+		}
+		res, err := p.ResolveSubject("t", deviceNamed(t, "srx-fw-04"), noon)
+		if err != nil || res.Blob.FailClosed != "" {
+			t.Fatalf("the other subject: %q %v", res.Blob.Attributes, err)
+		}
+		res, err = p.ResolveSubject("s", deviceNamed(t, "srx-fw-04"), noon)
+		if err != nil || res.Blob.FailClosed != "refused_shape" ||
+			!reflect.DeepEqual(res.Blob.Attributes, []string{"deny-commands=^.*$"}) {
+			t.Fatalf("%q %q %v", res.Blob.Attributes, res.Blob.FailClosed, err)
+		}
+	}
+}
+
+// No role or grant sets an attribute the projection renders, in any case or
+// numbered variant the device reads (I1).
+func TestARoleCannotSetAProjectedAttribute(t *testing.T) {
+	for _, key := range []string{"juniper_junos", "all"} {
+		for _, a := range []string{"deny-commands=^request.*$", "allow-commands2=^request.*$",
+			"User-Permissions=all", "local-user-name1=p49-admin", "allow-configuration-regexps=.*"} {
+			_, err := Parse([]byte("platform_set: "+projectedSet+"\n"+scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show **"], attributes: {`+key+`: ["`+a+`"]}}
+`+subjOK+grantOK), projectedEnv(platform.BitDeliveryUserPermissions))
+			if err == nil || !strings.Contains(err.Error(), "rendered by juniper_junos's projection") {
+				t.Errorf("%s %s: %v", key, a, err)
+			}
+		}
+	}
+}
+
+// A subject may not take a device template user's name: a session under one
+// lands in that template's class whatever the reply says (I9).
+func TestATemplateUsernameIsReserved(t *testing.T) {
+	for _, u := range []string{"remote", "p49-admin", "p49-remote"} {
+		_, err := Parse([]byte(scopeOK+roleOK+"subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: "+
+			u+", token_ttl: 60s}\n"+grantOK), env())
+		if err == nil || !strings.Contains(err.Error(), "is reserved") {
+			t.Errorf("%s: %v", u, err)
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
+
+// Each composition is projected once per policy, however many devices it
+// lands on: 1,000 SRXs and 20 subjects load within 2 s (I12; spec §8).
+func TestProjectionLoadTime(t *testing.T) {
+	if testing.Short() {
+		t.Skip("load-time bound")
+	}
+	e := projectedEnv(platform.BitDeliveryUserPermissions)
+	e.Devices = nil
+	for i := range 1000 {
+		e.Devices = append(e.Devices, admission.Device{Name: fmt.Sprintf("srx-%04d", i), Platform: "juniper_junos",
+			Addresses:  []netip.Addr{netip.AddrFrom4([4]byte{10, 9, byte(i >> 8), byte(i)})},
+			Attributes: map[string]string{"site": fmt.Sprintf("s%d", i%10)}})
+	}
+	var b strings.Builder
+	b.WriteString("platform_set: " + projectedSet + "\n" + scopeOK + `roles:
+  - {name: ro, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}
+  - {name: narrow, privilege: readonly, permit: ["show version", "show interfaces **"]}
+  - {name: op, privilege: operator, permit: ["show **", "clear **", "ping **"], deny: ["clear bgp **"]}
+  - {name: refused, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
+subjects:
+`)
+	roles := []string{"ro", "narrow", "op", "refused"}
+	for i := range 20 {
+		fmt.Fprintf(&b, "  - {name: s%d, identity: [\"user:u%d@example.com\"], username: u%d, token_ttl: 60s}\n", i, i, i)
+	}
+	b.WriteString("grants:\n")
+	for i := range 20 {
+		fmt.Fprintf(&b, "  - {subject: s%d, scope: all_devices, roles: [%s]}\n", i, roles[i%len(roles)])
+	}
+	start := time.Now()
+	if _, err := Parse([]byte(b.String()), e); err != nil {
+		t.Fatal(err)
+	}
+	if d := time.Since(start); d > 2*time.Second {
+		t.Fatalf("1,000 SRXs x 20 subjects loaded in %v; the bound is 2 s", d)
+	} else {
+		t.Logf("1,000 SRXs x 20 subjects loaded in %v", d)
+	}
+}
````

<!-- patch: internal/token/minter_test.go -->
````diff
diff --git a/internal/token/minter_test.go b/internal/token/minter_test.go
index 6237827..f1ee286 100644
--- a/internal/token/minter_test.go
+++ b/internal/token/minter_test.go
@@ -383,3 +383,16 @@ func TestEveryTokenCarriesItsMintTime(t *testing.T) {
 		}
 	}
 }
+
+// A device template user's name is never minted for: a directory may derive
+// one the policy never declared (spec §13 decision 26).
+func TestMintRefusesATemplateUsername(t *testing.T) {
+	m, _, _ := minter(t)
+	for _, u := range []string{"remote", "p49-readonly"} {
+		s := subject()
+		s.Username = u
+		if _, err := m.Mint(context.Background(), Request{Subject: s, Device: "leaf-01", TTL: time.Minute}); !errors.Is(err, ErrUsernameReserved) {
+			t.Fatalf("%q: %v", u, err)
+		}
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./internal/token/`
Expected: FAIL, build failed: `res.Blob.FailClosed undefined (type engine.Blob has no field or method
FailClosed)`, `res.Projection undefined (type Resolution has no field or method Projection)`, and
`undefined: ErrUsernameReserved`.

- [ ] **Step 3: Render the projection in compile**

<!-- patch: internal/engine/blob.go -->
````diff
diff --git a/internal/engine/blob.go b/internal/engine/blob.go
index 97837b3..861a89d 100644
--- a/internal/engine/blob.go
+++ b/internal/engine/blob.go
@@ -63,6 +63,12 @@ type Blob struct {
 	// Classes are the patterns behind every `@class` the rules name, as this
 	// platform defines them.
 	Classes map[string][]string `json:"classes"`
+	// FailClosed is set where Attributes are a projection's fail-closed reply
+	// (spec §13 decision 26): why the composition could not be told
+	// faithfully, one of projection's Fail* categories. The daemon records
+	// the session under projection_fail_closed. Written only when set, so a
+	// blob without it keeps its hash.
+	FailClosed string `json:"fail_closed,omitempty"`
 }
 
 // Normalize is the platform's dialect as the evaluator needs it (spec §3).
````

<!-- patch: internal/policy/load.go -->
````diff
diff --git a/internal/policy/load.go b/internal/policy/load.go
index 2c4faec..5829f3f 100644
--- a/internal/policy/load.go
+++ b/internal/policy/load.go
@@ -17,6 +17,7 @@ import (
 	"slices"
 	"strconv"
 	"strings"
+	"sync"
 	"time"
 	"unicode"
 
@@ -64,6 +65,8 @@ type Policy struct {
 	set       string
 	adapters  map[string]platform.Dialect
 	overrides map[string]filePlatform
+	// projected memoizes project, keyed by what a projection reads.
+	projected sync.Map
 
 	levels  []string          // the declared ordering, lowest first
 	parents map[string]string // level → parent, for rendering
@@ -894,6 +897,9 @@ func (p *Policy) checkAttributes(attrs map[string][]string) error {
 			if err := engine.CheckAttribute(a); err != nil {
 				return fmt.Errorf("%s: %w", at, err)
 			}
+			if err := p.checkProjected(at, key, a); err != nil {
+				return err
+			}
 			if err := p.checkPlaceholder(at, key, a); err != nil {
 				return err
 			}
@@ -902,6 +908,25 @@ func (p *Policy) checkAttributes(attrs map[string][]string) error {
 	return nil
 }
 
+// checkProjected refuses an attribute a projection renders, under a
+// projected platform's key or under `all` where any platform is projected:
+// beside the projection it would be a second instance the device drops or
+// keeps first, and over it a regex nothing proved (spec §8, "Generator
+// constraints" 1, 4 and 6). A name is caught in every case and numbered
+// variant the device reads (allow-commands2, User-Permissions), and every
+// name the adapter lists as bearing privilege (Dialect.ProjectionOwns).
+func (p *Policy) checkProjected(at, key, a string) error {
+	name := engine.AttributeName(a)
+	for _, plat := range sortedKeys(p.adapters) {
+		d := p.adapters[plat]
+		if (key == plat || key == "all") && d.ProjectionOwns(name) {
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
@@ -1094,6 +1119,11 @@ func (p *Policy) buildSubjects(f file) error {
 		// Whether a username is required depends on whether a grant names the
 		// subject, which checkMinters settles once the grants are read.
 		if len(s.Identity) > 0 && s.Username != "" {
+			if token.ReservedUsername(s.Username) {
+				return fmt.Errorf("subject %q: username %q is reserved: `remote` and every p49-* name are the "+
+					"device's template users, and a session under one lands in that template's class whatever "+
+					"the reply says (spec §8, §13 decision 26)", s.Name, s.Username)
+			}
 			if !token.CanonicalUsername(s.Username) {
 				return fmt.Errorf("subject %q: username %q must be printable ASCII and already canonical — lower "+
 					"case, no DOMAIN\\ prefix, no @suffix — because the daemon looks tokens up by the canonical form "+
````

<!-- patch: internal/policy/resolve.go -->
````diff
diff --git a/internal/policy/resolve.go b/internal/policy/resolve.go
index f7b007b..3a04a7e 100644
--- a/internal/policy/resolve.go
+++ b/internal/policy/resolve.go
@@ -1,6 +1,7 @@
 package policy
 
 import (
+	"encoding/json"
 	"errors"
 	"fmt"
 	"slices"
@@ -13,6 +14,7 @@ import (
 	"github.com/blanketfish/port49/internal/decision"
 	"github.com/blanketfish/port49/internal/engine"
 	"github.com/blanketfish/port49/internal/platform"
+	"github.com/blanketfish/port49/internal/projection"
 )
 
 // ErrNoGrants is no_grants_matched: no subject lists the principal, or no
@@ -45,6 +47,9 @@ type Resolution struct {
 	// attributes came from and what it shadowed (spec §6).
 	Blob       engine.Blob
 	Attributes []AttributeSource
+	// Projection is the session reply's projection of the rules on a
+	// projected platform (spec §8), and what it reports: nil elsewhere.
+	Projection *projection.Result
 }
 
 // AttributeSource is one attribute of the session reply and its provenance:
@@ -131,7 +136,7 @@ func (p *Policy) resolved(sub *Subject, d admission.Device, c composition) (Reso
 		res.MaxPrivilege, res.HasCeiling = n, true
 	}
 	var err error
-	res.Blob, res.Attributes, err = p.compile(c, d, dialect)
+	res.Blob, res.Attributes, res.Projection, err = p.compile(c, d, dialect)
 	return res, err
 }
 
@@ -139,7 +144,8 @@ func (p *Policy) resolved(sub *Subject, d admission.Device, c composition) (Reso
 // every role's rules, each carrying its role; the pipe allowlist of every
 // role that permits anything; the patterns behind every class a rule names,
 // as this platform defines them; and the session attributes, layered.
-func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dialect) (engine.Blob, []AttributeSource, error) {
+func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dialect) (engine.Blob, []AttributeSource,
+	*projection.Result, error) {
 	b := engine.Blob{Version: engine.Version, Bundle: p.Bundle, Platform: d.Platform, Privilege: c.level,
 		Normalize: p.normalizeFor(d.Platform), Classes: map[string][]string{}}
 	pipe := map[string]bool{}
@@ -173,7 +179,7 @@ func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dia
 					// A class the platform does not define would silently never
 					// match — a deny that does nothing — so it is an error, and
 					// at load, not at a mint (spec §4, §8).
-					return engine.Blob{}, nil, fmt.Errorf("role %q names @%s, which %s does not define", name,
+					return engine.Blob{}, nil, nil, fmt.Errorf("role %q names @%s, which %s does not define", name,
 						t.Text, platformName(d.Platform))
 				}
 				b.Classes[t.Text] = patterns
@@ -194,9 +200,18 @@ func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dia
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
+		b.FailClosed = r.FailClosed
+	}
+	attrs, err := p.layerAttributes(c, d.Platform, dialect, proj)
 	if err != nil {
-		return engine.Blob{}, nil, err
+		return engine.Blob{}, nil, nil, err
 	}
 	for _, a := range attrs {
 		b.Attributes = append(b.Attributes, a.Attribute)
@@ -208,7 +223,60 @@ func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dia
 		slices.Sort(b.AcceptedAttributes)
 		b.AcceptedAttributes = slices.Compact(b.AcceptedAttributes)
 	}
-	return b, attrs, nil
+	return b, attrs, proj, nil
+}
+
+// project renders the composition's rules into a projected platform's
+// session reply (spec §8; §13 decisions 22 and 26): the level's ceiling bits
+// and template, its parent chain followed as a rendering's is, and the blob's
+// rules and classes. A composition the projection cannot carry faithfully
+// gets the fail-closed reply, for that subject only; `policy test` and
+// `policy diff` fail on it (projectionRefusals). It is never a quarantine:
+// every other subject on the device keeps working.
+//
+// Compositions repeat across devices, so each is projected once per policy
+// (plan 5b pre-flight I12): the result depends only on the platform, whose
+// adapter, normalization and redactions this policy fixes, the level, and the
+// blob's rules and classes.
+func (p *Policy) project(c composition, b engine.Blob, dialect platform.Dialect) (projection.Result, error) {
+	key, err := json.Marshal([]any{b.Platform, c.level, b.Rules, b.Classes})
+	if err != nil {
+		return projection.Result{}, err
+	}
+	if r, ok := p.projected.Load(string(key)); ok {
+		return r.(projection.Result), nil
+	}
+	r, err := p.projectOnce(c, b, dialect)
+	if err == nil {
+		p.projected.Store(string(key), r)
+	}
+	return r, err
+}
+
+func (p *Policy) projectOnce(c composition, b engine.Blob, dialect platform.Dialect) (projection.Result, error) {
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
@@ -222,7 +290,8 @@ func platformName(name string) string {
 // specific winning on a duplicate attribute name and every override recorded.
 // Within one layer, sources are taken in name order — roles by name, grants by
 // scope — so which one wins cannot depend on a file's layout.
-func (p *Policy) layerAttributes(c composition, platformName string, dialect platform.Dialect) ([]AttributeSource, error) {
+func (p *Policy) layerAttributes(c composition, platformName string, dialect platform.Dialect,
+	proj *projection.Result) ([]AttributeSource, error) {
 	var out []AttributeSource
 	index := map[string]int{}
 	put := func(a, source string) {
@@ -236,7 +305,13 @@ func (p *Policy) layerAttributes(c composition, platformName string, dialect pla
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
@@ -461,6 +536,12 @@ func (p *Policy) exceeds(dialect platform.Dialect, bound, level string, reply []
 	held, sent := attributesByName(ceiling), attributesByName(reply)
 	for i, a := range reply {
 		name := engine.AttributeName(a)
+		// A projection's own attributes are held to the level's ceiling bits
+		// by the projection itself, which renders them from the level and
+		// never past it (spec §8). No role or grant sets one (checkProjected).
+		if dialect.ProjectionOwns(name) {
+			continue
+		}
 		if !strings.EqualFold(name, "priv-lvl") && raisesCeiling(name, dialect) &&
 			rose(held[name], sent[name], ceiling, rendered, dialect, dialect) {
 			return i, true
````

<!-- patch: internal/token/minter.go -->
````diff
diff --git a/internal/token/minter.go b/internal/token/minter.go
index aa39f06..bd20cae 100644
--- a/internal/token/minter.go
+++ b/internal/token/minter.go
@@ -8,6 +8,7 @@ import (
 	"errors"
 	"fmt"
 	"io"
+	"strings"
 	"time"
 
 	"github.com/blanketfish/port49/internal/decision"
@@ -33,6 +34,18 @@ var ErrIdempotencyConflict = errors.New("token: idempotency key reused with a di
 // The daemon cannot refuse a name a device sends; the mint can.
 var ErrUsernameNotCanonical = errors.New("token: device-facing username must be printable ASCII and already canonical")
 
+// ErrUsernameReserved refuses a device-facing username a Junos device keeps
+// for a template user: `remote`, where a session with no template lands, and
+// every p49-* name port49's reference classes use. A session under such a
+// name lands in that template's class whatever the reply says, so a subject
+// the projection told less (the fail-closed reply) would run what the
+// template's class runs (spec §13 decision 26). Policy load refuses a
+// declared one; this catches one a directory derives.
+var ErrUsernameReserved = errors.New("token: device-facing username is reserved for a device template user (remote, p49-*)")
+
+// ReservedUsername reports whether u is `remote` or a p49-* name.
+func ReservedUsername(u string) bool { return u == "remote" || strings.HasPrefix(u, "p49-") }
+
 // asciiUsername reports whether every byte of u is printable ASCII
 // (0x21–0x7E), which excludes the empty name, spaces and control characters.
 func asciiUsername(u string) bool {
@@ -164,6 +177,9 @@ func (m *Minter) Mint(ctx context.Context, r Request) (Result, error) {
 	if !CanonicalUsername(r.Subject.Username) {
 		return Result{}, ErrUsernameNotCanonical
 	}
+	if ReservedUsername(r.Subject.Username) {
+		return Result{}, ErrUsernameReserved
+	}
 	// idemErr names what a lost idempotency record cost, carried onto the mint
 	// record that is emitted anyway. It is Record.IndexError's idiom: the
 	// failure does not fail the mint, so the only place it can be said is the
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/blob.go internal/policy/load.go internal/policy/projection_test.go internal/policy/resolve.go internal/token/minter.go internal/token/minter_test.go
git commit -m "$(cat <<'EOF'
feat: a Junos session reply is its composition's projection, or that subject's fail-closed reply

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: A session answered with the fail-closed reply is recorded as projection_fail_closed

**Files:**
- Modify: `internal/decision/reasons.go` (`ProjectionFailClosed`)
- Modify: `internal/engine/blob.go` (`Blob.SessionReason`)
- Modify: `internal/daemon/author/engine.go` (`Session` records the blob's reason)
- Modify: `internal/replay/replay.go` (the reason is replayable, and a session replays to it)
- Modify: `internal/policy/explain.go` (the session line prints it)
- Test: `internal/engine/blob_test.go`, `internal/daemon/author/engine_test.go`,
  `internal/replay/replay_test.go`

**Interfaces:**
- Consumes: Task 9's `Blob.FailClosed`; spec §5.7's `projection_fail_closed`, which Task 1 added.
- Produces: `decision.ProjectionFailClosed Reason = "projection_fail_closed"`, and `func (b
  engine.Blob) SessionReason() decision.Reason`.

The fail-closed reply is a permit: the session opens, told less than port49 would permit. Its
`authorize_session` record says so by reason, so the one subject it reached is in the log by name
at 3am, and the blob event carries why. The reason is read off the blob in one place,
`Blob.SessionReason`, which the daemon, `policy replay` and `explain` all call, so a replay of such
a record agrees and one whose reason was edited to `context_matched` diverges. No metric is added:
the existing decision counters count it by reason.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/daemon/author/engine_test.go -->
````diff
diff --git a/internal/daemon/author/engine_test.go b/internal/daemon/author/engine_test.go
index 65123bf..a0a1b1f 100644
--- a/internal/daemon/author/engine_test.go
+++ b/internal/daemon/author/engine_test.go
@@ -423,3 +423,17 @@ func TestASecretOneFormMissesIsRedactedInBoth(t *testing.T) {
 		t.Fatalf("%v", r)
 	}
 }
+
+// A blob whose reply is a projection's fail-closed reply opens the session
+// with that reply, recorded as projection_fail_closed: the subject told less
+// than port49 would permit is in the log by name (spec §13 decision 26).
+func TestAFailClosedReplyIsRecordedByName(t *testing.T) {
+	b := eosBlob()
+	b.FailClosed = "refused_shape"
+	f := newEngineFixture(t, b)
+	c := store.Context{Username: "alice", Principal: "user:alice@example.com", BlobHash: f.hash}
+	d := (&Engine{Store: f.st, Metrics: f.m}).Session(context.Background(), Request{Context: c, Device: peer})
+	if !d.Permit || d.Reason != decision.ProjectionFailClosed || len(d.Attributes) == 0 {
+		t.Fatalf("%+v", d)
+	}
+}
````

<!-- patch: internal/engine/blob_test.go -->
````diff
diff --git a/internal/engine/blob_test.go b/internal/engine/blob_test.go
index 89e78dd..aeeaf60 100644
--- a/internal/engine/blob_test.go
+++ b/internal/engine/blob_test.go
@@ -322,3 +322,27 @@ func TestSessionAttributesSubstitute(t *testing.T) {
 		t.Errorf("an unused value refused: %v", err)
 	}
 }
+
+// A projection's fail-closed reply is marked on the blob, so the daemon and a
+// replay record the session as projection_fail_closed; a blob without the
+// mark encodes as before and keeps its hash (spec §13 decision 26).
+func TestFailClosedIsCarriedAndOmittedWhenEmpty(t *testing.T) {
+	const v2 = `{"version":2,"bundle":"b","platform":"juniper_junos","normalize":{"pipe_token":"|","pipe_authorized":false,` +
+		`"strip_cr":true,"expands_abbreviations":false,"session_only":true},"privilege":"","attributes":["deny-commands=^.*$"],` +
+		`"rules":[],"pipe":[],"classes":{}}`
+	b, err := Decode(HashOf([]byte(v2)), []byte(v2))
+	if err != nil || b.FailClosed != "" || b.SessionReason() != "context_matched" {
+		t.Fatalf("without the key: %+v, %v", b, err)
+	}
+	if body, _, err := Encode(b); err != nil || string(body) != v2 {
+		t.Fatalf("unset is omitted: %s %v", body, err)
+	}
+	b.FailClosed = "refused_shape"
+	body, hash, err := Encode(b)
+	if err != nil || !strings.HasSuffix(string(body), `"classes":{},"fail_closed":"refused_shape"}`) {
+		t.Fatalf("set: %s %v", body, err)
+	}
+	if got, err := Decode(hash, body); err != nil || got.SessionReason() != "projection_fail_closed" {
+		t.Fatalf("round trip: %+v %v", got, err)
+	}
+}
````

<!-- patch: internal/replay/replay_test.go -->
````diff
diff --git a/internal/replay/replay_test.go b/internal/replay/replay_test.go
index e6a9153..2a79d09 100644
--- a/internal/replay/replay_test.go
+++ b/internal/replay/replay_test.go
@@ -355,3 +355,39 @@ func TestARedactedBlobEventLeavesItsRecordsUnverifiable(t *testing.T) {
 		}
 	}
 }
+
+// A session answered with a projection's fail-closed reply replays to the
+// same reason and reply, and editing its reason to context_matched diverges
+// (spec §13 decision 26).
+func TestAFailClosedSessionReplays(t *testing.T) {
+	b := engine.Blob{Bundle: "sha256:policy", Platform: "juniper_junos",
+		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}, Privilege: "readonly",
+		Attributes: []string{"deny-commands=^.*$"}, FailClosed: "refused_shape",
+		Rules: []engine.Rule{{Verdict: engine.Permit, Rule: "show interfaces **", Role: "r"},
+			{Verdict: engine.Deny, Rule: "show interfaces terse", Role: "r"}}}
+	body, hash, err := engine.Encode(b)
+	if err != nil {
+		t.Fatal(err)
+	}
+	var log bytes.Buffer
+	sink := decision.NewJSONLines(&log)
+	sink.Emit(decision.Record{TS: time.Now(), Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
+	st := memory.New(time.Now)
+	st.PutBlob(context.Background(), hash, body, time.Hour)
+	st.PutContext(context.Background(), store.ContextKey{NAS: "srx-01", Username: "alice"},
+		store.Context{CtxID: "ctx1", Username: "alice", Principal: "user:alice@example.com", BlobHash: hash}, time.Hour)
+	m := metrics.New(prometheus.NewRegistry())
+	h := author.New(st, &author.Engine{Store: st, Metrics: m}, sink, m, time.Now, platform.Defaults(),
+		time.Hour, time.Minute, time.Hour)
+	h.Handle(context.Background(), authen.Peer{NAS: "srx-01", NASAddr: "10.20.0.9", Platform: "juniper_junos"},
+		wire.AuthorRequest{User: []byte("alice"), Port: []byte("vty0"),
+			Args: [][]byte{[]byte("service=junos-exec"), []byte("cmd=")}})
+	res := replayAll(t, log.String())
+	if len(res) != 1 || res[0].Status != Agree || res[0].Reason != decision.ProjectionFailClosed {
+		t.Fatalf("%+v\n%s", res, log.String())
+	}
+	edited := strings.Replace(log.String(), `"reason":"projection_fail_closed"`, `"reason":"context_matched"`, 1)
+	if res := replayAll(t, edited); res[0].Status != Diverge {
+		t.Fatalf("an edited reason: %+v", res)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/engine/ ./internal/daemon/author/ ./internal/replay/`
Expected: FAIL, build failed: `b.SessionReason undefined (type Blob has no field or method
SessionReason)`, `undefined: decision.ProjectionFailClosed`.

- [ ] **Step 3: Record the reason**

<!-- patch: internal/daemon/author/engine.go -->
````diff
diff --git a/internal/daemon/author/engine.go b/internal/daemon/author/engine.go
index 7e114f2..c5072bc 100644
--- a/internal/daemon/author/engine.go
+++ b/internal/daemon/author/engine.go
@@ -149,7 +149,7 @@ func (e *Engine) Session(ctx context.Context, r Request) Decision {
 			return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg, Policy: pol}
 		}
 	}
-	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: attrs, Policy: pol}
+	return Decision{Permit: true, Reason: p.Blob.SessionReason(), Attributes: attrs, Policy: pol}
 }
 
 // Command decides one command vector against the blob (spec §5.3).
````

<!-- patch: internal/decision/reasons.go -->
````diff
diff --git a/internal/decision/reasons.go b/internal/decision/reasons.go
index e4aa1a1..7979f51 100644
--- a/internal/decision/reasons.go
+++ b/internal/decision/reasons.go
@@ -57,6 +57,12 @@ const (
 	// from; operational, like blob_unavailable (spec §5.7).
 	BlobPlatformMismatch Reason = "blob_platform_mismatch"
 	DeviceQuarantined    Reason = "device_quarantined"
+	// ProjectionFailClosed: a session on a projected platform answered with
+	// its composition's fail-closed reply, deny every command but what the
+	// projection proved, because the composition cannot be told to the
+	// device faithfully (spec §8; §13 decision 26). A permit: the session
+	// opens, told less than port49 would permit. `policy test` fails on it.
+	ProjectionFailClosed Reason = "projection_fail_closed"
 )
 
 // Events.
@@ -89,7 +95,7 @@ var reasons = []Reason{
 	ContextMatched, EscalationGranted, PermitDominates, PipeStageDenied, ServiceUnsupported, EnableRefused,
 	CeilingExceeded, NoRuleMatched, NoPermitDominatesDeny, ContextMissing, UsernameMismatch, RemAddrMismatch,
 	PrivilegeExceeded, SessionExpired, ContextStale, CredentialRevoked, DeviceUnknown, PlatformUnknown,
-	BlobUnavailable, BlobPlatformMismatch, DeviceQuarantined,
+	BlobUnavailable, BlobPlatformMismatch, DeviceQuarantined, ProjectionFailClosed,
 }
 
 // Known reports whether r is in spec §5.7's vocabulary. A policy test's
````

<!-- patch: internal/engine/blob.go -->
````diff
diff --git a/internal/engine/blob.go b/internal/engine/blob.go
index 861a89d..ce95000 100644
--- a/internal/engine/blob.go
+++ b/internal/engine/blob.go
@@ -22,6 +22,8 @@ import (
 	"slices"
 	"strings"
 	"unicode/utf8"
+
+	"github.com/blanketfish/port49/internal/decision"
 )
 
 // Version is the blob format this package writes and the only one it reads.
@@ -124,7 +126,7 @@ func HashOf(body []byte) string {
 func Encode(b Blob) ([]byte, string, error) {
 	c := Blob{Version: Version, Bundle: b.Bundle, Platform: b.Platform, Normalize: b.Normalize,
 		Privilege: b.Privilege, Attributes: append([]string{}, b.Attributes...),
-		Rules: []Rule{}, Pipe: []string{}, Classes: map[string][]string{}}
+		Rules: []Rule{}, Pipe: []string{}, Classes: map[string][]string{}, FailClosed: b.FailClosed}
 	if len(b.AcceptedAttributes) > 0 {
 		c.AcceptedAttributes = slices.Clone(b.AcceptedAttributes)
 		slices.Sort(c.AcceptedAttributes)
@@ -317,3 +319,14 @@ func referencedClasses(b Blob) map[string]bool {
 	}
 	return out
 }
+
+// SessionReason is the reason a session answered from b is recorded under:
+// projection_fail_closed where b's reply is a projection's fail-closed reply,
+// so the one subject told less than port49 would permit is in the log by
+// name (spec §13 decision 26), and context_matched otherwise.
+func (b Blob) SessionReason() decision.Reason {
+	if b.FailClosed != "" {
+		return decision.ProjectionFailClosed
+	}
+	return decision.ContextMatched
+}
````

<!-- patch: internal/policy/explain.go -->
````diff
diff --git a/internal/policy/explain.go b/internal/policy/explain.go
index 828245c..7afdbde 100644
--- a/internal/policy/explain.go
+++ b/internal/policy/explain.go
@@ -339,7 +339,7 @@ func (e Explanation) Render(w io.Writer, showAttributes bool) {
 	r := e.Resolution
 	o := e.Outcome
 	if e.Command == "" {
-		fmt.Fprintf(w, "permit %s (session)\n", decision.ContextMatched)
+		fmt.Fprintf(w, "permit %s (session)\n", r.Blob.SessionReason())
 	} else if o.Permit {
 		fmt.Fprintf(w, "permit %s\n", o.Reason)
 	} else {
````

<!-- patch: internal/replay/replay.go -->
````diff
diff --git a/internal/replay/replay.go b/internal/replay/replay.go
index 342c0dd..5986021 100644
--- a/internal/replay/replay.go
+++ b/internal/replay/replay.go
@@ -53,6 +53,7 @@ type Result struct {
 var replayable = map[decision.Reason]bool{
 	decision.PermitDominates: true, decision.NoRuleMatched: true, decision.NoPermitDominatesDeny: true,
 	decision.PipeStageDenied: true, decision.ContextMatched: true, decision.BlobPlatformMismatch: true,
+	decision.ProjectionFailClosed: true,
 }
 
 // Replay reads a decision log and replays every authorization record that
@@ -268,6 +269,7 @@ func one(rec decision.Record, p *program) (Status, string) {
 		if attrs, err = b.SessionAttributes(v); err != nil {
 			return Diverge, "the blob's session attributes do not fit this record's values: " + err.Error()
 		}
+		reason = b.SessionReason()
 		session = true
 	case rec.Event == decision.EventAuthorizeCommand:
 		if rec.Request == nil {
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/author/engine.go internal/daemon/author/engine_test.go internal/decision/reasons.go internal/engine/blob.go internal/engine/blob_test.go internal/policy/explain.go internal/replay/replay.go internal/replay/replay_test.go
git commit -m "$(cat <<'EOF'
feat: a session answered with the fail-closed reply is recorded as projection_fail_closed

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: policy test reports each projection and fails on a fail-closed reply or a quarantine; explain says what the device runs

**Files:**
- Modify: `internal/policy/tests.go` (`Caveats` on a projected platform; `ProjectionCaveats`;
  `RunTests` appends them)
- Modify: `internal/policy/explain.go` (session and command caveats)
- Modify: `internal/policy/lint.go` (`projection`, `projection_refused` and `projection_overflow`
  findings; `Projections`, `ProjectionRefusals`, `refusedMessage`)
- Modify: `cmd/port49/policy.go` (`policy test` exits 1 on a quarantine or a refusal)
- Test: `internal/policy/projection_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: Task 9's `Resolution.Projection`; Task 8's `Result.Device`, `Result.Narrower`,
  `Result.FailClosed`, `Refusal`; 5a's `redacted` (intersect.go); `p.expiryInstants`.
- Produces:
  - `func ProjectionCaveats(res Resolution, platformName string, o engine.Outcome) []string`;
  - `FindingProjection = "projection"`, `FindingProjectionRefused = "projection_refused"`,
    `FindingProjectionOverflow = "projection_overflow"`;
  - `func (p *Policy) Projections(now time.Time) []Finding` and `func ProjectionRefusals(findings
    []Finding) int`.

Spec §8's reporting duties, and its "CI MUST refuse the policy":
- CI names each composition's shape, its bits or template, what each regex carries, what the bits
  refuse, what is beyond the level's bits, and up to three commands where the device is narrower.
- A composition that gets the fail-closed reply is `projection_refused`, or `projection_overflow`
  for an attribute past the budget, with the subject, **every device it lands on**, the reason and
  what it is told. The overflow prints the class line for `deny-commands` only, and says it binds
  every subject at that template; for `allow-commands` it says to narrow the grant (pre-flight
  C2). Every rule and value the findings quote is redacted (M9). The refusal's own sentence quotes
  only rules the secret check passed, since a composition with a secret rule is refused as
  `secret_rule`, whose text names only the role.
- **`policy test` exits 1 on any such finding and on any quarantine**, now or at a later expiry
  (pre-flight I10). The summary line counts both. The daemon still loads such a policy and serves
  the rest (decision 20); CI refuses to ship it.
- `explain` states that the effective set is class ∩ wire, says what the device does with the
  command under the reply, and names a fail-closed composition's reason.

`platform upgrade`'s preview of the same findings lands with set 1.1.0 in Task 14, where a test can
reach it.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/policy_test.go -->
````diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index ffaf454..45bb4b8 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -504,16 +504,22 @@ func TestPolicyTestPrintsReportsNotesAndScheduledQuarantines(t *testing.T) {
 		t.Fatal(err)
 	}
 	var out, errb bytes.Buffer
-	run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb)
+	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb)
 	for _, want := range []string{
 		`report: grantless_subject: subject "gone" has no grant`,
 		"     note: arista_eos applies output modifiers itself",
 		"quarantine: leaf-01 (arista_eos): will be quarantined from 2099-01-01T00:00:00.000Z, when grant all_devices [admin] expires",
+		"; 1 quarantined, 0 projection refusals\n",
 	} {
 		if !strings.Contains(out.String(), want) {
 			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
 		}
 	}
+	// A quarantine, even one an expiry brings on later, fails the gate
+	// (plan 5b pre-flight I10): the daemon serves the rest, CI ships none.
+	if code != 1 {
+		t.Fatalf("code %d", code)
+	}
 }
 
 // A session test prints the level and ceiling the subject resolved to, and
````

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
index f9fc9b1..34aeccc 100644
--- a/internal/policy/projection_test.go
+++ b/internal/policy/projection_test.go
@@ -11,6 +11,7 @@ import (
 	"github.com/blanketfish/port49/internal/admission"
 
 	"github.com/blanketfish/port49/internal/platform"
+	"github.com/blanketfish/port49/internal/projection"
 )
 
 // projectedSet is the test's second platform set: 1.0.0 with juniper_junos
@@ -208,3 +209,121 @@ subjects:
 		t.Logf("1,000 SRXs x 20 subjects loaded in %v", d)
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
+	// That subject gets the fail-closed reply, and the finding prints no class
+	// line: a class allow would run for every subject at that template, past
+	// their own denies (C2).
+	p = parseProjected(t, platform.BitDeliveryUserPermissions, body+"]}\n"+subjOK+grantOK)
+	var over []Finding
+	for _, f := range p.Lint(noon) {
+		if f.Kind == FindingProjectionOverflow {
+			over = append(over, f)
+		}
+	}
+	if len(over) != 1 || strings.Contains(over[0].Message, "set system login class") ||
+		!strings.Contains(over[0].Message, "narrow the grant") ||
+		!strings.Contains(over[0].Message, `subject "s" on juniper_junos (srx-fw-04, srx-fw-05, srx-fw-22, srx-lab-01)`) ||
+		ProjectionRefusals(p.Lint(noon)) != 1 {
+		t.Fatalf("%+v", over)
+	}
+	// Past the budget in deny-commands, the class line carries the denies,
+	// and says it binds every subject at that template.
+	body = scopeOK + "roles:\n  - {name: r, privilege: readonly, permit: [\"show **\"], deny: ["
+	for i, w := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"} {
+		if i > 0 {
+			body += ", "
+		}
+		body += `"show ` + w + ` **"`
+	}
+	// A deny narrower than every command goes out only once L9 measures that
+	// the device matches it against the expanded command.
+	saved := projection.JunosFacts
+	projection.JunosFacts.DenyMatchesExpanded = true
+	defer func() { projection.JunosFacts = saved }()
+	p = parseProjected(t, platform.BitDeliveryLocalUserName, body+"]}\n"+subjOK+grantOK)
+	over = nil
+	for _, f := range p.Lint(noon) {
+		if f.Kind == FindingProjectionOverflow {
+			over = append(over, f)
+		}
+	}
+	if len(over) != 1 || !strings.Contains(over[0].Message, "binding every subject at that template: "+
+		"set system login class p49-readonly deny-commands \"^( *[sS]") {
+		t.Fatalf("%+v", over)
+	}
+}
+
+// A refused composition is a projection_refused finding naming the subject,
+// every device, and why, and it is what fails policy test (I10).
+func TestARefusalIsAFinding(t *testing.T) {
+	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show interfaces **", "show version"], deny: ["show interfaces terse"]}
+`+subjOK+grantOK)
+	var got []string
+	for _, f := range p.Lint(noon) {
+		if f.Kind == FindingProjectionRefused {
+			got = append(got, f.Message)
+		}
+	}
+	if len(got) != 1 || !strings.Contains(got[0], `subject "s" on juniper_junos (srx-fw-04, srx-fw-05, srx-fw-22, `+
+		`srx-lab-01) gets the fail-closed reply (refused_shape)`) ||
+		!strings.Contains(got[0], `it is told every command denied but show version`) {
+		t.Fatalf("%q", got)
+	}
+	e, err := p.Explain("s", "", "srx-fw-04", "show interfaces em0", noon)
+	if err != nil || !strings.Contains(strings.Join(e.Caveats, "\n"), "gets the fail-closed reply there") ||
+		!strings.Contains(strings.Join(e.Caveats, "\n"), "the device refuses it") {
+		t.Fatalf("%q %v", e.Caveats, err)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/`
Expected: FAIL, build failed: `undefined: FindingProjection`, `undefined: FindingProjectionOverflow`,
`undefined: ProjectionRefusals`, `undefined: FindingProjectionRefused`; and `--- FAIL:
TestPolicyTestPrintsReportsNotesAndScheduledQuarantines: missing "; 1 quarantined, 0 projection
refusals\n"`, `code 0`.

- [ ] **Step 3: Add the caveats, the findings and the exit**

<!-- patch: cmd/port49/policy.go -->
````diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 9bc5239..42ab167 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -111,9 +111,11 @@ func policyCmd(args []string, stdout, stderr io.Writer) int {
 
 // policyTest is the CI gate (spec §11, §12): it loads the policy against the
 // inventory — every load-time check is a failure here — prints what CI must
-// report without refusing, the shadowed-deny report, then runs the file's
-// tests. It exits 1 if the policy does not load, any test fails, or a deny is
-// shadowed and no test exercises it.
+// report, the shadowed-deny report, then runs the file's tests. It exits 1 if
+// the policy does not load, any test fails, a deny is shadowed and no test
+// exercises it, a device is quarantined now or at a later expiry, or a
+// composition gets a projection's fail-closed reply (spec §8, "CI MUST refuse
+// the policy"; §13 decision 26).
 func policyTest(args []string, stdout, stderr io.Writer) int {
 	fs := flag.NewFlagSet("port49 policy test", flag.ContinueOnError)
 	fs.SetOutput(stderr)
@@ -142,18 +144,21 @@ func policyTest(args []string, stdout, stderr io.Writer) int {
 	// The set the policy renders with, first: a reviewer reading a rendering
 	// change needs to know which adapters produced it (spec §8).
 	fmt.Fprintf(stdout, "platform_set: %s\n", p.PlatformSet())
-	// A quarantined device is reported, not a failure of its own: the policy
-	// loaded, and decision 20 exists so one device cannot block the rest. A
-	// test on it fails in the ordinary way, as device_quarantined. An entry an
-	// expiry will bring on is reported too, so CI sees it before it lands.
+	// A quarantined device fails the gate: the daemon still loads the policy
+	// and serves the rest (decision 20), but CI refuses to ship one. An entry
+	// an expiry will bring on fails it too, so CI sees it before it lands.
+	quarantined := 0
 	for _, q := range p.Quarantines(now) {
 		for _, e := range q.Entries {
+			quarantined++
 			fmt.Fprintf(stdout, "quarantine: %s (%s): %s\n", q.Device, q.Platform, quarantineLine(e, now))
 		}
 	}
-	for _, f := range p.Lint(now) {
+	findings := p.Lint(now)
+	for _, f := range findings {
 		fmt.Fprintf(stdout, "report: %s: %s\n", f.Kind, f.Message)
 	}
+	refused := policy.ProjectionRefusals(findings)
 	// An acknowledge: entry is the author's written word for a widening no
 	// test can show (spec §12); review reads each one.
 	for _, a := range p.Acknowledgments() {
@@ -253,9 +258,9 @@ func policyTest(args []string, stdout, stderr io.Writer) int {
 			fmt.Fprintf(stdout, "     note: %s\n", c)
 		}
 	}
-	fmt.Fprintf(stdout, "%d tests, %d failed; %d shadowed denies, %d unacknowledged\n", len(results), failed,
-		len(shadows), unacknowledged)
-	if failed > 0 || unacknowledged > 0 {
+	fmt.Fprintf(stdout, "%d tests, %d failed; %d shadowed denies, %d unacknowledged; %d quarantined, %d "+
+		"projection refusals\n", len(results), failed, len(shadows), unacknowledged, quarantined, refused)
+	if failed > 0 || unacknowledged > 0 || quarantined > 0 || refused > 0 {
 		return 1
 	}
 	return 0
````

<!-- patch: internal/policy/explain.go -->
````diff
diff --git a/internal/policy/explain.go b/internal/policy/explain.go
index 7afdbde..086cbf8 100644
--- a/internal/policy/explain.go
+++ b/internal/policy/explain.go
@@ -133,10 +133,21 @@ func (p *Policy) Explain(subject, principal, device, line string, now time.Time)
 				"no command in this session is asked of port49, and a revocation or a session ceiling does not "+
 				"reach a live session there (spec §5.6)", d.Platform, strings.Join(dialect.Supports, ", ")))
 		}
+		if pr := res.Projection; pr != nil {
+			e.Caveats = append(e.Caveats, fmt.Sprintf("the reply projects these rules as the %s shape (spec §8): what "+
+				"the device runs is its class ∩ the wire, and the class half is the device's configuration, outside "+
+				"port49 (port49 platform export --classes prints the reference)", pr.Shape))
+			if pr.FailClosed != "" {
+				e.Caveats = append(e.Caveats, fmt.Sprintf("the composition cannot be told to %s faithfully (%s): %s; "+
+					"this subject gets the fail-closed reply there, and policy test fails on it (spec §13 decision 26)",
+					d.Platform, pr.FailClosed, pr.Refusal.Why))
+			}
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
index 9a91683..ad27049 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -11,6 +11,7 @@ import (
 	"github.com/blanketfish/port49/internal/admission"
 	"github.com/blanketfish/port49/internal/engine"
 	"github.com/blanketfish/port49/internal/platform"
+	"github.com/blanketfish/port49/internal/projection"
 )
 
 // Finding is something CI reports about a policy that loads: not an error,
@@ -40,6 +41,23 @@ const (
 	// FindingDeviceConfigSecretLiteral is a `platforms:` block's device_config
 	// line carrying a value redaction hides (spec §5.8).
 	FindingDeviceConfigSecretLiteral = "device_config_secret_literal"
+	// FindingProjection is how a composition's rules render on a projected
+	// platform: the shape, the bits, what each regex carries, and where the
+	// device is narrower than port49 (spec §8).
+	FindingProjection = "projection"
+	// FindingProjectionOverflow is a reply attribute past RFC 8907's length:
+	// the subject gets the fail-closed reply, and where the attribute is
+	// deny-commands the finding prints the class line that would carry the
+	// denies on the device instead (spec §8). Never for allow-commands: a
+	// class allow runs for every subject at that template, past their own
+	// denies (L11). It fails `policy test`.
+	FindingProjectionOverflow = "projection_overflow"
+	// FindingProjectionRefused is a composition a projected platform cannot
+	// be told faithfully, naming the subject, the devices and the reason: the
+	// subject gets the fail-closed reply there and everyone else keeps
+	// theirs (spec §13 decision 26). It fails `policy test`, as spec §8's
+	// "CI MUST refuse the policy" requires.
+	FindingProjectionRefused = "projection_refused"
 )
 
 // Lint computes the findings at now, ordered by kind and then message so two
@@ -140,6 +158,7 @@ func (p *Policy) Lint(now time.Time) []Finding {
 		}
 	}
 	out = append(out, p.redundantOverrides()...)
+	out = append(out, p.Projections(now)...)
 	out = append(out, p.intersections(now)...)
 	if len(p.tests) == 0 {
 		add(FindingNoTests, "the policy has no tests: nothing in it acknowledges a shadowed deny, an expansion or "+
@@ -517,3 +536,143 @@ func (p *Policy) onGeneric(name string) bool {
 	_, shipped := builtin[name]
 	return b.Replace || !shipped
 }
+
+// Projections reports each composition on a projected platform (spec §8,
+// "CI reports which shape each grant rendered under, the bit set it chose"):
+// once per subject, platform and reply, at now and at every later grant
+// expiry. A composition that gets the fail-closed reply is a
+// projection_refused finding, or projection_overflow where a reply attribute
+// is past RFC 8907's length, naming the subject, every device it lands on
+// and why; both fail `policy test` (spec §13 decision 26).
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
+	type refusal struct {
+		kind, msg string
+		devices   []string
+	}
+	var refusals []*refusal
+	index := map[string]*refusal{}
+	for _, name := range sortedKeys(p.subs) {
+		for _, d := range p.env.Devices {
+			if !p.dialect(d.Platform).Projected() {
+				continue
+			}
+			for _, at := range p.expiryInstants(now) {
+				res, err := p.resolve(p.subs[name], d, at)
+				if err != nil || res.Projection == nil {
+					continue // a quarantine or a refused mint, reported as one
+				}
+				pr := *res.Projection
+				if pr.FailClosed == "" {
+					add(FindingProjection, projectionMessage(name, d.Platform, pr, patterns))
+					continue
+				}
+				kind, msg := refusedMessage(name, d.Platform, pr, patterns)
+				r := index[kind+msg]
+				if r == nil {
+					r = &refusal{kind: kind, msg: msg}
+					index[kind+msg] = r
+					refusals = append(refusals, r)
+				}
+				if !slices.Contains(r.devices, d.Name) {
+					r.devices = append(r.devices, d.Name)
+				}
+			}
+		}
+	}
+	for _, r := range refusals {
+		slices.Sort(r.devices)
+		add(r.kind, strings.Replace(r.msg, "%DEVICES%", strings.Join(r.devices, ", "), 1))
+	}
+	return out
+}
+
+// ProjectionRefusals counts the findings that fail `policy test`: every
+// composition that gets the fail-closed reply (spec §8, "CI MUST refuse").
+func ProjectionRefusals(findings []Finding) int {
+	n := 0
+	for _, f := range findings {
+		if f.Kind == FindingProjectionRefused || f.Kind == FindingProjectionOverflow {
+			n++
+		}
+	}
+	return n
+}
+
+// refusedMessage is a fail-closed composition's finding, the devices left as
+// %DEVICES% for Projections to fill. Every rule and value it quotes is
+// redacted (spec §5.8; plan 5b pre-flight M9). The refusal's own text quotes
+// only rules the secret check passed: a composition with a rule redaction
+// would hide is refused as secret_rule, whose text names only the role.
+func refusedMessage(subject, platformName string, pr projection.Result, patterns []platform.Redaction) (string, string) {
+	r := pr.Refusal
+	var allows []string
+	for _, a := range pr.Allows {
+		allows = append(allows, a.Rule)
+	}
+	told := "every command denied"
+	if len(allows) > 0 {
+		told = "every command denied but " + strings.Join(redacted(patterns, allows), "; ")
+	}
+	msg := fmt.Sprintf("subject %q on %s (%%DEVICES%%) gets the fail-closed reply (%s): %s; it is told %s, and "+
+		"every other subject on those devices keeps its reply (spec §13 decision 26)", subject, platformName,
+		pr.FailClosed, r.Why, told)
+	if pr.FailClosed != projection.FailOverflow {
+		return FindingProjectionRefused, msg
+	}
+	if r.Class != "" {
+		msg += fmt.Sprintf("; the class line that carries the denies on the device instead, binding every subject at "+
+			"that template: set system login class %s %s %q", r.Class, r.Attribute,
+			strings.Join(redacted(patterns, []string{r.Value}), ""))
+	}
+	return FindingProjectionOverflow, msg
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
index da7e8a2..afe25c2 100644
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
@@ -108,6 +113,36 @@ func Caveats(platformName string, dialect platform.Dialect, o engine.Outcome) []
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
+	if pr.FailClosed != "" {
+		out = append(out, fmt.Sprintf("the composition cannot be told to %s faithfully (%s), so this subject gets "+
+			"the fail-closed reply there: every command denied but what the projection proved (spec §13 decision "+
+			"26); policy test fails on it", platformName, pr.FailClosed))
+	}
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
@@ -198,6 +233,7 @@ func (p *Policy) RunTests(now time.Time) []TestResult {
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
git add cmd/port49/policy.go cmd/port49/policy_test.go internal/policy/explain.go internal/policy/lint.go internal/policy/projection_test.go internal/policy/tests.go
git commit -m "$(cat <<'EOF'
feat: policy test reports each projection and fails on a fail-closed reply or a quarantine

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: policy diff judges a projected reply by what the device can do, and refuses a fail-closed one

**Files:**
- Modify: `internal/projection/model.go` (`model.held`, `programs`, `probes`, `Widens`)
- Modify: `internal/policy/diff.go` (`Diff.Projections`, `ProjectionChange`, `projectionChange`,
  `Diff.ProjectionRefusals`, `projectionRose`; `levelChange` takes the two projections)
- Modify: `cmd/port49/policy.go` (the `projection:` and `REFUSED:` lines, `projectionText`, the exit)
- Test: `internal/projection/project_test.go`, `internal/policy/projection_test.go`,
  `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: Task 9's `Resolution.Projection`; Task 11's `Projections` and finding kinds; the
  diff's `side`, `group`, `once`, `levelChange`, `replyRose`.
- Produces:
  - `func projection.Widens(from, to *Result) ([]string, bool)`;
  - `Diff.Projections []ProjectionChange` and `Diff.ProjectionRefusals []Finding`;
  - `type ProjectionChange struct{ Subject string; Devices []string; At time.Time; OldShape, NewShape
    string; OldBits, NewBits []string; OldTemplate, NewTemplate string }`;
  - `projectionText(shape string, bits []string, template string) string` in cmd/port49.

**The reply gate on a projected platform** (pre-flight I14, ruled by the controller once C1, I2
and I3 were fixed). The C4 ruling judged a reply change whole because the gate could not read its
direction. With the device model sound, it can: `projection.Widens` reports a bit the new reply
holds that the old did not, or a command the device runs under the new reply and not the old,
among one probe per way either reply's rules can be told apart. Only that is a `reply` raise; a
pure narrowing — a revoked permit, an added deny — is reported and needs no `reply:` test, so an
emergency revocation is not held up by snapshot tests. A projection that went away is a raise.
Attributes the projection does not own keep the existing judgment. The proof that the device runs
nothing port49 denies is what makes this safe; the effective-permission diff still gates the rule
changes themselves.

The diff also prints a `projection:` line when a composition's shape, bits or template moved, as
spec §8 asks, and a `REFUSED:` line for every fail-closed composition in the new version, new or
not, and exits non-zero on any (decision 26).

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/policy_test.go -->
````diff
diff --git a/cmd/port49/policy_test.go b/cmd/port49/policy_test.go
index 45bb4b8..ee6d885 100644
--- a/cmd/port49/policy_test.go
+++ b/cmd/port49/policy_test.go
@@ -791,7 +791,7 @@ func TestPolicyDiffGatesAnAdapterEdit(t *testing.T) {
 	var out, errb bytes.Buffer
 	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
 		!strings.Contains(out.String(), `ADAPTER: platforms.arista_eos.entity_classes {"loopback":`) ||
-		!strings.Contains(out.String(), "; 1 unacknowledged adapter edits\n") {
+		!strings.Contains(out.String(), "; 1 unacknowledged adapter edits; 0 projection refusals\n") {
 		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
 	}
 	// The entry is printed ready to paste, bound by digest to this edit.
@@ -961,3 +961,17 @@ key_groups:
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
index 34aeccc..498595f 100644
--- a/internal/policy/projection_test.go
+++ b/internal/policy/projection_test.go
@@ -4,6 +4,7 @@ import (
 	"fmt"
 	"net/netip"
 	"reflect"
+	"slices"
 	"strings"
 	"testing"
 	"time"
@@ -327,3 +328,47 @@ func TestARefusalIsAFinding(t *testing.T) {
 		t.Fatalf("%q %v", e.Caveats, err)
 	}
 }
+
+// The diff reports a reply whose shape or bits moved, and the reply gate
+// judges it by what the device can do: a carve-out only narrows, so it is no
+// raise, and lifting it again is (plan 5b pre-flight I14).
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
+	if d.UnacknowledgedLevels() != 0 {
+		t.Errorf("a narrowing is no raise: %+v", d.Levels)
+	}
+	d = Compare(after, before, noon)
+	if d.UnacknowledgedLevels() == 0 || !slices.Contains(d.Levels[0].Raised, "reply") {
+		t.Errorf("a widening is a raise until a reply: test asserts it: %+v", d.Levels)
+	}
+	// A narrow grant losing a permit is no raise either, though every regex
+	// in its reply changed.
+	narrow := func(permits string) *Policy {
+		return parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: [`+permits+`]}
+`+subjOK+grantOK)
+	}
+	if d := Compare(narrow(`"show version", "show route **"`), narrow(`"show version"`), noon); d.UnacknowledgedLevels() != 0 {
+		t.Errorf("revoking a narrow permit: %+v", d.Levels)
+	}
+}
+
+// A composition that gets the fail-closed reply fails the diff, whether or
+// not the change brought it (spec §8; §13 decision 26).
+func TestTheDiffRefusesAFailClosedReply(t *testing.T) {
+	refused := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
+  - {name: r, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
+`+subjOK+grantOK)
+	d := Compare(refused, refused, noon)
+	if len(d.ProjectionRefusals) != 1 || !strings.Contains(d.ProjectionRefusals[0].Message, "(refused_shape)") {
+		t.Fatalf("%+v", d.ProjectionRefusals)
+	}
+}
````

<!-- patch: internal/projection/project_test.go -->
````diff
diff --git a/internal/projection/project_test.go b/internal/projection/project_test.go
index c482916..09275da 100644
--- a/internal/projection/project_test.go
+++ b/internal/projection/project_test.go
@@ -316,3 +316,39 @@ func TestTheBaselineIsDenied(t *testing.T) {
 		t.Fatalf("%+v %v", res, err)
 	}
 }
+
+// A reply widens where the device can do more under it: a bit it did not
+// hold, or a command it did not run. Narrowing the grant is no widening,
+// whatever the regexes say (plan 5b pre-flight I14).
+func TestWidens(t *testing.T) {
+	project := func(rules ...engine.Rule) *Result {
+		res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, rules...))
+		if err != nil {
+			t.Fatal(err)
+		}
+		return &res
+	}
+	all := project(permit("show **"))
+	carved := project(permit("show **"), deny("show configuration **"))
+	narrow := project(permit("show version"), permit("show interfaces **"))
+	narrower := project(permit("show version"))
+	for _, c := range []struct {
+		name     string
+		from, to *Result
+		want     bool
+	}{
+		{"a carve-out drops a bit", all, carved, false},
+		{"lifting it adds the bit back", carved, all, true},
+		{"a narrow grant loses a permit", narrow, narrower, false},
+		{"and gains it back", narrower, narrow, true},
+		{"nothing before", nil, narrower, true},
+		{"the same reply", narrow, narrow, false},
+	} {
+		if _, got := Widens(c.from, c.to); got != c.want {
+			t.Errorf("%s: %v", c.name, got)
+		}
+	}
+	if v, _ := Widens(narrower, narrow); strings.Join(v, " ") == "" {
+		t.Error("a widening by a command names it")
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/projection/ ./internal/policy/ ./cmd/port49/`
Expected: FAIL, build failed: `undefined: Widens`, `d.Projections undefined (type Diff has no field
or method Projections)`, and `undefined: projectionText`.

- [ ] **Step 3: Judge the reply and report the projection**

<!-- patch: cmd/port49/policy.go -->
````diff
diff --git a/cmd/port49/policy.go b/cmd/port49/policy.go
index 42ab167..7d39f14 100644
--- a/cmd/port49/policy.go
+++ b/cmd/port49/policy.go
@@ -443,6 +443,11 @@ func policyDiff(args []string, stdout, stderr io.Writer) int {
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
@@ -500,15 +505,21 @@ func policyDiff(args []string, stdout, stderr io.Writer) int {
 		fmt.Fprintf(stdout, "%s: %s: %s %q (%s) %s; the commands it matches are not "+
 			"enumerated (spec §12)%s\n", label, on, r.Rule.Verdict, r.Rule.Rule, r.Rule.Role, verb, tail)
 	}
+	// A fail-closed reply fails the diff whether or not the change brought
+	// it: CI refuses a policy that ships one (spec §8; §13 decision 26).
+	for _, f := range d.ProjectionRefusals {
+		fmt.Fprintf(stdout, "REFUSED: %s: %s\n", f.Kind, f.Message)
+	}
 	fmt.Fprintf(stdout, "%d commands changed: %d widen, %d narrow; %d unacknowledged expansions past a deny; "+
 		"%d unacknowledged privilege raises; %d unacknowledged regex-constrained widenings; %d unacknowledged "+
 		"principal or username changes; %d devices newly quarantined, %d released; %d mints newly refused; "+
-		"%d unresolved; %d unacknowledged adapter edits\n", len(d.Changes), widen, narrow, d.Unacknowledged(),
-		d.UnacknowledgedLevels(), d.UnacknowledgedRegex(), d.UnacknowledgedPrincipals(), len(d.Quarantined),
-		len(d.Released), len(d.Refused), len(d.Unresolved), d.UnacknowledgedAdapters())
+		"%d unresolved; %d unacknowledged adapter edits; %d projection refusals\n", len(d.Changes), widen, narrow,
+		d.Unacknowledged(), d.UnacknowledgedLevels(), d.UnacknowledgedRegex(), d.UnacknowledgedPrincipals(),
+		len(d.Quarantined), len(d.Released), len(d.Refused), len(d.Unresolved), d.UnacknowledgedAdapters(),
+		len(d.ProjectionRefusals))
 	if d.Unacknowledged() > 0 || d.UnacknowledgedLevels() > 0 || d.UnacknowledgedRegex() > 0 ||
 		d.UnacknowledgedPrincipals() > 0 || len(d.Quarantined) > 0 || len(d.Refused) > 0 || len(d.Unresolved) > 0 ||
-		d.UnacknowledgedAdapters() > 0 {
+		d.UnacknowledgedAdapters() > 0 || len(d.ProjectionRefusals) > 0 {
 		return 1
 	}
 	return 0
@@ -853,3 +864,17 @@ func redactOutput(stdout, stderr io.Writer) (out, errOut *redacting, flush func(
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
index a4ce029..95a98a5 100644
--- a/internal/policy/diff.go
+++ b/internal/policy/diff.go
@@ -16,6 +16,7 @@ import (
 	"github.com/blanketfish/port49/internal/decision"
 	"github.com/blanketfish/port49/internal/engine"
 	"github.com/blanketfish/port49/internal/platform"
+	"github.com/blanketfish/port49/internal/projection"
 )
 
 // Diff is the effective-permission diff between two versions of a policy
@@ -57,6 +58,40 @@ type Diff struct {
 	// inventory has devices of: a platform_set moved, or a `platforms:` block
 	// edited (spec §8, §12).
 	Adapters []AdapterChange
+	// Projections are compositions on a projected platform whose reply
+	// changed shape, bits or template: a change in what the wire says even
+	// where no rule changed (spec §8). Reported; the reply gate is what fails
+	// on one that widens (Levels, "reply"; projection.Widens).
+	Projections []ProjectionChange
+	// ProjectionRefusals are the new version's compositions that get a
+	// projection's fail-closed reply, each naming the subject, the devices
+	// and why (Policy.Projections). Every one fails the diff, new or not:
+	// spec §8's "CI MUST refuse the policy" (§13 decision 26).
+	ProjectionRefusals []Finding
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
@@ -392,6 +427,11 @@ func Compare(before, after *Policy, now time.Time) Diff {
 	}
 	c.principals(now)
 	c.adapters()
+	for _, f := range after.Projections(now) {
+		if f.Kind == FindingProjectionRefused || f.Kind == FindingProjectionOverflow {
+			c.d.ProjectionRefusals = append(c.d.ProjectionRefusals, f)
+		}
+	}
 	for _, a := range after.acked {
 		if !c.usedAcks[a] {
 			c.d.StaleAcknowledgments = append(c.d.StaleAcknowledgments, a)
@@ -643,7 +683,12 @@ func (c *comparison) group(subject string, devices []string, was, is side, at ti
 			OldLevel: wr.Level, NewLevel: ir.Level, OldCeiling: wr.Ceiling, NewCeiling: ir.Ceiling,
 			OldPrivLvl: was.priv.device, NewPrivLvl: is.priv.device, OldEnable: was.priv.enable,
 			NewEnable: is.priv.enable, OldReply: splitReply(was.priv.reply), NewReply: splitReply(is.priv.reply)},
-			was.priv, is.priv))
+			was.priv, is.priv, wr.Projection, ir.Projection))
+	}
+	if pc, ok := projectionChange(wr.Projection, ir.Projection); ok && c.once("projection", subject, on, pc.OldShape,
+		pc.NewShape, strings.Join(pc.OldBits, " "), strings.Join(pc.NewBits, " "), pc.OldTemplate, pc.NewTemplate) {
+		pc.Subject, pc.Devices, pc.At = subject, devices, at
+		c.d.Projections = append(c.d.Projections, pc)
 	}
 	if was.hash == is.hash {
 		return
@@ -806,8 +851,13 @@ func (p *Policy) regexAcks(before *Policy, instants []time.Time) map[string]bool
 //   - enable: the mechanism went from none to token, or to auto, which asks
 //     for nothing more than a login;
 //   - reply: the session reply gained, changed or lost an attribute that
-//     bears privilege on the platform, priv-lvl aside.
-func (c *comparison) levelChange(l LevelChange, was, is privilege) LevelChange {
+//     bears privilege on the platform, priv-lvl aside. On a projected
+//     platform the projection's own attributes are judged by what the device
+//     can do under them instead (projection.Widens): a bit it did not hold,
+//     or a command it did not run, is a raise, and a reply that only narrows
+//     is not, whatever its regexes say (plan 5b pre-flight I14). The proof
+//     that the device runs nothing port49 denies is what makes that safe.
+func (c *comparison) levelChange(l LevelChange, was, is privilege, wasProj, isProj *projection.Result) LevelChange {
 	rose := func(from, to string) bool {
 		return from != to && to != "" && (c.before.levelIndex(to) > c.before.levelIndex(from) ||
 			c.after.levelIndex(to) > c.after.levelIndex(from))
@@ -832,7 +882,17 @@ func (c *comparison) levelChange(l LevelChange, was, is privilege) LevelChange {
 	before, after := c.before.dialect(was.platform), c.after.dialect(is.platform)
 	oldRendered, _, _ := c.before.render(before, was.level)
 	newRendered, _, _ := c.after.render(after, is.level)
-	if replyRose(l.OldReply, l.NewReply, oldRendered, newRendered, before, after) {
+	oldReply, newReply := l.OldReply, l.NewReply
+	projected := before.Projected() || after.Projected()
+	if projected {
+		owned := func(a string) bool {
+			return before.ProjectionOwns(engine.AttributeName(a)) || after.ProjectionOwns(engine.AttributeName(a))
+		}
+		oldReply = slices.DeleteFunc(slices.Clone(oldReply), owned)
+		newReply = slices.DeleteFunc(slices.Clone(newReply), owned)
+	}
+	if replyRose(oldReply, newReply, oldRendered, newRendered, before, after) ||
+		projected && projectionRose(wasProj, isProj) {
 		l.Raised = append(l.Raised, "reply")
 	}
 	l.Raise = len(l.Raised) > 0
@@ -850,6 +910,18 @@ func (c *comparison) levelChange(l LevelChange, was, is privilege) LevelChange {
 	return l
 }
 
+// projectionRose reports whether a projected reply lets the device do more:
+// it widens (projection.Widens), or the projection went away, after which the
+// device runs whatever its template user's class does, which port49 cannot
+// read.
+func projectionRose(was, is *projection.Result) bool {
+	if is == nil {
+		return was != nil
+	}
+	_, widens := projection.Widens(was, is)
+	return widens
+}
+
 // replyRose reports whether the session reply gained, changed or lost an
 // attribute, other than priv-lvl, which priv_lvl judges, that bears privilege
 // under either version's adapter or any shipped set, other than by provably
````

<!-- patch: internal/projection/model.go -->
````diff
diff --git a/internal/projection/model.go b/internal/projection/model.go
index d53e729..35be170 100644
--- a/internal/projection/model.go
+++ b/internal/projection/model.go
@@ -21,6 +21,9 @@ import (
 // widest reading, which for the reach errs toward the device running more.
 type model struct {
 	port, allow, deny, reach, carve *engine.Program
+	// held is every bit the session holds, `all` expanded and the baseline
+	// in: what configuration mode, which no probe reaches, is read from.
+	held []string
 }
 
 func (g generator) model(res Result) (*model, error) {
@@ -55,6 +58,7 @@ func (g generator) model(res Result) (*model, error) {
 		return nil, err
 	}
 	held := g.held(res.Bits)
+	m.held = held
 	if m.reach, err = prog(parsed(g.reach(held), "reach")); err != nil {
 		return nil, err
 	}
@@ -88,12 +92,50 @@ func (m *model) device(vector []string) bool {
 // less those with a word the device's parser never sees: empty, or with a
 // space at either end. The parser splits a line on whitespace, so such a
 // vector is its trimmed form, which is probed in its own right.
-func (m *model) probes() [][]string {
-	return slices.DeleteFunc(engine.Probes(m.port, m.allow, m.deny, m.reach, m.carve), func(v []string) bool {
+func (m *model) probes() [][]string { return probes(m.programs()...) }
+
+func (m *model) programs() []*engine.Program {
+	return []*engine.Program{m.port, m.allow, m.deny, m.reach, m.carve}
+}
+
+func probes(programs ...*engine.Program) [][]string {
+	return slices.DeleteFunc(engine.Probes(programs...), func(v []string) bool {
 		return slices.ContainsFunc(v, func(w string) bool { return w == "" || strings.TrimSpace(w) != w })
 	})
 }
 
+// Widens reports whether the device can do more under to than under from:
+// to holds a bit from does not, or runs a command from does not, among one
+// vector per way either reply's rules can be told apart. It is how the diff
+// judges a projected reply (spec §12; plan 5b pre-flight I14): a reply that
+// only narrows is no raise, whatever its regexes say, and one that widens
+// is. A side with no projection runs nothing and holds no bit. The vector is
+// nil where a bit decided it.
+func Widens(from, to *Result) ([]string, bool) {
+	if to == nil || to.model == nil {
+		return nil, false
+	}
+	var was *model
+	if from != nil {
+		was = from.model
+	}
+	for _, b := range to.model.held {
+		if was == nil || !slices.Contains(was.held, b) {
+			return nil, true
+		}
+	}
+	progs := to.model.programs()
+	if was != nil {
+		progs = append(progs, was.programs()...)
+	}
+	for _, v := range probes(progs...) {
+		if len(v) > 0 && to.model.device(v) && (was == nil || !was.device(v)) {
+			return v, true
+		}
+	}
+	return nil, false
+}
+
 // unsound is a command the device would run and port49 would deny, among one
 // vector per way the rules can be told apart (engine.Probes).
 func (m *model) unsound() ([]string, bool) {
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/policy.go cmd/port49/policy_test.go internal/policy/diff.go internal/policy/projection_test.go internal/projection/model.go internal/projection/project_test.go
git commit -m "$(cat <<'EOF'
feat: policy diff judges a projected reply by what the device can do, and refuses a fail-closed one

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: platform export --classes writes the reference as a replace, and check-config holds a device to it

**Files:**
- Create: `internal/platform/classes.go` (`lockTemplates`, `ReferenceClasses`, `templates`,
  `TemplateDrift`)
- Modify: `internal/config/config.go` (`DefaultMaxSessionAge`, `MaxSessionAge`; Load uses the
  constant)
- Modify: `cmd/port49/platform.go` (`--classes`, `--config`, `exportClasses`), `cmd/port49/devices.go`
  (`check-config --config` and the template check), `cmd/port49/main.go` (usage)
- Test: `internal/platform/classes_test.go` (new), `internal/config/config_test.go`,
  `cmd/port49/platform_test.go`, `cmd/port49/devices_test.go`

**Interfaces:**
- Consumes: Task 6's `Projected`, `DeviceConfig`, `CeilingBits`, `LocalUserNames`, `BitDelivery`,
  `RemoteClass`; 5a's `platformShow`, `adapters.load`, `RedactAdapter`, `eachLine`, `ConfigFinding`.
- Produces:
  - `func ReferenceClasses(d Dialect, maxSessionAge time.Duration) ([]string, error)`;
  - `func TemplateDrift(config []byte, d Dialect, maxSessionAge time.Duration) (missing []string,
    extra []ConfigFinding, err error)`;
  - `var lockTemplates = false`, the one value Task 14's Step 4 may flip;
  - `const config.DefaultMaxSessionAge = 12 * time.Hour`;
  - `func config.MaxSessionAge(raw []byte) (time.Duration, error)`;
  - `port49 platform export --classes --config PORT49D_YAML PLATFORM` and `port49 devices
    check-config ... [--config PORT49D_YAML] CONFIGFILE`.

Decision 21's enforced approximation is `idle-timeout` in the class, from `max_session_age`, and
spec §8 requires the reference class per level to be published. **The reference is a replace**
(pre-flight I8): each template class and user is a `delete` followed by its `set` lines, so loading
it leaves nothing a device carried under one, such as a class `allow-commands`, which beats every
wire deny (L11), or a stale bit. `ReferenceClasses` prints:
- the adapter's `device_config`;
- `delete system login class p49-remote`, its `idle-timeout N`, `delete system login user remote`
  and `user remote class p49-remote`;
- under `local_user_name`, each template the same way, its class carrying the level's bits one
  `permissions` line each, as `display set` prints them.

N is whole minutes rounded down, at least 1. No template user carries `authentication`: Juniper
documents a template user as one with no authentication, which cannot log in locally, and Task 2
measures it; `lockTemplates` adds `authentication encrypted-password "*"` to each only if Task 14
finds otherwise (Decided 18). No uid is written; Task 2 measures that too.

`TemplateDrift` is `check-config`'s half (pre-flight I8, M8). It reads a `show configuration |
display set` capture: each reference line the device lacks is `TEMPLATE: ...: the configuration
does not carry this line`, and each line under a template class or user the reference does not
write is `TEMPLATE: file:N: ...` — a class `allow-commands`, an extra permission, a template's
password — except the uid Junos assigns. A capture with no `set` line is an error that says to
use `display set`. On a projected platform `check-config` requires `--config`, since the reference
carries the idle-timeout; elsewhere `--config` is a usage error. `config.MaxSessionAge` reads
`session.max_session_age_default` alone, so neither command needs the daemon's secrets. On 1.0.0
Junos projects nothing and the export says so; Task 14's tests cover the success paths.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/devices_test.go -->
````diff
diff --git a/cmd/port49/devices_test.go b/cmd/port49/devices_test.go
index 3bd2e72..00e7598 100644
--- a/cmd/port49/devices_test.go
+++ b/cmd/port49/devices_test.go
@@ -359,3 +359,22 @@ func TestCheckConfigWarnsOnAPartialCapture(t *testing.T) {
 		t.Errorf("whole:\n%s", out)
 	}
 }
+
+// --config goes with a projected platform alone: it is the template
+// classes' idle-timeout, and a platform that projects nothing has none.
+func TestCheckConfigTakesConfigOnlyOnAProjectedPlatform(t *testing.T) {
+	pol, inv := policyFixture(t)
+	dir := t.TempDir()
+	cfg, daemon := filepath.Join(dir, "leaf-01.cfg"), filepath.Join(dir, "port49d.yaml")
+	if err := os.WriteFile(cfg, []byte("hostname leaf-01\n"), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	if err := os.WriteFile(daemon, []byte("session: {max_session_age_default: 8h}\n"), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	if code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01",
+		"--config", daemon, cfg}, &out, &errb); code != 2 {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+}
````

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
index 0000000..f3a4363
--- /dev/null
+++ b/internal/platform/classes_test.go
@@ -0,0 +1,88 @@
+package platform
+
+import (
+	"reflect"
+	"strings"
+	"testing"
+	"time"
+)
+
+// The reference replaces each template class and user, a delete before its
+// set lines, so nothing a device carried under one survives the load (I8).
+// The classes carry the level's bits, one per line, and an idle-timeout from
+// max_session_age (decision 21); the remote template has no bits, and no
+// template user can log in locally (I9).
+func TestReferenceClasses(t *testing.T) {
+	d := junosProjected(BitDeliveryLocalUserName)
+	d.DeviceConfig = []string{"set system tacplus-options strict-authorization"}
+	got, err := ReferenceClasses(d, 12*time.Hour+59*time.Second)
+	if err != nil {
+		t.Fatal(err)
+	}
+	want := []string{
+		"set system tacplus-options strict-authorization",
+		"delete system login class p49-remote",
+		"set system login class p49-remote idle-timeout 720",
+		"delete system login user remote",
+		"set system login user remote class p49-remote",
+		"delete system login class p49-admin",
+		"set system login class p49-admin permissions all",
+		"set system login class p49-admin idle-timeout 720",
+		"delete system login user p49-admin",
+		"set system login user p49-admin class p49-admin",
+		"delete system login class p49-readonly",
+		"set system login class p49-readonly permissions view",
+		"set system login class p49-readonly permissions view-configuration",
+		"set system login class p49-readonly idle-timeout 720",
+		"delete system login user p49-readonly",
+		"set system login user p49-readonly class p49-readonly",
+	}
+	if !reflect.DeepEqual(got, want) {
+		t.Fatalf("%q", got)
+	}
+	for _, l := range got {
+		if strings.Contains(l, "authentication") {
+			t.Errorf("a template user that can log in locally: %s", l)
+		}
+	}
+	up, _ := ReferenceClasses(junosProjected(BitDeliveryUserPermissions), 30*time.Second)
+	if len(up) != 4 || up[1] != "set system login class p49-remote idle-timeout 1" {
+		t.Fatalf("user_permissions: %q", up)
+	}
+	eos, _ := DialectFor("arista_eos")
+	if _, err := ReferenceClasses(eos, time.Hour); err == nil {
+		t.Error("a platform that projects nothing has no classes")
+	}
+}
+
+// The template check reads a display-set configuration against the
+// reference: a line it lacks, and any line under a template class or user it
+// does not write — a class allow-commands (M8), a template password — are
+// drift; the uid Junos assigns is not (I8, I9).
+func TestTemplateDrift(t *testing.T) {
+	d := junosProjected(BitDeliveryLocalUserName)
+	ref, _ := ReferenceClasses(d, time.Hour)
+	var config []string
+	for _, l := range ref {
+		if !strings.HasPrefix(l, "delete ") {
+			config = append(config, l)
+		}
+	}
+	config = append(config, "set system login user p49-admin uid 2001", "set system host-name srx1")
+	missing, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, time.Hour)
+	if err != nil || len(missing) != 0 || len(extra) != 0 {
+		t.Fatalf("clean: %q %+v %v", missing, extra, err)
+	}
+	drifted := append(config[1:], `set system login class p49-remote allow-commands "^configure"`,
+		`set system login user p49-readonly authentication encrypted-password "$6$x"`,
+		"set system login class p49-readonly permissions   clear")
+	missing, extra, err = TemplateDrift([]byte(strings.Join(drifted, "\n")), d, time.Hour)
+	if err != nil || !reflect.DeepEqual(missing, []string{config[0]}) || len(extra) != 3 ||
+		extra[2].Text != "set system login class p49-readonly permissions clear" {
+		t.Fatalf("drift: %q %+v %v", missing, extra, err)
+	}
+	if _, _, err := TemplateDrift([]byte("system {\n  login {\n  }\n}\n"), d, time.Hour); err == nil ||
+		!strings.Contains(err.Error(), "display set") {
+		t.Fatalf("curly form: %v", err)
+	}
+}
````

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/config/ ./cmd/port49/`
Expected: FAIL, build failed: `undefined: ReferenceClasses`, `undefined: TemplateDrift`,
`undefined: DefaultMaxSessionAge`, `undefined: MaxSessionAge`.

- [ ] **Step 3: Add the export and the check**

<!-- patch: cmd/port49/devices.go -->
````diff
diff --git a/cmd/port49/devices.go b/cmd/port49/devices.go
index c56188d..fe4847c 100644
--- a/cmd/port49/devices.go
+++ b/cmd/port49/devices.go
@@ -9,6 +9,7 @@ import (
 	"strings"
 	"time"
 
+	daemonconfig "github.com/blanketfish/port49/internal/config"
 	"github.com/blanketfish/port49/internal/platform"
 	"github.com/blanketfish/port49/internal/username"
 )
@@ -27,6 +28,13 @@ import (
 // device; this reads a file a compliance tool fetched (spec §8,
 // "Verification").
 //
+// On a projected platform it also reads the configuration, in `display set`
+// form, against the reference `platform export --classes` writes, whose
+// idle-timeout comes from --config's port49d.yaml, which is then required:
+// every reference line the device lacks, and every line under a template
+// class or user the reference does not write (platform.TemplateDrift; plan 5b
+// pre-flight I8).
+//
 // A device's configuration is full of secrets — communities, keys, enable
 // secrets, a URL's password — so every line of it this prints is redacted by
 // every pattern that applies under the policy, and a line that could not be
@@ -37,6 +45,8 @@ func checkConfig(args []string, stdout, stderr io.Writer) int {
 	var files policyFiles
 	files.register(fs)
 	device := fs.String("device", "", "the device the configuration is from, by its inventory name")
+	cfgPath := fs.String("config", "", "port49d.yaml, whose session.max_session_age_default is the template "+
+		"classes' idle-timeout (required on a projected platform)")
 	if err := fs.Parse(args); err != nil {
 		return 2
 	}
@@ -96,7 +106,44 @@ func checkConfig(args []string, stdout, stderr io.Writer) int {
 		fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", fs.Arg(0), err)
 		return 1
 	}
+	var templateMissing []string
+	var drift []platform.ConfigFinding
+	if dialect.Projected() {
+		if *cfgPath == "" {
+			fmt.Fprintf(stderr, "port49 devices check-config: %s projects the policy into its session reply, so its "+
+				"template classes are checked against the reference, whose idle-timeout is port49d.yaml's "+
+				"session.max_session_age_default: pass --config\n", d.Platform)
+			return 2
+		}
+		raw, err := os.ReadFile(*cfgPath)
+		if err != nil {
+			fmt.Fprintln(stderr, "port49 devices check-config:", err)
+			return 1
+		}
+		age, err := daemonconfig.MaxSessionAge(raw)
+		if err != nil {
+			fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", *cfgPath, err)
+			return 1
+		}
+		if templateMissing, drift, err = platform.TemplateDrift(config, dialect, age); err != nil {
+			fmt.Fprintf(stderr, "port49 devices check-config: %s: %v\n", fs.Arg(0), err)
+			return 1
+		}
+	} else if *cfgPath != "" {
+		fmt.Fprint(stderr, usage)
+		return 2
+	}
 	failed := 0
+	for _, line := range templateMissing {
+		failed++
+		fmt.Fprintf(stdout, "TEMPLATE: %s: %s: the configuration does not carry this line of the reference "+
+			"(port49 platform export --classes): a session under that template is not what the projection "+
+			"proved (spec §8)\n", fs.Arg(0), line)
+	}
+	for _, f := range drift {
+		failed++
+		fmt.Fprintf(stdout, "TEMPLATE: %s:%d: %s: %s\n", fs.Arg(0), f.Line, redact(f.Text), f.Says)
+	}
 	for _, a := range accounts {
 		// The daemon looks a context up by the canonical form of the username
 		// the device sends (spec §2), so a local NOC, CORP\noc or noc@corp
````

<!-- patch: cmd/port49/main.go -->
````diff
diff --git a/cmd/port49/main.go b/cmd/port49/main.go
index 0d7804f..0bf8b27 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -41,9 +41,10 @@ const usage = `usage:
   port49 grants remove --policy FILE --inventory FILE --subject NAME [--write | --pr [--remote R] [--base B]]
   port49 platform list [--set VERSION | --policy FILE --inventory FILE]
   port49 platform show [--set VERSION | --policy FILE --inventory FILE] PLATFORM
-  port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir EMPTY_DIR)
+  port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir EMPTY_DIR |
+                         --classes --config PORT49D_YAML PLATFORM)
   port49 platform upgrade --policy FILE --inventory FILE --to VERSION [--write]
-  port49 devices check-config --policy FILE --inventory FILE --device NAME CONFIGFILE
+  port49 devices check-config --policy FILE --inventory FILE --device NAME [--config PORT49D_YAML] CONFIGFILE
 `
 
 func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
````

<!-- patch: cmd/port49/platform.go -->
````diff
diff --git a/cmd/port49/platform.go b/cmd/port49/platform.go
index a607e68..fc9ed79 100644
--- a/cmd/port49/platform.go
+++ b/cmd/port49/platform.go
@@ -16,6 +16,7 @@ import (
 	"gopkg.in/yaml.v3"
 
 	"github.com/blanketfish/port49/internal/admission"
+	"github.com/blanketfish/port49/internal/config"
 	"github.com/blanketfish/port49/internal/platform"
 	"github.com/blanketfish/port49/internal/policy"
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
@@ -485,3 +493,41 @@ func sortedNames(set map[string]platform.Dialect) []string {
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
+	fmt.Fprintf(stdout, "# %s: reference configuration, platform set %s (spec §8). Load it with `load set "+
+		"terminal`: each template class and user is deleted before it is set, so nothing a device carried under one "+
+		"survives, and `port49 devices check-config --config` verifies it. idle-timeout is "+
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
index 0000000..97df33a
--- /dev/null
+++ b/internal/platform/classes.go
@@ -0,0 +1,154 @@
+package platform
+
+import (
+	"errors"
+	"fmt"
+	"regexp"
+	"slices"
+	"strings"
+	"time"
+)
+
+// lockTemplates is whether each template user's reference carries a locked
+// password line. Juniper documents a template user as one with no
+// authentication, which cannot log in locally; tests/lab/results/L12-juniper_*.md
+// ("template logins") measures that, and this is true only if it found a
+// template user that did accept a local login and that the locked line
+// refuses it (plan 5b Task 14).
+var lockTemplates = false
+
+// lockLine is the line that locks a template user's local login.
+const lockLine = `authentication encrypted-password "*"`
+
+// ReferenceClasses is the device configuration a projected platform's
+// replies rest on, as `set` lines (spec §8, "publish the reference class per
+// privilege level through port49 platform export"): the adapter's
+// device_config lines, then the bitless `remote` template and, under
+// BitDeliveryLocalUserName, each level's template user and class carrying the
+// level's bits, one bit per line as `show configuration | display set`
+// prints them. Each template class and user is written as a replace, a
+// `delete` before its `set` lines, so loading the reference over a device
+// leaves nothing of what was there: a class allow-commands, which would run
+// for every subject at that template past their own denies (L11), or a
+// template user's local password. No template user is one that can log in
+// locally (lockTemplates). Every class carries `idle-timeout` from
+// maxSessionAge, in whole minutes rounded down and at least one: a
+// session-only device never asks port49 again after login, so the class's
+// own timer is the one limit that ends a session there (spec §5.6; §13
+// decision 21).
+func ReferenceClasses(d Dialect, maxSessionAge time.Duration) ([]string, error) {
+	if !d.Projected() {
+		return nil, errors.New("the platform projects nothing, so it has no reference classes; its device_config " +
+			"is what `platform show` prints")
+	}
+	if maxSessionAge <= 0 {
+		return nil, errors.New("max_session_age must be positive: it is the classes' idle-timeout")
+	}
+	out := slices.Clone(d.DeviceConfig)
+	for _, t := range templates(d) {
+		out = append(out, "delete system login class "+t.class)
+		out = append(out, t.lines(maxSessionAge)...)
+	}
+	return out, nil
+}
+
+// template is one template user and its class.
+type template struct {
+	user, class string
+	bits        []string
+}
+
+// templates is `remote`, whose class p49-remote carries no bit, then under
+// BitDeliveryLocalUserName each level's template, in name order.
+func templates(d Dialect) []template {
+	out := []template{{user: "remote", class: RemoteClass}}
+	if d.BitDelivery != BitDeliveryLocalUserName {
+		return out
+	}
+	seen := map[string]bool{}
+	for _, level := range sortedKeys(d.LocalUserNames) {
+		name := d.LocalUserNames[level]
+		if !seen[name] {
+			seen[name] = true
+			out = append(out, template{user: name, class: name, bits: d.CeilingBits[level]})
+		}
+	}
+	return out
+}
+
+// lines is the template's class and user as set lines, without the deletes.
+func (t template) lines(maxSessionAge time.Duration) []string {
+	minutes := max(int64(maxSessionAge/time.Minute), 1)
+	var out []string
+	for _, b := range t.bits {
+		out = append(out, fmt.Sprintf("set system login class %s permissions %s", t.class, b))
+	}
+	out = append(out, fmt.Sprintf("set system login class %s idle-timeout %d", t.class, minutes),
+		"delete system login user "+t.user, fmt.Sprintf("set system login user %s class %s", t.user, t.class))
+	if lockTemplates {
+		out = append(out, fmt.Sprintf("set system login user %s %s", t.user, lockLine))
+	}
+	return out
+}
+
+// uidLine is the uid Junos assigns a login user at commit: the one line under
+// a template user the reference does not write and the check allows.
+var uidLine = regexp.MustCompile(`^set system login user \S+ uid [0-9]+$`)
+
+// TemplateDrift reads a projected platform's device configuration, as `show
+// configuration | display set` prints it, against ReferenceClasses: every
+// reference set line the configuration lacks, and every line under a
+// template class or template user the reference does not write (spec §8; plan
+// 5b pre-flight I8). A class line the reference lacks — an allow-commands,
+// a permission — widens every subject at that template, and a template
+// user's authentication line lets it log in locally, so each is drift. The
+// device_config lines are Missing's. It is an error where the configuration
+// is not in set form, since then nothing could be read.
+func TemplateDrift(config []byte, d Dialect, maxSessionAge time.Duration) (missing []string, extra []ConfigFinding,
+	err error) {
+	if _, err := ReferenceClasses(d, maxSessionAge); err != nil {
+		return nil, nil, err
+	}
+	var want []string
+	var prefixes []string
+	for _, t := range templates(d) {
+		want = append(want, slices.DeleteFunc(t.lines(maxSessionAge), func(l string) bool {
+			return strings.HasPrefix(l, "delete ")
+		})...)
+		prefixes = append(prefixes, "set system login class "+t.class+" ", "set system login user "+t.user+" ")
+	}
+	carried := map[string]bool{}
+	setForm := false
+	err = eachLine(config, func(n int, line string) {
+		line = strings.Join(strings.Fields(line), " ")
+		if !strings.HasPrefix(line, "set ") {
+			return
+		}
+		setForm = true
+		carried[line] = true
+		if slices.Contains(want, line) || uidLine.MatchString(line) {
+			return
+		}
+		for _, p := range prefixes {
+			if strings.HasPrefix(line, p) {
+				extra = append(extra, ConfigFinding{Line: n, Text: line, Says: "a line under a port49 template the " +
+					"reference does not write: it changes what every subject at that template runs, or lets the " +
+					"template user log in locally; load port49 platform export --classes, which replaces the template"})
+				return
+			}
+		}
+	})
+	if err != nil {
+		return nil, nil, err
+	}
+	if !setForm {
+		return nil, nil, errors.New("the configuration has no set line: the template check reads `show configuration " +
+			"| display set`")
+	}
+	for _, l := range want {
+		if !carried[l] {
+			missing = append(missing, l)
+		}
+	}
+	return missing, extra, nil
+}
````

- [ ] **Step 4: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

- [ ] **Step 5: Commit**

```bash
git add cmd/port49/devices.go cmd/port49/devices_test.go cmd/port49/main.go cmd/port49/platform.go cmd/port49/platform_test.go internal/config/config.go internal/config/config_test.go internal/platform/classes.go internal/platform/classes_test.go
git commit -m "$(cat <<'EOF'
feat: platform export --classes writes the reference as a replace, and check-config holds a device to it

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: Platform set 1.1.0: Junos projected, from what L9, L12 and L23 measured, with a fail-closed branch for every outcome

**Files:**
- Create: `platforms/1.1.0/arista_eos.yaml`, `cisco_iosxe.yaml`, `cisco_nxos.yaml` (copies of
  1.0.0's), `platforms/1.1.0/juniper_junos.yaml`
- Modify: `internal/platform/set.go` (`DefaultSet = "1.1.0"`), `internal/platform/dialect.go`
  (`generics["1.1.0"]`), `cmd/port49/platform.go` (`upgradeReport` previews quarantines and
  refusals)
- Modify, only in a Step 4 branch: `internal/projection/project.go` (`JunosFacts`),
  `internal/platform/classes.go`, `cmd/port49/platform.go`'s export header
- Test: `internal/platform/adapter_test.go` (`shipped110`, `releasedGeneric`, the set list),
  `config_test.go`, `dialect_test.go`, `classes_test.go`, `cmd/port49/platform_test.go`

**Interfaces:**
- Consumes: the notes of Tasks 2, 3 and 4; Task 6's keys; Task 13's `ReferenceClasses`,
  `TemplateDrift`, `lockTemplates`; Task 11's `Projections`.
- Produces: set 1.1.0, `platform.DefaultSet == "1.1.0"`, and the test table `shipped110`, which
  Task 20 freezes. In `shipped110`, the line `// What 1.1.0 changes in juniper_junos: the
  projection and what it rests on.` directly follows `j := out["juniper_junos"]`, and every Step 4
  branch edits only below it: Task 20's hunk anchors on those two lines (pre-flight I7).

The patches below are the set as this plan's candidates write it:
- `bit_delivery: local_user_name`, with templates `p49-readonly`, `p49-operator` and `p49-admin`;
- the bits of Decided 11, `baseline` from Task 3's candidate, and the one carve-out,
  `view-configuration: ["show configuration **"]`;
- `ceiling_levels {1, 15, 15}`;
- `device_config` requiring `strict-authorization`; the templates are the reference's (Task 13);
- a `config_checks` entry for bits on `p49-remote`;
- the EOS, NX-OS and IOS-XE files unchanged from 1.0.0.

`platform upgrade` now previews every quarantine and every fail-closed composition the move brings
(pre-flight I10, M10). The tests this task adds assert no candidate value, so each Step 4 branch
leaves them green: they read the shape, the delivery and the keys from the shipped adapter
(pre-flight I6). Step 4 then changes exactly what the lab notes measured differently. Where a note
and a candidate agree, the candidate stands. Where the two Junos images disagree, the value that
denies more stands.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/platform_test.go -->
````diff
diff --git a/cmd/port49/platform_test.go b/cmd/port49/platform_test.go
index 5aeb248..bdaa6dc 100644
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
@@ -649,6 +649,22 @@ func TestPlatformExportClasses(t *testing.T) {
 		&out, &errb); code != 1 || !strings.Contains(errb.String(), "projects nothing") {
 		t.Fatalf("1.0.0: code %d\n%s%s", code, out.String(), errb.String())
 	}
+	out.Reset()
+	if code := run([]string{"platform", "export", "--classes", "--config", cfg, "juniper_junos"}, &out, &errb); code != 0 ||
+		!strings.Contains(out.String(), "platform set 1.1.0") ||
+		!strings.Contains(out.String(), "delete system login class p49-remote\n"+
+			"set system login class p49-remote idle-timeout 480\n") ||
+		!strings.Contains(out.String(), "set system login user remote class p49-remote\n") {
+		t.Fatalf("1.1.0: code %d\n%s%s", code, out.String(), errb.String())
+	}
+	// Each level's template, where the delivery is one, is a replace too.
+	if d, _ := platform.DialectFor("juniper_junos"); d.BitDelivery == platform.BitDeliveryLocalUserName &&
+		!strings.Contains(out.String(), "delete system login class p49-readonly\n"+
+			"set system login class p49-readonly permissions view\n"+
+			"set system login class p49-readonly permissions view-configuration\n"+
+			"set system login class p49-readonly idle-timeout 480\n") {
+		t.Fatalf("templates:\n%s", out.String())
+	}
 	for _, args := range [][]string{
 		{"platform", "show", "--classes", "--config", cfg, "juniper_junos"},
 		{"platform", "export", "--classes", "juniper_junos"},
@@ -660,3 +676,147 @@ func TestPlatformExportClasses(t *testing.T) {
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
+	keys := []string{"command_projection", "bits", "bit_delivery", "privilege"}
+	if d, _ := platform.DialectFor("juniper_junos"); len(d.LocalUserNames) > 0 {
+		keys = append(keys, "local_user_names")
+	}
+	if d, _ := platform.DialectFor("juniper_junos"); len(d.CarveOuts) > 0 {
+		keys = append(keys, "carve_outs")
+	}
+	for _, key := range keys {
+		if !strings.Contains(out.String(), "platforms.juniper_junos."+key+"\n") ||
+			!strings.Contains(out.String(), "field: "+key+", sha256:") {
+			t.Errorf("%s is not reported gated:\n%s%s", key, out.String(), errb.String())
+		}
+	}
+}
+
+// junosFixture is a policy pinned to 1.1.0 with one Junos device: noc
+// permitted every show command, which renders whatever L9 and L12 measured,
+// and for ops a composition the projection cannot carry under any of them,
+// the refused shape (spec §8).
+func junosFixture(t *testing.T) (pol, inv, cfg string) {
+	t.Helper()
+	dir := t.TempDir()
+	pol, inv, cfg = filepath.Join(dir, "policy.yaml"), filepath.Join(dir, "inventory.yaml"),
+		filepath.Join(dir, "port49d.yaml")
+	for path, body := range map[string]string{
+		pol: `platform_set: 1.1.0
+scopes: [{name: all_devices, match: {}}]
+roles:
+  - {name: read_only, privilege: readonly, permit: ["show **"]}
+  - {name: interfaces, privilege: readonly, permit: ["show interfaces **"], deny: ["show interfaces terse"]}
+subjects:
+  - {name: noc, identity: "user:noc@example.com", username: noc, token_ttl: 60s}
+  - {name: ops, identity: "user:ops@example.com", username: ops, token_ttl: 60s}
+grants:
+  - {subject: noc, scope: all_devices, roles: [read_only]}
+  - {subject: ops, scope: all_devices, roles: [interfaces]}
+tests:
+  - {subject: noc, device: srx-01, level: readonly}
+`,
+		inv: `
+devices:
+  - {name: srx-01, platform: juniper_junos, addresses: [10.0.0.9]}
+key_groups:
+  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
+`,
+		cfg: "inventory_file: inventory.yaml\nsession: {max_session_age_default: 8h}\n",
+	} {
+		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
+			t.Fatal(err)
+		}
+	}
+	return pol, inv, cfg
+}
+
+// One subject's composition the projection cannot carry fails policy test
+// and policy diff, naming the subject, the device and why, and platform
+// upgrade previews it; the other subject keeps its reply (spec §8, "CI MUST
+// refuse the policy"; §13 decision 26; plan 5b pre-flight I10).
+func TestAProjectionRefusalFailsTheGates(t *testing.T) {
+	pol, inv, _ := junosFixture(t)
+	var out, errb bytes.Buffer
+	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb)
+	for _, want := range []string{
+		`report: projection_refused: subject "ops" on juniper_junos (srx-01) gets the fail-closed reply (refused_shape)`,
+		`report: projection: subject "noc" on juniper_junos: `,
+		"; 0 quarantined, 1 projection refusals\n",
+	} {
+		if !strings.Contains(out.String(), want) {
+			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
+		}
+	}
+	if code != 1 {
+		t.Fatalf("policy test: code %d", code)
+	}
+	out.Reset()
+	if code := run([]string{"policy", "diff", "--old", pol, "--new", pol, "--inventory", inv}, &out, &errb); code != 1 ||
+		!strings.Contains(out.String(), `REFUSED: projection_refused: subject "ops" on juniper_junos (srx-01)`) {
+		t.Fatalf("policy diff: code %d\n%s%s", code, out.String(), errb.String())
+	}
+	unpinned := filepath.Join(t.TempDir(), "policy.yaml")
+	if err := os.WriteFile(unpinned, []byte(strings.Replace(string(readFile(t, pol)), "platform_set: 1.1.0\n", "", 1)),
+		0o600); err != nil {
+		t.Fatal(err)
+	}
+	out.Reset()
+	if code := run([]string{"platform", "upgrade", "--policy", unpinned, "--inventory", inv, "--to", "1.1.0"}, &out,
+		&errb); code != 0 || !strings.Contains(out.String(),
+		`  projection_refused on 1.1.0: subject "ops" on juniper_junos (srx-01) gets the fail-closed reply`) {
+		t.Fatalf("platform upgrade: code %d\n%s%s", code, out.String(), errb.String())
+	}
+}
+
+// check-config holds a Junos device to the reference export --classes
+// writes: it needs --config for the classes' idle-timeout, passes the
+// reference itself, and fails a template class carrying an allow (I8, M8).
+func TestCheckConfigHoldsAJunosDeviceToTheReference(t *testing.T) {
+	pol, inv, cfg := junosFixture(t)
+	var ref, errb bytes.Buffer
+	if code := run([]string{"platform", "export", "--policy", pol, "--inventory", inv, "--classes", "--config", cfg,
+		"juniper_junos"}, &ref, &errb); code != 0 {
+		t.Fatalf("export: code %d\n%s", code, errb.String())
+	}
+	var lines []string
+	for _, l := range strings.Split(ref.String(), "\n") {
+		if strings.HasPrefix(l, "set ") {
+			lines = append(lines, l)
+		}
+	}
+	device := filepath.Join(t.TempDir(), "srx-01.set")
+	write := func(extra ...string) {
+		if err := os.WriteFile(device, []byte(strings.Join(append(append([]string{"set system host-name srx-01"},
+			lines...), extra...), "\n")+"\n"), 0o600); err != nil {
+			t.Fatal(err)
+		}
+	}
+	write()
+	var out bytes.Buffer
+	args := []string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "srx-01"}
+	if code := run(append(args, device), &out, &errb); code != 2 || !strings.Contains(errb.String(), "pass --config") {
+		t.Fatalf("no --config: code %d\n%s%s", code, out.String(), errb.String())
+	}
+	out.Reset()
+	if code := run(append(args, "--config", cfg, device), &out, &errb); code != 0 {
+		t.Fatalf("the reference: code %d\n%s%s", code, out.String(), errb.String())
+	}
+	write(`set system login class p49-remote allow-commands "^configure"`)
+	out.Reset()
+	if code := run(append(args, "--config", cfg, device), &out, &errb); code != 1 ||
+		!strings.Contains(out.String(), "TEMPLATE: "+device+":") {
+		t.Fatalf("drift: code %d\n%s%s", code, out.String(), errb.String())
+	}
+}
````

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index a884283..f744275 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -12,8 +12,8 @@ import (
 	"github.com/blanketfish/port49/platforms"
 )
 
-// shipped is the default set, value for value: the table plan 4 compiled
-// into the binary, and each change plan 5 made to it with the note behind it.
+// shipped is set 1.0.0, value for value: the table plan 4 compiled into the
+// binary, and each change plan 5a made to it with the note behind it.
 var shipped = map[string]Dialect{
 	"arista_eos": {
 		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
@@ -126,12 +126,39 @@ var shipped = map[string]Dialect{
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
+	// What 1.1.0 changes in juniper_junos: the projection and what it rests on.
+	j.CommandProjection, j.BitDelivery = ProjectionJunosRegex, BitDeliveryLocalUserName
+	j.LocalUserNames = map[string]string{"readonly": "p49-readonly", "operator": "p49-operator", "admin": "p49-admin"}
+	j.Bits = map[string][]string{BaselineBit: {"help **", "quit **", "exit **", "set cli **", "show cli **"},
+		"view": {"show **"}, "view-configuration": {"show configuration **"}, "clear": {"clear **"},
+		"network": {"ping **", "traceroute **", "ssh **", "telnet **"}, "trace": {"monitor **"}, "all": {"**"}}
+	j.CarveOuts = map[string][]string{"view-configuration": {"show configuration **"}}
+	j.CeilingBits = map[string][]string{"readonly": {"view", "view-configuration"},
+		"operator": {"clear", "network", "trace", "view", "view-configuration"}, "admin": {"all"}}
+	j.CeilingLevels = map[string]uint8{"readonly": 1, "operator": 15, "admin": 15}
+	j.DeviceConfig = []string{"set system tacplus-options strict-authorization"}
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
@@ -168,6 +195,9 @@ var releasedGeneric = map[string]Dialect{
 	"1.0.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
 		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"},
 		EnableUsername: EnablePrincipal},
+	"1.1.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
+		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"},
+		EnableUsername: EnablePrincipal},
 }
 
 // Each released set's generic adapter is its own and frozen, and every set
@@ -203,7 +233,7 @@ func TestEmbeddedSetsLoad(t *testing.T) {
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
index f3a4363..a4faef9 100644
--- a/internal/platform/classes_test.go
+++ b/internal/platform/classes_test.go
@@ -37,18 +37,34 @@ func TestReferenceClasses(t *testing.T) {
 		"delete system login user p49-readonly",
 		"set system login user p49-readonly class p49-readonly",
 	}
+	if lockTemplates {
+		// Each user's set lines end with the lock (plan 5b Task 14).
+		var locked []string
+		for _, l := range want {
+			locked = append(locked, l)
+			if strings.HasPrefix(l, "set system login user ") {
+				locked = append(locked, strings.Replace(l, "class "+l[strings.LastIndex(l, " ")+1:], lockLine, 1))
+			}
+		}
+		want = locked
+	}
 	if !reflect.DeepEqual(got, want) {
 		t.Fatalf("%q", got)
 	}
-	for _, l := range got {
-		if strings.Contains(l, "authentication") {
-			t.Errorf("a template user that can log in locally: %s", l)
-		}
-	}
 	up, _ := ReferenceClasses(junosProjected(BitDeliveryUserPermissions), 30*time.Second)
-	if len(up) != 4 || up[1] != "set system login class p49-remote idle-timeout 1" {
+	if up[1] != "set system login class p49-remote idle-timeout 1" {
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
Expected: FAIL, among others: `TestTheDefaultSetValueForValue`, `TestTheGenericAdapterIsFrozen`,
`TestEmbeddedSetsLoad`, `TestReferenceClasses`, `TestPlatformShowAndExportPrintTheAdapter: missing
"# cisco_iosxe: built-in, platform set 1.1.0\n"`, `TestPlatformExportClasses: 1.1.0: code 1`, and
`TestUpgradingToTheProjectedSet: command_projection is not reported gated`.

- [ ] **Step 3: Add the set**

```bash
mkdir -p platforms/1.1.0
cp platforms/1.0.0/arista_eos.yaml platforms/1.0.0/cisco_iosxe.yaml platforms/1.0.0/cisco_nxos.yaml platforms/1.1.0/
```

Then apply:

<!-- patch: cmd/port49/platform.go -->
````diff
diff --git a/cmd/port49/platform.go b/cmd/port49/platform.go
index fc9ed79..432c468 100644
--- a/cmd/port49/platform.go
+++ b/cmd/port49/platform.go
@@ -333,6 +333,19 @@ func upgradeReport(w io.Writer, before, after *policy.Policy, now time.Time) {
 		fmt.Fprintf(w, "  shadowed: %s: set %s changes the built-in value and the policy's block keeps its "+
 			"own; compare the two\n", key, after.PlatformSet())
 	}
+	// What the move quarantines or fails closed, before anyone runs the
+	// gate: each fails policy test (plan 5b pre-flight I10).
+	for _, q := range after.Quarantines(now) {
+		for _, e := range q.Entries {
+			fmt.Fprintf(w, "  quarantine on %s: %s (%s): %s\n", after.PlatformSet(), q.Device, q.Platform,
+				quarantineLine(e, now))
+		}
+	}
+	for _, f := range after.Projections(now) {
+		if f.Kind == policy.FindingProjectionRefused || f.Kind == policy.FindingProjectionOverflow {
+			fmt.Fprintf(w, "  %s on %s: %s\n", f.Kind, after.PlatformSet(), f.Message)
+		}
+	}
 	switch {
 	case len(d.Adapters) == 0:
 		fmt.Fprintln(w, "  no adapter changes")
````

<!-- patch: internal/platform/dialect.go -->
````diff
diff --git a/internal/platform/dialect.go b/internal/platform/dialect.go
index dec8bec..25eebc9 100644
--- a/internal/platform/dialect.go
+++ b/internal/platform/dialect.go
@@ -289,6 +289,9 @@ var inert = []string{"home-directory"}
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
index 0000000..717efa7
--- /dev/null
+++ b/platforms/1.1.0/juniper_junos.yaml
@@ -0,0 +1,103 @@
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
+    # alone ran or completed in the lab, one level under each word, as rules
+    # that hold them, an upper bound (tests/lab/results/L12-bits-juniper_*.md).
+    # A session runs the union of its bits' reach. `baseline` is what a class
+    # with no bits runs, held by every session: the projection denies each of
+    # its commands no permit holds. `all` is every bit.
+    bits:
+      baseline: ["help **", "quit **", "exit **", "set cli **", "show cli **"]
+      view: ["show **"]
+      view-configuration: ["show configuration **"]
+      clear: ["clear **"]
+      network: ["ping **", "traceroute **", "ssh **", "telnet **"]
+      trace: ["monitor **"]
+      all: ["**"]
+    # The one subtraction from the union: a command a bit alone makes
+    # available, whatever other bit reaches it. Under `view` without
+    # `view-configuration` the configuration is not shown
+    # (tests/lab/results/L12-bits-juniper_*.md, "carve-outs"). Only a listed
+    # carve-out lets the projection leave a deny off the wire.
+    carve_outs:
+      view-configuration: ["show configuration **"]
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
+    # The template users and their classes are the reference `port49 platform
+    # export --classes` writes, and `port49 devices check-config --config`
+    # holds a device to: `remote` in the bitless p49-remote, since a reply
+    # naming a template the device lacks lands the session there
+    # (L18-juniper_*.md, variant 7), and each level's template.
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

- [ ] **Step 4: Apply what the lab measured: one branch per outcome**

Read Tasks 2–4's notes and take the branch each line selects. Every branch fails closed, and none
is skipped: where a note and the candidate agree, write that in the commit message instead. Record
in the commit message which notes each value came from. `shipped110` edits go below its comment
line `// What 1.1.0 changes in juniper_junos: ...`.

**A. The projection cannot be sound here** — any of: `explicit anchors with the pipe tail: false`
on either image; `narrow shape exact: false` because the narrow reply **ran** `show system uptime`,
`clear interfaces statistics fxp0`, `ping` or the configuration; the baseline line showing a
command that ran under the no-bit class also ran under `deny .*` (`narrow true`); or a template
user with no authentication that logged in locally where the locked user did not commit or also
logged in. Each means a reply port49 writes can let the device run what port49 denies, including
the fail-closed reply. Junos stays unprojected in 1.1.0, as in 1.0.0:
1. `cp platforms/1.0.0/juniper_junos.yaml platforms/1.1.0/juniper_junos.yaml`, and add a comment
   at its top naming the note and the fact that ruled the projection out.
2. In `shipped110`, delete every line between the comment line and `out["juniper_junos"] = j`.
3. Delete `TestAProjectionRefusalFailsTheGates`, `TestCheckConfigHoldsAJunosDeviceToTheReference`,
   `TestUpgradingToTheProjectedSet` and the `1.1.0` success block of `TestPlatformExportClasses`
   (`cmd/port49/platform_test.go`), and the "What export prints for the shipped Junos adapter"
   block of `TestReferenceClasses`.
4. In the spec, §8 "As built": replace "The projection ships in platform set **1.1.0**" with "The
   projection is built but not shipped: <fact> (<note>) means a reply cannot be proven sound on
   Junos", and keep decision 22's "*Provisional on L12.*".
5. Skip Task 19; Task 20 applies only its `released` hunk. Report this to the controller before
   continuing: it is the one outcome that ships no projection.

**B. `JunosFacts` (L9).** In `internal/projection/project.go`, set `var JunosFacts =
Facts{CaseSensitive: <A>, DenyMatchesExpanded: <B>}`: `<A>` is `false` only if both notes say
`JunosFacts.CaseSensitive = false`, and `<B>` is `true` only if both say
`JunosFacts.DenyMatchesExpanded = true`. Rewrite the comment above it to cite both notes.

**C. `bit_delivery` (L12).** Switch to `user_permissions` only if both notes show all three:
`user-permissions over a bitless template applied: true`, both bits of the two-bit value applied,
and the per-session line showing A's permissions unchanged after B. Then: in the adapter file,
`bit_delivery: user_permissions`, delete the `local_user_names` line, and rewrite the comment above
to cite `L12-juniper_*.md`; in `shipped110`, `j.CommandProjection, j.BitDelivery =
ProjectionJunosRegex, BitDeliveryUserPermissions`, and delete the `j.LocalUserNames = ...` line.
Otherwise write "local_user_name kept: <which line failed>" in the commit message.

**D. Bits and the baseline (L12-bits).** If Task 3 widened `junosBitReach`, `baseline` included,
paste the note's `bits:` block under `bits:` here (keeping `all: ["**"]`) and write the same map
in `shipped110`'s `j.Bits`. A widened reach makes the generator ask more of a grant before it
sends the bit: the direction that fails closed.

**E. The carve-out (L12-bits).** If the note says `view` alone showed the configuration, delete the
`carve_outs:` block and its comment here, and the `j.CarveOuts = ...` line in `shipped110`. Every
deny then goes on the wire.

**F. Template logins (L12).** If the template user with no authentication refused both local
logins, change nothing. If it logged in, and `authentication encrypted-password "*"` committed and
refused both logins, set `var lockTemplates = true` in `internal/platform/classes.go` and rewrite
its comment to cite the note. Any other outcome is branch A.

**G. A template needs a uid (L12).** If "The templates were committed without a uid" says the
commit did not complete, give each template user a uid. In `internal/platform/classes.go`, add a
field `uid int` to `template`, give `remote` `templateUID` and each level's template
`templateUID + len(out)` in `templates`, add `const templateUID = 2101` with a comment citing the
note, and in `lines` insert `fmt.Sprintf("set system login user %s uid %d", t.user, t.uid)` right
after the user's `class` line. In `TestReferenceClasses`, insert the same line after each `set
system login user` line of `want` (`remote` 2101, then `p49-admin`, `p49-operator`, `p49-readonly`
in order). `TemplateDrift` already allows a uid line.

**H. L24.** If either note says the idle-timeout did not end the session, decision 21's
approximation is not enforced there: in the spec, §5.6 and decision 21, replace "measured by L24"
with what L24 measured, citing the note; in `cmd/port49/platform.go`'s export header, replace "so
this timer is what ends a session there (decision 21)" with "though tests/lab/results/L24-<image>.md
measured it not ending an idle session there (decision 21)". Keep the idle-timeout lines: they
bound nothing less than before.

**I. The malformed deny (L9).** Write the line into §15's L9 paragraph in Task 20: a session that
opened with `show version` running means a malformed wire regex fails open, and Task 7's refusal
of anything outside the ERE subset is what keeps port49 from sending one. No code changes.

**J. Configuration mode, `-regexps`, `allow-commands2` (L12).** Write each into the commit
message. Decided 6 stands either way; if `deny-commands` reached the statement and `run`, say that
the refusal is cautious rather than necessary, for the carried `deny-configuration` item.
`allow-commands2` is refused as a role attribute whatever it measured (Task 6).

**K. Inert beside readonly (L23).** For each candidate the note shows not inert on `arista_eos` or
`cisco_nxos`: in that platform's 1.1.0 file, move it from `inert_attributes` to
`privilege_attributes`, citing `L23-<platform>.md`; make the same edit to that platform's entry in
`shipped110`, which becomes a copy with the two lists changed. A 1.0.0 pin is covered through
`PrivilegeAttributeNames` (Decided 16).

**L. priv_lvl (Task 2's table).** If a Junos request carried a priv_lvl other than 1, set
`ceiling_levels` so that readonly's number is at least that value, and say so in the commit.

Add every file these edits touch to the commit in the last step.

- [ ] **Step 5: Run everything**

Run: `make test && make vet && go vet -tags lab ./tests/lab/... && make build`
Expected: every package `ok`, no `gofmt` output, both binaries built.

Also run `./bin/port49 platform upgrade --policy <a policy pinning nothing> --inventory
tests/lab/inventory-lab.yaml --to 1.1.0` and read the report. Every `platforms.juniper_junos.*` key
the move changes is listed with its `acknowledge:` entry, and every subject the move fails closed
is listed as `projection_refused on 1.1.0`.

- [ ] **Step 6: Commit**

```bash
git add cmd/port49/platform.go cmd/port49/platform_test.go internal/platform/adapter_test.go internal/platform/classes_test.go internal/platform/config_test.go internal/platform/dialect.go internal/platform/dialect_test.go internal/platform/set.go platforms/1.1.0/arista_eos.yaml platforms/1.1.0/cisco_iosxe.yaml platforms/1.1.0/cisco_nxos.yaml platforms/1.1.0/juniper_junos.yaml
git commit -m "$(cat <<'EOF'
feat: platform set 1.1.0 projects juniper_junos

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: NX-OS's vsh.bin record under admin is system, on its task_id only (L25; only if measured)

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

**Run this task only if L25's note shows an SSH accounting record under `admin` with a task_id of
the form `vsh.bin.<digits>`, and the NX-API session's task_ids carry no `vsh.bin`** (pre-flight
M7). If the NX-API session carried one, the task_id does not tell the device's machinery from a
person's API call, and keying a system user on it would hide a person: do not apply this task; in
§5.8, after "One production observation remains **unmeasured in this lab**", add "L25 found the
same task_id on an NX-API session as `admin` (`tests/lab/results/L25-cisco_nxos.md`), so it is no
discriminator and no system user is keyed on it", and commit that alone as `docs: L25's task_id is
no discriminator on NX-OS`. If no record came, skip the task, leave L25 open, and say so in the PR
body under "Carried". If the note's task_id has another exact shape, write the pattern that shape
needs in `systemTasks` and in the test, anchored at both ends, and change nothing else.

The pair is keyed on the user and the task_id (Decided 15). It is not among `WireFactsDiffer`'s
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
index b63fcfe..28362a9 100644
--- a/docs/design/2026-08-23-policy-engine-spec.md
+++ b/docs/design/2026-08-23-policy-engine-spec.md
@@ -2308,9 +2308,16 @@ for a session port49 was never asked to authenticate. Without the entry those th
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
@@ -2931,7 +2938,7 @@ attribute is complete in four lines:
 | `session_services` | the authorization `service` values this platform's sessions arrive with; a **list**, because the name is device-configurable on Junos | defaults per platform |
 | `session_discriminator` | the accounting AV pair whose value separates two sessions of one user on one device (§5.8) | defaults per platform |
 | `exec_commands` | the `cmd` values that mark an exec record rather than a per-command one; empty means "the exec record carries no `cmd` at all" (§5.8) | defaults per platform |
-| `system_users` | usernames this platform's own machinery writes accounting under, attributed `system` (§5.8); `juniper_junos` ships `root`, every other adapter ships empty | optional |
+| `system_users` | usernames this platform's own machinery writes accounting under, attributed `system` (§5.8); `juniper_junos` ships `root`, and `cisco_nxos` `admin` on a task_id `vsh.bin.<n>` only (L25); every other adapter ships empty | optional |
 | `port_pattern` | expected `port` shape, used only for drift detection | optional |
 | `ceiling_levels` | the priv-lvl number each level stands for where the rendering sends no `priv-lvl` (NX-OS is sent a role and no level, L16), for the token's ceiling | if `privilege` sends no `priv-lvl` |
 | `strip_cr` / `shows_server_msg` | whether commands end in `<cr>` (§3 rule 1); whether the device displays a denial's `server_msg` (L2) | defaults from the generic adapter |
@@ -5256,8 +5263,8 @@ Beyond those already listed in the design document's §14:
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
feat: NX-OS admin is a system user on its vsh.bin task_id only

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 16: A dropped accounting record is an account_gap in the log

**Files:**
- Modify: `internal/decision/reasons.go` (`EventAccountGap`), `internal/decision/log.go` (`Gap`,
  `Record.Gap`)
- Modify: `internal/daemon/acct/spool.go` (`gapMu`, `gaps`, `gapSince`, `drop`, `flushGaps`;
  every drop goes through `drop`; `drainOnce` flushes first and last)
- Test: `internal/daemon/acct/spool_test.go`, `internal/daemon/acct/sink_test.go`

**Interfaces:**
- Consumes: the spool's existing drop points: `offerFailed`, the oversized-line and set-aside
  branches of `drainOnce`, and `deliverLine`'s unparseable line.
- Produces, for Tasks 17 and 18:
  - `decision.EventAccountGap = "account_gap"`;
  - `type decision.Gap struct{ Stage string; Records int; Since string }`, JSON keys `stage`,
    `records`, `since`;
  - `decision.Record.Gap *Gap`, JSON key `gap`, omitted when nil.

Spec §9 says reconciliation MUST be qualified by the accounting stream's health: spool drops,
`ERROR` replies and unattributed counts. Two of those were metrics only, and a reader of the log
could not see them. Now every drop is counted by stage, as before, and also held in memory. The
drain writes one `account_gap` record per stage **before its pass's records for a drop held since
the last pass** (an `offer_refused`), and **when the pass ends for a drop during it** (a line
unparseable or set aside), after the records it sat among, `since` saying when it began: exactly
what Task 1's §5.7 text says (pre-flight M6). A refused write keeps the count for the next pass.
`offer_refused` is the stage an `ERROR` reply comes from. Two existing tests now see the gap record
after the records they count, and are updated to expect it.

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
index d126bba..d73d0af 100644
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
@@ -823,3 +826,35 @@ func TestTheDrainRedactsARecordSpooledBeforeTheUpgrade(t *testing.T) {
 		t.Fatalf("%s", out.String())
 	}
 }
+
+// A record the spool drops is written to the log as an account_gap record,
+// by stage: one the drain drops when the pass ends, after the records it sat
+// among, and once. Reconciliation reads the log, and must know it has a hole
+// before it says a device did not ask (spec §9).
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
index d04e921..5f8d399 100644
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
@@ -503,6 +511,16 @@ func (s *Spool) drainOnce() (ok bool, forwarded int) {
 	if s.forceFail { // test-only hook; see spool_test.go
 		return false, 0
 	}
+	// A drop held since the last pass, an offer refused, is written before
+	// this pass's records, so a reader meets the gap before what followed it.
+	// A drop during the pass, a record unparseable or set aside, is written
+	// when the pass ends, after the records it sat among; its `since` says
+	// when it began (spec §5.7, §9).
+	if !s.flushGaps() {
+		s.sinkRefused = true
+		return false, 0
+	}
+	defer s.flushGaps()
 
 	draining := s.path + ".draining"
 	s.sinkRefused = false
@@ -572,7 +590,7 @@ func (s *Spool) drainOnce() (ok bool, forwarded int) {
 			switch {
 			case oversized:
 				log.Printf("acct: dropping oversized spool line (over %d bytes)", maxLineBytes)
-				s.metrics.SpoolDrops.WithLabelValues(dropDrainUnparseable).Inc()
+				s.drop(dropDrainUnparseable)
 			default:
 				err := s.deliverLine(bytes.TrimRight(line, "\n"))
 				if errors.Is(err, decision.ErrUnencodable) {
@@ -582,7 +600,7 @@ func (s *Spool) drainOnce() (ok bool, forwarded int) {
 					if err = s.setAside(line); err == nil {
 						log.Printf("acct: an accounting record the decision log cannot encode was set aside in %s",
 							s.path+".unencodable")
-						s.metrics.SpoolDrops.WithLabelValues(dropDrainSetAside).Inc()
+						s.drop(dropDrainSetAside)
 					}
 				}
 				if err != nil {
@@ -712,7 +730,7 @@ func (s *Spool) deliverLine(line []byte) error {
 	var r decision.Record
 	if err := r.UnmarshalJSON(line); err != nil {
 		log.Printf("acct: dropping spool line that failed to unmarshal: %v", err)
-		s.metrics.SpoolDrops.WithLabelValues(dropDrainUnparseable).Inc()
+		s.drop(dropDrainUnparseable)
 		return nil
 	}
 	// Offer took the record already redacted, but a spool file an earlier
@@ -794,3 +812,43 @@ func (f *failAfterReader) Read(p []byte) (int, error) {
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
index 7979f51..5a63b41 100644
--- a/internal/decision/reasons.go
+++ b/internal/decision/reasons.go
@@ -75,6 +75,10 @@ const (
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
feat: a dropped accounting record is an account_gap record in the decision log

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 17: Infer each device's configured capability from the decision log (spec §9)

**Files:**
- Create: `internal/capability/capability.go`
- Test: `internal/capability/capability_test.go`

**Interfaces:**
- Consumes: `decision.Record` and its events; Task 16's `EventAccountGap`, `Gap`;
  `platform.IsExecRecord`.
- Produces, for Task 18:
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
- **Warnings**, each a contradiction between what a device declares and what it did:
  - `config-commands probably off`: on a `commands` platform, at least `ConfigEntries` entries
    (default 5), at least `ConfigSilent` (0.8) of them followed by no request.
  - `N commands in accounting had no corresponding authorization request`: resolved command
    accounting whose text holds no authorized command of its context.
- **Notes**, which are no fault: a capability observed that the adapter does not declare, a lab
  measurement waiting to be made; and `never seen`, an admitted device with no record in the
  window (pre-flight I13). In a day's window every device nobody logged into is one, and a job
  that pages on them is one nobody reads.
- **Gaps.** The window's `account_gap` records.

The join is text containment, lower-cased with `<cr>` dropped (Decided 14), and it runs only on
platforms that declare `commands`. A session-only platform decides every command itself by design.

- [ ] **Step 1: Write the failing tests**

<!-- patch: internal/capability/capability_test.go -->
````diff
diff --git a/internal/capability/capability_test.go b/internal/capability/capability_test.go
new file mode 100644
index 0000000..caf9597
--- /dev/null
+++ b/internal/capability/capability_test.go
@@ -0,0 +1,124 @@
+package capability
+
+import (
+	"reflect"
+	"strings"
+	"testing"
+	"time"
+
+	"github.com/blanketfish/port49/internal/decision"
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
+	if r := rep.Rows[2]; len(r.Warnings) != 0 || !reflect.DeepEqual(r.Notes,
+		[]string{"never seen: no record in the window, so nothing is inferred"}) {
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
index 0000000..74a110a
--- /dev/null
+++ b/internal/capability/capability.go
@@ -0,0 +1,266 @@
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
+	"github.com/blanketfish/port49/internal/decision"
+	"github.com/blanketfish/port49/internal/platform"
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
+	// made, never one to assert by hand (spec §9, "Principle"); a device never
+	// seen in the window is one nobody logged into, which pages nobody (plan
+	// 5b pre-flight I13: "once that happens nobody reads the report again").
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
+		if row.Device.Quarantine == "" && len(row.Observed) == 0 {
+			row.Notes = append(row.Notes, "never seen: no record in the window, so nothing is inferred")
+		}
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
feat: infer each device's capabilities and reconcile accounting from the decision log

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 18: port49 devices capabilities, and CI names rules a platform never enforces (spec §9)

**Files:**
- Create: `cmd/port49/capabilities.go`
- Modify: `cmd/port49/main.go` (usage and dispatch)
- Modify: `internal/policy/lint.go` (`unenforced_rules`, `UnenforcedRules`)
- Test: `cmd/port49/capabilities_test.go` (new), `internal/policy/projection_test.go`,
  `internal/policy/spec11_test.go`

**Interfaces:**
- Consumes: Task 17's `capability.Infer` and its types; `policyFiles`, `redactOutput`;
  `(*Policy).Quarantined`, `Dialect`, `Devices`, `Redactions`.
- Produces:
  - `port49 devices capabilities --policy FILE --inventory FILE [--since DURATION] LOGFILE...|-`;
  - `devicesCapabilities(args []string, stdout, stderr io.Writer) int`;
  - `readLogs(names []string) ([]decision.Record, int, error)`;
  - `FindingUnenforcedRules = "unenforced_rules"` and `func (p *Policy) UnenforcedRules(now
    time.Time) []Finding`.

The command prints spec §9's matrix with a header line naming the window and the accounting
stream's health, each row's warnings (`⚠`) and notes (`note:`), then one `⚠ UNAUTHORIZED TIER —
<device>` block per device with its examples and its accounting health. With a gap in the window,
the block reads `? POSSIBLY AN UNAUTHORIZED TIER` and does not set the exit code. The command exits
1 on a warning, a contradiction a cron job should page on, 0 otherwise, a device never seen
included (pre-flight I13), and 2 on a usage error. A log line that does not parse is counted,
never quoted, and everything printed passes through the policy's redaction. `--since` is measured
back from the newest record, never from the wall clock, so a replayed log reports the same thing on
any day.

CI's half: a subject whose roles carry command rules on a platform that neither authorizes
commands nor projects them is told the rules decide nothing there. That covers Junos under 1.0.0,
and spec §11's example pins no set, so its expected findings gain four.

- [ ] **Step 1: Write the failing tests**

<!-- patch: cmd/port49/capabilities_test.go -->
````diff
diff --git a/cmd/port49/capabilities_test.go b/cmd/port49/capabilities_test.go
new file mode 100644
index 0000000..2209704
--- /dev/null
+++ b/cmd/port49/capabilities_test.go
@@ -0,0 +1,63 @@
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
+
+// A device never seen in the window is a note, not a page: exit 0 (I13).
+func TestANeverSeenDeviceIsANote(t *testing.T) {
+	pol, inv := policyFixture(t)
+	if err := os.WriteFile(inv, []byte(strings.Replace(string(readFile(t, inv)), "devices:\n",
+		"devices:\n  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.2]}\n", 1)), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	log := filepath.Join(t.TempDir(), "decisions.jsonl")
+	if err := os.WriteFile(log, []byte(`{"ts":"2026-09-24T12:00:01.000Z","event":"authorize_session","verdict":"permit",`+
+		`"reason":"context_matched","device":{"nas":"10.0.0.1","name":"leaf-01","platform":"arista_eos"},`+
+		`"session":{"ctx_id":"c1","port":"vty4","rem_addr":"","privilege":15}}`+"\n"), 0o600); err != nil {
+		t.Fatal(err)
+	}
+	var out, errb bytes.Buffer
+	code := run([]string{"devices", "capabilities", "--policy", pol, "--inventory", inv, log}, &out, &errb)
+	if code != 0 || !strings.Contains(out.String(), "note: never seen") {
+		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
+	}
+}
````

<!-- patch: internal/policy/projection_test.go -->
````diff
diff --git a/internal/policy/projection_test.go b/internal/policy/projection_test.go
index 498595f..3d45508 100644
--- a/internal/policy/projection_test.go
+++ b/internal/policy/projection_test.go
@@ -372,3 +372,23 @@ func TestTheDiffRefusesAFailClosedReply(t *testing.T) {
 		t.Fatalf("%+v", d.ProjectionRefusals)
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
TestDevicesCapabilities: code 2` and `--- FAIL: TestANeverSeenDeviceIsANote: code 2` (usage: the
command does not exist yet).

- [ ] **Step 3: Add the command and the finding**

<!-- patch: cmd/port49/capabilities.go -->
````diff
diff --git a/cmd/port49/capabilities.go b/cmd/port49/capabilities.go
new file mode 100644
index 0000000..2450acd
--- /dev/null
+++ b/cmd/port49/capabilities.go
@@ -0,0 +1,187 @@
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
+	"github.com/blanketfish/port49/internal/capability"
+	"github.com/blanketfish/port49/internal/decision"
+)
+
+// devicesCapabilities is `port49 devices capabilities` (spec §9): what each
+// inventory device declares it authorizes beside what the decision log shows
+// it asked, and each device whose accounting holds commands no authorization
+// request accounts for. It reads the log a daemon wrote; it never contacts a
+// device, and nobody asserts anything by hand. It exits 1 on a finding a
+// cron job should page on, a contradiction between what a device declares and
+// what it did: config-commands probably off, or an unauthorized tier in a
+// window whose accounting stream is whole. A device never seen in the window
+// is a note and exits 0: in a day's window every device nobody logged into
+// is one, and a job that pages on them is a job nobody reads (spec §9; plan 5b
+// pre-flight I13).
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
index 0bf8b27..9fa5cef 100644
--- a/cmd/port49/main.go
+++ b/cmd/port49/main.go
@@ -45,6 +45,7 @@ const usage = `usage:
                          --classes --config PORT49D_YAML PLATFORM)
   port49 platform upgrade --policy FILE --inventory FILE --to VERSION [--write]
   port49 devices check-config --policy FILE --inventory FILE --device NAME [--config PORT49D_YAML] CONFIGFILE
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
index ad27049..9eeb4f3 100644
--- a/internal/policy/lint.go
+++ b/internal/policy/lint.go
@@ -58,6 +58,10 @@ const (
 	// theirs (spec §13 decision 26). It fails `policy test`, as spec §8's
 	// "CI MUST refuse the policy" requires.
 	FindingProjectionRefused = "projection_refused"
+	// FindingUnenforcedRules is a subject's command rules on a platform that
+	// neither asks port49 about a command nor has them projected into its
+	// session reply: they decide nothing there (spec §9, "CI").
+	FindingUnenforcedRules = "unenforced_rules"
 )
 
 // Lint computes the findings at now, ordered by kind and then message so two
@@ -159,6 +163,7 @@ func (p *Policy) Lint(now time.Time) []Finding {
 	}
 	out = append(out, p.redundantOverrides()...)
 	out = append(out, p.Projections(now)...)
+	out = append(out, p.UnenforcedRules(now)...)
 	out = append(out, p.intersections(now)...)
 	if len(p.tests) == 0 {
 		add(FindingNoTests, "the policy has no tests: nothing in it acknowledges a shadowed deny, an expansion or "+
@@ -676,3 +681,35 @@ func projectionMessage(subject, platformName string, pr projection.Result, patte
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
feat: port49 devices capabilities, and CI reports rules no platform enforces

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 19: (lab, on beehive) The projection's differential test, typed as an operator might type it

**Files:**
- Create: `tests/lab/projection_test.go`
- Results (written by the run): `tests/lab/results/L12-projection-juniper_vjunos-router.md`,
  `L12-projection-juniper_vsrx.md`; evidence `projection-juniper_*.pcap`

**Interfaces:**
- Consumes: Task 2's `junosProbe`, `junosRun`, `junosConfigureAdmin`, `junosPer`, `junosHost`;
  Task 13's `platform.ReferenceClasses`; Task 14's set 1.1.0; Task 8's `projection.JunosFacts`,
  `Result.Device`, `Result.FailClosed`; `policy.Load`, `Decide`, `ResolveSubject`, `Quarantined`; the
  slice's `sliceUser`, `slicePrincipal`, `sliceBrokerURL`, `slicePKIDir`, `sliceToken`,
  `stopSliceAgent`, `tests/lab/slice/broker.yaml`.
- Produces: the notes Task 20 closes L9, L10 (Junos) and L12 on, and sets `verified` by.

This is spec §8's "Differential testing is required". The test applies the reference
configuration `ReferenceClasses` renders for 1.1.0, with a 12h max_session_age, over the
break-glass CLI, and restores the lab's own afterwards: the `remote` user (uid 2001) in
`p49-readonly` and that class's `view view-configuration`, as the startup configuration writes
them, every other class and user the reference added deleted, and no `strict-authorization`. For
each of eleven rule shapes it writes a policy pinning 1.1.0, restarts port49d with the slice's
broker on it, runs `port49 login` and `port49 token <node>`, logs in with the token, reads `show
cli authorization` (a miss fails the test), and types the probes under `junosPer`.

**The probes type what the projection could let past** (pre-flight I15, M4): each denied command
in full, abbreviated (`sh int ter`, `sh conf sys host-name`), in upper case and piped (`| no-more`,
`| display set`); the commands a class with no bits runs (`set cli screen-width 200`, `show cli`,
`file list /var/tmp`); `request system reboot` and `restart routing` by completion; and
`configure`, typed last, left at once if it entered configuration mode. A `show configuration`
probe counts as run only where it printed `host-name srx1`, so a filtered, empty output reads as
refused. The shapes include an exact deny (`show interfaces terse` under `show **`) and an admin
with a deny.

Each probe's outcome is compared with `policy.Decide` on the command as the device expands it,
its pipeline stripped:
- the device running a command port49 denies fails the test, as fail-open;
- the device running a command the projection's model says it refuses fails the test too, even
  where port49 permits it: the proof rests on the model holding everything the device runs;
- the device refusing one the model says it runs is narrower, which fails closed, and is recorded.

Which shape each composition renders to is the generator's, from the facts the binary ships, and
the note records it with any fail-closed reason. The refused shape must get the fail-closed reply,
and no shape may quarantine the device (decision 26).

- [ ] **Step 1: Add the test**

<!-- patch: tests/lab/projection_test.go -->
````diff
diff --git a/tests/lab/projection_test.go b/tests/lab/projection_test.go
new file mode 100644
index 0000000..70aacec
--- /dev/null
+++ b/tests/lab/projection_test.go
@@ -0,0 +1,318 @@
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
+	"github.com/blanketfish/port49/internal/admission"
+	adapter "github.com/blanketfish/port49/internal/platform"
+	"github.com/blanketfish/port49/internal/policy"
+	"github.com/blanketfish/port49/internal/projection"
+	"github.com/blanketfish/port49/internal/testpki"
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
+// the level's bits, say), or it fails too. A shape the generator cannot carry
+// gets that subject the fail-closed reply (decision 26): the session opens,
+// and the device runs no more than the allows the generator proved. Nothing
+// quarantines the device.
+//
+// The probes type what the projection could let past: each denied command
+// abbreviated, in upper case and piped; the commands a class with no bits
+// runs; and configuration mode (plan 5b pre-flight I15). Every command typed
+// has junosPer's deadline; a prompt that does not come back is not observed,
+// and fails.
+
+// projectionProbe is a command as typed and as the device expands it, without
+// its pipeline: port49 is asked about the second, since a session-only device
+// decides on it and the engine strips a pipeline before matching.
+type projectionProbe struct {
+	junosProbe
+	canonical string
+}
+
+const hostEvidence = "host-name " + junosHost
+
+var projectionProbes = []projectionProbe{
+	{junosProbe{cmd: "show version"}, "show version"},
+	{junosProbe{cmd: "show system uptime"}, "show system uptime"},
+	{junosProbe{cmd: "show interfaces terse"}, "show interfaces terse"},
+	{junosProbe{cmd: "sh int ter"}, "show interfaces terse"},
+	{junosProbe{cmd: "SHOW INTERFACES TERSE"}, "show interfaces terse"},
+	{junosProbe{cmd: "show interfaces terse | no-more"}, "show interfaces terse"},
+	{junosProbe{cmd: "show interfaces fxp0 terse"}, "show interfaces fxp0 terse"},
+	{junosProbe{cmd: "show interfaces lo0 terse"}, "show interfaces lo0 terse"},
+	{junosProbe{cmd: "show configuration system host-name", evidence: hostEvidence}, "show configuration system host-name"},
+	{junosProbe{cmd: "sh conf sys host-name", evidence: hostEvidence}, "show configuration system host-name"},
+	{junosProbe{cmd: "SHOW CONFIGURATION SYSTEM HOST-NAME", evidence: hostEvidence}, "show configuration system host-name"},
+	{junosProbe{cmd: "show configuration system host-name | display set", evidence: hostEvidence},
+		"show configuration system host-name"},
+	{junosProbe{cmd: "show route summary"}, "show route summary"},
+	{junosProbe{cmd: "clear interfaces statistics fxp0"}, "clear interfaces statistics fxp0"},
+	{junosProbe{cmd: "ping 127.0.0.1 count 1 rapid"}, "ping 127.0.0.1 count 1 rapid"},
+	{junosProbe{cmd: "sh ver"}, "show version"},
+	{junosProbe{cmd: "SHOW VERSION"}, "show version"},
+	// What a class with no bits runs (the adapter's baseline).
+	{junosProbe{cmd: "set cli screen-width 200"}, "set cli screen-width 200"},
+	{junosProbe{cmd: "show cli"}, "show cli"},
+	{junosProbe{cmd: "file list /var/tmp"}, "file list /var/tmp"},
+	{junosProbe{cmd: "request system reboot", complete: true}, "request system reboot"},
+	{junosProbe{cmd: "restart routing", complete: true}, "restart routing"},
+	// Configuration mode, typed last: a statement there is governed by the
+	// class's configuration permissions, which no command regex reaches.
+	{junosProbe{cmd: "configure"}, "configure"},
+}
+
+// projectionShapes are the rule shapes the generator produces, and the one
+// no measurement lets it carry. Each is the roles block of a policy pinning
+// set 1.1.0. Which shape a composition renders to is the generator's, from
+// the facts the binary ships, and the note records it; the test asserts only
+// that the refused shape gets the fail-closed reply, since nothing measured
+// can carry it.
+var projectionShapes = []struct {
+	name, roles string
+	failClosed  bool
+}{
+	{"readonly", `  - {name: r, privilege: readonly, permit: ["show **"]}`, false},
+	{"readonly, a deny aligned with a bit", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}`, false},
+	{"a permit beneath a deny", `  - {name: r, privilege: readonly, permit: ["show **", "show configuration system host-name"], deny: ["show configuration **"]}`, false},
+	{"an exact deny", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show interfaces terse"]}`, false},
+	{"narrow", `  - {name: r, privilege: readonly, permit: ["show version", "show interfaces **"]}`, false},
+	{"a class term", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show interfaces @management **"]}`, false},
+	{"a permit beyond the bits", `  - {name: r, privilege: readonly, permit: ["show **", "clear interfaces statistics **"]}`, false},
+	{"operator", `  - {name: r, privilege: operator, permit: ["show **", "clear **", "ping **"]}`, false},
+	{"admin", `  - {name: r, privilege: admin, permit: ["**"]}`, false},
+	{"admin with a deny", `  - {name: r, privilege: admin, permit: ["**"], deny: ["request system reboot **"]}`, false},
+	{"the refused shape", `  - {name: r, privilege: readonly, permit: ["show interfaces **", "show version"], deny: ["show interfaces terse"]}`, true},
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
+			t.Fatal("set 1.1.0 does not project juniper_junos (plan 5b, Task 14)")
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
+			b.WriteString(l.projectionShape(t, port49, pki, inv.Devices, shape.name, shape.roles, shape.failClosed))
+		}
+		l.result(t, "L12-projection", "Decisions 22 and 26's projection, differentially: for each rule shape the "+
+			"generator produces, what the device runs under the reply port49 renders, typed as an operator might "+
+			"type it — abbreviated, in upper case, piped — compared with port49's own decision on the command as the "+
+			"device expands it: never more; and, for a composition the projection cannot carry, that the subject "+
+			"gets the fail-closed reply and the device is not quarantined (spec §8, \"Verification\"; §13 decisions "+
+			"22 and 26; §15 L9, L12).", b.String())
+	})
+}
+
+// projectionShape runs one shape and renders its section of the note.
+func (l *lab) projectionShape(t *testing.T, port49, pki string, devices []admission.Device, name, roles string,
+	failClosed bool) string {
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
+		// A projection never quarantines: a composition it cannot carry is
+		// that subject's fail-closed reply (decision 26).
+		t.Errorf("%s: port49 quarantined %s", name, l.p.node)
+		return "port49 quarantined the device, which a projection never does.\n"
+	}
+	res, err := pol.ResolveSubject("slice_operator", device, time.Now())
+	if err != nil {
+		t.Fatalf("%s: %v", name, err)
+	}
+	if failClosed && res.Projection.FailClosed == "" {
+		t.Errorf("%s: expected the fail-closed reply, and port49 rendered the %s shape", name, res.Projection.Shape)
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
+	auth, err := c.sendExpect("show cli authorization", junosPer, junosOpPrompt)
+	if err != nil {
+		t.Errorf("%s: show cli authorization not observed within %s: %v", name, junosPer, err)
+		return "`show cli authorization` was not observed: " + oneLine(err.Error()) + "\n"
+	}
+	shape := res.Projection.Shape
+	if res.Projection.FailClosed != "" {
+		shape += ", " + res.Projection.FailClosed
+	}
+	fmt.Fprintf(&b, "Reply `%s` (%s). `show cli authorization`:\n\n```\n%s\n```\n\n", strings.Join(res.Blob.Attributes,
+		"`, `"), shape, precReply(l16TrimEcho(auth, "show cli authorization")))
+	b.WriteString("| typed | port49 on | port49 | projection predicts | device | agrees |\n|---|---|---|---|---|---|\n")
+	for _, p := range projectionProbes {
+		devOut, err := l.junosProbe(c, p.junosProbe)
+		if err != nil {
+			t.Errorf("%s: %q not observed within %s: %v", name, p.cmd, junosPer, err)
+			fmt.Fprintf(&b, "| `%s` | | | | not observed | |\n", p.cmd)
+			break
+		}
+		r := junosRun{outs: map[string]string{p.cmd: devOut}}
+		ran := r.runs(p.junosProbe)
+		if p.complete {
+			ran = r.completes(p.junosProbe)
+		}
+		if p.cmd == "configure" && strings.Contains(devOut, "configuration mode") {
+			ran = true
+			if _, err := c.sendExpect("exit configuration-mode", junosPer, junosOpPrompt); err != nil {
+				t.Errorf("%s: leaving configuration mode not observed within %s: %v", name, junosPer, err)
+			}
+		}
+		_, o, err := pol.Decide("slice_operator", "", device, p.canonical, time.Now())
+		if err != nil {
+			t.Fatalf("%s: %v", name, err)
+		}
+		predicts := res.Projection.Device(strings.Fields(p.canonical))
+		// The proof rests on the model holding every command the device runs:
+		// a command it runs and the model says it refuses is a model defect
+		// even where port49 permits it. The device refusing what the model
+		// says it runs is narrower, which fails closed, and is recorded.
+		switch {
+		case ran && !o.Permit:
+			t.Errorf("%s: the device ran %q, which port49 denies (%s): the projection fails open", name, p.cmd, o.Reason)
+		case ran && !predicts:
+			t.Errorf("%s: the device ran %q, and the projection's model says it refuses it: the model the proof "+
+				"rests on is short of the device", name, p.cmd)
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
+// reference configuration, which replaced the startup config's remote user
+// and p49-readonly class: both rebuilt as tests/lab/configs/vjunos-startup.conf
+// writes them, uid 2001 included, every other class and user the reference
+// added deleted, and strict-authorization removed.
+func projectionRestore(reference []string) []string {
+	out := []string{"delete system tacplus-options strict-authorization",
+		"delete system login user remote", "set system login user remote uid 2001",
+		"set system login user remote class p49-readonly", "delete system login class p49-readonly",
+		"set system login class p49-readonly permissions view",
+		"set system login class p49-readonly permissions view-configuration"}
+	seen := map[string]bool{"userremote": true, "classp49-readonly": true}
+	for _, line := range reference {
+		f := strings.Fields(line)
+		if len(f) < 5 || f[0] != "set" || f[1] != "system" || f[2] != "login" {
+			continue
+		}
+		kind, name := f[3], f[4]
+		if seen[kind+name] {
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

Run it in the background as "Running the lab" shows, with the stall watchdog running for the whole run and cleaning up after a `go test` timeout. Then the same with `PORT49_LAB_PLATFORMS=vsrx`. The test spends no seeded
token, because the broker mints each one. A timeout leaves the reference on the device; the
watchdog's cleanup destroys the topology, which discards it.

Expected: PASS on both images. Otherwise:
- **`the projection fails open`**: a defect in this plan, or in a measurement a set value rests
  on. Apply Task 14's branch A as its own commit, so 1.1.0 ships no projection, and report the
  probe, the reply and `show cli authorization` to the controller. CLAUDE.md rule 4 applies: the
  device is right.
- **`the model the proof rests on is short of the device`**: a reach, baseline or carve-out the lab
  contradicts. Widen the bit or the baseline (Task 14's branch D) or drop the carve-out (branch E),
  rerun `make test`, and rerun this test.
- **a shape quarantined, or the refused shape rendered**: a defect in Tasks 8 or 9. Stop and
  report it.

- [ ] **Step 4: Commit the test, the notes and the evidence**

```bash
make evidence
git add tests/lab/projection_test.go tests/lab/results/L12-projection-juniper_*.md \
  tests/lab/evidence/projection-juniper_*.pcap
git commit -m "$(cat <<'EOF'
test: the projection's differential lab test, typed as an operator might type it (L9, L12)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 20: Close what the lab measured, freeze set 1.1.0, and write plan 5b as built

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 statuses and per-row paragraphs; §13
  decision 22's provisional marker)
- Modify: `platforms/1.1.0/juniper_junos.yaml` (`verified: containerlab`), `internal/platform/adapter_test.go`
  (`released`, `shipped110`), `cmd/port49/platform_test.go` (the list row)
- Modify: `docs/superpowers/plans/README.md` (plan 5b as built, the carried items)

**Interfaces:**
- Consumes: every note Tasks 2, 3, 4 and 19 wrote; the Step 4 branches Task 14 took.
- Produces: set 1.1.0, frozen (`TestEveryReleasedSetIsFrozen`), and the roadmap entry plan 6 reads.

A row closes only where its lab test passed, and only where `tests/lab/results/L<N>-<platform>.md`
exists with the platform, the image version, the observation and a capture pointer. The Status
then reads `closed — measured <date>; tests/lab/results/...` (CLAUDE.md rule 3). A row with a
platform still open stays open.

The patches below touch only lines no Task 14 branch moves: `j.Verified` goes right after `j :=
out["juniper_junos"]`, above the comment every branch edits below (pre-flight I7), and the
`adapter_test.go` block carries one line of context for that reason.

- [ ] **Step 1: Close the rows the notes close**

In §15's table:
- **L9**: close it if both Junos notes read every fact, with no `not observed` cell. Cite
  `L9-juniper_vjunos-router.md` and `L9-juniper_vsrx.md`, and write the malformed-deny line (Task
  14, branch I) into its paragraph.
- **L12**: close it if `L12-*`, `L12-bits-*` and `L12-projection-*` all passed on both images.
  Leave it open, naming the clause, if any clause is unmeasured, or if Task 14 took branch A.
- **L10**: add "Junos's spellings (`local-user-name`, `user-permissions`, `deny-commands`,
  `allow-commands`) measured by plan 5b (`L12-projection-juniper_*.md`)". Close it: every shipped
  adapter's spellings are now measured. Under branch A, cite `L12-juniper_*.md` instead.
- **L23**: close it on `L23-arista_eos.md` and `L23-cisco_nxos.md`.
- **L24**: close it on `L24-juniper_*.md`, whichever way it measured (branch H).
- **L25**: close it on `L25-cisco_nxos.md` only if the record was measured over SSH and the NX-API
  line was measured. Otherwise leave it open with what the note found.

Add one paragraph per closed row under "What has been measured so far", in the form the existing
rows use: what was measured, on which images, and the one-line answer. Remove decision 22's
"*Provisional on L12.*" only if L12 closed. If it did not, keep the marker and say which clause
holds it open. Where a note contradicts the spec, fix the spec and cite the note (CLAUDE.md rule 4).

- [ ] **Step 2: Mark the Junos adapter verified, and freeze 1.1.0**

If `TestProjectionDifferential` passed on both images, apply all three blocks. If it did not, or
Task 14 took branch A, apply only the `released` hunk of the `internal/platform/adapter_test.go`
block (the `var released = ...` line) and skip the other two: 1.1.0 is frozen without `verified`.

<!-- patch: platforms/1.1.0/juniper_junos.yaml -->
````diff
diff --git a/platforms/1.1.0/juniper_junos.yaml b/platforms/1.1.0/juniper_junos.yaml
index 717efa7..b0a3ea4 100644
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

<!-- patch: internal/platform/adapter_test.go -->
````diff
diff --git a/internal/platform/adapter_test.go b/internal/platform/adapter_test.go
index f744275..38ecbf5 100644
--- a/internal/platform/adapter_test.go
+++ b/internal/platform/adapter_test.go
@@ -136,2 +136,3 @@ var shipped110 = func() map[string]Dialect {
 	j := out["juniper_junos"]
+	j.Verified = "containerlab" // tests/lab/results/L12-projection-juniper_*.md
 	// What 1.1.0 changes in juniper_junos: the projection and what it rests on.
@@ -172,3 +173,3 @@ func TestTheDefaultSetValueForValue(t *testing.T) {
 // renders without this test failing.
-var released = map[string]map[string]Dialect{"1.0.0": shipped}
+var released = map[string]map[string]Dialect{"1.0.0": shipped, "1.1.0": shipped110}
 
````

<!-- patch: cmd/port49/platform_test.go -->
````diff
diff --git a/cmd/port49/platform_test.go b/cmd/port49/platform_test.go
index bdaa6dc..16d8c84 100644
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

- [ ] **Step 3: Write plan 5b as built into the roadmap**

In `docs/superpowers/plans/README.md`:
- Update the status line: "**5b merged <date>** (PR #N; `2026-09-24-05b-projection-capabilities.md`,
  twenty tasks: one docs, three lab, fourteen code, one lab, one lab-and-docs)". Name the rows it
  closed.
- Add "Plan 5b — As built" under Plan 5. It covers:
  - the set 1.1.0 pin and its values as measured, with every Task 14 branch taken;
  - which JunosFacts closed, and whether the realistic readonly still fails closed;
  - the `bit_delivery` outcome and the template-login outcome;
  - the reference-classes rollout order and `check-config --config`;
  - decision 26's fail-closed reply, and the CI gates on it;
  - `devices capabilities` and `account_gap`;
  - whether the NX-OS system task landed.
- Add these carried items:
  - `deny-configuration` for statements typed in configuration mode, which would lift decided
    item 6;
  - the `-regexps` family if Task 2 measured its deny precedence, which spec §8 says lifts the
    refused shape, rendered by a later plan;
  - a way to declare a deny class-resident, the deny overflow's workaround in policy;
  - `engine.Contains`, `MayMeet` and the rest compile both rules per call; the per-composition
    cache bounds the load, and plan 12 measures it at 10k devices;
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
EOF
)"
```

Name only the rows actually closed in the subject line. Then open the pull request with the
"Operator-facing notes" below in its body (roadmap rule).

---

## Operator-facing notes (for the pull request body)

- **New platform set 1.1.0.** It projects Junos's rules into the session reply. An unpinned policy
  still renders with 1.0.0 and changes nothing. Pin it with `port49 platform upgrade --to 1.1.0
  --write`; the report lists every gated key and every subject the move fails closed, and `policy
  diff` gates the keys.
- **Before pinning,** load `port49 platform export --classes --config port49d.yaml juniper_junos`
  on every Junos device with `load set terminal`. Each template class and user is replaced whole.
  Check each device with `port49 devices check-config --config port49d.yaml` against `show
  configuration | display set`: a missing reference line, and any extra line under a template
  (a class `allow-commands`, a template password), fails it.
- **A composition the projection cannot carry fails closed for that subject alone** (decision 26):
  the session opens with `deny-commands=^.*$` and only the allows port49 proved, is logged
  `projection_fail_closed`, and every other subject on the device keeps working. `policy test` and
  `policy diff` fail on it, naming the subject, the devices and why. Until L9 measures that a deny
  reads the command as the CLI expands it, that includes every Junos composition with a deny
  beneath a permit.
- **`policy test` now fails on any quarantined device**, now or at a later grant expiry, as well
  as on a fail-closed composition. The daemon still serves the rest of the fleet.
- **`remote` and `p49-*` are reserved usernames**: refused at load, and never minted for.
- **New adapter keys:** `command_projection`, `bits`, `carve_outs`, `bit_delivery`,
  `local_user_names`. All are gated in the diff. A block may add to a bit's reach (a gated
  widening) and drop a carve-out; it may not remove reach, add a bit or add a carve-out.
- **Refused at load:** a role or grant attribute the projection renders, in any case or numbered
  variant, on a projected platform or under `all`.
- **New `policy test` reports:** `projection`, `projection_refused`, `projection_overflow` (with
  the class line for an overflowing deny set, never for allows), and `unenforced_rules`.
- **`policy diff`:** a Junos reply that lets the device do more fails until a `reply:` test
  asserts it; a pure narrowing is reported and passes. A `projection:` line reports each shape or
  bits change.
- **`port49 explain`** on a Junos command says whether the device runs it under the reply, and
  names a fail-closed composition's reason.
- **New command: `port49 devices capabilities`.** It gives the supports-versus-observed matrix and
  the unauthorized tier, read from the decision log. It exits 1 on a contradiction; a device never
  seen in the window is a note.
- **New log event: `account_gap`.** Accounting records the spool dropped, by stage. **New reason:
  `projection_fail_closed`.**
- **NX-OS (if L25 measured it):** an `admin` accounting record with task_id `vsh.bin.<n>` is now
  `system`.
- **Lab register:** L9, L10, L12, L23, L24 and L25, each closed or left open as Task 20 records.

## Self-review against the spec

- **§8 "Projection for session-only platforms":**
  - bits first, regexes second, chosen per composition: Task 8;
  - the capability, narrow and refused shapes, and the fail-closed reply: Task 8;
  - `bit_delivery`, both ways: Tasks 6, 8 and 14;
  - `bits`, `carve_outs`, `privilege` as the ceiling, reference classes by export: Tasks 6 and 13;
  - CI reporting shape and bits: Task 11, and changes between versions: Task 12;
  - "CI MUST refuse the policy": Tasks 11 and 12 (`projection_refused`, the diff's refusals);
  - the class-crossing report with its snippet, for denies: Task 11 (`projection_overflow`);
  - generator constraints 1–6: Task 8's `attributes` and Task 9's `checkProjected` for 1 and 6,
    `CheckAttribute` for 2, 3 by construction (nothing emits `-regexps`), `allowable` and `within`
    for 4, and for 5 the fail-closed reply with CI's refusal (decision 26);
  - differential testing: Task 19;
  - `explain` stating class ∩ wire: Task 11;
  - anchoring as a platform property: `JunosFacts` from L9 (Tasks 2 and 14).
- **Decision 21:** the class idle-timeout from `max_session_age` is Task 13, measured by Task 3
  (L24). `explain`'s statement already existed. Revocation records naming unreached contexts are
  plan 7's (roadmap), and stay there.
- **Decision 22:** Tasks 5–14 and 19. It stays provisional until L12 closes (Task 20).
- **Decision 26:** Tasks 8 (the reply), 9 (per subject, never a quarantine), 10 (the record),
  11 and 12 (CI), and Task 1 writes it.
- **§2's reserved usernames:** Task 9.
- **§9:**
  - the three observations and the matrix: Task 17;
  - `devices capabilities`: Task 18;
  - reconciliation over the tiers `supports` declares: Task 17;
  - qualified by stream health (the spool's drops, ERROR replies and unattributed counts): Tasks
    16–18;
  - the CI check: Task 18.
- **Roadmap carries:**
  - Junos's inert list and spellings: Tasks 2, 14, 19 and 20;
  - M3 re-measured beside readonly: Tasks 4 and 14;
  - the NX-OS `vsh.bin` system user if measured: Tasks 4 and 15.
- **Lab rules:**
  - every read has a deadline, and expiry is not observed and fails;
  - boot budgets are the harness's, per image;
  - the controller runs the stall watchdog, 40 minutes on the N9Kv, and cleans up after a
    `go test` timeout, per "Running the lab".
- **Carried, not built here:** the `-regexps` family, which spec §8 says lifts the refused shape
  once L12 measures its deny precedence (Task 2 measures it; the generator keeps the fail-closed
  reply until a later plan renders it); `deny-configuration` for statements typed in configuration
  mode, which would lift decided item 6.
