# Junos view-configuration under a deny beneath show: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Ruling (controller, 2026-10-16): ships as set 1.3.0, not 1.2.0, because 1.2.0 is released
> and frozen; same behaviour Ryan ruled.** (R3, below. Set 1.2.0's YAML is frozen value for
> value by `TestEveryReleasedSetIsFrozen`, and a binary upgrade must not change what a pinned
> policy renders, spec §8 "the platform set is pinned".)
>
> **A finding from writing this plan.** Set 1.2.0 already sends the reply Task 1 measures,
> today, to a readonly whose grant also writes `deny: [monitor **]`. Its `deny-commands` is
> 173 bytes (measured from the shipped code; Task 1 pins it). Two consequences:
> - **If Task 1 finds a refused probe running in row P, that is a live hole in set 1.2.0.**
>   Stop, write the note, and report it to the controller for Ryan's attention. Do not continue
>   silently, and do not start any later task.
> - An operator can get "permitted means it runs" under 1.2.0 now, with no code, by adding that
>   deny.

**Goal:** Ryan's ruling: "permitted means it runs". Take a Junos grant that permits `show
configuration` under a deny beneath `show` (`show **` less `show security **`), at any level
whose ceiling holds `view-configuration`: readonly, and operator. Its reply sends
`view-configuration` beside its other bits, and denies on the wire the rest of
view-configuration's reach that the grant decides nothing of. This ships only behind a lab cell
(L68) proving that the bit reaches nothing its declared reach, NETCONF, `op` or the exec channel
leaves open. Completion lists no hidden command, so hidden commands stay unmeasured (decision 48
ruling 6). An operator reply ships only if L68's operator row passes too.

**Architecture:** First, a lab cell measures the exact reply on both Junos images, before any
production code. The rest depends on it.

New set 1.3.0 = set 1.2.0 + one adapter key on `juniper_junos`: `deny_reach_bits:
[view-configuration]`. In `internal/projection`'s capability shape, a ceiling bit the grant
decides only in part goes out when all of these hold:
- the key lists the bit;
- the dialect closes the RPC entry points;
- the grant permits a carve-out of the bit that an allow past the bits is not measured to run;
- a bit already sent reaches that carve-out.

The bit's undecided reach then goes out as denies with role `reach_deny`. They are placed after
the grant's own denies, so the reply is byte for byte the one L68 measured. Everything else
already does the right thing: the deny beneath the bit brings the entry denies, and the model
predicts `show configuration` runs.

**Tech Stack:** Go 1.26 (module `github.com/blanketfish/port49`), `internal/projection`,
`internal/platform`, `internal/policy`, `cmd/port49`; the containerlab Junos lab
(`tests/lab`, build tag `lab`) on vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md`, in four places:
- §8 "The projection model", the paragraphs from "**A readonly with a deny beneath `show **`**" (:4036) to "**Set 1.1.0 is unchanged**" (:4083);
- §8's Fields table (`rpc_entry_denies`, :3644);
- §13 decision 44 rulings 4, 5 and 10 (:8910);
- §15 L12, L26c and L59.

The ruling is Ryan's of 2026-10-15, recorded in `docs/superpowers/plans/README.md` ("Ruled 2026-10-15 (Ryan): permitted means it runs").

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, no cgo. Before any "done": `make test && make vet`, and
  report the real output.
- Data is snake_case: the adapter key is `deny_reach_bits`, the deny role `reach_deny`.
- Reason codes are spec §5.7's closed vocabulary. This plan adds none. A fail-closed reply's
  category is a projection `Fail*` constant (`overflow`), not a reason code.
- Nothing secret is logged. Refusals and findings quote rules through the existing
  `g.quote`/`platform.QuoteShown`/`redacted` paths. A lab note passes `entryResult`'s leak check
  against every token the run minted.
- A released set is never edited. `platforms/1.0.0`, `1.1.0`, `1.2.0` and their keyword trees do
  not change. `TestEveryReleasedSetIsFrozen`, `TestTheGenericAdapterIsFrozen` and
  `TestReleasedKeywordTreesAreFrozen` pass with their existing entries untouched.
- RFC 8907: one attribute value ≤ 255 bytes (`engine.MaxAttribute`). Ryan's production
  experience: over 255 bytes locks the user out. Never send past it.
- The lab register is the source of truth. A claim cited to an open entry is unmeasured. If a
  result contradicts a doc, the doc is wrong: fix it, cite the note, and say so in the commit.
- Lab runs follow every one of these rules:
  - single occupant;
  - the STOP sentinel `/tmp/port49-STOP-LAB` (checked before every row by `labGuardAt`);
  - a free-disk floor of 67584M on `/`;
  - a background stall watchdog, re-armed on every wake;
  - a detached run worktree pinned at the commit;
  - captures copied to the main checkout before the run worktree is removed.

  An INVALID run writes no note.
- Commits: Conventional Commits, one per step that says Commit. Each message ends with only
  `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`, with no session line and no
  claude.ai link.

## Rulings (controller, 2026-10-16)

- **R1. Lab first.** Task 1 is the lab cell L68, on vJunos-router and vSRX, before any production
  code changes the reply. Its rows and probes are below. **If any refused probe runs, the plan stops
  at Task 1.** No reply change ships. The results note says so, and the plan is reported back to
  the controller. A refused probe running in row P is a live hole in set 1.2.0: stop, write the
  note, and report it to the controller for Ryan's attention. Tasks 2 to 7 depend on gate **G1**
  (rows P and H passed on both images).
  - **Operators: measure, don't restrict** (controller's ruling on pre-flight I6). The mechanism
    applies at any level whose ceiling holds view-configuration. Row O measures the operator
    reply `clear view view-configuration` and gates it separately, as **G1-operator**. It is
    also a reply set 1.2.0 sends today, to an operator granted `show **` and `clear **` less
    `show security **` and `monitor **`, so a refused probe running in row O is a live 1.2.0
    hole too: report it for Ryan's attention.
  - If G1 passes and G1-operator does not, the plan continues. The operator class keeps
    today's reply: Task 4 Step 3b restricts the mechanism to replies whose other bits are
    `view` alone, and Tasks 2, 4, 6 and the operator notes say so.
- **R2. The 255-byte limit** (controller's ruling, 2026-10-16: the fallback). The rendered
  `deny-commands` stays within 255 bytes. A test measures its real length: 173 bytes for the
  canonical readonly. Where the added reach denies would take it past 255, the reply falls back
  to the 1.2.0-style reply: no `view-configuration`, the carved allows, and `show configuration`
  refused, as today. That reply is measured (`L26c-projected-juniper_*.md`) and no wider. Lint
  warns with a new warning, `projection_reach_deny_overflow`, which Task 2 adds to spec §12
  before any code uses it. The composition fails closed only where the fallback cannot carry
  it either, as any overflow does.
- **R3. Sets.** The rule (spec §8, `platforms/platforms.go:7`, `adapter_test.go:192-197`): a
  released set is never edited, and a binary upgrade must not change what a pinned policy renders.
  Neither route under 1.2.0 meets it:
  - *A YAML key in 1.2.0* edits a frozen file. `TestEveryReleasedSetIsFrozen` fails.
  - *A new `JunosFacts` field* is binary-wide. Gating rendering on it changes what every
    1.2.0-pinned readonly gets on upgrade. Two tests pin that render today:
    `TestAReadonlyWithAShowDenyFitsTheBudget` (`view`, 165 bytes) and
    `TestThePredictionFollowsTheMeasuredAllowsPastTheBits`.

  So this is **set 1.3.0**: 1.2.0 plus `juniper_junos`'s `deny_reach_bits:
  [view-configuration]`, with 1.2.0's keyword tree copied unchanged. Precedent: decision 44
  ruling 5. `rpc_entry_denies` shipped as a new set, 1.2.0, so 1.1.0 renders byte for byte as
  before, and ruling 10's render changes hang on that key. Here they hang on the new key in the
  same way.
  - `DefaultSet` moves to 1.3.0.
  - A policy gets the change by `port49 platform upgrade --to 1.3.0`. Its gated `deny_reach_bits`
    entry is the review, so "permitted means it runs" reaches a fleet as a reviewed pin move.
  - Accepted by the controller, 2026-10-16 (recorded at the top).
- **R4.** The spec is edited first among the post-gate tasks, in its own task (Task 2):
  - §8's text at :4066-4072;
  - the warning paragraph;
  - decision 44 ruling 10;
  - a new decision 48.

  `projection_deny_beneath_view_configuration` never names a reach deny, and a reply sent under
  decision 48 gets no such warning. `policy test` and `explain` predict that `show configuration`
  runs, and the projection finding names the reach denies.
- **R5.** Reason codes only from §5.7. Data is snake_case. Nothing secret in logs. The lab rules
  in Global Constraints apply.

## Review Focus

1. **A policy pinned to 1.2.0 on the new binary** renders byte for byte as before, for both
   readonly deny-beneath-`show` grants and the operator ones. A reviewer should see 1.2.0's
   attributes asserted literally next to 1.3.0's (Task 4, `TestSet120RendersAsBefore`).
2. **A block `rpc_entry_denies: []` on 1.3.0.** `deny_reach_bits` is then inert, and the
   show-security readonly fails closed as on 1.1.0. It is never sent `view-configuration` with
   denies that bind no RPC (Task 4, `TestReachDeniesNeedTheEntryDeny`).
3. **A grant that permits part of the undecided reach** (`monitor interface **`) gets no deny
   beneath a permit. That composition renders as set 1.2.0 renders it (Task 4,
   `TestReachDeniesDeclineAPermittedReach`).
4. **A block that adds reach to view-configuration.** A rule the keyword tree proves is denied too
   (the device refuses it). One the tree does not prove keeps the 1.2.0 render byte for byte
   (Task 4, `TestAddedReachIsDeniedOrDeclined`).
   - A block that drops view-configuration's carve-out makes the key inert after the merge. The
     policy still loads, so `platform upgrade --to 1.3.0` is not refused (Task 3,
     `TestABlockDroppingTheCarveOutLoadsOn130`).
5. **A block `bit_delivery: local_user_name` on 1.3.0.** The template branch is unchanged: the
   attributes equal 1.2.0's under the same block (Task 4, `TestATemplateDeliveryIsUnchanged`).

---

### Task 1: Lab cell L68, before any production code (gate G1)

**Files:**
- Create: `tests/lab/junos_viewcfg_test.go`
- Create: `tests/lab/junos_viewcfg_unit_test.go`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15: add row L68 after L67, :10619)
- Create (by the run): `tests/lab/results/L68-juniper_<image>.md`, `L68-netconf-juniper_<image>.md`,
  `L68-netconf-operator-juniper_<image>.md` for vjunos-router and vsrx; `tests/lab/evidence/L68-*.pcap`
  (redacted, `make evidence`)

**Interfaces:**
- Consumes these existing lab helpers:
  - sessions and runs: `junosLogin`, `junosProbe`, `junosSurvey`, `l26cRun`/`newL26cRun`, `l26cSend`;
  - NETCONF cells: `entryXMLMode`, `entryNetconf`, `entryExec`, `entryVerdict`, `entryProbes`, `entryCanonical`, `entryLogControl`;
  - the exec channel and scp: `dialHostPort`, `nextLogin`, `dialCell`, `xnmOut`, `entryScp`;
  - CLI readings: `caretAt`, `caretOn`, `containsAny`, `junosL26bRefusal`, `beyond`, `heldBy`;
  - the `op url` script: `stageOpScript`, `opURLCmd`, `opAbbrevCmd`, `opURLEvidence`, `hostEvidence`;
  - setup and notes: `projectionRestore`, `entryResult`, `labGuardAt`, `l66StopSentinel`, `l66DiskFloorMB`, `jsonEscape`, `tableCell`, `cellOr`, `firstLines`, `commitWord`.
- Produces:
  - `l68Projected`: set 1.2.0's render, pinned. Task 6 pins it to set 1.3.0's render too.
  - The notes `tests/lab/results/L68-*.md`, whose "Gate" line reads `G1: pass` or `G1: STOP — …`, and
    `G1-operator: pass` or `G1-operator: STOP — …` (pre-flight I6).

**The rows** (each `user-permissions` over the reference configuration's bitless `p49-remote`,
the shape production sends):

| row | bits | deny-commands | why | gate |
|---|---|---|---|---|
| P | view view-configuration | `l68Projected`, 173 bytes: set 1.2.0's render of a readonly granted `show **` less `show security **` and `monitor **` | what set 1.3.0 will send a readonly without the `monitor **` deny | G1 |
| H | view view-configuration | `l68Hand`, 235 bytes: `show security`, view-configuration's other reach, `junoscript`, `op` | the bit's reach denied exactly, nothing else | G1 |
| O | clear view view-configuration | `l68Projected`: set 1.2.0's render of an operator granted `show **` and `clear **` less `show security **` and `monitor **` (the same bytes) | what set 1.3.0 will send that operator (pre-flight I6) | G1-operator |
| V | view | `l68Projected` | what the bit adds | — |
| Vc | view | none | completion baseline | — |
| C | view view-configuration | none | the control | — |

The CLI test types every probe in every row. It also runs three commands over the SSH exec
channel in P, H, O and C, and reads `/config/juniper.conf.gz` over scp in P, V and C (a reading).
NETCONF runs in two invocations, each against C: P and H (`L68-netconf`), then O
(`L68-netconf-operator`). Each stays within the seeded pool of 16 tokens per process. The CLI
test uses 13 tokens: 6 logins, 4 exec connections and 3 scp reads.

- [ ] **Step 1: Add the L68 register row (open)**

In `docs/design/2026-08-23-policy-engine-spec.md`, after the `| **L67** |` row, insert:

```markdown
| **L68** | A Junos reply sending view-configuration with the rest of its reach denied (plan 9g; decision 48). Under `user-permissions` over the bitless `p49-remote`, six rows: P, `view view-configuration` and set 1.2.0's render of a readonly granted `show **` less `show security **` and `monitor **` (173 bytes); H, the same bits and a deny of exactly `show security`, view-configuration's other reach and the entry denies (235 bytes); O, `clear view view-configuration` and P's deny, set 1.2.0's render of the operator granted `show **` and `clear **` less the same; V, `view` alone under P's deny; Vc, `view` alone; C, `view view-configuration` and no deny, the control. Whether `show cli authorization` lists each row's bits exactly; whether `show configuration` runs in P, H and O and not in V; whether `show security` and each word of view-configuration's other reach (`monitor`, `request mpls`, `request path-computation-client`, `request security`, `request unified-edge`, `request virtual-chassis`, `load` and `save dhcp-security-snoop`), typed in full and abbreviated, is refused in P, H and O where C takes it; whether `configure`, `edit` or `configure private` enters configuration mode in any row; whether, over the SSH exec channel, `show configuration` runs and `monitor list` and `show security zones` are refused in P, H and O where C takes them; whether `<get-configuration/>` through `xml-mode`, port 830, the port-22 subsystem and the exec channel's NETCONF, and `op url` and its abbreviation, are refused in P, H and O where C reaches them; whether view-configuration's completion over `view` (C against Vc) offers a word its declared reach does not hold. Recorded, not gated: `show log`, `show firewall`, `show policer`, `file list /config`, `file show /config/juniper.conf.gz`, an scp read of `/config/juniper.conf.gz` (P, V, C), and `show configuration`'s `\| save` and pager `s` (L59). Row O gates the operator reply alone (G1-operator). | Decision 48: set 1.3.0's `deny_reach_bits: [view-configuration]` | Junos (vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15) | open — added by plan 9g 2026-10-16 |
```

- [ ] **Step 2: Write the failing unit tests**

Create `tests/lab/junos_viewcfg_unit_test.go`:

```go
//go:build lab

package lab

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/engine"
	adapter "github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/projection"
)

// l68Shipped renders a juniper_junos composition at level on set version, as
// the policy layer hands the projection one (internal/projection's `shipped`
// helper).
func l68Shipped(version, level string, rules ...engine.Rule) (projection.Result, error) {
	set, _ := adapter.Set(version)
	d := set["juniper_junos"]
	return projection.Project(projection.Input{
		Platform:  "juniper_junos",
		Dialect:   d,
		Level:     level,
		Bits:      d.CeilingBits[level],
		Rules:     rules,
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true},
		Facts:     projection.JunosFacts,
		Keywords:  adapter.KeywordsFor(version, "juniper_junos"),
	})
}

func l68Rule(verdict, rule string) engine.Rule { return engine.Rule{Verdict: verdict, Rule: rule, Role: "r"} }

// Rows P and O are byte for byte what set 1.2.0 renders for a readonly, and
// for an operator also granted `clear **`, granted `show **` less `show
// security **` and `monitor **`, and within RFC 8907.
func TestL68ProjectedIsSet120sRender(t *testing.T) {
	for _, c := range []struct {
		level string
		bits  string
		extra []engine.Rule
	}{
		{"readonly", "user-permissions=view view-configuration", nil},
		{"operator", "user-permissions=clear view view-configuration", []engine.Rule{l68Rule(engine.Permit, "clear **")}},
	} {
		rules := append([]engine.Rule{l68Rule(engine.Permit, "show **"), l68Rule(engine.Deny, "show security **"),
			l68Rule(engine.Deny, "monitor **")}, c.extra...)
		res, err := l68Shipped("1.2.0", c.level, rules...)
		if err != nil || res.Shape != projection.ShapeCapability || !slices.Equal(res.Attributes, []string{c.bits, l68Projected}) {
			t.Fatalf("%s: %s %q %+v %v", c.level, res.Shape, res.Attributes, res.Refusal, err)
		}
	}
	if len(l68Projected) != 173 || len(l68Projected) > engine.MaxAttribute {
		t.Errorf("deny-commands is %d bytes", len(l68Projected))
	}
}

// Row H fits RFC 8907, denies an example of every rule of set 1.2.0's
// view-configuration reach that is not a carve-out, the grant's deny and the
// entry denies, and leaves the configuration and the carve-outs open.
func TestL68HandFitsAndCoversTheReach(t *testing.T) {
	if len(l68Hand) > engine.MaxAttribute {
		t.Fatalf("H's deny-commands is %d bytes", len(l68Hand))
	}
	re := regexp.MustCompile(strings.TrimPrefix(l68Hand, "deny-commands="))
	set, _ := adapter.Set("1.2.0")
	d := set["juniper_junos"]
	for _, r := range d.Bits["view-configuration"] {
		if slices.Contains(d.CarveOuts["view-configuration"], r) {
			continue
		}
		if ex := strings.TrimSuffix(r, " **") + " x"; !re.MatchString(ex) {
			t.Errorf("H leaves %q open", ex)
		}
	}
	for _, s := range []string{"show security zones", "show security zones | no-more", "junoscript", "op url x",
		"monitor list", "  monitor   list"} {
		if !re.MatchString(s) {
			t.Errorf("H leaves %q open", s)
		}
	}
	for _, s := range []string{"show configuration system host-name", "show log messages", "show firewall",
		"show policer", "show version", "request system reboot", "load merge x"} {
		if re.MatchString(s) {
			t.Errorf("H denies %q", s)
		}
	}
}

// A cell reads where the CLI refused: on the probe's prefix (refused), after
// it or not at all (past), by a platform's refusal of the whole command
// (platform refused), or by its evidence (ran).
func TestL68Cell(t *testing.T) {
	// The window's first echo carries no prompt; the caret's column counts it
	// (caretAt, TestCaretAt).
	const prompt = "p49user@vjunos1> "
	pl := len(prompt)
	caret := func(off int) string { return strings.Repeat(" ", pl+off) + "^" }
	mpls := l68Probe{cmd: "request mpls p49-none", prefix: 2}
	for _, c := range []struct {
		p    l68Probe
		out  string
		want string
	}{
		{mpls, "request mpls p49-none\n" + caret(8) + "\nsyntax error.\n" + prompt, "refused"},
		{mpls, "request mpls p49-none\n" + caret(0) + "\nsyntax error.\n" + prompt, "refused"},
		{mpls, "request mpls p49-none\n" + caret(13) + "\nsyntax error, expecting <command>.\n" + prompt, "past"},
		{l68Probe{cmd: "req mpls p49-none", prefix: 2}, "req mpls p49-none\n" + caret(4) + "\nsyntax error.\n" + prompt,
			"refused"},
		{mpls, "request mpls p49-none\nerror: permission denied\n" + prompt, "refused"},
		{l68Probe{cmd: "save dhcp-security-snoop | count", prefix: 2},
			"save dhcp-security-snoop | count\nerror: command is not valid on the vsrx\n" + prompt, "platform refused"},
		{l68Probe{cmd: "monitor list", prefix: 1}, "monitor list\n" + prompt, "past"},
		{l68Probe{cmd: "junoscript", prefix: 1}, "junoscript\nerror: unknown command: junoscript\n" + prompt, "refused"},
		{l68Probe{cmd: "show configuration system host-name", evidence: hostEvidence},
			"show configuration system host-name\n" + hostEvidence + ";\n" + prompt, "ran"},
		{l68Probe{cmd: "show configuration system host-name", evidence: hostEvidence},
			"show configuration system host-name\n" + prompt, "not observed"},
		{l68Probe{cmd: "configure", prefix: 1, evidence: l68ConfigMode, entry: true},
			"configure\nEntering configuration mode\n\n[edit]\np49user@vjunos1# ", "ran"},
		{l68Probe{cmd: "configure", prefix: 1, evidence: l68ConfigMode, entry: true},
			"configure\n" + caret(0) + "\nunknown command.\n" + prompt, "refused"},
	} {
		if got := l68Cell(c.p, c.out, pl); got != c.want {
			t.Errorf("%q on %q: %s, want %s", c.p.cmd, c.out, got, c.want)
		}
	}
}

// An exec-channel command's cell: its evidence, a refusal word, or an exit
// that said neither.
func TestL68ExecCell(t *testing.T) {
	show := l68Probe{cmd: "show configuration system host-name", evidence: hostEvidence}
	mon := l68Probe{cmd: "monitor list", prefix: 1}
	for _, c := range []struct {
		p    l68Probe
		out  string
		err  error
		want string
	}{
		{show, hostEvidence + ";\n", nil, "ran"},
		{show, "", nil, "not observed"},
		{mon, "error: syntax error: monitor\n", errors.New("Process exited with status 1"), "refused"},
		{mon, "", nil, "past"},
		{mon, "", errors.New("no exit within 45s"), "not observed"},
	} {
		if got := l68ExecCell(c.p, c.out, c.err); got != c.want {
			t.Errorf("%q on %q %v: %s, want %s", c.p.cmd, c.out, c.err, got, c.want)
		}
	}
}

// `show cli authorization` lists the session's bits under "Permissions:".
func TestL68AuthBits(t *testing.T) {
	out := "Current user: 'remote' login: 'p49user' class 'p49-remote'\nPermissions:\n" +
		"    view        -- Can view current values and statistics\n" +
		"    view-configuration-- Can view all configuration (not including secrets)\n" +
		"Individual command authorization:\n    Allow regular expression: none\n"
	if got := l68AuthBits(out); !slices.Equal(got, []string{"view", "view-configuration"}) {
		t.Errorf("%v", got)
	}
	if got := l68AuthBits("Permissions:\nIndividual command authorization:\n"); len(got) != 0 {
		t.Errorf("no bits: %v", got)
	}
}

func TestL68Verdict(t *testing.T) {
	for _, c := range []struct{ row, control, want string }{
		{"refused", "past", "deny"}, {"refused", "ran", "deny"}, {"past", "past", "reached"},
		{"ran", "ran", "reached"}, {"refused", "refused", "runs nowhere"}, {"not observed", "past", "not observed"},
		{"platform refused", "platform refused", "runs nowhere"}, {"platform refused", "past", "reached"},
		{"refused", "platform refused", "deny"},
	} {
		if got := l68Verdict(c.row, c.control); got != c.want {
			t.Errorf("%s against %s: %s, want %s", c.row, c.control, got, c.want)
		}
	}
}

// The gate: a deny row (P, H) that takes what it denies is a STOP, and O's is
// a G1-operator STOP; P, H or O not running the configuration, or V running
// it, likewise; any row entering configuration mode, likewise; the control
// not taking a canonical probe is INVALID; completion beyond the declared
// reach is a STOP.
func TestL68Gate(t *testing.T) {
	good := func() map[string]l26cRun {
		runs := map[string]l26cRun{}
		for _, n := range []string{"P", "H", "O", "V", "Vc", "C"} {
			runs[n] = newL26cRun()
		}
		for _, p := range l68Gated() {
			k := p.key()
			switch {
			case p.entry:
				for _, n := range []string{"P", "H", "O", "V", "C"} {
					runs[n].cells[k] = "refused"
				}
				continue
			case p.evidence == hostEvidence:
				runs["V"].cells[k] = "refused"
				runs["C"].cells[k] = "ran"
				for _, n := range l68DenyRows {
					runs[n].cells[k] = "ran"
				}
				continue
			case p.evidence != "":
				runs["C"].cells[k] = "ran"
			default:
				runs["C"].cells[k] = "past"
			}
			for _, n := range l68DenyRows {
				runs[n].cells[k] = "refused"
			}
		}
		return runs
	}
	reach := []string{"show configuration **", "show log **", "monitor **", "request mpls **"}
	vc := []string{"show", "show configuration", "show log", "monitor", "monitor list", "request mpls"}
	v := []string{"show", "show configuration"}
	if inv, stop, op, _ := l68Gate(good(), vc, v, reach); len(inv)+len(stop)+len(op) != 0 {
		t.Fatalf("a clean run: invalid %v stop %v operator %v", inv, stop, op)
	}
	runs := good()
	runs["P"].cells["monitor p49-none"] = "past"
	if _, stop, op, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 || len(op) != 0 ||
		!strings.Contains(stop[0], "monitor p49-none") {
		t.Errorf("P took monitor: %v %v", stop, op)
	}
	runs = good()
	runs["O"].cells["exec: monitor list"] = "past"
	if _, stop, op, _ := l68Gate(runs, vc, v, reach); len(stop) != 0 || len(op) != 1 {
		t.Errorf("O took monitor over exec: %v %v", stop, op)
	}
	runs = good()
	runs["H"].cells["show configuration system host-name"] = "refused"
	if _, stop, _, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 {
		t.Errorf("H refused the configuration: %v", stop)
	}
	runs = good()
	runs["V"].cells["show configuration system host-name"] = "ran"
	if _, stop, _, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 {
		t.Errorf("V ran the configuration: %v", stop)
	}
	runs = good()
	runs["C"].cells["configure"] = "ran"
	if _, stop, _, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 || !strings.Contains(stop[0], "configuration mode") {
		t.Errorf("C entered configuration mode: %v", stop)
	}
	runs = good()
	runs["C"].cells["request mpls p49-none"] = "refused"
	if inv, _, _, _ := l68Gate(runs, vc, v, reach); len(inv) != 1 {
		t.Errorf("the control refused a canonical probe: %v", inv)
	}
	if _, stop, _, _ := l68Gate(good(), append(slices.Clone(vc), "request zzz"), v, reach); len(stop) != 1 ||
		!strings.Contains(stop[0], "request zzz") {
		t.Errorf("completion beyond the reach: %v", stop)
	}
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test -tags lab ./tests/lab/ -run '^TestL68' -count=1`
Expected: FAIL to compile: `undefined: l68Projected`, `l68Hand`, `l68Probe`, `l68Cell`,
`l68ExecCell`, `l68AuthBits`, `l68Verdict`, `l68Gate`, `l68Gated`, `l68DenyRows`, `l68ConfigMode`.

- [ ] **Step 4: Write the harness**

Create `tests/lab/junos_viewcfg_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	adapter "github.com/blanketfish/port49/internal/platform"
)

// TestL68ViewConfigurationCLI, TestL68ViewConfigurationNetconf and
// TestL68ViewConfigurationNetconfOperator measure spec §15 L68 (plan 9g Task
// 1, gates G1 and G1-operator). The question: does a reply sending
// view-configuration, with deny-commands covering the grant's deny and the
// rest of view-configuration's reach, let the session read the configuration
// and nothing the denies leave open? Each row is user-permissions over the
// reference configuration's bitless p49-remote, the shape production sends:
//   - P: set 1.2.0's render of a readonly granted `show **` less `show
//     security **` and `monitor **` (l68Projected), which set 1.3.0 sends
//     without the `monitor **` deny;
//   - H: the same bits, and a deny of exactly `show security`,
//     view-configuration's other reach, and the entry denies (l68Hand);
//   - O: `clear view view-configuration` and P's deny, the operator reply;
//   - V: `view` alone under P's deny: what the bit adds;
//   - Vc: `view` alone and no deny: the completion baseline;
//   - C: `view view-configuration` and no deny: the control.
// A refused probe that runs in P or H is a STOP: no reply change ships (plan
// 9g ruling R1). One that runs in O stops the operator reply alone
// (G1-operator).

// l68Projected is set 1.2.0's deny-commands for a readonly granted `show **`
// less `show security **` and `monitor **`, and for an operator also granted
// `clear **`: 173 bytes (TestL68ProjectedIsSet120sRender pins both).
const l68Projected = `deny-commands=^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$`

// l68Hand denies `show security`, view-configuration's other reach (set
// 1.2.0's `bits:`) and the entry denies, nothing else: 235 bytes. The
// `request` words share one group after `request`, the L26b shape
// (l26bDeny); written one rule to an alternative it is 373 bytes, past RFC
// 8907.
const l68Hand = `deny-commands=^( *show +security( .*)? *(\|.*)?| *(monitor|junoscript|op)( .*)? *(\|.*)?| *request +(mpls|path-computation-client|security|unified-edge|virtual-chassis)( .*)? *(\|.*)?| *(load|save) +dhcp-security-snoop( .*)? *(\|.*)?)$`

func l68Attrs(bits, deny string) string {
	out := `["user-permissions=` + bits + `"`
	if deny != "" {
		out += `, "` + jsonEscape(deny) + `"`
	}
	return out + "]"
}

var junosL68Variants = []junosVariant{
	{"P", l68Attrs("view view-configuration", l68Projected),
		"set 1.2.0's render of a readonly granted show ** less show security ** and monitor **: set 1.3.0's reply"},
	{"H", l68Attrs("view view-configuration", l68Hand),
		"show security, view-configuration's other reach and the entry denies, nothing else"},
	{"O", l68Attrs("clear view view-configuration", l68Projected),
		"the operator granted show ** and clear ** less the same: set 1.3.0's operator reply"},
	{"V", l68Attrs("view", l68Projected), "view alone under P's deny: what the bit adds"},
	{"Vc", l68Attrs("view", ""), "view alone, no deny: the completion baseline"},
	{"C", l68Attrs("view view-configuration", ""), "the control"},
}

func l68Variant(name string) junosVariant {
	i := slices.IndexFunc(junosL68Variants, func(v junosVariant) bool { return v.name == name })
	return junosL68Variants[i]
}

// l68DenyRows are the rows whose deny is gated: P and H under G1, O under
// G1-operator.
var l68DenyRows = []string{"P", "H", "O"}

// l68Bits is what `show cli authorization` must list for each row: the reply
// landed as sent, and no configuration group adds a bit to p49-remote (L57).
var l68Bits = map[string][]string{
	"P": {"view", "view-configuration"}, "H": {"view", "view-configuration"},
	"O": {"clear", "view", "view-configuration"}, "V": {"view"}, "Vc": {"view"},
	"C": {"view", "view-configuration"},
}

// l68ConfigMode is what the CLI prints entering configuration mode.
const l68ConfigMode = "Entering configuration mode"

// l68Probe is one command a row types. prefix is how many of its leading
// typed words name the reach (or the grant's deny) it probes: the cell reads
// whether the CLI refused it there. A `p49-none` after the prefix is never a
// command: the control's CLI takes the prefix and stops at it, so nothing
// runs, and a deny refuses at the prefix (L58's reading of `save`). evidence
// is what a run prints. canonical: the control must take it, or the run is
// INVALID. reading: recorded, gated by nothing. entry: it enters
// configuration mode, which no row may. exec: typed over the SSH exec
// channel, not the CLI.
type l68Probe struct {
	cmd       string
	prefix    int
	evidence  string
	canonical bool
	reading   bool
	entry     bool
	exec      bool
}

// key is the probe's cell key: an exec probe's is prefixed, since the same
// command is typed at the CLI too.
func (p l68Probe) key() string {
	if p.exec {
		return "exec: " + p.cmd
	}
	return p.cmd
}

var l68Probes = []l68Probe{
	// What the bit is sent for: it runs in P, H, O and C, and not in V.
	{cmd: "show configuration system host-name", evidence: hostEvidence, canonical: true},
	{cmd: "sh conf sys host-name", evidence: hostEvidence},
	{cmd: "show configuration system host-name | display set", evidence: hostEvidence},
	// The grant's deny.
	{cmd: "show security p49-none", prefix: 2, canonical: true},
	{cmd: "sh sec p49-none", prefix: 2},
	// view-configuration's other reach, in full (as a hidden command must be
	// typed: it does not abbreviate, L26c-junoscript), abbreviated, spaced and
	// piped (L9's forms). Case is the CLI's own refusal (L9), recorded.
	{cmd: "monitor p49-none", prefix: 1, canonical: true},
	{cmd: "mon p49-none", prefix: 1},
	{cmd: "monitor list", prefix: 1},
	{cmd: "monitor list | no-more", prefix: 1},
	{cmd: "   monitor   list", prefix: 1},
	{cmd: "MONITOR LIST", prefix: 1, reading: true},
	{cmd: "request mpls p49-none", prefix: 2, canonical: true},
	{cmd: "req mpls p49-none", prefix: 2},
	{cmd: "request mp p49-none", prefix: 2},
	{cmd: "request path-computation-client p49-none", prefix: 2},
	{cmd: "req path-computation-client p49-none", prefix: 2},
	{cmd: "request security p49-none", prefix: 2, canonical: true},
	{cmd: "req sec p49-none", prefix: 2},
	{cmd: "request unified-edge p49-none", prefix: 2},
	{cmd: "request virtual-chassis p49-none", prefix: 2},
	{cmd: "req vir p49-none", prefix: 2},
	{cmd: "load dhcp-security-snoop /var/tmp/p49-l68-none", prefix: 2},
	{cmd: "save dhcp-security-snoop | count", prefix: 2},
	// The entry denies: `op url` runs the staged script in the control.
	{cmd: opURLCmd, prefix: 1, evidence: opURLEvidence, canonical: true},
	{cmd: opAbbrevCmd, prefix: 1, evidence: opURLEvidence},
	// Configuration mode's entries, none of them in P's deny: view-configuration
	// must not enter it, in any row (pre-flight I5).
	{cmd: "configure", prefix: 1, evidence: l68ConfigMode, entry: true},
	{cmd: "edit", prefix: 1, evidence: l68ConfigMode, entry: true},
	{cmd: "configure private", prefix: 1, evidence: l68ConfigMode, entry: true},
	// Readings: the carve-outs, the configuration file, (L59).
	{cmd: "show log messages | count", evidence: "Count: ", reading: true},
	{cmd: "show firewall | no-more", reading: true},
	{cmd: "show policer | no-more", reading: true},
	{cmd: "file list /config", reading: true},
	{cmd: "file show /config/juniper.conf.gz | count", evidence: "Count: ", reading: true},
}

// l68ExecProbes run over the SSH exec channel in P, H, O and C: a reply's
// deny must bind a command sent there as at the CLI (pre-flight I5).
var l68ExecProbes = []l68Probe{
	{cmd: "show configuration system host-name", evidence: hostEvidence, canonical: true, exec: true},
	{cmd: "monitor list", prefix: 1, canonical: true, exec: true},
	{cmd: "show security zones", prefix: 2, exec: true},
}

// l68Gated are the probes the gate reads: every CLI probe but the readings,
// then the exec probes.
func l68Gated() []l68Probe {
	var out []l68Probe
	for _, p := range slices.Concat(l68Probes, l68ExecProbes) {
		if !p.reading {
			out = append(out, p)
		}
	}
	return out
}

var l68UnknownCommand = regexp.MustCompile(`unknown command: ([a-z][a-z-]*)`)

// l68Cell reads one CLI probe's window:
//   - "ran": its evidence, and no refusal;
//   - "refused": a caret on one of its first prefix words, `permission
//     denied`, or `unknown command` naming one;
//   - "platform refused": the platform's "command is not valid on the" refusal
//     of the whole command;
//   - "past": a caret after the prefix, or, for a probe with no evidence, no
//     refusal at all;
//   - else "not observed".
func l68Cell(p l68Probe, out string, promptLen int) string {
	lower := strings.ToLower(out)
	refusal := containsAny(lower, junosL26bRefusal)
	if p.evidence != "" && strings.Contains(out, p.evidence) && !refusal {
		return "ran"
	}
	words := strings.Fields(p.cmd)
	n := p.prefix
	if n == 0 || n > len(words) {
		n = len(words)
	}
	if at := caretAt(out, promptLen); at != "" {
		for _, w := range words[:n] {
			if caretOn(at, w) {
				return "refused"
			}
		}
		return "past"
	}
	if strings.Contains(lower, "permission denied") {
		return "refused"
	}
	if m := l68UnknownCommand.FindStringSubmatch(lower); m != nil && slices.Contains(words[:n], m[1]) {
		return "refused"
	}
	if strings.Contains(lower, "command is not valid on the") {
		return "platform refused"
	}
	if !refusal && p.evidence == "" {
		return "past"
	}
	return "not observed"
}

// l68ExecCell reads an exec-channel command: "ran" (its evidence), "refused"
// (a refusal word), "past" (it exited and said neither, for a probe with no
// evidence), else "not observed" (a hang, or no evidence where one is due).
func l68ExecCell(p l68Probe, out string, err error) string {
	refused := containsAny(strings.ToLower(out), junosL26bRefusal)
	switch {
	case p.evidence != "" && strings.Contains(out, p.evidence) && !refused:
		return "ran"
	case refused:
		return "refused"
	case err != nil && strings.Contains(err.Error(), "no exit"):
		return "not observed"
	case p.evidence == "":
		return "past"
	}
	return "not observed"
}

// l68AuthBits are the bits `show cli authorization` lists under
// "Permissions:", sorted.
func l68AuthBits(out string) []string {
	var bits []string
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		switch {
		case strings.HasPrefix(strings.TrimSpace(line), "Permissions:"):
			in = true
		case in && (line == "" || line[0] != ' '):
			in = false
		case in:
			if f := strings.Fields(line); len(f) > 0 {
				bits = append(bits, strings.SplitN(f[0], "--", 2)[0])
			}
		}
	}
	slices.Sort(bits)
	return bits
}

// l68Verdict is a gated probe's reading in a deny row against the control:
// "runs nowhere" where both met the platform's refusal, or both refused it
// (the image lacks the word); "reached" where the row ran it or took it;
// "deny" where the row refused it and the control took it.
func l68Verdict(row, control string) string {
	took := func(c string) bool { return c == "ran" || c == "past" || c == "platform refused" }
	switch {
	case row == "platform refused" && control == "platform refused":
		return "runs nowhere"
	case took(row):
		return "reached"
	case row == "refused" && took(control):
		return "deny"
	case row == "refused" && control == "refused":
		return "runs nowhere"
	}
	return "not observed"
}

// l68Gate reads the CLI run. It returns:
//   - invalid: the control did not take a canonical probe or run the configuration;
//   - stop: a G1 STOP, which is one of these:
//     - P or H took what it denies;
//     - P or H did not run the configuration, or V did;
//     - a row other than O entered configuration mode;
//     - the bit's completion over `view` offers a word reach does not hold;
//   - operator: the same STOPs for row O, G1-operator's;
//   - the verdicts the note prints, keyed "row key".
func l68Gate(runs map[string]l26cRun, surveyC, surveyVc, reach []string) (invalid, stop, operator []string,
	verdicts map[string]string) {
	verdicts = map[string]string{}
	add := func(row, s string) {
		if row == "O" {
			operator = append(operator, s)
		} else {
			stop = append(stop, s)
		}
	}
	c := runs["C"]
	for _, p := range l68Gated() {
		k := p.key()
		cc := c.cells[k]
		switch {
		case p.entry:
			for _, row := range []string{"P", "H", "O", "V", "C"} {
				if runs[row].cells[k] == "ran" {
					add(row, fmt.Sprintf("%s: %s entered configuration mode", k, row))
				}
			}
			continue
		case p.evidence == hostEvidence:
			if p.canonical && cc != "ran" {
				invalid = append(invalid, k+": the control "+cellOr(c, k))
			}
			for _, row := range l68DenyRows {
				if got := runs[row].cells[k]; got != "ran" {
					add(row, fmt.Sprintf("%s: %s %s, so the bit does not deliver the configuration", k, row,
						cellOr(runs[row], k)))
				}
			}
			if !p.exec && runs["V"].cells[k] == "ran" {
				stop = append(stop, k+": V ran it under `view` alone, which L12-bits measured refused")
			}
			continue
		}
		if p.canonical && cc != "ran" && cc != "past" && cc != "platform refused" {
			invalid = append(invalid, k+": the control "+cellOr(c, k))
		}
		for _, row := range l68DenyRows {
			v := l68Verdict(runs[row].cells[k], cc)
			verdicts[row+" "+k] = v
			if v == "reached" {
				add(row, fmt.Sprintf("%s: %s took it past its deny", k, row))
			}
		}
	}
	for _, w := range beyond(surveyC, surveyVc) {
		if !heldBy(reach, w+" **") {
			stop = append(stop, fmt.Sprintf("completion: view-configuration offers %q over `view`, which its "+
				"declared reach does not hold, so no deny covers it", w))
		}
	}
	return invalid, stop, operator, verdicts
}

// l68Guard is the lab's rules before each row: the STOP sentinel and the
// disk floor.
func l68Guard(t *testing.T) {
	t.Helper()
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("%v", err)
	}
}

// l68Reference is set 1.2.0's reference configuration for juniper_junos:
// remote in the bitless p49-remote, as the projection differential applies it.
func l68Reference(t *testing.T) []string {
	t.Helper()
	set, _ := adapter.Set("1.2.0")
	ref, err := adapter.ReferenceClasses(set["juniper_junos"], 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func (l *lab) l68RestoreDaemon(t *testing.T) {
	t.Helper()
	if std, err := l.configPath(); err == nil {
		if err := l.restart(std); err != nil {
			t.Errorf("could not put port49d back on the lab config: %v", err)
		}
	}
}

// l68Exec runs l68ExecProbes over the SSH exec channel, one session each on
// one connection with the next token, while port49d sends the row's reply.
func (l *lab) l68Exec(t *testing.T, r l26cRun) {
	t.Helper()
	user, secret := l.nextLogin(t)
	conn, err := l.dialHostPort(user, secret, l.p.addr+":22", 60*time.Second)
	if err != nil {
		for _, p := range l68ExecProbes {
			r.cells[p.key()], r.outs[p.key()] = dialCell(err), oneLine(err.Error())
		}
		return
	}
	defer conn.Close()
	for _, p := range l68ExecProbes {
		k := p.key()
		s, err := conn.NewSession()
		if err != nil {
			r.cells[k], r.outs[k] = "not observed", oneLine(err.Error())
			continue
		}
		var out xnmOut
		s.Stdout, s.Stderr = &out, &out
		done := make(chan error, 1)
		go func() { done <- s.Run(p.cmd) }()
		select {
		case err = <-done:
		case <-time.After(junosPer):
			err = fmt.Errorf("no exit within %s", junosPer)
		}
		s.Close()
		r.outs[k] = firstLines(out.String(), 12)
		r.cells[k] = l68ExecCell(p, out.String(), err)
	}
}

// l68PagerSave pages `show configuration` and answers the pager's `s` with
// path, then quits the pager and turns paging off again. It records what the
// pager said; whether the file was written is read over the admin CLI
// afterwards (l68Files). A reading only (L59).
func l68PagerSave(c *cliConn, path string) (string, string) {
	from := len(c.out.String())
	if _, err := c.sendExpect("set cli screen-length 5", junosPer, junosOpPrompt); err != nil {
		return "not observed", oneLine(err.Error())
	}
	if err := c.send("show configuration"); err != nil {
		return "not observed", oneLine(err.Error())
	}
	if _, err := c.expectFrom(from, junosPer, junosPagerMark, junosOpPrompt); err != nil ||
		!junosPaged(c.out.String()[from:]) {
		junosSettle(c)
		c.sendExpect("set cli screen-length 0", junosPer, junosOpPrompt)
		return "no pager", c.out.String()[from:]
	}
	at := len(c.out.String())
	fmt.Fprint(c.in, "s")
	_, err := c.expectFrom(at, junosPer, "ile", junosPagerMark, junosOpPrompt)
	cell := "prompted for a file"
	if err != nil || !strings.Contains(c.out.String()[at:], "ile") {
		cell = "no save prompt"
	} else {
		c.send(path)
		c.expectFrom(at, junosPer, junosPagerMark, junosOpPrompt)
	}
	fmt.Fprint(c.in, "q")
	c.expectFrom(at, junosPer, junosOpPrompt)
	junosSettle(c)
	c.sendExpect("set cli screen-length 0", junosPer, junosOpPrompt)
	return cell, c.out.String()[from:]
}

// l68Files lists what the rows' `| save` and pager `s` wrote under /var/tmp,
// over the break-glass CLI, and deletes each.
func (l *lab) l68Files(t *testing.T) string {
	t.Helper()
	var out string
	l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
		return l.junosCLI(breakglassUser, breakglassPassword)
	}, func(c *cliConn) error {
		o, err := l26cSend(c, "file list /var/tmp/ | match p49-l68")
		out = o
		if err != nil {
			return err
		}
		for _, v := range junosL68Variants {
			for _, f := range []string{"p49-l68-pipe-", "p49-l68-pager-"} {
				l26cSend(c, "file delete /var/tmp/"+f+v.name)
			}
		}
		return nil
	})
	return out
}

func TestL68ViewConfigurationCLI(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		l68Guard(t)
		stop := l.capture(t, "L68")
		defer stop()
		reference := l68Reference(t)
		commit := l.junosConfigureAdmin(t, reference)
		defer l.junosConfigureAdmin(t, projectionRestore(reference))
		defer l.l68RestoreDaemon(t)
		l.stageOpScript(t)
		runs := map[string]l26cRun{}
		surveys := map[string][]string{}
		var invalid []string
		for _, v := range junosL68Variants {
			l68Guard(t)
			r := newL26cRun()
			runs[v.name] = r
			c, run, _ := l.junosLogin(t, "L68 "+v.name, v.attrs)
			if c == nil {
				t.Fatalf("INVALID: %s: the session did not open, so nothing was measured: %s", v.name, run.loginErr)
			}
			r.outs["show cli authorization"] = run.auth
			if got := l68AuthBits(run.auth); !slices.Equal(got, l68Bits[v.name]) {
				invalid = append(invalid, fmt.Sprintf("%s: show cli authorization lists %v, want %v: the reply did "+
					"not land as sent, or a configuration group adds a bit to p49-remote", v.name, got, l68Bits[v.name]))
			}
			promptLen := len(run.user + "@" + junosHost + "> ")
			// l26cSend keeps the echo, which caretAt reads the caret against;
			// junosProbe trims it. Paging is off (junosLogin's junosPrepare).
			for _, p := range l68Probes {
				out, err := l26cSend(c, p.cmd)
				r.outs[p.cmd], r.cells[p.cmd] = out, l68Cell(p, out, promptLen)
				if err == nil && p.entry && r.cells[p.cmd] == "ran" {
					_, err = l26cSend(c, "exit configuration-mode")
				}
				if err != nil {
					r.cells[p.cmd] = "not observed"
					break // the session's state is unknown past a missed prompt
				}
			}
			pipe := "show configuration system host-name | save /var/tmp/p49-l68-pipe-" + v.name
			r.outs["| save"], _ = l26cSend(c, pipe)
			r.cells["pager s"], r.outs["pager s"] = l68PagerSave(c, "/var/tmp/p49-l68-pager-"+v.name)
			if v.name == "C" || v.name == "Vc" {
				surveys[v.name] = l.junosSurvey(t, "L68 "+v.name, c, &run)
			}
			if len(run.unobserved) > 0 {
				invalid = append(invalid, fmt.Sprintf("%s: not observed: %s", v.name, strings.Join(run.unobserved, ", ")))
			}
			c.Close()
			// port49d still sends this row's reply: the exec channel and scp
			// log in under it.
			if slices.Contains([]string{"P", "H", "O", "C"}, v.name) {
				l.l68Exec(t, r)
			}
			if slices.Contains([]string{"P", "V", "C"}, v.name) {
				l.entryScp(t, r, "/config/juniper.conf.gz") // a reading (L59)
			}
		}
		files := l.l68Files(t)
		set, _ := adapter.Set("1.2.0")
		gi, stopped, operator, verdicts := l68Gate(runs, surveys["C"], surveys["Vc"],
			set["juniper_junos"].Bits["view-configuration"])
		invalid = append(invalid, gi...)
		// A gated cell not observed (or never typed, past a missed prompt) says
		// nothing: the run is INVALID before any STOP is read.
		for _, p := range l68Gated() {
			rows := []string{"P", "H", "O", "V", "C"}
			if p.exec {
				rows = []string{"P", "H", "O", "C"}
			}
			for _, n := range rows {
				if cell, ok := runs[n].cells[p.key()]; !ok || cell == "not observed" || cell == "login refused" {
					invalid = append(invalid, fmt.Sprintf("%s in %s: %s", p.key(), n, cellOr(runs[n], p.key())))
				}
			}
		}
		if len(invalid) > 0 {
			t.Fatalf("INVALID: %s; no note is written", strings.Join(invalid, "; "))
		}
		// Anything that failed before the STOPs are read makes a STOP note
		// INVALID too (pre-flight I3).
		failedBefore := t.Failed()
		var b strings.Builder
		fmt.Fprintf(&b, "**Gate:** %s; %s\n\nThe reference configuration was committed: %s.\n\n",
			l68GateLine("G1", stopped), l68GateLine("G1-operator", operator), commitWord(commit))
		l68Tables(&b, runs, verdicts, surveys, files)
		for _, s := range stopped {
			t.Errorf("STOP: %s: no reply change ships; report to the controller (plan 9g R1)", s)
		}
		for _, s := range operator {
			t.Errorf("STOP (G1-operator): %s: the operator reply does not ship; report to the controller", s)
		}
		l.l68Note(t, "L68", "Whether `user-permissions` holding view-configuration, with deny-commands covering `show "+
			"security` and view-configuration's other reach, lets the session read the configuration and nothing the "+
			"denies leave open, at the CLI and over the exec channel, for a readonly's reply and an operator's, "+
			"against `view` alone and a control with the same bits and no deny (spec §15 L68; plan 9g Task 1, gates "+
			"G1 and G1-operator).", b.String(), len(stopped)+len(operator) > 0, failedBefore)
	})
}

// l68GateLine is a gate's line in a note: pass, or STOP and why.
func l68GateLine(gate string, stops []string) string {
	if len(stops) == 0 {
		return gate + ": pass"
	}
	return gate + ": STOP — " + strings.Join(stops, "; ")
}

func TestL68ViewConfigurationNetconf(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		l.l68Netconf(t, "L68-netconf", "G1", []string{"P", "H"})
	})
}

func TestL68ViewConfigurationNetconfOperator(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		l.l68Netconf(t, "L68-netconf-operator", "G1-operator", []string{"O"})
	})
}

// l68Netconf probes NETCONF (`xml-mode` from the CLI, port 830, the port-22
// subsystem, the exec channel) in the deny rows and the control C, and gates
// them under gate. Each row takes four tokens, so the readonly rows and the
// operator row run in two invocations within the pool of 16.
func (l *lab) l68Netconf(t *testing.T, entry, gate string, deny []string) {
	t.Helper()
	if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
		t.Skip("Junos only")
	}
	l68Guard(t)
	stop := l.capture(t, entry)
	defer stop()
	reference := l68Reference(t)
	commit := l.junosConfigureAdmin(t, append(slices.Clone(reference), "set system services netconf ssh"))
	defer l.junosConfigureAdmin(t, projectionRestore(reference))
	defer l.l68RestoreDaemon(t)
	probes, canonical := entryProbes[1:], entryCanonical[1:] // the CLI test reads the configuration
	names := append(slices.Clone(deny), "C")
	runs := map[string]l26cRun{}
	for _, n := range names {
		l68Guard(t)
		v := l68Variant(n)
		r := newL26cRun()
		runs[n] = r
		c, run, _ := l.junosLogin(t, "L68 netconf "+n, v.attrs)
		if c == nil {
			t.Fatalf("INVALID: %s: the session did not open, so nothing was measured: %s", n, run.loginErr)
		}
		r.outs["show cli authorization"] = run.auth
		entryXMLMode(c, r)
		c.Close()
		l.entryNetconf(t, r, "port 830", "830")
		l.entryNetconf(t, r, "port 22 subsystem", "22")
		l.entryExec(t, r)
	}
	var unobserved []string
	for _, p := range probes {
		for _, n := range names {
			if runs[n].cells[p] == "not observed" || runs[n].cells[p] == "login refused" {
				unobserved = append(unobserved, p+" in "+n)
			}
		}
	}
	readings, unisolated := entryVerdict(runs, deny, "C", canonical, probes)
	if len(unisolated) > 0 {
		entryLogControl(t, runs["C"], unisolated)
		t.Fatalf("INVALID: the control did not reach %s; no note is written", strings.Join(unisolated, "; "))
	}
	// A deny row's cell counts as refused only on a positive refusal: a
	// reading of "not observed" (a login refused, a hang) is INVALID, never a
	// pass (pre-flight I4).
	for _, n := range deny {
		for _, p := range probes {
			if readings[n+" "+p] == "not observed" {
				unobserved = append(unobserved, p+" in "+n+" (reading)")
			}
		}
	}
	if len(unobserved) > 0 {
		t.Fatalf("INVALID: not observed: %s; no note is written", strings.Join(unobserved, "; "))
	}
	var stopped []string
	for k, v := range readings {
		if v == "reached" {
			stopped = append(stopped, k)
		}
	}
	slices.Sort(stopped)
	failedBefore := t.Failed()
	var b strings.Builder
	fmt.Fprintf(&b, "**Gate:** %s\n\nThe reference configuration and `netconf ssh` were committed: %s.\n\n",
		l68GateLine(gate, stopped), commitWord(commit))
	l68NetconfTables(&b, runs, readings, probes, names, deny)
	for _, s := range stopped {
		t.Errorf("STOP (%s): reached past the entry deny: %s; report to the controller (plan 9g R1)", gate, s)
	}
	l.l68Note(t, entry, "Whether NETCONF (`xml-mode` from the CLI, port 830, the port-22 subsystem, the exec "+
		"channel) reaches `<get-configuration/>` under a reply holding view-configuration with the entry denies "+
		"beside view-configuration's other reach denied ("+strings.Join(deny, ", ")+"), against a control with "+
		"the same bits and no deny (spec §15 L68; plan 9g Task 1, gate "+gate+").", b.String(), len(stopped) > 0,
		failedBefore)
}

// l68Note writes the note. A passing run goes through entryResult, which
// writes nothing after a failure. A STOP is a measurement, so its note is
// written, under the same leak check, but only where the run was otherwise
// VALID: failedBefore (anything failed before the STOPs were read) makes it
// INVALID, and no note is written (pre-flight I3).
func (l *lab) l68Note(t *testing.T, entry, claim, observation string, stopped, failedBefore bool) {
	t.Helper()
	if !stopped {
		l.entryResult(t, entry, claim, observation)
		return
	}
	if failedBefore {
		t.Fatalf("INVALID: %s: the run read a STOP but had already failed; no note is written", entry)
	}
	if err := leakIn(claim+"\n"+observation, poolSecrets()); err != nil {
		t.Fatalf("%s: the note is withheld: %v", entry, err)
	}
	l.result(t, entry, claim, observation)
}

// l68Tables writes the rows, every probe's cells, the verdicts against the
// control, the completion difference, the files, and each row's raw outputs.
func l68Tables(b *strings.Builder, runs map[string]l26cRun, verdicts map[string]string, surveys map[string][]string,
	files string) {
	names := []string{"P", "H", "O", "V", "Vc", "C"}
	b.WriteString("| row | reply | why | `show cli authorization` bits |\n|---|---|---|---|\n")
	for _, v := range junosL68Variants {
		fmt.Fprintf(b, "| %s | `%s` | %s | %s |\n", v.name, tableCell(v.attrs), v.why,
			strings.Join(l68AuthBits(runs[v.name].outs["show cli authorization"]), " "))
	}
	fmt.Fprintf(b, "\n| probe | %s |\n|---|%s\n", strings.Join(names, " | "), strings.Repeat("---|", len(names)))
	var keys []string
	for _, p := range slices.Concat(l68Probes, l68ExecProbes) {
		keys = append(keys, p.key())
	}
	keys = append(keys, "pager s", "scp /config/juniper.conf.gz")
	for _, k := range keys {
		cells := make([]string, len(names))
		for i, n := range names {
			cells[i] = cellOr(runs[n], k)
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(k), strings.Join(cells, " | "))
	}
	b.WriteString("\n### Verdict against the control\n\n| probe | P | H | O |\n|---|---|---|---|\n")
	for _, p := range l68Gated() {
		if !p.entry && p.evidence != hostEvidence {
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n", tableCell(p.key()), verdicts["P "+p.key()],
				verdicts["H "+p.key()], verdicts["O "+p.key()])
		}
	}
	fmt.Fprintf(b, "\n### Completion: what view-configuration offers over `view` (C against Vc)\n\n%s\n",
		strings.Join(beyond(surveys["C"], surveys["Vc"]), ", "))
	fmt.Fprintf(b, "\n### Files under /var/tmp after the rows (`| save`, pager `s`)\n\n```\n%s\n```\n", files)
	for _, n := range names {
		fmt.Fprintf(b, "\n### %s\n", n)
		ks := make([]string, 0, len(runs[n].outs))
		for k := range runs[n].outs {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		for _, k := range ks {
			fmt.Fprintf(b, "\n`%s`:\n\n```\n%s\n```\n", k, firstLines(runs[n].outs[k], 20))
		}
	}
}

// l68NetconfTables writes the NETCONF rows' cells, the deny rows' verdicts
// and the raw outputs.
func l68NetconfTables(b *strings.Builder, runs map[string]l26cRun, readings map[string]string, probes, names,
	deny []string) {
	fmt.Fprintf(b, "| probe | %s |\n|---|%s\n", strings.Join(names, " | "), strings.Repeat("---|", len(names)))
	for _, p := range probes {
		cells := make([]string, len(names))
		for i, n := range names {
			cells[i] = cellOr(runs[n], p)
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(p), strings.Join(cells, " | "))
	}
	fmt.Fprintf(b, "\n### Verdict against the control\n\n| probe | %s |\n|---|%s\n", strings.Join(deny, " | "),
		strings.Repeat("---|", len(deny)))
	for _, p := range probes {
		cells := make([]string, len(deny))
		for i, n := range deny {
			cells[i] = jsdOrDash(readings[n+" "+p])
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(p), strings.Join(cells, " | "))
	}
	for _, n := range names {
		fmt.Fprintf(b, "\n### %s\n", n)
		ks := make([]string, 0, len(runs[n].outs))
		for k := range runs[n].outs {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		for _, k := range ks {
			fmt.Fprintf(b, "\n`%s`:\n\n```\n%s\n```\n", k, firstLines(runs[n].outs[k], 20))
		}
	}
}
```

If a helper named above does not exist under that exact name, `go vet -tags lab` reports it.
Use the existing helper of that role; do not write a second one. `entryScp` writes its cell under
the key `scp /config/juniper.conf.gz` (`tests/lab/junos_entry_test.go:460`).

Before the first run, check `l68AuthBits` against a real `show cli authorization` output recorded
in `tests/lab/results/L26c-projected-juniper_vjunos-router.md`. If its format differs from the
unit test's sample, fix both the sample and the parser to match.

- [ ] **Step 5: Run the unit tests and vet**

Run: `gofmt -l tests/lab/ && go test -tags lab ./tests/lab/ -run '^TestL68' -count=1 && go vet -tags lab ./tests/lab/ && make lab-unit`
Expected: no file listed by `gofmt -l`, and PASS. Then prove each test by mutation, and revert each mutation:
- change one byte of `l68Projected`;
- drop `virtual-chassis` from `l68Hand`;
- make `l68Cell` return "past" for a caret on the prefix;
- make `l68Verdict` read two platform refusals as "reached";
- make `l68Gate` skip the completion check;
- make `l68Gate` put O's STOPs in `stop`;
- make `l68ExecCell` read a refusal as "past";
- make `l68AuthBits` keep the `--` suffix.

Each must turn a test red.

- [ ] **Step 6: Commit the harness and the open row**

```bash
git add tests/lab/junos_viewcfg_test.go tests/lab/junos_viewcfg_unit_test.go docs/design/2026-08-23-policy-engine-spec.md
git commit -m "test: L68 harness, view-configuration with its other reach denied"
```

- [ ] **Step 7: Run L68 on both images, under the lab rules**

The lab has one occupant at a time. Check it and the floor first:

```bash
pgrep -f "^/tmp/go-build[^ ]*/lab\.test" && { echo "a lab run is live: wait"; exit 1; }
ls -d $HOME/git/port49/.worktrees/*-run 2>/dev/null && { echo "another run worktree exists: wait"; exit 1; }
[ -e /tmp/port49-STOP-LAB ] && { echo "the STOP sentinel is set"; exit 1; }
[ "$(df -BM --output=avail / | tail -1 | tr -dc 0-9)" -ge 67584 ] || { echo "below the 67584M floor"; exit 1; }
```

Then pin the run worktree:

```bash
sha=$(git -C $HOME/git/port49/.worktrees/junos-view-configuration rev-parse HEAD)
git -C $HOME/git/port49 worktree add --detach $HOME/git/port49/.worktrees/l68-run "$sha"
cd $HOME/git/port49/.worktrees/l68-run && make build
```

Start the run loop detached, with its pid recorded. Each test runs in its own invocation per
platform:

```bash
cd $HOME/git/port49/.worktrees/l68-run
nohup bash -c 'for t in TestL68ViewConfigurationCLI TestL68ViewConfigurationNetconf TestL68ViewConfigurationNetconfOperator; do
  for p in vjunos vsrx; do
    PORT49_LAB_PLATFORMS=$p go test -tags lab ./tests/lab/ -run "^$t\$" -count=1 -v -timeout 90m || exit 1
  done
done; make evidence' > /tmp/l68-run.log 2>&1 &
echo $! > /tmp/l68-loop.pid
```

Arm the stall watchdog in a background shell, and re-arm it on every wake. It watches the loop's
pid, not `lab.test`, which is absent between invocations and during each compile (pre-flight
I7):

```bash
loop=$(cat /tmp/l68-loop.pid)
while kill -0 "$loop" 2>/dev/null; do
  sleep 120
  [ -z "$(find $HOME/git/port49/.worktrees/l68-run/tests/lab/captures /tmp/port49-lab-tokens.jsonl \
    /tmp/l68-run.log -newermt '-10 minutes' 2>/dev/null | head -1)" ] && { echo "STALL: no progress in 10 minutes"; break; }
done; echo "the run loop ended"
```

Wait for the loop in the foreground, with a deadline: `while kill -0 "$(cat /tmp/l68-loop.pid)"
2>/dev/null; do sleep 60; done`. On a stall, take a goroutine dump (`kill -QUIT` on the
`lab.test` process) before anything else.

Expected: six PASS runs and six notes.
- L68 notes read `G1: pass; G1-operator: pass`.
- L68-netconf notes read `G1: pass`.
- L68-netconf-operator notes read `G1-operator: pass`.

Other outcomes:
- **`INVALID:`** writes no note. Fix the harness or the cell reader, then rerun. A control that
  cannot reach is a harness or image fault.
- **A G1 `STOP:`** (rows P or H) writes its note. **Stop the plan here.** Report to the
  controller with the note's tables. Do not start Task 2.
- **A `STOP:` in row P** is a live hole in set 1.2.0. Row P is a reply set 1.2.0 sends today to
  a grant that writes `deny: [monitor **]`. Stop, still do Step 8 (copy the outputs out) so the
  note is kept, and report it to the controller as a security finding for Ryan's attention,
  naming the probe and the image. Do not continue silently. Do not start any later task, and do
  not rerun to get a different answer.
- **A G1-operator `STOP:`** (row O) with G1 passing is a live hole in set 1.2.0 for that
  operator grant. Report it the same way, for Ryan's attention. Then continue the plan with
  the operator class keeping today's reply:
  - Task 4 Step 3b applies the restriction;
  - Task 2 and the operator notes say operators are unchanged;
  - Task 6 expects row "operator denying show security" to render without view-configuration.

  The loop exits at the first failing invocation, and a G1-operator STOP fails its invocation.
  So rerun the invocations it did not reach, without the failed one. This is not a rerun of the
  failed measurement.

- [ ] **Step 8: Copy the outputs out and remove the run worktree**

```bash
run=$HOME/git/port49/.worktrees/l68-run
feat=$HOME/git/port49/.worktrees/junos-view-configuration
cp "$run"/tests/lab/results/L68-*.md "$feat"/tests/lab/results/
cp "$run"/tests/lab/evidence/L68-*.pcap "$feat"/tests/lab/evidence/
mkdir -p $HOME/git/port49/tests/lab/captures && cp "$run"/tests/lab/captures/L68* $HOME/git/port49/tests/lab/captures/
git -C $HOME/git/port49 worktree remove "$run"
```

On a G1 STOP, commit the notes and evidence and leave the L68 row open. Add to its Status:
"STOP measured <date>; see the notes". Then report:

```bash
git add tests/lab/results/L68-*.md tests/lab/evidence/L68-*.pcap docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: L68 STOP, a refused probe ran under view-configuration"
```

- [ ] **Step 9: Close L68 and commit (only on G1: pass on both images)**

Edit the L68 row's Status to:

```
closed — measured <date>; `tests/lab/results/L68-juniper_vjunos-router.md`, `L68-juniper_vsrx.md`, `L68-netconf-juniper_vjunos-router.md`, `L68-netconf-juniper_vsrx.md`, `L68-netconf-operator-juniper_vjunos-router.md`, `L68-netconf-operator-juniper_vsrx.md`
```

Use the run's date. Then, in the row:
- Add one sentence per reading the notes record, without widening any claim:
  - `show log`, `show firewall`, `show policer`;
  - the `/config` reads, the CLI ones and scp's;
  - `| save` and pager `s`, which stay L59's;
  - any word that "runs nowhere" on an image.
- Say G1-operator's outcome. A G1-operator STOP is a measured outcome, so the row still
  closes, with that result.

```bash
git add tests/lab/results/L68-*.md tests/lab/evidence/L68-*.pcap docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L68"
```

**Gate G1:** Tasks 2 to 7 start only when both images' L68 notes read `G1: pass`, and both
images' L68-netconf notes read `G1: pass`. G1-operator decides only Task 4 Step 3b and the
operator wording. R3 is ruled: set 1.3.0.

---

### Task 2: The spec, first (depends on G1)

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`, in these places:
  - §8 Fields table, after the `rpc_entry_denies` row (:3644);
  - §8 :4065-4070, the paragraph beginning "So a readonly granted `show **` less `show configuration **`"
    and ending "as under set 1.1.0." (the next paragraph, "Where the reply must send an allow…", stays);
  - §8 :4078-4081, the warning paragraph;
  - §8 :4083, "**Set 1.1.0 is unchanged**";
  - §12 findings table, the `projection_deny_beneath_view_configuration` row (:5886);
  - §13 decision 44 ruling 10's last sentence (:9004-9006);
  - §13: a new decision 48 after decision 47, before "## 14. Required test assertions" (:9848).

Line numbers are as of `ded40681`; find each by its quoted text, which is what binds.

**Interfaces:** Produces the text Tasks 3 to 5 cite: decision 48, the key `deny_reach_bits`, and
the role `reach_deny`.

- [ ] **Step 1: Add the Fields row** after `rpc_entry_denies`:

```markdown
| `deny_reach_bits` | on a projected platform whose adapter carries `rpc_entry_denies`, the bits a reply may send where the grant permits a carve-out of the bit that an allow past the bits is not measured to run, with the rest of the bit's reach that the grant decides nothing of denied on the wire, role `reach_deny` (decision 48). Set 1.3.0's `juniper_junos` carries `[view-configuration]` (L68). Each is a declared bit, never `baseline` or `all`; a bit with no carve-out (a block may drop it) is inert. A block may drop one, `[]` all, and never add one; where the block drops `rpc_entry_denies` the key is inert | optional |
```

- [ ] **Step 2: Replace :4065-4070** (from "So a readonly granted `show **` less `show
  configuration **` gets `view`" through "as under set 1.1.0.") with the text below. Write
  each measured sentence as Task 1's notes read it. If a note records a word that "runs
  nowhere" on an image, say so for that image. Widen nothing.

```markdown
So a readonly granted `show **` less `show configuration **` gets `view`, a `deny-commands` of
170 bytes (its twelve `word **` denies and `junoscript` in one alternative, `set cli` and its
own deny), and allows of `show log`, `show firewall` and `show policer`, view-configuration's
other carve-outs. view-configuration stays out: the grant denies the configuration, the one
thing only it adds. A readonly granted `show **` alone keeps the narrow shape and both bits, as
under set 1.1.0.

**A grant that permits `show configuration` under a deny beneath `show`** (decision 48), at any
level whose ceiling holds view-configuration. Take a readonly granted `show **` less `show
security **`. Only view-configuration shows the configuration: under `view`
an allow of `show configuration` was refused on both images (`L26c-projected-juniper_*.md`).
Under set 1.2.0 that readonly gets `view` and allows of the four carve-outs, and the device
refuses `show configuration`; CI says so. Under set 1.3.0, whose `juniper_junos` carries
`deny_reach_bits: [view-configuration]`, the reply sends `view view-configuration`. It denies
the reach of view-configuration that the grant decides nothing of: here `monitor **`, since the
baseline denies already hold `request **`, `load **` and `save **`. Its `deny-commands` is 173
bytes, the grant's deny, then `monitor` in the baseline's alternative. An operator granted `show
**` and `clear **` less `show security **` gets `clear view view-configuration` and the same
`deny-commands`.

L68 measured those replies on both images (`tests/lab/results/L68-juniper_*.md`,
`L68-netconf-juniper_*.md`, `L68-netconf-operator-juniper_*.md`):
- `show cli authorization` listed each reply's bits exactly;
- `show configuration` ran, at the CLI and over the SSH exec channel;
- `show security` was refused;
- each word of view-configuration's other reach was refused, typed in full and abbreviated, and
  `monitor list` over the exec channel;
- no row entered configuration mode (`configure`, `edit`, `configure private`);
- `<get-configuration/>` was refused on every way into NETCONF, and so was `op url`;
- the control, with the same bits and no deny, reached each one;
- a deny of exactly view-configuration's other reach, with no baseline denies, was refused the same way;
- view-configuration's completion over `view` offered no word its declared reach does not hold.

If L68's operator row stopped (G1-operator), say instead that the operator reply was not
measured safe, and that an operator keeps set 1.2.0's reply under 1.3.0: the bit goes out only
beside `view` alone (Task 4 Step 3b).

Completion lists no hidden command, so that reach is an upper bound only as far as completion
shows it (L12-bits). The bit goes out this way only where all of these hold:

- the adapter lists it in `deny_reach_bits` and carries `rpc_entry_denies`, under
  `user_permissions` (a template's class carries every bit, so `local_user_name` is unchanged);
- the grant permits a carve-out of the bit that no deny holds whole, and an allow of it past the
  bits is not measured to run (`show configuration`, not `show log`);
- a bit the reply already sends reaches that carve-out (view-configuration alone shows no
  configuration, `L12-bits-juniper_*.md`);
- no permit meets the reach it denies, and the keyword tree proves each of those denies.

Otherwise the reply is set 1.2.0's. The reach denies follow the grant's own and precede the
baseline's, so a 1.2.0 grant that writes `deny: [monitor **]` itself renders the same bytes.
Where they would take `deny-commands` past 255 bytes, the reply falls back to set 1.2.0's: no
view-configuration, the carved allows, and the device refusing `show configuration`, as
measured. That reply is no wider than port49. CI warns `projection_reach_deny_overflow`, naming
the reach denies and the remedy. The composition fails closed only where that reply cannot
carry it either.
```

- [ ] **Step 3: Amend the warning paragraph** (:4078-4081). Change "CI reports two warnings." to
  "CI reports three warnings.". After "...so withholding the bit is the real fence.", add:

```markdown
A reply that sends view-configuration under decision 48 carries no deny that meets `show
configuration`, and a reach deny is never named, so it gets no such warning.
`projection_reach_deny_overflow` names each composition whose reach denies would pass 255 bytes,
which keeps set 1.2.0's reply (decision 48 ruling 4).
```

- [ ] **Step 4: Replace "**Set 1.1.0 is unchanged**, since a released set is never edited."**
  with:

```markdown
**Sets 1.1.0 and 1.2.0 are unchanged**, since a released set is never edited. Set 1.2.0 renders
the readonly above without view-configuration on every binary; decision 48 ships as set 1.3.0,
the default, and a policy moves to it with `port49 platform upgrade --to 1.3.0`, whose gated
`deny_reach_bits` entry is the review. Set 1.1.0
```

  Keep the rest of the paragraph ("sends no entry deny, so a composition…") as it is.

- [ ] **Step 5: The §12 row.** In `projection_deny_beneath_view_configuration`'s Condition cell,
  after "withhold the bit instead (§8; decision 44)", add "; a reach deny (decision 48) is never
  named". Then, after that row, add the new warning. It must be in the spec before Task 4 or
  Task 5 uses the name:

```markdown
| `projection_reach_deny_overflow` | on a platform whose pinned set carries `deny_reach_bits`, a composition whose reply would send a bit with its undecided reach denied (decision 48), except that those denies take `deny-commands` past RFC 8907's 255 bytes. The reply falls back to the one the set renders without the key: the bit not sent, and the device refusing the carve-out it would have shown (`show configuration`). The warning names the reach denies and the remedy: fewer denies beneath `show`, or the denies moved into the template's class (`port49 platform export --classes`) | no, a warning; `policy diff` prints the ones the change brings |
```

- [ ] **Step 6: Decision 44 ruling 10** (:9004-9006). Replace its last sentence, "view-configuration is not
  sent to such a readonly, whose grant decides none of its other reach; ruling 4's warning stays
  an operator's and an admin's.", with:

```markdown
Under set 1.2.0 view-configuration is not sent to such a readonly, whose grant decides none of
its other reach; set 1.3.0 sends it where the grant permits `show configuration` (decision 48).
Ruling 4's warning stays an operator's and an admin's.
```

- [ ] **Step 7: Add decision 48** after decision 47 ends, directly before "## 14. Required test
  assertions" (:9848):

```markdown
**48. Junos: view-configuration sent with the rest of its reach denied.** *Plan 9g, 2026-10-16,
on Ryan's ruling of 2026-10-15: "permitted means it runs".* Rulings rest on reasoning unless they
say data.

- **1. The rule** (data: `tests/lab/results/L68-juniper_*.md`, `L68-netconf-juniper_*.md`,
  `L68-netconf-operator-juniper_*.md`). Under a set whose platform carries `deny_reach_bits` and
  `rpc_entry_denies`, under `user_permissions`, at any level whose ceiling holds the bit (a
  readonly's and an operator's alike), a ceiling bit the grant decides only in part is sent where:
  - the key lists it;
  - the grant permits a carve-out of it that no deny holds whole and whose allow past the bits
    is not measured to run (`JunosFacts.AllowPastCarve`);
  - a bit the reply already sends reaches that carve-out;
  - no permit meets the rest of its reach, each rule of which the keyword tree proves.

  That rest goes out as denies, role `reach_deny`, after the grant's own denies and before the
  baseline's. The deny beneath the bit brings the entry denies (decision 44 ruling 1). If L68's
  operator row stopped, add here: the bit goes out only beside `view` alone, and an operator
  keeps set 1.2.0's reply (plan 9g G1-operator).
- **2. A new set** (§8, "the platform set is pinned"). Ryan's ruling named set 1.2.0. Set 1.2.0 is
  released: its files are frozen, and a binary upgrade must not change what a pinned policy
  renders. So the change is set 1.3.0, which is 1.2.0 plus `juniper_junos`'s `deny_reach_bits:
  [view-configuration]`, 1.2.0's keyword tree unchanged. `DefaultSet` is 1.3.0. A policy pinned to
  1.2.0 renders byte for byte as before. A policy writing `deny: [monitor **]` under 1.2.0 already
  gets the 1.3.0 reply (L68's row P). (Controller's ruling on plan 9g R3, 2026-10-16.)
- **3. The key is adapter data**, read only on a projected platform. A block may drop an entry and
  never add one the set did not measure. A block that drops `rpc_entry_denies` makes it inert: a
  wire deny binds no native RPC, so the bit is never sent with denies alone guarding it. A block
  that adds reach to a listed bit has that reach denied too where the tree proves it, and the
  bit is not sent where it does not. A block that drops the bit's carve-out leaves the key inert,
  and the policy loads: no permit can need the bit sent.
- **4. The budget** (RFC 8907; Ryan's production experience that over 255 bytes locks the user
  out). The readonly granted `show **` less `show security **` renders 173 bytes, measured in a
  test. Where the reach denies would take it past 255, the reply falls back to the one the set
  renders without the key (set 1.2.0's): no bit, the carved allows, and `show configuration`
  refused, as measured (`L26c-projected-juniper_*.md`). Failing closed would take a working
  readonly to nothing for a narrowing the device already makes safely. CI warns
  `projection_reach_deny_overflow` (§12). (Controller's ruling, 2026-10-16.)
- **5. Warnings and predictions.** `projection_deny_beneath_view_configuration` never names a reach
  deny. `policy test` and `explain` predict `show configuration` runs under the reply, and the
  projection finding names the reach denies.
- **6. Unmeasured.** Hidden commands under view-configuration that completion does not list (L12-bits
  holds the reach as an upper bound for every bit). Bit sets other than the two L68 measured
  (`view view-configuration`, `clear view view-configuration`); the model covers them. L59's
  cells: REST, the XML API, `outbound-ssh`, file reads of `/config` (L68 recorded the CLI's and
  scp's, ungated), NETCONF off, and `| save` and the pager's `s`, which L68 recorded and did not
  gate.
```

- [ ] **Step 8: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: decision 48, set 1.3.0 sends view-configuration with its other reach denied"
```

---

### Task 3: Set 1.3.0 and the `deny_reach_bits` key (depends on G1)

**Files:**
- Modify: `internal/platform/dialect.go` (the `Dialect` struct after `RPCEntryDenies` :191; the role
  constants after `RPCEntryRole` :209; `generics` :297-311; `clone` :404)
- Modify: `internal/platform/adapter.go` (`Spec` :53; `Over` :116; `SpecOf` :697;
  `validateProjection` :814 and after the `RPCEntryDenies` loop :907)
- Modify: `internal/platform/set.go:16` (`DefaultSet`)
- Modify: `internal/policy/load.go` (the unprojected-platform key list :559; `keepsProjection`
  after the `carve_outs` loop :767)
- Create: `platforms/1.3.0/arista_eos.yaml`, `cisco_iosxe.yaml`, `cisco_nxos.yaml` (copies of
  1.2.0's), `platforms/1.3.0/juniper_junos.yaml` (1.2.0's plus the key)
- Create: `platforms/keywords/1.3.0/juniper_junos.yaml` (a copy of 1.2.0's)
- Test: `internal/platform/adapter_test.go`, `internal/platform/keywords_test.go`,
  `internal/platform/projection_rulings_test.go`, `internal/policy/platforms_test.go`,
  `cmd/port49/platform_test.go`

**Interfaces:**
- Produces:
  - `platform.Dialect.DenyReachBits []string`;
  - `platform.ReachDenyRole = "reach_deny"`;
  - `platform.Set("1.3.0")`;
  - `platform.DefaultSet == "1.3.0"`;
  - `platform.KeywordsFor("1.3.0", "juniper_junos")`.

- [ ] **Step 1: Write the failing tests**

In `internal/platform/adapter_test.go`, after `shipped120` (:178). The file lacks the `io/fs`
import, and the test needs it: add it, with `strings` and `github.com/blanketfish/port49/platforms` if
they are missing too.

```go
// shipped130 is set 1.3.0, value for value: 1.2.0 and juniper_junos's
// deny_reach_bits (decision 48).
var shipped130 = func() map[string]Dialect {
	out := map[string]Dialect{}
	for name, d := range shipped120 {
		out[name] = d.clone()
	}
	j := out["juniper_junos"]
	j.DenyReachBits = []string{"view-configuration"}
	out["juniper_junos"] = j
	return out
}()

// Set 1.3.0's files are 1.2.0's, byte for byte, but for juniper_junos's
// deny_reach_bits block after rpc_entry_denies: nothing else moves.
func TestTheSet130FilesAreSet120AndDenyReachBits(t *testing.T) {
	for _, name := range []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"} {
		was, err1 := fs.ReadFile(platforms.FS, "1.2.0/"+name+".yaml")
		is, err2 := fs.ReadFile(platforms.FS, "1.3.0/"+name+".yaml")
		if err1 != nil || err2 != nil {
			t.Fatal(name, err1, err2)
		}
		want := string(was)
		if name == "juniper_junos" {
			const at = "    rpc_entry_denies: [\"junoscript **\", \"op **\"]\n"
			want = strings.Replace(want, at, at+denyReachBlock, 1)
		}
		if string(is) != want {
			t.Errorf("platforms/1.3.0/%s.yaml is not 1.2.0's%s", name,
				map[bool]string{true: " with the deny_reach_bits block", false: ""}[name == "juniper_junos"])
		}
	}
}
```

Then:
- In `TestTheDefaultSetValueForValue` (:180), replace both `shipped120` with `shipped130`.
- Change `released` (:197) to:

```go
var released = map[string]map[string]Dialect{"1.0.0": shipped, "1.1.0": shipped110, "1.2.0": shipped120,
	"1.3.0": shipped130}
```

- Add `"1.3.0"` to `releasedGeneric` (:218) with the same value as `"1.2.0"`.
- Add `denyReachBlock` beside the test: the exact text Step 3 puts in the YAML. It has no
  backticks, so it is one raw string:

```go
const denyReachBlock = `    # Set 1.3.0: the bits a reply may send where the grant permits a carve-out
    # of the bit that an allow past the bits is not measured to run, with the
    # rest of the bit's reach the grant decides nothing of denied on the wire
    # (decision 48). view-configuration is the one: under view alone an allow
    # of show configuration was refused on both images
    # (tests/lab/results/L26c-projected-juniper_*.md), and under view and
    # view-configuration with its other reach denied, show configuration ran
    # and that reach, NETCONF and op url were refused on both images
    # (tests/lab/results/L68-juniper_*.md, L68-netconf-juniper_*.md). Read only
    # where rpc_entry_denies is kept: a wire deny binds no native RPC. A block
    # may drop an entry, never add one.
    deny_reach_bits: [view-configuration]
`
```

In `internal/platform/keywords_test.go`:
- Add `"1.3.0/juniper_junos": "2017ca9e10d5e3e7c53fb78cd65a5480aa91387212cef7a6924aa87110912688",`
  to `releasedKeywords` (:396). It is the same file, so the same sha256.
- Add:

```go
// Set 1.3.0's Junos tree is 1.2.0's, byte for byte (decision 48 changes no
// keyword).
func TestTheSet130JunosTreeIsSet120s(t *testing.T) {
	was, err1 := fs.ReadFile(platforms.Keywords, "keywords/1.2.0/juniper_junos.yaml")
	is, err2 := fs.ReadFile(platforms.Keywords, "keywords/1.3.0/juniper_junos.yaml")
	if err1 != nil || err2 != nil || string(is) != string(was) {
		t.Fatal("platforms/keywords/1.3.0/juniper_junos.yaml is not 1.2.0's", err1, err2)
	}
}
```

In `internal/platform/projection_rulings_test.go`, add cases to `TestValidateProjectionMessages`'
table. Its `d` is `junosProjected(BitDeliveryUserPermissions)`, which carries a
`view-configuration` carve-out.

```go
		{"a reach bit that is not a bit", func(d *Dialect) {
			d.RPCEntryDenies = []string{"junoscript **"}
			d.DenyReachBits = []string{"zzz"}
		}, "deny_reach_bits[0]: zzz is not a bit under bits"},
		{"baseline as a reach bit", func(d *Dialect) {
			d.RPCEntryDenies = []string{"junoscript **"}
			d.DenyReachBits = []string{BaselineBit}
		}, "deny_reach_bits[0]: baseline"},
```

A bit with no carve-out is not a load error: a block may drop the carve-out, and the key is then
inert (pre-flight M3). The shipped set must not list one, so pin that instead, in
`adapter_test.go`:

```go
// Every bit a released set lists in deny_reach_bits has a carve-out: no
// permit could need it sent otherwise (decision 48).
func TestShippedReachBitsHaveCarveOuts(t *testing.T) {
	for version, set := range released {
		for name, d := range set {
			for _, bit := range d.DenyReachBits {
				if len(d.CarveOuts[bit]) == 0 {
					t.Errorf("set %s, %s: deny_reach_bits names %s, which has no carve-out", version, name, bit)
				}
			}
		}
	}
}
```

And a new test for an unprojected platform:

```go
// deny_reach_bits is read only with command_projection.
func TestDenyReachBitsNeedAProjection(t *testing.T) {
	d, _ := Generic("1.2.0")
	d.DenyReachBits = []string{"view"}
	if err := Validate("x", d); err == nil || !strings.Contains(err.Error(), "deny_reach_bits is read only with "+
		"command_projection") {
		t.Errorf("%v", err)
	}
}
```

In `internal/policy/platforms_test.go`, after `TestABlockKeepsTheWholeEntryDenyListOrDropsIt` (:738):

```go
// A block may drop set 1.3.0's deny_reach_bits and never add a bit the set
// did not measure; a platform the set does not project may not carry it
// (decision 48 ruling 3).
func TestABlockMayDropDenyReachBitsNotAddOne(t *testing.T) {
	head := "platform_set: 1.3.0\nplatforms:\n  juniper_junos:\n"
	for _, c := range []struct {
		block string
		ok    bool
	}{
		{"    deny_reach_bits: []\n", true},
		{"    deny_reach_bits: [view-configuration]\n", true},
		{"    deny_reach_bits: [view-configuration, view]\n", false},
	} {
		_, err := Parse([]byte(head+c.block+scopeOK+"roles:\n  - {name: r, privilege: readonly, permit: [\"show **\"]}\n"+
			subjOK+grantOK), env())
		if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), "deny_reach_bits") {
			t.Errorf("%q: %v", c.block, err)
		}
	}
	_, err := Parse([]byte("platform_set: 1.3.0\nplatforms:\n  arista_eos:\n    deny_reach_bits: [view]\n"+
		scopeOK+"roles:\n  - {name: r, permit: [\"show **\"]}\n"+subjOK+grantOK), env())
	if err == nil || !strings.Contains(err.Error(), "deny_reach_bits") {
		t.Errorf("a platform the set does not project: %v", err)
	}
}

// A block that drops view-configuration's carve-out leaves deny_reach_bits
// inert: the policy loads on 1.3.0, so `platform upgrade --to 1.3.0` is not
// refused (pre-flight M3). reachDenies finds no carve-out to need the bit.
func TestABlockDroppingTheCarveOutLoadsOn130(t *testing.T) {
	_, err := Parse([]byte("platform_set: 1.3.0\nplatforms:\n  juniper_junos:\n    carve_outs: {view-configuration: []}\n"+
		scopeOK+"roles:\n  - {name: r, privilege: readonly, permit: [\"show **\"], deny: [\"show security **\"]}\n"+
		subjOK+grantOK), env())
	if err != nil {
		t.Fatal(err)
	}
}
```

Changes to existing tests the set bump breaks (pre-flight M1):
- `TestEmbeddedSetsLoad` asserts `Sets()` is `[1.0.0 1.1.0 1.2.0]`. Add `1.3.0` to that list.
- `TestSet120IsSet110AndTheEntryDeny` asserts `DefaultSet != "1.2.0"`. Drop only that
  `DefaultSet` clause; keep everything it pins about 1.2.0.

In `cmd/port49/platform_test.go`, change `"# cisco_iosxe: built-in, platform set 1.2.0\n"` (:101)
and `"platform set 1.2.0"` / `"1.2.0: code %d"` (:655, :659) to 1.3.0. Then add:

```go
// Moving a pin from 1.2.0 to 1.3.0 reports juniper_junos's deny_reach_bits as
// a gated adapter change, with the acknowledge entry that clears it
// (decision 48 ruling 2).
func TestPlatformUpgradeTo130GatesDenyReachBits(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: jx-01, platform: juniper_junos, addresses: [10.0.0.2]}\n"+
		"key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: k}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("platform_set: 1.2.0\nscopes: [{name: all_devices, match: {}}]\n"+
		"roles: [{name: r, privilege: readonly, permit: [\"show **\"], deny: [\"show security **\"]}]\n"+
		"subjects: [{name: noc, identity: \"user:noc@example.com\", username: noc, token_ttl: 60s}]\n"+
		"grants: [{subject: noc, scope: all_devices, roles: [r]}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"platform", "upgrade", "--policy", pol, "--inventory", inv, "--to", "1.3.0"}, &out,
		&errb); code != 0 || !strings.Contains(out.String(), "platform_set 1.2.0 -> 1.3.0\n") ||
		!strings.Contains(out.String(), "field: deny_reach_bits") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/ ./internal/policy/ ./cmd/port49/ -count=1`
Expected: FAIL to compile: `d.DenyReachBits undefined` (`DenyReachBits` is not a field). The YAML
and tree tests then fail on missing files.

- [ ] **Step 3: Implement**

`internal/platform/dialect.go`, after `RPCEntryDenies` in `Dialect`:

```go
	// DenyReachBits are the bits a reply may send where the grant permits a
	// carve-out of the bit that an allow past the bits is not measured to
	// run, with the rest of the bit's reach the grant decides nothing of
	// denied on the wire (decision 48; tests/lab/results/L68-juniper_*.md).
	// Set 1.3.0's juniper_junos carries view-configuration. Read only where
	// RPCEntryDenies is kept: a wire deny binds no native RPC. A block may
	// drop one and never add one (spec §8).
	DenyReachBits []string
```

After `RPCEntryRole`:

```go
// ReachDenyRole is the role of a deny the projection adds from DenyReachBits:
// a bit's reach the grant decides nothing of, none of the grant's (decision
// 48).
const ReachDenyRole = "reach_deny"
```

In `generics`, after `"1.2.0"`:

```go
	// 1.3.0 changes no generic value: deny_reach_bits is juniper_junos's.
	"1.3.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert, EnableUsername: EnablePrincipal},
```

In `clone`, after `d.RPCEntryDenies = slices.Clone(d.RPCEntryDenies)`: `d.DenyReachBits =
slices.Clone(d.DenyReachBits)`.

`internal/platform/adapter.go`:
- `Spec`: `DenyReachBits *[]string \`yaml:"deny_reach_bits,omitempty"\`` after `RPCEntryDenies`.
- `Over`, after the `RPCEntryDenies` block:

```go
	if s.DenyReachBits != nil {
		d.DenyReachBits = append([]string{}, *s.DenyReachBits...)
	}
```

- `SpecOf`, after `RPCEntryDenies`:

```go
	if d.DenyReachBits != nil {
		s.DenyReachBits = &d.DenyReachBits
	}
```

- `validateProjection`'s unprojected list: add `{"deny_reach_bits", d.DenyReachBits != nil}`.
- After the `RPCEntryDenies` loop:

```go
	for i, bit := range d.DenyReachBits {
		switch {
		case bit == BaselineBit || bit == "all":
			return fmt.Errorf("%s[%d]: %s has no reach a grant decides in part", field("deny_reach_bits"), i, bit)
		case d.Bits[bit] == nil:
			return fmt.Errorf("%s[%d]: %s is not a bit under bits", field("deny_reach_bits"), i, bit)
		}
	}
```

`internal/policy/load.go`:
- In the unprojected-platform key list (:559), add `{"deny_reach_bits", b.Spec.DenyReachBits != nil}`.
- In `keepsProjection`, after the `carve_outs` loop:

```go
	for i, bit := range d.DenyReachBits {
		if !slices.Contains(ref.DenyReachBits, bit) {
			return fmt.Errorf("%s.deny_reach_bits[%d]: platform set %s does not measure %s sent with its other "+
				"reach denied on %s; a block may drop one, not add one (spec §8, §15 L68)", at, i, version, bit,
				shippedAs)
		}
	}
```

`internal/platform/set.go:16`: `const DefaultSet = "1.3.0"`.

The files:

```bash
mkdir -p platforms/1.3.0 platforms/keywords/1.3.0
cp platforms/1.2.0/arista_eos.yaml platforms/1.2.0/cisco_iosxe.yaml platforms/1.2.0/cisco_nxos.yaml \
   platforms/1.2.0/juniper_junos.yaml platforms/1.3.0/
cp platforms/keywords/1.2.0/juniper_junos.yaml platforms/keywords/1.3.0/
```

Then, in `platforms/1.3.0/juniper_junos.yaml`, directly after the line
`    rpc_entry_denies: ["junoscript **", "op **"]`, insert this text, the same bytes as
`denyReachBlock`. Use the Edit tool, not sed.

```yaml
    # Set 1.3.0: the bits a reply may send where the grant permits a carve-out
    # of the bit that an allow past the bits is not measured to run, with the
    # rest of the bit's reach the grant decides nothing of denied on the wire
    # (decision 48). view-configuration is the one: under view alone an allow
    # of show configuration was refused on both images
    # (tests/lab/results/L26c-projected-juniper_*.md), and under view and
    # view-configuration with its other reach denied, show configuration ran
    # and that reach, NETCONF and op url were refused on both images
    # (tests/lab/results/L68-juniper_*.md, L68-netconf-juniper_*.md). Read only
    # where rpc_entry_denies is kept: a wire deny binds no native RPC. A block
    # may drop an entry, never add one.
    deny_reach_bits: [view-configuration]
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/platform/ ./internal/policy/ ./cmd/port49/ -count=1`
Expected: PASS. If another test asserts the default set's text (`platform set 1.2.0`, or
`platform show`/`export` output naming 1.2.0 as the default), change it to 1.3.0. Change only
assertions about the default; keep every test that pins 1.2.0 explicitly. Then:
- run `make test && make vet`;
- prove `TestABlockMayDropDenyReachBitsNotAddOne` by deleting the `keepsProjection` loop, and revert;
- prove `TestABlockDroppingTheCarveOutLoadsOn130` by adding back a "no carve-out" rule to
  `validateProjection`, and revert;
- prove `TestTheSet130FilesAreSet120AndDenyReachBits` by editing one comment byte in
  `platforms/1.3.0/cisco_nxos.yaml`, and revert.

- [ ] **Step 5: Commit**

```bash
git add internal/platform internal/policy/load.go internal/policy/platforms_test.go cmd/port49/platform_test.go \
  platforms/1.3.0 platforms/keywords/1.3.0
git commit -m "feat: platform set 1.3.0 with juniper_junos deny_reach_bits"
```

---

### Task 4: The projection sends the bit with its undecided reach denied (depends on G1)

**Files:**
- Modify: `internal/projection/project.go`:
  - `capability` user_permissions branch :631-641;
  - `configurationBeneath` :840;
  - `attributes`, the deny-commands overflow branch :1248-1255;
  - `shape`, after `res, err = g.finish(res, err)` :395 (the fallback);
  - the `generator` struct :263 (`noReach`), `Refusal` :169 (`reach`), `Result` :115
    (`ReachOverflow`) and `Clone` :194;
  - new `reachDenies`, `insertReachDenies` and `Result.ReachDenies`, after `carvedAllows` :826.
- Modify: `internal/projection/project_test.go` (`TestCloneCopiesEverySlice` :554). This edit is
  required: the test fails with "ReachOverflow: set it in this test" until its fixture sets the new
  field (pre-flight M11).
- Test: create `internal/projection/project_reach_test.go`

**Interfaces:**
- Consumes: `platform.Dialect.DenyReachBits`, `platform.ReachDenyRole`, `platform.Set("1.3.0")`,
  `platform.KeywordsFor("1.3.0", …)` (Task 3).
- Produces:
  - `func (r Result) ReachDenies() []engine.Rule`: the reply's denies with role
    `platform.ReachDenyRole`;
  - `Result.ReachOverflow []engine.Rule`: the reach denies left off because they took
    `deny-commands` past 255 bytes, where the reply fell back (R2). Task 5's warning reads it;
  - `Result.ConfigurationBeneath` never holding one.

- [ ] **Step 1: Write the failing tests**

Create `internal/projection/project_reach_test.go`:

```go
package projection

import (
	"slices"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/platform"
)

func denyCommands(res Result) string {
	for _, a := range res.Attributes {
		if strings.HasPrefix(a, "deny-commands=") {
			return a
		}
	}
	return ""
}

// Set 1.3.0 sends a readonly granted `show **` less `show security **`
// `view view-configuration`, `monitor **` denied (decision 48): byte for byte
// set 1.2.0's reply to the same grant writing `deny: [monitor **]`, which L68
// measured (row P). Its deny-commands is 173 bytes, within RFC 8907 (R2).
func TestTheSet130ReadonlySendsViewConfiguration(t *testing.T) {
	res, err := Project(shipped("1.3.0", "readonly", permit("show **"), deny("show security **")))
	if err != nil || res.Shape != ShapeCapability || !slices.Equal(res.Bits, []string{"view", "view-configuration"}) ||
		!res.EntryDenied() || len(res.Allows) != 0 || len(res.Closed) != 1 {
		t.Fatalf("%s %q allows %v %+v %v", res.Shape, res.Attributes, res.Allows, res.Refusal, err)
	}
	measured, err := Project(shipped("1.2.0", "readonly", permit("show **"), deny("show security **"),
		deny("monitor **")))
	if err != nil || !slices.Equal(res.Attributes, measured.Attributes) {
		t.Fatalf("not L68's reply:\n 1.3.0 %q\n 1.2.0 %q %v", res.Attributes, measured.Attributes, err)
	}
	if n := len(denyCommands(res)); n != 173 || n > engine.MaxAttribute {
		t.Errorf("deny-commands is %d bytes, want 173", n)
	}
	if rd := res.ReachDenies(); len(rd) != 1 || rd[0].Rule != "monitor **" || rd[0].Role != platform.ReachDenyRole {
		t.Errorf("reach denies: %v", rd)
	}
	if len(res.ConfigurationBeneath) != 0 {
		t.Errorf("a reach deny is named beneath view-configuration: %v", res.ConfigurationBeneath)
	}
	for _, c := range []struct {
		v    []string
		runs bool
	}{
		{[]string{"show", "configuration", "system", "host-name"}, true},
		{[]string{"show", "log", "messages"}, true},
		{[]string{"show", "version"}, true},
		{[]string{"show", "security", "zones"}, false},
		{[]string{"monitor", "list"}, false},
		{[]string{"request", "mpls", "lsp"}, false},
		{[]string{"junoscript"}, false},
	} {
		if got := res.Device(c.v); got != c.runs || res.Unmeasured(c.v) {
			t.Errorf("%v: runs %v (unmeasured %v), want %v", c.v, got, res.Unmeasured(c.v), c.runs)
		}
	}
	if n := res.Narrower(3); len(n) != 0 {
		t.Errorf("the device refuses what port49 permits: %v", n)
	}
}

// A policy pinned to 1.2.0 renders as before (Review Focus 1): the readonly
// deny-beneath-show grants keep `view` and their carved allows, the bytes
// TestAReadonlyWithAShowDenyFitsTheBudget measured. Under 1.3.0 a deny of
// `show configuration` renders as 1.2.0 does: the grant denies what only
// view-configuration adds, so it stays out.
func TestSet120RendersAsBefore(t *testing.T) {
	for _, c := range []struct {
		deny  string
		bytes int
	}{{"show configuration **", 170}, {"show security **", 165}} {
		res, err := Project(shipped("1.2.0", "readonly", permit("show **"), deny(c.deny)))
		if err != nil || !slices.Equal(res.Bits, []string{"view"}) || len(denyCommands(res)) != c.bytes ||
			len(res.ReachDenies()) != 0 {
			t.Errorf("1.2.0 %s: %s %q %v", c.deny, res.Shape, res.Attributes, err)
		}
	}
	was, _ := Project(shipped("1.2.0", "readonly", permit("show **"), deny("show configuration **")))
	is, err := Project(shipped("1.3.0", "readonly", permit("show **"), deny("show configuration **")))
	if err != nil || !slices.Equal(is.Attributes, was.Attributes) {
		t.Errorf("1.3.0 show configuration denied:\n %q\n %q %v", is.Attributes, was.Attributes, err)
	}
	was, _ = Project(shipped("1.2.0", "operator", permit("**"), deny("show configuration **")))
	is, err = Project(shipped("1.3.0", "operator", permit("**"), deny("show configuration **")))
	if err != nil || !slices.Equal(is.Attributes, was.Attributes) || len(is.ConfigurationBeneath) != 1 {
		t.Errorf("1.3.0 operator:\n %q\n %q %v", is.Attributes, was.Attributes, err)
	}
}

// Without the entry deny the key is inert (Review Focus 2): view-configuration
// is never sent with wire denies alone guarding an RPC-reachable bit.
func TestReachDeniesNeedTheEntryDeny(t *testing.T) {
	in := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	in.Dialect.RPCEntryDenies = nil
	res, err := Project(in)
	if err != nil || res.Shape != ShapeFailClosed || slices.Contains(res.Bits, "view-configuration") ||
		len(res.ReachDenies()) != 0 {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}

// A permit inside the undecided reach declines the reach deny (Review Focus
// 3): a deny of `monitor **` would sit beneath `monitor interface **`. The
// composition renders as set 1.2.0 renders it.
func TestReachDeniesDeclineAPermittedReach(t *testing.T) {
	rules := []engine.Rule{permit("show **"), permit("monitor interface **"), deny("show security **")}
	is, err := Project(shipped("1.3.0", "readonly", rules...))
	was, err2 := Project(shipped("1.2.0", "readonly", rules...))
	if err != nil || err2 != nil || len(is.ReachDenies()) != 0 || !slices.Equal(is.Attributes, was.Attributes) ||
		is.FailClosed == FailUnsound {
		t.Fatalf("1.3.0 %s %q\n1.2.0 %s %q %v %v", is.Shape, is.Attributes, was.Shape, was.Attributes, err, err2)
	}
}

// A block that adds reach to view-configuration (Review Focus 4): a rule the
// shipped tree proves (`restart`, a root keyword no baseline deny holds) is
// denied too, and the device refuses it; one it does not prove (nothing under
// `clear` is proven) keeps the 1.2.0 render.
func TestAddedReachIsDeniedOrDeclined(t *testing.T) {
	in := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	in.Dialect.Bits["view-configuration"] = append(slices.Clone(in.Dialect.Bits["view-configuration"]), "restart **")
	res, err := Project(in)
	if err != nil || !slices.ContainsFunc(res.ReachDenies(), func(d engine.Rule) bool { return d.Rule == "restart **" }) ||
		res.Device([]string{"restart", "routing"}) || len(denyCommands(res)) > engine.MaxAttribute {
		t.Errorf("proven: %s %q reach %v %v", res.Shape, res.Attributes, res.ReachDenies(), err)
	}
	in = shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	in.Dialect.Bits["view-configuration"] = append(slices.Clone(in.Dialect.Bits["view-configuration"]), "clear zzz **")
	res, err = Project(in)
	off := in
	off.Dialect.DenyReachBits = nil
	was, err2 := Project(off)
	if err != nil || err2 != nil || len(res.ReachDenies()) != 0 || slices.Contains(res.Bits, "view-configuration") ||
		!slices.Equal(res.Attributes, was.Attributes) {
		t.Errorf("unproven: %s %q, without the key %q %v %v", res.Shape, res.Attributes, was.Attributes, err, err2)
	}
}

// Under local_user_name the template's class carries every bit, and the
// branch is unchanged (Review Focus 5).
func TestATemplateDeliveryIsUnchanged(t *testing.T) {
	tmpl := func(version string) Input {
		in := shipped(version, "readonly", permit("show **"), deny("show security **"))
		in.Dialect.BitDelivery = platform.BitDeliveryLocalUserName
		in.Dialect.LocalUserNames = map[string]string{"readonly": "p49-readonly", "operator": "p49-operator",
			"admin": "p49-admin"}
		in.Template = "p49-readonly"
		return in
	}
	is, err := Project(tmpl("1.3.0"))
	was, err2 := Project(tmpl("1.2.0"))
	if err != nil || err2 != nil || !slices.Equal(is.Attributes, was.Attributes) || len(is.ReachDenies()) != 0 {
		t.Fatalf("1.3.0 %q\n1.2.0 %q %v %v", is.Attributes, was.Attributes, err, err2)
	}
}

// view-configuration alone shows no configuration (L12-bits), so a grant of
// `show configuration **` alone, where `view` is not sent, keeps the narrow
// shape and sends no reach deny.
func TestTheBitIsNotSentAloneForItsCarveOut(t *testing.T) {
	res, err := Project(shipped("1.3.0", "readonly", permit("show configuration **")))
	was, _ := Project(shipped("1.2.0", "readonly", permit("show configuration **")))
	if err != nil || len(res.ReachDenies()) != 0 || len(res.ReachOverflow) != 0 ||
		!slices.Equal(res.Attributes, was.Attributes) {
		t.Fatalf("%s %q overflow %v, 1.2.0 %q %v", res.Shape, res.Attributes, res.ReachOverflow, was.Attributes, err)
	}
}

// reachDenies' guards, read directly. An end-to-end test cannot see them, since
// a later stage can mask each one: without the entry deny `capability` goes
// narrow anyway, and a bit sent alone overflows into the fallback (pre-flight
// I1).
func TestReachDeniesGuards(t *testing.T) {
	view := []string{"view"}
	in := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	if rest, ok := newGenerator(in, in.Bits).reachDenies("view-configuration", view); !ok || len(rest) != 1 {
		t.Fatalf("control: the readonly denying show security needs the bit: %v %v", rest, ok)
	}
	noEntry := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	noEntry.Dialect.RPCEntryDenies = nil
	if _, ok := newGenerator(noEntry, noEntry.Bits).reachDenies("view-configuration", view); ok {
		t.Error("sent without the entry deny")
	}
	g := newGenerator(in, in.Bits)
	g.noReach = true
	if _, ok := g.reachDenies("view-configuration", view); ok {
		t.Error("sent under noReach")
	}
	alone := shipped("1.3.0", "readonly", permit("show configuration **"))
	if _, ok := newGenerator(alone, alone.Bits).reachDenies("view-configuration", nil); ok {
		t.Error("sent beside no bit that reaches the carve-out")
	}
	unproven := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	unproven.Dialect.Bits["view-configuration"] = append(slices.Clone(unproven.Dialect.Bits["view-configuration"]),
		"clear zzz **")
	if _, ok := newGenerator(unproven, unproven.Bits).reachDenies("view-configuration", view); ok {
		t.Error("sent with a reach rule the tree does not prove")
	}
}

// The mechanism holds at any level whose ceiling holds view-configuration
// (pre-flight I6). An operator granted `show **` and `clear **` less `show
// security **` gets `clear view view-configuration` and the 173 bytes L68's
// row O measured, where set 1.2.0 sends `clear view` and carved allows.
func TestTheSet130OperatorSendsViewConfiguration(t *testing.T) {
	rules := []engine.Rule{permit("show **"), permit("clear **"), deny("show security **")}
	res, err := Project(shipped("1.3.0", "operator", rules...))
	measured, err2 := Project(shipped("1.2.0", "operator", append(slices.Clone(rules), deny("monitor **"))...))
	if err != nil || err2 != nil || !slices.Equal(res.Bits, []string{"clear", "view", "view-configuration"}) ||
		!slices.Equal(res.Attributes, measured.Attributes) || len(denyCommands(res)) != 173 {
		t.Fatalf("1.3.0 %s %q
 row O %q %v %v", res.Shape, res.Attributes, measured.Attributes, err, err2)
	}
	if was, _ := Project(shipped("1.2.0", "operator", rules...)); !slices.Equal(was.Bits, []string{"clear", "view"}) {
		t.Errorf("1.2.0 operator: %q", was.Attributes)
	}
	for _, c := range []struct {
		v    []string
		runs bool
	}{
		{[]string{"show", "configuration", "system", "host-name"}, true},
		{[]string{"clear", "interfaces", "statistics", "fxp0"}, true},
		{[]string{"show", "security", "zones"}, false},
		{[]string{"monitor", "list"}, false},
	} {
		if got := res.Device(c.v); got != c.runs {
			t.Errorf("%v: runs %v, want %v", c.v, got, c.runs)
		}
	}
}

// R2 (controller's ruling, 2026-10-16): where the reach denies would take
// deny-commands past 255 bytes, the reply falls back to set 1.2.0's. That
// means no view-configuration, the carved allows, and the device refusing
// `show configuration`, here byte for byte the 249-byte reply 1.2.0 sends.
// ReachOverflow names the denies left off, for the warning. `monitor` alone
// takes 1.3.0's past 255.
func TestAReachDenyPastTheBudgetFallsBackToTheCarvedReply(t *testing.T) {
	rules := []engine.Rule{permit("show **"), deny("show security **"), deny("show route **"), deny("show bgp **"),
		deny("show ospf **")}
	was, err := Project(shipped("1.2.0", "readonly", rules...))
	if err != nil || was.Shape != ShapeCapability || len(denyCommands(was)) != 249 {
		t.Fatalf("1.2.0: %s %q %v", was.Shape, was.Attributes, err)
	}
	res, err := Project(shipped("1.3.0", "readonly", rules...))
	if err != nil || res.Shape != ShapeCapability || res.FailClosed != "" || !slices.Equal(res.Attributes, was.Attributes) ||
		slices.Contains(res.Bits, "view-configuration") || len(res.ReachDenies()) != 0 {
		t.Fatalf("not 1.2.0's reply: %s %q %+v %v\n 1.2.0 %q", res.Shape, res.Attributes, res.Refusal, err, was.Attributes)
	}
	if len(res.ReachOverflow) != 1 || res.ReachOverflow[0].Rule != "monitor **" {
		t.Errorf("reach overflow: %v", res.ReachOverflow)
	}
	if res.Device([]string{"show", "configuration", "system", "host-name"}) || !res.Device([]string{"show", "version"}) {
		t.Error("the fallback is not 1.2.0's measured reading")
	}
	// A reply that fits records no overflow.
	if fits, _ := Project(shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))); len(fits.ReachOverflow) != 0 {
		t.Errorf("a fitting reply records an overflow: %v", fits.ReachOverflow)
	}
}

// configurationBeneath never names a reach deny, even one that meets `show
// configuration` (decision 48 ruling 5).
func TestConfigurationBeneathSkipsAReachDeny(t *testing.T) {
	g := newGenerator(shipped("1.3.0", "readonly", permit("show **")), []string{"view", "view-configuration"})
	res := Result{Bits: []string{"view", "view-configuration"},
		Denies: []engine.Rule{{Verdict: engine.Deny, Rule: "show configuration **", Role: platform.ReachDenyRole}}}
	if got := g.configurationBeneath(res); len(got) != 0 {
		t.Errorf("%v", got)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/projection/ -run 'Set130|Set120RendersAsBefore|ReachDen|AddedReach|TemplateDelivery|NotSentAlone|PastTheBudget|ConfigurationBeneathSkips' -count=1`
Expected: FAIL to compile: `res.ReachDenies undefined`.

- [ ] **Step 3: Implement**

In `internal/projection/project.go`, replace the `else` branch of `capability`'s bit choice
(:631-641) with:

```go
	} else {
		for _, b := range g.ceiling {
			if g.usable(b) && !g.aligned(b) {
				bits = append(bits, b)
			}
		}
		// A bit the grant decides only in part goes out where the grant needs
		// what only it shows, the rest of its reach denied (reachDenies;
		// decision 48). The denies follow the grant's own and precede the
		// baseline's, so the reply is the one L68 measured, byte for byte.
		for _, b := range g.ceiling {
			if slices.Contains(bits, b) {
				continue
			}
			if rest, ok := g.reachDenies(b, bits); ok {
				bits = append(bits, b)
				g.denies = insertReachDenies(g.denies, rest)
			}
		}
		slices.SortStableFunc(bits, func(x, y string) int {
			return slices.Index(g.ceiling, x) - slices.Index(g.ceiling, y)
		})
		// `all` holds every bit, so it is sent alone: the smallest set.
		if slices.Contains(bits, "all") {
			bits = []string{"all"}
		}
	}
```

`g` is `capability`'s own copy (a value receiver), so the reach denies reach the rest of
`capability` (`allowable`, `omittable`, the deny loop, `beneath`) and nothing outside it. Every
later reader takes them from `res.Denies`.

After `carvedAllows` (:826), add:

```go
// reachDenies is bit b's reach the grant decides nothing of, as denies, where
// the reply may send b with that reach denied (decision 48). That is where b
// is in the adapter's DenyReachBits and the dialect closes the entry points;
// the grant permits a carve-out of b that no deny holds and that an allow
// past the bits is not measured to run (Facts.AllowPastCarve), `show
// configuration`; the bits already chosen reach that carve-out, since
// view-configuration alone shows no configuration
// (tests/lab/results/L12-bits-juniper_*.md); and no permit meets a rule it
// denies, each of which the keyword tree proves. ok is false otherwise, and
// the reply is what set 1.2.0 renders.
func (g generator) reachDenies(b string, bits []string) ([]engine.Rule, bool) {
	if g.noReach || !g.closesEntries() || !slices.Contains(g.in.Dialect.DenyReachBits, b) {
		return nil, false
	}
	reached := g.reach(g.held(bits))
	needed := false
	for _, c := range g.in.Dialect.CarveOuts[b] {
		if g.in.Facts.AllowPastCarve[c] ||
			slices.ContainsFunc(g.denies, func(d engine.Rule) bool { return g.contains(d.Rule, c) }) ||
			!slices.ContainsFunc(g.permits, func(p engine.Rule) bool { return g.mayMeet(p.Rule, c) }) {
			continue
		}
		if !slices.ContainsFunc(reached, func(r string) bool { return g.contains(r, c) }) {
			return nil, false
		}
		needed = true
	}
	if !needed {
		return nil, false
	}
	var out []engine.Rule
	for _, r := range g.in.Dialect.Bits[b] {
		if g.covered(r) {
			continue
		}
		if slices.ContainsFunc(g.permits, func(p engine.Rule) bool { return g.mayMeet(p.Rule, r) }) ||
			!g.denyProvable(r) {
			return nil, false
		}
		out = append(out, engine.Rule{Verdict: engine.Deny, Rule: r, Role: platform.ReachDenyRole})
	}
	return out, true
}

// insertReachDenies is denies with rest after the grant's own denies, before
// the first baseline deny (newGenerator appends those last), in a new slice.
func insertReachDenies(denies, rest []engine.Rule) []engine.Rule {
	i := slices.IndexFunc(denies, func(d engine.Rule) bool { return d.Role == platform.BaselineBit })
	if i < 0 {
		i = len(denies)
	}
	return slices.Concat(denies[:i], rest, denies[i:])
}

// ReachDenies are the reply's denies of a bit's reach the grant decides
// nothing of, sent so the bit can go out (decision 48).
func (r Result) ReachDenies() []engine.Rule {
	var out []engine.Rule
	for _, d := range r.Denies {
		if d.Role == platform.ReachDenyRole {
			out = append(out, d)
		}
	}
	return out
}
```

In `configurationBeneath` (:840), extend the role check:

```go
		if dn.Role != platform.BaselineBit && dn.Role != platform.RPCEntryRole && dn.Role != platform.ReachDenyRole &&
			g.mayMeet(configurationRead, dn.Rule) {
```

**The fallback (R2).** Add to `generator` (:263):

```go
	// noReach turns reachDenies off: the reply as the set renders it without
	// DenyReachBits, the fallback where the reach denies overflow (decision 48
	// ruling 4).
	noReach bool
```

To `Refusal` (:169), after `Attribute, Value, Class string`:

```go
	// reach are the reach denies an overflowing deny-commands carried: where
	// set, shape falls back to the reply without them.
	reach []engine.Rule
```

To `Result` (:115), after `Closed`:

```go
	// ReachOverflow are the reach denies left off because they took
	// deny-commands past RFC 8907's 255 bytes: the reply fell back to the one
	// without them, the bit unsent and its carve-out refused on the device,
	// and policy test warns (projection_reach_deny_overflow; decision 48
	// ruling 4).
	ReachOverflow []engine.Rule
```

In `Clone`, after `r.Closed = slices.Clone(r.Closed)`: `r.ReachOverflow =
slices.Clone(r.ReachOverflow)`.

In `attributes`, in the `if r.Attribute == "deny-commands" {` branch, before
`r.Class = res.Template`: `r.reach = res.ReachDenies()`.

In `shape`, directly after `res, err = g.finish(res, err)` (:395) and before the narrow
preference:

```go
	// Where the reach denies take deny-commands past RFC 8907's length, the
	// reply is the one without them, as the set renders it without
	// DenyReachBits: the bit unsent, and the device refusing the carve-out it
	// would have shown, which is narrower than port49 and measured (decision
	// 48 ruling 4). Where that reply does not carry the grant either, the
	// overflow stands and the composition fails closed.
	// It runs once: the fallback's own generator has noReach set, so a
	// fallback that overflowed again could not recurse (pre-flight I1).
	// ReachOverflow is set only where the fallback kept the capability
	// shape: a narrow fallback means the grant's own denies overflow too, and
	// the warning would blame the wrong denies (pre-flight M4).
	var over *Refusal
	if !g.noReach && errors.As(err, &over) && over.Category == FailOverflow && len(over.reach) > 0 {
		h := g
		h.noReach = true
		if fb, ferr := h.shape(); ferr == nil {
			if fb.Shape == ShapeCapability {
				fb.ReachOverflow = over.reach
			}
			return fb, nil
		}
	}
```

Update the `Result.ConfigurationBeneath` field comment (:148-151). After
"(projection_deny_beneath_view_configuration; decision 44)", add "; never a reach deny (decision
48)".

- [ ] **Step 3b: Only if L68 read `G1-operator: STOP` on either image.** The operator class keeps
  today's reply (controller's ruling on pre-flight I6). In `reachDenies`, after the
  `closesEntries` check, add:

```go
	// L68's operator row stopped (plan 9g G1-operator): the bit goes out only
	// beside `view` alone, the reply L68 measured safe.
	if !slices.Equal(bits, []string{"view"}) {
		return nil, false
	}
```

  Then replace `TestTheSet130OperatorSendsViewConfiguration` with:

```go
// L68's operator row stopped (G1-operator): an operator keeps set 1.2.0's
// reply under 1.3.0, byte for byte, and no reach deny.
func TestTheSet130OperatorKeepsTheSet120Reply(t *testing.T) {
	rules := []engine.Rule{permit("show **"), permit("clear **"), deny("show security **")}
	is, err := Project(shipped("1.3.0", "operator", rules...))
	was, err2 := Project(shipped("1.2.0", "operator", rules...))
	if err != nil || err2 != nil || !slices.Equal(is.Attributes, was.Attributes) || len(is.ReachDenies()) != 0 {
		t.Fatalf("1.3.0 %q\n1.2.0 %q %v %v", is.Attributes, was.Attributes, err, err2)
	}
}
```

  In the mutation table, the operator row's test becomes this one, and its mutation is "drop
  the `view`-alone check". If G1-operator passed, skip this step.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/projection/ -count=1 -timeout 120s && make test && make vet`
Expected: PASS. `TestAReadonlyWithAShowDenyFitsTheBudget`, `TestTheShippedSetsEntryDeny` and
`TestACarvedPermitTheSentBitsDoNotReachIsRefused` pass unchanged. `TestCloneCopiesEverySlice`
passes once its fixture sets `ReachOverflow` (Files).
Prove each new test with a mutation, and revert each:

| Mutation | Test that must go red |
|---|---|
| `insertReachDenies` appends at the end instead | the byte-for-byte check in `TestTheSet130ReadonlySendsViewConfiguration` |
| drop the `closesEntries()` check | `TestReachDeniesGuards` |
| drop the permit-meets check | `TestReachDeniesDeclineAPermittedReach` |
| drop the `reached` check | `TestReachDeniesGuards`, and `TestTheBitIsNotSentAloneForItsCarveOut` (its `ReachOverflow`) |
| drop `!g.denyProvable(r)` | `TestReachDeniesGuards`, and `TestAddedReachIsDeniedOrDeclined` (unproven, byte for byte) |
| drop the fallback in `shape` | `TestAReachDenyPastTheBudgetFallsBackToTheCarvedReply` |
| `reachDenies` ignores `noReach` | `TestReachDeniesGuards`, at once, and `TestAReachDenyPastTheBudgetFallsBackToTheCarvedReply` in well under a second: the `!g.noReach` guard in `shape` stops the fallback recursing, so the overflow stands and the composition fails closed |
| the recursion guard: `reachDenies` ignores `noReach` **and** `shape` drops `!g.noReach` | the guard's own test. Run this double mutation with `go test ./internal/projection/ -run PastTheBudget -timeout 60s`: it must hit the timeout or a stack overflow. Restore only the guard: the same run must fail in under a second. That pair shows the guard is what bounds the recursion |
| the operator ceiling excluded from `reachDenies` | `TestTheSet130OperatorSendsViewConfiguration` |
| drop the `ReachDenyRole` check in `configurationBeneath` | `TestConfigurationBeneathSkipsAReachDeny` |

- [ ] **Step 5: Commit**

```bash
git add internal/projection/project.go internal/projection/project_reach_test.go internal/projection/project_test.go
git commit -m "feat: set 1.3.0 sends view-configuration with its undecided reach denied"
```

---

### Task 5: `policy test`, `explain` and the warnings follow (depends on G1)

**Files:**
- Modify: `internal/policy/lint.go`:
  - `projectionMessage` :964-990;
  - the `FindingProjectionDenyBeneathViewConfiguration` comment :674-677;
  - a new `FindingProjectionReachDenyOverflow` beside it, and in `projectionNote` :682-685;
  - its emission in `Projections` beside the view-configuration warning :745-748;
  - a new `reachOverflowMessage` after `configurationBeneathMessage`.
- Modify: `internal/policy/diff.go:456` (the warning kinds `policy diff` prints)
- Test: `internal/policy/projection_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `projection.Result.ReachDenies()` and `Result.ReachOverflow` (Task 4);
  `platform_set: 1.3.0` (Task 3); the warning name `projection_reach_deny_overflow`, which spec
  §12 already carries (Task 2).
- Produces:
  - the projection finding's clause `; of those, the reach of a bit the grant decides only in
    part, denied so the bit can be sent (deny_reach_bits; decision 48): <rules>`;
  - the warning `FindingProjectionReachDenyOverflow = "projection_reach_deny_overflow"`.

- [ ] **Step 1: Write the failing tests**

In `internal/policy/projection_test.go`, after
`TestThePredictionFollowsTheMeasuredAllowsPastTheBits`. That test stays as it is: it is set
1.2.0's.

```go
// Under set 1.3.0 the readonly denying `show security` is sent
// view-configuration (decision 48): explain says the device runs `show
// configuration` and refuses `monitor`; the projection finding names the
// reach deny and no shortfall; the view-configuration warning does not fire,
// and the netconf-closed one does.
func TestSet130PredictsTheConfigurationRuns(t *testing.T) {
	p := mustParse(t, "platform_set: 1.3.0\n"+scopeOK+`roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show security **"]}
`+subjOK+grantOK)
	caveats := func(cmd string) string {
		e, err := p.Explain("s", "", "srx-fw-04", cmd, noon)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(e.Caveats, "\n")
	}
	if c := caveats("show configuration system host-name"); !strings.Contains(c, "the device runs it;") ||
		strings.Contains(c, "does not carry it") || strings.Contains(c, "may refuse") {
		t.Errorf("show configuration: %q", c)
	}
	if c := caveats("monitor interface fxp0"); !strings.Contains(c, "the device refuses it;") {
		t.Errorf("monitor: %q", c)
	}
	kinds := map[string][]string{}
	for _, f := range p.Projections(noon) {
		kinds[f.Kind] = append(kinds[f.Kind], f.Message)
	}
	msg := strings.Join(kinds[FindingProjection], "\n")
	if !strings.Contains(msg, "capability shape, bits view view-configuration") ||
		!strings.Contains(msg, "(deny_reach_bits; decision 48): monitor **") ||
		strings.Contains(msg, "probe commands") {
		t.Errorf("projection finding: %q", msg)
	}
	if len(kinds[FindingProjectionDenyBeneathViewConfiguration]) != 0 || len(kinds[FindingProjectionNetconfClosed]) != 1 {
		t.Errorf("warnings: %v", kinds)
	}
	if ProjectionRefusals(p.Projections(noon)) != 0 {
		t.Error("the composition is refused")
	}
}

// Past 255 bytes the reach denies are left off under 1.3.0 and the reply falls
// back to 1.2.0's (R2, controller's ruling): nothing is refused, policy test
// warns projection_reach_deny_overflow naming the deny and the remedy, explain
// says the device refuses `show configuration`, and policy diff prints the
// warning the change brings.
func TestSet130OverflowWarnsAndFallsBack(t *testing.T) {
	role := `roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show security **", "show route **", "show bgp **", "show ospf **"]}
`
	was := mustParse(t, "platform_set: 1.2.0\n"+scopeOK+role+subjOK+grantOK)
	p := mustParse(t, "platform_set: 1.3.0\n"+scopeOK+role+subjOK+grantOK)
	fs := p.Projections(noon)
	var warn []string
	for _, f := range fs {
		if f.Kind == FindingProjectionReachDenyOverflow {
			warn = append(warn, f.Message)
		}
	}
	if ProjectionRefusals(fs) != 0 || len(warn) != 1 || !strings.Contains(warn[0], "monitor **") ||
		!strings.Contains(warn[0], "255") || !strings.Contains(warn[0], "port49 platform export --classes") {
		t.Errorf("refusals %d, warning %q", ProjectionRefusals(fs), warn)
	}
	e, err := p.Explain("s", "", "srx-fw-04", "show configuration system host-name", noon)
	if err != nil || !strings.Contains(strings.Join(e.Caveats, "\n"), "the device refuses it;") {
		t.Errorf("explain: %+v %v", e.Caveats, err)
	}
	for _, f := range was.Projections(noon) {
		if f.Kind == FindingProjectionReachDenyOverflow {
			t.Errorf("1.2.0 warns: %q", f.Message)
		}
	}
	if d := Compare(was, p, noon); !slices.ContainsFunc(d.ProjectionWarnings, func(f Finding) bool {
		return f.Kind == FindingProjectionReachDenyOverflow
	}) {
		t.Errorf("policy diff does not print the warning: %+v", d.ProjectionWarnings)
	}
}
```

In `cmd/port49/policy_test.go`, next to `TestPolicyDiffPrintsAProjectionWarningAndExitsZero`:

```go
// `port49 policy test` on a 1.3.0 readonly denying `show security` reports
// the capability reply with both bits and the reach deny, and passes.
func TestPolicyTestReportsTheSet130Reply(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: jx-01, platform: juniper_junos, addresses: [10.0.0.2]}\n"+
		"key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: k}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("platform_set: 1.3.0\nscopes: [{name: all_devices, match: {}}]\n"+
		"roles: [{name: r, privilege: readonly, permit: [\"show **\"], deny: [\"show security **\"]}]\n"+
		"subjects: [{name: noc, identity: \"user:noc@example.com\", username: noc, token_ttl: 60s}]\n"+
		"grants: [{subject: noc, scope: all_devices, roles: [r]}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "capability shape, bits view view-configuration") ||
		!strings.Contains(out.String(), "monitor **") ||
		strings.Contains(out.String(), "projection_deny_beneath_view_configuration") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./cmd/port49/ -run 'Set130|PolicyTestReportsTheSet130Reply' -count=1`
Expected: FAIL. The finding has no `(deny_reach_bits; decision 48)` clause.

- [ ] **Step 3: Implement**

In `internal/policy/lint.go` `projectionMessage`, after the `if len(pr.Denies) > 0 { … }` block:

```go
	if rd := pr.ReachDenies(); len(rd) > 0 {
		msg += "; of those, the reach of a bit the grant decides only in part, denied so the bit can be sent " +
			"(deny_reach_bits; decision 48): " + rules(rd)
	}
```

Extend `FindingProjectionDenyBeneathViewConfiguration`'s comment. After "(decision 44 ruling
4)", add: "; never a reach deny, which a reply sent under decision 48 carries".

After `FindingProjectionDenyBeneathViewConfiguration`, add:

```go
// FindingProjectionReachDenyOverflow is a composition whose reply would send
// a bit with its undecided reach denied (decision 48), except that those
// denies take deny-commands past RFC 8907's 255 bytes: the reply falls back to
// the one without them, the bit unsent and its carve-out refused on the
// device (spec §12; decision 48 ruling 4). A warning.
const FindingProjectionReachDenyOverflow = "projection_reach_deny_overflow"
```

Add `|| kind == FindingProjectionReachDenyOverflow` to `projectionNote`. In `Projections`, after
the `len(pr.ConfigurationBeneath) > 0` block:

```go
				if len(pr.ReachOverflow) > 0 {
					reports[i] = append(reports[i], item{FindingProjectionReachDenyOverflow,
						reachOverflowMessage(*pr, patterns, secrets)})
				}
```

After `configurationBeneathMessage`:

```go
// reachOverflowMessage is a projection_reach_deny_overflow warning after its
// subject and platform, each rule redacted and quoted as
// configurationBeneathMessage quotes its own: a block may add reach rules.
func reachOverflowMessage(pr projection.Result, patterns []platform.Redaction, secrets []string) string {
	var rules []string
	for _, r := range pr.ReachOverflow {
		rules = append(rules, r.Rule)
	}
	var quoted []string
	for _, r := range redacted(patterns, rules) {
		quoted = append(quoted, platform.QuoteShown(secrets, r))
	}
	return " the denies " + strings.Join(quoted, ", ") + ", which would let the reply send " +
		"the bit whose carve-out the grant permits (deny_reach_bits), take deny-commands past RFC 8907's 255 " +
		"bytes, so the reply does not send that bit and the device refuses what only it shows (show " +
		"configuration): deny fewer commands beneath show, or move the denies into the template's class on the " +
		"device, where they bind every subject at that template (port49 platform export --classes) (spec §8; decision 48 ruling 4)"
}
```

In `internal/policy/diff.go:456`, add `|| k == FindingProjectionReachDenyOverflow` to the
warning kinds, so `policy diff` prints the ones a change brings.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1 && make test && make vet`
Expected: PASS, with `TestThePredictionFollowsTheMeasuredAllowsPastTheBits` (set 1.2.0) and
`TestTheEntryDenyWarnings` unchanged. Prove each by a mutation, and revert:
- delete the reach clause in `projectionMessage`;
- delete the `ReachOverflow` emission;
- delete the `diff.go` kind.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/lint.go internal/policy/diff.go internal/policy/projection_test.go cmd/port49/policy_test.go
git commit -m "feat: policy test names set 1.3.0's reach denies and predicts the configuration runs"
```

---

### Task 6: Lab, set 1.3.0's reply through the broker (depends on G1, Tasks 3 to 5)

**Files:**
- Modify: `tests/lab/projection_test.go`:
  - `projectionSet`'s `capName` map, set switch and claim (:257-264, :324-332);
  - `projectionShape`: the lab guard at its top, a `probes` parameter, and the 1.3.0 STOP case in
    its probe switch (:425-463);
  - after `projectionShapes120` (:233), add `projectionShapes130` and `projectionProbes130`;
  - the default of `PORT49_LAB_PROJECTION_SETS` stays `1.1.0,1.2.0`.
- Modify: `tests/lab/junos_viewcfg_unit_test.go` (one test)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (the L68 row)
- Create (by the run): `tests/lab/results/L68-projected-juniper_vjunos-router.md`,
  `L68-projected-juniper_vsrx.md`; `tests/lab/evidence/L68-projected-*.pcap`

**Interfaces:**
- Consumes: set 1.3.0 (Task 3) and its render (Task 4); `l68Projected`, `l68Shipped` and
  `l68Rule` (Task 1).

- [ ] **Step 1: Write the failing unit test**

In `tests/lab/junos_viewcfg_unit_test.go`:

```go
// What set 1.3.0 sends a readonly granted `show **` less `show security **`
// is row P, byte for byte, and what it sends the operator also granted
// `clear **` is row O: the replies L68 measured. If G1-operator stopped (Task
// 4 Step 3b), drop the operator case: it then renders set 1.2.0's reply.
func TestL68ProjectedIsSet130sRender(t *testing.T) {
	for _, c := range []struct {
		level, bits string
		extra       []engine.Rule
	}{
		{"readonly", "user-permissions=view view-configuration", nil},
		{"operator", "user-permissions=clear view view-configuration", []engine.Rule{l68Rule(engine.Permit, "clear **")}},
	} {
		rules := append([]engine.Rule{l68Rule(engine.Permit, "show **"), l68Rule(engine.Deny, "show security **")},
			c.extra...)
		res, err := l68Shipped("1.3.0", c.level, rules...)
		if err != nil || !slices.Equal(res.Attributes, []string{c.bits, l68Projected}) {
			t.Fatalf("%s: %s %q %+v %v", c.level, res.Shape, res.Attributes, res.Refusal, err)
		}
	}
}
```

Run: `go test -tags lab ./tests/lab/ -run '^TestL68ProjectedIsSet130sRender$' -count=1`. Expected:
PASS, since Tasks 3 and 4 are in. To see it red, change one byte of `l68Projected` and check it
fails, then revert.

- [ ] **Step 2: Add the 1.3.0 rows, the guard and the STOP**

In `tests/lab/projection_test.go`, after `projectionShapes120`:

```go
// projectionShapes130 are set 1.3.0's (plan 9g; L68). The readonly denying
// `show security` now gets `view view-configuration` with `monitor **`
// denied, and its `show configuration` must run; so must the operator's, at
// `clear view view-configuration` (pre-flight I6). The readonly denying `show
// configuration` keeps 1.2.0's reply; the operator control keeps NETCONF.
var projectionShapes130 = []struct{ name, roles, want string }{
	{"readonly denying show security", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show security **"]}`, projection.ShapeCapability},
	{"operator denying show security", `  - {name: r, privilege: operator, permit: ["show **", "clear **"], deny: ["show security **"]}`, projection.ShapeCapability},
	{"readonly denying show configuration", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"operator, all it reaches", `  - {name: r, privilege: operator, permit: ["**"]}`, projection.ShapeCapability},
	{"readonly", `  - {name: r, privilege: readonly, permit: ["show **"]}`, projection.ShapeNarrow},
}

// projectionProbes130 are typed in set 1.3.0's rows besides projectionProbes:
// view-configuration's other reach as commands that run in the control
// ("operator, all it reaches"), so a reply that let one through is seen. The
// `request` words, which run in no row, are Task 1's (L68), with their
// isolation.
var projectionProbes130 = []projectionProbe{
	{junosProbe{cmd: "monitor list"}, "monitor list"},
	{junosProbe{cmd: "mon list"}, "monitor list"},
	{junosProbe{cmd: "monitor list | no-more"}, "monitor list"},
}

// viewConfigurationRows130 are the set 1.3.0 rows sent view-configuration for
// `show configuration`: the device refusing it there is a STOP, since that
// delivery is plan 9g's point (pre-flight I2).
var viewConfigurationRows130 = []string{"readonly denying show security", "operator denying show security"}
```

If G1-operator stopped (Task 4 Step 3b), the operator row renders set 1.2.0's reply. Keep the
row, take it out of `viewConfigurationRows130`, and say in its comment that it measures the
operator keeping that reply.

Add `slices` to `projection_test.go`'s imports (it has none today).

In `projectionSet`:
- Extend `capName` with `"1.3.0": "L68-projected"`.
- Add `if v == "1.3.0" { shapes, entry = projectionShapes130, "L68-projected" }`.
- Give `projectionShape` a `probes []projectionProbe` parameter, and use it in place of
  `projectionProbes` in its loop. Pass `projectionProbes` for 1.1.0 and 1.2.0, so those runs are
  unchanged, and `slices.Concat(projectionProbes, projectionProbes130)` for 1.3.0.
- Where `opControlMissing` names set `"1.2.0"`, make it hold for `"1.3.0"` too: the control row
  is the same.
- After the `if v == "1.2.0" { claim = … }` block, add (pre-flight M5):

```go
	if v == "1.3.0" {
		claim = "Set 1.3.0's projection end to end (plan 9g Task 6; L68): for each shape, the reply port49 " +
			"renders, the readonly and the operator denying `show security` sent view-configuration with " +
			"`monitor **` denied (decision 48), what the CLI runs and refuses, `show configuration` running " +
			"where it is sent, and the XML entries and NETCONF under port49's rendered reply (spec §15 L68)."
	}
```

At the top of `projectionShape`, before anything else (pre-flight I7):

```go
	// The lab's rules before each row: the STOP sentinel and the disk floor.
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("%v", err)
	}
```

In `projectionShape`'s first probe `switch` (the one beginning `case keepsDeny && configEntry(p.cmd) && ran:`),
add a case before `case ran && !o.Permit:` (pre-flight I2):

```go
		case set == "1.3.0" && slices.Contains(viewConfigurationRows130, name) && p.evidence == hostEvidence &&
			!upperCaseTyped(p.cmd) && predicts && o.Permit && !ran:
			t.Errorf("STOP: %s: the device refused %q under set 1.3.0's reply, which sends view-configuration "+
				"so that it runs: the reply does not deliver what plan 9g ships; report to the controller", name, p.cmd)
```

Run: `go vet -tags lab ./tests/lab/ && make lab-unit`. Expected: PASS.

- [ ] **Step 3: Commit the harness**

```bash
git add tests/lab/projection_test.go tests/lab/junos_viewcfg_unit_test.go
git commit -m "test: the projection differential runs set 1.3.0's rows (L68)"
```

- [ ] **Step 4: Run under the lab rules**

The rules are Task 1 Step 7's, with the run worktree `l68p-run` at this commit:
- the single-occupancy, sentinel and floor checks;
- the detached worktree, and `make build` there;
- the run loop detached with its pid recorded;
- the watchdog on that pid.

The loop:

```bash
cd $HOME/git/port49/.worktrees/l68p-run
nohup bash -c 'for p in vjunos vsrx; do
  PORT49_LAB_PROJECTION_SETS=1.3.0 PORT49_LAB_PLATFORMS=$p go test -tags lab ./tests/lab/ \
    -run "^TestProjectionDifferential\$" -count=1 -v -timeout 120m || exit 1
done; make evidence' > /tmp/l68p-run.log 2>&1 &
echo $! > /tmp/l68p-loop.pid
```

Arm the watchdog on `/tmp/l68p-loop.pid`, `l68p-run`'s captures and `/tmp/l68p-run.log`, as in
Task 1 Step 7. Then wait in the foreground with a deadline.

Expected: PASS on both images, and two `L68-projected` notes.
- In the two rows sent view-configuration, `show configuration system host-name` ran (the STOP
  case above gates it), and the `monitor` probes were refused.
- A device running what port49 denies fails the run, and so does that STOP. Either is a STOP:
  report it to the controller, and do not merge.

Then copy the outputs out as in Task 1 Step 8, using `L68-projected-*`, and remove the worktree.

- [ ] **Step 5: Extend the L68 row and commit**

Add `L68-projected-juniper_vjunos-router.md`, `L68-projected-juniper_vsrx.md` to the closed row's
note list. Add one sentence: "Set 1.3.0's rendered replies, through the broker, ran `show
configuration` and refused `monitor` on both images, for the readonly and the operator." If
G1-operator stopped, the sentence names the readonly alone. Then:

```bash
git add tests/lab/results/L68-projected-*.md tests/lab/evidence/L68-projected-*.pcap docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: L68 measures set 1.3.0's reply through the broker"
```

---

### Task 7: Roadmap, as built (depends on Tasks 1 to 6)

**Files:**
- Modify: `docs/superpowers/plans/README.md`:
  - the 9g status line written with this plan;
  - "Ruled 2026-10-15 (Ryan)" and "Former open question" (:5716-5726);
  - a new "Plan 9g — As built" section after 9f's.

- [ ] **Step 1: Update the status line** to `**9g executed <date>** on
  `feature/junos-view-configuration`, each task reviewed (Plan 9g — As built, below); L68
  closed.`

- [ ] **Step 2: Under "Ruled 2026-10-15 (Ryan)"**:
  - Add: "Built as set 1.3.0 by plan 9g (decision 48; the controller's R3 ruling): set 1.2.0 is
    released."
  - Change "Former open question" so it says the question is closed under 1.3.0 and stays as
    measured under 1.2.0.

- [ ] **Step 3: Write "Plan 9g — As built"** in the form 9f's uses. Include:
  - the task commits;
  - L68's gate readings per image, G1 and G1-operator, and any word that "runs nowhere";
  - the 173-byte replies, readonly and operator (or the operator keeping 1.2.0's, if G1-operator stopped);
  - the `| save`, pager and `/config` readings, which stay L59's;
  - "Carried" items:
    - L59 unchanged;
    - hidden commands unmeasured;
    - R2's fallback past 255 bytes (the 1.2.0-style reply and `projection_reach_deny_overflow`), as ruled;
    - bit sets other than the two L68 measured, covered by the model only.
  - The "Operator notes (plan 13)" below, as built, so plan 13's docs pick them up.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: roadmap records plan 9g as built"
```

---

## Operator notes (plan 13)

These go in the pull request body, and the roadmap carries them to plan 13's docs. Rewrite each
as built: if G1-operator stopped, every "and operator" below becomes "readonly only".

- **What changes for a readonly (and an operator) under set 1.3.0.** Take a Junos grant that
  permits `show **` but denies something beneath it other than the configuration, such as
  `show security **`.
  - Under set 1.2.0 it could not read the configuration: the device refused `show configuration`,
    and `policy test` listed that refusal.
  - Under 1.3.0 the reply sends `view-configuration` too, and denies the rest of that bit's reach
    the grant does not grant (`monitor`, for a readonly). So `show configuration` runs.
  - Secrets stay hidden as they are for any session without the `secret` bit.
  - `monitor` stays refused. NETCONF stays closed for that subject, as it already was under 1.2.0
    (`projection_netconf_closed`).
  - Nothing changes for a grant that denies `show configuration **`, or for one with no deny
    beneath `show`.
  - A grant of `show **` less exactly `show configuration` (no `**`) does change: under 1.2.0 it
    failed closed; under 1.3.0 it gets `view view-configuration` with `deny show configuration`
    and `deny monitor **`. `policy diff` shows it as a RAISE.
- **Getting it: `port49 platform upgrade --to 1.3.0`.** A policy pinned to 1.2.0 renders exactly
  as before on the new binary; the change arrives only with the pin.
  - The upgrade report lists `platforms.juniper_junos.deny_reach_bits` as a gated change, with the
    `acknowledge:` entry to paste.
  - `port49 policy diff` on the move shows each reply that gains `view-configuration`.
  - To stay on 1.2.0's behaviour while taking the rest of 1.3.0, write
    `platforms: {juniper_junos: {deny_reach_bits: []}}`.
- **`projection_reach_deny_overflow`, at 3am.** It is a warning, not a failure. It means:
  - this subject's reply would have carried `view-configuration`, but the extra denies it needs
    would push `deny-commands` past RFC 8907's 255 bytes, which locks a Junos user out;
  - so port49 sent the 1.2.0-style reply instead: the session works, and `show configuration` is
    refused on the device.

  Nothing is broken and nobody is locked out. There are two remedies:
  - deny fewer commands beneath `show` in that subject's roles;
  - move the denies into the template's class on the device (`port49 platform export --classes`),
    where the 255-byte limit does not apply but they bind every subject at that template: every
    remote user on that device loses those commands, so move only denies all of them should have.
