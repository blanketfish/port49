# Junos view-configuration under a deny beneath show: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **For the controller, before anything runs: this plan ships the change as set 1.3.0, not
> 1.2.0 (R3, below).** Ryan's ruling of 2026-10-15 says "under set 1.2.0". But set 1.2.0 is
> released: it is in `released` (`internal/platform/adapter_test.go:197`), its YAML is frozen
> value for value, and the spec says a binary upgrade must not change what a pinned policy
> renders (§8 "the platform set is pinned"; `platforms/platforms.go:7`). Today a 1.2.0 readonly
> granted `show **` less `show security **` renders `view` and four carved allows, and two shipped
> tests pin that (`TestAReadonlyWithAShowDenyFitsTheBudget`, `TestThePredictionFollowsTheMeasuredAllowsPastTheBits`).
> Changing that under 1.2.0 is the edit the rule forbids. **Rule on R3 before Task 2 starts.**
> Task 1, the lab cell, is the same under either answer.
>
> **A finding from writing this plan.** Set 1.2.0 already sends the reply Task 1 measures,
> today, to a readonly whose grant also writes `deny: [monitor **]`. Its `deny-commands` is
> 173 bytes (measured from the shipped code; Task 1 pins it). Two consequences:
> - If Task 1 finds a refused probe that runs, that is a live hole in set 1.2.0, not only a
>   reason to drop this plan. Report it as a security finding.
> - An operator can get "permitted means it runs" under 1.2.0 now, with no code, by adding that
>   deny.

**Goal:** Ryan's ruling: "permitted means it runs". Take a Junos readonly that permits `show
configuration` under a deny beneath `show` (`show **` less `show security **`). Its reply sends
`view view-configuration`, and denies on the wire the rest of view-configuration's reach that the
grant decides nothing of. This ships only behind a lab cell (L68) proving the bit reaches nothing
those denies leave open.

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

**Tech Stack:** Go 1.26 (module `github.com/rhwendt/port49`), `internal/projection`,
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
  the controller. Tasks 2 to 7 depend on gate **G1** (Task 1 passed on both images).
- **R2. The 255-byte limit.** The rendered `deny-commands` stays within 255 bytes. A test measures
  its real length: 173 bytes for the canonical readonly. Past 255 the composition fails closed
  (`overflow`), as the 1.1.0 readonly does, and the refusal (and so the `policy test` finding)
  names the reach denies.
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
  - **Flagged above for the controller to rule on.**
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
   (the device refuses it). One the tree does not prove keeps the 1.2.0 render (Task 4,
   `TestAddedReachIsDeniedOrDeclined`).
5. **A block `bit_delivery: local_user_name` on 1.3.0.** The template branch is unchanged: the
   attributes equal 1.2.0's under the same block (Task 4, `TestATemplateDeliveryIsUnchanged`).

---

### Task 1: Lab cell L68, before any production code (gate G1)

**Files:**
- Create: `tests/lab/junos_viewcfg_test.go`
- Create: `tests/lab/junos_viewcfg_unit_test.go`
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15: add row L68 after L67, :10619)
- Create (by the run): `tests/lab/results/L68-juniper_vjunos-router.md`, `L68-juniper_vsrx.md`,
  `L68-netconf-juniper_vjunos-router.md`, `L68-netconf-juniper_vsrx.md`;
  `tests/lab/evidence/L68-*.pcap`, `L68-netconf-*.pcap` (redacted, `make evidence`)

**Interfaces:**
- Consumes these existing lab helpers:
  - sessions and runs: `junosLogin`, `junosProbe`, `junosSurvey`, `l26cRun`/`newL26cRun`, `l26cSend`;
  - NETCONF cells: `entryXMLMode`, `entryNetconf`, `entryExec`, `entryVerdict`, `entryProbes`, `entryCanonical`, `entryLogControl`;
  - CLI readings: `caretAt`, `caretOn`, `containsAny`, `junosL26bRefusal`, `beyond`, `heldBy`;
  - the `op url` script: `stageOpScript`, `opURLCmd`, `opAbbrevCmd`, `opURLEvidence`, `hostEvidence`;
  - setup and notes: `projectionRestore`, `entryResult`, `labGuardAt`, `l66StopSentinel`, `l66DiskFloorMB`, `jsonEscape`, `tableCell`, `cellOr`, `firstLines`, `commitWord`.
- Produces:
  - `l68Projected`: set 1.2.0's render, pinned. Task 6 pins it to set 1.3.0's render too.
  - The notes `tests/lab/results/L68-*.md`, whose "Gate" line reads `G1: pass` or `G1: STOP`.

**The rows** (each `user-permissions` over the reference configuration's bitless `p49-remote`,
the shape production sends):

| row | bits | deny-commands | why |
|---|---|---|---|
| P | view view-configuration | `l68Projected`, 173 bytes: set 1.2.0's render of `show **` less `show security **` and `monitor **` | what set 1.3.0 will send without the `monitor **` deny |
| H | view view-configuration | `l68Hand`, 235 bytes: `show security`, view-configuration's other reach, `junoscript`, `op` | the bit's reach denied exactly, nothing else |
| V | view | `l68Projected` | what the bit adds |
| Vc | view | none | completion baseline |
| C | view view-configuration | none | the control |

- [ ] **Step 1: Add the L68 register row (open)**

In `docs/design/2026-08-23-policy-engine-spec.md`, after the `| **L67** |` row, insert:

```markdown
| **L68** | A Junos reply sending `view view-configuration` with the rest of view-configuration's reach denied (plan 9g; decision 48). Under `user-permissions` over the bitless `p49-remote`, five rows: P, `view view-configuration` and set 1.2.0's render of a readonly granted `show **` less `show security **` and `monitor **` (173 bytes); H, the same bits and a deny of exactly `show security`, view-configuration's other reach and the entry denies (235 bytes); V, `view` alone under P's deny; Vc, `view` alone; C, `view view-configuration` and no deny, the control. Whether `show configuration` runs in P and H and not in V; whether `show security` and each word of view-configuration's other reach (`monitor`, `request mpls`, `request path-computation-client`, `request security`, `request unified-edge`, `request virtual-chassis`, `load` and `save dhcp-security-snoop`), typed in full and abbreviated, is refused in P and H where C takes it; whether `<get-configuration/>` through `xml-mode`, port 830, the port-22 subsystem and the exec channel, and `op url` and its abbreviation, are refused in P and H where C reaches them; whether view-configuration's completion over `view` (C against Vc) offers a word its declared reach does not hold. Recorded, not gated: `show log`, `show firewall`, `show policer`, `file list /config`, `file show /config/juniper.conf.gz`, and `show configuration`'s `\| save` and pager `s` (L59). | Decision 48: set 1.3.0's `deny_reach_bits: [view-configuration]` | Junos (vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15) | open — added by plan 9g 2026-10-16 |
```

- [ ] **Step 2: Write the failing unit tests**

Create `tests/lab/junos_viewcfg_unit_test.go`:

```go
//go:build lab

package lab

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/engine"
	adapter "github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/projection"
)

// l68Shipped renders a juniper_junos readonly on set version, as the policy
// layer hands the projection one (internal/projection's `shipped` helper).
func l68Shipped(version string, rules ...engine.Rule) (projection.Result, error) {
	set, _ := adapter.Set(version)
	d := set["juniper_junos"]
	return projection.Project(projection.Input{Platform: "juniper_junos", Dialect: d, Level: "readonly",
		Bits: d.CeilingBits["readonly"], Rules: rules,
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true},
		Facts: projection.JunosFacts, Keywords: adapter.KeywordsFor(version, "juniper_junos")})
}

func l68Rule(verdict, rule string) engine.Rule { return engine.Rule{Verdict: verdict, Rule: rule, Role: "r"} }

// Row P is byte for byte what set 1.2.0 renders for a readonly granted
// `show **` less `show security **` and `monitor **`, and within RFC 8907.
func TestL68ProjectedIsSet120sRender(t *testing.T) {
	res, err := l68Shipped("1.2.0", l68Rule(engine.Permit, "show **"), l68Rule(engine.Deny, "show security **"),
		l68Rule(engine.Deny, "monitor **"))
	want := []string{"user-permissions=view view-configuration", l68Projected}
	if err != nil || res.Shape != projection.ShapeCapability || !slices.Equal(res.Attributes, want) {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
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
// it or not at all (past), or by its evidence (ran).
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
			"save dhcp-security-snoop | count\nerror: command is not valid on the vsrx\n" + prompt, "past"},
		{l68Probe{cmd: "monitor list", prefix: 1}, "monitor list\n" + prompt, "past"},
		{l68Probe{cmd: "junoscript", prefix: 1}, "junoscript\nerror: unknown command: junoscript\n" + prompt, "refused"},
		{l68Probe{cmd: "show configuration system host-name", evidence: hostEvidence},
			"show configuration system host-name\n" + hostEvidence + ";\n" + prompt, "ran"},
		{l68Probe{cmd: "show configuration system host-name", evidence: hostEvidence},
			"show configuration system host-name\n" + prompt, "not observed"},
	} {
		if got := l68Cell(c.p, c.out, pl); got != c.want {
			t.Errorf("%q on %q: %s, want %s", c.p.cmd, c.out, got, c.want)
		}
	}
}

func TestL68Verdict(t *testing.T) {
	for _, c := range []struct{ row, control, want string }{
		{"refused", "past", "deny"}, {"refused", "ran", "deny"}, {"past", "past", "reached"},
		{"ran", "ran", "reached"}, {"refused", "refused", "runs nowhere"}, {"not observed", "past", "not observed"},
	} {
		if got := l68Verdict(c.row, c.control); got != c.want {
			t.Errorf("%s against %s: %s, want %s", c.row, c.control, got, c.want)
		}
	}
}

// The gate: a deny row that takes what it denies is a STOP; P or H not
// running the configuration, or V running it, is a STOP; the control not
// taking a canonical probe is INVALID; completion beyond the declared reach is
// a STOP.
func TestL68Gate(t *testing.T) {
	good := func() map[string]l26cRun {
		runs := map[string]l26cRun{}
		for _, n := range []string{"P", "H", "V", "Vc", "C"} {
			runs[n] = newL26cRun()
		}
		for _, p := range l68Probes {
			if p.reading {
				continue
			}
			ctl, deny := "past", "refused"
			if p.evidence == hostEvidence {
				ctl, deny = "ran", "ran"
				runs["V"].cells[p.cmd] = "refused"
			} else if p.evidence != "" {
				ctl = "ran"
			}
			runs["C"].cells[p.cmd], runs["P"].cells[p.cmd], runs["H"].cells[p.cmd] = ctl, deny, deny
		}
		return runs
	}
	reach := []string{"show configuration **", "show log **", "monitor **", "request mpls **"}
	vc := []string{"show", "show configuration", "show log", "monitor", "monitor list", "request mpls"}
	v := []string{"show", "show configuration"}
	if inv, stop, _ := l68Gate(good(), vc, v, reach); len(inv)+len(stop) != 0 {
		t.Fatalf("a clean run: invalid %v stop %v", inv, stop)
	}
	runs := good()
	runs["P"].cells["monitor p49-none"] = "past"
	if _, stop, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 || !strings.Contains(stop[0], "monitor p49-none") {
		t.Errorf("P took monitor: %v", stop)
	}
	runs = good()
	runs["H"].cells["show configuration system host-name"] = "refused"
	if _, stop, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 {
		t.Errorf("H refused the configuration: %v", stop)
	}
	runs = good()
	runs["V"].cells["show configuration system host-name"] = "ran"
	if _, stop, _ := l68Gate(runs, vc, v, reach); len(stop) != 1 {
		t.Errorf("V ran the configuration: %v", stop)
	}
	runs = good()
	runs["C"].cells["request mpls p49-none"] = "refused"
	if inv, _, _ := l68Gate(runs, vc, v, reach); len(inv) != 1 {
		t.Errorf("the control refused a canonical probe: %v", inv)
	}
	if _, stop, _ := l68Gate(good(), append(slices.Clone(vc), "request zzz"), v, reach); len(stop) != 1 ||
		!strings.Contains(stop[0], "request zzz") {
		t.Errorf("completion beyond the reach: %v", stop)
	}
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test -tags lab ./tests/lab/ -run '^(TestL68ProjectedIsSet120sRender|TestL68HandFitsAndCoversTheReach|TestL68Cell|TestL68Verdict|TestL68Gate)$' -count=1`
Expected: FAIL to compile: `undefined: l68Projected`, `l68Hand`, `l68Probe`, `l68Cell`, `l68Verdict`, `l68Gate`, `l68Probes`.

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

	adapter "github.com/rhwendt/port49/internal/platform"
)

// TestL68ViewConfigurationCLI and TestL68ViewConfigurationNetconf measure spec
// §15 L68 (plan 9g Task 1, gate G1): whether a reply sending `view
// view-configuration`, with deny-commands covering the grant's deny and the
// rest of view-configuration's reach, lets the session read the configuration
// and nothing the denies leave open. Each row is user-permissions over the
// reference configuration's bitless p49-remote, the shape production sends:
//   - P: set 1.2.0's render of a readonly granted `show **` less `show
//     security **` and `monitor **` (l68Projected), which set 1.3.0 sends
//     without the `monitor **` deny;
//   - H: the same bits, and a deny of exactly `show security`,
//     view-configuration's other reach, and the entry denies (l68Hand);
//   - V: `view` alone under P's deny: what the bit adds;
//   - Vc: `view` alone and no deny: the completion baseline;
//   - C: `view view-configuration` and no deny: the control.
// A refused probe that runs in P or H is a STOP: no reply change ships (plan
// 9g ruling R1).

// l68Projected is set 1.2.0's deny-commands for a readonly granted `show **`
// less `show security **` and `monitor **`, 173 bytes
// (TestL68ProjectedIsSet120sRender pins it).
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
		"set 1.2.0's render of show ** less show security ** and monitor **: set 1.3.0's reply"},
	{"H", l68Attrs("view view-configuration", l68Hand),
		"show security, view-configuration's other reach and the entry denies, nothing else"},
	{"V", l68Attrs("view", l68Projected), "view alone under P's deny: what the bit adds"},
	{"Vc", l68Attrs("view", ""), "view alone, no deny: the completion baseline"},
	{"C", l68Attrs("view view-configuration", ""), "the control"},
}

// l68Probe is one command a row types. prefix is how many of its leading
// typed words name the reach (or the grant's deny) it probes: the cell reads
// whether the CLI refused it there. A `p49-none` after the prefix is never a
// command: the control's CLI takes the prefix and stops at it, so nothing
// runs, and a deny refuses at the prefix (L58's reading of `save`). evidence
// is what a run prints. canonical: the control must take it, or the run is
// INVALID. reading: recorded, gated by nothing.
type l68Probe struct {
	cmd       string
	prefix    int
	evidence  string
	canonical bool
	reading   bool
}

var l68Probes = []l68Probe{
	// What the bit is sent for: it runs in P, H and C, and not in V.
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
	// Readings: the carve-outs, the configuration file, (L59).
	{cmd: "show log messages | count", evidence: "Count: ", reading: true},
	{cmd: "show firewall | no-more", reading: true},
	{cmd: "show policer | no-more", reading: true},
	{cmd: "file list /config", reading: true},
	{cmd: "file show /config/juniper.conf.gz | count", evidence: "Count: ", reading: true},
}

var l68UnknownCommand = regexp.MustCompile(`unknown command: ([a-z][a-z-]*)`)

// l68Cell reads one probe's window. "ran": its evidence and no refusal.
// "refused": a caret on one of its first prefix words, `permission denied`,
// or `unknown command` naming one. "past": a caret after the prefix, a
// platform's "command is not valid on the" refusal of the whole command, or,
// for a probe with no evidence, no refusal at all. Else "not observed".
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
		return "past"
	}
	if !refusal && p.evidence == "" {
		return "past"
	}
	return "not observed"
}

// l68Verdict is a gated probe's reading in a deny row against the control:
// "reached" where the row ran it or took its prefix; "deny" where the row
// refused it and the control took it; "runs nowhere" where both refused it
// (the image lacks the word).
func l68Verdict(row, control string) string {
	took := func(c string) bool { return c == "ran" || c == "past" }
	switch {
	case took(row):
		return "reached"
	case row == "refused" && took(control):
		return "deny"
	case row == "refused" && control == "refused":
		return "runs nowhere"
	}
	return "not observed"
}

// l68Gate reads the CLI run: invalid lines (the control did not take a
// canonical probe or run the configuration), stop lines (a deny row took
// what it denies; P or H did not run the configuration; V did; the bit's
// completion over `view` offers a word reach does not hold), and the
// verdicts the note prints, keyed "row probe".
func l68Gate(runs map[string]l26cRun, surveyC, surveyVc, reach []string) (invalid, stop []string,
	verdicts map[string]string) {
	verdicts = map[string]string{}
	c := runs["C"]
	for _, p := range l68Probes {
		if p.reading {
			continue
		}
		cc := c.cells[p.cmd]
		if p.evidence == hostEvidence {
			if p.canonical && cc != "ran" {
				invalid = append(invalid, p.cmd+": the control "+cellOr(c, p.cmd))
			}
			for _, row := range []string{"P", "H"} {
				if got := runs[row].cells[p.cmd]; got != "ran" {
					stop = append(stop, fmt.Sprintf("%s: %s %s, so the bit does not deliver the configuration",
						p.cmd, row, cellOr(runs[row], p.cmd)))
				}
			}
			if runs["V"].cells[p.cmd] == "ran" {
				stop = append(stop, p.cmd+": V ran it under `view` alone, which L12-bits measured refused")
			}
			continue
		}
		if p.canonical && cc != "ran" && cc != "past" {
			invalid = append(invalid, p.cmd+": the control "+cellOr(c, p.cmd))
		}
		for _, row := range []string{"P", "H"} {
			v := l68Verdict(runs[row].cells[p.cmd], cc)
			verdicts[row+" "+p.cmd] = v
			if v == "reached" {
				stop = append(stop, fmt.Sprintf("%s: %s took it past its deny", p.cmd, row))
			}
		}
	}
	for _, w := range beyond(surveyC, surveyVc) {
		if !heldBy(reach, w+" **") {
			stop = append(stop, fmt.Sprintf("completion: view-configuration offers %q over `view`, which its "+
				"declared reach does not hold, so no deny covers it", w))
		}
	}
	return invalid, stop, verdicts
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
		for _, v := range junosL68Variants {
			l68Guard(t)
			r := newL26cRun()
			runs[v.name] = r
			c, run, _ := l.junosLogin(t, "L68 "+v.name, v.attrs)
			if c == nil {
				t.Fatalf("INVALID: %s: the session did not open, so nothing was measured: %s", v.name, run.loginErr)
			}
			r.outs["show cli authorization"] = run.auth
			promptLen := len(run.user + "@" + junosHost + "> ")
			// l26cSend keeps the echo, which caretAt reads the caret against;
			// junosProbe trims it. Paging is off (junosLogin's junosPrepare).
			for _, p := range l68Probes {
				out, err := l26cSend(c, p.cmd)
				r.outs[p.cmd], r.cells[p.cmd] = out, l68Cell(p, out, promptLen)
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
			c.Close()
		}
		files := l.l68Files(t)
		set, _ := adapter.Set("1.2.0")
		invalid, stopped, verdicts := l68Gate(runs, surveys["C"], surveys["Vc"],
			set["juniper_junos"].Bits["view-configuration"])
		// A gated cell not observed (or never typed, past a missed prompt) says
		// nothing: the run is INVALID before any STOP is read.
		for _, p := range l68Probes {
			for _, n := range []string{"P", "H", "V", "C"} {
				if cell, ok := runs[n].cells[p.cmd]; !p.reading && (!ok || cell == "not observed") {
					invalid = append(invalid, fmt.Sprintf("%s in %s: not observed", p.cmd, n))
				}
			}
		}
		if len(invalid) > 0 {
			t.Fatalf("INVALID: %s; no note is written", strings.Join(invalid, "; "))
		}
		var b strings.Builder
		gate := "G1: pass"
		if len(stopped) > 0 {
			gate = "G1: STOP — " + strings.Join(stopped, "; ")
		}
		fmt.Fprintf(&b, "**Gate:** %s\n\nThe reference configuration was committed: %s.\n\n", gate, commitWord(commit))
		l68Tables(&b, runs, verdicts, surveys, files)
		for _, s := range stopped {
			t.Errorf("STOP: %s: no reply change ships; report to the controller (plan 9g R1)", s)
		}
		// A STOP is a measurement: its note is written so the controller reads it.
		l.l68Note(t, "L68", "Whether `user-permissions=view view-configuration` with deny-commands covering `show "+
			"security` and view-configuration's other reach lets the session read the configuration and nothing the "+
			"denies leave open, against `view` alone and a control with the same bits and no deny (spec §15 L68; plan "+
			"9g Task 1, gate G1).", b.String(), len(stopped) > 0)
	})
}

// l68NetconfVariants are the rows NETCONF is probed in: the two deny rows and
// the control.
var l68NetconfVariants = []junosVariant{junosL68Variants[0], junosL68Variants[1], junosL68Variants[4]}

func TestL68ViewConfigurationNetconf(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		l68Guard(t)
		stop := l.capture(t, "L68-netconf")
		defer stop()
		reference := l68Reference(t)
		commit := l.junosConfigureAdmin(t, append(slices.Clone(reference), "set system services netconf ssh"))
		defer l.junosConfigureAdmin(t, projectionRestore(reference))
		defer l.l68RestoreDaemon(t)
		probes, canonical := entryProbes[1:], entryCanonical[1:] // the CLI test reads the configuration
		runs := map[string]l26cRun{}
		for _, v := range l68NetconfVariants {
			l68Guard(t)
			r := newL26cRun()
			runs[v.name] = r
			c, run, _ := l.junosLogin(t, "L68 netconf "+v.name, v.attrs)
			if c == nil {
				t.Fatalf("INVALID: %s: the session did not open, so nothing was measured: %s", v.name, run.loginErr)
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
			for _, n := range []string{"P", "H", "C"} {
				if runs[n].cells[p] == "not observed" {
					unobserved = append(unobserved, p+" in "+n)
				}
			}
		}
		if len(unobserved) > 0 {
			t.Fatalf("INVALID: not observed: %s; no note is written", strings.Join(unobserved, "; "))
		}
		readings, unisolated := entryVerdict(runs, []string{"P", "H"}, "C", canonical, probes)
		if len(unisolated) > 0 {
			entryLogControl(t, runs["C"], unisolated)
			t.Fatalf("INVALID: the control did not reach %s; no note is written", strings.Join(unisolated, "; "))
		}
		var stopped []string
		for k, v := range readings {
			if v == "reached" {
				stopped = append(stopped, k)
			}
		}
		slices.Sort(stopped)
		var b strings.Builder
		gate := "G1: pass"
		if len(stopped) > 0 {
			gate = "G1: STOP — reached past the entry deny: " + strings.Join(stopped, "; ")
		}
		fmt.Fprintf(&b, "**Gate:** %s\n\nThe reference configuration and `netconf ssh` were committed: %s.\n\n", gate,
			commitWord(commit))
		l68NetconfTables(&b, runs, readings, probes)
		for _, s := range stopped {
			t.Errorf("STOP: %s: no reply change ships; report to the controller (plan 9g R1)", s)
		}
		l.l68Note(t, "L68-netconf", "Whether NETCONF (`xml-mode` from the CLI, port 830, the port-22 subsystem, "+
			"the exec channel) reaches `<get-configuration/>` under `user-permissions=view view-configuration` with "+
			"the entry denies beside view-configuration's other reach denied, against a control with the same bits "+
			"and no deny (spec §15 L68; plan 9g Task 1, gate G1).", b.String(), len(stopped) > 0)
	})
}

// l68Note writes the note through entryResult's leak check. A STOP run has
// failed, which entryResult reads as INVALID; a STOP is a measurement, so it
// is written under its own check: the same leak check, and nothing else
// failed.
func (l *lab) l68Note(t *testing.T, entry, claim, observation string, stopped bool) {
	t.Helper()
	if !stopped {
		l.entryResult(t, entry, claim, observation)
		return
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
	names := []string{"P", "H", "V", "Vc", "C"}
	b.WriteString("| row | reply | why |\n|---|---|---|\n")
	for _, v := range junosL68Variants {
		fmt.Fprintf(b, "| %s | `%s` | %s |\n", v.name, tableCell(v.attrs), v.why)
	}
	fmt.Fprintf(b, "\n| probe | %s |\n|---|%s\n", strings.Join(names, " | "), strings.Repeat("---|", len(names)))
	keys := []string{}
	for _, p := range l68Probes {
		keys = append(keys, p.cmd)
	}
	keys = append(keys, "pager s")
	for _, k := range keys {
		cells := make([]string, len(names))
		for i, n := range names {
			cells[i] = cellOr(runs[n], k)
		}
		fmt.Fprintf(b, "| %s | %s |\n", tableCell(k), strings.Join(cells, " | "))
	}
	b.WriteString("\n### Verdict against the control\n\n| probe | P | H |\n|---|---|---|\n")
	for _, p := range l68Probes {
		if !p.reading && p.evidence != hostEvidence {
			fmt.Fprintf(b, "| %s | %s | %s |\n", tableCell(p.cmd), verdicts["P "+p.cmd], verdicts["H "+p.cmd])
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

// l68NetconfTables writes the NETCONF rows' cells, the verdicts and the raw
// outputs.
func l68NetconfTables(b *strings.Builder, runs map[string]l26cRun, readings map[string]string, probes []string) {
	names := []string{"P", "H", "C"}
	fmt.Fprintf(b, "| probe | %s |\n|---|---|---|---|\n", strings.Join(names, " | "))
	for _, p := range probes {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", tableCell(p), cellOr(runs["P"], p), cellOr(runs["H"], p),
			cellOr(runs["C"], p))
	}
	b.WriteString("\n### Verdict against the control\n\n| probe | P | H |\n|---|---|---|\n")
	for _, p := range probes {
		fmt.Fprintf(b, "| %s | %s | %s |\n", tableCell(p), jsdOrDash(readings["P "+p]), jsdOrDash(readings["H "+p]))
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

If a helper named above does not exist under that exact name, `go vet -tags lab` reports it. The
ones to check: `oneLine`, `junosPaged`, `jsdOrDash`, `tableCell`, `leakIn`, `poolSecrets`,
`breakglassUser`. Use the existing helper of that role; do not write a second one.

- [ ] **Step 5: Run the unit tests and vet**

Run: `go test -tags lab ./tests/lab/ -run '^(TestL68ProjectedIsSet120sRender|TestL68HandFitsAndCoversTheReach|TestL68Cell|TestL68Verdict|TestL68Gate)$' -count=1 && go vet -tags lab ./tests/lab/ && make lab-unit`
Expected: PASS. Then prove each test by mutation, and revert each mutation:
- change one byte of `l68Projected`;
- drop `virtual-chassis` from `l68Hand`;
- make `l68Cell` return "past" for a caret on the prefix;
- make `l68Gate` skip the completion check.

Each must turn a test red.

- [ ] **Step 6: Commit the harness and the open row**

```bash
git add tests/lab/junos_viewcfg_test.go tests/lab/junos_viewcfg_unit_test.go docs/design/2026-08-23-policy-engine-spec.md
git commit -m "test: L68 harness, view-configuration with its other reach denied"
```

- [ ] **Step 7: Run L68 on both images, under the lab rules**

The lab has one occupant at a time. Check the floor first: `df -BM --output=avail / | tail -1`
must be ≥ 67584M, and `/tmp/port49-STOP-LAB` must not exist.

```bash
sha=$(git -C /home/rwendt/git/port49/.worktrees/junos-view-configuration rev-parse HEAD)
git -C /home/rwendt/git/port49 worktree add --detach /home/rwendt/git/port49/.worktrees/l68-run "$sha"
cd /home/rwendt/git/port49/.worktrees/l68-run && make build
```

Arm the stall watchdog in a background shell before the run, and re-arm it on every wake:

```bash
while sleep 120; do
  pgrep -f "^/tmp/go-build[^ ]*/lab\.test" >/dev/null || { echo "lab.test exited"; break; }
  [ -z "$(find /home/rwendt/git/port49/.worktrees/l68-run/tests/lab/captures /tmp/port49-lab-tokens.jsonl \
    -newermt '-10 minutes' 2>/dev/null | head -1)" ] && { echo "STALL: no progress in 10 minutes"; break; }
done
```

On a stall, take a goroutine dump with `kill -QUIT` before anything else. Then run each test in
its own invocation, per platform, in the foreground:

```bash
cd /home/rwendt/git/port49/.worktrees/l68-run
for t in TestL68ViewConfigurationCLI TestL68ViewConfigurationNetconf; do
  for p in vjunos vsrx; do
    PORT49_LAB_PLATFORMS=$p go test -tags lab ./tests/lab/ -run "^$t\$" -count=1 -v -timeout 90m || break 2
  done
done
make evidence
```

Expected: four PASS runs and four notes, each reading `**Gate:** G1: pass`. Other outcomes:
- **`INVALID:`** writes no note. Fix the harness or the cell reader, then rerun. A control that
  cannot reach is a harness or image fault.
- **`STOP:`** writes its note with `G1: STOP — …`. **Stop the plan here.** Report to the
  controller with the note's tables. Say that row P is a reply set 1.2.0 sends today to a grant
  that writes `deny: [monitor **]`, so a P STOP is a live 1.2.0 finding. Do not start Task 2.

- [ ] **Step 8: Copy the outputs out and remove the run worktree**

```bash
run=/home/rwendt/git/port49/.worktrees/l68-run
feat=/home/rwendt/git/port49/.worktrees/junos-view-configuration
cp "$run"/tests/lab/results/L68-*.md "$feat"/tests/lab/results/
cp "$run"/tests/lab/evidence/L68-*.pcap "$feat"/tests/lab/evidence/
mkdir -p /home/rwendt/git/port49/tests/lab/captures && cp "$run"/tests/lab/captures/L68* /home/rwendt/git/port49/tests/lab/captures/
git -C /home/rwendt/git/port49 worktree remove "$run"
```

- [ ] **Step 9: Close L68 and commit (only on G1: pass on both images)**

Edit the L68 row's Status to:

```
closed — measured <date>; `tests/lab/results/L68-juniper_vjunos-router.md`, `L68-juniper_vsrx.md`, `L68-netconf-juniper_vjunos-router.md`, `L68-netconf-juniper_vsrx.md`
```

Use the run's date. In the row, add one sentence per reading the notes record, without
widening any claim:
- `show log`, `show firewall`, `show policer`;
- the `/config` reads;
- `| save` and pager `s`, which stay L59's;
- any word that "runs nowhere" on an image.

```bash
git add tests/lab/results/L68-*.md tests/lab/evidence/L68-*.pcap docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L68"
```

**Gate G1:** Tasks 2 to 7 start only when both images' L68 and L68-netconf notes read `G1:
pass`, and the controller has ruled on R3.

---

### Task 2: The spec, first (depends on G1)

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`, in these places:
  - §8 Fields table, after the `rpc_entry_denies` row (:3644);
  - §8 :4066-4072, the paragraph beginning "So a readonly granted `show **` less `show configuration **`";
  - §8 :4078-4081, the warning paragraph;
  - §8 :4083, "**Set 1.1.0 is unchanged**";
  - §12 findings table, the `projection_deny_beneath_view_configuration` row (:5886);
  - §13 decision 44 ruling 10's last sentence (:8989-8991);
  - §13: a new decision 48 after decision 47.

**Interfaces:** Produces the text Tasks 3 to 5 cite: decision 48, the key `deny_reach_bits`, and
the role `reach_deny`.

- [ ] **Step 1: Add the Fields row** after `rpc_entry_denies`:

```markdown
| `deny_reach_bits` | on a projected platform whose adapter carries `rpc_entry_denies`, the bits a reply may send where the grant permits a carve-out of the bit that an allow past the bits is not measured to run, with the rest of the bit's reach that the grant decides nothing of denied on the wire, role `reach_deny` (decision 48). Set 1.3.0's `juniper_junos` carries `[view-configuration]` (L68). Each is a declared bit with a carve-out, never `baseline` or `all`. A block may drop one, `[]` all, and never add one; where the block drops `rpc_entry_denies` the key is inert | optional |
```

- [ ] **Step 2: Replace :4066-4072** (from "So a readonly granted `show **` less `show
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

**A readonly that permits `show configuration` under a deny beneath `show`** (decision 48). Take
`show **` less `show security **`. Only view-configuration shows the configuration: under `view`
an allow of `show configuration` was refused on both images (`L26c-projected-juniper_*.md`).
Under set 1.2.0 that readonly gets `view` and allows of the four carve-outs, and the device
refuses `show configuration`; CI says so. Under set 1.3.0, whose `juniper_junos` carries
`deny_reach_bits: [view-configuration]`, the reply sends `view view-configuration`. It denies
the reach of view-configuration that the grant decides nothing of: here `monitor **`, since the
baseline denies already hold `request **`, `load **` and `save **`. Its `deny-commands` is 173
bytes, the grant's deny, then `monitor` in the baseline's alternative.

L68 measured that reply on both images (`tests/lab/results/L68-juniper_*.md`,
`L68-netconf-juniper_*.md`):
- `show configuration` ran;
- `show security` was refused;
- each word of view-configuration's other reach was refused, typed in full and abbreviated;
- `<get-configuration/>` was refused on every way into NETCONF, and so was `op url`;
- the control, with the same bits and no deny, reached each one;
- a deny of exactly view-configuration's other reach, with no baseline denies, was refused the same way;
- view-configuration's completion over `view` offered no word its declared reach does not hold.

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
Where they take `deny-commands` past 255 bytes, the composition fails closed (`overflow`), as set
1.1.0's readonly does, and the refusal names them.
```

- [ ] **Step 3: Amend the warning paragraph** (:4078-4081). After "...so withholding the bit is the
  real fence.", add:

```markdown
A reply that sends view-configuration under decision 48 carries no deny that meets `show
configuration`, and a reach deny is never named, so it gets no such warning.
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
  named".

- [ ] **Step 6: Decision 44 ruling 10.** Replace its last sentence, "view-configuration is not
  sent to such a readonly, whose grant decides none of its other reach; ruling 4's warning stays
  an operator's and an admin's.", with:

```markdown
Under set 1.2.0 view-configuration is not sent to such a readonly, whose grant decides none of
its other reach; set 1.3.0 sends it where the grant permits `show configuration` (decision 48).
Ruling 4's warning stays an operator's and an admin's.
```

- [ ] **Step 7: Add decision 48** after decision 47 ends (before the next `**4x.`/section heading
  that follows it):

```markdown
**48. Junos: view-configuration sent with the rest of its reach denied.** *Plan 9g, 2026-10-16,
on Ryan's ruling of 2026-10-15: "permitted means it runs".* Rulings rest on reasoning unless they
say data.

- **1. The rule** (data: `tests/lab/results/L68-juniper_*.md`, `L68-netconf-juniper_*.md`). Under
  a set whose platform carries `deny_reach_bits` and `rpc_entry_denies`, under `user_permissions`,
  a ceiling bit the grant decides only in part is sent where:
  - the key lists it;
  - the grant permits a carve-out of it that no deny holds whole and whose allow past the bits
    is not measured to run (`JunosFacts.AllowPastCarve`);
  - a bit the reply already sends reaches that carve-out;
  - no permit meets the rest of its reach, each rule of which the keyword tree proves.

  That rest goes out as denies, role `reach_deny`, after the grant's own denies and before the
  baseline's. The deny beneath the bit brings the entry denies (decision 44 ruling 1).
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
  bit is not sent where it does not.
- **4. The budget** (RFC 8907; Ryan's production experience that over 255 bytes locks the user
  out). The readonly granted `show **` less `show security **` renders 173 bytes, measured in a
  test. Past 255 the composition fails closed (`overflow`) and the refusal names the reach
  denies; the reply does not fall back to set 1.2.0's.
- **5. Warnings and predictions.** `projection_deny_beneath_view_configuration` never names a reach
  deny. `policy test` and `explain` predict `show configuration` runs under the reply, and the
  projection finding names the reach denies.
- **6. Unmeasured.** Hidden commands under view-configuration that completion does not list (L12-bits
  holds the reach as an upper bound for every bit). L59's cells: REST, the XML API,
  `outbound-ssh`, file reads of `/config`, NETCONF off, and `| save` and the pager's `s`, which
  L68 recorded and did not gate.
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

In `internal/platform/adapter_test.go`, after `shipped120` (:178). Add the imports `io/fs`,
`strings` and `github.com/rhwendt/port49/platforms` if the file lacks them.

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
		{"a reach bit with no carve-out", func(d *Dialect) {
			d.RPCEntryDenies = []string{"junoscript **"}
			d.DenyReachBits = []string{"clear"}
		}, "deny_reach_bits[0]: clear has no carve-out"},
		{"baseline as a reach bit", func(d *Dialect) {
			d.RPCEntryDenies = []string{"junoscript **"}
			d.DenyReachBits = []string{BaselineBit}
		}, "deny_reach_bits[0]: baseline"},
```

And in `TestValidateProjectionMessages`'s unprojected sibling, if there is one, or a new test:

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

In `internal/policy/platforms_test.go`, after `TestABlockMayDropTheEntryDenyNotAddOne`:

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
```

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
		case len(d.CarveOuts[bit]) == 0:
			return fmt.Errorf("%s[%d]: %s has no carve-out, so no permit needs it sent (decision 48)",
				field("deny_reach_bits"), i, bit)
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
  - new `reachDenies`, `insertReachDenies` and `Result.ReachDenies`, after `carvedAllows` :826.
- Test: create `internal/projection/project_reach_test.go`

**Interfaces:**
- Consumes: `platform.Dialect.DenyReachBits`, `platform.ReachDenyRole`, `platform.Set("1.3.0")`,
  `platform.KeywordsFor("1.3.0", …)` (Task 3).
- Produces:
  - `func (r Result) ReachDenies() []engine.Rule`: the reply's denies with role
    `platform.ReachDenyRole`;
  - the overflow refusal's `Why` naming them;
  - `Result.ConfigurationBeneath` never holding one.

- [ ] **Step 1: Write the failing tests**

Create `internal/projection/project_reach_test.go`:

```go
package projection

import (
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
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
	if err != nil || len(res.ReachDenies()) != 0 || slices.Contains(res.Bits, "view-configuration") {
		t.Errorf("unproven: %s %q %v", res.Shape, res.Attributes, err)
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
	if err != nil || len(res.ReachDenies()) != 0 || !slices.Equal(res.Attributes, was.Attributes) {
		t.Fatalf("%s %q, 1.2.0 %q %v", res.Shape, res.Attributes, was.Attributes, err)
	}
}

// R2: past 255 bytes the composition fails closed as overflow, the refusal
// names the reach denies, and it does not fall back to 1.2.0's reply. Under
// 1.2.0 the same grant fits (249 bytes); `monitor` takes 1.3.0's past.
func TestAReachDenyPastTheBudgetFailsClosed(t *testing.T) {
	rules := []engine.Rule{permit("show **"), deny("show security **"), deny("show route **"), deny("show bgp **"),
		deny("show ospf **")}
	was, err := Project(shipped("1.2.0", "readonly", rules...))
	if err != nil || was.Shape != ShapeCapability || len(denyCommands(was)) != 249 {
		t.Fatalf("1.2.0: %s %q %v", was.Shape, was.Attributes, err)
	}
	res, err := Project(shipped("1.3.0", "readonly", rules...))
	if err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailOverflow ||
		!strings.Contains(res.Refusal.Why, "deny_reach_bits") || !strings.Contains(res.Refusal.Why, "monitor **") {
		t.Fatalf("%s %s %+v %v", res.Shape, res.FailClosed, res.Refusal, err)
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
	if !g.closesEntries() || !slices.Contains(g.in.Dialect.DenyReachBits, b) {
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

In `attributes`, in the `if r.Attribute == "deny-commands" {` branch, before
`r.Class = res.Template`:

```go
				if rd := res.ReachDenies(); len(rd) > 0 {
					var rules []string
					for _, d := range rd {
						rules = append(rules, d.Rule)
					}
					r.Why += fmt.Sprintf("; it carries the denies of a bit's reach the grant does not decide, sent so "+
						"the bit can go out (deny_reach_bits; decision 48): %s", strings.Join(rules, ", "))
				}
```

Update the `Result.ConfigurationBeneath` field comment (:148-151). After "(projection_deny_beneath_view_configuration; decision 44)", add "; never a reach deny (decision 48)".

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/projection/ -count=1 && make test && make vet`
Expected: PASS, including the existing `TestAReadonlyWithAShowDenyFitsTheBudget`,
`TestTheShippedSetsEntryDeny` and `TestACarvedPermitTheSentBitsDoNotReachIsRefused`, unchanged.
Prove each new test with a mutation, and revert each:

| Mutation | Test that must go red |
|---|---|
| `insertReachDenies` appends at the end instead | the byte-for-byte check in `TestTheSet130ReadonlySendsViewConfiguration` |
| drop the `closesEntries()` check | `TestReachDeniesNeedTheEntryDeny` |
| drop the permit-meets check | `TestReachDeniesDeclineAPermittedReach` |
| drop the `reached` check | `TestTheBitIsNotSentAloneForItsCarveOut` |
| drop the overflow clause | `TestAReachDenyPastTheBudgetFailsClosed` |
| drop the `ReachDenyRole` check in `configurationBeneath` | `TestConfigurationBeneathSkipsAReachDeny` |

- [ ] **Step 5: Commit**

```bash
git add internal/projection/project.go internal/projection/project_reach_test.go
git commit -m "feat: set 1.3.0 sends view-configuration with its undecided reach denied"
```

---

### Task 5: `policy test`, `explain` and the warnings follow (depends on G1)

**Files:**
- Modify: `internal/policy/lint.go` (`projectionMessage` :964-990; the
  `FindingProjectionDenyBeneathViewConfiguration` comment :674-677)
- Test: `internal/policy/projection_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `projection.Result.ReachDenies()` (Task 4); `platform_set: 1.3.0` (Task 3).
- Produces: the projection finding's clause `; of those, the reach of a bit the grant decides
  only in part, denied so the bit can be sent (deny_reach_bits; decision 48): <rules>`.

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

// Past 255 bytes the readonly fails closed under 1.3.0, and the refusal
// policy test prints names the reach deny (R2); under 1.2.0 it fits.
func TestSet130OverflowIsARefusalNamingTheReachDeny(t *testing.T) {
	role := `roles:
  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show security **", "show route **", "show bgp **", "show ospf **"]}
`
	if p := mustParse(t, "platform_set: 1.2.0\n"+scopeOK+role+subjOK+grantOK); ProjectionRefusals(p.Projections(noon)) != 0 {
		t.Fatal("1.2.0 refuses it")
	}
	p := mustParse(t, "platform_set: 1.3.0\n"+scopeOK+role+subjOK+grantOK)
	fs := p.Projections(noon)
	var msg string
	for _, f := range fs {
		if f.Kind == FindingProjectionOverflow {
			msg = f.Message
		}
	}
	if ProjectionRefusals(fs) != 1 || !strings.Contains(msg, "RFC 8907 carries at most") ||
		!strings.Contains(msg, "monitor **") || !strings.Contains(msg, "deny_reach_bits") {
		t.Errorf("%q", msg)
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

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1 && make test && make vet`
Expected: PASS, with `TestThePredictionFollowsTheMeasuredAllowsPastTheBits` (set 1.2.0) and
`TestTheEntryDenyWarnings` unchanged. Prove the clause by deleting it, and revert.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/lint.go internal/policy/projection_test.go cmd/port49/policy_test.go
git commit -m "feat: policy test names set 1.3.0's reach denies and predicts the configuration runs"
```

---

### Task 6: Lab, set 1.3.0's reply through the broker (depends on G1, Tasks 3 to 5)

**Files:**
- Modify: `tests/lab/projection_test.go`:
  - `projectionSet`'s `capName` map and set switch (:257-264);
  - after `projectionShapes120` (:233), add `projectionShapes130` and `projectionProbes130`;
  - the default of `PORT49_LAB_PROJECTION_SETS` stays `1.1.0,1.2.0`.
- Modify: `tests/lab/junos_viewcfg_unit_test.go` (one test)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (the L68 row)
- Create (by the run): `tests/lab/results/L68-projected-juniper_vjunos-router.md`,
  `L68-projected-juniper_vsrx.md`; `tests/lab/evidence/L68-projected-*.pcap`

**Interfaces:**
- Consumes: set 1.3.0 (Task 3) and its render (Task 4); `l68Projected` (Task 1).

- [ ] **Step 1: Write the failing unit test**

In `tests/lab/junos_viewcfg_unit_test.go`:

```go
// What set 1.3.0 sends a readonly granted `show **` less `show security **`
// is row P, byte for byte: the reply L68 measured.
func TestL68ProjectedIsSet130sRender(t *testing.T) {
	res, err := l68Shipped("1.3.0", l68Rule(engine.Permit, "show **"), l68Rule(engine.Deny, "show security **"))
	want := []string{"user-permissions=view view-configuration", l68Projected}
	if err != nil || !slices.Equal(res.Attributes, want) {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}
```

Run: `go test -tags lab ./tests/lab/ -run '^TestL68ProjectedIsSet130sRender$' -count=1`. Expected:
PASS, since Tasks 3 and 4 are in. To see it red, change one byte of `l68Projected` and check it
fails, then revert.

- [ ] **Step 2: Add the 1.3.0 rows**

In `tests/lab/projection_test.go`, after `projectionShapes120`:

```go
// projectionShapes130 are set 1.3.0's (plan 9g; L68): the readonly denying
// `show security` now gets `view view-configuration` with `monitor **`
// denied, and its `show configuration` must run; the readonly denying `show
// configuration` keeps 1.2.0's reply; the operator control keeps NETCONF.
var projectionShapes130 = []struct{ name, roles, want string }{
	{"readonly denying show security", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show security **"]}`, projection.ShapeCapability},
	{"readonly denying show configuration", `  - {name: r, privilege: readonly, permit: ["show **"], deny: ["show configuration **"]}`, projection.ShapeCapability},
	{"operator, all it reaches", `  - {name: r, privilege: operator, permit: ["**"]}`, projection.ShapeCapability},
	{"readonly", `  - {name: r, privilege: readonly, permit: ["show **"]}`, projection.ShapeNarrow},
}

// projectionProbes130 are typed in set 1.3.0's rows besides projectionProbes:
// view-configuration's other reach, which the readonly's reply denies and
// the operator's grant permits.
var projectionProbes130 = []projectionProbe{
	{junosProbe{cmd: "monitor list"}, "monitor list"},
	{junosProbe{cmd: "mon list"}, "monitor list"},
	{junosProbe{cmd: "request mpls p49-none"}, "request mpls p49-none"},
	{junosProbe{cmd: "request security p49-none"}, "request security p49-none"},
}
```

In `projectionSet`:
- Extend `capName` with `"1.3.0": "L68-projected"`.
- Add `if v == "1.3.0" { shapes, entry = projectionShapes130, "L68-projected" }`.
- Pass the probe list into `projectionShape`: `projectionProbes`, plus `projectionProbes130`
  when `v == "1.3.0"`. If `projectionShape` reads `projectionProbes` directly, give it a `probes
  []projectionProbe` parameter, and pass `projectionProbes` at the 1.1.0 and 1.2.0 call sites,
  so those runs are unchanged.
- Where `opControlMissing` names set `"1.2.0"`, make it hold for `"1.3.0"` too: the control row
  is the same.

Run: `go vet -tags lab ./tests/lab/ && make lab-unit`. Expected: PASS.

- [ ] **Step 3: Commit the harness**

```bash
git add tests/lab/projection_test.go tests/lab/junos_viewcfg_unit_test.go
git commit -m "test: the projection differential runs set 1.3.0's rows (L68)"
```

- [ ] **Step 4: Run under the lab rules**

The rules are Task 1 Step 7's:
- single occupant;
- the floor checked and the sentinel absent;
- a detached worktree `l68p-run` at this commit, and `make build` there;
- the watchdog armed on its captures.

Then:

```bash
cd /home/rwendt/git/port49/.worktrees/l68p-run
for p in vjunos vsrx; do
  PORT49_LAB_PROJECTION_SETS=1.3.0 PORT49_LAB_PLATFORMS=$p go test -tags lab ./tests/lab/ \
    -run '^TestProjectionDifferential$' -count=1 -v -timeout 120m || break
done
make evidence
```

Expected: PASS on both images, and two `L68-projected` notes.
- In "readonly denying show security", `show configuration system host-name` ran (the
  differential fails on a device refusal the model does not predict), and `monitor list` and the
  `request` probes were refused.
- A device running what port49 denies fails the run. That is a STOP: report it to the
  controller, and do not merge.

Then copy the outputs out as in Task 1 Step 8, using `L68-projected-*`, and remove the worktree.

- [ ] **Step 5: Extend the L68 row and commit**

Add `L68-projected-juniper_vjunos-router.md`, `L68-projected-juniper_vsrx.md` to the closed row's
note list. Add one sentence: "Set 1.3.0's rendered reply, through the broker, ran `show
configuration` and refused view-configuration's other reach on both images." Then:

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
  - L68's gate readings per image, and any word that "runs nowhere";
  - the 173-byte reply;
  - the `| save`, pager and `/config` readings, which stay L59's;
  - "Carried" items:
    - L59 unchanged;
    - hidden commands unmeasured;
    - R2's fail-closed past 255, with no 1.2.0 fallback, as ruled.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: roadmap records plan 9g as built"
```
