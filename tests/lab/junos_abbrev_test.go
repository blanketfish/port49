//go:build lab

package lab

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// TestL9JunosAbbreviations first reads whether the rendered deny is enforced
// at all: every command typed in full, plain and piped, refused under it. A
// shape the device does not enforce is Task 14's branch B2, which reverts
// the deny to the shape Task 2 measured or ships Junos unprojected. It then
// measures JunosFacts.DenyMatchesExpanded for
// keywords (spec §15 L9; decision 27; the lead's ruling of 2026-09-25): that a
// keyword deny refuses the command however its keywords are abbreviated, at
// several lengths and command depths, piped, and where an abbreviation is
// ambiguous at one level. Task 2 measured one abbreviation, `sh ver`, which is
// too little to trust a deny against every abbreviated form, so the fact stays
// false in set 1.1.0 unless every probe here is refused under the deny on both
// images, while the control, a class holding every bit and no regex, ran each
// unambiguous one. An ambiguous abbreviation the CLI refuses in the control
// is recorded, and must be refused under the deny too.
//
// Two sessions, two seeded tokens. Every command has junosPer; a missed
// prompt is not observed and fails the test.

var junosAbbrevClass = []string{
	"set system login class p49-l9-all permissions all",
	"set system login user p49-l9-all class p49-l9-all",
}

var junosAbbrevDelete = []string{"delete system login user p49-l9-all", "delete system login class p49-l9-all"}

// junosAbbrevDeny names five commands of two and three keywords exactly as
// the generator renders a deny (ruleERE, Task 7 as fixed in eaf7975;
// pre-flight B-M3): a leading ` *`, words joined by ` +`, the tail ` *(\|.*)?`
// taking trailing spaces and a pipeline, one alternation, anchored. Its
// letters are lower case, as with CaseSensitive false; the bracketed form a
// case-sensitive device gets matches everything this does and more, so a
// probe this refuses, that refuses too.
const junosAbbrevDeny = `^( *show +version *(\\|.*)?| *show +interfaces +terse *(\\|.*)?| *show +system +uptime *(\\|.*)?|` +
	` *show +route +summary *(\\|.*)?| *show +chassis +hardware *(\\|.*)?)$`

// junosAbbrevProbe is one abbreviation of the denied command of, and whether
// the CLI may find it ambiguous, in which case the control need not run it.
// An odd probe is one the CLI may refuse outright in the control, which is
// recorded, not failed: where the control runs it, the deny must not.
//
// A probe with uncounted set is typed and recorded, and counts neither way
// (the lead's ruling of 2026-09-25): its control cannot run it on some image,
// so its cell is not isolated there, and it is replaced by a probe of the same
// shape that every image's control runs.
type junosAbbrevProbe struct {
	cmd, of   string
	ambiguous bool
	odd       bool
	uncounted string
}

// junosAbbrevEvidence is what each denied command's own output holds. A
// probe ran only where its output holds it (the lead's ruling of 2026-09-25):
// `| count` over an error prints "Count: 1 lines", which is not the command
// running. A `| count` probe is read by its count instead (countCell).
var junosAbbrevEvidence = map[string]string{
	"show version":          "Junos:",
	"show interfaces terse": "Admin Link Proto",
	"show system uptime":    "System booted",
	"show route summary":    "destinations,",
	"show chassis hardware": "Hardware inventory",
}

// junosAbbrevRefusal are the answers of a CLI refusing the command typed. An
// answer that is neither this nor the command's output, but a device error,
// is "not run": the command did not execute, but the deny did not refuse it
// either (`error: device ter not found`, where the deny hid `terse` from
// completion and `ter` resolved as an interface name). An answer that is none
// of these is not observed.
var junosAbbrevRefusal = []string{"permission denied", "not allowed", "unknown command", "syntax error",
	"missing argument"}

var junosAbbrevProbes = []junosAbbrevProbe{
	{cmd: "show version", of: "show version"}, {cmd: "show version | no-more", of: "show version"},
	{cmd: "sh ver", of: "show version"}, {cmd: "sho vers", of: "show version"}, {cmd: "show versi", of: "show version"},
	{cmd: "sh ver | no-more", of: "show version"},
	{cmd: "show interfaces terse", of: "show interfaces terse"}, {cmd: "sh int ter", of: "show interfaces terse"},
	{cmd: "sh interfaces te", of: "show interfaces terse"}, {cmd: "show int terse", of: "show interfaces terse"},
	{cmd: "sh int ter | count", of: "show interfaces terse"},
	{cmd: "show system uptime", of: "show system uptime"}, {cmd: "sh sys upt", of: "show system uptime"},
	{cmd: "sh system up", of: "show system uptime"}, {cmd: "show sy uptime", of: "show system uptime"},
	{cmd: "show route summary", of: "show route summary"},
	{cmd: "sh rou sum", of: "show route summary",
		uncounted: "control not run — ambiguous on vSRX (completes to `rout`)"},
	// sh rou sum's replacement: `route` is whole, and `sum` completes uniquely
	// after it on both images (L26-keywords-juniper_*.yaml).
	{cmd: "sh route sum", of: "show route summary"},
	{cmd: "sh route summ", of: "show route summary"},
	{cmd: "show chassis hardware", of: "show chassis hardware"}, {cmd: "sh chas hard", of: "show chassis hardware"},
	{cmd: "sh chassis hardw", of: "show chassis hardware"},
	// `i` is ambiguous after `show` (interfaces, igmp, ike, ...).
	{cmd: "sh i terse", of: "show interfaces terse", ambiguous: true},
	// The Task 7 review's: a lookalike letter (U+017F, which case-folds to
	// `s`), and a denied command padded with spaces, no pipe.
	{cmd: "ſhow version", of: "show version", odd: true}, {cmd: "   show version", of: "show version", odd: true},
	{cmd: "show version   ", of: "show version", odd: true}, {cmd: "   sh int ter   ", of: "show interfaces terse", odd: true},
}

var junosCountLine = regexp.MustCompile(`Count: (\d+) lines`)

// abbrevCell is a probe's outcome in one session: ambiguous, ran (the denied
// command's own output), refused (the CLI's refusal), not run (a device
// error), or not observed (none of these).
func abbrevCell(out, evidence string) string {
	switch {
	case strings.Contains(out, "ambiguous"):
		return "ambiguous"
	case evidence != "" && strings.Contains(out, evidence):
		return "ran"
	case containsAny(strings.ToLower(out), junosAbbrevRefusal):
		return "refused"
	case strings.Contains(out, "error:"):
		return "not run"
	}
	return "not observed"
}

// countCell is a `| count` probe's outcome against want, the lines the
// denied command's own output holds: the control session's uncounted run of it
// (commandLines). A count of exactly want, more than one, is the command
// running, in either session; a count of one line or none is an error's, not
// the command running; any other count is not observed, since then the pipe
// did not count the command's output (review R2).
func countCell(out string, want int) string {
	if strings.Contains(out, "ambiguous") {
		return "ambiguous"
	}
	m := junosCountLine.FindStringSubmatch(out)
	if m == nil {
		return abbrevCell(out, "")
	}
	n, _ := strconv.Atoi(m[1])
	switch {
	case n <= 1:
		return "not run"
	case want > 1 && n == want:
		return "ran"
	}
	return "not observed"
}

var junosPromptLine = regexp.MustCompile(`@\S+> ?$`)

// commandLines is the lines a command's output holds as `| count` counts
// them: not blank, and not the prompt that follows it.
func commandLines(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" && !junosPromptLine.MatchString(line) {
			n++
		}
	}
	return n
}

// abbrevCells is a probe's cell in the control and under the deny. plain is
// the control's output of the full command p abbreviates, which a `| count`
// probe's count is held to.
func abbrevCells(p junosAbbrevProbe, control, deny, plain string) (string, string) {
	if !strings.Contains(p.cmd, "| count") {
		ev := junosAbbrevEvidence[p.of]
		return abbrevCell(control, ev), abbrevCell(deny, ev)
	}
	want := 0
	if abbrevCell(plain, junosAbbrevEvidence[p.of]) == "ran" {
		want = commandLines(plain)
	}
	return countCell(control, want), countCell(deny, want)
}

// junosAbbrevFull are the full forms, plain and piped, whose cells say whether
// the rendered deny shape is enforced at all.
var junosAbbrevFull = map[string]bool{"show version": true, "show version | no-more": true,
	"show interfaces terse": true, "show system uptime": true, "show route summary": true,
	"show chassis hardware": true}

// abbrevVerdict reads the note's two facts off every probe's cells (control,
// deny): the rendered shape is enforced where every full form ran in the
// control and was refused under the deny; DenyMatchesExpanded holds where it
// is enforced, nothing is not observed, the control ran every counted probe
// but the ambiguous and the odd, and nothing counted ran under the deny.
func abbrevVerdict(cells map[string][2]string) (enforced, expanded bool) {
	enforced, expanded = true, true
	for _, p := range junosAbbrevProbes {
		cc, dc := cells[p.cmd][0], cells[p.cmd][1]
		if cc == "not observed" || dc == "not observed" {
			expanded = false
		}
		if p.uncounted != "" {
			continue
		}
		if junosAbbrevFull[p.cmd] {
			enforced = enforced && cc == "ran" && dc == "refused"
		}
		if (cc != "ran" && cc != "ambiguous" && !p.odd) || dc == "ran" {
			expanded = false
		}
	}
	return enforced, expanded && enforced
}

// expansion is the command line the CLI echoed as it expanded an
// abbreviation: the output's first line that is not blank, the bells a
// rejected keystroke rings trimmed off.
func expansion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimFunc(line, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }); line != "" {
			return line
		}
	}
	return ""
}

func TestL9JunosAbbreviations(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L9-abbreviations")
		defer stop()
		commit := l.junosConfigureAdmin(t, junosAbbrevClass)
		defer l.junosConfigureAdmin(t, junosAbbrevDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		probes := make([]junosProbe, len(junosAbbrevProbes))
		for i, p := range junosAbbrevProbes {
			probes[i] = junosProbe{cmd: p.cmd}
		}
		control := l.junosSession(t, "control", `["local-user-name=p49-l9-all"]`, probes)
		deny := l.junosSession(t, "deny", `["local-user-name=p49-l9-all", "deny-commands=`+junosAbbrevDeny+`"]`, probes)
		for _, r := range []junosRun{control, deny} {
			if r.loginErr != "" {
				t.Fatalf("%s: the session did not open, so nothing was measured: %s", r.name, r.loginErr)
			}
			if len(r.unobserved) > 0 {
				t.Fatalf("%s: not observed: %v", r.name, r.unobserved)
			}
		}
		cells := map[string][2]string{}
		for _, p := range junosAbbrevProbes {
			cc, dc := abbrevCells(p, control.outs[p.cmd], deny.outs[p.cmd], control.outs[p.of])
			cells[p.cmd] = [2]string{cc, dc}
		}
		enforced, expanded := abbrevVerdict(cells)
		var b strings.Builder
		fmt.Fprintf(&b, "The class was committed: %s.\n\n```\n%s\n```\n\nThe deny: `deny-commands=%s`.\n\n",
			commitWord(commit), strings.Join(junosAbbrevClass, "\n"), tableCell(junosAbbrevDeny))
		b.WriteString("A probe ran only where its output holds the denied command's own output (for `| count`, " +
			"the lines the control's own run of the command held, more than one); `refused` is the CLI's refusal; " +
			"`not run` is a device error, so the command did not execute, and the deny did not refuse it either; " +
			"anything else is not observed and fails the test. A `not run` cell marked not isolated as an " +
			"abbreviation still counts toward the fact (the lead's ruling of 2026-09-25): the denied command did " +
			"not execute; leaving them out would not change the verdict, since a `not run` cell never makes it " +
			"false.\n\n")
		b.WriteString("| probe | control | under the deny | expanded, control / deny |\n|---|---|---|---|\n")
		for _, p := range junosAbbrevProbes {
			cc, dc := cells[p.cmd][0], cells[p.cmd][1]
			if cc == "not observed" || dc == "not observed" {
				t.Errorf("%q: not observed (control %s, deny %s): %s / %s", p.cmd, cc, dc,
					oneLine(control.outs[p.cmd]), oneLine(deny.outs[p.cmd]))
			}
			if p.uncounted != "" {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", tableCell(fmt.Sprintf("%q", p.cmd)), cc,
					tableCell("not counted: "+p.uncounted+" (here: "+dc+")"),
					tableCell(fmt.Sprintf("`%s` / `%s`", expansion(control.outs[p.cmd]), expansion(deny.outs[p.cmd]))))
				continue
			}
			// The control's own answer says which abbreviation is ambiguous on
			// this image; one it did not run for any other reason measures nothing.
			if cc != "ran" && cc != "ambiguous" && !p.odd {
				t.Errorf("the control did not run %q, so the deny's cell measures nothing: %s", p.cmd,
					oneLine(control.outs[p.cmd]))
			}
			if p.ambiguous && cc != "ambiguous" {
				t.Logf("%q was expected ambiguous and was not on this image", p.cmd)
			}
			cell := dc
			// A deny cell whose control did not run the probe isolates nothing;
			// nor does one not run because the device expanded it otherwise
			// under the deny, where the deny hid a keyword from completion and
			// the abbreviation resolved as an argument. A refused cell's echo
			// stops where the CLI refused it, and says nothing of this.
			ce, de := expansion(control.outs[p.cmd]), expansion(deny.outs[p.cmd])
			switch {
			case cc != "ran":
				cell = "not isolated (" + dc + ")"
			case dc == "not run" && strings.HasPrefix(ce, "show ") && de != ce:
				cell = fmt.Sprintf("%s; not isolated as an abbreviation of `%s`: it expanded otherwise under the deny", dc, p.of)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", tableCell(fmt.Sprintf("%q", p.cmd)), cc, tableCell(cell),
				tableCell(fmt.Sprintf("`%s` / `%s`", ce, de)))
		}
		fmt.Fprintf(&b, "\n### Read off the table\n\n- the rendered deny shape (` *... *(\\|.*)?`) enforced: %v: every "+
			"full form, plain and piped, refused under it and run by the control\n", enforced)
		fmt.Fprintf(&b, "- JunosFacts.DenyMatchesExpanded (keywords) = %v: true only where the shape is enforced, no "+
			"probe ran under the deny (each refused or not run) and the control ran every unambiguous one; set "+
			"1.1.0 takes true only where both images say true\n", expanded)
		b.WriteString("- A keyword the deny hides from completion changes how an abbreviation resolves: under the " +
			"deny an abbreviation of it may resolve as an argument instead (a probe marked \"expanded otherwise\").\n")
		b.WriteString("- `ſhow version` shows that the CLI refuses a non-ASCII keystroke (it rings the bell, drops " +
			"`ſ` and reads `how`), not whether `ſ` case-folds to `s` in a deny: the control refuses it too, so " +
			"its deny cell isolates nothing.\n")
		for _, r := range []junosRun{control, deny} {
			fmt.Fprintf(&b, "\n### %s\n\nReply `%s`. `show cli authorization`:\n\n```\n%s\n```\n", r.name, r.attrs, r.auth)
			for _, p := range junosAbbrevProbes {
				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", p.cmd, orEmpty([]string{r.outs[p.cmd]}, 0))
			}
		}
		l.result(t, "L9-abbreviations", "Whether a keyword deny-commands refuses its command however the keywords "+
			"are abbreviated, at several lengths and depths, piped, and ambiguous at one level: "+
			"JunosFacts.DenyMatchesExpanded for keywords (spec §15 L9; decision 27).", b.String())
	})
}
