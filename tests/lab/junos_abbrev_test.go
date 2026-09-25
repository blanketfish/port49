//go:build lab

package lab

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
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
// running. A `| count` probe's evidence is the control's own count line.
var junosAbbrevEvidence = map[string]string{
	"show version":          "Junos:",
	"show interfaces terse": "Admin Link Proto",
	"show system uptime":    "System booted",
	"show route summary":    "destinations,",
	"show chassis hardware": "Hardware inventory",
}

// junosAbbrevRefusal are the answers of a CLI refusing the command typed. An
// answer that is neither this nor the command's output is "not run": the
// command did not execute, but the deny did not refuse it either
// (`error: device ter not found`, where the deny hid `terse` from completion
// and `ter` resolved as an interface name).
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
// command's own output), refused (the CLI's refusal), or not run.
func abbrevCell(out, evidence string) string {
	switch {
	case strings.Contains(out, "ambiguous"):
		return "ambiguous"
	case evidence != "" && strings.Contains(out, evidence):
		return "ran"
	case containsAny(strings.ToLower(out), junosAbbrevRefusal):
		return "refused"
	}
	return "not run"
}

// expansion is the command line the CLI echoed as it expanded an
// abbreviation: the output's first line that is not blank.
func expansion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
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
		evidence := func(p junosAbbrevProbe) string {
			if !strings.Contains(p.cmd, "| count") {
				return junosAbbrevEvidence[p.of]
			}
			// The control's count of the command's lines; one line is an
			// error's, and proves nothing.
			if m := junosCountLine.FindStringSubmatch(control.outs[p.cmd]); m != nil && m[1] != "1" && m[1] != "0" {
				return m[0]
			}
			return ""
		}
		// The rendered shape is enforced where every full form, plain and
		// piped, is run by the control and refused by the CLI under the deny.
		full := map[string]bool{"show version": true, "show version | no-more": true, "show interfaces terse": true,
			"show system uptime": true, "show route summary": true, "show chassis hardware": true}
		enforced := true
		expanded := true
		var b strings.Builder
		fmt.Fprintf(&b, "The class was committed: %s.\n\n```\n%s\n```\n\nThe deny: `deny-commands=%s`.\n\n",
			commitWord(commit), strings.Join(junosAbbrevClass, "\n"), tableCell(junosAbbrevDeny))
		b.WriteString("A probe ran only where its output holds the denied command's own output; `refused` is the " +
			"CLI's refusal; `not run` is neither, so the command did not execute, and the deny did not refuse it " +
			"either.\n\n")
		b.WriteString("| probe | control | under the deny | expanded, control / deny |\n|---|---|---|---|\n")
		for _, p := range junosAbbrevProbes {
			ev := evidence(p)
			cc := abbrevCell(control.outs[p.cmd], ev)
			dc := abbrevCell(deny.outs[p.cmd], ev)
			if p.uncounted != "" {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", tableCell(fmt.Sprintf("%q", p.cmd)), cc,
					tableCell("not counted: "+p.uncounted+" (here: "+dc+")"),
					tableCell(fmt.Sprintf("`%s` / `%s`", expansion(control.outs[p.cmd]), expansion(deny.outs[p.cmd]))))
				continue
			}
			if full[p.cmd] {
				enforced = enforced && cc == "ran" && dc == "refused"
			}
			// The control's own answer says which abbreviation is ambiguous on
			// this image; one it did not run for any other reason measures nothing.
			if cc != "ran" && cc != "ambiguous" && !p.odd {
				t.Errorf("the control did not run %q, so the deny's cell measures nothing: %s", p.cmd,
					oneLine(control.outs[p.cmd]))
				expanded = false
			}
			if p.ambiguous && cc != "ambiguous" {
				t.Logf("%q was expected ambiguous and was not on this image", p.cmd)
			}
			if dc == "ran" {
				expanded = false
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
		expanded = expanded && enforced
		fmt.Fprintf(&b, "\n### Read off the table\n\n- the rendered deny shape (` *... *(\\|.*)?`) enforced: %v: every "+
			"full form, plain and piped, refused under it and run by the control\n", enforced)
		fmt.Fprintf(&b, "- JunosFacts.DenyMatchesExpanded (keywords) = %v: true only where the shape is enforced, no "+
			"probe ran under the deny (each refused or not run) and the control ran every unambiguous one; set "+
			"1.1.0 takes true only where both images say true\n", expanded)
		b.WriteString("- A keyword the deny hides from completion changes how an abbreviation resolves: under the " +
			"deny an abbreviation of it may resolve as an argument instead (a probe marked \"expanded otherwise\").\n")
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
