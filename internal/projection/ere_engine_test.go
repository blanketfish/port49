package projection

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/engine"
)

// program is rule alone in a blob on a session-only platform.
func program(t *testing.T, verdict, rule string, classes map[string][]string) *engine.Program {
	t.Helper()
	p, err := engine.Compile(engine.Blob{Version: engine.Version, Bundle: "b", Platform: "juniper_junos",
		Normalize: engine.Normalize{PipeToken: "|", SessionOnly: true},
		Rules:     []engine.Rule{{Verdict: verdict, Rule: rule, Role: "r"}}, Classes: classes})
	if err != nil {
		t.Fatalf("%s %s: %v", verdict, rule, err)
	}
	return p
}

// matches reports whether p's one rule matches the command vector as the
// engine's own matcher reads it.
func matches(p *engine.Program, verdict string, vector []string) bool {
	raw := []string{"cmd=" + vector[0]}
	for _, a := range vector[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	o := p.Command(raw)
	if verdict == engine.Deny {
		return len(o.Denies) > 0
	}
	return len(o.Permits) > 0
}

// vectors is every command of 1 to n words over alphabet.
func vectors(alphabet []string, n int) [][]string {
	var out, level [][]string
	level = [][]string{{}}
	for k := 0; k < n; k++ {
		var next [][]string
		for _, v := range level {
			for _, w := range alphabet {
				next = append(next, append(append([]string{}, v...), w))
			}
		}
		out, level = append(out, next...), next
	}
	return out
}

var bruteClasses = map[string][]string{
	"management": {"^(fxp0|em0)$"},
	"uplink":     {"^et-0/0/[0-3]$", "^ae1$"},
	"spaced":     {"^[a-z ]+$"},
	"exact":      {"(?-i)^[A{]$"},
	"ifalt":      {"^(?:ge|xe)-0$"},
}

var bruteRules = []string{
	"show version", "show route *", "show interfaces **", "**", "show *",
	"show interfaces @management", "show interfaces @uplink **", "show interfaces @spaced",
	"show interfaces /^ge-/", "show interfaces /ge-/", "show interfaces /^(fxp|em)[0-9]$/",
	"show interfaces /^x?$/", "show interfaces /^.e-.*$/", "show interfaces /^[a-c]+$/",
	"show interfaces @exact", "show interfaces /(?-i)^Ge-/", "show interfaces @ifalt",
	"show /^(?:ab|cd)x$/", "show interfaces /^(?:ge|xe|et)-.$/", "show /(?:ab|cd)+/",
}

// The alphabet holds each shape a term reads differently: case, a run of
// spaces inside a quoted argument, a tab, the empty argument, a pipe stage,
// and each class's and pattern's members and near-misses.
var bruteAlphabet = []string{"show", "SHOW", "interfaces", "version", "route", "ge-0/0/0", "GE-0/0/0",
	"fxp0", "em0", "ae1", "et-0/0/2", "et-0/0/9", "x", "a b", "A", "a", "|", "no-more",
	"ge-0", "xe-0", "ab", "abx", "cdx", "x\ty", "", "|v", "v|"}

// commands is every command of up to three words over bruteAlphabet, and of
// four where the first two are `show interfaces`: no rule has more than
// three terms before a `**`.
func commands() [][]string {
	cmds := vectors(bruteAlphabet, 3)
	for _, v := range vectors(bruteAlphabet, 2) {
		cmds = append(cmds, append([]string{"show", "interfaces"}, v...))
	}
	return cmds
}

// For every command the engine denies under a deny rule, the deny's ERE
// matches the line in every spelling the device may be handed: one space or
// two between words, a space before or after it, a quoted argument quoted,
// and a pipeline after it. For every line an allow's ERE matches, the engine
// permits it under the allow, read as typed and split at white space; a line
// that opens on a lone pipe is no command, and no allow matches it. Each on
// a case-sensitive and a case-insensitive device.
func TestEREAgreesWithTheEngineOnEveryCommand(t *testing.T) {
	cmds := commands()
	for _, rule := range bruteRules {
		for _, deny := range []bool{true, false} {
			verdict := engine.Permit
			if deny {
				verdict = engine.Deny
			}
			for _, f := range []Facts{{CaseSensitive: true}, {CaseSensitive: false}} {
				e, err := ruleERE(rule, bruteClasses, deny, f)
				if errors.Is(err, errUnwritable) {
					continue // refused: nothing reaches the device
				}
				if err != nil {
					t.Fatalf("%s %s: %v", verdict, rule, err)
				}
				p := program(t, verdict, rule, bruteClasses)
				// The device matches the whole line, ignoring case unless f
				// says it does not.
				anchored := "^(" + e + ")$"
				if !f.CaseSensitive {
					anchored = "(?i)" + anchored
				}
				device := regexp.MustCompile(anchored).MatchString
				patterned := strings.ContainsAny(rule, "/@")
				for _, v := range cmds {
					if deny {
						if !matches(p, verdict, v) || (patterned && slices.Contains(v, "")) {
							// An empty argument is typed `""`, and a pattern
							// anchored at both ends reads the quotes outside
							// its anchors: moot under decision 27, which
							// sends no argument deny (task 7 review, minor 7).
							continue
						}
						quoted := make([]string, len(v))
						for i, w := range v {
							quoted[i] = w
							if w == "" || strings.Contains(w, " ") {
								quoted[i] = `"` + w + `"`
							}
						}
						for _, line := range []string{strings.Join(quoted, " "), strings.Join(quoted, "  "),
							strings.Join(quoted, " ") + " | no-more",
							strings.Join(quoted, " ") + "|count", " " + strings.Join(quoted, " "),
							strings.Join(quoted, " ") + " "} {
							if !device(line) {
								t.Errorf("deny %s (%+v): the engine denies %q; the ERE %q misses %q", rule, f, v, e, line)
							}
						}
						continue
					}
					line := strings.Join(v, " ")
					if !device(line) {
						continue
					}
					// The engine must permit the line read either way: as
					// typed, a tab or an empty argument inside a word, and
					// split at every run of white space.
					if fields := strings.Fields(line); len(fields) == 0 || fields[0] == "|" {
						t.Errorf("allow %s (%+v): the ERE %q matches %q, which is no command", rule, f, e, line)
					} else if !matches(p, verdict, v) || !matches(p, verdict, fields) {
						t.Errorf("allow %s (%+v): the ERE %q matches %q; the engine does not permit it", rule, f, e, line)
					}
				}
			}
		}
	}
}

// No allow's argument holds a `|`, at its start, end or inside: a device that
// splits a pipeline off without a space would read a stage there (Task 7
// review, parked).
func TestAnAllowArgumentNeverHoldsAPipe(t *testing.T) {
	for _, rule := range []string{"show route *", "show *", "show interfaces /^ge-/", "show interfaces /ge-/",
		"show interfaces /^.e-.*$/"} {
		e, err := ruleERE(rule, bruteClasses, false, Facts{CaseSensitive: true})
		if err != nil {
			t.Fatalf("%s: %v", rule, err)
		}
		device := regexp.MustCompile("^(" + e + ")$").MatchString
		for _, line := range []string{"show route |v", "show route v|", "show route a|b", "show |", "show |v",
			"show interfaces ge-|", "show interfaces ge-0|", "show interfaces |ge-0"} {
			if device(line) {
				t.Errorf("allow %s: the ERE %q matches %q", rule, e, line)
			}
		}
	}
}

// A case-sensitive pattern in an allow is written in the case it holds, and
// refused where the device ignores case, which would read it wider.
func TestACaseSensitiveAllowIsNeverWidened(t *testing.T) {
	classes := map[string][]string{"exact": {"(?-i)^[A{]$"}}
	if got, err := ruleERE("show @exact", classes, false, Facts{CaseSensitive: true}); err != nil || got != "show (A)" {
		t.Errorf("one-rune class: %q %v", got, err)
	}
	for _, rule := range []string{"show @exact", "show /(?-i)^Ge-/"} {
		if _, err := ruleERE(rule, classes, false, Facts{}); !errors.Is(err, errUnwritable) {
			t.Errorf("%s on a case-insensitive device: %v", rule, err)
		}
	}
	if got, err := ruleERE("show /(?-i)^Ge-/", nil, false, Facts{CaseSensitive: true}); err != nil || got != "show (Ge-)[!#-z~]*" {
		t.Errorf("case-sensitive device: %q %v", got, err)
	}
}

// An alternation inside a concatenation keeps its group: RE2 drops a
// `(?:…)`, and `ge|xe-0` would read as `ge` or `xe-0`.
func TestAnAlternationKeepsItsGroup(t *testing.T) {
	classes := map[string][]string{"ifalt": {"^(?:ge|xe)-0$"}}
	e, err := ruleERE("show interfaces @ifalt", classes, true, Facts{CaseSensitive: true})
	if err != nil || !regexp.MustCompile("^("+e+")$").MatchString("show interfaces ge-0") {
		t.Errorf("deny %q %v misses show interfaces ge-0", e, err)
	}
	e, err = ruleERE("show /^(?:ab|cd)x$/", nil, false, Facts{CaseSensitive: true})
	if err != nil || regexp.MustCompile("^("+e+")$").MatchString("show ab") {
		t.Errorf("allow %q %v permits show ab", e, err)
	}
}

// A repeat is written out up to 8, and refused past it.
func TestARepeatPast8IsRefused(t *testing.T) {
	for _, rule := range []string{"show /^x{9}$/", "show /^x{0,9}$/", "show /^x{9,}$/", "show /^(x{2}){9}$/"} {
		if _, err := ruleERE(rule, nil, false, Facts{}); !errors.Is(err, errUnwritable) {
			t.Errorf("%s: %v", rule, err)
		}
	}
	if got, err := ruleERE("show /^x{2,3}$/", nil, false, Facts{}); err != nil ||
		!regexp.MustCompile("^("+got+")$").MatchString("show xxx") || regexp.MustCompile("^("+got+")$").MatchString("show xxxx") {
		t.Errorf("x{2,3}: %q %v", got, err)
	}
}

// A `]` outside a bracket is written bare, which POSIX ERE defines, and a
// deny tolerates a space before and after the command.
func TestBareBracketAndSpacedDeny(t *testing.T) {
	if got, err := ruleERE("show a]b", nil, false, Facts{}); err != nil || got != "show a]b" {
		t.Errorf("]: %q %v", got, err)
	}
	e, err := ruleERE("clear bgp all", nil, true, Facts{CaseSensitive: true})
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile("^(" + e + ")$")
	for _, line := range []string{" clear bgp all", "clear bgp all ", "clear bgp all  | no-more"} {
		if !re.MatchString(line) {
			t.Errorf("%q misses %q", e, line)
		}
	}
}
