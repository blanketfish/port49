package projection

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/engine"
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
}

var bruteRules = []string{
	"show version", "show route *", "show interfaces **", "**", "show *",
	"show interfaces @management", "show interfaces @uplink **", "show interfaces @spaced",
	"show interfaces /^ge-/", "show interfaces /ge-/", "show interfaces /^(fxp|em)[0-9]$/",
	"show interfaces /^x?$/", "show interfaces /^.e-.*$/", "show interfaces /^[a-c]+$/",
	"show interfaces @exact", "show interfaces /(?-i)^Ge-/",
}

// The alphabet holds each shape a term reads differently: case, a run of
// spaces inside a quoted argument, a brace, a pipe stage, and each class's
// members and near-misses.
var bruteAlphabet = []string{"show", "SHOW", "interfaces", "version", "route", "ge-0/0/0", "GE-0/0/0",
	"fxp0", "em0", "ae1", "et-0/0/2", "et-0/0/9", "x", "a b", "A", "a", "|", "no-more"}

// For every command the engine denies under a deny rule, the deny's ERE
// matches the line in every spelling the device may be handed: one space or
// two between words, a quoted argument quoted, and a
// pipeline after it. For every line an allow's ERE matches, the engine
// permits it under the allow. Both on a case-sensitive device, and the allow
// also on a case-insensitive one.
func TestEREAgreesWithTheEngineOnEveryCommand(t *testing.T) {
	cmds := vectors(bruteAlphabet, 4)
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
				for _, v := range cmds {
					if deny {
						if !matches(p, verdict, v) {
							continue
						}
						quoted := make([]string, len(v))
						for i, w := range v {
							quoted[i] = w
							if strings.Contains(w, " ") {
								quoted[i] = `"` + w + `"`
							}
						}
						for _, line := range []string{strings.Join(quoted, " "), strings.Join(quoted, "  "),
							strings.Join(quoted, " ") + " | no-more",
							strings.Join(quoted, " ") + "|count"} {
							if !device(line) {
								t.Errorf("deny %s (%+v): the engine denies %q; the ERE %q misses %q", rule, f, v, e, line)
							}
						}
						continue
					}
					if strings.Contains(strings.Join(v, ""), " ") || v[0] == "|" || v[len(v)-1] == "|" {
						// A quoted argument is the deny side's; a line that
						// opens or ends on a lone pipe is no command.
						continue
					}
					line := strings.Join(v, " ")
					if device(line) && !matches(p, verdict, strings.Fields(line)) {
						t.Errorf("allow %s (%+v): the ERE %q matches %q; the engine does not permit it", rule, f, e, line)
					}
				}
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
	if got, err := ruleERE("show /(?-i)^Ge-/", nil, false, Facts{CaseSensitive: true}); err != nil || got != "show (Ge-)[^ ]*" {
		t.Errorf("case-sensitive device: %q %v", got, err)
	}
}
