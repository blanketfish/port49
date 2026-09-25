package engine

import (
	"slices"
	"testing"
)

func TestContains(t *testing.T) {
	classes := map[string][]string{"management": {"^(fxp0|em0)$"}}
	for _, c := range []struct {
		outer, inner string
		want         bool
	}{
		{"show **", "show configuration **", true},
		{"show **", "show", true},
		{"show configuration **", "show **", false},
		{"show *", "show version", true},
		{"show *", "show version detail", false},
		{"show version", "SHOW VERSION", true},
		{"**", "request system reboot", true},
		{"show interfaces @management", "show interfaces fxp0", true},
		{"show interfaces @management", "show interfaces ge-0/0/0", false},
		{"show interfaces @management", "show interfaces *", false},
		{"show interfaces @management", "show interfaces @management", true},
		{"show interfaces /^fxp/", "show interfaces /^fxp0$/", false},
		{"show interfaces *", "show interfaces @management", true},
		{"show version", "show version **", false},
		{"show version **", "show version", true},
	} {
		got, err := Contains(c.outer, c.inner, classes)
		if err != nil || got != c.want {
			t.Errorf("Contains(%q, %q) = %v, %v; want %v", c.outer, c.inner, got, err, c.want)
		}
	}
}

func TestMayMeetAndAlwaysDominates(t *testing.T) {
	junos := Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}
	for _, c := range []struct {
		permit, deny string
		meet, dom    bool
	}{
		// The spec's capability shape: a permit beneath a deny wins there.
		{"show configuration interfaces **", "show configuration **", true, true},
		// The refused shape: a deny beneath the permit.
		{"show interfaces **", "show interfaces terse", true, false},
		{"show version", "request system reboot", false, true},
		// Incomparable: neither is more specific at every position.
		{"show * detail", "show interfaces *", true, false},
		// Two patterns meeting at one position: possible, never definite.
		{"show interfaces /^ge-/", "show interfaces /-0$/", true, false},
	} {
		meet, err := MayMeet(c.permit, c.deny, nil, junos)
		if err != nil || meet != c.meet {
			t.Errorf("MayMeet(%q, %q) = %v, %v; want %v", c.permit, c.deny, meet, err, c.meet)
		}
		dom, err := AlwaysDominates(c.permit, c.deny, nil, junos)
		if err != nil || dom != c.dom {
			t.Errorf("AlwaysDominates(%q, %q) = %v, %v; want %v", c.permit, c.deny, dom, err, c.dom)
		}
	}
}

// A word takes every case-fold of itself, so a pattern holds it only where it
// takes every one: `(?-i)` takes `fxp0` and not `FXP0`, and `\b` sees a word
// boundary before `k` and none before the Kelvin sign `K` (U+212A), which
// folds to it.
func TestContainsReadsEveryCaseFold(t *testing.T) {
	for _, c := range []struct {
		outer, inner string
		want         bool
	}{
		{"show interfaces /(?-i)^fxp0$/", "show interfaces fxp0", false},
		{`show /\bk$/`, "show k", false},
		{"show interfaces /^FXP0$/", "show interfaces fxp0", true},
		{"show interfaces /(?-i)^[0-9]+$/", "show interfaces 10", true},
	} {
		got, err := Contains(c.outer, c.inner, nil)
		if err != nil || got != c.want {
			t.Errorf("Contains(%q, %q) = %v, %v; want %v", c.outer, c.inner, got, err, c.want)
		}
	}
}

// Each case carries a command the engine denies with both rules matching it:
// a witness MayMeet must see and AlwaysDominates must not deny. A deny takes a
// word in every case and with whitespace around it (compiled.match), and a
// permit pattern need not.
func TestMayMeetSeesWhatADenyTakes(t *testing.T) {
	junos := Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}
	iosxe := Normalize{PipeToken: "|", StripCR: true, SplitsInterfaceNames: true}
	for _, c := range []struct {
		permit, deny string
		n            Normalize
		witness      []string
	}{
		{"show /(?-i)^VERSION$/", "show version", junos, []string{"show", "VERSION"}},
		{`request system /^reboot\s$/`, "request system reboot", junos, []string{"request", "system", "reboot "}},
		{`request system /^\sreb$/`, "request system reboot", iosxe, []string{"request", "system", " reb"}},
		{"show interfaces /(?-i)^GIGABITETHERNET$/ 1", "show interfaces GigabitEthernet1", iosxe,
			[]string{"show", "interfaces", "GIGABITETHERNET", "1"}},
		// A split name's head may be only whitespace: it trims to nothing,
		// and the index alone is the deny's word.
		{"show interfaces * 1/0", "show interfaces 1/0", iosxe, []string{"show", "interfaces", " ", "1/0"}},
	} {
		p := compileBlob(t, Blob{Version: Version, Bundle: "b", Platform: "p", Normalize: c.n,
			Rules: []Rule{{Verdict: Permit, Rule: c.permit, Role: "a"}, {Verdict: Deny, Rule: c.deny, Role: "a"}}})
		if o := p.Command(rawOf(c.witness)); o.Permit || len(o.Permits) == 0 || len(o.Denies) == 0 {
			t.Fatalf("%q is not a witness for %q against %q: %+v", c.witness, c.permit, c.deny, o)
		}
		if meet, err := MayMeet(c.permit, c.deny, nil, c.n); err != nil || !meet {
			t.Errorf("MayMeet(%q, %q) = %v, %v; %q matches both", c.permit, c.deny, meet, err, c.witness)
		}
		if dom, err := AlwaysDominates(c.permit, c.deny, nil, c.n); err != nil || dom {
			t.Errorf("AlwaysDominates(%q, %q) = %v, %v; the deny wins %q", c.permit, c.deny, dom, err, c.witness)
		}
	}
}

// A deny pattern that turns case folding off still meets the permit's word in
// the case it takes; the permit, a word, dominates it there.
func TestMayMeetReadsADenyPatternOnEveryCase(t *testing.T) {
	junos := Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}
	if meet, err := MayMeet("show fxp0", "show /(?-i)^FXP0$/", nil, junos); err != nil || !meet {
		t.Errorf("MayMeet = %v, %v; `show FXP0` matches both", meet, err)
	}
}

// Reading a pattern as everything it takes keeps a clear miss a miss: `^ge-`
// takes nothing that trims to `fxp0`, whatever follows it.
func TestMayMeetStaysPrecise(t *testing.T) {
	junos := Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}
	for _, c := range [][2]string{
		{"show interfaces /^ge-/", "show interfaces fxp0"},
		{"show interfaces /^(ge|xe)-.*$/", "show interfaces fxp0"},
	} {
		if meet, err := MayMeet(c[0], c[1], nil, junos); err != nil || meet {
			t.Errorf("MayMeet(%q, %q) = %v, %v; want false", c[0], c[1], meet, err)
		}
	}
}

// Every answer is checked against the matcher over every short vector of
// words chosen to reach the edges: case-folds (the Kelvin sign folds to `k`,
// `ſ` to `s`), padding a deny trims (tab, newline, NBSP, U+3000), the empty
// argument, U+FFFD and a byte that is not UTF-8, abbreviations and split
// names. A vector matching both rules is a meet MayMeet must see; one where
// the permit does not dominate a matching deny refutes AlwaysDominates; one
// the inner rule matches and the outer does not refutes Contains. The narrow
// set is read to three words and the wide set, which adds the harder
// patterns and words, to two, to keep the run short.
//
// Soundness alone would pass an engine that never proves anything, so each
// set must also give every answer that licenses something: a Contains that is
// true of two different rules, a MayMeet that is false, and an
// AlwaysDominates that is true of rules that do meet.
func TestContainAgreesWithTheMatcher(t *testing.T) {
	narrowRules := []string{"**", "show **", "show *", "show * *", "sh **", "show version",
		"show /(?-i)^VERSION$/", `show /^\bk$/`, "show k", "show /^sh/", `show /^\s/`, "show /^fxp0$/",
		"show fxp0", "show @management", "* 1/0", "show gi1", "show /(?-i)^gi$/ 1", "show /(?-i)^GI$/ 1",
		"show /(?-i)^GI1$/", `show /^k\s$/`, "show 1/0", "show * 1/0"}
	narrowWords := []string{"show", "SHOW", "sh", "VERSION", "version", "show ", "k", "\u212a", "fxp0",
		"FXP0", " ", "1/0", "1", "gi", "GI", "Gi1", "k "}
	wideRules := append(slices.Clone(narrowRules), `show /^\Qfxp0/`, "show /^(ver|VER)(sion)?$/",
		"show /^.{2,}$/", "show /(?m)^k$/", `show /\Bk/`, `show /^\w+$/`, "show @two", "show @mixed",
		`show /\x{FFFD}/`, "ſhow **", "show /(?-i)^ſ/", "show /(?-i)^s/", `show /\s+k/`, "show /^$/")
	wideWords := append(slices.Clone(narrowWords), "ſ", "ſh", "ſhow", "", "\t", "\tk", "k\n", "\n",
		"\u00a0k", "k\u3000", "\ufffd", "\xff", "em0", "gi\u212a")
	for _, set := range []struct {
		name         string
		rules, words []string
		n            int
	}{
		{"narrow", narrowRules, narrowWords, 3},
		{"wide", wideRules, wideWords, 2},
	} {
		c := agreeWithTheMatcher(t, set.rules, set.words, set.n)
		t.Logf("%s: %d Contains true, %d MayMeet false, %d AlwaysDominates true of rules that meet",
			set.name, c.contains, c.apart, c.dominates)
		if c.contains == 0 || c.apart == 0 || c.dominates == 0 {
			t.Errorf("%s: an answer that licenses something never came back: %+v", set.name, c)
		}
	}
}

type licensed struct{ contains, apart, dominates int }

func agreeWithTheMatcher(t *testing.T, rules, words []string, n int) licensed {
	t.Helper()
	classes := map[string][]string{
		"management": {"^(fxp0|em0)$"},
		"two":        {"^fxp0$", "^em[0-9]$"},
		"mixed":      {"^(?-i)GI[0-9]+$", "^em0$"},
	}
	vectors := universe(words, n)
	dialects := []Normalize{
		{PipeToken: "|", StripCR: true, SessionOnly: true},
		{PipeToken: "|", StripCR: true},
		{PipeToken: "|", StripCR: true, SplitsInterfaceNames: true},
	}
	permits := map[string][][]int{}
	for _, r := range rules {
		cs, err := compileRule(Permit, r, "", classes, dialects[0])
		if err != nil {
			t.Fatal(err)
		}
		specs := make([][]int, len(vectors))
		for i, v := range vectors {
			specs[i], _ = cs[0].match(v, false)
		}
		permits[r] = specs
	}
	var c licensed
	for _, outer := range rules {
		for _, inner := range rules {
			ok, err := Contains(outer, inner, classes)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				continue
			}
			if outer != inner {
				c.contains++
			}
			for i, v := range vectors {
				if permits[inner][i] != nil && permits[outer][i] == nil {
					t.Errorf("Contains(%q, %q) is true and %q refutes it", outer, inner, v)
					break
				}
			}
		}
	}
	for _, d := range dialects {
		for _, deny := range rules {
			ds, err := compileRule(Deny, deny, "", classes, d)
			if err != nil {
				t.Fatal(err)
			}
			for _, permit := range rules {
				meet, err := MayMeet(permit, deny, classes, d)
				if err != nil {
					t.Fatal(err)
				}
				dom, err := AlwaysDominates(permit, deny, classes, d)
				if err != nil {
					t.Fatal(err)
				}
				met := false
				for i, v := range vectors {
					ps := permits[permit][i]
					if ps == nil {
						continue
					}
					for _, shape := range ds {
						spec, ok := shape.match(v, d.abbreviated())
						if !ok {
							continue
						}
						met = true
						if !meet {
							t.Errorf("%+v: MayMeet(%q, %q) is false and %q matches both", d, permit, deny, v)
						}
						if dom && !Dominates(ps, spec) {
							t.Errorf("%+v: AlwaysDominates(%q, %q) is true and the deny wins %q", d, permit, deny, v)
						}
					}
				}
				if !meet {
					c.apart++
				}
				if dom && met {
					c.dominates++
				}
			}
		}
	}
	return c
}

// A pattern is read on its own, never pasted into a larger one: `\Q` with no
// `\E` quotes to the pattern's end and would swallow whatever followed it,
// and the meet it hid would come back only possible.
func TestAQuotedPatternIsReadWhole(t *testing.T) {
	for _, expands := range []bool{false, true} {
		p := program(t, expands, `a:permit show fxp0`, `a:deny show /^\Qfxp0/`)
		ss := p.Shadows()
		if len(ss) != 1 || ss[0].Possible {
			t.Errorf("expands=%v: Shadows() = %+v; want one certain shadow", expands, ss)
		}
	}
	if ok, err := Contains(`show /\Qfxp0/`, "show fxp0", nil); err != nil || !ok {
		t.Errorf(`Contains("show /\Qfxp0/", "show fxp0") = %v, %v; want true`, ok, err)
	}
}
