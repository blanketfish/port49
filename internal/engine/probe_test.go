package engine

import (
	"slices"
	"strings"
	"testing"
)

// rawOf is a command vector as a device sends it, each argument exactly as
// given: whitespace inside an argument is kept (spec §3), which cmd would lose.
func rawOf(vector []string) []string {
	raw := []string{"service=shell", "cmd=" + vector[0]}
	for _, a := range vector[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return append(raw, "cmd-arg=<cr>")
}

// verdictOf is a program's answer to a command vector, as a comparable
// string: the reason and every rule that matched. Two vectors with the same
// verdict are the same class to that program.
func verdictOf(p *Program, vector []string) string {
	o := p.Command(rawOf(vector))
	var b strings.Builder
	b.WriteString(string(o.Reason))
	for _, m := range o.Permits {
		b.WriteString(" +" + m.Role + ":" + m.Rule)
	}
	for _, m := range o.Denies {
		b.WriteString(" -" + m.Role + ":" + m.Rule)
	}
	return b.String()
}

// universe is every vector up to length n over words: small enough to
// enumerate, and a check on Probes that does not trust Probes.
func universe(words []string, n int) [][]string {
	out := [][]string{}
	var grow func(prefix []string)
	grow = func(prefix []string) {
		if len(prefix) > 0 {
			out = append(out, append([]string(nil), prefix...))
		}
		if len(prefix) == n {
			return
		}
		for _, w := range words {
			grow(append(append([]string(nil), prefix...), w))
		}
	}
	grow(nil)
	return out
}

// crossCheck asserts the probes reach every disagreement a brute-force walk
// over every vector of up to n of words finds, keyed by the reason and the
// rules each program matched, so two classes that happen to share a reason
// pair are still told apart. The converse needs no check: every probe is a
// real vector, so a disagreement it finds is real.
func crossCheck(t *testing.T, before, after *Program, words []string, n int) {
	t.Helper()
	pairs := func(vectors [][]string) map[string]bool {
		seen := map[string]bool{}
		for _, v := range vectors {
			a, b := verdictOf(before, v), verdictOf(after, v)
			if before.Command(rawOf(v)).Reason != after.Command(rawOf(v)).Reason {
				seen[a+" -> "+b] = true
			}
		}
		return seen
	}
	want := pairs(universe(words, n))
	got := pairs(Probes(before, after))
	if len(want) == 0 {
		t.Fatal("the fixture must disagree somewhere")
	}
	for k := range want {
		if !got[k] {
			t.Errorf("brute force finds %q, the probes do not", k)
		}
	}
}

// The probes find every disagreement a brute-force walk over a whole small
// command space finds. That is the diff's exactness claim (spec §5.4, §12),
// for words, `*`, `**` and abbreviations.
func TestProbesFindEveryDisagreementBruteForceFinds(t *testing.T) {
	before := program(t, false, "ro:permit show **", "cve:deny show chassis **", "nd:deny reload **", "op:permit clear * all")
	after := program(t, false, "ro:permit show **", "cve:deny show chassis **", "nd:deny reload **",
		"backup:permit show chassis hardware", "op:permit clear counters *", "op2:permit rel now")
	crossCheck(t, before, after,
		[]string{"show", "chassis", "hardware", "clear", "counters", "all", "reload", "rel", "re", "now", "x"}, 4)
}

// An argument carrying whitespace is its own shape: a deny matches it trimmed
// and a permit only as received, so ` reload now` is refused by `reload **`
// and not permitted by `reload now`. Here only that argument moves from
// no_rule_matched to a deny `* now` fails to dominate.
func TestProbesModelTheDenyOnlyTrim(t *testing.T) {
	before := program(t, true, "nd:deny reload **", "fix:permit reload now")
	after := program(t, true, "nd:deny reload **", "fix:permit reload now", "any:permit * now")
	crossCheck(t, before, after, []string{"reload", "now", "x", " reload", " now", "reload "}, 3)
}

// An abbreviation two deny words share is a class of its own where the
// platform may send what was typed: `re now` is refused by both `reload **`
// and `reset **`, which no whole word is.
func TestProbesModelTheDenyAbbreviations(t *testing.T) {
	before := program(t, false, "nd:deny reload **", "nr:deny reset **")
	after := program(t, false, "nd:deny reload **", "nr:deny reset **", "any:permit * now")
	crossCheck(t, before, after, []string{"reload", "reset", "re", "rel", "now", "x"}, 2)
}

// Where the platform splits interface names, the probes try the name and the
// index a deny names joined, as two arguments: adding the deny turns
// `interface GigabitEthernet 1` and `interface Loopback 0` from permitted to
// denied.
func TestProbesModelTheSplitInterfaceName(t *testing.T) {
	b := testBlob(true, "any:permit * * *", "any:permit * *")
	b.Normalize.SplitsInterfaceNames = true
	before := compileBlob(t, b)
	b.Rules = append(b.Rules, Rule{Verdict: Deny, Rule: "interface GigabitEthernet1", Role: "gi"},
		Rule{Verdict: Deny, Rule: "interface /^Loopback[0-9]+$/", Role: "lo"})
	after := compileBlob(t, b)
	crossCheck(t, before, after, []string{"interface", "GigabitEthernet", "GigabitEthernet1", "Loopback", "Loopback0", "1", "0", "x"}, 3)
	// A pattern no stem can be read from splits too, and the probes find it.
	b.Rules = append(b.Rules[:2], Rule{Verdict: Deny, Rule: "interface /^Gig[a-z]*[0-9]+$/", Role: "gi"},
		Rule{Verdict: Permit, Rule: "interface Gigabit 1", Role: "fix"})
	crossCheck(t, before, compileBlob(t, b), []string{"interface", "Gig", "Gigabit", "Gigabit1", "1", "x"}, 3)
}

// A deny's `*` splits too: adding `default interface *` turns the split
// `default interface GigabitEthernet 1` from permitted to denied, and the
// probes find it.
func TestProbesModelTheSplitAnyTerm(t *testing.T) {
	b := testBlob(true, "any:permit **")
	b.Normalize.SplitsInterfaceNames = true
	before := compileBlob(t, b)
	b.Rules = append(b.Rules, Rule{Verdict: Deny, Rule: "default interface *", Role: "d"})
	after := compileBlob(t, b)
	crossCheck(t, before, after, []string{"default", "interface", "GigabitEthernet", "1", "x"}, 4)
	split := false
	for _, v := range Probes(before, after) {
		if len(v) == 4 && verdictOf(before, v) != verdictOf(after, v) {
			split = true
		}
	}
	if !split {
		t.Errorf("no probe splits the name: %q", Probes(before, after))
	}
}

// A regex term is tried against an argument it matches, not only against the
// words the rules name: narrowing the deny `copy * startup-config` frees
// `copy scp:x startup-config` for the unchanged `copy /^scp:/ *`.
func TestProbesTryWhatARegexMatches(t *testing.T) {
	before := program(t, true, "bk:permit copy /^scp:/ *", "nd:deny copy * startup-config")
	after := program(t, true, "bk:permit copy /^scp:/ *", "nd:deny copy * running-config")
	crossCheck(t, before, after, []string{"copy", "scp:x", "startup-config", "running-config", "x"}, 3)
}

// The command a change turns on is itself among the probes, spelled with the
// rule's words, and a word no rule names is one probe, not many.
func TestProbesUseTheRulesWords(t *testing.T) {
	before := program(t, true, "ro:permit show **", "cve:deny show chassis **")
	after := program(t, true, "ro:permit show **", "cve:deny show chassis **", "backup:permit show chassis hardware")
	var flipped []string
	for _, v := range Probes(before, after) {
		if verdictOf(before, v) != verdictOf(after, v) {
			flipped = append(flipped, strings.Join(v, " "))
		}
	}
	if len(flipped) != 1 || flipped[0] != "show chassis hardware" {
		t.Fatalf("flipped %q", flipped)
	}
	if Probes() != nil || Probes(nil) != nil {
		t.Fatal("no programs, no probes")
	}
}

// The pipe allowlist is probed the same way: a stage one version's entries
// permit and the other's do not is among the stages, and the empty stage
// always is.
func TestPipeProbesFindAWidenedAllowlist(t *testing.T) {
	b := testBlob(true, "ro:permit show **")
	before := compileBlob(t, b)
	b.Pipe = append(b.Pipe, "save **")
	after := compileBlob(t, b)
	flipped := 0
	stages := PipeProbes(before, after)
	for _, s := range stages {
		if before.PipeEntry(s) == "" && after.PipeEntry(s) == "save **" {
			flipped++
		}
	}
	if flipped == 0 || len(stages[0]) != 0 {
		t.Fatalf("stages %q", stages)
	}
}

// A permit carrying a regex that meets a deny the change removed is exposed:
// which commands it frees turns on the pattern (spec §12).
func TestExposuresNameARegexPermitAChangedDenyMeets(t *testing.T) {
	before := program(t, true, "bk:permit copy /^scp:/ *", "nd:deny copy * startup-config", "ro:permit show **")
	after := program(t, true, "bk:permit copy /^scp:/ *", "nd:deny copy * running-config", "ro:permit show **")
	got := Exposures(before, after)
	if len(got) != 2 || got[0].Deny.Rule != "copy * startup-config" || got[0].Added ||
		got[1].Deny.Rule != "copy * running-config" || !got[1].Added || got[0].Permit.Rule != "copy /^scp:/ *" {
		t.Fatalf("%+v", got)
	}
}

// A removed deny that meets a regex permit both as written and split is one
// exposure.
func TestExposuresNameASplitDenyOnce(t *testing.T) {
	b := testBlob(true, "gi:permit interface /^Gig/ * **", "nd:deny interface /^Gig.*/ **")
	b.Normalize.SplitsInterfaceNames = true
	before := compileBlob(t, b)
	b.Rules = b.Rules[:1]
	after := compileBlob(t, b)
	if got := Exposures(before, after); len(got) != 1 || got[0].Deny.Rule != "interface /^Gig.*/ **" {
		t.Fatalf("%+v", got)
	}
}

// ProbeSources names the rule word each probe argument was made from: split
// into a name and an index, cut to an abbreviation, or padded, so a report
// can print one made from a secret as redacted.
func TestProbeSourcesNameTheWordEachArgumentWasMadeFrom(t *testing.T) {
	b := testBlob(false, "any:permit **", "nd:deny snmp-server community Kilo7 **")
	b.Normalize.SplitsInterfaceNames = true
	src := ProbeSources(compileBlob(t, b))
	for arg, want := range map[string]string{"Kilo": "Kilo7", "7": "Kilo7", "Kil": "Kilo7", " Kilo7": "Kilo7",
		"community": "community"} {
		if !slices.Contains(src[arg], want) {
			t.Errorf("%q: %q", arg, src[arg])
		}
	}
	// Every argument Probes tries that a rule's word made is named.
	for _, v := range Probes(compileBlob(t, b)) {
		for _, a := range v {
			if a != OtherArgument && strings.Contains(strings.ToLower(a), "kil") && len(src[a]) == 0 {
				t.Errorf("%q has no source", a)
			}
		}
	}
}

// Every argument Probes and PipeProbes try but OtherArgument has a source,
// whatever term kind made it: a class or regex witness, whole or split, is
// recorded against the term as its rule writes it (task 11 re-review 3, R6).
func TestEveryProbeArgumentHasASource(t *testing.T) {
	b := testBlob(false, "any:permit **", "nd:deny snmp-server community @backup_targets **",
		"nr:deny snmp-server community /^Mango5[5-6]$/ **", "ni:deny interface @physical", "na:deny default * now")
	b.Classes["backup_targets"] = []string{`^Mango55$`}
	b.Normalize.SplitsInterfaceNames = true
	p := compileBlob(t, b)
	src := ProbeSources(p)
	for _, v := range slices.Concat(Probes(p), PipeProbes(p)) {
		for _, a := range v {
			if a != OtherArgument && len(src[a]) == 0 {
				t.Errorf("%q in %q has no source", a, v)
			}
		}
	}
	for arg, want := range map[string]string{"MANGO55": "@backup_targets", "MANGO": "/^Mango5[5-6]$/", "|": "|"} {
		if !slices.Contains(src[arg], want) {
			t.Errorf("%q: %q", arg, src[arg])
		}
	}
}
