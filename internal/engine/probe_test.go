package engine

import (
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

// verdictOf is a program's answer to a command vector, as a comparable string.
func verdictOf(p *Program, vector []string) string {
	o := p.Command(rawOf(vector))
	return string(o.Reason)
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

// crossCheck asserts the probes find every pair of answers the two programs
// give to one command, and only those: the same set a brute-force walk over
// every vector of up to n of words finds.
func crossCheck(t *testing.T, before, after *Program, words []string, n int) {
	t.Helper()
	pairs := func(vectors [][]string) map[string]bool {
		seen := map[string]bool{}
		for _, v := range vectors {
			if a, b := verdictOf(before, v), verdictOf(after, v); a != b {
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
	for k := range got {
		if !want[k] {
			t.Errorf("the probes find %q, brute force does not", k)
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
