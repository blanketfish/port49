package engine

import (
	"slices"
	"strconv"
	"strings"
)

// OtherArgument stands for every argument no rule names. It is one value
// because every rule treats all such arguments alike, except a regex or class
// term, which is tested against it as against any other word.
const OtherArgument = "port49-other-argument"

// probeRule is one rule as Probes walks it.
type probeRule struct {
	c      compiled
	fixed  int
	rest   bool
	abbrev bool
}

// Probes returns one command vector for every distinct way the programs'
// rules can be told apart (spec §5.4, §12, "Effective-permission diff"). Two
// commands matched by exactly the same rules score the same tuples, so every
// program decides them alike, and one vector per such class is enough to
// compare programs: that is what makes the diff a computed difference rather
// than a sample. Arguments are drawn from the words the rules name, OtherArgument,
// and the shapes only a deny reads differently: each deny word's
// abbreviations where the program's platform may send them, and each deny
// word with whitespace around it, which a deny matches trimmed and a permit
// does not (compiled.match). A regex or class term is tested only against
// those, and that is where the comparison stops being exact (spec §4, "Leaf
// regex"); the caller reports a changed rule carrying one instead of
// enumerating it.
//
// Nil programs are skipped. The vectors come in a fixed order.
func Probes(programs ...*Program) [][]string {
	var rules []probeRule
	maxFixed := -1
	for _, p := range programs {
		if p == nil {
			continue
		}
		for _, r := range p.rules {
			fixed, rest := fixedLen(r.terms)
			rules = append(rules, probeRule{c: r, fixed: fixed, rest: rest,
				abbrev: r.verdict == Deny && !p.Blob.Normalize.ExpandsAbbreviations})
			maxFixed = max(maxFixed, fixed)
		}
	}
	if len(rules) == 0 {
		return nil
	}
	// A rule of n fixed terms matches vectors of length n, or n and longer
	// behind a `**`; one past the longest, only `**` rules remain and nothing
	// new can be told apart.
	maxLen := maxFixed + 1
	cands := make([][]string, maxLen)
	for i := range cands {
		// The rules' own words come first, so a group's representative is
		// spelled as a rule spells it, then the abbreviations, and the
		// whitespace shapes last.
		words, abbrevs, padded := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, r := range rules {
			if i >= r.fixed || r.c.terms[i].kind != Word {
				continue
			}
			w := r.c.terms[i].word
			words[w] = true
			if r.c.verdict != Deny {
				continue
			}
			padded[" "+w] = true
			if r.abbrev {
				for k := 1; k < len(w); k++ {
					abbrevs[w[:k]] = true
					padded[" "+w[:k]] = true
				}
			}
		}
		cands[i] = append(sortedSet(words), OtherArgument)
		cands[i] = append(cands[i], sortedSet(abbrevs)...)
		cands[i] = append(cands[i], sortedSet(padded)...)
	}

	all := make([]int, len(rules))
	for i := range all {
		all[i] = i
	}
	var out [][]string
	seen := map[string]bool{}
	var walk func(depth int, alive []int, prefix []string)
	walk = func(depth int, alive []int, prefix []string) {
		if depth > 0 && endsAt(rules, alive, depth) {
			out = append(out, slices.Clone(prefix))
		}
		if depth == maxLen {
			return
		}
		var order []string
		next := map[string][]int{}
		rep := map[string]string{}
		for _, c := range cands[depth] {
			var keep []int
			for _, ri := range alive {
				if rules[ri].matchesAt(depth, c) {
					keep = append(keep, ri)
				}
			}
			if len(keep) == 0 {
				continue
			}
			key := aliveKey(keep)
			if _, ok := rep[key]; !ok {
				order = append(order, key)
				next[key], rep[key] = keep, c
			}
		}
		for _, key := range order {
			state := strconv.Itoa(depth+1) + "|" + key
			if seen[state] {
				continue
			}
			seen[state] = true
			walk(depth+1, next[key], append(slices.Clone(prefix), rep[key]))
		}
	}
	walk(0, all, nil)
	return out
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for w := range set {
		out = append(out, w)
	}
	slices.Sort(out)
	return out
}

// endsAt reports whether some rule still alive matches a vector that stops at
// length n.
func endsAt(rules []probeRule, alive []int, n int) bool {
	for _, ri := range alive {
		if r := rules[ri]; (!r.rest && r.fixed == n) || (r.rest && r.fixed <= n) {
			return true
		}
	}
	return false
}

// matchesAt reports whether the rule, alive so far, still matches with arg at
// position i, exactly as compiled.match reads it: a deny also compares the
// argument trimmed and, where abbrev, as an abbreviation; a permit compares it
// only as received.
func (r probeRule) matchesAt(i int, arg string) bool {
	if i >= r.fixed {
		return r.rest
	}
	trimmed := arg
	if r.c.verdict == Deny {
		trimmed = strings.TrimSpace(arg)
	}
	t := r.c.terms[i]
	switch t.kind {
	case Any:
		return true
	case Word:
		return strings.EqualFold(t.word, arg) || strings.EqualFold(t.word, trimmed) ||
			(r.abbrev && abbreviates(trimmed, t.word))
	default:
		return anyMatch(t.res, arg) || anyMatch(t.res, trimmed)
	}
}

func aliveKey(alive []int) string {
	var b strings.Builder
	for _, ri := range alive {
		b.WriteString(strconv.Itoa(ri))
		b.WriteByte(',')
	}
	return b.String()
}
