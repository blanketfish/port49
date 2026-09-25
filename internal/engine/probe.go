package engine

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
)

// OtherArgument stands for every argument no rule names. It is one value
// because every rule treats all such arguments alike, except a regex or class
// term, which is tested against it as against any other word.
const OtherArgument = "port49-other-argument"

// anyJoined is what a deny's split `*` is tried as: a name and an index.
const anyJoined = "Name1"

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
// than a sample. Arguments are drawn from the words the rules name,
// OtherArgument, one argument each regex or class pattern matches, and the
// shapes only a deny reads differently: each deny word's abbreviations where
// the program's platform may send them, and each deny word with whitespace
// around it, which a deny matches trimmed and a permit does not
// (compiled.match). Where two regex or class terms meet at one position, the
// arguments one matches and the other does not are tried only as far as
// those candidates reach, and that is where the comparison stops being exact
// (spec §4, "Leaf regex"); the caller reports such a rule instead of
// enumerating it.
//
// Nil programs are skipped. The vectors come in a fixed order.
func Probes(programs ...*Program) [][]string {
	return walkProbes(probeRules(programs), false)
}

// probeRules is the programs' rules as Probes walks them; nil programs are
// skipped.
func probeRules(programs []*Program) []probeRule {
	var rules []probeRule
	for _, p := range programs {
		if p == nil {
			continue
		}
		abbrev := p.Blob.Normalize.abbreviated()
		for _, r := range p.rules {
			fixed, rest := fixedLen(r.terms)
			rules = append(rules, probeRule{c: r, fixed: fixed, rest: rest, abbrev: r.verdict == Deny && abbrev})
		}
	}
	return rules
}

// ProbeSources maps each argument Probes may try for the programs to the
// words of their rules it was made from: a word as written, split into a
// name and an index, cut to an abbreviation, or padded with whitespace. A
// report printing a probe reads it to print, as redacted, every argument
// made from a word redaction hides, which no writer would recognize once
// split or cut (spec §5.8).
func ProbeSources(programs ...*Program) map[string][]string {
	rules := probeRules(programs)
	src := map[string][]string{}
	maxLen := 0
	for _, r := range rules {
		maxLen = max(maxLen, r.fixed+1)
	}
	for i := 0; i < maxLen; i++ {
		candidates(rules, i, src)
	}
	return src
}

// PipeProbes is Probes for the programs' pipe allowlists: one pipeline stage
// for every distinct way the entries can be told apart, the empty stage
// among them. A stage is matched as written (pipePermits), so there are no
// abbreviations or whitespace shapes to try.
func PipeProbes(programs ...*Program) [][]string {
	var rules []probeRule
	for _, p := range programs {
		if p == nil {
			continue
		}
		for _, r := range p.pipe {
			fixed, rest := fixedLen(r.terms)
			rules = append(rules, probeRule{c: r, fixed: fixed, rest: rest})
		}
	}
	return walkProbes(rules, true)
}

// PipeEntry is the first allowlist entry that permits stage, or "" when none
// does: what a pipeline stage's permit rests on.
func (p *Program) PipeEntry(stage []string) string {
	for _, r := range p.pipe {
		if _, ok := r.match(stage, false); ok {
			return r.rule
		}
	}
	return ""
}

// walkProbes walks the rules together, position by position, following one
// representative argument per set of rules it keeps alive. With empty, the
// empty vector is a probe too.
func walkProbes(rules []probeRule, empty bool) [][]string {
	if len(rules) == 0 {
		return nil
	}
	// A rule of n fixed terms matches vectors of length n, or n and longer
	// behind a `**`; one past the longest, only `**` rules remain and nothing
	// new can be told apart.
	maxLen := 0
	for _, r := range rules {
		maxLen = max(maxLen, r.fixed+1)
	}
	cands := make([][]string, maxLen)
	for i := range cands {
		cands[i] = candidates(rules, i, nil)
	}

	all := make([]int, len(rules))
	for i := range all {
		all[i] = i
	}
	var out [][]string
	if empty {
		out = append(out, []string{})
	}
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
			prev := ""
			if depth > 0 {
				prev = prefix[depth-1]
			}
			for _, ri := range alive {
				if rules[ri].matchesAt(depth, prev, c) {
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

// candidates are the arguments tried at position i. The rules' own words come
// first, so a group's representative is spelled as a rule spells it, then
// OtherArgument, then what the regex and class patterns match, then the
// abbreviations, and the whitespace shapes last. Where src is not nil, each
// candidate made from a rule's word, split, cut short or padded, is recorded
// in it against that word (ProbeSources).
func candidates(rules []probeRule, i int, src map[string][]string) []string {
	words, matched, abbrevs, padded := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	from := func(set map[string]bool, w, word string) {
		set[w] = true
		if src != nil && word != "" && !slices.Contains(src[w], word) {
			src[w] = append(src[w], word)
		}
	}
	for _, r := range rules {
		if i >= r.fixed {
			continue
		}
		t := r.c.terms[i]
		if t.joinHead || t.joinTail {
			// A split term is tried as each name and index its joined
			// candidates divide into.
			joined := []string{t.word}
			switch t.kind {
			case Any:
				joined = []string{anyJoined}
			case Class, Regex:
				joined = witnesses(t.res)
			}
			for _, w := range joined {
				for _, sp := range splitsOf(w) {
					if t.joinHead {
						from(words, sp[0], w)
					} else {
						from(words, sp[1], w)
					}
				}
			}
			continue
		}
		switch t.kind {
		case Regex, Class:
			for _, re := range t.res {
				if w, ok := witness(re); ok {
					matched[w] = true
				}
			}
			continue
		case Word:
		default:
			continue
		}
		w := t.word
		from(words, w, w)
		if r.c.verdict != Deny {
			continue
		}
		from(padded, " "+w, w)
		if r.abbrev {
			for k := range w {
				if k > 0 {
					from(abbrevs, w[:k], w)
					from(padded, " "+w[:k], w)
				}
			}
		}
	}
	out := append(sortedSet(words), OtherArgument)
	for _, set := range []map[string]bool{matched, abbrevs, padded} {
		out = append(out, sortedSet(set)...)
	}
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

// witnesses is one argument per pattern that has one.
func witnesses(res []*regexp.Regexp) []string {
	var out []string
	for _, re := range res {
		if w, ok := witness(re); ok {
			out = append(out, w)
		}
	}
	return out
}

// witness is one argument re matches, built from its syntax: the first branch
// of every alternation, the fewest repetitions, the first printable rune of a
// class. It is checked against re, so a pattern it cannot serve (an anchor
// the build ignores, say) gives none.
func witness(re *regexp.Regexp) (string, bool) {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	var build func(r *syntax.Regexp) bool
	build = func(r *syntax.Regexp) bool {
		switch r.Op {
		case syntax.OpLiteral:
			b.WriteString(string(r.Rune))
		case syntax.OpCharClass:
			if len(r.Rune) == 0 {
				return false
			}
			pick := r.Rune[0]
			for j := 0; j+1 < len(r.Rune); j += 2 {
				if lo, hi := max(r.Rune[j], '!'), min(r.Rune[j+1], '~'); lo <= hi {
					pick = lo
					break
				}
			}
			b.WriteRune(pick)
		case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			b.WriteByte('x')
		case syntax.OpCapture:
			return build(r.Sub[0])
		case syntax.OpPlus:
			return build(r.Sub[0])
		case syntax.OpRepeat:
			for range r.Min {
				if !build(r.Sub[0]) {
					return false
				}
			}
		case syntax.OpConcat:
			for _, s := range r.Sub {
				if !build(s) {
					return false
				}
			}
		case syntax.OpAlternate:
			return build(r.Sub[0])
		case syntax.OpNoMatch:
			return false
		}
		// Anchors, boundaries, empty matches, `*` and `?` add nothing.
		return true
	}
	if !build(parsed.Simplify()) {
		return "", false
	}
	w := b.String()
	return w, re.MatchString(w)
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
// position i after prev, exactly as compiled.match reads it: a deny also
// compares the argument trimmed and, where abbrev, as an abbreviation, and a
// split tail joined to prev; a permit compares it only as received.
func (r probeRule) matchesAt(i int, prev, arg string) bool {
	if i >= r.fixed {
		return r.rest
	}
	trimmed := arg
	if r.c.verdict == Deny {
		trimmed = strings.TrimSpace(arg)
	}
	t := r.c.terms[i]
	switch {
	case t.joinHead:
		return true
	case t.joinTail:
		return t.joins(prev, arg, false) || t.joins(strings.TrimSpace(prev), trimmed, r.abbrev)
	case t.kind == Any:
		return true
	case t.kind == Word:
		return strings.EqualFold(t.word, arg) || t.takes(trimmed, r.abbrev)
	default:
		return t.takes(arg, false) || t.takes(trimmed, false)
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

// Exposure is a permit carrying a regex or class term that meets a deny only
// one of two programs holds: some command both match may have changed
// decision, and which ones turn on the pattern, so it is reported rather than
// enumerated (spec §12).
type Exposure struct {
	Permit, Deny Rule
	// Added is a deny the second program holds and the first does not.
	Added bool
}

// Exposures lists, from before to after, every permit carrying a regex or
// class term that meets a deny one of them added or removed: a removed deny
// against the permits after holds, an added one against those before held.
func Exposures(before, after *Program) []Exposure {
	var out []Exposure
	for _, v := range []struct {
		denies, permits *Program
		other           *Program
		added           bool
	}{{before, after, after, false}, {after, before, before, true}} {
		abbrev := v.denies.Blob.Normalize.abbreviated()
		for _, d := range v.denies.rules {
			if d.verdict != Deny || v.other.holds(d) {
				continue
			}
			for _, pm := range v.permits.rules {
				if pm.verdict != Permit || !pm.constrained() || !meets(pm, d, abbrev) {
					continue
				}
				e := Exposure{Permit: Rule{Verdict: Permit, Rule: pm.rule, Role: pm.role},
					Deny: Rule{Verdict: Deny, Rule: d.rule, Role: d.role}, Added: v.added}
				// A deny compiled as written and split is one rule here.
				if !slices.Contains(out, e) {
					out = append(out, e)
				}
			}
		}
	}
	return out
}

func (p *Program) holds(c compiled) bool {
	return slices.ContainsFunc(p.rules, func(r compiled) bool {
		return r.verdict == c.verdict && r.rule == c.rule && r.role == c.role
	})
}

func (c compiled) constrained() bool {
	return slices.ContainsFunc(c.terms, func(t cterm) bool { return t.kind == Regex || t.kind == Class })
}

// meets reports whether some command may match both rules, reading each term
// as overlap does.
func meets(pm, d compiled, abbrev bool) bool {
	pf, pr := fixedLen(pm.terms)
	df, dr := fixedLen(d.terms)
	if (!pr && !dr && pf != df) || (pr && !dr && df < pf) || (!pr && dr && pf < df) {
		return false
	}
	for i := 0; i < max(pf, df); i++ {
		if meet, _ := overlapAt(pm.terms, pf, d.terms, df, i, abbrev); !meet {
			return false
		}
	}
	return true
}
