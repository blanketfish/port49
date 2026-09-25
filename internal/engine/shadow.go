package engine

import (
	"regexp"
	"slices"
	"strings"
)

// Shadow is a deny that a permit in the same blob overrides for some command:
// on a command both match, the permit is at least as specific at every
// position and more specific at one, so the deny does not bind there (spec
// §5.4, "What is given up, and what replaces it"). Under most-specific
// semantics a deny is a default rather than a guarantee, and this is the
// visibility spec §12 puts in the guarantee's place.
type Shadow struct {
	Deny, Permit Rule
	// Possible is an overlap that turns on two regex or class terms meeting
	// at one position. Whether two patterns share a string cannot be decided
	// cheaply, so it is reported as possible rather than asserted (spec §12).
	Possible bool
}

// Shadows lists every deny some permit in the program overrides, ordered by
// the deny's role and rule and then the permit's, so a report built from it
// does not depend on a file's layout.
func (p *Program) Shadows() []Shadow {
	abbrev := p.Blob.Normalize.abbreviated()
	var out []Shadow
	for _, d := range p.rules {
		if d.verdict != Deny {
			continue
		}
		for _, pm := range p.rules {
			if pm.verdict != Permit {
				continue
			}
			if ok, possible := overrides(pm, d, abbrev); ok {
				out = append(out, Shadow{Deny: Rule{Verdict: Deny, Rule: d.rule, Role: d.role},
					Permit: Rule{Verdict: Permit, Rule: pm.rule, Role: pm.role}, Possible: possible})
			}
		}
	}
	key := func(s Shadow) string {
		return s.Deny.Role + "\x00" + s.Deny.Rule + "\x00" + s.Permit.Role + "\x00" + s.Permit.Rule
	}
	slices.SortFunc(out, func(a, b Shadow) int { return strings.Compare(key(a), key(b)) })
	// A deny compiled as written and split (compileRule) is one rule to the
	// report, and overridden for certain if any of its shapes is.
	var merged []Shadow
	for _, s := range out {
		if last := len(merged) - 1; last >= 0 && key(merged[last]) == key(s) {
			merged[last].Possible = merged[last].Possible && s.Possible
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// overrides reports whether some command is matched by both rules with the
// permit's tuple dominating the deny's (spec §5.4). The shortest length both
// can match is enough: past it both rules sit in their trailing `**`, which
// scores 0 on each side and cannot change the comparison.
func overrides(pm, d compiled, abbrev bool) (ok, possible bool) {
	pf, pr := fixedLen(pm.terms)
	df, dr := fixedLen(d.terms)
	var n int
	switch {
	case !pr && !dr:
		if pf != df {
			return false, false
		}
		n = pf
	case pr && !dr:
		if df < pf {
			return false, false
		}
		n = df
	case !pr && dr:
		if pf < df {
			return false, false
		}
		n = pf
	default:
		n = max(pf, df)
	}
	strict := false
	for i := 0; i < n; i++ {
		a, b := termAt(pm.terms, pf, i), termAt(d.terms, df, i)
		meet, maybe := overlapAt(pm.terms, pf, d.terms, df, i, abbrev)
		if !meet {
			return false, false
		}
		possible = possible || maybe
		switch ra, rb := a.kind.Rank(), b.kind.Rank(); {
		case ra < rb:
			return false, false
		case ra > rb:
			strict = true
		}
	}
	return strict, possible && strict
}

// fixedLen is the number of terms before a trailing `**`, and whether there
// is one.
func fixedLen(terms []cterm) (int, bool) {
	if n := len(terms); n > 0 && terms[n-1].kind == Rest {
		return n - 1, true
	}
	return len(terms), false
}

// termAt is the term covering position i: a fixed term, or the trailing `**`.
func termAt(terms []cterm, fixed, i int) cterm {
	if i < fixed {
		return terms[i]
	}
	return cterm{kind: Rest}
}

// overlap reports whether one argument can match both the permit's term a and
// the deny's term b, and whether that answer is only possible. It reads the
// terms exactly as the matcher does: a permit matches an argument only as
// received; a deny also matches it trimmed and, where the platform may send
// what was typed (abbrev), a deny's word also matches its own abbreviations.
// A word stands for every case-fold of itself, and a pattern is asked about
// all of them (someTaken), since one that turns case folding off takes some
// and not others.
func overlap(a, b cterm, abbrev bool) (meet, possible bool) {
	switch {
	case a.kind == Rest || b.kind == Rest || a.kind == Any || b.kind == Any:
		return true, false
	case a.kind == Word && b.kind == Word:
		// A permit's word holds no whitespace, so trimming it changes nothing.
		return strings.EqualFold(a.word, b.word) || (abbrev && abbreviates(a.word, b.word)), false
	case a.kind == Word:
		return someTaken(b.rd, a.word, false, false)
	case b.kind == Word:
		// The permit's pattern may take the deny's word, or an abbreviation
		// of it, with whitespace the deny trims.
		return someTaken(a.rd, b.word, true, abbrev)
	case a.kind == b.kind && a.word == b.word:
		return true, false
	}
	return true, true
}

// overlapAt is overlap at position i of a permit's terms and a deny's, where
// a deny term in its split shape is read as a pair: its head meets anything,
// and its tail meets the permit's two terms there when some name and index
// they take joins to what the deny's term takes.
func overlapAt(pterms []cterm, pf int, dterms []cterm, df int, i int, abbrev bool) (meet, possible bool) {
	a, b := termAt(pterms, pf, i), termAt(dterms, df, i)
	switch {
	case b.joinHead:
		return true, false
	case b.joinTail:
		return joinOverlap(termAt(pterms, pf, i-1), a, b, abbrev)
	}
	return overlap(a, b, abbrev)
}

// joinOverlap decides whether some name the permit term h takes and some
// index the permit term x takes join to what the deny's split term t takes. A
// deny word lists its own names and indexes, and two permit words are one
// candidate; any other pair turns on two patterns and is only possible. A
// deny trims both before joining them, so a name that is only whitespace
// trims to nothing and the index alone may be the deny's word.
func joinOverlap(h, x, t cterm, abbrev bool) (meet, possible bool) {
	if h.kind == Word && x.kind == Word {
		switch {
		case t.kind == Word:
			return t.joins(h.word, x.word, abbrev), false
		case !indexShape.MatchString(x.word):
			return false, false
		case t.kind == Any:
			return someTaken(nameReader, h.word, false, false)
		}
		return someTaken(t.rd, h.word+x.word, false, false)
	}
	if t.kind != Word {
		return true, true
	}
	for _, w := range denyWords(t.word, abbrev) {
		for k := 0; k < len(w); k++ {
			if !indexShape.MatchString(w[k:]) {
				continue
			}
			hm, hp := permitMayTake(h, w[:k])
			xm, xp := permitMayTake(x, w[k:])
			if hm && xm && !hp && !xp {
				return true, false
			}
			possible = possible || (hm && xm)
		}
	}
	return possible, possible
}

// denyWords are the arguments a deny's word takes, trimmed: the word, and
// where abbrev every proper prefix of it, rune by rune as abbreviates reads
// one.
func denyWords(word string, abbrev bool) []string {
	out := []string{word}
	if abbrev {
		for k := range word {
			if k > 0 {
				out = append(out, word[:k])
			}
		}
	}
	return out
}

// permitMayTake reports whether a permit's term takes some argument that,
// trimmed, is a case-fold of w: what a deny's word would take of it.
func permitMayTake(t cterm, w string) (meet, possible bool) {
	switch t.kind {
	case Any, Rest:
		return true, false
	case Word:
		// A permit's word holds no whitespace, so trimming it changes nothing.
		return strings.EqualFold(t.word, w), false
	}
	return someTaken(t.rd, w, true, false)
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
