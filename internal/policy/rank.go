package policy

import (
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
)

// rankLint reports whether a regex term is only a costlier spelling of a
// simpler term, and which: `/^.*$/` is `*` and `/^show$/` is the word `show`,
// but each ranks 2 where the simple spelling ranks 1 or 3 (spec §4). A policy
// that let them stand would buy specificity by how a rule is written rather
// than by what it constrains, so they are refused at load (spec §14, "Rank
// lint"). It recognizes the common spellings, not every equivalent regex —
// a lint, not a proof: capture groups, `.*` or `.+` (an argument is never
// empty), and a one-letter class like `[s]`. A `(?-i)` literal is not
// flagged: a case-sensitive match is something a word cannot say.
func rankLint(body string) (simpler string, ok bool) {
	re, err := syntax.Parse("(?i)"+body, syntax.Perl)
	if err != nil {
		return "", false
	}
	subs := flatten(re.Simplify())
	begin, end := false, false
	if len(subs) > 0 && (subs[0].Op == syntax.OpBeginText || subs[0].Op == syntax.OpBeginLine) {
		begin, subs = true, subs[1:]
	}
	if n := len(subs); n > 0 && (subs[n-1].Op == syntax.OpEndText || subs[n-1].Op == syntax.OpEndLine) {
		end, subs = true, subs[:n-1]
	}
	switch {
	case len(subs) == 0 && !(begin && end):
		return "`*` (it matches every argument)", true
	case len(subs) == 1 && (subs[0].Op == syntax.OpStar || subs[0].Op == syntax.OpPlus) &&
		(subs[0].Sub[0].Op == syntax.OpAnyChar || subs[0].Sub[0].Op == syntax.OpAnyCharNotNL):
		return "`*` (it matches every argument)", true
	case begin && end && len(subs) > 0:
		word, ok := literalWord(subs)
		if !ok || strings.ContainsAny(word, "*/@ \t") {
			return "", false // not a word, or not writable as one
		}
		return "the word `" + word + "`", true
	}
	return "", false
}

// flatten unwraps capture groups and splices nested concatenations, so
// `^(show)$` and `(^show$)` read as `^show$` does.
func flatten(re *syntax.Regexp) []*syntax.Regexp {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat {
		return []*syntax.Regexp{re}
	}
	var out []*syntax.Regexp
	for _, s := range re.Sub {
		out = append(out, flatten(s)...)
	}
	return out
}

// literalWord spells out a run of case-insensitive literals and one-letter
// classes, or reports that the run is not one.
func literalWord(subs []*syntax.Regexp) (string, bool) {
	var b strings.Builder
	for _, s := range subs {
		switch {
		case s.Op == syntax.OpLiteral && s.Flags&syntax.FoldCase != 0:
			// the fold-case literal is stored upper-cased
			b.WriteString(strings.ToLower(string(s.Rune)))
		case s.Op == syntax.OpCharClass:
			r, ok := oneLetter(s.Rune)
			if !ok {
				return "", false
			}
			b.WriteRune(unicode.ToLower(r))
		default:
			return "", false
		}
	}
	return b.String(), true
}

// oneLetter reports whether a class's ranges are exactly one rune's case
// folds: under (?i), `[s]` is the class {S, s, ſ}.
func oneLetter(ranges []rune) (rune, bool) {
	var set []rune
	for i := 0; i+1 < len(ranges); i += 2 {
		if ranges[i+1]-ranges[i] > 4 {
			return 0, false
		}
		for r := ranges[i]; r <= ranges[i+1]; r++ {
			set = append(set, r)
		}
	}
	if len(set) == 0 {
		return 0, false
	}
	orbit := []rune{set[0]}
	for f := unicode.SimpleFold(set[0]); f != set[0]; f = unicode.SimpleFold(f) {
		orbit = append(orbit, f)
	}
	slices.Sort(set)
	slices.Sort(orbit)
	return set[0], slices.Equal(set, orbit)
}
