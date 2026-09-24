package policy

import (
	"regexp/syntax"
	"strings"
)

// rankLint reports whether a regex term is only a costlier spelling of a
// simpler term, and which: `/^.*$/` is `*` and `/^show$/` is the word `show`,
// but each ranks 2 where the simple spelling ranks 1 or 3 (spec §4). A policy
// that let them stand would buy specificity by how a rule is written rather
// than by what it constrains, so they are refused at load (spec §14, "Rank
// lint"). It recognizes the common spellings, not every equivalent regex —
// a lint, not a proof. A `(?-i)` literal is not flagged: a case-sensitive
// match is something a word cannot say.
func rankLint(body string) (simpler string, ok bool) {
	re, err := syntax.Parse("(?i)"+body, syntax.Perl)
	if err != nil {
		return "", false
	}
	re = re.Simplify()
	subs := []*syntax.Regexp{re}
	if re.Op == syntax.OpConcat {
		subs = re.Sub
	}
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
	case len(subs) == 1 && subs[0].Op == syntax.OpStar &&
		(subs[0].Sub[0].Op == syntax.OpAnyChar || subs[0].Sub[0].Op == syntax.OpAnyCharNotNL):
		return "`*` (it matches every argument)", true
	case begin && end && len(subs) == 1 && subs[0].Op == syntax.OpLiteral && subs[0].Flags&syntax.FoldCase != 0:
		word := strings.ToLower(string(subs[0].Rune)) // the fold-case literal is stored upper-cased
		if strings.ContainsAny(word, "*/@ \t") {
			return "", false // not writable as a word
		}
		return "the word `" + word + "`", true
	}
	return "", false
}
