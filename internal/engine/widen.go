package engine

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"
	"unicode"
)

// A deny's regex or class pattern is widened where the platform's dialect
// says an argument may arrive in another shape than the one the pattern names
// (spec §3 rules 4 and 5): abbreviated, where the platform may send what was
// typed, and split, where it sends an interface name and its index as two
// arguments (IOS-XE sends a typed `Gi1` as `GigabitEthernet`, `1`;
// tests/lab/results/L21-cisco_iosxe.md). Widening is deny-only, like the word abbreviations in compiled.match: it can
// only make a deny match more.
//
// A pattern is widened by reading its syntax as the names it matches: each
// branch of it is `^`, a literal stem, and what the pattern allows after the
// stem. `^Management[0-9]+$` is the stem `Management` and then `[0-9]+$`, and
// its abbreviations are every non-empty prefix of the stem followed by the
// same `[0-9]+$`, so `Ma1` is denied as `Management1` is; split, it is the stem
// as one argument and an index `[0-9]+$` matches as the next. A branch that
// starts with no letter names nothing a device abbreviates or splits and is
// left as written. A
// pattern whose branches cannot be read that way — unanchored, starting with a
// class or a wildcard that may be a letter, or a stem that runs on into
// something that may be a letter — is refused, because the abbreviations it
// would miss cannot be listed (spec §3 rule 4: fail closed rather than match a
// possibly-abbreviated vector).
//
// A split is a second shape of the whole rule, not of one argument: the
// vector is never re-joined (spec §3 rule 5), so a deny whose term may name an
// interface with its index compiles to the rule as written and one sibling per
// way of splitting it, each with the name and the index as two terms. The
// siblings carry the rule's text and role, so a decision names the rule as
// written.

// stemmed is one branch of a pattern read as a name: its literal stem and what
// the pattern allows after it.
type stemmed struct {
	stem  []rune
	flags syntax.Flags
	rest  []*syntax.Regexp
	// anything is a branch that matches every argument (`^.*`): no stem,
	// nothing to abbreviate, and any name to split.
	anything bool
}

// maxBranches bounds how many branches a pattern's alternations and optional
// parts may expand to. A pattern past it is refused rather than widened.
const maxBranches = 64

var errUnreadable = errors.New("port49 cannot list what it would miss; " +
	"start the pattern with `^` and the literal name, like /^Management[0-9]+$/")

// stems reads a pattern, compiled as compileTerm compiles it, as the names it
// matches. Branches that start with no letter are omitted: there is nothing in
// them to abbreviate.
func stems(pattern string) ([]stemmed, error) {
	re, err := syntax.Parse("(?i)"+pattern, syntax.Perl)
	if err != nil {
		return nil, err
	}
	bs, ok := branches(re)
	if !ok {
		return nil, fmt.Errorf("it has more than %d branches, so %w", maxBranches, errUnreadable)
	}
	var out []stemmed
	for _, b := range bs {
		b = mergeLiterals(b)
		if len(b) == 0 || b[0].Op != syntax.OpBeginText {
			return nil, fmt.Errorf("it is not anchored with `^`, so %w", errUnreadable)
		}
		b = b[1:]
		if len(b) == 0 || matchesAnything(b) {
			out = append(out, stemmed{anything: true})
			continue
		}
		if !mayStartName(b, false) {
			continue
		}
		lit := b[0]
		if lit.Op != syntax.OpLiteral || !unicode.IsLetter(lit.Rune[0]) {
			return nil, fmt.Errorf("a branch starts with no literal name, so %w", errUnreadable)
		}
		n := 1
		for n < len(lit.Rune) && nameRune(lit.Rune[n], true) {
			n++
		}
		s := stemmed{stem: lit.Rune[:n], flags: lit.Flags}
		if n < len(lit.Rune) {
			s.rest = append(s.rest, &syntax.Regexp{Op: syntax.OpLiteral, Flags: lit.Flags, Rune: lit.Rune[n:]})
		}
		s.rest = append(s.rest, b[1:]...)
		if !matchesAnything(s.rest) && mayStartName(s.rest, true) {
			return nil, fmt.Errorf("the name %q runs on into a part that may be more of it, so %w", string(s.stem), errUnreadable)
		}
		out = append(out, s)
	}
	return out, nil
}

// abbreviations are the patterns a deny's pattern also matches where the
// platform may send what was typed: per branch, `^`, any non-empty prefix of
// the stem, and the rest as written.
func abbreviations(pattern string) ([]string, error) {
	ss, err := stems(pattern)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s.anything {
			continue
		}
		nodes := append([]*syntax.Regexp{{Op: syntax.OpBeginText, Flags: s.flags}, prefixes(s.stem, s.flags)}, s.rest...)
		out = append(out, (&syntax.Regexp{Op: syntax.OpConcat, Flags: s.flags, Sub: nodes}).String())
	}
	return out, nil
}

// prefixes matches every non-empty prefix of stem: `M(?:A(?:N)?)?` for MAN.
func prefixes(stem []rune, flags syntax.Flags) *syntax.Regexp {
	node := &syntax.Regexp{Op: syntax.OpLiteral, Flags: flags, Rune: []rune{stem[len(stem)-1]}}
	for i := len(stem) - 2; i >= 0; i-- {
		node = &syntax.Regexp{Op: syntax.OpConcat, Flags: flags, Sub: []*syntax.Regexp{
			{Op: syntax.OpLiteral, Flags: flags, Rune: []rune{stem[i]}},
			{Op: syntax.OpQuest, Flags: flags, Sub: []*syntax.Regexp{node}},
		}}
	}
	return node
}

// branches expands captures, alternations and optional parts into the
// sequences of nodes a pattern may match, or false past maxBranches.
func branches(re *syntax.Regexp) ([][]*syntax.Regexp, bool) {
	switch re.Op {
	case syntax.OpCapture:
		return branches(re.Sub[0])
	case syntax.OpEmptyMatch:
		return [][]*syntax.Regexp{nil}, true
	case syntax.OpQuest:
		bs, ok := branches(re.Sub[0])
		return append(bs, nil), ok && len(bs) < maxBranches
	case syntax.OpAlternate:
		var out [][]*syntax.Regexp
		for _, sub := range re.Sub {
			bs, ok := branches(sub)
			if out = append(out, bs...); !ok || len(out) > maxBranches {
				return nil, false
			}
		}
		return out, true
	case syntax.OpConcat:
		out := [][]*syntax.Regexp{nil}
		for _, sub := range re.Sub {
			bs, ok := branches(sub)
			if !ok || len(out)*len(bs) > maxBranches {
				return nil, false
			}
			var next [][]*syntax.Regexp
			for _, a := range out {
				for _, b := range bs {
					next = append(next, append(slices.Clone(a), b...))
				}
			}
			out = next
		}
		return out, true
	}
	return [][]*syntax.Regexp{{re}}, true
}

// mergeLiterals joins adjacent literals that fold alike, so a stem a parser
// factored (`M(?:ANAGEMENT|GMT)`) reads whole again.
func mergeLiterals(b []*syntax.Regexp) []*syntax.Regexp {
	var out []*syntax.Regexp
	for _, n := range b {
		if last := len(out) - 1; last >= 0 && n.Op == syntax.OpLiteral && out[last].Op == syntax.OpLiteral &&
			n.Flags&syntax.FoldCase == out[last].Flags&syntax.FoldCase {
			out[last] = &syntax.Regexp{Op: syntax.OpLiteral, Flags: out[last].Flags,
				Rune: append(slices.Clone(out[last].Rune), n.Rune...)}
			continue
		}
		out = append(out, n)
	}
	return out
}

// matchesAnything reports whether the nodes, after a stem, allow any text at
// all: a `.*` or `.+`, alone or before the end. Nothing past the stem then
// constrains a name, so none is missed.
func matchesAnything(rest []*syntax.Regexp) bool {
	if len(rest) == 0 || len(rest) > 2 || (len(rest) == 2 && rest[1].Op != syntax.OpEndText) {
		return false
	}
	r := rest[0]
	return (r.Op == syntax.OpStar || r.Op == syntax.OpPlus) &&
		(r.Sub[0].Op == syntax.OpAnyChar || r.Sub[0].Op == syntax.OpAnyCharNotNL)
}

// mayStartName reports whether the nodes may match text that starts with a
// letter or, where hyphen, a `-`: a rune a name may continue with. A node that
// may match nothing defers to the next. It answers true wherever it cannot
// tell.
func mayStartName(nodes []*syntax.Regexp, hyphen bool) bool {
	for _, node := range nodes {
		switch node.Op {
		case syntax.OpLiteral:
			return nameRune(node.Rune[0], hyphen)
		case syntax.OpCharClass:
			return classHasName(node.Rune, hyphen)
		case syntax.OpEndText, syntax.OpEndLine:
			return false
		case syntax.OpPlus:
			return mayStartName(node.Sub, hyphen)
		case syntax.OpStar:
			if mayStartName(node.Sub, hyphen) {
				return true
			}
		case syntax.OpRepeat:
			if mayStartName(node.Sub, hyphen) {
				return true
			}
			if node.Min > 0 {
				return false
			}
		default:
			return true
		}
	}
	return false
}

func classHasName(ranges []rune, hyphen bool) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if hi-lo > 0x3000 {
			return true
		}
		for r := lo; r <= hi; r++ {
			if nameRune(r, hyphen) {
				return true
			}
		}
	}
	return false
}

func nameRune(r rune, hyphen bool) bool { return unicode.IsLetter(r) || (hyphen && r == '-') }

// denyPatterns is what one pattern of a deny's regex or class term matches on
// a platform with dialect n: the pattern, and its abbreviations where the
// platform may send what was typed. It refuses a pattern whose widening it
// cannot read.
func denyPatterns(pattern string, n Normalize) ([]string, error) {
	out := []string{pattern}
	if !n.ExpandsAbbreviations {
		abbrs, err := abbreviations(pattern)
		if err != nil {
			return nil, fmt.Errorf("the platform may send it abbreviated (spec §3 rule 4) and %w", err)
		}
		out = append(out, abbrs...)
	}
	return out, nil
}

// split is one way a deny's term also matches an interface name and its index
// sent as two arguments: head matches the name and tail the index. A word
// splits into two words; a pattern into two patterns, and the tail matches
// only an argument shaped as an index.
type split struct {
	head, tail string
	word       bool
}

var (
	// splitWord is a word that names an interface with its index:
	// `GigabitEthernet1`, `Port-channel2`, `GigabitEthernet1/0/1.100`.
	splitWord = regexp.MustCompile(`^(\pL[\pL-]*)([0-9][0-9/.:]*)$`)
	// indexShape is an argument a split tail may be: what IOS-XE sent after
	// `GigabitEthernet` for `Gi1` (L21), widened to slot, subinterface and
	// channel separators, which are unmeasured.
	indexShape = regexp.MustCompile(`^[0-9][0-9/.:]*$`)
)

// splits lists the ways a deny's term also matches an interface name split
// from its index, where the platform splits them, and refuses a pattern whose
// split it cannot read.
func splits(t Term, classes map[string][]string, n Normalize) ([]split, error) {
	if !n.SplitsInterfaceNames {
		return nil, nil
	}
	if t.Kind == Word {
		if m := splitWord.FindStringSubmatch(t.Text); m != nil {
			return []split{{head: m[1], tail: m[2], word: true}}, nil
		}
		return nil, nil
	}
	var out []split
	for _, pat := range termPatterns(t, classes) {
		ss, err := stems(pat)
		if err != nil {
			return nil, fmt.Errorf("%s: the platform sends an interface name and its index as two arguments (spec §3 rule 5) and %w",
				termName(t, pat), err)
		}
		for _, s := range ss {
			if len(s.rest) > 0 && s.rest[0].Op == syntax.OpEndText {
				continue // the name ends the argument: no index follows it
			}
			// The head is the stem, and on a platform that may send what was
			// typed its abbreviations; where anything may follow the stem,
			// the head is the stem and any more of a name.
			var head string
			switch {
			case s.anything:
				head = `^\pL[\pL\-]*$`
			default:
				stem := &syntax.Regexp{Op: syntax.OpLiteral, Flags: s.flags, Rune: s.stem}
				if !n.ExpandsAbbreviations {
					stem = prefixes(s.stem, s.flags)
				}
				head = (&syntax.Regexp{Op: syntax.OpConcat, Flags: s.flags, Sub: []*syntax.Regexp{
					{Op: syntax.OpBeginText, Flags: s.flags}, stem}}).String()
				if len(s.rest) == 0 || matchesAnything(s.rest) {
					head += `[\pL\-]*$`
				} else {
					head += `$`
				}
			}
			tail := (&syntax.Regexp{Op: syntax.OpConcat, Flags: s.flags,
				Sub: append([]*syntax.Regexp{{Op: syntax.OpBeginText, Flags: s.flags}}, s.rest...)}).String()
			out = append(out, split{head: head, tail: tail})
		}
	}
	return out, nil
}

// CheckDeny refuses a deny rule whose regex or class terms cannot be widened
// as a platform with dialect n needs (spec §3 rules 4 and 5). A class classes
// does not define is skipped: that is another check's refusal.
func CheckDeny(rule string, classes map[string][]string, n Normalize) error {
	_, err := compileRule(Deny, rule, "", classes, n)
	return err
}

// termPatterns are the patterns behind a regex or class term, and none for any
// other.
func termPatterns(t Term, classes map[string][]string) []string {
	switch t.Kind {
	case Regex:
		return []string{t.Text}
	case Class:
		return classes[t.Text]
	}
	return nil
}

func termName(t Term, pattern string) string {
	if t.Kind == Class {
		return fmt.Sprintf("@%s pattern %q", t.Text, pattern)
	}
	return "/" + t.Text + "/"
}
