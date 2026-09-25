// Package projection renders a composition's command rules into the session
// reply of a platform that never asks port49 about a command (spec §8,
// "Projection for session-only platforms"; §13 decision 22). Junos is the
// case it is built for: its login classes carry permission bits and two
// command regexes, and a matching allow beats a matching deny from any origin
// (§15, L11). The reply is computed from the composed rules, never per role,
// and it is proven not to let the device run a command port49 would deny
// before it is sent; what cannot be proven is refused, and the policy with it
// on that platform.
package projection

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"

	"github.com/rhwendt/port49/internal/engine"
)

// Facts are what a projection's device was measured doing with a command
// regex (spec §15, L9). Each is read in the direction that fails closed until
// a lab note says otherwise.
type Facts struct {
	// CaseSensitive: the device matches a regex against the command in the
	// case it was typed, so a deny spells each letter in both cases. A deny
	// that matched only one case would let `SHOW CONFIGURATION` past a deny
	// of `show configuration`, where port49 compares case-insensitively
	// (spec §3 rule 3).
	CaseSensitive bool
	// DenyMatchesExpanded: the device matches a deny regex against the
	// command with its words expanded, `sh conf` as `show configuration`.
	// Where it does not, a deny of anything narrower than every command is
	// walked past by abbreviating it, so no deny but `.*` is sent (spec §3
	// rule 4).
	DenyMatchesExpanded bool
}

// ereLiteral are the runes ERE reads as operators outside a bracket
// expression, escaped with a backslash. `{`, `}`, `"` and `\` are refused
// rather than escaped: a brace pair is read as a spec §6 placeholder by the
// attribute check, and the wire's handling of a quote or a backslash in an
// attribute value is unmeasured.
const ereLiteral = `.[]()*+?|^$`

// errUnwritable is a rule the device's regex cannot carry faithfully.
var errUnwritable = errors.New("unwritable")

// pipeTail ends every deny: the engine matches a command with its pipeline
// stripped, so port49 denies `clear bgp all | no-more` under a deny of
// `clear bgp all`, and a deny anchored at the rule's last word would miss
// that line on a device that matches the whole line. Whether Junos strips
// the pipeline first is L9's pipe probe; the tail is right either way, since
// it only makes a deny match more.
const pipeTail = `( *\|.*)?`

// ruleERE is one rule as an extended regex over a whole command line, without
// anchors: `show interfaces **` is `show interfaces( .*)?`. deny says which
// side of the reply it lands on, and every choice below is the one that fails
// closed on that side. An allow is as narrow as the rule: lower case, one
// space between words, and no space inside an argument. A deny is as wide:
// every case where the device matches case-sensitively, any run of spaces
// between words, an argument that may hold a space (a quoted one does, and
// the engine never splits it), and the pipe tail.
func ruleERE(rule string, classes map[string][]string, deny bool, f Facts) (string, error) {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i, t := range terms {
		if t.Kind == engine.Rest {
			if i == 0 {
				b.WriteString(".*")
			} else {
				b.WriteString("( .*)?")
			}
			break
		}
		if i > 0 {
			b.WriteString(pick(deny, " +", " "))
		}
		switch t.Kind {
		case engine.Any:
			b.WriteString(pick(deny, ".+", "[^ ]+"))
		case engine.Word:
			w, err := wordERE(t.Text, deny, f)
			if err != nil {
				return "", fmt.Errorf("term %d: %w", i+1, err)
			}
			b.WriteString(w)
		case engine.Regex, engine.Class:
			patterns := []string{t.Text}
			if t.Kind == engine.Class {
				patterns = classes[t.Text]
			}
			if len(patterns) == 0 {
				return "", fmt.Errorf("term %d: @%s has no pattern on this platform", i+1, t.Text)
			}
			var alts []string
			for k, p := range patterns {
				e, err := patternERE(p, deny, f)
				if err != nil {
					return "", fmt.Errorf("term %d, pattern %d: %w", i+1, k+1, err)
				}
				alts = append(alts, e)
			}
			if len(alts) == 1 {
				b.WriteString(alts[0])
			} else {
				b.WriteString("(" + strings.Join(alts, "|") + ")")
			}
		}
	}
	if deny {
		b.WriteString(pipeTail)
	}
	return b.String(), nil
}

func pick(deny bool, ifDeny, ifAllow string) string {
	if deny {
		return ifDeny
	}
	return ifAllow
}

// wordERE is a literal word: printable ASCII only, since the device's
// command line is, and no rune the wire or the attribute check reads.
func wordERE(w string, deny bool, f Facts) (string, error) {
	var b strings.Builder
	for _, r := range w {
		switch {
		case r < 0x21 || r > 0x7e:
			return "", fmt.Errorf("%w: a word holds a rune that is not printable ASCII", errUnwritable)
		case strings.ContainsRune(`{}"\`, r):
			return "", fmt.Errorf("%w: a word holds %q, which the reply cannot carry", errUnwritable, r)
		case strings.ContainsRune(ereLiteral, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteString(letter(r, deny, f))
		}
	}
	return b.String(), nil
}

// letter is one literal rune: a deny's letter in both cases where the device
// is case-sensitive, anything else lower case.
func letter(r rune, deny bool, f Facts) string {
	lo, up := unicode.ToLower(r), unicode.ToUpper(r)
	if deny && f.CaseSensitive && lo != up {
		return "[" + string(lo) + string(up) + "]"
	}
	return string(lo)
}

// patternERE is an RE2 pattern from a regex term or an entity class, read
// as the matcher reads it — case-insensitive, and matching the argument
// anywhere unless it anchors (engine.compileTerm) — as an ERE over that one
// argument. It takes literals, bracket
// expressions, `.`, grouping, alternation, `*`, `+`, `?`, a bounded repeat
// written out, and anchors at the pattern's two ends; anything else refuses
// the pattern rather than guessing at the device's dialect (spec §8,
// "Anchoring is a per-platform property"; §15 L9). So does anything that
// would write an empty group, `()` or `(ge|)`, which POSIX leaves undefined.
func patternERE(pattern string, deny bool, f Facts) (string, error) {
	re, err := syntax.Parse("(?i)"+pattern, syntax.Perl)
	if err != nil {
		return "", err
	}
	re = re.Simplify()
	lead, trail := pick(deny, ".*", "[^ ]*"), pick(deny, ".*", "[^ ]*")
	if re.Op == syntax.OpConcat && len(re.Sub) > 0 {
		subs := re.Sub
		if subs[0].Op == syntax.OpBeginText {
			lead, subs = "", subs[1:]
		}
		if n := len(subs); n > 0 && subs[n-1].Op == syntax.OpEndText {
			trail, subs = "", subs[:n-1]
		}
		re = &syntax.Regexp{Op: syntax.OpConcat, Sub: subs, Flags: re.Flags}
	}
	body, err := ere(re, deny, f)
	if err != nil {
		return "", err
	}
	if body == "" {
		return "", fmt.Errorf("%w: the pattern matches only the empty argument", errUnwritable)
	}
	return lead + "(" + body + ")" + trail, nil
}

func ere(re *syntax.Regexp, deny bool, f Facts) (string, error) {
	switch re.Op {
	case syntax.OpEmptyMatch:
		return "", fmt.Errorf("%w: an empty alternative or group", errUnwritable)
	case syntax.OpLiteral:
		var b strings.Builder
		for _, r := range re.Rune {
			s, err := wordERE(string(r), deny, f)
			if err != nil {
				return "", err
			}
			if re.Flags&syntax.FoldCase == 0 {
				// A literal the pattern made case-sensitive: an allow may take
				// it as written; a deny policy refuses a (?-i) (checkRule).
				// A device that ignores case would read it wider than port49
				// does, so an allow refuses it there.
				if !deny && !f.CaseSensitive && cased(r) {
					return "", fmt.Errorf("%w: a case-sensitive letter on a device that ignores case", errUnwritable)
				}
				s = escaped(r)
			}
			b.WriteString(s)
		}
		return b.String(), nil
	case syntax.OpCharClass:
		if !deny && !f.CaseSensitive && re.Flags&syntax.FoldCase == 0 && slices.ContainsFunc(classRunes(re.Rune), cased) {
			return "", fmt.Errorf("%w: a case-sensitive class on a device that ignores case", errUnwritable)
		}
		return bracket(re.Rune, deny)
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return pick(deny, ".", "[^ ]"), nil
	case syntax.OpCapture:
		s, err := ere(re.Sub[0], deny, f)
		if err == nil && s == "" {
			err = fmt.Errorf("%w: an empty group", errUnwritable)
		}
		return "(" + s + ")", err
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		s, err := ere(re.Sub[0], deny, f)
		op := map[syntax.Op]string{syntax.OpStar: "*", syntax.OpPlus: "+", syntax.OpQuest: "?"}[re.Op]
		return "(" + s + ")" + op, err
	case syntax.OpRepeat:
		// A brace is read as a placeholder by the attribute check, so a
		// bounded repeat is written out; an unbounded one is n copies and a star.
		if re.Max > 8 || (re.Max < 0 && re.Min > 8) {
			return "", fmt.Errorf("%w: a repeat above 8", errUnwritable)
		}
		s, err := ere(re.Sub[0], deny, f)
		if err != nil {
			return "", err
		}
		out := strings.Repeat("("+s+")", re.Min)
		if re.Max < 0 {
			return out + "(" + s + ")*", nil
		}
		return out + strings.Repeat("("+s+")?", re.Max-re.Min), nil
	case syntax.OpConcat:
		var b strings.Builder
		for _, sub := range re.Sub {
			s, err := ere(sub, deny, f)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		return b.String(), nil
	case syntax.OpAlternate:
		alts := make([]string, len(re.Sub))
		for i, sub := range re.Sub {
			s, err := ere(sub, deny, f)
			if err != nil {
				return "", err
			}
			alts[i] = s
		}
		return strings.Join(alts, "|"), nil
	}
	return "", fmt.Errorf("%w: the pattern uses an operator the device's regex is not measured to take", errUnwritable)
}

// escaped is one printable rune as an ERE literal, in the case it is written.
func escaped(r rune) string {
	if strings.ContainsRune(ereLiteral, r) {
		return `\` + string(r)
	}
	return string(r)
}

// cased reports whether r has another case.
func cased(r rune) bool { return unicode.SimpleFold(r) != r }

// classRunes are the printable ASCII runes a class's ranges hold, the only
// ones bracket writes.
func classRunes(ranges []rune) []rune {
	var out []rune
	for i := 0; i+1 < len(ranges); i += 2 {
		for r := max(ranges[i], 0x21); r <= min(ranges[i+1], 0x7e); r++ {
			out = append(out, r)
		}
	}
	return out
}

// bracket is a character class as a POSIX bracket expression over printable
// ASCII less the space. A class that also admits a space, a rune past ASCII or
// a rune the reply cannot carry is `.` in a deny, which matches more, and
// loses that rune in an allow, which matches less: each the side that fails
// closed.
func bracket(ranges []rune, deny bool) (string, error) {
	in := func(r rune) bool {
		for i := 0; i+1 < len(ranges); i += 2 {
			if ranges[i] <= r && r <= ranges[i+1] {
				return true
			}
		}
		return false
	}
	beyond := in(' ') || in('{') || in('}') || in('"') || in('\\')
	for i := 0; i+1 < len(ranges); i += 2 {
		if ranges[i+1] > 0x7e || ranges[i] < 0x21 {
			beyond = true
		}
	}
	if deny && beyond {
		return ".", nil
	}
	var set []rune
	for r := rune(0x21); r <= 0x7e; r++ {
		if in(r) && !strings.ContainsRune(`{}"\`, r) {
			set = append(set, r)
		}
	}
	if len(set) == 0 {
		return "", fmt.Errorf("%w: a character class with nothing printable in it", errUnwritable)
	}
	if len(set) == 1 {
		// As the class holds it: lower-casing it would take a rune a
		// case-sensitive class does not.
		return escaped(set[0]), nil
	}
	// POSIX: `]` first, `-` last, `^` anywhere but first; runs of three or
	// more of the rest as a range. A backslash is literal inside brackets,
	// and none is ever in one (refused above).
	special := func(r rune) bool { return r == ']' || r == '-' || r == '^' }
	var head, body, tail string
	for i := 0; i < len(set); {
		r := set[i]
		switch r {
		case ']':
			head = "]"
			i++
			continue
		case '-':
			tail = "-"
			i++
			continue
		case '^':
			tail = "^" + tail
			i++
			continue
		}
		j := i
		for j+1 < len(set) && set[j+1] == set[j]+1 && !special(set[j+1]) {
			j++
		}
		if j-i >= 2 {
			body += string(r) + "-" + string(set[j])
		} else {
			body += string(set[i : j+1])
		}
		i = j + 1
	}
	if strings.HasPrefix(tail, "^") && head == "" && body == "" {
		// `^` and `-` alone: `^` may not open the expression.
		tail = strings.TrimPrefix(tail, "^") + "^"
		return "[" + tail + "]", nil
	}
	return "[" + head + body + tail + "]", nil
}
