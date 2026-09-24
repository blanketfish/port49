package engine

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Kind is a rule term's kind (spec §4, "Grammar").
type Kind uint8

const (
	// Rest is `**`: zero or more arguments, trailing position only.
	Rest Kind = iota
	// Any is `*`: exactly one argument, any value.
	Any
	// Class is `@name`: one argument in a platform-defined entity class.
	Class
	// Regex is `/re/`: one argument matching an RE2 expression.
	Regex
	// Word is a literal argument, compared case-insensitively.
	Word
)

// Rank is the term's specificity at the position it covers (spec §4). A class
// and a regex share rank 2 deliberately: neither is reliably narrower.
func (k Kind) Rank() int {
	switch k {
	case Rest:
		return 0
	case Any:
		return 1
	case Class, Regex:
		return 2
	default:
		return 3
	}
}

// Term is one parsed term. Text is the word, the class name without `@`, or
// the regex body without its slashes.
type Term struct {
	Kind Kind
	Text string
}

var className = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ParseRule splits a rule into its terms and refuses what the grammar does not
// allow: an empty rule, `**` anywhere but last, a wildcard inside a word, a
// class name that is not snake_case, and a regex RE2 will not compile. The
// regex is compiled the way the matcher compiles it, case-insensitive unless it
// opts out with `(?-i)` (spec §3 rule 3), so a rule that parses is a rule that
// runs.
func ParseRule(rule string) ([]Term, error) {
	fields := strings.Fields(rule)
	if len(fields) == 0 {
		return nil, errors.New("an empty rule matches nothing; remove it")
	}
	terms := make([]Term, 0, len(fields))
	for i, f := range fields {
		switch {
		case f == "**":
			if i != len(fields)-1 {
				return nil, fmt.Errorf("rule %q: `**` is trailing-only (spec §4)", rule)
			}
			terms = append(terms, Term{Kind: Rest})
		case f == "*":
			terms = append(terms, Term{Kind: Any})
		case strings.HasPrefix(f, "@"):
			if !className.MatchString(f[1:]) {
				return nil, fmt.Errorf("rule %q: %q is not a class name; a class is `@` and a snake_case name", rule, f)
			}
			terms = append(terms, Term{Kind: Class, Text: f[1:]})
		case len(f) >= 2 && strings.HasPrefix(f, "/") && strings.HasSuffix(f, "/"):
			body := f[1 : len(f)-1]
			if body == "" {
				return nil, fmt.Errorf("rule %q: an empty regex matches every argument; write `*`", rule)
			}
			if _, err := compileTerm(body); err != nil {
				return nil, fmt.Errorf("rule %q: regex %q: %w", rule, f, err)
			}
			terms = append(terms, Term{Kind: Regex, Text: body})
		case strings.Contains(f, "*"):
			return nil, fmt.Errorf("rule %q: %q puts a wildcard inside a word; a wildcard is a whole term (spec §4)", rule, f)
		default:
			terms = append(terms, Term{Kind: Word, Text: f})
		}
	}
	return terms, nil
}

// CanonicalRule is the rule respaced to single spaces, which is the one
// spelling a blob and a log record carry.
func CanonicalRule(rule string) string { return strings.Join(strings.Fields(rule), " ") }

// compileTerm compiles a regex term or an entity-class pattern: RE2, and
// case-insensitive by default, because a case-sensitive deny fails open —
// `interface management1` would slip past `/^Management/` (spec §3 rule 3).
// A pattern that starts with `(?-i)` turns it back off for itself.
func compileTerm(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern)
}
