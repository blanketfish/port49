package platform

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/platforms"
)

// Redacted is what a removed word becomes (spec §5.8): the vector keeps its
// shape and length, so the reconciliation join still lines up.
const Redacted = "«redacted»"

// Redaction is one `redact:` pattern (spec §5.8): a command it matches loses
// every word after the first word equal to After, or every word from position
// From on. Match is words, `*` for one word and `**` for any number, anchored
// at both ends as a rule is.
type Redaction struct {
	Match []string `yaml:"match"`
	After string   `yaml:"after,omitempty"`
	From  *int     `yaml:"from,omitempty"`
}

// check refuses a pattern that could not do what it says, or could remove the
// command word the join needs.
func (r Redaction) check() error {
	stars := 0
	for _, w := range r.Match {
		switch {
		case w == "**":
			stars++
		case w == "*":
		case w == "" || strings.ContainsAny(w, " \t/@"):
			return fmt.Errorf("match word %q: a pattern is words, * and **, with no regex or class", w)
		}
	}
	switch {
	case len(r.Match) == 0:
		return errors.New("match is required: the command the pattern applies to")
	case stars > 2:
		return errors.New("match has more than two **; split it into two patterns")
	case (r.After == "") == (r.From == nil):
		return errors.New("give after or from, one of the two")
	case r.After != "" && strings.ContainsAny(r.After, " \t"):
		return fmt.Errorf("after %q is one word", r.After)
	case r.From != nil && *r.From == 0:
		return errors.New("from: 0 is the command word, which the reconciliation join needs; the first argument is 1")
	case r.From != nil && !slices.ContainsFunc(r.Match, func(w string) bool { return w != "*" && w != "**" }):
		// A match of wildcards alone is every command, and `from` then
		// blanks the arguments of every record: the audit trail, not a
		// secret. Name the word the secret follows, with after.
		return errors.New("a match of * and ** alone matches every command, and from would remove the arguments of " +
			"every record; name the command's words, or use after with the word the secret follows")
	}
	return nil
}

// redactions is the built-in table, platforms/redact.yaml, parsed once. An
// embedded file that does not load is a build defect: TestBuiltInRedactionsLoad
// keeps it from reaching a binary.
var redactions = mustLoadRedactions(platforms.Redact)

func mustLoadRedactions(raw []byte) map[string][]Redaction {
	out, err := LoadRedactions(raw)
	if err != nil {
		panic("platform: the built-in redactions do not load: " + err.Error())
	}
	return out
}

// LoadRedactions reads a redaction table: platform name, or `default`, to its
// patterns.
func LoadRedactions(raw []byte) (map[string][]Redaction, error) {
	var out map[string][]Redaction
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if len(out["default"]) == 0 {
		return nil, errors.New("the redaction table has no default list")
	}
	for _, name := range sortedKeys(out) {
		for i, r := range out[name] {
			if err := r.check(); err != nil {
				return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
			}
		}
	}
	return out, nil
}

// Redactions is a platform's built-in patterns, copied: the default list, and
// the platform's own after it. A platform's list adds and never replaces, so
// a word the default removes is removed on every platform.
func Redactions(platformName string) []Redaction {
	list := slices.Clone(redactions["default"])
	if platformName != "default" {
		list = append(list, redactions[platformName]...)
	}
	return list
}

// Redact applies rules to a command's elements — a vector, or the values of
// a record's cmd and cmd-arg pairs — and returns them with every removed word
// replaced by Redacted, and whether any was. Each element is split into words,
// because Junos sends a whole command line as one `cmd`. A pattern's word also
// matches any abbreviation of it — `sec` for `secret` — on every platform,
// whatever expands_abbreviations says: L21 measured expansion for interactive
// SSH only, and a flag that is wrong here leaks a secret into a log that
// cannot take it back, where matching an abbreviation only removes more
// (task 10 review I1). An element no pattern touches comes back as it was.
func Redact(rules []Redaction, elements []string) ([]string, bool) {
	var words []string
	var owner []int
	for i, e := range elements {
		for _, w := range strings.Fields(e) {
			words, owner = append(words, w), append(owner, i)
		}
	}
	hide := make([]bool, len(words))
	redacted := false
	for _, r := range rules {
		if !matchWords(r.Match, words) {
			continue
		}
		start := len(words)
		switch {
		case r.After != "":
			// From the command word itself: in a submode the secret's
			// keyword is the command, `key-string X` in a key chain or
			// `pre-shared-key local X` in an IKEv2 keyring. The command
			// word is still never removed.
			for i := 0; i < len(words); i++ {
				if sameWord(r.After, words[i]) {
					start = i + 1
					break
				}
			}
		case *r.From > 0:
			start = *r.From
		default:
			start = len(words) + *r.From
		}
		for i := max(start, 1); i < len(words); i++ {
			hide[i], redacted = true, true
		}
	}
	if !redacted {
		return elements, false
	}
	out := slices.Clone(elements)
	touched := map[int]bool{}
	for i, h := range hide {
		if h {
			touched[owner[i]] = true
		}
	}
	for e := range touched {
		var rebuilt []string
		for i, w := range words {
			if owner[i] != e {
				continue
			}
			if hide[i] {
				w = Redacted
			}
			rebuilt = append(rebuilt, w)
		}
		out[e] = strings.Join(rebuilt, " ")
	}
	return out, true
}

// RedactRaw applies rules to a record's raw AV pairs: the values of its cmd
// and cmd-arg pairs are the command's elements, a trailing `<cr>` aside, and
// each keeps its own key and separator.
func RedactRaw(rules []Redaction, raw []string) ([]string, bool) {
	var at []int
	var elements []string
	for i, a := range raw {
		j := strings.IndexAny(a, "=*")
		if j < 0 || (a[:j] != "cmd" && a[:j] != "cmd-arg") {
			continue
		}
		at, elements = append(at, i), append(elements, a[j+1:])
	}
	if n := len(elements); n > 0 && elements[n-1] == "<cr>" {
		at, elements = at[:n-1], elements[:n-1]
	}
	redactedElements, redacted := Redact(rules, elements)
	if !redacted {
		return raw, false
	}
	out := slices.Clone(raw)
	for k, i := range at {
		j := strings.IndexAny(out[i], "=*")
		out[i] = out[i][:j+1] + redactedElements[k]
	}
	return out, true
}

// matchWords reports whether pattern matches every word, anchored at both
// ends: a word matches itself or an abbreviation of it (sameWord), `*` one
// word, `**` any number.
func matchWords(pattern, words []string) bool {
	if len(pattern) == 0 {
		return len(words) == 0
	}
	switch pattern[0] {
	case "**":
		for i := 0; i <= len(words); i++ {
			if matchWords(pattern[1:], words[i:]) {
				return true
			}
		}
		return false
	case "*":
		return len(words) > 0 && matchWords(pattern[1:], words[1:])
	}
	return len(words) > 0 && sameWord(pattern[0], words[0]) && matchWords(pattern[1:], words[1:])
}

// sameWord reports whether word, as a pattern writes it, is the word sent:
// equal ignoring case, or a shorter prefix of it, as an abbreviation is.
func sameWord(word, sent string) bool {
	if strings.EqualFold(word, sent) {
		return true
	}
	return sent != "" && len(sent) < len(word) && strings.EqualFold(word[:len(sent)], sent)
}
