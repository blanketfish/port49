package platform

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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
	// An error names a word by its position, never quotes it (spec §5.8).
	for i, w := range r.Match {
		switch {
		case w == "**":
			stars++
		case w == "*":
		case w == "" || strings.ContainsAny(w, " \t/@"):
			return fmt.Errorf("match word #%d: a pattern is words, * and **, with no regex or class", i+1)
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
		return errors.New("after is one word")
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

// Redactor says which patterns apply to a platform's records. The daemon's
// handlers take one, so a policy's `platforms:` blocks reach them (spec §5.8).
type Redactor func(platformName string) []Redaction

// BuiltInRedactor is the Redactor with no policy in force: the built-in
// patterns alone.
func BuiltInRedactor(platformName string) []Redaction { return Redactions(platformName) }

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
// (task 10 review I1). A URL's password is replaced whatever the patterns
// say (redactURL). An element nothing touches comes back as it was.
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
	rewritten := make([]bool, len(words))
	for i, w := range words {
		if u, ok := redactURL(w); ok {
			words[i], rewritten[i], redacted = u, true, true
		}
	}
	// A value glued to its keyword, `key=X` or `password:X`, is the word
	// after the keyword: each such word is matched as the two, and a keyword
	// ending in the separator, `password:`, as the keyword (task 15 review
	// I4). A URL is left whole: redactURL read it. A keyword's leading `-`
	// or `/` is an option's, not the keyword's, so `--password=X` is the
	// password (task 15 re-review N1).
	var split []glued
	for i, w := range words {
		j := strings.IndexAny(w, "=:")
		if rewritten[i] || j <= 0 || strings.Contains(w, "://") {
			lead, text := option(w)
			split = append(split, glued{word: i, lead: lead, text: text})
			continue
		}
		lead, text := option(w[:j])
		split = append(split, glued{word: i, lead: lead, text: text, sep: w[j : j+1]})
		if j+1 < len(w) {
			split = append(split, glued{word: i, text: w[j+1:], value: true})
		}
	}
	matched := make([]string, len(split))
	for k, g := range split {
		matched[k] = g.text
	}
	hideSplit := make([]bool, len(split))
	// The command word: the first, or the one after a leading `do`, which is
	// itself read as a command word.
	command := 0
	if len(matched) > 1 && strings.EqualFold(matched[0], "do") {
		command = 1
	}
	for _, r := range rules {
		if !matchWords(r.Match, matched) {
			continue
		}
		start := len(matched)
		switch {
		case r.After != "":
			// From the command word itself: in a submode the secret's
			// keyword is the command, `key-string X` in a key chain or
			// `pre-shared-key local X` in an IKEv2 keyring. The command
			// word is still never removed.
			for k := 0; k < len(matched); k++ {
				if sameWord(r.After, matched[k]) && (k > command || keywordShaped(r.After, matched, k)) {
					start = k + 1
					break
				}
			}
		case *r.From > 0:
			start = *r.From
		default:
			start = len(matched) + *r.From
		}
		for k := max(start, 1); k < len(matched); k++ {
			hideSplit[k], redacted = true, true
		}
	}
	if !redacted {
		return elements, false
	}
	// A hidden keyword part hides its whole word; a hidden value part keeps
	// the keyword and its separator, `key=«redacted»`.
	for k, g := range split {
		switch {
		case !hideSplit[k]:
		case g.value && !hide[g.word]:
			kw := split[k-1]
			words[g.word], rewritten[g.word] = kw.lead+kw.text+kw.sep+Redacted, true
		default:
			hide[g.word] = true
		}
	}
	out := slices.Clone(elements)
	touched := map[int]bool{}
	for i, h := range hide {
		if h || rewritten[i] {
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

// keywordShaped reports whether words[k], the command word, abbreviating
// keyword, reads as the keyword (spec §5.8): the keyword whole, three
// characters or more, one character (`k X` in a key chain), or two followed by
// a bare digit, an encryption type (`sh 7 X` in an EOS IPsec profile). An
// exec `sh ip int br` or `sh run` is not read as `shared-key`; an argument
// matches every abbreviation.
func keywordShaped(keyword string, words []string, k int) bool {
	w := words[k]
	switch {
	case strings.EqualFold(w, keyword), len(w) >= 3, len(w) == 1:
		return true
	case len(w) == 2:
		return k+1 < len(words) && len(words[k+1]) == 1 && words[k+1][0] >= '0' && words[k+1][0] <= '9'
	}
	return false
}

// glued is one word as Redact matches it: a whole word, or the keyword or
// the value part of one glued with sep, with an option's leading `-` or `/`
// as lead.
type glued struct {
	word  int
	lead  string
	text  string
	sep   string
	value bool
}

// option splits an option's leading `-` and `/` from w; a word of nothing
// else is left whole.
func option(w string) (lead, text string) {
	text = strings.TrimLeft(w, "-/")
	if text == "" {
		return "", w
	}
	return w[:len(w)-len(text)], text
}

// AllRedactions is every built-in pattern, the default list and every
// platform's: what redacts text that belongs to no one platform, such as a
// line quoting a policy the daemon refused.
func AllRedactions() []Redaction {
	var all []Redaction
	for _, name := range sortedKeys(redactions) {
		all = append(all, redactions[name]...)
	}
	return all
}

// RedactQuoted is line with every quoted value in it — "…" as %q writes one,
// or `…` — redacted word by word as a rule is (RedactRule), and the rest
// left as it was. A line that quotes policy text, an error or a report,
// goes to a log like any other (spec §5.8).
func RedactQuoted(rules []Redaction, line string) string {
	var out strings.Builder
	for i := 0; i < len(line); {
		var quoted, value string
		switch line[i] {
		case '"':
			q, err := strconv.QuotedPrefix(line[i:])
			if err != nil {
				break
			}
			quoted = q
			value, _ = strconv.Unquote(q)
		case '`':
			if end := strings.IndexByte(line[i+1:], '`'); end >= 0 {
				quoted = line[i : i+end+2]
				value = quoted[1 : len(quoted)-1]
			}
		}
		if quoted == "" {
			out.WriteByte(line[i])
			i++
			continue
		}
		words, redacted := RedactRule(rules, strings.Fields(value))
		switch {
		case !redacted:
			out.WriteString(quoted)
		case quoted[0] == '"':
			out.WriteString(strconv.Quote(strings.Join(words, " ")))
		default:
			out.WriteString("`" + strings.Join(words, " ") + "`")
		}
		i += len(quoted)
	}
	return out.String()
}

// RedactRecord applies rules to a record's raw pairs and its vector, which are
// two spellings of one command: the raw pairs keep a pipeline the engine's
// vector drops, and drop a `<cr>` a vector may keep. Each pattern is judged
// on its own against both forms as sent. Where it removes words from one form
// and matches nothing in the other, the other loses every argument — removing
// more rather than leaving the secret in the form the pattern missed — and
// that holds whatever another pattern did to either form (spec §5.8). The
// results of every pattern are merged: a word any of them removed is removed.
func RedactRecord(rules []Redaction, raw, vector []string) ([]string, []string, bool) {
	at, elements := rawElements(raw)
	// A URL's password is removed wherever it is, pattern or none; what each
	// pattern adds is judged against that.
	baseRaw, urlRaw := Redact(nil, elements)
	baseVector, urlVector := Redact(nil, vector)
	raws, vectors := [][]string{baseRaw}, [][]string{baseVector}
	// Every argument: the rule check refuses this pattern in a file, where it
	// would blank every record; here it applies to one record already found
	// to carry a secret.
	one := 1
	everything := []Redaction{{Match: []string{"**"}, From: &one}}
	redacted := urlRaw || urlVector
	for _, rule := range rules {
		r, _ := Redact([]Redaction{rule}, elements)
		v, _ := Redact([]Redaction{rule}, vector)
		inRaw, inVector := !slices.Equal(r, baseRaw), !slices.Equal(v, baseVector)
		switch {
		case inRaw && !inVector:
			v, _ = Redact(everything, vector)
		case inVector && !inRaw:
			r, _ = Redact(everything, elements)
		case !inRaw:
			continue
		}
		raws, vectors, redacted = append(raws, r), append(vectors, v), true
	}
	if !redacted {
		return raw, vector, false
	}
	out := slices.Clone(raw)
	for k, e := range merge(elements, raws) {
		j := strings.IndexAny(out[at[k]], "=*")
		out[at[k]] = out[at[k]][:j+1] + e
	}
	return out, merge(vector, vectors), true
}

// merge is elements with every word any of outs changed taken from an out
// that changed it. Redact rebuilds an element it touches from its words, one
// for one, so the words of an element line up across every out.
func merge(elements []string, outs [][]string) []string {
	merged := slices.Clone(elements)
	for e, orig := range elements {
		var words []string
		for _, out := range outs {
			if out[e] == orig {
				continue
			}
			if words == nil {
				words = strings.Fields(orig)
			}
			for i, w := range strings.Fields(out[e]) {
				if w != strings.Fields(orig)[i] {
					words[i] = w
				}
			}
		}
		if words != nil {
			merged[e] = strings.Join(words, " ")
		}
	}
	return merged
}

// RedactRule applies rules to a policy rule's words wherever the rule is
// echoed — a record's matched rules, a denial's server_msg — because a rule
// written with a literal secret in it is no safer in a log than a typed one.
// A wildcard, `*` or `**`, is not a secret and keeps its place, so a rule such
// as `username * secret **` is echoed as written.
func RedactRule(rules []Redaction, words []string) ([]string, bool) {
	out, redacted := Redact(rules, words)
	if !redacted {
		return words, false
	}
	redacted = false
	for i, w := range words {
		if w == "*" || w == "**" {
			out[i] = w
		}
		redacted = redacted || out[i] != w
	}
	if !redacted {
		return words, false
	}
	return out, true
}

// RedactRaw applies rules to a record's raw AV pairs: the values of its cmd
// and cmd-arg pairs are the command's elements, a trailing `<cr>` aside, and
// each keeps its own key and separator.
func RedactRaw(rules []Redaction, raw []string) ([]string, bool) {
	at, elements := rawElements(raw)
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

// rawElements is where in raw the command's elements are, and their values:
// the cmd and cmd-arg pairs, a trailing `<cr>` aside.
func rawElements(raw []string) (at []int, elements []string) {
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
	return at, elements
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

// redactURL replaces the password in a URL's userinfo,
// `scheme://user:password@host...` in any scheme, and keeps the scheme, user
// and host, so the audit still shows where a configuration was copied (task 10
// re-review C3). No `after:` pattern can hide part of a word. The userinfo
// ends at the last `@`, so a password holding one, or a path after it,
// removes more rather than less.
func redactURL(word string) (string, bool) {
	i := strings.Index(word, "://")
	if i < 0 {
		return word, false
	}
	rest := word[i+3:]
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return word, false
	}
	colon := strings.Index(rest[:at], ":")
	if colon < 0 {
		return word, false
	}
	return word[:i+3] + rest[:colon+1] + Redacted + rest[at:], true
}

// proseWord is a word of prose as redaction reads it: punctuation separates
// words as whitespace does, so a value glued to `community)` or `community:`
// is still the word after `community` (spec §5.8). A regex's anchors and
// operators, `^`, `$`, `|`, `\`, `*` and `+`, separate too, so a block's
// config check match `^snmp-server community X` is read as its words, and an
// escape, `\s` or `\S`, is one separator, never the word `s`, which would
// read as `secret`'s abbreviation (task 15 re-review 2, R1). The pattern's
// first alternative finds the escapes, which RedactProse skips.
// Over-redaction is the accepted cost.
var proseWord = regexp.MustCompile("\\\\[A-Za-z]|[^\\s()\\[\\]{}<>,;:!?\"'=`^$|\\\\*+]+")

// RedactProse is text redacted as a rule is, first by whitespace, which is
// where a URL's password is found whole, and then by proseWord, with the
// text's punctuation kept where it was: what a report prints of text a
// `platforms:` block wrote, a fallback note or a config check's says.
func RedactProse(patterns []Redaction, text string) string {
	words, _ := RedactRule(patterns, strings.Fields(text))
	text = strings.Join(words, " ")
	var spans [][]int
	for _, sp := range proseWord.FindAllStringIndex(text, -1) {
		if text[sp[0]] != '\\' {
			spans = append(spans, sp)
		}
	}
	words = make([]string, len(spans))
	for i, sp := range spans {
		words[i] = text[sp[0]:sp[1]]
	}
	out, ok := RedactRule(patterns, words)
	if !ok {
		return text
	}
	var b strings.Builder
	last := 0
	for i, sp := range spans {
		b.WriteString(text[last:sp[0]])
		b.WriteString(out[i])
		last = sp[1]
	}
	b.WriteString(text[last:])
	return b.String()
}
