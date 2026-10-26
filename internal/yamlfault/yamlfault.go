// Package yamlfault is a yaml.v3 decode error as port49 shows it: each
// fault's line and a fixed category, and no text from the document. yaml.v3
// quotes a value, a field name, an anchor or a tag from the file in its
// errors, and any of those may be a secret pasted where a file names only a
// key or its environment variable: port49d.yaml's keys, or an inventory
// record's key_ref pin. The line is what an operator fixes the file by.
package yamlfault

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Of is err, a yaml.v3 decode error, as it is shown.
func Of(err error) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return errors.New(faultAt(err.Error(), syntaxCategory(err.Error())))
	}
	parts := make([]string, len(te.Errors))
	for i, e := range te.Errors {
		parts[i] = faultAt(e, typeCategory(e))
	}
	return errors.New(strings.Join(parts, "; "))
}

// Described is err, a yaml.v3 decode error, as a strict decode of a policy
// file shows it: the line, the kind of fault and the types involved, in words
// built here from an allowlist. yaml.v3 quotes a value, a tag, a field name or
// an anchor from the document in its text, so none of that text is passed
// through, whatever it looks like: a pasted key is a value, a tag or a field
// name to the parser (re-review 8, I1). An error the caller's own unmarshal
// hook raised, which yaml.v3 returns as it is, passes unchanged.
func Described(err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		parts := make([]string, len(te.Errors))
		for i, e := range te.Errors {
			parts[i] = describeEntry(e)
		}
		return errors.New(strings.Join(parts, "; "))
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "yaml: ") {
		return err
	}
	switch m := decodeAs.FindStringSubmatch(msg); {
	case strings.HasPrefix(msg, "yaml: unknown anchor"):
		return errors.New("an unknown anchor was referenced; quote a rule that starts with *")
	case m != nil:
		at := ""
		if m[1] != "" {
			at = "line " + m[1] + ": "
		}
		return errors.New(at + "cannot decode a " + coreTag(m[2]) + " value as a " + coreTag(m[3]))
	}
	return errors.New(faultAt(msg, syntaxCategory(msg)))
}

var (
	// yaml.v3's own spellings of a type error, anchored at both ends so the
	// value between can hold any text. Only the captures marked as types are
	// ever printed, and only after the checks below.
	entryLine    = regexp.MustCompile(`(?s)^line (\d+): (.*)$`)
	entryValue   = regexp.MustCompile(`(?s)^cannot (unmarshal|decode) (\S*)(?: .*)? into ([^\s]+)$`)
	entryField   = regexp.MustCompile(`(?s)^field .* not found in type ([^\s]+)$`)
	entryKey     = regexp.MustCompile(`(?s)^mapping key .* already defined at line (\d+)$`)
	decodeAs     = regexp.MustCompile(`(?s)^yaml: (?:line (\d+): )?cannot decode (\S*) .* as a (\S+)$`)
	goTypeName   = regexp.MustCompile(`^[\w.*\[\]]+$`)
	coreTagNames = map[string]bool{"!!str": true, "!!int": true, "!!bool": true, "!!float": true, "!!null": true,
		"!!map": true, "!!seq": true, "!!timestamp": true, "!!binary": true, "!!merge": true}
)

// coreTag is tag if it is a YAML core tag, else a fixed word for a custom one.
func coreTag(tag string) string {
	if coreTagNames[tag] {
		return tag
	}
	return "custom tag"
}

// typeName is t if it reads as a Go type name, else "a type".
func typeName(t string) string {
	if goTypeName.MatchString(t) {
		return t
	}
	return "a type"
}

func describeEntry(e string) string {
	m := entryLine.FindStringSubmatch(e)
	if m == nil {
		return "a value port49 could not decode"
	}
	at, rest := "line "+m[1]+": ", m[2]
	if v := entryValue.FindStringSubmatch(rest); v != nil {
		// The value sits between the tag and " into <Go type>": the type is
		// what follows the last " into ", and only a type name is shown.
		if i := strings.LastIndex(rest, " into "); i >= 0 {
			tag := coreTag(v[2])
			if tag == "custom tag" {
				return at + "cannot decode a value with a custom tag"
			}
			return at + "cannot " + v[1] + " a " + tag + " value into " + typeName(rest[i+len(" into "):])
		}
	}
	if f := entryField.FindStringSubmatch(rest); f != nil {
		return at + "an unknown field in type " + typeName(f[1])
	}
	if k := entryKey.FindStringSubmatch(rest); k != nil {
		return at + "a mapping key already defined at line " + k[1]
	}
	return at + "a value port49 could not decode"
}

// faultLine is the line yaml.v3 opens a message with, before any document
// text.
var faultLine = regexp.MustCompile(`^(?:yaml: )?line (\d+):`)

func faultAt(msg, category string) string {
	if m := faultLine.FindStringSubmatch(msg); m != nil {
		return "line " + m[1] + ": " + category
	}
	return category
}

// typeCategory names one *yaml.TypeError entry. It reads the message only to
// choose among fixed strings; a secret that happens to contain one of these
// phrases changes the category, never what is printed.
func typeCategory(msg string) string {
	msg = faultLine.ReplaceAllString(msg, "")
	switch {
	case strings.HasPrefix(msg, " cannot unmarshal "):
		return "a value of the wrong type"
	case strings.Contains(msg, " already set in type "), strings.HasPrefix(msg, " mapping key "):
		return "a key given twice"
	case strings.HasPrefix(msg, " field "):
		return "an unknown field"
	}
	return "a value that does not fit the schema"
}

func syntaxCategory(msg string) string {
	switch {
	case strings.HasPrefix(msg, "yaml: unknown anchor"), strings.HasPrefix(msg, "yaml: anchor"),
		strings.Contains(msg, "aliasing"):
		return "an unknown anchor or alias"
	case strings.Contains(msg, " tag"):
		return "an unknown tag"
	}
	return "a yaml syntax error"
}

// ErrSecondDocument is a file holding a YAML document after its first.
var ErrSecondDocument = errors.New("holds more than one YAML document")

// OneDocument refuses a document after the one dec has decoded: a single
// Decode ignores everything past a `---`, and an ignored block is a file that
// reads one way and runs another (decision 53 ruling 6). A second document
// that does not parse is still a second document, and so is a read error:
// callers pass an in-memory reader. It quotes nothing.
func OneDocument(dec *yaml.Decoder) error {
	var next yaml.Node
	if err := dec.Decode(&next); errors.Is(err, io.EOF) {
		return nil
	}
	return ErrSecondDocument
}

// Replaced refuses a key anywhere in raw that has been removed, naming the
// replacement and the key's line, as `receipt_ttl` is: a removed key is a
// refusal, never an alias (decision 53 ruling 1). Only a mapping key counts, so
// the word as a value is left alone. A file that does not parse returns nil:
// the strict decode reports it, in its own fixed text. Nothing of the file but
// the key's own name, which the caller chose, is quoted.
func Replaced(raw []byte, replaced map[string]string) error {
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil {
		return nil
	}
	return replacedIn(&doc, replaced)
}

func replacedIn(n *yaml.Node, replaced map[string]string) error {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if by, ok := replaced[k.Value]; ok && k.Kind == yaml.ScalarNode {
				return fmt.Errorf("line %d: %s was replaced by %s (decision 53 ruling 1)", k.Line, k.Value, by)
			}
		}
	}
	for _, c := range n.Content {
		if err := replacedIn(c, replaced); err != nil {
			return err
		}
	}
	return nil
}
