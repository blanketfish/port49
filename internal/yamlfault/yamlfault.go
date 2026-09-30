// Package yamlfault is a yaml.v3 decode error as port49 shows it: each
// fault's line and a fixed category, and no text from the document. yaml.v3
// quotes a value, a field name, an anchor or a tag from the file in its
// errors, and any of those may be a secret pasted where a file names only a
// key or its environment variable: port49d.yaml's keys, or an inventory
// record's key_ref pin. The line is what an operator fixes the file by.
package yamlfault

import (
	"errors"
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
