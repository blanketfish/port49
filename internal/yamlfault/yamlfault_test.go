package yamlfault

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Each decode fault is its line and a fixed category, and nothing of the
// document: the value, the key, the anchor or the tag may be a secret.
func TestOfNamesTheLineAndCategoryOnly(t *testing.T) {
	const secret = "Sx9qT4vWz7Kp"
	type doc struct {
		Keys map[string]struct {
			Version int `yaml:"version"`
		} `yaml:"keys"`
	}
	for _, c := range []struct{ body, want string }{
		{"keys:\n  k:\n    version: " + secret + "\n", "line 3: a value of the wrong type"},
		{"keys:\n  k:\n    version: 1\n    " + secret + ": 1\n", "line 4: an unknown field"},
		{"keys:\n  k: {version: 1}\n  k: {version: 2}\n", "line 3: a key given twice"},
		{"keys: *" + secret + "\n", "an unknown anchor or alias"},
		{"keys: !" + secret + " x\n", "a value of the wrong type"},
		{"keys: [" + secret + "\n", "a yaml syntax error"},
	} {
		var d doc
		dec := yaml.NewDecoder(strings.NewReader(c.body))
		dec.KnownFields(true)
		err := dec.Decode(&d)
		if err == nil {
			t.Fatalf("%q decoded", c.body)
		}
		got := Of(err).Error()
		if !strings.Contains(got, c.want) || strings.Contains(got, secret[:6]) {
			t.Errorf("%q: got %q, want %q and no document text", c.body, got, c.want)
		}
	}
}
