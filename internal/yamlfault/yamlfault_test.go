package yamlfault

import (
	"errors"
	"io"
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

// OneDocument refuses anything after the first document, and quotes none of
// it: a second document that does not even parse is still refused as one.
func TestOneDocumentRefusesASecondDocument(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want error
	}{
		{"a: 1\n", nil},
		{"", nil},
		{"a: 1\n---\nb: 2\n", ErrSecondDocument},
		{"a: 1\n---\n[unclosed\n", ErrSecondDocument},
		{"a: 1\n---\n", ErrSecondDocument},
		{"a: 1\n---\n# c\n", ErrSecondDocument},
		{"a: 1\n# c\n", nil},
	} {
		dec := yaml.NewDecoder(strings.NewReader(c.raw))
		var v map[string]any
		if err := dec.Decode(&v); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("%q: the first document: %v", c.raw, err)
		}
		err := OneDocument(dec)
		if !errors.Is(err, c.want) || (err != nil && strings.Contains(err.Error(), "unclosed")) {
			t.Errorf("%q: %v, want %v", c.raw, err, c.want)
		}
	}
}

// A removed key is refused wherever it stands, naming its replacement and
// its line; the same word as a value is not a key.
func TestReplacedRefusesARemovedKeyAnywhere(t *testing.T) {
	m := map[string]string{"secret_env": "secret_ref"}
	for _, c := range []struct {
		raw  string
		want string
	}{
		{"keys:\n  k:\n    current: {version: 1, secret_env: X}\n", "line 3: secret_env was replaced by secret_ref"},
		{"secret_env: X\n", "line 1: secret_env was replaced by secret_ref"},
		{"x: secret_env\n", ""},
		{"a: [\n", ""},
	} {
		err := Replaced([]byte(c.raw), m)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%q: %v, want %q", c.raw, err, c.want)
		}
	}
}
