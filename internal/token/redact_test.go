package token

import (
	"encoding/json"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/secretref/secretreftest"
)

type windowHolder struct{ w TagWindow }

// A TagWindow holds keys derived from the encryption keys. Reached through an
// unexported field, by value, pointer, slice or map, it prints no key under
// any verb, JSON or YAML (re-review 3, M3).
func TestATagWindowPrintsNoKey(t *testing.T) {
	k1, k2 := []byte("fake-tag-key-one-0123456789abcd!"), []byte("fake-tag-key-two-0123456789abcd!")
	w := NewTagWindow(k1, k2)
	var forms [][]byte
	forms = append(forms, secretreftest.Forms(k1)...)
	forms = append(forms, secretreftest.Forms(k2)...)
	holders := map[string]any{"window": w, "pointer": &w, "holder": windowHolder{w}, "slice": []windowHolder{{w}},
		"map": map[string]windowHolder{"k": {w}}, "holder pointer": &windowHolder{w}}
	for name, h := range holders {
		for _, verb := range secretreftest.Verbs {
			if l := secretreftest.Leak([]byte(fmt.Sprintf(verb, h)), forms); l != "" {
				t.Errorf("%s %s carries a key (%s)", name, verb, l)
			}
		}
		for enc, marshal := range map[string]func(any) ([]byte, error){"json": json.Marshal, "yaml": yaml.Marshal} {
			out, err := marshal(h)
			if err != nil {
				t.Fatal(err)
			}
			if l := secretreftest.Leak(out, forms); l != "" {
				t.Errorf("%s %s carries a key (%s)", enc, name, l)
			}
		}
	}
	if !w.Matches(Tag(k2, "leaf-01"), "leaf-01") {
		t.Fatal("the window no longer matches a tag under its second key")
	}
}
