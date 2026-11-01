package crypt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/secretref/secretreftest"
)

// A Key prints no key bytes under any verb or as JSON, in any spelling of
// them, whether held by value, by pointer or in the rotation window.
func TestAKeyPrintsNoBytes(t *testing.T) {
	k := NewKey("v2", [32]byte([]byte("fake-encryption-key-32-bytes!!!!")))
	prev := k
	prev.ID = "v1"
	keys := Keys{Current: k, Previous: &prev}
	kb := k.Bytes()
	raw := kb[:]
	forms := []string{string(raw), hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), fmt.Sprint(raw),
		fmt.Sprint(kb), string(mustJSON(t, raw)), string(mustJSON(t, kb))}
	out := map[string][]byte{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
		out[verb+" key"] = []byte(fmt.Sprintf(verb, k))
		out[verb+" *key"] = []byte(fmt.Sprintf(verb, &k))
		out[verb+" keys"] = []byte(fmt.Sprintf(verb, keys))
	}
	for name, v := range map[string]any{"key": k, "keys": keys} {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out["json "+name] = j
	}
	for name, b := range out {
		for i, f := range forms {
			if bytes.Contains(b, []byte(f)) {
				t.Errorf("%s carries the key (form %d)", name, i) // never the value
			}
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type holder struct{ k Key }
type holderPtr struct{ k *Key }
type holderKeys struct{ ks Keys }

// A Key held in an unexported field, where fmt cannot call its Format, still
// prints no bytes under any verb or as YAML (re-review 2).
func TestAKeyInAnUnexportedFieldPrintsNoBytes(t *testing.T) {
	k := NewKey("v2", [32]byte([]byte("fake-encryption-key-32-bytes!!!!")))
	kb := k.Bytes()
	raw := kb[:]
	forms := secretreftest.Forms(raw)
	holders := map[string]any{"value": holder{k}, "pointer": holderPtr{&k}, "keys": holderKeys{Keys{Current: k, Previous: &k}}}
	for hn, h := range holders {
		for _, verb := range secretreftest.Verbs {
			if l := secretreftest.Leak([]byte(fmt.Sprintf(verb, h)), forms); l != "" {
				t.Errorf("%s %s carries the key (%s)", hn, verb, l)
			}
		}
	}
	for name, x := range map[string]any{"key": k, "pointer": &k, "keys": Keys{Current: k, Previous: &k}} {
		y, err := yaml.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		if l := secretreftest.Leak(y, forms); l != "" {
			t.Errorf("yaml %s carries the key (%s)", name, l)
		}
		if !bytes.Contains(y, []byte("<redacted>")) {
			t.Errorf("yaml %s does not say the key is withheld", name)
		}
	}
}
