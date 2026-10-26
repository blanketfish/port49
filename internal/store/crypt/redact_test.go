package crypt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// A Key prints no key bytes under any verb or as JSON, in any spelling of
// them, whether held by value, by pointer or in the rotation window.
func TestAKeyPrintsNoBytes(t *testing.T) {
	var k Key
	k.ID = "v2"
	copy(k.Bytes[:], "fake-encryption-key-32-bytes!!!!")
	prev := k
	prev.ID = "v1"
	keys := Keys{Current: k, Previous: &prev}
	raw := k.Bytes[:]
	forms := []string{string(raw), hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), fmt.Sprint(raw),
		fmt.Sprint(k.Bytes), string(mustJSON(t, raw)), string(mustJSON(t, k.Bytes))}
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
