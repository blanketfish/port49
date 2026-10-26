package keyring

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/secretref"
)

// A Version prints no key bytes under any verb or as JSON, in any spelling
// of them: a Set is held by value in the server's config and the admin
// surface, and one logged struct must not put a device key in the journal.
func TestAVersionPrintsNoSecret(t *testing.T) {
	secret := []byte("fake-device-key-zzz-2")
	s := Set{Ref: "prod_key", Versions: []Version{{Number: 3, Secret: secretref.Of(secret)}, {Number: 2, Secret: secretref.Of(secret), Retired: true}}}
	forms := []string{string(secret), hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret),
		fmt.Sprint(secret), string(mustJSON(t, secret))}
	out := map[string][]byte{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
		out[verb] = []byte(fmt.Sprintf(verb, s))
		out[verb+" version"] = []byte(fmt.Sprintf(verb, s.Versions[0]))
	}
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	out["json"] = j
	for name, b := range out {
		for i, f := range forms {
			if bytes.Contains(b, []byte(f)) {
				t.Errorf("%s carries the secret (form %d)", name, i) // never the value
			}
		}
	}
	if !bytes.Contains(out["%+v version"], []byte("3")) {
		t.Errorf("the version number is withheld too: %s", out["%+v version"])
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

type holder struct{ v Version }
type holderPtr struct{ v *Version }
type holderSlice struct{ vs []Version }

// A Version held in an unexported field, where fmt cannot call its Format,
// still prints no bytes under any verb or as YAML, in any spelling of them
// (re-review 2).
func TestAVersionInAnUnexportedFieldPrintsNoSecret(t *testing.T) {
	secret := []byte("fake-device-key-zzz-2")
	v := Version{Number: 3, Secret: secretref.Of(secret)}
	forms := [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret)),
		[]byte(fmt.Sprint(secret)), []byte(fmt.Sprintf("%#v", secret)), []byte("0x66, 0x61"), []byte("0x66 0x61")}
	holders := map[string]any{"value": holder{v}, "pointer": holderPtr{&v}, "slice": holderSlice{[]Version{v}},
		"map": map[string]holder{"k": {v}}}
	for hn, h := range holders {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d", "%q", "%t", "%c"} {
			out := []byte(fmt.Sprintf(verb, h))
			for i, f := range forms {
				if bytes.Contains(out, f) {
					t.Errorf("%s %s carries the secret (form %d)", hn, verb, i)
				}
			}
		}
	}
	for name, x := range map[string]any{"version": v, "pointer": &v, "set": Set{Ref: "k", Versions: []Version{v}}} {
		y, err := yaml.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		for i, f := range forms {
			if bytes.Contains(y, f) {
				t.Errorf("yaml %s carries the secret (form %d)", name, i)
			}
		}
		if !bytes.Contains(y, []byte("<redacted>")) {
			t.Errorf("yaml %s withholds nothing it should say", name)
		}
	}
}
