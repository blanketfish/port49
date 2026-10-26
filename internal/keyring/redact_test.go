package keyring

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// A Version prints no key bytes under any verb or as JSON, in any spelling
// of them: a Set is held by value in the server's config and the admin
// surface, and one logged struct must not put a device key in the journal.
func TestAVersionPrintsNoSecret(t *testing.T) {
	secret := []byte("fake-device-key-zzz-2")
	s := Set{Ref: "prod_key", Versions: []Version{{Number: 3, Secret: secret}, {Number: 2, Secret: secret, Retired: true}}}
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
