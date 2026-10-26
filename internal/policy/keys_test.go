package policy

import (
	"strings"
	"testing"
)

// The policy carries its key sets beside key_groups (decision 53 ruling 3):
// names, versions, dates and references, never a secret.
const keyed = keyGrouped + `
keys:
  prod_key:
    current: {version: 3, secret_ref: file:/run/secrets/prod_v3}
    accept:
      - {version: 2, secret_ref: env:PROD_V2, retire_after: 2026-12-01}
  campus_key:
    current: {version: 1, secret_ref: file:/run/secrets/campus}
`

func TestThePolicyCarriesItsKeySets(t *testing.T) {
	p, err := Parse([]byte(keyed), env())
	if err != nil {
		t.Fatal(err)
	}
	if !p.KeysDeclared() || len(p.KeySets()) != 2 || p.KeySets()["prod_key"].Accept[0].RetireAt.IsZero() {
		t.Fatalf("%+v", p.KeySets())
	}
	if q, _ := Parse([]byte(keyGrouped), env()); q.KeysDeclared() || q.KeySets() != nil {
		t.Fatal("a policy with no keys: declares none")
	}
	if q, _ := Parse([]byte(keyGrouped+"keys: {}\n"), env()); !q.KeysDeclared() {
		t.Fatal("keys: {} is declared, and empty")
	}
	// A bare keys: is refused in its own words, not taken for "no block"
	// (pre-flight M8).
	if _, err := Parse([]byte(keyGrouped+"keys:\n"), env()); err == nil || !strings.Contains(err.Error(), "keys: {}") {
		t.Fatalf("a bare keys: %v", err)
	}
}

func TestAKeySetThePolicyCannotUseIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"no ref":     "keys:\n  k:\n    current: {version: 1}\n",
		"pasted":     "keys:\n  k:\n    current: {version: 1, secret_ref: hunter2hunter2}\n",
		"twice":      "keys:\n  k:\n    current: {version: 1, secret_ref: env:A}\n    accept: [{version: 1, secret_ref: env:B}]\n",
		"not a name": "keys:\n  \"hunter2 hunter2\":\n    current: {version: 1, secret_ref: env:A}\n",
	} {
		_, err := Parse([]byte(good+body), env())
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the refusal carries the secret", name)
		}
	}
	// A reference that does not parse may be the secret itself, now in the
	// policy repository: the refusal says to rotate it (pre-flight M12).
	_, err := Parse([]byte(good+"keys:\n  k:\n    current: {version: 1, secret_ref: hunter2hunter2}\n"), env())
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatal("a pasted secret: accepted, or printed in the refusal")
	}
	if !strings.Contains(err.Error(), "rotate it") {
		t.Fatalf("%v", err)
	}
	// A block moved verbatim from port49d.yaml names its replacement, not an
	// unknown field (re-review N6).
	_, err = Parse([]byte(good+"keys:\n  k:\n    current: {version: 1, secret_env: PORT49_KEY_K}\n"), env())
	if err == nil || !strings.Contains(err.Error(), "secret_env was replaced by secret_ref") {
		t.Fatalf("%v", err)
	}
}

// KeySets hands out a deep copy: a caller that edits it, down to a version in
// accept or retired, does not edit the policy.
func TestKeySetsReturnsACopy(t *testing.T) {
	p, err := Parse([]byte(strings.Replace(keyed, "  campus_key:", "    retired: [{version: 1, secret_ref: env:OLD}]\n  campus_key:", 1)), env())
	if err != nil {
		t.Fatal(err)
	}
	got := p.KeySets()
	got["prod_key"].Accept[0].Version = 99
	got["prod_key"].Retired[0].SecretRef = "env:CHANGED"
	delete(got, "campus_key")
	again := p.KeySets()
	if len(again) != 2 || again["prod_key"].Accept[0].Version != 2 || again["prod_key"].Retired[0].SecretRef != "env:OLD" {
		t.Fatal("a caller edited the policy's key sets")
	}
}
