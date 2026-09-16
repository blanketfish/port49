package authen

import "testing"

func TestCanonicalForms(t *testing.T) {
	cases := map[string]string{
		"ALICE":                  "alice", // lower-casing
		`CORP\Alice`:             "alice", // DOMAIN\user -> user
		"alice@corp.example.com": "alice", // user@realm -> user
		"  alice  ":              "alice", // surrounding whitespace
		"bob":                    "bob",   // plain name unchanged
	}
	for in, want := range cases {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}
