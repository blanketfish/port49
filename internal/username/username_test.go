package username

import "testing"

func TestCanonicalForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"already_canonical_unchanged", "alice", "alice"},
		{"lower_cases", "ALICE", "alice"},
		{"strips_domain_prefix", `CORP\Alice`, "alice"},
		{"strips_at_suffix", "alice@corp.example.com", "alice"},
		{"trims_whitespace", "  alice  ", "alice"},
		{"plain_name_unchanged", "bob", "bob"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Canonical(c.in); got != c.want {
				t.Errorf("Canonical(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
