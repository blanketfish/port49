package k8sid

import (
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]ID{
		"system:serviceaccount:netops:oxidized":     {"netops", "oxidized"},
		"system:serviceaccount:a:b":                 {"a", "b"},
		"system:serviceaccount:net-ops-1:backup.v2": {"net-ops-1", "backup.v2"},
		"system:serviceaccount:kube-system:default": {"kube-system", "default"},
	} {
		got, err := Parse(in)
		if err != nil || got != want || got.String() != in {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	for _, in := range []string{
		"", "system:serviceaccount:", "system:serviceaccount:netops", "system:serviceaccount:netops:",
		"system:serviceaccount::oxidized", "System:serviceaccount:netops:oxidized",
		"system:serviceaccount:NetOps:oxidized", "system:serviceaccount:netops:Oxidized",
		"system:serviceaccount:-netops:oxidized", "system:serviceaccount:netops-:oxidized",
		"system:serviceaccount:netops:oxidized:extra", "system:serviceaccount:net_ops:oxidized",
		"system:serviceaccount:netops:a..b", "system:serviceaccount:netops:.a", "system:serviceaccount:netops:a.",
		"system:serviceaccount:" + strings.Repeat("a", 64) + ":x",
		"system:serviceaccount:netops:" + strings.Repeat("a", 254),
		"system:serviceaccount:netops:oxi dized", "system:serviceaccount:netops:oxidized\n",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q parsed", in)
		}
	}
	if _, err := Parse("user:alice@example.com"); !errors.Is(err, ErrNotServiceAccount) {
		t.Fatalf("another form: %v", err)
	}
}

// Review Focus 5: a name of 253 bytes, the principal 339, parses whole.
func TestTheLongestServiceAccountParses(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	ns := strings.Repeat("n", 63)
	p := Prefix + ns + ":" + name
	if len(name) != 253 || len(p) != MaxLen {
		t.Fatalf("lengths %d %d", len(name), len(p))
	}
	if id, err := Parse(p); err != nil || id.Name != name || id.Namespace != ns {
		t.Fatalf("%v %v", id, err)
	}
}
