package devicemock

import (
	"strings"
	"testing"
)

func TestMergeFragmentReplacesTopLevelKeys(t *testing.T) {
	out, err := MergeFragment([]byte("listen: a\nsession:\n  staleness_ceiling: 0s\nlab:\n  x: 1\n"),
		[]byte("session:\n  staleness_ceiling: 0s\n  max_session_age_default: 1h\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Count(s, "session:") != 1 || !strings.Contains(s, "max_session_age_default: 1h") || !strings.Contains(s, "listen: a") {
		t.Fatalf("%s", s)
	}
}

func TestMergeFragmentRefusesANonMapping(t *testing.T) {
	if _, err := MergeFragment([]byte("a: 1\n"), []byte("- x\n")); err == nil {
		t.Fatal("a list fragment has no top-level keys")
	}
}

// Base and fragment are each one document: a second is refused, not dropped.
func TestMergeFragmentRefusesASecondDocument(t *testing.T) {
	for name, c := range map[string][2]string{
		"base":     {"a: 1\n---\nb: 2\n", "c: 3\n"},
		"fragment": {"a: 1\n", "c: 3\n---\nd: 4\n"},
	} {
		_, err := MergeFragment([]byte(c[0]), []byte(c[1]))
		if err == nil || !strings.Contains(err.Error(), "more than one YAML document") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
