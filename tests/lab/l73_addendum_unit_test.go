//go:build lab

package lab

import (
	"strings"
	"testing"
)

func TestL71AddendumIsReplacedInPlaceNotAppended(t *testing.T) {
	doc := "# L71\n\nbody\n\n## Addendum 2026-10-18: v (`img`)\n\nProbed by TestL73 (old run); the exchange is `x`.\n\nold obs\n\n" +
		"## Addendum 2026-10-01: a person's\n\nHand-written, keep.\n\n## Sources\n\nkept\n"
	sec := func(obs string) string {
		return l71AddendumHeading + "\n\nMeasured today. Probed by TestL73 (run).\n\n" + obs
	}
	once := upsertL71Addendum(doc, sec("first"))
	twice := upsertL71Addendum(once, sec("second"))
	if n := strings.Count(twice, l71AddendumHeading); n != 1 {
		t.Fatalf("two writes must leave one section, got %d:\n%s", n, twice)
	}
	if strings.Contains(twice, "old obs") || strings.Contains(twice, "first") || !strings.Contains(twice, "second") {
		t.Fatalf("the new text replaces the old:\n%s", twice)
	}
	for _, keep := range []string{"Hand-written, keep.", "## Sources", "kept", "body"} {
		if !strings.Contains(twice, keep) {
			t.Fatalf("lost %q:\n%s", keep, twice)
		}
	}
	if strings.Index(twice, l71AddendumHeading) > strings.Index(twice, "## Addendum 2026-10-01") {
		t.Fatalf("the section stays where the old one was:\n%s", twice)
	}
	if got := upsertL71Addendum("# L71\n\nbody\n", sec("x")); !strings.HasSuffix(got, "x\n") || strings.Count(got, "## ") != 1 {
		t.Fatalf("a note with none gets it appended:\n%s", got)
	}
}
