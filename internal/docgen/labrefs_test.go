package docgen

import (
	"strings"
	"testing"
)

var refsReg = map[string]LabRow{
	"L4": {ID: "L4", Open: true}, "L5": {ID: "L5"}, "L15": {ID: "L15", Open: true},
	"L26c": {ID: "L26c"}, "L73": {ID: "L73"},
}

const refsBase = "../reference/lab-register.md"

func TestABareLabIDBecomesALinkToItsAnchor(t *testing.T) {
	got, err := LinkLabIDs("A repeat (L15) passes; L26c too.\n| L4 | x |\n", refsReg, refsBase)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"([L15](../reference/lab-register.md#l15))", "[L26c](../reference/lab-register.md#l26c) too",
		"| [L4](../reference/lab-register.md#l4) |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("got %q, want it to hold %q", got, want)
		}
	}
}

func TestWhatIsAlreadyLinkedOrCodeIsLeftAlone(t *testing.T) {
	keep := "---\ndescription: L15 is in front matter.\n---\n\n" +
		"<!-- L4 in a comment -->\n" +
		"`L4` and ``L5 `x` `` in a span.\n" +
		"```text\nL15 in a fence\n```\n" +
		"[L15](../reference/lab-register.md#l15) and [the L4 note](https://x.example/L4-error.md) and ![L5](a.png).\n" +
		"See <https://x.example/L4> and https://x.example/L5 and tests/lab/results/L73-cisco_nxos.md and L73-cisco_nxos.md.\n" +
		"!!! warning \"Unmeasured L15\"\n    text\n" +
		"[ref]: https://x.example/L4\n" +
		"### L15 {#l15}\n"
	got, err := LinkLabIDs(keep, refsReg, refsBase)
	if err != nil {
		t.Fatal(err)
	}
	if got != keep {
		t.Errorf("a protected span changed:\n%s", got)
	}
	if ids := BareLabIDs(keep); len(ids) != 0 {
		t.Errorf("BareLabIDs reports %v in a page with none", ids)
	}
}

func TestARangeOfLabIDsLinksBothEnds(t *testing.T) {
	got, err := LinkLabIDs("L4-L5 and L4, L5\n", refsReg, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := "[L4](#l4)-[L5](#l5) and [L4](#l4), [L5](#l5)\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLinkingTwiceChangesNothing(t *testing.T) {
	once, err := LinkLabIDs("See L15, and L73 (L26c).\n", refsReg, refsBase)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := LinkLabIDs(once, refsReg, refsBase)
	if err != nil {
		t.Fatal(err)
	}
	if once != twice {
		t.Errorf("second run changed the text:\n%s\n%s", once, twice)
	}
}

func TestAnIDOutsideTheRegisterIsRefused(t *testing.T) {
	_, err := LinkLabIDs("see L99 here\n", refsReg, refsBase)
	if err == nil || !strings.Contains(err.Error(), "L99") {
		t.Fatalf("err = %v, want L99 named", err)
	}
}

func TestARegisterLinkIsRelativeToThePage(t *testing.T) {
	for page, want := range map[string]string{
		"index.md":                       "reference/lab-register.md",
		"reference/alerts.md":            "lab-register.md",
		"admin/devices/juniper-junos.md": "../../reference/lab-register.md",
		"operate/tls.md":                 "../reference/lab-register.md",
	} {
		if got := RegisterLinkFrom(page); got != want {
			t.Errorf("RegisterLinkFrom(%q) = %q, want %q", page, got, want)
		}
	}
}
