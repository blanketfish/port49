package docgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func registerFixture(t *testing.T) (map[string]LabRow, string) {
	t.Helper()
	spec := []byte("## 15. Lab register\n\n| ID | Claim | Rests | Platforms | Status |\n|---|---|---|---|---|\n" +
		"| **L10** | Whether `a. b` holds, e.g. on Junos. A second sentence that is left out. | x | all | open |\n" +
		"| **L2** | Whether a `server_msg` is shown, as L10 also asks. | x | all | closed — measured 2026-10-01; `tests/lab/results/L2-arista_eos.md` |\n" +
		"| **L26c** | " + strings.Repeat("word ", 80) + "end. | x | all | **closed** — measured 2026-09-25 |\n")
	reg, err := LabRegister(spec)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, n := range []string{"L2-arista_eos.md", "L2-cisco_nxos.md", "L2-L10-both.md", "L26-other.md", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("# x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return reg, dir
}

func TestTheRegisterPageHasAnAnchoredSectionPerRowInNumericOrder(t *testing.T) {
	reg, dir := registerFixture(t)
	page, err := LabRegisterText(reg, dir)
	if err != nil {
		t.Fatal(err)
	}
	last := -1
	for _, h := range []string{"### L2 {#l2}", "### L10 {#l10}", "### L26c {#l26c}"} {
		i := strings.Index(page, h)
		if i < 0 || i < last {
			t.Fatalf("%q is missing or out of order in:\n%s", h, page)
		}
		last = i
	}
	for _, want := range []string{
		"title: \"Lab register\"", Header,
		"**Open.**", "**Closed**, measured 2026-10-01.",
		"Whether `a. b` holds, e.g. on Junos.",
		"[L10](#l10)", // a cross-reference inside a claim links to its section
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not hold %q", want)
		}
	}
	if strings.Contains(page, "second sentence") {
		t.Error("the claim was not cut at its first sentence")
	}
	if ids := BareLabIDs(page); len(ids) != 0 {
		t.Errorf("page holds bare lab IDs %v", ids)
	}
}

func TestTheRegisterPageLinksEveryNoteOfARow(t *testing.T) {
	reg, dir := registerFixture(t)
	page, err := LabRegisterText(reg, dir)
	if err != nil {
		t.Fatal(err)
	}
	l2 := page[strings.Index(page, "### L2 {#l2}"):strings.Index(page, "### L10 {#l10}")]
	for _, n := range []string{"L2-arista_eos.md", "L2-cisco_nxos.md", "L2-L10-both.md"} {
		if !strings.Contains(l2, "["+n+"]("+resultsURL+n+")") {
			t.Errorf("L2 does not link %s:\n%s", n, l2)
		}
	}
	if strings.Contains(l2, "L26-other.md") || strings.Contains(l2, "README.md") {
		t.Errorf("L2 links a note that is not its own:\n%s", l2)
	}
	l10 := page[strings.Index(page, "### L10 {#l10}"):strings.Index(page, "### L26c {#l26c}")]
	if !strings.Contains(l10, "L2-L10-both.md") {
		t.Error("a note that leads with two IDs is listed under the second as well")
	}
	l26c := page[strings.Index(page, "### L26c {#l26c}"):]
	if !strings.Contains(l26c, "No results note yet.") {
		t.Errorf("a row with no note says so:\n%s", l26c)
	}
}

func TestALongClaimIsCutAtAWordWithAnEllipsis(t *testing.T) {
	reg, dir := registerFixture(t)
	page, err := LabRegisterText(reg, dir)
	if err != nil {
		t.Fatal(err)
	}
	sec := page[strings.Index(page, "### L26c {#l26c}"):]
	if !strings.Contains(sec, "word …") || strings.Contains(sec, "end.") {
		t.Errorf("long claim not cut with an ellipsis:\n%s", sec)
	}
}

func TestTheRegisterPageExplainsOpenClosedAndWhoWins(t *testing.T) {
	reg, dir := registerFixture(t)
	page, err := LabRegisterText(reg, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lab", "**Open**", "**Closed**", "results note", "wins"} {
		if !strings.Contains(page, want) {
			t.Errorf("the introduction does not say %q", want)
		}
	}
}

// The spec's wording of a few rows names the lab machine, a person's availability or a command the product
// no longer has. The site keeps those off its pages, so the page says them in site words.
func TestRowsThatNameTheLabMachineOrARemovedCommandAreReworded(t *testing.T) {
	pages, err := Pages(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	page := pages[LabRegisterPage]
	for _, bad := range []string{"SER8", "Ryan", "devices trust"} {
		if strings.Contains(page, bad) {
			t.Errorf("the register page holds %q", bad)
		}
	}
	spec, err := os.ReadFile(filepath.Join(repoRoot, specPath))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := LabRegister(spec)
	if err != nil {
		t.Fatal(err)
	}
	for id, o := range claimRewordings {
		if !strings.HasPrefix(shortClaim(reg[id].Claim), o.From) {
			t.Errorf("%s: the spec's claim no longer starts %q, so the rewording is stale", id, o.From)
		}
		if !strings.Contains(page, o.Text) {
			t.Errorf("%s: the page does not say its rewording", id)
		}
	}
}

func TestTheRegisterPageIsGeneratedForEverySpecRow(t *testing.T) {
	pages, err := Pages(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	page, ok := pages[LabRegisterPage]
	if !ok {
		t.Fatalf("Pages does not generate %s", LabRegisterPage)
	}
	spec, _ := os.ReadFile(filepath.Join(repoRoot, specPath))
	reg, err := LabRegister(spec)
	if err != nil {
		t.Fatal(err)
	}
	for id := range reg {
		if !strings.Contains(page, "### "+id+" {#"+strings.ToLower(id)+"}") {
			t.Errorf("no section for %s", id)
		}
	}
}
