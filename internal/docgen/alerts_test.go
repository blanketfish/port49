package docgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeReadme = `# Rules

<!-- --8<-- [start:intro] -->
Intro text.
<!-- --8<-- [end:intro] -->

## The rules

| Statement | Alert | Severity | for | Why this threshold |
|---|---|---|---|---|
| a statement with a ` + "`x{a=~\"b|c\"}`" + ` pipe | ` + "`first_alert`" + ` | page | 2m | Because of two minutes. |
| second statement | ` + "`second_alert`" + ` | ticket | none | Because. |
`

func TestAlertsPageHasOneAnchoredSectionPerRuleInOrder(t *testing.T) {
	as := []Alert{
		{Name: "first_alert", Severity: "page", For: "2m", Expr: "up == 0", Summary: "First is down."},
		{Name: "second_alert", Severity: "ticket", Expr: "x > 1", Summary: "Second."},
	}
	page, err := AlertsPage(as, []byte(fakeReadme))
	if err != nil {
		t.Fatal(err)
	}
	i, j := strings.Index(page, "### first_alert {#first_alert}"), strings.Index(page, "### second_alert {#second_alert}")
	if i < 0 || j < i {
		t.Fatalf("sections missing or out of order (%d, %d):\n%s", i, j, page)
	}
	for _, want := range []string{Header, "Intro text.", "```promql\nup == 0\n```", "First is down.", "Because of two minutes.",
		"**Severity:** page", "**For:** 2m", "**For:** none", `x{a=~"b|c"}`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "start:intro") || strings.Contains(page, "## The rules") {
		t.Errorf("the intro carries a marker or the README's table heading:\n%s", page)
	}
}

func TestAlertsPageNamesARuleWithNoReadmeRow(t *testing.T) {
	as := []Alert{{Name: "first_alert"}, {Name: "orphan_alert"}}
	_, err := AlertsPage(as, []byte(fakeReadme))
	if err == nil || !strings.Contains(err.Error(), "orphan_alert") || strings.Contains(err.Error(), "first_alert") {
		t.Errorf("err = %v, want one naming only orphan_alert", err)
	}
}

func TestAlertsPageNeedsTheIntroMarkers(t *testing.T) {
	if _, err := AlertsPage([]Alert{{Name: "first_alert"}}, []byte("| s | `first_alert` | page | 1m | why |\n")); err == nil {
		t.Error("a README with no intro section was accepted")
	}
}

func TestAlertsPageIsCurrent(t *testing.T) {
	pages, err := Pages(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := pages[alertsPage]
	if !ok {
		t.Fatalf("Pages has no %s", alertsPage)
	}
	b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(alertsPage)))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != got {
		t.Errorf("%s is stale: run make docs", alertsPage)
	}
}
