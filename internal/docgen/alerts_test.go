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

Each rule is a statement. **Edit in the safe direction.** Preamble end.

| Statement | Alert | Severity | for | Why this threshold |
|---|---|---|---|---|
| a statement with a ` + "`x{a=~\"b|c\"}`" + ` pipe | ` + "`first_alert`" + ` | page | 2m | Because of two minutes. |
| second statement | ` + "`second_alert`" + ` | ticket | none | Because. |

## Notes

**A restart is not evidence.** Read the decision log.
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
		"**Severity:** page", "**For:** 2m", "**For:** none", `x{a=~"b|c"}`,
		"**Source:** a statement", "**Why this threshold:** Because of two minutes.",
		"**Edit in the safe direction.** Preamble end.", "## Notes", "**A restart is not evidence.** Read the decision log."} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "start:intro") || strings.Contains(page, "what to do") || strings.Contains(page, "What it answers") {
		t.Errorf("the page carries a marker or promises an action the README does not give:\n%s", page)
	}
}

// The guidance the README holds outside the table (its text above the table and its Notes) reaches the page
// whole, so an edit to the README cannot drop it.
func TestAlertsPageCarriesTheReadmesGuidance(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join(repoRoot, "deploy/alerts/README.md"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := os.ReadFile(filepath.Join(repoRoot, "deploy/alerts/port49.rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	as, err := Alerts(rules)
	if err != nil {
		t.Fatal(err)
	}
	page, err := AlertsPage(as, readme)
	if err != nil {
		t.Fatal(err)
	}
	text := string(readme)
	pre := text[strings.Index(text, "## The rules")+len("## The rules") : strings.Index(text, "\n| Statement")]
	notes := text[strings.Index(text, "## Notes"):]
	for _, want := range []string{pre, notes} {
		if want = strings.TrimSpace(want); !strings.Contains(page, want) {
			t.Errorf("the page lacks the README text %.60q...", want)
		}
	}
	for _, want := range []string{"Edit in the safe direction", "read the decision log"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
}

func TestAlertsPageNeedsTheGuidanceSections(t *testing.T) {
	for _, readme := range []string{
		strings.Replace(fakeReadme, "## Notes", "## Other", 1),
		strings.Replace(fakeReadme, "## The rules", "## Rules", 1),
	} {
		if _, err := AlertsPage([]Alert{{Name: "first_alert"}}, []byte(readme)); err == nil {
			t.Error("a README without its Notes or rules heading was accepted")
		}
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
