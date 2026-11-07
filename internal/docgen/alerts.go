package docgen

import (
	"fmt"
	"regexp"
	"strings"
)

const alertsPage = "docs/site/reference/alerts.md"

const (
	introStart = "<!-- --8<-- [start:intro] -->"
	introEnd   = "<!-- --8<-- [end:intro] -->"
)

// readmeAlertRow is a row of deploy/alerts/README.md's table: statement, alert, severity, for, why. The
// statement and the why may hold a pipe inside backticks, so the alert cell anchors the match.
var readmeAlertRow = regexp.MustCompile("^\\| (.*?) \\| `([a-z0-9_]+)` \\| (?:page|ticket) \\| [^|]+ \\| (.*) \\|$")

// AlertsPage is the reference page for the shipped alert rules: the README's introduction, then one
// section per rule in the file's order, anchored by the alert's name so a rule's runbook_url can name it.
// It fails, naming them all, if a rule has no row in the README or the README has no intro section.
func AlertsPage(as []Alert, readme []byte) (string, error) {
	text := string(readme)
	start := strings.Index(text, introStart)
	end := strings.Index(text, introEnd)
	if start < 0 || end < start {
		return "", fmt.Errorf("deploy/alerts/README.md has no intro section between %s and %s", introStart, introEnd)
	}
	intro := strings.TrimSpace(text[start+len(introStart) : end])

	type row struct{ statement, why string }
	rows := map[string]row{}
	for _, l := range strings.Split(text, "\n") {
		if m := readmeAlertRow.FindStringSubmatch(l); m != nil {
			rows[m[2]] = row{statement: m[1], why: m[3]}
		}
	}
	var missing []string
	for _, a := range as {
		if _, ok := rows[a.Name]; !ok {
			missing = append(missing, a.Name)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("deploy/alerts/README.md has no table row for: %s", strings.Join(missing, ", "))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "---\ntitle: Alerts\ndescription: %s\n---\n\n%s\n\n# Alerts\n\n%s\n\n"+
		"Each alert below carries a `runbook_url` annotation that points at its section here. "+
		"The metrics each rule reads are in the [metrics reference](metrics.md).\n",
		jsonString("Every shipped alert rule, what fires it and what to do about it."), Header, intro)
	for _, a := range as {
		r := rows[a.Name]
		forDur := a.For
		if forDur == "" {
			forDur = "none"
		}
		fmt.Fprintf(&b, "\n### %s {#%s}\n\n**Severity:** %s. **For:** %s.\n\n%s\n\n```promql\n%s\n```\n\n"+
			"**What it answers:** %s\n\n**Why this threshold, and what to do:** %s\n",
			a.Name, a.Name, a.Severity, forDur, strings.TrimSpace(a.Summary), strings.TrimSpace(a.Expr),
			strings.TrimSpace(r.statement), strings.TrimSpace(r.why))
	}
	return b.String(), nil
}
