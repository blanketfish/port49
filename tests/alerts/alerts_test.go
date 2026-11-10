package alerts

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/docgen"
)

type rule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type group struct {
	Name  string `yaml:"name"`
	Rules []rule `yaml:"rules"`
}

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func loadRules(t *testing.T) []group {
	t.Helper()
	var f struct {
		Groups []group `yaml:"groups"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "deploy/alerts/port49.rules.yaml")), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Groups) == 0 {
		t.Fatal("deploy/alerts/port49.rules.yaml holds no groups")
	}
	return f.Groups
}

func allRules(t *testing.T) []rule {
	var out []rule
	for _, g := range loadRules(t) {
		out = append(out, g.Rules...)
	}
	return out
}

// Every port49_ name in an expression is one port49 registers (the etcd group's etcd_ names are etcd's).
func TestEveryAlertNamesARegisteredMetric(t *testing.T) {
	names, err := RegisteredNames()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	tok := regexp.MustCompile(`port49_[a-z0-9_]+`)
	for _, r := range allRules(t) {
		found := tok.FindAllString(r.Expr, -1)
		if strings.HasPrefix(r.Alert, "port49_") && len(found) == 0 && !scrapeExpr.MatchString(r.Expr) {
			t.Errorf("%s: its expression names no port49 metric: %s", r.Alert, r.Expr)
		}
		for _, n := range found {
			base := n
			if !have[base] {
				for _, suf := range []string{"_bucket", "_sum", "_count"} {
					if s := strings.TrimSuffix(n, suf); s != n && have[s] {
						base = s
					}
				}
			}
			if !have[base] {
				t.Errorf("%s: %s is not a registered metric", r.Alert, n)
			}
		}
	}
}

// The target rules read Prometheus's own up series for port49's two jobs, which port49 does not register.
var scrapeExpr = regexp.MustCompile(`\bup\{job=~?"port49`)

func TestScrapeExprMatchesOnlyPort49sUpSeries(t *testing.T) {
	for expr, want := range map[string]bool{
		`up{job=~"port49d|port49-broker"} == 0`: true,
		`absent(up{job="port49d"})`:             true,
		`startup{job="port49d"} == 0`:           false,
		`up{job="node"} == 0`:                   false,
	} {
		if got := scrapeExpr.MatchString(expr); got != want {
			t.Errorf("%s: matches %v, want %v", expr, got, want)
		}
	}
}

func TestEveryAlertIsSnakeCaseAndHasASeverity(t *testing.T) {
	name := regexp.MustCompile(`^(port49|etcd)_[a-z0-9_]+$`)
	seen := map[string]bool{}
	for _, r := range allRules(t) {
		if !name.MatchString(r.Alert) {
			t.Errorf("alert %q is not snake_case under port49_ or etcd_", r.Alert)
		}
		if seen[r.Alert] {
			t.Errorf("alert %s is defined twice", r.Alert)
		}
		seen[r.Alert] = true
		if s := r.Labels["severity"]; s != "page" && s != "ticket" {
			t.Errorf("%s: severity %q, want page or ticket", r.Alert, s)
		}
		sum := r.Annotations["summary"]
		if sum == "" {
			t.Errorf("%s: no summary", r.Alert)
		}
		for _, l := range deviceLabels {
			if strings.Contains(sum, "$labels."+l) {
				t.Errorf("%s: the summary names the device label %s", r.Alert, l)
			}
		}
		for k := range r.Labels {
			if k != "severity" {
				t.Errorf("%s: label %s: only severity is set by a rule", r.Alert, k)
			}
		}
	}
}

// deviceLabels are labels that would name a device or a person. source is not one: on the inventory
// metrics it is the connector, a bounded set.
var deviceLabels = []string{"device", "nas", "name", "address", "principal", "subject", "username"}

func TestNoAlertAggregatesByADeviceLabel(t *testing.T) {
	clause := regexp.MustCompile(`\b(?:by|without|on|ignoring|group_left|group_right)\s*\(([^)]*)\)`)
	matcher := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|!=|=)\s*"`)
	for _, r := range allRules(t) {
		var used []string
		for _, m := range clause.FindAllStringSubmatch(r.Expr, -1) {
			for _, l := range strings.Split(m[1], ",") {
				used = append(used, strings.TrimSpace(l))
			}
		}
		for _, m := range matcher.FindAllStringSubmatch(r.Expr, -1) {
			used = append(used, m[1])
		}
		for _, l := range used {
			if slices.Contains(deviceLabels, l) {
				t.Errorf("%s: its expression names the device label %q: %s", r.Alert, l, r.Expr)
			}
		}
	}
}

// RegisteredNames sees a vector with no child, and reads the name out of Desc.String().
func TestRegisteredNamesParsesDescString(t *testing.T) {
	names, err := RegisteredNames()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "port49_connections_shed_total") {
		t.Errorf("port49_connections_shed_total, a vector with no child at construction, is missing from %d names", len(names))
	}
	if !slices.Contains(names, "port49_inventory_syncs_total") {
		t.Error("the inventory constructor's metrics are missing")
	}
}

var readmeRow = regexp.MustCompile("^\\|.*\\| `([a-z0-9_]+)` \\| (?:page|ticket) \\|")

func TestEveryReadmeRowHasARuleAndEveryRuleARow(t *testing.T) {
	var rows, rules []string
	for _, l := range strings.Split(read(t, "deploy/alerts/README.md"), "\n") {
		if m := readmeRow.FindStringSubmatch(l); m != nil {
			rows = append(rows, m[1])
		}
	}
	for _, r := range allRules(t) {
		rules = append(rules, r.Alert)
	}
	sort.Strings(rows)
	sort.Strings(rules)
	if !slices.Equal(rows, rules) {
		t.Errorf("the README table and the rules differ.\nREADME only: %v\nrules only: %v", minus(rows, rules), minus(rules, rows))
	}
}

func minus(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// Helm cannot read outside the chart, so the chart carries a copy, and it is the same bytes.
func TestTheChartCarriesTheSameRules(t *testing.T) {
	if read(t, "deploy/helm/port49/files/port49.rules.yaml") != read(t, "deploy/alerts/port49.rules.yaml") {
		t.Error("deploy/helm/port49/files/port49.rules.yaml differs from deploy/alerts/port49.rules.yaml: copy it over")
	}
}

// promtool checks the cases (make alerts-check); this pins that none is missing.
func TestEveryAlertHasAPromtoolCase(t *testing.T) {
	var f struct {
		Tests []struct {
			Alerts []struct {
				Alertname string `yaml:"alertname"`
				Exp       []any  `yaml:"exp_alerts"`
			} `yaml:"alert_rule_test"`
		} `yaml:"tests"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "deploy/alerts/port49.rules.test.yaml")), &f); err != nil {
		t.Fatal(err)
	}
	fires, quiet := map[string]bool{}, map[string]bool{}
	for _, tc := range f.Tests {
		for _, a := range tc.Alerts {
			if len(a.Exp) > 0 {
				fires[a.Alertname] = true
			} else {
				quiet[a.Alertname] = true
			}
		}
	}
	for _, r := range allRules(t) {
		if !fires[r.Alert] || !quiet[r.Alert] {
			t.Errorf("%s: promtool case where it fires: %v, where it stays quiet: %v", r.Alert, fires[r.Alert], quiet[r.Alert])
		}
	}
}

// The README states hold_ttl's default in prose ("`hold_ttl` 15s", "the 15s `hold_ttl` default"). Each
// statement must be the default the code applies, which is read from config.go rather than copied here.
func TestReadmeHoldTTLDefaultIsTheCodes(t *testing.T) {
	m := regexp.MustCompile(`etcd\.hold_ttl", &e\.HoldTTL, (\d+) \* time\.Second`).FindStringSubmatch(read(t, "internal/config/config.go"))
	if m == nil {
		t.Fatal("internal/config/config.go: the hold_ttl default row was not found")
	}
	readme := read(t, "deploy/alerts/README.md")
	n := 0
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile("`hold_ttl` (\\d+)s"),
		regexp.MustCompile("(\\d+)s `hold_ttl` default"),
	} {
		for _, s := range re.FindAllStringSubmatch(readme, -1) {
			n++
			if s[1] != m[1] {
				t.Errorf("the README says a hold_ttl default of %ss (%q); config.go applies %ss", s[1], s[0], m[1])
			}
		}
	}
	if n == 0 {
		t.Error("the README states no hold_ttl default in either form")
	}
}

// runbookURL is where the docs site explains an alert: site_url from mkdocs.yml, latest, the alerts
// page, the alert's anchor.
func runbookURL(t *testing.T, alert string) string {
	t.Helper()
	var mk struct {
		SiteURL string `yaml:"site_url"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "mkdocs.yml")), &mk); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mk.SiteURL, "https://") || !strings.HasSuffix(mk.SiteURL, "/") {
		t.Fatalf("mkdocs.yml site_url = %q, want an https URL ending in /", mk.SiteURL)
	}
	// site_url is the bare root; a runbook link names latest so it outlives the release it was written for
	return mk.SiteURL + "latest/reference/alerts/#" + alert
}

func TestEveryRuleHasARunbookURL(t *testing.T) {
	for _, r := range allRules(t) {
		if got, want := r.Annotations["runbook_url"], runbookURL(t, r.Alert); got != want {
			t.Errorf("%s: runbook_url = %q, want %q", r.Alert, got, want)
		}
	}
}

// The URL's fragment must be an anchor the generated alerts page really has.
func TestEveryRunbookAnchorExists(t *testing.T) {
	as, err := docgen.Alerts([]byte(read(t, "deploy/alerts/port49.rules.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	page, err := docgen.AlertsPage(as, []byte(read(t, "deploy/alerts/README.md")))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range allRules(t) {
		_, frag, _ := strings.Cut(r.Annotations["runbook_url"], "#")
		if frag == "" || !strings.Contains(page, "{#"+frag+"}") {
			t.Errorf("%s: runbook_url %q names an anchor the alerts page lacks", r.Alert, r.Annotations["runbook_url"])
		}
	}
}

// promtool compares annotations exactly, so each expected alert carries the runbook too.
func TestEveryExpectedAnnotationCarriesTheRunbook(t *testing.T) {
	var f struct {
		Tests []struct {
			Alerts []struct {
				Alertname string `yaml:"alertname"`
				Exp       []struct {
					Annotations map[string]string `yaml:"exp_annotations"`
				} `yaml:"exp_alerts"`
			} `yaml:"alert_rule_test"`
		} `yaml:"tests"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "deploy/alerts/port49.rules.test.yaml")), &f); err != nil {
		t.Fatal(err)
	}
	blocks := 0
	for _, tc := range f.Tests {
		for _, a := range tc.Alerts {
			for _, e := range a.Exp {
				blocks++
				if got, want := e.Annotations["runbook_url"], runbookURL(t, a.Alertname); got != want {
					t.Errorf("%s: exp_annotations runbook_url = %q, want %q", a.Alertname, got, want)
				}
			}
		}
	}
	if blocks == 0 {
		t.Error("no exp_annotations block found")
	}
}

// One recorder serves the alert checks and the metrics reference: RegisteredNames is the names of docgen.Metrics.
func TestRegisteredNamesIsMetrics(t *testing.T) {
	ms, err := docgen.Metrics()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, m := range ms {
		want = append(want, m.Name)
	}
	sort.Strings(want)
	got, err := RegisteredNames()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("RegisteredNames = %v, want %v", got, want)
	}
}
