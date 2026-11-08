package docgen

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func metricByName(t *testing.T, name string) Metric {
	t.Helper()
	ms, err := Metrics()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("Metrics() has no %s", name)
	return Metric{}
}

func TestMetricsFindsTheKnownSeries(t *testing.T) {
	c := metricByName(t, "port49_store_calls_total")
	if c.Kind != "counter" || !slices.Contains(c.Labels, "outcome") {
		t.Errorf("port49_store_calls_total = %+v, want a counter with label outcome", c)
	}
	if c.Help == "" {
		t.Errorf("port49_store_calls_total has no help")
	}
	if g := metricByName(t, "port49_connections_max"); g.Kind != "gauge" {
		t.Errorf("port49_connections_max kind = %q, want gauge", g.Kind)
	}
	if h := metricByName(t, "port49_request_seconds"); h.Kind != "histogram" {
		t.Errorf("port49_request_seconds kind = %q, want histogram", h.Kind)
	}
	if a := metricByName(t, "port49_authentication_failures_total"); a.Kind != "counter" {
		t.Errorf("a plain counter's kind = %q, want counter", a.Kind)
	}
	if f := metricByName(t, "port49_devices_quarantined"); f.Kind != "gauge" {
		t.Errorf("a gauge function's kind = %q, want gauge", f.Kind)
	}
	if p := metricByName(t, "process_start_time_seconds"); p.Kind != "collector" {
		t.Errorf("process_start_time_seconds kind = %q, want collector", p.Kind)
	}
}

func TestKeyCollectorSeriesAreGauges(t *testing.T) {
	for _, n := range []string{"port49_key_version_devices", "port49_key_retirement_seconds"} {
		if m := metricByName(t, n); m.Kind != "gauge" {
			t.Errorf("%s kind = %q, want gauge (the key collector emits GaugeValue)", n, m.Kind)
		}
	}
}

func TestStaleKindOverridesFail(t *testing.T) {
	ms := []Metric{{Name: "a", Kind: "collector"}, {Name: "b", Kind: "counter"}}
	if err := applyKindOverrides(ms, map[string]string{"a": "gauge"}); err != nil || ms[0].Kind != "gauge" {
		t.Fatalf("a live override: err = %v, kind = %q", err, ms[0].Kind)
	}
	err := applyKindOverrides(ms, map[string]string{"gone": "gauge", "b": "gauge"})
	if err == nil || !strings.Contains(err.Error(), "gone is not registered") || !strings.Contains(err.Error(), "b is found as a counter") {
		t.Errorf("stale overrides: err = %v", err)
	}
}

func TestProcessParagraphLinksTheAlertsThatReadStartTime(t *testing.T) {
	ms := []Metric{{Name: "process_start_time_seconds", Kind: "collector"}}
	as := []Alert{{Name: "uses_it", Expr: "time() - process_start_time_seconds > 1"}, {Name: "not_it", Expr: "x"}}
	page := MetricsPage(ms, as)
	if !strings.Contains(page, "[uses_it](alerts.md#uses_it)") || strings.Contains(page, "not_it") {
		t.Errorf("the process paragraph does not link exactly the alerts on process_start_time_seconds:\n%s", page)
	}
	if strings.Contains(page, "count that starts at 0") {
		t.Error("the process paragraph still carries the stale uptime claim")
	}
}

func TestNoMetricHasADeviceLabel(t *testing.T) {
	ms, err := Metrics()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		for _, l := range m.Labels {
			switch l {
			case "device", "nas", "device_name", "address":
				t.Errorf("%s has the device label %q; CLAUDE.md allows no device identity in metric labels", m.Name, l)
			}
		}
	}
}

func TestEveryMetricNameIsSnakeCase(t *testing.T) {
	ms, err := Metrics()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Name != strings.ToLower(m.Name) || strings.ContainsAny(m.Name, "-. ") {
			t.Errorf("metric %q is not snake_case", m.Name)
		}
	}
}

func TestAlertsReadsTheShippedRules(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "deploy/alerts/port49.rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	as, err := Alerts(b)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range as {
		if a.Name == "port49_target_down" {
			found = true
			if a.Severity != "page" || a.For != "2m" || !strings.Contains(a.Expr, "up{") || a.Summary == "" {
				t.Errorf("port49_target_down = %+v", a)
			}
		}
	}
	if !found {
		t.Error("Alerts has no port49_target_down")
	}
}

func TestMetricsPageLinksAlertsAndCollapsesProcessSeries(t *testing.T) {
	ms := []Metric{
		{Name: "port49_store_calls_total", Kind: "counter", Help: "Store calls.", Labels: []string{"outcome"}},
		{Name: "port49_connections_max", Kind: "gauge", Help: "The cap."},
		{Name: "process_cpu_seconds_total", Kind: "collector", Help: "CPU."},
	}
	as := []Alert{{Name: "port49_near_cap", Expr: "x / on(instance) port49_connections_max > 0.8"}}
	page := MetricsPage(ms, as)
	for _, want := range []string{
		Header, "## store", "## connections",
		"| `port49_store_calls_total` | counter | `outcome` | Store calls. |  |",
		"[port49_near_cap](alerts.md#port49_near_cap)",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "`process_cpu_seconds_total`") {
		t.Errorf("a process_ series got its own row")
	}
	if !strings.Contains(page, "process_*") {
		t.Errorf("page has no line for the process_* series")
	}
}

// A metric name is matched whole: port49_store_calls must not be linked to an alert on port49_store_calls_total.
func TestAlertMatchIsByWholeName(t *testing.T) {
	ms := []Metric{{Name: "port49_store_calls", Kind: "counter", Help: "h"}}
	as := []Alert{{Name: "a", Expr: "rate(port49_store_calls_total[5m]) > 0"}}
	if strings.Contains(MetricsPage(ms, as), "[a](alerts.md#a)") {
		t.Error("alert on port49_store_calls_total linked to port49_store_calls")
	}
}

// A metric with no name matches no alert: an empty pattern would link every alert to it.
func TestAnEmptyMetricNameLinksNoAlert(t *testing.T) {
	as := []Alert{{Name: "a", Expr: "rate(port49_store_calls_total[5m]) > 0"}}
	if got := alertsOn(Metric{Kind: "counter"}, as); len(got) != 0 {
		t.Errorf("an empty name linked %v", got)
	}
}

func TestMetricsPageIsCurrent(t *testing.T) {
	pages, err := Pages(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := pages[metricsPage]
	if !ok {
		t.Fatalf("Pages has no %s", metricsPage)
	}
	if !strings.Contains(got, "## store") {
		t.Errorf("the metrics page has no store section")
	}
	b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(metricsPage)))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != got {
		t.Errorf("%s is stale: run make docs", metricsPage)
	}
}
