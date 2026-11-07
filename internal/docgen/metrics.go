package docgen

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/inventory"
)

const metricsPage = "docs/site/reference/metrics.md"

// Metric is one series name port49 registers: its kind, its help text and its label names.
type Metric struct {
	Name, Kind, Help string
	Labels           []string
}

// Alert is one shipped alert rule.
type Alert struct{ Name, Severity, For, Expr, Summary string }

// recorder is a prometheus.Registerer that reads each collector's descriptors and never collects, so a vector
// with no child still counts.
type recorder struct {
	byName map[string]*Metric
	err    error
}

// descString is the form of Desc.String; the Desc exports no name, help or labels.
var descString = regexp.MustCompile(`^Desc\{fqName: ("(?:[^"\\]|\\.)*"), help: ("(?:[^"\\]|\\.)*"), constLabels: \{([^}]*)\}, variableLabels: \{([^}]*)\}\}$`)

var constLabelName = regexp.MustCompile(`(?:^|,)\s*([A-Za-z_][A-Za-z0-9_]*)=`)

func (r *recorder) Register(c prometheus.Collector) error {
	ch := make(chan *prometheus.Desc, 16)
	go func() { c.Describe(ch); close(ch) }()
	kind := kindOf(c)
	for d := range ch {
		m := descString.FindStringSubmatch(d.String())
		if m == nil {
			return fmt.Errorf("unrecognized Desc form %q", d.String())
		}
		name, err := strconv.Unquote(m[1])
		if err != nil {
			return err
		}
		help, err := strconv.Unquote(m[2])
		if err != nil {
			return err
		}
		var labels []string
		for _, l := range constLabelName.FindAllStringSubmatch(m[3], -1) {
			labels = append(labels, l[1])
		}
		for _, l := range strings.Split(m[4], ",") {
			if l = strings.TrimSpace(l); l != "" {
				labels = append(labels, l)
			}
		}
		have, ok := r.byName[name]
		if !ok {
			r.byName[name] = &Metric{Name: name, Kind: kind, Help: help, Labels: labels}
			continue
		}
		// Several collectors can share a name by const label (devices by transport): one metric, all labels.
		for _, l := range labels {
			if !contains(have.Labels, l) {
				have.Labels = append(have.Labels, l)
			}
		}
	}
	return nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// kindOf names the metric type of a collector. A collector that describes many series of its own (the
// process collector) is "collector".
func kindOf(c prometheus.Collector) string {
	// Gauge comes before Counter: a Gauge has every method of a Counter, so it would match the Counter case.
	// GaugeFunc and CounterFunc are one interface (Metric and Collector), which every other metric also
	// satisfies, so it comes last: port49 registers only gauge functions, and a plain Collector is not a Metric.
	switch c.(type) {
	case *prometheus.GaugeVec, prometheus.Gauge:
		return "gauge"
	case *prometheus.CounterVec, prometheus.Counter:
		return "counter"
	case *prometheus.HistogramVec, prometheus.Histogram:
		return "histogram"
	case *prometheus.SummaryVec, prometheus.Summary:
		return "summary"
	case prometheus.GaugeFunc:
		return "gauge"
	}
	return "collector"
}

func (r *recorder) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
}

func (r *recorder) Unregister(prometheus.Collector) bool { return true }

// Metrics is every series port49 registers, sorted by name: both constructors run against a recording
// Registerer.
func Metrics() (out []Metric, err error) {
	r := &recorder{byName: map[string]*Metric{}}
	defer func() {
		if p := recover(); p != nil {
			out, err = nil, fmt.Errorf("recording the registered metrics: %v", p)
		}
	}()
	metrics.New(r)
	inventory.NewMetrics(r)
	for _, m := range r.byName {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if err := applyKindOverrides(out, kindOverrides); err != nil {
		return nil, err
	}
	return out, nil
}

// kindOverrides names the series a custom collector emits whose type the Describe pass cannot see. The key
// collector emits both as GaugeValue, but it emits nothing before WatchKeys runs, so no Collect pass finds it.
var kindOverrides = map[string]string{
	"port49_key_version_devices":    "gauge",
	"port49_key_retirement_seconds": "gauge",
}

// applyKindOverrides sets the kind of each overridden metric. It fails on an override that names a metric that
// is not registered, or whose kind the recorder now finds: the override is stale and must go.
func applyKindOverrides(ms []Metric, overrides map[string]string) error {
	idx := map[string]int{}
	for i, m := range ms {
		idx[m.Name] = i
	}
	var problems []string
	for name, kind := range overrides {
		i, ok := idx[name]
		switch {
		case !ok:
			problems = append(problems, name+" is not registered")
		case ms[i].Kind != "collector":
			problems = append(problems, fmt.Sprintf("%s is found as a %s", name, ms[i].Kind))
		default:
			ms[i].Kind = kind
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("stale kind override: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Alerts reads the alert rules of a Prometheus rules file, in file order.
func Alerts(rules []byte) ([]Alert, error) {
	var f struct {
		Groups []struct {
			Rules []struct {
				Alert       string            `yaml:"alert"`
				Expr        string            `yaml:"expr"`
				For         string            `yaml:"for"`
				Labels      map[string]string `yaml:"labels"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(rules, &f); err != nil {
		return nil, err
	}
	var out []Alert
	for _, g := range f.Groups {
		for _, r := range g.Rules {
			if r.Alert == "" {
				continue
			}
			out = append(out, Alert{Name: r.Alert, Severity: r.Labels["severity"], For: r.For, Expr: r.Expr,
				Summary: r.Annotations["summary"]})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the rules file holds no alerts")
	}
	return out, nil
}

// alertsOn lists the alerts whose expression names m: the series itself, or for a histogram or summary
// its _bucket, _sum or _count series.
func alertsOn(m Metric, as []Alert) []string {
	names := []string{regexp.QuoteMeta(m.Name)}
	if m.Kind == "histogram" || m.Kind == "summary" {
		names = append(names, regexp.QuoteMeta(m.Name)+"_(?:bucket|sum|count)")
	}
	re := regexp.MustCompile(`\b(?:` + strings.Join(names, "|") + `)\b`)
	var out []string
	for _, a := range as {
		if re.MatchString(a.Expr) {
			out = append(out, fmt.Sprintf("[%s](alerts.md#%s)", a.Name, a.Name))
		}
	}
	return out
}

// section is the second word of a metric name: port49_store_calls_total is in "store".
func section(name string) string {
	parts := strings.Split(name, "_")
	if len(parts) < 2 {
		return name
	}
	return parts[1]
}

// MetricsPage is the reference page for the metrics: one section per second word of the name, one row per
// series. The process collector's process_* series are one line.
func MetricsPage(ms []Metric, as []Alert) string {
	var order []string
	groups := map[string][]Metric{}
	process := false
	var processStart Metric
	for _, m := range ms {
		if strings.HasPrefix(m.Name, "process_") {
			process = true
			if m.Name == "process_start_time_seconds" {
				processStart = m
			}
			continue
		}
		s := section(m.Name)
		if _, ok := groups[s]; !ok {
			order = append(order, s)
		}
		groups[s] = append(groups[s], m)
	}
	sort.Strings(order)

	var b strings.Builder
	fmt.Fprintf(&b, "---\ntitle: Metrics\ndescription: %s\n---\n\n%s\n\n# Metrics\n\n"+
		"Every metric port49d and port49-broker export on `/metrics`, with its type, labels and help text, "+
		"read from the registered collectors. Sections group the series by the second word of the name. "+
		"No metric carries a device's identity as a label. The last column links the shipped [alerts](alerts.md) "+
		"whose expression uses the series.\n",
		jsonString("Every metric port49 exports, with its type, labels and meaning."), Header)
	for _, s := range order {
		fmt.Fprintf(&b, "\n## %s\n\n| Metric | Type | Labels | Meaning | Alerts |\n|---|---|---|---|---|\n", s)
		for _, m := range groups[s] {
			labels := ""
			if len(m.Labels) > 0 {
				labels = "`" + strings.Join(m.Labels, "`, `") + "`"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", m.Name, m.Kind, labels, cell(m.Help),
				strings.Join(alertsOn(m, as), ", "))
		}
	}
	if process {
		b.WriteString("\n## process\n\nThe standard Prometheus process collector adds the `process_*` series " +
			"(CPU time, open file descriptors, memory, start time).")
		if links := alertsOn(processStart, as); len(links) > 0 {
			fmt.Fprintf(&b, " `process_start_time_seconds` is read by %s, which gate a refresh timestamp on "+
				"uptime so that a fresh start does not fire them.", strings.Join(links, " and "))
		}
		b.WriteString("\n")
	}
	return b.String()
}
