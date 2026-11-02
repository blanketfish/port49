// Package alerts checks the shipped alert rules against the metrics port49
// registers (plan 12c, Task 5).
package alerts

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/inventory"
)

// recorder is a prometheus.Registerer that keeps the name of each collector's
// descriptors and never collects, so a vector with no child still counts.
type recorder struct{ names map[string]bool }

var fqName = regexp.MustCompile(`fqName: "([^"]+)"`)

func (r *recorder) Register(c prometheus.Collector) error {
	ch := make(chan *prometheus.Desc, 16)
	go func() { c.Describe(ch); close(ch) }()
	for d := range ch {
		// prometheus.Desc exports no name; its String carries it.
		m := fqName.FindStringSubmatch(d.String())
		if m == nil {
			return fmt.Errorf("no fqName in %q", d.String())
		}
		r.names[m[1]] = true
	}
	return nil
}

func (r *recorder) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
}

func (r *recorder) Unregister(prometheus.Collector) bool { return true }

// RegisteredNames is every metric name port49 registers: both constructors
// run against a recording Registerer.
func RegisteredNames() ([]string, error) {
	r := &recorder{names: map[string]bool{}}
	metrics.New(r)
	inventory.NewMetrics(r)
	out := make([]string, 0, len(r.names))
	for n := range r.names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
