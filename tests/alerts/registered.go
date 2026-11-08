// Package alerts checks the shipped alert rules against the metrics port49
// registers (plan 12c, Task 5).
package alerts

import "github.com/blanketfish/port49/internal/docgen"

// RegisteredNames is every metric name port49 registers: docgen.Metrics runs
// both constructors against a recording Registerer, so the metrics reference
// and this check read one list.
func RegisteredNames() ([]string, error) {
	ms, err := docgen.Metrics()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Name
	}
	return out, nil
}
