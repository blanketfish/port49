package helm

import "testing"

// Every check on the Go stand-in's render (gorender_test.go). The same checks run on real helm's in
// render_test.go (tag helm).
func TestChartChecksOnTheGoRender(t *testing.T) {
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) { c.fn(t, goRender) })
	}
}
