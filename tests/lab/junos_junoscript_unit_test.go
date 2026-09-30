//go:build lab

package lab

import (
	"slices"
	"testing"
)

// These run without a device: the junoscript deny's isolation verdict.

func jsdRun(cells map[string]string) l26cRun {
	r := newL26cRun()
	for k, v := range cells {
		r.cells[k] = v
	}
	return r
}

func TestJSDVerdict(t *testing.T) {
	const show, xml, abbr, p830 = "show version", "entry: xml-mode netconf", "entry: xml-mod netconf", "port 830"
	probes := []string{show, xml, abbr, p830}

	// The measured run: W and L refuse, C reaches the canonical probes and
	// refuses the abbreviation like everyone else.
	runs := map[string]l26cRun{
		"W": jsdRun(map[string]string{show: "ran", xml: "refused", abbr: "refused", p830: "refused"}),
		"L": jsdRun(map[string]string{show: "ran", xml: "refused", abbr: "refused", p830: "refused"}),
		"C": jsdRun(map[string]string{show: "ran", xml: "hello", abbr: "refused", p830: "hello"}),
	}
	readings, unisolated := jsdVerdict(runs, probes)
	for _, c := range []struct{ key, want string }{
		{"W " + show, "reached"}, {"W " + xml, "deny"}, {"L " + p830, "deny"},
		{"W " + abbr, "unisolated"}, {"L " + abbr, "unisolated"},
	} {
		if readings[c.key] != c.want {
			t.Errorf("%s: got %q, want %q", c.key, readings[c.key], c.want)
		}
	}
	if len(unisolated) != 0 {
		t.Errorf("an unisolated abbreviation is not canonical, so nothing fails: %v", unisolated)
	}

	// A rerun where C fails too: the same W and L column must not read as the
	// deny's, and the canonical cells fail.
	runs["C"] = jsdRun(map[string]string{xml: "refused", abbr: "refused", p830: "not observed"})
	readings, unisolated = jsdVerdict(runs, probes)
	if readings["W "+xml] != "unisolated" || readings["L "+p830] != "unisolated" {
		t.Errorf("C did not reach, yet: %v", readings)
	}
	if len(unisolated) != 4 {
		t.Errorf("want the 4 canonical W/L cells unisolated, got %v", unisolated)
	}

	// A W that reaches is reached, whatever C did, and is not a failure.
	runs["W"] = jsdRun(map[string]string{xml: "hello"})
	readings, unisolated = jsdVerdict(runs, probes)
	if readings["W "+xml] != "reached" {
		t.Errorf("W reached: got %q", readings["W "+xml])
	}
	if slices.ContainsFunc(unisolated, func(s string) bool { return s[:1] == "W" }) {
		t.Errorf("a reached W cell is not unisolated: %v", unisolated)
	}
}
