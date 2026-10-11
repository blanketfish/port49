//go:build lab

package lab

import (
	"errors"
	"testing"
)

// These run without a device: the entry cells' isolation verdict, and the
// op script's and scp's cells.

func TestEntryVerdict(t *testing.T) {
	const p830, xml, p22 = "port 830", "entry: xml-mode netconf need-trailer", "port 22 subsystem"
	runs := map[string]l26cRun{
		"W": jsdRun(map[string]string{p830: "refused", xml: "refused", p22: "refused"}),
		"V": jsdRun(map[string]string{p830: "hello", xml: "hello", p22: "refused"}),
		"C": jsdRun(map[string]string{p830: "hello", xml: "hello", p22: "refused"}),
	}
	readings, unisolated := entryVerdict(runs, []string{"W"}, "C", []string{p830, xml}, []string{p830, xml, p22})
	if readings["W "+p830] != "deny" || readings["W "+xml] != "deny" {
		t.Errorf("W refused where C reached: %v", readings)
	}
	// Port 22 runs nowhere: C refused it too, so W's refusal is no deny, and
	// it is not canonical, so nothing fails.
	if readings["W "+p22] != "runs nowhere" || len(unisolated) != 0 {
		t.Errorf("port 22: %v %v", readings, unisolated)
	}
	// A canonical probe C did not reach fails the run.
	runs["C"] = jsdRun(map[string]string{p830: "refused", xml: "hello"})
	if _, unisolated = entryVerdict(runs, []string{"W"}, "C", []string{p830, xml}, []string{p830, xml}); len(unisolated) != 1 {
		t.Errorf("C refused port 830: %v", unisolated)
	}
	// W reaching is "reached", the deny's failure, whatever C did.
	runs["W"] = jsdRun(map[string]string{p830: "hello"})
	if r, _ := entryVerdict(runs, []string{"W"}, "C", nil, []string{p830}); r["W "+p830] != "reached" {
		t.Errorf("W reached: %v", r)
	}
	// A token the device refused, or a cell not observed, says nothing about
	// the deny: never "deny", even where C reached (G2 must not drop a
	// service on a spent token).
	runs["C"] = jsdRun(map[string]string{p830: "hello"})
	for _, cell := range []string{"login refused", "not observed"} {
		runs["W"] = jsdRun(map[string]string{p830: cell})
		if r, _ := entryVerdict(runs, []string{"W"}, "C", nil, []string{p830}); r["W "+p830] != "not observed" {
			t.Errorf("W %s: %v", cell, r)
		}
	}
}

func TestOpScriptCell(t *testing.T) {
	for _, c := range []struct{ out, want string }{
		{"P49OP-VERSION srx1\nP49OP-CONFIG 1\n", "version and configuration"},
		{"P49OP-VERSION srx1\nP49OP-CONFIG 0\n", "version only"},
		{"error: permission denied\n", "refused"},
		{"syntax error, expecting <command>\n", "refused"},
		{"", "not observed"},
	} {
		if got := opScriptCell(c.out); got != c.want {
			t.Errorf("%q: got %q, want %q", c.out, got, c.want)
		}
	}
}

func TestScpCell(t *testing.T) {
	for _, c := range []struct {
		n    int64
		err  error
		want string
	}{
		{4096, nil, "file read"},
		{0, errors.New("scp: permission denied"), "refused"},
		{0, nil, "refused"},
	} {
		if got := scpCell(c.n, c.err); got != c.want {
			t.Errorf("%d %v: got %q, want %q", c.n, c.err, got, c.want)
		}
	}
}

// The xnm-ssh cell: the JUNOScript greeting is a hello, a refusal text is
// refused, and silence is not observed.
func TestXnmHelloCell(t *testing.T) {
	for _, c := range []struct{ out, want string }{
		{"<?xml version=\"1.0\" encoding=\"us-ascii\"?>\n<junoscript xmlns=\"http://xml.juniper.net/xnm/1.1/xnm\" version=\"1.0\">", "hello"},
		{"error: permission denied\n", "refused"},
		{"", "not observed"},
	} {
		if got := xnmHelloCell(c.out); got != c.want {
			t.Errorf("%q: got %q, want %q", c.out, got, c.want)
		}
	}
}
