//go:build lab

package lab

import (
	"slices"
	"strings"
	"testing"
)

// These run without a device: the L26c classifiers and the verdict.

func TestL26cCells(t *testing.T) {
	for _, c := range []struct{ name, got, want string }{
		{"hello", l26cEntryCell("xml-mode netconf need-trailer\n<hello xmlns=\"x\"><capabilities/></hello>\n]]>]]>"), "hello"},
		{"entry refused", l26cEntryCell("xml-mode netconf need-trailer\n        ^\nunknown command.\nalice@srx1> "), "refused"},
		{"entry both", l26cEntryCell("<hello></hello> permission denied"), "not observed"},
		{"entry neither", l26cEntryCell("xml-mode netconf need-trailer\n"), "not observed"},
		{"rpc result", l26cRPCCell("<rpc-reply><software-information><host-name>srx1</host-name></software-information></rpc-reply>", "<software-information"), "result"},
		{"rpc warning and result", l26cRPCCell("<rpc-reply><rpc-error><error-severity>warning</error-severity></rpc-error><configuration><system><host-name>srx1</host-name></system></configuration></rpc-reply>", "host-name"), "result"},
		{"rpc refused", l26cRPCCell("<rpc-reply><rpc-error><error-severity>error</error-severity><error-message>permission denied</error-message></rpc-error></rpc-reply>", "host-name"), "refused"},
		{"rpc echo only", l26cRPCCell("<rpc><get-software-information/></rpc>]]>]]>", "<software-information"), "not observed"},
		{"op url accepted", l26cOpURLCell("op url /var/tmp/p49-none.slax\nerror: file /var/tmp/p49-none.slax does not exist\n"), "accepted"},
		{"op url refused", l26cOpURLCell("op url /var/tmp/p49-none.slax\n^\nunknown command.\n"), "refused"},
		{"op url neither", l26cOpURLCell("op url /var/tmp/p49-none.slax\n"), "not observed"},
		{"shell", l26cShellCell("start shell\n% "), "shell"},
		{"shell dollar", l26cShellCell("start shell\nbash$ "), "shell"},
		{"shell refused", l26cShellCell("start shell\n      ^\nunknown command.\nalice@srx1> "), "refused"},
		{"shell neither", l26cShellCell("start shell\nalice@srx1> "), "not observed"},
		{"cli ran", l26cCLICell("Hostname: srx1\nJunos: 23.4", "Junos:"), "ran"},
		{"cli refused with the command echoed", l26cCLICell("show configuration system host-name \n^\nsyntax error.\nalice@srx1> ",
			junosHostProbe.evidence), "refused"},
		{"cli ran host-name", l26cCLICell("show configuration system host-name \nhost-name srx1;\n", junosHostProbe.evidence), "ran"},
		{"cli refused", l26cCLICell("show configuration\n^\npermission denied.", "host-name"), "refused"},
	} {
		if c.got != c.want {
			t.Errorf("%s: %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestL26cVerdict(t *testing.T) {
	run := func(cells map[string]string) l26cRun { return l26cRun{cells: cells, outs: map[string]string{}} }
	probes := []string{"entry: x", "x: rpc"}
	// P reaches: reachable.
	runs := map[string]l26cRun{
		"P": run(map[string]string{"entry: x": "hello", "x: rpc": "result"}),
		"F": run(map[string]string{"entry: x": "refused"}),
		"C": run(map[string]string{"entry: x": "hello", "x: rpc": "result"}),
		"R": run(map[string]string{"entry: x": "hello", "x: rpc": "result"}),
	}
	if reachable, isolated, _ := l26cVerdict(runs, probes); !reachable || !isolated {
		t.Errorf("P reaching: reachable %v, isolated %v", reachable, isolated)
	}
	// Both refuse, C reaches: not reachable, isolated.
	runs["P"] = run(map[string]string{"entry: x": "refused"})
	if reachable, isolated, _ := l26cVerdict(runs, probes); reachable || !isolated {
		t.Errorf("both refused: reachable %v, isolated %v", reachable, isolated)
	}
	// Both refuse, and C and R too: the probe runs nowhere; isolated.
	runs["C"] = run(map[string]string{"entry: x": "refused"})
	runs["R"] = run(map[string]string{"entry: x": "refused"})
	if reachable, isolated, _ := l26cVerdict(runs, probes); reachable || !isolated {
		t.Errorf("runs nowhere: reachable %v, isolated %v", reachable, isolated)
	}
	// A refusal no control accounts for: not isolated.
	runs["R"] = run(map[string]string{"entry: x": "not observed"})
	if _, isolated, _ := l26cVerdict(runs, probes); isolated {
		t.Error("a refusal with no control is isolated")
	}
	// Not observed in P and C alike, reached in R: the bits, recorded.
	runs["P"] = run(map[string]string{"entry: x": "hello", "x: rpc": "not observed"})
	runs["C"] = run(map[string]string{"entry: x": "hello", "x: rpc": "not observed"})
	runs["R"] = run(map[string]string{"entry: x": "hello", "x: rpc": "result"})
	if _, isolated, why := l26cVerdict(runs, probes); !isolated || !slices.ContainsFunc(why, func(w string) bool { return strings.HasPrefix(w, "bits-limited:") }) {
		t.Errorf("a bits-limited cell: isolated %v, %v", isolated, why)
	}
	runs["C"] = run(map[string]string{"entry: x": "hello", "x: rpc": "result"})
	// Not observed in P: not isolated.
	runs["R"] = run(map[string]string{"entry: x": "hello"})
	runs["P"] = run(map[string]string{"entry: x": "not observed"})
	if _, isolated, _ := l26cVerdict(runs, probes); isolated {
		t.Error("a not observed cell is isolated")
	}
}
