//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/projection"
)

// TestUpperCaseTyped pins which probes the device-refused check skips: every
// uppercase form in projectionProbes, and none other.
func TestUpperCaseTyped(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"SHOW VERSION", true}, {"SHOW INTERFACES TERSE", true}, {"SHOW CONFIGURATION SYSTEM HOST-NAME", true},
		{"show version", false}, {"sh int ter", false}, {"   show configuration system host-name   ", false},
	} {
		if got := upperCaseTyped(c.cmd); got != c.want {
			t.Errorf("upperCaseTyped(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
	for _, p := range projectionProbes {
		if upperCaseTyped(p.cmd) != (p.cmd == strings.ToUpper(p.cmd) && p.cmd != strings.ToLower(p.cmd)) {
			t.Errorf("%q: a probe is partly upper case; the predicate and the probe table disagree", p.cmd)
		}
	}
}

// TestJunosPaged pins the pager matcher, and that every reading probe is
// typed `| no-more`.
func TestJunosPaged(t *testing.T) {
	if !junosPaged("Filename: how firewall\nWrote 1050 lines of output to 'how firewall'\n---(more 18%)---") {
		t.Error("the pager prompt was not read")
	}
	if junosPaged("srx> show version\nHostname: x\nsrx> ") {
		t.Error("an output with no pager prompt was read as paged")
	}
	for _, p := range projectionProbes {
		if projectionReadings[p.cmd] && !strings.HasSuffix(p.cmd, " | no-more") && !strings.HasSuffix(p.cmd, " | count") {
			t.Errorf("reading probe %q is not typed | no-more or | count", p.cmd)
		}
	}
	for cmd := range projectionReadings {
		found := false
		for _, p := range projectionProbes {
			found = found || p.cmd == cmd
		}
		if !found {
			t.Errorf("projectionReadings names %q, which no probe types", cmd)
		}
	}
}

// `show log messages` prints the syslog, which can hold any refusal word, so its
// reading is `| count` read by the "Count: " line, never by the absence of a
// refusal word (review I2).
func TestShowLogIsReadByEvidence(t *testing.T) {
	var found bool
	for _, p := range projectionProbes {
		if strings.HasPrefix(p.cmd, "show log") {
			found = true
			if p.cmd != "show log messages | count" || p.evidence != "Count: " {
				t.Errorf("show log probe %q with evidence %q", p.cmd, p.evidence)
			}
		}
	}
	if !found {
		t.Error("no show log probe")
	}
	r := junosRun{outs: map[string]string{"show log messages | count": "Count: 1050 lines"}}
	if !r.runs(junosProbe{cmd: "show log messages | count", evidence: "Count: "}) {
		t.Error("a Count line was not read as the command having run")
	}
	// A syslog full of refusals is not a refused command; an absent Count line is.
	r.outs["show log messages | count"] = "Oct 12 sshd: error: permission denied\n"
	if r.runs(junosProbe{cmd: "show log messages | count", evidence: "Count: "}) {
		t.Error("output without a Count line was read as the command having run")
	}
}

// The `op url` probes: the canonical form and an abbreviation, both read by the
// script's own marker, both asked of port49 as the canonical command.
func TestOpURLProbes(t *testing.T) {
	var canonical, abbrev bool
	for _, p := range projectionProbes {
		switch p.cmd {
		case opURLCmd:
			canonical = true
		case opAbbrevCmd:
			abbrev = true
		default:
			continue
		}
		if p.canonical != opURLCmd || p.evidence != opURLEvidence {
			t.Errorf("%q: canonical %q, evidence %q", p.cmd, p.canonical, p.evidence)
		}
	}
	if !canonical || !abbrev {
		t.Errorf("op probes: canonical %v, abbreviation %v", canonical, abbrev)
	}
	if opURLCmd == opAbbrevCmd || !strings.HasPrefix(opAbbrevCmd, "op ur ") {
		t.Errorf("the abbreviation %q is not an abbreviation of %q", opAbbrevCmd, opURLCmd)
	}
	// The script prints the marker with the host name only where jcs:invoke was
	// answered; the typed line's echo carries neither.
	r := junosRun{outs: map[string]string{opURLCmd: "<output>P49OP-VERSION srx1</output>"}}
	if !r.runs(junosProbe{cmd: opURLCmd, evidence: opURLEvidence}) {
		t.Error("the script's output was not read as a run")
	}
	r.outs[opURLCmd] = opURLCmd + "\nerror: permission denied\n"
	if r.runs(junosProbe{cmd: opURLCmd, evidence: opURLEvidence}) {
		t.Error("a refusal was read as a run")
	}
}

// The control is the only row whose `op url` must run: the other rows' refusals
// mean something only beside it.
func TestOpControlMissing(t *testing.T) {
	const control = "operator, all it reaches"
	for _, c := range []struct {
		set, row, cmd string
		ran, want     bool
	}{
		{"1.2.0", control, opURLCmd, false, true},
		{"1.2.0", control, opURLCmd, true, false},
		{"1.2.0", control, opAbbrevCmd, false, false}, // the abbreviation may be ambiguous; only the canonical form is mandatory
		{"1.2.0", "admin keeping a keyword deny", opURLCmd, false, false},
		{"1.1.0", control, opURLCmd, false, false},
	} {
		if got := opControlMissing(c.set, c.row, c.cmd, c.ran); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
	found := false
	for _, s := range projectionShapes120 {
		found = found || s.name == control
	}
	if !found {
		t.Errorf("projectionShapes120 has no %q row for the control", control)
	}
}

// TestProjectionShapes120Render runs without a device: each row of
// projectionShapes120 renders, from this branch's code and the lab inventory,
// the shape its `want` names, so the differential's run is not wasted on a row
// whose reply differs (plan 9b1 Task 9, Step 1). The entry deny rides every
// capability row, the control carries none, and the readonly rows with a deny
// carry the nested deny-commands.
func TestProjectionShapes120Render(t *testing.T) {
	// A unit test runs in tests/lab, and `root` is set only once a platform is up.
	inv, err := admission.LoadFile("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"srx1", "vsrx1"} {
		for _, s := range projectionShapes120 {
			body := "platform_set: 1.2.0\nscopes:\n  - {name: all_devices, match: {}}\nroles:\n" + s.roles + "\n" +
				"subjects:\n  - {name: slice_operator, identity: [\"" + slicePrincipal + "\"], username: " + sliceUser +
				", enable: none, token_ttl: 60s}\ngrants:\n  - {subject: slice_operator, scope: all_devices, roles: [r]}\n"
			path := filepath.Join(t.TempDir(), "shape.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			pol, err := policy.Load(path, policy.Env{Devices: inv.Devices})
			if err != nil {
				t.Fatalf("%s: the shape's policy does not load: %v", s.name, err)
			}
			device, _ := pol.Device(node)
			res, err := pol.ResolveSubject("slice_operator", device, time.Now())
			if err != nil {
				t.Fatalf("%s: %v", s.name, err)
			}
			got := res.Projection.Shape
			if res.Projection.FailClosed != "" {
				got = projection.ShapeFailClosed
			}
			if got != s.want {
				t.Errorf("%s on %s: want the %s shape, rendered %s (%s)", s.name, node, s.want, got, res.Projection.FailClosed)
			}
			// The differential's `op url` probe: the entry deny is the projection's
			// alone (the engine's decision on `op url` is the role's, a permit where
			// the role permits `op **`), so it is the projection's model that
			// predicts the device's refusal wherever the reply carries the entry
			// deny, and its run there is `ran && !predicts`, a fail-open failure.
			// The control's model runs it: its run is the positive control.
			opModel := res.Projection.Device(strings.Fields(opURLCmd))
			if entry := res.Projection.EntryDenied(); (entry && opModel) || (s.name == "operator, all it reaches" && !opModel) {
				t.Errorf("%s on %s: entry deny %v, but the model predicts the device %s %q", s.name, node, entry,
					verb(opModel), opURLCmd)
			}
			switch {
			case s.name == "operator, all it reaches":
				if res.Projection.EntryDenied() || res.Projection.NetconfClosed() {
					t.Errorf("%s: the control carries an entry deny or closes NETCONF", s.name)
				}
			case strings.Contains(s.roles, "privilege: readonly") && strings.Contains(s.roles, "deny:"):
				if !res.Projection.EntryDenied() {
					t.Errorf("%s: no entry deny in the reply", s.name)
				}
				var deny string
				for _, a := range res.Blob.Attributes {
					if v, ok := strings.CutPrefix(a, "deny-commands="); ok {
						deny = v
					}
				}
				if !strings.HasPrefix(deny, "^(") || !strings.HasSuffix(deny, ")$") || !strings.Contains(deny, "save") ||
					!strings.Contains(deny, "junoscript") {
					t.Errorf("%s: deny-commands is not the nested form: %s", s.name, deny)
				}
			case s.want == projection.ShapeCapability:
				if !res.Projection.EntryDenied() {
					t.Errorf("%s: no entry deny in the reply", s.name)
				}
			}
		}
	}
}
