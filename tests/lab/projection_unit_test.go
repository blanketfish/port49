//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/projection"
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
