package port49d

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store/memory"
)

// failClosedPolicy is a policy on platform set 1.1.0 where subject s is
// admin and subject t holds role long, whose body is role; expiry, when set,
// ends t's grant ("" or ", expires: <time>").
func failClosedPolicy(role, expiry string) string {
	return `
platform_set: 1.1.0
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: r, privilege: admin, permit: ["**"]}
  - {name: long, ` + role + `}
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: t, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [r]}
  - {subject: t, scope: all_devices, roles: [long]` + expiry + `}
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`
}

// junosFleet is n juniper_junos devices.
func junosFleet(n int) string {
	var b strings.Builder
	b.WriteString("devices:\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "  - {name: srx%02d, platform: juniper_junos, addresses: [10.0.%d.%d]}\n", i, i/250, i%250+1)
	}
	return b.String()
}

// A refused argument deny and an overflowing allow: each is a composition
// the fail-closed reply answers (spec §12).
const (
	cleanRole       = `privilege: readonly, permit: ["show **"]`
	overflowingRole = `privilege: readonly, permit: ["show interfaces **", "show route **", "show chassis **", ` +
		`"show bgp **", "show ospf **", "show isis **", "show lldp **", "show arp **", "show version **", ` +
		`"show mpls **", "show ldp **", "show rsvp **", "show system **", "show security **", "show log **", ` +
		`"show ethernet-switching **", "show evpn **", "show bfd **", "show vrrp **", "show pfe **", ` +
		`"show services **", "show firewall **", "show policy-options **", "show class-of-service **", ` +
		`"show multicast **", "show pim **", "show igmp **", "show vlans **", "show ntp **", "show snmp **"]`
	refusedRole = `privilege: readonly, permit: ["show **"], deny: ["show configuration system"]`
)

const countLine = "composition(s) answered fail-closed now (port49 policy test names them)"

// failClosedRig is a broker on clean policy with n Junos devices.
func failClosedRig(t *testing.T, n int) *reloadRig {
	t.Helper()
	rig := newReloadRig(t, failClosedPolicy(cleanRole, ""))
	rig.r.cfg.MaxRemovedPercent = 100 // the fleet replaces the one device the rig starts with
	rig.writeInventory(t, junosFleet(n))
	rig.pollTwice()
	return rig
}

func failClosedGauge(rig *reloadRig) float64 { return testutil.ToFloat64(rig.m.PolicyFailClosed) }

// A reload to a composition the fail-closed reply answers says so right
// after the reload line, names the finding as policy test does, and sets the
// gauge; reloading back says 0 once and clears it (spec §12).
func TestAReloadToAFailClosedCompositionIsSaidAndGauged(t *testing.T) {
	rig := failClosedRig(t, 2)
	if strings.Contains(rig.out.String(), countLine) || failClosedGauge(rig) != 0 {
		t.Fatalf("said with nothing fail-closed:\n%s", rig.out.String())
	}
	swapTo(t, rig, failClosedPolicy(overflowingRole, ""))
	out := rig.out.String()
	reloaded, said := strings.Index(out, "policy reloaded"), strings.Index(out, "port49d: policy: 1 "+countLine)
	if reloaded < 0 || said < reloaded || !strings.Contains(out, `policy: projection_overflow: subject "t" on juniper_junos `) ||
		!strings.Contains(out, "on 2 devices: srx01, srx02") || failClosedGauge(rig) != 1 {
		t.Fatalf("gauge %v:\n%s", failClosedGauge(rig), out)
	}
	swapTo(t, rig, failClosedPolicy(cleanRole, ""))
	if n := strings.Count(rig.out.String(), "policy: 0 "+countLine); n != 1 || failClosedGauge(rig) != 0 {
		t.Fatalf("the fix was said %d times, gauge %v:\n%s", n, failClosedGauge(rig), rig.out.String())
	}
	before := rig.out.String()
	swapTo(t, rig, failClosedPolicy(cleanRole, "")+"# comment\n")
	if strings.Count(rig.out.String(), countLine) != strings.Count(before, countLine) {
		t.Fatalf("a clean policy said it again:\n%s", rig.out.String())
	}
}

// The line is said after the refresh pass, as the unverifiable-requirement
// line is: the pass carries the swap into live sessions, and the walk over
// every subject and device must not delay it.
func TestTheFailClosedLineIsSaidAfterTheRefreshPass(t *testing.T) {
	rig := failClosedRig(t, 2)
	var mu sync.Mutex
	pass := rig.r.pass
	rig.r.pass = func(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintln(stderr, "MARK pass")
		return pass(ctx, priors)
	}
	swapTo(t, rig, failClosedPolicy(refusedRole, ""))
	out := rig.out.String()
	if pi, li := strings.Index(out, "MARK pass"), strings.Index(out, countLine); pi < 0 || li < pi {
		t.Fatalf("the line was said before the pass ran:\n%s", out)
	}
}

// A grant's expiry that ends a fail-closed composition moves the gauge to 0
// at the expiry pass, and says so; the finding before it carries its moment.
func TestAnExpiryPassClearsTheFailClosedGauge(t *testing.T) {
	for _, brokerInProcess := range []bool{true, false} {
		t.Run(fmt.Sprintf("broker=%v", brokerInProcess), func(t *testing.T) {
			rig := failClosedRig(t, 2)
			lapse := rig.now.Add(time.Hour)
			swapTo(t, rig, failClosedPolicy(overflowingRole, ", expires: "+lapse.UTC().Format(time.RFC3339)))
			if failClosedGauge(rig) != 1 || !strings.Contains(rig.out.String(), "until ") {
				t.Fatalf("gauge %v:\n%s", failClosedGauge(rig), rig.out.String())
			}
			if !brokerInProcess {
				rig.r.pass = nil
				rig.with(func() { rig.r.refresh(context.Background()) })
			}
			rig.now = lapse
			seen := len(rig.out.String())
			rig.with(func() { rig.r.refresh(context.Background()) })
			if n := strings.Count(rig.out.String()[seen:], "policy: 0 "+countLine); n != 1 || failClosedGauge(rig) != 0 {
				t.Fatalf("the expiry pass: gauge %v, said %d times:\n%s", failClosedGauge(rig), n, rig.out.String()[seen:])
			}
		})
	}
}

// A refusal as secret_rule prints no value a rule hides.
func TestAFailClosedLinePrintsNoHiddenLiteral(t *testing.T) {
	rig := failClosedRig(t, 2)
	swapTo(t, rig, failClosedPolicy(`privilege: readonly, permit: ["show **"], `+
		`deny: ["show system radius-server 10.0.0.1 secret HUNTER2"]`, ""))
	out := rig.out.String()
	if !strings.Contains(out, "projection_refused") || !strings.Contains(out, "secret_rule") ||
		strings.Contains(out, "HUNTER2") || failClosedGauge(rig) != 1 {
		t.Fatalf("gauge %v:\n%s", failClosedGauge(rig), out)
	}
}

// A finding on fifty devices says the count and three names.
func TestAFailClosedFindingNamesThreeDevices(t *testing.T) {
	rig := failClosedRig(t, 50)
	swapTo(t, rig, failClosedPolicy(refusedRole, ""))
	out := rig.out.String()
	if !strings.Contains(out, "on 50 devices: srx01, srx02, srx03 and 47 more") || strings.Contains(out, "srx04") {
		t.Fatalf("%s", out)
	}
}

// A start says it as a reload does, from the policy and inventory it loaded.
func TestAStartSaysWhichCompositionsAreFailClosed(t *testing.T) {
	rig := failClosedRig(t, 2)
	// A start reads the inventory config.Load read.
	inv, err := admission.LoadFile(rig.cfg.InventoryFile)
	if err != nil {
		t.Fatal(err)
	}
	rig.cfg.Inventory = inv
	for _, c := range []struct {
		role string
		want float64
	}{{cleanRole, 0}, {refusedRole, 1}} {
		rig.write(t, failClosedPolicy(c.role, ""))
		var start syncBuffer
		func() {
			defer func(w io.Writer) { stderr = w }(stderr)
			stderr = &start
			if _, _, err := buildBroker(rig.cfg, "inventory_file "+rig.cfg.InventoryFile, memory.New(time.Now), seedMinter(),
				decision.NewJSONLines(io.Discard), rig.m); err != nil {
				t.Fatalf("the start refused: %v", err)
			}
		}()
		if got := strings.Count(start.String(), "policy: 1 "+countLine); (got == 1) != (c.want == 1) || failClosedGauge(rig) != c.want {
			t.Fatalf("%q: gauge %v, said %d times:\n%s", c.role, failClosedGauge(rig), got, start.String())
		}
	}
}
