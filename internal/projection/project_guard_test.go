package projection

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// No reply that carries a deny lets the device enter configuration mode,
// where no deny-commands reaches a statement (L12). Task 12a adds `edit`,
// the alias, to the guard and to this assertion.
func TestAReplyWithADenyNeverConfigures(t *testing.T) {
	entries := [][]string{{"configure"}, {"configure", "private"}, {"configure", "exclusive"},
		{"configure", "batch"}}
	for _, rules := range [][]engine.Rule{
		{permit("**"), deny("request system reboot **")},
		{permit("**"), deny("show configuration **")},
		{permit("show **"), permit("configure **"), deny("show version")},
		{permit("configure **"), deny("configure exclusive")},
		{permit("show version"), permit("configure")},
	} {
		for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
			for _, f := range []Facts{measured, JunosFacts} {
				res, err := Project(input(delivery, "admin", f, rules...))
				if err != nil {
					t.Fatal(err)
				}
				if len(res.Denies) == 0 && res.Shape == ShapeCapability {
					continue
				}
				for _, e := range entries {
					if res.Device(e) {
						t.Errorf("%s %v: a reply with a deny runs %q: %q", delivery, rules, e, res.Attributes)
					}
				}
			}
		}
	}
}

// The fail-closed reply is deny .* with no template and no bit that enters
// configuration mode, whatever refused the composition (decision 26).
func TestTheFailClosedReplyIsBounded(t *testing.T) {
	for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
		res, err := Project(input(delivery, "admin", measured, permit("**"), permit("show version"),
			deny("request system reboot **")))
		if err != nil {
			t.Fatal(err)
		}
		if delivery == platform.BitDeliveryUserPermissions {
			// Dropping the configuration bits proves it; force the refusal
			// another way to reach the fail-closed reply.
			res, err = Project(input(delivery, "operator", Facts{CaseSensitive: true}, permit("show **"),
				permit("clear **"), deny("clear bgp **")))
			if err != nil {
				t.Fatal(err)
			}
		}
		if res.Shape != ShapeFailClosed || res.Template != "" {
			t.Fatalf("%s: %+v", delivery, res)
		}
		if !slices.Contains(res.Attributes, "deny-commands=^.*$") {
			t.Errorf("%s: no deny .*: %q", delivery, res.Attributes)
		}
		for _, a := range res.Attributes {
			if strings.HasPrefix(a, "local-user-name=") {
				t.Errorf("%s: the fail-closed reply sends a template: %q", delivery, res.Attributes)
			}
		}
		for _, b := range res.Bits {
			if b == "all" || b == "configure" {
				t.Errorf("%s: the fail-closed reply holds %s", delivery, b)
			}
		}
		if res.Device([]string{"configure"}) {
			t.Errorf("%s: the fail-closed reply configures", delivery)
		}
	}
}

// A bit's reach is a union under both deliveries (C1): an unheld bit's
// reach, however it overlaps a held one, never takes a command out of it.
func TestAnUnheldBitRemovesNothingUnderEitherDelivery(t *testing.T) {
	for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
		in := input(delivery, "readonly", measured, permit("show **"), deny("show log **"))
		in.Dialect.Bits["trace"] = []string{"monitor **", "show log **"}
		res, err := Project(in)
		if err != nil || len(res.Omitted) != 0 || res.Device([]string{"show", "log", "messages"}) ||
			!res.Device([]string{"show", "version"}) {
			t.Fatalf("%s: %+v %v", delivery, res, err)
		}
	}
}

// An omitted deny is proven by engine.Contains(carve-out, deny), which reads
// the deny as a permit does, as received. The device model reads the
// carve-out as port49 reads a deny, trimmed, so the carve refuses whatever
// spacing the deny would have caught.
func TestAnOmittedDenyHoldsItsPaddedForms(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
		permit("show **"), deny("show configuration **")))
	if err != nil || len(res.Omitted) != 1 || len(res.Denies) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, v := range [][]string{{"show", " configuration"}, {"show", "configuration "}, {" show", "configuration"},
		{"SHOW", "Configuration", "system"}} {
		if res.Device(v) {
			t.Errorf("the device runs %q, which the omitted deny holds", v)
		}
	}
}

// cover takes the smallest set, not the greedy one: the bit reaching the
// most allows first would need two more (I11).
func TestCoverIsTheSmallestSet(t *testing.T) {
	in := input(platform.BitDeliveryUserPermissions, "operator", measured)
	in.Dialect.Bits = map[string][]string{
		"wide":  {"show a", "show b", "show c", "show d"},
		"left":  {"show a", "show b", "show e"},
		"right": {"show c", "show d", "show f"},
	}
	g := newGenerator(in, []string{"wide", "left", "right"})
	var allows []engine.Rule
	for _, w := range []string{"a", "b", "c", "d", "e", "f"} {
		allows = append(allows, permit("show "+w))
	}
	if got := g.cover(g.ceiling, allows); !reflect.DeepEqual(got, []string{"left", "right"}) {
		t.Fatalf("cover: %q", got)
	}
}

// Each composition is projected once per policy (Task 9 caches it, I12), so
// a load of 1,000 SRXs whose 20 subjects compose differently costs 20
// projections. This holds that cost well inside the 2 s bound.
func TestTwentyCompositionsProjectQuickly(t *testing.T) {
	var ins []Input
	for i := range 20 {
		rules := []engine.Rule{permit("show **"), deny("show configuration **"),
			permit(fmt.Sprintf("show configuration interfaces ge-0/0/%d **", i)), permit("ping **")}
		for j := range i % 5 {
			rules = append(rules, deny(fmt.Sprintf("show route table t%d **", j)))
		}
		level := []string{"readonly", "operator", "admin"}[i%3]
		delivery := []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName}[i%2]
		ins = append(ins, input(delivery, level, JunosFacts, rules...))
	}
	best := time.Hour
	for range 3 {
		start := time.Now()
		for _, in := range ins {
			if _, err := Project(in); err != nil {
				t.Fatal(err)
			}
		}
		best = min(best, time.Since(start))
	}
	if best > 2*time.Second {
		t.Errorf("20 compositions took %v; the load bound is 2s", best)
	}
	t.Logf("20 compositions projected in %v", best)
}

// measuredJunos is junos with the reach and baseline the lab measured on the
// vSRX (tests/lab/results/L12-bits-juniper_vsrx.md) and the test levels.
func measuredJunos(delivery string) platform.Dialect {
	d := junos(delivery)
	d.Bits = map[string][]string{
		platform.BaselineBit: {"help **", "quit **", "exit **", "set cli **", "show cli **", "file **", "load **",
			"op **", "request **", "save **", "scp **", "set **", "start **", "test **"},
		"clear":   {"clear **", "request mpls **", "set chassis **"},
		"network": {"ping **", "traceroute **", "ssh **", "telnet **", "mtrace **", "probe **", "request routing-engine **"},
		"trace":   {"monitor **"},
		"view": {"show **", "request flight-recorder **", "request pppoe **", "request snmp **",
			"request validation **", "test interface **", "test msdp **", "test policy **", "test rib-sharding **",
			"test services **"},
		"view-configuration": {"show configuration **", "monitor **", "request mpls **",
			"request path-computation-client **", "request security **", "request unified-edge **",
			"request virtual-chassis **", "load dhcp-security-snoop **", "save dhcp-security-snoop **"},
		"all": {"**"},
	}
	return d
}

func measuredInput(delivery, level string, f Facts, rules ...engine.Rule) Input {
	in := input(delivery, level, f, rules...)
	in.Dialect = measuredJunos(delivery)
	in.Bits = in.Dialect.CeilingBits[level]
	return in
}

// A baseline deny is port49's reading of what the baseline runs, not a rule
// anyone wrote: a permit of a baseline command beneath it is no refused
// shape (review I1).
func TestAPermitOfABaselineCommandIsNotRefused(t *testing.T) {
	for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
		for _, f := range []Facts{measured, JunosFacts} {
			res, err := Project(measuredInput(delivery, "operator", f, permit("show **"), permit("clear **"),
				permit("ping **"), permit("request support information **"), permit("quit"), permit("exit")))
			if err != nil || res.Shape == ShapeFailClosed {
				t.Errorf("%s %+v: %+v %v", delivery, f, res.Refusal, err)
				continue
			}
			if !res.Device([]string{"quit"}) || !res.Device([]string{"exit"}) || res.Device([]string{"quit", "now"}) {
				t.Errorf("%s %+v: %q", delivery, f, res.Attributes)
			}
		}
	}
}

// cover gives each allow a bit that proves it runs: a carve-out counted, and
// the baseline's reach needing no bit (review I3).
func TestCoverCountsCarveOutsAndTheBaseline(t *testing.T) {
	// Only view-configuration runs show configuration: view alone is carved.
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
		permit("show configuration interfaces **")))
	if err != nil || res.Shape != ShapeNarrow || !reflect.DeepEqual(res.Bits, []string{"view-configuration"}) {
		t.Fatalf("carved: %s %q %v", res.Shape, res.Attributes, err)
	}
	// request support information is the baseline's; show still needs view.
	res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "admin", JunosFacts, permit("show **"),
		permit("request support information **")))
	if err != nil || res.Shape != ShapeNarrow || !reflect.DeepEqual(res.Bits, []string{"view", "view-configuration"}) {
		t.Fatalf("baseline and view: %s %q %v", res.Shape, res.Attributes, err)
	}
	// A grant the baseline alone reaches takes no bit, and loses nothing.
	res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("quit")))
	if err != nil || res.Shape != ShapeNarrow || len(res.Bits) != 0 || len(res.Narrower(5)) != 0 ||
		!reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$", "allow-commands=^quit$"}) {
		t.Fatalf("baseline only: %s %q %v", res.Shape, res.Attributes, err)
	}
}

// An allow sent under bits that do not reach it may not run: whether a Junos
// allow runs without its bit is unmeasured, so CI says so (review I3).
func TestAnAllowTheBitsDoNotReachIsReported(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "operator", measured, permit("show **"),
		permit("clear **"), permit("ping **"), deny("clear bgp **")))
	if err != nil || len(res.Unreached) != 1 || res.Unreached[0].Rule != "ping **" {
		t.Fatalf("%+v %v", res, err)
	}
	n := res.Narrower(20)
	if !slices.ContainsFunc(n, func(v []string) bool { return v[0] == "ping" }) {
		t.Errorf("narrower: %q", n)
	}
}

// The measured baseline alone overflows a capability shape's deny-commands;
// the narrow shape carries the same grant within the budget (review I2).
func TestAnOverflowingCapabilityShapeGoesNarrow(t *testing.T) {
	in := measuredInput(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"))
	g := newGenerator(in, in.Bits)
	c, err := g.capability()
	if err != nil {
		t.Fatal(err)
	}
	var r *Refusal
	if err := g.attributes(&c); !errors.As(err, &r) || r.Attribute != "deny-commands" || len(r.Value) < 400 {
		t.Fatalf("the fixture no longer overflows: %v", err)
	}
	res, err := Project(in)
	want := []string{"user-permissions=view view-configuration", "deny-commands=^.*$", "allow-commands=^show( .*)?$"}
	if err != nil || res.Shape != ShapeNarrow || !reflect.DeepEqual(res.Attributes, want) {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}
