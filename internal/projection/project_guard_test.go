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
// where no deny-commands reaches a statement (L12), by `configure`, its
// variants or `edit`, its alias (pre-flight B-M1).
func TestAReplyWithADenyNeverConfigures(t *testing.T) {
	entries := [][]string{{"configure"}, {"configure", "private"}, {"configure", "exclusive"},
		{"configure", "batch"}, {"edit"}, {"edit", "private"}}
	for _, rules := range [][]engine.Rule{
		{permit("**"), deny("request system reboot **")},
		{permit("**"), deny("show configuration **")},
		{permit("show **"), permit("configure **"), deny("show version")},
		{permit("configure **"), deny("configure exclusive")},
		{permit("show version"), permit("configure")},
		{permit("show **"), permit("edit **"), deny("show version")},
		{permit("show **"), permit("edit"), deny("show version")},
		{permit("edit **"), deny("edit exclusive")},
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

// A bit whose reach holds `edit` enters configuration mode as one holding
// `configure` does (Task 8 left it unguarded; pre-flight B-M1): a reply that
// carries a deny holds neither, and an allow of `edit` is never sent beside a
// deny, in any shape.
func TestABitReachingEditEntersConfiguration(t *testing.T) {
	for _, rules := range [][]engine.Rule{{permit("show **"), permit("edit **"), deny("show version")},
		{permit("show **"), permit("edit"), deny("show version")}} {
		for _, f := range []Facts{measured, JunosFacts, {CaseSensitive: true}} {
			in := input(platform.BitDeliveryUserPermissions, "operator", f, rules...)
			in.Dialect.Bits["edit"] = []string{"edit **"}
			in.Bits = append(slices.Clone(in.Bits), "edit")
			in.Keywords = keywordTree("edit")
			g := newGenerator(in, in.Bits)
			if !g.entersConfiguration("edit") {
				t.Fatal("a bit reaching edit does not enter configuration mode")
			}
			res, err := Project(in)
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(res.Bits, "edit") || res.Device([]string{"edit"}) ||
				res.Device([]string{"edit", "private"}) {
				t.Errorf("%v %+v: a reply with a deny enters configuration mode: %s %q", rules, f, res.Shape,
					res.Attributes)
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

// The fail-closed and narrow replies deny exactly ^.*$, once: the only deny
// seen to refuse `xml-mode`, in the lab (L26c) and on SRX hardware
// (23.4R2-S8.7, operator-reported), where every deny naming it, `^xml-mode.*`
// and `xml.*` among them, let it in. No other catch-all may stand in.
func TestTheCatchAllDenyIsExactlyAnchoredDotStar(t *testing.T) {
	for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
		for _, c := range []struct {
			in    Input
			shape string
		}{
			{measuredInput(delivery, "admin", JunosFacts, permit("**"), deny("request security **")), ShapeFailClosed},
			{measuredInput(delivery, "readonly", measured, permit("show **")), ShapeNarrow},
		} {
			res, err := Project(c.in)
			if err != nil || res.Shape != c.shape {
				t.Fatalf("%s: %s, want %s: %q %v", delivery, res.Shape, c.shape, res.Attributes, err)
			}
			var denies []string
			for _, a := range res.Attributes {
				if strings.HasPrefix(a, "deny-commands=") {
					denies = append(denies, a)
				}
			}
			if !reflect.DeepEqual(denies, []string{"deny-commands=^.*$"}) {
				t.Errorf("%s %s: denies %q", delivery, c.shape, denies)
			}
			if res.Device([]string{"xml-mode", "netconf"}) {
				t.Errorf("%s %s: the reply runs xml-mode", delivery, c.shape)
			}
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
	// Every word of the measured reach is a keyword, as the lab's capture
	// proves most of them (tests/lab/results/L26-keywords-juniper_vsrx.yaml):
	// these tests are about the bits, not the tree.
	var reach []string
	for _, rules := range in.Dialect.Bits {
		reach = append(reach, rules...)
	}
	in.Keywords = keywordTree(reach...)
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

// omittable leans on Contains reading a deny as received, which holds only
// where port49 widens a deny by trimming alone (review M1).
func TestADenyIsOmittedOnlyWhereItIsReadAsReceived(t *testing.T) {
	for _, n := range []engine.Normalize{{PipeToken: "|", StripCR: true},
		{PipeToken: "|", StripCR: true, SessionOnly: true, SplitsInterfaceNames: true}} {
		in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
			deny("show configuration **"))
		in.Normalize = n
		g := newGenerator(in, in.Bits)
		if g.omittable(g.denies[0], []string{"view"}, nil) {
			t.Errorf("%+v: omitted", n)
		}
	}
}

// A refusal names only rules the operator wrote, and a failed retry
// without the configuration bits says what stopped it (review M3).
func TestRefusalsNameTheRealBlocker(t *testing.T) {
	res, err := Project(measuredInput(platform.BitDeliveryLocalUserName, "admin", measured, permit("show **"),
		permit("clear **")))
	if err != nil || res.Refusal == nil || strings.Contains(res.Refusal.Why, "baseline") ||
		!strings.Contains(res.Refusal.Why, "permits less than every command") {
		t.Fatalf("%+v %v", res.Refusal, err)
	}
	// Without all and configure the allows beneath the deny overflow: that is
	// the blocker, not configuration mode.
	var rules []engine.Rule
	// The allows are of keywords, which alone Junos matches (decision 27).
	rules = append(rules, permit("**"), deny("show **"))
	for _, w := range strings.Fields("alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa") {
		rules = append(rules, permit("show "+w+" **"))
	}
	res, err = Project(input(platform.BitDeliveryUserPermissions, "admin", measured, rules...))
	if err != nil || res.FailClosed != FailOverflow || res.Refusal.Attribute != "allow-commands" {
		t.Fatalf("%s: %+v %v", res.FailClosed, res.Refusal, err)
	}
}

// treeOf is a keyword tree from nodes written as the capture writes them.
func treeOf(t *testing.T, nodes ...string) *platform.Keywords {
	t.Helper()
	_, k, err := platform.ParseKeywords([]byte("platform: juniper_junos\nnodes:\n  " + strings.Join(nodes, "\n  ") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// An allow goes out only where no argument may be typed among its words: at
// the root, after any word, and after the last unless `**` ends it. Each
// shape checks it, the fail-closed reply included (decision 27; review I2).
// The device model reads every word as a keyword, so these assert the reply,
// not Device.
func TestNoShapeSendsAnAllowAnArgumentWidens(t *testing.T) {
	unsent := func(res Result, rule string) bool {
		return slices.ContainsFunc(res.Unsent, func(u Unsent) bool { return u.Rule.Rule == rule }) &&
			!slices.ContainsFunc(res.Allows, func(a engine.Rule) bool { return a.Rule == rule })
	}
	// Capability: the permit beneath a deny it dominates needs an allow, and
	// `show interfaces` takes an argument, so `allow show interfaces terse`
	// would also run `show interfaces ge-0/0/0 terse`, which the deny holds.
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
		deny("show interfaces **"), permit("show interfaces terse")))
	if err != nil || res.Shape != ShapeCapability || !unsent(res, "show interfaces terse") ||
		!reflect.DeepEqual(res.Attributes, []string{"user-permissions=view view-configuration", `deny-commands=^ *[sS][hH][oO][wW] +` +
			`[iI][nN][tT][eE][rR][fF][aA][cC][eE][sS]( .*)? *(\|.*)?$`}) {
		t.Errorf("capability: %s %q %+v %v", res.Shape, res.Attributes, res.Unsent, err)
	}
	// The fail-closed reply: `deny show route summary` names an argument,
	// and of the permits only `show version` goes out.
	res, err = Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show version"),
		permit("show interfaces terse"), permit("show route **"), deny("show route summary")))
	if err != nil || res.FailClosed != FailArgumentDeny || !unsent(res, "show interfaces terse") ||
		!reflect.DeepEqual(res.Attributes, []string{"user-permissions=view", "deny-commands=^.*$",
			"allow-commands=^show version$"}) {
		t.Errorf("fail-closed: %s %q %+v %v", res.FailClosed, res.Attributes, res.Unsent, err)
	}
	// After the last word: where `show version` takes an argument, `allow
	// show version` would run `show version <argument>`.
	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show version"), permit("show log **"))
	in.Keywords = treeOf(t, `"": {words: [show], argument: false}`, `"show": {words: [log, version], argument: false}`,
		`"show version": {words: [], argument: true}`, `"show log": {words: [], argument: true}`)
	if res, err := Project(in); err != nil || !unsent(res, "show version") || unsent(res, "show log **") {
		t.Errorf("trailing: %q %+v %v", res.Attributes, res.Unsent, err)
	}
	// At the root: where a command may begin with an argument, even `allow
	// show **` would run `<argument> show`.
	in = input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show version"), permit("show log **"))
	in.Keywords = treeOf(t, `"": {words: [show], argument: true}`, `"show": {words: [log, version], argument: false}`,
		`"show version": {words: [], argument: false}`, `"show log": {words: [], argument: true}`)
	if res, err := Project(in); err != nil || !unsent(res, "show log **") || !unsent(res, "show version") {
		t.Errorf("root: %q %+v %v", res.Attributes, res.Unsent, err)
	}
}

// A deny the bits would carry and the device would not enforce, one no
// permit meets, is never sent in the capability shape: a baseline command
// the tree does not prove a keyword goes narrow, `.*` holding it, and is
// never dropped (review I3).
func TestAnUnprovableDenyUnderTheBitsGoesNarrow(t *testing.T) {
	for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
		in := input(delivery, "readonly", measured, permit("show **"))
		in.Dialect.Bits[platform.BaselineBit] = []string{"help **", "exit **", "set cli **"}
		// `help` is proven; `exit` and `set cli` are not, as on the lab's tree.
		in.Keywords = treeOf(t, `"": {words: [help, set, show], argument: false}`,
			`"show": {words: [], argument: true}`, `"help": {words: [], argument: true}`,
			`"set": {words: [], argument: true}`)
		res, err := Project(in)
		if err != nil || res.Shape != ShapeNarrow || !slices.Contains(res.Attributes, "deny-commands=^.*$") {
			t.Fatalf("%s: %s %q %v", delivery, res.Shape, res.Attributes, err)
		}
		for _, v := range [][]string{{"exit"}, {"set", "cli", "x"}, {"help", "topic"}} {
			if res.Device(v) {
				t.Errorf("%s: the reply runs %q", delivery, v)
			}
		}
		// With the tree proving them the same grant is the capability shape,
		// the baseline's denies sent.
		in.Keywords = keywordTree("help", "exit", "set cli")
		if res, err := Project(in); err != nil || res.Shape != ShapeCapability || len(res.Denies) != 3 {
			t.Errorf("%s proven: %s %q %v", delivery, res.Shape, res.Attributes, err)
		}
	}
}

// A reach rule that is a variant of `configure` or `edit` enters
// configuration mode as the bare command does (review M1).
func TestAVariantOfConfigureEntersConfiguration(t *testing.T) {
	for _, r := range []string{"configure", "configure **", "configure private **", "configure exclusive", "edit",
		"edit private", "**"} {
		in := input(platform.BitDeliveryUserPermissions, "operator", measured)
		in.Dialect.Bits["x"] = []string{"show **", r}
		if !newGenerator(in, in.Bits).entersConfiguration("x") {
			t.Errorf("%q does not enter configuration mode", r)
		}
	}
	in := input(platform.BitDeliveryUserPermissions, "operator", measured)
	in.Dialect.Bits["x"] = []string{"show configuration **", "request system configuration rescue **"}
	if newGenerator(in, in.Bits).entersConfiguration("x") {
		t.Error("a reach that names configuration elsewhere enters configuration mode")
	}
}

// On Junos port49 assumes a native RPC may reach whatever the bits reach: a
// CLI session opened NETCONF through `xml-mode`, and whether a wire deny
// binds an RPC there is unmeasured (tests/lab/results/L26c-juniper_*.md, open;
// option C, spec §8). So a composition whose only guard beneath a sent bit is
// a deny — a grant's or the baseline's — fails closed, saying so; one the
// narrow shape's `.*` carries does not, since `.*` refuses both entry points.
func TestACarveOutBeneathASentBitFailsClosed(t *testing.T) {
	rpc := func(res Result) bool {
		return res.Shape == ShapeFailClosed && res.FailClosed == FailRefusedShape &&
			strings.Contains(res.Refusal.Why, "xml-mode") && strings.Contains(res.Refusal.Why, "L26c")
	}
	// admin, everything but one command view-configuration reaches: the
	// capability shape where a deny binds RPCs, refused on Junos.
	rules := []engine.Rule{permit("**"), deny("request security **")}
	res, err := Project(measuredInput(platform.BitDeliveryUserPermissions, "admin", measured, rules...))
	if err != nil || res.Shape != ShapeCapability || len(res.Denies) != 1 {
		t.Fatalf("binding: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "admin", JunosFacts, rules...))
	if err != nil || !rpc(res) || !strings.Contains(res.Refusal.Why, `"request security **"`) ||
		!strings.Contains(res.Refusal.Why, "view-configuration") {
		t.Fatalf("junos: %s %+v %v", res.Shape, res.Refusal, err)
	}
	if !reflect.DeepEqual(res.Attributes[len(res.Attributes)-1:], []string{"deny-commands=^.*$"}) {
		t.Errorf("the fail-closed reply: %q", res.Attributes)
	}
	// The baseline's deny is one too: every session holds what it reaches.
	// operator, every command its bits and the baseline reach but `start`.
	rules = []engine.Rule{permit("show **"), permit("clear **"), permit("request **"), permit("test **")}
	for _, w := range []string{"help", "quit", "exit", "set", "file", "load", "op", "save", "scp", "ping",
		"traceroute", "ssh", "telnet", "mtrace", "probe", "monitor"} {
		rules = append(rules, permit(w+" **"))
	}
	res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "operator", measured, rules...))
	if err != nil || res.Shape != ShapeCapability || len(res.Denies) != 1 || res.Denies[0].Rule != "start **" {
		t.Fatalf("baseline, binding: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "operator", JunosFacts, rules...))
	if err != nil || !rpc(res) || !strings.Contains(res.Refusal.Why, `"start **"`) ||
		!strings.Contains(res.Refusal.Why, "baseline") {
		t.Fatalf("baseline: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	rules = append(rules, permit("start **"))
	// A deny no sent bit, and not the baseline, reaches stays projectable:
	// `restart` is `all`'s alone, and operator holds no `all`.
	in := measuredInput(platform.BitDeliveryUserPermissions, "operator", JunosFacts, append(rules, deny("restart **"))...)
	in.Keywords = keywordTree(append(reachOf(in.Dialect), "restart **")...)
	res, err = Project(in)
	if err != nil || res.Shape != ShapeCapability || len(res.Denies) != 1 || res.Denies[0].Rule != "restart **" {
		t.Fatalf("beyond every bit: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	// The narrow shape's `.*` refuses xml-mode and op url: show ** alone
	// projects.
	res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show **")))
	if err != nil || res.Shape != ShapeNarrow ||
		!reflect.DeepEqual(res.Attributes, []string{"user-permissions=view view-configuration", "deny-commands=^.*$",
			"allow-commands=^ *show( .*)?$"}) && !reflect.DeepEqual(res.Attributes,
			[]string{"user-permissions=view view-configuration", "deny-commands=^.*$", "allow-commands=^show( .*)?$"}) {
		t.Fatalf("narrow: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	// An allow that opens an entry point voids the `.*` for RPCs: refused,
	// and the fail-closed reply leaves it off.
	res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show **"),
		permit("op **")))
	if err != nil || !rpc(res) || !strings.Contains(res.Refusal.Why, `"op **"`) ||
		strings.Count(res.Refusal.Why, "L26c-juniper") != 1 ||
		slices.ContainsFunc(res.Allows, func(a engine.Rule) bool { return a.Rule == "op **" }) {
		t.Fatalf("op: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	if res, err = Project(measuredInput(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
		permit("op **"))); err != nil || res.Shape == ShapeFailClosed {
		t.Fatalf("op, binding: %s %+v %v", res.Shape, res.Refusal, err)
	}
}

func reachOf(d platform.Dialect) []string {
	var out []string
	for _, rules := range d.Bits {
		out = append(out, rules...)
	}
	return out
}

// A deny is left off the wire through a carve-out only where that carve-out
// was measured holding over RPC too, and until L26c closes none was: even
// `show configuration **`, whose empty `<configuration>` the note's table
// does not record, is provisional (final review I-3). So on Junos each deny a
// carve-out holds is sent, and where it guards the CLI alone beneath `view`
// the subject fails closed (review I-1). Where a deny binds RPCs, the
// carve-outs omit both.
func TestOnlyACarveOutMeasuredOverRPCOmitsADeny(t *testing.T) {
	in := func(f Facts) Input {
		in := input(platform.BitDeliveryUserPermissions, "readonly", f, permit("show **"),
			deny("show configuration **"), deny("show log **"))
		in.Dialect.Bits["view-configuration"] = []string{"show configuration **", "show log **"}
		in.Dialect.CarveOuts["view-configuration"] = []string{"show configuration **", "show log **"}
		in.Keywords = keywordTree("show log **", "show configuration **")
		return in
	}
	res, err := Project(in(measured))
	if err != nil || res.Shape != ShapeCapability || len(res.Omitted) != 2 ||
		!reflect.DeepEqual(res.Attributes, []string{"user-permissions=view"}) {
		t.Fatalf("binding: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	res, err = Project(in(JunosFacts))
	if err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape ||
		len(res.Omitted) != 0 || !strings.Contains(res.Refusal.Why, "L26c") {
		t.Fatalf("junos: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	// Nor does `show configuration **` alone: its deny is sent, and fails
	// closed beneath `view`.
	res, err = Project(input(platform.BitDeliveryUserPermissions, "readonly", JunosFacts, permit("show **"),
		deny("show configuration **")))
	if err != nil || res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape || len(res.Omitted) != 0 ||
		!strings.Contains(res.Refusal.Why, `deny "show configuration **"`) || !strings.Contains(res.Refusal.Why, "L26c") {
		t.Fatalf("show configuration: %s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
	if len(rpcCarves) != 0 {
		t.Fatalf("a carve-out omits a deny over RPC before L26c closes: %q", rpcCarves)
	}
}

// The refusal an operator reads states RPC reach as port49's assumption,
// provisional on the open L26c, never as a measurement (Task 20 re-review
// R-I1).
func TestTheRPCReachRefusalSaysItIsAnAssumption(t *testing.T) {
	why := generator{in: Input{Platform: "juniper_junos"}}.rpcWhy()
	for _, want := range []string{
		"on juniper_junos port49 assumes a native RPC may reach whatever the bits reach",
		"whether a wire deny binds them there is unmeasured",
		"L26c-juniper_*.md, open; option C, spec §8",
		"so port49 fails the composition closed",
	} {
		if !strings.Contains(why, want) {
			t.Errorf("rpcWhy lacks %q: %s", want, why)
		}
	}
	for _, overclaim := range []string{"binds the CLI only", "whole reach", "no deny applies", "CLI-only safe"} {
		if strings.Contains(why, overclaim) {
			t.Errorf("rpcWhy asserts the unmeasured %q: %s", overclaim, why)
		}
	}
}
