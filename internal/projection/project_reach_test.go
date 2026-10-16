package projection

import (
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

func denyCommands(res Result) string {
	for _, a := range res.Attributes {
		if strings.HasPrefix(a, "deny-commands=") {
			return a
		}
	}
	return ""
}

// Set 1.3.0 sends a readonly granted `show **` less `show security **`
// `view view-configuration`, `monitor **` denied (decision 48): byte for byte
// set 1.2.0's reply to the same grant writing `deny: [monitor **]`, which L68
// measured (row P). Its deny-commands is 173 bytes, within RFC 8907 (R2).
func TestTheSet130ReadonlySendsViewConfiguration(t *testing.T) {
	res, err := Project(shipped("1.3.0", "readonly", permit("show **"), deny("show security **")))
	if err != nil || res.Shape != ShapeCapability || !slices.Equal(res.Bits, []string{"view", "view-configuration"}) ||
		!res.EntryDenied() || len(res.Allows) != 0 || len(res.Closed) != 1 {
		t.Fatalf("%s %q allows %v %+v %v", res.Shape, res.Attributes, res.Allows, res.Refusal, err)
	}
	measured, err := Project(shipped("1.2.0", "readonly", permit("show **"), deny("show security **"),
		deny("monitor **")))
	if err != nil || !slices.Equal(res.Attributes, measured.Attributes) {
		t.Fatalf("not L68's reply:\n 1.3.0 %q\n 1.2.0 %q %v", res.Attributes, measured.Attributes, err)
	}
	if n := len(denyCommands(res)); n != 173 || n > engine.MaxAttribute {
		t.Errorf("deny-commands is %d bytes, want 173", n)
	}
	if rd := res.ReachDenies(); len(rd) != 1 || rd[0].Rule != "monitor **" || rd[0].Role != platform.ReachDenyRole {
		t.Errorf("reach denies: %v", rd)
	}
	if len(res.ConfigurationBeneath) != 0 {
		t.Errorf("a reach deny is named beneath view-configuration: %v", res.ConfigurationBeneath)
	}
	for _, c := range []struct {
		v    []string
		runs bool
	}{
		{[]string{"show", "configuration", "system", "host-name"}, true},
		{[]string{"show", "log", "messages"}, true},
		{[]string{"show", "version"}, true},
		{[]string{"show", "security", "zones"}, false},
		{[]string{"monitor", "list"}, false},
		{[]string{"request", "mpls", "lsp"}, false},
		{[]string{"junoscript"}, false},
	} {
		if got := res.Device(c.v); got != c.runs || res.Unmeasured(c.v) {
			t.Errorf("%v: runs %v (unmeasured %v), want %v", c.v, got, res.Unmeasured(c.v), c.runs)
		}
	}
	if n := res.Narrower(3); len(n) != 0 {
		t.Errorf("the device refuses what port49 permits: %v", n)
	}
}

// A policy pinned to 1.2.0 renders as before (Review Focus 1): the readonly
// deny-beneath-show grants keep `view` and their carved allows, the bytes
// TestAReadonlyWithAShowDenyFitsTheBudget measured. Under 1.3.0 a deny of
// `show configuration` renders as 1.2.0 does: the grant denies what only
// view-configuration adds, so it stays out.
func TestSet120RendersAsBefore(t *testing.T) {
	for _, c := range []struct {
		deny  string
		bytes int
	}{{"show configuration **", 170}, {"show security **", 165}} {
		res, err := Project(shipped("1.2.0", "readonly", permit("show **"), deny(c.deny)))
		if err != nil || !slices.Equal(res.Bits, []string{"view"}) || len(denyCommands(res)) != c.bytes ||
			len(res.ReachDenies()) != 0 {
			t.Errorf("1.2.0 %s: %s %q %v", c.deny, res.Shape, res.Attributes, err)
		}
	}
	was, _ := Project(shipped("1.2.0", "readonly", permit("show **"), deny("show configuration **")))
	is, err := Project(shipped("1.3.0", "readonly", permit("show **"), deny("show configuration **")))
	if err != nil || !slices.Equal(is.Attributes, was.Attributes) {
		t.Errorf("1.3.0 show configuration denied:\n %q\n %q %v", is.Attributes, was.Attributes, err)
	}
	was, _ = Project(shipped("1.2.0", "operator", permit("**"), deny("show configuration **")))
	is, err = Project(shipped("1.3.0", "operator", permit("**"), deny("show configuration **")))
	if err != nil || !slices.Equal(is.Attributes, was.Attributes) || len(is.ConfigurationBeneath) != 1 {
		t.Errorf("1.3.0 operator:\n %q\n %q %v", is.Attributes, was.Attributes, err)
	}
}

// Without the entry deny the key is inert (Review Focus 2): view-configuration
// is never sent with wire denies alone guarding an RPC-reachable bit.
func TestReachDeniesNeedTheEntryDeny(t *testing.T) {
	in := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	in.Dialect.RPCEntryDenies = nil
	res, err := Project(in)
	if err != nil || res.Shape != ShapeFailClosed || slices.Contains(res.Bits, "view-configuration") ||
		len(res.ReachDenies()) != 0 {
		t.Fatalf("%s %q %+v %v", res.Shape, res.Attributes, res.Refusal, err)
	}
}

// A permit inside the undecided reach declines the reach deny (Review Focus
// 3): a deny of `monitor **` would sit beneath `monitor interface **`. The
// composition renders as set 1.2.0 renders it.
func TestReachDeniesDeclineAPermittedReach(t *testing.T) {
	rules := []engine.Rule{permit("show **"), permit("monitor interface **"), deny("show security **")}
	is, err := Project(shipped("1.3.0", "readonly", rules...))
	was, err2 := Project(shipped("1.2.0", "readonly", rules...))
	if err != nil || err2 != nil || len(is.ReachDenies()) != 0 || !slices.Equal(is.Attributes, was.Attributes) ||
		is.FailClosed == FailUnsound {
		t.Fatalf("1.3.0 %s %q\n1.2.0 %s %q %v %v", is.Shape, is.Attributes, was.Shape, was.Attributes, err, err2)
	}
}

// A block that adds reach to view-configuration (Review Focus 4): a rule the
// shipped tree proves (`restart`, a root keyword no baseline deny holds) is
// denied too, and the device refuses it; one it does not prove (nothing under
// `clear` is proven) keeps the 1.2.0 render.
func TestAddedReachIsDeniedOrDeclined(t *testing.T) {
	in := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	in.Dialect.Bits["view-configuration"] = append(slices.Clone(in.Dialect.Bits["view-configuration"]), "restart **")
	res, err := Project(in)
	if err != nil || !slices.ContainsFunc(res.ReachDenies(), func(d engine.Rule) bool { return d.Rule == "restart **" }) ||
		res.Device([]string{"restart", "routing"}) || len(denyCommands(res)) > engine.MaxAttribute {
		t.Errorf("proven: %s %q reach %v %v", res.Shape, res.Attributes, res.ReachDenies(), err)
	}
	in = shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	in.Dialect.Bits["view-configuration"] = append(slices.Clone(in.Dialect.Bits["view-configuration"]), "clear zzz **")
	res, err = Project(in)
	off := in
	off.Dialect.DenyReachBits = nil
	was, err2 := Project(off)
	if err != nil || err2 != nil || len(res.ReachDenies()) != 0 || slices.Contains(res.Bits, "view-configuration") ||
		!slices.Equal(res.Attributes, was.Attributes) {
		t.Errorf("unproven: %s %q, without the key %q %v %v", res.Shape, res.Attributes, was.Attributes, err, err2)
	}
}

// Under local_user_name the template's class carries every bit, and the
// branch is unchanged (Review Focus 5).
func TestATemplateDeliveryIsUnchanged(t *testing.T) {
	tmpl := func(version string) Input {
		in := shipped(version, "readonly", permit("show **"), deny("show security **"))
		in.Dialect.BitDelivery = platform.BitDeliveryLocalUserName
		in.Dialect.LocalUserNames = map[string]string{"readonly": "p49-readonly", "operator": "p49-operator",
			"admin": "p49-admin"}
		in.Template = "p49-readonly"
		return in
	}
	is, err := Project(tmpl("1.3.0"))
	was, err2 := Project(tmpl("1.2.0"))
	if err != nil || err2 != nil || !slices.Equal(is.Attributes, was.Attributes) || len(is.ReachDenies()) != 0 {
		t.Fatalf("1.3.0 %q\n1.2.0 %q %v %v", is.Attributes, was.Attributes, err, err2)
	}
}

// view-configuration alone shows no configuration (L12-bits), so a grant of
// `show configuration **` alone, where `view` is not sent, keeps the narrow
// shape and sends no reach deny.
func TestTheBitIsNotSentAloneForItsCarveOut(t *testing.T) {
	res, err := Project(shipped("1.3.0", "readonly", permit("show configuration **")))
	was, _ := Project(shipped("1.2.0", "readonly", permit("show configuration **")))
	if err != nil || len(res.ReachDenies()) != 0 || len(res.ReachOverflow) != 0 ||
		!slices.Equal(res.Attributes, was.Attributes) {
		t.Fatalf("%s %q overflow %v, 1.2.0 %q %v", res.Shape, res.Attributes, res.ReachOverflow, was.Attributes, err)
	}
}

// reachDenies' guards, read directly. An end-to-end test cannot see them, since
// a later stage can mask each one: without the entry deny `capability` goes
// narrow anyway, and a bit sent alone overflows into the fallback (pre-flight
// I1).
func TestReachDeniesGuards(t *testing.T) {
	view := []string{"view"}
	in := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	if rest, ok := newGenerator(in, in.Bits).reachDenies("view-configuration", view); !ok || len(rest) != 1 {
		t.Fatalf("control: the readonly denying show security needs the bit: %v %v", rest, ok)
	}
	noEntry := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	noEntry.Dialect.RPCEntryDenies = nil
	if _, ok := newGenerator(noEntry, noEntry.Bits).reachDenies("view-configuration", view); ok {
		t.Error("sent without the entry deny")
	}
	g := newGenerator(in, in.Bits)
	g.noReach = true
	if _, ok := g.reachDenies("view-configuration", view); ok {
		t.Error("sent under noReach")
	}
	alone := shipped("1.3.0", "readonly", permit("show configuration **"))
	if _, ok := newGenerator(alone, alone.Bits).reachDenies("view-configuration", nil); ok {
		t.Error("sent beside no bit that reaches the carve-out")
	}
	unproven := shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))
	unproven.Dialect.Bits["view-configuration"] = append(slices.Clone(unproven.Dialect.Bits["view-configuration"]),
		"clear zzz **")
	if _, ok := newGenerator(unproven, unproven.Bits).reachDenies("view-configuration", view); ok {
		t.Error("sent with a reach rule the tree does not prove")
	}
}

// The mechanism holds at any level whose ceiling holds view-configuration
// (pre-flight I6). An operator granted `show **` and `clear **` less `show
// security **` gets `clear view view-configuration` and the 173 bytes L68's
// row O measured, where set 1.2.0 sends `clear view` and carved allows.
func TestTheSet130OperatorSendsViewConfiguration(t *testing.T) {
	rules := []engine.Rule{permit("show **"), permit("clear **"), deny("show security **")}
	res, err := Project(shipped("1.3.0", "operator", rules...))
	measured, err2 := Project(shipped("1.2.0", "operator", append(slices.Clone(rules), deny("monitor **"))...))
	if err != nil || err2 != nil || !slices.Equal(res.Bits, []string{"clear", "view", "view-configuration"}) ||
		!slices.Equal(res.Attributes, measured.Attributes) || len(denyCommands(res)) != 173 {
		t.Fatalf("1.3.0 %s %q row O %q %v %v", res.Shape, res.Attributes, measured.Attributes, err, err2)
	}
	if was, _ := Project(shipped("1.2.0", "operator", rules...)); !slices.Equal(was.Bits, []string{"clear", "view"}) {
		t.Errorf("1.2.0 operator: %q", was.Attributes)
	}
	for _, c := range []struct {
		v    []string
		runs bool
	}{
		{[]string{"show", "configuration", "system", "host-name"}, true},
		{[]string{"clear", "interfaces", "statistics", "fxp0"}, true},
		{[]string{"show", "security", "zones"}, false},
		{[]string{"monitor", "list"}, false},
	} {
		if got := res.Device(c.v); got != c.runs {
			t.Errorf("%v: runs %v, want %v", c.v, got, c.runs)
		}
	}
}

// R2 (controller's ruling, 2026-10-16): where the reach denies would take
// deny-commands past 255 bytes, the reply falls back to set 1.2.0's. That
// means no view-configuration, the carved allows, and the device refusing
// `show configuration`, here byte for byte the 249-byte reply 1.2.0 sends.
// ReachOverflow names the denies left off, for the warning. `monitor` alone
// takes 1.3.0's past 255.
func TestAReachDenyPastTheBudgetFallsBackToTheCarvedReply(t *testing.T) {
	rules := []engine.Rule{permit("show **"), deny("show security **"), deny("show route **"), deny("show bgp **"),
		deny("show ospf **")}
	was, err := Project(shipped("1.2.0", "readonly", rules...))
	if err != nil || was.Shape != ShapeCapability || len(denyCommands(was)) != 249 {
		t.Fatalf("1.2.0: %s %q %v", was.Shape, was.Attributes, err)
	}
	res, err := Project(shipped("1.3.0", "readonly", rules...))
	if err != nil || res.Shape != ShapeCapability || res.FailClosed != "" || !slices.Equal(res.Attributes, was.Attributes) ||
		slices.Contains(res.Bits, "view-configuration") || len(res.ReachDenies()) != 0 {
		t.Fatalf("not 1.2.0's reply: %s %q %+v %v\n 1.2.0 %q", res.Shape, res.Attributes, res.Refusal, err, was.Attributes)
	}
	if len(res.ReachOverflow) != 1 || res.ReachOverflow[0].Rule != "monitor **" {
		t.Errorf("reach overflow: %v", res.ReachOverflow)
	}
	if res.Device([]string{"show", "configuration", "system", "host-name"}) || !res.Device([]string{"show", "version"}) {
		t.Error("the fallback is not 1.2.0's measured reading")
	}
	// A reply that fits records no overflow.
	if fits, _ := Project(shipped("1.3.0", "readonly", permit("show **"), deny("show security **"))); len(fits.ReachOverflow) != 0 {
		t.Errorf("a fitting reply records an overflow: %v", fits.ReachOverflow)
	}
}

// configurationBeneath never names a reach deny, even one that meets `show
// configuration` (decision 48 ruling 5).
func TestConfigurationBeneathSkipsAReachDeny(t *testing.T) {
	g := newGenerator(shipped("1.3.0", "readonly", permit("show **")), []string{"view", "view-configuration"})
	res := Result{Bits: []string{"view", "view-configuration"},
		Denies: []engine.Rule{{Verdict: engine.Deny, Rule: "show configuration **", Role: platform.ReachDenyRole}}}
	if got := g.configurationBeneath(res); len(got) != 0 {
		t.Errorf("%v", got)
	}
}

// A readonly permitting exactly the hierarchies the bits do not reach, `show
// configuration` among them, is rendered as set 1.2.0 renders it, with no reach
// deny: the `reached` guard. The reach words are all permitted, so view-
// configuration would send the device's refusal of what port49 permits.
func TestAPermitOfTheConfigurationHierarchiesSendsNoReachDeny(t *testing.T) {
	rules := []engine.Rule{permit("show configuration **"), permit("show log **"), permit("show firewall **"),
		permit("show policer **")}
	res, err := Project(shipped("1.3.0", "readonly", rules...))
	was, werr := Project(shipped("1.2.0", "readonly", rules...))
	if err != nil || werr != nil || len(res.ReachDenies()) != 0 || !slices.Equal(res.Attributes, was.Attributes) {
		t.Fatalf("1.3.0 %q %v\n1.2.0 %q %v", res.Attributes, err, was.Attributes, werr)
	}
}

// Where the fallback overflows too, the refusal is the fallback's, quoting the
// length the grant's own denies make, not one with the reach deny added.
func TestADoubleOverflowQuotesTheFallbacksLength(t *testing.T) {
	rules := []engine.Rule{permit("show **"), deny("show security **"), deny("show route **"), deny("show bgp **"),
		deny("show ospf **"), deny("show isis **"), deny("show chassis **"), deny("show system **"),
		deny("show interfaces **")}
	was, _ := Project(shipped("1.2.0", "readonly", rules...))
	res, err := Project(shipped("1.3.0", "readonly", rules...))
	if err != nil || was.FailClosed != FailOverflow || res.FailClosed != FailOverflow ||
		res.Refusal.Value != was.Refusal.Value || strings.Contains(res.Refusal.Value, "monitor") {
		t.Fatalf("1.3.0 %+v %v\n1.2.0 %+v", res.Refusal, err, was.Refusal)
	}
}
