package projection

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// junos is a projected Junos adapter as the tests read one: spec §8's bits,
// view-configuration's measured carve-out, and the levels' ceilings.
func junos(delivery string) platform.Dialect {
	d := platform.Dialect{Supports: []string{"session"}, PipeToken: "|", StripCR: true,
		CommandProjection: platform.ProjectionJunosRegex, BitDelivery: delivery,
		Bits: map[string][]string{"view": {"show **"}, "view-configuration": {"show configuration **"},
			"clear": {"clear **"}, "network": {"ping **", "traceroute **"}, "configure": {"configure **"},
			"all": {"**"}},
		CarveOuts: map[string][]string{"view-configuration": {"show configuration **"}},
		CeilingBits: map[string][]string{"readonly": {"view", "view-configuration"},
			"operator": {"view", "view-configuration", "clear", "network"}, "admin": {"all"}}}
	if delivery == platform.BitDeliveryLocalUserName {
		d.LocalUserNames = map[string]string{"readonly": "p49-readonly", "operator": "p49-operator", "admin": "p49-admin"}
	}
	return d
}

var measured = Facts{CaseSensitive: true, DenyMatchesExpanded: true}

func input(delivery, level string, f Facts, rules ...engine.Rule) Input {
	d := junos(delivery)
	return Input{Platform: "juniper_junos", Dialect: d, Level: level, Bits: d.CeilingBits[level],
		Template: d.LocalUserNames[level], Rules: rules,
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}, Facts: f}
}

func permit(rule string) engine.Rule {
	return engine.Rule{Verdict: engine.Permit, Rule: rule, Role: "r"}
}
func deny(rule string) engine.Rule { return engine.Rule{Verdict: engine.Deny, Rule: rule, Role: "d"} }

// Spec §8's realistic readonly: a deny aligned with a bit drops the bit and
// sends nothing for the deny.
func TestADenyAlignedWithABitDropsIt(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
		permit("show **"), deny("show configuration **")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Shape != ShapeCapability || !reflect.DeepEqual(res.Attributes, []string{"user-permissions=view"}) ||
		len(res.Omitted) != 1 {
		t.Fatalf("%+v", res)
	}
	if res.Device([]string{"show", "configuration"}) || !res.Device([]string{"show", "version"}) {
		t.Error("the device model disagrees with the reply")
	}
}

// Under a template the class carries every bit of the level, so the deny
// travels as a regex.
func TestATemplateCarriesTheLevelsBits(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryLocalUserName, "readonly", measured,
		permit("show **"), deny("show configuration **")))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"local-user-name=p49-readonly",
		`deny-commands=^ *[sS][hH][oO][wW] +[cC][oO][nN][fF][iI][gG][uU][rR][aA][tT][iI][oO][nN]( .*)? *(\|.*)?$`}
	if !reflect.DeepEqual(res.Attributes, want) {
		t.Fatalf("%q", res.Attributes)
	}
}

// A permit beneath a deny dominates it in port49, so it travels as an allow,
// which beats the deny on the device too (L11).
func TestAPermitBeneathADenyIsAnAllow(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
		permit("show **"), deny("show configuration **"), permit("show configuration interfaces **")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Denies) != 1 || len(res.Allows) != 1 ||
		res.Attributes[2] != "allow-commands=^show configuration interfaces( .*)?$" {
		t.Fatalf("%q", res.Attributes)
	}
	if !res.Device([]string{"show", "configuration", "interfaces", "fxp0"}) ||
		res.Device([]string{"show", "configuration", "system"}) {
		t.Error("device model")
	}
}

// Spec §8's read_only_limited: permits narrower than every bit render as
// deny .* and one allow alternation, under the bits that reach them.
func TestANarrowGrantIsDenyAllAndOneAllow(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
		permit("show version"), permit("show interfaces **"), permit("show route **")))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"user-permissions=view", "deny-commands=^.*$",
		"allow-commands=^(show version|show interfaces( .*)?|show route( .*)?)$"}
	if res.Shape != ShapeNarrow || !reflect.DeepEqual(res.Attributes, want) {
		t.Fatalf("%s %q", res.Shape, res.Attributes)
	}
}

// The refused shape gets the fail-closed reply, which names the two rules
// and the platform for CI: deny everything, and no allow, since the one
// permit meets the deny beneath it (decision 26).
func TestTheRefusedShapeFailsClosed(t *testing.T) {
	for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
		res, err := Project(input(delivery, "readonly", measured,
			permit("show interfaces **"), deny("show interfaces terse"), permit("show version")))
		if err != nil {
			t.Fatal(err)
		}
		r := res.Refusal
		if res.Shape != ShapeFailClosed || res.FailClosed != FailRefusedShape || r == nil ||
			!strings.Contains(r.Why, `permit "show interfaces **"`) ||
			!strings.Contains(r.Why, `deny "show interfaces terse"`) || !strings.Contains(r.Why, "juniper_junos") {
			t.Fatalf("%s: %+v", delivery, res)
		}
		// show version is proven and goes out; the template never does, so the
		// session lands in the bitless p49-remote.
		want := []string{"deny-commands=^.*$", "allow-commands=^show version$"}
		if delivery == platform.BitDeliveryUserPermissions {
			want = append([]string{"user-permissions=view"}, want...)
		}
		if !reflect.DeepEqual(res.Attributes, want) || len(res.Beyond) != 1 {
			t.Errorf("%s: %q, beyond %v", delivery, res.Attributes, res.Beyond)
		}
		if res.Device([]string{"show", "interfaces", "terse"}) || res.Device([]string{"show", "interfaces", "em0"}) {
			t.Errorf("%s: the fail-closed reply runs a command it did not prove", delivery)
		}
	}
}

// A permit no ceiling bit reaches is never sent: the device refuses it where
// port49 would permit it, which fails closed, and CI says so.
func TestAPermitBeyondTheCeilingIsNotSent(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
		permit("show **"), permit("clear counters")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Beyond) != 1 || res.Beyond[0].Rule != "clear counters" || len(res.Allows) != 0 {
		t.Fatalf("%+v", res)
	}
	if n := res.Narrower(5); len(n) != 1 || strings.Join(n[0], " ") != "clear counters" {
		t.Errorf("narrower: %q", n)
	}
}

func TestAdmin(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**")))
	if err != nil || !reflect.DeepEqual(res.Attributes, []string{"user-permissions=all"}) {
		t.Fatalf("%q %v", res.Attributes, err)
	}
	// A deny under bits that enter configuration mode cannot be carried: a
	// statement there is no command the regexes reach. Under user_permissions
	// those bits are dropped and the rest is proven (decision 26): the admin
	// keeps every operational command the other bits reach, less the deny.
	res, err = Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**"),
		deny("request system reboot **")))
	if err != nil || res.Shape != ShapeCapability ||
		!reflect.DeepEqual(res.ConfigurationDropped, []string{"all", "configure"}) ||
		res.Attributes[0] != "user-permissions=clear network view view-configuration" {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Device([]string{"configure"}) || !res.Device([]string{"show", "configuration"}) {
		t.Error("device model")
	}
	// Under local_user_name the template's class carries the level's bits
	// whole, so there is nothing to drop: the fail-closed reply.
	res, err = Project(input(platform.BitDeliveryLocalUserName, "admin", measured, permit("**"),
		deny("request system reboot **")))
	if err != nil || res.FailClosed != FailConfigurationMode ||
		!reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$"}) ||
		!strings.Contains(res.Refusal.Why, "enters configuration mode") {
		t.Fatalf("%+v %v", res, err)
	}
}

// A narrow admin grant takes the smallest bits that reach its permits, not
// all, which would enter configuration mode and be refused (I11).
func TestANarrowAdminTakesTheSmallestBits(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("show version"),
		permit("ping **")))
	want := []string{"user-permissions=network view", "deny-commands=^.*$",
		"allow-commands=^(show version|ping( .*)?)$"}
	if err != nil || res.Shape != ShapeNarrow || !reflect.DeepEqual(res.Attributes, want) {
		t.Fatalf("%s %q %v", res.Shape, res.Attributes, err)
	}
}

func TestOperator(t *testing.T) {
	rules := []engine.Rule{permit("show **"), permit("clear **"), permit("ping **"), deny("clear bgp **")}
	res, err := Project(input(platform.BitDeliveryUserPermissions, "operator", measured, rules...))
	if err != nil {
		t.Fatal(err)
	}
	// network also reaches traceroute, which nothing permits: ping goes as an
	// allow instead of the bit.
	if !reflect.DeepEqual(res.Bits, []string{"clear", "view", "view-configuration"}) || len(res.Allows) != 1 ||
		res.Allows[0].Rule != "ping **" || len(res.Denies) != 1 {
		t.Fatalf("%+v", res)
	}
	// Where a deny can be walked past by abbreviating it, only .* is sent, and
	// the operator's shape is refused: clear ** would beat clear bgp **. The
	// subject keeps what is proven: show and ping, not clear.
	res, err = Project(input(platform.BitDeliveryUserPermissions, "operator", Facts{CaseSensitive: true}, rules...))
	want := []string{"user-permissions=network view view-configuration", "deny-commands=^.*$",
		"allow-commands=^(show( .*)?|ping( .*)?)$"}
	if err != nil || res.FailClosed != FailRefusedShape || !reflect.DeepEqual(res.Attributes, want) {
		t.Fatalf("%q %v", res.Attributes, err)
	}
	if res.Device([]string{"clear", "bgp", "neighbor"}) || res.Device([]string{"clear", "arp"}) {
		t.Error("the fail-closed reply runs clear")
	}
}

func TestNoLevelIsDenyAll(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "", measured, permit("show **")))
	if err != nil || !reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$"}) || len(res.Beyond) != 1 {
		t.Fatalf("%q %v", res.Attributes, err)
	}
}

func TestSecretsAndBudget(t *testing.T) {
	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
		deny("show snmp community hunter2"))
	in.Secret = func(rule string) bool { return strings.Contains(rule, "hunter2") }
	if res, err := Project(in); err != nil || res.FailClosed != FailSecretRule ||
		!strings.Contains(res.Refusal.Why, "redaction hides") ||
		!reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$"}) {
		t.Fatalf("secret: %+v %v", res, err)
	}
	var rules []engine.Rule
	rules = append(rules, permit("show **"))
	for _, w := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"} {
		rules = append(rules, deny("show "+w+" **"))
	}
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, rules...))
	r := res.Refusal
	if err != nil || res.FailClosed != FailOverflow || r.Attribute != "deny-commands" ||
		!strings.HasPrefix(r.Value, "^(") || r.Class != platform.RemoteClass {
		t.Fatalf("over budget: %+v %v", res, err)
	}
	// An allow past the budget is never moved into a class, where it would
	// run for every subject past their own denies (C2): no class line.
	rules = nil
	for i := range 16 {
		rules = append(rules, permit(fmt.Sprintf("show interfaces ge-0/0/%d extensive", i)))
	}
	res, err = Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, rules...))
	if r := res.Refusal; err != nil || res.FailClosed != FailOverflow || r.Attribute != "allow-commands" ||
		r.Class != "" || !strings.Contains(r.Why, "narrow the grant") {
		t.Fatalf("allow over budget: %+v %v", res, err)
	}
	// The allows cannot go out whole, so none does.
	if !reflect.DeepEqual(res.Attributes, []string{"deny-commands=^.*$"}) || len(res.Beyond) != 16 {
		t.Errorf("%q", res.Attributes)
	}
}

// A permit a bit outside the ceiling carves out of a bit inside it is beyond
// the ceiling: an allow for it would run what the level's bits do not.
func TestACarvedPermitIsBeyondTheCeiling(t *testing.T) {
	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
		deny("show configuration **"), permit("show configuration interfaces **"))
	in.Bits = []string{"view"}
	res, err := Project(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Allows) != 0 || len(res.Beyond) != 1 || res.Beyond[0].Rule != "show configuration interfaces **" {
		t.Fatalf("%+v", res)
	}
}

// A bit's reach is a union (C1): a bit not held never takes a command out of
// one that is, so a deny under a held bit's reach is sent, whatever reach a
// bit outside the ceiling claims. Only a measured carve-out licenses leaving
// a deny off the wire.
func TestAnUnheldBitRemovesNothing(t *testing.T) {
	in := input(platform.BitDeliveryLocalUserName, "readonly", measured, permit("show **"), deny("show log **"))
	in.Dialect.Bits["trace"] = []string{"monitor **", "show log **"}
	res, err := Project(in)
	if err != nil || len(res.Omitted) != 0 || len(res.Denies) != 1 || res.Denies[0].Rule != "show log **" {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Device([]string{"show", "log", "messages"}) {
		t.Error("the device runs a command port49 denies")
	}
}

// The baseline runs its commands for every session, so each no permit holds
// is denied on the wire (I3), and a bit never drops it.
func TestTheBaselineIsDenied(t *testing.T) {
	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"))
	in.Dialect.Bits[platform.BaselineBit] = []string{"quit **", "show cli **"}
	res, err := Project(in)
	if err != nil || res.Shape != ShapeCapability || len(res.Denies) != 1 ||
		res.Denies[0].Rule != "quit **" || res.Denies[0].Role != platform.BaselineBit {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Device([]string{"quit"}) || !res.Device([]string{"show", "cli"}) {
		t.Error("device model")
	}
	// Where a deny may be walked past, the baseline's deny sends the grant
	// narrow, and .* holds it.
	in.Facts = Facts{CaseSensitive: true}
	res, err = Project(in)
	if err != nil || res.Shape != ShapeNarrow || res.Device([]string{"quit"}) {
		t.Fatalf("%+v %v", res, err)
	}
}
