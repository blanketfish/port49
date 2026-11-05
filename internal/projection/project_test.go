package projection

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/platform"
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

// measured is a device whose every fact is the permissive one, a wire deny
// binding every RPC a CLI session reaches included: what the capability
// shape's own logic is tested under. JunosFacts is the shipped device, where
// a deny beneath a sent bit fails closed (TestACarveOutBeneathASentBitFailsClosed).
var measured = Facts{CaseSensitive: true, DenyMatchesExpanded: true, DenyBindsRPCs: true}

func input(delivery, level string, f Facts, rules ...engine.Rule) Input {
	d := junos(delivery)
	return Input{Platform: "juniper_junos", Dialect: d, Level: level, Bits: d.CeilingBits[level],
		Template: d.LocalUserNames[level], Rules: rules,
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}, Facts: f,
		Keywords: testKeywords}
}

// testKeywords is a keyword tree in the shape the lab captures (Task 3b):
// every word these tests deny or allow as a keyword, and an argument after
// `show interfaces`, `show route`, `show log`, `ping` and the rest, as Junos
// takes one there.
var testKeywords = keywordTree()

// keywordTree is testKeywords with every word of each proven rule a keyword
// at its place, and no argument after it where the tree has no node there:
// the tree a fixture whose adapter reaches more than testKeywords needs.
func keywordTree(proven ...string) *platform.Keywords {
	type node struct {
		words string
		arg   bool
	}
	nodes := map[string]node{
		"":                              {"clear configure exit help monitor ping quit request set show traceroute", false},
		"show":                          {"alpha bravo charlie chassis cli configuration delta echo foxtrot golf hotel india interfaces juliett kilo lima log mike november oscar papa route snmp system version", false},
		"show interfaces":               {"extensive terse", true},
		"show interfaces terse":         {"", true},
		"show configuration":            {"interfaces system", false},
		"show configuration interfaces": {"", true},
		"show configuration system":     {"", false},
		"show version":                  {"", false},
		"show route":                    {"", true},
		"show log":                      {"", true},
		"show system":                   {"uptime", false},
		"clear":                         {"bgp counters interfaces", false},
		"clear bgp":                     {"neighbor", false},
		"clear counters":                {"", false},
		"request":                       {"system", false},
		"request system":                {"reboot", false},
		"ping":                          {"", true},
		"traceroute":                    {"", true},
		"monitor":                       {"", true},
		"set":                           {"cli", false},
		"set cli":                       {"", true},
		"quit":                          {"", false},
		"exit":                          {"", false},
		"configure":                     {"", false},
	}
	for _, w := range strings.Fields("alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa") {
		nodes["show "+w] = node{"", false}
	}
	for _, r := range proven {
		var path []string
		for _, w := range strings.Fields(strings.TrimSuffix(r, "**")) {
			n := nodes[strings.Join(path, " ")]
			if !slices.Contains(strings.Fields(n.words), w) {
				n.words += " " + w
				nodes[strings.Join(path, " ")] = n
			}
			path = append(path, w)
			if _, ok := nodes[strings.Join(path, " ")]; !ok {
				nodes[strings.Join(path, " ")] = node{}
			}
		}
	}
	var b strings.Builder
	b.WriteString("platform: juniper_junos\nnodes:\n")
	for path, n := range nodes {
		words := strings.Fields(n.words)
		slices.Sort(words)
		fmt.Fprintf(&b, "  %q: {words: [%s], argument: %v}\n", path, strings.Join(words, ", "), n.arg)
	}
	_, k, err := platform.ParseKeywords([]byte(b.String()))
	if err != nil {
		panic(err)
	}
	return k
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
	for _, w := range strings.Fields("alpha bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa") {
		rules = append(rules, permit("show "+w+" **"))
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

// A reply widens where the device can do more under it: a bit it did not
// hold, or a command it did not run. Narrowing the grant is no widening,
// whatever the regexes say (plan 5b pre-flight I14).
func TestWidens(t *testing.T) {
	project := func(rules ...engine.Rule) *Result {
		res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, rules...))
		if err != nil {
			t.Fatal(err)
		}
		return &res
	}
	all := project(permit("show **"))
	carved := project(permit("show **"), deny("show configuration **"))
	narrow := project(permit("show version"), permit("show interfaces **"))
	narrower := project(permit("show version"))
	for _, c := range []struct {
		name     string
		from, to *Result
		want     bool
	}{
		{"a carve-out drops a bit", all, carved, false},
		{"lifting it adds the bit back", carved, all, true},
		{"a narrow grant loses a permit", narrow, narrower, false},
		{"and gains it back", narrower, narrow, true},
		{"nothing before", nil, narrower, true},
		{"the same reply", narrow, narrow, false},
	} {
		if _, got := Widens(c.from, c.to); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if v, _ := Widens(narrower, narrow); strings.Join(v, " ") == "" {
		t.Error("a widening by a command names it")
	}
}

// Junos matches a deny against a command's keywords only (decision 27): a
// deny that meets a permit and names an argument is one the device never
// enforces, so the subject gets the fail-closed reply, and the refusal names
// the word and the whole command to deny instead. Classes, regexes and `*`
// stand for arguments; a deny no permit meets is no_rule_matched anyway.
func TestADenyNamingAnArgumentFailsClosed(t *testing.T) {
	for _, c := range []struct{ deny, word, instead string }{
		{"show interfaces fxp0", "`fxp0` in `deny show interfaces fxp0`", "deny the whole command (`show interfaces`)"},
		{"show interfaces fxp0 **", "`fxp0`", "deny the whole command (`show interfaces`)"},
		{"show interfaces @management", "`@management`", "@management stands for an argument"},
		{"show route *", "`*`", "deny the whole command (`show route`)"},
		{"show /^int/ **", "`/^int/`", "deny the whole command (`show`)"},
		{"show frobnicate", "`frobnicate`", "not a keyword the lab measured after \"show\""},
	} {
		in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"), deny(c.deny))
		in.Classes = map[string][]string{"management": {"^fxp0$"}}
		res, err := Project(in)
		if err != nil || res.FailClosed != FailArgumentDeny || !strings.Contains(res.Refusal.Why, "Junos can't deny by argument") ||
			!strings.Contains(res.Refusal.Why, c.word) || !strings.Contains(res.Refusal.Why, c.instead) {
			t.Errorf("%s: %+v %v", c.deny, res.Refusal, err)
		}
		if res.Device([]string{"show", "interfaces", "fxp0", "terse"}) {
			t.Errorf("%s: the fail-closed reply runs a command", c.deny)
		}
	}
	// No permit meets it: port49 refuses those commands for want of a
	// permit, and the reply needs no deny.
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show version"),
		deny("clear interfaces fxp0")))
	if err != nil || res.FailClosed != "" {
		t.Fatalf("%+v %v", res, err)
	}
	// A deny of keywords, `**` or not, goes out.
	res, err = Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"),
		deny("show system **"), deny("show version")))
	if err != nil || res.FailClosed != "" || len(res.Denies) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// With no keyword tree nothing is proven.
	in := input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show **"), deny("show version"))
	in.Keywords = nil
	if res, err := Project(in); err != nil || res.FailClosed != FailArgumentDeny {
		t.Fatalf("no tree: %+v %v", res, err)
	}
}

// An allow naming an argument never matches on Junos, and one with an
// argument possible among its words would run more than port49 permits:
// neither is sent, the device refuses what port49 permits there, and the
// result says why (decision 27).
func TestAnAllowNamingAnArgumentIsNotSent(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured, permit("show version"),
		permit("show interfaces fxp0 **"), permit("show interfaces terse"), permit("show route **")))
	if err != nil || res.Shape != ShapeNarrow {
		t.Fatalf("%+v %v", res, err)
	}
	want := []string{"user-permissions=view", "deny-commands=^.*$", "allow-commands=^(show version|show route( .*)?)$"}
	if !reflect.DeepEqual(res.Attributes, want) || len(res.Unsent) != 2 ||
		!strings.Contains(res.Unsent[0].Why, `"fxp0" is not a keyword the lab measured after "show interfaces"`) ||
		!strings.Contains(res.Unsent[1].Why, `would also run "show interfaces <argument> terse"`) {
		t.Fatalf("%q %+v", res.Attributes, res.Unsent)
	}
	if res.Device([]string{"show", "interfaces", "fxp0", "terse"}) || !res.Device([]string{"show", "route", "x"}) {
		t.Error("device model")
	}
}

// deny-commands never reaches configuration mode (decision 27;
// L12-configuration-juniper_*.md). A reply that can enter it carries no deny,
// so a deny of a configuration statement is enforced only as an operational
// command: where the keyword tree does not prove it one, the subject gets the
// fail-closed reply, saying why. The admin path that drops the configuration
// bits relies on no deny in configuration mode: the device cannot enter it.
func TestADenyOfAConfigurationStatementFailsClosed(t *testing.T) {
	res, err := Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**"),
		deny("set system host-name **")))
	if err != nil || res.FailClosed != FailConfigurationDeny || !strings.Contains(res.Refusal.Why,
		"names a configuration statement, and Junos never applies deny-commands in configuration mode") {
		t.Fatalf("%+v %v", res.Refusal, err)
	}
	if res.Device([]string{"configure"}) {
		t.Error("the fail-closed reply enters configuration mode")
	}
	// An operational command that begins with a configuration verb, which
	// the tree proves, is sent, under bits that cannot configure.
	res, err = Project(input(platform.BitDeliveryUserPermissions, "admin", measured, permit("**"), deny("set cli **")))
	if err != nil || res.FailClosed != "" || !slices.Contains(res.ConfigurationDropped, "configure") ||
		res.Device([]string{"configure"}) || res.Device([]string{"set", "cli", "screen-width", "80"}) {
		t.Fatalf("%+v %v", res, err)
	}
	// No reply that carries a deny can enter configuration mode, by
	// `configure`, its variants or `edit`, its alias (pre-flight B-M1).
	entries := [][]string{{"configure"}, {"configure", "private"}, {"configure", "exclusive"},
		{"configure", "batch"}, {"edit"}}
	for _, rules := range [][]engine.Rule{{permit("**"), deny("request system reboot")},
		{permit("show **"), permit("configure"), deny("show version")},
		{permit("show **"), permit("edit **"), deny("show version")}} {
		for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
			res, err := Project(input(delivery, "admin", measured, rules...))
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

// Clone copies every slice and pointer of a Result, Unsent included, so a
// caller's append or write to its copy never reaches another's (Task 9). Every
// field is accounted for by kind: a field added later that Clone would share
// (a map, a pointer, a slice left unset here) fails this test until it is
// copied and set below. The model alone is shared: nothing writes it after
// Project returns.
func TestCloneCopiesEverySlice(t *testing.T) {
	r := permit("show version")
	fresh := func() Result {
		return Result{Shape: ShapeFailClosed, Bits: []string{"view"}, Template: "p49-readonly",
			Attributes: []string{"a"}, Denies: []engine.Rule{r}, Allows: []engine.Rule{r}, Omitted: []engine.Rule{r},
			Beyond: []engine.Rule{r}, Unreached: []engine.Rule{r}, ConfigurationDropped: []string{"all"},
			Unsent: []Unsent{{Rule: r, Why: "why"}}, ConfigurationBeneath: []engine.Rule{r},
			Closed: []engine.Rule{r}, ReachOverflow: []engine.Rule{r}, FailClosed: FailRefusedShape, Refusal: &Refusal{Why: "w"}}
	}
	res := fresh()
	c := res.Clone()
	v := reflect.ValueOf(&c).Elem()
	for i := range v.NumField() {
		f, name := v.Field(i), v.Type().Field(i).Name
		if !v.Type().Field(i).IsExported() {
			if name != "model" {
				t.Fatalf("%s: say whether Clone shares or copies it", name)
			}
			continue
		}
		switch f.Kind() {
		case reflect.String:
			if f.Len() == 0 {
				t.Fatalf("%s: set it in this test", name)
			}
		case reflect.Slice:
			if f.Len() == 0 {
				t.Fatalf("%s: set it in this test", name)
			}
			f.Index(0).Set(reflect.Zero(f.Type().Elem()))
		case reflect.Pointer:
			if f.IsNil() {
				t.Fatalf("%s: set it in this test", name)
			}
			f.Elem().Set(reflect.Zero(f.Type().Elem()))
		default:
			t.Fatalf("%s is a %s: copy it in Clone, and cover it here", name, f.Kind())
		}
	}
	if !reflect.DeepEqual(res, fresh()) {
		t.Fatalf("a clone's write reached the original: %+v", res)
	}
}

// Neither a refusal nor an Unsent's why quotes a rule that carries a value
// redaction hides: the composition is refused as secret_rule first, whose
// text names only the role, and the fail-closed reply puts the rule in
// Beyond, never Unsent (spec §5.8; decision 27).
func TestAnUnsentAllowNeverCarriesASecret(t *testing.T) {
	for _, rules := range [][]engine.Rule{
		{permit("show version"), permit("show interfaces HUNTER2 **")},
		{permit("show **"), deny("show interfaces HUNTER2")},
		{permit("show version"), permit("show interfaces terse"), deny("show route HUNTER2")},
	} {
		for _, delivery := range []string{platform.BitDeliveryUserPermissions, platform.BitDeliveryLocalUserName} {
			in := input(delivery, "readonly", measured, rules...)
			in.Secret = func(rule string) bool { return strings.Contains(rule, "HUNTER2") }
			res, err := Project(in)
			if err != nil || res.FailClosed != FailSecretRule {
				t.Fatalf("%v: %+v %v", rules, res, err)
			}
			shown := res.Refusal.Why
			for _, u := range res.Unsent {
				shown += u.Why + u.Rule.Rule
			}
			if strings.Contains(shown, "HUNTER2") {
				t.Errorf("%v: %q", rules, shown)
			}
		}
	}
}

// Project proves the reply from the rules it rendered it from; a fault in the
// rendering itself, after that, is caught by reading the regexes it sent
// (policy M4). An allow missing its anchors lets the device run what port49
// denies, and Project says which command rather than calling it proven.
func TestProjectRechecksTheRenderedRegexes(t *testing.T) {
	renderFault = func(attrs []string) []string {
		for i, a := range attrs {
			if strings.HasPrefix(a, "allow-commands=") {
				attrs[i] = "allow-commands=.*"
			}
		}
		return attrs
	}
	t.Cleanup(func() { renderFault = nil })
	_, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
		permit("show version"), permit("show interfaces **")))
	if err == nil || !strings.Contains(err.Error(), "allow-commands") || !strings.Contains(err.Error(), "which port49 denies") {
		t.Fatalf("a rendering fault was proven sound: %v", err)
	}
	renderFault = nil
	if _, err := Project(input(platform.BitDeliveryUserPermissions, "readonly", measured,
		permit("show version"), permit("show interfaces **"))); err != nil {
		t.Fatalf("the unfaulted reply: %v", err)
	}
}
