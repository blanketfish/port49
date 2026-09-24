package platform

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/rhwendt/port49/platforms"
)

// shipped is the default set, value for value: the table plan 4 compiled
// into the binary, and each change plan 5 made to it with the note behind it.
var shipped = map[string]Dialect{
	"arista_eos": {
		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
		Supports: []string{"session", "commands"},
		EntityClasses: map[string][]string{
			"management": {`^Management[0-9]+$`},
			"loopback":   {`^Loopback[0-9]+$`},
			"physical":   {`^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$`},
		},
		// L16-arista_eos.md, ceiling-arista_eos.md; decisions 23 and 25.
		Levels: map[string][]string{"readonly": {"priv-lvl=1", "roles=network-operator"},
			"operator": {"priv-lvl=15", "roles=network-operator"}, "admin": {"priv-lvl=15", "roles=network-admin"}},
		PrivilegeAttributes: []string{"priv-lvl", "roles"},
		InertAttributes:     []string{"home-directory"},
		EnableUsername:      EnablePrincipal,
		// L16-arista_eos.md, command authorization LOCAL.
		RoleOrder: map[string][]string{"roles": {"network-operator", "network-admin"}},
		DeviceConfig: []string{"aaa authorization exec default group port49 local",
			"aaa authorization commands all default group port49 local"},
		// ceiling-arista_eos.md; L16-arista_eos.md, command authorization LOCAL.
		Unreachable: map[string][]string{"readonly": {"clear counters **", "clear ip bgp **", "configure terminal **",
			"show users detail **"}},
		Fallback:      map[string]string{"admin": "network-admin: every command, configuration included"},
		LocalAccounts: []string{`^username (\S+)`},
		ConfigChecks: []ConfigCheck{
			{Match: `^aaa authorization commands \S+ default .*\b(none|if-authenticated)\s*$`, Says: "the command method " +
				"list falls back to none or if-authenticated: an operator session at 15 runs every command when port49 " +
				"cannot answer; end it in local (spec §6, decision 23)"},
			{Match: `^aaa authentication enable default .*\b(local|enable)\s*$`, Says: "enable falls back to a local " +
				"secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)"},
		},
	},
	"cisco_nxos": {
		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true,
		Supports:      []string{"session", "commands"},
		EntityClasses: map[string][]string{"management": {`^mgmt[0-9]+$`}},
		// L16-cisco_nxos.md, ceiling-cisco_nxos.md; decisions 23 and 25.
		Levels: map[string][]string{"readonly": {"shell:roles*network-operator"},
			"operator": {"shell:roles*network-operator"}, "admin": {"shell:roles*network-admin"}},
		CeilingLevels:       map[string]uint8{"readonly": 1, "operator": 15, "admin": 15},
		PrivilegeAttributes: []string{"priv-lvl", "shell:roles", "cisco-av-pair"},
		InertAttributes:     []string{"home-directory"},
		EnableUsername:      EnablePrincipal,
		// L16-cisco_nxos.md, command authorization LOCAL.
		RoleOrder: map[string][]string{"shell:roles": {"network-operator", "network-admin"}},
		DeviceConfig: []string{"aaa authentication login default group port49 local",
			"aaa authorization commands default group port49 local",
			"aaa authorization config-commands default group port49 local"},
		Fallback:      map[string]string{"admin": "network-admin: every command, configuration included"},
		LocalAccounts: []string{`^username (\S+)`},
		ConfigChecks: []ConfigCheck{
			{Match: `^aaa authorization (config-)?commands default .*\b(none|if-authenticated)\s*$`, Says: "the command " +
				"method list falls back to none or if-authenticated: an operator session runs every command when port49 " +
				"cannot answer; end it in local (spec §6, decision 23)"},
		},
	},
	"cisco_iosxe": {
		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true, SplitsInterfaceNames: true,
		Supports: []string{"session", "commands"},
		// L18-cisco_iosxe.md, ceiling-cisco_iosxe.md; decision 25.
		Levels:              map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=7"}, "admin": {"priv-lvl=15"}},
		PrivilegeAttributes: []string{"priv-lvl"},
		InertAttributes:     []string{"home-directory"},
		EnableUsername:      EnablePrincipal,
		AcceptedAttributes:  []string{"priv-lvl"},
		DeviceConfig: []string{"aaa authorization exec default group port49 local",
			"aaa authorization commands 1 default group port49 local",
			"aaa authorization commands 7 default group port49 local",
			"aaa authorization commands 15 default group port49 local",
			"aaa authorization config-commands", "privilege exec level 7 clear counters",
			"aaa accounting commands 1 default start-stop group port49",
			"aaa accounting commands 7 default start-stop group port49",
			"aaa accounting commands 15 default start-stop group port49"},
		Unreachable: map[string][]string{"readonly": {"clear counters **", "clear ip bgp **", "configure terminal **"},
			"operator": {"clear ip bgp **", "configure terminal **"}},
		Fallback:      map[string]string{"admin": "level 15: every command, configuration included"},
		LocalAccounts: []string{`^username (\S+)`},
		ConfigChecks: []ConfigCheck{
			{Match: `^aaa authorization commands \d+ default .*\b(none|if-authenticated)\s*$`, Says: "the command method " +
				"list falls back to none or if-authenticated: an ERROR or an outage then permits every command at that " +
				"level (tests/lab/results/L4-error-cisco_iosxe.md); end it in local"},
			{Match: `^aaa authentication enable default .*\b(local|enable)\s*$`, Says: "enable falls back to a local " +
				"secret: a session that reaches enable through it holds the port49 context's level unchecked (spec §5.6)"},
		},
	},
	"juniper_junos": {
		PipeToken: "|", StripCR: true,
		Supports:      []string{"session"},
		EntityClasses: map[string][]string{"management": {`^(fxp0|em0)$`}},
		PrivilegeAttributes: []string{"local-user-name", "user-permissions", "allow-commands", "deny-commands",
			"allow-configuration", "deny-configuration", "allow-commands-regexps", "deny-commands-regexps",
			"allow-configuration-regexps", "deny-configuration-regexps"},
		InertAttributes: []string{"home-directory"},
		EnableUsername:  EnablePrincipal,
		LocalAccounts:   []string{`^set system login user (\S+)`, `^\s*user (\S+) \{`},
		ConfigChecks: []ConfigCheck{{Match: `authentication-order .*\bpassword\b`, Says: "a FAIL from port49 falls " +
			"through to the local password on this platform (tests/lab/results/L4-juniper_vsrx.md, " +
			"L4-juniper_vjunos-router.md): a denied operator logs in locally"}},
	},
}

func TestTheDefaultSetValueForValue(t *testing.T) {
	got := Dialects()
	if len(got) != len(shipped) {
		t.Fatalf("%d platforms, want %d", len(got), len(shipped))
	}
	for name, want := range shipped {
		if !reflect.DeepEqual(got[name], want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got[name], want)
		}
	}
}

// released is every released platform set, value for value. A released set is
// never edited (spec §8, "the platform set is pinned"): when a later set
// becomes the default, 1.0.0's entry stays here as it is and the new set is
// added beside it, so a binary upgrade cannot change what a pinned policy
// renders without this test failing.
var released = map[string]map[string]Dialect{"1.0.0": shipped}

func TestEveryReleasedSetIsFrozen(t *testing.T) {
	for version, want := range released {
		got, ok := Set(version)
		if !ok || len(got) != len(want) {
			t.Fatalf("set %s: %d platforms, want %d", version, len(got), len(want))
		}
		for name := range want {
			if !reflect.DeepEqual(got[name], want[name]) {
				t.Errorf("set %s, %s:\n got %+v\nwant %+v", version, name, got[name], want[name])
			}
		}
	}
}

// releasedGeneric is every released set's generic adapter, value for value:
// each of the set's files is laid over it, and a `replace:` block or a
// platform the set does not ship starts from it. It is frozen with its set,
// so a device on a platform missing from a pinned set renders the same on
// every later binary; a new set with a different generic adds its own entry.
var releasedGeneric = map[string]Dialect{
	"1.0.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"},
		EnableUsername: EnablePrincipal},
}

// Each released set's generic adapter is its own and frozen, and every set
// this binary ships has one. So is plan 3's ceiling table, for a platform that
// renders nothing. A change to either would change a pinned policy's
// rendering; a change ships as a new set instead (spec §8).
func TestTheGenericAdapterIsFrozen(t *testing.T) {
	for version, want := range releasedGeneric {
		if got, ok := Generic(version); !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("set %s generic:\n got %+v\nwant %+v", version, got, want)
		}
	}
	for _, version := range Sets() {
		if _, ok := Generic(version); !ok {
			t.Errorf("set %s has no generic adapter", version)
		}
	}
	if d, _ := DialectFor("no_such_platform"); !reflect.DeepEqual(d, releasedGeneric[DefaultSet]) {
		t.Errorf("DialectFor an unknown platform is not the default set's generic: %+v", d)
	}
	if !reflect.DeepEqual(ceilingLevels, map[string]uint8{"readonly": 1, "admin": 15}) {
		t.Errorf("ceilingLevels: %v", ceilingLevels)
	}
}

// Every embedded set loads, and the default is one of them: the binary
// panics at start otherwise, so this is where a bad file is caught.
func TestEmbeddedSetsLoad(t *testing.T) {
	all, err := LoadSets(platforms.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := all[DefaultSet]; !ok {
		t.Fatalf("no set %s in %v", DefaultSet, Sets())
	}
	if !reflect.DeepEqual(Sets(), []string{"1.0.0"}) {
		t.Fatalf("sets: %v", Sets())
	}
	set, ok := Set(DefaultSet)
	if !ok {
		t.Fatal("Set(DefaultSet)")
	}
	set["arista_eos"].EntityClasses["management"][0] = "changed"
	if again, _ := Set(DefaultSet); again["arista_eos"].EntityClasses["management"][0] == "changed" {
		t.Fatal("Set must return a copy")
	}
	if _, ok := Set("0.9.0"); ok {
		t.Fatal("no set 0.9.0 ships")
	}
}

// A set is a directory named by its version, and each file defines the
// platform it is named for and nothing else.
func TestLoadSetsRefusesAMisfiledAdapter(t *testing.T) {
	good := "platforms:\n  meinberg_lantime:\n    supports: [session]\n"
	for name, fsys := range map[string]fstest.MapFS{
		"a set not named by a version": {"latest/meinberg_lantime.yaml": {Data: []byte(good)}},
		"a file named for another":     {"1.0.0/lantime.yaml": {Data: []byte(good)}},
		"a file defining two": {"1.0.0/meinberg_lantime.yaml": {Data: []byte(good +
			"  other:\n    supports: [session]\n")}},
		"an invalid adapter": {"1.0.0/meinberg_lantime.yaml": {Data: []byte(
			"platforms:\n  meinberg_lantime:\n    supports: [telnet]\n")}},
		// A set is laid over its own generic adapter, so one with none
		// frozen for it has nothing to stand on.
		"a set with no generic adapter": {"9.9.9/meinberg_lantime.yaml": {Data: []byte(good)}},
	} {
		if _, err := LoadSets(fsys); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	all, err := LoadSets(fstest.MapFS{"1.0.0/meinberg_lantime.yaml": {Data: []byte(good)}})
	if err != nil || !reflect.DeepEqual(all["1.0.0"]["meinberg_lantime"].Supports, []string{"session"}) {
		t.Fatalf("%v %+v", err, all)
	}
}

// The schema is closed: a key it does not know is refused, not ignored, and
// a file is one document.
func TestParseSpecsIsStrict(t *testing.T) {
	for name, raw := range map[string]string{
		"an unknown key":   "platforms:\n  x:\n    supports: [session]\n    privelege: {}\n",
		"two documents":    "platforms:\n  x:\n    supports: [session]\n---\nplatforms: {}\n",
		"no platforms key": "x:\n  supports: [session]\n",
		"a level too high": "platforms:\n  x:\n    ceiling_levels: {admin: 300}\n",
	} {
		if _, err := ParseSpecs([]byte(raw)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// Over merges a map a block sets per entry, replaces a list or a value
// whole, and keeps what the block leaves out (spec §8's "adds one class,
// inherits everything else").
func TestOverMergesPerTopLevelKey(t *testing.T) {
	specs, err := ParseSpecs([]byte("platforms:\n  arista_eos:\n    entity_classes:\n      uplink: ['^Ethernet49$']\n" +
		"      management: ['^Management1$']\n    supports: [session]\n"))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := DialectFor("arista_eos")
	d := specs["arista_eos"].Over(base)
	want := map[string][]string{"uplink": {`^Ethernet49$`}, "management": {`^Management1$`},
		"loopback": base.EntityClasses["loopback"], "physical": base.EntityClasses["physical"]}
	if !reflect.DeepEqual(d.EntityClasses, want) || !reflect.DeepEqual(d.Supports, []string{"session"}) {
		t.Fatalf("classes: %v supports %v", d.EntityClasses, d.Supports)
	}
	if !reflect.DeepEqual(d.Levels, base.Levels) || !d.ExpandsAbbreviations {
		t.Fatalf("the rest is the base's: %+v", d)
	}
	d.Levels["admin"][0] = "changed"
	if again, _ := DialectFor("arista_eos"); again.Levels["admin"][0] == "changed" {
		t.Fatal("Over must not share the base's maps")
	}
}

// Validate refuses what a device would get wrong silently or loudly.
func TestValidateNamesTheField(t *testing.T) {
	ok := Dialect{PipeToken: "|", Supports: []string{"session"}, EnableUsername: EnablePrincipal}
	for field, d := range map[string]Dialect{
		"supports":                        {PipeToken: "|"},
		"supports[0] is not a capability": {PipeToken: "|", Supports: []string{"telnet"}},
		"must include session":            {PipeToken: "|", Supports: []string{"commands"}},
		"privilege.admin":                 with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"priv-lvl"}} }),
		"takes no placeholder":            with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"x*{username}"}} }),
		"is sent twice":                   with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"a=1", "a*2"}} }),
		"ceiling_levels.admin":            with(ok, func(d *Dialect) { d.CeilingLevels = map[string]uint8{"admin": 16} }),
		"not a class name":                with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"Mgmt": {"x"}} }),
		"matches nothing":                 with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"mgmt": {}} }),
		"does not compile":                with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"mgmt": {"("}} }),
		"pipe_token":                      with(ok, func(d *Dialect) { d.PipeToken = "" }),
		"not an attribute name":           with(ok, func(d *Dialect) { d.InertAttributes = []string{"a=b"} }),
		"also in privilege_attribu":       with(ok, func(d *Dialect) { d.PrivilegeAttributes, d.InertAttributes = []string{"a"}, []string{"a"} }),
		"a level renders it": with(ok, func(d *Dialect) {
			d.Levels, d.InertAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"roles"}
		}),
		"inert_attributes: priv-lvl": with(ok, func(d *Dialect) { d.InertAttributes = []string{"priv-lvl"} }),
		"not in accepted_attributes": with(ok, func(d *Dialect) {
			d.Levels, d.AcceptedAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"priv-lvl"}
		}),
		"device_config[0]":                with(ok, func(d *Dialect) { d.DeviceConfig = []string{"line one\nline two"} }),
		"role_order: key 1 in name order": with(ok, func(d *Dialect) { d.RoleOrder = map[string][]string{"a=b": {"x"}} }),
		"role_order.priv-lvl":             with(ok, func(d *Dialect) { d.RoleOrder = map[string][]string{"priv-lvl": {"1"}} }),
		"role_order.roles is empty":       with(ok, func(d *Dialect) { d.RoleOrder = map[string][]string{"roles": {}} }),
		"verified is not containerlab":    with(ok, func(d *Dialect) { d.Verified = "lab" }),
		"role_order.roles[2] is ranked twice": with(ok, func(d *Dialect) {
			d.RoleOrder = map[string][]string{"roles": {"x", "y", "x"}}
		}),
		"role_order.roles[0]":     with(ok, func(d *Dialect) { d.RoleOrder = map[string][]string{"roles": {""}} }),
		"unreachable.readonly[0]": with(ok, func(d *Dialect) { d.Unreachable = map[string][]string{"readonly": {"/(/"}} }),
		"fallback.admin is empty": with(ok, func(d *Dialect) { d.Fallback = map[string]string{"admin": " "} }),
	} {
		err := Validate("x", d)
		if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "platforms.x.") {
			t.Errorf("%s: %v", field, err)
		}
	}
	if err := Validate("x", ok); err != nil {
		t.Fatal(err)
	}
}

// A rendered priv-lvl is a level, 0 to 15: IOS-XE refused the session for
// priv-lvl=99 (L18-cisco_iosxe.md, variant 7), and PrivLvl never numbers such
// a level from ceiling_levels instead.
func TestValidateRefusesARenderedPrivLvlThatIsNotALevel(t *testing.T) {
	ok := Dialect{PipeToken: "|", Supports: []string{"session"}, CeilingLevels: map[string]uint8{"admin": 15},
		EnableUsername: EnablePrincipal}
	for _, a := range []string{"priv-lvl=16", "priv-lvl=99", "priv-lvl=abc", "priv-lvl=", "priv-lvl*-1"} {
		d := with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {a}} })
		if err := Validate("x", d); err == nil || !strings.Contains(err.Error(), "platforms.x.privilege.admin[0]: not a privilege level; they run 0 to 15") || strings.Contains(err.Error(), a) {
			t.Errorf("%s: %v", a, err)
		}
		if n, ok := d.PrivLvl("admin"); ok {
			t.Errorf("%s: PrivLvl = %d, want none", a, n)
		}
	}
	d := with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"priv-lvl*0"}} })
	if err := Validate("x", d); err != nil {
		t.Fatal(err)
	}
}

// A device_config line is one printable ASCII line, so an operator's adapter
// cannot slip a second line, or a byte a terminal acts on, into what is pasted.
func TestValidateRefusesADeviceConfigLineThatIsNotOneLine(t *testing.T) {
	ok := Dialect{PipeToken: "|", Supports: []string{"session"}, EnableUsername: EnablePrincipal}
	for _, line := range []string{"", "  ", "a\tb", "a\rb", "a\x1bb", "café", "a\x7fb"} {
		d := with(ok, func(d *Dialect) { d.DeviceConfig = []string{"aaa new-model", line} })
		if err := Validate("x", d); err == nil || !strings.Contains(err.Error(), "platforms.x.device_config[1]") {
			t.Errorf("%q: %v", line, err)
		}
	}
}

// Every line a shipped adapter says its renderings depend on is one the lab
// device carries, so what the lab measured is what the adapter hands out.
func TestTheDeviceConfigIsTheLabs(t *testing.T) {
	for name, cfg := range map[string]string{"arista_eos": "eos", "cisco_nxos": "nxos", "cisco_iosxe": "iosxe"} {
		body, err := os.ReadFile("../../tests/lab/configs/" + cfg + "-startup.cfg")
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(body), "\n")
		d, _ := DialectFor(name)
		if len(d.DeviceConfig) == 0 {
			t.Errorf("%s: no device_config", name)
		}
		for _, l := range d.DeviceConfig {
			if !slices.Contains(lines, l) {
				t.Errorf("%s: %q is not in %s-startup.cfg", name, l, cfg)
			}
		}
	}
}

// An override's accepted_attributes and device_config replace the base's.
func TestOverReplacesTheAcceptedAttributesAndDeviceConfig(t *testing.T) {
	specs, err := ParseSpecs([]byte("platforms:\n  cisco_iosxe:\n    accepted_attributes: [priv-lvl, idletime]\n" +
		"    device_config: [aaa new-model]\n"))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := DialectFor("cisco_iosxe")
	d := specs["cisco_iosxe"].Over(base)
	if !reflect.DeepEqual(d.AcceptedAttributes, []string{"priv-lvl", "idletime"}) ||
		!reflect.DeepEqual(d.DeviceConfig, []string{"aaa new-model"}) {
		t.Fatalf("%v %v", d.AcceptedAttributes, d.DeviceConfig)
	}
	d = Spec{}.Over(base)
	if !reflect.DeepEqual(d.AcceptedAttributes, base.AcceptedAttributes) || !reflect.DeepEqual(d.DeviceConfig, base.DeviceConfig) {
		t.Fatalf("unset keys keep the base's: %v %v", d.AcceptedAttributes, d.DeviceConfig)
	}
}

// Every shipped adapter renders monotone in the reserved order, so a block
// that sets no privilege never trips Monotone on what it inherits; one that
// swaps two levels' numbers does.
func TestShippedAdaptersAreMonotone(t *testing.T) {
	order := []string{"readonly", "operator", "admin"}
	for _, v := range Sets() {
		set, _ := Set(v)
		for name, d := range set {
			if err := Monotone(name, d, order); err != nil {
				t.Errorf("%s %s: %v", v, name, err)
			}
		}
	}
	eos, _ := DialectFor("arista_eos")
	// Value, not name: the swapped roles keep every attribute name.
	roles := with(eos, func(d *Dialect) {
		d.Levels["readonly"] = []string{"priv-lvl=15", "roles=network-admin"}
		d.Levels["admin"] = []string{"priv-lvl=15", "roles=network-operator"}
	})
	if err := Monotone("arista_eos", roles, order); err == nil || !strings.Contains(err.Error(),
		"platforms.arista_eos.privilege.readonly: roles=network-admin ranks above operator's roles=network-operator") {
		t.Fatalf("%v", err)
	}
	// A value role_order does not rank ranks highest: a higher level may
	// render one, a lower level may not.
	unranked := with(eos, func(d *Dialect) { d.Levels["admin"] = []string{"priv-lvl=15", "roles=p49-noc"} })
	if err := Monotone("arista_eos", unranked, order); err != nil {
		t.Fatalf("an unranked role at the top: %v", err)
	}
	unranked = with(eos, func(d *Dialect) { d.Levels["readonly"] = []string{"priv-lvl=1", "roles=p49-noc"} })
	if err := Monotone("arista_eos", unranked, order); err == nil || !strings.Contains(err.Error(),
		"platforms.arista_eos.privilege.readonly: roles=p49-noc ranks above operator's roles=network-operator") {
		t.Fatalf("an unranked role below: %v", err)
	}
	swapped := with(eos, func(d *Dialect) { d.Levels["readonly"] = []string{"priv-lvl=15", "roles=network-operator"} })
	if err := Monotone("arista_eos", with(swapped, func(d *Dialect) {
		d.Levels["operator"] = []string{"priv-lvl=1", "roles=network-operator"}
	}), order); err == nil || !strings.Contains(err.Error(), "privilege.readonly: priv-lvl 15 is above operator's 1") {
		t.Fatalf("%v", err)
	}
}

// An explicitly empty accepted_attributes is refused: nothing accepted and
// no list at all are opposite readings, and neither is safe to guess.
func TestValidateRefusesAnEmptyAcceptedList(t *testing.T) {
	xe, _ := DialectFor("cisco_iosxe")
	err := Validate("cisco_iosxe", with(xe, func(d *Dialect) { d.AcceptedAttributes = []string{} }))
	if err == nil || !strings.Contains(err.Error(), "platforms.cisco_iosxe.accepted_attributes is empty") {
		t.Fatalf("%v", err)
	}
	// With no level rendered there is no rendering to catch it: the joint
	// check would read [] as nothing accepted, and the blob, which omits an
	// empty list, as anything.
	generic, _ := DialectFor("")
	err = Validate("x", with(generic, func(d *Dialect) { d.AcceptedAttributes = []string{} }))
	if generic.Levels != nil || err == nil || !strings.Contains(err.Error(), "platforms.x.accepted_attributes is empty") {
		t.Fatalf("no levels: %v", err)
	}
}

// RoleRank places a value in its attribute's role_order, lowest first; a
// value or an attribute it does not list is unranked.
func TestRoleRank(t *testing.T) {
	nx, _ := DialectFor("cisco_nxos")
	for _, tt := range []struct {
		name, value string
		rank        int
		ok          bool
	}{
		{"shell:roles", "network-operator", 0, true},
		{"shell:roles", "network-admin", 1, true},
		{"shell:roles", "vdc-operator", 0, false},
		{"shell:roles", "network-admin vdc-admin", 0, false},
		{"roles", "network-admin", 0, false},
	} {
		if r, ok := nx.RoleRank(tt.name, tt.value); r != tt.rank || ok != tt.ok {
			t.Errorf("%s=%s: %d %v", tt.name, tt.value, r, ok)
		}
	}
}

// role_order is a map, merged per attribute like privilege.
func TestOverMergesRoleOrder(t *testing.T) {
	specs, err := ParseSpecs([]byte("platforms:\n  arista_eos:\n    role_order:\n      x-role: [basic, super]\n"))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := DialectFor("arista_eos")
	d := specs["arista_eos"].Over(base)
	if !reflect.DeepEqual(d.RoleOrder, map[string][]string{"roles": {"network-operator", "network-admin"},
		"x-role": {"basic", "super"}}) || len(base.RoleOrder) != 1 {
		t.Fatalf("%v %v", d.RoleOrder, base.RoleOrder)
	}
}

// unreachable and fallback say what the lab measured, so a block adds to
// them and never takes away (spec §8, §12): a level's rules are the union,
// and a block's fallback text over the set's is kept apart, as the
// operator's note. A block that restates the set's text is the set's again,
// and the round trip through SpecOf holds for a merged adapter.
func TestOverKeepsTheMeasuredIntersection(t *testing.T) {
	base, _ := DialectFor("arista_eos")
	d := Spec{Unreachable: &map[string][]string{"readonly": {"show users detail **", "reload **"}},
		Fallback: &map[string]string{"admin": "read-only in practice", "operator": "network-operator"}}.Over(base)
	if !reflect.DeepEqual(d.Unreachable["readonly"], []string{"clear counters **", "clear ip bgp **",
		"configure terminal **", "show users detail **", "reload **"}) {
		t.Errorf("unreachable: %q", d.Unreachable)
	}
	if d.Fallback["admin"] != base.Fallback["admin"] || d.FallbackNote["admin"] != "read-only in practice" ||
		d.Fallback["operator"] != "network-operator" || d.FallbackNote["operator"] != "" {
		t.Errorf("fallback: %q, note %q", d.Fallback, d.FallbackNote)
	}
	if again := SpecOf(d).Over(base); !reflect.DeepEqual(again, d) {
		t.Errorf("a merged adapter laid over its set again:\n got %+v\nwant %+v", again, d)
	}
	if same := (Spec{Fallback: &map[string]string{"admin": base.Fallback["admin"]}}).Over(base); !reflect.DeepEqual(same, base) {
		t.Errorf("restating the set's text: %q %q", same.Fallback, same.FallbackNote)
	}
}

func with(d Dialect, edit func(*Dialect)) Dialect {
	d = d.clone()
	edit(&d)
	return d
}

// SpecOf is Over's inverse: every built-in adapter, written back out as a
// block and laid over nothing, is itself again. Export and the policy diff
// both rely on it.
func TestSpecOfRoundTrips(t *testing.T) {
	for name, d := range Dialects() {
		if got := SpecOf(d).Over(Dialect{}); !reflect.DeepEqual(got, d) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, d)
		}
	}
	// A Dialect field with no Spec key would be one no block sets and the
	// diff never compares (task 9 review M1).
	if n, m := reflect.TypeOf(Dialect{}).NumField(), reflect.TypeOf(Spec{}).NumField(); n != m {
		t.Fatalf("Dialect has %d fields and Spec %d keys", n, m)
	}
	keys := SpecKeys()
	if len(keys) != reflect.TypeOf(Spec{}).NumField() || keys[0] != "supports" || !slices.Contains(keys, "enable_username") {
		t.Fatalf("keys %v", keys)
	}
}
