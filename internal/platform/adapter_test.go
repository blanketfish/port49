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
		DeviceConfig: []string{"aaa authorization exec default group port49 local",
			"aaa authorization commands all default group port49 local"},
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
		DeviceConfig: []string{"aaa authentication login default group port49 local",
			"aaa authorization commands default group port49 local",
			"aaa authorization config-commands default group port49 local"},
	},
	"cisco_iosxe": {
		PipeToken: "|", StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true, SplitsInterfaceNames: true,
		Supports: []string{"session", "commands"},
		// L18-cisco_iosxe.md, ceiling-cisco_iosxe.md; decision 25.
		Levels:              map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=7"}, "admin": {"priv-lvl=15"}},
		PrivilegeAttributes: []string{"priv-lvl"},
		InertAttributes:     []string{"home-directory"},
		AcceptedAttributes:  []string{"priv-lvl"},
		DeviceConfig: []string{"aaa authorization exec default group port49 local",
			"aaa authorization commands 1 default group port49 local",
			"aaa authorization commands 7 default group port49 local",
			"aaa authorization commands 15 default group port49 local",
			"aaa authorization config-commands", "privilege exec level 7 clear counters",
			"aaa accounting commands 1 default start-stop group port49",
			"aaa accounting commands 7 default start-stop group port49",
			"aaa accounting commands 15 default start-stop group port49"},
	},
	"juniper_junos": {
		PipeToken: "|", StripCR: true,
		Supports:      []string{"session"},
		EntityClasses: map[string][]string{"management": {`^(fxp0|em0)$`}},
		PrivilegeAttributes: []string{"local-user-name", "user-permissions", "allow-commands", "deny-commands",
			"allow-configuration", "deny-configuration", "allow-commands-regexps", "deny-commands-regexps",
			"allow-configuration-regexps", "deny-configuration-regexps"},
		InertAttributes: []string{"home-directory"},
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

// The generic adapter is under every released set: each file is laid over it,
// and a `replace:` block or a platform no set ships starts from it. So is
// plan 3's ceiling table, for a platform that renders nothing. A change to
// either would change a pinned policy's rendering; a change ships as a new
// set instead (spec §8).
func TestTheGenericAdapterIsFrozen(t *testing.T) {
	want := Dialect{PipeToken: "|", StripCR: true, Supports: []string{"session"},
		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: []string{"home-directory"}}
	if !reflect.DeepEqual(generic, want) {
		t.Errorf("generic:\n got %+v\nwant %+v", generic, want)
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
	ok := Dialect{PipeToken: "|", Supports: []string{"session"}}
	for field, d := range map[string]Dialect{
		"supports":                  {PipeToken: "|"},
		"supports: \"telnet\"":      {PipeToken: "|", Supports: []string{"telnet"}},
		"must include session":      {PipeToken: "|", Supports: []string{"commands"}},
		"privilege.admin":           with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"priv-lvl"}} }),
		"takes no placeholder":      with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"x*{username}"}} }),
		"is sent twice":             with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {"a=1", "a*2"}} }),
		"ceiling_levels.admin":      with(ok, func(d *Dialect) { d.CeilingLevels = map[string]uint8{"admin": 16} }),
		"not a class name":          with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"Mgmt": {"x"}} }),
		"matches nothing":           with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"mgmt": {}} }),
		"does not compile":          with(ok, func(d *Dialect) { d.EntityClasses = map[string][]string{"mgmt": {"("}} }),
		"pipe_token":                with(ok, func(d *Dialect) { d.PipeToken = "" }),
		"not an attribute name":     with(ok, func(d *Dialect) { d.InertAttributes = []string{"a=b"} }),
		"also in privilege_attribu": with(ok, func(d *Dialect) { d.PrivilegeAttributes, d.InertAttributes = []string{"a"}, []string{"a"} }),
		"a level renders it": with(ok, func(d *Dialect) {
			d.Levels, d.InertAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"roles"}
		}),
		"inert_attributes: priv-lvl": with(ok, func(d *Dialect) { d.InertAttributes = []string{"priv-lvl"} }),
		"not in accepted_attributes": with(ok, func(d *Dialect) {
			d.Levels, d.AcceptedAttributes = map[string][]string{"admin": {"roles=x"}}, []string{"priv-lvl"}
		}),
		"device_config[0]": with(ok, func(d *Dialect) { d.DeviceConfig = []string{"line one\nline two"} }),
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
	ok := Dialect{PipeToken: "|", Supports: []string{"session"}, CeilingLevels: map[string]uint8{"admin": 15}}
	for _, a := range []string{"priv-lvl=16", "priv-lvl=99", "priv-lvl=abc", "priv-lvl=", "priv-lvl*-1"} {
		d := with(ok, func(d *Dialect) { d.Levels = map[string][]string{"admin": {a}} })
		if err := Validate("x", d); err == nil || !strings.Contains(err.Error(), "platforms.x.privilege.admin: "+a+
			": not a privilege level; they run 0 to 15") {
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
	ok := Dialect{PipeToken: "|", Supports: []string{"session"}}
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

func with(d Dialect, edit func(*Dialect)) Dialect {
	d = d.clone()
	edit(&d)
	return d
}
