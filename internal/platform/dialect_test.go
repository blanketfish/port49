package platform

import (
	"reflect"
	"regexp"
	"slices"
	"testing"
)

// expandsMeasured is every platform that may claim ExpandsAbbreviations, with
// the results note that measured it sending the resolved words.
var expandsMeasured = map[string]bool{
	"arista_eos":  true, // tests/lab/results/L21-arista_eos.md
	"cisco_nxos":  true, // tests/lab/results/L21-cisco_nxos.md
	"cisco_iosxe": true, // tests/lab/results/L21-cisco_iosxe.md
}

// splitsMeasured is every platform measured sending an interface name and its
// index as two arguments. EOS and NX-OS sent one (`Ethernet1`, `Ethernet1/1`).
var splitsMeasured = map[string]bool{
	"cisco_iosxe": true, // tests/lab/results/L21-cisco_iosxe.md: `int Gi1` as `GigabitEthernet`, `1`
}

// Every built-in platform has a dialect, and every dialect's pipe claim is the
// measured one: on each platform with a command path, a typed output modifier
// never reached port49 (tests/lab/results/L2-*.md). A dialect that claimed
// otherwise would have explain promise a protection the device does not give.
func TestEveryBuiltInPlatformHasAMeasuredDialect(t *testing.T) {
	for _, name := range Names() {
		d, ok := DialectFor(name)
		if !ok {
			t.Errorf("%s: known for session services but has no dialect", name)
		}
		if d.PipeAuthorized {
			t.Errorf("%s: PipeAuthorized, but no platform in the lab sent a modifier for authorization (L2)", name)
		}
		if d.PipeToken != "|" || !d.StripCR {
			t.Errorf("%s: pipe token %q strip_cr %v", name, d.PipeToken, d.StripCR)
		}
		// A wrong claim to expand fails open — an abbreviation slips past a
		// deny's word — so a true value must be the measured one.
		if d.ExpandsAbbreviations != expandsMeasured[name] {
			t.Errorf("%s: ExpandsAbbreviations %v, want %v: true only where L21 measured resolved words (spec §15, L21)",
				name, d.ExpandsAbbreviations, expandsMeasured[name])
		}
		// Config-command authorization is unmeasured everywhere, so claiming
		// it would tell explain a configuration-mode command reaches port49.
		if d.Authorizes("config_commands") {
			t.Errorf("%s: declares config_commands, which no lab run measured", name)
		}
		if d.SplitsInterfaceNames != splitsMeasured[name] {
			t.Errorf("%s: SplitsInterfaceNames %v, want %v: true only where L21 measured the split", name,
				d.SplitsInterfaceNames, splitsMeasured[name])
		}
		for class, patterns := range d.EntityClasses {
			for _, p := range patterns {
				if _, err := regexp.Compile(p); err != nil {
					t.Errorf("%s @%s: %v", name, class, err)
				}
			}
		}
	}
	if d, _ := DialectFor("juniper_junos"); d.Authorizes("commands") {
		t.Error("Junos sends no per-command authorization (L18; decision 21)")
	}
	if d, _ := DialectFor("arista_eos"); !d.Authorizes("commands") || !d.Authorizes("session") {
		t.Error("vEOS authorizes sessions and commands (L1, L10)")
	}
}

// One class, three spellings: @management is Management1 on EOS, mgmt0 on
// NX-OS, and fxp0 on Junos (spec §14, "Entity classes").
func TestManagementIsDefinedPerPlatform(t *testing.T) {
	for platform, name := range map[string]string{"arista_eos": "Management1", "cisco_nxos": "mgmt0", "juniper_junos": "fxp0"} {
		d, _ := DialectFor(platform)
		matched := false
		for _, p := range d.EntityClasses["management"] {
			if regexp.MustCompile(p).MatchString(name) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%s: @management does not name %s", platform, name)
		}
	}
	if d, _ := DialectFor("cisco_iosxe"); len(d.EntityClasses) != 0 {
		t.Errorf("IOS-XE defines no class until plan 5 says what its names are: %v", d.EntityClasses)
	}
}

// Levels render per platform, and a platform that renders no priv-lvl still
// has a number for the token's ceiling.
func TestLevelsRenderAndHaveANumber(t *testing.T) {
	eos, _ := DialectFor("arista_eos")
	if a, ok := eos.Render("admin"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15", "roles=network-admin"}) {
		t.Fatalf("eos admin: %v %v", a, ok)
	}
	if n, ok := eos.PrivLvl("readonly"); !ok || n != 1 {
		t.Fatalf("eos readonly: %d %v", n, ok)
	}
	nx, _ := DialectFor("cisco_nxos")
	if a, ok := nx.Render("admin"); !ok || !reflect.DeepEqual(a, []string{"shell:roles*network-admin"}) {
		t.Fatalf("nx-os admin: %v %v", a, ok)
	}
	if n, ok := nx.PrivLvl("admin"); !ok || n != 15 {
		t.Fatalf("nx-os renders no priv-lvl, and admin's ceiling number is its table's: %d %v", n, ok)
	}
	junos, _ := DialectFor("juniper_junos")
	if a, ok := junos.Render("admin"); !ok || len(a) != 0 {
		t.Fatalf("junos renders nothing until plan 5b's projection: %v %v", a, ok)
	}
	if n, ok := junos.PrivLvl("admin"); !ok || n != 15 {
		t.Fatalf("junos admin's ceiling number is plan 3's table's: %d %v", n, ok)
	}
}

// operator gets admin's device privilege on arista_eos and cisco_nxos, where
// the device cannot draw the operator line (tests/lab/results/ceiling-*.md;
// spec §6, decision 23), and level 7 on IOS-XE, where it can (decision 25).
func TestOperatorIsAdminsLevelWhereTheDeviceCannotFenceIt(t *testing.T) {
	eos, _ := DialectFor("arista_eos")
	if a, ok := eos.Render("operator"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15", "roles=network-operator"}) {
		t.Fatalf("eos operator gets admin's level and readonly's role: %v %v", a, ok)
	}
	if n, ok := eos.PrivLvl("operator"); !ok || n != 15 {
		t.Fatalf("eos operator: %d %v", n, ok)
	}
	nx, _ := DialectFor("cisco_nxos")
	if n, ok := nx.PrivLvl("operator"); !ok || n != 15 {
		t.Fatalf("nx-os operator's ceiling number is admin's: %d %v", n, ok)
	}
	if n, ok := nx.PrivLvl("readonly"); !ok || n != 1 {
		t.Fatalf("nx-os readonly: %d %v", n, ok)
	}
	xe, _ := DialectFor("cisco_iosxe")
	if n, ok := xe.PrivLvl("operator"); !ok || n != 7 {
		t.Fatalf("ios-xe operator: %d %v", n, ok)
	}
	for _, name := range []string{"juniper_junos", "no_such_platform"} {
		d, _ := DialectFor(name)
		if _, ok := d.PrivLvl("operator"); ok {
			t.Fatalf("%s: operator has no number there yet", name)
		}
	}
}

// An unknown platform logs in on the generic dialect (spec §8), and the table
// cannot be edited through what DialectFor returns.
func TestUnknownPlatformsAreGenericAndTheTableIsCopied(t *testing.T) {
	d, ok := DialectFor("meinberg_lantime")
	if ok || d.PipeToken != "|" || !reflect.DeepEqual(d.Supports, []string{"session"}) || d.Levels != nil {
		t.Fatalf("generic: %+v %v", d, ok)
	}
	eos, _ := DialectFor("arista_eos")
	eos.EntityClasses["management"][0] = "changed"
	eos.Levels["admin"] = nil
	again, _ := DialectFor("arista_eos")
	if again.EntityClasses["management"][0] == "changed" || len(again.Levels["admin"]) != 2 {
		t.Fatal("DialectFor must return a copy")
	}
	if len(Dialects()) != len(Names()) {
		t.Fatalf("Dialects() has %d platforms, Names() %d", len(Dialects()), len(Names()))
	}
	for name := range Dialects() {
		if !slices.Contains(Names(), name) {
			t.Errorf("dialect %s has no session-service platform", name)
		}
	}
}

// Each platform lists the attribute names that carry privilege on it, from
// the lab (L16, L18; spec §6), and the names it holds inert, seeded with spec
// §6's home-directory everywhere but IOS-XE; every other attribute bears
// privilege for the gate (spec §12).
func TestPrivilegeAttributesArePerPlatformAndFailClosed(t *testing.T) {
	junos := []string{"local-user-name", "user-permissions", "allow-commands", "deny-commands", "allow-configuration",
		"deny-configuration", "allow-commands-regexps", "deny-commands-regexps", "allow-configuration-regexps",
		"deny-configuration-regexps"}
	for name, want := range map[string][]string{
		"arista_eos":       {"priv-lvl", "roles"},
		"cisco_nxos":       {"priv-lvl", "shell:roles", "cisco-av-pair"},
		"cisco_iosxe":      {"priv-lvl"},
		"juniper_junos":    junos,
		"no_such_platform": {"priv-lvl"},
	} {
		d, _ := DialectFor(name)
		if !reflect.DeepEqual(d.PrivilegeAttributes, want) {
			t.Errorf("%s: %v", name, d.PrivilegeAttributes)
		}
		// IOS-XE refused a session for home-directory
		// (tests/lab/results/L22-cisco_iosxe.md), so nothing is inert there.
		inert := []string{"home-directory"}
		if name == "cisco_iosxe" {
			inert = []string{}
		}
		if !reflect.DeepEqual(d.InertAttributes, inert) {
			t.Errorf("%s inert: %v", name, d.InertAttributes)
		}
		if !d.BearsPrivilege("idletime") || !d.BearsPrivilege(want[0]) ||
			d.BearsPrivilege("home-directory") != (name == "cisco_iosxe") {
			t.Errorf("%s: only an attribute listed inert bears no privilege", name)
		}
	}
	all := PrivilegeAttributeNames()
	for _, n := range append([]string{"priv-lvl", "roles", "shell:roles", "cisco-av-pair"}, junos...) {
		if !slices.Contains(all, n) {
			t.Errorf("PrivilegeAttributeNames lacks %s: %v", n, all)
		}
	}
}

// EOS is told the level and the role together, because a role with no
// priv-lvl beside it lands the session at 1 (L16-arista_eos.md). The level
// fences a session while port49 answers and the role when the device falls
// back to local, so operator gets admin's level and readonly's role
// (ceiling-arista_eos.md; decisions 23 and 25).
func TestEOSSendsTheLevelAndTheRole(t *testing.T) {
	eos, _ := DialectFor("arista_eos")
	for level, want := range map[string][]string{
		"readonly": {"priv-lvl=1", "roles=network-operator"},
		"operator": {"priv-lvl=15", "roles=network-operator"},
		"admin":    {"priv-lvl=15", "roles=network-admin"},
	} {
		if got, ok := eos.Render(level); !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v %v, want %v", level, got, ok, want)
		}
	}
}

// NX-OS is told the role and never priv-lvl: the role decides in both
// directions and a priv-lvl beside it is inert (L16-cisco_nxos.md). IOS-XE is
// told priv-lvl and nothing else, and its level 7 is the operator rung
// (L18-cisco_iosxe.md, ceiling-cisco_iosxe.md).
func TestNXOSSendsTheRoleAndIOSXETheLevel(t *testing.T) {
	nx, _ := DialectFor("cisco_nxos")
	xe, _ := DialectFor("cisco_iosxe")
	for _, tt := range []struct {
		d     Dialect
		level string
		want  []string
	}{
		{nx, "readonly", []string{"shell:roles*network-operator"}},
		{nx, "operator", []string{"shell:roles*network-operator"}},
		{nx, "admin", []string{"shell:roles*network-admin"}},
		{xe, "readonly", []string{"priv-lvl=1"}},
		{xe, "operator", []string{"priv-lvl=7"}},
		{xe, "admin", []string{"priv-lvl=15"}},
	} {
		if got, ok := tt.d.Render(tt.level); !ok || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: %v %v, want %v", tt.level, got, ok, tt.want)
		}
	}
}
