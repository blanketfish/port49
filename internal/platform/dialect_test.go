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

// Levels render per platform. arista_eos is the one platform whose rendering is
// measured (L16); every other platform renders nothing, which is not a mapping
// error, and still has a number for the token's ceiling.
func TestLevelsRenderAndHaveANumber(t *testing.T) {
	eos, _ := DialectFor("arista_eos")
	if a, ok := eos.Render("admin"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15"}) {
		t.Fatalf("eos admin: %v %v", a, ok)
	}
	if n, ok := eos.PrivLvl("readonly"); !ok || n != 1 {
		t.Fatalf("eos readonly: %d %v", n, ok)
	}
	nx, _ := DialectFor("cisco_nxos")
	if a, ok := nx.Render("operator"); !ok || len(a) != 0 {
		t.Fatalf("nx-os renders nothing, for any level: %v %v", a, ok)
	}
	if n, ok := nx.PrivLvl("admin"); !ok || n != 15 {
		t.Fatalf("nx-os admin's ceiling number: %d %v", n, ok)
	}
}

// operator gets admin's device privilege on arista_eos and cisco_nxos, where
// the device cannot draw the operator line (tests/lab/results/ceiling-*.md;
// spec §6, decision 23), and nothing new on IOS-XE, which can (plan 5's).
func TestOperatorIsAdminsLevelWhereTheDeviceCannotFenceIt(t *testing.T) {
	eos, _ := DialectFor("arista_eos")
	if a, ok := eos.Render("operator"); !ok || !reflect.DeepEqual(a, []string{"priv-lvl=15"}) {
		t.Fatalf("eos operator renders as admin does: %v %v", a, ok)
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
	for _, name := range []string{"cisco_iosxe", "juniper_junos", "no_such_platform"} {
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
	if again.EntityClasses["management"][0] == "changed" || len(again.Levels["admin"]) != 1 {
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
