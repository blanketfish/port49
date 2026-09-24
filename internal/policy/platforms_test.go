package policy

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/platform"
)

// withDevice is the test inventory with one more device, of a platform the
// built-in set does not ship.
func withDevice(name, platformName string) Env {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: name, Platform: platformName,
		Addresses: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})
	return e
}

// A `platforms:` block merges over the pinned set per top-level key: a map
// per entry, so a block adding one class keeps the rest; a list or value
// whole (spec §8, "User-editable, day one").
func TestAPlatformBlockMergesOverTheBuiltIn(t *testing.T) {
	p := mustParse(t, `
platforms:
  arista_eos:
    entity_classes:
      uplink: ['^Ethernet(49|50)$']
`+scopeOK+`roles:
  - {name: r, privilege: admin, permit: ["**"], deny: [interface @uplink]}
`+subjOK+grantOK)
	eos := p.Dialect("arista_eos")
	builtin, _ := platform.DialectFor("arista_eos")
	if !reflect.DeepEqual(eos.EntityClasses["uplink"], []string{`^Ethernet(49|50)$`}) ||
		!reflect.DeepEqual(eos.EntityClasses["management"], builtin.EntityClasses["management"]) ||
		!reflect.DeepEqual(eos.Levels, builtin.Levels) {
		t.Fatalf("arista_eos: %+v", eos)
	}
	d := deviceNamed(t, "leaf-01")
	if _, o, err := p.Decide("s", "", d, "interface Ethernet49", noon); err != nil || o.Permit {
		t.Fatalf("the operator's class binds on EOS: %+v %v", o, err)
	}
	// The class is EOS's alone, so every other platform in inventory fails the
	// joint check and is quarantined, as with a built-in class (spec §10).
	if q := p.Quarantines(noon); len(q) != 6 || q[0].Device != "nx-01" {
		t.Fatalf("quarantines: %+v", q)
	}
}

// based_on declares a variant under a new name; replace starts from nothing;
// a platform the set does not ship starts from the generic adapter. Each is
// validated as a built-in is.
func TestAPlatformBlockDeclaresAVariantOrStartsClean(t *testing.T) {
	body := `
platforms:
  whitebox_nos:
    based_on: arista_eos
    entity_classes:
      management: ['^ma1$']
  meinberg_lantime:
    supports: [session]
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=7"]
      admin: ["priv-lvl=15"]
  cisco_iosxe:
    replace: true
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=1"]
      admin: ["priv-lvl=15"]
` + scopeOK + roleOK + subjOK + grantOK
	e := withDevice("wb-01", "whitebox_nos")
	p, err := Parse([]byte(body), e)
	if err != nil {
		t.Fatal(err)
	}
	wb, eos := p.Dialect("whitebox_nos"), p.Dialect("arista_eos")
	if !reflect.DeepEqual(wb.EntityClasses["management"], []string{"^ma1$"}) ||
		!reflect.DeepEqual(wb.EntityClasses["loopback"], eos.EntityClasses["loopback"]) ||
		!reflect.DeepEqual(wb.Levels, eos.Levels) || !wb.ExpandsAbbreviations {
		t.Fatalf("whitebox_nos is EOS with its own management class: %+v", wb)
	}
	if d, ok := p.device("wb-01"); !ok {
		t.Fatal("wb-01")
	} else if r, err := p.Resolve("user:a@example.com", d, noon); err != nil ||
		!reflect.DeepEqual(r.Blob.Attributes, []string{"priv-lvl=15", "roles=network-admin"}) {
		t.Fatalf("wb-01 renders as EOS does: %+v %v", r.Blob.Attributes, err)
	}
	lantime := p.Dialect("meinberg_lantime")
	if n, ok := lantime.PrivLvl("operator"); !ok || n != 7 || lantime.PipeToken != "|" {
		t.Fatalf("meinberg_lantime starts from the generic adapter: %+v", lantime)
	}
	xe := p.Dialect("cisco_iosxe")
	if xe.AcceptedAttributes != nil || xe.SplitsInterfaceNames || xe.DeviceConfig != nil ||
		!reflect.DeepEqual(xe.Supports, []string{"session"}) {
		t.Fatalf("replace discards the built-in: %+v", xe)
	}
}

// Every refusal names the block.
func TestAPlatformBlockIsRefusedByName(t *testing.T) {
	rest := scopeOK + roleOK + subjOK + grantOK
	for _, tt := range []struct{ name, block, want string }{
		{"a name no inventory could write", "  Arista-EOS: {supports: [session]}\n", "platforms.Arista-EOS: a platform name"},
		{"replace and based_on", "  x: {replace: true, based_on: arista_eos}\n", "platforms.x: replace starts from nothing"},
		{"based_on a shipped name", "  cisco_nxos: {based_on: arista_eos}\n", "platforms.cisco_nxos: based_on declares a variant"},
		{"based_on nothing shipped", "  x: {based_on: arista}\n", `platforms.x: based_on "arista" is not a platform in set 1.0.0`},
		{"an invalid adapter", "  x: {entity_classes: {mgmt: ['(']}}\n", "platforms.x.entity_classes.mgmt"},
		{"an unknown key", "  arista_eos: {entity_class: {}}\n", "field entity_class not found"},
		{"the attributes key", "  all: {supports: [session]}\n", "platforms.all: all is reserved"},
		{"the redaction default", "  default: {supports: [session]}\n", "platforms.default: default is reserved"},
		{"a rendering the device refuses", "  cisco_iosxe: {privilege: {admin: [\"roles=x\"]}}\n",
			"platforms.cisco_iosxe.privilege.admin: roles is not in accepted_attributes"},
		{"a priv-lvl that is not a level", "  cisco_iosxe: {privilege: {admin: [\"priv-lvl=16\"]}}\n",
			"platforms.cisco_iosxe.privilege.admin: priv-lvl=16: not a privilege level"},
		{"an explicitly empty accepted_attributes", "  cisco_iosxe: {accepted_attributes: []}\n",
			"platforms.cisco_iosxe.accepted_attributes is empty"},
		{"a rendered attribute listed inert", "  arista_eos: {privilege_attributes: [priv-lvl], inert_attributes: [home-directory, roles]}\n",
			"platforms.arista_eos.inert_attributes: roles: a level renders it"},
		{"priv-lvl listed inert", "  x: {privilege_attributes: [], inert_attributes: [priv-lvl]}\n",
			"platforms.x.inert_attributes: priv-lvl: a level renders it"},
		{"a priv-lvl that falls as the level rises",
			"  cisco_iosxe: {privilege: {operator: [\"priv-lvl=15\"], admin: [\"priv-lvl=7\"]}}\n",
			"platforms.cisco_iosxe.privilege.operator: priv-lvl 15 is above admin's 7"},
		{"a ceiling that falls as the level rises", "  cisco_nxos: {ceiling_levels: {admin: 1}}\n",
			"platforms.cisco_nxos.ceiling_levels.operator: priv-lvl 15 is above admin's 1"},
		{"a role only a lower level renders",
			"  x: {privilege: {readonly: [\"priv-lvl=1\", \"shell:roles*network-admin\"], admin: [\"priv-lvl=15\"]}}\n",
			"platforms.x.privilege.readonly: shell:roles is rendered at readonly and not at admin"},
	} {
		if _, err := Parse([]byte("platforms:\n"+tt.block+rest), env()); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
		}
	}
}

// A block's renderings rise with the policy's own level order, custom levels
// included: the diff gate lets a move to a lower level through as a lowering
// (spec §12), which holds only while a lower level renders no more.
func TestAPlatformBlockRendersMonotoneInThePolicysOrder(t *testing.T) {
	levels := "privilege_levels:\n  - {name: readonly}\n  - {name: operator}\n  - {name: netops, parent: operator}\n" +
		"  - {name: admin}\n"
	rest := scopeOK + roleOK + subjOK + grantOK
	bad := "platforms:\n  cisco_iosxe:\n    privilege:\n      netops: [\"priv-lvl=3\"]\n" + levels + rest
	if _, err := Parse([]byte(bad), env()); err == nil ||
		!strings.Contains(err.Error(), "platforms.cisco_iosxe.privilege.operator: priv-lvl 7 is above netops's 3") {
		t.Fatalf("%v", err)
	}
	good := "platforms:\n  cisco_iosxe:\n    privilege:\n      netops: [\"priv-lvl=7\"]\n" + levels + rest
	if _, err := Parse([]byte(good), env()); err != nil {
		t.Fatalf("an equal rendering is monotone: %v", err)
	}
}

// A class pattern is matched case-insensitively, and one an operator writes
// with (?-i) is refused where a deny names the class: a differently-cased
// name would walk past it (spec §4). A permit may opt out, which only narrows
// it (roadmap, plan 4's "Hands to plan 5").
func TestACaseSensitiveClassIsRefusedInADeny(t *testing.T) {
	block := "platforms:\n  arista_eos:\n    entity_classes:\n      uplink: ['(?-i)^Ethernet49$']\n"
	deny := block + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [\"**\"], deny: [interface @uplink]}\n" +
		subjOK + grantOK
	if _, err := Parse([]byte(deny), env()); err == nil || !strings.Contains(err.Error(),
		`role "r": deny "interface @uplink" names @uplink, whose pattern /(?-i)^Ethernet49$/ on arista_eos turns `+
			`case-insensitivity off`) {
		t.Fatalf("%v", err)
	}
	// A flag group clearing i is the same opt-out, and so is a class on a
	// platform the block adds.
	for _, b := range []string{"platforms:\n  arista_eos:\n    entity_classes:\n      uplink: ['^(?-i:Ethernet)49$']\n",
		"platforms:\n  x:\n    entity_classes:\n      uplink: ['(?i)^eth(?-i)ernet49$']\n"} {
		body := b + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [\"**\"], deny: [interface @uplink]}\n" +
			subjOK + grantOK
		if _, err := Parse([]byte(body), env()); err == nil || !strings.Contains(err.Error(), "turns case-insensitivity off") {
			t.Errorf("%q: %v", b, err)
		}
	}
	permit := block + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [interface @uplink]}\n" + subjOK + grantOK
	if _, err := Parse([]byte(permit), env()); err != nil {
		t.Fatalf("a permit may opt out: %v", err)
	}
}

// Attributes may be keyed by a platform a block defines, and a placeholder
// is refused in an attribute such a platform says carries privilege.
func TestAttributesMayNameAnOperatorsPlatform(t *testing.T) {
	block := "platforms:\n  f5_bigip:\n    privilege_attributes: [F5-LTM-User-Role]\n"
	ok := block + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [\"**\"], attributes: {f5_bigip: [\"F5-LTM-User-Partition*all\"]}}\n" +
		subjOK + grantOK
	if _, err := Parse([]byte(ok), env()); err != nil {
		t.Fatal(err)
	}
	bad := block + scopeOK + "roles:\n  - {name: r, privilege: admin, permit: [\"**\"], attributes: {f5_bigip: [\"F5-LTM-User-Role*{username}\"]}}\n" +
		subjOK + grantOK
	if _, err := Parse([]byte(bad), env()); err == nil || !strings.Contains(err.Error(), "carries privilege and takes no placeholder") {
		t.Fatalf("%v", err)
	}
}

// An override that says what the pinned set already says is reported, so
// local platform files do not rot as upstream improves (spec §8).
func TestARedundantOverrideIsReported(t *testing.T) {
	p := mustParse(t, "platforms:\n  arista_eos:\n    expands_abbreviations: true\n    shows_server_msg: false\n"+
		scopeOK+roleOK+subjOK+grantOK)
	got := findings(p, FindingPlatformOverride)
	if len(got) != 1 || !strings.Contains(got[0], "platforms.arista_eos.expands_abbreviations says what platform set 1.0.0") {
		t.Fatalf("%q", got)
	}
}
