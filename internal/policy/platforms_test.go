package policy

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/projection"
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
    accepted_attributes: [priv-lvl]
    inert_attributes: []
    splits_interface_names: true
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
	// replace discards the built-in, save what the set measured about the
	// device, which the block restates (spec §8; task 7 review I1).
	if !reflect.DeepEqual(xe.AcceptedAttributes, []string{"priv-lvl"}) || !xe.SplitsInterfaceNames ||
		xe.DeviceConfig != nil || xe.EntityClasses != nil || !reflect.DeepEqual(xe.Supports, []string{"session"}) {
		t.Fatalf("replace discards the built-in: %+v", xe)
	}
}

// The lab verified the set's adapter, not what a block makes of it: an
// override, a variant and a replace each lose `verified`, whatever key they
// change, and an adapter no block touches keeps it (spec §8, "Knowing what is
// verified").
func TestABlockNeverInheritsVerified(t *testing.T) {
	for _, name := range []string{"arista_eos", "cisco_nxos", "cisco_iosxe"} {
		if d, _ := platform.DialectFor(name); d.Verified != "containerlab" {
			t.Fatalf("%s: the set's adapter is verified %q, want containerlab (L22-%s.md)", name, d.Verified, name)
		}
	}
	body := `
platforms:
  arista_eos:
    inert_attributes: [home-directory]
  whitebox_nos:
    based_on: cisco_nxos
  cisco_iosxe:
    replace: true
    accepted_attributes: [priv-lvl]
    inert_attributes: []
    splits_interface_names: true
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=1"]
      admin: ["priv-lvl=15"]
` + scopeOK + roleOK + subjOK + grantOK
	p, err := Parse([]byte(body), withDevice("wb-01", "whitebox_nos"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"arista_eos", "whitebox_nos", "cisco_iosxe"} {
		if v := p.Dialect(name).Verified; v != "" {
			t.Errorf("%s: a block's adapter is verified %q", name, v)
		}
	}
	if v := p.Dialect("cisco_nxos").Verified; v != "containerlab" {
		t.Errorf("cisco_nxos: no block touches it, and it is verified %q", v)
	}
}

// Every refusal names the block.
func TestAPlatformBlockIsRefusedByName(t *testing.T) {
	rest := scopeOK + roleOK + subjOK + grantOK
	for _, tt := range []struct{ name, block, want string }{
		{"a name no inventory could write", "  Arista-EOS: {supports: [session]}\n", "platforms.Arista-EOS: a platform name"},
		// A key written with no value decodes as unset and inherits: it reads
		// as set and means the opposite (task 2 review minor 3).
		{"a key with no value", "  arista_eos:\n    inert_attributes:\n",
			"platforms.arista_eos.inert_attributes is null"},
		{"a key set to null", "  cisco_iosxe: {accepted_attributes: ~}\n", "platforms.cisco_iosxe.accepted_attributes is null"},
		// One name in two cases reads as two to a comparison (RR2-M1).
		{"a privilege name in a rendered name's other case", "  arista_eos: {privilege_attributes: [priv-lvl, roles, Roles]}\n",
			"platforms.arista_eos.privilege_attributes: Roles and roles"},
		{"an inert name in a rendered name's other case", "  x: {inert_attributes: [home-directory, PRIV-LVL]}\n",
			"platforms.x.inert_attributes: PRIV-LVL and priv-lvl"},
		{"replace and based_on", "  x: {replace: true, based_on: arista_eos}\n", "platforms.x: replace starts from nothing"},
		{"based_on a shipped name", "  cisco_nxos: {based_on: arista_eos}\n", "platforms.cisco_nxos: based_on declares a variant"},
		{"based_on nothing shipped", "  x: {based_on: arista}\n", `platforms.x: based_on "arista" is not a platform in set 1.0.0`},
		{"an invalid adapter", "  x: {entity_classes: {mgmt: ['(']}}\n", "platforms.x.entity_classes.mgmt"},
		{"an unknown key", "  arista_eos: {entity_class: {}}\n", "an unknown field in type policy.filePlatform"},
		{"the attributes key", "  all: {supports: [session]}\n", "platforms.all: all is reserved"},
		{"the redaction default", "  default: {supports: [session]}\n", "platforms.default: default is reserved"},
		{"a fallback note", "  arista_eos: {fallback_note: {admin: \"measured\"}}\n",
			"platforms.arista_eos: fallback_note is port49's own record"},
		{"a verified claim", "  arista_eos: {verified: containerlab}\n", "platforms.arista_eos: verified is port49's own claim"},
		{"a rendering the device refuses", "  cisco_iosxe: {privilege: {admin: [\"roles=x\"]}}\n",
			"platforms.cisco_iosxe.privilege.admin: roles is not in accepted_attributes"},
		{"a priv-lvl that is not a level", "  cisco_iosxe: {privilege: {admin: [\"priv-lvl=16\"]}}\n",
			"platforms.cisco_iosxe.privilege.admin[0]: not a privilege level"},
		{"a priv-lvl with a leading zero", "  cisco_iosxe: {privilege: {operator: [\"priv-lvl=07\"]}}\n",
			"platforms.cisco_iosxe.privilege.operator[0]: not a privilege level"},
		{"an explicitly empty accepted_attributes", "  cisco_iosxe: {accepted_attributes: []}\n",
			"platforms.cisco_iosxe.accepted_attributes is empty"},
		{"an empty accepted_attributes where no level renders", "  x: {accepted_attributes: []}\n",
			"platforms.x.accepted_attributes is empty"},
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
		{"roles swapped between levels", "  arista_eos: {privilege: {readonly: [\"priv-lvl=1\", \"roles=network-admin\"], " +
			"admin: [\"priv-lvl=15\", \"roles=network-operator\"]}}\n",
			"platforms.arista_eos.privilege.readonly: roles=network-admin ranks above operator's roles=network-operator"},
		{"a role unranked below a ranked one", "  x: {role_order: {x-role: [basic]}, privilege: {readonly: [\"x-role=super\"], " +
			"admin: [\"x-role=basic\"]}}\n",
			"platforms.x.privilege.readonly: x-role=super ranks above admin's x-role=basic"},
		{"the set's role_order reversed", "  arista_eos: {role_order: {roles: [network-admin, network-operator]}}\n",
			"platforms.arista_eos.role_order.roles: network-operator is ranked above network-admin, and platform set " +
				"1.0.0 ranks it below"},
		{"a variant's role_order reversed", "  wb: {based_on: cisco_nxos, role_order: {shell:roles: [network-admin, network-operator]}}\n",
			"platforms.wb.role_order.shell:roles: network-operator is ranked above network-admin"},
		// What the set measured about a device is a floor or a ceiling a block
		// only tightens, in every mode (task 7 review C1, I1).
		{"a set's privilege attribute demoted to inert", "  cisco_nxos: {privilege_attributes: [priv-lvl, shell:roles], " +
			"inert_attributes: [home-directory, cisco-av-pair]}\n",
			"platforms.cisco_nxos.inert_attributes: cisco-av-pair bears privilege in a platform set port49 ships"},
		{"a role demoted to inert where no level renders it", "  arista_eos: {privilege_attributes: [priv-lvl], " +
			"inert_attributes: [home-directory, roles], privilege: {readonly: [priv-lvl=1], operator: [priv-lvl=15], " +
			"admin: [priv-lvl=15]}}\n",
			"platforms.arista_eos.inert_attributes: roles bears privilege in a platform set port49 ships"},
		{"a new platform listing a set's privilege attribute inert", "  x: {inert_attributes: [home-directory, shell:roles]}\n",
			"platforms.x.inert_attributes: shell:roles bears privilege"},
		// inert_attributes is a ceiling: a name the set does not hold inert
		// bears privilege there, as home-directory and idletime do on IOS-XE
		// (spec §6), and replace would inherit the generic adapter's
		// home-directory (final review M5).
		{"an inert name the set holds bearing", "  cisco_iosxe: {inert_attributes: [idletime]}\n",
			"platforms.cisco_iosxe.inert_attributes: idletime is not listed inert by platform set 1.0.0 on cisco_iosxe"},
		{"an inert name the set does not list", "  cisco_nxos: {inert_attributes: [home-directory, x-label]}\n",
			"platforms.cisco_nxos.inert_attributes: x-label is not listed inert by platform set 1.0.0 on cisco_nxos"},
		{"an inert name a variant's base holds bearing", "  wb: {based_on: cisco_iosxe, inert_attributes: [home-directory]}\n",
			"platforms.wb.inert_attributes: home-directory is not listed inert by platform set 1.0.0 on cisco_iosxe"},
		{"generic's inert list inherited by replace", "  cisco_iosxe: {replace: true, supports: [session, commands], " +
			"accepted_attributes: [priv-lvl], privilege: {readonly: [priv-lvl=1], operator: [priv-lvl=7], admin: [priv-lvl=15]}}\n",
			"platforms.cisco_iosxe.inert_attributes: home-directory is not listed inert by platform set 1.0.0 on cisco_iosxe"},
		{"a set's privilege attribute dropped", "  cisco_nxos: {privilege_attributes: [priv-lvl, shell:roles]}\n",
			"platforms.cisco_nxos.privilege_attributes: cisco-av-pair is missing"},
		{"accepted_attributes widened", "  cisco_iosxe: {accepted_attributes: [priv-lvl, roles]}\n",
			"platforms.cisco_iosxe.accepted_attributes: roles is not in platform set 1.0.0's"},
		{"accepted_attributes widened on a variant", "  wb: {based_on: cisco_iosxe, accepted_attributes: [priv-lvl, roles]}\n",
			"platforms.wb.accepted_attributes: roles is not in platform set 1.0.0's"},
		{"accepted_attributes dropped by replace", "  cisco_iosxe: {replace: true, supports: [session, commands], " +
			"privilege: {readonly: [priv-lvl=1], operator: [priv-lvl=7], admin: [priv-lvl=15]}}\n",
			"platforms.cisco_iosxe.accepted_attributes: platform set 1.0.0 lists what cisco_iosxe takes"},
		{"a capability the set did not measure", "  juniper_junos: {supports: [session, commands]}\n",
			"platforms.juniper_junos.supports: commands is not"},
		{"pipe_authorized claimed", "  arista_eos: {pipe_authorized: true}\n",
			"platforms.arista_eos.pipe_authorized: platform set 1.0.0 measured false"},
		{"expands_abbreviations claimed", "  juniper_junos: {expands_abbreviations: true}\n",
			"platforms.juniper_junos.expands_abbreviations: platform set 1.0.0 measured false"},
		{"splits_interface_names dropped", "  cisco_iosxe: {splits_interface_names: false}\n",
			"platforms.cisco_iosxe.splits_interface_names: platform set 1.0.0 measured true"},
		{"strip_cr dropped", "  cisco_iosxe: {strip_cr: false}\n",
			"platforms.cisco_iosxe.strip_cr: platform set 1.0.0 measured true"},
		// The token cuts a command before any rule reads it, so a different one
		// splits a deny's vector apart (task 7 re-review): no tighter value.
		{"pipe_token changed", "  arista_eos: {pipe_token: running-config}\n",
			"platforms.arista_eos.pipe_token: platform set 1.0.0 measured \"|\" on arista_eos"},
		{"pipe_token changed on a variant", "  wb: {based_on: cisco_nxos, pipe_token: \"||\"}\n",
			"platforms.wb.pipe_token: platform set 1.0.0 measured \"|\" on cisco_nxos"},
		// A typo is a level nobody has (task 7 review I2).
		{"a privilege entry for an undeclared level", "  cisco_iosxe: {privilege: {admn: [\"priv-lvl=7\"]}}\n",
			"platforms.cisco_iosxe.privilege.admn: level admn is not declared"},
		{"a ceiling entry for an undeclared level", "  cisco_nxos: {ceiling_levels: {superuser: 15}}\n",
			"platforms.cisco_nxos.ceiling_levels.superuser: level superuser is not declared"},
		// Both would only add a report, so a typo would silently add none.
		{"an unreachable entry for an undeclared level", "  arista_eos: {unreachable: {radonly: [\"clear **\"]}}\n",
			"platforms.arista_eos.unreachable.radonly: level radonly is not declared"},
		{"a fallback entry for an undeclared level", "  arista_eos: {fallback: {admni: \"all of it\"}}\n",
			"platforms.arista_eos.fallback.admni: level admni is not declared"},
		{"the set's role_order reversed under replace", "  cisco_nxos: {replace: true, role_order: {shell:roles: [network-admin, network-operator]}}\n",
			"platforms.cisco_nxos.role_order.shell:roles: network-operator is ranked above network-admin"},
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

// A block may rank a value the set does not, anywhere, and rank a new
// platform's roles from nothing.
func TestAPlatformBlockMayRankNewRoles(t *testing.T) {
	body := "platforms:\n  arista_eos:\n    role_order:\n      roles: [network-operator, p49-noc, network-admin]\n" +
		"  f5_bigip:\n    privilege_attributes: [F5-LTM-User-Role]\n    role_order:\n      F5-LTM-User-Role: [guest, admin]\n" +
		"    privilege:\n      readonly: [\"F5-LTM-User-Role*guest\"]\n      admin: [\"F5-LTM-User-Role*admin\"]\n" +
		scopeOK + roleOK + subjOK + grantOK
	p := mustParse(t, body)
	if r, ok := p.Dialect("arista_eos").RoleRank("roles", "p49-noc"); !ok || r != 1 {
		t.Fatalf("p49-noc: %d %v", r, ok)
	}
	if r, ok := p.Dialect("f5_bigip").RoleRank("F5-LTM-User-Role", "admin"); !ok || r != 1 {
		t.Fatalf("f5: %d %v", r, ok)
	}
}

// The re-review's probe: a pipe_token that is a deny's word would cut the
// deny's vector before it forms, and let the command through.
func TestAPipeTokenThatSplitsADenyIsRefused(t *testing.T) {
	body := "platforms:\n  arista_eos:\n    pipe_token: running-config\n" + scopeOK + "roles:\n" +
		"  - {name: r, privilege: admin, permit: [\"**\"], pipe: {permit: [\"**\"]}, deny: [\"copy running-config **\"]}\n" +
		subjOK + grantOK
	if _, err := Parse([]byte(body), env()); err == nil || !strings.Contains(err.Error(), "platforms.arista_eos.pipe_token") {
		t.Fatalf("%v", err)
	}
	same := "platforms:\n  arista_eos:\n    pipe_token: \"|\"\n" + scopeOK + roleOK + subjOK + grantOK
	if _, err := Parse([]byte(same), env()); err != nil {
		t.Fatalf("the set's own token: %v", err)
	}
}

// A block tightens what the set measured and may say anything the set is
// silent on: a new platform lists inert a name no set calls privileged.
func TestAPlatformBlockMayTightenTheSet(t *testing.T) {
	body := "platforms:\n  cisco_iosxe:\n    accepted_attributes: [priv-lvl]\n    strip_cr: true\n" +
		"  arista_eos:\n    supports: [session]\n    privilege_attributes: [priv-lvl, roles, idletime]\n" +
		"    inert_attributes: [home-directory, timeout]\n" +
		"  juniper_junos:\n    expands_abbreviations: false\n" +
		"  x:\n    inert_attributes: [home-directory, idletime]\n" + scopeOK + roleOK + subjOK + grantOK
	p := mustParse(t, body)
	if !p.Dialect("x").BearsPrivilege("roles") || p.Dialect("x").BearsPrivilege("idletime") {
		t.Fatalf("x: %+v", p.Dialect("x"))
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
		`role "r": deny #1: term 2 names a class whose pattern on arista_eos turns case-insensitivity off`) {
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

// Moving the pin is a policy change like any other (spec §8): the diff finds
// every adapter key the move changes on a platform the inventory has, a block
// that keeps its own value hides the built-in's change and is named for it,
// and Reach says what a change touches. This build ships one set, so the
// environment stands up a second.
func TestAPinMoveIsReportedKeyByKey(t *testing.T) {
	first, _ := platform.Set("1.0.0")
	second, _ := platform.Set("1.0.0")
	eos, xe := second["arista_eos"], second["cisco_iosxe"]
	eos.EntityClasses = map[string][]string{"management": {"^Management1$"}, "loopback": eos.EntityClasses["loopback"],
		"physical": eos.EntityClasses["physical"]}
	xe.DeviceConfig = append(xe.DeviceConfig, "privilege exec level 7 show logging")
	second["arista_eos"], second["cisco_iosxe"] = eos, xe
	e := env()
	e.Sets = map[string]map[string]platform.Dialect{"1.0.0": first, "1.1.0": second}
	body := "platforms:\n  arista_eos:\n    entity_classes: {management: ['^Management[12]$']}\n" + scopeOK + roleOK +
		subjOK + grantOK
	before, err := Parse([]byte("platform_set: 1.0.0\n"+body), e)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := SetPlatformSet([]byte("platform_set: 1.0.0\n"+body), "1.1.0")
	if err != nil || !strings.HasPrefix(string(moved), "platform_set: 1.1.0\nplatforms:\n") {
		t.Fatalf("%v\n%s", err, moved)
	}
	after, err := Parse(moved, e)
	if err != nil {
		t.Fatal(err)
	}
	d := Compare(before, after, noon)
	if len(d.Adapters) != 1 || d.Adapters[0].Platform != "cisco_iosxe" || d.Adapters[0].Field != "device_config" ||
		!d.Adapters[0].Gated || d.Adapters[0].Sha256 != fmt.Sprintf("%x", sha256.Sum256([]byte(d.Adapters[0].New))) {
		t.Fatalf("the block hides arista_eos's management change; iosxe's device_config is gated: %+v", d.Adapters)
	}
	// The entry `platform upgrade` prints, pasted, acknowledges the move.
	a := d.Adapters[0]
	acked, err := Parse(append(moved, fmt.Sprintf("acknowledge:\n  - {platform: %s, field: %s, sha256: %s, reason: "+
		"set 1.1.0}\n", a.Platform, a.Field, a.Sha256)...), e)
	if err != nil {
		t.Fatal(err)
	}
	if d := Compare(before, acked, noon); d.UnacknowledgedAdapters() != 0 || len(d.StaleAcknowledgments) != 0 {
		t.Fatalf("acknowledged: %+v stale %+v", d.Adapters, d.StaleAcknowledgments)
	}
	if got := after.ShadowedBuiltIns("1.0.0"); !reflect.DeepEqual(got, []string{"platforms.arista_eos.entity_classes"}) {
		t.Fatalf("shadowed: %q", got)
	}
	if devices, subjects := before.Reach("arista_eos", noon); devices != 2 || subjects != 1 {
		t.Fatalf("reach: %d devices, %d subjects", devices, subjects)
	}
}

// Reach counts a subject only where it holds a grant on a device of the
// platform, and nothing on a platform the inventory has none of.
func TestReachCountsOnlyTheSubjectsAChangeTouches(t *testing.T) {
	p, err := Parse([]byte(scopeOK+roleOK+"subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, "+
		"token_ttl: 60s}\n  - {name: idle, identity: [\"user:b@example.com\"], username: b, token_ttl: 60s}\n"+
		grantOK), env())
	if err != nil {
		t.Fatal(err)
	}
	if devices, subjects := p.Reach("arista_eos", noon); devices != 2 || subjects != 1 {
		t.Fatalf("arista_eos: %d devices, %d subjects", devices, subjects)
	}
	if devices, subjects := p.Reach("acme_os", noon); devices != 0 || subjects != 0 {
		t.Fatalf("acme_os: %d devices, %d subjects", devices, subjects)
	}
	// The generic adapter reaches a device of a platform with no adapter and
	// no block (task 13 review M5).
	q, err := Parse([]byte(scopeOK+roleOK+subjOK+grantOK), withDevice("x-01", "acme_os"))
	if err != nil {
		t.Fatal(err)
	}
	if devices, subjects := q.Reach("generic", noon); devices != 1 || subjects != 1 {
		t.Fatalf("generic: %d devices, %d subjects", devices, subjects)
	}
}

// A pin move changes the generic adapter too, which every device of a
// platform with no adapter receives: the diff gates each of its keys that
// moves, as platform generic, whether or not the inventory has such a device
// yet (owner's ruling 2026-09-24); a block over it that keeps its own value
// hides the change and is named for it; and the acknowledge: entries clear it.
func TestAPinMoveGatesTheGenericAdapter(t *testing.T) {
	first, _ := platform.Set("1.0.0")
	g1, _ := platform.Generic("1.0.0")
	g2, _ := platform.Generic("1.0.0")
	g2.EntityClasses = map[string][]string{"management": {"^mgmt$"}}
	g2.DeviceConfig = []string{"aaa authorization exec default group port49 local"}
	g2.Supports = []string{"session", "commands"}
	sets := map[string]map[string]platform.Dialect{"1.0.0": first, "1.1.0": first}
	generics := map[string]platform.Dialect{"1.0.0": g1, "1.1.0": g2}
	type change struct{ platform, field string }
	for _, c := range []struct {
		name  string
		env   Env
		block string
		want  []change
	}{
		{"no device and no block", env(), "", []change{{"generic", "supports"}, {"generic", "entity_classes"},
			{"generic", "device_config"}}},
		{"a block over it", withDevice("acme-01", "acme_os"),
			"platforms:\n  acme_os:\n    entity_classes: {management: ['^oob$']}\n",
			[]change{{"acme_os", "supports"}, {"acme_os", "device_config"}, {"generic", "supports"},
				{"generic", "entity_classes"}, {"generic", "device_config"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := c.env
			e.Sets, e.Generics = sets, generics
			body := c.block + scopeOK + roleOK + subjOK + grantOK
			before, err := Parse([]byte("platform_set: 1.0.0\n"+body), e)
			if err != nil {
				t.Fatal(err)
			}
			moved, _ := SetPlatformSet([]byte("platform_set: 1.0.0\n"+body), "1.1.0")
			after, err := Parse(moved, e)
			if err != nil {
				t.Fatal(err)
			}
			d := Compare(before, after, noon)
			var got []change
			acks := "acknowledge:\n"
			for _, a := range d.Adapters {
				if !a.Gated || a.Acknowledged {
					t.Fatalf("every change is gated and unacknowledged: %+v", a)
				}
				got = append(got, change{a.Platform, a.Field})
				acks += fmt.Sprintf("  - {platform: %s, field: %s, sha256: %s, reason: set 1.1.0}\n", a.Platform,
					a.Field, a.Sha256)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("changes %v, want %v", got, c.want)
			}
			acked, err := Parse(append(moved, acks...), e)
			if err != nil {
				t.Fatal(err)
			}
			if d := Compare(before, acked, noon); d.UnacknowledgedAdapters() != 0 || len(d.StaleAcknowledgments) != 0 {
				t.Fatalf("acknowledged: %+v stale %+v", d.Adapters, d.StaleAcknowledgments)
			}
			if c.block == "" {
				return
			}
			if got := after.ShadowedBuiltIns("1.0.0"); !reflect.DeepEqual(got,
				[]string{"platforms.acme_os.entity_classes"}) {
				t.Fatalf("shadowed: %q", got)
			}
			if devices, subjects := before.Reach("generic", noon); devices != 1 || subjects != 1 {
				t.Fatalf("the generic adapter reaches acme-01: %d devices, %d subjects", devices, subjects)
			}
		})
	}
	if _, err := Parse([]byte("platforms:\n  generic: {}\n"+scopeOK+roleOK+subjOK+grantOK), env()); err == nil ||
		!strings.Contains(err.Error(), "generic is reserved") {
		t.Fatalf("a block named generic: %v", err)
	}
}

// SetPlatformSet rewrites the pin and nothing else, or adds one where the
// file pins none.
func TestSetPlatformSetTouchesOnlyThePin(t *testing.T) {
	raw := "# the policy\nscopes: []\nplatform_set: 1.0.0   # pinned 2026-09-24\nroles: []\n"
	got, err := SetPlatformSet([]byte(raw), "1.1.0")
	if err != nil || string(got) != "# the policy\nscopes: []\nplatform_set: 1.1.0\nroles: []\n" {
		t.Fatalf("%v %q", err, got)
	}
	if got, _ := SetPlatformSet([]byte("roles: []\n"), "1.0.0"); string(got) != "platform_set: 1.0.0\nroles: []\n" {
		t.Fatalf("%q", got)
	}
	if _, err := SetPlatformSet([]byte("platform_set:\n  - 1.0.0\n"), "1.1.0"); err == nil {
		t.Fatal("a pin that is not one line is refused")
	}
	if _, err := SetPlatformSet([]byte("{platform_set: 1.0.0, roles: []}\n"), "1.1.0"); err == nil {
		t.Fatal("a flow mapping, whose one line holds every key, is refused")
	}
	if _, err := SetPlatformSet([]byte("roles: []\n"), "1.1.0\nroles: [x]"); err == nil {
		t.Fatal("a version that is not dotted numbers is refused")
	}
	// A pin the file lacks goes after a leading document marker, so the file
	// stays one document; one it has is rewritten where it is, its line
	// ending kept (task 13 review I1, M7).
	for raw, want := range map[string]string{
		"---\nroles: []\n":                      "---\nplatform_set: 1.1.0\nroles: []\n",
		"# c\n---\nroles: []\n":                 "# c\n---\nplatform_set: 1.1.0\nroles: []\n",
		"--- # doc\n# roles\nroles: []\n":       "--- # doc\nplatform_set: 1.1.0\n# roles\nroles: []\n",
		"---\nplatform_set: 1.0.0\nroles: []\n": "---\nplatform_set: 1.1.0\nroles: []\n",
		"roles: []\r\nplatform_set: 1.0.0\r\n":  "roles: []\r\nplatform_set: 1.1.0\r\n",
		"roles: []\r\n":                         "platform_set: 1.1.0\r\nroles: []\r\n",
	} {
		got, err := SetPlatformSet([]byte(raw), "1.1.0")
		if err != nil || string(got) != want {
			t.Errorf("%q: %v %q", raw, err, got)
			continue
		}
		var f file
		if err := yaml.Unmarshal(got, &f); err != nil || f.PlatformSet != "1.1.0" {
			t.Errorf("%q does not read back pinned: %v %+v", got, err, f.PlatformSet)
		}
	}
	// A value that spans lines is refused, not half rewritten (review M1).
	for _, raw := range []string{"platform_set: >-\n  1.0.0\n", "platform_set: |\n  1.0.0\n",
		"platform_set: 1.0.0\n  continued\nroles: []\n"} {
		if got, err := SetPlatformSet([]byte(raw), "1.1.0"); err == nil {
			t.Errorf("%q: %q", raw, got)
		}
	}
}

// A file whose lines end in a bare CR is one line to a split on LF, and YAML
// reads it as many: the pin's line number points past the split, and the
// rewrite panicked with nothing written. It is refused, naming the line
// endings (task 13 review, parked).
func TestSetPlatformSetRefusesCROnlyLineEndings(t *testing.T) {
	raw := []byte("scopes: [{name: all_devices, match: {}}]\rplatform_set: 1.0.0\rsubjects: []\r")
	out, err := SetPlatformSet(raw, "1.1.0")
	if err == nil || out != nil || !strings.Contains(err.Error(), "line endings") {
		t.Fatalf("%q, %v", out, err)
	}
}

// A variant is the same device under another name: port49d reads its wire
// facts, redaction and keyword tree as its base's (spec §8; plan 6a).
func TestAJunosVariantLoadsAndIsReadAsJunos(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "srx-var-1", Platform: "srx_variant",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.50")}})
	p, err := Parse([]byte(good+"platforms:\n  srx_variant: {based_on: juniper_junos}\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.WirePlatform("srx_variant"); got != "juniper_junos" {
		t.Fatalf("WirePlatform: %q", got)
	}
	if got := p.WirePlatform("arista_eos"); got != "arista_eos" {
		t.Fatalf("a shipped platform is its own: %q", got)
	}
	if r, _ := p.Admitted("srx-var-1"); r.WirePlatform != "juniper_junos" {
		t.Fatalf("the admission index does not carry the base: %+v", r)
	}
}

// A rule carrying a value Junos's own patterns hide (platforms/redact.yaml,
// not the default list) is one the variant's session reply never sends and
// lint names, as it does on Junos: keyed by its own name the variant would
// log the hash whole (spec §5.8; plan 6a).
func TestAVariantsRuleSecretIsHiddenAsJunoss(t *testing.T) {
	const hash = "$6$Vq9rT2xK$Zm8pL0wQyS3cN5vB7aHjE1uO4iR6tY"
	const rule = "set system root-authentication encrypted-password " + hash
	e := env()
	e.Devices = []admission.Device{{Name: "srx-var-1", Platform: "srx_variant",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.50")}}}
	p, err := Parse([]byte(`
platform_set: 1.1.0
platforms:
  srx_variant: {based_on: juniper_junos}
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: r, privilege: admin, permit: ["**"], deny: ["`+rule+`"]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`), e)
	if err != nil {
		t.Fatal(err)
	}
	if _, hidden := platform.Redact(platform.Redactions("srx_variant"), []string{rule}); hidden {
		t.Fatal("the default list hides the hash, so this test proves nothing")
	}
	var found []string
	for _, f := range p.RuleSecretLiterals() {
		found = append(found, f.Message)
	}
	if len(found) != 1 || !strings.Contains(found[0], "on srx_variant") {
		t.Fatalf("lint does not read the variant's redaction as Junos's: %q", found)
	}
	for _, m := range found {
		if strings.Contains(strings.ToLower(m), strings.ToLower(hash)) {
			t.Fatalf("the finding prints the hash: %q", m)
		}
	}
	d, ok := p.device("srx-var-1")
	if !ok {
		t.Fatal("srx-var-1")
	}
	res, err := p.ResolveSubject("s", d, noon)
	if err != nil {
		t.Fatal(err)
	}
	if res.Projection.FailClosed != projection.FailSecretRule {
		t.Fatalf("the variant's reply would carry the hash: %+v", res.Projection)
	}
	if sent := strings.ToLower(strings.Join(res.Projection.Attributes, " ")); strings.Contains(sent, "vq9rt2xk") {
		t.Fatalf("the reply carries the hash: %q", res.Projection.Attributes)
	}
}

// A variant projects with its base's keyword tree (spec §8; plan 6a): the
// same composition on a juniper_junos variant and on juniper_junos gets the
// same reply, a capability with a keyword deny and a fail-closed one alike.
// Read under its own name the variant would have no tree, and the reply
// would differ (task 9 review).
func TestAJunosVariantProjectsWithJunossKeywordTree(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "srx-var-1", Platform: "srx_variant",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.50")}})
	for _, deny := range []string{"restart **", "request system reboot", "set system root-authentication **"} {
		p, err := Parse([]byte(`
platform_set: 1.1.0
platforms:
  srx_variant: {based_on: juniper_junos}
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: r, privilege: admin, permit: ["**"], deny: ["`+deny+`"]}
subjects: [{name: s, identity: "user:s@example.com", username: s, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`), e)
		if err != nil {
			t.Fatal(err)
		}
		var got [2]projection.Result
		for i, name := range []string{"srx-fw-04", "srx-var-1"} {
			d, ok := p.device(name)
			if !ok {
				t.Fatal(name)
			}
			res, err := p.ResolveSubject("s", d, noon)
			if err != nil {
				t.Fatal(err)
			}
			got[i] = *res.Projection
		}
		if got[0].Shape != got[1].Shape || got[0].FailClosed != got[1].FailClosed ||
			!reflect.DeepEqual(got[0].Attributes, got[1].Attributes) {
			t.Errorf("deny %q: junos %s %s %q, variant %s %s %q", deny, got[0].Shape, got[0].FailClosed,
				got[0].Attributes, got[1].Shape, got[1].FailClosed, got[1].Attributes)
		}
	}
}

// A block may drop set 1.2.0's entry deny and never add one the set did not
// measure (decision 44 ruling 5).
func TestABlockMayDropTheEntryDenyNotAddOne(t *testing.T) {
	head := "platform_set: 1.2.0\nplatforms:\n  juniper_junos:\n"
	for _, c := range []struct {
		block string
		ok    bool
	}{
		{"    rpc_entry_denies: []\n", true},
		{"    rpc_entry_denies: [\"junoscript **\"]\n", true},
		{"    rpc_entry_denies: [\"junoscript **\", \"op **\", \"start **\"]\n", false},
	} {
		_, err := Parse([]byte(head+c.block+scopeOK+"roles:\n  - {name: r, privilege: readonly, permit: [\"show **\"]}\n"+
			subjOK+grantOK), env())
		if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), "rpc_entry_denies") {
			t.Errorf("%q: %v", c.block, err)
		}
	}
	_, err := Parse([]byte("platform_set: 1.1.0\nplatforms:\n  arista_eos:\n    rpc_entry_denies: [\"x **\"]\n"+
		scopeOK+"roles:\n  - {name: r, permit: [\"show **\"]}\n"+subjOK+grantOK), env())
	if err == nil || !strings.Contains(err.Error(), "rpc_entry_denies") {
		t.Errorf("a platform the set does not project: %v", err)
	}
}
