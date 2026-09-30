package bundle

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/policy"
)

// A policy with a security_log scope, for the diff's security changes.
const withScopes = `
scopes:
  - {name: all_devices, match: {}}
  - {name: campus, match: {site: campus}, security_log: true}
  - {name: dc, match: {site: dc1}}
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: s, scope: campus, roles: [r]}, {subject: s, scope: dc, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]
`

func mustBundle(t *testing.T, devices ...admission.Device) *policy.Policy {
	t.Helper()
	p, err := Parse([]byte(withScopes), admission.Inventory{Devices: devices}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiffSaysWhatChangedAndWhichChangesAreSecurity(t *testing.T) {
	old := mustBundle(t,
		dev("leaf-01", "10.0.1.1", map[string]string{"site": "dc1"}),
		dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"}),
		dev("gone", "10.0.1.3", nil))
	new := mustBundle(t,
		dev("leaf-01", "10.0.1.1 10.66.0.1", map[string]string{"site": "campus"}),
		dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"}),
		dev("fresh", "192.0.2.7", nil))
	rep := Diff(old, new, time.Now())
	if rep.Added != 1 || rep.Removed != 1 || rep.Changed != 1 {
		t.Fatalf("counts: %+v", rep)
	}
	want := map[string]bool{
		"device_added fresh": false, "device_removed gone": false, "attributes_changed leaf-01": false,
		"address_added leaf-01 10.66.0.1 security": false, "scope_joined leaf-01 campus security": false,
		"scope_left leaf-01 dc": false,
	}
	for _, c := range rep.Changes {
		key := c.Kind + " " + c.Device
		if c.Address != "" {
			key += " " + c.Address
		}
		if c.Scope != "" {
			key += " " + c.Scope
		}
		if c.Security {
			key += " security"
		}
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing %q in %+v", k, rep.Changes)
		}
	}
	if len(rep.Security()) != 2 {
		t.Fatalf("security: %+v", rep.Security())
	}
	if s := rep.Summary(); !strings.Contains(s, "+1 device(s), -1, 1 changed") || !strings.Contains(s, old.Bundle) {
		t.Fatalf("summary: %s", s)
	}
	// I5: a pin moving a device to another key, and a device becoming
	// admitted, are security changes.
	pinned := dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"})
	pinned.KeyRef = "lab_key"
	stray := dev("stray", "192.0.2.8", nil)
	before := mustBundle(t, dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"}), stray)
	stray.Addresses = []netip.Addr{netip.MustParseAddr("10.0.1.8")}
	after := mustBundle(t, pinned, stray)
	var kinds []string
	for _, c := range Diff(before, after, time.Now()).Security() {
		kinds = append(kinds, c.Kind+" "+c.Device)
	}
	if got := strings.Join(kinds, ","); !strings.Contains(got, "key_ref_changed leaf-02") ||
		!strings.Contains(got, "admission_changed stray") {
		t.Fatalf("security: %s", got)
	}
	// N5: a device added and admitted is a security change; one added and
	// refused is not.
	added := mustBundle(t, dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"}), dev("stray", "192.0.2.8", nil),
		dev("newbie", "10.0.1.9", nil), dev("outsider", "192.0.2.9", nil))
	kinds = nil
	for _, c := range Diff(before, added, time.Now()).Security() {
		kinds = append(kinds, c.Kind+" "+c.Device)
	}
	if got := strings.Join(kinds, ","); !strings.Contains(got, "device_added newbie") || strings.Contains(got, "outsider") {
		t.Fatalf("security: %s", got)
	}
	// A refused entry carries no key_ref, so a flip between admitted and
	// refused is an admission_changed, not a key_ref_changed beside it
	// (Task 4 review).
	for _, c := range Diff(before, after, time.Now()).Changes {
		if c.Kind == KeyRefChanged && c.Device == "stray" {
			t.Fatalf("a flip to admitted is not a key_ref change: %+v", c)
		}
	}
	for _, c := range Diff(after, before, time.Now()).Changes {
		if c.Kind == KeyRefChanged && c.Device == "stray" {
			t.Fatalf("a flip to refused is not a key_ref change: %+v", c)
		}
	}
}

// On a policy that does not assess admission every device reads as refused
// no_key_group, which nothing acts on: an added device there is still a
// security change, never classed benign by that artifact.
func TestDiffOnAnUnassessedPolicyTreatsDevicesAsAdmitted(t *testing.T) {
	raw := []byte(strings.Replace(withScopes, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n", "", 1))
	parse := func(devices ...admission.Device) *policy.Policy {
		p, err := Parse(raw, admission.Inventory{Devices: devices}, policy.Env{})
		if err != nil {
			t.Fatal(err)
		}
		if p.AdmissionAssessed() {
			t.Fatal("the fixture assesses admission")
		}
		return p
	}
	rep := Diff(parse(dev("a", "10.0.3.1", nil)), parse(dev("a", "10.0.3.1", nil), dev("b", "10.0.3.2", nil)), time.Now())
	if s := rep.Security(); len(s) != 1 || s[0].Kind != DeviceAdded || s[0].To != "admitted" {
		t.Fatalf("security: %+v", s)
	}
}

// N1: a policy that refuses more than the bound of the devices admitted
// under the policy in force is refused, naming them.
func TestCheckAdmissionBoundsAPolicyThatRefusesTheFleet(t *testing.T) {
	// c is refused under the policy in force, so the bound is over a and b,
	// and admitted under the typo, so the typo does not admit nothing.
	devs := []admission.Device{dev("a", "10.0.3.1", nil), dev("b", "10.0.3.2", nil), dev("c", "11.0.3.3", nil)}
	old := mustBundle(t, devs...)
	typo, err := Parse([]byte(strings.Replace(withScopes, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1)),
		admission.Inventory{Devices: devs}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	err = CheckAdmission(old, typo, 10)
	if err == nil || !strings.Contains(err.Error(), "refuses admission to 2 of 2 devices") || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("%v", err)
	}
	if err := CheckAdmission(old, typo, 100); err != nil {
		t.Fatalf("the bound off: %v", err)
	}
	if err := CheckAdmission(old, old, 10); err != nil {
		t.Fatalf("no change: %v", err)
	}
}

// A swap whose bundle admits no device of a non-empty inventory is refused
// whatever the bound, as a start is (spec §10), and names stopping port49d
// as the deliberate way to take the fleet off.
func TestASwapThatAdmitsNoDeviceIsRefusedWhateverTheBound(t *testing.T) {
	devs := []admission.Device{dev("a", "10.0.3.1", nil), dev("b", "10.0.3.2", nil)}
	old := mustBundle(t, devs...)
	typo, err := Parse([]byte(strings.Replace(withScopes, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1)),
		admission.Inventory{Devices: devs}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdmission(old, typo, 100); err == nil || !strings.Contains(err.Error(), "admits none of the 2 device(s)") ||
		!strings.Contains(err.Error(), "stop port49d") {
		t.Fatalf("policy reload admitting nothing: %v", err)
	}
	outside := mustBundle(t, dev("a", "192.0.2.1", nil), dev("b", "192.0.2.2", nil))
	if err := Check(old, outside, 100); err == nil || !strings.Contains(err.Error(), "admits none of the 2 device(s)") ||
		!strings.Contains(err.Error(), "stop port49d") {
		t.Fatalf("inventory reload admitting nothing: %v", err)
	}
	// From an old bundle that admitted nothing either, still refused: the
	// bound is not what refuses it.
	if err := Check(outside, outside, 100); err == nil {
		t.Fatal("a bundle admitting nothing was taken")
	}
}

func TestCheckRefusesAnEmptyOrOverShrinkingInventory(t *testing.T) {
	var ten []admission.Device
	for i := 0; i < 10; i++ {
		ten = append(ten, dev(fmt.Sprintf("d%d", i), fmt.Sprintf("10.0.2.%d", i+1), nil))
	}
	old := mustBundle(t, ten...)
	if err := Check(old, mustBundle(t, ten[1:]...), 10); err != nil {
		t.Fatalf("one of ten at 10%%: %v", err)
	}
	err := Check(old, mustBundle(t, ten[2:]...), 10)
	if err == nil || !strings.Contains(err.Error(), "removes 2 of 10 devices and refuses 0 more (20%)") ||
		!strings.Contains(err.Error(), "send SIGHUP") {
		t.Fatalf("two of ten at 10%%: %v", err)
	}
	// I4: the same ten kept, two moved out of every key group, is the same
	// loss of service and is refused the same way, naming them.
	moved := append([]admission.Device(nil), ten...)
	moved[0].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	moved[1].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	err = Check(old, mustBundle(t, moved...), 10)
	if err == nil || !strings.Contains(err.Error(), "refuses 2 more") || !strings.Contains(err.Error(), "d0, d1") {
		t.Fatalf("two of ten newly refused at 10%%: %v", err)
	}
	if err := Check(old, mustBundle(t, ten[2:]...), 100); err != nil {
		t.Fatalf("the bound off: %v", err)
	}
	if err := Check(old, mustBundle(t), 100); err == nil || !strings.Contains(err.Error(), "names no device") {
		t.Fatalf("empty: %v", err)
	}
}

func TestCheckFromNamesTheFixAndHintsOnlyWhereKeyGroupsWere(t *testing.T) {
	// A policy and inventories as the file's other Check tests build them;
	// old carries no inventory key groups.
	old, new := checkPair(t, 10, 5) // ten devices, then five
	err := CheckFrom(old, new, 10, "fix the source of truth")
	if err == nil || !strings.Contains(err.Error(), "fix the source of truth") ||
		strings.Contains(err.Error(), "key_groups was deleted") {
		t.Fatalf("got %v", err)
	}
	// Devices newly refused, from an inventory with no key groups of its
	// own: named, with no hint about a block it never had.
	moved := old.Inventory().Devices
	moved[0].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	moved[1].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	err = CheckFrom(old, mustBundle(t, moved...), 10, "fix the source of truth")
	if err == nil || !strings.Contains(err.Error(), "newly refused: d0, d1") ||
		strings.Contains(err.Error(), "key_groups was deleted") {
		t.Fatalf("got %v", err)
	}
}

// checkPair is a bundle of before devices and one of the first after of
// them, as TestCheckRefusesAnEmptyOrOverShrinkingInventory builds them: the
// key groups are the policy's, so the inventory carries none.
func checkPair(t *testing.T, before, after int) (*policy.Policy, *policy.Policy) {
	t.Helper()
	var devs []admission.Device
	for i := 0; i < before; i++ {
		devs = append(devs, dev(fmt.Sprintf("d%d", i), fmt.Sprintf("10.0.2.%d", i+1), nil))
	}
	return mustBundle(t, devs...), mustBundle(t, devs[:after]...)
}
