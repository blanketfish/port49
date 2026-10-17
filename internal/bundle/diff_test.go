package bundle

import (
	"fmt"
	"net/netip"
	"slices"
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
	err = CheckAdmission(old, typo, 10, time.Now())
	if err == nil || !strings.Contains(err.Error(), "refuses admission to 2 of 2 devices") || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("%v", err)
	}
	if err := CheckAdmission(old, typo, 100, time.Now()); err != nil {
		t.Fatalf("the bound off: %v", err)
	}
	if err := CheckAdmission(old, old, 10, time.Now()); err != nil {
		t.Fatalf("no change: %v", err)
	}
}

// quarantineOn is withScopes over devs with an admin role capped at operator
// on the named scopes' grants: it lands above its ceiling's level on
// arista_eos, so every device those scopes select is quarantined.
func quarantineOn(t *testing.T, devs []admission.Device, scopes ...string) *policy.Policy {
	t.Helper()
	return quarantineIn(t, withScopes, devs, scopes...)
}

// quarantineIn is quarantineOn over policy text, a variant of withScopes.
func quarantineIn(t *testing.T, text string, devs []admission.Device, scopes ...string) *policy.Policy {
	t.Helper()
	text = strings.Replace(text, "roles: [{name: r, privilege: readonly, permit: [show **]}]",
		"roles: [{name: r, privilege: readonly, permit: [show **]}, {name: big, privilege: admin, permit: [show **]}]", 1)
	for _, sc := range scopes {
		text = strings.Replace(text, "scope: "+sc+", roles: [r]}", "scope: "+sc+", roles: [big], max_privilege: operator}", 1)
	}
	p, err := Parse([]byte(text), admission.Inventory{Devices: devs}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A policy that takes more than the bound of the devices in service out of
// service, by quarantining them, is refused, naming each, the remedy, and
// the knob's other use, as one that refuses admission is (plan 4b's
// candidate guard; spec §13 decision 34). Against a fleet that already has
// a quarantine (Review Focus 4; pre-flight M6): a release passes; the
// policy in force reloaded passes; one more of the three in service
// quarantined is 34%, the share rounded up, and refused; and a reload that
// releases one and quarantines another, leaving as many in service as
// before, passes (pre-flight M14).
func TestCheckAdmissionBoundsAPolicyThatQuarantinesTheFleet(t *testing.T) {
	now := time.Now()
	devs := []admission.Device{dev("a", "10.0.3.1", nil), dev("b", "10.0.3.2", nil),
		dev("c", "10.0.3.3", map[string]string{"site": "campus"}), dev("d", "10.0.3.4", map[string]string{"site": "dc1"})}
	good := mustBundle(t, devs...)
	all := quarantineOn(t, devs, "all_devices", "campus", "dc")
	dc := quarantineOn(t, devs, "dc")                 // d out: a, b, c in service
	dcCampus := quarantineOn(t, devs, "dc", "campus") // c and d out: a, b in service
	campus := quarantineOn(t, devs, "campus")         // c out: a, b, d in service
	for name, c := range map[string]struct {
		p   *policy.Policy
		out string
	}{"all": {all, "a b c d"}, "dc": {dc, "d"}, "dc and campus": {dcCampus, "c d"}, "campus": {campus, "c"}} {
		var out []string
		for _, d := range devs {
			if _, q := c.p.Quarantined(d.Name, now); q {
				out = append(out, d.Name)
			}
		}
		if strings.Join(out, " ") != c.out {
			t.Fatalf("the %s fixture quarantines %v, not %s", name, out, c.out)
		}
	}
	err := CheckAdmission(good, all, 10, now)
	if err == nil || !strings.Contains(err.Error(), "takes 4 of 4 devices in service out of it") ||
		!strings.Contains(err.Error(), "it quarantines 4: a (") || !strings.Contains(err.Error(), "port49 revoke") ||
		!strings.Contains(err.Error(), "raise inventory.max_removed_percent") ||
		!strings.Contains(err.Error(), "then lower it again, since it bounds inventory syncs too") {
		t.Fatalf("the whole fleet: %v", err)
	}
	if err := CheckAdmission(good, all, 100, now); err != nil {
		t.Fatalf("the bound off: %v", err)
	}
	if err := CheckAdmission(dc, good, 10, now); err != nil {
		t.Fatalf("(a) a reload that releases the quarantine and quarantines nothing: %v", err)
	}
	if was := inServiceCount(dc, now); was != 3 {
		t.Fatalf("(b) the policy in force has %d devices in service, not 3", was)
	}
	if err := CheckAdmission(dc, dc, 10, now); err != nil || len(NewlyQuarantined(dc, dc, now)) != 0 {
		t.Fatalf("(b) the policy in force again, three of four in service: %v", err)
	}
	err = CheckAdmission(dc, dcCampus, 10, now)
	if err == nil || !strings.Contains(err.Error(), "takes 1 of 3 devices in service out of it (34%)") ||
		!strings.Contains(err.Error(), "it quarantines 1: c (") {
		t.Fatalf("(c) one more of the three in service: %v", err)
	}
	if err := CheckAdmission(campus, dc, 10, now); err != nil {
		t.Fatalf("(d) c released and d quarantined, three in service before and after: %v", err)
	}
	if got := NewlyQuarantined(good, all, now); len(got) != 4 || got[0].Device != "a" || got[0].Cause == "" {
		t.Fatalf("NewlyQuarantined: %+v", got)
	}
}

// A combined reload is judged on what its policy does: against the policy in
// force over the new inventory (base), a device the inventory moves into a
// capped scope is the inventory's, quarantined as decision 20 says, and the
// same policy text passes. A nil base, one that did not parse, counts it as
// the policy's (fail closed); and a policy that caps the scope the
// inventory moves devices into is still refused (task 10 review I1).
func TestCheckAdmissionOverJudgesThePolicysEffectAlone(t *testing.T) {
	now := time.Now()
	var before, after []admission.Device
	for i := range 10 {
		before = append(before, dev(fmt.Sprintf("d%02d", i), fmt.Sprintf("10.0.6.%d", i+1), nil))
		var attrs map[string]string
		if i < 2 {
			attrs = map[string]string{"site": "dc1"}
		}
		after = append(after, dev(fmt.Sprintf("d%02d", i), fmt.Sprintf("10.0.6.%d", i+1), attrs))
	}
	old := quarantineOn(t, before, "dc")
	base := quarantineOn(t, after, "dc")
	combined := quarantineOn(t, after, "dc")
	if n := len(NewlyQuarantined(old, combined, now)); n != 2 {
		t.Fatalf("the fixture: the inventory quarantines %d, not 2", n)
	}
	if err := Check(old, combined, 10); err != nil {
		t.Fatalf("the inventory's bound: %v", err)
	}
	if err := CheckAdmissionOver(old, base, combined, 10, now); err != nil {
		t.Fatalf("the same policy, the inventory's quarantine: %v", err)
	}
	if err := CheckAdmissionOver(old, nil, combined, 10, now); err == nil ||
		!strings.Contains(err.Error(), "takes 2 of 10 devices in service out of it (20%)") {
		t.Fatalf("no base counts every device: %v", err)
	}
	uncapped := mustBundle(t, before...)
	if err := CheckAdmissionOver(uncapped, mustBundle(t, after...), combined, 10, now); err == nil ||
		!strings.Contains(err.Error(), "it quarantines 2: d00 (") {
		t.Fatalf("the policy caps the scope the inventory moves devices into: %v", err)
	}
}

// The share is of one population: a device the policy in force quarantines
// is not in service, so its refusal is not counted. Two of twenty
// quarantined and then refused, and one more quarantined, is 1 of 18, and
// passes (task 10 review I2).
func TestCheckAdmissionCountsOnlyDevicesInService(t *testing.T) {
	now := time.Now()
	var devs []admission.Device
	for i := range 20 {
		addr, attrs := fmt.Sprintf("10.1.0.%d", i+1), map[string]string(nil)
		switch {
		case i < 2:
			addr, attrs = fmt.Sprintf("10.2.0.%d", i+1), map[string]string{"site": "dc1"}
		case i == 2:
			attrs = map[string]string{"site": "campus"}
		}
		devs = append(devs, dev(fmt.Sprintf("d%02d", i), addr, attrs))
	}
	old := quarantineOn(t, devs, "dc")
	narrowed := quarantineIn(t, strings.Replace(withScopes, "cidr: 10.0.0.0/8", "cidr: 10.1.0.0/16", 1), devs,
		"dc", "campus")
	if inServiceCount(old, now) != 18 || len(NewlyRefused(old, narrowed)) != 2 ||
		len(NewlyQuarantined(old, narrowed, now)) != 1 {
		t.Fatalf("the fixture: %d in service, %d refused, %d quarantined", inServiceCount(old, now),
			len(NewlyRefused(old, narrowed)), len(NewlyQuarantined(old, narrowed, now)))
	}
	if err := CheckAdmission(old, narrowed, 10, now); err != nil {
		t.Fatalf("1 of 18 in service: %v", err)
	}
	if err := CheckAdmissionOver(old, nil, narrowed, 10, now); err != nil {
		t.Fatalf("1 of 18 in service, with no base: %v", err)
	}
}

// A release never offsets a refusal, which deletes tokens a revert does not
// bring back: fifty quarantined devices released and twenty in service
// refused by a key_groups typo is refused, though more are in service after
// it than before (decision 34, amended). And the share prints rounded up, so
// 21 of 200 over a bound of 10 never reads "(10%)" (task 10 review M1, M2).
func TestCheckAdmissionNeverExemptsARefusal(t *testing.T) {
	now := time.Now()
	var devs []admission.Device
	for i := range 100 {
		addr, attrs := fmt.Sprintf("10.1.0.%d", i+1), map[string]string(nil)
		switch {
		case i < 50:
			attrs = map[string]string{"site": "dc1"}
		case i < 70:
			addr = fmt.Sprintf("10.2.0.%d", i+1)
		}
		devs = append(devs, dev(fmt.Sprintf("d%02d", i), addr, attrs))
	}
	old := quarantineOn(t, devs, "dc")
	typo, err := Parse([]byte(strings.Replace(withScopes, "cidr: 10.0.0.0/8", "cidr: 10.1.0.0/16", 1)),
		admission.Inventory{Devices: devs}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if inServiceCount(old, now) != 50 || keptInService(old, typo, now) != 80 {
		t.Fatalf("the fixture: %d in service before, %d after", inServiceCount(old, now), keptInService(old, typo, now))
	}
	if err := CheckAdmission(old, typo, 10, now); err == nil ||
		!strings.Contains(err.Error(), "refuses admission to 20 of 100 devices (20%)") {
		t.Fatalf("a release offset a refusal: %v", err)
	}

	devs = devs[:0]
	for i := range 200 {
		addr := fmt.Sprintf("10.1.%d.%d", i/200, i%200+1)
		if i < 21 {
			addr = fmt.Sprintf("10.2.0.%d", i+1)
		}
		devs = append(devs, dev(fmt.Sprintf("e%03d", i), addr, nil))
	}
	old = mustBundle(t, devs...)
	typo, err = Parse([]byte(strings.Replace(withScopes, "cidr: 10.0.0.0/8", "cidr: 10.1.0.0/16", 1)),
		admission.Inventory{Devices: devs}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAdmission(old, typo, 10, now); err == nil ||
		!strings.Contains(err.Error(), "refuses admission to 21 of 200 devices (11%)") {
		t.Fatalf("21 of 200: %v", err)
	}
}

// Plan 6a's refusal bound is kept as it was, over the devices the policy in
// force admits, quarantined ones included: a refusal deletes the contexts a
// quarantine keeps for the device's release. Five of ten quarantined, and
// refused by a narrowed key group, is 5 of 10 admitted and refused, though
// none of the five was in service (task 10 re-review R1).
func TestCheckAdmissionBoundsTheRefusalOfQuarantinedDevices(t *testing.T) {
	now := time.Now()
	var devs []admission.Device
	for i := range 10 {
		addr, attrs := fmt.Sprintf("10.1.0.%d", i+1), map[string]string(nil)
		if i < 5 {
			addr, attrs = fmt.Sprintf("10.2.0.%d", i+1), map[string]string{"site": "dc1"}
		}
		devs = append(devs, dev(fmt.Sprintf("d%02d", i), addr, attrs))
	}
	old := quarantineOn(t, devs, "dc")
	narrowed := quarantineIn(t, strings.Replace(withScopes, "cidr: 10.0.0.0/8", "cidr: 10.1.0.0/16", 1), devs, "dc")
	if inServiceCount(old, now) != 5 || len(NewlyRefused(old, narrowed)) != 5 {
		t.Fatalf("the fixture: %d in service, %d refused", inServiceCount(old, now), len(NewlyRefused(old, narrowed)))
	}
	if err := CheckAdmission(old, narrowed, 10, now); err == nil ||
		!strings.Contains(err.Error(), "refuses admission to 5 of 10 devices (50%)") {
		t.Fatalf("five quarantined devices refused: %v", err)
	}
}

// The net exemption counts only the devices the inventory before the reload
// held: a combined policy-and-inventory reload that adds five devices and
// quarantines five of the twenty in service has as many in service after it
// as before, but is refused, 25% against 10%, so padding the inventory
// cannot pass the bound (spec §10; §13 decision 34).
func TestCheckAdmissionIsNotOffsetByTheDevicesAReloadAdds(t *testing.T) {
	now := time.Now()
	var before []admission.Device
	for i := range 20 {
		var attrs map[string]string
		if i < 5 {
			attrs = map[string]string{"site": "dc1"}
		}
		before = append(before, dev(fmt.Sprintf("old-%02d", i), fmt.Sprintf("10.0.4.%d", i+1), attrs))
	}
	after := slices.Clone(before)
	for i := range 5 {
		after = append(after, dev(fmt.Sprintf("new-%02d", i), fmt.Sprintf("10.0.5.%d", i+1), nil))
	}
	old := mustBundle(t, before...)
	padded := quarantineOn(t, after, "dc")
	if got := inServiceCount(padded, now); got != 20 {
		t.Fatalf("the padded bundle has %d devices in service, not 20", got)
	}
	err := CheckAdmission(old, padded, 10, now)
	if err == nil || !strings.Contains(err.Error(), "takes 5 of 20 devices in service out of it (25%)") ||
		!strings.Contains(err.Error(), "it quarantines 5: old-00 (") {
		t.Fatalf("five added offset five quarantined: %v", err)
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
	if err := CheckAdmission(old, typo, 100, time.Now()); err == nil || !strings.Contains(err.Error(), "admits none of the 2 device(s)") ||
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

// Pre-flight I2: port49d's bound counts a device left with no address, as
// the service's does, and names it.
func TestCheckCountsADeviceLeftWithNoAddress(t *testing.T) {
	pol := []byte(`
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {attributes: {site: dc1}}, key_ref: lab_key}]
`)
	inv := func(addressed bool) admission.Inventory {
		var out admission.Inventory
		for i := 1; i <= 3; i++ {
			d := admission.Device{Name: fmt.Sprintf("leaf-%02d", i), Platform: "arista_eos",
				Attributes: map[string]string{"site": "dc1"}, Transport: admission.TransportTCP}
			if addressed {
				d.Addresses = []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}
			}
			out.Devices = append(out.Devices, d)
		}
		return out
	}
	env := policy.Env{KeyRefs: []string{"lab_key"}}
	old, err := Parse(pol, inv(true), env)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := Parse(pol, inv(false), env)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(Unaddressed(old, bare), ","); got != "leaf-01,leaf-02,leaf-03" {
		t.Fatalf("Unaddressed: %q", got)
	}
	err = CheckFrom(old, bare, 10, "fix the source of truth")
	if err == nil || !strings.Contains(err.Error(), "removes 0 of 3 devices and refuses 0 more and leaves 3 more with "+
		"no address (100%)") || !strings.Contains(err.Error(), "left with no address: leaf-01, leaf-02, leaf-03") {
		t.Fatalf("got %v", err)
	}
	if err := CheckFrom(old, bare, 100, "fix the source of truth"); err != nil {
		t.Fatalf("a bound of 100 is off: %v", err)
	}
	if got := Unaddressed(bare, old); len(got) != 0 {
		t.Fatalf("gaining addresses is not losing them: %v", got)
	}
	if got := Unaddressed(bare, bare); len(got) != 0 {
		t.Fatalf("a device that never had an address did not lose one: %v", got)
	}

	// A device newly refused and stripped too counts once, as refused.
	moved := inv(true)
	moved.Devices[0].Attributes = map[string]string{"site": "dc2"}
	moved.Devices[0].Addresses = nil
	next, err := Parse(pol, moved, env)
	if err != nil {
		t.Fatal(err)
	}
	if r := NewlyRefused(old, next); len(r) != 1 || r[0].Device.Name != "leaf-01" {
		t.Fatalf("NewlyRefused: %v", r)
	}
	if got := Unaddressed(old, next); len(got) != 0 {
		t.Fatalf("a newly refused device is counted twice: %v", got)
	}

	// A device old already refuses was out of service before it lost its
	// address: it is not counted again (review M3).
	was := inv(true)
	was.Devices[0].Attributes = map[string]string{"site": "dc2"}
	before, err := Parse(pol, was, env)
	if err != nil {
		t.Fatal(err)
	}
	if got := Unaddressed(before, next); len(got) != 0 {
		t.Fatalf("an already refused device is counted: %v", got)
	}
	if err := CheckFrom(before, next, 10, "fix the source of truth"); err != nil {
		t.Fatalf("stripping an already refused device: %v", err)
	}
}

// An inventory's refusal prints its share rounded up, as the policy's does,
// so 21 of 200 removed over a bound of 10 never reads "(10%)" (task 10
// re-review R2).
func TestCheckPrintsTheShareRoundedUp(t *testing.T) {
	var devs []admission.Device
	for i := range 200 {
		devs = append(devs, dev(fmt.Sprintf("e%03d", i), fmt.Sprintf("10.1.%d.%d", i/200, i%200+1), nil))
	}
	if err := Check(mustBundle(t, devs...), mustBundle(t, devs[21:]...), 10); err == nil ||
		!strings.Contains(err.Error(), "removes 21 of 200 devices and refuses 0 more (11%)") {
		t.Fatalf("%v", err)
	}
}

// port49d's reload guard rewrites three phrases of these refusals for
// port49-broker by their exact text (RaiseBound, KeyRefsFile, StopFleet):
// each refusal must still carry its phrase, or the broker's advice is
// port49d's again (Task 18).
func TestTheRefusalsCarryTheWordsThatArePerProcess(t *testing.T) {
	devs := []admission.Device{dev("a", "10.0.3.1", nil), dev("b", "10.0.3.2", nil)}
	old := mustBundle(t, devs...)
	typo, err := Parse([]byte(strings.Replace(withScopes, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1)),
		admission.Inventory{Devices: devs}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	none := CheckAdmission(old, typo, 100, time.Now())
	if none == nil || !strings.Contains(none.Error(), KeyRefsFile) || !strings.Contains(none.Error(), StopFleet) {
		t.Fatalf("admits none: %v", none)
	}
	outside := mustBundle(t, dev("a", "192.0.2.1", nil), dev("b", "192.0.2.2", nil))
	if err := Check(old, outside, 100); err == nil || !strings.Contains(err.Error(), KeyRefsFile) ||
		!strings.Contains(err.Error(), StopFleet) {
		t.Fatalf("inventory admits none: %v", err)
	}
	if !strings.Contains(reloadRemedy, RaiseBound) {
		t.Fatalf("the bound's remedy: %s", reloadRemedy)
	}
}

func TestATransportFlipIsOneSecurityChange(t *testing.T) {
	tcp := dev("leaf-01", "10.0.1.1", map[string]string{"site": "dc1"})
	tls := tcp
	tls.Transport = admission.TransportTLS
	var kinds []string
	for _, c := range Diff(mustBundle(t, tcp), mustBundle(t, tls), time.Now()).Changes {
		if c.Device == "leaf-01" {
			kinds = append(kinds, c.Kind)
			if c.Kind == TransportChanged && (c.From != "tcp" || c.To != "tls" || !c.Security) {
				t.Errorf("transport_changed: %+v", c)
			}
		}
	}
	if !slices.Equal(kinds, []string{TransportChanged}) {
		t.Fatalf("changes for leaf-01: %v, want only transport_changed", kinds)
	}
}

func TestATLSToTCPFlipIsOneSecurityChange(t *testing.T) {
	tls := dev("leaf-01", "10.0.1.1", map[string]string{"site": "dc1"})
	tls.Transport = admission.TransportTLS
	tcp := tls
	tcp.Transport = ""
	var got []Change
	for _, c := range Diff(mustBundle(t, tls), mustBundle(t, tcp), time.Now()).Changes {
		if c.Device == "leaf-01" {
			got = append(got, c)
		}
	}
	if len(got) != 1 || got[0].Kind != TransportChanged || got[0].From != "tls" || got[0].To != "tcp" || !got[0].Security {
		t.Fatalf("changes for leaf-01: %+v, want one security transport_changed tls to tcp", got)
	}
}
