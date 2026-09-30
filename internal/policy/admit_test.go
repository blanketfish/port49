package policy

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
)

const keyGrouped = good + `
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: prod_key}
  - {match: {attributes: {site: campus}}, key_ref: campus_key}
`

func TestKeyGroupsInThePolicyAssignAndAdmit(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"campus_key", "prod_key"}
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Admission().Lookup(netip.MustParseAddr("10.0.1.1"))
	if !ok || r.Refused != "" || r.KeyRef != "prod_key" || r.Device.Name != "leaf-01" {
		t.Fatalf("leaf-01: %+v, %v", r, ok)
	}
	// The attribute tier beats the CIDR tier (spec §10).
	if r, _ := p.Admitted("campus-sw-7"); r.KeyRef != "campus_key" || r.Refused != "" {
		t.Fatalf("campus-sw-7: %+v", r)
	}
	if as, _ := p.KeyAssignment("campus-sw-7"); as.Tier != admission.TierAttribute {
		t.Fatalf("campus-sw-7's tier: %+v", as)
	}
	if len(p.AdmissionRefusals()) != 0 {
		t.Fatalf("refused: %+v", p.AdmissionRefusals())
	}
	if d, ok := p.Device("nx-01"); !ok || d.Platform != "cisco_nxos" {
		t.Fatalf("Device: %+v, %v", d, ok)
	}
}

// A device no group admits is refused on its own; the policy loads and the
// rest of the fleet is admitted (spec §10; plan 6a Decided 5).
func TestADeviceNoGroupAdmitsIsRefusedNotThePolicy(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	refused := p.AdmissionRefusals()
	if len(refused) != 1 || refused[0].Device.Name != "stray" ||
		!strings.Contains(refused[0].Refused, "matches no key group") {
		t.Fatalf("refused: %+v", refused)
	}
	if r, ok := p.Admission().Lookup(netip.MustParseAddr("192.0.2.9")); !ok || r.Refused == "" {
		t.Fatalf("the refused device is not in the index as refused: %+v, %v", r, ok)
	}
}

func TestAKeyRefPort49dDoesNotHoldRefusesTheDevice(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"prod_key"}
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Admitted("campus-sw-7"); !strings.Contains(r.Refused, "campus_key") {
		t.Fatalf("campus-sw-7: %+v", r)
	}
	if r, _ := p.Admitted("leaf-01"); r.Refused != "" {
		t.Fatalf("leaf-01: %+v", r)
	}
}

// Owner decision 1: a tie that exists only on one device refuses that device.
func TestAKeyGroupTieOnOneDeviceRefusesThatDevice(t *testing.T) {
	body := good + "key_groups:\n  - {match: {attributes: {site: campus}}, key_ref: a}\n" +
		"  - {match: {attributes: {role: leaf}}, key_ref: b}\n"
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "both", Platform: "arista_eos",
		Addresses:  []netip.Addr{netip.MustParseAddr("10.0.9.9")},
		Attributes: map[string]string{"site": "campus", "role": "leaf"}})
	p, err := Parse([]byte(body), e)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Admitted("both"); !strings.Contains(r.Refused, "attribute tier") || r.Refusal != admission.RefusedTie {
		t.Fatalf("both: %+v", r)
	}
	if r, _ := p.Admitted("campus-sw-7"); r.KeyRef != "a" || r.Refused != "" {
		t.Fatalf("campus-sw-7: %+v", r)
	}
}

func TestKeyGroupLoadErrors(t *testing.T) {
	for _, c := range []struct{ name, groups, want string }{
		{"no key_ref", "  - {match: {cidr: 10.0.0.0/8}}\n", "key_ref is required"},
		{"no match", "  - {key_ref: k}\n", "matches on neither cidr nor attributes"},
		{"both terms", "  - {match: {cidr: 10.0.0.0/8, attributes: {a: b}}, key_ref: k}\n", "not both"},
		{"host bits", "  - {match: {cidr: 10.0.0.1/8}, key_ref: k}\n", "host bits"},
		{"one prefix twice", "  - {match: {cidr: 10.0.0.0/8}, key_ref: a}\n  - {match: {cidr: 10.0.0.0/8}, key_ref: b}\n",
			"tie for every device"},
		{"one attribute set twice", "  - {match: {attributes: {a: b}}, key_ref: a}\n  - {match: {attributes: {a: b}}, key_ref: b}\n",
			"tie for every device"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(good+"key_groups:\n"+c.groups), env())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

// The inventory file's key groups apply, with a notice, until they are moved;
// where both files carry them the policy's win and the inventory's are named
// ignored, so no step of the move refuses a device (plan 6a Decided 4, C3).
func TestInventoryKeyGroupsApplyWithANoticeUntilMoved(t *testing.T) {
	e := env()
	e.InventoryKeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "prod_key"}}
	p, err := Parse([]byte(good), e)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Admitted("leaf-01"); r.KeyRef != "prod_key" {
		t.Fatalf("leaf-01: %+v", r)
	}
	if n := p.Notices(); len(n) != 1 || !strings.Contains(n[0], "move the block into the policy file") {
		t.Fatalf("notices: %q", n)
	}
	// Both files: the policy's block wins, and the notice names the other.
	e.InventoryKeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "old_key"}}
	p, err = Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatalf("both files refused: %v", err)
	}
	if r, _ := p.Admitted("leaf-01"); r.KeyRef != "prod_key" {
		t.Fatalf("the inventory's group won: %+v", r)
	}
	if n := p.Notices(); len(n) != 1 || !strings.Contains(n[0], "ignored") {
		t.Fatalf("notices: %q", n)
	}
}

// C1: a policy with a tests: block loads (good has one), and the tests
// resolve their devices through the index filled before buildTests.
func TestAPolicyWithTestsLoadsAndItsTestsFindTheirDevices(t *testing.T) {
	p := mustParse(t, good)
	if len(p.Tests()) == 0 {
		t.Fatal("good has tests")
	}
	for _, r := range p.RunTests(noon) {
		if r.Err != nil {
			t.Fatalf("%+v", r)
		}
	}
}

// I3: a test naming a device the inventory no longer has fails the test run,
// never the load, so an inventory change never waits on a policy edit.
func TestATestOnAnAbsentDeviceFailsTheRunNotTheLoad(t *testing.T) {
	body := strings.Replace(good, "device: leaf-01,", "device: leaf-gone,", 1)
	p, err := Parse([]byte(body), env())
	if err != nil {
		t.Fatalf("the load refused a test on an absent device: %v", err)
	}
	res := p.RunTests(noon)
	if len(res) == 0 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), `device "leaf-gone" is not in the inventory`) {
		t.Fatalf("%+v", res)
	}
}

// I2: where admission is assessed, a refused device resolves to
// ErrDeviceRefused after the grants check; where it is not (no key groups and
// no key names), nothing changes.
func TestARefusedDeviceDoesNotResolve(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	stray, _ := p.Device("stray")
	if _, err := p.Resolve("user:alice@example.com", stray, noon); !errors.Is(err, ErrDeviceRefused) {
		t.Fatalf("stray: %v", err)
	}
	if _, err := p.Resolve("user:nobody@example.com", stray, noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("no grant is answered first: %v", err)
	}
	unassessed := mustParse(t, good)
	if unassessed.AdmissionAssessed() {
		t.Fatal("no key groups and no key names is assessed")
	}
	leaf, _ := unassessed.Device("leaf-01")
	if _, err := unassessed.Resolve("user:alice@example.com", leaf, noon); err != nil {
		t.Fatalf("an unassessed policy refused: %v", err)
	}
}

func TestExplainSaysADeviceIsRefusedAndWhy(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	x, err := p.Explain("alice", "", "stray", "show version", noon)
	if err != nil || !strings.Contains(x.Refused, "matches no key group") {
		t.Fatalf("%+v, %v", x, err)
	}
	var out strings.Builder
	x.Render(&out, false)
	if !strings.Contains(out.String(), "deny device_unknown") {
		t.Fatalf("%s", out.String())
	}
}

// A refused entry never carries a key_ref, the unknown key's included: a
// reader that takes KeyRef != "" as admitted must not admit it (Task 3
// review M3). The key's name is in the refusal text.
func TestADeviceRefusedForAnUnknownKeyCarriesNoKeyRef(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"prod_key"}
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := p.Admitted("campus-sw-7")
	if r.Refusal != admission.RefusedUnknownKey || r.KeyRef != "" || !strings.Contains(r.Refused, "campus_key") {
		t.Fatalf("campus-sw-7: %+v", r)
	}
	if r, _ := p.Admission().Lookup(netip.MustParseAddr("10.0.2.7")); r.KeyRef != "" || r.Refused == "" {
		t.Fatalf("the index admits it: %+v", r)
	}
}
