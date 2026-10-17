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
		{"no match", "  - {key_ref: k}\n", "matches on neither name, cidr nor attributes"},
		{"both terms", "  - {match: {cidr: 10.0.0.0/8, attributes: {a: b}}, key_ref: k}\n", "exactly one of name, cidr or attributes"},
		{"host bits", "  - {match: {cidr: 10.0.0.1/8}, key_ref: k}\n", "host bits"},
		{"one prefix twice", "  - {match: {cidr: 10.0.0.0/8}, key_ref: a}\n  - {match: {cidr: 10.0.0.0/8}, key_ref: b}\n",
			"tie for every device"},
		{"one attribute set twice", "  - {match: {attributes: {a: b}}, key_ref: a}\n  - {match: {attributes: {a: b}}, key_ref: b}\n",
			"tie for every device"},
		{"a key_ref that is no name", "  - {match: {cidr: 10.0.0.0/8}, key_ref: Sx9qT4vLm2pR7zK0wYh5}\n",
			"key_groups[0]: key_ref is not a valid key_ref name"},
		// netip quotes the value it could not parse; the error names the
		// position instead (Task 18 review m1).
		{"a cidr that is no prefix", "  - {match: {cidr: Sx9qT4vLm2pR7zK0wYh5}, key_ref: k}\n",
			"match.cidr is not a CIDR prefix"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(good+"key_groups:\n"+c.groups), env())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
			// A key_ref that is no name may be a secret pasted there.
			if strings.Contains(err.Error(), "Sx9qT") {
				t.Fatalf("printed the key_ref: %v", err)
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
	// A device this inventory never named was never assessed: it fails closed
	// (review M-1).
	ghost := admission.Device{Name: "ghost", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.9.1")}}
	if _, err := p.Resolve("user:alice@example.com", ghost, noon); !errors.Is(err, ErrDeviceRefused) {
		t.Fatalf("ghost: %v", err)
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

// A declared subject whose grants do not select a refused device is told
// no_grants_matched, never that the device exists and is refused: the grants
// are checked first, as for a quarantine (design §17; plan 6a I2).
func TestARefusedDeviceIsNeverRevealedAheadOfTheGrants(t *testing.T) {
	body := strings.Replace(keyGrouped, "grants:\n",
		"  - {name: bob, identity: \"user:bob@example.com\", username: bob, token_ttl: 60s}\n"+
			"grants:\n  - {subject: bob, scope: dc_fabric, roles: [read_only]}\n", 1)
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses:  []netip.Addr{netip.MustParseAddr("192.0.2.9")},
		Attributes: map[string]string{"site": "edge"}})
	p, err := Parse([]byte(body), e)
	if err != nil {
		t.Fatal(err)
	}
	stray, _ := p.Device("stray")
	if r, _ := p.Admitted("stray"); r.Refused == "" {
		t.Fatalf("stray is admitted: %+v", r)
	}
	if _, err := p.ResolveSubject("bob", stray, noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("ResolveSubject: %v", err)
	}
	if _, err := p.Resolve("user:bob@example.com", stray, noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("Resolve: %v", err)
	}
	// bob's grant still resolves where it selects an admitted device.
	leaf, _ := p.Device("leaf-01")
	if _, err := p.ResolveSubject("bob", leaf, noon); err != nil {
		t.Fatalf("leaf-01: %v", err)
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

// A pin that is not a key_ref name refuses that device alone: the policy and
// the rest of the fleet load, and nothing the load says prints the pin.
func TestAPinThatIsNoNameRefusesThatDeviceAlone(t *testing.T) {
	const secret = "Sx9qT4vLm2pR7zK0wYh5"
	e := env()
	e.KeyRefs = []string{"k"}
	e.Devices = append(e.Devices, admission.Device{Name: "pasted", Platform: "arista_eos", KeyRef: secret,
		Transport: admission.TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.200")}})
	p, err := Parse([]byte(good+"key_groups:\n  - {match: {cidr: 0.0.0.0/0}, key_ref: k}\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := p.Admitted("pasted")
	if r.Refusal != admission.RefusedUnknownKey || r.KeyRef != "" {
		t.Fatalf("pasted: %+v", r)
	}
	var said []string
	for _, r := range p.AdmissionRefusals() {
		said = append(said, r.Refused)
	}
	said = append(said, p.Notices()...)
	if strings.Contains(strings.Join(said, "\n"), "Sx9qT") {
		t.Fatalf("printed the pin: %q", said)
	}
	for _, d := range inventory() {
		if r, _ := p.Admitted(d.Name); r.Refused != "" && d.KeyRef == "" {
			t.Errorf("%s refused: %s", d.Name, r.Refused)
		}
	}
}

// Owner decision 3: the pin, in the reviewed policy, by name.
func TestAKeyGroupPinsADeviceByName(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"campus_key", "prod_key", "pin_key"}
	p, err := Parse([]byte(keyGrouped+"  - {match: {name: campus-sw-7}, key_ref: pin_key}\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	if as, _ := p.KeyAssignment("campus-sw-7"); as.KeyRef != "pin_key" || as.Tier != admission.TierPin {
		t.Fatalf("%+v", as)
	}
}

func TestANameGroupIsOneTermAndOneGroupPerName(t *testing.T) {
	for name, c := range map[string]struct{ group, want string }{
		"with a cidr": {"  - {match: {name: leaf-01, cidr: 10.0.0.0/8}, key_ref: prod_key}\n", "exactly one of name, cidr or attributes"},
		"twice":       {"  - {match: {name: leaf-01}, key_ref: prod_key}\n  - {match: {name: leaf-01}, key_ref: campus_key}\n", "tie for device leaf-01"},
		"not a name":  {"  - {match: {name: \"leaf 01\"}, key_ref: prod_key}\n", "match.name is not a device name"},
	} {
		if _, err := Parse([]byte(keyGrouped+c.group), env()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	// A value that is no name is not echoed.
	if _, err := Parse([]byte(keyGrouped+"  - {match: {name: \"leaf 01\"}, key_ref: prod_key}\n"), env()); err == nil ||
		strings.Contains(err.Error(), "leaf 01") {
		t.Fatalf("echoed the rejected name: %v", err)
	}
	// 253 bytes is a device name; 254 is not (broker's maxDeviceName).
	for n, ok := range map[int]bool{253: true, 254: false} {
		_, err := Parse([]byte(keyGrouped+"  - {match: {name: "+strings.Repeat("a", n)+"}, key_ref: prod_key}\n"), env())
		if refused := err != nil && strings.Contains(err.Error(), "match.name is not a device name"); refused == ok {
			t.Errorf("%d bytes: got %v", n, err)
		}
	}
}

func TestATLSDeviceIsNotRefusedForAKeyPort49dLacks(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"prod_key"}
	e.Devices = append(e.Devices, admission.Device{Name: "tls-1", Platform: "arista_eos",
		Transport: admission.TransportTLS, Attributes: map[string]string{"site": "campus"},
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.9")}})
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	// campus_key is not held, and the campus group would pick it for tls-1:
	// a TLS device takes no key, so it is admitted anyway.
	r, ok := p.Admitted("tls-1")
	if !ok || r.Refused != "" || r.KeyRef != "" {
		t.Fatalf("tls-1: %+v %v", r, ok)
	}
	if _, has := p.KeyAssignment("tls-1"); has {
		t.Fatal("a TLS device has no key assignment for keys show to print")
	}
	for _, ref := range p.AdmissionRefusals() {
		if ref.Device.Name == "tls-1" {
			t.Fatalf("tls-1 refused: %+v", ref)
		}
	}
}

func TestTwoTLSDevicesEqualUnderCaseFoldingAreBothRefused(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"prod_key"}
	for i, n := range []string{"Leaf-01", "leaf-01", "tcp-A", "tcp-a"} {
		tr := admission.TransportTLS
		if i >= 2 {
			tr = admission.TransportTCP
		}
		e.Devices = append(e.Devices, admission.Device{Name: n, Platform: "arista_eos", Transport: tr,
			Addresses: []netip.Addr{netip.MustParseAddr("10.0.7." + string(rune('1'+i)))}})
	}
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatalf("the load must not fail: %v", err)
	}
	for _, n := range []string{"Leaf-01", "leaf-01"} {
		r, _ := p.Admitted(n)
		if r.Refusal != admission.RefusedTLSNameClash || r.Refused == "" || r.KeyRef != "" {
			t.Errorf("%s: %+v", n, r)
		}
	}
	for _, n := range []string{"tcp-A", "tcp-a"} {
		if r, _ := p.Admitted(n); r.Refused != "" || r.KeyRef != "prod_key" {
			t.Errorf("tcp device %s is not admitted on prod_key: %+v", n, r)
		}
	}
}
