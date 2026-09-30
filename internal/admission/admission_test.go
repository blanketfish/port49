package admission

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T) *Trie {
	t.Helper()
	inv, err := LoadFile("testdata/inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestLookupTiers(t *testing.T) {
	tr := load(t)
	cases := []struct{ addr, device, keyRef string }{
		{"10.20.0.7", "leaf-01", "prod_key"},     // tier 3, longest prefix is /8
		{"10.20.255.7", "leaf-01", "prod_key"},   // second address, same device
		{"10.99.0.5", "lab-sw-1", "lab_key"},     // tier 2 attribute beats the /16 CIDR
		{"10.20.0.9", "pinned-1", "special_key"}, // tier 1 pin beats everything
	}
	for _, c := range cases {
		r, ok := tr.Lookup(netip.MustParseAddr(c.addr))
		if !ok || r.Device.Name != c.device || r.KeyRef != c.keyRef {
			t.Fatalf("%s: ok=%v %+v", c.addr, ok, r)
		}
	}
	if _, ok := tr.Lookup(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("unknown address admitted")
	}
}

func TestBuildRefusesAddressCollision(t *testing.T) {
	inv := Inventory{Devices: []Device{
		{Name: "a", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		{Name: "b", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
	}}
	_, err := Build(inv)
	if err == nil || !strings.Contains(err.Error(), "a") || !strings.Contains(err.Error(), "b") {
		t.Fatalf("want error naming both devices, got %v", err)
	}
}

// TestBuildRefusesUnnamedOrDuplicateDevices covers the name as what it is: a
// namespace. store.TokenKey and store.ContextKey are keyed on the device
// name, so two devices sharing one (or sharing the empty string) share a
// token namespace, and a token minted for one redeems on the other.
func TestBuildRefusesUnnamedOrDuplicateDevices(t *testing.T) {
	t.Run("a device with no name", func(t *testing.T) {
		inv := Inventory{Devices: []Device{{Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}}}
		_, err := Build(inv)
		if err == nil || !strings.Contains(err.Error(), "10.0.0.1") {
			t.Fatalf("want an error naming the address of the unnamed device, got %v", err)
		}
	})
	t.Run("two devices with one name", func(t *testing.T) {
		inv := Inventory{Devices: []Device{
			{Name: "leaf-01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
			{Name: "leaf-01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}},
		}}
		_, err := Build(inv)
		if err == nil || !strings.Contains(err.Error(), "leaf-01") {
			t.Fatalf("want an error naming the duplicated device name, got %v", err)
		}
	})
}

// TestLoadFileRefusesUnknownKeys covers the 3am failure the package doc says
// cannot happen: `keyref:` for `key_ref:` silently un-pins a device onto a
// group key, and the first packet from it reads `no_known_key_matches`.
func TestLoadFileRefusesUnknownKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "inventory.yaml")
	body := "devices:\n  - {name: leaf-01, addresses: [10.0.0.1], keyref: special_key}\nkey_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: k}\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(p)
	if err == nil {
		t.Fatal("a misspelled inventory key must be refused at load")
	}
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "keyref") {
		t.Fatalf("the error must name the file and the key, got %v", err)
	}
}

// TestLoadFileRefusesAKeyGroupThatMatchesNothing covers a group with neither
// cidr nor attributes: attrsMatch against an empty want is vacuously true, so
// such a group silently claims every device in the attribute tier.
func TestLoadFileRefusesAKeyGroupThatMatchesNothing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "inventory.yaml")
	body := "devices:\n  - {name: leaf-01, addresses: [10.0.0.1]}\nkey_groups:\n  - {match: {}, key_ref: catch_all}\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(p)
	if err == nil {
		t.Fatal("a key group with neither cidr nor attributes must be refused")
	}
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "catch_all") {
		t.Fatalf("the error must name the file and the key group, got %v", err)
	}
}

func TestBuildRefusesSameTierOverlap(t *testing.T) {
	inv := Inventory{
		Devices: []Device{{Name: "d", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, Attributes: map[string]string{"env": "lab", "site": "x"}}},
		KeyGroups: []KeyGroup{
			{Attributes: map[string]string{"env": "lab"}, KeyRef: "k1"},
			{Attributes: map[string]string{"site": "x"}, KeyRef: "k2"},
		},
	}
	_, err := Build(inv)
	if err == nil || !strings.Contains(err.Error(), "k1") || !strings.Contains(err.Error(), "k2") {
		t.Fatalf("want error naming both groups, got %v", err)
	}
}

func TestBuildRefusesEqualLengthCIDROverlap(t *testing.T) {
	// Tier-3: two CIDR groups with same prefix and different key_refs matching one address must error
	inv := Inventory{
		Devices: []Device{{Name: "d", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.5")}}},
		KeyGroups: []KeyGroup{
			{CIDR: netip.MustParsePrefix("10.0.0.0/24"), KeyRef: "key_a"},
			{CIDR: netip.MustParsePrefix("10.0.0.0/24"), KeyRef: "key_b"},
		},
	}
	_, err := Build(inv)
	if err == nil || !strings.Contains(err.Error(), "key_a") || !strings.Contains(err.Error(), "key_b") {
		t.Fatalf("want error naming both key groups, got %v", err)
	}
}

func TestDeviceMatchingNoGroupIsNotAdmitted(t *testing.T) {
	inv := Inventory{Devices: []Device{{Name: "d", Addresses: []netip.Addr{netip.MustParseAddr("172.16.0.1")}}},
		KeyGroups: []KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "k"}}}
	tr, err := Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tr.Lookup(netip.MustParseAddr("172.16.0.1")); ok {
		t.Fatal("device with no key group must be refused")
	}
}

func TestBuildRefusesDisagreeingAddresses(t *testing.T) {
	// Case 1: two addresses resolving to different keys at same prefix length must error
	inv := Inventory{
		Devices: []Device{{
			Name:      "leaf-02",
			Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.1.5")},
		}},
		KeyGroups: []KeyGroup{
			{CIDR: netip.MustParsePrefix("10.0.0.0/24"), KeyRef: "key_a"},
			{CIDR: netip.MustParsePrefix("10.0.1.0/24"), KeyRef: "key_b"},
		},
	}
	_, err := Build(inv)
	if err == nil || !strings.Contains(err.Error(), "10.0.0.0/24") || !strings.Contains(err.Error(), "10.0.1.0/24") {
		t.Fatalf("want error naming both CIDRs, got %v", err)
	}

	// Case 2: two addresses resolving to different groups with same key_ref must succeed
	inv2 := Inventory{
		Devices: []Device{{
			Name:      "leaf-03",
			Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.1.5")},
		}},
		KeyGroups: []KeyGroup{
			{CIDR: netip.MustParsePrefix("10.0.0.0/24"), KeyRef: "unified_key"},
			{CIDR: netip.MustParsePrefix("10.0.1.0/24"), KeyRef: "unified_key"},
		},
	}
	tr, err := Build(inv2)
	if err != nil {
		t.Fatalf("two addresses with same key_ref should succeed: %v", err)
	}
	// Both addresses should resolve to unified_key
	r1, ok1 := tr.Lookup(netip.MustParseAddr("10.0.0.5"))
	r2, ok2 := tr.Lookup(netip.MustParseAddr("10.0.1.5"))
	if !ok1 || !ok2 || r1.KeyRef != "unified_key" || r2.KeyRef != "unified_key" {
		t.Fatalf("both addresses should resolve to unified_key: %v, %v", r1, r2)
	}
}

func TestAssignNamesTheTierAndTheGroup(t *testing.T) {
	inv, err := LoadFile("testdata/inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Device{}
	for _, d := range inv.Devices {
		byName[d.Name] = d
	}
	for _, c := range []struct {
		device string
		want   Assignment
	}{
		{"leaf-01", Assignment{KeyRef: "prod_key", Tier: TierCIDR, Group: "cidr 10.0.0.0/8 → prod_key"}},
		{"lab-sw-1", Assignment{KeyRef: "lab_key", Tier: TierAttribute, Group: "attributes {env: lab} → lab_key"}},
		{"pinned-1", Assignment{KeyRef: "special_key", Tier: TierPin, Group: "key_ref pinned on the device record"}},
	} {
		got, err := Assign(byName[c.device], inv.KeyGroups)
		if err != nil || got != c.want {
			t.Errorf("%s: %+v, %v; want %+v", c.device, got, err, c.want)
		}
	}
	stray := Device{Name: "stray", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	if got, err := Assign(stray, inv.KeyGroups); err != nil || got != (Assignment{}) {
		t.Errorf("a device no group matches is the zero assignment, not an error: %+v, %v", got, err)
	}
}

func TestAssignRefusesATieOnTheDevice(t *testing.T) {
	groups := []KeyGroup{{Attributes: map[string]string{"site": "campus"}, KeyRef: "a"},
		{Attributes: map[string]string{"role": "leaf"}, KeyRef: "b"}}
	both := Device{Name: "both", Attributes: map[string]string{"site": "campus", "role": "leaf"}}
	if _, err := Assign(both, groups); err == nil || !strings.Contains(err.Error(), "attribute tier") {
		t.Fatalf("want the attribute-tier tie, got %v", err)
	}
}

// A refused device is still in the index, so its packets are told apart from
// an unknown source's (spec §10's admission_refused bucket).
func TestNewTrieIndexesARefusedDevice(t *testing.T) {
	d := Device{Name: "stray", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	tr, err := NewTrie([]Resolved{{Device: d, Refused: "matches no key group"}})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := tr.Lookup(netip.MustParseAddr("192.0.2.1"))
	if !ok || r.Refused == "" || r.Device.Name != "stray" {
		t.Fatalf("got %+v, %v", r, ok)
	}
	a := Device{Name: "a", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	b := Device{Name: "b", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	if _, err := NewTrie([]Resolved{{Device: a}, {Device: b}}); err == nil {
		t.Fatal("two devices on one address were indexed")
	}
}

func TestValidateNamesBothDevicesOfACollision(t *testing.T) {
	err := Validate([]Device{{Name: "a", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		{Name: "b", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}})
	if err == nil || !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), `"b"`) {
		t.Fatalf("want both named, got %v", err)
	}
	if err := Validate([]Device{{Name: "a"}, {Name: "a"}}); err == nil {
		t.Fatal("a repeated name passed")
	}
}

// An unsupported transport refuses its device alone, never the file: a sync
// can write one, and refusing the file would stop every inventory change
// fleet-wide (spec §10).
func TestAnUnsupportedTransportRefusesTheDeviceAlone(t *testing.T) {
	inv, err := ParseFile([]byte(`devices:
  - {name: plain, platform: arista_eos, addresses: [10.0.0.1]}
  - {name: tcp-1, platform: arista_eos, addresses: [10.0.0.2], transport: tcp}
  - {name: tls-1, platform: arista_eos, addresses: [10.0.0.3], transport: tls}
  - {name: udp-1, platform: arista_eos, addresses: [10.0.0.4], transport: udp}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: prod_key}
`), "inventory.yaml")
	if err != nil {
		t.Fatalf("one device's transport refused the file: %v", err)
	}
	byName := map[string]Device{}
	for _, d := range inv.Devices {
		byName[d.Name] = d
	}
	if byName["plain"].Transport != TransportTCP {
		t.Errorf("an absent transport is %q, want tcp", byName["plain"].Transport)
	}
	for _, name := range []string{"plain", "tcp-1"} {
		if r := Resolve(byName[name], inv.KeyGroups); r.Refused != "" || r.KeyRef != "prod_key" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	for name, why := range map[string]string{"tls-1": "plan 11", "udp-1": `transport "udp"`} {
		r := Resolve(byName[name], inv.KeyGroups)
		if r.Refusal != RefusedTransport || r.KeyRef != "" || !strings.Contains(r.Refused, why) {
			t.Errorf("%s: want refused_transport naming %s, got %+v", name, why, r)
		}
	}
	tr, err := Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	for addr, admitted := range map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": false, "10.0.0.4": false} {
		if _, ok := tr.Lookup(netip.MustParseAddr(addr)); ok != admitted {
			t.Errorf("%s: admitted %v, want %v", addr, ok, admitted)
		}
	}
}

func TestResolveRefusesATieAndANoMatch(t *testing.T) {
	groups := []KeyGroup{{Attributes: map[string]string{"site": "campus"}, KeyRef: "a"},
		{Attributes: map[string]string{"role": "leaf"}, KeyRef: "b"}}
	both := Device{Name: "both", Attributes: map[string]string{"site": "campus", "role": "leaf"}}
	if r := Resolve(both, groups); r.Refusal != RefusedTie || r.KeyRef != "" || !strings.Contains(r.Refused, "attribute tier") {
		t.Errorf("tie: %+v", r)
	}
	if r := Resolve(Device{Name: "none"}, groups); r.Refusal != RefusedNoGroup || r.KeyRef != "" || r.Refused == "" {
		t.Errorf("no match: %+v", r)
	}
}

// Two attribute groups can share a key_ref, so a tie names each group by what
// it matches, not only by the key_ref.
func TestATieNamesTheGroupsByWhatTheyMatch(t *testing.T) {
	groups := []KeyGroup{{Attributes: map[string]string{"site": "campus"}, KeyRef: "k"},
		{Attributes: map[string]string{"role": "leaf"}, KeyRef: "k"}}
	both := Device{Name: "both", Attributes: map[string]string{"site": "campus", "role": "leaf"}}
	_, err := Assign(both, groups)
	if err == nil || !strings.Contains(err.Error(), "attributes {site: campus} → k") ||
		!strings.Contains(err.Error(), "attributes {role: leaf} → k") {
		t.Fatalf("want both groups named, got %v", err)
	}
}
