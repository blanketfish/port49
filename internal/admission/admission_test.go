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
