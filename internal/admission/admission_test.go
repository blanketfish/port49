package admission

import (
	"net/netip"
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
