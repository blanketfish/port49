package bundle

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
)

const pol = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]
`

func dev(name, addrs string, attrs map[string]string) admission.Device {
	d := admission.Device{Name: name, Platform: "arista_eos", Attributes: attrs}
	for _, a := range strings.Fields(addrs) {
		d.Addresses = append(d.Addresses, netip.MustParseAddr(a))
	}
	return d
}

// The name is the content: order and spelling do not change it, a fact does.
func TestIDIsTheContent(t *testing.T) {
	a := admission.Inventory{Devices: []admission.Device{dev("leaf-01", "10.0.0.2 10.0.0.1", nil),
		dev("leaf-02", "10.0.0.3", map[string]string{})}}
	b := admission.Inventory{Devices: []admission.Device{dev("leaf-02", "10.0.0.3", nil),
		dev("leaf-01", "10.0.0.1 10.0.0.2", nil)}}
	b.Devices[0].Transport = admission.TransportTCP
	if ID([]byte(pol), a) != ID([]byte(pol), b) {
		t.Fatal("reordering, an empty map and an explicit tcp changed the name")
	}
	c := admission.Inventory{Devices: []admission.Device{dev("leaf-01", "10.0.0.2 10.0.0.1", map[string]string{"site": "dc1"}),
		dev("leaf-02", "10.0.0.3", nil)}}
	if ID([]byte(pol), a) == ID([]byte(pol), c) {
		t.Fatal("an attribute did not change the name")
	}
	// Every other fact that decides admission names another bundle too.
	for name, change := range map[string]func(*admission.Inventory){
		"a pinned key_ref": func(i *admission.Inventory) { i.Devices[0].KeyRef = "lab_key" },
		"a transport":      func(i *admission.Inventory) { i.Devices[0].Transport = "udp" },
		"a platform":       func(i *admission.Inventory) { i.Devices[0].Platform = "juniper_junos" },
		"an address":       func(i *admission.Inventory) { i.Devices[0].Addresses[0] = netip.MustParseAddr("10.0.0.9") },
		"a key group": func(i *admission.Inventory) {
			i.KeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "prod_key"}}
		},
	} {
		d := admission.Inventory{Devices: []admission.Device{dev("leaf-01", "10.0.0.2 10.0.0.1", nil),
			dev("leaf-02", "10.0.0.3", nil)}}
		change(&d)
		if ID([]byte(pol), a) == ID([]byte(pol), d) {
			t.Errorf("%s did not change the name", name)
		}
	}
	if ID([]byte(pol), a) == ID([]byte(pol+"\n"), a) {
		t.Fatal("the policy's bytes did not change the name")
	}
	if !strings.HasPrefix(ID([]byte(pol), a), "sha256:") {
		t.Fatal("the name is not a sha256: string")
	}
}

func TestParseNamesTheBundleAndKeepsThePolicysOwnHash(t *testing.T) {
	inv := admission.Inventory{Devices: []admission.Device{dev("leaf-01", "10.0.0.1", nil)}}
	p, err := Parse([]byte(pol), inv, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Bundle != ID([]byte(pol), inv) || p.Source != engine.HashOf([]byte(pol)) {
		t.Fatalf("bundle %s source %s", p.Bundle, p.Source)
	}
	if string(p.Raw()) != pol || len(p.Inventory().Devices) != 1 {
		t.Fatal("the policy does not carry its bytes and its inventory")
	}
	if r, _ := p.Admitted("leaf-01"); r.KeyRef != "prod_key" {
		t.Fatalf("leaf-01: %+v", r)
	}
	dup := admission.Inventory{Devices: []admission.Device{dev("a", "10.0.0.1", nil), dev("b", "10.0.0.1", nil)}}
	if _, err := Parse([]byte(pol), dup, policy.Env{}); err == nil || !strings.Contains(err.Error(), `"b"`) {
		t.Fatalf("a collision: %v", err)
	}
}
