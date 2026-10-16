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
	// The key by its line, not its text: a decode error quotes nothing from
	// the file, where a secret may be pasted (yamlfault).
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "line 2: an unknown field") ||
		strings.Contains(err.Error(), "keyref") {
		t.Fatalf("the error must name the file and the key's line, and quote nothing, got %v", err)
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

// A bad address names its device by position: the name has passed no shape
// check yet, so it is not echoed.
func TestABadAddressNamesItsDeviceByPosition(t *testing.T) {
	_, err := ParseFile([]byte("devices:\n  - {name: ok-1, platform: arista_eos, addresses: [10.0.0.1]}\n"+
		"  - {name: \"leaf 01\\u001b[2J\", platform: arista_eos, addresses: [10.0.0.2, nope]}\n"), "")
	if err == nil || !strings.Contains(err.Error(), "devices[1]: addresses[1] is not an IP address") ||
		strings.Contains(err.Error(), "leaf 01") {
		t.Fatalf("got %v", err)
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
	if r := Resolve(byName["tls-1"], inv.KeyGroups); r.Refused != "" || r.KeyRef != "" {
		t.Errorf("tls-1: a TLS device is admitted with no key_ref (decision 50 ruling 4), got %+v", r)
	}
	r := Resolve(byName["udp-1"], inv.KeyGroups)
	if r.Refusal != RefusedTransport || r.KeyRef != "" || !strings.Contains(r.Refused, `transport "udp"`) {
		t.Errorf("udp-1: want refused_transport, got %+v", r)
	}
	tr, err := Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	for addr, admitted := range map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true, "10.0.0.4": false} {
		if _, ok := tr.Lookup(netip.MustParseAddr(addr)); ok != admitted {
			t.Errorf("%s: admitted %v, want %v", addr, ok, admitted)
		}
	}
}

func TestATLSDeviceIgnoresKeyGroupsAndItsPin(t *testing.T) {
	d := Device{Name: "tls-9", Platform: "arista_eos", Transport: TransportTLS, KeyRef: "pinned_key",
		Addresses: []netip.Addr{netip.MustParseAddr("10.9.0.1")}}
	groups := []KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "prod_key"},
		{Name: "tls-9", KeyRef: "other_key"}}
	r := Resolve(d, groups)
	if r.Refused != "" || r.KeyRef != "" {
		t.Fatalf("a TLS device takes no key, pinned or grouped: %+v", r)
	}
	if got := d.EffectiveTransport(); got != TransportTLS {
		t.Fatalf("EffectiveTransport: %q", got)
	}
	if got := (Device{}).EffectiveTransport(); got != TransportTCP {
		t.Fatalf("an absent transport is tcp: %q", got)
	}
	tr, err := Build(Inventory{Devices: []Device{d}})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := tr.Lookup(netip.MustParseAddr("10.9.0.1")); !ok || got.Refused != "" || got.KeyRef != "" {
		t.Fatalf("Build: %+v %v", got, ok)
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

// A pin that is not a key_ref name, most likely a secret pasted there,
// refuses that device alone and is never printed.
func TestAPinThatIsNoNameRefusesTheDeviceUnprinted(t *testing.T) {
	const secret = "Sx9qT4vLm2pR7zK0wYh5"
	bad := Device{Name: "bad", KeyRef: secret, Transport: TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	good := Device{Name: "good", KeyRef: "prod_key", Transport: TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	r := Resolve(bad, nil)
	if r.Refusal != RefusedUnknownKey || r.KeyRef != "" || !strings.Contains(r.Refused, "not a valid key_ref name") ||
		strings.Contains(r.Refused, "Sx9qT") {
		t.Fatalf("%+v", r)
	}
	tr, err := Build(Inventory{Devices: []Device{bad, good}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tr.Lookup(bad.Addresses[0]); ok {
		t.Fatal("the bad pin was admitted")
	}
	if r, ok := tr.Lookup(good.Addresses[0]); !ok || r.KeyRef != "prod_key" {
		t.Fatalf("the rest of the inventory: %+v", r)
	}
}

// An inventory key group's key_ref is shape-checked as a policy's is, and a
// bad one is refused without being printed.
func TestAnInventoryKeyGroupKeyRefThatIsNoNameIsRefusedUnprinted(t *testing.T) {
	p := filepath.Join(t.TempDir(), "inventory.yaml")
	body := "devices: []\nkey_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: Sx9qT4vLm2pR7zK0wYh5}\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(p); err == nil || !strings.Contains(err.Error(), "not a valid key_ref name") ||
		strings.Contains(err.Error(), "Sx9qT") {
		t.Fatalf("%v", err)
	}
}

// A name group is tier 1: it outranks an attribute group, and a device with
// addresses in two CIDR groups for different keys takes it whole.
func TestANameGroupPinsTheDeviceAtTierOne(t *testing.T) {
	d := Device{Name: "leaf-01", Attributes: map[string]string{"env": "lab"},
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.168.1.1")}}
	groups := []KeyGroup{
		{Attributes: map[string]string{"env": "lab"}, KeyRef: "lab_key"},
		{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "prod_key"},
		{CIDR: netip.MustParsePrefix("192.168.0.0/16"), KeyRef: "other_key"},
		{Name: "leaf-01", KeyRef: "pin_key"},
	}
	as, err := Assign(d, groups)
	if err != nil || as.KeyRef != "pin_key" || as.Tier != TierPin || as.Group != "name leaf-01 → pin_key" {
		t.Fatalf("%+v %v", as, err)
	}
	// Without the name group the same device is refused: its addresses
	// disagree at tier 3 — the multi-address case the pin tier exists for.
	d.Attributes = nil
	if _, err := Assign(d, groups[1:3]); err == nil {
		t.Fatal("the addresses' disagreement was not refused")
	}
}

func TestTwoNameGroupsForOneDeviceTie(t *testing.T) {
	d := Device{Name: "leaf-01"}
	if _, err := Assign(d, []KeyGroup{{Name: "leaf-01", KeyRef: "a"}, {Name: "leaf-01", KeyRef: "b"}}); err == nil ||
		!strings.Contains(err.Error(), "in the pin tier") {
		t.Fatalf("got %v", err)
	}
}

// With inventory_file, a record pin and a name group that name different
// keys refuse the device; the same key is no conflict.
func TestARecordPinAndANameGroupMustAgree(t *testing.T) {
	groups := []KeyGroup{{Name: "leaf-01", KeyRef: "b"}}
	if _, err := Assign(Device{Name: "leaf-01", KeyRef: "a"}, groups); err == nil {
		t.Fatal("a disagreement was not refused")
	}
	// The record's key_ref is not printed: a pin is where a secret gets pasted.
	if _, err := Assign(Device{Name: "leaf-01", KeyRef: "sx9qt4vlm2pr7zk0wyh5"}, groups); err == nil ||
		strings.Contains(err.Error(), "sx9qt") {
		t.Fatalf("printed the record's pin: %v", err)
	}
	if as, err := Assign(Device{Name: "leaf-01", KeyRef: "b"}, groups); err != nil || as.KeyRef != "b" {
		t.Fatalf("%+v %v", as, err)
	}
}

func TestTLSNameClashes(t *testing.T) {
	tls := func(n, addr string) Device {
		return Device{Name: n, Transport: TransportTLS, Addresses: []netip.Addr{netip.MustParseAddr(addr)}}
	}
	devs := []Device{tls("LEAF-01", "10.0.0.1"), tls("leaf-01", "10.0.0.2"), tls("leaf-02", "10.0.0.3"),
		{Name: "TCP-1", Transport: TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.4")}},
		{Name: "tcp-1", Transport: TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.5")}},
		tls("Kr", "10.0.0.6"), tls("kr", "10.0.0.7")}
	devs[5].Name = "\u212ar" // a Kelvin sign is not ASCII: it folds to nothing
	got := TLSNameClashes(devs, nil)
	if len(got) != 2 || got["LEAF-01"] == "" || got["leaf-01"] == "" {
		t.Fatalf("want exactly LEAF-01 and leaf-01, got %v", got)
	}
	if err := Validate(devs); err != nil {
		t.Fatalf("nothing else in the load fails: %v", err)
	}
	tr, err := Build(Inventory{Devices: devs})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"10.0.0.1", "10.0.0.2"} {
		if _, ok := tr.Lookup(netip.MustParseAddr(a)); ok {
			t.Errorf("%s is indexed as admitted", a)
		}
	}
	if _, ok := tr.Lookup(netip.MustParseAddr("10.0.0.3")); !ok {
		t.Error("leaf-02 was refused with them")
	}
}

func TestTLSNameClashesUnderDNSSuffixes(t *testing.T) {
	tls := func(n, addr string) Device {
		return Device{Name: n, Transport: TransportTLS, Addresses: []netip.Addr{netip.MustParseAddr(addr)}}
	}
	devs := []Device{tls("leaf-01", "10.0.0.1"), tls("Leaf-01.Example.NET", "10.0.0.2"), tls("leaf-02", "10.0.0.3"),
		{Name: "leaf-02.example.net", Transport: TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.4")}}}
	if got := TLSNameClashes(devs, nil); len(got) != 0 {
		t.Fatalf("without suffixes the names differ: %v", got)
	}
	got := TLSNameClashes(devs, []string{"example.net"})
	if len(got) != 2 || got["leaf-01"] == "" || got["Leaf-01.Example.NET"] == "" {
		t.Fatalf("want exactly leaf-01 and Leaf-01.Example.NET, got %v", got)
	}
	// A tcp device is never affected, and a suffix that joins nothing refuses nothing.
	if got := TLSNameClashes(devs, []string{"other.org"}); len(got) != 0 {
		t.Fatalf("an unrelated suffix: %v", got)
	}
	tr, err := Build(Inventory{Devices: devs, DNSSuffixes: []string{"example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"10.0.0.1", "10.0.0.2"} {
		if _, ok := tr.Lookup(netip.MustParseAddr(a)); ok {
			t.Errorf("%s is indexed as admitted", a)
		}
	}
	if _, ok := tr.Lookup(netip.MustParseAddr("10.0.0.3")); !ok {
		t.Error("leaf-02 was refused with them")
	}
}

func TestTLSNameInvalid(t *testing.T) {
	tls := func(n, addr string) Device {
		return Device{Name: n, Transport: TransportTLS, Addresses: []netip.Addr{netip.MustParseAddr(addr)}}
	}
	devs := []Device{tls("l\u00e9af-01", "10.0.0.1"), tls("leaf-02", "10.0.0.2"),
		{Name: "l\u00e9af-03", Transport: TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.3")}}}
	got := TLSNameInvalid(devs)
	if len(got) != 1 || got["l\u00e9af-01"] == "" {
		t.Fatalf("want exactly the non-ASCII tls device, got %v", got)
	}
	tr, err := Build(Inventory{Devices: devs, KeyGroups: []KeyGroup{{Name: "l\u00e9af-03", KeyRef: "k"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tr.Lookup(netip.MustParseAddr("10.0.0.1")); ok {
		t.Error("the non-ASCII tls device is indexed as admitted")
	}
	if _, ok := tr.Lookup(netip.MustParseAddr("10.0.0.2")); !ok {
		t.Error("leaf-02 was refused with it")
	}
}
