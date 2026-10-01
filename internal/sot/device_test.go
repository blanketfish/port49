package sot

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The recorded leaf-01 of each profile (tests/lab/sot/l30/<stack>/graphql.json
// and rest-device.json), with status in the release's spelling (L30) and
// primary_ip6 null.
const (
	netbox37GraphQL = `{"name": "leaf-01", "status": "ACTIVE", "platform": {"slug": "eos"}, "site": {"slug": "dc1"},
		"role": {"slug": "leaf"}, "primary_ip4": {"address": "10.0.1.5/32"}, "primary_ip6": null,
		"custom_fields": {"os_version": "4.31.2F"}, "tags": [{"slug": "port49"}],
		"interfaces": [{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}]},
			{"name": "Management1", "ip_addresses": [{"address": "10.0.1.5/32"}]}]}`
	netbox4GraphQL = `{"name": "leaf-01", "status": "active", "platform": {"slug": "eos"}, "site": {"slug": "dc1"},
		"role": {"slug": "leaf"}, "primary_ip4": {"address": "10.0.1.5/32"}, "primary_ip6": null,
		"custom_fields": {"os_version": "4.31.2F"}, "tags": [{"slug": "port49"}],
		"interfaces": [{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}]},
			{"name": "Management1", "ip_addresses": [{"address": "10.0.1.5/32"}]}]}`
	nautobot16REST = `{"name": "leaf-01", "status": {"value": "active", "label": "Active"},
		"platform": {"name": "eos", "slug": "eos"}, "site": {"name": "dc1", "slug": "dc1"},
		"device_role": {"name": "leaf", "slug": "leaf"}, "primary_ip4": {"address": "10.0.1.5/32"}, "primary_ip6": null,
		"custom_fields": {"os_version": "4.31.2F"}, "tags": [{"name": "port49", "slug": "port49"}]}`
	nautobot2GraphQL = `{"name": "leaf-01", "status": {"name": "Active"},
		"platform": {"name": "eos", "network_driver": "arista_eos"}, "location": {"name": "dc1"}, "role": {"name": "leaf"},
		"primary_ip4": {"address": "10.0.1.5/32"}, "primary_ip6": null, "_custom_field_data": {"os_version": "4.31.2F"},
		"tags": [{"name": "port49"}],
		"interfaces": [{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}]},
			{"name": "Management1", "ip_addresses": [{"address": "10.0.1.5/32"}]}]}`
)

func raw(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// active is the default filter Load gives a source (Task 9).
var active = Filter{Status: []string{"active"}}

func addrs(d []netip.Addr) string {
	out := make([]string, len(d))
	for i, a := range d {
		out[i] = a.String()
	}
	return strings.Join(out, ",")
}

// Decision 31: each profile's default map reads its release's recorded
// fields, and a platform slug becomes port49's name.
func TestTheDefaultMapReadsEachProfile(t *testing.T) {
	for _, c := range []struct {
		profile, api, body string
	}{
		{NetBox37, "graphql", netbox37GraphQL},
		{NetBox4, "graphql", netbox4GraphQL},
		{Nautobot2, "graphql", nautobot2GraphQL},
	} {
		m := Mapping{Filter: active, Addresses: Addresses{Primary: true}}
		p := profiles[c.profile]
		if err := m.check(p, c.api); err != nil {
			t.Fatal(err)
		}
		d, keep, notes := m.device(p, c.api, raw(t, c.body))
		if !keep || len(notes) != 0 || d.Name != "leaf-01" || d.Platform != "arista_eos" ||
			d.Attributes["site"] != "dc1" || d.Attributes["role"] != "leaf" || addrs(d.Addresses) != "10.0.1.5" ||
			d.Transport != "tcp" || d.KeyRef != "" {
			t.Errorf("%s: %+v keep=%v %v", c.profile, d, keep, notes)
		}
	}
}

// L27: Nautobot 1.6 gives network_driver over GraphQL only, so its default
// map does not read over REST; a map that names platform.slug does.
func TestAPathAProfileDoesNotGiveIsRefused(t *testing.T) {
	if err := (Mapping{}).check(profiles[Nautobot16], "rest"); err == nil ||
		!strings.Contains(err.Error(), "map.platform: platform.network_driver is not read over REST on profile nautobot_1_6") {
		t.Fatalf("got %v", err)
	}
	m := Mapping{Map: map[string]string{"platform": "platform.slug", "site": "site.slug", "role": "role.slug"},
		Filter: active, Addresses: Addresses{Primary: true}}
	if err := m.check(profiles[Nautobot16], "rest"); err != nil {
		t.Fatal(err)
	}
	d, keep, _ := m.device(profiles[Nautobot16], "rest", raw(t, nautobot16REST))
	if !keep || d.Platform != "arista_eos" || d.Attributes["role"] != "leaf" || d.Attributes["site"] != "dc1" {
		t.Fatalf("%+v", d)
	}
	if err := (Mapping{Map: map[string]string{"platform": "platform.slug", "site": "location.name"}}).check(
		profiles[NetBox4], "graphql"); err == nil ||
		!strings.Contains(err.Error(), "map.site: location.name is not read on profile netbox_4; it reads "+
			"platform.slug, role.slug, site.slug") {
		t.Fatalf("got %v", err)
	}
	if err := (Mapping{Addresses: Addresses{AllInterfaces: true}}).check(profiles[NetBox4], "rest"); err == nil ||
		!strings.Contains(err.Error(), "REST does not give") {
		t.Fatalf("got %v", err)
	}
}

// Decision 31: status is compared in lower case, so every recorded spelling
// matches; a decommissioned device is not admitted by default.
func TestTheStatusFilterKeepsActiveByDefault(t *testing.T) {
	m := Mapping{Filter: active, Addresses: Addresses{Primary: true}}
	for _, body := range []string{netbox37GraphQL, netbox4GraphQL, nautobot2GraphQL} {
		planned := strings.NewReplacer(`"ACTIVE"`, `"PLANNED"`, `"active"`, `"planned"`, `"Active"`, `"Planned"`).Replace(body)
		for _, p := range []Profile{profiles[NetBox37], profiles[NetBox4], profiles[Nautobot2]} {
			if _, keep, _ := m.device(p, "graphql", raw(t, planned)); keep {
				t.Fatalf("%s kept a planned device", p.Name)
			}
		}
	}
	if _, keep, _ := (Mapping{Addresses: Addresses{Primary: true}}).device(profiles[NetBox4], "graphql",
		raw(t, strings.Replace(netbox4GraphQL, `"active"`, `"planned"`, 1))); !keep {
		t.Fatal("an empty status filter keeps every status")
	}
}

func TestTagsAndHasPrimaryIPFilter(t *testing.T) {
	p := profiles[Nautobot2]
	m := Mapping{Filter: Filter{Tags: []string{"port49"}, HasPrimaryIP: true}, Addresses: Addresses{Primary: true}}
	if _, keep, _ := m.device(p, "graphql", raw(t, nautobot2GraphQL)); !keep {
		t.Fatal("tagged and addressed")
	}
	m.Filter.Tags = []string{"port49", "core"}
	if _, keep, _ := m.device(p, "graphql", raw(t, nautobot2GraphQL)); keep {
		t.Fatal("every tag named is required")
	}
	m.Filter.Tags = nil
	noIP := strings.Replace(nautobot2GraphQL, `"primary_ip4": {"address": "10.0.1.5/32"}`, `"primary_ip4": null`, 1)
	if _, keep, _ := m.device(p, "graphql", raw(t, noIP)); keep {
		t.Fatal("has_primary_ip")
	}
}

// Decision 31: interface addresses only when named, deduplicated, sorted.
func TestInterfacesAreReadOnlyWhenNamed(t *testing.T) {
	p := profiles[NetBox4]
	for _, c := range []struct {
		a    Addresses
		want string
	}{
		{Addresses{Primary: true}, "10.0.1.5"},
		{Addresses{Primary: true, Interfaces: []string{"Loopback0"}}, "10.0.1.5,10.0.1.6"},
		{Addresses{Interfaces: []string{"Loopback0"}}, "10.0.1.6"},
		{Addresses{Primary: true, AllInterfaces: true}, "10.0.1.5,10.0.1.6"},
	} {
		d, _, _ := (Mapping{Addresses: c.a}).device(p, "graphql", raw(t, netbox4GraphQL))
		if addrs(d.Addresses) != c.want {
			t.Errorf("%+v: %s", c.a, addrs(d.Addresses))
		}
	}
	sel := (Mapping{Addresses: Addresses{Interfaces: []string{"Loopback0"}}}).selection(p).String()
	if !strings.Contains(sel, "interfaces { ip_addresses { address } name }") {
		t.Fatalf("%s", sel)
	}
	if sel := (Mapping{}).selection(p).String(); strings.Contains(sel, "interfaces") || strings.Contains(sel, "tags") {
		t.Fatalf("asked for what nothing reads: %s", sel)
	}
}

// Decision 31: a custom field that is a string, number or boolean is an
// attribute; one that is null is left unset; one that is an object is left
// unset and said; status may be mapped, in lower case.
func TestCustomFieldsAndStatusMapToAttributes(t *testing.T) {
	p := profiles[NetBox4]
	m := Mapping{Map: map[string]string{"platform": "platform.slug", "os_version": "custom_fields.os_version",
		"rack_units": "custom_fields.units", "managed": "custom_fields.managed", "owner": "custom_fields.owner",
		"lifecycle": "status"}}
	body := strings.Replace(netbox4GraphQL, `{"os_version": "4.31.2F"}`,
		`{"os_version": "4.31.2F", "units": 2, "managed": true, "owner": {"id": 7}, "absent": null}`, 1)
	d, _, notes := m.device(p, "graphql", raw(t, body))
	if d.Attributes["os_version"] != "4.31.2F" || d.Attributes["rack_units"] != "2" || d.Attributes["managed"] != "true" ||
		d.Attributes["lifecycle"] != "active" {
		t.Fatalf("%+v", d.Attributes)
	}
	if _, set := d.Attributes["owner"]; set || len(notes) != 1 ||
		!strings.Contains(notes[0], "custom field owner is not a string, number or boolean; attribute owner is left unset") {
		t.Fatalf("%+v %v", d.Attributes, notes)
	}
	if got := m.selection(p).String(); got != "custom_fields name platform { slug } primary_ip4 { address } "+
		"primary_ip6 { address } status" {
		t.Fatalf("%q", got)
	}
}

// Pre-flight M13: an interface's loopback or link-local address is left
// out, said once as a note; the primary is kept whatever it is.
func TestAnInterfaceAddressThatCannotSourceTACACSIsLeftOut(t *testing.T) {
	body := strings.Replace(netbox4GraphQL, `{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}]}`,
		`{"name": "Loopback0", "ip_addresses": [{"address": "10.0.1.6/32"}, {"address": "127.0.0.1/8"}, `+
			`{"address": "fe80::1/64"}]}`, 1)
	d, _, notes := (Mapping{Addresses: Addresses{Primary: true, AllInterfaces: true}}).device(profiles[NetBox4],
		"graphql", raw(t, body))
	if addrs(d.Addresses) != "10.0.1.5,10.0.1.6" || len(notes) != 1 ||
		!strings.Contains(notes[0], "cannot source TACACS+") {
		t.Fatalf("%s %v", addrs(d.Addresses), notes)
	}
}

func TestAnAddressThatDoesNotParseIsSaidAndLeftOut(t *testing.T) {
	body := strings.Replace(netbox4GraphQL, `"primary_ip4": {"address": "10.0.1.5/32"}`, `"primary_ip4": {"address": "ten"}`, 1)
	d, keep, notes := (Mapping{Addresses: Addresses{Primary: true}}).device(profiles[NetBox4], "graphql", raw(t, body))
	if !keep || len(d.Addresses) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "device leaf-01: primary_ip4 is not an IP address") {
		t.Fatalf("%+v %v", d, notes)
	}
}

// Spec §10: an alias table, overrides, and an unrecognized slug kept.
func TestTheAliasTable(t *testing.T) {
	for slug, want := range map[string]string{"eos": "arista_eos", "EOS": "arista_eos", "arista-eos": "arista_eos",
		"arista_eos": "arista_eos", "veos": "arista_eos", "cisco_xe": "cisco_iosxe", "ios-xe": "cisco_iosxe",
		"nx-os": "cisco_nxos", "cisco_nxos": "cisco_nxos", "junos": "juniper_junos", "juniper_junos": "juniper_junos",
		"cisco_ios": "cisco_ios", "eos-lab": "eos-lab"} {
		if got := platformName(slug, nil); got != want {
			t.Errorf("%s: %s", slug, got)
		}
	}
	if got := platformName("eos", map[string]string{"eos": "arista_eos_lab"}); got != "arista_eos_lab" {
		t.Fatalf("override: %s", got)
	}
	names := map[string]bool{}
	for _, v := range builtinAliases {
		names[v] = true
	}
	if !slices.Equal(sortedKeys(names), []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"}) {
		t.Fatalf("the table maps to %v, which are not the four shipped platforms", sortedKeys(names))
	}
}

// An address is one host, never a range: a prefix length is dropped, an
// IPv4-mapped IPv6 address is its IPv4 address (port49d unmaps a source the
// same way, and two devices sharing one must collide), and a zoned address,
// or one written as its prefix's network or broadcast address, is left out
// and said, since no device sources TACACS+ from it.
func TestAnAddressIsOneHostAndNeverARange(t *testing.T) {
	for _, c := range []struct {
		addr, want string
		note       bool
	}{
		{"10.0.1.6/24", "10.0.1.5,10.0.1.6", false},
		{"10.0.1.6", "10.0.1.5,10.0.1.6", false},
		{"::ffff:10.0.1.6/128", "10.0.1.5,10.0.1.6", false},
		{"::ffff:10.0.1.6", "10.0.1.5,10.0.1.6", false},
		{"::ffff:10.0.1.5/120", "10.0.1.5", false},
		{"10.0.1.6/31", "10.0.1.5,10.0.1.6", false},
		{"10.0.1.7/31", "10.0.1.5,10.0.1.7", false},
		{"10.0.1.0/24", "10.0.1.5", true},
		{"10.0.1.255/24", "10.0.1.5", true},
		{"::ffff:10.0.1.0/120", "10.0.1.5", true},
		{"10.0.1.0/0", "10.0.1.5", true},
		{"2001:db8::/64", "10.0.1.5", true},
		{"2001:db8::/127", "10.0.1.5,2001:db8::", false},
		{"2001:db8::6%eth0", "10.0.1.5", true},
		{"2001:db8::6%eth0/64", "10.0.1.5", true},
		{"::ffff:127.0.0.1", "10.0.1.5", true},
		{"fe80::1%eth0/64", "10.0.1.5", true},
	} {
		body := strings.Replace(netbox4GraphQL, `{"address": "10.0.1.6/32"}`, `{"address": "`+c.addr+`"}`, 1)
		d, _, notes := (Mapping{Addresses: Addresses{Primary: true, AllInterfaces: true}}).device(profiles[NetBox4],
			"graphql", raw(t, body))
		if addrs(d.Addresses) != c.want || (len(notes) > 0) != c.note {
			t.Errorf("%s: %s %v", c.addr, addrs(d.Addresses), notes)
		}
		for _, a := range d.Addresses {
			if a.Zone() != "" || a.Is4In6() {
				t.Errorf("%s: kept %s", c.addr, a)
			}
		}
	}
	for _, primary := range []string{"10.0.1.0/24", "2001:db8::5%eth0", "::ffff:10.0.1.0/120"} {
		body := strings.Replace(netbox4GraphQL, `"primary_ip4": {"address": "10.0.1.5/32"}`,
			`"primary_ip4": {"address": "`+primary+`"}`, 1)
		d, _, notes := (Mapping{Addresses: Addresses{Primary: true}}).device(profiles[NetBox4], "graphql", raw(t, body))
		if len(d.Addresses) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "device leaf-01: primary_ip4 is not") {
			t.Errorf("%s: %s %v", primary, addrs(d.Addresses), notes)
		}
	}
	// A zoned link-local is one of the addresses that cannot source TACACS+,
	// said once for every device, not a note naming this one.
	body := strings.Replace(netbox4GraphQL, `{"address": "10.0.1.6/32"}`, `{"address": "fe80::1%eth0"}`, 1)
	if _, _, notes := (Mapping{Addresses: Addresses{Primary: true, AllInterfaces: true}}).device(profiles[NetBox4],
		"graphql", raw(t, body)); len(notes) != 1 || !strings.Contains(notes[0], "cannot source TACACS+") {
		t.Fatalf("a zoned link-local: %v", notes)
	}
	body = strings.Replace(netbox4GraphQL, `"primary_ip4": {"address": "10.0.1.5/32"}`,
		`"primary_ip4": {"address": "::ffff:10.0.1.5"}`, 1)
	if d, _, _ := (Mapping{Addresses: Addresses{Primary: true}}).device(profiles[NetBox4], "graphql",
		raw(t, body)); addrs(d.Addresses) != "10.0.1.5" {
		t.Fatalf("a mapped primary: %s", addrs(d.Addresses))
	}
}
