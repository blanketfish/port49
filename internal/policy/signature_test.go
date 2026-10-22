package policy

import (
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
)

// fleetPolicy is a 10k-device Junos fleet across sites, roles and versions,
// with an overflowing composition, a refused one and an expiring grant: what
// the cost of the fail-closed report at a reload is measured on.
func fleetPolicy(tb testing.TB, devices int) *Policy {
	tb.Helper()
	e := Env{Now: noon}
	sites, roles := []string{"dc1", "dc2", "edge", "campus", "lab"}, []string{"leaf", "spine", "fw", "core"}
	versions := []string{"21.4R3-S4", "21.4R3-S5", "22.2R1", "23.4R2"}
	for i := range devices {
		e.Devices = append(e.Devices, admission.Device{Name: fmt.Sprintf("srx-%05d", i), Platform: "juniper_junos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})},
			Attributes: map[string]string{"site": sites[i%len(sites)], "role": roles[(i/5)%len(roles)],
				"os_version": versions[(i/20)%len(versions)], "serial": fmt.Sprintf("SN%07d", i)}})
	}
	var shows []string
	for _, w := range []string{"interfaces", "route", "chassis", "bgp", "ospf", "isis", "lldp", "arp", "version",
		"mpls", "ldp", "rsvp", "system", "security", "log", "ethernet-switching", "evpn", "bfd", "vrrp", "pfe",
		"services", "firewall", "policy-options", "class-of-service", "multicast", "pim", "igmp", "vlans", "ntp",
		"snmp"} {
		shows = append(shows, `"show `+w+` **"`)
	}
	body := `platform_set: 1.1.0
scopes:
  - {name: all_devices, match: {}}
  - {name: dc_fabric, match: {site: [dc1, dc2], role: [leaf, spine]}}
  - {name: edge, match: {site: [edge]}, on_missing: include}
  - {name: unpatched, match: {os_version: {lt: "21.4R3-S5"}}, on_missing: include}
roles:
  - {name: admin, privilege: admin, permit: ["**"]}
  - {name: ops, privilege: readonly, permit: [` + strings.Join(shows, ", ") + `]}
  - {name: refused, privilege: readonly, permit: ["show **"], deny: ["show configuration system"]}
  - {name: ro, privilege: readonly, permit: ["show **"]}
subjects:
  - {name: s, identity: ["user:a@example.com"], username: a, token_ttl: 60s}
  - {name: t, identity: ["user:b@example.com"], username: b, token_ttl: 60s}
  - {name: u, identity: ["user:c@example.com"], username: c, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [admin]}
  - {subject: t, scope: all_devices, roles: [ro]}
  - {subject: t, scope: dc_fabric, roles: [ops], expires: 2099-01-01}
  - {subject: u, scope: edge, roles: [refused], expires: 2098-01-01}
  - {subject: u, scope: unpatched, roles: [ro]}
`
	p, err := Parse([]byte(body), e)
	if err != nil {
		tb.Fatal(err)
	}
	return p
}

// The fail-closed report at a reload, policy test and policy diff read every
// subject on every device at every moment: grouped by device signature, a
// 10k-device fleet takes under a second (Task 4's limit).
func TestTheFailClosedReportTakesUnderASecondAtTenThousandDevices(t *testing.T) {
	if testing.Short() || raceBuild {
		t.Skip("a time bound; the race detector's slowdown alone breaks it")
	}
	p := fleetPolicy(t, 10000)
	start := time.Now()
	found := p.FailClosedCompositions(noon)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("FailClosedCompositions took %s on 10k devices", took)
	}
	if len(found) == 0 {
		t.Fatal("the fleet has no fail-closed composition, so the bound proves nothing")
	}
}

// bySignature and byDevice are what projectionGroups groups devices by: the
// signature, and the device's own name, which resolves every device on its
// own, as it did before the signature.
func bySignature(p *Policy) func(admission.Device) string {
	scopes := sortedKeys(p.scopes)
	return func(d admission.Device) string { return p.signature(d, scopes) }
}

func byDevice(d admission.Device) string { return d.Name }

// sameReports fails t unless grouping by signature reports what resolving
// every device on its own does, as Projections and FailClosedCompositions
// word it.
func sameReports(t *testing.T, p *Policy) {
	t.Helper()
	fast, fastLands := p.projectionGroupsBy(noon, bySignature(p))
	slow, slowLands := p.projectionGroupsBy(noon, byDevice)
	if got, want := projectionFindings(fast, fastLands), projectionFindings(slow, slowLands); !reflect.DeepEqual(got, want) {
		t.Fatalf("grouped by signature:\n%s\nresolved per device:\n%s", findingLines(got), findingLines(want))
	}
	if got, want := failClosed(fast), failClosed(slow); !reflect.DeepEqual(got, want) {
		t.Fatalf("grouped by signature: %+v\nresolved per device: %+v", got, want)
	}
}

func findingLines(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "  %s: %s\n", f.Kind, f.Message)
	}
	return b.String()
}

// Grouped by signature, the fleet's report is the one resolving each device
// gives, word for word: policy test, policy diff and the reload's line read
// it.
func TestGroupingBySignatureReportsWhatEachDeviceResolves(t *testing.T) {
	p := fleetPolicy(t, 400)
	if len(p.Projections(noon)) == 0 {
		t.Fatal("no projection finding")
	}
	sameReports(t, p)
}

// The signature holds every input resolve reads of a device. Each pair of
// devices differs in one input alone, and that input changes what the pair
// is told: grouped by a signature that missed it, the second device would be
// reported with the first.
func TestTheSignatureHoldsEveryInputResolveReads(t *testing.T) {
	var n byte
	dev := func(name, plat string, attrs map[string]string) admission.Device {
		n++
		return admission.Device{Name: name, Platform: plat, Attributes: attrs,
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{10, 7, 0, n})}}
	}
	base := map[string]string{"site": "edge", "os_version": "21.4R3-S4", "serial": "SN100"}
	with := func(k, v string) map[string]string {
		m := maps.Clone(base)
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	pairs := []struct{ input, a, b string }{
		{"platform", "plat-a", "plat-b"},
		{"an attribute's value", "site-a", "site-b"},
		{"an attribute's absence", "present-a", "present-b"},
		{"a version's order", "version-a", "version-b"},
		{"a version that does not compare", "comparable-a", "comparable-b"},
		{"a regex", "re-a", "re-b"},
		{"the name", "name-a", "name-b"},
		{"a version selected only as it does not compare", "inc-a", "inc-b"},
	}
	e := Env{Now: noon, Devices: []admission.Device{
		dev("plat-a", "juniper_junos", base), dev("plat-b", "srx_variant", base),
		dev("site-a", "juniper_junos", base), dev("site-b", "juniper_junos", with("site", "campus")),
		dev("present-a", "juniper_junos", base), dev("present-b", "juniper_junos", with("serial", "")),
		dev("version-a", "juniper_junos", base), dev("version-b", "juniper_junos", with("os_version", "22.2R1")),
		dev("comparable-a", "juniper_junos", base), dev("comparable-b", "juniper_junos", with("os_version", "beta")),
		dev("re-a", "juniper_junos", base), dev("re-b", "juniper_junos", with("serial", "XX100")),
		dev("name-a", "juniper_junos", base), dev("name-b", "juniper_junos", base),
		dev("inc-a", "juniper_junos", with("fw_version", "21.4R3-S4")),
		dev("inc-b", "juniper_junos", with("fw_version", "beta")),
	}}
	// Each scope is selected by one input, and grants its own subject a role
	// with a deny of its own: a device the scope selects is told that deny,
	// and one it does not select is not. The variant hides the word after
	// "interfaces", which makes sp's deny a secret_rule refusal there.
	p, err := Parse([]byte(`
platform_set: 1.1.0
platforms:
  srx_variant: {based_on: juniper_junos, redact: [{match: ['**'], after: interfaces}]}
scopes:
  - {name: all_devices, match: {}}
  - {name: by_site, match: {site: [edge]}, on_missing: exclude}
  - {name: by_serial, match: {serial: {re: "^SN"}}, on_missing: exclude}
  - {name: unpatched, match: {os_version: {lt: "21.4R3-S5"}}, on_missing: exclude}
  - {name: by_name, match: {name: [name-a]}, on_missing: exclude}
  - {name: unpatched_or_unknown, match: {fw_version: {lt: "21.4R3-S5"}}, on_missing: include}
roles:
  - {name: ro, privilege: readonly, permit: ["show **"]}
  - {name: plat, privilege: readonly, permit: ["show **"], deny: ["show interfaces ge-0/0/0"]}
  - {name: site, privilege: readonly, permit: ["show **"], deny: ["show route summary"]}
  - {name: serial, privilege: readonly, permit: ["show **"], deny: ["show chassis alarms"]}
  - {name: version, privilege: readonly, permit: ["show **"], deny: ["show version detail"]}
  - {name: named, privilege: readonly, permit: ["show **"], deny: ["show arp no-resolve"]}
subjects:
  - {name: sp, identity: ["user:p@example.com"], username: p, token_ttl: 60s}
  - {name: ss, identity: ["user:s@example.com"], username: s, token_ttl: 60s}
  - {name: sr, identity: ["user:r@example.com"], username: r, token_ttl: 60s}
  - {name: sv, identity: ["user:v@example.com"], username: v, token_ttl: 60s}
  - {name: sn, identity: ["user:n@example.com"], username: n, token_ttl: 60s}
  - {name: si, identity: ["user:i@example.com"], username: i, token_ttl: 60s}
grants:
  - {subject: sp, scope: all_devices, roles: [plat]}
  - {subject: ss, scope: all_devices, roles: [ro]}
  - {subject: ss, scope: by_site, roles: [site]}
  - {subject: sr, scope: all_devices, roles: [ro]}
  - {subject: sr, scope: by_serial, roles: [serial]}
  - {subject: sv, scope: all_devices, roles: [ro]}
  - {subject: sv, scope: unpatched, roles: [version]}
  - {subject: sn, scope: all_devices, roles: [ro]}
  - {subject: sn, scope: by_name, roles: [named]}
  - {subject: si, scope: unpatched_or_unknown, roles: [ro]}
`), e)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture proves something only where each pair is told apart: in
	// what the pair is reported in, or, for a selection by an incomparable
	// version, which spec §5.5 has reported but no projection reads, in
	// what it resolves to.
	groups, _ := p.projectionGroupsBy(noon, byDevice)
	for _, c := range pairs {
		a, _ := p.device(c.a)
		b, _ := p.device(c.b)
		if !slices.ContainsFunc(groups, func(g *projectionGroup) bool {
			return slices.Contains(g.devices, c.a) != slices.Contains(g.devices, c.b)
		}) && reflect.DeepEqual(resolutions(p, a), resolutions(p, b)) {
			t.Fatalf("%s: %s and %s are told alike, so the pair proves nothing", c.input, c.a, c.b)
		}
	}
	sameReports(t, p)
	// Devices of one signature resolve alike, subject by subject.
	key := bySignature(p)
	for _, a := range p.env.Devices {
		for _, b := range p.env.Devices {
			if key(a) == key(b) && !reflect.DeepEqual(resolutions(p, a), resolutions(p, b)) {
				t.Fatalf("%s and %s share a signature and resolve differently", a.Name, b.Name)
			}
		}
	}
}

// resolutions is what every subject resolves to on d at noon. An error is
// the zero Resolution, since its text may quote the device's name.
func resolutions(p *Policy, d admission.Device) []Resolution {
	var out []Resolution
	for _, name := range sortedKeys(p.subs) {
		res, err := p.resolve(p.subs[name], d, noon)
		if err != nil {
			res = Resolution{}
		}
		out = append(out, res)
	}
	return out
}

// BenchmarkFailClosedCompositions is the report's cost at a reload on a
// 10k-device fleet: under a second (Task 4's limit).
func BenchmarkFailClosedCompositions(b *testing.B) {
	p := fleetPolicy(b, 10000)
	for b.Loop() {
		p.FailClosedCompositions(noon)
	}
}
