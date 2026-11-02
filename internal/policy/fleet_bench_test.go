package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/engine"
)

// The fleet benchmarks (plan 12c, Task 6) run at the design's size: 500
// subjects (50 machine principals with a batch grant, 450 people) over 10 000
// arista_eos devices. Each reports ns/op and allocs.
const (
	benchPrincipals = 50
	benchHumans     = 450
	benchDevices    = 10000
)

func benchPolicyText(permit string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `scopes:
  - {name: all_devices, match: {}}
  - {name: arista, match: {platform: arista_eos}, on_missing: include}
roles:
  - {name: load_admin, privilege: admin, permit: [%q]}
  - {name: load_read, privilege: readonly, permit: ["show **"]}
  - {name: load_denies, deny: ["show users"]}
subjects:
`, permit)
	for p := range benchPrincipals {
		fmt.Fprintf(&b, "  - {name: svc_%02d, identity: [\"user:svc%02d@example.com\"], username: svc%02d, token_ttl: 900s}\n", p, p, p)
	}
	for h := range benchHumans {
		fmt.Fprintf(&b, "  - {name: human_%03d, identity: [\"user:human%03d@example.com\"], username: human%03d, token_ttl: 900s}\n", h, h, h)
	}
	b.WriteString("grants:\n")
	for p := range benchPrincipals {
		fmt.Fprintf(&b, "  - {subject: svc_%02d, scope: all_devices, roles: [load_admin], max_privilege: admin}\n", p)
		fmt.Fprintf(&b, "  - {subject: svc_%02d, scope: arista, roles: [load_denies], max_privilege: admin}\n", p)
	}
	for h := range benchHumans {
		fmt.Fprintf(&b, "  - {subject: human_%03d, scope: all_devices, roles: [load_read], max_privilege: readonly}\n", h)
	}
	b.WriteString("keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_KEY_LOAD}\nkey_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n")
	return b.String()
}

func benchFleet(n int) []admission.Device {
	devs := make([]admission.Device, n)
	for i := range devs {
		devs[i] = admission.Device{Name: fmt.Sprintf("load-%05d", i), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{127, byte(1 + i/254/256), byte(i / 254 % 256), byte(1 + i%254)})}}
	}
	return devs
}

func benchParse(b testing.TB, text string, devs []admission.Device) *Policy {
	b.Helper()
	b.Setenv("PORT49_KEY_LOAD", "not-a-real-key-0123456789")
	p, err := Parse([]byte(text), Env{Now: noon, Devices: devs})
	if err != nil {
		b.Fatal(err)
	}
	return p
}

// BenchmarkResolveFleet is every subject resolved on every device: one op is
// the 5 000 000 resolves a full bundle check makes.
func BenchmarkResolveFleet(b *testing.B) {
	devs := benchFleet(benchDevices)
	p := benchParse(b, benchPolicyText("**"), devs)
	var subjects []string
	for s := range benchPrincipals {
		subjects = append(subjects, fmt.Sprintf("svc_%02d", s))
	}
	for h := range benchHumans {
		subjects = append(subjects, fmt.Sprintf("human_%03d", h))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for _, s := range subjects {
			for _, d := range devs {
				if _, err := p.ResolveSubject(s, d, noon); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
}

// BenchmarkClassAgesFleet is ClassAges (Task 2) at the same size, which
// check-config runs once per platform.
func BenchmarkClassAgesFleet(b *testing.B) {
	p := benchParse(b, benchPolicyText("**"), benchFleet(benchDevices))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := p.ClassAges("arista_eos", 15*time.Minute, noon); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompareFleet is the review of one role edit against the fleet.
func BenchmarkCompareFleet(b *testing.B) {
	devs := benchFleet(benchDevices)
	before := benchParse(b, benchPolicyText("**"), devs)
	after := benchParse(b, benchPolicyText("show **"), devs)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if d := Compare(before, after, noon); len(d.Changes) == 0 {
			b.Fatal("a role edit that changes nothing")
		}
	}
}

// BenchmarkParseFleet is policy.Parse at the design's size: every daemon
// start, policy reload and inventory-only reload runs it (bundle.Parse is
// this plus the inventory's validation), and the broker runs it at its own
// reloads.
func BenchmarkParseFleet(b *testing.B) {
	text, devs := []byte(benchPolicyText("**")), benchFleet(benchDevices)
	b.Setenv("PORT49_KEY_LOAD", "not-a-real-key-0123456789")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Parse(text, Env{Now: noon, Devices: devs}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkContainsAtFleet is the containment and meet checks the projection
// makes (the plan 4 carry): every subject's grant rules against the roles'
// patterns, once per subject, as a fleet-wide projection asks.
func BenchmarkContainsAtFleet(b *testing.B) {
	permits := []string{"**", "show **", "show running-config", "show interfaces *"}
	probes := []string{"show version", "show interfaces ethernet1", "show users", "configure terminal", "show ip route *"}
	n := engine.Normalize{PipeToken: "|"}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for range benchPrincipals + benchHumans {
			for _, outer := range permits {
				for _, inner := range probes {
					if _, err := engine.Contains(outer, inner, nil); err != nil {
						b.Fatal(err)
					}
				}
				if _, err := engine.MayMeet(outer, "show users", nil, n); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
}

// variedFleet is the fleet the memo's classes are measured on: five
// platforms, one of them projected, in five sites with four roles and four
// versions, an incomparable version on 1 % of the devices and eight scopes —
// an lt version scope and a name: scope pinning ten devices among them. Humans
// hold all_devices and one site scope, machines two scopes, and a tenth of the
// grants expire in the future. mfaScope puts per_login_mfa on one scope.
func variedFleet(n int, mfaScope bool) (string, []admission.Device) {
	platforms := []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos", "f5_bigip"}
	sites, roles := []string{"dc1", "dc2", "edge", "campus", "lab"}, []string{"leaf", "spine", "fw", "core"}
	versions := []string{"21.4R3-S4", "21.4R3-S5", "22.2R1", "23.4R2"}
	devs := make([]admission.Device, n)
	for i := range devs {
		version := versions[(i/20)%len(versions)]
		if i%100 == 7 {
			version = "beta"
		}
		devs[i] = admission.Device{Name: fmt.Sprintf("load-%05d", i), Platform: platforms[i%len(platforms)],
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{127, byte(1 + i/254/256), byte(i / 254 % 256), byte(1 + i%254)})},
			Attributes: map[string]string{"site": sites[(i/5)%len(sites)], "role": roles[(i/25)%len(roles)],
				"os_version": version}}
	}
	var pins []string
	for i := range 10 {
		pins = append(pins, fmt.Sprintf("load-%05d", i*997%n))
	}
	var b strings.Builder
	b.WriteString("scopes:\n  - {name: all_devices, match: {}}\n")
	for _, s := range []string{"dc1", "dc2", "edge", "campus"} {
		mfa := ""
		if mfaScope && s == "dc1" {
			mfa = ", security_log: true, per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}"
		}
		fmt.Fprintf(&b, "  - {name: site_%s, match: {site: [%s]}, on_missing: include%s}\n", s, s, mfa)
	}
	fmt.Fprintf(&b, "  - {name: fabric, match: {site: [dc1, dc2], role: [leaf, spine]}, on_missing: exclude}\n"+
		"  - {name: unpatched, match: {os_version: {lt: \"21.4R3-S5\"}}, on_missing: include}\n"+
		"  - {name: pinned, match: {name: [%s]}, on_missing: exclude}\n", strings.Join(pins, ", "))
	b.WriteString("roles:\n  - {name: load_admin, privilege: admin, permit: [\"**\"]}\n" +
		"  - {name: load_read, privilege: readonly, permit: [\"show **\"]}\n" +
		"  - {name: load_site, privilege: readonly, permit: [\"show version\", \"show interfaces **\"]}\n" +
		"  - {name: load_denies, deny: [\"show users\"]}\nsubjects:\n")
	for p := range benchPrincipals {
		fmt.Fprintf(&b, "  - {name: svc_%02d, identity: [\"user:svc%02d@example.com\"], username: svc%02d, token_ttl: 900s}\n", p, p, p)
	}
	for h := range benchHumans {
		fmt.Fprintf(&b, "  - {name: human_%03d, identity: [\"user:human%03d@example.com\"], username: human%03d, token_ttl: 900s}\n", h, h, h)
	}
	b.WriteString("grants:\n")
	expires := func(i int) string {
		if i%10 == 0 {
			return fmt.Sprintf(", expires: 2026-%02d-15", 10+i/10%3)
		}
		return ""
	}
	for p := range benchPrincipals {
		fmt.Fprintf(&b, "  - {subject: svc_%02d, scope: all_devices, roles: [load_admin], max_privilege: admin%s}\n", p, expires(p))
		fmt.Fprintf(&b, "  - {subject: svc_%02d, scope: unpatched, roles: [load_denies], max_privilege: admin}\n", p)
	}
	for h := range benchHumans {
		fmt.Fprintf(&b, "  - {subject: human_%03d, scope: all_devices, roles: [load_read], max_privilege: readonly}\n", h)
		fmt.Fprintf(&b, "  - {subject: human_%03d, scope: site_%s, roles: [load_site], max_privilege: readonly%s}\n", h,
			[]string{"dc1", "dc2", "edge", "campus"}[h%4], expires(h))
	}
	b.WriteString("keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_KEY_LOAD}\nkey_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n")
	return b.String(), devs
}

// namedScopesFleet is the shape the class memo cannot help: every one of
// scoped devices is pinned by a scope of its own, so each is a class of one.
func namedScopesFleet(n, scoped int) (string, []admission.Device) {
	text, devs := variedFleet(n, false)
	var scopes, grants strings.Builder
	for i := range scoped {
		fmt.Fprintf(&scopes, "  - {name: only_%05d, match: {name: [load-%05d]}, on_missing: exclude}\n", i, i)
	}
	for p := range benchPrincipals {
		fmt.Fprintf(&grants, "  - {subject: svc_%02d, scope: only_%05d, roles: [load_read], max_privilege: admin}\n", p, p)
	}
	text = strings.Replace(text, "roles:\n", scopes.String()+"roles:\n", 1)
	text = strings.Replace(text, "keys:\n", grants.String()+"keys:\n", 1)
	return text, devs
}

func benchParseText(b *testing.B, text string, devs []admission.Device) {
	b.Helper()
	b.Setenv("PORT49_KEY_LOAD", "not-a-real-key-0123456789")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Parse([]byte(text), Env{Now: noon, Devices: devs}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseFleetVaried is Parse at the design's size over a fleet with a
// hundred classes of device (task 6b).
func BenchmarkParseFleetVaried(b *testing.B) {
	text, devs := variedFleet(benchDevices, false)
	benchParseText(b, text, devs)
}

// BenchmarkParseFleetNamedScopes is Parse where 1 000 devices are each pinned
// by a scope of their own: a class per device, which no memo shortens. The
// number is recorded in the operator notes (task 6b ruling 2).
func BenchmarkParseFleetNamedScopes(b *testing.B) {
	text, devs := namedScopesFleet(benchDevices, 1000)
	benchParseText(b, text, devs)
}

// BenchmarkMFARequirementsFleet is the per-device requirements the broker is
// handed at each swap, on the varied fleet with per_login_mfa on one scope.
func BenchmarkMFARequirementsFleet(b *testing.B) {
	text, devs := variedFleet(benchDevices, true)
	p := benchParse(b, text, devs)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if len(p.MFARequirements(noon)) == 0 {
			b.Fatal("a scope with per_login_mfa that no device is held to")
		}
	}
}
