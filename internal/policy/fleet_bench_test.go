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

func benchParse(b *testing.B, text string, devs []admission.Device) *Policy {
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

// BenchmarkInventoryOnlyRefresh is the broker's refresh when only the
// inventory changed (the plan 6a carry): the same policy text over an
// inventory with one device moved, compared with the one in force.
func BenchmarkInventoryOnlyRefresh(b *testing.B) {
	text := benchPolicyText("**")
	devs := benchFleet(benchDevices)
	before := benchParse(b, text, devs)
	moved := append([]admission.Device(nil), devs...)
	moved[0].Addresses = []netip.Addr{netip.MustParseAddr("127.9.9.9")}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		after := benchParse(b, text, moved)
		Compare(before, after, noon)
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
