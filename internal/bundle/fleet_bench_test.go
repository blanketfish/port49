package bundle

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/policy"
)

// BenchmarkInventoryReloadFleet is port49d's inventory-only reload at the
// design's size (plan 12c, Task 6): Parse, Check and Diff, as inventoryBundle
// and the reload run them, over 500 subjects and 10 000 devices with one
// device moved. The policy in force is built outside the timer.
func BenchmarkInventoryReloadFleet(b *testing.B) {
	const principals, humans, devices = 50, 450, 10000
	var t strings.Builder
	t.WriteString("scopes:\n  - {name: all_devices, match: {}}\n  - {name: arista, match: {platform: arista_eos}, on_missing: include}\n" +
		"roles:\n  - {name: load_admin, privilege: admin, permit: [\"**\"]}\n  - {name: load_read, privilege: readonly, permit: [\"show **\"]}\n" +
		"  - {name: load_denies, deny: [\"show users\"]}\nsubjects:\n")
	for p := range principals {
		fmt.Fprintf(&t, "  - {name: svc_%02d, identity: [\"user:svc%02d@example.com\"], username: svc%02d, token_ttl: 900s}\n", p, p, p)
	}
	for h := range humans {
		fmt.Fprintf(&t, "  - {name: human_%03d, identity: [\"user:human%03d@example.com\"], username: human%03d, token_ttl: 900s}\n", h, h, h)
	}
	t.WriteString("grants:\n")
	for p := range principals {
		fmt.Fprintf(&t, "  - {subject: svc_%02d, scope: all_devices, roles: [load_admin], max_privilege: admin}\n", p)
		fmt.Fprintf(&t, "  - {subject: svc_%02d, scope: arista, roles: [load_denies], max_privilege: admin}\n", p)
	}
	for h := range humans {
		fmt.Fprintf(&t, "  - {subject: human_%03d, scope: all_devices, roles: [load_read], max_privilege: readonly}\n", h)
	}
	t.WriteString("keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_KEY_LOAD}\nkey_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n")
	raw := []byte(t.String())
	devs := make([]admission.Device, devices)
	for i := range devs {
		devs[i] = admission.Device{Name: fmt.Sprintf("load-%05d", i), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.AddrFrom4([4]byte{127, byte(1 + i/254/256), byte(i / 254 % 256), byte(1 + i%254)})}}
	}
	b.Setenv("PORT49_KEY_LOAD", "not-a-real-key-0123456789")
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	old, err := Parse(raw, admission.Inventory{Devices: devs}, policy.Env{Now: now})
	if err != nil {
		b.Fatal(err)
	}
	moved := append([]admission.Device(nil), devs...)
	moved[0].Addresses = []netip.Addr{netip.MustParseAddr("127.9.9.9")}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		pol, err := Parse(raw, admission.Inventory{Devices: moved}, policy.Env{Now: now})
		if err == nil {
			err = Check(old, pol, 10)
		}
		if err != nil {
			b.Fatal(err)
		}
		Diff(old, pol, now)
	}
}

const (
	editPrincipals = 50
	editHumans     = 450
)

// variedFleet is (copied from internal/policy, which keeps its generator private) the fleet the memo's classes are measured on: five
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
	for p := range editPrincipals {
		fmt.Fprintf(&b, "  - {name: svc_%02d, identity: [\"user:svc%02d@example.com\"], username: svc%02d, token_ttl: 900s}\n", p, p, p)
	}
	for h := range editHumans {
		fmt.Fprintf(&b, "  - {name: human_%03d, identity: [\"user:human%03d@example.com\"], username: human%03d, token_ttl: 900s}\n", h, h, h)
	}
	b.WriteString("grants:\n")
	expires := func(i int) string {
		if i%10 == 0 {
			return fmt.Sprintf(", expires: 2026-%02d-15", 10+i/10%3)
		}
		return ""
	}
	for p := range editPrincipals {
		fmt.Fprintf(&b, "  - {subject: svc_%02d, scope: all_devices, roles: [load_admin], max_privilege: admin%s}\n", p, expires(p))
		fmt.Fprintf(&b, "  - {subject: svc_%02d, scope: unpatched, roles: [load_denies], max_privilege: admin}\n", p)
	}
	for h := range editHumans {
		fmt.Fprintf(&b, "  - {subject: human_%03d, scope: all_devices, roles: [load_read], max_privilege: readonly}\n", h)
		fmt.Fprintf(&b, "  - {subject: human_%03d, scope: site_%s, roles: [load_site], max_privilege: readonly%s}\n", h,
			[]string{"dc1", "dc2", "edge", "campus"}[h%4], expires(h))
	}
	b.WriteString("keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_KEY_LOAD}\nkey_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n")
	return b.String(), devs
}

// BenchmarkPolicyEditLoad is the work port49d does for one policy edit at the
// design's size (plan 12c, Task 6b): the loadBoth sequence, in order, over the
// varied fleet and one role's rule changed. The policy in force is built
// outside the timer. Its bound is the 30 s settle.
func BenchmarkPolicyEditLoad(b *testing.B) {
	text, devs := variedFleet(10000, true)
	edited := strings.Replace(text, `{name: load_read, privilege: readonly, permit: ["show **"]}`,
		`{name: load_read, privilege: readonly, permit: ["show version", "show interfaces **"]}`, 1)
	if edited == text {
		b.Fatal("the edit changed nothing")
	}
	b.Setenv("PORT49_KEY_LOAD", "not-a-real-key-0123456789")
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	inv := admission.Inventory{Devices: devs}
	old, err := Parse([]byte(text), inv, policy.Env{Now: now})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		pol, err := Parse([]byte(edited), inv, policy.Env{Now: now})
		if err == nil {
			err = CheckFrom(old, pol, 10, "fix the file")
		}
		if err != nil {
			b.Fatal(err)
		}
		base, err := Parse(old.Raw(), inv, policy.Env{Now: now})
		if err != nil {
			b.Fatal(err)
		}
		if err := CheckAdmissionOver(old, base, pol, 10, now); err != nil {
			b.Fatal(err)
		}
		policy.NewMFADisjoint(base, pol)
		if len(pol.MFARequirements(now)) == 0 {
			b.Fatal("no device is held to per_login_mfa")
		}
		Diff(old, pol, now)
	}
}
