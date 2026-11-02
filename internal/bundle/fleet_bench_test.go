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
