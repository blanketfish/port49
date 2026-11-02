package broker

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/policy"
)

// BenchmarkRefreshInventoryOnly is the 6a carry (plan 12c, Task 6): the
// per-context cost of an inventory-only Refresh, which reads one blob and
// decodes two per live context to find its answer unchanged (sameSource).
// Each op is one Refresh over 500 live contexts; the policy parse and the
// swap are outside the timer.
func BenchmarkRefreshInventoryOnly(b *testing.B) {
	const contexts = 500
	var devs []admission.Device
	for i := range contexts {
		devs = append(devs, admission.Device{Name: fmt.Sprintf("load-%05d", i), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("10.9.%d.%d", i/250, 1+i%250))}})
	}
	f := newFixtureWithDevices(b, 8, devs...)
	for _, d := range devs {
		f.login(b, alice, d.Name, "alice")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := range b.N {
		b.StopTimer()
		extra := admission.Device{Name: fmt.Sprintf("extra-%d", n), Platform: "arista_eos",
			Addresses: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("10.99.%d.%d", n/250, 1+n%250))}}
		pol, err := policy.Parse([]byte(testPolicy), policy.Env{Devices: append(f.b.Policy.Load().Devices(), extra),
			Now: f.b.Now(), Bundle: fmt.Sprintf("sha256:%064x", n+1)})
		if err != nil {
			b.Fatal(err)
		}
		priors := []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
		b.StartTimer()
		rep, err := f.b.Refresh(context.Background(), priors)
		b.StopTimer()
		if err != nil || rep.Updated != 0 || rep.Unchanged < contexts-5 {
			b.Fatalf("%+v, %v", rep, err)
		}
	}
}
