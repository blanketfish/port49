package policy

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
)

func TestGenericDevicesAreAdmittedDevicesWithNoAdapter(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices,
		admission.Device{Name: "srl2", Platform: "nokia_srlinux",
			Addresses: []netip.Addr{netip.MustParseAddr("10.9.0.2")}},
		admission.Device{Name: "srl1", Platform: "nokia_srlinux",
			Addresses: []netip.Addr{netip.MustParseAddr("10.9.0.1")}},
		// No platform: unconfigured, not generic.
		admission.Device{Name: "blank",
			Addresses: []netip.Addr{netip.MustParseAddr("10.9.0.3")}},
		// No adapter, but no key group admits it: refused, not served.
		admission.Device{Name: "stray", Platform: "nokia_srlinux",
			Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	p, err := Parse([]byte(keyGrouped+keysFor("campus_key", "prod_key")), e)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range p.GenericDevices() {
		got = append(got, d.Name)
	}
	if want := []string{"srl1", "srl2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("GenericDevices = %v, want %v", got, want)
	}
}
