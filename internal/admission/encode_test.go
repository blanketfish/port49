package admission

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestAnEncodedFileReadsBackToTheSameDevices(t *testing.T) {
	inv := Inventory{Devices: []Device{
		{Name: "leaf-02", Platform: "arista_eos", Transport: TransportTCP,
			Addresses:  []netip.Addr{netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("10.0.0.2")},
			Attributes: map[string]string{"site": "dc1", "os_version": "4.31.2F", "flag": "true", "n": "42"}},
		{Name: "leaf-01", Platform: "eos-lab", Transport: TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		{Name: "tls-01", Platform: "arista_eos", Transport: TransportTLS},
	}}
	raw, err := EncodeFile(inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(raw), "leaf-01") > strings.Index(string(raw), "leaf-02") ||
		!strings.Contains(string(raw), "transport: tls") || strings.Contains(string(raw), "transport: tcp") {
		t.Fatalf("%s", raw)
	}
	back, err := ParseFile(raw, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	byName := map[string]Device{}
	for _, d := range back.Devices {
		byName[d.Name] = d
	}
	for _, d := range inv.Devices {
		got := byName[d.Name]
		want := d
		if len(want.Addresses) > 1 && want.Addresses[0].Compare(want.Addresses[1]) > 0 {
			want.Addresses = []netip.Addr{want.Addresses[1], want.Addresses[0]}
		}
		if got.Platform != want.Platform || got.Transport != want.Transport || !reflect.DeepEqual(got.Attributes, want.Attributes) ||
			len(got.Addresses) != len(want.Addresses) || (len(got.Addresses) > 0 && !reflect.DeepEqual(got.Addresses, want.Addresses)) {
			t.Errorf("%s: %+v, want %+v", d.Name, got, want)
		}
	}
	if _, err := EncodeFile(Inventory{KeyGroups: []KeyGroup{{Name: "leaf-01", KeyRef: "k"}}}); err == nil {
		t.Fatal("encoded key groups")
	}
}
