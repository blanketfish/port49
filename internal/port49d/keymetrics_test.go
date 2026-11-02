package port49d

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/policy"
)

func TestSingleDeviceKeyRefsAreTheOnesHeldOnce(t *testing.T) {
	got := singleDeviceKeyRefs([]string{"core", "r1_pin", "core", ""})
	if len(got) != 1 || !got["r1_pin"] {
		t.Fatalf("got %v, want only r1_pin", got)
	}
}

// A policy pinning one device to its own key and two to core reports the pin
// as single-device and core as itself.
func TestAPinnedDeviceIsReportedAsSingleDevice(t *testing.T) {
	dev := func(name, addr, pin string) admission.Device {
		return admission.Device{Name: name, Platform: "arista_eos", KeyRef: pin, Transport: admission.TransportTCP,
			Addresses: []netip.Addr{netip.MustParseAddr(addr)}}
	}
	keys := "keys:\n"
	for _, r := range []string{"core", "r1_pin"} {
		keys += "  " + r + ":\n    current: {version: 1, secret_ref: env:PORT49_KEY_RUN}\n"
	}
	body := strings.Replace(minimalPolicy, runKeys, "", 1) +
		"key_groups:\n  - {match: {cidr: 0.0.0.0/0}, key_ref: core}\n" + keys
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: []admission.Device{
		dev("r1", "192.0.2.1", "r1_pin"), dev("a", "192.0.2.2", ""), dev("b", "192.0.2.3", "")}})
	if err != nil {
		t.Fatal(err)
	}
	got := policySingleDeviceKeyRefs(pol)
	if len(got) != 1 || !got["r1_pin"] {
		t.Fatalf("policy: got %v, want only r1_pin", got)
	}
	// With no policy: the admission index config.Load built.
	inv := admission.Inventory{Devices: []admission.Device{dev("r1", "192.0.2.1", "r1_pin"),
		dev("a", "192.0.2.2", "core"), dev("b", "192.0.2.3", "core")}}
	trie, err := admission.Build(inv)
	if err != nil {
		t.Fatal(err)
	}
	got = indexSingleDeviceKeyRefs(config.Config{Inventory: inv, Admission: trie})
	if len(got) != 1 || !got["r1_pin"] {
		t.Fatalf("index: got %v, want only r1_pin", got)
	}
}
