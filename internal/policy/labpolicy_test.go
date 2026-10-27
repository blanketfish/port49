package policy

import (
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
)

// The lab's policy is loaded by a daemon only inside `make lab`. Loading it here,
// against the lab's own inventory, means a typo in it — or a check it newly
// fails — fails `make test`, not a VM boot ten minutes in.
func TestTheLabPolicyLoads(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	inv, err := admission.LoadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load(filepath.Join(root, "tests", "lab", "slice", "policy.yaml"), Env{Devices: inv.Devices, InventoryKeyGroups: inv.KeyGroups})
	if err != nil {
		t.Fatal(err)
	}
	if q := p.Quarantines(noon); len(q) != 0 {
		t.Fatalf("the lab policy quarantines no lab device: %+v", q)
	}
	leaf := admission.Device{Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}}
	r, err := p.Resolve("user:alice@slice.port49.test", leaf, noon)
	if err != nil || r.Username != "slice01" || r.MaxPrivilege != 15 {
		t.Fatalf("%+v %v", r, err)
	}
	_, o, err := p.Decide("", "user:alice@slice.port49.test", leaf, "show hostname", noon)
	if err != nil || o.Permit || o.Deny == nil || o.Deny.Role != "slice_denies" {
		t.Fatalf("the slice's one denial: %+v %v", o, err)
	}
}
