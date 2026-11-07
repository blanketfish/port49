//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/policy"
)

// assertPolicyAdmits loads text as port49d would and fails when it declares no
// keys: block, or when the inventory's refusals differ from want.
func assertPolicyAdmits(t *testing.T, name, text string, inv admission.Inventory, want []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path, policy.Env{Devices: inv.Devices, InventoryKeyGroups: inv.KeyGroups})
	if err != nil {
		t.Errorf("%s: the policy does not load: %v", name, err)
		return
	}
	if !p.KeysDeclared() {
		t.Errorf("%s: port49d refuses a policy with no keys: block (decision 53 ruling 3)", name)
	}
	var got []string
	for _, r := range p.AdmissionRefusals() {
		got = append(got, r.Device.Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: refused devices %v, want %v (%v)", name, got, want, refusedWhy(p))
	}
}

func refusedWhy(p *policy.Policy) []string {
	var out []string
	for _, r := range p.AdmissionRefusals() {
		out = append(out, r.Device.Name+": "+r.Refused)
	}
	return out
}

func labInventoryForUnit(t *testing.T) admission.Inventory {
	t.Helper()
	inv, err := admission.LoadFile("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// labRefusalsControl returns the refusals of slice/policy.yaml against the lab
// inventory, which passed the Task 26 regression: devices the inventory refuses
// on purpose are not a harness bug.
func labRefusalsControl(t *testing.T) []string {
	t.Helper()
	inv := labInventoryForUnit(t)
	raw, err := os.ReadFile(filepath.Join("slice", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path, policy.Env{Devices: inv.Devices, InventoryKeyGroups: inv.KeyGroups})
	if err != nil {
		t.Fatal(err)
	}
	if !p.KeysDeclared() {
		t.Fatal("the control policy slice/policy.yaml declares no keys: block")
	}
	var names []string
	for _, r := range p.AdmissionRefusals() {
		names = append(names, r.Device.Name)
	}
	return names
}

func TestL66PolicyDeclaresTheLabKey(t *testing.T) {
	inv := labInventoryForUnit(t)
	want := labRefusalsControl(t)
	n := 0
	for _, p := range platforms {
		if _, ok := l66Platforms[p.name]; !ok {
			continue
		}
		n++
		assertPolicyAdmits(t, "l66 "+p.name, l66Policy(p.node), inv, want)
	}
	if n == 0 {
		t.Fatal("no platform of l66Platforms is in platforms")
	}
}

func TestProjectionPolicyDeclaresTheLabKey(t *testing.T) {
	inv := labInventoryForUnit(t)
	want := labRefusalsControl(t)
	for _, s := range projectionShapes {
		assertPolicyAdmits(t, "1.1.0 "+s.name, projectionPolicy("1.1.0", s.roles), inv, want)
	}
	for _, s := range projectionShapes120 {
		assertPolicyAdmits(t, "1.2.0 "+s.name, projectionPolicy("1.2.0", s.roles), inv, want)
	}
	for _, s := range projectionShapes130 {
		assertPolicyAdmits(t, "1.3.0 "+s.name, projectionPolicy("1.3.0", s.roles), inv, want)
	}
}
