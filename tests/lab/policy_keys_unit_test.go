//go:build lab

package lab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

// qualInventoryForUnit is inventory-lab.yaml as the qualify run sees it.
func qualInventoryForUnit(t *testing.T) admission.Inventory {
	t.Helper()
	raw, err := os.ReadFile("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text, err := qualInventory(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := admission.ParseFile([]byte(text), "inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestTheQualPolicyAdmitsTheLabInventory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "qual", "qual-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := labRefusalsControl(t)
	assertPolicyAdmits(t, "qual policy, rewritten inventory", string(raw), qualInventoryForUnit(t), want)

	// The control that must fail: the unrewritten inventory assigns lab_key,
	// which the qual policy does not declare. This is what Task 26 saw.
	inv := labInventoryForUnit(t)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path, policy.Env{Devices: inv.Devices, InventoryKeyGroups: inv.KeyGroups})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range p.AdmissionRefusals() {
		if r.Device.Name == "leaf1" && strings.Contains(r.Refused, "is assigned key_ref lab_key") {
			found = true
		}
	}
	if !found {
		t.Errorf("the unrewritten inventory should refuse leaf1 with %q, got %v", "is assigned key_ref lab_key", refusedWhy(p))
	}
}

func TestQualPolicyKeysMatchesTheQualPolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "qual", "qual-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), qualPolicyKeys) {
		t.Errorf("qualPolicyKeys %q is not a block of tests/qual/qual-policy.yaml", qualPolicyKeys)
	}
}

func TestL78PolicyDeclaresTheQualKey(t *testing.T) {
	inv := qualInventoryForUnit(t)
	want := labRefusalsControl(t)
	if len(l78Steps) == 0 {
		t.Fatal("no l78Steps")
	}
	for i, s := range l78Steps {
		assertPolicyAdmits(t, fmt.Sprintf("l78 step %d", i), l78Policy(s), inv, want)
	}
}

func TestQualInventoryRewritesExactlyOneKeyRef(t *testing.T) {
	if _, err := qualInventory("key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: other}\n"); err == nil {
		t.Error("an inventory with no lab_key line should be an error")
	}
	two := "key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: lab_key}\n  - {match: {cidr: 11.0.0.0/8}, key_ref: lab_key}\n"
	if _, err := qualInventory(two); err == nil || !strings.Contains(err.Error(), "2") {
		t.Errorf("two lab_key lines should be an error naming the count, got %v", err)
	}
	got, err := qualInventory("key_groups:\n  - {match: {cidr: 10.0.0.0/8}, key_ref: lab_key}\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "key_ref: k}") || strings.Contains(got, "lab_key") {
		t.Errorf("got %q", got)
	}
}

func TestL28StatusPolicyCarriesTheAcceptedKeys(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("l28", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := l28StatusPolicy(string(base), l28AcceptedKeys)
	assertPolicyAdmits(t, "l28 status policy", text, labInventoryForUnit(t), labRefusalsControl(t))
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	inv := labInventoryForUnit(t)
	p, err := policy.Load(path, policy.Env{Devices: inv.Devices, InventoryKeyGroups: inv.KeyGroups})
	if err != nil {
		t.Fatal(err)
	}
	set, ok := p.KeySets()["lab_key"]
	if !ok {
		t.Fatal("the status policy has no lab_key set")
	}
	if set.Current.Version != 2 {
		t.Errorf("lab_key current version %d, want 2", set.Current.Version)
	}
	if len(set.Accept) != 1 || set.Accept[0].Version != 1 {
		t.Errorf("lab_key accepts %+v, want version 1 only", set.Accept)
	}
}

func TestL28StatusArgsNameNoRemovedFlag(t *testing.T) {
	args := l28StatusArgs("port49", "p.yaml", "i.yaml", "log")
	// cmd/port49/policy.go:36 and keys.go:62 register --policy, --inventory and --since.
	known := map[string]bool{"--policy": true, "--inventory": true, "--since": true}
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			continue
		}
		if a == "--config" {
			t.Errorf("keys status no longer has --config (decision 53 ruling 3): %v", args)
		}
		if !known[a] {
			t.Errorf("%s is not a flag of port49 keys status: %v", a, args)
		}
	}
}

// The qualify run's private inventory is the lab inventory with its one
// key_ref rewritten to the qual policy's k, whatever device the run is on.
func TestQualPrivateInventoryAssignsEveryDeviceTheQualKey(t *testing.T) {
	priv := filepath.Join(t.TempDir(), "priv")
	pol, err := filepath.Abs(filepath.Join("..", "qual", "qual-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	invSrc, err := filepath.Abs("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := "# qual\n  policy_file: " + pol + "\ninventory_file: " + invSrc + "\n"
	if _, err := privatePolicy(cfg, priv); err != nil {
		t.Fatal(err)
	}
	if err := qualPrivateInventory(priv); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(priv, "inventory.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "key_ref: lab_key") || !strings.Contains(string(raw), "key_ref: k") {
		t.Errorf("the private inventory still assigns lab_key, or never assigns k")
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("private inventory mode: %v %v, want 0600", fi, err)
	}
	// And it is the inventory the qual policy admits.
	inv, err := admission.ParseFile(raw, "inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	praw, err := os.ReadFile(filepath.Join("..", "qual", "qual-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	assertPolicyAdmits(t, "qual policy, private inventory", string(praw), inv, labRefusalsControl(t))
}

// (*qualEnv).config is device-only, so the unit tests cannot call it; this
// holds its call to qualPrivateInventory, after privatePolicy has copied the
// inventory.
func TestQualConfigRewritesThePrivateInventory(t *testing.T) {
	b, err := os.ReadFile("qualify_test.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "func (q *qualEnv) config(")
	if i < 0 {
		t.Fatal("(*qualEnv).config not found")
	}
	body := s[i:]
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j]
	}
	p, r := strings.Index(body, "privatePolicy("), strings.Index(body, "qualPrivateInventory(priv)")
	if r < 0 || p < 0 || r < p {
		t.Errorf("config must call qualPrivateInventory(priv) after privatePolicy (positions %d, %d)", r, p)
	}
}

// projectionShape loads its policy through loadProjectionPolicy with the inventory's devices and key groups.
// Without the key groups no device matches one, and the first shape's resolve fails with "admission refuses the
// device" (vjunos, 2026-11-07).
func TestProjectionPolicyLoadedWithTheInventoryAdmitsTheLabNodes(t *testing.T) {
	inv := labInventoryForUnit(t)
	path := filepath.Join(t.TempDir(), "projection.yaml")
	roles := "  - {name: r, privilege: readonly, permit: [\"show **\"], deny: [\"show configuration **\"]}"
	if err := os.WriteFile(path, []byte(projectionPolicy("1.2.0", roles)), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := loadProjectionPolicy(path, inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"leaf1", "srx1", "vsrx1", "nx1", "xe1"} {
		device, ok := pol.Device(name)
		if !ok {
			t.Fatalf("%s is not in the inventory", name)
		}
		if _, err := pol.ResolveSubject("slice_operator", device, time.Now()); errors.Is(err, policy.ErrDeviceRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
