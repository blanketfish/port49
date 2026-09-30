package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/keyfile"
)

const diffPolicy = `
scopes:
  - {name: all_devices, match: {}}
  - {name: campus, match: {site: campus}, security_log: true}
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: s, scope: campus, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]
`

// Spec §10, §12: the review artifact for an inventory change, the security
// lines marked, and an exit that says whether port49d would take it.
func TestInventoryDiff(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pol := write("policy.yaml", diffPolicy)
	old := write("old.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1], attributes: {site: dc1}}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n")
	new := write("new.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1, 10.66.0.1], attributes: {site: campus}}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, old, new}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"+0 device(s), -0, 1 changed", "! address added leaf-01: 10.66.0.1",
		"! scope campus (security_log): leaf-01 joined"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	half := write("half.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n")
	out.Reset()
	if code := run([]string{"inventory", "diff", "--policy", pol, old, half}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "refused: the new inventory removes 1 of 2 devices") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}

// diffFiles writes the policy and the old inventory of the tests below.
func diffFiles(t *testing.T) (dir, pol, old string, write func(name, body string) string) {
	t.Helper()
	dir = t.TempDir()
	write = func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pol = write("policy.yaml", diffPolicy)
	old = write("old.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n")
	return dir, pol, old, write
}

// Every security change is marked as port49d writes it an inventory_change
// record: an admitted device added, and a key_ref moved by a pin.
func TestInventoryDiffMarksEverySecurityChange(t *testing.T) {
	_, pol, old, write := diffFiles(t)
	new := write("new.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2], key_ref: lab_key}\n"+
		"  - {name: leaf-03, platform: arista_eos, addresses: [10.0.1.3]}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, old, new}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"! device added leaf-03 (arista_eos) at 10.0.1.3: admitted",
		"! key_ref_changed leaf-02: prod_key → lab_key", "ok: port49d would take the new inventory"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

// With --config the key_refs and the bound are port49d.yaml's, as port49d
// reads them: a pin to a key the file does not define refuses the device, and
// that counts against inventory.max_removed_percent.
func TestInventoryDiffReadsTheConfigAsPort49dDoes(t *testing.T) {
	_, pol, old, write := diffFiles(t)
	new := write("new.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2], key_ref: lab_key}\n")
	cfg := write("port49d.yaml", "keys:\n  prod_key: {current: {version: 1, secret_env: NEVER_READ}}\n"+
		"inventory: {max_removed_percent: 50}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, "--config", cfg, old, new}, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "admission_changed leaf-02: admitted → refused") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	cfg10 := write("port49d-10.yaml", "keys:\n  prod_key: {current: {version: 1, secret_env: NEVER_READ}}\n")
	out.Reset()
	if code := run([]string{"inventory", "diff", "--policy", pol, "--config", cfg10, old, new}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "refused: the new inventory removes 0 of 2 devices and refuses 1 more") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"inventory", "diff", "--policy", pol, "--config", cfg, "--max-removed-percent", "20", old, new},
		&out, &errOut); code != 2 {
		t.Fatalf("--config with --max-removed-percent: exit %d, want 2: %s", code, errOut.String())
	}
}

// An inventory that admits no device is refused whatever the bound, as
// port49d refuses it (spec §10).
func TestInventoryDiffRefusesAnInventoryThatAdmitsNone(t *testing.T) {
	_, pol, old, write := diffFiles(t)
	none := write("none.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [192.0.2.1]}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [192.0.2.2]}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, "--max-removed-percent", "100", old, none},
		&out, &errOut); code != 1 || !strings.Contains(out.String(), "refused: the new inventory admits none of the 2 device(s)") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
}

// The same devices respelled are no swap, as port49d says.
func TestInventoryDiffOfTheSameInventory(t *testing.T) {
	_, pol, old, write := diffFiles(t)
	same := write("same.yaml", "devices:\n  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n"+
		"  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, old, same}, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "unchanged: the same inventory, respelled") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
}

// Moving key_groups from the inventory to the policy is taken with the policy
// reloaded first; the other way round the inventory is refused until the
// policy lands (plan 6a, C3), and port49d takes both in the end.
func TestInventoryDiffWithANewPolicySaysTheOrder(t *testing.T) {
	_, _, _, write := diffFiles(t)
	bare := strings.Replace(diffPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n", "", 1)
	oldPol := write("old-policy.yaml", bare)
	newPol := write("new-policy.yaml", diffPolicy)
	devices := "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n" +
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n"
	old := write("old.yaml", devices+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n")
	new := write("new.yaml", devices)
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", oldPol, "--new-policy", newPol, old, new}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"policy file first: taken",
		"inventory file first: the inventory reload is refused: the new inventory admits none of the 2 device(s)",
		"ok: port49d would take both"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	// The key groups deleted from both files: one policy, so one reload.
	out.Reset()
	if code := run([]string{"inventory", "diff", "--policy", oldPol, "--new-policy", oldPol, old, new}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "refused: the new inventory admits none of the 2 device(s)") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	// The new policy deletes the key groups too: the policy reload is taken
	// (the inventory in force still has them), and the inventory's after it
	// is refused, so port49d stays on the bundle between.
	out.Reset()
	if code := run([]string{"inventory", "diff", "--policy", oldPol, "--new-policy", write("bare2.yaml", bare+"\n"), old, new},
		&out, &errOut); code != 1 || !strings.Contains(out.String(), "refused: if the policy file lands first, port49d "+
		"takes it, then refuses the inventory file (the new inventory admits none") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
}

// Neither order: each file's reload is refused against the other in force,
// so whichever lands first swaps nothing, and so does the other.
func TestInventoryDiffWithANewPolicyInNeitherOrder(t *testing.T) {
	_, _, _, write := diffFiles(t)
	groups := func(cidr string) string {
		return strings.Replace(diffPolicy, "cidr: 10.0.0.0/8", "cidr: "+cidr, 1)
	}
	oldPol, newPol := write("old-policy.yaml", groups("172.16.0.0/12")), write("new-policy.yaml", groups("10.9.0.0/16"))
	old := write("old.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [172.16.0.1]}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [172.16.0.2]}\n")
	new := write("new.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.9.0.1]}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.9.0.2]}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", oldPol, "--new-policy", newPol, old, new}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "refused: port49d would take both files in neither order") ||
		strings.Contains(out.String(), "stays on that bundle") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
}

// The reviewer's case (I1): the new policy narrows key_groups, and the new
// inventory adds devices outside the narrowed range. Inventory first, the
// inventory reload is taken and the policy's after it refused, so port49d
// stays half-applied: the diff fails, and says so, not "refused until".
func TestInventoryDiffFailsAChangePort49dWouldHalfTake(t *testing.T) {
	_, _, _, write := diffFiles(t)
	oldPol := write("old-policy.yaml", diffPolicy)
	newPol := write("new-policy.yaml", strings.Replace(diffPolicy, "cidr: 10.0.0.0/8", "cidr: 10.0.1.0/24", 1))
	var oldBody, added strings.Builder
	oldBody.WriteString("devices:\n")
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&oldBody, "  - {name: leaf-%02d, platform: arista_eos, addresses: [10.0.1.%d]}\n", i, i)
	}
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(&added, "  - {name: n%d, platform: arista_eos, addresses: [10.0.2.%d]}\n", i, i)
	}
	old := write("old.yaml", oldBody.String())
	new := write("new.yaml", oldBody.String()+added.String())
	var out, errOut bytes.Buffer
	code := run([]string{"inventory", "diff", "--policy", oldPol, "--new-policy", newPol, old, new}, &out, &errOut)
	got := out.String()
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s%s", code, got, errOut.String())
	}
	for _, want := range []string{"policy file first: taken", "! device added n1 (arista_eos) at 10.0.2.1: admitted",
		"refused: if the inventory file lands first, port49d takes it, then refuses the policy file (the new policy " +
			"refuses admission to 5 of 15 devices",
		"and stays on that bundle until the inventory file changes again"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "ok:") || strings.Contains(got, "refused until") {
		t.Errorf("a half-take is reported as converging:\n%s", got)
	}
}

// Without --config every verdict says the key_refs went unchecked (I2): a pin
// to a key port49d.yaml does not define reads as admitted here and is refused
// there. With --config it is not said.
func TestInventoryDiffSaysTheKeyRefsWentUnchecked(t *testing.T) {
	_, pol, old, write := diffFiles(t)
	new := write("new.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2], key_ref: lab_key}\n")
	const note = "key_refs not checked against port49d.yaml: pass --config to check them"
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, old, new}, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "ok: port49d would take the new inventory (inventory.max_removed_percent 10%); "+note) {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	half := write("half.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n")
	out.Reset()
	if code := run([]string{"inventory", "diff", "--policy", pol, old, half}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), note) {
		t.Fatalf("a refused verdict must say it too: exit %d: %s", code, out.String())
	}
	cfg := write("port49d.yaml", "keys:\n  prod_key: {current: {version: 1, secret_env: NEVER_READ}}\n"+
		"  lab_key: {current: {version: 1, secret_env: NEVER_READ}}\n")
	out.Reset()
	if code := run([]string{"inventory", "diff", "--policy", pol, "--config", cfg, old, new}, &out, &errOut); code != 0 ||
		strings.Contains(out.String(), note) {
		t.Fatalf("with --config: exit %d: %s", code, out.String())
	}
}

// A secret pasted into the inventory is never printed: a decode error is its
// line and a category, a bad address or a bad pin is named by where it is.
func TestInventoryDiffNeverPrintsASecret(t *testing.T) {
	_, pol, old, write := diffFiles(t)
	const secret = "Sx9qT4vWz7Kp"
	for name, body := range map[string]string{
		"type":    "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1], key_ref: [" + secret + "]}\n",
		"address": "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [" + secret + "]}\n",
		"cidr": "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n" +
			"key_groups: [{match: {cidr: " + secret + "}, key_ref: lab_key}]\n",
		"pin": "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n" +
			"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2], key_ref: " + secret + "}\n",
	} {
		t.Run(name, func(t *testing.T) {
			new := write(name+".yaml", body)
			var out, errOut bytes.Buffer
			code := run([]string{"inventory", "diff", "--policy", pol, old, new}, &out, &errOut)
			all := out.String() + errOut.String()
			if code != 1 {
				t.Errorf("exit %d, want 1:\n%s", code, all)
			}
			for i := 0; i+6 <= len(secret); i++ {
				if w := secret[i : i+6]; strings.Contains(all, w) || strings.Contains(strings.ToLower(all), strings.ToLower(w)) {
					t.Fatalf("the output echoes %q:\n%s", w, all)
				}
			}
			if name == "type" && !strings.Contains(all, "line 2: a value of the wrong type") {
				t.Errorf("the decode error does not name its line and category:\n%s", all)
			}
		})
	}
}

// Without --config, a bundle with key groups in neither file admits only
// pinned devices, as port49d reads it and `policy test` judges it: one that
// pins none is refused whatever the bound.
func TestInventoryDiffRefusesTheKeyGroupsDeletedWithoutConfig(t *testing.T) {
	_, _, _, write := diffFiles(t)
	pol := write("bare.yaml", strings.Replace(diffPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n", "", 1))
	devices := "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n" +
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n"
	old := write("old.yaml", devices+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n")
	new := write("new.yaml", devices)
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, "--max-removed-percent", "100", old, new},
		&out, &errOut); code != 1 || !strings.Contains(out.String(), "refused: the new inventory admits none of the 2 device(s)") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	// One device pinned is admitted: not admit-none, and at 100 the bound is off.
	pinned := write("pinned.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1], key_ref: prod_key}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n")
	out.Reset()
	if code := run([]string{"inventory", "diff", "--policy", pol, "--max-removed-percent", "100", old, pinned},
		&out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
}

// Under --new-policy each reload's changes are shown as port49d logs that
// swap: a device the inventory moves into a security_log scope that the new
// policy then narrows away from it joins and leaves, two records, though the
// two ends of the change show no membership change at all.
func TestInventoryDiffMarksEachReloadStep(t *testing.T) {
	_, pol, _, write := diffFiles(t)
	narrowed := write("narrowed.yaml", strings.Replace(diffPolicy, "match: {site: campus}", "match: {site: other}", 1))
	old := write("old.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1], attributes: {site: dc1}}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n")
	new := write("new.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1], attributes: {site: campus}}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, "--new-policy", narrowed, old, new}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	got := out.String()
	inv := strings.Index(got, "inventory file first:\n")
	if inv < 0 {
		t.Fatalf("no inventory-first heading:\n%s", got)
	}
	policyFirst, inventoryFirst := got[:inv], got[inv:]
	if strings.Contains(policyFirst, "scope campus") {
		t.Errorf("policy first, leaf-01 never enters campus:\n%s", got)
	}
	join := strings.Index(inventoryFirst, "! scope campus (security_log): leaf-01 joined")
	polStep := strings.Index(inventoryFirst, "the policy reload: ")
	leave := strings.Index(inventoryFirst, "! scope campus (security_log): leaf-01 left")
	if join < 0 || polStep < 0 || leave < 0 || !(join < polStep && polStep < leave) {
		t.Errorf("inventory first, leaf-01 joins in the inventory reload and leaves in the policy reload:\n%s", got)
	}
	if !strings.Contains(got, "ok: port49d would take both, in either order") {
		t.Errorf("missing the verdict:\n%s", got)
	}
}

func TestInventoryKeygenWritesAPairOnceAndNamesIt(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "keygen", "--dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	fi, err := os.Stat(filepath.Join(dir, "signing.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("signing.key: %v %v", fi, err)
	}
	priv, err := keyfile.LoadEd25519(filepath.Join(dir, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := os.ReadFile(filepath.Join(dir, "signing.pub"))
	pub, err := keyfile.ParseEd25519Public(pubPEM, "signing.pub")
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("signing.pub: %v", err)
	}
	if !strings.Contains(out.String(), keyfile.Ed25519KeyID(pub)) {
		t.Fatalf("the key id is not printed: %s", out.String())
	}
	// Never over an existing key: that would strand every port49d verifying
	// against the old public half.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"inventory", "keygen", "--dir", dir}, &out, &errOut); code != 1 ||
		!strings.Contains(errOut.String(), "already exists") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	// One file present: refused before either is written, so no lone new
	// private key is left beside an old public one (conflict scan F14).
	lone := t.TempDir()
	os.WriteFile(filepath.Join(lone, "signing.pub"), []byte("old"), 0o644)
	errOut.Reset()
	if code := run([]string{"inventory", "keygen", "--dir", lone}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(lone, "signing.key")); err == nil {
		t.Fatal("a lone signing.key was left")
	}
}
