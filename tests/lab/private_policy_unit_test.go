//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A broker config reads inventory_file behind the policy file's fence (plan
// 6a C2), so privatePolicy gives it a private copy beside the policy's: a
// checkout under umask 002 would otherwise refuse the start. The standing
// config, with no broker, keeps reading the repository's file.
func TestPrivatePolicyCopiesABrokerConfigsInventory(t *testing.T) {
	r, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer func(was string) { root = was }(root)
	root = r
	raw, err := os.ReadFile(filepath.Join(r, "tests", "lab", "port49d-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	standing := string(raw)

	dir := filepath.Join(t.TempDir(), "private")
	if got, err := privatePolicy(standing, dir); err != nil || got != standing {
		t.Fatalf("the standing config was changed: %v", err)
	}

	pol := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(pol, []byte("version: 1\n"), 0o664); err != nil {
		t.Fatal(err)
	}
	// A revocations file a previous run left, and its marker, would refuse
	// this run's mints or, the marker alone, its start (plan 7a, pre-flight
	// I6): neither outlives the derivation.
	rev := filepath.Join(dir, "revocations.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{rev, rev + ".created"} {
		if err := os.WriteFile(p, []byte("stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := privatePolicy(standing+"\nbroker:\n  policy_file: "+pol+"\n"+
		"  revocations_file: tests/lab/logs/revocations-slice.json\n", dir)
	if err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(dir, "inventory.yaml")
	if !strings.Contains(got, "\ninventory_file: "+inv+"\n") ||
		!strings.Contains(got, "\n  policy_file: "+filepath.Join(dir, "policy.yaml")+"\n") ||
		!strings.Contains(got, "\n  revocations_file: "+rev+"\n") {
		t.Fatalf("the lines were not pointed at the copies:\n%s", got)
	}
	for _, p := range []string{rev, rev + ".created"} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s outlived the derivation: %v", p, err)
		}
	}
	want, err := os.ReadFile(filepath.Join(r, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if copied, err := os.ReadFile(inv); err != nil || string(copied) != string(want) {
		t.Fatalf("the copy is not the repository's inventory: %v", err)
	}
	for path, perm := range map[string]os.FileMode{dir: 0o700, inv: 0o600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != perm {
			t.Errorf("%s is mode %v, want %v", path, fi.Mode().Perm(), perm)
		}
	}
}
