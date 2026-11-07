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
		"  revocations_file: tests/lab/logs/revocations-slice.json\n  certificate_status: {disabled: true}\n", dir)
	if err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(dir, "inventory.yaml")
	if !strings.Contains(got, "\ninventory_file: "+inv+"\n") ||
		!strings.Contains(got, "\n  policy_file: "+filepath.Join(dir, "policy.yaml")+"\n") ||
		!strings.Contains(got, "\n  revocations_file: "+rev+"\n  certificate_status: {disabled: true}\n") {
		t.Fatalf("the lines were not pointed at the copies:\n%s", got)
	}
	// The file is written empty on purpose, since port49d never creates it
	// (spec §13 decision 32, amended 2026-10-02); the marker is a start's to
	// write, so the derivation writes none.
	if got, err := os.ReadFile(rev); err != nil || string(got) != "{\"revocations\": []}\n" {
		t.Errorf("%s is not a fresh empty revocations file: %q %v", rev, got, err)
	}
	if _, err := os.Lstat(rev + ".created"); !os.IsNotExist(err) {
		t.Errorf("%s.created outlived the derivation: %v", rev, err)
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

// The broker's bind key, the keytab and krb5.conf are copied into the private directory for one test; the
// copies are removed when it ends, so key material does not outlive the run.
func TestPrivateSecretCopiesAreRemovedWhenTheTestEnds(t *testing.T) {
	src := filepath.Join(t.TempDir(), "secret-fixture.bin")
	if err := os.WriteFile(src, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cert, key, kt, krb string
	t.Run("copies", func(t *testing.T) {
		pki := &dirPKI{brokerCert: src, brokerKey: src}
		cert, key = pki.privateBroker(t)
		l := &labDir{keytabFile: src, krb5File: src}
		kt, krb = l.privateKerberos(t)
		for _, p := range []string{cert, key, kt, krb} {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("the copy %s is not there during the test: %v", p, err)
			}
		}
	})
	for _, p := range []string{cert, key, kt, krb} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("the private copy %s outlived its test (stat: %v)", p, err)
		}
	}
}
