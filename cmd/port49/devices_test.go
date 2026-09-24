package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A device-local account named as a username port49 serves on the device is
// the collision spec §5.6 forbids, and each line the adapter's checks name is
// reported beside it; either fails the check (plan 2b's owed configuration
// check). The break-glass account port49 does not serve is fine.
func TestCheckConfigFindsACollisionAndAForbiddenLine(t *testing.T) {
	pol, inv := policyFixture(t)
	cfg := filepath.Join(t.TempDir(), "leaf-01.cfg")
	if err := os.WriteFile(cfg, []byte("hostname leaf-01\n"+
		"username breakglass privilege 15 role network-admin secret 0 x\n"+
		"username noc privilege 1 secret 0 y\n"+
		"aaa authorization commands all default group port49 none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
	for _, want := range []string{
		`COLLISION: ` + cfg + `:3: a device-local account "noc" is the username port49 serves subject noc on leaf-01`,
		`CONFIG: ` + cfg + `:4: aaa authorization commands all default group port49 none: the command method list falls back`,
		"2 local accounts, 2 usernames served on leaf-01 (arista_eos), 2 findings\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
	}
	if code != 1 || strings.Contains(out.String(), `"breakglass"`) {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	if err := os.WriteFile(cfg, []byte("username breakglass privilege 15 secret 0 x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg},
		&out, &errb); code != 0 {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	for _, args := range [][]string{{"devices", "check-config", "--policy", pol, "--inventory", inv, cfg},
		{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01"}, {"devices"}} {
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%q: code %d", args, code)
		}
	}
}
