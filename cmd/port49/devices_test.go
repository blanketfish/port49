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
// reported beside it, as is each line the adapter depends on that the
// configuration lacks; any of them fails the check (plan 2b's owed
// configuration check). The break-glass account port49 does not serve is
// fine.
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
		"MISSING: " + cfg + ": aaa authorization exec default group port49 local: ",
		"MISSING: " + cfg + ": aaa authorization commands all default group port49 local: ",
		"2 local accounts, 2 usernames served on leaf-01 (arista_eos), 4 findings\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
	}
	if code != 1 || strings.Contains(out.String(), `"breakglass"`) {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	if err := os.WriteFile(cfg, []byte("username breakglass privilege 15 secret 0 x\n"+
		"aaa authorization exec default group port49 local\n"+
		"aaa authorization commands all default group port49 local\n"), 0o600); err != nil {
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

// checkConfigFixture is policyFixture with block laid in front of the policy
// as its platforms: key, and an IOS-XE, an NX-OS and a Junos device beside
// leaf-01.
func checkConfigFixture(t *testing.T, block string) (pol, inv string) {
	t.Helper()
	pol, inv = policyFixture(t)
	body, err := os.ReadFile(pol)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pol, append([]byte(block), body...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}
  - {name: xe-01, platform: cisco_iosxe, addresses: [10.0.0.2]}
  - {name: nx-01, platform: cisco_nxos, addresses: [10.0.0.3]}
  - {name: srx-01, platform: juniper_junos, addresses: [10.0.0.4]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	return pol, inv
}

// A line the adapter depends on that the configuration lacks fails the
// check: IOS-XE's operator is level 7, and without the level-7 command method
// list a level-7 command is never asked about (spec §6). No config_checks
// entry could see it, since it is the absence of a line.
func TestCheckConfigFindsAMissingRequiredLine(t *testing.T) {
	pol, inv := checkConfigFixture(t, "")
	raw, err := os.ReadFile("../../tests/lab/configs/iosxe-startup.cfg")
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "xe-01.cfg")
	cut := strings.Replace(string(raw), "aaa authorization commands 7 default group port49 local\n", "", 1)
	if err := os.WriteFile(cfg, []byte(cut), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "xe-01", cfg}, &out, &errb)
	want := "MISSING: " + cfg + ": aaa authorization commands 7 default group port49 local: "
	if code != 1 || !strings.Contains(out.String(), want) || strings.Count(out.String(), "MISSING: ") != 1 {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A platforms: block's device_config, config_checks and local_accounts add to
// the set's and never take from them (spec §8): a block that rewrites the set's
// `local` to `none` and empties the checks still has the set's line required,
// its own `none` line reported by the set's check, and the set's pattern
// finding the colliding account.
func TestCheckConfigHoldsTheSetsLinesUnderABlock(t *testing.T) {
	pol, inv := checkConfigFixture(t, `platforms:
  arista_eos:
    device_config: ["aaa authorization exec default group port49 local",
      "aaa authorization commands all default group port49 none"]
    config_checks: []
    local_accounts: []
`)
	cfg := filepath.Join(t.TempDir(), "leaf-01.cfg")
	if err := os.WriteFile(cfg, []byte("username noc privilege 1 secret 0 y\n"+
		"aaa authorization exec default group port49 local\n"+
		"aaa authorization commands all default group port49 none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
	for _, want := range []string{
		"MISSING: " + cfg + ": aaa authorization commands all default group port49 local: ",
		"CONFIG: " + cfg + ":3: aaa authorization commands all default group port49 none: the command method list falls back",
		`COLLISION: ` + cfg + `:1: a device-local account "noc"`,
		"3 findings\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
	}
	if code != 1 {
		t.Fatalf("code %d", code)
	}
}

// A device configuration is full of secrets, so no line check-config echoes
// is printed as the device wrote it: a finding's line, a missing line and the
// read error all pass through redaction (spec §5.8).
func TestCheckConfigNeverPrintsASecret(t *testing.T) {
	pol, inv := checkConfigFixture(t, `platforms:
  arista_eos:
    device_config: ["aaa authorization exec default group port49 local",
      "aaa authorization commands all default group port49 local", "snmp-server community Hunter2 rw"]
    config_checks:
      - {match: '^snmp-server community', says: "an snmp community"}
      - {match: '^tacacs-server key', says: "a tacacs key"}
      - {match: 'Hunter2', says: "the secret itself"}
`)
	cfg := filepath.Join(t.TempDir(), "leaf-01.cfg")
	config := "username noc privilege 1 secret 0 Hunter2\n" +
		"aaa authorization exec default group port49 local\n" +
		"aaa authorization commands all default group port49 local\n" +
		"snmp-server community Hunter2 ro\n" +
		"tacacs-server key Hunter2\n" +
		"tacacs-server host 10.9.9.9 key 7 Hunter2\n" +
		"copy scp://backup:Hunter2@10.9.9.9/cfg flash:\n"
	if err := os.WriteFile(cfg, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
	for _, want := range []string{
		"CONFIG: " + cfg + ":4: snmp-server community «redacted» «redacted»: an snmp community",
		"CONFIG: " + cfg + ":5: tacacs-server key «redacted»: a tacacs key",
		"MISSING: " + cfg + ": snmp-server community «redacted» «redacted»: ",
		"CONFIG: " + cfg + ":7: copy scp://backup:«redacted»@10.9.9.9/cfg flash:: the secret itself",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
	}
	if code != 1 || strings.Contains(out.String()+errb.String(), "Hunter2") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	long := "banner motd Hunter2 " + strings.Repeat("x", 2<<20) + " Hunter2\n" + config
	if err := os.WriteFile(cfg, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	code = run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "not read to the end") ||
		strings.Contains(out.String()+errb.String(), "Hunter2") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A device-local account collides with a served username in any form the
// daemon reads as that username: the daemon looks a context up by the
// canonical form of what the device sends — lower case, no DOMAIN\\ prefix,
// no @suffix (spec §2) — so a local NOC under a local fallback reaches the
// port49 noc's context. A quoted name, a tab, and Junos's protect: and
// inactive: prefixes are read too.
func TestCheckConfigFindsACollisionInAnyForm(t *testing.T) {
	pol, inv := checkConfigFixture(t, "")
	for device, tt := range map[string]struct {
		config string
		want   int
	}{
		"xe-01": {"username NOC privilege 1 secret 0 x\nusername Ops secret 0 x\nusername\tnoc@corp secret 0 x\n" +
			"username  \"ops\" secret 0 x\nusername CORP\\noc secret 0 x\nusername breakglass secret 0 x\n", 5},
		"srx-01": {"system {\n    login {\n        protect: user noc {\n            class super-user;\n        }\n" +
			"        user \"ops\" {\n        }\n        inactive: user NOC {\n        }\n        user breakglass {\n" +
			"        }\n    }\n}\nset system login user \"Ops\" class super-user\n", 4},
	} {
		cfg := filepath.Join(t.TempDir(), device+".cfg")
		if err := os.WriteFile(cfg, []byte(tt.config), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", device, cfg},
			&out, &errb)
		if n := strings.Count(out.String(), "COLLISION: "); code != 1 || n != tt.want ||
			strings.Contains(out.String(), `"breakglass"`) {
			t.Errorf("%s: code %d, %d collisions, want %d\n%s%s", device, code, n, tt.want, out.String(), errb.String())
		}
	}
}
