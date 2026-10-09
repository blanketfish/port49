package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/platform"
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
// is printed as the device wrote it (spec §5.8). A finding from the set's own
// checks, which read method lists, echoes its line redacted; one from a
// block's check names the check by key and index and never echoes the line,
// since the patterns are best-effort and a block's check may match anything
// (task 15 review I4). A block's says is redacted, a missing line is, and the
// read error quotes nothing.
func TestCheckConfigNeverPrintsASecret(t *testing.T) {
	pol, inv := checkConfigFixture(t, `platforms:
  arista_eos:
    device_config: ["aaa authorization exec default group port49 local",
      "aaa authorization commands all default group port49 local", "snmp-server community Hunter2 rw"]
    config_checks:
      - {match: '^snmp-server community', says: "an snmp community"}
      - {match: '^tacacs-server key', says: 'tacacs-server key Hunter2 and "snmp-server community Hunter2 ro"'}
      - {match: 'Hunter2', says: "the value itself"}
`)
	cfg := filepath.Join(t.TempDir(), "leaf-01.cfg")
	config := "username noc privilege 1 secret 0 Hunter2\n" +
		"aaa authorization exec default group port49 local\n" +
		"aaa authorization commands all default group port49 local\n" +
		"snmp-server community Hunter2 ro\n" +
		"tacacs-server key Hunter2\n" +
		"tacacs-server host 10.9.9.9 key 7 Hunter2\n" +
		"copy scp://backup:Hunter2@10.9.9.9/cfg flash:\n" +
		"tacacs-server key=Hunter2\n" +
		"password:Hunter2\n" +
		"    community Hunter2 {\n" +
		"wpa-psk ascii 0 Hunter2\n" +
		"management api gnmi token Hunter2\n" +
		"radius-server shared-secret Hunter2\n" +
		"oauth client-secret Hunter2\n" +
		"aaa authentication enable default group port49 key=Hunter2 local\n"
	if err := os.WriteFile(cfg, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
	for _, want := range []string{
		"CONFIG: " + cfg + ":4: platforms.arista_eos.config_checks[0]: an snmp community\n",
		"CONFIG: " + cfg + ":5: platforms.arista_eos.config_checks[1]: tacacs-server key «redacted» ",
		"CONFIG: " + cfg + ":7: platforms.arista_eos.config_checks[2]: the value itself\n",
		"CONFIG: " + cfg + ":15: platforms.arista_eos.config_checks[2]: the value itself\n",
		"CONFIG: " + cfg + ":15: aaa authentication «redacted»",
		"MISSING: " + cfg + ": snmp-server community «redacted» «redacted»: ",
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

// A missing line a set ships prints as written, though abbreviation matching
// reads NX-OS's `aaa authentication login` as `authentication-key`: the
// operator is told which line the device lacks (task 15 review M4).
func TestCheckConfigPrintsAMissingSetLineAsWritten(t *testing.T) {
	pol, inv := checkConfigFixture(t, "")
	cfg := filepath.Join(t.TempDir(), "nx-01.cfg")
	if err := os.WriteFile(cfg, []byte("aaa authorization commands default group port49 local\n"+
		"aaa authorization config-commands default group port49 local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "nx-01", cfg}, &out, &errb)
	if code != 1 || !strings.Contains(out.String(), "MISSING: "+cfg+": aaa authentication login default group port49 local: ") ||
		strings.Contains(out.String(), platform.Redacted) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A platform whose adapter, as the daemon resolves it, holds nothing to read
// a configuration against — no local_accounts, no device_config, no
// config_checks, as the generic adapter an unknown platform gets — is never
// reported clean: the check exits 2 and says nothing was checked (final
// review I4).
func TestCheckConfigSaysNothingWasCheckedOnAPlatformItCannotRead(t *testing.T) {
	pol, inv := policyFixture(t)
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}
  - {name: fw-01, platform: fortinet_fortios, addresses: [10.0.0.2]}
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "fw-01.cfg")
	if err := os.WriteFile(cfg, []byte("username noc privilege 15 secret 5 x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "fw-01", cfg}, &out, &errb)
	if code != 2 || !strings.Contains(out.String()+errb.String(), "nothing checked: fortinet_fortios has no config checks") ||
		strings.Contains(out.String(), "0 findings") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	// Half an adapter checks half, and says which half it could not.
	raw := readFile(t, pol)
	block := "platforms:\n  fortinet_fortios:\n    config_checks: [{match: '^set admin-lockout', says: a test check}]\n"
	if err := os.WriteFile(pol, append([]byte(block), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	code = run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "fw-01", cfg}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "note: local-account collisions were not checked: the "+
		"fortinet_fortios adapter has no local_accounts") {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A MISSING line points where the operator can read it: a line the set holds
// the device to is in the set's adapter, not in `platform show --policy`,
// which prints a block's device_config without the set's floor (final review
// M7).
func TestCheckConfigPointsAMissingLineAtWhereItIsWritten(t *testing.T) {
	pol, inv := policyFixture(t)
	raw := readFile(t, pol)
	block := "platforms:\n  arista_eos:\n    device_config: [\"aaa authorization exec default group port49 local\", " +
		"\"aaa accounting commands all default start-stop group port49\"]\n"
	if err := os.WriteFile(pol, append([]byte(block), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "leaf-01.cfg")
	if err := os.WriteFile(cfg, []byte("aaa authorization exec default group port49 local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
	for _, want := range []string{
		"MISSING: " + cfg + ": aaa authorization commands all default group port49 local: ",
		"(spec §6; the platform set's line: port49 platform show --set 1.0.0 arista_eos)\n",
		"MISSING: " + cfg + ": aaa accounting commands all default start-stop group port49: ",
		"(spec §6; the policy's platforms: block's line: port49 platform show --policy " + pol + " --inventory " + inv +
			" arista_eos)\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
	}
}

// A partial capture, `show running-config | section aaa`, lacks every line
// outside the section, so a line the adapter requires may read as MISSING
// when the device carries it. A configuration with no hostname line is not
// a whole running-config, and the check says so beside the MISSING lines
// (task 17 review, parked).
func TestCheckConfigWarnsOnAPartialCapture(t *testing.T) {
	pol, inv := policyFixture(t)
	cfg := filepath.Join(t.TempDir(), "leaf-01.cfg")
	run1 := func(body string) string {
		t.Helper()
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
		return out.String()
	}
	const warning = "note: the configuration has no hostname line, so it may be a partial capture"
	if out := run1("aaa authorization exec default group port49 local\n"); !strings.Contains(out, "MISSING: ") ||
		!strings.Contains(out, warning) {
		t.Errorf("partial:\n%s", out)
	}
	if out := run1("hostname leaf-01\naaa authorization exec default group port49 local\n"); strings.Contains(out, warning) {
		t.Errorf("whole:\n%s", out)
	}
}

// --config goes with a projected platform alone: it is the template
// classes' idle-timeout, and a platform that projects nothing has none.
func TestCheckConfigTakesConfigOnlyOnAProjectedPlatform(t *testing.T) {
	pol, inv := policyFixture(t)
	dir := t.TempDir()
	cfg, daemon := filepath.Join(dir, "leaf-01.cfg"), filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(cfg, []byte("hostname leaf-01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(daemon, []byte("session: {max_session_age_default: 8h}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01",
		"--config", daemon, cfg}, &out, &errb); code != 2 {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}

// A subject whose username is its directory entry's, and a group subject,
// serve no username the check can compare: each is named in a note that says
// where the username comes from, never as an empty one.
func TestCheckConfigNamesSubjectsWhoseUsernameIsTheDirectorys(t *testing.T) {
	pol, inv := policyFixture(t)
	body := strings.Replace(string(readFile(t, pol)), "subjects:\n",
		"subjects:\n  - {name: oncall, group: NetOps-OnCall, token_ttl: 60s}\n"+
			"  - {name: oxidized, identity: \"spiffe://corp.example.com/host/oxidized-01\", token_ttl: 60s}\n", 1)
	body = strings.Replace(body, "grants:\n", "grants:\n  - {subject: oncall, scope: all_devices, roles: [read_only]}\n"+
		"  - {subject: oxidized, scope: all_devices, roles: [read_only]}\n", 1)
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "leaf-01.cfg")
	if err := os.WriteFile(cfg, []byte("aaa authorization exec default group port49 local\n"+
		"aaa authorization commands all default group port49 local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"devices", "check-config", "--policy", pol, "--inventory", inv, "--device", "leaf-01", cfg}, &out, &errb)
	for _, want := range []string{
		"note: subject oncall reaches leaf-01; its usernames come from its directory entries, so they are not checked\n",
		"note: subject oxidized reaches leaf-01; its usernames come from its directory entries, so they are not checked\n",
		"2 usernames served on leaf-01 (arista_eos), 0 findings\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s%s", want, out.String(), errb.String())
		}
	}
	if code != 0 || strings.Contains(out.String(), `""`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}
