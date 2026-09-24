package platform

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// The adapters read the lab's own device configurations the way the check
// does: each names its break-glass account, and each line the spec forbids is
// found where the lab carries it on purpose — the enable fallback L3 needs, and
// the Junos authentication order L4 measured falling through on a FAIL.
func TestTheAdaptersReadTheLabConfigs(t *testing.T) {
	for _, tt := range []struct {
		platform, file string
		accounts       []LocalAccount
		checks         []int
		says           string
	}{
		{"arista_eos", "eos-startup.cfg", []LocalAccount{{"breakglass", 16}}, []int{24}, "enable falls back to a local secret"},
		{"cisco_iosxe", "iosxe-startup.cfg", []LocalAccount{{"breakglass", 50}}, []int{91}, "enable falls back to a local secret"},
		{"cisco_nxos", "nxos-startup.cfg", []LocalAccount{{"breakglass", 34}}, nil, ""},
		{"juniper_junos", "vjunos-startup.conf", []LocalAccount{{"remote", 52}, {"breakglass", 56}}, []int{32},
			"falls through to the local password"},
	} {
		raw, err := os.ReadFile("../../tests/lab/configs/" + tt.file)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := DialectFor(tt.platform)
		accounts, findings, err := d.ReadConfig(raw)
		if err != nil || !reflect.DeepEqual(accounts, tt.accounts) {
			t.Errorf("%s accounts: %+v %v", tt.platform, accounts, err)
		}
		var lines []int
		for _, f := range findings {
			lines = append(lines, f.Line)
			if !strings.Contains(f.Says, tt.says) {
				t.Errorf("%s line %d: %q", tt.platform, f.Line, f.Says)
			}
		}
		if !reflect.DeepEqual(lines, tt.checks) {
			t.Errorf("%s checks on lines %v, want %v", tt.platform, lines, tt.checks)
		}
	}
}

// A command method list that falls back to none or if-authenticated is named
// on every per-command platform (spec §6, decision 23).
func TestAMethodListThatFallsBackToNoneIsNamed(t *testing.T) {
	for platformName, line := range map[string]string{
		"arista_eos":  "aaa authorization commands all default group port49 none",
		"cisco_iosxe": "aaa authorization commands 15 default group port49 if-authenticated",
		"cisco_nxos":  "aaa authorization config-commands default group port49 none",
	} {
		d, _ := DialectFor(platformName)
		if _, findings, _ := d.ReadConfig([]byte("hostname x\n" + line + "\n")); len(findings) != 1 ||
			findings[0].Line != 2 || !strings.Contains(findings[0].Says, "none or if-authenticated") {
			t.Errorf("%s: %+v", platformName, findings)
		}
	}
	eos, _ := DialectFor("arista_eos")
	if _, findings, _ := eos.ReadConfig([]byte("aaa authorization commands all default group port49 local\n")); len(findings) != 0 {
		t.Errorf("a list ending in local is what the spec asks for: %+v", findings)
	}
}

// A configuration the check could not read to the end is an error, never a
// clean result: a line past the scanner's limit — a banner, a certificate
// chain — would otherwise stop the read and pass whatever followed it.
func TestAConfigReadShortIsAnError(t *testing.T) {
	eos, _ := DialectFor("arista_eos")
	raw := "banner motd " + strings.Repeat("x", 2<<20) + "\naaa authorization commands all default group port49 none\n"
	if _, _, err := eos.ReadConfig([]byte(raw)); err == nil {
		t.Fatal("a line past the limit must fail the read")
	}
}

// A pattern with no capture group could not say which account it found.
func TestALocalAccountPatternCapturesTheName(t *testing.T) {
	d, _ := DialectFor("arista_eos")
	d.LocalAccounts = []string{`^username \S+`}
	if err := Validate("arista_eos", d); err == nil || !strings.Contains(err.Error(), "one capture group") {
		t.Fatalf("%v", err)
	}
	d.LocalAccounts, d.ConfigChecks = nil, []ConfigCheck{{Match: "x"}}
	if err := Validate("arista_eos", d); err == nil || !strings.Contains(err.Error(), "config_checks[0]") {
		t.Fatalf("%v", err)
	}
}

// A line the adapter's renderings depend on that the configuration does not
// carry is missing: IOS-XE's operator is level 7, and without its level-7
// command method list a level-7 command is never asked about (spec §6). The
// lab's configurations carry every line their adapter names.
func TestARequiredLineThatIsAbsentIsMissing(t *testing.T) {
	for platformName, file := range map[string]string{"arista_eos": "eos-startup.cfg", "cisco_iosxe": "iosxe-startup.cfg",
		"cisco_nxos": "nxos-startup.cfg", "juniper_junos": "vjunos-startup.conf"} {
		raw, err := os.ReadFile("../../tests/lab/configs/" + file)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := DialectFor(platformName)
		if missing, err := Missing(raw, d.DeviceConfig); err != nil || len(missing) != 0 {
			t.Errorf("%s: %q %v", platformName, missing, err)
		}
	}
	xe, _ := DialectFor("cisco_iosxe")
	raw, _ := os.ReadFile("../../tests/lab/configs/iosxe-startup.cfg")
	cut := strings.Replace(string(raw), "aaa authorization commands 7 default group port49 local\n", "", 1)
	missing, err := Missing([]byte(cut), xe.DeviceConfig)
	if err != nil || !reflect.DeepEqual(missing, []string{"aaa authorization commands 7 default group port49 local"}) {
		t.Fatalf("%q %v", missing, err)
	}
	// Runs of whitespace are one space; a line indented under another command,
	// or carrying more words, is not the line.
	required := []string{"aaa authorization commands 7 default group port49 local"}
	for config, want := range map[string]int{
		"aaa  authorization commands 7 default group port49 local  \n":   0,
		"aaa authorization commands 7 default group port49 local\r\n":    0,
		" aaa authorization commands 7 default group port49 local\n":     1,
		"aaa authorization commands 7 default group port49 local none\n": 1,
		"": 1,
	} {
		if missing, _ := Missing([]byte(config), required); len(missing) != want {
			t.Errorf("%q: missing %q", config, missing)
		}
	}
	if _, err := Missing([]byte("banner motd "+strings.Repeat("x", 2<<20)+"\n"), required); err == nil {
		t.Fatal("a line past the limit must fail the read")
	}
}

// The set's device_config, local_accounts and config_checks are the floor
// the check holds a device to: a block adds to them and never takes one away,
// so a block that rewrites `local` to `none`, or empties the checks, still has
// the set's line required and the set's checks run.
func TestTheSetsConfigIsTheFloor(t *testing.T) {
	ref, _ := DialectFor("arista_eos")
	d := ref.clone()
	d.DeviceConfig = []string{"aaa authorization exec default group port49 local",
		"aaa authorization commands all default group port49 none"}
	d.ConfigChecks, d.LocalAccounts = []ConfigCheck{}, []string{`^user (\S+)`}
	got := ConfigFloor(d, ref)
	if !reflect.DeepEqual(got.DeviceConfig, []string{"aaa authorization exec default group port49 local",
		"aaa authorization commands all default group port49 local",
		"aaa authorization commands all default group port49 none"}) {
		t.Errorf("device_config %q", got.DeviceConfig)
	}
	if !reflect.DeepEqual(got.ConfigChecks, ref.ConfigChecks) {
		t.Errorf("config_checks %+v", got.ConfigChecks)
	}
	if !reflect.DeepEqual(got.LocalAccounts, []string{`^username (\S+)`, `^user (\S+)`}) {
		t.Errorf("local_accounts %q", got.LocalAccounts)
	}
	if !reflect.DeepEqual(ConfigFloor(ref, ref), ref) || !reflect.DeepEqual(ref, shipped["arista_eos"]) {
		t.Fatal("the floor under the set's own adapter is that adapter, and it shares nothing")
	}
}

// A configuration line is printed redacted, save a line some set's adapter
// ships as device_config: that is lab text, never a secret, and the
// abbreviation matching that reads `authentication` as `authentication-key`
// would otherwise hide which line a device lacks.
func TestAConfigLineIsRedactedUnlessASetShipsIt(t *testing.T) {
	for line, want := range map[string]string{
		"aaa authentication login default group port49 local":         "aaa authentication login default group port49 local",
		"  aaa  authentication login default group port49 local ":     "aaa authentication login default group port49 local",
		"aaa authentication login default group port49 local Hunter2": "aaa authentication «redacted» «redacted» «redacted» «redacted» «redacted» «redacted»",
		"snmp-server community Hunter2 ro":                            "snmp-server community «redacted» «redacted»",
		"copy scp://u:Hunter2@h/x":                                    "copy scp://u:«redacted»@h/x",
	} {
		if got := RedactConfigLine(AllRedactions(), line); got != want {
			t.Errorf("%q: %q", line, got)
		}
	}
}
