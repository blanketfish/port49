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
