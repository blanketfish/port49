package lab

import (
	"strings"
	"testing"
)

func TestDeviceDebugArmPlatformKeys(t *testing.T) {
	for fam, want := range map[string]string{"eos": "eos", "xr": "iosxr", "iosxe": "iosxe", "junos": "junos"} {
		if got, ok := ddArmPlatform(fam); !ok || got != want {
			t.Errorf("%s -> %q %v, want %q", fam, got, ok, want)
		}
		if _, ok := deviceDebugCmds[want]; !ok {
			t.Errorf("%s has no commands", want)
		}
	}
	if _, ok := ddArmPlatform("nxos"); ok {
		t.Error("nxos has its own arm")
	}
}

func TestDeviceDebugArmLineCount(t *testing.T) {
	if ddArmLineCount("") != 0 || ddArmLineCount("a") != 1 || ddArmLineCount("a\nb\nc") != 3 {
		t.Error("lines counted wrongly")
	}
}

func TestDeviceDebugArmSummaryStatesWhatItCannotOrder(t *testing.T) {
	s := ddArmSummary("junos", "tls_token_login", "", 12, []string{"conn port=1 syn=x hold=0.01s end=server-fin"})
	for _, want := range []string{"device returned 12 log lines", "kept 0", "tls connections (header-only capture): 1",
		"conn port=1", "connections that carried more than one request: 0 of 0", "do not order those"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
}

// The shape sample never carries a value: secret-word lines are dropped,
// long and hex runs, numbers and unusual words are masked.
func TestDeviceDebugArmSampleCarriesShapesNotValues(t *testing.T) {
	raw := strings.Join([]string{
		"Oct 22 05:00:11 tacacs: user alice07 from 172.100.100.31 session 1234567",
		"Oct 22 05:00:12 tacacs: password for bob is hunter2",
		"Oct 22 05:00:13 tacacs: Blob0123456789abcdef0123456789abcdef0123 seen",
		"Oct 22 05:00:14 tacacs: aVeryLongIdentifierName ok deadbeef",
		"payload(hex) 00112233",
		"Oct 22 05:00:15 tacacs: key is abcdef",
		"Oct 22 05:00:16 tacacs: cred zzz",
	}, "\n")
	got := strings.Join(ddArmSample(raw, 10), "\n")
	for _, never := range []string{"alice07", "172", "1234567", "hunter2", "password", "0123456789abcdef", "aVeryLong", "deadbeef", "payload", "bob", "abcdef", "zzz"} {
		if strings.Contains(got, never) {
			t.Errorf("the sample carries %q:\n%s", never, got)
		}
	}
	if !strings.Contains(got, "tacacs:") || !strings.Contains(got, "session N") {
		t.Errorf("the shape is gone:\n%s", got)
	}
	if n := len(ddArmSample(raw, 1)); n != 1 {
		t.Errorf("max not honoured: %d", n)
	}
}

func TestDeviceDebugArmWaitFollowsTheJunosModes(t *testing.T) {
	cfg := false
	step := func(cmd, want string, wantCfg bool) {
		t.Helper()
		var w []string
		w, cfg = ddArmWait("junos", cmd, cfg, "ignored")
		if len(w) != 1 || w[0] != want || cfg != wantCfg {
			t.Errorf("%q: waits for %q, config mode %v; want %q, %v", cmd, w, cfg, want, wantCfg)
		}
	}
	step("clear log p49-tacplus.log", "> ", false)
	step("configure", "# ", true)
	step("set system processes general-authentication-service traceoptions flag all", "# ", true)
	step("commit and-quit", "> ", false)
	step("show log p49-tacplus.log", "> ", false)
	if w, _ := ddArmWait("iosxe", "clear logging", false, "r1#"); len(w) != 2 || w[1] != "[confirm]" {
		t.Errorf("clear logging waits for %q", w)
	}
	if w, _ := ddArmWait("eos", "debug aaa", false, "eos1#"); len(w) != 1 || w[0] != "eos1#" {
		t.Errorf("debug aaa waits for %q", w)
	}
}
