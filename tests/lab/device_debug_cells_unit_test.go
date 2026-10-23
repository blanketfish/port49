package lab

import (
	"regexp"
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

// The shape sample keeps no value character: after it, every run of two or
// more letters is a word of the fixed vocabulary, whatever the input held.
func TestDeviceDebugArmSampleKeepsNoValueCharacters(t *testing.T) {
	raw := strings.Join([]string{
		"tacacs server opened hunter2 for session",          // a short lowercase-and-digit value
		"tacacs message a1b2c3d4e5 from peer",               // letters and digits alternating
		"tacacs socket data de ad be ef 0f 1a 2b 3c closed", // space-separated hex bytes
		"tacacs connect user qual01 alice07 breakglass",     // lab usernames
		"tacacs connect host leaf3-xrd1 srx1 xe1 from 172.100.100.31/24",
		"tacacs secure value abc-def_ghi 0xdeadbe sunrise", // joined values, a short hex, a plain word
		"TAC+: Queuing AAA Accounting request 7 for processing",
		"password for bob is hunter2",
		"payload(hex) 00112233",
		"tacacs key is abcdef",
	}, "\n")
	got := ddArmSample(raw, 20)
	joined := strings.Join(got, "\n")
	for _, ln := range got {
		for _, w := range regexp.MustCompile(`[A-Za-z]{2,}`).FindAllString(ln, -1) {
			if !ddArmVocab[strings.ToLower(w)] {
				t.Errorf("a non-vocabulary run of letters survives: %q in %q", w, ln)
			}
		}
		if regexp.MustCompile(`[0-9]`).MatchString(ln) {
			t.Errorf("a digit survives: %q", ln)
		}
	}
	for _, never := range []string{"hunter", "alice", "qual", "breakglass", "leaf", "xrd", "srx", "172", "sunrise", "deadbe", "abc", "ghi", "bob", "payload", "abcdef"} {
		if strings.Contains(joined, never) {
			t.Errorf("the sample carries %q:\n%s", never, joined)
		}
	}
	for _, shape := range []string{"TAC+: Queuing AAA Accounting request N for processing", "from peer", "from A"} {
		if !strings.Contains(joined, shape) {
			t.Errorf("the shape %q is gone:\n%s", shape, joined)
		}
	}
	if n := len(ddArmSample(raw, 1)); n != 1 {
		t.Errorf("max not honoured: %d", n)
	}
}

func TestDeviceDebugArmCountLinesLeavesOutTheEchoAndThePrompt(t *testing.T) {
	out := "show logging\r\nline one\r\nline two\r\nxe1#"
	if n := ddArmCountLines(out, "show logging", "xe1#"); n != 2 {
		t.Errorf("counted %d, want 2", n)
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

func TestDeviceDebugArmMasterCaptureNeverTakesTheReVetName(t *testing.T) {
	if got := ddArmMasterName("Nexus-9300v-10.6-2-F", false); got != "QUAL-Nexus-9300v-10.6-2-F" {
		t.Errorf("an unarmed run names its master %q", got)
	}
	if got := ddArmMasterName("Nexus-9300v-10.6-2-F", true); got != "QUAL-DEBUG-Nexus-9300v-10.6-2-F" {
		t.Errorf("an armed run names its master %q", got)
	}
}
