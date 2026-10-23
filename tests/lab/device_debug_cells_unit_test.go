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

// wantVocab is the vocabulary as the test knows it: a separate, hard-coded
// list, so a word added to ddArmWords makes this test fail until it is reviewed.
const wantVocab = `tac tacacs tplus connect connected connection socket server opened open closed close secure message
	type request reply send sent receive received queued queuing processed processing created start started timeout
	tls ssl tcp session author authorization authentication accounting group list method status error failed fail
	established peer port host address bind bound immediate new not the and for are has was with from using
	previously default handle name addr timer expired unavailable available detected thread sleeping seconds debug
	auth login packet create destroy free alloc state transaction transactions cmd arg service shell exec`

func TestDeviceDebugArmVocabularyIsClosed(t *testing.T) {
	want := map[string]bool{}
	for _, w := range strings.Fields(wantVocab) {
		want[w] = true
	}
	for w := range ddArmVocab {
		if !want[w] {
			t.Errorf("vocabulary word %q is not in the test's list", w)
		}
	}
	for w := range want {
		if !ddArmVocab[w] {
			t.Errorf("test's word %q is not in the vocabulary", w)
		}
		if !regexp.MustCompile(`^[a-z]{3,}$`).MatchString(w) {
			t.Errorf("%q is not three or more lowercase ASCII letters", w)
		}
		if regexp.MustCompile(`^[0-9a-f]+$`).MatchString(w) {
			t.Errorf("%q could be a hex value", w)
		}
	}
}

// Each input becomes exactly the expected tokens: no character of a value
// survives, whatever it is made of.
func TestDeviceDebugArmTokensAreAClosedAlphabet(t *testing.T) {
	for in, want := range map[string]string{
		"TAC+: Opened TCP/IP handle 0x1F to 10.149.0.2/49":   "tac _ opened tcp _ handle _ A _",
		"tacacs server opened hunter2 for session":           "tacacs server opened _ for session",
		"tacacs message a1b2c3d4e5 from peer":                "tacacs message _ from peer",
		"tacacs socket data de ad be ef 0f 1a closed":        "tacacs socket _ closed",
		"server Tr0ub4dor&3!# closed":                        "server _ closed",
		"server dGVzdA==/Zm9v+YmFy= closed":                  "server _ closed",
		"server \u043f\u0430\u0440\u043e\u043b\u044c closed": "server _ closed",
		"server \uff11\uff12\uff13 closed":                   "server _ closed",
		"server \x01\x9f\xfe\x10 closed":                     "server _ closed",
		"server xx-server-yy closed":                         "server _ server _ closed",
		"peer 2001:db8::1 closed":                            "peer A closed",
		"peer fe80::abcd closed":                             "peer A closed",
		"peer ::ffff:10.1.2.3 closed":                        "peer A closed",
		"02:35:11.079 server closed":                         "_ server closed",
		"SERVER Opened":                                      "server opened",
		"server fd closed":                                   "server _ closed",
		"open1 server xopen server":                          "_ server _ server",
		"server user alice07 qual01 breakglass leaf3 closed": "server _ closed",
		"  \t ": "",
	} {
		got := ddArmTokens(in)
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
		if !regexp.MustCompile(`^[a-zA_ ]*$`).MatchString(got) {
			t.Errorf("%q: the output holds a character outside [a-z A _ space]: %q", in, got)
		}
	}
}

// A line with a secret word produces no sample line at all, and the others
// come back in the closed alphabet, hot lines first.
func TestDeviceDebugArmSampleDropsSecretWordLinesAndKeepsTheRest(t *testing.T) {
	raw := strings.Join([]string{
		"password for bob is hunter2",
		"payload(hex) 00112233",
		"tacacs key is abcdef",
		"cred zzz token yyy",
		"noise line one",
		"tacacs server opened",
		"tacacs server opened",
	}, "\n")
	got := ddArmSample(raw, 10)
	if len(got) != 2 || got[0] != "tacacs server opened" || got[1] != "_" {
		t.Errorf("sample = %q", got)
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
