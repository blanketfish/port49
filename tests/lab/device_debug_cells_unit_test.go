package lab

import (
	"regexp"
	"slices"
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
	auth login packet create destroy free alloc state transaction transactions cmd arg service shell exec
	tacacsd tacplus authd invalid syntax`

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

// The 160-character cut lands on a token boundary: a partial last token such
// as "authentica" is dropped, not listed.
func TestDeviceDebugArmSampleCutsOnATokenBoundary(t *testing.T) {
	line := strings.Repeat("tacacs ", 22) + "authentication" // 7*22 = 154, then "authentica" would straddle 160
	got := ddArmSample(line, 5)
	if len(got) != 1 {
		t.Fatalf("sample = %q", got)
	}
	if len(got[0]) > 160 {
		t.Errorf("longer than 160: %d", len(got[0]))
	}
	if strings.HasSuffix(got[0], "authentica") || strings.Contains(got[0], "authentic") {
		t.Errorf("a partial token was kept: %q", got[0])
	}
	if got[0] != strings.TrimSpace(strings.Repeat("tacacs ", 22)) {
		t.Errorf("sample = %q", got[0])
	}
}

// Hot or cold is decided on the sampled output, not the raw line: a hot word
// that only appears in a span the closed alphabet replaces with _ makes the
// line cold.
func TestDeviceDebugArmSampleOrdersOnTheSampledOutput(t *testing.T) {
	raw := strings.Join([]string{
		"interface Serverfarm1 up", // "Serverfarm1" is one unknown run: no hot word survives
		"tacacs server opened",
	}, "\n")
	got := ddArmSample(raw, 10)
	if len(got) != 2 || got[0] != "tacacs server opened" {
		t.Errorf("hot line not first: %q", got)
	}
}

func TestDeviceDebugArmWaitFollowsTheEOSConfigMode(t *testing.T) {
	cfg := false
	step := func(cmd, want string, wantCfg bool) {
		t.Helper()
		var w []string
		w, cfg = ddArmWait("eos", cmd, cfg, "eos1#")
		if len(w) != 1 || w[0] != want || cfg != wantCfg {
			t.Errorf("%q: waits for %q, config mode %v; want %q, %v", cmd, w, cfg, want, wantCfg)
		}
	}
	step("terminal length 0", "eos1#", false)
	step("configure", ")#", true)
	step("trace Aaa setting *", ")#", true)
	step("end", "eos1#", false)
	step("show agent Aaa logs", "eos1#", false)
}

func TestDeviceDebugArmIsCollectNamesOnlyTheCollectCommands(t *testing.T) {
	for _, p := range []string{"eos", "iosxr", "iosxe", "junos"} {
		for _, c := range deviceDebugCmds[p].Collect {
			if !ddArmIsCollect(p, c) {
				t.Errorf("%s: %q is a collect command", p, c)
			}
		}
		for _, c := range append(append([]string{}, deviceDebugCmds[p].Enable...), deviceDebugCmds[p].Disable...) {
			if ddArmIsCollect(p, c) {
				t.Errorf("%s: %q is not a collect command", p, c)
			}
		}
	}
}

// The enable commands that worked on the lab images (shapes report, step 1):
// EOS 4.36.3M traces the Aaa agent in config mode and reads it with
// `show agent Aaa logs`; vJunos 26.2R1.7 traces general-authentication-service
// and also logs every authentication-facility message to a file.
func TestDeviceDebugEOSTracesTheAaaAgent(t *testing.T) {
	c := deviceDebugCmds["eos"]
	want := []string{"configure", "trace Aaa setting *", "end"}
	if !ddHasRun(c.Enable, want) {
		t.Errorf("eos enable %q does not hold %q in a row", c.Enable, want)
	}
	if !ddHasRun(c.Disable, []string{"configure", "no trace Aaa setting *", "end"}) {
		t.Errorf("eos disable %q does not undo the trace in config mode", c.Disable)
	}
	if !slices.Equal(c.Collect, []string{"show agent Aaa logs"}) {
		t.Errorf("eos collect %q", c.Collect)
	}
	// debug aaa and debug tacacs answer invalid input on 4.36.3M.
	for _, cmd := range append(append([]string{}, c.Enable...), c.Disable...) {
		if strings.HasPrefix(cmd, "debug ") || strings.HasPrefix(cmd, "no debug ") {
			t.Errorf("eos uses %q, which 4.36.3M rejects", cmd)
		}
	}
}

func TestDeviceDebugJunosTracesAuthdAndLogsTheAuthFacility(t *testing.T) {
	c := deviceDebugCmds["junos"]
	for _, set := range []string{
		"set system processes general-authentication-service traceoptions flag all",
		"set system syslog file p49-auth.log any any",
	} {
		if !slices.Contains(c.Enable, set) {
			t.Errorf("junos enable lacks %q", set)
		}
	}
	if c.Enable[len(c.Enable)-1] != "commit and-quit" || c.Disable[len(c.Disable)-3] != "commit and-quit" {
		t.Errorf("junos enable %q or disable %q does not commit", c.Enable, c.Disable)
	}
	if !slices.Equal(c.Collect, []string{"show log p49-tacplus.log", "show log p49-auth.log"}) {
		t.Errorf("junos collect %q", c.Collect)
	}
	// 26.2R1.7 rejects these (syntax error at the set).
	for _, cmd := range c.Enable {
		if strings.Contains(cmd, "traceoptions level") || strings.Contains(cmd, "services ssh traceoptions") ||
			strings.Contains(cmd, "tacplus-options traceoptions") {
			t.Errorf("junos enable has %q, which 26.2R1.7 rejects", cmd)
		}
	}
}

// ddHasRun is whether run appears in cmds as consecutive entries.
func ddHasRun(cmds, run []string) bool {
	for i := 0; i+len(run) <= len(cmds); i++ {
		if slices.Equal(cmds[i:i+len(run)], run) {
			return true
		}
	}
	return false
}
