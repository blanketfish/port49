package lab

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Every fixture here is invented for the test, never a device transcript, and
// every "secret" in it is an obvious sentinel. Failure messages name a platform
// and a fixture index and never print a sentinel.

// The sentinels the run "handled": a TACACS+ key, a password whose base64 uses
// the characters the standard and URL alphabets spell differently, a token and
// a TOTP code. All are short enough that their hex forms are under sixteen
// digits, so the payload rule does not drop the line before the redaction is
// tried; the token is long on purpose and is caught by the payload rule in hex.
const (
	ddSentinelKey   = "p49-zzz"
	ddSentinelPass  = "zz?>>?~"
	ddSentinelType7 = "zq-42"
	ddSentinelToken = "faketok-1x"
	ddSentinelOTP   = "424242"
	// ddSentinelShort is three bytes: its hex is six digits, under the eight the
	// hex-dump rule drops, so the hex form of a secret is redacted by its own rule.
	ddSentinelShort = "zq7"
)

func ddTestSecrets() []string {
	return []string{ddSentinelKey, ddSentinelPass, ddSentinelType7, ddSentinelToken, ddSentinelOTP, ddSentinelShort}
}

func ddTestFilter(platform string) deviceDebugFilter {
	return deviceDebugFilter{Platform: platform, Secrets: ddTestSecrets}
}

// ddFacility is a line prefix each platform's facility keeps, in the shape of
// the step 4 samples where they showed one.
var ddFacility = map[string]string{
	"iosxr": "RP/0/RP0/CPU0:Oct 23 09:39:03.054 UTC: tacacsd[1000]: ",
	"iosxe": "*Oct 23 09:48:29.345: TAC+: ",
	"eos":   "Oct 23 09:40:00.123 Aaa: ",
	"junos": "Oct 23 09:41:00.123 vjunos tacplus[1234]: ",
	"nxos":  "05:00:11.100001 tacacsd: ",
}

var ddPlatforms = []string{"iosxr", "iosxe", "eos", "junos", "nxos"}

func ddKeep(t *testing.T, f deviceDebugFilter, text string) string {
	t.Helper()
	k, err := f.Keep(text)
	if err != nil {
		t.Fatalf("%s: Keep failed: %v", f.Platform, err)
	}
	return string(k)
}

// ddEncodings are the forms of s the tests plant, written without the
// production code: the literal, its hex in both cases, and its base64 in both
// alphabets.
func ddEncodings(s string) map[string]string {
	b := []byte(s)
	return map[string]string{
		"literal":    s,
		"upper":      strings.ToUpper(s),
		"hex_lower":  hex.EncodeToString(b),
		"hex_upper":  strings.ToUpper(hex.EncodeToString(b)),
		"base64_std": base64.StdEncoding.EncodeToString(b),
		"base64_url": base64.URLEncoding.EncodeToString(b),
		"base64_raw": base64.RawStdEncoding.EncodeToString(b),
	}
}

// ddSurvives is whether any form of any secret is in text, case-insensitively.
func ddSurvives(text string, secrets []string, withType7 bool) (string, bool) {
	low := strings.ToLower(text)
	for i, s := range secrets {
		for name, enc := range ddEncodings(s) {
			if strings.Contains(low, strings.ToLower(enc)) {
				return name + " of secret " + string(rune('0'+i)), true
			}
		}
		if withType7 {
			for salt := 0; salt < 16; salt++ {
				if strings.Contains(low, strings.ToLower(ddType7(s, salt))) {
					return "type7 of secret " + string(rune('0'+i)), true
				}
			}
		}
	}
	return "", false
}

// The fixtures mean something only if the base64 alphabets differ for the
// password and the encodings of the others fit under the payload rule.
func TestDeviceDebugFixturesAreMeaningful(t *testing.T) {
	e := ddEncodings(ddSentinelPass)
	if e["base64_std"] == e["base64_url"] {
		t.Errorf("the password's standard and URL base64 are the same, so the URL form tests nothing")
	}
	if ddHexView(ddEncodings(ddSentinelShort)["hex_lower"]) {
		t.Errorf("the hex-dump rule would drop the fixture's own hex before the redaction is tried")
	}
}

// The lines step 4 showed each family printing are kept as they are, because
// they carry only a facility and no secret.
func TestDeviceDebugKeepsTheStep4Shapes(t *testing.T) {
	const xr = "RP/0/RP0/CPU0:Oct 23 09:39:03.054 UTC: tacacsd[1000]: "
	const xe = "*Oct 23 09:48:29.345: "
	lines := map[string][]string{
		"iosxr": {
			xr + "packet 0x1 start 0x2 login 3 session 0x4f server 172.100.100.1/49 fd=7",
			xr + "packet author 0x1 start 0x2 session 17 server 172.100.100.1/49 fd=7",
			xr + "packet 0x1 request 0x2 start 0x3 session 0x4f server 172.100.100.1/49 fd=7",
			xr + "reply 0x1 session 0x4f from server 172.100.100.1/49 fd=7",
			xr + "socket created 5 172.100.100.1/49 ok",
			// No process name: the facility takes the close line by its words.
			"RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection closed 5 172.100.100.1 port 49",
		},
		"iosxe": {
			xe + "TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (fd 7)",
			xe + "TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)",
			xe + "TPLUS(1A2B)/0/7F12: connected socket 5",
			xe + "TPLUS: immediate connect 3, new 0x7F12",
			xe + "TAC+: (1234): opened 172.100.100.1/49 ok",
		},
		"eos": {
			ddFacility["eos"] + "Tacacs: close 5",
			ddFacility["eos"] + "Sending authentication request 3 to 172.100.100.1",
		},
		"junos": {
			ddFacility["junos"] + "sending authentication request 3 to 172.100.100.1",
			"Oct 23 09:41:00.124 vjunos authd[900]: tacplus: connecting to server 172.100.100.1",
		},
		"nxos": {
			ddFacility["nxos"] + "construct_tac_req(1762):aaa session id: 7, aaa type: 2, user_len=5",
			"05:00:11.100002 aaad: Fall back method none succeeded",
		},
	}
	for _, p := range ddPlatforms {
		got := ddKeep(t, ddTestFilter(p), strings.Join(lines[p], "\n"))
		if got != strings.Join(lines[p], "\n") {
			t.Errorf("%s: the step 4 shapes were not kept as they are:\n%s", p, got)
		}
	}
}

// Step 1: a line without the platform's facility is dropped, whatever it says.
func TestDeviceDebugDropsLinesWithoutTheFacility(t *testing.T) {
	for _, p := range ddPlatforms {
		for i, ln := range []string{
			"Oct 23 09:40:00.123 sshd[77]: Accepted publickey for operator",
			"Oct 23 09:40:00.124 kernel: eth0: link up",
			"RP/0/RP0/CPU0:Oct 23 09:39:03.054 UTC: sshd[1000]: session opened",
		} {
			if got := ddKeep(t, ddTestFilter(p), ln); got != "" {
				t.Errorf("%s: line %d without the facility was kept", p, i)
			}
		}
	}
}

// Step 2: a payload line is dropped whole, hex or not.
func TestDeviceDebugDropsPayloadLines(t *testing.T) {
	for _, p := range ddPlatforms {
		f := ddTestFilter(p)
		for i, body := range []string{
			"in tac payload(hex): c0 1 2 1 de ad be ef 0 0 0 5",
			"packet Payload follows",
			"body 1234567812345678",
			"body 1a 2b 3c 4d 5e 6f 70 81 92",
			"body 0123456789ABCDEF0123",
		} {
			if got := ddKeep(t, f, ddFacility[p]+body); got != "" {
				t.Errorf("%s: payload line %d was kept", p, i)
			}
		}
	}
}

// Step 3: every known secret, in every form, inside a facility line, on every
// platform, is gone from what Keep returns.
func TestDeviceDebugNoKnownSecretSurvives(t *testing.T) {
	secrets := ddTestSecrets()
	for _, p := range ddPlatforms {
		f := ddTestFilter(p)
		var in []string
		for _, s := range secrets {
			for name, enc := range ddEncodings(s) {
				in = append(in, ddFacility[p]+"seen "+name+" ["+enc+"] after the request")
			}
			for _, salt := range []int{0, 5, 11, 15} {
				in = append(in, ddFacility[p]+"cfg "+ddType7(s, salt)+" end")
			}
		}
		got := ddKeep(t, f, strings.Join(in, "\n"))
		if what, bad := ddSurvives(got, secrets, true); bad {
			t.Errorf("%s: a secret survived Keep (%s)", p, what)
		}
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("%s: nothing was redacted", p)
		}
	}
}

// The redaction itself, below the hex-dump rule (which drops a line holding eight
// or more hex digits before the redaction runs, so most hex and every type 7
// form never reach it): each form of a secret is redacted by its own entry in
// the form list, so dropping a form turns exactly this test red.
func TestDeviceDebugEachFormIsRedactedByItsOwnRule(t *testing.T) {
	redact := ddRedactSecrets(ddSecretForms([]string{ddSentinelPass}))
	for _, form := range []string{"literal", "upper", "hex_lower", "hex_upper", "base64_std", "base64_url", "base64_raw"} {
		enc := ddEncodings(ddSentinelPass)[form]
		got := redact("x " + enc + " y")
		if got != "x <redacted> y" {
			t.Errorf("the %s form was not redacted by the form list: %q", form, got)
		}
	}
	// and end to end: the hex of a known secret, contiguous or not, drops the
	// line (a spaced form cannot be redacted in place, so none is)
	for _, form := range []string{"hex_lower", "hex_upper"} {
		for _, p := range ddPlatforms {
			enc := ddEncodings(ddSentinelShort)[form]
			if got := ddKeepOrLeak(ddTestFilter(p), ddFacility[p]+"x "+enc+" y"); got != "" {
				t.Errorf("%s: a line with the %s form of a secret was kept", p, form)
			}
		}
	}
}

// Type 7: the encodings of a known secret at every salt are in the form list, so
// the redaction and the post-check both cover them.
func TestDeviceDebugRedactsEverySaltOfTypeSeven(t *testing.T) {
	forms := ddSecretForms([]string{ddSentinelType7})
	redact := ddRedactSecrets(forms)
	for salt := 0; salt < 16; salt++ {
		enc := ddType7(ddSentinelType7, salt)
		if got := redact("cfg " + enc + " end"); got != "cfg <redacted> end" {
			t.Errorf("the type 7 encoding at salt %d was not redacted: %q", salt, got)
		}
		if !ddLeaks("cfg "+enc+" end", forms, nil) {
			t.Errorf("the post-check does not know the type 7 encoding at salt %d", salt)
		}
	}
	// a type 7 line is dropped by the hex-dump rule before it gets that far
	for _, p := range ddPlatforms {
		if got := ddKeep(t, ddTestFilter(p), ddFacility[p]+"cfg "+ddType7(ddSentinelType7, 5)+" end"); got != "" {
			t.Errorf("%s: a type 7 line was kept", p)
		}
	}
}

// The reversible encodings are redacted by shape, without knowing the secret.
func TestDeviceDebugRedactsReversibleEncodingsByShape(t *testing.T) {
	const j9 = "$9$qf3nCtu1hSyKvLx"
	for _, p := range ddPlatforms {
		f := ddTestFilter(p)
		for name, c := range map[string]struct{ in, gone string }{
			"junos_9":      {"set secret " + j9, j9},
			"junos_9_bare": {"x " + j9 + " y", j9},
			"crypt_1":      {"hash $1$salt$abcxyz12 here", "abcxyz12"},
			"crypt_5":      {"hash $5$salt$abcxyz12 here", "abcxyz12"},
			"crypt_6":      {"hash $6$salt$abcxyz12 here", "abcxyz12"},
			"crypt_8":      {"hash $8$salt$abcxyz12 here", "abcxyz12"},
			"type7_key":    {"tacacs-server key 7 08224A", "08224A"},
			"type7_pass":   {"username x password 7 08224A", "08224A"},
			"type7_secret": {"enable secret 7 08224A", "08224A"},
			"key_0":        {"tacacs-server key 0 plainvalue", "plainvalue"},
			"key_6":        {"tacacs-server key 6 plainvalue", "plainvalue"},
			"pass_8":       {"password 8 plainvalue", "plainvalue"},
			"secret_9":     {"secret 9 plainvalue", "plainvalue"},
		} {
			got := ddKeep(t, f, ddFacility[p]+c.in)
			if strings.Contains(got, c.gone) || !strings.Contains(got, "<redacted>") {
				t.Errorf("%s: %s was not redacted by shape", p, name)
			}
		}
	}
	// A key word without a value shape is left alone.
	if got := ddKeep(t, ddTestFilter("eos"), ddFacility["eos"]+"key exchange done"); !strings.Contains(got, "key exchange done") {
		t.Errorf("a harmless key line was changed: %q", got)
	}
}

// Step 4: a run of 24 or more token characters is masked.
func TestDeviceDebugMasksLongRuns(t *testing.T) {
	run := strings.Repeat("Qq", 12)
	for _, p := range ddPlatforms {
		got := ddKeep(t, ddTestFilter(p), ddFacility[p]+"id "+run+" and "+run[:23])
		if strings.Contains(got, run) || !strings.Contains(got, "<LONG>") || !strings.Contains(got, run[:23]) {
			t.Errorf("%s: long run handling wrong: %q", p, got)
		}
	}
}

// Step 5: if a known secret survives the scrub, the whole capture is discarded
// with an error that names no device text.
func TestDeviceDebugFailsClosed(t *testing.T) {
	broken := ddRedactSecrets
	t.Cleanup(func() { ddRedactSecrets = broken })
	ddRedactSecrets = func([]string) func(string) string { return func(s string) string { return s } } // a redaction that does nothing
	for _, p := range ddPlatforms {
		in := ddFacility[p] + "benign line one\n" + ddFacility[p] + "leak " + ddSentinelKey + " end\n" + ddFacility[p] + "benign line two"
		kept, err := ddTestFilter(p).Keep(in)
		if !errors.Is(err, errDeviceDebugLeak) || kept != "" {
			t.Errorf("%s: a leaked secret did not discard the capture (err %v, %d bytes)", p, err, len(kept))
			continue
		}
		if strings.Contains(err.Error(), ddSentinelKey) || strings.Contains(err.Error(), "benign") {
			t.Errorf("%s: the error names device text", p)
		}
	}
	// A redaction that misses one form is caught the same way.
	std := ddEncodings(ddSentinelPass)["base64_std"]
	ddRedactSecrets = func(forms []string) func(string) string {
		return broken(slices.DeleteFunc(slices.Clone(forms), func(f string) bool { return f != strings.ToLower(ddSentinelPass) }))
	}
	if _, err := ddTestFilter("eos").Keep(ddFacility["eos"] + "cfg " + std); !errors.Is(err, errDeviceDebugLeak) {
		t.Errorf("a surviving base64 form did not fail closed: %v", err)
	}
}

// The capture is discarded as a whole: captureDeviceDebug returns nothing and
// the error, and still turns the debug off.
func TestDeviceDebugCollectDiscardsAfterALeak(t *testing.T) {
	broken := ddRedactSecrets
	t.Cleanup(func() { ddRedactSecrets = broken })
	ddRedactSecrets = func([]string) func(string) string { return func(s string) string { return s } }
	cmds := deviceDebugCmds["eos"]
	var ran []string
	run := func(cmd string) (string, error) {
		ran = append(ran, cmd)
		if cmd == cmds.Collect[0] {
			return ddFacility["eos"] + "ok line\n" + ddFacility["eos"] + "leak " + ddSentinelKey, nil
		}
		return "", nil
	}
	kept, err := captureDeviceDebug(ddTestFilter("eos"), run, func() error { return nil })
	if !errors.Is(err, errDeviceDebugLeak) || kept != "" {
		t.Errorf("err %v, %d bytes kept", err, len(kept))
	}
	if ran[len(ran)-1] != cmds.Disable[len(cmds.Disable)-1] {
		t.Errorf("debug was not turned off after a leak: %v", ran)
	}
}

// The marker Keep writes is not itself a leak: a secret that spells a piece of
// it cannot fail a clean capture.
func TestDeviceDebugMarkerIsNotALeak(t *testing.T) {
	f := deviceDebugFilter{Platform: "eos", Secrets: func() []string { return []string{"acted", "ong"} }}
	k, err := f.Keep(ddFacility["eos"] + "acted here " + strings.Repeat("Zz", 14) + " ong")
	if err != nil {
		t.Fatalf("a clean capture failed closed: %v", err)
	}
	if strings.Contains(string(k), "acted") && !strings.Contains(string(k), "<redacted>") {
		t.Errorf("not redacted: %q", k)
	}
}

func TestDeviceDebugUnknownPlatformKeepsNothing(t *testing.T) {
	if got := ddKeep(t, deviceDebugFilter{Platform: "nope"}, ddFacility["eos"]+"anything"); got != "" {
		t.Errorf("kept %d bytes for an unknown platform", len(got))
	}
}

func TestDeviceDebugNilSecretsStillScrubsByShape(t *testing.T) {
	got := ddKeep(t, deviceDebugFilter{Platform: "eos"}, ddFacility["eos"]+"x $9$qf3nCtu1hSyKvLx y")
	if strings.Contains(got, "qf3nCtu1hSyKvLx") {
		t.Errorf("a filter without secrets skipped the shape rules")
	}
}

// The counters, over kept lines in the step 4 shapes.
func TestDeviceDebugCounters(t *testing.T) {
	const xr = "RP/0/RP0/CPU0:Oct 23 09:39:03.054 UTC: tacacsd[1000]: "
	const xe = "*Oct 23 09:48:29.345: "
	type want struct {
		open, closed, single, dead, fallback int
		conns                                []deviceDebugConn
	}
	cases := []struct {
		platform string
		in       []string
		want     want
	}{
		{"iosxr", []string{
			xr + "socket connected 5 172.100.100.1/49",
			xr + "packet 0x1 start 0x2 login 3 session 0x4f server 172.100.100.1/49 fd=7",
			xr + "packet author 0x1 start 0x2 session 17 server 172.100.100.1/49 fd=7",
			xr + "packet 0x1 request 0x2 start 0x3 session 17 server 172.100.100.1/49 fd=7",
			"RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection closed 5 172.100.100.1 port 49",
		}, want{open: 1, closed: 1, conns: []deviceDebugConn{{Opened: "09:39:03.054", Closed: "09:39:03.099", Authen: 1, Author: 1, Acct: 1}}}},
		{"iosxe", []string{
			xe + "TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (fd 7)",
			xe + "TPLUS: processing authentication login request id 1",
			xe + "TPLUS: Authorization request created for 0(alice07)",
			xe + "TAC+: Using single connection to 172.100.100.1",
			"*Oct 23 09:48:30.001: TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)",
		}, want{open: 1, closed: 1, single: 1, conns: []deviceDebugConn{{Opened: "09:48:29.345", Closed: "09:48:30.001", Authen: 1, Author: 1}}}},
		{"eos", []string{
			ddFacility["eos"] + "Tacacs: Connecting to 172.100.100.1 port 49",
			ddFacility["eos"] + "Sending authentication request 1 to 172.100.100.1",
			ddFacility["eos"] + "Single connect negotiated",
			ddFacility["eos"] + "Tacacs: Connection to 172.100.100.1:49 closed by peer",
		}, want{open: 1, closed: 1, single: 1, conns: []deviceDebugConn{{Opened: "09:40:00.123", Closed: "09:40:00.123", Authen: 1, Reason: "closed by peer"}}}},
		{"junos", []string{
			"Oct 23 09:41:00.101 vjunos auditd[1]: AUDITD_TACPLUS_MSG_SENT: successfully sent tacacs+ Accounting-Request message",
		}, want{conns: []deviceDebugConn{{Acct: 1}}}},
		{"nxos", []string{
			"05:00:11.100001 tacacsd: nxos_ssl_open success",
			"05:00:11.100002 tacacsd: construct_tac_req(1762):aaa session id: 7, aaa type: 1, user_len=5",
			"05:00:11.100003 aaad: Fall back method none succeeded",
			"05:00:11.100004 tacacsd: clean_up_sock_sm_node: freeing ssl_ctx for sock_fd 32",
			"05:00:11.100005 tacacsd: clean_up_sock_sm_node(4564): mark server(172.100.100.1) dead",
		}, want{open: 1, closed: 1, dead: 1, fallback: 1, conns: []deviceDebugConn{{Opened: "05:00:11.100001", Closed: "05:00:11.100004", Authen: 1}}}},
	}
	for _, c := range cases {
		kept := ddKeep(t, ddTestFilter(c.platform), strings.Join(c.in, "\n"))
		s := deviceDebugSummarize(c.platform, deviceDebugKept(kept))
		if s.Opened != c.want.open || s.Closed != c.want.closed || s.SingleConnect != c.want.single || s.ServerDead != c.want.dead || s.Fallback != c.want.fallback {
			t.Errorf("%s: counters %+v", c.platform, s)
		}
		if !slices.Equal(s.Conns, c.want.conns) {
			t.Errorf("%s: conns %+v, want %+v", c.platform, s.Conns, c.want.conns)
		}
	}
}

// Junos has no close line: the summary says the close is unknown, and the arm
// text does not print 0.
func TestDeviceDebugJunosCloseIsUnknownNotZero(t *testing.T) {
	kept := ddKeep(t, ddTestFilter("junos"), "Oct 23 09:41:00.100 vjunos tacplus[1]: connecting to server 172.100.100.1")
	s := deviceDebugSummarize("junos", deviceDebugKept(kept))
	if !s.CloseUnknown || s.Closed != 0 {
		t.Errorf("junos summary %+v", s)
	}
	text := ddArmSummary("junos", "tls_token_login", deviceDebugKept(kept), 40, nil)
	if !strings.Contains(text, "closed=unknown") || strings.Contains(text, "closed=0") {
		t.Errorf("the arm text does not say the close is unknown:\n%s", text)
	}
	e := deviceDebugSummarize("eos", deviceDebugKept(ddFacility["eos"]+"Tacacs: close 5"))
	if e.CloseUnknown || e.Closed != 1 {
		t.Errorf("eos summary %+v", e)
	}
	if !strings.Contains(ddArmSummary("eos", "c", "", 0, nil), "closed=0") {
		t.Errorf("eos arm text lost its zero")
	}
}

func TestDeviceDebugJunosSummaryStatesTheAttribution(t *testing.T) {
	if !strings.Contains(ddArmSummary("junos", "c", "", 0, nil), "attributed to the last connection opened in the trace") {
		t.Errorf("the junos summary does not state how requests are attributed")
	}
	if strings.Contains(ddArmSummary("eos", "c", "", 0, nil), "attributed to the last connection") {
		t.Errorf("another platform carries the junos note")
	}
}

// Requests before any open belong to a connection opened earlier (reuse), and
// two connections keep their own counts: the pipelining question.
func TestDeviceDebugRequestsPerConnection(t *testing.T) {
	p := ddFacility["eos"]
	in := strings.Join([]string{
		p + "Sending authentication request 1 to 172.100.100.1",
		p + "Tacacs: Connecting to server 172.100.100.1 port 49",
		p + "Sending authentication request 2 to 172.100.100.1",
		p + "Sending authorization request 3 to 172.100.100.1",
		p + "Tacacs: Connecting to server 172.100.100.1 port 49",
		p + "Sending accounting request 4 to 172.100.100.1",
		p + "Tacacs: Connection to 172.100.100.1:49 closed",
	}, "\n")
	s := deviceDebugSummarize("eos", deviceDebugKept(ddKeep(t, ddTestFilter("eos"), in)))
	want := []deviceDebugConn{{Authen: 1}, {Authen: 1, Author: 1}, {Acct: 1}}
	if len(s.Conns) != len(want) {
		t.Fatalf("conns %+v", s.Conns)
	}
	for i, w := range want {
		g := s.Conns[i]
		if g.Authen != w.Authen || g.Author != w.Author || g.Acct != w.Acct {
			t.Errorf("conn %d = %+v, want %+v", i, g, w)
		}
	}
	if s.Opened != 2 || s.Closed != 1 {
		t.Errorf("opened %d closed %d", s.Opened, s.Closed)
	}
}

// A request counts once when IOS XE prints both the send line and the
// request-created line for it; the created lines count when no send line of
// that kind exists.
func TestDeviceDebugIOSXECountsARequestOnce(t *testing.T) {
	const xe = "*Oct 22 05:00:01.00"
	both := strings.Join([]string{
		xe + "0: TAC+: tacacs secure connection established with peer 172.100.100.1/49",
		xe + "1: TPLUS: Authorization request created for 0(alice07)",
		xe + "2: TAC+: send AUTHOR/REQ packet",
		xe + "3: TPLUS: Accounting request created for 0(alice07)",
		xe + "4: TPLUS: processing authentication login request id 1",
		xe + "5: TAC+: send AUTHEN/START packet",
	}, "\n")
	s := deviceDebugSummarize("iosxe", deviceDebugKept(ddKeep(t, ddTestFilter("iosxe"), both)))
	if c := s.Conns[0]; c.Authen != 1 || c.Author != 1 || c.Acct != 1 {
		t.Errorf("both families: %+v", c)
	}
	only := deviceDebugSummarize("iosxe", deviceDebugKept(ddKeep(t, ddTestFilter("iosxe"),
		strings.Join(strings.Split(both, "\n")[:2], "\n")+"\n"+xe+"6: TPLUS: Authorization request created for 0(alice07)")))
	if c := only.Conns[0]; c.Author != 2 {
		t.Errorf("created lines only: %+v", c)
	}
}

// The vocabulary holds the words of the step 2 shapes and still not aaa (a hex
// word); the sampler writes them through.
func TestDeviceDebugArmVocabularyHasTheStep2Words(t *testing.T) {
	for _, w := range []string{"tacacsd", "tacplus", "authd", "invalid", "syntax"} {
		if !ddArmVocab[w] {
			t.Errorf("%q is not in the vocabulary", w)
		}
	}
	if ddArmVocab["aaa"] {
		t.Errorf("aaa is hex letters only and must stay out of the vocabulary")
	}
	got := ddArmTokens("tacacsd[88]: AUTHD tacplus Invalid syntax Aaa 10.0.0.1")
	if got != "tacacsd _ authd tacplus invalid syntax _ A" {
		t.Errorf("tokens %q", got)
	}
}

// Every command sequence is a fixed list, and the kept text is all the
// collector returns; the raw output stays in the function.
func TestDeviceDebugCollectFiltersInProcess(t *testing.T) {
	f := ddTestFilter("eos")
	cmds := deviceDebugCmds["eos"]
	var ran []string
	raw := ddFacility["eos"] + "ok line\n" + ddFacility["eos"] + "leak " + ddSentinelKey + "\n" + "Oct 23 09:40:00.124 sshd[7]: other"
	run := func(cmd string) (string, error) {
		ran = append(ran, cmd)
		if cmd == cmds.Collect[0] {
			return raw, nil
		}
		return "", nil
	}
	kept, err := captureDeviceDebug(f, run, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(kept), ddSentinelKey) || strings.Contains(string(kept), "sshd") || !strings.Contains(string(kept), "ok line") {
		t.Errorf("collector result:\n%s", kept)
	}
	if len(ran) == 0 || ran[0] != cmds.Enable[0] || ran[len(ran)-1] != cmds.Disable[len(cmds.Disable)-1] {
		t.Errorf("ran %v", ran)
	}
	// Debug is turned off even when the cell fails.
	ran = nil
	_, err = captureDeviceDebug(f, run, func() error { return errors.New("cell failed") })
	if err == nil || !slices.Contains(ran, cmds.Disable[0]) {
		t.Errorf("no disable after a failed cell: err %v ran %v", err, ran)
	}
}

func TestDeviceDebugCmdsCoverEveryPlatformAndTypeNoSecret(t *testing.T) {
	for _, p := range []string{"eos", "iosxr", "junos", "iosxe"} {
		c, ok := deviceDebugCmds[p]
		if !ok || len(c.Enable) == 0 || len(c.Disable) == 0 || len(c.Collect) == 0 {
			t.Errorf("%s: incomplete command set", p)
			continue
		}
		for _, cmd := range slices.Concat(c.Enable, c.Disable, c.Collect) {
			if nxosDebugSecret.MatchString(cmd) {
				t.Errorf("%s: command %q holds a secret word", p, cmd)
			}
		}
	}
}

// An error from collecting or disabling must not carry the device's output.
func TestDeviceDebugErrorsCarryNoDeviceOutput(t *testing.T) {
	const sentinel = "fakesecret77-device-tail"
	for _, platform := range []string{"eos", "iosxr", "junos", "iosxe"} {
		cmds := deviceDebugCmds[platform]
		for stage, failOn := range map[string]string{"enable": cmds.Enable[len(cmds.Enable)-1],
			"collect": cmds.Collect[0], "disable": cmds.Disable[len(cmds.Disable)-1]} {
			run := func(cmd string) (string, error) {
				if cmd == failOn {
					return sentinel, errors.New(`none of ["#"] appeared on the device within 5s; what it said was:` + "\n" + sentinel)
				}
				return "", nil
			}
			kept, err := captureDeviceDebug(ddTestFilter(platform), run, func() error { return nil })
			if err == nil {
				t.Errorf("%s %s: no error", platform, stage)
				continue
			}
			if strings.Contains(err.Error(), sentinel) || strings.Contains(string(kept), sentinel) {
				t.Errorf("%s %s: the device's output is in the result", platform, stage)
			}
			if !strings.Contains(err.Error(), failOn) {
				t.Errorf("%s %s: the error names no command", platform, stage)
			}
		}
	}
}

// A failed cell still yields the filtered debug, and returns its own error.
func TestDeviceDebugCollectsWhenTheCellFails(t *testing.T) {
	f := ddTestFilter("eos")
	raw := ddFacility["eos"] + "ok line\nOct 23 09:40:00.124 sshd[7]: other"
	run := func(cmd string) (string, error) {
		if cmd == deviceDebugCmds["eos"].Collect[0] {
			return raw, nil
		}
		return "", nil
	}
	cellErr := errors.New("cell failed")
	kept, err := captureDeviceDebug(f, run, func() error { return cellErr })
	if err != cellErr {
		t.Errorf("err %v, want the cell's", err)
	}
	if string(kept) != ddFacility["eos"]+"ok line" {
		t.Errorf("kept %d bytes after a failed cell", len(kept))
	}
	// A collect step that fails with a partial capture still keeps it, filtered.
	run2 := func(cmd string) (string, error) {
		if cmd == deviceDebugCmds["eos"].Collect[0] {
			return raw, errors.New("timeout")
		}
		return "", nil
	}
	kept, err = captureDeviceDebug(f, run2, func() error { return nil })
	if err == nil || string(kept) != ddFacility["eos"]+"ok line" {
		t.Errorf("partial capture: err %v, %d bytes", err, len(kept))
	}
}

// Every file a Collect reads is cleared by Disable.
func TestDeviceDebugJunosClearsTheFilesItReads(t *testing.T) {
	c := deviceDebugCmds["junos"]
	for _, col := range c.Collect {
		if !slices.Contains(c.Disable, "clear log "+strings.TrimPrefix(col, "show log ")) {
			t.Errorf("Disable %v does not clear what %q reads", c.Disable, col)
		}
	}
}

func ddKeepStr(t *testing.T, f deviceDebugFilter, text string) deviceDebugKept {
	t.Helper()
	return deviceDebugKept(ddKeep(t, f, text))
}
