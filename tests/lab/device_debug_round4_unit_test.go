package lab

import (
	"strings"
	"testing"
)

// Step 4c: the counters read the lines the measured images print. The fixtures
// copy the shape of the kept lines of that run; every value is fake.

func TestDeviceDebugCEOSCountersFromTheCounterLines(t *testing.T) {
	c := func(name string) string {
		return "2026-10-23 15:52:47.342339  1140 TacacsLib            6 TACACS+ counter " + name + " host 192.0.2.1:300/0/Tacacs+ TLS"
	}
	kept := strings.Join([]string{
		c("connOpens"), c("connFails"), // a refused open: opened, then failed
		c("connOpens"), c("messagesSent"), c("messagesReceived"), c("messagesSent"), c("messagesReceived"), c("connCloses"),
		c("connOpens"), c("messagesSent"), c("messagesReceived"), c("connCloses"),
	}, "\n")
	s := deviceDebugSummarize("eos", deviceDebugKept(kept))
	if s.Opened != 3 || s.Closed != 2 || s.Failed != 1 {
		t.Errorf("opened=%d closed=%d failed=%d, want 3 2 1", s.Opened, s.Closed, s.Failed)
	}
	got := []int{}
	for _, cn := range s.Conns {
		got = append(got, cn.Total())
	}
	if len(got) != 3 || got[0] != 0 || got[1] != 2 || got[2] != 1 {
		t.Errorf("requests per connection %v, want [0 2 1]", got)
	}
}

func TestDeviceDebugXRdClosingTheSocketIsAClose(t *testing.T) {
	kept := "RP/0/RP0/CPU0:Oct 23 15:31:11.860 UTC: tacacsd[1139]: Socket connected successfully\n" +
		"RP/0/RP0/CPU0:Oct 23 15:31:12.195 UTC: tacacsd[1139]: closing the socket 1000084"
	s := deviceDebugSummarize("iosxr", deviceDebugKept(kept))
	if s.Opened != 1 || s.Closed != 1 {
		t.Errorf("opened=%d closed=%d, want 1 1", s.Opened, s.Closed)
	}
}

// Junos: the auditd accounting line is the one request line measured; the
// reservation-file "opened" lines of authd are not connections.
func TestDeviceDebugJunosCountsAccountingFromAuditd(t *testing.T) {
	kept := strings.Join([]string{
		"Oct 23 15:31:11.100 srx1 authd[6]: /var/db/x.reserv opened", // not a connection
		"Oct 23 15:31:11.100 srx1 authd[6]: Read persistent Address Reservations encodeType 3",
		"Oct 23 15:31:12.400 srx1 auditd[20326]: AUDITD_TACPLUS_MSG_SENT: successfully sent tacacs+ Accounting-Request message",
	}, "\n")
	s := deviceDebugSummarize("junos", deviceDebugKept(kept))
	if s.Opened != 0 {
		t.Errorf("opened=%d: an authd file-open line counted as a connection", s.Opened)
	}
	if len(s.Conns) != 1 || s.Conns[0].Acct != 1 || s.Conns[0].Authen != 0 || s.Conns[0].Author != 0 {
		t.Errorf("summary %+v", s)
	}
}

// Authentication stays unmeasured until the login path's tag is known: a guessed
// phrase on any line does not count.
func TestDeviceDebugJunosAuthenticationIsUnmeasured(t *testing.T) {
	s := deviceDebugSummarize("junos", "Oct 23 15:31:11.200 srx1 authd[6]: sending authentication request 3 to host")
	if len(s.Conns) != 0 {
		t.Errorf("a guessed authentication line counted: %+v", s)
	}
}

// W2: cEOS's failed opens are written next to the opens.
func TestDeviceDebugFailedOpensAreWritten(t *testing.T) {
	c := func(name string) string {
		return "2026-10-23 15:52:47.342339  1140 TacacsLib            6 TACACS+ counter " + name + " host 192.0.2.1:300/0/Tacacs+ TLS"
	}
	kept := deviceDebugKept(c("connOpens") + "\n" + c("connFails"))
	if sum := ddArmSummary("eos", "tls_unknown_ca", kept, 2, nil); !strings.Contains(sum, "failed_opens=1") {
		t.Errorf("the summary does not write the failed opens")
	}
	_, obs, err := ddDebugNote(ddNoteRun{Platform: "arista_ceos", Profile: "eos", Image: "x", Cells: []ddNoteCell{{Cell: "tls_unknown_ca", Kept: kept, RawLines: 2}}})
	if err != nil || !strings.Contains(obs, "failed_opens=1") {
		t.Errorf("the note does not write the failed opens (err %v)", err)
	}
}

func TestDeviceDebugTagCounterEmitsOnlyCounts(t *testing.T) {
	var tags ddTagCounts
	f := ddTestFilter("junos")
	f.Tags = &tags
	long := "z" + strings.Repeat("y", 30)
	in := strings.Join([]string{
		"Oct 23 15:31:11 srx1 authd[6]: line one",
		"Oct 23 15:31:12 srx1 authd[6]: line two",
		"Oct 23 15:31:13 srx1 sshd[7]: login",
		"Oct 23 15:31:14 srx1 " + ddSentinelKey + "[8]: x", // a secret in the tag position
		"Oct 23 15:31:15 srx1 Mixed[9]: x",                 // mixed case
		"Oct 23 15:31:16 srx1 " + long + "[9]: x",          // too long
		"Oct 23 15:31:17 srx1 deadbeef0011[1]: x",          // hex
		"Oct 23 15:31:18 srx1 " + ddSentinelToken + ": x",  // a minted token
		"no tag at all",
	}, "\n")
	f.Secrets = func() []string { return append(ddTestSecrets(), "p49-zzz") }
	if _, err := f.Keep(in); err != nil {
		t.Fatal(err)
	}
	got := tags.String()
	if got != "authd=2 sshd=1 other=6" {
		t.Errorf("tags %q", got)
	}
	for _, bad := range []string{ddSentinelKey, ddSentinelToken, "Mixed", long, "deadbeef"} {
		if strings.Contains(got, bad) {
			t.Errorf("a tag position value reached the counts")
		}
	}
}

func TestDeviceDebugTagCounterCapsAtThirtyTags(t *testing.T) {
	var tags ddTagCounts
	f := ddTestFilter("junos")
	f.Tags = &tags
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, "Oct 23 15:31:11 srx1 proc"+strings.Repeat("a", i%3)+string(rune('a'+i%26))+string(rune('a'+i/26))+": x")
	}
	if _, err := f.Keep(strings.Join(lines, "\n")); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(tags.String(), "="); n != 31 {
		t.Errorf("%d entries, want 30 tags and other", n)
	}
	if !strings.HasSuffix(tags.String(), "other=10") {
		t.Errorf("the tags past the cap are not counted as other: %q", tags.String())
	}
}

// Junos: every line of the authd traceoptions file is a TACACS line whatever its
// prefix; the same rules scrub it; a line of the auth log still needs the facility.
func TestDeviceDebugJunosTraceFileKeepsEveryLine(t *testing.T) {
	f := ddTestFilter("junos")
	tok := ddSentinelToken
	in := strings.Join([]string{
		"Oct 23 15:31:11.100 conn up to 192.0.2.1",                    // no facility word
		"Oct 23 15:31:11.200 got reply for " + ddSentinelKey + " end", // a known secret
		"Oct 23 15:31:11.300 bearer " + tok + " end",                  // a minted token
		"Oct 23 15:31:11.400 cfg key 7 08224A end",                    // type 7
		"Oct 23 15:31:11.500 cfg secret \"$9$qf3nCtu1hSyKvLx\" end",   // $9$
		"Oct 23 15:31:11.600 dump c0 01 02 03 04",                     // a hex dump
		"Oct 23 15:31:11.700 body_payload word",                       // a body word
		"Oct 23 15:31:11.800 tls_aes_128_gcm_sha256 negotiated",       // a marker
		"6b 2d 31", // a message of only hex groups, with nothing before it
		"",
	}, "\n")
	f.Secrets = func() []string { return append(ddTestSecrets(), tok) }
	got, err := f.KeepSource(in, true)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(got), "\n")
	if len(lines) != 5 {
		t.Fatalf("kept %d lines, want 5 (plain, secret, token, type 7, nine)", len(lines))
	}
	for _, bad := range []string{ddSentinelKey, tok, "08224A", "qf3nCtu1hSyKvLx", "c0 01"} {
		if strings.Contains(string(got), bad) {
			t.Errorf("a scrubbed value survived")
		}
	}
	if !strings.Contains(string(got), "conn up to") || strings.Count(string(got), "<redacted>") < 3 {
		t.Errorf("the plain line was lost or the values were not redacted")
	}
	// the same text is dropped by the facility rule when it is not from the authd trace file
	if got, _ := f.KeepSource("Oct 23 15:31:11.100 conn up to 192.0.2.1", false); got != "" {
		t.Errorf("a line with no facility was kept from a file that is not the authd trace file")
	}
}

func TestDeviceDebugJunosCollectsTheTraceFileWhole(t *testing.T) {
	cmds := deviceDebugCmds["junos"]
	var ran []string
	run := func(cmd string) (string, error) {
		ran = append(ran, cmd)
		switch cmd {
		case "show log tacacs-traceoptions":
			return "show log tacacs-traceoptions\nOct 23 15:31:11.100 conn up to 192.0.2.1\nlab@vjunos> \n", nil
		case "show log p49-auth.log":
			return "Oct 23 15:31:11.100 auditd[5]: login ok\nOct 23 15:31:11.200 authd[6]: TACACS ok\n", nil
		}
		return "", nil
	}
	kept, err := captureDeviceDebug(ddTestFilter("junos"), run, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(kept), "\n") != 1 { // two lines: conn up, and authd[6]
		t.Errorf("the echo or the prompt was kept: %d lines", strings.Count(string(kept), "\n")+1)
	}
	if !strings.Contains(string(kept), "conn up to") || strings.Contains(string(kept), "auditd") || !strings.Contains(string(kept), "authd[6]") {
		t.Errorf("collection did not apply the file rule to the authd trace file only: %q", kept)
	}
	_ = cmds
}

func TestDeviceDebugFlagWordsAreOnlyFlagNames(t *testing.T) {
	help := strings.Join([]string{
		"set system processes general-authentication-service traceoptions flag ?",
		"Possible completions:",
		"  all                  Trace everything",
		"  authentication       Trace authentication",
		"  Bad_Token            upper case and underscore",
		"  " + strings.Repeat("a", 40) + "   too long",
		"  p49-zzz-key7         a word shaped like a name",
		"  all                  repeated",
		"  <[Enter]>            Execute this command",
		"  1abc                 starts with a digit",
		"[edit]",
	}, "\n")
	got := strings.Join(ddFlagWords(help), " ")
	// the echoed command is before the completions and is not read; only
	// lower-case words of at most 31 characters are kept, each once
	if got != "all authentication p49-zzz-key7" {
		t.Errorf("flag words %q", got)
	}
	if len(ddFlagWords("all\nauthentication")) != 0 {
		t.Errorf("a line outside the completions was read")
	}
}

func TestDeviceDebugFlagWordsReachTheNote(t *testing.T) {
	_, obs, err := ddDebugNote(ddNoteRun{Platform: "juniper_vjunos-router", Profile: "junos", Image: "x",
		Cells: []ddNoteCell{{Cell: "tls_token_login", Flags: []string{"all", "authentication"}, Tags: "auditd=2 other=1"}}})
	if err != nil || !strings.Contains(obs, "traceoptions flag words the CLI offered: all authentication") ||
		!strings.Contains(obs, "syslog process tags (counts only): auditd=2 other=1") {
		t.Errorf("the note lacks the flag words or tags (err %v)", err)
	}
}
