package lab

import (
	"strings"
	"testing"
	"time"
)

// Final fix wave. The fixtures take the three line shapes the final review quoted,
// with invented values (192.0.2.1, sessions 13 and 14).

// I1, IOS XE: requests logged between two kept opens are not a connection's.
func TestDeviceDebugIOSXERequestsBeforeAnOpenAreNotPlaced(t *testing.T) {
	lines := []string{
		"*Oct 23 09:48:29.100: TPLUS(1A2B)/0/7F12: send AUTHEN/START",
		"*Oct 23 09:48:29.110: TPLUS(1A2B)/0/7F12: send AUTHEN/CONTINUE",
		"*Oct 23 09:48:29.120: TPLUS(1A2B)/0/7F12: send ACCT/START",
		"*Oct 23 09:48:30.000: TAC+: TACACS SECURE connection established with peer 192.0.2.1",
		"*Oct 23 09:48:30.010: TPLUS(1A2C)/0/7F12: send AUTHEN/START",
		"*Oct 23 09:48:31.000: TAC+: TACACS SECURE connection established with peer 192.0.2.1",
		"*Oct 23 09:48:31.010: TPLUS(1A2D)/0/7F12: send AUTHOR/REQUEST",
	}
	s := deviceDebugSummarize("iosxe", deviceDebugKept(strings.Join(lines, "\n")))
	conns, reqs, multi := s.Placed()
	if conns != 2 || reqs != 2 || multi != 0 || s.Unplaced != 3 {
		t.Errorf("placed conns=%d requests=%d pipelined=%d, unplaced=%d; want 2 2 0 3", conns, reqs, multi, s.Unplaced)
	}
}

// I1, XRd: one request prints three lines; only the anchored one counts.
func TestDeviceDebugXRCountsOneLinePerRequest(t *testing.T) {
	const xr = "RP/0/RP0/CPU0:Oct 23 16:51:42.077 UTC: tacacsd[1139]: "
	lines := []string{
		xr + "Socket connected successfully",
		xr + "packet AUTHOR/START selected server 192.0.2.1/300",
		xr + "Encrypted: [session 13] packet AUTHOR/START",
		xr + "Packet AUTHOR/START (session 13) to server 192.0.2.1/300",
		xr + "closing the socket 1000084",
	}
	s := deviceDebugSummarize("iosxr", deviceDebugKept(strings.Join(lines, "\n")))
	if len(s.Conns) != 1 || s.Conns[0].Author != 1 || s.Conns[0].Total() != 1 {
		t.Errorf("conns %+v: want one connection with one author request", s.Conns)
	}
}

// I1, cEOS: messagesSent is the request; tac_send_* lines never count, a failed
// one never counts, and a line after a close opens no connection.
func TestDeviceDebugCEOSCountsMessagesSentOnly(t *testing.T) {
	c := func(name string) string {
		return "2026-10-23 16:46:07.543338  1140 TacacsLib            6 TACACS+ counter " + name + " host 192.0.2.1:300/0/Tacacs+ TLS"
	}
	lines := []string{
		c("connOpens"),
		c("messagesSent"),
		"2026-10-23 16:46:09.198958  5684 Tacacs               2 tac_send_authen returned 261 status: 5 noecho: True",
		c("messagesSent"),
		c("connCloses"),
		"2026-10-23 16:46:09.543720  1031 Tacacs               2 tac_send_authen returned 2",
		"2026-10-23 16:46:07.543720  1031 Tacacs               0 tac_send_acct failed: connect: Connection refused",
	}
	s := deviceDebugSummarize("eos", deviceDebugKept(strings.Join(lines, "\n")))
	if len(s.Conns) != 1 || s.Conns[0].Total() != 2 || s.Unplaced != 0 {
		t.Errorf("conns %+v unplaced %d: want one connection with two requests", s.Conns, s.Unplaced)
	}
}

func TestDeviceDebugPipeliningIsUnmeasuredWhenOpensAreMissing(t *testing.T) {
	lines := []string{
		"*Oct 23 09:48:30.000: TAC+: TACACS SECURE connection established with peer 192.0.2.1",
		"*Oct 23 09:48:30.010: TPLUS(1A2C)/0/7F12: send AUTHEN/START",
		"*Oct 23 09:48:30.020: TPLUS(1A2C)/0/7F12: send AUTHEN/CONTINUE",
	}
	kept := deviceDebugKept(strings.Join(lines, "\n"))
	conns := []string{"conn port=1", "conn port=2", "conn port=3"}
	sum := ddArmSummary("iosxe", "tls_token_login", kept, 3, conns)
	if !strings.Contains(sum, "connections that carried more than one request: unmeasured") ||
		!strings.Contains(sum, "requests not placed on a connection: 0") || !strings.Contains(sum, "requests=2") {
		t.Errorf("summary:\n%s", sum)
	}
	_, obs, err := ddDebugNote(ddNoteRun{Platform: "cisco_iosxe", Profile: "iosxe", Image: "x",
		Cells: []ddNoteCell{{Cell: "tls_token_login", Kept: kept, RawLines: 3, TLSConns: conns}}})
	if err != nil || !strings.Contains(obs, "Unmeasured: the debug kept 1 open(s) for the capture's 3 connection(s)") {
		t.Errorf("note (err %v):\n%s", err, obs)
	}
	// with every connection's open kept, the answer is a count over placed ones
	sum = ddArmSummary("iosxe", "tls_token_login", kept, 3, conns[:1])
	if !strings.Contains(sum, "connections that carried more than one request: 1 of 1") {
		t.Errorf("summary:\n%s", sum)
	}
	// a noClose platform is unmeasured in the summary as it is in the note
	sum = ddArmSummary("junos", "tls_token_login", "", 0, nil)
	if !strings.Contains(sum, "connections that carried more than one request: unmeasured") {
		t.Errorf("junos summary:\n%s", sum)
	}
}

// I3: the shapes of the NX-OS 10.6 restart run, with invented times: a setup
// phase with a failed open and server-dead lines while port49d was stopped, and a
// cell whose first connection retries its open 5 s later.
func nxosRestartFixture() string {
	t := func(clock, msg string) string { return clock + " tacacsd: " + msg }
	return strings.Join([]string{
		// the setup's own accounting request, sent while port49d is stopped
		t("05:00:01.000001", "construct_tac_req(1563):aaa session id: 3, aaa type: 3, user_len=5"),
		t("05:00:01.000002", "nxos_ssl_open failed"),
		t("05:00:01.000003", "aaa_mark_server_dead 1"),
		t("05:00:01.000004", "aaa_mark_server_dead :  Idle time is 0. Server will not be monitored"),
		// the cell: its request, the first open fails, the retry 5 s later succeeds
		t("05:00:46.000001", "construct_tac_req(1762):aaa session id: 7, aaa type: 1, user_len=5"),
		t("05:00:46.000002", "after nxos_ssl_open rc -1"),
		t("05:00:51.000002", "nxos_ssl_retry_open"),
		t("05:00:51.000003", "nxos_ssl_open success"),
	}, "\n")
}

// nxosDeadInCellFixture is a cell whose own first open marks the server dead
// before a later success: that dead line belongs to the cell.
func nxosDeadInCellFixture() string {
	t := func(clock, msg string) string { return clock + " tacacsd: " + msg }
	return strings.Join([]string{
		t("05:00:01.000001", "construct_tac_req(1563):aaa session id: 3, aaa type: 3, user_len=5"),
		t("05:00:46.000001", "construct_tac_req(1762):aaa session id: 7, aaa type: 1, user_len=5"),
		t("05:00:46.000002", "after nxos_ssl_open rc -1"),
		t("05:00:46.000003", "aaa_mark_server_dead 1"),
		t("05:00:51.000003", "nxos_ssl_open success"),
	}, "\n")
}

func TestNXOSDeadCounterSeesAAAMarkServerDead(t *testing.T) {
	if !nxosDebugMarkers["mark_server_dead"].MatchString("05:00:01.000002 tacacsd: aaa_mark_server_dead 1") {
		t.Errorf("aaa_mark_server_dead N is not counted")
	}
	if nxosDebugMarkers["mark_server_dead"].MatchString("aaa_mark_server_dead :  Idle time is 0.") {
		t.Errorf("the idle-time continuation line is counted as a second dead")
	}
	if !deviceDebugProfiles["nxos"].dead.MatchString("tacacsd: aaa_mark_server_dead 1") {
		t.Errorf("the nxos profile does not count it")
	}
}

func TestNXOSCountsAreOverTheCellWindowAndSetupApart(t *testing.T) {
	c := nxosWindowedCounts(nxosRestartFixture())
	if c["mark_server_dead"] != 0 || c["setup_mark_server_dead"] != 1 || c["ssl_open_failed"] != 0 || c["setup_ssl_open_failed"] != 1 {
		t.Errorf("setup lines leaked into the cell counts: %v", c)
	}
	if c["ssl_open_retry"] != 1 || c["setup_ssl_open_retry"] != 0 || c["ssl_open_success"] != 1 || c["request_authen"] != 1 || c["request_acct"] != 0 {
		t.Errorf("cell counts: %v", c)
	}
	d := nxosWindowedCounts(nxosDeadInCellFixture())
	if d["mark_server_dead"] != 1 || d["setup_mark_server_dead"] != 0 {
		t.Errorf("the cell's own dead line was put in setup: %v", d)
	}
	// no open of the cell: the window is unmeasured, not the whole file
	if c := nxosWindowedCounts("05:00:01.000002 tacacsd: aaa_mark_server_dead 1"); c["window_unmeasured"] != 1 || c["mark_server_dead"] != 0 {
		t.Errorf("a file with no open was graded as a window: %v", c)
	}
}

func TestL80RestartGradePrintsTheOpenRetry(t *testing.T) {
	g := l80GradeRestart(l80StoreMemory, nil, l80RestartWindow{}, nxosWindowedCounts(nxosRestartFixture()), 0, nil)
	joined := strings.Join(g.Facts, "\n")
	if !strings.Contains(joined, "ssl_open_retry=1") || !strings.Contains(joined, "mark_server_dead=0") {
		t.Errorf("facts: %s", joined)
	}
	if g.Verdict != l80RestartClean {
		t.Errorf("the real order graded %s, want %s", g.Verdict, l80RestartClean)
	}
	if c := nxosWindowedCounts(nxosRestartFixture()); c["setup_mark_server_dead"] != 1 {
		t.Errorf("the setup's dead line is not in setup_*: %v", c)
	}
	g = l80GradeRestart(l80StoreMemory, nil, l80RestartWindow{}, nxosWindowedCounts("tacacsd: aaa_mark_server_dead 1"), 0, nil)
	if g.Verdict != l80RestartWindowUnmeasured {
		t.Errorf("no cell open graded %s", g.Verdict)
	}
}

// M1: the flag words stop at the first line that is not an indented
// `word  description` pair, so an error line is not read as a flag.
func TestDeviceDebugFlagWordsStopAtTheEndOfTheList(t *testing.T) {
	help := strings.Join([]string{
		"Possible completions:",
		"  all                  Trace everything",
		"  authentication       Trace authentication",
		"syntax error, expecting <data>.",
		"  later                Trace later",
	}, "\n")
	if got := strings.Join(ddFlagWords(help), " "); got != "all authentication" {
		t.Errorf("flag words %q", got)
	}
	if got := ddFlagWords("Possible completions:\n  all   Trace\n\n  other   Trace"); len(got) != 1 {
		t.Errorf("a blank line did not end the list: %v", got)
	}
}

// M1: the help is asked with the ? and a kill-line, no newline, so nothing is submitted.
func TestDeviceDebugFlagHelpKeysSubmitNothing(t *testing.T) {
	if !strings.HasPrefix(ddJunosFlagHelpKeys, ddJunosFlagHelp) || !strings.HasSuffix(ddJunosFlagHelpKeys, "\x15") ||
		strings.ContainsAny(ddJunosFlagHelpKeys, "\r\n") {
		t.Errorf("flag help keys %q", ddJunosFlagHelpKeys)
	}
}

// M2: the tag counter's output is a closed alphabet: a fixed list of Junos
// daemon names and other, and only the syslog file is counted.
func TestDeviceDebugTagsAreAFixedListOfDaemons(t *testing.T) {
	var tags ddTagCounts
	f := ddTestFilter("junos")
	f.Tags = &tags
	in := strings.Join([]string{
		"Oct 24 10:00:01 srx1 mgd[1]: x",
		"Oct 24 10:00:02 srx1 sshd-session[2]: x",
		"Oct 24 10:00:03 srx1 zqvhorsestaple[3]: x", // an unknown word
		"Oct 24 10:00:04 srx1 sdk-vmmd: x",
	}, "\n")
	if _, err := f.Keep(in); err != nil {
		t.Fatal(err)
	}
	if got := tags.String(); got != "mgd=1 sdk-vmmd=1 sshd-session=1 other=1" {
		t.Errorf("tags %q", got)
	}
}

func TestDeviceDebugOnlyTheSyslogFileIsTagCounted(t *testing.T) {
	var tags ddTagCounts
	f := ddTestFilter("junos")
	f.Tags = &tags
	run := func(cmd string) (string, error) {
		switch cmd {
		case "show log tacacs-traceoptions":
			return "Oct 24 10:00:01 srx1 authd[1]: trace line\nOct 24 10:00:01 srx1 authd[1]: trace line two\n", nil
		case "show log p49-auth.log":
			return "Oct 24 10:00:02 srx1 auditd[2]: x\n", nil
		}
		return "", nil
	}
	if _, err := captureDeviceDebug(f, run, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := tags.String(); got != "auditd=1 other=0" {
		t.Errorf("tags %q: the trace file was counted", got)
	}
}

// M5: a truncated value (%.16s) of a long secret is redacted.
func TestDeviceDebugRedactsATruncatedSecret(t *testing.T) {
	long := "zzlong-" + strings.Repeat("q7", 15) // 37 characters
	for _, p := range ddPlatforms {
		for _, n := range []int{12, 16, 19} {
			f := ddTestFilter(p)
			f.Secrets = func() []string { return []string{long} }
			got, err := f.Keep(ddFacility[p] + "tok=" + long[:n] + " end")
			if err != nil || strings.Contains(string(got), long[:n]) || !strings.Contains(string(got), "<redacted>") {
				t.Errorf("%s: a %d character prefix was kept (err %v)", p, n, err)
			}
		}
		// a prefix under 12 characters is not a known form, and says so in the limit
		f := ddTestFilter(p)
		f.Secrets = func() []string { return []string{long} }
		if got, _ := f.Keep(ddFacility[p] + "tok=" + long[:8] + " end"); !strings.Contains(string(got), long[:8]) {
			t.Errorf("%s: an 8 character prefix was redacted; the 12 character floor moved", p)
		}
	}
}

// M7: the authd process id is read as a number from the probe's answer.
func TestDeviceDebugAuthdPIDIsANumberOnly(t *testing.T) {
	out := ddAuthdProbe + "\n 4821  -  S      0:03.12 /usr/sbin/authd -N\n 4830  -  S      0:00.01 grep authd\nsrx1@vjunos> "
	if got := ddAuthdPID(out); got != 4821 {
		t.Errorf("pid %d", got)
	}
	if got := ddAuthdPID(ddAuthdProbe + "\nsrx1@vjunos> "); got != 0 {
		t.Errorf("no authd line gave pid %d", got)
	}
	for _, c := range []struct {
		b, a int
		want string
	}{{4821, 4821, "no"}, {4821, 5000, "yes"}, {0, 5000, "unmeasured"}, {4821, 0, "unmeasured"}} {
		if got := ddAuthdPIDChange(c.b, c.a); got != c.want {
			t.Errorf("change(%d,%d) = %s", c.b, c.a, got)
		}
	}
}

func TestDeviceDebugNoteStatesAuthdPIDChange(t *testing.T) {
	run := ddNoteFixtureRun(t)
	run.Cells[0].AuthdPID = "no"
	claim, obs, err := ddDebugNote(run)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(claim+obs, "authd_pid_changed=no") {
		t.Errorf("the note lacks authd_pid_changed")
	}
}

// M8: the restart grade says how many commands were typed in the window.
func TestL80RestartGradeCountsCommandsInTheWindow(t *testing.T) {
	stop := time.Date(2026, 10, 24, 10, 0, 5, 0, time.UTC)
	w := l80RestartWindow{StopAt: stop, UpAt: stop.Add(time.Second)}
	typed := []l80Typed{
		{Command: "show clock", At: stop.Add(-time.Second), Done: stop.Add(-time.Second), Asked: true},
		{Command: "show clock", At: stop.Add(300 * time.Millisecond), Done: stop.Add(400 * time.Millisecond), Asked: true},
		{Command: "show version", At: stop.Add(500 * time.Millisecond), Done: stop.Add(600 * time.Millisecond), Asked: true},
	}
	g := l80GradeRestart(l80StoreEtcd, typed, w, map[string]int{}, 0, nil)
	if !strings.Contains(strings.Join(g.Facts, "\n"), "commands typed in the window: 2") {
		t.Errorf("facts: %v", g.Facts)
	}
}

// The note names a request line for the Q4 answer from the same patterns the
// summarizer counts with. Each platform's real request shape, one connection, one
// kept open: the answer must be reached and must quote a line, not panic.
func TestDeviceDebugNoteQuotesARequestLineOnEveryPlatform(t *testing.T) {
	cases := map[string][]string{
		"eos": {"TACACS+ counter connOpens host 192.0.2.1:300/0/Tacacs+ TLS", "TACACS+ counter messagesSent host 192.0.2.1:300/0/Tacacs+ TLS"},
		"iosxr": {"Socket connected successfully", "Packet AUTHEN/START (session 13) to server 192.0.2.1/300",
			"closing the socket 1000084"},
		"iosxe": {"TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 192.0.2.1/300 (fd 7)",
			"TPLUS: processing authentication login request id 1"},
	}
	for p, msgs := range cases {
		var in []string
		for _, m := range msgs {
			in = append(in, ddFacility[p]+m)
		}
		kept := ddKeep(t, ddTestFilter(p), strings.Join(in, "\n"))
		run := ddNoteRun{Platform: "p_" + p, Profile: p, Image: "Test 1.0", Cells: []ddNoteCell{{
			Cell: "tls_token_login", Kept: deviceDebugKept(kept), RawLines: 10, TLSConns: []string{"conn port=1 syn=09:48:29.345 hold=0.03s end=server-fin"}}}}
		claim, obs, err := ddDebugNote(run)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if got := claim + obs; !strings.Contains(got, "first request line `") {
			t.Errorf("%s: the note quotes no request line:\n%s", p, got)
		}
	}
}

func TestDeviceDebugNoteRequestPatternIsTheSummarizersOwn(t *testing.T) {
	re := ddNoteRequest(deviceDebugProfiles["eos"])
	if re == nil || !re.MatchString("TACACS+ counter messagesSent host x") || re.MatchString("tac_send_authen returned 2") {
		t.Errorf("the eos note pattern is not the summarizer's request pattern")
	}
}

func TestDeviceDebugQuoteFirstNeverIndexesAnEmptyList(t *testing.T) {
	if got := ddQuoteFirst(nil, "no request line to quote", strings.ToUpper); got != "no request line to quote" {
		t.Errorf("got %q", got)
	}
	if got := ddQuoteFirst([]string{"a b"}, "none", strings.ToUpper); got == "none" {
		t.Errorf("a line was not quoted")
	}
}
