package lab

import (
	"strings"
	"testing"
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
		t("05:00:01.000001", "nxos_ssl_open failed"),
		t("05:00:01.000002", "aaa_mark_server_dead 1"),
		t("05:00:01.000003", "aaa_mark_server_dead :  Idle time is 0. Server will not be monitored"),
		t("05:00:46.000001", "construct_tac_req(1762):aaa session id: 7, aaa type: 1, user_len=5"),
		t("05:00:46.000002", "after nxos_ssl_open rc -1"),
		t("05:00:51.000002", "nxos_ssl_retry_open"),
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
	if c["ssl_open_retry"] != 1 || c["ssl_open_success"] != 1 || c["request_authen"] != 1 {
		t.Errorf("cell counts: %v", c)
	}
	// no request line: no window, everything is the cell
	if c := nxosWindowedCounts("05:00:01.000002 tacacsd: aaa_mark_server_dead 1"); c["mark_server_dead"] != 1 {
		t.Errorf("without a request line the dead line was hidden in setup: %v", c)
	}
}

func TestL80RestartGradePrintsTheOpenRetry(t *testing.T) {
	g := l80GradeRestart(l80StoreMemory, nil, l80RestartWindow{}, nxosWindowedCounts(nxosRestartFixture()), 0, nil)
	joined := strings.Join(g.Facts, "\n")
	if !strings.Contains(joined, "ssl_open_retry=1") || !strings.Contains(joined, "mark_server_dead=0") {
		t.Errorf("facts: %s", joined)
	}
	if g.Verdict == l80RestartDeadOnly {
		t.Errorf("a setup-phase dead line decided the restart verdict")
	}
}
