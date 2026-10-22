package lab

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// Every fixture here is invented for the test, never a device transcript, and
// every "secret" in it is made up. The line shapes are plausible, not
// measured (the lab run confirms them), so a test that a shape is kept
// proves the filter's rule, not the device's wording. Failure messages name
// a fixture by index and never print a sentinel.

// ddSentinels are the made-up values no kept line may contain, whatever
// field they sit in.
var ddSentinels = []string{"hunter9", "fakesecret77", "faketok123abc", "deadbeefcafe0123", "QWxhZGRpbjpvcGVuIHNlc2FtZQ",
	"mallory42", "evilgroup", "evil:list", "frobwidget", "10.66.66.66", "0xfeedface", "badmethod"}

var ddTestFilter = func(platform string) deviceDebugFilter {
	return deviceDebugFilter{Platform: platform, Groups: []string{"port49"},
		Addrs: []netip.Addr{netip.MustParseAddr("172.100.100.1"), netip.MustParseAddr("172.100.100.41")}}
}

// ddCase is one platform's fixtures: lines kept verbatim, lines kept with a
// field masked, and attacks (each holds a sentinel in a field position, or an
// unknown shape) that must come out dropped or masked.
type ddCase struct {
	platform string
	kept     []string
	masked   map[string]string
	attacks  []string
	// counters, over kept and the conns the kept lines describe
	open, closed, single, dead, fallback int
	conns                                []deviceDebugConn
}

var ddCases = []ddCase{
	{
		platform: "iosxe",
		kept: []string{
			"*Oct 22 05:00:11.100: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5",
			"*Oct 22 05:00:11.101: TAC+: Using single connection to 172.100.100.1",
			"*Oct 22 05:00:11.102: AAA/AUTHEN/LOGIN (00000001): Pick method list 'default'",
			"*Oct 22 05:00:11.103: TAC+: send AUTHEN/START packet",
			"*Oct 22 05:00:11.104: TAC+: (1234): received authen response status = PASS",
			"*Oct 22 05:00:11.105: TAC+: send AUTHOR/REQ packet",
			"*Oct 22 05:00:11.106: TAC+:    priv-lvl=15",
			"*Oct 22 05:00:11.107: TAC+:    cmd=show",
			"*Oct 22 05:00:11.108: TAC+: send ACCT/REQ packet",
			"*Oct 22 05:00:11.109: TAC+: Closing TCP/IP 0x7F1234 connection to 172.100.100.1/49 (idle timeout)",
			"*Oct 22 05:00:11.110: TAC+: Server 172.100.100.1 marked DEAD",
			"*Oct 22 05:00:11.111: AAA/AUTHEN/LOGIN (00000001): Method=LOCAL",
			"*Oct 22 05:00:11.112: TPLUS(00000001) login timer stopped",
		},
		masked: map[string]string{
			"*Oct 22 05:00:12.001: TAC+: Closing TCP/IP 0x7F1234 connection to 172.100.100.1/49 (idle timeout)": "05:00:12.001 TAC+: Closing TCP/IP <masked> connection to 172.100.100.1/49 (idle timeout)",
			"*Oct 22 05:00:12.002: TAC+: Using single connection to 198.51.100.9":                               "05:00:12.002 TAC+: Using single connection to <masked>",
			"*Oct 22 05:00:12.003: AAA/AUTHEN/LOGIN (00000001): Pick method list 'evil-list'":                   "05:00:12.003 AAA/AUTHEN/LOGIN (<masked>): Pick method list '<masked>'",
			"*Oct 22 05:00:12.004: TAC+: Using default tacacs server-group \"evilgroup\"":                       "05:00:12.004 TAC+: Using default tacacs server-group \"<masked>\"",
			"*Oct 22 05:00:12.005: TPLUS: Authentication start packet created for 0(mallory42)":                 "05:00:12.005 TPLUS: Authentication start packet created for 0(<masked>)",
			"*Oct 22 05:00:12.006: TPLUS: Authentication start packet created for 0(alice07)":                   "05:00:12.006 TPLUS: Authentication start packet created for 0(alice07)",
			"*Oct 22 05:00:12.007: TAC+:    priv-lvl=16":                                                        "05:00:12.007 TAC+:    priv-lvl=<masked>",
			"*Oct 22 05:00:12.008: TAC+:    cmd-arg=frobwidget":                                                 "05:00:12.008 TAC+:    cmd-arg=<masked>",
			"*Oct 22 05:00:12.009: TAC+:    service=shell":                                                      "05:00:12.009 TAC+:    service=shell",
			"*Oct 22 05:00:12.010: TAC+:    service=frobwidget":                                                 "05:00:12.010 TAC+:    service=<masked>",
			"*Oct 22 05:00:12.011: AAA/AUTHEN/LOGIN (00000001): Method=badmethod (tacacs+)":                     "05:00:12.011 AAA/AUTHEN/LOGIN (<masked>): Method=<masked> (tacacs+)",
		},
		attacks: []string{
			"*Oct 22 05:00:13.001: TAC+: send AUTHEN/START packet password hunter9",
			"*Oct 22 05:00:13.002: TAC+: payload(hex): c0 01 02 01 de ad be ef 00 00 00 05",
			"*Oct 22 05:00:13.003: TAC+: (1234): received authen response status = PASS token faketok123abc",
			"*Oct 22 05:00:13.004: TAC+: Server 172.100.100.1 marked DEAD deadbeefcafe0123",
			"*Oct 22 05:00:13.005: TAC+: body QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			"*Oct 22 05:00:13.006: TAC+:    user=mallory42",
			"*Oct 22 05:00:13.007: TAC+:    cmd=username fakesecret77",
			"*Oct 22 05:00:13.008: some new debug line about frobwidget 42",
			"*Oct 22 05:00:13.009: TAC+: Opening TCP/IP to 10.66.66.66/49 timeout=5 hunter9",
		},
		open: 1, closed: 1, single: 1, dead: 1, fallback: 1,
		conns: []deviceDebugConn{{Opened: "*Oct 22 05:00:11.100", Closed: "", Reason: "idle timeout", Authen: 1, Author: 1, Acct: 1}},
	},
	{
		platform: "eos",
		kept: []string{
			"Oct 22 05:00:11.100 Tacacs: Connecting to server 172.100.100.1 port 49",
			"Oct 22 05:00:11.101 Tacacs: Single connect flag set",
			"Oct 22 05:00:11.102 Aaa: Sending authentication request 7 to 172.100.100.1",
			"Oct 22 05:00:11.103 Aaa: Received authentication reply 7 status PASS",
			"Oct 22 05:00:11.104 Aaa: Sending authorization request 8 to 172.100.100.1",
			"Oct 22 05:00:11.105 Aaa: Sending accounting request 9 to 172.100.100.1",
			"Oct 22 05:00:11.106 Aaa: priv-lvl=15",
			"Oct 22 05:00:11.107 Tacacs: Connection to 172.100.100.1:49 closed by peer",
			"Oct 22 05:00:11.108 Tacacs: Server 172.100.100.1 marked dead",
			"Oct 22 05:00:11.109 Aaa: Falling back to local for authentication",
			"Oct 22 05:00:11.110 Aaa: User breakglass authenticating via method list default",
		},
		masked: map[string]string{
			"Oct 22 05:00:12.001 Tacacs: Connecting to server 10.66.66.66 port 49":                        "05:00:12.001 Tacacs: Connecting to server <masked> port 49",
			"Oct 22 05:00:12.002 Aaa: Falling back to badmethod for authentication":                       "05:00:12.002 Aaa: Falling back to <masked> for authentication",
			"Oct 22 05:00:12.003 Aaa: User mallory42 authenticating via method list evil:list":            "05:00:12.003 Aaa: User <masked> authenticating via method list <masked>",
			"Oct 22 05:00:12.004 Aaa: Using server group evilgroup":                                       "05:00:12.004 Aaa: Using server group <masked>",
			"Oct 22 05:00:12.005 Aaa: Using server group port49":                                          "05:00:12.005 Aaa: Using server group port49",
			"Oct 22 05:00:12.006 Aaa: cmd-arg=frobwidget":                                                 "05:00:12.006 Aaa: cmd-arg=<masked>",
			"Oct 22 05:00:12.007 Aaa: cmd-arg=users":                                                      "05:00:12.007 Aaa: cmd-arg=users",
			"2026-10-22T05:00:12.008+00:00 eos1 Tacacs: Connecting to server 2001:db8::1 port 49":         "05:00:12.008 Tacacs: Connecting to server <masked> port 49",
			"Oct 22 05:00:12.009 Tacacs: Connection to 7061:7373:776f:7264:7365:6372:6574:3132:49 closed": "05:00:12.009 Tacacs: Connection to <masked>:49 closed",
		},
		attacks: []string{
			"Oct 22 05:00:13.001 Aaa: Sending authentication request 7 to 172.100.100.1 password hunter9",
			"Oct 22 05:00:13.002 Tacacs: payload(hex): c0 01 02 01 de ad be ef 00 00 00 05",
			"Oct 22 05:00:13.003 Aaa: Received authentication reply 7 status PASS secret fakesecret77",
			"Oct 22 05:00:13.004 Tacacs: key deadbeefcafe0123",
			"Oct 22 05:00:13.005 Aaa: user=mallory42",
			"Oct 22 05:00:13.006 Aaa: some new debug line about frobwidget 42",
			"Oct 22 05:00:13.007 Aaa: Received authentication reply 7 status QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			"Oct 22 05:00:13.008 Sshd: Received authentication reply 7 status PASS faketok123abc",
		},
		open: 1, closed: 1, single: 1, dead: 1, fallback: 1,
		conns: []deviceDebugConn{{Opened: "Oct 22 05:00:11.100", Reason: "closed by peer", Authen: 1, Author: 1, Acct: 1}},
	},
	{
		platform: "iosxr",
		kept: []string{
			"RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacsd[1000]: Opening connection to 172.100.100.1 port 49",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.101 UTC: tacacsd[1000]: Single connection negotiated",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.102 UTC: tacacsd[1000]: Sending authentication request 3 to 172.100.100.1",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.103 UTC: tacacsd[1000]: Received authentication reply 3 status PASS",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.104 UTC: tacacsd[1000]: Sending authorization request 4 to 172.100.100.1",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.105 UTC: tacacsd[1000]: Sending accounting request 5 to 172.100.100.1",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.106 UTC: aaad[1001]: service=shell",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.107 UTC: tacacsd[1000]: Closing connection to 172.100.100.1 port 49 (remote reset)",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.108 UTC: tacacsd[1000]: Server 172.100.100.1 marked dead",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.109 UTC: aaad[1001]: Falling back to local for authentication",
		},
		masked: map[string]string{
			"RP/0/RP0/CPU0:Oct 22 05:00:12.001 UTC: tacacsd[1000]: Opening connection to 10.66.66.66 port 49":       "05:00:12.001 tacacsd: Opening connection to <masked> port 49",
			"RP/0/RP0/CPU0:Oct 22 05:00:12.002 UTC: aaad[1001]: service=frobwidget":                                 "05:00:12.002 aaad: service=<masked>",
			"RP/0/RP0/CPU0:Oct 22 05:00:12.003 UTC: aaad[1001]: User mallory42 authenticating via method list evil": "05:00:12.003 aaad: User <masked> authenticating via method list <masked>",
			"RP/0/RP0/CPU0:Oct 22 05:00:12.004 UTC: aaad[1001]: Using server group evilgroup":                       "05:00:12.004 aaad: Using server group <masked>",
		},
		attacks: []string{
			"RP/0/RP0/CPU0:Oct 22 05:00:13.001 UTC: tacacsd[1000]: Sending authentication request 3 to 172.100.100.1 password hunter9",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.002 UTC: tacacsd[1000]: payload(hex): c0 01 02 01 de ad be ef 00 00 00 05",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.003 UTC: tacacsd[1000]: Received authentication reply 3 status PASS token faketok123abc",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.004 UTC: aaad[1001]: user=mallory42",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.005 UTC: aaad[1001]: cmd=username fakesecret77",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.006 UTC: tacacsd[1000]: some new debug line about frobwidget 42",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.007 UTC: tacacsd[1000]: key deadbeefcafe0123",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.008 UTC: tacacsd[1000]: body QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
		},
		open: 1, closed: 1, single: 1, dead: 1, fallback: 1,
		conns: []deviceDebugConn{{Opened: "RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC", Reason: "remote reset", Authen: 1, Author: 1, Acct: 1}},
	},
	{
		platform: "junos",
		kept: []string{
			"Oct 22 05:00:11.100 vjunos mgd[900]: connecting to server 172.100.100.1 port 49",
			"Oct 22 05:00:11.101 vjunos mgd[900]: single-connect flag set",
			"Oct 22 05:00:11.102 vjunos mgd[900]: sending authentication request 1 to 172.100.100.1",
			"Oct 22 05:00:11.103 vjunos mgd[900]: received authentication reply 1 status PASS",
			"Oct 22 05:00:11.104 vjunos mgd[900]: sending authorization request 2 to 172.100.100.1",
			"Oct 22 05:00:11.105 vjunos mgd[900]: sending accounting request 3 to 172.100.100.1",
			"Oct 22 05:00:11.106 vjunos mgd[900]: priv-lvl=15",
			"Oct 22 05:00:11.107 vjunos mgd[900]: connection to 172.100.100.1 closed by server",
			"Oct 22 05:00:11.108 vjunos mgd[900]: server 172.100.100.1 marked dead",
			"Oct 22 05:00:11.109 vjunos mgd[900]: falling back to local",
		},
		masked: map[string]string{
			"Oct 22 05:00:12.001 vjunos mgd[900]: connecting to server 10.66.66.66 port 49":                               "05:00:12.001 mgd: connecting to server <masked> port 49",
			"Oct 22 05:00:12.002 vjunos mgd[900]: cmd-arg=frobwidget":                                                     "05:00:12.002 mgd: cmd-arg=<masked>",
			"Oct 22 05:00:12.003 vjunos mgd[900]: user mallory42 authenticating via method list evil":                     "05:00:12.003 mgd: user <masked> authenticating via method list <masked>",
			"Oct 22 05:00:12.004 vjunos mgd[900]: falling back to badmethod":                                              "05:00:12.004 mgd: falling back to <masked>",
			"Oct 22 05:00:12.005 vjunos mgd[900]: sending authentication request 1 to 172.100.100.1 on socket 0xfeedface": "",
		},
		attacks: []string{
			"Oct 22 05:00:13.001 vjunos mgd[900]: sending authentication request 1 to 172.100.100.1 password hunter9",
			"Oct 22 05:00:13.002 vjunos mgd[900]: payload(hex): c0 01 02 01 de ad be ef 00 00 00 05",
			"Oct 22 05:00:13.003 vjunos mgd[900]: received authentication reply 1 status PASS token faketok123abc",
			"Oct 22 05:00:13.004 vjunos mgd[900]: user=mallory42",
			"Oct 22 05:00:13.005 vjunos mgd[900]: cmd=username fakesecret77",
			"Oct 22 05:00:13.006 vjunos mgd[900]: some new debug line about frobwidget 42",
			"Oct 22 05:00:13.007 vjunos mgd[900]: key deadbeefcafe0123",
			"Oct 22 05:00:13.008 vjunos mgd[900]: body QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			"Oct 22 05:00:13.009 vjunos cron[900]: connecting to server 172.100.100.1 port 49 hunter9",
		},
		open: 1, closed: 1, single: 1, dead: 1, fallback: 1,
		conns: []deviceDebugConn{{Opened: "Oct 22 05:00:11.100", Reason: "closed by server", Authen: 1, Author: 1, Acct: 1}},
	},
}

func ddCaseFor(t *testing.T, platform string) ddCase {
	t.Helper()
	for _, c := range ddCases {
		if c.platform == platform {
			return c
		}
	}
	t.Fatalf("no fixtures for %s", platform)
	return ddCase{}
}

// ddNorm is the kept form of a verbatim fixture line: what Keep writes for
// it.
func ddNorm(f deviceDebugFilter, ln string) string { return f.Keep(ln) }

func TestDeviceDebugKeepsTheAllowedShapes(t *testing.T) {
	for _, c := range ddCases {
		f := ddTestFilter(c.platform)
		got := strings.Split(f.Keep(strings.Join(c.kept, "\n")), "\n")
		if len(got) != len(c.kept) {
			t.Errorf("%s: kept %d lines, want %d:\n%s", c.platform, len(got), len(c.kept), strings.Join(got, "\n"))
			continue
		}
		// Keep may rewrite a line's prefix (process name, host cut), so each
		// kept line is checked against what Keep makes of the fixture alone,
		// and must still hold the fixture's own message tail.
		for i, ln := range c.kept {
			if one := ddNorm(f, ln); got[i] != one || one == "" {
				t.Errorf("%s: fixture %d kept as %q, want one line", c.platform, i, one)
			}
		}
	}
}

func TestDeviceDebugMasksOnlyTheLabsValues(t *testing.T) {
	for _, c := range ddCases {
		f := ddTestFilter(c.platform)
		for in, want := range c.masked {
			got := f.Keep(in)
			if want == "" {
				if got != "" {
					t.Errorf("%s: a line meant to drop was kept (%d bytes)", c.platform, len(got))
				}
				continue
			}
			if got != want {
				t.Errorf("%s: %.50q...\n kept %q\n want %q", c.platform, in, got, want)
			}
		}
	}
}

// The binding rule: a sentinel in any field position, or an unknown shape,
// never survives.
func TestDeviceDebugNoSentinelSurvivesKeep(t *testing.T) {
	for _, c := range ddCases {
		f := ddTestFilter(c.platform)
		for i, ln := range c.attacks {
			got := f.Keep(ln)
			for _, s := range ddSentinels {
				if strings.Contains(got, s) {
					t.Errorf("%s: attack %d: a sentinel survived (%d bytes kept)", c.platform, i, len(got))
				}
			}
			if strings.Contains(strings.ToLower(got), "payload") {
				t.Errorf("%s: attack %d: a payload line survived", c.platform, i)
			}
		}
		// And the whole mixed capture, as the harness passes it.
		all := strings.Join(append(append([]string{}, c.kept...), c.attacks...), "\n")
		for key := range c.masked {
			all += "\n" + key
		}
		got := f.Keep(all)
		for _, s := range ddSentinels {
			if strings.Contains(got, s) {
				t.Errorf("%s: a sentinel survived the whole capture", c.platform)
			}
		}
	}
}

// An unknown platform keeps nothing: the filter fails closed.
func TestDeviceDebugUnknownPlatformKeepsNothing(t *testing.T) {
	f := deviceDebugFilter{Platform: "nope", Groups: []string{"port49"}}
	if got := f.Keep(strings.Join(ddCases[1].kept, "\n")); got != "" {
		t.Errorf("kept %d bytes for an unknown platform", len(got))
	}
}

// A hex run or a long token with no keyword is dropped or masked, in a shape
// the allow-list would admit.
func TestDeviceDebugHexAndLongRuns(t *testing.T) {
	f := ddTestFilter("eos")
	for _, in := range []string{
		"Oct 22 05:00:14.001 Aaa: Sending authentication request 1a 2b 3c 4d 5e 6f 70 81 92 to 172.100.100.1",
		"Oct 22 05:00:14.002 Aaa: Sending authentication request 1234567812345678 to 172.100.100.1",
	} {
		if got := f.Keep(in); got != "" {
			t.Errorf("kept %q", got)
		}
	}
	long := "Oct 22 05:00:14.003 Aaa: User " + strings.Repeat("Qq", 20) + " authenticating via method list default"
	if got := f.Keep(long); got != "" && strings.Contains(got, "QqQqQq") {
		t.Errorf("a long token survived")
	}
}

func TestDeviceDebugCountersAndConnections(t *testing.T) {
	for _, c := range ddCases {
		f := ddTestFilter(c.platform)
		kept := f.Keep(strings.Join(c.kept, "\n"))
		s := deviceDebugSummarize(c.platform, kept)
		if s.Opened != c.open || s.Closed != c.closed || s.SingleConnect != c.single || s.ServerDead != c.dead || s.Fallback != c.fallback {
			t.Errorf("%s: counters %+v", c.platform, s)
		}
		if len(s.Conns) != len(c.conns) {
			t.Errorf("%s: %d conns, want %d", c.platform, len(s.Conns), len(c.conns))
			continue
		}
		for i, w := range c.conns {
			g := s.Conns[i]
			if g.Opened == "" || g.Closed == "" ||
				g.Reason != w.Reason || g.Authen != w.Authen || g.Author != w.Author || g.Acct != w.Acct {
				t.Errorf("%s: conn %d = %+v, want reason %q authen %d author %d acct %d, closed set", c.platform, i, g, w.Reason, w.Authen, w.Author, w.Acct)
			}
		}
	}
}

// Requests before any open belong to a connection opened earlier (reuse), and
// two connections keep their own counts: the pipelining question.
func TestDeviceDebugRequestsPerConnection(t *testing.T) {
	f := ddTestFilter("eos")
	in := strings.Join([]string{
		"Oct 22 05:00:01.000 Aaa: Sending authentication request 1 to 172.100.100.1",
		"Oct 22 05:00:02.000 Tacacs: Connecting to server 172.100.100.1 port 49",
		"Oct 22 05:00:02.100 Aaa: Sending authentication request 2 to 172.100.100.1",
		"Oct 22 05:00:02.200 Aaa: Sending authorization request 3 to 172.100.100.1",
		"Oct 22 05:00:03.000 Tacacs: Connecting to server 172.100.100.1 port 49",
		"Oct 22 05:00:03.100 Aaa: Sending accounting request 4 to 172.100.100.1",
		"Oct 22 05:00:04.000 Tacacs: Connection to 172.100.100.1:49 closed",
	}, "\n")
	s := deviceDebugSummarize("eos", f.Keep(in))
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
	// The one still open at the end has no close.
	if s.Conns[0].Closed != "" || s.Conns[1].Closed != "" || s.Conns[2].Closed == "" {
		t.Errorf("a connection that never closed shows a close: %+v", s.Conns)
	}
}

// Every command sequence is a fixed list, and the kept text is all the
// collector returns; the raw output stays in the function.
func TestDeviceDebugCollectFiltersInProcess(t *testing.T) {
	c := ddCaseFor(t, "eos")
	f := ddTestFilter("eos")
	var ran []string
	raw := strings.Join(append(append([]string{}, c.kept...), c.attacks...), "\n")
	run := func(cmd string) (string, error) {
		ran = append(ran, cmd)
		if slices.Contains(deviceDebugCmds["eos"].Collect, cmd) {
			return raw, nil
		}
		return "", nil
	}
	during := false
	kept, err := captureDeviceDebug(f, run, func() error { during = true; return nil })
	if err != nil || !during {
		t.Fatalf("err %v during %v", err, during)
	}
	for _, s := range ddSentinels {
		if strings.Contains(kept, s) {
			t.Errorf("a sentinel reached the collector's result")
		}
	}
	cmds := deviceDebugCmds["eos"]
	if len(ran) == 0 || ran[0] != cmds.Enable[0] || ran[len(ran)-1] != cmds.Disable[len(cmds.Disable)-1] {
		t.Errorf("ran %v", ran)
	}
	// Debug is turned off even when the cell fails or a command errors.
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

// The secret-word rule works on its own: a line a shape admits, whose lab
// value is itself a secret word, is dropped.
func TestDeviceDebugSecretWordDropsAnAdmittedLine(t *testing.T) {
	f := deviceDebugFilter{Platform: "eos", Groups: []string{"password-grp"}}
	if got := f.Keep("Oct 22 05:00:15.001 Aaa: Using server group password-grp"); got != "" {
		t.Errorf("kept %d bytes", len(got))
	}
	f.Groups = []string{"labgrp"}
	if got := f.Keep("Oct 22 05:00:15.002 Aaa: Using server group labgrp"); got == "" {
		t.Errorf("lost an ordinary admitted line")
	}
}
