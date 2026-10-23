package lab

import (
	"errors"
	"net/netip"
	"regexp"
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
	want     []string // exactly what Keep writes for each kept line, written by hand
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
			"*Oct 22 05:00:11.113: TAC+: ver=192 id=1234 received AUTHEN status = PASS",
		},
		want: []string{
			"05:00:11.100 TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5",
			"05:00:11.101 TAC+: Using single connection to 172.100.100.1",
			"05:00:11.102 AAA/AUTHEN/LOGIN (<masked>): Pick method list 'default'",
			"05:00:11.103 TAC+: send AUTHEN/START packet",
			"05:00:11.104 TAC+: (<n>): received authen response status = PASS",
			"05:00:11.105 TAC+: send AUTHOR/REQ packet",
			"05:00:11.106 TAC+:    priv-lvl=15",
			"05:00:11.107 TAC+:    cmd=show",
			"05:00:11.108 TAC+: send ACCT/REQ packet",
			"05:00:11.109 TAC+: Closing TCP/IP <masked> connection to 172.100.100.1/49 (idle timeout)",
			"05:00:11.110 TAC+: Server 172.100.100.1 marked DEAD",
			"05:00:11.111 AAA/AUTHEN/LOGIN (<masked>): Method=LOCAL",
			"05:00:11.112 TPLUS(<masked>) login timer stopped",
			"05:00:11.113 TAC+: ver=192 id=<n> received AUTHEN status = PASS",
		},
		masked: map[string]string{
			"*Oct 22 05:00:12.001: TAC+: Closing TCP/IP 0x7F1234 connection to 172.100.100.1/49 (idle timeout)": "05:00:12.001 TAC+: Closing TCP/IP <masked> connection to 172.100.100.1/49 (idle timeout)",
			"*Oct 22 05:00:12.002: TAC+: Using single connection to 198.51.100.9":                               "05:00:12.002 TAC+: Using single connection to <masked>",
			"*Oct 22 05:00:12.003: AAA/AUTHEN/LOGIN (00000001): Pick method list 'evil-list'":                   "05:00:12.003 AAA/AUTHEN/LOGIN (<masked>): Pick method list '<masked>'",
			"*Oct 22 05:00:12.004: TAC+: Using default tacacs server-group \"evilgroup\"":                       "05:00:12.004 TAC+: Using default tacacs server-group \"<masked>\"",
			"*Oct 22 05:00:12.005: TPLUS: Authentication start packet created for 0(mallory42)":                 "05:00:12.005 TPLUS: Authentication start packet created for <n>(<masked>)",
			"*Oct 22 05:00:12.006: TPLUS: Authentication start packet created for 0(alice07)":                   "05:00:12.006 TPLUS: Authentication start packet created for <n>(alice07)",
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
		conns: []deviceDebugConn{{Opened: "05:00:11.100", Closed: "05:00:11.109", Reason: "idle timeout", Authen: 1, Author: 1, Acct: 1}},
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
		want: []string{
			"05:00:11.100 Tacacs: Connecting to server 172.100.100.1 port 49",
			"05:00:11.101 Tacacs: Single connect flag set",
			"05:00:11.102 Aaa: Sending authentication request <n> to 172.100.100.1",
			"05:00:11.103 Aaa: Received authentication reply <n> status PASS",
			"05:00:11.104 Aaa: Sending authorization request <n> to 172.100.100.1",
			"05:00:11.105 Aaa: Sending accounting request <n> to 172.100.100.1",
			"05:00:11.106 Aaa: priv-lvl=15",
			"05:00:11.107 Tacacs: Connection to 172.100.100.1:49 closed by peer",
			"05:00:11.108 Tacacs: Server 172.100.100.1 marked dead",
			"05:00:11.109 Aaa: Falling back to local for authentication",
			"05:00:11.110 Aaa: User breakglass authenticating via method list default",
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
		conns: []deviceDebugConn{{Opened: "05:00:11.100", Closed: "05:00:11.107", Reason: "closed by peer", Authen: 1, Author: 1, Acct: 1}},
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
		want: []string{
			"05:00:11.100 tacacsd: Opening connection to 172.100.100.1 port 49",
			"05:00:11.101 tacacsd: Single connection negotiated",
			"05:00:11.102 tacacsd: Sending authentication request <n> to 172.100.100.1",
			"05:00:11.103 tacacsd: Received authentication reply <n> status PASS",
			"05:00:11.104 tacacsd: Sending authorization request <n> to 172.100.100.1",
			"05:00:11.105 tacacsd: Sending accounting request <n> to 172.100.100.1",
			"05:00:11.106 aaad: service=shell",
			"05:00:11.107 tacacsd: Closing connection to 172.100.100.1 port 49 (remote reset)",
			"05:00:11.108 tacacsd: Server 172.100.100.1 marked dead",
			"05:00:11.109 aaad: Falling back to local for authentication",
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
		conns: []deviceDebugConn{{Opened: "05:00:11.100", Closed: "05:00:11.107", Reason: "remote reset", Authen: 1, Author: 1, Acct: 1}},
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
			"Oct 22 05:00:11.108 vjunos mgd[900]: server 172.100.100.1 marked dead",
			"Oct 22 05:00:11.109 vjunos mgd[900]: falling back to local",
		},
		want: []string{
			"05:00:11.100 mgd: connecting to server 172.100.100.1 port 49",
			"05:00:11.101 mgd: single-connect flag set",
			"05:00:11.102 mgd: sending authentication request <n> to 172.100.100.1",
			"05:00:11.103 mgd: received authentication reply <n> status PASS",
			"05:00:11.104 mgd: sending authorization request <n> to 172.100.100.1",
			"05:00:11.105 mgd: sending accounting request <n> to 172.100.100.1",
			"05:00:11.106 mgd: priv-lvl=15",
			"05:00:11.108 mgd: server 172.100.100.1 marked dead",
			"05:00:11.109 mgd: falling back to local",
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
		// Junos has no close line (step 1), so the connection never closes here.
		open: 1, closed: 0, single: 1, dead: 1, fallback: 1,
		conns: []deviceDebugConn{{Opened: "05:00:11.100", Authen: 1, Author: 1, Acct: 1}},
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
func ddNorm(f deviceDebugFilter, ln string) string { return ddKeep(f, ln) }

func ddKeep(f deviceDebugFilter, text string) string { return string(f.Keep(text)) }

func TestDeviceDebugKeepsTheAllowedShapes(t *testing.T) {
	for _, c := range ddCases {
		f := ddTestFilter(c.platform)
		if len(c.want) != len(c.kept) {
			t.Fatalf("%s: %d fixtures, %d expected lines", c.platform, len(c.kept), len(c.want))
		}
		got := strings.Split(ddKeep(f, strings.Join(c.kept, "\n")), "\n")
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: kept\n%s\nwant\n%s", c.platform, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
}

func TestDeviceDebugMasksOnlyTheLabsValues(t *testing.T) {
	for _, c := range ddCases {
		f := ddTestFilter(c.platform)
		for in, want := range c.masked {
			got := ddKeep(f, in)
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
			got := ddKeep(f, ln)
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
		got := ddKeep(f, all)
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
	if got := ddKeep(f, strings.Join(ddCases[1].kept, "\n")); got != "" {
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
		if got := ddKeep(f, in); got != "" {
			t.Errorf("kept %q", got)
		}
	}
	long := "Oct 22 05:00:14.003 Aaa: User " + strings.Repeat("Qq", 20) + " authenticating via method list default"
	if got := ddKeep(f, long); got != "" {
		t.Errorf("a line with a long token was kept")
	}
	// Sixteen contiguous hex digits drop the line even where the shape and the
	// lab list admit the value.
	h := deviceDebugFilter{Platform: "eos", Groups: []string{"0123456789abcdef"}}
	if got := ddKeep(h, "Oct 22 05:00:14.005 Aaa: Using server group 0123456789abcdef"); got != "" {
		t.Errorf("a lab value that is a hex run was kept")
	}
	// A base64-looking run drops the line even where the shape admits it:
	// here the lab's own group name is the long run.
	g := deviceDebugFilter{Platform: "eos", Groups: []string{strings.Repeat("Zz", 14)}}
	if got := ddKeep(g, "Oct 22 05:00:14.004 Aaa: Using server group "+strings.Repeat("Zz", 14)); got != "" {
		t.Errorf("a lab value that is a long run was kept")
	}
}

func TestDeviceDebugCountersAndConnections(t *testing.T) {
	for _, c := range ddCases {
		f := ddTestFilter(c.platform)
		kept := ddKeep(f, strings.Join(c.kept, "\n"))
		s := deviceDebugSummarize(c.platform, deviceDebugKept(kept))
		if s.Opened != c.open || s.Closed != c.closed || s.SingleConnect != c.single || s.ServerDead != c.dead || s.Fallback != c.fallback {
			t.Errorf("%s: counters %+v", c.platform, s)
		}
		if len(s.Conns) != len(c.conns) {
			t.Errorf("%s: %d conns, want %d", c.platform, len(s.Conns), len(c.conns))
			continue
		}
		for i, w := range c.conns {
			g := s.Conns[i]
			if g != w {
				t.Errorf("%s: conn %d = %+v, want %+v", c.platform, i, g, w)
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
		if cmd == deviceDebugCmds["eos"].Collect[0] {
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
		if strings.Contains(string(kept), s) {
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
	if got := ddKeep(f, "Oct 22 05:00:15.001 Aaa: Using server group password-grp"); got != "" {
		t.Errorf("kept %d bytes", len(got))
	}
	f.Groups = []string{"labgrp"}
	if got := ddKeep(f, "Oct 22 05:00:15.002 Aaa: Using server group labgrp"); got == "" {
		t.Errorf("lost an ordinary admitted line")
	}
}

// ddNumberRuns puts an OTP-shaped number (6 and 8 digits) in each numeric
// position of each line in turn, after the time prefix and outside addresses,
// and reports every position where the number survived Keep. It returns how
// many positions it tried.
func ddNumberRuns(lines []string, keep func(string) string) (tried int, leaked []string) {
	prefix := regexp.MustCompile(`\d\d:\d\d:\d\d(\.\d+)?`)
	runs := regexp.MustCompile(`\d+`)
	for _, ln := range lines {
		loc := prefix.FindStringIndex(ln)
		if loc == nil {
			continue
		}
		for _, r := range runs.FindAllStringIndex(ln, -1) {
			if r[0] < loc[1] || (r[0] > 0 && ln[r[0]-1] == '.') || (r[1] < len(ln) && ln[r[1]] == '.') {
				continue
			}
			for _, otp := range []string{"481516", "48151623"} {
				tried++
				if strings.Contains(keep(ln[:r[0]]+otp+ln[r[1]:]), otp) {
					leaked = append(leaked, ln[:loc[1]]+"... position "+ln[r[0]:r[1]]+" with "+otp)
				}
			}
		}
	}
	return tried, leaked
}

// F2: a number is kept only in a named position within bounds, so a 6- or
// 8-digit OTP-shaped number in any numeric position never survives.
func TestDeviceDebugNumbersAreBounded(t *testing.T) {
	for _, c := range ddCases {
		f := ddTestFilter(c.platform)
		tried, leaked := ddNumberRuns(c.kept, func(s string) string { return ddKeep(f, s) })
		if tried == 0 {
			t.Errorf("%s: no numeric positions tried", c.platform)
		}
		for _, l := range leaked {
			t.Errorf("%s: a number survived at %s", c.platform, l)
		}
	}
	// Ports are 1-65535, ids are written <n>.
	f := ddTestFilter("eos")
	for in, want := range map[string]string{
		"Oct 22 05:00:20.001 Tacacs: Connecting to server 172.100.100.1 port 65535": "05:00:20.001 Tacacs: Connecting to server 172.100.100.1 port 65535",
		"Oct 22 05:00:20.002 Tacacs: Connecting to server 172.100.100.1 port 65536": "",
		"Oct 22 05:00:20.003 Tacacs: Connecting to server 172.100.100.1 port 0":     "",
		"Oct 22 05:00:20.004 Aaa: Sending accounting request 99 to 172.100.100.1":   "05:00:20.004 Aaa: Sending accounting request <n> to 172.100.100.1",
	} {
		if got := ddKeep(f, in); got != want {
			t.Errorf("%.60q: kept %q, want %q", in, got, want)
		}
	}
	x := ddTestFilter("iosxe")
	if got := ddKeep(x, "*Oct 22 05:00:20.005: TAC+: ver=1920 id=7 received AUTHEN status = PASS"); got != "" {
		t.Errorf("a four-digit version was kept")
	}
}

// F3: a username is kept only when the whole field is a lab name. A lab name
// as the prefix or suffix of the field, or in another case, is masked.
func TestDeviceDebugUserIsAnExactLabName(t *testing.T) {
	f := ddTestFilter("eos")
	for _, u := range []string{"alice07x", "xalice07", "breakglassx", "xbreakglass", "Alice07", "BREAKGLASS", "alice7", "alice123", "alice07.evil"} {
		in := "Oct 22 05:00:21.001 Aaa: User " + u + " authenticating via method list default"
		want := "05:00:21.001 Aaa: User <masked> authenticating via method list default"
		if got := ddKeep(f, in); got != want {
			t.Errorf("a user field was not masked: kept %d bytes", len(got))
		}
	}
	for _, u := range []string{"alice07", "alice99", "breakglass"} {
		in := "Oct 22 05:00:21.002 Aaa: User " + u + " authenticating via method list default"
		if got := ddKeep(f, in); !strings.Contains(got, "User "+u+" ") {
			t.Errorf("lost the lab user %s", u)
		}
	}
}

// F1: an error from collecting or disabling must not carry the device's
// output. The device buffer holds the sentinel and a step fails at each of
// the three stages; the sentinel is in neither the returned error nor
// anything else the function returns.
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

// F7: a failed cell still yields the filtered debug, and returns its own error.
func TestDeviceDebugCollectsWhenTheCellFails(t *testing.T) {
	c := ddCaseFor(t, "eos")
	f := ddTestFilter("eos")
	raw := strings.Join(append(append([]string{}, c.kept...), c.attacks...), "\n")
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
	if string(kept) != strings.Join(c.want, "\n") {
		t.Errorf("kept %d bytes after a failed cell, want the filtered debug (%d)", len(kept), len(strings.Join(c.want, "\n")))
	}
	// A collect step that fails with a partial capture still keeps it, filtered.
	run2 := func(cmd string) (string, error) {
		if cmd == deviceDebugCmds["eos"].Collect[0] {
			return raw, errors.New("timeout")
		}
		return "", nil
	}
	kept, err = captureDeviceDebug(f, run2, func() error { return nil })
	if err == nil || string(kept) != strings.Join(c.want, "\n") {
		t.Errorf("partial capture: err %v, %d bytes", err, len(kept))
	}
}

// F9: the counters take kept text only. Handed text that was never filtered
// (an explicit conversion), the close reason is still one of the fixed words.
func TestDeviceDebugSummaryReadsNoFreeText(t *testing.T) {
	raw := deviceDebugKept("05:00:01.000 TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5\n" +
		"05:00:02.000 TAC+: Closing TCP/IP x connection to y (fake free text)")
	s := deviceDebugSummarize("iosxe", raw)
	for _, c := range s.Conns {
		if c.Reason != "" {
			t.Errorf("a free-text reason was read")
		}
	}
	if s.Closed != 0 {
		t.Errorf("an unlisted close was counted")
	}
}

// F10: the raw Junos trace file is cleared after it is collected, and every
// file a Collect reads is cleared by Disable.
func TestDeviceDebugJunosClearsTheTraceFile(t *testing.T) {
	c := deviceDebugCmds["junos"]
	if !slices.Contains(c.Disable, "clear log p49-tacplus.log") {
		t.Errorf("Disable does not clear the trace file: %v", c.Disable)
	}
	if !slices.Contains(c.Collect, "show log p49-tacplus.log") {
		t.Errorf("Collect reads another file: %v", c.Collect)
	}
}
