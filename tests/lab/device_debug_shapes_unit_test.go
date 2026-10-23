package lab

import (
	"regexp"
	"strings"
	"testing"
)

// The fixtures for the shapes written from the step 1 samples (device-debug
// shapes follow-up, step 2). Like the others they are invented: the spelling in
// a position the sample showed as `_` is a guess, so a test that a line is kept
// proves the filter's rule, not the device's wording. Each case joins ddCases,
// so the keep, mask, sentinel, number-run and counter tests cover it too. Every
// attack puts a made-up secret, token, OTP or hex run in a value position.

var ddShapeCases = []ddCase{
	{
		platform: "iosxr",
		kept: []string{
			"RP/0/RP0/CPU0:Oct 22 05:00:11.090 UTC: tacacsd[1000]: socket created: 172.100.100.1/49",
			"RP/0/RP0/CPU0 Oct 22 05:00:11.091 UTC: tacacsd[1000]: socket bound 3 with local address 172.100.100.41",
			"0/RP0/CPU0 Oct 22 05:00:11.092 UTC: tacacsd[1000]: socket connected to 172.100.100.1/49",
			"0/RP0/CPU0:Oct 22 05:00:11.093 UTC: tacacsd[1000]: socket 12 172.100.100.1/49 opened",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.094 UTC: tacacsd[1000]: packet: start: login session 17 server 172.100.100.1/49 socket 3 tls 1",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.095 UTC: tacacsd[1000]: session 18 packet author start server 172.100.100.1",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.096 UTC: tacacsd[1000]: packet request start session 19 server 172.100.100.1/49",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.097 UTC: tacacsd[1000]: reply: session 17 from server 172.100.100.1/49",
			"RP/0/RP0/CPU0:Oct 22 05:00:11.098 UTC: tacacsd[1000]: connection closed to 172.100.100.1 port 49",
		},
		want: []string{
			"05:00:11.090 tacacsd: socket created: 172.100.100.1/49",
			"05:00:11.091 tacacsd: socket bound <masked> with <masked> address 172.100.100.41",
			"05:00:11.092 tacacsd: socket connected to 172.100.100.1/49",
			"05:00:11.093 tacacsd: socket <masked> 172.100.100.1/49 opened",
			"05:00:11.094 tacacsd: packet: start: login session <n> server 172.100.100.1/49 socket <masked> tls <masked>",
			"05:00:11.095 tacacsd: session <n> packet author start server 172.100.100.1",
			"05:00:11.096 tacacsd: packet request start session <n> server 172.100.100.1/49",
			"05:00:11.097 tacacsd: reply: session <n> from server 172.100.100.1/49",
			"05:00:11.098 tacacsd: connection closed to 172.100.100.1 port 49",
		},
		masked: map[string]string{
			"RP/0/RP0/CPU0:Oct 22 05:00:12.001 UTC: tacacsd[1000]: socket created: 10.66.66.66/49":     "05:00:12.001 tacacsd: socket created: <masked>/49",
			"RP/0/RP0/CPU0:Oct 22 05:00:12.002 UTC: tacacsd[1000]: socket connected to 10.66.66.66/49": "05:00:12.002 tacacsd: socket connected to <masked>/49",
			// An address position holds an address (dotted quad or colon-hex), not any word.
			"RP/0/RP0/CPU0:Oct 22 05:00:12.003 UTC: tacacsd[1000]: reply: session 17 from server frobwidget":                "",
			"RP/0/RP0/CPU0:Oct 22 05:00:12.004 UTC: tacacsd[1000]: socket bound hunter9 with mallory42 address 10.66.66.66": "05:00:12.004 tacacsd: socket bound <masked> with <masked> address <masked>",
			"RP/0/RP0/CPU0:Oct 22 05:00:12.005 UTC: tacacsd[1000]: connection closed to 172.100.100.1 port 65536":           "",
			// A session id that is not a number is an opaque value.
			"RP/0/RP0/CPU0:Oct 22 05:00:12.006 UTC: tacacsd[1000]: packet start login session 0xfeedface server 172.100.100.1": "05:00:12.006 tacacsd: packet start login session <masked> server 172.100.100.1",
			"RP/0/RP0/CPU0:Oct 22 05:00:12.007 UTC: sshd[1000]: socket connected to 172.100.100.1/49":                          "",
			// A secret word or a hex run in an opaque position drops the line: the rule, not the mask, holds it.
			"RP/0/RP0/CPU0:Oct 22 05:00:12.008 UTC: tacacsd[1000]: socket bound password with local address 172.100.100.41":         "",
			"RP/0/RP0/CPU0:Oct 22 05:00:12.009 UTC: tacacsd[1000]: socket bound deadbeefcafe0123 with local address 172.100.100.41": "",
		},
		attacks: []string{
			"RP/0/RP0/CPU0:Oct 22 05:00:13.001 UTC: tacacsd[1000]: packet start login session 17 server 172.100.100.1 password hunter9",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.002 UTC: tacacsd[1000]: payload(hex): c0 01 02 01 de ad be ef 00 00 00 05",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.003 UTC: tacacsd[1000]: reply: session 17 from server 172.100.100.1 faketok123abc",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.004 UTC: tacacsd[1000]: socket created: frobwidget 42",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.005 UTC: tacacsd[1000]: packet author start session deadbeefcafe0123 server 172.100.100.1",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.006 UTC: tacacsd[1000]: packet request start session 19 server QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.007 UTC: tacacsd[1000]: socket connected to 172.100.100.1 evilgroup",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.008 UTC: tacacsd[1000]: socket bound 3 with fakesecret77 address 172.100.100.1",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.009 UTC: tacacsd[1000]: packet start login session 17 server 172.100.100.1 socket 3 tls 1 mallory42",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.010 UTC: tacacsd[1000]: socket connected to 172.100.100.1/49 hunter9",
			"RP/0/RP0/CPU0:Oct 22 05:00:13.011 UTC: tacacsd[1000]: hunter9 now frobwidget socket connected to 172.100.100.1/49",
		},
		open: 1, closed: 1,
		conns: []deviceDebugConn{{Opened: "05:00:11.092", Closed: "05:00:11.098", Authen: 1, Author: 1, Acct: 1}},
	},
	{
		platform: "iosxe",
		kept: []string{
			"*Oct 22 05:00:11.200: TPLUS: connected socket 5",
			"*Oct 22 05:00:11.201: TPLUS: immediate connect 3, new 0x7F12",
			"*Oct 22 05:00:11.202: TAC+: opened 172.100.100.1/49",
			"*Oct 22 05:00:11.203: TAC+: tacacs secure connection established with peer 172.100.100.1/49",
			"*Oct 22 05:00:11.204: TPLUS: Accounting request created for 0(alice07)",
			"*Oct 22 05:00:11.205: TPLUS: Authorization request created for 0(mallory42)",
			"*Oct 22 05:00:11.206: TPLUS: processing authentication login request id 5",
			"*Oct 22 05:00:11.207: TPLUS(00000001)/0/7F1234: Processing the reply packet",
			"*Oct 22 05:00:11.208: TAC+: using previously known server 172.100.100.1 from group port49",
			"*Oct 22 05:00:11.209: TAC+: tacacs-secure: session: closed: tacacs secure connection closed with peer 172.100.100.1 port 49",
		},
		want: []string{
			"05:00:11.200 TPLUS: connected socket <masked>",
			"05:00:11.201 TPLUS: immediate connect <masked>, new <masked>",
			"05:00:11.202 TAC+: opened 172.100.100.1/49",
			"05:00:11.203 TAC+: tacacs secure connection established with peer 172.100.100.1/49",
			"05:00:11.204 TPLUS: Accounting request created for <n>(alice07)",
			"05:00:11.205 TPLUS: Authorization request created for <n>(<masked>)",
			"05:00:11.206 TPLUS: processing authentication <masked> request id <n>",
			"05:00:11.207 TPLUS(<masked>)/<n>/<masked> Processing the reply packet",
			"05:00:11.208 TAC+: using previously <masked> server 172.100.100.1 from group port49",
			"05:00:11.209 TAC+: tacacs-secure: session: closed: tacacs secure connection closed with peer 172.100.100.1 port 49",
		},
		masked: map[string]string{
			"*Oct 22 05:00:12.001: TAC+: tacacs secure connection established with peer 10.66.66.66/49":    "05:00:12.001 TAC+: tacacs secure connection established with peer <masked>/49",
			"*Oct 22 05:00:12.002: TAC+: opened 10.66.66.66/49":                                            "05:00:12.002 TAC+: opened <masked>/49",
			"*Oct 22 05:00:12.003: TAC+: using previously known server 172.100.100.1 from group evilgroup": "05:00:12.003 TAC+: using previously <masked> server 172.100.100.1 from group <masked>",
			"*Oct 22 05:00:12.004: TPLUS: Accounting request created for 0(mallory42)":                     "05:00:12.004 TPLUS: Accounting request created for <n>(<masked>)",
			"*Oct 22 05:00:12.005: TPLUS: Accounting request created for frobwidget":                       "05:00:12.005 TPLUS: Accounting request created for <masked>",
			// A port out of range is not kept: it falls in the bounded trailing span, masked.
			"*Oct 22 05:00:12.006: TAC+: tacacs secure connection closed with peer 172.100.100.1 port 65536": "05:00:12.006 TAC+: tacacs secure connection closed with peer 172.100.100.1 <masked> <masked>",
			"*Oct 22 05:00:12.007: TPLUS: processing authentication login request id 0xfeedface":             "",
			"*Oct 22 05:00:12.008: TPLUS(00000001)/0/7F1234: Processing the reply packet hunter9":            "",
			"*Oct 22 05:00:12.009: TPLUS: connected socket secret":                                           "",
			"*Oct 22 05:00:12.010: TPLUS: connected socket deadbeefcafe0123":                                 "",
		},
		attacks: []string{
			"*Oct 22 05:00:13.001: TPLUS: connected socket 5 password hunter9",
			"*Oct 22 05:00:13.002: TPLUS: immediate connect 3, new 0x7F12 token faketok123abc",
			"*Oct 22 05:00:13.003: TAC+: tacacs secure connection established with peer 172.100.100.1/49 mallory42",
			"*Oct 22 05:00:13.004: TPLUS: Accounting request created for 0(alice07) fakesecret77",
			"*Oct 22 05:00:13.005: TPLUS: processing authentication login request id 5 deadbeefcafe0123",
			"*Oct 22 05:00:13.006: TPLUS: payload(hex): c0 01 02 01 de ad be ef 00 00 00 05",
			"*Oct 22 05:00:13.007: TPLUS: Authorization request created for QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			"*Oct 22 05:00:13.008: TAC+: tacacs secure connection closed with peer frobwidget 42",
			"*Oct 22 05:00:13.009: TAC+: opened 172.100.100.1/49 evilgroup",
			"*Oct 22 05:00:13.010: hunter9 now frobwidget TAC+: opened 172.100.100.1/49",
		},
		open: 1, closed: 1,
		conns: []deviceDebugConn{{Opened: "05:00:11.203", Closed: "05:00:11.209", Authen: 1, Author: 1, Acct: 1}},
	},
	{
		platform: "eos",
		kept: []string{
			"2026-10-22 05:00:11.100000 21 Aaa Tacacs: created socket 5 172.100.100.1",
			"2026-10-22 05:00:11.101000 21 Aaa Tacacs: tac_send_authen 7",
			"2026-10-22 05:00:11.102000 21 Aaa Tacacs: tac_send_author",
			"2026-10-22 05:00:11.103000 21 Aaa Tacacs: tac_send_acct 9",
			"2026-10-22 05:00:11.104000 21 Aaa Tacacs: tac_send_author_status PASS",
			"2026-10-22 05:00:11.105000 21 Aaa Tacacs: tac_send_author_status 3",
			"2026-10-22 05:00:11.106000 21 Aaa Tacacs: tac_create_author",
			"2026-10-22 05:00:11.107000 21 Aaa Tacacs: tac_send_author failed: connect: connection refused",
			"2026-10-22 05:00:11.108000 21 Aaa Tacacs: tls session 3 for sess default",
			"2026-10-22 05:00:11.109000 21 Aaa Tacacs: authorization from 172.100.100.41",
			"2026-10-22 05:00:11.110000 21 Aaa Tacacs: accounting request 12 exec",
			"2026-10-22 05:00:11.111000 21 Aaa Tacacs: error: ssl failed 7 tls",
			"Oct 22 05:00:11.112 Aaa: Tacacs: close 5",
		},
		want: []string{
			"05:00:11.100000 Tacacs: created socket <masked> 172.100.100.1",
			"05:00:11.101000 Tacacs: tac_send_authen <masked>",
			"05:00:11.102000 Tacacs: tac_send_author",
			"05:00:11.103000 Tacacs: tac_send_acct <masked>",
			"05:00:11.104000 Tacacs: tac_send_author_status PASS",
			"05:00:11.105000 Tacacs: tac_send_author_status <n>",
			"05:00:11.106000 Tacacs: tac_create_author",
			"05:00:11.107000 Tacacs: tac_send_author failed: connect: connection <masked>",
			"05:00:11.108000 Tacacs: tls session <masked> for <masked> default",
			"05:00:11.109000 Tacacs: authorization from 172.100.100.41",
			"05:00:11.110000 Tacacs: accounting request <masked> exec",
			"05:00:11.111000 Tacacs: error: ssl failed <masked> tls",
			"05:00:11.112 Aaa: Tacacs: close <masked>",
		},
		masked: map[string]string{
			"2026-10-22 05:00:12.001000 21 Aaa Tacacs: created socket 5 10.66.66.66":                  "05:00:12.001000 Tacacs: created socket <masked> <masked>",
			"2026-10-22 05:00:12.002000 21 Aaa Tacacs: authorization from 10.66.66.66":                "05:00:12.002000 Tacacs: authorization from <masked>",
			"2026-10-22 05:00:12.003000 21 Aaa Tacacs: close faketok123abc":                           "05:00:12.003000 Tacacs: close <masked>",
			"2026-10-22 05:00:12.004000 21 Aaa Tacacs: tac_send_author_status 0xfeedface":             "",
			"2026-10-22 05:00:12.005000 21 Aaa Tacacs: created socket frobwidget 42 hunter9":          "",
			"2026-10-22 05:00:12.006000 21 Sshd Tacacs: tac_send_author hunter9":                      "05:00:12.006000 Tacacs: tac_send_author <masked>",
			"2026-10-22 05:00:12.007000 21 Aaa Tacacs: created socket token 172.100.100.1":            "",
			"2026-10-22 05:00:12.008000 21 Aaa Tacacs: created socket deadbeefcafe0123 172.100.100.1": "",
		},
		attacks: []string{
			"2026-10-22 05:00:13.001000 21 Aaa Tacacs: tac_send_author_status hunter9",
			"2026-10-22 05:00:13.002000 21 Aaa Tacacs: tls session 3 for 7 default password hunter9",
			"2026-10-22 05:00:13.003000 21 Aaa Tacacs: tac_send_author failed: connect: connection QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			"2026-10-22 05:00:13.004000 21 Aaa Tacacs: created socket deadbeefcafe0123",
			"2026-10-22 05:00:13.005000 21 Aaa Tacacs: payload(hex): c0 01 02 01 de ad be ef 00 00 00 05",
			"2026-10-22 05:00:13.006000 21 Aaa Tacacs: accounting request 12 exec fakesecret77",
			"2026-10-22 05:00:13.007000 21 Aaa Tacacs: error: ssl failed 7 tls token faketok123abc",
			"2026-10-22 05:00:13.008000 21 Aaa Tacacs: authorization from 172.100.100.41 mallory42",
			"2026-10-22 05:00:13.009000 21 Aaa Tacacs: tac_send_acct 9 evilgroup",
			"2026-10-22 05:00:13.010000 21 Aaa Tacacs: close 5 frobwidget",
			"2026-10-22 05:00:13.011000 21 Aaa Tacacs: hunter9 now frobwidget created socket 5 172.100.100.1",
		},
		open: 1, closed: 1,
		conns: []deviceDebugConn{{Opened: "05:00:11.100000", Closed: "05:00:11.112", Authen: 1, Author: 1, Acct: 1}},
	},
	{
		platform: "junos",
		kept: []string{
			"Oct 22 05:00:11.100000 authd[900]: connect to 172.100.100.1 port 49",
			"Oct 22 05:00:11.101000 authd[900]: connect fail: 172.100.100.1",
			"Oct 22 05:00:11.102000 authd[900]: connection state 4",
			"Oct 22 05:00:11.103000 authd[900]: opened 172.100.100.1/49",
			"Oct 22 05:00:11.104000 authd[900]: server 0 name tacacs1",
			"Oct 22 05:00:11.105000 authd[900]: address 172.100.100.1",
			"Oct 22 05:00:11 vjunos authd[900]: connection received from 172.100.100.41",
			"Oct 22 05:00:12 vjunos authd[900]: open session open sent",
			"Oct 22 05:00:12 vjunos authd[900]: connect failed",
			"Oct 22 05:00:13 vjunos authd[900]: tacplus_send: sent tacacs+ authentication request message, 7",
			"Oct 22 05:00:13 vjunos authd[900]: sent tacacs+ authorization request message",
			"Oct 22 05:00:14 vjunos authd[900]: sent tacacs+ accounting request message, 9",
			"Oct 22 05:00:14 vjunos authd[900]: send failed: authentication with error TLS 5 has failed",
		},
		want: []string{
			"05:00:11.100000 authd: connect to 172.100.100.1 port 49",
			"05:00:11.101000 authd: connect fail: 172.100.100.1",
			"05:00:11.102000 authd: connection state <masked>",
			"05:00:11.103000 authd: opened 172.100.100.1/49",
			"05:00:11.104000 authd: server <masked> name <masked>",
			"05:00:11.105000 authd: address 172.100.100.1",
			"05:00:11 authd: connection received from 172.100.100.41",
			"05:00:12 authd: open session open sent",
			"05:00:12 authd: connect failed",
			"05:00:13 authd: <masked> sent tacacs+ authentication request message, <n>",
			"05:00:13 authd: sent tacacs+ authorization request message",
			"05:00:14 authd: sent tacacs+ accounting request message, <n>",
			"05:00:14 authd: <masked> <masked> authentication with error TLS <masked> has failed",
		},
		masked: map[string]string{
			"Oct 22 05:00:12.001000 authd[900]: connect to 10.66.66.66 port 49":                      "05:00:12.001000 authd: connect to <masked> port 49",
			"Oct 22 05:00:12.002000 authd[900]: opened 10.66.66.66/49":                               "05:00:12.002000 authd: opened <masked>/49",
			"Oct 22 05:00:12.003000 authd[900]: connection received from frobwidget":                 "05:00:12.003000 authd: connection received from <masked>",
			"Oct 22 05:00:12.004000 authd[900]: connect to 172.100.100.1 port 65536":                 "",
			"Oct 22 05:00:12.005000 authd[900]: sent tacacs+ accounting request message, 0xfeedface": "",
			"Oct 22 05:00:12.006000 cron[900]: connect to 172.100.100.1 port 49":                     "",
			// A secret word or a hex run in an opaque position drops the line.
			"Oct 22 05:00:12.007000 authd[900]: connection state payload":          "",
			"Oct 22 05:00:12.008000 authd[900]: connection state deadbeefcafe0123": "",
		},
		attacks: []string{
			"Oct 22 05:00:13.001000 authd[900]: connect to 172.100.100.1 port 49 password hunter9",
			"Oct 22 05:00:13.002000 authd[900]: opened 172.100.100.1/49 token faketok123abc",
			"Oct 22 05:00:13.003000 authd[900]: sent tacacs+ accounting request message, 7 fakesecret77",
			"Oct 22 05:00:13.004000 authd[900]: connection received from 172.100.100.41 mallory42",
			"Oct 22 05:00:13.005000 authd[900]: payload(hex): c0 01 02 01 de ad be ef 00 00 00 05",
			"Oct 22 05:00:13.006000 authd[900]: connect fail: QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			"Oct 22 05:00:13.007000 authd[900]: server 0 name deadbeefcafe0123",
			"Oct 22 05:00:13.008000 authd[900]: connect to frobwidget 42 evilgroup",
			"Oct 22 05:00:13.009000 authd[900]: address 172.100.100.1 10.66.66.66",
			"Oct 22 05:00:13.010000 authd[900]: authentication with error tls 5 has failed for mallory42",
			"Oct 22 05:00:13.011000 authd[900]: hunter9 now frobwidget now evilgroup opened 172.100.100.1/49",
		},
		open: 1, closed: 0,
		conns: []deviceDebugConn{{Opened: "05:00:11.103000", Authen: 1, Author: 1, Acct: 1}},
	},
}

func init() { ddCases = append(ddCases, ddShapeCases...) }

// Junos has no close line: the summary says the close is unknown, and the arm
// text does not print 0.
func TestDeviceDebugJunosCloseIsUnknownNotZero(t *testing.T) {
	c := ddCaseFor(t, "junos")
	for _, cc := range ddShapeCases {
		if cc.platform == "junos" {
			c = cc
		}
	}
	kept := ddKeep(ddTestFilter("junos"), strings.Join(c.kept, "\n"))
	s := deviceDebugSummarize("junos", deviceDebugKept(kept))
	if !s.CloseUnknown || s.Closed != 0 {
		t.Errorf("junos summary %+v", s)
	}
	text := ddArmSummary("junos", "tls_token_login", deviceDebugKept(kept), 40, nil)
	if !strings.Contains(text, "closed=unknown") || strings.Contains(text, "closed=0") || !strings.Contains(text, "closed=unknown reason") {
		t.Errorf("the arm text does not say the close is unknown:\n%s", text)
	}
	// Another platform still counts.
	e := deviceDebugSummarize("eos", deviceDebugKept("05:00:01.000 Tacacs: close <masked>"))
	if e.CloseUnknown || e.Closed != 1 {
		t.Errorf("eos summary %+v", e)
	}
	if !strings.Contains(ddArmSummary("eos", "c", "", 0, nil), "closed=0") {
		t.Errorf("eos arm text lost its zero")
	}
}

// The XR line prefix: the node name, its colon or space, and the zone all take
// the same message; a prefix without the process name drops the line.
func TestDeviceDebugXRLinePrefix(t *testing.T) {
	f := ddTestFilter("iosxr")
	const msg = "socket connected to 172.100.100.1/49"
	for _, pre := range []string{
		"RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacsd[1000]: ",
		"RP/0/RP0/CPU0 Oct 22 05:00:11.100 UTC: tacacsd[1000]: ",
		"0/RP0/CPU0 Oct 22 05:00:11.100 UTC: tacacsd[7]: ",
		"RP/0/RP0/CPU0:Oct 22 2026 05:00:11.100 CEST: tacacsd[1000]: ",
		"05:00:11.100 UTC: tacacsd[1000]: ",
	} {
		if got := ddKeep(f, pre+msg); got != "05:00:11.100 tacacsd: "+msg {
			t.Errorf("%q: kept %q", pre, got)
		}
	}
	for _, pre := range []string{
		"RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: ",
		"RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacs[1000]: ",
		"RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: sshd[1000]: ",
		"RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacsd[1000] ",
	} {
		if got := ddKeep(f, pre+msg); got != "" {
			t.Errorf("%q: kept %d bytes", pre, len(got))
		}
	}
}

// Priority 2: the IOS XE lifecycle counts connections from the secure
// connection lines, and every request line counts once.
func TestDeviceDebugIOSXELifecycleCountsConnectionsAndRequests(t *testing.T) {
	f := ddTestFilter("iosxe")
	in := strings.Join([]string{
		"*Oct 22 05:00:01.000: TPLUS: immediate connect 3, new 0x7F12",
		"*Oct 22 05:00:01.001: TPLUS: connected socket 5",
		"*Oct 22 05:00:01.002: TAC+: tacacs secure connection established with peer 172.100.100.1/49",
		"*Oct 22 05:00:01.003: TPLUS: processing authentication login request id 1",
		"*Oct 22 05:00:01.004: TPLUS: Authorization request created for 0(alice07)",
		"*Oct 22 05:00:02.000: TAC+: tacacs secure connection established with peer 172.100.100.1/49",
		"*Oct 22 05:00:02.001: TPLUS: Accounting request created for 0(alice07)",
		"*Oct 22 05:00:03.000: TAC+: tacacs secure connection closed with peer 172.100.100.1/49",
	}, "\n")
	s := deviceDebugSummarize("iosxe", f.Keep(in))
	if s.Opened != 2 || s.Closed != 1 || len(s.Conns) != 2 {
		t.Fatalf("summary %+v", s)
	}
	if c := s.Conns[0]; c.Authen != 1 || c.Author != 1 || c.Acct != 0 || c.Closed != "" {
		t.Errorf("conn 0 = %+v", c)
	}
	if c := s.Conns[1]; c.Authen != 0 || c.Author != 0 || c.Acct != 1 || c.Closed != "05:00:03.000" {
		t.Errorf("conn 1 = %+v", c)
	}
}

// The vocabulary holds the five words of this step and still not aaa (a hex
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
	if !regexp.MustCompile(`^[a-zA_ ]*$`).MatchString(got) {
		t.Errorf("alphabet %q", got)
	}
}

// A plain sentinel in each opaque position comes out <masked>: the opaque kind,
// not the shape's wording, is what hides it.
func TestDeviceDebugOpaquePositionsMaskPlainSentinels(t *testing.T) {
	for _, c := range []struct{ platform, in, want string }{
		{"iosxr", "RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacsd[1000]: socket 12 172.100.100.1/49 opened frobwidget",
			"05:00:11.100 tacacsd: socket <masked> 172.100.100.1/49 opened <masked>"},
		{"iosxr", "RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacsd[1000]: packet: start: login session 17 server 172.100.100.1/49 socket frobwidget tls hunter9",
			"05:00:11.100 tacacsd: packet: start: login session <n> server 172.100.100.1/49 socket <masked> tls <masked>"},
		{"iosxr", "RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacsd[1000]: socket connected hunter9 to 172.100.100.1/49",
			"05:00:11.100 tacacsd: socket connected <masked> to 172.100.100.1/49"},
		{"iosxr", "RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacsd[1000]: socket created frobwidget to 10.66.66.66/49",
			"05:00:11.100 tacacsd: socket created <masked> <masked> <masked>/49"},
		{"iosxe", "*Oct 22 05:00:11.100: TPLUS: immediate connect frobwidget, new hunter9",
			"05:00:11.100 TPLUS: immediate connect <masked>, new <masked>"},
		{"iosxe", "*Oct 22 05:00:11.100: TPLUS(frobwidget)/0/hunter9/mallory42: Processing the reply packet",
			"05:00:11.100 TPLUS(<masked>)/<n>/<masked>/<masked> Processing the reply packet"},
		{"eos", "2026-10-22 05:00:11.100000 21 Aaa Tacacs: tls session frobwidget for hunter9 default",
			"05:00:11.100000 Tacacs: tls session <masked> for <masked> default"},
		{"eos", "2026-10-22 05:00:11.100000 21 Aaa Tacacs: accounting request frobwidget exec hunter9",
			"05:00:11.100000 Tacacs: accounting request <masked> exec <masked>"},
		{"junos", "Oct 22 05:00:11.100000 authd[900]: frobwidget hunter9 opened 172.100.100.1/49",
			"05:00:11.100000 authd: <masked> <masked> opened 172.100.100.1/49"},
		{"junos", "Oct 22 05:00:11.100000 authd[900]: frobwidget connection state hunter9",
			"05:00:11.100000 authd: <masked> connection state <masked>"},
		{"junos", "Oct 22 05:00:11.100000 authd[900]: server frobwidget name hunter9",
			"05:00:11.100000 authd: server <masked> name <masked>"},
	} {
		got := ddKeep(ddTestFilter(c.platform), c.in)
		if got != c.want {
			t.Errorf("%s: %.60q...\n kept %q\n want %q", c.platform, c.in, got, c.want)
		}
		for _, s := range ddSentinels {
			if strings.Contains(got, s) {
				t.Errorf("%s: a sentinel survived", c.platform)
			}
		}
	}
}

// A free word before a shape, or between a request's verbs and its tail, drops
// the line: a shape is a fixed sequence, not a prefix.
func TestDeviceDebugNoFreeWordBeforeOrBetween(t *testing.T) {
	xr := "RP/0/RP0/CPU0:Oct 22 05:00:11.100 UTC: tacacsd[1000]: "
	for _, c := range []struct{ platform, in string }{
		{"eos", "2026-10-22 05:00:11.100000 21 Aaa Tacacs: frobwidget created socket 5 172.100.100.1"},
		{"eos", "2026-10-22 05:00:11.100000 21 Aaa frobwidget: created socket 5 172.100.100.1"},
		{"eos", "2026-10-22 05:00:11.100000 21 Aaa Tacacs: frobwidget tac_send_author"},
		// Step 4 showed a `_` between most XR request words, so a value there is an
		// opaque span (device_debug_step4b_unit_test.go); these are the positions
		// with none: before the first word, between `packet` and `author`, and
		// between `server` and its address.
		{"iosxr", xr + "frobwidget packet start login session 17 server 172.100.100.1"},
		{"iosxr", xr + "packet frobwidget author start session 17 server 172.100.100.1"},
		{"iosxr", xr + "packet author start session 17 server frobwidget 172.100.100.1"},
		{"iosxr", xr + "packet request start session 19 server frobwidget 172.100.100.1/49"},
		{"iosxr", xr + "session 17 packet start login server frobwidget 172.100.100.1"},
		{"iosxe", "*Oct 22 05:00:11.100: TPLUS: frobwidget connected socket 5"},
		{"junos", "Oct 22 05:00:11.100000 authd[900]: frobwidget now hunter9 opened 172.100.100.1/49"},
	} {
		if got := ddKeep(ddTestFilter(c.platform), c.in); got != "" {
			t.Errorf("%s: %.70q... was kept (%d bytes)", c.platform, c.in, len(got))
		}
	}
}

// The clock in the line prefix is copied to the output, so its fraction is
// bounded: an OTP-shaped number glued to the clock digits drops the line.
func TestDeviceDebugClockFractionIsBounded(t *testing.T) {
	for _, c := range []struct{ platform, pre, post string }{
		{"iosxr", "RP/0/RP0/CPU0:Oct 22 05:00:11.", " UTC: tacacsd[1000]: socket connected to 172.100.100.1/49"},
		{"iosxe", "*Oct 22 05:00:11.", ": TAC+: opened 172.100.100.1/49"},
		{"eos", "Oct 22 05:00:11.", " Tacacs: created socket 5 172.100.100.1"},
		{"junos", "Oct 22 05:00:11.", " authd[900]: opened 172.100.100.1/49"},
	} {
		f := ddTestFilter(c.platform)
		if got := ddKeep(f, c.pre+"123456789"+c.post); got == "" {
			t.Errorf("%s: a nine-digit fraction was dropped", c.platform)
		}
		for _, otp := range []string{"1234567481516", "123456748151623", "1234567890"} {
			if got := ddKeep(f, c.pre+otp+c.post); got != "" {
				t.Errorf("%s: a %d-digit fraction was kept", c.platform, len(otp))
			}
		}
	}
	if got := nxosTestFilter.Keep("05:00:11.123456481516 tacacsd: avstr=cmd=show"); got != "" {
		t.Errorf("nxos: a long fraction was kept")
	}
	if got := nxosTestFilter.Keep("05:00:11.123456 tacacsd: avstr=cmd=show"); got == "" {
		t.Errorf("nxos: an ordinary fraction was dropped")
	}
}

// A request counts once when the device prints both the send line and the
// request-created line for it; the created lines count when no send line of
// that kind exists.
func TestDeviceDebugIOSXECountsARequestOnce(t *testing.T) {
	f := ddTestFilter("iosxe")
	both := strings.Join([]string{
		"*Oct 22 05:00:01.000: TAC+: tacacs secure connection established with peer 172.100.100.1/49",
		"*Oct 22 05:00:01.001: TPLUS: Authorization request created for 0(alice07)",
		"*Oct 22 05:00:01.002: TAC+: send AUTHOR/REQ packet",
		"*Oct 22 05:00:01.003: TPLUS: Accounting request created for 0(alice07)",
		"*Oct 22 05:00:01.004: TPLUS: processing authentication login request id 1",
		"*Oct 22 05:00:01.005: TAC+: send AUTHEN/START packet",
	}, "\n")
	s := deviceDebugSummarize("iosxe", f.Keep(both))
	// authen and author have send lines (counted once each); acct has none, so
	// its created line counts.
	if c := s.Conns[0]; c.Authen != 1 || c.Author != 1 || c.Acct != 1 {
		t.Errorf("both families: %+v", c)
	}
	only := deviceDebugSummarize("iosxe", f.Keep(strings.Join(strings.Split(both, "\n")[:2], "\n")+"\n"+
		"*Oct 22 05:00:01.006: TPLUS: Authorization request created for 0(alice07)"))
	if c := only.Conns[0]; c.Author != 2 {
		t.Errorf("created lines only: %+v", c)
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
