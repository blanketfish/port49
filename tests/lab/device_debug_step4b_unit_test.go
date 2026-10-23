package lab

import (
	"regexp"
	"strings"
	"testing"
)

// The fixtures for the shapes fixed after step 4 (device-debug shapes follow-up,
// step 4b). Step 4 ran the armed qual with the step 2 shapes and listed, as
// closed-alphabet skeletons, the XRd and IOS XE lines the filter dropped. Each
// fixture below is an invented line whose skeleton (ddArmTokens) is exactly the
// sample's, so the test proves the filter admits a line of the measured shape
// without a device line ever being copied. Every value in a `_` position is a
// made-up one.

const (
	ddXRPre = "RP/0/RP0/CPU0:Oct 23 09:39:03.054 UTC: tacacsd[1000]: "
	ddXEPre = "*Oct 23 09:48:29.345: "
)

type ddStep4bCase struct {
	platform string
	sample   string // the step 4 skeleton, as the report lists it
	line     string // an invented line of that skeleton
	want     string // what Keep writes for it
}

var ddStep4bCases = []ddStep4bCase{
	// IOS XR: the lines step 4 reported dropped.
	{"iosxr", "_ tacacsd _ packet _ start _ login _ session _ server A _",
		ddXRPre + "packet 0x1 start 0x2 login 3 session 0x4f server 172.100.100.1/49 fd=7",
		"09:39:03.054 tacacsd: packet <masked> start <masked> login <masked> session <masked> server 172.100.100.1/49 <masked>=<masked>"},
	{"iosxr", "_ tacacsd _ packet author _ start _ session _ server A _",
		ddXRPre + "packet author 0x1 start 0x2 session 17 server 172.100.100.1/49 fd=7",
		"09:39:03.054 tacacsd: packet author <masked> start <masked> session <n> server 172.100.100.1/49 <masked>=<masked>"},
	{"iosxr", "_ tacacsd _ packet _ request _ start _ session _ server A _",
		ddXRPre + "packet 0x1 request 0x2 start 0x3 session 0x4f server 172.100.100.1/49 fd=7",
		"09:39:03.054 tacacsd: packet <masked> request <masked> start <masked> session <masked> server 172.100.100.1/49 <masked>=<masked>"},
	{"iosxr", "_ tacacsd _ reply _ session _ from server A _",
		ddXRPre + "reply 0x1 session 0x4f from server 172.100.100.1/49 fd=7",
		"09:39:03.054 tacacsd: reply <masked> session <masked> from server 172.100.100.1/49 <masked>=<masked>"},
	{"iosxr", "_ tacacsd _ socket created _ A _",
		ddXRPre + "socket created 5 172.100.100.1/49 ok",
		"09:39:03.054 tacacsd: socket created <masked> 172.100.100.1/49 <masked>"},
	// No process name: the line is admitted only as a connection close.
	{"iosxr", "_ connection closed _ A port _",
		"RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection closed 5 172.100.100.1 port 49",
		"09:39:03.099 connection closed <masked> 172.100.100.1 port 49"},
	// IOS XE: the lifecycle lines step 4 reported dropped.
	{"iosxe", "tac _ tacacs _ secure _ session _ established _ tacacs secure connection established with peer A _",
		ddXEPre + "TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (fd 7)",
		"09:48:29.345 TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (<masked> <masked>)"},
	{"iosxe", "tac _ tacacs _ secure _ session _ closed _ tacacs secure connection closed with peer A _",
		ddXEPre + "TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)",
		"09:48:29.345 TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (<masked> <masked>)"},
	{"iosxe", "tplus _ connected socket _",
		ddXEPre + "TPLUS(00000001)/0/7F1234: connected socket 5",
		"09:48:29.345 TPLUS(<masked>)/<n>/<masked> connected socket <masked>"},
	{"iosxe", "tplus _ immediate connect _ new _",
		ddXEPre + "TPLUS: immediate connect 3, new 0x7F12",
		"09:48:29.345 TPLUS: immediate connect <masked>, new <masked>"},
	{"iosxe", "tac _ opened A _",
		ddXEPre + "TAC+: (1234): opened 172.100.100.1/49 ok",
		"09:48:29.345 TAC+: (<masked>): opened 172.100.100.1/49 <masked>"},
}

// The fixtures are the samples: each line's skeleton, written without its
// timestamp, is the step 4 sample. A fixture that drifts from the sample would
// make the Keep tests prove nothing about the measured shape.
func TestDeviceDebugStep4bFixturesAreTheMeasuredSkeletons(t *testing.T) {
	for i, c := range ddStep4bCases {
		got := ddArmTokens(c.line)
		// The timestamp and node prefix is one `_` span; the process name, where
		// there is one, is a vocabulary word.
		got = strings.TrimPrefix(got, "_ ")
		want := strings.TrimPrefix(c.sample, "_ ")
		if c.platform == "iosxe" {
			// The IOS XE sample is of the message, after the clock.
			got = strings.TrimPrefix(ddArmTokens(strings.TrimPrefix(c.line, ddXEPre)), "_ ")
		}
		if got != want {
			t.Errorf("fixture %d (%s): skeleton %q, sample %q", i, c.platform, got, want)
		}
	}
}

func TestDeviceDebugStep4bKeepsTheMeasuredShapes(t *testing.T) {
	for i, c := range ddStep4bCases {
		if got := ddKeep(ddTestFilter(c.platform), c.line); got != c.want {
			t.Errorf("fixture %d (%s) kept\n %q\nwant\n %q", i, c.platform, got, c.want)
		}
	}
}

// A value in each position: a sentinel or an unknown word is masked, a secret
// word, a payload line or a hex run drops the line, and nothing in the output
// is a sentinel.
func TestDeviceDebugStep4bValuePositions(t *testing.T) {
	for _, c := range []struct{ platform, in, want string }{
		// Plain sentinels in the `_` positions of the XR request shapes.
		{"iosxr", ddXRPre + "packet frobwidget start mallory42 login hunter9 session evilgroup server 172.100.100.1/49 frobwidget",
			"09:39:03.054 tacacsd: packet <masked> start <masked> login <masked> session <masked> server 172.100.100.1/49 <masked>"},
		{"iosxr", ddXRPre + "reply frobwidget session mallory42 from server 10.66.66.66/49 hunter9",
			"09:39:03.054 tacacsd: reply <masked> session <masked> from server <masked>/49 <masked>"},
		{"iosxr", ddXRPre + "socket created frobwidget 10.66.66.66/49 mallory42",
			"09:39:03.054 tacacsd: socket created <masked> <masked>/49 <masked>"},
		{"iosxr", "RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection closed frobwidget 10.66.66.66 port 49 hunter9",
			"09:39:03.099 connection closed <masked> <masked> port 49 <masked>"},
		// IOS XE.
		{"iosxe", ddXEPre + "TAC+: frobwidget: tacacs-secure: mallory42: session: hunter9: established: TACACS secure connection established with peer 10.66.66.66/49 evilgroup",
			"09:48:29.345 TAC+: <masked> tacacs-secure: <masked> session: <masked> established: TACACS secure connection established with peer <masked>/49 <masked>"},
		{"iosxr", ddXRPre + "packet 0x1 start 0x2 login 3 session 0x4f server 172.100.100.1/49 tok=faketok123abc",
			"09:39:03.054 tacacsd: packet <masked> start <masked> login <masked> session <masked> server 172.100.100.1/49 <masked>=<masked>"},
		{"iosxe", ddXEPre + "TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 10.66.66.66/49 frobwidget mallory42",
			"09:48:29.345 TAC+: tacacs-secure: session: established: TACACS secure connection established with peer <masked>/49 <masked> <masked>"},
		{"iosxe", ddXEPre + "TPLUS(frobwidget)/0/mallory42/hunter9: connected socket evilgroup",
			"09:48:29.345 TPLUS(<masked>)/<n>/<masked>/<masked> connected socket <masked>"},
		{"iosxe", ddXEPre + "TPLUS: immediate connect frobwidget, new mallory42 hunter9",
			"09:48:29.345 TPLUS: immediate connect <masked>, new <masked> <masked>"},
		{"iosxe", ddXEPre + "TAC+: (frobwidget): opened 10.66.66.66/49 mallory42",
			"09:48:29.345 TAC+: (<masked>): opened <masked>/49 <masked>"},
	} {
		got := ddKeep(ddTestFilter(c.platform), c.in)
		if got != c.want {
			t.Errorf("%s: %.70q...\n kept %q\n want %q", c.platform, c.in, got, c.want)
		}
		for _, s := range ddSentinels {
			if strings.Contains(got, s) {
				t.Errorf("%s: a sentinel survived", c.platform)
			}
		}
	}
}

// The trailing span after an address is two opaque values at most. A third word,
// or a word glued to the address, drops the line: it is a bounded span, not free
// text. (A mutation that turns it into `.*` keeps these and fails here.)
func TestDeviceDebugStep4bTrailingSpanIsBounded(t *testing.T) {
	for _, c := range []struct{ platform, in string }{
		{"iosxr", ddXRPre + "packet 0x1 start 0x2 login 3 session 0x4f server 172.100.100.1/49 frobwidget mallory42 hunter9"},
		{"iosxr", ddXRPre + "reply 0x1 session 0x4f from server 172.100.100.1/49 frobwidget mallory42 hunter9"},
		{"iosxr", ddXRPre + "socket created 5 172.100.100.1/49 frobwidget mallory42 hunter9"},
		{"iosxr", "RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection closed 5 172.100.100.1 port 49 frobwidget mallory42 hunter9"},
		{"iosxe", ddXEPre + "TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 frobwidget mallory42 hunter9"},
		{"iosxe", ddXEPre + "TPLUS: connected socket 5 frobwidget mallory42 hunter9"},
		{"iosxe", ddXEPre + "TPLUS: immediate connect 3, new 0x7F12 frobwidget mallory42 hunter9"},
		{"iosxe", ddXEPre + "TAC+: opened 172.100.100.1/49 frobwidget mallory42 hunter9"},
	} {
		if got := ddKeep(ddTestFilter(c.platform), c.in); got != "" {
			t.Errorf("%s: %.60q... was kept (%d bytes)", c.platform, c.in, len(got))
		}
	}
}

// Words in a position the sample did not show as `_` stay fixed: a word before
// the first vocabulary word, between adjacent vocabulary words, or a process
// that is not the XR one before a close line.
func TestDeviceDebugStep4bAdjacentWordsStayFixed(t *testing.T) {
	for _, c := range []struct{ platform, in string }{
		{"iosxr", ddXRPre + "frobwidget packet 0x1 start 0x2 login 3 session 0x4f server 172.100.100.1/49"},
		{"iosxr", ddXRPre + "packet frobwidget author 0x1 start 0x2 session 17 server 172.100.100.1/49"},
		{"iosxr", ddXRPre + "packet author 0x1 start 0x2 session 17 server frobwidget 172.100.100.1/49"},
		{"iosxr", ddXRPre + "reply 0x1 session 0x4f from frobwidget server 172.100.100.1/49"},
		{"iosxr", ddXRPre + "frobwidget socket created 5 172.100.100.1/49"},
		{"iosxr", ddXRPre + "socket frobwidget created 5 172.100.100.1/49"},
		{"iosxr", "RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection frobwidget closed 5 172.100.100.1 port 49"},
		{"iosxr", "RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection closed 5 172.100.100.1 frobwidget port 49"},
		{"iosxe", ddXEPre + "TAC+: tacacs-secure: session: established: TACACS secure frobwidget connection established with peer 172.100.100.1/49"},
		{"iosxe", ddXEPre + "TAC+: tacacs-secure: session: established: TACACS secure connection established with frobwidget peer 172.100.100.1/49"},
		{"iosxe", ddXEPre + "TPLUS: connected frobwidget socket 5"},
		{"iosxe", ddXEPre + "TPLUS: frobwidget connected socket 5"},
		{"iosxe", ddXEPre + "TAC+: opened frobwidget 172.100.100.1/49"},
	} {
		if got := ddKeep(ddTestFilter(c.platform), c.in); got != "" {
			t.Errorf("%s: %.60q... was kept (%d bytes)", c.platform, c.in, len(got))
		}
	}
	// A process-less XR line is admitted only as a connection close: any other
	// message, and any other named process, is dropped.
	f := ddTestFilter("iosxr")
	for _, in := range []string{
		"RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: socket created 5 172.100.100.1/49",
		"RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: socket connected to 172.100.100.1/49",
		"RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: sshd[7]: connection closed 5 172.100.100.1 port 49",
		"RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: tacacs[7]: connection closed 5 172.100.100.1 port 49",
	} {
		if got := ddKeep(f, in); got != "" {
			t.Errorf("%.70q: kept %d bytes", in, len(got))
		}
	}
}

// The secret-word and hex rules run before the shapes: a measured shape with a
// payload, secret or hex run in any position is dropped, never masked.
func TestDeviceDebugStep4bSecretRulesStillDrop(t *testing.T) {
	for _, c := range []struct{ platform, in string }{
		{"iosxr", ddXRPre + "packet 0x1 start 0x2 login 3 session 0x4f server 172.100.100.1/49 payload"},
		{"iosxr", ddXRPre + "reply password session 0x4f from server 172.100.100.1/49"},
		{"iosxr", ddXRPre + "socket created deadbeefcafe0123 172.100.100.1/49"},
		{"iosxr", "RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection closed secret 172.100.100.1 port 49"},
		{"iosxe", ddXEPre + "TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 token"},
		{"iosxe", ddXEPre + "TPLUS: connected socket deadbeefcafe0123"},
		{"iosxe", ddXEPre + "TPLUS: immediate connect 3, new payload(hex)"},
		{"iosxe", ddXEPre + "TAC+: opened 172.100.100.1/49 c0 01 02 01 de ad be ef 00 00 00 05"},
		{"iosxe", ddXEPre + "TAC+: opened 172.100.100.1/49 QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
	} {
		if got := ddKeep(ddTestFilter(c.platform), c.in); got != "" {
			t.Errorf("%s: %.60q... was kept (%d bytes)", c.platform, c.in, len(got))
		}
	}
}

// The corrected counters, on the step 4 lines: XR counts a socket connect as an
// open, a connection closed line as a close and each request kind once; IOS XE
// counts the secure established and closed lines and does not count the three
// lifecycle lines around them again.
func TestDeviceDebugStep4bCounters(t *testing.T) {
	xr := strings.Join([]string{
		ddXRPre + "socket created 5 172.100.100.1/49 ok",
		"RP/0/RP0/CPU0:Oct 23 09:39:03.060 UTC: tacacsd[1000]: socket connected 0x1f",
		ddXRPre + "packet 0x1 start 0x2 login 3 session 0x4f server 172.100.100.1/49 fd=7",
		ddXRPre + "reply 0x1 session 0x4f from server 172.100.100.1/49 fd=7",
		ddXRPre + "packet author 0x1 start 0x2 session 17 server 172.100.100.1/49 fd=7",
		ddXRPre + "packet 0x1 request 0x2 start 0x3 session 0x4f server 172.100.100.1/49 fd=7",
		ddXRPre + "packet 0x1 request 0x2 start 0x3 session 0x4f server 172.100.100.1/49 fd=7",
		"RP/0/RP0/CPU0:Oct 23 09:39:03.099 UTC: connection closed 5 172.100.100.1 port 49",
		"RP/0/RP0/CPU0:Oct 23 09:39:04.000 UTC: tacacsd[1000]: socket connected 0x20",
	}, "\n")
	s := deviceDebugSummarize("iosxr", ddTestFilter("iosxr").Keep(xr))
	if s.Opened != 2 || s.Closed != 1 || len(s.Conns) != 2 {
		t.Fatalf("xr summary %+v", s)
	}
	if c := s.Conns[0]; c.Authen != 1 || c.Author != 1 || c.Acct != 2 || c.Closed != "09:39:03.099" || c.Opened != "09:39:03.060" {
		t.Errorf("xr conn 0 = %+v", c)
	}
	if c := s.Conns[1]; c.Authen+c.Author+c.Acct != 0 || c.Closed != "" {
		t.Errorf("xr conn 1 = %+v", c)
	}

	xe := strings.Join([]string{
		ddXEPre + "TPLUS: immediate connect 3, new 0x7F12",
		ddXEPre + "TPLUS(00000001)/0/7F1234: connected socket 5",
		ddXEPre + "TAC+: (1234): opened 172.100.100.1/49 ok",
		ddXEPre + "TAC+: tacacs-secure: session: established: TACACS secure connection established with peer 172.100.100.1/49 (fd 7)",
		ddXEPre + "TPLUS: processing authentication login request id 1",
		ddXEPre + "TPLUS: Accounting request created for 0(alice07)",
		ddXEPre + "TAC+: tacacs-secure: session: closed: TACACS secure connection closed with peer 172.100.100.1/49 (fd 7)",
	}, "\n")
	e := deviceDebugSummarize("iosxe", ddTestFilter("iosxe").Keep(xe))
	if e.Opened != 1 || e.Closed != 1 || len(e.Conns) != 1 {
		t.Fatalf("xe summary %+v", e)
	}
	if c := e.Conns[0]; c.Authen != 1 || c.Acct != 1 || c.Author != 0 || c.Closed != "09:48:29.345" {
		t.Errorf("xe conn 0 = %+v", c)
	}
}

// Every value position of every fixture: each token of the message, in turn, is
// replaced by a made-up secret, token, OTP or hex run, and each of them is also
// inserted as an extra word before it. None may reach the output. (A line that
// is dropped is fine; a line kept holds only <masked>, <n> or a lab value.)
func TestDeviceDebugStep4bNoValueSurvivesInAnyPosition(t *testing.T) {
	clock := regexp.MustCompile(`^.*?\d\d:\d\d:\d\d\.\d+(?: [A-Z]{2,5})?: `)
	values := []string{"hunter9", "fakesecret77", "faketok123abc", "481516", "48151623", "deadbeefcafe0123",
		"QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "mallory42", "frobwidget", "10.66.66.66", "0xfeedface"}
	tried := 0
	for i, c := range ddStep4bCases {
		f := ddTestFilter(c.platform)
		loc := clock.FindStringIndex(c.line)
		if loc == nil {
			t.Fatalf("fixture %d has no clock", i)
		}
		pre, words := c.line[:loc[1]], strings.Fields(c.line[loc[1]:])
		for pos := range words {
			for _, v := range values {
				for _, mut := range [][]string{
					append(append(append([]string{}, words[:pos]...), v), words[pos+1:]...),
					append(append(append([]string{}, words[:pos]...), v), words[pos:]...),
				} {
					tried++
					got := ddKeep(f, pre+strings.Join(mut, " "))
					if strings.Contains(got, v) {
						t.Errorf("fixture %d (%s), position %d: a made-up value survived (%d bytes kept)", i, c.platform, pos, len(got))
					}
				}
			}
		}
	}
	if tried < 1000 {
		t.Errorf("only %d positions tried", tried)
	}
	// And the whole mixed capture, as the harness passes it.
	for _, plat := range []string{"iosxr", "iosxe"} {
		var all []string
		for _, c := range ddStep4bCases {
			if c.platform == plat {
				all = append(all, c.line)
			}
		}
		got := ddKeep(ddTestFilter(plat), strings.Join(all, "\n"))
		for _, v := range values {
			if strings.Contains(got, v) {
				t.Errorf("%s: a made-up value survived the whole capture", plat)
			}
		}
	}
}

// A 6- or 8-digit number in a numeric position, outside an address, never
// survives, in every fixture line.
func TestDeviceDebugStep4bNumbersAreBounded(t *testing.T) {
	for _, plat := range []string{"iosxr", "iosxe"} {
		var lines []string
		for _, c := range ddStep4bCases {
			if c.platform == plat {
				lines = append(lines, c.line)
			}
		}
		f := ddTestFilter(plat)
		tried, leaked := ddNumberRuns(lines, func(s string) string { return ddKeep(f, s) })
		if tried == 0 {
			t.Errorf("%s: no numeric positions tried", plat)
		}
		for _, l := range leaked {
			t.Errorf("%s: a number survived at %s", plat, l)
		}
	}
}
