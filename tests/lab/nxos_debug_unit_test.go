package lab

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every fixture here is invented for the test, never a device transcript,
// and every "secret" in it is made up.

// nxosDebugKeptFixture are lines the capture keeps verbatim.
var nxosDebugKeptFixture = []string{
	"05:00:11.100001 tacacsd: construct_tac_req(1762):aaa session id: 7, aaa type: 2, user_len=5, av_count_net=3, av_count_host=3",
	"05:00:11.100002 tacacsd: avstr=cmd=show",
	"05:00:11.100003 tacacsd: avstr=cmd-arg=users",
	"05:00:11.100004 tacacsd: avstr=priv-lvl=15",
	"05:00:11.100005 tacacsd: avstr=service=shell",
	"05:00:11.100006 tacacsd: connect_tac_server(1762): connection is Active/connect succeeded  ! socket(32)",
	"05:00:11.100007 tacacsd: nxos_ssl_write:sending 76 bytes to 192.0.2.1 port 300 on socket 32",
	"05:00:11.100008 tacacsd: aaad: response for accounting request of old library will be sent as SUCCESS",
	"05:00:11.100009 tacacsd: <LONG>: nxos_ssl_read() failed for socket 32.",
	"05:00:11.100010 tacacsd: clean_up_sock_sm_node(4564): mark server(192.0.2.1) dead",
	"05:00:11.100011 aaad: protocol TACACS failed with server group grp9",
	"05:00:11.100012 aaad: LOCAL method not supported for Authorization req all_cmds:default",
	"05:00:11.100013 aaad: Fall back method none succeeded",
}

// nxosDebugDroppedFixture are lines the capture must drop, each with the
// invented secret it would otherwise leak.
var nxosDebugDroppedFixture = map[string]string{
	"05:00:12.000001 aaad: protocol TACACS failed with server group grp9 password=hunter9":            "hunter9",
	"05:00:12.000002 tacacsd: aaad: response for authentication request secret fakesecret77":          "fakesecret77",
	"05:00:12.000003 tacacsd: aaad: response for accounting request token faketok123 sent as SUCCESS": "faketok123",
	"05:00:12.000004 tacacsd: in tac payload(hex): c0 1 2 1 de ad be ef 0 0 0 5":                      "de ad be ef",
	// A hex run with no keyword, in a shape an allow pattern admits: only
	// the hex-run rule drops it.
	"05:00:12.000005 tacacsd: aaa_mark_server_dead 1234567812345678":          "1234567812345678",
	"05:00:12.000006 tacacsd: nxos_ssl_write: out 1a 2b 3c 4d 5e 6f 70 81 92": "1a 2b 3c",
	"05:00:12.000007 tacacsd: avstr=user=fakeuser42":                          "fakeuser42",
	"05:00:12.000008 tacacsd: connect_tac_server: eyJmYWtlIjoiand0In0":        "eyJmYWtl",
	"05:00:12.000009 tacacsd: some new debug line about frobwidget 42":        "frobwidget",
	"05:00:12.000010 aaad: user fakeuser43 logged in from vty0":               "fakeuser43",
}

func nxosDebugSample() string {
	var b strings.Builder
	b.WriteString("2026 Oct 22 " + nxosDebugKeptFixture[0] + "\r\n")
	for _, ln := range nxosDebugKeptFixture[1:] {
		b.WriteString(ln + "\n")
	}
	for ln := range nxosDebugDroppedFixture {
		b.WriteString(ln + "\n")
	}
	b.WriteString("05:00:13.000001 sshd: nxos_ssl_write:sending 76 bytes to 192.0.2.1 port 300 on socket 32\n")
	b.WriteString("plain text with no timestamp\n")
	return b.String()
}

func TestNXOSDebugKeepKeepsTheAllowedShapes(t *testing.T) {
	kept := strings.Split(nxosTestFilter.Keep(nxosDebugSample()), "\n")
	for _, want := range nxosDebugKeptFixture {
		if !slices.Contains(kept, want) {
			t.Errorf("lost %q", want)
		}
	}
	if len(kept) != len(nxosDebugKeptFixture) {
		t.Errorf("kept %d lines, want %d:\n%s", len(kept), len(nxosDebugKeptFixture), strings.Join(kept, "\n"))
	}
}

func TestNXOSDebugKeepDropsEverySecretAndUnknownLine(t *testing.T) {
	kept := nxosTestFilter.Keep(nxosDebugSample())
	for ln, secret := range nxosDebugDroppedFixture {
		if strings.Contains(kept, secret) {
			t.Errorf("kept %q from the line %.40q...", secret, ln)
		}
	}
	for _, bad := range []string{"payload", "password", "secret", "token", "eyJ", "sshd", "no timestamp"} {
		if strings.Contains(kept, bad) {
			t.Errorf("kept a line with %q", bad)
		}
	}
}

// The controller's ruling: a typed secret leaves no value. `username x
// password fakesecret123` arrives as four avstr= lines: username and x are
// masked as words outside the list, and the secret-word rule drops the
// other two.
func TestNXOSDebugAvstrValues(t *testing.T) {
	in := "05:00:14.000001 tacacsd: avstr=cmd=username\n" +
		"05:00:14.000002 tacacsd: avstr=cmd-arg=x\n" +
		"05:00:14.000003 tacacsd: avstr=cmd-arg=password\n" +
		"05:00:14.000004 tacacsd: avstr=cmd-arg=fakesecret123\n" +
		"05:00:14.000005 tacacsd: avstr=cmd-arg=frobnicate\n" +
		"05:00:14.000006 tacacsd: avstr=cmd-arg=users\n" +
		"05:00:14.000007 tacacsd: avstr=priv-lvl=15\n" +
		"05:00:14.000008 tacacsd: avstr=cmd-arg=" + strings.Repeat("q", 30) + "\n"
	want := []string{
		"05:00:14.000001 tacacsd: avstr=cmd=<masked>",
		"05:00:14.000002 tacacsd: avstr=cmd-arg=<masked>",
		"05:00:14.000005 tacacsd: avstr=cmd-arg=<masked>",
		"05:00:14.000006 tacacsd: avstr=cmd-arg=users",
		"05:00:14.000007 tacacsd: avstr=priv-lvl=15",
		"05:00:14.000008 tacacsd: avstr=cmd-arg=<masked>",
	}
	got := nxosTestFilter.Keep(in)
	if got != strings.Join(want, "\n") {
		t.Fatalf("kept:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	for _, secret := range []string{"fakesecret123", "username", "password", "frobnicate", "=x"} {
		if strings.Contains(got, secret) {
			t.Errorf("kept %q", secret)
		}
	}
}

// A sequence that types a new word adds it to the list in the same commit.
func TestNXOSDebugSequencesUseOnlyListedWords(t *testing.T) {
	for _, seq := range [][]string{nxosSeqS1, nxosSeqS3, nxosSeqE1, nxosSeqSpacing} {
		for _, cmd := range seq {
			for _, w := range strings.Fields(cmd) {
				if !slices.Contains(nxosDebugWords, w) {
					t.Errorf("%q types %q, which nxosDebugWords does not list", cmd, w)
				}
			}
		}
	}
}

func TestNXOSDebugCountsAndFallbacks(t *testing.T) {
	kept := nxosTestFilter.Keep(nxosDebugSample())
	c := nxosDebugCounts(kept)
	for k, v := range map[string]int{"ssl_read_failed": 1, "mark_server_dead": 1, "fall_back_none": 1,
		"tacacs_group_failed": 1, "connection_active": 1, "request_author": 1} {
		if c[k] != v {
			t.Errorf("%s = %d, want %d (counts %v)", k, c[k], v, c)
		}
	}
	fb := nxosFallbacks(kept)
	if len(fb) != 1 {
		t.Fatalf("fallbacks %+v", fb)
	}
	f := fb[0]
	if f.At != "05:00:11.100013" || f.Before != nxosDebugKeptFixture[11] ||
		f.Context[0] != nxosDebugKeptFixture[0] || !slices.Contains(f.Context, nxosDebugKeptFixture[1]) ||
		!slices.Contains(f.Context, nxosDebugKeptFixture[10]) {
		t.Fatalf("fallback context %+v", f)
	}
}

// The review's attacks (task 7 review M3), made up: a long avstr value of
// any key, an "address" that is colon-separated hex, and repeated
// word=decimal fields. Each comes out masked or dropped.
func TestNXOSDebugReviewFixturesAreMaskedOrDropped(t *testing.T) {
	long := strings.Repeat("FAKE", 9) // 36 characters
	for in, want := range map[string]string{
		"05:00:15.000001 tacacsd: avstr=priv-lvl=" + long:                                                          "05:00:15.000001 tacacsd: avstr=priv-lvl=<masked>",
		"05:00:15.000002 tacacsd: avstr=service=" + long:                                                           "05:00:15.000002 tacacsd: avstr=service=<masked>",
		"05:00:15.000003 tacacsd: avstr=service=FAKEFAKEFAKEFAKEZ":                                                 "05:00:15.000003 tacacsd: avstr=service=<masked>",
		"05:00:15.000004 tacacsd: avstr=service=shell":                                                             "05:00:15.000004 tacacsd: avstr=service=shell",
		"05:00:15.000005 tacacsd: <LONG>: nxos_ssl_read() for server 70:61:73:73:77:6f:72:64:31:32:33 on socket 5": "05:00:15.000005 tacacsd: <LONG>: nxos_ssl_read() for server <masked> on socket 5",
		"05:00:15.000006 tacacsd: nxos_ssl_write:sending 9 bytes to 66:61:6b:65 port 300 on socket 5":              "05:00:15.000006 tacacsd: nxos_ssl_write:sending 9 bytes to <masked> port 300 on socket 5",
		"05:00:15.000007 tacacsd: nxos_ssl_write:sending 9 bytes to 2001:db8::1 port 300 on socket 5":              "05:00:15.000007 tacacsd: nxos_ssl_write:sending 9 bytes to 2001:db8::1 port 300 on socket 5",
		"05:00:15.000008 tacacsd: non_blocking_read: a=112, a=97, a=115, a=115":                                    "",
		"05:00:15.000009 tacacsd: non_blocking_read: socket=5, a=97":                                               "",
		"05:00:15.000010 tacacsd: non_blocking_read: socket=5, bytes=76, socket=6, bytes=1, rc=0":                  "",
		"05:00:15.000011 tacacsd: non_blocking_read: socket=5, bytes=76":                                           "05:00:15.000011 tacacsd: non_blocking_read: socket=5, bytes=76",
	} {
		if got := nxosTestFilter.Keep(in); got != want {
			t.Errorf("%.60q...: kept %q, want %q", in, got, want)
		}
	}
}

// nxosTestFilter is the lab's filter with made-up lab values: port49 at
// 192.0.2.1 and 2001:db8::1, the server group grp9.
var nxosTestFilter = nxosDebugFilter{Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
	Groups: []string{"grp9"}}

// Task 7 re-review N6, ruled allow-list: an address is kept only if it is
// one of the lab's, priv-lvl only as 0-15, service, group and method-list
// names only from the lab's words. Everything else is <masked>. Every value
// here is made up; the IPv6 ones spell bytes.
func TestNXOSDebugKeepsOnlyTheLabsValues(t *testing.T) {
	g23 := "wxyzwxyzwxyzwxyzwxyzwxy"
	for in, want := range map[string]string{
		"05:00:16.000001 tacacsd: <LONG>: nxos_ssl_read() for server 7061:7373:776f:7264:7365:6372:6574:3132 on socket 5":             "05:00:16.000001 tacacsd: <LONG>: nxos_ssl_read() for server <masked> on socket 5",
		"05:00:16.000002 tacacsd: nxos_ssl_write:sending 9 bytes to dead:beef:: port 300 on socket 5":                                 "05:00:16.000002 tacacsd: nxos_ssl_write:sending 9 bytes to <masked> port 300 on socket 5",
		"05:00:16.000003 tacacsd: before nxos_ssl_open  hostname 198.51.100.7 server 198.51.100.8 on port 300 vrf 1":                  "05:00:16.000003 tacacsd: before nxos_ssl_open  hostname <masked> server <masked> on port 300 vrf 1",
		"05:00:16.000004 tacacsd: before nxos_ssl_open  hostname 192.0.2.1 server 192.0.2.1 on port 300 vrf 1":                        "05:00:16.000004 tacacsd: before nxos_ssl_open  hostname 192.0.2.1 server 192.0.2.1 on port 300 vrf 1",
		"05:00:16.000005 tacacsd: avstr=priv-lvl=15":                                                                                  "05:00:16.000005 tacacsd: avstr=priv-lvl=15",
		"05:00:16.000006 tacacsd: avstr=priv-lvl=0":                                                                                   "05:00:16.000006 tacacsd: avstr=priv-lvl=0",
		"05:00:16.000007 tacacsd: avstr=priv-lvl=16":                                                                                  "05:00:16.000007 tacacsd: avstr=priv-lvl=<masked>",
		"05:00:16.000008 tacacsd: avstr=priv-lvl=abcdefghijklmnop":                                                                    "05:00:16.000008 tacacsd: avstr=priv-lvl=<masked>",
		"05:00:16.000009 tacacsd: avstr=service=shell":                                                                                "05:00:16.000009 tacacsd: avstr=service=shell",
		"05:00:16.000010 tacacsd: avstr=service=frobnicatefrobni":                                                                     "05:00:16.000010 tacacsd: avstr=service=<masked>",
		"05:00:16.000011 aaad: protocol TACACS failed with server group " + g23:                                                       "05:00:16.000011 aaad: protocol TACACS failed with server group <masked>",
		"05:00:16.000012 aaad: protocol TACACS failed with server group grp9":                                                         "05:00:16.000012 aaad: protocol TACACS failed with server group grp9",
		"05:00:16.000013 aaad: LOCAL method not supported for Authorization req all_cmds:" + g23:                                      "05:00:16.000013 aaad: LOCAL method not supported for Authorization req <masked>",
		"05:00:16.000014 aaad: group " + g23 + " method failed for Authorization req all_cmds:default":                                "05:00:16.000014 aaad: group <masked> method failed for Authorization req all_cmds:default",
		"05:00:16.000015 tacacsd: <LONG>: nxos_ssl_read() for server 192.0.2.1 group " + g23 + " aaa session id: 7 recv_bytes_left 0": "05:00:16.000015 tacacsd: <LONG>: nxos_ssl_read() for server 192.0.2.1 group <masked> aaa session id: 7 recv_bytes_left 0",
		"05:00:16.000016 tacacsd: <LONG>: nxos_ssl_read() for server 192.0.2.1 group  aaa session id: 7 recv_bytes_left 0":            "05:00:16.000016 tacacsd: <LONG>: nxos_ssl_read() for server 192.0.2.1 group  aaa session id: 7 recv_bytes_left 0",
		"05:00:16.000017 tacacsd: nxos_ssl_write:sending 9 bytes to 2001:db8:0:0::1 port 300 on socket 5":                             "05:00:16.000017 tacacsd: nxos_ssl_write:sending 9 bytes to 2001:db8:0:0::1 port 300 on socket 5",
	} {
		if got := nxosTestFilter.Keep(in); got != want {
			t.Errorf("%.70q...:\n kept %q\n want %q", in, got, want)
		}
	}
}

// Task 7 re-review R2: the fallback method is the filter's last free word;
// only NX-OS's own methods are kept.
func TestNXOSDebugFallBackMethodIsAllowListed(t *testing.T) {
	for in, want := range map[string]string{
		"05:00:17.000001 aaad: Fall back method none succeeded":             "05:00:17.000001 aaad: Fall back method none succeeded",
		"05:00:17.000002 aaad: Fall back method local failed":               "05:00:17.000002 aaad: Fall back method local failed",
		"05:00:17.000003 aaad: Fall back method hunterxyzabcdefg succeeded": "05:00:17.000003 aaad: Fall back method <masked> succeeded",
	} {
		if got := nxosTestFilter.Keep(in); got != want {
			t.Errorf("kept %q, want %q", got, want)
		}
	}
}

// Task 8 fix round 1, F2: a count or id is at most five digits and a port is
// 1-65535, so an OTP-shaped number in any numeric position never survives.
func TestNXOSDebugNumbersAreBounded(t *testing.T) {
	tried, leaked := ddNumberRuns(nxosDebugKeptFixture, nxosTestFilter.Keep)
	if tried == 0 {
		t.Fatal("no numeric positions tried")
	}
	for _, l := range leaked {
		t.Errorf("a number survived at %s", l)
	}
	for in, want := range map[string]string{
		"05:00:18.000001 tacacsd: nxos_ssl_write:sending 9 bytes to 192.0.2.1 port 65535 on socket 5": "05:00:18.000001 tacacsd: nxos_ssl_write:sending 9 bytes to 192.0.2.1 port 65535 on socket 5",
		"05:00:18.000002 tacacsd: nxos_ssl_write:sending 9 bytes to 192.0.2.1 port 65536 on socket 5": "",
		"05:00:18.000003 tacacsd: nxos_ssl_write:sending 9 bytes to 192.0.2.1 port 0 on socket 5":     "",
		"05:00:18.000004 tacacsd: connect_tac_server:7 tplus_sm->ssl_enable 1":                        "05:00:18.000004 tacacsd: connect_tac_server:7 tplus_sm->ssl_enable 1",
	} {
		if got := nxosTestFilter.Keep(in); got != want {
			t.Errorf("%.70q: kept %q, want %q", in, got, want)
		}
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
