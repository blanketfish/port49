package lab

import (
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
	kept := strings.Split(nxosDebugKeep(nxosDebugSample()), "\n")
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
	kept := nxosDebugKeep(nxosDebugSample())
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
	got := nxosDebugKeep(in)
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
	kept := nxosDebugKeep(nxosDebugSample())
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
		"05:00:15.000005 tacacsd: <LONG>: nxos_ssl_read() for server 70:61:73:73:77:6f:72:64:31:32:33 on socket 5": "",
		"05:00:15.000006 tacacsd: nxos_ssl_write:sending 9 bytes to 66:61:6b:65 port 300 on socket 5":              "",
		"05:00:15.000007 tacacsd: nxos_ssl_write:sending 9 bytes to 2001:db8::1 port 300 on socket 5":              "05:00:15.000007 tacacsd: nxos_ssl_write:sending 9 bytes to 2001:db8::1 port 300 on socket 5",
		"05:00:15.000008 tacacsd: non_blocking_read: a=112, a=97, a=115, a=115":                                    "",
		"05:00:15.000009 tacacsd: non_blocking_read: socket=5, a=97":                                               "",
		"05:00:15.000010 tacacsd: non_blocking_read: socket=5, bytes=76, socket=6, bytes=1, rc=0":                  "",
		"05:00:15.000011 tacacsd: non_blocking_read: socket=5, bytes=76":                                           "05:00:15.000011 tacacsd: non_blocking_read: socket=5, bytes=76",
	} {
		if got := nxosDebugKeep(in); got != want {
			t.Errorf("%.60q...: kept %q, want %q", in, got, want)
		}
	}
}
