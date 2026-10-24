package lab

import (
	"slices"
	"strings"
	"testing"
)

// Every fixture here is invented for the test, never a device transcript,
// and every "secret" in it is made up. L80 filters its NX-OS debug with the
// "nxos" profile of deviceDebugFilter; these are the fixtures L80 grades on.

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
// invented value it would otherwise leak: a payload or hex-dump line, a line
// of another facility, and a line with no facility at all.
var nxosDebugDroppedFixture = map[string]string{
	"05:00:12.000004 tacacsd: in tac payload(hex): c0 1 2 1 de ad be ef 0 0 0 5":       "de ad be ef",
	"05:00:12.000005 tacacsd: aaa_mark_server_dead 1234567812345678":                   "1234567812345678",
	"05:00:12.000006 tacacsd: nxos_ssl_write: out 1a 2b 3c 4d 5e 6f 70 81 92":          "1a 2b 3c",
	"05:00:12.000009 sshd: nxos_ssl_write:sending 76 bytes to 192.0.2.1 port 300":      "sshd",
	"05:00:12.000010 vsh: user fakeuser43 logged in from vty0":                         "fakeuser43",
	"plain text with fakeuser44 and no timestamp or facility":                          "fakeuser44",
	"05:00:12.000011 tacacsd: tac Payload follows, frobwidget":                         "frobwidget",
	"05:00:12.000012 tacacsd: body 0123456789ABCDEF0123 marker-no-secret-here-fake-99": "0123456789ABCDEF0123",
}

func nxosDebugSample() string {
	var b strings.Builder
	b.WriteString(nxosDebugKeptFixture[0] + "\r\n")
	for _, ln := range nxosDebugKeptFixture[1:] {
		b.WriteString(ln + "\n")
	}
	for ln := range nxosDebugDroppedFixture {
		b.WriteString(ln + "\n")
	}
	return b.String()
}

func TestNXOSDebugKeepKeepsTheFixtureLines(t *testing.T) {
	kept := strings.Split(ddKeep(t, ddTestFilter("nxos"), nxosDebugSample()), "\n")
	for _, want := range nxosDebugKeptFixture {
		if !slices.Contains(kept, want) {
			t.Errorf("lost %q", want)
		}
	}
	if len(kept) != len(nxosDebugKeptFixture) {
		t.Errorf("kept %d lines, want %d:\n%s", len(kept), len(nxosDebugKeptFixture), strings.Join(kept, "\n"))
	}
}

func TestNXOSDebugKeepDropsPayloadHexAndOtherFacilities(t *testing.T) {
	kept := ddKeep(t, ddTestFilter("nxos"), nxosDebugSample())
	for ln, leak := range nxosDebugDroppedFixture {
		if strings.Contains(kept, leak) {
			t.Errorf("kept %q from the line %.40q...", leak, ln)
		}
	}
}

// A typed or minted secret inside a kept NX-OS line leaves no value, whatever
// form it is in, and the avstr lines keep their keys.
func TestNXOSDebugKeepRedactsSecretsInKeptLines(t *testing.T) {
	var in []string
	for _, s := range []string{ddSentinelKey, ddSentinelPass, ddSentinelToken, ddSentinelOTP} {
		for _, enc := range ddEncodings(s) {
			in = append(in, "05:00:14.000001 tacacsd: avstr=cmd-arg="+enc)
		}
	}
	in = append(in, "05:00:14.000002 tacacsd: avstr=cmd-arg=users")
	got := ddKeep(t, ddTestFilter("nxos"), strings.Join(in, "\n"))
	if what, bad := ddSurvives(got, ddTestSecrets(), true); bad {
		t.Errorf("a secret survived (%s)", what)
	}
	if !strings.Contains(got, "avstr=cmd-arg=users") {
		t.Errorf("a harmless avstr line was lost")
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

// The measures L80 grades on stay counted over the kept text.
func TestNXOSDebugCountsAndFallbacks(t *testing.T) {
	kept := ddKeep(t, ddTestFilter("nxos"), nxosDebugSample())
	c := nxosDebugCounts(kept)
	for k, v := range map[string]int{"ssl_read_failed": 1, "mark_server_dead": 1, "fall_back_none": 1,
		"tacacs_group_failed": 1, "connection_active": 1, "request_author": 1, "request_authen": 0, "request_acct": 0} {
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

// With a date prefix on the device's line (the logfile prints one), the
// fallback's time is still the clock.
func TestNXOSDebugFallbackTimeSurvivesADatePrefix(t *testing.T) {
	kept := ddKeep(t, ddTestFilter("nxos"), "2026 Oct 22 05:00:11.100013 aaad: Fall back method local failed")
	fb := nxosFallbacks(kept)
	if len(fb) != 1 || fb[0].At != "05:00:11.100013" {
		t.Errorf("fallbacks %+v", fb)
	}
	if c := nxosDebugCounts(kept); c["fall_back_none"] != 0 {
		t.Errorf("a local fallback counted as none: %v", c)
	}
}
