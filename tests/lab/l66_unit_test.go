//go:build lab

package lab

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The fixtures are ansible-core 2.21's wording (the PLAY RECAP, a `fatal:` block, -vvv's host tags) and
// OpenSSH 10.2p1's -vvv lines; the token is a made-up base62 string of the minted length, and no test here
// holds a real one.

const l66Token = "Ab3Xy9Qk2LmNp7Rt5Uv1Wz8Cd4Ef6G"

const l66Recap2 = `
PLAY RECAP *********************************************************************
leaf1                      : ok=11   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
leaf2                      : ok=2    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
`

const l66FatalPretty = `TASK [mint once] ***************************************************************
[WARNING]: port49: srx1: deny no_grants_matched: no grant selects this device
fatal: [srx1]: FAILED! => {
    "censored": "the output has been hidden due to the fact that 'no_log: true' was specified for this result"
}
fatal: [srx1]: FAILED! => {
    "changed": false,
    "msg": "port49: srx1: deny no_grants_matched: no grant selects this device"
}

PLAY RECAP *********************************************************************
`

func TestL66ReadsThePlayRecap(t *testing.T) {
	got := l66ReadRecap(l66Recap2)
	want := l66Recap{OK: 11}
	if got["leaf1"] != want {
		t.Errorf("leaf1 = %+v, want %+v", got["leaf1"], want)
	}
	if got["leaf2"].Failed != 1 || got["leaf2"].OK != 2 {
		t.Errorf("leaf2 = %+v", got["leaf2"])
	}
	if !got["leaf1"].Passed() {
		t.Error("ok=11 and nothing failed is a pass")
	}
	if got["leaf2"].Passed() {
		t.Error("failed=1 is not a pass")
	}
	if (l66Recap{OK: 3, Unreachable: 1}).Passed() || (l66Recap{}).Passed() {
		t.Error("an unreachable host, or a host that ran nothing, is not a pass")
	}
	if len(l66ReadRecap("no recap here")) != 0 {
		t.Error("output without a recap holds no host")
	}
}

func TestL66ErrorTextIsTheFirstFatalBlockOnOneLine(t *testing.T) {
	got := l66ErrorText(l66FatalPretty, 400)
	if !strings.HasPrefix(got, "fatal: [srx1]: FAILED! =>") || !strings.Contains(got, "censored") {
		t.Errorf("not the first block: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("a multi-line block is not one line: %q", got)
	}
	one := "fatal: [leaf1]: UNREACHABLE! => {\"changed\": false, \"msg\": \"Authentication failed.\", \"unreachable\": true}\n"
	if got := l66ErrorText("x\n"+one+"y\n", 400); !strings.Contains(got, "Authentication failed.") || strings.Contains(got, "y") {
		t.Errorf("single-line block: %q", got)
	}
	if got := l66ErrorText(one, 20); len(got) > 20+len("...") {
		t.Errorf("not capped at 20: %q", got)
	}
	if got := l66ErrorText("TASK [x]\nok: [leaf1]\n", 400); got != "" {
		t.Errorf("a run with no fatal reads %q, want empty", got)
	}
}

func TestL66WarningLinesAreTheWarningsOnly(t *testing.T) {
	got := l66WarningLines(l66FatalPretty)
	if len(got) != 1 || !strings.Contains(got[0], "no_grants_matched") {
		t.Errorf("warnings = %q", got)
	}
}

// l66UndefinedFact is ansible-core 2.21.4's output when the fact play's connection variables were read before
// the mint: no_log censors the fatal, and only the [ERROR] line says why (re-review 3, C1).
const l66UndefinedFact = `TASK [mint once] ***************************************************************
[ERROR]: Task failed: Error processing keyword 'remote_user': 'p49' is undefined

Task failed.
Origin: /w/play/b.yml:4:7

<<< caused by >>>

Error processing keyword 'remote_user': 'p49' is undefined
fatal: [leaf1]: FAILED! => {"censored": "the output has been hidden due to the fact that 'no_log: true' was specified for this result", "changed": false}

PLAY RECAP *********************************************************************
leaf1                      : ok=0    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
`

func TestL66SummaryKeepsAnsiblesErrorLines(t *testing.T) {
	r := l66Run{stdout: l66UndefinedFact, exit: 2, recap: l66ReadRecap(l66UndefinedFact)}
	s := r.summary("leaf1")
	if !strings.Contains(s, "[ERROR]: Task failed: Error processing keyword 'remote_user': 'p49' is undefined") {
		t.Errorf("the summary lost the only line that says why the censored task failed: %s", s)
	}
	if got := l66ErrorLines(l66FatalPretty); len(got) != 0 {
		t.Errorf("a run without [ERROR] lines: %q", got)
	}
	many := strings.Repeat("[ERROR]: one\n", 5)
	if got := (l66Run{stdout: many}).summary("leaf1"); strings.Count(got, "[ERROR]") != 3 {
		t.Errorf("the summary keeps three [ERROR] lines: %s", got)
	}
}

func TestL66CountsMintsAndRedeemsByReason(t *testing.T) {
	recs := []map[string]any{
		{"event": "mint", "verdict": "permit", "reason": "grants_matched"},
		{"event": "blob"},
		{"event": "mint", "verdict": "deny", "reason": "no_grants_matched"},
		{"event": "redeem", "reason": "token_redeemed"},
		{"event": "redeem", "reason": "token_not_found"},
		{"event": "account"},
		{"event": "authorize_session"},
	}
	c := l66CountRecords(recs)
	if c.Mints != 2 || c.MintDenies != 1 || c.Redeems != 2 {
		t.Errorf("counts = %+v", c)
	}
	if c.MintReasons["no_grants_matched"] != 1 || c.RedeemReasons["token_not_found"] != 1 || c.RedeemReasons["token_redeemed"] != 1 {
		t.Errorf("reasons = %v, %v", c.MintReasons, c.RedeemReasons)
	}
	if !slices.Equal(c.Other, []string{"account", "authorize_session"}) {
		t.Errorf("other = %v, want every event but mint, blob and redeem", c.Other)
	}
}

func TestL66TokenHashesCoverMintsAndRedeems(t *testing.T) {
	recs := []map[string]any{
		{"event": "mint", "mint": map[string]any{"token_sha256": []any{"aaa", "bbb"}}},
		{"event": "redeem", "auth": map[string]any{"credential_sha256": "ccc"}},
		{"event": "redeem", "auth": map[string]any{}},
	}
	h := l66TokenHashes(recs)
	if len(h) != 3 || !h["aaa"] || !h["bbb"] || !h["ccc"] {
		t.Errorf("hashes = %v", h)
	}
}

func TestL66FindsATokenByItsHashAndNeverByItsText(t *testing.T) {
	hashes := map[string]bool{sha(l66Token): true}
	text := "line one\n" +
		"ESTABLISH SSH CONNECTION password=" + l66Token + ", user=slice01\n" +
		"a long run xx" + l66Token + "yy of base62\n" +
		"an unrelated word Zb3Xy9Qk2LmNp7Rt5Uv1Wz8Cd4Ef6G of the same length\n" +
		"short " + l66Token[:12] + " only\n"
	got := l66FindTokens(text, hashes, len(l66Token))
	if !slices.Equal(got, []int{2, 3}) {
		t.Errorf("lines = %v, want [2 3]: the token delimited, and the token inside a longer run", got)
	}
	if got := l66FindTokens(text, map[string]bool{}, len(l66Token)); len(got) != 0 {
		t.Errorf("with no hashes learned nothing can be found: %v", got)
	}
}

func TestL66ScrubReplacesATokenAndKeepsTheRest(t *testing.T) {
	hashes := map[string]bool{sha(l66Token): true}
	got := l66Scrub("pw="+l66Token+";user=slice01", hashes, len(l66Token))
	if strings.Contains(got, l66Token) || got != "pw=[token];user=slice01" {
		t.Errorf("scrubbed = %q", got)
	}
	if got := l66Scrub("nothing here", hashes, len(l66Token)); got != "nothing here" {
		t.Errorf("unchanged text changed: %q", got)
	}
}

const l66KHBefore = "# a comment the operator wrote\n" +
	"@revoked unrelated.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n" +
	"@cert-authority *.unrelated.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n"

func TestL66ParsesKnownHostsLines(t *testing.T) {
	got := l66ParseKH(l66KHBefore + "\n[172.100.100.11]:22,172.100.100.11 ecdsa-sha2-nistp521 AAAAE2VjZHNh comment\n|1|salt=|hash= ssh-rsa AAAAB3\n")
	if len(got) != 4 {
		t.Fatalf("lines = %+v, want the 4 key lines (comments and blanks left out)", got)
	}
	if got[0].Marker != "@revoked" || got[0].Hosts != "unrelated.example" || got[0].Type != "ssh-ed25519" {
		t.Errorf("revoked line = %+v", got[0])
	}
	if got[1].Marker != "@cert-authority" {
		t.Errorf("cert-authority line = %+v", got[1])
	}
	if got[2].Marker != "" || got[2].Hosts != "[172.100.100.11]:22,172.100.100.11" || got[2].Type != "ecdsa-sha2-nistp521" || got[2].Blob != "AAAAE2VjZHNh" {
		t.Errorf("plain line = %+v", got[2])
	}
	if !strings.HasPrefix(got[3].Hosts, "|1|") {
		t.Errorf("hashed line = %+v", got[3])
	}
}

func TestL66ShortNamesAKeyLineWithoutItsWholeKey(t *testing.T) {
	l := l66KHLine{Hosts: "172.100.100.11", Type: "ssh-ed25519", Blob: "AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBB"}
	s := l.Short()
	if !strings.Contains(s, "172.100.100.11") || !strings.Contains(s, "ssh-ed25519") || strings.Contains(s, l.Blob) {
		t.Errorf("short = %q: the hosts and the type, not the whole key", s)
	}
	m := l66KHLine{Marker: "@revoked", Hosts: "x", Type: "ssh-rsa", Blob: "AAAAB3"}
	if !strings.HasPrefix(m.Short(), "@revoked ") {
		t.Errorf("a marker leads the line: %q", m.Short())
	}
}

func TestL66DiffAnAppendedFileKeepsEveryCommentAndMarker(t *testing.T) {
	after := l66KHBefore + "[172.100.100.11]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDDD\n"
	d := l66DiffKH(l66KHBefore, after)
	if d.Mode != "appended" {
		t.Errorf("mode = %q, want appended", d.Mode)
	}
	if len(d.Added) != 1 || d.Added[0].Hosts != "[172.100.100.11]:22" {
		t.Errorf("added = %+v", d.Added)
	}
	if len(d.Removed)+len(d.LostComments)+len(d.LostMarkers) != 0 {
		t.Errorf("an append loses nothing: %+v", d)
	}
}

func TestL66DiffAFileWithoutATrailingNewlineIsStillAppendedTo(t *testing.T) {
	before := strings.TrimSuffix(l66KHBefore, "\n")
	after := l66KHBefore + "172.100.100.11 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB\n"
	if d := l66DiffKH(before, after); d.Mode != "appended" {
		t.Errorf("mode = %q: libssh finishing the last line before it appends is still an append", d.Mode)
	}
}

func TestL66DiffARewrittenFileNamesWhatItLost(t *testing.T) {
	after := "172.100.100.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDDD\n"
	d := l66DiffKH(l66KHBefore, after)
	if d.Mode != "rewritten" {
		t.Errorf("mode = %q, want rewritten", d.Mode)
	}
	if !slices.Equal(d.LostComments, []string{"# a comment the operator wrote"}) {
		t.Errorf("lost comments = %q", d.LostComments)
	}
	if len(d.LostMarkers) != 2 || !strings.HasPrefix(d.LostMarkers[0], "@revoked ") || !strings.HasPrefix(d.LostMarkers[1], "@cert-authority ") {
		t.Errorf("lost markers = %q", d.LostMarkers)
	}
	if len(d.Removed) != 2 || len(d.Added) != 1 {
		t.Errorf("removed %d added %d, want the two marker lines gone and one key added", len(d.Removed), len(d.Added))
	}
}

func TestL66DiffUnchangedAndEmptyBefore(t *testing.T) {
	if d := l66DiffKH(l66KHBefore, l66KHBefore); d.Mode != "unchanged" || len(d.Added) != 0 {
		t.Errorf("same file: %+v", d)
	}
	if d := l66DiffKH("", "h ssh-rsa AAAAB3\n"); d.Mode != "appended" || len(d.Added) != 1 {
		t.Errorf("an empty file filled is an append: %+v", d)
	}
}

func TestL66ReplaceBlobSwapsTheKeyOfThatLineOnly(t *testing.T) {
	content := l66KHBefore + "[172.100.100.11]:22 ssh-ed25519 AAAAOLD extra\n172.100.100.12 ssh-ed25519 AAAAOLD\n"
	line := l66KHLine{Hosts: "[172.100.100.11]:22", Type: "ssh-ed25519", Blob: "AAAAOLD"}
	got, ok := l66ReplaceBlob(content, line, "AAAANEW")
	if !ok {
		t.Fatal("the line is in the file")
	}
	if !strings.Contains(got, "[172.100.100.11]:22 ssh-ed25519 AAAANEW extra\n") || !strings.Contains(got, "172.100.100.12 ssh-ed25519 AAAAOLD\n") {
		t.Errorf("replaced = %q", got)
	}
	if !strings.HasPrefix(got, l66KHBefore) {
		t.Error("the comment and marker lines must stand as they were")
	}
	if _, ok := l66ReplaceBlob(content, l66KHLine{Hosts: "nobody", Type: "ssh-rsa", Blob: "X"}, "Y"); ok {
		t.Error("a line that is not there cannot be replaced")
	}
}

func TestL66BaselineHoldsACommentARevokedAndACertAuthorityLine(t *testing.T) {
	got := l66BaselineKH("AAAAREVOKED", "AAAACA")
	lines := l66ParseKH(got)
	if len(lines) != 2 || lines[0].Marker != "@revoked" || lines[1].Marker != "@cert-authority" {
		t.Fatalf("lines = %+v", lines)
	}
	if !strings.HasPrefix(got, "#") || !strings.HasSuffix(got, "\n") {
		t.Errorf("a comment line first and a newline last: %q", got)
	}
	if strings.Contains(got, "172.100.100") || strings.Contains(got, "leaf1") {
		t.Errorf("the markers must be for unrelated patterns, not the lab's: %q", got)
	}
}

const l66StandinLog = `{"event":"ready","host_keys":["ssh-ed25519 SHA256:abc"],"listen":"[::]:22"}
{"event":"connect","remote":"172.100.100.1:41000"}
{"event":"publickey_offered","key_type":"ssh-ed25519","user":"slice01"}
{"event":"password_attempt","len":30,"remote":"172.100.100.1:41000","sha256":"aaa","user":"slice01"}
{"event":"kbdint_attempt","len":30,"remote":"172.100.100.1:41002","sha256":"bbb","user":"slice01"}
{"event":"ended","remote":"172.100.100.1:41000","error":"ssh: no auth passed yet"}
not json
{"event":"connect","remote":"172.100.100.1:41002"}
`

func TestL66ParsesTheStandinLogAndSkipsWhatIsNotAnEvent(t *testing.T) {
	es := l66ParseStandin(l66StandinLog)
	if len(es) != 7 {
		t.Fatalf("events = %d, want 7 (the non-JSON line is skipped)", len(es))
	}
	if es[3].Event != "password_attempt" || es[3].Len != 30 || es[3].SHA256 != "aaa" || es[3].User != "slice01" {
		t.Errorf("password event = %+v", es[3])
	}
}

func TestL66TallyAndWhetherTheTokenWasPresented(t *testing.T) {
	tally := l66TallyStandin(l66ParseStandin(l66StandinLog))
	if tally.Connects != 2 || tally.Passwords != 1 || tally.Kbdint != 1 {
		t.Errorf("tally = %+v", tally)
	}
	if !tally.Presented(map[string]bool{"bbb": true}) || !tally.Presented(map[string]bool{"aaa": true}) {
		t.Error("an attempt whose hash is a minted token's was the token, by either method")
	}
	if tally.Presented(map[string]bool{"zzz": true}) || tally.Presented(nil) {
		t.Error("an attempt that is no minted token is not the token")
	}
}

func authStart(seq byte) []byte {
	// TACACS+ header: version 0xc1, type 1 (authentication), seq_no, flags, session_id (4), length (4).
	return append([]byte{0xc1, 0x01, seq, 0x00, 1, 2, 3, 4}, make([]byte, 8)...)
}

func TestL66AuthStartsCountsTypeOneSeqOneOncePerSegment(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	author := []byte{0xc0, 0x02, 0x01, 0x00, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0}
	segs := []l66Seg{
		{At: base, SrcPort: 40001, Seq: 100, Payload: authStart(1)},
		{At: base.Add(time.Second), SrcPort: 40001, Seq: 100, Payload: authStart(1)},     // the same segment on a second interface
		{At: base.Add(2 * time.Second), SrcPort: 40001, Seq: 200, Payload: authStart(3)}, // a later reply of the exchange
		{At: base.Add(3 * time.Second), SrcPort: 40002, Seq: 100, Payload: authStart(1)}, // another connection
		{At: base.Add(4 * time.Second), SrcPort: 40003, Seq: 100, Payload: author},       // authorization
		{At: base.Add(5 * time.Second), SrcPort: 40004, Seq: 100, Payload: []byte{0xc1}}, // too short for a header
		{At: base.Add(time.Minute), SrcPort: 40005, Seq: 100, Payload: authStart(1)},     // outside the window
	}
	if got := l66AuthStarts(segs, base, base.Add(10*time.Second)); got != 2 {
		t.Errorf("starts = %d, want 2: one per connection, a duplicate sighting not counted twice", got)
	}
	if got := l66AuthStarts(segs, base.Add(time.Hour), base.Add(2*time.Hour)); got != 0 {
		t.Errorf("an empty window counts %d", got)
	}
}

// l66Pcap writes a pcap of TCP segments (LINUX_SLL2, as the lab's capture takes them) with their payload bytes.
func l66Pcap(t *testing.T, segs []l66PcapSeg) string {
	t.Helper()
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(buf[4:6], 2)
	binary.LittleEndian.PutUint16(buf[6:8], 4)
	binary.LittleEndian.PutUint32(buf[16:20], 262144)
	binary.LittleEndian.PutUint32(buf[20:24], 276)
	for _, s := range segs {
		tcp := make([]byte, 20+len(s.payload))
		binary.BigEndian.PutUint16(tcp[0:2], s.sport)
		binary.BigEndian.PutUint16(tcp[2:4], s.dport)
		binary.BigEndian.PutUint32(tcp[4:8], s.seq)
		tcp[12], tcp[13] = 5<<4, 0x18
		copy(tcp[20:], s.payload)
		ip := make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
		copy(ip[12:16], net.ParseIP(s.src).To4())
		copy(ip[16:20], net.ParseIP(s.dst).To4())
		sll := make([]byte, 20)
		binary.BigEndian.PutUint16(sll[0:2], 0x0800)
		pkt := append(append(sll, ip...), tcp...)
		hdr := make([]byte, 16)
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(s.at.Unix()))
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(pkt)))
		buf = append(append(buf, hdr...), pkt...)
	}
	p := filepath.Join(t.TempDir(), "c.pcap")
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type l66PcapSeg struct {
	at           time.Time
	src, dst     string
	sport, dport uint16
	seq          uint32
	payload      []byte
}

func TestL66LoadSegsKeepsTheDevicesPayloadToPort49Only(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	p := l66Pcap(t, []l66PcapSeg{
		{at, "172.100.100.11", "172.100.100.1", 40001, 49, 7, authStart(1)},
		{at, "172.100.100.1", "172.100.100.11", 49, 40001, 9, authStart(2)}, // port49d's reply: not a start
		{at, "172.100.100.21", "172.100.100.1", 40002, 49, 5, authStart(1)}, // another device
		{at, "172.100.100.11", "172.100.100.1", 40003, 22, 5, authStart(1)}, // not port 49
		{at, "172.100.100.11", "172.100.100.1", 40004, 49, 5, nil},          // a bare ACK
	})
	segs, err := l66LoadSegs(p, "172.100.100.11")
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || segs[0].SrcPort != 40001 || segs[0].Seq != 7 || len(segs[0].Payload) != 16 {
		t.Fatalf("segs = %+v, want the one payload segment the device sent to port 49", segs)
	}
	if !segs[0].At.Equal(at) {
		t.Errorf("time = %v, want %v", segs[0].At, at)
	}
	if got := l66AuthStarts(segs, at.Add(-time.Second), at.Add(time.Second)); got != 1 {
		t.Errorf("starts = %d, want 1", got)
	}
	if _, err := l66LoadSegs(filepath.Join(t.TempDir(), "missing.pcap"), "172.100.100.11"); err == nil {
		t.Error("a capture that cannot be read is an error, never a zero")
	}
}

func TestL66OutcomeTruthTable(t *testing.T) {
	cases := []struct {
		kind                      string
		ok, timedOut, control, un bool
		want                      string
	}{
		{"claim", true, false, true, false, "PASS"},
		{"claim", false, false, true, false, "FAIL"},
		{"claim", true, true, true, false, "TIMEOUT"},
		{"refusal", true, false, true, false, "PASS"},
		{"refusal", true, false, false, false, "INVALID"},
		{"refusal", false, false, false, false, "FAIL"},
		{"refusal", true, false, true, true, "INVALID"},
		{"claim", true, false, false, false, "PASS"},
		{"record", true, false, true, false, "OBSERVED"},
		{"record", false, false, true, false, "INVALID"},
		{"record", true, false, false, false, "INVALID"},
		{"record", true, false, true, true, "INVALID"},
		{"record", true, true, true, false, "TIMEOUT"},
	}
	for _, c := range cases {
		if got := l66Outcome(c.kind, c.ok, c.timedOut, c.control, c.un); got != c.want {
			t.Errorf("l66Outcome(%s ok=%v timeout=%v control=%v unread=%v) = %s, want %s", c.kind, c.ok, c.timedOut, c.control, c.un, got, c.want)
		}
	}
}

func TestL66WhyInvalidNamesTheFactThatMadeItInvalid(t *testing.T) {
	cases := []struct {
		kind                string
		ok, control, unread bool
		want                string
	}{
		{"claim", true, true, true, "could not be read"},
		{"refusal", true, false, false, "positive control"},
		{"record", true, false, false, "positive control"},
		{"record", false, true, false, "could not observe"},
	}
	for _, c := range cases {
		if got := l66WhyInvalid(c.kind, c.ok, c.control, c.unread); !strings.Contains(got, c.want) {
			t.Errorf("l66WhyInvalid(%s ok=%v control=%v unread=%v) = %q, want it to say %q", c.kind, c.ok, c.control, c.unread, got, c.want)
		}
	}
	if got := l66WhyInvalid("claim", true, true, false); got != "" {
		t.Errorf("nothing made a claim INVALID, yet %q", got)
	}
}

func TestL66AnInvalidRunWritesNoNote(t *testing.T) {
	good := []l66Result{{id: "L66a", outcome: "OBSERVED"}, {id: "L66d", outcome: "PASS"}, {id: "L66c1", outcome: "FAIL"}, {id: "L66x", outcome: "TIMEOUT"}}
	if ok, why := l66Writable(good); !ok || why != "" {
		t.Errorf("a FAIL or a TIMEOUT is a result, the run is writable: %v %q", ok, why)
	}
	bad := append(slices.Clone(good), l66Result{id: "L66e1", outcome: "INVALID"})
	ok, why := l66Writable(bad)
	if ok || !strings.Contains(why, "L66e1") {
		t.Errorf("an INVALID cell makes the run unwritable and is named: %v %q", ok, why)
	}
	if ok, _ := l66Writable(nil); ok {
		t.Error("a run with no cell measured nothing")
	}
	notRun := append(slices.Clone(good), l66Result{id: "L66c2-paramiko", outcome: "NOT RUN (paramiko refused the markers)"})
	if ok, why := l66Writable(notRun); !ok {
		t.Errorf("a cell blocked by a client behaviour another cell measured does not stop the note: %q", why)
	}
	cut := append(slices.Clone(good), l66Result{id: "L66e-ssh", outcome: "INCOMPLETE (deadline)"})
	if ok, why := l66Writable(cut); ok || !strings.Contains(why, "L66e-ssh") {
		t.Errorf("a cell skipped for the test's deadline leaves the run incomplete: %v %q", ok, why)
	}
}

func TestL66PlatformsNameTheModuleOfTheirCollection(t *testing.T) {
	want := map[string]string{
		"arista_eos": "arista.eos", "cisco_nxos": "cisco.nxos", "cisco_iosxe": "cisco.ios",
		"juniper_vjunos-router": "junipernetworks.junos", "juniper_vsrx": "junipernetworks.junos",
	}
	for _, p := range platforms {
		if optInPlatforms[p.sel] {
			continue
		}
		l, ok := l66Platforms[p.name]
		if !ok {
			t.Errorf("no L66 platform for %s", p.name)
			continue
		}
		if l.Collection != want[p.name] {
			t.Errorf("%s collection = %q, want %q", p.name, l.Collection, want[p.name])
		}
		if !strings.HasPrefix(l.Module, l.Collection+".") || !strings.HasSuffix(l.Module, "_command") {
			t.Errorf("%s module = %q", p.name, l.Module)
		}
		if !strings.HasPrefix(l.NetworkOS, l.Collection+".") {
			t.Errorf("%s network_os = %q", p.name, l.NetworkOS)
		}
	}
}

func TestL66DeniedNodeIsAnotherLabNode(t *testing.T) {
	for _, p := range platforms {
		if optInPlatforms[p.sel] {
			continue
		}
		d := l66DeniedNode(p.node)
		if d == "" || d == p.node {
			t.Errorf("denied node for %s = %q", p.node, d)
		}
		if !slices.ContainsFunc(platforms, func(q platform) bool { return q.node == d }) {
			t.Errorf("%q is not a node in port49d's inventory", d)
		}
	}
}

func TestL66PolicyGrantsTheOneNodeToTheSliceOperator(t *testing.T) {
	var p struct {
		Scopes []struct {
			Name  string
			Match map[string][]string
		}
		Subjects []struct {
			Name     string
			Identity []string
			Username string
		}
		Grants []struct {
			Subject, Scope string
			Roles          []string
		}
	}
	if err := yaml.Unmarshal([]byte(l66Policy("leaf1")), &p); err != nil {
		t.Fatalf("the policy is not YAML: %v", err)
	}
	if len(p.Scopes) != 1 || !slices.Equal(p.Scopes[0].Match["name"], []string{"leaf1"}) {
		t.Errorf("scopes = %+v, want one scope selecting leaf1 by name", p.Scopes)
	}
	if len(p.Subjects) != 1 || !slices.Contains(p.Subjects[0].Identity, "user:"+sliceEmail) || p.Subjects[0].Username != "slice01" {
		t.Errorf("subjects = %+v", p.Subjects)
	}
	if len(p.Grants) != 1 || p.Grants[0].Scope != p.Scopes[0].Name {
		t.Errorf("grants = %+v", p.Grants)
	}
}

func l66Parse(t *testing.T, s string) []map[string]any {
	t.Helper()
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(s), &plays); err != nil {
		t.Fatalf("not YAML: %v\n%s", err, s)
	}
	if len(plays) == 0 {
		t.Fatalf("no play in %q", s)
	}
	return plays
}

func TestL66TenTaskPlayHasTenCommandsAndNoMint(t *testing.T) {
	p := l66Platforms["arista_eos"]
	plays := l66Parse(t, l66Playbook("ten", p, 10, ""))
	tasks, _ := plays[0]["tasks"].([]any)
	if len(tasks) != 10 {
		t.Fatalf("tasks = %d, want 10", len(tasks))
	}
	for i, tk := range tasks {
		m := tk.(map[string]any)
		args, _ := m["arista.eos.eos_command"].(map[string]any)
		if args["commands"] != "show version" {
			t.Errorf("task %d = %v", i, m)
		}
	}
	if _, ok := plays[0]["pre_tasks"]; ok {
		t.Error("(a) mints nowhere but in ansible_password")
	}
	if plays[0]["gather_facts"] != false {
		t.Error("no fact gathering: it would be a task on the device")
	}
}

func TestL66OncePlayMintsOnceUnderNoLogThenRunsItsTasks(t *testing.T) {
	p := l66Platforms["juniper_vsrx"]
	plays := l66Parse(t, l66Playbook("once", p, 3, ""))
	pre, _ := plays[0]["pre_tasks"].([]any)
	if len(pre) != 1 {
		t.Fatalf("pre_tasks = %d, want the one mint", len(pre))
	}
	mint := pre[0].(map[string]any)
	if mint["no_log"] != true {
		t.Error("the mint is no_log: true")
	}
	facts, _ := mint["ansible.builtin.set_fact"].(map[string]any)
	if v, _ := facts["p49"].(string); !strings.Contains(v, "port49.client.token") || !strings.Contains(v, "field='all'") {
		t.Errorf("set_fact = %v", facts)
	}
	tasks, _ := plays[0]["tasks"].([]any)
	if len(tasks) != 3 {
		t.Errorf("tasks = %d, want 3", len(tasks))
	}
	if _, ok := tasks[0].(map[string]any)["junipernetworks.junos.junos_command"]; !ok {
		t.Errorf("task 0 = %v", tasks[0])
	}
}

func TestL66GapPlayPutsTheBetweenTaskBetweenTwoCommands(t *testing.T) {
	p := l66Platforms["cisco_nxos"]
	plays := l66Parse(t, l66Playbook("gap", p, 2, "- name: idle\n  ansible.builtin.pause:\n    seconds: 15\n"))
	tasks, _ := plays[0]["tasks"].([]any)
	if len(tasks) != 4 {
		t.Fatalf("tasks = %d, want 1 command, the gap, 2 commands", len(tasks))
	}
	if _, ok := tasks[0].(map[string]any)["cisco.nxos.nxos_command"]; !ok {
		t.Errorf("task 0 = %v", tasks[0])
	}
	if _, ok := tasks[1].(map[string]any)["ansible.builtin.pause"]; !ok {
		t.Errorf("task 1 = %v", tasks[1])
	}
	reset := l66Parse(t, l66Playbook("gap", p, 2, "- name: reset\n  meta: reset_connection\n"))
	if rt, _ := reset[0]["tasks"].([]any); len(rt) != 4 || rt[1].(map[string]any)["meta"] != "reset_connection" {
		t.Errorf("reset tasks = %v", rt)
	}
}

func TestL66RawPlayRunsRawNotTheModule(t *testing.T) {
	plays := l66Parse(t, l66Playbook("raw", l66Platforms["cisco_iosxe"], 1, ""))
	tasks, _ := plays[0]["tasks"].([]any)
	if len(tasks) != 1 || tasks[0].(map[string]any)["ansible.builtin.raw"] != "show version" {
		t.Errorf("tasks = %v", tasks)
	}
}

func l66InvDoc(t *testing.T, s string) (hosts map[string]map[string]any, vars map[string]any) {
	t.Helper()
	var doc struct {
		All struct {
			Hosts map[string]map[string]any
			Vars  map[string]any
		}
	}
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatalf("not YAML: %v\n%s", err, s)
	}
	return doc.All.Hosts, doc.All.Vars
}

func TestL66LookupInventoryPutsBothLookupsInTheConnectionVariables(t *testing.T) {
	inv := l66Inventory(l66InvSpec{Hosts: []l66Host{{"leaf1", "172.100.100.11"}}, Socket: "/s/agent.sock", Bin: "/r/bin/port49",
		Platform: l66Platforms["arista_eos"], Conn: "network_cli", SSHType: "libssh", Mode: "lookup"})
	hosts, vars := l66InvDoc(t, inv)
	if hosts["leaf1"]["ansible_host"] != "172.100.100.11" || hosts["leaf1"]["p49_name"] != "{{ inventory_hostname }}" {
		t.Errorf("host = %v", hosts["leaf1"])
	}
	pw, _ := vars["ansible_password"].(string)
	us, _ := vars["ansible_user"].(string)
	if !strings.Contains(pw, "lookup('port49.client.token', p49_name") || strings.Contains(pw, "field=") {
		t.Errorf("ansible_password = %q: the login token, minted by the lookup", pw)
	}
	if !strings.Contains(us, "field='username'") {
		t.Errorf("ansible_user = %q: a second lookup for the username", us)
	}
	if vars["ansible_connection"] != "ansible.netcommon.network_cli" || vars["ansible_network_os"] != "arista.eos.eos" ||
		vars["ansible_network_cli_ssh_type"] != "libssh" || vars["p49_socket"] != "/s/agent.sock" || vars["p49_bin"] != "/r/bin/port49" {
		t.Errorf("vars = %v", vars)
	}
	if _, ok := vars["ansible_connect_timeout"]; ok {
		t.Error("no connect timeout unless asked")
	}
}

func TestL66FactInventoryReadsTheFactAndNamesTheDeviceTheLookupAsks(t *testing.T) {
	inv := l66Inventory(l66InvSpec{Hosts: []l66Host{{"l66a", "172.100.100.11"}, {"l66b", "172.100.100.11"}}, P49Name: "leaf1",
		Platform: l66Platforms["arista_eos"], Conn: "network_cli", SSHType: "paramiko", Mode: "fact", ConnectTimeout: 10,
		LibsshConfig: "/w/libssh.conf"})
	hosts, vars := l66InvDoc(t, inv)
	if hosts["l66a"]["p49_name"] != "leaf1" || hosts["l66b"]["ansible_host"] != "172.100.100.11" {
		t.Errorf("hosts = %v", hosts)
	}
	if vars["ansible_password"] != "{{ p49.login | default(omit) }}" || vars["ansible_user"] != "{{ p49.username | default(omit) }}" {
		t.Errorf("fact vars = %v %v", vars["ansible_user"], vars["ansible_password"])
	}
	if vars["ansible_connect_timeout"] != 10 || vars["ansible_libssh_config_file"] != "/w/libssh.conf" || vars["ansible_network_cli_ssh_type"] != "paramiko" {
		t.Errorf("vars = %v", vars)
	}
}

func TestL66SSHInventoryUsesTheBuiltinConnectionAndItsArgs(t *testing.T) {
	inv := l66Inventory(l66InvSpec{Hosts: []l66Host{{"leaf1", "172.100.100.11"}}, Platform: l66Platforms["arista_eos"], Conn: "ssh", Mode: "fact",
		SSHCommonArgs: "-F /w/ssh_config", SSHExtraArgs: "-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new"})
	_, vars := l66InvDoc(t, inv)
	if vars["ansible_connection"] != "ssh" || vars["ansible_ssh_common_args"] != "-F /w/ssh_config" ||
		vars["ansible_ssh_extra_args"] != "-o HostKeyAlias={{ inventory_hostname }} -o StrictHostKeyChecking=accept-new" {
		t.Errorf("vars = %v", vars)
	}
	if _, ok := vars["ansible_network_os"]; ok {
		t.Error("the plain ssh connection has no network_os")
	}
	// The ssh plugin runs `raw` with -tt by default; a network CLI given a terminal pages (Junos's ---(more)---)
	// and waits for a key that never comes (lab run 2, vJunos and vSRX).
	if vars["ansible_ssh_use_tty"] != false {
		t.Errorf("ansible_ssh_use_tty = %v, want false", vars["ansible_ssh_use_tty"])
	}
	nc := l66Inventory(l66InvSpec{Hosts: []l66Host{{"leaf1", "172.100.100.11"}}, Platform: l66Platforms["arista_eos"], Conn: "network_cli",
		SSHType: "libssh", Mode: "fact"})
	if _, ncVars := l66InvDoc(t, nc); ncVars["ansible_ssh_use_tty"] != nil {
		t.Error("ansible_ssh_use_tty is the plain ssh connection's option only")
	}
}

func TestL66NoInventoryHoldsAToken(t *testing.T) {
	inv := l66Inventory(l66InvSpec{Hosts: []l66Host{{"leaf1", "172.100.100.11"}}, Platform: l66Platforms["arista_eos"], Conn: "network_cli", SSHType: "libssh", Mode: "lookup"})
	if got := l66FindTokens(inv, map[string]bool{sha(l66Token): true}, len(l66Token)); len(got) != 0 {
		t.Errorf("an inventory is written before any mint: %v", got)
	}
	if strings.Contains(inv, "ansible_ssh_pass") || strings.Contains(inv, "password: '") {
		t.Errorf("no literal password in the inventory:\n%s", inv)
	}
}

func TestL66ParsesGalaxyListAndNamesWhatIsMissing(t *testing.T) {
	js := `{"/c/clients/ansible/ansible_collections":{"port49.client":{"version":"0.1.0"}},` +
		`"/c/l66/.collections/ansible_collections":{"ansible.netcommon":{"version":"8.7.0"},"arista.eos":{"version":"12.3.0"},"cisco.nxos":{"version":"13.0.0"}}}`
	have, err := l66ParseGalaxy(js)
	if err != nil {
		t.Fatal(err)
	}
	if have["ansible.netcommon"] != "8.7.0" || have["port49.client"] != "0.1.0" {
		t.Errorf("have = %v", have)
	}
	miss := l66Missing(have)
	if !slices.Equal(miss, []string{"cisco.ios", "junipernetworks.junos"}) {
		t.Errorf("missing = %v, want the two the five platforms still need", miss)
	}
	if got := l66Missing(map[string]string{}); len(got) != 6 {
		t.Errorf("nothing installed misses %v, want netcommon, the four platforms and port49.client", got)
	}
	if _, err := l66ParseGalaxy("not json"); err == nil {
		t.Error("an unreadable list is an error, never an empty one")
	}
	if _, err := l66ParseGalaxy(""); err == nil {
		t.Error("an empty list is an error")
	}
}

func TestL66SnapshotNoticesAChangeAndSaysWhatWasAdded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(p, []byte("# mine\nh ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := l66Snapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	if ch, err := s.Changed(); err != nil || ch {
		t.Fatalf("an untouched file: changed %v, err %v", ch, err)
	}
	if err := os.WriteFile(p, []byte("# mine\nh ssh-ed25519 AAAA\n172.100.100.11 ssh-rsa BBBB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ch, _ := s.Changed(); !ch {
		t.Fatal("a file with a line added is changed")
	}
	d, err := s.Diff()
	if err != nil {
		t.Fatal(err)
	}
	if d.Mode != "appended" || len(d.Added) != 1 || d.Added[0].Hosts != "172.100.100.11" {
		t.Errorf("diff = %+v", d)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "172.100.100.11") {
		t.Error("the snapshot never writes the file back: it may hold the operator's own additions")
	}
}

func TestL66SnapshotOfAMissingFileSeesItCreated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "known_hosts")
	s, err := l66Snapshot(p)
	if err != nil || s.Exists {
		t.Fatalf("snapshot of a missing file: %+v %v", s, err)
	}
	if ch, _ := s.Changed(); ch {
		t.Error("a file still missing is unchanged")
	}
	if err := os.WriteFile(p, []byte("x ssh-rsa AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ch, _ := s.Changed(); !ch {
		t.Error("a created file is changed")
	}
	if d, err := s.Diff(); err != nil || len(d.Added) != 1 {
		t.Errorf("diff = %+v, %v", d, err)
	}
}

func TestL66ClientSumsAndTheirDifference(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"a.py": "one\n", "b.py": "two\n", "notes.txt": "skipped\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tree, err := l66ClientSums(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 2 || tree["a.py"] != sha("one\n") {
		t.Fatalf("sums = %v: the .py files only, by SHA-256", tree)
	}
	installed := l66ParseSums("a.py " + sha("one\n") + "\nb.py " + sha("other\n") + "\nextra.py " + sha("x") + "\n\nbad line\n")
	if len(installed) != 3 {
		t.Fatalf("parsed = %v", installed)
	}
	if got := l66DiffFileSums(tree, installed); !slices.Equal(got, []string{"b.py differs"}) {
		t.Errorf("diff = %v, want only b.py (an extra file in the venv is not stale code)", got)
	}
	delete(installed, "a.py")
	if got := l66DiffFileSums(tree, installed); !slices.Equal(got, []string{"a.py missing", "b.py differs"}) {
		t.Errorf("diff = %v", got)
	}
	if got := l66DiffFileSums(tree, tree); len(got) != 0 {
		t.Errorf("identical sums differ: %v", got)
	}
}

func TestL66InstallCommandNamesTheDirectoryAndEveryCollection(t *testing.T) {
	c := l66InstallCommand("/r/tests/lab/l66/.collections")
	for _, want := range []string{"ansible-galaxy collection install", "-p /r/tests/lab/l66/.collections", "ansible.netcommon", "arista.eos",
		"cisco.nxos", "cisco.ios", "junipernetworks.junos"} {
		if !strings.Contains(c, want) {
			t.Errorf("%q is missing from %q", want, c)
		}
	}
	if strings.Contains(c, "port49.client") {
		t.Error("port49.client comes from the tree (clients/ansible), never from Galaxy")
	}
}

// l66StubPort49 is a port49 CLI that permits every device with a made-up token and logs each call, for a play
// that needs no agent and no broker.
const l66StubPort49 = `#!/bin/sh
echo call >> "$(dirname "$0")/calls.log"
printf '%s\n' '{"device":"leaf1","verdict":"permit","address":"127.0.0.1","platform":"arista_eos","username":"alice","login":"STUBLOGINTOKEN","expires_at":"2026-10-13T10:00:00Z"}'
`

// TestL66FactPlaysMintUnderRealAnsible runs the harness's own fact inventory and minted-once plays, for
// network_cli and for ansible.builtin.ssh, under the lab venv's ansible-core with a stub port49, against a
// closed local port: no device, agent or broker. ansible-core templates the connection variables into
// remote_user and password for the mint's set_fact too, before the fact exists (2.21.4), so a fact read
// without a default fails every fact cell at its mint (re-review 3, C1). The mint must pass, and the next
// task must reach the connection. Skipped without the lab venv or the L66 collections.
func TestL66FactPlaysMintUnderRealAnsible(t *testing.T) {
	r, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	pb, coll := filepath.Join(l66Venv, "ansible-playbook"), filepath.Join(r, "tests", "lab", "l66", ".collections")
	for _, p := range []string{pb, filepath.Join(coll, "ansible_collections", "ansible", "netcommon"),
		filepath.Join(coll, "ansible_collections", "arista", "eos")} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s is not installed (the L66 preflight's venv and collections): %v", p, err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // closed: the connection is refused, so no login is ever attempted
	for _, conn := range []string{"network_cli", "ssh"} {
		t.Run(conn, func(t *testing.T) {
			dir := t.TempDir()
			// network_cli's and ssh's sockets: a short path, inside AF_UNIX's limit.
			cp, err := os.MkdirTemp("", "p49cp")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(cp) })
			bin := filepath.Join(dir, "port49")
			if err := os.WriteFile(bin, []byte(l66StubPort49), 0o700); err != nil {
				t.Fatal(err)
			}
			s := l66InvSpec{Hosts: []l66Host{{"leaf1", "127.0.0.1"}}, Socket: filepath.Join(dir, "agent.sock"), Bin: bin,
				Platform: l66Platforms["arista_eos"], Conn: conn, SSHType: "libssh", Mode: "fact", ConnectTimeout: 5}
			kind := "once"
			if conn == "ssh" {
				kind = "raw"
				s.SSHCommonArgs = "-F /dev/null"
				s.SSHExtraArgs = "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=" + filepath.Join(dir, "known_hosts")
			}
			inv, play := filepath.Join(dir, "inv.yml"), filepath.Join(dir, "play.yml")
			if err := os.WriteFile(inv, []byte(l66Inventory(s)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(play, []byte(l66Playbook(kind, s.Platform, 1, "")), 0o600); err != nil {
				t.Fatal(err)
			}
			env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "ANSIBLE_HOME=" + filepath.Join(dir, ".ansible"),
				"ANSIBLE_COLLECTIONS_PATH=" + filepath.Join(r, "clients", "ansible") + ":" + coll, "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=false",
				"PYTHONPATH=" + filepath.Join(r, "clients", "python", "src"), "PYTHONDONTWRITEBYTECODE=1", "ANSIBLE_NOCOLOR=1",
				"ANSIBLE_REMOTE_PORT=" + strconv.Itoa(port), "ANSIBLE_HOST_KEY_CHECKING=False",
				"ANSIBLE_PERSISTENT_CONTROL_PATH_DIR=" + cp, "ANSIBLE_SSH_CONTROL_PATH_DIR=" + cp,
				"ANSIBLE_PERSISTENT_CONNECT_TIMEOUT=5", "ANSIBLE_SSH_PASSWORD_MECHANISM=ssh_askpass"}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			stdout, stderr, exit, err := l64Run(ctx, env, dir, pb, "-i", inv, play)
			out := stdout + "\n" + stderr
			if err != nil {
				t.Fatalf("ansible-playbook: %v\n%s", err, out)
			}
			if strings.Contains(out, "is undefined") {
				t.Errorf("the play read the fact before its mint set it:\n%s", out)
			}
			rc := l66ReadRecap(stdout)["leaf1"]
			if rc.OK != 1 || rc.Failed+rc.Unreachable != 1 || exit == 0 {
				t.Errorf("recap %+v, exit %d: want the mint ok and the next task failed at the closed port\n%s", rc, exit, out)
			}
			if !strings.Contains(out, "TASK [show version 1]") || !strings.Contains(out, "Connection refused") {
				t.Errorf("the task after the mint did not reach the closed port:\n%s", out)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
			if n := strings.Count(string(calls), "call"); n != 1 {
				t.Errorf("port49 was called %d times, want 1 (the mint)", n)
			}
		})
	}
}

// l66PagingCLI stands in for a network CLI run with a command (an sshd's ForceCommand): it prints the command's
// output and, on a terminal, pages as Junos does (---(more)---), waiting for a key before it exits. Without a
// terminal it exits.
const l66PagingCLI = `#!/bin/sh
echo "cli: $SSH_ORIGINAL_COMMAND"
if [ -t 0 ]; then
  printf -- '---(more)---'
  read -r _
fi
echo "cli: done"
`

// TestL66RawOverSSHEndsAtACLIThatPagesOnATerminal runs the harness's own ansible.builtin.ssh inventory and raw
// play under the lab venv's ansible-core against a scratch sshd on 127.0.0.1 whose login runs l66PagingCLI. In
// lab run 2 the raw play logged in to vJunos and vSRX, its `show version` was accounted at once, and the session
// stayed open until the play's deadline: the ssh plugin's use_tty (default true) runs `raw` as `ssh -tt`, and a
// CLI given a terminal pages. The inventory turns use_tty off, so the play ends. Everything runs under
// nss_wrapper with a private home, a key login made for the test, and no agent. Skipped without the venv, sshd
// or nss_wrapper.
func TestL66RawOverSSHEndsAtACLIThatPagesOnATerminal(t *testing.T) {
	r, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	pb, sshd := filepath.Join(l66Venv, "ansible-playbook"), "/usr/sbin/sshd"
	for _, p := range []string{pb, sshd} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s is not installed: %v", p, err)
		}
	}
	lib, found := l66FindNSSWrapper(l66NSSDirs)
	if !found {
		t.Skip("libnss_wrapper.so is not installed")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	// ssh's control sockets: a short path, inside AF_UNIX's limit.
	cp, err := os.MkdirTemp("", "p49cp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(cp) })
	p := func(name string) string { return filepath.Join(dir, name) }
	for _, k := range []string{"host_key", "user_key"} {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "l66", "-f", p(k)).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
	}
	pub, err := os.ReadFile(p("user_key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	stub := strings.Replace(l66StubPort49, `"username":"alice"`, `"username":"`+u.Username+`"`, 1)
	for name, body := range map[string]string{
		"authorized_keys": string(pub), "nss_passwd": l66NSSPasswd(u.Username, uid, gid, home, "/bin/sh"),
		"nss_group": l66NSSGroup(u.Username, gid),
		"sshd_config": fmt.Sprintf("ListenAddress 127.0.0.1\nPort %d\nHostKey %s\nPidFile none\nUsePAM no\nStrictModes no\n"+
			"PermitUserRC no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthorizedKeysFile %s\nForceCommand %s\n"+
			"AllowTcpForwarding no\nX11Forwarding no\n", port, p("host_key"), p("authorized_keys"), p("cli")),
		"ssh_config": fmt.Sprintf("Host *\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile /dev/null\n  IdentityFile %s\n"+
			"  IdentitiesOnly yes\n  IdentityAgent none\n  StrictHostKeyChecking accept-new\n", filepath.Join(home, ".ssh", "known_hosts"),
			p("user_key")),
	} {
		if err := os.WriteFile(p(name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"cli": l66PagingCLI, "port49": stub} {
		if err := os.WriteFile(p(name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	base := []string{"PATH=" + os.Getenv("PATH")}
	srv := exec.Command(sshd, "-D", "-e", "-f", p("sshd_config"))
	srv.Env = l66PrivateEnv(base, home, lib, p("nss_passwd"), p("nss_group"))
	srv.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	slog, err := os.Create(p("sshd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer slog.Close()
	srv.Stdout, srv.Stderr = slog, slog
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-srv.Process.Pid, syscall.SIGKILL)
		_ = srv.Wait()
	})
	for i := 0; ; i++ {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err == nil {
			c.Close()
			break
		}
		if i == 50 {
			b, _ := os.ReadFile(p("sshd.log"))
			t.Fatalf("the scratch sshd never listened: %v\n%s", err, b)
		}
		time.Sleep(100 * time.Millisecond)
	}

	s := l66InvSpec{Hosts: []l66Host{{"srx1", "127.0.0.1"}}, Socket: p("agent.sock"), Bin: p("port49"),
		Platform: l66Platforms["juniper_vjunos-router"], Conn: "ssh", Mode: "fact", SSHCommonArgs: "-F " + p("ssh_config")}
	if err := os.WriteFile(p("inv.yml"), []byte(l66Inventory(s)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p("play.yml"), []byte(l66Playbook("raw", s.Platform, 1, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(l66PrivateEnv(base, home, lib, p("nss_passwd"), p("nss_group")), "ANSIBLE_HOME="+filepath.Join(home, ".ansible"),
		"ANSIBLE_COLLECTIONS_PATH="+filepath.Join(r, "clients", "ansible"), "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=false",
		"PYTHONPATH="+filepath.Join(r, "clients", "python", "src"), "PYTHONDONTWRITEBYTECODE=1", "ANSIBLE_NOCOLOR=1",
		"ANSIBLE_REMOTE_PORT="+strconv.Itoa(port), "ANSIBLE_HOST_KEY_CHECKING=True", "ANSIBLE_SSH_CONTROL_PATH_DIR="+cp,
		"ANSIBLE_SSH_PASSWORD_MECHANISM=ssh_askpass")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// -v prints the raw task's stdout: the CLI's lines.
	stdout, stderr, exit, err := l64Run(ctx, env, dir, pb, "-v", "-i", p("inv.yml"), p("play.yml"))
	// The play's ControlPersist master, by its exact socket.
	socks, _ := filepath.Glob(filepath.Join(cp, "*"))
	for _, sock := range socks {
		_ = exec.Command("ssh", "-F", "/dev/null", "-O", "exit", "-S", sock, "l66").Run()
	}
	out := stdout + "\n" + stderr
	if err != nil {
		t.Fatalf("the raw play did not end on its own at a CLI that pages on a terminal: %v\n%s", err, out)
	}
	if rc := l66ReadRecap(stdout)["srx1"]; exit != 0 || rc.OK != 2 || !rc.Passed() {
		t.Errorf("exit %d, recap %+v: want the mint and the raw task ok\n%s", exit, rc, out)
	}
	if !strings.Contains(out, "cli: show version") || !strings.Contains(out, "cli: done") {
		t.Errorf("the raw task did not reach the CLI and see it exit:\n%s", out)
	}
}
