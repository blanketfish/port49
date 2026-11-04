package labpcap

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/tests/lab/labcreds"
)

// TestRedactRemovesEveryCredentialAndNothingElse is the whole contract in one
// test: the tokens are gone, the packets are otherwise the packets that were
// captured, and the file still decodes under the same key.
func TestRedactRemovesEveryCredentialAndNothingElse(t *testing.T) {
	in := fullRun(t, false)
	opt := synthOptions()

	// The input really does carry the credentials. A test that redacted an
	// empty capture would pass just as loudly.
	if !bytes.Contains(deobfuscatedBodies(t, in, opt.Key), []byte(synthToken)) {
		t.Fatal("the synthetic capture does not carry the ASCII password; the test proves nothing")
	}

	out, st, err := Redact(in, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(in, out, opt); err != nil {
		t.Fatal(err)
	}
	// One ASCII password in a CONTINUE, one PAP password in a START.
	if st.FieldsRedacted != 2 || st.BytesRedacted != len(synthToken)+len(synthToken2) {
		t.Errorf("redacted %d field(s), %d bytes; want 2 and %d", st.FieldsRedacted, st.BytesRedacted,
			len(synthToken)+len(synthToken2))
	}
	if st.RecordsKept != st.RecordsIn {
		t.Errorf("kept %d of %d records; the capture is all TACACS+ and none should be dropped", st.RecordsKept, st.RecordsIn)
	}
	if st.Packets != 10 {
		t.Errorf("framed %d TACACS+ packets, want 10", st.Packets)
	}

	bodies := deobfuscatedBodies(t, out, opt.Key)
	for _, s := range []string{synthToken, synthToken2, labcreds.TokenPrefix} {
		if bytes.Contains(bodies, []byte(s)) {
			t.Errorf("a credential string survived into the decoded output")
			break
		}
	}
	if bytes.Contains(out, []byte(labcreds.TokenPrefix)) {
		t.Error("the output file's raw bytes hold the lab token prefix in the clear")
	}

	// The fields that are not credentials are still there in full: an
	// evidence file that lost the username or the AV pairs would be useless
	// for the thing the notes quote it for.
	got := decodeFields(t, out, opt.Key)
	for _, want := range []string{"alice01", "alice02", "ssh", "command-api", "service=shell", "task_id=42", "Password: "} {
		if !containsField(got, want) {
			t.Errorf("the output lost %q, which carries no credential", want)
		}
	}
}

// TestRedactKeepsEveryLengthAndSequenceNumber is the property that lets a
// reader diff an evidence file against a results note: same packets, same
// count, same framing.
func TestRedactKeepsEveryLengthAndSequenceNumber(t *testing.T) {
	in := fullRun(t, false)
	out, _, err := Redact(in, synthOptions())
	if err != nil {
		t.Fatal(err)
	}
	inF, _ := Parse(in)
	outF, _ := Parse(out)
	if len(inF.Records) != len(outF.Records) {
		t.Fatalf("%d records out, %d in", len(outF.Records), len(inF.Records))
	}
	for i := range inF.Records {
		ir, or := inF.Records[i], outF.Records[i]
		if ir.InclLen != or.InclLen || ir.OrigLen != or.OrigLen {
			t.Fatalf("record %d: %d/%d out, %d/%d in", i, or.InclLen, or.OrigLen, ir.InclLen, ir.OrigLen)
		}
		ifl, _ := FlowOf(inF.Link, inF.Bytes(ir))
		ofl, ok := FlowOf(outF.Link, outF.Bytes(or))
		if !ok || ifl.Seq != ofl.Seq || ifl.SrcPort != ofl.SrcPort || ifl.PayloadLen != ofl.PayloadLen {
			t.Fatalf("record %d: seq/ports/payload changed", i)
		}
	}
	// Headers are never obfuscated and never rewritten.
	inD, _ := inF.Decode(synthKey, nil)
	outD, _ := outF.Decode(synthKey, nil)
	if len(inD.Packets) != len(outD.Packets) {
		t.Fatalf("%d packets out, %d in", len(outD.Packets), len(inD.Packets))
	}
	for i := range inD.Packets {
		if inD.Packets[i].Header != outD.Packets[i].Header {
			t.Errorf("packet %d: the TACACS+ header changed", i)
		}
	}
}

// TestVerifyCatchesAMissedField is the test that makes the other ones worth
// anything. A verifier that has never been seen to fail is not known to work,
// so this one deliberately leaves the ASCII password in place and requires
// Verify to say so.
func TestVerifyCatchesAMissedField(t *testing.T) {
	in := fullRun(t, false)
	opt := synthOptions()
	opt.SkipFields = map[string]bool{"authen_continue.user_msg": true}

	out, st, err := Redact(in, opt)
	if err != nil {
		t.Fatal(err)
	}
	if st.FieldsRedacted != 1 {
		t.Fatalf("with one field skipped the pass redacted %d; want 1", st.FieldsRedacted)
	}
	err = Verify(in, out, opt)
	if err == nil {
		t.Fatal("Verify passed a capture that still holds the ASCII password")
	}
	if !strings.Contains(err.Error(), "authen_continue.user_msg") {
		t.Errorf("the failure must name the field that survived, got: %v", err)
	}

	// And the same with the PAP field, so neither is caught only by accident.
	opt.SkipFields = map[string]bool{"authen_start.data": true}
	out, _, err = Redact(in, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(in, out, opt); err == nil || !strings.Contains(err.Error(), "authen_start.data") {
		t.Errorf("a surviving PAP password must fail verification by name, got: %v", err)
	}
}

// TestRedactPatchesEveryCopyOfASegment is the `tcpdump -i any` case.
//
// The capture sees each packet twice, on the bridge and on the veth. The
// reassembly drops the duplicate, so a redactor that wrote back through the
// reassembled stream alone would leave the password in the copy it dropped —
// and every note in the repository is written from a capture taken this way.
func TestRedactPatchesEveryCopyOfASegment(t *testing.T) {
	s := newSynth()
	start := wire.AuthenStart{
		Action: wire.AuthenActionLogin, PrivLvl: 15, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice01"), Port: []byte("ssh"),
		RemAddr: []byte("192.0.2.9"), Data: []byte(synthToken),
	}
	pkt := tacacs(0x55555555, wire.TypeAuthen, 1, start.Encode())
	s.segment(synthDevice, synthServer, 50005, Port, 1000, flagSYN, nil, false)
	s.segment(synthDevice, synthServer, 50005, Port, 1000, flagSYN, nil, false) // the veth copy
	s.segment(synthDevice, synthServer, 50005, Port, 1001, flagACK, pkt, false)
	s.segment(synthDevice, synthServer, 50005, Port, 1001, flagACK, pkt, false) // and again
	in := s.buf

	opt := synthOptions()
	out, st, err := Redact(in, opt)
	if err != nil {
		t.Fatal(err)
	}
	if st.RecordsPatched != 2 {
		t.Errorf("patched %d record(s); both copies of the segment carry the password", st.RecordsPatched)
	}
	if err := Verify(in, out, opt); err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(out, []byte(synthToken)); n != 0 {
		t.Errorf("the token is still in the output %d time(s)", n)
	}
	// Byte for byte, the two copies must still be identical to each other.
	f, _ := Parse(out)
	if len(f.Records) != 4 {
		t.Fatalf("%d records, want 4", len(f.Records))
	}
	if !bytes.Equal(f.Bytes(f.Records[2]), f.Bytes(f.Records[3])) {
		t.Error("the two copies of the same segment were redacted differently")
	}
}

// TestRedactHandlesAPacketSplitAcrossSegments: a body that arrives in two TCP
// segments has its credential split across two records, and both halves have to
// be found. The framing only exists in the reassembled stream, which is why the
// redactor works in stream coordinates and maps back.
func TestRedactHandlesAPacketSplitAcrossSegments(t *testing.T) {
	s := newSynth()
	cont := wire.AuthenContinue{UserMsg: []byte(synthToken)}
	pkt := tacacs(0x66666666, wire.TypeAuthen, 3, cont.Encode())
	cut := len(pkt) - 6 // mid-password
	s.segment(synthDevice, synthServer, 50006, Port, 1000, flagSYN, nil, false)
	s.segment(synthDevice, synthServer, 50006, Port, 1001, flagACK, pkt[:cut], false)
	s.segment(synthDevice, synthServer, 50006, Port, uint32(1001+cut), flagACK, pkt[cut:], false)
	in := s.buf

	opt := synthOptions()
	out, st, err := Redact(in, opt)
	if err != nil {
		t.Fatal(err)
	}
	if st.RecordsPatched != 2 {
		t.Errorf("patched %d record(s); the password straddles both segments", st.RecordsPatched)
	}
	if err := Verify(in, out, opt); err != nil {
		t.Fatal(err)
	}
}

// TestRedactRefusesASequenceGap: a stream with a hole was never fully framed,
// so a credential could sit in the part this tool cannot read. Refusing is the
// only safe answer, and the error has to say why.
func TestRedactRefusesASequenceGap(t *testing.T) {
	s := newSynth()
	cont := wire.AuthenContinue{UserMsg: []byte(synthToken)}
	pkt := tacacs(0x77777777, wire.TypeAuthen, 3, cont.Encode())
	s.segment(synthDevice, synthServer, 50007, Port, 1000, flagSYN, nil, false)
	s.segment(synthDevice, synthServer, 50007, Port, 1001, flagACK, pkt, false)
	s.segment(synthDevice, synthServer, 50007, Port, 9999, flagACK, pkt, false) // a hole

	_, _, err := Redact(s.buf, synthOptions())
	if err == nil {
		t.Fatal("a capture with a sequence gap must not produce evidence")
	}
	if !strings.Contains(err.Error(), "gap") {
		t.Errorf("the error must say what it refused, got: %v", err)
	}
}

// TestRedactChecksums: a patched packet whose checksum was right is made right
// again; one whose checksum was already wrong is left exactly as it was found.
//
// The second half is not a shortcut. Every capture in tests/lab/captures has
// mostly-wrong TCP checksums — the packets are written to the savefile before
// checksum offload fills the field in, and tcpdump -vvv calls them incorrect
// too. Computing a correct checksum for the handful of packets this tool
// rewrites would make exactly the redacted packets the only correct ones in the
// file, which is a worse lie than leaving them alone.
func TestRedactChecksums(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{{"valid in the capture", true}, {"offloaded, wrong in the capture", false}} {
		t.Run(tc.name, func(t *testing.T) {
			in := fullRun(t, tc.valid)
			opt := synthOptions()
			out, st, err := Redact(in, opt)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(in, out, opt); err != nil {
				t.Fatal(err)
			}
			if tc.valid && (st.ChecksumsRecomputed != st.RecordsPatched || st.ChecksumsLeftStale != 0) {
				t.Errorf("recomputed %d of %d patched records, left %d stale; all were valid on input",
					st.ChecksumsRecomputed, st.RecordsPatched, st.ChecksumsLeftStale)
			}
			if !tc.valid && (st.ChecksumsLeftStale != st.RecordsPatched || st.ChecksumsRecomputed != 0) {
				t.Errorf("left %d of %d patched records stale, recomputed %d; none was valid on input",
					st.ChecksumsLeftStale, st.RecordsPatched, st.ChecksumsRecomputed)
			}
			// And the claim itself, checked from the output.
			f, _ := Parse(out)
			for i, r := range f.Records {
				fl, ok := FlowOf(f.Link, f.Bytes(r))
				if !ok || fl.PayloadLen == 0 {
					continue
				}
				if got := checksumOK(fl.Src, fl.Dst, f.Bytes(r)[fl.TCPOff:]); got != tc.valid {
					t.Errorf("record %d: checksum valid=%v, want %v", i, got, tc.valid)
				}
			}
		})
	}
}

// TestRedactDropsOnlyNonTACACSTraffic, and never a device packet: a results
// note quotes a count of packets to or from the lab subnet, and evidence
// holding fewer of them than the note claims is evidence of nothing.
func TestRedactDropsOnlyNonTACACSTraffic(t *testing.T) {
	s := newSynth()
	asciiLogin(s, 50008, 0x88888888, "alice01", synthToken, false)
	// An SSH segment between two hosts outside the lab subnet: dropped.
	s.segment("198.51.100.5", "198.51.100.9", 40000, 22, 1, flagACK, []byte("not tacacs"), false)
	in := s.buf

	opt := synthOptions()
	out, st, err := Redact(in, opt)
	if err != nil {
		t.Fatal(err)
	}
	if st.Dropped["not_port_49"] != 1 || st.RecordsKept != st.RecordsIn-1 {
		t.Errorf("dropped %v, kept %d of %d", st.Dropped, st.RecordsKept, st.RecordsIn)
	}
	if bytes.Contains(out, []byte("not tacacs")) {
		t.Error("non-TACACS traffic survived into the evidence")
	}
	if err := Verify(in, out, opt); err != nil {
		t.Fatal(err)
	}

	// The same packet inside the lab subnet is an error, not a drop.
	s2 := newSynth()
	asciiLogin(s2, 50009, 0x99999999, "alice01", synthToken, false)
	s2.segment(synthDevice, synthServer, 40000, 22, 1, flagACK, []byte("ssh to the device"), false)
	_, sn, _ := net.ParseCIDR("172.100.100.0/24")
	opt2 := synthOptions()
	opt2.Subnet = sn
	if _, _, err := Redact(s2.buf, opt2); err == nil {
		t.Fatal("dropping a packet to or from the lab subnet must be an error")
	}
}

// TestRedactedFileDecodesUnderTheSameKey is what the whole exercise is for: an
// evidence file someone opens in Wireshark with the published key and reads.
func TestRedactedFileDecodesUnderTheSameKey(t *testing.T) {
	in := fullRun(t, false)
	out, _, err := Redact(in, synthOptions())
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.Decode(synthKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Packets) != 10 {
		t.Fatalf("decoded %d packets from the evidence, want 10", len(d.Packets))
	}
	fields, err := d.Fields()
	if err != nil {
		t.Fatalf("the evidence no longer decodes as RFC 8907: %v", err)
	}
	var creds int
	for _, fd := range fields {
		if !fd.Credential || fd.Len == 0 {
			continue
		}
		creds++
		if !labcreds.Redacted(fd.Bytes(d.Packets[fd.Packet].Body)) {
			t.Errorf("%s is not all %q", fd.Name, string(rune(Fill)))
		}
	}
	if creds != 2 {
		t.Errorf("found %d non-empty credential fields in the evidence, want 2", creds)
	}
}

// TestParseRefusesWhatItCannotRead: a results note must never quote a count
// taken from a file this parser guessed at.
func TestParseRefusesWhatItCannotRead(t *testing.T) {
	if _, err := Parse([]byte("too short")); err == nil {
		t.Error("a file shorter than a pcap header must be refused")
	}
	bad := append([]byte(nil), fullRun(t, false)...)
	binary.LittleEndian.PutUint32(bad[0:4], 0xdeadbeef)
	if _, err := Parse(bad); err == nil {
		t.Error("an unexpected magic must be refused")
	}
	// A record claiming more bytes than the file's snaplen is corruption.
	corrupt := append([]byte(nil), fullRun(t, false)...)
	binary.LittleEndian.PutUint32(corrupt[FileHeaderLen+8:FileHeaderLen+12], 1<<20)
	if _, err := Parse(corrupt); err == nil {
		t.Error("a record longer than the snaplen must be refused")
	}
}

// ---------------------------------------------------------------------------

func deobfuscatedBodies(t *testing.T, raw []byte, key string) []byte {
	t.Helper()
	f, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.Decode(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, p := range d.Packets {
		out = append(out, p.Body...)
	}
	return out
}

func decodeFields(t *testing.T, raw []byte, key string) []string {
	t.Helper()
	f, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.Decode(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := d.Fields()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, fd := range fields {
		out = append(out, string(fd.Bytes(d.Packets[fd.Packet].Body)))
	}
	return out
}

func containsField(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

// TestVerifyAcceptsAPasswordThatIsAlreadyFill: an operator who types a wrong
// password of all Fill bytes puts the redaction's own output on the wire.
// Overwriting it changes nothing and it can leak nothing, so the verifier must
// not refuse the file because the input "carried" what the output holds.
func TestVerifyAcceptsAPasswordThatIsAlreadyFill(t *testing.T) {
	s := newSynth()
	papLogin(s, 50002, 0x22222222, "alice02", strings.Repeat(string(rune(Fill)), 30), false)
	asciiLogin(s, 50001, 0x11111111, "alice01", synthToken, false)
	opt := synthOptions()
	out, _, err := Redact(s.buf, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(s.buf, out, opt); err != nil {
		t.Fatal(err)
	}
}

// Port 300 is kept verbatim when each direction opens with a TLS handshake record, and refused
// when it carries anything else: a device sending plain TACACS+ to 300 must not reach evidence.
func TestRedactKeepsTLSOnPort300AndRefusesPlainTACACS(t *testing.T) {
	s := newSynth()
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x04, 1, 2, 3, 4}
	s.segment(synthDevice, synthServer, 50100, TLSPort, 1000, flagSYN, nil, false)
	s.segment(synthDevice, synthServer, 50100, TLSPort, 1001, flagACK, hello, false)
	s.segment(synthServer, synthDevice, TLSPort, 50100, 2000, flagACK, []byte{0x16, 0x03, 0x03, 0x00, 0x02, 9, 9}, false)
	opt := synthOptions()
	out, st, err := Redact(s.buf, opt)
	if err != nil {
		t.Fatal(err)
	}
	if st.RecordsKept != st.RecordsIn || st.Dropped["not_port_49"] != 0 {
		t.Errorf("kept %d of %d, dropped %v", st.RecordsKept, st.RecordsIn, st.Dropped)
	}
	if err := Verify(s.buf, out, opt); err != nil {
		t.Errorf("verify: %v", err)
	}

	p := newSynth()
	p.segment(synthDevice, synthServer, 50101, TLSPort, 1001, flagACK, []byte{0xc0, 0x01, 0x01, 0x00, 0x00}, false)
	if _, _, err := Redact(p.buf, synthOptions()); err == nil {
		t.Error("plain TACACS+ on port 300 was accepted into evidence")
	}
}
