package labpcap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/tests/lab/labcreds"
)

// The committed evidence audited on its own, as CI runs it: no capture is needed, because the
// invariants (every credential field all Fill, no token-shaped string, no password hash in an
// accounting or authorization argument) are properties of the evidence file. Counts only; a
// failure names a file and numbers, never a byte of a body.

func TestAuditEvidenceCountsANonFillCredential(t *testing.T) {
	s := newSynth()
	papLogin(s, 50002, 0x22222222, "alice02", "xxxxAbcdxxxx", true) // not all Fill, not token-shaped
	r, err := AuditEvidence(s.buf, Options{Key: synthKey})
	if r.NotFill != 1 {
		t.Fatalf("NotFill = %d, want 1 (report %+v)", r.NotFill, r)
	}
	if err == nil {
		t.Fatal("a credential field that is not all Fill is not an error")
	}
	if !strings.Contains(err.Error(), "authen_start.data") || strings.Contains(err.Error(), "Abcd") {
		t.Errorf("the error should name the field kind and nothing of its bytes: %v", err)
	}
}

func TestAuditEvidenceCountsAHashInAnAccountingArg(t *testing.T) {
	// Built from fragments: the shapes are the point, and a literal would trip the secret scanner.
	d := "$"
	for _, arg := range []string{
		"cmd=username bob secret 5 x " + d + "6" + d + "salt" + d + "abcdefgh",
		"cmd=snmp-server " + "key 7 " + "0822455D0A16",
		"cmd=enable " + "secret 0 " + "word",
		"cmd=set system root-authentication encrypted-password " + d + "9" + d + "abcdef",
		"cmd=x " + d + "aes1" + d + "abcdef",
	} {
		s := newSynth()
		req := wire.AcctRequest{
			Flags: wire.AcctFlagStart, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15,
			AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin,
			User: []byte("alice01"), Port: []byte("ssh"), RemAddr: []byte("192.0.2.9"),
			Args: [][]byte{[]byte("task_id=42"), []byte(arg)},
		}
		reply := wire.AcctReply{Status: 0x01}
		s.exchange(50004, [][]byte{
			tacacs(0x44444444, wire.TypeAcct, 1, req.Encode()),
			tacacs(0x44444444, wire.TypeAcct, 2, reply.Encode()),
		}, []bool{true, false}, true)
		r, err := AuditEvidence(s.buf, Options{Key: synthKey})
		if r.HashShaped != 1 || err == nil {
			t.Errorf("a hash-shaped argument: HashShaped = %d, err = %v (report %+v)", r.HashShaped, err, r)
		}
		if err != nil && strings.Contains(err.Error(), "abcdefgh") {
			t.Errorf("the error carries argument bytes: %v", err)
		}
	}
}

func TestAuditEvidenceAcceptsTheRedactedRun(t *testing.T) {
	out, _, err := Redact(fullRun(t, true), synthOptions())
	if err != nil {
		t.Fatal(err)
	}
	r, err := AuditEvidence(out, Options{Key: synthKey})
	if err != nil {
		t.Fatalf("redacted evidence failed its audit: %v (%+v)", err, r)
	}
	if r.CredentialFields == 0 || r.Unaudited != 0 {
		t.Errorf("report %+v: want credential fields counted and nothing unaudited", r)
	}
}

func TestCommittedEvidenceHoldsNoCredential(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Fatal(err)
	}
	names, _ := filepath.Glob(filepath.Join(root, "tests", "lab", "evidence", "*.pcap"))
	if len(names) == 0 {
		t.Fatal("no committed evidence in tests/lab/evidence: the evidence is committed, so this never skips")
	}
	seenTLS := map[string]bool{}
	for _, n := range names {
		base := filepath.Base(n)
		raw, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		opt := Options{Key: labcreds.Key}
		if k := labcreds.CaptureKey(base); k != "" {
			opt.Key = k
		}
		problems, r := auditCommitted(base, raw, opt, tlsEvidence)
		t.Logf("%s: %+v", base, r)
		if r.TLS > 0 {
			seenTLS[base] = true
		}
		for _, p := range problems {
			t.Errorf("%s", p)
		}
	}
	for name := range tlsEvidence {
		if !seenTLS[name] {
			t.Errorf("%s is on the TLS allowlist but is not committed or holds no TLS run: remove it", name)
		}
	}
}

// tlsEvidence names the committed files that are RFC 9887 TLS runs. Ciphertext cannot be audited
// without the session keys, and the lab keeps none (no keylog), so each file is exempt by name and
// reason; a TLS file not listed here fails.
var tlsEvidence = map[string]string{
	"L88-f-tls-ceos436-arista_ceos.pcap":            tlsReason,
	"L88-f-tls-iosxe1718-cisco_iosxe.pcap":          tlsReason,
	"L88-f-tls-nxos106-cisco_nxos.pcap":             tlsReason,
	"L88-f-tls-vjunos26-juniper_vjunos-router.pcap": tlsReason,
	"L88-f-tls-xrd261-cisco_xrd.pcap":               tlsReason,
}

const tlsReason = "RFC 9887 TLS 1.3 on port 300; ciphertext, the lab keeps nothing that decrypts it"

// auditCommitted is the rule for one committed file: any credential finding fails; plaintext
// port-49 data that frames nothing fails; a TLS run fails unless the file is on allow; a file with
// no port-49 payload at all is vacuous and passes (the caller logs its counts). It returns names
// and counts, never bytes.
func auditCommitted(base string, raw []byte, opt Options, allow map[string]string) ([]string, EvidenceReport) {
	r, err := AuditEvidence(raw, opt)
	var out []string
	if err != nil {
		out = append(out, fmt.Sprintf("%s: %v (counts %+v)", base, err, r))
	}
	if r.Unframed > 0 {
		out = append(out, fmt.Sprintf("%s: %d port-49 stream(s) carry data that is not TACACS+ and cannot be audited (counts %+v)", base, r.Unframed, r))
	}
	if r.Other > 0 {
		out = append(out, fmt.Sprintf("%s: %d record(s) are not IPv4 TCP on port 49 or 300 and cannot be audited (counts %+v)", base, r.Other, r))
	}
	if _, ok := allow[base]; r.TLS > 0 && !ok {
		out = append(out, fmt.Sprintf("%s: %d TLS stream(s) and the file is not on the RFC 9887 allowlist (counts %+v)", base, r.TLS, r))
	}
	return out, r
}

func TestAuditCommittedFailsAPlaintextStreamThatFramesNothing(t *testing.T) {
	s := newSynth()
	// port 49, not TACACS+: the bytes cannot be audited.
	s.exchange(50009, [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n")}, []bool{true}, true)
	problems, r := auditCommitted("synthetic.pcap", s.buf, Options{Key: synthKey}, nil)
	if r.Unframed != 1 || len(problems) != 1 {
		t.Fatalf("report %+v, problems %d: want one unframed stream failing", r, len(problems))
	}
}

func TestAuditCommittedFailsATLSFileNotOnTheAllowlist(t *testing.T) {
	s := newSynth()
	hello := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}
	s.segment(synthDevice, synthServer, 50010, TLSPort, 1000, flagSYN, nil, true)
	s.segment(synthDevice, synthServer, 50010, TLSPort, 1001, flagACK, hello, true)
	problems, r := auditCommitted("tls.pcap", s.buf, Options{Key: synthKey}, nil)
	if r.TLS != 1 || len(problems) != 1 {
		t.Fatalf("report %+v, problems %d: want one unlisted TLS file failing", r, len(problems))
	}
	if problems, _ := auditCommitted("tls.pcap", s.buf, Options{Key: synthKey}, map[string]string{"tls.pcap": "x"}); len(problems) != 0 {
		t.Errorf("an allowlisted TLS file failed: %v", problems)
	}
}

func TestAuditCommittedPassesAFileWithNoPort49Payload(t *testing.T) {
	s := newSynth()
	s.segment(synthDevice, synthServer, 50011, Port, 1000, flagSYN, nil, true)
	if problems, r := auditCommitted("empty.pcap", s.buf, Options{Key: synthKey}, nil); len(problems) != 0 {
		t.Errorf("a file with no payload failed: %v (%+v)", problems, r)
	}
}

func TestAuditCommittedFailsAStreamWithAnUnframedTail(t *testing.T) {
	s := newSynth()
	req := wire.AcctRequest{
		Flags: wire.AcctFlagStart, AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin,
		User: []byte("alice01"), Port: []byte("ssh"), RemAddr: []byte("192.0.2.9"),
		Args: [][]byte{[]byte("task_id=42")},
	}
	whole := tacacs(0x55555555, wire.TypeAcct, 1, req.Encode())
	cut := tacacs(0x55555555, wire.TypeAcct, 3, req.Encode())
	cut = cut[:len(cut)-5] // a packet whose body ends early: its header frames, its body does not
	s.exchange(50012, [][]byte{whole, cut}, []bool{true, true}, true)
	problems, r := auditCommitted("synthetic.pcap", s.buf, Options{Key: synthKey}, nil)
	if r.Unframed != 1 || len(problems) == 0 {
		t.Fatalf("report %+v, problems %d: want the unframed tail counted and failing", r, len(problems))
	}
}

func TestAuditCommittedChecksPort300EvenOnTheAllowlist(t *testing.T) {
	s := newSynth()
	plain := tacacs(0x66666666, wire.TypeAcct, 1, []byte{1, 2, 3, 4})
	s.segment(synthDevice, synthServer, 50013, TLSPort, 1000, flagSYN, nil, true)
	s.segment(synthDevice, synthServer, 50013, TLSPort, 1001, flagACK, plain, true)
	problems, _ := auditCommitted("tls.pcap", s.buf, Options{Key: synthKey}, map[string]string{"tls.pcap": "x"})
	if len(problems) == 0 {
		t.Fatal("plain TACACS+ on port 300 passed through the allowlist")
	}
}

func TestAuditCommittedFailsTrafficOffPorts49And300(t *testing.T) {
	s := newSynth()
	s.segment(synthDevice, synthServer, 50014, 8080, 1000, flagSYN, nil, true)
	s.segment(synthDevice, synthServer, 50014, 8080, 1001, flagACK, []byte("GET / HTTP/1.1\r\n\r\n"), true)
	problems, r := auditCommitted("other.pcap", s.buf, Options{Key: synthKey}, nil)
	if r.Other != 2 || len(problems) == 0 {
		t.Fatalf("report %+v, problems %d: want the other-protocol records counted and failing", r, len(problems))
	}
}

func TestCheckTLSOpensWalksEveryRecord(t *testing.T) {
	s := newSynth()
	hello := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00} // one whole handshake record
	plain := tacacs(0x88888888, wire.TypeAcct, 1, []byte{1, 2, 3, 4})
	s.segment(synthDevice, synthServer, 50030, TLSPort, 1000, flagSYN, nil, true)
	s.segment(synthDevice, synthServer, 50030, TLSPort, 1001, flagACK, hello, true)
	s.segment(synthDevice, synthServer, 50030, TLSPort, 1001+uint32(len(hello)), flagACK, plain, true)
	f, err := Parse(s.buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkTLSOpens(f); err == nil {
		t.Fatal("plain TACACS+ after a valid TLS record passed")
	}
	s = newSynth()
	s.segment(synthDevice, synthServer, 50031, TLSPort, 1000, flagSYN, nil, true)
	s.segment(synthDevice, synthServer, 50031, TLSPort, 1001, flagACK, append(append([]byte{}, hello...), 0x17, 0x03, 0x03, 0x00, 0x01, 0xff), true)
	f, _ = Parse(s.buf)
	if err := checkTLSOpens(f); err != nil {
		t.Errorf("two whole TLS records failed: %v", err)
	}
}

func TestAuditEvidenceReportsTailBytes(t *testing.T) {
	out, _, err := Redact(tailRun(t), synthOptions())
	if err != nil {
		t.Fatal(err)
	}
	r, err := AuditEvidence(out, Options{Key: synthKey})
	if err != nil || r.Unframed != 0 || r.TailBytes != 6 {
		t.Fatalf("report %+v, %v: want the filled 6-byte tail visible as TailBytes", r, err)
	}
}

func tlsHello() []byte { return []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00} }

func TestCheckTLSOpensChecksEveryConnectionOnAReusedTuple(t *testing.T) {
	s := newSynth()
	plain := tacacs(0x99999999, wire.TypeAcct, 1, []byte{1, 2, 3, 4})
	s.segment(synthDevice, synthServer, 50040, TLSPort, 1000, flagSYN, nil, true)
	s.segment(synthDevice, synthServer, 50040, TLSPort, 1001, flagACK, plain, true) // plaintext, first connection
	s.segment(synthDevice, synthServer, 50040, TLSPort, 5000, flagSYN, nil, true)   // the tuple is reused
	s.segment(synthDevice, synthServer, 50040, TLSPort, 5001, flagACK, tlsHello(), true)
	f, _ := Parse(s.buf)
	if err := checkTLSOpens(f); err == nil {
		t.Fatal("plaintext on the first connection of a reused tuple passed")
	}
}

func TestCheckTLSOpensFailsAGap(t *testing.T) {
	s := newSynth()
	hello := tlsHello()
	plain := tacacs(0x99999998, wire.TypeAcct, 1, []byte{1, 2, 3, 4})
	s.segment(synthDevice, synthServer, 50041, TLSPort, 1000, flagSYN, nil, true)
	s.segment(synthDevice, synthServer, 50041, TLSPort, 1001, flagACK, hello, true)
	s.segment(synthDevice, synthServer, 50041, TLSPort, 1001+uint32(len(hello))+500, flagACK, plain, true)
	f, _ := Parse(s.buf)
	if err := checkTLSOpens(f); err == nil {
		t.Fatal("plaintext after a sequence gap passed")
	}
}

func TestCheckTLSOpensFailsAnOversizedRecord(t *testing.T) {
	s := newSynth()
	big := []byte{0x16, 0x03, 0x03, 0x41, 0x01} // length 16641: past the 16640 a TLS 1.3 record may carry
	s.segment(synthDevice, synthServer, 50042, TLSPort, 1000, flagSYN, nil, true)
	s.segment(synthDevice, synthServer, 50042, TLSPort, 1001, flagACK, append(big, make([]byte, 20)...), true)
	f, _ := Parse(s.buf)
	if err := checkTLSOpens(f); err == nil {
		t.Fatal("a record header longer than 16640 passed")
	}
}
