package labpcap

import (
	"bytes"
	"testing"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// A stream's bytes after its last whole TACACS+ packet are bytes the redactor cannot frame, so it
// overwrites them with Fill, as it does a credential, and Verify and the audit hold it to that.

func tailRun(t *testing.T) []byte {
	t.Helper()
	s := newSynth()
	req := wire.AuthorRequest{
		AuthenMethod: wire.AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, User: []byte("alice01"), Port: []byte("ssh"),
		RemAddr: []byte("192.0.2.9"), Args: [][]byte{[]byte("service=shell")},
	}
	whole := tacacs(0x77777777, wire.TypeAuthor, 1, req.Encode())
	s.exchange(50020, [][]byte{whole, make([]byte, 6)}, []bool{true, true}, true)
	return s.buf
}

func TestRedactOverwritesAnUnframedTailWithFill(t *testing.T) {
	in := tailRun(t)
	if r, err := AuditEvidence(in, Options{Key: synthKey}); r.Unframed != 1 || err != nil {
		t.Fatalf("the input's audit: %+v, %v; want one unframed tail", r, err)
	}
	out, _, err := Redact(in, synthOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(in, out, synthOptions()); err != nil {
		t.Fatalf("Verify refused the redacted tail: %v", err)
	}
	r, err := AuditEvidence(out, Options{Key: synthKey})
	if err != nil || r.Unframed != 0 {
		t.Fatalf("the redacted file's audit: %+v, %v; want the tail redacted", r, err)
	}
	f, _ := Parse(out)
	d, _ := f.Decode(synthKey, nil)
	tails := d.Tails()
	if len(tails) != 1 || !bytes.Equal(d.Streams[tails[0].Stream].Payload[tails[0].Off:], bytes.Repeat([]byte{Fill}, 6)) {
		t.Fatalf("tails after redaction: %+v", tails)
	}
}

func TestVerifyRefusesAnUnredactedTail(t *testing.T) {
	in := tailRun(t)
	if err := Verify(in, in, synthOptions()); err == nil {
		t.Fatal("Verify accepted output whose unframed tail was left as it was")
	}
}
