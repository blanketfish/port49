package wire

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"testing"
)

func padHeader() Header {
	return Header{MajorVersion: 0xc, MinorVersion: 0, Type: TypeAuthen, SeqNo: 1, SessionID: 0xdeadbeef}
}

// Reference pad computed inline from the RFC text so the implementation is checked
// against the definition, not against itself:
//
//	MD5_1 = MD5(session_id ‖ key ‖ version ‖ seq_no)
//	MD5_n = MD5(session_id ‖ key ‖ version ‖ seq_no ‖ MD5_{n-1})
func referencePad(h Header, key []byte, n int) []byte {
	var out, prev []byte
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, h.SessionID)
	for len(out) < n {
		m := md5.New()
		m.Write(sid)
		m.Write(key)
		m.Write([]byte{h.Version()})
		m.Write([]byte{h.SeqNo})
		m.Write(prev)
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func TestPadMatchesReference(t *testing.T) {
	h := padHeader()
	key := []byte("s3cret")
	for _, n := range []int{0, 1, 15, 16, 17, 33, 100} {
		if got, want := Pad(h, key, n), referencePad(h, key, n); !bytes.Equal(got, want) {
			t.Fatalf("n=%d: got %x want %x", n, got, want)
		}
	}
}

func TestObfuscateIsSymmetric(t *testing.T) {
	h := padHeader()
	key := []byte("s3cret")
	body := []byte("the quick brown fox jumps over the lazy dog")
	enc := Obfuscate(h, key, body)
	if bytes.Equal(enc, body) {
		t.Fatal("obfuscation changed nothing")
	}
	if got := Obfuscate(h, key, enc); !bytes.Equal(got, body) {
		t.Fatalf("round trip: %q", got)
	}
	if &enc[0] == &body[0] {
		t.Fatal("Obfuscate must not alias its input")
	}
}

func TestObfuscateDependsOnSeqNo(t *testing.T) {
	h := padHeader()
	body := []byte("same body")
	h2 := h
	h2.SeqNo = 3
	if bytes.Equal(Obfuscate(h, []byte("k"), body), Obfuscate(h2, []byte("k"), body)) {
		t.Fatal("pad must vary with seq_no")
	}
}
