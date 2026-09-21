package wire

import "testing"

// Every decoder must reject or accept without panicking, and anything it accepts
// must re-encode to the identical bytes (the codecs are canonical).

func FuzzDecodeHeader(f *testing.F) {
	f.Add(goodHeader)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHeader(b)
		if err != nil {
			return
		}
		_ = h.Validate()
		if got := h.Encode(); string(got) != string(b[:HeaderLen]) {
			t.Fatalf("not canonical: %x vs %x", got, b[:HeaderLen])
		}
	})
}

func FuzzDecodeAuthenStart(f *testing.F) {
	f.Add(AuthenStart{Action: 1, AuthenType: 2, Service: 1, User: []byte("u"), Data: []byte("d")}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodeAuthenStart(b)
		if err != nil {
			return
		}
		if string(p.Encode()) != string(b) {
			t.Fatalf("not canonical")
		}
	})
}

func FuzzDecodeAuthenContinue(f *testing.F) {
	f.Add(AuthenContinue{UserMsg: []byte("x")}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := DecodeAuthenContinue(b); err == nil && string(p.Encode()) != string(b) {
			t.Fatalf("not canonical")
		}
	})
}

func FuzzDecodeAuthorRequest(f *testing.F) {
	f.Add(AuthorRequest{AuthenMethod: 6, AuthenType: 1, Service: 1, Args: [][]byte{[]byte("service=shell")}}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := DecodeAuthorRequest(b); err == nil && string(p.Encode()) != string(b) {
			t.Fatalf("not canonical")
		}
	})
}

func FuzzDecodeAcctRequest(f *testing.F) {
	f.Add(AcctRequest{Flags: AcctFlagStart, AuthenMethod: 6, AuthenType: 1, Service: 1, Args: [][]byte{[]byte("task_id=1")}}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := DecodeAcctRequest(b); err == nil && string(p.Encode()) != string(b) {
			t.Fatalf("not canonical")
		}
	})
}

func FuzzObfuscate(f *testing.F) {
	f.Add([]byte("k"), []byte("body"), uint32(7), uint8(1))
	f.Fuzz(func(t *testing.T, key, body []byte, sid uint32, seq uint8) {
		h := Header{MajorVersion: 0xc, Type: TypeAuthen, SeqNo: seq, SessionID: sid}
		if got := Obfuscate(h, key, Obfuscate(h, key, body)); string(got) != string(body) {
			t.Fatalf("not symmetric")
		}
	})
}
