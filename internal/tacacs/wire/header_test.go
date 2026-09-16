package wire

import (
	"bytes"
	"errors"
	"testing"
)

// A well-formed authentication START header: version c0, type 1, seq 1, flags 0,
// session 0x01020304, length 20.
var goodHeader = []byte{0xc0, 0x01, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x14}

func TestDecodeHeaderRoundTrip(t *testing.T) {
	h, err := DecodeHeader(goodHeader)
	if err != nil {
		t.Fatal(err)
	}
	if h.MajorVersion != 0xc || h.MinorVersion != 0 || h.Type != TypeAuthen ||
		h.SeqNo != 1 || h.Flags != 0 || h.SessionID != 0x01020304 || h.Length != 20 {
		t.Fatalf("decoded %+v", h)
	}
	if !bytes.Equal(h.Encode(), goodHeader) {
		t.Fatalf("encode mismatch: %x", h.Encode())
	}
	if h.Version() != 0xc0 {
		t.Fatalf("version octet %x", h.Version())
	}
}

func TestDecodeHeaderShort(t *testing.T) {
	if _, err := DecodeHeader(goodHeader[:11]); !errors.Is(err, ErrShort) {
		t.Fatalf("want ErrShort, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	mut := func(i int, v byte) []byte { b := append([]byte(nil), goodHeader...); b[i] = v; return b }
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"good", goodHeader, nil},
		{"minor version 1 is fine", mut(0, 0xc1), nil},
		{"bad major", mut(0, 0xb0), ErrBadVersion},
		{"bad type", mut(1, 0x04), ErrBadType},
		{"even seq", mut(2, 0x02), ErrSeqNotOdd},
		{"unencrypted", mut(3, FlagUnencrypted), ErrUnencrypted},
		{"single-connect is honored", mut(3, FlagSingleConnect), nil},
		{"too long", append(goodHeader[:8:8], 0x00, 0x00, 0x10, 0x01), ErrTooLong},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := DecodeHeader(c.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.Validate(); !errors.Is(got, c.want) {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}
}
