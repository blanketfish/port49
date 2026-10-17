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

func TestValidateTLSRequiresTheUnencryptedFlag(t *testing.T) {
	ok := Header{MajorVersion: MajorVersion, Type: TypeAuthen, SeqNo: 1, Flags: FlagUnencrypted, Length: 10}
	if err := ok.ValidateTLS(); err != nil {
		t.Fatalf("a flagged packet over TLS: %v", err)
	}
	single := ok
	single.Flags |= FlagSingleConnect
	if err := single.ValidateTLS(); err != nil {
		t.Fatalf("single-connect beside the flag: %v", err)
	}
	for name, c := range map[string]struct {
		h    Header
		want error
	}{
		"flag clear":  {Header{MajorVersion: MajorVersion, Type: TypeAuthor, SeqNo: 1, Length: 10}, ErrObfuscatedOverTLS},
		"bad version": {Header{MajorVersion: 0xb, Type: TypeAuthen, SeqNo: 1, Flags: FlagUnencrypted}, ErrBadVersion},
		"bad type":    {Header{MajorVersion: MajorVersion, Type: 4, SeqNo: 1, Flags: FlagUnencrypted}, ErrBadType},
		"even seq_no": {Header{MajorVersion: MajorVersion, Type: TypeAcct, SeqNo: 2, Flags: FlagUnencrypted}, ErrSeqNotOdd},
		// Length before the flag: a packet that is too long is noise, not a
		// misconfigured device, whatever its flag says.
		"too long, flag clear": {Header{MajorVersion: MajorVersion, Type: TypeAuthen, SeqNo: 1, Length: MaxBodyLen + 1}, ErrTooLong},
	} {
		if err := c.h.ValidateTLS(); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestValidateStillRefusesTheFlagOnTCP(t *testing.T) {
	h := Header{MajorVersion: MajorVersion, Type: TypeAuthen, SeqNo: 1, Flags: FlagUnencrypted, Length: 10}
	if err := h.Validate(); !errors.Is(err, ErrUnencrypted) {
		t.Fatalf("RFC 8907 listener: %v, want ErrUnencrypted", err)
	}
}

func TestErrorReplyIsTheTypesErrorWithTheFlagSet(t *testing.T) {
	for typ, want := range map[Type]uint8{TypeAuthen: AuthenStatusError, TypeAuthor: AuthorStatusError, TypeAcct: AcctStatusError} {
		h := Header{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne, Type: typ, SeqNo: 3,
			Flags: FlagSingleConnect, SessionID: 7, Length: 99}
		rh, body := ErrorReply(h)
		if rh.MajorVersion != MajorVersion || rh.MinorVersion != MinorVersionOne || rh.Type != typ || rh.SeqNo != 4 ||
			rh.Flags != FlagUnencrypted || rh.SessionID != 7 || rh.Length != uint32(len(body)) {
			t.Fatalf("type %d: header %+v", typ, rh)
		}
		var got uint8
		switch typ {
		case TypeAuthen:
			r, err := DecodeAuthenReply(body)
			if err != nil {
				t.Fatal(err)
			}
			got = r.Status
		case TypeAuthor:
			r, err := DecodeAuthorResponse(body)
			if err != nil {
				t.Fatal(err)
			}
			got = r.Status
		case TypeAcct:
			r, err := DecodeAcctReply(body)
			if err != nil {
				t.Fatal(err)
			}
			got = r.Status
		}
		if got != want {
			t.Errorf("type %d: status %#x, want %#x", typ, got, want)
		}
	}
}
