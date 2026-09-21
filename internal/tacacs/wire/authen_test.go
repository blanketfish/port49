package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthenStartRoundTrip(t *testing.T) {
	in := AuthenStart{
		Action: AuthenActionLogin, PrivLvl: 1, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte("p49_token"),
	}
	b := in.Encode()
	if len(b) != 8+5+4+12+9 {
		t.Fatalf("encoded length %d", len(b))
	}
	out, err := DecodeAuthenStart(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.User, in.User) || !bytes.Equal(out.Data, in.Data) || out.AuthenType != AuthenTypePAP {
		t.Fatalf("decoded %+v", out)
	}
}

func TestAuthenStartLengthIdentityIsStrict(t *testing.T) {
	b := AuthenStart{Action: AuthenActionLogin, AuthenType: AuthenTypeASCII, Service: AuthenServiceLogin, User: []byte("a")}.Encode()
	if _, err := DecodeAuthenStart(append(b, 0x00)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("trailing byte: want ErrLengthMismatch, got %v", err)
	}
	if _, err := DecodeAuthenStart(b[:len(b)-1]); !errors.Is(err, ErrShort) {
		t.Fatalf("truncated: want ErrShort, got %v", err)
	}
	if _, err := DecodeAuthenStart(b[:5]); !errors.Is(err, ErrShort) {
		t.Fatalf("no fixed part: want ErrShort, got %v", err)
	}
}

func TestAuthenStartEnumRanges(t *testing.T) {
	good := AuthenStart{Action: AuthenActionLogin, AuthenType: AuthenTypePAP, Service: AuthenServiceLogin}.Encode()
	bad := append([]byte(nil), good...)
	bad[0] = 0x09 // action
	if _, err := DecodeAuthenStart(bad); !errors.Is(err, ErrBadEnum) {
		t.Fatalf("action: %v", err)
	}
	bad = append([]byte(nil), good...)
	bad[2] = 0x00 // authen_type 0 is not defined
	if _, err := DecodeAuthenStart(bad); !errors.Is(err, ErrBadEnum) {
		t.Fatalf("authen_type: %v", err)
	}
	bad = append([]byte(nil), good...)
	bad[1] = 16 // priv_lvl 0..15
	if _, err := DecodeAuthenStart(bad); !errors.Is(err, ErrBadEnum) {
		t.Fatalf("priv_lvl: %v", err)
	}
}

func TestAuthenReplyRoundTrip(t *testing.T) {
	in := AuthenReply{Status: AuthenStatusGetPass, Flags: AuthenReplyFlagNoEcho, ServerMsg: []byte("Password: ")}
	out, err := DecodeAuthenReply(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != AuthenStatusGetPass || out.Flags != AuthenReplyFlagNoEcho || string(out.ServerMsg) != "Password: " || len(out.Data) != 0 {
		t.Fatalf("decoded %+v", out)
	}
}

func TestAuthenContinueRoundTrip(t *testing.T) {
	in := AuthenContinue{UserMsg: []byte("p49_token")}
	out, err := DecodeAuthenContinue(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if string(out.UserMsg) != "p49_token" || out.Flags != 0 {
		t.Fatalf("decoded %+v", out)
	}
	if _, err := DecodeAuthenContinue(append(in.Encode(), 1)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("trailing: %v", err)
	}
}
