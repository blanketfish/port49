package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthorRequestRoundTrip(t *testing.T) {
	in := AuthorRequest{
		AuthenMethod: AuthenMethodTACACSPlus, PrivLvl: 15, AuthenType: AuthenTypeASCII, Service: AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"),
		Args: [][]byte{[]byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=version")},
	}
	b := in.Encode()
	// 8 fixed + 3 arg_len octets + 5 + 4 + 12 + (13 + 8 + 15)
	if len(b) != 8+3+5+4+12+13+8+15 {
		t.Fatalf("encoded length %d", len(b))
	}
	out, err := DecodeAuthorRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Args) != 3 || !bytes.Equal(out.Args[2], []byte("cmd-arg=version")) || out.PrivLvl != 15 {
		t.Fatalf("decoded %+v", out)
	}
}

func TestAuthorRequestLengthIdentity(t *testing.T) {
	b := AuthorRequest{AuthenMethod: AuthenMethodTACACSPlus, AuthenType: AuthenTypeASCII, Service: AuthenServiceLogin,
		Args: [][]byte{[]byte("service=shell")}}.Encode()
	if _, err := DecodeAuthorRequest(append(b, 0)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("trailing: %v", err)
	}
	if _, err := DecodeAuthorRequest(b[:len(b)-1]); !errors.Is(err, ErrShort) {
		t.Fatalf("truncated: %v", err)
	}
	// arg_cnt claims 2 args but only one arg_len octet is present.
	bad := append([]byte(nil), b...)
	bad[7] = 2
	if _, err := DecodeAuthorRequest(bad); !errors.Is(err, ErrShort) && !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("arg_cnt lie: %v", err)
	}
}

func TestAuthorResponseRoundTrip(t *testing.T) {
	in := AuthorResponse{Status: AuthorStatusFail, ServerMsg: []byte("port49: denied by no-exfil"),
		Args: [][]byte{[]byte("priv-lvl=15")}}
	out, err := DecodeAuthorResponse(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != AuthorStatusFail || string(out.ServerMsg) != "port49: denied by no-exfil" || len(out.Args) != 1 {
		t.Fatalf("decoded %+v", out)
	}
}
