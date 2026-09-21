package wire

import (
	"errors"
	"testing"
)

func TestAcctRequestRoundTrip(t *testing.T) {
	in := AcctRequest{Flags: AcctFlagStop, AuthenMethod: AuthenMethodTACACSPlus, PrivLvl: 15,
		AuthenType: AuthenTypeASCII, Service: AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"),
		Args: [][]byte{[]byte("task_id=43"), []byte("service=shell"), []byte("cmd=show"), []byte("cmd-arg=running-config"), []byte("cmd-arg=<cr>")}}
	out, err := DecodeAcctRequest(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if out.Flags != AcctFlagStop || len(out.Args) != 5 || string(out.Args[4]) != "cmd-arg=<cr>" {
		t.Fatalf("decoded %+v", out)
	}
	if _, err := DecodeAcctRequest(append(in.Encode(), 0)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("trailing: %v", err)
	}
}

func TestAcctReplyRoundTrip(t *testing.T) {
	in := AcctReply{Status: AcctStatusSuccess}
	b := in.Encode()
	if len(b) != 5 {
		t.Fatalf("encoded %x", b)
	}
	out, err := DecodeAcctReply(b)
	if err != nil || out.Status != AcctStatusSuccess {
		t.Fatalf("decoded %+v err %v", out, err)
	}
}
