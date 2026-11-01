package keyring

import (
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/secretref"
	"github.com/blanketfish/port49/internal/tacacs/wire"
)

func packetUnder(secret string) (wire.Header, []byte) {
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 7}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("u"), Data: []byte("x")}.Encode()
	h.Length = uint32(len(body))
	return h, wire.Obfuscate(h, []byte(secret), body)
}

var trialSets = map[string]Set{
	"prod_key": {Ref: "prod_key", Versions: []Version{{Number: 3, Secret: secretref.Of([]byte("new"))}, {Number: 2, Secret: secretref.Of([]byte("old")), Retired: true}}},
	"lab_key":  {Ref: "lab_key", Versions: []Version{{Number: 1, Secret: secretref.Of([]byte("lab"))}}},
}

// Spec §10: Try names the group and version a packet validates under, retired
// versions and other groups' material included, and nothing else.
func TestTryNamesWhatThePacketHolds(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	h, body := packetUnder("old")
	got := Try(h, body, trialSets, now)
	if len(got) != 1 || got[0] != (Match{KeyRef: "prod_key", Version: 2, State: "retired"}) {
		t.Fatalf("%+v", got)
	}
	h, body = packetUnder("lab")
	if got := Try(h, body, trialSets, now); len(got) != 1 || got[0].KeyRef != "lab_key" {
		t.Fatalf("%+v", got)
	}
	h, body = packetUnder("nothing")
	if got := Try(h, body, trialSets, now); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}
