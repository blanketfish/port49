package keyring

import (
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

func TestSeenCountsEachDevicesLatestVersion(t *testing.T) {
	var s Seen
	s.Mark("leaf-01", "prod_key", 2)
	s.Mark("leaf-02", "prod_key", 2)
	s.Mark("leaf-01", "prod_key", 3)
	if s.Count("prod_key", 2) != 1 || s.Count("prod_key", 3) != 1 {
		t.Fatalf("v2 %d, v3 %d", s.Count("prod_key", 2), s.Count("prod_key", 3))
	}
}

// Spec §10: past retire_after a version identifies and never admits.
func TestAVersionPastItsDateIdentifiesAndNeverAdmits(t *testing.T) {
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 7}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("u"), Data: []byte("x")}.Encode()
	h.Length = uint32(len(body))
	obf := wire.Obfuscate(h, []byte("old"), body)
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	set := Set{Ref: "prod_key", Versions: []Version{{Number: 3, Secret: []byte("new")}, {Number: 2, Secret: []byte("old"), RetireAt: at}}}
	if r := set.Resolve(h, obf, at.Add(-time.Second)); r.Diagnosis != DiagValidated || r.Version != 2 {
		t.Fatalf("before the instant: %+v", r)
	}
	if r := set.Resolve(h, obf, at); r.Diagnosis != DiagMatchesRetired || r.Version != 2 || r.Body != nil {
		t.Fatalf("at the instant: %+v", r)
	}
	if set.State(0, at) != "current" || set.State(1, at.Add(-time.Second)) != "accept" || set.State(1, at) != "retired" {
		t.Fatal("State")
	}
}
