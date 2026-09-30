package keyring

import (
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

func start(t *testing.T) (wire.Header, []byte) {
	t.Helper()
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("tok")}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 0x11223344, Length: uint32(len(body))}
	return h, body
}

func set() Set {
	return Set{Ref: "prod_key", Versions: []Version{
		{Number: 3, Secret: []byte("v3-secret")},
		{Number: 2, Secret: []byte("v2-secret")},
		{Number: 1, Secret: []byte("v1-secret"), Retired: true},
	}}
}

func TestResolveCurrentAndAccepted(t *testing.T) {
	h, body := start(t)
	for _, v := range []struct {
		secret []byte
		want   int
	}{{[]byte("v3-secret"), 3}, {[]byte("v2-secret"), 2}} {
		r := set().Resolve(h, wire.Obfuscate(h, v.secret, body), time.Time{})
		if r.Diagnosis != DiagValidated || r.Version != v.want || string(r.Body) != string(body) {
			t.Fatalf("secret %s: %+v", v.secret, r)
		}
	}
}

func TestResolveRetiredIdentifiesButNeverAdmits(t *testing.T) {
	h, body := start(t)
	r := set().Resolve(h, wire.Obfuscate(h, []byte("v1-secret"), body), time.Time{})
	if r.Diagnosis != DiagMatchesRetired || r.Version != 1 {
		t.Fatalf("%+v", r)
	}
	if r.Body != nil {
		t.Fatal("a retired match must not hand the body to anyone")
	}
}

func TestResolveUnknownKey(t *testing.T) {
	h, body := start(t)
	r := set().Resolve(h, wire.Obfuscate(h, []byte("nope"), body), time.Time{})
	if r.Diagnosis != DiagNoKnownKey || r.Body != nil {
		t.Fatalf("%+v", r)
	}
}

func TestResolveNeverParsesUnencrypted(t *testing.T) {
	h, body := start(t)
	h.Flags = wire.FlagUnencrypted
	if r := set().Resolve(h, body, time.Time{}); r.Diagnosis != DiagUnencrypted || r.Body != nil {
		t.Fatalf("%+v", r)
	}
}

func TestResolveNotTACACS(t *testing.T) {
	h, body := start(t)
	h.MajorVersion = 0x4
	if r := set().Resolve(h, body, time.Time{}); r.Diagnosis != DiagNotTACACS {
		t.Fatalf("%+v", r)
	}
}

func TestValidatesEveryType(t *testing.T) {
	h, body := start(t)
	if !Validates(h, body) {
		t.Fatal("authen start")
	}
	ab := wire.AuthorRequest{AuthenMethod: 6, AuthenType: 1, Service: 1, Args: [][]byte{[]byte("service=shell")}}.Encode()
	if !Validates(wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthor, SeqNo: 1, Length: uint32(len(ab))}, ab) {
		t.Fatal("author")
	}
	cb := wire.AcctRequest{Flags: wire.AcctFlagStart, AuthenMethod: 6, AuthenType: 1, Service: 1}.Encode()
	if !Validates(wire.Header{MajorVersion: 0xc, Type: wire.TypeAcct, SeqNo: 1, Length: uint32(len(cb))}, cb) {
		t.Fatal("acct")
	}
	// seq_no 3 on an authentication session is a CONTINUE, whose identity differs.
	cont := wire.AuthenContinue{UserMsg: []byte("tok")}.Encode()
	if !Validates(wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 3, Length: uint32(len(cont))}, cont) {
		t.Fatal("continue")
	}
}

func TestSecretNilForRetiredAndUnknown(t *testing.T) {
	s := set()
	// Current and accepted versions return their secrets.
	if secret := s.Secret(3); string(secret) != "v3-secret" {
		t.Fatalf("version 3: got %q, want %q", secret, "v3-secret")
	}
	if secret := s.Secret(2); string(secret) != "v2-secret" {
		t.Fatalf("version 2: got %q, want %q", secret, "v2-secret")
	}
	// Retired version returns nil.
	if secret := s.Secret(1); secret != nil {
		t.Fatalf("retired version 1: got %v, want nil", secret)
	}
	// Unknown version returns nil.
	if secret := s.Secret(99); secret != nil {
		t.Fatalf("unknown version 99: got %v, want nil", secret)
	}
}
