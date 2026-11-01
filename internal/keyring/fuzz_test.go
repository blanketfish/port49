package keyring

import (
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/secretref"
	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// Resolve and Validates are the keyring's network-facing surface: every byte
// they see arrives from an unauthenticated TCP connection, and Resolve runs
// before any admission decision has been made. Neither may panic on any
// input, and Resolve's contract has two parts that must hold whatever the
// bytes are:
//
//   - a body is returned only when the diagnosis is DiagValidated, so no
//     caller can act on bytes the keyring did not vouch for;
//   - a retired version never admits, so it can identify a device and nothing
//     more (spec §10).

// seedSet is the shape a real deployment has: a current version, an accepted
// one, and a retired one kept for diagnosis.
func seedSet() Set {
	return Set{Ref: "prod_key", Versions: []Version{
		{Number: 3, Secret: secretref.Of([]byte("current"))},
		{Number: 2, Secret: secretref.Of([]byte("accepted"))},
		{Number: 1, Secret: secretref.Of([]byte("retired")), Retired: true},
	}}
}

func FuzzResolve(f *testing.F) {
	s := seedSet()
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_token")}.Encode()

	// A packet under the current key, one under the retired key, one that no
	// key validates, and a header with nothing behind it.
	for _, seed := range []struct {
		secret []byte
		typ    uint8
		seq    uint8
		body   []byte
	}{
		{[]byte("current"), uint8(wire.TypeAuthen), 1, start},
		{[]byte("retired"), uint8(wire.TypeAuthen), 1, start},
		{[]byte("some-other-key"), uint8(wire.TypeAuthen), 1, start},
		{[]byte("current"), uint8(wire.TypeAcct), 1, wire.AcctRequest{Flags: wire.AcctFlagStop, AuthenMethod: wire.AuthenMethodTACACSPlus,
			AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, Args: [][]byte{[]byte("task_id=1")}}.Encode()},
		{[]byte("current"), uint8(wire.TypeAuthor), 3, nil},
	} {
		h := wire.Header{MajorVersion: 0xc, Type: wire.Type(seed.typ), SeqNo: seed.seq, SessionID: 7, Length: uint32(len(seed.body))}
		f.Add(seed.typ, seed.seq, uint8(0), uint32(7), wire.Obfuscate(h, seed.secret, seed.body))
	}

	f.Fuzz(func(t *testing.T, typ, seq, flags uint8, sid uint32, obf []byte) {
		h := wire.Header{MajorVersion: 0xc, Type: wire.Type(typ), SeqNo: seq, Flags: flags, SessionID: sid, Length: uint32(len(obf))}
		r := s.Resolve(h, obf, time.Time{})
		if r.Diagnosis != DiagValidated && r.Body != nil {
			t.Fatalf("a body was returned for diagnosis %q; only a validated packet may carry one", r.Diagnosis)
		}
		if r.Diagnosis == DiagValidated {
			if len(r.Body) != len(obf) {
				t.Fatalf("a validated body must be the same length as the packet: %d vs %d", len(r.Body), len(obf))
			}
			// A validated version must be one that admits, and its secret must
			// be available to build the reply with.
			if s.Secret(r.Version) == nil {
				t.Fatalf("version %d validated but has no usable secret; a retired version must never admit", r.Version)
			}
			if !Validates(h, r.Body) {
				t.Fatalf("Resolve returned a body that does not validate under the header it validated against")
			}
		}
		if r.Diagnosis == DiagMatchesRetired && s.Secret(r.Version) != nil {
			t.Fatalf("version %d matched as retired but Secret still returns material for it", r.Version)
		}
	})
}

func FuzzValidates(f *testing.F) {
	f.Add(uint8(wire.TypeAuthen), uint8(1), []byte(wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_token")}.Encode()))
	f.Add(uint8(wire.TypeAuthen), uint8(3), []byte(wire.AuthenContinue{UserMsg: []byte("alice")}.Encode()))
	f.Add(uint8(wire.TypeAuthor), uint8(1), []byte(wire.AuthorRequest{AuthenMethod: wire.AuthenMethodTACACSPlus,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, Args: [][]byte{[]byte("service=shell")}}.Encode()))
	f.Add(uint8(wire.TypeAcct), uint8(1), []byte(wire.AcctRequest{Flags: wire.AcctFlagStart, AuthenMethod: wire.AuthenMethodTACACSPlus,
		AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin, Args: [][]byte{[]byte("task_id=1")}}.Encode()))
	f.Add(uint8(9), uint8(1), []byte("neither a packet nor a type this daemon answers"))

	f.Fuzz(func(t *testing.T, typ, seq uint8, body []byte) {
		h := wire.Header{MajorVersion: 0xc, Type: wire.Type(typ), SeqNo: seq, SessionID: 1, Length: uint32(len(body))}
		if Validates(h, body) && wire.Type(typ) != wire.TypeAuthen && wire.Type(typ) != wire.TypeAuthor && wire.Type(typ) != wire.TypeAcct {
			t.Fatalf("type %d must never validate: it is not a type the daemon decodes", typ)
		}
	})
}
