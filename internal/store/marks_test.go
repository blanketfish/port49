package store

import (
	"testing"
	"time"
)

// Marks is the daemon's copy of the standing marks (plan 7d; Ruling 17):
// a context its principal or certificate names stands revoked at the
// later of its own mark and the record's; a lifted mark names nothing; a
// blank certificate key names no certificate; nil names nothing.
func TestMarksNameAContextByPrincipalOrCertificate(t *testing.T) {
	at := time.Unix(1_000_000, 0).UTC()
	m := NewMarks()
	alice := Context{Principal: "user:alice@example.com", Credential: Credential{Issuer: "CN=Corp CA", Serial: "0a"}}
	if !m.RevokedAt(alice).IsZero() {
		t.Fatal("no mark, revoked")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal, At: at}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a principal's mark")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal, At: at.Add(time.Hour)}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a repeated mark moved the first one's time")
	}
	m.Set(Revocation{Kind: RevocationPrincipal, Key: alice.Principal}, false)
	if !m.RevokedAt(alice).IsZero() || m.Len() != 0 {
		t.Fatal("a lifted mark")
	}
	m.Set(Revocation{Kind: RevocationCert, Key: CertKey("CN=Corp CA", "0a"), At: at}, true)
	if !m.RevokedAt(alice).Equal(at) {
		t.Fatal("a certificate's mark")
	}
	oidc := Context{Principal: "user:bob@example.com"}
	m.Set(Revocation{Kind: RevocationCert, Key: "|", At: at}, true)
	if !m.RevokedAt(oidc).IsZero() {
		t.Fatal("a blank certificate key named an OIDC login")
	}
	later := alice
	later.RevokedAt = at.Add(time.Minute)
	if !m.RevokedAt(later).Equal(later.RevokedAt) {
		t.Fatal("the record's own later revocation")
	}
	var none *Marks
	if !none.RevokedAt(alice).IsZero() {
		t.Fatal("a nil Marks named a mark")
	}
}
