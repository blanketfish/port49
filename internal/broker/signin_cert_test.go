package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/testpki"
)

// withPasswordSignIn gives f's broker an issuing CA and a directory_password
// verifier for example.com, and no OIDC verifier (decision 47).
func (f *fixture) withPasswordSignIn(t *testing.T) {
	t.Helper()
	ca, err := issuer.Ephemeral(f.b.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.b.Issuer = ca
	f.b.NoX509 = true
	f.b.PasswordSignIn = &oidc.PasswordSignIn{PrincipalDomains: []string{"example.com"},
		NewEntriesFor: oidc.DefaultNewEntriesFor, ReopenFor: oidc.DefaultReopenFor,
		FailuresPerPrincipal: oidc.DefaultFailuresPerPrincipal, FailuresPerSource: oidc.DefaultFailuresPerSource,
		Window: oidc.DefaultSignInWindow, TOTPLabel: "port49 (broker.test)"}
}

// issuedDirectory is a certificate f's issuing CA issues for principal p on a
// directory sign-in of entry, for a fresh key.
func (f *fixture) issuedDirectory(t *testing.T, p, entry string) tls.Certificate {
	t.Helper()
	return f.issued(t, issuer.SignIn{Method: issuer.MethodDirectoryPassword, Principal: p,
		Subject: issuer.EntrySubject(entry), AMR: []string{"pwd", "otp"}, AuthTime: f.b.Now(), IssuedAt: f.b.Now()})
}

// refusedAs is w's error, which must be a 401 with this reason.
func refusedAs(t *testing.T, w *httptest.ResponseRecorder, reason string) api.Error {
	t.Helper()
	var e api.Error
	if w.Code != 401 || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error != reason {
		t.Fatalf("want 401 %s: %s", reason, shown(w))
	}
	return e
}

// A certificate issued over a directory sign-in mints as its principal,
// never mapped; its records carry auth.directory_password and no auth.oidc
// (decision 47 ruling 10, D6).
func TestADirectorySignInCertificateMints(t *testing.T) {
	f := newFixture(t, 8)
	f.withPasswordSignIn(t)
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now)
	if r := decodeMint(t, w); r.Principal != alicePrincipal || r.Results[0].Verdict != "permit" {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	auth, _ := recs[0]["auth"].(map[string]any)
	dp, _ := auth["directory_password"].(map[string]any)
	want := strings.TrimPrefix(issuer.EntrySubject("uuid:alice"), issuer.EntrySubjectPrefix)
	if dp == nil || auth["oidc"] != nil || dp["entry_sha256"] != want || auth["method"] != "cert" {
		t.Fatalf("%v", auth)
	}
}

// With the verifier gone, or the principal's domain no longer its, the
// certificate is refused: removing the verifier takes its people's
// certificates with it.
func TestADirectorySignInCertificateNeedsItsVerifier(t *testing.T) {
	f := newFixture(t, 8)
	f.withPasswordSignIn(t)
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	f.b.PasswordSignIn = nil
	e := refusedAs(t, f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now), "trust_domain_unresolved")
	if !strings.Contains(e.Detail, "directory_password verifier") {
		t.Fatalf("%s", e.Detail)
	}
	f.withPasswordSignIn(t)
	f.b.PasswordSignIn.PrincipalDomains = []string{"other.com"}
	c = f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	e = refusedAs(t, f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now), "trust_domain_unresolved")
	if !strings.Contains(e.Detail, "directory_password verifier") {
		t.Fatalf("%s", e.Detail)
	}
}

// An OIDC sign-in's certificate is not taken as a directory one, nor the
// reverse.
func TestTheMethodsDoNotCross(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	oidcCert := f.issued(t, f.aliceSignIn(iss))
	dirCert := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	// A directory verifier alone does not take an OIDC sign-in's certificate.
	f.b.PasswordSignIn = &oidc.PasswordSignIn{PrincipalDomains: []string{"example.com"}}
	idty := f.b.Identity
	f.b.Identity = nil
	refusedAs(t, f.postAt(context.Background(), f.issuedState(oidcCert), mintLeaf1, "", f.now), "trust_domain_unresolved")
	// An OIDC verifier alone does not take a directory sign-in's.
	f.b.Identity, f.b.PasswordSignIn = idty, nil
	refusedAs(t, f.postAt(context.Background(), f.issuedState(dirCert), mintLeaf1, "", f.now), "trust_domain_unresolved")
	// With both, each reads as its own method; the directory one never reaches
	// the OIDC logout check, which would dereference its absent assertion.
	f.b.PasswordSignIn = &oidc.PasswordSignIn{PrincipalDomains: []string{"example.com"}}
	if w := f.postAt(context.Background(), f.issuedState(dirCert), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	if w := f.postAt(context.Background(), f.issuedState(oidcCert), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	auth, _ := recs[len(recs)-1]["auth"].(map[string]any)
	if auth["oidc"] == nil || auth["directory_password"] != nil {
		t.Fatalf("the OIDC certificate's record: %v", auth)
	}
}

// A broker with a directory_password verifier alone builds its pool from
// its issuing CA, as a 9b OIDC-only broker does.
func TestAPasswordOnlyBrokerServes(t *testing.T) {
	f := newFixture(t, 8)
	f.withPasswordSignIn(t)
	f.b.Identity = nil
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, nil)
	if err != nil || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven || srv.TLSConfig.ClientCAs == nil {
		t.Fatalf("%v", err)
	}
	want := x509.NewCertPool()
	for _, c := range f.b.Issuer.Trusted {
		want.AddCert(c)
	}
	if len(f.b.Issuer.Trusted) == 0 || !srv.TLSConfig.ClientCAs.Equal(want) {
		t.Fatal("the client pool is not the issuing CA's")
	}
	// With no issuing CA a directory verifier alone is no way to authenticate.
	f.b.Issuer = nil
	if _, err := f.b.Server("127.0.0.1:0", srvCert, nil); err == nil || !strings.Contains(err.Error(), "directory_password") {
		t.Fatalf("%v", err)
	}
}

// A directory certificate's refresh records, extended or refused, carry
// auth.directory_password and no auth.oidc, as a mint's do (decision 47 D6).
func TestADirectorySignInCertificatesRefreshRecordsCarryItsSignIn(t *testing.T) {
	f := newFixture(t, 8)
	f.withPasswordSignIn(t)
	addr, _ := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) { f.b.Wire(l) })
	c := f.issuedDirectory(t, alicePrincipal, "uuid:alice")
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(c), f.now, f.now.Add(8*time.Hour))
	conn, br := held(t, f, addr, c)
	if status, resp := refreshOn(t, conn, br, c); status != 200 || len(resp.Sessions) != 1 ||
		resp.Sessions[0].Outcome != "extended" {
		t.Fatalf("a refresh by the issued key: %d %+v", status, resp)
	}
	want := strings.TrimPrefix(issuer.EntrySubject("uuid:alice"), issuer.EntrySubjectPrefix)
	signedIn := func(what string) {
		t.Helper()
		recs := eventsOf(f.records(t), decision.EventRefresh)
		auth, _ := recs[len(recs)-1]["auth"].(map[string]any)
		dp, _ := auth["directory_password"].(map[string]any)
		if dp == nil || dp["entry_sha256"] != want || auth["oidc"] != nil {
			t.Fatalf("%s: the refresh record's auth: %v", what, auth)
		}
	}
	signedIn("extended")
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alicePrincipal, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	conn2, br2 := held(t, f, addr, c)
	if status, _ := refreshOn(t, conn2, br2, c); status != 401 {
		t.Fatalf("a refresh after the revocation: %d", status)
	}
	signedIn("refused")
}

// A bearer token at a password-only broker (b.Identity nil): POST /v1/tokens
// with Authorization: Bearer is refused 401 and nothing panics.
func TestABearerAtAPasswordOnlyBroker(t *testing.T) {
	f := newFixture(t, 8)
	f.withPasswordSignIn(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, "not-a-token")
	refusedAs(t, w, "trust_domain_unresolved")
}
