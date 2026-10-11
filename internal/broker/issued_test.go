package broker

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

// withIssuance gives f's broker an issuing CA (plan 9b) beside withOIDC's
// provider, whose human verifier takes example.com.
func (f *fixture) withIssuance(t *testing.T) *oidctest.Issuer {
	t.Helper()
	iss := f.withOIDC(t)
	ca, err := issuer.Ephemeral(f.b.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.b.Issuer = ca
	return iss
}

// aliceSignIn is alice's sign-in at iss as withOIDC's tokens name it: sub
// sub-alice, sid s-sub-alice, at f's now.
func (f *fixture) aliceSignIn(iss *oidctest.Issuer) issuer.SignIn {
	return issuer.SignIn{Principal: alicePrincipal, Issuer: iss.URL, Subject: "sub-alice", Sid: "s-sub-alice",
		AMR: []string{"pwd", "otp"}, ACR: "1", AuthTime: f.b.Now(), IssuedAt: f.b.Now()}
}

// issued is a certificate f's issuing CA issues on s, for a fresh key, as
// crypto/tls holds it.
func (f *fixture) issued(t *testing.T, s issuer.SignIn) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.b.Issuer.Issue(key.Public(), s, f.b.Now(), 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
}

// issuedState is a handshake's state with c: one chain, ending at the
// issuing CA.
func (f *fixture) issuedState(c tls.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, f.b.Issuer.Cert}}}
}

// An issued certificate mints as its sign-in's principal; its records carry
// the sign-in, its token the sid and its serial, and the mint writes the
// owner record a logout finds the principal by (decision 43 rulings 10, 16).
func TestAnIssuedCertificateMintsAsItsSignIn(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	c := f.issued(t, f.aliceSignIn(iss))
	w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now)
	if r := decodeMint(t, w); r.Principal != alicePrincipal || r.Results[0].Verdict != "permit" {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	auth, _ := recs[len(recs)-1]["auth"].(map[string]any)
	o, _ := auth["oidc"].(map[string]any)
	if auth["method"] != "cert" || o["sid"] != "s-sub-alice" || o["issuer"] != iss.URL {
		t.Fatalf("the mint record's auth: %v", auth)
	}
	toks, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if err != nil || len(toks) == 0 || toks[0].Credential.Sid != store.SidKey(iss.URL, "s-sub-alice") ||
		toks[0].Credential.Serial != c.Leaf.SerialNumber.Text(16) {
		t.Fatalf("the token's credential: %d tokens, %v", len(toks), err)
	}
	own, err := f.st.OIDCOwner(context.Background(), store.SidKey(iss.URL, "s-sub-alice"))
	if _, ok := own.Entry(alicePrincipal); err != nil || !ok {
		t.Fatalf("no owner record for the sid: %v", err)
	}
}

// A back-channel logout of the sign-in reaches the contexts the
// certificate's tokens made, through the sid index (decision 43 ruling 16).
func TestALogoutReachesAnIssuedCertificatesContexts(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	if w := f.postAt(context.Background(), f.issuedState(f.issued(t, f.aliceSignIn(iss))), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	ctx := context.Background()
	toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"})
	tok := toks[len(toks)-1]
	// The daemon's redemption, as fixture.login writes it, with the
	// token's credential and its indexes.
	ref := store.ContextRef{NAS: "leaf1", Username: "alice"}
	if err := f.st.PutContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}, store.Context{CtxID: "ctx-leaf1",
		Principal: alicePrincipal, Username: "alice", PrivLvl: 15, BlobHash: tok.BlobHash, AuthTime: f.now,
		CreatedAt: f.now, RefreshedAt: f.now, SessionExpires: f.now.Add(time.Hour), Credential: tok.Credential},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, alicePrincipal, tok.Credential.Sid,
		store.CertKey(tok.Credential.Issuer, tok.Credential.Serial), ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Logout(ctx, oidc.LogoutToken{Issuer: iss.URL, Sid: "s-sub-alice", IssuedAt: f.b.Now(),
		Domains: []string{"example.com"}}, "backchannel_logout "+iss.URL); err != nil {
		t.Fatal(err)
	}
	if got := f.context(t, "leaf1", "alice"); got.RevokedAt.IsZero() {
		t.Fatal("the logout did not reach the issued certificate's context")
	}
}

// Through the listener: an issued certificate binds, mints, and refreshes by
// a key signature on its held connection, with no sign-in; after a logout of
// its sign-in, its next mint and its next refresh are refused in the
// broker's logout words (decision 43 rulings 11 and 16).
func TestALogoutRefusesAnIssuedCertificate(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	addr, _ := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) { f.b.Wire(l) })
	c := f.issued(t, f.aliceSignIn(iss))
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(c), f.now, f.now.Add(8*time.Hour))
	conn, br := held(t, f, addr, c)
	if a := postOn(t, conn, br, "/v1/tokens", mintLeaf1); a.status != 200 {
		t.Fatalf("a mint on the held connection: %d %s", a.status, a.body)
	}
	if status, resp := refreshOn(t, conn, br, c); status != 200 || len(resp.Sessions) != 1 ||
		resp.Sessions[0].Outcome != "extended" {
		t.Fatalf("a refresh by the issued key: %d %+v", status, resp)
	}
	if _, err := f.b.Logout(context.Background(), oidc.LogoutToken{Issuer: iss.URL, Sid: "s-sub-alice",
		IssuedAt: f.b.Now(), Domains: []string{"example.com"}}, "backchannel_logout "+iss.URL); err != nil {
		t.Fatal(err)
	}
	if a := postOn(t, conn, br, "/v1/tokens", mintLeaf1); a.status != 401 ||
		!strings.Contains(a.body, "credential_revoked") || !strings.Contains(a.body, "back-channel logout") {
		t.Fatalf("a mint after the logout: %d %s", a.status, a.body)
	}
	conn2, br2 := held(t, f, addr, c)
	if status, _ := refreshOn(t, conn2, br2, c); status != 401 {
		t.Fatalf("a refresh after the logout: %d", status)
	}
	recs := eventsOf(f.records(t), decision.EventRefresh)
	if r := recs[len(recs)-1]; r["verdict"] != "deny" || r["reason"] != "credential_revoked" {
		t.Fatalf("the refresh's record: %v", r)
	}
}

// An issued certificate is never mapped through the directory: the
// listener's Map is not asked for it. It is for a certificate an
// organization's CA issued: the control.
func TestAnIssuedCertificateIsNeverMapped(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	var maps atomic.Int32
	addr, _ := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) {
		f.b.Wire(l)
		l.Map = func(context.Context, tls.ConnectionState, store.Credential) (directory.Answer, *BindRefusal) {
			maps.Add(1)
			return directory.Answer{}, directoryRefusal(directory.ErrUnavailable)
		}
	})
	conn, br := held(t, f, addr, f.issued(t, f.aliceSignIn(iss)))
	if a := postOn(t, conn, br, "/v1/tokens", mintLeaf1); a.status != 200 || maps.Load() != 0 {
		t.Fatalf("the issued certificate: %d %s, mapped %d times", a.status, a.body, maps.Load())
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if a := postOn(t, c, bufio.NewReader(c), "/v1/tokens", mintLeaf1); a.status != 503 || maps.Load() != 1 {
		t.Fatalf("the control: %d %s, mapped %d times", a.status, a.body, maps.Load())
	}
}

// A chain ending at the issuing CA and at another anchor is no one's; a
// sign-in no human verifier takes now, by its issuer or its principal's
// domain, is refused (decision 43 ruling 10).
func TestAnIssuedCertificateTheBrokerCannotPlaceIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	c := f.issued(t, f.aliceSignIn(iss))
	both := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, f.b.Issuer.Cert}, {c.Leaf, f.ca.Cert}}}
	if w := f.postAt(context.Background(), both, mintLeaf1, "", f.now); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "issuing CA and to another trust anchor") {
		t.Fatalf("both anchors: %s", shown(w))
	}
	s := f.aliceSignIn(iss)
	s.Issuer = "https://elsewhere.example/realms/corp"
	if w := f.postAt(context.Background(), f.issuedState(f.issued(t, s)), mintLeaf1, "", f.now); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "port49 login --sign-in") {
		t.Fatalf("a provider no longer configured: %s", shown(w))
	}
	s = f.aliceSignIn(iss)
	s.Principal = "user:alice@elsewhere.example"
	if w := f.postAt(context.Background(), f.issuedState(f.issued(t, s)), mintLeaf1, "", f.now); w.Code != 401 {
		t.Fatalf("a domain the verifier does not hold: %s", shown(w))
	}
}

// everyChainUnknown answers every chain Unknown, as a CA no source covers.
type everyChainUnknown struct{}

func (everyChainUnknown) Check(context.Context, []*x509.Certificate) certstatus.Result {
	return certstatus.Result{Verdict: certstatus.Unknown, Detail: api.UncoveredStatus + " (test)"}
}

// An issued certificate is never put to certificate_status: the broker's
// marks are its status (decision 43 ruling 10). An organization's
// certificate is, the control.
func TestAnIssuedCertificateIsNotAskedItsStatus(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	f.b.CertStatus, f.b.OnUnavailable = everyChainUnknown{}, "refuse"
	if w := f.postAt(context.Background(), f.issuedState(f.issued(t, f.aliceSignIn(iss))), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("the issued certificate: %s", shown(w))
	}
	if w := f.postAt(context.Background(), f.state(f.alice), mintLeaf1, "", f.now); w.Code != 503 {
		t.Fatalf("the control: %s", shown(w))
	}
}

// An OIDC-only broker that issues asks for a certificate, against its own
// CAs, and takes its issued certificates on a held connection.
func TestAnOIDCOnlyBrokerThatIssuesTakesItsCertificates(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	f.b.NoX509 = true
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, nil)
	if err != nil || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven || srv.TLSConfig.ClientCAs == nil {
		t.Fatalf("%v: client auth %v", err, srv.TLSConfig.ClientAuth)
	}
	addr, _ := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) { f.b.Wire(l) })
	conn, br := held(t, f, addr, f.issued(t, f.aliceSignIn(iss)))
	if a := postOn(t, conn, br, "/v1/tokens", mintLeaf1); a.status != 200 {
		t.Fatalf("%d %s", a.status, a.body)
	}
}

// One path for people (decision 43 ruling 13): a broker that issues refuses
// a person's ID token on every endpoint but /v1/certificate; a machine's is
// unaffected; with no issuance a person's mints as plan 7h built.
func TestAPersonsBearerIsRefusedWhereTheBrokerIssues(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withIssuance(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	var e api.Error
	if w.Code != 401 || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error != "trust_domain_unresolved" ||
		!strings.Contains(e.Detail, "POST /v1/certificate") {
		t.Fatalf("a person's bearer: %s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if r := recs[len(recs)-1]; r["verdict"] != "deny" || r["principal"] != alicePrincipal {
		t.Fatalf("the refusal's record: %v", r)
	}
	now := f.b.Now()
	machine := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, machine); w.Code != 200 {
		t.Fatalf("a machine's bearer: %s", shown(w))
	}
	f.b.Issuer = nil
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil)); w.Code != 200 {
		t.Fatalf("a person's bearer with no issuance: %s", shown(w))
	}
}

// The third case of the placing test, by itself: a principal at a domain the
// verifier does not hold is refused in the broker's words, trust_domain_unresolved.
func TestAnIssuedCertificateForAnUnheldDomainIsRefusedInWords(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	s := f.aliceSignIn(iss)
	s.Principal = "user:alice@elsewhere.example"
	w := f.postAt(context.Background(), f.issuedState(f.issued(t, s)), mintLeaf1, "", f.now)
	var e api.Error
	if w.Code != 401 || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error != "trust_domain_unresolved" ||
		!strings.Contains(e.Detail, "port49 login --sign-in") {
		t.Fatalf("a domain the verifier does not hold: %s", shown(w))
	}
}

// oidcOf is the auth.oidc block of a record, nil when it has none.
func oidcOf(rec map[string]any) map[string]any {
	auth, _ := rec["auth"].(map[string]any)
	o, _ := auth["oidc"].(map[string]any)
	return o
}

// A back-channel logout by sub ends an issued certificate's use of the broker
// as it ends a sign-in's: the next call is refused credential_revoked, and
// the refusal's record carries the sign-in (decision 43 rulings 10, 16).
func TestASubLogoutRefusesAnIssuedCertificate(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	c := f.issued(t, f.aliceSignIn(iss))
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	f.advance(time.Minute)
	if _, err := f.b.Logout(context.Background(), oidc.LogoutToken{Issuer: iss.URL, Subject: "sub-alice",
		IssuedAt: f.b.Now(), Domains: []string{"example.com"}}, "backchannel_logout "+iss.URL); err != nil {
		t.Fatal(err)
	}
	w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "credential_revoked") {
		t.Fatalf("a mint after a sub logout: %s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if r := recs[len(recs)-1]; r["reason"] != "credential_revoked" || oidcOf(r)["sid"] != "s-sub-alice" {
		t.Fatalf("the refusal's record: %v", r)
	}
}

// An operator's revocation, by the certificate's serial or by its principal,
// refuses an issued certificate, and the record carries the sign-in.
func TestARevocationRefusesAnIssuedCertificate(t *testing.T) {
	for name, key := range map[string]func(c tls.Certificate) store.Revocation{
		"by serial": func(c tls.Certificate) store.Revocation {
			return store.Revocation{Kind: store.RevocationCert, Key: certKey(c)}
		},
		"by principal": func(tls.Certificate) store.Revocation {
			return store.Revocation{Kind: store.RevocationPrincipal, Key: alicePrincipal}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 8)
			iss := f.withIssuance(t)
			c := f.issued(t, f.aliceSignIn(iss))
			rv := key(c)
			rv.At, rv.Origin = f.now, "test"
			if err := f.st.PutRevocation(context.Background(), rv); err != nil {
				t.Fatal(err)
			}
			w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now)
			if w.Code != 401 || !strings.Contains(w.Body.String(), "credential_revoked") {
				t.Fatalf("%s", shown(w))
			}
			recs := eventsOf(f.records(t), decision.EventMint)
			if r := recs[len(recs)-1]; oidcOf(r)["sid"] != "s-sub-alice" {
				t.Fatalf("the revoked record carries no sign-in: %v", r)
			}
		})
	}
}

// failingMarks cannot read the marks.
type failingMarks struct{ store.Store }

func (failingMarks) GetRevocation(context.Context, string, string) (store.Revocation, error) {
	return store.Revocation{}, store.ErrUnavailable
}

// A mint whose marks cannot be read is a store_unavailable that still names
// the sign-in.
func TestAnIssuedCertificatesStoreErrorCarriesItsSignIn(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	c := f.issued(t, f.aliceSignIn(iss))
	f.b.Store = failingMarks{f.st}
	w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now)
	if w.Code != 503 {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if r := recs[len(recs)-1]; r["reason"] != "store_unavailable" || oidcOf(r)["sid"] != "s-sub-alice" {
		t.Fatalf("the store error's record: %v", r)
	}
}

// An issued certificate under a directory is not mapped, but its groups are
// read at the mint: the directory answering mints, the directory not
// answering is refused as any mint is.
func TestAnIssuedCertificateUnderADirectoryReadsMembershipAtMint(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	c := f.issued(t, f.aliceSignIn(iss))
	withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(alicePrincipal, "corp_alice")}, nil)
	w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now)
	if r := decodeMint(t, w); r.Principal != alicePrincipal || r.Results[0].Verdict != "permit" {
		t.Fatalf("%s", shown(w))
	}
	withDirectory(f, nil, directory.ErrUnavailable)
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 503 {
		t.Fatalf("the directory not answering: %s", shown(w))
	}
}

// partialIssuedRefresh sets up alice's two live contexts under an issued
// certificate's key, a held connection with that certificate, and a store
// whose second RefreshContext fails after onFirst ran at the first.
func partialIssuedRefresh(t *testing.T, onFirst func(f *fixture, iss *oidctest.Issuer) error, failLogouts *atomic.Bool) (
	*fixture, *oidctest.Issuer, *tls.Conn, *bufio.Reader, tls.Certificate, time.Time) {
	t.Helper()
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	c := f.issued(t, f.aliceSignIn(iss))
	auth := f.now.Add(-time.Hour)
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(c), auth, auth.Add(12*time.Hour))
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, certKey(c), auth, auth.Add(12*time.Hour))
	calls := 0
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"RefreshContext": func() error {
			calls++
			if calls == 1 {
				return onFirst(f, iss)
			}
			if failLogouts != nil {
				failLogouts.Store(true)
			}
			return store.ErrUnavailable
		},
		"GetLogout": func() error {
			if failLogouts != nil && failLogouts.Load() {
				return store.ErrUnavailable
			}
			return nil
		}}}
	addr, _ := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) { f.b.Wire(l) })
	conn, br := held(t, f, addr, c)
	f.advance(time.Minute)
	return f, iss, conn, br, c, auth
}

// Decision 43 ruling 16 on a refresh that fails part way: a logout that
// landed while the refresh extended marks what it extended, as on the OIDC
// path (pre-flight I-2), and the refresh's records carry the sign-in.
func TestAFailedIssuedRefreshStillHonoursALogout(t *testing.T) {
	f, _, conn, br, c, auth := partialIssuedRefresh(t, func(f *fixture, iss *oidctest.Issuer) error {
		return f.st.PutLogout(context.Background(), store.Logout{Key: store.SidKey(iss.URL, "s-sub-alice"),
			At: f.b.Now()}, time.Hour)
	}, nil)
	nonce, text := challengeOn(t, conn, br)
	status, body := answerOn(t, conn, br, conn, c, nonce, text)
	if status != 401 || !strings.Contains(body, "credential_revoked") {
		t.Fatalf("a refresh that failed part way after a logout: %d %s", status, body)
	}
	extended := 0
	for _, nas := range []string{"leaf1", "nx1"} {
		got := f.context(t, nas, "alice")
		if got.AuthTime.After(auth) {
			extended++
			if got.RevokedAt.IsZero() {
				t.Fatalf("%s: a context the failed refresh extended outlived the logout", nas)
			}
		}
	}
	if extended == 0 {
		t.Fatal("the refresh extended nothing, so the test proves nothing")
	}
}

// A failed refresh whose logout re-read fails says so, answers the
// certificate path's retry text, and its record carries the sign-in.
func TestAFailedIssuedRefreshWhoseLogoutReadFailsSaysSo(t *testing.T) {
	var failLogouts atomic.Bool
	f, _, conn, br, c, _ := partialIssuedRefresh(t, func(*fixture, *oidctest.Issuer) error { return nil }, &failLogouts)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	nonce, text := challengeOn(t, conn, br)
	status, body := answerOn(t, conn, br, conn, c, nonce, text)
	if status != 503 || !strings.Contains(body, "retry after Retry-After") {
		t.Fatalf("%d %s", status, body)
	}
	if !strings.Contains(said.String(), "failed part way") {
		t.Fatalf("the operator was told nothing: %q", said.String())
	}
	recs := eventsOf(f.records(t), decision.EventRefresh)
	if r := recs[len(recs)-1]; r["reason"] != "store_unavailable" || oidcOf(r)["sid"] != "s-sub-alice" {
		t.Fatalf("the refresh's record: %v", r)
	}
}
