package brokercrl

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// privateDir is a directory only its owner can write, as ~/.port49/crl is: a
// kept list is read back only from one.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fixture is a broker certificate chain and the CRL server its leaf names.
type fixture struct {
	root, signer *testpki.CA // signer issued the leaf: root itself, or an intermediate
	leaf         tls.Certificate
	srv          *httptest.Server
	hits         atomic.Int32
}

func (f *fixture) state() tls.ConnectionState {
	chain := []*x509.Certificate{f.leaf.Leaf, f.signer.Cert}
	if f.signer != f.root {
		chain = append(chain, f.root.Cert)
	}
	return tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain}}
}

func signCRL(t *testing.T, signer *testpki.CA, revoked ...*big.Int) []byte {
	t.Helper()
	now := time.Now()
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	for _, sn := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: sn, RevocationTime: now.Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, signer.Cert, signer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// signStaleCRL is a list whose next update has passed.
func signStaleCRL(t *testing.T, signer *testpki.CA) []byte {
	t.Helper()
	now := time.Now()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: now.Add(-3 * time.Hour), NextUpdate: now.Add(-2 * time.Hour)}, signer.Cert, signer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// newFixture serves, at the leaf's one distribution point, serve: "good" (a
// list naming nothing), "revoked" (naming the leaf), "forged" (a good list
// another key signed), "error" (a 500 each time) or "down" (a server that is
// shut). The leaf is issued by root, or by a DP-less intermediate under it.
func newFixture(t *testing.T, serve string, noDP, intermediate bool) *fixture {
	t.Helper()
	now := time.Now()
	root, err := testpki.NewCA("broker root", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{root: root, signer: root}
	if intermediate {
		if f.signer, err = root.IssueCA("broker intermediate", now.Add(-time.Hour), now.Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	other, err := testpki.NewCA("someone else", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var leafSerial *big.Int
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		switch serve {
		case "good":
			w.Write(signCRL(t, f.signer))
		case "revoked":
			w.Write(signCRL(t, f.signer, leafSerial))
		case "forged":
			w.Write(signCRL(t, other))
		case "stale":
			w.Write(signStaleCRL(t, f.signer))
		default:
			http.Error(w, "no", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(f.srv.Close)
	leaf := testpki.Leaf{CommonName: "broker", IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if !noDP {
		leaf.CRLDistributionPoints = []string{f.srv.URL + "/ca.crl"}
	}
	if f.leaf, err = f.signer.Issue(leaf); err != nil {
		t.Fatal(err)
	}
	leafSerial = f.leaf.Leaf.SerialNumber
	if serve == "down" {
		f.srv.Close()
	}
	return f
}

func brokerChain(t *testing.T, serve string, noDP bool) (tls.ConnectionState, *fixture) {
	f := newFixture(t, serve, noDP, false)
	return f.state(), f
}

func threeLevelChain(t *testing.T, serve string) (tls.ConnectionState, *fixture) {
	f := newFixture(t, serve, false, true)
	return f.state(), f
}

func TestBrokerCRLModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    Mode
		serve   string // "good" | "revoked" | "down" | "forged"
		noDP    bool
		refused bool
		said    string
	}{
		{"good list", ModeCheck, "good", false, false, ""},
		{"revoked under check", ModeCheck, "revoked", false, true, ""},
		{"revoked under require", ModeRequire, "revoked", false, true, ""},
		{"down under check goes on, said once", ModeCheck, "down", false, false, "could not check the broker certificate's revocation"},
		{"down under require refuses", ModeRequire, "down", false, true, ""},
		{"a list another key signed is not a list", ModeCheck, "forged", false, false, "could not check"},
		{"no distribution point under check: nothing checked, nothing said", ModeCheck, "down", true, false, ""},
		{"no distribution point under require refuses", ModeRequire, "good", true, true, ""},
		{"off checks nothing", ModeOff, "revoked", false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, _ := brokerChain(t, tc.serve, tc.noDP)
			var said []string
			c := New(privateDir(t), tc.mode, time.Now, func(s string) { said = append(said, s) })
			err := c.VerifyConnection(cs)
			if (err != nil) != tc.refused {
				t.Fatalf("VerifyConnection = %v, refused want %v", err, tc.refused)
			}
			if tc.serve == "revoked" && tc.refused {
				var re *RevokedError
				if !errors.As(err, &re) {
					t.Fatalf("want *RevokedError, got %T", err)
				}
				for _, want := range []string{"the broker's certificate", "(serial ", ") is revoked by ", "nothing was sent to it"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("revoked error %q lacks %q", err, want)
					}
				}
			}
			if tc.serve == "down" && tc.refused {
				var ue *UncheckedError
				if !errors.As(err, &ue) || !strings.Contains(err.Error(), "broker_crl: require") {
					t.Fatalf("require with the list unobtainable: %v, want *UncheckedError naming broker_crl: require", err)
				}
			}
			_ = c.VerifyConnection(cs) // a second connection says nothing new
			if tc.said == "" && len(said) != 0 || tc.said != "" && (len(said) != 1 || !strings.Contains(said[0], tc.said)) {
				t.Fatalf("said %q", said)
			}
		})
	}
}

func TestTheLastGoodListOutlivesTheServerUntilItsNextUpdate(t *testing.T) {
	cs, f := brokerChain(t, "good", false)
	dir := privateDir(t)
	clock := &fakeClock{t: time.Now()}
	var said []string
	warn := func(s string) { said = append(said, s) }
	if err := New(dir, ModeRequire, clock.Now, warn).VerifyConnection(cs); err != nil {
		t.Fatalf("first check against a live server: %v", err)
	}
	f.srv.Close()
	hits := f.hits.Load()
	// A new process on the same directory, the server gone, the list fresh.
	if err := New(dir, ModeRequire, clock.Now, warn).VerifyConnection(cs); err != nil {
		t.Fatalf("the kept list should answer under require: %v", err)
	}
	if len(said) != 0 || f.hits.Load() != hits {
		t.Fatalf("a fresh kept list said %q and made %d more requests", said, f.hits.Load()-hits)
	}
	clock.Advance(2 * time.Hour) // past the list's NextUpdate
	if err := New(dir, ModeCheck, clock.Now, warn).VerifyConnection(cs); err != nil {
		t.Fatalf("a stale list under check goes on: %v", err)
	}
	if len(said) != 1 || !strings.Contains(said[0], "could not check") || !strings.Contains(said[0], "next update") {
		t.Fatalf("a stale list said %q, want one 'could not check' naming the next update", said)
	}
	if err := New(dir, ModeRequire, clock.Now, warn).VerifyConnection(cs); err == nil {
		t.Fatal("a stale list under require was accepted")
	}
}

// An intermediate naming no distribution point (step-ca's default) is passed
// over under check, and the leaf it issued is still checked (decision 45
// ruling 9; pre-flight I10). Under require it is refused: it is a link with no
// fetchable list (Ryan, 2026-10-12).
func TestAnIntermediateWithNoDistributionPoint(t *testing.T) {
	for _, tc := range []struct {
		serve   string
		mode    Mode
		refused bool
	}{
		{"good", ModeCheck, false},
		{"revoked", ModeCheck, true}, // the leaf's own list still refuses
		{"good", ModeRequire, true},  // the intermediate names none
	} {
		cs, _ := threeLevelChain(t, tc.serve) // root → intermediate (no DP) → leaf (DP, list by the intermediate)
		var said []string
		c := New(privateDir(t), tc.mode, time.Now, func(s string) { said = append(said, s) })
		err := c.VerifyConnection(cs)
		if (err != nil) != tc.refused || len(said) != 0 {
			t.Fatalf("%s under %s: %v, said %q", tc.serve, tc.mode, err, said)
		}
		var ne *NoDistributionPointError
		if tc.mode == ModeRequire && (!errors.As(err, &ne) || !strings.Contains(err.Error(), "broker intermediate")) {
			t.Fatalf("require with a DP-less intermediate: %v, want *NoDistributionPointError naming it", err)
		}
	}
}

// A revoked leaf is reported as revoked, not as the missing distribution point
// of an intermediate above it.
func TestRevokedBeatsAMissingDistributionPointUnderRequire(t *testing.T) {
	cs, _ := threeLevelChain(t, "revoked")
	var re *RevokedError
	if err := New(privateDir(t), ModeRequire, time.Now, nil).VerifyConnection(cs); !errors.As(err, &re) {
		t.Fatalf("revoked leaf under a DP-less intermediate, require: %v, want *RevokedError", err)
	}
}

// A forged list is said in words a client user knows: they have no issuer_file.
func TestAForgedListIsNotSaidToBeIssuerFiles(t *testing.T) {
	cs, _ := brokerChain(t, "forged", false)
	err := New(privateDir(t), ModeRequire, time.Now, nil).VerifyConnection(cs)
	if err == nil || !strings.Contains(err.Error(), "is not signed by the issuing CA's certificate") ||
		strings.Contains(err.Error(), "issuer_file") {
		t.Fatalf("a forged list under require: %v, want it not signed by the issuing CA's certificate, with no issuer_file", err)
	}
}

// A down CRL server costs one wait, not one per connection.
func TestAFailedFetchIsRememberedForAMinute(t *testing.T) {
	cs, f := brokerChain(t, "error", false)
	clock := &fakeClock{t: time.Now()}
	c := New(privateDir(t), ModeCheck, clock.Now, func(string) {})
	for i := 0; i < 3; i++ {
		if err := c.VerifyConnection(cs); err != nil {
			t.Fatal(err)
		}
		clock.Advance(10 * time.Second)
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("three connections within a minute made %d fetches, want 1", n)
	}
	clock.Advance(time.Minute)
	if err := c.VerifyConnection(cs); err != nil {
		t.Fatal(err)
	}
	if n := f.hits.Load(); n != 2 {
		t.Fatalf("after a minute there were %d fetches, want 2", n)
	}
}

// Only http and https distribution points are fetched. A leaf naming only
// others (AD CS issues ldap:// by default), or none, names no fetchable one:
// under check it is not checked and nothing is said; under require it is
// refused, saying what to add (R9, Ryan 2026-10-12).
func TestALeafWithNoFetchableDistributionPoint(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name string
		dps  []string
	}{
		{"ldap and file only", []string{"ldap://h.example/CN=x", "file:///x.crl"}},
		{"none at all", nil},
	} {
		root, err := testpki.NewCA("broker root", now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := root.Issue(testpki.Leaf{CommonName: "broker", IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(time.Hour), CRLDistributionPoints: tc.dps})
		if err != nil {
			t.Fatal(err)
		}
		cs := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf.Leaf, root.Cert}}}

		var said []string
		check := New(privateDir(t), ModeCheck, time.Now, func(s string) { said = append(said, s) })
		for i := 0; i < 2; i++ {
			if err := check.VerifyConnection(cs); err != nil {
				t.Fatalf("%s under check: %v, want it to pass", tc.name, err)
			}
		}
		if len(said) > 1 {
			t.Fatalf("%s under check said %q, want at most one", tc.name, said)
		}

		err = New(privateDir(t), ModeRequire, time.Now, nil).VerifyConnection(cs)
		var ne *NoDistributionPointError
		if !errors.As(err, &ne) {
			t.Fatalf("%s under require: %v, want *NoDistributionPointError", tc.name, err)
		}
		for _, want := range []string{"names no http(s) CRL distribution point", "broker_crl: require refuses it",
			"add an HTTP CDP to the CA", "broker_crl: check"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s: error %q lacks %q", tc.name, err, want)
			}
		}
		if err := New(privateDir(t), ModeOff, time.Now, nil).VerifyConnection(cs); err != nil {
			t.Fatalf("%s under off: %v", tc.name, err)
		}
	}
}

// A leaf with an http list is still checked under require.
func TestAnHTTPLeafIsStillCheckedUnderRequire(t *testing.T) {
	for serve, refused := range map[string]bool{"good": false, "revoked": true} {
		cs, _ := brokerChain(t, serve, false)
		err := New(privateDir(t), ModeRequire, time.Now, nil).VerifyConnection(cs)
		if (err != nil) != refused {
			t.Fatalf("%s list under require: %v, refused want %v", serve, err, refused)
		}
	}
}

// A list that fetches fine but cannot answer (past its next update, as a stuck
// publisher leaves it) is remembered for a minute like a failed fetch, not
// downloaded again on every connection.
func TestAStaleListIsRememberedForAMinute(t *testing.T) {
	cs, f := brokerChain(t, "stale", false)
	clock := &fakeClock{t: time.Now()}
	c := New(privateDir(t), ModeCheck, clock.Now, func(string) {})
	for i := 0; i < 3; i++ {
		if err := c.VerifyConnection(cs); err != nil {
			t.Fatal(err)
		}
		clock.Advance(10 * time.Second)
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("three connections within a minute made %d fetches of a stale list, want 1", n)
	}
	clock.Advance(time.Minute)
	if err := c.VerifyConnection(cs); err != nil {
		t.Fatal(err)
	}
	if n := f.hits.Load(); n != 2 {
		t.Fatalf("after a minute there were %d fetches, want 2", n)
	}
}

// A state with no verified chain cannot happen with RootCAs set; if it ever
// did, require must not read it as a pass.
func TestNoVerifiedChainIsRefusedUnderRequire(t *testing.T) {
	var ue *UncheckedError
	if err := New(privateDir(t), ModeRequire, time.Now, nil).VerifyConnection(tls.ConnectionState{}); !errors.As(err, &ue) {
		t.Fatalf("require with no verified chain: %v, want *UncheckedError", err)
	}
	if err := New(privateDir(t), ModeCheck, time.Now, nil).VerifyConnection(tls.ConnectionState{}); err != nil {
		t.Fatalf("check with no verified chain: %v", err)
	}
}

func TestNoBearerTokenReachesARevokedBroker(t *testing.T) {
	_, f := brokerChain(t, "revoked", false)
	var called atomic.Bool
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true) }))
	broker.TLS = &tls.Config{Certificates: []tls.Certificate{f.leaf}} // the revoked leaf
	broker.StartTLS()
	defer broker.Close()
	c := New(privateDir(t), ModeCheck, time.Now, func(string) {})
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: f.root.Pool(), VerifyConnection: c.VerifyConnection}}}
	req, _ := http.NewRequest("POST", broker.URL+"/v1/certificate", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer an-id-token")
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("a request to a revoked broker succeeded")
	}
	var re *RevokedError
	if !errors.As(err, &re) {
		t.Fatalf("the refusal is %T (%v), want one that wraps *RevokedError", err, err)
	}
	if called.Load() {
		t.Fatal("the revoked broker's handler saw the request, bearer token and all")
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeCheck, "check": ModeCheck, "require": ModeRequire, "off": ModeOff} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Fatalf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseMode("strict"); err == nil || !strings.Contains(err.Error(), "check, require or off") {
		t.Fatalf("ParseMode(strict) = %v", err)
	}
}
