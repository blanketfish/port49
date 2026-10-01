package certstatus

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/testpki"
)

// t0 is every test's start, on a whole second: a CRL's times are.
var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: t0} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newCA(t *testing.T, cn string) *testpki.CA {
	t.Helper()
	ca, err := testpki.NewCA(cn, t0.Add(-365*24*time.Hour), t0.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// subCA is an intermediate CA parent signs.
func subCA(t *testing.T, parent *testpki.CA, cn string) *testpki.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := sign(t, parent, &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: cn}, NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, key)
	return &testpki.CA{Cert: cert, Key: key}
}

// sign issues tmpl for key under ca.
func sign(t *testing.T, ca *testpki.CA, tmpl *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// leaf is a client certificate ca issues with serial.
func leaf(t *testing.T, ca *testpki.CA, serial int64) *x509.Certificate {
	t.Helper()
	c, err := ca.Issue(testpki.Leaf{CommonName: fmt.Sprintf("user %d", serial), Client: true,
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour), Serial: big.NewInt(serial)})
	if err != nil {
		t.Fatal(err)
	}
	return c.Leaf
}

type crlSpec struct {
	number     int64
	this, next time.Time
	revoked    []x509.RevocationListEntry
	ext        []pkix.Extension
	sigAlg     x509.SignatureAlgorithm
}

// signCRL is ca's list. A zero this is t0; a zero next is an hour after this.
func signCRL(t *testing.T, ca *testpki.CA, s crlSpec) []byte {
	t.Helper()
	if s.this.IsZero() {
		s.this = t0
	}
	if s.next.IsZero() {
		s.next = s.this.Add(time.Hour)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(s.number),
		ThisUpdate: s.this, NextUpdate: s.next, RevokedCertificateEntries: s.revoked, ExtraExtensions: s.ext,
		SignatureAlgorithm: s.sigAlg},
		ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func revoked(serial int64, at time.Time) x509.RevocationListEntry {
	return x509.RevocationListEntry{SerialNumber: big.NewInt(serial), RevocationTime: at}
}

// crlServer serves a list a test can swap, or a failure.
type crlServer struct {
	*httptest.Server
	mu     sync.Mutex
	body   []byte
	status int
	hits   int
}

func newCRLServer(t *testing.T) *crlServer {
	s := &crlServer{status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/crl", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, status := s.body, s.status
		s.hits++
		s.mu.Unlock()
		w.WriteHeader(status)
		w.Write(body)
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/crl", http.StatusFound)
	})
	mux.HandleFunc("/huge", func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, crlMax+1))
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *crlServer) serve(body []byte, status int) {
	s.mu.Lock()
	s.body, s.status = body, status
	s.mu.Unlock()
}

type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *logs) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func stateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newChecker(t *testing.T, cfg Config, clk *clock) (*Checker, *metrics.Metrics, *logs) {
	t.Helper()
	m := metrics.New(prometheus.NewRegistry())
	lg := &logs{}
	return New(cfg, clk.now, m, lg.logf), m, lg
}

func loads(m *metrics.Metrics, name, outcome string) float64 {
	return testutil.ToFloat64(m.CRLLoads.WithLabelValues(name, outcome))
}

// entries records OnNewEntry's calls.
type entries struct {
	mu    sync.Mutex
	calls []string
}

func (e *entries) record(issuer, serial, source string) {
	e.mu.Lock()
	e.calls = append(e.calls, issuer+"|"+serial+"|"+source)
	e.mu.Unlock()
}

func (e *entries) take() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.calls
	e.calls = nil
	sort.Strings(out)
	return out
}

func check(t *testing.T, c *Checker, chain ...*x509.Certificate) Result {
	t.Helper()
	return c.Check(context.Background(), chain)
}

func TestCRL(t *testing.T) {
	ctx := context.Background()

	// one is a checker on a URL source "issuing", ca's lists from srv.
	one := func(t *testing.T, ca *testpki.CA) (*Checker, *metrics.Metrics, *logs, *crlServer, *clock, string) {
		srv := newCRLServer(t)
		clk := newClock()
		dir := stateDir(t)
		c, m, lg := newChecker(t, Config{CRLs: []CRLSource{{Name: "issuing", URL: srv.URL + "/crl", Issuer: ca.Cert}},
			RefreshInterval: 10 * time.Minute, StateDir: dir}, clk)
		return c, m, lg, srv, clk, dir
	}

	t.Run("a fresh verified list", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, _, _, srv, _, _ := one(t, ca)
		user := leaf(t, ca, 100)
		srv.serve(signCRL(t, ca, crlSpec{number: 1, revoked: []x509.RevocationListEntry{revoked(7, t0)}}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		if r := check(t, c, user, ca.Cert); r.Verdict != Good || r.Source != "crl" || r.Name != "issuing" {
			t.Fatalf("not named: %+v, want good from crl issuing", r)
		}
		at := t0.Add(-time.Hour)
		srv.serve(signCRL(t, ca, crlSpec{number: 2, revoked: []x509.RevocationListEntry{revoked(100, at)}}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		r := check(t, c, user, ca.Cert)
		if r.Verdict != Revoked || r.Source != "crl" || r.Depth != 0 || !r.RevokedAt.Equal(at) || r.Hold {
			t.Fatalf("named: %+v, want revoked at %s", r, at)
		}
	})

	t.Run("signed by another key", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		forger := newCA(t, "issuing CA") // the same name, another key
		c, m, _, srv, _, dir := one(t, ca)
		seen := &entries{}
		c.OnNewEntry(seen.record)
		named, other := leaf(t, ca, 100), leaf(t, ca, 200)
		genuine := signCRL(t, ca, crlSpec{number: 1, revoked: []x509.RevocationListEntry{revoked(100, t0)}})
		srv.serve(genuine, 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		seen.take()

		// The forgery lifts 100 and names 200.
		srv.serve(signCRL(t, forger, crlSpec{number: 2, this: t0.Add(time.Minute),
			revoked: []x509.RevocationListEntry{revoked(200, t0)}}), 200)
		errs := c.LoadAll(ctx)
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), "is not signed by issuer_file's certificate") {
			t.Fatalf("errs = %v, want the forgery refused as not signed by issuer_file's certificate", errs)
		}
		if got := loads(m, "issuing", "refused"); got != 1 {
			t.Errorf("refused loads = %v, want 1", got)
		}
		if r := check(t, c, named, ca.Cert); r.Verdict != Revoked {
			t.Errorf("the last good list's entry: %+v, want still revoked", r)
		}
		if r := check(t, c, other, ca.Cert); r.Verdict != Good {
			t.Errorf("the forgery's entry: %+v, want good under the last good list", r)
		}
		if got := seen.take(); len(got) != 0 {
			t.Errorf("OnNewEntry for the forgery: %v", got)
		}
		kept, err := os.ReadFile(filepath.Join(dir, "crl-issuing.der"))
		if err != nil || !bytes.Equal(kept, genuine) {
			t.Errorf("the kept list is not the genuine one (err %v)", err)
		}
		if names, _ := os.ReadDir(dir); len(names) != 1 {
			t.Errorf("state dir holds %d entries, want the genuine list alone", len(names))
		}
	})

	t.Run("signed by another key, before any good list", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		forger := newCA(t, "issuing CA")
		c, _, _, srv, _, dir := one(t, ca)
		seen := &entries{}
		c.OnNewEntry(seen.record)
		srv.serve(signCRL(t, forger, crlSpec{number: 1, revoked: []x509.RevocationListEntry{revoked(100, t0)}}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 1 {
			t.Fatalf("errs = %v, want the forgery refused", errs)
		}
		if r := check(t, c, leaf(t, ca, 100), ca.Cert); r.Verdict != Unknown {
			t.Errorf("%+v, want unknown: nothing verified covers the issuer", r)
		}
		if got := seen.take(); len(got) != 0 {
			t.Errorf("OnNewEntry for the forgery: %v", got)
		}
		if names, _ := os.ReadDir(dir); len(names) != 0 {
			t.Errorf("state dir holds %d entries, want none", len(names))
		}
	})

	t.Run("a forged huge CRL number does not move the floor", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		forger := newCA(t, "issuing CA")
		c, m, _, srv, _, _ := one(t, ca)
		srv.serve(signCRL(t, ca, crlSpec{number: 1}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		huge := crlSpec{number: 1 << 62, this: t0.Add(time.Minute)}
		srv.serve(signCRL(t, forger, huge), 200)
		if errs := c.LoadAll(ctx); len(errs) != 1 {
			t.Fatalf("errs = %v, want the forgery refused", errs)
		}
		srv.serve(signCRL(t, ca, crlSpec{number: 2, this: t0.Add(2 * time.Minute)}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatalf("the next genuine list: %v", errs)
		}
		if got := loads(m, "issuing", "loaded"); got != 2 {
			t.Errorf("loaded = %v, want 2", got)
		}
	})

	t.Run("the issuer's key under another name or key identifier", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		for _, tc := range []struct {
			name, want string
			tmpl       *x509.Certificate
		}{
			{"another name", "names its issuer", &x509.Certificate{Subject: pkix.Name{CommonName: "another CA"}}},
			{"another key identifier", "authority key identifier",
				&x509.Certificate{Subject: ca.Cert.Subject, SubjectKeyId: []byte{1, 2, 3, 4}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// A CA certificate for ca's own key, so the list's signature verifies.
				tc.tmpl.SerialNumber, tc.tmpl.NotBefore, tc.tmpl.NotAfter = big.NewInt(9), t0.Add(-time.Hour), t0.Add(time.Hour)
				tc.tmpl.IsCA, tc.tmpl.BasicConstraintsValid, tc.tmpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
				der, err := x509.CreateCertificate(rand.Reader, tc.tmpl, tc.tmpl, &ca.Key.PublicKey, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				alias, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				c, m, _, srv, _, _ := one(t, ca)
				srv.serve(signCRL(t, &testpki.CA{Cert: alias, Key: ca.Key}, crlSpec{number: 1}), 200)
				errs := c.LoadAll(ctx)
				if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want) {
					t.Fatalf("errs = %v, want one naming %q", errs, tc.want)
				}
				if got := loads(m, "issuing", "refused"); got != 1 {
					t.Errorf("refused = %v, want 1", got)
				}
			})
		}
	})

	t.Run("a list dated in the future is refused", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, _, _, srv, _, _ := one(t, ca)
		srv.serve(signCRL(t, ca, crlSpec{number: 9, this: t0.Add(10 * time.Minute)}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 1 || !strings.Contains(errs[0].Error(), "in the future") {
			t.Fatalf("errs = %v, want refused as dated in the future", errs)
		}
		// Within the skew it loads, and the current list is not refused by it.
		srv.serve(signCRL(t, ca, crlSpec{number: 1, this: t0.Add(4 * time.Minute)}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
	})

	t.Run("a SHA-1 signature is refused", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, m, _, srv, _, _ := one(t, ca)
		srv.serve(signCRL(t, ca, crlSpec{number: 1, sigAlg: x509.ECDSAWithSHA1}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 1 || !strings.Contains(errs[0].Error(), "ECDSA-SHA1") {
			t.Fatalf("errs = %v, want refused as signed with SHA-1", errs)
		}
		if got := loads(m, "issuing", "refused"); got != 1 {
			t.Errorf("refused = %v, want 1", got)
		}
	})

	t.Run("a url with a credential is redacted in its error", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		srv := newCRLServer(t)
		down := newCRLServer(t)
		down.Close() // its address now refuses: net/http's error repeats the url
		for _, base := range []string{srv.URL + "/moved", down.URL + "/crl"} {
			u := strings.Replace(base, "http://", "http://crluser:hunter2@", 1) + "?token=hunter2"
			c, _, _ := newChecker(t, Config{CRLs: []CRLSource{{Name: "issuing", URL: u, Issuer: ca.Cert}}}, newClock())
			errs := c.LoadAll(ctx)
			if len(errs) != 1 || strings.Contains(errs[0].Error(), "hunter2") || strings.Contains(errs[0].Error(), "crluser") {
				t.Fatalf("errs = %v, want one failure without the credential", errs)
			}
		}
	})

	t.Run("a rollback is refused", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, m, _, srv, _, _ := one(t, ca)
		srv.serve(signCRL(t, ca, crlSpec{number: 5, this: t0}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		for _, s := range []crlSpec{
			{number: 4, this: t0.Add(time.Minute)},  // a lower number
			{number: 5, this: t0.Add(-time.Minute)}, // the same number, earlier
		} {
			srv.serve(signCRL(t, ca, s), 200)
			errs := c.LoadAll(ctx)
			if len(errs) != 1 || !strings.Contains(errs[0].Error(), "older than the list in force") {
				t.Errorf("number %d at %s: errs = %v, want refused as older", s.number, s.this, errs)
			}
		}
		if got := loads(m, "issuing", "refused"); got != 2 {
			t.Errorf("refused = %v, want 2", got)
		}
	})

	t.Run("past its next update", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, _, _, srv, clk, _ := one(t, ca)
		srv.serve(signCRL(t, ca, crlSpec{number: 1, next: t0.Add(time.Hour),
			revoked: []x509.RevocationListEntry{revoked(100, t0)}}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		clk.advance(2 * time.Hour)
		r := check(t, c, leaf(t, ca, 200), ca.Cert)
		if r.Verdict != Unknown || !strings.Contains(r.Detail, "issuing") || !strings.Contains(r.Detail, "past its next update") {
			t.Errorf("not named: %+v, want unknown naming issuing past its next update", r)
		}
		if r := check(t, c, leaf(t, ca, 100), ca.Cert); r.Verdict != Revoked {
			t.Errorf("named in a stale list: %+v, want still revoked", r)
		}
	})

	t.Run("a list with no next update applies refresh_interval from its this update", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, _, _, srv, clk, _ := one(t, ca)
		srv.serve(crlWithoutNextUpdate(t, ca, t0.Add(-9*time.Minute)), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		if r := check(t, c, leaf(t, ca, 1), ca.Cert); r.Verdict != Good {
			t.Fatalf("%+v, want good within refresh_interval of its this update", r)
		}
		clk.advance(2 * time.Minute)
		if errs := c.LoadAll(ctx); len(errs) != 0 { // fetched again: unchanged, and no fresher
			t.Fatal(errs)
		}
		if r := check(t, c, leaf(t, ca, 1), ca.Cert); r.Verdict != Unknown {
			t.Errorf("%+v, want unknown past refresh_interval from its this update", r)
		}
	})

	t.Run("refused shapes", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		seq := func(body ...byte) []byte { return append([]byte{0x30, byte(len(body))}, body...) }
		uri := []byte("http://pki.example.com/a.crl")
		dp := append([]byte{0xa0, byte(len(uri) + 4), 0xa0, byte(len(uri) + 2), 0x86, byte(len(uri))}, uri...)
		intOne := []byte{0x02, 0x01, 0x01}
		idp := func(body []byte) pkix.Extension {
			return pkix.Extension{Id: oidIssuingDistPt, Critical: true, Value: body}
		}
		for _, tc := range []struct {
			name, want string
			spec       crlSpec
		}{
			{"a delta CRL", "delta", crlSpec{ext: []pkix.Extension{{Id: oidDeltaCRL, Critical: true, Value: intOne}}}},
			{"an unknown critical extension", "critical extension", crlSpec{ext: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{0x05, 0x00}}}}},
			{"onlySomeReasons", "some reasons", crlSpec{ext: []pkix.Extension{idp(seq(0x83, 0x02, 0x06, 0x40))}}},
			{"indirectCRL", "indirect", crlSpec{ext: []pkix.Extension{idp(seq(0x84, 0x01, 0xff))}}},
			{"a distributionPoint", "distribution point", crlSpec{ext: []pkix.Extension{idp(seq(dp...))}}},
			{"onlyContainsCACerts", "CA certificates", crlSpec{ext: []pkix.Extension{idp(seq(0x82, 0x01, 0xff))}}},
			{"onlyContainsAttributeCerts", "attribute", crlSpec{ext: []pkix.Extension{idp(seq(0x85, 0x01, 0xff))}}},
			{"an entry with a critical extension", "entry with a critical extension", crlSpec{
				revoked: []x509.RevocationListEntry{{SerialNumber: big.NewInt(9), RevocationTime: t0,
					ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true,
						Value: seq(append([]byte{0x86, 0x08}, "http://x"...)...)}}}}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, m, _, srv, _, _ := one(t, ca)
				tc.spec.number = 1
				srv.serve(signCRL(t, ca, tc.spec), 200)
				errs := c.LoadAll(ctx)
				if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want) {
					t.Fatalf("errs = %v, want one naming %q", errs, tc.want)
				}
				if got := loads(m, "issuing", "refused"); got != 1 {
					t.Errorf("refused = %v, want 1", got)
				}
				if r := check(t, c, leaf(t, ca, 1), ca.Cert); r.Verdict != Unknown {
					t.Errorf("%+v, want unknown: the refused list is not in force", r)
				}
			})
		}

		t.Run("onlyContainsUserCerts alone loads", func(t *testing.T) {
			c, _, _, srv, _, _ := one(t, ca)
			srv.serve(signCRL(t, ca, crlSpec{number: 1, ext: []pkix.Extension{idp(seq(0x81, 0x01, 0xff))}}), 200)
			if errs := c.LoadAll(ctx); len(errs) != 0 {
				t.Fatal(errs)
			}
			if r := check(t, c, leaf(t, ca, 1), ca.Cert); r.Verdict != Good {
				t.Errorf("a leaf: %+v, want good", r)
			}
		})
	})

	// Built by openssl (testdata/README.md), so a tagging mistake mirrored
	// in userCertsOnly and in the lists above cannot pass both (re-check R7).
	t.Run("lists built outside Go", func(t *testing.T) {
		blk, _ := pem.Decode(mustRead(t, "testdata/idp-ca.pem"))
		if blk == nil {
			t.Fatal("testdata/idp-ca.pem holds no PEM block")
		}
		issuer, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			file     string
			userOnly bool
			want     string
		}{
			{"testdata/idp-user-certs.der", true, ""},
			{"testdata/idp-distribution-point.der", false, "distribution point"},
		} {
			t.Run(tc.file, func(t *testing.T) {
				raw := mustRead(t, tc.file)
				list, err := x509.ParseRevocationList(raw)
				if err != nil {
					t.Fatal(err)
				}
				clk := &clock{t: list.ThisUpdate.Add(time.Hour)}
				if !clk.now().Before(list.NextUpdate) || clk.now().After(issuer.NotAfter) {
					t.Fatalf("the fixtures have expired; regenerate them (testdata/README.md)")
				}
				c, _, _ := newChecker(t, Config{}, clk)
				l, err := c.accept(CRLSource{Name: "fixture", Issuer: issuer}, raw)
				if tc.want != "" {
					if err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("err = %v, want refused naming %q", err, tc.want)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if !l.userOnly {
					t.Error("the list does not cover user certificates only")
				}
				for _, ext := range list.Extensions {
					if ext.Id.Equal(oidIssuingDistPt) {
						if got, err := userCertsOnly(ext.Value); err != nil || !got {
							t.Errorf("userCertsOnly = %v, %v; want true", got, err)
						}
					}
				}
			})
		}
	})

	t.Run("OnNewEntry", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, _, _, srv, _, _ := one(t, ca)
		seen := &entries{}
		c.OnNewEntry(seen.record)
		issuer := ca.Cert.Subject.String()
		srv.serve(signCRL(t, ca, crlSpec{number: 1,
			revoked: []x509.RevocationListEntry{revoked(0x11, t0), revoked(0x22, t0)}}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		if got, want := seen.take(), []string{issuer + "|11|issuing", issuer + "|22|issuing"}; !equal(got, want) {
			t.Errorf("first load: %v, want %v (every entry is new over no list)", got, want)
		}
		hold := revoked(0x44, t0)
		hold.ReasonCode = reasonCertificateHold
		srv.serve(signCRL(t, ca, crlSpec{number: 2,
			revoked: []x509.RevocationListEntry{revoked(0x11, t0), revoked(0x22, t0), revoked(0x3a, t0), hold}}), 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		if got, want := seen.take(), []string{issuer + "|3a|issuing"}; !equal(got, want) {
			t.Errorf("second load: %v, want %v: the new entry alone, the hold never", got, want)
		}
		if r := check(t, c, leaf(t, ca, 0x44), ca.Cert); r.Verdict != Revoked || !r.Hold {
			t.Errorf("the held leaf: %+v, want revoked with Hold", r)
		}
		if r := check(t, c, leaf(t, ca, 0x3a), ca.Cert); r.Verdict != Revoked || r.Hold {
			t.Errorf("the revoked leaf: %+v, want revoked, not a hold", r)
		}
	})

	t.Run("fetching", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		for _, tc := range []struct{ path, want string }{
			{"/moved", "does not redirect"},
			{"/huge", "larger than 16 MiB"},
		} {
			t.Run(tc.path, func(t *testing.T) {
				srv := newCRLServer(t)
				srv.serve(signCRL(t, ca, crlSpec{number: 1}), 200)
				c, m, _ := newChecker(t, Config{CRLs: []CRLSource{{Name: "issuing", URL: srv.URL + tc.path,
					Issuer: ca.Cert}}}, newClock())
				errs := c.LoadAll(ctx)
				if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want) {
					t.Fatalf("errs = %v, want one naming %q", errs, tc.want)
				}
				if got := loads(m, "issuing", "loaded"); got != 0 {
					t.Errorf("loaded = %v, want 0", got)
				}
				if r := check(t, c, leaf(t, ca, 1), ca.Cert); r.Verdict != Unknown {
					t.Errorf("%+v, want unknown", r)
				}
			})
		}

		t.Run("a file", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "issuing.crl")
			der := signCRL(t, ca, crlSpec{number: 1, revoked: []x509.RevocationListEntry{revoked(5, t0)}})
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644); err != nil {
				t.Fatal(err)
			}
			c, _, _ := newChecker(t, Config{CRLs: []CRLSource{{Name: "issuing", File: path, Issuer: ca.Cert}}}, newClock())
			if errs := c.LoadAll(ctx); len(errs) != 0 {
				t.Fatal(errs)
			}
			if r := check(t, c, leaf(t, ca, 5), ca.Cert); r.Verdict != Revoked {
				t.Errorf("%+v, want revoked from a PEM file", r)
			}
		})

		t.Run("a source that fails keeps the last good list and says so once", func(t *testing.T) {
			c, m, lg, srv, clk, _ := one(t, ca)
			srv.serve(signCRL(t, ca, crlSpec{number: 1, next: t0.Add(24 * time.Hour)}), 200)
			if errs := c.LoadAll(ctx); len(errs) != 0 {
				t.Fatal(errs)
			}
			srv.serve([]byte("down"), http.StatusServiceUnavailable)
			stop := runWith(t, c, clk, func(d time.Duration, i int) bool { return i < 4 })
			stop()
			if got := loads(m, "issuing", "failed"); got < 3 {
				t.Errorf("failed = %v, want at least 3", got)
			}
			var said int
			for _, l := range lg.all() {
				if strings.Contains(l, "CRL issuing") {
					said++
				}
			}
			if said != 1 {
				t.Errorf("said %d times, want once: %q", said, lg.all())
			}
			if r := check(t, c, leaf(t, ca, 1), ca.Cert); r.Verdict != Good {
				t.Errorf("%+v, want good from the last good list", r)
			}
		})
	})

	t.Run("persistence", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, _, _, srv, clk, dir := one(t, ca)
		der := signCRL(t, ca, crlSpec{number: 1, revoked: []x509.RevocationListEntry{revoked(5, t0)}})
		srv.serve(der, 200)
		if errs := c.LoadAll(ctx); len(errs) != 0 {
			t.Fatal(errs)
		}
		path := filepath.Join(dir, "crl-issuing.der")
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("kept list mode %v, want 0600", fi.Mode().Perm())
		}
		if kept, _ := os.ReadFile(path); !bytes.Equal(kept, der) {
			t.Error("the kept list is not the list loaded")
		}
		srv.Close()

		cfg := Config{CRLs: []CRLSource{{Name: "issuing", URL: srv.URL + "/crl", Issuer: ca.Cert}},
			RefreshInterval: 10 * time.Minute, StateDir: dir}
		restarted, _, _ := newChecker(t, cfg, clk)
		if errs := restarted.LoadPersisted(); len(errs) != 0 {
			t.Fatal(errs)
		}
		if r := check(t, restarted, leaf(t, ca, 1), ca.Cert); r.Verdict != Good {
			t.Errorf("after a restart with the server down: %+v, want good", r)
		}
		if r := check(t, restarted, leaf(t, ca, 5), ca.Cert); r.Verdict != Revoked {
			t.Errorf("after a restart with the server down: %+v, want revoked", r)
		}

		t.Run("a source name is confined to the state directory", func(t *testing.T) {
			kept := stateDir(t)
			for _, name := range []string{"../escape", "a/b", "UPPER", "issuing"} {
				srv := newCRLServer(t)
				srv.serve(der, 200)
				cfg := Config{CRLs: []CRLSource{{Name: name, URL: srv.URL + "/crl", Issuer: ca.Cert}}, StateDir: kept}
				c, _, _ := newChecker(t, cfg, clk)
				if errs := c.LoadAll(ctx); len(errs) != 0 {
					t.Fatal(errs)
				}
				restarted, _, _ := newChecker(t, cfg, clk)
				if errs := restarted.LoadPersisted(); len(errs) != 0 {
					t.Fatalf("%q: %v", name, errs)
				}
				if r := check(t, restarted, leaf(t, ca, 5), ca.Cert); r.Verdict != Revoked {
					t.Errorf("%q: %+v, want revoked from its kept list", name, r)
				}
			}
			entries, _ := os.ReadDir(kept)
			if len(entries) != 4 {
				t.Errorf("state dir holds %d files, want 4", len(entries))
			}
			for _, e := range entries {
				if !strings.HasPrefix(e.Name(), "crl-") || !strings.HasSuffix(e.Name(), ".der") {
					t.Errorf("kept as %q", e.Name())
				}
			}
			if outside, _ := os.ReadDir(filepath.Dir(kept)); len(outside) != 1 {
				t.Errorf("the state directory's parent holds %d entries, want the directory alone", len(outside))
			}
			if _, err := os.Stat(filepath.Join(kept, "crl-issuing.der")); err != nil {
				t.Errorf("a safe name is not kept as crl-<name>.der: %v", err)
			}
		})

		t.Run("a kept list that does not verify", func(t *testing.T) {
			forger := newCA(t, "issuing CA")
			bad := stateDir(t)
			if err := os.WriteFile(filepath.Join(bad, "crl-issuing.der"), signCRL(t, forger, crlSpec{number: 1}), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := cfg
			cfg.StateDir = bad
			c, _, _ := newChecker(t, cfg, clk)
			errs := c.LoadPersisted()
			if len(errs) != 1 || !strings.Contains(errs[0].Error(), "is not signed by issuer_file's certificate") {
				t.Fatalf("errs = %v, want the kept list refused", errs)
			}
			if r := check(t, c, leaf(t, ca, 1), ca.Cert); r.Verdict != Unknown {
				t.Errorf("%+v, want unknown", r)
			}
		})

		t.Run("a kept list in a directory others can write", func(t *testing.T) {
			loose := stateDir(t)
			if err := os.WriteFile(filepath.Join(loose, "crl-issuing.der"), der, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(loose, 0o777); err != nil {
				t.Fatal(err)
			}
			cfg := cfg
			cfg.StateDir = loose
			c, _, _ := newChecker(t, cfg, clk)
			if errs := c.LoadPersisted(); len(errs) != 1 || !strings.Contains(errs[0].Error(), "writable by others") {
				t.Fatalf("errs = %v, want the directory refused", errs)
			}
			if r := check(t, c, leaf(t, ca, 1), ca.Cert); r.Verdict != Unknown {
				t.Errorf("%+v, want unknown", r)
			}
		})
	})

	t.Run("backoff", func(t *testing.T) {
		ca := newCA(t, "issuing CA")
		c, _, _, srv, clk, _ := one(t, ca)
		c.cfg.RefreshInterval = 5 * time.Minute
		good := signCRL(t, ca, crlSpec{number: 1, next: t0.Add(24 * time.Hour)})
		srv.serve([]byte("down"), http.StatusServiceUnavailable)
		var waits []time.Duration
		// The first load fails; the source comes back after the fifth
		// failure, and goes down again after one success.
		stop := runWith(t, c, clk, func(d time.Duration, i int) bool {
			waits = append(waits, d)
			switch i {
			case 4:
				srv.serve(good, 200)
			case 5:
				srv.serve([]byte("down"), http.StatusServiceUnavailable)
			}
			return i < 6
		})
		stop()
		want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute,
			5 * time.Minute, 30 * time.Second}
		if !equalDurations(waits, want) {
			t.Errorf("waits = %v, want %v", waits, want)
		}
	})
}

// runWith runs c.Run with its waits under the test's control: each wait is
// handed to next with its index, the clock moves by it, and Run goes on
// while next says so. stop ends Run and waits for it.
func runWith(t *testing.T, c *Checker, clk *clock, next func(d time.Duration, i int) bool) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	asked := make(chan time.Duration)
	fire := make(chan time.Time)
	c.after = func(d time.Duration) <-chan time.Time {
		select {
		case asked <- d:
		case <-ctx.Done():
		}
		return fire
	}
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	for i := 0; ; i++ {
		var d time.Duration
		select {
		case d = <-asked:
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatal("Run did not wait")
		}
		goOn := next(d, i)
		clk.advance(d)
		if !goOn {
			break
		}
		fire <- clk.now()
	}
	return func() {
		cancel()
		<-done
	}
}

// crlWithoutNextUpdate is ca's list number 1 naming no nextUpdate, which
// RFC 5280 lets a list omit and x509.CreateRevocationList cannot make.
func crlWithoutNextUpdate(t *testing.T, ca *testpki.CA, this time.Time) []byte {
	t.Helper()
	alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}} // ecdsa-with-SHA256
	number, err := asn1.Marshal(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := asn1.Marshal(struct {
		Version    int
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate time.Time
		Extensions []pkix.Extension `asn1:"tag:0,explicit"`
	}{1, alg, asn1.RawValue{FullBytes: ca.Cert.RawSubject}, this.UTC(),
		[]pkix.Extension{{Id: oidCRLNumber, Value: number}}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, ca.Key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, alg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	if l, err := x509.ParseRevocationList(der); err != nil || !l.NextUpdate.IsZero() {
		t.Fatalf("the hand-built list: %v", err)
	}
	return der
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func equal(a, b []string) bool {
	return strings.Join(a, "\n") == strings.Join(b, "\n")
}

func equalDurations(a, b []time.Duration) bool {
	return fmt.Sprint(a) == fmt.Sprint(b)
}
