package certstatus

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/rhwendt/port49/internal/testpki"
)

// answer is what the test responder signs: by signerCert's key (the
// issuer's when nil), embedding embed, for serial (the request's when nil).
type answer struct {
	signerCert *x509.Certificate
	signerKey  crypto.Signer
	embed      *x509.Certificate
	status     int
	this, next time.Time
	serial     *big.Int
	revokedAt  time.Time
	reason     int
	garbage    bool              // an unsigned body, not an OCSP response
	certIDFor  *x509.Certificate // the CA the CertID names, when not the responder's issuer
	sigAlg     x509.SignatureAlgorithm
}

// responder is an OCSP responder for issuer that counts calls and can hang.
type responder struct {
	*httptest.Server
	t      *testing.T
	issuer *testpki.CA

	mu     sync.Mutex
	calls  int
	hashes []crypto.Hash
	ans    answer
	status int    // an HTTP status other than 200, answered with no body
	raw    string // a raw HTTP response written to the connection instead
	gate   chan struct{}
}

func newResponder(t *testing.T, issuer *testpki.CA) *responder {
	r := &responder{t: t, issuer: issuer, ans: answer{status: ocsp.Good, this: t0, next: t0.Add(30 * time.Minute)}}
	r.Server = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.Close)
	return r
}

func (r *responder) set(f func(r *responder)) {
	r.mu.Lock()
	f(r)
	r.mu.Unlock()
}

func (r *responder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *responder) serve(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	q, err := ocsp.ParseRequest(body)
	if err != nil {
		r.t.Errorf("the request does not parse: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.calls++
	r.hashes = append(r.hashes, q.HashAlgorithm)
	ans, status, raw, gate := r.ans, r.status, r.raw, r.gate
	r.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-req.Context().Done():
			return
		}
	}
	if raw != "" {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			r.t.Error(err)
			return
		}
		buf.WriteString(raw)
		buf.Flush()
		conn.Close()
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if ans.garbage {
		w.Write([]byte("not an OCSP response"))
		return
	}
	signerCert, signerKey := ans.signerCert, ans.signerKey
	if signerCert == nil {
		signerCert, signerKey = r.issuer.Cert, r.issuer.Key
	}
	serial := ans.serial
	if serial == nil {
		serial = q.SerialNumber
	}
	certIDFor := r.issuer.Cert
	if ans.certIDFor != nil {
		certIDFor = ans.certIDFor
	}
	der, err := ocsp.CreateResponse(certIDFor, signerCert, ocsp.Response{Status: ans.status, SerialNumber: serial,
		ThisUpdate: ans.this, NextUpdate: ans.next, RevokedAt: ans.revokedAt, RevocationReason: ans.reason,
		Certificate: ans.embed, IssuerHash: q.HashAlgorithm, SignatureAlgorithm: ans.sigAlg}, signerKey)
	if err != nil {
		r.t.Errorf("CreateResponse: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(der)
}

// delegate is a responder certificate ca issues, with id-kp-OCSPSigning
// when eku, valid from nb to na.
func delegate(t *testing.T, ca *testpki.CA, eku bool, nb, na time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "ocsp responder"},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature}
	if eku {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
	return sign(t, ca, tmpl, key), key
}

func ocspChecker(t *testing.T, cfg OCSPConfig) (*Checker, *clock) {
	t.Helper()
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	clk := newClock()
	c, _, _ := newChecker(t, Config{OCSP: &cfg, RefreshInterval: 10 * time.Minute}, clk)
	return c, clk
}

func TestOCSP(t *testing.T) {
	ca := newCA(t, "issuing CA")
	user := leaf(t, ca, 100)

	// Each answer here is refused, Unknown. It is cached as a failure for
	// 30s, never as the status it claims: a valid revoked answer after
	// that is taken.
	t.Run("refused answers", func(t *testing.T) {
		stranger := newCA(t, "issuing CA")
		noEKU, noEKUKey := delegate(t, ca, false, t0.Add(-time.Hour), t0.Add(time.Hour))
		expired, expiredKey := delegate(t, ca, true, t0.Add(-2*time.Hour), t0.Add(-time.Hour))
		early, earlyKey := delegate(t, ca, true, t0.Add(time.Hour), t0.Add(2*time.Hour))
		foreign, foreignKey := delegate(t, stranger, true, t0.Add(-time.Hour), t0.Add(time.Hour))
		// ca's own key under another name: the CertID's key hash is ca's,
		// its name hash is not (review N1).
		renamed := aliasCA(t, ca, &x509.Certificate{Subject: pkix.Name{CommonName: "another CA"}})
		for _, tc := range []struct {
			name, want string
			ans        answer
			hang       bool
		}{
			{name: "a delegate without the OCSP-signing usage", want: "without the OCSP-signing usage",
				ans: answer{signerCert: noEKU, signerKey: noEKUKey, embed: noEKU}},
			{name: "a delegate past its NotAfter", want: "out of validity",
				ans: answer{signerCert: expired, signerKey: expiredKey, embed: expired}},
			{name: "a delegate not yet valid", want: "out of validity",
				ans: answer{signerCert: early, signerKey: earlyKey, embed: early}},
			{name: "a CertID naming another CA under the same serial", want: "its answer is for another certificate",
				ans: answer{certIDFor: stranger.Cert}},
			{name: "a SHA-1 signature", want: "ECDSA-SHA1",
				ans: answer{sigAlg: x509.ECDSAWithSHA1}},
			{name: "a CertID naming the issuer's key under another name", want: "its answer is for another certificate",
				ans: answer{certIDFor: renamed}},
			{name: "an unknown status", want: "answered unknown", ans: answer{status: ocsp.Unknown}},
			{name: "a delegate another CA issued", want: "this issuer did not sign",
				ans: answer{signerCert: foreign, signerKey: foreignKey, embed: foreign}},
			{name: "signed by another key under the issuer's name", want: "does not verify for this issuer",
				ans: answer{signerCert: stranger.Cert, signerKey: stranger.Key}},
			{name: "a NextUpdate in the past", want: "past its next update",
				ans: answer{this: t0.Add(-2 * time.Hour), next: t0.Add(-time.Hour)}},
			{name: "a ThisUpdate 6m in the future", want: "dated in the future",
				ans: answer{this: t0.Add(6 * time.Minute), next: t0.Add(time.Hour)}},
			{name: "a ThisUpdate older than refresh_interval with no NextUpdate", want: "older than refresh_interval",
				ans: answer{this: t0.Add(-11 * time.Minute)}},
			{name: "an answer for another serial", want: "for another certificate",
				ans: answer{serial: big.NewInt(101)}},
			{name: "an unsigned body", want: "does not parse", ans: answer{garbage: true}},
			{name: "a hang past the timeout", want: "did not answer", hang: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resp := newResponder(t, ca)
				if tc.ans.this.IsZero() {
					tc.ans.this, tc.ans.next = t0, t0.Add(30*time.Minute)
				}
				gate := make(chan struct{})
				t.Cleanup(func() { close(gate) })
				resp.set(func(r *responder) {
					r.ans = tc.ans
					if tc.hang {
						r.gate = gate
					}
				})
				c, clk := ocspChecker(t, OCSPConfig{Responder: resp.URL, Timeout: 200 * time.Millisecond})
				r := check(t, c, user, ca.Cert)
				if r.Verdict != Unknown || r.Source != "none" || !strings.Contains(r.Detail, "OCSP") ||
					!strings.Contains(r.Detail, tc.want) {
					t.Fatalf("%+v, want unknown from OCSP naming %q", r, tc.want)
				}
				if check(t, c, user, ca.Cert); resp.count() != 1 {
					t.Errorf("calls within 30s = %d, want 1 (the failure cached)", resp.count())
				}
				clk.advance(31 * time.Second)
				resp.set(func(r *responder) {
					r.gate = nil
					r.ans = answer{status: ocsp.Revoked, this: clk.now(), next: clk.now().Add(time.Hour),
						revokedAt: t0.Add(-time.Hour)}
				})
				if r := check(t, c, user, ca.Cert); r.Verdict != Revoked {
					t.Errorf("after 30s, a valid revoked answer: %+v, want revoked", r)
				}
			})
		}
	})

	t.Run("the issuer signing good, cached to its NextUpdate", func(t *testing.T) {
		resp := newResponder(t, ca)
		c, clk := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		r := check(t, c, user, ca.Cert)
		if r.Verdict != Good || r.Source != "ocsp" || r.Name != resp.URL {
			t.Fatalf("%+v, want good from ocsp %s", r, resp.URL)
		}
		clk.advance(29 * time.Minute)
		if check(t, c, user, ca.Cert); resp.count() != 1 {
			t.Errorf("calls before NextUpdate = %d, want 1", resp.count())
		}
		clk.advance(2 * time.Minute)
		if check(t, c, user, ca.Cert); resp.count() != 2 {
			t.Errorf("calls past NextUpdate = %d, want 2", resp.count())
		}
	})

	t.Run("a good answer is cached an hour at most", func(t *testing.T) {
		resp := newResponder(t, ca)
		resp.set(func(r *responder) { r.ans.next = t0.Add(6 * time.Hour) })
		c, clk := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		check(t, c, user, ca.Cert)
		clk.advance(59 * time.Minute)
		if check(t, c, user, ca.Cert); resp.count() != 1 {
			t.Errorf("calls within the hour = %d, want 1", resp.count())
		}
		clk.advance(2 * time.Minute)
		if check(t, c, user, ca.Cert); resp.count() != 2 {
			t.Errorf("calls past the hour = %d, want 2", resp.count())
		}
	})

	t.Run("an answer with no NextUpdate is reused only within refresh_interval of its ThisUpdate", func(t *testing.T) {
		resp := newResponder(t, ca)
		resp.set(func(r *responder) { r.ans.this, r.ans.next = t0.Add(-9*time.Minute), time.Time{} })
		c, clk := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		if r := check(t, c, user, ca.Cert); r.Verdict != Good {
			t.Fatalf("%+v, want good", r)
		}
		clk.advance(30 * time.Second)
		if check(t, c, user, ca.Cert); resp.count() != 1 {
			t.Errorf("calls while fresh = %d, want 1", resp.count())
		}
		clk.advance(time.Minute)
		resp.set(func(r *responder) { r.ans.this = clk.now() })
		if check(t, c, user, ca.Cert); resp.count() != 2 {
			t.Errorf("calls past refresh_interval from its ThisUpdate = %d, want 2", resp.count())
		}
	})

	// A caller that hangs up mid-question stops waiting; the question runs
	// on to its own timeout, and its real answer is what the next caller
	// gets, never the hang-up as a failure (review I3).
	t.Run("a caller hanging up leaves the others the real answer", func(t *testing.T) {
		resp := newResponder(t, ca)
		gate := make(chan struct{})
		resp.set(func(r *responder) { r.gate = gate })
		c, _ := ocspChecker(t, OCSPConfig{Responder: resp.URL, Timeout: 5 * time.Second})
		ctx, cancel := context.WithCancel(context.Background())
		gone := make(chan Result)
		go func() { gone <- c.Check(ctx, []*x509.Certificate{user, ca.Cert}) }()
		for resp.count() == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		if r := <-gone; r.Verdict != Unknown || !strings.Contains(r.Detail, "abandoned") {
			t.Errorf("the caller that hung up: %+v, want unknown, abandoned", r)
		}
		close(gate)
		if r := check(t, c, user, ca.Cert); r.Verdict != Good {
			t.Errorf("the next caller: %+v, want the responder's good", r)
		}
		if resp.count() != 1 {
			t.Errorf("calls = %d, want 1: the next caller shares the question or its answer", resp.count())
		}
	})

	// A credential in a responder's url reaches no Result and no line.
	t.Run("a responder url is redacted", func(t *testing.T) {
		resp := newResponder(t, ca)
		resp.set(func(r *responder) { r.status = http.StatusInternalServerError })
		u := strings.Replace(resp.URL, "http://", "http://ocspuser:hunter2@", 1) + "/?token=hunter2"
		c, _ := ocspChecker(t, OCSPConfig{Responder: u})
		r := check(t, c, user, ca.Cert)
		resp.set(func(r *responder) { r.status = 0 })
		c2, _ := ocspChecker(t, OCSPConfig{Responder: u})
		good := check(t, c2, user, ca.Cert)
		for what, text := range map[string]string{"Detail": r.Detail, "Name": good.Name, "Describe": c.Describe()} {
			if strings.Contains(text, "hunter2") || strings.Contains(text, "ocspuser") {
				t.Errorf("%s carries the credential: %q", what, text)
			}
		}
		if good.Verdict != Good || !strings.Contains(good.Name, "redacted") {
			t.Errorf("%+v, want good, its name redacted", good)
		}
	})

	t.Run("an in-validity delegate with the OCSP-signing usage", func(t *testing.T) {
		d, key := delegate(t, ca, true, t0.Add(-time.Hour), t0.Add(time.Hour))
		resp := newResponder(t, ca)
		resp.set(func(r *responder) { r.ans.signerCert, r.ans.signerKey, r.ans.embed = d, key, d })
		c, _ := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		if r := check(t, c, user, ca.Cert); r.Verdict != Good || r.Source != "ocsp" {
			t.Errorf("%+v, want good", r)
		}
	})

	// Some responders embed the issuing CA itself; it carries no
	// OCSP-signing usage and needs none (re-check R8).
	t.Run("the issuer's own certificate embedded", func(t *testing.T) {
		resp := newResponder(t, ca)
		resp.set(func(r *responder) { r.ans.embed = ca.Cert })
		c, _ := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		if r := check(t, c, user, ca.Cert); r.Verdict != Good {
			t.Errorf("%+v, want good", r)
		}
	})

	t.Run("an intermediate issuer's own certificate embedded", func(t *testing.T) {
		inter := subCA(t, ca, "issuing intermediate")
		resp := newResponder(t, inter)
		resp.set(func(r *responder) { r.ans.embed = inter.Cert })
		c, _ := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		if r := check(t, c, leaf(t, inter, 5), inter.Cert); r.Verdict != Good {
			t.Errorf("%+v, want good", r)
		}
	})

	t.Run("revoked, and on hold", func(t *testing.T) {
		resp := newResponder(t, ca)
		at := t0.Add(-time.Hour)
		resp.set(func(r *responder) { r.ans.status, r.ans.revokedAt = ocsp.Revoked, at })
		c, _ := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		r := check(t, c, user, ca.Cert)
		if r.Verdict != Revoked || r.Source != "ocsp" || !r.RevokedAt.Equal(at) || r.Hold {
			t.Errorf("%+v, want revoked at %s", r, at)
		}
		resp.set(func(r *responder) { r.ans.reason = ocsp.CertificateHold })
		if r := check(t, c, leaf(t, ca, 101), ca.Cert); r.Verdict != Revoked || !r.Hold {
			t.Errorf("%+v, want revoked with Hold", r)
		}
	})

	t.Run("a failure is cached 30s", func(t *testing.T) {
		resp := newResponder(t, ca)
		resp.set(func(r *responder) { r.status = http.StatusInternalServerError })
		c, clk := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		check(t, c, user, ca.Cert)
		clk.advance(29 * time.Second)
		if r := check(t, c, user, ca.Cert); r.Verdict != Unknown || resp.count() != 1 {
			t.Errorf("within 30s: %+v after %d calls, want unknown after 1", r, resp.count())
		}
		clk.advance(2 * time.Second)
		if check(t, c, user, ca.Cert); resp.count() != 2 {
			t.Errorf("calls after 30s = %d, want 2", resp.count())
		}
	})

	t.Run("twenty concurrent checks make one call", func(t *testing.T) {
		resp := newResponder(t, ca)
		gate := make(chan struct{})
		resp.set(func(r *responder) { r.gate = gate })
		c, _ := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		var wg sync.WaitGroup
		results := make([]Result, 20)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = c.Check(context.Background(), []*x509.Certificate{user, ca.Cert})
			}(i)
		}
		time.Sleep(200 * time.Millisecond) // every check is waiting on the one in flight
		close(gate)
		wg.Wait()
		if resp.count() != 1 {
			t.Errorf("calls = %d, want 1", resp.count())
		}
		for i, r := range results {
			if r.Verdict != Good {
				t.Errorf("check %d: %+v, want good", i, r)
			}
		}
	})

	t.Run("use_aia reads the certificate's OCSP server", func(t *testing.T) {
		resp := newResponder(t, ca)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		aia := sign(t, ca, &x509.Certificate{SerialNumber: big.NewInt(300), Subject: pkix.Name{CommonName: "aia user"},
			NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour), OCSPServer: []string{resp.URL}}, key)
		c, _ := ocspChecker(t, OCSPConfig{UseAIA: true})
		if r := check(t, c, aia, ca.Cert); r.Verdict != Good || r.Name != resp.URL || resp.count() != 1 {
			t.Errorf("%+v after %d calls, want good from %s", r, resp.count(), resp.URL)
		}
		if r := check(t, c, user, ca.Cert); r.Verdict != Unknown || !strings.Contains(r.Detail, "no responder") {
			t.Errorf("a certificate naming no responder: %+v, want unknown", r)
		}
	})

	t.Run("a non-http AIA responder is not asked", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		aia := sign(t, ca, &x509.Certificate{SerialNumber: big.NewInt(301), Subject: pkix.Name{CommonName: "aia user"},
			NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour), OCSPServer: []string{"file:///etc/passwd"}}, key)
		c, _ := ocspChecker(t, OCSPConfig{UseAIA: true})
		if r := check(t, c, aia, ca.Cert); r.Verdict != Unknown || !strings.Contains(r.Detail, "not http or https") {
			t.Errorf("%+v, want unknown", r)
		}
	})

	t.Run("the CertID hash", func(t *testing.T) {
		for _, tc := range []struct {
			cfg, want crypto.Hash
		}{{0, crypto.SHA256}, {crypto.SHA256, crypto.SHA256}, {crypto.SHA1, crypto.SHA1}} {
			resp := newResponder(t, ca)
			c, _ := ocspChecker(t, OCSPConfig{Responder: resp.URL, Hash: tc.cfg})
			if r := check(t, c, user, ca.Cert); r.Verdict != Good {
				t.Errorf("hash %v: %+v, want good", tc.cfg, r)
			}
			resp.mu.Lock()
			if len(resp.hashes) != 1 || resp.hashes[0] != tc.want {
				t.Errorf("hash %v: the request's CertID used %v, want %v", tc.cfg, resp.hashes, tc.want)
			}
			resp.mu.Unlock()
		}
	})

	t.Run("a fresh list covering the issuer means no OCSP call", func(t *testing.T) {
		resp := newResponder(t, ca)
		c, _, _ := newChecker(t, Config{CRLs: []CRLSource{{Name: "issuing",
			File: crlFile(t, signCRL(t, ca, crlSpec{number: 1})), Issuer: ca.Cert}},
			OCSP: &OCSPConfig{Responder: resp.URL, Timeout: time.Second}}, newClock())
		if errs := c.LoadAll(context.Background()); len(errs) != 0 {
			t.Fatal(errs)
		}
		if r := check(t, c, user, ca.Cert); r.Verdict != Good || r.Source != "crl" || resp.count() != 0 {
			t.Errorf("%+v after %d calls, want good from the list and no call", r, resp.count())
		}
	})

	t.Run("a stale list falls back to OCSP", func(t *testing.T) {
		resp := newResponder(t, ca)
		clk := newClock()
		c, _, _ := newChecker(t, Config{CRLs: []CRLSource{{Name: "issuing",
			File: crlFile(t, signCRL(t, ca, crlSpec{number: 1})), Issuer: ca.Cert}},
			OCSP: &OCSPConfig{Responder: resp.URL, Timeout: time.Second}, RefreshInterval: 10 * time.Minute}, clk)
		if errs := c.LoadAll(context.Background()); len(errs) != 0 {
			t.Fatal(errs)
		}
		clk.advance(2 * time.Hour)
		resp.set(func(r *responder) { r.ans.this, r.ans.next = clk.now(), clk.now().Add(time.Hour) })
		if r := check(t, c, user, ca.Cert); r.Verdict != Good || r.Source != "ocsp" {
			t.Errorf("%+v, want good from ocsp", r)
		}
		resp.set(func(r *responder) { r.status = http.StatusServiceUnavailable })
		r := check(t, c, leaf(t, ca, 102), ca.Cert)
		if r.Verdict != Unknown || !strings.Contains(r.Detail, "past its next update") || !strings.Contains(r.Detail, "OCSP") {
			t.Errorf("%+v, want unknown naming the stale list and the responder", r)
		}
	})

	// A responder's status line reaches a detail the broker logs and
	// answers with; it is made printable first (M16).
	t.Run("peer text is made printable", func(t *testing.T) {
		resp := newResponder(t, ca)
		resp.set(func(r *responder) {
			r.raw = "HTTP/1.1 500 Bad\x1b[2J\x07Thing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		})
		c, _ := ocspChecker(t, OCSPConfig{Responder: resp.URL})
		r := check(t, c, user, ca.Cert)
		if r.Verdict != Unknown || !strings.Contains(r.Detail, "500") {
			t.Fatalf("%+v, want unknown naming the 500", r)
		}
		for _, ch := range r.Detail {
			if ch < 0x20 || ch == 0x7f {
				t.Fatalf("detail %q carries a control character", r.Detail)
			}
		}
	})
}
