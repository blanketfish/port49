package inventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

// clientFiles writes a certificate for l and the CA to files, as a deployment
// holds them.
func (rig *apiRig) clientFiles(t *testing.T, l testpki.Leaf) (ca, cert, key string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { // the secret-file rule refuses a group-writable directory
		t.Fatal(err)
	}
	l.Client, l.NotBefore, l.NotAfter = true, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	c, err := rig.ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := testpki.PEMs(c)
	ca, cert, key = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	writeFile(t, ca, rig.ca.PEM(), 0o644)
	writeFile(t, cert, certPEM, 0o644)
	writeFile(t, key, keyPEM, 0o600)
	return ca, cert, key
}

// writeFile writes body to path, failing the test if it cannot.
func writeFile(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

// fake is a TLS server the rig's CA vouches for, as a certificate for ips,
// answering with h: a service that misbehaves.
func (rig *apiRig) fake(t *testing.T, ips []net.IP, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	cert, err := rig.ca.Issue(testpki.Leaf{CommonName: "fake", IPs: ips, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestTheClientReadsAndSyncs(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}})
	c, err := NewClient(rig.srv.URL, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Version(ctx); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("before: %v", err)
	}
	res, err := c.Sync(ctx)
	if err != nil || res.Outcome != "published" {
		t.Fatalf("%+v %v", res, err)
	}
	v, err := c.Version(ctx)
	if err != nil || v.Sequence != 1 {
		t.Fatalf("%+v %v", v, err)
	}
	raw, etag, nm, err := c.Bundle(ctx, "")
	if err != nil || nm || etag != v.ETag || len(raw) == 0 {
		t.Fatalf("%v %v %v", etag, nm, err)
	}
	if _, _, nm, err := c.Bundle(ctx, etag); err != nil || !nm {
		t.Fatalf("If-None-Match: %v %v", nm, err)
	}
	d, err := c.Diff(ctx, 1)
	if err != nil || d.From != 1 || d.To != 1 {
		t.Fatalf("diff: %+v %v", d, err)
	}
	if _, err := c.Diff(ctx, 7); err == nil || !strings.Contains(err.Error(), "404 (not_kept)") {
		t.Fatalf("diff from a bundle not kept: %v", err)
	}
}

// Pre-flight minor 6: the CA file is read at each handshake. Another CA in the
// file fails the next connection; the right one back, the next succeeds —
// with the same client, no restart.
func TestTheClientReadsTheCAFileAtEachHandshake(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "d", URIs: []*url.URL{uri("spiffe://port49.test/port49d")}})
	c, err := NewClient(rig.srv.URL, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(ca)
	other, _ := testpki.NewCA("another", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	writeFile(t, ca, other.PEM(), 0o644)
	if _, err := c.Version(context.Background()); err == nil || errors.Is(err, ErrNoBundle) {
		t.Fatalf("a service the CA file does not vouch for was answered: %v", err)
	}
	writeFile(t, ca, good, 0o644)
	c.http.CloseIdleConnections()
	if _, err := c.Version(context.Background()); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("the CA put back: %v", err)
	}
	// An emptied CA file is no roots at all, never the system's.
	writeFile(t, ca, nil, 0o644)
	c.http.CloseIdleConnections()
	if _, err := c.Version(context.Background()); err == nil || errors.Is(err, ErrNoBundle) {
		t.Fatalf("an empty CA file was trusted: %v", err)
	}
}

// The service authenticates by certificate: a URL carrying a password is
// refused before anything is dialled, and not echoed.
func TestAURLWithCredentialsOrPlainHTTPIsRefused(t *testing.T) {
	for _, u := range []string{"https://ops:SECRET@inv.example:8443", "http://inv.example:8443",
		"https://inv.example:8443/?SECRET", "https://inv.example:8443/#SECRET"} {
		_, err := NewClient(u, "ca", "c", "k")
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// A missing or empty CA file is refused at the start, never a fall back to
// the host's roots.
func TestAClientWithoutACAFileIsRefused(t *testing.T) {
	rig := newAPIRig(t)
	_, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}})
	empty := filepath.Join(t.TempDir(), "empty.pem")
	writeFile(t, empty, nil, 0o644)
	for _, ca := range []string{"", filepath.Join(t.TempDir(), "missing.pem"), empty} {
		if _, err := NewClient(rig.srv.URL, ca, cert, key); err == nil {
			t.Errorf("ca_file %q: accepted", ca)
		}
	}
}

// The service is named by the URL: a certificate from the same CA for
// another address is not the service.
func TestTheClientChecksTheServicesName(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}})
	srv := rig.fake(t, []net.IP{net.ParseIP("127.0.0.2")}, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"sequence": 9}`))
	})
	c, err := NewClient(srv.URL, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := c.Version(context.Background()); err == nil {
		t.Fatalf("a certificate for another address was taken: %+v", v)
	}
}

// A redirect is an error, not followed: the client asks the service it was
// given and nothing else.
func TestTheClientFollowsNoRedirect(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}})
	followed := false
	target := rig.fake(t, testpki.Loopback(), func(w http.ResponseWriter, _ *http.Request) {
		followed = true
		w.Write([]byte(`{"sequence": 9}`))
	})
	srv := rig.fake(t, testpki.Loopback(), func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/bundle/version", http.StatusFound)
	})
	c, err := NewClient(srv.URL, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Version(context.Background()); err == nil || followed || !strings.Contains(err.Error(), "302") {
		t.Fatalf("followed %v: %v", followed, err)
	}
	if _, _, _, err := c.Bundle(context.Background(), ""); err == nil || followed {
		t.Fatalf("bundle: followed %v: %v", followed, err)
	}
}

// A service's error text is not the client's to print raw: control
// characters and a long body never reach the error.
func TestAServiceErrorIsNotEchoed(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}})
	for _, body := range []string{`{"error": "\u001b[31mEVIL"}`, `{"error": "` + strings.Repeat("A", 1<<20) + `"}`,
		"EVIL\n\x1b[2J" + strings.Repeat("B", 5000)} {
		srv := rig.fake(t, testpki.Loopback(), func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(body))
		})
		c, err := NewClient(srv.URL, ca, cert, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Version(context.Background())
		if err == nil || strings.Contains(err.Error(), "EVIL") || strings.ContainsAny(err.Error(), "\x1b\n") ||
			len(err.Error()) > 512 || !strings.Contains(err.Error(), "500") {
			t.Fatalf("%.80q", err)
		}
	}
}

// Whoever answers the service's address chooses the certificate it presents,
// and crypto/tls names its DNS names in the error: they reach neither the
// terminal nor port49d's log raw.
func TestACertificatesNamesAreNotEchoedRaw(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}})
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"evil\x1b[2Jcleared\nforged"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// By name, so the mismatch error lists the certificate's DNS names.
	c, err := NewClient(strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Version(context.Background())
	if err == nil || !errors.Is(err, ErrNoConnection) || !strings.Contains(err.Error(), "evil") ||
		strings.ContainsAny(err.Error(), "\x1b\n") {
		t.Fatalf("%q", err)
	}
}

// A service that accepts and never finishes the handshake costs dialTimeout,
// and is no connection: the ask was never sent.
func TestAHandshakeThatNeverEndsIsNoConnection(t *testing.T) {
	rig := newAPIRig(t)
	ca, cert, key := rig.clientFiles(t, testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	defer func(d time.Duration) { dialTimeout = d }(dialTimeout)
	dialTimeout = 200 * time.Millisecond
	c, err := NewClient("https://"+ln.Addr().String(), ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sync(context.Background()); !errors.Is(err, ErrNoConnection) {
		t.Fatalf("%v", err)
	}
}
