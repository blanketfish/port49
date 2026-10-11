package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

const bundleBroker = "https://broker.example:8443"

func testCA(t *testing.T) *testpki.CA {
	t.Helper()
	ca, err := testpki.NewCA("port49 test CA", time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// The agent keeps a bundle that holds the CA its connection was verified
// to, 0600, and says so by fingerprint, once; one that drops that CA, or is
// out of bounds, is refused and the kept file left as it was (decision 43
// ruling 25).
func TestKeepCABundle(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	cur, next, other := testCA(t), testCA(t), testCA(t)
	path, err := userconfig.CABundlePath(bundleBroker)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	keepCABundle(bundleBroker, string(cur.PEM())+string(next.PEM()), false, cur.Cert, &log)
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, append(cur.PEM(), next.PEM()...)) ||
		!strings.Contains(log.String(), "kept the broker's CA bundle in "+path) || !strings.Contains(log.String(), "(was none)") {
		t.Fatalf("%v %q", err, log.String())
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	// The same bundle again is no change, and no line.
	log.Reset()
	keepCABundle(bundleBroker, string(cur.PEM())+string(next.PEM()), false, cur.Cert, &log)
	if log.Len() != 0 {
		t.Fatalf("%q", log.String())
	}
	for name, c := range map[string]struct {
		bundle, want string
	}{
		"the CA in use dropped": {string(next.PEM()) + string(other.PEM()), "does not hold the CA this connection was verified to"},
		"five CAs":              {strings.Repeat(string(cur.PEM()), 5), "over 4 certificates"},
		"junk":                  {string(cur.PEM()) + "junk", "other than PEM"},
	} {
		log.Reset()
		keepCABundle(bundleBroker, c.bundle, false, cur.Cert, &log)
		if got, _ := os.ReadFile(path); !bytes.Equal(got, raw) || !strings.Contains(log.String(), c.want) ||
			!strings.Contains(log.String(), "is left as it was") {
			t.Errorf("%s: %q", name, log.String())
		}
	}
	// The rotation's end: the old CA leaves the bundle once the server's
	// certificate is the next CA's, and the change is said.
	log.Reset()
	keepCABundle(bundleBroker, string(next.PEM()), false, next.Cert, &log)
	if !strings.Contains(log.String(), "(was "+api.CAFingerprints([]*x509.Certificate{cur.Cert, next.Cert})+")") {
		t.Fatalf("%q", log.String())
	}
}

// A broker that sends no bundle, on a verified connection, clears what the
// agent kept: a kept bundle holding a CA beside the one verified to (one a
// broker key held briefly by another could have planted) is cut to that CA,
// and one that does not hold it is removed, each said; with nothing kept
// nothing is said (decision 43 ruling 25).
func TestABrokerWithNoBundleClearsTheKeptOne(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	cur, planted, other := testCA(t), testCA(t), testCA(t)
	path, err := userconfig.CABundlePath(bundleBroker)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	keepCABundle(bundleBroker, "", false, cur.Cert, &log)
	if _, err := os.Stat(path); !os.IsNotExist(err) || log.Len() != 0 {
		t.Fatalf("nothing kept: %v %q", err, log.String())
	}
	keepCABundle(bundleBroker, string(cur.PEM())+string(planted.PEM()), false, cur.Cert, &bytes.Buffer{})
	log.Reset()
	keepCABundle(bundleBroker, "", false, cur.Cert, &log)
	if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, cur.PEM()) ||
		!strings.Contains(log.String(), "now holds only the CA this connection was verified to") {
		t.Fatalf("the CA verified to, kept alone: %v %q", err, log.String())
	}
	// A broker that refused its own bundle at start leaves the kept file as it
	// was: a typo in tls_ca_bundle_file mid-rotation drops no CA a client holds.
	log.Reset()
	keepCABundle(bundleBroker, "", true, cur.Cert, &log)
	if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, cur.PEM()) ||
		!strings.Contains(log.String(), "refused its own tls_ca_bundle_file") ||
		!strings.Contains(log.String(), path+" is left as it was") {
		t.Fatalf("a refused bundle: %v %q", err, log.String())
	}
	keepCABundle(bundleBroker, string(other.PEM())+string(planted.PEM()), false, other.Cert, &bytes.Buffer{})
	log.Reset()
	keepCABundle(bundleBroker, "", false, cur.Cert, &log)
	if _, err := os.Stat(path); !os.IsNotExist(err) || !strings.Contains(log.String(), "removed "+path) {
		t.Fatalf("a bundle the connection did not need: %v %q", err, log.String())
	}
}

// A login trusts its broker_ca and the bundle the agent kept for that
// broker, and no other broker's; a kept file that cannot be used is refused
// naming it.
func TestALoginTrustsTheKeptBundleBesideItsCA(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	cur, next := testCA(t), testCA(t)
	keepCABundle(bundleBroker, string(next.PEM()), false, next.Cert, &bytes.Buffer{})
	caFile := filepath.Join(privateDir(t), "ca.pem")
	if err := os.WriteFile(caFile, cur.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := next.Issue(testpki.Leaf{CommonName: "broker", DNSNames: []string{"broker.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(srv.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for broker, verifies := range map[string]bool{bundleBroker: true, "https://other.example:8443": false} {
		sf := sessionFlags{broker: broker, brokerCA: caFile}
		pool, err := sf.brokerPool()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "broker.example"}); (err == nil) != verifies {
			t.Errorf("%s: %v", broker, err)
		}
	}
	path, _ := userconfig.CABundlePath(bundleBroker)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	sf := sessionFlags{broker: bundleBroker, brokerCA: caFile}
	if _, err := sf.brokerPool(); err == nil || !strings.Contains(err.Error(), path+", the broker's CA bundle the agent kept") {
		t.Fatalf("%v", err)
	}
}

// A kept file the agent cannot read is replaced by the broker's bundle and
// the line says so, not "was none"; with no bundle sent it is left as it was,
// said with why (decision 43 ruling 25).
func TestAnUnreadableKeptBundle(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	cur := testCA(t)
	path, err := userconfig.CABundlePath(bundleBroker)
	if err != nil {
		t.Fatal(err)
	}
	if err := userconfig.WritePrivate(path, []byte("not a bundle"), "broker CA bundle"); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	keepCABundle(bundleBroker, "", false, cur.Cert, &log)
	if got, _ := os.ReadFile(path); string(got) != "not a bundle" ||
		!strings.Contains(log.String(), path+" is left as it was") {
		t.Fatalf("no bundle sent: %q", log.String())
	}
	log.Reset()
	keepCABundle(bundleBroker, string(cur.PEM()), false, cur.Cert, &log)
	if got, _ := os.ReadFile(path); !bytes.Equal(got, cur.PEM()) ||
		!strings.Contains(log.String(), "(was unreadable; replaced)") || strings.Contains(log.String(), "was none") {
		t.Fatalf("a bundle sent: %q", log.String())
	}
}

// The /v1/config fetch of a login says the rotation's fix for a certificate
// no CA this host trusts issued, as the agent does, and only for that.
func TestTheConfigFetchSaysTheRotationFix(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	l := newLabBroker(t, time.Hour)
	pool := x509.NewCertPool()
	pool.AddCert(testCA(t).Cert)
	_, err := fetchBrokerConfig(context.Background(), l.url, pool)
	if err == nil || !strings.Contains(err.Error(), "does not verify") ||
		!strings.Contains(err.Error(), "; "+agent.RotatedCAHint) {
		t.Fatalf("%v", err)
	}
	// M2: "keeps it current" is said only where port49 has kept a bundle for
	// this broker, so the broker is known to send one.
	if strings.Contains(err.Error(), "keeps it current") ||
		!strings.Contains(err.Error(), "ask for /etc/port49/broker-ca.pem to be updated") {
		t.Fatalf("a promise with no bundle kept: %v", err)
	}
	path, perr := userconfig.CABundlePath(l.url)
	if perr != nil {
		t.Fatal(perr)
	}
	if werr := userconfig.WritePrivate(path, testCA(t).PEM(), "broker CA bundle"); werr != nil {
		t.Fatal(werr)
	}
	_, err = fetchBrokerConfig(context.Background(), l.url, pool)
	if err == nil || !strings.Contains(err.Error(), "; "+agent.RotatedCAHintKept) ||
		strings.Contains(err.Error(), "/etc/port49/broker-ca.pem") {
		t.Fatalf("with a bundle kept: %v", err)
	}
}
