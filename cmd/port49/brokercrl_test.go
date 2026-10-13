package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/brokercrl"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

// parsed is the session flags of args, filled from the config files as login
// and the agent do.
func parsed(t *testing.T, args ...string) *sessionFlags {
	t.Helper()
	var sf sessionFlags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var sink bytes.Buffer
	fs.SetOutput(&sink)
	sf.register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err, sink.String())
	}
	if err := sf.fill(fs); err != nil {
		t.Fatal(err)
	}
	return &sf
}

// broker_crl is a config key and --broker-crl its flag; the flag wins, and a
// command line that names the rest does not skip the file's require. The
// agent login starts is handed the value explicitly.
func TestBrokerCRLComesFromTheFileAndTheFlagWins(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	t.Setenv(userconfig.EnvConfig, "")
	dir := filepath.Join(home, ".port49")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := labConfig(t, dir, configBroker)
	body, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(body, "broker_crl: require\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := parsed(t).brokerCRL; got != "require" {
		t.Fatalf("from the default file: %q, want require", got)
	}
	if got := parsed(t, "--broker-crl", "off").brokerCRL; got != "off" {
		t.Fatalf("with --broker-crl off: %q", got)
	}
	// All four of the flags that used to make the file unnecessary.
	four := []string{"--broker", configBroker, "--cert", filepath.Join(dir, testpki.LabClientCert),
		"--key", filepath.Join(dir, testpki.LabClientKey), "--broker-ca", filepath.Join(dir, testpki.LabCA)}
	sf := parsed(t, four...)
	if sf.brokerCRL != "require" {
		t.Fatalf("four flags and no --broker-crl: %q, want the file's require", sf.brokerCRL)
	}
	if args := sf.args(); !slices.Contains(args, "--broker-crl") || args[slices.Index(args, "--broker-crl")+1] != "require" {
		t.Fatalf("the agent is handed %v, want --broker-crl require", args)
	}
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	sf = parsed(t, four...)
	if args := sf.args(); args[slices.Index(args, "--broker-crl")+1] != "check" {
		t.Fatalf("with nothing said the agent is handed %v, want --broker-crl check", args)
	}
}

func TestBrokerCRLRefusesAWordItDoesNotKnow(t *testing.T) {
	sf := parsed(t, "--broker-crl", "strict")
	if _, err := sf.verifyBroker(&bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "check, require or off") {
		t.Fatalf("verifyBroker(strict) = %v", err)
	}
	dir := privateDir(t)
	cfg := labConfig(t, dir, configBroker)
	body, _ := os.ReadFile(cfg)
	if err := os.WriteFile(cfg, append(body, "broker_crl: strict\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	var sf2 sessionFlags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	sf2.register(fs)
	if err := fs.Parse([]string{"--config", cfg}); err != nil {
		t.Fatal(err)
	}
	if err := sf2.fill(fs); err == nil || !strings.Contains(err.Error(), "broker_crl") {
		t.Fatalf("a config file with broker_crl: strict: %v", err)
	}
	if v, err := brokerVerifier("off", func(string) {}); v != nil || err != nil {
		t.Fatalf("off gave a check (%v) or an error (%v); want neither", v != nil, err)
	}
	if v, err := brokerVerifier("", func(string) {}); v == nil || err != nil {
		t.Fatalf("the default gave no check or an error (%v); want a check", err)
	}
}

// A broker certificate the CRL check refused is said as that, and is not
// "the broker did not answer": login treats a silent broker as an outage and
// goes on with a held certificate. Neither request was written: the handler
// never ran, bearer token and all.
func TestARevokedBrokerIsNotABrokerThatIsDown(t *testing.T) {
	ca := testCA(t)
	now := time.Now()
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: testpki.Loopback(),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var reached atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	refuse := func(tls.ConnectionState) error {
		return &brokercrl.RevokedError{Subject: "CN=broker", Serial: "1f", List: "the CRL at http://pki.example/ca.crl"}
	}
	var revoked *brokercrl.RevokedError
	var down *brokerDownError
	_, err = fetchBrokerConfig(context.Background(), srv.URL, pool, refuse)
	if !errors.As(err, &revoked) || errors.As(err, &down) {
		t.Fatalf("fetchBrokerConfig = %v (%T), want the revocation, not a broker that is down", err, err)
	}
	_, err = requestCertificate(context.Background(), srv.URL, pool, "an-id-token", []byte("csr"), refuse)
	if !errors.As(err, &revoked) || errors.As(err, &down) {
		t.Fatalf("requestCertificate = %v (%T), want the revocation, not a broker that is down", err, err)
	}
	unchecked := func(tls.ConnectionState) error { return &brokercrl.UncheckedError{Detail: "no list"} }
	_, err = fetchBrokerConfig(context.Background(), srv.URL, pool, unchecked)
	var ue *brokercrl.UncheckedError
	if !errors.As(err, &ue) || errors.As(err, &down) {
		t.Fatalf("under require with no list: %v (%T)", err, err)
	}
	if reached.Load() != 0 {
		t.Fatalf("the broker's handler ran %d times", reached.Load())
	}
}

// A 307 from anything answering under the broker CA (a front proxy's rule) is
// not followed: the certificate request's ID token and body, and the config
// fetch, go to the broker named and nowhere else (final review client I4).
func TestTheBrokerClientsFollowNoRedirect(t *testing.T) {
	ca := testCA(t)
	now := time.Now()
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: testpki.Loopback(),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var landed atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landed" {
			landed.Add(1)
			return
		}
		w.Header().Set("Location", "/landed")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = fetchBrokerConfig(context.Background(), srv.URL, pool, nil)
	if err == nil || !strings.Contains(err.Error(), "never follows a redirect") || landed.Load() != 0 {
		t.Fatalf("fetchBrokerConfig = %v, %d request(s) at /landed: want the 307 said and not followed", err, landed.Load())
	}
	_, err = requestCertificate(context.Background(), srv.URL, pool, "an-id-token", []byte("csr"), nil)
	if err == nil || !strings.Contains(err.Error(), "never follows a redirect") || landed.Load() != 0 {
		t.Fatalf("requestCertificate = %v, %d request(s) at /landed: want the 307 said and not followed", err, landed.Load())
	}
}

// With ~/.port49/crl unmakeable, "the CRLs cannot be kept" is said only when
// the check had no answer and needed a kept list: not on every run that
// merely fetched a fine list. Under require it rides on the refusal.
func TestTheCRLsCannotBeKeptIsSaidOnlyWhenItMatters(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.WriteFile(home, []byte("a file, not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	ca := testCA(t)
	now := time.Now()
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	var serveGood atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveGood.Load() {
			w.Write(crl)
			return
		}
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), CRLDistributionPoints: []string{srv.URL + "/ca.crl"}})
	if err != nil {
		t.Fatal(err)
	}
	cs := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf.Leaf, ca.Cert}}}
	run := func(mode string, good bool) ([]string, error) {
		serveGood.Store(good)
		var said []string
		v, err := brokerVerifier(mode, func(m string) { said = append(said, m) })
		if err != nil {
			t.Fatal(err)
		}
		err = v(cs)
		_ = v(cs)
		return said, err
	}
	if said, err := run("check", true); err != nil || len(said) != 0 {
		t.Fatalf("a fine list with nowhere to keep it: %v, said %q; want neither", err, said)
	}
	said, err := run("check", false)
	if err != nil || len(said) != 1 || !strings.Contains(said[0], "could not check") || !strings.Contains(said[0], "cannot be kept") {
		t.Fatalf("no list under check: %v, said %q; want one warning that also says the CRLs cannot be kept", err, said)
	}
	said, err = run("require", false)
	if err == nil || len(said) != 0 || !strings.Contains(err.Error(), "cannot be kept") {
		t.Fatalf("no list under require: %v, said %q; want a refusal that says the CRLs cannot be kept", err, said)
	}
}
