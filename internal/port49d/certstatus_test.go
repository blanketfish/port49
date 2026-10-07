package port49d

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/testpki"
)

// certStatusYAML is cs as writeRunConfig's broker.certificate_status block,
// indented under it; nil writes the key with no value, which Load refuses.
func certStatusYAML(t *testing.T, cs *config.CertificateStatusConfig) string {
	t.Helper()
	if cs == nil {
		return ""
	}
	if cs.Disabled {
		return "    disabled: true\n" // alone: Load refuses it beside any other key
	}
	raw, err := yaml.Marshal(cs)
	if err != nil {
		t.Fatal(err)
	}
	return regexp.MustCompile(`(?m)^`).ReplaceAllString(strings.TrimRight(string(raw), "\n"), "    ") + "\n"
}

// aliceSerial is the lab client certificate's serial.
var aliceSerial = big.NewInt(0xa11ce)

// statusPKI replaces the lab PKI beside b's client_ca_file with one whose CA
// key the test holds, so it can sign CRLs, and returns that CA. The client
// certificate's serial is aliceSerial.
func statusPKI(t *testing.T, b *config.BrokerConfig) *testpki.CA {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("port49 status test CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	writeLeaves(t, filepath.Dir(b.ClientCAFile), ca, ca.PEM())
	return ca
}

// writeLeaves writes a server and an alice client certificate ca issued into
// dir under the lab names, with anchorPEM as the client CA file. The client
// file carries ca's certificate too when ca is not the anchor, so the chain
// verifies.
func writeLeaves(t *testing.T, dir string, ca *testpki.CA, anchorPEM []byte) {
	t.Helper()
	now := time.Now()
	srv, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ca.Issue(testpki.Leaf{CommonName: "alice@example.com", Emails: []string{"alice@example.com"},
		Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), Serial: aliceSerial})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{testpki.LabCA: anchorPEM}
	sc, sk, err := testpki.PEMs(srv)
	if err != nil {
		t.Fatal(err)
	}
	cc, ck, err := testpki.PEMs(cli)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(anchorPEM), string(ca.PEM())) {
		cc = append(cc, ca.PEM()...)
	}
	files[testpki.LabServerCert], files[testpki.LabServerKey] = sc, sk
	files[testpki.LabClientCert], files[testpki.LabClientKey] = cc, ck
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// intermediate is a CA root signed.
func intermediate(t *testing.T, root *testpki.CA, cn string) *testpki.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, &key.PublicKey, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testpki.CA{Cert: cert, Key: key}
}

// crl is a list ca signs, naming serials, current from thisUpdate to
// nextUpdate.
func crl(t *testing.T, ca *testpki.CA, thisUpdate, nextUpdate time.Time, serials ...*big.Int) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: thisUpdate.Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(thisUpdate.Unix()),
		ThisUpdate: thisUpdate, NextUpdate: nextUpdate, RevokedCertificateEntries: entries}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// writeFile writes body to a new file in dir and returns its path.
func writeFile(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// captureStderr points stderr at a buffer for the test, and stdout at
// nothing.
func captureStderr(t *testing.T) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = out, io.Discard
	return out
}

// startDaemon runs port49d on cfgPath until stop, which waits for run to
// return, and returns the broker's address once it listens.
func startDaemon(t *testing.T, cfgPath string, out *syncBuffer) (addr string, stop func()) {
	t.Helper()
	n := strings.Count(out.String(), "port49d: broker listening on ")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	stop = func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not return")
		}
	}
	waitForCount(t, out, "port49d: broker listening on ", n+1)
	all := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindAllStringSubmatch(out.String(), -1)
	return all[len(all)-1][1], stop
}

// mintUntil asks for alice's token until the answer is not a 503, the
// status before the first list loads, and returns it.
func mintUntil(t *testing.T, pki, addr string) (int, string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, body, err := postAsAlice(pki, addr)
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusServiceUnavailable || time.Now().After(deadline) {
			return status, body
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// An issuer_file is the anchor or one it signed, one CA certificate, and
// nothing else; each refusal names the source (pre-flight C1).
func TestCertStatusConfigChecksEachIssuerFile(t *testing.T) {
	now := time.Now()
	anchor, err := testpki.NewCA("anchor", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	other, err := testpki.NewCA("another CA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inter := intermediate(t, anchor, "anchor's intermediate")
	leaf, err := anchor.Issue(testpki.Leaf{CommonName: "a leaf", Client: true, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, keyPEM, err := testpki.PEMs(leaf)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pemOf := func(c *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	cfg := func(issuer string) config.CertificateStatusConfig {
		return config.CertificateStatusConfig{RefreshInterval: time.Minute, OnUnavailable: "refuse",
			CRLs: []config.CertificateStatusCRL{{Name: "ok", File: "/x.crl", IssuerFile: writeFile(t, dir, "anchor.pem",
				anchor.PEM())}, {Name: "corp", URL: "http://pki.example.com/c.crl", IssuerFile: issuer}}}
	}
	for name, c := range map[string]struct {
		body []byte
		want string
	}{
		"another CA's":     {other.PEM(), "is neither a trust anchor's certificate nor signed by one"},
		"a leaf":           {leafPEM, "is not a CA certificate"},
		"two certificates": {append(inter.PEM(), anchor.PEM()...), "holds 2 PEM blocks"},
		"a key":            {keyPEM, "holds a PRIVATE KEY PEM block"},
		"no PEM":           {[]byte("not a certificate"), "holds 0 PEM blocks"},
	} {
		_, err := certStatusConfig(cfg(writeFile(t, dir, "issuer.pem", c.body)), []*x509.Certificate{anchor.Cert}, dir)
		if err == nil || !strings.Contains(err.Error(), "crls[1].issuer_file "+filepath.Join(dir, "issuer.pem")) ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && name == "a key" && strings.Contains(err.Error(), string(keyPEM[40:60])) {
			t.Errorf("the refusal repeats the file: %v", err)
		}
	}
	if _, err := certStatusConfig(cfg(filepath.Join(dir, "missing.pem")), []*x509.Certificate{anchor.Cert}, dir); err == nil ||
		!strings.Contains(err.Error(), "crls[1].issuer_file") {
		t.Errorf("a missing file: %v", err)
	}

	c := cfg(writeFile(t, dir, "issuer.pem", pemOf(inter.Cert)))
	c.OCSP = &config.CertificateStatusOCSP{UseAIA: true, Timeout: time.Second, Hash: "sha1"}
	got, err := certStatusConfig(c, []*x509.Certificate{anchor.Cert}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CRLs) != 2 || !got.CRLs[1].Issuer.Equal(inter.Cert) || got.CRLs[1].URL != "http://pki.example.com/c.crl" ||
		!got.CRLs[0].Issuer.Equal(anchor.Cert) || got.CRLs[0].File != "/x.crl" || got.StateDir != dir ||
		got.RefreshInterval != time.Minute || got.OCSP == nil || !got.OCSP.UseAIA || got.OCSP.Timeout != time.Second ||
		got.OCSP.Hash.String() != "SHA-1" {
		t.Fatalf("certstatus.Config: %+v %+v", got, got.OCSP)
	}
	c.OCSP.Hash = "sha256"
	if got, err := certStatusConfig(c, []*x509.Certificate{anchor.Cert}, dir); err != nil || got.OCSP.Hash.String() != "SHA-256" {
		t.Fatalf("sha256: %+v %v", got.OCSP, err)
	}
}

// broker.certificate_status: {disabled: true} is said at every start.
func TestRunSaysCertificateStatusIsDisabled(t *testing.T) {
	out := captureStderr(t)
	_, stop := startDaemon(t, writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker), out)
	stop()
	if !strings.Contains(out.String(), "port49d: broker: certificate status checking is disabled "+
		"(broker.certificate_status.disabled)") {
		t.Fatalf("stderr: %q", out.String())
	}
}

// A CRL file naming alice refuses her at bind; the list is kept, and the
// next start names it with its next update before anything is fetched.
func TestRunChecksAFileCRL(t *testing.T) {
	out := captureStderr(t)
	b := brokerConfig(t, minimalPolicy).Broker
	ca := statusPKI(t, b)
	pki := filepath.Dir(b.ClientCAFile)
	now := time.Now().UTC().Truncate(time.Second)
	next := now.Add(2 * time.Hour)
	b.CertificateStatus = &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "lab_ca",
		File:       writeFile(t, t.TempDir(), "lab.crl", crl(t, ca, now.Add(-time.Minute), next, aliceSerial)),
		IssuerFile: b.ClientCAFile}}}
	cfgPath := writeRunConfig(t, b)

	addr, stop := startDaemon(t, cfgPath, out)
	waitFor(t, out, "port49d: broker: certificate status from CRL lab_ca (not loaded yet); a status that cannot "+
		"be established is refused (503, retried)")
	if status, body := mintUntil(t, pki, addr); status != http.StatusUnauthorized ||
		!strings.Contains(body, `"credential_revoked"`) || !strings.Contains(body, "at its CA (crl lab_ca") {
		t.Fatalf("alice on the CRL: %s", reply(status, body))
	}
	stop()
	if _, err := os.Stat(filepath.Join(filepath.Dir(b.RevocationsFile), "crl-lab_ca.der")); err != nil {
		t.Fatalf("the list was not kept: %v", err)
	}

	addr, stop = startDaemon(t, cfgPath, out)
	defer stop()
	waitFor(t, out, "port49d: broker: certificate status from CRL lab_ca (next update "+
		next.Format(time.RFC3339)+")")
	if status, body, err := postAsAlice(pki, addr); err != nil || status != http.StatusUnauthorized ||
		!strings.Contains(body, `"credential_revoked"`) {
		t.Fatalf("alice after a restart: %s %v", reply(status, body), err)
	}
}

// A list past its next update establishes nothing: under refuse, the mint
// is answered 503 certificate_status_unavailable, retried in 60s, which ends
// no session (pre-flight I7).
func TestRunRefusesOnAStaleCRL(t *testing.T) {
	out := captureStderr(t)
	b := brokerConfig(t, minimalPolicy).Broker
	ca := statusPKI(t, b)
	now := time.Now()
	b.CertificateStatus = &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "lab_ca",
		File:       writeFile(t, t.TempDir(), "lab.crl", crl(t, ca, now.Add(-2*time.Hour), now.Add(-time.Hour))),
		IssuerFile: b.ClientCAFile}}, OnUnavailable: "refuse"}
	addr, stop := startDaemon(t, writeRunConfig(t, b), out)
	defer stop()
	waitUntil(t, "the stale list loads", func() bool {
		_, err := os.Stat(filepath.Join(filepath.Dir(b.RevocationsFile), "crl-lab_ca.der"))
		return err == nil
	})
	resp, body := mintResponse(t, filepath.Dir(b.ClientCAFile), addr)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "60" ||
		!strings.Contains(body, `"certificate_status_unavailable"`) || !strings.Contains(body, "past its next update") {
		t.Fatalf("a stale list: %s %q", reply(resp.StatusCode, body), resp.Header.Get("Retry-After"))
	}
}

// mintResponse is postAsAlice's answer with its headers.
func mintResponse(t *testing.T, pki, addr string) (*http.Response, string) {
	t.Helper()
	resp, body, err := postAsAliceResponse(pki, addr)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

// A URL that hangs never holds up device AAA: the TACACS+ listening line
// is said while the first fetch waits (pre-flight I8). A later start, with
// the URL down, serves from the kept list.
func TestRunFetchesAfterListeningAndKeepsTheList(t *testing.T) {
	out := captureStderr(t)
	b := brokerConfig(t, minimalPolicy).Broker
	ca := statusPKI(t, b)
	pki := filepath.Dir(b.ClientCAFile)
	now := time.Now()
	list := crl(t, ca, now.Add(-time.Minute), now.Add(time.Hour), aliceSerial)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var serve atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !serve.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		_, _ = w.Write(list)
	}))
	t.Cleanup(srv.Close)
	b.CertificateStatus = &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "lab_ca",
		URL: srv.URL + "/lab.crl", IssuerFile: b.ClientCAFile}}}
	cfgPath := writeRunConfig(t, b)

	_, stop := startDaemon(t, cfgPath, out)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the CRL was never fetched")
	}
	if !strings.Contains(out.String(), "port49d: listening on ") {
		t.Fatalf("the first fetch is waiting and TACACS+ is not listening: %q", out.String())
	}
	stop() // the hung fetch is cancelled, and run returns
	close(release)

	serve.Store(true)
	addr, stop := startDaemon(t, cfgPath, out)
	if status, body := mintUntil(t, pki, addr); status != http.StatusUnauthorized ||
		!strings.Contains(body, "at its CA (crl lab_ca") {
		t.Fatalf("alice on the fetched CRL: %s", reply(status, body))
	}
	// The first list in force is said (Task 11 review I1).
	const loaded = "port49d: broker: certificate status: CRL lab_ca loaded (next update "
	waitFor(t, out, loaded)
	stop()

	srv.Close()
	addr, stop = startDaemon(t, cfgPath, out)
	defer stop()
	if status, body, err := postAsAlice(pki, addr); err != nil || status != http.StatusUnauthorized ||
		!strings.Contains(body, "at its CA (crl lab_ca") {
		t.Fatalf("alice with the URL down: %s %v", reply(status, body), err)
	}
	if n := strings.Count(out.String(), loaded); n != 1 {
		t.Fatalf("the kept list, or the URL down, was said as loaded: %d lines", n)
	}
}

// A list that newly names a certificate in use revokes it: under
// on_unavailable: allow, alice mints while the URL hangs, and once it
// answers with her serial her mark is in revocations_file. That is the
// CRL's path to her token and live contexts (spec §5.1.4; pre-flight I9):
// the new-entry callback, the queue, and revokeIfPresent (Task 11 review
// I2).
func TestRunRevokesACertificateANewListNames(t *testing.T) {
	out := captureStderr(t)
	b := brokerConfig(t, minimalPolicy).Broker
	ca := statusPKI(t, b)
	pki := filepath.Dir(b.ClientCAFile)
	now := time.Now()
	list := crl(t, ca, now.Add(-time.Minute), now.Add(time.Hour), aliceSerial)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
			_, _ = w.Write(list)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	b.CertificateStatus = &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "lab_ca",
		URL: srv.URL + "/lab.crl", IssuerFile: b.ClientCAFile}}, OnUnavailable: "allow"}
	addr, stop := startDaemon(t, writeRunConfig(t, b), out)
	defer stop()
	if status, body, err := postAsAlice(pki, addr); err != nil || status != http.StatusOK {
		t.Fatalf("alice with no list in force, under allow: %s %v", reply(status, body), err)
	}
	close(release)
	waitUntil(t, "alice's mark in revocations_file", fileHolds(b.RevocationsFile, `"kind": "cert"`))
	raw, err := os.ReadFile(b.RevocationsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), aliceSerial.Text(16)) || !strings.Contains(string(raw), `"origin": "crl lab_ca"`) {
		t.Fatalf("revocations_file: %s", raw)
	}
}

// An intermediate's own status needs its issuer's list or OCSP: a start
// with neither says so once, and still starts (re-check R3).
func TestRunSaysAnIntermediateNothingCovers(t *testing.T) {
	now := time.Now()
	const tail = ": nothing covers CN=status intermediate itself; name the root CA's CRL"
	const refuse = "port49d: broker: certificate status: certificates issued by CN=status intermediate will be " +
		"refused (503, retried)" + tail
	const allow = "port49d: broker: certificate status: certificates issued by CN=status intermediate will be " +
		"admitted with their revocation status unchecked (on_unavailable: allow)" + tail
	for name, c := range map[string]struct {
		root, ocsp, allow bool
		want              bool
	}{
		"the intermediate's list alone":  {want: true},
		"under on_unavailable: allow":    {want: true, allow: true},
		"with the root's list":           {root: true},
		"with the root's list and allow": {root: true, allow: true},
		"with OCSP":                      {ocsp: true},
	} {
		line, other := refuse, allow
		if c.allow {
			line, other = allow, refuse
		}
		t.Run(name, func(t *testing.T) {
			out := captureStderr(t)
			b := brokerConfig(t, minimalPolicy).Broker
			root := statusPKI(t, b)
			inter := intermediate(t, root, "status intermediate")
			dir := t.TempDir()
			cs := &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "intermediate",
				File:       writeFile(t, dir, "inter.crl", crl(t, inter, now.Add(-time.Minute), now.Add(time.Hour))),
				IssuerFile: writeFile(t, dir, "inter.pem", inter.PEM())}}}
			if c.allow {
				cs.OnUnavailable = "allow"
			}
			if c.root {
				cs.CRLs = append(cs.CRLs, config.CertificateStatusCRL{Name: "root", IssuerFile: b.ClientCAFile,
					File: writeFile(t, dir, "root.crl", crl(t, root, now.Add(-time.Minute), now.Add(time.Hour)))})
			}
			if c.ocsp {
				cs.OCSP = &config.CertificateStatusOCSP{Responder: "http://127.0.0.1:9/ocsp"}
			}
			b.CertificateStatus = cs
			_, stop := startDaemon(t, writeRunConfig(t, b), out)
			waitFor(t, out, "port49d: broker: certificate status from ")
			stop()
			if got := strings.Count(out.String(), line); got != map[bool]int{true: 1, false: 0}[c.want] {
				t.Fatalf("the line %d times: %q", got, out.String())
			}
			if strings.Contains(out.String(), other) {
				t.Fatalf("the other mode's line: %q", out.String())
			}
		})
	}
}

// A certificate_status that does not load ends the start, naming the key,
// before anything says listening.
func TestRunRefusesAnIssuerFileTheAnchorDidNotSign(t *testing.T) {
	b := brokerConfig(t, minimalPolicy).Broker
	other, err := testpki.NewCA("another CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	b.CertificateStatus = &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "x",
		File: "/nonexistent.crl", IssuerFile: writeFile(t, t.TempDir(), "other.pem", other.PEM())}}}
	out, err := runExpectingRefusal(t, writeRunConfig(t, b))
	if err == nil || !strings.Contains(err.Error(), "broker.certificate_status.crls[0].issuer_file") {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "listening") {
		t.Fatalf("stderr claims a listener is up: %q", out)
	}
}

// reply is a broker answer for a failure message: its status, and its body
// unless that is a 200's, which carries tokens test output never prints
// (plan 7b final review M-1).
func reply(status int, body string) string {
	if status == http.StatusOK {
		return "200 (body withheld: it carries tokens)"
	}
	return fmt.Sprintf("%d %s", status, body)
}
