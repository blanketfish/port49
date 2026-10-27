package port49d

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// withIssuance rewrites the broker configuration at path: its x509 shorthand
// becomes one OIDC human verifier at iss with issuance on, and init-issuer
// makes the broker's own CA in its state_dir, which it returns.
func withIssuance(t *testing.T, path string, iss *oidctest.Issuer) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	ca := writeFile(t, dir, "idp-ca.pem", iss.CertPEM())
	identity := "  identity:\n    humans:\n      - type: oidc\n        issuer: " + iss.URL +
		"\n        client_id: port49-cli\n        principal_claim: email\n        principal_domains: [corp.example.com]\n" +
		"        ca_file: " + ca + "\n    issuance: {}\n"
	body := regexp.MustCompile(`(?m)^  client_ca_file: .*\n`).ReplaceAllString(string(raw), identity)
	body = strings.Replace(body, "  certificate_status: {disabled: true}\n", "", 1) // no x509 verifier to check
	if body == string(raw) {
		t.Fatalf("%s has no client_ca_file", path)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	state := regexp.MustCompile(`(?m)^  state_dir: (\S+)$`).FindStringSubmatch(body)[1]
	if _, _, err := initIssuer(state, time.Now()); err != nil {
		t.Fatal(err)
	}
	return state
}

// copyCA copies the issuing CA's certificate and key from one state
// directory to another, as an operator adds a broker.
func copyCA(t *testing.T, from, to string) {
	t.Helper()
	for _, name := range []string{issuer.CertFile, issuer.KeyFile} {
		raw, err := os.ReadFile(filepath.Join(from, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// refusal runs the broker at cfg and returns the error that ends it; a broker
// still running after a minute is stopped and "not refused" returned.
func refusal(t *testing.T, cfg string) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- runBroker(ctx, cfg) }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Minute):
		cancel()
		<-done
		return errors.New("the broker was not refused")
	}
}

func wantsBothFingerprints(t *testing.T, err error, mine, theirs string) {
	t.Helper()
	if err == nil {
		t.Fatal("a broker on another CA started")
	}
	for _, want := range []string{"is not the one the store records", mine, theirs, "forget-issuer"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal lacks %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("the refusal holds key material")
	}
}

func fingerprintIn(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, issuer.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	return fingerprintOf(raw)
}

// Two port49-brokers on one store, each with its own init-issuer: the first
// records its CA and starts, the second is refused naming both fingerprints,
// at each of the three places the directory first answers.
func TestASecondBrokerOnAnotherCAIsRefused(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	// secondBroker is another replica of f's broker with its own CA, reaching
	// the directory through a proxy of its own when the fleet has one.
	secondBroker := func(t *testing.T, f *fleet, own *etcdtest.Proxy) (cfg, state string) {
		t.Helper()
		cfg = f.copyBroker(t)
		if f.dsrv != nil {
			bc, bk := f.dsrv.ClientFiles(t, "port49-broker")
			withDirectory(t, cfg, own, f.dsrv, "broker", bc, bk)
		}
		return cfg, withIssuance(t, cfg, iss)
	}
	t.Run("shared stores", func(t *testing.T) {
		var out syncBuffer
		e := stderr
		t.Cleanup(func() { stderr = e })
		stderr = &out
		f := splitFleet(t)
		first := withIssuance(t, f.broker, iss)
		startBroker(t, f.broker, &out, 1)
		waitWithin(t, &out, "recorded the issuing CA "+fingerprintIn(t, first), 30*time.Second)
		cfg2, second := secondBroker(t, f, nil)
		wantsBothFingerprints(t, refusal(t, cfg2), fingerprintIn(t, second), fingerprintIn(t, first))
	})
	t.Run("a directory store of its own, at start", func(t *testing.T) {
		var out syncBuffer
		e := stderr
		t.Cleanup(func() { stderr = e })
		stderr = &out
		f := splitFleet(t)
		f.twoStores(t)
		first := withIssuance(t, f.broker, iss)
		startBroker(t, f.broker, &out, 1)
		waitWithin(t, &out, "recorded the issuing CA "+fingerprintIn(t, first), 30*time.Second)
		cfg2, second := secondBroker(t, f, f.dproxy)
		wantsBothFingerprints(t, refusal(t, cfg2), fingerprintIn(t, second), fingerprintIn(t, first))
		// The copy instruction works: with the first broker's CA files the
		// second starts.
		copyCA(t, first, second)
		startBroker(t, cfg2, &out, 2)
	})
	t.Run("a directory that opens late", func(t *testing.T) {
		var out syncBuffer
		e, every := stderr, snapshotEvery
		t.Cleanup(func() { stderr, snapshotEvery = e, every })
		stderr, snapshotEvery = &out, time.Second
		f := splitFleet(t)
		f.twoStores(t)
		f.judged(t)
		first := withIssuance(t, f.broker, iss)
		startBroker(t, f.broker, &out, 1)
		_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
		defer stopD()
		waitSnapshots(t, f.srv, 2)
		waitWithin(t, &out, "recorded the issuing CA "+fingerprintIn(t, first), 30*time.Second)
		own := etcdtest.NewProxy(t, strings.TrimPrefix(f.dsrv.Endpoint, "https://"))
		own.Hang(true) // the second broker's directory does not answer at its start
		cfg2, second := secondBroker(t, f, own)
		errc := make(chan error, 1)
		go func() { errc <- refusal(t, cfg2) }()
		waitWithin(t, &out, "directory store: not answering; serving from", 60*time.Second)
		own.Hang(false)
		wantsBothFingerprints(t, <-errc, fingerprintIn(t, second), fingerprintIn(t, first))
	})
}

// forget-issuer removes the record once, saying what it held, and the next
// broker start records its own: the way out when every broker lost the CA.
func TestForgetIssuerRemovesTheRecord(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	first := withIssuance(t, f.broker, iss)
	_, stop := startBroker(t, f.broker, &out, 1)
	waitWithin(t, &out, "recorded the issuing CA "+fingerprintIn(t, first), 30*time.Second)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	fp := fingerprintIn(t, first)
	var so, se bytes.Buffer
	// Forgetting re-opens the store to any CA, so it names the one forgotten:
	// none, or another store's, deletes nothing.
	if code := forgetIssuer([]string{"--config", f.broker}, &so, &se); code != 2 || !strings.Contains(se.String(), "--current") {
		t.Fatalf("forget with no --current: %d %q", code, se.String())
	}
	se.Reset()
	other := "sha256:" + strings.Repeat("0", 64)
	if code := forgetIssuer([]string{"--config", f.broker, "--current", other}, &so, &se); code != 1 ||
		!strings.Contains(se.String(), fp) || !strings.Contains(se.String(), "nothing removed") || so.Len() != 0 {
		t.Fatalf("forget naming another CA: %d %q %q", code, so.String(), se.String())
	}
	se.Reset()
	if code := forgetIssuer([]string{"--config", f.broker, "--current", fp}, &so, &se); code != 0 ||
		!strings.Contains(so.String(), "removed the issuing CA record ("+fp) ||
		!strings.Contains(se.String(), "forgot issuing CA "+fp+"; stop every broker on this store before starting one on another CA") {
		t.Fatalf("forget: %d %q %q", code, so.String(), se.String())
	}
	so.Reset()
	if code := forgetIssuer([]string{"--config", f.broker, "--current", fp}, &so, &se); code != 0 ||
		!strings.Contains(so.String(), "no issuing CA record to remove") {
		t.Fatalf("forget again: %d %q %q", code, so.String(), se.String())
	}
	if code := forgetIssuer([]string{"extra"}, &so, &se); code != 2 || !strings.Contains(se.String(), "usage: port49-broker forget-issuer") {
		t.Fatalf("usage: %d %q", code, se.String())
	}
	cfg2 := f.copyBroker(t)
	second := withIssuance(t, cfg2, iss)
	startBroker(t, cfg2, &out, 1)
	waitWithin(t, &out, "recorded the issuing CA "+fingerprintIn(t, second), 30*time.Second)
}

// certificateRequest is POST /v1/certificate on the broker at addr with a
// fresh sign-in of alice from iss whose nonce names a new key: the status
// and the API's error code ("" on a 200), and the certificate's PEM on one.
func certificateRequest(t *testing.T, addr string, iss *oidctest.Issuer) (status int, code string, certPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := api.IssuanceNonce(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(api.IssueRequest{CSR: base64.RawURLEncoding.EncodeToString(der)})
	tok := iss.IDToken(t, "k1", "port49-cli", "sub-alice", time.Now(), map[string]any{
		"email": "alice@corp.example.com", "email_verified": true, "amr": []string{"pwd", "otp"}, "acr": "1", "nonce": nonce})
	req, err := http.NewRequest("POST", "https://"+addr+"/v1/certificate", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // a loopback fixture's own certificate
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 {
		var ok api.IssueResponse
		if err := json.Unmarshal(raw, &ok); err != nil {
			t.Fatalf("a 200 that is no certificate: %v", err)
		}
		return 200, "", ok.Certificate
	}
	var e api.Error
	_ = json.Unmarshal(raw, &e)
	return resp.StatusCode, e.Error, ""
}

// A broker whose directory opens late issues nothing until its CA has been
// held to the record: a request in the window is 503 issuance_unavailable,
// and the same request is served once the check passes; on another CA it
// stays refused, and then the start is.
func TestALateDirectoryHoldsIssuanceUntilTheCAIsChecked(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	setup := func(t *testing.T) (f *fleet, out *syncBuffer, first string, own *etcdtest.Proxy) {
		t.Helper()
		out = &syncBuffer{}
		e, every := stderr, snapshotEvery
		t.Cleanup(func() { stderr, snapshotEvery = e, every })
		stderr, snapshotEvery = out, time.Second
		f = splitFleet(t)
		f.twoStores(t)
		f.judged(t)
		first = withIssuance(t, f.broker, iss)
		startBroker(t, f.broker, out, 1)
		_, stopD := runSplitDaemon(t, f.daemon, out, 1)
		t.Cleanup(func() { _ = stopD() })
		waitSnapshots(t, f.srv, 2)
		waitWithin(t, out, "recorded the issuing CA "+fingerprintIn(t, first), 30*time.Second)
		own = etcdtest.NewProxy(t, strings.TrimPrefix(f.dsrv.Endpoint, "https://"))
		own.Hang(true)
		return f, out, first, own
	}
	second := func(t *testing.T, f *fleet, own *etcdtest.Proxy) (cfg, state string) {
		t.Helper()
		cfg = f.copyBroker(t)
		bc, bk := f.dsrv.ClientFiles(t, "port49-broker")
		withDirectory(t, cfg, own, f.dsrv, "broker", bc, bk)
		state = withIssuance(t, cfg, iss)
		return cfg, state
	}
	run := func(t *testing.T, cfg string, out *syncBuffer) (addr string, errc chan error, stop func()) {
		t.Helper()
		// Everything is read after this mark: the first broker's lines, and a
		// freshness line that begins like the late-open one, come before or
		// after "listening on" and anchor nothing.
		mark := len(out.String())
		ctx, cancel := context.WithCancel(context.Background())
		errc = make(chan error, 1)
		go func() { errc <- runBroker(ctx, cfg) }()
		t.Cleanup(cancel)
		waitWithinFrom(t, out, mark, "directory store: not answering; serving from", 60*time.Second)
		waitWithinFrom(t, out, mark, "port49-broker: listening on ", 30*time.Second)
		all := brokerLine.FindAllStringSubmatch(out.String()[mark:], -1)
		return all[len(all)-1][1], errc, cancel
	}
	t.Run("the same CA", func(t *testing.T) {
		f, out, first, own := setup(t)
		cfg2, state2 := second(t, f, own)
		copyCA(t, first, state2)
		addr, errc, stop := run(t, cfg2, out)
		if st, code, _ := certificateRequest(t, addr, iss); st != 503 || code != "issuance_unavailable" {
			t.Fatalf("a request in the window: %d %q, want 503 issuance_unavailable", st, code)
		}
		if n := strings.Count(out.String(), "issuance waits for the directory store"); n != 1 {
			t.Fatalf("the hold is said %d times, want once:\n%s", n, out.String())
		}
		own.Hang(false)
		deadline := time.Now().Add(60 * time.Second)
		for {
			st, code, cert := certificateRequest(t, addr, iss)
			if st == 200 && cert != "" {
				break
			}
			if st != 503 || time.Now().After(deadline) {
				t.Fatalf("after the check: %d %q", st, code)
			}
			time.Sleep(200 * time.Millisecond)
		}
		if n := strings.Count(out.String(), "issuance waits for the directory store"); n != 1 {
			t.Fatalf("the hold is said %d times after the release, want once", n)
		}
		stop()
		<-errc
	})
	t.Run("another CA", func(t *testing.T) {
		f, out, first, own := setup(t)
		cfg2, state2 := second(t, f, own)
		addr, errc, _ := run(t, cfg2, out)
		for range 3 {
			if st, code, _ := certificateRequest(t, addr, iss); st != 503 || code != "issuance_unavailable" {
				t.Fatalf("a request in the window: %d %q, want 503 issuance_unavailable", st, code)
			}
		}
		own.Hang(false)
		wantsBothFingerprints(t, <-errc, fingerprintIn(t, state2), fingerprintIn(t, first))
	})
}

// The CA the broker issues from is the CA it checked: files swapped after the
// check and before the issuer is built (an operator copying a CA in, a
// rotate-issuer) change nothing, because the start reads them once.
func TestTheIssuerIsTheCAThatWasChecked(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	first := withIssuance(t, f.broker, iss)
	other := safeDir(t)
	if _, _, err := initIssuer(other, time.Now()); err != nil {
		t.Fatal(err)
	}
	swapped := false
	pagedLoadFault = func(name string) error {
		if name == "marks" && !swapped { // after the record check, before the issuer is built
			swapped = true
			copyCA(t, other, first)
		}
		return nil
	}
	t.Cleanup(func() { pagedLoadFault = nil })
	addr, _ := startBroker(t, f.broker, &out, 1)
	if !swapped {
		t.Fatal("the files were never swapped")
	}
	st, code, certPEM := certificateRequest(t, addr, iss)
	if st != 200 {
		t.Fatalf("a request: %d %q", st, code)
	}
	blk, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := fingerprintIn(t, first); got != fingerprintIn(t, other) {
		t.Fatalf("the swap did not happen: %s", got)
	}
	checked, _ := os.ReadFile(filepath.Join(other, issuer.CertFile)) // the swapped-in CA, which was not checked
	cb, _ := pem.Decode(checked)
	swappedIn, _ := x509.ParseCertificate(cb.Bytes)
	if cert.CheckSignatureFrom(swappedIn) == nil {
		t.Fatal("the certificate was issued by a CA the record check never saw")
	}
}
