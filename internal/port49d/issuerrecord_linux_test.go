package port49d

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

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
	var so, se bytes.Buffer
	if code := forgetIssuer([]string{"--config", f.broker}, &so, &se); code != 0 ||
		!strings.Contains(so.String(), "removed the issuing CA record ("+fingerprintIn(t, first)) {
		t.Fatalf("forget: %d %q %q", code, so.String(), se.String())
	}
	so.Reset()
	if code := forgetIssuer([]string{"--config", f.broker}, &so, &se); code != 0 ||
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
