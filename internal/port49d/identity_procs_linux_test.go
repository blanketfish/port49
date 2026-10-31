//go:build linux

package port49d

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/testpki"
)

const noX509Line = "no x509 verifier is configured, so no client certificate's status is checked"

// brokerWithIdentity rewrites the port49-broker.yaml at cfg to name an OIDC
// human verifier at iss (its CA in a file beside it), with an x509 anchor
// too, or alone as an OIDC-only broker (no client_ca_file, no
// certificate_status).
func brokerWithIdentity(t *testing.T, f *fleet, cfg string, iss *oidctest.Issuer, withX509 bool) {
	t.Helper()
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ca := writeFile(t, filepath.Dir(cfg), "idp-ca.pem", iss.CertPEM())
	identity := "  identity:\n    humans:\n"
	if withX509 {
		identity += "      - {type: x509, trust_anchor_file: " + filepath.Join(f.pki, testpki.LabCA) + "}\n"
	}
	identity += fmt.Sprintf("      - {type: oidc, issuer: %q, client_id: port49-cli, principal_claim: email, "+
		"principal_domains: [example.com], ca_file: %s}\n", iss.URL, ca)
	body := regexp.MustCompile(`(?m)^  client_ca_file: .*\n`).ReplaceAllLiteral(raw, []byte(identity))
	if !withX509 {
		body = regexp.MustCompile(`(?m)^  certificate_status: .*\n`).ReplaceAllLiteral(body, nil)
	}
	if string(body) == string(raw) {
		t.Fatal("the run config has no client_ca_file to replace")
	}
	if err := os.WriteFile(cfg, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Review I1: port49-broker, the process compose and Kubernetes run, fetches
// and keeps its provider's keys. Remove runKeySets from runBroker and the
// file never appears, while /readyz stays 200.
func TestPort49BrokerRunsItsKeySets(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	iss := oidctest.NewIssuer(t)
	f := splitFleet(t)
	brokerWithIdentity(t, f, f.broker, iss, true)
	runBrokerUntil(t, f.broker, &out, "port49-broker: listening on ", 1)
	keptKeys(t, keyFile(f.stateDir(t), iss.URL))
}

// An OIDC-only port49-broker starts (a nil certificate_status is not
// dereferenced), says it checks no certificate's status, and runs its loop.
func TestAnOIDCOnlyPort49BrokerStartsAndRunsItsKeySets(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	iss := oidctest.NewIssuer(t)
	f := splitFleet(t)
	brokerWithIdentity(t, f, f.broker, iss, false)
	runBrokerUntil(t, f.broker, &out, "port49-broker: listening on ", 1)
	if !strings.Contains(out.String(), "port49-broker: broker: "+noX509Line+"\n") {
		t.Fatalf("no x509 line:\n%s", out.String())
	}
	keptKeys(t, keyFile(f.stateDir(t), iss.URL))
}

// The same on port49d: OIDC-only, no client_ca_file and no certificate_status.
func TestAnOIDCOnlyPort49dStartsAndSaysItChecksNoCertificate(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, io.Discard
	iss := oidctest.NewIssuer(t)
	b := brokerConfig(t, minimalPolicy).Broker
	pki := filepath.Dir(b.ClientCAFile)
	ca := writeFile(t, pki, "idp-ca.pem", iss.CertPEM())
	cfgPath := writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := fmt.Sprintf("  identity:\n    humans:\n      - {type: oidc, issuer: %q, client_id: port49-cli, "+
		"principal_claim: email, principal_domains: [example.com], ca_file: %s}\n", iss.URL, ca)
	body := regexp.MustCompile(`(?m)^  client_ca_file: .*\n`).ReplaceAllLiteral(raw, []byte(identity))
	body = regexp.MustCompile(`(?m)^  certificate_status:\n(    .*\n)*`).ReplaceAllLiteral(body, nil)
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	if !strings.Contains(out.String(), "port49d: broker: "+noX509Line+"\n") {
		t.Fatalf("no x509 line:\n%s", out.String())
	}
}

// Review M1: a state directory port49d cannot keep keys in is said with the
// key port49d has, and port49-broker's is said with its own.
func TestTheStateDirLineNamesTheKeyTheProcessHas(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		stateDir string // broker.state_dir: "" on port49d
		want     []string
		never    string
	}{
		{"", []string{"the directory of broker.revocations_file (" + dir + ")", "move broker.revocations_file into a 0700 directory"},
			"broker.state_dir"},
		{dir, []string{"broker.state_dir " + dir, "chmod 0700 it"}, "revocations_file"},
	} {
		cfg := brokerConfig(t, directoryPolicy)
		cfg.Broker.StateDir = c.stateDir
		cfg.Broker.Identity = identityCfg(t, iss, stateDirT(t)) // ca_file is read through the fence: its directory is ours alone
		var said syncBuffer
		set, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(f string, a ...any) {
			said.Write([]byte(fmtLine(f, a...)))
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := set.Verifiers[0].Keys.Fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for !strings.Contains(said.String(), "could not be kept") && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond) // Save runs outside the fetch
		}
		for _, w := range c.want {
			if strings.Count(said.String(), w) != 2 { // the start line and the save's
				t.Errorf("state_dir %q: %q is not in both lines:\n%s", c.stateDir, w, said.String())
			}
		}
		if strings.Contains(said.String(), c.never) {
			t.Errorf("state_dir %q: names %s:\n%s", c.stateDir, c.never, said.String())
		}
	}
}
