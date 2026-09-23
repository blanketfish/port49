package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
)

func brokerConfig(t *testing.T, policyBody string) config.Config {
	t.Helper()
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(policyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Config{
		Session:   config.SessionConfig{MaxSessionAgeDefault: time.Hour},
		Inventory: admission.Inventory{Devices: []admission.Device{{Name: "leaf1", Platform: "arista_eos"}}},
		Broker: &config.BrokerConfig{Listen: "127.0.0.1:0", TLSCertFile: filepath.Join(dir, testpki.LabServerCert),
			TLSKeyFile: filepath.Join(dir, testpki.LabServerKey), ClientCAFile: filepath.Join(dir, testpki.LabCA),
			PolicyFile: pol, BatchMax: 10},
	}
}

const minimalPolicy = `
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

func buildWith(cfg config.Config) error {
	_, err := buildBroker(cfg, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	return err
}

func TestNoBrokerBlockBuildsNoBroker(t *testing.T) {
	srv, err := buildBroker(config.Config{}, nil, nil, nil, nil)
	if srv != nil || err != nil {
		t.Fatalf("%v %v", srv, err)
	}
}

func TestABrokerBuildsFromItsFiles(t *testing.T) {
	srv, err := buildBroker(brokerConfig(t, minimalPolicy), memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if srv.Addr != "127.0.0.1:0" || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven ||
		srv.TLSConfig.MinVersion != tls.VersionTLS13 || srv.IdleTimeout != time.Hour {
		t.Fatalf("server: %+v", srv)
	}
	// Every connection a full handshake that uses the key (pre-flight F2),
	// HTTP/1.1 only (F13), and a certificate-less connection closed when idle
	// (F1).
	if !srv.TLSConfig.SessionTicketsDisabled || srv.TLSNextProto == nil || len(srv.TLSNextProto) != 0 ||
		srv.ConnState == nil || srv.ConnContext == nil {
		t.Fatalf("server hardening: tickets off %v, TLSNextProto %v, ConnState set %v",
			srv.TLSConfig.SessionTicketsDisabled, srv.TLSNextProto, srv.ConnState != nil)
	}
}

// Everything that can fail on a typo fails before a listener opens.
func TestABrokerThatCannotLoadFailsTheStart(t *testing.T) {
	if err := buildWith(brokerConfig(t, "roles: [{name: r, privilege: operator}]\n")); err == nil ||
		!strings.Contains(err.Error(), "operator") {
		t.Fatalf("a bad policy: %v", err)
	}
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Broker.ClientCAFile = cfg.Broker.TLSKeyFile
	if err := buildWith(cfg); err == nil {
		t.Fatal("a trust anchor file with no certificate must fail the start")
	}
}

// At 3am the one line port49d exits with names the file to go and look at.
func TestABrokerLoadFailureNamesTheFile(t *testing.T) {
	for name, breakIt := range map[string]func(b *config.BrokerConfig) string{
		"missing policy": func(b *config.BrokerConfig) string {
			b.PolicyFile += ".missing"
			return b.PolicyFile
		},
		"missing certificate": func(b *config.BrokerConfig) string {
			b.TLSCertFile += ".missing"
			return b.TLSCertFile
		},
		"key readable by others": func(b *config.BrokerConfig) string {
			if err := os.Chmod(b.TLSKeyFile, 0o644); err != nil {
				t.Fatal(err)
			}
			return b.TLSKeyFile
		},
		"key that does not match the certificate": func(b *config.BrokerConfig) string {
			// The client key is a real key, just not the server certificate's.
			b.TLSKeyFile = filepath.Join(filepath.Dir(b.TLSKeyFile), testpki.LabClientKey)
			return b.TLSKeyFile
		},
		"missing client CA": func(b *config.BrokerConfig) string {
			b.ClientCAFile += ".missing"
			return b.ClientCAFile
		},
	} {
		cfg := brokerConfig(t, minimalPolicy)
		path := breakIt(cfg.Broker)
		if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: the error must name %s: %v", name, path, err)
		}
	}
}

// syncBuffer is a bytes.Buffer the server's goroutines can write while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A failed handshake — an expired or untrusted certificate — is logged by
// net/http, not by a handler. It must land in port49d's own stderr stream,
// prefixed so an operator can grep for it, rather than in the standard
// library's default logger.
func TestBrokerTLSErrorsReachPort49dsLog(t *testing.T) {
	var out syncBuffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out

	srv, err := buildBroker(brokerConfig(t, minimalPolicy), memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	// A client that does not trust the broker's certificate aborts the
	// handshake, which the server logs.
	if c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13}); err == nil {
		c.Close()
		t.Fatal("the handshake succeeded against an untrusted server certificate")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "TLS handshake error") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := out.String(); !strings.HasPrefix(got, "port49d: broker: ") || !strings.Contains(got, "TLS handshake error") {
		t.Fatalf("broker error log: %q", got)
	}
}

// A broker that cannot load ends run before the TACACS+ listener serves: run
// returns, with the file named, instead of serving until a signal.
func TestRunRefusesToStartWithABrokerThatCannotLoad(t *testing.T) {
	t.Setenv("T_RUN_SECRET", "run-test-secret")
	t.Setenv("T_RUN_ENC", "33333333333333333333333333333333")
	dir := t.TempDir()
	b := brokerConfig(t, minimalPolicy).Broker
	missing := b.PolicyFile + ".missing"
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte(`
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(`
listen: "127.0.0.1:0"
metrics_listen: "127.0.0.1:0"
inventory_file: %s
keys:
  k:
    current: {version: 1, secret_env: T_RUN_SECRET}
encryption:
  current: {id: v1, secret_env: T_RUN_ENC}
accounting: {spool_path: %s}
lab:
  session_attributes: ["priv-lvl=15"]
broker:
  listen: "127.0.0.1:0"
  tls_cert_file: %s
  tls_key_file: %s
  client_ca_file: %s
  policy_file: %s
`, inv, filepath.Join(dir, "acct.jsonl"), b.TLSCertFile, b.TLSKeyFile, b.ClientCAFile, missing)), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- run(cfgPath) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run is serving TACACS+ with a broker that failed to load")
	}
}
