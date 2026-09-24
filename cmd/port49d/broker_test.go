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
	"github.com/prometheus/client_golang/prometheus/testutil"

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
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

func buildWith(cfg config.Config) error {
	_, _, err := buildBroker(cfg, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	return err
}

func TestNoBrokerBlockBuildsNoBroker(t *testing.T) {
	srv, pol, err := buildBroker(config.Config{}, nil, nil, nil, nil)
	if srv != nil || pol != nil || err != nil {
		t.Fatalf("%v %v %v", srv, pol, err)
	}
}

func TestABrokerBuildsFromItsFiles(t *testing.T) {
	srv, _, err := buildBroker(brokerConfig(t, minimalPolicy), memory.New(time.Now), seedMinter(),
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
	if err := buildWith(brokerConfig(t, strings.Replace(minimalPolicy, "privilege: admin", "privilege: root", 1))); err == nil ||
		!strings.Contains(err.Error(), `"root" is not a privilege level`) {
		t.Fatalf("a bad policy: %v", err)
	}
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Broker.ClientCAFile = cfg.Broker.TLSKeyFile
	if err := buildWith(cfg); err == nil {
		t.Fatal("a trust anchor file with no certificate must fail the start")
	}
}

// A device the policy cannot be compiled for is quarantined, not a reason to
// stay down: the start goes on, and names the device and the cause (spec §10;
// §13 decision 20). leaf1 is arista_eos, which renders no `operator`.
func TestAQuarantinedDeviceDoesNotStopTheStart(t *testing.T) {
	var out bytes.Buffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	_, pol, err := buildBroker(brokerConfig(t, strings.Replace(minimalPolicy, "privilege: admin", "privilege: operator", 1)),
		memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatalf("a quarantined device must not stop the start: %v", err)
	}
	if _, ok := pol.Quarantined("leaf1", time.Now()); !ok {
		t.Fatal("the daemon is handed the policy that quarantines leaf1")
	}
	if !strings.Contains(out.String(), "device leaf1 (arista_eos) is quarantined") ||
		!strings.Contains(out.String(), "level operator has no rendering on arista_eos") {
		t.Fatalf("stderr: %s", out.String())
	}
}

// A deny term that matches any argument on a platform that may send what was
// typed, because its abbreviations cannot be read, is said at start with the
// term and the platform; the device is not quarantined (spec §3 rule 4).
func TestAWidenedDenyIsSaidAtStart(t *testing.T) {
	var out bytes.Buffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	cfg := brokerConfig(t, strings.Replace(minimalPolicy, `permit: ["**"]}`, `permit: ["**"], deny: ["* * /tftp/"]}`, 1))
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "ntp1", Platform: "meinberg_lantime"})
	_, pol, err := buildBroker(cfg, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pol.Quarantined("ntp1", time.Now()); ok {
		t.Fatal("a widened deny quarantines nothing")
	}
	if !strings.Contains(out.String(), `port49d: broker: role "r": deny "* * /tftp/" on meinberg_lantime: /tftp/:`) ||
		!strings.Contains(out.String(), "matches any argument") {
		t.Fatalf("stderr: %s", out.String())
	}
}

// The daemon asks the policy at the time of each packet, and the gauge counts
// at the time of each scrape: a device an expiry will quarantine is neither
// refused nor counted until then (spec §10).
func TestTheDaemonsQuarantineFollowsTheClock(t *testing.T) {
	now := time.Now()
	lapse := now.Add(48 * time.Hour).Truncate(time.Second)
	_, pol, err := buildBroker(brokerConfig(t, `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: op, privilege: operator, permit: [show **]}
  - {name: adm, privilege: admin, permit: ["**"]}
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [op]}
  - {subject: s, scope: all_devices, roles: [adm], expires: `+lapse.Format(time.RFC3339)+`}
`), memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	clock := now
	quarantined := watchQuarantine(pol, m, func() time.Time { return clock })
	if _, ok := quarantined("leaf1", now); ok || testutil.ToFloat64(m.DevicesQuarantined) != 0 {
		t.Fatal("before the expiry leaf1 is neither refused nor counted")
	}
	clock = lapse
	if _, ok := quarantined("leaf1", lapse); !ok || testutil.ToFloat64(m.DevicesQuarantined) != 1 {
		t.Fatalf("from the expiry leaf1 is refused and counted: gauge %v", testutil.ToFloat64(m.DevicesQuarantined))
	}
	if watchQuarantine(nil, m, time.Now) != nil {
		t.Fatal("with no broker there is no quarantine to ask")
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

// An expired or not-yet-valid broker server certificate does not stop the
// start: refusing would take device AAA down with the broker. But it is said
// at start, in one line, rather than first showing up as every operator's
// failed login (final review, Minor 5). A valid one says nothing.
func TestABrokerServerCertificateOutsideItsValidityIsWarnedAtStart(t *testing.T) {
	for _, c := range []struct {
		name  string
		shift time.Duration
		want  string
	}{
		{"valid", 0, ""},
		{"expired", -48 * time.Hour, "port49d: broker: server certificate expired at "},
		{"not yet valid", 48 * time.Hour, "port49d: broker: server certificate is not valid until "},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out syncBuffer
			defer func(w io.Writer) { stderr = w }(stderr)
			stderr = &out
			cfg := brokerConfig(t, minimalPolicy)
			if err := testpki.WriteLab(filepath.Dir(cfg.Broker.TLSCertFile), "alice@example.com",
				time.Now().Add(c.shift)); err != nil {
				t.Fatal(err)
			}
			if err := buildWith(cfg); err != nil {
				t.Fatalf("a certificate outside its validity must not stop the start: %v", err)
			}
			got := out.String()
			if c.want == "" {
				if got != "" {
					t.Fatalf("a valid certificate warns nothing: %q", got)
				}
				return
			}
			if !strings.Contains(got, c.want) || !strings.Contains(got, "logins will fail") ||
				strings.Count(got, "\n") != 1 {
				t.Fatalf("stderr %q, want one line with %q", got, c.want)
			}
		})
	}
}

// A failed handshake — an expired or untrusted certificate — is logged by
// net/http, not by a handler. It must land in port49d's own stderr stream,
// prefixed so an operator can grep for it, rather than in the standard
// library's default logger.
func TestBrokerTLSErrorsReachPort49dsLog(t *testing.T) {
	var out syncBuffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out

	srv, _, err := buildBroker(brokerConfig(t, minimalPolicy), memory.New(time.Now), seedMinter(),
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

// writeRunConfig writes a complete port49d.yaml whose broker block uses b,
// and returns its path.
func writeRunConfig(t *testing.T, b *config.BrokerConfig) string {
	t.Helper()
	t.Setenv("T_RUN_SECRET", "run-test-secret")
	t.Setenv("T_RUN_ENC", "33333333333333333333333333333333")
	dir := t.TempDir()
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
  listen: %q
  tls_cert_file: %s
  tls_key_file: %s
  client_ca_file: %s
  policy_file: %s
`, inv, filepath.Join(dir, "acct.jsonl"), b.Listen, b.TLSCertFile, b.TLSKeyFile, b.ClientCAFile,
		b.PolicyFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// runExpectingRefusal runs port49d on cfgPath and returns what it wrote to
// stderr and its error; run must return rather than serve until a signal.
func runExpectingRefusal(t *testing.T, cfgPath string) (string, error) {
	t.Helper()
	var out syncBuffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	done := make(chan error, 1)
	go func() { done <- run(cfgPath) }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(10 * time.Second):
		t.Fatal("run is serving TACACS+ with a broker that could not start")
		return "", nil
	}
}

// A broker that cannot load ends run before the TACACS+ listener serves: run
// returns, with the file named, instead of serving until a signal.
func TestRunRefusesToStartWithABrokerThatCannotLoad(t *testing.T) {
	b := brokerConfig(t, minimalPolicy).Broker
	b.PolicyFile += ".missing"
	if _, err := runExpectingRefusal(t, writeRunConfig(t, b)); err == nil || !strings.Contains(err.Error(), b.PolicyFile) {
		t.Fatalf("run: %v", err)
	}
}

// A broker port already taken ends the start, and nothing on stderr says
// port49d is listening: at 3am, under a supervisor restarting it every few
// seconds, a "listening" line followed by an exit reads as TACACS+ being up.
func TestRunWithTheBrokerPortTakenNeverSaysListening(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	b := brokerConfig(t, minimalPolicy).Broker
	b.Listen = taken.Addr().String()
	out, err := runExpectingRefusal(t, writeRunConfig(t, b))
	if err == nil || !strings.Contains(err.Error(), b.Listen) {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "listening") {
		t.Fatalf("stderr claims a listener is up: %q", out)
	}
}

// Two inventory devices sharing a name would collapse to one, and a token
// minted with one's platform would redeem on the other, carrying attributes
// compiled for a platform it is not.
func TestABrokerRefusesADeviceNamedTwice(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "leaf1", Platform: "cisco_iosxe"})
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), `"leaf1"`) {
		t.Fatalf("a device named twice: %v", err)
	}
}
