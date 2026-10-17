package port49d

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

func brokerConfig(t *testing.T, policyBody string) config.Config {
	t.Helper()
	return brokerConfigWith(t, policyBody, nil)
}

// brokerConfigWith is brokerConfig with a lab client certificate for each
// of others too (testpki.LabClientFiles), for mintAs.
func brokerConfigWith(t *testing.T, policyBody string, others []string) config.Config {
	t.Helper()
	dir := t.TempDir()
	if err := testpki.WriteLabWith(dir, "alice@example.com", others, time.Now()); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(policyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Session:   config.SessionConfig{MaxSessionAgeDefault: time.Hour},
		Keys:      map[string]config.KeySet{"lab_key": {Current: config.KeyVersion{Version: 1, SecretEnv: "UNUSED"}}},
		Inventory: admission.Inventory{Devices: []admission.Device{{Name: "leaf1", Platform: "arista_eos", KeyRef: "lab_key"}}},
		Broker: &config.BrokerConfig{Listen: "127.0.0.1:0", TLSCertFile: filepath.Join(dir, testpki.LabServerCert),
			TLSKeyFile: filepath.Join(dir, testpki.LabServerKey), ClientCAFile: filepath.Join(dir, testpki.LabCA),
			PolicyFile: pol, BatchMax: 10, RevocationsFile: filepath.Join(dir, "revocations.json"),
			MaxConnsPerPrincipal: 4, MaxPendingConnsPerSource: 16,
			CertificateStatus: &config.CertificateStatusConfig{Disabled: true}},
		// config.Load mirrors broker.policy_file here (plan 7e).
		Policy: &config.PolicyConfig{File: pol, WatchInterval: 5 * time.Second},
	}
	if _, err := initRevocations(cfg.Broker.RevocationsFile, testInitConfig); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// port49d names the bundle an offline tool names for the same two files, so a
// bundle in a record is one CI can load (Task 6 review M2).
func TestPort49dAndTheToolsNameOneBundle(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]\n")
	cfg.InventoryFile = filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(cfg.InventoryFile, []byte("devices:\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.3], attributes: {site: dc1}}\n"+
		"  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.2, 10.0.0.1]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := admission.LoadFile(cfg.InventoryFile) // as config.Load reads it
	if err != nil {
		t.Fatal(err)
	}
	cfg.Inventory = inv
	daemon, err := loadPolicy(cfg, "inventory_file "+cfg.InventoryFile)
	if err != nil {
		t.Fatal(err)
	}
	tool, err := bundle.Load(cfg.Broker.PolicyFile, cfg.InventoryFile, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if daemon.Bundle != tool.Bundle || daemon.Bundle == daemon.Source {
		t.Fatalf("port49d %s, the tools %s (source %s)", daemon.Bundle, tool.Bundle, daemon.Source)
	}
}

// unmappedLevel declares a level no built-in platform renders: a role landing
// an arista_eos session there quarantines the device. `operator` renders on
// EOS since the owner's ruling of 2026-09-24 (spec §6, decision 23).
const unmappedLevel = "privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]\n"

const minimalPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

// sharedUsernamePolicy is minimalPolicy with bob as a second identity of
// alice's subject: the two log in under one username, so one context key
// on a device. Two subjects may not share a username (spec §2).
const sharedUsernamePolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com", "user:bob@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

func buildWith(cfg config.Config) error {
	_, _, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	return err
}

func TestNoBrokerBlockBuildsNoBroker(t *testing.T) {
	srv, b, err := buildBroker(config.Config{}, "", nil, nil, nil, nil)
	if srv != nil || b != nil || err != nil {
		t.Fatalf("%v %v %v", srv, b, err)
	}
}

func TestABrokerBuildsFromItsFiles(t *testing.T) {
	srv, _, err := buildBroker(brokerConfig(t, minimalPolicy), "inventory_file", memory.New(time.Now), seedMinter(),
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
// §13 decision 20). leaf1 is arista_eos, which renders no custom level `unmapped`.
func TestAQuarantinedDeviceDoesNotStopTheStart(t *testing.T) {
	var out bytes.Buffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	_, b, err := buildBroker(brokerConfig(t, unmappedLevel+strings.Replace(minimalPolicy, "privilege: admin", "privilege: unmapped", 1)), "inventory_file",
		memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatalf("a quarantined device must not stop the start: %v", err)
	}
	if _, ok := b.Policy.Quarantined("leaf1", time.Now()); !ok {
		t.Fatal("the daemon is handed the policy that quarantines leaf1")
	}
	if !strings.Contains(out.String(), "device leaf1 (arista_eos) is quarantined") ||
		!strings.Contains(out.String(), "level unmapped has no rendering on arista_eos") {
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
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "ntp1", Platform: "meinberg_lantime", KeyRef: "lab_key"})
	_, b, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Policy.Quarantined("ntp1", time.Now()); ok {
		t.Fatal("a widened deny quarantines nothing")
	}
	if !strings.Contains(out.String(), `port49d: broker: role "r": deny "* * /tftp/" on meinberg_lantime: term 3 (a regex):`) ||
		!strings.Contains(out.String(), "matches any argument") {
		t.Fatalf("stderr: %s", out.String())
	}
}

// A permit naming an interface joined never matches on IOS-XE, which sends
// the name and the index apart (L21), and the start says so.
func TestAJoinedInterfacePermitIsSaidAtStart(t *testing.T) {
	var out bytes.Buffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	cfg := brokerConfig(t, strings.Replace(minimalPolicy, `permit: ["**"]}`, `permit: ["**", "interface Gi1 **"]}`, 1))
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "xe1", Platform: "cisco_iosxe", KeyRef: "lab_key"})
	if _, _, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry())); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `port49d: broker: role "r": permit "interface Gi1 **" on cisco_iosxe: `+"`Gi1`"+` never matches`) {
		t.Fatalf("stderr: %s", out.String())
	}
}

// A rule with a value redaction hides loads, and the start says so with the
// value redacted: stderr is a log like any other (spec §5.8).
func TestARuleSecretLiteralIsSaidAtStartRedacted(t *testing.T) {
	var out bytes.Buffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	cfg := brokerConfig(t, strings.Replace(minimalPolicy, `permit: ["**"]}`,
		`permit: ["**"], deny: ["snmp-server community Hunter2 **"]}`, 1))
	_, b, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if b.Redact == nil {
		t.Fatal("the broker's blob event must redact with the policy in force's patterns")
	}
	if !strings.Contains(out.String(), `port49d: broker: role "r": deny "snmp-server community «redacted» **" carries`) ||
		strings.Contains(out.String(), "Hunter2") {
		t.Fatalf("stderr: %s", out.String())
	}
}

// The daemon asks the policy at the time of each packet, and the gauge counts
// at the time of each scrape: a device an expiry will quarantine is neither
// refused nor counted until then (spec §10).
func TestTheDaemonsQuarantineFollowsTheClock(t *testing.T) {
	var out bytes.Buffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	now := time.Now()
	lapse := now.Add(48 * time.Hour).Truncate(time.Second)
	_, b, err := buildBroker(brokerConfig(t, unmappedLevel+`
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: op, privilege: unmapped, permit: [show **]}
  - {name: adm, privilege: admin, permit: ["**"]}
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants:
  - {subject: s, scope: all_devices, roles: [op]}
  - {subject: s, scope: all_devices, roles: [adm], expires: `+lapse.Format(time.RFC3339)+`}
`), "inventory_file", memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	// The start says it now, with when, while leaf1 still mints.
	if !strings.Contains(out.String(), "port49d: broker: device leaf1 (arista_eos) will be quarantined from "+
		decision.FormatTime(lapse)) || strings.Contains(out.String(), "is quarantined") {
		t.Fatalf("stderr: %s", out.String())
	}
	m := metrics.New(prometheus.NewRegistry())
	clock := now
	quarantined := watchQuarantine(b.Policy, m, func() time.Time { return clock })
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
		cfg.Policy.File = cfg.Broker.PolicyFile // as config.Load mirrors it
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

	srv, _, err := buildBroker(brokerConfig(t, minimalPolicy), "inventory_file", memory.New(time.Now), seedMinter(),
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
// and returns its path. It has no lab: block: it is the production shape, a
// daemon answering only what the broker minted (plan 4, Decided 12).
// safeDir is a fresh directory only its owner can write, whatever the umask.
func safeDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func writeRunConfig(t *testing.T, b *config.BrokerConfig) string {
	t.Helper()
	return writeRunConfigWith(t, b, `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`, "")
}

// writeRunConfigWith is writeRunConfig with the inventory's body and extra
// top-level YAML appended to port49d.yaml (a tls_listener block, say).
func writeRunConfigWith(t *testing.T, b *config.BrokerConfig, inventory, extra string) string {
	t.Helper()
	t.Setenv("T_RUN_SECRET", "run-test-secret")
	t.Setenv("T_RUN_ENC", "33333333333333333333333333333333")
	// safeDir: the inventory is read behind the policy file's fence.
	dir := safeDir(t)
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte(inventory), 0o600); err != nil {
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
broker:
  listen: %q
  tls_cert_file: %s
  tls_key_file: %s
  client_ca_file: %s
  policy_file: %s
  revocations_file: %s
  policy_watch_interval: 1s
  certificate_status:
%s`, inv, filepath.Join(dir, "acct.jsonl"), b.Listen, b.TLSCertFile, b.TLSKeyFile, b.ClientCAFile,
		b.PolicyFile, b.RevocationsFile, certStatusYAML(t, b.CertificateStatus))+extra), 0o600); err != nil {
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
	go func() { done <- run(context.Background(), cfgPath) }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(10 * time.Second):
		t.Fatal("run is serving TACACS+ with a broker that could not start")
		return "", nil
	}
}

// A port49d.yaml with policy: and no broker: block is the split daemon
// (plan 7e), which admits from the policy in force with no broker beside
// it: leaf1, which the policy admits, logs alice in with a token the lab
// seeded, and the listening line counts it admitted. Before Task 14 this
// file was refused at start (Task 13 review I-1).
func TestThePolicyOnlyDaemonAdmitsALogin(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfgPath, _ := policyOnlyRun(t)
	seeds := filepath.Join(safeDir(t), "seeds.jsonl")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("lab:\n  seed_token_file: " + seeds + "\n  seed_tokens:\n    - {nas: leaf1, username: alice}\n")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	tacacs := startSplitDaemon(t, cfgPath, &out, 1)
	if !strings.Contains(out.String(), ", 1 devices admitted\n") {
		t.Fatalf("the listening line: %s", out.String())
	}
	raw, err := os.ReadFile(seeds)
	if err != nil {
		t.Fatal(err)
	}
	var seed struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &seed); err != nil || seed.Login == "" {
		t.Fatalf("the seed file does not hold one login (%v)", err)
	}
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if st := dev.login("alice", seed.Login); st != wire.AuthenStatusPass {
		t.Fatalf("the split daemon's login: status %d", st)
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
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "leaf1", Platform: "cisco_iosxe", KeyRef: "lab_key"})
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), `"leaf1"`) {
		t.Fatalf("a device named twice: %v", err)
	}
}

// port49d admits from the policy in force: a device the policy refuses is in
// the index as refused, and a reload's index reaches the next Accept.
func TestPort49dAdmitsFromThePolicyInForce(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	_, b, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := liveAdmission{b.Policy}.Lookup(netip.MustParseAddr("192.0.2.9"))
	if !ok || !strings.Contains(r.Refused, "matches no key group") {
		t.Fatalf("stray: %+v, %v", r, ok)
	}
}

// C3: a restart in the middle of the key-group move loads (both files carry
// the block, the policy's wins), and a start whose bundle admits nothing is
// refused with the fix named.
func TestTheKeyGroupMoveNeverStopsAStartThatCouldServe(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]\n")
	cfg.Inventory.Devices[0].KeyRef = ""
	cfg.Inventory.Devices[0].Addresses = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	cfg.Inventory.KeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "lab_key"}}
	if err := buildWith(cfg); err != nil {
		t.Fatalf("both files carry the block: %v", err)
	}
	none := brokerConfig(t, minimalPolicy)
	none.Inventory.Devices[0].KeyRef = ""
	if err := buildWith(none); err == nil || !strings.Contains(err.Error(), "admits none of the 1 device(s)") {
		t.Fatalf("a bundle admitting nothing: %v", err)
	}
}

// The admits-none refusal says where to look for the inventory's source:
// the inventory file in file mode, the source of truth and the service's
// sync log in service mode, never the other's.
func TestAStartAdmittingNoneAdvisesByTheInventorySource(t *testing.T) {
	file := brokerConfig(t, minimalPolicy)
	file.Inventory.Devices[0].KeyRef = ""
	_, err := loadPolicy(file, "inventory_file "+file.InventoryFile)
	if err == nil || !strings.Contains(err.Error(), "with inventory_file "+file.InventoryFile) ||
		!strings.Contains(err.Error(), "deleted from the inventory file, add it to the policy file") ||
		strings.Contains(err.Error(), "sync log") {
		t.Fatalf("file mode: %v", err)
	}
	svc := brokerConfig(t, minimalPolicy)
	svc.Inventory.Devices[0].KeyRef = ""
	svc.InventoryFile, svc.InventoryService = "", &config.InventoryServiceConfig{URL: "https://inv.test:8443"}
	_, err = loadPolicy(svc, "the inventory service's bundle 7")
	if err == nil || !strings.Contains(err.Error(), "with the inventory service's bundle 7") ||
		!strings.Contains(err.Error(), "check the source of truth it syncs from and the service's sync log") ||
		strings.Contains(err.Error(), "inventory_file") || strings.Contains(err.Error(), "the inventory file") {
		t.Fatalf("service mode: %v", err)
	}
}

// A start that admits none of the inventory advises in the running
// process's terms (Task 18): port49d.yaml and stopping port49d on port49d;
// port49-broker.yaml and stopping every port49d on port49-broker, which
// serves no device.
func TestAStartAdmittingNoneAdvisesInTheProcessesOwnTerms(t *testing.T) {
	for _, c := range []struct {
		role        config.Role
		has, hasNot []string
	}{
		{config.RoleDaemon, []string{"the key_refs port49d.yaml defines", "to take the whole fleet off deliberately, stop port49d"},
			[]string{"port49-broker", "stop every port49d"}},
		{config.RoleBroker, []string{"the key_refs port49-broker.yaml defines",
			"to take the whole fleet off deliberately, stop every port49d (port49-broker serves no device)"},
			[]string{"port49d.yaml", "stop port49d"}},
	} {
		cfg := brokerConfig(t, minimalPolicy)
		cfg.Inventory.Devices[0].KeyRef = ""
		cfg.Role = c.role
		_, err := loadPolicy(cfg, "inventory_file "+cfg.InventoryFile)
		if err == nil {
			t.Fatalf("role %v: a bundle admitting nothing started", c.role)
		}
		for _, w := range c.has {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("role %v: no %q in %v", c.role, w, err)
			}
		}
		for _, w := range c.hasNot {
			if strings.Contains(err.Error(), w) {
				t.Errorf("role %v: %q in %v", c.role, w, err)
			}
		}
	}
}

// C2 at start: with a broker, a world-writable inventory file refuses the
// start, and a private one is what the reloader starts from.
func TestAStartReadsTheInventoryBehindTheFence(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	cfg.InventoryFile = filepath.Join(safeDir(t), "inventory.yaml")
	body := "devices: [{name: leaf1, platform: arista_eos, key_ref: lab_key}]\n"
	if err := os.WriteFile(cfg.InventoryFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, v, err := fencedInventory(cfg)
	if err != nil || len(inv.Devices) != 1 || v != engine.HashOf([]byte(body)) {
		t.Fatalf("%+v %s %v", inv, v, err)
	}
	if err := os.Chmod(cfg.InventoryFile, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fencedInventory(cfg); err == nil || !strings.Contains(err.Error(), "inventory_file") {
		t.Fatalf("a world-writable inventory started: %v", err)
	}
}

// A fault in the fenced bytes names the inventory file, as bundle.LoadInventory
// does, so the operator is sent to the inventory, not the policy.
func TestAFencedInventoryFaultNamesTheInventoryFile(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	cfg.InventoryFile = filepath.Join(safeDir(t), "inventory.yaml")
	for name, body := range map[string]string{
		"malformed": "devices: [{name: leaf1, keyref: lab_key}]\n",
		"invalid":   "devices: [{name: leaf1, platform: arista_eos}, {name: leaf1, platform: arista_eos}]\n",
		"one address twice": "devices: [{name: a, platform: arista_eos, addresses: [10.0.0.1]}, " +
			"{name: b, platform: arista_eos, addresses: [10.0.0.1]}]\n",
	} {
		if err := os.WriteFile(cfg.InventoryFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var ie *bundle.InventoryError
		if _, _, err := fencedInventory(cfg); !errors.As(err, &ie) || ie.Path != cfg.InventoryFile {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// With a broker, run refuses to start on an inventory file others could
// write, naming it, rather than serve from bytes anyone could have chosen.
func TestRunRefusesAnInventoryFileOthersCouldWrite(t *testing.T) {
	cfgPath := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	inv := filepath.Join(filepath.Dir(cfgPath), "inventory.yaml")
	if err := os.Chmod(inv, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := runExpectingRefusal(t, cfgPath); err == nil || !strings.Contains(err.Error(), "inventory_file "+inv) ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("run: %v", err)
	}
}

// postAsAlice asks the broker at addr for a token on leaf1 over the lab
// client certificate in pkiDir, and returns the status and the body; the
// caller judges them. It never prints a token.
func postAsAlice(pkiDir, addr string) (int, string, error) {
	resp, body, err := postAsAliceResponse(pkiDir, addr)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, body, nil
}

// postAsAliceResponse is postAsAlice with the answer's headers.
func postAsAliceResponse(pkiDir, addr string) (*http.Response, string, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, testpki.LabClientCert), filepath.Join(pkiDir, testpki.LabClientKey))
	if err != nil {
		return nil, "", err
	}
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, testpki.LabCA))
	if err != nil {
		return nil, "", err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	resp, err := c.Post("https://"+addr+"/v1/tokens", "application/json", strings.NewReader(`{"devices":["leaf1"]}`))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, string(body), err
}

// aliceCertKey is the mark key of the lab client certificate, as Identity
// spells it.
func aliceCertKey(t *testing.T, pkiDir string) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, testpki.LabClientCert), filepath.Join(pkiDir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return store.CertKey(leaf.Issuer.String(), leaf.SerialNumber.Text(16))
}

// brokerReadyz asks the broker at addr for /readyz over TLS with no client
// certificate, trusting the lab CA in pkiDir, and returns the status and
// the trimmed body.
func brokerReadyz(t *testing.T, pkiDir, addr string) (int, string) {
	t.Helper()
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(caPEM)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := hc.Get("https://" + addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(body))
}

// gatedWriter is a syncBuffer whose write of a line containing gate blocks
// until release is closed, after closing hit: a test holds run at the
// point it says that line.
type gatedWriter struct {
	syncBuffer
	gate    string
	hit     chan struct{}
	release chan struct{}
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(g.gate)) {
		close(g.hit)
		<-g.release
	}
	return g.syncBuffer.Write(p)
}

// From the moment shutdown begins, the broker's /readyz answers 503
// draining while the broker still serves: a load balancer takes this
// replica out before its listener closes, not after (design §12). run is
// held at its "draining" line, which it says after SetReady(ReadyDraining)
// and before brokerSrv.Shutdown, so the probe lands in that window every
// time.
func TestRunAnswersDrainingBeforeTheBrokerCloses(t *testing.T) {
	out := &gatedWriter{gate: "port49d: signal received, draining", hit: make(chan struct{}),
		release: make(chan struct{})}
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = out, io.Discard
	release := sync.OnceFunc(func() { close(out.release) })
	t.Cleanup(release) // a failed probe must not leave run held
	b := brokerConfig(t, minimalPolicy).Broker
	pki := filepath.Dir(b.ClientCAFile)
	cfgPath := writeRunConfig(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	waitFor(t, &out.syncBuffer, "port49d: broker listening on ")
	addr := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
	if code, body := brokerReadyz(t, pki, addr); code != 200 || body != broker.ReadyServing {
		t.Fatalf("broker /readyz serving: %d %q", code, body)
	}

	cancel()
	select {
	case <-out.hit:
	case <-time.After(10 * time.Second):
		t.Fatal("run never said it was draining")
	}
	code, body := brokerReadyz(t, pki, addr)
	release()
	if code != 503 || body != broker.ReadyDraining {
		t.Fatalf("broker /readyz draining: %d %q", code, body)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

// run restores the marks before the broker serves a request, and refuses
// to start on a file it cannot load or a directory others can write: the
// wiring is the point of the file, and a unit test of loadRevocations
// would pass with the restore moved after Serve (pre-flight I7).
func TestRunRestoresRevocationsBeforeTheBrokerServes(t *testing.T) {
	// port49d is started three times on one config: the first start
	// creates the file and alice mints; each restart finds one mark in the
	// file, as Revoke's Persist leaves it, and alice's first connection is
	// answered credential_revoked as it binds, by certificate and then by
	// principal. The
	// listener's copy refuses before any mint can read the store's; the
	// store's copy is the next subtest's.
	t.Run("a mark in the file holds across a restart", func(t *testing.T) {
		var out syncBuffer
		e, o := stderr, stdout
		t.Cleanup(func() { stderr, stdout = e, o })
		stderr, stdout = &out, io.Discard
		b := brokerConfig(t, minimalPolicy).Broker
		pki := filepath.Dir(b.ClientCAFile)
		cfgPath := writeRunConfig(t, b)
		start := func() (addr string, stop func()) {
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
			waitForCount(t, &out, "port49d: broker listening on ", n+1)
			all := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindAllStringSubmatch(out.String(), -1)
			return all[len(all)-1][1], stop
		}

		addr, stop := start()
		waitFor(t, &out, "port49d: broker: 0 revocation(s) in force from "+b.RevocationsFile)
		if status, _, err := postAsAlice(pki, addr); err != nil || status != http.StatusOK {
			t.Fatalf("the first start's mint: %d %v", status, err)
		}
		// The broker's readiness, over its own TLS listener with no client
		// certificate (decision 34).
		if code, body := brokerReadyz(t, pki, addr); code != 200 || body != broker.ReadyServing {
			t.Fatalf("broker /readyz: %d %q", code, body)
		}
		stop()

		at := time.Date(2026, 10, 2, 3, 12, 9, 0, time.UTC)
		for i, mark := range []store.Revocation{
			{Kind: store.RevocationCert, Key: aliceCertKey(t, pki), At: at, Origin: "admin_socket uid 0"},
			{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: at, Origin: "admin_socket uid 0"},
		} {
			held := memory.New(time.Now)
			if err := held.PutRevocation(context.Background(), mark); err != nil {
				t.Fatal(err)
			}
			if err := persister(held, b.RevocationsFile, nil, nil, newMetrics())(context.Background()); err != nil {
				t.Fatal(err)
			}
			addr, stop := start()
			waitForCount(t, &out, "port49d: broker: 1 revocation(s) in force from "+b.RevocationsFile, i+1)
			// Refused by the listener, the restored mark's time and all:
			// the request reaches no handler.
			status, body, err := postAsAlice(pki, addr)
			if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) ||
				!strings.Contains(body, "revoked at 2026-10-02T03:12:09Z") {
				t.Fatalf("by %s: alice's connection: %s %v", mark.Kind, reply(status, body), err)
			}
			waitForCount(t, &out, "as it bound: user:alice@example.com or its certificate is revoked", i+1)
			stop()
		}
	})

	// The store's copy: the marks restoreRevocations put in the store are
	// the ones every mint reads, so a connection that bound before the
	// listener heard of a mark is still refused at its first mint.
	t.Run("a restored mark refuses the mint", func(t *testing.T) {
		cfg := brokerConfig(t, minimalPolicy)
		if err := os.WriteFile(cfg.Broker.RevocationsFile+".created", []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg.Broker.RevocationsFile, []byte(`{"revocations":[{"kind":"principal",`+
			`"key":"user:alice@example.com","at":"2026-10-02T03:12:09Z","origin":"admin_socket uid 0"}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		st := memory.New(time.Now)
		if _, err := restoreRevocations(context.Background(), st, cfg.Broker.RevocationsFile); err != nil {
			t.Fatal(err)
		}
		srv, _, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, st, seedMinter(),
			decision.NewJSONLines(io.Discard), newMetrics())
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go srv.ServeTLS(ln, "", "")
		t.Cleanup(func() { srv.Close() })
		status, body, err := postAsAlice(filepath.Dir(cfg.Broker.ClientCAFile), ln.Addr().String())
		if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, "credential_revoked") {
			t.Fatalf("the first mint after a restore with alice revoked: %s %v", reply(status, body), err)
		}
	})

	for name, prepare := range map[string]func(t *testing.T, b *config.BrokerConfig){
		"a file that does not parse": func(t *testing.T, b *config.BrokerConfig) {
			if err := os.WriteFile(b.RevocationsFile+".created", []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(b.RevocationsFile, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a file deleted after the first start": func(t *testing.T, b *config.BrokerConfig) {
			if err := os.WriteFile(b.RevocationsFile+".created", []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a directory its group can write": func(t *testing.T, b *config.BrokerConfig) {
			if err := os.Chmod(filepath.Dir(b.RevocationsFile), 0o770); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := brokerConfig(t, minimalPolicy).Broker
			// Its own directory, so the chmod case does not loosen the
			// directory holding the policy and the PKI.
			own := safeDir(t)
			b.RevocationsFile = filepath.Join(own, "revocations.json")
			prepare(t, b)
			out, err := runExpectingRefusal(t, writeRunConfig(t, b))
			if err == nil || !strings.Contains(err.Error(), "broker.revocations_file "+b.RevocationsFile) {
				t.Fatalf("run: %v", err)
			}
			if strings.Contains(out, "listening") {
				t.Fatalf("stderr claims a listener is up: %q", out)
			}
			if _, err := os.Lstat(b.RevocationsFile); name != "a file that does not parse" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused start wrote the file: %v", err)
			}
		})
	}
}
