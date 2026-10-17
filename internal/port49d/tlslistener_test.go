package port49d

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// devicePKI is a device CA, port49's TLS server certificate under it, and
// leaf1's client certificate, written to files.
type devicePKI struct {
	ca                        *testpki.CA
	caFile, certFile, keyFile string
	client                    tls.Certificate
}

func writeDevicePKI(t *testing.T) devicePKI {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	ca, err := testpki.NewCA("Device CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ca.Issue(testpki.Leaf{DNSNames: []string{"tacacs.example.net"}, IPs: testpki.Loopback(),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ca.Issue(testpki.Leaf{DNSNames: []string{"leaf1"}, Client: true,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(srv)
	if err != nil {
		t.Fatal(err)
	}
	p := devicePKI{ca: ca, caFile: filepath.Join(dir, "device-ca.pem"), certFile: filepath.Join(dir, "srv.crt"),
		keyFile: filepath.Join(dir, "srv.key"), client: cli}
	for path, body := range map[string][]byte{p.caFile: ca.PEM(), p.certFile: certPEM, p.keyFile: keyPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func (p devicePKI) block(listen string, extra ...string) string {
	return "tls_listener:\n  listen: \"" + listen + "\"\n  cert_file: " + p.certFile + "\n  key_file: " + p.keyFile +
		"\n  client_ca_file: " + p.caFile + "\n  server_names: [tacacs.example.net]\n" +
		"  certificate_status: {disabled: true}\n" + strings.Join(extra, "")
}

// tlsLogin logs user in over the RFC 9887 listener as leaf1.
func tlsLogin(t *testing.T, addr string, p devicePKI, user, password string) uint8 {
	t.Helper()
	st, _, err := tlsLoginWith(p, addr, p.client, nil, user, password)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// tlsLoginWith logs user in presenting cert, with cache for resumption, and
// reports the reply's status and whether the handshake resumed a ticket.
func tlsLoginWith(p devicePKI, addr string, cert tls.Certificate, cache tls.ClientSessionCache, user,
	password string) (uint8, bool, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.ca.Pool(), ServerName: "tacacs.example.net",
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, ClientSessionCache: cache})
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte(user), Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"),
		Data: []byte(password)}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, Flags: wire.FlagUnencrypted, SessionID: 0x5eed,
		Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), body...)); err != nil {
		return 0, false, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(conn, hb); err != nil {
		return 0, false, fmt.Errorf("no reply over TLS: %w", err)
	}
	rh, _ := wire.DecodeHeader(hb)
	rb := make([]byte, rh.Length)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return 0, false, err
	}
	r, err := wire.DecodeAuthenReply(rb)
	if err != nil {
		return 0, false, err
	}
	return r.Status, conn.ConnectionState().DidResume, nil
}

func TestRunServesBothListenersApart(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	pkiDir := filepath.Dir(b.TLSCertFile)
	p := writeDevicePKI(t)
	cfgPath := writeRunConfigWith(t, b, `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}
`, p.block("127.0.0.1:0"))
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
	find := func(re string) string {
		m := regexp.MustCompile(re).FindStringSubmatch(out.String())
		if m == nil {
			t.Fatalf("no %q in stderr: %q", re, out.String())
		}
		return m[1]
	}
	tcpAddr := find(`port49d: listening on (127\.0\.0\.1:\d+)`)
	tlsAddr := find(`port49d: RFC 9887 listener on (127\.0\.0\.1:\d+)`)
	brokerAddr := find(`broker listening on (127\.0\.0\.1:\d+)`)
	for _, want := range []string{"RFC 9887 §5.1.1", "recorded transport_changed, not blocked",
		"holds both the shared keys and the TLS key", "1 devices transport tls", "tls_listener: anchors CN=Device CA"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stderr lacks %q: %s", want, out.String())
		}
	}

	if st := tlsLogin(t, tlsAddr, p, "alice", mint(t, brokerAddr, pkiDir, "leaf1")); st != wire.AuthenStatusPass {
		t.Fatalf("login over TLS: %d; log %s", st, log.String())
	}
	if !strings.Contains(log.String(), `"transport":"tls"`) || !strings.Contains(log.String(), `"cert_sha256":"`) {
		t.Fatalf("the redeem record names the transport and the certificate: %s", log.String())
	}

	// The same device on the RFC 8907 listener: one header, then a reset.
	conn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 1, Length: 4}
	conn.Write(append(h.Encode(), 0, 0, 0, 0))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("a tls device on 49 was answered: %d %v", n, err)
	}
	waitFor(t, &log, `"diagnosis":"transport_mismatch"`)
}

func TestListenNoneSaysTheRFC8907ListenerIsOff(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	b := brokerConfig(t, minimalPolicy).Broker
	p := writeDevicePKI(t)
	cfgPath := writeRunConfigWith(t, b, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}\n",
		p.block("127.0.0.1:0"))
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(string(raw), `listen: "127.0.0.1:0"`+"\nmetrics_listen",
		"listen: none\nmetrics_listen", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, &out, "port49d: RFC 8907 listener off (listen: none)")
	if strings.Contains(out.String(), "RFC 9887 §5.1.1") {
		t.Fatal("a TLS-only port49d said the same-host notice")
	}
}

func TestTLSMaterialReloadKeepsTheOldOnABadFile(t *testing.T) {
	p := writeDevicePKI(t)
	var lines []string
	say := func(f string, a ...any) { lines = append(lines, strings.TrimSpace(fmt.Sprintf(f, a...))) }
	cfg := config.TLSListenerConfig{Listen: ":0", CertFile: p.certFile, KeyFile: p.keyFile, ClientCAFile: p.caFile,
		DeviceIdentity: config.DeviceIdentityConfig{Match: []string{"dns_name", "ip_address"}}}
	l, err := newTLSListener(cfg, nil, nil, false, nil, time.Now, say)
	if err != nil {
		t.Fatal(err)
	}
	first := l.Material()
	l.reload("SIGHUP")
	if l.Material() != first {
		t.Fatal("unchanged files swapped the material")
	}
	if err := os.WriteFile(p.certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	l.reload("reload_interval")
	l.reload("reload_interval")
	if l.Material() != first {
		t.Fatal("a bad file replaced the material in force")
	}
	refusals := 0
	for _, line := range lines {
		if strings.Contains(line, "not reloaded, the files in force stay") {
			refusals++
		}
	}
	if refusals != 1 {
		t.Fatalf("a refusal is said once: %q", lines)
	}
	p2 := writeDevicePKI(t)
	certPEM, err := os.ReadFile(p2.certFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(p2.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p.certFile, certPEM, 0o600)
	os.WriteFile(p.keyFile, keyPEM, 0o600)
	l.reload("SIGHUP")
	if l.Material() == first || !strings.Contains(strings.Join(lines, "\n"), "SIGHUP: reloaded") {
		t.Fatalf("a good set was not swapped in: %q", lines)
	}
}

func TestTLSMaterialRefusesANonCAAnchor(t *testing.T) {
	p := writeDevicePKI(t)
	certPEM, _, err := testpki.PEMs(p.client)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p.caFile, certPEM, 0o600)
	cfg := config.TLSListenerConfig{CertFile: p.certFile, KeyFile: p.keyFile, ClientCAFile: p.caFile,
		DeviceIdentity: config.DeviceIdentityConfig{Match: []string{"dns_name"}}}
	if _, err := newTLSListener(cfg, nil, nil, false, nil, time.Now, func(string, ...any) {}); err == nil ||
		!strings.Contains(err.Error(), "is not a CA certificate") {
		t.Fatalf("a leaf as an anchor: %v", err)
	}
}

func TestRefusalSayerGathersStatusUnavailable(t *testing.T) {
	var lines []string
	now := time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC)
	r := &refusalSayer{now: func() time.Time { return now }, say: func(f string, a ...any) {
		lines = append(lines, fmt.Sprintf(f, a...))
	}}
	stale := devicecert.Verdict{Outcome: devicecert.StatusUnavailable, Detail: "CRL issuing: past its next update"}
	for i := 1; i <= 8; i++ {
		r.said(fmt.Sprintf("leaf-%02d", i), "10.0.0.1", stale)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "leaf-01") {
		t.Fatalf("the first device is said at once, the rest gathered: %q", lines)
	}
	r.flush()
	if len(lines) != 2 || !strings.Contains(lines[1], "7 devices declined status_unavailable") ||
		!strings.Contains(lines[1], "leaf-02, leaf-03, leaf-04, leaf-05, leaf-06 and 2 more") {
		t.Fatalf("one gathered line: %q", lines)
	}
	r.flush()
	if len(lines) != 2 {
		t.Fatalf("nothing gathered, nothing said: %q", lines)
	}
	expired := devicecert.Verdict{Outcome: devicecert.CertificateExpired, Detail: "x"}
	r.said("leaf-01", "10.0.0.1", expired)
	r.said("leaf-01", "10.0.0.1", expired)
	if len(lines) != 3 {
		t.Fatalf("a device's own refusal is said once per 10m: %q", lines)
	}
}

// reissueServer replaces the server certificate and key files with another
// certificate from the same device CA, as a renewal does.
func (p devicePKI) reissueServer(t *testing.T) {
	t.Helper()
	now := time.Now()
	srv, err := p.ca.Issue(testpki.Leaf{DNSNames: []string{"tacacs.example.net"}, IPs: testpki.Loopback(),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(srv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// listenerCfg is the loaded tls_listener block for p, as config.Load leaves it.
func (p devicePKI) listenerCfg() config.TLSListenerConfig {
	return config.TLSListenerConfig{Listen: ":0", CertFile: p.certFile, KeyFile: p.keyFile, ClientCAFile: p.caFile,
		DeviceIdentity:   config.DeviceIdentityConfig{Match: []string{"dns_name", "ip_address"}},
		HandshakeTimeout: 5 * time.Second, ReloadInterval: time.Minute}
}

// lineSink collects the lines a listener says.
type lineSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *lineSink) say(f string, a ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, strings.TrimSpace(fmt.Sprintf(f, a...)))
}

func (s *lineSink) all() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

func (s *lineSink) count(sub string) int {
	return strings.Count(s.all(), sub)
}

var (
	tlsDev = func(name string) admission.Device {
		return admission.Device{Name: name, Platform: "arista_eos", Transport: admission.TransportTLS,
			Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	}
)

// Carry 1: the material carries the devices the rule cannot identify, each
// named once with its reason, and an inventory change recomputes them.
func TestTLSMaterialCarriesUnidentifiableAndFollowsTheInventory(t *testing.T) {
	p := writeDevicePKI(t)
	var sink lineSink
	devs := []admission.Device{tlsDev("leaf1"), tlsDev("leaf1.example.net"), tlsDev("spine1")}
	var mu sync.Mutex
	cfg := p.listenerCfg()
	cfg.DeviceIdentity = config.DeviceIdentityConfig{Match: []string{"dns_name"}, DNSSuffixes: []string{"example.net"}}
	l, err := newTLSListener(cfg, nil, nil, false, func() []admission.Device {
		mu.Lock()
		defer mu.Unlock()
		return devs
	}, time.Now, sink.say)
	if err != nil {
		t.Fatal(err)
	}
	m := l.Material()
	if len(m.Unidentifiable) != 2 || m.Unidentifiable["leaf1"] == "" || m.Unidentifiable["leaf1.example.net"] == "" {
		t.Fatalf("the clashing pair is flagged, spine1 is not: %v", m.Unidentifiable)
	}
	for _, name := range []string{"leaf1", "leaf1.example.net"} {
		if n := sink.count("tls_listener: device " + name + " cannot be identified"); n != 1 {
			t.Fatalf("%s is named once at the start, got %d: %s", name, n, sink.all())
		}
	}
	if strings.Contains(sink.all(), "spine1") {
		t.Fatalf("an identifiable device is not named: %s", sink.all())
	}

	l.inventoryChanged("inventory") // nothing changed
	if l.Material() != m {
		t.Fatal("an inventory swap that changes no flag swapped the material")
	}

	mu.Lock()
	devs = []admission.Device{tlsDev("leaf1"), tlsDev("spine1")}
	mu.Unlock()
	l.inventoryChanged("inventory")
	if l.Material() == m || len(l.Material().Unidentifiable) != 0 {
		t.Fatalf("a swap that clears the clash recomputes the map: %v", l.Material().Unidentifiable)
	}
	if n := sink.count("tls_listener: device leaf1 cannot be identified"); n != 1 {
		t.Fatalf("a device is named once, not again at a recompute: %s", sink.all())
	}

	mu.Lock()
	devs = []admission.Device{tlsDev("leaf1"), tlsDev("leaf1.example.net")}
	mu.Unlock()
	l.inventoryChanged("inventory")
	if len(l.Material().Unidentifiable) != 2 {
		t.Fatalf("a clash that returns is flagged again: %v", l.Material().Unidentifiable)
	}
	if n := sink.count("tls_listener: device leaf1 cannot be identified"); n != 2 {
		t.Fatalf("a device flagged anew is named anew: %s", sink.all())
	}
}

// Carry 1, on a bad file: the inventory change still reaches the material,
// built from the last good files.
func TestTLSMaterialFollowsTheInventoryWhileAFileIsBad(t *testing.T) {
	p := writeDevicePKI(t)
	var sink lineSink
	var mu sync.Mutex
	devs := []admission.Device{tlsDev("leaf1")}
	cfg := p.listenerCfg()
	cfg.DeviceIdentity = config.DeviceIdentityConfig{Match: []string{"dns_name"}, DNSSuffixes: []string{"example.net"}}
	l, err := newTLSListener(cfg, nil, nil, false, func() []admission.Device {
		mu.Lock()
		defer mu.Unlock()
		return devs
	}, time.Now, sink.say)
	if err != nil {
		t.Fatal(err)
	}
	certDER := l.Material().Config.Certificates[0].Certificate[0]
	if err := os.WriteFile(p.certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	devs = []admission.Device{tlsDev("leaf1"), tlsDev("leaf1.example.net")}
	mu.Unlock()
	l.reload("reload_interval")
	if len(l.Material().Unidentifiable) != 2 {
		t.Fatalf("a bad file must not freeze the flags: %v", l.Material().Unidentifiable)
	}
	if !strings.Contains(sink.all(), "not reloaded, the files in force stay") {
		t.Fatalf("the bad file is said: %s", sink.all())
	}
	// The files in force are still the good ones, and the line says so
	// rather than "reloaded".
	if got := l.Material().Config.Certificates[0].Certificate[0]; !bytes.Equal(got, certDER) {
		t.Fatal("the certificate in force was replaced by the bad file")
	}
	if !strings.Contains(sink.all(), "kept: anchors CN=Device CA") ||
		!strings.Contains(sink.all(), "reload_interval: files unchanged; devices the rule cannot identify recomputed (2)") ||
		strings.Contains(sink.all(), "reload_interval: reloaded") {
		t.Fatalf("m1 wording: %s", sink.all())
	}
}

// The files going back to the bytes in force clear a refusal, and say so.
func TestTLSReloadSaysWhenAFailureClears(t *testing.T) {
	p := writeDevicePKI(t)
	var sink lineSink
	l, err := newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now, sink.say)
	if err != nil {
		t.Fatal(err)
	}
	first := l.Material()
	good, err := os.ReadFile(p.certFile)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p.certFile, []byte("junk"), 0o600)
	l.reload("reload_interval")
	os.WriteFile(p.certFile, good, 0o600)
	l.reload("reload_interval")
	if l.Material() != first || sink.count("the files load again; the set in force is unchanged") != 1 {
		t.Fatalf("a failure that clears is said once: %s", sink.all())
	}
	l.reload("reload_interval")
	if sink.count("the files load again") != 1 {
		t.Fatalf("and not again: %s", sink.all())
	}
}

// Carry 2: the material carries the ticket guard when the lifetime is above
// 0s, and tickets are off otherwise.
func TestTLSMaterialCarriesTheTicketGuard(t *testing.T) {
	p := writeDevicePKI(t)
	cfg := p.listenerCfg()
	l, err := newTLSListener(cfg, nil, nil, false, nil, time.Now, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if l.Material().Tickets != nil || !l.Material().Config.SessionTicketsDisabled {
		t.Fatal("session_ticket_lifetime 0s issues no ticket")
	}
	cfg.SessionTicketLifetime = time.Minute
	l, err = newTLSListener(cfg, nil, nil, false, nil, time.Now, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if l.Material().Tickets == nil || l.Material().Config.SessionTicketsDisabled {
		t.Fatal("session_ticket_lifetime above 0s must put the guard in the material, or tickets are silently off")
	}
}

// Carry 3, in the whole daemon: a ticket survives a SIGHUP that changes no
// file, and does not survive a renewed certificate.
func TestRunTicketsSurviveANoOpSIGHUPButNotAFileChange(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	pkiDir := filepath.Dir(b.TLSCertFile)
	p := writeDevicePKI(t)
	cfgPath := writeRunConfigWith(t, b, `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`, p.block("127.0.0.1:0", "  session_ticket_lifetime: 5m\n"))
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
	tlsAddr := regexp.MustCompile(`RFC 9887 listener on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())[1]
	brokerAddr := regexp.MustCompile(`broker listening on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())[1]

	cache := tls.NewLRUClientSessionCache(4)
	login := func() (uint8, bool) {
		st, resumed, err := tlsLoginWith(p, tlsAddr, p.client, cache, "alice", mint(t, brokerAddr, pkiDir, "leaf1"))
		if err != nil {
			t.Fatal(err)
		}
		return st, resumed
	}
	if st, resumed := login(); st != wire.AuthenStatusPass || resumed {
		t.Fatalf("the first login is a full handshake that passes: %d resumed %v", st, resumed)
	}
	hup := func(line string) {
		t.Helper()
		n := strings.Count(out.String(), line)
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		waitForCount(t, &out, line, n+1)
	}
	hup("port49d: policy reload (SIGHUP): broker.policy_file unchanged")
	if st, resumed := login(); st != wire.AuthenStatusPass || !resumed {
		t.Fatalf("a SIGHUP that changes no file keeps the tickets: %d resumed %v", st, resumed)
	}

	p.reissueServer(t)
	hup("tls_listener: SIGHUP: reloaded")
	if st, resumed := login(); st != wire.AuthenStatusPass || resumed {
		t.Fatalf("a renewed certificate ends every outstanding ticket: %d resumed %v", st, resumed)
	}
	if st, resumed := login(); st != wire.AuthenStatusPass || !resumed {
		t.Fatalf("and the new material issues tickets again: %d resumed %v", st, resumed)
	}
	if n := strings.Count(out.String(), "tls_listener: config changes take effect at restart; files reload now"); n != 1 {
		t.Fatalf("the config note is said once, at the first SIGHUP: %d", n)
	}
}

// Carry 4: server names are lower case with no trailing dot, whatever the
// config said.
func TestTLSServerNamesAreFoldedAtLoad(t *testing.T) {
	cfg := config.TLSListenerConfig{ServerNames: []string{"TACACS.Example.NET.", "b.example.net"}}
	got := tlsServerNames(cfg)
	if len(got) != 2 || got[0] != "tacacs.example.net" || got[1] != "b.example.net" {
		t.Fatalf("server names: %q", got)
	}
	if cfg.ServerNames[0] != "TACACS.Example.NET." {
		t.Fatal("the config's own slice was rewritten in place")
	}
}

// Carry 5: only Good is good.
func TestStatusOfOnlyMapsGoodToGood(t *testing.T) {
	cases := []struct {
		name string
		v    certstatus.Verdict
		want devicecert.Status
	}{
		{"good", certstatus.Good, devicecert.StatusGood},
		{"revoked", certstatus.Revoked, devicecert.StatusRevoked},
		{"unknown", certstatus.Unknown, devicecert.StatusUnknown},
		{"a verdict this code has never seen", certstatus.Verdict(99), devicecert.StatusUnknown},
		{"a negative verdict", certstatus.Verdict(-1), devicecert.StatusUnknown},
	}
	for _, c := range cases {
		st, detail := statusOf(certstatus.Result{Verdict: c.v, Source: "crl", Name: "x", Detail: "d", RevokedAt: time.Now()})
		if st != c.want {
			t.Errorf("%s: %v, want %v", c.name, st, c.want)
		}
		if c.want == devicecert.StatusUnknown && detail == "" {
			t.Errorf("%s: an unknown status says why", c.name)
		}
	}
}

// Carry 6, in the whole daemon: a refused device is said on stderr, once.
func TestRunSaysARefusedDeviceOnceOnStderr(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log

	b := brokerConfig(t, minimalPolicy).Broker
	p := writeDevicePKI(t)
	cfgPath := writeRunConfigWith(t, b, `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`, p.block("127.0.0.1:0"))
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
	tlsAddr := regexp.MustCompile(`RFC 9887 listener on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())[1]

	other, err := p.ca.Issue(testpki.Leaf{DNSNames: []string{"not-leaf1"}, Client: true,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := tlsLoginWith(p, tlsAddr, other, nil, "alice", "x"); err == nil {
			t.Fatal("a certificate naming another device logged in")
		}
	}
	waitFor(t, &log, `"tls_outcome":"identity_mismatch"`)
	waitFor(t, &out, "tls_listener: leaf1 (127.0.0.1) refused: identity_mismatch: ")
	time.Sleep(200 * time.Millisecond)
	if n := strings.Count(out.String(), "refused: identity_mismatch"); n != 1 {
		t.Fatalf("a refusal is said once per device and outcome, got %d: %s", n, out.String())
	}
	if strings.Contains(out.String(), "BEGIN") {
		t.Fatalf("stderr carries PEM: %s", out.String())
	}
}

// Carry 7: the checker's directory exists before it starts, owner-only.
func TestTLSListenerOfMakesItsStateDir(t *testing.T) {
	p := writeDevicePKI(t)
	state := filepath.Join(t.TempDir(), "state")
	tc := p.listenerCfg()
	tc.StateDir = state
	tc.CertificateStatus = &config.CertificateStatusConfig{OCSP: &config.CertificateStatusOCSP{
		Responder: "http://127.0.0.1:1/", Timeout: time.Second, Hash: "sha256"}, RefreshInterval: time.Hour}
	l, chk, err := tlsListenerOf(config.Config{TLSListener: &tc}, metrics.New(prometheus.NewRegistry()),
		func(string, ...any) {}, nil)
	if err != nil || l == nil || chk == nil {
		t.Fatalf("tlsListenerOf: %v %v %v", l, chk, err)
	}
	fi, err := os.Stat(filepath.Join(state, "tls_listener"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the listener's state directory: %v %v", fi, err)
	}
}

// Carry 8: the first load refuses a CA file that does not parse, by file;
// a reload keeps the last good material and says so.
func TestTLSListenerRefusesAnUnparseableCAFileAtStart(t *testing.T) {
	for name, status := range map[string]*config.CertificateStatusConfig{
		"status disabled": {Disabled: true},
		"status enabled": {OCSP: &config.CertificateStatusOCSP{Responder: "http://127.0.0.1:1/", Timeout: time.Second,
			Hash: "sha256"}, RefreshInterval: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			p := writeDevicePKI(t)
			if err := os.WriteFile(p.caFile, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc := p.listenerCfg()
			tc.CertificateStatus = status
			l, _, err := tlsListenerOf(config.Config{TLSListener: &tc}, metrics.New(prometheus.NewRegistry()),
				func(string, ...any) {}, nil)
			if err == nil || l != nil {
				t.Fatalf("an unparseable client_ca_file must refuse the start: %v %v", l, err)
			}
			if !strings.Contains(err.Error(), p.caFile) || !strings.Contains(err.Error(), "client_ca_file") {
				t.Fatalf("the error names the key and the file: %v", err)
			}
		})
	}
	t.Run("empty file", func(t *testing.T) {
		p := writeDevicePKI(t)
		os.WriteFile(p.caFile, []byte("nothing here\n"), 0o600)
		_, err := newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now, func(string, ...any) {})
		if err == nil || !strings.Contains(err.Error(), p.caFile) {
			t.Fatalf("a client_ca_file with no certificate names itself: %v", err)
		}
	})
	t.Run("intermediates", func(t *testing.T) {
		p := writeDevicePKI(t)
		inter := filepath.Join(t.TempDir(), "inter.pem")
		os.WriteFile(inter, []byte("nothing here\n"), 0o600)
		cfg := p.listenerCfg()
		cfg.IntermediatesFile = inter
		_, err := newTLSListener(cfg, nil, nil, false, nil, time.Now, func(string, ...any) {})
		if err == nil || !strings.Contains(err.Error(), inter) {
			t.Fatalf("an intermediates_file with no certificate names itself: %v", err)
		}
	})
}

func TestTLSReloadWithABadCAFileKeepsTheMaterial(t *testing.T) {
	p := writeDevicePKI(t)
	var sink lineSink
	l, err := newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now, sink.say)
	if err != nil {
		t.Fatal(err)
	}
	first := l.Material()
	os.WriteFile(p.caFile, []byte("garbage"), 0o600)
	l.reload("SIGHUP")
	if l.Material() != first || l.Material() == nil {
		t.Fatal("a bad CA file replaced the material in force")
	}
	if !strings.Contains(sink.all(), "not reloaded, the files in force stay") || !strings.Contains(sink.all(), p.caFile) {
		t.Fatalf("the refusal names the file: %s", sink.all())
	}
}

// Carry 9: a failed first load publishes nothing, and a load that follows
// failures never leaves nil behind.
func TestTLSListenerNeverPublishesNilMaterial(t *testing.T) {
	p := writeDevicePKI(t)
	cfg := p.listenerCfg()
	cfg.CertFile = filepath.Join(t.TempDir(), "missing.crt")
	l, err := newTLSListener(cfg, nil, nil, false, nil, time.Now, func(string, ...any) {})
	if err == nil || l != nil {
		t.Fatalf("a missing cert_file at the first load: %v %v", l, err)
	}
	l, err = newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p.certFile, p.keyFile, p.caFile} {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
		l.reload("reload_interval")
		if l.Material() == nil {
			t.Fatalf("material nil after %s went missing", f)
		}
	}
}

// Decision 50 ruling 4: devices on a transport no listener serves are named
// at the start.
func TestRunNamesDevicesWhoseTransportIsNotServed(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfigWith(t, b, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}\n"+
		"key_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n", "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, &out, "port49d: broker listening on ")
	waitFor(t, &out, "port49d: 1 devices have transport tls and port49d serves no tls_listener; their "+
		"connections here are declined transport_mismatch: leaf1")
	if strings.Contains(out.String(), "RFC 9887 listener on") {
		t.Fatalf("no tls_listener, no TLS line: %s", out.String())
	}
}

// The reloader tells the listener: each policy or inventory swap recomputes
// the devices the rule cannot identify, and a SIGHUP re-reads the files.
func TestReloaderHooksTheTLSListener(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	p := writeDevicePKI(t)
	var mu sync.Mutex
	devs := []admission.Device{tlsDev("leaf1")}
	var sink lineSink
	cfg := p.listenerCfg()
	cfg.DeviceIdentity = config.DeviceIdentityConfig{Match: []string{"dns_name"}, DNSSuffixes: []string{"example.net"}}
	tl, err := newTLSListener(cfg, nil, nil, false, func() []admission.Device {
		mu.Lock()
		defer mu.Unlock()
		return devs
	}, time.Now, sink.say)
	if err != nil {
		t.Fatal(err)
	}
	hookTLSReload(rig.r, tl, rig.cfg, rig.b.Policy)
	mat := tl.Material()

	mu.Lock()
	devs = []admission.Device{tlsDev("leaf1"), tlsDev("leaf1.example.net")}
	mu.Unlock()
	swapTo(t, rig, showOnly)
	if tl.Material() == mat || len(tl.Material().Unidentifiable) != 2 {
		t.Fatalf("a swap must reach the listener's flags: %v", tl.Material().Unidentifiable)
	}

	p.reissueServer(t)
	before := tl.Material()
	rig.r.onHUP()
	if tl.Material() == before || !strings.Contains(sink.all(), "SIGHUP: reloaded") {
		t.Fatalf("a SIGHUP re-reads the files: %s", sink.all())
	}
}

// judge is what the material in force makes of cert for leaf1: the path and
// identity, then the status, as a handshake does.
func judge(t *testing.T, l *tlsListener, cert tls.Certificate) devicecert.Outcome {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	dev := admission.Device{Name: "leaf1", Platform: "arista_eos", Transport: admission.TransportTLS,
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	mat := l.Material()
	v := mat.Verifier.Verify([]*x509.Certificate{leaf}, dev)
	if v.Outcome == devicecert.OK {
		v = mat.Verifier.CheckStatus(context.Background(), v)
	}
	return v.Outcome
}

// rotation is a listener over device CA p.ca whose status comes from one
// file CRL, and the files to rotate it with.
type rotation struct {
	p                devicePKI
	l                *tlsListener
	sink             *lineSink
	issuer, crlFile  string
	oldCert, newCert tls.Certificate
	newCA            *testpki.CA
}

func newRotation(t *testing.T) *rotation {
	t.Helper()
	r := &rotation{p: writeDevicePKI(t), sink: &lineSink{}}
	dir := safeDir(t)
	now := time.Now()
	r.issuer, r.crlFile = filepath.Join(dir, "issuer.pem"), filepath.Join(dir, "dev.crl")
	os.WriteFile(r.issuer, r.p.ca.PEM(), 0o600)
	os.WriteFile(r.crlFile, crl(t, r.p.ca, now.Add(-time.Minute), now.Add(time.Hour)), 0o600)
	var err error
	if r.newCA, err = testpki.NewCA("Device CA 2", now.Add(-time.Hour), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.newCert, err = r.newCA.Issue(testpki.Leaf{DNSNames: []string{"leaf1"}, Client: true,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r.oldCert = r.p.client
	tc := r.p.listenerCfg()
	tc.StateDir = filepath.Join(dir, "state")
	tc.CertificateStatus = &config.CertificateStatusConfig{RefreshInterval: time.Minute,
		CRLs: []config.CertificateStatusCRL{{Name: "dev", File: r.crlFile, IssuerFile: r.issuer}}}
	l, chk, err := tlsListenerOf(config.Config{TLSListener: &tc}, metrics.New(prometheus.NewRegistry()), r.sink.say, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.l = l
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { chk.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	r.eventually(t, "the first list", func() bool { return judge(t, l, r.oldCert) == devicecert.OK })
	return r
}

func (r *rotation) eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !f(); {
		if time.Now().After(end) {
			t.Fatalf("waited for %s; lines: %s", what, r.sink.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Ruling 15: client_ca_file reloads without a restart, and the status
// checker's issuers follow it: a device under the new CA with a good CRL is
// admitted, and one under the old CA no longer is.
func TestTLSCARotationFollowsInTheStatusChecker(t *testing.T) {
	r := newRotation(t)
	now := time.Now()
	os.WriteFile(r.p.caFile, r.newCA.PEM(), 0o600)
	os.WriteFile(r.issuer, r.newCA.PEM(), 0o600)
	os.WriteFile(r.crlFile, crl(t, r.newCA, now.Add(-time.Minute), now.Add(time.Hour)), 0o600)
	r.l.reload("reload_interval")
	r.eventually(t, "a new-CA device with a good CRL to be admitted", func() bool {
		return judge(t, r.l, r.newCert) == devicecert.OK
	})
	if got := judge(t, r.l, r.oldCert); got != devicecert.UnknownCA {
		t.Fatalf("the old CA no longer admits: %s", got)
	}
	if !strings.Contains(r.sink.all(), "the trust set changed") {
		t.Fatalf("the follow is said: %s", r.sink.all())
	}
}

// A new anchor no source can answer for is said once, with what to add.
func TestTLSNewAnchorWithoutAStatusSourceIsSaid(t *testing.T) {
	r := newRotation(t)
	both := append(r.p.ca.PEM(), r.newCA.PEM()...)
	os.WriteFile(r.p.caFile, both, 0o600)
	r.l.reload("reload_interval")
	r.l.reload("reload_interval")
	sum := sha256.Sum256(r.newCA.Cert.Raw)
	want := "no source can answer for the new anchor CN=Device CA 2 (sha256 " + hex.EncodeToString(sum[:]) + ")"
	if r.sink.count(want) != 1 || !strings.Contains(r.sink.all(), "Add a crls entry whose issuer_file is that CA, or an "+
		"ocsp block, to tls_listener.certificate_status; that config edit takes effect at restart") {
		t.Fatalf("the uncovered anchor is said once: %s", r.sink.all())
	}
	if got := judge(t, r.l, r.newCert); got != devicecert.StatusUnavailable {
		t.Fatalf("until a source is added, the new CA's devices are declined: %s", got)
	}
}

// A rotation whose issuer file was not rotated with it leaves the sources
// as they were, and says why, once.
func TestTLSRotationWithAStaleIssuerFileSaysSo(t *testing.T) {
	r := newRotation(t)
	os.WriteFile(r.p.caFile, r.newCA.PEM(), 0o600)
	r.l.reload("reload_interval")
	r.l.reload("reload_interval")
	if r.sink.count("the certificate status sources keep the issuers they had") != 1 ||
		!strings.Contains(r.sink.all(), "neither a trust anchor") {
		t.Fatalf("a stale issuer file is said once: %s", r.sink.all())
	}
}

// Decision 50 ruling 6, ordering: the flags of an inventory about to be put
// in force are in the material before it is, so no connection is admitted
// under the new inventory without them; a device whose twin is leaving
// stays flagged until the swap is done.
func TestTLSSwappingFlagsBeforeTheInventoryIsInForce(t *testing.T) {
	p := writeDevicePKI(t)
	var mu sync.Mutex
	devs := []admission.Device{tlsDev("leaf1"), tlsDev("spine1")}
	cfg := p.listenerCfg()
	cfg.DeviceIdentity = config.DeviceIdentityConfig{Match: []string{"dns_name"}, DNSSuffixes: []string{"example.net"}}
	l, err := newTLSListener(cfg, nil, nil, false, func() []admission.Device {
		mu.Lock()
		defer mu.Unlock()
		return devs
	}, time.Now, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	l.swapping([]admission.Device{tlsDev("leaf1"), tlsDev("leaf1.example.net"), tlsDev("spine1")})
	if len(l.Material().Unidentifiable) != 2 {
		t.Fatalf("the new pair is flagged while the old inventory is still in force: %v", l.Material().Unidentifiable)
	}
	mu.Lock()
	devs = []admission.Device{tlsDev("leaf1"), tlsDev("leaf1.example.net"), tlsDev("spine1")}
	mu.Unlock()
	flagged := l.Material()
	l.inventoryChanged("inventory")
	if l.Material() != flagged {
		t.Fatal("the swap that follows finds the flags already right")
	}

	// The twin leaves: still flagged until it is gone from the inventory in force.
	l.swapping([]admission.Device{tlsDev("leaf1"), tlsDev("spine1")})
	if len(l.Material().Unidentifiable) != 2 {
		t.Fatalf("leaf1 stays flagged while its twin is still admitted: %v", l.Material().Unidentifiable)
	}
	mu.Lock()
	devs = []admission.Device{tlsDev("leaf1"), tlsDev("spine1")}
	mu.Unlock()
	l.inventoryChanged("inventory")
	if len(l.Material().Unidentifiable) != 0 {
		t.Fatalf("and clear once it is: %v", l.Material().Unidentifiable)
	}
}

// The reloader runs beforeSwap before it puts the policy in force.
func TestReloaderTellsTheListenerBeforeThePolicyIsInForce(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	p := writeDevicePKI(t)
	tl, err := newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	hookTLSReload(rig.r, tl, rig.cfg, rig.b.Policy)
	inner := rig.r.beforeSwap
	told, still := 0, false
	rig.r.beforeSwap = func(pol *policy.Policy) {
		told++
		still = rig.b.Policy.Load() != pol
		inner(pol)
	}
	swapTo(t, rig, showOnly)
	if told != 1 || !still {
		t.Fatalf("beforeSwap runs once, with the old policy still in force: %d %v", told, still)
	}
}

func TestTLSDepsFoldServerNames(t *testing.T) {
	p := writeDevicePKI(t)
	tl, err := newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	tc := p.listenerCfg()
	tc.ServerNames = []string{"TACACS.Example.NET."}
	d := newTLSDeps(tc, tl, &devicecert.Expiry{}, &refusalSayer{now: time.Now, say: func(string, ...any) {}})
	if len(d.ServerNames) != 1 || d.ServerNames[0] != "tacacs.example.net" || d.Material() != tl.Material() ||
		d.Said == nil || d.Seen == nil {
		t.Fatalf("server.TLS: %+v", d)
	}
}

// reload_interval reloads the files with no SIGHUP, in the whole daemon.
func TestRunWatchesTheFilesEveryReloadInterval(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	b := brokerConfig(t, minimalPolicy).Broker
	p := writeDevicePKI(t)
	cfgPath := writeRunConfigWith(t, b, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}\n"+
		"key_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n", p.block("127.0.0.1:0", "  reload_interval: 10s\n"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, &out, "port49d: broker listening on ")
	p.reissueServer(t)
	for end := time.Now().Add(25 * time.Second); !strings.Contains(out.String(), "tls_listener: reload_interval: reloaded"); {
		if time.Now().After(end) {
			t.Fatalf("no reload at reload_interval: %s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// SIGHUP with no broker: block still re-reads the TLS files.
func TestRunWithNoBrokerReloadsTheTLSFilesAtSIGHUP(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	b := brokerConfig(t, minimalPolicy).Broker
	p := writeDevicePKI(t)
	cfgPath := writeRunConfigWith(t, b, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1], transport: tls}\n"+
		"key_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n", "")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(cfgPath, append(raw[:strings.Index(string(raw), "\nbroker:")+1], p.block("127.0.0.1:0")...), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, &out, "port49d: RFC 9887 listener on ")
	p.reissueServer(t)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "tls_listener: SIGHUP: reloaded")
	waitFor(t, &out, "tls_listener: config changes take effect at restart; files reload now")
}
