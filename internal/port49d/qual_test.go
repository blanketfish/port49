package port49d

// TestQual plays every profile in tests/qual/profiles against a real port49d
// under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with
// tokens the broker mints (plan 11b; spec §13 decision 52). Per PR, at 0.1
// time scale against handshake_timeout 1s: production's ratio.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/devicemock"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

const qualRoot = "../.."

func TestQual(t *testing.T) {
	paths, _ := filepath.Glob("../../tests/qual/profiles/*/*.yaml")
	if len(paths) == 0 {
		t.Skip("no profiles yet (Task 14 adds the first wave)")
	}
	for _, path := range paths {
		p, err := devicemock.Load(path, qualRoot)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(p.Platform+"/"+p.Firmware, func(t *testing.T) { qualProfile(t, p, qualRoot) })
	}
}

// qualLongJunosRole is a readonly role whose juniper_junos projection renders
// allow-commands and deny-commands each under 255 bytes and together over it.
// The test that uses it fails loudly if that stops being true.
const qualLongJunosRole = `
  - name: qual_long
    privilege: readonly
    permit:
      - "show interfaces **"
      - "show route **"
      - "show chassis alarms **"
      - "show bgp **"
      - "show ospf **"
      - "show isis **"
      - "show lldp **"
      - "show arp **"
      - "show version **"
      - "show mpls **"
      - "show ldp **"
      - "show rsvp **"
`

func TestQualFixtureJunosRuleFailsWhatThePlainFixturePasses(t *testing.T) {
	// A Junos grant whose reply's attributes are each under 255 bytes and
	// together over it (port49 never sends one attribute over 255: spec §6, "Length").
	pol := qualPolicyWith(t, qualLongJunosRole)
	for _, c := range []struct {
		profile string
		gated   bool
	}{{"fixture_junos.yaml", true}, {"fixture_plain.yaml", false}} {
		p, err := devicemock.Load("../devicemock/testdata/profiles/"+c.profile, "../devicemock/testdata")
		if err != nil {
			t.Fatal(err)
		}
		run := qualDaemon(t, p, qualOpts{policy: pol, scale: 0.1})
		tr, err := devicemock.Play(t.Context(), p, "token_login", run.target(p, 0), run.login(0))
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.profile, err, tr)
		}
		if len(tr.Steps) < 2 {
			t.Fatalf("%s: the play has no authorize_session step\n%s", c.profile, tr)
		}
		total := 0
		for _, a := range tr.Steps[1].Args {
			if len(a) >= 255 {
				t.Fatalf("an attribute is %d bytes; each must stay under 255 (spec §6)", len(a))
			}
			total += len(a)
		}
		if total <= 255 {
			t.Fatalf("the fixture policy renders %d bytes; lengthen qualLongJunosRole until it passes 255\n%s", total, tr)
		}
		fails, _ := devicemock.Judge(tr, devicemock.GoldenFrom(tr)) // against itself: only gates can fail
		if c.gated && !slices.ContainsFunc(fails, func(f string) bool { return strings.Contains(f, "junos_reply_total") }) {
			t.Fatalf("%s: the reply total rule did not gate: %q\n%s", c.profile, fails, tr)
		}
		if (len(fails) > 0) != c.gated {
			t.Fatalf("%s: failures %q, gated want %v\n%s", c.profile, fails, c.gated, tr)
		}
	}
}

func TestQualNXOSRealFlightUnderTheDefault(t *testing.T) {
	// The real numbers once: the N9Kv's 5.00 s flight (tests/lab/results/L73-cisco_nxos.md)
	// against the 10s default handshake_timeout, judged from port49's log: the device was
	// served, not merely finished writing (a TLS 1.3 client is done when it writes).
	p := qualFixture(t, "fixture_nxos_flight.yaml")
	run := qualDaemon(t, p, qualOpts{scale: 1}) // handshakeTimeout 0: the daemon's default
	tr, err := devicemock.Play(t.Context(), p, "flight_delay", run.target(p, 0), run.login(0))
	if err != nil || tr.Outcome != "login_ok" {
		t.Fatalf("%v\n%s", err, tr)
	}
	// login_ok needs a PASS over TLS, which only a served device gets; the log
	// check adds that no handshake timed out on the way.
	if run.logged(`"tls_outcome":"handshake_timeout"`) {
		t.Fatal("a handshake timed out at the real flight delay under the default")
	}
}

func TestQualAFlightPastTheTimeoutIsHandshakeTimeout(t *testing.T) {
	p := qualFixture(t, "fixture_nxos_flight.yaml")
	run := qualDaemon(t, p, qualOpts{scale: 0.5, handshakeTimeout: time.Second}) // 2.5 s against 1 s
	tr, _ := devicemock.Play(t.Context(), p, "flight_delay", run.target(p, 0), run.login(0))
	if tr.Outcome != "handshake_refused" || !run.waitLogged(`"tls_outcome":"handshake_timeout"`, 10*time.Second) ||
		!run.waitLogged(`"diagnosis":"tls_refused"`, 10*time.Second) {
		t.Fatalf("a flight past handshake_timeout is refused as handshake_timeout\n%s", tr)
	}
	if ev := tr.Steps[len(tr.Steps)-1].Event; ev != "conn_reset" && ev != "conn_closed" {
		t.Fatalf("the device sees port49 end the connection: %q", ev)
	}
}

func TestQualWaitForPrintsNoHash(t *testing.T) {
	var buf syncBuffer
	buf.Write([]byte(`{"event":"redeem","auth":{"credential_sha256":"` + strings.Repeat("a", 64) + `"}}` + "\n"))
	msg := qualWaitMessage(&buf, "never")
	if strings.Contains(msg, "_sha256") || strings.Contains(msg, strings.Repeat("a", 64)) {
		t.Fatalf("a failure message carried a hash: %q", msg)
	}
	if !strings.Contains(msg, "redeem") {
		t.Fatalf("it still names the events seen: %q", msg)
	}
}

func TestQualSharesTheFragmentWithTheLab(t *testing.T) {
	p := qualFixture(t, "fixture_nxos_flight.yaml")
	run := qualDaemon(t, p, qualOpts{scale: 0.1, handshakeTimeout: time.Second})
	frag, err := os.ReadFile("../../tests/qual/qual-daemon.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(run.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := devicemock.MergeFragment(frag, frag)
	if err != nil || len(strings.TrimSpace(string(merged))) == 0 {
		t.Fatalf("the fragment did not merge: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(merged)), "\n") {
		if !strings.Contains(string(cfg), line) {
			t.Fatalf("the mock's config lacks the shared fragment's %q", line)
		}
	}
}

// qualOpts shapes one qualDaemon.
type qualOpts struct {
	policy           string        // "" is tests/qual/qual-policy.yaml
	scale            float64       // the mock's delay scale
	handshakeTimeout time.Duration // 0 is the daemon's default
	devices          int           // admitted devices; 0 and 1 are one
	transport        string        // devicemock.ScenarioTransport(sc); "" is the profile's first
	untrustedClient  bool          // tls: the device's leaf is from a CA the daemon does not hold
}

type qualRun struct {
	t          *testing.T
	opts       qualOpts
	p          *devicemock.Profile
	cfgPath    string
	log        *syncBuffer // the decision log
	stderr     *syncBuffer
	tcpAddr    string
	tlsAddr    string
	broker     string
	pkiDir     string
	key        []byte
	faults     string
	policyPath string // the broker's policy file, for touchPolicy
	policyText string
	touches    int
	clients    []tls.Certificate
	pool       *x509.CertPool
	minted     []string // kept only for the golden check: never printed
}

// qualDeviceName is the inventory name of device i.
func qualDeviceName(i int) string { return fmt.Sprintf("q%04d", i) }

var (
	qualTCPLine    = regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`)
	qualTLSLine    = regexp.MustCompile(`port49d: RFC 9887 listener on (127\.0\.0\.1:\d+)`)
	qualBrokerLine = regexp.MustCompile(`port49d: broker listening on (127\.0\.0\.1:\d+)`)
)

// qualDaemon starts a real port49d under the qualification policy and
// fragment, with one admitted device per o.devices.
func qualDaemon(t *testing.T, p *devicemock.Profile, o qualOpts) *qualRun {
	t.Helper()
	r := &qualRun{t: t, opts: o, p: p, log: &syncBuffer{}, stderr: &syncBuffer{}}
	if r.opts.transport == "" {
		r.opts.transport = p.Transports[0]
	}
	e, lo := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, lo })
	stderr, stdout = r.stderr, r.log

	policy := o.policy
	if policy == "" {
		raw, err := os.ReadFile("../../tests/qual/qual-policy.yaml")
		if err != nil {
			t.Fatal(err)
		}
		policy = string(raw)
	}
	b := brokerConfig(t, policy).Broker
	r.pkiDir = filepath.Dir(b.TLSCertFile)
	r.policyPath, r.policyText = b.PolicyFile, policy

	n := max(o.devices, 1)
	var inv strings.Builder
	inv.WriteString("devices:\n")
	for i := range n {
		addr := "127.0.0.1"
		if o.devices > 1 {
			addr = devicemock.LoopbackSource(i)
		}
		fmt.Fprintf(&inv, "  - {name: %s, platform: %s, addresses: [%s]", qualDeviceName(i), p.Platform, addr)
		if r.opts.transport == "tls" {
			inv.WriteString(", transport: tls")
		}
		inv.WriteString("}\n")
	}
	var extra strings.Builder
	switch r.opts.transport {
	case "tls":
		extra.WriteString(r.tlsBlock(t, n))
	case "tcp":
		inv.WriteString("key_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: k}\n")
	}
	r.faults = filepath.Join(t.TempDir(), "fault")
	fmt.Fprintf(&extra, "lab:\n  fault_file: %s\n", r.faults)

	cfg := writeRunConfigWith(t, b, inv.String(), extra.String())
	if r.opts.transport == "tcp" {
		kb := make([]byte, 32)
		if _, err := rand.Read(kb); err != nil {
			t.Fatal(err)
		}
		r.key = []byte(hex.EncodeToString(kb))
		t.Setenv("T_RUN_SECRET", string(r.key))
	}
	frag, err := os.ReadFile("../../tests/qual/qual-daemon.yaml")
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := devicemock.MergeFragment(base, frag)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, merged, 0o600); err != nil {
		t.Fatal(err)
	}
	r.cfgPath = cfg

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()
	t.Cleanup(func() { // before stderr and stdout are put back
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("port49d did not exit within 10s of its context ending")
		}
	})
	qualWaitFor(t, r.stderr, "port49d: broker listening on ", 10*time.Second)
	qualWaitFor(t, r.stderr, "port49d: listening on ", 10*time.Second)
	r.broker = qualBrokerLine.FindStringSubmatch(r.stderr.String())[1]
	r.tcpAddr = qualTCPLine.FindStringSubmatch(r.stderr.String())[1]
	if r.opts.transport == "tls" {
		qualWaitFor(t, r.stderr, "port49d: RFC 9887 listener on ", 10*time.Second)
		r.tlsAddr = qualTLSLine.FindStringSubmatch(r.stderr.String())[1]
	}
	return r
}

// tlsBlock issues the daemon's server certificate and one client certificate
// per device, and returns the tls_listener block. With untrustedClient the
// client certificates come from a CA the daemon's client_ca_file lacks.
func (r *qualRun) tlsBlock(t *testing.T, n int) string {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("Qual Device CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	clientCA := ca
	if r.opts.untrustedClient {
		if clientCA, err = testpki.NewCA("Qual Other CA", now.Add(-time.Hour), now.Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := ca.Issue(testpki.Leaf{DNSNames: []string{qualServerName}, IPs: testpki.Loopback(),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		cli, err := clientCA.Issue(testpki.Leaf{DNSNames: []string{qualDeviceName(i)}, Client: true,
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		r.clients = append(r.clients, cli)
	}
	r.pool = ca.Pool()
	certPEM, keyPEM, err := testpki.PEMs(srv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string][]byte{"device-ca.pem": ca.PEM(), "srv.crt": certPEM, "srv.key": keyPEM}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	block := "tls_listener:\n  listen: \"127.0.0.1:0\"\n  cert_file: " + filepath.Join(dir, "srv.crt") +
		"\n  key_file: " + filepath.Join(dir, "srv.key") + "\n  client_ca_file: " + filepath.Join(dir, "device-ca.pem") +
		"\n  server_names: [" + qualServerName + "]\n  certificate_status: {disabled: true}\n"
	if r.opts.handshakeTimeout != 0 {
		block += fmt.Sprintf("  handshake_timeout: %s\n", r.opts.handshakeTimeout)
	}
	return block
}

const qualServerName = "tacacs.example.net"

// target is the devicemock.Target for device i.
func (r *qualRun) target(p *devicemock.Profile, i int) devicemock.Target {
	tg := devicemock.Target{Transport: r.opts.transport, Scale: r.opts.scale}
	if r.opts.devices > 1 {
		tg.LocalAddr = devicemock.LoopbackSource(i)
	}
	switch r.opts.transport {
	case "tls":
		tg.Addr = r.tlsAddr
		tg.TLS = &devicemock.TLSMaterial{Client: r.clients[i], ServerCAs: r.pool, ServerIP: "127.0.0.1",
			ServerName: qualServerName}
	default:
		tg.Addr, tg.Key = r.tcpAddr, r.key
	}
	return tg
}

// login is a fresh login for device i: the broker mints a token every call,
// which is kept for the golden check and never printed.
func (r *qualRun) login(i int) devicemock.Login {
	tok := mint(r.t, r.broker, r.pkiDir, qualDeviceName(i))
	r.minted = append(r.minted, tok)
	return devicemock.Login{User: "qual01", Credential: []byte(tok), RemAddr: "198.51.100.4"}
}

// touchPolicy rewrites the policy file with one more harmless deny, a real
// change the broker's policy watch reloads. The deny alternates between two
// Junos keyword paths the keyword tree proves (platforms/keywords/1.3.0/
// juniper_junos.yaml), so every touch changes the file and none makes a Junos
// projection fail closed. It calls no t helper: fleet mode calls it from a
// goroutine, so the error is returned.
func (r *qualRun) touchPolicy() error {
	r.touches++
	cmd := []string{"show system uptime", "show system alarms"}[r.touches%2]
	text := strings.ReplaceAll(r.policyText, `deny: ["show users"]`, `deny: ["show users", "`+cmd+`"]`)
	text = strings.ReplaceAll(text, `deny: ["show system users"]`, `deny: ["show system users", "`+cmd+`"]`)
	if text == r.policyText {
		return errors.New("touchPolicy: the policy has no qual_denies deny to extend")
	}
	tmp := r.policyPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.policyPath)
}

// fault puts the lab fault in force. It calls no t helper: fleet mode calls it
// from a goroutine, so the error is returned for the test goroutine to check.
func (r *qualRun) fault(code string) error { return os.WriteFile(r.faults, []byte(code), 0o600) }

// logged reports whether the decision log holds s; said, whether stderr does.
func (r *qualRun) logged(s string) bool { return strings.Contains(r.log.String(), s) }
func (r *qualRun) said(s string) bool   { return strings.Contains(r.stderr.String(), s) }

// waitLogged polls the decision log until it holds s, within d. A device sees
// port49 end a connection before port49 has written the record that says why,
// so a record is awaited, never read once.
func (r *qualRun) waitLogged(s string, d time.Duration) bool {
	for end := time.Now().Add(d); !r.logged(s); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			return false
		}
	}
	return true
}

// qualWaitFor polls buf until it holds want, or fails with a message that
// carries no credential hash.
func qualWaitFor(t *testing.T, buf *syncBuffer, want string, d time.Duration) {
	t.Helper()
	for end := time.Now().Add(d); !strings.Contains(buf.String(), want); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal(qualWaitMessage(buf, want))
		}
	}
}

// qualWaitMessage names what was waited for, the event and reason of the last
// 20 JSON lines in buf, and its non-JSON lines that hold no _sha256.
func qualWaitMessage(buf *syncBuffer, want string) string {
	var events, plain []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			ev, _ := m["event"].(string)
			why, _ := m["reason"].(string)
			events = append(events, strings.TrimSpace(ev+" "+why))
		} else if line != "" && !strings.Contains(line, "_sha256") {
			plain = append(plain, line)
		}
	}
	if len(events) > 20 {
		events = events[len(events)-20:]
	}
	return fmt.Sprintf("waited for %q; last events %q; other lines %q", want, events, plain)
}

// qualPolicyWith is the qualification policy with role (a roles-list entry, in
// YAML) added and granted to the operator on all_devices in place of qual_admin;
// the per-platform deny grants stay.
func qualPolicyWith(t *testing.T, role string) string {
	t.Helper()
	raw, err := os.ReadFile("../../tests/qual/qual-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pol := strings.Replace(string(raw), "\nsubjects:", role+"subjects:", 1)
	name := regexp.MustCompile(`name: (\w+)`).FindStringSubmatch(role)[1]
	out := strings.Replace(pol, "scope: all_devices, roles: [qual_admin]", "scope: all_devices, roles: ["+name+"]", 1)
	if out == pol {
		t.Fatal("the qualification policy's grant line moved")
	}
	return out
}

// qualFixture loads a devicemock test profile.
func qualFixture(t *testing.T, name string) *devicemock.Profile {
	t.Helper()
	root := "../devicemock/testdata"
	if name == "fixture_nxos_flight.yaml" {
		root = qualRoot
	}
	p, err := devicemock.Load("../devicemock/testdata/profiles/"+name, root)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// qualProfile plays each of p's scenarios against its own daemon and judges
// the replies against the golden.
// It returns every credential and key it minted, so a test can check that
// none reached a golden; nothing prints them.
func qualProfile(t *testing.T, p *devicemock.Profile, root string) (secrets []string) {
	t.Helper()
	update := os.Getenv("PORT49_QUAL_UPDATE") == "1"
	if p.Golden == "" {
		t.Fatalf("%s %s names no golden", p.Platform, p.Firmware)
	}
	goldenPath := filepath.Join(root, p.Golden)
	g, err := loadQualGolden(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	minted := &secrets
	changed := false
	for _, sc := range p.Scenarios {
		t.Run(sc, func(t *testing.T) {
			run := qualDaemon(t, p, qualOpts{scale: 0.1, handshakeTimeout: time.Second,
				transport: devicemock.ScenarioTransport(sc), untrustedClient: sc == "tls_unknown_ca"})
			if sc == "store_unavailable" || sc == "tls_store_unavailable" {
				if err := run.fault("store_unavailable"); err != nil {
					t.Fatal(err)
				}
			}
			tr, err := devicemock.Play(t.Context(), p, sc, run.target(p, 0), run.login(0))
			*minted = append(*minted, run.minted...)
			*minted = append(*minted, string(run.key))
			if err != nil {
				t.Fatalf("%v\n%s", err, tr)
			}
			if sc == "tls_unknown_ca" && (!run.waitLogged(`"diagnosis":"tls_refused"`, 10*time.Second) || !run.waitLogged(`"tls_outcome":"unknown_ca"`, 10*time.Second)) {
				t.Errorf("port49 did not log the untrusted device as tls_refused / unknown_ca\n%s", tr)
			}
			fails, warns := devicemock.Judge(tr, g.Scenarios[sc])
			for _, w := range warns {
				t.Log(w)
			}
			if update {
				if got := devicemock.GoldenFrom(tr); fmt.Sprint(got) != fmt.Sprint(g.Scenarios[sc]) {
					g.Scenarios[sc], g.PendingLab, changed = got, true, true
				}
				for _, f := range fails {
					if !strings.Contains(f, "moved from the golden") {
						t.Error(f)
					}
				}
				return
			}
			for _, f := range fails {
				t.Errorf("%s\n%s\ngolden: %+v", f, tr, g.Scenarios[sc])
			}
		})
	}
	if p.Stimulus.TLS != nil {
		t.Run("hello_probe", func(t *testing.T) {
			run := qualDaemon(t, p, qualOpts{scale: 0.1, handshakeTimeout: time.Second, transport: "tls"})
			got, err := devicemock.Probe(t.Context(), &net.Dialer{}, run.tlsAddr, p.Stimulus.TLS.ClientHello, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if got != p.Stimulus.TLS.ServerHello {
				t.Errorf("port49's ServerHello %+v is not the profile's %+v", got, p.Stimulus.TLS.ServerHello)
			}
		})
	}
	if update && changed {
		if err := devicemock.WriteGolden(goldenPath, g); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(goldenPath)
		if strings.Contains(string(raw), "_sha256") {
			t.Error("the golden holds a hash")
		}
		for _, m := range *minted {
			if m != "" && strings.Contains(string(raw), m) {
				t.Error("the golden holds a minted credential")
			}
		}
	}
	return secrets
}

// loadQualGolden reads a golden. Only a missing file is an empty golden: a
// corrupt one is an error, never a golden to overwrite.
func loadQualGolden(path string) (devicemock.Golden, error) {
	g, err := devicemock.LoadGolden(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		g, err = devicemock.Golden{}, nil
	case err != nil:
		return devicemock.Golden{}, fmt.Errorf("golden %s: %w", path, err)
	}
	if g.Scenarios == nil {
		g.Scenarios = map[string]devicemock.GoldenScenario{}
	}
	return g, nil
}

// TestQualProfileHarness runs the path TestQual takes for each profile, on
// fixtures: update writes a golden, verify passes against it. The nxos copy
// adds tls_unknown_ca, which reaches untrustedClient, and the hello probe;
// the tcp copy reaches fault through store_unavailable.
func TestQualProfileHarness(t *testing.T) {
	for _, c := range []struct {
		fixture   string
		scenarios []string
	}{
		{"fixture_plain.yaml", nil},
		{"fixture_nxos_flight.yaml", []string{"flight_delay", "tls_unknown_ca"}},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			p := qualFixture(t, c.fixture)
			p.Golden = "g.json"
			if c.scenarios != nil {
				p.Scenarios = c.scenarios
			}
			root := t.TempDir()
			t.Setenv("PORT49_QUAL_UPDATE", "1")
			secrets := qualProfile(t, p, root)
			raw, err := os.ReadFile(filepath.Join(root, "g.json"))
			if err != nil {
				t.Fatalf("update wrote no golden: %v", err)
			}
			g, err := devicemock.LoadGolden(filepath.Join(root, "g.json"))
			if err != nil || !g.PendingLab || len(g.Scenarios) != len(p.Scenarios) {
				t.Fatalf("the written golden: pending_lab %v, %d scenarios, %v", g.PendingLab, len(g.Scenarios), err)
			}
			if strings.Contains(string(raw), "_sha256") {
				t.Error("the golden holds a hash")
			}
			if len(secrets) == 0 {
				t.Fatal("no minted credential was tracked")
			}
			for _, s := range secrets {
				if s != "" && strings.Contains(string(raw), s) {
					t.Error("the golden holds a minted credential or key")
				}
			}
			t.Setenv("PORT49_QUAL_UPDATE", "")
			qualProfile(t, p, root) // verify: the golden it just wrote passes
		})
	}
}

func TestQualGoldenOnlyAMissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	g, err := loadQualGolden(filepath.Join(dir, "none.json"))
	if err != nil || len(g.Scenarios) != 0 {
		t.Fatalf("a missing golden is empty: %+v %v", g, err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"scenarios": {`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadQualGolden(bad); err == nil {
		t.Fatal("a corrupt golden loaded as empty")
	}
}

// The qualification policy's deny must project on every platform: a deny that
// fails closed on one would make its golden vet a login that can run nothing.
func TestQualPolicyProjectsOnEveryPlatform(t *testing.T) {
	for _, plat := range []string{"juniper_junos", "cisco_nxos", "cisco_iosxe", "arista_eos"} {
		t.Run(plat, func(t *testing.T) {
			p := qualFixture(t, "fixture_plain.yaml")
			p.Platform = plat
			run := qualDaemon(t, p, qualOpts{scale: 0.1})
			run.login(0)
			seen := false
			for _, line := range strings.Split(run.log.String(), "\n") {
				var m struct {
					Event string
					Blob  struct {
						Body struct {
							Platform   string
							FailClosed string `json:"fail_closed"`
							Attributes []string
						}
					}
				}
				if json.Unmarshal([]byte(line), &m) != nil || m.Event != "blob" {
					continue
				}
				seen = true
				total := 0
				for _, a := range m.Blob.Body.Attributes {
					total += len(a)
				}
				if m.Blob.Body.FailClosed != "" || total > 255 {
					t.Errorf("%s renders fail_closed=%q, %d attribute bytes", plat, m.Blob.Body.FailClosed, total)
				}
				if plat == "juniper_junos" && !slices.ContainsFunc(m.Blob.Body.Attributes, func(a string) bool {
					return strings.HasPrefix(a, "deny-commands=")
				}) {
					t.Error("juniper_junos renders no deny-commands attribute: its deny did not project")
				}
			}
			if !seen {
				t.Fatal("no blob was logged")
			}
		})
	}
}

// The per-command platforms ask port49 about each command: the qual policy's
// deny must hold there (the command_denied probe), and a permitted command pass.
func TestQualPolicyDeniesTheProbeOnPerCommandPlatforms(t *testing.T) {
	for _, plat := range []string{"cisco_nxos", "cisco_iosxe", "arista_eos"} {
		t.Run(plat, func(t *testing.T) {
			p := qualFixture(t, "fixture_plain.yaml")
			p.Platform = plat
			run := qualDaemon(t, p, qualOpts{scale: 0.1})
			dev := tacacsClient{t: t, addr: run.tcpAddr, key: run.key}
			if st := dev.login("qual01", string(run.login(0).Credential)); st != wire.AuthenStatusPass {
				t.Fatalf("login: status %d", st)
			}
			// NX-OS has no privilege levels and asks every command at 1; the others ask at 15
			// once the session reply has granted it.
			priv := uint8(15)
			if plat == "cisco_nxos" {
				priv = 1
			}
			dev.authorize("qual01")
			if dev.permitsAt(priv, "qual01", "show", "users") {
				t.Error("show users was permitted: the command_denied probe would not hold")
			}
			// The refusal is the deny's, on this request: the last authorize_command record.
			rec := lastCommand(t, run.log)
			vec, _ := rec["request"].(map[string]any)["vector"].([]any)
			if rec["reason"] != "no_permit_dominates_deny" || fmt.Sprint(vec) != "[show users]" {
				t.Errorf("the show users refusal is %v for %v; want no_permit_dominates_deny", rec["reason"], vec)
			}
			if !dev.permitsAt(priv, "qual01", "show", "version") {
				t.Error("show version was refused")
			}
		})
	}
}

// Every platform the qual policy knows is in exactly one deny scope, so one
// deny reaches it and no other platform's deny does.
func TestQualPolicyDeniesOncePerPlatform(t *testing.T) {
	raw, err := os.ReadFile("../../tests/qual/qual-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var pol struct {
		Scopes []struct {
			Name  string
			Match map[string]any
		}
	}
	if err := yaml.Unmarshal(raw, &pol); err != nil {
		t.Fatal(err)
	}
	for _, plat := range append(platform.Names(), "cisco_iosxr", "nokia_srlinux") {
		n := 0
		for _, sc := range pol.Scopes {
			switch v := sc.Match["platform"].(type) {
			case string:
				if v == plat {
					n++
				}
			case []any:
				if slices.Contains(v, any(plat)) {
					n++
				}
			}
		}
		if n != 1 {
			t.Errorf("%s is in %d platform scopes; want exactly 1", plat, n)
		}
	}
}
