package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tlsBase writes a no-broker port49d.yaml with one TLS device, the files a
// tls_listener names (contents unread by Load), and block appended.
func tlsBase(t *testing.T, top, block string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"srv.crt", "srv.key", "ca.pem", "inter.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: tls-1, platform: arista_eos, addresses: [10.0.0.9], transport: tls}\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("T_ENC", "33333333333333333333333333333333")
	body := top + "metrics_listen: 127.0.0.1:0\ninventory_file: " + inv + "\n" +
		"encryption:\n  current: {id: v1, secret_env: T_ENC}\naccounting: {spool_path: " + filepath.Join(dir, "acct.jsonl") + "}\n" +
		strings.ReplaceAll(block, "DIR", dir)
	p := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const tlsMinimal = `tls_listener:
  cert_file: DIR/srv.crt
  key_file: DIR/srv.key
  client_ca_file: DIR/ca.pem
  certificate_status: {disabled: true}
`

func TestTLSListenerDefaults(t *testing.T) {
	c, err := Load(tlsBase(t, "listen: 127.0.0.1:0\n", tlsMinimal))
	if err != nil {
		t.Fatal(err)
	}
	tl := c.TLSListener
	if tl == nil || tl.Listen != ":300" || tl.HandshakeTimeout != 5*time.Second || tl.SessionTicketLifetime != 0 ||
		tl.ExpiryWarningFraction != 0.33 || tl.ReloadInterval != time.Minute {
		t.Fatalf("defaults: %+v", tl)
	}
	off, err := Load(tlsBase(t, "listen: 127.0.0.1:0\n", tlsMinimal+"  expiry_warning_fraction: 0\n"))
	if err != nil || off.TLSListener.ExpiryWarningFraction != 0 {
		t.Fatalf("an explicit 0 is off, not the default: %v %+v", err, off.TLSListener)
	}
	if got := tl.DeviceIdentity.Match; len(got) != 2 || got[0] != "dns_name" || got[1] != "ip_address" {
		t.Fatalf("match default: %v", got)
	}
}

func TestListenNone(t *testing.T) {
	c, err := Load(tlsBase(t, "listen: none\n", tlsMinimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "" {
		t.Fatalf("listen: none is the empty Listen, got %q", c.Listen)
	}
	if _, err := Load(tlsBase(t, "listen: none\n", "")); err == nil ||
		!strings.Contains(err.Error(), "serves no TACACS+ listener") {
		t.Fatalf("neither listener: %v", err)
	}
}

func TestTLSListenerRefusals(t *testing.T) {
	for name, c := range map[string]struct{ top, block, want string }{
		"same bind": {"listen: 0.0.0.0:300\n", tlsMinimal, "same address as listen"},
		"wildcard against a host": {"listen: \":300\"\n",
			strings.Replace(tlsMinimal, "tls_listener:\n", "tls_listener:\n  listen: 10.0.0.1:300\n", 1), "same address as listen"},
		"no cert_file": {"", strings.Replace(tlsMinimal, "  cert_file: DIR/srv.crt\n", "", 1), "tls_listener.cert_file is required"},
		"no client_ca_file": {"", strings.Replace(tlsMinimal, "  client_ca_file: DIR/ca.pem\n", "", 1),
			"tls_listener.client_ca_file is required"},
		"no certificate_status": {"", strings.Replace(tlsMinimal, "  certificate_status: {disabled: true}\n", "", 1),
			"tls_listener.certificate_status is required"},
		"unknown match": {"", tlsMinimal + "  device_identity: {match: [common_name]}\n", "dns_name or ip_address"},
		"empty match":   {"", tlsMinimal + "  device_identity: {match: []}\n", "dns_name or ip_address"},
		"suffix without dns_name": {"", tlsMinimal + "  device_identity: {match: [ip_address], dns_suffixes: [example.net]}\n",
			"dns_suffixes needs dns_name"},
		"wildcard suffix":      {"", tlsMinimal + "  device_identity: {dns_suffixes: [\"*.example.net\"]}\n", "not a DNS suffix"},
		"wildcard server name": {"", tlsMinimal + "  server_names: [\"*.example.net\"]\n", "not a server name"},
		"handshake too long":   {"", tlsMinimal + "  handshake_timeout: 1m\n", "between 1s and 30s"},
		"tickets too long":     {"", tlsMinimal + "  session_ticket_lifetime: 2h\n", "between 0s and 1h"},
		"reload too fast":      {"", tlsMinimal + "  reload_interval: 1s\n", "between 10s and 1h"},
		"a fraction of 1":      {"", tlsMinimal + "  expiry_warning_fraction: 1\n", "at least 0 and below 1"},
		"crls without state_dir": {"", strings.Replace(tlsMinimal, "certificate_status: {disabled: true}",
			"certificate_status: {crls: [{name: issuing, file: DIR/ca.pem, issuer_file: DIR/ca.pem}]}", 1),
			"tls_listener.state_dir is required"},
	} {
		top := c.top
		if top == "" {
			top = "listen: 127.0.0.1:0\n"
		}
		if _, err := Load(tlsBase(t, top, c.block)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestTLSListenerStatusIsTheBrokersShape(t *testing.T) {
	block := strings.Replace(tlsMinimal, "certificate_status: {disabled: true}",
		"certificate_status: {crls: [{name: issuing, url: \"http://crl.example.net/i.crl\", issuer_file: DIR/ca.pem}]}", 1) +
		"  state_dir: DIR\n"
	c, err := Load(tlsBase(t, "listen: 127.0.0.1:0\n", block))
	if err != nil {
		t.Fatal(err)
	}
	cs := c.TLSListener.CertificateStatus
	if cs.OnUnavailable != "refuse" || cs.RefreshInterval != 10*time.Minute {
		t.Fatalf("the broker's defaults apply: %+v", cs)
	}
	// Its lists are kept in a subdirectory of their own, so a state_dir the
	// broker's checker also uses never holds one crl-issuing.der for both.
	if got, want := TLSListenerStateDir(c.TLSListener), filepath.Join(filepath.Dir(c.TLSListener.CertFile), "tls_listener"); got != want {
		t.Fatalf("TLSListenerStateDir: %s, want %s", got, want)
	}
	bad := strings.Replace(tlsMinimal, "certificate_status: {disabled: true}",
		"certificate_status: {crls: [{name: issuing, url: \"http://crl.example.net/i.crl\", issuer_file: DIR/ca.pem}], "+
			"on_unavailable: maybe}", 1) + "  state_dir: DIR\n"
	if _, err := Load(tlsBase(t, "listen: 127.0.0.1:0\n", bad)); err == nil ||
		!strings.Contains(err.Error(), "tls_listener.certificate_status.on_unavailable must be refuse or allow") {
		t.Fatalf("on_unavailable: %v", err)
	}
}

func TestTheBrokerRefusesATLSListener(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49-broker.yaml")
	if err := os.WriteFile(p, []byte("tls_listener:\n  cert_file: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// brokerRefusals runs right after the decode, before any required key
	// is asked for.
	_, err := LoadBroker(p)
	if err == nil || !strings.Contains(err.Error(), "tls_listener is not port49-broker.yaml's") {
		t.Fatalf("port49-broker.yaml with tls_listener: %v", err)
	}
}

// tlsInventory replaces the inventory tlsBase wrote.
func tlsInventory(t *testing.T, cfgPath, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(cfgPath), "inventory.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTLSNamesThatCannotBeToldApartAreRefusedNotFatal(t *testing.T) {
	const inv = "devices:\n" +
		"  - {name: leaf-01, platform: arista_eos, addresses: [10.0.0.1], transport: tls}\n" +
		"  - {name: Leaf-01.Example.NET, platform: arista_eos, addresses: [10.0.0.2], transport: tls}\n" +
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.3], transport: tls}\n"
	suffixed := tlsMinimal + "  device_identity: {dns_suffixes: [example.net]}\n"
	p := tlsBase(t, "listen: 127.0.0.1:0\n", suffixed)
	tlsInventory(t, p, inv)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("a clash refuses the two devices, never the load: %v", err)
	}
	for _, a := range []string{"10.0.0.1", "10.0.0.2"} {
		if _, ok := c.Admission.Lookup(netip.MustParseAddr(a)); ok {
			t.Errorf("%s is admitted", a)
		}
	}
	if r, ok := c.Admission.Lookup(netip.MustParseAddr("10.0.0.3")); !ok || r.Refused != "" {
		t.Errorf("leaf-02 was refused with them: %+v", r)
	}
	notices := strings.Join(c.Notices, "\n")
	for _, want := range []string{"leaf-01", "Leaf-01.Example.NET", "tls_name_clash"} {
		if !strings.Contains(notices, want) {
			t.Errorf("the start notices do not name %q: %q", want, notices)
		}
	}
	// Without the suffix the two names differ and both are admitted.
	p = tlsBase(t, "listen: 127.0.0.1:0\n", tlsMinimal)
	tlsInventory(t, p, inv)
	c, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Admission.Lookup(netip.MustParseAddr("10.0.0.1")); !ok || len(c.Notices) != 0 {
		t.Errorf("no suffix, no clash: %q", c.Notices)
	}
}

func TestANonASCIITLSNameIsRefusedAtLoad(t *testing.T) {
	p := tlsBase(t, "listen: 127.0.0.1:0\n", tlsMinimal)
	tlsInventory(t, p, "devices:\n"+
		"  - {name: \"léaf-01\", platform: arista_eos, addresses: [10.0.0.1], transport: tls}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.0.3], transport: tls}\n")
	c, err := Load(p)
	if err != nil {
		t.Fatalf("a name no certificate can carry refuses the device, never the load: %v", err)
	}
	if _, ok := c.Admission.Lookup(netip.MustParseAddr("10.0.0.1")); ok {
		t.Error("the non-ASCII device is admitted")
	}
	if _, ok := c.Admission.Lookup(netip.MustParseAddr("10.0.0.3")); !ok {
		t.Error("leaf-02 was refused with it")
	}
	if n := strings.Join(c.Notices, "\n"); !strings.Contains(n, "tls_name_invalid") || !strings.Contains(n, "léaf-01") {
		t.Errorf("the start notices do not name it: %q", n)
	}
}
