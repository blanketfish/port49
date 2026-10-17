package lab

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestL73JunosLinesTypeTheDocumentedStatements(t *testing.T) {
	got := l73JunosLines(l73DeviceTLS{Server: "172.100.100.1"})
	want := []string{
		"delete system tacplus-server",
		"delete system accounting destination tacplus",
		"set system tacplus-server 172.100.100.1 routing-instance mgmt_junos",
		"set system tacplus-server 172.100.100.1 tls trusted-ca-group l73-trust",
		"set system tacplus-server 172.100.100.1 tls mutual-authentication certificate-id l73-dev",
		"set system accounting destination tacplus server 172.100.100.1 routing-instance mgmt_junos",
		"set system accounting destination tacplus server 172.100.100.1 tls trusted-ca-group l73-trust",
		"set system accounting destination tacplus server 172.100.100.1 tls mutual-authentication certificate-id l73-dev",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	got = l73JunosLines(l73DeviceTLS{Server: "172.100.100.1", Port: 300, SingleConnection: true,
		Second: "172.100.100.2", SecondTLS: false})
	for _, line := range []string{
		"set system tacplus-server 172.100.100.1 port 300",
		"set system tacplus-server 172.100.100.1 single-connection",
		"set system accounting destination tacplus server 172.100.100.1 port 300",
		"set system tacplus-server 172.100.100.2 routing-instance mgmt_junos",
		`set system tacplus-server 172.100.100.2 secret "labsecret"`,
	} {
		if !slices.Contains(got, line) {
			t.Errorf("missing %q", line)
		}
	}
	for _, line := range got {
		if strings.HasPrefix(line, "set system tacplus-server 172.100.100.2 tls") {
			t.Errorf("a plain second server carries tls: %q", line)
		}
		if strings.Contains(line, "172.100.100.1") && strings.Contains(line, "secret") {
			t.Errorf("a tls server carries a secret it was not asked for: %q", line)
		}
	}
}

func TestL73RestoreIsTheStartupConfigsServers(t *testing.T) {
	got := l73JunosRestore()
	want := []string{
		"delete system tacplus-server",
		"delete system accounting destination tacplus",
		"set system tacplus-server 172.100.100.1 routing-instance mgmt_junos",
		`set system tacplus-server 172.100.100.1 secret "labsecret"`,
		"set system accounting destination tacplus server 172.100.100.1 routing-instance mgmt_junos",
		`set system accounting destination tacplus server 172.100.100.1 secret "labsecret"`,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}

// Every keyword the harness types is one the image's help is asked about
// first, so a renamed statement is an INVALID run at the probe, not a
// commit error half way through.
func TestL73JunosAsksCoverEveryTypedKeyword(t *testing.T) {
	need := map[string]bool{}
	for _, a := range l73JunosAsks {
		for _, w := range a.Need {
			need[w] = true
		}
	}
	for _, w := range []string{"tls", "trusted-ca-group", "mutual-authentication", "certificate-id", "routing-instance",
		"port", "single-connection", "ca-profile", "ca-identity", "revocation-check", "ca-profiles"} {
		if !need[w] {
			t.Errorf("%s is typed and never asked about", w)
		}
	}
}

func TestL73HelpVerdict(t *testing.T) {
	help := "Possible completions:\n  <[Enter]>            Execute this command\n" +
		"  port                 TACACS+ authentication server port number\n" +
		"  routing-instance     Routing instance\n  secret               Shared secret\n" +
		"  single-connection    Optimize TCP connection attempts\n  timeout              Request timeout period\n" +
		"  tls                  TLS configuration\n"
	miss, have, err := l73HelpVerdict(help, l73JunosAsks[0])
	if err != nil || len(miss) != 0 || len(have) != 0 {
		t.Fatalf("%v %v %v", miss, have, err)
	}
	miss, _, err = l73HelpVerdict(strings.Replace(help, "  tls ", "  xyz ", 1), l73JunosAsks[0])
	if err != nil || !slices.Equal(miss, []string{"tls"}) {
		t.Fatalf("%v %v", miss, err)
	}
	if _, _, err := l73HelpVerdict("syntax error, expecting <command>.\n", l73JunosAsks[0]); err == nil {
		t.Fatal("an error read as an option list")
	}
	// Want words are reported when listed and never missed when not.
	ask := l73Ask{Ask: "x ", Control: []string{"client"}, Need: []string{"client"}, Want: []string{"server"}}
	miss, have, err = l73HelpVerdict("  client   Client trustpoint\n  server   Server trustpoint\n", ask)
	if err != nil || len(miss) != 0 || !slices.Equal(have, []string{"server"}) {
		t.Fatalf("%v %v %v", miss, have, err)
	}
	miss, have, err = l73HelpVerdict("  client   Client trustpoint\n", ask)
	if err != nil || len(miss) != 0 || len(have) != 0 {
		t.Fatalf("%v %v %v", miss, have, err)
	}
}

func TestL73DaemonYAMLFromTheLabConfig(t *testing.T) {
	base, err := os.ReadFile("port49d-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := l73DaemonYAML(string(base), l73Daemon{Inventory: "/x/inventory.yaml", Listen: "172.100.100.2:49",
		TLSListen: "172.100.100.1:300", Cert: "/x/s.crt", Key: "/x/s.key", ClientCA: "/x/root.pem",
		Intermediates: "/x/inter.pem", ServerNames: []string{"tacacs.l73.example"}, Tickets: 10 * time.Minute,
		StateDir: "/x/state", Status: "{disabled: true}", FaultFile: "/x/fault", Attrs: "[]"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Listen        string         `yaml:"listen"`
		InventoryFile string         `yaml:"inventory_file"`
		Limits        map[string]any `yaml:"limits"`
		Lab           map[string]any `yaml:"lab"`
		TLS           map[string]any `yaml:"tls_listener"`
	}
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if cfg.Listen != "172.100.100.2:49" || cfg.InventoryFile != "/x/inventory.yaml" || cfg.Limits["malformed_backoff_base"] != "2s" ||
		cfg.Lab["fault_file"] != "/x/fault" || cfg.TLS["listen"] != "172.100.100.1:300" ||
		cfg.TLS["intermediates_file"] != "/x/inter.pem" || cfg.TLS["session_ticket_lifetime"] != "10m0s" {
		t.Fatalf("%+v", cfg)
	}
	if sa, ok := cfg.Lab["session_attributes"].([]any); !ok || len(sa) != 0 {
		t.Fatalf("session_attributes %v", cfg.Lab["session_attributes"])
	}
	out, err = l73DaemonYAML(string(base), l73Daemon{Inventory: "/i", TLSListen: "172.100.100.1:300", Cert: "c", Key: "k",
		ClientCA: "a", StateDir: "s", Status: "{disabled: true}"})
	if err != nil || !strings.Contains(out, `listen: "172.100.100.1:49"`) || strings.Contains(out, "intermediates_file") ||
		strings.Contains(out, "server_names") || strings.Contains(out, "fault_file") {
		t.Fatalf("%v\n%s", err, out)
	}
	// No Attrs keeps the lab file's session_attributes line as it is.
	var keep string
	for _, ln := range strings.Split(string(base), "\n") {
		if strings.HasPrefix(ln, "  session_attributes: ") {
			keep = ln
		}
	}
	if keep == "" || !strings.Contains(out, keep+"\n") {
		t.Fatalf("session_attributes changed with no Attrs:\n%s", out)
	}
	if _, err := l73DaemonYAML("listen: x\n", l73Daemon{Inventory: "/i"}); err == nil {
		t.Fatal("a config with no inventory_file line accepted")
	}
}

func TestL73InventoryMarksOneDeviceTLS(t *testing.T) {
	base, err := os.ReadFile("inventory-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := l73Inventory(string(base), "srx1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "transport: tls") != 1 || !regexp.MustCompile(`\{name: srx1,.*transport: tls\}`).MatchString(out) {
		t.Fatal(out)
	}
	if _, err := l73Inventory(out, "srx1"); err == nil {
		t.Fatal("a device that already names a transport rewritten")
	}
	if _, err := l73Inventory(string(base), "nosuch"); err == nil {
		t.Fatal("an absent device accepted")
	}
}

// Every L73 cell named in spec §15 has an entry, in its order, and nothing
// else does.
func TestL73CellsAreTheRegistersCells(t *testing.T) {
	spec, err := os.ReadFile("../../docs/design/2026-08-23-policy-engine-spec.md")
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, ln := range strings.Split(string(spec), "\n") {
		if strings.HasPrefix(ln, "| **L73** |") {
			row = strings.Split(ln, "|")[2]
		}
	}
	var want []string
	for _, m := range regexp.MustCompile(`\(([a-z])\)`).FindAllStringSubmatch(row, -1) {
		want = append(want, m[1])
	}
	var got []string
	for _, c := range l73Cells {
		got = append(got, c.ID)
	}
	if len(want) == 0 || !slices.Equal(got, want) {
		t.Fatalf("cells %v, the register's %v", got, want)
	}
}

func TestL73RenderTableNeedsEveryCellOnce(t *testing.T) {
	var obs []l73Obs
	for i := len(l73Cells) - 1; i >= 0; i-- {
		obs = append(obs, l73Obs{ID: l73Cells[i].ID, Configured: "c|d", Observed: "o\nk", Docs: "n/a"})
	}
	table, err := l73RenderTable(obs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table, `c\|d`) || strings.Contains(table, "o\nk") || strings.Index(table, "| a |") > strings.Index(table, "| j |") {
		t.Fatal(table)
	}
	if _, err := l73RenderTable(obs[1:]); err == nil {
		t.Fatal("a missing cell rendered")
	}
	if _, err := l73RenderTable(append(obs, obs[0])); err == nil {
		t.Fatal("a cell twice rendered")
	}
}

func TestL73PEMBlockFromACLIScreen(t *testing.T) {
	screen := "file show /var/tmp/l73-dev.csr\r\n-----BEGIN CERTIFICATE REQUEST-----\r\n" +
		"MIIBDzCBtgIBADAPMQ0wCwYDVQQDDARzcngxMFkwEwYHKoZIzj0CAQYIKoZIzj0D\r\n" +
		"-----END CERTIFICATE REQUEST-----\r\n\r\nbreakglass@srx1> "
	b, err := l73PEMBlock(screen)
	if err != nil || !strings.HasPrefix(string(b), "-----BEGIN CERTIFICATE REQUEST-----\n") || strings.Contains(string(b), "\r") ||
		!strings.HasSuffix(string(b), "-----END CERTIFICATE REQUEST-----\n") {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := l73PEMBlock("error: file not found\r\n> "); err == nil {
		t.Fatal("no block read as one")
	}
}

func TestScpSinkFrame(t *testing.T) {
	got := string(scpSinkFrame("l73-root.pem", []byte("PEM\n")))
	if got != "C0644 4 l73-root.pem\nPEM\n\x00" {
		t.Fatalf("%q", got)
	}
}

func TestL73MetricValue(t *testing.T) {
	exp := "# HELP x\nport49_tls_handshakes_total{outcome=\"ok\"} 3\nport49_tls_handshakes_total{outcome=\"resumed\"} 2\n"
	if v := l73MetricValue(exp, `port49_tls_handshakes_total{outcome="resumed"}`); v != 2 {
		t.Fatal(v)
	}
	if v := l73MetricValue(exp, `port49_tls_handshakes_total{outcome="unknown_ca"}`); v != 0 {
		t.Fatal(v)
	}
}

// A selector matches its own line only: not a longer name, and not a value
// glued on with no separator.
func TestL73MetricValueSelectorIsNotAPrefix(t *testing.T) {
	exp := "port49_x_total_extra{a=\"b\"} 9\nport49_x_totalfoo 8\nport49_x_total{a=\"b\"}7\nport49_x_total{a=\"b\"} 4\n"
	if v := l73MetricValue(exp, `port49_x_total{a="b"}`); v != 4 {
		t.Fatal(v)
	}
	if v := l73MetricValue("port49_x_total{a=\"b\"}7\n", `port49_x_total{a="b"}`); v != 0 {
		t.Fatal(v)
	}
}

func TestL73ScrubLog(t *testing.T) {
	in := "Oct 17 tacplus: TLS handshake failed: bad certificate\n" +
		"Oct 17 secret \"$9$abc\"\nOct 17 token eyJhbGciOi\n" +
		"Oct 17 cert " + strings.Repeat("A1b2", 8) + " loaded\n"
	got := l73ScrubLog(in)
	if !strings.Contains(got, "TLS handshake failed: bad certificate") || strings.Contains(got, "$9$") ||
		strings.Contains(got, "eyJ") || strings.Contains(got, strings.Repeat("A1b2", 8)) || !strings.Contains(got, "<LONG>") {
		t.Fatal(got)
	}
}
