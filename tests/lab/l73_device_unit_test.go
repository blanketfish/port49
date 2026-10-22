package lab

import (
	"bytes"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
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
			t.Errorf("missing %q", maskKey(line))
		}
	}
	for _, line := range got {
		if strings.HasPrefix(line, "set system tacplus-server 172.100.100.2 tls") {
			t.Errorf("a plain second server carries tls: %q", line)
		}
		if strings.Contains(line, "172.100.100.1") && strings.Contains(line, "secret") {
			t.Errorf("a tls server carries a secret it was not asked for: %q", maskKey(line))
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
		t.Fatalf("%q", maskKey(strings.Join(got, "\n")))
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
		Intermediates: "/x/inter.pem", ServerNames: []string{"tacacs.l73.example", "a: b, c"}, Tickets: 10 * time.Minute,
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
	if sn, ok := cfg.TLS["server_names"].([]any); !ok || !slices.Equal(sn, []any{"tacacs.l73.example", "a: b, c"}) {
		t.Fatalf("server_names %v", cfg.TLS["server_names"])
	}
	if sa, ok := cfg.Lab["session_attributes"].([]any); !ok || len(sa) != 0 {
		t.Fatalf("session_attributes %v", cfg.Lab["session_attributes"])
	}
	if cfg.Limits["idle_timeout"] != "5m" {
		t.Fatalf("with no DefaultIdle the lab file's idle_timeout stays: %v", cfg.Limits["idle_timeout"])
	}
	// DefaultIdle drops the lab's 5m, so port49d runs its own default (30s),
	// as L80's re-measure does.
	def, err := l73DaemonYAML(string(base), l73Daemon{Inventory: "/i", TLSListen: "172.100.100.1:300", Cert: "c", Key: "k",
		ClientCA: "a", StateDir: "s", Status: "{disabled: true}", DefaultIdle: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Limits = nil
	if err := yaml.Unmarshal([]byte(def), &cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Limits["idle_timeout"]; ok || cfg.Limits["malformed_backoff_base"] != "2s" {
		t.Fatalf("DefaultIdle: limits %v", cfg.Limits)
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
	for _, c := range l73Cells {
		if !regexp.MustCompile(regexp.QuoteMeta("("+c.ID+") "+c.Claim) + `(;|\.|\s*$)`).MatchString(row) {
			t.Errorf("cell %s's claim is not the register's wording", c.ID)
		}
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
	blank := slices.Clone(obs)
	blank[3].Observed = " "
	if _, err := l73RenderTable(blank); err == nil {
		t.Fatal("a cell with nothing observed rendered as measured")
	}
}

func TestL73PEMBlockFromACLIScreen(t *testing.T) {
	screen := "file show /var/tmp/l73-dev.csr\r\n-----BEGIN CERTIFICATE REQUEST-----\r\n" +
		"MIIBDzCBtgIBADAPMQ0wCwYDVQQDDARzcngxMFkwEwYHKoZIzj0CAQYIKoZIzj0D\r\n" +
		"-----END CERTIFICATE REQUEST-----\r\n\r\nbreakglass@srx1> "
	b, err := l73PEMBlock(screen, "CERTIFICATE REQUEST")
	if err != nil || !strings.HasPrefix(string(b), "-----BEGIN CERTIFICATE REQUEST-----\n") || strings.Contains(string(b), "\r") ||
		!strings.HasSuffix(string(b), "-----END CERTIFICATE REQUEST-----\n") {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := l73PEMBlock(screen, "CERTIFICATE"); err == nil {
		t.Fatal("a certificate request read as a certificate")
	}
	if _, err := l73PEMBlock("error: file not found\r\n> ", "CERTIFICATE REQUEST"); err == nil {
		t.Fatal("no block read as one")
	}
}

func TestScpSinkFrame(t *testing.T) {
	got := string(scpSinkFrame("l73-root.pem", []byte("PEM\n")))
	if got != "C0644 4 l73-root.pem\nPEM\n\x00" {
		t.Fatalf("%q", got)
	}
}

func TestScpBodyAllowsOnlyCertificates(t *testing.T) {
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("AAAA")}))
	for name, body := range map[string]string{
		"one":              cert,
		"a chain":          cert + "\n" + cert,
		"trailing newline": cert + "\n\n",
	} {
		if err := scpCheckBody([]byte(body)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, body := range map[string]string{
		"private key":       "x\n-----BEGIN PRIVATE KEY-----\nAAAA\n",
		"rsa key":           "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
		"ec key":            "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
		"encrypted key":     "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
		"lower-case key":    "-----BEGIN private key-----\nAAAA\n-----END private key-----\n",
		"crl":               "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n",
		"cert then key":     cert + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"non-pem":           "AAAA secretbytes",
		"garbage first":     "AAAA secretbytes\n" + cert,
		"garbage after":     cert + "AAAA secretbytes",
		"empty":             "",
		"cert with headers": "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END CERTIFICATE-----\n",
		"truncated cert":    "-----BEGIN CERTIFICATE-----\nAAAA\n",
		"cert with a key":   "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY",
	} {
		err := scpCheckBody([]byte(body))
		if err == nil || strings.Contains(err.Error(), "AAAA") || strings.Contains(err.Error(), "secretbytes") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestL73MetricValue(t *testing.T) {
	exp := "# HELP x\nport49_tls_handshakes_total{outcome=\"ok\"} 3\nport49_tls_handshakes_total{outcome=\"resumed\"} 2\n"
	if v, ok := l73MetricValue(exp, `port49_tls_handshakes_total{outcome="resumed"}`); !ok || v != 2 {
		t.Fatal(v, ok)
	}
	// An absent series is not a zero one: a misspelled selector must be seen.
	if v, ok := l73MetricValue(exp, `port49_tls_handshakes_total{outcome="unknown_ca"}`); ok || v != 0 {
		t.Fatal(v, ok)
	}
	if _, ok := l73MetricValue("port49_x_total 0\n", "port49_x_total"); !ok {
		t.Fatal("a series at zero read as absent")
	}
}

// A selector matches its own line only: not a longer name, and not a value
// glued on with no separator.
func TestL73MetricValueSelectorIsNotAPrefix(t *testing.T) {
	exp := "port49_x_total_extra{a=\"b\"} 9\nport49_x_totalfoo 8\nport49_x_total{a=\"b\"}7\nport49_x_total{a=\"b\"} 4\n"
	if v, ok := l73MetricValue(exp, `port49_x_total{a="b"}`); !ok || v != 4 {
		t.Fatal(v, ok)
	}
	if v, ok := l73MetricValue("port49_x_total{a=\"b\"}7\n", `port49_x_total{a="b"}`); ok || v != 0 {
		t.Fatal(v, ok)
	}
}

func TestL73ScrubLog(t *testing.T) {
	in := "Oct 17 tacplus: TLS handshake failed: bad certificate\n" +
		"Oct 17 secret \"$9$abc\"\nOct 17 token eyJhbGciOi\n" +
		"Oct 17 cert " + strings.Repeat("A1b2", 8) + " loaded\n"
	in += "Oct 17 authentication-key \"$9$ab\"\nOct 17 hash $6$short ok\n"
	got := l73ScrubLog(in)
	if strings.Contains(got, "$9$") || strings.Contains(got, "$6$") || !strings.Contains(got, "hash <HASH> ok") {
		t.Fatal(got)
	}
	if !strings.Contains(got, "TLS handshake failed: bad certificate") || strings.Contains(got, "$9$") ||
		strings.Contains(got, "eyJ") || strings.Contains(got, strings.Repeat("A1b2", 8)) || !strings.Contains(got, "<LONG>") {
		t.Fatal(got)
	}
}

func TestL73ControlInvalidKeepsSummary(t *testing.T) {
	got := l73ControlInvalid("exit status 1", "; hint", "(no record)", "the device's first connection went to port 300 (1 connection)")
	for _, want := range []string{"INVALID: the control login over TLS did not pass (exit status 1); hint", "records: (no record)",
		"the device's first connection went to port 300"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
	leaky := l73ControlInvalid("e", "", "(no record)", `x {"session_id":"`+strings.Repeat("ab", 16)+`"}`)
	if strings.Contains(leaky, strings.Repeat("ab", 16)) || !strings.Contains(leaky, "summary withheld: a long hex run") {
		t.Fatal(leaky)
	}
}

func TestL73DropPEM(t *testing.T) {
	in := "Issuer: CN=L73 Lab\n-----BEGIN CERTIFICATE-----\nMIIBabc\n-----END CERTIFICATE-----\n" +
		"-----BEGIN EC PRIVATE KEY-----\nMHcCAQ\n-----END EC PRIVATE KEY-----\nafter\n"
	got := l73DropPEM(in)
	if strings.Contains(got, "MIIB") || strings.Contains(got, "MHcC") || strings.Contains(got, "-----") ||
		!strings.Contains(got, "Issuer: CN=L73 Lab") || !strings.Contains(got, "after") || !strings.Contains(got, "<PEM block dropped>") {
		t.Fatal(got)
	}
	// An unterminated block drops through the end: nothing after BEGIN survives.
	if got := l73DropPEM("a\n-----BEGIN CERTIFICATE-----\nMIIB\n"); strings.Contains(got, "MIIB") {
		t.Fatal(got)
	}
}

func TestL73DropPEMLabels(t *testing.T) {
	for _, label := range []string{"NEW CERTIFICATE REQUEST", "X9.42 DH PARAMETERS", "OPENSSH-PRIVATE KEY", "CERTIFICATE"} {
		in := "head\n-----BEGIN " + label + "-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n-----END " + label + "-----\ntail\n"
		got := l73DropPEM(in)
		if strings.Contains(got, "QUJD") || !strings.Contains(got, "head") || !strings.Contains(got, "tail") {
			t.Fatalf("%s: %q", label, got)
		}
	}
}

// Files without the lab tag build under plain `go vet ./...`; they must not
// call what only lab-tagged files define (C1 of the T11 fix review).
func TestL73UntaggedFilesUseNothingLabTagged(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	tagged, untagged := map[string]bool{}, []string{}
	defs := map[string]string{}
	fset := token.NewFileSet()
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(src[:min(len(src), 200)], []byte("//go:build lab")) {
			tagged[f] = true
			for _, d := range af.Decls {
				if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil {
					defs[fn.Name.Name] = f
				}
			}
		} else if !strings.HasSuffix(f, "_test.go") {
			untagged = append(untagged, f)
		}
	}
	for _, f := range untagged {
		af, _ := parser.ParseFile(fset, f, nil, 0)
		ast.Inspect(af, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				id, ok := c.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				if def, bad := defs[id.Name]; bad {
					t.Errorf("%s uses %s, defined only in lab-tagged %s", f, id.Name, def)
				}
			}
			return true
		})
	}
}

func TestL73MissingLines(t *testing.T) {
	typed := []string{
		"delete system tacplus-server",
		"set system tacplus-server 172.100.100.1 routing-instance mgmt_junos",
		"set system tacplus-server 172.100.100.1 tls trusted-ca-group l73-trust",
		`set system tacplus-server 172.100.100.1 secret "labvalue"`,
		"set system tacplus-server 172.100.100.1   port 300",
	}
	shown := "show configuration system tacplus-server | display set \r\n" +
		"set system tacplus-server 172.100.100.1 routing-instance mgmt_junos\r\n" +
		"set system tacplus-server 172.100.100.1 tls trusted-ca-group \"l73-trust\"\r\n" +
		"set system tacplus-server 172.100.100.1 port 300\r\n" +
		"set system tacplus-server 172.100.100.1 secret \"$9$abcdef\"\r\n"
	if got := l73MissingLines(typed, shown); len(got) != 0 {
		t.Fatal(got)
	}
	// The tls line and the secret are gone: both are named, the secret without its value.
	shown = "set system tacplus-server 172.100.100.1 routing-instance mgmt_junos\nset system tacplus-server 172.100.100.1 port 300\n"
	got := l73MissingLines(typed, shown)
	want := []string{"set system tacplus-server 172.100.100.1 tls trusted-ca-group l73-trust",
		"set system tacplus-server 172.100.100.1 secret <masked>"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for _, g := range got {
		if strings.Contains(g, "labvalue") {
			t.Fatal(g)
		}
	}
}

func TestL73Hierarchy(t *testing.T) {
	for in, want := range map[string]string{
		"set system tacplus-server 1.2.3.4 port 300":               "system tacplus-server",
		"set system accounting destination tacplus server 1.2.3.4": "system accounting",
		"set security pki ca-profile x ca-identity x":              "security pki",
		"delete system tacplus-server":                             "",
	} {
		if got := l73Hierarchy(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func TestL73ScrubLogShowsOnlyAPlainFilePath(t *testing.T) {
	ans := func(p string) string { return "File path '" + p + "' doesn't exists." }
	ok := "/var/db/certs/common/local/l73-dev.pem"
	if got := l73ScrubLog(ans(ok)); got != ans(ok) {
		t.Fatalf("a plain path is masked: %s", got)
	}
	blob := strings.Repeat("QUJDREVG", 6) // 48 base64 characters
	for _, p := range []string{
		"/" + blob,                            // a base64 blob starting with a slash
		"//var/db/certs/" + "x",               // two slashes
		"/var/db/" + strings.Repeat("a", 65),  // a segment over 64
		"/home/x/" + strings.Repeat("ab", 14), // outside the directories
		"/var/db/" + blob + "+/==",            // characters a path does not hold
	} {
		got := l73ScrubLog(ans(p))
		if strings.Contains(got, blob) || strings.Contains(got, strings.Repeat("a", 65)) || strings.Contains(got, strings.Repeat("ab", 14)) {
			t.Errorf("%q left unmasked: %s", p, got)
		}
	}
	// A path that climbs out of its directory is not shown.
	for _, p := range []string{"/var/../etc/x", "/var/db/../../etc/x", "/var/./db/x"} {
		if l73PrintablePath(p) || l73RefusedDir(ans(p)) != "" || l73BarePath(p) {
			t.Errorf("%q is taken for a printable path", p)
		}
	}
	// The rest of the line is still masked.
	if got := l73ScrubLog(ans(ok) + " " + blob); strings.Contains(got, blob) || !strings.Contains(got, ok) {
		t.Fatal(got)
	}
}

func TestL73JunosDiagAsksEndAtTheirPosition(t *testing.T) {
	d := l73JunosDialect
	if len(d.DiagOpAsks) != 4 || len(d.DiagAsks) != 1 {
		t.Fatal(d.DiagOpAsks, d.DiagAsks)
	}
	for _, a := range append(slices.Clone(d.DiagOpAsks), d.DiagAsks...) {
		if !strings.HasSuffix(a, " ") || strings.Contains(a, "?") {
			t.Errorf("%q", a)
		}
	}
	for _, a := range d.DiagOpAsks {
		if strings.HasPrefix(a, "set ") {
			t.Errorf("%q is not operational", a)
		}
	}
}

func TestL73RootTrustCmds(t *testing.T) {
	got, err := l73RootTrustCmds("l73-trust", []l73RootCert{{"/var/tmp/l73-root.pem", []string{"0a1b2c3d"}},
		{"/var/tmp/l73-inter.pem", []string{"ffeeddcc", "11223344"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mkdir -p /var/db/aaa_certs/tacplus_tls/l73-trust",
		"cp /var/tmp/l73-root.pem /var/db/aaa_certs/tacplus_tls/l73-trust/0a1b2c3d.0",
		"cp /var/tmp/l73-inter.pem /var/db/aaa_certs/tacplus_tls/l73-trust/ffeeddcc.0",
		"cp /var/tmp/l73-inter.pem /var/db/aaa_certs/tacplus_tls/l73-trust/11223344.0",
		"ls -l /var/db/aaa_certs/tacplus_tls/l73-trust",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for _, bad := range []string{"", "0A1B2C3D", "0a1b2c3", "0a1b2c3d4", "../../etc", "0a1b2c3z", "0a1b2c3d;id"} {
		if _, err := l73RootTrustCmds("l73-trust", []l73RootCert{{"/var/tmp/l73-root.pem", []string{bad}}}); err == nil {
			t.Errorf("hash %q accepted", bad)
		}
	}
	if _, err := l73RootTrustCmds("l73-trust", []l73RootCert{{"/var/tmp/l73-root.pem", nil}}); err == nil {
		t.Error("a certificate with no file name was accepted")
	}
	// Only the two uploaded public CA certificates can be a source: not a
	// key, not the device certificate, not any other path.
	for _, src := range []string{"/var/tmp/l73-dev.key", "/var/tmp/l73-dev.crt", "/var/tmp/other.pem", "/var/tmp/l73-root.pem.key",
		"/var/tmp/../tmp/l73-root.pem", "l73-root.pem", "", "/var/tmp/l73-root.pem; cat /var/db/certd/key-pair/x"} {
		if _, err := l73RootTrustCmds("l73-trust", []l73RootCert{{src, []string{"0a1b2c3d"}}}); err == nil {
			t.Errorf("source %q accepted", src)
		}
	}
	for _, group := range []string{"", "../x", "a b", "a;b", "A"} {
		if _, err := l73RootTrustCmds(group, []l73RootCert{{"/var/tmp/l73-root.pem", []string{"0a1b2c3d"}}}); err == nil {
			t.Errorf("group %q accepted", group)
		}
	}
}

func TestL73HashNamesAndShellParsing(t *testing.T) {
	if got := l73HashNames(true, "aaaaaaaa", "bbbbbbbb"); !slices.Equal(got, []string{"aaaaaaaa"}) {
		t.Errorf("with a device openssl: %q", got)
	}
	if got := l73HashNames(false, "aaaaaaaa", "bbbbbbbb"); !slices.Equal(got, []string{"aaaaaaaa", "bbbbbbbb"}) {
		t.Errorf("without one: %q", got)
	}
	if got := l73HashNames(false, "aaaaaaaa", "aaaaaaaa"); !slices.Equal(got, []string{"aaaaaaaa"}) {
		t.Errorf("equal hashes are placed once: %q", got)
	}
	if !l73ParseWhich("which openssl\r\n/usr/bin/openssl\r\nroot@srx1:~ # ") || l73ParseWhich("which openssl\r\nopenssl: Command not found.\r\n# ") {
		t.Error("which openssl misread")
	}
	if got := l73ParseHash("openssl x509 -noout -subject_hash -in /var/tmp/l73-root.pem\r\n0a1b2c3d\r\n# "); got != "0a1b2c3d" {
		t.Errorf("hash %q", got)
	}
	if got := l73ParseHash("openssl: error\r\n"); got != "" {
		t.Errorf("hash %q from an error", got)
	}
}

func TestL73RootPasswordAndHash(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl on this host")
	}
	a, err := l73NewRootPassword()
	b, _ := l73NewRootPassword()
	if err != nil || len(a) < 20 || a == b || !regexp.MustCompile(`^[0-9A-Za-z]+$`).MatchString(a) {
		t.Fatalf("passwords: %d bytes, equal %v, err %v", len(a), a == b, err)
	}
	h, err := l73RootHash(a)
	if err != nil || !regexp.MustCompile(`^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$`).MatchString(h) {
		t.Fatalf("hash shape wrong (err %v)", err)
	}
	if strings.Contains(h, a) {
		t.Fatal("the hash holds the password")
	}
}

func TestL73MaskAll(t *testing.T) {
	got := l73MaskAll("a SECRET b SECRET2 c", "SECRET", "", "SECRET2")
	if strings.Contains(got, "SECRET") || !strings.HasPrefix(got, "a ") {
		t.Fatalf("%q", got)
	}
}

func TestL73SubjectHashOldIsOpenSSLs(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl on this host")
	}
	pki, err := l73NewPKI("ecdsa", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	o, err := l73SubjectHashOld(pki.Root.PEM())
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(o) {
		t.Fatalf("%q %v", o, err)
	}
}

// The folder's file names are openssl's subject hash, which only the openssl
// binary on the host can vouch for; the test runs where it is installed.
func TestL73SubjectHashIsOpenSSLs(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl on this host")
	}
	pki, err := l73NewPKI("ecdsa", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := l73SubjectHash(pki.Root.PEM())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l73SubjectHash(pki.Inter.PEM())
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(a) || a == b {
		t.Fatal(a, b)
	}
	if _, err := l73SubjectHash([]byte("not a certificate")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestL73RefusedDir(t *testing.T) {
	for in, want := range map[string]string{
		"File path '/var/db/certs/common/trusted-ca-groups/l73-trust' doesn't exists.": "/var/db/certs/common/trusted-ca-groups",
		"File path '/config/x/y' doesn't exist.":                                       "/config/x",
		"File path '/tmp/x/y' doesn't exists.":                                         "",
		"File path '/" + strings.Repeat("QUJDREVG", 6) + "' doesn't exists.":           "",
		"nothing here": "",
	} {
		if got := l73RefusedDir(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func TestL73ScrubLogKeepsABareDirectoryPath(t *testing.T) {
	in := "file list /var/db/aaa_certs/ recursive\n/var/db/aaa_certs/tacplus_tls:\nl73-trust\n/" + strings.Repeat("QUJDREVG", 6) + ":\n"
	got := l73ScrubLog(in)
	for _, want := range []string{"file list /var/db/aaa_certs/ recursive", "/var/db/aaa_certs/tacplus_tls:", "l73-trust"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Contains(got, strings.Repeat("QUJDREVG", 6)) {
		t.Fatal(got)
	}
}

// The Junos trust group is committed after the CA certificates are loaded
// and before any tacplus TLS line; earlier, the image wrote no group file and
// refused the tls trusted-ca-group line.
func TestL73TrustGroupComesAfterTheCALoads(t *testing.T) {
	for _, ln := range l73PKILines() {
		if strings.Contains(ln, "trusted-ca-group") {
			t.Errorf("l73PKILines commits the trust group before the CA loads: %s", ln)
		}
	}
	if g := strings.Join(l73TrustGroupLines(), "\n"); !strings.Contains(g, "set security pki trusted-ca-group "+l73TrustGroup+" ca-profiles "+l73RootProfile) {
		t.Fatal(g)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "l73_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var loadJunos, test *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			switch fn.Name.Name {
			case "loadJunos":
				loadJunos = fn
			case "TestL73":
				test = fn
			}
		}
	}
	first := func(fn *ast.FuncDecl, name string) token.Pos {
		var at token.Pos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && at == 0 {
				switch f := c.Fun.(type) {
				case *ast.Ident:
					if f.Name == name {
						at = c.Pos()
					}
				case *ast.SelectorExpr:
					if f.Sel.Name == name {
						at = c.Pos()
					}
				}
			}
			return true
		})
		return at
	}
	load, group := first(loadJunos, "l73LoadCommands"), first(loadJunos, "l73TrustGroupLines")
	if load == 0 || group == 0 || load > group {
		t.Fatalf("loadJunos: CA loads at %v, trust group at %v", load, group)
	}
	enrol, cellA := first(test, "enrol"), first(test, "cellA")
	if enrol == 0 || cellA == 0 || enrol > cellA {
		t.Fatalf("TestL73: enrol (which loads the CAs and commits the group) must precede cellA (the first tacplus tls line)")
	}
}

func TestL73RootCmdAllowed(t *testing.T) {
	d := "/var/db/aaa_certs/tacplus_tls/l73-trust"
	for _, ok := range []string{"which openssl", "exit", "echo rc=$?", "openssl version", "openssl help",
		"openssl x509 -noout -subject_hash -in /var/tmp/l73-root.pem",
		"openssl x509 -noout -subject_hash_old -in /var/tmp/l73-inter.pem",
		"mkdir -p " + d, "ls -l " + d,
		"mkdir -p " + l73TrustDir + "/l73-dev", "ls -l " + l73TrustDir + "/l73-dev",
		`openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		`openssl req -new -newkey rsa:2048 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		"chmod 600 " + l73TrustDir + "/l73-dev/client.key",
		"cp /var/tmp/l73-client.crt " + l73TrustDir + "/l73-dev/client.crt",
		"cp /var/tmp/l73-root.pem " + d + "/0a1b2c3d.0", "cp /var/tmp/l73-inter.pem " + d + "/ffeeddcc.0"} {
		if !l73RootCmdAllowed(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "id", "cat /var/db/certd/key-pair/x", "sh", "ls -l /var/db", "ls -l " + d + "; id",
		"cp /var/tmp/l73-dev.key " + d + "/0a1b2c3d.0", "cp /var/tmp/l73-root.pem " + d + "/0A1B2C3D.0",
		"cp /var/tmp/l73-root.pem /etc/master.passwd", "cp /var/tmp/l73-root.pem " + d + "/0a1b2c3d.0 /tmp",
		"mkdir -p /var/db/aaa_certs/tacplus_tls/../x", "mkdir -p /var/tmp/x", "rm -rf " + d, "cp /var/db/certd/x " + d + "/0a1b2c3d.0",
		"openssl x509 -noout -subject_hash -in /var/db/certd/key-pair/x", "openssl rsa -in /var/tmp/l73-root.pem", "exit; id",
		"which openssl\nid", "echo rc=$?; id", "echo $?", "echo rc=$? > /tmp/x", "openssl version -a", "openssl version; id",
		// nothing reads or moves the client key
		"cat " + l73TrustDir + "/l73-dev/client.key", "cp " + l73TrustDir + "/l73-dev/client.key /var/tmp/k.pem",
		"openssl pkey -in " + l73TrustDir + "/l73-dev/client.key", "openssl ec -in " + l73TrustDir + "/l73-dev/client.key -text",
		"openssl rsa -in " + l73TrustDir + "/l73-dev/client.key", "scp " + l73TrustDir + "/l73-dev/client.key x:",
		"chmod 644 " + l73TrustDir + "/l73-dev/client.key", "chmod 600 /var/tmp/l73-root.pem",
		"chmod 600 " + l73TrustDir + "/l73-dev/client.key; cat " + l73TrustDir + "/l73-dev/client.key",
		"openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out " + l73TrustDir + "/l73-dev/client.key",
		"openssl ecparam -name prime256v1 -genkey -noout -out " + l73TrustDir + "/l73-dev/client.key",
		"openssl genrsa -out " + l73TrustDir + "/l73-dev/client.key 2048",
		`openssl req -new -key ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		"openssl help -a", "openssl help; id", "openssl list -commands", "openssl help > /tmp/x",
		`openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /var/tmp/k.pem -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		`openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		`openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		`openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr -text`,
		`openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr -pubkey`,
		`openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		`openssl req -new -newkey rsa:4096 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		`openssl req -new -newkey rsa:1024 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		`openssl req -new -newkey rsa:2048 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1;id" -out /var/tmp/l73-client.csr`,
		`openssl req -new -newkey rsa:2048 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/other.csr`,
		`openssl req -new -newkey rsa:2048 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1"`,
		`openssl req -new -newkey rsa:2048 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr; cat ` + l73TrustDir + `/l73-dev/client.key`,
		`openssl req -new -newkey rsa:2048 -nodes -keyout ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr | cat`,
		`openssl req -new -key ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/other.csr`,
		`openssl req -new -key ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1;id" -out /var/tmp/l73-client.csr`,
		`openssl req -new -key ` + l73TrustDir + `/l73-dev/client.key -subj "/CN=srx1" -out /var/tmp/l73-client.csr -text`,
		`openssl req -new -key /var/db/certd/key-pair/x -subj "/CN=srx1" -out /var/tmp/l73-client.csr`,
		"cp /var/tmp/l73-client.crt " + l73TrustDir + "/l73-dev/client.key", "cp /var/tmp/l73-client.csr " + l73TrustDir + "/l73-dev/client.crt",
		"cp /var/tmp/l73-client.crt /etc/x"} {
		if l73RootCmdAllowed(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestL73RootClientCmds(t *testing.T) {
	prep, ec, rsa, finish, err := l73RootClientCmds("srx1")
	if err != nil {
		t.Fatal(err)
	}
	k := l73TrustDir + "/l73-dev/client.key"
	if !slices.Equal(prep, []string{"mkdir -p " + l73TrustDir + "/l73-dev"}) || !slices.Equal(finish, []string{"chmod 600 " + k}) {
		t.Fatalf("prep %q finish %q", prep, finish)
	}
	if ec != `openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout `+k+` -subj "/CN=srx1" -out /var/tmp/l73-client.csr` ||
		rsa != `openssl req -new -newkey rsa:2048 -nodes -keyout `+k+` -subj "/CN=srx1" -out /var/tmp/l73-client.csr` {
		t.Fatalf("keys %q %q", ec, rsa)
	}
	for _, bad := range []string{"", "a b", "x;id", `x"y`, "$(id)", "-x"} {
		if _, _, _, _, err := l73RootClientCmds(bad); err == nil {
			t.Errorf("node %q accepted", bad)
		}
	}
	place := l73RootPlaceCmds()
	if !slices.Equal(place, []string{"cp /var/tmp/l73-client.crt " + l73TrustDir + "/l73-dev/client.crt", "ls -l " + l73TrustDir + "/l73-dev"}) {
		t.Fatalf("place %q", place)
	}
	for _, c := range append(append(append(prep, ec, rsa), finish...), place...) {
		if !l73RootCmdAllowed(c) {
			t.Errorf("%q is not allowed", c)
		}
	}
	if l73ListsCommand("Standard commands\nasn1parse ca\nreq rsa\n", "req") != true || l73ListsCommand("Standard commands\nasn1parse x509 reqx\n", "req") {
		t.Error("l73ListsCommand reads a command list wrongly")
	}
}

func TestL73NXOSImportOKReadsTheCertificateBack(t *testing.T) {
	leaf := "trustpoint: l73-dev; key-pair: l73-key\r\ncertificate:\r\nsubject=/CN=nx1\r\nissuer=/CN=L73 Lab Device Intermediate\r\n"
	if err := l73NXOSImportOK("input (cut & paste) certificate in PEM format:\r\nnx1(config)# ", leaf, "nx1"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ imp, show string }{
		"invalid command in the import": {"nx1(config)# END OF INPUT\r\n% Invalid command at '^' marker.\r\n", leaf},
		"error in the import":           {"Error: could not parse\r\n", leaf},
		"error in the read-back":        {"ok", leaf + "Error: x\r\n"},
		"no certificate":                {"ok", "trustpoint: l73-dev; key-pair: l73-key\r\n"},
		"a CA's subject only":           {"ok", "CA certificate 0:\r\nsubject=/CN=L73 Lab Device Intermediate\r\n"},
		"a longer CN":                   {"ok", "subject=/CN=nx10\r\n"},
		"a CN of the wrong device":      {"ok", "subject=/CN=other\r\n"},
	} {
		if err := l73NXOSImportOK(c.imp, c.show, "nx1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, show := range map[string]string{
		"the image's own line":  "Trustpoint: l73-dev\r\ncertificate:\r\nsubject=CN = nx1\r\nissuer=CN = L73 Lab Device Intermediate\r\n",
		"no spaces":             "subject=CN=nx1",
		"a comma-ended CN":      "subject=CN=nx1,O=lab\r\n",
		"another RDN before it": "subject=O = x, CN = nx1\r\n",
		"a slash-ended CN":      "subject=/CN = nx1/O=x\n",
	} {
		if err := l73NXOSImportOK("ok", show, "nx1"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, show := range map[string]string{
		"a spaced longer CN": "subject=CN = nx10\r\n",
		"a CN with a suffix": "subject=CN = nx1x\r\n",
		"the CA-only screen": "CA certificate 0:\r\nsubject=CN = L73 Lab Device Intermediate\r\nissuer=CN = L73 Lab Root\r\n",
	} {
		if err := l73NXOSImportOK("ok", show, "nx1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestL73DaemonYAMLHandshakeTimeoutIsSetOnlyWhenAsked(t *testing.T) {
	base, err := os.ReadFile("port49d-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	o := l73Daemon{Inventory: "/x/i.yaml", TLSListen: "172.100.100.1:300", Cert: "/x/s.crt", Key: "/x/s.key", ClientCA: "/x/r.pem",
		StateDir: "/x/state", Status: "{disabled: true}", Attrs: "[]"}
	for want, d := range map[any]time.Duration{nil: 0, "30s": 30 * time.Second} {
		o.HandshakeTimeout = d
		out, err := l73DaemonYAML(string(base), o)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			TLS map[string]any `yaml:"tls_listener"`
		}
		if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if got := cfg.TLS["handshake_timeout"]; got != want {
			t.Errorf("handshake_timeout %v for %s, want %v", got, d, want)
		}
	}
}
