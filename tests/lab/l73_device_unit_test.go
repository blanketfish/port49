package lab

import (
	"bytes"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
	// The rest of the line is still masked.
	if got := l73ScrubLog(ans(ok) + " " + blob); strings.Contains(got, blob) || !strings.Contains(got, ok) {
		t.Fatal(got)
	}
}

func TestL73JunosDiagAsksStopAtTheValuePosition(t *testing.T) {
	asks := l73JunosDialect.DiagAsks
	if len(asks) != 3 {
		t.Fatal(asks)
	}
	for _, a := range asks {
		if !strings.HasPrefix(a, "set system tacplus-server "+l73Server+" tls ") || !strings.HasSuffix(a, " ") || strings.Contains(a, "?") {
			t.Errorf("%q", a)
		}
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
