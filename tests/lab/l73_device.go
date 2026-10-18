package lab

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// The Junos statements L73 types are the ones Juniper documents for 26.2R1
// ("TACACS+ over TLS overview": `tls trusted-ca-group` and
// `tls mutual-authentication certificate-id` under both `system
// tacplus-server <ip>` and `system accounting destination tacplus server
// <ip>`). The run's first cell asks the image's own help about every
// keyword here (l73JunosAsks) before any of them is committed.
const (
	l73Server       = "172.100.100.1" // the clab bridge's .1, where port49d listens
	l73SecondServer = "172.100.100.2" // splitSecondAddr's value (harness_test.go is lab-tagged)
	l73TLSPort      = 300
	l73Instance     = "mgmt_junos"
	l73TrustGroup   = "l73-trust"
	l73RootProfile  = "l73-root"
	l73InterProfile = "l73-inter"
	l73CertID       = "l73-dev"
	l73CSRPath      = "/var/tmp/l73-dev.csr"
)

// l73DeviceTLS is how the device's TACACS+ client is pointed at port49 in
// one cell.
type l73DeviceTLS struct {
	Server           string
	Port             int // 0: no port statement (cell a)
	SingleConnection bool
	Secret           bool // a shared secret beside tls, only if the image's commit demands one
	Second           string
	SecondTLS        bool
	SecondPort       int
}

func l73JunosLines(d l73DeviceTLS) []string {
	lines := []string{"delete system tacplus-server", "delete system accounting destination tacplus"}
	auth := "set system tacplus-server " + d.Server
	lines = append(lines, l73ServerLines(auth, true, d.Port, d.Secret)...)
	if d.SingleConnection {
		lines = append(lines, auth+" single-connection")
	}
	lines = append(lines, l73ServerLines("set system accounting destination tacplus server "+d.Server, true, d.Port, d.Secret)...)
	if d.Second != "" {
		lines = append(lines, l73ServerLines("set system tacplus-server "+d.Second, d.SecondTLS, d.SecondPort,
			d.Secret || !d.SecondTLS)...)
	}
	return lines
}

func l73ServerLines(prefix string, tls bool, port int, secret bool) []string {
	out := []string{prefix + " routing-instance " + l73Instance}
	if tls {
		out = append(out, prefix+" tls trusted-ca-group "+l73TrustGroup,
			prefix+" tls mutual-authentication certificate-id "+l73CertID)
	}
	if port != 0 {
		out = append(out, prefix+" port "+strconv.Itoa(port))
	}
	if secret {
		out = append(out, prefix+` secret "`+labcreds.Key+`"`)
	}
	return out
}

// l73JunosRestore is configs/vjunos-startup.conf's servers again.
func l73JunosRestore() []string {
	lines := []string{"delete system tacplus-server", "delete system accounting destination tacplus"}
	lines = append(lines, l73ServerLines("set system tacplus-server "+l73Server, false, 0, true)...)
	return append(lines, l73ServerLines("set system accounting destination tacplus server "+l73Server, false, 0, true)...)
}

// l73PKILines are the CA profiles and the trust group the device checks
// port49's certificate against. Revocation checking is off on the device:
// the lab's CAs publish no CRL, and whether Junos checks one is not an L73
// cell. The note says so.
func l73PKILines() []string {
	return []string{
		"set security pki ca-profile " + l73RootProfile + " ca-identity " + l73RootProfile,
		"set security pki ca-profile " + l73RootProfile + " revocation-check disable",
		"set security pki ca-profile " + l73InterProfile + " ca-identity " + l73InterProfile,
		"set security pki ca-profile " + l73InterProfile + " revocation-check disable",
		"set security pki trusted-ca-group " + l73TrustGroup + " ca-profiles " + l73RootProfile,
	}
}

// l73EnrolCommands are the documented offline enrolment's two operational
// commands: a key pair made on the device, and a request naming the device
// by its inventory name and address.
func l73EnrolCommands(node, addr string) (keyPair, csr string) {
	return "request security pki generate-key-pair certificate-id " + l73CertID,
		fmt.Sprintf(`request security pki generate-certificate-request certificate-id %s subject "CN=%s" domain-name %s ip-address %s filename %s`,
			l73CertID, node, node, addr, l73CSRPath)
}

func l73LoadCommands() []string {
	return []string{
		"request security pki ca-certificate load ca-profile " + l73RootProfile + " filename /var/tmp/l73-root.pem",
		"request security pki ca-certificate load ca-profile " + l73InterProfile + " filename /var/tmp/l73-inter.pem",
		"request security pki local-certificate load certificate-id " + l73CertID + " filename /var/tmp/l73-dev.crt",
	}
}

// l73Ask is one help request: typed, then "?" with no newline, then Ctrl-U.
// Control words prove the help is a real option list; Need are the
// keywords the harness will type at that level; Want are keywords it types
// only when the help lists them. Only, when set, asks this level only if an
// earlier ask listed that word.
//
// In and Out put the CLI in the mode the ask is meaningful in and back: In is
// typed before the ask and Out after its Ctrl-U, both only when set. They are
// for words typed outside the dialect's Enter mode (the AAA server group).
type l73Ask struct {
	Ask                 string
	Control, Need, Want []string
	Only                string
	In, Out             []string
}

// listed is the key under which a help's listing of word at this ask is
// recorded: by mode and level as well as word, so that two asks that look for
// the same word (IOS XE's AAA group and its `tls trustpoint` flag both look
// for `server`) never answer for each other. Only names such a key.
func (a l73Ask) listed(word string) string {
	return strings.Join(a.In, ";") + "@" + a.Ask + "|" + word
}

// l73RecordListed folds one ask's verdict (l73HelpVerdict's miss and have)
// into listed: a Need word is listed unless this help missed it, a Want word
// only if this help listed it.
func l73RecordListed(listed map[string]bool, a l73Ask, miss, have []string) {
	for _, w := range a.Need {
		k := a.listed(w)
		listed[k] = listed[k] || !slices.Contains(miss, w)
	}
	for _, w := range have {
		listed[a.listed(w)] = true
	}
}

// l73JunosAsks: the first is L71's own probe; the rest are asked only when
// it lists tls.
var l73JunosAsks = []l73Ask{
	{Ask: "set system tacplus-server 192.0.2.71 ", Control: []string{"secret", "port", "timeout"},
		Need: []string{"tls", "port", "single-connection", "routing-instance", "secret"}},
	{Ask: "set system tacplus-server 192.0.2.71 tls ", Control: []string{"trusted-ca-group"},
		Need: []string{"trusted-ca-group", "mutual-authentication"}},
	{Ask: "set system tacplus-server 192.0.2.71 tls mutual-authentication ", Control: []string{"certificate-id"},
		Need: []string{"certificate-id"}},
	{Ask: "set system accounting destination tacplus server 192.0.2.71 ", Control: []string{"secret", "port", "timeout"},
		Need: []string{"tls", "port", "routing-instance", "secret"}},
	{Ask: "set system accounting destination tacplus server 192.0.2.71 tls ", Control: []string{"trusted-ca-group"},
		Need: []string{"trusted-ca-group", "mutual-authentication"}},
	{Ask: "set system accounting destination tacplus server 192.0.2.71 tls mutual-authentication ", Control: []string{"certificate-id"},
		Need: []string{"certificate-id"}},
	{Ask: "set security pki ", Control: []string{"ca-profile"}, Need: []string{"ca-profile", "trusted-ca-group"}},
	{Ask: "set security pki ca-profile l73probe ", Control: []string{"ca-identity"}, Need: []string{"ca-identity", "revocation-check"}},
	{Ask: "set security pki ca-profile l73probe revocation-check ", Control: []string{"disable"}, Need: []string{"disable"}},
	{Ask: "set security pki trusted-ca-group l73probe ", Control: []string{"ca-profiles"}, Need: []string{"ca-profiles"}},
}

// l73HelpVerdict is the Need words help does not list, and the Want words it
// does. A help that lists none of the control words is an error: it is not
// an option list, and its lacking a word proves nothing.
func l73HelpVerdict(help string, a l73Ask) (miss, have []string, err error) {
	if _, ok := l71Says(help, a.Control); !ok {
		return nil, nil, fmt.Errorf("INVALID: the help for `%s?` lists none of %v, so it is not an option list; its words: %s",
			strings.TrimSpace(a.Ask), a.Control, l71Words(help))
	}
	for _, w := range a.Need {
		if _, ok := l71Says(help, []string{w}); !ok {
			miss = append(miss, w)
		}
	}
	for _, w := range a.Want {
		if _, ok := l71Says(help, []string{w}); ok {
			have = append(have, w)
		}
	}
	return miss, have, nil
}

// l73Daemon is one cell's port49d: the lab config with the inventory
// replaced, an optional other RFC 8907 bind, the platform's session reply,
// a 2s backoff base, and a tls_listener.
type l73Daemon struct {
	Inventory     string
	Listen        string // "" keeps 172.100.100.1:49
	TLSListen     string
	Cert, Key     string
	ClientCA      string
	Intermediates string
	ServerNames   []string
	Tickets       time.Duration // session_ticket_lifetime; 0 is off (the default)
	StateDir      string
	Status        string // certificate_status, a YAML flow mapping
	FaultFile     string
	Attrs         string // session_attributes, a YAML flow list; "" keeps the lab file's
}

func l73DaemonYAML(base string, o l73Daemon) (string, error) {
	out, err := l73SetLine(base, "inventory_file: ", "inventory_file: "+o.Inventory)
	if err != nil {
		return "", err
	}
	if o.Listen != "" {
		if out, err = l73SetLine(out, "listen: ", `listen: "`+o.Listen+`"`); err != nil {
			return "", err
		}
	}
	if o.Attrs != "" {
		if out, err = l73SetLine(out, "  session_attributes: ", "  session_attributes: "+o.Attrs); err != nil {
			return "", err
		}
	}
	if out, err = l73AddAfter(out, "limits:", "  malformed_backoff_base: 2s"); err != nil {
		return "", err
	}
	if o.FaultFile != "" {
		if out, err = l73AddAfter(out, "lab:", "  fault_file: "+o.FaultFile); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\ntls_listener:\n  listen: %q\n  cert_file: %s\n  key_file: %s\n  client_ca_file: %s\n",
		o.TLSListen, o.Cert, o.Key, o.ClientCA)
	if o.Intermediates != "" {
		fmt.Fprintf(&b, "  intermediates_file: %s\n", o.Intermediates)
	}
	if len(o.ServerNames) > 0 {
		quoted := make([]string, len(o.ServerNames))
		for i, n := range o.ServerNames {
			quoted[i] = strconv.Quote(n)
		}
		fmt.Fprintf(&b, "  server_names: [%s]\n", strings.Join(quoted, ", "))
	}
	fmt.Fprintf(&b, "  session_ticket_lifetime: %s\n  state_dir: %s\n  certificate_status: %s\n", o.Tickets, o.StateDir, o.Status)
	return out + b.String(), nil
}

// l73SetLine replaces the one line that begins with prefix.
func l73SetLine(cfg, prefix, line string) (string, error) {
	lines := strings.Split(cfg, "\n")
	n := 0
	for i, ln := range lines {
		if strings.HasPrefix(ln, prefix) {
			lines[i] = line
			n++
		}
	}
	if n != 1 {
		return "", fmt.Errorf("the lab config has %d lines beginning %q, want 1", n, prefix)
	}
	return strings.Join(lines, "\n"), nil
}

// l73AddAfter inserts line after the line that is exactly anchor.
func l73AddAfter(cfg, anchor, line string) (string, error) {
	lines := strings.Split(cfg, "\n")
	for i, ln := range lines {
		if ln == anchor {
			rest := append([]string{line}, lines[i+1:]...)
			return strings.Join(append(lines[:i+1], rest...), "\n"), nil
		}
	}
	return "", fmt.Errorf("the lab config has no %q line", anchor)
}

// l73Inventory marks device `transport: tls` in an inventory written with
// one flow mapping per device, as inventory-lab.yaml is.
func l73Inventory(base, device string) (string, error) {
	lines := strings.Split(base, "\n")
	found := false
	for i, ln := range lines {
		if !strings.Contains(ln, "{name: "+device+",") {
			continue
		}
		if strings.Contains(ln, "transport:") {
			return "", fmt.Errorf("the inventory's %s line already names a transport", device)
		}
		j := strings.LastIndex(ln, "}")
		if j < 0 {
			return "", fmt.Errorf("the inventory's %s line is not a flow mapping", device)
		}
		lines[i], found = ln[:j]+", transport: tls"+ln[j:], true
	}
	if !found {
		return "", fmt.Errorf("the inventory names no device %s", device)
	}
	return strings.Join(lines, "\n"), nil
}

// l73Cell is one L73 cell, as spec §15 words it.
type l73Cell struct{ ID, Claim string }

var l73Cells = []l73Cell{
	{"a", "the port it uses with none configured (RFC 9887 says 300; Cisco's documents use 6049)"},
	{"b", "whether every packet has the unencrypted flag set"},
	{"c", "whether it sends SNI, and what"},
	{"d", "whether it checks port49's certificate's dNSName or iPAddress against what it was configured with, and what it does on a mismatch and on an expired server certificate"},
	{"e", "the client certificate its documented enrolment issues: subjectAltName entries, extended key usage, chain sent"},
	{"f", "TLS 1.3 negotiated, and the suite"},
	{"g", "whether it resumes with a port49 ticket"},
	{"h", "single-connection over TLS"},
	{"i", "what it does on each port49 refusal (an alert at the handshake, a reset at Accept, a decline window, an ERROR for an obfuscated packet), and how fast it falls to its next server or local method, as L28 and L31 measured on 49"},
	{"j", "whether it ever falls back to a non-TLS server for the same host (RFC 9887 §5.1.1 forbids it)"},
}

// l73Obs is one cell's observation. Docs is "n/a", "yes", or "**no**: " and
// the document and sentence the observation contradicts.
type l73Obs struct{ ID, Configured, Observed, Docs string }

func l73RenderTable(obs []l73Obs) (string, error) {
	byID := map[string]l73Obs{}
	for _, o := range obs {
		if _, dup := byID[o.ID]; dup {
			return "", fmt.Errorf("cell %s observed twice", o.ID)
		}
		byID[o.ID] = o
	}
	esc := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
	}
	var b strings.Builder
	b.WriteString("| cell | claim | configured | observed | against the docs |\n|---|---|---|---|---|\n")
	for _, c := range l73Cells {
		o, ok := byID[c.ID]
		if !ok {
			return "", fmt.Errorf("cell %s has no observation", c.ID)
		}
		delete(byID, c.ID)
		if strings.TrimSpace(o.Observed) == "" {
			return "", fmt.Errorf("cell %s has an empty observation: a blank row reads as measured", c.ID)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", c.ID, esc(c.Claim), esc(o.Configured), esc(o.Observed), esc(o.Docs))
	}
	for id := range byID {
		return "", fmt.Errorf("observation for unknown cell %q", id)
	}
	return b.String(), nil
}

// l73PEMBlock is the first PEM block on a CLI screen, line endings fixed and
// decoded once to prove it is one, of the wanted type ("CERTIFICATE REQUEST").
func l73PEMBlock(out, want string) ([]byte, error) {
	s := strings.ReplaceAll(out, "\r", "")
	i := strings.Index(s, "-----BEGIN ")
	if i < 0 {
		return nil, errors.New("no PEM block on the screen")
	}
	b, _ := pem.Decode([]byte(s[i:]))
	if b == nil {
		return nil, errors.New("a PEM header with no block after it")
	}
	if b.Type != want {
		return nil, fmt.Errorf("the PEM block on the screen is a %s, want a %s", b.Type, want)
	}
	return pem.EncodeToMemory(b), nil
}

// scpCheckBody allows only what L73 sends over scp: PEM CERTIFICATE blocks
// with whitespace between them. Any other PEM type, a private key above all
// (scpSinkFrame sends mode 0644), and any other byte is refused. The error
// names no part of the body.
func scpCheckBody(body []byte) error {
	rest := bytes.TrimSpace(body)
	if len(rest) == 0 {
		return errors.New("scp: refusing to send an empty body")
	}
	for len(rest) > 0 {
		// pem.Decode skips whatever precedes a block, so the block must start here.
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("scp: refusing to send a body that is not only PEM certificates")
		}
		blk, after := pem.Decode(rest)
		if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
			return errors.New("scp: refusing to send a body that is not only PEM certificates")
		}
		rest = bytes.TrimSpace(after)
	}
	return nil
}

// scpSinkFrame is what an scp source sends a sink for one file: the C line,
// the bytes, the closing NUL.
func scpSinkFrame(name string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "C0644 %d %s\n", len(body), name)
	b.Write(body)
	b.WriteByte(0)
	return b.Bytes()
}

// l73MetricValue is the value of one exposition line, selector included, and
// whether the series exists: a misspelled selector is absent, not zero.
func l73MetricValue(exposition, selector string) (float64, bool) {
	for _, l := range strings.Split(exposition, "\n") {
		if strings.HasPrefix(l, selector+" ") {
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(l, selector)), 64)
			if err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

var (
	l73LogDrop = regexp.MustCompile(`(?i)password|token|secret|eyJ`)
	l73LogHash = regexp.MustCompile(`\$[0-9][a-z]?\$[^[:space:]"]*`)
	l73LogLong = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
)

// l73ScrubLog is the lab's log-reading rule as code: drop every line naming
// a password, token, secret or JWT, mask every crypt or $9$ hash whatever its
// length, and shorten every long run.
func l73ScrubLog(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if l73LogDrop.MatchString(ln) {
			continue
		}
		ln = l73LogHash.ReplaceAllString(ln, "<HASH>")
		out = append(out, l73LogLong.ReplaceAllString(ln, "<LONG>"))
	}
	return strings.Join(out, "\n")
}

// l73Grade is a refusal cell's verdict. "refused" needs positive evidence
// that the handshake failed (a handshake_failed record); a login that failed
// with no such record is a failure of unproven cause, never the cell's
// verdict.
func l73Grade(loginOK, redeemed, reasonProven bool) string {
	switch {
	case loginOK && redeemed:
		return "accepted"
	case reasonProven:
		return "refused"
	default:
		return "login failed, cause unproven"
	}
}
