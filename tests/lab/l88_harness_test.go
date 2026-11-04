//go:build lab

package lab

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/blanketfish/port49/tests/deviceaaa"
)

// L88 loads the shipped reference AAA configurations (deploy/device-aaa) onto each lab
// image and measures each cell of spec section 15's L88 row under them. The files are
// rendered by tests/deviceaaa, the package its unit tests run, and pushed unchanged.

// l88Refs maps a lab platform's name to the reference file's platform.
var l88Refs = map[string]string{
	"arista_eos": "arista_eos", "arista_ceos": "arista_eos",
	"cisco_iosxe": "cisco_iosxe", "cisco_nxos": "cisco_nxos", "cisco_xrd": "cisco_iosxr",
	"juniper_vjunos-router": "juniper_junos", "juniper_vsrx": "juniper_junos",
	"nokia_srlinux": "nokia_srlinux",
}

// l88Servers are the reference's two servers: port49d is on the first; the second is a
// bridge address where nothing listens, so a connection to it is refused at once.
var l88Servers = []string{"172.100.100.1", "172.100.100.2"}

// l88TLSImages are the images with an RFC 9887 client (cell h).
var l88TLSImages = map[string]bool{"srlinux": true, "vjunos26": true, "iosxe1718": true, "nxos106": true, "ceos436": true, "xrd261": true}

// l88L29 are the rows whose reload behaviour L29 measured, so cell g skips them.
var l88L29 = map[string]bool{"eos": true, "vjunos": true, "nxos": true, "iosxe": true}

func l88HasTLS(sel string) bool { return l88TLSImages[sel] }

// l88Cells is the cells one pass runs. tls is cell h, the RFC 9887 pass (PORT49_L88_TLS=1).
func l88Cells(sel string, tls bool) []string {
	if tls && l88PlatformOf(sel) == "nokia_srlinux" {
		// SR Linux's client never speaks TLS (cell h, measured), so a-f have nothing to run over it.
		return []string{"h"}
	}
	if tls {
		// Cell h, the cells where the transport changes what the device does (ruled 2026-11-04);
		// c, g and i do not depend on it and are measured on the plain pass.
		return []string{"a", "b", "d", "e", "f"}
	}
	cells := []string{"a", "b", "c", "d", "e", "f"}
	if !tls && l88PlatformOf(sel) == "cisco_iosxe" {
		// f2: what an IOS XE does after a break-glass session ran with port49d down.
		cells = append(cells, "f2", "f3")
	}
	if !l88L29[sel] {
		cells = append(cells, "g")
	}
	if strings.HasPrefix(l88PlatformOf(sel), "juniper_") {
		cells = append(cells, "i")
	}
	return cells
}

func l88PlatformOf(sel string) string {
	for _, p := range platforms {
		if p.sel == sel {
			return p.name
		}
	}
	return ""
}

// l88Values are the lab's values for p's placeholders.
func l88Values(p platform, servers []string) deviceaaa.Values {
	v := deviceaaa.Values{Servers: servers, BreakGlass: breakglassUser, TLSPort: 300,
		ServerName: p.node, CertID: "port49-device", SourceAddress: p.addr}
	if l88TLSPass() {
		v.CertID = l73CertID // L73's enrolment made the device's certificate under this id
	}
	switch p.name {
	case "arista_eos", "arista_ceos":
		v.MgmtVRF, v.SourceInterface = "default", "Management1"
		if p.name == "arista_ceos" {
			v.SourceInterface = "Management0"
		}
	case "cisco_iosxe":
		v.MgmtVRF, v.SourceInterface = "clab-mgmt", "GigabitEthernet1"
	case "cisco_nxos":
		v.MgmtVRF, v.SourceInterface = "management", "mgmt0"
	case "cisco_xrd":
		v.MgmtVRF, v.SourceInterface = "default", "MgmtEth0/RP0/CPU0/0"
		if n := l88XRVRF(); n != "" {
			v.MgmtVRF = n
		}
	case "nokia_srlinux":
		v.MgmtVRF = "mgmt"
	default:
		// fxp0's own address: vrnetlab NATs the VM's 10.0.0.15 to the container's, which is the
		// address port49d sees (L12). A source-address the box does not hold never leaves it.
		v.MgmtVRF, v.SourceAddress = "mgmt_junos", "10.0.0.15"
	}
	return v
}

// l88ApplyWith renders the shipped file for p and hands its lines, unchanged, to push.
func l88ApplyWith(p platform, transport string, servers []string, push func(lines []string) error) error {
	ref, ok := l88Refs[p.name]
	if !ok {
		return fmt.Errorf("no reference configuration for %s", p.name)
	}
	srlTLS := p.name == "nokia_srlinux" && transport == "tls"
	if srlTLS {
		transport = "tcp" // SR Linux over RFC 9887 is not measured (L92): the plain reference, then a tls-profile and port 300 (cell h)
	}
	lines, err := deviceaaa.Render(ref, transport, l88Values(p, servers), labKeyDefault)
	if err != nil {
		return err
	}
	if srlTLS { // the plain reference, then the one change an operator would try: a tls-profile and port 300
		if err := push(lines); err != nil {
			return err
		}
		var more []string
		for _, sv := range servers {
			more = append(more, "set / system aaa server-group port49 server "+sv+" tls-profile "+l73CertID,
				"set / system aaa server-group port49 server "+sv+" tacacs port 300")
		}
		return push(more)
	}
	return push(lines)
}

// l88Opener is the break-glass CLI of p.
func l88Opener(p platform) func(*lab) (*cliConn, error) {
	switch p.name {
	case "arista_eos":
		return func(l *lab) (*cliConn, error) { return l.eosCLI(breakglassUser, breakglassPassword) }
	case "juniper_vsrx":
		return func(l *lab) (*cliConn, error) { return l.junosCLI(breakglassUser, breakglassPassword) }
	case "nokia_srlinux":
		// Setup goes through sr_cli (l88SRPush); no break-glass CLI is opened for it.
		return func(*lab) (*cliConn, error) { return nil, nil }
	}
	return l73Opener(p.name)
}

func l88Junos(p platform) bool { return strings.HasPrefix(p.name, "juniper_") }

// l88Family is the family l73's line runners know, "" for vEOS.
func l88Family(p platform) string { return l73Dialects[p.name].Family }

// l88Push types lines on the device over c and reads them back.
func l88Push(p platform, c *cliConn, lines []string) error {
	if p.name == "nokia_srlinux" {
		return l88SRPush(lines)
	}
	if l88Junos(p) {
		// A long line (a password hash) wraps at the pty's width, and the wrap reads as an answer.
		if _, err := c.sendExpect("set cli screen-width 1000", 45*time.Second, junosOpPrompt); err != nil {
			return err
		}
		if _, err := junosConfigure(c, lines...); err != nil {
			c.sendExpect("rollback 0", 60*time.Second, junosCfgPrompt)
			c.sendExpect("exit configuration-mode", 60*time.Second, junosOpPrompt)
			return err
		}
		// The device shows a hash in its own form; cell a's control login is what proves it took.
		var check []string
		for _, ln := range l88ExpandLists(lines) {
			if !strings.Contains(ln, " encrypted-password ") {
				check = append(check, ln)
			}
		}
		return junosVerifyApplied(c, check)
	}
	if out, err := l73CiscoRun(c, l88WithCommit(p, l73Lines(lines...)), nil, false, l73ExtraMarks(l88Family(p))...); err != nil {
		if len(out) > 2500 {
			out = out[len(out)-2500:]
		}
		return fmt.Errorf("%w; the device said: %s", err, oneLine(out))
	}
	shown, err := c.sendExpect("show running-config", 60*time.Second, c.prompt)
	if err != nil {
		return err
	}
	if missing := l88Missing(lines, shown); len(missing) > 0 {
		var near []string
		for _, ln := range strings.Split(strings.ReplaceAll(shown, "\r", ""), "\n") {
			if l := strings.ToLower(ln); strings.Contains(l, "tacacs") || strings.Contains(l, "server ") || strings.Contains(l, "trustpoint") || strings.Contains(l, "enrollment") {
				near = append(near, strings.TrimSpace(ln))
			}
		}
		return fmt.Errorf("the device lacks %d line(s) that were typed: %s; its lines naming a server: %s", len(missing),
			strings.Join(missing, "; "), strings.Join(near, " | "))
	}
	return nil
}

// l88Missing names the lines (trimmed, blanks squeezed) the running configuration does
// not hold. A line carrying the key is skipped: the device shows it hashed.
//
// EOS shows the default VRF by leaving the clause out, so ` vrf default` is dropped from
// both sides: the lab's vEOS and cEOS manage in the default VRF. A default `privilege 1` is
// not shown either.
func l88Missing(lines []string, shown string) []string {
	norm := func(s string) string {
		s = strings.ReplaceAll(strings.Join(strings.Fields(s), " "), " vrf default", "")
		s = strings.ReplaceAll(s, " privilege 1 ", " ")                             // the default level is not shown
		s = strings.ReplaceAll(s, "enrollment url terminal", "enrollment terminal") // XR 26.1.1 spells it so
		// EOS shows a TLS host without its port when that is 300, the RFC 9887 default, and puts
		// `tls` last (cEOS 4.36.3M, L88 cell h).
		if strings.Contains(s, " tls") {
			s = strings.ReplaceAll(s, " port 300", "")
			s = strings.ReplaceAll(s, " tls single-connection", " single-connection tls")
		}
		return s
	}
	have := map[string]bool{}
	var host string // XR shows a server's options as lines under its `tacacs-server host` line
	tlsUnder := false
	for _, ln := range strings.Split(strings.ReplaceAll(shown, "\r", ""), "\n") {
		if strings.HasPrefix(ln, "tacacs-server host ") {
			host, tlsUnder = strings.TrimSpace(ln), false
		} else if host != "" && strings.HasPrefix(ln, " ") {
			child := strings.TrimSpace(ln)
			if child == "tls" {
				tlsUnder = true // XR 26.1.1 nests `trustpoint T` under `tls` under the host
			} else if tlsUnder && strings.HasPrefix(ln, "  ") {
				child = "tls " + child
			}
			have[norm(host+" "+child)] = true
		} else {
			host = ""
		}
		have[norm(ln)] = true
	}
	var missing []string
	for _, ln := range lines {
		n := norm(ln)
		if n == "" || n == "exit" || strings.Contains(ln, labKeyDefault) || have[n] {
			continue
		}
		missing = append(missing, n)
	}
	return missing
}

// l88Apply pushes the reference for transport over the break-glass session, with port49d
// stopped (the device takes the local password only then), and starts port49d again.
func l88Apply(l *lab, transport string) error {
	return l88ApplyServers(l, transport, l88Servers)
}

func l88ApplyServers(l *lab, transport string, servers []string) error {
	return l88Admin(l, func(c *cliConn) error {
		return l88ApplyWith(l.p, transport, servers, func(lines []string) error { return l88Push(l.p, c, lines) })
	})
}

// l88Admin opens the break-glass CLI with port49d stopped, runs fn, and restarts port49d.
func l88Admin(l *lab, fn func(c *cliConn) error) error {
	open := l88Opener(l.p)
	if open == nil {
		return fmt.Errorf("no break-glass CLI for %s", l.p.name)
	}
	if err := l.stopDaemon(); err != nil {
		return err
	}
	c, err := open(l)
	var fnErr error
	if err == nil {
		fnErr = fn(c)
		if c != nil {
			c.Close()
		}
	}
	base, cerr := l.configPath()
	if cerr == nil {
		cerr = l.startDaemonWith(base, true)
	}
	return errors.Join(err, fnErr, cerr)
}

// l88Clear is the lines that take the lab startup config's own TACACS+ servers off before
// the reference goes on: they would otherwise list the same address twice (IOS XE drops
// the second object). They are lab scaffolding and are not the shipped file.
func l88Clear(p platform) []string {
	switch p.name {
	case "arista_eos", "arista_ceos":
		return []string{"aaa group server tacacs+ port49", "no server 172.100.100.1", "exit", "no tacacs-server host 172.100.100.1"}
	case "cisco_iosxe":
		return []string{"aaa group server tacacs+ port49", "no server name port49-host", "exit", "no tacacs server port49-host"}
	case "cisco_xrd":
		if l88TLSPass() {
			// The startup config's plain host on port 49 beside the TLS host on 300 at the same address
			// leaves a group member that means two servers; a TLS pass starts from none.
			return []string{"aaa group server tacacs+ port49", "no server 172.100.100.1", "exit", "no tacacs-server host 172.100.100.1 port 49"}
		}
	case "cisco_nxos":
		if l88TLSPass() {
			// The startup config's host carries a key; "No key on a TLS host" (the reference) needs it gone.
			return []string{"aaa group server tacacs+ port49", "no server 172.100.100.1", "exit", "no tacacs-server host 172.100.100.1"}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The local account of cell a, and its password
// ---------------------------------------------------------------------------

const l88DenyUser = "l88deny"

// l88PasswordHash is the platform's hashed form of pw: Junos encrypted-password, EOS
// secret sha512, IOS XE secret 9, NX-OS password 5, XR secret 10, SR Linux's hashed
// password. The password is never an argument.
func l88PasswordHash(name, pw string) (string, error) {
	switch name {
	case "cisco_nxos":
		cmd := exec.Command("openssl", "passwd", "-1", "-stdin")
		cmd.Stdin = strings.NewReader(pw)
		out, err := cmd.Output()
		if err != nil {
			return "", errors.New("openssl passwd -1 failed")
		}
		return strings.TrimSpace(string(out)), nil
	case "cisco_iosxe":
		return l88Type9(pw)
	}
	return l73RootHash(pw)
}

// l88Type9 is Cisco's scrypt hash (`secret 9`): N 16384, r 1, p 1, a 14-character salt,
// the 32-byte result in Cisco's base64 alphabet.
func l88Type9(pw string) (string, error) {
	const alpha = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	raw := make([]byte, 14)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	salt := make([]byte, 14)
	for i, b := range raw {
		salt[i] = alpha[int(b)%len(alpha)]
	}
	key, err := scrypt.Key([]byte(pw), salt, 16384, 1, 1, 32)
	if err != nil {
		return "", err
	}
	var enc []byte
	for i := 0; i < len(key); i += 3 {
		var v uint32
		n := 0
		for j := 0; j < 3 && i+j < len(key); j++ {
			v |= uint32(key[i+j]) << (8 * (2 - j))
			n++
		}
		for k := 0; k < n+1; k++ {
			enc = append(enc, alpha[(v>>(6*(3-k)))&63])
		}
	}
	return "$9$" + string(salt) + "$" + string(enc), nil
}

// l88LocalAccount is the lines that add and remove cell a's local account. The hash is
// the only secret, and the delete lines carry none.
func l88LocalAccount(name, user, hash string) (add, del []string) {
	switch name {
	case "juniper_vjunos-router", "juniper_vsrx", "juniper_vjunos-switch":
		// Two lines: `display set` shows the class and the password apart.
		return []string{"set system login user " + user + " class read-only",
				`set system login user ` + user + ` authentication encrypted-password "` + hash + `"`},
			[]string{"delete system login user " + user}
	case "arista_eos", "arista_ceos":
		return []string{"username " + user + " privilege 1 secret sha512 " + hash}, []string{"no username " + user}
	case "cisco_iosxe":
		return []string{"username " + user + " privilege 1 secret 9 " + hash}, []string{"no username " + user}
	case "cisco_nxos":
		return []string{"username " + user + " password 5 " + hash + " role network-operator"}, []string{"no username " + user}
	case "nokia_srlinux":
		// Brace form, as the reference file is; the role p49-read exists in the lab config and the reference.
		return []string{"system {", "aaa {", "authentication {", "user " + user + " {", "password " + hash, "role [", "p49-read", "]", "}", "}", "}", "}"},
			[]string{"delete system aaa authentication user " + user}
	case "cisco_xrd":
		// XR takes the group and the secret in the user's own submode (the one-line form is refused).
		return []string{"username " + user, "group root-lr", "secret 10 " + hash, "exit"}, []string{"no username " + user}
	}
	return nil, nil
}

// l88Shape is a hash's first characters, for a failure message.
func l88Shape(h string) string {
	if len(h) > 4 {
		return h[:4] + "..."
	}
	return h
}

// ---------------------------------------------------------------------------
// The decision log
// ---------------------------------------------------------------------------

// l88AccountCounts is the accounting START and STOP records user's session reached
// port49 with.
func l88AccountCounts(recs []map[string]any, user string) (starts, stops int) {
	for _, r := range recs {
		if str(r, "event") != "account" {
			continue
		}
		if u := str(r, "username"); u != user && str(sub(r, "session"), "username") != user && str(r, "user") != user {
			continue
		}
		switch str(r, "flags") {
		case "start":
			starts++
		case "stop":
			stops++
		}
	}
	return starts, stops
}

// ---------------------------------------------------------------------------
// The note
// ---------------------------------------------------------------------------

type l88Cell struct{ id, verdict, observation, evidence string }

// l88Note collects the cells and writes one results note. Every string passes through
// l73MaskAll with the run's secrets when it is rendered, and render refuses a note that
// still holds the password.
type l88Note struct {
	id        string // the register entry the note is for; empty is L88
	p         platform
	transport string
	secrets   []string
	cells     []l88Cell
	facts     []string
	raw       string // text added after masking: only the unit test uses it
	captures  []string
	noCapture string // why a run kept no capture, written when it took none
}

// capture records the evidence file a cell's capture is committed as; render cites each.
func (n *l88Note) capture(path string) {
	if path != "" && !slices.Contains(n.captures, path) {
		n.captures = append(n.captures, path)
	}
}

func newL88Note(p platform, transport string, secrets ...string) *l88Note {
	return &l88Note{p: p, transport: transport, secrets: append(slices.Clone(secrets), labKeyDefault, breakglassPassword)}
}

func (n *l88Note) cell(id, verdict, observation, evidence string) {
	n.cells = append(n.cells, l88Cell{id, verdict, observation, evidence})
}

func (n *l88Note) fact(f string) { n.facts = append(n.facts, f) }

var l88Long = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)

// l88Hashed is a device-hashed secret ($aes1$ on SR Linux, $6$ and $9$ on Junos and others): the
// salt prefix alone is not shown either.
var l88Hashed = regexp.MustCompile(`\$(?:aes1|6|9)\$\S*`)

// l88DropKeyLines is s without the lines whose first word is `key`: an SR Linux TLS profile's
// private key, which the harness never writes whatever its form.
func l88DropKeyLines(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if f := strings.Fields(ln); len(f) > 0 && f[0] == "key" {
			out = append(out, "    key <removed>")
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// addSecret registers a credential the run used (a token) for masking.
func (n *l88Note) addSecret(s string) { n.secrets = append(n.secrets, s) }

// redact is s with every credential the run used replaced by <redacted>, then every run of
// 24 or more token characters by <LONG>. Text is redacted before it is kept or written.
func (n *l88Note) redact(s string) string {
	for _, sec := range n.secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "<redacted>")
		}
	}
	return l88Long.ReplaceAllStringFunc(l88Hashed.ReplaceAllString(hideKeys(s), "<hash>"), func(m string) string {
		if strings.HasPrefix(m, "tests/lab/evidence/") || strings.HasPrefix(m, "tests/lab/results/") {
			return m // a pointer to a committed file is not a secret
		}
		return "<LONG>"
	})
}

// mask is s with every secret of the run replaced.
func (n *l88Note) mask(s string) string {
	return l88Hashed.ReplaceAllString(hideKeys(l73MaskAll(s, n.secrets...)), "<hash>")
}

func (n *l88Note) render() (string, error) {
	var b strings.Builder
	id := cmp.Or(n.id, "L88")
	fmt.Fprintf(&b, "# %s: the reference AAA configuration on %s\n\n", id, n.p.version)
	fmt.Fprintf(&b, "Platform: %s. Image: %s. Transport: %s. Measured %s by Test%s.\n\n", n.p.name, n.p.version, n.transport,
		time.Now().UTC().Format("2006-01-02"), id)
	for _, f := range n.facts {
		b.WriteString("- " + n.mask(f) + "\n")
	}
	// CLAUDE.md rule 3: every note points at a capture, or says why none was kept.
	for _, c := range n.captures {
		fmt.Fprintf(&b, "\nCapture: `%s` (redacted copy of the run's capture)\n", c)
	}
	if len(n.captures) == 0 {
		why := n.noCapture
		if why == "" {
			why = "no cell of this run took a capture"
		}
		fmt.Fprintf(&b, "\nCapture: none kept: %s\n", why)
	}
	b.WriteString("\n| Cell | Verdict | Observation |\n|---|---|---|\n")
	for _, c := range n.cells {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", c.id, c.verdict, strings.ReplaceAll(n.mask(c.observation), "\n", " "))
	}
	for _, c := range n.cells {
		if c.evidence != "" {
			fmt.Fprintf(&b, "\n### Cell %s evidence\n\n```\n%s\n```\n", c.id, n.mask(c.evidence))
		}
	}
	out := b.String() + n.raw
	for _, s := range n.secrets {
		if s != "" && strings.Contains(out, s) {
			return "", errors.New("the L88 note still holds a secret after masking; it is not written")
		}
	}
	return out, nil
}

// l88ExpandLists is lines with each `set a b [ x y ]` replaced by `set a b x` and `set a b y`:
// `show configuration | display set` prints one line per member.
func l88ExpandLists(lines []string) []string {
	var out []string
	for _, ln := range lines {
		i, j := strings.Index(ln, " [ "), strings.LastIndex(ln, " ]")
		if i < 0 || j < i {
			out = append(out, ln)
			continue
		}
		for _, m := range strings.Fields(ln[i+3 : j]) {
			out = append(out, ln[:i]+" "+m+ln[j+2:])
		}
	}
	return out
}

// l88WithCommit ends an XR session's items with `commit`: XR keeps a change in its candidate
// until then. It is the device's dialogue, not part of the shipped file.
func l88WithCommit(p platform, items []l73Dialog) []l73Dialog {
	if l88Family(p) == "xr" {
		items = append(items, l73Dialog{Cmd: "commit"})
	}
	return items
}

// l88XRVRF is the named VRF the XR named-VRF pass builds for the management interface
// (PORT49_L88_XR_VRF=<name>); empty is the default-VRF pass. XR reserves the name default.
func l88XRVRF() string { return os.Getenv("PORT49_L88_XR_VRF") }

// l88XRVRFLines move the lab's management interface (and the SSH server the harness reaches
// it by) into the named VRF in one commit, and back. They are lab scaffolding, not the
// shipped file; the interface keeps its address and is on the lab subnet, so the TACACS+
// servers are directly connected.
func l88XRVRFLines(name, addr string) (set, undo []string) {
	set = []string{"vrf " + name, " address-family ipv4 unicast", "exit", "exit",
		"interface MgmtEth0/RP0/CPU0/0", " vrf " + name, " ipv4 address " + addr + " 255.255.255.0", "exit",
		"ssh server vrf " + name}
	undo = []string{"no ssh server vrf " + name, "interface MgmtEth0/RP0/CPU0/0", " no vrf " + name,
		" ipv4 address " + addr + " 255.255.255.0", "exit", "no vrf " + name}
	return set, undo
}

// l88Refusals are the refusal texts of the platforms L29 did not measure, as L88's cell e
// recorded them, so that cell g can use L29's phase code on them.
var l88Refusals = map[string]string{
	// tests/lab/results/L88-cisco_xrd.md cell e: `% Command authorization failed`
	"cisco_xrd": "% Command authorization failed",
	// tests/lab/results/L88-juniper_vsrx.md cell e: `error: unknown command: clear`
	"juniper_vsrx": "unknown command",
	// tests/lab/results/L88-arista_ceos.md cell e: `% Authorization denied for command 'show clock'`
	"arista_ceos": "% Authorization denied for command",
	// tests/lab/results/L76-nokia_srlinux.md: the role rules refuse with `No authorization to execute command`
	"nokia_srlinux": "No authorization to execute command",
}

func init() {
	for k, v := range l88Refusals {
		if _, ok := l29Refusals[k]; !ok {
			l29Refusals[k] = v
		}
	}
}

// l88SRPush loads lines into SR Linux's candidate datastore and commits, through sr_cli in
// the node as the container's root (outside TACACS+, as L76 did). It is setup, not
// break-glass: the break-glass logins the cells measure are pty logins over SSH.
func l88SRPush(lines []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", l76Container, "sr_cli", "-d")
	cmd.Stdin = strings.NewReader("enter candidate\n" + strings.Join(lines, "\n") + "\ncommit now\n")
	out, err := cmd.CombinedOutput()
	low := strings.ToLower(string(out))
	if err != nil || strings.Contains(low, "error") || strings.Contains(low, "invalid") || strings.Contains(low, "unknown") {
		o := string(out)
		if len(o) > 2500 {
			o = o[len(o)-2500:]
		}
		return fmt.Errorf("sr_cli refused the load (%v); it said: %s", err, oneLine(o))
	}
	return nil
}

// l88TLSConfig is port49d's config for the TLS pass: lab.configPath() returns it, so every
// restart (the break-glass pushes, a cell's cleanup) runs port49d with its RFC 9887 listener.
var l88TLSConfig string

// l88TLSSplit is what the split deployment cell d starts needs of the TLS pass: the inventory
// with the device's TLS entry, and the tls_listener block.
var l88TLSSplit struct{ Inventory, Block string }

// l88TLSPass is cell h's run: PORT49_L88_TLS=1.
func l88TLSPass() bool { return os.Getenv("PORT49_L88_TLS") == "1" }

// l88ReferenceNames gives L73's enrolment the names the shipped reference files use for the
// root CA's trust object, so the reference is applied unchanged over the enrolment.
func l88ReferenceNames(t *testing.T) {
	was := [...]string{l73RootProfile, l73TrustGroup, l73EOSRootFile, l73EOSInterFile, l73CiscoKey}
	t.Cleanup(func() { // L73's own tests share these
		l73RootProfile, l73TrustGroup, l73EOSRootFile, l73EOSInterFile, l73CiscoKey = was[0], was[1], was[2], was[3], was[4]
	})
	l73RootProfile, l73TrustGroup = "port49-root", "port49"
	l73EOSRootFile, l73EOSInterFile = "port49-root.crt", "port49-intermediate.crt"
	// The reference trustpoints name the key by the certificate id (eckeypair/rsakeypair <CERT_ID>).
	l73CiscoKey = l73CertID
}

// enrolTLS runs L73's enrolment on the device (its own PKI, key and certificate, trust of
// the root) and starts port49d on the config with an RFC 9887 listener on 300, then makes
// that config the one every restart uses. The reference is applied after this.
func (e *l88Env) enrolTLS() {
	l88ReferenceNames(e.t)
	srl := e.l.p.name == "nokia_srlinux"
	d, ok := l73Dialects[e.l.p.name]
	if srl {
		d, ok = l73Dialect{Family: "srl"}, true // L73 never ran SR Linux; its enrolment is written here
	}
	if !ok {
		e.t.Fatalf("INVALID: no L73 dialect for %s", e.l.p.name)
	}
	le := newL73Env(e.t, e.l, d)
	if !srl && !le.helpProbe() {
		e.t.Fatalf("INVALID: %s lists no RFC 9887 client", e.l.p.name)
	}
	// Cell f has the device dial the second address too, and a device that checks the name against
	// the certificate (the address it dialled) needs that address in it.
	now := time.Now()
	le.writeServer("server", le.pki.Root, l73ServerLeaf{DNSNames: []string{"tacacs.l73.example"},
		IPs: []net.IP{net.ParseIP(l73Server), net.ParseIP(l73SecondServer)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if srl {
		e.enrolSRLinux(le)
	} else {
		le.enrol()
	}
	le.daemon("l88", l73Daemon{Intermediates: le.files["inter.pem"]})
	// L73's cleanup restores the device's plain servers over a break-glass login; the lab VM is
	// destroyed after this run, and a device that answers locally for a while after the cells (IOS
	// XE) fails that login with an INVALID that says nothing about the cells.
	le.touched = false
	cfg, err := os.ReadFile(le.cfg)
	e.must("reading the TLS config", err)
	i := strings.Index(string(cfg), "\ntls_listener:")
	if i < 0 {
		e.t.Fatalf("INVALID: the TLS config has no tls_listener block")
	}
	inv, err := os.ReadFile(le.invTLS)
	e.must("reading the TLS inventory", err)
	l88TLSConfig, l88TLSSplit.Block, l88TLSSplit.Inventory = le.cfg, string(cfg)[i:], string(inv)
	e.t.Cleanup(func() {
		l88TLSConfig = ""
		l88TLSSplit.Block, l88TLSSplit.Inventory = "", ""
	})
	if e.l.p.name == "nokia_srlinux" {
		e.n.fact("only cell h ran: SR Linux over RFC 9887 is not measured (the schema has `server tls-profile`; L73 has no SR Linux enrolment dialect, register entry L92). This run is one observation of what the client does with a profile set. The plain reference " +
			"(`deploy/device-aaa/nokia_srlinux.cli`) was loaded, then each server was given `tls-profile " + l73CertID +
			"` and `tacacs port 300`, the one change an operator would try. The default CPM filter accepts a TACACS+ reply only from source port 49 " +
			"(entry 110), so this run added entry 111 for source port 300; without it the device's SYN gets a SYN-ACK and nothing more")
		e.n.fact("port49d's tls_listener on " + l73Server + ":" + strconv.Itoa(l73TLSPort) + " (L73's PKI; the device's profile `" + l73CertID +
			"` holds its key, certificate and the root)")
		return
	}
	e.n.fact("cells run over RFC 9887: a, b, d, e, f. c, g, i: not transport-dependent, measured on the plain pass (" +
		l88NoteName0(e.l.p) + ")")
	e.n.fact("port49d's server certificate carries both server addresses (" + l73Server + ", " + l73SecondServer +
		") as IP names, because cell f has the device dial the second one; with the first alone, a device that checks the dialled address would refuse the second server for the certificate, not for failover")
	e.n.fact("RFC 9887 enrolment by L73's machinery (its own PKI; the device's key and certificate id `" + l73CertID +
		"`, the root trusted as `" + l73RootProfile + "`); port49d's tls_listener on " + l73Server + ":" + strconv.Itoa(l73TLSPort) +
		". The reference TLS file was then applied over it unchanged.")
}

// enrolSRLinux makes the device's key and request off the box, has the lab intermediate sign
// it, and loads a TLS profile (key, certificate with the intermediate after the leaf, the root
// as trust anchor) through sr_cli: SR Linux's profile takes PEM text in its leaves.
func (e *l88Env) enrolSRLinux(le *l73Env) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e.must("making the device key", err)
	der, err := x509.MarshalECPrivateKey(key)
	e.must("encoding the device key", err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	e.n.addSecret(keyPEM)
	e.n.addSecret(oneLine(keyPEM)) // sr_cli's refusal text is one-lined before it is masked
	le.secrets = append(le.secrets, keyPEM)
	node, ip := e.l.p.node, net.ParseIP(e.l.p.addr)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: node}, DNSNames: []string{node}, IPAddresses: []net.IP{ip}}, key)
	e.must("making the device request", err)
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	le.sign(csr, "made off the device (SR Linux's profile takes a PEM key; the lab's own request)")
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: le.leaf.Raw}))
	profile := l73CertID
	q := func(s string) string { return `"` + s + `"` }
	// The default CPM filter lets a TACACS+ reply in only from source port 49 (entry 110).
	e.must("accepting replies from port 300", l88SRPush([]string{
		`set / acl acl-filter cpm type ipv4 entry 111 description "Accept incoming TACACS+ over TLS when this router initiates the TCP connection"`,
		"set / acl acl-filter cpm type ipv4 entry 111 match ipv4 protocol tcp",
		"set / acl acl-filter cpm type ipv4 entry 111 match transport source-port operator eq",
		"set / acl acl-filter cpm type ipv4 entry 111 match transport source-port value 300",
		"set / acl acl-filter cpm type ipv4 entry 111 action accept"}))
	e.must("loading the TLS profile", l88SRPush([]string{
		"set / system tls profile " + profile + " key " + q(keyPEM),
		"set / system tls profile " + profile + " certificate " + q(leaf+string(le.pki.Inter.PEM())),
		"set / system tls profile " + profile + " trust-anchor " + q(string(le.pki.Root.PEM()))}))
	e.n.fact("SR Linux enrolment: the harness made the key and request, the lab intermediate signed it, and `system tls profile " +
		profile + "` was loaded with the key, the leaf and intermediate, and the root as trust anchor (L73 never ran SR Linux)")
}
