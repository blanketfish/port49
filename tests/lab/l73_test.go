//go:build lab

package lab

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// scpWrite is the source side of scp's protocol to a sink at path: wait for
// its ack, send the C line, ack, the bytes and a NUL, ack. L73 sends only
// public certificates this way.
func scpWrite(c *ssh.Client, path string, body []byte) error {
	if err := scpCheckBody(body); err != nil {
		return err
	}
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	defer time.AfterFunc(60*time.Second, func() { s.Close() }).Stop()
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	var stderr bytes.Buffer
	s.Stderr = &stderr
	if err := s.Start("scp -t " + path); err != nil {
		return err
	}
	r := bufio.NewReader(out)
	ack := func() error {
		b, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("scp: %v %s", err, oneLine(stderr.String()))
		}
		if b != 0 {
			msg, _ := r.ReadString('\n')
			return fmt.Errorf("scp refused: %s %s", strings.TrimSpace(msg), oneLine(stderr.String()))
		}
		return nil
	}
	frame := scpSinkFrame(filepath.Base(path), body)
	nl := bytes.IndexByte(frame, '\n')
	for _, step := range [][]byte{nil, frame[:nl+1], frame[nl+1:]} {
		if step != nil {
			if _, err := in.Write(step); err != nil {
				return err
			}
		}
		if err := ack(); err != nil {
			return err
		}
	}
	in.Close()
	if err := s.Wait(); err != nil && err != io.EOF {
		return fmt.Errorf("scp: %v %s", err, oneLine(stderr.String()))
	}
	return nil
}

func l73Claim(vendor string) string {
	return vendor + "'s RFC 9887 (TACACS+ over TLS) client against port49d's tls_listener, cell by cell (policy " +
		"engine spec §15 L73; §13 decision 50 rulings 1, 2, 6, 7, 8, 10, 11, 13, 15). L73 stays open: this note is one " +
		"platform's, and spec §15's L73 row lists the rest."
}

type l73Env struct {
	t         *testing.T
	l         *lab
	d         l73Dialect
	opener    func(*lab) (*cliConn, error)
	x         map[string]bool // the Want words the image's help listed
	applied   *l73DeviceTLS   // IOS XE, NX-OS, EOS: the lines now on the device, undone before the next
	dir       string          // 0700: configs, inventories, keys, state
	home      string          // a port49 CLI's HOME, issued_key_store: file
	evDir     string
	capDir    string // git-ignored, outside writeEvidence's *.pcap glob
	pki       *l73PKI
	files     map[string]string
	invTLS    string
	invTCP    string
	evidence  map[string][]byte // written only by note(), after the leak gate
	secrets   []string
	obs       []l73Obs
	facts     []string
	first     []l73Conn // cell a's connections: c and f read them
	firstSpan l73Span   // the control login in e.first, for h's comparison
	port      int       // 0 when the device's default is 300
	needSec   bool
	tokenN    int
	start     int64 // decision log offset when L73 began
	csr       l73CSR
	leaf      *x509.Certificate
	l71Obs    string
	touched   bool
	bridge    bool
	cfg       string // port49d's config now: the last daemon() call's, "" for the standing one
	listen    string // the RFC 8907 address the last daemon() call moved the plain listener to, "" for the standing one
}

func TestL73(t *testing.T) {
	// Held until TestMain's teardown has destroyed the topology (labRelease).
	if err := labOccupyForRun(labLockPath, "TestL73 pid "+strconv.Itoa(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatal(err)
	}
	// Names only: nothing here touches another container.
	if out, err := exec.Command("docker", "ps", "--filter", "label=containerlab", "--format", "{{.Names}}").Output(); err != nil {
		t.Fatalf("INVALID: docker ps: %v", err)
	} else if s := strings.TrimSpace(string(out)); s != "" {
		t.Fatalf("a containerlab topology is already up (%s): the lab is single-occupant", strings.ReplaceAll(s, "\n", ", "))
	}
	eachOptInPlatform(t, func(t *testing.T, l *lab) {
		d, ok := l73Dialects[l.p.name]
		if !ok || !optInPlatforms[l.p.sel] {
			t.Skipf("TestL73 measures the opt-in L73 rows; %s (%s) is not one", l.p.sel, l.p.version)
		}
		if d.HelpOnly {
			e := &l73Env{t: t, l: l, d: d, opener: l73Opener(l.p.name), evidence: map[string][]byte{},
				evDir: filepath.Join(root, "tests", "lab", "evidence", "L73-"+l.p.name)}
			if e.helpProbe() {
				t.Logf("%s lists an RFC 9887 client; a full L73 run on it is a follow-up", l.p.version)
			}
			e.writeL71()
			return
		}
		e := newL73Env(t, l, d)
		if !e.helpProbe() {
			e.writeL71()
			t.Fatalf("L73 not measured on %s (%s): its CLI offers no RFC 9887 client; the L71 addendum is written",
				l.p.name, l.p.version)
		}
		e.enrol()
		e.cellA()
		e.cellC()
		e.cellF()
		e.cellD()
		e.cellE()
		e.cellG()
		e.cellH()
		e.cellI()
		e.cellJ()
		e.cellB()
		e.note()
	})
}

func newL73Env(t *testing.T, l *lab, d l73Dialect) *l73Env {
	t.Helper()
	alg := os.Getenv("PORT49_L73_ALG")
	if alg == "" {
		alg = "ecdsa"
	}
	now := time.Now()
	pki, err := l73NewPKI(alg, now)
	if err != nil {
		t.Fatal(err)
	}
	e := &l73Env{t: t, l: l, d: d, opener: l73Opener(l.p.name), pki: pki, files: map[string]string{},
		evidence: map[string][]byte{},
		dir:      filepath.Join(root, "tests", "lab", "logs", "l73-"+l.p.name),
		evDir:    filepath.Join(root, "tests", "lab", "evidence", "L73-"+l.p.name),
		capDir:   filepath.Join(root, "tests", "lab", "captures", "L73-"+l.p.name)}
	for _, dir := range []string{e.dir, e.capDir} {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.capDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// L73 runs no port49 CLI; any it ever runs gets HOME=e.home, whose
	// config pins issued_key_store: file (the lab never probes the TPM).
	e.home = e.mkdir("home")
	if err := pinFileKeyStore(e.home); err != nil {
		t.Fatal(err)
	}
	e.files["root.pem"] = e.write("root.pem", pki.Root.PEM())
	e.files["inter.pem"] = e.write("inter.pem", pki.Inter.PEM())
	e.files["other.pem"] = e.write("other.pem", pki.Other.PEM())
	e.writeServer("server", pki.Root, l73ServerLeaf{DNSNames: []string{"tacacs.l73.example"},
		IPs: []net.IP{net.ParseIP(l73Server)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	inv, err := os.ReadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tlsInv, err := l73Inventory(string(inv), l.p.node)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	e.invTLS, e.invTCP = e.write("inventory-tls.yaml", []byte(tlsInv)), e.write("inventory-tcp.yaml", inv)
	e.start = l.mark()
	e.facts = append(e.facts, "PKI: "+alg+" (root, a device intermediate, an untrusted CA); port49d's server certificate "+
		l73CertFacts(mustCert(t, e.files["server.crt"])))
	t.Cleanup(func() {
		if !e.touched {
			return
		}
		// The restore restarts port49d after its CLI. Cell j's cleanup has taken
		// 172.100.100.2 off the bridge by now, so the last cell's config would not
		// bind: the standing one is what the lab leaves behind anyway.
		e.cfg, e.listen = "", ""
		out, err := e.restore()
		switch {
		case err == nil:
		case e.d.Family == "junos":
			t.Errorf("restoring the device's plain TACACS+ servers: %s", hideKeys(err.Error()+" "+l73ScrubLog(out)))
		default:
			// A lenient undo refuses the lines of servers that were never
			// there; the restore's own outcome is the startup config's lines.
			t.Logf("restore (lenient): %s", oneLine(hideKeys(err.Error())))
		}
	})
	return e
}

func (e *l73Env) mkdir(name string) string {
	p := filepath.Join(e.dir, name)
	if err := os.MkdirAll(p, 0o700); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *l73Env) write(name string, b []byte) string {
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func mustCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s holds no PEM", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// writeServer issues one port49 server certificate from `from` and writes
// <name>.crt and <name>.key (0600); the key is registered for the leak check.
func (e *l73Env) writeServer(name string, from l73Cert, leaf l73ServerLeaf) {
	c, err := e.pki.Server(from, leaf)
	if err != nil {
		e.t.Fatal(err)
	}
	k, err := c.KeyPEM()
	if err != nil {
		e.t.Fatal(err)
	}
	e.secrets = append(e.secrets, string(k))
	e.files[name+".crt"], e.files[name+".key"] = e.write(name+".crt", c.PEM()), e.write(name+".key", k)
}

// guard is the lab's per-cell check: the STOP sentinel and the disk floor.
func (e *l73Env) guard() {
	e.t.Helper()
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		e.t.Fatal(err)
	}
}

// settle waits past a refusal's strike: malformed_backoff_base is 2s here,
// and the 5s default malformed_backoff_max caps a strike's hold.
func (e *l73Env) settle() { time.Sleep(6 * time.Second) }

func (e *l73Env) base() l73DeviceTLS { return l73DeviceTLS{Server: l73Server, Port: e.port} }

// cli runs fn on the break-glass CLI. On a measured row port49d is stopped
// first, so the device takes the local password (withAdminCLI's reason), and
// started again on the config it ran before, the one daemon() recorded.
// withAdminCLI is not used: it restarts port49d on the standing plain config,
// and a cell that configures the device after daemon() would then measure a
// port49d with no RFC 9887 listener. A help-only row runs no port49d.
func (e *l73Env) cli(fn func(*cliConn) error) {
	e.t.Helper()
	measured := !e.d.HelpOnly
	if measured {
		if err := e.l.stopDaemon(); err != nil {
			e.t.Fatalf("INVALID: stopping port49d for the break-glass CLI: %v", err)
		}
	}
	c, err := e.opener(e.l)
	if err == nil {
		err = fn(c)
		c.Close()
	} else {
		err = fmt.Errorf("INVALID: no break-glass CLI on %s: %w", e.l.p.name, err)
	}
	if measured {
		e.startOn()
	}
	if err != nil {
		e.t.Fatal(err)
	}
}

// opMark is what the operational prompt holds: Junos's "> ", the node's
// "#" prompt elsewhere.
func (e *l73Env) opMark(c *cliConn) string {
	if e.d.Family == "junos" {
		return junosOpPrompt
	}
	return c.prompt
}

// invalidScreen keeps a scrubbed device screen for an INVALID run's
// diagnosis in PORT49_L73_INVALID_DIR (never committed).
func (e *l73Env) invalidScreen(name, out string) {
	if d := os.Getenv("PORT49_L73_INVALID_DIR"); d != "" {
		_ = os.WriteFile(filepath.Join(d, "l73-invalid-"+e.l.p.name+"-"+name+".txt"),
			[]byte(l71MaskExchange(l73ScrubLog(hideKeys(l73DropPEM(out))))), 0o600)
	}
}

// diagHelp is the diagnostic PORT49_L73_DIAG=help asks for: the help at each
// DiagAsks value position (typed with "?", then Ctrl-U; never entered), its
// masked text kept in PORT49_L73_INVALID_DIR, and then INVALID on purpose,
// before any TLS line is typed. Nothing is configured.
func (e *l73Env) diagHelp() {
	if os.Getenv("PORT49_L73_DIAG") != "help" || len(e.d.DiagAsks) == 0 {
		return
	}
	e.cli(func(c *cliConn) error {
		opMark := e.opMark(c)
		if e.d.Family == "junos" {
			opMark = "@" + e.l.p.node + opMark // the prompt as the CLI redisplays it; "> " alone also opens help lines
		}
		ask := func(name, line, mark string, deep int, subs []string) error {
			words := strings.Fields(line)
			last := []string(nil)
			if len(words) > 0 {
				last = words[len(words)-1:]
			}
			ans, err := l71AskHelp(c, line, last, mark)
			if err != nil {
				return err
			}
			e.invalidScreen(name, fmt.Sprintf("### typed `%s?`, cleared %v, finished %v\n%s", line, ans.Cleared, ans.WaitErr == nil, ans.Masked))
			if !ans.Cleared {
				return errors.New("INVALID: after Ctrl-U the line was not empty; nothing more is typed")
			}
			if deep > 0 {
				for i, w := range l73HelpWordsHolding(ans.Masked, subs) {
					if err := e.diagDeeper(c, name, line, w, i, deep, mark); err != nil {
						return err
					}
				}
			}
			return nil
		}
		for i, a := range e.d.DiagOpAsks {
			if err := ask(fmt.Sprintf("help-op-%d", i+1), a, opMark, 0, nil); err != nil {
				return err
			}
		}
		for _, ln := range e.d.Enter {
			if _, err := c.sendExpect(ln, 60*time.Second, e.d.CfgMark); err != nil {
				return l71Wrap("INVALID: "+ln, err)
			}
		}
		for i, a := range e.d.DiagFilterAsks {
			if err := ask(fmt.Sprintf("help-f%d", i+1), a, e.d.CfgMark, 1, e.d.DiagFilter); err != nil {
				return err
			}
		}
		for i, a := range e.d.DiagAsks {
			if err := ask(fmt.Sprintf("help-%d", i+1), a, e.d.CfgMark, e.d.DiagDeep, nil); err != nil {
				return err
			}
		}
		if len(e.d.DiagSubAsks) > 0 {
			for _, ln := range e.d.DiagSubIn {
				if _, err := c.sendExpect(ln, 60*time.Second, e.d.CfgMark); err != nil {
					return l71Wrap("INVALID: "+ln, err)
				}
			}
			for i, a := range e.d.DiagSubAsks {
				if err := ask(fmt.Sprintf("help-sub-%d", i+1), a, e.d.CfgMark, 0, nil); err != nil {
					return err
				}
			}
			for _, ln := range e.d.DiagSubOut {
				c.sendExpect(ln, 30*time.Second, e.d.CfgMark)
			}
		}
		for _, ln := range e.d.Cleanup {
			c.sendExpect(ln, 30*time.Second, e.d.CfgMark, e.opMark(c))
		}
		return nil
	})
	e.t.Fatalf("INVALID: PORT49_L73_DIAG=help: the help texts are in PORT49_L73_INVALID_DIR; no TLS line was typed")
}

// diagDeeper asks the help one keyword further, then (while deep allows) at
// the keywords that answer lists. Only a keyword the device itself listed
// is typed, and nothing is entered.
func (e *l73Env) diagDeeper(c *cliConn, name, line, word string, i, deep int, mark string) error {
	next := line + word + " "
	ans, err := l71AskHelp(c, next, []string{word}, mark)
	if err != nil {
		return err
	}
	nm := fmt.Sprintf("%s-%d", name, i+1)
	e.invalidScreen(nm, fmt.Sprintf("### typed `%s?`, cleared %v, finished %v\n%s", next, ans.Cleared, ans.WaitErr == nil, ans.Masked))
	if !ans.Cleared {
		return errors.New("INVALID: after Ctrl-U the line was not empty; nothing more is typed")
	}
	if deep > 1 {
		for j, w := range l73HelpWords(ans.Masked) {
			if err := e.diagDeeper(c, nm, next, w, j, deep-1, mark); err != nil {
				return err
			}
		}
	}
	return nil
}

// invalidDeviceLogs keeps the dialect's INVALID commands' output (the device's
// own account of a refused handshake) in PORT49_L73_INVALID_DIR, scrubbed.
func (e *l73Env) invalidDeviceLogs() {
	if os.Getenv("PORT49_L73_INVALID_DIR") == "" || len(e.d.InvalidCmds) == 0 {
		return
	}
	e.cli(func(c *cliConn) error {
		for i, cmd := range e.d.InvalidCmds {
			out, err := c.sendExpect(cmd, 60*time.Second, e.opMark(c))
			if err != nil {
				out = "(read failed: " + l73Err(err) + ")" // the error already carries the output's tail
			}
			e.invalidScreen(fmt.Sprintf("device-%d", i+1), "$ "+cmd+"\n"+out)
		}
		return nil
	})
}

// daemon restarts port49d on the cell's config and waits for its RFC 9887
// listener's start line.
func (e *l73Env) daemon(name string, o l73Daemon) {
	e.t.Helper()
	if o.Inventory == "" {
		o.Inventory = e.invTLS
	}
	if o.TLSListen == "" {
		o.TLSListen = net.JoinHostPort(l73Server, strconv.Itoa(l73TLSPort))
	}
	if o.Cert == "" {
		o.Cert, o.Key = e.files["server.crt"], e.files["server.key"]
	}
	if o.ClientCA == "" {
		o.ClientCA = e.files["root.pem"]
	}
	if o.StateDir == "" {
		o.StateDir = e.mkdir("state")
	}
	if o.Status == "" {
		o.Status = "{disabled: true}"
	}
	if o.Attrs == "" {
		o.Attrs = e.d.Attrs
	}
	base, err := os.ReadFile(labConfigPath())
	if err != nil {
		e.t.Fatal(err)
	}
	cfg, err := l73DaemonYAML(string(base), o)
	if err != nil {
		e.t.Fatalf("INVALID: %v", err)
	}
	e.cfg = e.write("port49d-"+name+".yaml", []byte(cfg))
	e.listen = o.Listen
	if err := e.l.stopDaemon(); err != nil {
		e.t.Fatalf("INVALID: stopping port49d for %s: %v", name, err)
	}
	e.startOn()
}

// startOn starts port49d on e.cfg, or on the standing config before the
// first cell, and on a cell's config waits for the RFC 9887 listener's start
// line. It is the only place TestL73 starts port49d. Nothing here goes
// through lab.restart: its awaitTACACS gate waits on IOS XE for a record that
// a cell whose handshake port49 refuses never makes. fileSize is the lab
// package's (directory_e2e_test.go).
func (e *l73Env) startOn() {
	e.t.Helper()
	path := e.cfg
	if path == "" {
		p, err := e.l.configPath()
		if err != nil {
			e.t.Fatalf("INVALID: the standing config: %v", err)
		}
		path = p
	}
	off := fileSize(e.l.errPath)
	healthListen = e.listen
	defer func() { healthListen = "" }()
	if err := e.l.startDaemonWith(path, true); err != nil {
		e.t.Fatalf("INVALID: starting port49d on %s: %v\nbridge addresses now: %s", filepath.Base(path), err,
			strings.Join(strings.Fields(e.bridgeAddrs()), " "))
	}
	if e.cfg == "" {
		return
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, _ := os.ReadFile(e.l.errPath)
		if int64(len(b)) > off && strings.Contains(string(b[off:]), "RFC 9887 listener on") {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("INVALID: port49d on %s never announced its RFC 9887 listener", filepath.Base(path))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ready waits, for up to 3 minutes, until the device opens a connection to
// port49's address again. Each probe is a break-glass login (port49 holds no
// token for it) under a capture of its own. Configuring the device means a
// break-glass CLI with port49d stopped, and after port49 had been
// unreachable IOS XE 17.13 answered logins locally without sending it a
// packet (awaitTACACS's comment; L10). A cell measured then would record
// that memory, not the cell. The test is a connection, not a record: cell
// a's first login may go to a port nothing answers TLS on.
// It returns the connections of the probe that reached port49.
func (e *l73Env) ready(cell string) []l73Conn {
	e.t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for n := 1; ; n++ {
		stop := e.capture(fmt.Sprintf("%s-ready%d", cell, n))
		_, _, _ = e.breakglassLogin()
		if conns := stop(); len(l73Window(conns, l73Server, time.Time{}, time.Now())) > 0 {
			return conns
		}
		if time.Now().After(deadline) {
			e.invalidDeviceLogs()
			e.t.Fatalf("INVALID: %s: the device opened no connection to %s in 3 minutes of break-glass logins. "+
				"The likely cause is the device's dead-server memory outlasting 3 minutes after a refusal or a "+
				"stopped port49d (IOS XE: look at its deadtime and server state), not the TLS configuration", cell, l73Server)
		}
		time.Sleep(10 * time.Second)
	}
}

// revive is where every cell whose handshake port49 may refuse starts:
// port49d on cell a's config, the device seen connecting (ready), and only
// then the cell's own daemon. Switching daemons opens no CLI, so the device
// meets the refusal with no memory of an earlier failure.
func (e *l73Env) revive(cell string) {
	e.t.Helper()
	e.daemon(cell+"-revive", l73Daemon{Intermediates: e.files["inter.pem"]})
	e.ready(cell + "-revive")
}

// reached is INVALID unless the device opened a connection to port49 during
// a refusal cell: a refusal it never reached measures nothing.
func (e *l73Env) reached(cell string, conns []l73Conn) {
	e.t.Helper()
	if _, ok := l73FirstPort(conns, l73Server); !ok {
		e.t.Fatalf("INVALID: %s: the device opened no connection to %s, so the cell measured nothing", cell, l73Server)
	}
}

// junosCommit commits lines over the break-glass CLI with port49d stopped,
// and rolls back what a refused commit left half-entered.
func (e *l73Env) junosCommit(lines []string) (string, error) {
	var out string
	var cerr error
	e.cli(func(c *cliConn) error {
		out, cerr = junosConfigure(c, lines...)
		if cerr != nil {
			c.sendExpect("rollback 0", 60*time.Second, junosCfgPrompt)
			c.sendExpect("exit configuration-mode", 60*time.Second, junosOpPrompt)
			return nil
		}
		cerr = junosVerifyApplied(c, lines)
		return nil
	})
	return out, cerr
}

// junosVerifyApplied reads the committed configuration back and is an error
// naming every `set` line typed that is not in it. A line the CLI took
// without a word and the commit then dropped would otherwise leave every
// cell measuring a device with no TLS. The secret line is compared by
// presence and never printed.
func junosVerifyApplied(c *cliConn, lines []string) error {
	var shown strings.Builder
	seen := map[string]bool{}
	for _, ln := range lines {
		h := l73Hierarchy(ln)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out, err := junosShow(c, "show configuration "+h+" | display set")
		if err != nil {
			return fmt.Errorf("reading back %q: %s", h, l73Err(err))
		}
		shown.WriteString(out)
		shown.WriteString("\n")
	}
	if missing := l73MissingLines(lines, shown.String()); len(missing) > 0 {
		return fmt.Errorf("the committed configuration lacks %d line(s) that were typed: %s", len(missing), strings.Join(missing, "; "))
	}
	return nil
}

// ciscoType types lines in configuration mode with port49d stopped. What
// l73CiscoRun returns is already masked (hideKeys), so out is safe to pass on.
func (e *l73Env) ciscoType(lines []string, lenient bool) (string, error) {
	var out string
	var cerr error
	e.cli(func(c *cliConn) error {
		out, cerr = l73CiscoRun(c, l73Lines(lines...), nil, lenient)
		return nil
	})
	return out, cerr
}

// apply points the device's client at port49 as d says: a Junos commit, or
// on IOS XE, NX-OS and EOS the previous cell's undo and then d's lines. On
// EOS the group members come second, naming the ports `show tacacs` lists.
func (e *l73Env) apply(d l73DeviceTLS) (string, error) {
	if e.d.Family == "junos" {
		return e.junosCommit(l73JunosLines(d))
	}
	lines := l73CiscoLines(e.d.Family, e.applied, d, e.x)
	e.applied = &d // set first: the cleanup must undo whatever got in
	out, err := e.ciscoType(lines, false)
	if err != nil || e.d.Family != "eos" {
		return out, err
	}
	return e.eosMembers(&d, out)
}

// eosMembers reads the hosts' ports, types the group members with them, and
// reads the configuration back as Junos's junosVerifyApplied does: EOS has
// no commit, and a line it took without a word may still not be there. The
// lines it names carry no key.
func (e *l73Env) eosMembers(d *l73DeviceTLS, out string) (string, error) {
	show := func(cmd string) (shown string, err error) {
		e.cli(func(c *cliConn) error {
			shown, err = c.sendExpect(cmd, 30*time.Second, c.prompt)
			return nil
		})
		if err != nil {
			err = fmt.Errorf("reading %q: %s", cmd, l73Err(err))
		}
		return shown, err
	}
	hosts, err := show("show tacacs")
	if err != nil {
		return out, err
	}
	port, second, err := l73EOSMemberPorts(hosts, *d)
	if err != nil {
		e.invalidScreen("members", hosts)
		return out, err
	}
	d.MemberPort, d.SecondMemberPort = port, second
	if out, err = e.ciscoType(l73EOSMembers(*d, port, second), false); err != nil {
		return out, err
	}
	cfg, err := show("show running-config section tacacs")
	if err != nil {
		return out, err
	}
	grp, err := show("show tacacs")
	if err != nil {
		return out, err
	}
	missing := l73EOSMissing(cfg, *d)
	missing = append(missing, l73EOSGroupMissing(grp, *d, port, second)...)
	if len(missing) > 0 {
		e.invalidScreen("readback", cfg+"\n"+grp)
		return out, fmt.Errorf("the device lacks %d line(s) that were typed: %s", len(missing), strings.Join(missing, "; "))
	}
	return out, nil
}

// restore puts the startup config's servers back: Junos's restore commit,
// or every server L73 can configure undone leniently.
func (e *l73Env) restore() (string, error) {
	if e.d.Family == "junos" {
		return e.junosCommit(l73JunosRestore())
	}
	var undo []string
	if e.applied != nil && e.d.Family == "eos" {
		// The members were typed with ports the undo must name.
		undo = l73CiscoUndo("eos", l73DeviceTLS{Server: l73Server, Second: l73SecondServer,
			MemberPort: e.applied.MemberPort, SecondMemberPort: e.applied.SecondMemberPort}, e.x)
	} else {
		undo = l73CiscoRestoreAll(e.d.Family, e.x)
	}
	e.applied = nil
	return e.ciscoType(undo, true)
}

// configure is apply, INVALID on a refusal. If a Junos commit refuses a tls
// server with no secret, that is recorded and every later configuration
// carries the lab secret too.
func (e *l73Env) configure(d l73DeviceTLS) {
	e.t.Helper()
	e.touched = true
	d.Secret = d.Secret || e.needSec
	out, err := e.apply(d)
	if err != nil && e.d.Family == "junos" && !d.Secret && strings.Contains(out, "secret") {
		e.needSec, d.Secret = true, true
		e.facts = append(e.facts, "the image's commit refused a tls server with no secret; every server below "+
			"carries the lab secret as well")
		out, err = e.apply(d)
	}
	if err != nil {
		e.invalidScreen("configure", out)
		e.refusalDiag(out)
		e.t.Fatalf("INVALID: configuring the device's TLS client: %s", oneLine(l73ScrubLog(hideKeys(err.Error()))))
	}
}

// refusalDiag keeps what the device says about a refused TLS configuration:
// the directory a refused file path lies in, when it may be printed, and the
// dialect's RefusalCmds, all scrubbed in the INVALID dir. Reading goes first
// to a CLI that can fail; the refusal is already recorded.
func (e *l73Env) refusalDiag(out string) {
	cmds := slices.Clone(e.d.RefusalCmds)
	if dir := l73RefusedDir(out); dir != "" && e.d.Family == "junos" {
		cmds = append([]string{"file list " + dir}, cmds...)
	}
	if os.Getenv("PORT49_L73_INVALID_DIR") == "" || len(cmds) == 0 {
		return
	}
	e.cli(func(c *cliConn) error {
		for i, cmd := range cmds {
			o, err := c.sendExpect(cmd, 60*time.Second, e.opMark(c))
			if err != nil {
				o = "(read failed: " + l73Err(err) + ")"
			}
			e.invalidScreen(fmt.Sprintf("refusal-%d", i+1), "$ "+cmd+"\n"+o)
		}
		return nil
	})
}

// capture starts a capture of everything the device sends or receives
// except SSH and NETCONF, plus the loopback liveness probe. stop ends it,
// summarizes it, and keeps the summary for note().
func (e *l73Env) capture(cell string) (stop func() []l73Conn) {
	e.t.Helper()
	abs := filepath.Join(e.capDir, cell+".pcap")
	filter := fmt.Sprintf("(host %s and tcp and not port 22 and not port 830) or (host 127.0.0.1 and tcp port 49)", e.l.p.addr)
	end := e.l.captureWith(e.t, abs, filter)
	e.t.Cleanup(end) // idempotent: a Fatal mid-cell still stops tcpdump
	return func() []l73Conn {
		e.l.capAbs = abs // flush this capture, not the last one started (ready's, in cell h)
		end()
		raw, err := os.ReadFile(abs)
		if err != nil {
			e.t.Fatalf("INVALID: %v", err)
		}
		conns, err := l73Conns(raw, e.l.p.addr)
		if err != nil {
			e.t.Fatalf("INVALID: reading %s: %v", abs, err)
		}
		js, _ := json.MarshalIndent(conns, "", "  ")
		if hits := l73SummaryLeaks(string(js)); len(hits) > 0 {
			e.t.Fatalf("INVALID: the %s summary holds %v; nothing written", cell, hits)
		}
		e.evidence[cell+".tls.json"] = js
		return conns
	}
}

// tokenLogin logs in with the next l73u seed and runs the dialect's
// version command.
func (e *l73Env) tokenLogin() (user string, ok bool, took time.Duration, out string, err error) {
	e.tokenN++
	user = fmt.Sprintf("l73u%02d", e.tokenN)
	secret := e.l.mustLogin(e.t, user)
	start := time.Now()
	outs, err := e.l.login(user, secret, e.d.VersionCmd)
	if len(outs) > 0 {
		out = strings.TrimSpace(outs[0])
	}
	return user, err == nil && len(outs) == 1, time.Since(start), out, err
}

// breakglassLogin is a login port49 holds no token for: it lands only if
// the device reaches its local method.
func (e *l73Env) breakglassLogin() (ok bool, took time.Duration, err error) {
	start := time.Now()
	c, err := e.l.dial(breakglassUser, breakglassPassword, 120*time.Second)
	if err == nil {
		c.Close()
	}
	return err == nil, time.Since(start), err
}

func l73Err(err error) string {
	if err == nil {
		return "no error"
	}
	return oneLine(l73ScrubLog(hideKeys(err.Error())))
}

func (e *l73Env) quote(recs []map[string]any) string {
	recs, seeds := l73DropSeedMints(recs)
	var parts []string
	for _, r := range recs {
		b, _ := json.Marshal(r)
		parts = append(parts, string(l72RedactCredentialHash(b)))
	}
	if seeds > 0 {
		parts = append(parts, fmt.Sprintf("(%d lab seed mints omitted)", seeds))
	}
	if len(parts) == 0 {
		return "(no record)"
	}
	return strings.Join(parts, " ")
}

// l73Where is the records whose unvalidated block has key == val.
func l73Where(recs []map[string]any, key, val string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(sub(r, "unvalidated"), key) == val {
			out = append(out, r)
		}
	}
	return out
}

// Details port49d logs (internal/daemon/server/tls.go:64 and
// internal/devicecert/verify.go:99, chainOutcome's x509 text): a handshake the
// device aborted by alert, and a chain with no path to the anchors.
const (
	l73DeviceAborted    = "the device aborted the handshake"
	l73UnknownAuthority = "x509: certificate signed by unknown authority"
)

// l73RefusedFor is whether port49 recorded a tls_refused for exactly this
// reason: the outcome, and a detail starting with prefix. A refusal for
// another reason does not prove the cell's.
func l73RefusedFor(recs []map[string]any, outcome, prefix string) bool {
	for _, r := range l73Where(recs, "tls_outcome", outcome) {
		if strings.HasPrefix(str(sub(r, "unvalidated"), "detail"), prefix) {
			return true
		}
	}
	return false
}

func l73Redeemed(recs []map[string]any) bool {
	for _, r := range recs {
		if str(r, "event") == "redeem" && str(r, "verdict") == "permit" && str(sub(r, "device"), "transport") == "tls" {
			return true
		}
	}
	return false
}

// metric is one series' value and whether the daemon exports it. port49d
// creates every port49_tls_handshakes_total outcome series at start
// (internal/daemon/metrics/metrics.go), so a missing one is a misspelled
// selector, not a zero.
func (e *l73Env) metric(selector string) (float64, bool) {
	resp, err := http.Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		e.t.Fatalf("INVALID: metrics: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return l73MetricValue(string(b), selector)
}

func (e *l73Env) add(id, configured, observed, docs string) {
	e.obs = append(e.obs, l73Obs{ID: id, Configured: configured, Observed: observed, Docs: docs})
}

// upload copies public certificates to a Junos or EOS device over
// break-glass scp, with port49d stopped so the device takes the local password.
func (e *l73Env) upload(files map[string][]byte) {
	e.t.Helper()
	if err := e.l.stopDaemon(); err != nil {
		e.t.Fatal(err)
	}
	c, err := e.l.dial(breakglassUser, breakglassPassword, 60*time.Second)
	if err != nil {
		e.t.Fatalf("INVALID: break-glass SSH for the upload: %v", err)
	}
	for path, body := range files {
		if err := scpWrite(c, path, body); err != nil {
			c.Close()
			e.startOn()
			e.t.Fatalf("INVALID: scp to %s: %v", path, err)
		}
	}
	c.Close()
	e.startOn()
}

// helpProbe asks L71's question of this image, then each CLI level the
// harness will type, and reports whether the image has a client (tls listed
// at L71's question). It keeps the L71 observation for writeL71. On a
// measured row a missing keyword is INVALID, with the masked exchange in
// PORT49_L73_INVALID_DIR; on a help-only row it is part of the observation.
func (e *l73Env) helpProbe() bool {
	e.guard()
	var xchg strings.Builder
	var missing []string
	var first l71Answer
	hasClient := false
	listed := map[string]bool{}
	var evidence, evidenceKept []string
	probe := l71Probes[e.d.Probe]
	e.cli(func(c *cliConn) (err error) {
		entered, dirty, unsure := 0, false, false // unsure: an ask's In was typed and its Out has not finished
		defer func() {
			if dirty {
				return
			}
			if unsure {
				// The CLI's mode is unknown: leave configuration and enter as
				// the probe did (l73RecoverLines), so the cleanup below runs
				// from the mode it assumes and cannot leave l71probe behind.
				// A device that will not confirm the top level is INVALID.
				for i, ln := range l73RecoverLines(e.d) {
					mark := e.d.CfgMark
					if i == 0 {
						mark = e.opMark(c)
					}
					if _, rerr := c.sendExpect(ln, 30*time.Second, mark); rerr != nil {
						dirty = true
						recovery := l71Wrap("INVALID: could not return to the configuration top level before the cleanup; "+
							"check the device for a `tacacs server l71probe` object", rerr)
						if err != nil {
							// The first failure is the finding; the recovery's is what it left behind.
							err = fmt.Errorf("%s; recovery: %s", l73Err(err), l73Err(recovery))
						} else {
							err = recovery
						}
						return
					}
				}
				entered = len(e.d.Enter)
			}
			for _, ln := range l71CleanupFor(probe, entered) {
				c.sendExpect(ln, 30*time.Second, e.d.CfgMark, e.opMark(c))
			}
		}()
		for _, ln := range e.d.Enter {
			if _, err := c.sendExpect(ln, 60*time.Second, e.d.CfgMark); err != nil {
				return l71Wrap("INVALID: "+ln, err)
			}
			entered++
		}
		// leave is the Out lines of the ask in flight: typed once the ask has
		// been answered and on every error path, so the CLI is back in the
		// dialect's Enter mode for the cleanup that follows. They are not
		// counted in entered: the cleanup's lines assume the Enter mode.
		leave := func(a l73Ask) error {
			for _, ln := range a.Out {
				if _, err := c.sendExpect(ln, 30*time.Second, e.d.CfgMark); err != nil {
					return l71Wrap("INVALID: "+ln, err)
				}
			}
			return nil
		}
		evidenceOnly := false // the L71 ask found no client: only the evidence asks still run
		for i, a := range e.d.Asks {
			if a.Only != "" && !listed[a.Only] || evidenceOnly && !a.Evidence {
				continue
			}
			unsure = len(a.In) > 0
			for _, ln := range a.In {
				if _, err := c.sendExpect(ln, 30*time.Second, e.d.CfgMark); err != nil {
					return l71Wrap("INVALID: "+ln, err)
				}
			}
			ans, err := l71AskHelp(c, a.Ask, a.Control, e.d.CfgMark)
			if err != nil {
				return err
			}
			fmt.Fprintf(&xchg, "### typed `%s?`, then Ctrl-U\n%s\n\n", a.Ask, ans.Masked)
			e.invalidScreen(fmt.Sprintf("probe-%d", i+1), fmt.Sprintf("### typed `%s?`, then Ctrl-U\n%s", a.Ask, ans.Masked))
			if !ans.Cleared {
				dirty = true // Out is not typed: nothing more is typed on a line that did not clear
				return fmt.Errorf("INVALID: after Ctrl-U the line was not empty on `%s?`; the session was closed with nothing more typed", a.Ask)
			}
			if a.Evidence {
				// Recorded as it came; no verdict, and a help that showed none of its
				// control words is kept too (the screen is in the exchange file).
				kept := l73HelpBody(ans.Help)
				if len(a.Keep) > 0 {
					kept = l73KeepLines(ans.Help, a.Keep)
					evidenceKept = kept
				}
				evidence = append(evidence, fmt.Sprintf("%d. typed `%s?`, kept %s:\n\n```\n%s\n```\n", i+1, a.Ask,
					map[bool]string{true: "the lines beginning " + strings.Join(a.Keep, " or "), false: "the whole help"}[len(a.Keep) > 0],
					strings.Join(kept, "\n")))
				if err := leave(a); err != nil {
					return err
				}
				unsure = false
				continue
			}
			if ans.WaitErr != nil {
				leave(a)
				return l71Wrap(fmt.Sprintf("INVALID: no help for `%s?`", a.Ask), ans.WaitErr)
			}
			miss, have, err := l73HelpVerdict(ans.Help, a)
			if err != nil {
				leave(a)
				return err
			}
			l73RecordListed(listed, a, miss, have)
			if err := leave(a); err != nil {
				return err
			}
			unsure = false
			if i == 0 {
				// L71's own verdict: a client word (tls; ssl-profile on EOS).
				first = ans
				if _, hasClient = l71Says(ans.Help, probe.yes); !hasClient {
					evidenceOnly = true
					if !slices.ContainsFunc(e.d.Asks, func(x l73Ask) bool { return x.Evidence }) {
						return nil
					}
				}
			}
			for _, m := range miss {
				missing = append(missing, fmt.Sprintf("`%s` under `%s`", m, strings.TrimSpace(a.Ask)))
			}
		}
		return nil
	})
	e.x = listed
	e.evidence["l71-probe.txt"] = []byte(xchg.String())
	line, err := l71Read(first.Help, probe)
	if err != nil {
		e.t.Fatalf("%v", err)
	}
	ask := e.d.Asks[0].Ask
	if line != "" {
		e.l71Obs = fmt.Sprintf("**Has a client.** Typed `%s?`; the help lists:\n\n```\n%s\n```\n\nFull help:\n\n```\n%s\n```\n",
			ask, line, strings.TrimRight(first.Help, "\n"))
	} else if l73CROnly(first.Help) {
		e.l71Obs = negativeFinding{Claim: l73CRFinding(e.l.p.version, strings.ReplaceAll(strings.TrimSpace(ask), "192.0.2.71", "<addr>"),
			evidenceKept), Sent: ask + "?", Got: first.Help}.render(e.t)
	} else {
		e.l71Obs = negativeFinding{Claim: fmt.Sprintf("the help for `%s?` is a real option list (it lists one of the "+
			"control options %v) and lists none of %v, so this image offers no RFC 9887 client there", ask, probe.control, probe.yes),
			Sent: ask + "?", Got: first.Help}.render(e.t)
	}
	if len(evidence) > 0 {
		e.l71Obs += "\nThe asks, in the order the dialect lists them (the L71 ask first; the evidence-only asks next, " +
			"recorded and graded on nothing; the `tls` level only if the first ask listed `tls`). The first ask is above.\n\n" +
			strings.Join(evidence, "\n")
	}
	if hasClient && len(missing) > 0 {
		if e.d.HelpOnly {
			e.l71Obs += fmt.Sprintf("\nKeywords a full L73 run would type that this image's help does not list: %s.\n",
				strings.Join(missing, ", "))
			return hasClient
		}
		if d := os.Getenv("PORT49_L73_INVALID_DIR"); d != "" {
			_ = os.WriteFile(filepath.Join(d, "l73-invalid-"+e.l.p.name+".txt"), []byte(xchg.String()), 0o600)
		}
		e.t.Fatalf("INVALID: the image's help lacks %s, which this harness types; correct the dialect "+
			"(l73_dialect.go, and l73_device.go for Junos) from the exchange, then re-run", strings.Join(missing, ", "))
	}
	return hasClient
}

// writeL71 appends the addendum to this platform's L71 note, or writes the
// note when there is none (vJunos-switch, IOL-XE and XRd were never
// probed). Its evidence is the masked help exchange.
func (e *l73Env) writeL71() {
	ev := filepath.Join("tests", "lab", "evidence", "L73-"+e.l.p.name, "l71-probe.txt")
	body := e.evidence["l71-probe.txt"]
	if hits := l72TranscriptLeaks(string(body)); len(hits) > 0 || len(labcreds.Contains(body, e.allSecrets())) > 0 {
		e.t.Fatal("INVALID: the probe exchange carries a secret; nothing written")
	}
	if err := os.MkdirAll(e.evDir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ev), body, 0o644); err != nil {
		e.t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "tests", "lab", "results", "L71-"+e.l.p.name+".md")); err == nil {
		e.l.appendNote(e.t, "L71", fmt.Sprintf("## Addendum %s: %s (`%s`)\n\nProbed by TestL73 (%s); the exchange is `%s`.\n\n%s",
			time.Now().UTC().Format("2006-01-02"), e.l.p.version, e.l.p.image, runLine(), ev, e.l71Obs))
		return
	}
	e.l.captureNote = fmt.Sprintf("`%s` — the CLI exchange from the help request to the empty-line check, credentials "+
		"masked and control bytes shown as `cat -v` shows them. L71 sends no TACACS+ traffic, so there is no pcap.", ev)
	e.l.result(e.t, "L71", l71Claim, e.l71Obs)
	e.l.captureNote = ""
}

// allSecrets is every secret the run made or used: port49's key PEMs, every
// seed token any daemon minted, the published lab key and password.
func (e *l73Env) allSecrets() []string {
	runSeedsMu.Lock()
	seeds := append([]labcreds.SeedToken(nil), runSeeds...)
	runSeedsMu.Unlock()
	toks, err := labcreds.SecretsOf(seeds)
	if err != nil {
		e.t.Fatalf("INVALID: the run's tokens: %v", err)
	}
	return append(append(append([]string{}, e.secrets...), toks...), labcreds.Key, breakglassPassword)
}

func (e *l73Env) enrol() {
	e.guard()
	e.touched = true
	var csrPEM []byte
	var how string
	switch e.d.Family {
	case "junos":
		csrPEM, how = e.requestJunos()
	case "eos":
		csrPEM, how = e.requestEOS()
	default:
		csrPEM, how = e.requestCisco()
	}
	e.sign(csrPEM, how)
	switch e.d.Family {
	case "junos":
		e.loadJunos()
	case "eos":
		e.loadEOS()
	default:
		e.loadCisco()
	}
}

// requestEOS makes the key and prints the request, both exec commands.
func (e *l73Env) requestEOS() ([]byte, string) {
	keyGen, csrCmd, _, _ := l73EOSEnrol(e.l.p.node)
	var screen string
	e.cli(func(c *cliConn) error {
		for _, cmd := range []string{keyGen, csrCmd} {
			out, err := c.sendExpect(cmd, 180*time.Second, c.prompt)
			if r := l73Refusal(out); err != nil || r != "" {
				e.invalidScreen("enrol", out)
				return fmt.Errorf("INVALID: %q: %s %s", cmd, l73Err(err), hideKeys(r))
			}
			screen = out
		}
		return nil
	})
	csrPEM, err := l73PEMBlock(screen, "CERTIFICATE REQUEST")
	if err != nil {
		e.invalidScreen("enrol", screen)
		e.t.Fatalf("INVALID: the device's certificate request: %v", err)
	}
	return csrPEM, csrCmd
}

// loadEOS copies the public certificates to flash: by scp, moves them into
// certificate:, and configures the SSL profile that names them.
func (e *l73Env) loadEOS() {
	_, _, load, profile := l73EOSEnrol(e.l.p.node)
	e.upload(map[string][]byte{"/mnt/flash/l73-root.crt": e.pki.Root.PEM(), "/mnt/flash/l73-inter.crt": e.pki.Inter.PEM(),
		"/mnt/flash/" + l73CertID + ".crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.leaf.Raw})})
	e.cli(func(c *cliConn) error {
		for _, cmd := range load {
			out, err := c.sendExpect(cmd, 60*time.Second, c.prompt)
			if r := l73Refusal(out); err != nil || r != "" {
				e.invalidScreen("load", out)
				return fmt.Errorf("INVALID: %q: %s %s", cmd, l73Err(err), hideKeys(r))
			}
		}
		if out, err := l73CiscoRun(c, l73Lines(profile...), nil, false); err != nil {
			e.invalidScreen("profile", out)
			return fmt.Errorf("INVALID: the SSL profile: %s", oneLine(err.Error()))
		}
		return nil
	})
}

func (e *l73Env) requestJunos() ([]byte, string) {
	keyPair, csrCmd := l73EnrolCommands(e.l.p.node, e.l.p.addr)
	var screen string
	e.cli(func(c *cliConn) error {
		if out, err := junosConfigure(c, l73PKILines()...); err != nil {
			return errors.New(hideKeys(err.Error() + " " + l73ScrubLog(out)))
		}
		for _, cmd := range []string{keyPair, csrCmd} {
			out, err := c.sendExpect(cmd, 180*time.Second, junosOpPrompt)
			if err != nil || strings.Contains(out, "error:") {
				return fmt.Errorf("INVALID: %q: %s\n%s", cmd, l73Err(err), l73ScrubLog(hideKeys(out)))
			}
		}
		out, err := c.sendExpect("file show "+l73CSRPath, 60*time.Second, junosOpPrompt)
		screen = out
		if err != nil {
			return errors.New(l73Err(err))
		}
		return nil
	})
	csrPEM, err := l73PEMBlock(screen, "CERTIFICATE REQUEST")
	if err != nil {
		e.t.Fatalf("INVALID: the device's certificate request: %v", err)
	}
	return csrPEM, strings.TrimSpace(csrCmd)
}

// vals are the enrolment replies' placeholders: public certificates and
// the device's own names.
func (e *l73Env) vals() map[string]string {
	v := map[string]string{"ROOT": string(e.pki.Root.PEM()), "INTER": string(e.pki.Inter.PEM()),
		"NODE": e.l.p.node, "ADDR": e.l.p.addr}
	if e.leaf != nil {
		v["LEAF"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.leaf.Raw}))
	}
	return v
}

func (e *l73Env) requestCisco() ([]byte, string) {
	prep, enroll, _ := l73CiscoEnrol(e.d.Family, e.l.p.node)
	vals := e.vals()
	var screen string
	e.cli(func(c *cliConn) error {
		if out, err := l73CiscoRun(c, prep, vals, false); err != nil {
			e.invalidScreen("enrol-prep", out)
			return fmt.Errorf("INVALID: preparing the device's key and trustpoints: %s", oneLine(err.Error()))
		}
		out, err := l73CiscoRun(c, []l73Dialog{enroll}, vals, false)
		screen = out
		if err != nil {
			e.invalidScreen("enrol", out)
			return fmt.Errorf("INVALID: %q: %s", enroll.Cmd, oneLine(err.Error()))
		}
		return nil
	})
	csrPEM, err := l73PEMBlock(screen, "CERTIFICATE REQUEST")
	if err != nil {
		e.invalidScreen("enrol", screen)
		e.t.Fatalf("INVALID: the device's certificate request: %v", err)
	}
	return csrPEM, enroll.Cmd
}

func (e *l73Env) sign(csrPEM []byte, how string) {
	var err error
	if e.csr, err = l73CSRFacts(csrPEM); err != nil {
		e.t.Fatalf("INVALID: %v", err)
	}
	now := time.Now()
	leaf, added, err := l73SignCSR(csrPEM, e.pki.Inter, now.Add(-time.Hour), now.Add(24*time.Hour), e.l.p.node, net.ParseIP(e.l.p.addr))
	if err != nil {
		e.t.Fatalf("INVALID: signing the device's request: %v", err)
	}
	e.leaf = leaf
	e.facts = append(e.facts, fmt.Sprintf("the device's request (`%s`): subject %q, dNSName %v, iPAddress %v, email %v, key %s, "+
		"requested extensions %v, requested EKU %v", how, e.csr.Subject, e.csr.DNSNames, e.csr.IPs,
		e.csr.Emails, e.csr.KeyAlg, e.csr.Requested, e.csr.EKU))
	issued := "the lab intermediate issued " + l73CertFacts(leaf)
	if added {
		issued += " (the request named neither a dNSName nor an iPAddress, so the lab CA added the inventory's)"
	}
	e.facts = append(e.facts, issued)
}

func (e *l73Env) loadJunos() {
	trust := []struct {
		path string
		pem  []byte
	}{{l73RootOnDevice, e.pki.Root.PEM()}, {l73InterOnDevice, e.pki.Inter.PEM()}}
	e.upload(map[string][]byte{trust[0].path: trust[0].pem, trust[1].path: trust[1].pem,
		"/var/tmp/l73-dev.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.leaf.Raw})})
	e.cli(func(c *cliConn) error {
		for _, cmd := range l73LoadCommands() {
			out, err := c.sendExpect(cmd, 120*time.Second, "[yes,no]", junosOpPrompt)
			if err == nil && strings.Contains(out, "[yes,no]") {
				// The one question these commands ask; any other is not ours to answer.
				if !strings.Contains(strings.ToLower(out), "load this ca certificate") {
					_, _ = c.sendExpect("no", 60*time.Second, junosOpPrompt)
					return fmt.Errorf("INVALID: %q asked a question this run does not answer:\n%s", cmd, l73ScrubLog(hideKeys(out)))
				}
				out, err = c.sendExpect("yes", 120*time.Second, junosOpPrompt)
			}
			if err != nil || strings.Contains(out, "error:") {
				return fmt.Errorf("INVALID: %q: %s\n%s", cmd, l73Err(err), l73ScrubLog(hideKeys(out)))
			}
		}
		// The image reads a trusted-ca-group from a folder of CA certificates named
		// by their subject hash (l73TrustDir); make it and copy the two public
		// certificates, already on the device, into it.
		//
		// PROVISIONAL: this step rests on the RADSEC page by analogy (the TACACS+
		// page is silent), and attempt 14 measured it refused for the break-glass
		// user ("Permission denied": the directory needs root or `start shell`).
		// It fails closed, so every Junos enrol is INVALID here until Ryan rules
		// on the vJunos root shell (progress.md, "Task 11 attempt 14", HOLD). Do
		// not re-run it blind, and do not change it to get past the refusal.
		e.aaaListing(c, "aaa-before-group")
		var hashed [][2]string
		for _, tc := range trust {
			h, err := l73SubjectHash(tc.pem)
			if err != nil {
				return fmt.Errorf("INVALID: %v", err)
			}
			hashed = append(hashed, [2]string{tc.path, h})
		}
		folder, err := l73TrustFolderCmds(l73TrustGroup, hashed)
		if err != nil {
			return fmt.Errorf("INVALID: %v", err)
		}
		for _, cmd := range folder {
			out, err := junosShow(c, cmd)
			low := strings.ToLower(out)
			if err != nil || strings.Contains(low, "error") || strings.Contains(low, "denied") || strings.Contains(low, "cannot") || strings.Contains(low, "no such") {
				e.invalidScreen("trust-folder", "$ "+cmd+"\n"+out)
				return fmt.Errorf("INVALID: %q: %s\n%s", cmd, l73Err(err), l73ScrubLog(hideKeys(out)))
			}
		}
		e.aaaListing(c, "aaa-after-folder")
		// The trust group goes in only now that the CA certificates are loaded.
		if out, err := junosConfigure(c, l73TrustGroupLines()...); err != nil {
			return errors.New(hideKeys(err.Error() + " " + l73ScrubLog(out)))
		}
		if err := junosVerifyApplied(c, l73TrustGroupLines()); err != nil {
			return err
		}
		e.aaaListing(c, "aaa-after-group")
		return nil
	})
}

// aaaListing keeps the image's AAA certificate directory tree, scrubbed, in
// the INVALID dir under name (a diagnostic; nothing depends on it).
func (e *l73Env) aaaListing(c *cliConn, name string) {
	if os.Getenv("PORT49_L73_INVALID_DIR") == "" {
		return
	}
	out, err := c.sendExpect("file list /var/db/aaa_certs/ recursive", 60*time.Second, junosOpPrompt)
	if err != nil {
		out = "(read failed: " + l73Err(err) + ")"
	}
	e.invalidScreen(name, out)
}

func (e *l73Env) loadCisco() {
	_, _, load := l73CiscoEnrol(e.d.Family, e.l.p.node)
	vals := e.vals()
	e.cli(func(c *cliConn) error {
		if out, err := l73CiscoRun(c, []l73Dialog{load}, vals, false); err != nil {
			e.invalidScreen("import", out)
			return fmt.Errorf("INVALID: %q: %s", load.Cmd, oneLine(err.Error()))
		}
		return nil
	})
	if e.d.Family == "nxos" {
		e.confirmNXOSTrust()
	}
}

// confirmNXOSTrust is INVALID unless the device's trustpoints hold THIS run's
// CAs. NX-OS's CA import has no Done marker, and a trustpoint keeps its name
// between runs, so an earlier run's CA would pass every other check and then
// fail every cell for a reason that has nothing to do with TLS.
func (e *l73Env) confirmNXOSTrust() {
	e.t.Helper()
	tps := []struct {
		name string
		ca   l73Cert
	}{{l73RootProfile, e.pki.Root}, {l73CertID, e.pki.Inter}}
	screens := make([]string, len(tps))
	errs := make([]error, len(tps))
	e.cli(func(c *cliConn) error {
		for i, tp := range tps {
			screens[i], errs[i] = c.sendExpect("show crypto ca certificates "+tp.name, 60*time.Second, c.prompt)
		}
		return nil
	})
	for i, tp := range tps {
		if errs[i] != nil || !l73ScreenHasCert(screens[i], tp.ca.Cert) {
			e.invalidScreen("trust-"+tp.name, screens[i])
			e.t.Fatalf("INVALID: trustpoint %s does not hold this run's CA (its fingerprint is not on `show crypto ca certificates %s`; %s): "+
				"an earlier run's CA is probably still imported", tp.name, tp.name, l73Err(errs[i]))
		}
	}
}

func (e *l73Env) cellA() {
	e.guard()
	e.diagHelp()
	e.daemon("a", l73Daemon{Intermediates: e.files["inter.pem"]})
	e.configure(l73DeviceTLS{Server: l73Server})
	probe := e.ready("a")
	stop := e.capture("a")
	off, start := e.l.mark(), time.Now()
	user, ok, took, version, err := e.tokenLogin()
	e.firstSpan = l73Span{start, time.Now()}
	time.Sleep(l73SettleTail) // the same tail cell h gives each login
	conns := stop()
	recs := e.l.recordsSince(off)
	port, opened := l73FirstPort(conns, l73Server)
	first := "the device opened no connection to " + l73Server
	if opened {
		first = fmt.Sprintf("the device's first connection went to port %d", port)
	} else if port, opened = l73FirstPort(probe, l73Server); opened {
		// The readiness probe reached port49 and the login then sent nothing:
		// the probe's port is the device's default (IOS XE's dead-server memory
		// can silence the login after a failed handshake on that port).
		first = fmt.Sprintf("the device's first connection went to port %d (read off the readiness probe's "+
			"break-glass login; the token login after it sent nothing)", port)
	}
	obs := fmt.Sprintf("%s (%s); login as %s: ok %v in %s (%s)", first, l73Describe(conns, start), user, ok,
		took.Round(time.Millisecond), l73Err(err))
	configured := "no port configured on the TLS server; port49d's RFC 9887 listener on 172.100.100.1:300"
	e.first = conns
	if !opened || port != l73TLSPort {
		e.port = l73TLSPort
		e.configure(e.base())
		e.ready("a-port300")
		stop := e.capture("a-port300")
		off, start = e.l.mark(), time.Now()
		user, ok, took, version, err = e.tokenLogin()
		e.firstSpan = l73Span{start, time.Now()}
		time.Sleep(l73SettleTail)
		conns = stop()
		recs = e.l.recordsSince(off)
		obs += fmt.Sprintf("; then with port 300 configured (every later cell): login as %s ok %v in %s (%s), %s", user, ok,
			took.Round(time.Millisecond), l73Err(err), l73Describe(conns, start))
		configured += "; then port 300"
		e.first = conns
	}
	if !ok || !l73Redeemed(recs) {
		hint := ""
		if e.pki.Alg == "ecdsa" {
			hint = "; if the record says handshake_failed, re-run with PORT49_L73_ALG=rsa and record why in the commit"
		}
		// Error first: the CLI read below Fatals if the break-glass login fails,
		// and the INVALID's cause must be in the output either way. The message
		// carries the leak-gated TLS summary (obs); invalidDeviceLogs keeps the
		// dialect's InvalidCmds output, scrubbed and PEM-free, in the INVALID dir.
		e.t.Error(l73ControlInvalid(l73Err(err), hint, e.quote(recs), hideKeys(obs)))
		e.invalidDeviceLogs()
		e.t.FailNow()
	}
	if !strings.Contains(version, e.d.VersionHas) {
		e.t.Fatalf("INVALID: the device reports %q, not the image under test (%s)", version, e.l.p.version)
	}
	e.facts = append(e.facts, "the device reports "+version)
	e.add("a", configured, obs+"; the control's records: "+e.quote(recs),
		"n/a: no document claims "+e.d.Vendor+"'s default (Cisco's examples configure 6049; that is a choice, not a default); "+
			"decision 50 ruling 1 leaves it to L73 (a), and plan 12's reference configuration takes it from here")
}

func l73FirstHello(conns []l73Conn) (*l73Hello, *l73ServerHello) {
	for _, c := range conns {
		if c.Hello != nil {
			return c.Hello, c.ServerHello
		}
	}
	return nil, nil
}

func (e *l73Env) cellC() {
	e.guard()
	h, _ := l73FirstHello(e.first)
	sni := "no ClientHello was captured"
	docs := "yes: decision 50 ruling 10 (a device configured with the server's address sends none)"
	if h != nil {
		sni = "the ClientHello carries no server_name extension"
		if h.HasSNI {
			sni = fmt.Sprintf("the ClientHello's server_name is %q", h.SNI)
			docs = "**no**: decision 50 ruling 10 says a device configured with the server's address sends no SNI"
		}
	}
	e.settle()
	e.revive("c")
	e.daemon("c", l73Daemon{Intermediates: e.files["inter.pem"], ServerNames: []string{"tacacs.l73.example"}})
	stop := e.capture("c")
	off, start := e.l.mark(), time.Now()
	user, ok, took, _, err := e.tokenLogin()
	conns := stop()
	e.reached("c", conns)
	recs := e.l.recordsSince(off)
	e.add("c", "the device unchanged (configured by address); port49d first with no server_names (cell a), then with server_names [tacacs.l73.example]",
		fmt.Sprintf("%s; with server_names set: login as %s ok %v in %s (%s), sni_mismatch records %d, %s; records: %s",
			sni, user, ok, took.Round(time.Millisecond), l73Err(err), len(l73Where(recs, "tls_outcome", "sni_mismatch")),
			l73Describe(conns, start), e.quote(recs)), docs)
}

func (e *l73Env) cellF() {
	e.guard()
	h, s := l73FirstHello(e.first)
	if h == nil || s == nil {
		e.t.Fatal("INVALID: cell a's control login captured no ClientHello and ServerHello")
	}
	var versions, suites, groups, sigs []string
	for _, v := range h.Versions {
		versions = append(versions, tls.VersionName(v))
	}
	for _, c := range h.Suites {
		suites = append(suites, tls.CipherSuiteName(c))
	}
	for _, g := range h.Groups {
		groups = append(groups, tls.CurveID(g).String())
	}
	for _, a := range h.SigAlgs {
		sigs = append(sigs, tls.SignatureScheme(a).String())
	}
	docs := "yes: decision 50 ruling 2 (TLS 1.3, one of crypto/tls's three suites)"
	if s.Version != tls.VersionTLS13 {
		docs = "**no**: decision 50 ruling 2 and RFC 9887 §3.2 assume TLS 1.3"
	}
	e.add("f", "cell a's control connection",
		fmt.Sprintf("offered versions %v, suites %v, groups %v, signature schemes %v, ALPN %v; port49 chose %s %s (HelloRetryRequest %v)",
			versions, suites, groups, sigs, h.ALPN, tls.VersionName(s.Version), tls.CipherSuiteName(s.Suite), s.HelloRetry), docs)
}

func (e *l73Env) cellD() {
	e.guard()
	now := time.Now()
	right := []net.IP{net.ParseIP(l73Server)}
	variants := []struct {
		id, what string
		from     l73Cert
		leaf     l73ServerLeaf
	}{
		{"d-dns", "dNSName tacacs.l73.example only, no iPAddress", e.pki.Root,
			l73ServerLeaf{DNSNames: []string{"tacacs.l73.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}},
		{"d-wrongip", "iPAddress 172.100.100.9 only", e.pki.Root,
			l73ServerLeaf{IPs: []net.IP{net.ParseIP("172.100.100.9")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}},
		{"d-expired", "iPAddress 172.100.100.1, expired an hour ago", e.pki.Root,
			l73ServerLeaf{IPs: right, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)}},
		{"d-untrusted", "iPAddress 172.100.100.1, issued by a CA the device was never given", e.pki.Other,
			l73ServerLeaf{IPs: right, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}},
	}
	var parts []string
	docs := "n/a"
	refusedRows := 0
	for _, v := range variants {
		e.guard()
		e.settle()
		e.writeServer(v.id, v.from, v.leaf)
		e.revive(v.id)
		e.daemon(v.id, l73Daemon{Intermediates: e.files["inter.pem"], Cert: e.files[v.id+".crt"], Key: e.files[v.id+".key"]})
		stop := e.capture(v.id)
		off, start := e.l.mark(), time.Now()
		user, ok, took, _, err := e.tokenLogin()
		conns := stop()
		e.reached(v.id, conns)
		recs := e.l.recordsSince(off)
		alert, alerted := l73DeviceAlert(conns)
		verdict := l73Grade(ok, l73Redeemed(recs), l73RefusedFor(recs, "handshake_failed", l73DeviceAborted) || alerted)
		if verdict == "accepted" {
			verdict = "**accepted**"
		}
		if verdict == "refused" && alerted {
			// The device's own words, read off the capture: some images send the
			// alert in the clear after the ServerHello, which port49d's log
			// cannot tell from a handshake that merely did not complete.
			verdict += fmt.Sprintf(" (the device sent alert %d, %s, in the clear)", alert.Description, l73AlertName(alert.Description))
		}
		refusedRows++
		if !strings.HasPrefix(verdict, "refused") {
			refusedRows = -len(variants)
		}
		parts = append(parts, fmt.Sprintf("%s: %s (login as %s ok %v in %s, %s; %s; records: %s)", v.what, verdict, user, ok,
			took.Round(time.Millisecond), l73Err(err), l73Describe(conns, start), e.quote(recs)))
		switch {
		case (v.id == "d-dns" || v.id == "d-wrongip") && verdict == "**accepted**" && docs == "n/a":
			docs = "**no**: RFC 9887 §3.4 requires the client to check the server's identity, and the device was configured by address"
		case v.id == "d-expired" && verdict == "**accepted**" && docs == "n/a":
			docs = "**no**: decision 50 ruling 15 treats an expired server certificate as nothing a device can use"
		case v.id == "d-untrusted" && verdict == "**accepted**" && docs == "n/a":
			docs = "**no**: RFC 9887 §3.4 requires the client to validate the server's certificate path"
		}
	}
	if refusedRows == len(variants) && docs == "n/a" {
		docs = "yes: RFC 9887 §3.4 (the client checks the server's identity and path) and decision 50 ruling 15 (an expired server certificate): " +
			"the device refused each variant, by the alert named in its row"
	}
	parts = append(parts, "the device's log: "+e.deviceLog("d-device-log.txt"))
	e.add("d", "the device configured by address 172.100.100.1; port49d's server certificate varied per row, all else as cell a",
		strings.Join(parts, "; "), docs)
}

// deviceLog reads the device's TACACS+ and TLS lines (the dialect's LogCmd),
// scrubbed, into evidence as name, and returns how many lines it kept.
func (e *l73Env) deviceLog(name string) string {
	var out, unread string
	e.cli(func(c *cliConn) error {
		o, err := c.sendExpect(e.d.LogCmd, 60*time.Second, e.opMark(c))
		out = o
		if err != nil {
			// A failed read is a gap in the evidence, not a lost cell: the
			// rows measured so far still reach e.add.
			unread = l71MaskExchange(l73Err(err))
		}
		return nil
	})
	if unread != "" {
		return "the device's log could not be read: " + unread
	}
	text := l71MaskExchange(l73ScrubLog(hideKeys(out)))
	e.evidence[name] = []byte(text)
	return fmt.Sprintf("%d lines in `evidence/L73-%s/%s`", strings.Count(text, "\n"), e.l.p.name, name)
}

func (e *l73Env) cellE() {
	e.guard()
	e.settle()
	// port49d anchored at the root alone, no intermediates_file: the device's
	// leaf verifies only if the device sends the intermediate itself.
	e.revive("e")
	e.daemon("e", l73Daemon{})
	stop := e.capture("e")
	off, start := e.l.mark(), time.Now()
	user, ok, took, _, err := e.tokenLogin()
	conns := stop()
	e.reached("e", conns)
	recs := e.l.recordsSince(off)
	chain := "the device sends its chain (leaf and intermediate): the login verified with no intermediates_file"
	switch l73Grade(ok, l73Redeemed(recs), l73RefusedFor(recs, "unknown_ca", l73UnknownAuthority)) {
	case "refused":
		chain = "the device sends its leaf alone: with no intermediates_file port49 recorded unknown_ca (cell a, " +
			"with intermediates_file, passed)"
	case "login failed, cause unproven":
		chain = "the login failed and port49 recorded no unknown_ca refusal, so what the device sends is unproven"
	}
	e.add("e", e.d.Enrol+"; port49d's client_ca_file the root alone, no intermediates_file",
		fmt.Sprintf("request: subject %q, dNSName %v, iPAddress %v, key %s, requested EKU %v; issued: %s; %s (login as %s ok %v "+
			"in %s, %s; %s; records: %s)", e.csr.Subject, e.csr.DNSNames, e.csr.IPs, e.csr.KeyAlg, e.csr.EKU, l73CertFacts(e.leaf),
			chain, user, ok, took.Round(time.Millisecond), l73Err(err), l73Describe(conns, start), e.quote(recs)),
		"n/a: decision 50 ruling 7 leaves what enrolments issue to L73 (e); either chain verifies with intermediates_file, as ruling 7 says")
}

func (e *l73Env) cellG() {
	e.guard()
	e.settle()
	// revive, not ready: a probe on g's own daemon would hold a ticket
	// before login 1. Tickets do not cross daemons (each process's keys are
	// its own), so g's logins start with none.
	e.revive("g")
	e.daemon("g", l73Daemon{Intermediates: e.files["inter.pem"], Tickets: 10 * time.Minute})
	sel := `port49_tls_handshakes_total{outcome="` + string(devicecert.Resumed) + `"}`
	before, ok := e.metric(sel)
	if !ok {
		e.t.Fatal("INVALID: the resumed handshake series is not exported at daemon start")
	}
	stop := e.capture("g")
	off, start := e.l.mark(), time.Now()
	u1, ok1, _, _, err1 := e.tokenLogin()
	time.Sleep(5 * time.Second)
	u2, ok2, _, _, err2 := e.tokenLogin()
	conns := stop()
	after, ok := e.metric(sel)
	if !ok {
		e.t.Fatal("INVALID: the resumed handshake series vanished after the logins")
	}
	resumed := after - before
	var offered, selected int
	for _, c := range conns {
		if c.Hello != nil && c.Hello.PSKIdentities > 0 {
			offered++
		}
		if c.ServerHello != nil && c.ServerHello.PSKSelected {
			selected++
		}
	}
	caveat := "counts are per connection: a login's own later connections may resume from its first ticket"
	if !ok1 || !ok2 {
		caveat += "; a login failed, so the counts show no steady-state resumption"
	}
	e.add("g", "port49d with session_ticket_lifetime 10m (decision 50 ruling 11; off by default); two logins 5s apart",
		fmt.Sprintf("%s; logins %s ok %v (%s) and %s ok %v (%s); ClientHellos offering a ticket: %d, ServerHellos accepting one: %d, "+
			"port49_tls_handshakes_total{outcome=\"resumed\"} +%v; %s; records: %s", caveat, u1, ok1, l73Err(err1), u2, ok2, l73Err(err2),
			offered, selected, resumed, l73Describe(conns, start), e.quote(e.l.recordsSince(off))),
		"n/a: decision 50 ruling 11 says how often devices resume is unmeasured until this cell")
}

func (e *l73Env) cellH() {
	e.guard()
	e.settle()
	e.daemon("h", l73Daemon{Intermediates: e.files["inter.pem"]})
	d := e.base()
	d.SingleConnection = true
	e.configure(d)
	// Captured from before the readiness probe: with single-connection the
	// probe's connection may be the one both logins reuse, and a connection
	// is counted only from its SYN.
	stop := e.capture("h")
	e.ready("h")
	off := e.l.mark()
	s1 := time.Now()
	u1, ok1, _, _, err1 := e.tokenLogin()
	e1 := time.Now()
	time.Sleep(l73SettleTail)
	s2 := time.Now()
	u2, ok2, _, _, err2 := e.tokenLogin()
	e2 := time.Now()
	time.Sleep(l73SettleTail) // login 2 gets the tail login 1 had
	conns := stop()
	// One window helper for h's logins and cell a's control, one tail each:
	// accounting connections opened after a login returned count with it.
	win := l73LoginWindows(conns, l73Server, []l73Span{{s1, e1}, {s2, e2}})
	w1, w2 := win[0], win[1]
	held, probeHeld := 0, 0
	for _, c := range w1 {
		if c.End == "open" || c.EndAt.After(s2) {
			held++
		}
	}
	for _, c := range l73Window(conns, l73Server, time.Time{}, s1.Add(-time.Nanosecond)) {
		if c.End == "open" || c.EndAt.After(s1) {
			probeHeld++ // the readiness probe's, still open at the first login
		}
	}
	base := len(l73LoginWindows(e.first, l73Server, []l73Span{e.firstSpan})[0])
	e.configure(e.base())
	e.add("h", "`single-connection` on the TLS server; two logins 5s apart",
		fmt.Sprintf("connections the readiness probe opened that were still open at the first login: %d; "+
			"login %s ok %v (%s): %d new connection(s); login %s ok %v (%s): %d new connection(s); connections from the first "+
			"still open at the second: %d; without single-connection (cell a's control) one login opened %d; %s; records: %s",
			probeHeld, u1, ok1, l73Err(err1), len(w1), u2, ok2, l73Err(err2), len(w2), held, base, l73Describe(conns, s1),
			e.quote(e.l.recordsSince(off))),
		"n/a: plan 12's reference configuration takes it from here")
}

// addSecondAddress puts 172.100.100.2 on the clab bridge beside .1, as
// prepareSplit does, and takes it off when the test ends.
func (e *l73Env) addSecondAddress() {
	dev, err := bridgeDevice()
	if err != nil {
		e.t.Fatalf("INVALID: %v", err)
	}
	shown := []byte(e.bridgeAddrs())
	if e.bridge && l73HasAddress(string(shown), l73SecondServer) {
		return
	}
	if e.bridge {
		// Cell i put it there and it is gone: cell j's daemon would fail to bind
		// it. The cause is unmeasured; the run says so and puts it back.
		e.t.Logf("lab: %s was missing from %s when the next cell needed it (addresses: %s); adding it again",
			l73SecondServer, dev, strings.TrimSpace(string(shown)))
	} else {
		del := func() { _ = exec.Command("sudo", "-n", "ip", "addr", "del", l73SecondServer+"/24", "dev", dev).Run() }
		del()
		// Registered before the add: every exit path, a Fatal, an INVALID or the
		// STOP guard included, takes the address off again.
		e.t.Cleanup(del)
	}
	if out, err := exec.Command("sudo", "-n", "ip", "addr", "add", l73SecondServer+"/24", "dev", dev).CombinedOutput(); err != nil &&
		!strings.Contains(string(out), "File exists") {
		e.t.Fatalf("INVALID: adding %s to %s: %v\n%s", l73SecondServer, dev, err, out)
	}
	e.bridge = true
}

// bridgeAddrs is `ip -o -4 addr show` for the clab bridge ("" if unreadable).
func (e *l73Env) bridgeAddrs() string {
	dev, err := bridgeDevice()
	if err != nil {
		return ""
	}
	out, _ := exec.Command("ip", "-o", "-4", "addr", "show", "dev", dev).CombinedOutput()
	return string(out)
}

// logBridge puts the bridge's address list in the run's output, so a run
// shows when 172.100.100.2 goes.
func (e *l73Env) logBridge(when string) {
	e.t.Logf("lab: bridge addresses at %s: %s", when, strings.Join(strings.Fields(e.bridgeAddrs()), " "))
}

// cellI: the device lists a second TLS server, 172.100.100.2:300, where
// nothing listens (an RST). Each refusal is met with a break-glass login:
// port49 holds no token for breakglass, so the login lands only if the device
// reaches its local method. The timeline comes from the capture. A row's
// verdict needs a port49 record of the row's own reason; without one the row
// says the cause is unproven and contradicts nothing.
func (e *l73Env) cellI() {
	e.guard()
	e.addSecondAddress()
	e.logBridge("cell i start")
	d := e.base()
	d.Second, d.SecondTLS, d.SecondPort = l73SecondServer, true, e.port
	e.configure(d)
	fault := e.write("fault", []byte("store_unavailable\n"))
	unreachable := fmt.Sprintf("{crls: [{name: l73, url: \"http://127.0.0.1:%d/l73.crl\", issuer_file: %s}]}", freePort(e.t), e.files["inter.pem"])
	load, _ := os.ReadFile("/proc/loadavg")
	refusals := []struct {
		id, what, outcome string
		o                 l73Daemon
		again             bool
	}{
		{"i-alert", "an alert at the handshake (client_ca_file a CA that did not issue the device's chain: unknown_ca)", "unknown_ca",
			l73Daemon{ClientCA: e.files["other.pem"]}, false},
		{"i-accept", "a reset at Accept (the device's record says transport tcp: transport_mismatch)", "transport_mismatch",
			l73Daemon{Inventory: e.invTCP, Intermediates: e.files["inter.pem"]}, false},
		{"i-window", "a decline window (certificate status unavailable, an unreachable CRL: status_unavailable), then a second login at once, inside the window",
			"status_unavailable", l73Daemon{Intermediates: e.files["inter.pem"], Status: unreachable}, true},
		{"i-error", "an ERROR reply (the lab fault switch, store_unavailable: authentication answers ERROR)", "store_unavailable",
			l73Daemon{Intermediates: e.files["inter.pem"], FaultFile: fault}, false},
	}
	var parts, unproven []string
	docs := "yes: decision 50 rulings 5, 7 and 8 for the rows whose break-glass login landed (i-alert, i-accept, i-window); " +
		"i-error is an observation only: spec §5.7 store_unavailable records from L4 that an authentication ERROR is final on Junos with tacplus alone"
	contradicted := false
	for _, r := range refusals {
		e.guard()
		e.settle()
		e.revive(r.id)
		e.daemon(r.id, r.o)
		stop := e.capture(r.id)
		off, start := e.l.mark(), time.Now()
		ok, took, err := e.breakglassLogin()
		s := fmt.Sprintf("%s: break-glass login ok %v in %s (%s)", r.what, ok, took.Round(time.Millisecond), l73Err(err))
		ok2 := true
		if r.again {
			var took2 time.Duration
			var err2 error
			ok2, took2, err2 = e.breakglassLogin()
			s += fmt.Sprintf(", the second ok %v in %s (%s)", ok2, took2.Round(time.Millisecond), l73Err(err2))
		}
		conns := stop()
		e.reached(r.id, conns)
		recs := e.l.recordsSince(off)
		n := len(l73Where(recs, "tls_outcome", r.outcome)) + len(l73Where(recs, "diagnosis", r.outcome))
		for _, rec := range recs {
			if str(rec, "reason") == r.outcome {
				n++
			}
		}
		proof := fmt.Sprintf("%d record(s) of %s", n, r.outcome)
		switch contra, proven := l73RefusalVerdict(r.id, n, ok, ok2, r.again); {
		case !proven:
			proof = "no record of " + r.outcome + ", so the refusal itself is unproven"
			unproven = append(unproven, r.id)
		case contra != "":
			contradicted = true
			docs = contra
		}
		parts = append(parts, fmt.Sprintf("%s; %s; %s: %s", s, l73Describe(conns, start), proof, e.quote(recs)))
	}
	e.configure(e.base())
	if len(unproven) > 0 && !contradicted {
		docs = fmt.Sprintf("n/a: no port49 record proves the refusal on %v, so those rows say nothing about ruling 8", unproven)
	}
	obsI, docs := l73IRowGate(e.bridgeAddrs(), strings.Join(parts, "; ")+". An ERROR for an obfuscated packet (decision 50 ruling 13) cannot be provoked from port49's "+
		"side: only a device that clears the flag earns it, and cell b counts whether this one ever did.", docs)
	e.add("i", fmt.Sprintf("servers 172.100.100.1:%d (TLS, port49d refusing as each row says) then 172.100.100.2:%d (TLS, "+
		"nothing listening: an RST); login method list %s; load average at the start %s", l73TLSPort, l73TLSPort,
		e.d.Fallback, strings.TrimSpace(string(load))),
		obsI, docs)
}

// l73RefusalVerdict grades one cell (i) row. proven needs a port49 record of
// the row's own reason (n of them). contra is the docs text of a proven row
// whose device did not reach its local method, "" otherwise. i-error is an
// observation only: spec §5.7 store_unavailable records from L4 that an
// authentication ERROR is final on Junos with tacplus alone, so a failed
// local login there is the expected behaviour and contradicts no ruling.
// i-window's second login, inside the window, must land too (ruling 8).
func l73RefusalVerdict(id string, n int, ok, ok2, again bool) (contra string, proven bool) {
	if n == 0 {
		return "", false
	}
	if id == "i-error" {
		return "", true
	}
	ruling := map[string]string{
		"i-alert":  "7 (a chain with no path to the anchors is refused)",
		"i-accept": "5 (what needs no TLS byte is decided at Accept)",
		"i-window": "8 (an unavailable status declines the device)",
	}[id]
	switch {
	case !ok:
		return "**no**: decision 50 ruling " + ruling + " leaves the device to its local method; on " + id + " the local login did not land", true
	case again && !ok2:
		return "**no**: decision 50 ruling " + ruling + " sends the next login, inside the window, to the local method; on " + id + " the login inside the window did not land", true
	}
	return "", true
}

func (e *l73Env) cellJ() {
	e.guard()
	e.addSecondAddress()
	e.logBridge("cell j start")
	// j1: TLS only, port49 refusing, its RFC 8907 listener on .1:49 open.
	e.settle()
	e.revive("j1")
	e.daemon("j1", l73Daemon{ClientCA: e.files["other.pem"]})
	stop := e.capture("j1")
	start := time.Now()
	ok1, took1, err1 := e.breakglassLogin()
	c1 := stop()
	e.reached("j1", c1)
	plain1 := 0
	for _, c := range c1 {
		if l73PortOf(c.Server) == 49 {
			plain1++
		}
	}
	// j2: a mixed list, TLS .1 then plain .2, a second server address (j's
	// same-host question is j1's; Juniper documents a mixed list, and on IOS
	// XE and NX-OS it is the same group with a plain server after the TLS
	// one), port49's RFC 8907 listener moved to .2:49.
	// A device that refuses the list is an observation, not an INVALID run:
	// NX-OS's `tacacs-server secure tls` may apply to every host.
	e.settle()
	d := e.base()
	d.Second, d.SecondTLS = l73SecondServer, false
	e.touched = true
	if out, err := e.apply(d); err != nil {
		if _, rerr := e.restore(); rerr != nil && e.d.Family == "junos" {
			e.t.Fatalf("INVALID: restoring after the refused mixed list: %s", oneLine(hideKeys(rerr.Error())))
		}
		e.configure(e.base())
		what := "the device refused the mixed list"
		refusal := l73Refusal(out)
		if refusal == "" {
			// No refusal screen: the configuration did not read back as typed, which
			// says nothing about what the device accepts.
			what = "j2 was not measured, the configuration did not read back as typed"
			refusal = oneLine(hideKeys(err.Error()))
		}
		e.add("j", "j1: the TLS server alone, port49d refusing its handshake, port49d's RFC 8907 listener open on 172.100.100.1:49; "+
			"j2: TLS 172.100.100.1 then plain 172.100.100.2",
			fmt.Sprintf("j1: break-glass ok %v in %s (%s), connections to port 49: %d; %s. j2: %s: %s",
				ok1, took1.Round(time.Millisecond), l73Err(err1), plain1, l73Describe(c1, start), what, refusal),
			l73JDocs(plain1))
		return
	}
	e.logBridge("cell j before j2 (after j1 and the mixed list applied)")
	e.revive("j2")
	e.logBridge("cell j, j2's device ready")
	e.daemon("j2", l73Daemon{ClientCA: e.files["other.pem"], Listen: net.JoinHostPort(l73SecondServer, "49")})
	stop = e.capture("j2")
	off, start2 := e.l.mark(), time.Now()
	ok2, took2, err2 := e.breakglassLogin()
	c2 := stop()
	e.reached("j2", c2)
	recs := e.l.recordsSince(off)
	var headers int
	for _, c := range c2 {
		if l73Host(c.Server) == l73SecondServer && l73PortOf(c.Server) == 49 {
			headers += len(c.Plain)
		}
	}
	mismatch := 0
	for _, r := range l73Where(recs, "diagnosis", "transport_mismatch") {
		if str(sub(r, "unvalidated"), "transport") == "" { // the RFC 8907 listener's record carries no transport
			mismatch++
		}
	}
	e.configure(e.base())
	docs := l73JDocs(plain1)
	e.add("j", "j1: the TLS server alone, port49d refusing its handshake, port49d's RFC 8907 listener open on 172.100.100.1:49; "+
		"j2: a mixed list, TLS 172.100.100.1 then plain 172.100.100.2 (a second server address; port49d's RFC 8907 listener moved there), the TLS handshake refused",
		fmt.Sprintf("j1: break-glass ok %v in %s (%s), connections to port 49: %d; %s. j2: break-glass ok %v in %s (%s); %s; plain "+
			"TACACS+ headers the device sent to 172.100.100.2:49: %d; port49 declined it transport_mismatch %d time(s) (decision 50 "+
			"ruling 4); records: %s",
			ok1, took1.Round(time.Millisecond), l73Err(err1), plain1, l73Describe(c1, start), ok2, took2.Round(time.Millisecond),
			l73Err(err2), l73Describe(c2, start2), headers, mismatch, e.quote(recs)), docs)
}

// l73JDocs reads j1: a TLS-only list must never reach port 49.
func l73JDocs(plain1 int) string {
	if plain1 > 0 {
		return "**no**: RFC 9887 §5.1.1 forbids falling back to non-TLS for the same server; with a TLS-only list the device opened port 49"
	}
	return "yes: RFC 9887 §5.1.1"
}

// cellB: port49d answers any packet whose unencrypted flag is clear with an
// ERROR and records obfuscated_over_tls (decision 50 ruling 13), so no such
// record across every login of the run means every packet had the flag
// set. The capture cannot show it: the header is inside TLS. With no TLS
// record at all the run proves nothing either way.
func (e *l73Env) cellB() {
	e.guard()
	recs := e.l.recordsSince(e.start)
	obf := len(l73Where(recs, "diagnosis", "obfuscated_over_tls"))
	byEvent := map[string]int{}
	total := 0
	for _, r := range recs {
		if str(sub(r, "device"), "transport") == "tls" && str(r, "event") != "unvalidated" {
			byEvent[str(r, "event")]++
			total++
		}
	}
	docs := "yes: RFC 9887 §4, decision 50 ruling 13"
	switch {
	case obf > 0:
		docs = "**no**: RFC 9887 §4 requires the flag on every packet over TLS"
	case total == 0:
		docs = "n/a: port49 recorded no validated TLS packet, so the flag is unproven"
	}
	e.add("b", "every TLS login of this run (cells a, c, d, e, g, h); port49d checks each packet's flag",
		fmt.Sprintf("obfuscated_over_tls records: %d; records over TLS by event: %v", obf, byEvent), docs)
}

// note reads the device's configuration, gates every evidence file, writes
// the evidence, the L71 addendum and the L73 note. Nothing reaches
// results/ or evidence/ before this, so an INVALID run writes nothing.
func (e *l73Env) note() {
	e.guard()
	var conf string
	e.cli(func(c *cliConn) error {
		for _, cmd := range e.d.ShowCmds {
			o, err := c.sendExpect(cmd, 60*time.Second, e.opMark(c))
			if err != nil {
				return err
			}
			conf += o + "\n"
		}
		return nil
	})
	e.evidence["device-config.txt"] = []byte(l71MaskExchange(l73ScrubLog(hideKeys(conf))))
	all, seeds := l73DropSeedMints(e.l.recordsSince(e.start))
	e.facts = append(e.facts, fmt.Sprintf("the decision log in the evidence omits the %d lab seed mint records (the lab method reseeds every lab principal every few seconds; each is a `mint` event with `auth.method` lab)", seeds))
	var lines []string
	for _, r := range all {
		b, _ := json.Marshal(r)
		lines = append(lines, string(l72RedactCredentialHash(b)))
	}
	e.evidence["decisions.jsonl"] = []byte(strings.Join(lines, "\n") + "\n")
	secrets := e.allSecrets()
	for name, body := range e.evidence {
		if len(labcreds.Contains(body, secrets)) > 0 {
			e.t.Fatalf("INVALID: evidence %s holds a secret; nothing written", name)
		}
		if strings.HasSuffix(name, ".txt") && len(l72TranscriptLeaks(string(body))) > 0 {
			e.t.Fatalf("INVALID: evidence %s carries TLS session material; nothing written", name)
		}
		if leaks := l72HashValueLeaks(string(body)); len(leaks) > 0 {
			e.t.Fatalf("INVALID: evidence %s holds a hash value under %v; nothing written", name, leaks)
		}
		if strings.HasSuffix(name, ".tls.json") && len(l73SummaryLeaks(string(body))) > 0 {
			e.t.Fatalf("INVALID: evidence %s holds a long hex or base64 run; nothing written", name)
		}
	}
	table, err := l73RenderTable(e.obs)
	if err != nil {
		e.t.Fatalf("INVALID: %v", err)
	}
	var b strings.Builder
	b.WriteString("### Run\n\n")
	for _, f := range e.facts {
		fmt.Fprintf(&b, "- %s\n", f)
	}
	attrs := e.d.Attrs
	if attrs == "" {
		attrs = "the lab file's"
	}
	fmt.Fprintf(&b, "- port49d: `certificate_status: {disabled: true}` in every cell but (i)'s decline window (the status path is "+
		"L72's), `malformed_backoff_base: 2s`, `session_attributes: %s`; the device: %s\n", attrs, e.d.Revocation)
	fmt.Fprintf(&b, "- not measured here: SCEP, CMPv2, EST and ACME enrolment; whether %s checks port49's revocation status\n\n", e.d.Vendor)
	b.WriteString("### Cells\n\n" + table)
	note := string(l72RedactCredentialHash([]byte(b.String())))
	if leaks := l72HashValueLeaks(note); len(leaks) > 0 {
		e.t.Fatalf("INVALID: the note holds a hash value under %v; nothing written", leaks)
	}
	if len(labcreds.Contains([]byte(note), secrets)) > 0 {
		e.t.Fatal("INVALID: the note holds a secret; nothing written")
	}
	if err := os.RemoveAll(e.evDir); err != nil {
		e.t.Fatal(err)
	}
	if err := os.MkdirAll(e.evDir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	for name, body := range e.evidence {
		if err := os.WriteFile(filepath.Join(e.evDir, name), body, 0o644); err != nil {
			e.t.Fatal(err)
		}
	}
	e.writeL71()
	ev := "tests/lab/evidence/L73-" + e.l.p.name + "/"
	e.l.captureNote = fmt.Sprintf("`%s` — per-cell TLS summaries (`<cell>.tls.json`: each connection's ClientHello and "+
		"ServerHello fields, plaintext alerts, record counts and timings, with no session byte by construction; the raw "+
		"captures stay git-ignored in `tests/lab/captures/L73-%s/`), the decision log (`decisions.jsonl`, credential hashes "+
		"redacted), the device's TACACS+/TLS log lines and configuration (masked), and the CLI help exchange (`l71-probe.txt`).",
		ev, e.l.p.name)
	e.l.result(e.t, "L73", l73Claim(e.d.Vendor), note)
	e.l.captureNote = ""
	var contra []string
	for _, o := range e.obs {
		if strings.HasPrefix(o.Docs, "**no**") {
			contra = append(contra, o.ID)
		}
	}
	if len(contra) > 0 {
		e.t.Logf("cells %v contradict a document: CLAUDE.md rule 4, the doc is wrong (Task 17 fixes it)", contra)
	}
}
