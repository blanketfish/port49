//go:build lab

package lab

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

const l56Claim = "Port49-issued certificates end to end on Keycloak and one device (plan 9b), with the real port49 " +
	"CLI: a broker started with broker.identity.issuance and no issuing CA answers a sign-in's exchange 503 " +
	"issuance_unavailable and its log names init-issuer, and after port49-broker init-issuer and a restart issues; " +
	"port49 login --oidc --no-browser signs in through a scripted browser, asks the password, writes a 0600 key and " +
	"its certificate, names the principal, starts the agent and refreshes once; port49 token mints and the device " +
	"takes the token over SSH; port49 refresh extends the device session with no sign-in; port49 login after the " +
	"agent stopped starts a new one with no sign-in and extends the device session; port49 login --sign-in at a " +
	"terminal, the address pasted, issues a new certificate; an administrator's sign-out refuses the certificate's " +
	"next mint in the broker's logout words and ends the agent, a port49 login over that certificate removes it, and " +
	"a sign-in from the time the broker names works; with Keycloak stopped, port49 token, port49 refresh and a new " +
	"agent over the held certificate work, and port49 login --sign-in says the provider did not answer and when the " +
	"held certificate ends; no compact JWS, code or private key in the CLI's raw output or the agent's log " +
	"(policy engine spec §15 L56; §13 decision 43)."

// l56AuthURL is the authorization URL port49 prints on its own line,
// indented two spaces.
func l56AuthURL(line string) (string, bool) {
	if !strings.HasPrefix(line, "  https://") || strings.ContainsAny(strings.TrimSpace(line), " \t") {
		return "", false
	}
	return strings.TrimSpace(line), true
}

var loginFrom = regexp.MustCompile(`log in again from (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)`)

// l56LoginFrom is the time the broker's logout words say a login is taken from.
func l56LoginFrom(text string) (time.Time, bool) {
	m := loginFrom.FindStringSubmatch(text)
	if m == nil {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, m[1])
	return at, err == nil
}

// l56Files is the end to end's files: the human verifier asking for the
// email scope its principal claim needs, and the broker issuing.
func l56Files(files map[string]string) error {
	if err := oidcE2EFiles(files); err != nil {
		return err
	}
	const at = "        principal_claim: email\n"
	b := files["port49-broker.yaml"]
	if !strings.Contains(b, at) || !strings.Contains(b, "  identity:\n") {
		return fmt.Errorf("port49-broker.yaml has no human verifier's principal_claim, or no identity, to follow")
	}
	b = strings.Replace(b, at, at+"        scopes: [openid, email]\n", 1)
	files["port49-broker.yaml"] = strings.Replace(b, "  identity:\n", "  identity:\n    issuance: {}\n", 1)
	return nil
}

// l56Proxy is a CONNECT proxy on loopback that takes the CLI to Keycloak by
// its issuer's name, which this host does not resolve. It tunnels to that
// one name alone. It is lab plumbing, and the note says so.
func l56Proxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != kcHost+":"+kcPort {
			http.Error(w, "l56 proxy: "+kcHost+" alone", http.StatusForbidden)
			return
		}
		up, err := net.DialTimeout("tcp", "127.0.0.1:"+kcPort, 10*time.Second)
		if err != nil {
			http.Error(w, "l56 proxy: "+err.Error(), http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, conn); up.Close() }()
		_, _ = io.Copy(conn, up)
		conn.Close()
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// l56Pty is a pseudo-terminal: the master the test types on, and the slave
// port49 takes for its stdin, so it offers the paste.
func l56Pty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("INVALID: no pty: %v", err)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Fatalf("INVALID: no pty: TIOCSPTLCK: %v", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Fatalf("INVALID: no pty: TIOCGPTN: %v", e)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("INVALID: no pty: %v", err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

// l56CLI is bin/port49 as an operator runs it: its own config directory
// (where the issued key and certificate are kept) and agent socket, the
// broker's CA, Keycloak's CA, and the proxy.
type l56CLI struct {
	bin, sock, home string
	env             []string
	flags           []string
	// printed is what port49 prints by design among the values the run
	// registered as secret: each authorization URL's state, nonce and
	// code_challenge (decision 43 ruling 20). leak exempts these and nothing
	// else; a device token is never among them (tokenLeak).
	printed []string
}

func newL56CLI(t *testing.T, proxy, idpCA string) *l56CLI {
	t.Helper()
	bin := filepath.Join(root, "bin", "port49")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("bin/port49 is not built (`make build`): %v", err)
	}
	home, err := os.MkdirTemp("", "p49l56")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PORT49_CONFIG=") && !strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			env = append(env, kv)
		}
	}
	c := &l56CLI{bin: bin, home: home, sock: filepath.Join(home, "run", "agent.sock"),
		env: append(env, "HOME="+home, "HTTPS_PROXY=http://"+proxy, "NO_PROXY=127.0.0.1",
			"BROWSER=", "DISPLAY=", "WAYLAND_DISPLAY=")}
	c.flags = []string{"--oidc", "--no-browser", "--redirect-port", "18749", "--broker", sliceBrokerURL,
		"--broker-ca", filepath.Join(root, slicePKIDir, testpki.LabCA), "--oidc-ca", idpCA, "--socket", c.sock}
	t.Cleanup(c.stopAgent)
	return c
}

// issued is where the CLI keeps the broker's certificate and its key.
func (c *l56CLI) issued(t *testing.T) (string, string) {
	t.Helper()
	cert, key, err := userconfig.IssuedPathsIn(filepath.Join(c.home, ".port49"), sliceBrokerURL)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// keyNow registers the issued key there now, the whole key and each line of
// its PEM body (l56KeySecrets), as values no output may hold. finish calls it once the command has ended, so the run
// that wrote a key is checked against that key.
func (c *l56CLI) keyNow(kc *keycloak) {
	_, keyPath, err := userconfig.IssuedPathsIn(filepath.Join(c.home, ".port49"), sliceBrokerURL)
	if err != nil {
		return
	}
	if raw, err := os.ReadFile(keyPath); err == nil {
		kc.know(l56KeySecrets(raw)...)
	}
}

// l56KeySecrets is what of a PEM private key no output may hold: the whole
// key (the PKCS#8 DER in base64) and each line of the PEM body.
func l56KeySecrets(raw []byte) []string {
	blk, _ := pem.Decode(raw)
	if blk == nil || len(blk.Bytes) == 0 {
		return nil
	}
	secrets := []string{base64.StdEncoding.EncodeToString(blk.Bytes)}
	for _, line := range strings.Split(string(pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: blk.Bytes})), "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") {
			secrets = append(secrets, line)
		}
	}
	return secrets
}

// knowKey is keyNow, and the certificate's SHA-256, "" for none.
func (c *l56CLI) knowKey(t *testing.T, kc *keycloak) string {
	t.Helper()
	c.keyNow(kc)
	certPath, _ := c.issued(t)
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// agentLog is the agent's log, as the login started it.
func (c *l56CLI) agentLog() string {
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(c.sock), "agent.log"))
	return string(b)
}

// l56Run is one command's outcome. Its raw output is checked for a leaked
// credential first (leak), then scrubbed of every registered secret for the
// note.
type l56Run struct {
	code           int
	stdout, stderr string
	form           bool  // the scripted browser was shown the password form
	leak           error // the raw output held a credential (l56CLI.leak)
}

func (r l56Run) cell() string {
	return fmt.Sprintf("exit %d; stdout %q; stderr %q", r.code, oneLineMax(r.stdout, 300), oneLineMax(r.stderr, 400))
}

// leak is leakIn on raw CLI output, before any scrubbing: a compact JWS, or
// a value the run registered as secret (a code, the key, the admin password)
// that port49 does not print by design. The PKCE verifier port49 draws is
// never seen here; the unit tests' credentialsNowhere checks it.
func (c *l56CLI) leak(kc *keycloak, raw string) error {
	var secrets []string
	for _, v := range kc.known() {
		if !slices.Contains(c.printed, v) {
			secrets = append(secrets, v)
		}
	}
	return leakIn(raw, secrets)
}

// finish is r with its raw output checked for a leak, then scrubbed. The key
// the command may have written is registered first.
func (c *l56CLI) finish(kc *keycloak, r l56Run) l56Run {
	c.keyNow(kc)
	r.leak = c.leak(kc, r.stdout+"\n"+r.stderr)
	r.stdout, r.stderr = scrubbed(r.stdout, kc.known()), scrubbed(r.stderr, kc.known())
	return r
}

// l56Cmd is one port49 command running, its stderr read line by line for the
// authorization URL it prints.
type l56Cmd struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	urls           chan string
	done           chan struct{}
}

// start runs port49 with args, stdin from stdin (nil: none).
func (c *l56CLI) start(t *testing.T, stdin *os.File, args ...string) *l56Cmd {
	t.Helper()
	p := &l56Cmd{cmd: exec.Command(c.bin, args...), urls: make(chan string, 1), done: make(chan struct{})}
	p.cmd.Env = c.env
	p.cmd.Stdout = &p.stdout
	if stdin != nil {
		p.cmd.Stdin = stdin
	}
	errR, err := p.cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.done)
		sc := bufio.NewScanner(errR)
		sc.Buffer(make([]byte, 64<<10), 64<<10)
		for sc.Scan() {
			p.stderr.WriteString(sc.Text() + "\n")
			if u, ok := l56AuthURL(sc.Text()); ok {
				select {
				case p.urls <- u:
				default:
				}
			}
		}
	}()
	return p
}

// authURL is the address the command printed, its state, nonce and
// code_challenge registered as secret and as printed by design; "" when none
// came within 30s, the command killed.
func (p *l56Cmd) authURL(c *l56CLI, kc *keycloak) string {
	select {
	case u := <-p.urls:
		if q, err := url.Parse(u); err == nil {
			v := []string{q.Query().Get("state"), q.Query().Get("nonce"), q.Query().Get("code_challenge")}
			kc.know(v...)
			c.printed = append(c.printed, v...)
		}
		return u
	case <-p.done:
		return ""
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		return ""
	}
}

// wait waits up to 60s for the command to end, and is its outcome.
func (p *l56Cmd) wait(c *l56CLI, kc *keycloak, form bool) l56Run {
	waited := make(chan error, 1)
	go func() { <-p.done; waited <- p.cmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(60 * time.Second):
		_ = p.cmd.Process.Kill()
		<-waited
	}
	return c.finish(kc, l56Run{code: p.cmd.ProcessState.ExitCode(), stdout: p.stdout.String(),
		stderr: p.stderr.String(), form: form})
}

// signIn runs port49 with args, reads the address from its stderr, signs in
// as alice in the scripted browser, and lets Keycloak's redirect reach
// port49's listener on 127.0.0.1:18749.
func (c *l56CLI) signIn(t *testing.T, kc *keycloak, browser *http.Client, args ...string) l56Run {
	t.Helper()
	p := c.start(t, nil, args...)
	form := false
	if u := p.authURL(c, kc); u != "" {
		loc, shown := kc.answer(t, browser, u, oidcAlice, oidcAlicePassword)
		form = shown
		cb, err := (&http.Client{Timeout: 10 * time.Second}).Get(loc.String())
		if err != nil {
			t.Fatalf("the callback: %s", errCause(err))
		}
		cb.Body.Close()
	}
	return p.wait(c, kc, form)
}

// signInPasting is signIn at a terminal, the jump host's path (decision 43
// ruling 5): port49's stdin is a pty, and the address Keycloak sent the
// browser to is typed at port49's prompt, never sent to its listener. It
// also says whether that address carried iss and session_state.
func (c *l56CLI) signInPasting(t *testing.T, kc *keycloak, browser *http.Client, args ...string) (l56Run, string) {
	t.Helper()
	m, s := l56Pty(t)
	go func() { _, _ = io.Copy(io.Discard, m) }()
	p := c.start(t, s, args...)
	form, carried := false, "no address"
	if u := p.authURL(c, kc); u != "" {
		loc, shown := kc.answer(t, browser, u, oidcAlice, oidcAlicePassword)
		form = shown
		carried = fmt.Sprintf("the address pasted carries iss %v, session_state %v", loc.Query().Has("iss"),
			loc.Query().Has("session_state"))
		if _, err := io.WriteString(m, loc.String()+"\n"); err != nil {
			t.Fatalf("typing the address: %v", err)
		}
	}
	return p.wait(c, kc, form), carried
}

// answer is a person's browser on an address port49 printed: it signs in
// when Keycloak shows the form, and returns where Keycloak then sends the
// browser, port49's loopback address, unfollowed. It reports whether the
// form was shown.
func (k *keycloak) answer(t *testing.T, browser *http.Client, authURL, user, pass string) (*url.URL, bool) {
	t.Helper()
	resp, err := browser.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form := false
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			t.Fatalf("INVALID: the address port49 printed answered %s with no login form", resp.Status)
		}
		form = true
		if resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {user},
			"password": {pass}, "credentialId": {""}}); err != nil {
			t.Fatalf("login: %s", errCause(err))
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), "http://127.0.0.1:18749/callback") {
		t.Fatalf("INVALID: Keycloak did not send the browser to port49's listener (%s, %s)", resp.Status, locShape(loc))
	}
	k.know(loc.Query().Get("code"))
	return loc, form
}

// formWithoutPrompt is the control for "the password was asked": an
// authorization request in browser with no prompt=login, which Keycloak
// answers from the browser's SSO session, with no form. It reports whether
// the form was shown.
func (k *keycloak) formWithoutPrompt(t *testing.T, browser *http.Client) bool {
	t.Helper()
	resp, err := browser.Get(k.l55Authorize(t, kcRedirect, randomSecret(t)+randomSecret(t), url.Values{"prompt": {""}}))
	if err != nil {
		t.Fatalf("authorize: %s", errCause(err))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if loc, err := url.Parse(resp.Header.Get("Location")); err == nil {
		k.know(loc.Query().Get("code"))
	}
	return l55Accepted(resp.StatusCode, body)
}

// run runs port49 with args and no stdin, bounded at 60s: a command that
// tried to sign in here would wait for a browser no one drives.
func (c *l56CLI) run(t *testing.T, kc *keycloak, args ...string) l56Run {
	t.Helper()
	return c.start(t, nil, args...).wait(c, kc, false)
}

// tokenLeak is the leak check on `port49 token`'s output once it minted tok:
// the token's one intended appearance is stdout, exactly one line holding it
// and nothing else. stderr is checked with every registered secret, the
// token included, and so is any later command's output (the token is never
// put in c.printed).
func (c *l56CLI) tokenLeak(kc *keycloak, tok, stdout, stderr string) error {
	if stdout != tok+"\n" {
		return fmt.Errorf("stdout is not the token on a line of its own")
	}
	return c.leak(kc, stderr)
}

// token mints device and returns the token, registered as secret. Nothing
// exempts it from the check of any other output.
func (c *l56CLI) token(kc *keycloak, device string) (string, l56Run) {
	cmd := exec.Command(c.bin, "token", "--socket", c.sock, device)
	cmd.Env = c.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	r := l56Run{code: cmd.ProcessState.ExitCode(), stdout: "[the token]"}
	tok := strings.TrimSpace(stdout.String())
	if r.code != 0 {
		tok, r.stdout = "", scrubbed(stdout.String(), kc.known())
		r.leak = c.leak(kc, stdout.String()+"\n"+stderr.String())
	} else {
		kc.know(tok)
		r.leak = c.tokenLeak(kc, tok, stdout.String(), stderr.String())
	}
	r.stderr = scrubbed(stderr.String(), kc.known())
	return tok, r
}

// stopAgent ends the agent listening on the socket, by its peer credentials.
func (c *l56CLI) stopAgent() {
	conn, err := net.Dial("unix", c.sock)
	if err != nil {
		return
	}
	var cred *syscall.Ucred
	if raw, err := conn.(*net.UnixConn).SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
	}
	conn.Close()
	if cred != nil && cred.Pid > 0 && int(cred.Pid) != os.Getpid() {
		_ = syscall.Kill(int(cred.Pid), syscall.SIGTERM)
	}
}

// stopAgentAndWait is stopAgent, then up to 5s for the socket to go: a
// reboot, as the next login meets it.
func (c *l56CLI) stopAgentAndWait(t *testing.T) {
	t.Helper()
	c.stopAgent()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(c.sock); errors.Is(err, fs.ErrNotExist) {
			return
		}
	}
	t.Fatal("INVALID: the agent did not stop within 5s")
}

func TestL56IssuedEndToEnd(t *testing.T) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sel {
		if p.name != "arista_eos" {
			continue
		}
		p := p
		t.Run(p.name, func(t *testing.T) { l56(t, labFor(t, p)) })
		return
	}
	t.Skip("PORT49_LAB_PLATFORMS does not select arista_eos")
}

// l56 is the claim measured on one device. A fault in the setup, or a
// control that does not hold, is INVALID and stops before the note, as the
// 7h end to end's (oidcEndToEnd). Every cell asserts what the claim says of
// it, through fail, and each assertion has a control that shows it can
// fail, noted beside the cell (I5, I6).
func l56(t *testing.T, l *lab) {
	// The CLI reads the system config when it exists, which would change what
	// is measured; refuse before anything comes up.
	if _, err := os.Stat(userconfig.SystemPath); err == nil {
		t.Fatalf("INVALID: %s exists on this host, so the CLI would read it; no note is written", userconfig.SystemPath)
	}
	var failed []string
	fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
	var obs strings.Builder
	cell := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }
	// ran is a CLI cell: its outcome, and a failure if its output leaked.
	ran := func(step string, r l56Run, extra string) {
		cell(step, r.cell()+extra)
		if r.leak != nil {
			fail("%s: the CLI's output: %v", step, r.leak)
		}
	}
	complete := false
	var kc *keycloak

	now := time.Now()
	idpCA, err := testpki.NewCA("port49 lab oidc l56 CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c := l.startComposeWith(t, composeOptions{Overlay: "oidc.yaml", Files: l56Files, Prepare: func(c *composeStack) error {
		brokerCA, err := os.ReadFile(filepath.Join(root, slicePKIDir, testpki.LabCA))
		if err != nil {
			return err
		}
		return oidcE2EPKI(filepath.Join(c.local, "oidc"), idpCA, brokerCA, time.Now())
	}})
	stop := l.capture(t, "L56")
	defer stop()
	var cli *l56CLI
	defer func() {
		if !complete {
			if len(failed) > 0 {
				t.Errorf("L56, before it stopped: %s", strings.Join(failed, "; "))
			}
			return
		}
		note := "The CLI reaches Keycloak through a CONNECT proxy in the test (`l56Proxy`), since this host does " +
			"not resolve keycloak.port49.lab; that is lab plumbing, not part of the claim. The CLI's raw output " +
			"is checked for a compact JWS or any value the run registered as secret (the issued key's included) " +
			"before it is scrubbed for this note; only the authorization URL's state, nonce and code_challenge " +
			"are exempt, being printed by design. A device token must be `port49 token`'s whole stdout and is " +
			"checked for everywhere else, other commands' output and the broker's and port49d's logs included.\n\n" +
			"| step | observed |\n|---|---|\n" + obs.String()
		cli.knowKey(t, kc)
		if err := leakIn(cli.agentLog(), kc.known()); err != nil {
			failed = append(failed, "the agent's log: "+err.Error())
		}
		if logs, err := c.run("logs", "port49-broker", "port49d"); err != nil {
			failed = append(failed, "the broker's and port49d's logs could not be read: "+err.Error())
		} else if err := leakIn(logs, kc.known()); err != nil {
			failed = append(failed, "the broker's or port49d's log: "+err.Error())
		}
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		if err := oidcNoteLeak(note, kc.known()); err != nil {
			t.Errorf("the L56 note is not written: %v", err)
			return
		}
		l.result(t, "L56", l56Claim, note)
		if len(failed) > 0 {
			t.Errorf("L56: %s", strings.Join(failed, "; "))
		}
	}()

	kc = &keycloak{URL: "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm, ca: idpCA, HTTP: keycloakClient(idpCA)}
	kc.know(labSecrets...)
	kc.adminFromEnv(t, filepath.Join(c.local, "oidc", "admin.env"))
	kc.know(kc.admin)
	waitDiscovery(t, kc, 3*time.Minute)
	kc.SetLogoutURL(t, oidcBrokerLogout)
	br := oidcBroker{c: brokerClient(t), kc: kc, base: sliceBrokerURL}
	// The broker takes Keycloak's tokens once its key fetch and start gate
	// allow. A machine's token shows it: issuance leaves the machine path as
	// it was (decision 43 ruling 13). A fault here is setup, not the claim.
	svc := kc.ServiceToken(t)
	kc.know(svc)
	ready := func(what string) {
		if tok, said := br.mintRetry(t, svc, l.p.node, 3*time.Minute); tok == "" {
			t.Fatalf("INVALID: the broker never took a Keycloak token %s: %s", what, said)
		}
	}
	ready("at the start")
	cli = newL56CLI(t, l56Proxy(t), filepath.Join(c.local, "oidc", "idp-ca.pem"))
	browser := keycloakClient(idpCA)
	browser.Jar, _ = cookiejar.New(nil)
	login := append([]string{"login"}, cli.flags...)

	// 0. No issuing CA yet: the broker started, says what to run, and answers
	// a sign-in's exchange 503. Control: 1, the same login once the CA is made.
	r := cli.signIn(t, kc, browser, login...)
	ran("0a. port49 login --oidc, the broker with no issuing CA", r, "")
	if r.code != 1 || !strings.Contains(r.stderr, "issuance_unavailable") {
		fail("with no issuing CA: %s", r.cell())
	}
	logs, _ := c.run("logs", "port49-broker")
	said := strings.Contains(logs, "issuing-ca.pem is missing") && strings.Contains(logs, "init-issuer")
	cell("0b. the broker's start names the missing CA and init-issuer", fmt.Sprint(said))
	if !said {
		fail("the broker's start did not say the CA is missing and to run init-issuer")
	}
	out, err := c.run("run", "--rm", "--no-deps", "port49-broker", "init-issuer")
	if err != nil || !strings.Contains(out, "created the issuing CA") {
		t.Fatalf("INVALID: port49-broker init-issuer: %v: %s", err, oneLineMax(out, 400))
	}
	cell("0c. port49-broker init-issuer", oneLineMax(out, 300))
	if _, err := c.run("restart", "port49-broker"); err != nil {
		t.Fatalf("INVALID: restarting the broker: %v", err)
	}
	ready("after the restart")

	// 1. Login. Control for "password asked": with the SSO session it
	// leaves, a request with no prompt=login is answered with no form.
	r = cli.signIn(t, kc, browser, login...)
	before := cli.knowKey(t, kc)
	ran("1. port49 login --oidc --no-browser, a scripted browser", r, fmt.Sprintf("; password asked %v", r.form))
	if r.code != 0 {
		t.Fatalf("INVALID: the login failed: %s", r.cell())
	}
	if !r.form || !strings.Contains(r.stdout, " as "+e2eAlice+"; your certificate from ") ||
		!strings.Contains(r.stdout, "refreshed at") || !strings.Contains(r.stderr, "  https://") {
		fail("the login: password asked %v; %s", r.form, r.cell())
	}
	certPath, keyPath := cli.issued(t)
	for _, p := range []string{certPath, keyPath} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			mode := os.FileMode(0)
			if fi != nil {
				mode = fi.Mode().Perm()
			}
			fail("%s is not 0600: mode %v, error %v", p, mode, err)
		}
	}
	if kc.formWithoutPrompt(t, browser) {
		t.Fatal("INVALID: Keycloak showed the form to a request with no prompt=login inside the SSO session, so " +
			"\"password asked\" cannot tell prompt=login was honoured")
	}
	cell("1c. control: no prompt=login in the same browser", "no form shown")

	// 2. A token, and the device takes it. Control for the leak check: the
	// token's own stdout holds a registered value, and leakIn says so.
	// Control for "permitted": a token port49 did not mint is refused.
	tok, tr := cli.token(kc, l.p.node)
	ran("2a. port49 token", tr, "")
	if tok == "" {
		t.Fatalf("INVALID: the first token: %s", tr.cell())
	}
	if leakIn(tok+"\n", kc.known()) == nil {
		t.Fatal("INVALID: the leak check does not see a value the run registered")
	}
	sh, err := l.shell(oidcAlice, tok)
	if err != nil {
		t.Fatalf("INVALID: SSH with the token: %v", err)
	}
	res := l.runPermitted(sh, "show version", 20*time.Second)
	sh.Close()
	cell("2b. SSH as alice with it, `show version`", res.cell)
	if !res.permitted {
		fail("the device did not run `show version` with the minted token: %s", res.cell)
	}
	if bad, err := l.shell(oidcAlice, (randomSecret(t) + randomSecret(t))[:30]); err == nil {
		bad.Close()
		t.Fatal("INVALID: the device took a token port49 never minted, so 2b cannot tell")
	}
	cell("2c. control: SSH as alice with a token port49 never minted", "refused")

	// 3. A refresh by the key: no browser, no address printed. Control: 1,
	// whose sign-in printed the address.
	time.Sleep(11 * time.Second) // past the connection's refresh pacing
	r = cli.run(t, kc, "refresh", "--socket", cli.sock)
	ran("3. port49 refresh, no browser", r, "")
	if r.code != 0 || !strings.Contains(r.stdout, "extended to") || strings.Contains(r.stderr, "https://") {
		fail("the refresh: %s", r.cell())
	}

	// 4. A reboot: the agent stopped, a login over the held certificate signs
	// in no more and extends the device session (D1); then a --sign-in at a
	// terminal, the address pasted, issues a new certificate.
	cli.stopAgentAndWait(t)
	r = cli.run(t, kc, login...)
	ran("4a. port49 login after the agent stopped", r, "")
	if r.code != 0 || !strings.Contains(r.stdout, "using your certificate for "+e2eAlice) ||
		!strings.Contains(r.stdout, "extended to") || strings.Contains(r.stderr, "https://") {
		fail("a new agent over the held certificate: %s", r.cell())
	}
	cli.stopAgentAndWait(t)
	r, carried := cli.signInPasting(t, kc, browser, append([]string{"login", "--sign-in"}, cli.flags...)...)
	after := cli.knowKey(t, kc)
	ran("4b. port49 login --sign-in at a terminal, the address pasted", r, fmt.Sprintf("; password asked %v; %s; "+
		"a new certificate %v", r.form, carried, after != before))
	if r.code != 0 || !r.form || !strings.Contains(r.stderr, "paste it here (it is not shown)") || after == before {
		fail("the pasted sign-in: %s, password asked %v", r.cell(), r.form)
	}

	// 5. An administrator's sign-out: the certificate's next mint is refused
	// in the broker's logout words (its sid recorded against it), the agent
	// ends, a login over the certificate removes it, and a sign-in from the
	// time the broker names works. Control for 5a: a mint on the 4b
	// certificate before the sign-out, which must work.
	tok, tr = cli.token(kc, l.p.node)
	ran("5. control: port49 token on the new certificate, before the sign-out", tr, "")
	if tok == "" {
		t.Fatalf("INVALID: the new certificate cannot mint before the sign-out, so 5a cannot tell: %s", tr.cell())
	}
	signedOut := time.Now()
	kc.LogoutUser(t, kc.UserID(t, oidcAlice))
	ended := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if _, tr = cli.token(kc, l.p.node); tr.code != 0 {
			ended = strings.Contains(tr.stderr, "back-channel logout")
			break
		}
	}
	ran("5a. port49 token after an administrator's sign-out, polled up to 10s", tr, "")
	if !ended {
		fail("after the sign-out, no refusal in the broker's logout words: %s", tr.cell())
	}
	var gone l56Run
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if gone = cli.run(t, kc, "identity", "--socket", cli.sock); strings.Contains(gone.stderr, "no agent") {
			break
		}
	}
	ran("5b. the agent after it", gone, "")
	if gone.code == 0 || !strings.Contains(gone.stderr, "no agent") {
		fail("the agent still answers after the sign-out: %s", gone.cell())
	}
	r = cli.run(t, kc, login...)
	ran("5c. port49 login over the logged-out certificate", r, "")
	if _, err := os.Stat(certPath); r.code != 1 || !strings.Contains(r.stderr, "it is removed") ||
		!errors.Is(err, fs.ErrNotExist) {
		fail("a login over the logged-out certificate: %s; the certificate still there %v", r.cell(), err == nil)
	}
	from, named := l56LoginFrom(tr.stderr)
	waited := "the time the broker named"
	if !named {
		from, waited = loginAgainAt(signedOut), "clock_skew after the sign-out"
	}
	time.Sleep(time.Until(from) + time.Second)
	browser.Jar, _ = cookiejar.New(nil) // the sign-out ended the browser's SSO session too
	r = cli.signIn(t, kc, browser, login...)
	cli.knowKey(t, kc)
	ran("5d. port49 login again, from "+waited, r, "")
	if r.code != 0 {
		t.Fatalf("INVALID: the sign-in after the sign-out failed, so step 6 has no session: %s", r.cell())
	}

	// 6. Keycloak stopped: everyone holding a certificate keeps working.
	if _, err := c.run("stop", "keycloak"); err != nil {
		t.Fatalf("INVALID: stopping Keycloak: %v", err)
	}
	tok, tr = cli.token(kc, l.p.node)
	ran("6a. port49 token, Keycloak stopped", tr, "")
	if tok == "" {
		fail("a mint with Keycloak stopped: %s", tr.cell())
	}
	time.Sleep(11 * time.Second)
	r = cli.run(t, kc, "refresh", "--socket", cli.sock)
	ran("6b. port49 refresh, Keycloak stopped", r, "")
	if r.code != 0 || !strings.Contains(r.stdout, "extended to") {
		fail("a refresh with Keycloak stopped: %s", r.cell())
	}
	cli.stopAgentAndWait(t)
	r = cli.run(t, kc, login...)
	ran("6c. port49 login after the agent stopped, Keycloak stopped", r, "")
	if tok, tr = cli.token(kc, l.p.node); r.code != 0 || tok == "" {
		fail("a new agent with Keycloak stopped: %s; then %s", r.cell(), tr.cell())
	}
	cli.stopAgentAndWait(t)
	r = cli.run(t, kc, append([]string{"login", "--sign-in"}, cli.flags...)...)
	ran("6d. port49 login --sign-in, Keycloak stopped", r, "")
	if r.code != 1 || !strings.Contains(r.stderr, "did not answer") ||
		!strings.Contains(r.stderr, "without --sign-in uses it") {
		fail("a sign-in with Keycloak stopped: %s", r.cell())
	}
	if _, err := c.run("start", "keycloak"); err != nil {
		t.Fatalf("INVALID: starting Keycloak: %v", err)
	}
	waitDiscovery(t, kc, 3*time.Minute)
	complete = true
}
