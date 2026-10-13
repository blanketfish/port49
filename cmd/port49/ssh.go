package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hostkeys"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/userconfig"
)

// askpassEnv names the socket `port49 ssh` answers its token on. ssh runs
// port49 itself as SSH_ASKPASS, with this set, for each prompt it would
// otherwise read from the terminal (decision 42 ruling 10).
const askpassEnv = "PORT49_ASKPASS"

// askpassCall reports whether ssh ran this port49 as `port49 ssh`'s askpass,
// and the socket to ask: askpassEnv names it, SSH_ASKPASS_REQUIRE is force,
// and the one argument is ssh's prompt. A port49 that ssh's children run
// otherwise (a ProxyCommand, a Match exec) inherits askpassEnv but, given two
// or more arguments, is not one (decision 42 ruling 10). Given one under the
// askpass environment it is taken as one, and the token still never moves,
// because that prompt is not the device's.
func askpassCall(args []string) (string, bool) {
	sock := os.Getenv(askpassEnv)
	return sock, sock != "" && os.Getenv("SSH_ASKPASS_REQUIRE") == "force" && len(args) == 1
}

// minSSH is the oldest OpenSSH port49 ssh runs (decision 42 ruling 10,
// measured in tests/ssh-compat/2026-10-09-openssh-askpass.md). 8.0 to 8.3
// ignore SSH_ASKPASS_REQUIRE=force and take the terminal's prompt; 8.4, and
// the no-terminal route on the others, pass a keyboard-interactive prompt as
// the server's bare text, naming no host, so the askpass could not tell the
// device's prompt from a jump host's. 8.5 names it. 8.5 is also the first
// with KnownHostsCommand, which port49 ssh turns off.
var minSSH = [2]int{8, 5}

// maxPrompt bounds a prompt the askpass relays: ssh's own text and a
// device's keyboard-interactive one.
const maxPrompt = 4 << 10

// askpassMargin is how long before the token's expires_at the device's prompt
// must come for the token to be sent: the time to reach the device, and for
// it to ask port49d, which refuses a token past it.
const askpassMargin = 5 * time.Second

var sshVersionRE = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

// sshVersion is bin's OpenSSH major and minor version, from `ssh -V`.
func sshVersion(bin string) ([2]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-V").CombinedOutput()
	m := sshVersionRE.FindSubmatch(out)
	if m == nil {
		if err != nil {
			return [2]int{}, fmt.Errorf("%s -V: %v", bin, err)
		}
		return [2]int{}, fmt.Errorf("%s -V names no OpenSSH version: %s", bin, printsafe.Line(string(out), 200))
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	return [2]int{major, minor}, nil
}

// atLeast reports whether version v is floor or later.
func atLeast(v, floor [2]int) bool { return v[0] > floor[0] || v[0] == floor[0] && v[1] >= floor[1] }

// sshOptions is one ssh run's command line.
type sshOptions struct {
	config, knownHosts, device, address, username string
	port                                          int
	verbose                                       bool
	command                                       []string
}

// sshValue is v as an -o value ssh reads back as v: each '%' doubled, since
// ssh expands %-tokens in HostName and UserKnownHostsFile (an IPv6 zone's
// "%eth0" would be refused), and the whole double-quoted, since ssh splits a
// value on whitespace. A value holding '"' cannot be written so; sshCmd
// refuses one first.
func sshValue(v string) string { return `"` + strings.ReplaceAll(v, "%", "%%") + `"` }

// sshArgs is ssh's command line (decision 42 ruling 10). Every -o here comes
// before the operator's ssh_config is read, and ssh takes an option's first
// value, so none of them can be undone there; the rest of ssh_config
// (ProxyJump, algorithms, User for a jump host) applies as usual.
func sshArgs(o sshOptions) []string {
	var a []string
	if o.config != "" {
		a = append(a, "-F", o.config)
	}
	for _, opt := range []string{
		"HostName=" + sshValue(o.address),
		"HostKeyAlias=" + o.device,
		"UserKnownHostsFile=" + sshValue(o.knownHosts),
		"GlobalKnownHostsFile=/dev/null",
		"StrictHostKeyChecking=yes",
		"UpdateHostKeys=no",
		"CheckHostIP=no",
		"VerifyHostKeyDNS=no",
		"KnownHostsCommand=none",
		// L51: every key offered and refused counts against the device's
		// authentication-attempt limit, and an IOS-XE login block-for
		// locks the source address out.
		"PubkeyAuthentication=no",
		"PreferredAuthentications=keyboard-interactive,password",
		"KbdInteractiveAuthentication=yes",
		"PasswordAuthentication=yes",
		"NumberOfPasswordPrompts=1",
		"BatchMode=no",
		"ControlMaster=no",
		"ControlPath=none",
		"ForwardAgent=no",
	} {
		a = append(a, "-o", opt)
	}
	if o.verbose {
		a = append(a, "-v")
	}
	a = append(a, "-l", o.username)
	if o.port != 0 {
		a = append(a, "-p", strconv.Itoa(o.port))
	}
	a = append(a, "--", o.device)
	return append(a, o.command...)
}

// ownPrompt reports whether prompt is ssh asking for the device's own
// password: "<user>@<device>'s password: " for the password method,
// "(<user>@<device>) <the device's text>" for keyboard-interactive, where
// <device> is the HostKeyAlias (OpenSSH 8.5p1, 8.9p1 and 10.2p1, measured
// for plan 9a; §15 L54 per platform). A jump host's prompt names the jump
// host. ssh lowercases the alias in a prompt and keeps the username's case, so
// the device is compared folded and the username exact.
func ownPrompt(prompt, username, device string) bool {
	who := username + "@" + strings.ToLower(device)
	return prompt == who+"'s password: " || strings.HasPrefix(prompt, "("+who+") ")
}

// askpassServer answers ssh's askpass for one `port49 ssh`: the token, once,
// to the device's own prompt; "not ours" to any other, so the askpass asks
// the terminal as ssh would have; and, to the device's prompt asked again,
// nothing, after kill has ended ssh, so the token is presented once and no
// second or empty password follows it. A device prompt that comes when the
// token is within askpassMargin of expiresAt, or past it, is answered with a
// fresh mint's token from remint, or not at all (pre-flight I-3).
type askpassServer struct {
	ln               net.Listener
	token            string
	username, device string
	expiresAt        time.Time // the token's expires_at; zero when the broker gave none
	remint           func() (api.MintItem, error)

	mu       sync.Mutex
	served   bool
	repeated bool
	expired  string    // why a device prompt that came too late got no token
	askedAt  time.Time // when that prompt came
	kill     func()
}

// setKill sets what ends ssh before a refusal is answered: OpenSSH's
// read_passphrase sends an empty password for an askpass that fails.
func (s *askpassServer) setKill(f func()) {
	s.mu.Lock()
	s.kill = f
	s.mu.Unlock()
}

// state is whether the token was served, whether the device's prompt came
// again, and, for a prompt that came after the token's expiry with no fresh
// token to send, why and when.
func (s *askpassServer) state() (served, repeated bool, expired string, askedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.served, s.repeated, s.expired, s.askedAt
}

// refuse ends ssh, then answers "X".
func (s *askpassServer) refuse(c net.Conn) {
	if s.kill != nil {
		s.kill()
	}
	_, _ = io.WriteString(c, "X\n")
}

// failClosed ends ssh when a prompt could not be read, parsed or fitted: it
// may have been the device's, and an askpass left without an answer makes ssh
// send an empty password.
func (s *askpassServer) failClosed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kill != nil {
		s.kill()
	}
}

// stale reports whether the token is too near its expires_at, or past it, to
// reach the device and be redeemed.
func (s *askpassServer) stale() bool {
	return !s.expiresAt.IsZero() && time.Until(s.expiresAt) < askpassMargin
}

// renew replaces a stale token with a fresh mint's, for the same username,
// and reports whether it did; when it did not, expired says why.
func (s *askpassServer) renew() bool {
	s.askedAt = time.Now()
	why := "no fresh one could be minted"
	if s.remint != nil {
		item, err := s.remint()
		switch {
		case err != nil:
			why = "a fresh mint failed: " + unprefixed(err)
		case item.Verdict != "permit" || item.Login == "":
			why = fmt.Sprintf("a fresh mint answered %s %s", item.Verdict, item.Reason)
		case item.Username != s.username:
			why = "a fresh mint names another username, " + printsafe.Line(item.Username, 64)
		default:
			s.token = item.Login
			s.expiresAt, _ = time.Parse(time.RFC3339, item.ExpiresAt)
			return true
		}
	}
	s.expired = why
	return false
}

func (s *askpassServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.answer(c)
	}
}

// answer reads one quoted prompt and writes "T <token>", "N" (not the
// device's) or "X" (the device's again, or the device's with no token fit to
// send).
func (s *askpassServer) answer(c net.Conn) {
	defer c.Close()
	// Room for a fresh mint (remint's own bound is 10s) before the reply.
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, maxPrompt)).ReadString('\n')
	if err == io.EOF && line == "" {
		// Not a prompt: every ask sends at least `""`. Another run's sweep
		// dials each askpass socket and hangs up, and must not end a live
		// session.
		return
	}
	if err != nil {
		s.failClosed()
		return
	}
	prompt, err := strconv.Unquote(strings.TrimSuffix(line, "\n"))
	if err != nil {
		s.failClosed()
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !ownPrompt(prompt, s.username, s.device):
		_, _ = io.WriteString(c, "N\n")
	case s.served:
		s.repeated = true
		s.refuse(c)
	case s.stale() && !s.renew():
		s.refuse(c)
	default:
		s.served = true
		_, _ = io.WriteString(c, "T "+s.token+"\n")
	}
}

// askpassMain is port49 run by ssh as SSH_ASKPASS (askpassEnv set): it asks
// `port49 ssh` for the answer to the one prompt ssh passes and prints it for
// ssh. A prompt that is not the device's own is asked of the terminal (a jump
// host's password). The device's prompt asked a second time is refused,
// exit 1.
//
// SSH_ASKPASS_PROMPT=none marks a notification, not a question: ssh shows it
// and later kills the askpass, and never reads an answer. It is written to
// the terminal and the askpass exits 0 at once, reading nothing, touching no
// echo and not asking `port49 ssh`.
func askpassMain(sock string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "port49 askpass: ssh runs this with one prompt; it is not a command to type")
		return 1
	}
	if os.Getenv("SSH_ASKPASS_PROMPT") == "none" {
		notifyTerminal(args[0], stderr)
		return 0
	}
	parent := watchParent()
	c, err := net.DialTimeout("unix", sock, 10*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "port49 askpass: port49 ssh is not answering at %s: %v\n", sock, err)
		endSSH(parent)
		return 1
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(25 * time.Second))
	if _, err := io.WriteString(c, strconv.Quote(args[0])+"\n"); err != nil {
		fmt.Fprintf(stderr, "port49 askpass: %v\n", err)
		endSSH(parent)
		return 1
	}
	reply, err := bufio.NewReader(io.LimitReader(c, 1<<10)).ReadString('\n')
	if err != nil {
		fmt.Fprintf(stderr, "port49 askpass: port49 ssh did not answer: %v\n", err)
		endSSH(parent)
		return 1
	}
	switch reply = strings.TrimSuffix(reply, "\n"); {
	case strings.HasPrefix(reply, "T "):
		fmt.Fprintln(stdout, strings.TrimPrefix(reply, "T "))
		return 0
	case reply == "N":
		return askTerminal(args[0], stdout, stderr)
	}
	fmt.Fprintf(stderr, "port49 askpass: not answering %q: port49 ssh presents its token once, to the device's "+
		"own prompt\n", printsafe.Line(args[0], 200))
	return 1
}

// terminalPrompt is prompt with each control character but newline made `?`:
// a jump host's keyboard-interactive text is the server's, and must not move
// the operator's terminal. The yes/no questions are several lines, so newlines
// stay.
func terminalPrompt(prompt string) string {
	lines := strings.Split(prompt, "\n")
	for i, l := range lines {
		lines[i] = printsafe.Line(l, maxPrompt)
	}
	return strings.Join(lines, "\n")
}

// terminateSSH ends the ssh that ran this askpass, held as parent from the
// askpass's start. OpenSSH's read_passphrase sends an empty password for an
// askpass that fails, so an askpass that cannot get its answer ends ssh
// instead of leaving it to send one. It signals nothing else: a parent that
// has since exited leaves this adopted by a process that is not ssh. A test
// swaps it.
var terminateSSH = func(parent sshParent) { parent.terminate() }

// endSSH is terminateSSH for a port49 that ssh ran as its askpass
// (SSH_ASKPASS_REQUIRE=force), and nothing for any other.
func endSSH(parent sshParent) {
	if os.Getenv("SSH_ASKPASS_REQUIRE") == "force" {
		terminateSSH(parent)
	}
}

// askEchoes reports whether the answer to prompt is shown as it is typed: a
// yes/no question, as ssh asks of a jump host's unknown key (it passes no hint
// for that one), or one ssh marks a confirmation (SSH_ASKPASS_PROMPT=confirm).
// Never a password.
func askEchoes(prompt, hint string) bool {
	return hint == "confirm" || strings.Contains(prompt, "(yes/no")
}

// notifyTerminal shows an askpass notification (SSH_ASKPASS_PROMPT=none) on
// the controlling terminal, or on stderr without one. A test swaps it.
var notifyTerminal = func(prompt string, stderr io.Writer) {
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		defer tty.Close()
		stderr = tty
	}
	fmt.Fprintln(stderr, printsafe.Line(prompt, maxPrompt))
}

// askTerminal asks the controlling terminal for the answer to prompt, as ssh
// would have without SSH_ASKPASS_REQUIRE: a jump host's password, with echo
// off, or a yes/no question, with echo on (askEchoes), typed by the
// operator. A test swaps it.
var askTerminal = func(prompt string, stdout, stderr io.Writer) int {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(stderr, "port49 askpass: answering %q needs a terminal: %v\n", printsafe.Line(prompt, 200), err)
		return 1
	}
	defer tty.Close()
	fmt.Fprint(tty, terminalPrompt(prompt))
	if askEchoes(prompt, os.Getenv("SSH_ASKPASS_PROMPT")) {
		line, err := bufio.NewReader(tty).ReadString('\n')
		if err != nil && line == "" {
			return 1
		}
		fmt.Fprintln(stdout, strings.TrimRight(line, "\r\n"))
		return 0
	}
	// ReadPassword restores the terminal only when it returns, and a signal
	// that ends this process first would leave echo off, as ssh's own
	// readpassphrase never does: trap them, restore, then go.
	fd := int(tty.Fd())
	saved, err := term.GetState(fd)
	if err != nil {
		return 1
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	type read struct {
		pw  []byte
		err error
	}
	got := make(chan read, 1)
	go func() {
		pw, err := term.ReadPassword(fd)
		got <- read{pw, err}
	}()
	select {
	case <-sigs:
		_ = term.Restore(fd, saved)
		fmt.Fprint(tty, "\r\n")
		return 1
	case r := <-got:
		fmt.Fprint(tty, "\r\n")
		if r.err != nil {
			return 1
		}
		fmt.Fprintln(stdout, string(r.pw))
		return 0
	}
}

// listenAskpass opens the askpass socket in the agent socket's directory.
// userconfig.PrivateDir resolves it top down, holding no links, but accepts a
// root-owned, a 0755 or a sticky world-writable directory; the agent's own
// check then requires exactly 0700 and this uid, on the resolved path. So the
// socket is never made where another user can reach it, which also closes the
// window between Listen and Chmod: whoever can reach the socket can already
// mint as this operator.
func listenAskpass(agentSocket string) (net.Listener, string, error) {
	dir, err := userconfig.PrivateDir(filepath.Dir(agentSocket), "askpass socket")
	if err != nil {
		return nil, "", err
	}
	if err := agent.PrivateDir(dir); err != nil {
		return nil, "", err
	}
	removeStaleAskpassSockets(dir)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "askpass-"+hex.EncodeToString(b[:])+".sock")
	if len(path) > 107 {
		return nil, "", fmt.Errorf("the askpass socket %s is too long for a Unix socket; pass a shorter --socket", path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, "", err
	}
	return ln, path, nil
}

// staleAge is how old an askpass socket is before the sweep may judge it
// stale: a run between Listen and its first Accept refuses a dial for a
// moment. A test sets it to 0.
var staleAge = 10 * time.Second

// removeStaleAskpassSockets removes the askpass sockets in dir that nothing
// listens on: a port49 ssh that was killed leaves its own behind. A socket
// older than staleAge whose dial is refused is stale; any other answer leaves
// it.
func removeStaleAskpassSockets(dir string) {
	old, _ := filepath.Glob(filepath.Join(dir, "askpass-*.sock"))
	for _, p := range old {
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSocket == 0 || time.Since(fi.ModTime()) < staleAge {
			continue
		}
		c, err := net.DialTimeout("unix", p, time.Second)
		if err == nil {
			c.Close()
			continue
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			_ = os.Remove(p)
		}
	}
}

// withoutAskpass is env with no SSH_ASKPASS, SSH_ASKPASS_REQUIRE,
// SSH_ASKPASS_PROMPT or askpassEnv of the caller's.
func withoutAskpass(env []string) []string {
	var out []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "SSH_ASKPASS=") || strings.HasPrefix(kv, "SSH_ASKPASS_REQUIRE=") ||
			strings.HasPrefix(kv, "SSH_ASKPASS_PROMPT=") || strings.HasPrefix(kv, askpassEnv+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// sshAfterFunc arms the in-session warning's timer; a test swaps it so no
// test waits on, or races, a real ceiling.
var sshAfterFunc = time.AfterFunc

// warnInSession writes the ceiling warning once, on the terminal ssh draws
// on, when the device's session comes within warn of its ceiling, and
// returns the func that stops it. None is armed when there is no ceiling, or
// when the moment has passed and the warning was said before ssh started
// (decision 42 ruling 11).
//
// When the moment comes it asks the agent first: a `port49 refresh` in
// another terminal may have moved the ceiling (§5.6), and then the warning
// waits for the new moment rather than name a ceiling that has moved
// (pre-flight I-2).
func warnInSession(stderr io.Writer, socket, device string, item api.MintItem, warn time.Duration) (stop func()) {
	exp, err := time.Parse(time.RFC3339, item.SessionExpiresAt)
	if err != nil || warn <= 0 || time.Until(exp.Add(-warn)) <= 0 {
		return func() {}
	}
	var mu sync.Mutex
	stopped := false
	var t *time.Timer
	var fire func()
	fire = func() {
		later, moved := refreshedCeiling(socket, device, item.Username)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case stopped:
		case moved && later.After(exp):
			exp = later
			t = sshAfterFunc(time.Until(exp.Add(-warn)), fire)
		default:
			fmt.Fprintf(stderr, "\r\nport49: your session on %s ends at %s (%s); run 'port49 refresh'\r\n", device,
				exp.UTC().Format(time.RFC3339), timeLeft(time.Until(exp)))
		}
	}
	mu.Lock()
	t = sshAfterFunc(time.Until(exp.Add(-warn)), fire)
	mu.Unlock()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		t.Stop()
	}
}

// refreshedCeiling is the device session's ceiling as the agent's last
// refresh extended it, if that refresh did and reached the device: what a
// `port49 refresh` in another terminal moved (decision 42 ruling 11). An
// agent that does not answer moves nothing, and the warning is said.
func refreshedCeiling(socket, device, username string) (time.Time, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := agent.NewClient(socket).Status(ctx)
	if err != nil {
		return time.Time{}, false
	}
	for _, s := range st.Sessions {
		if s.Device == device && s.Username == username && s.Outcome == "extended" && !s.Unreached {
			if at, err := time.Parse(time.RFC3339, s.SessionExpires); err == nil {
				return at, true
			}
		}
	}
	return time.Time{}, false
}

// exitCode is ssh's exit status; 255 for an ssh port49 ssh ended or that
// died by a signal, as ssh's own failures are.
func exitCode(err error) int {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		return ee.ExitCode()
	}
	return 255
}

// sshCmd is `port49 ssh` (design §17; decision 42 rulings 7, 10 and 11).
func sshCmd(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 ssh"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
	ttl := fs.Duration("ttl", 0, "ask for this token lifetime; the broker clamps it to your policy's token_ttl")
	port := fs.Int("port", 0, "the device's SSH port (default: ssh's, 22 unless your ssh_config says otherwise)")
	bin := fs.String("ssh", "ssh", "the OpenSSH client to run, 8.5 or later")
	sshConfig := fs.String("ssh-config", "", "an ssh_config to read in place of ~/.ssh/config (ssh -F)")
	knownHosts := fs.String("known-hosts", hostkeys.Path(), "the pinned host keys file")
	verbose := fs.Bool("v", false, "ssh -v: say each step of the connection and its authentication")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	device, command := fs.Arg(0), fs.Args()[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if !hostkeys.ValidName(device) {
		fmt.Fprintf(stderr, "%s: %q: port49 ssh takes devices named with letters, digits, '.', '_' and '-' only "+
			"(decision 42 ruling 8); use `port49 token` and your own ssh for it\n", cmd, device)
		return 2
	}
	if strings.ContainsAny(*knownHosts, "\"\n") {
		fmt.Fprintf(stderr, "%s: --known-hosts %q holds a '\"' or a newline, which ssh cannot be handed; "+
			"name the file by another path\n", cmd, *knownHosts)
		return 2
	}
	pinned, err := hostkeys.Lookup(*knownHosts, device)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if len(pinned) == 0 {
		fmt.Fprintf(stderr, "%s: no host key is pinned for %s: verify its key on its console and run '%s' "+
			"first; a key never seen is never accepted (design §17)\n", cmd, device,
			trustCommand(trustHint{knownHosts: *knownHosts, socket: *socket, port: *port}, device))
		return 1
	}
	path, err := exec.LookPath(*bin)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	v, err := sshVersion(path)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v; port49 ssh runs OpenSSH 8.5 or later. Run `port49 token %s` and your own ssh "+
			"instead\n", cmd, err, device)
		return 1
	}
	if !atLeast(v, minSSH) {
		fmt.Fprintf(stderr, "%s: %s is OpenSSH %d.%d; port49 ssh needs 8.5 or later, the first whose prompts name "+
			"the device they ask for. Run `port49 token %s` and your own ssh instead\n", cmd, path, v[0], v[1], device)
		return 1
	}
	req := agent.TokenRequest{Device: device, TTLSeconds: int(*ttl / time.Second)}
	// The first mint proves a requirement, if there is one (a touch or a
	// sign-in, at this terminal); a re-mint while ssh runs is the agent's
	// alone: it holds the terminal, and the proof is reused for reuse_for.
	mint := func(ctx context.Context) (api.MintItem, error) {
		return agent.NewClient(*socket).Token(ctx, req)
	}
	item, err := mintProved(context.Background(), proveFlags(*socket), req, stderr)
	mintedAt := time.Now()
	if mintFailed(cmd, *socket, device, item, err, stderr) {
		return 1
	}
	if item.Address == "" || item.Username == "" || strings.ContainsAny(item.Address, "\"\n") {
		fmt.Fprintf(stderr, "%s: the broker gives %s no address and username ssh can be handed; tell the operator\n",
			cmd, device)
		return 1
	}
	warn := ceilingWarning(*socket)
	warnNearCeiling(stderr, device, item, warn)
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	// The terminal sends ^C and ^\ to ssh too; port49 ssh outlives them to
	// report ssh's status. A TERM or HUP sent to port49 alone goes on to ssh.
	// Taken before the socket is made, so a ^C between the two leaves none.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	ln, sockPath, err := listenAskpass(*socket)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s\n", cmd, unprefixed(err))
		return 1
	}
	defer os.Remove(sockPath)
	defer ln.Close()
	expiresAt, _ := time.Parse(time.RFC3339, item.ExpiresAt)
	srv := &askpassServer{ln: ln, token: item.Login, username: item.Username, device: device, expiresAt: expiresAt,
		remint: func() (api.MintItem, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return mint(ctx)
		}}

	c := exec.Command(path, sshArgs(sshOptions{config: *sshConfig, knownHosts: *knownHosts, device: device,
		address: item.Address, username: item.Username, port: *port, verbose: *verbose, command: command})...)
	c.Env = append(withoutAskpass(os.Environ()), "SSH_ASKPASS="+askpassPath(self), "SSH_ASKPASS_REQUIRE=force",
		askpassEnv+"="+sockPath)
	// ssh's stderr is the caller's own: ssh acts on whether it is a terminal,
	// and no descendant holding it can keep this from returning.
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, stdout, stderr
	// An askpass or ssh that dies mid-read can leave echo off; the terminal is
	// put back as it was found once ssh has ended.
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		if saved, err := term.GetState(fd); err == nil {
			defer func() { _ = term.Restore(fd, saved) }()
		}
	}
	if err := c.Start(); err != nil {
		fmt.Fprintf(stderr, "%s: starting %s: %v\n", cmd, path, err)
		return 1
	}
	// Served only once the kill is set: an ask that comes before waits in
	// the listener's backlog, so no refusal is ever answered with ssh left
	// running to send an empty password.
	srv.setKill(func() { _ = c.Process.Kill() })
	go srv.serve()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGTERM || s == syscall.SIGHUP {
					_ = c.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	stopWarn := warnInSession(stderr, *socket, device, item, warn)
	err = c.Wait()
	stopWarn()
	code := exitCode(err)
	served, repeated, expired, askedAt := srv.state()
	switch {
	case expired != "":
		// A timing fault, never policy's: the device asked after the
		// token's expiry, as behind a slow jump host (pre-flight I-3).
		fmt.Fprintf(stderr, "%s: %s asked for the token %s after it was minted, past its expires_at (%s), and %s; "+
			"nothing was sent to %s, and ssh was ended. Run `port49 ssh %s` again; a slow jump host login is the "+
			"usual cause\n", cmd, device, askedAt.Sub(mintedAt).Round(time.Second), item.ExpiresAt, expired, device,
			device)
		return 255
	case repeated:
		fmt.Fprintf(stderr, "%s: %s asked for the password again after it was sent the token; port49 ssh ended the "+
			"connection, so no second or empty password reached it; `port49 explain --device %s` says whether "+
			"your policy permits you, and port49d's decision log says why the device refused\n", cmd, device, device)
		return 255
	case code == 255 && served:
		fmt.Fprintf(stderr, "%s: %s was sent the token and the connection failed (ssh exit 255, its message is "+
			"above); if it says Permission denied, `port49 explain --device %s` says whether your policy permits "+
			"you, and port49d's decision log says why the device refused\n", cmd, device, device)
	case code == 255:
		fmt.Fprintf(stderr, "%s: ssh stopped before %s asked for the token, so it was never sent (ssh exit 255, "+
			"its message is above); if ssh's message above says Host key verification failed, the address inventory "+
			"gives for %s may not be the device: verify the key on its console, then run '%s'\n", cmd, device, device,
			trustCommand(trustHint{knownHosts: *knownHosts, socket: *socket, port: *port, replace: true}, device))
	}
	return code
}
