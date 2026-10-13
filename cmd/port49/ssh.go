package main

import (
	"bufio"
	"cmp"
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

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
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
// device's prompt from a jump host's. 8.5 names it. Host keys are the
// operator's OpenSSH's own (decision 46 ruling 2); plan 9d's gate G1 measured
// accept-new against a key of another type under a known alias
// (tests/ssh-compat/2026-10-13-openssh-accept-new.md).
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
	config, device, address, username string
	trust                             sshTrust
	port                              int
	verbose                           bool
	command                           []string
}

// sshTrust is what port49 ssh passes about host keys (decision 46 ruling 2).
type sshTrust struct {
	alias   string // HostKeyAlias to pass; "" when the operator's own stands
	keyName string // the name the device's keys are filed under: alias, or the operator's own
	strict  string // StrictHostKeyChecking: "yes" or "accept-new", never "no"
}

var validSSHName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// sshName reports whether device can be an ssh destination and a known_hosts
// host field as written (decision 42 ruling 8; decision 46 ruling 3): letters,
// digits, '.', '_' and '-', starting with a letter or a digit, 253 at most.
// known_hosts reads '*', '?', '!', ',' and '[' as patterns, and a leading '@'
// or '|' as a marker or a hash, so a name holding one could be filed for
// other devices.
func sshName(device string) bool { return validSSHName.MatchString(device) }

// shellWord quotes s for a shell when it holds anything but characters a
// shell leaves alone, so a hint can be pasted.
func shellWord(s string) string {
	plain := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_./:@%+=,-…", r)) {
			plain = false
		}
	}
	if plain {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sshValue is v as an -o value ssh reads back as v: each '%' doubled, since
// ssh expands %-tokens in HostName (an IPv6 zone's "%eth0" would be
// refused), and the whole double-quoted, since ssh splits a value on
// whitespace. A value holding '"' cannot be written so; sshCmd refuses one
// first.
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
	opts := []string{"HostName=" + sshValue(o.address)}
	if o.trust.alias != "" {
		opts = append(opts, "HostKeyAlias="+o.trust.alias)
	}
	opts = append(opts,
		"StrictHostKeyChecking="+o.trust.strict,
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
	)
	for _, opt := range opts {
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

// sshPolicy asks the operator's OpenSSH what its ssh_config makes of this
// connection (`ssh -G`: OpenSSH's own reading of it, Match blocks
// included), and returns what port49 ssh passes about host keys (decision 46
// ruling 2). The operator's StrictHostKeyChecking yes stands, and every other
// value is accept-new, never no; the operator's HostKeyAlias stands, and
// otherwise the alias is the device's name, lowercased as ssh files it.
// Under accept-new, a UserKnownHostsFile that keeps nothing (/dev/null, none)
// is refused: every connection would be a first contact, accepted silently.
// Nothing about trust is decided here that OpenSSH does not decide itself.
func sshPolicy(ctx context.Context, bin string, o sshOptions) (sshTrust, error) {
	args := []string{"-G"}
	if o.config != "" {
		args = append(args, "-F", o.config)
	}
	args = append(args, "-o", "HostName="+sshValue(o.address), "-l", o.username)
	if o.port != 0 {
		args = append(args, "-p", strconv.Itoa(o.port))
	}
	args = append(args, "--", o.device)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, bin, args...)
	// A descendant holding ssh -G's stderr cannot keep port49 ssh waiting
	// past ssh itself (pre-flight I2).
	c.WaitDelay = time.Second
	out, err := c.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			err = fmt.Errorf("%v: %s", err, printsafe.Line(strings.TrimSpace(string(ee.Stderr)), 300))
		}
		return sshTrust{}, fmt.Errorf("%s -G (reading your ssh_config for %s): %v", bin, o.device, err)
	}
	t := sshTrust{alias: strings.ToLower(o.device), keyName: strings.ToLower(o.device), strict: "accept-new"}
	var userFiles string
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "hostkeyalias":
			t.alias, t.keyName = "", printsafe.Line(v, 253)
		case "stricthostkeychecking":
			if v == "true" || v == "yes" {
				t.strict = "yes"
			}
		case "userknownhostsfile":
			userFiles = v
		}
	}
	if t.strict != "yes" {
		if why := knownHostsCannotKeep(userFiles); why != "" {
			return sshTrust{}, fmt.Errorf("your ssh_config keeps no host keys for %s (UserKnownHostsFile %s%s): every "+
				"connection would be a first contact, and a host at the device's address would get the token; point "+
				"the first UserKnownHostsFile for port49 devices at a file you can write, or set StrictHostKeyChecking "+
				"yes with a managed GlobalKnownHostsFile",
				o.device, printsafe.Line(cmp.Or(userFiles, "none"), 200), why)
		}
	}
	return t, nil
}

// knownHostsCannotKeep is why the first of userFiles (ssh -G's
// userknownhostsfile, already expanded) cannot keep the key accept-new files
// on a first contact, or "". Accept-new writes to the first file only, and
// connects anyway when it cannot write, so what matters is the file that
// first name resolves to, not how the setting is spelled: it must be a regular
// file the user can write, or one that does not exist yet in a directory the
// user can write (ssh creates the file, and ~/.ssh itself, but no other
// directory). A device node (/dev/null, however written or linked), a missing
// directory, a dangling link and an unwritable file keep nothing (decision 46
// ruling 2; task 3 review C1).
func knownHostsCannotKeep(userFiles string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(userFiles), " ")
	if first == "" || first == "none" {
		return ": it names no file"
	}
	home, _ := os.UserHomeDir()
	if rest, ok := strings.CutPrefix(first, "~/"); ok && home != "" {
		first = filepath.Join(home, rest)
	}
	at := func(resolved string) string {
		if resolved == first {
			return ""
		}
		return ", which is " + printsafe.Line(resolved, 200)
	}
	resolved, err := filepath.EvalSymlinks(first)
	if err == nil {
		fi, err := os.Stat(resolved)
		switch {
		case err != nil:
			return at(resolved) + ": " + unprefixed(err)
		case !fi.Mode().IsRegular():
			return at(resolved) + ": that is not a regular file"
		case unix.Access(resolved, unix.W_OK) != nil:
			return at(resolved) + ": you cannot write it"
		}
		return ""
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ": " + unprefixed(err)
	}
	if _, err := os.Lstat(first); err == nil {
		return ": it is a link to nothing"
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(first))
	if err != nil {
		// ssh makes ~/.ssh when it files the first key, if it can write the home directory.
		if home != "" && filepath.Dir(first) == filepath.Join(home, ".ssh") && unix.Access(home, unix.W_OK) == nil {
			return ""
		}
		return ": its directory does not exist"
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || unix.Access(dir, unix.W_OK|unix.X_OK) != nil {
		return at(filepath.Join(dir, filepath.Base(first))) + ": you cannot create it in " + printsafe.Line(dir, 200)
	}
	return ""
}

// legacyPinsHint says, while plan 9a's pins file exists, that port49 no
// longer reads it, and how to keep the keys in it (decision 46 ruling 5). It
// is found by Lstat alone and never opened, so a pins file or a ~/.config
// others can write stops nothing.
func legacyPinsHint(stderr io.Writer) {
	p := userconfig.LegacyPinsPath()
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return
	}
	fmt.Fprintf(stderr, "port49 ssh: %s holds keys `port49 devices trust` pinned (plan 9a); port49 no longer reads it, "+
		"and uses your OpenSSH known_hosts. Its lines are filed under the device names port49 ssh uses, so to keep "+
		"keys you verified: check they are yours, then `cat %s >> ~/.ssh/known_hosts`, and remove it\n",
		p, shellWord(p))
}

// ownPrompt reports whether prompt is ssh asking for the device's own
// password: "<user>@<device>'s password: " for the password method,
// "(<user>@<device>) <the device's text>" for keyboard-interactive, where
// <device> is the HostKeyAlias (OpenSSH 8.5p1, 8.9p1 and 10.2p1, measured
// for plan 9a; §15 L54 per platform). A jump host's prompt names the jump
// host. ssh lowercases the alias in a prompt and keeps the username's case, so
// the device is compared folded and the username exact. Under an operator's
// own HostKeyAlias the prompt names that alias (decision 46 ruling 2), so the
// askpass asks both names.
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
// fresh mint's token from remint, or not at all (pre-flight I-3). The token
// goes only to an asker whose parent is the ssh port49 started: a ProxyJump
// hop's askpass has the hop's ssh for a parent (pre-flight N3). The check is
// not a boundary against code of the operator's own: any direct child of the
// ssh port49 started (a ProxyCommand program, LocalCommand, KnownHostsCommand,
// a Match exec) inherits SSH_ASKPASS and the socket and passes it, and the
// same uid can already ask the agent for a token (task 3 review M3).
type askpassServer struct {
	ln               net.Listener
	token            string
	username, device string
	keyName          string                      // the HostKeyAlias ssh names in its prompt (decision 46 ruling 2)
	askerParent      func(net.Conn) (int, error) // see askerParent; nil only where a test builds the server by hand
	expiresAt        time.Time                   // the token's expires_at; zero when the broker gave none
	remint           func() (api.MintItem, error)

	mu         sync.Mutex
	served     bool
	repeated   bool
	expired    string    // why a device prompt that came too late got no token
	askedAt    time.Time // when that prompt came
	sshPid     int       // the ssh port49 started; set under mu by setSSHPid
	unverified string    // why an asker's parent could not be read
	kill       func()
}

// setSSHPid sets the pid of the ssh port49 started, the one parent whose
// askpass is answered the token.
func (s *askpassServer) setSSHPid(pid int) {
	s.mu.Lock()
	s.sshPid = pid
	s.mu.Unlock()
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

// unverifiedAsker is why a device prompt's asker could not be told from a
// hop's, or "".
func (s *askpassServer) unverifiedAsker() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unverified
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
	own := ownPrompt(prompt, s.username, s.device) || ownPrompt(prompt, s.username, s.keyName)
	if own && s.askerParent != nil {
		ppid, err := s.askerParent(c)
		switch {
		case err != nil:
			// Fail closed: the prompt may be the device's, and nothing says which ssh asked.
			s.unverified = err.Error()
			s.refuse(c)
			return
		case ppid != s.sshPid:
			// A ProxyJump hop's askpass: its parent is the hop's ssh, never the one started here.
			_, _ = io.WriteString(c, "N\n")
			return
		}
	}
	switch {
	case !own:
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
	knownHosts := fs.String("known-hosts", "", "removed in plan 9d: port49 ssh uses your OpenSSH known_hosts")
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
	if !sshName(device) {
		fmt.Fprintf(stderr, "%s: %q: port49 ssh takes devices named with letters, digits, '.', '_' and '-' only "+
			"(decision 42 ruling 8); use `port49 token` and your own ssh for it\n", cmd, device)
		return 2
	}
	if *knownHosts != "" {
		fmt.Fprintf(stderr, "%s: --known-hosts named port49's own pins file, which plan 9d removed: port49 ssh uses "+
			"your OpenSSH known_hosts. Name another with UserKnownHostsFile in an ssh_config (--ssh-config FILE)\n", cmd)
		return 2
	}
	legacyPinsHint(stderr)
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
	opts := sshOptions{config: *sshConfig, device: device, address: item.Address, username: item.Username,
		port: *port, verbose: *verbose, command: command}
	if opts.trust, err = sshPolicy(context.Background(), path, opts); err != nil {
		fmt.Fprintf(stderr, "%s: %v; nothing was sent to %s\n", cmd, err, device)
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
	srv := &askpassServer{ln: ln, token: item.Login, username: item.Username, device: device,
		keyName: opts.trust.keyName, askerParent: askerParent, expiresAt: expiresAt,
		remint: func() (api.MintItem, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return mint(ctx)
		}}

	c := exec.Command(path, sshArgs(opts)...)
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
	srv.setSSHPid(c.Process.Pid)
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
	switch unverified := srv.unverifiedAsker(); {
	case unverified != "":
		// Fail closed: the device's prompt came from a process whose parent could not
		// be read, so it might have been a ProxyJump hop's (pre-flight N3).
		fmt.Fprintf(stderr, "%s: could not tell which process asked for the token (%s), so it was not sent and "+
			"ssh was ended\n", cmd, printsafe.Line(unverified, 200))
		return 255
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
	case code == 255 && opts.trust.strict == "yes":
		fmt.Fprintf(stderr, "%s: ssh stopped before %s asked for the token, so it was never sent (ssh exit 255, "+
			"its message is above). Your ssh_config says StrictHostKeyChecking yes: if ssh says no host key is known, "+
			"no key is filed under %s, so add the device's key to your known_hosts after checking it on its console; "+
			"if it says the key changed, the key filed under %s is not the one %s presents, so verify it on the "+
			"console and run ssh-keygen -R %s and connect again\n",
			cmd, device, opts.trust.keyName, opts.trust.keyName, item.Address, shellWord(opts.trust.keyName))
	case code == 255:
		fmt.Fprintf(stderr, "%s: ssh stopped before %s asked for the token, so it was never sent (ssh exit 255, "+
			"its message is above). If it says Host key verification failed, the key your known_hosts files under "+
			"%s is not the one %s presents: either the device's key changed, or the address inventory gives for %s "+
			"is not the device. Verify the key on its console, then run ssh-keygen -R %s and connect again\n",
			cmd, device, opts.trust.keyName, item.Address, device, shellWord(opts.trust.keyName))
	}
	return code
}
