package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/hostkeys"
	"github.com/rhwendt/port49/internal/userconfig"
)

// trustScan reads a device's host key; a test swaps it.
var trustScan = hostkeys.Scan

// The operator's terminal; tests swap these. A confirmation needs stdin and
// stderr (where the fingerprint and the prompt go) both on a terminal.
var (
	trustStdinIsTerminal  = func() bool { return isTerminal(os.Stdin) }
	trustStderrIsTerminal = func(w io.Writer) bool {
		f, ok := w.(*os.File)
		return ok && isTerminal(f)
	}
	trustAnswer io.Reader = os.Stdin
)

// trustTTL is the lifetime trust asks for the token whose mint gives it the
// address: the token is never used, and expires at it (decision 42 ruling 9).
const trustTTL = 60 * time.Second

// trustHint is the flags a hint that names a `port49 devices trust` follow-up
// repeats from the command that printed it.
type trustHint struct {
	knownHosts, socket, address, fingerprint string
	port                                     int // 0 when the command left it unset
	replace                                  bool
}

// trustCommand is the command a hint tells the operator to run for device. A
// flag appears only when it differs from its default, so the command runs
// against the same pins file, socket, address and port as the one that printed
// it, and reads plainly when nothing differs.
func trustCommand(h trustHint, device string) string {
	parts := []string{"port49 devices trust"}
	if h.knownHosts != "" && h.knownHosts != hostkeys.Path() {
		parts = append(parts, "--known-hosts", shellWord(h.knownHosts))
	}
	if h.socket != "" && h.socket != agent.SocketPath() {
		parts = append(parts, "--socket", shellWord(h.socket))
	}
	if h.address != "" {
		parts = append(parts, "--address", shellWord(h.address))
	}
	if h.port != 0 && h.port != 22 {
		parts = append(parts, "--port", strconv.Itoa(h.port))
	}
	if h.fingerprint != "" {
		parts = append(parts, "--fingerprint", shellWord(h.fingerprint))
	}
	if h.replace {
		parts = append(parts, "--replace")
	}
	return strings.Join(append(parts, device), " ")
}

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

// forwardAdvice is what a scan that could not dial adds: trust connects
// directly, so a device behind a jump host is scanned through a forwarded
// port. The pin is keyed by the inventory name and authorized by the
// fingerprint the operator verified, so the forward cannot substitute a key.
func forwardAdvice(h trustHint, device, target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "22"
	}
	h.address, h.port = "127.0.0.1", 2222
	if h.fingerprint == "" {
		h.fingerprint = "SHA256:…"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("port49 devices trust connects directly, not through your ssh_config's ProxyJump or Port. "+
		"Through a jump host, forward a port (`ssh -N -L 2222:%s:%s <jump>`), then run `%s`", host, port,
		trustCommand(h, device))
}

// devicesTrust is `port49 devices trust` (design §17; decision 42 rulings
// 7–9): it reads the host key a device presents and pins it under the
// device's inventory name, only against a fingerprint the operator verified
// or a yes typed at a terminal.
func devicesTrust(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 devices trust"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fingerprint := fs.String("fingerprint", "", "the SHA256:... fingerprint of the key you verified on the "+
		"device's console (NX-OS prints it; the others print the key itself, so run `ssh-keygen -lf` on it); "+
		"the key is pinned only if the device presents it")
	address := fs.String("address", "", "the device's address, when you know it; otherwise one mint through "+
		"your agent asks the broker. trust connects directly, not through your ssh_config's ProxyJump or Port: "+
		"through a jump host, forward a port (`ssh -N -L 2222:<addr>:22 <jump>`), then run `port49 devices "+
		"trust --address 127.0.0.1 --port 2222 --fingerprint SHA256:… <device>`")
	port := fs.Int("port", 22, "the device's SSH port")
	replace := fs.Bool("replace", false, "replace the device's pinned key, once you have verified its new key "+
		"on its console")
	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
	knownHosts := fs.String("known-hosts", hostkeys.Path(), "the pinned host keys file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	device := fs.Arg(0)
	if !hostkeys.ValidName(device) {
		fmt.Fprintf(stderr, "%s: %q: port49 pins devices named with letters, digits, '.', '_' and '-' only, "+
			"since known_hosts reads other characters as patterns (decision 42 ruling 8); port49 token still "+
			"serves it\n", cmd, device)
		return 2
	}
	if *fingerprint != "" && !strings.HasPrefix(*fingerprint, "SHA256:") {
		fmt.Fprintf(stderr, "%s: --fingerprint %q is not in the SHA256:... form: give the SHA256:… form "+
			"`ssh-keygen -lf` prints, not an MD5 or hex one\n", cmd, *fingerprint)
		return 2
	}
	hint := trustHint{knownHosts: *knownHosts, socket: *socket, address: *address, port: *port,
		replace: true}
	pinned, err := hostkeys.Entries(*knownHosts, device)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if len(pinned) > 0 && !*replace {
		replaceCmd := trustCommand(hint, device)
		old := pinned[0]
		if old.Name != device {
			fmt.Fprintf(stderr, "%s: %s differs from %s, pinned on line %d of %s (%s), only in case; OpenSSH treats "+
				"the two as one host, so port49 will not pin a second key. To replace that pin, once you have verified "+
				"the device's key on its console: %s\n", cmd, device, old.Name, old.Line, *knownHosts,
				hostkeys.Fingerprint(old.Key), replaceCmd)
			return 1
		}
		fmt.Fprintf(stderr, "%s: %s is already pinned (%s); to pin another key, once you have verified the "+
			"device's new key on its console: %s\n", cmd, device, hostkeys.Fingerprint(old.Key), replaceCmd)
		return 1
	}
	// A pins directory port49 would refuse is refused here, before a mint and
	// a scan that the operator would answer yes to for nothing.
	if _, err := userconfig.PrivateDir(filepath.Dir(*knownHosts), "pinned host keys file"); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	addr := *address
	if addr == "" {
		item, err := mintProved(context.Background(), proveFlags(*socket),
			agent.TokenRequest{Device: device, TTLSeconds: int(trustTTL / time.Second)}, stderr)
		if mintFailed(cmd, *socket, device, item, err, stderr) {
			return 1
		}
		if addr = item.Address; addr == "" {
			fmt.Fprintf(stderr, "%s: inventory gives %s no address; pass --address\n", cmd, device)
			return 1
		}
	}
	target := net.JoinHostPort(addr, strconv.Itoa(*port))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key, err := trustScan(ctx, target)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s: %v\n", cmd, device, err)
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			advice := hint
			advice.fingerprint, advice.replace = *fingerprint, *replace
			fmt.Fprintf(stderr, "%s.\n", forwardAdvice(advice, device, target))
		}
		return 1
	}
	fp := hostkeys.Fingerprint(key)
	// The fingerprint and the prompt are stderr's, the result stdout's, so a
	// redirected stdout never hides what the operator is asked to confirm.
	fmt.Fprintf(stderr, "%s at %s presents %s %s\n", device, target, key.Type(), fp)
	// What replacing would do is said once the fingerprint check has passed,
	// and as a proposal: a refusal after it would have claimed a replacement.
	propose := func() {
		if len(pinned) == 0 {
			return
		}
		old := make([]string, len(pinned))
		for i, p := range pinned {
			old[i] = hostkeys.Fingerprint(p.Key)
		}
		fmt.Fprintf(stderr, "%s's pins: %s; the new key %s would replace them\n", device, strings.Join(old, ", "), fp)
	}
	switch {
	case *fingerprint != "" && *fingerprint != fp:
		fmt.Fprintf(stderr, "%s: %s presents %s, not the %s you verified: nothing pinned; the address inventory "+
			"gives may not be %s's, so check inventory's address for %s before anything else\n", cmd, device, fp,
			*fingerprint, device, device)
		return 1
	case *fingerprint == "" && !(trustStdinIsTerminal() && trustStderrIsTerminal(stderr)):
		fmt.Fprintf(stderr, "%s: nothing pinned: pass --fingerprint with the SHA256:... fingerprint of the key %s's "+
			"console shows (NX-OS prints the fingerprint; the other platforms print the key itself, so run "+
			"`ssh-keygen -lf` on it); a key is never pinned unseen (design §17)\n", cmd, device)
		return 2
	case *fingerprint == "":
		propose()
		fmt.Fprintf(stderr, "Compare it with the key %s's console shows. Pin it? [yes/no]: ", device)
		line, _ := bufio.NewReader(trustAnswer).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			fmt.Fprintf(stderr, "%s: nothing pinned\n", cmd)
			return 1
		}
	default:
		propose()
	}
	if err := hostkeys.Pin(*knownHosts, device, key, *replace); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	fmt.Fprintf(stdout, "pinned %s %s for %s in %s\n", key.Type(), fp, device, *knownHosts)
	return 0
}
