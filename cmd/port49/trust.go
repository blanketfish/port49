package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/hostkeys"
)

// trustScan reads a device's host key; a test swaps it.
var trustScan = hostkeys.Scan

// trustIsTerminal and trustAnswer are the operator's terminal; tests swap
// them.
var (
	trustIsTerminal           = func() bool { return isTerminal(os.Stdin) }
	trustAnswer     io.Reader = os.Stdin
)

// trustTTL is the lifetime trust asks for the token whose mint gives it the
// address: the token is never used, and expires at it (decision 42 ruling 9).
const trustTTL = 60 * time.Second

// devicesTrust is `port49 devices trust` (design §17; decision 42 rulings
// 7–9): it reads the host key a device presents and pins it under the
// device's inventory name, only against a fingerprint the operator verified
// or a yes typed at a terminal.
func devicesTrust(args []string, stdout, stderr io.Writer) int {
	const cmd = "port49 devices trust"
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fingerprint := fs.String("fingerprint", "", "the SHA256:... fingerprint you read on the device's console; "+
		"the key is pinned only if the device presents it")
	address := fs.String("address", "", "the device's address, when you know it; otherwise one mint through "+
		"your agent asks the broker")
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
	pinned, err := hostkeys.Lookup(*knownHosts, device)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	if len(pinned) > 0 && !*replace {
		fmt.Fprintf(stderr, "%s: %s is already pinned (%s); pass --replace to pin another key, once you have "+
			"verified the device's new key on its console\n", cmd, device, hostkeys.Fingerprint(pinned[0]))
		return 1
	}
	addr := *address
	if addr == "" {
		item, err := agent.NewClient(*socket).Token(context.Background(),
			agent.TokenRequest{Device: device, TTLSeconds: int(trustTTL / time.Second)})
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
		return 1
	}
	fp := hostkeys.Fingerprint(key)
	fmt.Fprintf(stdout, "%s at %s presents %s %s\n", device, target, key.Type(), fp)
	switch {
	case *fingerprint != "" && *fingerprint != fp:
		fmt.Fprintf(stderr, "%s: %s presents %s, not the %s you verified: nothing pinned; the address inventory "+
			"gives may not be %s's, so check inventory's address for %s before anything else\n", cmd, device, fp,
			*fingerprint, device, device)
		return 1
	case *fingerprint == "" && !trustIsTerminal():
		fmt.Fprintf(stderr, "%s: nothing pinned: pass --fingerprint with the fingerprint you read on %s's console; "+
			"a key is never pinned unseen (design §17)\n", cmd, device)
		return 2
	case *fingerprint == "":
		fmt.Fprintf(stdout, "Compare it with the key %s's console shows. Pin it? [yes/no]: ", device)
		line, _ := bufio.NewReader(trustAnswer).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			fmt.Fprintf(stderr, "%s: nothing pinned\n", cmd)
			return 1
		}
	}
	if err := hostkeys.Pin(*knownHosts, device, key, *replace); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	fmt.Fprintf(stdout, "pinned %s %s for %s in %s\n", key.Type(), fp, device, *knownHosts)
	return 0
}
