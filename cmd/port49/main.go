// Command port49 is the operator's CLI (design §17, "Client libraries"; §19
// step 3). `port49 login` starts the agent that holds the session — one
// mutual-TLS connection to the broker — and `port49 token DEVICE` mints
// through it, fresh every time. The policy tools of spec §12 (`explain`,
// `policy test`, `policy replay`, `access review`, `grants remove`) read a
// policy file and an inventory file offline and need no broker. Plan 9 builds
// the rest: `port49 ssh` with host-key verification, the OIDC client, and a
// key held on a hardware token.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/keyfile"
)

const usage = `usage:
  port49 login --broker URL --cert FILE --key FILE --broker-ca FILE [--socket PATH]
  port49 token [--enable] [--ttl DURATION] [--json] [--socket PATH] DEVICE
  port49 explain --policy FILE --inventory FILE (--subject NAME | --principal ID) --device NAME
                 [--command "LINE"] [--show-attributes]
  port49 policy test --policy FILE --inventory FILE
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "login":
		return login(args[1:], stdout, stderr)
	case "token":
		return tokenCmd(args[1:], stdout, stderr)
	case "agent":
		// What login starts; not for typing.
		return agentMain(args[1:], stderr)
	case "explain":
		return explainCmd(args[1:], stdout, stderr)
	case "policy":
		return policyCmd(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// sessionFlags are what the agent needs to open the session. The key is read
// from a file: BORROWED AHEAD from plan 9, which holds it on a hardware token
// (design §7; plan 3, Question 1).
type sessionFlags struct{ broker, cert, key, brokerCA, socket string }

func (s *sessionFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.broker, "broker", "", "the broker, https://host:port")
	fs.StringVar(&s.cert, "cert", "", "your client certificate (PEM)")
	fs.StringVar(&s.key, "key", "", "its private key (PEM)")
	fs.StringVar(&s.brokerCA, "broker-ca", "", "the CA that issued the broker's certificate (PEM)")
	fs.StringVar(&s.socket, "socket", agent.SocketPath(), "the agent's socket")
}

func (s *sessionFlags) args() []string {
	return []string{"--broker", s.broker, "--cert", s.cert, "--key", s.key, "--broker-ca", s.brokerCA, "--socket", s.socket}
}

func (s *sessionFlags) config(log io.Writer) (agent.Config, error) {
	if s.broker == "" || s.cert == "" || s.key == "" {
		return agent.Config{}, errors.New("--broker, --cert, --key and --broker-ca are all required")
	}
	// Required, not defaulted: with no pool the agent would trust every
	// public CA for a broker whose certificate a private CA issued.
	if s.brokerCA == "" {
		return agent.Config{}, errors.New("--broker-ca is required: the CA that issued the broker's certificate; " +
			"the system's roots are not trusted for the broker")
	}
	// Refused if the key is a symlink or readable by anyone but its owner
	// (keyfile; pre-flight F14).
	cert, err := keyfile.LoadX509KeyPair(s.cert, s.key)
	if err != nil {
		return agent.Config{}, fmt.Errorf("loading the client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(s.brokerCA)
	if err != nil {
		return agent.Config{}, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return agent.Config{}, fmt.Errorf("%s holds no PEM certificate", s.brokerCA)
	}
	return agent.Config{BrokerURL: s.broker, Cert: cert, BrokerCA: pool, Now: time.Now, Log: log}, nil
}

// login starts the agent in its own session, detached, and waits until its
// socket answers. The handshake happens in the agent, so an untrusted
// certificate fails here (plan 3, Decided 3) and the agent's log says why.
func login(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf sessionFlags
	sf.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, err := sf.config(stderr); err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	ctx := context.Background()
	if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
		fmt.Fprintf(stdout, "port49: already logged in to %s; the session ends at %s\n", st.Broker, st.SessionEndsAt)
		return 0
	}
	dir := filepath.Dir(sf.socket)
	if err := agent.PrivateDir(dir); err != nil {
		fmt.Fprintln(stderr, "port49 login:", unprefixed(err))
		return 1
	}
	logPath := filepath.Join(dir, "agent.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	defer logf.Close()
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	cmd := exec.Command(self, append([]string{"agent"}, sf.args()...)...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(stderr, "port49 login: starting the agent:", err)
		return 1
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-exited:
			tail, _ := os.ReadFile(logPath)
			fmt.Fprintf(stderr, "port49 login: the agent exited (%v); the end of %s:\n%s", err, logPath, lastLines(string(tail), 10))
			return 1
		case <-time.After(100 * time.Millisecond):
		}
		if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
			fmt.Fprintf(stdout, "port49: logged in to %s; the session ends at %s (agent pid %d, log %s)\n",
				st.Broker, st.SessionEndsAt, cmd.Process.Pid, logPath)
			return 0
		}
	}
	_ = cmd.Process.Kill()
	fmt.Fprintf(stderr, "port49 login: the agent did not answer within 15s; see %s\n", logPath)
	return 1
}

// agentMain is the agent process: open the session, serve the socket, and
// exit at the session's end, when the broker ends it (Agent.Done: an expired
// session or a certificate it no longer trusts; pre-flight F10), or on a
// signal.
func agentMain(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf sessionFlags
	sf.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := sf.config(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := agent.New(cfg)
	conf, err := a.Connect(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
		return 1
	}
	ln, err := agent.Listen(sf.socket)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
		return 1
	}
	defer os.Remove(sf.socket)
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Fprintf(stderr, "port49 agent: connected to %s; the session ends at %s (max_session_age %ds)\n",
		sf.broker, a.SessionEndsAt().UTC().Format(time.RFC3339), conf.MaxSessionAgeSeconds)
	timer := time.NewTimer(time.Until(a.SessionEndsAt()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		fmt.Fprintln(stderr, "port49 agent: signal received; exiting")
	case <-timer.C:
		fmt.Fprintln(stderr, "port49 agent: the session reached max_session_age; exiting - run `port49 login` to start another")
	case <-a.Done():
		// The agent logged the broker's reason on the line before this one.
		fmt.Fprintln(stderr, "port49 agent: exiting - run `port49 login` to start another session")
	}
	_ = srv.Close()
	return 0
}

// tokenCmd mints one device through the agent and prints the login token on
// stdout — the one place a token is ever written (design §17, write-once).
// Flags come before DEVICE.
func tokenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	enable := fs.Bool("enable", false, "mint an enable token beside the login one (printed with --json)")
	ttl := fs.Duration("ttl", 0, "ask for this lifetime; the broker clamps it to your policy's token_ttl")
	asJSON := fs.Bool("json", false, "print the broker's whole answer as JSON, enable token included")
	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	device := fs.Arg(0)
	item, err := agent.NewClient(*socket).Token(context.Background(),
		agent.TokenRequest{Device: device, Enable: *enable, TTLSeconds: int(*ttl / time.Second)})
	var ie *agent.ItemError
	switch {
	case errors.As(err, &ie):
		// The broker could not decide this device. Whatever else the item
		// carries is not printed.
		fmt.Fprintf(stderr, "port49 token: %s: %s\n", device, unprefixed(ie))
		return 1
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprintf(stderr, "port49 token: no agent at %s; run `port49 login`\n", *socket)
		return 1
	case errors.Is(err, agent.ErrSessionOver):
		// The error says to log in and then why the session ended: an
		// expired certificate has to be renewed before a login will work.
		fmt.Fprintf(stderr, "port49 token: %s\n", unprefixed(err))
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "port49 token:", unprefixed(err))
		return 1
	}
	if item.Verdict != "permit" {
		fmt.Fprintf(stderr, "port49 token: %s: %s %s\n", device, item.Verdict, item.Reason)
		return 1
	}
	if item.Login == "" {
		// Printed, it would be an empty password to whatever reads stdout.
		fmt.Fprintf(stderr, "port49 token: %s: the broker answered permit with no token\n", device)
		return 1
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(item)
		return 0
	}
	fmt.Fprintln(stdout, item.Login)
	return 0
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}

// unprefixed is err's text without the agent package's "agent: ", which the
// command's own "port49 <command>: " already says.
func unprefixed(err error) string {
	return strings.TrimPrefix(err.Error(), "agent: ")
}
