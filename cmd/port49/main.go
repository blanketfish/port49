// Command port49 is the operator's CLI (design §17, "Client libraries"; §19
// step 3). `port49 login` starts the agent that holds the session — one
// mutual-TLS connection to the broker — and `port49 token DEVICE` mints
// through it, fresh every time. `port49 identity`, `explain` given no files,
// and `revoke --mine` or `--via-agent` ask the broker through the agent, under
// the caller's api: rights. The policy tools of spec §12 (`explain`,
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
  port49 refresh [--socket PATH]
  port49 identity [--json] [--socket PATH]
  port49 explain --policy FILE --inventory FILE (--subject NAME | --principal ID) --device NAME
                 [--command "LINE"] [--show-attributes]
  port49 explain --device NAME [--command "LINE"] [--principal ID] [--socket PATH]
                 (asks the broker through your agent; --principal another needs api: explain_others)
  port49 policy test --policy FILE --inventory FILE [--config PORT49D_YAML]
  port49 policy replay [--line N] [--policy FILE --inventory FILE] LOGFILE|-
  port49 policy diff --old FILE --new FILE --inventory FILE
  port49 inventory diff --policy FILE [--new-policy FILE] [--max-removed-percent N | --config PORT49D_YAML]
                        OLD_INVENTORY NEW_INVENTORY
  port49 inventory diff --service URL --ca FILE --cert FILE --key FILE --from SEQUENCE
                        (waits up to 1 minute for the service's answer)
  port49 inventory sync --service URL --ca FILE --cert FILE --key FILE
                        (waits up to 6 minutes for the service's answer)
  port49 inventory export --service URL --ca FILE --cert FILE --key FILE --verify-key FILE [--from SEQUENCE] [--out FILE]
                        (--out is written 0600, never over an existing file)
  port49 inventory keygen --dir DIR
  port49 access review --policy FILE --inventory FILE --subject NAME
  port49 grants remove --policy FILE --inventory FILE --subject NAME [--write | --pr [--remote R] [--base B]]
  port49 platform list [--set VERSION | --policy FILE --inventory FILE]
  port49 platform show [--set VERSION | --policy FILE --inventory FILE] PLATFORM
  port49 platform export [--set VERSION | --policy FILE --inventory FILE] (PLATFORM | --all --dir EMPTY_DIR |
                         --classes --config PORT49D_YAML PLATFORM)
  port49 platform upgrade --policy FILE --inventory FILE --to VERSION [--write]
  port49 devices check-config --policy FILE --inventory FILE --device NAME [--config PORT49D_YAML] CONFIGFILE
  port49 devices capabilities --policy FILE --inventory FILE [--since DURATION] LOGFILE...|-
  port49 keys status --policy FILE --inventory FILE --config PORT49D_YAML [--since DURATION] LOGFILE...|-
  port49 keys show --policy FILE --inventory FILE [--config PORT49D_YAML] DEVICE
  port49 keys diagnose [--socket PATH] DEVICE
  port49 revoke [--socket PATH] (--principal PRINCIPAL | --cert FILE | --cert-issuer DN --cert-serial HEX) [--lift]
  port49 revoke [--socket PATH] --list
                (exits 3 when the revocation is in force but incomplete or not saved)
  port49 revoke --mine [--device NAME --username NAME] [--agent-socket PATH]
  port49 revoke --via-agent [--yes] (--principal PRINCIPAL | --device NAME --username NAME) [--agent-socket PATH]
                (through your agent, under your api: rights; --mine leaves no mark; --via-agent needs
                api: revoke_others, and asks first on a terminal unless --yes)
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
	case "refresh":
		return refreshCmd(args[1:], stdout, stderr)
	case "identity":
		return identityCmd(args[1:], stdout, stderr)
	case "agent":
		// What login starts; not for typing.
		return agentMain(args[1:], stderr)
	case "explain":
		return explainCmd(args[1:], stdout, stderr)
	case "policy":
		return policyCmd(args[1:], stdout, stderr)
	case "inventory":
		return inventoryCmd(args[1:], stdout, stderr)
	case "access":
		if len(args) > 1 && args[1] == "review" {
			return accessReview(args[2:], stdout, stderr)
		}
	case "grants":
		if len(args) > 1 && args[1] == "remove" {
			return grantsRemove(args[2:], stdout, stderr)
		}
	case "platform":
		return platformCmd(args[1:], stdout, stderr)
	case "devices":
		if len(args) > 1 && args[1] == "check-config" {
			return checkConfig(args[2:], stdout, stderr)
		}
		if len(args) > 1 && args[1] == "capabilities" {
			return devicesCapabilities(args[2:], stdout, stderr)
		}
	case "keys":
		return keysCmd(args[1:], stdout, stderr)
	case "revoke":
		return revokeCmd(args[1:], stdout, stderr)
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
// With an agent already running it refreshes that agent's session instead
// (spec §5.6; decision 33), and a new agent refreshes once it answers, so
// the device sessions an earlier login left are extended either way.
func login(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf sessionFlags
	sf.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := sf.config(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	ctx := context.Background()
	if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
		// Only the session these flags name is refreshed. Another broker's,
		// or another certificate's, is someone else's identity: refreshing
		// it would extend that identity's device sessions while the
		// operator believes they switched (anti-escalation).
		var other string
		switch {
		case strings.TrimRight(sf.broker, "/") != st.Broker:
			other = fmt.Sprintf("an agent logged in to %s", st.Broker)
		case agent.CertFingerprint(cfg.Cert) != st.CertFingerprint:
			other = fmt.Sprintf("an agent for %s with another certificate", st.Broker)
		}
		if other != "" {
			fmt.Fprintf(stderr, "port49 login: %s already holds %s; run 'port49 refresh' to extend that session, "+
				"stop that agent first, or use --socket\n", other, sf.socket)
			return 1
		}
		fmt.Fprintf(stdout, "port49: already logged in to %s; refreshing\n", st.Broker)
		out, err := agent.NewClient(sf.socket).Refresh(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "port49 login: refreshing the running agent's session:", unprefixed(err))
			return 1
		}
		printRefresh(stdout, out)
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
			// The session is up whatever the refresh does: a failure is
			// said, and the login still succeeds.
			if out, err := agent.NewClient(sf.socket).Refresh(ctx); err != nil {
				fmt.Fprintln(stderr, "port49 login: logged in, but the refresh of your live device sessions failed:",
					unprefixed(err))
			} else {
				printRefresh(stdout, out)
			}
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
	// A refresh moves the deadline, so the timer is re-armed on each one
	// (pre-flight I6).
	for {
		timer := time.NewTimer(time.Until(a.SessionEndsAt()))
		select {
		case <-ctx.Done():
			timer.Stop()
			fmt.Fprintln(stderr, "port49 agent: signal received; exiting")
		case <-a.DeadlineChanged():
			timer.Stop()
			fmt.Fprintf(stderr, "port49 agent: refreshed; the session now ends at %s\n",
				a.SessionEndsAt().UTC().Format(time.RFC3339))
			continue
		case <-timer.C:
			fmt.Fprintln(stderr, "port49 agent: the session reached max_session_age; exiting - run `port49 login` to start another")
		case <-a.Done():
			timer.Stop()
			// The agent logged the broker's reason on the line before this one.
			fmt.Fprintln(stderr, "port49 agent: exiting - run `port49 login` to start another session")
		}
		break
	}
	// Shutdown, not Close: the request that ended the session (a refresh or
	// mint the broker answered credential_revoked) is still writing that
	// answer, and Close would cut it, so its client would say "no agent"
	// instead of the broker's reason. The wait is bounded so a call held on
	// the broker cannot keep the agent up, and stop lets a second signal end
	// it at once.
	stop()
	sctx, cancel := context.WithTimeout(context.Background(), agentShutdownWait)
	defer cancel()
	_ = srv.Shutdown(sctx)
	_ = srv.Close()
	return 0
}

// agentShutdownWait bounds how long an exiting agent lets in-flight socket
// calls finish their answers.
const agentShutdownWait = 5 * time.Second

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
		// A revocation says since when and who lifts it instead.
		fmt.Fprintf(stderr, "port49 token: %s\n", unprefixed(err))
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "port49 token:", unprefixed(err))
		return 1
	}
	if item.Verdict != "permit" {
		// The item's detail, when it has one, says what to do: a session
		// past its ceiling is told to refresh (pre-flight M12).
		detail := ""
		if item.Detail != "" {
			detail = ": " + item.Detail
		}
		fmt.Fprintf(stderr, "port49 token: %s: %s %s%s\n", device, item.Verdict, item.Reason, detail)
		return 1
	}
	if item.Login == "" {
		// Printed, it would be an empty password to whatever reads stdout.
		fmt.Fprintf(stderr, "port49 token: %s: the broker answered permit with no token\n", device)
		return 1
	}
	// The device's own ceiling, said where the operator is looking, for a
	// platform that does not show the server_msg warning (decision 33). On
	// stderr, so --json's stdout stays one object (pre-flight M12). Placed
	// before the --json and plain prints, so both get it.
	if exp, err := time.Parse(time.RFC3339, item.SessionExpiresAt); err == nil {
		if st, err := agent.NewClient(*socket).Status(context.Background()); err == nil && st.CeilingWarningSeconds > 0 {
			if left := time.Until(exp); left <= time.Duration(st.CeilingWarningSeconds)*time.Second {
				fmt.Fprintf(stderr, "port49: your session on %s ends at %s (%s); run 'port49 refresh'\n",
					device, item.SessionExpiresAt, timeLeft(left))
			}
		}
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(item)
		return 0
	}
	fmt.Fprintln(stdout, item.Login)
	return 0
}

// timeLeft is d to the minute as the operator reads it: "in 29m", "in 1h5m".
// An expiry already past, as a permit inside the grace window can carry, is
// said so.
func timeLeft(d time.Duration) string {
	switch {
	case d <= 0:
		return "already past"
	case d < time.Minute:
		return "in under a minute"
	}
	return "in " + strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
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
