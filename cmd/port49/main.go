// Command port49 is the operator's CLI (design §17, "Client libraries"; §19
// step 3). `port49 login` starts the agent that holds the session — one
// mutual-TLS connection to the broker — and `port49 token DEVICE` mints
// through it, fresh every time. `port49 identity`, `explain` given no files,
// and `revoke` ask the broker through the agent, under
// the caller's api: rights. The policy tools of spec §12 (`explain`,
// `policy test`, `policy replay`, `access review`, `grants remove`) read a
// policy file and an inventory file offline and need no broker. Plan 9 builds
// the rest: `port49 ssh` with host-key verification, the OIDC client, and a
// key held on a hardware token.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/brokercrl"
	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/userconfig"
)

const usage = `usage:
  port49 login [--config FILE] [--broker URL] [--broker-ca FILE] [--socket PATH] [--touch-key REF] [--cert FILE --key FILE |
               --oidc [--issuer URL] [--oidc-ca FILE] [--redirect-port N] [--no-browser] [--sign-in] |
               --directory [--name NAME] [--sign-in]]
               (each flag overrides its key in ~/.port49/config.yaml, or the file $PORT49_CONFIG names,
               each of whose keys overrides /etc/port49/config.yaml's; --oidc signs in at your identity
               provider and holds the certificate the broker issues, signing in again when it has under a
               quarter of its life left, or with --sign-in; --directory asks your directory name, password
               and authenticator code at the terminal, enrolling the authenticator on first use, and holds
               the certificate the broker issues in the same way)
  port49 login [--config FILE] [--broker URL] --delete-key
               (issued_key_store: secure_enclave: deletes this Mac's Secure Enclave keys for the broker and
               the certificate held for them, after asking; the next login makes one key)
  port49 token [--enable] [--ttl DURATION] [--json] [--socket PATH] DEVICE
  port49 refresh [--socket PATH]
  port49 identity [--json] [--socket PATH]
  port49 ssh [--ttl DURATION] [--port N] [--ssh PATH] [--ssh-config FILE] [-v]
             [--socket PATH] DEVICE [-- COMMAND...]
             (mints through your agent and runs your OpenSSH, 8.5 or later; host keys are your OpenSSH
             known_hosts', accepted at first contact and refused if changed; exits with ssh's status)
  port49 workload token --broker URL --broker-ca FILE (--cert FILE --key FILE | --token-file FILE)
                        [--devices-file FILE]
                        [--enable] [--ttl DURATION] [--purpose TEXT] [--format tsv|json] [--out FILE]
                        [--deadline DURATION] [--scope NAME | DEVICE...]
                        (no agent: the certificate and key, or the pod's projected service account
                        token (--token-file), are read each run; under cron, always
                        --out, since cron mails a job's stdout; exits 1 when some devices were
                        written and some not, 75 when the broker did not answer by the deadline,
                        77 when nothing was minted and a run again will not change that)
  port49 workload identity --broker URL --broker-ca FILE (--cert FILE --key FILE | --token-file FILE) [--json]
  port49 explain --policy FILE --inventory FILE (--subject NAME | --principal ID) --device NAME
                 [--command "LINE"] [--show-attributes]
  port49 explain --device NAME [--command "LINE"] [--principal ID] [--socket PATH]
                 (asks the broker through your agent; --principal another needs api: explain_others)
  port49 policy test --policy FILE --inventory FILE [--config PORT49D_YAML]
                     (--config reads key_secret_refs alone; the key sets are the policy's)
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
  port49 devices check-config --policy FILE --inventory FILE [--config PORT49D_YAML]
                              (--device NAME CONFIGFILE | --batch CONFIGFILE...)
  port49 devices capabilities --policy FILE --inventory FILE [--since DURATION] LOGFILE...|-
  port49 keys status --policy FILE --inventory FILE [--since DURATION] LOGFILE...|-
  port49 keys show --policy FILE --inventory FILE DEVICE
  port49 store status [--metrics ADDR]
                (reads GET /store/status on the metrics listener of port49d or port49-broker: each
                store as that process sees it, backend, members, reachable, the directory cache's
                age; exits 3 when a store does not answer)
  port49 revoke (--principal PRINCIPAL | --cert FILE | --cert-issuer DN --cert-serial HEX | --device NAME --username NAME) [--yes]
  port49 revoke --sid SID --sid-issuer ISSUER
  port49 revoke --lift (--principal PRINCIPAL | --cert FILE | --cert-issuer DN --cert-serial HEX)
  port49 revoke --list
  port49 revoke --mine [--device NAME --username NAME]
                (through your agent, under your api: rights: revoke_others, or lift_revocations for
                --lift and --list. Every write but --mine asks for a press of your security key,
                bound to that one request; --principal asks first on a terminal unless --yes;
                --sid ends one OIDC session; --mine leaves no mark and asks for no press; exits 3 when the revocation is in
                force but incomplete or not saved)
  port49 directory forget PRINCIPAL
                (forget a principal's directory membership and the entry it is pinned to: for an
                entry deleted and re-created, once you have confirmed it is the same person)
  port49 directory reset-second-factor (PRINCIPAL | --all)
                (a person who lost their authenticator may enroll again for the broker's reopen_for;
                --all reopens it for every entry with no active second factor, and replaces a lost
                enrollment store, keeping the unreadable file beside it)
  port49 directory unlock PRINCIPAL
                (clear a person's failed password sign-ins)
  port49 directory import [--replace] < FILE
                (restore the enrollment store from an export; each directory command asks for a press
                of your security key, through your agent. Making the export and creating the store
                are on the broker host: port49-broker export-enrollments, init-enrollments)
`

func main() {
	// ssh runs port49 itself as its askpass, with askpassEnv naming `port49
	// ssh`'s socket (decision 42 ruling 10).
	if sock, ok := askpassCall(os.Args[1:]); ok {
		os.Exit(askpassMain(sock, os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// A port49 that ssh's children run (a ProxyCommand, a Match exec) under
	// `port49 ssh` inherits askpassEnv. Given two or more arguments it is not
	// the askpass, and runs no command there either: it says why (decision 42
	// ruling 10). Given one under SSH_ASKPASS_REQUIRE=force, main took it for
	// an askpass call before this, and no token moves, since that prompt is
	// not the device's.
	if os.Getenv(askpassEnv) != "" {
		fmt.Fprintf(stderr, "port49: %s is set, so this port49 was started under port49 ssh's ssh (a ProxyCommand "+
			"or Match exec?) and is not its askpass; unset %s to run a port49 command there\n", askpassEnv, askpassEnv)
		return 2
	}
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
	case "workload":
		return workloadCmd(args[1:], stdout, stderr)
	case "ssh":
		return sshCmd(args[1:], stdout, stderr)
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
		if len(args) > 1 && args[1] == "trust" {
			// Decision 46 ruling 4: host keys are OpenSSH's. Until the
			// pre-beta review, the old command says where it went.
			fmt.Fprintln(stderr, "port49 devices trust was removed in plan 9d: port49 ssh uses your OpenSSH "+
				"known_hosts, which accepts a device's key at first contact and refuses a changed one. To check a "+
				"key at first contact, compare the fingerprint ssh prints with the device's console")
			return 2
		}
		if len(args) > 1 && args[1] == "check-config" {
			return checkConfig(args[2:], stdout, stderr)
		}
		if len(args) > 1 && args[1] == "capabilities" {
			return devicesCapabilities(args[2:], stdout, stderr)
		}
	case "keys":
		return keysCmd(args[1:], stdout, stderr)
	case "store":
		return storeCmd(args[1:], stdout, stderr)
	case "revoke":
		return revokeCmd(args[1:], stdout, stderr)
	case "directory":
		return directoryCmd(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// sessionFlags are what the agent needs to open the session, from the flags
// and, for any they leave out, the per-user config file (decision 42 ruling
// 6). The key is read from a file until plan 9c holds it on a hardware token
// (design §7; plan 3, Question 1).
type sessionFlags struct {
	broker, cert, key, brokerCA, socket, configFile string
	// brokerCAPEM is the CA's bytes: userconfig.Load read them through its
	// ownership walk when brokerCA came from the config file, config() read
	// them from --broker-ca otherwise. login hands these same bytes to the
	// agent it starts on brokerCAFD, so what the session trusts is what was
	// read once, not a second read of the path.
	brokerCAPEM []byte
	// brokerCAFD is an inherited descriptor the CA's bytes come on, to EOF
	// (the agent child's; hidden: the login sets it). 0 is unset.
	brokerCAFD int
	// The OIDC path (plan 9b; spec §13 decision 43 ruling 19).
	oidc, noBrowser, signIn bool
	issuer, oidcCA          string
	redirectPort            int
	// The directory-password path (plan 9e; decision 47): signInName is the
	// name the directory knows the person by, offered at the name prompt.
	directory  bool
	signInName string
	// oidcCAPEM is oidc_ca's bytes, read by userconfig.Load through its walk.
	oidcCAPEM []byte
	// brokerCRL is broker_crl: check (the default), require or off (plan 9c,
	// ruling 9). verify is the one check every connection this process makes
	// to the broker shares, made on first use.
	brokerCRL string
	verify    func(tls.ConnectionState) error
	verified  bool
	// touchKey is touch_key, a key reference on the session key's token
	// (plan 9c, ruling 12). pinFD is an inherited descriptor the PIN comes on
	// (the agent child's; hidden: the login sets it). 0 is unset.
	touchKey string
	pinFD    int
	// issuedKeyStore and issuedKey are issued_key_store and issued_key, from
	// the config file alone.
	issuedKeyStore, issuedKey string
	// pin is the key's PIN while it is held: read from pinFD in the agent,
	// asked in the login. Never logged; zeroed by whoever sets it.
	pin []byte
}

// brokerVerifier is the VerifyConnection that checks the broker's
// certificate against its CRLs under mode, nil for off. The lists are kept in
// ~/.port49/crl; a directory that cannot be made is said once and the lists
// are fetched each run instead. warn says, once, a list that could not be
// had under check.
func brokerVerifier(mode string, warn func(string)) (func(tls.ConnectionState) error, error) {
	m, err := brokercrl.ParseMode(mode)
	if err != nil || m == brokercrl.ModeOff {
		return nil, err
	}
	var once sync.Once
	var chk *brokercrl.Checker
	// keepNote is why the CRLs are not kept, said only with a check that had
	// no answer (a kept list is what would have answered), not on every run.
	var keepNote string
	return func(cs tls.ConnectionState) error {
		once.Do(func() {
			dir, err := userconfig.PrivateDir(filepath.Join(userconfig.Dir(), "crl"), "kept CRL directory")
			if err != nil {
				keepNote = fmt.Sprintf("the CRLs cannot be kept (%v); they are fetched again at each run", err)
				dir = ""
			}
			chk = brokercrl.New(dir, m, time.Now, func(msg string) {
				if keepNote != "" {
					msg += "; " + keepNote
				}
				warn(msg)
			})
		})
		err := chk.VerifyConnection(cs)
		var unchecked *brokercrl.UncheckedError
		if keepNote != "" && errors.As(err, &unchecked) {
			return fmt.Errorf("%w; %s", err, keepNote)
		}
		return err
	}, nil
}

// verifyBroker is the check this session's connections to the broker make,
// said to log.
func (s *sessionFlags) verifyBroker(log io.Writer) (func(tls.ConnectionState) error, error) {
	if !s.verified {
		v, err := brokerVerifier(s.brokerCRL, func(m string) { fmt.Fprintln(log, "port49: warning:", m) })
		if err != nil {
			return nil, err
		}
		s.verify, s.verified = v, true
	}
	return s.verify, nil
}

// hardenAgent is harden, a var so TestMain makes it a no-op: the tests that
// run the agent in-process would make the whole test binary non-dumpable,
// and the ssh tests exec /proc/<pid>/exe as the askpass. An agent the login
// starts is its own process and hardens for real.
var hardenAgent = harden

// maxBrokerCA bounds the CA read from the descriptor, as userconfig bounds a file.
const maxBrokerCA = 1 << 20

func (s *sessionFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&s.oidc, "oidc", false, "sign in at the identity provider the broker lists, and hold the certificate "+
		"the broker issues, in place of your own")
	fs.BoolVar(&s.directory, "directory", false, "sign in with your directory password and authenticator code, and hold "+
		"the certificate the broker issues, in place of your own")
	fs.StringVar(&s.signInName, "name", "", "with --directory: the name your directory knows you by "+
		"(sign_in_name in the config file); the login user's otherwise")
	fs.StringVar(&s.issuer, "issuer", "", "with --oidc: which provider, when the broker lists several")
	fs.StringVar(&s.oidcCA, "oidc-ca", "", "with --oidc: the CA that issued your identity provider's certificate "+
		"(PEM); the system's roots otherwise")
	fs.IntVar(&s.redirectPort, "redirect-port", 0, "with --oidc: the loopback port the sign-in returns to; 0 picks a free one")
	fs.BoolVar(&s.noBrowser, "no-browser", false, "with --oidc: open no browser; print the address to sign in at")
	fs.BoolVar(&s.signIn, "sign-in", false, "with --oidc or --directory: sign in again even while your certificate has life left")
	fs.StringVar(&s.broker, "broker", "", "the broker, https://host:port")
	fs.StringVar(&s.cert, "cert", "", "your client certificate (PEM)")
	fs.StringVar(&s.key, "key", "", "its private key (PEM)")
	fs.StringVar(&s.brokerCA, "broker-ca", "", "the CA that issued the broker's certificate (PEM)")
	fs.IntVar(&s.brokerCAFD, "broker-ca-fd", 0, "internal: the descriptor the login passes the CA's bytes on")
	fs.StringVar(&s.brokerCRL, "broker-crl", "", "the broker certificate's CRL check: check (default) refuses a "+
		"revoked one; require also one it cannot check; off")
	fs.StringVar(&s.touchKey, "touch-key", "", "a key reference on the same token as --key, whose touch the agent may use "+
		"(touch_key in the config file)")
	fs.IntVar(&s.pinFD, "pin-fd", 0, "internal: the descriptor the login passes the key's PIN on")
	fs.StringVar(&s.socket, "socket", agent.SocketPath(), "the agent's socket")
	fs.StringVar(&s.configFile, "config", userconfig.Path(), "your port49 config file, over /etc/port49/config.yaml "+
		"key by key; each flag overrides its key")
}

// fill takes from the config files each value the command line left out
// (decision 42 ruling 6; decision 43 rulings 19 and 24): the personal one
// over the system-wide one, key by key. A missing file at the default path
// is no file; one --config or $PORT49_CONFIG names must be there, and
// --config's is read and checked even when every flag is given. A flag wins: --oidc, or
// --cert or --key, which make a certificate login, over the file's method.
func (s *sessionFlags) fill(fs *flag.FlagSet) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if !set["config"] && s.complete() {
		return nil
	}
	var opts []userconfig.Option
	if s.brokerCA != "" {
		opts = append(opts, userconfig.WithoutCA()) // --broker-ca wins; the file's is unused
	}
	if s.oidcCA != "" {
		opts = append(opts, userconfig.WithoutOIDCCA())
	}
	named := set["config"] || os.Getenv(userconfig.EnvConfig) != ""
	f, ok, err := userconfig.LoadAll(s.configFile, named, opts...)
	if err != nil || !ok {
		return err
	}
	if s.brokerCA == "" {
		s.brokerCA, s.brokerCAPEM = f.BrokerCA, f.BrokerCAPEM
	}
	if s.oidcCA == "" {
		s.oidcCA, s.oidcCAPEM = f.OIDCCA, f.OIDCCAPEM
	}
	s.broker = cmp.Or(s.broker, f.Broker)
	s.cert, s.key = cmp.Or(s.cert, f.Cert), cmp.Or(s.key, f.Key)
	if !set["oidc"] && !set["directory"] && !set["cert"] && !set["key"] {
		s.oidc, s.directory = f.Method == "oidc", f.Method == "directory"
	}
	s.signInName = cmp.Or(s.signInName, f.SignInName)
	s.issuer = cmp.Or(s.issuer, f.OIDCIssuer)
	s.brokerCRL = cmp.Or(s.brokerCRL, f.BrokerCRL)
	s.touchKey = cmp.Or(s.touchKey, f.TouchKey)
	s.issuedKeyStore, s.issuedKey = f.IssuedKeyStore, f.IssuedKey
	if !set["redirect-port"] {
		s.redirectPort = f.OIDCRedirectPort
	}
	return nil
}

// complete is whether the command line names all this command needs, so
// the config file is not read: the agent child is handed all of it, and a
// certificate login with all four flags reads no file, as before. broker_crl
// is the exception: without --broker-crl the file is read for it, so a
// require in the file is not skipped by a command line that names the rest.
// A pkcs11 key may leave --cert out (the certificate is on the token, or the
// file's cert:), and a touch_key may be only in the system file, so that is
// complete only for the agent child, which the login has handed all of it
// (it is the one given --broker-ca-fd).
func (s *sessionFlags) complete() bool {
	return !s.oidc && !s.directory && s.broker != "" &&
		(s.cert != "" || (strings.HasPrefix(s.key, "pkcs11:") && s.brokerCAFD != 0)) && s.key != "" &&
		s.brokerCA != "" && s.brokerCRL != ""
}

func (s *sessionFlags) args() []string {
	a := []string{"--broker", s.broker, "--cert", s.cert, "--key", s.key, "--broker-ca", s.brokerCA,
		"--broker-crl", cmp.Or(s.brokerCRL, string(brokercrl.ModeCheck)), "--socket", s.socket}
	if s.touchKey != "" {
		a = append(a, "--touch-key", s.touchKey)
	}
	return a
}

// brokerPool is the broker CA's pool, from the bytes the config file's walk
// read, the login's descriptor, or --broker-ca's path, in that order. It
// keeps the bytes in brokerCAPEM for the agent the login starts. Required,
// not defaulted: with no pool the agent would trust every public CA for a
// broker whose certificate a private CA issued.
func (s *sessionFlags) brokerPool() (*x509.CertPool, error) {
	if s.brokerCA == "" {
		return nil, errors.New("--broker-ca is required: the CA that issued the broker's certificate; the system's " +
			"roots are not trusted for the broker")
	}
	caPEM := s.brokerCAPEM
	// source is where the bytes came from, for the message when they hold no
	// certificate: the path is only read in the default case.
	source := s.brokerCA
	var err error
	switch {
	case caPEM != nil:
		source = "the broker CA read for " + s.configFile + " (" + s.brokerCA + ")"
	case s.brokerCAFD != 0:
		source = "the broker CA the login passed (from " + s.brokerCA + ")"
		// The login read the CA once and passed the bytes; the path is not
		// read again.
		in := os.NewFile(uintptr(s.brokerCAFD), "broker-ca")
		if in == nil {
			return nil, fmt.Errorf("--broker-ca-fd %d is not an open descriptor", s.brokerCAFD)
		}
		defer in.Close()
		if caPEM, err = io.ReadAll(io.LimitReader(in, maxBrokerCA+1)); err != nil {
			return nil, fmt.Errorf("reading the broker CA from the login: %w", err)
		}
		if len(caPEM) > maxBrokerCA {
			return nil, fmt.Errorf("the broker CA is over %d bytes", maxBrokerCA)
		}
	default:
		// Named by --broker-ca: the operator's own choice of path.
		if caPEM, err = os.ReadFile(s.brokerCA); err != nil {
			return nil, err
		}
	}
	// The bundle the agent kept for this broker joins the CA named here
	// (decision 43 ruling 25); the agent the login starts is handed both.
	if s.brokerCAFD == 0 {
		if caPEM, err = withKeptBundle(s.broker, caPEM); err != nil {
			return nil, err
		}
	}
	s.brokerCAPEM = caPEM
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s holds no PEM certificate", source)
	}
	return pool, nil
}

func (s *sessionFlags) config(log io.Writer) (agent.Config, error) {
	// A key on a PKCS#11 token may hold its certificate: --cert is then optional.
	if s.broker == "" || (s.cert == "" && !strings.HasPrefix(s.key, "pkcs11:")) || s.key == "" {
		return agent.Config{}, fmt.Errorf("--broker, --cert, --key and --broker-ca are all required, as flags "+
			"or in %s", s.configFile)
	}
	if s.brokerCA == "" {
		return agent.Config{}, errors.New("--broker-ca is required: the CA that issued the broker's certificate; " +
			"the system's roots are not trusted for the broker")
	}
	// Refused if the key is a symlink or readable by anyone but its owner
	// (keyfile; pre-flight F14).
	// A key reference is opened (clientkey.LoadPair); LoadPair zeroes the PIN
	// it is given, so it gets a copy.
	cert, err := clientkey.LoadPair(s.cert, s.key, slices.Clone(s.pin))
	if err != nil {
		return agent.Config{}, fmt.Errorf("loading the client certificate: %w", err)
	}
	pool, err := s.brokerPool()
	if err != nil {
		return agent.Config{}, err
	}
	verify, err := s.verifyBroker(log)
	if err != nil {
		return agent.Config{}, err
	}
	cfg := agent.Config{BrokerURL: s.broker, Cert: cert, BrokerCA: pool, Now: time.Now, Log: log,
		BundleKept: bundleKept(s.broker), VerifyBroker: verify, BrokerCAPEM: s.brokerCAPEM,
		BrokerCRL: cmp.Or(s.brokerCRL, string(brokercrl.ModeCheck))}
	if hwkey.IsRef(s.key) {
		cfg.KeyRef = clientkey.CanonicalRef(s.key)
	}
	return cfg, nil
}

// openTouchKey is the agent's touch_key: opened with no PIN, and given the
// PIN only once it is known to sit on the session key's own token, so a
// reference to another token never spends that token's PIN tries (ruling 12;
// pre-flight I6). Whatever goes wrong is the key's reason (TouchKeyUnusable)
// and never a start failure.
func (s *sessionFlags) openTouchKey(cfg *agent.Config, log io.Writer) {
	if s.touchKey == "" {
		return
	}
	tk, err := clientkey.Open(s.touchKey, nil)
	if err != nil {
		cfg.TouchKeyUnusable = "touch_key did not open: " + unprefixed(err)
		fmt.Fprintln(log, "port49 agent: touch_key unusable:", cfg.TouchKeyUnusable)
		return
	}
	if ok, why := agent.SameToken(cfg.Cert.PrivateKey, tk); ok && tk.State() == hwkey.Locked {
		if len(s.pin) > 0 {
			if err := tk.Unlock(slices.Clone(s.pin)); err != nil {
				fmt.Fprintln(log, "port49 agent: the touch key stayed locked:", unprefixed(err))
			}
		} else if r, ok := tk.(interface{ ReadLogin() }); ok {
			// The session key was unlocked from pin-source, so there is no PIN
			// here, and none is sent: the token's login is the application's,
			// and the touch key's session shows it (re-review M14).
			r.ReadLogin()
		}
	} else if !ok {
		fmt.Fprintln(log, "port49 agent: touch_key unusable:", why)
	}
	cfg.TouchKey = tk // agent.New keeps it only on the session key's token
}

// login logs in with the certificate --cert and --key name, or with --oidc
// signs in and holds the certificate the broker issues (loginIssued). With
// an agent already running it refreshes that agent's session instead (spec
// §5.6; decision 33); otherwise it starts one (startAgent).
func login(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf sessionFlags
	sf.register(fs)
	deleteKey := fs.Bool("delete-key", false, "with issued_key_store: secure_enclave: delete this Mac's Secure Enclave "+
		"keys for the broker, and the certificate held for them, after asking; logs in to nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if *deleteKey {
		if err := sf.fill(fs); err != nil {
			fmt.Fprintln(stderr, "port49 login:", err)
			return 2
		}
		return deleteSecureEnclaveKey(&sf, stdout, stderr)
	}
	if sf.oidc && sf.directory {
		fmt.Fprintln(stderr, "port49 login: --directory and --oidc are two logins; name one")
		return 2
	}
	if sf.oidc && (set["cert"] || set["key"]) {
		fmt.Fprintln(stderr, "port49 login: --cert and --key are a certificate login's; --oidc signs in at your "+
			"identity provider instead")
		return 2
	}
	if sf.directory && (set["cert"] || set["key"]) {
		fmt.Fprintln(stderr, "port49 login: --cert and --key are a certificate login's; --directory signs in with "+
			"your directory password instead")
		return 2
	}
	if err := sf.fill(fs); err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	// A login with a terminal asks the PIN of a key whose pin-source PIN was
	// held back for low tries; one without refuses (re-review N1).
	clientkey.AskWhenTriesLow = loginStdinIsTerminal
	defer func() { clientkey.AskWhenTriesLow = func() bool { return false } }()
	if sf.directory {
		for _, name := range []string{"issuer", "oidc-ca", "redirect-port", "no-browser"} {
			if set[name] {
				fmt.Fprintf(stderr, "port49 login: --%s is --oidc's, not --directory's\n", name)
				return 2
			}
		}
	} else if set["name"] {
		fmt.Fprintf(stderr, "port49 login: --name is --directory's (or method: directory in %s)\n", sf.configFile)
		return 2
	}
	if sf.oidc || sf.directory {
		return loginIssued(&sf, stdout, stderr)
	}
	for _, name := range []string{"issuer", "oidc-ca", "redirect-port", "no-browser", "sign-in"} {
		if set[name] {
			fmt.Fprintf(stderr, "port49 login: --%s is --oidc's (or method: oidc in %s)\n", name, sf.configFile)
			return 2
		}
	}
	ctx := context.Background()
	// A hardware key is not opened while the agent that holds this login's key
	// is running: that agent is asked first, so a token pulled out and put
	// back costs a PIN and no second look at the token (pre-flight I15).
	if hwkey.IsRef(sf.key) {
		if code, done := loginToHeldKey(ctx, &sf, stdout, stderr); done {
			return code
		}
	}
	cfg, err := sf.config(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	// The agent opens its own session on the token. This process lets go of
	// its own before the agent starts, so none holds the token while the
	// agent logs in (ruling 8); Close is idempotent for the early returns.
	var held hwkey.Key
	if k, ok := cfg.Cert.PrivateKey.(hwkey.Key); ok {
		held = k
		defer k.Close()
	}
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
		return refreshRunning(ctx, &sf, st, stdout, stderr)
	}
	if held != nil && !unlockForAgent(&sf, held, stderr) {
		return 1
	}
	defer clear(sf.pin)
	if held != nil {
		held.Close()
	}
	return startAgent(&sf, false, stdout, stderr)
}

// refreshRunning refreshes the session of the agent that is already logged in.
func refreshRunning(ctx context.Context, sf *sessionFlags, st agent.Status, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "port49: already logged in to %s; refreshing\n", st.Broker)
	out, err := agent.NewClient(sf.socket).Refresh(ctx, "")
	if err != nil {
		fmt.Fprintln(stderr, "port49 login: refreshing the running agent's session:", unprefixed(err))
		return 1
	}
	printRefresh(stdout, out)
	return 0
}

// startAgent starts the agent in its own session, detached, and waits until
// its socket answers. The handshake happens in the agent, so an untrusted
// certificate fails here (plan 3, Decided 3) and the agent's log says why.
// The broker CA's bytes go to it on descriptor 3, so it reads the path no
// second time. It then refreshes once, a key signature, so the device
// sessions an earlier login left are extended (decision 43 ruling 11). A
// certificate the broker issued (issued) that the refresh is refused
// credential_revoked is no use again: it and its key are removed, and the
// next login signs in (ruling 12; R6).
func startAgent(sf *sessionFlags, issued bool, stdout, stderr io.Writer) int {
	code, _ := startAgentDown(sf, issued, stdout, stderr)
	return code
}

// startAgentDown is startAgent, and says whether the agent could not start
// because the broker did not answer (said already, for a certificate port49
// issued), so a caller adds no hint of its own.
func startAgentDown(sf *sessionFlags, issued bool, stdout, stderr io.Writer) (int, bool) {
	ctx := context.Background()
	dir := filepath.Dir(sf.socket)
	if err := agent.PrivateDir(dir); err != nil {
		fmt.Fprintln(stderr, "port49 login:", unprefixed(err))
		return 1, false
	}
	logPath := filepath.Join(dir, "agent.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1, false
	}
	defer logf.Close()
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1, false
	}
	// The CA this login read goes to the agent on a pipe (descriptor 3, the
	// first of ExtraFiles), so the agent trusts these bytes and does not read
	// the path a second time.
	caR, caW, err := os.Pipe()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1, false
	}
	defer caR.Close()
	defer caW.Close()
	argv := append(append([]string{"agent"}, sf.args()...), "--broker-ca-fd", "3")
	extra := []*os.File{caR}
	// The PIN the login asked goes on a pipe as descriptor 4, never argv or
	// the environment, and is zeroed once written.
	var pinR *os.File
	if len(sf.pin) > 0 {
		var pinW *os.File
		if pinR, pinW, err = os.Pipe(); err != nil {
			fmt.Fprintln(stderr, "port49 login:", err)
			return 1, false
		}
		defer pinR.Close()
		_, werr := pinW.Write(sf.pin)
		pinW.Close()
		clear(sf.pin)
		sf.pin = nil
		if werr != nil {
			fmt.Fprintln(stderr, "port49 login: passing the PIN to the agent:", werr)
			return 1, false
		}
		extra = append(extra, pinR)
		argv = append(argv, "--pin-fd", "4")
	}
	cmd := exec.Command(self, argv...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.ExtraFiles = extra
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(stderr, "port49 login: starting the agent:", err)
		return 1, false
	}
	caR.Close()
	// A goroutine: the pipe holds 64 KiB and the CA may be larger. An agent
	// that dies leaves the write failing, which ends it.
	go func() {
		_, _ = caW.Write(sf.brokerCAPEM)
		caW.Close()
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-exited:
			tail, _ := os.ReadFile(logPath)
			var ee *exec.ExitError
			if issued && errors.As(err, &ee) && ee.ExitCode() == exitCredentialRevoked {
				// Refused at the bind, before the refresh could be: the same
				// as a refused refresh (R6), so the pair is not kept to fail
				// on every later login.
				removeIssued(sf.cert, sf.key)
				fmt.Fprint(stderr, refusedCertificate(revokedWords(string(tail))))
				return 1, false
			}
			if issued && errors.As(err, &ee) && ee.ExitCode() == exitBrokerDown {
				// The broker never answered, so nothing judged the
				// certificate; a sign-in would fail at the same place.
				until := ""
				if c, _, herr := heldCertificate(sf.cert, sf.key); herr == nil {
					until = "; your certificate is valid until " + rfc3339(c.Leaf.NotAfter)
				}
				fmt.Fprintf(stderr, "port49 login: the broker at %s did not answer%s; try again when it answers\n",
					sf.broker, until)
				return 1, true
			}
			fmt.Fprintf(stderr, "port49 login: the agent exited (%v); the end of %s:\n%s", err, logPath, lastLines(string(tail), 10))
			return 1, false
		case <-time.After(100 * time.Millisecond):
		}
		if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
			fmt.Fprintf(stdout, "port49: logged in to %s; the session ends at %s (agent pid %d, log %s)\n",
				st.Broker, st.SessionEndsAt, cmd.Process.Pid, logPath)
			// The session is up whatever the refresh does: a failure is
			// said, and the login still succeeds, unless the broker refused
			// a certificate it issued.
			out, err := agent.NewClient(sf.socket).Refresh(ctx, "")
			var revoked *agent.RevokedError
			switch {
			case issued && errors.As(err, &revoked):
				removeIssued(sf.cert, sf.key)
				fmt.Fprint(stderr, refusedCertificate(revoked.Detail))
				return 1, false
			case err != nil:
				fmt.Fprintln(stderr, "port49 login: logged in, but the refresh of your live device sessions failed:",
					unprefixed(err))
			default:
				printRefresh(stdout, out)
			}
			return 0, false
		}
	}
	_ = cmd.Process.Kill()
	fmt.Fprintf(stderr, "port49 login: the agent did not answer within 15s; see %s\n", logPath)
	return 1, false
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
	// Before any key is read: no core file or crash report holds it. It runs
	// on without: the key is a file this user reads already, until plan 9c
	// puts it in hardware.
	if err := hardenAgent(); err != nil {
		fmt.Fprintf(stderr, "port49 agent: could not make the agent non-dumpable (%v); it runs on\n", err)
	}
	if err := sf.fill(fs); err != nil {
		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
		return 2
	}
	// The PIN, if the login passed one, is read from its descriptor and held
	// only until the keys are open.
	if err := sf.readPINFD(); err != nil {
		fmt.Fprintln(stderr, "port49 agent:", err)
		return 2
	}
	defer func() { clear(sf.pin) }()
	cfg, err := sf.config(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
		return 2
	}
	sf.openTouchKey(&cfg, stderr)
	clear(sf.pin)
	sf.pin = nil
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := agent.New(cfg)
	conf, err := a.Connect(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
		var revoked *agent.RevokedError
		if errors.As(err, &revoked) {
			return exitCredentialRevoked
		}
		var op *net.OpError
		var verify *tls.CertificateVerificationError
		if errors.As(err, &op) && !errors.As(err, &verify) {
			return exitBrokerDown
		}
		return 1
	}
	keepCABundle(sf.broker, conf.BrokerCABundle, conf.BrokerCABundleRefused, a.BrokerRoots(), stderr)
	ln, err := agent.Listen(sf.socket)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", unprefixed(err))
		return 1
	}
	defer os.Remove(sf.socket)
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second, ConnContext: agent.ConnContext}
	go func() { _ = srv.Serve(ln) }()
	fmt.Fprintf(stderr, "port49 agent: connected to %s; the session ends at %s (max_session_age %ds)\n",
		sf.broker, a.SessionEndsAt().UTC().Format(time.RFC3339), conf.MaxSessionAgeSeconds)
	// A refresh moves the deadline, so the timer is re-armed on each one
	// (pre-flight I6).
	for {
		// The certificate's end, when it comes first, ends the agent: past it
		// the broker takes no request (decision 43 ruling 21).
		ends, certEnds := a.SessionEndsAt(), false
		if end := a.CertificateEnd(); !end.IsZero() && end.Before(ends) {
			ends, certEnds = end, true
		}
		timer := time.NewTimer(time.Until(ends))
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
			if certEnds {
				fmt.Fprintf(stderr, "port49 agent: your certificate ended at %s, and the session with it; exiting - run "+
					"`port49 login` (for a certificate port49 issued, it signs you in again)\n", ends.UTC().Format(time.RFC3339))
				break
			}
			fmt.Fprintln(stderr, "port49 agent: the session reached max_session_age; exiting - run `port49 login` to start another")
		case <-a.Done():
			timer.Stop()
			// The agent logged the broker's reason on the line before this one.
			fmt.Fprintln(stderr, "port49 agent: exiting - run `port49 login` to start another session")
		}
		break
	}
	// stop first, so a second signal ends the agent at once.
	stop()
	shutdownSocket(srv, agentShutdownWait)
	return 0
}

// exitCredentialRevoked is the agent's exit status when the broker refuses
// its certificate credential_revoked as the connection binds: `port49 login`
// then removes a certificate port49 issued (R6), as for a refused refresh.
const exitCredentialRevoked = 3

// exitBrokerDown is the agent's exit status when Connect fails on the wire
// (a dial or a reset), not on a refusal or a certificate that does not verify.
const exitBrokerDown = 4

// refusedCertificate is the line for a certificate the broker refused
// credential_revoked, with the broker's words, after it is removed.
func refusedCertificate(detail string) string {
	return fmt.Sprintf("port49 login: the broker refused your certificate: %s; it is removed, and the next "+
		"`port49 login` signs in if the broker takes you again (a revocation an operator made is theirs "+
		"to lift)\n", printsafe.Line(detail, 400))
}

// revokedWords is the broker's words in the agent log's last "the session is
// over: " line, which the agent wrote for a revoked certificate.
func revokedWords(agentLog string) string {
	lines := strings.Split(agentLog, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if _, words, ok := strings.Cut(lines[i], "the session is over: "); ok {
			return words
		}
	}
	return "it was revoked"
}

// shutdownSocket ends the agent's socket server. Shutdown, not Close: the
// request that ended the session (a refresh or mint the broker answered
// credential_revoked) is still writing that answer, and Close would cut
// it, so its client would say "no agent" instead of the broker's reason.
// The wait is bounded so a call held on the broker cannot keep the agent
// up.
func shutdownSocket(srv *http.Server, wait time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = srv.Close()
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
	item, err := mintRetrying(func() (api.MintItem, error) {
		return mintProved(context.Background(), proveFlags(*socket),
			agent.TokenRequest{Device: device, Enable: *enable, TTLSeconds: int(*ttl / time.Second)}, stderr)
	}, tokenRetryClock, "port49 token", stderr)
	if mintFailed("port49 token", *socket, device, item, err, stderr) {
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(tokenFailureOf(device, item, err))
		}
		return 1
	}
	// The device's own ceiling, said where the operator is looking, for a
	// platform that does not show the server_msg warning (decision 33).
	// Before the --json and plain prints, so both get it.
	warnNearCeiling(stderr, device, item, ceilingWarning(*socket))
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
