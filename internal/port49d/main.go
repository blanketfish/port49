// Package port49d is the TACACS+ daemon, and on memory its in-process broker (cmd/port49d).
//
// Startup order is deliberate: everything that can fail on a typo fails before
// the listener opens, and the process exits non-zero with one line an operator
// can act on. Shutdown is the mirror image: on SIGINT or SIGTERM the listener
// closes, open connections close, and the process waits for the accounting
// spool to drain what is already on disk before it exits.
package port49d

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"maps"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/daemon/server"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/keyset"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/token"
	"github.com/rhwendt/port49/internal/username"
)

// Main runs port49d with args (os.Args[1:]) and returns its exit code.
func Main(args []string) int {
	// The subcommands, before the daemon's flags: each reads port49d.yaml and
	// starts nothing (spec §12; §13 decisions 32, amended, and 35).
	if len(args) > 0 && args[0] == "init-revocations" {
		return initRevocationsCmd(args[1:], os.Stdout, os.Stderr)
	}
	if len(args) > 0 && args[0] == "store-roles" {
		return storeRolesCmd(args[1:], os.Stdout, os.Stderr)
	}
	if len(args) > 0 && (args[0] == "init-issuer" || args[0] == "rotate-issuer") {
		return issuerCmd("port49d", args[0], "/etc/port49/port49d.yaml", config.Load, args[1:], os.Stdout, os.Stderr)
	}
	fs := flag.NewFlagSet("port49d", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
	if err := fs.Parse(args); err != nil {
		// The exit codes flag.ExitOnError would have used.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// A subcommand after a flag (port49d --config X init-revocations) would
	// otherwise start the daemon (pre-flight M20).
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: port49d [--config FILE], "+
			"port49d init-revocations|init-issuer|rotate-issuer [--config FILE], or port49d store-roles [--config FILE] (a subcommand comes first)")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "port49d:", err)
		return 1
	}
	return 0
}

// newCtxID mints the ctx_id that ties a login to every later record. A
// duplicate would silently cross-link two operators' sessions in the log, so a
// broken CSPRNG is fatal rather than papered over.
func newCtxID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("port49d: crypto/rand is unavailable: " + err.Error())
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
}

// mintSeeds cuts a token pair for every `lab.seed_tokens` entry and writes the
// credentials to `lab.seed_token_file`, one JSON object per line.
//
// The file is opened O_TRUNC with mode 0600 before the first mint: 0600 because
// it is the only place a minted secret is ever written down, and truncated
// because the tokens of the previous run are gone with the store that held them
// — a file still naming them would hand a harness a credential that redeems as
// `token_not_found`, which reads as a device fault.
//
// O_NOFOLLOW is the third of those, and the lab config is why: it points this
// at a path in /tmp, which anyone on the box can place a symlink at. Followed,
// the pairs land wherever it points and the Chmod below narrows someone else's
// file, which they can widen again. Refused, the daemon fails before the
// listener opens and says which path it would not write through. Nothing
// legitimate needs the symlink: an operator who wants the file elsewhere names
// it elsewhere.
//
// It returns how many of each kind it wrote, because they are not the same
// number: an enable token exists only where the seed asked for one, so a config
// of plain seeds produces logins and no pair at all.
//
// It is the caller's job to unwind the spool on an error, the way every other
// startup failure in run does.
func mintSeeds(ctx context.Context, cfg config.Config, minter *token.Minter) (logins, enables int, err error) {
	f, err := os.OpenFile(cfg.Lab.SeedTokenFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return 0, 0, fmt.Errorf(procOf(cfg)+": opening lab.seed_token_file %s (a symlink at that path is refused, "+
			"deliberately: the credentials would land wherever it points): %w", cfg.Lab.SeedTokenFile, err)
	}
	defer f.Close()
	// O_CREATE's mode applies only to a file this call creates. A file already
	// at the path keeps whatever mode it has, so the lab's /tmp path left 0644
	// by an earlier build would be truncated, filled with credentials, and left
	// world-readable. Narrow it before the first token is written.
	if err := f.Chmod(0o600); err != nil {
		return 0, 0, err
	}
	for _, t := range cfg.Lab.SeedTokens {
		// Canonicalizing here is belt and braces, not a fix: the mint refuses
		// any name canonicalization would change. It is written this way so
		// there is one answer to whose job canonicalization is — the caller's,
		// before the mint checks it.
		user := username.Canonical(t.Username)
		res, err := minter.Mint(ctx, token.Request{
			Subject: token.Subject{
				// The canonical name on both, or the mint record and the
				// context it lands on carry two spellings of one identity.
				Principal:     "user:" + user + "@lab",
				Username:      user,
				TokenTTL:      cfg.ContextIdleTTL,
				Enable:        "token",
				MaxPrivilege:  15,
				MaxSessionAge: cfg.Session.MaxSessionAgeDefault,
				AuthTime:      time.Now(),
				Credential:    store.Credential{Method: "lab"},
			},
			Device: t.NAS, Platform: "lab", WithEnable: t.Enable, TTL: cfg.ContextIdleTTL})
		if err != nil {
			return logins, enables, fmt.Errorf(procOf(cfg)+": minting the lab seed for %s on %s: %w", user, t.NAS, err)
		}
		line, err := json.Marshal(map[string]string{"nas": t.NAS, "username": user,
			"login": res.Login, "enable": res.Enable, "expires_at": res.ExpiresAt.Format(time.RFC3339)})
		if err != nil {
			return logins, enables, err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return logins, enables, err
		}
		logins++
		if res.Enable != "" {
			enables++
		}
	}
	return logins, enables, nil
}

// announce is what the start says about the configuration file itself: the
// lab block's warning, and each notice config.Load left, such as a key that
// moved to the policy file (task 8 review minor 2).
func announce(w io.Writer, cfg *config.Config) {
	fmt.Fprint(w, labWarning(cfg.Lab))
	for _, n := range cfg.Notices {
		fmt.Fprintln(w, "port49d:", n)
	}
}

// labWarning is the line port49d prints at start when its config has a
// `lab:` block (owner's ruling 2026-09-24; design §13): what the block
// enables, and that it must never be in production. The block is the lab's
// instrument, and nothing refuses it, so the start says so where an operator
// reading the journal will see it. Empty without a block.
func labWarning(lab *config.LabConfig) string {
	if lab == nil {
		return ""
	}
	var enables []string
	if len(lab.SeedTokens) > 0 {
		enables = append(enables, fmt.Sprintf("%d seed token(s) minted to %s", len(lab.SeedTokens), lab.SeedTokenFile))
	}
	if lab.FaultFile != "" {
		enables = append(enables, "the fault file "+lab.FaultFile+", which fails the store on demand")
	}
	enables = append(enables, "the lab fallback authorizer, which answers a context with no blob from the "+
		"lab's fixed attributes and deny prefixes instead of denying it")
	return fmt.Sprintf("port49d: LAB MODE: port49d.yaml has a lab: block, which enables %s; a lab: block must "+
		"never be in production\n", strings.Join(enables, "; "))
}

// stderr is where port49d's operational lines go, and stdout is the decision
// log; both are swapped in tests.
var (
	stderr io.Writer = os.Stderr
	stdout io.Writer = os.Stdout
)

// buildBroker loads what the broker needs and returns its server and the
// broker, or nils when no broker: block is configured. The daemon asks the
// broker's policy about quarantine, and nothing else (spec §10). It runs
// before any listener opens, so a policy typo or an unreadable certificate
// ends the start with one line rather than surfacing at the first mint. Each
// error names the config key and the file, so that line says what to go and
// fix.
func buildBroker(cfg config.Config, inventoryFrom string, st store.Store, minter *token.Minter, log decision.Emitter,
	m *metrics.Metrics) (*http.Server, *broker.Broker, error) {
	srv, b, _, err := buildBrokerAnchor(cfg, inventoryFrom, st, minter, log, m)
	return srv, b, err
}

// namedAnchor is a trust anchor the broker read, and the key naming its
// file, for every line about it (plan 8).
type namedAnchor struct {
	key  string
	cert *x509.Certificate
}

func certsOf(as []namedAnchor) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(as))
	for _, a := range as {
		out = append(out, a.cert)
	}
	return out
}

// distinctAnchors refuses a workload anchor that is the human anchor, or
// that signs it or is signed by it (decision 40 ruling 2): a certificate
// under the subordinate would chain to both, refused at every request or not
// as its client's intermediates fall. A nil human anchor (people by OIDC)
// has nothing to cross.
func distinctAnchors(human, workload namedAnchor) error {
	if human.cert == nil {
		return nil
	}
	subj := func(c *x509.Certificate) string { return printsafe.Line(c.Subject.String(), 200) }
	switch {
	case bytes.Equal(human.cert.Raw, workload.cert.Raw):
		return fmt.Errorf("%s: holds the same certificate as %s; a certificate it verifies would be a person's and "+
			"a workload's at once", workload.key, human.key)
	case workload.cert.CheckSignatureFrom(human.cert) == nil, human.cert.CheckSignatureFrom(workload.cert) == nil:
		signer, signed := human, workload
		if human.cert.CheckSignatureFrom(workload.cert) == nil {
			signer, signed = workload, human
		}
		return fmt.Errorf("%s: %s signs %s (%s): a certificate under the one chains to both anchors and is refused "+
			"at every request; anchor each list at its own issuing CA", workload.key, subj(signer.cert),
			subj(signed.cert), human.key)
	}
	return nil
}

// buildBrokerAnchor is buildBroker with the trust anchors it read, which
// broker.certificate_status's issuers are checked against (certStatusConfig):
// the human one from client_ca_file, then the workload one.
func buildBrokerAnchor(cfg config.Config, inventoryFrom string, st store.Store, minter *token.Minter,
	log decision.Emitter, m *metrics.Metrics) (*http.Server, *broker.Broker, []namedAnchor, error) {
	return buildBrokerAnchorWith(cfg, inventoryFrom, st, minter, log, m, nil)
}

// buildBrokerAnchorWith is buildBrokerAnchor issuing from the CA already read
// and checked (loaded); nil reads it here.
func buildBrokerAnchorWith(cfg config.Config, inventoryFrom string, st store.Store, minter *token.Minter,
	log decision.Emitter, m *metrics.Metrics, loaded *loadedIssuer) (*http.Server, *broker.Broker, []namedAnchor, error) {
	if cfg.Broker == nil {
		return nil, nil, nil, nil
	}
	pol, err := loadPolicy(cfg, inventoryFrom)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	sayPolicy(procOf(cfg), pol, now)
	sayFailClosed(procOf(cfg), pol, now, m)
	var cert tls.Certificate
	var anchorCert *x509.Certificate
	if cfg.Broker.ClientCAFile != "" {
		cert, anchorCert, err = broker.LoadTLSAnchor(cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile)
	} else {
		cert, err = keyfile.LoadX509KeyPair(cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile)
	}
	if err != nil {
		if cfg.Broker.ClientCAFile == "" {
			// An OIDC-only broker has no client_ca_file to name (plan 7h).
			return nil, nil, nil, fmt.Errorf("broker TLS files (tls_cert_file %s, tls_key_file %s; an OIDC-only "+
				"broker has no x509 verifier): %w", cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, err)
		}
		return nil, nil, nil, fmt.Errorf("broker TLS files (tls_cert_file %s, tls_key_file %s, client_ca_file %s): %w",
			cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile, err)
	}
	// A server certificate outside its validity does not stop the start:
	// refusing would take device AAA down with the broker. It is said now, in
	// one line, rather than first showing up as every operator's failed login.
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		switch {
		case now.After(leaf.NotAfter):
			fmt.Fprintf(stderr, procOf(cfg)+": broker: server certificate expired at %s (tls_cert_file %s); logins "+
				"will fail\n",
				leaf.NotAfter.UTC().Format(time.RFC3339), cfg.Broker.TLSCertFile)
		case now.Before(leaf.NotBefore):
			fmt.Fprintf(stderr, procOf(cfg)+": broker: server certificate is not valid until %s (tls_cert_file %s); "+
				"logins will fail\n", leaf.NotBefore.UTC().Format(time.RFC3339), cfg.Broker.TLSCertFile)
		}
	}
	caBundle, caBundleRefused := loadCABundle(cfg.Broker.TLSCABundleFile, cert, func(format string, args ...any) {
		fmt.Fprintf(stderr, procOf(cfg)+": "+format+"\n", args...)
	})
	var anchors []namedAnchor
	human := namedAnchor{key: "broker.client_ca_file", cert: anchorCert}
	if id := cfg.Broker.Identity; id != nil && !id.Shorthand {
		human.key = "broker.identity.humans[].trust_anchor_file"
	}
	if anchorCert != nil {
		anchors = append(anchors, human)
	}
	var workload *broker.Workload
	if f := cfg.Broker.WorkloadCAFile; f != "" {
		wa, err := broker.ReadAnchor(f)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("broker.identity.machines[].trust_anchor_file %s: %w", f, err)
		}
		w := namedAnchor{key: "broker.identity.machines[].trust_anchor_file", cert: wa}
		if err := distinctAnchors(human, w); err != nil {
			return nil, nil, nil, err
		}
		anchors = append(anchors, w)
		workload = &broker.Workload{Anchor: wa, TrustDomains: cfg.Broker.Identity.X509Machine.TrustDomains}
	}
	b := &broker.Broker{Policy: policy.NewLive(pol), Minter: minter, Store: st, Log: log, Metrics: m, Now: time.Now,
		MaxSessionAge: cfg.Session.MaxSessionAgeDefault, BatchMax: cfg.Broker.BatchMax,
		CeilingWarning: cfg.Session.CeilingWarning, ContextIdleTTL: cfg.ContextIdleTTL,
		GraceWindow: cfg.Session.GraceWindow}
	// The blob event's rule text is redacted as the daemon's records are,
	// with the policy in force's patterns (spec §5.8).
	b.Redact = redactorFor(b.Policy)
	// The directory, when broker.directory is configured: its bind's
	// credentials are read now, so one that does not load ends the start with
	// the key named (plan 7g, pre-flight M-3).
	proc := procOf(cfg)
	if b.Directory, err = openDirectoryHook(cfg, st, b.Policy, m, func(format string, args ...any) {
		fmt.Fprintf(stderr, proc+": "+format+"\n", args...)
	}); err != nil {
		return nil, nil, nil, err
	}
	announceDirectory(stderr, proc, cfg, pol)
	announceWorkloadIdentities(stderr, proc, cfg, pol)
	announceServiceAccountIdentities(stderr, proc, cfg, pol)
	// The key sets fetch on goroutines that outlive this build: they say
	// through the writer held now, not the package's variable.
	idOut := stderr
	if b.Identity, err = openOIDC(cfg, brokerStateDir(cfg), m, func(format string, args ...any) {
		fmt.Fprintf(idOut, proc+": "+format+"\n", args...)
	}); err != nil {
		return nil, nil, nil, err
	}
	b.NoX509 = cfg.Broker.ClientCAFile == ""
	b.Workload = workload
	announceIdentity(stderr, proc, cfg, b.Identity)
	// The issuing CA (plan 9b; decision 43 ruling 14), before the server's
	// pool is built from it. It never refuses the start.
	if id := cfg.Broker.Identity; id != nil && id.Issuance != nil {
		if loaded == nil {
			loaded = loadIssuer(cfg, time.Now())
		}
		b.Issuer = openIssuerFrom(cfg, m, func(format string, args ...any) {
			fmt.Fprintf(stderr, proc+": "+format+"\n", args...)
		}, loaded)
		b.CertificateLifetime = id.Issuance.CertificateLifetime
	}
	// The directory_password verifier is set before Server, which accepts a
	// broker with no x509 anchor only while it has an OIDC or password
	// verifier and an issuer. wireSignIn adds the store, once the server is built.
	setPasswordSignIn(cfg, b)
	b.CABundle, b.CABundleRefused = caBundle, caBundleRefused
	if id := cfg.Broker.Identity; id != nil {
		b.PerLoginMFA = loadPerLoginMFA(id.PerLoginMFA, func(format string, args ...any) {
			fmt.Fprintf(stderr, proc+": "+format+"\n", args...)
		})
	}
	// Once the verifiers are known: a requirement none of them meets is said
	// now, never refused (decision 45 ruling 18); each swap says it again.
	if line := b.MFAUnavailable(pol, now); line != "" {
		fmt.Fprintf(stderr, "%s: broker: %s\n", proc, line)
	}
	var anchor *x509.CertPool
	if anchorCert != nil {
		anchor = x509.NewCertPool()
		anchor.AddCert(anchorCert)
	}
	srv, err := b.Server(cfg.Broker.Listen, cert, anchor)
	if err != nil {
		// The key an operator edits: client_ca_file when it is set, else
		// broker.identity, which must then name an OIDC verifier.
		if cfg.Broker.ClientCAFile == "" {
			return nil, nil, nil, fmt.Errorf("broker.identity (no x509 trust anchor is set, so it must name an oidc "+
				"or directory_password verifier): %w", err)
		}
		return nil, nil, nil, fmt.Errorf("broker.client_ca_file %s: %w", cfg.Broker.ClientCAFile, err)
	}
	// net/http logs what no handler sees — a handshake refused for an expired
	// or untrusted certificate — through ErrorLog. Left nil it goes to the
	// standard library's default logger; routed here it lands beside
	// port49d's other lines, where an operator is already looking.
	srv.ErrorLog = stdlog.New(stderr, procOf(cfg)+": broker: ", 0)
	return srv, b, anchors, nil
}

// policyKey is the key that named the policy file, for every line about
// it: broker.policy_file with a broker in the process, policy.file with
// none (plan 7e).
func policyKey(cfg config.Config) string {
	if cfg.Broker != nil {
		return "broker.policy_file"
	}
	return "policy.file"
}

// loadPolicy reads the policy file (cfg.Policy) and checks it against the
// inventory the daemon admits from: a class a platform in it does not
// define, or a level it cannot render, is found here rather than at the
// first mint for that device (spec §4, §6). It is the one load, at start
// and at every reload, so a file the start would refuse is a file a reload
// refuses, with the same words. A file anyone but port49d's user or root
// could have written is one of them (readPolicyFile). inventoryFrom names where the inventory came from, for
// that refusal: "inventory_file <path>", or the inventory service's bundle.
func loadPolicy(cfg config.Config, inventoryFrom string) (*policy.Policy, error) {
	raw, err := readPolicyFile(cfg.Policy.File)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", policyKey(cfg), cfg.Policy.File, err)
	}
	return startPolicy(cfg, raw, inventoryFrom)
}

// startPolicy is loadPolicy on raw, the policy file's bytes already read:
// what a start compiles and refuses.
func startPolicy(cfg config.Config, raw []byte, inventoryFrom string) (*policy.Policy, error) {
	pol, err := parseBundle(cfg, raw, cfg.Inventory)
	if err != nil {
		return nil, err
	}
	// A start whose bundle admits none of a non-empty inventory is refused
	// (plan 6a Decided 5, C3): no device caused that, and a daemon admitting
	// nothing is a misconfiguration to say at start, not a fleet to close
	// silently. A reload never reaches this: bundle.CheckAdmission refuses a
	// snapshot that newly refuses the fleet, in the same words.
	if n := len(pol.Devices()); n > 0 && len(pol.AdmissionRefusals()) == n {
		r := pol.AdmissionRefusals()[0]
		// Where to look depends on where the inventory came from: an
		// inventory_file an operator edits, or the service's bundle, whose
		// devices come from the source of truth.
		fix := "if key_groups was deleted from the inventory file, add it to the policy file"
		if cfg.InventoryService != nil {
			fix = "the inventory came from the inventory service, so check the source of truth it syncs from " +
				"and the service's sync log for what changed"
		}
		cause := fmt.Sprintf("the bundle admits none of the %d device(s) in the inventory "+
			"(%s: %s); check key_groups and "+bundle.KeyRefsFile+", and %s; "+bundle.StopFleet,
			n, r.Device.Name, r.Refused, fix)
		if cfg.Role == config.RoleBroker {
			cause = brokerWording(cause)
		}
		return nil, fmt.Errorf("%s %s with %s: %w", policyKey(cfg), cfg.Policy.File,
			inventoryFrom, quotesCut{errors.New(cause)})
	}
	return pol, nil
}

// fencedInventory reads inventory_file behind the fence (readInventoryFile)
// and returns it with the version the reloader starts from: the hash of the
// bytes loaded, so an edit between config.Load's read and this one is loaded,
// never skipped (plan 6a, M1). With a broker config.Load leaves the file
// unread, so these are the only bytes of it port49d reads at start. A fault is a
// *bundle.InventoryError, as bundle.LoadInventory's is, naming the file.
func fencedInventory(cfg config.Config) (admission.Inventory, string, error) {
	raw, err := readInventoryFile(cfg.InventoryFile)
	if err != nil {
		return admission.Inventory{}, "", &bundle.InventoryError{Path: cfg.InventoryFile, Err: err}
	}
	inv, err := admission.ParseFile(raw, "") // the InventoryError names the file
	if err == nil {
		err = admission.Validate(inv.Devices)
	}
	if err != nil {
		return admission.Inventory{}, "", &bundle.InventoryError{Path: cfg.InventoryFile, Err: quotesCut{err}}
	}
	return inv, engine.HashOf(raw), nil
}

// keysOf is the key set lookups port49d serves from: the policy's in force
// (dk), or with no policy port49d.yaml's, read once at load.
func keysOf(cfg config.Config, dk *liveKeys) (func(string) keyring.Set, func() map[string]keyring.Set) {
	if dk != nil {
		return dk.Set, dk.All
	}
	ring := cfg.Keyring()
	return func(ref string) keyring.Set { return ring[ref] }, func() map[string]keyring.Set { return ring }
}

// compileBundle compiles raw against inv, with no keys: requirement: the
// start guard's reading of a policy recorded before the policy carried its
// keys (pre-flight M14). Every file port49d reads goes through parseBundle.
func compileBundle(cfg config.Config, raw []byte, inv admission.Inventory) (*policy.Policy, error) {
	pol, err := bundle.Parse(raw, inv, policyEnv(cfg))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", policyKey(cfg), cfg.Policy.File, quotesCut{err})
	}
	return pol, nil
}

// parseBundle builds the bundle from the policy file's bytes and an
// inventory (bundle.Parse): a reload of either loads the one it read against
// the other in force, so the version it remembers refusing is the version it
// refused. The policy must declare its keys: block, the one place port49
// learns key names (decision 53 ruling 3).
func parseBundle(cfg config.Config, raw []byte, inv admission.Inventory) (*policy.Policy, error) {
	pol, err := compileBundle(cfg, raw, inv)
	if err != nil {
		return nil, err
	}
	if !pol.KeysDeclared() {
		return nil, fmt.Errorf("%s %s: the policy declares no keys: block, so %s knows no key name (decision 53 "+
			"ruling 3); add the key sets beside key_groups, or `keys: {}` for a fleet all on TLS",
			policyKey(cfg), cfg.Policy.File, procOf(cfg))
	}
	return pol, nil
}

// maxQuoted is the most of any one quoted value a refusal line carries.
const maxQuoted = 64

// quotesCut is a parse error whose text cuts every quoted value in it to
// maxQuoted characters. A refusal quotes what it found, and the file can hold
// anything a link aimed it at, so the line says where the fault is without
// echoing the file into stderr.
type quotesCut struct{ err error }

func (q quotesCut) Unwrap() error { return q.err }

func (q quotesCut) Error() string {
	var out strings.Builder
	// A load error quotes no rule text and no term (policy.Parse names a rule
	// by role, list and position), so there is nothing here to redact: a
	// refused file's own redaction patterns never loaded (spec §5.8). The
	// reload guard's causes do quote rule text: refusalLine redacts them
	// before they are cut.
	s := []rune(q.err.Error())
	for i := 0; i < len(s); i++ {
		out.WriteRune(s[i])
		if s[i] != '"' && s[i] != '`' {
			continue
		}
		// A quoted value runs to the matching quote; inside "…" a backslash
		// escapes the next character, as %q writes it.
		end := i + 1
		for end < len(s) && s[end] != s[i] {
			if s[i] == '"' && s[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(s) {
			continue // no closing quote: not a quoted value
		}
		value := s[i+1 : end]
		if len(value) > maxQuoted {
			value = append(value[:maxQuoted:maxQuoted], '…')
		}
		out.WriteString(string(value))
		out.WriteRune(s[end])
		i = end
	}
	return out.String()
}

// sayPolicy writes what a loaded policy does to the fleet short of refusing
// it, at start and after every reload, so the lines an operator reads after
// an edit are the lines they would read after a restart.
//
// A device a joint check failed on is quarantined rather than the policy
// refused: its mints are refused device_quarantined and the rest of the
// fleet loads (spec §10; §13 decision 20). Each is said, with its cause, so
// the line names what to fix. Quarantine is time-scoped: one a grant's
// expiry will bring on is said too, with when, while the device still mints.
// Each line begins with proc, the process's name (procOf).
func sayPolicy(proc string, pol *policy.Policy, now time.Time) {
	// Every line quotes the policy's own text, and stderr is a log: a rule's
	// secret value is redacted in it (spec §5.8).
	redact := pol.Redactions()
	say := func(format string, args ...any) {
		fmt.Fprintln(stderr, platform.RedactQuoted(redact, proc+": "+fmt.Sprintf(format, args...)))
	}
	for _, q := range pol.Quarantines(now) {
		for _, e := range q.Entries {
			msg := e.Message(now)
			if e.Current(now) {
				msg = "is " + msg
			}
			say("broker: device %s (%s) %s", q.Device, q.Platform, msg)
		}
	}
	// A deny term that matches any argument, because its platform may send
	// what was typed and its abbreviations cannot be read, over-denies
	// rather than refusing the device (spec §3 rule 4); say which.
	for _, f := range pol.WidenedDenies() {
		say("broker: %s", f.Message)
	}
	// A permit naming an interface joined never matches where the platform
	// sends the name and the index apart (spec §3 rule 5); say which.
	for _, f := range pol.JoinedNamePermits() {
		say("broker: %s", f.Message)
	}
	// A rule with a value redaction hides is echoed redacted everywhere
	// (spec §5.8); say which, in its redacted form.
	for _, f := range pol.RuleSecretLiterals() {
		say("broker: %s", f.Message)
	}
	// A device admission refuses is refused alone (spec §10): named, with
	// why, so the line says what to fix.
	for _, r := range pol.AdmissionRefusals() {
		say("admission: device %s (%s) is refused: %s", r.Device.Name, r.Device.Platform, r.Refused)
	}
	for _, n := range pol.Notices() {
		say("policy: %s", n)
	}
}

// liveAdmission is the policy in force's admission index, read at each
// Accept and at every packet: a reload reaches the next connection, and ends
// an open one whose device it refused, removed, renamed, re-keyed or
// re-platformed (spec §10).
type liveAdmission struct{ live *policy.Live }

func (a liveAdmission) Lookup(addr netip.Addr) (admission.Resolved, bool) {
	return a.live.Load().Admission().Lookup(addr)
}

// redactorFor is the redaction port49d applies before any record is written
// (spec §5.8): the built-in patterns and, where a policy is in force, the
// ones its `platforms:` blocks add, read at each record so a reload reaches
// them. With no policy the built-in patterns apply alone.
func redactorFor(live *policy.Live) platform.Redactor {
	if live == nil {
		return platform.BuiltInRedactor
	}
	return func(name string) []platform.Redaction {
		pol := live.Load()
		return append(platform.Redactions(pol.WirePlatform(name)), pol.Dialect(name).Redact...)
	}
}

// watchQuarantine is what the daemon asks of the policy: whether a device is
// quarantined at the time of a packet (spec §10; §13 decision 20), and at each
// scrape how many are, for port49_devices_quarantined. Quarantine is
// time-scoped, and the policy in force changes at a reload, so neither is
// captured at start: both ask the Live at the moment of asking. nil with no
// policy.
func watchQuarantine(live *policy.Live, m *metrics.Metrics,
	now func() time.Time) func(device string, at time.Time) (string, bool) {
	if live == nil {
		return nil
	}
	m.CountQuarantined(func() int { return quarantinedAt(live.Load(), now()) })
	m.CountGenericPlatform(func() int { return len(live.Load().GenericDevices()) })
	return live.Quarantined
}

// run is port49d from config load to exit (plan 7d): it runs runOnce
// until a run ends for a reason other than a store gone. A store gone
// closes every listener and drains, as a shutdown does. The next run
// then waits for the store with the listeners closed and no deadline,
// and starts again in-process: devices find TACACS+ refused meanwhile
// and use their local method, and no service manager is needed to
// bring port49d back (Ruling 11; pre-flight I19).
//
// SIGHUP reloads the policy (plan 4b), and is taken with no broker too,
// where it is said to do nothing: its default action ends the process, and
// a reload habit must not take device AAA down. It is caught here, once,
// before anything else, so a HUP sent while port49d starts — by the tool
// that just wrote the file, say — or between two runs does not end it
// either; one that arrives before the reloader runs waits in the channel.
//
// The ledger is the process's, built here once and kept across a store
// gone and a lost hold (decision 35; Ruling T12-b): a run after one starts
// with its marks and its base, so a record put back at a key while the
// store was gone is still below the key's mark, or the base. So is the
// start key check's alarm (keyAlarm): a run after a store gone keeps a
// warning raised. And so are the marks this process enforces, authMarks
// (Ruling 11): with no broker in the process a run after a store gone
// keeps every mark the store lost while it was dark (keepLost).
//
// Each run builds its own metrics registry and binds its own metrics
// listener, so between runs /healthz and /readyz are unbound for the
// drain and the next run's config load (seconds), and the counters
// restart (re-check R-M3). A liveness probe's failure window should be
// over 30s. Binding them once here would hold a metrics address across a
// config change, so it is said instead.
func run(parent context.Context, cfgPath string) error {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	ledger, alarm := crypt.NewLedger(), newKeyAlarm()
	// The daemon's copy of the standing marks, which every authorization,
	// enable and receipt replay reads (plan 7d; Ruling 17).
	authMarks := store.NewMarks()
	// And the directory store's marks are held across a store gone too, and
	// how fresh they are (plan 11a, R19).
	dc := &directoryCache{fresh: store.NewFreshness(time.Now), fatal: make(chan error, 1)}
	// The restore guard is the process's too: a restore that outlasts
	// hold_ttl ends a run, and the next must still know what was followed
	// (plan 7e, Task 15d).
	restored := newRestoreGuard(stderr)
	// The failed-check count is the process's too: the registry is per run, so
	// a gauge set only by the run that ended reads 0 in the next one's, and the
	// alert "above 0 for three intervals" would resolve at the close while the
	// store is still down (plan 7f, I-1; the shape of the key alarm's gauge).
	hs := &healthState{}
	return runLoop(parent, func(again bool) error {
		return runOnce(parent, cfgPath, hup, again, ledger, alarm, authMarks, dc, restored, hs)
	}, 5*time.Second)
}

// runLoop runs once until a run ends for a reason other than a store
// gone, or, once a store gone has happened, until parent ends (re-check
// R-I2). A start after a store gone repeats the whole start: config,
// inventory, policy, the revocations file, the hold, the marks. Any of
// those can fail for a reason that is not the store, such as a policy
// file caught half-written during the outage, or the broker's role
// refused on meta/. Since I19 nothing restarts port49d after an outage
// but this loop, so every such error is said and tried again every
// `every`, the listeners closed, never an exit. A cold start still
// returns its error, for exit 1 and a supervisor.
func runLoop(parent context.Context, once func(again bool) error, every time.Duration) error {
	again := false
	for {
		err := once(again)
		if parent.Err() != nil {
			return err
		}
		var gone *storeGone
		var fault *directoryFault
		switch {
		case errors.As(err, &fault):
			return err // a deferred check's fault ends the process in every mode (N2)
		case errors.As(err, &gone):
			fmt.Fprintf(stderr, "port49d: %v; every listener is closed; waiting for the store again, as at a start\n", gone)
			again = true
			continue
		case err == nil, !again:
			return err
		}
		fmt.Fprintf(stderr, "port49d: starting again after a store gone: %v; the listeners stay closed; trying "+
			"again in %v\n", err, every)
		select {
		case <-parent.Done():
			return nil
		case <-time.After(every):
		}
	}
}

// runOnce is one run of port49d, from config load to a drained spool. It
// serves until parent ends — main's is SIGINT or SIGTERM, a test's is its
// own — or the store is gone, and then shuts down in the order the
// package comment gives. again says a store gone ended the run before.
// authMarks and restored are the process's (run).
func runOnce(parent context.Context, cfgPath string, hup <-chan os.Signal, again bool, ledger *crypt.Ledger,
	alarm *keyAlarm, authMarks *store.Marks, dc *directoryCache, restored *restoreGuard, hs *healthState) (err error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	// A fault left by a run that ended some other way is not this run's: it
	// is found again when the directory opens (N2).
	select {
	case <-dc.fatal:
	default:
	}
	// A mark outlives any grace window a context is kept past its ceiling
	// (crypt.DefaultLedgerKeep), so a record put back is past its ceiling
	// before its mark goes.
	ledger.SetKeep(max(cfg.Session.GraceWindow+time.Hour, crypt.DefaultLedgerKeep))
	parent, cancelRun := context.WithCancelCause(parent)
	defer cancelRun(nil)
	// Whatever path a run ends by, a store gone is what it returns, so
	// run starts the next.
	defer func() {
		var gone *storeGone
		var fault *directoryFault
		if c := context.Cause(parent); errors.As(c, &gone) && !errors.As(err, &fault) {
			err = gone
		}
	}()
	// With a policy the inventory is live, so it is read behind the policy
	// file's fence, first and only there (config.Load leaves it unread), and
	// hashed now rather than when the reloader starts: the reloader starts
	// from the bytes loaded, so an edit in between is loaded (M1). With
	// inventory.service there is no file: the cold start below takes its
	// place, once the metrics listener is up.
	var inventoryAtStart string
	inventoryFrom := "inventory_file " + cfg.InventoryFile
	if cfg.Policy != nil && cfg.InventoryService == nil {
		inv, v, err := fencedInventory(cfg)
		if err != nil {
			return err
		}
		cfg.Inventory, inventoryAtStart = inv, v
	}
	announce(stderr, &cfg)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	// This run's new registry reads the count the last run left, and a run
	// after a store gone holds it at close_after for as long as it waits for
	// the store (openStores' retry), so the alert holds through the whole
	// outage and resolves only when the listeners open again (passes sets 0).
	hs.bind(m)
	if cfg.Stores.Session.Backend == config.BackendEtcd {
		tellFresh(dc.fresh, m)
	}
	if again && cfg.Stores.Session.Backend == config.BackendEtcd {
		hs.atLeast(cfg.Stores.Session.Etcd.Health.CloseAfter)
	}

	// A dead metrics listener is not a detail: without it nobody can see the
	// daemon at all, so its error ends the process rather than disappearing.
	// It binds first of all, before a cold start that may wait on the
	// inventory service, so the daemon is visible — and /readyz says it is
	// not ready — for as long as that takes. Its address is said at once for
	// the same reason.
	mln, err := net.Listen("tcp", cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("metrics listener on %s: %w", cfg.MetricsListen, err)
	}
	defer mln.Close()
	// rd is /readyz: 200 while the TACACS+ listener serves, and 503 with
	// why before it opens and from the start of shutdown.
	rd := newReadiness()
	metricsErr := make(chan error, 1)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		mux.Handle("/readyz", rd)
		metricsErr <- http.Serve(mln, mux)
	}()
	fmt.Fprintf(stderr, "port49d: metrics on %s\n", mln.Addr())

	var startDoc *inventory.Published
	var startFrom string
	var verifyKeysAtStart []ed25519.PublicKey
	var client *inventory.Client
	if cfg.InventoryService != nil {
		// Spec §10, cold start: a copy, or the service; until one, no
		// listener and /readyz 503 (Decided 5). The verify keys and the
		// client are the fetcher's to go on with after the start.
		var err error
		verifyKeysAtStart, err = config.VerifyKeys(cfg.InventoryService.VerifyKeyFiles)
		if err != nil {
			return err
		}
		client, err = inventory.NewClient(cfg.InventoryService.URL, cfg.InventoryService.CAFile,
			cfg.InventoryService.TLSCertFile, cfg.InventoryService.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("inventory.service: %w", err)
		}
		// No snapshot is in force until the start has one, so it has no
		// age: NaN, never the 0 that reads as fresh, for however long the
		// wait lasts. The reloader dates it from the document it starts from.
		m.WatchInventoryAge(func() float64 { return math.NaN() })
		picks, err := coldCopies(ctx, procOf(cfg), cfg.InventoryService, verifyKeysAtStart, client, m, rd)
		if err != nil {
			if ctx.Err() != nil {
				return nil // stopped while waiting for a bundle: nothing was served
			}
			return err
		}
		// The copy the policy in force takes, the newer first; it is
		// persisted only once buildBroker below has accepted it (I2).
		pick, err := startCopy(cfg, picks, m)
		if err != nil {
			return err
		}
		sayStart(procOf(cfg), cfg.InventoryService, pick)
		startDoc, startFrom = pick.p, pick.from
		cfg.Inventory = startDoc.Inv
		inventoryFrom = fmt.Sprintf("the inventory service's bundle %d", startDoc.Doc.Sequence)
		m.InventoryBundleSequence.Set(float64(startDoc.Doc.Sequence))
	}

	log := decision.NewJSONLinesWithFailureHook(stdout, m.DecisionLogWriteFailures.Inc)
	lim := limits.New(cfg.Limits, time.Now)

	// Everything that holds a credential, a principal or a context is sealed
	// before it reaches the backend (design §8). config.Load has already
	// refused a config without an encryption key and refused a key that is not
	// 32 bytes, so this fails only on the backstop in key32.
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		return err
	}
	// The tag key binds a token to the device it was minted for (design §8),
	// and it is derived from an encryption key rather than generated per
	// process: a process-local key would make every token minted by one daemon
	// a device_mismatch at the next, which is a fleet-wide denial that nothing
	// in the log would attribute to a restart. Derived, the tag is a function
	// of configuration, so two daemons on one key agree.
	//
	// A mint uses the current key. What is ACCEPTED is the whole read window,
	// current and previous, because the tag key is derived from a key that
	// rotates: deriving the accepted tag from `current` alone would mean the
	// instant an operator rotated, every outstanding token answered
	// device_mismatch — "this token was minted for another device" — to every
	// operator on every device, while its store record still opened perfectly
	// under `previous`. That is the same fleet-wide, unattributed denial the
	// derivation avoids on restart, triggered by a rotation instead. With the
	// window, a tag retires when its key leaves the window, and not before —
	// one rule for the record and for the tag on it.
	cur := keys.Current.Bytes()
	tagKey := token.TagKey(cur[:])
	tags := token.NewTagWindow(tagKey)
	if keys.Previous != nil {
		prev := keys.Previous.Bytes()
		tags = token.NewTagWindow(tagKey, token.TagKey(prev[:]))
	}
	// port49_revocations_in_force is the marks this process enforces, and
	// nothing else sets it (review M3). Metrics are the run's, and the last
	// run's feeds are joined by now, so this run's count replaces the last
	// one's before anything loads a mark (final review 7e-1).
	authMarks.Count(func(principal, cert int) {
		m.RevocationsInForce.WithLabelValues(store.RevocationPrincipal).Set(float64(principal))
		m.RevocationsInForce.WithLabelValues(store.RevocationCert).Set(float64(cert))
	})
	// The stores (plan 7d): on etcd, waited for with every listener still
	// closed, the daemon's identity and role checked, and the marks loaded
	// into authMarks (plan 7e); on memory, one store. Each sealing layer is
	// on the process's ledger, which denies a context another login wrote
	// at a key (decision 35).
	sts, err := openStores(ctx, cfg, keys, m, stderr, rd, again, func(e error) { cancelRun(e) }, ledger, alarm,
		authMarks, dc)
	if err != nil {
		if ctx.Err() != nil {
			return nil // stopped while waiting for the store: nothing was served, as coldCopies says
		}
		return err
	}
	defer sts.close()
	if sts.health != nil {
		sts.health.state = hs
	}
	if sts.follow != nil {
		// The ledger follows the store from the start's scan at once, before
		// anything reads a context, the start's reads included (plan 7e,
		// Ruling 3), and is joined before sts.close, as the sweep is.
		fctx, stopFollow := context.WithCancel(ctx)
		followDone := make(chan struct{})
		go func() { defer close(followDone); sts.follow(fctx) }()
		defer func() { stopFollow(); <-followDone }()
	}
	if sts.etcd != nil {
		// The restore guard reads the store at once and every second, and
		// redemptions wait for that first read once a witness was followed
		// (Task 15d); joined before sts.close too.
		restored.begin(m.RedemptionRestoreGuarded, m.StoreOps)
		gctx, stopGuard := context.WithCancel(ctx)
		guardDone := make(chan struct{})
		go func() { defer close(guardDone); restored.keep(gctx, sts.etcd, cfg.Stores.Session.Etcd.CallTimeout) }()
		defer func() { stopGuard(); <-guardDone }()
	}
	// The broker's store: the minter, the session manager, the broker, the
	// lab seeds and the revocations. The daemon's handlers read the
	// daemon's (sts.daemon; authorization through sts.author, the context
	// cache when one is set). On etcd it is nil, the broker being
	// port49-broker's (plan 7e), and nothing below writes through it.
	st := sts.broker

	spool, err := acct.NewSpool(cfg.Accounting.SpoolCapacity, cfg.Accounting.SpoolPath, log, m)
	if err != nil {
		return err
	}
	// The spool gets a context of its own, cancelled only once Serve has
	// returned. Sharing the server's would start the final drain at the same
	// instant connections begin closing: the drain returns as soon as the
	// spool is empty, and a connection still inside Acct.Handle can offer a
	// record after that — acknowledged to the device, left on disk, and gone
	// for good on an ephemeral volume.
	spoolCtx, stopSpool := context.WithCancel(context.Background())
	defer stopSpool()
	spoolDone := make(chan struct{})
	go func() { defer close(spoolDone); spool.Run(spoolCtx) }()

	// A context the broker minted names a compiled blob and is answered from it
	// by the policy engine (plan 4). A context with no blob — the lab's seeds —
	// is answered by the lab's instrument where port49d.yaml has a `lab:`
	// block, and denied where it has none: port49 never falls back to
	// permitting everything.
	authz := &author.Engine{Store: sts.author, Metrics: m}
	var fault author.LabFault
	if cfg.Lab != nil {
		fault = author.LabFault{Path: cfg.Lab.FaultFile}
		authz.Fallback = &author.Lab{
			SessionAttributes: cfg.Lab.SessionAttributes,
			CommandAttributes: cfg.Lab.CommandAttributes,
			DenyPrefixes:      cfg.Lab.DenyPrefixes,
			Fault:             fault,
			DenyMessageLength: cfg.Lab.DenyMessageLength,
			DenySession:       cfg.Lab.DenySession,
		}
	}
	// The request handlers see the store through the lab's fault switch; the
	// minter, the broker and the seeding below do not, so a fault can never
	// stop the daemon starting. With no `lab:` block or no fault_file this is
	// the store itself.
	handlerStore := labHandlerStore(sts.daemon, fault)
	minter := token.NewMinter(st, log, rand.Reader, tagKey, time.Now, cfg.Token.CandidateCap)
	// The broker marks a revoked principal's or certificate's live contexts
	// through the Manager (plan 7a); Refresh behind /v1/refresh is plan 7b's.
	sessions := session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)

	brokerSrv, brk, anchors, err := buildBrokerAnchor(cfg, inventoryFrom, st, minter, log, m)
	if err != nil {
		stopSpool()
		<-spoolDone
		return err
	}
	wirePasswordSignIn(ctx, cfg, brk, keys, m, nil, stderr)
	// The policy in force: the broker's, or with no broker the one policy:
	// names, which port49d admits from and asks about quarantine (plan 7e),
	// loaded as the broker loads it, and said the same. Nil with neither:
	// the admission index config.Load built.
	var live *policy.Live
	switch {
	case brk != nil:
		live = brk.Policy
	case cfg.Policy != nil:
		pol, err := loadPolicy(cfg, inventoryFrom)
		if err != nil {
			stopSpool()
			<-spoolDone
			return err
		}
		now := time.Now()
		sayPolicy(procOf(cfg), pol, now)
		sayFailClosed(procOf(cfg), pol, now, m)
		live = policy.NewLive(pol)
	}
	// The device keys in force: the policy's, each secret read now and at
	// every reload (decision 53). port49-broker serves no device: no keys.
	var dk *liveKeys
	if live != nil && cfg.Role == config.RoleDaemon {
		dk = newLiveKeys(cfg.Secrets, cfg.KeySecretRefs)
		kb, err := dk.build(live.Load())
		if err != nil {
			stopSpool()
			<-spoolDone
			return fmt.Errorf("%s %s: %w", policyKey(cfg), cfg.Policy.File, err)
		}
		dk.put(kb)
		// spec §10: a version whose retire_after has passed, an accept version
		// with none, said at start as config's notices were.
		for _, n := range keyset.Notices(live.Load().KeySets(), time.Now()) {
			fmt.Fprintf(stderr, "%s: %s\n", procOf(cfg), n)
		}
	}
	if startDoc != nil {
		persistStart(procOf(cfg), cfg.InventoryService, coldPick{startDoc, startFrom}, m)
	}
	if sts.judged != nil && live != nil {
		// Whether this port49d's policy is the bundle the runner last judged
		// (re-check R5), joined before sts.close. The read goes through no
		// guard: it is a gauge, and a store gone is the probe's to judge.
		jctx, stopJudged := context.WithCancel(ctx)
		judgedDone := make(chan struct{})
		go func() {
			defer close(judgedDone)
			keepDaemonBundle(jctx, sts.judged, live, cfg.Policy.WatchInterval, m, stderr)
		}()
		defer func() { stopJudged(); <-judgedDone }()
	}
	var marks []store.Revocation
	// authMarks is filled from the restore below, and kept by the broker's
	// Revoke and Lift; on etcd with no broker openStores loaded it, and the
	// marks feed keeps it; with neither it stays empty.
	if brk != nil {
		brk.Sessions = sessions
		// Every mark in the file is in force before the broker serves a
		// request: a port49d that forgot a revocation would mint for a stolen
		// certificate again (spec §13 decision 32). Restored into, and saved
		// from, the broker's own store, the one every mint reads, so the two
		// cannot drift apart (Task 9 review M6).
		// The in-process broker is on the memory store alone (plan 7e,
		// Ruling 1), so an error is a file that does not load.
		marks, err = restoreRevocations(ctx, brk.Store, cfg.Broker.RevocationsFile)
		if err != nil {
			stopSpool()
			<-spoolDone
			return fmt.Errorf("broker.revocations_file %s: %w", cfg.Broker.RevocationsFile, err)
		}
		brk.Persist = persister(brk.Store, cfg.Broker.RevocationsFile, marks, authMarks, m)
		brk.Say = func(format string, args ...any) { fmt.Fprintf(stderr, "port49d: "+format+"\n", args...) }
		fmt.Fprintf(stderr, "port49d: broker: %d revocation(s) in force from %s\n", len(marks),
			cfg.Broker.RevocationsFile)
		flagged := 0
		for _, r := range marks {
			if r.LandedAfterLift {
				flagged++
			}
		}
		sayFlagged(stderr, "port49d", flagged)
	}
	// The ledger's marks past their keep are pruned here, joined as every
	// run-scoped goroutine is: the memory store has no sweep, and on etcd
	// the sweep is port49-broker's runner's (plan 7e).
	pruneDone := make(chan struct{})
	go func() {
		defer close(pruneDone)
		pruneLoop(ctx, ledger, ledgerPruneEvery)
	}()
	defer func() { cancel(); <-pruneDone }()
	if brk != nil {
		// The daemon's marks are every mark in force: the file's, on memory,
		// the one store a broker runs on in this process (Task 13).
		for _, r := range marks {
			authMarks.Set(r, true)
		}
		brk.Marks = authMarks
	}
	// Certificate status (spec §5.1.4; decision 33): the kept lists are put
	// in force now, after the marks and before any listener binds. That is
	// local and fast, so it never delays device AAA; nothing is fetched
	// until the listeners are up (pre-flight I8). A source that fails here
	// is said and never stops the start.
	var checker *certstatus.Checker
	if brk != nil {
		cs := cfg.Broker.CertificateStatus
		if cs == nil {
			fmt.Fprintln(stderr, procOf(cfg)+": broker: no x509 verifier is configured, so no client certificate's "+
				"status is checked")
		} else if cs.Disabled {
			fmt.Fprintln(stderr, "port49d: broker: certificate status checking is disabled "+
				"(broker.certificate_status.disabled): a certificate revoked at its CA keeps minting until "+
				"`port49 revoke --cert`")
		} else {
			ccfg, err := certStatusConfig(*cs, certsOf(anchors), filepath.Dir(cfg.Broker.RevocationsFile),
				"broker.client_ca_file, or a broker.identity x509 trust_anchor_file", "the broker")
			if err != nil {
				stopSpool()
				<-spoolDone
				return fmt.Errorf("broker.certificate_status.%w", err)
			}
			checker = certstatus.New(ccfg, time.Now, m,
				func(format string, args ...any) { fmt.Fprintf(stderr, procOf(cfg)+": "+format+"\n", args...) })
			checker.OnNewEntry(brk.OnCRLEntry)
			for _, err := range checker.LoadPersisted() {
				fmt.Fprintf(stderr, "port49d: broker: certificate status: %s\n", printsafe.Line(err.Error(), 300))
			}
			for _, a := range anchors {
				if line := anchorCoverLine(a, ccfg, cs.OnUnavailable); line != "" {
					fmt.Fprintf(stderr, "port49d: %s\n", line)
					continue
				}
				for _, subject := range uncoveredIssuers(ccfg, a.cert) { // re-check R3
					fmt.Fprintf(stderr, "port49d: %s\n", intermediateCoverLine(subject, cs.OnUnavailable))
				}
			}
			brk.CertStatus, brk.OnUnavailable = checker, cs.OnUnavailable
		}
	}

	// The seeded pair is a credential. It goes to a file the operator named, at
	// 0600, and never to a stream: stderr on a systemd unit lands in the same
	// journal the operator ships the decision log to, and `CLAUDE.md` is
	// unconditional — the log never contains a token, and credentials appear
	// only as credential_sha256. Plan 1's shape was different in kind: the
	// operator put the secret in the config file themselves and the daemon
	// never re-emitted it. Here the daemon mints the secret, so it is the
	// daemon that must not publish it.
	//
	// One line per seed, JSON, written before the listener opens; the file is
	// truncated at start so a restart cannot leave a spent token behind.
	if cfg.Lab != nil && len(cfg.Lab.SeedTokens) > 0 {
		logins, enables, err := mintSeeds(ctx, cfg, minter)
		if err != nil {
			stopSpool()
			<-spoolDone
			return err
		}
		fmt.Fprintf(stderr, "port49d lab: %d login token(s) and %d enable token(s) minted, "+
			"credentials written to %s\n", logins, enables, cfg.Lab.SeedTokenFile)
	}

	// A quarantined device is closed without a reply, as for an unknown
	// source, so it falls to its local method exactly as in an outage.
	// sayPolicy has already named each one and its cause.
	//
	// The drain redacts too: a spool file an earlier build left holds records
	// it never redacted (spec §5.8).
	spool.WithRedactor(redactorFor(live))
	// With a policy, admission is the policy in force's (spec §10); without
	// one, the index config.Load built from the inventory's own key groups.
	admit := server.Admitter(cfg.Admission)
	if live != nil {
		admit = liveAdmission{live}
		m.CountAdmissionRefused(func() int { return len(live.Load().AdmissionRefusals()) })
	}
	keysFor, allKeys := keysOf(cfg, dk)
	seen := &keyring.Seen{}
	m.WatchKeys(func() []metrics.KeySample {
		var out []metrics.KeySample
		sets := allKeys()
		for _, ref := range slices.Sorted(maps.Keys(sets)) {
			for _, v := range sets[ref].Versions {
				out = append(out, metrics.KeySample{KeyRef: ref, Version: v.Number, Devices: seen.Count(ref, v.Number),
					RetireAt: v.RetireAt})
			}
		}
		return out
	}, time.Now)
	// On etcd, a redemption asks the restore guard first (Task 15d); on
	// memory nothing is restored.
	var redeemGuard func() bool
	if sts.etcd != nil {
		redeemGuard = restored.Allows
	}
	if cfg.StalenessOff {
		fmt.Fprintln(stderr, procOf(cfg)+": session.staleness_ceiling is 0s: no context ever goes context_stale, so a "+
			"context the broker stopped refreshing keeps its last answer until its own session ends")
	}
	// The global connection cap (decision 53 ruling 8): sized from the
	// open-file limit unless limits.max_connections sets it, said, and
	// published, so an operator sees what binds before it does.
	limit := openFileLimit()
	capN, err := connectionCap(cfg.Limits.MaxConnections, limit)
	if err != nil {
		mln.Close()
		stopSpool()
		<-spoolDone
		return fmt.Errorf("config: %w", err)
	}
	m.ConnectionsMax.Set(float64(capN))
	from := capSource(cfg.Limits.MaxConnections, limit)
	fmt.Fprintf(stderr, "%s: at most %d TACACS+ connections at once (%s); past it each new connection is reset "+
		"at Accept\n", procOf(cfg), capN, from)
	deps := server.Deps{Slots: server.NewSlots(capN, time.Now), Admission: admit, Quarantined: watchQuarantine(live, m, time.Now), Keys: keysFor, KeySeen: seen.Mark,
		// The context indexes are given the context's own idle TTL: they exist
		// to let revocation reach a live context, so they need to outlast
		// nothing the context does not.
		// The context cache is authorization's alone (plan 7f, Ruling 5): a
		// login's join reads the store.
		Authen: authen.New(handlerStore, log, lim, m, time.Now, newCtxID, cfg.ReceiptIdleTTL, cfg.ReceiptMaxAge,
			cfg.ContextIdleTTL, cfg.Session.IndexTTL, tags).WithMarks(authMarks).WithRedeemGuard(redeemGuard),
		// `session.staleness_ceiling` defaults to 4h (plan 7g; OR-1): the
		// broker's scheduled refresh stamps `refreshed_at` every
		// `broker.refresh_interval`. An explicit 0s turns the check off, which
		// the start says (cfg.StalenessOff).
		//
		// The grace window is how long past the ceiling a context is denied
		// and kept before the authorizer deletes it (plan 7b). The ceiling
		// warning rides on permits to the platforms L34 found show it, and
		// to the operator's own list.
		Author: author.New(labHandlerStore(sts.author, fault), authz, log, m, time.Now, cfg.SessionServices,
			cfg.Session.StalenessCeiling, cfg.Session.GraceWindow, cfg.ContextIdleTTL).WithRedactor(redactorFor(live)).
			WithCeilingWarning(cfg.Session.CeilingWarning, cfg.Session.CeilingWarningPlatforms).WithMarks(authMarks),
		// The system-user table is injected rather than looked up through a
		// package global, so nothing can mutate a security rule at run time.
		// It carries `root` for juniper_junos and nothing else
		// (internal/platform). No idle TTL: accounting does not extend one
		// (spec §5.8).
		Acct:   acct.New(handlerStore, spool, m, time.Now, platform.SystemUsers()).WithRedactor(redactorFor(live)),
		Limits: lim, Metrics: m, Log: log, Now: time.Now, IdleTimeout: cfg.Limits.IdleTimeout,
		PacketDeadline: cfg.Stores.Session.PacketDeadline,
		// A store gone resets the held connections (re-check R-M0).
		Abort: func() bool { var g *storeGone; return errors.As(context.Cause(parent), &g) }}

	// The RFC 9887 listener's material is loaded before anything binds: a
	// file that does not load stops the start, and names the file.
	sayf := func(format string, args ...any) { fmt.Fprintf(stderr, procOf(cfg)+": "+format+"\n", args...) }
	tl, tlsChecker, err := tlsListenerOf(cfg, m, sayf, tlsDeviceSource(cfg, live))
	if err != nil {
		mln.Close()
		stopSpool()
		<-spoolDone
		return err
	}
	var tlsDeps *server.TLS
	var said *refusalSayer
	if tl != nil {
		expiry := &devicecert.Expiry{Fraction: cfg.TLSListener.ExpiryWarningFraction, Say: sayf}
		said = &refusalSayer{now: time.Now, say: sayf}
		m.WatchTLSLifetime(func() (float64, bool) { return expiry.LeastLeft(time.Now()) }, tl.ServerLifetimeLeft)
		tlsDeps = newTLSDeps(*cfg.TLSListener, tl, expiry, said)
	}
	m.CountDevicesByTransport(func() map[string]int { n, _ := transportCount(cfg, live); return n })

	// After a store gone, TACACS+ binds only once open_after health checks
	// pass in a row (plan 7f; decision 37): the start's own reads are not
	// enough to say a store that just returned will stay. A cold start is
	// not gated. A stop meanwhile ends the run at once.
	if sts.health != nil && again {
		fmt.Fprintf(stderr, "port49d: store: the store answers; the listeners open again after %d consecutive "+
			"health checks pass (%s.etcd.health.open_after)\n", sts.health.openAfter, cfg.Stores.SessionPath())
		if err := sts.health.passes(ctx); err != nil {
			mln.Close()
			stopSpool()
			<-spoolDone
			return nil
		}
		fmt.Fprintf(stderr, "port49d: store: %d consecutive health checks passed\n", sts.health.openAfter)
	}
	var ln, tln net.Listener
	closeListeners := func() {
		if ln != nil {
			ln.Close()
		}
		if tln != nil {
			tln.Close()
		}
	}
	if cfg.Listen != "" {
		if ln, err = net.Listen("tcp", cfg.Listen); err != nil {
			mln.Close()
			stopSpool()
			<-spoolDone
			return err
		}
	}
	if tl != nil {
		if tln, err = net.Listen("tcp", cfg.TLSListener.Listen); err != nil {
			closeListeners()
			mln.Close()
			stopSpool()
			<-spoolDone
			return fmt.Errorf("tls_listener.listen %s: %w", cfg.TLSListener.Listen, err)
		}
	}
	// The broker binds before anything says "listening": a line claiming
	// TACACS+ is up, followed by an exit, reads at 3am as a daemon that is up —
	// and a supervisor restarting it repeats that every few seconds.
	var bln net.Listener
	var bl *broker.Listener
	if brokerSrv != nil {
		if bln, err = net.Listen("tcp", brokerSrv.Addr); err != nil {
			closeListeners()
			mln.Close()
			stopSpool()
			<-spoolDone
			return fmt.Errorf("broker listener on %s: %w", brokerSrv.Addr, err)
		}
		// Capped globally, so connections to the broker cannot take the file
		// descriptors the TACACS+ listener needs (pre-flight F1), and per
		// source and per principal before that (spec §13 decision 32). It
		// accepts nothing until Serve's first Accept, so the marks restored
		// above, given to it here, are in place before any connection can
		// bind: a revoked principal or certificate is answered
		// credential_revoked and closed as it binds, from the first
		// connection on.
		bl = broker.NewListener(broker.Limit(bln, broker.MaxConns), brokerSrv.TLSConfig,
			brokerLimits(cfg, brk),
			m, time.Now, func(format string, args ...any) {
				fmt.Fprintf(stderr, procOf(cfg)+": "+format+"\n", args...)
			})
		for _, r := range authMarks.All() {
			bl.Revoked(r, true)
		}
		brk.Wire(bl)
		brk.Conns = bl
	}
	// The admin socket binds before anything says "listening", as the broker
	// does, and a failure lets go of every listener already bound (pre-flight
	// M6). Only with it configured is any packet held: off, nothing is.
	if cfg.AdminSocket != "" {
		held := &keyring.Held{}
		deps.Held = held
		aln, err := admin.Listen(cfg.AdminSocket)
		if err != nil {
			if bln != nil {
				bln.Close()
			}
			closeListeners()
			mln.Close()
			stopSpool()
			<-spoolDone
			return fmt.Errorf("admin_socket %s: %w", cfg.AdminSocket, err)
		}
		srv := &admin.Server{Held: held, Keys: allKeys, Now: time.Now, Assigned: assignedKeyRef(cfg, live),
			StoreStatus: newStoreStatus(cfg, sts.dir, sts.etcd, sts.fresh).answer}
		if brk != nil {
			// The socket's deadline covers the wait and the run; one bound
			// for both, so they cannot drift apart.
			brk.RevokeTimeout = admin.OpTimeout
			brk.AdminSocket = cfg.AdminSocket
			srv.Revoke, srv.Revocations, srv.Forget = adminRevoke(brk, nil), adminRevocations(brk.Store), adminForget(brk)
			serveSignInOps(srv, brk)
		} else if sts.persistent {
			// Beside port49-broker on etcd (plan 7e, Ruling 13).
			srv.RevokeElsewhere = "port49-broker's admin socket (its admin_socket in port49-broker.yaml)"
		}
		go srv.Serve(ctx, aln)
		ops := "port49 keys diagnose, port49 revoke"
		if brk != nil && brk.PasswordSignIn != nil {
			ops += ", port49 directory reset-second-factor, unlock, init-enrollments, export, import"
		}
		fmt.Fprintf(stderr, "port49d: admin socket on %s (%s)\n", cfg.AdminSocket, ops)
	}
	if brk != nil && cfg.AdminSocket == "" {
		fmt.Fprintln(stderr, "port49d: broker: no admin_socket: a revocation over HTTP (port49 revoke --via-agent, "+
			"under api: revoke_others) is made, but none can be lifted, nor a certificate revoked, short of stopping "+
			"port49d and editing broker.revocations_file; set admin_socket. To cut someone off meanwhile, remove "+
			"their grants from broker.policy_file")
	}

	// The bound address, not the configured one: `:49` says nothing about
	// which address answered, and `:0` says nothing about which port.
	admitted := len(cfg.Inventory.Devices)
	if live != nil {
		admitted -= len(live.Load().AdmissionRefusals())
	}
	if ln != nil {
		fmt.Fprintf(stderr, "port49d: listening on %s, metrics on %s, %d devices admitted\n",
			ln.Addr(), mln.Addr(), admitted)
	} else {
		fmt.Fprintf(stderr, "port49d: RFC 8907 listener off (listen: none), metrics on %s, %d devices admitted\n",
			mln.Addr(), admitted)
	}
	announceTransports(stderr, cfg, live, ln, tln, tlsChecker)
	rd.serving()
	if sts.health != nil {
		// From the bind on, close_after failures in a row end the run as a
		// store gone, idle or not (plan 7f, Ruling 4); joined before
		// sts.close, as the feeds are.
		hctx, stopHealth := context.WithCancel(ctx)
		healthDone := make(chan struct{})
		go func() { defer close(healthDone); sts.health.watch(hctx, func(e error) { cancelRun(e) }) }()
		defer func() { stopHealth(); <-healthDone }()
	}

	brokerErr := make(chan error, 1)
	if brokerSrv != nil {
		go func() { brokerErr <- brokerSrv.Serve(bl) }()
		brk.SetReady(broker.ReadyServing)
		fmt.Fprintf(stderr, "port49d: broker listening on %s\n", bln.Addr())
	}

	// The network side of certificate status starts only now that device
	// AAA is up, and is joined at shutdown as the fetcher is (plan 6b, F8).
	// The start line is said first, so it names the state the kept lists
	// left, not a race with the first fetch.
	var statusDone sync.WaitGroup
	if tl != nil {
		statusDone.Add(2)
		go func() { defer statusDone.Done(); tl.watch(ctx) }()
		go func() { defer statusDone.Done(); said.run(ctx) }()
		if tlsChecker != nil {
			statusDone.Add(1)
			go func() { defer statusDone.Done(); tlsChecker.Run(ctx) }()
		}
	}
	if checker != nil {
		unavailable := map[string]string{"refuse": "refused (503, retried)", "allow": "allowed, alarmed"}
		fmt.Fprintf(stderr, "port49d: broker: certificate status from %s; a status that cannot be established is %s\n",
			checker.Describe(), unavailable[cfg.Broker.CertificateStatus.OnUnavailable])
		statusDone.Add(3)
		go func() { defer statusDone.Done(); brk.RunRevocationQueue(ctx) }()
		go func() { defer statusDone.Done(); checker.Run(ctx) }() // the first fetch happens now
		// Pending CRL revocations, retried each interval (pre-flight I9).
		go func() {
			defer statusDone.Done()
			t := time.NewTicker(cfg.Broker.CertificateStatus.RefreshInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					brk.RetryPending()
				}
			}
		}()
	}

	// The directory's duties, joined with certificate status's: the pool's
	// health checks, pre-warm, and the scheduled refresh. The refresh runs
	// with no directory too: it is what stamps refreshed_at, so without it a
	// session goes context_stale at session.staleness_ceiling. port49d's
	// own broker is the only minter here, so the pass is its own.
	if brk != nil {
		sayDir := func(format string, args ...any) { fmt.Fprintf(stderr, "port49d: "+format+"\n", args...) }
		statusDone.Add(4)
		go func() { defer statusDone.Done(); runPool(ctx, brk.Directory) }()
		go func() { defer statusDone.Done(); runKeySets(ctx, brk.Identity) }()
		go func() { defer statusDone.Done(); scheduled(ctx, brk, cfg.Broker.RefreshInterval, sayDir) }()
		go func() {
			defer statusDone.Done()
			prewarm(ctx, brk.Directory, brk.Policy, prewarmInterval(cfg), sayDir)
		}()
	}

	// The policy file is watched and SIGHUP reloads it (plan 4b); hup was
	// caught at the top of run.
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		if live == nil {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					if tl != nil {
						tl.reload("SIGHUP")
					}
					fmt.Fprintln(stderr, "port49d: SIGHUP: no `broker:` block in the config, so there is no policy to reload")
				}
			}
		}
		// With no broker in the process a swap carries nothing into the live
		// contexts: port49d reads the policy in force at each packet (plan 7e).
		var pass func(context.Context, []broker.Prior) (broker.RefreshReport, error)
		var mfaUnavailable func(*policy.Policy, time.Time) string
		if brk != nil {
			pass, mfaUnavailable = brk.Refresh, brk.MFAUnavailable
		}
		r := newReloader(cfg, live, log, pass, m, time.Now)
		r.keys = dk
		r.generic = newGenericRecorder(log, procOf(cfg))
		r.generic.record(live.Load(), time.Now())
		hookTLSReload(r, tl, cfg, live)
		r.mfaUnavailable = mfaUnavailable
		r.inventory, r.cfgPath = inventoryAtStart, cfgPath
		r.startDocument(startDoc, startFrom)
		r.seen, r.held = seen, deps.Held
		var fetchDone <-chan struct{}
		if cfg.InventoryService != nil {
			// The fetcher asks the service every poll_interval from here on;
			// startDocument above is the start's one call (conflict scan F11).
			keys := verifyKeysAtStart
			r.verifyKeys.Store(&keys)
			fetchDone = startFetcher(ctx, r, client, m)
		}
		r.run(ctx, hup)
		if fetchDone != nil {
			<-fetchDone // ctx is done: the fetcher returns without a line (F8)
		}
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- serveListeners(ctx, cancel, ln, deps, tln, tlsDeps) }()

	var runErr error
	select {
	case err := <-metricsErr:
		rd.draining()
		if brk != nil {
			brk.SetReady(broker.ReadyDrainingOf(procOf(cfg)))
		}
		runErr = fmt.Errorf("metrics listener on %s: %w", cfg.MetricsListen, err)
		cancel()
		<-serveErr
	case err := <-brokerErr:
		rd.draining()
		if brk != nil {
			brk.SetReady(broker.ReadyDrainingOf(procOf(cfg)))
		}
		runErr = fmt.Errorf("broker listener on %s: %w", cfg.Broker.Listen, err)
		cancel()
		<-serveErr
	case err := <-dc.fatal:
		// The directory opened after a snapshot start and failed a start
		// check (N2): a fault of the configuration, returned as a cold
		// start's are, never a store gone.
		rd.draining()
		if brk != nil {
			brk.SetReady(broker.ReadyDrainingOf(procOf(cfg)))
		}
		dc.loaded.Store(false) // the held marks are not served again
		runErr = &directoryFault{err}
		cancel()
		<-serveErr
	case err := <-serveErr:
		rd.draining()
		if brk != nil {
			brk.SetReady(broker.ReadyDrainingOf(procOf(cfg)))
		}
		runErr = err
		cancel()
	case <-ctx.Done():
		rd.draining()
		if brk != nil {
			brk.SetReady(broker.ReadyDrainingOf(procOf(cfg)))
		}
		var gone *storeGone
		if errors.As(context.Cause(parent), &gone) {
			// Close the broker's listener first, so the line is true when it
			// is said; TACACS+'s is closing with ctx, its held connections
			// reset (Deps.Abort).
			if bl != nil {
				bl.Close()
			}
			fmt.Fprintf(stderr, "port49d: %v; closing every listener so that devices use their local method\n", gone)
		} else {
			fmt.Fprintln(stderr, "port49d: signal received, draining")
		}
		<-serveErr
	}
	cancel()
	<-reloadDone
	statusDone.Wait()
	if brokerSrv != nil {
		// Close what Shutdown left at its timeout: the agent's held
		// connections.
		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		if err := brokerSrv.Shutdown(shutdownCtx); err != nil {
			brokerSrv.Close()
		}
		done()
	}

	// Serve has returned, so no connection can offer another record: only now
	// is it true that whatever the spool drains is all of it.
	stopSpool()
	<-spoolDone
	fmt.Fprintln(stderr, "port49d: accounting spool drained, exiting")
	mln.Close()
	return runErr
}

// readiness is /readyz: 200 "serving" while the TACACS+ listener serves,
// and otherwise 503 with a fixed line saying why — starting, waiting for a
// first bundle, or draining — for a probe's log or a curl at 3am.
type readiness struct{ why atomic.Pointer[string] }

// The fixed lines /readyz answers.
const (
	readyStarting = "starting: the TACACS+ listener is not open yet"
	readyWaiting  = "waiting for a first bundle from the inventory service"
	readyStore    = "waiting for the store: the TACACS+ listener stays closed until etcd answers (plan 7d)"
	readyDraining = "draining: port49d is shutting down, and the TACACS+ listener is closed or closing"
	readyServing  = "serving"
)

func newReadiness() *readiness {
	r := &readiness{}
	r.set(readyStarting)
	return r
}

func (r *readiness) set(why string) {
	if r != nil {
		r.why.Store(&why)
	}
}

func (r *readiness) waiting()  { r.set(readyWaiting) }
func (r *readiness) serving()  { r.set(readyServing) }
func (r *readiness) draining() { r.set(readyDraining) }

func (r *readiness) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	why := *r.why.Load()
	if why == readyServing {
		fmt.Fprintln(w, why)
		return
	}
	http.Error(w, why, http.StatusServiceUnavailable)
}

// assignedKeyRef is the key_ref a device is assigned now, for keys diagnose:
// the policy in force's with a broker, and without one the admission index
// config.Load built, by the device's first address. Empty is a name port49d
// does not admit.
func assignedKeyRef(cfg config.Config, live *policy.Live) func(string) string {
	return func(name string) string {
		if live != nil {
			r, _ := live.Load().Admitted(name)
			return r.KeyRef
		}
		if cfg.Admission == nil {
			return ""
		}
		for _, d := range cfg.Inventory.Devices {
			if d.Name == name && len(d.Addresses) > 0 {
				r, _ := cfg.Admission.Lookup(d.Addresses[0])
				return r.KeyRef
			}
		}
		return ""
	}
}

// labHandlerStore is the store the request handlers see: st itself unless the
// lab's fault switch is configured, and then st behind author.FaultStore.
func labHandlerStore(st store.Store, fault author.LabFault) store.Store {
	if fault.Path == "" {
		return st
	}
	return &author.FaultStore{Store: st, Fault: fault}
}
