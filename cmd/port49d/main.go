// Command port49d is the TACACS+ daemon.
//
// Startup order is deliberate: everything that can fail on a typo fails before
// the listener opens, and the process exits non-zero with one line an operator
// can act on. Shutdown is the mirror image: on SIGINT or SIGTERM the listener
// closes, open connections close, and the process waits for the accounting
// spool to drain what is already on disk before it exits.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/daemon/server"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/token"
	"github.com/rhwendt/port49/internal/username"
)

func main() {
	cfgPath := flag.String("config", "/etc/port49/port49d.yaml", "path to port49d.yaml")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "port49d:", err)
		os.Exit(1)
	}
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
		return 0, 0, fmt.Errorf("port49d: opening lab.seed_token_file %s (a symlink at that path is refused, "+
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
			return logins, enables, fmt.Errorf("port49d: minting the lab seed for %s on %s: %w", user, t.NAS, err)
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
	if cfg.Broker == nil {
		return nil, nil, nil
	}
	pol, err := loadPolicy(cfg, inventoryFrom)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	sayPolicy(pol, now)
	cert, anchor, err := broker.LoadTLS(cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("broker TLS files (tls_cert_file %s, tls_key_file %s, client_ca_file %s): %w",
			cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile, err)
	}
	// A server certificate outside its validity does not stop the start:
	// refusing would take device AAA down with the broker. It is said now, in
	// one line, rather than first showing up as every operator's failed login.
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		switch {
		case now.After(leaf.NotAfter):
			fmt.Fprintf(stderr, "port49d: broker: server certificate expired at %s (tls_cert_file %s); logins will fail\n",
				leaf.NotAfter.UTC().Format(time.RFC3339), cfg.Broker.TLSCertFile)
		case now.Before(leaf.NotBefore):
			fmt.Fprintf(stderr, "port49d: broker: server certificate is not valid until %s (tls_cert_file %s); "+
				"logins will fail\n", leaf.NotBefore.UTC().Format(time.RFC3339), cfg.Broker.TLSCertFile)
		}
	}
	b := &broker.Broker{Policy: policy.NewLive(pol), Minter: minter, Store: st, Log: log, Metrics: m, Now: time.Now,
		MaxSessionAge: cfg.Session.MaxSessionAgeDefault, BatchMax: cfg.Broker.BatchMax}
	// The blob event's rule text is redacted as the daemon's records are,
	// with the policy in force's patterns (spec §5.8).
	b.Redact = redactorFor(b.Policy)
	srv, err := b.Server(cfg.Broker.Listen, cert, anchor)
	if err != nil {
		return nil, nil, fmt.Errorf("broker.client_ca_file %s: %w", cfg.Broker.ClientCAFile, err)
	}
	// net/http logs what no handler sees — a handshake refused for an expired
	// or untrusted certificate — through ErrorLog. Left nil it goes to the
	// standard library's default logger; routed here it lands beside
	// port49d's other lines, where an operator is already looking.
	srv.ErrorLog = stdlog.New(stderr, "port49d: broker: ", 0)
	return srv, b, nil
}

// loadPolicy reads broker.policy_file and checks it against the inventory the
// daemon admits from: a class a platform in it does not define, or a level it
// cannot render, is found here rather than at the first mint for that device
// (spec §4, §6). It is the one load, at start and at every reload, so a file
// the start would refuse is a file a reload refuses, with the same words. A
// file anyone but port49d's user or root could have written is one of them
// (readPolicyFile). inventoryFrom names where the inventory came from, for
// that refusal: "inventory_file <path>", or the inventory service's bundle.
func loadPolicy(cfg config.Config, inventoryFrom string) (*policy.Policy, error) {
	raw, err := readPolicyFile(cfg.Broker.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, err)
	}
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
		return nil, fmt.Errorf("broker.policy_file %s with %s: %w", cfg.Broker.PolicyFile,
			inventoryFrom, quotesCut{fmt.Errorf("the bundle admits none of the %d device(s) in the inventory "+
				"(%s: %s); check key_groups and the key_refs port49d.yaml defines, and %s; to take the whole "+
				"fleet off deliberately, stop port49d", n, r.Device.Name, r.Refused, fix)})
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

// parseBundle builds the bundle from the policy file's bytes and an
// inventory (bundle.Parse): a reload of either loads the one it read against
// the other in force, so the version it remembers refusing is the version it
// refused.
func parseBundle(cfg config.Config, raw []byte, inv admission.Inventory) (*policy.Policy, error) {
	pol, err := bundle.Parse(raw, inv, policy.Env{KeyRefs: cfg.KeyRefs()})
	if err != nil {
		return nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, quotesCut{err})
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
	// refused file's own redaction patterns never loaded (spec §5.8).
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
func sayPolicy(pol *policy.Policy, now time.Time) {
	// Every line quotes the policy's own text, and stderr is a log: a rule's
	// secret value is redacted in it (spec §5.8).
	redact := pol.Redactions()
	say := func(format string, args ...any) {
		fmt.Fprintln(stderr, platform.RedactQuoted(redact, fmt.Sprintf(format, args...)))
	}
	for _, q := range pol.Quarantines(now) {
		for _, e := range q.Entries {
			msg := e.Message(now)
			if e.Current(now) {
				msg = "is " + msg
			}
			say("port49d: broker: device %s (%s) %s", q.Device, q.Platform, msg)
		}
	}
	// A deny term that matches any argument, because its platform may send
	// what was typed and its abbreviations cannot be read, over-denies
	// rather than refusing the device (spec §3 rule 4); say which.
	for _, f := range pol.WidenedDenies() {
		say("port49d: broker: %s", f.Message)
	}
	// A permit naming an interface joined never matches where the platform
	// sends the name and the index apart (spec §3 rule 5); say which.
	for _, f := range pol.JoinedNamePermits() {
		say("port49d: broker: %s", f.Message)
	}
	// A rule with a value redaction hides is echoed redacted everywhere
	// (spec §5.8); say which, in its redacted form.
	for _, f := range pol.RuleSecretLiterals() {
		say("port49d: broker: %s", f.Message)
	}
	// A device admission refuses is refused alone (spec §10): named, with
	// why, so the line says what to fix.
	for _, r := range pol.AdmissionRefusals() {
		say("port49d: admission: device %s (%s) is refused: %s", r.Device.Name, r.Device.Platform, r.Refused)
	}
	for _, n := range pol.Notices() {
		say("port49d: policy: %s", n)
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
	return live.Quarantined
}

// run is port49d from config load to exit. It serves until parent ends —
// main's is SIGINT or SIGTERM, a test's is its own — and then shuts down in
// the order the package comment gives, returning once the spool has drained.
func run(parent context.Context, cfgPath string) error {
	// SIGHUP reloads the policy (plan 4b), and is taken with no broker too,
	// where it is said to do nothing: its default action ends the process, and
	// a reload habit must not take device AAA down. It is caught first, before
	// anything else, so a HUP sent while port49d starts — by the tool that
	// just wrote the file, say — does not end it either; one that arrives
	// before the reloader runs waits in the channel.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	// With a broker the inventory is live, so it is read behind the policy
	// file's fence, first and only there (config.Load leaves it unread), and
	// hashed now rather than when the reloader starts: the reloader starts
	// from the bytes loaded, so an edit in between is loaded (M1). With
	// inventory.service there is no file: the cold start below takes its
	// place, once the metrics listener is up.
	var inventoryAtStart string
	inventoryFrom := "inventory_file " + cfg.InventoryFile
	if cfg.Broker != nil && cfg.InventoryService == nil {
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
		picks, err := coldCopies(ctx, cfg.InventoryService, verifyKeysAtStart, client, m, rd)
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
		sayStart(cfg.InventoryService, pick)
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
	tagKey := token.TagKey(keys.Current.Bytes[:])
	tags := token.NewTagWindow(tagKey)
	if keys.Previous != nil {
		tags = token.NewTagWindow(tagKey, token.TagKey(keys.Previous.Bytes[:]))
	}
	st := crypt.Wrap(memory.New(time.Now), keys, m.CryptOpenFailures)

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
	authz := &author.Engine{Store: st, Metrics: m}
	var fault author.LabFault
	if cfg.Lab != nil {
		fault = author.LabFault{Path: cfg.Lab.FaultFile}
		authz.Fallback = &author.Lab{
			SessionAttributes: cfg.Lab.SessionAttributes,
			CommandAttributes: cfg.Lab.CommandAttributes,
			DenyPrefixes:      cfg.Lab.DenyPrefixes,
			Fault:             fault,
		}
	}
	// The request handlers see the store through the lab's fault switch; the
	// minter, the broker and the seeding below do not, so a fault can never
	// stop the daemon starting. With no `lab:` block or no fault_file this is
	// the store itself.
	handlerStore := labHandlerStore(st, fault)
	minter := token.NewMinter(st, log, rand.Reader, tagKey, time.Now, cfg.Token.CandidateCap)
	// Plan 7's broker exposes Refresh, RevokeByPrincipal and RevokeBySID over
	// HTTP; plan 3's serves /v1/tokens and /v1/config only, so nothing in this
	// binary calls them yet. The Manager is built here so the wiring is proven
	// by the compiler rather than by plan 7 discovering it.
	sessions := session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	_ = sessions

	brokerSrv, brk, err := buildBroker(cfg, inventoryFrom, st, minter, log, m)
	if err != nil {
		stopSpool()
		<-spoolDone
		return err
	}
	if startDoc != nil {
		persistStart(cfg.InventoryService, coldPick{startDoc, startFrom}, m)
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
	// buildBroker has already named each one and its cause.
	var live *policy.Live
	if brk != nil {
		live = brk.Policy
	}
	// The drain redacts too: a spool file an earlier build left holds records
	// it never redacted (spec §5.8).
	spool.WithRedactor(redactorFor(live))
	// With a broker, admission is the policy in force's (spec §10); without
	// one, the index config.Load built from the inventory's own key groups.
	admit := server.Admitter(cfg.Admission)
	if live != nil {
		admit = liveAdmission{live}
		m.CountAdmissionRefused(func() int { return len(live.Load().AdmissionRefusals()) })
	}
	keySets := cfg.Keyring()
	seen := &keyring.Seen{}
	m.WatchKeys(func() []metrics.KeySample {
		var out []metrics.KeySample
		for _, ref := range cfg.KeyRefs() {
			for _, v := range keySets[ref].Versions {
				out = append(out, metrics.KeySample{KeyRef: ref, Version: v.Number, Devices: seen.Count(ref, v.Number),
					RetireAt: v.RetireAt})
			}
		}
		return out
	}, time.Now)
	deps := server.Deps{Admission: admit, Quarantined: watchQuarantine(live, m, time.Now), Keys: keySets, KeySeen: seen.Mark,
		// The context indexes are given the context's own idle TTL: they exist
		// to let revocation reach a live context, so they need to outlast
		// nothing the context does not.
		Authen: authen.New(handlerStore, log, lim, m, time.Now, newCtxID, cfg.ReceiptIdleTTL, cfg.ReceiptMaxAge,
			cfg.ContextIdleTTL, cfg.Session.IndexTTL, tags),
		// `session.staleness_ceiling` defaults to 0 — no staleness check — and
		// that default is the operational one, not an unfinished wiring: a
		// finite ceiling denies a steadily working operator `context_stale`,
		// "the broker is unreachable", at login plus the ceiling, whether or
		// not any broker exists to refresh from. It is worth setting only once
		// something is calling session.Manager.Refresh on a schedule.
		//
		// The grace window is carried for plan 7's sweep and read by nothing
		// today.
		Author: author.New(handlerStore, authz, log, m, time.Now, cfg.SessionServices,
			cfg.Session.StalenessCeiling, cfg.Session.GraceWindow, cfg.ContextIdleTTL).WithRedactor(redactorFor(live)),
		// The system-user table is injected rather than looked up through a
		// package global, so nothing can mutate a security rule at run time.
		// It carries `root` for juniper_junos and nothing else
		// (internal/platform). No idle TTL: accounting does not extend one
		// (spec §5.8).
		Acct:   acct.New(handlerStore, spool, m, time.Now, platform.SystemUsers()).WithRedactor(redactorFor(live)),
		Limits: lim, Metrics: m, Log: log, Now: time.Now, IdleTimeout: cfg.Limits.IdleTimeout}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		mln.Close()
		stopSpool()
		<-spoolDone
		return err
	}
	// The broker binds before anything says "listening": a line claiming
	// TACACS+ is up, followed by an exit, reads at 3am as a daemon that is up —
	// and a supervisor restarting it repeats that every few seconds.
	var bln net.Listener
	if brokerSrv != nil {
		if bln, err = net.Listen("tcp", brokerSrv.Addr); err != nil {
			ln.Close()
			mln.Close()
			stopSpool()
			<-spoolDone
			return fmt.Errorf("broker listener on %s: %w", brokerSrv.Addr, err)
		}
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
			ln.Close()
			mln.Close()
			stopSpool()
			<-spoolDone
			return fmt.Errorf("admin_socket %s: %w", cfg.AdminSocket, err)
		}
		srv := &admin.Server{Held: held, Keys: keySets, Now: time.Now, Assigned: assignedKeyRef(cfg, live)}
		go srv.Serve(ctx, aln)
		fmt.Fprintf(stderr, "port49d: admin socket on %s (port49 keys diagnose)\n", cfg.AdminSocket)
	}

	// The bound address, not the configured one: `:49` says nothing about
	// which address answered, and `:0` says nothing about which port.
	admitted := len(cfg.Inventory.Devices)
	if live != nil {
		admitted -= len(live.Load().AdmissionRefusals())
	}
	fmt.Fprintf(stderr, "port49d: listening on %s, metrics on %s, %d devices admitted\n",
		ln.Addr(), mln.Addr(), admitted)
	rd.serving()

	brokerErr := make(chan error, 1)
	if brokerSrv != nil {
		// Capped, so connections to the broker cannot take the file
		// descriptors the TACACS+ listener beside it needs (pre-flight F1).
		go func() { brokerErr <- brokerSrv.ServeTLS(broker.Limit(bln, broker.MaxConns), "", "") }()
		fmt.Fprintf(stderr, "port49d: broker listening on %s\n", bln.Addr())
	}

	// The policy file is watched and SIGHUP reloads it (plan 4b); hup was
	// caught at the top of run.
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		if brk == nil {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					fmt.Fprintln(stderr, "port49d: SIGHUP: no `broker:` block in the config, so there is no policy to reload")
				}
			}
		}
		r := newReloader(cfg, brk, m, time.Now)
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
	go func() { serveErr <- server.Serve(ctx, ln, deps) }()

	var runErr error
	select {
	case err := <-metricsErr:
		rd.draining()
		runErr = fmt.Errorf("metrics listener on %s: %w", cfg.MetricsListen, err)
		cancel()
		<-serveErr
	case err := <-brokerErr:
		rd.draining()
		runErr = fmt.Errorf("broker listener on %s: %w", cfg.Broker.Listen, err)
		cancel()
		<-serveErr
	case err := <-serveErr:
		rd.draining()
		runErr = err
		cancel()
	case <-ctx.Done():
		rd.draining()
		fmt.Fprintln(stderr, "port49d: signal received, draining")
		<-serveErr
	}
	cancel()
	<-reloadDone
	if brokerSrv != nil {
		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		_ = brokerSrv.Shutdown(shutdownCtx)
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
