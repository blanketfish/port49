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
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/daemon/server"
	"github.com/rhwendt/port49/internal/decision"
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
	if err := run(*cfgPath); err != nil {
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

// stderr is where port49d's operational lines go — not the decision log,
// which is stdout — swapped in tests.
var stderr io.Writer = os.Stderr

// buildBroker loads what the broker needs and returns its server, or nil when
// no broker: block is configured. It runs before any listener opens, so a
// policy typo or an unreadable certificate ends the start with one line
// rather than surfacing at the first mint. Each error names the config key
// and the file, so that line says what to go and fix.
func buildBroker(cfg config.Config, st store.Store, minter *token.Minter, log decision.Emitter,
	m *metrics.Metrics) (*http.Server, error) {
	if cfg.Broker == nil {
		return nil, nil
	}
	// The policy is checked against the inventory the daemon admits from: a
	// class a platform in it does not define, or a level it cannot render, is
	// found here rather than at the first mint for that device (spec §4, §6).
	pol, err := policy.Load(cfg.Broker.PolicyFile, policy.Env{Devices: cfg.Inventory.Devices,
		EnableUsernames: cfg.EnableUsernames})
	if err != nil {
		return nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, err)
	}
	// A device a joint check failed on is quarantined rather than the policy
	// refused: its mints are refused device_quarantined and the rest of the
	// fleet loads (spec §10; §13 decision 20). Each is said here, with its
	// cause, so the line at start names what to fix. Quarantine is
	// time-scoped: one a grant's expiry will bring on is said now too, with
	// when, while the device still mints.
	now := time.Now()
	for _, q := range pol.Quarantines(now) {
		for _, e := range q.Entries {
			msg := e.Message(now)
			if e.Current(now) {
				msg = "is " + msg
			}
			fmt.Fprintf(stderr, "port49d: broker: device %s (%s) %s\n", q.Device, q.Platform, msg)
		}
	}
	cert, anchor, err := broker.LoadTLS(cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("broker TLS files (tls_cert_file %s, tls_key_file %s, client_ca_file %s): %w",
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
	// The broker mints by name, and a token redeems on any device the name
	// tags. Two entries sharing one would collapse, last wins: a blob compiled
	// for one platform would be answered on the other, sending attributes that
	// device may not know while port49 logs permit. IOS-XE refuses the session
	// over any attribute it does not recognise, optional or mandatory, and every
	// command whose reply carries one (tests/lab/results/L18-cisco_iosxe.md).
	// admission.LoadFile does not refuse the repeat, so the broker does.
	devices := make(map[string]admission.Device, len(cfg.Inventory.Devices))
	for _, d := range cfg.Inventory.Devices {
		if _, seen := devices[d.Name]; seen {
			return nil, fmt.Errorf("inventory names device %q twice; the broker mints by name", d.Name)
		}
		devices[d.Name] = d
	}
	b := &broker.Broker{Policy: pol, Devices: devices, Minter: minter, Store: st, Log: log, Metrics: m,
		Now: time.Now, MaxSessionAge: cfg.Session.MaxSessionAgeDefault, BatchMax: cfg.Broker.BatchMax}
	// Startup only. Server panics on a nil or empty anchor pool; LoadTLS has
	// just returned a pool of exactly one, so it cannot here, and buildBroker
	// runs before the TACACS+ listener opens — a panic would end a start, never
	// a running daemon's device AAA. A reload path (plan 7) must not call
	// Server until it returns an error instead.
	srv := b.Server(cfg.Broker.Listen, cert, anchor)
	// net/http logs what no handler sees — a handshake refused for an expired
	// or untrusted certificate — through ErrorLog. Left nil it goes to the
	// standard library's default logger; routed here it lands beside
	// port49d's other lines, where an operator is already looking.
	srv.ErrorLog = stdlog.New(stderr, "port49d: broker: ", 0)
	return srv, nil
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	log := decision.NewJSONLinesWithFailureHook(os.Stdout, m.DecisionLogWriteFailures.Inc)
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
	if cfg.Lab != nil {
		authz.Fallback = &author.Lab{
			SessionAttributes: cfg.Lab.SessionAttributes,
			CommandAttributes: cfg.Lab.CommandAttributes,
			DenyPrefixes:      cfg.Lab.DenyPrefixes,
		}
	}
	minter := token.NewMinter(st, log, rand.Reader, tagKey, time.Now, cfg.Token.CandidateCap)
	// Plan 7's broker exposes Refresh, RevokeByPrincipal and RevokeBySID over
	// HTTP; plan 3's serves /v1/tokens and /v1/config only, so nothing in this
	// binary calls them yet. The Manager is built here so the wiring is proven
	// by the compiler rather than by plan 7 discovering it.
	sessions := session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	_ = sessions

	brokerSrv, err := buildBroker(cfg, st, minter, log, m)
	if err != nil {
		stopSpool()
		<-spoolDone
		return err
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

	deps := server.Deps{Admission: cfg.Admission, Keys: cfg.Keyring(),
		// The context indexes are given the context's own idle TTL: they exist
		// to let revocation reach a live context, so they need to outlast
		// nothing the context does not.
		Authen: authen.New(st, log, lim, m, time.Now, newCtxID, cfg.ReceiptIdleTTL, cfg.ReceiptMaxAge,
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
		Author: author.New(st, authz, log, m, time.Now, cfg.SessionServices,
			cfg.Session.StalenessCeiling, cfg.Session.GraceWindow, cfg.ContextIdleTTL),
		// The system-user table is injected rather than looked up through a
		// package global, so nothing can mutate a security rule at run time.
		// It carries `root` for juniper_junos and nothing else
		// (internal/platform). No idle TTL: accounting does not extend one
		// (spec §5.8).
		Acct:   acct.New(st, spool, m, time.Now, platform.SystemUsers()),
		Limits: lim, Metrics: m, Log: log, Now: time.Now, IdleTimeout: cfg.Limits.IdleTimeout}

	// A dead metrics listener is not a detail: without it nobody can see the
	// daemon at all, so its error ends the process rather than disappearing.
	metricsErr := make(chan error, 1)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		metricsErr <- http.ListenAndServe(cfg.MetricsListen, mux)
	}()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
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
			stopSpool()
			<-spoolDone
			return fmt.Errorf("broker listener on %s: %w", brokerSrv.Addr, err)
		}
	}
	fmt.Fprintf(stderr, "port49d: listening on %s, metrics on %s, %d devices admitted\n",
		cfg.Listen, cfg.MetricsListen, len(cfg.Inventory.Devices))

	brokerErr := make(chan error, 1)
	if brokerSrv != nil {
		// Capped, so connections to the broker cannot take the file
		// descriptors the TACACS+ listener beside it needs (pre-flight F1).
		go func() { brokerErr <- brokerSrv.ServeTLS(broker.Limit(bln, broker.MaxConns), "", "") }()
		fmt.Fprintf(stderr, "port49d: broker listening on %s\n", brokerSrv.Addr)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx, ln, deps) }()

	var runErr error
	select {
	case err := <-metricsErr:
		runErr = fmt.Errorf("metrics listener on %s: %w", cfg.MetricsListen, err)
		cancel()
		<-serveErr
	case err := <-brokerErr:
		runErr = fmt.Errorf("broker listener on %s: %w", cfg.Broker.Listen, err)
		cancel()
		<-serveErr
	case err := <-serveErr:
		runErr = err
		cancel()
	case <-ctx.Done():
		fmt.Fprintln(stderr, "port49d: signal received, draining")
		<-serveErr
	}
	cancel()
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
	return runErr
}
