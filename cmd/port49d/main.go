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
	"encoding/base32"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/acct"
	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/daemon/server"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/token"
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
	st := memory.New(time.Now)
	lim := limits.New(cfg.Limits, time.Now)

	// The tag key binds a token to the device it was minted for (design §8).
	// Nothing mints tokens yet — Task 15 wires the Minter and derives this
	// from the encryption-at-rest key, the same place the RFC 8907 shared keys
	// live — so until then it is process-local, which is exactly as long as
	// the in-memory token set it tags survives a restart. Random rather than
	// constant: a constant here would be a published key that lets anyone
	// compute any device's tag. Lab seed tokens are not token-shaped, so the
	// tag check never fires on them.
	var tagSeed [32]byte
	if _, err := rand.Read(tagSeed[:]); err != nil {
		return fmt.Errorf("port49d: crypto/rand is unavailable: %w", err)
	}
	tagKey := token.TagKey(tagSeed[:])

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

	// The lab authorizer is the only authorizer until the policy engine lands
	// (plan 4); config.Load refuses a config without it, so it is never nil and
	// port49 never falls back to permitting everything.
	authz := &author.Lab{
		SessionAttributes: cfg.Lab.SessionAttributes,
		CommandAttributes: cfg.Lab.CommandAttributes,
		DenyPrefixes:      cfg.Lab.DenyPrefixes,
	}
	for _, t := range cfg.Lab.SeedTokens {
		if _, err := st.PutToken(ctx, store.TokenKey{NAS: t.NAS, Username: authen.Canonical(t.Username)},
			// ID: t.Secret is the lab seed's stand-in for a minted handle. It
			// is what makes the seeded token addressable for redemption at
			// all; Task 15 replaces this loop with the Minter, which chooses
			// an ID that is not the secret.
			store.Token{ID: t.Secret, Secret: []byte(t.Secret), Kind: t.Kind, ExpiresAt: time.Now().Add(cfg.ContextIdleTTL)}); err != nil {
			stopSpool()
			<-spoolDone
			return err
		}
	}

	deps := server.Deps{Admission: cfg.Admission, Keys: cfg.Keyring(),
		// The context indexes are given the context's own idle TTL: they exist
		// to let revocation reach a live context, so they need to outlast
		// nothing the context does not.
		Authen: authen.New(st, log, lim, m, time.Now, newCtxID, cfg.ReceiptIdleTTL, cfg.ReceiptMaxAge,
			cfg.ContextIdleTTL, cfg.ContextIdleTTL, tagKey),
		// The staleness ceiling is 0 — no staleness check — until there is a
		// refresh to be stale relative to. `refreshed_at` is stamped once at
		// login and nothing moves it until plan 2's broker-side Refresh (task
		// 13); `session.staleness_ceiling` arrives with the config in task 14
		// and is wired here in task 15. Any finite ceiling before then denies
		// a steadily working operator `context_stale` — "the broker is
		// unreachable" — at login plus the ceiling, with no broker to reach,
		// which is the failure the idle TTL was just made extendable to avoid.
		//
		// The grace window is carried for plan 7's sweep and read by nothing
		// today.
		Author: author.New(st, authz, log, m, time.Now, cfg.SessionServices,
			0, 10*time.Minute, cfg.ContextIdleTTL),
		Acct:   acct.New(st, spool, m, time.Now),
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
	fmt.Fprintf(os.Stderr, "port49d: listening on %s, metrics on %s, %d devices admitted\n",
		cfg.Listen, cfg.MetricsListen, len(cfg.Inventory.Devices))

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx, ln, deps) }()

	var runErr error
	select {
	case err := <-metricsErr:
		runErr = fmt.Errorf("metrics listener on %s: %w", cfg.MetricsListen, err)
		cancel()
		<-serveErr
	case err := <-serveErr:
		runErr = err
		cancel()
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "port49d: signal received, draining")
		<-serveErr
	}
	cancel()

	// Serve has returned, so no connection can offer another record: only now
	// is it true that whatever the spool drains is all of it.
	stopSpool()
	<-spoolDone
	fmt.Fprintln(os.Stderr, "port49d: accounting spool drained, exiting")
	return runErr
}
