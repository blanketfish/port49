// Command port49-inventory is the inventory service (spec §10): the one
// component that talks to a source of truth. It syncs its sources on a
// schedule, at start, at SIGHUP and when a syncer asks, bounds each sync,
// and publishes one signed bundle document over a mutual-TLS API, to its
// state directory and to a shared mirror. Nothing depends on it being up:
// every port49d serves the bundle it holds, and starts from its own copy or
// the mirror's.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyfile"
)

const prefix = "port49-inventory: "

func main() {
	cfgPath := flag.String("config", "/etc/port49-inventory/port49-inventory.yaml", "path to port49-inventory.yaml")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	if err := run(ctx, *cfgPath, hup); err != nil {
		// Restore's errors already name the service; said once either way.
		fmt.Fprintln(os.Stderr, prefix+strings.TrimPrefix(err.Error(), prefix))
		os.Exit(1)
	}
}

// stderr is where the service's lines go; tests swap it.
var stderr io.Writer = os.Stderr

// onListening is told the bound addresses; a test's hook, nil otherwise.
var onListening func(api, metrics string)

// newSources builds the configured sources; a test swaps it.
var newSources = inventory.NewSources

// restore is the Syncer's Restore; a test swaps it for one that hangs.
var restore = (*inventory.Syncer).Restore

// maxConns caps the API's connections: its callers are a fleet of port49d
// polling every 30 s and a few operators.
const maxConns = 512

// grace is how long a shutdown waits for the API's requests, a POST /v1/sync
// among them, before it closes their connections and cancels them.
const grace = 5 * time.Second

// run is the service from config to exit. Everything that can fail on a
// typo fails before a listener opens, and nothing it starts outlives it.
func run(ctx context.Context, cfgPath string, hup <-chan os.Signal) error {
	cfg, err := inventory.Load(cfgPath)
	if err != nil {
		return err
	}
	key, err := keyfile.LoadEd25519(cfg.SigningKeyFile)
	if err != nil {
		return fmt.Errorf("signing_key_file %s: %w", cfg.SigningKeyFile, err)
	}
	cert, anchor, err := broker.LoadTLS(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ClientCAFile)
	if err != nil {
		// LoadTLS's errors name the file at fault; its prefix is the broker's.
		return fmt.Errorf("TLS: %s", strings.TrimPrefix(err.Error(), "broker: "))
	}
	sources, err := newSources(cfg.Sync, stderr)
	if err != nil {
		return err
	}
	// The keys its own state and mirror may be signed by besides its own:
	// the old key's, through a rotation (pre-flight M6). Behind the fence
	// (M3): whoever writes one decides what the service restores. The
	// Syncer always adds its own key's public half; an empty list is that
	// key alone.
	verify, err := fence.ReadVerifyKeys("verify_key_files", cfg.VerifyKeyFiles)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("state_dir %s: %w", cfg.StateDir, err)
	}
	reg := prometheus.NewRegistry()
	m := inventory.NewMetrics(reg)
	s := &inventory.Syncer{Sources: sources, Bounds: cfg.Bounds(), Default: cfg.MaxRemovedPercent,
		PolicyFile: cfg.PolicyFile, Key: key, VerifyKeys: verify, Timeout: cfg.SyncTimeout,
		State:   inventory.State{Dir: cfg.StateDir, MirrorDir: cfg.MirrorDir, Keep: 64},
		Metrics: m, Now: time.Now, Log: stderr}
	api := &inventory.API{Syncer: s, Readers: cfg.Readers, Syncers: cfg.Syncers, Now: time.Now, Log: stderr, Metrics: m}
	var reqs inflight
	srv, err := inventory.Server(cfg.Listen, cert, anchor, reqs.wrap(api.Handler()),
		stdlog.New(stderr, prefix+"api: ", 0))
	if err != nil {
		return err
	}
	// Every ticker and every API request, a POST /v1/sync's among them, runs
	// under ctx: a shutdown cancels a sync in flight at once, and the
	// Syncer says nothing of a sync its caller ended.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv.BaseContext = func(net.Listener) context.Context { return ctx }

	// The metrics listener binds before Restore, which reads the mirror: a
	// mount that hangs holds the start up to its deadline, and meanwhile
	// /healthz, /readyz (503) and port49_inventory_mirror_behind show it
	// (final review I3). Its address is said at once for the same reason.
	mln, err := net.Listen("tcp", cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("metrics_listen %s: %w", cfg.MetricsListen, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Ready is "has a bundle to serve": a probe needs nothing else, and this
	// listener carries no fleet data.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Current() == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	msrv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		ErrorLog: stdlog.New(stderr, prefix+"metrics: ", 0)}
	metricsErr := make(chan error, 1)
	go func() { metricsErr <- msrv.Serve(mln) }()
	fmt.Fprintf(stderr, prefix+"metrics on %s\n", mln.Addr())
	stopMetrics := func() {
		msrv.Close()
		<-metricsErr
	}

	// A copy the service cannot open stops it here, before the API listens:
	// it never serves below the bundle every port49d holds. A SIGTERM while
	// Restore waits on a hung mirror ends the start quietly.
	if err := restore(s, ctx); err != nil {
		stopMetrics()
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, prefix+"signal received, exiting")
			return nil
		}
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		stopMetrics()
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	apiErr := make(chan error, 1)
	go func() { apiErr <- srv.ServeTLS(broker.Limit(ln, maxConns), "", "") }()

	// Every ticker stops with ctx, and is joined, before run returns.
	var tickers sync.WaitGroup
	// shutdown closes both listeners, waits for the API's requests, and
	// joins every goroutine run started. apiDone and metricsDone say whether
	// that server's Serve has already returned.
	shutdown := func(apiDone, metricsDone bool) {
		cancel()
		shut, done := context.WithTimeout(context.Background(), grace)
		defer done()
		if err := srv.Shutdown(shut); err != nil {
			// Past the grace: closing the connections cancels their
			// requests, and a sync in one stops at its next context check.
			srv.Close()
		}
		if err := msrv.Shutdown(shut); err != nil {
			msrv.Close()
		}
		reqs.wait()
		if !apiDone {
			<-apiErr
		}
		if !metricsDone {
			<-metricsErr
		}
		tickers.Wait()
	}

	names := make([]string, len(cfg.Sync))
	for i, c := range cfg.Sync {
		names[i] = c.Name + " (" + c.Type + ")"
	}
	fmt.Fprintf(stderr, prefix+"API on %s (mutual TLS; %d reader(s), %d syncer(s)), metrics on %s; "+
		"signing key %s; %d source(s): %s\n", ln.Addr(), len(cfg.Readers), len(cfg.Syncers), mln.Addr(),
		keyfile.Ed25519KeyID(key.Public().(ed25519.PublicKey)), len(sources), strings.Join(names, ", "))
	if onListening != nil {
		onListening(ln.Addr().String(), mln.Addr().String())
	}

	// A sync is never started once a shutdown has begun.
	syncNow := func(trigger string, only ...string) {
		if ctx.Err() == nil {
			s.Sync(ctx, trigger, only...)
		}
	}
	syncNow("startup")
	// Each source on its own interval (spec §10): a ticker per source names
	// the source due, and that sync rebuilds the bundle with every other
	// source's latest fetch.
	due := make(chan string)
	for _, c := range cfg.Sync {
		tickers.Add(1)
		go func(name string, every time.Duration) {
			defer tickers.Done()
			tick := time.NewTicker(every)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					select {
					case due <- name:
					case <-ctx.Done():
						return
					}
				}
			}
		}(c.Name, c.Interval)
	}
	for {
		select {
		case <-ctx.Done():
			shutdown(false, false)
			fmt.Fprintln(stderr, prefix+"signal received, exiting")
			return nil
		case err := <-apiErr:
			shutdown(true, false)
			return fmt.Errorf("listen %s: %w", cfg.Listen, err)
		case err := <-metricsErr:
			shutdown(false, true)
			return fmt.Errorf("metrics_listen %s: %w", cfg.MetricsListen, err)
		case name := <-due:
			syncNow("schedule", name)
		case <-hup:
			syncNow("signal")
		}
	}
}

// inflight counts the API's requests, so a shutdown joins a POST /v1/sync's
// goroutine rather than returning beside it. http.Server.Close forgets a
// connection without waiting for its handler.
type inflight struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func (f *inflight) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error":"shutting_down"}`+"\n")
			return
		}
		f.wg.Add(1)
		f.mu.Unlock()
		defer f.wg.Done()
		h.ServeHTTP(w, r)
	})
}

// wait refuses every request from now on and waits for those running.
func (f *inflight) wait() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.wg.Wait()
}
